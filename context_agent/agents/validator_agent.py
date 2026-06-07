#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Validator Agent for the Context Agent system.

This agent validates generated mock return values for type correctness
and protocol semantics, providing correction suggestions when needed.
"""

import logging
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from context_agent.core.base_agent import BaseAgent, AgentResult
from context_agent.core.tool_registry import Tool
from context_agent.tools.validator_tool import ValidatorTool, TypeCheckerTool

logger = logging.getLogger(__name__)


@dataclass
class CorrectionSuggestion:
    """
    Suggestion for correcting an invalid value.

    Attributes:
        field_index: Index of the field that needs correction
        current_value: The current invalid value
        suggested_value: The suggested corrected value
        reason: Explanation of why correction is needed
        severity: "error" for invalid, "warning" for suspicious
    """
    field_index: int
    current_value: Any
    suggested_value: Any
    reason: str
    severity: str = "error"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ValidationResult:
    """
    Result of validating mock return values.

    Attributes:
        is_valid: Whether all values passed validation
        validated_values: The validated (and possibly corrected) values
        issues: List of issues found during validation
        corrections: List of correction suggestions
        summary: Human-readable summary
    """
    is_valid: bool
    validated_values: Dict[str, List[List[Any]]]
    issues: List[Dict[str, Any]] = field(default_factory=list)
    corrections: List[CorrectionSuggestion] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "validated_values": self.validated_values,
            "issues": self.issues,
            "corrections": [c.to_dict() for c in self.corrections],
            "summary": self.summary
        }


class ValidatorAgent(BaseAgent):
    """
    Validation agent for mock return values.

    Responsible for:
    - Validating type correctness
    - Checking protocol semantics
    - Detecting suspicious values
    - Providing correction suggestions
    """

    def __init__(
        self,
        llm_client,
        tools: List[Tool] = None,
        verbose: bool = False
    ):
        """
        Initialize the validator agent.

        Args:
            llm_client: LLM client for reasoning
            tools: Optional list of tools
            verbose: Whether to log detailed info
        """
        default_tools = [
            ValidatorTool(),
            TypeCheckerTool(),
        ]

        super().__init__(
            name="ValidatorAgent",
            llm_client=llm_client,
            tools=tools or default_tools,
            max_iterations=3,
            verbose=verbose
        )

    def _get_default_system_prompt(self) -> str:
        return """You are a smart contract mock value validator.

Your task is to validate generated mock return values for:
1. Type correctness - values must match expected Solidity types
2. Protocol semantics - values must make sense for the protocol
3. Test effectiveness - values should provide good coverage

When validating, check for:
- Values within type bounds (e.g., uint256 must be 0 to 2^256-1)
- Correct formats (addresses must be 42 characters with 0x prefix)
- Protocol reasonableness (e.g., ERC20 balances should be realistic)
- Suspicious patterns (obvious test values that might not trigger bugs)

If values are invalid, provide specific correction suggestions with:
- The field index that needs correction
- The current invalid value
- A suggested corrected value
- The reason for correction
- Severity (error or warning)

Output your validation result as JSON."""

    def validate(
        self,
        mock_values: Dict[str, List[List[Any]]],
        return_types: List[str],
        protocol: str = "Generic",
        function_signature: str = None
    ) -> ValidationResult:
        """
        Validate mock return values.

        Args:
            mock_values: Generated mock values
            return_types: Expected return types
            protocol: Protocol type
            function_signature: Optional function signature for context

        Returns:
            ValidationResult with validation outcome
        """
        logger.info(f"ValidatorAgent validating values for protocol: {protocol}")

        issues = []
        corrections = []
        validated_values = {"satisfy": [], "violate": [], "boundary": []}

        try:
            # Use the validator tool
            result = self.tools.execute(
                "validate_semantics",
                mock_values=mock_values,
                return_types=return_types,
                protocol=protocol,
                function_signature=function_signature or ""
            )

            if result.success:
                validated_values = result.data.get("validated_values", mock_values)
                issues = result.data.get("issues", [])

                # Convert corrections from tool result
                for corr in result.data.get("corrections", []):
                    corrections.append(CorrectionSuggestion(
                        field_index=corr.get("index", 0),
                        current_value=corr.get("original"),
                        suggested_value=corr.get("corrected"),
                        reason="Value corrected during validation",
                        severity="warning"
                    ))

            else:
                # Validation tool failed, do basic validation
                validated_values, issues, corrections = self._basic_validation(
                    mock_values, return_types
                )

        except Exception as e:
            logger.error(f"Validation error: {e}")
            # Return original values on error
            validated_values = mock_values

        # Determine overall validity
        is_valid = len(issues) == 0 and len(corrections) == 0

        # Generate summary
        summary = self._generate_summary(is_valid, issues, corrections)

        return ValidationResult(
            is_valid=is_valid,
            validated_values=validated_values,
            issues=issues,
            corrections=corrections,
            summary=summary
        )

    def _basic_validation(
        self,
        mock_values: Dict[str, List[List[Any]]],
        return_types: List[str]
    ) -> tuple:
        """Perform basic validation without the tool."""
        validated = {}
        issues = []
        corrections = []

        for scenario in ["satisfy", "violate", "boundary"]:
            values = mock_values.get(scenario, [])
            validated_scenario = []

            for i, val_array in enumerate(values):
                if not isinstance(val_array, list):
                    issues.append({
                        "scenario": scenario,
                        "index": i,
                        "issue": "Value is not an array"
                    })
                    continue

                if len(val_array) != len(return_types):
                    issues.append({
                        "scenario": scenario,
                        "index": i,
                        "issue": f"Wrong number of values: expected {len(return_types)}, got {len(val_array)}"
                    })
                    continue

                # Validate each value
                valid = True
                for j, (val, rtype) in enumerate(zip(val_array, return_types)):
                    if not self._validate_single_value(val, rtype):
                        corrections.append(CorrectionSuggestion(
                            field_index=j,
                            current_value=val,
                            suggested_value=self._get_default_for_type(rtype),
                            reason=f"Invalid value for type {rtype}",
                            severity="error"
                        ))
                        valid = False

                if valid:
                    validated_scenario.append(val_array)

            validated[scenario] = validated_scenario

        return validated, issues, corrections

    def _validate_single_value(self, value: Any, rtype: str) -> bool:
        """Validate a single value against its type."""
        try:
            if rtype.startswith("uint"):
                if isinstance(value, str):
                    if value.startswith("0x"):
                        int(value, 16)
                    else:
                        int(value)
                elif isinstance(value, (int, float)):
                    if int(value) < 0:
                        return False
                else:
                    return False

            elif rtype.startswith("int"):
                if isinstance(value, str):
                    int(value, 16) if value.startswith("0x") else int(value)
                elif not isinstance(value, (int, float)):
                    return False

            elif rtype == "bool":
                if not isinstance(value, bool):
                    if isinstance(value, str) and value.lower() not in ["true", "false"]:
                        return False

            elif rtype == "address":
                if not isinstance(value, str):
                    return False
                addr = value.lower()
                if not addr.startswith("0x"):
                    addr = "0x" + addr
                if len(addr) != 42:
                    return False
                int(addr, 16)

            return True

        except (ValueError, TypeError):
            return False

    def _get_default_for_type(self, rtype: str) -> Any:
        """Get default value for a type."""
        if rtype.startswith("uint"):
            return 0
        elif rtype.startswith("int"):
            return 0
        elif rtype == "bool":
            return False
        elif rtype == "address":
            return "0x0000000000000000000000000000000000000000"
        elif rtype.startswith("bytes"):
            if rtype == "bytes32":
                return "0x" + "00" * 32
            return "0x"
        return 0

    def _generate_summary(
        self,
        is_valid: bool,
        issues: List[Dict],
        corrections: List[CorrectionSuggestion]
    ) -> str:
        """Generate a human-readable summary."""
        if is_valid:
            return "All values passed validation"

        parts = []
        if issues:
            parts.append(f"{len(issues)} structural issue(s)")
        if corrections:
            errors = len([c for c in corrections if c.severity == "error"])
            warnings = len([c for c in corrections if c.severity == "warning"])
            if errors:
                parts.append(f"{errors} error(s)")
            if warnings:
                parts.append(f"{warnings} warning(s)")

        return "Validation issues: " + ", ".join(parts)

    def run(self, task: str, context: Dict[str, Any] = None) -> AgentResult:
        """
        Run the validator agent.

        Args:
            task: Task description
            context: Context with mock_values, return_types, protocol

        Returns:
            AgentResult with validation result
        """
        context = context or {}

        if "mock_values" in context and "return_types" in context:
            validation_result = self.validate(
                mock_values=context["mock_values"],
                return_types=context["return_types"],
                protocol=context.get("protocol", "Generic"),
                function_signature=context.get("function_signature")
            )
            return AgentResult(
                success=True,
                output=validation_result.to_dict()
            )

        return super().run(task, context)
