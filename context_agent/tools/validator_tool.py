#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Validator tool for the Context Agent system.

This tool wraps the SemanticValidator to provide validation and correction
capabilities for generated mock return values.
"""

import logging
from typing import Any, Dict, List, Optional

from context_agent.core.tool_registry import Tool, ToolResult

logger = logging.getLogger(__name__)



class ValidatorTool(Tool):
    """
    Semantic validator tool.

    Validates mock return values for type correctness and protocol semantics,
    and provides correction suggestions for invalid values.
    """

    def __init__(self):
        """Initialize the validator tool."""
        self._validator = None

    def _get_validator(self):
        """Lazily initialize the semantic validator."""
        if self._validator is None:
            from context_agent.tools.semantic_validator import SemanticValidator
            self._validator = SemanticValidator()
        return self._validator

    @property
    def name(self) -> str:
        return "validate_semantics"

    @property
    def description(self) -> str:
        return (
            "Validate mock return values for semantic correctness. "
            "Checks type bounds, protocol constraints, and suspicious values. "
            "Returns validated values and correction suggestions."
        )

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "mock_values": {
                    "type": "object",
                    "description": "Mock values with satisfy/violate/boundary arrays"
                },
                "return_types": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Expected return types"
                },
                "protocol": {
                    "type": "string",
                    "description": "Protocol type (e.g., 'ERC20')"
                },
                "function_signature": {
                    "type": "string",
                    "description": "The external function signature"
                }
            },
            "required": ["mock_values", "return_types", "protocol"]
        }

    def execute(
        self,
        mock_values: Dict[str, List[List[Any]]],
        return_types: List[str],
        protocol: str,
        function_signature: str = None
    ) -> ToolResult:
        """
        Validate mock return values.

        Args:
            mock_values: Dictionary with satisfy/violate/boundary arrays
            return_types: Expected return types
            protocol: Protocol type for semantic validation
            function_signature: Optional function signature for context

        Returns:
            ToolResult with validation results and corrections
        """
        try:
            validator = self._get_validator()

            context = {
                "return_types": return_types,
                "external_function_signature": function_signature or ""
            }

            # Validate and get corrected values
            validated_values = validator.validate(mock_values, protocol, context)

            # Collect validation issues
            issues = []
            corrections = []

            for scenario in ["satisfy", "violate", "boundary"]:
                original = mock_values.get(scenario, [])
                validated = validated_values.get(scenario, [])

                if len(validated) < len(original):
                    issues.append({
                        "scenario": scenario,
                        "original_count": len(original),
                        "validated_count": len(validated),
                        "dropped": len(original) - len(validated)
                    })

                # Check for corrections
                for i, (orig, valid) in enumerate(zip(original[:len(validated)], validated)):
                    if orig != valid:
                        corrections.append({
                            "scenario": scenario,
                            "index": i,
                            "original": orig,
                            "corrected": valid
                        })

            # Determine overall validation status
            is_valid = len(issues) == 0 and len(corrections) == 0

            return ToolResult.success_result({
                "is_valid": is_valid,
                "validated_values": validated_values,
                "issues": issues,
                "corrections": corrections,
                "summary": self._generate_summary(is_valid, issues, corrections)
            })

        except Exception as e:
            logger.error(f"Validation failed: {e}")
            return ToolResult.error_result(str(e))

    def _generate_summary(
        self,
        is_valid: bool,
        issues: List[Dict],
        corrections: List[Dict]
    ) -> str:
        """Generate a human-readable summary of validation results."""
        if is_valid:
            return "All values passed validation"

        parts = []

        if issues:
            dropped = sum(i["dropped"] for i in issues)
            parts.append(f"{dropped} invalid value(s) dropped")

        if corrections:
            parts.append(f"{len(corrections)} value(s) corrected")

        return "; ".join(parts)


class TypeCheckerTool(Tool):
    """
    Type checking tool for validating value types.
    """

    @property
    def name(self) -> str:
        return "check_type_bounds"

    @property
    def description(self) -> str:
        return (
            "Check if values are within the bounds for their Solidity types. "
            "Validates uint, int, address, bool, and bytes types."
        )

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "values": {
                    "type": "array",
                    "description": "List of values to check"
                },
                "types": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Corresponding Solidity types"
                }
            },
            "required": ["values", "types"]
        }

    # Type bounds
    TYPE_BOUNDS = {
        "uint256": (0, 2**256 - 1),
        "uint128": (0, 2**128 - 1),
        "uint112": (0, 2**112 - 1),
        "uint96": (0, 2**96 - 1),
        "uint80": (0, 2**80 - 1),
        "uint64": (0, 2**64 - 1),
        "uint32": (0, 2**32 - 1),
        "uint16": (0, 2**16 - 1),
        "uint8": (0, 2**8 - 1),
        "int256": (-2**255, 2**255 - 1),
        "int128": (-2**127, 2**127 - 1),
        "int64": (-2**63, 2**63 - 1),
        "int32": (-2**31, 2**31 - 1),
        "int16": (-2**15, 2**15 - 1),
        "int8": (-2**7, 2**7 - 1),
    }

    def execute(self, values: List[Any], types: List[str]) -> ToolResult:
        """
        Check type bounds for values.

        Args:
            values: List of values to check
            types: Corresponding Solidity types

        Returns:
            ToolResult with validation results
        """
        try:
            if len(values) != len(types):
                return ToolResult.error_result(
                    f"Length mismatch: {len(values)} values, {len(types)} types"
                )

            results = []
            all_valid = True

            for i, (value, type_name) in enumerate(zip(values, types)):
                check_result = self._check_single(value, type_name)
                results.append({
                    "index": i,
                    "value": value,
                    "type": type_name,
                    **check_result
                })
                if not check_result["valid"]:
                    all_valid = False

            return ToolResult.success_result({
                "all_valid": all_valid,
                "results": results
            })

        except Exception as e:
            logger.error(f"Type checking failed: {e}")
            return ToolResult.error_result(str(e))

    def _check_single(self, value: Any, type_name: str) -> Dict[str, Any]:
        """Check a single value against its type."""
        # Handle uint types
        if type_name.startswith("uint"):
            return self._check_uint(value, type_name)

        # Handle int types
        elif type_name.startswith("int"):
            return self._check_int(value, type_name)

        # Handle bool
        elif type_name == "bool":
            return self._check_bool(value)

        # Handle address
        elif type_name == "address":
            return self._check_address(value)

        # Handle bytes
        elif type_name.startswith("bytes"):
            return self._check_bytes(value, type_name)

        # Unknown type
        return {"valid": True, "note": "Unknown type, skipped validation"}

    def _check_uint(self, value: Any, type_name: str) -> Dict[str, Any]:
        """Check unsigned integer type."""
        try:
            if isinstance(value, str):
                if value.startswith("0x"):
                    num = int(value, 16)
                else:
                    num = int(value)
            else:
                num = int(value)

            min_val, max_val = self.TYPE_BOUNDS.get(type_name, (0, 2**256 - 1))

            if num < min_val:
                return {"valid": False, "error": f"Value {num} below minimum {min_val}"}
            if num > max_val:
                return {"valid": False, "error": f"Value {num} exceeds maximum {max_val}"}

            return {"valid": True}

        except (ValueError, TypeError) as e:
            return {"valid": False, "error": f"Invalid numeric value: {e}"}

    def _check_int(self, value: Any, type_name: str) -> Dict[str, Any]:
        """Check signed integer type."""
        try:
            if isinstance(value, str):
                num = int(value, 16) if value.startswith("0x") else int(value)
            else:
                num = int(value)

            min_val, max_val = self.TYPE_BOUNDS.get(type_name, (-2**255, 2**255 - 1))

            if num < min_val:
                return {"valid": False, "error": f"Value {num} below minimum {min_val}"}
            if num > max_val:
                return {"valid": False, "error": f"Value {num} exceeds maximum {max_val}"}

            return {"valid": True}

        except (ValueError, TypeError) as e:
            return {"valid": False, "error": f"Invalid numeric value: {e}"}

    def _check_bool(self, value: Any) -> Dict[str, Any]:
        """Check boolean type."""
        if isinstance(value, bool):
            return {"valid": True}
        if isinstance(value, str) and value.lower() in ["true", "false"]:
            return {"valid": True}
        if isinstance(value, int) and value in [0, 1]:
            return {"valid": True}

        return {"valid": False, "error": f"Invalid boolean value: {value}"}

    def _check_address(self, value: Any) -> Dict[str, Any]:
        """Check address type."""
        if not isinstance(value, str):
            return {"valid": False, "error": "Address must be a string"}

        addr = value.lower()
        if not addr.startswith("0x"):
            addr = "0x" + addr

        if len(addr) != 42:
            return {"valid": False, "error": f"Invalid address length: {len(addr)}"}

        try:
            int(addr, 16)
            return {"valid": True}
        except ValueError:
            return {"valid": False, "error": "Invalid hex characters in address"}

    def _check_bytes(self, value: Any, type_name: str) -> Dict[str, Any]:
        """Check bytes type."""
        if not isinstance(value, str):
            return {"valid": False, "error": "Bytes must be a hex string"}

        if not value.startswith("0x"):
            value = "0x" + value

        # Check for fixed-size bytes (bytes1-bytes32)
        if type_name != "bytes":
            try:
                size = int(type_name[5:])
                expected_len = 2 + size * 2  # 0x + 2 hex chars per byte
                if len(value) != expected_len:
                    return {
                        "valid": False,
                        "error": f"Expected {expected_len} chars for {type_name}, got {len(value)}"
                    }
            except ValueError:
                pass

        return {"valid": True}
