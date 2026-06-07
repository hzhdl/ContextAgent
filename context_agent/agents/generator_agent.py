#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Generator Agent for the Context Agent system.

This agent generates mock return values based on static analysis
and semantic understanding of external calls.
"""

import json
import re
import logging
from typing import Any, Dict, List, Optional

from context_agent.core.base_agent import BaseAgent, AgentResult
from context_agent.core.tool_registry import Tool
from context_agent.tools.protocol_tool import ProtocolTool, ProtocolDefaultsTool

logger = logging.getLogger(__name__)


class GeneratorAgent(BaseAgent):
    """
    Mock return value generator agent.

    Responsible for:
    - Generating satisfy values (satisfy conditions)
    - Generating violate values (trigger error paths)
    - Generating boundary values (edge cases)
    - Incorporating semantic understanding into generation
    """

    def __init__(
        self,
        llm_client,
        tools: List[Tool] = None,
        verbose: bool = False
    ):
        """
        Initialize the generator agent.

        Args:
            llm_client: LLM client for generation
            tools: Optional list of tools
            verbose: Whether to log detailed info
        """
        default_tools = [
            ProtocolTool(),
            ProtocolDefaultsTool(),
        ]

        super().__init__(
            name="GeneratorAgent",
            llm_client=llm_client,
            tools=tools or default_tools,
            max_iterations=5,
            verbose=verbose
        )

    def _get_default_system_prompt(self) -> str:
        return """You are an expert in generating mock return values for smart contract fuzzing.

Your goal is to generate CONCRETE return values that maximize code coverage by exploring different execution paths.

For each external call, you should generate:

1. **SATISFY** values (2-4 combinations):
   - Values that make conditions TRUE / pass checks
   - Should explore the "happy path" of the code
   - Consider protocol semantics (e.g., realistic token balances)

2. **VIOLATE** values (2-4 combinations):
   - Values that make conditions FALSE / fail checks
   - Should trigger error handling, reverts, or alternative branches
   - Important for finding vulnerabilities

3. **BOUNDARY** values (2-4 combinations):
   - Edge cases: 0, 1, max values, type limits
   - Values at thresholds mentioned in conditions
   - Overflow/underflow boundaries

CRITICAL RULES:
1. Return ONLY concrete numeric values - NO expressions like "amount-1" or "balance/2"
2. Match EXACT return type count - if function returns (uint256, uint256), each value must be [val1, val2]
3. Use decimal integers for uint/int types (e.g., 1000, not 0x3e8)
4. Use lowercase true/false for bool
5. Use 0x-prefixed hex strings for address (42 chars total)

Output format must be valid JSON:
{
  "satisfy": [[val1, val2, ...], [val1, val2, ...], ...],
  "violate": [[val1, val2, ...], [val1, val2, ...], ...],
  "boundary": [[val1, val2, ...], [val1, val2, ...], ...]
}"""

    def generate(
        self,
        external_call: Dict[str, Any],
        semantic_description: Dict[str, Any] = None,
        protocol: str = "Generic"
    ) -> Dict[str, List[List[Any]]]:
        """
        Generate mock return values for an external call.

        Args:
            external_call: External call information from analyzer
            semantic_description: Optional semantic description
            protocol: Protocol type

        Returns:
            Dictionary with satisfy/violate/boundary values
        """
        ext_info = external_call.get("external_call", {})
        ext_sig = ext_info.get("signature", "Unknown")
        return_types = ext_info.get("return_types", [])
        conditions = external_call.get("conditions", [])

        logger.info(f"GeneratorAgent generating values for: {ext_sig}")

        if not return_types:
            logger.warning(f"No return types for {ext_sig}, returning empty values")
            return {
                "satisfy": [[]],
                "violate": [[]],
                "boundary": [[]]
            }

        try:
            # Build the generation prompt
            prompt = self._build_generation_prompt(
                ext_sig=ext_sig,
                return_types=return_types,
                conditions=conditions,
                semantic_description=semantic_description,
                protocol=protocol
            )

            # Generate using LLM
            messages = [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": prompt}
            ]

            response = self.llm.generate(messages)

            # Parse the response
            mock_values = self._parse_generation_response(response)

            # Validate structure
            if self._validate_structure(mock_values, return_types):
                return mock_values
            else:
                # Try to normalize
                normalized = self._normalize_values(mock_values, return_types)
                if self._validate_structure(normalized, return_types):
                    return normalized

            # Fallback to defaults
            logger.warning(f"Generation failed for {ext_sig}, using defaults")
            return self._get_fallback_values(return_types, protocol)

        except Exception as e:
            logger.error(f"GeneratorAgent error: {e}")
            # 重新抛出异常，让 orchestrator 能够触发重试机制
            raise

    def _build_generation_prompt(
        self,
        ext_sig: str,
        return_types: List[str],
        conditions: List[Dict],
        semantic_description: Dict[str, Any],
        protocol: str
    ) -> str:
        """Build the prompt for value generation."""
        from context_agent.core.evm_context import get_evm_context
        evm_ctx = get_evm_context()

        # Format conditions
        cond_text = "No specific conditions"
        if conditions:
            cond_items = []
            for cond in conditions:
                expr = cond.get("expression", "")
                atomics = cond.get("atomic_conditions", [])
                if expr:
                    cond_items.append(f"- {expr}")
                if atomics:
                    cond_items.append(f"  Atomics: {atomics}")
            cond_text = "\n".join(cond_items) if cond_items else "No specific conditions"

        # Format semantic info
        semantic_text = "No semantic information available"
        if semantic_description:
            semantic_items = [
                f"- Business Purpose: {semantic_description.get('business_purpose', 'Unknown')}",
                f"- Return Meaning: {semantic_description.get('return_value_meaning', 'Unknown')}",
            ]
            constraints = semantic_description.get("value_constraints", [])
            if constraints:
                semantic_items.append(f"- Constraints: {constraints}")

            boundary_impact = semantic_description.get("boundary_impact", {})
            if boundary_impact:
                semantic_items.append(f"- Boundary Impact: {json.dumps(boundary_impact)}")

            scenarios = semantic_description.get("suggested_test_scenarios", [])
            if scenarios:
                semantic_items.append(f"- Suggested Scenarios: {scenarios}")

            implicit = semantic_description.get("implicit_constraints", [])
            if implicit:
                semantic_items.append("- Implicit Constraints (from data flow analysis):")
                for ic in implicit:
                    semantic_items.append(f"  - Flow: {ic.get('data_flow_chain', '')}")
                    semantic_items.append(f"    Condition: {ic.get('condition_expression', '')}")
                    semantic_items.append(f"    Constraint on return value: {ic.get('return_value_constraint', '')}")

            semantic_text = "\n".join(semantic_items)

        return f"""Generate mock return values for this external call:

## External Call
Signature: {ext_sig}
Protocol: {protocol}

## Return Types (CRITICAL - match exactly!)
Types: {', '.join(return_types)}
Count: {len(return_types)} value(s) per combination

## Associated Conditions
{cond_text}

## Semantic Understanding
{semantic_text}

{evm_ctx.to_prompt_section()}

## Generation Guidelines
1. For SATISFY: Generate 2-4 value combinations that would make conditions TRUE
2. For VIOLATE: Generate 2-4 value combinations that would make conditions FALSE
3. For BOUNDARY: Generate 2-4 edge case combinations (0, max, thresholds)
4. For SATISFY/VIOLATE: Pay special attention to "Implicit Constraints" - these are conditions
   that the return value must satisfy/violate through indirect data flow paths.
   These constraints may be MORE IMPORTANT than the directly associated conditions.

**Important: Use EVM context above for:**
- Timestamp values: Generate relative to block.timestamp ({evm_ctx.block_timestamp})
- Address values: Use contract_address ({evm_ctx.contract_address}) or caller_address ({evm_ctx.caller_address})
- Block numbers: Generate relative to current block.number ({evm_ctx.block_number})

Remember:
- Each value array must contain EXACTLY {len(return_types)} element(s)
- Use concrete values only (no expressions)
- Consider the semantic meaning for realistic values

Output your response as valid JSON only, no explanation:
{{"satisfy": [[...], ...], "violate": [[...], ...], "boundary": [[...], ...]}}"""

    def _parse_generation_response(self, response: str) -> Dict[str, List[List[Any]]]:
        """Parse LLM response to extract mock values."""
        # Try to find JSON in response
        json_patterns = [
            r'```json\s*(\{.*?\})\s*```',  # ```json {...} ```
            r'```\s*(\{.*?\})\s*```',       # ``` {...} ```
            r'(\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\})',  # Bare JSON
        ]

        for pattern in json_patterns:
            match = re.search(pattern, response, re.DOTALL)
            if match:
                try:
                    data = json.loads(match.group(1) if '```' in pattern else match.group(1))
                    if all(key in data for key in ["satisfy", "violate", "boundary"]):
                        return data
                except json.JSONDecodeError:
                    continue

        raise ValueError("Could not parse JSON from LLM response")

    def _validate_structure(
        self,
        mock_values: Dict[str, List[List[Any]]],
        return_types: List[str]
    ) -> bool:
        """Validate the structure of mock values."""
        expected_count = len(return_types)

        for scenario in ["satisfy", "violate", "boundary"]:
            if scenario not in mock_values:
                return False

            values = mock_values[scenario]
            if not isinstance(values, list):
                return False

            for val_array in values:
                if not isinstance(val_array, list):
                    return False
                if len(val_array) != expected_count:
                    return False

        return True

    def _normalize_values(
        self,
        mock_values: Dict[str, Any],
        return_types: List[str]
    ) -> Dict[str, List[List[Any]]]:
        """Normalize mock values to correct structure."""
        expected_count = len(return_types)
        normalized = {}

        for scenario in ["satisfy", "violate", "boundary"]:
            if scenario not in mock_values:
                normalized[scenario] = []
                continue

            scenario_data = mock_values[scenario]
            if not isinstance(scenario_data, list):
                normalized[scenario] = []
                continue

            normalized_scenario = []
            for item in scenario_data:
                normalized_item = self._flatten_to_correct_depth(item, expected_count)
                if len(normalized_item) == expected_count:
                    normalized_scenario.append(normalized_item)

            normalized[scenario] = normalized_scenario

        return normalized

    def _flatten_to_correct_depth(self, item: Any, expected_count: int) -> List[Any]:
        """Flatten nested arrays to correct depth."""
        if not isinstance(item, list):
            return [item]

        if len(item) == expected_count and not any(isinstance(x, list) for x in item):
            return item

        # Handle over-nesting
        if len(item) == 1 and isinstance(item[0], list):
            return self._flatten_to_correct_depth(item[0], expected_count)

        # Flatten one level
        if any(isinstance(x, list) for x in item):
            flattened = []
            for x in item:
                if isinstance(x, list):
                    flattened.extend(x)
                else:
                    flattened.append(x)
            return flattened[:expected_count]

        return item

    def _get_fallback_values(
        self,
        return_types: List[str],
        protocol: str
    ) -> Dict[str, List[List[Any]]]:
        """Get fallback default values."""
        # Type default values
        defaults = {
            "uint256": [0, 1, 10**18, 2**256 - 1],
            "uint128": [0, 1, 10**18, 2**128 - 1],
            "uint112": [0, 1, 10**18, 2**112 - 1],
            "uint96": [0, 1, 10**18, 2**96 - 1],
            "uint64": [0, 1, 10**9, 2**64 - 1],
            "uint32": [0, 1, 10**6, 2**32 - 1],
            "uint16": [0, 1, 1000, 2**16 - 1],
            "uint8": [0, 1, 100, 255],
            "int256": [0, -1, 10**18, 2**255 - 1],
            "bool": [True, False],
            "address": [
                "0x0000000000000000000000000000000000000000",
                "0x0000000000000000000000000000000000000001",
                "0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF"
            ],
        }

        # Generate combinations
        satisfy = []
        violate = []
        boundary = []

        # Create value sets
        for i in range(3):
            vals = []
            for rtype in return_types:
                type_defaults = defaults.get(rtype, defaults.get("uint256"))
                if isinstance(type_defaults, list):
                    vals.append(type_defaults[min(i, len(type_defaults) - 1)])
                else:
                    vals.append(0)

            if i == 0:
                satisfy.append(vals)
            elif i == 1:
                violate.append(vals)
            else:
                boundary.append(vals)

        return {
            "satisfy": satisfy,
            "violate": violate,
            "boundary": boundary
        }

    def run(self, task: str, context: Dict[str, Any] = None) -> AgentResult:
        """
        Run the generator agent.

        Args:
            task: Task description
            context: Context with external_call, semantic_description, protocol

        Returns:
            AgentResult with generated mock values
        """
        context = context or {}

        if "external_call" in context:
            try:
                mock_values = self.generate(
                    external_call=context["external_call"],
                    semantic_description=context.get("semantic_description"),
                    protocol=context.get("protocol", "Generic")
                )
                return AgentResult(
                    success=True,
                    output=mock_values
                )
            except Exception as e:
                logger.error(f"GeneratorAgent.run() failed: {e}")
                return AgentResult(
                    success=False,
                    error=str(e)
                )

        return super().run(task, context)
