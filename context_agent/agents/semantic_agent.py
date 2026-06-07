#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Semantic Agent for the Context Agent system.

This agent performs semantic understanding of external calls,
analyzing business logic and generating structured semantic descriptions.
"""

import json
import logging
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from context_agent.core.base_agent import BaseAgent, AgentResult
from context_agent.core.tool_registry import Tool
from context_agent.tools.source_reader_tool import SourceReaderTool
from context_agent.tools.protocol_tool import ProtocolTool

logger = logging.getLogger(__name__)


@dataclass
class SemanticDescription:
    """
    Structured semantic description of an external call.

    Attributes:
        external_call_signature: The external call signature
        business_purpose: Why this call is made (business logic)
        return_value_meaning: What the return value represents
        value_constraints: Semantic constraints on valid values
        boundary_impact: How boundary values affect business logic
        suggested_test_scenarios: Recommended test scenarios
    """
    external_call_signature: str
    business_purpose: str = ""
    return_value_meaning: str = ""
    value_constraints: List[str] = field(default_factory=list)
    boundary_impact: Dict[str, str] = field(default_factory=dict)
    suggested_test_scenarios: List[str] = field(default_factory=list)
    implicit_constraints: List[Dict[str, str]] = field(default_factory=list)
    # Each element format:
    # {
    #   "data_flow_chain": "How the return value flows through assignments/calls to reach a condition",
    #   "condition_expression": "The final condition expression",
    #   "return_value_constraint": "The concrete constraint on the original return value"
    # }

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SemanticAgent(BaseAgent):
    """
    Semantic understanding agent.

    Responsible for:
    - Reading and understanding contract source code
    - Analyzing the business purpose of external calls
    - Determining semantic constraints on return values
    - Generating structured semantic descriptions
    """

    def __init__(
        self,
        llm_client,
        tools: List[Tool] = None,
        verbose: bool = False
    ):
        """
        Initialize the semantic agent.

        Args:
            llm_client: LLM client for reasoning
            tools: Optional list of tools
            verbose: Whether to log detailed info
        """
        default_tools = [
            SourceReaderTool(),
            ProtocolTool(),
        ]

        super().__init__(
            name="SemanticAgent",
            llm_client=llm_client,
            tools=tools or default_tools,
            max_iterations=8,
            verbose=verbose
        )

    def _get_default_system_prompt(self) -> str:
        return """You are a smart contract analysis expert specialized in tracing data flow and identifying constraints.

Your PRIMARY task is to trace how return values from external calls flow through variable assignments, arithmetic operations, and function calls to eventually reach conditions (require/assert/if/revert).

Analysis process:
1. Find where the return value is assigned
2. Follow the variable through ALL subsequent operations (arithmetic, function calls, storage writes)
3. Identify EVERY condition that depends on it (directly or indirectly)
4. Express the constraint on the original return value

You should also analyze business purpose, value meaning, and boundary impacts, but constraint tracing is your MOST IMPORTANT deliverable.

Example for `IOracle.getPrice(address)` in a swap function:
- Implicit Constraints: [
    {
      "data_flow_chain": "getPrice() -> price -> outputAmount = inputAmount * price / 1e8 -> require(outputAmount >= minOutput)",
      "condition_expression": "outputAmount >= minOutput",
      "return_value_constraint": "price must be >= (minOutput * 1e8) / inputAmount to satisfy minimum output check"
    }
  ]

When you complete your analysis, provide the Final Answer with a JSON object containing your semantic description."""

    def _extract_return_variable(self, source: str, call_expression: str) -> str:
        """
        Extract the variable name(s) that receive the return value of an external call.

        Matches two patterns:
        - Single variable: `uint256 price = oracle.getPrice(token);`
        - Tuple: `(uint80 roundId, int256 answer, ...) = priceFeed.latestRoundData();`

        Args:
            source: Solidity source code to search in
            call_expression: The call expression (e.g., "oracle.getPrice(token)")

        Returns:
            Variable name(s) as string, or empty string if not found
        """
        if not source or not call_expression:
            return ""

        # Escape the call expression for use in regex
        # Extract the function name part for more flexible matching
        func_name_match = re.search(r'\.(\w+)\s*\(', call_expression)
        if not func_name_match:
            # Try without dot (e.g., direct function call)
            func_name_match = re.search(r'(\w+)\s*\(', call_expression)
        if not func_name_match:
            return ""

        func_name = func_name_match.group(1)

        # Pattern 1: Tuple assignment
        # (uint80 roundId, int256 answer, ...) = priceFeed.latestRoundData();
        tuple_pattern = rf'\(([^)]+)\)\s*=\s*[^;]*\.{re.escape(func_name)}\s*\('
        tuple_match = re.search(tuple_pattern, source)
        if tuple_match:
            tuple_content = tuple_match.group(1)
            # Extract variable names from typed declarations
            var_names = []
            for part in tuple_content.split(','):
                part = part.strip()
                if not part:
                    continue
                # Match "type varName" or just "varName"
                tokens = part.split()
                if tokens:
                    var_names.append(tokens[-1])
            if var_names:
                return ", ".join(var_names)

        # Pattern 2: Single variable assignment with type
        # uint256 price = oracle.getPrice(token);
        typed_pattern = rf'(\w+(?:\[\])?)\s+(\w+)\s*=\s*[^;]*\.{re.escape(func_name)}\s*\('
        typed_match = re.search(typed_pattern, source)
        if typed_match:
            return typed_match.group(2)

        # Pattern 3: Simple assignment without type declaration
        # price = oracle.getPrice(token);
        simple_pattern = rf'(\w+)\s*=\s*[^;]*\.{re.escape(func_name)}\s*\('
        simple_match = re.search(simple_pattern, source)
        if simple_match:
            return simple_match.group(1)

        return ""

    def _find_func_end_in_lines(self, lines: List[str], start_idx: int) -> int:
        """
        Find the end line index of a Solidity function starting at start_idx.
        Uses brace balancing to handle nested blocks.

        Returns the index of the closing brace line, or len(lines)-1 if not found.
        """
        depth = 0
        found_open = False
        for i in range(start_idx, len(lines)):
            for ch in lines[i]:
                if ch == '{':
                    depth += 1
                    found_open = True
                elif ch == '}':
                    depth -= 1
                    if found_open and depth == 0:
                        return i
        return len(lines) - 1

    def _prepare_source_context(
        self,
        full_source: str,
        func_source: str,
        target_name: str,
        max_chars: int = 6000
    ) -> str:
        """
        Prepare source code context with smart truncation.

        Strategy:
        1. If full source <= max_chars: use it directly
        2. If full source > max_chars: extract header + target function + called internal functions
        3. Fallback: just target function source

        Args:
            full_source: Complete contract source code
            func_source: Target function source code
            target_name: Name of the target function
            max_chars: Maximum character limit

        Returns:
            Truncated source context string
        """
        # Strategy 1: Full source fits
        if full_source and len(full_source) <= max_chars:
            return full_source

        if not full_source:
            return func_source[:max_chars] if func_source else ""

        lines = full_source.split('\n')

        # Extract header: pragma, imports, state variables (before first function)
        header_lines = []
        for i, line in enumerate(lines):
            stripped = line.strip()
            if re.match(r'^\s*(function|constructor|modifier|receive|fallback)\s', stripped):
                break
            header_lines.append(line)

        header = '\n'.join(header_lines)

        # Find the target function in full source
        target_func_lines = []
        target_start = -1
        for i, line in enumerate(lines):
            if re.match(rf'^\s*function\s+{re.escape(target_name)}\s*\(', line):
                target_start = i
                break

        if target_start >= 0:
            target_end = self._find_func_end_in_lines(lines, target_start)
            target_func_lines = lines[target_start:target_end + 1]
        target_func_text = '\n'.join(target_func_lines) if target_func_lines else func_source

        # Find internal function calls within target function and extract those functions
        internal_funcs_text = ""
        if target_func_text:
            # Find function calls that might be internal (not prefixed with object.)
            internal_calls = set(re.findall(r'(?<![.\w])(\w+)\s*\(', target_func_text))
            # Filter out common Solidity keywords and the target itself
            keywords = {'require', 'assert', 'revert', 'emit', 'if', 'for', 'while',
                        'return', 'delete', 'new', target_name, 'msg', 'block', 'tx',
                        'abi', 'keccak256', 'sha256', 'ecrecover', 'addmod', 'mulmod',
                        'selfdestruct', 'super', 'this', 'type'}
            internal_calls -= keywords

            found_funcs = []
            for func_name in internal_calls:
                for i, line in enumerate(lines):
                    if re.match(rf'^\s*function\s+{re.escape(func_name)}\s*\(', line):
                        func_end = self._find_func_end_in_lines(lines, i)
                        found_funcs.append('\n'.join(lines[i:func_end + 1]))
                        break

            if found_funcs:
                internal_funcs_text = '\n\n'.join(found_funcs)

        # Strategy 2: Assemble header + target + internal functions
        parts = []
        if header.strip():
            parts.append(header.rstrip())
        parts.append("")  # separator
        if target_func_text:
            parts.append(target_func_text)
        if internal_funcs_text:
            parts.append("")
            parts.append("// --- Internal functions called by " + target_name + " ---")
            parts.append(internal_funcs_text)

        assembled = '\n'.join(parts)
        if len(assembled) <= max_chars:
            return assembled

        # Truncate internal functions if still too long
        parts_no_internal = []
        if header.strip():
            parts_no_internal.append(header.rstrip())
        parts_no_internal.append("")
        if target_func_text:
            parts_no_internal.append(target_func_text)
        assembled_no_internal = '\n'.join(parts_no_internal)
        if len(assembled_no_internal) <= max_chars:
            remaining = max_chars - len(assembled_no_internal) - 50
            if remaining > 0 and internal_funcs_text:
                return assembled_no_internal + "\n\n// --- Internal functions (truncated) ---\n" + internal_funcs_text[:remaining]
            return assembled_no_internal

        # Strategy 3: Fallback to just target function
        return (func_source or target_func_text)[:max_chars]

    def _extract_json_object(self, text: str) -> Optional[str]:
        """
        Extract a JSON object from text using balanced brace matching.
        Correctly handles strings with escaped characters and nested structures.

        Returns the first valid JSON object string, or None.
        """
        start = text.find('{')
        if start == -1:
            return None

        depth = 0
        in_string = False
        escape_next = False
        i = start

        while i < len(text):
            ch = text[i]

            if escape_next:
                escape_next = False
                i += 1
                continue

            if ch == '\\' and in_string:
                escape_next = True
                i += 1
                continue

            if ch == '"' and not escape_next:
                in_string = not in_string
                i += 1
                continue

            if not in_string:
                if ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        return text[start:i + 1]

            i += 1

        return None

    def analyze(
        self,
        contract_file: str,
        analysis_result: Dict[str, Any],
        external_call: Dict[str, Any]
    ) -> SemanticDescription:
        """
        Analyze a single external call and generate semantic description.

        Args:
            contract_file: Path to the contract file
            analysis_result: Result from AnalyzerAgent
            external_call: Information about the specific external call

        Returns:
            SemanticDescription with semantic analysis
        """
        logger.info(f"SemanticAgent analyzing: {external_call.get('external_call', {}).get('signature', 'unknown')}")

        try:
            # Extract key information
            target_func = external_call.get("target_function", {})
            ext_call_info = external_call.get("external_call", {})
            conditions = external_call.get("conditions", [])

            target_sig = target_func.get("signature", "Unknown")
            target_name = target_sig.split("(")[0] if "(" in target_sig else target_sig
            ext_sig = ext_call_info.get("signature", "Unknown")
            return_types = ext_call_info.get("return_types", [])

            # Read complete contract source
            full_source_result = self.tools.execute(
                "read_source", contract_file=contract_file
            )
            full_source = full_source_result.data.get("source_code", "") if full_source_result.success else ""

            # Read target function source (fallback + used for variable extraction)
            func_source_result = self.tools.execute(
                "read_source",
                contract_file=contract_file,
                function_name=target_name,
                context_lines=15
            )
            func_source = func_source_result.data.get("source_code", "") if func_source_result.success else ""

            # Python-side extraction of return value variable name
            call_expression = ext_call_info.get("expression", "")
            return_var_name = self._extract_return_variable(
                full_source or func_source, call_expression
            )

            # Smart truncation: prefer full source, truncate if too long
            source_context = self._prepare_source_context(
                full_source, func_source, target_name, 6000
            )

            # Get protocol information
            protocol_result = self.tools.execute(
                "detect_protocol",
                function_signature=ext_sig,
                get_info=True
            )

            protocol = "Generic"
            protocol_info = {}
            if protocol_result.success:
                protocol = protocol_result.data.get("protocol", "Generic")
                protocol_info = protocol_result.data.get("protocol_info", {})

            # Build the prompt for semantic analysis
            prompt = self._build_semantic_prompt(
                target_sig=target_sig,
                ext_sig=ext_sig,
                return_types=return_types,
                conditions=conditions,
                source_context=source_context,
                protocol=protocol,
                protocol_info=protocol_info,
                return_var_hint=return_var_name,
                call_expression=call_expression
            )

            # Generate semantic description using LLM
            messages = [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": prompt}
            ]

            response = self.llm.generate(messages)

            # Parse the response
            semantic_desc = self._parse_semantic_response(response, ext_sig)

            return semantic_desc

        except Exception as e:
            logger.error(f"SemanticAgent error: {e}")
            # Return a basic description on error
            return SemanticDescription(
                external_call_signature=external_call.get("external_call", {}).get("signature", "Unknown"),
                business_purpose="Unable to determine - analysis failed",
                return_value_meaning="Unknown",
                value_constraints=[],
                boundary_impact={},
                suggested_test_scenarios=[]
            )

    def _build_semantic_prompt(
        self,
        target_sig: str,
        ext_sig: str,
        return_types: List[str],
        conditions: List[Dict],
        source_context: str,
        protocol: str,
        protocol_info: Dict,
        return_var_hint: str = "",
        call_expression: str = ""
    ) -> str:
        """Build the prompt for semantic analysis."""
        from context_agent.core.evm_context import get_evm_context
        evm_ctx = get_evm_context()

        conditions_text = ""
        if conditions:
            cond_items = []
            for cond in conditions:
                cond_items.append(f"  - Type: {cond.get('type', 'unknown')}")
                cond_items.append(f"    Expression: {cond.get('expression', 'unknown')}")
                cond_items.append(f"    Atomics: {cond.get('atomic_conditions', [])}")
            conditions_text = "\n".join(cond_items)
        else:
            conditions_text = "  No specific conditions found"

        # Variable hint section
        var_hint_text = return_var_hint if return_var_hint else "(please identify from source)"
        trace_target = f"`{return_var_hint}`" if return_var_hint else "the return value variable"

        return f"""## Contract Source Code
```solidity
{source_context[:6000] if source_context else 'Source not available'}
```

## TASK: Trace return value constraints (PRIMARY)

**Target Function**: `{target_sig}`
**External Call**: `{ext_sig}`
**Call Expression**: `{call_expression if call_expression else ext_sig}`
**Return Value Variable**: {var_hint_text}
**Return Types**: {', '.join(return_types) if return_types else 'void'}
**Protocol Type**: {protocol}

CRITICAL: Trace {trace_target} through ALL subsequent operations in the source code above.
Find every require/assert/if/revert that depends on it, even indirectly through arithmetic or function calls.

## Static Analysis Conditions (for reference)
{conditions_text}

## Protocol Information
{json.dumps(protocol_info, indent=2) if protocol_info else 'No protocol-specific info'}

{evm_ctx.to_prompt_section()}

## Secondary Analysis
Also provide:
- Business Purpose: Why is this call made?
- Return Value Meaning: What does the return value represent?
- Value Constraints: What semantic constraints apply?
- Boundary Impact: How do edge values affect the logic?
- Suggested Test Scenarios: What should be tested?

## Output Format
Provide your analysis as a JSON object with these keys (implicit_constraints FIRST):
- implicit_constraints (array of objects, each with "data_flow_chain", "condition_expression", "return_value_constraint")
- business_purpose (string)
- return_value_meaning (string)
- value_constraints (array of strings)
- boundary_impact (object mapping boundary type to impact description)
- suggested_test_scenarios (array of strings)

Final Answer:"""

    def _parse_semantic_response(self, response: str, ext_sig: str) -> SemanticDescription:
        """Parse the LLM response into a SemanticDescription."""
        # Try balanced-brace extraction first
        json_str = self._extract_json_object(response)

        if json_str:
            try:
                data = json.loads(json_str)
                return SemanticDescription(
                    external_call_signature=ext_sig,
                    business_purpose=data.get("business_purpose", ""),
                    return_value_meaning=data.get("return_value_meaning", ""),
                    value_constraints=data.get("value_constraints", []),
                    boundary_impact=data.get("boundary_impact", {}),
                    suggested_test_scenarios=data.get("suggested_test_scenarios", []),
                    implicit_constraints=data.get("implicit_constraints", [])
                )
            except json.JSONDecodeError:
                pass

        # Fallback: legacy regex (for simple responses)
        json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', response, re.DOTALL)
        if json_match:
            try:
                data = json.loads(json_match.group())
                return SemanticDescription(
                    external_call_signature=ext_sig,
                    business_purpose=data.get("business_purpose", ""),
                    return_value_meaning=data.get("return_value_meaning", ""),
                    value_constraints=data.get("value_constraints", []),
                    boundary_impact=data.get("boundary_impact", {}),
                    suggested_test_scenarios=data.get("suggested_test_scenarios", []),
                    implicit_constraints=data.get("implicit_constraints", [])
                )
            except json.JSONDecodeError:
                pass

        # Fallback: try to extract information from plain text
        return SemanticDescription(
            external_call_signature=ext_sig,
            business_purpose=self._extract_section(response, "business purpose"),
            return_value_meaning=self._extract_section(response, "return value"),
            value_constraints=[],
            boundary_impact={},
            suggested_test_scenarios=[]
        )

    def _extract_section(self, text: str, section_name: str) -> str:
        """Extract a section from plain text response."""
        pattern = rf'{section_name}[:\s]*([^\n]+)'
        match = re.search(pattern, text, re.IGNORECASE)
        return match.group(1).strip() if match else ""

    def analyze_all(
        self,
        contract_file: str,
        analysis_result: Dict[str, Any]
    ) -> Dict[str, SemanticDescription]:
        """
        Analyze all external calls in the analysis result.

        Args:
            contract_file: Path to the contract file
            analysis_result: Result from AnalyzerAgent

        Returns:
            Dictionary mapping external call signatures to their semantic descriptions
        """
        external_calls = analysis_result.get("external_calls", [])
        results = {}

        for ext_call in external_calls:
            ext_sig = ext_call.get("external_call", {}).get("signature", "")
            if ext_sig and ext_sig not in results:
                semantic_desc = self.analyze(contract_file, analysis_result, ext_call)
                results[ext_sig] = semantic_desc

        return results

    def run(self, task: str, context: Dict[str, Any] = None) -> AgentResult:
        """
        Run the semantic agent.

        Args:
            task: Task description
            context: Context with contract_file, analysis_result, and optionally external_call

        Returns:
            AgentResult with semantic descriptions
        """
        context = context or {}

        if "contract_file" in context and "analysis_result" in context:
            if "external_call" in context:
                # Analyze single external call
                semantic_desc = self.analyze(
                    context["contract_file"],
                    context["analysis_result"],
                    context["external_call"]
                )
                return AgentResult(
                    success=True,
                    output=semantic_desc.to_dict()
                )
            else:
                # Analyze all external calls
                results = self.analyze_all(
                    context["contract_file"],
                    context["analysis_result"]
                )
                return AgentResult(
                    success=True,
                    output={k: v.to_dict() for k, v in results.items()}
                )

        # Use ReAct loop for complex tasks
        return super().run(task, context)
