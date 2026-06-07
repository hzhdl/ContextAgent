#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Analyzer Agent for the Context Agent system.

This agent performs static analysis on smart contracts using Slither
to extract external calls, conditions, and structural information.
"""

import logging
from typing import Any, Dict, List, Optional

from context_agent.core.base_agent import BaseAgent, AgentResult
from context_agent.core.tool_registry import Tool
from context_agent.tools.slither_tool import SlitherTool
from context_agent.tools.protocol_tool import ProtocolTool
from context_agent.tools.selector_tool import SelectorTool

logger = logging.getLogger(__name__)


class AnalyzerAgent(BaseAgent):
    """
    Static analysis agent.

    Responsible for:
    - Running Slither analysis on contracts
    - Extracting external call information
    - Identifying protocol types
    - Building function selector maps
    """

    def __init__(
        self,
        llm_client,
        tools: List[Tool] = None,
        verbose: bool = False
    ):
        """
        Initialize the analyzer agent.

        Args:
            llm_client: LLM client for reasoning
            tools: Optional list of tools (default: Slither, Protocol, Selector)
            verbose: Whether to log detailed info
        """
        # Default tools for analyzer
        default_tools = [
            SlitherTool(),
            ProtocolTool(),
            SelectorTool(),
        ]

        super().__init__(
            name="AnalyzerAgent",
            llm_client=llm_client,
            tools=tools or default_tools,
            max_iterations=5,
            verbose=verbose
        )

    def _get_default_system_prompt(self) -> str:
        return """You are a smart contract static analysis expert.

Your task is to analyze Solidity contracts to extract information about external calls.

For each contract, you should:
1. Use the slither_analyze tool to perform static analysis
2. Use the detect_protocol tool to identify DeFi protocol types for each external call
3. Organize the results in a structured format

When analyzing external calls, pay attention to:
- The function signature of the external call
- The conditions associated with the call (require, if, assert)
- The return types expected from the external call
- The protocol semantics (ERC20, Uniswap, etc.)

Output your analysis in a structured JSON format with:
- external_calls: List of external call information
- protocol_types: Mapping of function signatures to protocols
- conditions: Associated conditions for each call

When you have completed the analysis, provide the Final Answer with the structured result."""

    def analyze(self, contract_file: str, contract_name: str = None) -> Dict[str, Any]:
        """
        Analyze a contract and return structured results.

        This method directly invokes tools without the full ReAct loop
        for efficiency.

        Args:
            contract_file: Path to the contract file
            contract_name: Optional contract name

        Returns:
            Dictionary with analysis results
        """
        logger.info(f"AnalyzerAgent analyzing: {contract_file}")

        try:
            # Run Slither analysis
            slither_result = self.tools.execute(
                "slither_analyze",
                contract_file=contract_file,
                contract_name=contract_name
            )

            if not slither_result.success:
                logger.error(f"Slither analysis failed: {slither_result.error}")
                return {
                    "success": False,
                    "error": slither_result.error
                }

            analysis_data = slither_result.data
            external_calls = analysis_data.get("external_calls", [])

            # Detect protocols for each external call
            protocol_types = {}
            for call in external_calls:
                ext_sig = call.get("external_call", {}).get("signature", "")
                if ext_sig:
                    protocol_result = self.tools.execute(
                        "detect_protocol",
                        function_signature=ext_sig,
                        get_info=True
                    )
                    if protocol_result.success:
                        protocol_types[ext_sig] = protocol_result.data

            # Build final result
            result = {
                "success": True,
                "contract_name": analysis_data.get("contract_name"),
                "contract_file": analysis_data.get("contract_file"),
                "external_calls": external_calls,
                "protocol_types": protocol_types,
                "function_selector_map": analysis_data.get("function_selector_map", {}),
                "total_external_calls": len(external_calls)
            }

            logger.info(f"AnalyzerAgent found {len(external_calls)} external calls")
            return result

        except Exception as e:
            logger.error(f"AnalyzerAgent error: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def run(self, task: str, context: Dict[str, Any] = None) -> AgentResult:
        """
        Run the analyzer agent on a task.

        For simple analysis tasks, this directly calls analyze().
        For complex reasoning tasks, it uses the ReAct loop.

        Args:
            task: Task description
            context: Context with contract_file and optionally contract_name

        Returns:
            AgentResult with analysis results
        """
        context = context or {}

        # If we have direct contract file info, use efficient direct analysis
        if "contract_file" in context:
            analysis_result = self.analyze(
                context["contract_file"],
                context.get("contract_name")
            )

            if analysis_result.get("success"):
                return AgentResult(
                    success=True,
                    output=analysis_result,
                    metadata={"method": "direct_analysis"}
                )
            else:
                return AgentResult(
                    success=False,
                    error=analysis_result.get("error", "Analysis failed")
                )

        # Otherwise, use the ReAct loop for more complex reasoning
        return super().run(task, context)
