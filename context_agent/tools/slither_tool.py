#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Slither static analysis tool for the Context Agent system.

This tool wraps the ExternalCallConditionAnalyzer to provide static analysis
capabilities for smart contracts.
"""

import os
import sys
import logging
from typing import Any, Dict, List, Optional

from context_agent.core.tool_registry import Tool, ToolResult

logger = logging.getLogger(__name__)

# Add utils path for imports
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "utils"))


class SlitherTool(Tool):
    """
    Slither static analysis tool.

    Uses Slither to analyze smart contracts and extract external call
    information and condition constraints.
    """

    @property
    def name(self) -> str:
        return "slither_analyze"

    @property
    def description(self) -> str:
        return (
            "Analyze a Solidity smart contract using Slither to extract "
            "external calls, condition constraints, and function signatures. "
            "Returns structured analysis results including external call points, "
            "associated conditions, and return types."
        )

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "contract_file": {
                    "type": "string",
                    "description": "Path to the Solidity contract file"
                },
                "contract_name": {
                    "type": "string",
                    "description": "Name of the contract to analyze (optional, will auto-detect if not provided)"
                }
            },
            "required": ["contract_file"]
        }

    def execute(self, contract_file: str, contract_name: str = None) -> ToolResult:
        """
        Execute Slither analysis on a contract.

        Args:
            contract_file: Path to the Solidity contract file
            contract_name: Optional contract name to analyze

        Returns:
            ToolResult with analysis results
        """
        try:
            # Validate file exists
            if not os.path.exists(contract_file):
                return ToolResult.error_result(f"Contract file not found: {contract_file}")

            # Import the analyzer
            try:
                from external_call_condition_analyzer import ExternalCallConditionAnalyzer
            except ImportError:
                # Try alternative import path
                sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
                from utils.external_call_condition_analyzer import ExternalCallConditionAnalyzer

            # Run analysis
            logger.info(f"Running Slither analysis on: {contract_file}")
            analyzer = ExternalCallConditionAnalyzer(contract_file, contract_name)
            analysis_result = analyzer.analyze_with_selectors()

            if "error" in analysis_result:
                return ToolResult.error_result(analysis_result["error"])

            # Transform results to a more structured format
            transformed_result = self._transform_analysis_result(analysis_result)

            return ToolResult.success_result(
                transformed_result,
                contract_file=contract_file,
                contract_name=analysis_result.get("contract_name")
            )

        except Exception as e:
            logger.error(f"Slither analysis failed: {e}")
            return ToolResult.error_result(str(e))

    def _transform_analysis_result(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transform raw analysis result to a more structured format.

        Args:
            raw_result: Raw result from ExternalCallConditionAnalyzer

        Returns:
            Transformed result with better structure
        """
        results = raw_result.get("results", {})
        selector_map = raw_result.get("function_selector_map", {})

        external_calls = []

        for target_selector, ext_calls in results.items():
            target_signature = selector_map.get(target_selector, "Unknown")

            for ext_selector, call_data in ext_calls.items():
                call_info = {
                    "target_function": {
                        "selector": target_selector,
                        "signature": target_signature
                    },
                    "external_call": {
                        "selector": ext_selector,
                        "signature": call_data.get("external_function_signature", "Unknown"),
                        "expression": None,
                        "return_types": call_data.get("external_return_types_expanded", [])
                    },
                    "conditions": []
                }

                # Extract condition information
                for condition in call_data.get("conditions", []):
                    call_info["external_call"]["expression"] = condition.get("external_call_expression")
                    # If conditions exist, prefer the return types from conditions
                    # (for backwards compatibility)
                    cond_return_types = condition.get("external_return_types_expanded", [])
                    if cond_return_types:
                        call_info["external_call"]["return_types"] = cond_return_types

                    cond_info = {
                        "type": condition.get("condition_type"),
                        "expression": condition.get("condition_expression"),
                        "line": condition.get("condition_line"),
                        "atomic_conditions": condition.get("atomic_conditions", []),
                        "variables": condition.get("variables_classified", {}),
                        "relationship": condition.get("relationship")
                    }
                    call_info["conditions"].append(cond_info)

                external_calls.append(call_info)

        return {
            "contract_name": raw_result.get("contract_name"),
            "contract_file": raw_result.get("contract_file"),
            "external_calls": external_calls,
            "function_selector_map": selector_map,
            "total_external_calls": len(external_calls)
        }
