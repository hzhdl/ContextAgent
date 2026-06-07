#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Orchestrator Agent for the Context Agent system.

This agent coordinates the execution of all sub-agents to generate
mock return values for smart contract external calls.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from context_agent.core.base_agent import BaseAgent, AgentResult
from context_agent.core.tool_registry import Tool
from context_agent.agents.analyzer_agent import AnalyzerAgent
from context_agent.agents.semantic_agent import SemanticAgent
from context_agent.agents.generator_agent import GeneratorAgent
from context_agent.agents.validator_agent import ValidatorAgent

logger = logging.getLogger(__name__)


class OrchestratorAgent(BaseAgent):
    """
    Orchestrator agent that coordinates all sub-agents.

    The orchestrator manages the pipeline:
    1. AnalyzerAgent: Static analysis
    2. SemanticAgent: Semantic understanding
    3. GeneratorAgent: Mock value generation
    4. ValidatorAgent: Validation and correction

    It handles retries when validation fails and assembles the final result.
    """

    def __init__(
        self,
        llm_client,
        sub_agents: Dict[str, BaseAgent] = None,
        max_retries: int = 3,
        verbose: bool = False,
        semantic_enable: bool = True
    ):
        """
        Initialize the orchestrator agent.

        Args:
            llm_client: LLM client for sub-agents
            sub_agents: Optional pre-configured sub-agents
            max_retries: Maximum retries for generation failures
            verbose: Whether to log detailed info
            semantic_enable: Whether to enable semantic analysis (False for ablation)
        """
        self.max_retries = max_retries
        self.semantic_enable = semantic_enable

        # Initialize sub-agents
        if sub_agents:
            self.analyzer = sub_agents.get("analyzer")
            self.semantic = sub_agents.get("semantic")
            self.generator = sub_agents.get("generator")
            self.validator = sub_agents.get("validator")
        else:
            self.analyzer = AnalyzerAgent(llm_client, verbose=verbose)
            self.semantic = SemanticAgent(llm_client, verbose=verbose)
            self.generator = GeneratorAgent(llm_client, verbose=verbose)
            self.validator = ValidatorAgent(llm_client, verbose=verbose)

        super().__init__(
            name="OrchestratorAgent",
            llm_client=llm_client,
            tools=[],  # Orchestrator uses sub-agents, not direct tools
            max_iterations=1,  # Orchestrator doesn't use ReAct loop
            verbose=verbose
        )

    def _get_default_system_prompt(self) -> str:
        return """You are an orchestration agent coordinating smart contract analysis.

You manage four specialized agents:
1. AnalyzerAgent: Performs static analysis using Slither
2. SemanticAgent: Understands business logic of external calls
3. GeneratorAgent: Generates mock return values
4. ValidatorAgent: Validates and corrects generated values

Your job is to coordinate these agents to produce high-quality mock return values."""

    def process_contract(
        self,
        contract_file: str,
        contract_name: str = None
    ) -> Dict[str, Any]:
        """
        Process a contract to generate mock return values.

        This is the main entry point for the orchestrator.

        Args:
            contract_file: Path to the contract file
            contract_name: Optional contract name

        Returns:
            Dictionary with complete mock return values
        """
        logger.info(f"OrchestratorAgent processing: {contract_file}")

        try:
            # Step 1: Static Analysis
            logger.info("Step 1: Running static analysis...")
            analysis_result = self.analyzer.analyze(contract_file, contract_name)

            if not analysis_result.get("success"):
                return {
                    "error": f"Analysis failed: {analysis_result.get('error', 'Unknown error')}",
                    "contract_file": contract_file
                }

            external_calls = analysis_result.get("external_calls", [])
            if not external_calls:
                logger.info("No external calls found in contract")
                return {
                    "contract_name": analysis_result.get("contract_name"),
                    "contract_file": contract_file,
                    "mock_return_values": {},
                    "function_selector_map": analysis_result.get("function_selector_map", {})
                }

            logger.info(f"Found {len(external_calls)} external calls")

            # Step 2: Semantic Analysis (can be skipped for ablation)
            if self.semantic_enable:
                logger.info("Step 2: Running semantic analysis...")
                semantic_descriptions = self._run_semantic_analysis(
                    contract_file, analysis_result
                )
            else:
                logger.info("Step 2: Semantic analysis SKIPPED (ablation mode)")
                semantic_descriptions = {}

            # Step 3 & 4: Generation and Validation
            logger.info("Steps 3-4: Generating and validating mock values...")
            mock_return_values = self._generate_mock_values(
                external_calls,
                analysis_result.get("protocol_types", {}),
                semantic_descriptions
            )

            # Check if generation failed
            if mock_return_values is None:
                return {
                    "error": "Failed to generate mock values for one or more external calls after all retries",
                    "contract_file": contract_file,
                    "contract_name": analysis_result.get("contract_name")
                }

            # Assemble final result
            result = {
                "contract_name": analysis_result.get("contract_name"),
                "contract_file": contract_file,
                "mock_return_values": mock_return_values,
                "function_selector_map": analysis_result.get("function_selector_map", {})
            }

            logger.info(f"OrchestratorAgent completed processing: {contract_file}")
            return result

        except Exception as e:
            logger.error(f"OrchestratorAgent error: {e}")
            return {
                "error": str(e),
                "contract_file": contract_file
            }

    def _run_semantic_analysis(
        self,
        contract_file: str,
        analysis_result: Dict[str, Any]
    ) -> Dict[str, Dict[str, Any]]:
        """Run semantic analysis on all external calls."""
        semantic_descriptions = {}

        try:
            result = self.semantic.run(
                task="Analyze semantic meaning of external calls",
                context={
                    "contract_file": contract_file,
                    "analysis_result": analysis_result
                }
            )

            if result.success and result.output:
                semantic_descriptions = result.output

        except Exception as e:
            logger.warning(f"Semantic analysis failed: {e}")
            # Continue without semantic descriptions

        return semantic_descriptions

    def _generate_mock_values(
        self,
        external_calls: List[Dict[str, Any]],
        protocol_types: Dict[str, Dict],
        semantic_descriptions: Dict[str, Dict]
    ) -> Optional[Dict[str, Dict[str, Any]]]:
        """
        Generate mock values for all external calls with validation.

        Returns:
            Dict with mock values if all successful, None if any generation failed
        """
        mock_return_values = {}
        failed_calls = []

        for ext_call in external_calls:
            target_func = ext_call.get("target_function", {})
            ext_info = ext_call.get("external_call", {})

            target_selector = target_func.get("selector", "")
            ext_selector = ext_info.get("selector", "")
            ext_sig = ext_info.get("signature", "")
            return_types = ext_info.get("return_types", [])

            if not target_selector:
                continue

            # Initialize target function dict if needed
            if target_selector not in mock_return_values:
                mock_return_values[target_selector] = {}

            # Get protocol info
            protocol_info = protocol_types.get(ext_sig, {})
            protocol = protocol_info.get("protocol", "Generic")

            # Get semantic description
            semantic_desc = semantic_descriptions.get(ext_sig, {})

            # Generate with retry loop
            mock_values = self._generate_with_retry(
                ext_call, protocol, semantic_desc, return_types
            )

            # Check if generation failed
            if mock_values is None:
                failed_calls.append(ext_sig)
                logger.error(f"Generation failed for external call: {ext_sig}")
                continue

            mock_return_values[target_selector][ext_selector] = {
                "external_function_signature": ext_sig,
                "return_types": return_types,
                "mock_values": mock_values
            }

        # If any generation failed, return None to indicate failure
        if failed_calls:
            logger.error(f"Failed to generate mock values for {len(failed_calls)} external call(s): {failed_calls}")
            return None

        return mock_return_values

    def _generate_with_retry(
        self,
        external_call: Dict[str, Any],
        protocol: str,
        semantic_description: Dict[str, Any],
        return_types: List[str]
    ) -> Dict[str, List[List[Any]]]:
        """Generate mock values with retry on validation failure."""
        ext_sig = external_call.get("external_call", {}).get("signature", "Unknown")
        mock_values = None  # 初始化，防止所有重试失败时变量未定义

        for attempt in range(self.max_retries):
            logger.debug(f"Generation attempt {attempt + 1}/{self.max_retries} for {ext_sig}")

            # Generate values
            gen_result = self.generator.run(
                task="Generate mock return values",
                context={
                    "external_call": external_call,
                    "semantic_description": semantic_description,
                    "protocol": protocol
                }
            )

            if not gen_result.success:
                logger.warning(f"Generation failed for {ext_sig}: {gen_result.error}")
                continue

            mock_values = gen_result.output

            # Validate values
            val_result = self.validator.run(
                task="Validate mock return values",
                context={
                    "mock_values": mock_values,
                    "return_types": return_types,
                    "protocol": protocol,
                    "function_signature": ext_sig
                }
            )

            if val_result.success:
                validation = val_result.output

                if validation.get("is_valid"):
                    logger.debug(f"Validation passed for {ext_sig}")
                    return mock_values

                # Use validated (corrected) values if available
                validated_values = validation.get("validated_values")
                if validated_values and self._has_valid_values(validated_values):
                    logger.debug(f"Using corrected values for {ext_sig}")
                    return validated_values

                # Log validation issues for next attempt
                logger.debug(f"Validation issues for {ext_sig}: {validation.get('summary')}")

        # All retries failed, return None to indicate failure
        logger.error(f"All {self.max_retries} retries failed for {ext_sig}")
        return None

    def _has_valid_values(self, mock_values: Dict[str, List]) -> bool:
        """Check if mock_values has at least some valid values."""
        for scenario in ["satisfy", "violate", "boundary"]:
            if mock_values.get(scenario) and len(mock_values[scenario]) > 0:
                return True
        return False

    def run(self, task: str, context: Dict[str, Any] = None) -> AgentResult:
        """
        Run the orchestrator agent.

        Args:
            task: Task description
            context: Context with contract_file and optionally contract_name

        Returns:
            AgentResult with complete mock return values
        """
        context = context or {}

        if "contract_file" in context:
            result = self.process_contract(
                context["contract_file"],
                context.get("contract_name")
            )

            if "error" in result:
                return AgentResult(
                    success=False,
                    error=result["error"],
                    output=result
                )

            return AgentResult(
                success=True,
                output=result
            )

        # For other tasks, return error (orchestrator requires contract_file)
        return AgentResult(
            success=False,
            error="OrchestratorAgent requires 'contract_file' in context"
        )


def create_orchestrator(
    llm_client,
    max_retries: int = 3,
    verbose: bool = False
) -> OrchestratorAgent:
    """
    Factory function to create a fully configured orchestrator.

    Args:
        llm_client: LLM client instance
        max_retries: Maximum retries for generation
        verbose: Whether to enable verbose logging

    Returns:
        Configured OrchestratorAgent
    """
    return OrchestratorAgent(
        llm_client=llm_client,
        max_retries=max_retries,
        verbose=verbose
    )
