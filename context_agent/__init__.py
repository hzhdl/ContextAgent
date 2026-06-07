#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Context Agent System for AMFuzz

This module provides a multi-agent architecture for generating mock return values
for external contract calls in smart contract fuzzing.

The system uses a layered orchestrator pattern with the following agents:
- AnalyzerAgent: Static analysis using Slither
- SemanticAgent: Semantic understanding of external calls
- GeneratorAgent: Mock value generation based on semantics
- ValidatorAgent: Validation and correction of generated values
- OrchestratorAgent: Coordination and task distribution

Usage:
    # Single contract processing
    from context_agent.pipeline import generate_mock_return_values
    generate_mock_return_values(contract_file, contract_name, output_path)

    # Batch processing
    from context_agent.batch_process_dataset import batch_process
    batch_process(contracts_dir, output_dir, workers=4)
"""

from context_agent.pipeline import generate_mock_return_values
from context_agent.batch_process_dataset import batch_process

__version__ = "1.0.0"
__all__ = ["generate_mock_return_values", "batch_process"]
