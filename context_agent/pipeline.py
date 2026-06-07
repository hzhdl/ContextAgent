#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Main pipeline for the Context Agent system.

This module provides the main entry point for generating mock return values
using the multi-agent architecture.

Usage:
    # Python API
    from context_agent.pipeline import generate_mock_return_values
    result = generate_mock_return_values(
        contract_file="/path/to/Contract.sol",
        contract_name="ContractName",
        output_file="/path/to/output.json"
    )

    # Command line
    python -m context_agent.pipeline --contract /path/to/Contract.sol --name ContractName --output /path/to/output.json
"""

import json
import os
import sys
import logging
import argparse
from typing import Any, Dict, Optional

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def generate_mock_return_values(
    contract_file: str,
    contract_name: str = None,
    output_file: str = None,
    verbose: bool = False,
    max_retries: int = 3
) -> Dict[str, Any]:
    """
    Generate mock return values for a smart contract using the Context Agent system.

    This is the main entry point for the Context Agent pipeline. It:
    1. Initializes the LLM client based on settings
    2. Creates the OrchestratorAgent with all sub-agents
    3. Runs the analysis and generation pipeline
    4. Optionally saves results to a JSON file

    Args:
        contract_file: Path to the Solidity contract file
        contract_name: Optional contract name (auto-detected if not provided)
        output_file: Optional path to save the JSON output
        verbose: Whether to enable verbose logging
        max_retries: Maximum retries for generation failures

    Returns:
        Dictionary containing the complete mock return values

    Example:
        >>> result = generate_mock_return_values(
        ...     contract_file="/path/to/MyContract.sol",
        ...     contract_name="MyContract",
        ...     output_file="/path/to/output.json"
        ... )
        >>> print(result["contract_name"])
        MyContract
    """
    # Set logging level
    if verbose:
        logging.getLogger("context_agent").setLevel(logging.DEBUG)

    logger.info(f"Context Agent pipeline starting for: {contract_file}")

    # Validate input file
    if not os.path.exists(contract_file):
        error_msg = f"Contract file not found: {contract_file}"
        logger.error(error_msg)
        return {"error": error_msg, "contract_file": contract_file}

    try:
        # Import here to avoid circular imports
        from context_agent.llm.client import create_llm_client
        from context_agent.llm.config import LLMConfig
        from context_agent.agents.orchestrator import OrchestratorAgent
        from context_agent.agent_config import AgentConfig

        # Initialize LLM client
        logger.info("Initializing LLM client...")
        try:
            config = LLMConfig.from_settings()
        except Exception as e:
            logger.warning(f"Could not load settings, using defaults: {e}")
            config = LLMConfig()

        llm_client = create_llm_client(config)
        logger.info(f"LLM client initialized: provider={config.provider}, model={config.model}")

        # Load agent config
        agent_config = AgentConfig.from_settings()
        print("-------------",agent_config.semantic_enable)

        # Create orchestrator
        logger.info("Creating OrchestratorAgent...")
        orchestrator = OrchestratorAgent(
            llm_client=llm_client,
            max_retries=max_retries,
            verbose=verbose,
            semantic_enable=agent_config.semantic_enable
        )

        # Run the pipeline
        logger.info("Running analysis and generation pipeline...")
        result = orchestrator.process_contract(
            contract_file=contract_file,
            contract_name=contract_name
        )

        # Check for errors
        if "error" in result:
            logger.error(f"Pipeline failed: {result['error']}")
            return result

        # Save to file if requested
        if output_file:
            save_result(result, output_file)
            logger.info(f"Results saved to: {output_file}")

        # Log summary
        mock_values = result.get("mock_return_values", {})
        total_calls = sum(len(calls) for calls in mock_values.values())
        logger.info(f"Pipeline completed: {len(mock_values)} target functions, {total_calls} external calls")

        return result

    except ImportError as e:
        error_msg = f"Import error - missing dependencies: {e}"
        logger.error(error_msg)
        return {"error": error_msg, "contract_file": contract_file}

    except Exception as e:
        error_msg = f"Pipeline error: {e}"
        logger.error(error_msg, exc_info=True)
        return {"error": error_msg, "contract_file": contract_file}


def save_result(result: Dict[str, Any], output_file: str) -> None:
    """
    Save the result to a JSON file.

    Args:
        result: The result dictionary to save
        output_file: Path to the output file
    """
    # Ensure directory exists
    output_dir = os.path.dirname(output_file)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    # Write JSON file
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False, default=str)


def batch_process(
    contract_files: list,
    output_dir: str,
    contract_names: list = None,
    verbose: bool = False,
    max_retries: int = 3
) -> list:
    """
    Process multiple contracts in batch.

    Args:
        contract_files: List of contract file paths
        output_dir: Directory to save output files
        contract_names: Optional list of contract names
        verbose: Whether to enable verbose logging
        max_retries: Maximum retries for generation failures

    Returns:
        List of result dictionaries with processing status
    """
    os.makedirs(output_dir, exist_ok=True)

    if contract_names is None:
        contract_names = [None] * len(contract_files)

    results = []

    for i, contract_file in enumerate(contract_files):
        # Generate output filename
        basename = os.path.basename(contract_file).replace('.sol', '')
        output_file = os.path.join(output_dir, f"{basename}_mock_return_values.json")

        # Skip if output already exists
        if os.path.exists(output_file):
            logger.info(f"Skipping {contract_file} - output already exists")
            results.append({
                "contract_file": contract_file,
                "output_file": output_file,
                "success": True,
                "skipped": True
            })
            continue

        logger.info(f"Processing {i+1}/{len(contract_files)}: {contract_file}")

        result = generate_mock_return_values(
            contract_file=contract_file,
            contract_name=contract_names[i] if i < len(contract_names) else None,
            output_file=output_file,
            verbose=verbose,
            max_retries=max_retries
        )

        results.append({
            "contract_file": contract_file,
            "output_file": output_file,
            "success": "error" not in result,
            "error": result.get("error") if "error" in result else None,
            "skipped": False
        })

    # Summary
    success_count = sum(1 for r in results if r["success"] and not r.get("skipped"))
    skipped_count = sum(1 for r in results if r.get("skipped"))
    failed_count = len(results) - success_count - skipped_count

    logger.info(f"Batch processing complete: {success_count} successful, {failed_count} failed, {skipped_count} skipped")

    return results


def main():
    """Command-line interface for the Context Agent pipeline."""
    parser = argparse.ArgumentParser(
        description="Context Agent - Generate mock return values for smart contracts"
    )
    parser.add_argument(
        "--contract", "-c",
        required=True,
        help="Path to the Solidity contract file or directory for batch processing"
    )
    parser.add_argument(
        "--name", "-n",
        help="Contract name (optional, auto-detected if not provided)"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output JSON file path (default: <contract>_mock_return_values.json)"
    )
    parser.add_argument(
        "--output-dir",
        help="Output directory for batch processing"
    )
    parser.add_argument(
        "--batch", "-b",
        action="store_true",
        help="Enable batch processing mode (contract arg should be a directory)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=3,
        help="Maximum retries for generation failures (default: 3)"
    )

    args = parser.parse_args()

    if args.batch:
        # Batch processing mode
        if not os.path.isdir(args.contract):
            print(f"Error: {args.contract} is not a directory")
            sys.exit(1)

        import glob
        contract_files = glob.glob(os.path.join(args.contract, "*.sol"))

        if not contract_files:
            print(f"No .sol files found in {args.contract}")
            sys.exit(1)

        output_dir = args.output_dir or args.contract

        results = batch_process(
            contract_files=contract_files,
            output_dir=output_dir,
            verbose=args.verbose,
            max_retries=args.max_retries
        )

        # Print summary
        print("\n" + "=" * 60)
        print("Batch Processing Summary")
        print("=" * 60)
        for r in results:
            status = "SKIP" if r.get("skipped") else ("OK" if r["success"] else "FAIL")
            print(f"  [{status}] {os.path.basename(r['contract_file'])}")
            if r.get("error"):
                print(f"       Error: {r['error']}")

    else:
        # Single file mode
        output_file = args.output
        if not output_file:
            output_file = args.contract.replace('.sol', '_mock_return_values.json')

        result = generate_mock_return_values(
            contract_file=args.contract,
            contract_name=args.name,
            output_file=output_file,
            verbose=args.verbose,
            max_retries=args.max_retries
        )

        if "error" in result:
            print(f"\nError: {result['error']}")
            sys.exit(1)
        else:
            print(f"\nSuccess! Results saved to: {output_file}")

            # Print summary
            mock_values = result.get("mock_return_values", {})
            total_calls = sum(len(calls) for calls in mock_values.values())
            print(f"  Contract: {result.get('contract_name', 'Unknown')}")
            print(f"  Target functions: {len(mock_values)}")
            print(f"  External calls: {total_calls}")


if __name__ == "__main__":
    main()
