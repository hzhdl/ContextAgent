#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Batch processing script for contract dataset using Context Agent.

This script processes multiple smart contracts in batch mode to generate
mock return values for external calls.

Usage:
    # Process all contracts in directory
    python -m context_agent.batch_process_dataset

    # Process with custom settings
    python -m context_agent.batch_process_dataset --contracts-dir /path/to/contracts --output-dir /path/to/output

    # Process with parallel workers
    python -m context_agent.batch_process_dataset --workers 4

    # Limit number of contracts (for testing)
    python -m context_agent.batch_process_dataset --limit 10
"""

import os
import sys
import json
import argparse
import logging
import time
import glob
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from concurrent.futures import ProcessPoolExecutor, as_completed

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Default paths
DEFAULT_CONTRACTS_DIR = "/home/hzh/AMFuzz/benchmark/amfuzz_vul_cost"
DEFAULT_OUTPUT_DIR = "/home/hzh/AMFuzz/benchmark/amfuzz_vul_cost"


def extract_contract_name(filename: str) -> str:
    """
    Extract contract name from filename.

    Filename format: ContractName_0xaddress.sol
    Returns the part before the last underscore.


    Examples:
        A2ACrowdsale_0xc8d2881128dbe1534495a85edf716278b892c037.sol -> A2ACrowdsale
        ABTokenTransfer_0x0a7fa17d89d45370819691e335cb8fe688364632.sol -> ABTokenTransfer
        My_Contract_0xabc123.sol -> My_Contract

    Args:
        filename: The contract filename (with or without path)

    Returns:
        The extracted contract name
    """
    # Get basename without path and extension
    base_name = os.path.basename(filename).replace('.sol', '')

    # Find the last underscore position
    last_underscore = base_name.rfind('_')

    if last_underscore > 0:
        return base_name[:last_underscore]
    else:
        # No underscore found, return the whole name
        return base_name


@dataclass
class ProcessResult:
    """Result of processing a single contract."""
    contract_file: str
    contract_name: str
    success: bool
    output_file: Optional[str] = None
    error: Optional[str] = None
    elapsed_time: float = 0.0
    target_functions: int = 0
    external_calls: int = 0
    mock_values: int = 0
    skipped: bool = False


def count_mock_values(result: Dict[str, Any]) -> Tuple[int, int, int]:
    """
    Count mock values statistics from result.

    Returns:
        Tuple of (target_functions, external_calls, total_mock_values)
    """
    if "error" in result or "mock_return_values" not in result:
        return 0, 0, 0

    mock_values = result["mock_return_values"]
    target_functions = len(mock_values)
    external_calls = 0
    total_mock_values = 0

    for _, ext_calls in mock_values.items():
        external_calls += len(ext_calls)
        for _, call_info in ext_calls.items():
            mock_vals = call_info.get("mock_values", {})
            for scenario in ["satisfy", "violate", "boundary"]:
                total_mock_values += len(mock_vals.get(scenario, []))

    return target_functions, external_calls, total_mock_values


def process_single_contract(args: Tuple[str, str, bool, int]) -> ProcessResult:
    """
    Process a single contract file.

    Args:
        args: Tuple of (contract_file, output_dir, verbose, max_retries)

    Returns:
        ProcessResult object
    """
    contract_file, output_dir, verbose, max_retries = args

    # Extract contract name from filename (e.g., "ContractName_0xaddress.sol" -> "ContractName")
    contract_name = extract_contract_name(contract_file)

    # Generate output file path
    base_name = os.path.basename(contract_file).replace('.sol', '')
    output_file = os.path.join(output_dir, f"{base_name}_mock_return_values.json")

    # Skip if output already exists
    if os.path.exists(output_file):
        try:
            with open(output_file, 'r') as f:
                result = json.load(f)

            # Check if it's a valid result (not an error file)
            if "error" not in result:
                target_funcs, ext_calls, mock_vals = count_mock_values(result)
                return ProcessResult(
                    contract_file=contract_file,
                    contract_name=result.get("contract_name", contract_name),
                    success=True,
                    output_file=output_file,
                    target_functions=target_funcs,
                    external_calls=ext_calls,
                    mock_values=mock_vals,
                    skipped=True
                )
        except Exception:
            pass  # Continue to reprocess

    start_time = time.time()

    try:
        # Import here to avoid issues with multiprocessing
        try:
            from .pipeline import generate_mock_return_values
        except ImportError:
            from pipeline import generate_mock_return_values

        result = generate_mock_return_values(
            contract_file=contract_file,
            contract_name=contract_name,  # Use extracted contract name
            output_file=output_file,
            verbose=verbose,
            max_retries=max_retries
        )

        elapsed_time = time.time() - start_time

        if "error" in result:
            return ProcessResult(
                contract_file=contract_file,
                contract_name=contract_name,
                success=False,
                error=result["error"],
                elapsed_time=elapsed_time
            )

        target_funcs, ext_calls, mock_vals = count_mock_values(result)

        return ProcessResult(
            contract_file=contract_file,
            contract_name=result.get("contract_name", contract_name),
            success=True,
            output_file=output_file,
            elapsed_time=elapsed_time,
            target_functions=target_funcs,
            external_calls=ext_calls,
            mock_values=mock_vals
        )

    except Exception as e:
        elapsed_time = time.time() - start_time
        return ProcessResult(
            contract_file=contract_file,
            contract_name=contract_name,
            success=False,
            error=str(e),
            elapsed_time=elapsed_time
        )


def find_contract_files(directory: str, limit: Optional[int] = None) -> List[str]:
    """
    Find all Solidity contract files in a directory.

    Args:
        directory: Directory to search
        limit: Maximum number of files to return

    Returns:
        List of contract file paths
    """
    pattern = os.path.join(directory, "*.sol")
    files = sorted(glob.glob(pattern))

    if limit and limit > 0:
        files = files[:limit]

    return files


def print_progress(current: int, total: int, result: ProcessResult) -> None:
    """Print progress for a single contract."""
    name = os.path.basename(result.contract_file)

    if result.skipped:
        status = "SKIP"
        print(f"  [{current}/{total}] [{status}] {name}")
    elif result.success:
        status = "OK"
        print(f"  [{current}/{total}] [{status}] {name} "
              f"(funcs={result.target_functions}, calls={result.external_calls}, "
              f"values={result.mock_values}, time={result.elapsed_time:.2f}s)")
    else:
        status = "FAIL"
        error_preview = result.error[:50] + "..." if len(result.error) > 50 else result.error
        print(f"  [{current}/{total}] [{status}] {name} - {error_preview}")


def save_batch_report(
    results: List[ProcessResult],
    output_dir: str,
    total_time: float
) -> str:
    """
    Save batch processing report to JSON file.

    Args:
        results: List of ProcessResult objects
        output_dir: Directory to save report
        total_time: Total elapsed time

    Returns:
        Path to the report file
    """
    success_count = sum(1 for r in results if r.success and not r.skipped)
    skipped_count = sum(1 for r in results if r.skipped)
    fail_count = sum(1 for r in results if not r.success)

    report = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_contracts": len(results),
            "successful": success_count,
            "skipped": skipped_count,
            "failed": fail_count,
            "success_rate": f"{(success_count + skipped_count) / len(results) * 100:.1f}%",
            "total_time_seconds": total_time,
            "total_target_functions": sum(r.target_functions for r in results),
            "total_external_calls": sum(r.external_calls for r in results),
            "total_mock_values": sum(r.mock_values for r in results)
        },
        "results": []
    }

    for r in results:
        report["results"].append({
            "contract_file": r.contract_file,
            "contract_name": r.contract_name,
            "success": r.success,
            "skipped": r.skipped,
            "output_file": r.output_file,
            "error": r.error,
            "elapsed_time": r.elapsed_time,
            "target_functions": r.target_functions,
            "external_calls": r.external_calls,
            "mock_values": r.mock_values
        })

    report_path = os.path.join(output_dir, "batch_processing_report.json")
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    return report_path


def print_batch_summary(results: List[ProcessResult], total_time: float) -> None:
    """Print summary of batch processing results."""
    print("\n" + "=" * 70)
    print("Batch Processing Summary")
    print("=" * 70)

    success_count = sum(1 for r in results if r.success and not r.skipped)
    skipped_count = sum(1 for r in results if r.skipped)
    fail_count = sum(1 for r in results if not r.success)

    print(f"\n  Total Contracts: {len(results)}")
    print(f"  Successful: {success_count}")
    print(f"  Skipped (already processed): {skipped_count}")
    print(f"  Failed: {fail_count}")
    print(f"  Success Rate: {(success_count + skipped_count) / len(results) * 100:.1f}%")
    print(f"  Total Time: {total_time:.2f}s")

    if success_count > 0:
        avg_time = sum(r.elapsed_time for r in results if r.success and not r.skipped) / success_count
        print(f"  Average Time per Contract: {avg_time:.2f}s")

    # Aggregate statistics
    total_target_funcs = sum(r.target_functions for r in results)
    total_ext_calls = sum(r.external_calls for r in results)
    total_mock_vals = sum(r.mock_values for r in results)

    print(f"\n  Statistics:")
    print(f"    Total Target Functions: {total_target_funcs}")
    print(f"    Total External Calls: {total_ext_calls}")
    print(f"    Total Mock Values: {total_mock_vals}")

    # List failed contracts (first 10)
    if fail_count > 0:
        print(f"\n  Failed Contracts (showing first 10):")
        failed = [r for r in results if not r.success][:10]
        for r in failed:
            name = os.path.basename(r.contract_file)
            error_preview = r.error[:50] + "..." if len(r.error) > 50 else r.error
            print(f"    - {name}: {error_preview}")

        if fail_count > 10:
            print(f"    ... and {fail_count - 10} more")

    print("=" * 70)


def batch_process(
    contracts_dir: str,
    output_dir: str,
    workers: int = 1,
    limit: Optional[int] = None,
    verbose: bool = False,
    max_retries: int = 3
) -> bool:
    """
    Process multiple contracts in batch.

    Args:
        contracts_dir: Directory containing contract files
        output_dir: Directory to save output files
        workers: Number of parallel workers
        limit: Maximum number of contracts to process
        verbose: Enable verbose logging
        max_retries: Maximum retries for generation

    Returns:
        True if all contracts processed successfully
    """
    print("\n" + "=" * 70)
    print("Context Agent - Batch Dataset Processing")
    print("=" * 70)
    print(f"Contracts Directory: {contracts_dir}")
    print(f"Output Directory: {output_dir}")
    print(f"Workers: {workers}")
    print(f"Limit: {limit or 'None'}")
    print(f"Verbose: {verbose}")
    print(f"Max Retries: {max_retries}")
    print("=" * 70)

    # Validate directory
    if not os.path.isdir(contracts_dir):
        print(f"\nERROR: Directory not found: {contracts_dir}")
        return False

    # Find contract files
    contract_files = find_contract_files(contracts_dir, limit)
    if not contract_files:
        print(f"\nERROR: No .sol files found in {contracts_dir}")
        return False

    print(f"\nFound {len(contract_files)} contract files")

    # Create output directory
    os.makedirs(output_dir, exist_ok=True)

    # Prepare arguments for processing
    process_args = [
        (contract_file, output_dir, verbose, max_retries)
        for contract_file in contract_files
    ]

    # Process contracts
    print("\nProcessing contracts...")
    results: List[ProcessResult] = []
    total_start_time = time.time()

    if workers > 1:
        # Parallel processing
        print(f"Using {workers} parallel workers")
        with ProcessPoolExecutor(max_workers=workers) as executor:
            future_to_file = {
                executor.submit(process_single_contract, args): args[0]
                for args in process_args
            }

            completed = 0
            for future in as_completed(future_to_file):
                completed += 1
                result = future.result()
                results.append(result)
                print_progress(completed, len(contract_files), result)
    else:
        # Sequential processing
        for i, args in enumerate(process_args, 1):
            result = process_single_contract(args)
            results.append(result)
            print_progress(i, len(contract_files), result)

    total_time = time.time() - total_start_time

    # Print summary
    print_batch_summary(results, total_time)

    # Save report
    report_path = save_batch_report(results, output_dir, total_time)
    print(f"\nBatch report saved to: {report_path}")

    # Return success if no failures
    fail_count = sum(1 for r in results if not r.success)
    return fail_count == 0


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Batch process contracts using Context Agent"
    )
    parser.add_argument(
        "--contracts-dir", "-d",
        type=str,
        default=DEFAULT_CONTRACTS_DIR,
        help=f"Directory containing Solidity contracts (default: {DEFAULT_CONTRACTS_DIR})"
    )
    parser.add_argument(
        "--output-dir", "-o",
        type=str,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory for results (default: {DEFAULT_OUTPUT_DIR})"
    )
    parser.add_argument(
        "--workers", "-w",
        type=int,
        default=1,
        help="Number of parallel workers (default: 1)"
    )
    parser.add_argument(
        "--limit", "-l",
        type=int,
        help="Maximum number of contracts to process"
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
        help="Maximum retries for generation (default: 3)"
    )

    args = parser.parse_args()

    # Run batch processing
    success = batch_process(
        contracts_dir=args.contracts_dir,
        output_dir=args.output_dir,
        workers=args.workers,
        limit=args.limit,
        verbose=args.verbose,
        max_retries=args.max_retries
    )

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
