#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Few-shot examples for the Context Agent system.

These examples help guide the LLM in generating appropriate outputs
by demonstrating the expected format and quality.
"""

FEW_SHOT_EXAMPLES = {
    "semantic_analysis": [
        {
            "input": {
                "external_call": "IERC20(token).balanceOf(user)",
                "target_function": "liquidate(address user, uint256 amount)",
                "condition": "require(balance >= minLiquidationAmount)",
                "protocol": "ERC20"
            },
            "output": {
                "business_purpose": "Query the user's token balance to determine if they have enough collateral to be liquidated. This is a prerequisite check before executing the liquidation logic.",
                "return_value_meaning": "The user's current token balance in the smallest unit (wei). Represents the available collateral that can be seized during liquidation.",
                "value_constraints": [
                    "Must be >= minLiquidationAmount for liquidation to proceed",
                    "Should be <= user's total deposited amount",
                    "Typically ranges from 0 to total supply of the token"
                ],
                "boundary_impact": {
                    "zero": "User has no balance - liquidation will revert with 'insufficient collateral' or similar",
                    "minLiquidationAmount": "Exactly at threshold - boundary case for liquidation eligibility",
                    "max_uint256": "Unrealistic value - could indicate oracle manipulation or overflow exploit"
                },
                "suggested_test_scenarios": [
                    "Normal liquidation with balance > minLiquidationAmount",
                    "Zero balance - should revert",
                    "Balance exactly at minLiquidationAmount - boundary test",
                    "Very small balance below threshold - should revert",
                    "Very large balance - test for overflow issues"
                ]
            }
        },
        {
            "input": {
                "external_call": "IUniswapV2Pair(pair).getReserves()",
                "target_function": "swap(uint256 amountIn, uint256 minAmountOut)",
                "condition": "require(amountOut >= minAmountOut)",
                "protocol": "Uniswap-V2"
            },
            "output": {
                "business_purpose": "Fetch the current reserves of the liquidity pool to calculate the expected output amount for a token swap. The reserves determine the price and available liquidity.",
                "return_value_meaning": "Returns (reserve0, reserve1, blockTimestampLast) where reserve0 and reserve1 are the token amounts in the pool, and timestamp indicates when reserves were last updated.",
                "value_constraints": [
                    "reserve0 * reserve1 should approximately equal K (constant product)",
                    "Both reserves should be > 0 for valid pools",
                    "Reserves must be <= uint112 max (2^112 - 1)",
                    "Timestamp should be recent (within acceptable staleness)"
                ],
                "boundary_impact": {
                    "zero_reserves": "Pool has no liquidity - swap will fail or produce 0 output",
                    "imbalanced": "Very imbalanced reserves indicate high price impact",
                    "max_reserves": "Maximum values might cause overflow in calculations",
                    "stale_timestamp": "Old timestamp might indicate abandoned pool"
                },
                "suggested_test_scenarios": [
                    "Normal pool with balanced reserves",
                    "Empty pool (0, 0) - should handle gracefully",
                    "Highly imbalanced pool (1000:1 ratio)",
                    "Maximum reserve values",
                    "Pool with only one token having liquidity"
                ]
            }
        },
        {
            "input": {
                "external_call": "AggregatorV3Interface(priceFeed).latestRoundData()",
                "target_function": "getAssetPrice(address asset)",
                "condition": "require(updatedAt > block.timestamp - maxStaleness)",
                "protocol": "Chainlink-Oracle"
            },
            "output": {
                "business_purpose": "Retrieve the latest price data from Chainlink oracle to determine current asset valuation. Used for collateral calculations, liquidation thresholds, and fair value assessments.",
                "return_value_meaning": "Returns (roundId, answer, startedAt, updatedAt, answeredInRound). 'answer' is the price with 8 decimals. 'updatedAt' indicates data freshness.",
                "value_constraints": [
                    "answer should be > 0 for valid prices",
                    "updatedAt should be within maxStaleness of current time",
                    "answeredInRound should be >= roundId for valid rounds",
                    "Price should be in reasonable range for the asset"
                ],
                "boundary_impact": {
                    "zero_price": "Price of 0 indicates oracle failure - should trigger emergency mode",
                    "negative_price": "Negative prices are invalid - should revert",
                    "stale_data": "Old updatedAt timestamp should fail staleness check",
                    "extreme_price": "Prices 10x normal might indicate manipulation"
                },
                "suggested_test_scenarios": [
                    "Normal fresh price data",
                    "Zero price - oracle failure",
                    "Stale price data (old timestamp)",
                    "Price at extreme high value",
                    "Price at extreme low value",
                    "Invalid round (answeredInRound < roundId)"
                ]
            }
        }
    ],

    "value_generation": [
        {
            "input": {
                "external_call": "balanceOf(address)",
                "return_types": ["uint256"],
                "condition": "balance > 100 ether",
                "protocol": "ERC20"
            },
            "output": {
                "satisfy": [
                    [1000000000000000000000],     # 1000 ether
                    [500000000000000000000],      # 500 ether
                    [101000000000000000000]       # 101 ether (just above threshold)
                ],
                "violate": [
                    [0],                          # Zero balance
                    [100000000000000000000],      # Exactly 100 ether
                    [50000000000000000000]        # 50 ether (below threshold)
                ],
                "boundary": [
                    [0],                          # Minimum
                    [1],                          # Near minimum
                    [115792089237316195423570985008687907853269984665640564039457584007913129639935]  # uint256 max
                ]
            }
        },
        {
            "input": {
                "external_call": "getReserves()",
                "return_types": ["uint112", "uint112", "uint32"],
                "condition": "reserve0 > 0 && reserve1 > 0",
                "protocol": "Uniswap-V2"
            },
            "output": {
                "satisfy": [
                    [1000000000000000000000, 1000000000000000000000, 1705000000],
                    [5000000000000000000000, 2500000000000000000000, 1705000000],
                    [100000000000000000000, 100000000000000000000, 1705000000]
                ],
                "violate": [
                    [0, 0, 1705000000],
                    [0, 1000000000000000000000, 1705000000],
                    [1000000000000000000000, 0, 1705000000]
                ],
                "boundary": [
                    [1, 1, 1705000000],
                    [5192296858534827628530496329220095, 5192296858534827628530496329220095, 4294967295],
                    [1, 5192296858534827628530496329220095, 1705000000]
                ]
            }
        },
        {
            "input": {
                "external_call": "latestRoundData()",
                "return_types": ["uint80", "int256", "uint256", "uint256", "uint80"],
                "condition": "answer > 0 && updatedAt > block.timestamp - 3600",
                "protocol": "Chainlink-Oracle"
            },
            "output": {
                "satisfy": [
                    [1, 200000000000, 1705000000, 1705000100, 1],
                    [2, 300000000000, 1705000000, 1705000200, 2],
                    [3, 150000000000, 1705000000, 1705000050, 3]
                ],
                "violate": [
                    [1, 0, 1705000000, 1705000100, 1],
                    [1, -100000000, 1705000000, 1705000100, 1],
                    [1, 200000000000, 1705000000, 1704990000, 1]
                ],
                "boundary": [
                    [1, 1, 1705000000, 1705000100, 1],
                    [1, 57896044618658097711785492504343953926634992332820282019728792003956564819967, 1705000000, 1705000100, 1],
                    [1208925819614629174706175, 200000000000, 1705000000, 1705000100, 1208925819614629174706175]
                ]
            }
        },
        {
            "input": {
                "external_call": "latestRoundData()",
                "return_types": ["uint80", "int256", "uint256", "uint256", "uint80"],
                "condition": "updatedAt > block.timestamp - 3600",
                "protocol": "Chainlink-Oracle",
                "evm_context": {
                    "block_timestamp": 1705000000
                }
            },
            "output": {
                "satisfy": [
                    # Fresh data (updated within last hour)
                    [1, 200000000000, 1704999000, 1704999500, 1],  # 500s ago
                    [2, 300000000000, 1704998000, 1704998800, 2],  # 1200s ago
                    [3, 150000000000, 1704999800, 1704999900, 3]   # 100s ago
                ],
                "violate": [
                    # Stale data (updated more than 1 hour ago)
                    [1, 200000000000, 1704990000, 1704995000, 1],  # 5000s ago (>1h)
                    [1, 0, 1704999000, 1704999500, 1],             # Zero price
                    [1, -100000000, 1704999000, 1704999500, 1]     # Negative price
                ],
                "boundary": [
                    # Exactly at threshold (3600s ago)
                    [1, 200000000000, 1704996000, 1704996400, 1],  # Exactly 3600s
                    # Just within threshold
                    [1, 200000000000, 1704996500, 1704996401, 1],  # 3599s ago
                    # Just outside threshold
                    [1, 200000000000, 1704996000, 1704996399, 1]   # 3601s ago
                ]
            },
            "note": "Timestamps calculated relative to block.timestamp (1705000000)"
        }
    ],

    "validation": [
        {
            "input": {
                "mock_values": {
                    "satisfy": [[[1000]]],  # Over-nested
                    "violate": [[0]],
                    "boundary": [["invalid"]]  # Wrong type
                },
                "return_types": ["uint256"],
                "protocol": "ERC20"
            },
            "output": {
                "is_valid": False,
                "validated_values": {
                    "satisfy": [[1000]],
                    "violate": [[0]],
                    "boundary": [[0]]
                },
                "issues": [
                    {"scenario": "satisfy", "index": 0, "issue": "Excessive nesting detected"},
                    {"scenario": "boundary", "index": 0, "issue": "Invalid type - expected uint256"}
                ],
                "corrections": [
                    {
                        "field_index": 0,
                        "current_value": [[1000]],
                        "suggested_value": [1000],
                        "reason": "Flattened over-nested array",
                        "severity": "warning"
                    },
                    {
                        "field_index": 0,
                        "current_value": "invalid",
                        "suggested_value": 0,
                        "reason": "Replaced invalid value with default",
                        "severity": "error"
                    }
                ],
                "summary": "2 issues found: 1 structural issue, 1 type error"
            }
        }
    ]
}


def get_examples_for_task(task_type: str) -> list:
    """
    Get few-shot examples for a specific task type.

    Args:
        task_type: One of "semantic_analysis", "value_generation", "validation"

    Returns:
        List of example dictionaries with input/output pairs
    """
    return FEW_SHOT_EXAMPLES.get(task_type, [])


def format_examples_for_prompt(task_type: str, max_examples: int = 2) -> str:
    """
    Format examples as a string for inclusion in prompts.

    Args:
        task_type: Type of task
        max_examples: Maximum number of examples to include

    Returns:
        Formatted string with examples
    """
    import json

    examples = get_examples_for_task(task_type)[:max_examples]
    if not examples:
        return ""

    parts = ["## Examples\n"]
    for i, example in enumerate(examples, 1):
        parts.append(f"### Example {i}")
        parts.append(f"Input:\n```json\n{json.dumps(example['input'], indent=2)}\n```")
        parts.append(f"Output:\n```json\n{json.dumps(example['output'], indent=2)}\n```\n")

    return "\n".join(parts)
