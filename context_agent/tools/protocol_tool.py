#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Protocol detection tool for the Context Agent system.

This tool wraps the ProtocolDetector to identify DeFi protocol types
based on function signatures.
"""

import logging
from typing import Any, Dict, List, Optional

from context_agent.core.tool_registry import Tool, ToolResult

logger = logging.getLogger(__name__)



class ProtocolTool(Tool):
    """
    Protocol detection tool.

    Identifies DeFi protocol types based on function signatures,
    supporting ERC20, ERC721, Uniswap, Chainlink, Aave, Compound, and more.
    """

    def __init__(self):
        """Initialize the protocol tool with detector instance."""
        self._detector = None

    def _get_detector(self):
        """Lazily initialize the protocol detector."""
        if self._detector is None:
            from context_agent.tools.protocol_detector import ProtocolDetector
            self._detector = ProtocolDetector()
        return self._detector

    @property
    def name(self) -> str:
        return "detect_protocol"

    @property
    def description(self) -> str:
        return (
            "Detect the DeFi protocol type based on a function signature. "
            "Supports ERC20, ERC721, ERC1155, Uniswap V2/V3, Chainlink Oracle, "
            "Aave, Compound, and Curve protocols. Returns the protocol name and category."
        )

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "function_signature": {
                    "type": "string",
                    "description": "The function signature to analyze (e.g., 'balanceOf(address)')"
                },
                "get_info": {
                    "type": "boolean",
                    "description": "Whether to include detailed protocol info (default: false)"
                }
            },
            "required": ["function_signature"]
        }

    def execute(
        self,
        function_signature: str,
        get_info: bool = False
    ) -> ToolResult:
        """
        Detect protocol type for a function signature.

        Args:
            function_signature: Function signature to analyze
            get_info: Whether to include detailed protocol info

        Returns:
            ToolResult with protocol detection result
        """
        try:
            detector = self._get_detector()

            # Detect protocol
            protocol = detector.detect(function_signature)

            result = {
                "function_signature": function_signature,
                "protocol": protocol,
            }

            # Get additional info if requested
            if get_info:
                info = detector.get_protocol_info(protocol)
                result["protocol_info"] = info

            # Add protocol defaults if it's a known protocol
            if protocol != "Generic":
                result["protocol_defaults"] = self._get_protocol_defaults(protocol, function_signature)

            return ToolResult.success_result(result)

        except Exception as e:
            logger.error(f"Protocol detection failed: {e}")
            return ToolResult.error_result(str(e))

    def _get_protocol_defaults(
        self,
        protocol: str,
        function_signature: str
    ) -> Dict[str, Any]:
        """
        Get default values and constraints for a protocol.

        Args:
            protocol: Protocol name
            function_signature: Function signature

        Returns:
            Dictionary with protocol-specific defaults
        """
        func_name = function_signature.split('(')[0].lower()

        defaults = {
            "ERC20": {
                "balanceof": {
                    "typical_range": [0, 10**30],
                    "common_values": [0, 10**18, 100 * 10**18, 1000 * 10**18],
                    "semantic": "Token balance in smallest unit"
                },
                "allowance": {
                    "typical_range": [0, 2**256 - 1],
                    "common_values": [0, 10**18, 2**256 - 1],
                    "semantic": "Approved spending amount"
                },
                "totalsupply": {
                    "typical_range": [10**18, 10**30],
                    "common_values": [10**24, 10**27],
                    "semantic": "Total token supply"
                },
                "decimals": {
                    "typical_range": [0, 18],
                    "common_values": [6, 8, 18],
                    "semantic": "Token decimal places"
                }
            },
            "Uniswap-V2": {
                "getreserves": {
                    "typical_range": {
                        "reserve0": [0, 2**112 - 1],
                        "reserve1": [0, 2**112 - 1],
                        "timestamp": "current_unix_timestamp"
                    },
                    "constraints": "reserve0 * reserve1 = k (constant product)",
                    "semantic": "Liquidity pool reserves"
                }
            },
            "Chainlink-Oracle": {
                "latestrounddata": {
                    "typical_values": {
                        "roundId": "sequential_integer",
                        "answer": "price_with_8_decimals",
                        "startedAt": "unix_timestamp",
                        "updatedAt": "unix_timestamp_recent",
                        "answeredInRound": "sequential_integer"
                    },
                    "common_prices": [
                        200000000000,  # $2000 (ETH)
                        3000000000000,  # $30000 (BTC)
                        100000000,      # $1 (stablecoin)
                    ],
                    "semantic": "Price feed data"
                }
            }
        }

        # Get defaults for the protocol and function
        protocol_defaults = defaults.get(protocol, {})
        return protocol_defaults.get(func_name, {"semantic": "Unknown function"})


class ProtocolDefaultsTool(Tool):
    """
    Tool to get protocol-specific default values for mock generation.
    """

    @property
    def name(self) -> str:
        return "get_protocol_defaults"

    @property
    def description(self) -> str:
        return (
            "Get protocol-specific default return values for mock generation. "
            "Provides typical value ranges, common test values, and semantic constraints "
            "based on the protocol type and return types."
        )

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "protocol": {
                    "type": "string",
                    "description": "Protocol type (e.g., 'ERC20', 'Uniswap-V2')"
                },
                "return_types": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of return types"
                }
            },
            "required": ["protocol", "return_types"]
        }

    def execute(
        self,
        protocol: str,
        return_types: List[str]
    ) -> ToolResult:
        """
        Get default values for a protocol.

        Args:
            protocol: Protocol type
            return_types: List of return types

        Returns:
            ToolResult with default values
        """
        try:
            # Import SemanticValidator for default values
            from context_agent.tools.semantic_validator import SemanticValidator

            validator = SemanticValidator()
            defaults = validator.get_default_values(return_types, protocol)

            return ToolResult.success_result({
                "protocol": protocol,
                "return_types": return_types,
                "defaults": defaults
            })

        except Exception as e:
            logger.error(f"Failed to get protocol defaults: {e}")
            return ToolResult.error_result(str(e))
