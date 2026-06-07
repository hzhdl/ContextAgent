#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Function selector tool for the Context Agent system.

This tool calculates function selectors (4-byte identifiers) for Solidity functions.
"""

import logging
from typing import Any, Dict, List

from context_agent.core.tool_registry import Tool, ToolResult

logger = logging.getLogger(__name__)


class SelectorTool(Tool):
    """
    Function selector calculation tool.

    Calculates the 4-byte function selector (first 4 bytes of keccak256 hash)
    for Solidity function signatures.
    """

    @property
    def name(self) -> str:
        return "get_selector"

    @property
    def description(self) -> str:
        return (
            "Calculate the 4-byte function selector for a Solidity function signature. "
            "The selector is the first 4 bytes of the keccak256 hash of the function signature."
        )

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "function_signature": {
                    "type": "string",
                    "description": "Function signature (e.g., 'transfer(address,uint256)')"
                },
                "normalize": {
                    "type": "boolean",
                    "description": "Whether to normalize the signature before hashing (default: true)"
                }
            },
            "required": ["function_signature"]
        }

    def execute(
        self,
        function_signature: str,
        normalize: bool = True
    ) -> ToolResult:
        """
        Calculate function selector for a signature.

        Args:
            function_signature: Function signature string
            normalize: Whether to normalize the signature

        Returns:
            ToolResult with the calculated selector
        """
        try:
            # Normalize the signature if requested
            if normalize:
                normalized = self._normalize_signature(function_signature)
            else:
                normalized = function_signature

            # Calculate selector
            selector = self._calculate_selector(normalized)

            return ToolResult.success_result({
                "function_signature": function_signature,
                "normalized_signature": normalized,
                "selector": selector,
                "selector_int": int(selector, 16)
            })

        except Exception as e:
            logger.error(f"Selector calculation failed: {e}")
            return ToolResult.error_result(str(e))

    def _normalize_signature(self, signature: str) -> str:
        """
        Normalize a function signature for hashing.

        Removes:
        - Whitespace
        - Parameter names
        - Return types
        - Array sizes (uint256[] stays as uint256[])

        Args:
            signature: Raw function signature

        Returns:
            Normalized signature
        """
        import re

        # Remove return type part if present
        if ')(' in signature:
            # Format: "funcName(params)(returns)"
            signature = signature.split(')(')[0] + ')'

        # Remove whitespace
        signature = re.sub(r'\s+', '', signature)

        # Extract function name and parameters
        match = re.match(r'(\w+)\(([^)]*)\)', signature)
        if not match:
            return signature

        func_name = match.group(1)
        params = match.group(2)

        # Process parameters
        if params:
            # Split parameters by comma (handling nested types)
            param_types = self._split_params(params)

            # For each parameter, extract just the type
            normalized_types = []
            for param in param_types:
                # Remove parameter names, keeping only type
                # Handle array types: type[]
                # Handle mapping: not typically in function sigs
                type_only = self._extract_type(param.strip())
                if type_only:
                    normalized_types.append(type_only)

            params = ','.join(normalized_types)

        return f"{func_name}({params})"

    def _split_params(self, params: str) -> List[str]:
        """
        Split parameters by comma, handling nested parentheses.

        Args:
            params: Parameter string

        Returns:
            List of parameter strings
        """
        result = []
        current = ""
        depth = 0

        for char in params:
            if char == '(':
                depth += 1
                current += char
            elif char == ')':
                depth -= 1
                current += char
            elif char == ',' and depth == 0:
                if current.strip():
                    result.append(current.strip())
                current = ""
            else:
                current += char

        if current.strip():
            result.append(current.strip())

        return result

    def _extract_type(self, param: str) -> str:
        """
        Extract the type from a parameter definition.

        Handles formats like:
        - "uint256"
        - "uint256 amount"
        - "address indexed sender"

        Args:
            param: Parameter string

        Returns:
            Type string
        """
        import re

        # Remove 'indexed', 'memory', 'storage', 'calldata' keywords
        param = re.sub(r'\b(indexed|memory|storage|calldata)\b', '', param).strip()

        # Split by whitespace and take the first part (the type)
        parts = param.split()
        if parts:
            return parts[0]

        return param

    def _calculate_selector(self, signature: str) -> str:
        """
        Calculate the 4-byte selector for a function signature.

        Args:
            signature: Normalized function signature

        Returns:
            Hex string of the selector (e.g., "0xa9059cbb")
        """
        try:
            # Try using eth_abi/web3 if available
            from eth_abi import encode as eth_encode
            from eth_utils import keccak

            hash_bytes = keccak(text=signature)
            return '0x' + hash_bytes[:4].hex()

        except ImportError:
            # Fallback to hashlib
            import hashlib

            # Use keccak256 from pysha3 if available, otherwise sha3_256
            try:
                import sha3
                k = sha3.keccak_256()
                k.update(signature.encode('utf-8'))
                hash_bytes = k.digest()
            except ImportError:
                # Last resort: use hashlib sha3_256 (not the same as keccak256!)
                logger.warning(
                    "Using sha3_256 instead of keccak256. "
                    "Install pysha3 or eth-utils for correct selectors."
                )
                hash_bytes = hashlib.sha3_256(signature.encode('utf-8')).digest()

            return '0x' + hash_bytes[:4].hex()


class BatchSelectorTool(Tool):
    """
    Batch function selector calculation tool.
    """

    @property
    def name(self) -> str:
        return "get_selectors_batch"

    @property
    def description(self) -> str:
        return (
            "Calculate function selectors for multiple signatures at once. "
            "Returns a mapping of signatures to their 4-byte selectors."
        )

    @property
    def parameters(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "function_signatures": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of function signatures"
                }
            },
            "required": ["function_signatures"]
        }

    def execute(self, function_signatures: List[str]) -> ToolResult:
        """
        Calculate selectors for multiple signatures.

        Args:
            function_signatures: List of function signatures

        Returns:
            ToolResult with selector mapping
        """
        try:
            selector_tool = SelectorTool()
            results = {}

            for sig in function_signatures:
                result = selector_tool.execute(sig)
                if result.success:
                    results[sig] = result.data["selector"]
                else:
                    results[sig] = {"error": result.error}

            return ToolResult.success_result({
                "selector_map": results,
                "count": len(results)
            })

        except Exception as e:
            logger.error(f"Batch selector calculation failed: {e}")
            return ToolResult.error_result(str(e))
