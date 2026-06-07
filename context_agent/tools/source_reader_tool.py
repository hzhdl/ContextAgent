#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Source code reader tool for the Context Agent system.

This tool provides functionality to read and analyze Solidity source code,
supporting function-level extraction and context-aware reading.
"""

import os
import re
import logging
from typing import Any, Dict, List, Optional, Tuple

from context_agent.core.tool_registry import Tool, ToolResult

logger = logging.getLogger(__name__)


class SourceReaderTool(Tool):
    """
    Source code reader tool for semantic analysis.

    Reads Solidity contract source code with support for:
    - Reading specific functions by name
    - Reading line ranges with context
    - Extracting comments and documentation
    - Identifying external calls within functions
    """

    @property
    def name(self) -> str:
        return "read_source"

    @property
    def description(self) -> str:
        return (
            "Read Solidity contract source code. Can read the entire file, "
            "specific functions by name, or line ranges with context. "
            "Returns source code along with extracted comments and identified external calls."
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
                "function_name": {
                    "type": "string",
                    "description": "Name of the function to read (optional)"
                },
                "line_start": {
                    "type": "integer",
                    "description": "Starting line number for range reading (optional)"
                },
                "line_end": {
                    "type": "integer",
                    "description": "Ending line number for range reading (optional)"
                },
                "context_lines": {
                    "type": "integer",
                    "description": "Number of context lines to include (default: 10)"
                }
            },
            "required": ["contract_file"]
        }

    def execute(
        self,
        contract_file: str,
        function_name: str = None,
        line_start: int = None,
        line_end: int = None,
        context_lines: int = 10
    ) -> ToolResult:
        """
        Read source code from a contract file.

        Args:
            contract_file: Path to the Solidity contract file
            function_name: Optional function name to extract
            line_start: Optional starting line number
            line_end: Optional ending line number
            context_lines: Number of context lines to include

        Returns:
            ToolResult with source code and analysis
        """
        try:
            # Validate file exists
            if not os.path.exists(contract_file):
                return ToolResult.error_result(f"Contract file not found: {contract_file}")

            # Read the entire file
            with open(contract_file, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.split('\n')

            result = {
                "file_path": contract_file,
                "total_lines": len(lines),
            }

            # Function-specific reading
            if function_name:
                func_result = self._extract_function(lines, function_name, context_lines)
                if func_result:
                    result.update(func_result)
                else:
                    return ToolResult.error_result(f"Function '{function_name}' not found")

            # Line range reading
            elif line_start is not None:
                range_result = self._extract_line_range(
                    lines, line_start, line_end, context_lines
                )
                result.update(range_result)

            # Full file reading (with summary)
            else:
                result["source_code"] = content
                result["functions"] = self._list_functions(lines)
                result["contracts"] = self._list_contracts(lines)
                result["imports"] = self._list_imports(lines)

            # Extract comments from the relevant section
            source = result.get("source_code", content)
            result["comments"] = self._extract_comments(source)

            # Identify external calls in the source
            result["external_calls_found"] = self._find_external_calls(source)

            return ToolResult.success_result(result)

        except Exception as e:
            logger.error(f"Source reading failed: {e}")
            return ToolResult.error_result(str(e))

    def _extract_function(
        self,
        lines: List[str],
        function_name: str,
        context_lines: int
    ) -> Optional[Dict[str, Any]]:
        """
        Extract a specific function from the source code.

        Args:
            lines: Source code lines
            function_name: Name of the function to extract
            context_lines: Number of context lines before the function

        Returns:
            Dictionary with function info or None if not found
        """
        # Pattern to match function definition
        func_pattern = rf'function\s+{re.escape(function_name)}\s*\('

        func_start = None
        for i, line in enumerate(lines):
            if re.search(func_pattern, line):
                func_start = i
                break

        if func_start is None:
            return None

        # Find function end by matching braces
        func_end = self._find_function_end(lines, func_start)

        # Include context lines
        start_with_context = max(0, func_start - context_lines)
        end_with_context = min(len(lines), func_end + 1)

        # Extract the function
        func_lines = lines[start_with_context:end_with_context]

        return {
            "function_name": function_name,
            "line_start": func_start + 1,  # 1-indexed
            "line_end": func_end + 1,
            "source_code": '\n'.join(func_lines),
            "context_start": start_with_context + 1,
            "context_end": end_with_context
        }

    def _find_function_end(self, lines: List[str], start: int) -> int:
        """
        Find the end of a function by matching braces.

        Args:
            lines: Source code lines
            start: Starting line index

        Returns:
            Ending line index
        """
        brace_count = 0
        in_function = False

        for i in range(start, len(lines)):
            line = lines[i]

            # Remove string literals and comments to avoid false matches
            line = re.sub(r'"[^"]*"', '', line)
            line = re.sub(r"'[^']*'", '', line)
            line = re.sub(r'//.*', '', line)

            for char in line:
                if char == '{':
                    brace_count += 1
                    in_function = True
                elif char == '}':
                    brace_count -= 1

                if in_function and brace_count == 0:
                    return i

        return len(lines) - 1

    def _extract_line_range(
        self,
        lines: List[str],
        line_start: int,
        line_end: Optional[int],
        context_lines: int
    ) -> Dict[str, Any]:
        """
        Extract a range of lines with context.

        Args:
            lines: Source code lines
            line_start: Starting line (1-indexed)
            line_end: Optional ending line (1-indexed)
            context_lines: Number of context lines

        Returns:
            Dictionary with extracted source
        """
        # Convert to 0-indexed
        start_idx = line_start - 1
        end_idx = (line_end or line_start) - 1

        # Include context
        start_with_context = max(0, start_idx - context_lines)
        end_with_context = min(len(lines), end_idx + context_lines + 1)

        extracted_lines = lines[start_with_context:end_with_context]

        return {
            "line_start": line_start,
            "line_end": line_end or line_start,
            "context_start": start_with_context + 1,
            "context_end": end_with_context,
            "source_code": '\n'.join(extracted_lines)
        }

    def _list_functions(self, lines: List[str]) -> List[Dict[str, Any]]:
        """
        List all functions in the source code.

        Args:
            lines: Source code lines

        Returns:
            List of function info dictionaries
        """
        functions = []
        func_pattern = r'function\s+(\w+)\s*\(([^)]*)\)'

        for i, line in enumerate(lines):
            match = re.search(func_pattern, line)
            if match:
                functions.append({
                    "name": match.group(1),
                    "parameters": match.group(2).strip(),
                    "line": i + 1
                })

        return functions

    def _list_contracts(self, lines: List[str]) -> List[Dict[str, Any]]:
        """
        List all contracts in the source code.

        Args:
            lines: Source code lines

        Returns:
            List of contract info dictionaries
        """
        contracts = []
        contract_pattern = r'(contract|interface|library)\s+(\w+)'

        for i, line in enumerate(lines):
            match = re.search(contract_pattern, line)
            if match:
                contracts.append({
                    "type": match.group(1),
                    "name": match.group(2),
                    "line": i + 1
                })

        return contracts

    def _list_imports(self, lines: List[str]) -> List[str]:
        """
        List all imports in the source code.

        Args:
            lines: Source code lines

        Returns:
            List of import statements
        """
        imports = []
        import_pattern = r'import\s+[^;]+;'

        for line in lines:
            match = re.search(import_pattern, line)
            if match:
                imports.append(match.group().strip())

        return imports

    def _extract_comments(self, source: str) -> List[Dict[str, Any]]:
        """
        Extract comments from source code.

        Args:
            source: Source code string

        Returns:
            List of comment dictionaries
        """
        comments = []

        # Single-line comments
        single_line = re.findall(r'//\s*(.*)', source)
        for comment in single_line:
            if comment.strip():
                comments.append({
                    "type": "single_line",
                    "content": comment.strip()
                })

        # Multi-line comments
        multi_line = re.findall(r'/\*\s*([\s\S]*?)\s*\*/', source)
        for comment in multi_line:
            if comment.strip():
                comments.append({
                    "type": "multi_line",
                    "content": comment.strip()
                })

        # NatSpec comments (@param, @return, @notice, @dev)
        natspec = re.findall(r'///\s*(@\w+)?\s*(.*)', source)
        for tag, content in natspec:
            if content.strip():
                comments.append({
                    "type": "natspec",
                    "tag": tag or "",
                    "content": content.strip()
                })

        return comments

    def _find_external_calls(self, source: str) -> List[Dict[str, Any]]:
        """
        Find external calls in the source code.

        Args:
            source: Source code string

        Returns:
            List of external call info dictionaries
        """
        external_calls = []

        # Pattern for external calls: identifier.functionName(...)
        call_pattern = r'(\w+)\.(\w+)\s*\(([^)]*)\)'

        for match in re.finditer(call_pattern, source):
            target = match.group(1)
            func = match.group(2)
            args = match.group(3)

            # Skip common internal patterns
            if target in ['this', 'super', 'msg', 'block', 'tx', 'abi', 'type']:
                continue

            # Skip if it looks like a library call (lowercase)
            if target[0].islower() and target not in ['address', 'bytes', 'string']:
                continue

            external_calls.append({
                "target": target,
                "function": func,
                "arguments": args.strip(),
                "full_expression": match.group(0)
            })

        return external_calls
