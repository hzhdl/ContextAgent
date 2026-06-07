#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tool registry and management for the Context Agent system.

This module provides the base Tool class and ToolRegistry for managing
tools that agents can use during execution.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Type, Union
import json
import logging

logger = logging.getLogger(__name__)


@dataclass
class ToolResult:
    """
    Result from a tool execution.

    Attributes:
        success: Whether the tool execution was successful
        data: The result data from the tool
        error: Error message if execution failed
        metadata: Additional metadata about the execution
    """
    success: bool
    data: Any = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "metadata": self.metadata
        }

    def to_str(self) -> str:
        """Convert to string for LLM consumption."""
        if self.success:
            if isinstance(self.data, (dict, list)):
                return json.dumps(self.data, indent=2, ensure_ascii=False, default=str)
            return str(self.data)
        else:
            return f"Error: {self.error}"

    @classmethod
    def success_result(cls, data: Any, **metadata) -> "ToolResult":
        """Create a successful result."""
        return cls(success=True, data=data, metadata=metadata)

    @classmethod
    def error_result(cls, error: str, **metadata) -> "ToolResult":
        """Create an error result."""
        return cls(success=False, error=error, metadata=metadata)


class Tool(ABC):
    """
    Base class for all tools that agents can use.

    Tools encapsulate specific functionality that agents can invoke
    during their execution. Each tool has a name, description, and
    parameter schema.

    Subclasses must implement the `execute` method.

    Attributes:
        name: Unique name for the tool
        description: Human-readable description of what the tool does
        parameters: JSON schema for tool parameters
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique name for the tool."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what the tool does."""
        pass

    @property
    def parameters(self) -> Dict[str, Any]:
        """
        JSON schema for tool parameters.

        Override this to define the expected parameters.
        Default returns an empty schema.
        """
        return {
            "type": "object",
            "properties": {},
            "required": []
        }

    @abstractmethod
    def execute(self, **kwargs) -> ToolResult:
        """
        Execute the tool with the given parameters.

        Args:
            **kwargs: Tool-specific parameters

        Returns:
            ToolResult containing the execution result
        """
        pass

    def validate_parameters(self, **kwargs) -> bool:
        """
        Validate the provided parameters against the schema.

        Args:
            **kwargs: Parameters to validate

        Returns:
            True if valid, raises ValueError otherwise
        """
        required = self.parameters.get("required", [])
        for param in required:
            if param not in kwargs:
                raise ValueError(f"Missing required parameter: {param}")
        return True

    def get_schema(self) -> Dict[str, Any]:
        """Get the complete tool schema for LLM function calling."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters
            }
        }

    def __repr__(self) -> str:
        return f"Tool(name={self.name})"


class SimpleTool(Tool):
    """
    A simple tool wrapper that takes a callable function.

    This allows creating tools from plain functions without subclassing.

    Example:
        def my_func(x: int) -> str:
            return f"Result: {x}"

        tool = SimpleTool(
            name="my_tool",
            description="Does something",
            func=my_func,
            parameters={"type": "object", "properties": {"x": {"type": "integer"}}}
        )
    """

    def __init__(
        self,
        name: str,
        description: str,
        func: Callable[..., Any],
        parameters: Dict[str, Any] = None
    ):
        self._name = name
        self._description = description
        self._func = func
        self._parameters = parameters or {"type": "object", "properties": {}, "required": []}

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return self._description

    @property
    def parameters(self) -> Dict[str, Any]:
        return self._parameters

    def execute(self, **kwargs) -> ToolResult:
        try:
            self.validate_parameters(**kwargs)
            result = self._func(**kwargs)
            return ToolResult.success_result(result)
        except Exception as e:
            logger.error(f"Tool {self.name} execution failed: {e}")
            return ToolResult.error_result(str(e))


class ToolRegistry:
    """
    Registry for managing tools available to an agent.

    The registry maintains a collection of tools and provides methods
    for registering, retrieving, and executing tools.

    Attributes:
        tools: Dictionary mapping tool names to Tool instances
    """

    def __init__(self, tools: List[Tool] = None):
        """
        Initialize the registry with optional initial tools.

        Args:
            tools: List of Tool instances to register
        """
        self.tools: Dict[str, Tool] = {}
        if tools:
            for tool in tools:
                self.register(tool)

    def register(self, tool: Tool) -> None:
        """
        Register a tool.

        Args:
            tool: The Tool instance to register

        Raises:
            ValueError: If a tool with the same name already exists
        """
        if tool.name in self.tools:
            logger.warning(f"Tool {tool.name} already registered, overwriting")
        self.tools[tool.name] = tool
        logger.debug(f"Registered tool: {tool.name}")

    def unregister(self, name: str) -> None:
        """
        Unregister a tool by name.

        Args:
            name: The name of the tool to unregister
        """
        if name in self.tools:
            del self.tools[name]
            logger.debug(f"Unregistered tool: {name}")

    def get(self, name: str) -> Optional[Tool]:
        """
        Get a tool by name.

        Args:
            name: The name of the tool

        Returns:
            The Tool instance or None if not found
        """
        return self.tools.get(name)

    def execute(self, name: str, **kwargs) -> ToolResult:
        """
        Execute a tool by name with the given parameters.

        Args:
            name: The name of the tool to execute
            **kwargs: Parameters to pass to the tool

        Returns:
            ToolResult from the execution
        """
        tool = self.get(name)
        if tool is None:
            return ToolResult.error_result(f"Tool not found: {name}")

        try:
            logger.debug(f"Executing tool {name} with params: {kwargs}")
            result = tool.execute(**kwargs)
            logger.debug(f"Tool {name} result: success={result.success}")
            return result
        except Exception as e:
            logger.error(f"Tool {name} execution error: {e}")
            return ToolResult.error_result(str(e))

    def get_all_schemas(self) -> List[Dict[str, Any]]:
        """Get schemas for all registered tools."""
        return [tool.get_schema() for tool in self.tools.values()]

    def get_tool_names(self) -> List[str]:
        """Get names of all registered tools."""
        return list(self.tools.keys())

    def get_tools_description(self) -> str:
        """Get a formatted description of all tools for prompts."""
        descriptions = []
        for name, tool in self.tools.items():
            params = tool.parameters.get("properties", {})
            params_str = ", ".join(
                f"{k}: {v.get('type', 'any')}"
                for k, v in params.items()
            )
            descriptions.append(f"- {name}({params_str}): {tool.description}")
        return "\n".join(descriptions)

    def __len__(self) -> int:
        return len(self.tools)

    def __contains__(self, name: str) -> bool:
        return name in self.tools

    def __iter__(self):
        return iter(self.tools.values())

    def __repr__(self) -> str:
        return f"ToolRegistry(tools={list(self.tools.keys())})"
