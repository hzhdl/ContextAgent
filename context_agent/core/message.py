#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Message definitions for the Context Agent system.

This module defines the message types used for communication between
agents and for building conversation history.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime


class MessageRole(Enum):
    """Message role types."""
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


@dataclass
class Message:
    """
    A message in the conversation.

    Attributes:
        role: The role of the message sender (system, user, assistant, tool)
        content: The text content of the message
        name: Optional name for tool messages
        tool_call_id: ID for tool call responses
        timestamp: When the message was created
        metadata: Additional metadata for the message
    """
    role: MessageRole
    content: str
    name: Optional[str] = None
    tool_call_id: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert message to dictionary format for LLM API calls."""
        result = {
            "role": self.role.value,
            "content": self.content
        }

        if self.name:
            result["name"] = self.name

        if self.tool_call_id:
            result["tool_call_id"] = self.tool_call_id

        return result

    @classmethod
    def system(cls, content: str, **kwargs) -> "Message":
        """Create a system message."""
        return cls(role=MessageRole.SYSTEM, content=content, **kwargs)

    @classmethod
    def user(cls, content: str, **kwargs) -> "Message":
        """Create a user message."""
        return cls(role=MessageRole.USER, content=content, **kwargs)

    @classmethod
    def assistant(cls, content: str, **kwargs) -> "Message":
        """Create an assistant message."""
        return cls(role=MessageRole.ASSISTANT, content=content, **kwargs)

    @classmethod
    def tool(cls, content: str, name: str, tool_call_id: str = None, **kwargs) -> "Message":
        """Create a tool response message."""
        return cls(
            role=MessageRole.TOOL,
            content=content,
            name=name,
            tool_call_id=tool_call_id,
            **kwargs
        )


@dataclass
class ToolCall:
    """
    Represents a tool call request from the LLM.

    Attributes:
        id: Unique identifier for the tool call
        name: Name of the tool to call
        arguments: Arguments to pass to the tool
    """
    id: str
    name: str
    arguments: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "id": self.id,
            "name": self.name,
            "arguments": self.arguments
        }


@dataclass
class AgentThought:
    """
    Represents an agent's thought during the ReAct loop.

    Attributes:
        thought: The agent's reasoning
        action: The action the agent wants to take
        action_input: Input for the action
        observation: The result of the action
    """
    thought: str
    action: Optional[str] = None
    action_input: Optional[Dict[str, Any]] = None
    observation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "thought": self.thought,
            "action": self.action,
            "action_input": self.action_input,
            "observation": self.observation
        }
