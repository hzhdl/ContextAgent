#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Conversation memory management for the Context Agent system.

This module provides memory management for maintaining conversation
history and context across agent interactions.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from collections import deque
import json

from context_agent.core.message import Message, MessageRole, AgentThought


@dataclass
class ConversationMemory:
    """
    Manages conversation history for an agent.

    Attributes:
        max_messages: Maximum number of messages to keep in memory
        messages: List of messages in the conversation
        thoughts: List of agent thoughts during ReAct loops
        context: Additional context information
    """
    max_messages: int = 100
    messages: List[Message] = field(default_factory=list)
    thoughts: List[AgentThought] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)

    def add_message(self, message: Message) -> None:
        """Add a message to the conversation history."""
        self.messages.append(message)

        # Trim if exceeding max
        if len(self.messages) > self.max_messages:
            # Keep system message if present
            system_msgs = [m for m in self.messages if m.role == MessageRole.SYSTEM]
            other_msgs = [m for m in self.messages if m.role != MessageRole.SYSTEM]

            # Keep most recent messages
            keep_count = self.max_messages - len(system_msgs)
            self.messages = system_msgs + other_msgs[-keep_count:]

    def add_thought(self, thought: AgentThought) -> None:
        """Add a thought to the thought history."""
        self.thoughts.append(thought)

    def get_messages_for_llm(self) -> List[Dict[str, Any]]:
        """Get messages formatted for LLM API calls."""
        return [msg.to_dict() for msg in self.messages]

    def get_last_n_messages(self, n: int) -> List[Message]:
        """Get the last n messages."""
        return self.messages[-n:] if n > 0 else []

    def get_system_message(self) -> Optional[Message]:
        """Get the system message if present."""
        for msg in self.messages:
            if msg.role == MessageRole.SYSTEM:
                return msg
        return None

    def set_context(self, key: str, value: Any) -> None:
        """Set a context value."""
        self.context[key] = value

    def get_context(self, key: str, default: Any = None) -> Any:
        """Get a context value."""
        return self.context.get(key, default)

    def clear(self) -> None:
        """Clear all messages and thoughts but keep context."""
        self.messages.clear()
        self.thoughts.clear()

    def clear_all(self) -> None:
        """Clear everything including context."""
        self.messages.clear()
        self.thoughts.clear()
        self.context.clear()

    def get_summary(self) -> str:
        """Get a summary of the conversation."""
        msg_count = len(self.messages)
        thought_count = len(self.thoughts)
        context_keys = list(self.context.keys())

        return (
            f"ConversationMemory: {msg_count} messages, "
            f"{thought_count} thoughts, "
            f"context keys: {context_keys}"
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize memory to dictionary."""
        return {
            "messages": [msg.to_dict() for msg in self.messages],
            "thoughts": [t.to_dict() for t in self.thoughts],
            "context": self.context
        }

    def to_json(self) -> str:
        """Serialize memory to JSON string."""
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False, default=str)


@dataclass
class WorkingMemory:
    """
    Short-term working memory for a single task execution.

    This is used within a single ReAct loop to track intermediate results.

    Attributes:
        task: The current task description
        intermediate_results: Results from tool executions
        current_step: Current step in the task
        max_steps: Maximum allowed steps
    """
    task: str = ""
    intermediate_results: List[Dict[str, Any]] = field(default_factory=list)
    current_step: int = 0
    max_steps: int = 10

    def add_result(self, tool_name: str, result: Any) -> None:
        """Add an intermediate result."""
        self.intermediate_results.append({
            "step": self.current_step,
            "tool": tool_name,
            "result": result
        })
        self.current_step += 1

    def get_latest_result(self) -> Optional[Dict[str, Any]]:
        """Get the latest intermediate result."""
        if self.intermediate_results:
            return self.intermediate_results[-1]
        return None

    def is_complete(self) -> bool:
        """Check if the task should be considered complete."""
        return self.current_step >= self.max_steps

    def reset(self, task: str = "") -> None:
        """Reset the working memory for a new task."""
        self.task = task
        self.intermediate_results.clear()
        self.current_step = 0

    def get_summary(self) -> str:
        """Get a summary of working memory."""
        return (
            f"Task: {self.task[:50]}...\n"
            f"Step: {self.current_step}/{self.max_steps}\n"
            f"Results: {len(self.intermediate_results)} items"
        )
