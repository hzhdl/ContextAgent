#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Core framework components for the Context Agent system.
"""

from context_agent.core.base_agent import BaseAgent, AgentResult
from context_agent.core.tool_registry import Tool, ToolRegistry, ToolResult
from context_agent.core.message import Message, MessageRole
from context_agent.core.memory import ConversationMemory
from context_agent.core.evm_context import EVMContext, get_evm_context, set_evm_context

__all__ = [
    "BaseAgent",
    "AgentResult",
    "Tool",
    "ToolRegistry",
    "ToolResult",
    "Message",
    "MessageRole",
    "ConversationMemory",
    "EVMContext",
    "get_evm_context",
    "set_evm_context",
]
