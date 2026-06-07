#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Base agent implementation for the Context Agent system.

This module provides the BaseAgent class that implements the ReAct
(Reasoning + Acting) pattern for agent execution.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union
from enum import Enum
import json
import re
import logging

from context_agent.core.tool_registry import Tool, ToolRegistry, ToolResult
from context_agent.core.message import Message, MessageRole, ToolCall, AgentThought
from context_agent.core.memory import ConversationMemory, WorkingMemory

logger = logging.getLogger(__name__)


class AgentState(Enum):
    """Agent execution states."""
    IDLE = "idle"
    THINKING = "thinking"
    ACTING = "acting"
    OBSERVING = "observing"
    COMPLETE = "complete"
    ERROR = "error"


@dataclass
class AgentResult:
    """
    Result from an agent's task execution.

    Attributes:
        success: Whether the task was completed successfully
        output: The final output from the agent
        thoughts: List of thoughts during execution
        tool_calls: List of tool calls made
        error: Error message if execution failed
        metadata: Additional metadata
    """
    success: bool
    output: Any = None
    thoughts: List[AgentThought] = field(default_factory=list)
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "success": self.success,
            "output": self.output,
            "thoughts": [t.to_dict() for t in self.thoughts],
            "tool_calls": self.tool_calls,
            "error": self.error,
            "metadata": self.metadata
        }


class BaseAgent(ABC):
    """
    Base agent class implementing the ReAct pattern.

    The ReAct pattern alternates between:
    1. Thought: Agent reasons about the current state
    2. Action: Agent chooses a tool to use or generates a response
    3. Observation: Agent processes the result of the action

    This continues until the agent decides to finish or hits max iterations.

    Attributes:
        name: Unique name for the agent
        llm: LLM client for generating responses
        tools: ToolRegistry containing available tools
        memory: ConversationMemory for maintaining history
        system_prompt: System prompt for the agent
        max_iterations: Maximum ReAct loop iterations
    """

    def __init__(
        self,
        name: str,
        llm_client,
        tools: List[Tool] = None,
        system_prompt: str = None,
        max_iterations: int = 10,
        verbose: bool = False
    ):
        """
        Initialize the agent.

        Args:
            name: Unique name for the agent
            llm_client: LLM client instance (must have generate method)
            tools: List of Tool instances available to the agent
            system_prompt: System prompt defining agent behavior
            max_iterations: Maximum iterations in ReAct loop
            verbose: Whether to log detailed execution info
        """
        self.name = name
        self.llm = llm_client
        self.tools = ToolRegistry(tools or [])
        self.memory = ConversationMemory()
        self.working_memory = WorkingMemory()
        self.system_prompt = system_prompt or self._get_default_system_prompt()
        self.max_iterations = max_iterations
        self.verbose = verbose
        self.state = AgentState.IDLE

        # Initialize memory with system prompt
        self.memory.add_message(Message.system(self.system_prompt))

    @abstractmethod
    def _get_default_system_prompt(self) -> str:
        """Get the default system prompt for this agent type."""
        pass

    def think(self, observation: str) -> str:
        """
        Thinking phase: Analyze current state and decide next action.

        Args:
            observation: The current observation/context

        Returns:
            The agent's thought about what to do next
        """
        self.state = AgentState.THINKING

        # Add observation to memory
        if observation:
            self.memory.add_message(Message.user(observation))

        # Generate thought using LLM
        messages = self.memory.get_messages_for_llm()
        thought = self.llm.generate(messages)

        # Add thought to memory
        self.memory.add_message(Message.assistant(thought))

        if self.verbose:
            logger.info(f"[{self.name}] Thought: {thought[:200]}...")

        return thought

    def act(self, thought: str) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
        """
        Acting phase: Parse thought and determine action.

        Args:
            thought: The agent's thought from the thinking phase

        Returns:
            Tuple of (action_name, action_input) or (None, None) if finishing
        """
        self.state = AgentState.ACTING

        # Parse action from thought
        action, action_input = self._parse_action(thought)

        if self.verbose and action:
            logger.info(f"[{self.name}] Action: {action} with input: {action_input}")

        return action, action_input

    def observe(self, action: str, action_input: Dict[str, Any]) -> str:
        """
        Observation phase: Execute action and process result.

        Args:
            action: Name of the tool to execute
            action_input: Parameters for the tool

        Returns:
            String representation of the observation
        """
        self.state = AgentState.OBSERVING

        # Execute the tool
        result = self.tools.execute(action, **(action_input or {}))

        # Store in working memory
        self.working_memory.add_result(action, result.to_dict())

        # Format observation for next iteration
        observation = f"Tool '{action}' result:\n{result.to_str()}"

        if self.verbose:
            logger.info(f"[{self.name}] Observation: {observation[:200]}...")

        return observation

    def run(self, task: str, context: Dict[str, Any] = None) -> AgentResult:
        """
        Execute the agent on a task using the ReAct loop.

        Args:
            task: The task description
            context: Optional context information

        Returns:
            AgentResult containing the final output
        """
        logger.info(f"[{self.name}] Starting task: {task[:100]}...")

        # Initialize working memory
        self.working_memory.reset(task)

        # Store context
        if context:
            for key, value in context.items():
                self.memory.set_context(key, value)

        # Build initial prompt
        initial_prompt = self._build_task_prompt(task, context)

        thoughts = []
        tool_calls = []
        observation = initial_prompt
        iterations = 0

        try:
            while iterations < self.max_iterations:
                iterations += 1

                # Think
                thought = self.think(observation)

                # Check if agent wants to finish
                final_answer = self._extract_final_answer(thought)
                if final_answer is not None:
                    self.state = AgentState.COMPLETE
                    return AgentResult(
                        success=True,
                        output=final_answer,
                        thoughts=thoughts,
                        tool_calls=tool_calls,
                        metadata={"iterations": iterations}
                    )

                # Act
                action, action_input = self.act(thought)

                # Record thought
                agent_thought = AgentThought(
                    thought=thought,
                    action=action,
                    action_input=action_input
                )

                if action is None:
                    # No action to take, agent is done
                    self.state = AgentState.COMPLETE
                    agent_thought.observation = "No action needed"
                    thoughts.append(agent_thought)

                    return AgentResult(
                        success=True,
                        output=thought,
                        thoughts=thoughts,
                        tool_calls=tool_calls,
                        metadata={"iterations": iterations}
                    )

                # Observe
                observation = self.observe(action, action_input)
                agent_thought.observation = observation
                thoughts.append(agent_thought)

                tool_calls.append({
                    "tool": action,
                    "input": action_input,
                    "output": observation
                })

            # Max iterations reached
            self.state = AgentState.ERROR
            logger.warning(f"[{self.name}] Max iterations ({self.max_iterations}) reached")
            return AgentResult(
                success=False,
                output=None,
                thoughts=thoughts,
                tool_calls=tool_calls,
                error=f"Max iterations ({self.max_iterations}) reached",
                metadata={"iterations": iterations}
            )

        except Exception as e:
            self.state = AgentState.ERROR
            logger.error(f"[{self.name}] Error during execution: {e}")
            return AgentResult(
                success=False,
                output=None,
                thoughts=thoughts,
                tool_calls=tool_calls,
                error=str(e),
                metadata={"iterations": iterations}
            )

    def _build_task_prompt(self, task: str, context: Dict[str, Any] = None) -> str:
        """Build the initial task prompt."""
        prompt_parts = [f"Task: {task}"]

        if context:
            context_str = json.dumps(context, indent=2, ensure_ascii=False, default=str)
            prompt_parts.append(f"\nContext:\n{context_str}")

        if self.tools:
            tools_desc = self.tools.get_tools_description()
            prompt_parts.append(f"\nAvailable Tools:\n{tools_desc}")

        prompt_parts.append("\nPlease complete this task step by step.")

        return "\n".join(prompt_parts)

    def _parse_action(self, thought: str) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
        """
        Parse action from the agent's thought.

        Looks for patterns like:
        - Action: tool_name
        - Action Input: {"param": "value"}
        - Or tool calls in JSON format

        Args:
            thought: The agent's thought string

        Returns:
            Tuple of (action_name, action_input) or (None, None)
        """
        # Pattern 1: Action: xxx / Action Input: {...}
        action_pattern = r"Action:\s*(\w+)"
        input_pattern = r"Action Input:\s*(\{.*?\})"

        action_match = re.search(action_pattern, thought, re.IGNORECASE)
        if action_match:
            action = action_match.group(1)

            # Check if tool exists
            if action not in self.tools:
                return None, None

            # Try to extract input
            input_match = re.search(input_pattern, thought, re.IGNORECASE | re.DOTALL)
            if input_match:
                try:
                    action_input = json.loads(input_match.group(1))
                    return action, action_input
                except json.JSONDecodeError:
                    pass

            return action, {}

        # Pattern 2: JSON tool call format
        json_pattern = r'\{[^{}]*"tool"[^{}]*"name"[^{}]*\}'
        json_match = re.search(json_pattern, thought, re.DOTALL)
        if json_match:
            try:
                tool_call = json.loads(json_match.group())
                action = tool_call.get("name") or tool_call.get("tool")
                action_input = tool_call.get("arguments") or tool_call.get("input") or {}
                if action and action in self.tools:
                    return action, action_input
            except json.JSONDecodeError:
                pass

        return None, None

    def _extract_final_answer(self, thought: str) -> Optional[Any]:
        """
        Extract final answer from thought if present.

        Looks for patterns like:
        - Final Answer: xxx
        - Output: xxx
        - Result: {...}

        Args:
            thought: The agent's thought string

        Returns:
            The final answer or None if not present
        """
        # Pattern 1: Final Answer: xxx
        final_pattern = r"Final Answer:\s*(.+)"
        match = re.search(final_pattern, thought, re.IGNORECASE | re.DOTALL)
        if match:
            answer = match.group(1).strip()
            # Try to parse as JSON
            try:
                return json.loads(answer)
            except json.JSONDecodeError:
                return answer

        # Pattern 2: Check for explicit completion markers
        completion_markers = [
            "task complete",
            "task finished",
            "analysis complete",
            "generation complete"
        ]
        thought_lower = thought.lower()
        for marker in completion_markers:
            if marker in thought_lower:
                # Try to extract JSON from thought
                json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', thought, re.DOTALL)
                if json_match:
                    try:
                        return json.loads(json_match.group())
                    except json.JSONDecodeError:
                        pass
                return thought

        return None

    def reset(self) -> None:
        """Reset the agent state for a new task."""
        # Keep system message, clear everything else
        system_msg = self.memory.get_system_message()
        self.memory.clear()
        if system_msg:
            self.memory.add_message(system_msg)

        self.working_memory.reset()
        self.state = AgentState.IDLE

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name}, tools={self.tools.get_tool_names()})"
