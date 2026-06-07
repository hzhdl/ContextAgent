#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LLM client implementation for the Context Agent system.

This module provides a unified interface for interacting with LLMs,
supporting both remote API calls (OpenAI-compatible) and local models.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Union
import json
import logging
import os

from context_agent.llm.config import LLMConfig

logger = logging.getLogger(__name__)


class LLMClient(ABC):
    """
    Abstract base class for LLM clients.

    All LLM client implementations must inherit from this class and
    implement the generate method.
    """

    @abstractmethod
    def generate(
        self,
        messages: List[Dict[str, str]],
        **kwargs
    ) -> str:
        """
        Generate a response from the LLM.

        Args:
            messages: List of message dictionaries with 'role' and 'content' keys
            **kwargs: Additional generation parameters

        Returns:
            Generated text response
        """
        pass

    @abstractmethod
    def generate_with_tools(
        self,
        messages: List[Dict[str, str]],
        tools: List[Dict[str, Any]],
        **kwargs
    ) -> Dict[str, Any]:
        """
        Generate a response with tool/function calling support.

        Args:
            messages: List of message dictionaries
            tools: List of tool schemas
            **kwargs: Additional generation parameters

        Returns:
            Dictionary containing response and any tool calls
        """
        pass


class RemoteLLMClient(LLMClient):
    """
    LLM client for remote OpenAI-compatible APIs.

    Supports APIs like OpenAI, Ollama, vLLM, and other OpenAI-compatible endpoints.
    """

    def __init__(self, config: LLMConfig):
        """
        Initialize the remote LLM client.

        Args:
            config: LLMConfig instance with connection settings
        """
        self.config = config
        self.model = config.model
        self.base_url = config.base_url or "http://localhost:11434/v1"
        self.api_key = config.api_key or "ollama"
        self.temperature = config.temperature
        self.max_tokens = config.max_tokens
        self.timeout = config.timeout

        # Initialize OpenAI client
        try:
            from openai import OpenAI
            self.client = OpenAI(
                base_url=self.base_url,
                api_key=self.api_key,
                timeout=self.timeout
            )
            logger.info(f"RemoteLLMClient initialized: model={self.model}, base_url={self.base_url}")
        except ImportError:
            raise ImportError("openai package is required. Install with: pip install openai")

    def generate(
        self,
        messages: List[Dict[str, str]],
        **kwargs
    ) -> str:
        """Generate a response from the LLM."""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=kwargs.get("temperature", self.temperature),
                max_tokens=kwargs.get("max_tokens", self.max_tokens),
            )

            return response.choices[0].message.content

        except Exception as e:
            logger.error(f"LLM generation error: {e}")
            raise

    def generate_with_tools(
        self,
        messages: List[Dict[str, str]],
        tools: List[Dict[str, Any]],
        **kwargs
    ) -> Dict[str, Any]:
        """Generate a response with tool calling support."""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                tools=tools,
                tool_choice=kwargs.get("tool_choice", "auto"),
                temperature=kwargs.get("temperature", self.temperature),
                max_tokens=kwargs.get("max_tokens", self.max_tokens),
            )

            message = response.choices[0].message
            result = {
                "content": message.content,
                "tool_calls": []
            }

            if message.tool_calls:
                for tool_call in message.tool_calls:
                    result["tool_calls"].append({
                        "id": tool_call.id,
                        "name": tool_call.function.name,
                        "arguments": json.loads(tool_call.function.arguments)
                    })

            return result

        except Exception as e:
            logger.error(f"LLM generation with tools error: {e}")
            raise


class LocalLLMClient(LLMClient):
    """
    LLM client for local models using transformers.

    Supports models that can be loaded with the Hugging Face transformers library.
    """

    def __init__(self, config: LLMConfig):
        """
        Initialize the local LLM client.

        Args:
            config: LLMConfig instance with model settings
        """
        self.config = config
        self.model_path = config.model
        self.device = config.extra_params.get("device", "auto")
        self.temperature = config.temperature
        self.max_tokens = config.max_tokens

        self._model = None
        self._tokenizer = None
        self._load_model()

    def _load_model(self):
        """Load the model and tokenizer."""
        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer
            import torch

            logger.info(f"Loading local model: {self.model_path}")

            self._tokenizer = AutoTokenizer.from_pretrained(
                self.model_path,
                trust_remote_code=True
            )

            # Determine device
            if self.device == "auto":
                device_map = "auto"
            elif self.device.startswith("cuda"):
                device_map = {"": self.device}
            else:
                device_map = {"": "cpu"}

            self._model = AutoModelForCausalLM.from_pretrained(
                self.model_path,
                device_map=device_map,
                torch_dtype=torch.float16,
                trust_remote_code=True
            )

            logger.info(f"LocalLLMClient initialized: model={self.model_path}, device={self.device}")

        except ImportError:
            raise ImportError(
                "transformers and torch packages are required for local models. "
                "Install with: pip install transformers torch"
            )

    def generate(
        self,
        messages: List[Dict[str, str]],
        **kwargs
    ) -> str:
        """Generate a response from the local LLM."""
        try:
            # Apply chat template
            prompt = self._tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True
            )

            # Tokenize
            inputs = self._tokenizer(prompt, return_tensors="pt")
            inputs = {k: v.to(self._model.device) for k, v in inputs.items()}

            # Generate
            import torch
            with torch.no_grad():
                outputs = self._model.generate(
                    **inputs,
                    max_new_tokens=kwargs.get("max_tokens", self.max_tokens),
                    temperature=kwargs.get("temperature", self.temperature),
                    do_sample=True,
                    pad_token_id=self._tokenizer.eos_token_id
                )

            # Decode response
            response = self._tokenizer.decode(
                outputs[0][inputs["input_ids"].shape[1]:],
                skip_special_tokens=True
            )

            return response

        except Exception as e:
            logger.error(f"Local LLM generation error: {e}")
            raise

    def generate_with_tools(
        self,
        messages: List[Dict[str, str]],
        tools: List[Dict[str, Any]],
        **kwargs
    ) -> Dict[str, Any]:
        """
        Generate a response with tool calling support.

        Note: Local models may not natively support tool calling.
        This implementation uses prompt engineering to simulate tool calls.
        """
        # Add tool descriptions to the system message
        tools_desc = self._format_tools_for_prompt(tools)

        enhanced_messages = list(messages)
        if enhanced_messages and enhanced_messages[0]["role"] == "system":
            enhanced_messages[0]["content"] += f"\n\nAvailable Tools:\n{tools_desc}"
        else:
            enhanced_messages.insert(0, {
                "role": "system",
                "content": f"You have access to the following tools:\n{tools_desc}"
            })

        # Generate response
        response = self.generate(enhanced_messages, **kwargs)

        # Parse any tool calls from the response
        tool_calls = self._parse_tool_calls(response, tools)

        return {
            "content": response,
            "tool_calls": tool_calls
        }

    def _format_tools_for_prompt(self, tools: List[Dict[str, Any]]) -> str:
        """Format tools for inclusion in prompt."""
        descriptions = []
        for tool in tools:
            func = tool.get("function", tool)
            name = func.get("name", "unknown")
            desc = func.get("description", "")
            params = func.get("parameters", {})

            param_str = json.dumps(params.get("properties", {}), indent=2)
            descriptions.append(f"- {name}: {desc}\n  Parameters: {param_str}")

        return "\n".join(descriptions)

    def _parse_tool_calls(
        self,
        response: str,
        tools: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Parse tool calls from response text."""
        import re

        tool_calls = []
        tool_names = {
            tool.get("function", tool).get("name", "")
            for tool in tools
        }

        # Look for JSON tool call patterns
        pattern = r'\{[^{}]*"(?:tool|name|function)"[^{}]*\}'
        matches = re.findall(pattern, response, re.DOTALL)

        for match in matches:
            try:
                data = json.loads(match)
                name = data.get("name") or data.get("tool") or data.get("function")
                if name in tool_names:
                    tool_calls.append({
                        "id": f"call_{len(tool_calls)}",
                        "name": name,
                        "arguments": data.get("arguments", data.get("input", {}))
                    })
            except json.JSONDecodeError:
                continue

        return tool_calls


def create_llm_client(config: LLMConfig = None, **kwargs) -> LLMClient:
    """
    Factory function to create the appropriate LLM client.

    Args:
        config: Optional LLMConfig instance. If not provided, will use settings.
        **kwargs: Override parameters for the config

    Returns:
        LLMClient instance (RemoteLLMClient or LocalLLMClient)
    """
    if config is None:
        config = LLMConfig.from_settings()

    # Apply any overrides
    if kwargs:
        for key, value in kwargs.items():
            if hasattr(config, key) and value is not None:
                setattr(config, key, value)

    logger.info(f"Creating LLM client: provider={config.provider}")

    if config.provider == "remote":
        return RemoteLLMClient(config)
    elif config.provider == "local":
        return LocalLLMClient(config)
    else:
        raise ValueError(f"Unknown LLM provider: {config.provider}")
