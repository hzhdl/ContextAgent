#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LLM configuration for the Context Agent system.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional
import os


@dataclass
class LLMConfig:
    """
    Configuration for LLM client.

    Attributes:
        provider: LLM provider type ('remote' or 'local')
        model: Model name or path
        base_url: Base URL for remote API
        api_key: API key for remote API
        temperature: Sampling temperature
        max_tokens: Maximum tokens to generate
        timeout: Request timeout in seconds
        extra_params: Additional provider-specific parameters
    """
    provider: str = "remote"
    model: str = "qwen2.5-coder:7b"
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    temperature: float = 0.7
    max_tokens: int = 4096
    timeout: int = 120
    extra_params: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_settings(cls) -> "LLMConfig":
        """Create config from settings.py."""
        try:
            import sys
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
            from utils.settings import (
                LLM_PROVIDER,
                LLM_REMOTE_MODEL,
                LLM_REMOTE_BASE_URL,
                LLM_REMOTE_API_KEY,
                LLM_LOCAL_MODEL_PATH,
                LLM_LOCAL_DEVICE,
                LLM_TEMPERATURE,
                LLM_MAX_TOKENS,
            )

            return cls(
                provider=LLM_PROVIDER,
                model=LLM_REMOTE_MODEL if LLM_PROVIDER == "remote" else LLM_LOCAL_MODEL_PATH,
                base_url=LLM_REMOTE_BASE_URL,
                api_key=LLM_REMOTE_API_KEY,
                temperature=LLM_TEMPERATURE,
                max_tokens=LLM_MAX_TOKENS,
                extra_params={
                    "device": LLM_LOCAL_DEVICE if LLM_PROVIDER == "local" else None
                }
            )
        except ImportError:
            # Fallback to defaults
            return cls()

    @classmethod
    def from_env(cls) -> "LLMConfig":
        """Create config from environment variables."""
        return cls(
            provider=os.getenv("LLM_PROVIDER", "remote"),
            model=os.getenv("LLM_MODEL", "qwen2.5-coder:7b"),
            base_url=os.getenv("LLM_BASE_URL", "http://localhost:11434/v1"),
            api_key=os.getenv("LLM_API_KEY", "ollama"),
            temperature=float(os.getenv("LLM_TEMPERATURE", "0.7")),
            max_tokens=int(os.getenv("LLM_MAX_TOKENS", "4096")),
            timeout=int(os.getenv("LLM_TIMEOUT", "120")),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "provider": self.provider,
            "model": self.model,
            "base_url": self.base_url,
            "api_key": "***" if self.api_key else None,  # Mask API key
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "timeout": self.timeout,
        }
