#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Agent configuration for the Context Agent system.

Centralizes Context Agent settings, reading from utils/settings.py.
"""

import os
from dataclasses import dataclass


@dataclass
class AgentConfig:
    """
    Configuration for Context Agent system.

    Attributes:
        semantic_enable: Whether to enable semantic analysis (SemanticAgent).
                         Set False for ablation study (no-semantic generation).
        validation_enable: Whether to enable validation (ValidatorAgent).
        max_retries: Maximum retries for generation failures.
        max_iterations: Maximum ReAct loop iterations per agent.
        verbose: Whether to output agent thinking process.
    """
    semantic_enable: bool = True
    validation_enable: bool = True
    max_retries: int = 3
    max_iterations: int = 10
    verbose: bool = False

    @classmethod
    def from_settings(cls) -> "AgentConfig":
        """Create config from utils/settings.py."""
        try:
            import sys
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
            from utils.settings import (
                CONTEXT_AGENT_SEMANTIC_ENABLE,
                CONTEXT_AGENT_VALIDATION_ENABLE,
                CONTEXT_AGENT_MAX_RETRIES,
                CONTEXT_AGENT_MAX_ITERATIONS,
                CONTEXT_AGENT_VERBOSE,
            )

            return cls(
                semantic_enable=CONTEXT_AGENT_SEMANTIC_ENABLE,
                validation_enable=CONTEXT_AGENT_VALIDATION_ENABLE,
                max_retries=CONTEXT_AGENT_MAX_RETRIES,
                max_iterations=CONTEXT_AGENT_MAX_ITERATIONS,
                verbose=CONTEXT_AGENT_VERBOSE,
            )
        except ImportError:
            return cls()
