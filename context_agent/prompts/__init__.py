#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Prompts module for the Context Agent system.

This module contains system prompts and few-shot examples used by the agents.
"""

from context_agent.prompts.system_prompts import (
    ANALYZER_SYSTEM_PROMPT,
    SEMANTIC_SYSTEM_PROMPT,
    GENERATOR_SYSTEM_PROMPT,
    VALIDATOR_SYSTEM_PROMPT,
    ORCHESTRATOR_SYSTEM_PROMPT,
)
from context_agent.prompts.few_shot_examples import FEW_SHOT_EXAMPLES

__all__ = [
    "ANALYZER_SYSTEM_PROMPT",
    "SEMANTIC_SYSTEM_PROMPT",
    "GENERATOR_SYSTEM_PROMPT",
    "VALIDATOR_SYSTEM_PROMPT",
    "ORCHESTRATOR_SYSTEM_PROMPT",
    "FEW_SHOT_EXAMPLES",
]
