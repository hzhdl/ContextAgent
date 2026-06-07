#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
EVM Environment Context Management

Provides fixed EVM execution environment parameters for enhancing prompt generation.
"""

import time
from typing import Dict
from dataclasses import dataclass, field

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from utils import settings


@dataclass
class EVMContext:
    """EVM execution environment context."""

    # Block information
    block_number: int = 19000000
    block_timestamp: int = field(default_factory=lambda: int(time.time()))
    block_difficulty: int = 2000000000000000
    block_gaslimit: int = 30000000

    # Contract and account addresses
    contract_address: str = "0x1234567890123456789012345678901234567890"
    caller_address: str = field(
        default_factory=lambda: (
            settings.ATTACKER_ACCOUNTS[0]
            if settings.ATTACKER_ACCOUNTS
            else "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        )
    )
    origin_address: str = field(
        default_factory=lambda: (
            settings.ATTACKER_ACCOUNTS[0]
            if settings.ATTACKER_ACCOUNTS
            else "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        )
    )

    # Transaction information
    tx_gasprice: int = field(default_factory=lambda: settings.GAS_PRICE)
    tx_gaslimit: int = field(default_factory=lambda: settings.GAS_LIMIT)

    # Account balance
    account_balance: int = field(default_factory=lambda: settings.ACCOUNT_BALANCE)

    def to_prompt_section(self) -> str:
        """Generate a prompt section describing the EVM context."""
        return f"""## EVM Environment Context

The fuzzer executes with the following EVM environment parameters:

**Block Information:**
- block.number: {self.block_number}
- block.timestamp: {self.block_timestamp} (Unix timestamp, approximately {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.block_timestamp))})
- block.difficulty: {self.block_difficulty}
- block.gaslimit: {self.block_gaslimit}

**Contract & Account Addresses:**
- address(this): {self.contract_address} (contract under test)
- msg.sender / tx.origin: {self.caller_address} (caller/attacker address)

**Transaction Parameters:**
- tx.gasprice: {self.tx_gasprice}
- Gas limit: {self.tx_gaslimit}
- Account balance: {self.account_balance} wei ({self.account_balance / (10**18)} ETH)

When generating mock return values:
1. For timestamp-based values (e.g., updatedAt in Chainlink), use values relative to block.timestamp
2. For address values, you can use contract_address, caller_address, or generate reasonable addresses
3. For time-sensitive checks (e.g., "updatedAt > block.timestamp - 3600"), ensure values respect this context
"""

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "block": {
                "number": self.block_number,
                "timestamp": self.block_timestamp,
                "difficulty": self.block_difficulty,
                "gaslimit": self.block_gaslimit,
            },
            "addresses": {
                "contract": self.contract_address,
                "caller": self.caller_address,
                "origin": self.origin_address,
            },
            "transaction": {
                "gasprice": self.tx_gasprice,
                "gaslimit": self.tx_gaslimit,
            },
            "balance": self.account_balance,
        }


_global_evm_context = None


def get_evm_context() -> EVMContext:
    """Get the global EVM context singleton."""
    global _global_evm_context
    if _global_evm_context is None:
        _global_evm_context = EVMContext()
    return _global_evm_context


def set_evm_context(context: EVMContext):
    """Set the global EVM context."""
    global _global_evm_context
    _global_evm_context = context
