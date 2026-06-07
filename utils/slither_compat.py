#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Slither 版本兼容性模块

功能:
1. 统一 Slither 导入接口
2. 提供版本无关的工具函数
3. 兼容 slither-analyzer 0.6.x 到 0.11.x

使用方法:
    from slither_compat import (
        Slither,
        NodeType,
        is_library_contract,
        get_line_number,
        get_contract_by_name
    )
"""

import warnings
from typing import Optional, List, Any

# ============ Slither 核心导入 ============

# 统一 Slither 导入（兼容不同版本）
try:
    from slither import Slither
except ImportError:
    from slither.slither import Slither

# 获取版本信息
try:
    import slither as _slither_pkg
    SLITHER_VERSION = getattr(_slither_pkg, '__version__', 'unknown')
except:
    SLITHER_VERSION = 'unknown'

# ============ CFG 节点导入 ============

from slither.core.cfg.node import Node, NodeType

# ============ 声明类导入 ============

from slither.core.declarations import Contract, Function

try:
    from slither.core.declarations import Modifier
except ImportError:
    Modifier = None

# ============ IR 操作导入 ============

from slither.slithir.operations import (
    LowLevelCall,
    HighLevelCall,
    Send,
    Transfer,
    SolidityCall,
    LibraryCall,
)

# 可选 IR 操作（某些版本可能不存在）
try:
    from slither.slithir.operations import InternalCall
except ImportError:
    InternalCall = None

try:
    from slither.slithir.operations import Assignment, Binary, Unary, Return
except ImportError:
    Assignment = Binary = Unary = Return = None

try:
    from slither.slithir.operations import Index, Unpack, TypeConversion
except ImportError:
    Index = Unpack = TypeConversion = None

# ============ 表达式类型导入 ============

try:
    from slither.core.expressions.binary_operation import BinaryOperation, BinaryOperationType
except ImportError:
    BinaryOperation = BinaryOperationType = None

try:
    from slither.core.expressions.unary_operation import UnaryOperation, UnaryOperationType
except ImportError:
    UnaryOperation = UnaryOperationType = None

try:
    from slither.core.expressions.identifier import Identifier
except ImportError:
    Identifier = None

try:
    from slither.core.expressions.call_expression import CallExpression
except ImportError:
    CallExpression = None

# ============ 类型系统导入 ============

try:
    from slither.core.solidity_types.elementary_type import ElementaryType
except ImportError:
    ElementaryType = None

try:
    from slither.core.solidity_types.user_defined_type import UserDefinedType
except ImportError:
    UserDefinedType = None

try:
    from slither.core.solidity_types.array_type import ArrayType
except ImportError:
    ArrayType = None

try:
    from slither.core.solidity_types.mapping_type import MappingType
except ImportError:
    MappingType = None


# ============ 兼容性工具函数 ============

def is_library_contract(contract) -> bool:
    """
    兼容性检测合约是否为 library

    Args:
        contract: Slither Contract 对象

    Returns:
        True 如果是 library，否则 False
    """
    # 方式1: is_library 属性（旧版本）
    if hasattr(contract, 'is_library'):
        return contract.is_library
    # 方式2: contract_kind 属性（新版本）
    if hasattr(contract, 'contract_kind'):
        return str(contract.contract_kind).lower() == 'library'
    return False


def is_interface_contract(contract) -> bool:
    """
    检测合约是否为 interface

    Args:
        contract: Slither Contract 对象

    Returns:
        True 如果是 interface，否则 False
    """
    if hasattr(contract, 'is_interface'):
        return contract.is_interface
    if hasattr(contract, 'contract_kind'):
        return str(contract.contract_kind).lower() == 'interface'
    return False


def get_line_number(node) -> int:
    """
    兼容性获取节点行号

    Args:
        node: Slither Node 对象

    Returns:
        行号，如果无法获取返回 0
    """
    try:
        if hasattr(node, 'source_mapping') and node.source_mapping:
            sm = node.source_mapping
            # 方式1: 属性访问 (lines)
            if hasattr(sm, 'lines') and sm.lines:
                return sm.lines[0]
            # 方式2: 字典访问
            if isinstance(sm, dict):
                lines = sm.get('lines', [])
                if lines:
                    return lines[0]
            # 方式3: start 属性（更新版本）
            if hasattr(sm, 'start') and sm.start:
                if hasattr(sm.start, 'line'):
                    return sm.start.line
    except Exception:
        pass
    return 0


def get_contract_by_name(slither_instance, name: str) -> Optional[Any]:
    """
    兼容性获取指定名称的合约

    Args:
        slither_instance: Slither 实例
        name: 合约名称

    Returns:
        Contract 对象，如果未找到返回 None
    """
    # 方式1: get_contract_from_name 方法
    if hasattr(slither_instance, 'get_contract_from_name'):
        result = slither_instance.get_contract_from_name(name)
        if result:
            # 新版本可能返回列表
            return result[0] if isinstance(result, list) else result
    # 方式2: 遍历 contracts
    for contract in slither_instance.contracts:
        if contract.name == name:
            return contract
    return None


def get_first_non_library_contract(slither_instance) -> Optional[Any]:
    """
    获取第一个非库合约

    Args:
        slither_instance: Slither 实例

    Returns:
        Contract 对象，如果未找到返回 None
    """
    for contract in slither_instance.contracts:
        if not is_library_contract(contract) and not is_interface_contract(contract):
            return contract
    # 如果没有非库合约，返回第一个合约
    return slither_instance.contracts[0] if slither_instance.contracts else None


def get_function_signature(function) -> str:
    """
    兼容性获取函数签名

    Args:
        function: Slither Function 对象

    Returns:
        函数签名字符串
    """
    if hasattr(function, 'signature_str'):
        return function.signature_str
    if hasattr(function, 'full_name'):
        return function.full_name
    return function.name


def safe_get_ir_lvalue(ir) -> Optional[Any]:
    """
    安全获取 IR 操作的左值

    Args:
        ir: IR 操作对象

    Returns:
        左值对象，如果不存在返回 None
    """
    return getattr(ir, 'lvalue', None)


def safe_get_ir_rvalue(ir) -> Optional[Any]:
    """
    安全获取 IR 操作的右值

    Args:
        ir: IR 操作对象

    Returns:
        右值对象，如果不存在返回 None
    """
    return getattr(ir, 'rvalue', None)


def get_node_expression_str(node) -> str:
    """
    安全获取节点表达式字符串

    Args:
        node: Slither Node 对象

    Returns:
        表达式字符串，如果不存在返回空字符串
    """
    if hasattr(node, 'expression') and node.expression:
        return str(node.expression)
    return ""


# ============ 版本检测 ============

def is_slither_version_at_least(major: int, minor: int = 0) -> bool:
    """
    检测 slither 版本是否至少为指定版本

    Args:
        major: 主版本号
        minor: 次版本号

    Returns:
        True 如果版本满足要求
    """
    try:
        parts = SLITHER_VERSION.split('.')
        current_major = int(parts[0])
        current_minor = int(parts[1]) if len(parts) > 1 else 0
        return (current_major, current_minor) >= (major, minor)
    except:
        return False


# ============ 导出列表 ============

__all__ = [
    # 核心类
    'Slither',
    'Contract',
    'Function',
    'Modifier',
    'Node',
    'NodeType',

    # IR 操作
    'LowLevelCall',
    'HighLevelCall',
    'Send',
    'Transfer',
    'SolidityCall',
    'LibraryCall',
    'InternalCall',
    'Assignment',
    'Binary',
    'Unary',
    'Return',
    'Index',
    'Unpack',
    'TypeConversion',

    # 表达式
    'BinaryOperation',
    'BinaryOperationType',
    'UnaryOperation',
    'UnaryOperationType',
    'Identifier',
    'CallExpression',

    # 类型
    'ElementaryType',
    'UserDefinedType',
    'ArrayType',
    'MappingType',

    # 工具函数
    'is_library_contract',
    'is_interface_contract',
    'get_line_number',
    'get_contract_by_name',
    'get_first_non_library_contract',
    'get_function_signature',
    'safe_get_ir_lvalue',
    'safe_get_ir_rvalue',
    'get_node_expression_str',
    'is_slither_version_at_least',

    # 版本信息
    'SLITHER_VERSION',
]
