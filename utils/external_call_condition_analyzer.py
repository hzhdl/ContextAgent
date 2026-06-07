#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
基于Slither的智能合约外部调用条件语句分析器

功能:
1. 提取合约中所有条件语句（require、assert、if等）
2. 识别外部合约函数调用（HighLevelCall、LowLevelCall、接口调用）
3. 建立条件语句与外部调用的关联关系
4. 输出三层嵌套的JSON结构：目标函数签名 -> 外部函数签名 -> 详细信息
"""

from typing import Dict, List, Set, Any, Optional, Tuple
from dataclasses import dataclass, field
import json
import logging
from eth_utils.functional import T
from web3 import Web3

try:
    from slither import Slither
except ImportError:
    from slither.slither import Slither

from slither.core.declarations import Contract, Function, Modifier
from slither.core.cfg.node import Node, NodeType
from slither.core.variables.variable import Variable
from slither.slithir.operations import (
    LowLevelCall, HighLevelCall, Send, Transfer, SolidityCall, LibraryCall,
    Assignment, Binary, Unary, Return, InternalCall
)
from slither.slithir.variables import (
    TemporaryVariable, ReferenceVariable, TupleVariable
)
from slither.core.expressions.binary_operation import BinaryOperation, BinaryOperationType
from slither.core.expressions.unary_operation import UnaryOperation, UnaryOperationType
from slither.core.expressions.identifier import Identifier
from slither.core.expressions.call_expression import CallExpression

# 导入版本管理器
from solc_version_manager import get_compiler_config, get_solc_binary_path


@dataclass
class ExternalCallInfo:
    """外部调用信息"""
    call_line: int
    call_expression: str
    external_contract_name: str
    external_contract_variable: str
    external_function_name: str
    external_function_signature: str
    call_type: str  # "high_level", "low_level", "interface"
    function_selector: Optional[str] = None  # hex函数选择器，如 "0xabcd1234"
    selector_fallback: bool = False  # 是否使用fallback计算
    node: Node = None  # 保存节点引用用于数据流分析
    from_modifier: Optional[str] = None  # 如果来自 modifier，记录 modifier 名称
    return_types: List[str] = field(default_factory=list)  # 原始返回值类型列表（如 ["Market"]）
    return_types_expanded: List[str] = field(default_factory=list)  # 展开的基本类型列表（如 ["bool", "uint256", ...]）


@dataclass
class ConditionInfo:
    """条件语句信息"""
    condition_type: str  # "require", "assert", "if", "loop"
    condition_line: int
    condition_expression: str
    atomic_conditions: List[str] = field(default_factory=list)  # 拆分后的原子条件
    node: Node = None  # 保存节点引用用于数据流分析
    variables_used: Set[str] = field(default_factory=set)  # 条件中使用的变量
    variables_classified: Dict[str, str] = field(default_factory=dict)  # {变量名: 类型}
    from_modifier: Optional[str] = None  # 如果来自 modifier，记录 modifier 名称


@dataclass
class ConditionExternalCallRelation:
    """条件语句与外部调用的关联关系"""
    condition_info: ConditionInfo
    external_call_info: ExternalCallInfo
    relationship: str  # "direct" 或 "indirect"
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        result = {
            "condition_type": self.condition_info.condition_type,
            "condition_line": self.condition_info.condition_line,
            "condition_expression": self.condition_info.condition_expression,
            "atomic_conditions": self.condition_info.atomic_conditions,
            "variables_classified": self.condition_info.variables_classified,
            "condition_from_modifier": self.condition_info.from_modifier,
            "external_call_line": self.external_call_info.call_line,
            "external_call_expression": self.external_call_info.call_expression,
            "external_contract_name": self.external_call_info.external_contract_name,
            "external_contract_variable": self.external_call_info.external_contract_variable,
            "external_function_signature": self.external_call_info.external_function_signature,
            "external_function_selector": self.external_call_info.function_selector,
            "external_return_types": self.external_call_info.return_types,
            "external_return_types_expanded": self.external_call_info.return_types_expanded,
            "external_call_from_modifier": self.external_call_info.from_modifier,
            "call_type": self.external_call_info.call_type,
            "relationship": self.relationship
        }

        # 如果使用了fallback计算，添加标记
        if self.external_call_info.selector_fallback:
            result["selector_fallback"] = True

        return result


class ExternalCallConditionAnalyzer:
    """外部调用条件语句分析器"""
    
    def __init__(self, contract_file: str, contract_name: Optional[str] = None):
        """
        初始化分析器
        
        Args:
            contract_file: Solidity合约文件路径
            contract_name: 要分析的合约名称（可选）
        """
        try:
            self.contract_file = contract_file
            # 获取编译器配置并使用指定的 solc 二进制
            solc_version, _, _ = get_compiler_config(contract_file)
            solc_binary = get_solc_binary_path(solc_version)
            self.slither = Slither(contract_file, solc=solc_binary)
            self.contract_name = contract_name
            self.contract = self._get_target_contract()
        except Exception as e:
            print(e)
        
        # 已知的安全标准库列表（不视为外部调用）
        self.safe_libraries = {
            'SafeMath', 'Math', 'SignedMath',
            'Address', 'Strings', 'Arrays',
            'SafeCast', 'SafeERC20',
            'EnumerableSet', 'EnumerableMap',
            'Counters', 'BitMaps',
            'DSMath', 'PRBMath', 'ABDKMath64x64',
            'FixedPoint', 'FullMath', 'TickMath',
            'BytesLib', 'StringUtils',
        }
    
    def _get_target_contract(self) -> Optional[Contract]:
        """获取目标合约"""
        if not self.slither.contracts:
            return None
        
        if self.contract_name:
            for contract in self.slither.contracts:
                if contract.name == self.contract_name:
                    return contract
            return None
        else:
            # 返回第一个非库合约
            for contract in self.slither.contracts:
                is_lib = False
                if hasattr(contract, 'is_library'):
                    is_lib = contract.is_library
                elif hasattr(contract, 'contract_kind'):
                    is_lib = str(contract.contract_kind) == 'library'
                
                if not is_lib:
                    return contract
            return self.slither.contracts[0] if self.slither.contracts else None
    
    def _get_line_number(self, node: Node) -> int:
        """安全获取节点行号"""
        try:
            if hasattr(node, 'source_mapping') and node.source_mapping:
                # 方法1：通过 dict 获取
                if isinstance(node.source_mapping, dict):
                    lines = node.source_mapping.get('lines', [])
                    if lines:
                        return lines[0]
                # 方法2：通过属性获取
                elif hasattr(node.source_mapping, 'lines'):
                    if node.source_mapping.lines:
                        return node.source_mapping.lines[0]
                # 方法3：通过 start 属性获取（兼容不同版本）
                elif hasattr(node.source_mapping, 'start'):
                    # 尝试从 start 计算行号
                    start = node.source_mapping.start
                    if start and hasattr(start, 'line'):
                        return start.line
            
            # 方法4：尝试从表达式的源映射获取
            if hasattr(node, 'expression') and node.expression:
                if hasattr(node.expression, 'source_mapping') and node.expression.source_mapping:
                    if hasattr(node.expression.source_mapping, 'lines'):
                        if node.expression.source_mapping.lines:
                            return node.expression.source_mapping.lines[0]
        except:
            pass
        return 0

    def _classify_variable(self, var, function: Function) -> str:
        """
        判断变量类型并返回分类标识

        Args:
            var: 变量对象
            function: 所属函数

        Returns:
            变量类型：msg, block, tx, number, input, state, local, temp, unknown
        """
        var_str = str(var)

        # 检查特殊前缀
        if var_str.startswith('msg.'):
            return 'msg'
        elif var_str.startswith('block.'):
            return 'block'
        elif var_str.startswith('tx.'):
            return 'tx'
        elif var_str.isnumeric():
            return 'number'

        # 检查是否为函数参数
        if hasattr(function, 'parameters'):
            for param in function.parameters:
                if hasattr(param, 'name') and str(param.name) == var_str:
                    return 'input'
                if str(param) == var_str:
                    return 'input'

        # 检查变量对象类型
        if hasattr(var, '__class__'):
            class_name = var.__class__.__name__
            if 'StateVariable' in class_name:
                return 'state'
            elif 'LocalVariable' in class_name:
                return 'local'
            elif 'TemporaryVariable' in class_name or 'Temporary' in class_name:
                return 'temp'

        # 检查是否在合约状态变量中
        if hasattr(self.contract, 'state_variables'):
            for state_var in self.contract.state_variables:
                if hasattr(state_var, 'name') and str(state_var.name) == var_str:
                    return 'state'

        return 'unknown'

    def _extract_atomic_conditions(self, expression, function: Function) -> List[str]:
        """
        递归解析复杂条件表达式，拆分为原子条件列表

        Args:
            expression: Slither 表达式对象
            function: 所属函数

        Returns:
            原子条件字符串列表

        示例：
            require(a > 0 && b < 10) -> ["a > 0", "b < 10"]
        """
        constraints = []

        # 检查表达式类型
        if expression.__class__ not in [BinaryOperation, Identifier, CallExpression, UnaryOperation]:
            # 如果有 expressions 属性（复合表达式），递归处理
            if hasattr(expression, 'expressions'):
                for sub_exp in expression.expressions:
                    sub_constraints = self._extract_atomic_conditions(sub_exp, function)
                    constraints.extend(sub_constraints)
            return constraints

        # 处理二元运算
        if isinstance(expression, BinaryOperation):
            # 比较运算符：返回完整条件
            if expression.type in [
                BinaryOperationType.GREATER, BinaryOperationType.LESS,
                BinaryOperationType.GREATER_EQUAL, BinaryOperationType.LESS_EQUAL,
                BinaryOperationType.EQUAL, BinaryOperationType.NOT_EQUAL
            ]:
                constraints.append(str(expression))
            # 逻辑运算符：递归拆分左右子表达式
            elif expression.type in [BinaryOperationType.ANDAND, BinaryOperationType.OROR]:
                left_constraints = self._extract_atomic_conditions(expression.expression_left, function)
                right_constraints = self._extract_atomic_conditions(expression.expression_right, function)
                constraints.extend(left_constraints)
                constraints.extend(right_constraints)
            else:
                # 其他运算符（算术等），作为整体保留
                constraints.append(str(expression))

        # 处理一元运算（如 !condition）
        elif isinstance(expression, UnaryOperation):
            if expression.type in [UnaryOperationType.BANG]:
                constraints.append(str(expression))
            else:
                # 递归处理子表达式
                if hasattr(expression, 'expression'):
                    sub_constraints = self._extract_atomic_conditions(expression.expression, function)
                    constraints.extend(sub_constraints)

        # 处理标识符（单个变量）
        elif isinstance(expression, Identifier):
            constraints.append(str(expression))

        # 处理函数调用
        elif isinstance(expression, CallExpression):
            constraints.append(str(expression))

        # 处理复合表达式
        elif hasattr(expression, 'expressions'):
            for sub_exp in expression.expressions:
                sub_constraints = self._extract_atomic_conditions(sub_exp, function)
                constraints.extend(sub_constraints)

        return constraints

    def _is_basic_type(self, type_str: str) -> bool:
        """判断是否为 Solidity 基本类型"""
        basic_types = {
            'bool', 'string', 'bytes', 'address',
            'uint', 'uint8', 'uint16', 'uint24', 'uint32', 'uint40', 'uint48', 'uint56', 'uint64',
            'uint72', 'uint80', 'uint88', 'uint96', 'uint104', 'uint112', 'uint120', 'uint128',
            'uint136', 'uint144', 'uint152', 'uint160', 'uint168', 'uint176', 'uint184', 'uint192',
            'uint200', 'uint208', 'uint216', 'uint224', 'uint232', 'uint240', 'uint248', 'uint256',
            'int', 'int8', 'int16', 'int24', 'int32', 'int40', 'int48', 'int56', 'int64',
            'int72', 'int80', 'int88', 'int96', 'int104', 'int112', 'int120', 'int128',
            'int136', 'int144', 'int152', 'int160', 'int168', 'int176', 'int184', 'int192',
            'int200', 'int208', 'int216', 'int224', 'int232', 'int240', 'int248', 'int256',
            'bytes1', 'bytes2', 'bytes3', 'bytes4', 'bytes5', 'bytes6', 'bytes7', 'bytes8',
            'bytes9', 'bytes10', 'bytes11', 'bytes12', 'bytes13', 'bytes14', 'bytes15', 'bytes16',
            'bytes17', 'bytes18', 'bytes19', 'bytes20', 'bytes21', 'bytes22', 'bytes23', 'bytes24',
            'bytes25', 'bytes26', 'bytes27', 'bytes28', 'bytes29', 'bytes30', 'bytes31', 'bytes32',
        }

        # 去掉数组标记和 memory/storage 修饰
        base_type = type_str.replace('[]', '').split()[0]
        return base_type in basic_types

    def _expand_type(self, sol_type) -> List[str]:
        """
        递归展开类型为基本类型列表

        - 基本类型：直接返回
        - struct：递归展开所有字段到基本类型
        - contract/interface：展开为 address
        - enum：展开为 uint8
        - array：保持数组格式不展开
        - mapping：展开 value 类型

        Returns:
            展开后的基本类型列表
        """
        from slither.core.solidity_types.elementary_type import ElementaryType
        from slither.core.solidity_types.user_defined_type import UserDefinedType
        from slither.core.solidity_types.array_type import ArrayType
        from slither.core.solidity_types.mapping_type import MappingType

        try:
            # 基本类型：直接返回
            if isinstance(sol_type, ElementaryType):
                return [str(sol_type)]

            # 用户定义类型：可能是 struct, enum, contract, interface
            elif isinstance(sol_type, UserDefinedType):
                type_def = sol_type.type

                # struct：递归展开所有字段
                # 检查是否有 elems 属性（StructureSolc）
                if hasattr(type_def, 'elems'):
                    result = []
                    # elems 可能是字典或列表
                    if isinstance(type_def.elems, dict):
                        # 字典：遍历值（StructureVariableSolc 对象）
                        for field_name, field_var in type_def.elems.items():
                            if hasattr(field_var, 'type'):
                                field_types = self._expand_type(field_var.type)
                                result.extend(field_types)
                    elif hasattr(type_def.elems, '__iter__'):
                        # 列表：直接遍历
                        for elem in type_def.elems:
                            if hasattr(elem, 'type'):
                                field_types = self._expand_type(elem.type)
                                result.extend(field_types)
                    return result if result else [str(sol_type)]

                # 尝试 elems_ordered 属性（旧版本 struct）
                elif hasattr(type_def, 'elems_ordered'):
                    result = []
                    for elem in type_def.elems_ordered:
                        field_types = self._expand_type(elem.type)
                        result.extend(field_types)
                    return result if result else [str(sol_type)]

                # enum：Solidity 中 enum 实际是 uint8
                elif hasattr(type_def, 'values'):
                    return ['uint8']

                # contract/interface：Solidity 中是 address 类型
                elif hasattr(type_def, 'kind'):
                    # 检查 contract_kind 属性
                    kind = str(type_def.kind).lower() if type_def.kind else ''
                    if kind in ['interface', 'contract']:
                        return ['address']
                    # 如果无法确定，返回原始类型名
                    return [str(sol_type)]

                # 兼容：检查类名判断类型
                else:
                    class_name = type_def.__class__.__name__
                    # Contract 类型
                    if 'Contract' in class_name:
                        return ['address']
                    # Enum 类型
                    elif 'Enum' in class_name:
                        return ['uint8']
                    # 其他：返回原始类型
                    else:
                        return [str(sol_type)]

            # 数组：不展开，保持数组格式
            elif isinstance(sol_type, ArrayType):
                return [self._get_solidity_type(sol_type)]

            # mapping：展开 value 类型
            elif isinstance(sol_type, MappingType):
                return self._expand_type(sol_type.type_to)

            # 其他类型
            else:
                type_str = self._get_solidity_type(sol_type)
                return [type_str] if type_str else []

        except Exception as e:
            logging.debug(f"Failed to expand type {sol_type}: {e}")
            # fallback：返回原始类型字符串
            type_str = self._get_solidity_type(sol_type)
            return [type_str] if type_str else []

    def _get_function_selector(self, function_or_variable) -> Tuple[Optional[str], bool]:
        """
        从 Slither Function 或 StateVariable 对象获取函数选择器
        
        Args:
            function_or_variable: Slither Function 或 StateVariable 对象
            
        Returns:
            (selector_hex, is_fallback): 选择器hex字符串和是否使用fallback的标记
        """
        # 检查是否是 StateVariable（公共状态变量的 getter）
        if hasattr(function_or_variable, '__class__'):
            class_name = function_or_variable.__class__.__name__
            if 'StateVariable' in class_name:
                return self._get_state_variable_selector(function_or_variable)
        
        function = function_or_variable
        
        # Fallback: 手动计算
        
        try:
            # 尝试导入 Crypto.Hash.keccak
            try:
                from Crypto.Hash import keccak
                sig = None
                # 尝试获取签名
                
                if hasattr(function, 'full_name'):
                    sig = function.full_name
                # elif hasattr(function, 'signature'):
                #     sig = function.signature
                else:
                    # 无法获取签名，尝试构建基本签名
                    sig = f"{function.name}()"
                    logging.warning(f"Using basic signature '{sig}' for function '{function.name}'")
                
                
                # HexBytes.hex() 已经包含 0x 前缀
                return Web3.keccak(text=sig)[:4].hex(), True
            except ImportError:
                # 如果没有 Crypto，尝试使用 hashlib
                import hashlib
                # keccak256 不在标准 hashlib 中，记录错误
                logging.error(f"Cannot calculate keccak256 for '{function.name}': Crypto library not available")
                # 使用函数名的简单哈希作为最后手段
                return '0x' + hashlib.sha256(function.name.encode()).hexdigest()[:8], True
        except Exception as e:
            logging.error(f"Failed to calculate selector for '{function.name}': {e}")
            return None, True
    
    def _get_solidity_type(self, slither_type) -> str:
        """
        将 Slither 类型对象转换为 Solidity 类型字符串
        
        Args:
            slither_type: Slither 类型对象
            
        Returns:
            Solidity 类型字符串（如 "address", "uint256" 等）
        """
        try:
            # 方法1: 直接获取类型名称
            if hasattr(slither_type, 'name'):
                type_name = slither_type.name
                # 处理一些特殊情况
                if type_name == 'uint':
                    return 'uint256'
                if type_name == 'int':
                    return 'int256'
                return type_name
            
            # 方法2: 转换为字符串
            type_str = str(slither_type)
            
            # 清理类型字符串
            type_str = type_str.strip()
            if ' ' in type_str:
                type_str = type_str.split()[0]
            
            return type_str
        except Exception as e:
            logging.debug(f"Failed to convert Slither type: {e}")
            return "unknown"
    
    def _get_state_variable_selector(self, state_var) -> Tuple[Optional[str], bool]:
        """
        为公共状态变量的 getter 生成函数选择器
        
        Args:
            state_var: Slither StateVariable 对象
            
        Returns:
            (selector_hex, is_fallback): 选择器hex字符串和fallback标记
        """
        try:
            var_name = state_var.name
            signature = None
            
            # 获取变量类型
            if hasattr(state_var, 'type') and state_var.type:
                var_type = state_var.type
                type_str = str(var_type).lower()
                
                # 处理 mapping 类型
                if 'mapping' in type_str:
                    # 尝试获取 mapping 的 key 类型
                    if hasattr(var_type, 'type_from'):
                        key_type = self._get_solidity_type(var_type.type_from)
                        signature = f"{var_name}({key_type})"
                        logging.info(f"State variable mapping '{var_name}' signature: {signature}")
                    else:
                        # 无法获取 key 类型，尝试解析字符串
                        # 例如: "mapping(address => Market)"
                        import re
                        match = re.search(r'mapping\s*\(\s*(\w+)', type_str)
                        if match:
                            key_type = match.group(1)
                            signature = f"{var_name}({key_type})"
                            logging.info(f"State variable mapping '{var_name}' signature (parsed): {signature}")
                        else:
                            # 使用默认签名
                            signature = f"{var_name}(address)"
                            logging.warning(f"Cannot determine mapping key type for '{var_name}', using default: {signature}")
                
                # 处理数组类型
                elif '[]' in type_str or 'array' in type_str:
                    signature = f"{var_name}(uint256)"
                    logging.info(f"State variable array '{var_name}' signature: {signature}")
                
                # 简单类型的 getter（无参数）
                else:
                    signature = f"{var_name}()"
                    logging.info(f"State variable '{var_name}' signature: {signature}")
            else:
                # 无法获取类型，使用无参数签名
                signature = f"{var_name}()"
                logging.warning(f"Cannot get type for state variable '{var_name}', using: {signature}")
            
            # 计算选择器
            if signature:
                selector_bytes = Web3.keccak(text=signature)[:4]
                # HexBytes.hex() 已经包含 0x 前缀
                selector = selector_bytes.hex()
                logging.info(f"Generated selector for state variable '{var_name}': {selector} (signature: {signature})")
                return selector, True
            else:
                logging.error(f"Failed to generate signature for state variable '{var_name}'")
                return None, True
                
        except Exception as e:
            logging.error(f"Failed to generate selector for state variable '{state_var.name if hasattr(state_var, 'name') else 'unknown'}': {e}")
            import traceback
            traceback.print_exc()
            return None, True

    def _get_return_types(self, function_or_variable) -> Tuple[List[str], List[str]]:
        """
        提取函数返回值类型

        Args:
            function_or_variable: Slither Function 或 StateVariable 对象

        Returns:
            tuple: (原始类型列表, 展开后的基本类型列表)
                - 原始类型：如 ["Market"]，保留类型结构
                - 展开类型：如 ["bool", "uint256", "address", ...]，用于数据流分析
        """
        from slither.core.solidity_types.mapping_type import MappingType
        from slither.core.solidity_types.array_type import ArrayType

        try:
            # StateVariable：需要根据类型返回 getter 的返回类型
            if hasattr(function_or_variable, '__class__'):
                if 'StateVariable' in function_or_variable.__class__.__name__:
                    if hasattr(function_or_variable, 'type'):
                        var_type = function_or_variable.type

                        # mapping：getter 返回 value 类型
                        if isinstance(var_type, MappingType):
                            value_type = var_type.type_to
                            original_type = self._get_solidity_type(value_type)
                            original_types = [original_type] if original_type else []
                            expanded_types = self._expand_type(value_type)
                            return original_types, expanded_types

                        # array：getter 返回元素类型
                        elif isinstance(var_type, ArrayType):
                            element_type = var_type.type
                            original_type = self._get_solidity_type(element_type)
                            original_types = [original_type] if original_type else []
                            expanded_types = self._expand_type(element_type)
                            return original_types, expanded_types

                        # 简单类型
                        else:
                            original_type = self._get_solidity_type(var_type)
                            original_types = [original_type] if original_type else []
                            expanded_types = self._expand_type(var_type)
                            return original_types, expanded_types

            # Function：从 returns 属性提取
            if hasattr(function_or_variable, 'returns') and function_or_variable.returns:
                original_types = []
                expanded_types = []

                for ret in function_or_variable.returns:
                    if hasattr(ret, 'type'):
                        # 原始类型
                        type_str = self._get_solidity_type(ret.type)
                        if type_str:
                            original_types.append(type_str)

                        # 展开类型
                        expanded = self._expand_type(ret.type)
                        expanded_types.extend(expanded)

                return original_types, expanded_types

        except Exception as e:
            logging.debug(f"Failed to get return types: {e}")

        return [], []

    def _extract_conditions_from_modifier(self, modifier: Modifier, function: Function) -> List[ConditionInfo]:
        """
        提取 modifier 中的所有条件语句

        Args:
            modifier: Modifier 对象
            function: 使用该 modifier 的函数

        Returns:
            条件信息列表
        """
        conditions = []

        for node in modifier.nodes:
            # 使用现有的条件提取方法
            condition_info = self._extract_condition_info(node, function)
            if condition_info:
                # 标记来源于 modifier
                condition_info.from_modifier = modifier.name
                conditions.append(condition_info)

        return conditions

    def _extract_external_calls_from_modifier(self, modifier: Modifier, function: Function) -> List[ExternalCallInfo]:
        """
        提取 modifier 中的所有外部调用

        Args:
            modifier: Modifier 对象
            function: 使用该 modifier 的函数

        Returns:
            外部调用信息列表
        """
        external_calls = []

        for node in modifier.nodes:
            for ir in node.irs:
                # 使用现有的外部调用提取方法
                external_call_info = self._extract_external_call_info(node, ir, function)
                if external_call_info:
                    # 标记来源于 modifier
                    external_call_info.from_modifier = modifier.name
                    external_calls.append(external_call_info)

        return external_calls

    def _is_condition_node(self, node: Node) -> bool:
        """判断节点是否为条件语句节点"""
        if not hasattr(node, 'type'):
            return False

        # 检查节点类型
        condition_types = [NodeType.IF, NodeType.IFLOOP]
        if node.type in condition_types:
            return True

        # 精确检查 require、assert、revert（带括号避免误报）
        if node.type == NodeType.EXPRESSION:
            node_str = str(node)
            if "require(" in node_str or "assert(" in node_str:
                return True
            # 可选：支持 revert
            if "revert(" in node_str:
                return True

        return False
    
    def _get_condition_type(self, node: Node) -> str:
        """获取条件语句类型"""
        # 区分循环条件和分支条件
        if node.type == NodeType.IFLOOP:
            return "loop"
        elif node.type == NodeType.IF:
            return "if"

        # 精确检查表达式（带括号）
        node_str = str(node)
        if "require(" in node_str:
            return "require"
        elif "assert(" in node_str:
            return "assert"
        elif "revert(" in node_str:
            return "revert"

        return "if"
    
    def _extract_condition_info(self, node: Node, function: Function) -> Optional[ConditionInfo]:
        """提取条件语句信息（增强版）"""
        if not self._is_condition_node(node):
            return None

        condition_type = self._get_condition_type(node)
        line_num = self._get_line_number(node)

        # 提取条件参数（对于 require/assert/revert）
        condition_arg = None
        if condition_type in ["require", "assert", "revert"]:
            try:
                if hasattr(node, 'expression') and node.expression:
                    if hasattr(node.expression, 'arguments') and node.expression.arguments:
                        condition_arg = node.expression.arguments[0]
            except:
                pass

        # 获取条件表达式字符串
        if condition_arg:
            expr_str = str(condition_arg)
        else:
            expr_str = str(node.expression) if node.expression else ""

        # 拆分复杂条件为原子条件
        atomic_conditions = []
        try:
            if condition_arg:
                atomic_conditions = self._extract_atomic_conditions(condition_arg, function)
            elif node.expression:
                atomic_conditions = self._extract_atomic_conditions(node.expression, function)
        except Exception as e:
            logging.debug(f"Failed to extract atomic conditions: {e}")
            atomic_conditions = []

        # 增强变量提取（包括函数参数、状态变量、局部变量）
        variables_used = set()
        variables_classified = {}

        # 状态变量
        if hasattr(node, 'state_variables_read'):
            for var in node.state_variables_read:
                var_name = str(var.name) if hasattr(var, 'name') else str(var)
                variables_used.add(var_name)
                variables_classified[var_name] = self._classify_variable(var, function)

        # 局部变量
        if hasattr(node, 'local_variables_read'):
            for var in node.local_variables_read:
                var_name = str(var.name) if hasattr(var, 'name') else str(var)
                variables_used.add(var_name)
                variables_classified[var_name] = self._classify_variable(var, function)

        # 尝试提取更多变量（从 IR 操作中）
        try:
            for ir in node.irs:
                if hasattr(ir, 'read'):
                    for var in ir.read:
                        var_name = str(var.name) if hasattr(var, 'name') else str(var)
                        if var_name not in variables_used:
                            variables_used.add(var_name)
                            variables_classified[var_name] = self._classify_variable(var, function)
        except:
            pass

        return ConditionInfo(
            condition_type=condition_type,
            condition_line=line_num,
            condition_expression=expr_str,
            atomic_conditions=atomic_conditions,
            node=node,
            variables_used=variables_used,
            variables_classified=variables_classified,
            from_modifier=None  # 默认不来自 modifier，在调用处设置
        )
    
    def _is_library_or_safe_call(self, ir) -> bool:
        """判断是否为库调用或安全库调用"""
        if isinstance(ir, LibraryCall):
            return True
        
        if isinstance(ir, HighLevelCall):
            if hasattr(ir, 'function') and ir.function:
                called_function = ir.function
                if hasattr(called_function, 'contract') and called_function.contract:
                    contract = called_function.contract
                    
                    if hasattr(contract, 'contract_kind'):
                        if str(contract.contract_kind).lower() == 'library':
                            return True
                    
                    if hasattr(contract, 'is_library') and contract.is_library:
                        return True
                    
                    if hasattr(contract, 'name') and contract.name in self.safe_libraries:
                        return True
            
            if hasattr(ir, 'destination') and ir.destination:
                destination = ir.destination
                if hasattr(destination, 'type') and destination.type:
                    type_obj = destination.type
                    if hasattr(type_obj, 'type') and hasattr(type_obj.type, 'name'):
                        contract_name = type_obj.type.name
                        if contract_name in self.safe_libraries:
                            return True
                    if hasattr(type_obj, 'name') and type_obj.name in self.safe_libraries:
                        return True
        
        return False

    def _is_true_library_call(self, ir) -> bool:
        """Check if an IR is a true library call (e.g., SafeMath) rather than an interface call."""
        if not isinstance(ir, LibraryCall):
            return True  # Not a library call at all

        # Check if the destination contract is a known safe library
        if hasattr(ir, 'destination') and ir.destination:
            if hasattr(ir.destination, 'type') and ir.destination.type:
                type_obj = ir.destination.type
                if hasattr(type_obj, 'type') and hasattr(type_obj.type, 'name'):
                    if type_obj.type.name in self.safe_libraries:
                        return True
                if hasattr(type_obj, 'name') and type_obj.name in self.safe_libraries:
                    return True

        # Check contract kind
        if hasattr(ir, 'function') and ir.function:
            if hasattr(ir.function, 'contract') and ir.function.contract:
                contract = ir.function.contract
                if hasattr(contract, 'name') and contract.name in self.safe_libraries:
                    return True
                if hasattr(contract, 'is_library') and contract.is_library:
                    return True
                if hasattr(contract, 'contract_kind'):
                    if str(contract.contract_kind).lower() == 'library':
                        return True

        return False

    def _extract_from_internal_call(self, ir, node: Node, function: Function) -> Optional[ExternalCallInfo]:
        """Extract external call info from an InternalCall IR that is actually an external call."""
        line_num = self._get_line_number(node)

        contract_name = "Unknown"
        contract_variable = "unknown"
        function_name = "unknown"
        function_signature = "unknown"

        if hasattr(ir, 'function') and ir.function:
            function_name = ir.function.name
            function_signature = (
                ir.function.signature_str
                if hasattr(ir.function, 'signature_str')
                else function_name
            )

            if hasattr(ir.function, 'contract') and ir.function.contract:
                contract_name = ir.function.contract.name
                contract_variable = contract_name

        call_expr = f"{contract_variable}.{function_name}(...)"

        # Get function selector and return types
        selector = None
        selector_fallback = False
        original_types = []
        expanded_types = []
        if hasattr(ir, 'function') and ir.function:
            selector, selector_fallback = self._get_function_selector(ir.function)
            original_types, expanded_types = self._get_return_types(ir.function)

        return ExternalCallInfo(
            call_line=line_num,
            call_expression=call_expr,
            external_contract_name=contract_name,
            external_contract_variable=contract_variable,
            external_function_name=function_name,
            external_function_signature=function_signature,
            call_type="high_level",
            function_selector=selector,
            selector_fallback=selector_fallback,
            return_types=original_types,
            return_types_expanded=expanded_types,
            node=node,
        )

    def _extract_from_library_call(self, ir, node: Node, function: Function) -> Optional[ExternalCallInfo]:
        """Extract external call info from a LibraryCall IR that is actually an interface call."""
        line_num = self._get_line_number(node)

        contract_name = "Unknown"
        contract_variable = "unknown"
        function_name = "unknown"
        function_signature = "unknown"

        if hasattr(ir, 'function') and ir.function:
            function_name = ir.function.name
            function_signature = (
                ir.function.signature_str
                if hasattr(ir.function, 'signature_str')
                else function_name
            )

            if hasattr(ir.function, 'contract') and ir.function.contract:
                contract_name = ir.function.contract.name

        if hasattr(ir, 'destination') and ir.destination:
            contract_variable = str(ir.destination)
            if hasattr(ir.destination, 'type') and ir.destination.type:
                type_obj = ir.destination.type
                if hasattr(type_obj, 'type') and hasattr(type_obj.type, 'name'):
                    contract_name = type_obj.type.name

        call_expr = f"{contract_variable}.{function_name}(...)"

        selector = None
        selector_fallback = False
        original_types = []
        expanded_types = []
        if hasattr(ir, 'function') and ir.function:
            selector, selector_fallback = self._get_function_selector(ir.function)
            original_types, expanded_types = self._get_return_types(ir.function)

        return ExternalCallInfo(
            call_line=line_num,
            call_expression=call_expr,
            external_contract_name=contract_name,
            external_contract_variable=contract_variable,
            external_function_name=function_name,
            external_function_signature=function_signature,
            call_type="interface",
            function_selector=selector,
            selector_fallback=selector_fallback,
            return_types=original_types,
            return_types_expanded=expanded_types,
            node=node,
        )

    def _extract_external_call_info(self, node: Node, ir, function: Function) -> Optional[ExternalCallInfo]:
        """提取外部调用信息"""
        line_num = self._get_line_number(node)
        
        # 处理 HighLevelCall
        if isinstance(ir, HighLevelCall):
            # 排除库调用
            if self._is_library_or_safe_call(ir):
                return None
            
            # 获取外部合约信息
            contract_name = "Unknown"
            contract_variable = "unknown"
            function_name = "unknown"
            function_signature = "unknown"
            
            if hasattr(ir, 'function') and ir.function:
                function_name = ir.function.name
                function_signature = ir.function.signature_str if hasattr(ir.function, 'signature_str') else function_name
                
                if hasattr(ir.function, 'contract') and ir.function.contract:
                    contract_name = ir.function.contract.name
            
            # 获取合约变量名
            if hasattr(ir, 'destination') and ir.destination:
                contract_variable = str(ir.destination)
                
                # 尝试获取更准确的合约类型名
                if hasattr(ir.destination, 'type') and ir.destination.type:
                    type_obj = ir.destination.type
                    if hasattr(type_obj, 'type') and hasattr(type_obj.type, 'name'):
                        contract_name = type_obj.type.name
            
            # 构建调用表达式
            call_expr = f"{contract_variable}.{function_name}(...)"
            
            # 获取函数选择器和返回值类型
            selector = None
            selector_fallback = False
            original_types = []
            expanded_types = []
            if hasattr(ir, 'function') and ir.function:
                selector, selector_fallback = self._get_function_selector(ir.function)
                original_types, expanded_types = self._get_return_types(ir.function)

            return ExternalCallInfo(
                call_line=line_num,
                call_expression=call_expr,
                external_contract_name=contract_name,
                external_contract_variable=contract_variable,
                external_function_name=function_name,
                external_function_signature=function_signature,
                call_type="high_level",
                function_selector=selector,
                selector_fallback=selector_fallback,
                return_types=original_types,
                return_types_expanded=expanded_types,
                node=node
            )
        
        # 处理 LowLevelCall
        if isinstance(ir, LowLevelCall):
            call_type_name = "call"
            if hasattr(ir, 'function_name'):
                call_type_name = ir.function_name
            
            destination = "unknown"
            if hasattr(ir, 'destination'):
                destination = str(ir.destination)
            
            call_expr = f"{destination}.{call_type_name}(...)"
            
            # 低级调用没有函数选择器，记录日志
            logging.info(f"Low-level call detected: {call_expr}, no selector available")
            
            return ExternalCallInfo(
                call_line=line_num,
                call_expression=call_expr,
                external_contract_name="Address",
                external_contract_variable=destination,
                external_function_name=call_type_name,
                external_function_signature=call_type_name,
                call_type="low_level",
                function_selector=None,
                selector_fallback=False,
                node=node
            )

        # Handle InternalCall that is actually an external call
        if isinstance(ir, InternalCall):
            if hasattr(ir, 'function') and ir.function:
                if hasattr(ir.function, 'contract') and ir.function.contract:
                    # If the called function's contract differs from the current contract,
                    # this is effectively an external call
                    if ir.function.contract != self.contract:
                        # Skip known safe libraries
                        if hasattr(ir.function.contract, 'name') and ir.function.contract.name in self.safe_libraries:
                            return None
                        if hasattr(ir.function.contract, 'is_library') and ir.function.contract.is_library:
                            return None
                        if hasattr(ir.function.contract, 'contract_kind'):
                            if str(ir.function.contract.contract_kind).lower() == 'library':
                                return None
                        return self._extract_from_internal_call(ir, node, function)

        # Handle LibraryCall that is actually an interface call
        if isinstance(ir, LibraryCall):
            if not self._is_true_library_call(ir):
                return self._extract_from_library_call(ir, node, function)

        return None
    
    def _check_direct_relation(self, condition_node: Node, external_call_node: Node) -> bool:
        """检查条件节点和外部调用节点是否有直接关系（在同一节点中）"""
        return condition_node == external_call_node

    def _check_order_in_function(self, external_call_info: ExternalCallInfo,
                                   condition_info: ConditionInfo,
                                   function: Function) -> bool:
        """检查函数体内外部调用是否在条件之前"""
        if external_call_info.call_line > 0 and condition_info.condition_line > 0:
            return external_call_info.call_line < condition_info.condition_line
        else:
            # 使用节点索引
            try:
                if hasattr(function, 'nodes'):
                    ext_node_idx = function.nodes.index(external_call_info.node)
                    cond_node_idx = function.nodes.index(condition_info.node)
                    return ext_node_idx < cond_node_idx
            except:
                pass
            return True

    def _check_order_in_modifier(self, external_call_info: ExternalCallInfo,
                                   condition_info: ConditionInfo,
                                   function: Function) -> bool:
        """检查同一 modifier 内的顺序"""
        # 找到对应的 modifier
        modifier_name = condition_info.from_modifier
        modifier = None
        for mod in function.modifiers:
            if mod.name == modifier_name:
                modifier = mod
                break

        if not modifier:
            return True

        # 在 modifier 节点列表中比较位置
        try:
            if hasattr(modifier, 'nodes'):
                ext_idx = modifier.nodes.index(external_call_info.node)
                cond_idx = modifier.nodes.index(condition_info.node)
                return ext_idx < cond_idx
        except:
            # 使用行号
            if external_call_info.call_line > 0 and condition_info.condition_line > 0:
                return external_call_info.call_line < condition_info.condition_line
        return True

    def _check_modifier_order(self, external_call_info: ExternalCallInfo,
                               condition_info: ConditionInfo,
                               function: Function) -> bool:
        """检查不同 modifier 之间的顺序"""
        # Modifier 按照声明顺序执行
        if not hasattr(function, 'modifiers'):
            return True

        modifier_names = [mod.name for mod in function.modifiers]

        ext_mod = external_call_info.from_modifier
        cond_mod = condition_info.from_modifier

        try:
            ext_idx = modifier_names.index(ext_mod)
            cond_idx = modifier_names.index(cond_mod)
            return ext_idx < cond_idx
        except:
            return True

    def _check_indirect_relation(self, condition_info: ConditionInfo, 
                                  external_call_info: ExternalCallInfo,
                                  function: Function) -> bool:
        """
        检查条件节点和外部调用节点是否有间接关系（通过变量依赖）
        
        策略：检查条件语句使用的变量是否在外部调用节点中被写入
        """
        if not condition_info.variables_used:
            return False
        
        # 获取外部调用节点写入的变量
        external_node = external_call_info.node
        variables_written = set()
        
        if hasattr(external_node, 'state_variables_written'):
            for var in external_node.state_variables_written:
                variables_written.add(str(var.name))
        
        if hasattr(external_node, 'local_variables_written'):
            for var in external_node.local_variables_written:
                variables_written.add(str(var.name))
        
        # 检查是否有交集
        return bool(condition_info.variables_used & variables_written)
    
    def analyze_function(self, function: Function) -> List[ConditionExternalCallRelation]:
        """
        Analyze a single function, extracting condition-external call relations (with Modifier support).

        Args:
            function: The function to analyze

        Returns:
            List of condition-external call relations
        """
        relations = []

        # Log function type
        func_type = "normal"
        if hasattr(function, 'view') and function.view:
            func_type = "view"
        elif hasattr(function, 'pure') and function.pure:
            func_type = "pure"
        elif hasattr(function, 'is_payable') and function.is_payable:
            func_type = "payable"

        logging.debug(f"Analyzing function: {function.name} (type: {func_type})")

        # 第一步：提取 modifier 中的条件和外部调用
        modifier_conditions = []
        modifier_external_calls = []

        if hasattr(function, 'modifiers') and function.modifiers:
            for modifier in function.modifiers:
                # 提取 modifier 条件
                try:
                    mod_conds = self._extract_conditions_from_modifier(modifier, function)
                    modifier_conditions.extend(mod_conds)
                except Exception as e:
                    logging.debug(f"Failed to extract conditions from modifier {modifier.name}: {e}")

                # 提取 modifier 外部调用
                try:
                    mod_calls = self._extract_external_calls_from_modifier(modifier, function)
                    modifier_external_calls.extend(mod_calls)
                except Exception as e:
                    logging.debug(f"Failed to extract external calls from modifier {modifier.name}: {e}")

        # 第二步：提取函数体中的条件和外部调用
        function_conditions = []
        function_external_calls = []

        for node in function.nodes:
            # Extract conditions
            condition_info = self._extract_condition_info(node, function)
            if condition_info:
                function_conditions.append(condition_info)

            # Log IR types for each node
            ir_types = [type(ir).__name__ for ir in node.irs]
            if ir_types:
                logging.debug(f"  Node at line {self._get_line_number(node)}: IR types = {ir_types}")

            # Extract external calls
            for ir in node.irs:
                external_call_info = self._extract_external_call_info(node, ir, function)
                if external_call_info:
                    function_external_calls.append(external_call_info)
                    logging.info(f"  Detected external call: {external_call_info.call_expression} (type: {external_call_info.call_type})")

        # Merge conditions and external calls
        all_conditions = modifier_conditions + function_conditions
        all_external_calls = modifier_external_calls + function_external_calls

        logging.info(f"Function {function.name}: found {len(all_external_calls)} external call(s), {len(all_conditions)} condition(s)")

        # 第三步：建立关联关系
        for condition_info in all_conditions:
            condition_node = condition_info.node

            # 检查条件节点本身是否包含外部调用（直接关联）
            for ir in condition_node.irs:
                external_call_info = self._extract_external_call_info(condition_node, ir, function)
                if external_call_info:
                    # 如果条件来自 modifier，标记外部调用也来自同一 modifier
                    if condition_info.from_modifier:
                        external_call_info.from_modifier = condition_info.from_modifier
                    relations.append(ConditionExternalCallRelation(
                        condition_info=condition_info,
                        external_call_info=external_call_info,
                        relationship="direct"
                    ))

            # 检查间接关联
            for external_call_info in all_external_calls:
                # 跳过已建立直接关联的
                if external_call_info.node == condition_node:
                    continue

                # 判断调用是否在条件之前
                call_before_condition = False

                # 如果都来自 modifier，检查是否同一个 modifier
                if (condition_info.from_modifier and
                    external_call_info.from_modifier):
                    if condition_info.from_modifier == external_call_info.from_modifier:
                        # 同一个 modifier 内，检查顺序
                        call_before_condition = self._check_order_in_modifier(
                            external_call_info, condition_info, function
                        )
                    else:
                        # 不同 modifier：按 modifier 顺序
                        call_before_condition = self._check_modifier_order(
                            external_call_info, condition_info, function
                        )
                elif condition_info.from_modifier and not external_call_info.from_modifier:
                    # Modifier 条件 vs 函数体调用：调用在条件之后（不相关，跳过）
                    call_before_condition = False
                elif not condition_info.from_modifier and external_call_info.from_modifier:
                    # 函数体条件 vs Modifier 调用：调用在条件之前
                    call_before_condition = True
                else:
                    # 都在函数体内，使用原有逻辑
                    call_before_condition = self._check_order_in_function(
                        external_call_info, condition_info, function
                    )

                if call_before_condition:
                    if self._check_indirect_relation(condition_info, external_call_info, function):
                        relations.append(ConditionExternalCallRelation(
                            condition_info=condition_info,
                            external_call_info=external_call_info,
                            relationship="indirect"
                        ))

        return relations
    
    def _extract_all_external_calls(self, function: Function) -> List[ExternalCallInfo]:
        """
        Extract all external calls from a function (including modifiers),
        regardless of whether they are associated with conditions.

        This is used to ensure external calls in functions without conditions
        (e.g., view functions with only return statements) are still captured.

        Args:
            function: The function to analyze

        Returns:
            List of ExternalCallInfo objects
        """
        external_calls = []

        # Extract from modifiers
        if hasattr(function, 'modifiers') and function.modifiers:
            for modifier in function.modifiers:
                try:
                    mod_calls = self._extract_external_calls_from_modifier(modifier, function)
                    external_calls.extend(mod_calls)
                except Exception as e:
                    logging.debug(f"Failed to extract external calls from modifier {modifier.name}: {e}")

        # Extract from function body
        for node in function.nodes:
            for ir in node.irs:
                external_call_info = self._extract_external_call_info(node, ir, function)
                if external_call_info:
                    external_calls.append(external_call_info)

        return external_calls

    def analyze(self) -> Dict[str, Any]:
        """
        分析整个合约，提取所有条件语句与外部调用的关联关系
        
        Returns:
            三层嵌套的JSON结构：
            {
                "ContractName.functionName(params)": {
                    "ExternalContract.functionName(params)": [
                        {详细信息}
                    ]
                }
            }
        """
        if not self.contract:
            return {
                "error": "No contract found or contract parsing failed",
                "contract_name": None,
                "results": {}
            }
        
        results = {}
        
        # 遍历所有函数
        for function in self.contract.functions:
            # 跳过构造函数、fallback等
            if function.is_constructor:
                continue
            
            # 兼容不同版本的 Slither
            if hasattr(function, 'is_fallback') and function.is_fallback:
                continue
            if hasattr(function, 'is_receive') and function.is_receive:
                continue
            
            # 通过函数名判断（兼容旧版本）
            if function.name in ['', 'fallback', 'receive']:
                continue
            
            # 分析函数
            relations = self.analyze_function(function)
            
            if not relations:
                continue
            
            # 构建函数签名
            function_signature = f"{self.contract.name}.{function.signature_str}"
            
            # 按外部函数签名分组
            external_call_groups = {}
            for relation in relations:
                ext_sig = relation.external_call_info.external_function_signature
                
                # 如果外部函数签名不完整，使用更详细的标识
                if ext_sig == "unknown" or not ext_sig:
                    ext_sig = f"{relation.external_call_info.external_contract_name}.{relation.external_call_info.external_function_name}"
                else:
                    ext_sig = f"{relation.external_call_info.external_contract_name}.{ext_sig}"
                
                if ext_sig not in external_call_groups:
                    external_call_groups[ext_sig] = []
                
                external_call_groups[ext_sig].append(relation.to_dict())
            
            results[function_signature] = external_call_groups
        
        return {
            "contract_name": self.contract.name,
            "contract_file": self.contract_file,
            "results": results
        }
    
    def analyze_with_selectors(self) -> Dict[str, Any]:
        """
        分析整个合约，生成基于hex选择器的JSON结构（用于EVM注入）
        
        Returns:
            基于选择器的JSON结构：
            {
                "results": {
                    "0xa1fdc2": {  // 目标函数选择器
                        "0xb2c3d4": {  // 外部函数选择器
                            "target_function_signature": "...",
                            "external_function_signature": "...",
                            "conditions": [...]
                        }
                    }
                },
                "function_selector_map": {
                    "0xa1fdc2": "ContractName.functionName(...)"
                }
            }
        """
        if not self.contract:
            return {
                "error": "No contract found or contract parsing failed",
                "contract_name": None,
                "results": {},
                "function_selector_map": {}
            }
        
        results = {}
        selector_map = {}
        
        # 遍历所有函数
        for function in self.contract.functions:
            # 跳过构造函数、fallback等
            if function.is_constructor:
                continue
            
            # 兼容不同版本的 Slither
            if hasattr(function, 'is_fallback') and function.is_fallback:
                continue
            if hasattr(function, 'is_receive') and function.is_receive:
                continue
            
            # 通过函数名判断（兼容旧版本）
            if function.name in ['', 'fallback', 'receive']:
                continue
            
            # 获取目标函数选择器
            target_selector, target_fallback = self._get_function_selector(function)
            if not target_selector:
                logging.warning(f"Skipping function '{function.name}' - no selector available")
                continue
            
            # 构建函数签名
            function_signature = f"{self.contract.name}.{function.signature_str}"
            selector_map[target_selector] = function_signature
            
            # 分析函数
            relations = self.analyze_function(function)

            # 按外部函数选择器分组
            if target_selector not in results:
                results[target_selector] = {}

            external_call_groups = {}

            if relations:
                # Build groups from condition-call relations
                for relation in relations:
                    ext_selector = relation.external_call_info.function_selector

                    # 如果没有外部选择器，跳过或使用函数名作为key
                    if not ext_selector:
                        ext_selector = f"{relation.external_call_info.external_contract_name}.{relation.external_call_info.external_function_name}"
                        logging.warning(f"No selector for external call '{ext_selector}', using function name as key")
                    else:
                        # 记录到映射表
                        ext_sig = f"{relation.external_call_info.external_contract_name}.{relation.external_call_info.external_function_signature}"
                        if ext_selector not in selector_map:
                            selector_map[ext_selector] = ext_sig

                    if ext_selector not in external_call_groups:
                        external_call_groups[ext_selector] = {
                            "target_function_signature": function_signature,
                            "target_function_selector": target_selector,
                            "external_function_signature": f"{relation.external_call_info.external_contract_name}.{relation.external_call_info.external_function_signature}",
                            "external_function_selector": ext_selector,
                            "external_return_types": relation.external_call_info.return_types,
                            "external_return_types_expanded": relation.external_call_info.return_types_expanded,
                            "conditions": []
                        }
                        if target_fallback:
                            external_call_groups[ext_selector]["target_selector_fallback"] = True
                        if relation.external_call_info.selector_fallback:
                            external_call_groups[ext_selector]["external_selector_fallback"] = True

                    external_call_groups[ext_selector]["conditions"].append(relation.to_dict())
            else:
                # No relations found, but there may be standalone external calls
                # (e.g., view functions with external calls in return statements)
                standalone_calls = self._extract_all_external_calls(function)
                for ext_call_info in standalone_calls:
                    ext_selector = ext_call_info.function_selector

                    if not ext_selector:
                        ext_selector = f"{ext_call_info.external_contract_name}.{ext_call_info.external_function_name}"
                        logging.warning(f"No selector for standalone external call '{ext_selector}', using function name as key")
                    else:
                        ext_sig = f"{ext_call_info.external_contract_name}.{ext_call_info.external_function_signature}"
                        if ext_selector not in selector_map:
                            selector_map[ext_selector] = ext_sig

                    if ext_selector not in external_call_groups:
                        external_call_groups[ext_selector] = {
                            "target_function_signature": function_signature,
                            "target_function_selector": target_selector,
                            "external_function_signature": f"{ext_call_info.external_contract_name}.{ext_call_info.external_function_signature}",
                            "external_function_selector": ext_selector,
                            "external_return_types": ext_call_info.return_types,
                            "external_return_types_expanded": ext_call_info.return_types_expanded,
                            "conditions": []  # No conditions for standalone calls
                        }
                        if target_fallback:
                            external_call_groups[ext_selector]["target_selector_fallback"] = True
                        if ext_call_info.selector_fallback:
                            external_call_groups[ext_selector]["external_selector_fallback"] = True

                        logging.info(f"  Added standalone external call: {ext_call_info.call_expression} in {function.name}")

            if external_call_groups:
                results[target_selector] = external_call_groups
        
        return {
            "contract_name": self.contract.name,
            "contract_file": self.contract_file,
            "results": results,
            "function_selector_map": selector_map
        }
    
    def analyze_and_save(self, output_file: str) -> Dict[str, Any]:
        """
        分析合约并保存结果到JSON文件（人类可读版本）
        
        Args:
            output_file: 输出文件路径
            
        Returns:
            分析结果
        """
        results = self.analyze()
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        return results
    
    def analyze_and_save_with_selectors(self, output_file: str) -> Dict[str, Any]:
        """
        分析合约并保存基于选择器的结果到JSON文件（EVM注入版本）
        
        Args:
            output_file: 输出文件路径
            
        Returns:
            分析结果
        """
        results = self.analyze_with_selectors()
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        return results
    
    def analyze_and_save_both(self, base_filename: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        分析合约并同时保存两个版本的JSON文件
        
        Args:
            base_filename: 基础文件名（不含扩展名）
            
        Returns:
            (人类可读版本结果, EVM注入版本结果)
        """
        import os
        
        # 保存人类可读版本
        readable_file = f"{base_filename}_external_call_conditions.json"
        # 确保目录存在
        os.makedirs(os.path.dirname(readable_file) if os.path.dirname(readable_file) else '.', exist_ok=True)
        readable_results = self.analyze_and_save(readable_file)
        
        # 保存EVM注入版本
        selector_file = f"{base_filename}_external_call_conditions_selectors.json"
        selector_results = self.analyze_and_save_with_selectors(selector_file)
        
        return readable_results, selector_results


def main():
    """测试代码"""
    import sys
    
    # 配置logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(levelname)s: %(message)s'
    )
    
    print("=" * 80)
    print("智能合约外部调用条件语句分析器（增强版）")
    print("=" * 80)
    
    # 测试合约文件
    test_file = "/home/hzh/AMFuzz/benchmark/contracts_sample/large/Liquidator_0x1055be4bf7338c7606d9efdcf80593f180ba043e.sol"
    base_filename = "/home/hzh/AMFuzz/fuzzer/contracts_external_call_conditions/Liquidator_0x1055be4bf7338c7606d9efdcf80593f180ba043e"
    contract_name = "Liquidator"
    
    try:
        print(f"\n分析合约文件: {test_file}")
        print(f"合约名称: {contract_name}")
        print("-" * 80)
        
        # 创建分析器
        analyzer = ExternalCallConditionAnalyzer(test_file, contract_name)
        
        # 同时生成两个版本的JSON
        print("\n正在生成两个版本的分析结果...")
        readable_results, selector_results = analyzer.analyze_and_save_both(base_filename)
        
        # 检查错误
        if 'error' in readable_results:
            print(f"\n错误: {readable_results['error']}")
            return
        
        # 打印摘要 - 人类可读版本
        print(f"\n【人类可读版本】")
        print(f"合约名称: {readable_results['contract_name']}")
        print(f"分析的函数数: {len(readable_results['results'])}")
        
        # 统计总关联数
        total_relations = 0
        for func_sig, ext_calls in readable_results['results'].items():
            for ext_sig, relations in ext_calls.items():
                total_relations += len(relations)
        
        print(f"发现的条件-外部调用关联数: {total_relations}")
        
        # 打印摘要 - EVM注入版本
        print(f"\n【EVM注入版本】")
        print(f"合约名称: {selector_results['contract_name']}")
        print(f"函数选择器数量: {len(selector_results['results'])}")
        print(f"选择器映射数量: {len(selector_results['function_selector_map'])}")
        
        # 打印详细结果（人类可读版本）
        print("\n" + "=" * 80)
        print("详细分析结果（人类可读版本）:")
        print("=" * 80)
        
        for func_sig, ext_calls in readable_results['results'].items():
            print(f"\n函数: {func_sig}")
            for ext_sig, relations in ext_calls.items():
                print(f"  外部调用: {ext_sig}")
                for i, relation in enumerate(relations, 1):
                    print(f"    [{i}] 条件类型: {relation['condition_type']}")
                    print(f"        条件行号: {relation['condition_line']}")
                    print(f"        外部调用行号: {relation['external_call_line']}")
                    print(f"        外部选择器: {relation.get('external_function_selector', 'N/A')}")
                    print(f"        关联类型: {relation['relationship']}")
                    if relation.get('selector_fallback'):
                        print(f"        ⚠️  使用fallback计算选择器")
        
        # 打印选择器版本示例
        print("\n" + "=" * 80)
        print("选择器映射表（部分）:")
        print("=" * 80)
        
        for selector, signature in list(selector_results['function_selector_map'].items())[:5]:
            print(f"  {selector} => {signature}")
        
        # 文件路径
        readable_file = f"{base_filename}_external_call_conditions.json"
        selector_file = f"{base_filename}_external_call_conditions_selectors.json"
        
        print(f"\n文件已保存:")
        print(f"  人类可读版本: {readable_file}")
        print(f"  EVM注入版本: {selector_file}")
        
    except Exception as e:
        print(f"\n错误: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        print("\n" + "=" * 80)
        print("分析完成!")
        print("=" * 80)


if __name__ == "__main__":
    main()

