#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mock Return Value Loader Module

This module provides functionality to load mock return values for external calls
from JSON files and inject them into the Generator's callresult_pool.
"""

import json
import os
import logging
import random
from typing import Dict, List, Any, Optional, Tuple
from utils import settings
from utils.utils import initialize_logger
from engine.components.generator import Generator, UINT_MAX, INT_MAX, INT_MIN

logger = initialize_logger("MockReturnValueLoader")


# 默认地址白名单（常用的测试地址和零地址等）
DEFAULT_ADDRESS_WHITELIST = [
    "0x0000000000000000000000000000000000000000",  # Zero address
    "0x0000000000000000000000000000000000000001",  # Precompile
    "0x1111111111111111111111111111111111111111",
    "0x2222222222222222222222222222222222222222",
    "0x3333333333333333333333333333333333333333",
    "0x4444444444444444444444444444444444444444",
    "0x5555555555555555555555555555555555555555",
    "0x6666666666666666666666666666666666666666",
    "0x7777777777777777777777777777777777777777",
    "0x8888888888888888888888888888888888888888",
    "0x9999999999999999999999999999999999999999",
    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "0xcccccccccccccccccccccccccccccccccccccccc",
    "0xdddddddddddddddddddddddddddddddddddddddd",
    "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
]


def is_valid_address(value: Any) -> bool:
    """
    检查值是否为有效的以太坊地址格式

    Args:
        value: 待检查的值

    Returns:
        是否为有效地址
    """
    if not isinstance(value, str):
        return False

    # 地址应该是 0x 开头的 42 个字符（0x + 40个十六进制字符）
    if not value.startswith("0x"):
        return False

    if len(value) != 42:
        return False

    # 检查是否全部为十六进制字符
    try:
        int(value, 16)
        return True
    except ValueError:
        return False


def is_valid_bytes(value: Any, bytes_type: str) -> bool:
    """
    检查值是否为有效的bytes类型

    Args:
        value: 待检查的值
        bytes_type: bytes类型字符串，如 "bytes32", "bytes"

    Returns:
        是否为有效bytes
    """
    if not isinstance(value, str):
        return False

    if not value.startswith("0x"):
        return False

    try:
        # 检查是否为有效的十六进制
        int(value, 16)

        # 如果是固定长度的bytes（如bytes32），检查长度
        if bytes_type.startswith("bytes") and bytes_type[5:].isdigit():
            expected_length = int(bytes_type[5:])
            # 0x + 2 * expected_length 个字符
            return len(value) == 2 + 2 * expected_length

        return True
    except ValueError:
        return False


def parse_solidity_type(type_str: str) -> Dict[str, Any]:
    """
    解析Solidity类型字符串

    Args:
        type_str: 类型字符串，如 "uint256", "address", "bytes32"

    Returns:
        包含类型信息的字典
    """
    type_str = type_str.strip()

    # uint 类型
    if type_str.startswith("uint"):
        bits = 256
        if type_str != "uint":
            bits = int(type_str[4:]) if type_str[4:].isdigit() else 256
        return {
            "category": "uint",
            "bits": bits,
            "min": 0,
            "max": 2 ** bits - 1
        }

    # int 类型
    if type_str.startswith("int") and not type_str.startswith("interface"):
        bits = 256
        if type_str != "int":
            bits = int(type_str[3:]) if type_str[3:].isdigit() else 256
        return {
            "category": "int",
            "bits": bits,
            "min": -(2 ** (bits - 1)),
            "max": 2 ** (bits - 1) - 1
        }

    # address 类型
    if type_str == "address":
        return {"category": "address"}

    # bool 类型
    if type_str == "bool":
        return {"category": "bool"}

    # bytes 类型
    if type_str.startswith("bytes"):
        return {"category": "bytes", "type": type_str}

    # string 类型
    if type_str == "string":
        return {"category": "string"}

    # 其他类型（如结构体、数组等）
    return {"category": "unknown", "type": type_str}


def sanitize_value_by_type(value: Any, type_str: str, address_whitelist: List[str] = None) -> Any:
    """
    根据类型清洗和转换返回值

    Args:
        value: 原始返回值
        type_str: Solidity类型字符串
        address_whitelist: 地址白名单（可选）

    Returns:
        清洗后的返回值
    """
    if address_whitelist is None:
        address_whitelist = DEFAULT_ADDRESS_WHITELIST

    type_info = parse_solidity_type(type_str)
    category = type_info.get("category")

    try:
        # uint 类型
        if category == "uint":
            # 尝试转换为整数
            if isinstance(value, bool):
                int_value = 1 if value else 0
            elif isinstance(value, str):
                # 处理十六进制字符串
                if value.startswith("0x"):
                    int_value = int(value, 16)
                else:
                    int_value = int(value)
            else:
                int_value = int(value)

            # 确保在范围内
            int_value = max(type_info["min"], min(int_value, type_info["max"]))
            return int_value

        # int 类型
        elif category == "int":
            if isinstance(value, bool):
                int_value = 1 if value else 0
            elif isinstance(value, str):
                if value.startswith("0x"):
                    int_value = int(value, 16)
                else:
                    int_value = int(value)
            else:
                int_value = int(value)

            # 确保在范围内
            int_value = max(type_info["min"], min(int_value, type_info["max"]))
            return int_value

        # address 类型
        elif category == "address":
            # 检查是否为有效地址
            if is_valid_address(value):
                return value.lower()

            # 尝试转换
            if isinstance(value, int):
                # 将整数转换为地址格式
                return f"0x{value:040x}"
            elif isinstance(value, str):
                if value.startswith("0x"):
                    # 确保长度正确
                    hex_part = value[2:].lower()
                    if len(hex_part) <= 40:
                        return f"0x{hex_part.zfill(40)}"

            # 如果无法转换，从白名单中选择第一个
            logger.warning(f"无效的地址值: {value}, 使用白名单地址替代")
            return address_whitelist[0]

        # bool 类型
        elif category == "bool":
            if isinstance(value, bool):
                return value
            elif isinstance(value, str):
                return value.lower() in ["true", "1", "yes"]
            elif isinstance(value, int):
                return value != 0
            else:
                return bool(value)

        # bytes 类型
        elif category == "bytes":
            if is_valid_bytes(value, type_str):
                return value.lower()

            # 尝试转换
            if isinstance(value, str):
                if not value.startswith("0x"):
                    value = "0x" + value
                return value.lower()
            elif isinstance(value, int):
                return f"0x{value:x}"

            # 如果无法转换，返回零值
            if type_str.startswith("bytes") and type_str[5:].isdigit():
                byte_length = int(type_str[5:])
                return "0x" + "00" * byte_length
            return "0x"

        # string 类型
        elif category == "string":
            return str(value)

        # 未知类型，原样返回
        else:
            logger.warning(f"未知类型: {type_str}, 原样返回值")
            return value

    except Exception as e:
        logger.error(f"清洗值时出错: type={type_str}, value={value}, error={e}")
        # 返回该类型的默认值
        if category == "uint" or category == "int":
            return 0
        elif category == "address":
            return address_whitelist[0]
        elif category == "bool":
            return False
        elif category == "bytes":
            return "0x"
        elif category == "string":
            return ""
        else:
            return value


def generate_random_value_by_type(
    type_str: str,
    accounts: List[str] = None,
    address_whitelist: List[str] = None
) -> Any:
    """
    根据类型生成随机返回值（复用Generator的逻辑）

    Args:
        type_str: Solidity类型字符串
        accounts: 账户地址列表（用于address类型，可选）
        address_whitelist: 地址白名单（可选）

    Returns:
        随机生成的返回值
    """
    if address_whitelist is None:
        address_whitelist = DEFAULT_ADDRESS_WHITELIST

    type_info = parse_solidity_type(type_str)
    category = type_info.get("category")

    try:
        # uint 类型
        if category == "uint":
            bits = type_info.get("bits", 256)
            bytes_count = bits // 8
            max_value = UINT_MAX.get(bytes_count, UINT_MAX[32])
            return Generator.get_random_unsigned_integer(0, max_value)

        # int 类型
        elif category == "int":
            bits = type_info.get("bits", 256)
            bytes_count = bits // 8
            min_value = INT_MIN.get(bytes_count, INT_MIN[32])
            max_value = INT_MAX.get(bytes_count, INT_MAX[32])
            return Generator.get_random_signed_integer(min_value, max_value)

        # address 类型
        elif category == "address":
            # 优先使用传入的accounts，否则使用白名单
            if accounts and len(accounts) > 0:
                return random.choice(accounts).lower()
            else:
                return random.choice(address_whitelist).lower()

        # bool 类型
        elif category == "bool":
            return random.randint(0, 1) == 1

        # bytes 类型
        elif category == "bytes":
            # 固定长度bytes（如bytes32）
            if type_str.startswith("bytes") and type_str[5:].isdigit():
                byte_length = int(type_str[5:])
                random_bytes = Generator.get_random_bytes(byte_length)
                return "0x" + random_bytes.hex()
            # 动态bytes
            else:
                # 随机生成0-32字节的数据
                byte_length = random.choice([0, 1, 16, 32])
                random_bytes = Generator.get_random_bytes(byte_length)
                return "0x" + random_bytes.hex()

        # string 类型
        elif category == "string":
            # 随机选择长度
            length = random.choice([0, 1, 16, 32])
            return Generator.get_string(length)

        # 未知类型，返回默认值
        else:
            logger.warning(f"未知类型: {type_str}, 返回默认值")
            return 0

    except Exception as e:
        logger.error(f"生成随机值时出错: type={type_str}, error={e}")
        # 返回该类型的默认值
        if category == "uint" or category == "int":
            return 0
        elif category == "address":
            return (accounts[0] if accounts else address_whitelist[0]).lower()
        elif category == "bool":
            return False
        elif category == "bytes":
            return "0x"
        elif category == "string":
            return ""
        else:
            return 0


def validate_and_sanitize_return_values(
    return_types: List[str],
    return_values: List[Any],
    address_whitelist: List[str] = None
) -> Tuple[bool, List[Any], List[str]]:
    """
    验证并清洗外部调用的返回值

    Args:
        return_types: 返回值类型列表，如 ["uint256", "address", "bool"]
        return_values: 具体的返回值列表
        address_whitelist: 地址白名单（可选）

    Returns:
        (是否需要清洗, 清洗后的返回值列表, 警告信息列表)
    """
    if address_whitelist is None:
        address_whitelist = DEFAULT_ADDRESS_WHITELIST

    warnings = []
    sanitized_values = []
    needs_sanitization = False

    # 检查数量是否匹配
    if len(return_types) != len(return_values):
        warnings.append(
            f"返回值数量不匹配: 期望 {len(return_types)} 个，实际 {len(return_values)} 个"
        )
        # 如果值太少，补充默认值
        if len(return_values) < len(return_types):
            return_values = list(return_values) + [None] * (len(return_types) - len(return_values))
            needs_sanitization = True
        # 如果值太多，截断
        else:
            return_values = return_values[:len(return_types)]
            needs_sanitization = True

    # 逐个检查和清洗
    for i, (type_str, value) in enumerate(zip(return_types, return_values)):
        original_value = value
        sanitized_value = sanitize_value_by_type(value, type_str, address_whitelist)

        # 检查是否发生了转换
        if sanitized_value != original_value:
            needs_sanitization = True
            warnings.append(
                f"索引 {i} 的值被清洗: {type_str} - {original_value} -> {sanitized_value}"
            )

        sanitized_values.append(sanitized_value)

    return needs_sanitization, sanitized_values, warnings


def sanitize_mock_data(
    mock_data: Dict,
    address_whitelist: List[str] = None,
    accounts: List[str] = None
) -> Tuple[Dict, Dict[str, List[str]]]:
    """
    清洗整个mock数据中的所有返回值，或生成随机返回值

    Args:
        mock_data: 加载的mock返回值数据
        address_whitelist: 地址白名单（可选）
        use_file_values: 是否使用文件中的值，False则生成随机值（默认True）
        accounts: 账户地址列表，用于生成随机address时使用（可选）

    Returns:
        (清洗后的mock数据, 警告信息字典)
    """
    if address_whitelist is None:
        address_whitelist = DEFAULT_ADDRESS_WHITELIST

    if not mock_data or "mock_return_values" not in mock_data:
        return mock_data, {}

    sanitized_data = {
        "contract_name": mock_data.get("contract_name"),
        "contract_file": mock_data.get("contract_file"),
        "mock_return_values": {}
    }

    all_warnings = {}
    total_sanitized = 0

    if not settings.MOCK_RETURN_VALUES_LLMGEN_ENABLE:
        logger.info(f"未启用LLM生成的返回值")

    # 遍历每个目标函数
    for target_selector, external_calls in mock_data["mock_return_values"].items():
        sanitized_data["mock_return_values"][target_selector] = {}

        # 遍历每个外部调用
        for external_selector, call_info in external_calls.items():
            return_types = call_info.get("return_types", [])
            mock_values = call_info.get("mock_values", {})

            sanitized_call_info = {
                "external_function_signature": call_info.get("external_function_signature"),
                "return_types": return_types,
                "mock_values": {}
            }

            call_warnings = []

            # 处理每个场景（satisfy, violate, boundary）
            for scenario in ["satisfy", "violate", "boundary"]:
                scenario_values = mock_values.get(scenario, [])
                sanitized_scenario_values = []

                if settings.MOCK_RETURN_VALUES_LLMGEN_ENABLE:
                    # 使用文件中的值，进行清洗
                    for value_set in scenario_values:
                        # 验证并清洗返回值
                        needs_sanitization, sanitized_values, warnings = validate_and_sanitize_return_values(
                            return_types,
                            value_set,
                            address_whitelist
                        )

                        sanitized_scenario_values.append(sanitized_values)

                        if needs_sanitization:
                            total_sanitized += 1
                            call_warnings.extend(warnings)
                else:
                    # 生成随机值，保持与文件中相同的数量
                    
                    num_values = len(scenario_values)
                    # for _ in range(num_values):
                    #     # 为每个返回类型生成随机值
                    #     random_values = []
                    #     for type_str in return_types:
                    #         random_value = generate_random_value_by_type(
                    #             type_str,
                    #             accounts,
                    #             address_whitelist
                    #         )
                    #         random_values.append(random_value)

                    #     sanitized_scenario_values.append(random_values)
                    #     total_sanitized += 1

                    random_values = []
                    for type_str in return_types:
                        random_value = generate_random_value_by_type(
                            type_str,
                            accounts,
                            address_whitelist
                        )
                        random_values.append(random_value)

                    sanitized_scenario_values.append(random_values)

                sanitized_call_info["mock_values"][scenario] = sanitized_scenario_values

            # 保存清洗后的调用信息
            sanitized_data["mock_return_values"][target_selector][external_selector] = sanitized_call_info

            # 记录警告
            if call_warnings:
                warning_key = f"{target_selector}:{external_selector}"
                all_warnings[warning_key] = call_warnings

    if total_sanitized > 0:
        if settings.MOCK_RETURN_VALUES_LLMGEN_ENABLE:
            logger.info(f"数据清洗完成: 共清洗 {total_sanitized} 个返回值集")
            for key, warnings in all_warnings.items():
                for warning in warnings:
                    logger.debug(f"{key} - {warning}")
        else:
            logger.info(f"随机值生成完成: 共生成 {total_sanitized} 个返回值集")

    return sanitized_data, all_warnings


def load_mock_return_values(
    json_path: str,
    sanitize: bool = True,
    address_whitelist: List[str] = None,
    accounts: List[str] = None
) -> Optional[Dict]:
    """
    从JSON文件加载外部调用返回值模拟策略，并可选地进行数据清洗或生成随机值

    Args:
        json_path: JSON文件路径
        sanitize: 是否进行数据清洗和类型检查（默认为True）
        address_whitelist: 地址白名单（可选）
        use_file_values: 是否使用文件中的值，False则生成随机值（默认True）
        accounts: 账户地址列表，用于生成随机address时使用（可选）

    Returns:
        包含mock返回值的字典，如果加载失败返回None
    """
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            mock_data = json.load(f)
        logger.info(f"成功加载mock返回值文件: {json_path}")

        # 如果需要清洗数据或生成随机值
        if sanitize:
            sanitized_data, warnings = sanitize_mock_data(
                mock_data,
                address_whitelist,
                accounts
            )
            if warnings:
                if settings.MOCK_RETURN_VALUES_LLMGEN_ENABLE:
                    logger.warning(f"发现并修复了 {len(warnings)} 个位置的数据问题")
            return sanitized_data
        else:
            return mock_data

    except FileNotFoundError:
        logger.warning(f"Mock返回值文件不存在: {json_path}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"JSON解析错误: {json_path}, 错误信息: {e}")
        return None
    except Exception as e:
        logger.error(f"加载mock返回值文件失败: {json_path}, 错误信息: {e}")
        return None


def get_mock_return_value_file_path(source_file: str, contract_name: str) -> str:
    """
    根据合约源文件路径和合约名称构造mock返回值文件路径

    Args:
        source_file: 合约源文件路径
        contract_name: 合约名称

    Returns:
        mock返回值文件的完整路径
    """
    if not source_file:
        return ""

    source_dir = os.path.dirname(source_file)
    file_name = source_file.split('/')[-1].split('.')[0]
    mock_filename = f"{file_name}_mock_return_values.json"
    mock_path = os.path.join(source_dir, mock_filename)

    return mock_path


def inject_mock_return_values_to_generator(
    generator,
    mock_data: Dict,
    function_selector_map: Optional[Dict] = None
) -> int:
    """
    将mock返回值注入到Generator的callresult_pool

    Args:
        generator: Generator实例
        mock_data: 加载的mock返回值数据
        function_selector_map: 函数选择器映射（可选，用于日志）

    Returns:
        注入的返回值总数
    """
    if not mock_data or "mock_return_values" not in mock_data:
        logger.warning("Mock数据为空或缺少 'mock_return_values' 字段")
        return 0

    mock_return_values = mock_data["mock_return_values"]
    total_injected = 0

    # 遍历每个目标函数
    for target_function_selector, external_calls in mock_return_values.items():
        # 遍历每个外部调用
        for external_call_selector, call_info in external_calls.items():
            mock_values = call_info.get("mock_values", {})

            # 获取三种场景的值：satisfy, violate, boundary
            all_values = []

            # 收集所有场景的值
            for scenario in ["satisfy", "violate", "boundary"]:
                scenario_values = mock_values.get(scenario, [])
                all_values.extend(scenario_values)

            # 注入到 callresult_pool
            # 格式：callresult_pool[target_function][external_address] = CircularSet(values)
            for value_set in all_values:
                # value_set 是一个列表，例如 [1000] 或 [true, 1, "0x..."]
                # 对于多返回值，value_set 会是多个元素的列表
                # 我们需要将其作为一个整体添加到 pool 中
                generator.add_callresult_to_pool(
                    target_function_selector,
                    external_call_selector,  # 使用外部调用选择器作为地址标识
                    tuple(value_set) if isinstance(value_set, list) else value_set
                )
                total_injected += 1

            # 日志输出
            external_sig = call_info.get("external_function_signature", "Unknown")
            logger.debug(
                f"注入 {len(all_values)} 个返回值到 "
                f"{target_function_selector}:{external_call_selector} ({external_sig})"
            )

    logger.info(f"成功注入 {total_injected} 个mock返回值到Generator")
    return total_injected


def inject_mock_return_values_with_selector_map(
    generator,
    mock_data: Dict,
    abi: List[Dict],
    funname2hash: Dict
) -> int:
    """
    将mock返回值注入到Generator，支持函数名到选择器的映射

    这个版本支持更复杂的映射场景，可以处理函数签名到选择器的转换

    Args:
        generator: Generator实例
        mock_data: 加载的mock返回值数据
        abi: 合约ABI
        funname2hash: 函数名到哈希的映射

    Returns:
        注入的返回值总数
    """
    # 目前直接调用基础版本
    # 未来可以扩展支持更复杂的映射逻辑
    return inject_mock_return_values_to_generator(
        generator,
        mock_data,
        funname2hash
    )


def validate_mock_return_values(mock_data: Dict) -> bool:
    """
    验证mock返回值数据的格式是否正确

    Args:
        mock_data: 加载的mock返回值数据

    Returns:
        验证是否通过
    """
    if not isinstance(mock_data, dict):
        logger.error("Mock数据不是字典类型")
        return False

    if "mock_return_values" not in mock_data:
        logger.error("Mock数据缺少 'mock_return_values' 字段")
        return False

    mock_return_values = mock_data["mock_return_values"]
    if not isinstance(mock_return_values, dict):
        logger.error("'mock_return_values' 不是字典类型")
        return False

    # 验证每个目标函数的结构
    for target_selector, external_calls in mock_return_values.items():
        if not isinstance(external_calls, dict):
            logger.error(f"目标函数 {target_selector} 的外部调用不是字典类型")
            return False

        for ext_selector, call_info in external_calls.items():
            if not isinstance(call_info, dict):
                logger.error(f"外部调用 {ext_selector} 的信息不是字典类型")
                return False

            if "mock_values" not in call_info:
                logger.warning(f"外部调用 {ext_selector} 缺少 'mock_values' 字段")
                continue

            mock_values = call_info["mock_values"]
            if not isinstance(mock_values, dict):
                logger.error(f"外部调用 {ext_selector} 的 'mock_values' 不是字典类型")
                return False

            # 检查必需的场景
            for scenario in ["satisfy", "violate", "boundary"]:
                if scenario not in mock_values:
                    logger.warning(
                        f"外部调用 {ext_selector} 缺少 '{scenario}' 场景"
                    )

    logger.info("Mock返回值数据格式验证通过")
    return True


def get_mock_return_values_statistics(mock_data: Dict) -> Dict[str, Any]:
    """
    获取mock返回值的统计信息

    Args:
        mock_data: 加载的mock返回值数据

    Returns:
        统计信息字典
    """
    if not mock_data or "mock_return_values" not in mock_data:
        return {
            "total_target_functions": 0,
            "total_external_calls": 0,
            "total_mock_values": 0
        }

    mock_return_values = mock_data["mock_return_values"]
    total_target_functions = len(mock_return_values)
    total_external_calls = 0
    total_mock_values = 0

    for target_selector, external_calls in mock_return_values.items():
        total_external_calls += len(external_calls)

        for ext_selector, call_info in external_calls.items():
            mock_values = call_info.get("mock_values", {})
            for scenario in ["satisfy", "violate", "boundary"]:
                scenario_values = mock_values.get(scenario, [])
                total_mock_values += len(scenario_values)

    return {
        "contract_name": mock_data.get("contract_name", "Unknown"),
        "contract_file": mock_data.get("contract_file", "Unknown"),
        "total_target_functions": total_target_functions,
        "total_external_calls": total_external_calls,
        "total_mock_values": total_mock_values
    }
