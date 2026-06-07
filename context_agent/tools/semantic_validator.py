#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
语义验证器 - Semantic Validator

功能：验证LLM生成的mock返回值是否符合DeFi协议的语义约束，
     过滤掉明显不合理的值，并尝试修正可修复的错误。

验证规则：
- ERC20: balanceOf返回值应在合理范围
- Uniswap: getReserves应满足乘积约束
- Oracle: 价格应在合理范围
- Address: 不应使用明显的测试地址
"""

from typing import Dict, List, Any, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class SemanticValidator:
    """语义合理性验证器"""

    # 类型边界值
    TYPE_BOUNDS = {
        "uint256": (0, 2**256 - 1),
        "uint128": (0, 2**128 - 1),
        "uint112": (0, 2**112 - 1),
        "uint96": (0, 2**96 - 1),
        "uint80": (0, 2**80 - 1),
        "uint64": (0, 2**64 - 1),
        "uint32": (0, 2**32 - 1),
        "uint16": (0, 2**16 - 1),
        "uint8": (0, 2**8 - 1),
        "int256": (-2**255, 2**255 - 1),
        "int128": (-2**127, 2**127 - 1),
        "int64": (-2**63, 2**63 - 1),
        "int32": (-2**31, 2**31 - 1),
        "int16": (-2**15, 2**15 - 1),
        "int8": (-2**7, 2**7 - 1),
    }

    # 明显的测试地址（应避免）
    SUSPICIOUS_ADDRESSES = {
        "0x1111111111111111111111111111111111111111",
        "0x2222222222222222222222222222222222222222",
        "0x3333333333333333333333333333333333333333",
        "0x4444444444444444444444444444444444444444",
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    }

    # 常见合理地址（用于替换）
    REASONABLE_ADDRESSES = [
        "0x0000000000000000000000000000000000000000",  # zero address
        "0x0000000000000000000000000000000000000001",  # minimal address
        "0xdAC17F958D2ee523a2206206994597C13D831ec7",  # USDT
        "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",  # USDC
        "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",  # WETH
        "0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF",  # max address
    ]

    def __init__(self):
        """初始化语义验证器"""
        pass

    def validate(self, mock_values: Dict[str, List[List[Any]]],
                 protocol: str,
                 context: Dict[str, Any]) -> Dict[str, List[List[Any]]]:
        """
        验证并修正返回值的语义合理性

        Args:
            mock_values: LLM生成的mock返回值
                格式: {"satisfy": [[v1, v2], ...], "violate": [...], "boundary": [...]}
            protocol: 协议类型
            context: 外部调用上下文

        Returns:
            验证后的mock返回值（过滤/修正不合理值）
        """
        validated = {}
        return_types = context.get("return_types", [])

        for scenario in ["satisfy", "violate", "boundary"]:
            if scenario not in mock_values:
                validated[scenario] = []
                continue

            validated_scenario = []
            for values in mock_values[scenario]:
                # 确保values是列表
                if not isinstance(values, list):
                    values = [values]

                # 基础类型验证
                is_valid, corrected = self._validate_types(values, return_types)

                if is_valid:
                    # 协议特定验证
                    is_valid, corrected = self._validate_protocol(
                        corrected, protocol, context
                    )

                if is_valid:
                    validated_scenario.append(corrected)
                else:
                    # 尝试修正
                    corrected = self._attempt_correction(values, protocol, context, return_types)
                    if corrected:
                        validated_scenario.append(corrected)
                    else:
                        logger.debug(f"Discarded invalid values: {values}")

            validated[scenario] = validated_scenario

        return validated

    def _validate_types(self, values: List[Any],
                        return_types: List[str]) -> Tuple[bool, List[Any]]:
        """
        验证值是否符合类型约束

        Args:
            values: 返回值列表
            return_types: 期望的类型列表

        Returns:
            (是否有效, 修正后的值)
        """
        if len(values) != len(return_types):
            return False, values

        corrected = []
        for value, rtype in zip(values, return_types):
            corrected_value = self._validate_single_type(value, rtype)
            if corrected_value is None:
                return False, values
            corrected.append(corrected_value)

        return True, corrected

    def _validate_single_type(self, value: Any, rtype: str) -> Optional[Any]:
        """验证单个值的类型"""
        # 处理uint类型
        if rtype.startswith("uint"):
            return self._validate_uint(value, rtype)

        # 处理int类型
        elif rtype.startswith("int"):
            return self._validate_int(value, rtype)

        # 处理bool类型
        elif rtype == "bool":
            return self._validate_bool(value)

        # 处理address类型
        elif rtype == "address":
            return self._validate_address(value)

        # 处理bytes类型
        elif rtype.startswith("bytes"):
            return self._validate_bytes(value, rtype)

        # 处理string类型
        elif rtype == "string":
            return str(value) if value is not None else ""

        # 未知类型，直接返回
        return value

    def _validate_uint(self, value: Any, rtype: str) -> Optional[Any]:
        """验证无符号整数"""
        try:
            # 处理字符串形式的数字
            if isinstance(value, str):
                if value.startswith("0x"):
                    num = int(value, 16)
                else:
                    num = int(value)
            elif isinstance(value, (int, float)):
                num = int(value)
            else:
                return None

            # 检查范围
            min_val, max_val = self.TYPE_BOUNDS.get(rtype, (0, 2**256 - 1))
            if num < min_val or num > max_val:
                # 超出范围，尝试截断
                num = max(min_val, min(num, max_val))

            return num

        except (ValueError, TypeError):
            return None

    def _validate_int(self, value: Any, rtype: str) -> Optional[Any]:
        """验证有符号整数"""
        try:
            if isinstance(value, str):
                if value.startswith("0x"):
                    num = int(value, 16)
                else:
                    num = int(value)
            elif isinstance(value, (int, float)):
                num = int(value)
            else:
                return None

            # 检查范围
            min_val, max_val = self.TYPE_BOUNDS.get(rtype, (-2**255, 2**255 - 1))
            if num < min_val or num > max_val:
                num = max(min_val, min(num, max_val))

            return num

        except (ValueError, TypeError):
            return None

    def _validate_bool(self, value: Any) -> Optional[bool]:
        """验证布尔值"""
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            if value.lower() in ["true", "1"]:
                return True
            elif value.lower() in ["false", "0"]:
                return False
        if isinstance(value, int):
            return bool(value)
        return None

    def _validate_address(self, value: Any) -> Optional[str]:
        """验证地址"""
        if not isinstance(value, str):
            return None

        # 统一格式
        addr = value.strip().lower()

        # 确保以0x开头
        if not addr.startswith("0x"):
            addr = "0x" + addr

        # 检查长度（0x + 40 hex chars）
        if len(addr) != 42:
            return None

        # 检查是否是有效十六进制
        try:
            int(addr, 16)
        except ValueError:
            return None

        return addr

    def _validate_bytes(self, value: Any, rtype: str) -> Optional[str]:
        """验证bytes类型"""
        if not isinstance(value, str):
            return None

        # 统一格式
        if not value.startswith("0x"):
            value = "0x" + value

        # 对于bytes32，检查长度
        if rtype == "bytes32" and len(value) != 66:  # 0x + 64 hex chars
            # 尝试填充
            hex_part = value[2:]
            if len(hex_part) < 64:
                value = "0x" + hex_part.zfill(64)
            else:
                value = "0x" + hex_part[:64]

        return value

    def _validate_protocol(self, values: List[Any],
                           protocol: str,
                           context: Dict[str, Any]) -> Tuple[bool, List[Any]]:
        """
        协议特定验证

        Args:
            values: 返回值列表
            protocol: 协议类型
            context: 上下文信息

        Returns:
            (是否有效, 修正后的值)
        """
        if protocol == "ERC20":
            return self._validate_erc20(values, context)
        elif protocol == "ERC721":
            return self._validate_erc721(values, context)
        elif protocol == "Uniswap-V2":
            return self._validate_uniswap_v2(values, context)
        elif protocol == "Chainlink-Oracle":
            return self._validate_chainlink(values, context)
        elif protocol in ["Aave", "Compound"]:
            return self._validate_lending(values, context)
        else:
            return True, values

    def _validate_erc20(self, values: List[Any],
                        context: Dict[str, Any]) -> Tuple[bool, List[Any]]:
        """ERC20协议验证"""
        func = context.get("external_function_signature", "")

        if "balanceOf" in func or "allowance" in func or "totalSupply" in func:
            # 检查是否为合理的代币数量
            if len(values) >= 1:
                amount = values[0]
                # 合理范围: 0 到 10^30 (超过所有主流代币的总供应量)
                if amount < 0 or amount > 10**30:
                    return False, values

                # 避免明显的测试值
                if amount in [0x1111111111111111, 0xFFFFFFFF, 0xDEADBEEF]:
                    return False, values

        elif "decimals" in func:
            # decimals通常是0-18
            if len(values) >= 1 and (values[0] < 0 or values[0] > 18):
                values[0] = 18  # 默认修正为18

        return True, values

    def _validate_erc721(self, values: List[Any],
                         context: Dict[str, Any]) -> Tuple[bool, List[Any]]:
        """ERC721协议验证"""
        func = context.get("external_function_signature", "")

        if "ownerOf" in func:
            # ownerOf返回地址
            if len(values) >= 1:
                addr = values[0]
                if isinstance(addr, str) and addr.lower() in self.SUSPICIOUS_ADDRESSES:
                    # 替换为合理地址
                    values[0] = self.REASONABLE_ADDRESSES[1]

        return True, values

    def _validate_uniswap_v2(self, values: List[Any],
                              context: Dict[str, Any]) -> Tuple[bool, List[Any]]:
        """Uniswap V2协议验证"""
        func = context.get("external_function_signature", "")

        if "getReserves" in func:
            if len(values) >= 2:
                r0, r1 = values[0], values[1]

                # 允许零值（用于测试零流动性）
                if r0 == 0 or r1 == 0:
                    return True, values

                # 检查储备池是否过于不平衡（超过100000倍）
                if r0 > 0 and r1 > 0:
                    ratio = max(r0, r1) / min(r0, r1)
                    if ratio > 100000:
                        # 调整为更合理的比例
                        if r0 > r1:
                            values[0] = r1 * 1000
                        else:
                            values[1] = r0 * 1000

                # 确保在uint112范围内
                max_112 = 2**112 - 1
                values[0] = min(values[0], max_112)
                values[1] = min(values[1], max_112)

        return True, values

    def _validate_chainlink(self, values: List[Any],
                            context: Dict[str, Any]) -> Tuple[bool, List[Any]]:
        """Chainlink Oracle验证"""
        func = context.get("external_function_signature", "")

        if "latestRoundData" in func:
            # latestRoundData返回: (roundId, answer, startedAt, updatedAt, answeredInRound)
            if len(values) >= 5:
                roundId, answer, startedAt, updatedAt, answeredInRound = values[:5]

                # answer应该是合理的价格（-10^15 到 10^15）
                if answer < -10**15 or answer > 10**15:
                    values[1] = 200000000000  # 默认2000 USD (8 decimals)

                # timestamp应该是合理的Unix时间戳
                import time
                current_time = int(time.time())
                # 如果时间戳不合理，设为当前时间
                if updatedAt < 1600000000 or updatedAt > current_time + 86400:
                    values[3] = current_time

        elif "latestAnswer" in func:
            if len(values) >= 1:
                answer = values[0]
                if answer < -10**15 or answer > 10**15:
                    values[0] = 200000000000

        return True, values

    def _validate_lending(self, values: List[Any],
                          context: Dict[str, Any]) -> Tuple[bool, List[Any]]:
        """借贷协议验证（Aave/Compound）"""
        func = context.get("external_function_signature", "")

        if "healthFactor" in func or "getUserAccountData" in func:
            # healthFactor通常以10^18为单位
            # < 10^18 可被清算, >= 10^18 健康
            pass  # 暂不做特殊验证

        return True, values

    def _attempt_correction(self, values: List[Any],
                            protocol: str,
                            context: Dict[str, Any],
                            return_types: List[str]) -> Optional[List[Any]]:
        """
        尝试修正无效值

        Args:
            values: 原始值
            protocol: 协议类型
            context: 上下文
            return_types: 期望的返回类型

        Returns:
            修正后的值，如果无法修正返回None
        """
        corrected = []

        # 如果长度不匹配，无法修正
        if len(values) != len(return_types):
            return None

        for value, rtype in zip(values, return_types):
            # 尝试类型转换
            if rtype.startswith("uint"):
                try:
                    val = int(str(value).replace(",", ""))
                    if val < 0:
                        val = abs(val)
                    min_val, max_val = self.TYPE_BOUNDS.get(rtype, (0, 2**256-1))
                    val = max(min_val, min(val, max_val))
                    corrected.append(val)
                except:
                    # 使用默认值
                    corrected.append(0)

            elif rtype.startswith("int"):
                try:
                    val = int(str(value).replace(",", ""))
                    min_val, max_val = self.TYPE_BOUNDS.get(rtype, (-2**255, 2**255-1))
                    val = max(min_val, min(val, max_val))
                    corrected.append(val)
                except:
                    corrected.append(0)

            elif rtype == "bool":
                corrected.append(bool(value))

            elif rtype == "address":
                if not isinstance(value, str) or len(value) != 42:
                    corrected.append(self.REASONABLE_ADDRESSES[0])
                else:
                    corrected.append(value)

            else:
                corrected.append(value)

        return corrected

    def get_default_values(self, return_types: List[str],
                           protocol: str = "Generic") -> Dict[str, List[List[Any]]]:
        """
        获取协议特定的默认返回值

        Args:
            return_types: 返回类型列表
            protocol: 协议类型

        Returns:
            默认的mock返回值
        """
        if protocol == "ERC20":
            return self._get_erc20_defaults(return_types)
        elif protocol == "Uniswap-V2":
            return self._get_uniswap_defaults(return_types)
        elif protocol == "Chainlink-Oracle":
            return self._get_chainlink_defaults(return_types)
        else:
            return self._get_generic_defaults(return_types)

    def _get_erc20_defaults(self, return_types: List[str]) -> Dict[str, List[List[Any]]]:
        """ERC20默认值"""
        if len(return_types) == 1 and return_types[0].startswith("uint"):
            return {
                "satisfy": [[1000 * 10**18], [100 * 10**18], [10 * 10**18]],
                "violate": [[0], [1]],
                "boundary": [[0], [2**256 - 1]]
            }
        elif len(return_types) == 1 and return_types[0] == "bool":
            return {
                "satisfy": [[True]],
                "violate": [[False]],
                "boundary": [[True], [False]]
            }
        return self._get_generic_defaults(return_types)

    def _get_uniswap_defaults(self, return_types: List[str]) -> Dict[str, List[List[Any]]]:
        """Uniswap V2默认值"""
        if len(return_types) == 3:  # getReserves
            import time
            ts = int(time.time())
            return {
                "satisfy": [
                    [10**21, 10**21, ts],  # 1000 tokens each
                    [10**24, 10**21, ts],  # imbalanced
                ],
                "violate": [[0, 0, ts]],
                "boundary": [
                    [0, 10**21, ts],
                    [2**112 - 1, 2**112 - 1, ts]
                ]
            }
        return self._get_generic_defaults(return_types)

    def _get_chainlink_defaults(self, return_types: List[str]) -> Dict[str, List[List[Any]]]:
        """Chainlink默认值"""
        if len(return_types) == 5:  # latestRoundData
            import time
            ts = int(time.time())
            return {
                "satisfy": [
                    [1, 200000000000, ts-100, ts, 1],  # $2000
                    [2, 300000000000, ts-100, ts, 2],  # $3000
                ],
                "violate": [
                    [1, 0, ts-100, ts, 1],  # Zero price
                    [1, -100000000, ts-100, ts, 1],  # Negative price
                ],
                "boundary": [
                    [1, 1, ts-100, ts, 1],  # Minimal price
                    [1, 10**14, ts-100, ts, 1],  # Very high price
                ]
            }
        return self._get_generic_defaults(return_types)

    def _get_generic_defaults(self, return_types: List[str]) -> Dict[str, List[List[Any]]]:
        """通用默认值"""
        default_vals = []
        for rtype in return_types:
            if rtype.startswith("uint"):
                default_vals.append([0, 1, 2**256 - 1])
            elif rtype.startswith("int"):
                default_vals.append([0, -1, 2**255 - 1])
            elif rtype == "bool":
                default_vals.append([True, False])
            elif rtype == "address":
                default_vals.append(self.REASONABLE_ADDRESSES[:3])
            else:
                default_vals.append([0, 1, 2**256 - 1])

        # 生成组合
        satisfy = [[d[0] for d in default_vals]]
        violate = [[d[1] for d in default_vals]] if len(default_vals[0]) > 1 else satisfy
        boundary = [[d[-1] for d in default_vals]] if len(default_vals[0]) > 2 else violate

        return {
            "satisfy": satisfy,
            "violate": violate,
            "boundary": boundary
        }


def test_semantic_validator():
    """测试语义验证器"""
    validator = SemanticValidator()

    print("=" * 80)
    print("Semantic Validator Test")
    print("=" * 80)

    # 测试用例1: ERC20 balanceOf
    print("\n[Test 1] ERC20 balanceOf validation")
    mock_values = {
        "satisfy": [[1000 * 10**18], [100 * 10**18]],
        "violate": [[0], [0x1111111111111111]],  # 后者是可疑值
        "boundary": [[0], [2**256 - 1]]
    }
    context = {
        "external_function_signature": "balanceOf(address)(uint256)",
        "return_types": ["uint256"]
    }

    validated = validator.validate(mock_values, "ERC20", context)
    print(f"  Input: {len(mock_values['satisfy'])} satisfy, {len(mock_values['violate'])} violate")
    print(f"  Output: {len(validated['satisfy'])} satisfy, {len(validated['violate'])} violate")
    print(f"  Satisfy values: {validated['satisfy']}")

    # 测试用例2: Uniswap V2 getReserves
    print("\n[Test 2] Uniswap V2 getReserves validation")
    mock_values = {
        "satisfy": [[10**21, 10**21, 1700000000]],
        "violate": [[0, 0, 1700000000]],
        "boundary": [[10**30, 1, 1700000000]]  # 过于不平衡
    }
    context = {
        "external_function_signature": "getReserves()(uint112,uint112,uint32)",
        "return_types": ["uint112", "uint112", "uint32"]
    }

    validated = validator.validate(mock_values, "Uniswap-V2", context)
    print(f"  Boundary after validation: {validated['boundary']}")

    # 测试用例3: Chainlink Oracle
    print("\n[Test 3] Chainlink Oracle validation")
    mock_values = {
        "satisfy": [[1, 200000000000, 1700000000, 1700000100, 1]],
        "violate": [[1, 0, 1700000000, 1700000100, 1]],
        "boundary": [[1, 10**20, 1700000000, 1700000100, 1]]  # 价格过高
    }
    context = {
        "external_function_signature": "latestRoundData()",
        "return_types": ["uint80", "int256", "uint256", "uint256", "uint80"]
    }

    validated = validator.validate(mock_values, "Chainlink-Oracle", context)
    print(f"  Satisfy values: {validated['satisfy']}")
    print(f"  Boundary corrected: {validated['boundary']}")

    # 测试用例4: 获取默认值
    print("\n[Test 4] Get default values")
    defaults = validator.get_default_values(["uint256"], "ERC20")
    print(f"  ERC20 uint256 defaults: {defaults}")

    defaults = validator.get_default_values(["uint112", "uint112", "uint32"], "Uniswap-V2")
    print(f"  Uniswap V2 defaults: {defaults}")

    print("\n" + "=" * 80)
    print("Test completed successfully!")
    print("=" * 80)


if __name__ == "__main__":
    test_semantic_validator()
