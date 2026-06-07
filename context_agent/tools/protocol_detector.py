#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
协议识别器 - Protocol Detector

功能：根据外部调用的函数签名自动检测DeFi协议类型，
     用于选择合适的生成策略和语义验证规则。

支持的协议：
- ERC20/ERC721/ERC1155: 代币标准
- Uniswap V2/V3: DEX协议
- Chainlink Oracle: 价格预言机
- Aave/Compound: 借贷协议
"""

from typing import Dict, List, Set


class ProtocolDetector:
    """DeFi协议识别器"""

    # 协议特征模式库
    PROTOCOL_PATTERNS: Dict[str, List[str]] = {
        # ERC代币标准
        "ERC20": [
            "balanceOf",
            "allowance",
            "totalSupply",
            "transfer",
            "approve",
            "transferFrom",
            "decimals",
            "symbol",
            "name"
        ],

        "ERC721": [
            "ownerOf",
            "tokenURI",
            "safeTransferFrom",
            "setApprovalForAll",
            "isApprovedForAll",
            "tokenOfOwnerByIndex",
            "tokenByIndex"
        ],

        "ERC1155": [
            "balanceOfBatch",
            "safeBatchTransferFrom",
            "setApprovalForAll",
            "isApprovedForAll",
            "uri"
        ],

        # Uniswap协议
        "Uniswap-V2": [
            "getReserves",
            "getAmountsOut",
            "getAmountsIn",
            "quote",
            "token0",
            "token1",
            "factory",
            "swapExactTokensForTokens",
            "swapTokensForExactTokens",
            "addLiquidity",
            "removeLiquidity",
            "WETH"
        ],

        "Uniswap-V3": [
            "slot0",
            "positions",
            "observe",
            "increaseObservationCardinalityNext",
            "mint",
            "burn",
            "collect",
            "swap"
        ],

        # Chainlink Oracle
        "Chainlink-Oracle": [
            "latestRoundData",
            "getRoundData",
            "latestAnswer",
            "latestTimestamp",
            "latestRound",
            "getAnswer",
            "getTimestamp",
            "decimals",
            "description",
            "version"
        ],

        # Aave借贷协议
        "Aave": [
            "deposit",
            "withdraw",
            "borrow",
            "repay",
            "getUserAccountData",
            "getReserveData",
            "liquidationCall",
            "flashLoan",
            "setUserUseReserveAsCollateral"
        ],

        # Compound借贷协议
        "Compound": [
            "mint",
            "redeem",
            "borrow",
            "repayBorrow",
            "liquidateBorrow",
            "getAccountLiquidity",
            "borrowBalanceCurrent",
            "exchangeRateCurrent",
            "balanceOfUnderlying"
        ],

        # Curve Finance
        "Curve": [
            "get_virtual_price",
            "get_dy",
            "exchange",
            "add_liquidity",
            "remove_liquidity",
            "remove_liquidity_one_coin",
            "calc_token_amount",
            "coins"
        ]
    }

    # 协议优先级（用于处理模糊匹配）
    PROTOCOL_PRIORITY = [
        "Uniswap-V3",     # 更具体的协议优先
        "Uniswap-V2",
        "Chainlink-Oracle",
        "Aave",
        "Compound",
        "Curve",
        "ERC1155",
        "ERC721",
        "ERC20"           # 最通用的放最后
    ]

    def __init__(self):
        """初始化协议检测器"""
        # 预计算：将模式转为小写用于不区分大小写匹配
        self._normalized_patterns = {
            protocol: [p.lower() for p in patterns]
            for protocol, patterns in self.PROTOCOL_PATTERNS.items()
        }

    def detect(self, function_signature: str) -> str:
        """
        检测函数签名对应的协议类型

        Args:
            function_signature: 函数签名字符串
                例如: "balanceOf(address)" 或 "getReserves()(uint112,uint112,uint32)"

        Returns:
            协议类型字符串，如 "ERC20", "Uniswap-V2", 或 "Generic"
        """
        if not function_signature:
            return "Generic"

        # 提取函数名（去除参数）
        function_name = self._extract_function_name(function_signature)

        # 按优先级匹配
        for protocol in self.PROTOCOL_PRIORITY:
            if self._matches_protocol(function_name, protocol):
                return protocol

        return "Generic"

    def detect_batch(self, function_signatures: List[str]) -> Dict[str, str]:
        """
        批量检测多个函数签名

        Args:
            function_signatures: 函数签名列表

        Returns:
            {函数签名: 协议类型} 的字典
        """
        return {
            sig: self.detect(sig)
            for sig in function_signatures
        }

    def get_protocol_info(self, protocol: str) -> Dict[str, any]:
        """
        获取协议的详细信息

        Args:
            protocol: 协议名称

        Returns:
            包含协议描述、函数列表等信息的字典
        """
        if protocol not in self.PROTOCOL_PATTERNS:
            return {
                "name": protocol,
                "functions": [],
                "category": "Unknown"
            }

        # 分类协议
        category = self._classify_protocol(protocol)

        return {
            "name": protocol,
            "functions": self.PROTOCOL_PATTERNS[protocol],
            "category": category,
            "function_count": len(self.PROTOCOL_PATTERNS[protocol])
        }

    def _extract_function_name(self, function_signature: str) -> str:
        """
        从函数签名中提取函数名

        Examples:
            "balanceOf(address)" → "balanceOf"
            "getReserves()(uint112,uint112,uint32)" → "getReserves"
            "transfer" → "transfer"
        """
        # 去除参数部分
        if '(' in function_signature:
            function_name = function_signature.split('(')[0].strip()
        else:
            function_name = function_signature.strip()

        return function_name

    def _matches_protocol(self, function_name: str, protocol: str) -> bool:
        """
        检查函数名是否匹配协议

        Args:
            function_name: 函数名
            protocol: 协议名称

        Returns:
            是否匹配
        """
        if protocol not in self._normalized_patterns:
            return False

        # 不区分大小写匹配
        function_name_lower = function_name.lower()
        patterns = self._normalized_patterns[protocol]

        return function_name_lower in patterns

    def _classify_protocol(self, protocol: str) -> str:
        """对协议进行分类"""
        if protocol.startswith("ERC"):
            return "Token Standard"
        elif "Uniswap" in protocol or "Curve" in protocol:
            return "DEX"
        elif "Oracle" in protocol or "Chainlink" in protocol:
            return "Oracle"
        elif protocol in ["Aave", "Compound"]:
            return "Lending"
        else:
            return "Other"

    def add_custom_protocol(self, protocol_name: str, patterns: List[str]):
        """
        添加自定义协议模式

        Args:
            protocol_name: 协议名称
            patterns: 函数名模式列表
        """
        self.PROTOCOL_PATTERNS[protocol_name] = patterns
        self._normalized_patterns[protocol_name] = [p.lower() for p in patterns]

        # 添加到优先级列表（默认添加到最前面）
        if protocol_name not in self.PROTOCOL_PRIORITY:
            self.PROTOCOL_PRIORITY.insert(0, protocol_name)

    def get_supported_protocols(self) -> List[str]:
        """获取所有支持的协议列表"""
        return list(self.PROTOCOL_PATTERNS.keys())

    def get_statistics(self) -> Dict[str, int]:
        """获取协议库统计信息"""
        return {
            "total_protocols": len(self.PROTOCOL_PATTERNS),
            "total_patterns": sum(len(patterns) for patterns in self.PROTOCOL_PATTERNS.values()),
            "by_category": {
                "Token Standard": len([p for p in self.PROTOCOL_PATTERNS if p.startswith("ERC")]),
                "DEX": len([p for p in self.PROTOCOL_PATTERNS if any(x in p for x in ["Uniswap", "Curve"])]),
                "Oracle": len([p for p in self.PROTOCOL_PATTERNS if "Oracle" in p or "Chainlink" in p]),
                "Lending": len([p for p in self.PROTOCOL_PATTERNS if p in ["Aave", "Compound"]]),
            }
        }


def test_protocol_detector():
    """测试函数"""
    detector = ProtocolDetector()

    # 测试用例
    test_cases = [
        ("balanceOf(address)", "ERC20"),
        ("getReserves()(uint112,uint112,uint32)", "Uniswap-V2"),
        ("latestRoundData()", "Chainlink-Oracle"),
        ("ownerOf(uint256)", "ERC721"),
        ("getUserAccountData(address)", "Aave"),
        ("unknown_function()", "Generic"),
    ]

    print("=" * 80)
    print("Protocol Detector Test Results")
    print("=" * 80)

    for signature, expected in test_cases:
        detected = detector.detect(signature)
        status = "✓" if detected == expected else "✗"
        print(f"{status} {signature:50s} → {detected:20s} (expected: {expected})")

    print("\n" + "=" * 80)
    print("Supported Protocols:")
    print("=" * 80)
    for protocol in detector.get_supported_protocols():
        info = detector.get_protocol_info(protocol)
        print(f"  {protocol:20s} - {info['category']:15s} ({info['function_count']} functions)")

    print("\n" + "=" * 80)
    print("Statistics:")
    print("=" * 80)
    stats = detector.get_statistics()
    for key, value in stats.items():
        if isinstance(value, dict):
            print(f"  {key}:")
            for sub_key, sub_value in value.items():
                print(f"    - {sub_key}: {sub_value}")
        else:
            print(f"  {key}: {value}")


if __name__ == "__main__":
    test_protocol_detector()
