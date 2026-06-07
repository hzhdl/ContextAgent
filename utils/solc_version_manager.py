#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Solidity 编译器版本管理器

功能：
1. 从 pragma 语句自动检测 Solidity 版本
2. 根据版本映射表选择合适的编译器和 EVM 版本
3. 获取 solcx 安装的编译器二进制路径
4. 支持并发编译（避免全局状态切换）

使用方法：
    from solc_version_manager import get_compiler_config, get_solc_binary_path

    # 自动获取编译配置
    solc_version, compile_evm, execute_evm = get_compiler_config("contract.sol")

    # 获取 solc 二进制路径（用于 Slither）
    solc_binary = get_solc_binary_path(solc_version)
"""

import os
import re
from typing import Tuple, Optional
import solcx

# solcx 安装目录
SOLCX_INSTALL_DIR = os.path.expanduser("~/.solcx")

# 版本映射表：主版本 -> (推荐编译器版本, 编译EVM, 执行EVM)
# 编译 EVM：solc 编译时使用的 EVM 版本（需要 solc 支持）
# 执行 EVM：py-evm 执行时使用的 EVM 版本（需要 py-evm 支持，目前最高 petersburg）
VERSION_MAP = {
    "0.4": ("0.4.26", "byzantium", "byzantium"),
    "0.5": ("0.5.17", "petersburg", "petersburg"),
    "0.6": ("0.6.12", "petersburg", "petersburg"),
    "0.7": ("0.7.6", "petersburg", "petersburg"),
    "0.8": ("0.8.24", "petersburg", "petersburg"),
}

# 默认版本配置
DEFAULT_CONFIG = ("0.4.26", "byzantium", "petersburg")


def extract_solidity_version(source_file: str) -> Optional[str]:
    """
    从源文件提取 Solidity 版本

    支持的 pragma 格式：
    - pragma solidity ^0.4.24;
    - pragma solidity >=0.4.24;
    - pragma solidity 0.8.24;
    - pragma solidity ^0.4.0;

    Args:
        source_file: Solidity 源文件路径

    Returns:
        版本字符串（如 "0.4.24"）或 None
    """
    try:
        with open(source_file, 'r', encoding='utf-8') as f:
            content = f.read()
    except UnicodeDecodeError:
        with open(source_file, 'r', encoding='latin-1') as f:
            content = f.read()

    # 匹配 pragma solidity 语句
    patterns = [
        r'pragma\s+solidity\s*[\^>=<]*\s*(\d+\.\d+\.\d+)',  # 精确版本 0.4.26
        r'pragma\s+solidity\s*[\^>=<]*\s*(\d+\.\d+)',        # 主版本 0.4
    ]

    for pattern in patterns:
        match = re.search(pattern, content)
        if match:
            return match.group(1)

    return None


def get_major_version(version_str: str) -> str:
    """
    提取主版本号

    Args:
        version_str: 版本字符串（如 "0.4.26" 或 "0.4"）

    Returns:
        主版本号（如 "0.4"）
    """
    parts = version_str.split('.')
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"
    return version_str


def get_compiler_config(source_file: str) -> Tuple[str, str, str]:
    """
    获取编译配置

    根据源文件中的 pragma 语句自动选择合适的编译器和 EVM 版本。

    Args:
        source_file: Solidity 源文件路径

    Returns:
        (solc_version, compile_evm, execute_evm) 三元组
        - solc_version: 推荐的编译器版本
        - compile_evm: 编译时使用的 EVM 版本
        - execute_evm: 执行时使用的 EVM 版本

    Raises:
        ValueError: 无法检测 Solidity 版本时
    """
    detected_version = extract_solidity_version(source_file)

    if not detected_version:
        print(f"Warning: Cannot detect Solidity version from {source_file}, using default config")
        return DEFAULT_CONFIG

    major = get_major_version(detected_version)

    if major in VERSION_MAP:
        config = VERSION_MAP[major]
        print(f"Auto-detected Solidity {detected_version} -> solc {config[0]}, compile EVM: {config[1]}, execute EVM: {config[2]}")
        return config

    # 未知版本，使用默认配置
    print(f"Warning: Unknown Solidity version {detected_version}, using default config")
    return DEFAULT_CONFIG


def get_solc_binary_path(version: str) -> str:
    """
    获取指定版本的 solc 二进制路径

    如果指定版本未安装，会自动安装。

    Args:
        version: 编译器版本（如 "0.4.26" 或 "v0.4.26"）

    Returns:
        solc 二进制文件的完整路径
    """
    # 标准化版本格式
    if not version.startswith("v"):
        version = f"v{version}"

    binary_path = os.path.join(SOLCX_INSTALL_DIR, f"solc-{version}")

    # 如果不存在，自动安装
    if not os.path.exists(binary_path):
        print(f"Installing solc {version}...")
        ensure_solc_installed(version)

    return binary_path


def ensure_solc_installed(version: str) -> None:
    """
    确保指定版本的编译器已安装

    Args:
        version: 编译器版本（如 "0.4.26" 或 "v0.4.26"）
    """
    # 标准化版本格式
    version_clean = version.lstrip("v")

    try:
        installed = [str(v) for v in solcx.get_installed_solc_versions()]

        if version_clean not in installed:
            print(f"Installing solc {version_clean}...")
            solcx.install_solc(version_clean)
            print(f"Successfully installed solc {version_clean}")
    except Exception as e:
        print(f"Warning: Failed to install solc {version_clean}: {e}")


def get_solc_version_object(version: str):
    """
    获取 semantic_version.Version 对象

    用于传递给 solcx.compile_standard() 的 solc_version 参数。

    Args:
        version: 编译器版本（如 "0.4.26" 或 "v0.4.26"）

    Returns:
        semantic_version.Version 对象
    """
    from semantic_version import Version

    version_clean = version.lstrip("v")
    return Version(version_clean)


def list_available_versions() -> dict:
    """
    列出所有支持的版本配置

    Returns:
        版本映射表的副本
    """
    return VERSION_MAP.copy()


def install_all_recommended_versions() -> None:
    """
    安装所有推荐的编译器版本

    用于预先安装所有需要的编译器，避免运行时安装。
    """
    for major, (solc_version, _, _) in VERSION_MAP.items():
        ensure_solc_installed(solc_version)
    print("All recommended solc versions are installed.")


# 模块测试
if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        source_file = sys.argv[1]
        print(f"\nAnalyzing: {source_file}")
        print("-" * 50)

        # 检测版本
        detected = extract_solidity_version(source_file)
        print(f"Detected Solidity version: {detected}")

        # 获取配置
        solc_ver, compile_evm, execute_evm = get_compiler_config(source_file)
        print(f"Recommended solc version: {solc_ver}")
        print(f"Compile EVM version: {compile_evm}")
        print(f"Execute EVM version: {execute_evm}")

        # 获取二进制路径
        binary_path = get_solc_binary_path(solc_ver)
        print(f"Solc binary path: {binary_path}")
        print(f"Binary exists: {os.path.exists(binary_path)}")
    else:
        print("Supported version configurations:")
        print("-" * 50)
        for major, (solc_ver, compile_evm, execute_evm) in VERSION_MAP.items():
            print(f"Solidity {major}.x -> solc {solc_ver}, compile: {compile_evm}, execute: {execute_evm}")

        print("\nInstalled solc versions:")
        for v in solcx.get_installed_solc_versions():
            print(f"  - {v}")
