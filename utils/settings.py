#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import os

# Ethereum VM ('homestead', 'byzantium' or 'petersburg')
EVM_VERSION = "petersburg"
# Size of population (None = auto-calculate as 2 × interface count)
POPULATION_SIZE = None
# Number of generations
GENERATIONS = 10
# Global timeout in seconds
GLOBAL_TIMEOUT = 200
# Probability of crossover
PROBABILITY_CROSSOVER = 0.9
# Probability of mutation
PROBABILITY_MUTATION = 0.1
# Maximum number of symbolic execution calls before restting population
MAX_SYMBOLIC_EXECUTION = 10
# Solver timeout in milliseconds
SOLVER_TIMEOUT = 100

# ==================== Population-Based Fuzzing Configuration ====================

# Survival strategy - Keep top X% parents in each generation
ELITE_RATIO = 0.1

# Elite archive size (replaces seed pool max)
ELITE_ARCHIVE_SIZE = 2000

# Elite injection interval (every N generations)
ELITE_INJECTION_INTERVAL = 5

# Number of elite seeds to inject
ELITE_INJECTION_COUNT = 5

# Population reset on stagnation
MAX_STAGNANT_GENERATIONS = 10

# Elite preservation ratio during reset
RESET_PRESERVE_ELITE_RATIO = 0.1

# ==================== End Population-Based Fuzzing Configuration ====================

# List of attacker accounts
ATTACKER_ACCOUNTS = ["0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"]
# Default gas limit for sending transactions
GAS_LIMIT = 45000000
# Default gas price for sending transactions
GAS_PRICE = 10
# Default account balance
ACCOUNT_BALANCE = 100000000*(10**18)
# Maximum length of individuals
MAX_INDIVIDUAL_LENGTH = 20
# Logging level
LOGGING_LEVEL = logging.INFO
# Block height
BLOCK_HEIGHT = 'latest'
# RPC Host
RPC_HOST = 'localhost'
# RPC Port
RPC_PORT = 8545
# True = Remote fuzzing, False = Local fuzzing
REMOTE_FUZZING = False
# True = Environmental instrumentation enabled, False = Environmental instrumentation disabled
ENVIRONMENTAL_INSTRUMENTATION = True

MUTATE_SNAPSHOT_ENABLE = False

MUTATE_ENERGY_ENABLE = True

TX_GEN = True

MUTATION_NUM = 2

MUTATE_KEY_VAR_WEIGHT = 0.8

MUTATE_KEY_VAR_PUBLISH_WEIGHT = 0.1

PM_LINE = 0.1

PM_ALPHA = 0.4
PM_BELTA = 0.2

# ==================== 适应能量配置 ====================

# 适应度阈值（低于此值的种子将被丢弃）
FITNESS_THRESHOLD = 0.2

# 参数适应能量 - 分支覆盖与漏洞接近的权重
PARAM_ALPHA = 0.2
PARAM_BELTA = 0.5

# 环境适应能量 - 成功率与调用活跃度的权重
ENV_SUCCESS_WEIGHT = 0.6

# 加权几何平均的权重
ADAPTIVE_WEIGHT_PARAM = 0.5      # 参数适应能量权重
ADAPTIVE_WEIGHT_STATE = 0.2      # 状态适应能量权重
ADAPTIVE_WEIGHT_ENV = 0.3        # 环境适应能量权重

# ==================== End 适应能量配置 ====================

PR_MUTATE_SEQ=0.5

GEN_FIGURE_ENABLE = False

# Enable/Disable mock return values for external calls from JSON file  True
MOCK_RETURN_VALUES_ENABLE = True

MOCK_RETURN_VALUES_LLMGEN_ENABLE = True


MOCK_RETURN_VALUES_MUTATE_PM = 0.2

# ==================== LLM 客户端配置 ====================

# 选择 LLM 提供商: "local" (本地模型) 或 "remote" (远程API)
LLM_PROVIDER = "remote"

# 本地模型配置
LLM_LOCAL_MODEL_PATH = "Qwen/Qwen2.5-Coder-3B-Instruct"
LLM_LOCAL_DEVICE = "cuda:0"

# 远程 API 配置 (使用 OpenAI 官方库)
# base_url: None 表示使用 OpenAI 官方地址 (https://api.openai.com/v1)
#           也可设置为其他兼容服务，如:
#           - "https://api.deepseek.com/v1" (DeepSeek)
#           - "https://api.siliconflow.cn/v1" (SiliconFlow)
LLM_REMOTE_BASE_URL = "https://api.siliconflow.cn/v1"  # None = OpenAI 官方
LLM_REMOTE_MODEL = "Qwen/Qwen3-Coder-30B-A3B-Instruct"  # 可选: gpt-4o, gpt-4o-mini, gpt-3.5-turbo
# LLM_REMOTE_MODEL = "Qwen/Qwen3-Coder-480B-A35B-Instruct"
LLM_REMOTE_API_KEY = os.getenv("LLM_API_KEY", "")  # API Key，从环境变量读取
LLM_REMOTE_TIMEOUT = 600  # 秒

# 重试配置 (openai 库内置支持)
LLM_RETRY_MAX_ATTEMPTS = 3

# LLM 生成参数
LLM_MAX_TOKENS = 8192  # 模型限制: 262144，生成 mock 值通常不需要太多
LLM_TEMPERATURE = 0.4
LLM_TOP_P = 0.9

# ==================== End LLM 客户端配置 ====================

# ==================== Context Agent 配置 ====================

# 是否启用 Context Agent 模式（多Agent架构）
# True: 使用新的 Context Agent 系统（多轮交互，自动修正）
# False: 使用原有的单次 LLM 调用方式
CONTEXT_AGENT_MODE_ENABLE = True

# Context Agent 最大重试次数（验证失败时重新生成）
CONTEXT_AGENT_MAX_RETRIES = 3

# Agent 最大迭代次数（单个 Agent 的 ReAct 循环上限）
CONTEXT_AGENT_MAX_ITERATIONS = 10

# 是否输出 Agent 思考过程（调试用）
CONTEXT_AGENT_VERBOSE = False

# 是否启用语义理解 Agent（SemanticAgent）
# 启用后会分析外部调用的业务含义，生成更精准的 mock 值
CONTEXT_AGENT_SEMANTIC_ENABLE = True

# 是否启用自动验证和修正（ValidatorAgent）
CONTEXT_AGENT_VALIDATION_ENABLE = True

# ==================== End Context Agent 配置 ====================

# ==================== 自适应阈值配置 ====================

# 启用自适应阈值
ADAPTIVE_THRESHOLD_ENABLE = True

# 基准适应度阈值（覆盖率增长时的阈值）
FITNESS_THRESHOLD_BASE = 0.2

# 最低适应度阈值（覆盖率长期停滞时的最低阈值）
FITNESS_THRESHOLD_MIN = 0.01

# 阈值衰减速率（每处理多少个停滞种子，阈值衰减约 63%）
THRESHOLD_DECAY_RATE = 20

# 阈值衰减强度系数
THRESHOLD_DECAY_STRENGTH = 2.0

# ==================== End 自适应阈值配置 ====================

# ==================== Crossover 配置 ====================

# 启用交叉算子
CROSSOVER_ENABLE = True

# Crossover与Mutation的数量比例（1.0表示1:1）
CROSSOVER_MUTATION_RATIO = 1.0

# ==================== End Crossover 配置 ====================

# Enable/Disable saving CFG to JSON file
SAVE_CFG_JSON_ENABLE = False

