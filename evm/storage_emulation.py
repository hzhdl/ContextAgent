#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random

from eth import constants
from eth._utils.address import force_bytes_to_address
from eth_hash.auto import keccak
from eth_typing import Address, Hash32
from eth_utils import to_bytes, to_normalized_address, to_hex

from eth.chains.mainnet import MainnetHomesteadVM
from eth.constants import BLANK_ROOT_HASH, EMPTY_SHA3
from eth.db import BaseAtomicDB
from eth.db.account import BaseAccountDB
from eth.db.typing import JournalDBCheckpoint
from eth.rlp.accounts import Account
from eth.tools._utils.normalization import to_int
from eth.validation import validate_uint256, validate_canonical_address, validate_is_bytes

from eth.vm.forks import FrontierVM, TangerineWhistleVM, SpuriousDragonVM, ByzantiumVM, PetersburgVM
from eth.vm.forks.byzantium import ByzantiumState
from eth.vm.forks.byzantium.computation import ByzantiumComputation
from eth.vm.forks.frontier import FrontierState
from eth.vm.forks.frontier.computation import FrontierComputation
from eth.vm.forks.homestead import HomesteadState
from eth.vm.forks.homestead.computation import HomesteadComputation
from eth.vm.forks.petersburg import PetersburgState
from eth.vm.forks.petersburg.computation import PetersburgComputation
from eth.vm.forks.spurious_dragon import SpuriousDragonState
from eth.vm.forks.spurious_dragon.computation import SpuriousDragonComputation
from eth.vm.forks.tangerine_whistle import TangerineWhistleState
from eth.vm.forks.tangerine_whistle.computation import TangerineWhistleComputation

from web3 import HTTPProvider
from web3 import Web3

from utils import settings

global BLOCK_ID
BLOCK_ID = "latest"


def encode_return_values_to_bytes(values: list) -> bytes:
    """
    将返回值列表编码为 EVM ABI 格式的 bytes
    每个值都编码为32字节并拼接在一起

    Args:
        values: 返回值列表，可以包含 bool, int, str(address), bytes 等类型

    Returns:
        编码后的 bytes，长度为 32 * len(values)
    """
    encoded_parts = []

    for value in values:
        # 处理不同类型的值
        if isinstance(value, bool):
            # bool 编码为32字节，最后一个字节是0或1
            encoded = (1 if value else 0).to_bytes(32, byteorder='big')

        elif isinstance(value, int):
            # int/uint 编码为32字节大端序
            # 处理负数（有符号整数）
            if value < 0:
                # 使用补码表示负数
                encoded = (value % (2**256)).to_bytes(32, byteorder='big')
            else:
                encoded = value.to_bytes(32, byteorder='big')

        elif isinstance(value, str):
            # 字符串可能是地址或十六进制数据
            if value.startswith('0x') or value.startswith('0X'):
                # 移除0x前缀
                hex_str = value[2:]

                # 检查是否是地址（40个字符）
                if len(hex_str) == 40:
                    # 地址：前12字节为0，后20字节是地址
                    address_bytes = bytes.fromhex(hex_str)
                    encoded = b'\x00' * 12 + address_bytes

                elif len(hex_str) == 64:
                    # bytes32：直接使用
                    encoded = bytes.fromhex(hex_str)

                else:
                    # 其他十六进制数据：补齐到32字节
                    hex_bytes = bytes.fromhex(hex_str)
                    if len(hex_bytes) <= 32:
                        # 右对齐（前面补0）
                        encoded = b'\x00' * (32 - len(hex_bytes)) + hex_bytes
                    else:
                        # 截断到32字节
                        encoded = hex_bytes[:32]
            else:
                # 非十六进制字符串，尝试解析为整数
                try:
                    int_value = int(value)
                    encoded = int_value.to_bytes(32, byteorder='big')
                except ValueError:
                    # 无法解析，填充0
                    encoded = b'\x00' * 32

        elif isinstance(value, bytes):
            # bytes 类型
            if len(value) <= 32:
                # 右对齐（前面补0）
                encoded = b'\x00' * (32 - len(value)) + value
            else:
                # 截断到32字节
                encoded = value[:32]

        else:
            # 其他类型，默认填充0
            encoded = b'\x00' * 32

        encoded_parts.append(encoded)

    # 拼接所有编码后的部分
    return b''.join(encoded_parts)


# STORAGE EMULATOR
class EmulatorAccountDB(BaseAccountDB):
    def __init__(self, db: BaseAtomicDB, state_root: Hash32 = BLANK_ROOT_HASH) -> None:
        if settings.REMOTE_FUZZING and settings.RPC_HOST and settings.RPC_PORT:
            self._w3 = Web3(HTTPProvider('http://%s:%s' % (settings.RPC_HOST, settings.RPC_PORT)))
            self._remote = self._w3.eth
        else:
            self._remote = None
        self.state_root = BLANK_ROOT_HASH
        self._raw_store_db = db
        self.snapshot = None

    def set_snapshot(self, snapshot):
        self.snapshot = snapshot

    @property
    def state_root(self) -> Hash32:
        return self._state_root

    @state_root.setter
    def state_root(self, value: Hash32) -> None:
        self._state_root = value

    @property
    def _storage_emulator(self):
        return self._raw_store_db["storage"]

    @property
    def _account_emulator(self):
        return self._raw_store_db["account"]

    @property
    def _code_storage_emulator(self):
        return self._raw_store_db["code"]

    def get_storage(self, address: Address, slot: int, from_journal: bool = True) -> int:
        validate_canonical_address(address, title="Storage Address")
        validate_uint256(slot, title="Storage Slot")
        if address in self._storage_emulator and slot in self._storage_emulator[address] or not self._remote:
            try:
                return self._storage_emulator[address][slot]
            except KeyError:
                return 0
        else:
            result = self._remote.getStorageAt(address, slot, "latest")
            result = to_int(result.hex())
            self.set_storage(address, slot, result)
            if self.snapshot != None:
                if address not in self.snapshot["storage"]:
                    self.snapshot["storage"][address] = dict()
                self.snapshot["storage"][address][slot] = result
            return result

    def set_storage(self, address: Address, slot: int, value: int) -> None:
        validate_uint256(value, title="Storage Value")
        validate_uint256(slot, title="Storage Slot")
        validate_canonical_address(address, title="Storage Address")
        if address not in self._storage_emulator:
            self._storage_emulator[address] = dict()
        self._storage_emulator[address][slot] = value

    def delete_storage(self, address: Address) -> None:
        validate_canonical_address(address, title="Storage Address")
        if address in self._storage_emulator:
            del self._storage_emulator[address]

    def _get_account(self, address: Address) -> Account:
        if address in self._account_emulator:
            account = self._account_emulator[address]
        elif not self._remote:
            account = Account()
        else:
            code = self._remote.getCode(address, BLOCK_ID)
            if code:
                code_hash = keccak(code)
                self._code_storage_emulator[code_hash] = code
                if self.snapshot != None:
                    self.snapshot["code"][code_hash] = code
            else:
                code_hash = EMPTY_SHA3
            account = Account(
                int(self._remote.getTransactionCount(address, BLOCK_ID)) + 1,
                self._remote.getBalance(address, BLOCK_ID),
                BLANK_ROOT_HASH,
                code_hash
            )
            if self.snapshot != None:
                self.snapshot["account"][address] = account
            self._set_account(address, account)
        return account

    def _has_account(self, address: Address) -> bool:
        return address in self._account_emulator

    def _set_account(self, address: Address, account: Account) -> None:
        self._account_emulator[address] = account

    def get_nonce(self, address: Address) -> int:
        validate_canonical_address(address, title="Storage Address")
        a = self._get_account(address)
        return a.nonce

    def set_nonce(self, address: Address, nonce: int) -> None:
        validate_canonical_address(address, title="Storage Address")
        validate_uint256(nonce, title="Nonce")
        account = self._get_account(address)
        self._set_account(address, account.copy(nonce=nonce))

    def increment_nonce(self, address: Address):
        current_nonce = self.get_nonce(address)
        self.set_nonce(address, current_nonce + 1)

    def get_balance(self, address: Address) -> int:
        validate_canonical_address(address, title="Storage Address")
        return self._get_account(address).balance

    def set_balance(self, address: Address, balance: int) -> None:
        validate_canonical_address(address, title="Storage Address")
        validate_uint256(balance, title="Account Balance")
        account = self._get_account(address)
        self._set_account(address, account.copy(balance=balance))

    def set_code(self, address: Address, code: bytes) -> None:
        validate_canonical_address(address, title="Storage Address")
        validate_is_bytes(code, title="Code")
        account = self._get_account(address)
        code_hash = keccak(code)
        self._code_storage_emulator[code_hash] = code
        self._set_account(address, account.copy(code_hash=code_hash))

    def get_code(self, address: Address) -> bytes:
        validate_canonical_address(address, title="Storage Address")
        code_hash = self.get_code_hash(address)
        if code_hash == EMPTY_SHA3:
            return b''
        elif code_hash in self._code_storage_emulator:
            return self._code_storage_emulator[code_hash]

    def get_code_hash(self, address: Address) -> Hash32:
        validate_canonical_address(address, title="Storage Address")
        account = self._get_account(address)
        return account.code_hash

    def delete_code(self, address: Address) -> None:
        validate_canonical_address(address, title="Storage Address")
        account = self._get_account(address)
        code_hash = account.code_hash
        self._set_account(address, account.copy(code_hash=EMPTY_SHA3))
        if code_hash in self._code_storage_emulator:
            del self._code_storage_emulator[code_hash]

    def account_is_empty(self, address: Address) -> bool:
        return not self.account_has_code_or_nonce(address) and self.get_balance(address) == 0

    def account_has_code_or_nonce(self, address):
        return self.get_nonce(address) != 0 or self.get_code_hash(address) != EMPTY_SHA3

    def account_exists(self, address: Address) -> bool:
        validate_canonical_address(address, title="Storage Address")
        return address in self._account_emulator

    def touch_account(self, address: Address) -> None:
        validate_canonical_address(address, title="Storage Address")
        account = self._get_account(address)
        self._set_account(address, account)

    def delete_account(self, address: Address) -> None:
        validate_canonical_address(address, title="Storage Address")
        self.delete_code(address)
        if address in self._storage_emulator:
            del self._storage_emulator[address]
        if address in self._account_emulator:
            del self._account_emulator[address]

    def record(self) -> BaseAtomicDB:
        import copy
        checkpoint = copy.deepcopy(self._raw_store_db)
        return checkpoint

    def discard(self, checkpoint: BaseAtomicDB) -> None:
        import copy
        self._raw_store_db = copy.deepcopy(checkpoint)

    def commit(self, checkpoint: JournalDBCheckpoint) -> None:
        pass

    def make_state_root(self) -> Hash32:
        return None

    def persist(self) -> None:
        pass

    def has_root(self, state_root: bytes) -> bool:
        return False


def get_block_hash_for_testing(self, block_number):
    if block_number >= self.block_number:
        return b''
    elif block_number < self.block_number - 256:
        return b''
    else:
        return keccak(to_bytes(text="{0}".format(block_number)))


def fuzz_timestamp_opcode_fn(computation) -> None:
    if settings.ENVIRONMENTAL_INSTRUMENTATION and hasattr(computation.state,
                                                          "fuzzed_timestamp") and computation.state.fuzzed_timestamp is not None:
        computation.stack_push_int(computation.state.fuzzed_timestamp)
    else:
        if random.random() < 0.5:
            computation.stack_push_int(computation.state.timestamp-random.randint(10000,computation.state.timestamp))
        else:
            computation.stack_push_int(computation.state.timestamp+random.randint(10000,1000000000000000000))


def fuzz_blocknumber_opcode_fn(computation) -> None:
    if settings.ENVIRONMENTAL_INSTRUMENTATION and hasattr(computation.state,
                                                          "fuzzed_blocknumber") and computation.state.fuzzed_blocknumber is not None:
        computation.stack_push_int(computation.state.fuzzed_blocknumber)
    else:
        if random.random() < 0.5:
            computation.stack_push_int(computation.state.block_number)
        else:
            computation.stack_push_int(computation.state.block_number)


def fuzz_call_opcode_fn(computation, opcode_fn,tx_function_sig) -> None:
    gas = computation.stack_pop1_int()
    to = computation.stack_pop1_bytes()
    _to = to_normalized_address(to_hex(force_bytes_to_address(to)))
    
    
    # 先保存所有参数
    value, memory_input_start_position, memory_input_size, memory_output_start_position, memory_output_size = computation.stack_pop_ints(5)
    tmp = computation.stack_pop1_int()
    fun_sig = computation.stack_pop1_bytes()
    _fun_sig = to_hex(fun_sig)

    
    # if settings.ENVIRONMENTAL_INSTRUMENTATION and hasattr(computation.state,
    #                                                       "fuzzed_call_return") and computation.state.fuzzed_call_return is not None \
    #         and _to in computation.state.fuzzed_call_return and computation.state.fuzzed_call_return[_to] is not None:
    #     # 使用预设的模拟值处理
    #     computation.memory_write(memory_output_start_position, memory_output_size,
    #                              b'\x00' * memory_output_size if random.randint(1,
    #                                                                             2) == 1 else b'\xff' * memory_output_size)
    #     computation.stack_push_int(computation.state.fuzzed_call_return[_to])
    # else:
    # 执行原始调用前，需要按照正确的顺序将参数压回栈中
    computation.stack_push_bytes(fun_sig)
    computation.stack_push_int(tmp)
    computation.stack_push_int(memory_output_size)
    computation.stack_push_int(memory_output_start_position)
    computation.stack_push_int(memory_input_size)
    computation.stack_push_int(memory_input_start_position)
    computation.stack_push_int(value)
    computation.stack_push_bytes(to)
    computation.stack_push_int(gas)
    

    # 执行原始调用
    opcode_fn(computation=computation)
    # 获取调用结果
    success = computation.stack_pop1_int()

    # detect_new_call = set()

    # 插桩 拦截外部调用函数，准备注入指定的有效的返回值。
    if settings.MOCK_RETURN_VALUES_ENABLE:
        try:
            # 仍保留一定的随机的能力, 避免过度拟合，保留一定的随机性
            if random.random()<0.5:
                # 优先使用交易级别的 mock 配置
                if hasattr(computation.state, "transaction_mock_returns") and \
                computation.state.transaction_mock_returns:

                    transaction_mocks = computation.state.transaction_mock_returns

                    # 检查是否有该外部调用的 mock 数据
                    if _fun_sig in transaction_mocks:
                        mock_config = transaction_mocks[_fun_sig]
                        encoded_bytes = mock_config["encoded"]

                        # 注入到 EVM 内存
                        computation.memory_write(
                            memory_output_start_position,
                            memory_output_size,
                            encoded_bytes
                        )

                        # 更新 returndatasize
                        computation.state.fuzzed_returndatasize[_to] = memory_output_size

                        # 设置调用成功
                        computation.stack_push_int(1)

                        # print(f"[Transaction-level Mock] Injected {mock_config['scenario']} values for {_fun_sig}: {mock_config['values']}")
                        
                        memory = encoded_bytes

                        return _to
                    else:
                        computation.state.detect_new_call.add((tx_function_sig,_fun_sig))
                        # print(f"[Transaction-level Mock] No mock return values found for {tx_function_sig}:{_fun_sig}")

                # Fallback: 使用全局 mock 配置（保留原有逻辑）
                if hasattr(computation.state, "mock_return_values") and computation.state.mock_return_values is not None:
                    mrv = computation.state.mock_return_values['mock_return_values']
                    tfss = tx_function_sig
                    for tfs in mrv.keys():
                        if _fun_sig in mrv[tfs]:
                            tfss = tfs
                            
                    if tfss in mrv and _fun_sig in mrv[tfss]:
                        injected_values = mrv[tfss][_fun_sig]['mock_values']
                        one_index = random.choice(list(injected_values.keys()))
                        two_index = random.choice(range(len(injected_values[one_index])))
                        injected_value_data = injected_values[one_index][two_index]
                        encoded_bytes = encode_return_values_to_bytes(injected_value_data)
                        # 直接增加这一配置
                        if tx_function_sig not in computation.state.mock_return_values['mock_return_values']:
                            computation.state.mock_return_values['mock_return_values'][tx_function_sig] = {}
                        computation.state.mock_return_values['mock_return_values'][tx_function_sig][_fun_sig] = mrv[tfss][_fun_sig]
                        # 写入内存时转为bytes
                        computation.memory_write(memory_output_start_position, memory_output_size, encoded_bytes)
                        computation.state.fuzzed_returndatasize[_to] = memory_output_size
                        computation.stack_push_int(1)

                        # print(f"[Global Mock] Found mock return values for {tx_function_sig}:{_fun_sig}")
                        return _to
        except Exception as e:
            # 错误时直接返回随机结果
            print("wrong mock value, skip and return random value!")


        # 如果没有找到 mock 配置或随机失败，使用随机返回值
        if random.random() < 0.5:
            random_output = bytearray(b'\x00' * memory_output_size)
            for i in range(memory_output_size):
                # if random.random() < 0.5:
                random_output[i] = random.randint(0, 255)  # 生成 0-255 的随机整数
            # 写入内存时转为bytes
            if random.random() < 0.3:
                # computation.memory_write(memory_output_start_position, memory_output_size, bytes(random_output))
                computation.state.fuzzed_returndatasize[_to] = 0
            else:
                computation.memory_write(memory_output_start_position, memory_output_size, bytes(random_output))
                computation.state.fuzzed_returndatasize[_to] = memory_output_size
            computation.stack_push_int(1)
        else:
            computation.state.fuzzed_returndatasize[_to] = None
            computation.stack_push_int(0)
        # print(f"[Random Mock] Injected random return values for {tx_function_sig}:{_fun_sig}")
    else:
        # if not success and random.random() < 0.2:  # 如果调用失败
        #     # 生成随机的返回数据
        #     random_output = bytearray(b'\x00' * memory_output_size)
        #     if random.random() < 0.5:
        #         for i in range(memory_output_size):
        #             if random.random() < 0.5:
        #                 random_output[i] = 0xff  # 用整数
        #     # 写入内存时转为bytes
        #     computation.memory_write(memory_output_start_position, memory_output_size, bytes(random_output))
            
        #     computation.state.fuzzed_returndatasize[_to] = memory_output_size
            
        #     # 返回失败状态
        #     computation.stack_push_int(1)
        # else:  # 如果调用成功
            
        #     if not success:
        #         computation.state.fuzzed_returndatasize[_to] = None
        #     else:
        #         computation.state.fuzzed_returndatasize[_to] = memory_output_size
            
        #     # 保持原有的成功状态
        #     computation.stack_push_int(success)

        # random_output = bytearray(b'\x00' * memory_output_size)
        # for i in range(memory_output_size):
        #     if random.random() < 0.5:
        #         random_output[i] = 0xff  # 用整数
        # # 写入内存时转为bytes
        # computation.memory_write(memory_output_start_position, memory_output_size, bytes(random_output))
        
        # computation.state.fuzzed_returndatasize[_to] = memory_output_size
        computation.stack_push_int(success)

    return _to

def fuzz_staticcall_opcode_fn(computation, opcode_fn,tx_function_sig) -> None:
    gas = computation.stack_pop1_int()
    to = computation.stack_pop1_bytes()
    _to = to_normalized_address(to_hex(force_bytes_to_address(to)))
    
    
    if settings.ENVIRONMENTAL_INSTRUMENTATION and hasattr(computation.state,
                                                          "fuzzed_call_return") and computation.state.fuzzed_call_return is not None \
            and _to in computation.state.fuzzed_call_return and computation.state.fuzzed_call_return[_to] is not None:
        # 使用预设的模拟值处理
        (
            memory_input_start_position,
            memory_input_size,
            memory_output_start_position,
            memory_output_size,
        ) = computation.stack_pop_ints(4)
        computation.memory_write(memory_output_start_position, memory_output_size, b'\x00' * memory_output_size if random.randint(1, 2) == 1 else b'\xff' * memory_output_size)
        computation.stack_push_int(computation.state.fuzzed_call_return[_to])
    else:
        computation.stack_push_bytes(to)
        computation.stack_push_int(gas)
        opcode_fn(computation=computation)
    
    return _to


def fuzz_extcodesize_opcode_fn(computation, opcode_fn) -> None:
    # 从栈顶弹出地址
    to = computation.stack_pop1_bytes()
    _to = to_normalized_address(to_hex(force_bytes_to_address(to)))
    
    # 检查是否有预设的模拟值
    if settings.ENVIRONMENTAL_INSTRUMENTATION and hasattr(computation.state,
                                                          "fuzzed_extcodesize") and computation.state.fuzzed_extcodesize is not None \
            and _to in computation.state.fuzzed_extcodesize and computation.state.fuzzed_extcodesize[_to] is not None:
        # 使用预设的模拟值
        computation.stack_push_int(computation.state.fuzzed_extcodesize[_to])
    else:
        # 先执行原始操作码获取实际代码大小
        computation.stack_push_bytes(to)
        opcode_fn(computation=computation)
        
        # 获取操作码执行结果
        code_size = computation.stack_pop1_int()
        
        # 如果代码大小为0，进行随机处理,对应模拟值注入，避免为执行call既回滚
        if settings.MOCK_RETURN_VALUES_ENABLE and code_size == 0:
            # import random
            if random.random() < 0.5:  # 50%概率返回0
                computation.stack_push_int(0)
            else:  # 50%概率返回随机长度
            # 生成一个随机的合理的代码长度 (例如在0到24576字节之间)
                random_size = random.randint(100, 24576)  # 24576是一个常见的最大合约大小
                computation.stack_push_int(random_size)
        else:
            # 如果不是0，保持原值
            computation.stack_push_int(code_size)


def fuzz_returndatasize_opcode_fn(previous_call_address, computation, opcode_fn) -> None:
    opcode_fn(computation=computation)
    size = computation.stack_pop1_int()
    if settings.ENVIRONMENTAL_INSTRUMENTATION and hasattr(computation.state,
                                                          "fuzzed_returndatasize") and computation.state.fuzzed_returndatasize is not None \
            and previous_call_address in computation.state.fuzzed_returndatasize and \
            computation.state.fuzzed_returndatasize[previous_call_address] is not None:
        computation.stack_push_int(computation.state.fuzzed_returndatasize[previous_call_address])
    else:
        computation.stack_push_int(size)


def fuzz_balance_opcode_fn(computation, opcode_fn) -> None:
    if settings.ENVIRONMENTAL_INSTRUMENTATION and hasattr(computation.state,
                                                          "fuzzed_balance") and computation.state.fuzzed_balance is not None:
        computation.stack_pop1_bytes()
        computation.stack_push_int(computation.state.fuzzed_balance)
    else:
        opcode_fn(computation=computation)


def fuzz_apply_computation(cls, state, message, transaction_context):
    cls = cls.__class__
    # 读取message.data中的前4个字节，并转为hex
    tx_function_sig = to_hex(message.data_as_bytes[:4]) if hasattr(message.data_as_bytes, '__getitem__') else None
    with cls(state, message, transaction_context) as computation:
        # Early exit on pre-compiles
        from eth.vm.computation import NO_RESULT
        precompile = computation.precompiles.get(message.code_address, NO_RESULT)
        if precompile is not NO_RESULT:
            precompile(computation)
            return computation

        opcode_lookup = computation.opcodes
        computation.trace = list()
        previous_stack = []
        previous_call_address = None
        memory = None
        

        for opcode in computation.code:
            try:
                opcode_fn = opcode_lookup[opcode]
            except KeyError:
                from eth.vm.logic.invalid import InvalidOpcode
                opcode_fn = InvalidOpcode(opcode)

            from eth.exceptions import Halt
            from copy import deepcopy

            previous_pc = computation.code.pc
            previous_gas = computation.get_gas_remaining()

            try:
                if opcode == 0x42:  # TIMESTAMP
                    fuzz_timestamp_opcode_fn(computation=computation)
                elif opcode == 0x43:  # NUMBER
                    fuzz_blocknumber_opcode_fn(computation=computation)
                elif opcode == 0x31:  # BALANCE
                    fuzz_balance_opcode_fn(computation=computation, opcode_fn=opcode_fn)
                elif opcode == 0xf1:  # CALL
                    previous_call_address = fuzz_call_opcode_fn(computation=computation, opcode_fn=opcode_fn,tx_function_sig=tx_function_sig)
                    # print(f"previous_call_address: {previous_call_address}")
                    
                elif opcode == 0xfa:  # STATICCALL
                    previous_call_address = fuzz_staticcall_opcode_fn(computation=computation, opcode_fn=opcode_fn,tx_function_sig=tx_function_sig)
                elif opcode == 0x3b:  # EXTCODESIZE
                    fuzz_extcodesize_opcode_fn(computation=computation, opcode_fn=opcode_fn)
                elif opcode == 0x3d:  # RETURNDATASIZE
                    fuzz_returndatasize_opcode_fn(previous_call_address, computation=computation, opcode_fn=opcode_fn)
                elif opcode == 0x20:  # SHA3
                    start_position, size = computation.stack_pop_ints(2)
                    memory = computation.memory_read_bytes(start_position, size)
                    computation.stack_push_int(size)
                    computation.stack_push_int(start_position)
                    opcode_fn(computation=computation)
                else:
                    opcode_fn(computation=computation)
            except Halt:
                break
            finally:
                computation.trace.append(
                    {
                        "pc": max(0, previous_pc - 1),
                        "op": opcode_fn.mnemonic,
                        "depth": computation.msg.depth + 1,
                        "error": deepcopy(computation._error),
                        "stack": previous_stack,
                        "memory": memory,
                        "gas": computation.get_gas_remaining(),
                        "gas_used_by_opcode": previous_gas - computation.get_gas_remaining()
                    }
                )
                previous_stack = list(computation._stack.values)

    return computation


# VMs

# FRONTIER
FrontierComputationForFuzzTesting = FrontierComputation.configure(
    __name__='FrontierComputationForFuzzTesting',
    apply_computation=fuzz_apply_computation,
)
FrontierStateForFuzzTesting = FrontierState.configure(
    __name__='FrontierStateForFuzzTesting',
    get_ancestor_hash=get_block_hash_for_testing,
    computation_class=FrontierComputationForFuzzTesting,
    account_db_class=EmulatorAccountDB,
)
FrontierVMForFuzzTesting = FrontierVM.configure(
    __name__='FrontierVMForFuzzTesting',
    _state_class=FrontierStateForFuzzTesting,
)

# HOMESTEAD
HomesteadComputationForFuzzTesting = HomesteadComputation.configure(
    __name__='HomesteadComputationForFuzzTesting',
    apply_computation=fuzz_apply_computation,
)
HomesteadStateForFuzzTesting = HomesteadState.configure(
    __name__='HomesteadStateForFuzzTesting',
    get_ancestor_hash=get_block_hash_for_testing,
    computation_class=HomesteadComputationForFuzzTesting,
    account_db_class=EmulatorAccountDB,
)
HomesteadVMForFuzzTesting = MainnetHomesteadVM.configure(
    __name__='HomesteadVMForFuzzTesting',
    _state_class=HomesteadStateForFuzzTesting,
)

# TANGERINE WHISTLE
TangerineWhistleComputationForFuzzTesting = TangerineWhistleComputation.configure(
    __name__='TangerineWhistleComputationForFuzzTesting',
    apply_computation=fuzz_apply_computation,
)
TangerineWhistleStateForFuzzTesting = TangerineWhistleState.configure(
    __name__='TangerineWhistleStateForFuzzTesting',
    get_ancestor_hash=get_block_hash_for_testing,
    computation_class=TangerineWhistleComputationForFuzzTesting,
    account_db_class=EmulatorAccountDB,
)
TangerineWhistleVMForFuzzTesting = TangerineWhistleVM.configure(
    __name__='TangerineWhistleVMForFuzzTesting',
    _state_class=TangerineWhistleStateForFuzzTesting,
)

# SPURIOUS DRAGON
SpuriousDragonComputationForFuzzTesting = SpuriousDragonComputation.configure(
    __name__='SpuriousDragonComputationForFuzzTesting',
    apply_computation=fuzz_apply_computation,
)
SpuriousDragonStateForFuzzTesting = SpuriousDragonState.configure(
    __name__='SpuriousDragonStateForFuzzTesting',
    get_ancestor_hash=get_block_hash_for_testing,
    computation_class=SpuriousDragonComputationForFuzzTesting,
    account_db_class=EmulatorAccountDB,
)
SpuriousDragonVMForFuzzTesting = SpuriousDragonVM.configure(
    __name__='SpuriousDragonVMForFuzzTesting',
    _state_class=SpuriousDragonStateForFuzzTesting,
)

# BYZANTIUM
ByzantiumComputationForFuzzTesting = ByzantiumComputation.configure(
    __name__='ByzantiumComputationForFuzzTesting',
    apply_computation=fuzz_apply_computation,
)
ByzantiumStateForFuzzTesting = ByzantiumState.configure(
    __name__='ByzantiumStateForFuzzTesting',
    get_ancestor_hash=get_block_hash_for_testing,
    computation_class=ByzantiumComputationForFuzzTesting,
    account_db_class=EmulatorAccountDB,
)
ByzantiumVMForFuzzTesting = ByzantiumVM.configure(
    __name__='ByzantiumVMForFuzzTesting',
    _state_class=ByzantiumStateForFuzzTesting,
)

# PETERSBURG
PetersburgComputationForFuzzTesting = PetersburgComputation.configure(
    __name__='PetersburgComputationForFuzzTesting',
    apply_computation=fuzz_apply_computation,
)
PetersburgStateForFuzzTesting = PetersburgState.configure(
    __name__='PetersburgStateForFuzzTesting',
    get_ancestor_hash=get_block_hash_for_testing,
    computation_class=PetersburgComputationForFuzzTesting,
    account_db_class=EmulatorAccountDB,
)
PetersburgVMForFuzzTesting = PetersburgVM.configure(
    __name__='PetersburgVMForFuzzTesting',
    _state_class=PetersburgStateForFuzzTesting,
)
