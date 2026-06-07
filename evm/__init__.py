#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pickle
import logging
import json
import copy

from eth import Chain, constants
from eth.chains.mainnet import (
    MAINNET_GENESIS_HEADER,
    HOMESTEAD_MAINNET_BLOCK,
    TANGERINE_WHISTLE_MAINNET_BLOCK,
    SPURIOUS_DRAGON_MAINNET_BLOCK,
    BYZANTIUM_MAINNET_BLOCK,
    PETERSBURG_MAINNET_BLOCK
)
from eth.constants import ZERO_ADDRESS, CREATE_CONTRACT_ADDRESS
from eth.db.atomic import AtomicDB
from eth.db.backends.memory import MemoryDB
from eth.rlp.accounts import Account
from eth.rlp.headers import BlockHeader
from eth.tools.logging import DEBUG2_LEVEL_NUM
from eth.validation import validate_uint256
from eth.vm.spoof import SpoofTransaction
from eth_utils import to_canonical_address, decode_hex, encode_hex
from web3 import HTTPProvider
from web3 import Web3
from eth_abi import decode

from .storage_emulation import (
    FrontierVMForFuzzTesting,
    HomesteadVMForFuzzTesting,
    TangerineWhistleVMForFuzzTesting,
    SpuriousDragonVMForFuzzTesting,
    ByzantiumVMForFuzzTesting,
    PetersburgVMForFuzzTesting
)

import utils.settings as settings
from utils.utils import initialize_logger

class InstrumentedEVM:
    def __init__(self, eth_node_ip=None, eth_node_port=None) -> None:
        chain_class = Chain.configure(
            __name__='Blockchain',
            vm_configuration=(
                (constants.GENESIS_BLOCK_NUMBER, FrontierVMForFuzzTesting),
                (HOMESTEAD_MAINNET_BLOCK, HomesteadVMForFuzzTesting),
                (TANGERINE_WHISTLE_MAINNET_BLOCK, TangerineWhistleVMForFuzzTesting),
                (SPURIOUS_DRAGON_MAINNET_BLOCK, SpuriousDragonVMForFuzzTesting),
                (BYZANTIUM_MAINNET_BLOCK, ByzantiumVMForFuzzTesting),
                (PETERSBURG_MAINNET_BLOCK, PetersburgVMForFuzzTesting),
            ),
        )
        class MyMemoryDB(MemoryDB):
            def __init__(self) -> None:
                self.kv_store = {'storage': dict(), 'account': dict(), 'code': dict()}
            def rst(self) -> None:
                self.kv_store = {'storage': dict(), 'account': dict(), 'code': dict()}
        if eth_node_ip and eth_node_port and settings.REMOTE_FUZZING:
            self.w3 = Web3(HTTPProvider('http://%s:%s' % (eth_node_ip, eth_node_port)))
        else:
            self.w3 = None
        self.chain = chain_class.from_genesis_header(AtomicDB(MyMemoryDB()), MAINNET_GENESIS_HEADER)
        self.logger = initialize_logger("EVM")
        self.accounts = list()
        self.snapshot = None
        self.vm = None
    
    def set_mock_return_values(self, mock_return_values):
        if self.vm:
            self.vm.state.mock_return_values = mock_return_values
        else:
            print("VM not initialized")

    def get_block_by_blockid(self, block_identifier):
        validate_uint256(block_identifier)
        return self.w3.eth.getBlock(block_identifier)

    def get_cached_block_by_id(self, block_number):
        block = None
        with open(os.path.dirname(os.path.abspath(__file__))+"/"+".".join([str(block_number), "block"]), "rb") as f:
            block = pickle.load(f)
        return block

    @property
    def storage_emulator(self):
        return self.vm.state._account_db

    def set_vm(self, block_identifier='latest'):
        _block = None
        if self.w3:
            if block_identifier == 'latest':
                block_identifier = self.w3.eth.blockNumber
            validate_uint256(block_identifier)
            _block = self.w3.eth.getBlock(block_identifier)
        if not _block:
            if block_identifier in [HOMESTEAD_MAINNET_BLOCK, BYZANTIUM_MAINNET_BLOCK,PETERSBURG_MAINNET_BLOCK]:
                _block = self.get_cached_block_by_id(block_identifier)
            else:
                self.logger.error("Unknown block identifier.")
                sys.exit(-4)
        block_header = BlockHeader(difficulty=_block.difficulty,
                                   block_number=_block.number,
                                   gas_limit=_block.gasLimit,
                                   timestamp=_block.timestamp,
                                   coinbase=ZERO_ADDRESS,  # default value
                                   parent_hash=_block.parentHash,
                                   uncles_hash=_block.uncles,
                                   state_root=_block.stateRoot,
                                   transaction_root=_block.transactionsRoot,
                                   receipt_root=_block.receiptsRoot,
                                   bloom=0,  # default value
                                   gas_used=_block.gasUsed,
                                   extra_data=_block.extraData,
                                   mix_hash=_block.mixHash,
                                   nonce=_block.nonce)
        self.vm = self.chain.get_vm(block_header)

    def execute(self, tx, debug=False):
        if debug:
            logging.getLogger('eth.vm.computation.Computation')
            logging.basicConfig(level=DEBUG2_LEVEL_NUM)
        return self.vm.state.apply_transaction(tx)

    def reset(self):
        self.storage_emulator._raw_store_db.wrapped_db.rst()

    def create_fake_account(self, address, nonce=0, balance=settings.ACCOUNT_BALANCE, code='', storage=None):
        if storage is None:
            storage = {}
        address = to_canonical_address(address)
        account = Account(nonce=nonce, balance=balance)
        self.vm.state._account_db._set_account(address, account)
        if code and code != '':
            self.vm.state._account_db.set_code(address, code)
        if storage:
            for k,v in storage.items():
                self.vm.state._account_db.set_storage(address, int.from_bytes(decode_hex(k), byteorder="big"), int.from_bytes(decode_hex(v), byteorder="big"))
        self.logger.debug("Created account %s with balance %s", encode_hex(address), account.balance)
        return encode_hex(address)

    def has_account(self, address):
        address = to_canonical_address(address)
        return self.vm.state._account_db._has_account(address)

    def deploy_contract(self, creator, bin_code,amount=0, gas=settings.GAS_LIMIT, gas_price=settings.GAS_PRICE, debug=False):
        nonce = self.vm.state.get_nonce(decode_hex(creator))
        tx = self.vm.create_unsigned_transaction(
            nonce=nonce,
            gas_price=gas_price,
            gas=gas,
            to=CREATE_CONTRACT_ADDRESS,
            value=amount,
            data=decode_hex(bin_code),
        )
        tx = SpoofTransaction(tx, from_=decode_hex(creator))

        
        self.vm.state.fuzzed_timestamp = None
        self.vm.state.fuzzed_blocknumber = None
        self.vm.state.fuzzed_balance = None
        self.vm.state.fuzzed_call_return = {}
        self.vm.state.fuzzed_extcodesize = {}
        self.vm.state.fuzzed_returndatasize = {}

        self.vm.state.mock_return_values = {}
        self.vm.state.detect_new_call = set()

        result = self.execute(tx, debug=debug)
        address = to_canonical_address(encode_hex(result.msg.storage_address))
        self.storage_emulator.set_balance(address, 1)
        return result

    def deploy_transaction(self, input, gas_price=settings.GAS_PRICE, debug=False):
        transaction = input["transaction"]
        from_account = decode_hex(transaction["from"])
        nonce = self.vm.state.get_nonce(from_account)
        try:
            to = decode_hex(transaction["to"])
        except:
            to = transaction["to"]
        tx = self.vm.create_unsigned_transaction(
            nonce=nonce,
            gas_price=gas_price,
            gas=transaction["gaslimit"],
            to=to,
            value=transaction["value"],
            data=decode_hex(transaction["data"]),
        )
        tx = SpoofTransaction(tx, from_=from_account)

        block = input["block"]
        if "timestamp" in block and block["timestamp"] is not None:
            self.vm.state.fuzzed_timestamp = block["timestamp"]
        else:
            self.vm.state.fuzzed_timestamp = None
        if "blocknumber" in block and block["blocknumber"] is not None:
            self.vm.state.fuzzed_blocknumber = block["blocknumber"]
        else:
            self.vm.state.fuzzed_blocknumber = None

        global_state = input["global_state"]
        if "balance" in global_state and global_state["balance"] is not None:
            self.vm.state.fuzzed_balance = global_state["balance"]
        else:
            self.vm.state.fuzzed_balance = None

        if "call_return" in global_state and global_state["call_return"] is not None \
                and len(global_state["call_return"]) > 0:
            self.vm.state.fuzzed_call_return = global_state["call_return"]
        if "extcodesize" in global_state and global_state["extcodesize"] is not None \
                and len(global_state["extcodesize"]) > 0:
            self.vm.state.fuzzed_extcodesize = global_state["extcodesize"]

        # 新增：设置当前交易的 mock 配置
        if "mock_call_returns" in global_state and global_state["mock_call_returns"] is not None \
                and len(global_state["mock_call_returns"]) > 0:
            self.vm.state.transaction_mock_returns = global_state["mock_call_returns"]
        else:
            self.vm.state.transaction_mock_returns = {}

        environment = input["environment"]
        if "returndatasize" in environment and environment["returndatasize"] is not None:
            self.vm.state.fuzzed_returndatasize = environment["returndatasize"]

        self.storage_emulator.set_balance(from_account, settings.ACCOUNT_BALANCE)
        return self.execute(tx, debug=debug)

    def get_balance(self, address):
        return self.storage_emulator.get_balance(address)

    def get_code(self, address):
        return self.storage_emulator.get_code(address)

    def set_code(self, address, code):
        return self.storage_emulator.set_code(address, code)

    def create_snapshot(self):
        self.snapshot = self.storage_emulator.record()
        self.storage_emulator.set_snapshot(self.snapshot)

    def restore_from_snapshot(self):
        self.storage_emulator.discard(self.snapshot)

    def create_new_snapshot(self):
        snapshot = self.storage_emulator.record()
        return copy.deepcopy(snapshot)

    def restore_by_snapshot(self,snapshot):
        self.storage_emulator.discard(snapshot)

    def get_accounts(self):
        return [encode_hex(x) for x in self.storage_emulator._raw_store_db.wrapped_db["account"].keys()]

    def set_vm_by_name(self, EVM_VERSION):
        if   EVM_VERSION == "homestead":
            self.set_vm(HOMESTEAD_MAINNET_BLOCK)
        elif EVM_VERSION == "byzantium":
            self.set_vm(BYZANTIUM_MAINNET_BLOCK)
        elif EVM_VERSION == "petersburg":
            self.set_vm(PETERSBURG_MAINNET_BLOCK)
        else:
            raise Exception("Unknown EVM version, please choose either 'homestead', 'byzantium' or 'petersburg'.")

    def create_fake_accounts(self):
        self.accounts.append(self.create_fake_account("0xcafebabecafebabecafebabecafebabecafebabe"))
        for address in settings.ATTACKER_ACCOUNTS:
            self.accounts.append(self.create_fake_account(address))

    def read_contract_state(self, contract_address, abi, from_address):
        state = {}
        storage_emulator = self.storage_emulator
        contract_addr = to_canonical_address(contract_address)
        
        # 获取合约代码确保合约存在
        code = storage_emulator.get_code(contract_addr)
        if not code:
            return state
            
        # 通过ABI解析状态变量
        for item in abi:
            # 只处理状态变量的getter函数
            if item['type'] == 'function' and len(item['inputs']) == 0 and \
               item.get('stateMutability') in ['view', 'pure', 'constant']:
                try:
                    # 创建函数选择器
                    name = item['name']
                    selector = Web3.keccak(text=f"{name}()")[:4]
                    
                    # 构造调用消息
                    message = {
                        "transaction": {
                            "from": from_address,
                            "to": contract_address,
                            "data": selector.hex(),
                            "value": 0,
                            "gaslimit": 3000000
                        },
                        "block": {},
                        "global_state": {},
                        "environment": {}
                    }
                    
                    # 执行调用
                    result = self.deploy_transaction(message)
                    
                    # 如果调用成功，解析返回值
                    if result.is_success and hasattr(result, 'output'):
                        # 根据ABI输出类型解码返回值
                        return_type = item['outputs'][0]['type']
                        try:
                            # 使用旧版本的decode函数从output解码
                            decoded_value = decode([return_type], result.output)[0]
                            # 对于address类型，确保转换为正确的格式
                            # if return_type == 'address':
                            #     # 确保地址是20字节长度，并添加0x前缀
                            #     decoded_value = '0x' + decoded_value.hex().lower().zfill(40)
                            state[name] = decoded_value
                        except Exception as e:
                            self.logger.debug(f"Error decoding {name} ({return_type}): {e}")
                            # 如果解码失败，保存原始数据
                            state[name] = result.output.hex() if result.output else None
                            
                except Exception as e:
                    self.logger.debug(f"Error reading {name}: {e}")
                    
        return state
    
    def read_contract_state_by_names(self, contract_address, abi, from_address, state_names):
        state = {}
        storage_emulator = self.storage_emulator
        contract_addr = to_canonical_address(contract_address)
        
        # 获取合约代码确保合约存在
        code = storage_emulator.get_code(contract_addr)
        if not code:
            return state
            
        # 通过ABI解析状态变量
        for item in abi:
            # 只处理状态变量的getter函数
            if  item['type'] == 'function' and item['name'] in state_names and len(item['inputs']) == 0 and \
               item.get('stateMutability') in ['view', 'pure', 'constant']:
                try:
                    # 创建函数选择器
                    name = item['name']
                    selector = Web3.keccak(text=f"{name}()")[:4]
                    
                    # 构造调用消息
                    message = {
                        "transaction": {
                            "from": from_address,
                            "to": contract_address,
                            "data": selector.hex(),
                            "value": 0,
                            "gaslimit": 3000000
                        },
                        "block": {},
                        "global_state": {},
                        "environment": {}
                    }
                    
                    # 执行调用
                    result = self.deploy_transaction(message)
                    
                    # 如果调用成功，解析返回值
                    if result.is_success and hasattr(result, 'output'):
                        # 根据ABI输出类型解码返回值
                        return_type = item['outputs'][0]['type']
                        try:
                            # 使用旧版本的decode函数从output解码
                            decoded_value = decode([return_type], result.output)[0]
                            # 对于address类型，确保转换为正确的格式
                            # if return_type == 'address':
                            #     # 确保地址是20字节长度，并添加0x前缀
                            #     decoded_value = '0x' + decoded_value.hex().lower().zfill(40)
                            state[name] = decoded_value
                        except Exception as e:
                            self.logger.debug(f"Error decoding {name} ({return_type}): {e}")
                            # 如果解码失败，保存原始数据
                            state[name] = result.output.hex() if result.output else None
                            
                except Exception as e:
                    self.logger.debug(f"Error reading {name}: {e}")
                    
        return state

    def read_contract_state_by_layout(self, contract_address, storage_layout_json):
        """
        通过solc生成的storage-layout读取合约状态
        :param contract_address: 合约地址
        :param storage_layout_json: solc生成的storage-layout JSON数据
        :return: 合约状态变量的值
        """
        state = {}
        storage_emulator = self.storage_emulator
        contract_addr = to_canonical_address(contract_address)

        # 获取合约代码确保合约存在
        code = storage_emulator.get_code(contract_addr)
        if not code:
            return state

        try:
            # 处理每个存储变量
            for storage_var in storage_layout_json.get("storage", []):
                var_name = storage_var["label"]
                var_type = storage_var["type"]
                slot = int(storage_var["slot"])
                offset = int(storage_var.get("offset", 0))

                try:
                    # 读取基本类型
                    if "t_uint" in var_type or "t_int" in var_type:
                        value = storage_emulator.get_storage(contract_addr, slot)
                        if offset > 0:
                            # 计算位数
                            bits = 256  # 默认为256位
                            if type_info := storage_layout_json.get("types", {}).get(var_type):
                                bits = int(type_info.get("numberOfBytes", 32)) * 8
                            mask = (1 << bits) - 1
                            value = (value >> (offset * 8)) & mask
                        state[var_name] = value

                    elif "t_address" in var_type:
                        value = storage_emulator.get_storage(contract_addr, slot)
                        if offset > 0:
                            value = (value >> (offset * 8)) & ((1 << 160) - 1)
                        state[var_name] = encode_hex(value.to_bytes(20, 'big'))

                    elif "t_bool" in var_type:
                        value = storage_emulator.get_storage(contract_addr, slot)
                        if offset > 0:
                            value = (value >> (offset * 8)) & 1
                        state[var_name] = bool(value)

                    elif "t_bytes" in var_type:
                        value = storage_emulator.get_storage(contract_addr, slot)
                        size = 32  # 默认32字节
                        if type_info := storage_layout_json.get("types", {}).get(var_type):
                            size = int(type_info.get("numberOfBytes", 32))
                        if offset > 0:
                            value = (value >> (offset * 8)) & ((1 << (size * 8)) - 1)
                        state[var_name] = '0x' + value.to_bytes(size, 'big').hex()

                    elif "t_string" in var_type:
                        # 字符串特殊处理
                        value = storage_emulator.get_storage(contract_addr, slot)
                        if value & 1:  # 短字符串，直接存储在槽中
                            length = (value >> 1) & 0xFF
                            string_bytes = (value >> 8).to_bytes(length, 'big')
                            try:
                                state[var_name] = string_bytes.decode('utf-8')
                            except UnicodeDecodeError:
                                state[var_name] = '0x' + string_bytes.hex()
                        else:  # 长字符串，存储在其他槽中
                            length = value >> 1
                            if length > 0:
                                from eth_hash.auto import keccak
                                data_slot = int.from_bytes(keccak(slot.to_bytes(32, 'big')), 'big')
                                string_data = b''
                                for i in range((length + 31) // 32):
                                    word = storage_emulator.get_storage(contract_addr, data_slot + i)
                                    string_data += word.to_bytes(32, 'big')
                                try:
                                    state[var_name] = string_data[:length].decode('utf-8')
                                except UnicodeDecodeError:
                                    state[var_name] = '0x' + string_data[:length].hex()

                    elif "t_mapping" in var_type:
                        # 对于mapping，我们只记录它的槽位，因为需要key才能读取具体值
                        state[var_name] = {"base_slot": slot, "type": var_type}

                    elif "t_array" in var_type:
                        # 读取数组长度
                        length = storage_emulator.get_storage(contract_addr, slot)
                        state[var_name] = {
                            "length": length,
                            "base_slot": slot,
                            "type": var_type
                        }

                except Exception as e:
                    self.logger.debug(f"Error reading {var_name}: {e}")
                    state[var_name] = None

        except Exception as e:
            self.logger.error(f"Error processing storage layout: {e}")

        return state

    

    def read_array_length(self, contract_address, slot):
        """
        读取动态数组的长度
        :param contract_address: 合约地址
        :param slot: 数组的槽位
        :return: 数组长度
        """
        try:
            return self.storage_emulator.get_storage(
                to_canonical_address(contract_address), 
                slot
            )
        except Exception as e:
            self.logger.debug(f"Error reading array length: {e}")
            return 0

    def read_array_element(self, contract_address, slot, index, element_type='uint256'):
        """
        读取数组元素
        :param contract_address: 合约地址
        :param slot: 数组的槽位
        :param index: 元素索引
        :param element_type: 元素类型
        :return: 元素值
        """
        try:
            from eth_hash.auto import keccak
            # 动态数组的元素存储在 keccak256(slot) + index
            array_slot = int.from_bytes(keccak(slot.to_bytes(32, 'big')), 'big')
            element_slot = array_slot + index
            
            value = self.storage_emulator.get_storage(
                to_canonical_address(contract_address), 
                element_slot
            )
            
            # 根据类型处理返回值
            if element_type == 'address':
                return encode_hex(value.to_bytes(20, 'big'))
            elif element_type == 'bool':
                return bool(value)
            elif element_type.startswith('bytes'):
                size = int(element_type.replace('bytes', ''))
                return '0x' + value.to_bytes(size, 'big').hex()
            else:  # uint256 或其他数值类型
                return value
                
        except Exception as e:
            self.logger.debug(f"Error reading array element: {e}")
            return None

    

    



