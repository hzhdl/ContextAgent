#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import collections

from utils import settings
from utils.utils import *
from eth_utils import decode_hex
from evm.storage_emulation import encode_return_values_to_bytes

UINT_MAX = {
    1: int("0xff", 16),
    2: int("0xffff", 16),
    3: int("0xffffff", 16),
    4: int("0xffffffff", 16),
    5: int("0xffffffffff", 16),
    6: int("0xffffffffffff", 16),
    7: int("0xffffffffffffff", 16),
    8: int("0xffffffffffffffff", 16),
    9: int("0xffffffffffffffffff", 16),
    10: int("0xffffffffffffffffffff", 16),
    11: int("0xffffffffffffffffffffff", 16),
    12: int("0xffffffffffffffffffffffff", 16),
    13: int("0xffffffffffffffffffffffffff", 16),
    14: int("0xffffffffffffffffffffffffffff", 16),
    15: int("0xffffffffffffffffffffffffffffff", 16),
    16: int("0xffffffffffffffffffffffffffffffff", 16),
    17: int("0xffffffffffffffffffffffffffffffffff", 16),
    18: int("0xffffffffffffffffffffffffffffffffffff", 16),
    19: int("0xffffffffffffffffffffffffffffffffffffff", 16),
    20: int("0xffffffffffffffffffffffffffffffffffffffff", 16),
    21: int("0xffffffffffffffffffffffffffffffffffffffffff", 16),
    22: int("0xffffffffffffffffffffffffffffffffffffffffffff", 16),
    23: int("0xffffffffffffffffffffffffffffffffffffffffffffff", 16),
    24: int("0xffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    25: int("0xffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    26: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    27: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    28: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    29: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    30: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    31: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    32: int("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
}

INT_MAX = {
    1: int("0x7f", 16),
    2: int("0x7fff", 16),
    3: int("0x7fffff", 16),
    4: int("0x7fffffff", 16),
    5: int("0x7fffffffff", 16),
    6: int("0x7fffffffffff", 16),
    7: int("0x7fffffffffffff", 16),
    8: int("0x7fffffffffffffff", 16),
    9: int("0x7fffffffffffffffff", 16),
    10: int("0x7fffffffffffffffffff", 16),
    11: int("0x7fffffffffffffffffffff", 16),
    12: int("0x7fffffffffffffffffffffff", 16),
    13: int("0x7fffffffffffffffffffffffff", 16),
    14: int("0x7fffffffffffffffffffffffffff", 16),
    15: int("0x7fffffffffffffffffffffffffffff", 16),
    16: int("0x7fffffffffffffffffffffffffffffff", 16),
    17: int("0x7fffffffffffffffffffffffffffffffff", 16),
    18: int("0x7fffffffffffffffffffffffffffffffffff", 16),
    19: int("0x7fffffffffffffffffffffffffffffffffffff", 16),
    20: int("0x7fffffffffffffffffffffffffffffffffffffff", 16),
    21: int("0x7fffffffffffffffffffffffffffffffffffffffff", 16),
    22: int("0x7fffffffffffffffffffffffffffffffffffffffffff", 16),
    23: int("0x7fffffffffffffffffffffffffffffffffffffffffffff", 16),
    24: int("0x7fffffffffffffffffffffffffffffffffffffffffffffff", 16),
    25: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    26: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    27: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    28: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    29: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    30: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    31: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
    32: int("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
}

INT_MIN = {
    1: int("-0x80", 16),
    2: int("-0x8000", 16),
    3: int("-0x800000", 16),
    4: int("-0x80000000", 16),
    5: int("-0x8000000000", 16),
    6: int("-0x800000000000", 16),
    7: int("-0x80000000000000", 16),
    8: int("-0x8000000000000000", 16),
    9: int("-0x800000000000000000", 16),
    10: int("-0x80000000000000000000", 16),
    11: int("-0x8000000000000000000000", 16),
    12: int("-0x800000000000000000000000", 16),
    13: int("-0x80000000000000000000000000", 16),
    14: int("-0x8000000000000000000000000000", 16),
    15: int("-0x800000000000000000000000000000", 16),
    16: int("-0x80000000000000000000000000000000", 16),
    17: int("-0x8000000000000000000000000000000000", 16),
    18: int("-0x800000000000000000000000000000000000", 16),
    19: int("-0x80000000000000000000000000000000000000", 16),
    20: int("-0x8000000000000000000000000000000000000000", 16),
    21: int("-0x800000000000000000000000000000000000000000", 16),
    22: int("-0x80000000000000000000000000000000000000000000", 16),
    23: int("-0x8000000000000000000000000000000000000000000000", 16),
    24: int("-0x800000000000000000000000000000000000000000000000", 16),
    25: int("-0x80000000000000000000000000000000000000000000000000", 16),
    26: int("-0x8000000000000000000000000000000000000000000000000000", 16),
    27: int("-0x800000000000000000000000000000000000000000000000000000", 16),
    28: int("-0x80000000000000000000000000000000000000000000000000000000", 16),
    29: int("-0x8000000000000000000000000000000000000000000000000000000000", 16),
    30: int("-0x800000000000000000000000000000000000000000000000000000000000", 16),
    31: int("-0x80000000000000000000000000000000000000000000000000000000000000", 16),
    32: int("-0x8000000000000000000000000000000000000000000000000000000000000000", 16)
}

MAX_RING_BUFFER_LENGTH = 10
MAX_ARRAY_LENGTH = 2

class CircularSet:
    def __init__(self, set_size=MAX_RING_BUFFER_LENGTH, initial_set=None):
        self._q = collections.deque(maxlen=set_size)
        if initial_set:
            self._q.extend(initial_set)

    @property
    def empty(self):
        return len(self._q) == 0

    def add(self, value):
        if value not in self._q:
            self._q.append(value)
        else:
            self._q.remove(value)
            self._q.append(value)

    def head_and_rotate(self):
        value = self._q[-1]
        self._q.rotate(1)
        return value

    def discard(self, value):
        if value in self._q:
            self._q.remove(value)

    def __repr__(self):
        return repr(self._q)


class Generator:
    def __init__(self, interface, bytecode, accounts, contract):
        self.logger = initialize_logger("Generator")
        self.interface = interface
        self.bytecode = bytecode
        self.accounts = accounts
        self.contract = contract

        # Pools
        self.function_circular_buffer = CircularSet(set_size=len(self.interface), initial_set=set(self.interface))
        self.accounts_pool = {}
        self.amounts_pool = {}
        self.arguments_pool = {}
        self.timestamp_pool = {}
        self.blocknumber_pool = {}
        self.balance_pool = {}
        self.callresult_pool = {}
        self.gaslimit_pool = {}
        self.extcodesize_pool = {}
        self.returndatasize_pool = {}
        self.argument_array_sizes_pool = {}
        self.strings_pool = CircularSet()
        self.bytes_pool = CircularSet()

        # Mock return values pool
        self.mock_return_values_pool = {}  # 存储从 JSON 加载的 mock 数据
        self.mock_scenarios = ["satisfy", "violate", "boundary"]  # 场景列表

        # Mock 返回值参数池（类似 arguments_pool）
        self.mock_return_values_argument_pool = {}
        # 结构：{function_sig: {ext_call_sig: {return_index: CircularSet([val1, val2, ...])}}}

    def get_random_argument_constructor(self,con_interface,deployement_bytecode,from_address,to_address):
        individual = []

        if  con_interface and deployement_bytecode:
            arguments = ["constructor"]
            for index in range(len(con_interface)):
                arguments.append(self.get_random_argument(con_interface[index], "constructor", index))
            individual.append({
                "account": from_address,
                "to": to_address,
                "account": self.get_random_account("constructor"),
                "contract": deployement_bytecode,
                "amount": self.get_random_amount("constructor"),
                "arguments": arguments,
                "blocknumber": self.get_random_blocknumber("constructor"),
                "timestamp": self.get_random_timestamp("constructor"),
                "gaslimit": self.get_random_gaslimit("constructor"),
                "returndatasize": dict()
            })
        return individual

    def generate_random_individual(self):
        individual = []

        if "constructor" in self.interface and self.bytecode:
            arguments = ["constructor"]
            for index in range(len(self.interface["constructor"])):
                arguments.append(self.get_random_argument(self.interface["constructor"][index], "constructor", index))
            individual.append({
                "account": self.get_random_account("constructor"),
                "contract": self.bytecode,
                "amount": self.get_random_amount("constructor"),
                "arguments": arguments,
                "blocknumber": self.get_random_blocknumber("constructor"),
                "timestamp": self.get_random_timestamp("constructor"),
                "gaslimit": self.get_random_gaslimit("constructor"),
                "returndatasize": dict()
            })

        function, argument_types = self.get_random_function_with_argument_types()
        arguments = [function]
        for index in range(len(argument_types)):
            arguments.append(self.get_random_argument(argument_types[index], function, index))
        individual.append({
            "account": self.get_random_account(function),
            "contract": self.contract,
            "amount": self.get_random_amount(function),
            "arguments": arguments,
            "blocknumber": self.get_random_blocknumber(function),
            "timestamp": self.get_random_timestamp(function),
            "gaslimit": self.get_random_gaslimit(function),
            "call_return": dict(),
            "extcodesize": dict(),
            "returndatasize": dict()
        })

        address, call_return_value = self.get_random_callresult_and_address(function)
        individual[-1]["call_return"] = {address: call_return_value}

        address, extcodesize_value = self.get_random_extcodesize_and_address(function)
        individual[-1]["extcodesize"] = {address: extcodesize_value}

        address, value = self.get_random_returndatasize_and_address(function)
        individual[-1]["returndatasize"] = {address: value}

        # 新增：添加 mock 返回值字段
        if settings.MOCK_RETURN_VALUES_ENABLE and function in self.mock_return_values_pool:
            individual[-1]["mock_call_returns"] = self._generate_mock_call_returns(function)

        return individual

    def generate_individual_By_Functionlist(self, function_list,funname2hash=None):
        individual = []


        if "constructor" in function_list and "constructor" in self.interface:
            arguments = ["constructor"]
            for index in range(len(self.interface["constructor"])):
                arguments.append(self.get_random_argument(self.interface["constructor"][index], "constructor", index))
            individual.append({
                "account": self.get_random_account("constructor"),
                "contract": self.bytecode,
                "amount": self.get_random_amount("constructor"),
                "arguments": arguments,
                "blocknumber": self.get_random_blocknumber("constructor"),
                "timestamp": self.get_random_timestamp("constructor"),
                "gaslimit": self.get_random_gaslimit("constructor"),
                "returndatasize": dict()
            })



        for fa in function_list:
            if funname2hash and  "constructor" not in funname2hash and fa == "constructor":
                continue
            
            if funname2hash:
                function = funname2hash[fa]
            else:
                function = fa
            argument_types = self.interface[function]
            arguments = [function]
            for index in range(len(argument_types)):
                arguments.append(self.get_random_argument(argument_types[index], function, index))
            address, call_return_value = self.get_random_callresult_and_address(function)
            cr = {address: call_return_value}

            address, extcodesize_value = self.get_random_extcodesize_and_address(function)
            es = {address: extcodesize_value}

            address, value = self.get_random_returndatasize_and_address(function)
            rds = {address: value}

            transaction = {
                "account": self.get_random_account(function),
                "contract": self.contract,
                "amount": self.get_random_amount(function),
                "arguments": arguments,
                "blocknumber": self.get_random_blocknumber(function),
                "timestamp": self.get_random_timestamp(function),
                "gaslimit": self.get_random_gaslimit(function),
                "call_return": cr,
                "extcodesize": es,
                "returndatasize": rds
            }

            # 新增：添加 mock 返回值字段
            if settings.MOCK_RETURN_VALUES_ENABLE and function in self.mock_return_values_pool:
                transaction["mock_call_returns"] = self._generate_mock_call_returns(function)

            individual.append(transaction)



        return individual
    
    def generate_individual_By_mutate_require_list(self, function_list):
        individual = []

        for fa in function_list:


            function = fa
            argument_types = self.interface[function]
            arguments = [function]
            for index in range(len(argument_types)):
                arguments.append(self.get_random_argument(argument_types[index], function, index))
            address, call_return_value = self.get_random_callresult_and_address(function)
            cr = {address: call_return_value}

            address, extcodesize_value = self.get_random_extcodesize_and_address(function)
            es = {address: extcodesize_value}

            address, value = self.get_random_returndatasize_and_address(function)
            rds = {address: value}

            transaction = {
                "account": self.get_random_account(function),
                "contract": self.contract,
                "amount": self.get_random_amount(function),
                "arguments": arguments,
                "blocknumber": self.get_random_blocknumber(function),
                "timestamp": self.get_random_timestamp(function),
                "gaslimit": self.get_random_gaslimit(function),
                "call_return": cr,
                "extcodesize": es,
                "returndatasize": rds
            }

            # 新增：添加 mock 返回值字段
            if settings.MOCK_RETURN_VALUES_ENABLE and function in self.mock_return_values_pool:
                transaction["mock_call_returns"] = self._generate_mock_call_returns(function)

            individual.append(transaction)



        return individual

    def generate_random_input(self):
        input = {}

        function, argument_types = self.get_random_function_with_argument_types()
        arguments = [function]
        for index in range(len(argument_types)):
            arguments.append(self.get_random_argument(argument_types[index], function, index))
        input = {
            "account": self.get_random_account(function),
            "contract": self.contract,
            "amount": self.get_random_amount(function),
            "arguments": arguments,
            "blocknumber": self.get_random_blocknumber(function),
            "timestamp": self.get_random_timestamp(function),
            "gaslimit": self.get_random_gaslimit(function),
            "returndatasize": dict()
        }

        address, value = self.get_random_returndatasize_and_address(function)
        input["returndatasize"] = {address: value}

        return input

    def get_random_function_with_argument_types(self):
        function_hash = self.function_circular_buffer.head_and_rotate()
        if function_hash == "constructor":
            function_hash = self.function_circular_buffer.head_and_rotate()
        return function_hash, self.interface[function_hash]

    #
    # TIMESTAMP
    #

    def add_timestamp_to_pool(self, function, timestamp):
        if not function in self.timestamp_pool:
            self.timestamp_pool[function] = CircularSet()
        self.timestamp_pool[function].add(timestamp)

    def get_random_timestamp(self, function):
        if function in self.timestamp_pool:
            return self.timestamp_pool[function].head_and_rotate()
        return None

    def remove_timestamp_from_pool(self, function, timestamp):
        if function in self.timestamp_pool:
            self.timestamp_pool[function].discard(timestamp)
            if self.timestamp_pool[function].empty:
                del self.timestamp_pool[function]

    #
    # BLOCKNUMBER
    #

    def add_blocknumber_to_pool(self, function, blocknumber):
        if not function in self.blocknumber_pool:
            self.blocknumber_pool[function] = CircularSet()
        self.blocknumber_pool[function].add(blocknumber)

    def get_random_blocknumber(self, function):
        if function in self.blocknumber_pool:
            return self.blocknumber_pool[function].head_and_rotate()
        return None

    def remove_blocknumber_from_pool(self, function, blocknumber):
        if function in self.blocknumber_pool:
            self.blocknumber_pool[function].discard(blocknumber)
            if self.blocknumber_pool[function].empty:
                del self.blocknumber_pool[function]

    #
    # BALANCE
    #

    def add_balance_to_pool(self, function, balance):
        if not function in self.balance_pool:
            self.balance_pool[function] = CircularSet()
        self.balance_pool[function].add(balance)

    def get_random_balance(self, function):
        if function in self.balance_pool:
            return self.balance_pool[function].head_and_rotate()
        return None

    #
    # CALL RESULT
    #

    def add_callresult_to_pool(self, function, address, result):
        if not function in self.callresult_pool:
            self.callresult_pool[function] = dict()
        if not address in self.callresult_pool[function]:
            self.callresult_pool[function][address] = CircularSet()
        self.callresult_pool[function][address].add(result)

    def get_random_callresult_and_address(self, function):
        if function in self.callresult_pool:
            address = random.choice(list(self.callresult_pool[function].keys()))
            value = self.callresult_pool[function][address].head_and_rotate()
            return address, value
        return None, None

    def get_random_callresult(self, function, address):
        if function in self.callresult_pool:
            if address in self.callresult_pool[function]:
                value = self.callresult_pool[function][address].head_and_rotate()
                return value
        return None

    def remove_callresult_from_pool(self, function, address, result):
        if function in self.callresult_pool and address in self.callresult_pool[function]:
            self.callresult_pool[function][address].discard(result)
            if self.callresult_pool[function][address].empty:
                del self.callresult_pool[function][address]
                if len(self.callresult_pool[function]) == 0:
                    del self.callresult_pool[function]

    #
    # EXTCODESIZE
    #

    def add_extcodesize_to_pool(self, function, address, size):
        if not function in self.extcodesize_pool:
            self.extcodesize_pool[function] = dict()
        if not address in self.extcodesize_pool[function]:
            self.extcodesize_pool[function][address] = CircularSet()
        self.extcodesize_pool[function][address].add(size)

    def get_random_extcodesize_and_address(self, function):
        if function in self.extcodesize_pool:
            address = random.choice(list(self.extcodesize_pool[function].keys()))
            return address, self.extcodesize_pool[function][address].head_and_rotate()
        return None, None

    def get_random_extcodesize(self, function, address):
        if function in self.extcodesize_pool:
            if address in self.extcodesize_pool[function]:
                return self.extcodesize_pool[function][address].head_and_rotate()
        return None

    def remove_extcodesize_from_pool(self, function, address, size):
        if function in self.extcodesize_pool and address in self.extcodesize_pool[function]:
            self.extcodesize_pool[function][address].discard(size)
            if self.extcodesize_pool[function][address].empty:
                del self.extcodesize_pool[function][address]
                if len(self.extcodesize_pool[function]) == 0:
                    del self.extcodesize_pool[function]

    #
    # RETURNDATASIZE
    #

    def add_returndatasize_to_pool(self, function, address, size):
        if not function in self.returndatasize_pool:
            self.returndatasize_pool[function] = dict()
        if not address in self.returndatasize_pool[function]:
            self.returndatasize_pool[function][address] = CircularSet()
        self.returndatasize_pool[function][address].add(size)

    def get_random_returndatasize_and_address(self, function):
        if function in self.returndatasize_pool:
            address = random.choice(list(self.returndatasize_pool[function].keys()))
            return address, self.returndatasize_pool[function][address].head_and_rotate()
        return None, None

    def get_random_returndatasize(self, function, address):
        if function in self.returndatasize_pool:
            if address in self.returndatasize_pool[function]:
                return self.returndatasize_pool[function][address].head_and_rotate()
        return None

    def remove_returndatasize_from_pool(self, function, address, size):
        if function in self.returndatasize_pool and address in self.returndatasize_pool[function]:
            self.returndatasize_pool[function][address].discard(size)
            if self.returndatasize_pool[function][address].empty:
                del self.returndatasize_pool[function][address]
                if len(self.returndatasize_pool[function]) == 0:
                    del self.returndatasize_pool[function]

    #
    # GASLIMIT
    #

    def add_gaslimit_to_pool(self, function, gaslimit):
        if not function in self.gaslimit_pool:
            self.gaslimit_pool[function] = CircularSet()
        self.gaslimit_pool[function].add(gaslimit)

    def remove_gaslimit_from_pool(self, function, gaslimit):
        if function in self.gaslimit_pool:
            self.gaslimit_pool[function].discard(gaslimit)
            if self.gaslimit_pool[function].empty:
                del self.gaslimit_pool[function]

    def clear_gaslimits_in_pool(self, function):
        if function in self.gaslimit_pool:
            del self.gaslimit_pool[function]

    def get_random_gaslimit(self, function):
        if function in self.gaslimit_pool:
            return self.gaslimit_pool[function].head_and_rotate()
        return settings.GAS_LIMIT

    #
    # ACCOUNTS
    #

    def add_account_to_pool(self, function, account):
        if not function in self.accounts_pool:
            self.accounts_pool[function] = CircularSet()
        self.accounts_pool[function].add(account)

    def remove_account_from_pool(self, function, account):
        if function in self.accounts_pool:
            self.accounts_pool[function].discard(account)
            if self.accounts_pool[function].empty:
                del self.accounts_pool[function]

    def clear_accounts_in_pool(self, function):
        if function in self.accounts_pool:
            self.accounts_pool[function] = CircularSet()

    def get_random_account_from_pool(self, function):
        return self.accounts_pool[function].head_and_rotate()

    def get_random_account(self, function):
        if function in self.accounts_pool:
            return self.get_random_account_from_pool(function)
        else:
            return random.choice(self.accounts)

    #
    # AMOUNTS
    #

    def add_amount_to_pool(self, function, amount):
        if not function in self.amounts_pool:
            self.amounts_pool[function] = CircularSet()
        self.amounts_pool[function].add(amount)

    def remove_amount_from_pool(self, function, amount):
        if function in self.amounts_pool:
            self.amounts_pool[function].discard(amount)
            if self.amounts_pool[function].empty:
                del self.amounts_pool[function]

    def get_random_amount_from_pool(self, function):
        return self.amounts_pool[function].head_and_rotate()

    def get_random_amount(self, function):
        if function in self.amounts_pool:
            amount = self.get_random_amount_from_pool(function)
        else:
            amount = random.randint(0, 1)
            self.add_amount_to_pool(function, amount)
            self.add_amount_to_pool(function, 1 - amount)
        return amount

    #
    # STRINGS
    #

    def add_string_to_pool(self, string):
        self.strings_pool.add(string)


    def get_random_string_from_pool(self):
        return self.strings_pool.head_and_rotate()

    #
    # BYTES
    #

    def add_bytes_to_pool(self, string):
        self.bytes_pool.add(string)


    def get_random_bytes_from_pool(self):
        return self.bytes_pool.head_and_rotate()

    #
    # FUNCTION ARGUMENTS
    #

    def add_parameter_array_size(self, function, parameter_index, array_size):
        if function not in self.argument_array_sizes_pool:
            self.argument_array_sizes_pool[function] = dict()
        if parameter_index not in self.argument_array_sizes_pool[function]:
            self.argument_array_sizes_pool[function][parameter_index] = CircularSet()
        self.argument_array_sizes_pool[function][parameter_index].add(min(array_size, MAX_ARRAY_LENGTH))

    def _get_parameter_array_size_from_pool(self, function, argument_index):
        return self.argument_array_sizes_pool[function][argument_index].head_and_rotate()

    def remove_parameter_array_size_from_pool(self, function, parameter_index, array_size):
        if function in self.argument_array_sizes_pool and parameter_index in self.argument_array_sizes_pool[function]:
            self.argument_array_sizes_pool[function][parameter_index].discard(array_size)
            if self.argument_array_sizes_pool[function][parameter_index].empty:
                del self.argument_array_sizes_pool[function][parameter_index]
                if len(self.argument_array_sizes_pool[function]) == 0:
                    del self.argument_array_sizes_pool[function]


    def add_argument_to_pool(self, function, argument_index, argument):
        if type(argument) is list:
            for element in argument:
                self.add_argument_to_pool(function, argument_index, element)
            return
        if function not in self.arguments_pool:
            self.arguments_pool[function] = {}
        if argument_index not in self.arguments_pool[function]:
            self.arguments_pool[function][argument_index] = CircularSet()
        self.arguments_pool[function][argument_index].add(argument)

    def remove_argument_from_pool(self, function, argument_index, argument):
        if type(argument) is list:
            for element in argument:
                self.remove_argument_from_pool(function, argument_index, element)
            return
        if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
            self.arguments_pool[function][argument_index].discard(argument)
            if self.arguments_pool[function][argument_index].empty:
                del self.arguments_pool[function][argument_index]
                if len(self.arguments_pool[function]) == 0:
                    del self.arguments_pool[function]

    def _get_random_argument_from_pool(self, function, argument_index):
        return self.arguments_pool[function][argument_index].head_and_rotate()

    def get_random_argument(self, type, function, argument_index):
        # Boolean
        if type.startswith("bool"):
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                        if self._get_random_argument_from_pool(function, argument_index) == 0:
                            array.append(False)
                        else:
                            array.append(True)
                    else:
                        if random.randint(0, 1) == 0:
                            array.append(False)
                        else:
                            array.append(True)
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    if self._get_random_argument_from_pool(function, argument_index) == 0:
                        return False
                    return True
                else:
                    if random.randint(0, 1) == 0:
                        return False
                    return True

        # Unsigned integer
        elif type.startswith("uint"):
            bytes = int(int(type.replace("uint", "").split("[")[0]) / 8)
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                        array.append(self._get_random_argument_from_pool(function, argument_index))
                    else:
                        array.append(self.get_random_unsigned_integer(0, UINT_MAX[bytes]))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    return self._get_random_argument_from_pool(function, argument_index)
                return self.get_random_unsigned_integer(0, UINT_MAX[bytes])

        # Signed integer
        elif type.startswith("int"):
            bytes = int(int(type.replace("int", "").split("[")[0]) / 8)
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                        array.append(self._get_random_argument_from_pool(function, argument_index))
                    else:
                        array.append(self.get_random_signed_integer(INT_MIN[bytes], INT_MAX[bytes]))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    return self._get_random_argument_from_pool(function, argument_index)
                return self.get_random_signed_integer(INT_MIN[bytes], INT_MAX[bytes])

        # Address
        elif type.startswith("address"):
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                        array.append(self._get_random_argument_from_pool(function, argument_index))
                    else:
                        array.append(random.choice(self.accounts))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    return self._get_random_argument_from_pool(function, argument_index)
                return random.choice(self.accounts)

        # String
        elif type.startswith("string"):
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    array.append(self.get_string(random.randint(0, MAX_ARRAY_LENGTH)))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    return self._get_random_argument_from_pool(function, argument_index)
                if self.strings_pool.empty:
                    self.add_string_to_pool(self.get_string(0))
                    self.add_string_to_pool(self.get_string(1))
                    self.add_string_to_pool(self.get_string(32))
                    self.add_string_to_pool(self.get_string(33))
                return self.get_random_string_from_pool()

        # Bytes1 ... Bytes32
        elif type.startswith("bytes1") or \
             type.startswith("bytes2") or \
             type.startswith("bytes3") or \
             type.startswith("bytes4") or \
             type.startswith("bytes5") or \
             type.startswith("bytes6") or \
             type.startswith("bytes7") or \
             type.startswith("bytes8") or \
             type.startswith("bytes9") or \
             type.startswith("bytes10") or \
             type.startswith("bytes11") or \
             type.startswith("bytes12") or \
             type.startswith("bytes13") or \
             type.startswith("bytes14") or \
             type.startswith("bytes15") or \
             type.startswith("bytes16") or \
             type.startswith("bytes17") or \
             type.startswith("bytes18") or \
             type.startswith("bytes19") or \
             type.startswith("bytes20") or \
             type.startswith("bytes21") or \
             type.startswith("bytes22") or \
             type.startswith("bytes23") or \
             type.startswith("bytes24") or \
             type.startswith("bytes25") or \
             type.startswith("bytes26") or \
             type.startswith("bytes27") or \
             type.startswith("bytes28") or \
             type.startswith("bytes29") or \
             type.startswith("bytes30") or \
             type.startswith("bytes31") or \
             type.startswith("bytes32"):
            length = int(type.replace("bytes", "").split("[")[0])
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                        bas = self._get_random_argument_from_pool(function, argument_index)
                        if bas==0:
                            bas = bas.to_bytes(length, 'big')
                        array.append(bas)
                        # array.append(self._get_random_argument_from_pool(function, argument_index))
                    else:
                        array.append(self.get_random_bytes(length))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    return self._get_random_argument_from_pool(function, argument_index)
                return self.get_random_bytes(random.randint(0, length))

        # Bytes
        elif type.startswith("bytes"):
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    array.append(self.get_random_bytes(random.randint(0, MAX_ARRAY_LENGTH)))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    return self._get_random_argument_from_pool(function, argument_index)
                if self.bytes_pool.empty:
                    self.add_bytes_to_pool(self.get_random_bytes(0))
                    self.add_bytes_to_pool(self.get_random_bytes(1))
                    self.add_bytes_to_pool(self.get_random_bytes(32))
                    self.add_bytes_to_pool(self.get_random_bytes(33))
                return self.get_random_bytes_from_pool()

        # Unknown type
        else:
            self.logger.error("Unsupported type: "+str(type))

    def get_mutate_argument(self, type, function, argument_index, ori_argument):
        # Boolean
        if type.startswith("bool"):
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    if random.randint(0, 1) == 0:
                        array.append(False)
                    else:
                        array.append(True)
                return array
            # Single value
            else:
                return ori_argument == False

        # Unsigned integer
        elif type.startswith("uint"):
            bytes = int(int(type.replace("uint", "").split("[")[0]) / 8)
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                
                    array.append(self.get_random_unsigned_integer(0, UINT_MAX[bytes]))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                return self.get_random_unsigned_integer(0, UINT_MAX[bytes])

        # Signed integer
        elif type.startswith("int"):
            bytes = int(int(type.replace("int", "").split("[")[0]) / 8)
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    array.append(self.get_random_signed_integer(INT_MIN[bytes], INT_MAX[bytes]))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                return self.get_random_signed_integer(INT_MIN[bytes], INT_MAX[bytes])

        # Address
        elif type.startswith("address"):
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                        array.append(self._get_random_argument_from_pool(function, argument_index))
                    else:
                        array.append(random.choice(self.accounts))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if function in self.arguments_pool and argument_index in self.arguments_pool[function]:
                    return self._get_random_argument_from_pool(function, argument_index)
                return random.choice(self.accounts)

        # String
        elif type.startswith("string"):
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    array.append(self.get_string(random.randint(0, MAX_ARRAY_LENGTH)))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if self.strings_pool.empty:
                    self.add_string_to_pool(self.get_string(0))
                    self.add_string_to_pool(self.get_string(1))
                    self.add_string_to_pool(self.get_string(32))
                    self.add_string_to_pool(self.get_string(33))
                return self.get_random_string_from_pool()

        # Bytes1 ... Bytes32
        elif type.startswith("bytes1") or \
             type.startswith("bytes2") or \
             type.startswith("bytes3") or \
             type.startswith("bytes4") or \
             type.startswith("bytes5") or \
             type.startswith("bytes6") or \
             type.startswith("bytes7") or \
             type.startswith("bytes8") or \
             type.startswith("bytes9") or \
             type.startswith("bytes10") or \
             type.startswith("bytes11") or \
             type.startswith("bytes12") or \
             type.startswith("bytes13") or \
             type.startswith("bytes14") or \
             type.startswith("bytes15") or \
             type.startswith("bytes16") or \
             type.startswith("bytes17") or \
             type.startswith("bytes18") or \
             type.startswith("bytes19") or \
             type.startswith("bytes20") or \
             type.startswith("bytes21") or \
             type.startswith("bytes22") or \
             type.startswith("bytes23") or \
             type.startswith("bytes24") or \
             type.startswith("bytes25") or \
             type.startswith("bytes26") or \
             type.startswith("bytes27") or \
             type.startswith("bytes28") or \
             type.startswith("bytes29") or \
             type.startswith("bytes30") or \
             type.startswith("bytes31") or \
             type.startswith("bytes32"):
            length = int(type.replace("bytes", "").split("[")[0])
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    array.append(self.get_random_bytes(length))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                return self.get_random_bytes(random.randint(0, length))

        # Bytes
        elif type.startswith("bytes"):
            # Array
            if "[" in type and "]" in type:
                sizes = self._get_array_sizes(argument_index, function, type)
                array = []
                for _ in range(sizes[0]):
                    array.append(self.get_random_bytes(random.randint(0, MAX_ARRAY_LENGTH)))
                if len(sizes) > 1:
                    new_array = []
                    for _ in range(sizes[1]):
                        new_array.append(array)
                    array = new_array
                return array
            # Single value
            else:
                if self.bytes_pool.empty:
                    self.add_bytes_to_pool(self.get_random_bytes(0))
                    self.add_bytes_to_pool(self.get_random_bytes(1))
                    self.add_bytes_to_pool(self.get_random_bytes(32))
                    self.add_bytes_to_pool(self.get_random_bytes(33))
                return self.get_random_bytes_from_pool()

        # Unknown type
        else:
            self.logger.error("Unsupported type: "+str(type))




    def _get_array_sizes(self, argument_index, function, type):
        sizes = []
        for size in re.compile(r"\[(.*?)\]").findall(type):
            # Dynamic array
            if size == "":
                if function in self.argument_array_sizes_pool \
                        and argument_index in self.argument_array_sizes_pool[function]:
                    sizes.append(self._get_parameter_array_size_from_pool(function, argument_index))
                else:
                    sizes.append(random.randint(0, MAX_ARRAY_LENGTH))
            # Fixed size array
            else:
                sizes.append(int(size))
        return sizes

    @staticmethod
    def get_random_unsigned_integer(min, max):
        seed = int(random.uniform(-2, 2))
        if seed == -1:
            return random.choice([min, min + 1, min + 2])
        elif seed == 1:
            return random.choice([max, max - 1, max - 2])
        else:
            return random.randint(min, max)
        
    @staticmethod
    def get_random_unsigned_integer_walk(min, max,ori_value):
        walk_size = random.random(-1, 1)
        return ori_value *(1 + walk_size)

    @staticmethod
    def get_random_signed_integer(min, max):
        seed = int(random.uniform(-2, 2))
        if seed == -1:
            return random.choice([0, -1, min, min + 1])
        elif seed == 1:
            return random.choice([0, 1, max, max - 1])
        else:
            return random.randint(min, max)

    @staticmethod
    def get_string(length):
        return ''.join('A' for _ in range(length))

    @staticmethod
    def get_random_bytes(length):
        return bytearray(random.getrandbits(8) for _ in range(length))

    #
    # MOCK RETURN VALUES
    #

    def load_mock_return_values_new_call(self, target_function_sig, ext_call_sig):
        """
        当发现新的调用关系时，从其他函数复制该外部调用的历史数据

        Args:
            target_function_sig: 目标函数签名
            ext_call_sig: 外部调用函数签名
        """
        # 检查是否已经存在该外部调用的数据
        has_in_argument_pool = (target_function_sig in self.mock_return_values_argument_pool and
                                ext_call_sig in self.mock_return_values_argument_pool[target_function_sig])
        has_in_values_pool = (target_function_sig in self.mock_return_values_pool and
                              ext_call_sig in self.mock_return_values_pool[target_function_sig])

        if has_in_argument_pool and has_in_values_pool:
            return  # 两个池都已有数据，无需加载

        # 查找其他函数中是否有该外部调用的数据
        found_argument_pool = False
        found_values_pool = False

        # 1. 从 mock_return_values_argument_pool 中查找并复制
        if not has_in_argument_pool:
            for function_sig, ext_calls_dict in self.mock_return_values_argument_pool.items():
                if ext_call_sig in ext_calls_dict:
                    # 确保 target_function_sig 存在
                    if target_function_sig not in self.mock_return_values_argument_pool:
                        self.mock_return_values_argument_pool[target_function_sig] = {}

                    # 深拷贝整个 ext_call_sig 的数据（包括所有 return_index）
                    self.mock_return_values_argument_pool[target_function_sig][ext_call_sig] = {}

                    for return_index, value_set in ext_calls_dict[ext_call_sig].items():
                        new_set = value_set
                        
                        self.mock_return_values_argument_pool[target_function_sig][ext_call_sig][return_index] = new_set

                    found_argument_pool = True
                    break

        # 2. 从 mock_return_values_pool 中查找并复制
        if not has_in_values_pool:
            for function_sig, ext_calls_dict in self.mock_return_values_pool.items():
                if ext_call_sig in ext_calls_dict:
                    # 确保 target_function_sig 存在
                    if target_function_sig not in self.mock_return_values_pool:
                        self.mock_return_values_pool[target_function_sig] = {}

                    # 深拷贝该外部调用的完整配置
                    import copy
                    self.mock_return_values_pool[target_function_sig][ext_call_sig] = copy.deepcopy(ext_calls_dict[ext_call_sig])

                    found_values_pool = True
                    break

    def load_mock_return_values(self, mock_data, target_function_sig):
        """
        加载 mock 返回值数据到池中

        Args:
            mock_data: 从 JSON 加载的完整 mock 数据
            target_function_sig: 目标函数签名（用于匹配）
        """
        if not mock_data or "mock_return_values" not in mock_data:
            return

        mrv = mock_data["mock_return_values"]

        # 检查是否有该函数的 mock 数据
        if target_function_sig not in mrv:
            return

        # 存储该函数的所有外部调用 mock 数据
        self.mock_return_values_pool[target_function_sig] = mrv[target_function_sig]

        # 新增：将所有场景值加载到 pool
        for ext_call_sig, call_config in mrv[target_function_sig].items():
            self._load_mock_values_to_pool(target_function_sig, ext_call_sig, call_config)

    def _load_mock_values_to_pool(self, function_sig, ext_call_sig, call_config):
        """
        将 mock 配置中的所有场景值加载到参数池中

        Args:
            function_sig: 目标函数签名
            ext_call_sig: 外部调用函数签名
            call_config: mock 配置对象
        """
        if function_sig not in self.mock_return_values_argument_pool:
            self.mock_return_values_argument_pool[function_sig] = {}

        if ext_call_sig not in self.mock_return_values_argument_pool[function_sig]:
            self.mock_return_values_argument_pool[function_sig][ext_call_sig] = {}

        return_types = call_config.get("return_types", [])
        mock_values_dict = call_config.get("mock_values", {})

        # 遍历所有场景的所有值
        for scenario, values_list_list in mock_values_dict.items():
            if scenario not in ["satisfy", "violate", "boundary"]:
                continue
            for values_list in values_list_list:
                # 为每个返回值位置创建/填充 pool
                for i, val in enumerate(values_list):
                    if i not in self.mock_return_values_argument_pool[function_sig][ext_call_sig]:
                        self.mock_return_values_argument_pool[function_sig][ext_call_sig][i] = CircularSet()

                    # 添加到 pool（CircularSet 会自动去重）
                    self.mock_return_values_argument_pool[function_sig][ext_call_sig][i].add(val)

    def _get_mock_argument_from_pool(self, function_sig, ext_call_sig, return_index):
        """
        从 pool 中获取指定位置的返回值（轮转机制）

        Args:
            function_sig: 目标函数签名
            ext_call_sig: 外部调用函数签名
            return_index: 返回值索引（0-based）

        Returns:
            返回值，如果 pool 为空则返回 None
        """
        if function_sig in self.mock_return_values_argument_pool and \
           ext_call_sig in self.mock_return_values_argument_pool[function_sig] and \
           return_index in self.mock_return_values_argument_pool[function_sig][ext_call_sig]:
            return self.mock_return_values_argument_pool[function_sig][ext_call_sig][return_index].head_and_rotate()
        return None

    def add_mock_argument_to_pool(self, function_sig, ext_call_sig, return_index, value):
        """
        将运行时观察到的返回值添加到 pool 中
        （从 execution_trace_analysis 调用）

        Args:
            function_sig: 目标函数签名
            ext_call_sig: 外部调用函数签名
            return_index: 返回值索引（0-based）
            value: 观察到的返回值
        """
        if function_sig not in self.mock_return_values_argument_pool:
            self.mock_return_values_argument_pool[function_sig] = {}

        if ext_call_sig not in self.mock_return_values_argument_pool[function_sig]:
            self.mock_return_values_argument_pool[function_sig][ext_call_sig] = {}

        if return_index not in self.mock_return_values_argument_pool[function_sig][ext_call_sig]:
            self.mock_return_values_argument_pool[function_sig][ext_call_sig][return_index] = CircularSet()

        self.mock_return_values_argument_pool[function_sig][ext_call_sig][return_index].add(value)

    def _generate_mock_call_returns(self, function_sig):
        """
        为指定函数生成 mock 返回值配置

        Args:
            function_sig: 函数签名（如 "0x70a08231"）

        Returns:
            dict: mock_call_returns 字典
        """
        

        mock_call_returns = {}

        # 获取该函数的所有外部调用配置
        external_calls = self.mock_return_values_pool.get(function_sig, {})

        # 限制每个交易最多 10 个 mock 调用（风险缓解措施）
        external_call_items = list(external_calls.items())
        if len(external_call_items) > 10:
            external_call_items = random.sample(external_call_items, 10)

        for ext_call_sig, call_config in external_call_items:
            # 随机选择一个场景
            scenario = random.choice(self.mock_scenarios)

            # 从该场景中随机选择一组值
            mock_values_dict = call_config.get("mock_values", {})
            if scenario not in mock_values_dict or not mock_values_dict[scenario]:
                continue

            # 随机选择该场景下的一组值
            values_list = random.choice(mock_values_dict[scenario])

            # 获取返回值类型
            return_types = call_config.get("return_types", [])

            # 编码返回值
            try:
                encoded = encode_return_values_to_bytes(values_list)

                mock_call_returns[ext_call_sig] = {
                    "values": values_list,
                    "types": return_types,
                    "encoded": encoded,
                    "scenario": scenario
                }
            except Exception as e:
                # 如果编码失败，跳过该 mock 配置
                self.logger.warning(f"Failed to encode mock return values for {ext_call_sig}: {e}")
                continue

        return mock_call_returns

    def get_mock_values_for_call(self, target_function_sig, ext_call_sig):
        """
        从 mock 池中查询指定外部调用签名的 mock 值配置

        Args:
            ext_call_sig: 被调用函数的签名（如 "0xa9059cbb"）
            target_function_sig: 目标函数签名（可选，如果提供则优先从该函数上下文查找）

        Returns:
            dict or None: 如果找到，返回包含以下字段的字典（与 mutation.py 格式一致）：
                {
                    "values": [...],      # 返回值列表
                    "types": [...],       # 类型列表
                    "encoded": bytes,     # 编码后的字节
                    "scenario": "satisfy" # 场景名称
                }
                如果未找到，返回 None
        """
        # 策略1：如果提供了目标函数，优先从目标函数的池中查找
        if target_function_sig:
            # 1.1 先从 mock_return_values_pool 查找（静态配置）
            if target_function_sig in self.mock_return_values_pool:
                if ext_call_sig in self.mock_return_values_pool[target_function_sig]:
                    result = self._get_mock_config_from_pool(
                        self.mock_return_values_pool[target_function_sig][ext_call_sig],
                        ext_call_sig
                    )
                    if result:
                        return result

            # 1.2 再从 mock_return_values_argument_pool 查找（运行时观察值）
            if target_function_sig in self.mock_return_values_argument_pool:
                if ext_call_sig in self.mock_return_values_argument_pool[target_function_sig]:
                    result = self._get_mock_config_from_argument_pool(
                        self.mock_return_values_argument_pool[target_function_sig][ext_call_sig],
                        ext_call_sig,
                        target_function_sig
                    )
                    if result:
                        return result

        # 策略2：从其他函数的池中查找（适用于未指定目标函数或目标函数中没有数据的情况）
        # 2.1 先尝试从 mock_return_values_pool 查找
        for function_sig, external_calls in self.mock_return_values_pool.items():
            if function_sig == target_function_sig:
                continue  # 已经查找过，跳过
            if ext_call_sig in external_calls:
                result = self._get_mock_config_from_pool(external_calls[ext_call_sig], ext_call_sig)
                if result:
                    return result

        # 2.2 最后尝试从 mock_return_values_argument_pool 查找
        for function_sig, ext_calls_dict in self.mock_return_values_argument_pool.items():
            if function_sig == target_function_sig:
                continue  # 已经查找过，跳过
            if ext_call_sig in ext_calls_dict:
                result = self._get_mock_config_from_argument_pool(
                    ext_calls_dict[ext_call_sig],
                    ext_call_sig,
                    function_sig
                )
                if result:
                    return result

        # 没有找到该外部调用签名
        return None

    def _get_mock_config_from_pool(self, call_config, ext_call_sig):
        """
        从 mock 配置中提取返回值配置（与 mutation.py 格式一致）

        Args:
            call_config: mock 配置对象（包含 mock_values 和 return_types）
            ext_call_sig: 外部调用签名（用于日志）

        Returns:
            dict or None: 返回完整的 mock 配置字典，包含 values, types, encoded, scenario；
                         如果没有可用值则返回 None
        """
        # 随机选择一个场景
        scenario = random.choice(self.mock_scenarios)

        # 获取该场景的 mock 值
        mock_values_dict = call_config.get("mock_values", {})
        if scenario not in mock_values_dict or not mock_values_dict[scenario]:
            # 如果该场景没有值，尝试其他场景
            for alt_scenario in self.mock_scenarios:
                if alt_scenario in mock_values_dict and mock_values_dict[alt_scenario]:
                    scenario = alt_scenario
                    break
            else:
                # 所有场景都没有值
                return None

        # 随机选择该场景下的一组值
        values = random.choice(mock_values_dict[scenario])

        # 获取返回值类型
        types = call_config.get("return_types", [])

        # 编码返回值
        try:
            encoded = encode_return_values_to_bytes(values)

            return {
                "values": values,
                "types": types,
                "encoded": encoded,
                "scenario": scenario
            }
        except Exception as e:
            # 编码失败
            self.logger.warning(f"Failed to encode mock return values for {ext_call_sig}: {e}")
            return None

    def _get_mock_config_from_argument_pool(self, return_indices_dict, ext_call_sig, function_sig):
        """
        从运行时参数池中构造返回值配置（与 mutation.py 格式一致）

        Args:
            return_indices_dict: 按 return_index 组织的 CircularSet 字典
            ext_call_sig: 外部调用签名
            function_sig: 函数签名（用于查找对应的 types）

        Returns:
            dict or None: 返回完整的 mock 配置字典，包含 values, types, encoded, scenario；
                         如果没有可用值则返回 None
        """
        if not return_indices_dict:
            return None

        # 按索引顺序构造返回值列表
        max_index = max(return_indices_dict.keys())
        values = []

        for i in range(max_index + 1):
            if i in return_indices_dict:
                value_set = return_indices_dict[i]
                if value_set:
                    # 从 CircularSet 中获取一个值
                    values.append(value_set.head_and_rotate())
                else:
                    # 该位置没有观察到的值，使用默认值
                    values.append(0)
            else:
                # 该位置没有数据，使用默认值
                values.append(0)

        if not values:
            return None

        # 尝试从 mock_return_values_pool 中获取 types 信息
        types = []
        if function_sig in self.mock_return_values_pool:
            if ext_call_sig in self.mock_return_values_pool[function_sig]:
                types = self.mock_return_values_pool[function_sig][ext_call_sig].get("return_types", [])

        # 如果没有找到 types，根据 values 的数量生成默认类型（uint256）
        if not types:
            types = ["uint256"] * len(values)

        # 编码返回值
        try:
            encoded = encode_return_values_to_bytes(values)

            return {
                "values": values,
                "types": types,
                "encoded": encoded,
                "scenario": "runtime"  # 标记为运行时观察值
            }
        except Exception as e:
            # 编码失败
            self.logger.warning(f"Failed to encode mock return values from argument pool for {ext_call_sig}: {e}")
            return None
        