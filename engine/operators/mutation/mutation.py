#!/usr/bin/env python3
# -*- coding: utf-8 -*-

''' Mutation implementation. '''

import random
import math
import numpy as np

from utils import settings
from ...plugin_interfaces.operators.mutation import Mutation
from ...components.individual import Individual
from evm.storage_emulation import encode_return_values_to_bytes

class Mutation(Mutation):
    def __init__(self, pm):
        '''
        :param pm: The probability of mutation (usually between 0.001 ~ 0.1)
        :type pm: float in (0.0, 1.0]
        '''
        if pm <= 0.0 or pm > 1.0:
            raise ValueError('Invalid mutation probability')

        self.pm = pm
        self.m_num = settings.MUTATION_NUM
        self.pm_line = settings.PM_LINE
        self.pr_mutate_seq = settings.PR_MUTATE_SEQ
        self.snapshot_energy = 0.5
        self.environment_energy = 0.5
    
    def addenv_info(self,env):
        self.env = env
        return self

    def cal_pm(self, function_hash,i):
        # return self.pm
        if function_hash not in self.env.tx2influ or self.env.tx2influ[function_hash] ==None:
            return self.pm
        if len(self.env.code_coverage) == self.env.previous_code_coverage_length:
            # pm=self.env.tx2influ[function_hash][i]
            # if pm > self.pm_line:
            #     return 1
            # return pm
            return 1
        else:
            pm=self.env.tx2influ[function_hash][i]
            if pm > self.pm_line:
                return 1
            return pm

    def mutate(self, individual, res):
        for gene in individual.chromosome:
            # TRANSACTION
            function_hash = gene["arguments"][0]
            for element in gene:
                if element == "account" and random.random() <= self.pm:
                    gene["account"] = individual.generator.get_random_account(function_hash)
                elif element == "amount" and random.random() <= self.pm:
                # elif element == "amount" and random.random() <= self.cal_pm(function_hash,0):
                    gene["amount"] = individual.generator.get_random_amount(function_hash)
                elif element == "gaslimit" and random.random() <= self.pm:
                    gene["gaslimit"] = individual.generator.get_random_gaslimit(function_hash)
                else:
                    for argument_index in range(1, len(gene["arguments"])):
                        # if random.random() > self.cal_pm(function_hash,argument_index):
                        if random.random() > self.pm:
                            continue
                        argument_type = individual.generator.interface[function_hash][argument_index - 1]
                        argument = individual.generator.get_random_argument(argument_type,
                                                                            function_hash,
                                                                            argument_index - 1)
                        gene["arguments"][argument_index] = argument

            # BLOCK
            if "timestamp" in gene:
                if random.random() <= self.pm:
                    gene["timestamp"] = individual.generator.get_random_timestamp(function_hash)
            else:
                gene["timestamp"] = individual.generator.get_random_timestamp(function_hash)

            if "blocknumber" in gene:
                if random.random() <= self.pm:
                    gene["blocknumber"] = individual.generator.get_random_blocknumber(function_hash)
            else:
                gene["blocknumber"] = individual.generator.get_random_blocknumber(function_hash)

            # GLOBAL STATE
            if "balance" in gene:
                if random.random() <= self.pm:
                    gene["balance"] = individual.generator.get_random_balance(function_hash)
            else:
                gene["balance"] = individual.generator.get_random_balance(function_hash)

            if "call_return" in gene:
                for address in gene["call_return"]:
                    if random.random() <= self.pm:
                        gene["call_return"][address] = individual.generator.get_random_callresult(function_hash, address)
            else:
                gene["call_return"] = dict()
                address, call_return_value = individual.generator.get_random_callresult_and_address(function_hash)
                if address and address not in gene["call_return"]:
                    gene["call_return"][address] = call_return_value

            if "extcodesize" in gene:
                for address in gene["extcodesize"]:
                    if random.random() <= self.pm:
                        gene["extcodesize"][address] = individual.generator.get_random_extcodesize(function_hash, address)
            else:
                gene["extcodesize"] = dict()
                address, extcodesize_value = individual.generator.get_random_extcodesize_and_address(function_hash)
                if address and address not in gene["extcodesize"]:
                    gene["extcodesize"][address] = extcodesize_value

            if "returndatasize" in gene:
                for address in gene["returndatasize"]:
                    if random.random() <= self.pm:
                        gene["returndatasize"][address] = individual.generator.get_random_returndatasize(function_hash, address)
            else:
                gene["returndatasize"] = dict()
                address, returndatasize_value = individual.generator.get_random_returndatasize_and_address(function_hash)
                if address and address not in gene["returndatasize"]:
                    gene["returndatasize"][address] = returndatasize_value

            # 新增：变异 mock_call_returns
            if settings.MOCK_RETURN_VALUES_ENABLE and "mock_call_returns" in gene and gene["mock_call_returns"] and random.random() <= self.environment_energy:
                gene["mock_call_returns"] = self._mutate_mock_call_returns(
                    gene["mock_call_returns"],
                    function_hash,
                    individual.generator
                )

        if settings.MUTATE_SNAPSHOT_ENABLE and len(self.env.code_coverage) == self.env.previous_code_coverage_length and random.random() > self.snapshot_energy:
            state_names = list(self.env.key_var.keys())
            if len(state_names) > 0:
                state_name, state_value = self.env.select_maxweight_snapshot()
                if state_name:
                    # print(state_name,state_value)
                    individual.set_snapshot_key([state_name,[state_value]])
        individual.solution = individual.decode()
        return individual
    
    def mutate_require(self, individual:Individual, mutate_require_list):
        new_indvs = []
        for i in range(len(mutate_require_list)):
            for ii in range(mutate_require_list[i][1]*2):
                new_indv = individual.clone()
                m_ind = Individual(generator=individual.generator).init(individual.generator.generate_individual_By_mutate_require_list(mutate_require_list[i][2]))
                new_indv.chromosome = new_indv.chromosome[:mutate_require_list[i][0]+1] + self.mutate(m_ind,None).chromosome
                new_indv.update_solution()
                new_indvs.append(new_indv)
        
        return new_indvs
    
    def mutate_require_by_snapshot(self, individual:Individual, mutate_require_list):
        new_indvs = []
        for i in range(len(mutate_require_list)):
            for ii in range(mutate_require_list[i][1]*2):
                m_ind = Individual(generator=individual.generator).init(individual.generator.generate_individual_By_mutate_require_list(mutate_require_list[i][2]),mutate_require_list[i][3])
                # m_ind = self.mutate(m_ind,None)
                m_ind.update_solution()
                new_indvs.append(m_ind)
        
        return new_indvs

    def mutate_fun(self, gene, generator):
        
    
        # TRANSACTION
        function_hash = gene["arguments"][0]
        for element in gene:
            if element == "account" and random.random() <= self.pm:
                gene["account"] = generator.get_random_account(function_hash)
            # elif element == "amount" and random.random() <= 1:
            elif element == "amount" and random.random() <= self.cal_pm(function_hash,0):
            # elif element == "amount" and random.random() <= self.pm:
                gene["amount"] = generator.get_random_amount(function_hash)
            elif element == "gaslimit" and random.random() <= self.pm:
                gene["gaslimit"] = generator.get_random_gaslimit(function_hash)
            else:
                for argument_index in range(1, len(gene["arguments"])):
                    if random.random() > self.cal_pm(function_hash,argument_index):
                    # if random.random() > 1:
                        continue
                    argument_type = generator.interface[function_hash][argument_index - 1]
                    argument = generator.get_random_argument(argument_type,
                                                                        function_hash,
                                                                        argument_index - 1)
                    # argument = generator.get_mutate_argument(argument_type,
                    #                                                     function_hash,
                    #                                                     argument_index - 1, gene["arguments"][argument_index])
                    gene["arguments"][argument_index] = argument

        # BLOCK
        if "timestamp" in gene:
            if random.random() <= self.pm:
                gene["timestamp"] = generator.get_random_timestamp(function_hash)
        else:
            gene["timestamp"] = generator.get_random_timestamp(function_hash)

        if "blocknumber" in gene:
            if random.random() <= self.pm:
                gene["blocknumber"] = generator.get_random_blocknumber(function_hash)
        else:
            gene["blocknumber"] = generator.get_random_blocknumber(function_hash)

        # GLOBAL STATE
        if "balance" in gene:
            if random.random() <= self.pm:
                gene["balance"] = generator.get_random_balance(function_hash)
        else:
            gene["balance"] = generator.get_random_balance(function_hash)

        if "call_return" in gene:
            for address in gene["call_return"]:
                if random.random() <= self.pm:
                    gene["call_return"][address] = generator.get_random_callresult(function_hash, address)
        else:
            gene["call_return"] = dict()
            address, call_return_value = generator.get_random_callresult_and_address(function_hash)
            if address and address not in gene["call_return"]:
                gene["call_return"][address] = call_return_value

        if "extcodesize" in gene:
            for address in gene["extcodesize"]:
                if random.random() <= self.pm:
                    gene["extcodesize"][address] = generator.get_random_extcodesize(function_hash, address)
        else:
            gene["extcodesize"] = dict()
            address, extcodesize_value = generator.get_random_extcodesize_and_address(function_hash)
            if address and address not in gene["extcodesize"]:
                gene["extcodesize"][address] = extcodesize_value

        if "returndatasize" in gene:
            for address in gene["returndatasize"]:
                if random.random() <= self.pm:
                    gene["returndatasize"][address] = generator.get_random_returndatasize(function_hash, address)
        else:
            gene["returndatasize"] = dict()
            address, returndatasize_value = generator.get_random_returndatasize_and_address(function_hash)
            if address and address not in gene["returndatasize"]:
                gene["returndatasize"][address] = returndatasize_value

        return gene

    def mutate_fundis(self, individual, res, off_mutate_history=False, energy=None):
        if off_mutate_history:
            one = individual.clone()
            two = individual.clone()
            result = []
            pm_back = self.pm
            if energy:
                self.pm = energy[1]
                # DEPRECATED: Snapshot energy disabled (energy vector is now 3-element)
                # self.snapshot_energy = max(energy[3], self.snapshot_energy)
                self.environment_energy = max(energy[3], self.environment_energy)

            one = self.mutate(one, res)
            if energy:
                if random.random() <= energy[0]:
                    one = self.mutate_seq(one)
            one.update_solution()
                
            # two = self.mutate(two, res)
            # if energy:
            #     if random.random() <= energy[0]:
            #         two = self.mutate_seq(two)
            # two.update_solution()

            one.res_ind = None
            # two.res_ind = None
            result.append(one)
            # result.append(two)

            # if energy and random.random() < energy[2]:
            #     append_nums = min(math.floor(energy[2]*6),3)
            #     for i in range(append_nums): 
            #         tmp = individual.clone()
            #         tmp = self.mutate(tmp, res)
            #         if energy:
            #             if random.random() <= energy[0]:
            #                 tmp = self.mutate_seq(tmp)
                    
            #         tmp.update_solution()
            #         result.append(tmp)
            #         tmp = None
            self.pm = pm_back
            
            self.environment_energy = 0.2
            return result
        
        m_fun_list = self.cal_mutate_schedule_by_vul_w(res)

        newinds = [individual.clone() for i in range(len(m_fun_list))]
        for i in range(len(newinds)):
            newinds[i].chromosome[m_fun_list[i]] = self.mutate_fun(individual.chromosome[m_fun_list[i]], individual.generator)
            newinds[i] = self.mutate_seq(newinds[i])
            newinds[i].update_solution()

        return newinds
    
    def add_tx(self,txlist):
        marklist = []
        add_tx = []
        for gene in txlist:
            writes = self.extract_reads_and_writes(gene["arguments"][0])
            for write in writes:
                if write not in marklist:
                    add_tx.append(write)
                    # if len(txlist) >= settings.MAX_INDIVIDUAL_LENGTH: 
                    #     if random.random()<0.5:
                    #         marklist.append(self.env.example_tx[write]["write"])
                    # else:
                    #     marklist.append(self.env.example_tx[write]["write"])
                    marklist.append(self.env.example_tx[write]["write"])
            marklist.append(gene)

        return marklist



    def extract_reads_and_writes(self,_function_hash):
        if _function_hash not in self.env.data_dependencies:
            return set()
        reads = self.env.data_dependencies[_function_hash]["read"]
        writes = set()
        for read in reads:
            writes.update(self.env.dep_data['s'+ str(read)]["write"])
        return writes

    def mutate_seq(self, individual):
        txlist = individual.chromosome
        if len(txlist) > len(self.env.funname2hash)*2/3:
            return individual
        # tx = self.add_tx(txlist)
        individual.chromosome= self.add_tx(txlist)
        # individual.update_solution()
        return individual

    def cal_mutate_schedule(self,res):
        m_size = 0
        size = 0
        m_fun_list = []
        #统计有变异的函数
        for i,v in enumerate(res["fun_flag"]):
            if v != 0:
                m_size += 1
                m_fun_list.append(i)
        
        #计算构建变异个体的数量以及设计到的变异函数个数
        if m_size <= self.m_num:
            size = m_size
        else:
            # size = max(self.m_num, math.ceil(math.log2(m_size)+2))
            size = max(self.m_num, m_size)

        if len(res["cri_opc"])>0:
            size = size*2

        # schedule =[[] for i in range(math.pow(2,size))]
        m_fun_list = self.get_sorted_indices(res["fun_dis"], m_fun_list, size)
        return m_fun_list
    
    def cal_mutate_schedule_by_vul_w(self,res):
        # 获取值小于0.995的索引
        m_fun_list = [i for i,v in enumerate(res["vul_w"]) if v < 0.995]
        
        # 如果数量大于5,取最小的5个值的索引
        if len(m_fun_list) > 2:
            # 根据vul_w值对索引进行排序
            m_fun_list = sorted(m_fun_list, key=lambda x: res["vul_w"][x])[:5]

        return m_fun_list

    def _mutate_mock_call_returns(self, mock_call_returns, function_sig, generator):
        """
        变异 mock_call_returns 字段

        三级策略（按优先级）：
        1. 20% - 场景切换：从 JSON 配置中选择其他场景的值
        2. 40% - Pool 选择：从参数池中选择已知有效值（包括运行时收集的）
        3. 40% - 边界生成：使用 generator 的边界值策略生成新值

        Args:
            mock_call_returns: 当前的 mock_call_returns 字典
            function_sig: 函数签名
            generator: Generator 实例

        Returns:
            变异后的 mock_call_returns 字典
        """
        if not mock_call_returns:
            return mock_call_returns

        mutated = {}

        for ext_call_sig, mock_config in mock_call_returns.items():
            scenario = mock_config["scenario"]
            values = mock_config["values"]
            types = mock_config["types"]

            strategy = random.random()

            # ============ 策略 1：场景切换（10%）============
            if strategy < 0.05:
                if function_sig in generator.mock_return_values_pool:
                    ext_call_config = generator.mock_return_values_pool[function_sig].get(ext_call_sig)
                    if ext_call_config:
                        # 切换到不同的场景
                        available_scenarios = [s for s in generator.mock_scenarios if s != scenario]
                        if available_scenarios:
                            new_scenario = random.choice(available_scenarios)
                            mock_values_dict = ext_call_config.get("mock_values", {})
                            if new_scenario in mock_values_dict and mock_values_dict[new_scenario]:
                                new_values = random.choice(mock_values_dict[new_scenario])
                                try:
                                    # from fuzzer.evm.storage_emulation import encode_return_values_to_bytes
                                    new_encoded = encode_return_values_to_bytes(new_values)
                                    mutated[ext_call_sig] = {
                                        "values": new_values,
                                        "types": types,
                                        "encoded": new_encoded,
                                        "scenario": new_scenario
                                    }
                                    continue
                                except:
                                    pass  # 失败则fallback到下一策略

            # ============ 策略 2：从 Pool 中选择（45%）============
            if strategy >= 0.05 and strategy < 0.15:
                new_values = []
                pool_used = False

                for i, (val, typ) in enumerate(zip(values, types)):
                    # 尝试从 pool 中获取该位置的值
                    pool_val = generator._get_mock_argument_from_pool(function_sig, ext_call_sig, i)
                    if pool_val is not None:
                        new_values.append(pool_val)
                        pool_used = True
                    else:
                        new_values.append(val)  # pool 为空则保持原值

                if pool_used:
                    try:
                        # from fuzzer.evm.storage_emulation import encode_return_values_to_bytes
                        new_encoded = encode_return_values_to_bytes(new_values)
                        mutated[ext_call_sig] = {
                            "values": new_values,
                            "types": types,
                            "encoded": new_encoded,
                            "scenario": scenario
                        }
                        continue
                    except:
                        pass

            # ============ 策略 3：边界值生成（10%）============
            if random.random() < settings.MOCK_RETURN_VALUES_MUTATE_PM:   
                new_values = []
                for val, typ in zip(values, types):
                    new_val = self._mutate_single_mock_value(val, typ, generator)
                    new_values.append(new_val)

                try:
                    # from fuzzer.evm.storage_emulation import encode_return_values_to_bytes
                    new_encoded = encode_return_values_to_bytes(new_values)
                    mutated[ext_call_sig] = {
                        "values": new_values,
                        "types": types,
                        "encoded": new_encoded,
                        "scenario": scenario
                    }
                except:
                    # 所有策略都失败，保持原值
                    mutated[ext_call_sig] = mock_config
            else:
                mutated[ext_call_sig] = mock_config

        return mutated

    def _mutate_single_mock_value(self, val, typ, generator):
        """
        对单个 mock 返回值进行边界值变异
        完全复用 generator 的边界值策略

        Args:
            val: 原始值
            typ: 类型字符串（如 "uint256", "address", "bool"）
            generator: Generator 实例

        Returns:
            变异后的值
        """
        # Boolean - 直接取反
        if typ.startswith("bool"):
            return not val if isinstance(val, bool) else random.choice([True, False])

        # Unsigned integer - 边界值策略（0/MAX/random）
        elif typ.startswith("uint"):
            # 解析位数：uint256 -> 256, uint -> 256
            type_clean = typ.replace("uint", "").split("[")[0]
            bit_size = int(type_clean) if type_clean else 256
            bytes_size = bit_size // 8

            from engine.components.generator import UINT_MAX

            if bytes_size in UINT_MAX:
                max_val = UINT_MAX[bytes_size]
                # 复用 generator 的三分策略
                seed = int(random.uniform(-2, 2))
                if seed == -1:
                    # 33% - 最小值附近
                    return random.choice([0, 1, 2])
                elif seed == 1:
                    # 33% - 最大值附近
                    return random.choice([max_val, max_val - 1, max_val - 2])
                else:
                    # 33% - 随机中间值
                    return random.randint(0, max_val)
            else:
                return val

        # Signed integer - 边界值策略（包括0）
        elif typ.startswith("int"):
            type_clean = typ.replace("int", "").split("[")[0]
            bit_size = int(type_clean) if type_clean else 256
            bytes_size = bit_size // 8

            from engine.components.generator import INT_MIN, INT_MAX

            if bytes_size in INT_MIN and bytes_size in INT_MAX:
                min_val = INT_MIN[bytes_size]
                max_val = INT_MAX[bytes_size]
                seed = int(random.uniform(-2, 2))
                if seed == -1:
                    return random.choice([0, -1, min_val, min_val + 1])
                elif seed == 1:
                    return random.choice([0, 1, max_val, max_val - 1])
                else:
                    return random.randint(min_val, max_val)
            else:
                return val

        # Address - 从账户池随机选择
        elif typ.startswith("address"):
            return random.choice(generator.accounts)

        # Bytes - 保持原值或生成随机 bytes
        elif typ.startswith("bytes"):
            if isinstance(val, (bytes, bytearray)):
                return val
            else:
                return generator.get_random_bytes(32)

        # String - 从 pool 或生成
        elif typ.startswith("string"):
            if generator.strings_pool.empty:
                return generator.get_string(random.randint(0, 32))
            else:
                return generator.get_random_string_from_pool()

        # 未知类型保持不变
        else:
            return val

    def get_sorted_indices(self, original_list, index_list, n):
        # 根据索引列表取出对应的值
        values = [original_list[i] for i in index_list]
        # 对这些值进行排序，并获取排序后的索引
        sorted_indices = sorted(index_list, key=lambda x: original_list[x])
        # 返回排序后前n个最小值在原列表中的索引
        return sorted_indices[:n]