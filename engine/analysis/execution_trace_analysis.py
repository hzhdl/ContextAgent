#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
import json
import psutil
import pandas as pd
from math import log2
from collections import defaultdict
import numpy as np

from engine.environment import FuzzingEnvironment
from engine.plugin_interfaces import OnTheFlyAnalysis
from eth_abi import decode as decode_abi

from engine.fitness import fitness_function

from utils.utils import initialize_logger, convert_stack_value_to_int, convert_stack_value_to_hex, normalize_32_byte_hex_address, get_function_signature_mapping
from eth._utils.address import force_bytes_to_address
from eth_utils import to_hex, to_int, int_to_big_endian, encode_hex, ValidationError, to_canonical_address, to_normalized_address

from z3 import simplify, BitVec, BitVecVal, Not, Optimize, sat, unsat, unknown, is_expr
from z3.z3util import get_vars

from utils import settings

class ExecutionTraceAnalyzer(OnTheFlyAnalysis):
    def __init__(self, fuzzing_environment: FuzzingEnvironment) -> None:
        self.logger = initialize_logger("Analysis")
        self.env = fuzzing_environment
        self.symbolic_execution_count = 0
        self.Critical_opcode = ['CALL', 'TIMESTAMP', 'NUMBER', 'INVALID', 'DELEGATECALL','SELFDESTRUCT']
        self.count = 0
        
        # 增量学习相关属性
        self.feature_stats = {}  # 存储特征统计信息
        self.target_stats = {}   # 存储目标变量统计信息
        self.joint_stats = {}    # 存储联合统计信息
        self.total_samples = 0   # 总样本数
        self.window_size = 1000  # 滑动窗口大小

    def setup(self, ng, engine):
        pass

    def cal_energy(self, k, x):
        """Energy calculation function using exponential formula"""
        return 1 - np.exp(-k * x)

    def safe_min(self, arr):
        """Safe minimum calculation that handles empty arrays"""
        if len(arr) == 0:
            return 0.95
        else:
            return np.min(arr)

    def calculate_adaptive_threshold(self):
        """
        Calculate adaptive fitness threshold based on stagnant seed count

        Formula: threshold = max(MIN, BASE × exp(-k × stagnant_seeds / decay_rate))

        Returns:
            float: Adaptive fitness threshold
        """
        if not settings.ADAPTIVE_THRESHOLD_ENABLE:
            return settings.FITNESS_THRESHOLD

        stagnant_seeds = self.env.seeds_since_last_coverage_improvement

        # Exponential decay factor
        decay_factor = np.exp(-settings.THRESHOLD_DECAY_STRENGTH * stagnant_seeds /
                             settings.THRESHOLD_DECAY_RATE)

        # Calculate adaptive threshold
        adaptive_threshold = settings.FITNESS_THRESHOLD_BASE * decay_factor

        # Limit to minimum threshold
        adaptive_threshold = max(settings.FITNESS_THRESHOLD_MIN, adaptive_threshold)

        return adaptive_threshold

    def calculate_adaptive_energies(self, res_ind):
        """
        Calculate three adaptive energies

        Args:
            res_ind: Result dictionary from analysis

        Returns:
            tuple: (parameter_energy, state_energy, environment_energy)
        """
        # 1. Parameter adaptive energy
        branch_improvement = res_ind.get("unbranlens_pre", 0) - res_ind.get("unbranlens", 0)
        parameter_energy = settings.PARAM_ALPHA * self.cal_energy(1, np.sum(res_ind["fun_flag"])) + (settings.PARAM_BELTA) * (1 - self.safe_min(res_ind["vul_w"])) + (1-settings.PARAM_ALPHA - settings.PARAM_BELTA) * self.cal_energy(2, branch_improvement)
        # parameter_energy = min(0.1,parameter_energy)
        parameter_energy = max(0.3,parameter_energy)

        # 2. State adaptive energy
        state_energy = self.cal_energy(2, res_ind.get("raw_news_list", 0))

        # 3. Environment adaptive energy
        success_count = len(res_ind.get("mock_detect_call_success", [])) \
                        if res_ind.get("mock_detect_call_success") else 0
        fail_count = len(res_ind.get("mock_detect_call_fail", [])) \
                     if res_ind.get("mock_detect_call_fail") else 0

        total_calls = success_count + fail_count * 2
        environment_energy = self.cal_energy(0.1, total_calls)

        return parameter_energy, state_energy, environment_energy

    def calculate_fitness(self, parameter_energy, state_energy, environment_energy, time_ratio):
        """
        Calculate fitness using weighted sum

        Args:
            parameter_energy: Parameter adaptive energy [0, 1]
            state_energy: State adaptive energy [0, 1]
            environment_energy: Environment adaptive energy [0, 1]
            time_ratio: Ratio of elapsed time to timeout

        Returns:
            float: Fitness value [0, 1]
        """
        epsilon = 1e-6  # Avoid zero values
        w1 = settings.ADAPTIVE_WEIGHT_PARAM
        w2 = settings.ADAPTIVE_WEIGHT_STATE
        w3 = settings.ADAPTIVE_WEIGHT_ENV

        # Dynamic weight adjustment based on time
        timeyuzhi = self.cal_energy(0.7, time_ratio * 100)
        w1 += min(timeyuzhi * w3 / 2, w3 * 0.33)
        w2 += min(timeyuzhi * w3 / 2, w3 * 0.33)
        w3 = 1 - w1 - w2

        fitness = ((parameter_energy + epsilon) * w1 +
                   (state_energy + epsilon) * w2 +
                   (environment_energy + epsilon) * w3)

        return fitness

    def _collect_embedded_contract_stats(self, contract):
        """
        收集单个嵌入合约的统计信息

        在提取嵌入合约后立即调用，用于统计：
        1. 嵌入合约的所有PC
        2. 嵌入合约字节码所在block向外的分支数

        Args:
            contract: EmbeddedContract 对象，如果为 None 则直接返回

        Note:
            使用 contract.trigger_opcode_pc 作为唯一标识进行去重，
            避免重复统计同一个嵌入合约
        """
        if contract is None:
            return

        # 去重检查：如果这个合约已经统计过，直接返回
        if contract.trigger_opcode_pc in self.env.embedded_contract_stats['processed_contract_pcs']:
            return

        # 标记这个合约为已处理
        self.env.embedded_contract_stats['processed_contract_pcs'].add(contract.trigger_opcode_pc)

        # 1. 统计嵌入合约的所有PC
        if contract.creation_code_offset_in_parent is not None and \
           contract.creation_code_length is not None:
            start = contract.creation_code_offset_in_parent
            end = start + contract.creation_code_length

            # 添加所有嵌入合约字节码的PC
            i = start
            while i < end:
                self.env.embedded_contract_stats['total_pcs'].add(hex(i))
                if self.env.cfg._bytecode[i] == 87: # JUMPI
                    self.env.embedded_contract_stats['bytecode_blocks_branches'] += 1
                if self.env.cfg._bytecode[i] >= 96 and self.env.cfg._bytecode[i] <= 127: # PUSH
                    size = self.env.cfg._bytecode[i] - 96 + 1
                    i += size
                i += 1

        # 2. 统计嵌入合约字节码所在block的分支数
        # embedded_pcs = self.env.cfg._get_embedded_contract_bytecode_pcs()

        # for bb in self.env.cfg.vertices.values():
        #     block_pcs = bb.get_instructions().keys()

        #     # 如果block包含嵌入合约字节码
        #     has_embedded = any(pc in embedded_pcs for pc in block_pcs)

        #     if has_embedded:
        #         # 统计该block向外的分支数
        #         bb_end = bb.get_end_address()
        #         if bb_end in self.env.cfg.edges:
        #             branch_count = len(self.env.cfg.edges[bb_end])
        #             self.env.embedded_contract_stats['bytecode_blocks_branches'] += branch_count

    def _update_embedded_covered_pcs(self):
        """
        更新嵌入合约中已覆盖的PC

        需要在每次计算覆盖率前调用，用于计算嵌入合约PC与已覆盖PC的交集
        """
        # 计算嵌入合约PC与已覆盖PC的交集
        self.env.embedded_contract_stats['covered_pcs'] = \
            self.env.embedded_contract_stats['total_pcs'].intersection(
                self.env.code_coverage
            )

    def _calculate_corrected_coverage(self, enablexiuzheng=False):
        """
        计算修正后的代码覆盖率和分支覆盖率, 暂时不予修正

        修正逻辑：
        1. 代码覆盖率 = 已覆盖指令数 / (总指令数 - (嵌入合约总指令数 - 嵌入合约已覆盖指令数))
        2. 分支覆盖率 = 已覆盖分支数 / (总分支数 - 嵌入合约block的分支数)

        Returns:
            tuple: (code_coverage_percentage, branch_coverage_percentage,
                    branch_coverage_count)
        """
        # 更新嵌入合约已覆盖PC
        self._update_embedded_covered_pcs()

        # 1. 修正代码覆盖率
        # 公式: 已覆盖指令数 / (总指令数 - (嵌入合约总指令数 - 嵌入合约已覆盖指令数))
        corrected_total_pcs = 0
        code_coverage_percentage = 0
        if enablexiuzheng and len(self.env.overall_pcs) > 0:
            embedded_total = len(self.env.embedded_contract_stats['total_pcs'])
            embedded_covered = len(self.env.embedded_contract_stats['covered_pcs'])

            # 修正后的总PC数
            corrected_total_pcs = len(self.env.overall_pcs) - (embedded_total - embedded_covered)

            if corrected_total_pcs > 0:
                code_coverage_percentage = (len(self.env.code_coverage) / corrected_total_pcs) * 100
        else:
            corrected_total_pcs = len(self.env.overall_pcs)
            code_coverage_percentage = len(self.env.code_coverage) / len(self.env.overall_pcs) * 100
        
        if code_coverage_percentage ==0:
            print(f"code_coverage_percentage: {code_coverage_percentage}")

        # 2. 修正分支覆盖率
        # 公式: 已覆盖分支数 / (总分支数 - 嵌入合约block的分支数)
        branch_coverage = 0
        for pc in self.env.visited_branches:
            branch_coverage += len(self.env.visited_branches[pc])

        branch_coverage_percentage = 0
        corrected_total_branches = 0
        if enablexiuzheng and  len(self.env.overall_jumpis) > 0:
            embedded_branches = self.env.embedded_contract_stats['bytecode_blocks_branches']
            corrected_total_branches = (len(self.env.overall_jumpis) * 2) - embedded_branches*2

            if corrected_total_branches > 0:
                branch_coverage_percentage = (branch_coverage / corrected_total_branches) * 100
        else:
            corrected_total_branches = len(self.env.overall_jumpis) * 2
            branch_coverage_percentage = (branch_coverage / corrected_total_branches) * 100

        return code_coverage_percentage, corrected_total_pcs, branch_coverage_percentage, branch_coverage, corrected_total_branches


    def _process_target(self,values):
        """目标变量专用处理"""
        if all(isinstance(v, (int, float)) for v in values):
            try:
                return self._discretize(values, 5)
            except:
                return values
        return values

    def _process_feature(self,values):
        """特征列处理"""
        # 混合类型处理逻辑
        type_counter = defaultdict(int)
        for v in values:
            type_counter[type(v)] += 1
        
        # 确定主要类型
        main_type = max(type_counter, key=type_counter.get)
        
        # 数值型处理
        if main_type in (int, float):
            try:
                return self._discretize(values, 5)
            except:
                return [str(v) for v in values]  # 退化为字符串处理
        
        # 字节类型特殊处理
        if main_type == bytes:
            return [v.decode('utf-8', 'ignore')[:10] for v in values]
        
        # 默认转为字符串
        return [str(v) for v in values]

    def _discretize(self,values, bins):
        """增强型分箱函数"""
        if len(values) < bins:
            return values
        
        try:
            # 等频分箱，处理重复值
            return pd.qcut(values, q=bins, labels=False, duplicates='drop').tolist()
        except:
            # 失败时改用等宽分箱
            return pd.cut(values, bins=bins, labels=False).tolist()

    def _calculate_ig(self,y, x):
        """改进的信息增益计算"""
        # 熵计算
        def _entropy(elements):
            counter = defaultdict(int)
            total = len(elements)
            for e in elements:
                counter[e] += 1
            return -sum((c/total)*log2(c/total) for c in counter.values())

        # 条件熵计算
        conditional_counts = defaultdict(list)
        for x_val, y_val in zip(x, y):
            conditional_counts[x_val].append(y_val)
        
        total = len(y)
        conditional_entropy = 0.0
        for x_val, y_list in conditional_counts.items():
            prob = len(y_list) / total
            conditional_entropy += prob * _entropy(y_list)
        
        # 信息增益
        return _entropy(y) - conditional_entropy
        
    #对涉及到数据进行分析，并指明具体函数的变异方向。
            
    def cal_res(self,t2ds):
        # self.env.fit_tx2dis_res = dict()
        #函数距离
        fun_dis = []
        #函数标签，设计未覆盖分支数量
        fun_flag = []
        #函数错过分支的权重均值
        # fun_w=[]
        #函数错过分支的权重和
        fun_w=[]
        #综合距离，使用调和距离
        dis = 0
        #危险分支标签
        vul_branch_flag = {}
        
        for i,iv in enumerate(t2ds):
            function_hash=iv[0]
            fun_dis.append(0)
            fun_flag.append(0)
            fun_w.append(0)
            tvw=[]
           
            if  function_hash == "00000000":
                continue
            
            for key,val in iv[1].items():
                if key == "jumpi_pos":
                    for k,v in val.items():
                        if k in self.env.unvisited_branches:
                            tmp_vw = self.cal_vul_dis(v,k)
                            tvw.append(tmp_vw)
                            fun_dis[i] += 1/(abs(v)+1)
                            fun_flag[i]+=1
            if fun_dis[i] == 0:
                fun_dis[i] = 1
            if len(tvw) == 0:
                fun_w[i] = 0.995
            else:
                tsum=0
                for vw in tvw:
                    tsum+=vw
                fun_w[i] = tsum/len(tvw)
            dis += fun_dis[i]
            fun_dis[i] = 1/fun_dis[i]
        if dis == 0:
            dis = 1
        
        return 1/dis, fun_dis, fun_flag , fun_w
    
    def cal_vul_dis(self,v,pcs):
        
        for i in self.env.individual_branches:
            if pcs in self.env.individual_branches[i]:
                for k in self.env.individual_branches[i][pcs]:
                    pc=int(pcs,16)
                    kk=int(k,16)
                    if not self.env.individual_branches[i][pcs][k] and pc in self.env.vul_bran_weight and kk in self.env.vul_bran_weight[pc]:
                        return 1-max(0.005,self.env.vul_bran_weight[pc][kk])
                    else:
                        return 1-0.005
            else:
                return 1-0.005
        return 1-0.005


    
    def decode_jumpis(self,function_hash,jumpi_pos):
        y={}
        # print(individual.chromosome)
        for key,val in jumpi_pos.items():
            if key in self.env.unvisited_branches:
                for kk,vv in val.items():
                    y.append([key,kk])
        return y

    def decode(self, function_hash, tx):
        try:
            atype=self.env.interface[function_hash]
        except:
            atype=[]
        res=[tx["transaction"]['value']]
        if len(atype)==0:
            r=[]
        else:
            dataa=bytes.fromhex(tx["transaction"]["data"][10:])
            try:
                r=decode_abi(atype,dataa)
            except:
                r=[]
        res.extend(r)
        # print(r)
        return res

    def execute_seed(self, indv, engine):
        self.env.memoized_fitness.clear()
        self.env.memoized_storage.clear()
        self.env.memoized_symbolic_execution.clear()
        self.env.individual_branches.clear()
             



        
        if indv.hash in self.env.unique_individuals:
            return None, None, None, None, [None,None]
        
        if settings.MUTATE_SNAPSHOT_ENABLE and indv.snapshot_key:
            snapshot = self.env.get_snapshot(indv.snapshot_key) 
            if not snapshot is None:
            # if snapshot:
                self.env.instrumented_evm.restore_by_snapshot(snapshot)

        t2ds, cri_opc, mutate_require_list, raw_news_list, [mock_detect_call_success, mock_detect_call_fail]=self.execution_function(indv, self.env)

        return t2ds, cri_opc, mutate_require_list, raw_news_list, [mock_detect_call_success, mock_detect_call_fail]
        # engine._update_statvars()

    def register_step(self, g, population, engine):
        """
        Batch execute all individuals in the population and calculate fitness

        This method:
        1. Executes each individual using self.analysis
        2. Stores res_ind to individual.res_ind
        3. Calculates multi-dimensional energies
        4. Computes comprehensive fitness and caches it
        5. Optionally adds to elite archive
        """
        # Clear caches
        self.env.memoized_fitness.clear()
        if hasattr(self.env, 'memoized_energies'):
            self.env.memoized_energies.clear()

        # Track executed individuals for deduplication
        executed_individuals = dict()

        for i, individual in enumerate(population.individuals):
            # Deduplication check
            if individual.hash in executed_individuals:
                population.individuals[i] = executed_individuals[individual.hash]
                continue

            # Execute individual and get res_ind
            res_ind = self.analysis(g=g, indv=individual, engine=engine, flag=True)

            if res_ind is None:
                # Execution failed, skip this individual
                continue

            # Store res_ind to individual for energy-driven mutation
            individual.res_ind = res_ind

            # Calculate multi-dimensional energies
            parameter_energy, state_energy, environment_energy = \
                self.calculate_adaptive_energies(res_ind)

            # Calculate comprehensive fitness
            time_ratio = (time.time() - self.env.execution_begin) / settings.GLOBAL_TIMEOUT \
                         if settings.GLOBAL_TIMEOUT else 0
            fitness = self.calculate_fitness(
                parameter_energy, state_energy,
                environment_energy, time_ratio
            )
            individual.res_ind["fitness"] = fitness

            # Cache fitness
            self.env.memoized_fitness[individual.hash] = fitness

            # Cache energies for analysis/logging
            if not hasattr(self.env, 'memoized_energies'):
                self.env.memoized_energies = {}
            self.env.memoized_energies[individual.hash] = {
                'parameter_energy': parameter_energy,
                'state_energy': state_energy,
                'environment_energy': environment_energy
            }

            # Add to elite archive if available
            if hasattr(population, 'add_to_archive'):
                population.add_to_archive(individual, fitness)

            executed_individuals[individual.hash] = individual

        executed_individuals.clear()

        # Update statistics
        engine._update_statvars()

        # Calculate corrected coverage
        code_coverage_percentage, corrected_total_pcs, branch_coverage_percentage, \
            branch_coverage, corrected_total_branches = self._calculate_corrected_coverage()

        revert_percentage = 0
        if self.env.nr_of_transactions > 0:
            revert_percentage = (self.env.revert_tx / self.env.nr_of_transactions) * 100

        msg = 'Generation {} \t Code coverage: {:.2f}% ({}/{}) \t Branch coverage: {:.2f}% ({}/{}) \t ' \
              'Transactions: {} ({} unique)   \t revert_percentage: {:.2f}% ({}/{}) \t Time: {}'.format(
            g + 1, code_coverage_percentage, len(self.env.code_coverage), corrected_total_pcs,
            branch_coverage_percentage, branch_coverage, corrected_total_branches,
            self.env.nr_of_transactions, len(self.env.unique_individuals),
            revert_percentage, self.env.revert_tx, self.env.nr_of_transactions,
            time.time() - self.env.execution_begin)
        self.logger.title(msg)

        # Save results
        if len(self.env.code_coverage) == self.env.previous_code_coverage_length:
            # if self.symbolic_execution_count > 10:
                # print("start symbolic execution:", self.symbolic_execution_count )
            self.symbolic_execution(engine.population.indv_generator)
            # self.symbolic_execution_count= 0
            if self.symbolic_execution_count == settings.MAX_SYMBOLIC_EXECUTION:
                # engine.population.insert_individuals()
                self.symbolic_execution_count = 0
                del population.individuals[:]
                population.init_hash()
                self.logger.debug("Resetting population...")
                self.register_step(g+1,population, engine)
                
            self.symbolic_execution_count +=1
            # print("---------------------", self.env.fitseeds_count / self.env.execseeds_count * 100, "*****",self.env.fitseeds_count,self.env.execseeds_count)
            
        else:
            # self.symbolic_execution(engine.population.indv_generator)
            self.symbolic_execution_count = 0
            if "results" not in self.env.results:
                self.env.results["results"]=[]
            self.env.results["results"].append({
                # "time": g + 1,
                # "vul": str(self.env.errors_list),
                "file_name":self.env.file_name,
                "contract": self.env.contract_name,
                "time": time.time() - self.env.execution_begin,
                "total_transactions": self.env.nr_of_transactions,
                "revert_transactions_percentage": revert_percentage,
                "unique_transactions": len(self.env.unique_individuals),
                "code_coverage": code_coverage_percentage,
                "branch_coverage": branch_coverage_percentage
            })

        

    def analysis(self, g, indv, engine,flag=False):
        #分析结果
        result={}
        result["unbranlens_pre"]=len(self.env.unvisited_branches)
        tmprevert_num = self.env.revert_tx
        
        t2ds,cri_opc, mutate_require_list, result["raw_news_list"], [mock_detect_call_success, mock_detect_call_fail]=self.execute_seed(indv, engine)

        result["revert_tx"] = self.env.revert_tx - tmprevert_num
        result["revertrate"] = result["revert_tx"] / len(indv.solution)

        if mutate_require_list:
            result["mutate_require_list"] = mutate_require_list
        else:
            result["mutate_require_list"] = []
        if t2ds is None:
            return None

        if mock_detect_call_success is not None:
            result["mock_detect_call_success"] = mock_detect_call_success
        if mock_detect_call_fail is not None:
            result["mock_detect_call_fail"] = mock_detect_call_fail
        
        result["unbranlens"]=len(self.env.unvisited_branches)
        if not cri_opc and cri_opc != set():
            result["cri_opc"]=cri_opc
        else:
            result["cri_opc"] = set()



        # 使用修正后的覆盖率计算（考虑嵌入合约字节码）
        code_coverage_percentage, corrected_total_pcs, branch_coverage_percentage, branch_coverage,corrected_total_branches = self._calculate_corrected_coverage()

        revert_percentage = 0
        if self.env.nr_of_transactions > 0:
            revert_percentage = (self.env.revert_tx / self.env.nr_of_transactions) * 100


        if "generations" not in self.env.results:
                self.env.results["generations"] = []

        if g!=-2 and flag and len(self.env.code_coverage) != self.env.previous_code_coverage_length:
        # self.count+=1
        # if g!=-2:
            # msg = ' Code coverage: {:.2f}% ({}/{}) \t Branch coverage: {:.2f}% ({}/{}) \t ' \
            #     'Transactions: {} ({} unique)   \t revert_transactions_percentage: {:.2f}% ({}/{}) \t Time: {}'.format(
            #     code_coverage_percentage, len(self.env.code_coverage), len(self.env.overall_pcs),
            #     branch_coverage_percentage, branch_coverage, len(self.env.overall_jumpis) * 2, self.env.nr_of_transactions, len(self.env.unique_individuals),
            #     revert_percentage, self.env.revert_tx,self.env.nr_of_transactions,
            #     time.time() - self.env.execution_begin)
            # msg = ' Code coverage: {:.2f}% ({}/{}) \t Branch coverage: {:.2f}% ({}/{}) \t ' \
            #     'Transactions: {} ({} unique)   \t revert_transactions_percentage: {:.2f}% ({}/{}) \t Time: {}'.format(
            #     code_coverage_percentage, len(self.env.code_coverage), corrected_total_pcs,
            #     branch_coverage_percentage, branch_coverage, corrected_total_branches, self.env.nr_of_transactions, len(self.env.unique_individuals),
            #     revert_percentage, self.env.revert_tx,self.env.nr_of_transactions,
            #     time.time() - self.env.execution_begin)
            # self.logger.title(msg)
            self.count = 0
            # Save to results
            self.env.results["generations"].append({
                    # "time": g + 1,
                    # "vul": str(self.env.errors_list),
                    "file_name":self.env.file_name,
                    "contract": self.env.contract_name,
                    "time": time.time() - self.env.execution_begin,
                    "total_transactions": self.env.nr_of_transactions,
                    "revert_transactions_percentage": revert_percentage,
                    "revert_transactions": self.env.revert_tx,


                    "unique_transactions": len(self.env.unique_individuals),
                    "nr_of_transactions": self.env.nr_of_transactions,

                    
                    "code_coverage": code_coverage_percentage,
                    "code_coverage_length": len(self.env.code_coverage),
                    "code_coverage_allpcs": len(self.env.overall_pcs),
                    "branch_coverage": branch_coverage_percentage,
                    "branch_coverage_length": branch_coverage,
                    "branch_coverage_jumpis": len(self.env.overall_jumpis) * 2
                })

        
        # 记录开始时间
        # start_time = time.time()
        
        # 执行第一个操作
        result["dis"],result["fun_dis"], result["fun_flag"], result["vul_w"] = self.cal_res(t2ds)
        
        # # ========== 新增：更新停滞种子计数器 ==========
        # current_code_coverage_size = len(self.env.code_coverage)
        # current_branch_coverage_size = len(self.env.visited_branches)

        # # 检测覆盖率是否增长
        # if (current_code_coverage_size > self.env.last_code_coverage_size or
        #     current_branch_coverage_size > self.env.last_branch_coverage_size):
        #     # 覆盖率有增长，重置计数器
        #     self.env.seeds_since_last_coverage_improvement = 0
        #     self.env.last_code_coverage_size = current_code_coverage_size
        #     self.env.last_branch_coverage_size = current_branch_coverage_size
        # else:
        #     # 覆盖率未增长，计数器递增
        #     self.env.seeds_since_last_coverage_improvement += 1

        # # 记录到日志（可选，用于调试）
        # if settings.ADAPTIVE_THRESHOLD_ENABLE:
        #     self.logger.debug("Seeds since last coverage improvement: %d",
        #                       self.env.seeds_since_last_coverage_improvement)
        # # ========== 新增结束 ==========



        
        
        self.env.symbolic_execution_count=self.symbolic_execution_count

        self.env.previous_code_coverage_length = len(self.env.code_coverage)

        return result

    

    def judge_key_var(self, state_name, state,env,To=None, From=None):
        if state == None:
            return []
        mutate_require = []
        for index,item in enumerate(self.env.key_var[state_name]):
            # [operator, value, weight]
            state_value = self.state_value_convert(state_name,state,env,item,To,From)
            
            
            if self.satisfies_require([item[0],state_value], state):
                
                if item[2] > 1/(2*len(self.env.key_var[state_name])):
                    mutate_require.append(index)
                    self.env.key_var[state_name][index][2] = settings.MUTATE_KEY_VAR_WEIGHT*self.env.key_var[state_name][index][2] + (1-settings.MUTATE_KEY_VAR_WEIGHT)*settings.MUTATE_KEY_VAR_PUBLISH_WEIGHT
        return mutate_require
    
    def state_value_convert(self,state_name,state,env,item,To=None,From=None):
        final_state_value = item[1]
        if item[0] and item[0] != "!" and item[1] in self.env.state_var:
                state_value = env.instrumented_evm.read_contract_state_by_names(To, env.abi, From, [item[1]])
                if state_value!={}:
                    final_state_value = state_value[item[1]]
        elif item[1] in ["true","false"]:
            final_state_value = 1 if item[1] == "true" else 0

        return final_state_value
    
    def satisfies_require(self, item, state):
        try:
            if item[0] == None:
                return state != 0
            elif item[0] == "!":
                return state ==0
            elif item[0] == "!=":
                return state != item[1]
            elif item[0] == "==":
                return state == item[1]
            elif item[0] == ">":
                return state > item[1]
            elif item[0] == "<":
                return state < item[1]
            elif item[0] == ">=":
                return state >= item[1]
            elif item[0] == "<=":
                return state <= item[1]
            else:
                return False
        except:
            return False


    def execution_function(self, indv, env: FuzzingEnvironment):
        env.unique_individuals.add(indv.hash)
        
        # Initialize metric
        branches = {}
        indv.data_dependencies = []
        contract_address = None
        t2ds=[]

        env.detector_executor.initialize_detectors()
        critical_opcode = set()
        mutate_require_list = []
        raw_news_list = 0
        mock_detect_call_success = []
        mock_detect_call_fail = []


        for transaction_index, test in enumerate(indv.solution):
            

            transaction = test["transaction"]

            _function_hash = transaction["data"][:10] if transaction["data"].startswith("0x") else transaction["data"][:8]
            _function_hash = "fallback" if _function_hash == '' else _function_hash
            _array_size_indexes = dict()

            if transaction["to"] is None and contract_address is not None:
                transaction["to"] = contract_address

            if transaction["to"] is None:
                continue

            try:
                result = env.instrumented_evm.deploy_transaction(test)
            except ValidationError as e:
                self.logger.error("Validation error in %s : %s (ignoring for now)", indv.hash, e)
                continue

            # 处理意料之外的调用，缓解编译造成的语义丢失问题。
            success_call = 0
            fail_call = 0
            for new_call in env.instrumented_evm.vm.state.detect_new_call:
                indv.generator.load_mock_return_values_new_call(new_call[0], new_call[1])
                mockvalues = indv.generator.get_mock_values_for_call(new_call[0], new_call[1])
                if mockvalues:
                    indv.chromosome[transaction_index]["mock_call_returns"][new_call[1]] = mockvalues
                    success_call +=1
                else:
                    fail_call +=1
            mock_detect_call_success.append(success_call)
            mock_detect_call_fail.append(fail_call)
            env.instrumented_evm.vm.state.detect_new_call.clear()
                # print(mockvalues)
                
                    

            if not result.is_error and transaction["to"] == b'':
                contract_address = encode_hex(result.msg.storage_address)
                self.logger.debug("(%s - %d) Contract deployed at %s", indv.hash, transaction_index, contract_address)

            for child_computation in result.children:
                if child_computation.msg.to not in env.other_contracts:
                    continue
                if child_computation.msg.to not in env.children_code_coverage:
                    env.children_code_coverage[child_computation.msg.to] = set()
                env.children_code_coverage[child_computation.msg.to].update([x["pc"] for x in child_computation.trace])

            env.nr_of_transactions += 1

            previous_instruction = None
            previous_branch = []
            previous_branch_expression = None
            previous_branch_address = None
            previous_call_address = None
            sha3 = {}
            
            if _function_hash not in env.txdata2dis:
                if _function_hash == 'fallback':
                    env.txdata2dis["00000000"]=[]
                else:
                    env.txdata2dis[_function_hash]=[]
            
            
            t2d={}
            t2d["tx"]= test
            t2d["jumpi_pos"]={}
            codecopy_params = ()
                # env.txdata2dis[_function_hash].append(t2d)
            if settings.MUTATE_SNAPSHOT_ENABLE and _function_hash in env.require_key_fun.keys():
                state_names = list(env.require_key_fun[_function_hash])
                state=self.env.instrumented_evm.read_contract_state_by_names(transaction["to"], env.abi, transaction["from"], state_names)
                mutate_require_nums={}
                mutate_require_tx_list={}
                for k,v in state.items():
                    mutate_require_nums[k]=self.judge_key_var(k, state[k],env,transaction["to"],transaction["from"])
                mutate_require=0
                for mrk in mutate_require_nums.keys():
                    mutate_require+=len(mutate_require_nums[mrk])
                if mutate_require > 0:
                    snapshot = env.instrumented_evm.create_new_snapshot()
                    
                    for ks in state.keys():
                        for require_index in mutate_require_nums[ks]:
                            env.add_snapshot(ks,require_index,snapshot)
                        read_tx_list=set()
                        # if ks not in env.RAW[0]:
                        #     continue
                        # for kss in env.RAW[0][ks]:
                        #     if kss == "constructor":
                        #         continue
                        #     read_tx_list.add(env.funname2hash[kss])
                        tmpkey = env.key_var[ks][require_index][:-1]
                        for kk in env.require_key_tx_fun[ks][str(tmpkey)]:
                            if kk in env.funname2hash:
                                read_tx_list.add(env.funname2hash[kk])
                        # read_tx_list.discard(_function_hash)
                        mutate_require_list.append([transaction_index, len(mutate_require_nums[ks]), read_tx_list,[ks,mutate_require_nums[ks]]])
                    print(state)
            
            

            for i, instruction in enumerate(result.trace):

                env.symbolic_taint_analyzer.propagate_taint(instruction, contract_address)

                els=env.detector_executor.run_detectors(previous_instruction, instruction, env.results["errors"],
                                                env.symbolic_taint_analyzer.get_tainted_record(index=-2), indv, env, previous_branch,
                                                transaction_index)
                for elss in els:
                    if elss not in self.env.errorsdic:
                        self.env.errors_list.append([self.env.file_name,elss,time.time() - env.execution_begin])
                        self.env.errorsdic[elss]=1
                if hex(instruction["pc"]) in env.basic_block_cover:
                    self.env.basic_block_cover[hex(instruction["pc"])] = 1

                # If constructor, we don't have to take into account the constructor inputs because they will be part of the
                # state. We don't have to compute the code coverage, because the code is not the deployed one. We don't need
                # to compute the cfg because we are on a different code. We actlually don't need analyzing its traces.
                if indv.chromosome[transaction_index]["arguments"][0] == "constructor":
                    continue

                # Code coverage
                env.code_coverage.add(hex(instruction["pc"]))

                # Dynamically build control flow graph
                if env.cfg:
                    env.cfg.execute(instruction["pc"], instruction["stack"], instruction["op"], env.visited_branches,
                                    env.results["errors"].keys())

                if previous_instruction and previous_instruction["op"] == "SHA3":
                    sha3[instruction["stack"][-1][1]] = instruction["memory"]

                elif previous_instruction and previous_instruction["op"] == "ADD":
                    if previous_instruction["stack"][-1][1] in sha3:
                        sha3[instruction["stack"][-1][1]] = sha3[previous_instruction["stack"][-1][1]]
                    if previous_instruction["stack"][-2][1] in sha3:
                        sha3[instruction["stack"][-1][1]] = sha3[previous_instruction["stack"][-2][1]]

                if instruction["op"] == "JUMPI":
                    jumpi_pc = hex(instruction["pc"])
                    if jumpi_pc not in env.visited_branches:
                        env.visited_branches[jumpi_pc] = {}
                    if jumpi_pc not in branches:
                        branches[jumpi_pc] = dict()

                    destination = convert_stack_value_to_int(instruction["stack"][-1])
                    jumpi_condition = convert_stack_value_to_int(instruction["stack"][-2])
                    # Normalize condition to binary: 0 = not taken, 1 = taken
                    normalized_condition = 0 if jumpi_condition == 0 else 1
                    # normalized_condition = jumpi_condition
                    
                    if jumpi_condition == 0:
                        # don't jump, but increase pc
                        branches[jumpi_pc][hex(destination)] = False
                        branches[jumpi_pc][hex(instruction["pc"] + 1)] = True
                    else:
                        # jump to destination
                        branches[jumpi_pc][hex(destination)] = True
                        branches[jumpi_pc][hex(instruction["pc"] + 1)] = False

                    # if jumpi_condition > 1:
                    #     print("this is a vul!")

                    env.visited_branches[jumpi_pc][normalized_condition] = {}
                    env.visited_branches[jumpi_pc][normalized_condition]["indv_hash"] = indv.hash
                    env.visited_branches[jumpi_pc][normalized_condition]["chromosome"] = indv.chromosome
                    env.visited_branches[jumpi_pc][normalized_condition]["transaction_index"] = transaction_index
                    env.visited_branches[jumpi_pc][normalized_condition]["original_condition"] = jumpi_condition
                    
                    # if jumpi_pc not in t2d["jumpi_pos"]:
                    #     t2d["jumpi_pos"][jumpi_pc]={}
                    # t2d["jumpi_pos"][jumpi_pc]=jumpi_condition

                    if jumpi_pc not in t2d["jumpi_pos"]:
                        t2d["jumpi_pos"][jumpi_pc]={}
                    if result.trace[i-2]["op"] in ["EQ","LT","GT","SLT","SGT"]:
                        instruct = result.trace[i-2]
                        t2d["jumpi_pos"][jumpi_pc] = convert_stack_value_to_int(instruct["stack"][-1]) - convert_stack_value_to_int(instruct["stack"][-2])
                    elif result.trace[i-2]["op"] in ["ISZERO"]:
                        # t2d["jumpi_pos"][jumpi_pc] = convert_stack_value_to_int(instruct["stack"][-1])
                        iszero_test=env.jumpi_analyzer.analyze_iszero(result.trace, i-2)
                        if iszero_test == []:
                            t2d["jumpi_pos"][jumpi_pc] = 1
                        else:
                            t2d["jumpi_pos"][jumpi_pc] = abs(iszero_test[0])
                        
                    else:
                        t2d["jumpi_pos"][jumpi_pc]=jumpi_condition

                    

                    tainted_record = env.symbolic_taint_analyzer.check_taint(instruction=instruction)
                    if tainted_record and tainted_record.stack and tainted_record.stack[-2]:
                        if jumpi_condition != 0:
                            previous_branch.append(tainted_record.stack[-2][0] != 0)
                        else:
                            previous_branch.append(tainted_record.stack[-2][0] == 0)
                        previous_branch_expression = previous_branch[-1]
                        env.visited_branches[jumpi_pc][normalized_condition]["expression"] = previous_branch.copy()
                    else:
                        env.visited_branches[jumpi_pc][normalized_condition]["expression"] = None
                        previous_branch_expression = None
                    
                    if jumpi_pc in env.unvisited_branches and len(env.visited_branches[jumpi_pc])==2:
                        del env.unvisited_branches[jumpi_pc]

                    previous_branch_address = jumpi_pc

                # Extract data dependencies (read-after-write)
                elif instruction["op"] == "SLOAD":
                    if instruction["stack"][-1][1] in sha3:
                        hash = instruction["stack"][-1][1]
                        while hash in sha3:
                            if len(sha3[hash]) == 64:
                                hash = sha3[hash][32:64]
                            else:
                                hash = sha3[hash]
                        storage_slot = int.from_bytes(hash, byteorder='big')
                    else:
                        storage_slot = convert_stack_value_to_int(instruction["stack"][-1])

                    _function_hash = indv.chromosome[transaction_index]["arguments"][0]
                    if _function_hash not in self.env.data_dependencies:
                        self.env.data_dependencies[_function_hash] = {"read": set(), "write": set()}
                    if 's'+str(storage_slot) not in self.env.dep_data:
                        self.env.dep_data['s'+str(storage_slot)] = {"read": set(), "write": set()}
                    if _function_hash not in self.env.example_tx:
                        self.env.example_tx[_function_hash] = {"read": None, "write": None}
                    if storage_slot not in self.env.data_dependencies[_function_hash]["read"]:
                        raw_news_list +=1
                    self.env.data_dependencies[_function_hash]["read"].add(storage_slot)
                    self.env.dep_data['s'+str(storage_slot)]["read"].add(_function_hash)
                    self.env.example_tx[_function_hash]["read"] = indv.chromosome[transaction_index]

                elif instruction["op"] == "SSTORE":
                    if instruction["stack"][-1][1] in sha3:
                        hash = instruction["stack"][-1][1]
                        while hash in sha3:
                            if len(sha3[hash]) == 64:
                                hash = sha3[hash][32:64]
                            else:
                                hash = sha3[hash]
                        storage_slot = int.from_bytes(hash, byteorder='big')
                    else:
                        storage_slot = convert_stack_value_to_int(instruction["stack"][-1])

                    _function_hash = indv.chromosome[transaction_index]["arguments"][0]
                    if _function_hash not in self.env.data_dependencies:
                        self.env.data_dependencies[_function_hash] = {"read": set(), "write": set()}
                    if 's'+str(storage_slot) not in self.env.dep_data:
                        self.env.dep_data['s'+str(storage_slot)] = {"read": set(), "write": set()}
                    if _function_hash not in self.env.example_tx:
                        self.env.example_tx[_function_hash] = {"read": None, "write": None}
                    self.env.data_dependencies[_function_hash]["write"].add(storage_slot)
                    self.env.dep_data['s'+str(storage_slot)]["write"].add(_function_hash)
                    self.env.example_tx[_function_hash]["write"] = indv.chromosome[transaction_index]

                # If something goes wrong, we need to clean some pools
                elif instruction["op"] in ["REVERT", "INVALID", "ASSERTFAIL"]:
                    if previous_branch_expression is not None and is_expr(previous_branch_expression):
                        # Only remove from pool when you are sure which variable caused the exception
                        if len(get_vars(previous_branch_expression)) == 1:
                            for var in get_vars(previous_branch_expression):
                                _str_var = str(var)

                                if _str_var.startswith("calldataload_") or str(var).startswith("calldatacopy_"):
                                    _parameter_index = int(str(var).split("_")[-1])
                                    _transaction_index = int(str(var).split("_")[-2])
                                    _function_hash = indv.chromosome[_transaction_index]["arguments"][0]
                                    _argument = indv.chromosome[_transaction_index]["arguments"][_parameter_index + 1]
                                    indv.generator.remove_argument_from_pool(_function_hash, _parameter_index, _argument)

                                elif _str_var.startswith("callvalue_"):
                                    _function_hash = indv.chromosome[transaction_index]["arguments"][0]
                                    _amount = transaction["value"]
                                    if _amount == 0 or _amount == 1:
                                        indv.generator.remove_amount_from_pool(_function_hash, _amount)

                                elif _str_var.startswith("caller_"):
                                    _function_hash = indv.chromosome[transaction_index]["arguments"][0]
                                    _caller = transaction["from"]
                                    indv.generator.remove_account_from_pool(_function_hash, _caller)

                                elif _str_var.startswith("gas_"):
                                    _function_hash = indv.chromosome[transaction_index]["arguments"][0]
                                    _gas_limit = indv.chromosome[transaction_index]["gaslimit"]
                                    indv.generator.remove_gaslimit_from_pool(_function_hash, _gas_limit)

                                elif _str_var.startswith("blocknumber_"):
                                    _function_hash = indv.chromosome[transaction_index]["arguments"][0]
                                    _blocknumber = indv.chromosome[transaction_index]["blocknumber"]
                                    indv.generator.remove_blocknumber_from_pool(_function_hash, _blocknumber)

                                elif _str_var.startswith("timestamp_"):
                                    _function_hash = indv.chromosome[transaction_index]["arguments"][0]
                                    _timestamp = indv.chromosome[transaction_index]["timestamp"]
                                    indv.generator.remove_timestamp_from_pool(_function_hash, _timestamp)

                                elif _str_var.startswith("call_"):
                                    _function_hash = indv.chromosome[transaction_index]["arguments"][0]
                                    _var_split = str(var).split("_")
                                    _address = to_normalized_address(_var_split[2])
                                    _result = int(_var_split[3], 16)
                                    indv.generator.remove_callresult_from_pool(_function_hash, _address, _result)

                                elif _str_var.startswith("extcodesize"):
                                    _function_hash = indv.chromosome[transaction_index]["arguments"][0]
                                    _var_split = str(var).split("_")
                                    _address = to_normalized_address(_var_split[2])
                                    _size = int(_var_split[3], 16)
                                    indv.generator.remove_extcodesize_from_pool(_function_hash, _address, _size)

                                elif _str_var.startswith("returndatasize"):
                                    _function_hash = indv.chromosome[transaction_index]["arguments"][0]
                                    _var_split = str(var).split("_")
                                    _address = to_normalized_address(_var_split[2])
                                    _size = int(_var_split[3], 16)
                                    indv.generator.remove_returndatasize_from_pool(_function_hash, _address, _size)

                elif instruction["op"] == "BALANCE":
                    taint = BitVec("_".join(["balance", str(transaction_index)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                elif instruction["op"] in ["CALL", "STATICCALL"]:
                    _address_as_hex = to_hex(force_bytes_to_address(int_to_big_endian(convert_stack_value_to_int(result.trace[i]["stack"][-2]))))
                    if i + 1 < len(result.trace):
                        _result_as_hex = convert_stack_value_to_hex(result.trace[i + 1]["stack"][-1])
                    else:
                        _result_as_hex = ""

                    # ========== 原有代码继续 ==========
                    previous_call_address = _address_as_hex
                    call_type = "call"
                    if instruction["op"] == "STATICCALL":
                        call_type = "staticcall"
                    taint = BitVec("_".join([call_type, str(transaction_index), str(_address_as_hex), str(_result_as_hex), str(instruction["pc"])]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                elif instruction["op"] == "CALLER":
                    taint = BitVec("_".join(["caller", str(transaction_index)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                elif instruction["op"] == "CALLDATALOAD":
                    input_index = convert_stack_value_to_int(instruction["stack"][-1])
                    if input_index > 0 and _function_hash in env.interface:
                        input_index = int((input_index - 4) / 32)
                        if input_index < len(env.interface[_function_hash]):
                            parameter_type = env.interface[_function_hash][input_index]
                            if '[' in parameter_type:
                                array_size_index = convert_stack_value_to_int(result.trace[i + 1]["stack"][-1]) / 32
                                _array_size_indexes[array_size_index] = input_index
                            elif "bytes" in parameter_type:
                                pass
                            else:
                                taint = BitVec("_".join(["calldataload",
                                                         str(transaction_index),
                                                         str(input_index)
                                                         ]), 256)
                                env.symbolic_taint_analyzer.introduce_taint(taint, instruction)
                        else:
                            if input_index in _array_size_indexes:
                                array_size = convert_stack_value_to_int(result.trace[i + 1]["stack"][-1])
                                taint = BitVec("_".join(["inputarraysize",
                                                         str(transaction_index),
                                                         str(_array_size_indexes[input_index])
                                                         ]), 256)
                                env.symbolic_taint_analyzer.introduce_taint(taint, instruction)
                            else:
                                pass

                elif instruction["op"] == "CALLDATACOPY":
                    destOffset = convert_stack_value_to_int(instruction["stack"][-1])
                    offset = convert_stack_value_to_int(instruction["stack"][-2])
                    array_start_index = (offset - 4) / 32
                    lenght = convert_stack_value_to_int(instruction["stack"][-3])

                    if array_start_index - 1 in _array_size_indexes:
                        taint = BitVec("_".join(["calldatacopy",
                                                 str(transaction_index),
                                                 str(_array_size_indexes[array_start_index - 1])
                                                 ]), 256)
                        env.symbolic_taint_analyzer.introduce_taint(taint, instruction)
                    else:
                        pass

                elif instruction["op"] == "CALLDATASIZE":
                    taint = BitVec("_".join(["calldatasize", str(transaction_index)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                elif instruction["op"] == "CALLVALUE":
                    taint = BitVec("_".join(["callvalue", str(transaction_index)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                elif instruction["op"] == "GAS":
                    taint = BitVec("_".join(["gas", str(transaction_index)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                # BLOCK Opcodes
                elif instruction["op"] == "BLOCKHASH":
                    taint = BitVec("_".join(["blockhash", str(transaction_index)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                elif instruction["op"] == "COINBASE":
                    taint = BitVec("_".join(["coinbase", str(transaction_index)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                elif instruction["op"] == "TIMESTAMP":
                    taint = BitVec("_".join(["timestamp", str(transaction_index)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                elif instruction["op"] == "NUMBER":
                    taint = BitVec("_".join(["blocknumber", str(transaction_index)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                elif instruction["op"] == "DIFFICULTY":
                    taint = BitVec("_".join(["difficulty", str(transaction_index)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                elif instruction["op"] == "GASLIMIT":
                    taint = BitVec("_".join(["gaslimit", str(transaction_index)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                elif instruction["op"] == "EXTCODESIZE":
                    _address_as_hex = to_hex(
                        force_bytes_to_address(int_to_big_endian(convert_stack_value_to_int(result.trace[i]["stack"][-1]))))
                    if i + 1 < len(result.trace):
                        _result_as_hex = convert_stack_value_to_hex(result.trace[i + 1]["stack"][-1])
                    else:
                        _result_as_hex = ""
                    taint = BitVec("_".join(["extcodesize", str(transaction_index), str(_address_as_hex), str(_result_as_hex)]), 256)
                    env.symbolic_taint_analyzer.introduce_taint(taint, instruction)

                elif instruction["op"] == "RETURNDATASIZE":
                    if previous_call_address:
                        if i + 1 < len(result.trace):
                            _size = convert_stack_value_to_int(result.trace[i + 1]["stack"][-1])
                        else:
                            _size = 0
                        taint = BitVec("_".join(["returndatasize", str(transaction_index), previous_call_address, str(_size)]), 256)
                        env.symbolic_taint_analyzer.introduce_taint(taint, instruction)
                elif instruction["op"] == "CODECOPY":
                    offset = convert_stack_value_to_int(instruction["stack"][-2])
                    length = convert_stack_value_to_int(instruction["stack"][-3])
                    codecopy_params = (offset, length)
                elif instruction["op"] in ["CREATE", "CREATE2"]:
                    offset, length = codecopy_params
                    contract, success = self.env.cfg.extract_embedded_contract_from_codecopy(
                        offset, length, instruction["pc"], instruction["op"]
                    )
                    # 收集嵌入合约统计信息用于覆盖率修正
                    if success:
                        self._collect_embedded_contract_stats(contract)
                        self.logger.info(f"Extracted embedded contract!")


                if instruction["op"] in self.Critical_opcode:
                    critical_opcode.add(str(instruction["op"]))

                previous_instruction = instruction
            
            if result.trace[-1]["op"] == "REVERT" and convert_stack_value_to_int(result.trace[-1]["stack"][-1])==0:
                env.revert_tx += 1

            env.symbolic_taint_analyzer.clear_callstack()
            if _function_hash == 'fallback':
                env.txdata2dis["00000000"].append(t2d)
            else:
                env.txdata2dis[_function_hash].append(t2d)
            
            function_hash = transaction["data"][:10] if transaction["data"].startswith("0x") else transaction["data"][:8]
            function_hash = "00000000" if function_hash == '' else function_hash
            if function_hash != _function_hash:
                t2ds.append([function_hash,t2d])
            else:
                t2ds.append([_function_hash,t2d])
            

            if not result.is_error and not transaction["to"]:
                contract_address = encode_hex(result.msg.storage_address)

        env.individual_branches[indv.hash] = branches

        env.symbolic_taint_analyzer.clear_storage()
        env.instrumented_evm.restore_from_snapshot()

        # 采集覆盖率快照用于后续可视化
        if hasattr(env, 'coverage_analyzer') and hasattr(env, 'overall_pcs'):
            env.coverage_analyzer.capture_snapshot(
                env.overall_pcs,
                env.code_coverage,
                env.embedded_contract_stats
            )

        if t2ds is None:
            print("t2ds is None")

        return t2ds, critical_opcode, mutate_require_list, raw_news_list, [mock_detect_call_success, mock_detect_call_fail]

    def _find_actual_condition(self, trace, iszero_index):
        """
        反向回溯寻找ISZERO操作码前的实际条件
        """
        if iszero_index < 1:
            return None

        # 常见的比较操作码
        comparison_ops = ["EQ", "LT", "GT", "SLT", "SGT", "AND", "OR", "XOR"]
        
        # 检查前一个操作码
        prev_op = trace[iszero_index-1]["op"]
        if prev_op in comparison_ops:
            return self._calculate_comparison_result(prev_op, trace[iszero_index-1])
            
        # 检查NOT操作的情况
        if prev_op == "NOT" and iszero_index > 1:
            prev_prev_op = trace[iszero_index-2]["op"]
            if prev_prev_op in comparison_ops:
                return self._calculate_comparison_result(prev_prev_op, trace[iszero_index-2], negated=True)
                
        return None

    def _calculate_comparison_result(self, op, instruction, negated=False):
        """
        计算比较操作的结果
        """
        if len(instruction["stack"]) < 2:
            return None
            
        # 获取比较的两个值
        val1 = convert_stack_value_to_int(instruction["stack"][-1])
        val2 = convert_stack_value_to_int(instruction["stack"][-2])
        
        # 计算比较结果
        if op == "EQ":
            result = 1 if val1 == val2 else 0
        elif op == "LT":
            result = 1 if val1 < val2 else 0
        elif op == "GT":
            result = 1 if val1 > val2 else 0
        elif op == "SLT":
            result = 1 if val1 < val2 else 0
        elif op == "SGT":
            result = 1 if val1 > val2 else 0
        elif op == "AND":
            result = 1 if (val1 & val2) != 0 else 0
        elif op == "OR":
            result = 1 if (val1 | val2) != 0 else 0
        elif op == "XOR":
            result = 1 if (val1 ^ val2) != 0 else 0
        else:
            return None
            
        # 如果被NOT操作取反，则取反结果
        if negated:
            result = 1 - result
            
        return result

    def get_coverage_with_children(self, children_code_coverage, code_coverage):
        code_coverage = len(code_coverage)

        for child_cc in children_code_coverage:
            code_coverage += len(child_cc)
        return code_coverage

    def symbolic_execution(self, indv_generator):
        if not self.env.args.constraint_solving:
            return

        for index, pc in enumerate(self.env.visited_branches):
            self.logger.debug("b(%d) pc : %s - visited branches : %s", index, pc,
                               self.env.visited_branches[pc].keys())

            if len(self.env.visited_branches[pc]) != 1:
                continue

            branch, _d = next(iter(self.env.visited_branches[pc].items()))

            if not _d["expression"]:
                self.logger.debug("No expression for b(%d) pc : %s", index, pc)
                continue

            negated_branch = simplify(Not(_d["expression"][-1]))

            if negated_branch in self.env.memoized_symbolic_execution:
                continue

            self.env.solver.reset()
            for expression_index in range(len(_d["expression"]) - 1):
                expression = simplify(_d["expression"][expression_index])
                self.env.solver.add(expression)
            self.env.solver.add(negated_branch)

            check = self.env.solver.check()

            if check == sat:
                model = self.env.solver.model()

                self.logger.debug("(%s) Symbolic Solution to branch %s: %s ", _d["indv_hash"], pc,
                                  "; ".join([str(x)+" ("+str(model[x])+")" for x in model]))

                for variable in model:
                    if str(variable).startswith("underflow"):
                        continue

                    var_split = str(variable).split("_")
                    transaction_index = int(var_split[1])

                    if str(variable).startswith("balance"):
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        opt = Optimize()
                        for expression_index in range(len(_d["expression"]) - 1):
                            opt.add(_d["expression"][expression_index])
                        opt.add(negated_branch)
                        check = opt.check()
                        if check == sat:
                            opt_model = opt.model()
                            balance = int(opt_model[variable].as_long())
                            if _d["chromosome"][transaction_index]["contract"]:
                                indv_generator.add_balance_to_pool(_function_hash, self.env.instrumented_evm.get_balance(
                                    to_canonical_address(_d["chromosome"][transaction_index]["contract"])))
                            indv_generator.add_balance_to_pool(_function_hash, balance)

                    elif str(variable).startswith("blocknumber"):
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        blocknumber = int(model[variable].as_long())
                        indv_generator.add_blocknumber_to_pool(_function_hash,
                                                               self.env.instrumented_evm.vm.state.block_number)
                        indv_generator.add_blocknumber_to_pool(_function_hash, blocknumber)

                    elif str(variable).startswith("call_") or str(variable).startswith("staticcall_"):
                        address = to_normalized_address(var_split[2])
                        old_result = int(var_split[3], 16)
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        new_result = 1 - old_result
                        indv_generator.add_callresult_to_pool(_function_hash, address, old_result)
                        indv_generator.add_callresult_to_pool(_function_hash, address, new_result)

                    elif str(variable).startswith("caller_"):
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        if model[variable].as_long() > 8 and model[variable].as_long() < 2**160:
                            account_address = normalize_32_byte_hex_address("0x"+hex(model[variable].as_long()).replace("0x", "").zfill(40))
                            if not self.env.instrumented_evm.has_account(account_address):
                                self.env.instrumented_evm.restore_from_snapshot()
                                self.env.instrumented_evm.accounts.append(self.env.instrumented_evm.create_fake_account(account_address))
                                self.env.instrumented_evm.create_snapshot()
                            indv_generator.add_account_to_pool(_function_hash, _d["chromosome"][transaction_index]["account"])
                            indv_generator.add_account_to_pool(_function_hash, account_address)

                    elif str(variable).startswith("calldatacopy_"):
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        parameter_index = int(var_split[2])
                        if "[" in indv_generator.interface[_function_hash][parameter_index]:
                            if indv_generator.interface[_function_hash][parameter_index].startswith("int"):
                                argument = model[variable].as_signed_long()
                            elif indv_generator.interface[_function_hash][parameter_index].startswith("address"):
                                try:
                                    _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                                    argument = normalize_32_byte_hex_address(hex(model[variable].as_long()))
                                    if not self.env.instrumented_evm.has_account(argument):
                                        self.env.instrumented_evm.restore_from_snapshot()
                                        self.env.instrumented_evm.accounts.append(self.env.instrumented_evm.create_fake_account(argument))
                                        self.env.instrumented_evm.create_snapshot()
                                except Exception as e:
                                    self.logger.error("(%s) [symbolic execution : calldatacopy ] %s", _function_hash,
                                                       e)
                                    continue
                            else:
                                argument = model[variable].as_long()
                            indv_generator.add_argument_to_pool(_function_hash, parameter_index, _d["chromosome"][transaction_index]["arguments"][parameter_index + 1])
                            indv_generator.add_argument_to_pool(_function_hash, parameter_index, argument)

                    elif str(variable).startswith("calldataload_"):
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        parameter_index = int(var_split[2])
                        # TODO: THE SOLVER DOES NOT CONSIDER THE MAX SIZE OF THE VARIABLE
                        #   GENERATING LATER A eth_abi.exceptions.ValueOutOfBounds
                        if "[" in indv_generator.interface[_function_hash][parameter_index]:
                            if indv_generator.interface[_function_hash][parameter_index].startswith("int"):
                                argument = model[variable].as_signed_long()
                            elif indv_generator.interface[_function_hash][parameter_index].startswith("address"):
                                try:
                                    _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                                    argument = normalize_32_byte_hex_address(hex(model[variable].as_long()))
                                    if not self.env.instrumented_evm.has_account(argument):
                                        self.env.instrumented_evm.restore_from_snapshot()
                                        self.env.instrumented_evm.accounts.append(self.env.instrumented_evm.create_fake_account(argument))
                                        self.env.instrumented_evm.create_snapshot()
                                except Exception as e:
                                    self.logger.error("(%s) [symbolic execution : calldataload ] %s", _function_hash,
                                                       e)
                                    continue

                        elif indv_generator.interface[_function_hash][parameter_index].startswith("int"):
                            argument = model[variable].as_signed_long()

                        elif indv_generator.interface[_function_hash][parameter_index] == "address":
                            try:
                                _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                                argument = to_hex(
                                    force_bytes_to_address(int_to_big_endian(int(model[variable].as_long()))))
                                if not self.env.instrumented_evm.has_account(argument):
                                    self.env.instrumented_evm.restore_from_snapshot()
                                    self.env.instrumented_evm.accounts.append(self.env.instrumented_evm.create_fake_account(argument))
                                    self.env.instrumented_evm.create_snapshot()
                            except Exception as e:
                                self.logger.error("(%s) [symbolic execution : calldataload ] %s", _function_hash, e)
                                continue

                        elif indv_generator.interface[_function_hash][parameter_index] == "string":
                            argument = _d["chromosome"][transaction_index]["arguments"][parameter_index + 1]
                        elif indv_generator.interface[_function_hash][parameter_index].startswith("uint"):
                            argument = model[variable].as_long()
                            bits = 256
                            if indv_generator.interface[_function_hash][parameter_index] != "uint":
                                bits = int(indv_generator.interface[_function_hash][parameter_index].replace("uint", ""))
                            base = 1 << bits
                            argument %= base
                        else:
                            argument = model[variable].as_long()
                            self.env.solver.add(BitVec(str(variable), 256) != BitVecVal(0, 256))
                            for variable_2 in model:
                                if variable_2 != variable and str(variable_2).startswith("callvalue"):
                                    callvalue_index = int(str(variable_2).split("_")[1])
                                    self.env.solver.add(BitVec(str(variable_2), 256) == BitVecVal(int(_d["chromosome"][callvalue_index]["amount"]), 256))
                            check = self.env.solver.check()
                            if check == sat:
                                model = self.env.solver.model()
                                argument = model[variable].as_long()

                        indv_generator.add_argument_to_pool(_function_hash, parameter_index, _d["chromosome"][transaction_index]["arguments"][parameter_index + 1])
                        indv_generator.add_argument_to_pool(_function_hash, parameter_index, argument)

                    elif str(variable).startswith("callvalue_"):
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        amount = model[variable].as_long()
                        if amount > settings.ACCOUNT_BALANCE:
                            amount = settings.ACCOUNT_BALANCE
                        indv_generator.remove_amount_from_pool(_function_hash, 0)
                        indv_generator.remove_amount_from_pool(_function_hash, 1)
                        indv_generator.add_amount_to_pool(_function_hash, _d["chromosome"][transaction_index]["amount"])
                        indv_generator.add_amount_to_pool(_function_hash, amount)

                    elif str(variable).startswith("gas_"):
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        indv_generator.add_gaslimit_to_pool(_function_hash, _d["chromosome"][transaction_index]["gaslimit"])
                        indv_generator.add_gaslimit_to_pool(_function_hash, model[variable].as_long())

                    elif str(variable).startswith("inputarraysize"):
                        opt = Optimize()
                        for expression_index in range(len(_d["expression"]) - 1):
                            opt.add(_d["expression"][expression_index])
                        opt.add(negated_branch)
                        check = opt.check()
                        if check == sat:
                            opt_model = opt.model()
                            array_size = opt_model[variable].as_long()
                            _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                            parameter_index = int(var_split[2])
                            indv_generator.add_parameter_array_size(_function_hash, parameter_index, len(
                                _d["chromosome"][transaction_index]["arguments"][parameter_index + 1]))
                            indv_generator.add_parameter_array_size(_function_hash, parameter_index, array_size)

                    elif str(variable).startswith("timestamp"):
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        timestamp = int(model[variable].as_long())
                        indv_generator.add_timestamp_to_pool(_function_hash, self.env.instrumented_evm.vm.state.timestamp)
                        indv_generator.add_timestamp_to_pool(_function_hash, timestamp)

                    elif str(variable).startswith("calldatasize"):
                        pass

                    elif str(variable).startswith("extcodesize"):
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        _address = to_normalized_address(var_split[2])
                        indv_generator.add_extcodesize_to_pool(_function_hash, _address, int(var_split[3], 16))
                        indv_generator.add_extcodesize_to_pool(_function_hash, _address, int(model[variable].as_long()))

                    elif str(variable).startswith("returndatasize"):
                        _function_hash = _d["chromosome"][transaction_index]["arguments"][0]
                        _address = to_normalized_address(var_split[2])
                        _size = int(var_split[3], 16)
                        indv_generator.add_returndatasize_to_pool(_function_hash, _address, int(var_split[3], 16))
                        indv_generator.add_returndatasize_to_pool(_function_hash, _address, int(model[variable].as_long()))

                    else:
                        self.logger.warning("Unknown symbolic variable: %s ", str(variable))

            self.env.memoized_symbolic_execution[negated_branch] = True

    def finalize(self, population, engine):
        execution_end = time.time()
        execution_delta = execution_end - self.env.execution_begin

        self.logger.title("-----------------------------------------------------")
        msg = 'Vul of Contracts: \t {}'.format(self.env.errors_list)
        self.logger.info(msg)
        msg = 'Number of generations: \t {}'.format(engine.current_generation + 1)
        self.logger.info(msg)
        msg = 'Number of transactions: \t {} ({} unique)'.format(self.env.nr_of_transactions, len(self.env.unique_individuals))
        self.logger.info(msg)
        msg = 'Transactions per second: \t {:.0f}'.format(self.env.nr_of_transactions / execution_delta)
        self.logger.info(msg)
        msg = 'Transactions revert: \t {:.2f} ({}/{})'.format(self.env.revert_tx / self.env.nr_of_transactions, self.env.revert_tx, self.env.nr_of_transactions)
        self.logger.info(msg)

        # 使用修正后的覆盖率计算（考虑嵌入合约字节码）
        code_coverage_percentage, corrected_total_pcs, branch_coverage_percentage, branch_coverage,corrected_total_branches = self._calculate_corrected_coverage()

        # msg = 'Total code coverage (corrected): \t {:.2f}% ({}/{})'.format(code_coverage_percentage,
        #                                                         len(self.env.code_coverage),
        #                                                         len(self.env.overall_pcs))
        msg = 'Total code coverage (corrected): \t {:.2f}% ({}/{})'.format(code_coverage_percentage,
                                                                len(self.env.code_coverage),
                                                                corrected_total_pcs)
        self.logger.info(msg)
        # msg = 'Total branch coverage (corrected): \t {:.2f}% ({}/{})'.format(branch_coverage_percentage,
        #                                                          branch_coverage, len(self.env.overall_jumpis) * 2)
        msg = 'Total branch coverage (corrected): \t {:.2f}% ({}/{})'.format(branch_coverage_percentage,
                                                                 branch_coverage, corrected_total_branches)
        self.logger.info(msg)
        msg = 'Total execution time: \t {:.2f} seconds'.format(execution_delta)
        self.logger.info(msg)
        msg = 'Total memory consumption: \t {:.2f} MB'.format(psutil.Process(os.getpid()).memory_info().rss/1024/1024)
        self.logger.info(msg)

        # Save to results
        self.env.results["transactions"] = {"total": self.env.nr_of_transactions,
                                            "per_second": self.env.nr_of_transactions / execution_delta}
        self.env.results["code_coverage"] = {"percentage": code_coverage_percentage,
                                             "covered": len(self.env.code_coverage),
                                             "total": len(self.env.overall_pcs),
                                             "covered_with_children": self.get_coverage_with_children(
                                                 self.env.children_code_coverage,
                                                 self.env.code_coverage),
                                             "total_with_children": self.env.len_overall_pcs_with_children
                                             }
        self.env.results["branch_coverage"] = {"percentage": branch_coverage_percentage,
                                               "covered": branch_coverage,
                                               "total": len(self.env.overall_jumpis) * 2}
        self.env.results["execution_time"] = execution_delta
        self.env.results["memory_consumption"] = psutil.Process(os.getpid()).memory_info().rss/1024/1024
        self.env.results["address_under_test"] = self.env.population.indv_generator.contract
        self.env.results["seed"] = self.env.seed
        self.env.results["revert_tx"] = [self.env.nr_of_transactions, self.env.revert_tx]

        #  Write results to file
        if self.env.args.results:
            results = {}
            if self.env.args.results.lower().endswith(".json"):
                if os.path.exists(self.env.args.results):
                    with open(self.env.args.results, 'r') as file:
                        results = json.load(file)
                results[self.env.contract_name] = self.env.results
                with open(self.env.args.results, 'w') as file:
                    json.dump(results, file)
            else:
                if os.path.exists(self.env.args.results + '/' + os.path.splitext(os.path.basename(self.env.contract_name))[0] + '.json'):
                    with open(self.env.args.results + '/' + os.path.splitext(os.path.basename(self.env.contract_name))[0] + '.json', 'r') as file:
                        results = json.load(file)
                results[self.env.contract_name] = self.env.results
                with open(self.env.args.results + '/' + os.path.splitext(os.path.basename(self.env.contract_name))[0] + '.json', 'w') as file:
                    json.dump(results, file)

        diff = list(set(self.env.code_coverage).symmetric_difference(set([hex(x) for x in self.env.overall_pcs])))
        self.logger.debug("Instructions not executed: %s", sorted(diff))

    def _update_incremental_stats(self, feature_vector, target_value):
        """
        增量更新统计信息
        """
        self.total_samples += 1
        
        # 更新特征统计
        for i, feature_value in enumerate(feature_vector):
            if i not in self.feature_stats:
                self.feature_stats[i] = defaultdict(int)
            self.feature_stats[i][feature_value] += 1
            
        # 更新目标统计
        if target_value not in self.target_stats:
            self.target_stats[target_value] = 0
        self.target_stats[target_value] += 1
        
        # 更新联合统计
        for i, feature_value in enumerate(feature_vector):
            if i not in self.joint_stats:
                self.joint_stats[i] = defaultdict(lambda: defaultdict(int))
            self.joint_stats[i][feature_value][target_value] += 1

    def _calculate_incremental_ig(self, feature_idx):
        """
        计算单个特征的增量信息增益
        """
        # 计算目标变量的熵
        target_entropy = self._calculate_entropy(self.target_stats)
        
        # 计算条件熵
        conditional_entropy = 0.0
        for feature_value in self.feature_stats[feature_idx]:
            # 计算特征值出现的概率
            p_feature = self.feature_stats[feature_idx][feature_value] / self.total_samples
            
            # 计算给定特征值时的条件概率分布
            conditional_dist = self.joint_stats[feature_idx][feature_value]
            conditional_entropy += p_feature * self._calculate_entropy(conditional_dist)
        
        return target_entropy - conditional_entropy

    def _calculate_entropy(self, distribution):
        """
        计算概率分布的熵
        """
        entropy = 0.0
        total = sum(distribution.values())
        for count in distribution.values():
            p = count / total
            if p > 0:
                entropy -= p * log2(p)
        return entropy

    def _apply_sliding_window(self):
        """
        应用滑动窗口机制
        """
        if self.total_samples <= self.window_size:
            return
            
        # 计算需要移除的样本数
        remove_count = self.total_samples - self.window_size
        
        # 更新统计信息
        self._remove_old_samples(remove_count)
        self.total_samples = self.window_size

    def _remove_old_samples(self, count):
        """
        移除最旧的count个样本的统计信息
        """
        # 实现统计信息的衰减
        decay_factor = 0.9  # 衰减因子
        
        for feature_idx in self.feature_stats:
            for value in self.feature_stats[feature_idx]:
                self.feature_stats[feature_idx][value] *= decay_factor
                
        for target_value in self.target_stats:
            self.target_stats[target_value] *= decay_factor
            
        for feature_idx in self.joint_stats:
            for feature_value in self.joint_stats[feature_idx]:
                for target_value in self.joint_stats[feature_idx][feature_value]:
                    self.joint_stats[feature_idx][feature_value][target_value] *= decay_factor

    