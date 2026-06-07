#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from utils.coverage_analyzer import CoverageAnalyzer

class FuzzingEnvironment:
    def __init__(self, **kwargs) -> None:
        self.nr_of_transactions = 0
        self.unique_individuals = set()
        self.code_coverage = set()
        self.children_code_coverage = dict()
        self.previous_code_coverage_length = 0

        self.visited_branches = dict()

        # 自适应阈值相关变量
        self.seeds_since_last_coverage_improvement = 0  # 停滞种子计数
        self.last_code_coverage_size = 0                # 上次代码覆盖率大小
        self.last_branch_coverage_size = 0              # 上次分支覆盖率大小

        # 嵌入合约覆盖率修正相关统计
        self.embedded_contract_stats = {
            'total_pcs': set(),           # 嵌入合约的所有PC集合
            'covered_pcs': set(),         # 嵌入合约中已覆盖的PC集合
            'bytecode_blocks_branches': 0,  # 嵌入合约字节码block向外的分支数
            'processed_contract_pcs': set()  # 已统计过的合约PC（去重用）
        }

        self.memoized_fitness = dict()
        self.memoized_storage = dict()
        self.memoized_symbolic_execution = dict()
        # Store calculated energies for analysis
        self.memoized_energies = dict()

        self.individual_branches = dict()

        self.data_dependencies = dict()
        self.dep_data = dict()
        self.example_tx = dict()
        self.revert_tx = 0

        # 初始化覆盖率分析器
        self.coverage_analyzer = CoverageAnalyzer()

        # 外部调用返回值模拟策略数据（可选）
        self.mock_return_values = None

        self.__dict__.update(kwargs)
    
    def addinfo(self,unvisited_branches,jumpi_analyzer,fit_info=None):
        #保存未访问的分支
        self.unvisited_branches = unvisited_branches
        self.txdata2dis = dict()
        self.fit_info = fit_info
        self.fit_tx2dis_res = dict()
        self.tx2influ = dict()
        self.symbolic_execution_count=0
        self.errors_list = []
        self.vul_bran_weight = {}
        self.jumpi_analyzer = jumpi_analyzer
        self.errorsdic = {}
        self.key_var = {}
        self.require_key_fun = []
        self.snapshot = {}
        return self
    
    def add_snapshot(self,state_name,require_index,snapshot):
        if state_name not in self.snapshot:
            self.snapshot[state_name] = {}
        self.snapshot[state_name][require_index] = {
            "snapshot":snapshot
        }
        # return self
    
    def get_snapshot(self,keylist):
        state_name,require_index = keylist
        if state_name in self.snapshot and require_index[0] in self.snapshot[state_name]:
            return self.snapshot[state_name][require_index[0]]["snapshot"]
        else:
            return None
        # return self.snapshot[state_name][require_index[0]]["snapshot"]
    
    def select_maxweight_snapshot(self):
        sn = None
        inde = 0
        weight = 0 
        for state_name in self.snapshot:
            for index in range(len(self.snapshot[state_name])):
                if not sn:
                    sn = state_name
                    inde = index
                    weight = self.key_var[state_name][index][2]
                else:
                    if self.key_var[state_name][index][2] > weight:
                        sn = state_name
                        inde = index
                        weight = self.key_var[state_name][index][2]
        
        return sn, inde


    def remove_snapshot(self,state_name,require_index):
        del self.snapshot[state_name][require_index]