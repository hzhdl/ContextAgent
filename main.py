#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import math
import os
import sys
import time
import json
import solcx
import random
import logging
import argparse

from eth_utils import encode_hex, decode_hex, to_canonical_address
from z3 import Solver

from evm import InstrumentedEVM
from detectors import DetectorExecutor
from engine import EvolutionaryFuzzingEngine
from engine.components import Generator, Individual, Population
from engine.analysis import SymbolicTaintAnalyzer
from engine.analysis import ExecutionTraceAnalyzer
from engine.environment import FuzzingEnvironment
from engine.operators import LinearRankingSelection
from engine.operators import DataDependencyLinearRankingSelection
from engine.operators import Crossover
from engine.operators import DataDependencyCrossover
from engine.operators import Mutation
from engine.fitness import fitness_function
from eth.constants import ZERO_ADDRESS, CREATE_CONTRACT_ADDRESS
import utils.settings as settings
from utils.source_map import SourceMap
from utils.utils import initialize_logger, compile, get_interface_from_abi, get_pcs_and_jumpis, get_function_signature_mapping, get_signature_function_mapping, get_functions_from_abi
from utils.control_flow_graph import ControlFlowGraph
from utils.raw_analysis import get_tx_list
from utils.jumpi_analyzer import JumpiAnalyzer
from utils.solc_version_manager import get_compiler_config, ensure_solc_installed

from typing import List, Dict, Any, Optional
import copy

def bucketize_per_second(
    records: List[Dict[str, Any]],
    total_seconds: int = 200,
    initial_entry: Optional[Dict[str, Any]] = None
) -> List[Optional[Dict[str, Any]]]:
    """
    将实验记录按秒聚合：第 s 秒取所有 time ≤ s 的最后一条；若无则沿用上一秒。
    输出长度为动态：不强制到 total_seconds；而是到最后一条记录所在秒（向下取整）或 total_seconds 中较小者。

    参数：
      - records: 每条包含 'time'（秒）的字典
      - total_seconds: 上限秒数（含 0），默认 200（仅作上限，不强制填满）
      - initial_entry: 可选的初始快照（用于 0 秒无数据时的基线）

    返回：
      - 长度为 horizon+1 的列表（0..horizon），每个元素是该秒的快照（深拷贝），并包含键 'sec' 标注秒数；
        若在此秒之前没有任何数据且无基线，则该秒为 None。
    """
    # 无任何记录时，仅返回 0 秒的结果（使用基线或 None）
    if not records:
        if initial_entry is None:
            return [None]
        snap = copy.deepcopy(initial_entry)
        snap['sec'] = 0
        return [snap]

    # 按时间排序，并确定聚合的终止秒（horizon）
    recs = sorted(records, key=lambda r: float(r.get('time', 0)))
    last_time = float(recs[-1].get('time', 0))
    horizon = int(min(total_seconds, math.ceil(max(0.0, last_time))))  # 向下取整且不超过上限

    result: List[Optional[Dict[str, Any]]] = []
    idx = 0
    last: Optional[Dict[str, Any]] = copy.deepcopy(initial_entry) if initial_entry is not None else None

    for sec in range(0, horizon + 1):
        # 吃掉所有 time ≤ sec 的记录，保留最后一条
        while idx < len(recs) and float(recs[idx].get('time', 0)) <= sec:
            last = recs[idx]
            idx += 1

        if last is None:
            result.append(None)
        else:
            snap = copy.deepcopy(last)
            snap['sec'] = sec  # 标注当前是第几秒的快照
            result.append(snap)

    return result

class Fuzzer:
    def __init__(self, contract_name, abi, deployment_bytecode, runtime_bytecode, test_instrumented_evm, blockchain_state, solver, args, seed, source_map=None):
        global logger

        logger = initialize_logger("Fuzzer  ")
        logger.title("Fuzzing contract %s", contract_name)

        cfg = ControlFlowGraph()
        cfg.build(runtime_bytecode, settings.EVM_VERSION)

        self.contract_name = contract_name
        self.interface = get_interface_from_abi(abi)
        self.deployement_bytecode = deployment_bytecode
        self.blockchain_state = blockchain_state
        self.instrumented_evm = test_instrumented_evm
        self.solver = solver
        self.args = args

        # Get some overall metric on the code
        self.overall_pcs, self.overall_jumpis = get_pcs_and_jumpis(runtime_bytecode)
        self.unvisited_branches = dict()
        for jumpis in self.overall_jumpis:
            self.unvisited_branches[jumpis] = 0

        # Initialize results
        self.results = {"errors": {}}

        # Initialize fuzzing environment
        self.env = FuzzingEnvironment(instrumented_evm=self.instrumented_evm,
                                      contract_name=self.contract_name,
                                      solver=self.solver,
                                      results=self.results,
                                      symbolic_taint_analyzer=SymbolicTaintAnalyzer(),
                                      detector_executor=DetectorExecutor(source_map, get_function_signature_mapping(abi)),
                                      interface=self.interface,
                                      overall_pcs=self.overall_pcs,
                                      overall_jumpis=self.overall_jumpis,
                                      len_overall_pcs_with_children=0,
                                      other_contracts = list(),
                                      args=args,
                                      seed=seed,
                                      cfg=cfg,
                                      abi=abi).addinfo(self.unvisited_branches,JumpiAnalyzer())

        # 保存初始CFG（如果启用）
        if settings.SAVE_CFG_JSON_ENABLE and args.source:
            source_dir = os.path.dirname(os.path.abspath(args.source))
            initial_cfg_path = os.path.join(source_dir, f"{args.source.split('/')[-1].split('.')[0]}_cfg_static.json")
            cfg.save_to_json(initial_cfg_path, deployment_bytecode=deployment_bytecode)

    def run(self):
        contract_address = None
        self.instrumented_evm.create_fake_accounts()
        self.env.resfile = self.args.resfile
        self.env.file_name = self.args.source.split('/')[-1].split('.')[0]

        generator_constructor = Generator(interface=self.interface,
                              bytecode=self.deployement_bytecode,
                              accounts=self.instrumented_evm.accounts,
                              contract=contract_address)

        if self.args.source:
            for transaction in self.blockchain_state:
                if transaction['from'].lower() not in self.instrumented_evm.accounts:
                    self.instrumented_evm.accounts.append(self.instrumented_evm.create_fake_account(transaction['from']))

                if not transaction['to']:
                    result = self.instrumented_evm.deploy_contract(transaction['from'], transaction['input'], int(transaction['value']), int(transaction['gas']), int(transaction['gasPrice']))
                    if result.is_error:
                        logger.error("Problem while deploying contract %s using account %s. Error message: %s", self.contract_name, transaction['from'], result._error)
                        #sys.exit(-2)
                        return None,None
                    else:
                        contract_address = encode_hex(result.msg.storage_address)
                        self.instrumented_evm.accounts.append(contract_address)
                        self.env.nr_of_transactions += 1
                        logger.debug("Contract deployed at %s", contract_address)
                        self.env.other_contracts.append(to_canonical_address(contract_address))
                        cc, _ = get_pcs_and_jumpis(self.instrumented_evm.get_code(to_canonical_address(contract_address)).hex())
                        self.env.len_overall_pcs_with_children += len(cc)
                else:
                    input = {}
                    input["block"] = {}
                    input["transaction"] = {
                        "from": transaction["from"],
                        "to": transaction["to"],
                        "gaslimit": int(transaction["gas"]),
                        "value": int(transaction["value"]),
                        "data": transaction["input"]
                    }
                    input["global_state"] = {}
                    out = self.instrumented_evm.deploy_transaction(input, int(transaction["gasPrice"]))
            tmp_interface = None
            tmp_arguments = self.deployement_bytecode
            retry_arguments = []
            if "constructor" in self.interface or self.contract_name in self.interface: 
                if self.interface["constructor"] or self.contract_name in self.interface:
                    tmp_interface = self.interface["constructor"] if self.interface["constructor"] else self.contract_name
                    tmp_indv_con =  Individual(generator=generator_constructor).init_constructor(
                        generator_constructor.get_random_argument_constructor(self.interface["constructor"],self.deployement_bytecode,
                                                                    self.instrumented_evm.accounts[0],CREATE_CONTRACT_ADDRESS)).decode()
                    tmp_arguments = tmp_indv_con[0]["transaction"]["data"]
                    for i in range(3):
                        retry_tmp_indv_con =  Individual(generator=generator_constructor).init_constructor(
                        generator_constructor.get_random_argument_constructor(self.interface["constructor"],self.deployement_bytecode,
                                                                    self.instrumented_evm.accounts[0],CREATE_CONTRACT_ADDRESS)).decode()
                        retry_tmp_arguments = retry_tmp_indv_con[0]["transaction"]["data"]
                        retry_arguments.append(retry_tmp_arguments)
                if "constructor" in self.interface:
                    del self.interface["constructor"]
                if self.contract_name in self.interface:
                    del self.interface[self.contract_name]
                

            if not contract_address:
                if "constructor" not in self.interface:
                    retry = 0
                    result = self.instrumented_evm.deploy_contract(self.instrumented_evm.accounts[0], tmp_arguments)
                    while retry < 3 and len(retry_arguments) == 3:
                        if result.is_error:
                            result = self.instrumented_evm.deploy_contract(self.instrumented_evm.accounts[0], retry_arguments[retry])
                            logger.info("Retry to deploy contract.")
                            retry+=1
                            continue
                        else:
                            break

                    if result.is_error:
                        logger.error("Problem while deploying contract %s using account %s. Error message: %s", self.contract_name, self.instrumented_evm.accounts[0], result._error)
                        # sys.exit(-2)
                        return None,None
                    else:
                        contract_address = encode_hex(result.msg.storage_address)
                        self.instrumented_evm.accounts.append(contract_address)
                        self.env.nr_of_transactions += 1
                        print("Contract deployed at %s", contract_address)

            

            if contract_address in self.instrumented_evm.accounts:
                self.instrumented_evm.accounts.remove(contract_address)

            self.env.overall_pcs, self.env.overall_jumpis = get_pcs_and_jumpis(self.instrumented_evm.get_code(to_canonical_address(contract_address)).hex())

        if self.args.abi:
            contract_address = self.args.contract

        self.instrumented_evm.create_snapshot()

        # print("------------",self.instrumented_evm.MAX_CONTRACT_CODE_SIZE)
        

        generator = Generator(interface=self.interface,
                              bytecode=self.deployement_bytecode,
                              accounts=self.instrumented_evm.accounts,
                              contract=contract_address)
        #获取函数名到函数hash的映射
        self.env.funname2hash = get_signature_function_mapping(self.env.abi)

        # 加载外部调用返回值模拟策略（如果启用）
        if settings.MOCK_RETURN_VALUES_ENABLE and self.args.source:
            from utils.mock_return_value_loader import (
                load_mock_return_values,
                get_mock_return_value_file_path
            )

            mock_rv_path = get_mock_return_value_file_path(self.args.source, self.contract_name)
            mock_rv_data = load_mock_return_values(mock_rv_path,accounts=self.instrumented_evm.accounts)
            # self.env.mock_return_values = mock_rv_data
            self.instrumented_evm.set_mock_return_values(mock_rv_data)

            # 新增：将 mock 数据加载到 Generator 中，支持交易级 mock
            if mock_rv_data and "mock_return_values" in mock_rv_data:
                # 遍历所有目标函数签名，加载到 generator
                for target_function_sig in mock_rv_data["mock_return_values"].keys():
                    generator.load_mock_return_values(mock_rv_data, target_function_sig)
                logger.info(f"Mock return values loaded into generator from {mock_rv_path}")

        #增加种子的序列的预生成模块，基于状态依赖图的序列生成。
        
        self.env.pre_tx_list , self.env.RAW , self.env.state_var , self.env.key_var , self.env.require_key_fun,self.env.require_key_tx_fun = get_tx_list(self.args.source,self.env.funname2hash,get_functions_from_abi(self.env.abi),self.contract_name)
       
        self.env.vul_bran_weight = self.env.cfg.get_vul_weight()
        self.env.basic_block_cover= {}

        for bb in  self.env.cfg.Vul_Branchs.basic_blocks.keys():
            if bb not in self.env.basic_block_cover:
                self.env.basic_block_cover[hex(bb)] = 0
            
        

        # Create initial population
        size = 2 * len(self.interface)
        # population = Population(indv_template=Individual(generator=generator),
        #                         indv_generator=generator,
        #                         size=settings.POPULATION_SIZE if settings.POPULATION_SIZE else size).init(self.env.pre_tx_list,self.env.funname2hash)
        tx_list = []
        # for infa in self.interface:
        #     tx_list.append([infa])
        #     tx_list.append([infa])
        population = Population(indv_template=Individual(generator=generator),
                                indv_generator=generator,
                                size=settings.POPULATION_SIZE if settings.POPULATION_SIZE else size)#.init_hash(tx_list)
        
        population.addlist(self.env.pre_tx_list,self.env.funname2hash)

        # Create genetic operators
        if self.args.data_dependency:
            selection = DataDependencyLinearRankingSelection(env=self.env)
            crossover = DataDependencyCrossover(pc=settings.PROBABILITY_CROSSOVER, env=self.env)
            mutation = Mutation(pm=settings.PROBABILITY_MUTATION).addenv_info(self.env)
        else:
            selection = LinearRankingSelection()
            crossover = Crossover(pc=settings.PROBABILITY_CROSSOVER)
            mutation = Mutation(pm=settings.PROBABILITY_MUTATION).addenv_info(self.env)

        

        # Create and run our evolutionary fuzzing engine
        engine = EvolutionaryFuzzingEngine(population=population, selection=selection, crossover=crossover, mutation=mutation, mapping=get_function_signature_mapping(self.env.abi))
        engine.fitness_register(lambda x: fitness_function(x, self.env))
        engine.analysis.append(ExecutionTraceAnalyzer(self.env))

        self.env.execution_begin = time.time()
        self.env.population = population

        engine.run(ng=settings.GENERATIONS)



        resbranches = {}
        for bk,bv in self.env.visited_branches.items():
            if bk not in resbranches:
                resbranches[bk] = []
            if 0 in bv:
                resbranches[bk].append(0)
            if 1 in bv:
                resbranches[bk].append(1)

        resblockcov = []
        for pc in self.env.code_coverage:
            resblockcov.append(pc)

        # with open("visited_branches.json", "w") as f:
        #     json.dump(resbranches, f, indent=4, ensure_ascii=False)
        # print("visited_branches已保存为visited_branches.json")

        # with open("code_coverage.json", "w") as f:
        #     json.dump(resblockcov, f, indent=4, ensure_ascii=False)
        # print("code_coverage已保存为code_coverage.json")

        #保存执行结果
        # resresults = self.env.results["results"]
        cover_results = self.env.results["generations"]

        # {'file_name': 'AbleDollarToken_0x5cfaf9ad2cb84ce2bc40be1beb735bd12a075e99', 'contract': 'AbleDollarToken', 'time': 0.06032156944274902, 'total_transactions': 2, 'revert_transactions_percentage': 50.0, 'revert_transactions': 1, 'unique_transactions': 1, 'nr_of_transactions': 2, 'code_coverage': 4.736467236467236, 'code_coverage_length': 133, 'code_coverage_allpcs': 2808, 'branch_coverage': 15.0, 'branch_coverage_length': 24, 'branch_coverage_jumpis': 160}
        bucket_results = bucketize_per_second(cover_results)

        # [{'contract': 'AbleDollarToken', 'swc_id': 101, 'severity': 'High', 'type': 'Integer Overflow', 'individual': [...], 'time': 2.113675355911255, 'total_transactions': 33, 'revert_transactions': 27, 'unique_transactions': 29, 'line': 46, 'column': 1, 'source_code': 'a + b'}]
        errors_results = []
        for error in self.env.results["errors"].keys():
            errors_results.extend(self.env.results["errors"][error])

        for error in errors_results:
            error.pop("individual")

        # 将数据保存到CSV文件中
        if self.env.resfile:
        # if settings.RESFILE:
            with open(settings.RESFILE, 'a', newline='') as f:
                if cover_results and isinstance(cover_results[-1], dict):
                    writer = csv.DictWriter(f, fieldnames=cover_results[-1].keys())
                    # writer.writeheader()
                    writer.writerow(cover_results[-1])
                else:
                    logger.error("Invalid data format for CSV writing: last element must be a dictionary")
            
            # with open(self.args.resfile+"_vul.csv", 'a', newline='') as f:
            #     writer = csv.writer(f)
            #     for errors in self.env.errors_list:
            #         writer.writerow(errors)
                

        if self.env.args.cfg:
            if self.env.args.source:
                self.env.cfg.save_coverage_highlighted_cfg(os.path.splitext(self.env.args.source)[0]+'-'+self.contract_name, 'pdf', covered_pcs=set(resblockcov))
            elif self.env.args.abi:
                self.env.cfg.save_coverage_highlighted_cfg(os.path.join(os.path.dirname(self.env.args.abi), self.contract_name), 'pdf', covered_pcs=set(resblockcov))

        self.instrumented_evm.reset()


        def save_results_to_file(data, folder_path, filename, data_type):
            """保存数据到指定文件夹，使用文件名作为保存文件名"""
            try:
                # 确保文件夹存在
                os.makedirs(folder_path, exist_ok=True)
                
                # 构建保存路径
                if data_type:
                    save_filename = f"{filename}_{data_type}.json"
                else:
                    save_filename = f"{filename}.json"
                save_path = os.path.join(folder_path, save_filename)
                
                # 保存数据
                with open(save_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False, default=str)
                
                print(f"已保存 {data_type} 结果到: {save_path}")
                return save_path
            except Exception as e:
                print(f"保存 {data_type} 结果失败: {e}")
                return None

        # 获取当前合约文件名（不包含扩展名）
        
        
        # 指定保存文件夹路径
        results_folder = self.args.output_dir

        # 保存最终CFG（如果启用）
        if settings.SAVE_CFG_JSON_ENABLE and self.args.source:
            source_dir = os.path.dirname(os.path.abspath(self.args.source))
            final_cfg_path = os.path.join(source_dir, f"{self.env.file_name}_cfg_dynamic.json")
            self.env.cfg.save_to_json(final_cfg_path, deployment_bytecode=self.deployement_bytecode)

        # 保存 errors_results
        errors_save_path = save_results_to_file(errors_results, results_folder, self.env.file_name, "vul")

        # 保存 bucket_results
        bucket_save_path = save_results_to_file(bucket_results, results_folder, self.env.file_name, None)

        # 生成覆盖率可视化图表
        if  settings.GEN_FIGURE_ENABLE and hasattr(self.env, 'coverage_analyzer'):
            try:
                self.env.coverage_analyzer.generate_all_plots(
                    contract_name=self.contract_name,
                    output_dir=results_folder
                )
            except Exception as e:
                print(f"生成覆盖率可视化图表时出错: {e}")
                import traceback
                traceback.print_exc()

        # return self.env.errors_list, cover_results
        return errors_results, bucket_results

def main():
    print_logo()
    args = launch_argument_parser()

    logger = initialize_logger("Main    ")

    # Check if contract has already been analyzed
    if args.results and os.path.exists(args.results):
        os.remove(args.results)
        logger.info("Contract "+str(args.source)+" has already been analyzed: "+str(args.results))
        sys.exit(0)

    # Initializing random
    if args.seed:
        seed = args.seed
        if not "PYTHONHASHSEED" in os.environ:
            logger.debug("Please set PYTHONHASHSEED to '1' for Python's hash function to behave deterministically.")
    else:
        seed = random.random()
    random.seed(seed)
    logger.title("Initializing seed to %s", seed)

    # Initialize EVM
    instrumented_evm = InstrumentedEVM(settings.RPC_HOST, settings.RPC_PORT)
    instrumented_evm.set_vm_by_name(settings.EVM_VERSION)
    # print(settings.EVM_VERSION)

    # Create Z3 solver instance
    solver = Solver()
    solver.set("timeout", settings.SOLVER_TIMEOUT)

    # Parse blockchain state if provided
    blockchain_state = []
    if args.blockchain_state:
        if args.blockchain_state.endswith(".json"):
            with open(args.blockchain_state) as json_file:
                for line in json_file.readlines():
                    blockchain_state.append(json.loads(line))
        elif args.blockchain_state.isnumeric():
            settings.BLOCK_HEIGHT = int(args.blockchain_state)
            instrumented_evm.set_vm(settings.BLOCK_HEIGHT)
        else:
            logger.error("Unsupported input file: " + args.blockchain_state)
            return None,None
            # sys.exit(-1)    

    # Compile source code to get deployment bytecode, runtime bytecode and ABI
    if args.source:
        if args.source.endswith(".sol"):
            # 使用 compile_evm_version 进行编译（可能与执行 EVM 版本不同）
            compiler_output = compile(args.solc_version, args.compile_evm_version, args.source)
            if not compiler_output:
                logger.error("No compiler output for: " + args.source)
                return None,None
                # sys.exit(-1)
            for contract_name, contract in compiler_output['contracts'][args.source].items():
                if args.contract and contract_name != args.contract:
                    continue
                if contract['abi'] and contract['evm']['bytecode']['object'] and contract['evm']['deployedBytecode']['object']:
                    source_map = SourceMap(':'.join([args.source, contract_name]), compiler_output)
                    return Fuzzer(contract_name, contract["abi"], contract['evm']['bytecode']['object'], contract['evm']['deployedBytecode']['object'], instrumented_evm, blockchain_state, solver, args, seed, source_map).run()
        else:
            logger.error("Unsupported input file: " + args.source)
            return None,None
            # sys.exit(-1)

    if args.abi:
        with open(args.abi) as json_file:
            abi = json.load(json_file)
            runtime_bytecode = instrumented_evm.get_code(to_canonical_address(args.contract)).hex()
            return Fuzzer(args.contract, abi, None, runtime_bytecode, instrumented_evm, blockchain_state, solver, args, seed).run()

def launch_argument_parser():
    parser = argparse.ArgumentParser()

    # Contract parameters
    group1 = parser.add_mutually_exclusive_group(required=True)
    group1.add_argument("-s", "--source", type=str,
                        help="Solidity smart contract source code file (.sol).")
    group1.add_argument("-a", "--abi", type=str,
                        help="Smart contract ABI file (.json).")

    #group2 = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument("-c", "--contract", type=str,
                        help="Contract name to be fuzzed (if Solidity source code file provided) or blockchain contract address (if ABI file provided).")

    parser.add_argument("-b", "--blockchain-state", type=str,
                        help="Initialize fuzzer with a blockchain state by providing a JSON file (if Solidity source code file provided) or a block number (if ABI file provided).")

    # Compiler parameters
    parser.add_argument("--solc", help="Solidity compiler version (default '" + str(
        solcx.get_solc_version()) + "'). Installed compiler versions: " + str(solcx.get_installed_solc_versions()) + ".",
                        action="store", dest="solc_version", type=str)
    parser.add_argument("--evm", help="Ethereum VM (default '" + str(
        settings.EVM_VERSION) + "'). Available VM's: 'homestead', 'byzantium' or 'petersburg'.", action="store",
                        dest="evm_version", type=str)

    # Evolutionary parameters
    group3 = parser.add_mutually_exclusive_group(required=False)
    group3.add_argument("-g", "--generations",
                        help="Number of generations (default " + str(settings.GENERATIONS) + ").", action="store",
                        dest="generations", type=int)
    group3.add_argument("-t", "--timeout",
                        help="Number of seconds for fuzzer to stop.", action="store",
                        dest="global_timeout", type=int)
    parser.add_argument("-n", "--population-size",
                        help="Size of the population.", action="store",
                        dest="population_size", type=int)
    parser.add_argument("-pc", "--probability-crossover",
                        help="Size of the population.", action="store",
                        dest="probability_crossover", type=float)
    parser.add_argument("-pm", "--probability-mutation",
                        help="Size of the population.", action="store",
                        dest="probability_mutation", type=float)
    parser.add_argument("-rf", "--resfile",
                        help="file of result.", action="store",
                        dest="resfile", type=str)
    parser.add_argument("--output-dir",
                        help="Directory for JSON result files (default: ./amfuzz_testca_ab_nosematic/).",
                        action="store", dest="output_dir", type=str,
                        default="./amfuzz_testca_ab_nosematic/")

    # Miscellaneous parameters
    parser.add_argument("-r", "--results", type=str, help="Folder or JSON file where results should be stored.")
    parser.add_argument("--seed", type=float, help="Initialize the random number generator with a given seed.")
    parser.add_argument("--cfg", help="Build control-flow graph and highlight code coverage.", action="store_true")
    parser.add_argument("--rpc-host", help="Ethereum client RPC hostname.", action="store", dest="rpc_host", type=str)
    parser.add_argument("--rpc-port", help="Ethereum client RPC port.", action="store", dest="rpc_port", type=int)

    parser.add_argument("--data-dependency",
                        help="Disable/Enable data dependency analysis: 0 - Disable, 1 - Enable (default: 1)", action="store",
                        dest="data_dependency", type=int)
    parser.add_argument("--constraint-solving",
                        help="Disable/Enable constraint solving: 0 - Disable, 1 - Enable (default: 1)", action="store",
                        dest="constraint_solving", type=int)
    parser.add_argument("--environmental-instrumentation",
                        help="Disable/Enable environmental instrumentation: 0 - Disable, 1 - Enable (default: 1)", action="store",
                        dest="environmental_instrumentation", type=int)
    parser.add_argument("--max-individual-length",
                        help="Maximal length of an individual (default: " + str(settings.MAX_INDIVIDUAL_LENGTH) + ")", action="store",
                        dest="max_individual_length", type=int)
    parser.add_argument("--max-symbolic-execution",
                        help="Maximum number of symbolic execution calls before restting population (default: " + str(settings.MAX_SYMBOLIC_EXECUTION) + ")", action="store",
                        dest="max_symbolic_execution", type=int)

    version = "ConFuzzius - Version 0.0.2 - "
    version += "\"By three methods we may learn wisdom:\n"
    version += "First, by reflection, which is noblest;\n"
    version += "Second, by imitation, which is easiest;\n"
    version += "And third by experience, which is the bitterest.\"\n"
    parser.add_argument("-v", "--version", action="version", version=version)

    args = parser.parse_args()

    if not args.contract:
        args.contract = ""

    if args.source and args.contract.startswith("0x"):
        parser.error("--source requires --contract to be a name, not an address.")
    if args.source and args.blockchain_state and args.blockchain_state.isnumeric():
        parser.error("--source requires --blockchain-state to be a file, not a number.")

    if args.abi and not args.contract.startswith("0x"):
        parser.error("--abi requires --contract to be an address, not a name.")
    if args.abi and args.blockchain_state and not args.blockchain_state.isnumeric():
        parser.error("--abi requires --blockchain-state to be a number, not a file.")

    if args.evm_version:
        settings.EVM_VERSION = args.evm_version

    # 自动检测编译器和 EVM 版本
    if args.source and args.source.endswith(".sol"):
        if not args.solc_version or not args.evm_version:
            # 从源文件自动检测版本
            solc_ver, compile_evm, execute_evm = get_compiler_config(args.source)

            if not args.solc_version:
                args.solc_version = solc_ver

            if not args.evm_version:
                settings.EVM_VERSION = execute_evm

            # 保存编译 EVM 版本（可能与执行 EVM 不同）
            args.compile_evm_version = compile_evm
        else:
            args.compile_evm_version = args.evm_version

        # 确保编译器已安装
        ensure_solc_installed(args.solc_version)
    else:
        if not args.solc_version:
            args.solc_version = solcx.get_solc_version()
        args.compile_evm_version = settings.EVM_VERSION
    if args.generations:
        settings.GENERATIONS = args.generations
    if args.global_timeout:
        settings.GLOBAL_TIMEOUT = args.global_timeout
    if args.population_size:
        settings.POPULATION_SIZE = args.population_size
    if args.probability_crossover:
        settings.PROBABILITY_CROSSOVER = args.probability_crossover
    if args.probability_mutation:
        settings.PROBABILITY_MUTATION = args.probability_mutation

    if args.data_dependency == None:
        args.data_dependency = 1
    if args.constraint_solving == None:
        args.constraint_solving = 1
    if args.environmental_instrumentation == None:
        args.environmental_instrumentation = 1

    if args.environmental_instrumentation == 1:
        settings.ENVIRONMENTAL_INSTRUMENTATION = True
    elif args.environmental_instrumentation == 0:
        settings.ENVIRONMENTAL_INSTRUMENTATION = False

    if args.max_individual_length:
        settings.MAX_INDIVIDUAL_LENGTH = args.max_individual_length
    if args.max_symbolic_execution:
        settings.MAX_SYMBOLIC_EXECUTION = args.max_symbolic_execution

    if args.abi:
        settings.REMOTE_FUZZING = True

    if args.rpc_host:
        settings.RPC_HOST = args.rpc_host
    if args.rpc_port:
        settings.RPC_PORT = args.rpc_port

    return args

def print_logo():
    print("")
    print("     _____                      __  ______                ")
    print("    / ___/____ ___  ____ ______/ /_/ ____/_  __________  ")
    print("    \__ \/ __ `__ \/ __ `/ ___/ __/ /_  / / / /_  /_  / ")
    print("   ___/ / / / / / / /_/ / /  / /_/ __/ / /_/ / / /_/ /_ ")
    print("  /____/_/ /_/ /_/\__,_/_/   \__/_/    \__,_/ /___/___/ ")
    print("")

if '__main__' == __name__:
    main()
