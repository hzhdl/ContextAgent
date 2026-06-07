#!/usr/bin/env python3
# -*- coding: utf-8 -*-

def fitness_function(indv, env):
    # 如果个体未被分析过（如初始种群），返回默认适应度0.0
    # 这些个体在选择时优先级最低，后续被执行后会有正确的适应度
    if indv.hash not in env.individual_branches:
        return 0.0

    block_coverage_fitness = compute_branch_coverage_fitness(env.individual_branches[indv.hash], env.code_coverage)
    if env.args.data_dependency:
        data_dependency_fitness = compute_data_dependency_fitness(indv, env.data_dependencies)
        return block_coverage_fitness + data_dependency_fitness
    return block_coverage_fitness

def compute_branch_coverage_fitness(branches, pcs):
    non_visited_branches = 0.0

    for jumpi in branches:
        for destination in branches[jumpi]:
            if not branches[jumpi][destination] and destination not in pcs:
                non_visited_branches += 1

    return non_visited_branches

def compute_data_dependency_fitness(indv, data_dependencies):
    data_dependency_fitness = 0.0
    all_reads = set()

    for d in data_dependencies:
        all_reads.update(data_dependencies[d]["read"])

    for i in indv.chromosome:
        _function_hash = i["arguments"][0]
        if _function_hash in data_dependencies:
            for i in data_dependencies[_function_hash]["write"]:
                if i in all_reads:
                    data_dependency_fitness += 1

    return data_dependency_fitness
