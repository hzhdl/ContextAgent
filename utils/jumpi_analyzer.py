#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import List, Dict, Tuple, Set
from dataclasses import dataclass
import copy
import re

from utils.utils import convert_stack_value_to_int

@dataclass
class StackItem:
    value: int
    source_op: str
    source_loc: int
    dependencies: List[int]  # 依赖的其他栈项索引
    stack_state: List[str]   # 当前指令执行时的栈状态

@dataclass
class ConditionInfo:
    op: str
    location: int
    stack_values: List[int]
    difference: int  # 栈顶两个值的差值
    is_negated: bool  # 是否被ISZERO取反
    stack_state: List[str]  # 执行该指令时的栈状态

class JumpiAnalyzer:
    def __init__(self):
        
        self.stack: List[StackItem] = []
        self.conditions: List[ConditionInfo] = []
        self.comparison_ops = {"EQ", "LT", "GT", "SLT", "SGT", "ISZERO"}
        self.basic_block_terminators = {"JUMP", "JUMPI", "RETURN", "REVERT", "STOP"}
    
    def parse_opcode_line(self, line: str) -> Tuple[int, str, str, List[str]]:
        """解析操作码行，返回位置、操作码、参数和栈状态"""
        # 使用正则表达式分离栈状态
        match = re.match(r"(\d+): ([^[]+)(?:\[([^\]]+)\])?", line)
        if not match:
            raise ValueError(f"Invalid opcode line format: {line}")
            
        location = int(match.group(1))
        op_parts = match.group(2).strip().split(" ")
        opcode = op_parts[0]
        param = op_parts[1] if len(op_parts) > 1 else None
        
        # 解析栈状态
        stack_state = []
        if match.group(3):
            stack_state = [s.strip() for s in match.group(3).split(",")]
            
        return location, opcode, param, stack_state



    def analyze_jumpi(self, jumpi_location: int) -> List[ConditionInfo]:
        """分析指定位置的JUMPI指令"""
        self.stack = []
        self.conditions = []
        current_loc = jumpi_location
        
        while current_loc >= 0:
            line = self.opcodes[current_loc]
            try:
                location, opcode, param, stack_state = self.parse_opcode_line(line)
            except ValueError as e:
                print(f"Warning: {e}")
                current_loc -= 1
                continue
            
            # 处理操作码对栈的影响
            self.process_opcode(location, opcode, param, stack_state)
            
            # 检查是否到达basic block的开始
            if current_loc > 0:
                prev_loc, prev_op, _, _ = self.parse_opcode_line(self.opcodes[current_loc - 1])
                if prev_op in self.basic_block_terminators:
                    break
            
            current_loc -= 1
        
        return self.conditions

    def analyze_iszero(self, trace: List[str], location: int) -> List[ConditionInfo]:
        """分析指定位置的JUMPI指令"""
        distance_list = []
        num = location
        while num >= 0:
            if trace[num]["op"] in ["JUMPDEST"]:
                break
            elif num > 0 and trace[num-1]["op"] in ["CALL", "DELEGATECALL", "STATICCALL"]:
                v1=trace[num-1]["stack"][-1]
                
                distance_list.append(convert_stack_value_to_int(v1))
                break
            elif trace[num]["op"] in ["LT", "GT", "SLT", "SGT", "EQ"]:
                v1=trace[num]["stack"][-1]
                v2=trace[num]["stack"][-2]
                distance_list.append(convert_stack_value_to_int(v1)-convert_stack_value_to_int(v2))
            elif trace[num]["op"] in ["AND", "OR"]:
                v1=trace[num]["stack"][-1]
                v2=trace[num]["stack"][-2]
                distance_list.append(convert_stack_value_to_int(v1) - convert_stack_value_to_int(v2))
            num -= 1
        
        return distance_list

    def process_opcode(self, location: int, opcode: str, param: str = None, stack_state: List[str] = None):
        """处理单个操作码对栈的影响"""
        if opcode == "PUSH1" or opcode.startswith("PUSH"):
            value = int(param, 16) if param else 0
            self.stack.append(StackItem(value, opcode, location, [], stack_state))
            
        elif opcode == "DUP1":
            if self.stack:
                top = copy.deepcopy(self.stack[-1])
                top.stack_state = stack_state
                self.stack.append(top)
                
        elif opcode == "SWAP1":
            if len(self.stack) >= 2:
                self.stack[-1], self.stack[-2] = self.stack[-2], self.stack[-1]
                self.stack[-1].stack_state = stack_state
                self.stack[-2].stack_state = stack_state
                
        elif opcode == "POP":
            if self.stack:
                self.stack.pop()
                
        elif opcode in self.comparison_ops:
            self.handle_comparison(location, opcode, stack_state)
            
        elif opcode == "JUMPI":
            if len(self.stack) >= 2:
                condition = self.stack[-2]
                destination = self.stack[-1]
                # 记录跳转条件
                self.add_condition_info(location, "JUMPI", 
                                      [condition.value, destination.value], 
                                      stack_state=stack_state)
                
    def handle_comparison(self, location: int, opcode: str, stack_state: List[str]):
        """处理比较操作"""
        if len(self.stack) >= 2:
            val2 = self.stack.pop()
            val1 = self.stack.pop()
            
            # 计算差值
            difference = val1.value - val2.value
            
            # 记录比较条件
            is_negated = False
            if opcode == "ISZERO":
                is_negated = True
                if self.conditions:
                    # 更新前一个条件的取反状态
                    self.conditions[-1].is_negated = True
            else:
                self.add_condition_info(location, opcode, 
                                      [val1.value, val2.value], 
                                      difference, is_negated, 
                                      stack_state)
            
            # 将比较结果压入栈
            result = StackItem(1 if difference == 0 else 0, 
                             opcode, location, [], stack_state)
            self.stack.append(result)
            
    def add_condition_info(self, location: int, op: str, stack_values: List[int], 
                          difference: int = 0, is_negated: bool = False, 
                          stack_state: List[str] = None):
        """添加条件信息"""
        condition = ConditionInfo(op, location, stack_values, 
                                difference, is_negated, stack_state)
        self.conditions.append(condition)

    def analyze_jumpi_path(self,opcode_sequence: List[str], jumpi_index: int) -> List[ConditionInfo]:
        """分析指定JUMPI指令的执行路径"""
        self.opcodes = opcode_sequence
        conditions = self.analyze_jumpi(jumpi_index)
        return conditions

    def print_analysis_results(self,conditions: List[ConditionInfo]):
        """打印分析结果"""
        print("\n=== 执行路径分析结果 ===")
        for i, cond in enumerate(conditions):
            print(f"\n条件 {i+1}:")
            print(f"操作码: {cond.op}")
            print(f"位置: {cond.location}")
            print(f"栈值: {cond.stack_values}")
            if cond.op in {"EQ", "LT", "GT", "SLT", "SGT"}:
                print(f"差值: {cond.difference}")
            print(f"是否取反: {cond.is_negated}")
            print(f"栈状态: {cond.stack_state}")

# if __name__ == "__main__":
#     # 示例用法，包含栈状态的操作码序列
#     opcode_sequence = [
#         "0: PUSH1 0x80 [0x80]",
#         "1: PUSH1 0x40 [0x40, 0x80]",
#         "2: MSTORE [0x80]",
#         "3: CALLVALUE [0x00]",
#         "4: DUP1 [0x00, 0x00]",
#         "5: ISZERO [0x01]",
#         "6: PUSH2 0x000f [0x000f, 0x01]",
#         "7: JUMPI [] "
#     ]
    
#     # 分析JUMPI指令（位置7）
#     conditions = analyze_jumpi_path(opcode_sequence, 7)
#     print_analysis_results(conditions) 