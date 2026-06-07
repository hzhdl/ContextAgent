#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import subprocess
from queue import Queue
from dataclasses import dataclass
from typing import Optional

from .utils import remove_swarm_hash, convert_stack_value_to_int


@dataclass
class EmbeddedContract:
    """
    Data structure for storing embedded contract extraction results.
    Implements the Context-Separated Program Model (CSPM) analysis results.
    """
    # Trigger information
    trigger_opcode_pc: int  # PC address of the CREATE or CREATE2 opcode
    trigger_opcode_name: str  # "CREATE" or "CREATE2"
    trigger_bb_id: int  # Start address of the basic block containing the trigger opcode

    # Pattern 1: A -> B's creation code
    creation_code_offset_in_parent: Optional[int]  # Offset of B's creation code in A's runtime bytecode
    creation_code_length: Optional[int]  # Length of B's creation code
    creation_code: Optional[bytes]  # B's creation bytecode

    # Pattern 2: B's creation code -> B's runtime code
    runtime_code_offset_in_creation: Optional[int]  # Offset of B's runtime code in B's creation code
    runtime_code_length: Optional[int]  # Length of B's runtime code
    runtime_code: Optional[bytes]  # B's runtime bytecode

    def __str__(self):
        result = f"EmbeddedContract at {hex(self.trigger_opcode_pc)} ({self.trigger_opcode_name})\n"
        result += f"  Basic Block ID: {hex(self.trigger_bb_id)}\n"
        if self.creation_code:
            result += f"  Creation Code: offset={self.creation_code_offset_in_parent}, "
            result += f"length={self.creation_code_length}, "
            result += f"bytecode={self.creation_code.hex()[:64]}...\n"
        if self.runtime_code:
            result += f"  Runtime Code: offset={self.runtime_code_offset_in_creation}, "
            result += f"length={self.runtime_code_length}, "
            result += f"bytecode={self.runtime_code.hex()[:64]}...\n"
        return result

class BasicBlock:
    def __init__(self):
        self.start_address    = None
        self.end_address      = None
        self.instructions     = {}
        

    def __str__(self):
        string  = "---------Basic Block---------\n"
        string += "Start address: %d (0x%x)\n" % ((self.start_address, self.start_address) if self.start_address else (0, 0))
        string += "End address: %d (0x%x)\n" % ((self.end_address, self.end_address) if self.end_address else (0, 0))
        string += "Instructions: "+str(self.instructions)+"\n"
        string += "-----------------------------"
        return string

    def __hash__(self):
        return hash(str(self))

    def __eq__(self, _other):
        return self.__dict__ == _other.__dict__

    def set_start_address(self, start_address,Vul_Branchs):
        Vul_Branchs.add(start_address)
        self.start_address = start_address

    def get_start_address(self):
        return self.start_address

    def set_end_address(self, end_address,Vul_Branchs):
        self.end_address = end_address
        Vul_Branchs.end(self.get_start_address(),end_address)

    def get_end_address(self):
        return self.end_address

    def add_instruction(self, key, value, opcode, Vul_Branchs):
        self.instructions[key] = value
        if opcode in ["CALL", "TIMESTAMP", "NUMBER","INVALID","DELEGATECALL","SELFDESTRUCT"]:
            Vul_Branchs.set(self.get_start_address(),opcode)


    def get_instructions(self):
        return self.instructions
    
class Vul_Branchs:
    def __init__(self):
        self.basic_blocks = {}
        self.end2start = {}
        self.branchs = {}

    def __str__(self):
        string  = "---------Vul Branchs---------\n"
        string += "Basic Blocks: "+str(self.basic_blocks)+"\n"
        string += "Branchs: "+str(self.branchs)+"\n"
        string += "-----------------------------"
        return string

    def __hash__(self):
        return hash(str(self))
    
    def add(self, start_address):
        self.basic_blocks[start_address] = {"vul_opcodes":[]}

    def set(self, start_address, opcode):
        # self.branchs[basic_block.get_start_address()]["basic_block"] = basic_block
        # if start_address not in self.branchs:
        #     self.add(start_address)
        self.basic_blocks[start_address]["vul_opcodes"].append(opcode)

    def end(self, start_address, end_address):
        self.basic_blocks[start_address]["end_address"] = end_address
        self.end2start[end_address] = start_address
        

    def cal_vul_weight(self,graph):
        reversed_graph = self.reverse_graph(graph)
        vul_nodes = {}
        for vulkey in self.basic_blocks:
            if len(self.basic_blocks[vulkey]["vul_opcodes"]) > 0:
                vul_nodes[self.basic_blocks[vulkey]["end_address"]]=[vulkey,len(self.basic_blocks[vulkey]["vul_opcodes"])*20]
        visited_nodes = []
        for i in vul_nodes.keys():
            self.spread_weight(reversed_graph, i, vul_nodes[i][1])
        
    

    def normalize_weight(self,data):
        all_values = []
        for features in data.values():
            all_values.extend(features.values())
        if len(all_values) == 0:
            return {}
        
        global_min = min(all_values)
        global_max = max(all_values)
        
        normalized_data = {}
        for category, features in data.items():
            normalized_features = {}
            for feature, value in features.items():
                normalized_value = (value - global_min+0.01) / (global_max - global_min+0.01)
                # normalized_features[feature] = normalized_value + 0.5
                normalized_features[feature] = normalized_value
            normalized_data[category] = normalized_features
        return normalized_data

        
        

    def spread_weight(self,graph, start, weight):
        deque = Queue()
        deque.put((-1,start,weight))
        if self.end2start[start] not in graph:
            return
        while not deque.empty():
            start,end,w = deque.get()
            e = self.end2start[end]
            if e not in graph:
                continue
            
            for n in graph[e]:
                if n not in self.branchs:
                    self.branchs[n]={}
                if e not in self.branchs[n]:
                    self.branchs[n][e]=0
                self.branchs[n][e]+=w
                if w !=0:
                    deque.put((e,n,w-1))
        return 

    def reverse_graph(self,graph):
        reversed_graph = {}
        for node in graph:
            for neighbor in graph[node]:
                if neighbor not in reversed_graph:
                    reversed_graph[neighbor] = []
                reversed_graph[neighbor].append(node)
        return reversed_graph

    


class ControlFlowGraph:
    def __init__(self):
        self.edges = {}
        self.vertices = {}
        self.visited_pcs = set()
        self.visited_branches = {}
        self.error_pcs = set()
        self.can_send_ether = False
        self.Vul_Branchs = Vul_Branchs()
        self.embedded_contracts = []  # List to store EmbeddedContract objects
        self._bytecode = None  # Store original bytecode for re-analysis
        self._evm_version = None  # Store EVM version for re-analysis
        
    def get_vul_weight(self):
        return self.Vul_Branchs.normalize_weight(self.Vul_Branchs.branchs)

    def _find_codecopy_in_block(self, basic_block, bytecode, max_pc=None):
        """
        Find CODECOPY instruction and extract its parameters within a basic block.

        Args:
            basic_block: The BasicBlock to search in
            bytecode: The full bytecode being analyzed
            max_pc: Maximum PC to consider (used when searching in the block containing CREATE)

        Returns:
            (code_offset, length) tuple if found, None otherwise
        """
        instructions = basic_block.get_instructions()
        instruction_pcs = sorted(instructions.keys())

        # If max_pc is specified, only consider instructions up to that point
        if max_pc is not None:
            instruction_pcs = [pc for pc in instruction_pcs if pc < max_pc]

        # Scan backwards to find CODECOPY
        codecopy_pc = None
        for pc in reversed(instruction_pcs):
            if instructions[pc] == "CODECOPY":
                codecopy_pc = pc
                break

        if codecopy_pc is None:
            return None

        # Scan backwards from CODECOPY to find PUSH instructions
        push_values = []
        for pc in reversed([p for p in instruction_pcs if p < codecopy_pc]):
            opcode = bytecode[pc]

            # Check if it's a PUSH instruction (0x60-0x7f)
            if opcode >= 96 and opcode <= 127:  # PUSH1 to PUSH32
                instruction_str = instructions[pc]
                if " " in instruction_str:
                    parts = instruction_str.split(" ", 1)
                    if len(parts) == 2 and parts[1].startswith("0x"):
                        try:
                            value = int(parts[1], 16)
                            push_values.append(value)

                            # Pattern: PUSH length, PUSH offset, PUSH dest, CODECOPY
                            # In reverse order: push_values[0] = dest, push_values[1] = offset, push_values[2] = length
                            if len(push_values) >= 3:
                                code_offset = push_values[1]  # offset
                                code_length = push_values[2]  # length
                                return (code_offset, code_length)
                        except ValueError:
                            continue

        return None

    def _analyze_creation_pattern(self, current_bb, create_pc, bytecode, evm_version):
        """
        Pattern 1: Analyze CREATE/CREATE2 to find the CODECOPY that provides creation bytecode.

        This method performs backward inter-block stack analysis to find the CODECOPY instruction
        that provides the creation bytecode for a CREATE/CREATE2 operation. It searches across
        multiple basic blocks by following predecessor edges.

        Args:
            current_bb: The BasicBlock containing the CREATE/CREATE2 instruction
            create_pc: The PC address of the CREATE/CREATE2 instruction
            bytecode: The full bytecode being analyzed
            evm_version: The EVM version for opcode mapping

        Returns:
            (code_offset, length) tuple if pattern is found, None otherwise
        """
        MAX_SEARCH_DEPTH = 5  # Limit backward search to 5 basic blocks
        visited_blocks = set()  # Avoid cycles

        def search_codecopy(block, depth, max_pc=None):
            """Recursively search for CODECOPY in the block and its predecessors."""
            if depth > MAX_SEARCH_DEPTH:
                return None

            # Avoid infinite loops
            block_id = block.get_start_address()
            if block_id in visited_blocks:
                return None
            visited_blocks.add(block_id)

            # Try to find CODECOPY in the current block
            result = self._find_codecopy_in_block(block, bytecode, max_pc)
            if result is not None:
                return result

            # If not found, search in predecessor blocks
            predecessors = self._get_predecessor_blocks(block)
            for pred_block in predecessors:
                result = search_codecopy(pred_block, depth + 1, max_pc=None)
                if result is not None:
                    return result

            return None

        # Start the search from the current block
        return search_codecopy(current_bb, depth=0, max_pc=create_pc)

    def _analyze_runtime_pattern(self, creation_bytecode):
        """
        Pattern 2: Analyze creation bytecode to extract runtime bytecode.

        This method performs lightweight static analysis on creation bytecode to find
        the RETURN instruction and its associated CODECOPY that provides runtime bytecode.

        Args:
            creation_bytecode: The creation bytecode (bytes) to analyze

        Returns:
            (runtime_offset, runtime_length) tuple if pattern is found, None otherwise
        """
        if not creation_bytecode or len(creation_bytecode) == 0:
            return None

        # Find all RETURN (0xf3) instructions in the creation bytecode
        return_pcs = []
        pc = 0
        while pc < len(creation_bytecode):
            opcode = creation_bytecode[pc]

            if opcode == 243:  # RETURN
                return_pcs.append(pc)
                pc += 1
            elif opcode >= 96 and opcode <= 127:  # PUSH1-PUSH32
                size = opcode - 96 + 1
                pc += size + 1
            else:
                pc += 1

        if not return_pcs:
            return None

        # For each RETURN, scan backwards to find CODECOPY
        for return_pc in return_pcs:
            # Build a simple instruction map for the creation bytecode
            instructions = {}
            pc = 0
            while pc < return_pc:
                opcode = creation_bytecode[pc]
                instructions[pc] = opcode

                if opcode >= 96 and opcode <= 127:  # PUSH1-PUSH32
                    size = opcode - 96 + 1
                    pc += size + 1
                else:
                    pc += 1

            # Scan backwards from RETURN to find CODECOPY (0x39)
            codecopy_pc = None
            for pc in sorted(instructions.keys(), reverse=True):
                if instructions[pc] == 57:  # CODECOPY (0x39)
                    codecopy_pc = pc
                    break

            if codecopy_pc is None:
                continue

            # Find PUSH instructions before CODECOPY
            push_values = []
            pc = 0
            while pc < codecopy_pc:
                opcode = creation_bytecode[pc]

                if opcode >= 96 and opcode <= 127:  # PUSH1-PUSH32
                    size = opcode - 96 + 1
                    # Extract the value
                    value_bytes = creation_bytecode[pc+1:pc+1+size]
                    if len(value_bytes) == size:
                        value = int.from_bytes(value_bytes, byteorder='big')
                        push_values.append((pc, value))
                    pc += size + 1
                else:
                    pc += 1

            # Look for the pattern: PUSH length, PUSH offset, PUSH dest, CODECOPY
            # We need the last 3 PUSH values before CODECOPY
            if len(push_values) >= 3:
                # Find the 3 PUSH instructions closest to CODECOPY
                recent_pushes = [v for pc, v in push_values if pc < codecopy_pc][-3:]
                if len(recent_pushes) >= 2:
                    # Pattern: dest, offset, length (in order of appearance)
                    runtime_offset = recent_pushes[1] if len(recent_pushes) >= 2 else recent_pushes[0]
                    runtime_length = recent_pushes[2] if len(recent_pushes) >= 3 else recent_pushes[1]
                    return (runtime_offset, runtime_length)

        return None

    def build(self, bytecode, evm_version):
        tmp_bytecode = remove_swarm_hash(bytecode).replace("0x", "")
        bytecode = bytes.fromhex(tmp_bytecode)

        # Store for re-analysis during visualization (after execution adds dynamic edges)
        self._bytecode = bytecode
        self._evm_version = evm_version

        current_pc = 0
        previous_pc = 0
        basic_block = None
        previous_opcode = None
        previous_push_value = None

        while current_pc < len(bytecode):
            opcode = bytecode[current_pc]

            if opcode in self.opcode_to_mnemonic[evm_version] and self.opcode_to_mnemonic[evm_version][opcode] in ["CREATE", "CALL", "DELEGATECALL", "SELFDESTRUCT", "SUICIDE"]:
                self.can_send_ether = True

            if previous_opcode == 255: # SELFDESTRUCT
                basic_block.set_end_address(previous_pc,self.Vul_Branchs)
                self.vertices[current_pc] = basic_block
                basic_block = None

            if basic_block is None:
                basic_block = BasicBlock()
                basic_block.set_start_address(current_pc,self.Vul_Branchs)

            if opcode == 91 and basic_block.get_instructions(): # JUMPDEST
                basic_block.set_end_address(previous_pc,self.Vul_Branchs)
                if previous_pc not in self.edges and previous_opcode not in [0, 86, 87, 243, 253, 254, 255]: # Terminating/Conditional: STOP, JUMP, JUMPI, RETURN, REVERT, INVALID, SELFDESTRUCT
                    self.edges[previous_pc] = []
                    self.edges[previous_pc].append(current_pc)
                self.vertices[current_pc] = basic_block
                basic_block = BasicBlock()
                basic_block.set_start_address(current_pc,self.Vul_Branchs)

            if opcode < 96 or opcode > 127: # PUSH??
                if opcode in self.opcode_to_mnemonic[evm_version]:
                    basic_block.add_instruction(current_pc, self.opcode_to_mnemonic[evm_version][opcode], self.opcode_to_mnemonic[evm_version][opcode], self.Vul_Branchs)
                else:
                    basic_block.add_instruction(current_pc, "Missing opcode "+hex(opcode), "None", self.Vul_Branchs)

            if opcode == 86 or opcode == 87: # JUMP or JUMPI
                basic_block.set_end_address(current_pc,self.Vul_Branchs)
                self.vertices[current_pc] = basic_block
                basic_block = None
                if opcode == 86 and previous_opcode and previous_opcode >= 96 and previous_opcode <= 127:
                    if current_pc not in self.edges:
                        self.edges[current_pc] = []
                    self.edges[current_pc].append(previous_push_value)
                if opcode == 87:
                    if current_pc not in self.edges:
                        self.edges[current_pc] = []
                    self.edges[current_pc].append(current_pc+1)
                    if previous_opcode and previous_opcode >= 96 and previous_opcode <= 127:
                        if current_pc not in self.edges:
                            self.edges[current_pc] = []
                        self.edges[current_pc].append(previous_push_value)

            previous_pc = current_pc
            if opcode >= 96 and opcode <= 127: # PUSH??
                size = opcode - 96 + 1
                previous_push_value = ""
                for i in range(size):
                    try:
                        previous_push_value += str(hex(bytecode[current_pc+i+1])).replace("0x", "").zfill(2)
                    except Exception as e:
                        pass
                if previous_push_value:
                    previous_push_value = "0x" + previous_push_value
                    basic_block.add_instruction(current_pc, self.opcode_to_mnemonic[evm_version][opcode]+" "+previous_push_value, self.opcode_to_mnemonic[evm_version][opcode], self.Vul_Branchs)
                    previous_push_value = int(previous_push_value, 16)
                    current_pc += size

            current_pc += 1
            previous_opcode = opcode

        if basic_block:
            basic_block.set_end_address(previous_pc,self.Vul_Branchs)
            self.vertices[current_pc] = basic_block
        self.Vul_Branchs.cal_vul_weight(self.edges)

        # CSPM Analysis: Commented out automatic static analysis
        # Use extract_embedded_contract_from_codecopy() for dynamic analysis instead
        # self._analyze_embedded_contracts(bytecode, evm_version)

    def _analyze_embedded_contracts(self, bytecode, evm_version):
        """
        Analyze the fully-built CFG to extract embedded contracts.

        This method should be called after the CFG is completely constructed.
        It scans all basic blocks for CREATE/CREATE2 instructions and performs
        the CSPM analysis to extract embedded contract bytecode.

        Args:
            bytecode: The full bytecode being analyzed (bytes)
            evm_version: The EVM version for opcode mapping
        """
        # Scan all basic blocks for CREATE/CREATE2 instructions
        for basic_block in self.vertices.values():
            instructions = basic_block.get_instructions()

            # Check each instruction in the basic block
            for pc, instruction in instructions.items():
                # Check if this is a CREATE or CREATE2 instruction
                if instruction in ["CREATE", "CREATE2"]:
                    opcode_name = instruction

                    # Step 1: Analyze Pattern 1 (A -> B's creation code)
                    creation_pattern_result = self._analyze_creation_pattern(
                        basic_block, pc, bytecode, evm_version
                    )

                    if creation_pattern_result is not None:
                        creation_offset, creation_length = creation_pattern_result

                        # Step 2: Safe extraction of creation bytecode
                        if creation_offset + creation_length <= len(bytecode):
                            creation_code_bytes = bytecode[creation_offset:creation_offset + creation_length]

                            # Step 3: Analyze Pattern 2 (B's creation code -> B's runtime code)
                            runtime_pattern_result = self._analyze_runtime_pattern(creation_code_bytes)

                            runtime_offset = None
                            runtime_length = None
                            runtime_code_bytes = None

                            if runtime_pattern_result is not None:
                                runtime_offset, runtime_length = runtime_pattern_result

                                # Step 4: Safe extraction of runtime bytecode
                                if runtime_offset + runtime_length <= len(creation_code_bytes):
                                    runtime_code_bytes = creation_code_bytes[runtime_offset:runtime_offset + runtime_length]

                            # Step 5: Store the result
                            embedded_contract = EmbeddedContract(
                                trigger_opcode_pc=pc,
                                trigger_opcode_name=opcode_name,
                                trigger_bb_id=basic_block.get_start_address(),
                                creation_code_offset_in_parent=creation_offset,
                                creation_code_length=creation_length,
                                creation_code=creation_code_bytes,
                                runtime_code_offset_in_creation=runtime_offset,
                                runtime_code_length=runtime_length,
                                runtime_code=runtime_code_bytes
                            )
                            self.embedded_contracts.append(embedded_contract)

    def execute(self, pc, stack, mnemonic, visited_branches, error_pcs):
        if mnemonic == "JUMP":
            if pc not in self.edges:
                self.edges[pc] = []
            if convert_stack_value_to_int(stack[-1]) not in self.edges[pc]:
                self.edges[pc].append(convert_stack_value_to_int(stack[-1]))
        self.visited_pcs.add(pc)
        self.visited_branches = visited_branches
        self.error_pcs = error_pcs

    def extract_embedded_contract_from_codecopy(self, codecopy_offset, codecopy_length,
                                                 create_pc, create_opcode_name):
        """
        Extract embedded contract bytecode using CODECOPY parameters from execution.

        This method provides a public interface for dynamic embedded contract extraction.
        Instead of static analysis, it uses actual CODECOPY stack parameters captured
        during execution to extract embedded contract bytecode.

        Usage scenario:
        1. During execution, when CODECOPY is executed, capture stack parameters:
           - stack[-1] = dest (memory destination, usually 0)
           - stack[-2] = offset (offset in parent bytecode)
           - stack[-3] = length (length of creation code)
        2. When CREATE/CREATE2 is about to execute, call this method with:
           - codecopy_offset = stack[-2] from CODECOPY
           - codecopy_length = stack[-3] from CODECOPY
           - create_pc = current PC of CREATE/CREATE2
           - create_opcode_name = "CREATE" or "CREATE2"

        Args:
            codecopy_offset: Offset in parent bytecode where creation code starts (from CODECOPY stack)
            codecopy_length: Length of creation code (from CODECOPY stack)
            create_pc: PC address of the CREATE/CREATE2 instruction
            create_opcode_name: "CREATE" or "CREATE2"

        Returns:
            EmbeddedContract object if successful, None otherwise

        Example:
            # In fuzzer execution loop:
            if opcode == "CODECOPY":
                codecopy_offset = convert_stack_value_to_int(stack[-2])
                codecopy_length = convert_stack_value_to_int(stack[-3])
                # Store these for later

            if opcode in ["CREATE", "CREATE2"]:
                contract = cfg.extract_embedded_contract_from_codecopy(
                    codecopy_offset, codecopy_length, pc, opcode
                )
                if contract:
                    print(f"Extracted embedded contract at {hex(pc)}")
        """
        if self._bytecode is None:
            return None, False

        # Validate parameters
        if codecopy_offset < 0 or codecopy_length <= 0:
            return None, False

        # Check bounds
        if codecopy_offset + codecopy_length > len(self._bytecode):
            return None, False

        # Find the basic block containing the CREATE instruction
        create_bb_id = None
        for bb in self.vertices.values():
            if create_pc in bb.get_instructions():
                create_bb_id = bb.get_start_address()
                break

        # Extract creation bytecode from parent contract
        creation_code_bytes = self._bytecode[codecopy_offset:codecopy_offset + codecopy_length]

        # Analyze Pattern 2: Extract runtime code from creation code
        runtime_pattern_result = self._analyze_runtime_pattern(creation_code_bytes)

        runtime_offset = None
        runtime_length = None
        runtime_code_bytes = None

        if runtime_pattern_result is not None:
            runtime_offset, runtime_length = runtime_pattern_result

            # Safe extraction of runtime bytecode
            if runtime_offset + runtime_length <= len(creation_code_bytes):
                runtime_code_bytes = creation_code_bytes[runtime_offset:runtime_offset + runtime_length]

        # Check for duplicates: avoid storing the same embedded contract multiple times
        # Use create_pc as unique identifier (same CREATE instruction should not be recorded twice)
        for existing_contract in self.embedded_contracts:
            if existing_contract.trigger_opcode_pc == create_pc:
                # Already extracted this embedded contract
                return existing_contract, False

        # Create and store the embedded contract object
        embedded_contract = EmbeddedContract(
            trigger_opcode_pc=create_pc,
            trigger_opcode_name=create_opcode_name,
            trigger_bb_id=create_bb_id if create_bb_id is not None else -1,
            creation_code_offset_in_parent=codecopy_offset,
            creation_code_length=codecopy_length,
            creation_code=creation_code_bytes,
            runtime_code_offset_in_creation=runtime_offset,
            runtime_code_length=runtime_length,
            runtime_code=runtime_code_bytes
        )

        self.embedded_contracts.append(embedded_contract)
        return embedded_contract, True

    def _get_embedded_contract_trigger_pcs(self):
        """
        Get the set of PC addresses where embedded contracts are triggered.

        Returns:
            set: Set of PC addresses containing CREATE/CREATE2 that successfully extracted embedded contracts
        """
        return {contract.trigger_opcode_pc for contract in self.embedded_contracts}

    def _get_embedded_contract_bytecode_pcs(self):
        """
        Get the set of PC addresses covered by embedded contract bytecode.

        This method returns all PC addresses that fall within the ranges of embedded contract
        creation bytecode in the parent contract. These PCs represent the actual bytecode
        that will be deployed as child contracts.

        Returns:
            set: Set of PC addresses covered by embedded contract creation bytecode

        Example:
            If an embedded contract's creation code is at offset 0x50 with length 0x80:
            - Returns all PCs in range [0x50, 0xd0)
            - These PCs will be highlighted in blue in CFG visualizations
        """
        bytecode_pcs = set()

        for contract in self.embedded_contracts:
            if contract.creation_code_offset_in_parent is not None and contract.creation_code_length is not None:
                # Add all PCs in the range [offset, offset + length)
                start_offset = contract.creation_code_offset_in_parent
                end_offset = start_offset + contract.creation_code_length

                # Add all PCs in this range
                i = start_offset
                while i < end_offset:
                    bytecode_pcs.add(i)
                    if self._bytecode[i] >= 96 and self._bytecode[i] <= 127: # PUSH
                        size = self._bytecode[i] - 96 + 1
                        i += size
                    i += 1

        return bytecode_pcs

    def _get_predecessor_blocks(self, basic_block):
        """
        Find all predecessor basic blocks of a given basic block.

        Args:
            basic_block: The BasicBlock to find predecessors for

        Returns:
            list: List of BasicBlock objects that have edges leading to the given basic block
        """
        predecessors = []
        target_start_address = basic_block.get_start_address()

        # Search through all edges to find blocks that point to this block
        for source_pc, targets in self.edges.items():
            if target_start_address in targets:
                # Find the basic block that contains source_pc as its end address
                for vertex_start, vertex_block in self.vertices.items():
                    if vertex_block.get_end_address() == source_pc:
                        predecessors.append(vertex_block)
                        break

        return predecessors

    def save_control_flow_graph(self, filename, extension):
        # Re-analysis commented out - use extract_embedded_contract_from_codecopy() for dynamic analysis
        # if self._bytecode is not None and self._evm_version is not None:
        #     self.embedded_contracts = []
        #     self._analyze_embedded_contracts(self._bytecode, self._evm_version)

        f = open(filename+'.dot', 'w')
        f.write('digraph confuzzius_cfg {\n')
        f.write('rankdir = TB;\n')
        f.write('size = "240"\n')
        f.write('graph[fontname = Courier, fontsize = 14.0, labeljust = l, nojustify = true];node[shape = record];\n')
        address_width = 10
        for basic_block in self.vertices.values():
            if len(hex(list(basic_block.get_instructions().keys())[-1])) > address_width:
                address_width = len(hex(list(basic_block.get_instructions().keys())[-1]))

        # Get embedded contract bytecode PCs for highlighting
        # NOT highlighting trigger blocks (CREATE/CREATE2) - those are parent contract code
        embedded_bytecode_pcs = self._get_embedded_contract_bytecode_pcs()

        for basic_block in self.vertices.values():
            # Draw vertices
            label = '"'+hex(basic_block.get_start_address())+'"[label="'
            for address in basic_block.get_instructions():
                label += "{0:#0{1}x}".format(address, address_width)+" "+basic_block.get_instructions()[address]+"\l"
            visited_basic_block = False

            # Priority 1: Error blocks (red)
            for pc in self.error_pcs:
                if pc in basic_block.get_instructions().keys():
                    f.write(label+'",style=filled,fillcolor=red];\n')
                    visited_basic_block = True
                    break

            # Priority 2: Embedded contract bytecode blocks (lightblue)
            # Only highlights blocks containing embedded contract bytecode
            # NOT the blocks containing CREATE/CREATE2 (those are parent contract code)
            if not visited_basic_block:
                has_embedded_bytecode = False
                block_pcs = basic_block.get_instructions().keys()

                # Check if block contains embedded contract bytecode
                for pc in embedded_bytecode_pcs:
                    if pc in block_pcs:
                        has_embedded_bytecode = True
                        break

                if has_embedded_bytecode:
                    f.write(label+'",style=filled,fillcolor=lightblue];\n')
                    visited_basic_block = True

            # Priority 3: Visited blocks (gray) or unvisited (white)
            if not visited_basic_block:
                if  basic_block.get_start_address() in self.visited_pcs and basic_block.get_end_address() in self.visited_pcs:
                    f.write(label+'",style=filled,fillcolor=gray];\n')
                else:
                    f.write(label+'",style=filled,fillcolor=white];\n')
            # Draw edges
            if basic_block.get_end_address() in self.edges:
                # JUMPI
                if list(basic_block.get_instructions().values())[-1] == "JUMPI":
                    if hex(basic_block.get_end_address()) in self.visited_branches and 0 in self.visited_branches[hex(basic_block.get_end_address())] and self.visited_branches[hex(basic_block.get_end_address())][0]["expression"]:
                        f.write('"'+hex(basic_block.get_start_address())+'" -> "'+hex(self.edges[basic_block.get_end_address()][0])+'" [label=" '+str(self.visited_branches[hex(basic_block.get_end_address())][0]["expression"][-1])+'",color="red"];\n')
                    else:
                        f.write('"'+hex(basic_block.get_start_address())+'" -> "'+hex(self.edges[basic_block.get_end_address()][0])+'" [label="",color="red"];\n')
                    if hex(basic_block.get_end_address()) in self.visited_branches and 1 in self.visited_branches[hex(basic_block.get_end_address())] and self.visited_branches[hex(basic_block.get_end_address())][1]["expression"]:
                        f.write('"'+hex(basic_block.get_start_address())+'" -> "'+hex(self.edges[basic_block.get_end_address()][1])+'" [label=" '+str(self.visited_branches[hex(basic_block.get_end_address())][1]["expression"][-1])+'",color="green"];\n')
                    else:
                        f.write('"'+hex(basic_block.get_start_address())+'" -> "'+hex(self.edges[basic_block.get_end_address()][1])+'" [label="",color="green"];\n')
                # Other instructions
                else:
                    for i in range(len(self.edges[basic_block.get_end_address()])):
                        f.write('"'+hex(basic_block.get_start_address())+'" -> "'+hex(self.edges[basic_block.get_end_address()][i])+'" [label="",color="black"];\n')
        f.write('}\n')
        f.close()
        if not subprocess.call('dot '+filename+'.dot -T'+extension+' -o '+filename+'.'+extension, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0:
            print("Graphviz is not available. Please install Graphviz from https://www.graphviz.org/download/.")
        else:
            os.remove(filename+".dot")

    def save_coverage_highlighted_cfg(self, filename, extension, covered_pcs=None):
        """
        保存带覆盖率高亮的控制流图

        参数:
            filename: 输出文件名（不含扩展名）
            extension: 文件扩展名（如'pdf', 'png', 'svg'）
            covered_pcs: 已覆盖的PC地址集合。如果为None，使用self.visited_pcs

        颜色方案:
            - red: 包含错误的basic block
            - lightblue: 嵌入合约触发的basic block (CREATE/CREATE2)
            - darkgreen: 已覆盖的basic block（start_address在covered_pcs中）
            - white: 未覆盖的basic block
        """
        # Re-analysis commented out - use extract_embedded_contract_from_codecopy() for dynamic analysis
        # if self._bytecode is not None and self._evm_version is not None:
        #     self.embedded_contracts = []
        #     self._analyze_embedded_contracts(self._bytecode, self._evm_version)

        if covered_pcs is None:
            covered_pcs = self.visited_pcs

        # 将 covered_pcs 转换为整数集合（处理16进制字符串）
        covered_pcs_int = set()
        for pc in covered_pcs:
            if isinstance(pc, str):
                # 如果是字符串（16进制），转换为整数
                try:
                    covered_pcs_int.add(int(pc, 16) if pc.startswith('0x') else int(pc))
                except ValueError:
                    pass
            else:
                # 如果已经是整数，直接添加
                covered_pcs_int.add(pc)

        # Get embedded contract bytecode PCs for highlighting
        # NOT highlighting trigger blocks (CREATE/CREATE2) - those are parent contract code
        embedded_bytecode_pcs = self._get_embedded_contract_bytecode_pcs()

        # 统计信息
        total_blocks = len(self.vertices)
        fully_covered_blocks = 0
        partially_covered_blocks = 0
        uncovered_blocks = 0
        error_blocks = 0
        embedded_blocks = 0

        # 预先统计
        for basic_block in self.vertices.values():
            has_error = any(pc in self.error_pcs for pc in basic_block.get_instructions().keys())
            block_pcs = basic_block.get_instructions().keys()

            # Check if block contains embedded contract bytecode
            # NOT checking trigger blocks (CREATE/CREATE2) - those are parent contract code
            has_embedded = any(pc in embedded_bytecode_pcs for pc in block_pcs)

            if has_error:
                error_blocks += 1
            elif has_embedded:
                embedded_blocks += 1
            else:
                # 计算该 block 的覆盖率
                block_instructions = list(basic_block.get_instructions().keys())
                covered_count = sum(1 for pc in block_instructions if pc in covered_pcs_int)
                total_count = len(block_instructions)
                coverage_ratio = covered_count / total_count if total_count > 0 else 0

                if coverage_ratio == 1.0:
                    fully_covered_blocks += 1
                elif coverage_ratio > 0:
                    partially_covered_blocks += 1
                else:
                    uncovered_blocks += 1

        coverage_percentage = (fully_covered_blocks / total_blocks * 100) if total_blocks > 0 else 0
        partial_coverage_percentage = (partially_covered_blocks / total_blocks * 100) if total_blocks > 0 else 0
        uncovered_percentage = (uncovered_blocks / total_blocks * 100) if total_blocks > 0 else 0
        embedded_percentage = (embedded_blocks / total_blocks * 100) if total_blocks > 0 else 0

        # 开始生成DOT文件
        f = open(filename+'.dot', 'w')
        f.write('digraph confuzzius_cfg {\n')
        f.write('rankdir = TB;\n')
        f.write('size = "240"\n')

        # 添加标题和统计信息
        f.write('label="CFG Coverage Analysis\\n')
        f.write('Total Blocks: {} | Fully Covered: {} ({:.1f}%) | Partially Covered: {} ({:.1f}%) | Uncovered: {} ({:.1f}%) | Embedded: {} ({:.1f}%) | Errors: {}";\n'.format(
            total_blocks, fully_covered_blocks, coverage_percentage,
            partially_covered_blocks, partial_coverage_percentage,
            uncovered_blocks, uncovered_percentage, embedded_blocks, embedded_percentage, error_blocks))
        f.write('labelloc=t;\n')
        f.write('fontsize=16;\n')
        f.write('fontname=Courier;\n')

        f.write('graph[fontname = Courier, fontsize = 14.0, labeljust = l, nojustify = true];node[shape = record];\n')

        # 计算地址宽度
        address_width = 10
        for basic_block in self.vertices.values():
            if len(hex(list(basic_block.get_instructions().keys())[-1])) > address_width:
                address_width = len(hex(list(basic_block.get_instructions().keys())[-1]))

        # 绘制所有基本块
        for basic_block in self.vertices.values():
            # 构建标签
            label = '"'+hex(basic_block.get_start_address())+'"[label="'
            for address in basic_block.get_instructions():
                label += "{0:#0{1}x}".format(address, address_width)+" "+basic_block.get_instructions()[address]+"\l"

            # 判断颜色：优先级 error > embedded > covered > uncovered
            block_colored = False

            # Priority 1: Error blocks (red)
            for pc in self.error_pcs:
                if pc in basic_block.get_instructions().keys():
                    f.write(label+'",style=filled,fillcolor=red];\n')
                    block_colored = True
                    break

            # Priority 2: Embedded contract bytecode blocks (lightblue)
            # Only highlights blocks containing embedded contract bytecode
            # NOT the blocks containing CREATE/CREATE2 (those are parent contract code)
            if not block_colored:
                has_embedded_bytecode = False
                block_pcs = basic_block.get_instructions().keys()

                # Check if block contains embedded contract bytecode
                for pc in embedded_bytecode_pcs:
                    if pc in block_pcs:
                        has_embedded_bytecode = True
                        break

                if has_embedded_bytecode:
                    f.write(label+'",style=filled,fillcolor=lightblue];\n')
                    block_colored = True

            # Priority 3: Coverage-based coloring
            if not block_colored:
                # 计算该 block 的覆盖率
                block_instructions = list(basic_block.get_instructions().keys())
                covered_count = sum(1 for pc in block_instructions if pc in covered_pcs_int)
                total_count = len(block_instructions)
                coverage_ratio = covered_count / total_count if total_count > 0 else 0

                # 根据覆盖率选择颜色
                if coverage_ratio == 1.0:
                    # 完全覆盖：深绿色
                    f.write(label+'",style=filled,fillcolor=darkgreen,fontcolor=white];\n')
                elif coverage_ratio > 0:
                    # 部分覆盖：浅绿色
                    f.write(label+'",style=filled,fillcolor=lightgreen];\n')
                else:
                    # 未覆盖：白色
                    f.write(label+'",style=filled,fillcolor=white];\n')

            # 绘制边
            if basic_block.get_end_address() in self.edges:
                # JUMPI分支
                if list(basic_block.get_instructions().values())[-1] == "JUMPI":
                    if hex(basic_block.get_end_address()) in self.visited_branches and 0 in self.visited_branches[hex(basic_block.get_end_address())] and self.visited_branches[hex(basic_block.get_end_address())][0]["expression"]:
                        f.write('"'+hex(basic_block.get_start_address())+'" -> "'+hex(self.edges[basic_block.get_end_address()][0])+'" [label=" '+str(self.visited_branches[hex(basic_block.get_end_address())][0]["expression"][-1])+'",color="red"];\n')
                    else:
                        f.write('"'+hex(basic_block.get_start_address())+'" -> "'+hex(self.edges[basic_block.get_end_address()][0])+'" [label="",color="red"];\n')
                    if hex(basic_block.get_end_address()) in self.visited_branches and 1 in self.visited_branches[hex(basic_block.get_end_address())] and self.visited_branches[hex(basic_block.get_end_address())][1]["expression"]:
                        f.write('"'+hex(basic_block.get_start_address())+'" -> "'+hex(self.edges[basic_block.get_end_address()][1])+'" [label=" '+str(self.visited_branches[hex(basic_block.get_end_address())][1]["expression"][-1])+'",color="green"];\n')
                    else:
                        f.write('"'+hex(basic_block.get_start_address())+'" -> "'+hex(self.edges[basic_block.get_end_address()][1])+'" [label="",color="green"];\n')
                # 其他指令
                else:
                    for i in range(len(self.edges[basic_block.get_end_address()])):
                        f.write('"'+hex(basic_block.get_start_address())+'" -> "'+hex(self.edges[basic_block.get_end_address()][i])+'" [label="",color="black"];\n')

        f.write('}\n')
        f.close()

        # 使用Graphviz生成图形
        if not subprocess.call('dot '+filename+'.dot -T'+extension+' -o '+filename+'.'+extension, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0:
            print("Graphviz is not available. Please install Graphviz from https://www.graphviz.org/download/.")
        else:
            os.remove(filename+".dot")

        # 打印统计信息
        print(f"CFG saved to {filename}.{extension}")
        print(f"Coverage Statistics:")
        print(f"  Total Blocks: {total_blocks}")
        print(f"  Fully Covered: {fully_covered_blocks} ({coverage_percentage:.1f}%)")
        print(f"  Partially Covered: {partially_covered_blocks} ({partial_coverage_percentage:.1f}%)")
        print(f"  Uncovered: {uncovered_blocks} ({uncovered_percentage:.1f}%)")
        print(f"  Embedded Contracts: {embedded_blocks} ({embedded_percentage:.1f}%)")
        print(f"  Errors: {error_blocks}")

    def export_to_json(self, deployment_bytecode=None):
        """
        将CFG导出为JSON兼容的字典

        参数:
            deployment_bytecode: 完整字节码（部署字节码），可选

        返回:
            dict: 包含5个字段的字典，所有PC使用十进制表示
        """
        # 1. full_bytecode: 完整字节码
        full_bytecode = deployment_bytecode if deployment_bytecode else ""

        # 2. runtime_bytecode: 运行时字节码
        runtime_bytecode = self._bytecode.hex() if self._bytecode else ""

        # 3. basic_blocks: {start_pc(十进制): [[pc, opcode, param], ...]}
        basic_blocks = {}
        for bb in self.vertices.values():
            start_pc = bb.start_address
            instructions_list = []
            for pc, instr in sorted(bb.instructions.items()):
                # 解析 "OPCODE 0xparam" 或 "OPCODE"
                parts = instr.split(" ", 1)
                opcode = parts[0]
                param = parts[1] if len(parts) > 1 else ""
                # PC使用十进制
                instructions_list.append([pc, opcode, param])
            basic_blocks[start_pc] = instructions_list

        # 4. edges: [[from_start_pc, to_start_pc], ...]
        edges_list = []
        # 构建 end_pc -> start_pc 映射
        end_to_start = {}
        for bb in self.vertices.values():
            end_to_start[bb.end_address] = bb.start_address

        for end_pc, targets in self.edges.items():
            from_start = end_to_start.get(end_pc)
            if from_start is not None:
                for target_pc in targets:
                    edges_list.append([from_start, target_pc])

        # 5. block_starts: [[start_pc, end_pc], ...]
        block_starts = sorted([[bb.start_address, bb.end_address] for bb in self.vertices.values()], key=lambda x: x[0])

        return {
            "full_bytecode": full_bytecode,
            "runtime_bytecode": runtime_bytecode,
            "basic_blocks": basic_blocks,
            "edges": edges_list,
            "block_starts": block_starts
        }

    def save_to_json(self, filename, deployment_bytecode=None):
        """
        保存CFG到JSON文件

        参数:
            filename: 输出文件路径
            deployment_bytecode: 完整字节码（部署字节码），可选
        """
        import json
        data = self.export_to_json(deployment_bytecode)
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"CFG saved to {filename}")

    opcode_to_mnemonic = {
        'homestead': {
            # 0s: Stop and Arithmetic Operations
              0: 'STOP',
              1: 'ADD',
              2: 'MUL',
              3: 'SUB',
              4: 'DIV',
              5: 'SDIV',
              6: 'MOD',
              7: 'SMOD',
              8: 'ADDMOD',
              9: 'MULMOD',
             10: 'EXP',
             11: 'SIGNEXTEND',
            # 10s: Comparison & Bitwise Logic Operations
             16: 'LT',
             17: 'GT',
             18: 'SLT',
             19: 'SGT',
             20: 'EQ',
             21: 'ISZERO',
             22: 'AND',
             23: 'OR',
             24: 'XOR',
             25: 'NOT',
             26: 'BYTE',
            # 20s: SHA3
             32: 'SHA3',
            # 30s: Environmental Information
             48: 'ADDRESS',
             49: 'BALANCE',
             50: 'ORIGIN',
             51: 'CALLER',
             52: 'CALLVALUE',
             53: 'CALLDATALOAD',
             54: 'CALLDATASIZE',
             55: 'CALLDATACOPY',
             56: 'CODESIZE',
             57: 'CODECOPY',
             58: 'GASPRICE',
             59: 'EXTCODESIZE',
             60: 'EXTCODECOPY',
            # 40s: Block Information
             64: 'BLOCKHASH',
             65: 'COINBASE',
             66: 'TIMESTAMP',
             67: 'NUMBER',
             68: 'DIFFICULTY',
             69: 'GASLIMIT',
            # 50s: Stack, Memory, Storage and Flow Operations
             80: 'POP',
             81: 'MLOAD',
             82: 'MSTORE',
             83: 'MSTORE8',
             84: 'SLOAD',
             85: 'SSTORE',
             86: 'JUMP',
             87: 'JUMPI',
             88: 'PC',
             89: 'MSIZE',
             90: 'GAS',
             91: 'JUMPDEST',
            # 60s & 70s: Push Operations
             96: 'PUSH1',
             97: 'PUSH2',
             98: 'PUSH3',
             99: 'PUSH4',
            100: 'PUSH5',
            101: 'PUSH6',
            102: 'PUSH7',
            103: 'PUSH8',
            104: 'PUSH9',
            105: 'PUSH10',
            106: 'PUSH11',
            107: 'PUSH12',
            108: 'PUSH13',
            109: 'PUSH14',
            110: 'PUSH15',
            111: 'PUSH16',
            112: 'PUSH17',
            113: 'PUSH18',
            114: 'PUSH19',
            115: 'PUSH20',
            116: 'PUSH21',
            117: 'PUSH22',
            118: 'PUSH23',
            119: 'PUSH24',
            120: 'PUSH25',
            121: 'PUSH26',
            122: 'PUSH27',
            123: 'PUSH28',
            124: 'PUSH29',
            125: 'PUSH30',
            126: 'PUSH31',
            127: 'PUSH32',
            # 80s: Duplication Operations
            128: 'DUP1',
            129: 'DUP2',
            130: 'DUP3',
            131: 'DUP4',
            132: 'DUP5',
            133: 'DUP6',
            134: 'DUP7',
            135: 'DUP8',
            136: 'DUP9',
            137: 'DUP10',
            138: 'DUP11',
            139: 'DUP12',
            140: 'DUP13',
            141: 'DUP14',
            142: 'DUP15',
            143: 'DUP16',
            # 90s: Exchange Operations
            144: 'SWAP1',
            145: 'SWAP2',
            146: 'SWAP3',
            147: 'SWAP4',
            148: 'SWAP5',
            149: 'SWAP6',
            150: 'SWAP7',
            151: 'SWAP8',
            152: 'SWAP9',
            153: 'SWAP10',
            154: 'SWAP11',
            155: 'SWAP12',
            156: 'SWAP13',
            157: 'SWAP14',
            158: 'SWAP15',
            159: 'SWAP16',
            # a0s: Logging Operations
            160: 'LOG0',
            161: 'LOG1',
            162: 'LOG2',
            163: 'LOG3',
            164: 'LOG4',
            # f0s: System Operations
            240: 'CREATE',
            241: 'CALL',
            242: 'CALLCODE',
            243: 'RETURN',
            244: 'DELEGATECALL',
            254: 'ASSERTFAIL',
            255: 'SUICIDE'
        },
        'byzantium': {
            # 0s: Stop and Arithmetic Operations
              0: 'STOP',
              1: 'ADD',
              2: 'MUL',
              3: 'SUB',
              4: 'DIV',
              5: 'SDIV',
              6: 'MOD',
              7: 'SMOD',
              8: 'ADDMOD',
              9: 'MULMOD',
             10: 'EXP',
             11: 'SIGNEXTEND',
            # 10s: Comparison & Bitwise Logic Operations
             16: 'LT',
             17: 'GT',
             18: 'SLT',
             19: 'SGT',
             20: 'EQ',
             21: 'ISZERO',
             22: 'AND',
             23: 'OR',
             24: 'XOR',
             25: 'NOT',
             26: 'BYTE',
            # 20s: SHA3
             32: 'SHA3',
            # 30s: Environmental Information
             48: 'ADDRESS',
             49: 'BALANCE',
             50: 'ORIGIN',
             51: 'CALLER',
             52: 'CALLVALUE',
             53: 'CALLDATALOAD',
             54: 'CALLDATASIZE',
             55: 'CALLDATACOPY',
             56: 'CODESIZE',
             57: 'CODECOPY',
             58: 'GASPRICE',
             59: 'EXTCODESIZE',
             60: 'EXTCODECOPY',
             61: 'RETURNDATASIZE',
             62: 'RETURNDATACOPY',
            # 40s: Block Information
             64: 'BLOCKHASH',
             65: 'COINBASE',
             66: 'TIMESTAMP',
             67: 'NUMBER',
             68: 'DIFFICULTY',
             69: 'GASLIMIT',
            # 50s: Stack, Memory, Storage and Flow Operations
             80: 'POP',
             81: 'MLOAD',
             82: 'MSTORE',
             83: 'MSTORE8',
             84: 'SLOAD',
             85: 'SSTORE',
             86: 'JUMP',
             87: 'JUMPI',
             88: 'PC',
             89: 'MSIZE',
             90: 'GAS',
             91: 'JUMPDEST',
            # 60s & 70s: Push Operations
             96: 'PUSH1',
             97: 'PUSH2',
             98: 'PUSH3',
             99: 'PUSH4',
            100: 'PUSH5',
            101: 'PUSH6',
            102: 'PUSH7',
            103: 'PUSH8',
            104: 'PUSH9',
            105: 'PUSH10',
            106: 'PUSH11',
            107: 'PUSH12',
            108: 'PUSH13',
            109: 'PUSH14',
            110: 'PUSH15',
            111: 'PUSH16',
            112: 'PUSH17',
            113: 'PUSH18',
            114: 'PUSH19',
            115: 'PUSH20',
            116: 'PUSH21',
            117: 'PUSH22',
            118: 'PUSH23',
            119: 'PUSH24',
            120: 'PUSH25',
            121: 'PUSH26',
            122: 'PUSH27',
            123: 'PUSH28',
            124: 'PUSH29',
            125: 'PUSH30',
            126: 'PUSH31',
            127: 'PUSH32',
            # 80s: Duplication Operations
            128: 'DUP1',
            129: 'DUP2',
            130: 'DUP3',
            131: 'DUP4',
            132: 'DUP5',
            133: 'DUP6',
            134: 'DUP7',
            135: 'DUP8',
            136: 'DUP9',
            137: 'DUP10',
            138: 'DUP11',
            139: 'DUP12',
            140: 'DUP13',
            141: 'DUP14',
            142: 'DUP15',
            143: 'DUP16',
            # 90s: Exchange Operations
            144: 'SWAP1',
            145: 'SWAP2',
            146: 'SWAP3',
            147: 'SWAP4',
            148: 'SWAP5',
            149: 'SWAP6',
            150: 'SWAP7',
            151: 'SWAP8',
            152: 'SWAP9',
            153: 'SWAP10',
            154: 'SWAP11',
            155: 'SWAP12',
            156: 'SWAP13',
            157: 'SWAP14',
            158: 'SWAP15',
            159: 'SWAP16',
            # a0s: Logging Operations
            160: 'LOG0',
            161: 'LOG1',
            162: 'LOG2',
            163: 'LOG3',
            164: 'LOG4',
            # f0s: System Operations
            240: 'CREATE',
            241: 'CALL',
            242: 'CALLCODE',
            243: 'RETURN',
            244: 'DELEGATECALL',
            250: 'STATICCALL',
            253: 'REVERT',
            254: 'INVALID',
            255: 'SELFDESTRUCT'
        },
        'petersburg': {
            # 0s: Stop and Arithmetic Operations
              0: 'STOP',
              1: 'ADD',
              2: 'MUL',
              3: 'SUB',
              4: 'DIV',
              5: 'SDIV',
              6: 'MOD',
              7: 'SMOD',
              8: 'ADDMOD',
              9: 'MULMOD',
             10: 'EXP',
             11: 'SIGNEXTEND',
            # 10s: Comparison & Bitwise Logic Operations
             16: 'LT',
             17: 'GT',
             18: 'SLT',
             19: 'SGT',
             20: 'EQ',
             21: 'ISZERO',
             22: 'AND',
             23: 'OR',
             24: 'XOR',
             25: 'NOT',
             26: 'BYTE',
             27: 'SHL',
             28: 'SHR',
             29: 'SAR',
            # 20s: SHA3
             32: 'SHA3',
            # 30s: Environmental Information
             48: 'ADDRESS',
             49: 'BALANCE',
             50: 'ORIGIN',
             51: 'CALLER',
             52: 'CALLVALUE',
             53: 'CALLDATALOAD',
             54: 'CALLDATASIZE',
             55: 'CALLDATACOPY',
             56: 'CODESIZE',
             57: 'CODECOPY',
             58: 'GASPRICE',
             59: 'EXTCODESIZE',
             60: 'EXTCODECOPY',
             61: 'RETURNDATASIZE',
             62: 'RETURNDATACOPY',
             63: 'EXTCODEHASH',
            # 40s: Block Information
             64: 'BLOCKHASH',
             65: 'COINBASE',
             66: 'TIMESTAMP',
             67: 'NUMBER',
             68: 'DIFFICULTY',
             69: 'GASLIMIT',
             70: 'CHAINID',
             71: 'SELFBALANCE',
            # 50s: Stack, Memory, Storage and Flow Operations
             80: 'POP',
             81: 'MLOAD',
             82: 'MSTORE',
             83: 'MSTORE8',
             84: 'SLOAD',
             85: 'SSTORE',
             86: 'JUMP',
             87: 'JUMPI',
             88: 'PC',
             89: 'MSIZE',
             90: 'GAS',
             91: 'JUMPDEST',
            # 60s & 70s: Push Operations
             96: 'PUSH1',
             97: 'PUSH2',
             98: 'PUSH3',
             99: 'PUSH4',
            100: 'PUSH5',
            101: 'PUSH6',
            102: 'PUSH7',
            103: 'PUSH8',
            104: 'PUSH9',
            105: 'PUSH10',
            106: 'PUSH11',
            107: 'PUSH12',
            108: 'PUSH13',
            109: 'PUSH14',
            110: 'PUSH15',
            111: 'PUSH16',
            112: 'PUSH17',
            113: 'PUSH18',
            114: 'PUSH19',
            115: 'PUSH20',
            116: 'PUSH21',
            117: 'PUSH22',
            118: 'PUSH23',
            119: 'PUSH24',
            120: 'PUSH25',
            121: 'PUSH26',
            122: 'PUSH27',
            123: 'PUSH28',
            124: 'PUSH29',
            125: 'PUSH30',
            126: 'PUSH31',
            127: 'PUSH32',
            # 80s: Duplication Operations
            128: 'DUP1',
            129: 'DUP2',
            130: 'DUP3',
            131: 'DUP4',
            132: 'DUP5',
            133: 'DUP6',
            134: 'DUP7',
            135: 'DUP8',
            136: 'DUP9',
            137: 'DUP10',
            138: 'DUP11',
            139: 'DUP12',
            140: 'DUP13',
            141: 'DUP14',
            142: 'DUP15',
            143: 'DUP16',
            # 90s: Exchange Operations
            144: 'SWAP1',
            145: 'SWAP2',
            146: 'SWAP3',
            147: 'SWAP4',
            148: 'SWAP5',
            149: 'SWAP6',
            150: 'SWAP7',
            151: 'SWAP8',
            152: 'SWAP9',
            153: 'SWAP10',
            154: 'SWAP11',
            155: 'SWAP12',
            156: 'SWAP13',
            157: 'SWAP14',
            158: 'SWAP15',
            159: 'SWAP16',
            # a0s: Logging Operations
            160: 'LOG0',
            161: 'LOG1',
            162: 'LOG2',
            163: 'LOG3',
            164: 'LOG4',
            # f0s: System Operations
            240: 'CREATE',
            241: 'CALL',
            242: 'CALLCODE',
            243: 'RETURN',
            244: 'DELEGATECALL',
            245: 'CREATE2',
            250: 'STATICCALL',
            253: 'REVERT',
            254: 'INVALID',
            255: 'SELFDESTRUCT'
        }
    }
