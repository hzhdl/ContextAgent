#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from z3 import is_expr
from utils import settings

class UnprotectedSelfdestructDetector():
    def __init__(self):
        self.init()

    def init(self):
        self.swc_id = 106
        self.severity = "High"
        self.trusted_arguments = ""

    def detect_unprotected_selfdestruct(self, current_instruction, tainted_record, individual, transaction_index):
        if current_instruction["op"] in ["SELFDESTRUCT", "SUICIDE"]:
            # 原有data校验
            sender = individual.solution[transaction_index]["transaction"]["from"]
            is_data_unprotected = False
            self.trusted_arguments = getattr(self, 'trusted_arguments', "")
            for i in range(transaction_index):
                # Check if it is a trusted account
                if individual.solution[i]["transaction"]["from"] not in settings.ATTACKER_ACCOUNTS:
                    # Add the arguments to the list of trusted arguments
                    if individual.solution[i]["transaction"]["data"] not in self.trusted_arguments:
                        self.trusted_arguments += individual.solution[i]["transaction"]["data"]
            if sender in settings.ATTACKER_ACCOUNTS and not sender.replace("0x", "") in self.trusted_arguments:
                is_data_unprotected = True

            # 新增权限校验
            is_permission_unprotected = False
            if sender in settings.ATTACKER_ACCOUNTS:
                has_protection = False
                for i in range(transaction_index+1):
                    tx = individual.solution[i]["transaction"]
                    # 检查是否有require/assert等权限校验
                    if "require" in tx.get("conditions", "") or "assert" in tx.get("conditions", ""):
                        # 检查是否有类似 require(msg.sender == owner) 的表达式
                        if "msg.sender" in tx["conditions"] and ("owner" in tx["conditions"] or "admin" in tx["conditions"]):
                            has_protection = True
                            break
                if not has_protection:
                    is_permission_unprotected = True

            # 只要有一种方式不安全就报告
            if is_data_unprotected or is_permission_unprotected:
                return current_instruction["pc"], transaction_index
        return None, None
