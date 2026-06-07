from slither import Slither
from slither.core.declarations import Function, Contract, Modifier
from slither.core.variables.variable import Variable
from slither.slithir.operations import InternalCall, Condition, Binary
from slither.core.expressions.binary_operation import BinaryOperation, BinaryOperationType
from slither.core.expressions.unary_operation import UnaryOperation, UnaryOperationType
from slither.core.expressions.identifier import Identifier
from slither.core.expressions.call_expression import CallExpression
from typing import Dict, List, Any

class RequireExtractor:
    def __init__(self, contract: Contract):
        self.contract = contract
        self.state_var = []
        for v in self.contract.state_variables:
            if v.visibility == 'public':
                self.state_var.append(v.name)
        self.key_val = {}
        self.require_key_fun = {}

    def add_key_val(self, key: str, value: List[str],function_name: str):
        """向key_val字典中添加key-value，已存在则不添加"""
        if key not in self.key_val:
            self.key_val[key] = []
            self.require_key_fun[key] = {}
        if value not in self.key_val[key]:
            self.key_val[key].append(value)
            self.require_key_fun[key][str(value)] = []
        
        for i in range(len(self.key_val[key])):
            if value == self.key_val[key][i] and function_name not in self.require_key_fun[key][str(self.key_val[key][i])]:
                self.require_key_fun[key][str(self.key_val[key][i])].append(function_name)
                break

    def analyze(self) -> Dict[str, Any]:
        """主分析函数"""
        results = {}
        # 兼容性检查：isInterface (旧版) vs is_interface (新版)
        is_interface = getattr(self.contract, 'is_interface', None) or getattr(self.contract, 'isInterface', False)
        if is_interface:
            return {}
        
        for function in self.contract.functions:
            if function.is_constructor:
                continue
            results[function.full_name] = []
            for modifier in function.modifiers:
                resdata = self.extract_require_from_modifier(modifier,function)
                results[function.full_name].extend(resdata)
            for node in function.nodes:
                for ir in node.irs:
                    if "require(" in str(node):
                        results[function.full_name].extend(self.extract_comparison(ir.node.expression.arguments[0], function))
        results = self.deduplicate_require_json(results)
        return results , self.key_val, self.state_var , self.require_key_fun
    
    def analyze_require_complexity(self) -> Dict[str, Any]:
        """主分析函数"""
        results = {}
        # 兼容性检查：isInterface (旧版) vs is_interface (新版)
        is_interface = getattr(self.contract, 'is_interface', None) or getattr(self.contract, 'isInterface', False)
        if is_interface:
            return {}
        max_require = 0
        
        for function in self.contract.functions:
            if function.is_constructor:
                continue
            results[function.full_name] = []
            for modifier in function.modifiers:
                resdata = self.extract_require_from_modifier(modifier,function)
                results[function.full_name].extend(resdata)
            for node in function.nodes:
                for ir in node.irs:
                    if "require" in str(node) and len(ir.node.expression.arguments) > 0:
                        results[function.full_name].extend(self.extract_comparison(ir.node.expression.arguments[0], function))
            
        results = self.deduplicate_require_json(results)
        for k,v in results.items():
            max_require = max(max_require,len(results[k]))
        return max_require

    def extract_require_from_modifier(self, modifier: Modifier, function: Function) -> List[str]:
        """提取modifier中的require条件"""
        results = []
        for node in modifier.nodes:
            for ir in node.irs:
                if "require" in str(node) and len(ir.node.expression.arguments) > 0:
                    results.extend(self.extract_comparison(ir.node.expression.arguments[0], function))
        return results
    
    

    def classify_variable(self, var: Variable, function: Function) -> str:
        """判断变量类型并返回分类标识"""
        if str(var).startswith('msg.'):
            return 'msg'
        elif str(var).startswith('block.'):
            return 'block'
        elif str(var).startswith('tx.'):
            return 'tx'
        elif str(var).isnumeric():
            return 'number'
        if var in function.parameters:
            return 'input'
        return 'state'

    def cal_operator(self, operator: str) -> str:
        """计算操作符"""
        if operator == '>':
            return '<'
        elif operator == '<':
            return '>'
        elif operator == '>=':
            return '<='
        elif operator == '<=':
            return '>='
        else:
            return operator
    def extract_comparison(self, expression, function: Function) -> List[str]:
        """递归解析比较表达式"""
        constraints = []
        if expression.__class__ not in [BinaryOperation, Identifier, CallExpression, UnaryOperation]:
            return constraints
        if isinstance(expression, BinaryOperation) and expression.type in [
            BinaryOperationType.GREATER, BinaryOperationType.LESS,
            BinaryOperationType.GREATER_EQUAL, BinaryOperationType.LESS_EQUAL,
            BinaryOperationType.EQUAL, BinaryOperationType.NOT_EQUAL
        ]:
            # 兼容性: type_str (旧版) vs str(type) (新版)
            operator = getattr(expression, 'type_str', None) or str(expression.type)
            left = expression.expression_left
            right = expression.expression_right
            left_type = self.classify_variable(left, function)
            right_type = self.classify_variable(right, function)
            
            if left_type == 'state':
                if str(left) in self.state_var:
                    self.add_key_val(str(left), [operator, str(right)],function.name)
            if right_type == 'state':
                if str(right) in self.state_var:
                    self.add_key_val(str(right), [self.cal_operator(operator), str(left)],function.name)
            if operator in ['>', '<', '>=', '<=', '==', '!=']:
                if left_type == 'number' and right_type == 'number':
                    return []
                if left_type != 'state':
                    constraints.append(str(left) + operator + str(right))
                elif right_type != 'state':
                    constraints.append(str(left) + operator + str(right))
        elif isinstance(expression, UnaryOperation) and expression.type in [UnaryOperationType.BANG]:
            constraints.append(str(expression))
            type = self.classify_variable(expression.expression, function)
            if type == 'state':
                if str(expression.expression) in self.state_var:
                    # 兼容性: type_str (旧版) vs str(type) (新版)
                    op_str = getattr(expression, 'type_str', None) or str(expression.type)
                    self.add_key_val(str(expression.expression), [op_str, str(expression.expression)],function.name)
        elif isinstance(expression, Identifier):
            constraints.append(str(expression))
            type = self.classify_variable(expression, function)
            if type == 'state':
                if str(expression) in self.state_var:
                    self.add_key_val(str(expression),  [None, str(expression)],function.name)
        elif isinstance(expression, CallExpression):
            constraints.append(str(expression))
        elif hasattr(expression, 'expressions'):
            for sub_exp in expression.expressions:
                sub_constraints = self.extract_comparison(sub_exp, function)
                constraints.extend(sub_constraints)
        return constraints

    def deduplicate_require_json(self, require_json: dict) -> dict:
        """
        对提取的require条件JSON结果去重
        :param require_json: 形如 { \"func_name\": [cond1, cond2, ...], ... }
        :return: 去重后的JSON
        """
        deduped = {}
        for func, conds in require_json.items():
            seen = set()
            unique_conds = []
            for cond in conds:
                if cond not in seen:
                    unique_conds.append(cond)
                    seen.add(cond)
            deduped[func] = unique_conds
        return deduped

# 用法示例
if __name__ == "__main__":
    from solc_version_manager import get_compiler_config, get_solc_binary_path

    contract_path = '/home/hzh/AMFuzz/benchmark/contracts_sample/large/Liquidator_0x1055be4bf7338c7606d9efdcf80593f180ba043e.sol'
    contract_name = 'Liquidator'

    # 使用版本管理器获取正确的 solc 二进制
    solc_version, _, _ = get_compiler_config(contract_path)
    solc_binary = get_solc_binary_path(solc_version)
    slither = Slither(contract_path, solc=solc_binary)

    contract = slither.get_contract_from_name(contract_name)
    extractor = RequireExtractor(contract)
    constraints = extractor.analyze()
    import json
    print(json.dumps(constraints, indent=2, ensure_ascii=False))
    print(json.dumps(extractor.key_val, indent=2, ensure_ascii=False))

