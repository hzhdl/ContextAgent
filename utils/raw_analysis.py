from slither.slither import Slither
from collections import defaultdict
from . import settings
from math import log2
import random
from slither.core.declarations import Function
from slither.core.cfg.node import NodeType
from slither.slithir.operations import (Binary,HighLevelCall, LowLevelCall,
                                       Transfer, Send)
# RequireOrAssert 兼容性导入（可能在新版本中路径变化或不再需要）
try:
    from slither.printers.summary.require_calls import RequireOrAssert
except ImportError:
    RequireOrAssert = None  # 未使用，允许导入失败

# 导入版本管理器
from .solc_version_manager import get_compiler_config, get_solc_binary_path


# example.py
from .require_extractor import (
    RequireExtractor
)


def _get_contract_by_name(slither_instance, name):
    """兼容性获取指定名称的合约（适配不同 slither 版本）"""
    if hasattr(slither_instance, 'get_contract_from_name'):
        result = slither_instance.get_contract_from_name(name)
        if result:
            # 新版本可能返回列表
            return result[0] if isinstance(result, list) else result
    # 回退方法：遍历 contracts
    for c in slither_instance.contracts:
        if c.name == name:
            return c
    return None


def get_tx_list(contract_path,funname2hash,abi,contractname=None):
    # 获取编译器配置并使用指定的 solc 二进制
    solc_version, _, _ = get_compiler_config(contract_path)
    solc_binary = get_solc_binary_path(solc_version)
    slither = Slither(contract_path, solc=solc_binary)

    # Get the contract
    Read = {}
    Written = {}
    other_fun = abi[0] + abi[1]
    cri_functions = []
    min_seq_len = 10
    min_paths = 100
    contract = _get_contract_by_name(slither, contractname)
    extractor = RequireExtractor(contract)
    require_data, key_val, state_var , require_key_tx_fun = extractor.analyze()
   
        # for fun in contract.functions_entry_points:
        #     if fun.visibility == 'internal' or fun.visibility == 'private' or fun.is_constructor:
        #         continue
        #     other_fun.append(fun.name)

    for function in contract.functions:
        if function.visibility == 'internal' or function.visibility == 'private':
            continue

        
        
        if has_dangerous_operations(function) and not function.is_constructor:
            cri_functions.append(function.name)
        # print('Function: {}'.format(function.name))

        # print('\tRead: {}'.format([v.name for v in function.state_variables_read]))
        # print('\tWritten {}'.format([v.name for v in function.state_variables_written]))
        for v in function.state_variables_read:
            if Read.get(v.name) == None:
                Read[v.name] = []
            if function.is_constructor:
                Read[v.name].append("constructor")
            else:
                Read[v.name].append(function.name)
            
        for v in function.state_variables_written:
            if Written.get(v.name) == None:
                Written[v.name] = []
            if function.is_constructor:
                Written[v.name].append("constructor")
            else:
                Written[v.name].append(function.name)

    # 将abi[0]中的元素添加到Read中

    graph = {}
    rw_count= {}

    for k,v in Read.items():
        for kk,vv in Written.items():
            if k == kk:
                for i in v:
                    for j in vv:                    
                        if i!=j:
                            if rw_count.get(j) == None:
                                rw_count[j] = 0
                            rw_count[j] += 1
                            if graph.get(j) == None:
                                graph[j] = []
                            graph[j].append(i)
    if "constructor" in graph:
        mk = "constructor"
    elif len(graph) != 0:
        mv=max(rw_count.values())
        mk= None
        for k,v in rw_count.items():
            if v == mv:
                mk = k
                break
    else:
        mk = None
        mv = None
    # print(graph)

    if len(graph) == 0:
        paths = []
        use_functions = []
    else:
        # paths, use_functions = find_paths(graph, mk)
        # paths, use_functions = find_half_paths(graph)
        importance = get_key_nodes_importance(graph, cri_functions)
        paths, use_functions = extract_paths_by_importance(graph, importance,num_walks=30)
        

        
        # length = 0
        # for path in paths:
        #     length += len(path)
        # avlen= length/len(paths)
    
    # all_fun = list(funname2hash.keys())
    
    difference_list = [item for item in other_fun if item not in use_functions]
    if len(difference_list) != 0:
        ran_list = generate_subsets(difference_list, max(min_paths*2//3-len(paths)*2,2), 3)
        # for i,v in enumerate(paths):
            # 这里可以生成构造函数在列表中，这里不考虑增加了
            # paths.append(ran_list[i]) 
            # paths[i]=  v[1:] 
        paths.extend(ran_list)
    # if mk!= "constructor":
    #     for path in paths:
    #         path.insert(0,"constructor")
    
    if cri_functions:
        for i,v in enumerate(paths):
            paths[i] = v + random.choices(cri_functions, k=1)
        while len(paths) < min_paths:
            paths.insert(0,random.choices(cri_functions, k=1))
    else:
        if len(paths) < min_paths:
            tl=generate_subsets(difference_list, min_paths-len(paths), 1)
            paths.extend(tl)
    for i in abi[0]:
        paths.insert(0,[i])
        paths.insert(0,[i])
    for i in abi[1]:
        paths.insert(0,[i])
        paths.insert(0,[i])
    
    #处理key_val
    for k in key_val.keys():
        for item in key_val[k]:
            item.append(1/len(key_val[k]))

    require_key_fun = {}
    for k in key_val.keys():
        if k in Written.keys():
            for kk in Written[k]:
                if kk == "constructor":
                    continue
                if kk not in require_key_fun.keys():
                    require_key_fun[funname2hash[kk]] = set()
                require_key_fun[funname2hash[kk]].add(k)
    # key_var = {}
    # for k in key_val.keys():
    #     for item in key_val[k]:
    #         key_var[funname2hash[k]] = item.copy()
    if not settings.TX_GEN:
        newpaths = []
        for i in abi[0]:
            newpaths.insert(0,[i])
            newpaths.insert(0,[i])
        for i in abi[1]:
            newpaths.insert(0,[i])
            newpaths.insert(0,[i])
        abis = abi[0] + abi[1]
        # while len(newpaths) < 100:
            # newpaths.append(random.choices(abis,k=1))
        return newpaths, [Read, Written], state_var , key_val, require_key_fun,require_key_tx_fun

    
    return paths, [Read, Written], state_var , key_val, require_key_fun,require_key_tx_fun



def has_dangerous_operations(function) -> bool:
    """
    检查函数是否包含危险操作
    :param function: Slither 函数对象
    :return: 是否包含危险操作
    """
    # 遍历函数的中间表示（IR）操作
    for node in function.nodes:
        for ir in node.irs:
            # 检测低级调用（call.value/delegatecall）
            if isinstance(ir, LowLevelCall):
                return True
            if any(
            "delegatecall(" in str(ir) or 
            ".call.value(" in str(ir) 
            for ir in node.irs if hasattr(ir, 'expression')
            ):
                return True
            # 检测 transfer/send
            elif isinstance(ir, (Transfer, Send)):
                return True
            # 检测 selfdestruct
            elif (node.type == NodeType.EXPRESSION and 
            "selfdestruct(" in str(node.expression)):
                return True
            # 检测未经验证的外部调用（HighLevelCall 可能是安全的，但需结合上下文）
            elif isinstance(ir, HighLevelCall) and not is_safe_external_call(ir):
                return True
            # 检测时间戳依赖
            elif (isinstance(ir, Binary) and 
                ((ir.variable_left and "block.timestamp" in str(ir.variable_left)) or
                (ir.variable_right and "block.timestamp" in str(ir.variable_right)))):
                return True
            elif (isinstance(ir, Binary) and 
                ((ir.variable_left and "block.number" in str(ir.variable_left)) or
                (ir.variable_right and "block.number" in str(ir.variable_right)))):
                return True
    return False


def is_safe_external_call(ir: HighLevelCall) -> bool:
    """
    检查外部调用是否安全（例如有权限控制或返回值验证）
    :param ir: 高级调用对象
    :return: 是否安全
    """
    # 示例：如果调用后验证了返回值，则认为是相对安全的
    if not hasattr(ir.function, 'nodes'):
        return False
    for node in ir.function.nodes:
        if "require" in str(node) or "assert" in str(node):
            return True
    return False


def generate_subsets(original_list, M, N):
    
    K = len(original_list)
    subsets = []
    element_counts = defaultdict(int)
    
    # 生成M个子集，每个子集长度在2和N之间
    for _ in range(M):
        subset = random.sample(original_list, min(2, K))
        while len(subset) < min(2, K):
            subset.append(random.choice(original_list))
        while len(subset) < N and random.choice([True, False]):
            subset.append(random.choice(original_list))
        subsets.append(subset)
        for elem in subset:
            element_counts[elem] += 1
    
    # 确保每个元素至少出现两次
    for elem in original_list:
        while element_counts[elem] < 2:
            # 选择一个子集添加elem
            for subset in subsets:
                if len(subset) < N:
                    subset.append(elem)
                    element_counts[elem] += 1
                    break
            else:
                # 所有子集已满，无法添加
                break
    
    # 确保子集数量为M
    while len(subsets) < M:
        if subsets:
            subsets.append(random.choice(subsets))
        else:
            subsets.append([random.choice(original_list), random.choice(original_list)])
    
    return subsets[:M]

def find_paths(graph, start):
    use_functions = []
    def dfs(node, path):
        # 将当前节点加入路径
        path.append(node)
        if node not in use_functions:
            use_functions.append(node)
        # 如果当前节点没有邻居节点，保存当前路径
        if node not in graph:
            all_paths.append(path.copy())
        else:
            # 遍历当前节点的所有邻居节点
            for neighbor in graph[node]:
                if neighbor not in path:  # 确保节点只被访问一次
                    dfs(neighbor, path)
        # 回溯，移除当前节点
        path.pop()

    all_paths = []
    dfs(start, [])
    for path in all_paths:
        if path[0] == "constructor":
            del path[0]
    return all_paths , use_functions

def find_half_paths(graph):
    use_functions = []
    def dfs(node, path):
        # 将当前节点加入路径
        path.append(node)
        if node not in use_functions:
            use_functions.append(node)
        # 如果当前路径长度达到总节点数的一半，保存当前路径
        # if len(path) >= len(graph) // 2:
        if len(path) >= 3 :
            all_paths.append(path.copy())
            path.pop()
            return
        # 如果当前节点没有邻居节点，保存当前路径
        if node not in graph:
            all_paths.append(path.copy())
        else:
            # 遍历当前节点的所有邻居节点
            for neighbor in graph[node]:
                if neighbor not in path:  # 确保节点只被访问一次
                    dfs(neighbor, path)
        # 回溯，移除当前节点
        all_paths.append(path.copy())
        path.pop()

    all_paths = []
    # 随机选择起始点
    graphlen = len(graph.keys())//2
    if len(graph.keys())//2 < 4:
        graphlen = len(graph.keys()) + 1
    
    for i in range(graphlen):
        start = random.choice(list(graph.keys()))
        if start == "constructor":
            continue
        
        dfs(start, [])
    
    return all_paths , use_functions


def calculate_betweenness_centrality(graph):
    """
    计算有向图每个节点的中介中心度。
    graph: dict, 形如 {node: [neighbor1, neighbor2, ...]}
    返回: dict, {node: betweenness_centrality}
    """
    from collections import deque, defaultdict
    nodes = list(graph.keys())
    for vlist in graph.values():
        for v in vlist:
            if v not in nodes:
                nodes.append(v)
    centrality = dict.fromkeys(nodes, 0.0)
    for s in nodes:
        # 单源最短路径
        stack = []
        pred = defaultdict(list)  # 前驱
        sigma = dict.fromkeys(nodes, 0)  # 最短路径条数
        dist = dict.fromkeys(nodes, -1)  # 距离
        sigma[s] = 1
        dist[s] = 0
        queue = deque()
        queue.append(s)
        while queue:
            v = queue.popleft()
            stack.append(v)
            for w in graph.get(v, []):
                # w尚未被发现
                if dist[w] < 0:
                    dist[w] = dist[v] + 1
                    queue.append(w)
                # 最短路径发现
                if dist[w] == dist[v] + 1:
                    sigma[w] += sigma[v]
                    pred[w].append(v)
        # 依次回退累加
        delta = dict.fromkeys(nodes, 0.0)
        while stack:
            w = stack.pop()
            for v in pred[w]:
                delta[v] += (sigma[v] / sigma[w]) * (1 + delta[w])
            if w != s:
                centrality[w] += delta[w]
    # 归一化（有向图）
    n = len(nodes)
    if n > 2:
        for v in centrality:
            centrality[v] /= ((n-1)*(n-2))
    return centrality


def calculate_closeness_centrality(graph):
    """
    计算有向图每个节点的紧密度中心度（归一化）。
    graph: dict, 形如 {node: [neighbor1, neighbor2, ...]}
    返回: dict, {node: closeness_centrality}
    """
    from collections import deque
    nodes = list(graph.keys())
    for vlist in graph.values():
        for v in vlist:
            if v not in nodes:
                nodes.append(v)
    n = len(nodes)
    centrality = dict.fromkeys(nodes, 0.0)
    for s in nodes:
        # BFS计算最短路径
        dist = {v: float('inf') for v in nodes}
        dist[s] = 0
        queue = deque([s])
        while queue:
            v = queue.popleft()
            for w in graph.get(v, []):
                if dist[w] == float('inf'):
                    dist[w] = dist[v] + 1
                    queue.append(w)
        # 只统计可达节点
        reachable = [d for v, d in dist.items() if v != s and d < float('inf')]
        if reachable:
            sum_dist = sum(reachable)
            # 归一化紧密度中心度
            centrality[s] = (len(reachable)) / sum_dist * (len(reachable)/(n-1))
        else:
            centrality[s] = 0.0
    return centrality


def get_key_nodes_importance(graph, key_nodes):
    """
    计算关键节点的重要性：0.5*中心性 + 0.5*1
    graph: 有向图
    key_nodes: 关键节点列表
    返回: {node: importance}
    """
    closeness = calculate_closeness_centrality(graph)
    importance = {}
    for node in key_nodes:
        c = closeness.get(node, 0.0)
        importance[node] = 0.5 * c + 0.5 * 1
    return importance


def extract_paths_by_importance(graph, importance, walk_length=5, num_walks=20, backward_steps=3):
    """
    按重要性分数排序，将所有大于0的重要性节点作为起点进行游走，
    游走时优先选择重要性更高的邻居节点作为下个节点。
    同时也从该节点逆向（前驱）游走backward_steps步。
    返回所有抽取的路径，以及所有路径中出现过的节点列表（去重）。
    """
    import random
    # 构建反向图
    reverse_graph = {n: [] for n in graph}
    for src, dsts in graph.items():
        for dst in dsts:
            if dst not in reverse_graph:
                reverse_graph[dst] = []
            reverse_graph[dst].append(src)
    # 1. 按重要性分数排序，筛选大于0的节点作为起点
    start_nodes = [n for n, score in sorted(importance.items(), key=lambda x: -x[1]) if score > 0]
    paths = []
    for start in start_nodes:
        for _ in range(num_walks):
            # 正向游走
            path = [start]
            current = start
            for _ in range(walk_length - 1):
                neighbors = graph.get(current, [])
                if not neighbors:
                    break
                neighbors = sorted(neighbors, key=lambda n: importance.get(n, 0), reverse=True)
                max_score = importance.get(neighbors[0], 0)
                candidates = [n for n in neighbors if importance.get(n, 0) == max_score]
                next_node = random.choice(candidates)
                path.append(next_node)
                current = next_node
            paths.append(path)
            # 逆向游走
            back_path = [start]
            current = start
            for _ in range(backward_steps):
                prevs = reverse_graph.get(current, [])
                if not prevs:
                    break
                prevs = sorted(prevs, key=lambda n: importance.get(n, 0), reverse=True)
                max_score = importance.get(prevs[0], 0)
                candidates = [n for n in prevs if importance.get(n, 0) == max_score]
                prev_node = random.choice(candidates)
                back_path.append(prev_node)
                current = prev_node
            if len(back_path) > 1:
                paths.append(back_path)
    # 拆分并去重
    final_paths = split_and_deduplicate_paths(paths)
    # 收集所有节点
    node_set = set()
    for p in final_paths:
        node_set.update(p)
    return final_paths, list(node_set)


def split_and_deduplicate_paths(paths):
    """
    对所有路径进行拆分，保留所有长度>=2的连续子路径，并去重。
    返回去重后的路径列表。
    """
    unique_paths = set()
    for path in paths:
        n = len(path)
        for length in range(2, n+1):
            for i in range(n - length + 1):
                sub_path = tuple(path[i:i+length])
                unique_paths.add(sub_path)
    return [list(p) for p in unique_paths]


if __name__ == '__main__':
    # contract_path = '/home/hzh/Fuzz/MPFuzz/ConFuzzius/examples/data/crowdsale.sol'
    # paths, rw = get_tx_list(contract_path)
    # print(paths)
    # # print(rw)

    # contract_path = '/home/hzh/Fuzz/MPFuzz/ConFuzzius/examples/data/grid.sol'
    # paths, rw = get_tx_list(contract_path)
    # print(paths)

    contract_path = '/home/hzh/Fuzz/MPFuzz/ConFuzzius/examples/RemiCoin/contracts/RemiCoin.sol'
    paths, rw = get_tx_list(contract_path,"RemiCoin")
    print(paths)

    

        






