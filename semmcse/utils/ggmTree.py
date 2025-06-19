import copy
import hashlib
import math
import numpy as np


def key_derivation(plaintext: bytes, bit: int) -> bytes or None:
    hash_msg = hashlib.sha256(plaintext).digest()
    if bit == 0:
        return hash_msg[0:16]
    if bit == 1:
        return hash_msg[16:]
    print("bit should be 0 or 1")
    return None


class GGMNode:

    def __init__(self, index: int, level: int, key: bytes = None):
        self.index = index
        self.level = level
        self.key = copy.deepcopy(key)

class GGMTree:

    def __init__(self, node_num):
        self.level = int(math.ceil(np.log2(node_num)))

    # compute min_coverage of a node_list, without keys
    @staticmethod
    def min_coverage(node_list: list[GGMNode]) -> list[GGMNode]:
        next_level_node = []
        i = 0
        while i < len(node_list):
            node1 = node_list[i]
            if i + 1 == len(node_list):
                next_level_node.append(node1)
            else:
                node2 = node_list[i + 1]
                if ((node1.index >> 1) == (node2.index >> 1)) and (node1.level == node2.level):
                    next_level_node.append(GGMNode(node1.index >> 1, node1.level - 1))
                    i += 1
                else:
                    next_level_node.append(node1)
            i += 1
        if len(next_level_node) == len(node_list) or len(next_level_node) == 0:
            return node_list
        return GGMTree.min_coverage(next_level_node)

    # compute key of a node
    @staticmethod
    def derive_key_from_tree(current_key: bytes, offset: int, start_level: int, target_level: int) -> bytes:
        if start_level == target_level:
            return current_key
        k = start_level
        while k > target_level:
            k_bit = (offset & (1 << (k - 1))) >> (k - 1)
            current_key = copy.deepcopy(key_derivation(current_key, k_bit))
            k -= 1
        return current_key

    # compute leaf_node and their keys by min coverage
    @staticmethod
    def compute_leaf(node_list: list[GGMNode], target_level: int) -> list[GGMNode]:
        leaf = []
        for node in node_list:
            i = 0
            while i < pow(2, target_level - node.level):
                offset = (node.index << (target_level - node.level)) + i
                derive_key = node.key
                derive_key = GGMTree.derive_key_from_tree(derive_key, offset, target_level - node.level, 0)
                leaf.append(GGMNode(offset, target_level, derive_key))
                i += 1
        return leaf

def testGGMTree():
    TREE_SIZE = 8
    tree = GGMTree(TREE_SIZE)
    
    # add test nodes
    node_list = []
    node_list.append(GGMNode(0,tree.level))
    node_list.append(GGMNode(1,tree.level))
    node_list.append(GGMNode(3,tree.level))
    node_list.append(GGMNode(4,tree.level))
    node_list.append(GGMNode(5,tree.level))
    
    # 测试min_coverage
    coverage = tree.min_coverage(node_list)
    print(coverage) 
    
    # 测试derive_key_from_tree和compute_leaf
    root_key = 'root'.encode('utf-8') #设置根节点密钥
    for node in node_list:
        node.key = tree.derive_key_from_tree(root_key, node.index, node.level, 0)
    print(node_list) 
    for node in coverage:
        node.key = tree.derive_key_from_tree(root_key, node.index, node.level, 0)
    leaf = tree.compute_leaf(coverage, 3)
    print(leaf)
    
if __name__ == "__main__":
    debug = True
    testGGMTree()