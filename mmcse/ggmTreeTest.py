'''
Sensen Li

| XXXXXX

:Author:         Sensen Li
:Date:           11/2024
'''
# import ggmTree
from utils import ggmTree

TREE_SIZE = 8

def main():
    tree = ggmTree.GGMTree(TREE_SIZE)
    
    # add test nodes
    node_list = []
    node_list.append(ggmTree.GGMNode(0,tree.level))
    node_list.append(ggmTree.GGMNode(1,tree.level))
    node_list.append(ggmTree.GGMNode(3,tree.level))
    node_list.append(ggmTree.GGMNode(4,tree.level))
    node_list.append(ggmTree.GGMNode(5,tree.level))
    
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
    main()