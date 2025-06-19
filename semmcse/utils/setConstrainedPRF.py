'''
Sensen Li

| Set-constrained pseudorandom function (scPRF)

:Author:         Sensen Li
:Date:           11/2024
'''

# import ggmTree
from utils import ggmTree
# import SSEUtil
from utils import SSEUtil
import random

class SCPRF(object):
    """
    Set-constrained pseudorandom function (scPRF) class
    Reference: "Practical Multi-source Multi-client Searchable Encryption with Forward Privacy: Refined
                Security Notion and New Constructions"
                
    Implements Setup, Cons, and Eval operations.
    """
    def __init__(self, total_element_num=100):
        """
        Args:
            total_element_num (int, optional): The number of elements in the set. Defaults to 100.
        """
        # self.tElementNum = total_element_num
        self.tElementList = [i for i in range(total_element_num)]
        self.tree = ggmTree.GGMTree(total_element_num)

    def Setup(self, sec_lambda = 128):
        """
        Setup
        It takes a security parameter λ and outputs a description of a PRF key msk_SCPRF
        Args:
            sec_lambda (int): The length of security parameter. Defaults to 128.
        """
        msk_SCPRF = SSEUtil.gen_key_F(random.getrandbits(sec_lambda))
        return msk_SCPRF
    
    def Cons(self, msk_SCPRF, cons_set):
        """Cons 
        This algorithm takes as input a PRF key msk_SCPRF and the description of a set cons_set. 
        It outputs a constrained key cons_key. This key cons_key enables the evaluation of
        F(k, x) for all x ∈ cons_set and no other x.
        
        Args:
            msk_SCPRF (bytes): the system key
            cons_set (list): the index set of elements, e.g. cons_set = [1,2,3,8,10]
        """
        # msk_SCPRF_bytes = msk_SCPRF.to_bytes(16, 'little') # the length is defined as 16 bytes
        node_list = []
        for index in cons_set:
            node_list.append(ggmTree.GGMNode(index, self.tree.level))
        min_coverage_list = self.tree.min_coverage(node_list)
        cons_key = []
        for node in min_coverage_list:
            node.key = self.tree.derive_key_from_tree(msk_SCPRF, node.index, node.level, 0)
            cons_key.append((node.level, node.index, node.key))
        return cons_key

    def Eval(self, cons_key, e_index):
        """Eval 
        It takes as input a constrained key cons_key and an an element e_x in tElementList,
        and outputs the value of PRF(msk_SCPRF, e_index) (if e_index is in cons_set 
        corresponding to cons_key) or False (if e_x is not in cons_set corresponding to cons_key).
        
        Args:
            cons_key (list): the t-punctured key list
            e_index (int): the index of element to be evaluated
        """
        bit_length = self.tree.level
        e_index_binstr = SSEUtil.int_to_binary(e_index, bit_length)
        derive_key = 0
        for (level, index, key) in cons_key:
            key_index_binstr = SSEUtil.int_to_binary(index, level)
            if e_index_binstr.startswith(key_index_binstr):
                derive_key = self.tree.derive_key_from_tree(key, e_index, self.tree.level - level, 0)
                return derive_key
        return False
    
def testSCPRF():
    scPRF = SCPRF(65536)
    msk_SCPRF = scPRF.Setup(128)
    cons_set = [1,2,3,8,10,20,30,40,50,100]
    cons_key = scPRF.Cons(msk_SCPRF, cons_set)
    print(len(cons_key))
    print(cons_key)
    print('index = 0:   ' + str(scPRF.Eval(cons_key, 0)) + ';  ' + str(scPRF.tree.derive_key_from_tree(msk_SCPRF, 0, scPRF.tree.level, 0)))
    print('index = 1:   ' + str(scPRF.Eval(cons_key, 1)) + ';  ' + str(scPRF.tree.derive_key_from_tree(msk_SCPRF, 1, scPRF.tree.level, 0)))
    print('index = 2:   ' + str(scPRF.Eval(cons_key, 2)) + ';  ' + str(scPRF.tree.derive_key_from_tree(msk_SCPRF, 2, scPRF.tree.level, 0)))
    print('index = 3:   ' + str(scPRF.Eval(cons_key, 3)) + ';  ' + str(scPRF.tree.derive_key_from_tree(msk_SCPRF, 3, scPRF.tree.level, 0)))
    print('index = 5:   ' + str(scPRF.Eval(cons_key, 5)) + ';  ' + str(scPRF.tree.derive_key_from_tree(msk_SCPRF, 5, scPRF.tree.level, 0)))
    print('index = 8:   ' + str(scPRF.Eval(cons_key, 8)) + ';  ' + str(scPRF.tree.derive_key_from_tree(msk_SCPRF, 8, scPRF.tree.level, 0)))
    print('index = 10:   ' + str(scPRF.Eval(cons_key, 10)) + ';  ' + str(scPRF.tree.derive_key_from_tree(msk_SCPRF, 10, scPRF.tree.level, 0)))
    print('index = 50:   ' + str(scPRF.Eval(cons_key, 50)) + ';  ' + str(scPRF.tree.derive_key_from_tree(msk_SCPRF, 50, scPRF.tree.level, 0)))
    print('index = 80:   ' + str(scPRF.Eval(cons_key, 80)) + ';  ' + str(scPRF.tree.derive_key_from_tree(msk_SCPRF, 80, scPRF.tree.level, 0)))
    print('index = 100:   ' + str(scPRF.Eval(cons_key, 100)) + ';  ' + str(scPRF.tree.derive_key_from_tree(msk_SCPRF, 100, scPRF.tree.level, 0)))
    print('index = 65535:   ' + str(scPRF.Eval(cons_key, 65535)) + ';  ' + str(scPRF.tree.derive_key_from_tree(msk_SCPRF, 65535, scPRF.tree.level, 0)))
    
if __name__ == "__main__":
    debug = True
    testSCPRF()