'''
Sensen Li

| t-puncturable pseudorandom function (t-Punc-PRF)

:Author:         Sensen Li
:Date:           11/2024
'''

# import ggmTree
from utils import ggmTree
# import SSEUtil
from utils import SSEUtil
import random

class TPPRF(object):
    """
    t-puncturable pseudorandom function (t-Punc-PRF) class
    Reference: "Adaptively Secure Puncturable Pseudorandom Functions in the Standard Model"

    Implements Setup, Punc, and Eval operations.
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
        It takes a security parameter λ and outputs a description of a PRF key msk_PPRF
        Args:
            sec_lambda (int): The length of security parameter. Defaults to 128.
        """
        msk_PPRF = SSEUtil.gen_key_F(random.getrandbits(sec_lambda))
        return msk_PPRF
    
    def Punc(self, msk_PPRF, punc_set):
        """Punc 
        It takes as input a PRF key msk_PPRF and the set of elements to be punctured punc_set, 
        and outputs a t-punctured key (list) punc_key.
        Args:
            msk_PPRF (bytes): the system key
            punc_set (list): the index set of elements to be punctured, e.g. punc_set = [1,2,3,8,10]
        """
        # msk_PPRF_bytes = msk_PPRF.to_bytes(16, 'little') # the length is defined as 16 bytes
        remain_list = [item for item in self.tElementList if item not in punc_set]
        node_list = []
        for index in remain_list:
            node_list.append(ggmTree.GGMNode(index, self.tree.level))
        min_coverage_list = self.tree.min_coverage(node_list)
        punc_key = []
        for node in min_coverage_list:
            node.key = self.tree.derive_key_from_tree(msk_PPRF, node.index, node.level, 0)
            punc_key.append((node.level, node.index, node.key))
        return punc_key

    def Eval(self, punc_key, e_index):
        """Eval 
        It takes as input a t-punctured key punc_key and an element e_x in tElementList, 
        and outputs the value of PRF(msk_PPRF, e_index) (if e_index is not in punc_set 
        corresponding to punc_key) or False (if e_x is in punc_set corresponding to punc_key).
        Args:
            punc_key (list): the t-punctured key list
            e_index (int): the index of element to be evaluated
        """
        bit_length = self.tree.level
        e_index_binstr = SSEUtil.int_to_binary(e_index, bit_length)
        derive_key = 0
        for (level, index, key) in punc_key:
            key_index_binstr = SSEUtil.int_to_binary(index, level)
            if e_index_binstr.startswith(key_index_binstr):
                derive_key = self.tree.derive_key_from_tree(key, index, self.tree.level - level, 0)
                return derive_key
        return False

def testPPRF():
    tPPRF = TPPRF(65536)
    msk_PPF = tPPRF.Setup(128)
    punc_set = [1,2,3,8,10]
    punc_key = tPPRF.Punc(msk_PPF, punc_set)
    print(len(punc_key))
    print(punc_key)
    print(tPPRF.Eval(punc_key, 0))
    print(tPPRF.Eval(punc_key, 1))
    print(tPPRF.Eval(punc_key, 2))
    print(tPPRF.Eval(punc_key, 3))
    print(tPPRF.Eval(punc_key, 5))
    print(tPPRF.Eval(punc_key, 8))
    print(tPPRF.Eval(punc_key, 10))
    print(tPPRF.Eval(punc_key, 50))
    print(tPPRF.Eval(punc_key, 99))
    print(tPPRF.Eval(punc_key, 65535))
    
if __name__ == "__main__":
    debug = True
    testPPRF()