'''
Sensen Li

| n-dimensional dynamic symmetric hidden vector encryption (n-DSHVE)

:Author:         Sensen Li
:Date:           11/2024
'''

# import SSEUtil
from utils import SSEUtil
import random
# from aesCryptor import AEScryptor
from utils.aesCryptor import AEScryptor
from Crypto.Cipher import AES
import numpy as np

class DSHVE(object):
    """
    n-dimensional dynamic symmetric hidden vector encryption (n-DSHVE) class
    Reference: "2018-CCS-Result Pattern Hiding Searchable Encryption for Conjunctive Queries"

    Implements Setup, Enc, UpdParamGen, ApplyUpd, KeyGen, and Query operations.
    """
    # def __init__(self, dim_n, max_pattern_len = 100):
    #     """
    #     Args:
    #         total_element_num (int, optional): The number of elements in the set. Defaults to 100.
    #     """
    #     self.dim_n = dim_n
    #     self.max_pattern_len = max_pattern_len
    
    def Setup(self, sec_lambda = 128):
        """
        Setup
        It takes a security parameter λ and outputs a description of a HVE key msk_HVE
        Args:
            sec_lambda (int): The length of security parameter. Defaults to 128.
        """
        self.sec_len = sec_lambda
        msk_HVE = SSEUtil.gen_key_F(random.getrandbits(sec_lambda))
        return msk_HVE
    
    def Enc(self, msk_HVE, matrix_index):
        """
        Enc
        It takes the master secret key msk_HVE and an index matrix matrix_index, 
        and outputs the ciphertext c_hve
        Args:
            msk_HVE (bytes): the system key
            matrix_index (matrix): the index matrix whose size is m*dim_n, where 'm' means the index matrix 
                          has m attributes and 'dim_n' refers to the length of each attribute's value.
        """
        # 获取matrix_index的行数和列数
        rows = len(matrix_index)
        cols = len(matrix_index[0]) if matrix_index else 0
        c_hve = [[b'0' for _ in range(cols)] for _ in range(rows)] # 创建一个填充b'0'的矩阵
        for i, attribute in enumerate(matrix_index):
            for j, val in enumerate(attribute):
                # SSEUtil.prf_F(msk_HVE, (str(val) + str(i) + str(j)).encode()) * val
                c_hve[i][j] = SSEUtil.prf_F(msk_HVE, (str(val) + str(i) + str(j)).encode()) * val
        return c_hve
    
    def UpdParamGen(self, msk_HVE, position, bVal):
        """
        UpdParamGen
        It takes the master secret key msk_HVE, the coordinate of the updated position in the index matrix, 
        and the new value bVal, and outputs the update token updToken
        Args:
            msk_HVE (bytes): the system key
            position (tuple): the coordinate of the updated position in the index matrix, e.g. position = (2, 3).
            bVal (int): the new value in the position
        """
        (i, j) = position
        updToken = SSEUtil.prf_F(msk_HVE, (str(bVal) + str(i) + str(j)).encode()) * bVal
        return updToken
    
    def ApplyUpd(self, c_hve, position, updToken):
        """
        UpdParamGen
        It takes the ciphertext c_hve, the coordinate of the updated position in the index matrix, 
        and the update token updToken, and outputs the updated ciphertext c_hve
        Args:
            c_hve (matrix): the ciphertext to be updated
            position (tuple): the coordinate of the updated position in the index matrix, e.g. position = (2, 3).
            updToken (bytes): the update token
        """
        (i, j) = position
        c_hve[i][j] = updToken
        return c_hve
    
    def KeyGen(self, msk_HVE, matrix_predicate):
        """
        KeyGen
        It takes the master secret key msk_HVE and an predicate matrix matrix_predicate, 
        and outputs the decryption key d_key = (d0, d1, SP) corresponding to matrix_predicate.
        Args:
            msk_HVE (bytes): the system key
            matrix_predicate (matrix): the predicate matrix
        """
        SP = [] # SP denotes the set of all positions in matrix_predicate that do not contain wildcard characters.
        if hasattr(self, 'sec_len'):
            Key = SSEUtil.gen_key_F(self.sec_len)
        else:
            Key = SSEUtil.gen_key_F(128) 
        d0 = Key
        
        non_minus_one_indices = np.nonzero(matrix_predicate != -1) # 非通配符位置
        SP = list(zip(non_minus_one_indices[0], non_minus_one_indices[1]))
        for (i,j) in SP:
            val = matrix_predicate[i][j]
            d0 = SSEUtil.bytes_XOR(d0, SSEUtil.prf_F(msk_HVE, (str(val) + str(i) + str(j)).encode()) * val)
        
        # 计算d1
        data = '0000000000000000'
        aes = AEScryptor(Key, AES.MODE_ECB, paddingMode= "ZeroPadding", characterSet='utf-8')
        d1 = aes.encryptFromString(data)
        d_key = (d0, d1, SP)
        return d_key
    
    def Query(self, d_key, c_hve):
        """
        Query
        It takes a decryption key d_key and a ciphertext c_hve,
        and outputs True or False.
        Args:
            d_key (tuple): the decryption key (d0, d1, SP) corresponding to certain predicate matrix
            c_hve (matrix): the ciphertext corresponding to certain index matrix
        """
        (d0, d1, SP) = d_key
        Key = d0
        for (i, j) in SP:
            Key = SSEUtil.bytes_XOR(Key, c_hve[i][j])
        aes = AEScryptor(Key, AES.MODE_ECB,paddingMode= "ZeroPadding",characterSet='utf-8')
        u = aes.decryptFromBytes(d1.toBytes())
        try:
            if u.toString() == '0000000000000000':
                return True
            else:
                return False
        except Exception:
            return False
    
def testDSHVE():
    dSHVE = DSHVE()
    msk_HVE = dSHVE.Setup(128)
    matrix_index = [[1, 0],
                    [4, 21],
                    [1, 8],
                    [1, 0],
                    [1, 0]]
    c_hve = dSHVE.Enc(msk_HVE, matrix_index)
    updToken = dSHVE.UpdParamGen(msk_HVE, (2, 0), 10)
    c_hve = dSHVE.ApplyUpd(c_hve, (2, 0), updToken)
    matrix_predicate1 = [[1, 0],
                         [4, -1],
                         [-1, 8],
                         [1, 0],
                         [1, -1]]
    d_key1 = dSHVE.KeyGen(msk_HVE, matrix_predicate1)
    print(dSHVE.Query(d_key1, c_hve)) # True
    
    updToken = dSHVE.UpdParamGen(msk_HVE, (0, 1), 2)
    c_hve = dSHVE.ApplyUpd(c_hve, (0, 1), updToken)
    print(dSHVE.Query(d_key1, c_hve)) # False
    
    matrix_predicate2 = [[1, 1],
                         [4, -1],
                         [-1, 8],
                         [1, 0],
                         [1, -1]]
    d_key2 = dSHVE.KeyGen(msk_HVE, matrix_predicate2)
    print(dSHVE.Query(d_key2, c_hve)) # False
    
    updToken = dSHVE.UpdParamGen(msk_HVE, (0, 1), 1)
    c_hve = dSHVE.ApplyUpd(c_hve, (0, 1), updToken)
    print(dSHVE.Query(d_key2, c_hve)) # True
    
    updToken = dSHVE.UpdParamGen(msk_HVE, (1, 1), 100)
    c_hve = dSHVE.ApplyUpd(c_hve, (1, 1), updToken)
    print(dSHVE.Query(d_key2, c_hve)) # True
    
    updToken = dSHVE.UpdParamGen(msk_HVE, (3, 1), 100)
    c_hve = dSHVE.ApplyUpd(c_hve, (3, 1), updToken)
    print(dSHVE.Query(d_key2, c_hve)) # False
    
    updToken = dSHVE.UpdParamGen(msk_HVE, (3, 1), 0)
    c_hve = dSHVE.ApplyUpd(c_hve, (3, 1), updToken)
    print(dSHVE.Query(d_key2, c_hve)) # True
    
if __name__ == "__main__":
    debug = True
    testDSHVE()