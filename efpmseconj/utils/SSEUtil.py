import random
import hashlib
from math import sqrt, gcd
import sys
import pickle
# import os

KEYSIZE = 10**8
MAXBITS = 256
MAXBYTES = 64
MAXINT = sys.maxsize

MAXDSNUM = 65536 # the max number of data sources
MAXClientNUM = 65536 # the max number of clients
# MAXKWNUM = 100000 # the max number of keywords (m)

# def bytes_XOR(b1: bytes, b2: bytes) -> bytes:
#     if b1 == b'':
#         return b2
#     if b2 == b'':
#         return b1
#     '''bytes异或操作'''
#     return bytes(x^y for x,y in zip(b1, b2))

def bytes_XOR(b1: bytes, b2: bytes) -> bytes:
    if b1 == b'':
        return b2
    if b2 == b'':
        return b1
    '''bytes异或操作'''
    # return bytes(x^y for x,y in zip(b1, b2))
    cipher_data = []
    len_b1 = len(b1)
    len_b2 = len(b2)
    for idx in range(len_b1):
        bias = b2[idx % len_b2]
        curr_byte = b1[idx]
        cipher_data.append(bias ^ curr_byte)
    return bytes(cipher_data)

def mul_inv(a, b):
    if(gcd(a, b) > 1):
        a = a % b
    b0 = b
    x0, x1 = 0, 1
    if b == 1:
        return 1
    while a > 1 and b != 0:
        q = a // b
        a, b = b, a % b
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += b0
    return x1


def gen_key_F(l, bitsize=MAXBITS):
    '''生成随机数'''
    random.seed(l)
    return random.getrandbits(bitsize).to_bytes(32, 'little')


def prf_F(Key: bytes, M: bytes) -> bytes:
    '''
    伪随机数
    返回: 32Bytes随机数
    '''
    random.seed(Key)
    # rval = random.getrandbits(MAXBITS)
    rval = random.randbytes(MAXBYTES)
    Mhash = hashlib.new('sha256')
    Mhash.update(M)
    hs = Mhash.digest()
    res = bytes_XOR(hs, rval)
    return res
    # Mval = int.from_bytes(Mhash.digest())
    # rstr = (rval ^ Mval)
    # return rstr.to_bytes(32)


def prf_Fp(Key: bytes, M: bytes, p: int, g: int) -> bytes:
    '''循环群上伪随机数，素数阶为p，g是生成元'''
    random.seed(Key)
    # rval = random.getrandbits(MAXBITS)
    rval = random.randbytes(MAXBYTES)
    Mhash = hashlib.new('sha256')
    Mhash.update(M)
    hs = Mhash.digest()
    res = int.from_bytes(bytes_XOR(hs, rval), byteorder='little')
    # Mval = int.from_bytes(Mhash.digest())
    # rstr = (rval ^ Mval)
    if(res % p == 0):
        res += 1
    ex = (res % p)
    return pow(g, ex, p-1).to_bytes(32, 'little')


def findPrimefactors(s, n):
    while (n % 2 == 0):
        s.add(2)
        n = n // 2
    for i in range(3, int(sqrt(n)), 2):
        while (n % i == 0):
            s.add(i)
            n = n // i
    if (n > 2):
        s.add(n)


def findPrimitive(n):
    s = set()
    phi = n - 1
    findPrimefactors(s, phi)
    for r in range(2, phi + 1):
        flag = False
        for it in s:
            if (pow(r, phi // it, n) == 1):
                flag = True
                break
        if (flag == False):
            return r
    return -1


def shuffle_and_index(lst):
    i_lst = list(enumerate(lst))
    random.shuffle(i_lst)
    return ([i[1] for i in i_lst], [i[0] for i in i_lst])

def sort_by_order(lst, index):
    e_lst = list(zip(index, lst))
    return [i[1] for i in sorted(e_lst)]


def int_to_binary(num, length):
    # 将整数转换为二进制字符串，并去掉前缀'0b'
    binary_str = bin(num)[2:]
    # 填充前导零以确保长度
    binary_str = binary_str.zfill(length)
    return binary_str

def getHash(data : bytes):
    Mhash = hashlib.new('sha256')
    Mhash.update(data)
    hashVal = Mhash.digest()
    return hashVal

def saveData(FileName,data: bytes):
    with open(FileName,'wb') as f:
        f.write(data)

def readData(FileName) -> bytes:
    # current_directory = os.getcwd()
    # print("Current working directory:", current_directory)
    with open(FileName,'rb') as f:
        return pickle.loads(f.read())