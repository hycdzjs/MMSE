'''
Sensen Li

| Data Source (DS)
| Multi-Source Multi-Client Conjunctive Searchable Encryption (MMCSE)

:Author:         Sensen Li
:Date:           12/2024
'''

# import SSEUtil
from utils import SSEUtil
# import tPuncPRF
from utils import tPuncPRF
# import nDSHVE
from utils import nDSHVE
import random
import socket
import pickle
import logging
from utils.aesCryptor import AEScryptor
from Crypto.Cipher import AES

log = logging.getLogger(__name__)

maxClientnum = SSEUtil.MAXClientNUM

class MMCSEDS:
    def __init__(self, taAddr, severAddr):
        self.sk: tuple = ()
        self.sid: int = -1
        self.taAddr = taAddr
        self.severAddr = severAddr
        self.STc = b''
        
    def initDS(self, fileName):
        ds_params = SSEUtil.readData(fileName)
        sid, taAddr, severAddr, sec_lambda, sk, STc = ds_params
        self.sid = sid
        self.taAddr = taAddr
        self.severAddr = severAddr
        self.sec_lambda = sec_lambda
        self.sk = sk
        self.STc = STc
    
    def Setup(self, sec_lambda = 128):
        self.sec_lambda = sec_lambda
        KS = SSEUtil.gen_key_F(random.getrandbits(sec_lambda))
        
        conn_ta = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn_ta.connect(self.taAddr)
        conn_ta.send(pickle.dumps((0, 'DS Register!')))
        #
        # TA WORK
        #
        resp_tup = pickle.loads(conn_ta.recv(4096))
        conn_ta.close()
        (sid, KI) = resp_tup[1]
        self.sid = sid
        self.sk = (KI, KS)
        
        conn_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn_server.connect(self.severAddr)
        req_s = (sid, KS)
        conn_server.send(pickle.dumps((0, req_s))+b'#####')
        #
        # Server WORK
        #
        data = pickle.loads(conn_server.recv(4096))
        # if(data == (1,)):
        #     log.info("Setup completed")
        conn_server.close()
        return
    
    def Update(self, op: str, id, w):
        (KI, KS) = self.sk
        table_T = {}
        table_S = {}
        table_V = {}
        
        STc = self.STc
        random.seed()
        if STc == b'':
            STc_new = SSEUtil.gen_key_F(random.getrandbits(self.sec_lambda))
            SKc_new = b''
            hIndex = SSEUtil.getHash(STc_new)
            table_S[hIndex] = SKc_new
            # c = -1
        else:
            STc_new = SSEUtil.gen_key_F(random.getrandbits(self.sec_lambda))
            SKc_new = SSEUtil.bytes_XOR(STc, SSEUtil.getHash(STc_new))
            hIndex = SSEUtil.getHash(STc_new)
            table_S[hIndex] = SKc_new
            
        Ew = []
        Kw0 = SSEUtil.prf_F(KI, str(w).encode())
        Kwc_new = SSEUtil.getHash((str(Kw0) + str(STc_new)).encode())
        Kw = SSEUtil.prf_F(KS, Kwc_new)
        
        e_ind_w = SSEUtil.bytes_XOR(str(id).encode(), SSEUtil.getHash((str(Kw) + str(STc_new)).encode()))
        Ew.append(e_ind_w)          
        
        UTw_new = SSEUtil.getHash((str(Kw) + str(STc_new)).encode())
        table_T[UTw_new] = Ew
        aes1 = AEScryptor(STc_new, AES.MODE_ECB, paddingMode= "ZeroPadding", characterSet='utf-8')
        params_enc = aes1.encryptFromString(str(SSEUtil.getHash((str(Kw0) + str(STc)).encode())))
        table_V[UTw_new] = params_enc
        
        self.STc = STc_new
        
        conn_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn_server.connect(self.severAddr)
        
        conn_server.send(pickle.dumps((1, (table_T, table_V, table_S)))+b'#####')
        #
        # Server WORK
        #
        data = pickle.loads(conn_server.recv(4096))
        # if(data == (1,)):
        #     log.info("Server update completed")
        conn_server.close()
        
        conn_ta = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn_ta.connect(self.taAddr)
        conn_ta.send(pickle.dumps((1, (self.sid, STc_new))))
        #
        # TA WORK
        #
        data = pickle.loads(conn_ta.recv(4096))
        # if(data == (1,)):
        #     log.info("TA update completed")
        conn_ta.close()
 
        
    
        
        
        
        
        
        
        

        
        
        