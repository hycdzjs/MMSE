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
        self.st: dict = {}
        self.sid: int = -1
        self.p: int = -1
        self.g: int = -1
        self.taAddr = taAddr
        self.severAddr = severAddr
        self.tPPRF = tPuncPRF.TPPRF(maxClientnum)
        
    def initDS(self, fileName):
        ds_params = SSEUtil.readData(fileName)
        sid, taAddr, severAddr, sec_lambda, p, g, sk, st, tPPRF = ds_params
        self.sid = sid
        self.taAddr = taAddr
        self.severAddr = severAddr
        self.sec_lambda = sec_lambda
        self.p = p
        self.g = g
        self.sk = sk
        self.st = st
        self.tPPRF = tPPRF
    
    def Setup(self, sec_lambda = 128):
        self.sec_lambda = sec_lambda
        self.p = 69445180235231407255137142482031499329548634082242122837872648805446522657159
        self.g = 65537
        
        KM = SSEUtil.gen_key_F(random.getrandbits(sec_lambda))
        KY = SSEUtil.gen_key_F(random.getrandbits(sec_lambda))
        
        conn_ta = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn_ta.connect(self.taAddr)
        conn_ta.send(pickle.dumps((0, KM)))
        #
        # TA WORK
        #
        KP = self.tPPRF.Setup(sec_lambda)
        resp_tup = pickle.loads(conn_ta.recv(4096))
        conn_ta.close()
        (sid, KI) = resp_tup[1]
        KH = SSEUtil.prf_F(KI, (str(sid) + 'hve').encode())
        self.sid = sid
        self.sk = (KM, KI, KY, KP, KH)
        # log.info("Setup completed")
        return
    
    def Update(self, op: str, id, w):
        (KM, KI, KY, KP, KH) = self.sk
        KT = SSEUtil.prf_F(KI, (str(self.sid) + str(0)).encode())
        KX = SSEUtil.prf_F(KI, (str(self.sid) + str(1)).encode())
        KZ = SSEUtil.prf_F(KI, (str(self.sid) + str(2)).encode())
        
        if w not in self.st or self.st[w] == ():
            UpdState0 = 0
            self.st[w] = (0, UpdState0.to_bytes(32, 'little'), len(self.st))
        (UpdCnt, UpdState, wInd) = self.st[w]
        UpdCnt += 1
        ST0 = UpdState
        ST1 = SSEUtil.gen_key_F(random.getrandbits(self.sec_lambda))
        state = SSEUtil.bytes_XOR(ST0, SSEUtil.getHash(ST1))
        UpdState = ST1
        self.st[w] = (UpdCnt, UpdState, wInd)
        
        if op == 'add':
            ind = (wInd, 0)
        else:
            ind = (wInd, 1)
        bVal = 1
        updToken = nDSHVE.DSHVE().UpdParamGen(KH, ind, bVal)
        
        tAddr = SSEUtil.bytes_XOR(SSEUtil.prf_F(KT, (str(w) + str(UpdCnt) + str(0)).encode()), SSEUtil.getHash(UpdState))
        op_id = str(op)+str(id)
        tVal = SSEUtil.bytes_XOR(op_id.encode(), SSEUtil.prf_F(KT, (str(w) + str(UpdCnt) + str(1)).encode()))
        
        b1 = str(id).encode()
        b2 = (str(w) + str(UpdCnt)).encode()
        A = int.from_bytes(SSEUtil.prf_Fp(KY, b1, self.p, self.g), 'little')
        B = int.from_bytes(SSEUtil.prf_Fp(KZ, b2, self.p, self.g), 'little')
        B_inv = SSEUtil.mul_inv(B, self.p-1)
        C = int.from_bytes(SSEUtil.prf_Fp(KX, (str(w) + str(op)).encode(), self.p, self.g), 'little')
        # alpha_add = (A1 * B_inv).to_bytes(SSEUtil.MAXBYTES, 'little')
        # alpha_del = (A2 * B_inv).to_bytes(SSEUtil.MAXBYTES, 'little')
        alpha = A * B_inv
        xTag = pow(self.g, C*A, self.p).to_bytes(SSEUtil.MAXBYTES, 'little')
        
        PK0 = 0
        PK = PK0.to_bytes(32, 'little')

        conn_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn_server.connect(self.severAddr)
        conn_server.send(pickle.dumps((1, (tAddr, tVal, alpha, state, updToken, PK, xTag)))+b'#####')
        #
        # Server WORK
        #
        data = pickle.loads(conn_server.recv(4096))
        # if(data == (1,)):
        #     log.info("Update completed")
        conn_server.close()
        
        conn_ta = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn_ta.connect(self.taAddr)
        conn_ta.send(pickle.dumps((1, (self.sid, w, UpdCnt, UpdState, wInd))))
        #
        # TA WORK
        #
        data = pickle.loads(conn_ta.recv(4096))
        # if(data == (1,)):
        #     log.info("Setup completed")
        conn_ta.close()
    
    def revocation_client(self, CID):
        (KM, KI, KY, KP, KH) = self.sk
        RSetVal = []
        for cid in CID:
            aTag = SSEUtil.prf_F(KI, str(cid).encode())
            vfyVal = SSEUtil.prf_F(SSEUtil.bytes_XOR(KM, KI), str(cid).encode())
            rSetVal = (aTag, vfyVal)
            RSetVal.append(rSetVal)
            
        conn_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn_server.connect(self.severAddr)
        conn_server.send(pickle.dumps((4, (RSetVal)))+b'#####')
        #
        # Server WORK
        #
        data = pickle.loads(conn_server.recv(4096))
        # if(data == (1,)):
        #     log.info("Revocation_client completed")
        conn_server.close()
    
    def revocation_operation(self, CID, operation):
        (KM, KI, KY, KP, KH) = self.sk
        op, id, w = operation
        KX = SSEUtil.prf_F(KI, (str(self.sid) + str(1)).encode())
        b1 = str(id).encode()
        A = int.from_bytes(SSEUtil.prf_Fp(KY, b1, self.p, self.g), 'little')
        C = int.from_bytes(SSEUtil.prf_Fp(KX, (str(w) + str(op)).encode(), self.p, self.g), 'little')
        xTag = pow(self.g, C*A, self.p).to_bytes(SSEUtil.MAXBYTES, 'little')
        
        rkl = []
        for cid in CID:
            pVal = SSEUtil.prf_F(SSEUtil.bytes_XOR(KM, KI), str(cid).encode())
            rkl.append(pVal)
        PK = self.tPPRF.Punc(KP, CID)
        
        conn_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn_server.connect(self.severAddr)
        conn_server.send(pickle.dumps((5, (xTag, PK)))+b'#####')
        
        #
        # Server WORK
        #
        data = pickle.loads(conn_server.recv(4096))
        # if(data == (1,)):
        #     log.info("Revocation_operation completed")
        conn_server.close()
 
        
    
        
        
        
        
        
        
        

        
        
        