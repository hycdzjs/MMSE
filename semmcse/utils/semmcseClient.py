'''
Sensen Li

| Client (C)
| Multi-Source Multi-Client Conjunctive Searchable Encryption (MMCSE)

:Author:         Sensen Li
:Date:           12/2024
'''

# import SSEUtil
from utils import SSEUtil
# import setConstrainedPRF
from utils import setConstrainedPRF
# import nDSHVE
from utils import nDSHVE
import random
import socket
import pickle
import logging
from utils.aesCryptor import AEScryptor
from Crypto.Cipher import AES
import ast
import numpy as np

log = logging.getLogger(__name__)

class MMCSEClient:
    def __init__(self, taAddr, severAddr):
        # self.ss: dict = {}
        self.cid: int = -1
        self.taAddr = taAddr
        self.severAddr = severAddr
        self.p = 69445180235231407255137142482031499329548634082242122837872648805446522657159
        self.g = 65537
        
    def initClient(self, fileName):
        client_params = SSEUtil.readData(fileName)
        cid, taAddr, severAddr, p, g, SID, AK, KC, ss = client_params
        self.cid = cid
        self.taAddr = taAddr
        self.severAddr = severAddr
        self.p = p
        self.g = g
        self.AK = AK
        self.KC = KC
        self.ss = ss
    
    def AggKey(self, SID):
        conn_ta = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn_ta.connect(self.taAddr)
        conn_ta.send(pickle.dumps((2, SID)))
        #
        # TA WORK
        #
        # resp_tak = pickle.loads(conn_ta.recv(4096))
        data_received =  b''
        while True:
            data = conn_ta.recv(4096)
            if len(data) > 0:
                if data[-5:0]==b'#####':
                    data_received += data[:-5]
                    break
                else:
                    data_received += data
            else:
                break
        resp_tak = pickle.loads(data_received)
        conn_ta.close()
        (cid, AK, KC, ss) = resp_tak[1]
        self.cid = cid
        self.SID = SID
        self.AK = AK
        self.KC = KC
        self.ss = ss
        return
    
    def Search(self, sid, q_w_list):
        n = len(q_w_list)
        maxDSnum = SSEUtil.MAXDSNUM
        scPRF = setConstrainedPRF.SCPRF(maxDSnum)
        KI = scPRF.Eval(self.AK, sid)
        
        if sid in self.ss:
            q_w_params = self.ss[sid]
        else:
            return
        if len(q_w_list) == 0:
            return
        w1 = q_w_list[0]
        min_cnt = SSEUtil.MAXINT
        WI = []
        for q_w in q_w_list:
            if q_w not in q_w_params:
                return
            wInd = q_w_params[q_w][2]
            WI.append(wInd)
            UpdCnt = q_w_params[q_w][0]
            if UpdCnt < min_cnt:
                w1 = q_w
                min_cnt = UpdCnt
        
        (w1_UpdCnt, w1_UpdState, w1_wInd) = q_w_params[w1]
        MP = np.full((SSEUtil.MAXKWNUM, 2), -1)
        for wInd in WI:
            MP[wInd][0] = 1
            MP[wInd][1] = 0
                
        stokenlist = []
        xtokenlists = []
        KT = SSEUtil.prf_F(KI, (str(sid) + str(0)).encode())
        KX = SSEUtil.prf_F(KI, (str(sid) + str(1)).encode())
        KZ = SSEUtil.prf_F(KI, (str(sid) + str(2)).encode())
        KH = SSEUtil.prf_F(KI, (str(sid) + 'hve').encode())
        
        SH = nDSHVE.DSHVE().KeyGen(KH, MP)
        # (d0, d1, SP) = SH
        
        if w1 in q_w_params:
            for j in range(1, w1_UpdCnt+1):
                addr_j = SSEUtil.prf_F(KT, (str(w1) + str(j) + str(0)).encode())
                stokenlist.append(addr_j)
                xtl = []
                B0 = SSEUtil.prf_Fp(KZ, (str(w1) + str(j)).encode(), self.p, self.g)
                B = int.from_bytes(B0, 'little')
                for i in range(n):
                    A1 = int.from_bytes(SSEUtil.prf_Fp(KX, (str(q_w_list[i]) + 'add').encode(), self.p, self.g), 'little')
                    A2 = int.from_bytes(SSEUtil.prf_Fp(KX, (str(q_w_list[i]) + 'del').encode(), self.p, self.g), 'little')
                    xtoke_add = pow(self.g, A1*B, self.p)
                    xtoken_del = pow(self.g, A2*B, self.p)
                    xtl.append(xtoke_add)
                    xtl.append(xtoken_del)
                random.shuffle(xtl)
                xtokenlists.append(xtl)
        
        hState = SSEUtil.getHash(w1_UpdState)
        aTag = SSEUtil.prf_F(KI, str(self.cid).encode())
        utoken = (hState, SH, aTag, self.cid)
        res = (stokenlist, xtokenlists, utoken)
        
        conn_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn_server.connect(self.severAddr)
        # conn_server.send(pickle.dumps((3, res)))
        conn_server.sendall(pickle.dumps((3, res))+b'#####')
        #
        # Server WORK
        #
        # resp_ts = pickle.loads(conn_server.recv(4096000))
        data_received =  b''
        while True:
            data = conn_server.recv(4096)
            if len(data) > 0:
                if data[-5:0]==b'#####':
                    data_received += data[:-5]
                    break
                else:
                    data_received += data
            else:
                break
        resp_ts = pickle.loads(data_received)
        sEOpList = resp_ts[0]
        IdList = []
        aVal = SSEUtil.prf_F(self.KC, str(sid).encode())
        for l in sEOpList:
            val_j = l
            index_tVal_bytes = SSEUtil.bytes_XOR(val_j, aVal) 
            index_tVal_str = index_tVal_bytes.decode().rstrip('\x00')
            index_tVal_dict = ast.literal_eval(index_tVal_str)
            j = index_tVal_dict['index']
            tVal = index_tVal_dict['tVal']
            
            X0 = SSEUtil.prf_F(KT, (str(w1)+str(j + 1)+str(1)).encode())
            op_id = SSEUtil.bytes_XOR(tVal, X0)
            op_id = op_id.decode().rstrip('\x00')
            IdList.append(int(op_id[3:]))
        
        conn_server.close()
        return list(set(IdList))