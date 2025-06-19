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

log = logging.getLogger(__name__)

class MMCSEClient:
    def __init__(self, taAddr, severAddr):
        # self.ss: dict = {}
        self.cid: int = -1
        self.taAddr = taAddr
        self.severAddr = severAddr
        self.SID = []
        self.AK = b''
        self.KC = b''
        self.ss = b''
        
    def initClient(self, fileName):
        client_params = SSEUtil.readData(fileName)
        cid, taAddr, severAddr, SID, AK, KC, ss = client_params
        self.cid = cid
        self.taAddr = taAddr
        self.severAddr = severAddr
        self.SID = SID
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
        resp_tak = pickle.loads(conn_ta.recv(4096))
        conn_ta.close()
        (AK, ss) = resp_tak[1]
        self.SID = SID
        self.AK = AK
        self.ss = ss
        return
    
    
    def SingleSearch(self, sid, KI, SC, w):
        STw0 = SSEUtil.prf_F(KI, str(w).encode())
        KSC = SSEUtil.getHash((str(STw0) + str(SC)).encode())
        
        conn_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn_server.connect(self.severAddr)
        # conn_server.send(pickle.dumps((3, (sid, KSC, SC))))
        conn_server.send(pickle.dumps((3, (sid, KSC, SC, STw0)))+b'#####')
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
        setR = resp_ts[0]
        conn_server.close()
        return list(set(setR))
    
    def Search(self, sid, q_w_list):
        n = len(q_w_list)
        maxDSnum = SSEUtil.MAXDSNUM
        scPRF = setConstrainedPRF.SCPRF(maxDSnum)
        KI = scPRF.Eval(self.AK, sid)
        
        if sid in self.ss:
            SC = self.ss[sid]
        else:
            return
        if len(q_w_list) == 0:
            return
        
        IdList = self.SingleSearch(sid, KI, SC, q_w_list[0])
        for i in range(1, len(q_w_list)):
            if IdList == []:
                return []
            w_IdList = self.SingleSearch(sid, KI, SC, q_w_list[i])
            IdListSet = set(IdList)
            w_IdListSet = set(w_IdList)
            IdList = list(IdListSet.intersection(w_IdListSet))
        
        return list(set(IdList))