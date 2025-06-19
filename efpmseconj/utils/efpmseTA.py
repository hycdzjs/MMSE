'''
Sensen Li

| Trusted Authority (TA)
| Multi-Source Multi-Client Conjunctive Searchable Encryption (MMCSE)

:Author:         Sensen Li
:Date:           12/2024
'''

# import SSEUtil
from utils import SSEUtil
# import setConstrainedPRF
from utils import setConstrainedPRF
import random
import socket
import socketserver
import pickle
import logging
from utils.aesCryptor import AEScryptor
from Crypto.Cipher import AES
import ast

log = logging.getLogger(__name__)

# maxDSnum = 65536 # the max number of data sources
maxDSnum = SSEUtil.MAXDSNUM

class TaReqHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, addr, server):
        super().__init__(request, addr, server)

    def handle(self):
        resp_tup = pickle.loads(self.request.recv(4096))
        if(resp_tup[0] == 0):  # for setup
            resp = self.server.Setup(resp_tup[1])
            data = (1, resp)
            self.request.sendall(pickle.dumps(data))
            log.debug("setup completed")
        elif(resp_tup[0] == 1):  # for update
            self.server.Update(resp_tup[1])
            data = (1,)
            self.request.sendall(pickle.dumps(data))
            # log.debug("update completed")
        elif(resp_tup[0] == 2):  # for AggKey
            resp = self.server.AggKey(resp_tup[1])
            data = (1, resp)
            self.request.sendall(pickle.dumps(data))
            # log.debug("AggKey completed")

class EFPMSETA(socketserver.TCPServer):
    def __init__(self, addr, severAddr, handler_class = TaReqHandler, sec_lambda = 128) -> None:
        self.sec_lambda = sec_lambda
        self.addr = addr
        self.severAddr = severAddr
        self.msk = SSEUtil.gen_key_F(random.getrandbits(sec_lambda))
        self.dsIndex = 0
        self.clientIndex = 0
        self.table_C: dict = {}
        self.dsParams: dict = {}
        self.scPRF = setConstrainedPRF.SCPRF(maxDSnum)
        
        # msk_SCPRF = scPRF.Setup(sec_lambda)
        super().__init__(addr, handler_class)
    
    def initTA(self, fileName):
        ta_params = SSEUtil.readData(fileName)
        sec_lambda, addr, severAddr, msk, dsIndex, clientIndex, table_C, dsParams, scPRF = ta_params
        self.sec_lambda = sec_lambda
        self.addr = addr
        self.severAddr = severAddr
        self.msk = msk
        self.dsIndex = dsIndex
        self.clientIndex = clientIndex
        self.table_C = table_C
        self.dsParams = dsParams
        self.scPRF = scPRF
    
    def Setup(self, data):
        sid = self.dsIndex # select sid for current data source
        self.dsIndex += 1
        KI = self.scPRF.tree.derive_key_from_tree(self.msk, sid, self.scPRF.tree.level, 0)
        # self.dsParams[sid] = (KM, KI)
        return (sid, KI)
    
    def Update(self, data):
        (sid, STc_new) = data
        table_C = self.table_C
        table_C[sid] = STc_new
        self.table_C = table_C
        
    def AggKey(self, data):
        SID = data # SID=[sid1, sid2, ...]
        AK = self.scPRF.Cons(self.msk, SID)
        
        ss = {}
        for sid in SID:
            if sid in self.table_C:
                ss[sid] = self.table_C[sid]
        
        return (AK, ss)
    
    
        
        
        