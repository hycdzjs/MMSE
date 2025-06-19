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
            # log.debug("setup completed")
        elif(resp_tup[0] == 1):  # for update
            self.server.Update(resp_tup[1])
            data = (1,)
            self.request.sendall(pickle.dumps(data))
            # log.debug("update completed")
        elif(resp_tup[0] == 2):  # for AggKey
            resp = self.server.AggKey(resp_tup[1])
            data = (1, resp)
            # self.request.sendall(pickle.dumps(data))
            self.request.sendall(pickle.dumps(data)+b'#####')
            # log.debug("AggKey completed")

class MMCSETA(socketserver.TCPServer):
    def __init__(self, addr, severAddr, handler_class = TaReqHandler, sec_lambda = 128) -> None:
        self.sec_lambda = sec_lambda
        self.addr = addr
        self.severAddr = severAddr
        self.msk = SSEUtil.gen_key_F(random.getrandbits(sec_lambda))
        self.dsIndex = 0
        self.clientIndex = 0
        self.dsParams: dict = {}
        self.st_TA: dict = {}
        self.scPRF = setConstrainedPRF.SCPRF(maxDSnum)
        super().__init__(addr, handler_class)
    
    def initTA(self, fileName):
        ta_params = SSEUtil.readData(fileName)
        sec_lambda, addr, msk, dsIndex, clientIndex, dsParams, st_TA, scPRF = ta_params
        self.sec_lambda = sec_lambda
        self.addr = addr
        self.msk = msk
        self.dsIndex = dsIndex
        self.clientIndex = clientIndex
        self.dsParams = dsParams
        self.st_TA = st_TA
        self.scPRF = scPRF
    
    def Setup(self, data):
        sid = self.dsIndex # select sid for current data source
        self.dsIndex += 1
        KM = data
        KI = self.scPRF.tree.derive_key_from_tree(self.msk, sid, self.scPRF.tree.level, 0)
        self.dsParams[sid] = (KM, KI)
        return (sid, KI)
    
    def Update(self, data):
        (sid, w, UpdCnt, UpdState, wInd) = data
        st_TA = self.st_TA
        if sid not in st_TA:
            st_TA[sid] = {}
        st_TA[sid][w] = (UpdCnt, UpdState, wInd)
        
    def AggKey(self, data):
        SID = data # SID=[sid1, sid2, ...]
        AK = self.scPRF.Cons(self.msk, SID)
        
        cid = self.clientIndex # select cid for current client
        self.clientIndex += 1
        KC = SSEUtil.prf_F(self.msk, (str(cid) + 'client').encode())
        
        ss = {}
        ASetVal = []
        for sid in SID:
            if sid in self.st_TA:
                ss[sid] = self.st_TA[sid]
                (KM, KI) = self.dsParams[sid]
                aTag = SSEUtil.prf_F(KI, str(cid).encode())
                aVal1 = SSEUtil.prf_F(SSEUtil.bytes_XOR(KM, KI), str(cid).encode())
                aVal2 = SSEUtil.prf_F(KC, str(sid).encode())
                aSetVal = (aTag, aVal1, aVal2)
                ASetVal.append(aSetVal)

        conn_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn_server.connect(self.severAddr)
        conn_server.send(pickle.dumps((2, ASetVal))+b'#####')
        #
        # Server WORK
        #
        data = pickle.loads(conn_server.recv(4096))
        if(data == (1,)):
            log.info("AggKey of Server completed")
        conn_server.close()
        
        return (cid, AK, KC, ss)
    
    
        
        
        