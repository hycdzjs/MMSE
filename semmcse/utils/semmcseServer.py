'''
Sensen Li

| Server (S)
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
# import tPuncPRF
from utils import tPuncPRF
import random
import socketserver
import pickle
import logging
from utils.aesCryptor import AEScryptor
from Crypto.Cipher import AES
import ast
import numpy as np

log = logging.getLogger(__name__)

maxDSnum = 65536 # the max number of data sources
maxClientnum = SSEUtil.MAXClientNUM

class SeverReqHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, addr, server):
        super().__init__(request, addr, server)

    def handle(self):
        # resp_tup = pickle.loads(self.request.recv(4096000))
        data_received =  b''
        while True:
            data = self.request.recv(4096)
            if len(data) > 0:
                if data[-5:]==b'#####':
                    data_received += data[:-5]
                    break
                else:
                    data_received += data
            else:
                break
        resp_tup = pickle.loads(data_received)
        if(resp_tup[0] == 1):  # for update
            self.server.Update(resp_tup[1])
            data = (1,)
            self.request.sendall(pickle.dumps(data))
            # log.debug("update completed")
        elif(resp_tup[0] == 2): # for AggKey
            self.server.AggKey(resp_tup[1])
            data = (1,)
            self.request.sendall(pickle.dumps(data))
            # log.debug("AggKey completed")
        elif(resp_tup[0] == 3): # for Search
            data = self.server.Search(resp_tup[1])
            self.request.sendall(pickle.dumps(data)+b'#####')
            # log.debug("Search completed")
        elif(resp_tup[0] == 4): # for Revocation_client
            self.server.RevocationClient(resp_tup[1])
            data = (1,)
            self.request.sendall(pickle.dumps(data))
            # log.debug("Revocation_client completed")
        elif(resp_tup[0] == 5): # for Revocation_operation
            self.server.RevocationOperation(resp_tup[1])
            data = (1,)
            self.request.sendall(pickle.dumps(data))
            # log.debug("Revocation_operation completed")

class MMCSEServer(socketserver.TCPServer):
    def __init__(self, addr, handler_class = SeverReqHandler, sec_lambda = 128) -> None:
        self.sec_lambda = sec_lambda
        self.addr = addr
        TSet: dict = {}
        XSet: dict = {}
        ASet: dict = {}
        self.EDB = (TSet, XSet, ASet)
        self.p = 69445180235231407255137142482031499329548634082242122837872648805446522657159
        self.g = 65537
        self.tPPRF = tPuncPRF.TPPRF(maxClientnum)
        super().__init__(addr, handler_class)
    
    def initServer(self, fileName):
        server_params = SSEUtil.readData(fileName)
        sec_lambda, addr, p, g, EDB, tPPRF = server_params
        self.sec_lambda = sec_lambda
        self.addr = addr
        self.p = p
        self.g = g
        self.EDB = EDB
        self.tPPRF = tPPRF
        
    def Update(self, data):
        (tAddr, tVal, alpha, state, updToken, PK, xTag) = data
        TSet, XSet, ASet = self.EDB
        TSet[tAddr] = (tVal, alpha, state)
        XSet[xTag] = (updToken, PK)
    
    def AggKey(self, data):
        ASetVal = data
        TSet, XSet, ASet = self.EDB
        for (aTag, aVal1, aVal2) in ASetVal:
            ASet[aTag] = (aVal1, aVal2)
    
    def Search(self, data):
        stokenlist, xtokenlists, utoken = data
        (hState, SH, aTag, cid) = utoken
        (d0, d1, SP) = SH
        TSet, XSet, ASet = self.EDB

        sEOpList = []
        if aTag not in ASet:
            return (sEOpList,)
        (aVal1, aVal2) = ASet[aTag]
        
        m = len(stokenlist)
        for j in range(m-1, -1, -1):
            cnt = 0
            tAddr = SSEUtil.bytes_XOR(stokenlist[j], hState)
            if tAddr not in TSet:
                continue
            (tVal, alpha, state) = TSet[tAddr]
            hState = SSEUtil.getHash(SSEUtil.bytes_XOR(state, hState))
            CH = np.full((SSEUtil.MAXKWNUM, 2), b'')
            for i, xtoken in enumerate(xtokenlists[j]):
                xTag = pow(xtoken, alpha, self.p).to_bytes(SSEUtil.MAXBYTES, 'little')
                (c_i, c_j) = SP[i]
                # CH[c_i][c_j] = b''
                if xTag in XSet:
                    (updToken, PK) = XSet[xTag]
                    PK0_int = 0
                    PK0 = PK0_int.to_bytes(32, 'little')
                    if PK == PK0:
                        CH[c_i][c_j] = updToken
                    else:
                        # y = self.tPPRF.Eval(PK, aVal1)
                        y = self.tPPRF.Eval(PK, cid)
                        if y != False:
                            CH[c_i][c_j] = updToken

            if nDSHVE.DSHVE().Query(SH, CH) == True:
                tVal_index = {'tVal': tVal, 'index': j}
                val_j = SSEUtil.bytes_XOR(str(tVal_index).encode(), aVal2)     
                sEOpList.append(val_j)
        
        return (sEOpList,)

    def RevocationClient(self, data):
        RSetVal = data
        TSet, XSet, ASet = self.EDB
        for (aTag, vfyVal) in RSetVal:
            if aTag in ASet:
                (aVal1, aVal2) = ASet[aTag]
                if aVal1 == vfyVal:
                    del ASet[aTag]

    def RevocationOperation(self, data):
        (xTag, PK) = data
        TSet, XSet, ASet = self.EDB
        (updToken, PK0) = XSet[xTag]
        XSet[xTag] = (updToken, PK)

        