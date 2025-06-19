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

log = logging.getLogger(__name__)

maxDSnum = 65536 # the max number of data sources
maxClientnum = SSEUtil.MAXClientNUM

class SeverReqHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, addr, server):
        super().__init__(request, addr, server)

    def handle(self):
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
        if(resp_tup[0] == 0):  # for setup
            self.server.Setup(resp_tup[1])
            data = (1,)
            self.request.sendall(pickle.dumps(data))
            # log.debug("setup completed")
        elif(resp_tup[0] == 1):  # for update
            self.server.Update(resp_tup[1])
            data = (1,)
            self.request.sendall(pickle.dumps(data))
            # log.debug("update completed")
        # elif(resp_tup[0] == 2): # for AggKey
        #     self.server.AggKey(resp_tup[1])
        #     data = (1,)
        #     self.request.sendall(pickle.dumps(data))
        #     log.debug("AggKey completed")
        elif(resp_tup[0] == 3): # for Search
            data = self.server.Search(resp_tup[1])
            self.request.sendall(pickle.dumps(data)+b'#####')
            # log.debug("Search completed")

class MMCSEServer(socketserver.TCPServer):
    def __init__(self, addr, handler_class = SeverReqHandler, sec_lambda = 128) -> None:
        self.sec_lambda = sec_lambda
        self.addr = addr
        self.dsParams: dict = {}
        table_T: dict = {}
        table_V: dict = {}
        table_S: dict = {}
        self.EDB = (table_T, table_V, table_S)
        super().__init__(addr, handler_class)
    
    def initServer(self, fileName):
        server_params = SSEUtil.readData(fileName)
        sec_lambda, addr, dsParams, EDB = server_params
        self.sec_lambda = sec_lambda
        self.addr = addr
        self.dsParams = dsParams
        self.EDB = EDB
        
    def Setup(self, data):
        (sid, KS) = data
        self.dsParams[sid] = KS
        
    def Update(self, data):
        (new_table_T, new_table_V, new_table_S) = data
        
        table_T, table_V, table_S = self.EDB
        for key, value in new_table_T.items():
            if key in table_T:
                table_T[key] = list(set(table_T[key]+value))
            else:
                table_T.update(new_table_T)

        table_V.update(new_table_V)
        table_S.update(new_table_S)
        
        self.EDB = (table_T, table_V, table_S)
        
    def Search(self, data):
        # sid, KSC, SC = data
        sid, KSC, SC, STw0 = data
        KS = self.dsParams[sid]
        table_T, table_V, table_S = self.EDB
        setR = []
        # STw = SSEUtil.prf_F(KS, STw0)
        
        SKc_new = 0
        while SKc_new != b'':
            KSC = SSEUtil.getHash((str(STw0) + str(SC)).encode())
            
            Kw = SSEUtil.prf_F(KS, KSC)
            UTw = SSEUtil.getHash((str(Kw) + str(SC)).encode())
            
            E = []
            if UTw in table_T:
                E = table_T[UTw]
            
            if E != []:
                CTwk = SSEUtil.getHash((str(Kw) + str(SC)).encode())
                for e in E:
                    ind_bytes = SSEUtil.bytes_XOR(e, CTwk)
                    ind = int(str(ind_bytes, encoding='utf-8'))
                    setR.append(ind)
            
            if UTw in table_V:
                aes = AEScryptor(SC, AES.MODE_ECB,paddingMode= "ZeroPadding",characterSet='utf-8')
                KSC_str = aes.decryptFromBytes(table_V[UTw].toBytes()).toString()
                KSC = ast.literal_eval(KSC_str)
            
            SKc_new = table_S[SSEUtil.getHash(SC)]
            SC = SSEUtil.bytes_XOR(SKc_new, SSEUtil.getHash(SC))
        
        return (setR,)
       