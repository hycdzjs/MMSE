import sys, logging
from utils.mmcseServer import MMCSEServer, SeverReqHandler
# import SSEUtil
from utils import SSEUtil
import pickle
import os

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

HOST = 'localhost'
SERVER_PORT = 50057

INIT_FROM_FILE = False
FILE_NAME = 'serverParams.dat'
FILE_PATH = os.path.join('.\\mmcse', FILE_NAME)

if __name__ == "__main__":
    # HOST = sys.argv[1]
    # PORT = int(sys.argv[2])
    try:
        server = MMCSEServer((HOST, SERVER_PORT), SeverReqHandler)
        if INIT_FROM_FILE == True:
            server.initServer(FILE_PATH)
        server.serve_forever()
    except	KeyboardInterrupt:
        print("CTRL+C, break")
        server_params = (server.sec_lambda, server.addr,
                server.dsParams, server.p, server.g,
                server.EDB)
        SSEUtil.saveData(FILE_PATH, pickle.dumps(server_params))
        server.server_close()
        sys.exit()
        