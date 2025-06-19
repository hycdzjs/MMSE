import sys, logging
from utils.semmcseTA import MMCSETA, TaReqHandler
# import SSEUtil
from utils import SSEUtil
import pickle
import os


logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

HOST = 'localhost'
TA_PORT = 40057
SERVER_PORT = 50057

INIT_FROM_FILE = False
FILE_NAME = 'taParams.dat'
FILE_PATH = os.path.join('.\\semmcse', FILE_NAME)

if __name__ == "__main__":
    # HOST = sys.argv[1]
    # PORT = int(sys.argv[2])
    try:
        ta = MMCSETA((HOST, TA_PORT), (HOST, SERVER_PORT), TaReqHandler)
        if INIT_FROM_FILE == True:
            ta.initTA(FILE_PATH)
        ta.serve_forever()
    except	KeyboardInterrupt:
        print("CTRL+C, break")
        ta_params = (ta.sec_lambda, ta.addr,
                ta.msk, ta.dsIndex, ta.clientIndex,
                ta.dsParams, ta.st_TA, ta.scPRF)
        SSEUtil.saveData(FILE_PATH, pickle.dumps(ta_params))
        ta.server_close()
        sys.exit()
    
