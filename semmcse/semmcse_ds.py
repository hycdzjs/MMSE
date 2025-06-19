import sys, logging
from utils.semmcseDS import MMCSEDS
# import SSEUtil
from utils import SSEUtil
import pickle
import os

logging.basicConfig(level=logging.DEBUG)

log = logging.getLogger(__name__)

MAXINT = sys.maxsize
HOST = 'localhost'
TA_PORT = 40057
SERVER_PORT = 50057

INIT_FROM_FILE = False
FILE_NAME = 'dsParams.dat'
FILE_PATH = os.path.join('.\\semmcse', FILE_NAME)

if __name__ == "__main__":
    # HOST = sys.argv[1]
    # TA_PORT = int(sys.argv[2])
    # SERVER_PORT = int(sys.argv[3])
    
    ds_obj = MMCSEDS((HOST, TA_PORT), (HOST, SERVER_PORT))
    if INIT_FROM_FILE == True:
        ds_obj.initDS(FILE_PATH)
    else:
        ds_obj.Setup(100)
        ds_params = (ds_obj.sid, ds_obj.taAddr,
                ds_obj.severAddr, ds_obj.sec_lambda,
                ds_obj.p, ds_obj.g, ds_obj.sk, ds_obj.st, ds_obj.tPPRF)
        SSEUtil.saveData(FILE_PATH, pickle.dumps(ds_params))

    ds_obj.Update('add', 2, "apple")
    ds_obj.Update('add', 4, "apple")
    ds_obj.Update('add', 5, "apple")
    ds_obj.Update('add', 6, "apple")
    ds_obj.Update('add', 7, "apple")
    ds_obj.Update('add', 8, "apple")
    ds_obj.Update('del', 7, "apple")
    ds_obj.Update('add', 9, "apple")
    ds_obj.Update('add', 10, "apple")
    ds_obj.Update('add', 11, "apple")
    ds_obj.Update('add', 12, "apple")
    ds_obj.Update('add', 13, "apple")
    ds_obj.Update('add', 14, "apple")
    ds_obj.Update('add', 2, "banana")
    ds_obj.Update('add', 4, "banana")
    ds_obj.Update('add', 5, "banana")
    ds_obj.Update('add', 6, "banana")
    ds_obj.Update('add', 7, "banana")
    ds_obj.Update('del', 4, "banana")
    ds_obj.Update('add', 3, "pincode")
    ds_obj.Update('add', 4, "pincode")
    ds_obj.Update('add', 5, "pincode")
    ds_obj.Update('add', 6, "pincode")
    ds_obj.Update('add', 7, "pincode")
    ds_obj.Update('del', 3, "pincode")
    
    
    ds_obj.revocation_operation([0], ('add', 2, "apple"))
    ds_obj.revocation_operation([0], ('add', 4, "apple"))
    ds_obj.revocation_operation([0], ('add', 5, "apple"))
    ds_obj.revocation_operation([0], ('del', 7, "apple"))
    ds_obj.revocation_operation([0], ('add', 2, "banana"))
    ds_obj.revocation_operation([0], ('del', 4, "banana"))
    ds_obj.revocation_operation([0], ('add', 4, "pincode"))
    
    ds_obj.revocation_client([0, 1])
