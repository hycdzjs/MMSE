import sys, logging
from utils.efpmseClient import MMCSEClient
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
FILE_NAME = 'clientParams.dat'
FILE_PATH = os.path.join('.\\efpmseconj', FILE_NAME)

if __name__ == "__main__":
    # HOST = sys.argv[1]
    # TA_PORT = int(sys.argv[2])
    # SERVER_PORT = int(sys.argv[3])
    
    client_obj = MMCSEClient((HOST, TA_PORT), (HOST, SERVER_PORT))
    
    if INIT_FROM_FILE == True:
        client_obj.initClient(FILE_PATH)
    else:
        client_obj.AggKey([0,1,2,3,5,10])
        client_params = (client_obj.cid, client_obj.taAddr,
                client_obj.severAddr,
                client_obj.SID, client_obj.AK, client_obj.KC, client_obj.ss)
        SSEUtil.saveData(FILE_PATH, pickle.dumps(client_params))
        
    sid = 0
    log.info("Search for banana of sid=0")
    log.info(client_obj.Search(sid, ["banana"]))
    log.info("Search for apple of sid=0")
    log.info(client_obj.Search(sid, ["apple"]))
    
    # log.info("Search for apple and banana of sid=0")
    # log.info(client_obj.Search(sid, ["apple", "banana"]))
    log.info("Search for pincode of sid=0")
    log.info(client_obj.Search(sid, ["pincode"]))
    log.info("Search for apple and pincode of sid=0")
    log.info(client_obj.Search(sid, ["apple", "pincode"]))
    log.info("Search for banana and pincode of sid=0")
    log.info(client_obj.Search(sid, ["banana", "pincode"]))
    log.info("Search for apple, banana and pincode of sid=0")
    log.info(client_obj.Search(sid, ["apple", "banana","pincode"]))
    
    log.info("Search for pear of sid=0")
    log.info(client_obj.Search(sid, ["pear"]))
    
    sid = 1
    log.info("Search for pincode of sid=1")
    log.info(client_obj.Search(sid, ["pincode"]))
    
    # log.info("Search for apple and banana of sid=1")
    # log.info(client_obj.Search(sid, ["apple", "banana"]))
    # # log.info("Search for apple and pincode of sid=1")
    # # log.info(client_obj.Search(sid, ["apple", "pincode"]))
    
    # sid = 2
    # log.info("Search for apple of sid=2")
    # log.info(client_obj.Search(sid, ["apple"]))
    # log.info("Search for banana of sid=2")
    # log.info(client_obj.Search(sid, ["banana"]))
    # log.info("Search for pincode of sid=2")
    # log.info(client_obj.Search(sid, ["pincode"]))
    # log.info("Search for apple and banana of sid=2")
    # log.info(client_obj.Search(sid, ["apple", "banana"]))
    # log.info("Search for apple and pincode of sid=2")
    # log.info(client_obj.Search(sid, ["apple", "pincode"]))
    
    # sid = 3
    # log.info("Search for pincode of sid=3")
    # log.info(client_obj.Search(sid, ["pincode"]))
    # log.info("Search for apple and banana of sid=3")
    # log.info(client_obj.Search(sid, ["apple", "banana"]))
    # log.info("Search for apple and pincode of sid=3")
    # log.info(client_obj.Search(sid, ["apple", "pincode"]))
    # log.info("Search for apple, banana and pincode of sid=3")
    # log.info(client_obj.Search(sid, ["apple", "banana","pincode"]))
    
    # sid = 5
    # log.info("Search for banana and pincode of sid=5")
    # log.info(client_obj.Search(sid, ["banana", "pincode"]))
    # log.info("Search for apple and pincode and banana of sid=5")
    # log.info(client_obj.Search(sid, ["apple", "pincode", "banana"]))
