from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from Crypto.Util import Counter
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Random.random import getrandbits
from hashlib import sha256
from merkletools import MerkleTools
import time
import sys
from itertools import cycle
import can
import os

bustype = 'socketcan'
channel = 'vcan0'

def sendData(id, ciphertext):
    bus = can.interface.Bus(channel=channel, bustype=bustype)

    #reading the encrypted bytes from the file to send through the bus.
    with open("tempx.txt", 'rb') as f:
        data = f.read()
    #Send data
    os.remove("temp.txt")
    msg = can.Message(arbitration_id=0xc0ffee, data=ciphertext,is_extended_id=False)
    bus.send(msg)
    #time.sleep(1)

mt = MerkleTools()

def xor(var, key) :
    key = key[:len(var)]
    int_var = int.from_bytes(var, sys.byteorder)
    int_key = int.from_bytes(key, sys.byteorder)
    int_enc = int_var ^ int_key
    return int_enc.to_bytes(len(var), sys.byteorder)
    
def generateHanchorCanData(current_anchor_random_number, message, can_id_key, can_id_counter, nonce=0):
    salt = current_anchor_random_number
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256() ,
        length = 64,
        salt = salt,
        iterations = 10000,
        backend = default_backend()
    )
    kdf_output = kdf.derive(can_id_key)
    hash_digest = sha256(kdf_output+can_id_counter).hexdigest().encode()
    #Authentication

    #Encryption
    length = len(message)#+len(can_id_counter)
    hash_digest = hash_digest[:length]

    data_frame = message #+ can_id_counter

    ciphertext = xor(data_frame,hash_digest)
    #mt.add_leaf(message,True)
    #mt.make_tree()
    return ciphertext


def verifyHanchorCanData(current_anchor_random_number, ciphertext, can_id_key, can_id_counter, nonce=0):
    salt = current_anchor_random_number
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 64,
        salt = salt,
        iterations = 10000,
        backend = default_backend()
    )
    kdf_output = kdf.derive(can_id_key)
    hash_digest = sha256(kdf_output+can_id_counter).hexdigest().encode()
    length = len(ciphertext)
    hash_digest = hash_digest[:length]

    data_frame = xor(ciphertext, hash_digest)
    message = data_frame[:7]
    counter = data_frame[7:8]

    mt.get_merkle_root()
    return message

current_anchor_random_number = get_random_bytes(64)
can_id_counter = get_random_bytes(1)
can_id_key = b'thisisjustakeythisisjustakeeyID1'

message = ' '.join(sys.argv[1][i:i+2] for i in range(0,len(sys.argv[1]),2))
#message = "69081F67FE5C6B36"
message_bytes = bytes.fromhex(message)
ciphertext = generateHanchorCanData(current_anchor_random_number, message_bytes, can_id_key, can_id_counter)


#To-do:
    #Define ID for the purpose of each ECU.
sendData(10, ciphertext)

#Writing the encrypted bytes on an external file.
with open("temp.txt", "wb") as f:
    f.write(ciphertext)


#message_1 = verifyHanchorCanData(current_anchor_random_number, ciphertext, can_id_key, can_id_counter)
        #print("message: " + str("".join("\\x%02x" % i for i in message))) # display bytes



