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
import threading
import random

bustype = 'socketcan'
channel = 'vcan0'
mt_sending = MerkleTools()
mt_receiving = MerkleTools()


def xor(var, key):
    """
        - ** var ** *bit_string* : First input of the xor operation
        - ** key ** *bit_string* : Second input of the xor operation
    """
    key = key[:len(var)]
    int_var = int.from_bytes(var, sys.byteorder)
    int_key = int.from_bytes(key, sys.byteorder)
    int_enc = int_var ^ int_key
    return int_enc.to_bytes(len(var), sys.byteorder)

def encryption(current_anchor_random_number, message, can_id_key, can_id_counter, nonce=0):
    """
        - ** current_anchor_random_number ** *bytes* : Anchor random number being broadcasted through the bus
        - ** message ** *bytes* : data being encrypted in the form of bytes.
        - ** can_id_key ** *bit_string* : bit string key, length of 32, 64, 128 bits.
        - ** can_id_counter ** *bytes* : Counter
        - ** nonce ** *number* : Cryptographically (NO USE)

        Returns the encrypted message in form of bytes.
    """

    salt = current_anchor_random_number
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256() ,
        length = 64,
        salt = salt,
        iterations = 10000,
        backend = default_backend()
    )
    kdf_output = kdf.derive(can_id_key)
    hash_digest = sha256(kdf_output).hexdigest().encode()

    length = len(message)#+len(can_id_counter)
    hash_digest = hash_digest[:length]

    data_frame = message

    ciphertext = xor(data_frame,hash_digest)
   
    return ciphertext

def decryption(current_anchor_random_number, ciphertext, can_id_key, can_id_counter, nonce=0):
    """
        - ** current_anchor_random_number ** *bytes* : Anchor random number being broadcasted through the bus
        - ** ciphertext ** *bytes* : data being decrypted in the form of bytes.
        - ** can_id_key ** *bit_string* : bit string key, length of 32, 64, 128 bits.
        - ** can_id_counter ** *bytes* : Counter
        - ** nonce ** *number* : Cryptographically (NO USE)

        Returns the decrypted ciphertext in form of bytes.
    """
    salt = current_anchor_random_number
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 64,
        salt = salt,
        iterations = 10000,
        backend = default_backend()
    )
    kdf_output = kdf.derive(can_id_key)
    #print("Decryption derivation key: ",kdf_output)
    hash_digest = sha256(kdf_output).hexdigest().encode()
    length = len(ciphertext)
    hash_digest = hash_digest[:length]

    data_frame = xor(ciphertext, hash_digest)
    message = data_frame

    return message

def sendData(id, ciphertext):
    """
        Sends single data frames through the CAN bus.
        - ** id ** *bytes* : ID key identifying the message in the bus.
        - ** ciphertext ** *bit_string* : ciphertext being send through the CAN bus
    """
    bus = can.interface.Bus(channel=channel, bustype=bustype)
    message = can.Message(arbitration_id=id, data=ciphertext, is_extended_id=False)
    
    IDs = ["0x2aa"]

    #print(hex(message.arbitration_id) in IDs)
    if(hex(message.arbitration_id) in IDs):
        #Should be the periodic verified anchor number instead of the 303030303030
        if (message.data.hex() == "3030303030303030"):
            print("Merkle tree root hash, sending: %s",mt_sending.get_merkle_root())
            mt_sending.reset_tree()
        else:
            mt_sending.add_leaf(message.data.hex())
            mt_sending.make_tree()

    bus.send(message)
    time.sleep(1)

def randomData(id, current_anchor_random_number):
    """
        Sends periodic random data frames through the CAN bus.
        - ** id ** *bytes* : ID key identifying the message in the bus.
        - ** current_anchor_random_number ** *bit_string* : current anchor random number that was being broadcasted through the bus
    """
    while(True):
        initial_data = "00000000"
        sendData(id,bytes(initial_data.encode()))
        for i in range(0,10):
            can_id_counter = get_random_bytes(1)
            can_id_key = b'thisisjustakeythisisjustakeeyID1'

            length_data = random.randint(0,8)
            random_data = get_random_bytes(length_data)
            #print("Unencrypted message from ECU_ is: %s", random_data.hex())
            ciphertext = encryption(current_anchor_random_number, random_data, can_id_key, can_id_counter)
            #ciphertext = sendData()

            sendData(id, ciphertext)

def receiveData(id, current_anchor_random_number):
    """
        Receives all the data that is going through the bus.ID is used to distinguish what messages we want to pull out.
        - ** id ** *bytes* : ID key identifying the message pulling from the bus.
    """
    bus = can.interface.Bus(channel=channel, bustype=bustype)

    IDs = ["0x2aa"]
    can_id_counter = get_random_bytes(1)
    can_id_key = b'thisisjustakeythisisjustakeeyID1'

    for message in bus: 
        #Should be the periodic verified anchor number instead of the 303030303030
        if(hex(message.arbitration_id) in IDs):  
            if(message.data.hex() == "3030303030303030"):
                print("Merkle tree root hash, receiving: %s",mt_receiving.get_merkle_root())
                mt_receiving.reset_tree()
            else:
                #print("Message from the interface: ",message.data.hex())
                mt_receiving.add_leaf(message.data.hex())
                mt_receiving.make_tree()  
                message = decryption(current_anchor_random_number, message.data,can_id_key, can_id_counter)
                print("Decrypted message from broadcastECU is %s", message.hex())
    return 0

try:
        current_anchor_random_number = get_random_bytes(8)
        current_anchor_random_number = b'\xfd\xf2\xcdQO\x1b\xa6\x06'
        IDa = 0x3aa
        IDb = 0x3ab

        thread_1 = threading.Thread(target=randomData, args=(IDa, current_anchor_random_number,))
        #thread_2 = threading.Thread(target=periodicBroadcast, args=(IDb, current_anchor_random_number,))
        thread_3 = threading.Thread(target=receiveData, args=(IDa, current_anchor_random_number,))
        
        thread_1.start()
        #thread_2.start()
        thread_3.start()

except:  
    print("Error: Unable to start thread.")
while 1: 
    pass  