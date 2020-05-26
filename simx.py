import time
import can
import sys
import os

bustype = 'socketcan'
channel = 'vcan0'

def producer(id):
    bus = can.interface.Bus(channel=channel, bustype=bustype)

    #reading the encrypted bytes from the file to send through the bus.
    with open("tempx.txt", 'rb') as f:
        data = f.read()
    os.remove("temp.txt")
    msg = can.Message(arbitration_id=0xc0ffee, data=data,is_extended_id=False)
    bus.send(msg)
    #time.sleep(1)

producer(10)


