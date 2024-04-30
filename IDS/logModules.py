import datetime
import pickle
import os
from scapy.all import *

def log_packet(rule, pkt):
    if not hasattr(log_packet, "counter"):
        log_packet.counter = 1  # initialize counter at 1 on first call
    
    msg = f"SID: {rule.sid}\nSummary: {pkt.summary()}"
    
    directory = "logs"
    if not os.path.exists(directory):
        os.makedirs(directory)
    
    filename = os.path.join(directory, f"Log{log_packet.counter}.txt")
    with open(filename, 'w') as file:
        file.write(msg)
    
    log_packet.counter += 1  # Increment the counter after writing the file
