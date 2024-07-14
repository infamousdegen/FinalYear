from scapy.layers.http import *
def checkApplicationProtocol(protocol,pkt):
    '''
    Responsible to check whether the packet has the given application layer
    '''
    if (protocol.lower() == 'http' and  pkt.haslayer(HTTP)):
        return True
    return False 

