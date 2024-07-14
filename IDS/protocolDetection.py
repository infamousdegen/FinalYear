from scapy.all import TCP,UDP,ICMP
def checkProtocol(protocol,pkt):
    if(protocol.lower() =='any'):
        return True
    if (protocol.lower() == 'tcp' and pkt.haslayer(TCP)):
        return True
    elif(protocol.lower() == 'udp' and pkt.haslayer(UDP)):
        return True
    # elif(protocol.lower() == 'icmp' and pkt.haslayer(ICMP)):
    #     return True
    return False 