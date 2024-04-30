from scapy.all import *
import ipaddress
#todo check the direction also currently not implemented 
#make the ip matching better to include wide variety 
def checkIpAndPort(sourceIp, destinationIP, sourcePorts, destinationPorts, direction, pkt):
    # Print packet summary for troubleshooting
    
    if (not pkt.haslayer(IP)):
        print("IP layer missing in packet.")
        return False

    
    # Additional checks for TCP layer
    if (not pkt.haslayer(TCP)):
        print("TCP layer missing in packet.")
        return False
    
    pkt_source_ip = ipaddress.ip_address(pkt[IP].src)
    pkt_dst_ip = ipaddress.ip_address(pkt[IP].dst)

    def is_ip_present(ip, spec):
        if spec.strip().lower() == 'any':
            return True
        elif '/' in spec:
            network = ipaddress.ip_network(spec, strict=False)
            return ip in network
        else:
            return ip == ipaddress.ip_address(spec)
    
    isSourceMatch = is_ip_present(pkt_source_ip, sourceIp)
    isDstMatch = is_ip_present(pkt_dst_ip, destinationIP)

    if (not isSourceMatch or not isDstMatch):
        return False

    if pkt.haslayer(UDP):
        srcPort = pkt[UDP].sport
        dstPort = pkt[UDP].dport
    elif pkt.haslayer(TCP):
        srcPort = pkt[TCP].sport
        dstPort = pkt[TCP].dport
    else:
        print("Neither TCP nor UDP layer found in packet.")
        return False 

    if ('any' not in sourcePorts and srcPort not in sourcePorts) or ('any' not in destinationPorts and dstPort not in destinationPorts):
        return False
    return True
