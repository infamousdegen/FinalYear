from scapy.all import *
from scapy.all import IP
import ipaddress

# ToDo: Check the direction also, currently not implemented 
# Make the IP matching better to include a wide variety 
def checkIp(sourceIp, destinationIP, pkt):
    # Print packet summary for troubleshooting
    if not pkt.haslayer(IP):
        print("IP layer missing in packet.")
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

    if not isSourceMatch or not isDstMatch:
        return False

    return True
