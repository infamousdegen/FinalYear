from scapy.all import *
from scapy.layers.http import *

def safe_decode(field):
    return field.decode() if field else None

def packet_handler(pkt):
    if pkt.haslayer(HTTPRequest):
        # print("HTTP Request:")
        # print(f"Method: {safe_decode(pkt[HTTPRequest].Method)}")
        # print(f"Host: {safe_decode(pkt[HTTPRequest].Host)}")
        # print(f"Path: {safe_decode(pkt[HTTPRequest].Path)}")
        # pkt.show()
        pass
    elif pkt.haslayer(HTTPResponse):
        print("HTTP Response:")
        print(f"Status Code: {pkt[HTTPResponse].Status_Code}")
        print(f"Reason: {safe_decode(pkt[HTTPResponse].Reason_Phrase)}")
        print(f"Content-Length: {pkt[HTTPResponse].Content_Length}")
        # pkt.show()

# Load the PCAP file and analyze HTTP packets
pcap_file = "http_traffic.pcap"  # Replace with the path to your PCAP file
sniff(offline=pcap_file, prn=packet_handler, store=0, session=TCPSession)
