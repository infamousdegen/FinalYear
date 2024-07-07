from scapy.all import *
from scapy.layers.http import *
from scapy.layers.inet import IP, TCP

# Function to create an HTTP request
def create_http_request(dst_ip, dst_port, src_ip, src_port):
    ip = IP(dst=dst_ip, src=src_ip)
    tcp = TCP(dport=dst_port, sport=src_port, seq=1000, flags="S")
    http_req = HTTPRequest(
        Method=b"GET",
        Path=b"/",
        Http_Version=b"HTTP/1.1",
        Host=b"www.example.com"
    )
    return ip/tcp/http_req

# Function to create an HTTP response
def create_http_response(dst_ip, dst_port, src_ip, src_port):
    ip = IP(dst=dst_ip, src=src_ip)
    tcp = TCP(dport=dst_port, sport=src_port, seq=1001, ack=1001, flags="S")
    http_resp = HTTPResponse(
        Http_Version=b"HTTP/1.1",
        Status_Code=b"200",
        Reason_Phrase=b"OK",
        Content_Type=b"text/html",
        Content_Length=b"44"
    )
    return ip/tcp/http_resp

# List to store the packets
packets = []

# Create multiple HTTP requests and responses
for i in range(5):
    req = create_http_request("192.168.1.1", 80, "192.168.1.2", 12345 + i)
    resp = create_http_response("192.168.1.2", 12345 + i, "192.168.1.1", 80)
    packets.append(req)
    packets.append(resp)

# Save the packets to a PCAP file
wrpcap("http_traffic.pcap", packets)

print("HTTP requests and responses saved to http_traffic.pcap")
