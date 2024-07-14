from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse, Raw
from scapy.layers.inet import IP, TCP
from  HTTP import *

# Craft an HTTP Request with a body
packet = IP(dst="www.example.com")/TCP()/HTTPRequest(Method="GET", Path="/", Http_Version="HTTP/1.1")/Raw(load="Hello, world!")

# Instantiate ApplHttp
try:
    appl_http = ApplHttp(packet)
    payload = appl_http.get_payload()
    print("Payload:", payload)
except ValueError as e:
    print(e)

# Craft an HTTP Response with a body
response_packet = IP(dst="www.example.com")/TCP()/HTTPResponse(Http_Version="HTTP/1.1", Status_Code="200", Reason_Phrase="OK")/Raw(load="Response body here")

# Instantiate ApplHttp
try:
    appl_http_response = ApplHttp(response_packet)
    response_payload = appl_http_response.get_payload()
    print("Response Payload:", response_payload)
except ValueError as e:
    print(e)
