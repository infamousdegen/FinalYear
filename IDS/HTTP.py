from scapy.all import *
from scapy.layers.http import *
from scapy.packet import Packet
from typing import *

class ApplHttp:
    def __init__(self, pkt: Packet):
        '''
        Create instances of ApplHttp on top of HTTP instances to make analyzing HTTP packets faster.
        '''
        self.pkt = pkt
        # self.type = self._determine_http_type()


        # if self.type == "Unknown":
        #     raise ValueError("Inside HTTP.py some issue ")

    # def _determine_http_type(self) -> str:
    #     '''
    #     Determine whether the packet is an HTTP request or response.
    #     '''
    #     if self.pkt.haslayer(HTTPRequest):
    #         return "HTTPRequest"
    #     elif self.pkt.haslayer(HTTPResponse):
    #         return "HTTPResponse"
    #     else:
    #         return "Unknown"

    def get_payload(self) -> Optional[str]:
        '''
        To get the HTTP payload of a packet.
        Retrieves the body of an HTTP request or response.
        '''
        if self.type == "HTTPRequest":
            layer = HTTPRequest
        elif self.type == "HTTPResponse":
            layer = HTTPResponse
        else:
            return None 

        if Raw in self.pkt[layer]:
            return self.pkt[layer][Raw].load.decode(errors='ignore')
        else:
            return None
        
    #Have to test
    def get_headers(self) -> dict:
        '''
        Extracts and returns HTTP headers as a dictionary.
        '''
        
        headers = {}
        if self.type == "HTTPRequest":
            layer = self.pkt.getlayer(HTTPRequest)
        elif self.type == "HTTPResponse":
            layer = self.pkt.getlayer(HTTPResponse)
        else:
            print("inside retunr None")
            return None 
        
        for field_name, field_value in layer.fields.items():
            if field_name not in ['Method', 'Path', 'Http_Version', 'Status_Code', 'Reason_Phrase']:
                if isinstance(field_value, bytes):
                    field_value = field_value.decode('utf-8', errors='ignore')
                headers[field_name] = field_value

        return headers
