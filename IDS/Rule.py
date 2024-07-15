from ipDetection import checkIp
from protocolDetection import checkProtocol
from applicationLayerDetection import checkApplicationProtocol
from HTTP import ApplHttp
from alertModule import Alert
import re
from scapy.all import Packet, TCP, UDP, Raw
from typing import Optional
from scapy.layers.http import *

class Rule:
    """ NIDS RULE """

    def __init__(self, data) -> None:
        """Below mentioned are mandatory"""
        self.action = data["ruleHeader"]["action"]
        self.protocol = data["ruleHeader"]["protocols"]
        self.sourceIP = data["ruleHeader"]["sourceIP"]
        self.destinationIP = data["ruleHeader"]["destinationIP"]
        self.sourcePort = data["ruleHeader"]["sourcePort"]
        self.destinationPort = data["ruleHeader"]["destinationPort"]
        self.direction = data["ruleHeader"]["direction"]
        self.sid = data["ruleHeader"]["sid"]

        # Allow ruleOptions to be None
        self.ruleOptions = data.get("ruleOptions", None)
        self.applicationLayer = data["ruleHeader"].get("applicationLayer", None)

    def match(self, pkt: Packet) -> bool:
        """
        Return True if and only if everything in the provided rule matches or else it will return False
        """

        # Application Layer
        if self.applicationLayer is not None:
            
            if not checkApplicationProtocol(self.applicationLayer, pkt):
                return False

            if self.applicationLayer.lower() == 'http':
                try:
                    
                    # #Take care of this IMPORTANT
                    # if not pkt.haslayer(HTTPRequest) or not pkt.haslayer(HTTPResponse): return False
                    http = ApplHttp(pkt)
                    httpheader = self.ruleOptions.get("httpHeaders", None) if self.ruleOptions else None
                    httpbody = self.ruleOptions.get("httpBody", None) if self.ruleOptions else None

                    print("2")
                    if httpheader is not None:
                        pktheader = http.get_headers()
                        print("pktheaders",pktheader)
                        ruleheaderName = httpheader.get("headerName")
                        ruleheaderValue = httpheader.get("headerValue")

                        if ruleheaderName not in pktheader or pktheader[ruleheaderName] != ruleheaderValue:
                            return False
                    print("3")
                    if httpbody is not None:
                        pktpayload = http.get_payload()
                        if pktpayload is None:
                            return False

                        content = httpbody.get("content", None)
                        regex = httpbody.get("regex", None)

                        if content is not None and content != pktpayload:
                            return False
                        if regex is not None and not re.search(regex, pktpayload):
                            return False
                except Exception as e:
                    print(f"Error processing HTTP packet: {e}")
                    return False

        # Transport Layer
        if not checkProtocol(self.protocol, pkt):
            return False

        # Matches PAYLOAD
        payload = self.ruleOptions.get("payloadDetectionOptions", None) if self.ruleOptions else None
        if payload is not None:
            pktpayload = self._process_tcp_payload(pkt)
            if pktpayload is None:
                return False
            content = payload.get("content", None)
            regex = payload.get("regex", None)
            if content is not None and content != pktpayload:
                return False
            # print("pktpayload",pktpayload)
            if regex is not None and not re.search(regex, pktpayload):
                return False

        if not checkIp(self.sourceIP, self.destinationIP, pkt):
            return False
        return True

    def getEntireAlertMessage(self, pkt: Packet, ruleSid: int) -> str:
        """
        Based on the assumptions made in match we can directly get it to print IP layer and Transport Layer
        """
        # If there is some message to print 
        msg = "[USER DEFINED MSG] \n"
        msg += self.getMessageToPrint()
        print("before calling alert")
        alert = Alert()
        ipString = alert.ipString(pkt, ruleSid)
        tcpString = alert.tcpString(pkt, ruleSid) if pkt.haslayer(TCP) else ""
        udpString = alert.udpString(pkt, ruleSid) if pkt.haslayer(UDP) else ""

        httpHeader = ""
        httpBody = ""
        if self.applicationLayer is not None and self.applicationLayer.lower() == 'http':
            try:
                httpHeader = alert.httpString(pkt, ruleSid)
                httpBody = alert.httpBody(pkt, ruleSid)
            except Exception as e:
                print(f"Error processing HTTP alert: {e}")

        tcpPayload = "[TCP PAYLOAD]"
        udpPayload = "[UDP PAYLOAD]"

        if self.ruleOptions and self.ruleOptions.get("payloadDetectionOptions", None):
            tcpPayload += alert.tcpPayload(pkt, ruleSid) if pkt.haslayer(TCP) else ""
            udpPayload += alert.udpPayload(pkt, ruleSid) if pkt.haslayer(UDP) else ""

        completeAlertMessage = msg + "\n" + ipString + tcpString + udpString + httpHeader + httpBody + tcpPayload + udpPayload
        return completeAlertMessage

    def getMessageToPrint(self) -> str:
        if self.ruleOptions:
            return self.ruleOptions.get("msg", "")
        return ""

    def _process_tcp_payload(self, pkt: Packet) -> Optional[str]:
        if Raw in pkt:
            payload = pkt[Raw].load
            if isinstance(payload, bytes):
                try:
                    payload = payload.decode('utf-8', errors='ignore')
                except UnicodeDecodeError:
                    payload = str(payload)
            return payload
        else:
            return None

    def _process_udp_payload(self, pkt: Packet) -> Optional[str]:
        if Raw in pkt:
            payload = pkt[Raw].load
            if isinstance(payload, bytes):
                try:
                    payload = payload.decode('utf-8', errors='ignore')
                except UnicodeDecodeError:
                    payload = str(payload)
            return payload
        else:
            return None
