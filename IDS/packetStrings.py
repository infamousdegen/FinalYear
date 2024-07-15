from ipDetection import checkIp
from protocolDetection import checkProtocol
from applicationLayerDetection import checkApplicationProtocol
from HTTP import ApplHttp
from alertModule import Alert
import re
from scapy.all import Packet, TCP, UDP, Raw

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
                http = ApplHttp(pkt)
                httpheader = self.ruleOptions.get("httpHeaders", None)
                httpbody = self.ruleOptions.get("httpBody", None)

                if httpheader is not None:
                    pktheader = http.get_headers()
                    ruleheaderName = httpheader.get("headerName")
                    ruleheaderValue = httpheader.get("headerValue")

                    if ruleheaderName not in pktheader or pktheader[ruleheaderName] != ruleheaderValue:
                        return False

                if httpbody is not None:
                    pktpayload = http.get_payload()
                    if pktpayload is None:
                        return False

                    content = httpbody.get("content", None)
                    regex = httpbody.get("regex", None)

                    if content is not None and content != pktpayload:
                        return False
                    if regex is not None and not re.search(regex.encode('utf-8'), pktpayload):
                        return False

        # Transport Layer
        if not checkProtocol(self.protocol, pkt):
            return False

        print(Alert.tcpPayload(pkt,1))
        # Matches PAYLOAD
        # if self.ruleOptions is not None:
        #     payload = self.ruleOptions.get("payloadDetectionOptions", None)
        #     if payload is not None:
        #         pktpayload = pkt[Raw].load if Raw in pkt else None
        #         content = payload.get("content", None)
        #         regex = payload.get("regex", None)
        #         if content is not None and content != pktpayload:
        #             return False
        #         if regex is not None and pktpayload and not re.search(regex.encode('utf-8'), pktpayload):
        #             return False

        if not checkIp(self.sourceIP, self.destinationIP, pkt):
            return False

        return True

    def process_payload(self, tcp):
        if (hasattr(self.ruleOptions, "content") and tcp.payload):
            data = bytes(tcp.payload)
            data = re.sub(self.ruleOptions["content"].encode('utf-8'), self.ruleOptions["content"].encode('utf-8'), data)
            lines = data.splitlines()
            s = ""
            for line in lines:
                s += "\t" + line.decode("utf-8", errors="ignore") + "\n"
            return s
        else:
            return self.payloadString(tcp)

    def getEntireAlertMessage(self, pkt: Packet, ruleSid: int) -> str:
        """
        Based on the assumptions made in match we can directly get it to print IP layer and Transport Layer
        """
        alert = Alert()
        ipString = alert.ipString(pkt, ruleSid)
        tcpString = alert.tcpString(pkt, ruleSid) if pkt.haslayer(TCP) else ""
        udpString = alert.udpString(pkt, ruleSid) if pkt.haslayer(UDP) else ""

        httpHeader = ""
        httpBody = ""
        if self.applicationLayer is not None and self.applicationLayer.lower() == 'http':
            httpHeader = alert.httpString(pkt, ruleSid)
            httpBody = alert.httpBody(pkt, ruleSid)

        tcpPayload = ""
        udpPayload = ""

        if self.ruleOptions.get("payloadDetectionOptions", None):
            tcpPayload = self.process_payload(pkt[TCP]) if pkt.haslayer(TCP) else ""
            udpPayload = alert.udpPayload(pkt, ruleSid) if pkt.haslayer(UDP) else ""

        completeAlertMessage = ipString + tcpString + udpString + httpHeader + httpBody + tcpPayload + udpPayload
        return completeAlertMessage

    def getMessageToPrint(self, pkt: Packet) -> str:
        msg = self.ruleOptions.get("msg", None)
        if msg:
            return msg
        return ""
