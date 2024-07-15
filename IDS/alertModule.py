from scapy.all import *
from scapy.all import IP, TCP,UDP,Packet
from HTTP import ApplHttp

class Alert():
    
    def ipString(self,pkt:Packet,sid:int) -> str:
        '''
        If this function is being called then that means that there is IP layer in the packet and prints entire details about the IP
        '''

        msg = ""
        msg += " ALERT \n"
        msg += f"Rule Matched: {sid} \n"
        ip = pkt[IP]
        out = "[IP HEADER]" + "\n"
        out += "\t Version: " + str(ip.version) + "\n"
        out += "\t IHL: " + str(ip.ihl * 4) + " bytes" + "\n"
        out += "\t ToS: " + str(ip.tos) + "\n"
        out += "\t Total Length: " + str(ip.len) + "\n"
        out += "\t Identification: " + str(ip.id) + "\n"
        out += "\t Flags: " + str(ip.flags) + "\n"
        out += "\t Fragment Offset: " + str(ip.frag) + "\n"
        out += "\t TTL: " + str(ip.ttl) + "\n"
        out += "\t Protocol: " + str(ip.proto) + "\n"
        out += "\t Header Checksum: " + str(ip.chksum) + "\n"
        out += "\t Source: " + str(ip.src) + "\n"
        out += "\t Destination: " + str(ip.dst) + "\n"
        if (ip.ihl > 5):
            out += "\t Options: " + str(ip.options) + "\n"
        return msg + out
    
    def tcpString(self,pkt:Packet,sid:int) -> str:
        """
        If this function is called then it means that there is TCP layer in the packet
        """
        msg = ""
        msg += " ALERT \n"
        msg += f"Rule Matched: {sid} \n"
        tcp = pkt[TCP]
        out = "[TCP Header]" + "\n"
        out += "\t Source Port: " + str(tcp.sport) + "\n"
        out += "\t Destination Port: " + str(tcp.dport) + "\n"
        out += "\t Sequence Number: " + str(tcp.seq) + "\n"
        out += "\t Acknowledgment Number: " + str(tcp.ack) + "\n"
        out += "\t Data Offset: " + str(tcp.dataofs) + "\n"
        out += "\t Reserved: " + str(tcp.reserved) + "\n"
        out += "\t Flags: " + tcp.underlayer.sprintf("%TCP.flags%") + "\n"
        out += "\t Window Size: " + str(tcp.window) + "\n"
        out += "\t Checksum: " + str(tcp.chksum) + "\n"
        if (tcp.flags & 0x20):
            out += "\t Urgent Pointer: " + str(tcp.window) + "\n"
        if (tcp.dataofs > 5):
            out += "\t Options: " + str(tcp.options) + "\n"
        return msg + out
    

    def udpString(self,pkt:Packet,sid:int):
        """
        If this function is called then the packet has UDP layer 
        """
        msg = ""
        msg += " ALERT \n"
        msg += f"Rule Matched: {sid} \n"
        udp = pkt[UDP]
        out = "[UDP Header]" + "\n"
        out += "\t Source Port: " + str(udp.sport) + "\n"
        out += "\t Destination Port: " + str(udp.dport) + "\n"
        out += "\t Length: " + str(udp.len) + "\n"
        out += "\t Checksum: " + str(udp.chksum) + "\n"
        return msg+out
    

    def httpString(self,pkt:Packet,sid:int):
        msg = ""
        msg += " Alert \n"
        msg += f"Rule Matched: {sid} \n"
        http = ApplHttp(pkt)
        headers = http.get_headers()
        out = "[HTTP Header] \n"
        for key, value in headers.items():
            out += f"{key}: {value}\n"
        msg += out

        return msg
    
    def tcpPayload(self,pkt:Packet,sid:int) -> str:
        """
        If this function is called then that means tcp payload was matched or had to be printed
        """
        msg = ""
        msg += " Alert \n"
        msg += f"Rule Matched: {sid} \n"
        if Raw in pkt:
            payload = pkt[Raw].load
            if isinstance(payload, bytes):
                try:
                    payload = payload.decode('utf-8', errors='ignore')
                except UnicodeDecodeError:
                    payload = str(payload)
            msg += payload
        else:
            msg += "No TCP payload found."

        return msg
    
    # def tcpPayload(pkt:Packet,sid:int) -> str:
    #     print("inside alert module")
    #     """
    #     If this function is called then that means tcp payload was matched or had to be printed
    #     """
    #     msg = ""
    #     msg += " Alert \n"
    #     msg += f"Rule Matched: {sid} \n"
    #     if Raw in pkt:
    #         payload = pkt[Raw].load
    #         if isinstance(payload, bytes):
    #             try:
    #                 payload = payload.decode('utf-8', errors='ignore')
    #                 print("printing stuff")
    #             except UnicodeDecodeError:
    #                 payload = str(payload)
    #         msg += payload
    #     else:
    #         msg += "No TCP payload found."

    #     return msg
    

    def udpPayload(self,pkt:Packet,sid:int) -> str:
        """ 
        If this function is called then udp payload was matched or had to be printed
        """
        msg = ""
        msg += " Alert \n"
        msg += f"Rule Matched: {sid} \n"
        if Raw in pkt:
            payload = pkt[Raw].load
            if isinstance(payload, bytes):
                try:
                    payload = payload.decode('utf-8', errors='ignore')
                except UnicodeDecodeError:
                    payload = str(payload)
            msg += payload
        else:
            msg += "No UDP payload found."

        return msg
    

    def httpBody(self,pkt:Packet,sid:int) -> str:
        """
        If this function is called then http body was needed or had to be printed
        """
        msg = ""
        msg += " Alert \n"
        msg += f"Rule Matched: {sid} \n"
        http = ApplHttp(pkt)
        body = http.get_payload()
        out = ""
        if body is not None:
            out = "[HTTP BODY] \n"
            msg += body + "\n"
        else:
            msg += "Empty Body \n"
        msg += out

        return msg


    
    


