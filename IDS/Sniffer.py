from threading import Thread
from scapy.all import *
from Rule import Rule
from logModules import log_packet

class Sniffer(Thread):
    """Thread responsible for sniffing and detecting suspect packet."""

    def __init__(self, ruleList:List[Rule], pcap_file=None):
        Thread.__init__(self)
        self.stopped = False
        self.ruleList = ruleList
        self.pcap_file = pcap_file

    def stop(self):
        self.stopped = True

    def stopfilter(self, x):
        return self.stopped

    def inPacket(self, pkt):
        """Directive for each received packet."""
        for rule in self.ruleList:
            matched = rule.match(pkt)

            if matched:
                action = rule.action
                if action.lower() == 'alert':
                    
                    messagetoAlert = rule.getEntireAlertMessage(pkt,rule.sid)
                    print("...............................................................................................")
                    print(messagetoAlert)
                    print("...............................................................................................")
                elif action.lower() == 'log':
                    log_packet(rule, pkt)
                elif action.lower() == 'block':
                    print("Action Under Construction")
                elif action.lower() == 'drop':
                    print("Action Under Construction")
                else:
                    print("Not a valid action")

    def run(self):
        print("Sniffing started.")
        # if self.pcap_file:
        # sniff(iface="eth0", prn=self.inPacket, store=0, stop_filter=self.stopfilter, session=TCPSession)
        # else:
        # pdb.set_trace()
        sniff(iface="wlan0", prn=self.inPacket, filter="", store=0, stop_filter=self.stopfilter, session=TCPSession)
