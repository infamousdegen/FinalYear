from threading import Thread
from scapy.all import *
from Rule import *
from alertModules import *
from logModules import *

class Sniffer(Thread):
    """Thread responsible for sniffing and detecting suspect packet."""

    def __init__(self, ruleList):
        Thread.__init__(self)
        self.stopped = False
        self.ruleList = ruleList

    def stop(self):
        self.stopped = True

    def stopfilter(self, x):
        return self.stopped

    def inPacket(self, pkt):
        """Directive for each received packet."""
        # print(pkt)


        for rule in self.ruleList:

            matched = rule.match(pkt)
            if (matched):
                print(matched)
                action = rule.action
                if action.lower() == 'alert':
                    print(alert(pkt,rule.sid))
                elif action.lower() == 'log':
                    log_packet(rule,pkt)
                elif action.lower() == 'block':
                    print("Action Under Construction")
                elif action.lower() == 'drop':
                    print("Action Under Construction")
                else:
                    print("Not a valid action")


    def run(self):
        print("Sniffing started.")
        sniff( iface="lo",prn=self.inPacket, filter="", store=0, stop_filter=self.stopfilter)
 