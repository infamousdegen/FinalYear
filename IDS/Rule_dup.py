import sys


from ipAndPortDetection import *
from protocolDetection import *
from payloadDetection import *
class Rule:
    #Assumptions that all validation for the rules has taken place and rules are as specified in the schema
    """ NIDS RULE """

    def __init__(self,data):
        """Below mentioned are mandatory"""

        self.action = data["ruleHeader"]["action"]
        self.protocol = data["ruleHeader"]["protocols"]
        self.sourceIP = data["ruleHeader"]["sourceIP"]
        self.destinationIP = data["ruleHeader"]["destinationIP"]
        self.sourcePort = data["ruleHeader"]["sourcePort"]
        self.destinationPort = data["ruleHeader"]["destinationPort"]
        self.direction = data["ruleHeader"]["direction"]
        self.sid = data["ruleHeader"]["sid"]

        #It will be a dict of ruleoptions(these are optional)
        self.ruleOptions = data.get("ruleOptions",None)



    
    def match(self,pkt):

        #check protocol
        if(not checkProtocol(self.protocol,pkt)):
            print("inside checkprotocol")
            return False
        
        #check Ip and port
        if(not checkIpAndPort(self.sourceIP,self.destinationIP,self.sourcePort,self.destinationPort,self.direction,pkt)):
            print("inside checkIp")
            return False

        payloadOptions = self.ruleOptions.get("payloadDetectionOptions",None)
        if(payloadOptions):
            if(not checkPayload(payloadOptions,pkt)):
                return False

        return True

        
    def getMessageToPrint(self):
        msg = self.ruleOptions.get("generalOptions",None).get("msg",None)
        if msg:
            return msg
        return False


    # def getMatchLogMessage(self):
    #     return msg
    
    # def getMatchedPrintMessag(self):
    #     return msg
        
