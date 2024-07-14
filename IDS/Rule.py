from ipDetection import checkIp
from protocolDetection import *
from payloadDetection import *
from applicationLayerDetection import *
import pdb
from HTTP import ApplHttp
class Rule:
    #Assumptions that all validation for the rules has taken place and rules are as specified in the schema
    """ NIDS RULE """

    def __init__(self,data):
        """Below mentioned are mandatory"""

        self.action = data["ruleHeader"]["action"]
        #FIX THIS , IT IS NOT NECESSARY THAT TRANSPORT LAYER HAS TO BE PRESENT 
        self.protocol = data["ruleHeader"]["protocols"]
        self.sourceIP = data["ruleHeader"]["sourceIP"]
        self.destinationIP = data["ruleHeader"]["destinationIP"]
        self.sourcePort = data["ruleHeader"]["sourcePort"]
        self.destinationPort = data["ruleHeader"]["destinationPort"]
        self.direction = data["ruleHeader"]["direction"]
        self.sid = data["ruleHeader"]["sid"]

        #It will be a dict of ruleoptions(these are optional)
        self.ruleOptions = data.get("ruleOptions",None)

        self.applicationLayer = data.get["ruleHeader"].get("applicationlayer",None)



    
    def match(self,pkt) -> bool:
        """
        Return True if and only if everything in the the provided rule matches or else it will return False
        """

        #ApplicationLayer 
        ''''
        Only check Applicaiton layer if the  rule has applicationLayer 
        '''
        if self.applicationLayer is not None:
            '''
            Current only implemented HTTP for application layer 
            '''
            # Check whether the given pkt has the application layer mention in the pkt 
            if not checkApplicationProtocol(self.applicationLayer,pkt): return False
            #Check whether any rule option exist , 
            # like checking for payload or checking for headers and whether the given header and the packet matches
            #Only support application layer is HTTP for now 

            if self.applicationLayer.lower() == 'http':
                http = ApplHttp(pkt)
                
                #This means that application the provided application layer is http and thus check all matching rule options 
                #such as http headers , payload 

                httpheader = self.ruleOptions.get("httpHeaders",None)
                httpbody = self.ruleOptionsl.get("httpBody",None)
                if httpheader is not None:
                    #Assumption if httpheader is present in rule options then a header name with some value will be provided
                    
                    pktheader = http.get_headers()
                    ruleheaderName = httpheader.get("headerName")
                    ruleheaderValue = httpheader.get("headerValue")

                    if ruleheaderName not in pktheader or pktheader[ruleheaderName] != ruleheaderValue: return False
                
                #Assumption that if the httpbody key exist then there will be either content or regex matching request 
                if httpbody is not None:
                    #Get whether the httpbody wants for content matching or regex matching 
                    pktpayload = http.get_payload()
                    if pktpayload is None: return False

                    content = httpbody.get("content", None)
                    regex = httpbody.get("regex", None)

                    #If it is content matching then match for exact content
                    if content is not None and content != pktpayload: return False
                    if regex is not None and not re.search(regex, pktpayload): return False



        #Transport Layer
        '''
        Assumption that transport layer will  be present 
        Note: Assumption is wrong fix it later 
        '''

        if(not checkProtocol(self.protocol,pkt)): return False

        #For now only thing to match is payload , whether it maybe the TCP or UDP

        #Matches PAYLOAD  

        if self.ruleOptions is not None:
            payload = self.ruleOptions.get("payloadDetectionRules",None)
            content = payload.get("content",None)
            regex = payload.get("regex",None)

            if content is not None and content != pktpayload: return False
            if regex is not None and not re.search(regex, pktpayload): return False


        #Matches PORT on the Transport Layer 
        #PUT MANOMITHRANS CODE HERE 


        #Network Layer

        '''
        Assumption there will be IP's 
        Note: Assumption is wrong , not sure whether we have to go even lower layer where IP's are not present 
        '''
        # In the Network Layer only focusing on IP not other fields as of now
        if not checkIp(self.sourceIP,self.destinationIP,pkt): return False

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
        
