from scapy.all import *
from sys import argv
import datetime


import RuleFileReader as RuleFileReader
from Sniffer import *

RED = '\033[91m'
BLUE = '\033[34m'
GREEN = '\033[32m'
ENDC = '\033[0m'

def main():
    """Read the rule file and start listening."""



    print("Simple-NIDS started.")
    # Read the rule file
    print("Reading rule file...")
    ruleList = RuleFileReader.read_all_rules("rules")
    print("Finished reading rule file.")
    sniffer = Sniffer(ruleList)
    sniffer.start()

main()
