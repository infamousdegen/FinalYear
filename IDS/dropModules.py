import iptc 
    
def drop(ruleobj,pkt):
    #if pkt.haslayer(Raw) and b"get lost" in pkt[Raw].load:
    if pkt[IP].src == "127.0.0.1":
        print(f"Dropping packets from {pkt[IP].src}")
        rule = iptc.Rule()
        rule.src = ruleobj.sourceIP
        if ruleobj.destinationIP:
            rule.dst = ruleobj.destinationIP
        if ruleobj.protocol:
            rule.protocol = ruleobj.protocol
        rule.target = rule.create_target("DROP")
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
        chain.insert_rule(rule)
            
    return f"Droped packet from {pkt[IP].src}"
    
"""

    This rule is written to drop a http request  form 192.168.1.1 to 192.168.1.2 in various_packets.pcap
    rule = iptc.Rule()
    rule.src = "192.168.1.1"
    rule.dst = "192.168.1.2"
    rule.protocol = "tcp"

    rule.target = rule.create_target("DROP")

    tcp_match = rule.create_match("tcp")
    tcp_match.dport = "80"
    tcp_match.sport = "1024:65535"

    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    chain.insert_rule(rule)

    """

    
