from scapy.all import *
def alert(pkt,sid):
    msg = ""
    msg += " ALERT \n"
    msg += f"Rule Matched: {sid} \n"
    ip = pkt[IP]
    print(ip)
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