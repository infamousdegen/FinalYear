from scapy.all import *
import re


def checkPayload(payloadOptions, pkt):
    payload = None

    if pkt.haslayer(TCP):
        payload = pkt[TCP].payload
    elif pkt.haslayer(UDP):
        payload = pkt[UDP].payload

    if isinstance(payload, NoPayload):
        return False

    content = payloadOptions.get("content", None)
    pattern = payloadOptions.get("regex", None)

    if content is not None:
        if isinstance(payload, Raw):
            return content.encode("utf-8") == payload.load

    elif pattern is not None:
        decoded = bytes(payload).decode('UTF-8','replace')
        try:
            match = re.search(pattern,decoded)
            if match:
                return True
        except re.error as e:
            print("Error occurred while searching:", e)
    return False
