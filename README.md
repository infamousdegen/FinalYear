# Todo List

- [ ] Identify Https Packet
- [x] Figure out how to decrypt TLS packets
- [ ] Create Drop (Need to check how to differentiate between 'allowing' a whitelisted packet and 'dropping' a blacklisted packet)
- [ ] Create Block (Implemented sending back ICMP packet) (Need to check how to differentiate between 'allowing' a whitelisted packet and 'dropping' a blacklisted packet)
- [ ] Create classes for PORT AND ACTION module 
- [ ] Make PORT parsing better 
- [ ] Content matching based on the HTTP/HTTPS packet content
- [ ] the packets.py matches http packets based on port number get a better way to do it (solution = https://github.com/secdev/scapy/issues/2218)
- [ ] https://github.com/the-tcpdump-group/libpcap (might have to move to raw accessing of the packets using libpcap)