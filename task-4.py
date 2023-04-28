#!/usr/bin/python
from scapy.all import *

# Variables
client_ip = '10.0.2.17'
server_ip = '10.0.2.18'
attacker_ip = '10.0.2.19'

# DNS Query Section
Qdsec = DNSQR(qname='www.example.com')

# DNS Header
dns = DNS(id=0xAAAA, qr=0, qdcount=1, ancount=0, nscount=0, arcount=0, qd=Qdsec)

# IP Header
ip = IP(dst=server_ip, src=client_ip)

# UDP Header
udp = UDP(dport=53, sport=33333, chksum=0)

# Complete Request
request = ip/udp/dns

# Send the request
send(request)