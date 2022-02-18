#!/usr/bin/env python3

import sys
import socket
import errno
import json
import csv
from scapy.all import *
#from scapy.layers.dns import DNS, DNSQR, DNSRR, IP, UDP
#from scapy.sendrecv import sr1

# def reverse(ip):
# if len(ip) <= 1:
# return ip
# return '.'.join(ip.split('.')[::-1])


def reverse_dns_name(pkt):
    #hostname=sr1(IP(dst="8.8.8.8")/UDP()/DNS(rd=1,qd=DNSQR(qname="hostName.in-addr.arpa", qtype='PTR')))
    headernames = ["Source","Destination", "Name", "Protocol"]
    f = open("reversedns.txt", "a")
    if ARP in pkt and pkt[ARP].op in (1, 2):  # who-has or is-at
        f.write("The ARP Hardware Source is {} and address is {} \n".format(
            pkt[ARP].hwsrc, pkt[ARP].psrc))
    else:
        dstName = socket.gethostbyaddr(pkt[IP].dst)
        e = socket.herror
        if e.errno == 1:
            print('IP address has no DNS record \n')
        elif e.errno == 2:
            print('DNS server is temporarily unavailable \n')
        else:
            with open("livecapture.csv", "a", encoding="UTF8") as f:
            	writer = csv.writer(f)
        #f = open("reversednsv4.txt", "a")
            	row = [pkt[IP].src, pkt[IP].dst,
                   dstName, pkt[IP].proto]
            	writer.writerow(row)
            # f.write("IP address {} Host Name {} Protocol {}\n".format(
            # pkt[IP].dst, hostName, pkt[IP].proto))
        #f = open("detailedreportv1.txt", "a")
        # f.write("\n"''.join((pkt.show2(dump=True).split('\n'))))


sniff(prn=reverse_dns_name)
