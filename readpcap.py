#!/usr/bin/env python3

import socket
from struct import pack
import pyshark
import csv
import json
from scapy.all import *
import urllib.request as ur


def readcap(packet):
    load_layer('tls')
    with open("csvfrommessages.csv", "a", encoding="UTF8") as f:  # change file name
        writer = csv.writer(f)
        try:
             if ARP in packet and packet[ARP].op in (1, 2):
               row = [packet[ARP].hwsrc, packet[ARP].psrc, 0, 0, 0, 0]
               writer.writerow(row)

             else:
                    dstName = socket.gethostbyaddr(packet[IP].dst)
                    with ur.urlopen("https://geolocation-db.com/jsonp/"+packet[IP].dst) as url:
                        data = url.read().decode()
                        data = json.loads(data.split("(")[1].strip(")"))
                        rows = [packet[IP].src, packet[IP].sport, packet[IP].dst,packet[IP].dport, 
                                dstName, packet[IP].proto, packet[IP].len, packet[IP].tos, data['country_name']] 
                        writer.writerow(rows)

        except Exception as e:
           #print(e)
          pass


cap = sniff(offline='messages.pcapng', prn=readcap)  # change file name

# cap = sniff(offline='messages.pcapng', prn=readcap)
