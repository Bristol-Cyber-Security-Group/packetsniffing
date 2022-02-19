#!/usr/bin/env python3

import socket
from struct import pack
import pyshark
import csv
from scapy.all import *


def readcap(packet):
    # print(packet)
    # return
    with open("csvfrommessages.csv", "a", encoding="UTF8") as f: # change file name

        writer = csv.writer(f)

        try:

            if ARP in packet and packet[ARP].op in (1, 2):  # who-has or is-at

                row = [packet[ARP].hwsrc, packet[ARP].psrc, 0, 0 ,0]

                writer.writerow(row)

            else:
                dstName = socket.gethostbyaddr(packet[IP].dst)
                rows = [packet[IP].src, packet[IP].dst,
                    dstName, packet[IP].proto, packet[IP].len]
                writer.writerow(rows)

        except Exception as e:
            #print(e)
            # print("==================", ARP in packet)
            pass



cap = sniff(offline = 'messages.pcapng', prn=readcap) # change file name
