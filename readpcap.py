#!/usr/bin/env python3

import socket
import pyshark
import csv
from scapy.all import *


def readcap(packet):
    try:
        source_address = packet.ip.src
        source_port = packet[packet.transport_layer].srcport
        destination_address = packet.ip.dst
        destination_port = packet[packet.transport_layer].dstport
        packetlength = len(packet)
        # if ARP in packet and packet[ARP].op in (1, 2):  # who-has or is-at
        #   print("The ARP Hardware Source is {} and address is {} \n".format(
        #      packet[ARP].hwsrc, packet[ARP].psrc))
        # else:
        dstName = socket.gethostbyaddr(packet.ip.dst)
        # packetlength = len(packet)
        with open("excelfrommyregistration.csv", "a", encoding="UTF8") as f:
            writer = csv.writer(f)
        # f = open("reversednsv4.txt", "a")
            row = [packet.ip.src, packet.ip.dst,
                   dstName, packet.ip.proto, packet.ip.len]
            writer.writerow(row)
        # return (f'{protocol} {source_address}:{source_port} --> {destination_address}:{destination_port}{dstName}{packetlength}')
    except AttributeError as e:
        pass


cap = pyshark.FileCapture('registration.pcapng')
res = []
for packet in cap:
    lists = readcap(packet)
    if lists != None:
        res.append(lists)
