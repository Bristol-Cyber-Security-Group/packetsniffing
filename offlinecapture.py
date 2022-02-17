#!/usr/bin/env python3

import pyshark
from scapy.all import *


def packetcapture(pkt):


	wrpcap('rephrain-1.pcap', [pkt], append=True)


sniff(prn=packetcapture)
