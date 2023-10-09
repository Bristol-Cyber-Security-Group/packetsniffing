#!/usr/bin/env python3

import socket
from struct import pack
import pyshark
import csv
import json
from scapy.all import *
import urllib.request as ur
import pandas as pd
import sys
from datetime import datetime
load_layer('tls')
IP_PROTOS = load_protocols("/etc/protocols")

packet_counter = 0
headerList = ['Source', 'SrcPort', 'Destination', 'DstPort', 'Name', 'Protocol', 'Length', 'Service', 'Country', 'Time']
report_headers = ["Destination IP", "Name", "Country"]


def readcap2(pcap):
    global packet_counter
    with open(sys.argv[2], "a", encoding="UTF8") as f:
        writer = csv.writer(f)
        for pp in pcap:
            try:

                packet_time = datetime.fromtimestamp(pp.time)
                ip_layer = pp.getlayer(IP)
                dns_layer = pp.getlayer(DNS)

                if ip_layer is None and dns_layer:
                    # no ip layer, probably local DNS
                    # print(pp)
                    # dns_layer = pp.getlayer(DNS)

                    try:
                        hostname = socket.gethostbyaddr(pp.dst)
                    except:
                        hostname = ""

                    row = [pp.src,pp.sport,pp.dst,pp.dport,hostname,pp.lastlayer().name,pp.len,"","",packet_time]

                elif ip_layer is None and dns_layer is None:
                    # no or dns, probably ARP or PADDING
                    row = [pp.src, "", pp.dst, "", "", pp.lastlayer().name, "", "", "",packet_time]

                else:
                    # has ip layer
                    try:
                        hostname = socket.gethostbyaddr(ip_layer.dst)
                    except:
                        hostname = ""

                    row = [ip_layer.src,ip_layer.sport,ip_layer.dst,ip_layer.dport,hostname,ip_layer.proto,ip_layer.len,ip_layer.tos,"",packet_time]
                    # print(row)

                writer.writerow(row)

            except Exception as e:
                print(e, pp.layers(), pp.lastlayer().name)
                # last ditch to add something
                packet_time = datetime.fromtimestamp(pp.time)
                row = [pp.src, "", pp.dst, "", "", pp.lastlayer().name, "", "", "", packet_time]
                writer.writerow(row)
            packet_counter += 1


def addheaders():
    file = pd.read_csv(sys.argv[2])
    file.to_csv(sys.argv[2], header=headerList, index=False)


def get_location(in_ip):
    try:
        with ur.urlopen("https://geolocation-db.com/jsonp/" + in_ip) as url:
            data = url.read().decode()
            data = json.loads(data.split("(")[1].strip(")"))
            # return float(data['latitude']), float(data['longitude'])
            return data['country_name']
    except Exception as e:
        # could not get location
        return None


def unique_report():
    # read the output csv from the processed pcap
    processed_pcap_csv = pd.read_csv(sys.argv[2])
    grouped = processed_pcap_csv.groupby(["Destination"]).count()
    # create a report dataframe that will be filled with data from the unique dataframe
    # and a location lookup
    # report = pd.DataFrame(columns=report_headers)
    new_rows = []
    for row in grouped.index:

        # get one of the rows for that destination based on the unique ip
        unique_row = processed_pcap_csv[processed_pcap_csv["Destination"] == row].iloc[0]
        # get hostname, could be NaN TODO: a different lookup for hostname
        hostname = unique_row["Name"]
        # get location as a tuple or None
        # if is a mac address then skip
        if ":" in row:
            print("skipped a mac address", row)
            location = None
        else:
            location = get_location(row)

        new_rows.append({
            "Destination IP": row,
            "Name": hostname,
            "Country": location,
        })
    report = pd.DataFrame(new_rows, columns=report_headers)
    report.to_csv("report_"+sys.argv[2], index=False)


# TODO - any optimisations possible, even 10k packets from a few seconds capture takes a while
#      - potentially skip the payloads by using "IP.payload_guess = []"
#      - consider using PcapReader rather than rdpcap
#      - consider using PyPy to speed up the runtime?
#      - consider parsing the pcap file without scapy... tshark directly with filters or compiled language
# TODO - address the deprecation warnings
# TODO - local ip addresses and mac addresses are present, may not be relevant for some analysis - option to remove?


# create an empty csv for the scapy output
f = open(sys.argv[1], "a")
f.close()

cap = rdpcap(sys.argv[1])
readcap2(cap)
print("n packets processed =", packet_counter)
addheaders()

# create the report of unique ips
print("creating report...")
unique_report()

