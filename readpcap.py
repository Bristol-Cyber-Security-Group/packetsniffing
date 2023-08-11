#!/usr/bin/env python3

import socket
from struct import pack
import pyshark
import csv
import json
from scapy.all import *
import urllib.request as ur
import pandas as pd
# import gmplot
import numpy as np
import sys
from datetime import datetime
load_layer('tls')
IP_PROTOS = load_protocols("/etc/protocols")

packet_counter = 0

# def readcap(packet):
#     global packet_counter
#     with open(sys.argv[2], "a", encoding="UTF8") as f:
#         writer = csv.writer(f)
#         packet_counter += 1
#         try:
#             delta = datetime.fromtimestamp(packet[IP].time) - datetime(2023, 6, 23, 10, 28, 17)
#             actual_time = datetime.fromtimestamp(packet[IP].time) - delta
#             print(datetime.fromtimestamp(packet[IP].time), "-", datetime(2023, 6, 23, 10, 28, 17), "delta =", delta, actual_time, actual_time)
#             if ARP in packet and packet[ARP].op in (1, 2):
#                 row = [packet[ARP].hwsrc, packet[ARP].psrc, 0, 0, 0, 0]
#                 writer.writerow(row)
#
#             else:
#                 dstName = socket.gethostbyaddr(packet[IP].dst)
#                 with ur.urlopen("https://geolocation-db.com/jsonp/"+packet[IP].dst) as url:
#                     data = url.read().decode()
#                     data = json.loads(data.split("(")[1].strip(")"))
#                     rows = [packet[IP].src, packet[IP].sport, packet[IP].dst, packet[IP].dport,
#                             dstName, packet[IP].proto, packet[IP].len, packet[IP].tos, data['country_name'], actual_time]
#                     writer.writerow(rows)
#
#         except Exception as e:
#             print(e)
#             pass


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


def get_ip_hostnames(packet_csv):
    # to save time
    # get all unique dst ip addresses, then ping the geolocation site
    # then insert the geolocation for each unique ip
    pass


def addheaders():

    file = pd.read_csv(sys.argv[2])
    headerList = ['Source', 'Port', 'Destination', 'Port', 'Name', 'Protocol', 'Length', 'Service', 'Country', 'Time']
    file.to_csv(sys.argv[1], header=headerList, index=False)


def uniqueipandmap():
    file = pd.read_csv(sys.argv[2])  # Please insert the csv file
    colors = ['red', 'blue', 'green', 'purple',
              'orange', 'yellow', 'pink', 'white']
    Latitude = []
    Longitude = []
    try:
        file2 = pd.DataFrame(file.groupby(['Destination']).count())
        for i in file2.index:
            try:
                with ur.urlopen("https://geolocation-db.com/jsonp/"+i) as url:
                    data = url.read().decode()
                    data = json.loads(data.split("(")[1].strip(")"))
                    dstname = socket.gethostbyaddr(i)
                    print(i, dstname, data['country_name'])
                    Latitude.append(float(data['latitude']))
                    Longitude.append(float(data['longitude']))
            except Exception as e:
                #print(e)
                pass
        # gmap = gmplot.GoogleMapPlotter(Latitude[0], Longitude[0], 5)
        # gmap.scatter(Latitude, Longitude, colors[0], edge_width=10)
        # gmap.polygon(Latitude, Longitude, color='cornflowerblue')
        # gmap.apikey = "Please Ask Me"
        # gmap.draw("map.html")
    except Exception as e:
        #print(e)
        pass

# TODO - add unique location ip code here, dont need to save the intermediate

# adding headers
# b = addheaders()
# reading packet capture
# cap = sniff(offline= sys.argv[1], prn=readcap)
cap = rdpcap(sys.argv[1])
readcap2(cap)
# builds map but disabled since we dont need the map and dont use the google api
# c = uniqueipandmap()

print("n packets =", packet_counter)
