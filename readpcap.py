#!/usr/bin/env python3

import socket
from struct import pack
import pyshark
import csv
import json
from scapy.all import *
import urllib.request as ur
import pandas as pd
import gmplot
import numpy as np
import sys

def readcap(packet):
    load_layer('tls')
    with open(sys.argv[1], "a", encoding="UTF8") as f:  
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
                    rows = [packet[IP].src, packet[IP].sport, packet[IP].dst, packet[IP].dport,
                            dstName, packet[IP].proto, packet[IP].len, packet[IP].tos, data['country_name']]
                    writer.writerow(rows)

        except Exception as e:
           # print(e)
            pass

def addheaders():

    file = pd.read_csv(sys.argv[1])
    headerList = ['Source', 'Port', 'Destination', 'Port', 'Name', 'Protocol', 'Length', 'Service', 'Country']
    file.to_csv(sys.argv[1], header=headerList, index=False)


def uniqueipandmap():
    file = pd.read_csv(sys.argv[1])  # Please insert the csv file
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
        gmap = gmplot.GoogleMapPlotter(Latitude[0], Longitude[0], 5)
        gmap.scatter(Latitude, Longitude, colors[0], edge_width=10)
        gmap.polygon(Latitude, Longitude, color='cornflowerblue')
        gmap.apikey = "Please Ask Me"
        gmap.draw("map.html")
    except Exception as e:
        #print(e)
        pass


cap = sniff(offline= sys.argv[2], prn=readcap)  
b = addheaders()
c = uniqueipandmap()
