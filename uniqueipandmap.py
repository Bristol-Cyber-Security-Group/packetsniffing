#!/usr/bin/env python3

import pandas as pd
import urllib.request as ur
import json
import csv
import socket
import gmplot
import numpy as np

file = pd.read_csv("name.csv") #Please insert the csv file
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
            print(e)
            pass
    gmap = gmplot.GoogleMapPlotter(Latitude[0],Longitude[0], 5)
    gmap.scatter(Latitude,Longitude, colors[0], edge_width=10)
    gmap.polygon(Latitude, Longitude, color = 'cornflowerblue')
    gmap.apikey = "Please Ask Me For The Key"
    gmap.draw("map.html")
except Exception as e:
  print(e)  
  pass

