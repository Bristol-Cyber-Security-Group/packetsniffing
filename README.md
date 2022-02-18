# packetsniffing
There are three files, the livecapture will capture packets and give the output in a csv file with IP address, reverse DNS and protocol
The offline capture is a simple sniffing. 
The readpcap.py will read pcap files and output a csv file with source destination, protocol, size and hostname of the destination
There are duplicates as of now.

sudo apt install python3-autopep8 <br/>
autopep8 -i <script>.py<br/>
sudo apt-get install python3-pandas<br/>

installing pyshark <br/>
git clone https://github.com/KimiNewt/pyshark.git<br/>
cd pyshark/src <br/>
sudo python3 setup.py install <br/>
sudo apt-get install tshark <br/>

installing scapy <br/>
git clone https://github.com/secdev/scapy.git <br/>
cd scapy <br/>
sudo python3 setup.py install <br/>

git clone git@github.com:matplotlib/matplotlib.git <br/>
cd matplotlib <br/>
python3 -m pip install -e <br/>

Running<br/>
chmod +x <script>.py<br/>
sudo ./<script>.py<br/>


