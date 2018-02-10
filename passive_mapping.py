import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

from libnmap.process import NmapProcess
from libnmap.parser import NmapParser

addressList = [] # Will contain the list of found IP addresses

def readPacket(pkt):
        if pkt.haslayer(IP): # If our packet has an IP layer
            IPaddress = pkt[IP].src # get IP address (located in IP layer)
            MACaddress = pkt[Ether].src # get MAC address (located in Ether Layer)

            if IPaddress not in addressList:    # Then If IP never found before
                addressList.append(IPaddress) # Add to our list
                print('\n[+] ' + str(pkt.summary()))
                print ('[+] Host Found\nMAC: ' + MACaddress + ' | IP: '+ IPaddress) # Print characteristics

def list(addressList): 
    return readPacket(pkt)

while True:
        try:
                print('[+] Listening... \n')
                sniff(prn=list(addressList)) # Sniff any type of packet, send each of them to readPacket()
        except KeyboardInterrupt:
                break

for hostname in addressList:
        nmproc = NmapProcess(hostname, "-sV")
        rc = nmproc.run()
        parsed = NmapParser.parse(nmproc.stdout)
        host = parsed.hosts[0]
        services = []
        cracked = False
        for serv in host.services:
                services.append(str(serv.port) + "/" + str(serv.service))
        
        print(host)
        print(services)
