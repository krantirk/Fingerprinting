import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

adressList=[] # Will contain the list of found IP addresses

def list(adressList): 

	def readPacket(pkt):

		if pkt.haslayer(IP): # If our packet has an IP layer
			IPadress = pkt[IP].src # get IP adress (located in IP layer)
			MACadress = pkt[Ether].src # get MAC adress (located in Ether Layer)

			if IPadress not in adressList: 	# Then If IP never found before
				adressList.append(IPadress) # Add to our list
				print ('[+] Host Found\nMAC: ' + MACadress + ' | IP: '+ IPadress + '\n') # Print caracteristics

	return readPacket

print('[+] Listening... \n')
sniff(prn=list(adressList)) # Sniff any type of packet, send each of them to readPacket()