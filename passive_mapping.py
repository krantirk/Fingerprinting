import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

addressList=[] # Will contain the list of found IP addresses

def list(addressList): 

	def readPacket(pkt):

		if pkt.haslayer(IP): # If our packet has an IP layer
			IPaddress = pkt[IP].src # get IP address (located in IP layer)
			MACaddress = pkt[Ether].src # get MAC address (located in Ether Layer)

			if IPaddress not in addressList: 	# Then If IP never found before
				addressList.append(IPaddress) # Add to our list
				print('[+] ' + str(pkt.summary()))
				print ('\n[+] Host Found\nMAC: ' + MACaddress + ' | IP: '+ IPaddress) # Print characteristics

	return readPacket

print('[+] Listening... \n')
sniff(prn=list(addressList)) # Sniff any type of packet, send each of them to readPacket()
