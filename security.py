from scapy.all import sniff, IP, TCP, Raw,scapy
from scapy.all import sniff, IP, TCP, Raw,scapy
def scan(packet):
	if packet.haslayer(TCP):
		flags = int(packet[TCP].flags)
		if flags == 0:
			return  "\033[1;31mNULL SCAN ALERT\033[0m"
		elif flags == 1:
			return"\033[1;31m ILLEGAL FIN SCAN ALERT\033[0m"
		elif flags == 41:
			return"\033[1;31m XMAS SCAN ALERT\033[0m"
		elif flags == 3:
			return"\033[1;31m SYN-FIN SCAN ALERT\033[0m"
		else:
			return("Normal")
