from scapy.all import sniff, IP, TCP, Raw,scapy
def nullscan(packet):
	if packet.haslayer(TCP):
		if int(packet[TCP].flags) == 0:
			return  "\033[1;31malert\033[0m"
		else:
			return"\033[1;31msafe\033[0m"
