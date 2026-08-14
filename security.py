from scapy.all import sniff, IP, TCP, Raw,scapy,conf,get_if_addr
from layout import colors
localip = get_if_addr(conf.iface)
trapports = (333,443,80,22,23,26,30,118,113)
anomlyflags= (0,1,41,3)
def sys(packet):
	nwindow = packet[TCP].window
	if packet.haslayer(IP) and packet.haslayer(TCP):
		if packet[IP].flags.MF == 1 or packet[IP].frag > 0 :
				return("fragmentation detected!!")
		flags = int(packet[TCP].flags)
		for name, value in packet[TCP].options:
			if name == "MSS" and value <= 1024 and nwindow <= 4096:
				return("MSS and window size anomly!!")
		
		if flags in anomlyflags :
			return  (f"{colors.RED}SCAN ALERT - we are being scanned{colors.END}")
				
		elif flags in (32,4,2) and len(packet[TCP].payload) > 0:
			return("payload+flag anomly!!")
			
			
		elif flags == 2 and not bool(packet.options) and nwindow <= 4096  :
			return ("syn without options!!- likely a scan")
			
		elif packet[IP].dst == localip:	
				
			trapports = (333,443,80,22,23,26,30,118,113)	
				
			if packet[TCP].dport in trapports:
					
				return("TRAP PORT PROBED")
					
			else: 
				return("Normal")
		else:
			return"Normal"
	else:
		return("Normal")
def ntcpsys(packet):
	if packet.haslayer(IP):
		if packet[IP].flags.MF == 1 or packet[IP].frag > 0 :
				return("fragmentation detected!!")
		else:
			return("normal")
	else:
		return("test")
