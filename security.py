from scapy.all import sniff, IP, TCP, Raw,scapy,conf,get_if_addr
localip = get_if_addr(conf.iface)
trapports = (333,443,80,22,23,26,30,118,113)
anomlyflags= (0,1,41,3)	
def sys(packet):
	
	if packet.haslayer(IP):
		for name, value in packet[TCP].options:
				if name == "MSS" and value == 1024:
					return("MSS anomly!!")
		if packet.haslayer(TCP):
			flags = int(packet[TCP].flags)
			
			
			if flags in anomlyflags :
				return  (f"SCAN ALERT - we are being scanned")
			elif flags == 2 and not bool(packet.options):
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
	else:
		return("Normal")
