from scapy.all import sniff, IP, TCP, Raw,scapy,conf,get_if_addr
localip = get_if_addr(conf.iface)
trapports = (333,443,80,22,23,26,30,118,113)	
def sys(packet):
	
	if packet.haslayer(IP):
		
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
				
			elif flags == 2 and not packet[TCP].options :
				return "empty TCP options!!"
			
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
