from scapy.all import sniff,TCP,IP
def flaggingz(packet):
	flag = int(packet[TCP].flags)
	if flag == 2:
		return(f"\033[1;32m(SYN)\033[0m")
	elif flag == 18:
		return(f"\033[1;35m(SAK)\033[0m")
	elif flag == 16:
		return(f"\033[0;32m(ACK)\033[0m")
	elif flag == 8:
		return(f"\033[0;36m(PSH)\033[0m")
	elif flag == 24:
		return(f"\033[1;36m(PCK)\033[0m")
	elif flag == 1:
		return(f"\033[1;33m(FIN)\033[0m")
	elif flag == 17:
		return(f"\033[1;33m(FCK)\033[0m")
	elif flag == 64:
		return(f"\033[0;33m(ECE)\033[0m")
	elif flag == 128:
		return(f"\033[0;33m(CWR)\033[0m")
	elif flag == 4:
		return(f"\033[1;31m(RST)\033[0m")
	elif flag == 20:
		return(f"\033[1;31m(RCK)\033[0m")
	elif flag == 32:
		return(f"\033[1;31m(URG)\033[0m")
	else:
		return packet[TCP].flags
