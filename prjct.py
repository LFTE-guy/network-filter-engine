from scapy.all import scapy,IP,sniff,TCP, UDP, ARP, Ether
print("welcome to ali filter")
SHOW_TTL = input("ttl?:")
target_ip = input("target IP:")
target_port = input("target port:")
target_prot= input("protocol(TCP,UDP,ARP...:)")
def showttl(packet):
	if SHOW_TTL == "y":
		return packet[IP].ttl
	else:
		pass
if target_ip:
	Y = (f"host {target_ip}")
else:
	Y= ("")
if target_port:
	X = (f"port {target_port}")
else:
	X = ("")
if target_prot:
	Z =(f"{target_prot}")
else:
	Z =("")
active_rules = [rule for rule in [Z, X, Y] if rule]
filterA = " and " .join(active_rules)
def flagging(packet):
	flag = int(packet[TCP].flags)
	if flag == 2:
		print(f"\033[1;32m[+] NEW CONNECTION REQUEST (SYN)\033[0m")
	elif flag == 18:
		print(f"\033[1;35m[+] HANDSHAKE RESPONSE (SYN-ACK)\033[0m")
	elif flag == 16:
		print(f"\033[0;32m[+] PACKET ACKNOWLEDGED (ACK)\033[0m")
	elif flag == 8:
		print(f"\033[0;36m[*] DATA PUSHED TO APP (PSH)\033[0m")
	elif flag == 24:
		print(f"\033[1;36m[*] ACTIVE DATA STREAM (PSH-ACK)\033[0m")
	elif flag == 1:
		print(f"\033[1;33m[-] CONNECTION FINISHED (FIN)\033[0m")
	elif flag == 17:
		print(f"\033[1;33m[-] TEARDOWN ACKNOWLEDGED (FIN-ACK)\033[0m")
	elif flag == 64:
		print(f"\033[0;33m[!] CONGESTION NOTIFICATION (ECE)\033[0m")
	elif flag == 128:
		print(f"\033[0;33m[!] CONGESTION WINDOW REDUCED (CWR)\033[0m")
	elif flag == 4:
		print(f"\033[1;31m[!] CONNECTION RESET | ABORTED (RST)\033[0m")
	elif flag == 20:
		print(f"\033[1;31m[!] CONNECTION RESET ACKNOWLEDGED (RST-ACK)\033[0m")
	elif flag == 32:
		print(f"\033[1;31m[!] URGENT DATA POINTER (URG)\033[0m")
def inspect(packet):
	if packet.haslayer(IP):
		srcip = packet[IP].src
		dstip = packet[IP].dst
		if packet.haslayer(TCP) and showttl != "y":
			print(f"\033[1;34m[+]|{srcip}:{packet[TCP].sport}|\033[1;34m      -------->      \033[1;33m|{dstip}:{packet[TCP].dport}|TTL:{showttl(packet)}| on TCP\033[1;33m")
			flagging(packet)
		elif packet.haslayer(UDP):
			print(f"\033[0;36m[+]|{srcip}:{packet[UDP].sport}|      -------->      |{dstip}:{packet[UDP].dport}|  on UDP\033[0;36m")
		
sniff(prn=inspect, store=0, iface="wlan0", count=1000000, filter=filterA)
