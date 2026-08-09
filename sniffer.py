from scapy.all import scapy,IP,sniff,TCP, UDP, ARP, Ether,Raw,hexdump,ICMP,packet
from security import *
from flagging import flaggingz
import time
print("\033[1;32m┌──────────────────────────────────────────────────────────┐\033[0m")
print("\033[1;32m│               === ALI FILTER ENGINE ===                  │\033[0m")
print("\033[1;32m└──────────────────────────────────────────────────────────┘\033[0m")
ttloption = input("\033[1;32mttl?:\033[1;32m").strip().lower()
dumpusr = input("\033[1;32mHex dump(y/n):\033[1;32m").strip().lower()
target_ip = input("\033[1;32mtarget IP:\033[1;32m").strip().lower()
target_port = input("\033[1;32mtarget port:\033[1;32m").strip().lower()
target_prot= input("\033[1;32mprotocol(TCP,UDP,ARP...:\033[1;32m)").strip().lower()

def showttl(packet):
	if ttloption == "y":
		return (f"TTL:{packet[IP].ttl}")
	else:
		return("")
		
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

def dumpsys(packet):
	if dumpusr == "y":
		if packet.haslayer(Raw):
			hexdump(f"{packet[Raw].load}")
			
def inspect(packet):
	if packet.haslayer(IP):
		srcip = packet[IP].src
		dstip = packet[IP].dst
		
		
		if packet.haslayer(TCP) and localip == srcip :
			
			flagger = flaggingz(packet)
			alert = sys(packet)
			
			print(f">>>>>    \033[2;32m{srcip}:{packet[TCP].sport}\033[0m        ----[{alert}]---->      \033[1;35m{dstip}:{packet[TCP].dport}\033[0m{showttl(packet)}   {flagger}   TCP\033[1;33m")
			
			flaggingz(packet)
			sys(packet)
		elif packet.haslayer(TCP) and localip == dstip:
			
			flagger = flaggingz(packet)
			alert = sys(packet)
			
			print(f">>>>>    \033[2;32m{dstip}:{packet[TCP].dport}\033[0m     <----[{alert}]----      \033[1;35m{srcip}:{packet[TCP].sport}\033[0m{showttl(packet)}    {flagger}    TCP\033[1;33m")
			
			flaggingz(packet)
			sys(packet)
		elif packet.haslayer(ICMP) and localip == dstip:
			print(f"{dstip} <----ICMP---- {srcip}")
			
		elif packet.haslayer(ICMP) and localip == srcip:
			print(f"{srcip} ----ICMP----> {dstip}")
			if dumpusr == "y":
				dumpsys(packet)
				
		elif packet.haslayer(UDP):
			print(f"\033[0;36m[+]<{srcip}:{packet[UDP].sport}>      -------->      <{dstip}:{packet[UDP].dport}>  on UDP\033[0;36m")

sniff(prn=inspect, store=0, iface="wlan0", count=1000000, filter=filterA)
