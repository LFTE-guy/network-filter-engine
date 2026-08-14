
from scapy.all import scapy,IP,sniff,TCP, UDP, ARP, Ether,Raw,hexdump,ICMP,packet
from security import *
from flagging import flaggingz
import time
from layout import colors,backbone
print("\033[1;32m┌──────────────────────────────────────────────────────────┐\033[0m")
print("\033[1;32m│               === ALI FILTER ENGINE ===                  │\033[0m")
print("\033[1;32m└──────────────────────────────────────────────────────────┘\033[0m")
ttloption = input(f"{colors.NEGATIVE}ttl?:{colors.END}").strip().lower()
dumpusr = input(f"{colors.NEGATIVE}Hex dump(y/n):{colors.END}").strip().lower()
target_ip = input(f"{colors.NEGATIVE}target IP:{colors.END}").strip().lower()
target_port = input(f"{colors.NEGATIVE}target port:{colors.END}").strip().lower()
target_prot= input(f"{colors.NEGATIVE}protocol(tcp,udp,arp,icmp):{colors.END}").strip().lower() 
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
		if dumpusr == "y" and  packet.haslayer(Raw):
			hexdump(packet[Raw].load)
			
def inspect(packet):
	if packet.haslayer(IP):
		srcip = packet[IP].src
		dstip = packet[IP].dst
		
		
		if packet.haslayer(TCP) and localip == srcip :
			sys(packet)
			flagger = flaggingz(packet)
			alert = sys(packet)
			
			print(f"{backbone.backrow}  {colors.LIGHT_GREEN}{srcip}:{packet[TCP].sport}{colors.END}  ----[{alert}]---->  {colors.YELLOW}{dstip}:{packet[TCP].dport}{colors.END}  {colors.NEGATIVE}{showttl(packet)}{colors.END}  {colors.NEGATIVE}{flagger}{colors.END}")
			dumpsys(packet)
			flaggingz(packet)
		
		
		
		elif packet.haslayer(TCP) and localip == dstip:
			
			flagger = flaggingz(packet)
			alert = sys(packet)
			
			
			
			print(f"{backbone.backrow}  {colors.YELLOW}{dstip}:{packet[TCP].dport}  <----[{alert}]----  {colors.LIGHT_GREEN}{srcip}:{packet[TCP].sport}{colors.END}  {colors.NEGATIVE}{showttl(packet)}{colors.END}  {colors.NEGATIVE}{flagger}{colors.END} {packet[TCP].window}")
			dumpsys(packet)
			flaggingz(packet)
			
		elif packet.haslayer(ICMP) and localip == dstip:
			alertntcp = ntcpsys(packet)
			print(f"{backbone.backrow}{dstip} <----ICMP{alertntcp}--- {srcip}")
			dumpsys(packet)
			
		elif packet.haslayer(ICMP) and localip == srcip:
			alertntcp = ntcpsys(packet)
			print(f"{backbone.backrow}{srcip} ----ICMP{alertntcp}----> {dstip}")
			dumpsys(packet)	
			
		elif packet.haslayer(UDP):
			
			print(f"{backbone.backrow}{srcip}:{packet[UDP].sport}      -------->      {dstip}:{packet[UDP].dport}    UDP")
			dumpsys(packet)
sniff(prn=inspect, store=0, iface="wlan0", count=10000000, filter=filterA,promisc=True)
