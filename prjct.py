from scapy.all import scapy,IP,sniff,TCP, UDP, ARP
print("welcome to ali filter")
def inspect(packet):
	if packet.haslayer(IP):
		srcip = packet[IP].src
		dstip = packet[IP].dst
		if packet.haslayer(TCP):
			print(f"{srcip}:{packet[TCP].sport} --------> {dstip}:{packet[TCP].dport} on TCP")
		elif packet.haslayer(UDP):
			print(f"{srcip}:{packet[UDP].sport} --------> {dstip}:{packet[UDP].dport} on UDP")
		
sniff(prn=inspect, store=0, iface="wlan0", count=100)

