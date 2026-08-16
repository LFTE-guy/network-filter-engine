# FilterX

FilterX is a lightweight, stateless TCP/IP packet inspection and anomaly detection engine written in Python. 

## Features
- **Stateless Anomaly Detection:** Flags zero-window SYN attempts, payloads on handshake packets, and invalid TCP flag states.
- **Protocol Inspection:** Identifies non-standard protocol usage and malformed headers at line speed.
- **Lightweight Architecture:** Low CPU overhead designed for local network monitoring.

## Prerequisite
- Python 3.x
- Scapy (`pip install scapy`)

## Usage
Run with elevated privileges (required for raw socket capture):
`sudo python3 filterx.py`
##Disclaimer: 
FilterX is developed strictly for network analysis, educational purposes, and defensive monitoring.
Always ensure you have proper authorization before capturing or analyzing network traffic on any network.
note that this is a simple project for fun and learning.
