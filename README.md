# Packet Sniffer -- Python Network Monitor

Hello I'm `Cybernerddd` and this is a Packet Sniffer I created. It's `beginner-friendly` Python-based tool built
using `Scapy` that monitors live network traffic and detects potential `credentials` in raw data transmissions.

## Features
- Detects common `credential` fields like `username`, `password`, `email`, `login`, etc.
-  Live `Traffic` Capture: Sniffs network packets in real time from any specified `interface`
- Lightweight & Fast: Minimal dependencies, its also low memory usage
- Command-line Ready: This tool zccepts interface argument for easy deployment.
- Built with `Scapy`

## ⚙️ Usage
### 📦 Requirements

> - Python 3
> - Scapy library
----

Install with:
```bash
pip install scapy
```
**RUN THE TOOL**
```bash
sudo python3 packet_sniffer.py -i <interface>
```
**EXAMPLE**
```bash
sudo python3 packet_sniffer.py -i eth0
```
 You’ll need `sudo` or root privileges to sniff packets.

### Sample Output
```
[*] Sniffing on interface: eth0

[+] Possible credentials found!
b'username=admin&password=123456'
```
### Ethical Usage Disclaimer
This tool was built for educational and ethical hacking purposes only. 
Do not use it on networks you don't own or have permission to monitor.

### Author
Built with grind by `Cybernerddd` 👨🏽‍💻
Twitter: `@Cybernerddd`
GitHub: `github.com/Cybernerddd`
