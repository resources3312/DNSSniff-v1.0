#! /usr/bin/python
import sys
from scapy.all import sniff, IP
from datetime import datetime


class DNSSniffer:
    def __init__(self, interface):
        self.interface = interface

    def packetAnalysis(self, packet) -> None:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Sender: {packet[IP].src} Domain: {packet['DNS Question Record'].qname.decode()[:-1]}")

    def startMonitoring(self) -> None:
        print(f"DNSsniff v1.0\n\nDNS Question Record packages:\n{'—' * 35}\n")
        sniff(filter="udp dst port 53", iface=self.interface, prn=self.packetAnalysis, store=0)


def main() -> None:
    try:
        sniffer = DNSSniffer(interface=sys.argv[sys.argv.index("--interface") + 1])
        sniffer.startMonitoring()
    except (ValueError, IndexError): sys.exit("Usage: dnssniff.py --interface <interface>")
    except OSError: sys.exit("Interface doesn`t exists, try again")
if __name__ == '__main__': main()
