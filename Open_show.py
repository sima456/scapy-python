#!/usr/bin/env python3

"""
open_show.py

Open a PCAP and show the packets content.

Usage:
open_show.py <capture.pcap>
"""


import sys
from scapy.all import PcapReader

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <capture.pcap>")
    sys.exit(1)

print("+ Read and show packets ...")
packets = PcapReader(sys.argv[1])
for packet in packets:
    packet.show()
