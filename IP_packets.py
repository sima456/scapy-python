#!/usr/bin/env python3

"""
ip_packets.py

Detect IP addresses that send a lot of packets.

Usage:
ip_packets.py <capture.pcap>
"""

import statistics
import math
import sys
from scapy.all import IP, PcapReader
import matplotlib.pyplot as plt

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <capture.pcap>")
    sys.exit(1)

print("+ Read and count packets per IP ...")
packets = PcapReader(sys.argv[1])
counts = {}
for packet in packets:
    if packet.haslayer(IP):
        ip = packet[IP].src
        counts[ip] = counts.get(ip, 0) + 1

print("+ Compute threshold ...")
mean = statistics.mean(counts.values())
stddev = statistics.stdev(counts.values())
threshold = mean + 3 * stddev

print("+ Create list of suspicious IP addresses ...")
suspicious = []
for ip, occurrences in counts.items():
    if occurrences < threshold:
        continue
    suspicious.append(ip)

print(suspicious)

print("+ Show histogram ...")
plt.hist(counts.values(), bins=int(math.sqrt(len(counts))))
plt.title('Histogram of packets per IP')
plt.xlabel('Number of packets')
plt.ylabel('Number of source IP addresses')
plt.plot(
    [threshold, threshold],
    plt.ylim(),
    'r-',
    label='Threshold (mean + 3 x stddev): ' + str(round(threshold, 2)))
plt.legend()
plt.show()
