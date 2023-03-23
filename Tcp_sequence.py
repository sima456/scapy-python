#!/usr/bin/env python3

"""
tcp_sequences.py

Detect repeated TCP sequence numbers. Packets with a suspicious
sequence number will be saved to a new pcap

Usage:
tcp_sequences.py <capture.pcap> <suspicious.pcap>
"""


import statistics
import math
import sys
from scapy.all import TCP, PcapReader, wrpcap
import matplotlib.pyplot as plt


if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <capture.pcap> <suspicious.pcap>")
    sys.exit(1)

print("+ Read and count TCP sequence numbers occurrences ...")
packets = PcapReader(sys.argv[1])
counts = {}
for packet in packets:
    if packet.haslayer(TCP):
        seq = packet[TCP].seq
        counts[seq] = counts.get(seq, 0) + 1

print("+ Compute threshold ...")
mean = statistics.mean(counts.values())
stddev = statistics.stdev(counts.values())
threshold = mean + 4 * stddev

print("+ Create list of suspicious sequence numbers ...")
suspicious = []
for seq, occurrences in counts.items():
    if occurrences < threshold:
        continue
    suspicious.append(seq)

suspicious_pcap = sys.argv[2]
print(f"+ Write suspicious packets to {suspicious_pcap} ...")
packets = PcapReader(sys.argv[1])
for pkt in packets:
    if pkt.haslayer(TCP) and (pkt[TCP].seq in suspicious):
        wrpcap(suspicious_pcap, pkt, append=True)

print("+ Show histogram ...")
plt.hist(counts.values(), bins=int(math.sqrt(len(counts))))
plt.title('Histogram of TCP sequence number occurrences')
plt.xlabel('Number of occurrences of the same sequence number')
plt.ylabel('Count')
plt.plot(
    [threshold, threshold],
    plt.ylim(),
    'r-',
    label='Threshold (mean + 4 x stddev): ' + str(round(threshold, 2)))
plt.legend()
plt.show()
