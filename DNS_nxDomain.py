#!/usr/bin/env python3
"""
dns_nxdomain.py

Detect devices that cause lots of NXDOMAIN DNS responses.

Usage:
nx_domain.py <capture.pcap> <suspicious.pcap>
"""


import statistics
import math
import sys
from scapy.all import DNS, IP, PcapReader, wrpcap
import matplotlib.pyplot as plt

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <capture.pcap> <suspicious.pcap>")
    sys.exit(1)

print("+ Read and count NXDOMAIN occurrences per IP ...")
packets = PcapReader(sys.argv[1])
counts = {}
# QR = Query Response
# ANCOUNT = Answer Count
# https://datatracker.ietf.org/doc/html/rfc5395#section-2
for packet in packets:
    if packet.haslayer(DNS) and packet[DNS].qr == 1 and packet[DNS].ancount == 0:
        ip = packet[IP].dst
        counts[ip] = counts.get(ip, 0) + 1

print("+ Compute threshold ...")
mean = statistics.mean(counts.values())
stddev = statistics.stdev(counts.values())
threshold = mean + 2 * stddev
median = statistics.median(counts.values())

print("+ Create list of suspicious IP addresses ...")
suspicious = []
for ip, occurrences in counts.items():
    if occurrences < threshold:
        continue
    suspicious.append(ip)

print(suspicious)

suspicious_pcap = sys.argv[2]
print(f"+ Write suspicious packets to {suspicious_pcap} ...")
packets = PcapReader(sys.argv[1])
for pkt in packets:
    if pkt.haslayer(IP) and (pkt[IP].dst in suspicious):
        wrpcap(suspicious_pcap, pkt, append=True)

print("+ Show histogram ...")
plt.hist(counts.values(), bins=int(math.sqrt(len(counts))))
plt.title('Histogram of NXDOMAIN DNS responses per IP')
plt.xlabel('Number of NXDOMAIN DNS responses')
plt.ylabel('Number of devices (IP addresses)')
ylim = plt.ylim()
plt.plot(
    [threshold, threshold],
    ylim,
    'r-',
    label='threshold (mean + 2 x stddev): ' + str(round(threshold, 2)))
plt.plot(
    [mean, mean],
    ylim,
    'g-',
    label='mean: ' + str(round(mean, 2)))
plt.plot(
    [median, median],
    ylim,
    '',
    label='median: ' + str(round(median, 2)))
plt.legend()
plt.show()
