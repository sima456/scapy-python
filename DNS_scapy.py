from scapy.all import *

# PcapReader creates a generator
# it does NOT load the complete file in memory
packets = PcapReader("capture.pcap")

for packet in packets:
    if packet.hasLayer(DNS)
