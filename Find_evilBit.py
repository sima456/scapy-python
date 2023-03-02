import argparse
from scapy.all import *

# Define a callback function to handle each captured packet
def packet_handler(packet, verbose=False):
    if packet.haslayer(UDP):
        udp = packet[UDP]
        if udp.haslayer(IP):
            ip = udp[IP]
            if ip.flags & 0x02:
                print("Malicious packet detected!" if verbose else "M")
            else:
                print("Packet OK" if verbose else ".")

def main():
    # Set up command line arguments
    parser = argparse.ArgumentParser(description="Detect malicious UDP packets with the evil bit set.")
    parser.add_argument("pcap_file", help="Path to the PCAP file to analyze.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print verbose output.")
    args = parser.parse_args()

    # Open the PCAP file and sniff packets
    with PcapReader(args.pcap_file) as pcap_reader:
        for packet in pcap_reader:
            packet_handler(packet, args.verbose)

if __name__ == "__main__":
    main()
