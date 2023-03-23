from scapy.all import *

# Open the pcap file using a context manager
with PcapReader("capture.pcap") as packets:

    # Create a new pcap file for writing
    wrpcap("filtered_capture.pcap", [])

    # Iterate over each packet in the file
    for packet in packets:
        try:
            # Filter packets based on some criteria
            if packet.haslayer(IP):
                # Write the filtered packet to the new pcap file
                wrpcap("filtered_capture.pcap", [packet], append=True)
                
                # Process the packet
                print(packet.summary())
        except Exception as e:
            print(f"Error processing packet: {e}")
