from scapy.all import *

# Define the target IP address
target_ip = "172.20.10.6"

# Define the port range used by the sending program
start_port = 1024
end_port = 1033

# Define the filter to receive only packets from the sending program
sniff_filter = f"portrange {start_port}-{end_port}"

# Function to process sniffed packets and print their summaries
def process_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        source_ip = packet[IP].src
        dest_ip = packet[IP].dst
        source_port = packet[TCP].sport
        dest_port = packet[TCP].dport
        print(f"Source IP: {source_ip}, Destination IP: {dest_ip}, Source Port: {source_port}, Destination Port: {dest_port}")

# Start sniffing packets continuously and process them
sniff(filter=sniff_filter, prn=process_packet)