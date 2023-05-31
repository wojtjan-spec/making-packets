from scapy.all import *

target_ip = "172.20.10.6"
start_port = 1024
end_port = 1033
sniff_filter = f"portrange {start_port}-{end_port}"

def process_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        source_ip = packet[IP].src
        dest_ip = packet[IP].dst
        source_port = packet[TCP].sport
        dest_port = packet[TCP].dport
        print(f"Source IP: {source_ip}, Destination IP: {dest_ip}, Source Port: {source_port}, Destination Port: {dest_port}")

sniff(filter=sniff_filter, prn=process_packet)