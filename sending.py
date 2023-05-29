from scapy.all import *

target_ip = "172.20.10.4"

source_ips = ["172.20.10." + str(i) for i in range(1,11)]

for i in range(1, 11):
    source_ip = source_ips[i-1]
    dest_port = 1024 + i
    packet = IP(src=source_ip, dst=target_ip) / TCP(dport =dest_port)
    print("packet send: ", packet[IP].src)
    send(packet, verbose=False)