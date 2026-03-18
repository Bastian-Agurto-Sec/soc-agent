from scapy.all import rdpcap, IP

def extract_ips_from_pcap(file):

    packets = rdpcap(file)

    ips = set()

    for packet in packets:

        if packet.haslayer(IP):

            src = packet[IP].src
            dst = packet[IP].dst

            ips.add(src)
            ips.add(dst)

    return list(ips)