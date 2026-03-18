from scapy.all import rdpcap, DNS, DNSQR

def extract_dns_queries(pcap_file):

    packets = rdpcap(pcap_file)

    domains = set()

    for packet in packets:

        if packet.haslayer(DNS) and packet.haslayer(DNSQR):

            query = packet[DNSQR].qname.decode().rstrip(".")

            domains.add(query)

    return list(domains)