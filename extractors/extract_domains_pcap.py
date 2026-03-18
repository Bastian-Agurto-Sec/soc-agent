from scapy.all import rdpcap, TCP, Raw

def extract_http_hosts(pcap_file):

    packets = rdpcap(pcap_file)

    hosts = set()

    for packet in packets:

        if packet.haslayer(Raw):

            payload = packet[Raw].load

            try:

                payload = payload.decode(errors="ignore")

                if "Host:" in payload:

                    lines = payload.split("\r\n")

                    for line in lines:

                        if line.startswith("Host:"):

                            host = line.split("Host:")[1].strip()

                            hosts.add(host)

            except:
                pass

    return list(hosts)

from scapy.all import rdpcap
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.extensions import TLS_Ext_ServerName

def extract_tls_sni(pcap_file):

    packets = rdpcap(pcap_file)

    domains = set()

    for packet in packets:

        if packet.haslayer(TLSClientHello):

            hello = packet[TLSClientHello]

            if hasattr(hello, "ext"):

                for ext in hello.ext:

                    if isinstance(ext, TLS_Ext_ServerName):

                        for server in ext.servernames:

                            domains.add(server.servername.decode())

    return list(domains)