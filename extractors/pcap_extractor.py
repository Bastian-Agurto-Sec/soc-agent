from extractors.extract_ips_pcap import extract_ips_from_pcap
from extractors.extract_dns_pcap import extract_dns_queries
from extractors.extract_domains_pcap import extract_http_hosts, extract_tls_sni

def extract_from_pcap(file):

    ips = extract_ips_from_pcap(file)

    dns_domains = extract_dns_queries(file)
    http_domains = extract_http_hosts(file)
    tls_domains = extract_tls_sni(file)

    domains = list(set(dns_domains + http_domains + tls_domains))

    return {
        "ips": ips,
        "domains": domains
    }