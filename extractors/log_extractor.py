import re

ip_pattern = r"(?:\d{1,3}\.){3}\d{1,3}"
domain_pattern = r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

def extract_from_logs(file):

    ips = set()
    domains = set()

    with open(file) as f:
        for line in f:

            ips_found = re.findall(ip_pattern, line)
            domains_found = re.findall(domain_pattern, line)

            ips.update(ips_found)
            domains.update(domains_found)

    return {
        "ips": list(ips),
        "domains": list(domains)
    }