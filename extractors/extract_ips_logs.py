import re

def extract_ips(file):

    ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"

    ips = set()

    with open(file, "r") as f:
        for line in f:
            found = re.findall(ip_pattern, line)

            for ip in found:
                ips.add(ip)

    return list(ips)