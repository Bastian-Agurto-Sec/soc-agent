KNOWN_SAFE_IP_PREFIXES = [
"172.217.",   # Google
"216.58.",    # Google
"13.107.",    # Microsoft
"151.101.",   # Fastly CDN
"104.16.",    # Cloudflare
"104.17.",    # Cloudflare
"23.",        # Akamai (muchas IPs empiezan con 23)
]

def is_known_cloud_ip(ip):

    for prefix in KNOWN_SAFE_IP_PREFIXES:
        if ip.startswith(prefix):
            return True

    return False

import ipaddress


def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except:
        return False

def is_multicast(ip):

    try:
        return ipaddress.ip_address(ip).is_multicast
    except:
        return False

SAFE_DOMAINS = [
"google.com",
"gstatic.com",
"microsoft.com",
"windowsupdate.com",
"cloudflare.com",
"amazonaws.com",
"akadns.net",
"akamai.net",
"fastly.net",
]

def is_known_safe_domain(domain):

    for safe in SAFE_DOMAINS:
        if domain.endswith(safe):
            return True

    return False

def is_certificate_domain(domain):

    if "ocsp" in domain:
        return True

    if "crl" in domain:
        return True

    return False

def is_internal_domain(domain):

    if domain.endswith(".local"):
        return True

    if domain.endswith(".localdomain"):
        return True

    if domain.startswith("_ldap"):
        return True

    if domain.startswith("_kerberos"):
        return True

    return False

def clean_iocs(ips, domains):

    clean_ips = []
    clean_domains = []

    for ip in ips:

        if is_known_cloud_ip(ip):
            continue

        clean_ips.append(ip)

    for domain in domains:

        if is_known_safe_domain(domain):
            continue

        if is_certificate_domain(domain):
            continue

        clean_domains.append(domain)

    return clean_ips, clean_domains