import ipaddress

def is_public_ip(ip):

    try:
        return ipaddress.ip_address(ip).is_global
    except:
        return False