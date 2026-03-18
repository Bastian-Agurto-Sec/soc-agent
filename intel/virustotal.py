import requests
import os

API_KEY = os.getenv("VT_API_KEY")

def check_ip(ip):

    print(f"Consultando VirusTotal para: {ip}")

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    headers = {
        "x-apikey": API_KEY
    }

    r = requests.get(url, headers=headers)

    if r.status_code != 200:
        return {"ip": ip, "error": "API error"}

    data = r.json()

    if "data" not in data:
        print(f"[VT ERROR] {ip}: {data}")
        return {
            "ip": ip,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0
        }

    stats = data["data"]["attributes"]["last_analysis_stats"]

    return {
        "ip": ip,
        "malicious": stats["malicious"],
        "suspicious": stats["suspicious"],
        "harmless": stats["harmless"]
    }

def check_domain(domain):

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"

    headers = {
        "x-apikey": API_KEY
    }

    response = requests.get(url, headers=headers)

    data = response.json()

    if "data" not in data:
        print(f"[VT ERROR] {domain}: {data}")
        return {
            "domain": domain,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0
        }

    stats = data["data"]["attributes"]["last_analysis_stats"]

    return {
        "domain": domain,
        "malicious": stats["malicious"],
        "suspicious": stats["suspicious"],
        "harmless": stats["harmless"]
    }