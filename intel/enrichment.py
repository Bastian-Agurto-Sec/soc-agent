import json
import os
import time

from intel.virustotal import check_ip, check_domain


CACHE_FILE = "intel_cache.json"


def load_cache():

    if not os.path.exists(CACHE_FILE):
        return {}

    with open(CACHE_FILE, "r") as f:
        return json.load(f)


def save_cache(cache):

    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)


def enrich_iocs(ips, domains):

    cache = load_cache()

    results = []

    # -----------------
    # IPs
    # -----------------

    for ip in ips:

        if ip in cache:

            print(f"[CACHE] {ip}")

            results.append(cache[ip])

            continue


        print(f"[VT] Checking IP: {ip}")

        vt_result = check_ip(ip)

        result = {
            "ioc": ip,
            "type": "ip",
            "vt": vt_result
        }

        results.append(result)

        cache[ip] = result

        save_cache(cache)

        time.sleep(15)


    # -----------------
    # DOMAINS
    # -----------------

    for domain in domains:

        if domain in cache:

            print(f"[CACHE] {domain}")

            results.append(cache[domain])

            continue


        print(f"[VT] Checking domain: {domain}")

        vt_result = check_domain(domain)

        result = {
            "ioc": domain,
            "type": "domain",
            "vt": vt_result
        }

        results.append(result)

        cache[domain] = result

        save_cache(cache)

        time.sleep(15)

    return results