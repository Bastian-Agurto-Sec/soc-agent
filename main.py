from extractors.pcap_extractor import extract_from_pcap
from extractors.log_extractor import extract_from_logs
from analysis.ioc_filter import clean_iocs, is_multicast
from analysis.llm_triage import llm_triage
from utils.utils import is_public_ip
from intel.enrichment import enrich_iocs
from analysis.reporting import generate_report
from analysis.dga_detection import is_suspicious_domain

import ipaddress
import sys


# -----------------------------
# detectar tipo de fuente
# -----------------------------
def detect_source(file):

    if file.endswith(".pcap") or file.endswith(".pcapng"):
        return "pcap"

    if file.endswith(".log"):
        return "log"

    return None


# -----------------------------
# helper: detectar si es IP
# -----------------------------
def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except:
        return False


# -----------------------------
# input del usuario
# -----------------------------
if len(sys.argv) < 2:
    print("Usage: python main.py <input_file>")
    sys.exit()

input_file = sys.argv[1]


# -----------------------------
# detectar fuente
# -----------------------------
source_type = detect_source(input_file)

if source_type is None:
    print("Unsupported file type")
    sys.exit()


# -----------------------------
# extraer IoCs según fuente
# -----------------------------
if source_type == "pcap":
    data = extract_from_pcap(input_file)

elif source_type == "log":
    data = extract_from_logs(input_file)


ips = data["ips"]
domains = data["domains"]

print("\nIPs encontradas:")
print(ips)

print("\nDominios encontrados:")
print(domains)


# -----------------------------
# filtrar IPs públicas
# -----------------------------
public_ips = [ip for ip in ips if is_public_ip(ip)]

print("\nIPs públicas:")
print(public_ips)


# -----------------------------
# limpieza offline
# -----------------------------
clean_ips, clean_domains = clean_iocs(public_ips, domains)

print("\nIPs después de limpieza:")
print(clean_ips)

print("\nDominios después de limpieza:")
print(clean_domains)

# -----------------------------
# LLM triage
# -----------------------------
result = llm_triage(clean_ips, clean_domains)

if result is None:
    print("LLM triage failed")
    sys.exit()

print("\nLLM TRIAGE RESULT:")
print(result)


# -----------------------------
# preparar IoCs para VT
# -----------------------------
ioc_for_vt = result["suspicious"] + result["unknown"]


# -----------------------------
# DGA detection (AQUÍ)
# -----------------------------
dga_domains = [d for d in clean_domains if is_suspicious_domain(d)]

print("\nDominios sospechosos por DGA:")
print(dga_domains)


# -----------------------------
# filtrar multicast
# -----------------------------
ioc_for_vt = [
    ioc for ioc in ioc_for_vt
    if not (is_ip(ioc) and is_multicast(ioc))
]


print("\nIoCs enviados a VirusTotal:")
print(ioc_for_vt)


# -----------------------------
# separar IPs y dominios
# -----------------------------
ips_for_vt = [ioc for ioc in ioc_for_vt if is_ip(ioc)]
domains_for_vt = [ioc for ioc in ioc_for_vt if not is_ip(ioc)]


# eliminar cosas raras tipo IP:PUERTO
domains_for_vt = [
    d for d in domains_for_vt
    if ":" not in d
]


# -----------------------------
# 🔥 integrar DGA aquí
# -----------------------------
domains_for_vt = list(set(domains_for_vt + dga_domains))


print("\nDomains finales para VirusTotal:")
print(domains_for_vt)

print("\nIPs para VirusTotal:")
print(ips_for_vt)

print("\nDomains para VirusTotal:")
print(domains_for_vt)

from intel.virustotal import check_ip, check_domain
import time


def enrich_iocs(ips, domains):

    results = []

    for ip in ips:

        print(f"Checking IP: {ip}")

        vt_result = check_ip(ip)

        results.append({
            "ioc": ip,
            "type": "ip",
            "vt": vt_result
        })

        time.sleep(15)   # respetar rate limit


    for domain in domains:

        print(f"Checking domain: {domain}")

        vt_result = check_domain(domain)

        results.append({
            "ioc": domain,
            "type": "domain",
            "vt": vt_result
        })

        time.sleep(15)

    return results

vt_results = enrich_iocs(ips_for_vt, domains_for_vt)

print("\nThreat Intel Results:")
print(vt_results)

report = generate_report(
    input_file,
    clean_ips,
    clean_domains,
    vt_results
)

print("\n")
print(report)

with open("analysis_report.txt", "w") as f:
    f.write(report)

"""for ip in public_ips:

    result = check_ip(ip)

    print("\n------")
    print(result)

    time.sleep(15)"""