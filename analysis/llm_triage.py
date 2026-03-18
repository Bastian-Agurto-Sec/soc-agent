import requests
from dotenv import load_dotenv
import os
import json

load_dotenv()

API_KEY = os.getenv("OPENROUTER_API_KEY")

if not API_KEY:
    raise ValueError("OPENROUTER_API_KEY not set")


def llm_triage(ips, domains):

    prompt = f"""
You are a SOC analyst performing IOC triage.

Classify the following IPs and domains into:

benign
suspicious
unknown

Rules:
- Major cloud infrastructure (Google, Microsoft, AWS, Cloudflare) is benign.
- Certificate validation domains (ocsp, crl) are benign.
- Internal domains (.local, Active Directory records) are benign.
- Random looking domains or unusual subdomains may be suspicious.

Return ONLY valid JSON:

{{
 "benign": [],
 "suspicious": [],
 "unknown": []
}}

IPs:
{ips}

Domains:
{domains}
"""

    url = "https://openrouter.ai/api/v1/chat/completions"

    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }

    data = {
        "model": "deepseek/deepseek-chat",
        "messages": [
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.2
    }

    response = requests.post(url, headers=headers, json=data)

    result = response.json()

    if "error" in result:
        print("LLM API error:", result["error"]["message"])
        return None

    content = result["choices"][0]["message"]["content"]

    # limpiar markdown
    content = content.replace("```json", "")
    content = content.replace("```", "")
    content = content.strip()

    try:
        parsed = json.loads(content)
        return parsed
    except:
        print("LLM returned non-JSON response:")
        print(content)
        return None