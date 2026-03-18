🛡️ SOC Agent – AI-Assisted Threat Analysis

A modular SOC analysis tool that processes PCAPs and logs to extract IoCs, perform AI-based triage, detect suspicious domains, and enrich results with threat intelligence.

🚀 Features

📦 PCAP & log analysis

🌐 IOC extraction (IPs, domains)

🧹 Noise filtering

🤖 LLM-based triage

🧠 DGA (malware domain) detection

🔍 VirusTotal enrichment

📝 Automated SOC report generation

💾 Local caching (API optimization)

⚙️ How it works
Input (PCAP / logs)
↓
IOC extraction
↓
Filtering
↓
LLM triage
↓
DGA detection
↓
Threat intelligence enrichment
↓
SOC report
🧪 Usage
python main.py data/pcaps/sample.pcap
📊 Example Output
Suspicious domains:
- xolightfinance.com
- twereptale.com

Threat intelligence:
xolightfinance.com → malicious 5/92
🔐 Setup
pip install -r requirements.txt

Create .env file:

VT_API_KEY=your_key
OPENROUTER_API_KEY=your_key
📌 Project Goal

This project simulates a SOC investigation pipeline, combining:

heuristic detection

AI-based classification

threat intelligence