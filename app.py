from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
import os
import requests
import anthropic
import re

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")

app = Flask(__name__)
claude = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

def is_ip(ioc):
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ioc))

def get_virustotal(ioc):
    if is_ip(ioc):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    else:
        url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0)
        }
    return {"error": f"VirusTotal returned {response.status_code}"}

def get_abuseipdb(ioc):
    if not is_ip(ioc):
        return {"note": "AbuseIPDB only supports IP addresses"}
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ioc, "maxAgeInDays": 90}
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        data = response.json()["data"]
        return {
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "total_reports": data.get("totalReports"),
            "last_reported": data.get("lastReportedAt")
        }
    return {"error": f"AbuseIPDB returned {response.status_code}"}

def get_shodan(ioc):
    if not is_ip(ioc):
        return {"note": "Shodan IP lookup only supports IP addresses"}
    url = f"https://api.shodan.io/shodan/host/{ioc}?key={SHODAN_API_KEY}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        return {
            "org": data.get("org"),
            "country": data.get("country_name"),
            "os": data.get("os"),
            "open_ports": data.get("ports", []),
            "tags": data.get("tags", []),
            "vulnerabilities": list(data.get("vulns", {}).keys())[:5]
        }
    return {"error": f"Shodan returned {response.status_code}"}

def get_ai_verdict(ioc, vt, abuse, shodan):
    prompt = f"""You are a SOC analyst. Analyse this IOC and give a concise triage report.

IOC: {ioc}

VirusTotal:
- Malicious flags: {vt.get('malicious')}
- Suspicious flags: {vt.get('suspicious')}
- Harmless flags: {vt.get('harmless')}

AbuseIPDB:
- Abuse confidence score: {abuse.get('abuse_confidence_score')}%
- Country: {abuse.get('country')}
- ISP: {abuse.get('isp')}
- Total reports: {abuse.get('total_reports')}

Shodan:
- Org: {shodan.get('org')}
- Open ports: {shodan.get('open_ports')}
- Tags: {shodan.get('tags')}
- Known vulnerabilities: {shodan.get('vulnerabilities')}

Provide:
1. VERDICT: (Malicious / Suspicious / Likely Benign)
2. RISK LEVEL: (Critical / High / Medium / Low)
3. SUMMARY: 2-3 sentences explaining what this IOC is and why it is or isn't a threat
4. RECOMMENDED ACTION: One clear sentence on what a SOC analyst should do"""

    message = claude.messages.create(
        model="claude-opus-4-6",
        max_tokens=500,
        messages=[{"role": "user", "content": prompt}]
    )
    return message.content[0].text

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/analyse", methods=["POST"])
def analyse():
    ioc = request.json.get("ioc")
    print(f"Analysing: {ioc}")
    vt_result = get_virustotal(ioc)
    abuse_result = get_abuseipdb(ioc)
    shodan_result = get_shodan(ioc)
    verdict = get_ai_verdict(ioc, vt_result, abuse_result, shodan_result)
    return jsonify({
        "ioc": ioc,
        "virustotal": vt_result,
        "abuseipdb": abuse_result,
        "shodan": shodan_result,
        "ai_verdict": verdict
    })

if __name__ == "__main__":
     app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
