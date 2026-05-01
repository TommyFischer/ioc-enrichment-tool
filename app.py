from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
import os
import requests
import anthropic

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")

app = Flask(__name__)
claude = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

def get_virustotal(ioc):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
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

def get_ai_verdict(ioc, vt, abuse):
    prompt = f"""You are a SOC analyst. Analyse this IOC and give a concise triage report.

IOC: {ioc}

VirusTotal Results:
- Malicious flags: {vt.get('malicious')}
- Suspicious flags: {vt.get('suspicious')}
- Harmless flags: {vt.get('harmless')}
- Undetected: {vt.get('undetected')}

AbuseIPDB Results:
- Abuse confidence score: {abuse.get('abuse_confidence_score')}%
- Country: {abuse.get('country')}
- ISP: {abuse.get('isp')}
- Total reports: {abuse.get('total_reports')}
- Last reported: {abuse.get('last_reported')}

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
    verdict = get_ai_verdict(ioc, vt_result, abuse_result)
    return jsonify({
        "ioc": ioc,
        "virustotal": vt_result,
        "abuseipdb": abuse_result,
        "ai_verdict": verdict
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
