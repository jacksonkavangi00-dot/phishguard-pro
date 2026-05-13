import whois
import dns.resolver
import requests
from datetime import datetime
import base64

# ================= WHOIS =================
def get_whois_info(domain):
    try:
        w = whois.whois(domain)

        creation_date = w.creation_date
        registrar = w.registrar

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age_days = (datetime.now() - creation_date).days
        else:
            age_days = None

        return {
            "registrar": registrar or "Unknown",
            "age_days": age_days
        }

    except:
        return {
            "registrar": "Unknown",
            "age_days": None
        }


# ================= DNS =================
def dns_check(domain):
    try:
        answers = dns.resolver.resolve(domain, "A")
        return len(answers) > 0
    except:
        return False


# ================= BLACKLIST =================
# simple local check (you can expand later)
BLACKLIST_KEYWORDS = [
    "paypal-login",
    "secure-login",
    "bank-update",
    "verify-account",
]

def blacklist_check(url):
    for bad in BLACKLIST_KEYWORDS:
        if bad in url.lower():
            return True
    return False

VT_API_KEY = "YOUR_API_KEY_HERE"


def virustotal_check(url):
    try:
        # encode URL (VT requirement)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        headers = {
            "x-apikey": VT_API_KEY
        }

        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        response = requests.get(vt_url, headers=headers)

        if response.status_code != 200:
            return {"malicious": 0, "suspicious": 0}

        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0)
        }

    except Exception as e:
        print("VT error:", e)
        return {"malicious": 0, "suspicious": 0}
