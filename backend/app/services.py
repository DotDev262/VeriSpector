import os
import re
import requests
import whois
import dns.resolver
from datetime import datetime, timezone
from urllib.parse import urlparse
from dotenv import load_dotenv

# Load environment variables from the .env file
load_dotenv()

# Get the API key from the environment
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

async def query_virustotal(url: str):
    """Queries the VirusTotal API for a URL report."""
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VirusTotal API key not configured."}

    vt_url = f"https://www.virustotal.com/api/v3/urls/{url}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    try:
        response = requests.get(vt_url, headers=headers)
        response.raise_for_status()
        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0)
        }
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            return {"malicious": 0, "suspicious": 0, "harmless": 0, "note": "URL not found in VirusTotal."}
        return {"error": f"HTTP error occurred: {e}"}
    except Exception as e:
        return {"error": str(e)}

async def perform_url_analysis(url: str):
    try:
        domain_name = urlparse(url).netloc
        if not domain_name:
            return {"error": "Could not parse domain from URL"}

        w = whois.whois(domain_name)

        # --- FIX: Use dictionary .get() method for safe access ---
        creation_date = w.get('creation_date')
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            domain_age_days = (datetime.now(timezone.utc) - creation_date).days
        else:
            domain_age_days = None
        
        vt_results = await query_virustotal(url)
        
        return {
            "url": url,
            "domain": domain_name,
            "domain_age_days": domain_age_days,
            # --- FIX: Use dictionary .get() method ---
            "registrar": w.get('registrar'),
            "virustotal_analysis": vt_results
        }
    except Exception as e:
        return {"error": str(e)}

async def perform_email_analysis(email: str):
    is_valid_syntax = re.match(r"[^@]+@[^@]+\.[^@]+", email) is not None
    if not is_valid_syntax:
        return {
            "email": email,
            "is_valid_syntax": False,
            "domain": "",
            "has_mx_records": False
        }

    domain = email.split('@')[1]
    has_mx_records = False
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        if mx_records:
            has_mx_records = True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        has_mx_records = False
        
    return {
        "email": email,
        "is_valid_syntax": True,
        "domain": domain,
        "has_mx_records": has_mx_records
    }