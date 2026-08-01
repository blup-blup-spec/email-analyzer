"""
Phase 4 -- Threat Intelligence Enrichment

Queries multiple threat intel APIs for each IOC:
- VirusTotal (IP, domain, URL, file hash)
- AbuseIPDB (IP reputation)
- URLScan.io (URL scanning)
- OTX AlienVault (general IOC lookup)

Implements rate limiting and graceful error handling.
"""

import time
import requests
from typing import Dict, Any, Optional
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


class RateLimiter:
    """Simple rate limiter tracking last call timestamps per API."""

    def __init__(self):
        self._last_call = {}
        self._call_counts = {}

    def wait_if_needed(self, api_name: str):
        """Block until it's safe to make another request."""
        limit = config.RATE_LIMITS.get(api_name, 60)
        interval = 60.0 / limit

        now = time.time()
        last = self._last_call.get(api_name, 0)
        elapsed = now - last

        if elapsed < interval:
            wait_time = interval - elapsed
            time.sleep(wait_time)

        self._last_call[api_name] = time.time()
        self._call_counts[api_name] = self._call_counts.get(api_name, 0) + 1


_rate_limiter = RateLimiter()


def enrich_iocs(iocs: Dict[str, Any]) -> Dict[str, Any]:
    """Enrich all extracted IOCs with threat intelligence data."""
    enrichment = {}

    # Enrich IPs
    for ip in iocs.get("public_ips", []):
        enrichment[ip] = {"type": "ip", "sources": {}}
        vt = check_virustotal(ip, "ip")
        if vt:
            enrichment[ip]["sources"]["virustotal"] = vt
        abuse = check_abuseipdb(ip)
        if abuse:
            enrichment[ip]["sources"]["abuseipdb"] = abuse
        otx = check_otx(ip, "ip")
        if otx:
            enrichment[ip]["sources"]["otx"] = otx

    # Enrich URLs
    for url in iocs.get("urls", [])[:10]:
        enrichment[url] = {"type": "url", "sources": {}}
        vt = check_virustotal(url, "url")
        if vt:
            enrichment[url]["sources"]["virustotal"] = vt
        urlscan = check_urlscan(url)
        if urlscan:
            enrichment[url]["sources"]["urlscan"] = urlscan

    # Enrich domains
    for domain in iocs.get("domains", [])[:10]:
        enrichment[domain] = {"type": "domain", "sources": {}}
        vt = check_virustotal(domain, "domain")
        if vt:
            enrichment[domain]["sources"]["virustotal"] = vt
        otx = check_otx(domain, "domain")
        if otx:
            enrichment[domain]["sources"]["otx"] = otx

    # Enrich file hashes
    for hash_info in iocs.get("hashes", []):
        sha256 = hash_info.get("sha256", "")
        if sha256:
            enrichment[sha256] = {"type": "hash", "filename": hash_info.get("filename", ""), "sources": {}}
            vt = check_virustotal(sha256, "hash")
            if vt:
                enrichment[sha256]["sources"]["virustotal"] = vt

    # Summary
    enrichment["_summary"] = {
        "total_iocs_enriched": len([k for k in enrichment if not k.startswith("_")]),
        "malicious_count": sum(
            1 for k, v in enrichment.items()
            if not k.startswith("_") and _is_malicious(v)
        ),
    }

    return enrichment


def check_virustotal(ioc: str, ioc_type: str) -> Optional[Dict]:
    """Query VirusTotal for an IOC."""
    if not config.VIRUSTOTAL_API_KEY:
        return None

    _rate_limiter.wait_if_needed("virustotal")
    headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}
    base_url = "https://www.virustotal.com/api/v3"

    try:
        if ioc_type == "ip":
            url = f"{base_url}/ip_addresses/{ioc}"
        elif ioc_type == "domain":
            url = f"{base_url}/domains/{ioc}"
        elif ioc_type == "url":
            import base64
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            url = f"{base_url}/urls/{url_id}"
        elif ioc_type == "hash":
            url = f"{base_url}/files/{ioc}"
        else:
            return None

        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total_engines": sum(stats.values()) if stats else 0,
                "reputation": data.get("reputation", 0),
                "verdict": "malicious" if stats.get("malicious", 0) > 2 else (
                    "suspicious" if stats.get("suspicious", 0) > 0 else "clean"
                ),
            }
        elif response.status_code == 404:
            return {"verdict": "not_found", "detail": "IOC not found in VirusTotal database"}
        elif response.status_code == 429:
            return {"verdict": "rate_limited", "detail": "API rate limit exceeded"}
        else:
            return {"verdict": "error", "detail": f"HTTP {response.status_code}"}

    except requests.exceptions.Timeout:
        return {"verdict": "error", "detail": "Request timed out"}
    except Exception as e:
        return {"verdict": "error", "detail": str(e)}


def check_abuseipdb(ip: str) -> Optional[Dict]:
    """Query AbuseIPDB for IP reputation."""
    if not config.ABUSEIPDB_API_KEY:
        return None

    _rate_limiter.wait_if_needed("abuseipdb")

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=15,
        )

        if response.status_code == 200:
            data = response.json().get("data", {})
            abuse_score = data.get("abuseConfidenceScore", 0)
            return {
                "abuse_confidence_score": abuse_score,
                "total_reports": data.get("totalReports", 0),
                "country": data.get("countryCode", ""),
                "isp": data.get("isp", ""),
                "domain": data.get("domain", ""),
                "is_tor": data.get("isTor", False),
                "is_whitelisted": data.get("isWhitelisted", False),
                "verdict": "malicious" if abuse_score > 50 else (
                    "suspicious" if abuse_score > 20 else "clean"
                ),
            }
        else:
            return {"verdict": "error", "detail": f"HTTP {response.status_code}"}

    except Exception as e:
        return {"verdict": "error", "detail": str(e)}


def check_urlscan(url: str) -> Optional[Dict]:
    """Submit URL to URLScan.io for analysis."""
    if not config.URLSCAN_API_KEY:
        return None

    _rate_limiter.wait_if_needed("urlscan")

    try:
        response = requests.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f'page.url:"{url}"', "size": 1},
            headers={"API-Key": config.URLSCAN_API_KEY},
            timeout=15,
        )

        if response.status_code == 200:
            results = response.json().get("results", [])
            if results:
                result = results[0]
                verdicts = result.get("verdicts", {})
                overall = verdicts.get("overall", {})
                return {
                    "malicious": overall.get("malicious", False),
                    "score": overall.get("score", 0),
                    "categories": overall.get("categories", []),
                    "verdict": "malicious" if overall.get("malicious", False) else "clean",
                }
            return {"verdict": "not_found", "detail": "URL not previously scanned"}
        else:
            return {"verdict": "error", "detail": f"HTTP {response.status_code}"}

    except Exception as e:
        return {"verdict": "error", "detail": str(e)}


def check_otx(ioc: str, ioc_type: str = "ip") -> Optional[Dict]:
    """Query OTX AlienVault for IOC intelligence."""
    if not config.OTX_API_KEY:
        return None

    _rate_limiter.wait_if_needed("otx")
    headers = {"X-OTX-API-KEY": config.OTX_API_KEY}
    base_url = "https://otx.alienvault.com/api/v1"

    try:
        if ioc_type == "ip":
            url = f"{base_url}/indicators/IPv4/{ioc}/general"
        elif ioc_type == "domain":
            url = f"{base_url}/indicators/domain/{ioc}/general"
        elif ioc_type == "url":
            url = f"{base_url}/indicators/url/{ioc}/general"
        elif ioc_type == "hash":
            url = f"{base_url}/indicators/file/{ioc}/general"
        else:
            return None

        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code == 200:
            data = response.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            pulses = data.get("pulse_info", {}).get("pulses", [])
            pulse_names = [p.get("name", "") for p in pulses[:5]]
            return {
                "pulse_count": pulse_count,
                "pulse_names": pulse_names,
                "country": data.get("country_name", ""),
                "reputation": data.get("reputation", 0),
                "verdict": "malicious" if pulse_count > 5 else (
                    "suspicious" if pulse_count > 0 else "clean"
                ),
            }
        else:
            return {"verdict": "error", "detail": f"HTTP {response.status_code}"}

    except Exception as e:
        return {"verdict": "error", "detail": str(e)}


def _is_malicious(enrichment_entry: Dict) -> bool:
    """Check if any source flagged this IOC as malicious."""
    for source_name, source_data in enrichment_entry.get("sources", {}).items():
        if isinstance(source_data, dict) and source_data.get("verdict") == "malicious":
            return True
    return False
