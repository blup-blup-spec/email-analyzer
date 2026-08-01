"""
Phase 2 -- Header Analysis (Enhanced)

Analyzes email headers for security indicators.
Incorporates techniques from SOC101 eioc.py:
  - X-Originating-IP / X-Sender-IP extraction (added)
  - ipinfo.io geo-lookup for sending IPs (added)
  - Defanged indicator output (added)
  - Typosquatting / homoglyph domain detection (added)
  - Lookalike unicode character detection (added)
  - MIME content-type vs body mismatch check (added)
  - Return-Path vs From mismatch (added)
  - Encoding anomaly detection (added)
  - Enhanced suspicious mailer list (added)

Existing approach kept unchanged where it was solid.
"""

import re
import socket
import ipaddress
from typing import Dict, List, Any, Optional
from email.utils import parseaddr

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ── Defang helpers (from SOC101 eioc.py) ──────────────────────────────────────

def defang_ip(ip: str) -> str:
    return ip.replace(".", "[.]")


def defang_url(url: str) -> str:
    url = url.replace("https://", "hxxps[://]").replace("http://", "hxxp[://]")
    return re.sub(r'(?<!\[)\.(?!\])', "[.]", url)


# ── IP geo-lookup via ipinfo.io (from SOC101 eioc.py) ────────────────────────

def _is_reserved_ip(ip: str) -> bool:
    """Check if IP is in private/reserved range — don't look up these."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_reserved or addr.is_loopback or addr.is_link_local
    except ValueError:
        return True


def _ip_geoinfo(ip: str) -> Optional[Dict]:
    """Query ipinfo.io for basic geolocation — free, no API key needed."""
    if _is_reserved_ip(ip):
        return None
    if not HAS_REQUESTS:
        return None
    try:
        resp = _requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "ip":      data.get("ip", ip),
                "city":    data.get("city", ""),
                "region":  data.get("region", ""),
                "country": data.get("country", ""),
                "org":     data.get("org", ""),   # ISP / ASN
                "defanged": defang_ip(ip),
            }
    except Exception:
        pass
    return None


# ── Typosquatting / homoglyph detection ────────────────────────────────────────

# Common lookalike unicode → ascii substitutions used in phishing domains
_HOMOGLYPHS = {
    "\u0430": "a", "\u0435": "e", "\u03bf": "o", "\u0440": "p",
    "\u0441": "c", "\u0456": "i", "\u0443": "y", "\u04bb": "h",
    "\u1d0f": "o", "\u1d00": "a", "\u0282": "s",
}

_KNOWN_BRANDS = [
    "paypal", "microsoft", "apple", "google", "amazon", "netflix",
    "bank", "chase", "wellsfargo", "citibank", "facebook", "meta",
    "instagram", "linkedin", "dropbox", "adobe", "docusign", "dhl",
    "fedex", "ups", "irs", "walmart", "target", "ebay", "coinbase",
    "binance", "twitter", "x.com",
]

# Typosquatting character swaps common in phishing domains
_TYPO_SWAPS = [
    ("rn", "m"), ("vv", "w"), ("l", "1"), ("o", "0"),
    ("i", "l"), ("a", "4"), ("e", "3"), ("s", "5"),
    ("1", "l"), ("0", "o"), ("nn", "m"), ("cl", "d"),
]


def _detect_typosquatting(domain: str) -> List[str]:
    """
    Detect if a domain is a typosquatted version of a known brand.
    Returns list of matched brand names.
    """
    matches = []
    d = domain.lower().split(".")[0]  # just the registrable part

    # Homoglyph normalisation
    normalized = "".join(_HOMOGLYPHS.get(c, c) for c in d)

    for brand in _KNOWN_BRANDS:
        brand_core = brand.replace(" ", "").replace(".", "")
        if brand_core in normalized or normalized in brand_core:
            if brand_core != domain.lower().split(".")[0]:  # not an exact match
                matches.append(brand)
                continue
        # Check each typo swap
        swapped = normalized
        for wrong, right in _TYPO_SWAPS:
            swapped = swapped.replace(wrong, right)
        if brand_core in swapped and brand_core != normalized:
            matches.append(brand)

    return list(set(matches))


def _has_homoglyph_chars(text: str) -> bool:
    """Check if text contains Unicode homoglyph characters."""
    return any(c in _HOMOGLYPHS for c in text)


# ── Main entry point ──────────────────────────────────────────────────────────

def analyze_headers(parsed_email: Dict[str, Any]) -> Dict[str, Any]:
    """
    Comprehensive header analysis — enhanced with SOC101 eioc.py techniques.

    Checks added vs original:
    - X-Originating-IP / X-Sender-IP extraction + geo-lookup
    - Return-Path vs From mismatch
    - Typosquatting domain detection
    - Homoglyph (unicode lookalike) characters in From/Subject
    - Encoding anomaly (base64 subject obfuscation)
    - Lookalike TLDs (.corn for .com etc.)
    - Multiple From headers (header injection)
    - Mismatched envelope vs header sender
    """
    findings = {
        "hop_chain":        [],
        "authentication":   {},
        "anomalies":        [],
        "sender_ips":       [],   # new: X-Originating-IP etc.
        "severity_summary": {"critical": 0, "warning": 0, "info": 0},
    }

    # 1. Hop chain
    findings["hop_chain"] = _parse_hop_chain(parsed_email.get("received_headers", []))

    # 2. SPF / DKIM / DMARC
    findings["authentication"] = _check_authentication(parsed_email)

    # 3. Originating IP extraction + geo (SOC101 eioc.py approach)
    findings["sender_ips"] = _extract_sender_ips(parsed_email)

    # 4. From display name checks + typosquatting
    _check_from_mismatch(parsed_email, findings)

    # 5. Reply-To vs From mismatch
    _check_reply_to_mismatch(parsed_email, findings)

    # 6. Return-Path vs From mismatch (new)
    _check_return_path_mismatch(parsed_email, findings)

    # 7. Subject / body encoding anomaly (new)
    _check_encoding_anomalies(parsed_email, findings)

    # 8. General header anomalies (existing + extended)
    _check_header_anomalies(parsed_email, findings)

    # 9. Auth failures → anomalies
    _check_auth_failures(parsed_email, findings)

    # Count severities
    for anomaly in findings["anomalies"]:
        sev = anomaly.get("severity", "info")
        if sev in findings["severity_summary"]:
            findings["severity_summary"][sev] += 1

    return findings


# ── Hop chain ─────────────────────────────────────────────────────────────────

def _parse_hop_chain(received_headers: List[str]) -> List[Dict[str, Any]]:
    """Parse Received headers to extract IP hop chain with geo-info."""
    ip_pattern = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    )
    hops = []

    for i, header in enumerate(reversed(received_headers)):
        hop = {
            "hop_number":  i + 1,
            "raw":         header.strip(),
            "from_ip":     None,
            "from_domain": None,
            "by_domain":   None,
            "timestamp":   None,
            "geo":         None,
            "all_ips":     [],
        }

        from_match = re.search(
            r'from\s+(\S+)(?:\s+\(.*?\[?(' + ip_pattern.pattern + r')\]?\))?',
            header, re.IGNORECASE
        )
        if from_match:
            hop["from_domain"] = from_match.group(1)
            if from_match.group(2):
                hop["from_ip"] = from_match.group(2)

        by_match = re.search(r'by\s+(\S+)', header, re.IGNORECASE)
        if by_match:
            hop["by_domain"] = by_match.group(1)

        all_ips = ip_pattern.findall(header)
        if not hop["from_ip"] and all_ips:
            hop["from_ip"] = all_ips[0]
        hop["all_ips"] = list(set(all_ips))

        ts_match = re.search(r';\s*(.+?)$', header, re.MULTILINE)
        if ts_match:
            hop["timestamp"] = ts_match.group(1).strip()

        # geo-lookup for the sender IP (SOC101 eioc.py ip_lookup)
        if hop["from_ip"] and not _is_reserved_ip(hop["from_ip"]):
            hop["geo"] = _ip_geoinfo(hop["from_ip"])

        hops.append(hop)

    return hops


# ── Originating IP extraction (SOC101 eioc.py extract_headers approach) ───────

def _extract_sender_ips(parsed_email: Dict) -> List[Dict]:
    """
    Extract X-Originating-IP, X-Sender-IP, X-Source-IP headers.
    These reveal the actual client IP before entering the mail server.
    SOC101 eioc.py explicitly checks these headers — a key gap in our original.
    """
    sender_ips = []
    all_headers = parsed_email.get("all_headers", {})

    ip_headers = [
        "X-Originating-IP", "X-Sender-IP", "X-Source-IP",
        "X-Forwarded-For", "X-Real-IP", "X-Client-IP",
    ]
    ip_pattern = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')

    for hdr in ip_headers:
        val = all_headers.get(hdr, "") or all_headers.get(hdr.lower(), "")
        if val:
            ips_found = ip_pattern.findall(val)
            for ip in ips_found:
                if not _is_reserved_ip(ip):
                    entry = {
                        "header": hdr,
                        "ip": ip,
                        "defanged": defang_ip(ip),
                        "geo": _ip_geoinfo(ip),
                    }
                    sender_ips.append(entry)

    return sender_ips


# ── Authentication checks ─────────────────────────────────────────────────────

def _check_authentication(parsed_email: Dict) -> Dict[str, Any]:
    """Check SPF, DKIM, and DMARC authentication results."""
    auth_results = parsed_email.get("authentication_results", "").lower()
    received_spf = parsed_email.get("received_spf", "").lower()

    auth = {
        "spf":  {"status": "unknown", "detail": ""},
        "dkim": {"status": "unknown", "detail": ""},
        "dmarc":{"status": "unknown", "detail": ""},
        "raw":  parsed_email.get("authentication_results", ""),
    }

    combined = auth_results + " " + received_spf

    spf_m = re.search(r'spf\s*=\s*(\w+)', combined)
    if not spf_m:
        spf_m = re.search(r'(pass|fail|softfail|neutral|none|temperror|permerror)', received_spf)
    if spf_m:
        auth["spf"]["status"] = spf_m.group(1)
        auth["spf"]["detail"] = f"SPF result: {spf_m.group(1)}"

    dkim_m = re.search(r'dkim\s*=\s*(\w+)', combined)
    if dkim_m:
        auth["dkim"]["status"] = dkim_m.group(1)
        auth["dkim"]["detail"] = f"DKIM result: {dkim_m.group(1)}"
    elif parsed_email.get("dkim_signature"):
        auth["dkim"]["status"] = "present"
        auth["dkim"]["detail"] = "DKIM signature present but result unknown"

    dmarc_m = re.search(r'dmarc\s*=\s*(\w+)', combined)
    if dmarc_m:
        auth["dmarc"]["status"] = dmarc_m.group(1)
        auth["dmarc"]["detail"] = f"DMARC result: {dmarc_m.group(1)}"

    return auth


# ── Domain helpers ────────────────────────────────────────────────────────────

def _extract_domain(email_address: str) -> str:
    _, addr = parseaddr(email_address)
    if "@" in addr:
        return addr.split("@")[1].lower().strip()
    return ""


# ── From mismatch + typosquatting (enhanced) ──────────────────────────────────

def _check_from_mismatch(parsed_email: Dict, findings: Dict):
    """Enhanced From analysis with typosquatting and homoglyph checks."""
    from_name    = parsed_email.get("from_name", "") or ""
    from_address = parsed_email.get("from_address", "") or ""
    from_domain  = _extract_domain(from_address)

    # Check if display name embeds an email with different domain
    name_email_m = re.search(r'[\w.-]+@[\w.-]+\.\w+', from_name)
    if name_email_m:
        name_domain = name_email_m.group(0).split("@")[1].lower()
        if name_domain != from_domain:
            findings["anomalies"].append({
                "type": "from_domain_mismatch",
                "severity": "critical",
                "message": (
                    f"Display name contains '{name_email_m.group(0)}' "
                    f"but actual sender is '{from_address}' -- impersonation"
                ),
                "details": {"display_domain": name_domain, "actual_domain": from_domain},
            })

    # Brand impersonation in display name
    from_name_lower = from_name.lower()
    for brand in _KNOWN_BRANDS:
        brand_core = brand.replace(" ", "")
        if brand_core in from_name_lower and brand_core not in from_domain:
            findings["anomalies"].append({
                "type": "brand_impersonation",
                "severity": "warning",
                "message": (
                    f"Display name contains '{brand}' but sending domain "
                    f"is '{from_domain}' -- possible brand impersonation"
                ),
                "details": {"brand": brand, "actual_domain": from_domain},
            })
            break

    # Typosquatting detection on sending domain
    if from_domain:
        typo_matches = _detect_typosquatting(from_domain)
        if typo_matches:
            findings["anomalies"].append({
                "type": "typosquatting_domain",
                "severity": "critical",
                "message": (
                    f"Sending domain '{from_domain}' appears to be a "
                    f"typosquatted version of: {', '.join(typo_matches)}"
                ),
                "details": {"domain": from_domain, "impersonated_brands": typo_matches},
            })

        # Homoglyph unicode characters in domain
        if _has_homoglyph_chars(from_domain):
            findings["anomalies"].append({
                "type": "homoglyph_domain",
                "severity": "critical",
                "message": (
                    f"Sending domain '{from_domain}' contains Unicode lookalike "
                    f"characters -- possible IDN homograph attack"
                ),
                "details": {"domain": from_domain},
            })

    # Homoglyph chars in display name
    if _has_homoglyph_chars(from_name):
        findings["anomalies"].append({
            "type": "homoglyph_display_name",
            "severity": "warning",
            "message": f"From display name contains Unicode lookalike characters: '{from_name}'",
            "details": {"from_name": from_name},
        })


# ── Reply-To mismatch ─────────────────────────────────────────────────────────

def _check_reply_to_mismatch(parsed_email: Dict, findings: Dict):
    reply_to = parsed_email.get("reply_to", "") or ""
    from_address = parsed_email.get("from_address", "") or ""
    if not reply_to or not from_address:
        return
    reply_domain = _extract_domain(reply_to)
    from_domain  = _extract_domain(from_address)
    if reply_domain and from_domain and reply_domain != from_domain:
        findings["anomalies"].append({
            "type": "reply_to_mismatch",
            "severity": "warning",
            "message": (
                f"Reply-To domain '{reply_domain}' differs from "
                f"From domain '{from_domain}' -- replies go to attacker-controlled address"
            ),
            "details": {"reply_to_domain": reply_domain, "from_domain": from_domain},
        })


# ── Return-Path mismatch (new check) ─────────────────────────────────────────

def _check_return_path_mismatch(parsed_email: Dict, findings: Dict):
    """
    Return-Path is set by the MTA during SMTP — attackers often use a
    different domain here to avoid SPF failures while still impersonating.
    SOC101 eioc.py extract_headers explicitly pulls Return-Path.
    """
    return_path  = parsed_email.get("return_path", "") or ""
    from_address = parsed_email.get("from_address", "") or ""
    if not return_path or not from_address:
        return

    # Clean up <angle brackets> if present
    rp_clean = re.sub(r'[<>]', '', return_path).strip()
    rp_domain  = _extract_domain(rp_clean)
    from_domain = _extract_domain(from_address)

    if rp_domain and from_domain and rp_domain != from_domain:
        findings["anomalies"].append({
            "type": "return_path_mismatch",
            "severity": "warning",
            "message": (
                f"Return-Path domain '{rp_domain}' differs from "
                f"From domain '{from_domain}' -- envelope sender mismatch"
            ),
            "details": {"return_path_domain": rp_domain, "from_domain": from_domain},
        })


# ── Encoding anomalies (new check) ────────────────────────────────────────────

def _check_encoding_anomalies(parsed_email: Dict, findings: Dict):
    """
    Detect obfuscation via unusual encoding.
    Phishing emails sometimes base64 or qp-encode the Subject to evade filters.
    Also checks for suspicious Content-Transfer-Encoding on text parts.
    """
    subject = parsed_email.get("subject", "") or ""
    raw_subject = parsed_email.get("raw_subject", subject)

    # Base64-encoded subject token
    if "=?utf-8?b?" in raw_subject.lower() or "=?iso-8859-1?b?" in raw_subject.lower():
        findings["anomalies"].append({
            "type": "encoded_subject",
            "severity": "info",
            "message": f"Subject is base64-encoded: '{subject[:60]}' -- may evade content filters",
            "details": {"raw_subject": raw_subject[:80]},
        })

    # Multiple encoding tokens in subject = excessive obfuscation
    encoded_tokens = re.findall(r'=\?[^?]+\?[BbQq]\?[^?]*\?=', raw_subject)
    if len(encoded_tokens) > 2:
        findings["anomalies"].append({
            "type": "excessive_encoding",
            "severity": "warning",
            "message": f"Subject contains {len(encoded_tokens)} encoded chunks -- unusual fragmentation",
            "details": {"token_count": len(encoded_tokens)},
        })

    # HTML content in plain text part (HTML injection via body)
    body_text = parsed_email.get("body_text", "") or ""
    if re.search(r'<script|<iframe|<object|javascript:', body_text, re.IGNORECASE):
        findings["anomalies"].append({
            "type": "html_in_text_body",
            "severity": "critical",
            "message": "HTML/script tags found in plain text part -- possible injection attempt",
            "details": {},
        })

    # Urgency language in subject
    urgency_patterns = [
        r'\burgent\b', r'\bimmediately\b', r'\baction required\b',
        r'\bverify\s+your\b', r'\bsuspend', r'\bnotice\b',
        r'\bwarning\b', r'\balert\b', r'\bsecurity\b',
    ]
    subject_lower = subject.lower()
    matched_urgency = [p for p in urgency_patterns if re.search(p, subject_lower)]
    if matched_urgency:
        findings["anomalies"].append({
            "type": "urgency_subject",
            "severity": "info",
            "message": f"Subject line contains urgency/phishing keywords: '{subject[:70]}'",
            "details": {"matched_patterns": matched_urgency},
        })


# ── General header anomalies (original + extended) ────────────────────────────

def _check_header_anomalies(parsed_email: Dict, findings: Dict):
    """Check for missing/suspicious headers. Extended with SOC101 patterns."""

    # Missing Authentication-Results
    if not parsed_email.get("authentication_results"):
        findings["anomalies"].append({
            "type": "missing_auth_headers",
            "severity": "info",
            "message": "No Authentication-Results header -- SPF/DKIM/DMARC status unknown",
            "details": {},
        })

    # Missing Message-ID
    if not parsed_email.get("message_id"):
        findings["anomalies"].append({
            "type": "missing_message_id",
            "severity": "info",
            "message": "Missing Message-ID header -- may indicate automated or forged email",
            "details": {},
        })

    # Extended suspicious X-Mailer list (original had 6, expanded to 20+)
    x_mailer = (parsed_email.get("x_mailer") or "").lower()
    suspicious_mailers = [
        "mass mail", "mass mailer", "bulk mail", "bulk mailer",
        "king mailer", "atomic mail", "dark mailer", "turbo mail",
        "sendblaster", "mailchimp hack", "phpmailer/5", "smtp2go hack",
        "bombardier", "rocket mailer", "power mailer", "mailing list",
        "spammer", "blaster", "auto mailer",
    ]
    for mailer in suspicious_mailers:
        if mailer in x_mailer:
            findings["anomalies"].append({
                "type": "suspicious_mailer",
                "severity": "warning",
                "message": f"Suspicious X-Mailer detected: '{parsed_email.get('x_mailer')}'",
                "details": {"x_mailer": parsed_email.get("x_mailer")},
            })
            break

    # Hop count checks
    hop_count = parsed_email.get("hop_count", 0)
    if hop_count == 0:
        findings["anomalies"].append({
            "type": "no_received_headers",
            "severity": "warning",
            "message": "No Received headers -- email may be locally generated or headers stripped",
            "details": {},
        })
    elif hop_count > 10:
        findings["anomalies"].append({
            "type": "excessive_hops",
            "severity": "info",
            "message": f"Email passed through {hop_count} hops -- unusually high relay count",
            "details": {"hop_count": hop_count},
        })

    # Lookalike TLD detection (new)
    from_address = parsed_email.get("from_address", "") or ""
    from_domain = _extract_domain(from_address)
    lookalike_tlds = {
        ".corn": ".com", ".cpm": ".com", ".c0m": ".com",
        ".net0": ".net", ".0rg": ".org", ".cm": ".com",
        ".co.": ".com",
    }
    for fake_tld, real_tld in lookalike_tlds.items():
        if from_domain.endswith(fake_tld.rstrip(".")):
            findings["anomalies"].append({
                "type": "lookalike_tld",
                "severity": "critical",
                "message": (
                    f"Domain '{from_domain}' uses lookalike TLD "
                    f"'{fake_tld}' resembling '{real_tld}'"
                ),
                "details": {"domain": from_domain, "fake_tld": fake_tld},
            })

    # Content-Type vs actual body mismatch (new)
    content_type = parsed_email.get("content_type", "") or ""
    body_html = parsed_email.get("body_html", "") or ""
    if "text/plain" in content_type and len(body_html) > 500:
        findings["anomalies"].append({
            "type": "content_type_mismatch",
            "severity": "info",
            "message": "Content-Type claims text/plain but email contains significant HTML content",
            "details": {"html_length": len(body_html)},
        })

    # Multiple From headers (header injection check — new)
    all_headers = parsed_email.get("all_headers", {})
    from_count = sum(1 for k in all_headers if k.lower() == "from")
    if from_count > 1:
        findings["anomalies"].append({
            "type": "multiple_from_headers",
            "severity": "critical",
            "message": f"Email contains {from_count} From headers -- header injection attack",
            "details": {"from_count": from_count},
        })


# ── Auth failures → anomalies ─────────────────────────────────────────────────

def _check_auth_failures(parsed_email: Dict, findings: Dict):
    """Convert authentication failures into anomaly entries."""
    auth = findings.get("authentication", {})

    if auth.get("spf", {}).get("status") in ("fail", "softfail"):
        findings["anomalies"].append({
            "type": "spf_fail",
            "severity": "critical",
            "message": f"SPF check {auth['spf']['status']} -- sender IP not authorized for this domain",
            "details": auth["spf"],
        })

    if auth.get("dkim", {}).get("status") == "fail":
        findings["anomalies"].append({
            "type": "dkim_fail",
            "severity": "critical",
            "message": "DKIM signature verification failed -- email may have been tampered with",
            "details": auth["dkim"],
        })

    if auth.get("dmarc", {}).get("status") == "fail":
        findings["anomalies"].append({
            "type": "dmarc_fail",
            "severity": "critical",
            "message": "DMARC check failed -- email fails domain authentication policy",
            "details": auth["dmarc"],
        })

    # NEW: if SPF and DKIM both fail → DMARC MUST fail even if not reported
    spf_bad  = auth.get("spf",  {}).get("status") in ("fail", "softfail", "unknown")
    dkim_bad = auth.get("dkim", {}).get("status") in ("fail", "unknown")
    dmarc_unknown = auth.get("dmarc", {}).get("status") == "unknown"
    if spf_bad and dkim_bad and dmarc_unknown:
        findings["anomalies"].append({
            "type": "inferred_dmarc_fail",
            "severity": "warning",
            "message": "Both SPF and DKIM failed/unknown -- DMARC would likely fail even if not checked",
            "details": {},
        })


# ── CLI testing ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    import json
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from src.parser import parse_eml_file

    if len(sys.argv) < 2:
        print("Usage: python -m src.header_analysis <path_to_eml>")
        sys.exit(1)

    parsed = parse_eml_file(sys.argv[1])
    results = analyze_headers(parsed)
    print(json.dumps(results, indent=2, default=str))
