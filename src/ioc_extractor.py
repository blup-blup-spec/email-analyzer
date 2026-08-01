"""
Phase 3 -- IOC (Indicator of Compromise) Extraction

Extracts all IOCs from email body and attachments:
- IP addresses (IPv4 and IPv6)
- Domain names
- URLs (defanged and normal)
- Email addresses
- File hashes (MD5, SHA1, SHA256) for attachments

Uses iocextract for robust extraction from both
plain text and HTML bodies.
"""

import re
import hashlib
from typing import Dict, List, Any, Set
from bs4 import BeautifulSoup

try:
    import iocextract
    HAS_IOCEXTRACT = True
except ImportError:
    HAS_IOCEXTRACT = False


def extract_iocs(parsed_email: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract all IOCs from a parsed email.

    Args:
        parsed_email: Output from parser.parse_eml_file()

    Returns:
        Dictionary of IOCs categorized by type
    """
    iocs = {
        "urls": [],
        "ips": [],
        "domains": [],
        "emails": [],
        "hashes": [],
        "total_count": 0,
    }

    # Get text content
    plain_text = parsed_email.get("body_plain", "") or ""
    html_body = parsed_email.get("body_html", "") or ""

    # Strip HTML tags to get clean text from HTML body
    html_text = ""
    if html_body:
        try:
            soup = BeautifulSoup(html_body, "html.parser")
            html_text = soup.get_text(separator=" ", strip=True)

            # Also extract URLs from href attributes
            for link in soup.find_all("a", href=True):
                href = link["href"].strip()
                if href and href.startswith(("http://", "https://", "ftp://")):
                    iocs["urls"].append(href)

            # Extract URLs from img src
            for img in soup.find_all("img", src=True):
                src = img["src"].strip()
                if src and src.startswith(("http://", "https://")):
                    iocs["urls"].append(src)

        except Exception:
            html_text = re.sub(r'<[^>]+>', ' ', html_body)

    combined_text = f"{plain_text}\n{html_text}"

    # Extract IOCs using iocextract
    if HAS_IOCEXTRACT:
        _extract_with_iocextract(combined_text, iocs)
    else:
        _extract_with_regex(combined_text, iocs)

    # Extract from HTML body separately (catches obfuscated IOCs)
    if html_body and HAS_IOCEXTRACT:
        _extract_with_iocextract(html_body, iocs)

    # Compute file hashes for attachments
    for attachment in parsed_email.get("attachments", []):
        raw_bytes = attachment.get("raw_bytes")
        if raw_bytes:
            hash_info = _compute_hashes(raw_bytes, attachment.get("filename", "unknown"))
            iocs["hashes"].append(hash_info)

    # Deduplicate
    iocs["urls"] = list(set(iocs["urls"]))
    iocs["ips"] = list(set(iocs["ips"]))
    iocs["domains"] = list(set(iocs["domains"]))
    iocs["emails"] = list(set(iocs["emails"]))

    # Filter out internal/private IPs from analysis targets
    iocs["public_ips"] = [ip for ip in iocs["ips"] if not _is_private_ip(ip)]

    # Total count
    iocs["total_count"] = (
        len(iocs["urls"]) + len(iocs["ips"]) +
        len(iocs["domains"]) + len(iocs["emails"]) +
        len(iocs["hashes"])
    )

    return iocs


def _extract_with_iocextract(text: str, iocs: Dict):
    """Use iocextract library for robust IOC extraction."""
    try:
        for url in iocextract.extract_urls(text, refang=True):
            url = url.strip().rstrip(".,;:>)")
            if len(url) > 10:
                iocs["urls"].append(url)
    except Exception:
        pass

    try:
        for ip in iocextract.extract_ipv4s(text, refang=True):
            iocs["ips"].append(ip.strip())
    except Exception:
        pass

    try:
        for ip in iocextract.extract_ipv6s(text):
            iocs["ips"].append(ip.strip())
    except Exception:
        pass

    try:
        for addr in iocextract.extract_emails(text, refang=True):
            iocs["emails"].append(addr.strip().lower())
    except Exception:
        pass

    # Extract domains from URLs
    for url in iocs["urls"]:
        domain = _extract_domain_from_url(url)
        if domain:
            iocs["domains"].append(domain)


def _extract_with_regex(text: str, iocs: Dict):
    """Fallback regex-based IOC extraction if iocextract not available."""
    url_pattern = re.compile(r'https?://[^\s<>"\'`\])}]+', re.IGNORECASE)
    for match in url_pattern.finditer(text):
        url = match.group(0).rstrip(".,;:>)")
        iocs["urls"].append(url)

    ipv4_pattern = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    )
    for match in ipv4_pattern.finditer(text):
        iocs["ips"].append(match.group(0))

    email_pattern = re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    )
    for match in email_pattern.finditer(text):
        iocs["emails"].append(match.group(0).lower())

    for url in iocs["urls"]:
        domain = _extract_domain_from_url(url)
        if domain:
            iocs["domains"].append(domain)


def _extract_domain_from_url(url: str) -> str:
    """Extract domain name from a URL."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.hostname
        if domain:
            return domain.lower()
    except Exception:
        pass
    return ""


def _compute_hashes(raw_bytes: bytes, filename: str) -> Dict[str, str]:
    """Compute MD5, SHA1, and SHA256 hashes for file bytes."""
    return {
        "filename": filename,
        "md5": hashlib.md5(raw_bytes).hexdigest(),
        "sha1": hashlib.sha1(raw_bytes).hexdigest(),
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "size_bytes": len(raw_bytes),
    }


def _is_private_ip(ip: str) -> bool:
    """Check if an IP address is private/reserved."""
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_reserved or addr.is_loopback
    except (ValueError, TypeError):
        return False
