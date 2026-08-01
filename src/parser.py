"""
Phase 1 — Email Parser

Reads .eml files and extracts all relevant components:
- Headers: From, To, Subject, Date, Reply-To, Message-ID
- All Received headers (hop chain)
- Authentication-Results header
- Plain text body and HTML body
- Attachments with filenames, content types, and raw bytes

Returns a structured dictionary for downstream phases.
"""

import email
import email.policy
from email import message_from_file, message_from_bytes
from email.utils import parseaddr, parsedate_to_datetime
from typing import Dict, List, Optional, Any
import os


def parse_eml_file(file_path: str) -> Dict[str, Any]:
    """
    Parse a .eml file and extract all components.

    Args:
        file_path: Path to the .eml file

    Returns:
        Dictionary containing all parsed email components
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Email file not found: {file_path}")

    with open(file_path, "rb") as f:
        raw_bytes = f.read()

    msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)

    parsed = {
        "file_path": file_path,
        "file_name": os.path.basename(file_path),

        # ── Core headers ──
        "from": msg.get("From", ""),
        "from_name": "",
        "from_address": "",
        "to": msg.get("To", ""),
        "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""),
        "reply_to": msg.get("Reply-To", ""),
        "message_id": msg.get("Message-ID", ""),
        "return_path": msg.get("Return-Path", ""),
        "x_mailer": msg.get("X-Mailer", ""),

        # ── Authentication headers ──
        "authentication_results": msg.get("Authentication-Results", ""),
        "received_spf": msg.get("Received-SPF", ""),
        "dkim_signature": msg.get("DKIM-Signature", ""),

        # ── Received headers (hop chain) ──
        "received_headers": [],

        # ── Bodies ──
        "body_plain": "",
        "body_html": "",

        # ── Attachments ──
        "attachments": [],

        # ── Raw headers for advanced analysis ──
        "all_headers": {},
    }

    # Parse From into name and address
    from_name, from_addr = parseaddr(parsed["from"])
    parsed["from_name"] = from_name
    parsed["from_address"] = from_addr

    # Parse date
    try:
        if parsed["date"]:
            parsed["date_parsed"] = parsedate_to_datetime(parsed["date"])
        else:
            parsed["date_parsed"] = None
    except Exception:
        parsed["date_parsed"] = None

    # ── Collect ALL Received headers in order ──
    received_headers = msg.get_all("Received", [])
    parsed["received_headers"] = [str(h) for h in received_headers]

    # ── Collect all headers ──
    for key in msg.keys():
        if key.lower() not in parsed["all_headers"]:
            parsed["all_headers"][key.lower()] = []
        parsed["all_headers"][key.lower()].append(str(msg.get(key, "")))

    # ── Extract bodies and attachments ──
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            # Check if it's an attachment
            if "attachment" in content_disposition or part.get_filename():
                attachment = _extract_attachment(part)
                if attachment:
                    parsed["attachments"].append(attachment)
            elif content_type == "text/plain" and not parsed["body_plain"]:
                try:
                    body = part.get_content()
                    if isinstance(body, bytes):
                        body = body.decode("utf-8", errors="replace")
                    parsed["body_plain"] = body
                except Exception:
                    try:
                        parsed["body_plain"] = part.get_payload(decode=True).decode(
                            "utf-8", errors="replace"
                        )
                    except Exception:
                        pass
            elif content_type == "text/html" and not parsed["body_html"]:
                try:
                    body = part.get_content()
                    if isinstance(body, bytes):
                        body = body.decode("utf-8", errors="replace")
                    parsed["body_html"] = body
                except Exception:
                    try:
                        parsed["body_html"] = part.get_payload(decode=True).decode(
                            "utf-8", errors="replace"
                        )
                    except Exception:
                        pass
    else:
        # Single-part message
        content_type = msg.get_content_type()
        try:
            body = msg.get_content()
            if isinstance(body, bytes):
                body = body.decode("utf-8", errors="replace")
        except Exception:
            try:
                body = msg.get_payload(decode=True).decode("utf-8", errors="replace")
            except Exception:
                body = ""

        if content_type == "text/html":
            parsed["body_html"] = body
        else:
            parsed["body_plain"] = body

    # ── Summary stats ──
    parsed["has_attachments"] = len(parsed["attachments"]) > 0
    parsed["attachment_count"] = len(parsed["attachments"])
    parsed["hop_count"] = len(parsed["received_headers"])

    return parsed


def _extract_attachment(part) -> Optional[Dict[str, Any]]:
    """Extract attachment metadata and raw bytes from an email part."""
    filename = part.get_filename()
    if not filename:
        # Try to generate a name from content type
        ext = part.get_content_type().split("/")[-1]
        filename = f"unnamed_attachment.{ext}"

    try:
        raw_bytes = part.get_payload(decode=True)
        if raw_bytes is None:
            return None
    except Exception:
        return None

    return {
        "filename": filename,
        "content_type": part.get_content_type(),
        "size_bytes": len(raw_bytes) if raw_bytes else 0,
        "raw_bytes": raw_bytes,
    }


def get_combined_body_text(parsed_email: Dict) -> str:
    """Get combined plain text from both body types for analysis."""
    text_parts = []

    if parsed_email.get("body_plain"):
        text_parts.append(parsed_email["body_plain"])

    if parsed_email.get("body_html"):
        # Strip HTML tags for text analysis
        from bs4 import BeautifulSoup
        try:
            soup = BeautifulSoup(parsed_email["body_html"], "html.parser")
            html_text = soup.get_text(separator=" ", strip=True)
            if html_text and html_text not in text_parts:
                text_parts.append(html_text)
        except Exception:
            pass

    return "\n".join(text_parts)


# ── CLI testing ──
if __name__ == "__main__":
    import sys
    import json

    if len(sys.argv) < 2:
        print("Usage: python -m src.parser <path_to_eml>")
        sys.exit(1)

    result = parse_eml_file(sys.argv[1])

    # Print without raw bytes (not JSON-serializable)
    display = {k: v for k, v in result.items() if k != "attachments"}
    display["attachments"] = [
        {k: v for k, v in att.items() if k != "raw_bytes"}
        for att in result["attachments"]
    ]

    # Convert datetime to string for JSON
    if display.get("date_parsed"):
        display["date_parsed"] = str(display["date_parsed"])

    print(json.dumps(display, indent=2, default=str))
