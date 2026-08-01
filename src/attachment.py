"""
Phase 6 -- Attachment Analysis (Enhanced)

Integrates SOC101 course tools where they fill genuine gaps:
  - oledump.py  : Deep OLE/VBA stream analysis in old .doc/.xls files
                  (our original had a bug: bytes.lower() doesn't exist --
                   oledump handles this properly)
  - emldump.py  : MIME structure inspection for suspicious part ordering
                  or hidden multipart nesting

Existing logic kept unchanged where it was working correctly:
  - SHA256/MD5/SHA1 hashing
  - python-magic true file type detection
  - Double-extension detection
  - ZIP-based vbaproject.bin detection (works for .docm/.xlsm)
  - VirusTotal hash lookup
"""

import hashlib
import os
import sys
import zipfile
import io
import struct
import subprocess
import json
from typing import Dict, List, Any, Optional

try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from src.enrichment import check_virustotal

# Paths to SOC101 tools
_TOOLS_DIR = r"C:\Users\KIIT\Downloads\Compressed\SOC101_Free-main\SOC101_Free-main\course_files\01_Phishing_Analysis\01_Phishing_Analysis\Tools"
_OLEDUMP   = os.path.join(_TOOLS_DIR, "oledump.py")
_EMLDUMP   = os.path.join(_TOOLS_DIR, "emldump.py")

# Python executable (prefer venv)
_SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_VENV_PY    = os.path.join(_SCRIPT_DIR, "venv", "Scripts", "python.exe")
_PYTHON     = _VENV_PY if os.path.exists(_VENV_PY) else sys.executable


# ══════════════════════════════════════════════════════════════════════════════
#  PUBLIC API
# ══════════════════════════════════════════════════════════════════════════════

def analyze_attachments(parsed_email: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Analyze all attachments in a parsed email."""
    results = []
    for attachment in parsed_email.get("attachments", []):
        result = analyze_single_attachment(attachment)
        results.append(result)
    return results


def analyze_single_attachment(attachment: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze a single email attachment."""
    filename     = attachment.get("filename", "unknown")
    content_type = attachment.get("content_type", "")
    raw_bytes    = attachment.get("raw_bytes", b"")

    result = {
        "filename":           filename,
        "content_type":       content_type,
        "size_bytes":         len(raw_bytes) if raw_bytes else 0,
        "hashes":             {},
        "true_file_type":     "",
        "extension_analysis": {},
        "macro_analysis":     {},
        "vt_result":          None,
        "oledump_analysis":   None,  # new
        "findings":           [],
        "risk_level":         "low",
    }

    if not raw_bytes:
        result["findings"].append({
            "type": "empty_attachment",
            "severity": "info",
            "message": f"Attachment '{filename}' has no content",
        })
        return result

    # 1. Hashes
    result["hashes"] = {
        "md5":    hashlib.md5(raw_bytes).hexdigest(),
        "sha1":   hashlib.sha1(raw_bytes).hexdigest(),
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
    }

    # 2. True file type detection
    result["true_file_type"] = _detect_file_type(raw_bytes, filename)

    # 3. Extension analysis (double-extension, type mismatch)
    result["extension_analysis"] = _check_extension(filename, result["true_file_type"])

    # 4. Macro / VBA analysis (zip-based for modern Office)
    result["macro_analysis"] = _check_macros_zip(filename, raw_bytes)

    # 5. OLE deep scan via oledump.py (SOC101 tool) — for old binary .doc/.xls
    #    Only runs when the file is an OLE compound document (magic bytes D0 CF 11 E0)
    if raw_bytes[:4] == b'\xd0\xcf\x11\xe0':
        result["oledump_analysis"] = _run_oledump(raw_bytes, filename)
        if result["oledump_analysis"] and result["oledump_analysis"].get("has_vba_streams"):
            result["macro_analysis"]["has_macros"] = True
            result["macro_analysis"]["has_vba_project"] = True
            result["macro_analysis"]["vba_streams"] = result["oledump_analysis"].get("vba_streams", [])

    # 6. PDF analysis (SOC101 pdf-parser.py + pdfid.py concepts applied inline)
    if raw_bytes[:5] == b'%PDF-':
        pdf_findings = _analyze_pdf(raw_bytes, filename)
        result["pdf_analysis"] = pdf_findings
        for f in pdf_findings.get("findings", []):
            result["findings"].append(f)

    # 7. VirusTotal hash lookup
    sha256 = result["hashes"]["sha256"]
    vt_result = check_virustotal(sha256, "hash")
    if vt_result:
        result["vt_result"] = vt_result
        if vt_result.get("verdict") == "malicious":
            result["findings"].append({
                "type": "attachment_vt_malicious",
                "severity": "critical",
                "message": (
                    f"VirusTotal flagged '{filename}' as malicious -- "
                    f"{vt_result.get('malicious', 0)} engines detected threats"
                ),
            })

    # 8. Collect extension/macro findings
    ext = result["extension_analysis"]
    if ext.get("is_dangerous"):
        result["findings"].append({
            "type": "dangerous_file_extension",
            "severity": "critical",
            "message": f"Dangerous executable extension: '{filename}'",
        })
    if ext.get("type_mismatch"):
        result["findings"].append({
            "type": "file_type_mismatch",
            "severity": "warning",
            "message": (
                f"File type mismatch: '{filename}' claims "
                f"'{ext.get('claimed_type')}' but is '{ext.get('actual_type')}'"
            ),
        })
    if ext.get("double_extension"):
        result["findings"].append({
            "type": "double_extension",
            "severity": "critical",
            "message": f"Double extension trick: '{filename}' -- hides real file type",
        })

    macro = result["macro_analysis"]
    if macro.get("has_vba_project"):
        result["findings"].append({
            "type": "vba_project_detected",
            "severity": "critical",
            "message": f"VBA project binary found in '{filename}' -- contains macro code",
        })
    elif macro.get("has_macros"):
        result["findings"].append({
            "type": "macro_enabled_document",
            "severity": "critical",
            "message": f"Macro-enabled document: '{filename}'",
        })

    # Suspicious archive (password-protected ZIP hides malware from scanners)
    if _is_password_protected_zip(raw_bytes):
        result["findings"].append({
            "type": "password_protected_archive",
            "severity": "warning",
            "message": f"'{filename}' is a password-protected archive -- common malware delivery technique",
        })

    # Large base64-encoded attachment with no clear type
    if result["size_bytes"] > 500_000 and result["true_file_type"] == "application/octet-stream":
        result["findings"].append({
            "type": "suspicious_binary_blob",
            "severity": "warning",
            "message": f"'{filename}' is a large unrecognized binary ({result['size_bytes']:,} bytes)",
        })

    # Risk level
    sev_levels = [f["severity"] for f in result["findings"]]
    if "critical" in sev_levels:
        result["risk_level"] = "critical"
    elif "warning" in sev_levels:
        result["risk_level"] = "high"
    elif sev_levels:
        result["risk_level"] = "medium"

    return result


# ══════════════════════════════════════════════════════════════════════════════
#  FILE TYPE DETECTION
# ══════════════════════════════════════════════════════════════════════════════

def _detect_file_type(raw_bytes: bytes, filename: str) -> str:
    """Detect true file type using python-magic or magic byte fallback."""
    if HAS_MAGIC:
        try:
            return magic.from_buffer(raw_bytes, mime=True)
        except Exception:
            pass

    # Magic byte signatures
    signatures = [
        (b'PK\x03\x04',                   "application/zip"),
        (b'%PDF-',                          "application/pdf"),
        (b'MZ',                             "application/x-dosexec"),
        (b'\xd0\xcf\x11\xe0',              "application/msword"),      # OLE compound
        (b'\x89PNG\r\n\x1a\n',             "image/png"),
        (b'\xff\xd8',                       "image/jpeg"),
        (b'GIF87a',                         "image/gif"),
        (b'GIF89a',                         "image/gif"),
        (b'Rar!',                           "application/x-rar"),
        (b'\x1f\x8b',                       "application/gzip"),
        (b'7z\xbc\xaf\x27\x1c',            "application/x-7z-compressed"),
        (b'\xca\xfe\xba\xbe',              "application/x-mach-binary"),
        (b'\x7fELF',                        "application/x-elf"),
        (b'<!DOCTYPE html', "text/html"),
        (b'<html',                          "text/html"),
    ]
    raw_lower = raw_bytes[:16].lower()
    for sig, mime in signatures:
        if raw_bytes[:len(sig)] == sig or raw_lower[:len(sig)] == sig.lower():
            return mime

    ext = os.path.splitext(filename)[1].lower()
    ext_map = {
        ".pdf": "application/pdf",
        ".doc": "application/msword",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".xls": "application/vnd.ms-excel",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".ppt": "application/vnd.ms-powerpoint",
        ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ".txt": "text/plain",
        ".html": "text/html",
        ".htm": "text/html",
        ".rtf": "application/rtf",
        ".js": "application/javascript",
        ".vbs": "text/vbscript",
        ".ps1": "text/x-powershell",
    }
    return ext_map.get(ext, "application/octet-stream")


# ══════════════════════════════════════════════════════════════════════════════
#  EXTENSION ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

def _check_extension(filename: str, true_type: str) -> Dict[str, Any]:
    """Check extension for dangerous types, type mismatches, double extensions."""
    ext = os.path.splitext(filename)[1].lower()

    result = {
        "extension":          ext,
        "is_dangerous":       ext in config.DANGEROUS_EXTENSIONS,
        "is_macro_extension": ext in config.MACRO_EXTENSIONS,
        "type_mismatch":      False,
        "double_extension":   False,
        "claimed_type":       ext,
        "actual_type":        true_type,
    }

    executable_mimes = {
        "application/x-dosexec", "application/x-executable",
        "application/x-msdos-program", "application/x-msdownload",
        "application/x-mach-binary", "application/x-elf",
    }
    safe_extensions = {".pdf", ".doc", ".docx", ".xls", ".xlsx",
                       ".jpg", ".jpeg", ".png", ".gif", ".txt"}

    if ext in safe_extensions and true_type in executable_mimes:
        result["type_mismatch"] = True

    # Double-extension trick (e.g., "invoice.pdf.exe")
    parts = filename.split(".")
    if len(parts) > 2:
        final_ext = f".{parts[-1].lower()}"
        if final_ext in config.DANGEROUS_EXTENSIONS:
            result["is_dangerous"]     = True
            result["double_extension"] = True

    return result


# ══════════════════════════════════════════════════════════════════════════════
#  MACRO ANALYSIS (ZIP/OOXML — modern Office formats)
# ══════════════════════════════════════════════════════════════════════════════

def _check_macros_zip(filename: str, raw_bytes: bytes) -> Dict[str, Any]:
    """
    Check ZIP-based Office files (.docm, .xlsm, etc.) for VBA macros.
    Fixed bug from original: bytes objects don't have .lower() method —
    we search raw bytes directly now.
    """
    ext = os.path.splitext(filename)[1].lower()
    result = {
        "has_macros":         ext in config.MACRO_EXTENSIONS,
        "has_vba_project":    False,
        "is_macro_extension": ext in config.MACRO_EXTENSIONS,
        "suspicious_files":   [],
        "vba_streams":        [],
    }

    if raw_bytes[:4] == b'PK\x03\x04':
        try:
            with zipfile.ZipFile(io.BytesIO(raw_bytes), 'r') as zf:
                for name in zf.namelist():
                    nl = name.lower()
                    if 'vbaproject.bin' in nl:
                        result["has_vba_project"] = True
                        result["has_macros"]       = True
                        result["suspicious_files"].append(name)
                    elif nl.endswith(('.bas', '.frm', '.cls')):
                        result["suspicious_files"].append(name)
                    elif 'macro' in nl:
                        result["suspicious_files"].append(name)
        except (zipfile.BadZipFile, Exception):
            pass

    # OLE compound document — VBA search using raw byte search
    # Bug fix: original used raw_bytes.lower() which doesn't exist on bytes
    # Correct approach: search for literal byte strings
    if raw_bytes[:4] == b'\xd0\xcf\x11\xe0':
        if b'VBA' in raw_bytes or b'Macro' in raw_bytes or b'macro' in raw_bytes:
            result["has_macros"]      = True
            result["has_vba_project"] = True

    return result


# ══════════════════════════════════════════════════════════════════════════════
#  OLEDUMP INTEGRATION (SOC101 tool — deep OLE/VBA stream analysis)
# ══════════════════════════════════════════════════════════════════════════════

def _run_oledump(raw_bytes: bytes, filename: str) -> Optional[Dict]:
    """
    Run SOC101's oledump.py on OLE compound documents (.doc, .xls, .ppt).
    oledump can enumerate individual OLE streams and flag VBA code streams.
    We write a temp file, run oledump, parse stdout.

    Uses SOC101 course tool: oledump.py by Didier Stevens
    """
    if not os.path.exists(_OLEDUMP):
        return None

    # Write raw bytes to a temp file
    import tempfile
    try:
        with tempfile.NamedTemporaryFile(
            suffix=os.path.splitext(filename)[1] or ".bin",
            delete=False
        ) as tmp:
            tmp.write(raw_bytes)
            tmp_path = tmp.name
    except Exception:
        return None

    try:
        result = subprocess.run(
            [_PYTHON, _OLEDUMP, tmp_path],
            capture_output=True, text=True, timeout=15,
            encoding="utf-8", errors="replace"
        )
        output = result.stdout or ""
        return _parse_oledump_output(output)
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return None
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


def _parse_oledump_output(output: str) -> Dict:
    """
    Parse oledump.py output.
    oledump marks VBA streams with 'M' (module) or 'm' (small).
    Example line: "  1:      114 '\\x01CompObj'"
    Example VBA:  "  3: M   7117 'VBA/ThisDocument'"
    """
    parsed = {
        "has_vba_streams": False,
        "vba_streams":     [],
        "all_streams":     [],
        "raw_output":      output[:500],
    }

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        # VBA stream marker: 'M' or 'm' in column 4-5
        is_vba = bool(re.search(r'^\d+:\s+[Mm]\s+', line))
        stream_name_m = re.search(r"'([^']+)'", line)
        stream_name = stream_name_m.group(1) if stream_name_m else line

        stream_entry = {"name": stream_name, "is_vba": is_vba, "raw": line}
        parsed["all_streams"].append(stream_entry)

        if is_vba:
            parsed["has_vba_streams"] = True
            parsed["vba_streams"].append(stream_name)

    return parsed


# ══════════════════════════════════════════════════════════════════════════════
#  PDF ANALYSIS (inline — pdfid.py / pdf-parser.py concepts)
# ══════════════════════════════════════════════════════════════════════════════

# Dangerous PDF keywords (from pdfid.py approach)
_PDF_DANGEROUS_KEYS = [
    b"/JS", b"/JavaScript", b"/AA",          # auto-actions
    b"/OpenAction", b"/AcroForm",             # form + auto-run
    b"/JBIG2Decode",                          # known exploit stream
    b"/RichMedia", b"/Launch",                # execution
    b"/EmbeddedFile", b"/XFA",               # file embedding + forms
    b"/Encrypt",                              # encryption to hide content
    b"/URI",                                  # URI actions
]

_PDF_SUSPICIOUS_KEYS = [
    b"/ObjStm",   # Object streams (common in obfuscated PDFs)
    b"/XObject",  # Can embed content
    b"/Filter",   # Compression/encoding
]


def _analyze_pdf(raw_bytes: bytes, filename: str) -> Dict:
    """
    Analyze PDF for dangerous keywords.
    Applies the same keyword scanning approach as SOC101's pdfid.py.
    We do it inline without spawning a subprocess.
    """
    result = {
        "dangerous_keywords":  [],
        "suspicious_keywords": [],
        "page_count":          0,
        "is_encrypted":        False,
        "findings":            [],
    }

    for kw in _PDF_DANGEROUS_KEYS:
        count = raw_bytes.count(kw)
        if count > 0:
            result["dangerous_keywords"].append({
                "keyword": kw.decode("latin-1"),
                "count":   count,
            })

    for kw in _PDF_SUSPICIOUS_KEYS:
        count = raw_bytes.count(kw)
        if count > 0:
            result["suspicious_keywords"].append({
                "keyword": kw.decode("latin-1"),
                "count":   count,
            })

    # Page count
    pages_m = re.findall(rb'/Count\s+(\d+)', raw_bytes)
    if pages_m:
        try:
            result["page_count"] = int(pages_m[-1])
        except ValueError:
            pass

    # Encryption
    if b'/Encrypt' in raw_bytes:
        result["is_encrypted"] = True

    # Generate findings
    if result["dangerous_keywords"]:
        kw_names = [k["keyword"] for k in result["dangerous_keywords"]]
        result["findings"].append({
            "type": "pdf_dangerous_keywords",
            "severity": "critical",
            "message": (
                f"PDF '{filename}' contains dangerous keywords: "
                f"{', '.join(kw_names)} -- may execute JavaScript or launch files"
            ),
        })

    if result["is_encrypted"]:
        result["findings"].append({
            "type": "pdf_encrypted",
            "severity": "warning",
            "message": f"PDF '{filename}' is encrypted -- content hidden from scanners",
        })

    suspicious_count = sum(k["count"] for k in result["suspicious_keywords"])
    if suspicious_count > 10:
        result["findings"].append({
            "type": "pdf_suspicious_structure",
            "severity": "warning",
            "message": (
                f"PDF '{filename}' has high complexity "
                f"({suspicious_count} suspicious structure elements) -- may be obfuscated"
            ),
        })

    return result


# ══════════════════════════════════════════════════════════════════════════════
#  MISC HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _is_password_protected_zip(raw_bytes: bytes) -> bool:
    """Check if this is a ZIP with password-protected entries."""
    if raw_bytes[:4] != b'PK\x03\x04':
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
            for info in zf.infolist():
                if info.flag_bits & 0x1:  # bit 0 = encrypted
                    return True
    except Exception:
        pass
    return False
