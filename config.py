"""
config.py -- Central configuration for Email Threat Analyzer.

Loads API keys from .env, defines risk scoring weights,
MITRE ATT&CK mappings, and all tunable constants.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# API Keys
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
MODELS_DIR = os.path.join(BASE_DIR, "models")
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")
DATA_DIR = os.path.join(BASE_DIR, "data")

os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(SAMPLES_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

# ML Model Configuration
PHISHING_MODEL_PATH = os.path.join(MODELS_DIR, "phishing_model", "phishing-distilbert")
ML_CONFIDENCE_THRESHOLD = 0.7

# Rate Limiting (requests per minute)
RATE_LIMITS = {
    "virustotal": 4,
    "abuseipdb": 60,
    "urlscan": 10,
    "otx": 30,
}

# Risk Scoring Weights
RISK_WEIGHTS = {
    # Header anomaly weights
    "spf_fail":                      15,
    "dkim_fail":                     15,
    "dmarc_fail":                    15,
    "from_domain_mismatch":          20,
    "reply_to_mismatch":             10,
    "return_path_mismatch":           8,   # new
    "missing_auth_headers":           5,
    "missing_message_id":             5,
    "suspicious_hop":                 5,
    "brand_impersonation":            5,
    "suspicious_mailer":              5,
    "typosquatting_domain":          20,   # new
    "homoglyph_domain":              20,   # new — IDN homograph
    "homoglyph_display_name":        10,   # new
    "lookalike_tld":                 20,   # new
    "multiple_from_headers":         25,   # new — header injection
    "inferred_dmarc_fail":           10,   # new
    "urgency_subject":                5,   # new
    "encoded_subject":                5,   # new
    "excessive_encoding":            10,   # new
    "html_in_text_body":             15,   # new
    "content_type_mismatch":          5,   # new
    "no_received_headers":           10,
    "excessive_hops":                 5,
    # Enrichment weights
    "malicious_url_vt":              25,
    "malicious_ip_vt":               20,
    "malicious_domain_vt":           20,
    "high_abuse_score":              20,
    "suspicious_url_urlscan":        15,
    "otx_pulse_match":               15,
    "known_phishing_url":            25,
    # ML weights
    "ml_phishing_high_confidence":   25,
    "ml_phishing_medium_confidence": 15,
    # Attachment weights
    "dangerous_file_extension":      20,
    "double_extension":              25,   # new
    "macro_enabled_document":        25,
    "vba_project_detected":          30,
    "attachment_vt_malicious":       30,
    "file_type_mismatch":            15,
    "pdf_dangerous_keywords":        25,   # new — JS/Launch/OpenAction
    "pdf_encrypted":                 10,   # new
    "pdf_suspicious_structure":       8,   # new
    "password_protected_archive":    15,   # new
    "suspicious_binary_blob":        10,   # new
    # Content weights
    "urgency_language":              10,
    "credential_harvesting_indicators": 15,
    "financial_scam_indicators":     15,
}

RISK_THRESHOLDS = {
    "low": (0, 25),
    "medium": (26, 50),
    "high": (51, 75),
    "critical": (76, 100),
}

# Dangerous File Extensions
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".ps1", ".psm1", ".msi", ".msp", ".mst",
    ".cpl", ".hta", ".inf", ".reg",
    ".dll", ".ocx", ".sys",
}

MACRO_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm",
    ".xlam", ".ppam", ".sldm",
}

# MITRE ATT&CK Technique Mapping
MITRE_MAPPING = {
    "phishing_email": {
        "id": "T1566",
        "name": "Phishing",
        "description": "Adversary sends phishing message to gain access to victim systems.",
        "tactic": "Initial Access",
    },
    "phishing_attachment": {
        "id": "T1566.001",
        "name": "Phishing: Spearphishing Attachment",
        "description": "Adversary sends spearphishing email with malicious attachment.",
        "tactic": "Initial Access",
    },
    "phishing_link": {
        "id": "T1566.002",
        "name": "Phishing: Spearphishing Link",
        "description": "Adversary sends spearphishing email with malicious link.",
        "tactic": "Initial Access",
    },
    "credential_harvesting": {
        "id": "T1598.003",
        "name": "Phishing for Information: Spearphishing Link",
        "description": "Adversary sends phishing messages to elicit sensitive information via link.",
        "tactic": "Reconnaissance",
    },
    "bec_impersonation": {
        "id": "T1534",
        "name": "Internal Spearphishing",
        "description": "Adversary uses existing access to send spearphishing emails within the organization.",
        "tactic": "Lateral Movement",
    },
    "malicious_macro": {
        "id": "T1204.002",
        "name": "User Execution: Malicious File",
        "description": "Adversary relies on user to open a malicious file containing macros.",
        "tactic": "Execution",
    },
    "obfuscated_files": {
        "id": "T1027",
        "name": "Obfuscated Files or Information",
        "description": "Adversary uses obfuscation to evade detection.",
        "tactic": "Defense Evasion",
    },
    "data_exfiltration": {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "description": "Adversary exfiltrates data over command and control channel.",
        "tactic": "Exfiltration",
    },
    "domain_spoofing": {
        "id": "T1583.001",
        "name": "Acquire Infrastructure: Domains",
        "description": "Adversary acquires domains that can be used for phishing.",
        "tactic": "Resource Development",
    },
}

# Urgency / Phishing Language Patterns
URGENCY_KEYWORDS = [
    "urgent", "immediately", "suspend", "verify your account",
    "confirm your identity", "unusual activity", "unauthorized access",
    "click here now", "act now", "expire", "limited time",
    "your account will be", "failure to", "within 24 hours",
    "within 48 hours", "account will be closed",
]

CREDENTIAL_HARVEST_KEYWORDS = [
    "enter your password", "verify your credentials", "login here",
    "update your payment", "confirm your bank", "social security",
    "credit card number", "reset your password", "sign in to",
    "validate your account",
]

FINANCIAL_SCAM_KEYWORDS = [
    "wire transfer", "western union", "moneygram", "bitcoin",
    "inheritance", "lottery winner", "prince", "beneficiary",
    "processing fee", "million dollars", "million usd",
    "claim your prize", "bank details",
]

# Groq LLM Configuration
# llama-3.1-70b-versatile was deprecated — use 3.3 now
# fallback list tried in order if primary fails
GROQ_MODEL = "llama-3.3-70b-versatile"
GROQ_MODEL_FALLBACKS = [
    "llama-3.3-70b-versatile",
    "llama3-70b-8192",
    "llama-3.1-8b-instant",
    "mixtral-8x7b-32768",
]
GROQ_MAX_TOKENS = 2048
GROQ_TEMPERATURE = 0.3
