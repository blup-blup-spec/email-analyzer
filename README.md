# Email Threat Analysis Platform (ETA)
### Complete Technical Guide — Updated August 2026

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Full Project Structure](#2-full-project-structure)
3. [Complete Analysis Pipeline](#3-complete-analysis-pipeline)
4. [Phase-by-Phase Deep Dive](#4-phase-by-phase-deep-dive)
   - [Phase 1 — Email Parser](#phase-1--email-parser)
   - [Phase 2 — Header Analysis](#phase-2--header-analysis-enhanced)
   - [Phase 3 — IOC Extraction](#phase-3--ioc-extraction)
   - [Phase 4 — Threat Intel Enrichment](#phase-4--threat-intel-enrichment)
   - [Phase 5 — ML Classifier](#phase-5--ml-classifier-distilbert)
   - [Phase 6 — Attachment Analysis](#phase-6--attachment-analysis-enhanced)
   - [Phase 7 — Risk Scoring](#phase-7--risk-scoring)
   - [Phase 9 — LLM Analyst](#phase-9--llm-analyst-groq)
   - [Phase 8 — PDF Report](#phase-8--pdf-report)
5. [Risk Scoring Reference](#5-risk-scoring-reference)
6. [API Reference — All 4 Tools + When They Fire](#6-api-reference)
7. [The ML Model Explained](#7-the-ml-model-explained)
8. [The LLM Integration Explained](#8-the-llm-integration-explained)
9. [SOC101 Tool Integrations](#9-soc101-tool-integrations)
10. [The GUI — Complete Guide](#10-the-gui--complete-guide)
11. [Output Files Reference](#11-output-files-reference)
12. [Setup & First Run](#12-setup--first-run)
13. [Command Line Reference](#13-command-line-reference)
14. [API Keys — Where to Get Them](#14-api-keys--where-to-get-them)
15. [MITRE ATT&CK Mapping](#15-mitre-attck-mapping)
16. [Configuration Reference](#16-configuration-reference)
17. [Known Limitations](#17-known-limitations)

---

## 1. Project Overview

**ETA (Email Threat Analyzer)** is a fully local, offline-first email security analysis platform. You give it a raw `.eml` email file. It automatically runs 9 analysis phases and produces:

- A live GUI showing exactly what each phase found as it runs
- Per-phase JSON files saved to `output/{email_name}/`
- A structured PDF threat report

**Architecture philosophy:**
- All heavy AI (DistilBERT) runs **locally** on your machine — no data sent anywhere
- Threat intel APIs (VirusTotal, AbuseIPDB, URLScan, OTX) are **optional** — skip with `--no-enrich`
- Groq LLM only receives a **text summary** of findings, not the raw email
- Everything is structured as Python modules — easy to extend or swap components

---

## 2. Full Project Structure

```
email-analyser/
│
├── main.py                    # Orchestrator — runs all 9 phases, emits ##ETA_DATA lines
├── gui.py                     # GUI (raw tkinter, 3-panel resizable layout)
├── config.py                  # All constants: API keys, weights, thresholds, MITRE map
├── requirements.txt           # Python dependencies
├── .env                       # API keys (never commit to git)
├── README.md                  # This file
│
├── src/                       # Analysis modules — one file per phase
│   ├── parser.py              # Phase 1  — raw .eml parsing
│   ├── header_analysis.py     # Phase 2  — SPF/DKIM/DMARC + 18 anomaly checks
│   ├── ioc_extractor.py       # Phase 3  — URL/IP/domain/hash extraction
│   ├── enrichment.py          # Phase 4  — VirusTotal, AbuseIPDB, URLScan, OTX
│   ├── ml_classifier.py       # Phase 5  — DistilBERT phishing classifier
│   ├── attachment.py          # Phase 6  — file type, macros, OLE, PDF analysis
│   ├── risk_scorer.py         # Phase 7  — weighted scoring engine (0–100)
│   ├── llm_analyst.py         # Phase 9  — Groq LLM narrative generation
│   └── report_generator.py   # Phase 8  — PDF generation via fpdf2
│
├── models/
│   └── phishing_model/
│       └── phishing-distilbert/
│           ├── config.json            # Architecture + id2label mapping
│           ├── model.safetensors      # Fine-tuned weights (~267MB)
│           ├── tokenizer_config.json
│           └── vocab.txt              # 30,522 word-piece tokens
│
├── samples/                   # Test .eml files to analyze
│   ├── phishing_sample_1.eml
│   ├── phishing_sample_2.eml
│   └── clean_sample_1.eml
│
├── output/                    # Created at runtime — one folder per email analyzed
│   └── phishing_sample_1/
│       ├── 01_parse.json
│       ├── 02_headers.json
│       ├── 03_iocs.json
│       ├── 04_enrichment.json
│       ├── 05_ml_result.json
│       ├── 06_attachments.json
│       ├── 07_risk_score.json
│       ├── 08_report.json
│       ├── 09_llm_narrative.json
│       └── *.pdf              # PDF report also saved here
│
├── reports/                   # Default PDF output when not using GUI
└── venv/                      # Python virtual environment
```

---

## 3. Complete Analysis Pipeline

```
                         .eml file (input)
                              │
              ┌───────────────▼──────────────────┐
              │     Phase 1 — EMAIL PARSER        │
              │     src/parser.py                 │
              │     Extracts all headers, body,   │
              │     attachments, auth headers      │
              └───────────────┬──────────────────┘
                              │ parsed_email dict
              ┌───────────────▼──────────────────┐
              │   Phase 2 — HEADER ANALYSIS       │
              │   src/header_analysis.py          │
              │   18 anomaly checks incl:         │
              │   SPF/DKIM/DMARC, typosquatting,  │
              │   homoglyphs, X-Originating-IP,   │
              │   Return-Path mismatch, geo-lookup │
              └───────────────┬──────────────────┘
                              │ header_analysis dict
              ┌───────────────▼──────────────────┐
              │   Phase 3 — IOC EXTRACTION        │
              │   src/ioc_extractor.py            │
              │   URLs, IPs, domains, emails,     │
              │   file hashes from body + HTML    │
              └───────────────┬──────────────────┘
                              │ iocs dict
              ┌───────────────▼──────────────────┐
              │   Phase 4 — ENRICHMENT            │
              │   src/enrichment.py               │
              │   VirusTotal  → all IOC types     │
              │   AbuseIPDB   → IPs only          │
              │   URLScan.io  → URLs only         │
              │   OTX         → IPs + domains     │
              └───────────────┬──────────────────┘
                              │ enrichment dict
              ┌───────────────▼──────────────────┐
              │   Phase 5 — ML CLASSIFIER         │
              │   src/ml_classifier.py            │
              │   DistilBERT loads from disk      │
              │   Tokenizes body text             │
              │   Outputs: PHISHING/LEGIT + %     │
              └───────────────┬──────────────────┘
                              │ ml_result dict
              ┌───────────────▼──────────────────┐
              │   Phase 6 — ATTACHMENT ANALYSIS   │
              │   src/attachment.py               │
              │   File type magic, ZIP/VBA scan,  │
              │   oledump.py for OLE files,       │
              │   PDF keyword scan, hashes + VT   │
              └───────────────┬──────────────────┘
                              │ attachment_results list
              ┌───────────────▼──────────────────┐
              │   Phase 7 — RISK SCORING          │
              │   src/risk_scorer.py              │
              │   Weighs ALL phase results        │
              │   Outputs: 0–100 + CRITICAL etc.  │
              └───────────────┬──────────────────┘
                              │ risk_result dict
              ┌───────────────▼──────────────────┐
              │   Phase 9 — LLM ANALYST           │
              │   src/llm_analyst.py              │
              │   Sends summary to Groq           │
              │   llama-3.3-70b-versatile         │
              │   Returns structured JSON         │
              └───────────────┬──────────────────┘
                              │ llm_analysis dict
              ┌───────────────▼──────────────────┐
              │   Phase 8 — PDF REPORT            │
              │   src/report_generator.py         │
              │   Combines all phases into PDF    │
              │   Saved to output/{name}/ + PDF   │
              └──────────────────────────────────┘
```

---

## 4. Phase-by-Phase Deep Dive

---

### Phase 1 — Email Parser
**File:** `src/parser.py`  
**Library:** Python built-in `email`

Reads the raw `.eml` bytes and extracts every field.

**What it pulls out:**

| Field | Header | Notes |
|-------|--------|-------|
| `from_address` | From | Clean `user@domain.com` (display name stripped) |
| `from_name` | From | Display name only e.g. `"PayPal Security"` |
| `to` | To | Recipient(s) |
| `subject` | Subject | Decoded from any MIME encoding |
| `date` | Date | Raw timestamp string |
| `reply_to` | Reply-To | Often different domain in phishing |
| `return_path` | Return-Path | Envelope bounce address |
| `message_id` | Message-ID | Unique email ID |
| `x_mailer` | X-Mailer | Mail client / sending software |
| `authentication_results` | Authentication-Results | SPF/DKIM/DMARC results string |
| `received_spf` | Received-SPF | Standalone SPF result |
| `dkim_signature` | DKIM-Signature | Full DKIM sig if present |
| `received_headers` | All Received: | List of all relay hops (reversed = oldest first) |
| `body_text` | — | Decoded plain text body |
| `body_html` | — | Decoded HTML body |
| `attachments` | — | List of `{filename, content_type, raw_bytes, size}` |
| `has_attachments` | — | Boolean |
| `all_headers` | — | Full dict of every header for downstream checks |

**Encoding handling:** Automatically decodes base64, quoted-printable, UTF-8, Latin-1, and Windows CP1252.

---

### Phase 2 — Header Analysis (Enhanced)
**File:** `src/header_analysis.py`  
**Now includes SOC101 eioc.py techniques**

**Checks performed:**

#### Authentication Checks
| Check | How | Points if fail |
|-------|-----|----------------|
| SPF | Reads `Authentication-Results` + `Received-SPF` headers | +15 |
| DKIM | Reads `Authentication-Results` | +15 |
| DMARC | Reads `Authentication-Results` | +15 |
| Inferred DMARC | If both SPF+DKIM unknown/fail, infers DMARC would fail | +10 |

#### Sender IP Analysis (from SOC101 eioc.py)
The module now extracts:
- `X-Originating-IP` — actual client IP before hitting the mail server
- `X-Sender-IP` — alternative client IP header
- `X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`

For each public IP found, it calls **ipinfo.io** (free, no key needed) to get:
- City, Region, Country
- ISP/Organization name
- Defanged format: `185[.]220[.]101[.]45`

#### Domain Mismatch Checks
| Check | Severity | What it catches |
|-------|----------|----------------|
| From display name embeds different email | critical | `"paypal.com" <hacker@evil.com>` |
| Brand name in display name, wrong domain | warning | Display says "PayPal" but sends from `freemail.net` |
| Reply-To domain ≠ From domain | warning | Replies go to attacker's address |
| Return-Path domain ≠ From domain | warning | Envelope sender mismatch |

#### Typosquatting Detection (new)
Detects if the sending domain is a typosquatted version of a known brand using 10+ character swap patterns:

| Pattern | Example |
|---------|---------|
| `rn` → `m` | `payrnent.com` looks like `payment.com` |
| `l` → `1` | `paypa1.com` |
| `0` → `o` | `micros0ft.com` |
| `vv` → `w` | `tvvitter.com` |
| `cl` → `d` | `clrop.com` → `drop.com` |

Checks against 25 brands: paypal, microsoft, apple, google, amazon, netflix, chase, facebook, instagram, linkedin, dropbox, adobe, docusign, dhl, fedex, ups, irs, walmart, ebay, coinbase, binance, etc.

#### Homoglyph / IDN Attack Detection (new)
Detects Unicode lookalike characters in domain names and display names:

| Unicode char | Looks like |
|-------------|-----------|
| Cyrillic `а` (U+0430) | Latin `a` |
| Cyrillic `е` (U+0435) | Latin `e` |
| Greek `ο` (U+03BF) | Latin `o` |
| Cyrillic `р` (U+0440) | Latin `p` |

#### Encoding Anomaly Detection (new)
- Base64-encoded Subject line (obfuscates content from filters)
- Excessive MIME encoding chunks in Subject
- HTML/script tags in plain text body part (injection attempt)
- Urgency keywords in Subject: "URGENT", "Action Required", "Verify your account", "Security Alert"

#### Structural Checks
| Check | Severity | Notes |
|-------|----------|-------|
| Missing Authentication-Results | info | SPF/DKIM/DMARC status unknown |
| Missing Message-ID | info | Automated/forged emails skip this |
| Suspicious X-Mailer | warning | 20+ patterns: "Mass Mailer", "Bulk Mail", "SendBlaster", etc. |
| No Received headers | warning | Headers stripped or locally generated |
| Excessive hops (>10) | info | Unusual relay chain |
| Lookalike TLD | critical | `.corn` for `.com`, `.c0m`, `.cm` |
| Multiple From headers | critical | Header injection attack (+25 pts) |
| Content-Type vs body mismatch | info | Claims text/plain but has heavy HTML |

#### Hop Chain Analysis
Every `Received:` header is parsed to extract:
- Sender domain and IP per hop
- Receiving server per hop
- Timestamp per hop
- **Geolocation for each public IP** (city/ISP via ipinfo.io)

---

### Phase 3 — IOC Extraction
**File:** `src/ioc_extractor.py`

Scans both plain text body AND HTML body for indicators.

| IOC Type | Method | Notes |
|----------|--------|-------|
| URLs | Regex + HTML href/src parsing | Catches obfuscated URLs in HTML anchors |
| IPs | IPv4 regex, filtered | Private ranges excluded (10.x, 192.168.x, 127.x) |
| Domains | Extracted from URLs + headers | From, Reply-To, Return-Path domains |
| Email addresses | Email regex | May reveal attacker infrastructure |
| File hashes | MD5/SHA1/SHA256 regex | 32/40/64 hex strings in body |

---

### Phase 4 — Threat Intel Enrichment
**File:** `src/enrichment.py`  
**Rate-limited to stay within free API tiers**

#### Which API checks which IOC type

```
IOC Type    VirusTotal    AbuseIPDB    URLScan.io    OTX AlienVault
─────────────────────────────────────────────────────────────────────
URLs            ✅           ❌            ✅              ❌
IPs             ✅           ✅            ❌              ✅
Domains         ✅           ❌            ❌              ✅
Hashes          ✅           ❌            ❌              ❌
```

#### VirusTotal
- Checks URLs, IPs, domains, and file hashes against 70–87 security engines
- Returns: malicious count, suspicious count, total engines, verdict
- Verdict threshold: `malicious > 2` → flagged malicious

#### AbuseIPDB
- Only fires when the email contains **raw public IP addresses**
- Returns: abuse confidence score (0–100%), total reports, country, ISP, Tor exit flag
- Verdict: score > 50% → malicious, > 20% → suspicious

#### URLScan.io
- Searches for previously submitted scans of the URL (does not submit new scans)
- Returns: malicious verdict, score, categories from community scans
- Returns "not_found" for URLs that have never been submitted to URLScan

#### OTX AlienVault
- Checks IPs and domains against community threat reports ("pulses")
- Returns: pulse count, pulse names, country, reputation
- Verdict: > 5 pulses → malicious, > 0 pulses → suspicious

**Why only VirusTotal shows results in most tests:**  
Test emails with fabricated domains/URLs have no OTX history and have never been scanned by URLScan. AbuseIPDB only activates on raw IP addresses. VT checks everything. Real-world phishing emails with known malicious infrastructure will trigger all 4.

**Rate limits enforced automatically:**

| API | Free Limit | Auto-wait interval |
|-----|------------|-------------------|
| VirusTotal | 4/min | 15 seconds between calls |
| AbuseIPDB | 60/min | 1 second between calls |
| URLScan | 10/min | 6 seconds between calls |
| OTX | 30/min | 2 seconds between calls |

---

### Phase 5 — ML Classifier (DistilBERT)
**File:** `src/ml_classifier.py`  
**Model:** `models/phishing_model/phishing-distilbert/`

#### What DistilBERT is
- Compressed version of Google's BERT language model
- 40% smaller than BERT, retains 97% of its performance
- Pre-trained on Wikipedia + BooksCorpus to understand English
- **Fine-tuned** on phishing datasets to classify emails

#### Training data used (Kaggle)
- Enron Email Dataset (legitimate corporate emails)
- CEAS 2008 Spam Dataset
- SpamAssassin Public Corpus
- Nazario Phishing Dataset

#### How fine-tuning worked (Google Colab)
1. Loaded `distilbert-base-uncased` from HuggingFace
2. Added classification head (2 neurons: phishing / legitimate)
3. Trained for 3 epochs on labeled email dataset
4. Evaluated: F1 score > 0.97
5. Saved weights with `model.save_pretrained()`
6. Uploaded `phishing-distilbert/` folder to local `models/`

#### How inference runs
```
Email body text (plain + HTML combined)
        │
        ▼
Tokenizer (vocab.txt, 30,522 tokens)
Converts text → integer token IDs
Truncates at 512 tokens
        │
        ▼
DistilBERT forward pass
6 transformer layers × 12 attention heads
        │
        ▼
Classification head → 2 raw logits
        │
        ▼
Softmax → probabilities (sum to 1.0)
P(phishing) = 0.9998  →  PHISHING 99.98%
P(legitimate) = 0.0002
```

#### Model files
| File | Purpose |
|------|---------|
| `model.safetensors` | Trained weights (~267MB) |
| `config.json` | Architecture + `id2label: {0: legitimate, 1: phishing}` |
| `vocab.txt` | 30,522 word-piece tokens |
| `tokenizer_config.json` | Tokenization settings |

**First run takes ~45 seconds** — model loads 267MB from disk into RAM. Subsequent runs in the same session are fast (~5s) since the model stays cached.

**Limitation:** Trained on English-only emails. Non-English phishing gets lower accuracy. For multilingual support, switch to `distilbert-base-multilingual-cased`.

---

### Phase 6 — Attachment Analysis (Enhanced)
**File:** `src/attachment.py`  
**SOC101 tools integrated: oledump.py, pdfid.py concepts**

#### What it checks

**1. File Hashes**
- MD5, SHA1, SHA256 computed from raw bytes
- SHA256 submitted to VirusTotal for known malware lookup

**2. True File Type Detection**
Reads magic bytes (first bytes of file) — not the extension.

| Magic Bytes | Detected As |
|-------------|-------------|
| `PK\x03\x04` | ZIP / Office OOXML |
| `%PDF-` | PDF |
| `MZ` | Windows executable |
| `\xd0\xcf\x11\xe0` | OLE compound (old .doc/.xls) |
| `\x89PNG` | PNG image |
| `Rar!` | RAR archive |
| `7z\xbc\xaf` | 7-Zip archive |
| `\x7fELF` | Linux binary |

**3. Extension Analysis**
| Check | Severity | Example |
|-------|----------|---------|
| Dangerous extension | critical | `.exe`, `.scr`, `.bat`, `.vbs`, `.ps1`, `.js`, `.hta`, `.cmd` |
| Double extension | critical | `invoice.pdf.exe` — hides real type from users |
| File type mismatch | warning | Extension says `.pdf` but magic bytes say `MZ` (executable) |
| Macro-capable extension | info | `.docm`, `.xlsm`, `.pptm` |

**4. Macro / VBA Analysis**
For OOXML (modern Office — `.docm`, `.xlsm`):
- Unzips the file (they're ZIP archives internally)
- Looks for `vbaproject.bin` inside the ZIP
- Flags `.bas`, `.frm`, `.cls` VBA source files

**5. OLE Deep Scan via oledump.py (SOC101 tool)**
For old binary Office files (`.doc`, `.xls`, `.ppt` — OLE format, magic `\xd0\xcf\x11\xe0`):
- **Runs `oledump.py` as a subprocess** (from SOC101 course tools)
- oledump enumerates all OLE streams inside the file
- Streams marked with `M` or `m` contain VBA module code
- Reports exact stream names e.g. `VBA/ThisDocument`, `VBA/Module1`

> **Bug fixed:** The original code used `raw_bytes.lower()` which doesn't exist on Python `bytes` objects — this was crashing silently. Now searches literal byte strings directly.

**6. PDF Analysis (pdfid.py concepts, inline)**
Scans PDF raw bytes for dangerous keywords:

| Keyword | Risk | What it does |
|---------|------|-------------|
| `/JS` `/JavaScript` | critical | Executes JavaScript when PDF opens |
| `/OpenAction` | critical | Runs code automatically on open |
| `/Launch` | critical | Launches external applications |
| `/EmbeddedFile` | critical | Contains embedded files |
| `/AcroForm` | critical | Can auto-submit data to remote server |
| `/JBIG2Decode` | critical | Used in known PDF exploits |
| `/Encrypt` | warning | PDF encrypted — hides content from scanners |
| `/ObjStm` | warning | Object streams — common in obfuscated PDFs |

**7. Additional Checks**
| Check | Severity | Notes |
|-------|----------|-------|
| Password-protected ZIP | warning | Encrypted ZIP hides content from antivirus |
| Large unrecognized binary | warning | >500KB with no recognized type |

#### Risk Level Assignment
| Condition | Risk Level |
|-----------|-----------|
| Any critical finding | `critical` |
| Any warning finding (no critical) | `high` |
| Info findings only | `medium` |
| No findings | `low` |

---

### Phase 7 — Risk Scoring
**File:** `src/risk_scorer.py`  
**Config:** `config.py` → `RISK_WEIGHTS`

Takes ALL previous phase results and computes a single 0–100 score.

#### Scoring formula
```
score = 0
# Apply weights for every anomaly/finding from all phases
score += weight_for_each_finding
score = min(score, 100)   # cap at 100
```

#### Severity thresholds
| Score | Level | Color |
|-------|-------|-------|
| 0–25 | LOW | Green |
| 26–50 | MEDIUM | Yellow |
| 51–75 | HIGH | Orange |
| 76–100 | CRITICAL | Red |

#### Full weight table

**Header Analysis:**

| Anomaly | Points |
|---------|--------|
| SPF fail | 15 |
| DKIM fail | 15 |
| DMARC fail | 15 |
| From domain mismatch | 20 |
| Typosquatting domain | 20 |
| Homoglyph/IDN domain | 20 |
| Lookalike TLD | 20 |
| Multiple From headers | 25 |
| Reply-To mismatch | 10 |
| Return-Path mismatch | 8 |
| Inferred DMARC fail | 10 |
| Brand impersonation | 5 |
| Suspicious X-Mailer | 5 |
| HTML in text body | 15 |
| Excessive encoding | 10 |
| Homoglyph display name | 10 |
| Urgency in subject | 5 |
| No Received headers | 10 |

**Threat Intelligence:**

| Finding | Points |
|---------|--------|
| VT malicious URL | 25 |
| VT malicious domain | 20 |
| VT malicious IP | 20 |
| VT malicious hash | 25 |
| AbuseIPDB high score | 20 |
| URLScan malicious | 15 |
| OTX pulse match | 15 |

**ML Classification:**

| Finding | Points |
|---------|--------|
| Phishing, confidence ≥ 70% | 25 |
| Phishing, confidence < 70% | 15 |

**Attachment:**

| Finding | Points |
|---------|--------|
| VBA project detected | 30 |
| VT malicious attachment | 30 |
| PDF dangerous keywords | 25 |
| Macro-enabled document | 25 |
| Double extension | 25 |
| Dangerous extension | 20 |
| File type mismatch | 15 |
| Password-protected archive | 15 |
| PDF encrypted | 10 |
| Suspicious binary blob | 10 |

**Content:**

| Finding | Points |
|---------|--------|
| Credential harvesting language | 15 |
| Financial scam language | 15 |
| Urgency language (≥3 indicators) | 10 |

---

### Phase 9 — LLM Analyst (Groq)
**File:** `src/llm_analyst.py`  
**API:** Groq Cloud (free tier)  
**Model:** `llama-3.3-70b-versatile`

#### What gets sent to Groq
Only a **text summary** — not the raw email:
```
RISK SCORE: 100/100 (CRITICAL)
From: security@paypa1-secure.com
Subject: URGENT: Your PayPal Account Has Been Limited
ML Classification: PHISHING (confidence: 100.0%)
SPF: fail  DKIM: fail  DMARC: fail
Anomalies: 6 found
  - typosquatting domain: paypa1-secure.com → paypal
  - Reply-To domain freemail-service.net differs from From
  - SPF fail: sender not authorized
  - ...
IOCs: 4 URLs, 0 IPs
VT Results: 2 URLs malicious
Key Findings: [scored list]
```

#### What comes back
```json
{
  "executive_summary": "2–3 sentence threat summary",
  "threat_narrative": "4–6 sentence detailed analysis",
  "attack_type": "credential_phishing",
  "mitre_analysis": [{"technique_id": "T1566.002", ...}],
  "recommended_actions": ["Block sender domain", "..."],
  "confidence_assessment": "High confidence based on..."
}
```

#### Model fallback chain
If the primary model fails (deprecated, rate-limited, network error), it tries each in order:
```
1. llama-3.3-70b-versatile   ← primary
2. llama3-70b-8192
3. llama-3.1-8b-instant
4. mixtral-8x7b-32768
5. Rule-based fallback        ← no API, always works
```

---

### Phase 8 — PDF Report
**File:** `src/report_generator.py`  
**Library:** `fpdf2`

Sections in the generated PDF:
1. Executive Summary (from LLM)
2. Email Metadata table
3. Authentication results (SPF/DKIM/DMARC)
4. Header Anomalies list
5. IOC table (all extracted indicators)
6. Threat Intelligence results (per-IOC API verdicts)
7. ML Classification result + bar
8. Risk Score breakdown + all findings with points
9. Attachment analysis results
10. MITRE ATT&CK techniques
11. Recommended Actions
12. Full Threat Narrative

---

## 5. Risk Scoring Reference

Every finding from every phase feeds into the risk scorer. Each finding shows:
- **Category** (Header/Enrichment/ML/Attachment/Content)
- **Description** (human-readable)
- **Points** (weight from config.py)
- **Severity** (critical/warning/info)

The score is additive and capped at 100. A typical CRITICAL email:
```
+15  SPF fail
+15  DKIM fail
+20  Typosquatting domain (paypa1.com → paypal)
+10  Reply-To mismatch
+25  ML: PHISHING at 100% confidence
+25  VirusTotal flagged URL as malicious
+10  Urgency language in body
+15  Credential harvesting keywords
─────
135  → capped at 100 → CRITICAL
```

---

## 6. API Reference

### VirusTotal
- **Endpoint:** `https://www.virustotal.com/api/v3/`
- **Auth:** `x-apikey` header
- **IOC types:** IPs → `/ip_addresses/{ip}`, domains → `/domains/{d}`, URLs → `/urls/{base64id}`, hashes → `/files/{hash}`
- **Free tier:** 4 req/min, 500 req/day
- **Verdict logic:** `malicious_count > 2` → malicious

### AbuseIPDB
- **Endpoint:** `https://api.abuseipdb.com/api/v2/check`
- **Auth:** `Key` header
- **IOC types:** IPs only
- **Free tier:** 1,000 req/day
- **Verdict logic:** abuse score > 50 → malicious, > 20 → suspicious

### URLScan.io
- **Endpoint:** `https://urlscan.io/api/v1/search/`
- **Auth:** `API-Key` header
- **IOC types:** URLs only (search mode, not submit)
- **Free tier:** 100 req/day
- **Note:** Returns "not_found" for URLs never previously submitted

### OTX AlienVault
- **Endpoint:** `https://otx.alienvault.com/api/v1/indicators/`
- **Auth:** `X-OTX-API-KEY` header
- **IOC types:** IPs (`/IPv4/{ip}/general`) and domains (`/domain/{d}/general`)
- **Free tier:** Very generous (community platform)
- **Verdict logic:** pulse_count > 5 → malicious, > 0 → suspicious

### ipinfo.io (Header Analysis — no key needed)
- **Endpoint:** `https://ipinfo.io/{ip}/json`
- **Auth:** None required (free tier: 50,000 req/month)
- **Used in:** Phase 2 header analysis for hop chain IP geolocation
- **Returns:** city, region, country, ISP/org

---

## 7. The ML Model Explained

**Architecture:** `distilbert-base-uncased` + 2-class classification head

**What DistilBERT understands:**
The base model was pre-trained to predict masked words in sentences — this forced it to learn grammar, context, and meaning. Fine-tuning then directed this understanding toward phishing patterns:
- Urgency language patterns
- Credential request phrasing
- Mismatched sender legitimacy cues
- Link obfuscation patterns in body text

**Confidence threshold:** `config.py` → `ML_CONFIDENCE_THRESHOLD = 0.7`
- Confidence ≥ 70% → +25 points (high confidence)
- Confidence 50–70% → +15 points (medium confidence)
- Confidence < 50% as phishing → no points (treated as legitimate)

**Model path:** `models/phishing_model/phishing-distilbert/`

---

## 8. The LLM Integration Explained

**Groq** runs LLaMA models on LPUs (Language Processing Units) — custom chips optimized for inference that are ~10x faster than GPU. The free tier is extremely generous for this use case.

**What the LLM does vs what the pipeline does:**

| Task | Done by |
|------|---------|
| Detect phishing | DistilBERT (Phase 5) |
| Check SPF/DKIM/DMARC | Rule-based (Phase 2) |
| Find URLs/IPs | Regex (Phase 3) |
| Check VT/AbuseIPDB | API calls (Phase 4) |
| Calculate risk score | Weighted rules (Phase 7) |
| **Write analyst report** | **Groq LLM (Phase 9)** |
| **Explain attack in English** | **Groq LLM (Phase 9)** |
| **Recommend actions** | **Groq LLM (Phase 9)** |

The LLM is the **explainer**, not the detector. It takes structured machine output and converts it to analyst-grade narrative that a SOC analyst can immediately act on.

**Temperature = 0.3** — low temperature means the model stays factual and doesn't hallucinate creative threat descriptions.

---

## 9. SOC101 Tool Integrations

Three tools from the SOC101 course were referenced:

| Tool | Location | How used |
|------|----------|---------|
| `eioc.py` | Tools/ | Techniques copied into `header_analysis.py`: X-Originating-IP extraction, ipinfo.io geo-lookup, defanging functions |
| `oledump.py` | Tools/ | Called as **subprocess** from `attachment.py` for deep OLE/VBA stream analysis on `.doc`/`.xls` files |
| `pdfid.py` | Tools/ | Keyword list and scanning logic implemented inline in `attachment.py` PDF analysis section |
| `emldump.py` | Tools/ | Read for MIME structure concepts — not called (existing parser already handles MIME completely) |
| `pdf-parser.py` | Tools/ | Not needed — pdfid inline approach covers requirements |

**No SOC101 files were modified.** They are read-only references.

**oledump.py subprocess call:**
```python
# In src/attachment.py — only runs on OLE files (magic bytes D0 CF 11 E0)
result = subprocess.run(
    [python_exe, oledump_path, tmp_file],
    capture_output=True, text=True, timeout=15
)
# Parse output: streams with 'M' marker = VBA code
```

---

## 10. The GUI — Complete Guide

**File:** `gui.py`  
**Framework:** Raw tkinter — no ttk, no external GUI library

### Layout

```
┌─────────────────────────────────────────────────────────┐
│ ● ETA  Email Threat Analyzer            v2.0 distilbert │  ← 52px title bar
├──────────────────────────────────────────────────────────┤
│ ████████████████████████████████████████████████████     │  ← brass underline (60% width)
├────────────┬─────────────────────────────┬───────────────┤
│ FILE       │   100  /100                 │ RAW OUTPUT    │
│ phishing.. │   ────  CRITICAL            │               │
│ BROWSE EML │                          0% │ ▐░░░░░░░░░░░░▌│
│            │   ██ ██ ██ ██ ██ ██ ██ ██   │               │
│ OPTIONS    │                             │ [Phase 1]...  │
│ ☑ Skip API │ [01] PARSE EMAIL ✓ done 5%  │ [Phase 2]...  │
│ ☐ Skip LLM │  FROM  security@paypa1..    │ [Phase 5]...  │
│            │  TO    victim@company..     │               │
│ ▶ RUN      │  SUBJ  URGENT: Your Pay..   │               │
│ ■ STOP     │  DATE  Wed, 15 Jan 2025..   │               │
│            │                             │               │
│ PHASES     │ [02] HEADER ANALYSIS ✓ 17%  │               │
│ [01] PARSE │  SPF FAIL  DKIM FAIL  DMARC │               │
│ [02] HEADER│  ANOMALIES 6                │               │
│ [03] IOC   │   * paypa1-secure.com typo  │               │
│ [04] ENRICH│   * Reply-To mismatch       │               │
│ [05] ML    │   * SPF check fail          │               │
│ [06] ATTACH│                             │               │
│ [07] RISK  │ [03] IOC EXTRACTION ✓ 27%   │               │
│ [09] LLM   │  TOTAL IOCs  4              │               │
│ [08] PDF   │  URLS  4 extracted          │               │
│            │   http://paypa1-secure..    │               │
│ OPEN REPORT│                             │               │
│            │ [05] ML CLASSIFIER ✓ 80%    │               │
│ OUTPUT     │  VERDICT  PHISHING          │               │
│ phishing_1 │  CONF     100.0%            │               │
│ OPEN FOLDER│  P(phish) [##########] 1.0  │               │
└────────────┴─────────────────────────────┴───────────────┘
│ ready.                    "DKIM was ratified in 2007..." │  ← status bar
└─────────────────────────────────────────────────────────┘
```

### Panel Details
| Panel | Width | Purpose |
|-------|-------|---------|
| Left sidebar | 200px (resizable) | File select, options, phase tracker, run/stop |
| Center | Flexible | Score banner, segmented progress bar, live phase detail cards |
| Right | 340px (resizable) | Raw stdout from main.py subprocess |

**All panels are resizable** — drag the sash between panels.

### Progress Bar
10 brass-colored segments = 100%. Fills as each phase completes based on phase weight:

| Phase | Weight | Cumulative |
|-------|--------|-----------|
| Parse | 5% | 5% |
| Headers | 12% | 17% |
| IOC | 10% | 27% |
| Enrichment | 25% | 52% |
| ML | 28% | 80% |
| Attachments | 5% | 85% |
| Risk | 5% | 90% |
| LLM | 5% | 95% |
| PDF | 5% | 100% |

### Phase Tracker (sidebar)
```
[01] PARSE EMAIL    ✓    ← brass tick = done
[02] HEADER ANALYS  ✓
[03] IOC EXTRACTION ~    ← tilde = running
[04] ENRICHMENT     -    ← dash = skipped
[05] ML CLASSIFIER  x    ← x muted = error
```

### How GUI → Pipeline communication works
1. GUI starts `main.py` as a **subprocess** via `subprocess.Popen`
2. Background thread reads stdout line by line
3. Normal lines → raw output panel (right)
4. Lines starting with `##ETA_DATA:N:{json}` → parsed by GUI to populate phase detail cards
5. Phase status detected from emoji characters in output (`✅`, `⏳`, `⏭️`, `❌`)
6. Score/severity updated from "Risk score: X/100" pattern in output

### Per-email output folder
When RUN is clicked, GUI automatically:
1. Creates `output/{email_name_without_ext}/`
2. Passes `--output-dir` flag to `main.py`
3. `main.py` writes `01_parse.json` through `09_llm_narrative.json` after each phase

### Custom Checkboxes
Fully drawn on Canvas — not OS native checkboxes. 14×14px, 1px border, brass fill when checked.

### LED Dot
1px brass dot next to title. Blinks at 800ms interval while analysis is running. Stays lit (solid) when complete.

### Easter Egg
Click the score number 3 times — window title changes to a random analyst quip.

---

## 11. Output Files Reference

Every analysis creates `output/{email_name}/`:

| File | Contents |
|------|---------|
| `01_parse.json` | from, to, subject, date, hop_count, attachment_count, body_length |
| `02_headers.json` | SPF/DKIM/DMARC status, anomaly_count, full anomalies list, sender_ips with geo |
| `03_iocs.json` | urls[], ips[], public_ips[], domains[], emails[], hashes[], total_count |
| `04_enrichment.json` | Per-IOC results from each API source with verdicts |
| `05_ml_result.json` | label, confidence, phishing_probability, model_used |
| `06_attachments.json` | Per-attachment: filename, hashes, true_file_type, macro_analysis, findings |
| `07_risk_score.json` | score, severity, finding_count, findings[], mitre_techniques[] |
| `08_report.json` | report_path (path to generated PDF) |
| `09_llm_narrative.json` | executive_summary, threat_narrative, attack_type, recommended_actions |
| `*.pdf` | Full PDF threat report |

---

## 12. Setup & First Run

### Prerequisites
- Python 3.10 or higher
- Windows 10/11 (tested) — Linux/Mac should work with minor path adjustments
- 4GB RAM minimum (DistilBERT needs ~2GB)
- Fine-tuned model files in `models/phishing_model/phishing-distilbert/`

### Step 1 — Create virtual environment
```powershell
python -m venv venv
venv\Scripts\activate
```

### Step 2 — Install dependencies
```powershell
pip install -r requirements.txt
```

### Step 3 — Set API keys
Create `.env` in the project root:
```env
VIRUSTOTAL_API_KEY=your_vt_key_here
ABUSEIPDB_API_KEY=your_abuse_key_here
URLSCAN_API_KEY=your_urlscan_key_here
OTX_API_KEY=your_otx_key_here
GROQ_API_KEY=your_groq_key_here
```

### Step 4 — Place your model
```
models/
  phishing_model/
    phishing-distilbert/
      config.json          ← must have id2label mapping
      model.safetensors    ← ~267MB trained weights
      tokenizer_config.json
      vocab.txt
```

### Step 5 — Run the GUI
```powershell
venv\Scripts\activate
python gui.py
```

### Expected first run time
| Phase | Time | Reason |
|-------|------|--------|
| Parse | <1s | Pure Python |
| Headers | 2–10s | ipinfo.io calls for hop IPs |
| IOC | <1s | Regex |
| Enrichment (5 IOCs) | 75–120s | VT rate limit: 4/min |
| ML | 45s | Model loads from disk |
| Attachments | 2–5s | File analysis |
| Risk | <1s | Math |
| LLM | 3–8s | Groq API |
| PDF | 2–3s | fpdf2 rendering |

---

## 13. Command Line Reference

```powershell
# Full analysis (all phases enabled)
python main.py samples/phishing_sample_1.eml

# Skip API enrichment (fastest run, local only)
python main.py samples/phishing_sample_1.eml --no-enrich

# Skip LLM (no Groq call, uses fallback narrative)
python main.py samples/phishing_sample_1.eml --no-llm

# Skip PDF report
python main.py samples/phishing_sample_1.eml --no-report

# Fastest possible (no network calls at all)
python main.py samples/phishing_sample_1.eml --no-enrich --no-llm --no-report

# Custom output directory
python main.py samples/phishing_sample_1.eml --output-dir output/my_run

# All options
python main.py samples/phishing_sample_1.eml \
    --no-enrich \
    --no-llm \
    --output-dir output/test_run
```

---

## 14. API Keys — Where to Get Them

| Service | URL | Free Tier |
|---------|-----|-----------|
| **VirusTotal** | https://www.virustotal.com/gui/join-us | 4 req/min, 500 req/day |
| **AbuseIPDB** | https://www.abuseipdb.com/register | 1,000 req/day |
| **URLScan.io** | https://urlscan.io/user/signup | 100 search/day |
| **OTX AlienVault** | https://otx.alienvault.com | Very generous |
| **Groq** | https://console.groq.com | ~14,400 req/day free |

All keys are stored in `.env` — loaded automatically by `config.py` via `python-dotenv`.

---

## 15. MITRE ATT&CK Mapping

Automatically mapped based on findings:

| Condition | Technique ID | Name | Tactic |
|-----------|-------------|------|--------|
| Any phishing detected | T1566 | Phishing | Initial Access |
| Malicious URL found | T1566.002 | Spearphishing Link | Initial Access |
| Malicious attachment | T1566.001 | Spearphishing Attachment | Initial Access |
| Credential keywords | T1598.003 | Phishing for Information | Reconnaissance |
| Brand impersonation | T1534 | Internal Spearphishing | Lateral Movement |
| VBA macro found | T1204.002 | User Execution: Malicious File | Execution |
| File type obfuscation | T1027 | Obfuscated Files | Defense Evasion |
| Domain spoofing | T1583.001 | Acquire Infrastructure: Domains | Resource Development |

---

## 16. Configuration Reference

**File:** `config.py`

All tunable parameters:

| Setting | Default | Purpose |
|---------|---------|---------|
| `ML_CONFIDENCE_THRESHOLD` | 0.7 | Min confidence for "high confidence" ML finding |
| `GROQ_MODEL` | `llama-3.3-70b-versatile` | Primary LLM model |
| `GROQ_MAX_TOKENS` | 2048 | Max LLM response length |
| `GROQ_TEMPERATURE` | 0.3 | LLM creativity (0 = factual, 1 = creative) |
| `RATE_LIMITS` | VT:4, Abuse:60, URLScan:10, OTX:30 | API req/min limits |
| `RISK_THRESHOLDS` | 0–25 low, 26–50 med, 51–75 high, 76+ critical | Score bands |
| `RISK_WEIGHTS` | See full table in Section 5 | Points per finding type |
| `REPORTS_DIR` | `./reports` | Default PDF output directory |
| `PHISHING_MODEL_PATH` | `./models/phishing_model/phishing-distilbert` | Model location |

---

## 17. Known Limitations

| Limitation | Detail | Workaround |
|------------|--------|-----------|
| **English-only ML** | DistilBERT trained on English emails only | Switch to `distilbert-base-multilingual-cased` and retrain |
| **VT rate limit** | Free tier = 4 req/min — slow for emails with many IOCs | Get paid VT key (500/min) or use `--no-enrich` |
| **URLScan search only** | Only finds previously submitted URLs | Real phishing campaigns are usually already in URLScan |
| **AbuseIPDB IPs only** | Most phishing emails use domains, not raw IPs | Works well for emails with IP-based C2 infrastructure |
| **Model loading time** | First run 45s — model is 267MB | Subsequent runs fast; model stays in memory |
| **Non-ASCII in PDF** | PDF uses Helvetica (Latin-1 only) — special chars stripped | Switch to Unicode-capable font in `report_generator.py` |
| **ipinfo.io rate limit** | 50,000 req/month free — can hit limit with heavy use | Add `IPINFO_TOKEN` to `.env` for 150,000 free/month |
| **oledump for OLE only** | oledump.py only analyzes old binary .doc/.xls (OLE format) | Modern .docm/.xlsm already handled by ZIP scan |

---

*Stack: Python 3.10+ · transformers · fpdf2 · requests · iocextract · python-magic · groq · tkinter · python-dotenv · colorama · beautifulsoup4*

*SOC101 tools by Didier Stevens (oledump.py, emldump.py, pdf-parser.py, pdfid.py) used as read-only references — not modified.*
