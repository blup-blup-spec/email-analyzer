"""
gui.py -- Email Threat Analyzer GUI v2
Warm charcoal / aged brass / military terminal aesthetic.
Raw tkinter only. No ttk. No rounded cards. No gradients.
"""

import tkinter as tk
import tkinter.filedialog as fd
import tkinter.messagebox as mb
import subprocess
import threading
import os
import sys
import json
import re
import time
import random

# ── runtime paths ──────────────────────────────────────────────────────────────
_DIR = os.path.dirname(os.path.abspath(__file__))
_VENV_PY = os.path.join(_DIR, "venv", "Scripts", "python.exe")
PYTHON_EXE = _VENV_PY if os.path.exists(_VENV_PY) else sys.executable
MAIN_SCRIPT = os.path.join(_DIR, "main.py")
OUTPUT_ROOT = os.path.join(_DIR, "output")

# ── PALETTE ────────────────────────────────────────────────────────────────────
BG_MAIN    = "#1a1814"   # warm charcoal — main canvas
BG_SIDEBAR = "#141210"   # almost black-brown — sidebar
BG_RIGHT   = "#0f0d0b"   # deepest warm black — right panel
BG_LOG     = "#161412"   # log tray — 1 shade lighter than BG_RIGHT
BG_INPUT   = "#100e0c"   # input fields

BRASS      = "#c9a96e"   # aged brass/gold — THE ONE accent
BRASS_HOV  = "#b8985e"   # brass on hover
BRASS_DIM  = "#7a6540"   # dim brass for completed state

TEXT_PRI   = "#d4cfc7"   # warm off-white
TEXT_SEC   = "#8a8279"   # muted warm gray
TEXT_CODE  = "#a39e96"   # log text color

BORDER     = "#2a2620"   # subtle warm divider
RIDGE      = "#25211c"   # 1px ridge above borders

BTN_STOP_BG = "#3a2a2a"
BTN_STOP_FG = "#c97e7e"

SEV_CRIT   = "#c84040"
SEV_HIGH   = "#c87830"
SEV_MED    = "#c8a028"
SEV_LOW    = "#4a8a58"

# ── FONTS (Segoe UI = Inter fallback on Windows) ───────────────────────────────
# section headers = Segoe UI, 10px, ALL CAPS, weight normal (not bold)
# body/log = Consolas, 12px (JetBrains Mono fallback)
# big score = Consolas, 32px light feel
FONT_LABEL  = ("Segoe UI", 10)          # UI chrome, section headers
FONT_LABEL_B= ("Segoe UI", 10, "bold")  # emphasized labels
FONT_BODY   = ("Consolas", 11)          # phase detail content
FONT_LOG    = ("Consolas", 10)          # raw log
FONT_SCORE  = ("Consolas", 34)          # big risk score number
FONT_BADGE  = ("Segoe UI", 11, "bold")  # severity badge
FONT_PHASE  = ("Consolas", 10)          # phase list items
FONT_MINI   = ("Segoe UI", 9)           # tiny labels

# ── phase configuration ────────────────────────────────────────────────────────
PHASES = [
    (1, "PARSE EMAIL",     5),
    (2, "HEADER ANALYSIS", 12),
    (3, "IOC EXTRACTION",  10),
    (4, "ENRICHMENT",      25),
    (5, "ML CLASSIFIER",   28),
    (6, "ATTACHMENTS",     5),
    (7, "RISK SCORING",    5),
    (9, "LLM NARRATIVE",   5),
    (8, "PDF REPORT",      5),
]
# cumulative progress thresholds (0..100)
_cum = 0
PHASE_PROGRESS = {}
for _pn, _pl, _pw in PHASES:
    PHASE_PROGRESS[_pn] = (_cum, _cum + _pw)
    _cum += _pw

SEV_COLORS = {
    "critical": SEV_CRIT, "high": SEV_HIGH,
    "medium": SEV_MED, "low": SEV_LOW, "unknown": TEXT_SEC,
}

STATUS_FACTS = [
    "The word 'phishing' borrows 'ph' from 1990s phone hacking culture.",
    "DKIM was ratified as RFC 4871 in 2007 — took 12 years to reach widespread adoption.",
    "SPF records were invented by a single engineer in 2003.",
    "VirusTotal scans files against 70+ antivirus engines simultaneously.",
    "A properly enforced DMARC policy blocks ~99% of domain spoofing attacks.",
    "The Enron email corpus contains 500,000 real corporate emails — used heavily in spam research.",
    "Base64 bloats file size by exactly 4/3x. Every single time.",
    "The first known phishing attack targeted AOL users in 1995.",
    "DistilBERT is 40% smaller than BERT with 97% of its performance.",
    "Most BEC (Business Email Compromise) attacks use no malware at all.",
    "OTX AlienVault aggregates threat data from 100,000+ security researchers.",
]


# ══════════════════════════════════════════════════════════════════════════════
#  SEGMENTED PROGRESS BAR
# ══════════════════════════════════════════════════════════════════════════════

class SegmentedBar:
    """
    10 segments, 18px wide, 6px tall, 4px gap.
    Feels like an old stereo level meter.
    """
    SEGS = 10
    SEG_W = 18
    SEG_H = 6
    GAP = 4

    def __init__(self, parent):
        total_w = self.SEGS * self.SEG_W + (self.SEGS - 1) * self.GAP
        self.canvas = tk.Canvas(
            parent, width=total_w, height=self.SEG_H,
            bg=BG_MAIN, highlightthickness=0, bd=0,
        )
        self._segs = []
        for i in range(self.SEGS):
            x0 = i * (self.SEG_W + self.GAP)
            x1 = x0 + self.SEG_W
            seg = self.canvas.create_rectangle(
                x0, 0, x1, self.SEG_H,
                fill=BORDER, outline="",
            )
            self._segs.append(seg)
        self._current = 0

    def pack(self, **kw):
        self.canvas.pack(**kw)

    def set_progress(self, pct: float):
        """pct = 0..100"""
        filled = int(round((pct / 100.0) * self.SEGS))
        if filled == self._current:
            return
        self._current = filled
        for i, seg in enumerate(self._segs):
            self.canvas.itemconfig(seg, fill=BRASS if i < filled else BORDER)

    def reset(self):
        self._current = 0
        for seg in self._segs:
            self.canvas.itemconfig(seg, fill=BORDER)


# ══════════════════════════════════════════════════════════════════════════════
#  LED DOT
# ══════════════════════════════════════════════════════════════════════════════

class LedDot:
    """1px brass dot next to the title. Blinks slowly when processing."""

    def __init__(self, parent, size=7):
        self.canvas = tk.Canvas(
            parent, width=size, height=size,
            bg=BG_SIDEBAR, highlightthickness=0, bd=0,
        )
        self._dot = self.canvas.create_oval(
            1, 1, size - 1, size - 1, fill=BORDER, outline=""
        )
        self._active = False
        self._state = True
        self._job = None

    def pack(self, **kw):
        self.canvas.pack(**kw)

    def start(self):
        self._active = True
        self._blink()

    def stop(self, lit=False):
        self._active = False
        if self._job:
            self.canvas.after_cancel(self._job)
        self.canvas.itemconfig(self._dot, fill=BRASS if lit else BORDER)

    def _blink(self):
        if not self._active:
            return
        self._state = not self._state
        self.canvas.itemconfig(self._dot, fill=BRASS if self._state else BORDER)
        self._job = self.canvas.after(800, self._blink)


# ══════════════════════════════════════════════════════════════════════════════
#  CUSTOM CHECKBOX
# ══════════════════════════════════════════════════════════════════════════════

class BrassCheckbox:
    """14x14 checkbox drawn on a Canvas. Checked = brass fill + tick."""

    SZ = 14

    def __init__(self, parent, text, var, bg=BG_SIDEBAR):
        self.var = var
        self._bg = bg

        frame = tk.Frame(parent, bg=bg)
        self.frame = frame

        self.canvas = tk.Canvas(
            frame, width=self.SZ, height=self.SZ,
            bg=bg, highlightthickness=0, bd=0, cursor="hand2",
        )
        self.canvas.pack(side="left", padx=(0, 6))

        self._box = self.canvas.create_rectangle(
            0, 0, self.SZ - 1, self.SZ - 1,
            outline="#3a3630", fill=BG_INPUT, width=1,
        )
        self._check = self.canvas.create_text(
            self.SZ // 2, self.SZ // 2,
            text="", font=("Consolas", 8, "bold"),
            fill=BG_SIDEBAR,
        )

        tk.Label(
            frame, text=text,
            font=FONT_MINI, fg=TEXT_SEC, bg=bg, cursor="hand2",
        ).pack(side="left")

        self.canvas.bind("<Button-1>", self._toggle)
        self._refresh()

    def _toggle(self, event=None):
        self.var.set(not self.var.get())
        self._refresh()

    def _refresh(self):
        if self.var.get():
            self.canvas.itemconfig(self._box, fill=BRASS, outline=BRASS)
            self.canvas.itemconfig(self._check, text="+", fill=BG_SIDEBAR)
        else:
            self.canvas.itemconfig(self._box, fill=BG_INPUT, outline="#3a3630")
            self.canvas.itemconfig(self._check, text="")

    def pack(self, **kw):
        self.frame.pack(**kw)


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE ROW  (sidebar)
# ══════════════════════════════════════════════════════════════════════════════

class PhaseRow:
    def __init__(self, parent, num, label):
        self.num = num
        self.frame = tk.Frame(parent, bg=BG_SIDEBAR)
        self.frame.pack(fill="x", pady=1)

        self.num_lbl = tk.Label(
            self.frame,
            text=f"[{num:02d}]",
            font=FONT_PHASE, fg=TEXT_SEC, bg=BG_SIDEBAR,
            width=5, anchor="e",
        )
        self.num_lbl.pack(side="left", padx=(8, 4))

        self.name_lbl = tk.Label(
            self.frame, text=label,
            font=FONT_PHASE, fg=TEXT_SEC, bg=BG_SIDEBAR,
            anchor="w",
        )
        self.name_lbl.pack(side="left", fill="x", expand=True)

        self.status_lbl = tk.Label(
            self.frame, text="",
            font=("Consolas", 10, "bold"),
            fg=TEXT_SEC, bg=BG_SIDEBAR,
            width=2, anchor="e",
        )
        self.status_lbl.pack(side="right", padx=(0, 8))

    def set_running(self):
        self.name_lbl.config(fg=TEXT_PRI)
        self.status_lbl.config(text="~", fg=BRASS)

    def set_done(self):
        self.name_lbl.config(fg=TEXT_SEC)
        self.status_lbl.config(text="\u2713", fg=BRASS)

    def set_skipped(self):
        self.name_lbl.config(fg=TEXT_SEC)
        self.status_lbl.config(text="-", fg=BORDER)

    def set_error(self):
        self.name_lbl.config(fg=BTN_STOP_FG)
        self.status_lbl.config(text="x", fg=TEXT_SEC)

    def reset(self):
        self.name_lbl.config(fg=TEXT_SEC)
        self.status_lbl.config(text="", fg=TEXT_SEC)


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE DETAIL CARD  (main center area)
# ══════════════════════════════════════════════════════════════════════════════

class PhaseDetail:
    """
    Renders what a single phase found as a compact text block.
    Appears in the scrollable center panel as each phase completes.
    """

    def __init__(self, parent, num, label, pct_start, pct_end):
        self.num = num
        self.frame = tk.Frame(parent, bg=BG_MAIN)
        self.frame.pack(fill="x", pady=(0, 1))

        # 1px ridge above each card
        tk.Frame(self.frame, bg=RIDGE, height=1).pack(fill="x")

        # header row
        hdr = tk.Frame(self.frame, bg=BG_MAIN)
        hdr.pack(fill="x", padx=(64, 64), pady=(8, 2))

        self.num_lbl = tk.Label(
            hdr, text=f"[{num:02d}]",
            font=FONT_PHASE, fg=TEXT_SEC, bg=BG_MAIN,
        )
        self.num_lbl.pack(side="left", padx=(0, 8))

        self.title_lbl = tk.Label(
            hdr, text=label,
            font=FONT_LABEL, fg=TEXT_SEC, bg=BG_MAIN,
        )
        self.title_lbl.pack(side="left")

        self.pct_lbl = tk.Label(
            hdr, text=f"{pct_end}%",
            font=FONT_MINI, fg=TEXT_SEC, bg=BG_MAIN,
        )
        self.pct_lbl.pack(side="right")

        self.state_lbl = tk.Label(
            hdr, text="waiting...",
            font=FONT_MINI, fg=TEXT_SEC, bg=BG_MAIN,
        )
        self.state_lbl.pack(side="right", padx=(0, 12))

        # content text area
        self.text = tk.Text(
            self.frame,
            font=FONT_BODY, fg=TEXT_CODE, bg=BG_MAIN,
            relief="flat", bd=0,
            state="disabled",
            wrap="word",
            highlightthickness=0,
            padx=0, pady=2,
            height=1,  # will expand
            cursor="arrow",
        )
        self.text.pack(fill="x", padx=(64 + 42, 64))

        # configure text tags
        self.text.tag_configure("label",  foreground=TEXT_SEC)
        self.text.tag_configure("value",  foreground=TEXT_PRI)
        self.text.tag_configure("brass",  foreground=BRASS)
        self.text.tag_configure("crit",   foreground=SEV_CRIT)
        self.text.tag_configure("warn",   foreground=SEV_HIGH)
        self.text.tag_configure("good",   foreground=SEV_LOW)
        self.text.tag_configure("dim",    foreground=TEXT_SEC)

    def set_running(self):
        self.state_lbl.config(text="running", fg=BRASS)
        self.title_lbl.config(fg=TEXT_PRI)

    def set_done(self):
        self.state_lbl.config(text="\u2713 done", fg=BRASS)

    def set_skipped(self):
        self.state_lbl.config(text="- skip", fg=TEXT_SEC)
        self._write_line("skipped", "dim")

    def set_error(self, msg=""):
        self.state_lbl.config(text="x error", fg=BTN_STOP_FG)
        if msg:
            self._write_line(f"error: {msg[:80]}", "crit")

    def reset(self):
        self.state_lbl.config(text="waiting...", fg=TEXT_SEC)
        self.title_lbl.config(fg=TEXT_SEC)
        self.text.config(state="normal")
        self.text.delete("1.0", "end")
        self.text.config(state="disabled", height=1)

    def _write_line(self, text, tag="value"):
        self.text.config(state="normal")
        self.text.insert("end", text + "\n", tag)
        self.text.config(state="disabled")
        self._resize()

    def _write_kv(self, key, value, val_tag="value"):
        self.text.config(state="normal")
        self.text.insert("end", f"{key:<12}", "label")
        self.text.insert("end", str(value) + "\n", val_tag)
        self.text.config(state="disabled")
        self._resize()

    def _resize(self):
        lines = int(self.text.index("end-1c").split(".")[0])
        self.text.config(height=max(1, lines))

    def populate_phase1(self, data):
        self.set_done()
        self._write_kv("FROM", data.get("from_address", "N/A"))
        self._write_kv("TO", (data.get("to", "N/A") or "N/A")[:60])
        self._write_kv("SUBJECT", (data.get("subject", "N/A") or "N/A")[:60])
        self._write_kv("DATE", data.get("date", "N/A") or "N/A")
        self._write_kv("REPLY-TO", data.get("reply_to", "") or "(same as from)")
        self._write_kv("MSG-ID", (data.get("message_id", "") or "N/A")[:55])
        self._write_kv("ATTACHMENTS", data.get("attachment_count", 0))
        self._write_kv("HOPS", data.get("hop_count", 0))
        self._write_kv("BODY SIZE", f"{data.get('body_length', 0):,} chars")
        if data.get("x_mailer"):
            self._write_kv("X-MAILER", data["x_mailer"], "warn")

    def populate_phase2(self, data):
        if data.get("error"):
            self.set_error(data["error"])
            return
        self.set_done()
        spf  = data.get("spf", "unknown")
        dkim = data.get("dkim", "unknown")
        dmarc= data.get("dmarc", "unknown")
        spf_tag  = "good" if spf  == "pass" else "crit"
        dkim_tag = "good" if dkim == "pass" else "crit"
        dmarc_tag= "good" if dmarc== "pass" else "warn"
        self.text.config(state="normal")
        self.text.insert("end", f"{'SPF':<12}", "label")
        self.text.insert("end", spf.upper() + "  ", spf_tag)
        self.text.insert("end", f"{'DKIM':<8}", "label")
        self.text.insert("end", dkim.upper() + "  ", dkim_tag)
        self.text.insert("end", f"{'DMARC':<8}", "label")
        self.text.insert("end", dmarc.upper() + "\n", dmarc_tag)
        self.text.config(state="disabled")
        self._resize()

        self._write_kv("ANOMALIES", data.get("anomaly_count", 0),
                       "crit" if data.get("anomaly_count", 0) > 0 else "good")
        for anomaly in data.get("anomalies", [])[:8]:
            sev = anomaly.get("severity", "info")
            tag = "crit" if sev == "critical" else ("warn" if sev == "warning" else "dim")
            msg = anomaly.get("message", "")[:70]
            self._write_line(f"  * {msg}", tag)

    def populate_phase3(self, data):
        if data.get("error"):
            self.set_error(data["error"])
            return
        self.set_done()
        self._write_kv("TOTAL IOCs", data.get("total_count", 0),
                       "crit" if data.get("total_count", 0) > 0 else "dim")
        urls = data.get("urls", [])
        if urls:
            self._write_kv("URLS", f"{len(urls)} extracted")
            for u in urls[:5]:
                self._write_line(f"  {u[:65]}", "warn")
        ips = data.get("public_ips", [])
        if ips:
            self._write_kv("IPs", f"{len(ips)} extracted")
            for ip in ips[:5]:
                self._write_line(f"  {ip}", "warn")
        domains = data.get("domains", [])
        if domains:
            self._write_kv("DOMAINS", f"{len(domains)} extracted")
            for d in domains[:5]:
                self._write_line(f"  {d}", "dim")
        emails = data.get("emails", [])
        if emails:
            self._write_kv("EMAILS", f"{len(emails)} found")
        hashes = data.get("hashes", [])
        if hashes:
            self._write_kv("HASHES", f"{len(hashes)} files")
        if data.get("total_count", 0) == 0:
            self._write_line("  no IOCs found in email body", "dim")

    def populate_phase4(self, data):
        if data.get("skipped"):
            self.set_skipped()
            return
        if data.get("error"):
            self.set_error(data["error"])
            return
        self.set_done()
        self._write_kv("CHECKED", data.get("total_checked", 0))
        mal = data.get("malicious_count", 0)
        self._write_kv("MALICIOUS", mal, "crit" if mal > 0 else "good")
        for res in data.get("results", [])[:10]:
            ioc = res.get("ioc", "")[:45]
            ioc_type = res.get("type", "")
            verdicts = res.get("verdicts", [])
            verdict_str = "  ".join(verdicts[:3])
            is_mal = any("malicious" in v for v in verdicts)
            tag = "crit" if is_mal else ("warn" if any("suspicious" in v for v in verdicts) else "dim")
            self._write_line(f"  [{ioc_type}] {ioc}", tag)
            if verdicts:
                self._write_line(f"         {verdict_str[:65]}", "dim")

    def populate_phase5(self, data):
        if data.get("error"):
            self.set_error(data["error"])
            return
        self.set_done()
        label = data.get("label", "unknown").upper()
        conf  = data.get("confidence", 0)
        phi   = data.get("phishing_probability", 0)
        model = data.get("model_used", "unknown")
        label_tag = "crit" if label == "PHISHING" else "good"
        self._write_kv("VERDICT", label, label_tag)
        self._write_kv("CONFIDENCE", f"{conf:.1%}")
        self._write_kv("MODEL", model)

        # probability bar
        bar_filled = int(phi * 20)
        bar = "#" * bar_filled + "." * (20 - bar_filled)
        self.text.config(state="normal")
        self.text.insert("end", f"{'P(phish)':<12}", "label")
        self.text.insert("end", f"[{bar}] ", "crit" if phi > 0.5 else "dim")
        self.text.insert("end", f"{phi:.4f}\n", "value")
        self.text.config(state="disabled")
        self._resize()

        details = data.get("details", {})
        if details.get("matched_indicators"):
            self._write_line("  indicators:", "dim")
            for ind in details["matched_indicators"][:5]:
                self._write_line(f"    * {ind}", "warn")

    def populate_phase6(self, data):
        if data.get("skipped"):
            self.set_skipped()
            self._write_line("  no attachments in this email", "dim")
            return
        if data.get("error"):
            self.set_error(data["error"])
            return
        self.set_done()
        self._write_kv("COUNT", data.get("attachment_count", 0))
        self._write_kv("CRITICAL", data.get("critical_count", 0),
                       "crit" if data.get("critical_count", 0) > 0 else "dim")
        for att in data.get("attachments", []):
            self._write_line(f"  FILE  {att.get('filename', '?')}", "value")
            self._write_line(f"        {att.get('true_file_type', '')}  {att.get('size_bytes', 0):,}B  risk:{att.get('risk_level', '?').upper()}", "dim")
            sha = att.get("hashes", {}).get("sha256", "")
            if sha:
                self._write_line(f"        SHA256: {sha[:40]}...", "dim")
            for f in att.get("findings", [])[:3]:
                self._write_line(f"        ! {f.get('message', '')[:60]}", "crit")

    def populate_phase7(self, data):
        if data.get("error"):
            self.set_error(data["error"])
            return
        self.set_done()
        score = data.get("score", 0)
        sev   = data.get("severity", "unknown").upper()
        sev_tag = {"CRITICAL": "crit", "HIGH": "warn", "MEDIUM": "warn", "LOW": "good"}.get(sev, "dim")
        self._write_kv("SCORE", f"{score}/100", sev_tag)
        self._write_kv("SEVERITY", sev, sev_tag)
        self._write_kv("FINDINGS", data.get("finding_count", 0))
        for f in data.get("findings", [])[:8]:
            pts = f.get("points", 0)
            desc = f.get("description", "")[:65]
            sev_f = f.get("severity", "info")
            tag = "crit" if sev_f == "critical" else ("warn" if sev_f == "warning" else "dim")
            self._write_line(f"  +{pts:<3}  {desc}", tag)
        techs = data.get("mitre_techniques", [])
        if techs:
            self._write_line("  MITRE ATT&CK:", "label")
            for t in techs:
                self._write_line(f"    {t.get('id','')}  {t.get('name','')}", "brass")

    def populate_phase9(self, data):
        if data.get("skipped"):
            self.set_skipped()
            fallback = data.get("fallback", {})
            summary = fallback.get("executive_summary", "")
            if summary:
                self._write_line(summary[:120], "dim")
            return
        if data.get("error"):
            self.set_error(data["error"])
            return
        self.set_done()
        self._write_kv("MODEL", data.get("llm_model", "unknown"))
        self._write_kv("ATTACK", data.get("attack_type", "unknown"), "warn")
        summary = data.get("executive_summary", "")
        if summary:
            self._write_line("  SUMMARY:", "label")
            self._write_line(f"  {summary[:140]}", "value")
        actions = data.get("recommended_actions", [])
        if actions:
            self._write_line("  ACTIONS:", "label")
            for i, act in enumerate(actions[:4], 1):
                self._write_line(f"  {i}. {act[:75]}", "dim")

    def populate_phase8(self, data):
        if data.get("skipped"):
            self.set_skipped()
            return
        if data.get("error"):
            self.set_error(data["error"])
            return
        self.set_done()
        path = data.get("report_path", "")
        self._write_kv("SAVED", os.path.basename(path) if path else "unknown")
        if path:
            self._write_line(f"  {path}", "dim")


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN APPLICATION
# ══════════════════════════════════════════════════════════════════════════════

class EmailAnalyzerGUI:

    def __init__(self, root: tk.Tk):
        self.root = root
        self._setup_window()

        self.current_file = None
        self._running = False
        self._proc = None
        self._output_dir = None
        self._last_report_path = None
        self._progress = 0.0
        self._click_count = 0

        self._no_enrich = tk.BooleanVar(value=True)
        self._no_llm    = tk.BooleanVar(value=False)

        self._build_ui()
        self._cycle_fact()

        # global mousewheel router — must happen after UI is built
        self.root.bind_all("<MouseWheel>", self._route_mousewheel)

    def _setup_window(self):
        self.root.title("ETA — Email Threat Analyzer")
        self.root.configure(bg=BG_MAIN)
        self.root.resizable(True, True)
        self.root.minsize(900, 580)
        w, h = 1100, 720
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = (sw - w) // 2
        y = (sh - h) // 2
        self.root.geometry(f"{w}x{h}+{x}+{y}")

    # ── BUILD UI ───────────────────────────────────────────────────────────────

    def _build_ui(self):
        self._build_titlebar()
        self._paned = tk.PanedWindow(
            self.root, orient="horizontal",
            bg=BORDER,
            sashwidth=3,
            sashrelief="flat",
            sashpad=0,
            showhandle=False,
        )
        self._paned.pack(fill="both", expand=True)

        self._sidebar_frame = tk.Frame(self._paned, bg=BG_SIDEBAR, width=200)
        self._center_frame  = tk.Frame(self._paned, bg=BG_MAIN)
        self._right_frame   = tk.Frame(self._paned, bg=BG_RIGHT, width=340)

        self._paned.add(self._sidebar_frame, minsize=160, width=200)
        self._paned.add(self._center_frame,  minsize=400)
        self._paned.add(self._right_frame,   minsize=200, width=340)

        self._build_sidebar(self._sidebar_frame)
        self._build_center(self._center_frame)
        self._build_right(self._right_frame)
        self._build_statusbar()

    def _build_titlebar(self):
        hdr = tk.Frame(self.root, bg=BG_SIDEBAR, height=52)
        hdr.pack(fill="x", side="top")
        hdr.pack_propagate(False)

        inner = tk.Frame(hdr, bg=BG_SIDEBAR)
        inner.place(relx=0, rely=0, relwidth=1, relheight=1)

        self.led = LedDot(inner, size=7)
        self.led.canvas.pack(side="left", padx=(18, 8), pady=(27, 0))

        tk.Label(
            inner, text="ETA",
            font=("Consolas", 14, "bold"),
            fg=BRASS, bg=BG_SIDEBAR,
        ).pack(side="left", pady=(28, 0))

        tk.Label(
            inner, text="  Email Threat Analyzer",
            font=FONT_LABEL, fg=TEXT_SEC, bg=BG_SIDEBAR,
        ).pack(side="left", pady=(28, 0))

        # version right side
        tk.Label(
            inner, text="v2.0  distilbert + groq",
            font=FONT_MINI, fg=BORDER, bg=BG_SIDEBAR,
        ).pack(side="right", padx=16, pady=(28, 0))

        # brass underline — 60% width, left-aligned, fades (fake it with a frame)
        line_frame = tk.Frame(self.root, bg=BG_SIDEBAR, height=4)
        line_frame.pack(fill="x", side="top")
        line_frame.pack_propagate(False)

        # 60%-width brass line, left-aligned
        self._brass_line_canvas = tk.Canvas(
            line_frame, bg=BG_SIDEBAR, height=2, highlightthickness=0, bd=0,
        )
        self._brass_line_canvas.pack(fill="x", side="top")
        self._brass_line_canvas.bind("<Configure>", self._draw_brass_line)

    def _draw_brass_line(self, event):
        c = self._brass_line_canvas
        c.delete("all")
        w = event.width
        # 60% width, brass, then fade to nothing (simulate with a gradient of rects)
        end = int(w * 0.60)
        # solid brass for first 80% of the 60%
        solid_end = int(end * 0.80)
        c.create_rectangle(0, 0, solid_end, 2, fill=BRASS, outline="")
        # fade: draw 5 steps of decreasing opacity (simulate with intermediate colors)
        fade_colors = ["#a8844a", "#7a6030", "#503d1a", "#2e2210", BG_SIDEBAR]
        step = (end - solid_end) // max(1, len(fade_colors))
        for i, fc in enumerate(fade_colors):
            x0 = solid_end + i * step
            x1 = solid_end + (i + 1) * step
            c.create_rectangle(x0, 0, x1, 2, fill=fc, outline="")

    def _build_body(self):
        body = tk.Frame(self.root, bg=BG_MAIN)
        body.pack(fill="both", expand=True)

        self._build_sidebar(body)

        # 1px divider
        tk.Frame(body, bg=BORDER, width=1).pack(side="left", fill="y")

        self._build_center(body)

        # 1px divider
        tk.Frame(body, bg=BORDER, width=1).pack(side="left", fill="y")

        self._build_right(body)

    def _build_sidebar(self, parent):
        side = parent
        side.configure(bg=BG_SIDEBAR)

        # FILE section
        self._sec_hdr(side, "FILE")
        self.file_lbl = tk.Label(
            side, text="no file selected",
            font=FONT_MINI, fg=TEXT_SEC, bg=BG_SIDEBAR,
            wraplength=176, justify="left", anchor="w",
        )
        self.file_lbl.pack(fill="x", padx=10, pady=(0, 6))

        self._sidebar_btn(side, "BROWSE .EML", self._browse_file, accent=False)

        self._divider(side)

        # OPTIONS section
        self._sec_hdr(side, "OPTIONS")
        opts = tk.Frame(side, bg=BG_SIDEBAR)
        opts.pack(fill="x", padx=10, pady=(0, 6))
        BrassCheckbox(opts, "Skip API Enrichment", self._no_enrich).pack(anchor="w", pady=3)
        BrassCheckbox(opts, "Skip Groq LLM", self._no_llm).pack(anchor="w", pady=3)

        self._divider(side)

        # RUN / STOP
        self.run_btn = self._sidebar_btn(
            side, "\u25b6  RUN ANALYSIS",
            lambda: self.root.after(50, self._run),
            accent=True,
        )
        self.stop_btn = self._sidebar_btn(
            side, "\u25a0  STOP",
            self._stop,
            accent=False,
            fg=BTN_STOP_FG, bg=BTN_STOP_BG,
        )
        self.stop_btn.config(state="disabled")

        self._divider(side)

        # PHASES section
        self._sec_hdr(side, "PHASES")
        phases_frame = tk.Frame(side, bg=BG_SIDEBAR)
        phases_frame.pack(fill="x", pady=(0, 4))

        self.phase_rows = {}
        for num, lbl, _ in PHASES:
            row = PhaseRow(phases_frame, num, lbl[:14])
            self.phase_rows[num] = row

        self._divider(side)

        # OPEN REPORT
        self.report_btn = self._sidebar_btn(side, "OPEN PDF REPORT", self._open_report, accent=False)
        self.report_btn.config(state="disabled")

        self._divider(side)

        # OUTPUT DIR link
        self._sec_hdr(side, "OUTPUT")
        self.outdir_lbl = tk.Label(
            side, text="--",
            font=FONT_MINI, fg=TEXT_SEC, bg=BG_SIDEBAR,
            wraplength=176, justify="left", anchor="w",
        )
        self.outdir_lbl.pack(fill="x", padx=10, pady=(0, 4))
        self._sidebar_btn(side, "OPEN FOLDER", self._open_output_dir, accent=False)

    def _build_center(self, parent):
        center = parent
        center.configure(bg=BG_MAIN)

        # ── score banner ──────────────────────────────────────────────────────
        banner = tk.Frame(center, bg=BG_MAIN, height=100)
        banner.pack(fill="x")
        banner.pack_propagate(False)

        score_area = tk.Frame(banner, bg=BG_MAIN)
        score_area.pack(side="left", padx=(64, 0), pady=16)

        self.score_var = tk.StringVar(value="--")
        self.score_lbl = tk.Label(
            score_area, textvariable=self.score_var,
            font=FONT_SCORE, fg=BORDER, bg=BG_MAIN,
        )
        self.score_lbl.pack(side="left")
        self.score_lbl.bind("<Button-1>", self._easter_egg)

        tk.Label(
            score_area, text="/100",
            font=("Consolas", 13), fg=TEXT_SEC, bg=BG_MAIN,
        ).pack(side="left", anchor="s", pady=(0, 14))

        sev_area = tk.Frame(banner, bg=BG_MAIN)
        sev_area.pack(side="left", padx=20)

        self.sev_var = tk.StringVar(value="NO FILE")
        self.sev_lbl = tk.Label(
            sev_area, textvariable=self.sev_var,
            font=FONT_BADGE,
            fg=BG_MAIN, bg=TEXT_SEC,
            padx=14, pady=5,
        )
        self.sev_lbl.pack()

        # progress bar + pct on right
        prog_area = tk.Frame(banner, bg=BG_MAIN)
        prog_area.pack(side="right", padx=(0, 64), pady=20)

        self.pct_lbl = tk.Label(
            prog_area, text="0%",
            font=("Consolas", 11), fg=TEXT_SEC, bg=BG_MAIN,
        )
        self.pct_lbl.pack(anchor="e")

        self.seg_bar = SegmentedBar(prog_area)
        self.seg_bar.pack(anchor="e", pady=(4, 0))

        self.time_lbl = tk.Label(
            prog_area, text="",
            font=FONT_MINI, fg=TEXT_SEC, bg=BG_MAIN,
        )
        self.time_lbl.pack(anchor="e", pady=(4, 0))

        # ── 1px ridge ─────────────────────────────────────────────────────────
        tk.Frame(center, bg=RIDGE, height=1).pack(fill="x")
        tk.Frame(center, bg=BORDER, height=1).pack(fill="x")

        # ── scrollable phase detail area ──────────────────────────────────────
        scroll_outer = tk.Frame(center, bg=BG_MAIN)
        scroll_outer.pack(fill="both", expand=True)

        vscroll = tk.Scrollbar(
            scroll_outer, orient="vertical",
            bg=BG_MAIN, troughcolor=BG_SIDEBAR,
            activebackground=BRASS, width=8,
        )
        vscroll.pack(side="right", fill="y")

        self.detail_canvas = tk.Canvas(
            scroll_outer, bg=BG_MAIN,
            highlightthickness=0, bd=0,
            yscrollcommand=vscroll.set,
        )
        self.detail_canvas.pack(side="left", fill="both", expand=True)
        vscroll.config(command=self.detail_canvas.yview)

        self.detail_frame = tk.Frame(self.detail_canvas, bg=BG_MAIN)
        self._detail_win = self.detail_canvas.create_window(
            (0, 0), window=self.detail_frame, anchor="nw"
        )
        self.detail_frame.bind("<Configure>", self._on_detail_resize)
        self.detail_canvas.bind("<Configure>", self._on_canvas_resize)
        # mousewheel is routed globally via _route_mousewheel

        # ── build phase detail cards ──────────────────────────────────────────
        self.phase_cards = {}
        cum = 0
        for num, lbl, weight in PHASES:
            card = PhaseDetail(self.detail_frame, num, lbl, cum, cum + weight)
            self.phase_cards[num] = card
            cum += weight

        # bottom spacer
        tk.Frame(self.detail_frame, bg=BG_MAIN, height=20).pack()

    def _build_right(self, parent):
        right = parent
        right.configure(bg=BG_RIGHT)

        self._sec_hdr(right, "RAW OUTPUT", bg=BG_RIGHT)

        log_frame = tk.Frame(right, bg=BG_LOG)
        log_frame.pack(fill="both", expand=True, padx=0, pady=0)

        log_scroll = tk.Scrollbar(
            log_frame, orient="vertical",
            bg=BG_LOG, troughcolor=BG_LOG,
            activebackground=BRASS, width=8,
        )
        self.log_text = tk.Text(
            log_frame,
            font=FONT_LOG, fg=TEXT_CODE, bg=BG_LOG,
            relief="flat", bd=0,
            state="disabled",
            wrap="none",
            highlightthickness=0,
            yscrollcommand=log_scroll.set,
            padx=10, pady=8,
            insertbackground=BRASS,
        )
        log_scroll.config(command=self.log_text.yview)
        log_scroll.pack(side="right", fill="y")
        self.log_text.pack(side="left", fill="both", expand=True)

        # color tags for log
        self.log_text.tag_configure("brass", foreground=BRASS)
        self.log_text.tag_configure("crit",  foreground=SEV_CRIT)
        self.log_text.tag_configure("warn",  foreground=SEV_HIGH)
        self.log_text.tag_configure("dim",   foreground=TEXT_SEC)
        self.log_text.tag_configure("data",  foreground="#3a3630")  # ##ETA lines hidden

    def _build_statusbar(self):
        tk.Frame(self.root, bg=RIDGE, height=1).pack(fill="x", side="bottom")
        bar = tk.Frame(self.root, bg=BG_SIDEBAR, height=24)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)

        self.status_lbl = tk.Label(
            bar, text="ready.",
            font=FONT_MINI, fg=TEXT_SEC, bg=BG_SIDEBAR, anchor="w",
        )
        self.status_lbl.pack(side="left", padx=12)

        self.fact_lbl = tk.Label(
            bar, text="",
            font=FONT_MINI, fg=BORDER, bg=BG_SIDEBAR, anchor="e",
        )
        self.fact_lbl.pack(side="right", padx=10)

    # ── WIDGET HELPERS ─────────────────────────────────────────────────────────

    def _sec_hdr(self, parent, text, bg=BG_SIDEBAR):
        tk.Label(
            parent, text=text,
            font=FONT_MINI, fg=TEXT_SEC, bg=bg,
            anchor="w",
        ).pack(anchor="w", padx=10, pady=(8, 2))

    def _divider(self, parent):
        tk.Frame(parent, bg=RIDGE, height=1).pack(fill="x", pady=(6, 0))
        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", pady=(0, 4))

    def _sidebar_btn(self, parent, text, command, accent=False, fg=None, bg=None):
        _bg  = BRASS if accent else (bg or BG_MAIN)
        _fg  = BG_SIDEBAR if accent else (fg or TEXT_PRI)
        _abg = BRASS_HOV if accent else (bg or BG_MAIN)
        btn = tk.Button(
            parent, text=text,
            font=FONT_MINI,
            fg=_fg, bg=_bg,
            activeforeground=_fg,
            activebackground=_abg,
            disabledforeground=BORDER,
            relief="flat", borderwidth=0,
            highlightthickness=1,
            highlightbackground=BRASS if accent else BORDER,
            highlightcolor=BRASS,
            # asymmetric padding: left 24, right 20
            padx=0, pady=0,
            cursor="hand2",
            command=command,
        )
        # can't do asymmetric padx in tk.Button directly, use place or a wrapper
        btn.pack(fill="x", padx=(10, 8), pady=(0, 3), ipady=4)
        return btn

    # ── CANVAS RESIZE ──────────────────────────────────────────────────────────

    def _on_detail_resize(self, event):
        self.detail_canvas.configure(scrollregion=self.detail_canvas.bbox("all"))

    def _on_canvas_resize(self, event):
        self.detail_canvas.itemconfig(self._detail_win, width=event.width)

    def _route_mousewheel(self, event):
        """Global mousewheel router.
        Walks widget ancestry to decide which scrollable area gets the event.
        Child Text widgets inside the detail canvas were eating the events before.
        """
        w = event.widget
        # check if the hovered widget lives inside the detail canvas area
        while w is not None:
            if w is self.detail_canvas or w is self.detail_frame:
                self.detail_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
                return
            if w is self.log_text:
                # let the log Text widget scroll itself naturally
                return
            try:
                w = w.master
            except Exception:
                break
        # fallback — scroll the detail canvas
        self.detail_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    # ── FILE BROWSE ────────────────────────────────────────────────────────────

    def _browse_file(self):
        path = fd.askopenfilename(
            title="Select .eml file",
            filetypes=[("Email files", "*.eml"), ("All files", "*.*")],
            initialdir=os.path.join(_DIR, "samples"),
        )
        if path:
            self.current_file = path
            fname = os.path.basename(path)
            display = fname if len(fname) <= 26 else "..." + fname[-23:]
            self.file_lbl.config(text=display)
            self._set_status(f"loaded: {fname}")
            self._reset()

    # ── RUN / STOP ────────────────────────────────────────────────────────────

    def _run(self):
        if self._running:
            return
        if not self.current_file:
            mb.showwarning("No file", "Select a .eml file first.")
            return
        if not os.path.exists(self.current_file):
            mb.showerror("Missing", f"File not found:\n{self.current_file}")
            return

        self._reset()           # clear everything BEFORE starting
        self._running = True
        self.run_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.report_btn.config(state="disabled")
        self.led.start()
        self._set_status("analysis running...")

        # create output directory for this email
        email_name = os.path.splitext(os.path.basename(self.current_file))[0]
        self._output_dir = os.path.join(OUTPUT_ROOT, email_name)
        os.makedirs(self._output_dir, exist_ok=True)
        self.outdir_lbl.config(text=email_name)

        cmd = [PYTHON_EXE, MAIN_SCRIPT, self.current_file,
               "--output-dir", self._output_dir]
        if self._no_enrich.get():
            cmd.append("--no-enrich")
        if self._no_llm.get():
            cmd.append("--no-llm")

        threading.Thread(target=self._worker, args=(cmd,), daemon=True).start()

    def _worker(self, cmd):
        start = time.time()
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                cwd=_DIR,
            )
            for line in self._proc.stdout:
                line = line.rstrip("\n\r")
                if line:
                    self.root.after(0, self._handle_line, line)
            self._proc.wait()
            elapsed = time.time() - start
            self.root.after(0, self._done, elapsed, self._proc.returncode)
        except Exception as e:
            self.root.after(0, self._error, str(e))

    def _handle_line(self, line):
        clean = re.sub(r'\x1b\[[0-9;]*m', '', line)

        # structured data line — parse it, hide in log
        if clean.startswith("##ETA_DATA:"):
            self.log_text.config(state="normal")
            self.log_text.insert("end", clean + "\n", "data")
            self.log_text.config(state="disabled")
            self._parse_eta_data(clean)
            return

        # show in log with coloring
        self._log_append(clean)

        # phase status detection
        phase_m = re.search(r'\[Phase\s+(\d+)\]', clean)
        if phase_m:
            num = phase_m.group(1)
            if num in self.phase_rows:
                has_done  = '\u2705' in clean or 'saved:' in clean.lower()
                has_run   = '\u23f3' in clean
                has_skip  = '\u23ed' in clean or 'skipped' in clean.lower()
                has_err   = '\u274c' in clean

                if has_err:
                    self.phase_rows[num].set_error()
                    if num in self.phase_cards:
                        self.phase_cards[num].set_error()
                elif has_skip:
                    self.phase_rows[num].set_skipped()
                elif has_done:
                    self.phase_rows[num].set_done()
                elif has_run:
                    self.phase_rows[num].set_running()
                    if num in self.phase_cards:
                        self.phase_cards[num].set_running()

        # risk score for banner
        sm = re.search(r'Risk score[:\s]+(\d+)/100', clean, re.IGNORECASE)
        if sm:
            self._last_score = int(sm.group(1))

        sev_m = re.search(r'THREAT LEVEL:\s+(\w+)', clean, re.IGNORECASE)
        if sev_m:
            self._update_score(self._last_score, sev_m.group(1).lower())

        # report path
        rpt_m = re.search(r'Report saved:\s+(.+\.pdf)', clean, re.IGNORECASE)
        if rpt_m:
            self._last_report_path = rpt_m.group(1).strip()
            self.report_btn.config(state="normal")

    def _parse_eta_data(self, line):
        """Parse ##ETA_DATA:N:{json} and populate the phase detail card."""
        try:
            _, rest = line.split(":", 1)
            num_str, json_str = rest.split(":", 1)
            num = int(num_str)
            data = json.loads(json_str)
        except Exception:
            return

        card = self.phase_cards.get(num)
        if not card:
            return

        populate_map = {
            1: card.populate_phase1,
            2: card.populate_phase2,
            3: card.populate_phase3,
            4: card.populate_phase4,
            5: card.populate_phase5,
            6: card.populate_phase6,
            7: card.populate_phase7,
            9: card.populate_phase9,
            8: card.populate_phase8,
        }
        fn = populate_map.get(num)
        if fn:
            fn(data)

        # update progress bar
        pct_range = PHASE_PROGRESS.get(num, (0, 0))
        new_pct = pct_range[1]
        self._update_progress(new_pct)

        # scroll detail to bottom so new content is visible
        self.detail_canvas.update_idletasks()
        self.detail_canvas.yview_moveto(1.0)

    def _update_progress(self, pct):
        self._progress = pct
        self.seg_bar.set_progress(pct)
        self.pct_lbl.config(text=f"{int(pct)}%")

    def _update_score(self, score, severity):
        col = SEV_COLORS.get(severity, TEXT_SEC)
        self.score_var.set(str(score))
        self.score_lbl.config(fg=col)
        self.sev_var.set(f" {severity.upper()} ")
        self.sev_lbl.config(fg=BG_MAIN, bg=col)

    def _done(self, elapsed, returncode):
        self._running = False
        self._proc = None
        self.run_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.led.stop(lit=True)
        # don't force 100% — last ETA_DATA already set the final pct.
        # just show the elapsed time next to the bar.
        self.time_lbl.config(text=f"{elapsed:.1f}s total")
        self._set_status(f"done in {elapsed:.1f}s  |  output: {self._output_dir}")

    def _error(self, msg):
        self._running = False
        self._proc = None
        self.run_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.led.stop(lit=False)
        self._set_status(f"error: {msg[:80]}")
        mb.showerror("Error", f"Subprocess failed:\n\n{msg}")

    def _stop(self):
        if self._proc and self._running:
            try:
                self._proc.terminate()
            except Exception:
                pass
        self._running = False
        self.run_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.led.stop(lit=False)
        self._set_status("stopped by user.")

    # ── RESET ─────────────────────────────────────────────────────────────────

    def _reset(self):
        # score banner
        self.score_var.set("--")
        self.score_lbl.config(fg=BORDER)
        self.sev_var.set("--")
        self.sev_lbl.config(fg=TEXT_SEC, bg=BORDER)

        # progress — force to zero immediately
        self._progress = 0.0
        self.pct_lbl.config(text="0%")
        self.time_lbl.config(text="")
        self.seg_bar.reset()  # clears all 10 segments to empty

        self._last_score = 0
        self._last_report_path = None
        self._click_count = 0

        # clear log
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.config(state="disabled")

        # reset all phase sidebar rows
        for row in self.phase_rows.values():
            row.reset()

        # reset all phase detail cards AND scroll back to top
        for card in self.phase_cards.values():
            card.reset()
        self.detail_canvas.yview_moveto(0.0)

    # ── LOG ───────────────────────────────────────────────────────────────────

    def _log_append(self, text):
        tag = "dim"
        if "error" in text.lower() or "\u274c" in text:
            tag = "crit"
        elif "\u2705" in text or "DONE" in text:
            tag = "brass"
        elif "CRITICAL" in text or "malicious" in text.lower():
            tag = "warn"

        self.log_text.config(state="normal")
        self.log_text.insert("end", text + "\n", tag)
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    # ── OPEN ACTIONS ──────────────────────────────────────────────────────────

    def _open_report(self):
        if self._last_report_path and os.path.exists(self._last_report_path):
            os.startfile(self._last_report_path)
        else:
            mb.showinfo("Not ready", "No report available. Run analysis first.")

    def _open_output_dir(self):
        if self._output_dir and os.path.exists(self._output_dir):
            os.startfile(self._output_dir)
        else:
            mb.showinfo("Not ready", "No output folder yet. Run analysis first.")

    # ── STATUS BAR ────────────────────────────────────────────────────────────

    def _set_status(self, msg):
        self.status_lbl.config(text=msg)

    def _cycle_fact(self):
        self.fact_lbl.config(text=random.choice(STATUS_FACTS))
        self.root.after(9000, self._cycle_fact)

    # ── EASTER EGG ────────────────────────────────────────────────────────────

    def _easter_egg(self, event=None):
        self._click_count += 1
        if self._click_count >= 3:
            titles = [
                "ETA -- the phishing is coming from inside the headers",
                "ETA -- we found things. warm, brass-colored things.",
                "ETA -- your DMARC policy called. it's disappointed.",
                "ETA [CLASSIFIED] -- EYES ONLY",
                "ETA -- llama 70B says this email is very bad actually",
            ]
            self.root.title(random.choice(titles))
            self._click_count = 0


# ── ENTRY POINT ───────────────────────────────────────────────────────────────

def main():
    root = tk.Tk()
    app = EmailAnalyzerGUI(root)

    def on_close():
        if app._running and app._proc:
            try:
                app._proc.terminate()
            except Exception:
                pass
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
