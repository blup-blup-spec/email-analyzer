"""
main.py -- Email Threat Analyzer Entry Point (v2)

Orchestrates all 9 analysis phases. After every phase,
emits a structured ##ETA_DATA line so the GUI can parse
and display per-phase results in real time.

Also writes per-phase JSON files to --output-dir if supplied.

Usage:
    python main.py <eml_file> [--no-enrich] [--no-llm] [--output-dir DIR]
"""

import argparse
import sys
import os
import json
import time

# Fix Windows encoding
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if sys.stderr.encoding != 'utf-8':
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from colorama import init, Fore, Style
    init()
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False


def color(text, color_code=""):
    if HAS_COLOR and color_code:
        return f"{color_code}{text}{Style.RESET_ALL}"
    return text


def emit_data(phase_num, data, output_dir=None):
    """Emit structured phase data for GUI parsing and save to output folder."""
    try:
        payload = json.dumps(data, default=str, ensure_ascii=False)
        print(f"##ETA_DATA:{phase_num}:{payload}", flush=True)
    except Exception:
        pass

    if output_dir:
        phase_names = {
            1: "01_parse", 2: "02_headers", 3: "03_iocs",
            4: "04_enrichment", 5: "05_ml_result",
            6: "06_attachments", 7: "07_risk_score",
            9: "09_llm_narrative", 8: "08_report",
        }
        fname = phase_names.get(phase_num, f"phase_{phase_num:02d}") + ".json"
        try:
            fpath = os.path.join(output_dir, fname)
            with open(fpath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str, ensure_ascii=False)
        except Exception:
            pass


def print_phase(phase_num, name, status="RUNNING"):
    icons = {"RUNNING": "\u23f3", "DONE": "\u2705", "SKIP": "\u23ed", "ERROR": "\u274c"}
    icon = icons.get(status, "*")
    phase_str = f"Phase {phase_num}" if phase_num else "      "
    line = f"  {icon} [{phase_str}] {name}"
    if status == "DONE":
        print(color(line, Fore.GREEN if HAS_COLOR else ""))
    elif status == "ERROR":
        print(color(line, Fore.RED if HAS_COLOR else ""))
    elif status == "SKIP":
        print(color(line, Fore.YELLOW if HAS_COLOR else ""))
    else:
        print(line, end="", flush=True)


def print_banner():
    banner = """
\u256c\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u256c
\u2551        \U0001f6e1\ufe0f  EMAIL THREAT ANALYSIS PLATFORM  \U0001f6e1\ufe0f            \u2551
\u2551     AI-Powered Phishing Detection & IOC Intelligence     \u2551
\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d
    """
    print(color(banner, Fore.CYAN if HAS_COLOR else ""))


def main():
    parser = argparse.ArgumentParser(
        description="Email Threat Analyzer -- AI-powered phishing detection",
    )
    parser.add_argument("eml_file", help="Path to the .eml file to analyze")
    parser.add_argument("--no-enrich", action="store_true", help="Skip API enrichment")
    parser.add_argument("--no-llm", action="store_true", help="Skip LLM analysis")
    parser.add_argument("--no-report", action="store_true", help="Skip PDF report")
    parser.add_argument("--output-dir", default=None,
                        help="Directory to write per-phase JSON output files")

    args = parser.parse_args()

    if not os.path.exists(args.eml_file):
        print(f"\u274c File not found: {args.eml_file}")
        sys.exit(1)

    # Create output dir if specified
    output_dir = args.output_dir
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    print_banner()
    print(f"  \U0001f4e7 Analyzing: {args.eml_file}")
    print(f"  \u23f0 Started: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    if output_dir:
        print(f"  \U0001f4c1 Output dir: {output_dir}")
    print(f"  {chr(9472) * 54}")

    total_start = time.time()

    # ==========================================================
    # Phase 1 -- Parse Email
    # ==========================================================
    print_phase(1, "Parsing email file...")
    try:
        from src.parser import parse_eml_file, get_combined_body_text
        parsed_email = parse_eml_file(args.eml_file)
        body_text = get_combined_body_text(parsed_email)
        print(f"\r", end="")
        print_phase(1, f"Email parsed -- From: {parsed_email.get('from_address', 'N/A')}, "
                       f"Subject: {parsed_email.get('subject', 'N/A')[:40]}", "DONE")
        emit_data(1, {
            "from_address": parsed_email.get("from_address", ""),
            "from": parsed_email.get("from", ""),
            "to": parsed_email.get("to", ""),
            "subject": parsed_email.get("subject", ""),
            "date": parsed_email.get("date", ""),
            "message_id": parsed_email.get("message_id", ""),
            "reply_to": parsed_email.get("reply_to", ""),
            "return_path": parsed_email.get("return_path", ""),
            "has_attachments": parsed_email.get("has_attachments", False),
            "attachment_count": parsed_email.get("attachment_count", 0),
            "hop_count": parsed_email.get("hop_count", 0),
            "x_mailer": parsed_email.get("x_mailer", ""),
            "body_length": len(body_text),
        }, output_dir)
    except Exception as e:
        print(f"\r", end="")
        print_phase(1, f"Parser error: {e}", "ERROR")
        emit_data(1, {"error": str(e)}, output_dir)
        sys.exit(1)

    # ==========================================================
    # Phase 2 -- Header Analysis
    # ==========================================================
    print_phase(2, "Analyzing headers...")
    try:
        from src.header_analysis import analyze_headers
        header_analysis = analyze_headers(parsed_email)
        anomaly_count = len(header_analysis.get("anomalies", []))
        print(f"\r", end="")
        print_phase(2, f"Header analysis complete -- {anomaly_count} anomalies found", "DONE")
        auth = header_analysis.get("authentication", {})
        emit_data(2, {
            "anomaly_count": anomaly_count,
            "anomalies": header_analysis.get("anomalies", []),
            "spf": auth.get("spf", {}).get("status", "unknown"),
            "dkim": auth.get("dkim", {}).get("status", "unknown"),
            "dmarc": auth.get("dmarc", {}).get("status", "unknown"),
            "hop_count": len(parsed_email.get("received_headers", [])),
            "x_mailer": parsed_email.get("x_mailer", ""),
            "severity_summary": header_analysis.get("severity_summary", {}),
        }, output_dir)
    except Exception as e:
        print(f"\r", end="")
        print_phase(2, f"Header analysis error: {e}", "ERROR")
        emit_data(2, {"error": str(e)}, output_dir)
        header_analysis = {"anomalies": [], "authentication": {}, "severity_summary": {}}

    # ==========================================================
    # Phase 3 -- IOC Extraction
    # ==========================================================
    print_phase(3, "Extracting IOCs...")
    try:
        from src.ioc_extractor import extract_iocs
        iocs = extract_iocs(parsed_email)
        print(f"\r", end="")
        print_phase(3, f"IOCs extracted -- {iocs.get('total_count', 0)} indicators found "
                       f"({len(iocs.get('urls', []))} URLs, {len(iocs.get('public_ips', []))} IPs)", "DONE")
        emit_data(3, {
            "total_count": iocs.get("total_count", 0),
            "urls": iocs.get("urls", [])[:20],
            "ips": iocs.get("ips", [])[:20],
            "public_ips": iocs.get("public_ips", [])[:20],
            "domains": iocs.get("domains", [])[:20],
            "emails": iocs.get("emails", [])[:20],
            "hashes": iocs.get("hashes", [])[:10],
        }, output_dir)
    except Exception as e:
        print(f"\r", end="")
        print_phase(3, f"IOC extraction error: {e}", "ERROR")
        emit_data(3, {"error": str(e)}, output_dir)
        iocs = {"urls": [], "ips": [], "public_ips": [], "domains": [], "emails": [], "hashes": [], "total_count": 0}

    # ==========================================================
    # Phase 4 -- Threat Intelligence Enrichment
    # ==========================================================
    enrichment = {}
    if args.no_enrich:
        print_phase(4, "Enrichment skipped (--no-enrich flag)", "SKIP")
        emit_data(4, {"skipped": True}, output_dir)
    else:
        print_phase(4, "Enriching IOCs via threat intelligence APIs...")
        try:
            from src.enrichment import enrich_iocs
            enrichment = enrich_iocs(iocs)
            malicious_count = enrichment.get("_summary", {}).get("malicious_count", 0)
            total_enriched = enrichment.get("_summary", {}).get("total_iocs_enriched", 0)
            print(f"\r", end="")
            print_phase(4, f"Enrichment complete -- {total_enriched} IOCs checked, "
                           f"{malicious_count} flagged malicious", "DONE")
            # Build a clean summary for the GUI
            enrichment_summary = []
            for ioc_val, ioc_data in enrichment.items():
                if ioc_val.startswith("_"):
                    continue
                ioc_type = ioc_data.get("type", "?")
                verdicts = []
                for src_name, src_data in ioc_data.get("sources", {}).items():
                    if isinstance(src_data, dict):
                        verdicts.append(f"{src_name}: {src_data.get('verdict', '?')}")
                enrichment_summary.append({
                    "ioc": ioc_val[:60],
                    "type": ioc_type,
                    "verdicts": verdicts,
                })
            emit_data(4, {
                "total_checked": total_enriched,
                "malicious_count": malicious_count,
                "results": enrichment_summary[:15],
            }, output_dir)
        except Exception as e:
            print(f"\r", end="")
            print_phase(4, f"Enrichment error: {e}", "ERROR")
            emit_data(4, {"error": str(e)}, output_dir)

    # ==========================================================
    # Phase 5 -- ML Classification
    # ==========================================================
    print_phase(5, "Running ML phishing classifier...")
    try:
        from src.ml_classifier import classify_email
        ml_result = classify_email(body_text)
        print(f"\r", end="")
        label_display = ml_result.get("label", "unknown").upper()
        conf = ml_result.get("confidence", 0)
        model = ml_result.get("model_used", "unknown")
        print_phase(5, f"ML classification: {label_display} "
                       f"(confidence: {conf:.1%}, model: {model})", "DONE")
        emit_data(5, {
            "label": ml_result.get("label", "unknown"),
            "confidence": ml_result.get("confidence", 0),
            "phishing_probability": ml_result.get("phishing_probability", 0),
            "model_used": ml_result.get("model_used", "unknown"),
            "details": ml_result.get("details", {}),
        }, output_dir)
    except Exception as e:
        print(f"\r", end="")
        print_phase(5, f"ML classification error: {e}", "ERROR")
        emit_data(5, {"error": str(e)}, output_dir)
        ml_result = {"label": "unknown", "confidence": 0, "phishing_probability": 0, "model_used": "error"}

    # ==========================================================
    # Phase 6 -- Attachment Analysis
    # ==========================================================
    attachment_results = []
    if parsed_email.get("has_attachments"):
        print_phase(6, "Analyzing attachments...")
        try:
            from src.attachment import analyze_attachments
            attachment_results = analyze_attachments(parsed_email)
            critical_atts = sum(1 for a in attachment_results if a.get("risk_level") == "critical")
            print(f"\r", end="")
            print_phase(6, f"Attachment analysis complete -- {len(attachment_results)} attachments, "
                           f"{critical_atts} critical", "DONE")
            emit_data(6, {
                "attachment_count": len(attachment_results),
                "critical_count": critical_atts,
                "attachments": [
                    {
                        "filename": a.get("filename", ""),
                        "size_bytes": a.get("size_bytes", 0),
                        "true_file_type": a.get("true_file_type", ""),
                        "risk_level": a.get("risk_level", "low"),
                        "findings": a.get("findings", []),
                        "hashes": a.get("hashes", {}),
                    }
                    for a in attachment_results
                ],
            }, output_dir)
        except Exception as e:
            print(f"\r", end="")
            print_phase(6, f"Attachment analysis error: {e}", "ERROR")
            emit_data(6, {"error": str(e)}, output_dir)
    else:
        print_phase(6, "No attachments to analyze", "SKIP")
        emit_data(6, {"skipped": True, "reason": "no attachments"}, output_dir)

    # ==========================================================
    # Phase 7 -- Risk Scoring
    # ==========================================================
    print_phase(7, "Calculating risk score...")
    try:
        from src.risk_scorer import calculate_risk
        analysis_bundle = {
            "header_analysis": header_analysis,
            "enrichment": enrichment,
            "ml_result": ml_result,
            "attachment_results": attachment_results,
            "parsed_email": parsed_email,
        }
        risk_result = calculate_risk(analysis_bundle)
        print(f"\r", end="")
        severity = risk_result.get("severity", "unknown").upper()
        score = risk_result.get("score", 0)
        severity_color = {
            "CRITICAL": Fore.RED, "HIGH": Fore.YELLOW,
            "MEDIUM": Fore.YELLOW, "LOW": Fore.GREEN,
        }.get(severity, "") if HAS_COLOR else ""
        print_phase(7, f"Risk score: {score}/100 -- "
                       f"{color(severity, severity_color)}", "DONE")
        emit_data(7, {
            "score": score,
            "severity": risk_result.get("severity", "unknown"),
            "finding_count": risk_result.get("finding_count", 0),
            "findings": risk_result.get("findings", []),
            "mitre_techniques": risk_result.get("mitre_techniques", []),
        }, output_dir)
    except Exception as e:
        print(f"\r", end="")
        print_phase(7, f"Risk scoring error: {e}", "ERROR")
        emit_data(7, {"error": str(e)}, output_dir)
        risk_result = {"score": 0, "severity": "unknown", "findings": [], "finding_count": 0, "mitre_techniques": []}

    # ==========================================================
    # Phase 9 -- LLM Threat Analyst
    # ==========================================================
    llm_analysis = {}
    if args.no_llm:
        print_phase(9, "LLM analysis skipped (--no-llm flag)", "SKIP")
        from src.llm_analyst import _generate_fallback
        llm_analysis = _generate_fallback(parsed_email, iocs, risk_result, ml_result, header_analysis)
        emit_data(9, {"skipped": True, "fallback": llm_analysis}, output_dir)
    else:
        print_phase(9, "Generating AI threat narrative...")
        try:
            from src.llm_analyst import generate_threat_narrative
            llm_analysis = generate_threat_narrative(
                parsed_email, iocs, risk_result, ml_result, header_analysis
            )
            llm_model = llm_analysis.get("llm_model", "fallback")
            print(f"\r", end="")
            print_phase(9, f"AI narrative generated (model: {llm_model})", "DONE")
            emit_data(9, {
                "executive_summary": llm_analysis.get("executive_summary", ""),
                "threat_narrative": llm_analysis.get("threat_narrative", ""),
                "attack_type": llm_analysis.get("attack_type", "unknown"),
                "recommended_actions": llm_analysis.get("recommended_actions", []),
                "mitre_analysis": llm_analysis.get("mitre_analysis", []),
                "confidence_assessment": llm_analysis.get("confidence_assessment", ""),
                "llm_model": llm_model,
            }, output_dir)
        except Exception as e:
            print(f"\r", end="")
            print_phase(9, f"LLM analysis error: {e}", "ERROR")
            from src.llm_analyst import _generate_fallback
            llm_analysis = _generate_fallback(parsed_email, iocs, risk_result, ml_result, header_analysis)
            emit_data(9, {"error": str(e), "fallback": llm_analysis}, output_dir)

    # ==========================================================
    # Phase 8 -- PDF Report Generation
    # ==========================================================
    if args.no_report:
        print_phase(8, "Report generation skipped (--no-report flag)", "SKIP")
        emit_data(8, {"skipped": True}, output_dir)
    else:
        print_phase(8, "Generating PDF report...")
        try:
            from src.report_generator import generate_report
            report_data = {
                "parsed_email": parsed_email,
                "header_analysis": header_analysis,
                "iocs": iocs,
                "enrichment": enrichment,
                "ml_result": ml_result,
                "attachment_results": attachment_results,
                "risk_result": risk_result,
                "llm_analysis": llm_analysis,
            }
            # If output_dir given, save PDF there too
            if output_dir:
                import config as cfg
                orig_reports = cfg.REPORTS_DIR
                cfg.REPORTS_DIR = output_dir
                report_path = generate_report(report_data)
                cfg.REPORTS_DIR = orig_reports
            else:
                report_path = generate_report(report_data)

            print(f"\r", end="")
            print_phase(8, f"Report saved: {report_path}", "DONE")
            emit_data(8, {"report_path": report_path}, output_dir)
        except Exception as e:
            print(f"\r", end="")
            print_phase(8, f"Report generation error: {e}", "ERROR")
            emit_data(8, {"error": str(e)}, output_dir)
            report_path = None

    # ==========================================================
    # Summary
    # ==========================================================
    elapsed = time.time() - total_start
    print(f"\n  {chr(9472) * 54}")
    print(f"  \u23f1\ufe0f  Analysis completed in {elapsed:.1f} seconds")

    severity = risk_result.get("severity", "unknown").upper()
    score = risk_result.get("score", 0)
    print(f"\n  {'=' * 54}")
    if severity in ("CRITICAL", "HIGH"):
        print(color(f"  \u26a0\ufe0f  THREAT LEVEL: {severity} ({score}/100)", Fore.RED if HAS_COLOR else ""))
    elif severity == "MEDIUM":
        print(color(f"  \u26a1 THREAT LEVEL: {severity} ({score}/100)", Fore.YELLOW if HAS_COLOR else ""))
    else:
        print(color(f"  \u2705 THREAT LEVEL: {severity} ({score}/100)", Fore.GREEN if HAS_COLOR else ""))
    print(f"  {'=' * 54}")

    if risk_result.get("findings"):
        print(f"\n  \U0001f4cb Key Findings:")
        for finding in risk_result["findings"][:5]:
            sev_icon = {"critical": "\U0001f534", "warning": "\U0001f7e1", "info": "\U0001f535"}.get(finding["severity"], "\u26aa")
            print(f"     {sev_icon} +{finding['points']}pts -- {finding['description'][:65]}")

    if risk_result.get("mitre_techniques"):
        print(f"\n  \U0001f3af MITRE ATT&CK:")
        for tech in risk_result["mitre_techniques"]:
            print(f"     * {tech['id']} -- {tech['name']}")

    if llm_analysis.get("executive_summary"):
        print(f"\n  \U0001f916 AI Summary:")
        print(f"     {llm_analysis['executive_summary'][:120]}")

    print()


if __name__ == "__main__":
    main()
