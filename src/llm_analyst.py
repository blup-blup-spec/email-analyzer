"""
Phase 9 -- LLM Threat Analyst

Uses Groq API (Llama 3.1 70B) to generate:
- Human-readable threat narrative summary
- Dynamic MITRE ATT&CK technique mapping with reasoning
- Contextual incident response / remediation steps

Falls back to static templates if API is unavailable.
"""

import json
import sys
import os
from typing import Dict, Any, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

_groq_client = None


def generate_threat_narrative(parsed_email, iocs, risk_result, ml_result, header_analysis):
    """Generate a complete LLM-powered threat analysis."""
    context = _build_context(parsed_email, iocs, risk_result, ml_result, header_analysis)

    llm_result = _call_groq(context)
    if llm_result:
        return llm_result

    return _generate_fallback(parsed_email, iocs, risk_result, ml_result, header_analysis)


def _build_context(parsed_email, iocs, risk_result, ml_result, header_analysis):
    severity = risk_result.get("severity", "unknown").upper()
    score = risk_result.get("score", 0)

    parts = [
        f"RISK SCORE: {score}/100 ({severity})",
        f"From: {parsed_email.get('from', 'N/A')}",
        f"To: {parsed_email.get('to', 'N/A')}",
        f"Subject: {parsed_email.get('subject', 'N/A')}",
        f"Date: {parsed_email.get('date', 'N/A')}",
        f"Reply-To: {parsed_email.get('reply_to', 'N/A')}",
    ]

    if ml_result:
        parts.append(
            f"ML Classification: {ml_result.get('label', 'N/A')} "
            f"(confidence: {ml_result.get('confidence', 0):.1%}, "
            f"model: {ml_result.get('model_used', 'N/A')})"
        )

    url_count = len(iocs.get("urls", []))
    ip_count = len(iocs.get("public_ips", []))
    domain_count = len(iocs.get("domains", []))
    parts.append(f"IOCs Found: {url_count} URLs, {ip_count} IPs, {domain_count} domains")

    if iocs.get("urls"):
        parts.append(f"Sample URLs: {', '.join(iocs['urls'][:3])}")

    anomaly_count = len(header_analysis.get("anomalies", []))
    parts.append(f"Header Anomalies: {anomaly_count}")
    for anomaly in header_analysis.get("anomalies", [])[:5]:
        parts.append(f"  - [{anomaly.get('severity', 'info')}] {anomaly.get('message', '')}")

    parts.append(f"Total Risk Findings: {risk_result.get('finding_count', 0)}")
    for finding in risk_result.get("findings", [])[:8]:
        parts.append(f"  - [{finding['severity']}] +{finding['points']}pts: {finding['description']}")

    techniques = risk_result.get("mitre_techniques", [])
    if techniques:
        tech_ids = [f"{t['id']} ({t['name']})" for t in techniques]
        parts.append(f"MITRE Techniques: {', '.join(tech_ids)}")

    return "\n".join(parts)


def _call_groq(context):
    global _groq_client

    if not config.GROQ_API_KEY:
        return None

    try:
        if _groq_client is None:
            from groq import Groq
            _groq_client = Groq(api_key=config.GROQ_API_KEY)

        prompt = f"""You are an expert SOC (Security Operations Center) analyst.
Analyze the following email threat analysis data and provide a structured security assessment.

=== EMAIL ANALYSIS DATA ===
{context}
=== END DATA ===

Respond in EXACTLY this JSON format (no markdown, no code blocks, just raw JSON):
{{
    "executive_summary": "2-3 sentence executive summary of the threat level and key concerns. Be direct and actionable.",
    "threat_narrative": "Detailed 4-6 sentence narrative explaining the attack type, techniques used, and why this email is or is not a threat. Reference specific findings from the data.",
    "attack_type": "One of: credential_phishing, spearphishing_attachment, business_email_compromise, spam, financial_scam, clean_email, unknown",
    "mitre_analysis": [
        {{
            "technique_id": "T1566",
            "technique_name": "Phishing",
            "reasoning": "Why this technique applies based on the evidence"
        }}
    ],
    "recommended_actions": [
        "Action 1 - most critical action to take",
        "Action 2 - next priority",
        "Action 3 - additional measure"
    ],
    "confidence_assessment": "How confident you are in this analysis and any caveats"
}}"""

        # try each model in fallback order until one works
        models_to_try = getattr(config, "GROQ_MODEL_FALLBACKS", [config.GROQ_MODEL])
        response_text = None
        used_model = None

        for model_name in models_to_try:
            try:
                response = _groq_client.chat.completions.create(
                    model=model_name,
                    messages=[
                        {"role": "system", "content": "You are a SOC analyst. Respond only in valid JSON. Use plain ASCII only, no special unicode characters or em-dashes."},
                        {"role": "user", "content": prompt},
                    ],
                    max_tokens=config.GROQ_MAX_TOKENS,
                    temperature=config.GROQ_TEMPERATURE,
                )
                response_text = response.choices[0].message.content.strip()
                used_model = model_name
                break
            except Exception as model_err:
                print(f"[LLM] Model '{model_name}' failed: {model_err}")
                continue

        if response_text is None:
            print("[LLM] All Groq models failed.")
            return None

        if response_text.startswith("```"):
            lines = response_text.split("\n")
            response_text = "\n".join(lines[1:-1])

        llm_output = json.loads(response_text)

        return {
            "executive_summary": llm_output.get("executive_summary", ""),
            "threat_narrative": llm_output.get("threat_narrative", ""),
            "attack_type": llm_output.get("attack_type", "unknown"),
            "mitre_analysis": llm_output.get("mitre_analysis", []),
            "recommended_actions": llm_output.get("recommended_actions", []),
            "confidence_assessment": llm_output.get("confidence_assessment", ""),
            "llm_used": True,
            "llm_model": used_model or config.GROQ_MODEL,
        }

    except json.JSONDecodeError:
        return {
            "executive_summary": response_text[:500] if 'response_text' in dir() else "",
            "threat_narrative": "",
            "attack_type": "unknown",
            "mitre_analysis": [],
            "recommended_actions": [],
            "confidence_assessment": "LLM response was not in expected format",
            "llm_used": True,
            "llm_model": config.GROQ_MODEL,
            "raw_response": response_text[:1000] if 'response_text' in dir() else "",
        }
    except Exception as e:
        print(f"[LLM] Groq API error: {e}")
        return None


def _generate_fallback(parsed_email, iocs, risk_result, ml_result, header_analysis):
    """Generate analysis using static templates when LLM is unavailable."""
    severity = risk_result.get("severity", "low")
    score = risk_result.get("score", 0)
    subject = parsed_email.get("subject", "N/A")
    from_addr = parsed_email.get("from_address", "N/A")

    if severity == "critical":
        summary = (
            f"CRITICAL THREAT DETECTED -- Email from '{from_addr}' with subject '{subject}' "
            f"scored {score}/100 and poses an immediate security risk. "
            f"Multiple threat indicators were identified requiring urgent investigation."
        )
    elif severity == "high":
        summary = (
            f"HIGH RISK EMAIL -- Email from '{from_addr}' scored {score}/100. "
            f"Several suspicious indicators were found. Further investigation recommended."
        )
    elif severity == "medium":
        summary = (
            f"MODERATE RISK -- Email from '{from_addr}' scored {score}/100. "
            f"Some suspicious elements detected but no confirmed malicious activity."
        )
    else:
        summary = (
            f"LOW RISK -- Email from '{from_addr}' scored {score}/100. "
            f"No significant threat indicators detected."
        )

    actions = []
    if severity in ("critical", "high"):
        actions = [
            "Quarantine this email immediately and prevent delivery to the recipient",
            "Block the sender domain and associated IPs at the email gateway",
            "Check if any users have interacted with links or attachments in this email",
            "Report IOCs to your threat intelligence platform for correlation",
            "If credentials may have been compromised, initiate password reset procedures",
        ]
    elif severity == "medium":
        actions = [
            "Flag this email for manual review by a security analyst",
            "Monitor the sender domain for additional suspicious activity",
            "Warn the recipient about potential phishing indicators",
        ]
    else:
        actions = [
            "No immediate action required",
            "Continue monitoring for patterns from this sender",
        ]

    mitre_analysis = []
    for technique in risk_result.get("mitre_techniques", []):
        mitre_analysis.append({
            "technique_id": technique["id"],
            "technique_name": technique["name"],
            "reasoning": technique["description"],
        })

    return {
        "executive_summary": summary,
        "threat_narrative": (
            f"Analysis of email from {from_addr} identified {risk_result.get('finding_count', 0)} "
            f"security findings across header forensics, IOC enrichment, ML classification, "
            f"and content analysis. The overall risk score is {score}/100 ({severity})."
        ),
        "attack_type": _infer_attack_type(risk_result, ml_result),
        "mitre_analysis": mitre_analysis,
        "recommended_actions": actions,
        "confidence_assessment": "Analysis based on static templates (LLM unavailable)",
        "llm_used": False,
        "llm_model": "fallback-template",
    }


def _infer_attack_type(risk_result, ml_result):
    finding_descs = " ".join(f.get("description", "").lower() for f in risk_result.get("findings", []))
    if "credential" in finding_descs or "password" in finding_descs:
        return "credential_phishing"
    if "macro" in finding_descs or "vba" in finding_descs:
        return "spearphishing_attachment"
    if "financial" in finding_descs or "wire" in finding_descs:
        return "financial_scam"
    if ml_result and ml_result.get("label") == "phishing":
        return "credential_phishing"
    if risk_result.get("score", 0) < 20:
        return "clean_email"
    return "unknown"
