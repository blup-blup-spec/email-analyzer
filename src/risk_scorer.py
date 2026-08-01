"""
Phase 7 -- Risk Scoring Engine

Evaluates combined analysis results from all previous phases
and computes a weighted risk score (0-100).

Severity mapping:
- 0-25:  Low (Green)
- 26-50: Medium (Yellow)
- 51-75: High (Orange)
- 76+:   Critical (Red)
"""

import sys
import os
from typing import Dict, Any, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config


class RiskScorer:
    """Risk scoring engine for email threat analysis."""

    def __init__(self):
        self.score = 0
        self.findings = []
        self.mitre_techniques = []
        self.severity = "low"

    def evaluate(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate all analysis results and compute risk score."""
        self.score = 0
        self.findings = []
        self.mitre_techniques = []

        self._evaluate_headers(analysis_results.get("header_analysis", {}))
        self._evaluate_iocs(analysis_results.get("enrichment", {}))
        self._evaluate_ml(analysis_results.get("ml_result", {}))
        self._evaluate_attachments(analysis_results.get("attachment_results", []))
        self._evaluate_content(analysis_results.get("parsed_email", {}))

        self.score = min(self.score, 100)
        self.severity = self._get_severity(self.score)

        if self.score > 25:
            self._add_mitre("phishing_email")

        return {
            "score": self.score,
            "severity": self.severity,
            "findings": self.findings,
            "mitre_techniques": self.mitre_techniques,
            "finding_count": len(self.findings),
        }

    def _add_finding(self, category: str, description: str, points: int, severity: str = "info"):
        self.findings.append({
            "category": category,
            "description": description,
            "points": points,
            "severity": severity,
        })
        self.score += points

    def _add_mitre(self, technique_key: str):
        technique = config.MITRE_MAPPING.get(technique_key)
        if technique and technique not in self.mitre_techniques:
            self.mitre_techniques.append(technique)

    def _get_severity(self, score: int) -> str:
        for level, (low, high) in config.RISK_THRESHOLDS.items():
            if low <= score <= high:
                return level
        return "critical" if score > 75 else "low"

    def _evaluate_headers(self, header_analysis: Dict):
        if not header_analysis:
            return
        for anomaly in header_analysis.get("anomalies", []):
            anomaly_type = anomaly.get("type", "")
            weight = config.RISK_WEIGHTS.get(anomaly_type, 5)
            self._add_finding(
                category="Header Analysis",
                description=anomaly.get("message", anomaly_type),
                points=weight,
                severity=anomaly.get("severity", "info"),
            )
            if anomaly_type in ("from_domain_mismatch", "brand_impersonation"):
                self._add_mitre("domain_spoofing")
            if anomaly_type == "reply_to_mismatch":
                self._add_mitre("bec_impersonation")

    def _evaluate_iocs(self, enrichment: Dict):
        if not enrichment:
            return
        for ioc_value, ioc_data in enrichment.items():
            if ioc_value.startswith("_"):
                continue
            ioc_type = ioc_data.get("type", "unknown")
            for source_name, source_data in ioc_data.get("sources", {}).items():
                if not isinstance(source_data, dict):
                    continue
                verdict = source_data.get("verdict", "clean")
                if verdict == "malicious":
                    weight_key = f"malicious_{ioc_type}_vt"
                    if source_name == "abuseipdb":
                        weight_key = "high_abuse_score"
                    elif source_name == "urlscan":
                        weight_key = "suspicious_url_urlscan"
                    elif source_name == "otx":
                        weight_key = "otx_pulse_match"
                    weight = config.RISK_WEIGHTS.get(weight_key, 15)
                    self._add_finding(
                        category="Threat Intelligence",
                        description=f"{source_name} flagged {ioc_type} '{ioc_value[:50]}' as {verdict}",
                        points=weight,
                        severity="critical",
                    )
                    if ioc_type == "url":
                        self._add_mitre("phishing_link")
                    elif ioc_type == "hash":
                        self._add_mitre("phishing_attachment")
                elif verdict == "suspicious":
                    self._add_finding(
                        category="Threat Intelligence",
                        description=f"{source_name} flagged {ioc_type} '{ioc_value[:50]}' as suspicious",
                        points=8,
                        severity="warning",
                    )

    def _evaluate_ml(self, ml_result: Dict):
        if not ml_result:
            return
        label = ml_result.get("label", "unknown")
        confidence = ml_result.get("confidence", 0.0)
        if label == "phishing":
            if confidence >= config.ML_CONFIDENCE_THRESHOLD:
                weight = config.RISK_WEIGHTS.get("ml_phishing_high_confidence", 25)
                self._add_finding(
                    category="ML Classification",
                    description=f"ML model classified email as PHISHING with {confidence:.1%} confidence (model: {ml_result.get('model_used', 'unknown')})",
                    points=weight,
                    severity="critical",
                )
            else:
                weight = config.RISK_WEIGHTS.get("ml_phishing_medium_confidence", 15)
                self._add_finding(
                    category="ML Classification",
                    description=f"ML model classified email as PHISHING with {confidence:.1%} confidence (below high-confidence threshold)",
                    points=weight,
                    severity="warning",
                )
            self._add_mitre("credential_harvesting")

    def _evaluate_attachments(self, attachment_results: List[Dict]):
        if not attachment_results:
            return
        for att in attachment_results:
            for finding in att.get("findings", []):
                finding_type = finding.get("type", "")
                weight = config.RISK_WEIGHTS.get(finding_type, 10)
                self._add_finding(
                    category="Attachment Analysis",
                    description=finding.get("message", finding_type),
                    points=weight,
                    severity=finding.get("severity", "warning"),
                )
                if "macro" in finding_type or "vba" in finding_type:
                    self._add_mitre("malicious_macro")
                if "dangerous" in finding_type or "vt_malicious" in finding_type:
                    self._add_mitre("phishing_attachment")

    def _evaluate_content(self, parsed_email: Dict):
        if not parsed_email:
            return
        body = ""
        if parsed_email.get("body_plain"):
            body += parsed_email["body_plain"]
        if parsed_email.get("body_html"):
            from bs4 import BeautifulSoup
            try:
                soup = BeautifulSoup(parsed_email["body_html"], "html.parser")
                body += " " + soup.get_text(separator=" ", strip=True)
            except Exception:
                pass

        body_lower = body.lower()

        urgency_count = sum(1 for kw in config.URGENCY_KEYWORDS if kw in body_lower)
        if urgency_count >= 3:
            self._add_finding(
                category="Content Analysis",
                description=f"High urgency language detected ({urgency_count} indicators found)",
                points=config.RISK_WEIGHTS.get("urgency_language", 10),
                severity="warning",
            )

        cred_count = sum(1 for kw in config.CREDENTIAL_HARVEST_KEYWORDS if kw in body_lower)
        if cred_count >= 2:
            self._add_finding(
                category="Content Analysis",
                description=f"Credential harvesting language detected ({cred_count} indicators)",
                points=config.RISK_WEIGHTS.get("credential_harvesting_indicators", 15),
                severity="critical",
            )
            self._add_mitre("credential_harvesting")

        fin_count = sum(1 for kw in config.FINANCIAL_SCAM_KEYWORDS if kw in body_lower)
        if fin_count >= 2:
            self._add_finding(
                category="Content Analysis",
                description=f"Financial scam language detected ({fin_count} indicators)",
                points=config.RISK_WEIGHTS.get("financial_scam_indicators", 15),
                severity="warning",
            )


def calculate_risk(analysis_results: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience function to calculate risk score."""
    scorer = RiskScorer()
    return scorer.evaluate(analysis_results)
