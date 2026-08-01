"""
Phase 5 -- ML Phishing Classifier (Local Inference)

Loads the fine-tuned DistilBERT model from models/phishing-distilbert/
and classifies email text as phishing or legitimate.

Primary: DistilBERT transformer (trained in Google Colab)
Fallback: Keyword heuristic classifier
"""

import os
import re
import sys
from typing import Dict, Any, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

_transformer_model = None
_transformer_tokenizer = None


def classify_email(email_text: str) -> Dict[str, Any]:
    """
    Classify email text as phishing or legitimate.

    Returns dict with label, confidence, phishing_probability, model_used.
    """
    if not email_text or len(email_text.strip()) < 10:
        return {
            "label": "unknown",
            "confidence": 0.0,
            "phishing_probability": 0.0,
            "model_used": "none",
            "details": "Email text too short for classification",
        }

    cleaned = _clean_text(email_text)

    # Try transformer model first
    result = _classify_transformer(cleaned)
    if result:
        return result

    # Fallback to keyword-based heuristic
    return _classify_heuristic(cleaned)


def _clean_text(text: str) -> str:
    """Clean email text for classification."""
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'https?://\S+', '[URL]', text)
    text = re.sub(r'\S+@\S+\.\S+', '[EMAIL]', text)
    text = re.sub(r'\s+', ' ', text).strip()
    text = text.lower()
    if len(text) > 2000:
        text = text[:2000]
    return text


def _classify_transformer(text: str) -> Optional[Dict[str, Any]]:
    """Classify using fine-tuned DistilBERT transformer model."""
    global _transformer_model, _transformer_tokenizer

    model_path = config.PHISHING_MODEL_PATH

    if not os.path.exists(model_path):
        return None

    try:
        if _transformer_model is None:
            from transformers import (
                DistilBertForSequenceClassification,
                DistilBertTokenizerFast,
                pipeline,
            )

            _transformer_tokenizer = DistilBertTokenizerFast.from_pretrained(model_path)
            _transformer_model = pipeline(
                "text-classification",
                model=model_path,
                tokenizer=_transformer_tokenizer,
                device=-1,
                top_k=None,
            )

        results = _transformer_model(text, truncation=True, max_length=512)

        # Pipeline returns list of dicts (top_k=None gives all labels)
        if results and isinstance(results[0], list):
            scores_raw = {r["label"].lower(): r["score"] for r in results[0]}
        elif results and isinstance(results[0], dict):
            scores_raw = {results[0]["label"].lower(): results[0]["score"]}
        else:
            return None

        # Handle both named labels and LABEL_0/LABEL_1 fallback
        if "phishing" in scores_raw:
            phishing_prob = scores_raw.get("phishing", 0.0)
            legit_prob = scores_raw.get("legitimate", 1.0 - phishing_prob)
        else:
            # LABEL_1 = phishing, LABEL_0 = legitimate (from training_metadata)
            phishing_prob = scores_raw.get("label_1", 0.0)
            legit_prob = scores_raw.get("label_0", 1.0 - phishing_prob)

        is_phishing = phishing_prob > 0.5
        confidence = max(phishing_prob, legit_prob)

        return {
            "label": "phishing" if is_phishing else "legitimate",
            "confidence": round(confidence, 4),
            "phishing_probability": round(phishing_prob, 4),
            "model_used": "distilbert-phishing",
            "details": {
                "phishing_score": round(phishing_prob, 4),
                "legitimate_score": round(legit_prob, 4),
                "threshold": 0.5,
                "model_path": model_path,
            },
        }

    except Exception as e:
        print(f"[ML] Transformer model error: {e}")
        return None


def _classify_heuristic(text: str) -> Dict[str, Any]:
    """Fallback keyword-based heuristic classifier."""
    text_lower = text.lower()

    phishing_score = 0.0
    matched_indicators = []

    for keyword in config.URGENCY_KEYWORDS:
        if keyword in text_lower:
            phishing_score += 0.08
            matched_indicators.append(f"urgency: '{keyword}'")

    for keyword in config.CREDENTIAL_HARVEST_KEYWORDS:
        if keyword in text_lower:
            phishing_score += 0.12
            matched_indicators.append(f"credential_harvest: '{keyword}'")

    for keyword in config.FINANCIAL_SCAM_KEYWORDS:
        if keyword in text_lower:
            phishing_score += 0.10
            matched_indicators.append(f"financial_scam: '{keyword}'")

    if re.search(r'\[URL\]', text_lower):
        url_count = len(re.findall(r'\[URL\]', text_lower))
        if url_count > 3:
            phishing_score += 0.1
            matched_indicators.append(f"excessive_urls: {url_count}")

    phishing_score = min(phishing_score, 1.0)
    is_phishing = phishing_score > 0.4

    return {
        "label": "phishing" if is_phishing else "legitimate",
        "confidence": round(max(phishing_score, 1.0 - phishing_score), 4),
        "phishing_probability": round(phishing_score, 4),
        "model_used": "heuristic-keyword",
        "details": {
            "matched_indicators": matched_indicators[:10],
            "note": "Using keyword heuristic -- place trained model in models/phishing-distilbert/ for better accuracy",
        },
    }
