"""
engines/certin.py
-----------------
CERT-In 2025 Incident Category Rule Engine.
Maps MailForensix engine outputs to CERT-In mandatory incident categories.

Public API:
    classify_certin(...) -> CertInResult
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional

CATEGORY_PHISHING_SPOOFED    = "Phishing / Spoofed Sender"
CATEGORY_BEC                 = "Business Email Compromise (BEC) / Social Engineering"
CATEGORY_CAMPAIGN            = "Coordinated Phishing Campaign"
CATEGORY_PHISHING_ATTACHMENT = "Phishing with Malicious Attachment"
CATEGORY_PHISHING            = "Phishing"
CATEGORY_SPAM                = "Unsolicited Bulk Email (Spam)"
CATEGORY_SAFE                = "No Incident - Email appears legitimate"

_STATUTORY_REFS = {
    CATEGORY_PHISHING_SPOOFED:    "IT Act 2000, Ss. 43, 66, 66C, 66D; IPC S. 419, 420",
    CATEGORY_BEC:                 "IT Act 2000, Ss. 43, 66, 66C, 66D; IPC S. 420, 467",
    CATEGORY_CAMPAIGN:            "IT Act 2000, Ss. 43, 66, 66F; CERT-In Coordination Protocol",
    CATEGORY_PHISHING_ATTACHMENT: "IT Act 2000, Ss. 43, 66, 66B, 66C, 66D",
    CATEGORY_PHISHING:            "IT Act 2000, Ss. 43, 66, 66C, 66D",
    CATEGORY_SPAM:                "IT Act 2000, S. 66A (as applicable)",
    CATEGORY_SAFE:                "N/A",
}

_FINANCIAL_KEYWORDS = {
    "wire transfer", "invoice", "payment", "fund", "remittance",
    "bank account", "ach", "swift", "financial", "urgent payment",
    "vendor payment", "payroll", "overdue", "balance", "transaction",
    "retainage", "executive", "ceo", "cfo", "director",
}


@dataclass
class CertInResult:
    category:             str
    subcategory:          str
    severity:             str
    statutory_refs:       str
    ioc_summary:          str
    mandatory_fields:     dict
    cert_in_report_ready: bool = False


def _has_financial_urgency(subject: str, intent_label: str) -> bool:
    text = (subject or "").lower()
    return any(kw in text for kw in _FINANCIAL_KEYWORDS) or intent_label in ("bec", "financial_fraud")


def _severity_from_score(score: int) -> str:
    if score >= 85: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 30: return "MEDIUM"
    return "LOW"


def _recommended_action(category: str, severity: str) -> str:
    if category == CATEGORY_CAMPAIGN:
        return "Block relay IP CIDRs; submit STIX bundle to CERT-In; alert all recipients"
    if category == CATEGORY_BEC:
        return "Alert finance team; freeze pending transactions; verify sender via alternate channel"
    if category == CATEGORY_PHISHING_SPOOFED:
        return "Quarantine email; report sender domain to CERT-In; add to DNSBL"
    if category == CATEGORY_PHISHING_ATTACHMENT:
        return "Quarantine email; do not open attachment; submit to CERT-In sandbox"
    if severity in ("CRITICAL", "HIGH"):
        return "Quarantine email; escalate to SOC; file CERT-In report within 6 hours"
    return "Review email; apply standard spam filtering policy"


def _reporting_obligation(severity: str) -> str:
    if severity in ("CRITICAL", "HIGH"):
        return "Mandatory CERT-In report within 6 hours (CERT-In Directions 2022)"
    return "Optional CERT-In advisory notification recommended"


def classify_certin(
    auth_score: float,
    nlp_score: float,
    composite_score: int,
    intent_label: str,
    is_campaign: bool = False,
    has_malicious_attachment: bool = False,
    has_malicious_url: bool = False,
    sender_domain: str = "",
    subject: str = "",
    relay_country: str = "",
    analysis_id: str = "",
    timestamp: str = "",
) -> CertInResult:
    # Rule 1: Coordinated campaign
    if is_campaign and composite_score >= 60:
        category = CATEGORY_CAMPAIGN
        subcategory = "Multi-email coordinated attack from shared infrastructure"
    # Rule 2: Malicious attachment + URL
    elif has_malicious_attachment and has_malicious_url:
        category = CATEGORY_PHISHING_ATTACHMENT
        subcategory = "Phishing email with malicious attachment and embedded URL"
    # Rule 3: Auth fail + high NLP (spoofed sender)
    elif auth_score < 30 and nlp_score > 60:
        category = CATEGORY_PHISHING_SPOOFED
        subcategory = "SPF/DKIM/DMARC failure with phishing content"
    # Rule 4: Auth pass + financial urgency (BEC)
    elif auth_score >= 70 and nlp_score > 70 and _has_financial_urgency(subject, intent_label):
        category = CATEGORY_BEC
        subcategory = "Authenticated sender with financial urgency - possible lookalike/compromised domain"
    # Rule 5: General phishing
    elif composite_score >= 60:
        category = CATEGORY_PHISHING
        subcategory = f"Phishing email - intent: {intent_label}"
    # Rule 6: Spam
    elif composite_score >= 30:
        category = CATEGORY_SPAM
        subcategory = "Unsolicited bulk email"
    # Rule 7: Safe
    else:
        category = CATEGORY_SAFE
        subcategory = "No significant threat signals detected"

    severity = _severity_from_score(composite_score)
    ioc_parts = []
    if sender_domain: ioc_parts.append(f"Sender domain: {sender_domain}")
    if relay_country:  ioc_parts.append(f"Relay origin: {relay_country}")
    if has_malicious_url: ioc_parts.append("Malicious URL in body")
    if has_malicious_attachment: ioc_parts.append("Malicious attachment")
    ioc_summary = "; ".join(ioc_parts) if ioc_parts else "See full analysis report"

    mandatory_fields = {
        "Incident Category":     category,
        "Subcategory":           subcategory,
        "Severity":              severity,
        "Discovery Method":      "Automated MailForensix Analysis",
        "Discovery Timestamp":   timestamp,
        "Analysis ID":           analysis_id,
        "IoC Summary":           ioc_summary,
        "Authentication Status": "FAIL" if auth_score < 30 else ("WARN" if auth_score < 60 else "PASS"),
        "Composite Risk Score":  str(composite_score),
        "Statutory References":  _STATUTORY_REFS.get(category, "IT Act 2000"),
        "Recommended Action":    _recommended_action(category, severity),
        "Reporting Obligation":  _reporting_obligation(severity),
        "CERT-In Notification":  "Required" if severity in ("CRITICAL", "HIGH") else "Optional",
        "Regulatory Reference":  "CERT-In Cyber Incident Reporting Format 2025; DPDP Act 2023",
    }

    return CertInResult(
        category=category,
        subcategory=subcategory,
        severity=severity,
        statutory_refs=_STATUTORY_REFS.get(category, ""),
        ioc_summary=ioc_summary,
        mandatory_fields=mandatory_fields,
        cert_in_report_ready=True,
    )
