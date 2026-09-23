"""
engines/actor_profile.py
-------------------------
Actor profiling and MITRE ATT&CK sub-technique mapping for campaign clusters.
Reads local enterprise-attack.json for technique definitions.

Public API:
    build_actor_profile(cluster_emails: list[ParsedEmail]) -> dict
    map_mitre_techniques(actor_profile: dict) -> list[dict]
"""

from __future__ import annotations
import json
import logging
from collections import Counter
from pathlib import Path
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

_MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
_ATTACK_JSON = _MODELS_DIR / "enterprise-attack.json"

# Hardcoded sub-techniques relevant to phishing campaigns (proposal §3.2 Obj 3)
_TECHNIQUE_MAP = {
    "T1566.001": {
        "id": "T1566.001", "name": "Spearphishing Attachment",
        "tactic": "Initial Access",
        "description": "Phishing email with malicious attachment to deliver payload.",
        "trigger": "has_attachment",
    },
    "T1566.002": {
        "id": "T1566.002", "name": "Spearphishing Link",
        "tactic": "Initial Access",
        "description": "Phishing email with embedded malicious URL.",
        "trigger": "has_url",
    },
    "T1583.001": {
        "id": "T1583.001", "name": "Acquire Infrastructure: Domains",
        "tactic": "Resource Development",
        "description": "Attacker registered domains to host phishing pages.",
        "trigger": "new_domain",
    },
    "T1583.002": {
        "id": "T1583.002", "name": "Acquire Infrastructure: DNS Server",
        "tactic": "Resource Development",
        "description": "Attacker controls DNS infrastructure for phishing campaign.",
        "trigger": "relay_asn",
    },
    "T1566.003": {
        "id": "T1566.003", "name": "Spearphishing via Service",
        "tactic": "Initial Access",
        "description": "Phishing via third-party service (DocuSign, Google Forms, etc.)",
        "trigger": "third_party_service",
    },
    "T1078": {
        "id": "T1078", "name": "Valid Accounts",
        "tactic": "Defense Evasion / Initial Access",
        "description": "Attacker used authenticated (legitimate-appearing) sender account.",
        "trigger": "auth_pass",
    },
}


def _load_attack_json() -> Dict:
    if not _ATTACK_JSON.exists():
        logger.warning(f"[actor_profile] enterprise-attack.json not found at {_ATTACK_JSON}")
        return {}
    try:
        with open(_ATTACK_JSON, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"[actor_profile] Failed to load attack JSON: {e}")
        return {}


def _extract_ip_set(parsed) -> set:
    ips = set()
    for hop in getattr(parsed, "received_hops", []):
        if getattr(hop, "ip", None):
            ips.add(hop.ip)
    return ips


def _extract_asn_set(relay_hops: list) -> set:
    return {h.get("asn", "") for h in relay_hops if h.get("asn")}


def _extract_domain_set(parsed) -> set:
    domains = set()
    if getattr(parsed, "sender_domain", None):
        domains.add(parsed.sender_domain)
    return domains


def build_actor_profile(
    cluster_emails: list,  # list of (ParsedEmail, relay_hops, domain_intel) tuples
) -> Dict[str, Any]:
    """
    Build actor profile from a cluster of emails.
    Returns structured dict with infrastructure analysis and MITRE mappings.
    """
    relay_ips    = Counter()
    asn_counter  = Counter()
    countries    = Counter()
    domains      = Counter()
    subjects     = []
    has_url      = False
    has_attach   = False
    auth_passes  = 0
    domain_ages  = []

    for item in cluster_emails:
        parsed   = item.get("parsed")
        hops     = item.get("relay_hops", [])
        domain   = item.get("domain_intel")
        auth     = item.get("auth")
        intent   = item.get("intent_label", "")

        if parsed:
            if getattr(parsed, "subject", None):
                subjects.append(parsed.subject)
            if getattr(parsed, "sender_domain", None):
                domains[parsed.sender_domain] += 1
            # URL detection
            body = (getattr(parsed, "body_text", "") or "") + (getattr(parsed, "body_html", "") or "")
            if "http" in body.lower():
                has_url = True

        for hop in hops:
            if isinstance(hop, dict):
                ip      = hop.get("ip", "")
                asn     = hop.get("asn", "")
                country = hop.get("country", "")
            else:
                ip      = getattr(hop, "ip", "")
                asn     = getattr(hop, "asn", "")
                country = getattr(hop, "country", "")
            if ip:      relay_ips[ip] += 1
            if asn:     asn_counter[asn] += 1
            if country: countries[country] += 1

        if domain:
            age = getattr(domain, "age_days", None) or (domain.get("age_days") if isinstance(domain, dict) else None)
            if age is not None:
                domain_ages.append(int(age))

        if auth:
            spf  = getattr(auth, "spf", None)  or (auth.get("spf")  if isinstance(auth, dict) else None)
            dkim = getattr(auth, "dkim", None) or (auth.get("dkim") if isinstance(auth, dict) else None)
            if spf == "pass" or dkim == "pass":
                auth_passes += 1

    # Infer new domains (age < 30 days)
    new_domain = any(a < 30 for a in domain_ages) if domain_ages else False
    auth_pass  = auth_passes > len(cluster_emails) // 2

    profile = {
        "email_count":        len(cluster_emails),
        "relay_ips":          dict(relay_ips.most_common(10)),
        "top_asns":           dict(asn_counter.most_common(5)),
        "top_countries":      dict(countries.most_common(5)),
        "sender_domains":     dict(domains.most_common(5)),
        "subject_samples":    subjects[:5],
        "avg_domain_age_days": round(sum(domain_ages) / len(domain_ages), 1) if domain_ages else None,
        "has_malicious_url":  has_url,
        "has_attachment":     has_attach,
        "auth_pass_ratio":    round(auth_passes / max(len(cluster_emails), 1), 2),
        "new_domain_detected": new_domain,
        "mitre_techniques":   map_mitre_techniques(
            has_url=has_url, has_attach=has_attach, new_domain=new_domain,
            relay_asn=bool(asn_counter), auth_pass=auth_pass,
        ),
    }
    return profile


def map_mitre_techniques(
    has_url: bool = False,
    has_attach: bool = False,
    new_domain: bool = False,
    relay_asn: bool = True,
    auth_pass: bool = False,
) -> List[Dict]:
    """Map observed signals to MITRE ATT&CK sub-techniques."""
    matched = []
    if has_attach:
        matched.append(_TECHNIQUE_MAP["T1566.001"])
    if has_url:
        matched.append(_TECHNIQUE_MAP["T1566.002"])
    if new_domain:
        matched.append(_TECHNIQUE_MAP["T1583.001"])
    if relay_asn:
        matched.append(_TECHNIQUE_MAP["T1583.002"])
    if auth_pass:
        matched.append(_TECHNIQUE_MAP["T1078"])
    # Default: always include T1566.002 (link) if no attachment but email has url
    if not matched:
        matched.append(_TECHNIQUE_MAP["T1566.002"])
    return matched
