"""
engines/domain.py — Phase 2
Domain intelligence engine.

Signals:
  - WHOIS creation date → domain age (days)
  - Registrar name + privacy proxy detection
  - Domain age < 30 days → new-domain flag
  - MX record validity via dnspython
  - Suspicion score (0–1) from combined signals

Public API:
    get_domain_intel(domain: str) → DomainIntelResult
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# ── Privacy proxy strings (common WHOIS privacy registrars) ───────────────────
_PRIVACY_STRINGS = [
    "privacy", "whoisguard", "domains by proxy", "perfect privacy",
    "withheld for privacy", "contact privacy", "redacted for privacy",
    "registration private", "private registration", "data protected",
    "identity protect", "protect privacy", "proxy", "anonymize",
]
_PRIVACY_RE = re.compile(
    "|".join(re.escape(s) for s in _PRIVACY_STRINGS),
    re.IGNORECASE,
)

# ── Known high-risk TLDs (extra suspicion signal) ─────────────────────────────
_RISKY_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".link"}


@dataclass
class DomainIntelResult:
    domain:          str
    age_days:        Optional[int]   = None
    registrar:       Optional[str]   = None
    creation_date:   Optional[str]   = None
    expiry_date:     Optional[str]   = None
    mx_valid:        bool            = False
    privacy_proxy:   bool            = False
    new_domain:      bool            = False   # age_days < 30
    risky_tld:       bool            = False
    suspicion_score: float           = 0.0
    notes:           list[str]       = field(default_factory=list)


def _score_domain(result: DomainIntelResult) -> float:
    """Compute 0–1 suspicion score from combined domain signals."""
    score = 0.0

    if result.new_domain:
        score += 0.35    # Domain registered very recently
    if result.privacy_proxy:
        score += 0.20    # WHOIS privacy masking
    if result.risky_tld:
        score += 0.20    # High-risk TLD
    if result.age_days is not None and result.age_days < 90:
        score += 0.10    # Less than 3 months old (extra signal)
    if not result.mx_valid:
        score += 0.10    # No valid MX record → can't receive email legitimately
    if result.age_days is None:
        score += 0.05    # Could not determine age (WHOIS failed)

    return round(min(score, 1.0), 4)


def _whois_lookup(domain: str) -> dict:
    """Synchronous WHOIS lookup. Returns dict with keys: age_days, registrar, creation, expiry, privacy."""
    result = {
        "age_days": None, "registrar": None,
        "creation": None, "expiry": None, "privacy": False,
    }
    try:
        import whois as python_whois
        w = python_whois.whois(domain)

        # Creation date
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(creation, datetime):
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            result["creation"] = creation.date().isoformat()
            result["age_days"] = (datetime.now(timezone.utc) - creation).days

        # Expiry date
        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]
        if isinstance(expiry, datetime):
            result["expiry"] = expiry.date().isoformat()

        # Registrar
        registrar = w.registrar
        if isinstance(registrar, list):
            registrar = registrar[0]
        if registrar:
            result["registrar"] = str(registrar)[:120]
            if _PRIVACY_RE.search(str(registrar)):
                result["privacy"] = True

        # Privacy from org / emails field as well
        for field_val in [w.org, w.emails]:
            if field_val and _PRIVACY_RE.search(str(field_val)):
                result["privacy"] = True

    except Exception as e:
        logger.debug(f"[domain] WHOIS lookup failed for {domain}: {e}")

    return result


def _mx_check(domain: str) -> bool:
    """Check if domain has valid MX records via dnspython."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "MX", lifetime=5.0)
        return len(answers) > 0
    except Exception:
        return False


async def get_domain_intel(domain: str) -> DomainIntelResult:
    """
    Resolve domain intel for a sender domain.
    Runs WHOIS + MX check concurrently in thread executor.
    """
    if not domain or len(domain) < 3:
        return DomainIntelResult(
            domain=domain or "unknown",
            notes=["No sender domain to analyse."],
        )

    # Check risky TLD
    tld = "." + domain.rsplit(".", 1)[-1].lower() if "." in domain else ""
    risky_tld = tld in _RISKY_TLDS

    loop = asyncio.get_event_loop()
    try:
        # Run both WHOIS + MX concurrently in thread pool
        whois_data, mx_valid = await asyncio.gather(
            loop.run_in_executor(None, _whois_lookup, domain),
            loop.run_in_executor(None, _mx_check,    domain),
        )
    except Exception as e:
        logger.warning(f"[domain] Lookup error for {domain}: {e}")
        whois_data = {"age_days": None, "registrar": None, "creation": None, "expiry": None, "privacy": False}
        mx_valid   = False

    age_days = whois_data["age_days"]
    new_domain = (age_days is not None and age_days < 30)

    notes = []
    if new_domain:
        notes.append(f"Domain registered only {age_days} days ago — high suspicion.")
    if whois_data["privacy"]:
        notes.append("WHOIS privacy proxy detected — registrant identity hidden.")
    if risky_tld:
        notes.append(f"High-risk TLD: {tld}")
    if not mx_valid:
        notes.append("No valid MX records found for sender domain.")
    if not notes:
        notes.append("No significant domain anomalies detected.")

    result = DomainIntelResult(
        domain          = domain,
        age_days        = age_days,
        registrar       = whois_data["registrar"],
        creation_date   = whois_data["creation"],
        expiry_date     = whois_data["expiry"],
        mx_valid        = mx_valid,
        privacy_proxy   = whois_data["privacy"],
        new_domain      = new_domain,
        risky_tld       = risky_tld,
        notes           = notes,
    )
    result.suspicion_score = _score_domain(result)
    return result
