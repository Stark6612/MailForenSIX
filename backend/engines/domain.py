"""
engines/domain.py -- Phase 4
Domain intelligence engine.

Signals:
  - WHOIS creation date -> domain age (days)
  - Registrar name + privacy proxy detection
  - Domain age < 30 days -> new-domain flag
  - MX record validity via dnspython
  - URLhaus + PhishTank offline blacklist check (air-gapped safe)
  - SPF/DMARC SQLite cache lookup for air-gapped auth hints
  - Suspicion score (0-1) from combined signals

Public API:
    get_domain_intel(domain: str, air_gapped: bool = False) -> DomainIntelResult
    lookup_spf_dmarc_cache(domain: str) -> dict | None
    check_blacklist(domain: str) -> tuple[bool, str | None]
"""

from __future__ import annotations

import asyncio
import logging
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

BASE_DIR       = Path(__file__).resolve().parent.parent
DATA_DIR       = BASE_DIR / "data"
MODELS_DIR     = BASE_DIR / "models"
# Runtime lookup files live in models/ -- tracked in git, available on Render
SPF_DB_PATH    = MODELS_DIR / "spf_dmarc_cache.db"
URLHAUS_PATH   = MODELS_DIR / "urlhaus_domains.txt"
PHISHTANK_PATH = MODELS_DIR / "phishtank_domains.txt"

# -- Privacy proxy strings -------------------------------------------------------
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

# -- Known high-risk TLDs --------------------------------------------------------
_RISKY_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".link"}


# -- Offline threat intel blacklists (loaded once at module import) --------------

def _load_blacklist(path: Path) -> frozenset:
    """Load a domain list file (one domain per line) into a frozenset."""
    if not path.exists():
        return frozenset()
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        return frozenset(l.strip().lower() for l in lines if l.strip() and not l.startswith("#"))
    except Exception as e:
        logger.warning(f"[domain] Failed to load blacklist {path}: {e}")
        return frozenset()


_URLHAUS_DOMAINS   = _load_blacklist(URLHAUS_PATH)
_PHISHTANK_DOMAINS = _load_blacklist(PHISHTANK_PATH)

logger.info(
    f"[domain] Threat intel: URLhaus={len(_URLHAUS_DOMAINS):,} "
    f"PhishTank={len(_PHISHTANK_DOMAINS):,} domains"
)


def check_blacklist(domain: str) -> tuple[bool, Optional[str]]:
    """
    Check domain against offline URLhaus + PhishTank blacklists.
    Returns (hit: bool, source: str | None).
    """
    d    = domain.lower().strip()
    in_uh = d in _URLHAUS_DOMAINS
    in_pt = d in _PHISHTANK_DOMAINS
    if in_uh and in_pt:
        return True, "urlhaus+phishtank"
    if in_uh:
        return True, "urlhaus"
    if in_pt:
        return True, "phishtank"
    return False, None


# -- SPF/DMARC SQLite cache (air-gapped) -----------------------------------------

def lookup_spf_dmarc_cache(domain: str) -> Optional[dict]:
    """
    Look up pre-built SPF/DMARC SQLite cache.
    Returns dict or None if not found / DB absent.
    """
    if not SPF_DB_PATH.exists():
        return None
    try:
        conn = sqlite3.connect(str(SPF_DB_PATH), timeout=2)
        row  = conn.execute(
            "SELECT spf_record, spf_policy, dmarc_record, dmarc_policy, cached_date "
            "FROM spf_dmarc_cache WHERE domain=?",
            (domain.lower(),)
        ).fetchone()
        conn.close()
        if row:
            return {
                "spf_record":   row[0],
                "spf_policy":   row[1],
                "dmarc_record": row[2],
                "dmarc_policy": row[3],
                "cached_date":  row[4],
            }
    except Exception as e:
        logger.debug(f"[domain] Cache lookup error: {e}")
    return None


@dataclass
class DomainIntelResult:
    domain:           str
    age_days:         Optional[int]  = None
    registrar:        Optional[str]  = None
    creation_date:    Optional[str]  = None
    expiry_date:      Optional[str]  = None
    mx_valid:         bool           = False
    privacy_proxy:    bool           = False
    new_domain:       bool           = False   # age_days < 30
    risky_tld:        bool           = False
    blacklist_hit:    bool           = False   # URLhaus / PhishTank hit
    blacklist_source: Optional[str]  = None
    suspicion_score:  float          = 0.0
    notes:            list[str]      = field(default_factory=list)


def _score_domain(result: DomainIntelResult) -> float:
    """Compute 0-1 suspicion score from combined domain signals."""
    score = 0.0
    if result.blacklist_hit:
        score += 0.50    # Definitive threat intel hit
    if result.new_domain:
        score += 0.35    # Domain registered very recently
    if result.privacy_proxy:
        score += 0.20    # WHOIS privacy masking
    if result.risky_tld:
        score += 0.20    # High-risk TLD
    if result.age_days is not None and result.age_days < 90:
        score += 0.10    # Less than 3 months old
    if not result.mx_valid:
        score += 0.10    # No valid MX record
    if result.age_days is None:
        score += 0.05    # Could not determine age
    return round(min(score, 1.0), 4)


def _whois_lookup(domain: str) -> dict:
    """Synchronous WHOIS lookup."""
    result = {
        "age_days": None, "registrar": None,
        "creation": None, "expiry": None, "privacy": False,
    }
    try:
        import whois as python_whois
        w = python_whois.whois(domain)

        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(creation, datetime):
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            result["creation"] = creation.date().isoformat()
            result["age_days"] = (datetime.now(timezone.utc) - creation).days

        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]
        if isinstance(expiry, datetime):
            result["expiry"] = expiry.date().isoformat()

        registrar = w.registrar
        if isinstance(registrar, list):
            registrar = registrar[0]
        if registrar:
            result["registrar"] = str(registrar)[:120]
            if _PRIVACY_RE.search(str(registrar)):
                result["privacy"] = True

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


async def get_domain_intel(domain: str, air_gapped: bool = False) -> DomainIntelResult:
    """
    Resolve domain intel for a sender domain.
    In air-gapped mode: skips WHOIS/MX network calls; uses SQLite SPF cache
    and offline URLhaus/PhishTank blacklists only.
    """
    if not domain or len(domain) < 3:
        return DomainIntelResult(
            domain=domain or "unknown",
            notes=["No sender domain to analyse."],
        )

    # Risky TLD check (local, no network)
    tld       = "." + domain.rsplit(".", 1)[-1].lower() if "." in domain else ""
    risky_tld = tld in _RISKY_TLDS

    # Offline blacklist check (URLhaus + PhishTank)
    bl_hit, bl_source = check_blacklist(domain)

    if air_gapped:
        # Air-gapped: no WHOIS, no MX, no live DNS -- use cache only
        cache = lookup_spf_dmarc_cache(domain)

        notes = []
        if bl_hit:
            notes.append(f"THREAT INTEL HIT: Domain on {bl_source} malicious domain list.")
        if risky_tld:
            notes.append(f"High-risk TLD: {tld}")
        if cache:
            notes.append(f"SPF cached policy: {cache['spf_policy']} (as of {cache['cached_date']})")
            notes.append(f"DMARC cached policy: {cache['dmarc_policy']} (as of {cache['cached_date']})")
        else:
            notes.append("Domain not in SPF/DMARC cache -- no air-gapped auth data.")
        if not notes or (not bl_hit and not risky_tld and not cache):
            notes.append("No significant domain anomalies detected (air-gapped mode).")

        result = DomainIntelResult(
            domain           = domain,
            risky_tld        = risky_tld,
            blacklist_hit    = bl_hit,
            blacklist_source = bl_source,
            notes            = notes,
        )
        result.suspicion_score = _score_domain(result)
        return result

    # Connected mode: full WHOIS + MX + blacklist
    loop = asyncio.get_event_loop()
    try:
        whois_data, mx_valid = await asyncio.gather(
            loop.run_in_executor(None, _whois_lookup, domain),
            loop.run_in_executor(None, _mx_check,    domain),
        )
    except Exception as e:
        logger.warning(f"[domain] Lookup error for {domain}: {e}")
        whois_data = {"age_days": None, "registrar": None, "creation": None, "expiry": None, "privacy": False}
        mx_valid   = False

    age_days   = whois_data["age_days"]
    new_domain = (age_days is not None and age_days < 30)

    notes = []
    if bl_hit:
        notes.append(f"THREAT INTEL HIT: Domain on {bl_source} malicious domain list.")
    if new_domain:
        notes.append(f"Domain registered only {age_days} days ago -- high suspicion.")
    if whois_data["privacy"]:
        notes.append("WHOIS privacy proxy detected -- registrant identity hidden.")
    if risky_tld:
        notes.append(f"High-risk TLD: {tld}")
    if not mx_valid:
        notes.append("No valid MX records found for sender domain.")
    if not notes:
        notes.append("No significant domain anomalies detected.")

    result = DomainIntelResult(
        domain           = domain,
        age_days         = age_days,
        registrar        = whois_data["registrar"],
        creation_date    = whois_data["creation"],
        expiry_date      = whois_data["expiry"],
        mx_valid         = mx_valid,
        privacy_proxy    = whois_data["privacy"],
        new_domain       = new_domain,
        risky_tld        = risky_tld,
        blacklist_hit    = bl_hit,
        blacklist_source = bl_source,
        notes            = notes,
    )
    result.suspicion_score = _score_domain(result)
    return result