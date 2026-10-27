"""
engines/risk.py — Phase 2
Real weighted risk scoring engine.

Weights:
  Auth   30%  — SPF/DKIM/DMARC + spoofing signals
  Intent 30%  — ML classifier confidence (phishing probability)
  Geo    20%  — VPN/TOR flags, high-risk hop countries, missing geo
  Domain 20%  — Age, privacy proxy, MX validity, risky TLD

Risk Tiers:
  SAFE        0–29
  SUSPICIOUS  30–59
  HIGH        60–84
  CRITICAL    85–100

Public API:
    compute_risk(auth, intent_label, intent_confidence, geo_hops, domain) → (score, tier)
"""

from __future__ import annotations

import logging
from typing import Optional, TYPE_CHECKING

logger = logging.getLogger(__name__)

# Defer import to avoid circular dependency
if TYPE_CHECKING:
    from engines.auth   import AuthValidationResult
    from engines.geo    import GeoResult
    from engines.domain import DomainIntelResult
    from models.schemas import RiskTier


# ── High-risk country codes (geopolitical threat intel heuristic) ─────────────
_HIGH_RISK_COUNTRIES = {
    "RU", "CN", "KP", "IR", "NG", "PK", "BD", "UA", "RO", "BR",
}

# ── Risk tier thresholds ───────────────────────────────────────────────────────
_TIER_THRESHOLDS = [
    (85, "critical"),
    (60, "high"),
    (30, "suspicious"),
    (0,  "safe"),
]


def _auth_component(auth) -> float:
    """
    Compute auth sub-score (0–100).
    SPF / DKIM / DMARC each contribute, plus display-name spoofing.
    """
    score = 0.0

    # SPF
    if auth.spf == "fail":    score += 25.0
    elif auth.spf == "warn":  score += 12.0
    elif auth.spf == "none":  score += 5.0

    # DKIM
    if auth.dkim == "fail":   score += 25.0
    elif auth.dkim == "warn": score += 10.0
    elif auth.dkim == "none": score += 5.0

    # DMARC
    if auth.dmarc == "fail":  score += 20.0
    elif auth.dmarc == "warn": score += 8.0
    elif auth.dmarc == "none": score += 5.0

    # Display-name spoofing (extra penalty on top of auth)
    if getattr(auth, "alignment_fail", False):
        score += 15.0

    return min(score, 100.0)


def _intent_component(label: str, confidence: float) -> float:
    """
    Compute intent sub-score (0–100) from classifier output.
    """
    if label == "phishing":
        return min(confidence * 100, 100.0)
    elif label == "suspicious":
        return min(confidence * 70, 70.0)
    else:
        return min(confidence * 20, 20.0)  # even 'safe' can have some residual


def _geo_component(geo_hops: list) -> float:
    """
    Compute geo sub-score (0–100) from relay hop geo results.
    Penalise: VPN/proxy flags, high-risk country codes, missing geo.
    """
    if not geo_hops:
        return 5.0  # no hops → minor penalty

    score = 0.0
    n     = len(geo_hops)

    for hop in geo_hops:
        if getattr(hop, "vpn", False):
            score += 30.0
        country_code = getattr(hop, "country", None)
        if country_code and country_code.upper() in _HIGH_RISK_COUNTRIES:
            score += 15.0
        if getattr(hop, "lat", None) is None:
            score += 3.0   # geo not resolved

    # Normalise by hop count so one bad hop doesn't dominate
    score = score / n if n > 0 else score
    return min(score, 100.0)


def _domain_component(domain) -> float:
    """
    Compute domain sub-score (0–100) from DomainIntelResult.
    """
    if domain is None:
        return 10.0   # no domain data → minor penalty

    suspicion = getattr(domain, "suspicion_score", 0.0)
    return round(suspicion * 100, 2)


def compute_risk_detailed(
    auth,
    intent_label:      str,
    intent_confidence: float,
    geo_hops:          list,
    domain,
    attachments:       list = None,
) -> tuple[int, str, dict]:
    """
    Compute final weighted risk score + tier + detailed breakdown.

    Returns:
        (score: int 0–100, tier: str, breakdown: dict)
    """
    auth_score   = 0.0
    intent_score = 0.0
    geo_score    = 0.0
    domain_score = 0.0
    score = 0

    try:
        auth_score   = _auth_component(auth)
        intent_score = _intent_component(intent_label, intent_confidence)
        geo_score    = _geo_component(geo_hops)
        domain_score = _domain_component(domain)

        logger.debug(
            f"[risk] auth={auth_score:.1f} intent={intent_score:.1f} "
            f"geo={geo_score:.1f} domain={domain_score:.1f}"
        )

        # Weighted sum: 30% Auth + 30% Intent + 20% Geo + 20% Domain
        total = (
            auth_score   * 0.30 +
            intent_score * 0.30 +
            geo_score    * 0.20 +
            domain_score * 0.20
        )

        # Elevate risk if malicious attachment is detected
        if attachments:
            for att in attachments:
                risk_lvl = getattr(att, "risk_level", None) or (att.get("risk_level") if isinstance(att, dict) else "")
                if risk_lvl == "MALICIOUS":
                    total = max(total, 85.0)  # Guarantee Critical tier
                    break
                elif risk_lvl == "SUSPICIOUS":
                    total = max(total, 60.0)  # Guarantee High tier

        score = int(round(min(max(total, 0.0), 100.0)))

    except Exception as e:
        logger.error(f"[risk] compute_risk error: {e}")
        score = 0

    # Map to tier
    tier_found = "safe"
    for threshold, tier in _TIER_THRESHOLDS:
        if score >= threshold:
            tier_found = tier
            break

    breakdown = {
        "auth_score": round(auth_score, 1),
        "intent_score": round(intent_score, 1),
        "geo_score": round(geo_score, 1),
        "domain_score": round(domain_score, 1),
        "auth_weighted": round(auth_score * 0.30, 1),
        "intent_weighted": round(intent_score * 0.30, 1),
        "geo_weighted": round(geo_score * 0.20, 1),
        "domain_weighted": round(domain_score * 0.20, 1),
        "total": score,
    }

    return score, tier_found, breakdown


def compute_risk(
    auth,
    intent_label:      str,
    intent_confidence: float,
    geo_hops:          list,
    domain,
) -> tuple[int, str]:
    """Backwards-compatible wrapper returning (score, tier)."""
    score, tier, _ = compute_risk_detailed(auth, intent_label, intent_confidence, geo_hops, domain)
    return score, tier
