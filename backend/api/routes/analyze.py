"""
/analyze endpoint — Phase 2 (all engines wired)
Parser + Auth (Phase 1) + Classifier + Geo + Domain + Risk (Phase 2)

Pipeline (asyncio.gather):
  parse_eml()  →  [validate_auth | predict_intent | resolve_geo_batch | get_domain_intel]
               →  compute_risk()  →  response
"""

import asyncio
import hashlib
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, UploadFile, File, Form, HTTPException

from models.schemas import (
    AnalysisResponse, ErrorResponse,
    AuthResult, AuthStatus, RelayHop,
    DomainIntel, LIMESentence, ForensicMeta,
    RiskTier, ThreatLabel,
)
from core.config import settings
from engines.parser     import parse_eml, ParsedEmail
from engines.auth       import validate_auth, AuthValidationResult
from engines.classifier import predict_intent, explain_sentences, model_loaded
from engines.geo        import resolve_geo_batch, GeoResult
from engines.domain     import get_domain_intel, DomainIntelResult
from engines.risk       import compute_risk

router = APIRouter()

MAX_EML_BYTES = 10 * 1024 * 1024   # 10 MB


# ── Helpers ────────────────────────────────────────────────────────────────────

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _validate_mime(data: bytes) -> bool:
    """RFC 5322 sniff — must contain at least one known header."""
    try:
        text = data[:4096].decode('utf-8', errors='replace')
        return any(h in text for h in ('From:', 'Received:', 'MIME-Version:', 'Subject:'))
    except Exception:
        return False


def _map_auth_status(s: str) -> AuthStatus:
    return {
        'pass': AuthStatus.PASS,
        'fail': AuthStatus.FAIL,
        'warn': AuthStatus.WARN,
    }.get(s, AuthStatus.NONE)


def _map_threat_label(label: str) -> ThreatLabel:
    return {
        'phishing':     ThreatLabel.PHISHING,
        'suspicious':   ThreatLabel.SUSPICIOUS,
        'safe':         ThreatLabel.SAFE,
        'bec':          ThreatLabel.BEC,
        'impersonation': ThreatLabel.IMPERSONATION,
    }.get(label, ThreatLabel.SUSPICIOUS)


def _map_risk_tier(tier: str) -> RiskTier:
    return {
        'safe':       RiskTier.SAFE,
        'suspicious': RiskTier.SUSPICIOUS,
        'high':       RiskTier.HIGH,
        'critical':   RiskTier.CRITICAL,
    }.get(tier, RiskTier.SUSPICIOUS)


# ── Async engine wrappers ──────────────────────────────────────────────────────

async def _run_classifier(parsed: ParsedEmail):
    """Run TF-IDF + XGBoost intent classifier + LIME explanations."""
    body = (parsed.body_text or "") + " " + (parsed.body_html or "")
    loop = asyncio.get_event_loop()

    label, confidence = await loop.run_in_executor(None, predict_intent, body)
    lime_raw          = await loop.run_in_executor(None, explain_sentences, body)

    lime_sentences = [
        LIMESentence(
            text=item["text"],
            score=item["score"],
            explanation=item["explanation"],
        )
        for item in lime_raw
    ]
    return _map_threat_label(label), confidence, lime_sentences


async def _run_geo(parsed: ParsedEmail) -> list[RelayHop]:
    """Geolocate all relay hop IPs via geo engine."""
    hops     = parsed.received_hops
    hop_ips  = [h.ip for h in hops]

    geo_results: list[GeoResult] = await resolve_geo_batch(
        hop_ips, air_gapped=settings.AIR_GAPPED
    )

    relay_hops = []
    for h, geo in zip(hops, geo_results):
        relay_hops.append(RelayHop(
            hop_index  = h.hop_index,
            ip         = h.ip,
            hostname   = h.hostname,
            country    = geo.country,
            city       = geo.city,
            asn        = geo.asn,
            isp        = geo.isp,
            lat        = geo.lat,
            lon        = geo.lon,
            masked     = h.masked,
            mask_reason = h.mask_provider,
            geo_mode   = geo.mode,
        ))
    return relay_hops


async def _run_domain(parsed: ParsedEmail) -> DomainIntel | None:
    """WHOIS + MX domain intel lookup."""
    if not parsed.sender_domain:
        return None

    result: DomainIntelResult = await get_domain_intel(parsed.sender_domain)

    return DomainIntel(
        domain          = result.domain,
        age_days        = result.age_days,
        registrar       = result.registrar,
        creation_date   = result.creation_date,
        expiry_date     = result.expiry_date,
        mx_valid        = result.mx_valid,
        privacy_proxy   = result.privacy_proxy,
        suspicion_score = result.suspicion_score,
        notes           = result.notes,
    )


# ── Main /analyze endpoint ─────────────────────────────────────────────────────

@router.post(
    '/analyze',
    response_model=AnalysisResponse,
    responses={
        400: {'model': ErrorResponse, 'description': 'Invalid or malformed email'},
        413: {'model': ErrorResponse, 'description': 'File too large'},
    },
    summary='Analyze a suspicious email (Phase 2 — all engines active)',
)
async def analyze_email(
    eml_file:    UploadFile | None = File(default=None),
    raw_headers: str | None        = Form(default=None),
):
    # ── Input validation ───────────────────────────────────────────────────────
    if not eml_file and not raw_headers:
        raise HTTPException(400, detail='Provide eml_file or raw_headers.')

    if eml_file:
        raw_bytes = await eml_file.read()
        if len(raw_bytes) > MAX_EML_BYTES:
            raise HTTPException(413, detail='File exceeds 10 MB limit.')
        if not _validate_mime(raw_bytes):
            raise HTTPException(400, detail='INVALID_MIME: Not a valid RFC 5322 email.')
    else:
        raw_bytes = raw_headers.encode('utf-8', errors='replace')
        if not _validate_mime(raw_bytes):
            raise HTTPException(400, detail='INVALID_MIME: Pasted text is not valid email source.')

    email_hash   = _sha256(raw_bytes)
    analysis_id  = str(uuid.uuid4())
    timestamp    = datetime.now(timezone.utc).isoformat()

    # ── Phase 1: Parse email ───────────────────────────────────────────────────
    loop = asyncio.get_event_loop()
    parsed: ParsedEmail = await loop.run_in_executor(None, parse_eml, raw_bytes)

    # ── Phase 2: All engines in parallel ──────────────────────────────────────
    (auth_result,
     (threat_label, confidence, lime_sentences),
     relay_hops,
     domain_intel) = await asyncio.gather(
        loop.run_in_executor(None, validate_auth, parsed),   # Phase 1 — real auth
        _run_classifier(parsed),                              # Phase 2 — NLP
        _run_geo(parsed),                                     # Phase 2 — Geo
        _run_domain(parsed),                                  # Phase 2 — Domain
    )

    # ── Phase 2: Real risk engine ──────────────────────────────────────────────
    risk_score_raw, risk_tier_str = compute_risk(
        auth           = auth_result,
        intent_label   = threat_label.value if hasattr(threat_label, 'value') else str(threat_label),
        intent_confidence = confidence,
        geo_hops       = relay_hops,
        domain         = domain_intel,
    )
    risk_score = risk_score_raw
    risk_tier  = _map_risk_tier(risk_tier_str)

    # ── Build warnings ─────────────────────────────────────────────────────────
    warnings = []
    if settings.AIR_GAPPED:
        warnings.append('Air-gapped mode active — live DNS/geo APIs disabled.')
    if auth_result.source == 'dns':
        warnings.append('Authentication-Results header absent — using DNS policy lookup (less precise).')
    if not parsed.received_hops:
        warnings.append('No relay hops extracted — headers may be minimal or stripped.')
    if not model_loaded():
        warnings.append(
            '[ML] XGBoost model not loaded — using heuristic classifier. '
            'Run: python scripts/train_classifier.py to enable full ML.'
        )
    if all(h.geo_mode == 'none' for h in relay_hops) and relay_hops:
        warnings.append('Geo lookup failed for all hops — ip-api.com may be rate-limited.')

    return AnalysisResponse(
        analysis_id    = analysis_id,
        subject        = parsed.subject,
        sender         = parsed.from_,
        recipient      = parsed.to,
        date           = parsed.date,
        risk_score     = risk_score,
        risk_tier      = risk_tier,
        threat_label   = threat_label,
        confidence     = confidence,
        auth           = AuthResult(
            spf    = _map_auth_status(auth_result.spf),
            dkim   = _map_auth_status(auth_result.dkim),
            dmarc  = _map_auth_status(auth_result.dmarc),
            details = auth_result.details,
        ),
        lime_sentences = lime_sentences,
        relay_hops     = relay_hops,
        domain_intel   = domain_intel,
        forensic       = ForensicMeta(
            email_sha256       = email_hash,
            analysis_timestamp = timestamp,
            air_gapped         = settings.AIR_GAPPED,
        ),
        warnings = warnings,
    )
