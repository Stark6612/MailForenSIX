"""
Pydantic schemas for the /analyze endpoint.
These define the API contract shared between frontend and backend.
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from enum import Enum


# ── Enums ──────────────────────────────────────────────────────────────────────

class AuthStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    NONE = "none"


class RiskTier(str, Enum):
    SAFE = "safe"           # 0–29
    SUSPICIOUS = "suspicious"   # 30–59
    HIGH = "high"           # 60–84
    CRITICAL = "critical"   # 85–100


class ThreatLabel(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    PHISHING = "phishing"
    BEC = "bec"
    IMPERSONATION = "impersonation"


# ── Sub-models ─────────────────────────────────────────────────────────────────

class AuthResult(BaseModel):
    spf: AuthStatus
    dkim: AuthStatus
    dmarc: AuthStatus
    details: Optional[str] = None


class LIMESentence(BaseModel):
    text: str
    score: float = Field(ge=0.0, le=1.0)
    explanation: str


class RelayHop(BaseModel):
    hop_index: int
    ip: str
    hostname: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    asn: Optional[str] = None
    isp: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    masked: bool = False          # True when Gmail/Outlook strips originating IP
    mask_reason: Optional[str] = None
    geo_mode: str = "online"      # "online" | "offline" | "cached"


class DomainIntel(BaseModel):
    domain: str
    age_days: Optional[int] = None
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiry_date: Optional[str] = None
    mx_valid: bool = False
    privacy_proxy: bool = False
    suspicion_score: float = Field(default=0.0, ge=0.0, le=1.0)
    notes: List[str] = []


class ForensicMeta(BaseModel):
    email_sha256: str
    analysis_timestamp: str
    air_gapped: bool
    # Phase 4 — blockchain anchor
    anchor_tx_id: Optional[str] = None
    anchor_status: Optional[str] = None   # "pending" | "local" | "anchored"
    anchor_backend: Optional[str] = None  # "opentimestamps" | "local"


# ── Main Response ──────────────────────────────────────────────────────────────

class AnalysisResponse(BaseModel):
    # Identity
    analysis_id: str
    subject: Optional[str] = None
    sender: Optional[str] = None
    recipient: Optional[str] = None
    date: Optional[str] = None

    # Risk
    risk_score: int = Field(ge=0, le=100)
    risk_tier: RiskTier
    threat_label: ThreatLabel
    confidence: float = Field(ge=0.0, le=1.0)

    # Analysis modules
    auth: AuthResult
    lime_sentences: List[LIMESentence] = []
    relay_hops: List[RelayHop] = []
    domain_intel: Optional[DomainIntel] = None

    # Forensic metadata
    forensic: ForensicMeta

    # Error / warning messages surfaced to the UI
    warnings: List[str] = []


# ── Error response ─────────────────────────────────────────────────────────────

class ErrorResponse(BaseModel):
    error_code: str
    message: str
    detail: Optional[str] = None
