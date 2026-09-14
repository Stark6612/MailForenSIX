"""
engines/auth.py — Phase 1
SPF / DKIM / DMARC authentication validation.

Strategy (two-tier):
  1. Parse `Authentication-Results` headers set by the receiving mail server
     — most reliable source; the server already did the cryptographic checks.
  2. If absent, fall back to DNS-based policy lookup using checkdmarc + dnspython
     to at least show whether the domain *has* valid records.

Public API:
    validate_auth(parsed_email) -> AuthValidationResult
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Optional

import dns.resolver
import dns.exception

logger = logging.getLogger(__name__)


# ── Result dataclass ───────────────────────────────────────────────────────────

@dataclass
class AuthValidationResult:
    spf:   str = 'none'     # pass | fail | warn | none
    dkim:  str = 'none'
    dmarc: str = 'none'
    spf_detail:   str = ''
    dkim_detail:  str = ''
    dmarc_detail: str = ''
    source: str = 'header'  # 'header' | 'dns' | 'mixed'
    alignment_ok: bool = False   # From domain == Return-Path domain
    details: str = ''


# ── Tier 1: Parse Authentication-Results header ────────────────────────────────

_STATUS_MAP = {
    'pass':      'pass',
    'fail':      'fail',
    'hardfail':  'fail',
    'softfail':  'warn',
    'neutral':   'warn',
    'temperror': 'warn',
    'permerror': 'fail',
    'none':      'none',
}

def _parse_header_auth(auth_headers: list[str]) -> dict:
    """
    Extract SPF / DKIM / DMARC results from Authentication-Results headers.
    Returns dict with keys spf, dkim, dmarc and their raw detail strings.
    """
    result = {
        'spf': 'none',   'spf_detail': '',
        'dkim': 'none',  'dkim_detail': '',
        'dmarc': 'none', 'dmarc_detail': '',
    }

    for header in auth_headers:
        h = header.lower()

        # SPF
        if result['spf'] == 'none':
            m = re.search(
                r'spf\s*=\s*(pass|fail|hardfail|softfail|neutral|none|temperror|permerror)',
                h
            )
            if m:
                result['spf'] = _STATUS_MAP.get(m.group(1), 'none')
                # Extract smtp.mailfrom or envelope-from detail
                detail_m = re.search(r'smtp\.(?:mailfrom|helo)\s*=\s*([^\s;]+)', h)
                result['spf_detail'] = detail_m.group(1) if detail_m else ''

        # DKIM
        if result['dkim'] == 'none':
            m = re.search(
                r'dkim\s*=\s*(pass|fail|neutral|none|temperror|permerror)',
                h
            )
            if m:
                result['dkim'] = _STATUS_MAP.get(m.group(1), 'none')
                detail_m = re.search(r'header\.(?:d|i)\s*=\s*([^\s;]+)', h)
                result['dkim_detail'] = detail_m.group(1) if detail_m else ''

        # DMARC
        if result['dmarc'] == 'none':
            m = re.search(
                r'dmarc\s*=\s*(pass|fail|none|temperror|permerror)',
                h
            )
            if m:
                result['dmarc'] = _STATUS_MAP.get(m.group(1), 'none')
                detail_m = re.search(r'header\.from\s*=\s*([^\s;]+)', h)
                result['dmarc_detail'] = detail_m.group(1) if detail_m else ''

    return result


# ── Tier 2: DNS-based fallback ─────────────────────────────────────────────────

def _check_spf_dns(domain: str) -> tuple[str, str]:
    """
    Check if the domain has an SPF TXT record.
    Returns (status, detail) — 'pass' means record exists, not that email passed.
    """
    if not domain:
        return 'none', 'No domain'
    try:
        answers = dns.resolver.resolve(domain, 'TXT', lifetime=5)
        for rdata in answers:
            txt = b''.join(rdata.strings).decode('utf-8', errors='replace')
            if txt.startswith('v=spf1'):
                # SPF record exists — can't verify pass/fail without sending IP
                if 'all' in txt:
                    qualifier = re.search(r'([~\-\+\?])all', txt)
                    q = qualifier.group(1) if qualifier else '?'
                    status = 'pass' if q == '+' else ('warn' if q in ('~', '?') else 'fail')
                    return status, txt[:120]
                return 'warn', txt[:120]
        return 'none', 'No SPF record found'
    except (dns.exception.DNSException, Exception) as e:
        logger.debug(f'SPF DNS lookup failed for {domain}: {e}')
        return 'none', str(e)[:80]


def _check_dmarc_dns(domain: str) -> tuple[str, str]:
    """
    Check if the domain has a DMARC TXT record at _dmarc.<domain>.
    """
    if not domain:
        return 'none', 'No domain'
    try:
        dmarc_domain = f'_dmarc.{domain}'
        answers = dns.resolver.resolve(dmarc_domain, 'TXT', lifetime=5)
        for rdata in answers:
            txt = b''.join(rdata.strings).decode('utf-8', errors='replace')
            if txt.startswith('v=DMARC1'):
                policy_m = re.search(r'p=(none|quarantine|reject)', txt)
                policy = policy_m.group(1) if policy_m else 'none'
                status = 'pass' if policy in ('quarantine', 'reject') else 'warn'
                return status, f'Policy: {policy} | {txt[:100]}'
        return 'none', 'No DMARC record found'
    except (dns.exception.DNSException, Exception) as e:
        logger.debug(f'DMARC DNS lookup failed for {domain}: {e}')
        return 'none', str(e)[:80]


def _check_dkim_signature(dkim_signature: str) -> tuple[str, str]:
    """
    Check DKIM-Signature header presence and extract signing domain.
    We can't cryptographically verify the signature without the public key
    lookup — but we can detect presence/absence and domain alignment.
    """
    if not dkim_signature:
        return 'none', 'No DKIM-Signature header'
    d_match = re.search(r'\bd=([^;]+)', dkim_signature)
    signing_domain = d_match.group(1).strip() if d_match else '?'
    return 'warn', f'Signature present, signing domain: {signing_domain} (not cryptographically verified)'


# ── Domain alignment check ─────────────────────────────────────────────────────

def _check_alignment(from_domain: Optional[str], return_path_domain: Optional[str]) -> bool:
    """
    SPF alignment: the Return-Path (envelope-from) domain should match
    the From header domain. Mismatch is a spoofing signal.
    """
    if not from_domain or not return_path_domain:
        return False
    # Allow organizational domain match (relaxed alignment)
    f = from_domain.lower().strip()
    r = return_path_domain.lower().strip()
    if f == r:
        return True
    # Relaxed: check if one is a subdomain of the other
    return f.endswith('.' + r) or r.endswith('.' + f)


# ── Main validator ─────────────────────────────────────────────────────────────

def validate_auth(parsed) -> AuthValidationResult:
    """
    Run full SPF/DKIM/DMARC validation on a ParsedEmail.
    parsed: engines.parser.ParsedEmail instance
    """
    result = AuthValidationResult()

    # ── Tier 1: Authentication-Results header ──────────────────────────────────
    if parsed.auth_results_headers:
        header_data = _parse_header_auth(parsed.auth_results_headers)
        result.spf          = header_data['spf']
        result.dkim         = header_data['dkim']
        result.dmarc        = header_data['dmarc']
        result.spf_detail   = header_data['spf_detail']
        result.dkim_detail  = header_data['dkim_detail']
        result.dmarc_detail = header_data['dmarc_detail']
        result.source       = 'header'

    # ── Tier 2: DNS fallback for anything still 'none' ─────────────────────────
    domain = parsed.sender_domain
    used_dns = False

    if result.spf == 'none' and domain:
        result.spf, result.spf_detail = _check_spf_dns(domain)
        used_dns = True

    if result.dkim == 'none':
        result.dkim, result.dkim_detail = _check_dkim_signature(parsed.dkim_signature or '')
        if result.dkim == 'none' and domain:
            # No DKIM-Signature in email — definitive absence
            result.dkim = 'fail'
            result.dkim_detail = 'No DKIM-Signature header found in email.'

    if result.dmarc == 'none' and domain:
        result.dmarc, result.dmarc_detail = _check_dmarc_dns(domain)
        used_dns = True

    if used_dns and result.source == 'header':
        result.source = 'mixed'
    elif used_dns:
        result.source = 'dns'

    # ── Alignment ──────────────────────────────────────────────────────────────
    result.alignment_ok = _check_alignment(parsed.sender_domain, parsed.return_path_domain)

    # ── Human-readable summary ─────────────────────────────────────────────────
    flags = []
    if result.spf   == 'fail':  flags.append('SPF FAIL — sender not authorized')
    if result.dkim  == 'fail':  flags.append('DKIM FAIL — no valid signature')
    if result.dmarc == 'fail':  flags.append('DMARC FAIL — policy violation')
    if not result.alignment_ok: flags.append('From/Return-Path domain mismatch (spoofing indicator)')
    result.details = ' | '.join(flags) if flags else 'No critical authentication failures detected.'

    return result
