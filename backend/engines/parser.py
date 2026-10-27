"""
engines/parser.py — Phase 1
RFC-compliant email header + body parser with relay-hop extraction and
provider-masking detection.

Public API:
    parse_eml(raw_bytes) -> ParsedEmail
    clean_hops(received_headers) -> list[RawHop]
"""

import email
import email.policy
import hashlib
import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional, List


# ── Private IP detection ───────────────────────────────────────────────────────
_PRIVATE_NETS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
]

# Known mail-provider infrastructure IP prefixes that mask the originating IP.
# When the outermost Received hop is one of these, we cannot determine true origin.
_PROVIDER_MASKS: dict[str, list[re.Pattern]] = {
    'gmail': [
        re.compile(r'^209\.85\.'),
        re.compile(r'^66\.249\.'),
        re.compile(r'^64\.18\.'),
        re.compile(r'^74\.125\.'),
        re.compile(r'^172\.217\.'),
    ],
    'outlook / microsoft': [
        re.compile(r'^40\.107\.'),
        re.compile(r'^52\.101\.'),
        re.compile(r'^104\.47\.'),
        re.compile(r'^207\.46\.'),
    ],
    'yahoo': [
        re.compile(r'^98\.136\.'),
        re.compile(r'^66\.196\.'),
        re.compile(r'^67\.195\.'),
    ],
    'sendgrid': [
        re.compile(r'^167\.89\.'),
        re.compile(r'^198\.37\.'),
        re.compile(r'^149\.72\.'),
    ],
    'amazon ses': [
        re.compile(r'^54\.240\.'),
        re.compile(r'^199\.255\.'),
    ],
}

# Regex to extract IPv4 from a Received header string
_IP_RE = re.compile(
    r'\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b'
)

# Regex to extract hostname from "from <hostname>" in Received header
_HOST_RE = re.compile(r'from\s+([^\s\[\(]+)', re.IGNORECASE)


# ── Data classes ───────────────────────────────────────────────────────────────

@dataclass
class RawHop:
    hop_index: int
    ip: str
    hostname: Optional[str] = None
    masked: bool = False
    mask_provider: Optional[str] = None
    is_private: bool = False
    raw_received: str = ''


# ── Attachment Analysis ────────────────────────────────────────────────────────
_DANGEROUS_EXTENSIONS = {
    '.exe', '.scr', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse',
    '.wsf', '.wsh', '.hta', '.ps1', '.ps1xml', '.iso', '.img', '.vhd',
    '.dll', '.cpl', '.pif', '.jar', '.msi', '.msp', '.reg',
}
_MACRO_EXTENSIONS = {
    '.docm', '.dotm', '.xlsm', '.xltm', '.xlam', '.pptm', '.potm', '.ppam', '.ppsm',
}
_ARCHIVE_EXTENSIONS = {
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.cab',
}


@dataclass
class AttachmentInfo:
    filename: str
    size_bytes: int
    size_formatted: str
    sha256: str
    md5: str
    extension: str
    is_dangerous: bool
    is_double_extension: bool
    entropy: float
    risk_level: str          # "SAFE" | "SUSPICIOUS" | "MALICIOUS"
    risk_reasons: list[str] = field(default_factory=list)


@dataclass
class ParsedEmail:
    # Identity
    subject: Optional[str] = None
    from_: Optional[str] = None
    to: Optional[str] = None
    date: Optional[str] = None
    message_id: Optional[str] = None
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    x_originating_ip: Optional[str] = None

    # Content
    body_text: str = ''
    body_html: str = ''
    has_attachments: bool = False
    attachment_names: list[str] = field(default_factory=list)
    attachments: list[AttachmentInfo] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)

    # Forensics
    sender_domain: Optional[str] = None
    return_path_domain: Optional[str] = None
    received_headers: list[str] = field(default_factory=list)
    auth_results_headers: list[str] = field(default_factory=list)
    dkim_signature: Optional[str] = None
    received_hops: list[RawHop] = field(default_factory=list)

    # Display-name spoofing flag
    display_name_mismatch: bool = False

    # Synthetic / Custom campaign metadata fallbacks
    x_campaign_asn: Optional[str] = None
    x_campaign_isp: Optional[str] = None


# ── Helpers ────────────────────────────────────────────────────────────────────

def _extract_domain(address: str) -> Optional[str]:
    """Extract domain from 'Display Name <user@domain.com>' or 'user@domain.com'."""
    if not address:
        return None
    match = re.search(r'@([\w.\-]+)', address)
    return match.group(1).lower() if match else None


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


def _get_provider(ip: str) -> Optional[str]:
    for provider, patterns in _PROVIDER_MASKS.items():
        if any(p.match(ip) for p in patterns):
            return provider
    return None


def _extract_urls(text: str) -> list[str]:
    return re.findall(r'https?://[^\s\'"<>]+', text)


def _calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = -sum((count / length) * math.log2(count / length) for count in counter.values())
    return round(entropy, 3)


def _format_size(num_bytes: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB']:
        if num_bytes < 1024.0:
            return f"{num_bytes:.1f} {unit}" if unit != 'B' else f"{num_bytes} B"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} TB"


def _analyze_attachment(filename: str, payload_bytes: bytes) -> AttachmentInfo:
    size = len(payload_bytes)
    sha256 = hashlib.sha256(payload_bytes).hexdigest()
    md5 = hashlib.md5(payload_bytes).hexdigest()
    entropy = _calculate_entropy(payload_bytes)

    clean_fn = filename.strip()
    parts = clean_fn.rsplit('.', 2)
    ext = ('.' + clean_fn.split('.')[-1].lower()) if '.' in clean_fn else ''
    is_double = len(parts) >= 3 and (('.' + parts[-1].lower()) in _DANGEROUS_EXTENSIONS or ('.' + parts[-1].lower()) in _MACRO_EXTENSIONS)

    is_dangerous = ext in _DANGEROUS_EXTENSIONS
    is_macro = ext in _MACRO_EXTENSIONS
    is_archive = ext in _ARCHIVE_EXTENSIONS

    risk_reasons = []
    if is_double:
        risk_reasons.append(f"Double extension masquerade detected: {clean_fn}")
    if is_dangerous:
        risk_reasons.append(f"Executable/script payload extension: {ext}")
    if is_macro:
        risk_reasons.append(f"Macro-enabled document (dropper vector): {ext}")
    if is_archive:
        risk_reasons.append("Archive container — commonly used to deliver evasive payloads")
    if entropy > 7.2:
        risk_reasons.append(f"High Shannon entropy ({entropy}/8.0) suggests packed or encrypted payload")

    if is_double or is_dangerous or (is_macro and entropy > 6.8):
        risk_level = "MALICIOUS"
    elif is_macro or is_archive or entropy > 7.0:
        risk_level = "SUSPICIOUS"
    else:
        risk_level = "SAFE"

    return AttachmentInfo(
        filename=clean_fn,
        size_bytes=size,
        size_formatted=_format_size(size),
        sha256=sha256,
        md5=md5,
        extension=ext,
        is_dangerous=is_dangerous or is_double,
        is_double_extension=is_double,
        entropy=entropy,
        risk_level=risk_level,
        risk_reasons=risk_reasons,
    )


def _check_display_name_mismatch(from_header: str) -> bool:
    """
    Detect display-name spoofing: 'PayPal Security <attacker@evil.com>'
    Heuristic: display name contains a known brand but domain doesn't match.
    """
    BRANDS = ['paypal', 'google', 'microsoft', 'amazon', 'apple', 'facebook',
              'netflix', 'bank', 'hdfc', 'sbi', 'icici', 'uidai', 'nsdl', 'irctc']
    from_lower = from_header.lower()
    domain = _extract_domain(from_header) or ''

    # Extract display name (text before the angle bracket)
    display_match = re.match(r'^([^<]+)<', from_header)
    display_name = display_match.group(1).lower() if display_match else ''

    for brand in BRANDS:
        if brand in display_name and brand not in domain:
            return True
    return False


# ── Received header hop extraction ─────────────────────────────────────────────

def clean_hops(received_headers: list[str]) -> list[RawHop]:
    """
    Extract relay hops from Received headers.
    - Strips private/loopback IPs.
    - Flags provider-masked hops.
    Returns list ordered oldest-first (email travels from last Received to first).
    """
    hops: list[RawHop] = []

    # Received headers are newest-first; reverse to get path oldest→newest
    ordered = list(reversed(received_headers))

    for idx, header in enumerate(ordered):
        ips = _IP_RE.findall(header)
        host_match = _HOST_RE.search(header)
        hostname = host_match.group(1) if host_match else None

        if not ips:
            # No IP found — may be redacted or internal
            hops.append(RawHop(
                hop_index=idx,
                ip='[redacted]',
                hostname=hostname,
                masked=True,
                mask_provider='unknown',
                raw_received=header[:200],
            ))
            continue

        # Take the first public IP found in the header line
        chosen_ip = None
        for ip in ips:
            if not _is_private(ip):
                chosen_ip = ip
                break

        if not chosen_ip:
            # All IPs in this hop are private/loopback — skip
            continue

        provider = _get_provider(chosen_ip)
        hops.append(RawHop(
            hop_index=idx,
            ip=chosen_ip,
            hostname=hostname,
            masked=(provider is not None),
            mask_provider=provider,
            is_private=False,
            raw_received=header[:200],
        ))

    return hops


# ── Main parser ────────────────────────────────────────────────────────────────

def parse_eml(raw_bytes: bytes) -> ParsedEmail:
    """
    Parse raw email bytes (RFC 5322 / .eml) into a structured ParsedEmail.
    Uses Python stdlib `email` with modern policy for correct header decoding.
    """
    # Defensively normalize double-CR from Windows file transfers
    if b'\r\r\n' in raw_bytes:
        raw_bytes = raw_bytes.replace(b'\r\r\n', b'\r\n')

    # Use compat32 for broadest format support (some old phishing emails use
    # non-standard MIME that default policy rejects)
    msg = email.message_from_bytes(raw_bytes, policy=email.policy.compat32)

    result = ParsedEmail()

    # ── Identity headers ───────────────────────────────────────────────────────
    result.subject    = msg.get('Subject', '')
    result.from_      = msg.get('From', '')
    result.to         = msg.get('To', '')
    result.date       = msg.get('Date', '')
    result.message_id = msg.get('Message-ID', '')
    result.reply_to   = msg.get('Reply-To', '')
    result.return_path = msg.get('Return-Path', '')
    result.x_originating_ip = msg.get('X-Originating-IP', '') or msg.get('X-Source-IP', '')
    result.dkim_signature = msg.get('DKIM-Signature', '')
    result.x_campaign_asn = msg.get('X-Campaign-ASN', '') or None
    result.x_campaign_isp = msg.get('X-Campaign-ISP', '') or None

    # ── Received / Auth headers ────────────────────────────────────────────────
    result.received_headers     = msg.get_all('Received', [])
    result.auth_results_headers = msg.get_all('Authentication-Results', [])

    # ── Domain extraction ──────────────────────────────────────────────────────
    result.sender_domain      = _extract_domain(result.from_)
    result.return_path_domain = _extract_domain(result.return_path)

    # ── Body extraction ────────────────────────────────────────────────────────
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == 'text/plain' and not result.body_text:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or 'utf-8'
                    result.body_text = payload.decode(charset, errors='replace')
            elif ct == 'text/html' and not result.body_html:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or 'utf-8'
                    result.body_html = payload.decode(charset, errors='replace')
            elif part.get_filename():
                raw_payload = part.get_payload(decode=True) or b''
                att_info = _analyze_attachment(part.get_filename(), raw_payload)
                result.has_attachments = True
                result.attachments.append(att_info)
                result.attachment_names.append(att_info.filename)
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or 'utf-8'
            ct = msg.get_content_type()
            text = payload.decode(charset, errors='replace')
            if 'html' in ct:
                result.body_html = text
            else:
                result.body_text = text

    # ── URL extraction ─────────────────────────────────────────────────────────
    combined = result.body_text + result.body_html
    result.urls = list(set(_extract_urls(combined)))

    # ── Relay hops ─────────────────────────────────────────────────────────────
    result.received_hops = clean_hops(result.received_headers)

    # ── Display-name spoofing check ────────────────────────────────────────────
    if result.from_:
        result.display_name_mismatch = _check_display_name_mismatch(result.from_)

    return result
