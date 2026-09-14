"""
engines/reporter.py — Phase 4
Generates a forensic PDF dossier from AnalysisResponse data.
Uses ReportLab (pure Python, no system GTK/GLib deps) to produce PDF bytes.
"""

from __future__ import annotations
import io
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from models.schemas import AnalysisResponse

# ── Color palette ──────────────────────────────────────────────────────────────
_TIER_COLORS = {
    "safe":       (0.065, 0.722, 0.506),   # #10B981 green
    "suspicious": (0.961, 0.620, 0.043),   # #F59E0B amber
    "high":       (0.976, 0.451, 0.024),   # #F97316 orange
    "critical":   (0.937, 0.267, 0.267),   # #EF4444 red
}
_SAFE    = (0.065, 0.722, 0.506)
_WARN    = (0.961, 0.620, 0.043)
_FAIL    = (0.937, 0.267, 0.267)
_MUTED   = (0.580, 0.650, 0.702)
_DARK    = (0.059, 0.090, 0.165)   # #0F172A
_ACCENT  = (0.220, 0.741, 0.973)   # #38BDF8
_TEXT    = (0.122, 0.180, 0.239)   # #1E293B
_BORDER  = (0.886, 0.910, 0.933)   # #E2E8F0
_LIGHT   = (0.973, 0.980, 0.988)   # #F8FAFC


def _ts_ist(iso_ts: str) -> str:
    try:
        dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
        try:
            from zoneinfo import ZoneInfo
            ist = dt.astimezone(ZoneInfo("Asia/Kolkata"))
        except Exception:
            ist = dt
        return ist.strftime("%d %b %Y, %H:%M:%S IST")
    except Exception:
        return iso_ts


def generate_dossier(data: "AnalysisResponse") -> bytes:
    """Render a forensic PDF dossier. Returns raw PDF bytes."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, KeepTogether
        )
        from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    except ImportError:
        raise RuntimeError("reportlab is not installed. Run: pip install reportlab")

    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=16*mm, rightMargin=16*mm,
        topMargin=18*mm, bottomMargin=16*mm,
        title="MailForenSIX Forensic Dossier",
        author="MailForenSIX v0.3.0",
    )

    W = A4[0] - 32*mm   # usable width

    tier        = data.risk_tier.value if hasattr(data.risk_tier, "value") else str(data.risk_tier)
    label       = data.threat_label.value if hasattr(data.threat_label, "value") else str(data.threat_label)
    tier_color  = _TIER_COLORS.get(tier.lower(), _MUTED)
    ts_ist      = _ts_ist(data.forensic.analysis_timestamp) if data.forensic else "—"
    sha256      = data.forensic.email_sha256 if data.forensic else "—"
    analysis_id = data.analysis_id or "—"
    air_gapped  = data.forensic.air_gapped if data.forensic else False
    anchor_tx   = getattr(data.forensic, "anchor_tx_id", None)
    anchor_st   = getattr(data.forensic, "anchor_status", None)
    anchor_be   = getattr(data.forensic, "anchor_backend", None)

    RL_COLOR = colors.Color
    def c(*rgb): return RL_COLOR(*rgb)

    # ── Styles ─────────────────────────────────────────────────────────────────
    styles = getSampleStyleSheet()

    def sty(name, **kw):
        base = styles["Normal"]
        return ParagraphStyle(name, parent=base, **kw)

    H1  = sty("H1",  fontSize=16, leading=20, textColor=c(*_ACCENT), spaceAfter=2)
    H2  = sty("H2",  fontSize=9,  leading=12, textColor=c(*_MUTED), spaceAfter=6,
               fontName="Helvetica-Bold", textTransform="uppercase", letterSpacing=0.5)
    NRM = sty("NRM", fontSize=9,  leading=13, textColor=c(*_TEXT))
    SML = sty("SML", fontSize=7.5,leading=11, textColor=c(*_MUTED))
    MON = sty("MON", fontSize=7,  leading=11, textColor=c(*_ACCENT), fontName="Courier")

    def hr():
        return HRFlowable(width=W, thickness=0.5, color=c(*_BORDER), spaceAfter=6, spaceBefore=4)

    story = []

    # ── HEADER ─────────────────────────────────────────────────────────────────
    header_data = [[
        Paragraph("<b>MailForenSIX</b>", sty("Logo", fontSize=18, textColor=c(*_ACCENT), fontName="Helvetica-Bold")),
        Paragraph(f"Forensic Dossier<br/><font size='8' color='grey'>{ts_ist}</font>",
                  sty("HdrR", fontSize=11, alignment=TA_RIGHT, textColor=c(*_TEXT))),
    ]]
    header_tbl = Table(header_data, colWidths=[W*0.6, W*0.4])
    header_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), c(*_DARK)),
        ("TEXTCOLOR",  (0,0), (-1,-1), c(1,1,1)),
        ("TOPPADDING",  (0,0),(-1,-1), 10),
        ("BOTTOMPADDING",(0,0),(-1,-1), 10),
        ("LEFTPADDING", (0,0),(-1,-1), 12),
        ("RIGHTPADDING",(0,0),(-1,-1), 12),
        ("ROUNDEDCORNERS", [4]),
    ]))
    story.append(header_tbl)
    story.append(Spacer(1, 8))

    # ── RISK SUMMARY ───────────────────────────────────────────────────────────
    risk_data = [[
        Paragraph(
            f"<font size='36' color='{_rgb_hex(*tier_color)}'><b>{data.risk_score}</b></font><br/>"
            f"<font size='8' color='grey'>out of 100</font>",
            sty("Score", alignment=TA_CENTER, fontSize=12, leading=16)
        ),
        [
            Paragraph(f"<b>{tier.upper()}</b>",
                      sty("Tier", fontSize=14, textColor=c(*tier_color), leading=18)),
            Paragraph(f"Threat: <b>{label.capitalize()}</b> · Confidence: <b>{int(data.confidence*100)}%</b>", NRM),
            Paragraph(f"Engine: XGBoost + TF-IDF (ngram 1-3) + LIME", SML),
        ],
        [
            Paragraph(f"<b>Subject:</b> {(data.subject or '—')[:55]}", SML),
            Paragraph(f"<b>From:</b> {(data.sender or '—')[:55]}", SML),
            Paragraph(f"<b>Date:</b> {data.date or '—'}", SML),
            Paragraph(f"<b>ID:</b> {analysis_id}", SML),
        ]
    ]]
    risk_tbl = Table(risk_data, colWidths=[W*0.15, W*0.35, W*0.50])
    risk_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), c(*_LIGHT)),
        ("BOX",        (0,0), (-1,-1), 0.5, c(*_BORDER)),
        ("VALIGN",     (0,0), (-1,-1), "TOP"),
        ("TOPPADDING", (0,0), (-1,-1), 10),
        ("BOTTOMPADDING",(0,0),(-1,-1), 10),
        ("LEFTPADDING",(0,0), (-1,-1), 10),
        ("LEFTLINEWIDTH",(0,0),(0,-1), 4),
        ("LEFTLINECOLOR",(0,0),(0,-1), c(*tier_color)),
    ]))
    story.append(risk_tbl)
    story.append(Spacer(1, 10))

    # ── SHA-256 HASH ───────────────────────────────────────────────────────────
    story.append(Paragraph("Evidence Hash (SHA-256)", H2))
    hash_data = [[Paragraph(sha256, MON)]]
    hash_tbl = Table(hash_data, colWidths=[W])
    hash_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0),(-1,-1), c(0.878, 0.953, 0.992)),
        ("BOX",        (0,0),(-1,-1), 0.5, c(0.729, 0.902, 0.973)),
        ("TOPPADDING", (0,0),(-1,-1), 8),
        ("BOTTOMPADDING",(0,0),(-1,-1), 8),
        ("LEFTPADDING",(0,0),(-1,-1), 10),
    ]))
    story.append(hash_tbl)
    if anchor_tx:
        anchor_label = ("🔒 Anchored (OpenTimestamps)" if anchor_be == "opentimestamps" else "📁 Local hash file")
        story.append(Spacer(1, 4))
        story.append(Paragraph(f"{anchor_label} · TX: {anchor_tx}", SML))
    story.append(Paragraph(
        "This SHA-256 digest uniquely identifies the submitted email artifact. "
        "Any modification to the original .eml file produces a different hash, "
        "providing tamper-evidence for chain-of-custody."
        + (" ⚠ Air-gapped mode was active." if air_gapped else ""),
        SML
    ))
    story.append(Spacer(1, 10))

    # ── AUTH MATRIX ────────────────────────────────────────────────────────────
    story.append(Paragraph("Email Authentication (SPF / DKIM / DMARC)", H2))
    if data.auth:
        spf_v  = data.auth.spf.value  if hasattr(data.auth.spf,  "value") else str(data.auth.spf)
        dkim_v = data.auth.dkim.value if hasattr(data.auth.dkim, "value") else str(data.auth.dkim)
        dmar_v = data.auth.dmarc.value if hasattr(data.auth.dmarc,"value") else str(data.auth.dmarc)

        def status_color(s):
            return {"pass": c(*_SAFE), "fail": c(*_FAIL), "warn": c(*_WARN)}.get(s, c(*_MUTED))

        auth_rows = [
            [Paragraph("<b>Protocol</b>", NRM), Paragraph("<b>Status</b>", NRM)],
            ["SPF",  spf_v.upper()],
            ["DKIM", dkim_v.upper()],
            ["DMARC",dmar_v.upper()],
        ]
        if data.auth.details:
            auth_rows.append([Paragraph(data.auth.details, SML), ""])

        auth_tbl = Table(auth_rows, colWidths=[W*0.3, W*0.7])
        auth_style = [
            ("BACKGROUND", (0,0),(-1,0), c(*_LIGHT)),
            ("BOX",        (0,0),(-1,-1), 0.5, c(*_BORDER)),
            ("INNERGRID",  (0,0),(-1,-1), 0.3, c(*_BORDER)),
            ("FONTSIZE",   (0,0),(-1,-1), 9),
            ("TOPPADDING", (0,0),(-1,-1), 5),
            ("BOTTOMPADDING",(0,0),(-1,-1), 5),
            ("LEFTPADDING",(0,0),(-1,-1), 8),
            ("TEXTCOLOR",  (1,1),(1,1), status_color(spf_v)),
            ("TEXTCOLOR",  (1,2),(1,2), status_color(dkim_v)),
            ("TEXTCOLOR",  (1,3),(1,3), status_color(dmar_v)),
            ("FONTNAME",   (1,1),(1,3), "Helvetica-Bold"),
        ]
        auth_tbl.setStyle(TableStyle(auth_style))
        story.append(auth_tbl)
    story.append(Spacer(1, 10))

    # ── RELAY HOPS ─────────────────────────────────────────────────────────────
    story.append(Paragraph(f"Relay Hop Chain ({len(data.relay_hops or [])} hops)", H2))
    if data.relay_hops:
        hop_rows = [[Paragraph(h, sty("TH", fontSize=8, fontName="Helvetica-Bold", textColor=c(*_TEXT)))
                     for h in ["#", "IP Address", "Location", "ISP", "ASN", "Flags"]]]
        for hop in data.relay_hops:
            flags = []
            if hop.masked: flags.append("⚠ Masked")
            if getattr(hop, "vpn", False): flags.append("VPN")
            hop_rows.append([
                str(hop.hop_index),
                Paragraph(hop.ip, sty("MONO", fontSize=7, fontName="Courier")),
                f"{hop.city or '—'}, {hop.country or '—'}",
                (hop.isp or "—")[:28],
                hop.asn or "—",
                " ".join(flags) or "—",
            ])
        hop_tbl = Table(hop_rows, colWidths=[W*0.05, W*0.17, W*0.20, W*0.28, W*0.18, W*0.12])
        hop_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,0), c(*_LIGHT)),
            ("BOX",           (0,0),(-1,-1), 0.5, c(*_BORDER)),
            ("INNERGRID",     (0,0),(-1,-1), 0.3, c(*_BORDER)),
            ("FONTSIZE",      (0,1),(-1,-1), 8),
            ("TOPPADDING",    (0,0),(-1,-1), 4),
            ("BOTTOMPADDING", (0,0),(-1,-1), 4),
            ("LEFTPADDING",   (0,0),(-1,-1), 6),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [c(1,1,1), c(*_LIGHT)]),
        ]))
        story.append(hop_tbl)
    else:
        story.append(Paragraph("No relay hops extracted.", SML))
    story.append(Spacer(1, 10))

    # ── LIME EXPLANATIONS ──────────────────────────────────────────────────────
    story.append(Paragraph("ML Explanation — Top Suspicious Sentences (LIME)", H2))
    sorted_lime = sorted(data.lime_sentences or [], key=lambda x: x.score, reverse=True)[:8]
    if sorted_lime:
        lime_rows = [[Paragraph(h, sty("TH", fontSize=8, fontName="Helvetica-Bold"))
                      for h in ["Sentence", "Score", "Explanation"]]]
        for sent in sorted_lime:
            pct = int(sent.score * 100)
            sc  = {"pass": c(*_SAFE), "fail": c(*_FAIL)}.get(
                "pass" if pct < 50 else "fail", c(*_WARN)
            )
            lime_rows.append([
                Paragraph(f'"{sent.text[:90]}{"…" if len(sent.text)>90 else ""}"', SML),
                Paragraph(f"<b>{pct}%</b>", sty("Pct", fontSize=8, textColor=c(*_FAIL) if pct>=70 else c(*_WARN) if pct>=40 else c(*_MUTED))),
                Paragraph(sent.explanation, SML),
            ])
        lime_tbl = Table(lime_rows, colWidths=[W*0.45, W*0.10, W*0.45])
        lime_tbl.setStyle(TableStyle([
            ("BACKGROUND",   (0,0),(-1,0), c(*_LIGHT)),
            ("BOX",          (0,0),(-1,-1), 0.5, c(*_BORDER)),
            ("INNERGRID",    (0,0),(-1,-1), 0.3, c(*_BORDER)),
            ("FONTSIZE",     (0,1),(-1,-1), 8),
            ("TOPPADDING",   (0,0),(-1,-1), 4),
            ("BOTTOMPADDING",(0,0),(-1,-1), 4),
            ("LEFTPADDING",  (0,0),(-1,-1), 6),
            ("VALIGN",       (0,0),(-1,-1), "TOP"),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [c(1,1,1), c(*_LIGHT)]),
        ]))
        story.append(lime_tbl)
        story.append(Paragraph(
            "LIME (Local Interpretable Model-agnostic Explanations) identifies which sentence "
            "fragments most influenced the XGBoost classifier's verdict.", SML
        ))
    else:
        story.append(Paragraph("No LIME explanations available.", SML))
    story.append(Spacer(1, 10))

    # ── DOMAIN INTEL ───────────────────────────────────────────────────────────
    if data.domain_intel:
        story.append(Paragraph("Domain Intelligence", H2))
        di = data.domain_intel
        di_rows = [
            ["Domain",          Paragraph(di.domain, sty("MON2", fontSize=8, fontName="Courier"))],
            ["Age",             f"{'⚠ ' if (di.age_days or 999) < 30 else ''}{di.age_days or '—'} days"],
            ["Registrar",       di.registrar or "—"],
            ["Created",         di.creation_date or "—"],
            ["Expires",         di.expiry_date or "—"],
            ["MX Valid",        "✓ Yes" if di.mx_valid else "✗ No"],
            ["Privacy Proxy",       # ── IT ACT 2000 — contextual selection ────────────────────────────────────────
    story.append(Paragraph("Legal Reference — IT Act 2000 (Applicable Sections)", H2))

    _tier_v  = data.risk_tier.value   if hasattr(data.risk_tier,   "value") else str(data.risk_tier)
    _label_v = data.threat_label.value if hasattr(data.threat_label,"value") else str(data.threat_label)
    _dkim_v  = data.auth.dkim.value  if data.auth and hasattr(data.auth.dkim,  "value") else "none"
    _dmarc_v = data.auth.dmarc.value if data.auth and hasattr(data.auth.dmarc, "value") else "none"
    _priv    = bool(data.domain_intel and data.domain_intel.privacy_proxy)
    _warn_lc = [w.lower() for w in (data.warnings or [])]
    _spoof   = any("spoof" in w or "align" in w for w in _warn_lc)

    it_hdr_s = sty("IT_HDR", fontSize=8, leading=10, fontName="Helvetica-Bold", textColor=c(*_TEXT))
    it_sec_s = sty("IT_SEC", fontSize=8, leading=10, fontName="Helvetica-Bold", textColor=c(*_ACCENT))
    it_dsc_s = sty("IT_DSC", fontSize=7.5, leading=10, textColor=c(*_TEXT))
    it_why_s = sty("IT_WHY", fontSize=7.5, leading=10, textColor=c(*_MUTED))

    it_applicable = [[
        Paragraph("Section", it_hdr_s),
        Paragraph("Description", it_hdr_s),
        Paragraph("Why Applicable", it_hdr_s)
    ]]

    # §43 — always baseline
    it_applicable.append([
        Paragraph("§43", it_sec_s),
        Paragraph("Penalty and compensation for damage to computer, computer system, etc.", it_dsc_s),
        Paragraph("Baseline — any fraudulent email interaction with computer systems", it_why_s),
    ])
    # §66 — deliberate offence, suspicious or higher risk
    if _tier_v in ("suspicious", "high", "critical"):
        it_applicable.append([
            Paragraph("§66", it_sec_s),
            Paragraph("Computer related offences — imprisonment up to 3 years or fine up to Rs.5 lakh", it_dsc_s),
            Paragraph(f"Risk tier: {_tier_v.upper()} — indicates deliberate fraudulent computer use", it_why_s),
        ])
    # §66C — identity theft, auth failure or impersonation
    if _dkim_v == "fail" or _dmarc_v == "fail" or _label_v == "impersonation" or _spoof:
        _why66c = ("DKIM FAIL — sender identity cannot be verified" if _dkim_v == "fail"
                   else "DMARC FAIL — domain policy violated, likely spoofed" if _dmarc_v == "fail"
                   else "Display-name or sender domain spoofing detected")
        it_applicable.append([
            Paragraph("§66C", it_sec_s),
            Paragraph("Punishment for identity theft — imprisonment up to 3 years and fine up to Rs.1 lakh", it_dsc_s),
            Paragraph(_why66c, it_why_s),
        ])
    # §66D — cheating by personation; phishing, BEC, impersonation
    if _label_v in ("bec", "impersonation", "phishing"):
        _why66d = ("Business Email Compromise pattern detected" if _label_v == "bec"
                   else "Email impersonates a trusted entity" if _label_v == "impersonation"
                   else "Phishing via privacy-proxy domain" if _priv
                   else "Phishing email — personation via deceptive communication")
        it_applicable.append([
            Paragraph("§66D", it_sec_s),
            Paragraph("Cheating by personation using computer resource — imprisonment up to 3 years", it_dsc_s),
            Paragraph(_why66d, it_why_s),
        ])

    it_tbl = Table(it_applicable, colWidths=[W*0.12, W*0.44, W*0.44])
    it_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,0),  c(*_LIGHT)),
        ("BOX",           (0,0),(-1,-1), 0.5, c(*_BORDER)),
        ("INNERGRID",     (0,0),(-1,-1), 0.3, c(*_BORDER)),
        ("TOPPADDING",    (0,0),(-1,-1), 5),
        ("BOTTOMPADDING", (0,0),(-1,-1), 5),
        ("LEFTPADDING",   (0,0),(-1,-1), 6),
        ("RIGHTPADDING",  (0,0),(-1,-1), 6),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [c(1,1,1), c(*_LIGHT)]),
        ("VALIGN",        (0,0),(-1,-1), "TOP"),
    ]))
    story.append(it_tbl)
    story.append(Spacer(1, 10))

    # ── CHAIN OF CUSTODY ───────────────────────────────────────────────────────
    story.append(Paragraph("Chain of Custody", H2))
    coc_val_s = sty("COC_VAL", fontSize=7.5, leading=10, textColor=c(*_TEXT))
    coc_rows = [
        ["Tool",              Paragraph("MailForenSIX v0.3.0 (SIH 2026)", coc_val_s)],
        ["Analysis Engine",   Paragraph("XGBoost + TF-IDF (ngram 1-3) · LIME · Real-time Geo · WHOIS Domain Intel", coc_val_s)],
        ["Timestamp",         Paragraph(ts_ist, coc_val_s)],
        ["Analysis UUID",     Paragraph(analysis_id, coc_val_s)],
        ["Evidence SHA-256",  Paragraph(sha256, sty("COC", fontSize=6.5, fontName="Courier", textColor=c(*_ACCENT)))],
        ["Mode",              Paragraph("Air-gapped (offline)" if air_gapped else "Online (live APIs)", coc_val_s)],
        ["Risk Weights",      Paragraph("Auth 30% · ML Intent 30% · Geo 20% · Domain 20%", coc_val_s)],
        ["Report Generated",  Paragraph(datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M:%S UTC"), coc_val_s)],
    ]
    coc_tbl = Table(coc_rows, colWidths=[W*0.22, W*0.78])
    coc_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0),(0,-1),  c(*_LIGHT)),
        ("BOX",          (0,0),(-1,-1), 0.5, c(*_BORDER)),
        ("INNERGRID",    (0,0),(-1,-1), 0.3, c(*_BORDER)),
        ("FONTSIZE",     (0,0),(-1,-1), 8),
        ("FONTNAME",     (0,0),(0,-1),  "Helvetica-Bold"),
        ("TOPPADDING",   (0,0),(-1,-1), 5),
        ("BOTTOMPADDING",(0,0),(-1,-1), 5),
        ("LEFTPADDING",  (0,0),(-1,-1), 8),
        ("ROWBACKGROUNDS",(0,0),(-1,-1), [c(1,1,1), c(*_LIGHT)]),
    ]))
    story.append(coc_tbl)
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "This report was generated automatically by MailForenSIX. It is intended for use by "
        "authorized law-enforcement and cybersecurity personnel. All analysis is based on the "
        "submitted email artifact identified by its SHA-256 hash above. This document may be used "
        "as supporting evidence in investigations under IT Act 2000 and IPC provisions.",
        SML
    ))

    # ── Build ──────────────────────────────────────────────────────────────────
    doc.build(story)
    return buffer.getvalue()


def _rgb_hex(r: float, g: float, b: float) -> str:
    """Convert 0–1 float RGB to hex string for ReportLab paragraph color."""
    return "#{:02x}{:02x}{:02x}".format(int(r*255), int(g*255), int(b*255))
