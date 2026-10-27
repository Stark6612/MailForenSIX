"""
engines/exporter.py
--------------------
Compliance-ready multi-format export for campaign intelligence results.
Formats: STIX 2.1, Sigma, Suricata, Postfix header_checks, Exchange Transport Rule, DNSBL.

Public API:
    export_stix(campaign, tlp="amber") -> str  (JSON)
    export_sigma(campaign)             -> str  (YAML)
    export_suricata(campaign)          -> str  (Suricata rule text)
    export_postfix(campaign)           -> str  (Postfix header_checks text)
    export_exchange(campaign)          -> str  (PowerShell New-TransportRule)
    export_dnsbl(campaign)             -> str  (plain-text IP list)
    validate_stix(stix_json: str)      -> dict (validation result)
"""

from __future__ import annotations
import json
import logging
import re
import uuid
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# TLP marking object IDs (STIX 2.1 standard GUIDs)
_TLP_IDS = {
    "white":  "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "green":  "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "amber":  "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "red":    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}


def _tlp_id(tlp: str) -> str:
    return _TLP_IDS.get(tlp.lower(), _TLP_IDS["amber"])


def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _safe_id(prefix: str) -> str:
    return f"{prefix}--{uuid.uuid4()}"


# ── STIX 2.1 ────────────────────────────────────────────────────────────────────

def export_stix(campaign: dict, tlp: str = "amber") -> str:
    """
    Build a STIX 2.1 bundle containing:
    - Intrusion Set (actor profile)
    - Campaign object
    - Infrastructure objects (relay IPs)
    - Indicator objects (domains)
    - TLP marking definition reference
    """
    ts     = _now_ts()
    tlp_id = _tlp_id(tlp)
    cid    = campaign.get("campaign_id", str(uuid.uuid4()))
    name   = campaign.get("name", f"Campaign-{cid[:8]}")
    profile = campaign.get("actor_profile", {})
    techniques = profile.get("mitre_techniques", [])

    # Intrusion Set
    intrusion_set_id = _safe_id("intrusion-set")
    intrusion_set = {
        "type": "intrusion-set",
        "spec_version": "2.1",
        "id": intrusion_set_id,
        "created": ts, "modified": ts,
        "name": f"Unknown Actor - {name}",
        "description": f"Actor profile derived from {profile.get('email_count', 0)} clustered emails.",
        "object_marking_refs": [tlp_id],
        "aliases": [name],
        "goals": ["Credential Harvesting", "Financial Fraud"],
        "resource_level": "individual",
        "primary_motivation": "financial-gain",
    }

    # Campaign
    campaign_id = _safe_id("campaign")
    campaign_obj = {
        "type": "campaign",
        "spec_version": "2.1",
        "id": campaign_id,
        "created": ts, "modified": ts,
        "name": name,
        "description": f"Phishing campaign with {profile.get('email_count', 0)} emails. "
                       f"Techniques: {', '.join(t['id'] for t in techniques)}",
        "object_marking_refs": [tlp_id],
    }

    # Relationship: campaign -[attributed-to]-> intrusion_set
    rel_id = _safe_id("relationship")
    attribution_rel = {
        "type": "relationship", "spec_version": "2.1",
        "id": rel_id, "created": ts, "modified": ts,
        "relationship_type": "attributed-to",
        "source_ref": campaign_id, "target_ref": intrusion_set_id,
        "object_marking_refs": [tlp_id],
    }

    objects = [intrusion_set, campaign_obj, attribution_rel]

    # Infrastructure objects (relay IPs)
    relay_ips = list(profile.get("relay_ips", {}).keys())
    for ip in relay_ips[:20]:  # cap at 20
        infra_id = _safe_id("infrastructure")
        objects.append({
            "type": "infrastructure",
            "spec_version": "2.1",
            "id": infra_id,
            "created": ts, "modified": ts,
            "name": f"Relay IP: {ip}",
            "infrastructure_types": ["hosting-malware", "botnet"],
            "object_marking_refs": [tlp_id],
        })

    # Indicator objects (sender domains)
    sender_domains = list(profile.get("sender_domains", {}).keys())
    for domain in sender_domains[:10]:
        ind_id = _safe_id("indicator")
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created": ts, "modified": ts,
            "name": f"Phishing domain: {domain}",
            "indicator_types": ["malicious-activity"],
            "pattern": f"[domain-name:value = '{domain}']",
            "pattern_type": "stix",
            "valid_from": ts,
            "object_marking_refs": [tlp_id],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
        })

    # Attack Pattern objects (MITRE techniques)
    for tech in techniques:
        ap_id = _safe_id("attack-pattern")
        objects.append({
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": ap_id,
            "created": ts, "modified": ts,
            "name": f"{tech['id']} - {tech['name']}",
            "description": tech.get("description", ""),
            "object_marking_refs": [tlp_id],
            "external_references": [{
                "source_name": "mitre-attack",
                "external_id": tech["id"],
                "url": f"https://attack.mitre.org/techniques/{tech['id'].replace('.', '/')}",
            }],
        })

    bundle = {
        "type": "bundle",
        "id": _safe_id("bundle"),
        "objects": objects,
    }

    return json.dumps(bundle, indent=2)


def validate_stix(stix_json: str) -> dict:
    """Validate a STIX 2.1 JSON string using the stix2 library."""
    try:
        import stix2
        bundle = stix2.parse(stix_json, allow_custom=False)
        return {"valid": True, "object_count": len(bundle.objects), "errors": []}
    except Exception as e:
        return {"valid": False, "object_count": 0, "errors": [str(e)]}


# ── Sigma ────────────────────────────────────────────────────────────────────────

def export_sigma(campaign: dict) -> str:
    profile = campaign.get("actor_profile", {})
    name    = campaign.get("name", "Unknown Campaign")
    domains = list(profile.get("sender_domains", {}).keys())
    ips     = list(profile.get("relay_ips", {}).keys())
    subjects = profile.get("subject_samples", [])

    domain_condition = " or ".join(f"'{d}'" for d in domains[:5]) if domains else "'phishing.example.com'"
    subject_condition = " or ".join(f"'{s[:60]}'" for s in subjects[:3]) if subjects else "'Urgent action required'"

    return f"""title: MailForensix - {name}
id: {uuid.uuid4()}
status: experimental
description: >
  Phishing campaign detected by MailForensix - {name}.
  {profile.get('email_count', 0)} emails clustered from {len(ips)} relay IPs.
references:
  - https://github.com/Stark6612/MailForenSIX
author: MailForensix (Academic Threat Intelligence & Forensics Lab)
date: {datetime.now(timezone.utc).strftime('%Y/%m/%d')}
tags:
  - attack.initial_access
  - attack.t1566.002
  - attack.t1583.001
logsource:
  category: email
  product: mail_server
detection:
  selection_domain:
    from|contains:
      - {chr(10) + chr(32)*6 + (chr(10) + chr(32)*6).join(f"- '{d}'" for d in domains[:5]) if domains else "      - 'phishing.example.com'"}
  condition: selection_domain
falsepositives:
  - None expected for listed domains
level: high
"""


# ── Suricata ─────────────────────────────────────────────────────────────────────

def export_suricata(campaign: dict) -> str:
    profile = campaign.get("actor_profile", {})
    name    = campaign.get("name", "Unknown Campaign")
    ips     = list(profile.get("relay_ips", {}).keys())
    sid_base = abs(hash(name)) % 9000000 + 1000000

    lines = [f"# MailForensix - {name}",
             f"# Generated: {_now_ts()}",
             f"# Relay IPs: {len(ips)}", ""]
    for i, ip in enumerate(ips[:20]):
        lines.append(
            f'alert ip {ip} any -> $HOME_NET any '
            f'(msg:"MailForensix - Phishing Campaign Relay IP [{name}] {ip}"; '
            f'classtype:trojan-activity; sid:{sid_base + i}; rev:1;)'
        )
    return "\n".join(lines)


# ── Postfix header_checks ─────────────────────────────────────────────────────────

def export_postfix(campaign: dict) -> str:
    profile  = campaign.get("actor_profile", {})
    name     = campaign.get("name", "Unknown Campaign")
    domains  = list(profile.get("sender_domains", {}).keys())
    subjects = profile.get("subject_samples", [])

    lines = [
        f"# MailForensix Postfix header_checks - {name}",
        f"# Generated: {_now_ts()}",
        f"# Add to /etc/postfix/header_checks and run: postmap /etc/postfix/header_checks",
        "",
    ]
    for domain in domains[:10]:
        escaped = re.escape(domain)
        lines.append(f"/^From:.*{escaped}/ REJECT Phishing domain blocked by MailForensix [{name}]")
    for subject in subjects[:5]:
        escaped = re.escape(subject[:60])
        lines.append(f"/^Subject:.*{escaped}/ REJECT Phishing subject blocked by MailForensix")
    return "\n".join(lines)


# ── Exchange Transport Rule ────────────────────────────────────────────────────────

def export_exchange(campaign: dict) -> str:
    profile = campaign.get("actor_profile", {})
    name    = campaign.get("name", "Unknown Campaign")
    domains = list(profile.get("sender_domains", {}).keys())
    safe_name = re.sub(r"[^A-Za-z0-9_-]", "_", name)[:50]

    domain_list = ", ".join(f'"{d}"' for d in domains[:10])

    return f"""# MailForensix - Exchange Transport Rule
# Campaign: {name}
# Generated: {_now_ts()}
# Run in Exchange Management Shell (PowerShell):

$senderDomains = @({domain_list})

New-TransportRule -Name "MailForensix Block - {safe_name}" `
    -FromAddressContainsWords $senderDomains `
    -RejectMessageReasonText "Email blocked by MailForensix: {name}" `
    -RejectMessageEnhancedStatusCode "5.7.1" `
    -StopRuleProcessing $true `
    -Comments "Auto-generated by MailForensix campaign analysis. Campaign: {name}"

Write-Host "Transport rule created: MailForensix Block - {safe_name}"
"""


# ── DNSBL plain text ─────────────────────────────────────────────────────────────

def export_dnsbl(campaign: dict) -> str:
    profile = campaign.get("actor_profile", {})
    name    = campaign.get("name", "Unknown Campaign")
    ips     = list(profile.get("relay_ips", {}).keys())
    domains = list(profile.get("sender_domains", {}).keys())

    lines = [
        f"# MailForensix DNSBL Block List",
        f"# Campaign: {name}",
        f"# Generated: {_now_ts()}",
        f"# Compatible with Pi-hole, pfSense, Unbound",
        "",
        "# Relay IPs",
    ]
    lines.extend(ips)
    lines.append("")
    lines.append("# Sender Domains")
    lines.extend(domains)
    return "\n".join(lines)
