"""
api/routes/campaign.py
-----------------------
Mode 2 Campaign Intelligence API.

Endpoints:
    POST /campaign/analyze        — Batch .eml analysis + clustering
    GET  /campaign/{id}/results   — Get cluster results
    GET  /campaign/{id}/export/{format}  — Export: stix|sigma|suricata|postfix|exchange|dnsbl
    POST /campaign/{id}/adjust    — Manual cluster merge/split
"""

import asyncio
import json
import uuid
import zipfile
import io
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List

from fastapi import APIRouter, UploadFile, File, Form, HTTPException, BackgroundTasks
from fastapi.responses import PlainTextResponse, JSONResponse

router = APIRouter(prefix="/campaign", tags=["campaign"])

# In-memory campaign store (replace with SQLite in production)
_campaigns: dict = {}

ALLOWED_FORMATS = {"stix", "sigma", "suricata", "postfix", "exchange", "dnsbl"}
MAX_EML_BYTES = 10 * 1024 * 1024   # 10 MB per file
MAX_FILES     = 200


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _process_campaign(campaign_id: str, raw_emails: list[bytes]):
    """Background task: parse, embed, cluster, profile campaign emails."""
    import numpy as np
    from engines.parser        import parse_eml
    from engines.embedder      import embed_texts
    from engines.distance      import compute_distance_matrix
    from engines.clusterer     import cluster_emails
    from engines.actor_profile import build_actor_profile
    from engines.geo           import resolve_geo_batch
    from engines.auth          import validate_auth

    _campaigns[campaign_id]["status"] = "processing"

    try:
        # 1. Parse all emails
        parsed_list = []
        for raw in raw_emails:
            try:
                parsed_list.append(parse_eml(raw))
            except Exception:
                parsed_list.append(None)

        valid = [(i, p) for i, p in enumerate(parsed_list) if p is not None]
        if not valid:
            _campaigns[campaign_id]["status"] = "error"
            _campaigns[campaign_id]["error"]  = "No valid emails parsed"
            return

        indices, parseds = zip(*valid)

        # 2. Embed texts
        texts = []
        for p in parseds:
            body = (getattr(p, "body_text", "") or "") + " " + (getattr(p, "subject", "") or "")
            texts.append(body.strip()[:512])

        embeddings = await asyncio.get_event_loop().run_in_executor(None, embed_texts, texts)

        # 3. Geo IP resolution & extract infrastructure feature sets
        all_unique_ips = list({
            h.ip for p in parseds
            for h in getattr(p, "received_hops", [])
            if getattr(h, "ip", None) and getattr(h, "ip", "") != "[redacted]"
        })

        geo_map = {}
        if all_unique_ips:
            try:
                geo_results = await resolve_geo_batch(all_unique_ips)
                geo_map = {g.ip: g for g in geo_results}
            except Exception as geo_err:
                pass

        email_hops_list = []
        ip_sets = []
        asn_sets = []
        domain_sets = []
        auth_list = []

        for p in parseds:
            e_hops = []
            ip_set = set()
            asn_set = set()

            for h in getattr(p, "received_hops", []):
                ip = getattr(h, "ip", "")
                if ip and ip != "[redacted]":
                    ip_set.add(ip)
                geo = geo_map.get(ip)
                country = geo.country if geo and geo.country else None
                city    = geo.city    if geo and geo.city    else None
                asn     = geo.asn     if geo and geo.asn     else getattr(p, "x_campaign_asn", None)
                isp     = geo.isp     if geo and geo.isp     else getattr(p, "x_campaign_isp", None)

                if asn:
                    asn_set.add(asn)

                e_hops.append({
                    "ip":       ip,
                    "hostname": getattr(h, "hostname", None),
                    "country":  country,
                    "city":     city,
                    "asn":      asn,
                    "isp":      isp,
                })

            email_hops_list.append(e_hops)
            ip_sets.append(ip_set)
            asn_sets.append(asn_set)
            domain_sets.append({getattr(p, "sender_domain", "")} - {"", None})

            try:
                auth_res = validate_auth(p, air_gapped=True)
            except Exception:
                auth_res = None
            auth_list.append(auth_res)

        # 4. Compute distance matrix
        loop = asyncio.get_event_loop()
        dist_matrix = await loop.run_in_executor(
            None,
            lambda: compute_distance_matrix(embeddings, ip_sets, asn_sets, domain_sets)
        )

        # 5. Cluster
        cluster_result = await loop.run_in_executor(
            None, lambda: cluster_emails(dist_matrix, min_cluster_size=3)
        )

        # 6. Build actor profiles per cluster
        cluster_ids = sorted(set(l for l in cluster_result.labels if l >= 0))
        clusters = []

        for cid in cluster_ids:
            cluster_indices = [i for i, l in enumerate(cluster_result.labels) if l == cid]
            cluster_items = [
                {
                    "parsed": parseds[i],
                    "relay_hops": email_hops_list[i],
                    "domain_intel": None,
                    "auth": auth_list[i],
                    "intent_label": "phishing"
                }
                for i in cluster_indices
            ]
            profile = build_actor_profile(cluster_items)

            top_domains = list((profile.get("sender_domains") or {}).keys())
            cluster_name = f"Campaign-{cid + 1} ({top_domains[0]})" if top_domains else f"Campaign-{cid + 1}"

            clusters.append({
                "cluster_id":    cid,
                "email_indices": cluster_indices,
                "email_count":   len(cluster_indices),
                "actor_profile": profile,
                "name":          cluster_name,
                "tlp":           "amber",
            })

        noise_indices = [i for i, l in enumerate(cluster_result.labels) if l == -1]

        _campaigns[campaign_id].update({
            "status":         "complete",
            "n_emails":       len(parseds),
            "n_clusters":     cluster_result.n_clusters,
            "n_noise":        cluster_result.n_noise,
            "algorithm":      cluster_result.algorithm,
            "labels":         cluster_result.labels,
            "clusters":       clusters,
            "noise_indices":  noise_indices,
            "umap_embedding": (
                cluster_result.umap_embedding.tolist()
                if cluster_result.umap_embedding is not None else None
            ),
            "completed_at":   _now(),
        })

    except Exception as e:
        _campaigns[campaign_id]["status"] = "error"
        _campaigns[campaign_id]["error"]  = str(e)
        import traceback
        _campaigns[campaign_id]["traceback"] = traceback.format_exc()


@router.post("/analyze")
async def campaign_analyze(
    background_tasks: BackgroundTasks,
    eml_files: Optional[List[UploadFile]] = File(default=None),
    zip_file:  Optional[UploadFile]       = File(default=None),
):
    """
    Upload multiple .eml files or a .zip archive of .eml files.
    Returns campaign_id immediately; processing runs in background.
    Poll GET /campaign/{campaign_id}/results for status.
    """
    raw_emails = []

    if zip_file:
        zip_bytes = await zip_file.read()
        try:
            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
                for name in zf.namelist():
                    if name.lower().endswith(".eml") and len(raw_emails) < MAX_FILES:
                        raw_emails.append(zf.read(name))
        except zipfile.BadZipFile:
            raise HTTPException(400, "Uploaded file is not a valid ZIP archive.")

    if eml_files:
        for f in eml_files[:MAX_FILES]:
            raw = await f.read()
            if len(raw) <= MAX_EML_BYTES:
                raw_emails.append(raw)

    if not raw_emails:
        raise HTTPException(400, "No .eml files provided. Upload a zip or individual .eml files.")

    campaign_id = str(uuid.uuid4())
    _campaigns[campaign_id] = {
        "campaign_id":  campaign_id,
        "status":       "queued",
        "submitted_at": _now(),
        "n_files":      len(raw_emails),
    }

    background_tasks.add_task(_process_campaign, campaign_id, raw_emails)

    return {"campaign_id": campaign_id, "status": "queued", "n_files": len(raw_emails),
            "message": f"Processing {len(raw_emails)} emails. Poll /campaign/{campaign_id}/results."}


@router.get("/{campaign_id}/results")
async def campaign_results(campaign_id: str):
    """Get campaign analysis results."""
    if campaign_id not in _campaigns:
        raise HTTPException(404, f"Campaign {campaign_id} not found.")
    camp = _campaigns[campaign_id].copy()
    # Remove heavy umap embedding from default results response
    camp.pop("umap_embedding", None)
    return camp


@router.get("/{campaign_id}/export/{format}")
async def campaign_export(campaign_id: str, format: str, tlp: str = "amber"):
    """Export campaign results in the specified format."""
    if campaign_id not in _campaigns:
        raise HTTPException(404, f"Campaign {campaign_id} not found.")

    camp = _campaigns[campaign_id]
    if camp.get("status") != "complete":
        raise HTTPException(400, f"Campaign not complete yet. Status: {camp.get('status')}")

    fmt = format.lower()
    if fmt not in ALLOWED_FORMATS:
        raise HTTPException(400, f"Format must be one of: {', '.join(ALLOWED_FORMATS)}")

    from engines.exporter import (
        export_stix, export_sigma, export_suricata,
        export_postfix, export_exchange, export_dnsbl,
    )

    # Build combined campaign dict for exporter
    all_relay_ips    = {}
    all_sender_domains = {}
    all_techniques   = []
    all_subjects     = []

    for cluster in camp.get("clusters", []):
        profile = cluster.get("actor_profile", {})
        all_relay_ips.update(profile.get("relay_ips", {}))
        all_sender_domains.update(profile.get("sender_domains", {}))
        all_techniques.extend(profile.get("mitre_techniques", []))
        all_subjects.extend(profile.get("subject_samples", []))

    campaign_obj = {
        "campaign_id": campaign_id,
        "name":        f"MailForensix Campaign — {camp.get('n_clusters', 0)} clusters",
        "actor_profile": {
            "email_count":     camp.get("n_emails", 0),
            "relay_ips":       all_relay_ips,
            "sender_domains":  all_sender_domains,
            "mitre_techniques": list({t["id"]: t for t in all_techniques}.values()),
            "subject_samples": all_subjects[:5],
            "top_asns":        {},
            "top_countries":   {},
        },
    }

    if fmt == "stix":
        content = export_stix(campaign_obj, tlp=tlp)
        return PlainTextResponse(content, media_type="application/json",
                                  headers={"Content-Disposition": f'attachment; filename="campaign_{campaign_id[:8]}_stix.json"'})
    elif fmt == "sigma":
        content = export_sigma(campaign_obj)
        return PlainTextResponse(content, media_type="text/yaml",
                                  headers={"Content-Disposition": f'attachment; filename="campaign_{campaign_id[:8]}.yml"'})
    elif fmt == "suricata":
        content = export_suricata(campaign_obj)
        return PlainTextResponse(content, media_type="text/plain",
                                  headers={"Content-Disposition": f'attachment; filename="campaign_{campaign_id[:8]}.rules"'})
    elif fmt == "postfix":
        content = export_postfix(campaign_obj)
        return PlainTextResponse(content, media_type="text/plain",
                                  headers={"Content-Disposition": f'attachment; filename="campaign_{campaign_id[:8]}_header_checks.txt"'})
    elif fmt == "exchange":
        content = export_exchange(campaign_obj)
        return PlainTextResponse(content, media_type="text/plain",
                                  headers={"Content-Disposition": f'attachment; filename="campaign_{campaign_id[:8]}_exchange.ps1"'})
    elif fmt == "dnsbl":
        content = export_dnsbl(campaign_obj)
        return PlainTextResponse(content, media_type="text/plain",
                                  headers={"Content-Disposition": f'attachment; filename="campaign_{campaign_id[:8]}_dnsbl.txt"'})


@router.post("/{campaign_id}/adjust")
async def campaign_adjust(
    campaign_id: str,
    action:      str = Form(...),    # "merge" | "split"
    cluster_ids: str = Form(...),    # comma-separated cluster IDs
    reason:      str = Form(default=""),
    analyst_id:  str = Form(default="anonymous"),
):
    """Manual cluster merge/split with audit logging."""
    if campaign_id not in _campaigns:
        raise HTTPException(404, f"Campaign {campaign_id} not found.")

    camp = _campaigns[campaign_id]
    if camp.get("status") != "complete":
        raise HTTPException(400, "Campaign must be complete before adjustments.")

    log_entry = {
        "action":      action,
        "cluster_ids": cluster_ids,
        "reason":      reason,
        "analyst_id":  analyst_id,
        "timestamp":   _now(),
    }
    camp.setdefault("adjustments", []).append(log_entry)

    # Simple merge: relabel all selected cluster emails to first cluster_id
    ids = [int(x.strip()) for x in cluster_ids.split(",") if x.strip().isdigit()]
    if action == "merge" and len(ids) >= 2:
        target_cid = ids[0]
        for cluster in camp["clusters"]:
            if cluster["cluster_id"] in ids[1:]:
                # Move emails to target cluster
                target = next((c for c in camp["clusters"] if c["cluster_id"] == target_cid), None)
                if target:
                    target["email_indices"].extend(cluster["email_indices"])
                    target["email_count"] = len(target["email_indices"])
                    cluster["email_indices"] = []
                    cluster["email_count"] = 0
        camp["clusters"] = [c for c in camp["clusters"] if c["email_count"] > 0]
        camp["n_clusters"] = len(camp["clusters"])

    return {"campaign_id": campaign_id, "adjustment_logged": log_entry, "n_clusters": camp.get("n_clusters")}
