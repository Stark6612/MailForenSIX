"""
api/routes/export.py — Phase 4
POST /api/v1/export/pdf   → generate forensic PDF from full analysis JSON
POST /api/v1/export/anchor → anchor SHA-256 to OpenTimestamps / local file
"""

import logging
from pydantic import BaseModel
from fastapi import APIRouter, HTTPException, Body
from fastapi.responses import Response

from models.schemas import AnalysisResponse
from engines.reporter import generate_dossier
from engines.anchor import anchor_hash, AnchorResult

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/export", tags=["export"])


# ── POST /export/pdf ──────────────────────────────────────────────────────────

@router.post(
    "/pdf",
    summary="Generate a forensic PDF dossier from a completed analysis",
    response_description="PDF file bytes",
    responses={
        200: {"content": {"application/pdf": {}}, "description": "PDF dossier"},
        422: {"description": "Invalid analysis payload"},
        500: {"description": "PDF generation failed"},
    },
)
async def export_pdf(payload: dict = Body(...)):
    """
    Accept a full AnalysisResponse JSON body and return a forensic PDF.
    The frontend POSTs the cached analysis result from the last /analyze call.
    """
    try:
        data = AnalysisResponse.model_validate(payload)
    except Exception as val_e:
        logger.warning(f"[export/pdf] Strict model_validate failed: {val_e}. Attempting tolerant construct.")
        try:
            data = AnalysisResponse.model_construct(**payload)
        except Exception:
            raise HTTPException(422, detail=f"Invalid analysis payload: {val_e}")

    try:
        pdf_bytes = generate_dossier(data)
    except Exception as e:
        logger.exception(f"[export/pdf] Unexpected error: {e}")
        raise HTTPException(500, detail=f"PDF generation failed: {e}")

    sha_raw = getattr(data.forensic, "email_sha256", "") if getattr(data, "forensic", None) else ""
    sha_slug = sha_raw[:12] if sha_raw else "report"
    filename = f"mailforensix_{sha_slug}.pdf"

    return Response(
        content     = pdf_bytes,
        media_type  = "application/pdf",
        headers     = {
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-SHA256":            sha_raw,
            "Access-Control-Expose-Headers": "Content-Disposition, X-SHA256",
        },
    )


# ── POST /export/anchor ───────────────────────────────────────────────────────

class AnchorRequestBody(BaseModel):
    sha256: str


class AnchorResponseBody(BaseModel):
    tx_id:   str
    status:  str
    backend: str
    ts:      str


@router.post(
    "/anchor",
    summary="Anchor a SHA-256 hash to OpenTimestamps (Bitcoin testnet)",
    response_model=AnchorResponseBody,
)
async def anchor_email_hash(body: AnchorRequestBody):
    """
    Submit the email's SHA-256 hash to OpenTimestamps for blockchain anchoring.
    Returns a tx_id (OTS receipt ID) or a local fallback reference.
    """
    result: AnchorResult = await anchor_hash(body.sha256)
    return AnchorResponseBody(
        tx_id   = result.tx_id,
        status  = result.status,
        backend = result.backend,
        ts      = result.ts,
    )
