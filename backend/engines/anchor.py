"""
engines/anchor.py — Phase 4
Lightweight SHA-256 hash anchor for forensic chain-of-custody.

Strategy:
  1. Try OpenTimestamps HTTP API (free, no key, Bitcoin testnet proof)
  2. Fallback: write a local .txt file with SHA-256 + timestamp
"""

from __future__ import annotations
import httpx
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

_OTS_CALENDAR  = "https://alice.btc.calendar.opentimestamps.org"
_OTS_SUBMIT    = "https://alice.btc.calendar.opentimestamps.org/digest"
_ANCHOR_DIR    = Path(__file__).parent.parent / "anchors"
_TIMEOUT       = 8.0   # seconds


@dataclass
class AnchorResult:
    tx_id:    str           # OTS receipt ID or local filename
    status:   str           # "anchored" | "pending" | "local"
    backend:  str           # "opentimestamps" | "local"
    ts:       str = ""      # ISO timestamp of anchor attempt
    raw:      bytes = field(default=b"", repr=False)  # raw OTS response bytes


async def anchor_hash(sha256_hex: str) -> AnchorResult:
    """
    Submit a SHA-256 digest to OpenTimestamps for Bitcoin blockchain anchoring.
    Falls back to a local .txt file on any error.

    Returns AnchorResult with tx_id, status, backend.
    """
    ts_now = datetime.now(timezone.utc).isoformat()

    # Validate
    sha256_hex = sha256_hex.strip().lower()
    if len(sha256_hex) != 64 or not all(c in "0123456789abcdef" for c in sha256_hex):
        return _local_fallback(sha256_hex, ts_now, reason="invalid sha256 hex")

    digest_bytes = bytes.fromhex(sha256_hex)

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            # POST raw digest bytes to OTS calendar
            resp = await client.post(
                _OTS_SUBMIT,
                content=digest_bytes,
                headers={"Content-Type": "application/octet-stream"},
            )

        if resp.status_code == 200:
            # OTS returns a binary .ots receipt
            ots_bytes = resp.content
            # Derive a human-readable tx_id: "ots:<first16hex>"
            tx_id = f"ots:{sha256_hex[:16]}"
            logger.info(f"[anchor] OTS receipt received for {sha256_hex[:16]}…")

            # Save the .ots file locally too (evidence artifact)
            _ensure_anchor_dir()
            ots_path = _ANCHOR_DIR / f"{sha256_hex[:16]}.ots"
            ots_path.write_bytes(ots_bytes)

            return AnchorResult(
                tx_id   = tx_id,
                status  = "pending",     # OTS is "pending" until Bitcoin confirms (~1hr)
                backend = "opentimestamps",
                ts      = ts_now,
                raw     = ots_bytes,
            )
        else:
            logger.warning(f"[anchor] OTS API returned {resp.status_code} — falling back to local")
            return _local_fallback(sha256_hex, ts_now, reason=f"OTS HTTP {resp.status_code}")

    except httpx.TimeoutException:
        logger.warning("[anchor] OTS API timed out — falling back to local")
        return _local_fallback(sha256_hex, ts_now, reason="OTS timeout")

    except Exception as exc:
        logger.warning(f"[anchor] OTS error: {exc} — falling back to local")
        return _local_fallback(sha256_hex, ts_now, reason=str(exc))


def _local_fallback(sha256_hex: str, ts: str, reason: str = "") -> AnchorResult:
    """Write a local anchor record file as fallback."""
    _ensure_anchor_dir()
    slug   = sha256_hex[:16] if len(sha256_hex) >= 16 else sha256_hex
    path   = _ANCHOR_DIR / f"{slug}.json"
    record = {
        "sha256":    sha256_hex,
        "timestamp": ts,
        "reason":    reason or "local",
        "tool":      "MailForenSIX v0.3.0",
    }
    try:
        path.write_text(json.dumps(record, indent=2), encoding="utf-8")
        logger.info(f"[anchor] Local anchor written: {path}")
    except Exception as e:
        logger.error(f"[anchor] Could not write local anchor file: {e}")

    return AnchorResult(
        tx_id   = f"local:{slug}",
        status  = "local",
        backend = "local",
        ts      = ts,
    )


def _ensure_anchor_dir():
    _ANCHOR_DIR.mkdir(parents=True, exist_ok=True)
