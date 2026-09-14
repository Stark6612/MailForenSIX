"""
engines/geo.py — Phase 2
IP geolocation engine with three-tier resolution:
  1. SQLite cache (instant — avoids repeat API calls)
  2. ip-api.com batch API (free, no key, 45 req/min)
  3. MaxMind GeoLite2 offline fallback (air-gapped mode)

Public API:
    resolve_geo_batch(ips: list[str]) → list[GeoResult]
    resolve_geo(ip: str)              → GeoResult
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# ── MaxMind path (optional — only needed for air-gapped mode) ──────────────────
_MMDB_PATHS = [
    Path(__file__).parent.parent / "models" / "GeoLite2-City.mmdb",
    Path(__file__).parent.parent / "data"   / "GeoLite2-City.mmdb",
]

# ── SQLite cache path ──────────────────────────────────────────────────────────
_DB_PATH = Path(__file__).parent.parent / "mailforensix.db"

# ── ip-api.com batch endpoint ──────────────────────────────────────────────────
_IPAPI_BATCH_URL = "http://ip-api.com/batch"
_IPAPI_FIELDS    = "status,country,countryCode,city,lat,lon,isp,as,proxy,hosting,query"

# ── Private / reserved IP ranges to skip ──────────────────────────────────────
import re as _re
_PRIVATE_RE = _re.compile(
    r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1|localhost|0\.0\.0\.0)"
)


@dataclass
class GeoResult:
    ip:      str
    lat:     Optional[float] = None
    lon:     Optional[float] = None
    country: Optional[str]   = None
    city:    Optional[str]   = None
    asn:     Optional[str]   = None
    isp:     Optional[str]   = None
    vpn:     bool            = False
    mode:    str             = "none"   # "online" | "offline" | "cached" | "none"


# ── SQLite cache helpers ───────────────────────────────────────────────────────

def _ensure_cache_table():
    con = sqlite3.connect(_DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS geo_cache (
            ip      TEXT PRIMARY KEY,
            lat     REAL,
            lon     REAL,
            country TEXT,
            city    TEXT,
            asn     TEXT,
            isp     TEXT,
            vpn     INTEGER DEFAULT 0
        )
    """)
    con.commit()
    con.close()


def _cache_get(ips: list[str]) -> dict[str, GeoResult]:
    """Return cached GeoResult objects for any IPs already in the DB."""
    if not ips:
        return {}
    try:
        _ensure_cache_table()
        placeholders = ",".join("?" * len(ips))
        con = sqlite3.connect(_DB_PATH)
        rows = con.execute(
            f"SELECT ip,lat,lon,country,city,asn,isp,vpn FROM geo_cache WHERE ip IN ({placeholders})",
            ips
        ).fetchall()
        con.close()
        return {
            row[0]: GeoResult(
                ip=row[0], lat=row[1], lon=row[2],
                country=row[3], city=row[4], asn=row[5], isp=row[6],
                vpn=bool(row[7]), mode="cached"
            )
            for row in rows
        }
    except Exception as e:
        logger.warning(f"[geo] Cache read error: {e}")
        return {}


def _cache_put(results: list[GeoResult]):
    """Store GeoResult objects in the SQLite cache."""
    try:
        _ensure_cache_table()
        con = sqlite3.connect(_DB_PATH)
        con.executemany(
            "INSERT OR REPLACE INTO geo_cache VALUES (?,?,?,?,?,?,?,?)",
            [(r.ip, r.lat, r.lon, r.country, r.city, r.asn, r.isp, int(r.vpn))
             for r in results if r.mode != "none"],
        )
        con.commit()
        con.close()
    except Exception as e:
        logger.warning(f"[geo] Cache write error: {e}")


# ── ip-api.com online lookup ───────────────────────────────────────────────────

async def _ipapi_batch(ips: list[str]) -> list[GeoResult]:
    """
    Call ip-api.com/batch (max 100 IPs per call).
    Returns GeoResult per IP in same order as input.
    """
    results = []
    payload = [{"query": ip, "fields": _IPAPI_FIELDS} for ip in ips]

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(_IPAPI_BATCH_URL, json=payload)
            resp.raise_for_status()
            data = resp.json()

        for item in data:
            ip = item.get("query", "")
            if item.get("status") == "success":
                results.append(GeoResult(
                    ip      = ip,
                    lat     = item.get("lat"),
                    lon     = item.get("lon"),
                    country = item.get("country"),
                    city    = item.get("city"),
                    asn     = item.get("as"),
                    isp     = item.get("isp"),
                    vpn     = bool(item.get("proxy") or item.get("hosting")),
                    mode    = "online",
                ))
            else:
                results.append(GeoResult(ip=ip, mode="none"))

    except Exception as e:
        logger.warning(f"[geo] ip-api.com batch failed: {e}")
        results = [GeoResult(ip=ip, mode="none") for ip in ips]

    return results


# ── MaxMind offline fallback ───────────────────────────────────────────────────

def _maxmind_lookup(ip: str) -> GeoResult:
    """Attempt MaxMind GeoLite2-City lookup. Returns mode='none' if .mmdb absent."""
    mmdb_path = next((p for p in _MMDB_PATHS if p.exists()), None)
    if not mmdb_path:
        return GeoResult(ip=ip, mode="none")

    try:
        import geoip2.database
        with geoip2.database.Reader(str(mmdb_path)) as reader:
            record = reader.city(ip)
            return GeoResult(
                ip      = ip,
                lat     = record.location.latitude,
                lon     = record.location.longitude,
                country = record.country.name,
                city    = record.city.name,
                asn     = None,
                isp     = None,
                vpn     = False,
                mode    = "offline",
            )
    except Exception:
        return GeoResult(ip=ip, mode="none")


# ── Public API ─────────────────────────────────────────────────────────────────

async def resolve_geo_batch(
    ips: list[str],
    air_gapped: bool = False,
) -> list[GeoResult]:
    """
    Resolve geolocation for a list of IPs.
    Strategy: cache → online (ip-api.com) OR offline (MaxMind) → null
    """
    if not ips:
        return []

    # Filter out private/loopback IPs
    valid_ips    = [ip for ip in ips if ip and not _PRIVATE_RE.match(ip)]
    skipped      = {ip: GeoResult(ip=ip, mode="none") for ip in ips if ip not in valid_ips}

    # Cache lookup
    cached       = _cache_get(valid_ips)
    uncached_ips = [ip for ip in valid_ips if ip not in cached]

    fetched: list[GeoResult] = []

    if uncached_ips:
        if air_gapped:
            # Air-gapped: MaxMind only — no external calls
            loop    = asyncio.get_event_loop()
            fetched = await asyncio.gather(
                *[loop.run_in_executor(None, _maxmind_lookup, ip) for ip in uncached_ips]
            )
        else:
            # Online: try ip-api.com batch first
            chunks = [uncached_ips[i:i+100] for i in range(0, len(uncached_ips), 100)]
            for chunk in chunks:
                fetched.extend(await _ipapi_batch(chunk))

            # ── Automatic MaxMind fallback ────────────────────────────────────────
            # If ip-api.com failed (offline, rate-limited, timeout), fall back to
            # MaxMind GeoLite2 for any IPs that still have mode="none".
            # This ensures geo data appears even without internet connectivity.
            unresolved = [r.ip for r in fetched if r.mode == "none"]
            if unresolved:
                mmdb_exists = any(p.exists() for p in _MMDB_PATHS)
                if mmdb_exists:
                    logger.info(
                        f"[geo] ip-api.com returned no data for {len(unresolved)} IPs "
                        f"— falling back to MaxMind offline for these"
                    )
                    loop = asyncio.get_event_loop()
                    mmdb_results = await asyncio.gather(
                        *[loop.run_in_executor(None, _maxmind_lookup, ip) for ip in unresolved]
                    )
                    # Merge: replace mode="none" entries with MaxMind results
                    mmdb_map = {r.ip: r for r in mmdb_results if r.mode != "none"}
                    fetched  = [mmdb_map.get(r.ip, r) for r in fetched]

        # Write new results to cache
        to_cache = [r for r in fetched if r.mode != "none"]
        if to_cache:
            _cache_put(to_cache)

    # Merge all results in original IP order
    all_results = {**skipped, **cached, **{r.ip: r for r in fetched}}
    return [all_results.get(ip, GeoResult(ip=ip, mode="none")) for ip in ips]


async def resolve_geo(ip: str, air_gapped: bool = False) -> GeoResult:
    """Convenience wrapper for a single IP."""
    results = await resolve_geo_batch([ip], air_gapped=air_gapped)
    return results[0] if results else GeoResult(ip=ip, mode="none")
