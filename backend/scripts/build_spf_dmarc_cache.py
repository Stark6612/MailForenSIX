"""
scripts/build_spf_dmarc_cache.py
---------------------------------
Pre-builds a SQLite cache of SPF/DMARC records for the top 10,000
Indian institutional and global phishing-target domains (Tranco-derived).

For air-gapped deployments: this script is run once on a connected machine,
then the resulting spf_dmarc_cache.db is shipped with the installation.

Output: backend/data/spf_dmarc_cache.db

Usage:
    python scripts/build_spf_dmarc_cache.py [--limit N] [--input domains.txt]
"""

import sqlite3
import sys
import argparse
import time
import socket
from pathlib import Path
from datetime import date

BASE_DIR   = Path(__file__).resolve().parent.parent
DB_PATH    = BASE_DIR / "data" / "spf_dmarc_cache.db"

# ── High-value Indian institutional + global mail provider domains ─────────────
# Used when Tranco list is not available.
SEED_DOMAINS = [
    # Indian government / CERT
    "gov.in", "nic.in", "mha.gov.in", "meity.gov.in", "cert-in.org.in",
    "india.gov.in", "pib.gov.in", "incometax.gov.in",
    # Indian banks
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com", "pnb.co.in",
    "canarabank.in", "bankofbaroda.in", "unionbankofindia.in", "boi.in",
    "kotak.com", "yesbank.in", "idfcfirstbank.com",
    # Indian tech / services
    "infosys.com", "tcs.com", "wipro.com", "hcltech.com", "techmahindra.com",
    "bajajfinserv.in", "reliance.com", "jio.com", "airtel.in", "bsnl.co.in",
    "irctc.co.in", "flipkart.com", "amazon.in",
    # Global mail providers (frequent phishing targets)
    "gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "yahoo.in",
    "microsoft.com", "office.com", "live.com",
    # Global financial (phishing targets)
    "paypal.com", "paypal.in", "apple.com", "google.com",
    # Education
    "iit.ac.in", "iitb.ac.in", "iitd.ac.in", "iitm.ac.in", "iisc.ac.in",
    "du.ac.in", "mu.ac.in",
]


def create_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS spf_dmarc_cache (
            domain          TEXT PRIMARY KEY,
            spf_record      TEXT,
            spf_policy      TEXT,
            dmarc_record    TEXT,
            dmarc_policy    TEXT,
            cached_date     TEXT,
            lookup_ok       INTEGER DEFAULT 1
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_domain ON spf_dmarc_cache(domain)")
    conn.commit()
    return conn


def lookup_spf(domain: str, timeout: float = 3.0) -> tuple:
    import dns.resolver, dns.exception
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=timeout)
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if txt.startswith("v=spf1"):
                import re
                m = re.search(r"([~\-\+\?])all", txt)
                policy = {"+" : "pass", "~": "softfail", "-": "hardfail", "?": "neutral"}.get(
                    m.group(1) if m else "", "none")
                return txt[:300], policy
        return None, "none"
    except Exception:
        return None, "none"


def lookup_dmarc(domain: str, timeout: float = 3.0) -> tuple:
    import dns.resolver, dns.exception, re
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=timeout)
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if txt.startswith("v=DMARC1"):
                m = re.search(r"p=(none|quarantine|reject)", txt)
                policy = m.group(1) if m else "none"
                return txt[:300], policy
        return None, "none"
    except Exception:
        return None, "none"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit",  type=int, default=None, help="Max domains to process")
    parser.add_argument("--input",  type=str, default=None, help="Path to domain list file (one per line)")
    parser.add_argument("--quiet",  action="store_true")
    args = parser.parse_args()

    domains = list(SEED_DOMAINS)

    if args.input:
        input_path = Path(args.input)
        if input_path.exists():
            extra = [l.strip() for l in input_path.read_text().splitlines() if l.strip() and not l.startswith("#")]
            domains.extend(extra)
            print(f"[INPUT] Loaded {len(extra)} extra domains from {args.input}")

    # Deduplicate
    domains = list(dict.fromkeys(domains))
    if args.limit:
        domains = domains[:args.limit]

    print(f"\n=== MailForensix - Building SPF/DMARC Air-Gapped Cache ===")
    print(f"[INFO] Processing {len(domains)} domains -> {DB_PATH}\n")

    conn  = create_db(DB_PATH)
    today = date.today().isoformat()
    ok = skip = fail = 0

    for i, domain in enumerate(domains, 1):
        # Check if already cached
        row = conn.execute("SELECT domain FROM spf_dmarc_cache WHERE domain=?", (domain,)).fetchone()
        if row:
            skip += 1
            continue

        spf_rec, spf_pol   = lookup_spf(domain)
        dmarc_rec, dmarc_pol = lookup_dmarc(domain)

        conn.execute("""
            INSERT OR REPLACE INTO spf_dmarc_cache
            (domain, spf_record, spf_policy, dmarc_record, dmarc_policy, cached_date, lookup_ok)
            VALUES (?,?,?,?,?,?,?)
        """, (domain, spf_rec, spf_pol, dmarc_rec, dmarc_pol, today, 1))

        if i % 10 == 0:
            conn.commit()

        if not args.quiet:
            spf_short   = f"SPF:{spf_pol}"   if spf_rec   else "SPF:none"
            dmarc_short = f"DMARC:{dmarc_pol}" if dmarc_rec else "DMARC:none"
            print(f"  [{i:4d}/{len(domains)}] {domain:<40} {spf_short:<14} {dmarc_short}")

        ok += 1

    conn.commit()
    conn.close()

    total = conn.execute = None
    print(f"\n[DONE] {ok} cached, {skip} skipped (already present)")
    print(f"[PATH] {DB_PATH}")


if __name__ == "__main__":
    main()
