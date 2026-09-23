"""
scripts/build_threat_intel_cache.py
-------------------------------------
Downloads URLhaus (Abuse.ch) and PhishTank threat intel feeds and
exports compact threat indicator files for air-gapped use.

Outputs:
    backend/data/urlhaus_urls.txt       -- malicious URLs (one per line)
    backend/data/urlhaus_domains.txt    -- extracted domains
    backend/data/phishtank_domains.txt  -- phishing domains from PhishTank

These files are loaded at startup by domain.py for air-gapped blacklist checks.
"""

import csv, json, re, sys
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError

BASE_DIR   = Path(__file__).resolve().parent.parent
DATA_DIR   = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

URLHAUS_CSV_URL   = "https://urlhaus.abuse.ch/downloads/csv_recent/"
PHISHTANK_URL     = "https://data.phishtank.com/data/online-valid.json"

_DOMAIN_RE = re.compile(r"https?://([^/:?#\s]+)")


def fetch_urlhaus():
    print("[URLhaus] Downloading recent malicious URL list...")
    try:
        req  = Request(URLHAUS_CSV_URL, headers={"User-Agent": "MailForensix/0.4 (SIH2026)"})
        resp = urlopen(req, timeout=30)
        raw  = resp.read().decode("utf-8", errors="replace")

        urls    = set()
        domains = set()
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) >= 3:
                url = parts[2].strip().strip('"')
                if url.startswith("http"):
                    urls.add(url)
                    m = _DOMAIN_RE.match(url)
                    if m:
                        domains.add(m.group(1).lower())

        url_path = DATA_DIR / "urlhaus_urls.txt"
        dom_path = DATA_DIR / "urlhaus_domains.txt"
        url_path.write_text("\n".join(sorted(urls)),    encoding="utf-8")
        dom_path.write_text("\n".join(sorted(domains)), encoding="utf-8")
        print(f"  -> {len(urls):,} URLs, {len(domains):,} domains saved")
        return len(domains)
    except Exception as e:
        print(f"  [WARN] URLhaus download failed: {e}")
        # Create empty files so domain.py can still load cleanly
        (DATA_DIR / "urlhaus_urls.txt").write_text("", encoding="utf-8")
        (DATA_DIR / "urlhaus_domains.txt").write_text("", encoding="utf-8")
        return 0


def fetch_phishtank():
    print("[PhishTank] Downloading verified phishing domains...")
    try:
        req  = Request(PHISHTANK_URL, headers={
            "User-Agent": "phishtank/MailForensix",
            "Accept":     "application/json",
        })
        resp = urlopen(req, timeout=60)
        data = json.loads(resp.read().decode("utf-8", errors="replace"))

        domains = set()
        for entry in data:
            url = entry.get("url", "")
            m   = _DOMAIN_RE.match(url)
            if m:
                domains.add(m.group(1).lower())

        dom_path = DATA_DIR / "phishtank_domains.txt"
        dom_path.write_text("\n".join(sorted(domains)), encoding="utf-8")
        print(f"  -> {len(domains):,} phishing domains saved")
        return len(domains)
    except Exception as e:
        print(f"  [WARN] PhishTank download failed: {e}")
        (DATA_DIR / "phishtank_domains.txt").write_text("", encoding="utf-8")
        return 0


def main():
    print("\n=== MailForensix - Building Threat Intel Cache ===\n")
    n_uh = fetch_urlhaus()
    n_pt = fetch_phishtank()
    print(f"\n[DONE] URLhaus: {n_uh} domains  |  PhishTank: {n_pt} domains")
    print("[INFO] Files written to backend/data/")
    print("       Load at startup via: engines/domain.py -> _load_blacklists()")
    print()


if __name__ == "__main__":
    main()
