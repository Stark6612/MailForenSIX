"""
Phase 1 QA test — runs parser + auth engines against all .eml files in data/
Usage: python test_phase1.py
"""

import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engines.parser import parse_eml
from engines.auth import validate_auth
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"
EML_DIRS = [
    DATA_DIR / "20030228_spam" / "spam",
    DATA_DIR / "20030228_easy_ham" / "easy_ham",
]

results = []
for eml_dir in EML_DIRS:
    label = "SPAM" if "spam" in str(eml_dir) else "HAM"
    for eml_file in sorted(eml_dir.glob("*.eml"))[:5]:
        raw = eml_file.read_bytes()
        parsed = parse_eml(raw)
        auth = validate_auth(parsed)

        result = {
            "file":    eml_file.name,
            "label":   label,
            "subject": parsed.subject[:60] if parsed.subject else "—",
            "from":    parsed.from_[:60] if parsed.from_ else "—",
            "domain":  parsed.sender_domain or "—",
            "hops":    len(parsed.received_hops),
            "masked":  sum(1 for h in parsed.received_hops if h.masked),
            "urls":    len(parsed.urls),
            "attach":  parsed.has_attachments,
            "spoof":   parsed.display_name_mismatch,
            "spf":     auth.spf,
            "dkim":    auth.dkim,
            "dmarc":   auth.dmarc,
            "auth_src":auth.source,
            "align":   auth.alignment_ok,
            "details": auth.details[:80],
        }
        results.append(result)
        status = "OK" if (auth.spf != "none" or auth.dkim != "none") else "??"
        print(f"[{status}] {label} | {eml_file.name[:30]:<32} | "
              f"SPF:{auth.spf:<5} DKIM:{auth.dkim:<5} DMARC:{auth.dmarc:<5} "
              f"hops:{len(parsed.received_hops)} masked:{sum(1 for h in parsed.received_hops if h.masked)} "
              f"urls:{len(parsed.urls)} spoof:{parsed.display_name_mismatch}")

print(f"\n{'─'*80}")
print(f"Tested {len(results)} emails | "
      f"SPF pass: {sum(1 for r in results if r['spf']=='pass')} | "
      f"DKIM fail: {sum(1 for r in results if r['dkim']=='fail')} | "
      f"Spoofing: {sum(1 for r in results if r['spoof'])}")
print("Phase 1 QA complete.")
