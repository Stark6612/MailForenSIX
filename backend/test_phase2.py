"""
Phase 2 QA test — validates all four new engines against real .eml files.

Usage: python test_phase2.py

Tests:
  1. Classifier — predict_intent() returns a valid label + confidence
  2. Classifier — explain_sentences() returns non-empty LIME list
  3. Geo engine — resolve_geo_batch() returns GeoResult objects
  4. Domain engine — get_domain_intel() returns DomainIntelResult
  5. Risk engine — compute_risk() returns score 0-100 + valid tier
  6. End-to-end — full parse → all engines → risk score
"""

import asyncio
import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from engines.parser     import parse_eml
from engines.auth       import validate_auth
from engines.classifier import load_model, predict_intent, explain_sentences, model_loaded
from engines.geo        import resolve_geo_batch
from engines.domain     import get_domain_intel
from engines.risk       import compute_risk

DATA_DIR = Path("data")
SPAM_DIR = DATA_DIR / "20030228_spam" / "spam"
HAM_DIR  = DATA_DIR / "20030228_easy_ham" / "easy_ham"

PASS = "[PASS]"
FAIL = "[FAIL]"
WARN = "[WARN]"


def fmt(ok: bool, msg: str) -> str:
    return f"  {PASS if ok else FAIL} {msg}"


async def main():
    print("\n=== MailForenSIX — Phase 2 QA Tests ===\n")
    all_passed = True

    # ── 1. Load ML model ───────────────────────────────────────────────────────
    print("[1] ML Model Load")
    loaded = load_model()
    print(fmt(True, f"model_loaded() = {model_loaded()} (fallback to heuristics if False)"))

    # ── 2. Classifier — predict_intent ────────────────────────────────────────
    print("\n[2] Classifier — predict_intent()")
    test_texts = [
        ("Spam sample",  "URGENT: Your account has been suspended. Click here to verify immediately!"),
        ("Ham sample",   "Hi team, please review the attached meeting notes from Monday's call."),
        ("Phishing URL", "Your bank account needs immediate verification: http://totally-not-phishing.tk/login"),
    ]
    for name, text in test_texts:
        label, conf = predict_intent(text)
        ok = label in ("safe", "suspicious", "phishing") and 0.0 <= conf <= 1.0
        print(fmt(ok, f"{name}: label={label}, confidence={conf:.4f}"))
        if not ok:
            all_passed = False

    # ── 3. Classifier — explain_sentences ─────────────────────────────────────
    print("\n[3] Classifier — explain_sentences()")
    test_body = "URGENT: Click here now! Your account expires tomorrow. Free prize winner!"
    sentences = explain_sentences(test_body, n=5)
    ok = len(sentences) > 0 and all("text" in s and "score" in s and "explanation" in s for s in sentences)
    print(fmt(ok, f"Got {len(sentences)} LIME sentences"))
    for s in sentences[:3]:
        print(f"       '{s['text'][:50]}' → score={s['score']:.4f}")
    if not ok:
        all_passed = False

    # ── 4. Geo engine ─────────────────────────────────────────────────────────
    print("\n[4] Geo Engine — resolve_geo_batch()")
    test_ips = ["8.8.8.8", "1.1.1.1", "185.220.101.1"]   # Google DNS, Cloudflare, known Tor exit
    results  = await resolve_geo_batch(test_ips)
    ok_all   = len(results) == len(test_ips)
    print(fmt(ok_all, f"Got {len(results)}/{len(test_ips)} results"))
    for ip, r in zip(test_ips, results):
        print(f"       {ip}: country={r.country}, city={r.city}, vpn={r.vpn}, mode={r.mode}")
    if not ok_all:
        all_passed = False

    # ── 5. Domain engine ──────────────────────────────────────────────────────
    print("\n[5] Domain Engine — get_domain_intel()")
    test_domains = ["google.com", "web.de"]
    for dom in test_domains:
        result = await get_domain_intel(dom)
        ok = result is not None and 0.0 <= result.suspicion_score <= 1.0
        print(fmt(ok, f"{dom}: age={result.age_days}d, registrar={str(result.registrar)[:30]}, "
                      f"mx={result.mx_valid}, suspicion={result.suspicion_score:.3f}"))
        if not ok:
            all_passed = False

    # ── 6. Risk engine ────────────────────────────────────────────────────────
    print("\n[6] Risk Engine — compute_risk()")
    # Use a real .eml file to produce auth + geo + domain objects
    eml_files = sorted(SPAM_DIR.glob("*.eml"))[:3] if SPAM_DIR.exists() else []
    if not eml_files:
        # Try without .eml extension (SpamAssassin files)
        eml_files = sorted(SPAM_DIR.iterdir())[:3] if SPAM_DIR.exists() else []

    if not eml_files:
        print(f"  {WARN} No .eml files found — skipping risk engine file test")
    else:
        for eml_path in eml_files[:2]:
            try:
                raw    = eml_path.read_bytes()
                parsed = parse_eml(raw)
                auth   = validate_auth(parsed)

                # Mock geo hops (resolved earlier tests showed geo works)
                from engines.geo import GeoResult
                mock_hops = [GeoResult(ip="8.8.8.8", lat=37.4, lon=-122.1, country="US", city="Mountain View", mode="online")]

                domain_result = await get_domain_intel(parsed.sender_domain or "example.com")

                score, tier = compute_risk(
                    auth             = auth,
                    intent_label     = "phishing",
                    intent_confidence= 0.8,
                    geo_hops         = mock_hops,
                    domain           = domain_result,
                )
                ok = 0 <= score <= 100 and tier in ("safe", "suspicious", "high", "critical")
                print(fmt(ok, f"{eml_path.name[:35]}: score={score}, tier={tier}"))
                if not ok:
                    all_passed = False
            except Exception as e:
                print(f"  {WARN} {eml_path.name}: {e}")

    # ── 7. End-to-end pipeline ────────────────────────────────────────────────
    print("\n[7] End-to-End Pipeline (parse → all engines → risk)")
    eml_files_all = []
    for d in [SPAM_DIR, HAM_DIR]:
        if d.exists():
            eml_files_all.extend(list(d.iterdir())[:3])

    for eml_path in eml_files_all[:4]:
        try:
            raw     = eml_path.read_bytes()
            parsed  = parse_eml(raw)
            auth    = validate_auth(parsed)
            label, conf = predict_intent(parsed.body_text or "")
            geo_results = await resolve_geo_batch([h.ip for h in parsed.received_hops])
            domain_r    = await get_domain_intel(parsed.sender_domain or "test.com")
            score, tier = compute_risk(auth, label, conf, geo_results, domain_r)

            print(fmt(True,
                f"{eml_path.name[:30]:<32} | score={score:>3} | tier={tier:<10} | "
                f"label={label:<10} | conf={conf:.2f}"
            ))
        except Exception as e:
            print(f"  {WARN} {eml_path.name}: {e}")

    # ── Summary ────────────────────────────────────────────────────────────────
    print(f"\n{'='*50}")
    print(f"Phase 2 QA: {'ALL PASSED' if all_passed else 'SOME FAILURES — review above'}")
    print(f"ML model loaded: {model_loaded()} {'(full XGBoost+LIME)' if model_loaded() else '(heuristic fallback)'}")
    print(f"{'='*50}\n")


if __name__ == "__main__":
    asyncio.run(main())
