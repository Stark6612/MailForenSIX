"""Live API test — hits the running FastAPI server with a real .eml file."""
import httpx, pathlib, json

eml_path = pathlib.Path("data/20030228_spam/spam/00001.7848dde101aa985090474a91ec93fcf0.eml")
eml_bytes = eml_path.read_bytes()

r = httpx.post(
    "http://localhost:8000/api/v1/analyze",
    files={"eml_file": ("test.eml", eml_bytes, "message/rfc822")},
    timeout=30,
)

d = r.json()
print(f"HTTP Status    : {r.status_code}")
print(f"Risk Score     : {d['risk_score']} / 100  |  Tier: {d['risk_tier'].upper()}")
print(f"Threat Label   : {d['threat_label'].upper()}  |  Confidence: {d['confidence']*100:.0f}%")
print(f"Subject        : {d['subject']}")
print(f"Sender         : {d['sender']}")
print(f"SPF            : {d['auth']['spf'].upper()}")
print(f"DKIM           : {d['auth']['dkim'].upper()}")
print(f"DMARC          : {d['auth']['dmarc'].upper()}")
print(f"Auth Details   : {d['auth']['details']}")
print(f"Relay Hops     : {len(d['relay_hops'])}")
for hop in d["relay_hops"]:
    print(f"  Hop {hop['hop_index']+1}: {hop['ip']}  masked={hop['masked']}")
print(f"SHA-256        : {d['forensic']['email_sha256'][:48]}...")
print(f"Analysis ID    : {d['analysis_id']}")
print(f"Warnings       : {len(d['warnings'])}")
for w in d["warnings"]:
    print(f"  - {w}")
print("\nPhase 1 live API test PASSED.")
