"""Full Phase 2+3 live API smoke test."""
import httpx, json, pathlib, sys

# Health
r = httpx.get('http://localhost:8000/health', timeout=5)
h = r.json()
print('=== Health ===')
print(f"status={h['status']} ml_loaded={h['ml_model_loaded']} version={h['version']}")

if not h.get('ml_model_loaded'):
    print('[WARN] ML model not loaded — check server startup logs')

# Analyze
eml_dir = pathlib.Path('data/20030228_spam/spam')
eml     = sorted(eml_dir.iterdir())[0]
print(f'\n=== Analyze: {eml.name} ===')
with open(eml, 'rb') as f:
    r2 = httpx.post(
        'http://localhost:8000/api/v1/analyze',
        files={'eml_file': (eml.name, f, 'message/rfc822')},
        timeout=90,
    )

if r2.status_code != 200:
    print('ERROR:', r2.status_code, r2.text[:500])
    sys.exit(1)

d = r2.json()
print(f"score      = {d['risk_score']}")
print(f"tier       = {d['risk_tier']}")
print(f"label      = {d['threat_label']}")
print(f"confidence = {d['confidence']:.4f}")
print(f"spf/dkim/dmarc = {d['auth']['spf']} / {d['auth']['dkim']} / {d['auth']['dmarc']}")
print(f"lime_sentences = {len(d['lime_sentences'])}")
print(f"relay_hops     = {len(d['relay_hops'])}")
if d.get('relay_hops'):
    h0 = d['relay_hops'][0]
    print(f"  hop[0]: ip={h0['ip']} country={h0.get('country')} geo_mode={h0.get('geo_mode')}")
di = d.get('domain_intel')
if di:
    print(f"domain         = {di['domain']} age={di.get('age_days')}d suspicion={di['suspicion_score']:.3f}")
print(f"sha256         = {d['forensic']['email_sha256'][:20]}...")
print(f"\nWarnings ({len(d['warnings'])}):")
for w in d['warnings']:
    print(f"  - {w}")
print('\n[OK] Phase 2+3 end-to-end test passed')
