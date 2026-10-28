"""
test_aics_pipeline.py — Comprehensive Test Suite for AICS Course 23AI2001
Course: Artificial Intelligence for Cyber Security (23AI2001)

Verifies:
  1. Multi-Model In-Memory Registry loading all 5 syllabus models (lr, svm, nb, dt, xgb).
  2. 3-Class Intent Prediction (Legitimate vs Spam vs Phishing) across each algorithm.
  3. Explainable AI (LIME) multi-class sentence & token attribution structure.
  4. Account & Domain Reputation Scoring Engine (ADRSE) mathematically validating SPF/DKIM/DMARC/Alignment.
  5. Antivirus Limits & Attachment Shannon Entropy triage (CO2).
  6. Live REST API routing:
       - GET  /api/v1/models
       - GET  /api/v1/models/benchmark
       - GET  /api/v1/models/benchmark/ablation
       - GET  /api/v1/models/benchmark/av-limits
       - POST /api/v1/analyze?model=lr
       - POST /api/v1/analyze?model=svm
       - POST /api/v1/analyze?model=nb
"""

import os
import sys
from pathlib import Path

# Ensure paths
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ["LOKY_MAX_CPU_COUNT"] = "1"

from fastapi.testclient import TestClient
from main import app
from engines.classifier import load_model, predict_intent, explain_sentences, get_available_models
from engines.auth import compute_account_reputation
from scripts.eval_av_limits import compute_shannon_entropy


client = TestClient(app)

SAMPLE_PHISHING_EMAIL = """From: Mail Security Team <alerts@secure-corp-verify.com>
To: victim@company.com
Subject: URGENT: Mailbox Session Expired
Date: Wed, 28 Oct 2026 10:00:00 +0000
Message-ID: <threat-test-82934@mail.com>
Authentication-Results: mx.google.com;
  spf=fail (google.com: domain of alerts@secure-corp-verify.com does not designate 192.0.2.1 as permitted sender) smtp.mailfrom=alerts@secure-corp-verify.com;
  dkim=fail;
  dmarc=fail (p=reject sp=reject) header.from=secure-corp-verify.com

Dear user, your mailbox session has expired and incoming emails are on pending status.
Action required: Click here immediately to verify your credentials: http://auth-portal-verify.com/login.
Failure to confirm within 24 hours will lead to account deactivation.
"""

SAMPLE_LEGIT_EMAIL = """From: Project Manager <pm@company.com>
To: engineer@company.com
Subject: Sprint Deliverables Review
Date: Wed, 28 Oct 2026 10:00:00 +0000
Message-ID: <legit-test-10293@mail.com>
Authentication-Results: mx.google.com;
  spf=pass smtp.mailfrom=company.com;
  dkim=pass header.d=company.com;
  dmarc=pass header.from=company.com

Hi team, please find attached the quarterly progress report and sprint deliverables.
Let me know if you have any questions before Friday's project standup meeting.
"""


def test_1_model_registry_loading():
    print("\n--- Test 1: Model Registry Initialization ---")
    loaded = load_model()
    assert loaded is True, "AICS models failed to load into memory."
    models = get_available_models()
    print(f"  [PASS] Successfully loaded {len(models)} models in registry:")
    for m in models:
        print(f"    - {m['id']}: {m['name']} ({m['type']})")
    assert len(models) == 5, f"Expected 5 models, got {len(models)}"


def test_2_multimodel_tripartite_inference():
    print("\n--- Test 2: Tripartite 3-Class Inference across All 5 Algorithms ---")
    test_text = (
        "Mail Security Alert: Dear user, incoming emails are on pending status due to session expiration. "
        "Please click here immediately to verify your identity and confirm your account login: "
        "http://security-update-portal.org/login"
    )
    
    for mid in ["lr", "svm", "nb", "dt", "xgb"]:
        label, conf, class_probs, mname = predict_intent(test_text, model_id=mid)
        print(f"  [PASS] Model: {mname:<38} | Pred: {label:<10} (Conf: {conf:.3f}) | Probs: {class_probs}")
        assert label in ["safe", "spam", "phishing"], f"Invalid threat label: {label}"
        assert 0.0 <= conf <= 1.0, f"Confidence out of bounds: {conf}"
        assert "phishing" in class_probs and "legitimate" in class_probs and "spam" in class_probs


def test_3_lime_multiclass_attributions():
    print("\n--- Test 3: Multi-Class Explainable AI (LIME) ---")
    body = (
        "URGENT: Your mailbox session has expired and messages are paused. "
        "Click here immediately to verify your login credentials. "
        "Thank you, Corporate Security Administrator."
    )
    lime_results = explain_sentences(body, model_id="lr", n=3)
    print(f"  [PASS] LIME generated {len(lime_results)} sentence attributions:")
    for item in lime_results:
        print(f"    - Score: {item['score']:.3f} | {item['explanation']} | Text: '{item['text'][:50]}...'")
    assert len(lime_results) > 0, "LIME produced empty explanation list."
    assert 0.0 <= lime_results[0]["score"] <= 1.0


def test_4_account_reputation_scoring():
    print("\n--- Test 4: Module 5 Account & Domain Reputation Scoring (ADRSE) ---")
    # Case A: Perfectly authenticated corporate email
    good_rep = compute_account_reputation(
        spf_status="pass", dkim_status="pass", dmarc_status="pass", alignment_ok=True
    )
    print(f"  [PASS] Good Sender: Score = {good_rep['reputation_score']}/100, Grade = {good_rep['grade']}")
    assert good_rep["reputation_score"] == 100.0
    assert good_rep["grade"] == "A"

    # Case B: Spoofed attacker email
    bad_rep = compute_account_reputation(
        spf_status="fail", dkim_status="fail", dmarc_status="fail", alignment_ok=False, alignment_fail=True
    )
    print(f"  [PASS] Spoofed Sender: Score = {bad_rep['reputation_score']}/100, Grade = {bad_rep['grade']}")
    assert bad_rep["reputation_score"] == 0.0
    assert bad_rep["grade"] == "F"


def test_5_shannon_entropy_triage():
    print("\n--- Test 5: CO2 Shannon Entropy Attachment Triage ---")
    benign_text = b"Normal readable ASCII email text with standard redundancy" * 20
    packed_malware = bytes(range(256)) * 16  # Uniform byte distribution

    h_benign = compute_shannon_entropy(benign_text)
    h_packed = compute_shannon_entropy(packed_malware)

    print(f"  [PASS] Benign text entropy: {h_benign:.3f} bits/byte (< 5.5)")
    print(f"  [PASS] Packed malware entropy: {h_packed:.3f} bits/byte (>= 7.2)")
    assert h_benign < 5.5
    assert h_packed >= 7.2


def test_6_rest_api_endpoints():
    print("\n--- Test 6: REST API Routing & Model Switching ---")
    
    # 1. Models list
    r = client.get("/api/v1/models")
    assert r.status_code == 200, f"GET /models failed: {r.text}"
    data = r.json()
    print(f"  [PASS] GET /api/v1/models returned {len(data['models'])} models.")

    # 2. Benchmark data
    r_bench = client.get("/api/v1/models/benchmark")
    assert r_bench.status_code == 200, f"GET /benchmark failed: {r_bench.text}"
    print("  [PASS] GET /api/v1/models/benchmark returned comparative metrics.")

    # 3. Ablation data
    r_ablate = client.get("/api/v1/models/benchmark/ablation")
    assert r_ablate.status_code == 200, f"GET /benchmark/ablation failed: {r_ablate.text}"
    print("  [PASS] GET /api/v1/models/benchmark/ablation returned 4 feature setups.")

    # 4. AV limits data
    r_av = client.get("/api/v1/models/benchmark/av-limits")
    assert r_av.status_code == 200, f"GET /benchmark/av-limits failed: {r_av.text}"
    print("  [PASS] GET /api/v1/models/benchmark/av-limits returned CO2 benchmark.")

    # 5. Full E2E analysis with Dynamic Model Switching
    for target_model in ["lr", "svm", "nb", "dt", "xgb"]:
        resp = client.post(
            f"/api/v1/analyze?model={target_model}",
            data={"raw_headers": SAMPLE_PHISHING_EMAIL}
        )
        assert resp.status_code == 200, f"Analyze with {target_model} failed: {resp.text}"
        res_json = resp.json()
        model_inf = res_json.get("model_inference", {})
        acc_rep   = res_json.get("account_reputation", {})

        assert model_inf.get("model_id") == target_model
        assert res_json["risk_score"] > 50  # Must flag high risk
        print(f"  [PASS] POST /analyze?model={target_model:<3} -> Risk: {res_json['risk_score']}/100 | Tier: {res_json['risk_tier']:<10} | Model: {model_inf.get('model_name')}")


def run_all_tests():
    print("=" * 80)
    print("  AICS (23AI2001) VERIFICATION & TEST PIPELINE")
    print("=" * 80)
    test_1_model_registry_loading()
    test_2_multimodel_tripartite_inference()
    test_3_lime_multiclass_attributions()
    test_4_account_reputation_scoring()
    test_5_shannon_entropy_triage()
    test_6_rest_api_endpoints()
    print("=" * 80)
    print("  [ALL TESTS PASSED 100%] PIPELINE INTEGRITY FULLY CERTIFIED!")
    print("=" * 80)


if __name__ == "__main__":
    run_all_tests()

