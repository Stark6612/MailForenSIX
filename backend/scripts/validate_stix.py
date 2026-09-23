"""
scripts/validate_stix.py
------------------------
Validates a sample STIX 2.1 bundle exported by MailForensix.
Outputs: backend/proof/stix_validation.json
"""

import json
import sys
from pathlib import Path

BASE_DIR  = Path(__file__).resolve().parent.parent
PROOF_DIR = BASE_DIR / "proof"
PROOF_DIR.mkdir(exist_ok=True)
sys.path.insert(0, str(BASE_DIR))


def make_sample_campaign():
    return {
        "campaign_id": "demo-campaign-001",
        "name": "Demo PayPal Phishing Campaign",
        "actor_profile": {
            "email_count": 15,
            "relay_ips": {"185.234.218.12": 5, "185.234.218.14": 4, "185.234.218.16": 6},
            "top_asns": {"AS197695": 15},
            "top_countries": {"RU": 15},
            "sender_domains": {"secure-paypal-verify.com": 8, "paypal-account-update.net": 7},
            "subject_samples": [
                "Your PayPal account has been limited",
                "Urgent: Verify your PayPal account now",
            ],
            "avg_domain_age_days": 12.0,
            "has_malicious_url": True,
            "has_attachment": False,
            "auth_pass_ratio": 0.0,
            "new_domain_detected": True,
            "mitre_techniques": [
                {"id": "T1566.002", "name": "Spearphishing Link", "tactic": "Initial Access", "description": "Phishing with URL"},
                {"id": "T1583.001", "name": "Acquire Infrastructure: Domains", "tactic": "Resource Development", "description": "Newly registered domains"},
            ],
        }
    }


def main():
    from engines.exporter import export_stix, validate_stix

    print("\n=== MailForensix - STIX 2.1 Validation ===\n")

    campaign = make_sample_campaign()

    for tlp in ["amber", "green", "white"]:
        stix_json = export_stix(campaign, tlp=tlp)
        result    = validate_stix(stix_json)
        print(f"[TLP:{tlp.upper()}] Valid={result['valid']}  Objects={result['object_count']}  Errors={result['errors']}")

        # Save sample bundle
        bundle_path = PROOF_DIR / f"sample_stix_{tlp}.json"
        with open(bundle_path, "w") as f:
            f.write(stix_json)
        print(f"           Bundle saved: {bundle_path}")

    # Final proof for TLP:AMBER
    stix_json = export_stix(campaign, tlp="amber")
    validation = validate_stix(stix_json)

    proof = {
        "campaign": campaign["name"],
        "tlp": "AMBER",
        "stix_valid": validation["valid"],
        "object_count": validation["object_count"],
        "errors": validation["errors"],
        "bundle_path": str(PROOF_DIR / "sample_stix_amber.json"),
    }
    proof_path = PROOF_DIR / "stix_validation.json"
    with open(proof_path, "w") as f:
        json.dump(proof, f, indent=2)
    print(f"\n[PROOF] {proof_path}")

    if validation["valid"]:
        print("[PASS] STIX 2.1 bundle schema-valid")
    else:
        print(f"[FAIL] STIX validation errors: {validation['errors']}")

    print("\n=== STIX Validation complete ===\n")


if __name__ == "__main__":
    main()
