"""
Regenerate synthetic corpus with properly formatted RFC 5322 headers.
Run from: backend/
"""
import os, random
from datetime import datetime, timedelta, timezone

random.seed(42)

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "synthetic_corpus")
os.makedirs(OUT_DIR, exist_ok=True)

CAMPAIGNS = {
    1: {
        "name": "PayPal Credential Phishing",
        "ip_prefix": "185.234.218", "ip_range": range(10, 30),
        "asn": "AS197695", "isp": "Reg.ru LLC", "country": "RU",
        "domains": ["secure-paypal-verify.com", "paypal-account-update.net"],
        "from_names": ["PayPal Security", "PayPal Support", "PayPal Account Team",
                       "PayPal Customer Care", "PayPal Alerts"],
        "subjects": [
            "Your PayPal account has been limited",
            "Urgent: Verify your PayPal account now",
            "Action required: Unusual activity on your account",
            "PayPal: Your account access has been restricted",
            "Important notice: Complete your account verification",
            "PayPal Security Alert: Suspicious login detected",
            "Your PayPal account will be suspended",
            "Confirm your identity to restore PayPal access",
            "PayPal: Update your billing information immediately",
            "Security update required for your PayPal account",
            "PayPal Notice: Account verification needed",
            "Immediate action required on your PayPal account",
            "PayPal: We noticed unusual sign-in activity",
            "Your PayPal account is at risk - act now",
            "PayPal: Verify your details to avoid suspension",
        ],
        "bodies": [
            "Dear Customer,\n\nWe have detected unusual activity on your PayPal account. To protect your account, we have temporarily limited access.\n\nPlease verify your identity within 24 hours:\nhttps://secure-paypal-verify.com/restore?token={tok}\n\nIf you do not verify, your account will be permanently restricted.\n\nPayPal Security Team",
            "Hello,\n\nYour PayPal account requires immediate verification. We noticed a sign-in attempt from an unrecognized device.\n\nConfirm it was you: https://paypal-account-update.net/confirm?id={tok}\n\nFailure to confirm within 48 hours will result in account suspension.\n\nPayPal Account Team",
            "Important Notice,\n\nYour PayPal account has been flagged for review due to suspicious transactions. To restore full access:\n\nhttps://secure-paypal-verify.com/verify?ref={tok}\n\nThis link expires in 12 hours.\n\nPayPal Support",
        ],
        "auth_pass": False,
    },
    2: {
        "name": "UIDAI Aadhaar Phishing",
        "ip_prefix": "103.21.58", "ip_range": range(5, 25),
        "asn": "AS394695", "isp": "HostSailor", "country": "IN",
        "domains": ["uidai-aadhar-update.in", "govt-kyc-portal.in"],
        "from_names": ["UIDAI Support", "Aadhaar Services", "UIDAI Help Desk",
                       "Govt KYC Portal", "Aadhaar Update"],
        "subjects": [
            "URGENT: Update your Aadhaar details immediately",
            "Aadhaar KYC verification required",
            "Your Aadhaar card will be deactivated",
            "Action required: Link Aadhaar with PAN",
            "UIDAI: Biometric update mandatory",
            "Final notice: Aadhaar verification pending",
            "Aadhaar: Your mobile number needs re-verification",
            "UIDAI Alert: Suspicious activity on your Aadhaar",
            "Complete your Aadhaar eKYC today",
            "Aadhaar services restricted - verify now",
            "UIDAI: Important update regarding your Aadhaar",
            "Link your bank account with Aadhaar immediately",
            "Aadhaar deactivation notice",
            "UIDAI: Update your biometrics before deadline",
            "Aadhaar verification failed - action required",
        ],
        "bodies": [
            "Dear Citizen,\n\nYour Aadhaar card requires mandatory KYC update as per UIDAI guidelines. Failure to update will result in deactivation.\n\nUpdate now: https://uidai-aadhar-update.in/kyc?ref={tok}\n\nUIDAI Support Team",
            "Important Notice,\n\nYour Aadhaar biometric data needs to be updated as per government regulations.\n\nClick here: https://govt-kyc-portal.in/update?id={tok}\n\nGovernment KYC Portal",
            "Dear Aadhaar Holder,\n\nYour Aadhaar has been flagged for reverification. Complete within 48 hours to avoid deactivation.\n\nVerify: https://uidai-aadhar-update.in/verify?token={tok}\n\nUIDAI Help Desk",
        ],
        "auth_pass": False,
    },
    3: {
        "name": "Microsoft 365 Phishing",
        "ip_prefix": "91.108.56", "ip_range": range(1, 20),
        "asn": "AS29076", "isp": "Citytelecom LLC", "country": "NL",
        "domains": ["microsoft-365-alert.net", "docusign-secure-sign.com"],
        "from_names": ["Microsoft 365", "Microsoft Security", "DocuSign",
                       "Microsoft Account Team", "Office 365"],
        "subjects": [
            "Your Microsoft 365 subscription is expiring",
            "Action required: Sign the document in DocuSign",
            "Microsoft account security alert",
            "Your Office 365 password will expire",
            "DocuSign: Document awaiting your signature",
            "Microsoft 365: Unusual sign-in activity",
            "Your Microsoft account has been compromised",
            "DocuSign: Final reminder to sign",
            "Microsoft: Verify your account to continue",
            "Office 365 storage quota exceeded",
            "Microsoft security: 2FA required",
            "DocuSign: Agreement ready for review",
            "Microsoft 365: Subscription payment failed",
            "Your OneDrive account will be suspended",
            "Microsoft: Account suspended - verify now",
        ],
        "bodies": [
            "Dear User,\n\nYour Microsoft 365 account has detected suspicious activity. Immediate verification is required.\n\nVerify here: https://microsoft-365-alert.net/secure?token={tok}\n\nMicrosoft Security Team",
            "Hello,\n\nA document is awaiting your signature in DocuSign. Please review and sign within 24 hours.\n\nSign now: https://docusign-secure-sign.com/sign?id={tok}\n\nDocuSign",
            "Dear Microsoft User,\n\nYour account password will expire in 24 hours. Update it now to maintain access.\n\nUpdate: https://microsoft-365-alert.net/password?ref={tok}\n\nOffice 365 Team",
        ],
        "auth_pass": False,
    },
}

NOISE = [
    {"from_name": "Amazon", "from_domain": "amazon.com", "ip": "54.239.28.85",
     "asn": "AS16509", "isp": "Amazon.com Inc", "country": "US",
     "subject": "Your Amazon order has shipped",
     "body": "Hi, your order #114-2847631 has been shipped. Track it at amazon.com/orders.",
     "auth_pass": True},
    {"from_name": "LinkedIn", "from_domain": "linkedin.com", "ip": "108.174.10.10",
     "asn": "AS14413", "isp": "LinkedIn Corp", "country": "US",
     "subject": "You have 3 new connection requests",
     "body": "Hi, you have new connection requests waiting on LinkedIn.",
     "auth_pass": True},
    {"from_name": "GitHub", "from_domain": "github.com", "ip": "192.30.255.112",
     "asn": "AS36459", "isp": "GitHub Inc", "country": "US",
     "subject": "Security advisory for your repository",
     "body": "A dependency in your repository has a known vulnerability. Please review.",
     "auth_pass": True},
    {"from_name": "Zoom", "from_domain": "zoom.us", "ip": "170.114.52.2",
     "asn": "AS3356", "isp": "Level3 Communications", "country": "US",
     "subject": "Your Zoom meeting starts in 15 minutes",
     "body": "Your scheduled Zoom meeting starts soon. Click to join: https://zoom.us/j/123456",
     "auth_pass": True},
    {"from_name": "Dropbox", "from_domain": "dropbox.com", "ip": "162.125.6.6",
     "asn": "AS19679", "isp": "Dropbox Inc", "country": "US",
     "subject": "Someone shared a file with you",
     "body": "A file has been shared with you on Dropbox. Log in to view it.",
     "auth_pass": True},
]


def _tok():
    return "".join(random.choices("0123456789abcdef", k=24))


def _date(base, offset_h):
    return (base + timedelta(hours=offset_h)).strftime("%a, %d %b %Y %H:%M:%S +0530")


def _mid(domain):
    r = "".join(random.choices("0123456789abcdef", k=16))
    return f"<{r}@{domain}>"


def build_eml(from_name, from_domain, to_addr, subject, body,
              relay_ip, relay_host, asn, isp, date, mid, auth_pass=False):
    """Build RFC 5322 compliant .eml — standard line endings, no leading spaces."""
    auth_header = (
        f"Authentication-Results: mx.victim-org.in;\r\n"
        f"    spf=pass (sender IP is {relay_ip}) smtp.mailfrom={from_domain};\r\n"
        f"    dkim=pass header.i=@{from_domain}\r\n"
        if auth_pass else
        f"Authentication-Results: mx.victim-org.in;\r\n"
        f"    spf=fail (sender IP {relay_ip} not authorized);\r\n"
        f"    dkim=fail header.i=@{from_domain}\r\n"
    )

    return (
        f"Received: from mail-transit.example.net (mail-transit.example.net [203.0.113.5])\r\n"
        f"    by mx.victim-org.in (Postfix) with ESMTPS\r\n"
        f"    for <{to_addr}>; {date}\r\n"
        f"Received: from {relay_host} ({relay_host} [{relay_ip}])\r\n"
        f"    by mail-transit.example.net (Postfix) with ESMTP\r\n"
        f"    for <{to_addr}>; {date}\r\n"
        f"{auth_header}"
        f"From: {from_name} <noreply@{from_domain}>\r\n"
        f"Reply-To: support@{from_domain}\r\n"
        f"To: {to_addr}\r\n"
        f"Subject: {subject}\r\n"
        f"Date: {date}\r\n"
        f"Message-ID: {mid}\r\n"
        f"MIME-Version: 1.0\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Transfer-Encoding: 7bit\r\n"
        f"X-Campaign-ASN: {asn}\r\n"
        f"X-Campaign-ISP: {isp}\r\n"
        f"\r\n"
        f"{body}\r\n"
    )


BASE_DT = datetime(2025, 8, 1, 9, 0, 0, tzinfo=timezone.utc)
VICTIMS = [
    "analyst@secureinstitution.in", "user@targetorg.gov.in",
    "employee@publicbank.co.in", "staff@university.ac.in", "officer@certrecipient.in",
]

idx = 1
for cid, camp in CAMPAIGNS.items():
    ips = [f"{camp['ip_prefix']}.{i}" for i in camp["ip_range"]]
    pool = random.choices(ips, k=5)
    for i in range(15):
        ip   = pool[i % len(pool)]
        dom  = camp["domains"][i % len(camp["domains"])]
        eml  = build_eml(
            from_name=camp["from_names"][i % len(camp["from_names"])],
            from_domain=dom,
            to_addr=VICTIMS[i % len(VICTIMS)],
            subject=camp["subjects"][i],
            body=camp["bodies"][i % len(camp["bodies"])].replace("{tok}", _tok()),
            relay_ip=ip, relay_host=f"mail.{dom}",
            asn=camp["asn"], isp=camp["isp"],
            date=_date(BASE_DT, i * 3 + (cid - 1) * 50),
            mid=_mid(dom),
            auth_pass=camp.get("auth_pass", False),
        )
        filepath = os.path.join(OUT_DIR, f"email_{idx:02d}_C{cid}.eml")
        with open(filepath, "wb") as f:
            f.write(eml.encode("utf-8"))
        idx += 1

for n in NOISE:
    eml = build_eml(
        from_name=n["from_name"], from_domain=n["from_domain"],
        to_addr=VICTIMS[idx % len(VICTIMS)],
        subject=n["subject"], body=n["body"],
        relay_ip=n["ip"], relay_host=f"mail.{n['from_domain']}",
        asn=n["asn"], isp=n["isp"],
        date=_date(BASE_DT, idx * 7), mid=_mid(n["from_domain"]),
        auth_pass=n.get("auth_pass", True),
    )
    filepath = os.path.join(OUT_DIR, f"email_{idx:02d}_NOISE.eml")
    with open(filepath, "wb") as f:
        f.write(eml.encode("utf-8"))
    idx += 1

print(f"Generated {idx-1} emails -> {OUT_DIR}")

# Verify parsing
import sys, os as _os
sys.path.insert(0, _os.path.join(_os.path.dirname(__file__), ".."))
from engines.parser import parse_eml as _parse

for test_file in ["email_01_C1.eml", "email_16_C2.eml", "email_31_C3.eml", "email_46_NOISE.eml"]:
    sample = open(os.path.join(OUT_DIR, test_file), "rb").read()
    p = _parse(sample)
    print(f"\nParser check {test_file}:")
    print(f"  sender_domain : {p.sender_domain}")
    print(f"  relay_hops    : {len(p.received_hops)} hops -> {[h.ip for h in p.received_hops]}")
    print(f"  subject       : {p.subject[:50] if p.subject else 'EMPTY'}")
    assert p.sender_domain is not None, f"sender_domain is None for {test_file}"
    assert p.subject, f"subject is empty for {test_file}"
    assert len(p.received_hops) >= 1, f"no hops for {test_file}"

print("\nAll parser checks passed successfully!")
