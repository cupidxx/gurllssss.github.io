from flask import Flask, request, jsonify
from flask_cors import CORS
import re

app = Flask(__name__)
CORS(app)

KNOWN_COMPANY_DOMAINS = {
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com"],
    "apple": ["apple.com"],
    "microsoft": ["microsoft.com", "outlook.com"],
    "google": ["google.com"],
    "linkedin": ["linkedin.com"],
    "netflix": ["netflix.com"],
    "bank of america": ["bankofamerica.com"],
    "chase": ["chase.com"],
    "wells fargo": ["wellsfargo.com"],
    "handshake": ["joinhandshake.com", "handshake.com"],
    "uscis": ["uscis.gov"],
    "clark university": ["clarku.edu"],
}

SUSPICIOUS_DOMAIN_WORDS = [
    "secure-login",
    "verify-now",
    "update-info",
    "account-alert",
    "bonus-pay",
    "claim-prize",
    "gift-card",
    "wallet",
    "crypto",
]

SUSPICIOUS_TLDS = [".ru", ".tk", ".xyz", ".top", ".click", ".buzz", ".work"]

SUSPICIOUS_SUBJECT_PATTERNS = [
    r"urgent",
    r"immediate action",
    r"verify your account",
    r"account suspended",
    r"payment failed",
    r"security alert",
    r"reset password",
    r"claim now",
    r"final warning",
    r"congratulations",
    r"job offer",
    r"selected without interview",
]

BODY_RED_FLAGS = [
    "click here immediately",
    "verify your account",
    "confirm your password",
    "urgent response needed",
    "act now",
    "wire transfer",
    "gift card",
    "crypto payment",
    "download attachment",
]

FREE_EMAIL_DOMAINS = [
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "icloud.com",
    "aol.com",
]

def extract_domain(email):
    if "@" not in email:
        return ""
    return email.split("@")[-1].strip().lower()

def find_company_mentions(text):
    found = []
    text = text.lower()
    for company in KNOWN_COMPANY_DOMAINS:
        if company in text:
            found.append(company)
    return found

def check_sender_domain(domain):
    score = 0
    reasons = []

    if not domain:
        reasons.append("Sender email is missing a valid domain.")
        score += 20
        return score, reasons

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            reasons.append(f"Sender domain uses suspicious ending: {tld}")
            score += 20
            break

    for word in SUSPICIOUS_DOMAIN_WORDS:
        if word in domain:
            reasons.append(f"Sender domain contains suspicious wording: '{word}'")
            score += 20

    if domain.count("-") >= 2:
        reasons.append("Sender domain has multiple hyphens, which can be suspicious.")
        score += 10

    if re.search(r"\d", domain):
        reasons.append("Sender domain contains numbers, which can sometimes be suspicious.")
        score += 5

    return score, reasons

def check_subject(subject):
    score = 0
    reasons = []
    subject_lower = subject.lower().strip()

    if len(subject_lower) < 4:
        reasons.append("Subject line is too short or vague.")
        score += 10

    for pattern in SUSPICIOUS_SUBJECT_PATTERNS:
        if re.search(pattern, subject_lower):
            reasons.append(f"Subject line includes suspicious wording: '{pattern}'")
            score += 15

    return score, reasons

def check_body(body):
    score = 0
    reasons = []
    body_lower = body.lower()

    for phrase in BODY_RED_FLAGS:
        if phrase in body_lower:
            reasons.append(f"Email body contains phishing-style phrase: '{phrase}'")
            score += 12

    urgency_count = len(re.findall(r"\burgent\b|\bimmediately\b|\bnow\b|\bfinal\b", body_lower))
    if urgency_count >= 2:
        reasons.append("Email body uses repeated urgency language.")
        score += 10

    return score, reasons

def check_company_mismatch(sender_email, subject, body):
    score = 0
    reasons = []

    domain = extract_domain(sender_email)
    combined_text = f"{subject} {body}".lower()
    mentioned_companies = find_company_mentions(combined_text)

    if mentioned_companies:
        matched = False

        for company in mentioned_companies:
            allowed_domains = KNOWN_COMPANY_DOMAINS.get(company, [])
            for allowed_domain in allowed_domains:
                if allowed_domain in domain:
                    matched = True
                    break
            if matched:
                break

        if not matched:
            reasons.append(
                f"The email mentions {', '.join(mentioned_companies)} but the sender domain is '{domain}', which may not match."
            )
            score += 25

        if domain in FREE_EMAIL_DOMAINS:
            reasons.append(
                f"The sender uses a free email domain '{domain}' while claiming to represent a company."
            )
            score += 30

    return score, reasons

@app.route("/")
def home():
    return jsonify({"message": "PhishShield backend is running"})

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()

    sender_email = data.get("sender_email", "").strip()
    subject = data.get("subject", "").strip()
    body = data.get("body", "").strip()

    total_score = 0
    flags = []

    sender_domain = extract_domain(sender_email)

    domain_score, domain_flags = check_sender_domain(sender_domain)
    subject_score, subject_flags = check_subject(subject)
    body_score, body_flags = check_body(body)
    mismatch_score, mismatch_flags = check_company_mismatch(sender_email, subject, body)

    total_score += domain_score + subject_score + body_score + mismatch_score
    flags.extend(domain_flags)
    flags.extend(subject_flags)
    flags.extend(body_flags)
    flags.extend(mismatch_flags)

    total_score = min(total_score, 100)

    if total_score >= 70:
        verdict = "High Risk"
    elif total_score >= 40:
        verdict = "Medium Risk"
    else:
        verdict = "Low Risk"

    return jsonify({
        "verdict": verdict,
        "risk_score": total_score,
        "sender_domain": sender_domain,
        "flags": flags
    })

if __name__ == "__main__":
    app.run(debug=True, port=5055, use_reloader=False)
    