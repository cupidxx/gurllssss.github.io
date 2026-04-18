from flask import Flask, request, jsonify
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app)

@app.route("/")
def home():
    return "PhishShield backend is live"

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()

    sender = data.get("sender_email", "")
    subject = data.get("subject", "")
    body = data.get("body", "")

    flags = []

    if ".xyz" in sender.lower():
        flags.append("Suspicious sender domain")
    if "urgent" in subject.lower():
        flags.append("Urgent language detected")
    if "click here" in body.lower():
        flags.append("Suspicious link phrase")

    score = 20
    if len(flags) == 1:
        score = 55
        verdict = "Medium Risk"
    elif len(flags) >= 2:
        score = 85
        verdict = "High Risk"
    else:
        verdict = "Low Risk"

    sender_domain = "-"
    if "@" in sender:
        sender_domain = sender.split("@")[-1].lower()

    return jsonify({
        "verdict": verdict,
        "risk_score": score,
        "sender_domain": sender_domain,
        "flags": flags,
        "explanation": "Basic phishing analysis"
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5055))
    app.run(host="0.0.0.0", port=port)
    
