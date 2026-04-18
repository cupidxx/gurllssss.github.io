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
    subject = data.get("subject_line", "")
    body = data.get("email_body", "")

    flags = []

    if ".xyz" in sender.lower():
        flags.append("Suspicious sender domain")
    if "urgent" in subject.lower():
        flags.append("Urgent language detected")
    if "click here" in body.lower():
        flags.append("Suspicious link phrase")

    risk = "High" if len(flags) >= 2 else "Medium" if len(flags) == 1 else "Low"

    return jsonify({
        "risk_score": risk,
        "flags": flags,
        "explanation": "Basic phishing analysis"
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5055))
    app.run(host="0.0.0.0", port=port)
    
