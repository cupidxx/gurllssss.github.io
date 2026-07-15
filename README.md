# 🛡️ PhishShield – AI-Powered Phishing Detection & Cybersecurity Awareness Platform

PhishShield is a full-stack web application that helps users detect phishing emails, analyze suspicious URLs, and improve cybersecurity awareness through an interactive learning experience. The platform combines rule-based email analysis with a modern web interface, educational phishing simulations, and an AI-powered assistant to help users recognize and respond to phishing attacks.

---

## 📖 Project Overview

Phishing is one of the most common cybersecurity threats, targeting individuals through fake emails, malicious links, and social engineering. PhishShield aims to provide a simple yet effective platform where users can:

- Analyze suspicious emails
- Evaluate potentially malicious URLs
- Learn phishing indicators through an interactive quiz
- Receive cybersecurity guidance from an AI assistant

This project demonstrates full-stack web development, REST API design, frontend-backend integration, and cybersecurity-focused application development.

---

## ✨ Features

### 📧 Email Phishing Analyzer

Analyze suspicious emails by evaluating:

- Sender email address
- Subject line
- Email content

The system identifies phishing indicators including:

- Suspicious sender domains
- Urgent or manipulative language
- Common phishing phrases
- Sender domain extraction
- Rule-based threat detection
- Risk score generation
- Human-readable explanations

---

### 🌐 URL Threat Analyzer

Inspect suspicious URLs before opening them.

Checks include:

- Suspicious top-level domains (.xyz, .ru, .tk)
- Phishing-related keywords
- Missing HTTPS
- Excessive URL length
- Multiple hyphens
- Hidden '@' characters

Features:

- Dynamic threat score
- Color-coded risk visualization
- VirusTotal integration
- Detailed explanations

---

### 🎮 Phishing Awareness Game

**Would You Click It?**

A gamified phishing training module where users classify emails as legitimate or malicious.

Features:

- Realistic phishing scenarios
- Job recruitment scams
- Banking fraud examples
- University email examples
- Immediate feedback
- Educational explanations
- Live score tracking

---

### 🤖 AI Chat Assistant

A built-in cybersecurity assistant that answers common questions such as:

- Is this recruiter legitimate?
- Should I reply to this email?
- Why is this email suspicious?
- How can I stay safe online?

The chatbot provides beginner-friendly cybersecurity guidance to help users make informed decisions.

---

## 🏗️ System Architecture

```text
                    User
                      │
                      ▼
        HTML + CSS + JavaScript Dashboard
                      │
                      ▼
              Flask REST API Backend
                      │
                      ▼
         Rule-Based Phishing Detection
                      │
                      ▼
                JSON API Response
                      │
                      ▼
         Interactive Dashboard Results
```

---

## 🛠️ Technology Stack

### Frontend

- HTML5
- CSS3
- JavaScript (ES6)

### Backend

- Python
- Flask
- Flask-CORS

### Tools & APIs

- REST API
- JSON
- VirusTotal Integration

### Development Tools

- Visual Studio Code
- Git
- GitHub

---

## 📂 Project Structure

```text
PhishShield/
│
├── app.py
├── index.html
├── dashboard.html
├── script.js
├── dashboard.js
├── style.css
├── requirements.txt
├── README.md
└── assets/
```

---

## 🚀 Installation

### Clone the Repository

```bash
git clone https://github.com/yourusername/phishshield.git
```

### Navigate to the Project

```bash
cd phishshield
```

### Create a Virtual Environment (Optional)

```bash
python -m venv venv
```

Activate it:

**Windows**

```bash
venv\Scripts\activate
```

**macOS/Linux**

```bash
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Start the Flask Server

```bash
python app.py
```

The backend runs on:

```text
http://127.0.0.1:5055
```

Open `index.html` in your browser to access the application.

---

## 📡 API Endpoint

### Analyze Email

**POST** `/analyze`

### Request

```json
{
  "sender_email": "security@company.xyz",
  "subject": "Urgent Account Verification",
  "body": "Click here immediately to verify your account."
}
```

### Response

```json
{
  "verdict": "High Risk",
  "risk_score": 85,
  "sender_domain": "company.xyz",
  "flags": [
    "Suspicious sender domain",
    "Urgent language detected",
    "Suspicious link phrase"
  ],
  "explanation": "Basic phishing analysis"
}
```

---

## 📊 Risk Levels

| Score | Risk Level |
|-------:|------------|
| 0–34 | 🟢 Low Risk |
| 35–59 | 🟡 Medium Risk |
| 60–100 | 🔴 High Risk |

---

## 🎯 Detection Rules

### Email Analysis

- Suspicious sender domains
- Urgent language detection
- Phishing phrases
- Risk score generation
- Human-readable explanations

### URL Analysis

- Missing HTTPS
- Suspicious TLDs
- Phishing keywords
- Long URLs
- Multiple hyphens
- Hidden '@' symbols

---

## 🎮 Educational Features

Users can learn to identify:

- Fake recruiter emails
- Credential theft attempts
- Banking scams
- Account verification scams
- University phishing emails
- Delivery scams
- Social engineering techniques

Each scenario includes feedback explaining why an email is safe or malicious.

---

## 🔮 Future Improvements

- Machine Learning phishing classifier
- Natural Language Processing (NLP)
- BERT-based email classification
- Domain reputation lookup
- WHOIS integration
- SPF/DKIM/DMARC validation
- Attachment malware scanning
- User authentication
- Threat history dashboard
- Explainable AI (XAI)
- Real-time phishing intelligence feeds

---

## 📸 Screenshots

Add screenshots of:

- Home Page
- Email Analyzer
- Analysis Results
- URL Threat Checker
- Phishing Awareness Game
- AI Chat Assistant

---

## 📚 Learning Outcomes

This project demonstrates:

- Full-stack web development
- Flask REST API development
- JavaScript DOM manipulation
- Frontend-backend communication
- Rule-based cybersecurity analysis
- Interactive UI/UX design
- Cybersecurity awareness education

---

## 👤 Author

**Krishnasree Konda**

Master's in Data Analytics  
Clark University

---

## 📄 License

This project is licensed under the MIT License.

---

