const form = document.getElementById("emailForm");
const resultCard = document.getElementById("resultCard");
const verdictEl = document.getElementById("verdict");
const scoreEl = document.getElementById("score");
const domainEl = document.getElementById("domain");
const flagsList = document.getElementById("flagsList");
const riskFill = document.getElementById("riskFill");
const finalDecision = document.getElementById("finalDecision");

function getRiskColor(score) {
  if (score >= 60) return "red";
  if (score >= 35) return "yellow";
  return "green";
}

function getSpamDecision(score) {
  if (score >= 60) return "YES — Likely Spam";
  if (score >= 35) return "SUSPICIOUS — Be Careful";
  return "NO — Likely Safe";
}

function extractDomain(email) {
  if (!email.includes("@")) return "unknown";
  return email.split("@")[1];
}

if (form) {
  form.addEventListener("submit", async (e) => {
    e.preventDefault();

    const sender = document.getElementById("senderEmail").value.trim();
    const subject = document.getElementById("subjectLine").value.trim();
    const body = document.getElementById("emailBody").value.trim();

    try {
      const response = await fetch("http://127.0.0.1:5055/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          sender_email: sender,
          subject_line: subject,
          email_body: body
        })
      });

      const data = await response.json();

      resultCard.classList.remove("hidden");

      const score = data.risk_score || 0;

      verdictEl.textContent = data.verdict || "Unknown";
      scoreEl.textContent = `${score}/100`;
      domainEl.textContent = data.sender_domain || extractDomain(sender);
      finalDecision.textContent = getSpamDecision(score);

      flagsList.innerHTML = "";
      (data.flags || []).forEach((flag) => {
        const li = document.createElement("li");
        li.textContent = flag;
        flagsList.appendChild(li);
      });

      riskFill.style.width = `${score}%`;
      riskFill.classList.remove("risk-red", "risk-yellow", "risk-green");

      const color = getRiskColor(score);
      if (color === "red") riskFill.classList.add("risk-red");
      else if (color === "yellow") riskFill.classList.add("risk-yellow");
      else riskFill.classList.add("risk-green");
    } catch (error) {
      alert("Could not connect to backend.");
      console.error(error);
    }
  });
}

/* URL TOOL */
const urlInput = document.getElementById("urlInput");
const analyzeUrlBtn = document.getElementById("analyzeUrlBtn");
const urlResult = document.getElementById("urlResult");
const urlVerdict = document.getElementById("urlVerdict");
const urlScore = document.getElementById("urlScore");
const urlFlagsList = document.getElementById("urlFlagsList");
const urlRiskFill = document.getElementById("urlRiskFill");
const virusTotalLink = document.getElementById("virusTotalLink");

function inspectUrl(url) {
  let score = 0;
  const reasons = [];
  const lower = url.toLowerCase();

  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    score += 10;
    reasons.push("Missing http/https prefix");
  }

  if (lower.includes("@")) {
    score += 25;
    reasons.push("Contains @ symbol");
  }

  if (lower.includes("login") || lower.includes("verify") || lower.includes("secure") || lower.includes("update")) {
    score += 20;
    reasons.push("Contains phishing-style keywords");
  }

  if (lower.includes(".xyz") || lower.includes(".ru") || lower.includes(".tk")) {
    score += 20;
    reasons.push("Suspicious top-level domain");
  }

  if ((url.match(/-/g) || []).length >= 2) {
    score += 15;
    reasons.push("Too many hyphens in URL");
  }

  if (url.length > 60) {
    score += 10;
    reasons.push("Very long URL");
  }

  if (score > 100) score = 100;

  let verdict = "Looks Safer";
  let color = "green";

  if (score >= 60) {
    verdict = "Likely Dangerous";
    color = "red";
  } else if (score >= 35) {
    verdict = "Suspicious";
    color = "yellow";
  }

  return { score, verdict, reasons, color };
}

if (analyzeUrlBtn) {
  analyzeUrlBtn.addEventListener("click", () => {
    const url = urlInput.value.trim();
    if (!url) return;

    const result = inspectUrl(url);

    urlResult.classList.remove("hidden");
    urlVerdict.textContent = result.verdict;
    urlScore.textContent = `${result.score}/100`;

    urlFlagsList.innerHTML = "";
    result.reasons.forEach((reason) => {
      const li = document.createElement("li");
      li.textContent = reason;
      urlFlagsList.appendChild(li);
    });

    urlRiskFill.style.width = `${result.score}%`;
    urlRiskFill.classList.remove("risk-red", "risk-yellow", "risk-green");

    if (result.color === "red") urlRiskFill.classList.add("risk-red");
    else if (result.color === "yellow") urlRiskFill.classList.add("risk-yellow");
    else urlRiskFill.classList.add("risk-green");

    const encodedUrl = encodeURIComponent(url);
    virusTotalLink.href = `https://www.virustotal.com/gui/search/${encodedUrl}`;
  });
}

/* GAME MODE */
const gameCards = [
  {
    sender: "jobs@amaz0n-hiring.com",
    subject: "Immediate Interview Selection",
    body: "Congratulations. You have been selected. Kindly send your SSN and pay onboarding charges.",
    answer: "scam",
    reason: "Fake-looking sender, pressure language, and request for money and sensitive info."
  },
  {
    sender: "careers@spotify.com",
    subject: "Application Received",
    body: "Thanks for applying. Our team will review your application and contact you through the official portal.",
    answer: "safe",
    reason: "This follows a normal hiring process and does not ask for money or private documents."
  },
  {
    sender: "support@bank-verification-alert.xyz",
    subject: "Verify your account now",
    body: "Your account will be blocked unless you verify within 2 hours.",
    answer: "scam",
    reason: "Urgency and suspicious domain are common phishing signs."
  },
  {
    sender: "events@clarku.edu",
    subject: "Career Workshop Reminder",
    body: "Reminder: the networking event starts tomorrow at 10 AM in Jefferson 202.",
    answer: "safe",
    reason: "This is a normal school reminder with no suspicious request."
  }
];

const correctMessages = [
  "Nice catch 👀",
  "Scammer exposed.",
  "Too smart for that one."
];

const wrongMessages = [
  "Oof. Sneaky one.",
  "Almost got you.",
  "That one was tricky."
];

let currentGameIndex = 0;
let gameScore = 0;

const gameSender = document.getElementById("gameSender");
const gameSubject = document.getElementById("gameSubject");
const gameBody = document.getElementById("gameBody");
const gameScoreEl = document.getElementById("gameScore");
const scamBtn = document.getElementById("scamBtn");
const safeBtn = document.getElementById("safeBtn");
const gameButtons = document.getElementById("gameButtons");
const gameResult = document.getElementById("gameResult");
const gameFeedback = document.getElementById("gameFeedback");
const gameCorrectAnswer = document.getElementById("gameCorrectAnswer");
const gameReason = document.getElementById("gameReason");
const nextRoundBtn = document.getElementById("nextRoundBtn");
const gameCard = document.getElementById("gameCard");

function renderGameCard() {
  const current = gameCards[currentGameIndex];

  gameSender.textContent = current.sender;
  gameSubject.textContent = current.subject;
  gameBody.textContent = current.body;
  gameButtons.classList.remove("hidden");
  gameResult.classList.add("hidden");
  gameCard.classList.remove("correct-answer-box", "wrong-answer-box");
}

function handleGameAnswer(choice) {
  const current = gameCards[currentGameIndex];
  const isCorrect = choice === current.answer;

  if (isCorrect) {
    gameScore += 10;
    gameScoreEl.textContent = gameScore;
    gameFeedback.textContent =
      correctMessages[Math.floor(Math.random() * correctMessages.length)];
    gameCard.classList.add("correct-answer-box");
  } else {
    gameFeedback.textContent =
      wrongMessages[Math.floor(Math.random() * wrongMessages.length)];
    gameCard.classList.add("wrong-answer-box");
  }

  gameCorrectAnswer.innerHTML = `Correct answer: <strong>${current.answer.toUpperCase()}</strong>`;
  gameReason.textContent = current.reason;

  gameButtons.classList.add("hidden");
  gameResult.classList.remove("hidden");
}

function nextGameRound() {
  currentGameIndex = (currentGameIndex + 1) % gameCards.length;
  renderGameCard();
}

if (scamBtn && safeBtn && nextRoundBtn) {
  scamBtn.addEventListener("click", () => handleGameAnswer("scam"));
  safeBtn.addEventListener("click", () => handleGameAnswer("safe"));
  nextRoundBtn.addEventListener("click", nextGameRound);
  renderGameCard();
}

/* CHATBOT */
const chatMessages = document.getElementById("chatMessages");
const quickBtns = document.querySelectorAll(".quick-btn");

const cannedReplies = {
  "Is this recruiter legit?":
    "Check whether the sender domain matches the real company, whether the process feels normal, and whether they ask for payment or private documents early.",
  "Should I reply?":
    "Do not reply if the email shows urgency, asks for money, requests IDs, or comes from an unverified sender.",
  "Why is this risky?":
    "It may contain phishing language, impersonation, suspicious links, or requests for sensitive information."
};

function addChatMessage(text, role) {
  const div = document.createElement("div");
  div.className = `chat-bubble ${role}`;
  div.textContent = text;
  chatMessages.appendChild(div);
}

quickBtns.forEach((btn) => {
  btn.addEventListener("click", () => {
    const question = btn.dataset.question;
    addChatMessage(question, "user");
    addChatMessage(cannedReplies[question], "bot");
  });
});