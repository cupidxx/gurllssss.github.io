const form = document.getElementById("emailForm");
const resultCard = document.getElementById("resultCard");

const verdictEl = document.getElementById("verdict");
const scoreEl = document.getElementById("score");
const domainEl = document.getElementById("domain");
const flagsList = document.getElementById("flagsList");

const riskBanner = document.getElementById("riskBanner");
const riskBannerText = document.getElementById("riskBannerText");
const plainExplanation = document.getElementById("plainExplanation");

function buildExplanation(data) {
  const flags = data.flags || [];

  if (flags.length === 0) {
    return "This email does not show obvious phishing red flags based on the current checks.";
  }

  if (data.verdict === "High Risk") {
    return "This email looks highly suspicious because it combines multiple phishing indicators, such as suspicious sender patterns, risky wording, or a mismatch between the claimed company and the sender domain.";
  }

  if (data.verdict === "Medium Risk") {
    return "This email shows some warning signs that deserve extra caution. It may be using urgency, vague wording, or a sender identity that does not fully match the message content.";
  }

  return "This email appears lower risk, but users should still verify the sender and avoid clicking links too quickly.";
}

function updateRiskBanner(verdict) {
  riskBanner.classList.remove("hidden", "risk-high", "risk-medium", "risk-low");

  if (verdict === "High Risk") {
    riskBanner.classList.add("risk-high");
    riskBannerText.textContent = "🚨 High Risk Email";
  } else if (verdict === "Medium Risk") {
    riskBanner.classList.add("risk-medium");
    riskBannerText.textContent = "⚠️ Medium Risk Email";
  } else {
    riskBanner.classList.add("risk-low");
    riskBannerText.textContent = "✅ Low Risk Email";
  }
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();

  const sender_email = document.getElementById("sender_email").value.trim();
  const subject = document.getElementById("subject").value.trim();
  const body = document.getElementById("body").value.trim();

  try {
    const response = await fetch("http://127.0.0.1:5055/analyze", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ sender_email, subject, body }),
    });

    const data = await response.json();

    verdictEl.textContent = data.verdict;
    scoreEl.textContent = `${data.risk_score}/100`;
    domainEl.textContent = data.sender_domain || "-";

    flagsList.innerHTML = "";

    if (data.flags.length === 0) {
      const li = document.createElement("li");
      li.textContent = "No obvious phishing red flags were detected.";
      flagsList.appendChild(li);
    } else {
      data.flags.forEach((flag) => {
        const li = document.createElement("li");
        li.textContent = flag;
        flagsList.appendChild(li);
      });
    }

    updateRiskBanner(data.verdict);
    plainExplanation.textContent = buildExplanation(data);

    resultCard.classList.remove("hidden");
  } catch (error) {
    alert("Could not connect to backend. Make sure Flask is running on port 5055.");
    console.error(error);
  }
});

/* Floating ScamBot Widget */
const chatLauncher = document.getElementById("chatLauncher");
const chatWidget = document.getElementById("chatWidget");
const closeChat = document.getElementById("closeChat");
const chatBody = document.getElementById("chatBody");
const chatInput = document.getElementById("chatInput");
const sendChat = document.getElementById("sendChat");

chatLauncher.addEventListener("click", () => {
  chatWidget.classList.remove("hidden");
});

closeChat.addEventListener("click", () => {
  chatWidget.classList.add("hidden");
});

function addBotMessage(text) {
  const wrapper = document.createElement("div");
  wrapper.className = "bot-msg";
  wrapper.innerHTML = `
    <span class="msg-time">Now</span>
    <p>${text}</p>
  `;
  chatBody.appendChild(wrapper);
  chatBody.scrollTop = chatBody.scrollHeight;
}

function addUserMessage(text) {
  const wrapper = document.createElement("div");
  wrapper.className = "user-msg";
  wrapper.innerHTML = `
    <span class="msg-time">You</span>
    <p>${text}</p>
  `;
  chatBody.appendChild(wrapper);
  chatBody.scrollTop = chatBody.scrollHeight;
}

function getCurrentEmailContext() {
  const sender = document.getElementById("sender_email")?.value?.trim() || "";
  const subject = document.getElementById("subject")?.value?.trim() || "";
  const body = document.getElementById("body")?.value?.trim() || "";

  return { sender, subject, body };
}

function getCurrentUrlContext() {
  const urlField =
    document.getElementById("url_input") ||
    document.getElementById("url") ||
    document.getElementById("website_url");

  return urlField ? urlField.value.trim() : "";
}

function handleQuickAction(action) {
  if (action === "email-check") {
    const { sender, subject, body } = getCurrentEmailContext();

    if (!sender && !subject && !body) {
      addBotMessage("I can’t find an email filled in yet. Paste an email first, then click Analyze Current Email.");
      return;
    }

    addBotMessage(
      `Here’s what I found in your current email:<br><br>
      <strong>Sender:</strong> ${sender || "Not entered"}<br>
      <strong>Subject:</strong> ${subject || "Not entered"}<br><br>
      I recommend clicking the main <strong>Analyze Email</strong> button to get the full phishing score.`
    );
  }

  if (action === "url-check") {
    const currentUrl = getCurrentUrlContext();

    if (!currentUrl) {
      addBotMessage("I can’t find a URL field yet. If you already built a URL checker, make sure its input id is <strong>url_input</strong>, <strong>url</strong>, or <strong>website_url</strong>.");
      return;
    }

    let msg = `Current URL found: <strong>${currentUrl}</strong><br><br>`;

    if (currentUrl.includes("@")) {
      msg += "⚠️ This URL contains an @ symbol, which can be suspicious.<br>";
    }
    if (currentUrl.includes("bit.ly") || currentUrl.includes("tinyurl")) {
      msg += "⚠️ This looks like a shortened URL.<br>";
    }
    if (currentUrl.startsWith("http://")) {
      msg += "⚠️ This is not using HTTPS.<br>";
    }
    if (!msg.includes("⚠️")) {
      msg += "No obvious URL red flags from this quick scan.";
    }

    addBotMessage(msg);
  }

  if (action === "quiz-start") {
    addBotMessage(
      `🎯 <strong>Scam Quiz:</strong><br><br>
      Which is the biggest red flag?<br><br>
      A. Company domain matches website<br>
      B. "Selected without interview"<br>
      C. Clear job description<br><br>
      Type A, B, or C.`
    );
  }

  if (action === "tips") {
    addBotMessage(
      `✅ <strong>Safety Tips:</strong><br><br>
      • Never pay for a job<br>
      • Verify sender domain<br>
      • Don’t share private info early<br>
      • Be careful with urgency language<br>
      • Check company website independently`
    );
  }
}

document.querySelectorAll(".quick-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    handleQuickAction(btn.dataset.action);
  });
});

function respondToChat(message) {
  const msg = message.toLowerCase().trim();

  if (msg === "b") {
    addBotMessage("✅ Correct. “Selected without interview” is a major phishing/job scam red flag.");
    return;
  }

  if (msg === "a" || msg === "c") {
    addBotMessage("❌ Not quite. The strongest red flag there was <strong>B: selected without interview</strong>.");
    return;
  }

  if (msg.includes("analyze email")) {
    handleQuickAction("email-check");
    return;
  }

  if (msg.includes("check url")) {
    handleQuickAction("url-check");
    return;
  }

  if (msg.includes("tips")) {
    handleQuickAction("tips");
    return;
  }

  if (msg.includes("scam") || msg.includes("phishing")) {
    addBotMessage(
      `Phishing emails usually show one or more of these patterns:<br><br>
      • urgency<br>
      • fake recruiter/company branding<br>
      • mismatched sender domain<br>
      • requests for credentials or personal info<br>
      • strange interview or payment process`
    );
    return;
  }

  if (msg.includes("job") || msg.includes("interview")) {
    addBotMessage(
      `For job scams, watch for:<br><br>
      • selected without interview<br>
      • Telegram/Teams setup pressure<br>
      • no official company domain<br>
      • unrealistic salary<br>
      • requests for ID or bank details too early`
    );
    return;
  }

  addBotMessage(
    `I can help with:<br><br>
    • Analyze Current Email<br>
    • Check Current URL<br>
    • Scam Quiz<br>
    • Safety Tips<br><br>
    Try typing: <strong>analyze email</strong>, <strong>check url</strong>, or <strong>tips</strong>.`
  );
}

sendChat.addEventListener("click", () => {
  const text = chatInput.value.trim();
  if (!text) return;

  addUserMessage(text);
  chatInput.value = "";
  respondToChat(text);
});

chatInput.addEventListener("keypress", (e) => {
  if (e.key === "Enter") {
    sendChat.click();
  }
});