# 🛡️ Phishing Link Detector — Chrome Extension

> An AI-powered Chrome extension that detects phishing links within AI chatbot interfaces using machine learning, Explainable AI, and real-time threat intelligence.

---

## 📌 Overview

This Chrome extension monitors hyperlinks on any webpage — with a specific focus on AI chatbot interfaces such as **ChatGPT, Claude, Gemini, and Perplexity** — and automatically flags potential phishing URLs in real time.

Unlike existing phishing detectors that scan the page you are currently visiting, this extension addresses a new and underexplored threat: **phishing links delivered through AI chatbot responses**. When a chatbot suggests a malicious link, users are significantly less likely to question it. This extension fills that gap.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🤖 **ML Detection** | Logistic regression model trained on 2,200 URLs with 16 extracted features |
| 🔍 **Explainable AI (XAI)** | Tells the user exactly *why* a link was flagged in plain English |
| 🔤 **Typosquatting Detection** | Levenshtein distance algorithm catches domains like `paypa1.com` (1 edit from `paypal`) |
| 🗓️ **WHOIS Domain Age** | Flags newly registered domains — a strong phishing indicator |
| 🗄️ **OpenPhish Database** | Real-time check against 30,000+ confirmed phishing URLs (no API key needed) |
| 🔬 **PhishTank & VirusTotal** | Optional third-party database checks (free API keys) |
| ✅ **Trusted Domain Whitelist** | 60+ major domains whitelisted to eliminate false positives |
| 🎯 **Chatbot-Aware Scanning** | Specifically monitors ChatGPT, Claude, Gemini, Perplexity, Copilot |
| 🚩 **User Report Button** | Report suspicious domains to your personal blocklist |
| 📋 **Reports Dashboard** | View, search, and export all reported domains to CSV |
| 🔔 **Browser Notifications** | Native Chrome notification when phishing links are detected |
| 🏠 **Page Domain Scanning** | Scores the current page's own domain to catch scam sites with no links |

---

## 🏗️ Architecture

```
User visits a page
        ↓
Content Script (content.js)
        ↓
┌─────────────────────────────────────┐
│  1. Trusted Domain Whitelist        │ → Skip (no false positives)
│  2. User Reported Domains           │ → Instant flag (100%)
│  3. ML Model — 16 URL features      │ → Phishing probability score
│  4. Typosquatting (Levenshtein)     │ → Brand impersonation check
│  5. OpenPhish / PhishTank Database  │ → Confirmed phishing check
│  6. WHOIS Domain Age                │ → New domain = suspicious
└─────────────────────────────────────┘
        ↓
Highlight flagged links red on page
Show XAI reasons in tooltip + popup
Send browser notification
```

---

## 📁 Project Structure

```
phishing-extension/
│
├── manifest.json          # Chrome extension configuration (Manifest V3)
├── background.js          # Service worker — OpenPhish feed, WHOIS, notifications
├── content.js             # Page scanner — injected into every webpage
├── featureExtractor.js    # URL feature extraction + XAI reason generation
├── model.js               # Logistic regression ML model (trained weights)
├── popup.html             # Extension popup UI
├── popup.js               # Popup logic and scan result rendering
├── reports.html           # Reported domains dashboard
├── reports.js             # Reports page logic
├── styles.css             # Phishing link highlight styles
│
├── demo_chatbot.html      # NexusAI demo chatbot for testing/presentation
├── test_page.html         # Static test page with known phishing/safe links
│
├── train_model.py         # Python script — trains logistic regression model
└── phishing_dataset.csv   # Training dataset (2,200 URLs, 16 features)
```

---

## 🧠 Machine Learning Model

The ML model is a **logistic regression classifier** trained in Python using scikit-learn.

### Features extracted from every URL:

| Feature | Description |
|---|---|
| `urlLength` | Total URL character length |
| `numDots` | Number of dots in hostname |
| `numHyphens` | Number of hyphens in hostname |
| `hasHttps` | Whether HTTPS is used |
| `hasIpAddress` | Whether hostname is a raw IP |
| `hasAtSymbol` | Presence of @ in URL |
| `suspiciousKeywordCount` | Brand keywords in domain |
| `numSubdomains` | Depth of subdomain nesting |
| `hasEncoding` | Encoded/obfuscated characters |
| `domainLength` | Length of domain name |
| `hasDigitsInDomain` | Digit substitution (e.g. `paypa1`) |
| `brandInSubdomain` | Brand name in subdomain only |
| `isTyposquat` | Levenshtein distance from known brands |
| `hasSuspiciousTld` | Abused TLDs (.xyz, .top, .tk etc.) |
| `scamKeywordCount` | Scam-specific words in domain |
| `rootDomainKeywordCount` | Suspicious words in root domain |

### Training results:

```
Accuracy:             99.32%
Precision:            99.31%
Recall:               99.31%
F1 Score:             99.31%
AUC-ROC:              99.97%
False Positive Rate:   0.00%
Training set:         1,760 URLs
Test set:               440 URLs
Cross-validation:     99.32% (±0.45%)
```

---

## 🚀 Installation

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/phishing-link-detector.git
```

### 2. Load into Chrome
1. Open Chrome and go to `chrome://extensions`
2. Enable **Developer Mode** (top right toggle)
3. Click **Load unpacked**
4. Select the cloned folder
5. The extension will appear in your toolbar

### 3. Enable file URL access (for demo chatbot)
1. Go to `chrome://extensions` → click **Details** on the extension
2. Enable **Allow access to file URLs**

---

## 🧪 Testing

### Demo Chatbot
Open `demo_chatbot.html` in Chrome. Use the scenario buttons (PayPal login, Microsoft support, Bank account help etc.) to simulate phishing link delivery through a chatbot interface.

### Test Page
Open `test_page.html` in Chrome. Contains 8 known phishing URLs and 8 safe URLs for controlled testing.

### Real Chatbots
Navigate to ChatGPT, Claude, Gemini or Perplexity. The extension will automatically switch to chatbot monitoring mode (visible in the popup badge).

---

## 🔑 Optional API Keys

The extension works fully without any API keys. To enable additional database checks:

| Service | Where to register | Where to add key |
|---|---|---|
| PhishTank | [phishtank.org](https://www.phishtank.com/api_register.php) | `background.js` → `PHISHTANK_API_KEY` |
| VirusTotal | [virustotal.com](https://www.virustotal.com/gui/join-us) | `background.js` → `VIRUSTOTAL_API_KEY` |

---

## 🐍 Training the Model (Python)

To retrain the model with updated data:

```bash
pip install scikit-learn pandas numpy matplotlib
python train_model.py
```

This will:
- Train a logistic regression classifier on `phishing_dataset.csv`
- Output updated weights directly into `model.js`
- Generate `evaluation.txt` with performance metrics
- Generate `training_results.png` with ROC curve and feature importance charts

---

## 🛠️ Technologies Used

| Layer | Technology |
|---|---|
| Browser Extension | JavaScript, HTML, CSS (Manifest V3) |
| ML Training | Python, scikit-learn, pandas, numpy |
| ML Inference | Client-side JavaScript (logistic regression) |
| Phishing Database | OpenPhish (free public feed) |
| Domain Intelligence | WHOIS API (domaininfo.shreshtait.com) |

---

## 📊 Comparison with Existing Solutions

| Feature | This Project | picopalette/phishing-detection-plugin | Phishing-Detection-System |
|---|---|---|---|
| Chatbot interface targeting | ✅ | ❌ | ❌ |
| Explainable AI (XAI) | ✅ | ❌ | ❌ |
| Typosquatting detection | ✅ | ❌ | ❌ |
| WHOIS domain age | ✅ | ❌ | ✅ (Python only) |
| Public phishing database | ✅ | ❌ | ❌ |
| Scans all links on page | ✅ | ❌ | ❌ |
| Trusted domain whitelist | ✅ | ❌ | ❌ |
| Runs fully in browser | ✅ | ✅ | ❌ |
| User report blocklist | ✅ | ❌ | ❌ |

---

## 📄 Academic Context

This project was developed as a Final Year Project at the **University of Greenwich** (2025–2026).

**Research question:** Can a browser extension using machine learning effectively detect phishing links delivered through AI chatbot interfaces, and provide explainable reasoning to improve user cybersecurity awareness?

**Key innovation:** Existing phishing detectors target emails or general web pages. This project specifically addresses the emerging threat of phishing links within AI chatbot responses — a threat surface identified by OX Security and Koi Security in 2025 as actively exploited through a technique termed "Prompt Poaching."

---

## 📜 Licence

This project is submitted for academic assessment at the University of Greenwich. All rights reserved.

---

## 👤 Author

**Meldon**  
BSc Computer Science — University of Greenwich  
Final Year Project, 2025–2026
