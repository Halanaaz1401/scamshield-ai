# 🛡️ ScamShield AI

<p align="center">
  <strong>AI-Powered Scam Detection, Threat Analysis & Explainable Security Intelligence</strong>
</p>

<p align="center">
  ScamShield AI analyzes suspicious messages, URLs, and digital communications
  to explain what an attacker is trying to achieve, why the content is suspicious,
  what could happen if the victim complies, and what to do next.
</p>

<p align="center">

![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Next.js](https://img.shields.io/badge/Next.js-15-black?style=for-the-badge&logo=next.js&logoColor=white)
![AWS Lambda](https://img.shields.io/badge/AWS-Lambda-FF9900?style=for-the-badge&logo=awslambda&logoColor=white)
![Amazon API Gateway](https://img.shields.io/badge/AWS-API%20Gateway-FF4F8B?style=for-the-badge&logo=amazonapigateway&logoColor=white)
![Google Gemini](https://img.shields.io/badge/Google-Gemini%202.5%20Flash-8E75C2?style=for-the-badge&logo=google&logoColor=white)

</p>

<p align="center">

**Built for First Commit — Bharat Builds Tour 2026**

**WeMakeDevs × AWS**

</p>

---

## 🚨 The Problem

Digital scams are no longer limited to obvious spam messages.

Attackers increasingly use social engineering techniques that imitate trusted organizations,
create artificial urgency, impersonate authorities, and manipulate victims into taking
dangerous actions.

Examples include:

- Electricity disconnection scams
- Bank and PAN KYC suspension scams
- LPG subsidy phishing
- Courier and parcel seizure scams
- Fake police / "digital arrest" messages
- OTP theft
- UPI payment manipulation
- Malicious APK installation
- Fake customer-support messages
- Credential harvesting
- Shortened and deceptive URLs
- Brand impersonation
- Homoglyph and look-alike domains

The problem is not simply:

> **"Is this message malicious?"**

The more important questions are:

> **What is the attacker trying to make me do?**

> **Why is this suspicious?**

> **What happens if I follow the instructions?**

> **What should I do right now?**

Traditional security tools often expose technical indicators without translating
them into actionable guidance for ordinary users.

---

## 💡 The ScamShield AI Solution

**ScamShield AI** is an explainable threat-defense platform designed to analyze
suspicious communications and URLs.

Instead of producing only:

```text
SAFE
or
MALICIOUS
```

ScamShield attempts to explain the complete threat context.

### ScamShield answers four questions:

| Question | ScamShield Response |
|---|---|
| What is happening? | Identifies suspicious communication patterns |
| What does the attacker want? | Extracts demanded actions and attacker intent |
| Why is it suspicious? | Explains manipulation techniques and technical indicators |
| What should I do? | Provides prioritized defensive guidance |

---

## 🎯 Core User Flow

```text
                USER INPUT
                    │
                    ▼
       ┌─────────────────────────┐
       │ Message / URL / Content │
       └────────────┬────────────┘
                    │
                    ▼
          SECURITY ANALYSIS
                    │
        ┌───────────┴───────────┐
        ▼                       ▼
Deterministic Engine       AI Analysis
        │                       │
        └───────────┬───────────┘
                    ▼
             Risk Fusion
                    │
                    ▼
          Explainable Verdict
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
     Threat      Evidence     Action
     Intent      Analysis     Guidance
```

---

## 🔍 What ScamShield Analyzes

ScamShield currently focuses on several high-risk fraud patterns.

### Social Engineering

- Artificial urgency
- Fear and intimidation
- Authority impersonation
- Threat-based manipulation
- Financial pressure
- Account suspension claims
- Fake government communication

### Credential & Payment Theft

- OTP requests
- UPI PIN manipulation
- Banking credential requests
- Payment collection traps
- KYC phishing
- Account takeover attempts

### Malicious Links

- URL obfuscation
- Shortened URLs
- IP-based hosts
- Suspicious TLDs
- Look-alike domains
- Subdomain stacking
- Suspicious paths

### Malware Delivery

- Malicious APK requests
- Fake application updates
- Courier/package scams
- Unknown download links

---

## 🧠 Explainable Threat Analysis

ScamShield does not stop at a risk score.

For every meaningful finding, the platform attempts to establish:

```text
INPUT
  ↓
OBSERVABLE SIGNAL
  ↓
SECURITY FINDING
  ↓
ATTACKER INTENT
  ↓
POTENTIAL IMPACT
  ↓
DEFENSIVE ACTION
```

For example:

```text
"Your electricity will be disconnected tonight.
Call this number immediately."

          ↓

Artificial urgency
          +
Authority impersonation
          +
Threat of service termination
          ↓

Potential social-engineering attempt
          ↓

User is advised not to call the
unverified number and verify through
an official electricity provider channel.
```

---

## 🤖 AI Layer — Google Gemini

ScamShield AI uses **Google Gemini 2.5 Flash** for contextual analysis.

The AI layer helps identify:

- Attacker intent
- Psychological manipulation
- Social-engineering techniques
- Contextual relationships between suspicious signals
- Human-readable explanations
- Potential attack progression

However, the LLM is **not treated as the sole security authority**.

---

## 🛡️ Deterministic Security Engine

ScamShield contains a deterministic security layer designed to provide
repeatable security signals.

The engine uses:

- Regex-based detectors
- Security heuristics
- URL parsing
- Domain analysis
- Threat-pattern matching
- Indian scam-specific detection rules
- Whitelisting rules
- Input validation

The current implementation contains **21 precision threat detectors**
covering patterns such as:

- OTP theft
- Reverse UPI collect scams
- Electricity scams
- Courier scams
- SIM deactivation
- Malicious APK delivery
- Homoglyph domains
- Suspicious TLDs
- Brand impersonation

---

## ⚖️ Multi-Signal Risk Fusion

ScamShield combines deterministic security signals with contextual AI analysis.

```text
Deterministic Signals
        │
        ├── Threat Patterns
        ├── URL Indicators
        ├── Domain Signals
        └── Security Heuristics
                │
                ▼
          Signal Fusion
                ▲
                │
        AI Contextual Analysis
                │
                ▼
          Final Risk Score
                │
                ▼
       Explainable Verdict
```

### Risk Categories

```text
KNOWN_MALICIOUS
HIGH_RISK
SUSPICIOUS
UNKNOWN_UNVERIFIED
LOW_RISK
BENIGN
```

Critical security findings can enforce minimum risk thresholds so that serious
indicators cannot simply be downgraded by contextual AI output.

---

## 🔬 Evidence-First Explainability

One of ScamShield's core design principles is:

> **NO EVIDENCE = NO CLAIM**

AI-generated evidence must be grounded in the user's submitted content.

The system validates quoted evidence against the original input instead of
blindly trusting generated explanations.

This is intended to reduce:

- Hallucinated evidence
- Unsupported claims
- Incorrect attack-chain stages
- Misleading security explanations

```text
User Input
    ↓
Extracted Evidence
    ↓
Evidence Validation
    ↓
Security Finding
    ↓
Rendered Explanation
```

If a claim cannot be supported by available evidence, the system should not
present it as an established finding.

---

## 🔗 Safe Link Gateway

ScamShield includes a dedicated:

```text
/safe-link
```

workflow for inspecting suspicious URLs.

The objective is to allow users to investigate an untrusted destination
without immediately clicking it.

The system analyzes indicators such as:

- Shortened URLs
- Unverified domains
- IP addresses
- Suspicious paths
- Domain structure
- Look-alike domains

### Important Security Principle

```text
UNKNOWN / UNVERIFIED
        ≠
SAFE
```

If a destination cannot be verified, ScamShield should communicate uncertainty
rather than incorrectly labeling the destination as safe.

---

## 🔐 Security & Privacy

Security is part of the architecture rather than an afterthought.

### Stateless Processing

Message analysis is designed to operate on ephemeral input rather than
requiring permanent storage of user communications.

### Input Bounding

The backend limits message size to reduce abuse and resource exhaustion.

### SSRF Protection

Outbound URL processing blocks:

- Loopback addresses
- Private network ranges
- Cloud metadata endpoints

### Rate Limiting

API requests are throttled to reduce automated abuse.

### Secret Isolation

Sensitive credentials such as:

```text
GEMINI_API_KEY
GOOGLE_WEB_RISK_API_KEY
```

remain server-side.

They must never be exposed through:

```text
NEXT_PUBLIC_*
```

variables or committed to source control.

---

## ☁️ AWS Architecture

For the **Ship It** deployment, ScamShield is designed around a serverless AWS architecture.

```text
                         USER
                           │
                           ▼
                    ┌────────────┐
                    │   Browser  │
                    └─────┬──────┘
                          │ HTTPS
                          ▼
                ┌────────────────────┐
                │ AWS Amplify        │
                │ Next.js Frontend   │
                └─────────┬──────────┘
                          │
                          ▼
                ┌────────────────────┐
                │ Amazon API Gateway │
                │ REST API           │
                │ Rate Limiting      │
                └─────────┬──────────┘
                          │
                          ▼
                ┌────────────────────┐
                │ AWS Lambda         │
                │ Python 3.12        │
                └─────────┬──────────┘
                          │
             ┌────────────┴────────────┐
             ▼                         ▼
    ┌──────────────────┐     ┌──────────────────┐
    │ Deterministic    │     │ Google Gemini    │
    │ Security Engine  │     │ 2.5 Flash        │
    └─────────┬────────┘     └─────────┬────────┘
              │                        │
              └────────────┬───────────┘
                           ▼
                    ┌─────────────┐
                    │ Risk Fusion │
                    └──────┬──────┘
                           ▼
                    Threat Analysis
                           │
                           ▼
                    User Explanation
```

---

## ☁️ AWS Services

| AWS Service | Role |
|---|---|
| **AWS Amplify** | Frontend hosting |
| **Amazon API Gateway** | Public API + throttling |
| **AWS Lambda** | Serverless backend execution |
| **Amazon DynamoDB** | Optional report persistence |
| **Amazon CloudWatch** | Application and Lambda logging |
| **AWS SAM** | Infrastructure as Code |

> Keep this table synchronized with the services that are actually configured
> and deployed in the final submission.

---

## 🏗️ Technology Stack

### Frontend

- Next.js 15
- React
- TypeScript
- Tailwind CSS
- Lucide Icons
- Space Grotesk

### Backend

- Python 3.12
- Serverless Python
- AWS Lambda
- API Gateway

### AI

- Google Gemini 2.5 Flash
- Google GenAI SDK
- Pydantic structured outputs

### AWS

- AWS Lambda
- Amazon API Gateway
- AWS Amplify
- Amazon DynamoDB
- Amazon CloudWatch
- AWS SAM
- CloudFormation

### Testing

- Pytest
- ESLint
- Browser testing

---

## 📊 Product Workflow

```text
┌──────────────────────┐
│ Paste suspicious     │
│ message or URL       │
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ Input normalization  │
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ Deterministic threat │
│ detection            │
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ URL / domain analysis│
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ Gemini contextual    │
│ analysis             │
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ Evidence validation  │
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ Risk fusion          │
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ Explainable result   │
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ Defensive guidance   │
└──────────────────────┘
```

---

## 🖥️ Product Screenshots

> Replace these placeholders with your final screenshots.

### Threat Analysis

![ScamShield Analysis](docs/screenshots/analysis.png)

### Safe Link Gateway

![Safe Link Gateway](docs/screenshots/safe-link.png)

### Threat Explanation

![Threat Explanation](docs/screenshots/explanation.png)

---

## 🎥 Demo

### Live Application

> ADD LIVE URL HERE

### Demo Video

> ADD YOUTUBE DEMO URL HERE

---

## 🧪 Testing & Verification

ScamShield includes automated security and regression testing.

Current validation includes:

- Threat detector testing
- URL analysis
- Scam classification
- Evidence validation
- Risk scoring
- API testing
- Security regression testing
- Frontend linting
- Production build verification
- Browser-level verification

### Backend

```bash
pytest
```

### Frontend

```bash
npm run lint
npm run build
```

---

## 📁 Project Structure

```text
scamshield-ai/
│
├── backend/
│   ├── src/
│   ├── tests/
│   └── requirements.txt
│
├── frontend/
│   ├── app/
│   ├── components/
│   ├── public/
│   └── package.json
│
├── data/
│
├── docs/
│   ├── architecture.md
│   └── demo-script.md
│
├── infrastructure/
│   └── template.yaml
│
├── scripts/
│
├── tests/
│
├── .env.example
├── LICENSE
├── pytest.ini
├── ruff.toml
└── README.md
```

---

## ⚡ Quick Start

### Prerequisites

- Node.js 18+
- Python 3.12+
- npm
- Git

### Clone

```bash
git clone https://github.com/Halanaaz1401/scamshield-ai.git
cd scamshield-ai
```

### Backend

```bash
cd backend
pip install -r requirements.txt
python src/server.py
```

Backend:

```text
http://localhost:8000
```

### Frontend

Open another terminal:

```bash
cd frontend
npm install
npm run dev
```

Frontend:

```text
http://localhost:3000
```

---

## 🔑 Environment Variables

Create the required environment files using the provided templates.

Example:

```env
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000

GEMINI_API_KEY=YOUR_GEMINI_API_KEY

GEMINI_MODEL_ID=gemini-2.5-flash

GOOGLE_WEB_RISK_API_KEY=YOUR_WEB_RISK_KEY

ALLOWED_ORIGINS=*
```

### Security Notice

Never commit:

- API keys
- AWS credentials
- Gemini credentials
- Web Risk credentials
- Database credentials
- `.env` files containing secrets

---

## 📴 Deterministic Fallback

ScamShield is designed so that the security analysis does not completely
depend on the availability of the generative AI layer.

If Gemini is unavailable or no Gemini API key is configured, the deterministic
security engine can continue providing rule-based analysis.

```text
Gemini Available
       │
       ▼
AI + Deterministic Analysis
       │
       ▼
Explainable Result


Gemini Unavailable
       │
       ▼
Deterministic Analysis
       │
       ▼
Security Result
```

This design reduces dependence on a single AI service.

---

## ⚠️ Limitations

ScamShield is a defensive security analysis tool.

It does not guarantee that:

- A message is completely safe
- A URL is completely harmless
- A detected scam is confirmed criminal activity
- A threat that is not detected does not exist

Risk classifications should therefore be treated as **security guidance**, not
as absolute guarantees.

---

## 🚀 Future Roadmap

Potential future improvements include:

- Real-time browser protection
- Browser extension
- Mobile share-sheet integration
- Voice scam detection
- Deepfake / voice-cloning detection
- Expanded threat-intelligence feeds
- Multilingual Indian-language analysis
- SMS and messaging-app integration
- Community threat reporting
- Reputation intelligence
- Automated URL sandboxing
- Security researcher dashboard

---

## 🏆 Hackathon Alignment

### First Commit — Bharat Builds Tour 2026

ScamShield AI was built for the **First Commit** hackathon in the
Bharat Builds Tour organized by WeMakeDevs in collaboration with AWS.

### Problem

Digital scams increasingly rely on social engineering, impersonation,
urgency, malicious links, and payment manipulation.

### Build

ScamShield combines:

```text
Deterministic Security
        +
AI Contextual Analysis
        +
Evidence Validation
        +
Risk Fusion
        +
Actionable Guidance
```

### AWS

The serverless architecture uses AWS infrastructure including:

```text
AWS Amplify
     ↓
API Gateway
     ↓
Lambda
     ↓
Security Engine
     ↓
Gemini
     ↓
Risk Fusion
```

> Update this section so that every AWS claim exactly matches what is actually
> implemented and demonstrated in the final submission.

---

## 🧠 Design Philosophy

ScamShield follows a simple principle:

> **Detection without explanation is not enough.**

A useful security product should help the user understand:

```text
WHAT
 ↓
WHY
 ↓
IMPACT
 ↓
ACTION
```

The goal is not simply to tell someone:

> "This looks dangerous."

The goal is to explain:

> "Here is the evidence, here is the attacker's likely objective,
> here is what could happen, and here is what you should avoid doing."

---

## 👩‍💻 Author

**Hala Naaz**

Cybersecurity Professional | GenAI & AI Security | Security Research

GitHub:  
https://github.com/Halanaaz1401

---

## 📄 License

This project is licensed under the MIT License.

See [`LICENSE`](LICENSE) for details.

---

<p align="center">

<strong>ScamShield AI</strong>

<br>

<em>Detect. Explain. Defend.</em>

</p>
