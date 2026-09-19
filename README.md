# ScamShield AI — Explainable Threat Defense

> **AI-Powered Threat Analysis & Explainable Scam Intelligence**  
> First Commit Hackathon — Target: **AWS "Ship It" Track**

---

## 1. The Problem

Digital fraud across India has evolved from obvious spam into highly targeted, multi-stage social engineering campaigns:
- **Electricity Disconnection Threats**: Urgent warnings threatening immediate power cutoffs tonight unless a fake officer is called.
- **Urgent PAN / Bank KYC Suspensions**: Deceptive warnings claiming bank accounts or SIM cards will be permanently blocked within hours.
- **LPG Gas Subsidy Phishing**: Lures promising pending subsidies to trick victims into sharing identity documents or NetBanking details.
- **Reverse UPI Collect Traps**: Deceptive collect requests where victims are tricked into entering their UPI PIN under the impression of receiving money.
- **Obfuscated Shortened Links**: Services like `bit.ly` that conceal malicious destinations from casual inspection.

Victims are overwhelmed by technical jargon, while conventional scanners provide binary "Safe/Malicious" labels without explaining **what the attacker wants them to do**.

---

## 2. The ScamShield AI Solution

ScamShield AI is a **web/browser-first explainable threat defense platform**. Instead of acting as just another URL scanner, ScamShield answers four vital human questions:

1. **What is this trying to make you do?** (Demanded action: OTP, UPI PIN, credentials, APK installation).
2. **Why is it suspicious?** (Manipulative tactics: artificial urgency, authority impersonation, threat of disconnection).
3. **What could happen if you comply?** (Concrete risk: account takeover, unauthorized electronic fund transfer).
4. **What should you do right now?** (Prioritized, actionable DO NOT and DO directives).

---

## 3. Core User Flow

```
[User Pastes Communication / URL]
               │
               ▼
   [INSPECT COMMUNICATION]
               │
               ▼
┌────────────────────────────────────────────────────────┐
│  1. Risk Verdict & Calibrated Score (0 - 100)          │
│  2. Demanded Action & Pressure Level                   │
│  3. Plain-Language Explanation & Warning Signs         │
│  4. Grounded Attack Progression (Scam DNA Kill Chain)  │
│  5. Actionable Guidance (DO NOT vs DO Columns)         │
│  6. Technical Forensics & Heuristic Finding IDs        │
└────────────────────────────────────────────────────────┘
```

---

## 4. Minimizing User Effort

- **Zero-Install & Zero-Plugin**: Works directly in any standard mobile or desktop web browser.
- **Human-First Language**: Translates cryptic cybersecurity jargon into clear, reassuring guidance with familiar Indian contextual terms.
- **Interactive Safe Link Gateway (`/safe-link`)**: Allows users to inspect untrusted URLs safely without clicking or triggering redirects.
- **One-Click Action Directives**: Copyable safety instructions and direct links to the National Cybercrime Portal (`cybercrime.gov.in` / `1930`).

---

## 5. The Role of AI (Google Gemini 2.5 Flash)

The AI layer is strictly **contextual and explainable**:
- **Attacker Intent Synthesis**: Extracts the attacker's underlying objective.
- **Psychological Manipulation Identification**: Identifies manufactured panic, fear of police/arrest ("Digital Arrest"), and authority pretexting.
- **Strict Anti-Hallucination Evidence Grounding**: Every phrase the AI cites as evidence must be validated as an exact substring of the user's input text; hallucinated quotes are automatically rejected.
- **Backend-Only Security**: Gemini runs exclusively on the server-side / Lambda backend. The API key is never exposed to client-side code or git.

---

## 6. Authoritative Deterministic Security Engine

The deterministic security engine serves as **ground truth** and cannot be overridden by AI:
- **21 Precision Threat Detectors**: Regex patterns and heuristics tuned for Indian fraud patterns (OTP theft, reverse UPI collect, electricity threats, courier seizures, SIM deactivation, malicious APKs, homoglyphs, and non-standard TLDs).
- **Domain Intelligence**: Deep URL parsing that detects look-alikes, IP hosts, subdomain stacking, and deceptive paths.
- **Authoritative Whitelisting**: Protects legitimate banking alerts (masked accounts with balance notifications) and RFC example domains from false positives.

---

## 7. Multi-Signal Risk Fusion

Final risk scores (0.0 to 100.0) and categorical verdicts are synthesized through a multi-stage fusion algorithm:

$$\text{Final Score} = \text{Blend}(\text{Deterministic Signals}, \text{AI Contextual Weights})$$

- **Hard Security Floors**: Critical findings (e.g. explicit OTP solicitation or brand mismatch) enforce minimum score floors ($\ge 75.0$), ensuring severe threats cannot be downgraded.
- **Calibrated Verdict Bands**:
  - `KNOWN_MALICIOUS`: Confirmed threat intelligence hit.
  - `HIGH_RISK`: Clear credential/payment trap or brand mismatch ($\ge 60.0$).
  - `SUSPICIOUS`: Multiple coercive cues ($\ge 40.0$).
  - `UNKNOWN_UNVERIFIED`: Arbitrary unverified destination or shortened link ($20.0 - 39.0$).
  - `LOW_RISK`: Established domain or low-level signal ($10.0 - 19.0$).
  - `BENIGN`: Normal personal or transactional communication ($< 10.0$).

---

## 8. Evidence & Explainability (NO EVIDENCE = NO CLAIM)

ScamShield enforces a strict forensic consistency rule:
- If a security stage or demanded action is not proven by deterministic or validated semantic evidence, **it is not rendered**.
- A phrase like *"within 15 minutes"* establishes time sensitivity, but does **not** by itself establish fraud or credential theft.
- `"No Direct Action Demanded"` will never coexist with an `"Unauthorized Action"` attack chain step.

---

## 9. Safe Link Gateway (`/safe-link`)

A specialized zero-click destination inspector:
- Checks shortened URLs (e.g. `bit.ly`, `tinyurl.com`) and unverified domains.
- Core Rule: **UNKNOWN / UNVERIFIED $\neq$ SAFE**.
- If a shortener cannot be resolved, ScamShield displays an amber warning: **`DESTINATION UNVERIFIED`** rather than falsely claiming the link is safe.

---

## 10. Privacy & Security Design

- **Stateless & Memory-Only**: Analyzes text in ephemeral memory; no permanent personally identifiable information (PII) is stored.
- **Input Bounding**: Max message length enforced at 4,000 characters to prevent buffer and denial-of-service abuse.
- **SSRF & Private IP Blocking**: Outbound URL fetching blocks loopback (`127.0.0.1`), private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and cloud metadata endpoints (`169.254.169.254`).
- **Rate Limiting**: Throttling controls on API Gateway (20 req/s, 50 burst).

---

## 11. Technology Stack

- **Frontend**: Next.js 15 (App Router, Server & Client Components), Tailwind CSS, Lucide Icons, Space Grotesk typography.
- **Backend Compute**: Python 3.12, AWS Lambda, FastAPI / Serverless Proxy Handler.
- **AI Engine**: Google Gemini 2.5 Flash via `google-genai` SDK with Pydantic structured output schemas.
- **Infrastructure as Code**: AWS SAM (Serverless Application Model), CloudFormation.
- **Testing**: Pytest, ESLint, Chrome Browser Subagent.

---

## 12. Local Setup & Quickstart

### Prerequisites
- Node.js 18+ and npm
- Python 3.12+ (or Python 3.11/3.14 with venv)

### 1. Backend Setup
```bash
# Navigate to backend directory
cd backend

# Install dependencies
pip install -r requirements.txt

# Start local serverless emulator
python src/server.py
```
*Backend runs at `http://localhost:8000` (Endpoints: `POST /analyze`, `GET /health`)*.

### 2. Frontend Setup
```bash
# Navigate to frontend directory
cd frontend

# Install npm dependencies
npm install

# Start development server
npm run dev
```
*Frontend runs at `http://localhost:3000`*.

---

## 13. Environment Variables

Reference templates are maintained in `.env.example`, `backend/.env.example`, and `frontend/.env.example`.

| Variable | Target | Description | Example / Default |
|---|---|---|---|
| `NEXT_PUBLIC_API_BASE_URL` | Frontend | URL of backend API Gateway or local server | `http://localhost:8000` |
| `GEMINI_API_KEY` | Backend Only | Google Gemini API Key | `YOUR_GEMINI_API_KEY` |
| `GEMINI_MODEL_ID` | Backend Only | Model ID | `gemini-2.5-flash` |
| `GOOGLE_WEB_RISK_API_KEY` | Backend Only | Optional Web Risk API Key | `YOUR_WEB_RISK_KEY` |
| `ALLOWED_ORIGINS` | Backend Only | CORS whitelist | `*` (or Amplify domain) |
| `AWS_REGION` | Infrastructure | Target deployment region | `us-east-1` |

> [!CAUTION]
> Never put API keys or secrets in `NEXT_PUBLIC_*` variables. `GEMINI_API_KEY` must remain strictly server-side.

---

## 14. AWS Deployment Architecture (Ship It Track)

ScamShield AI utilizes the smallest practical, serverless AWS footprint:

```
Browser
  ↓ HTTPS
AWS Amplify Hosting (Next.js 15 SSR/Edge)
  ↓ HTTPS
Amazon API Gateway (REST API /prod, Throttled)
  ↓ Lambda Proxy
AWS Lambda Function (Python 3.12, 512 MB, 30s timeout)
  ↓
Deterministic Security Engine + Google Gemini 2.5 Flash
  ↓
Risk Fusion Algorithm
  ↓
Amazon DynamoDB (PAY_PER_REQUEST, $0 when idle)
```

- **Zero Idle Costs**: No EC2 instances, no RDS databases, no NAT Gateways, no provisioned concurrency, and no load balancers.
- **Cost Safety**: When idle, the architecture incurs no compute hourly charges.

---

## 15. AWS Services Used & Responsibilities

1. **AWS Lambda (`AnalyzeFunction`)**: Executes stateless threat detection and intent reasoning on-demand within 512 MB memory limits.
2. **Amazon API Gateway (`ScamShieldApi`)**: Exposes public HTTPS endpoints (`/analyze`, `/health`) with built-in CORS and request throttling.
3. **AWS Amplify Hosting**: Serves the Next.js frontend with automated edge caching and SSL certificates.
4. **Amazon DynamoDB (`ReportsTable`)**: Optional on-demand storage for threat reports (`PAY_PER_REQUEST` billing mode).
5. **Amazon CloudWatch**: Retains execution logs with 7-day log expiration.

---

## 16. Gemini Configuration & Offline Fallback

- **Server-Side Parameter**: In AWS SAM (`infrastructure/template.yaml`), the key is supplied via parameter `GeminiApiKey` with `NoEcho: true`.
- **Automated Fallback**: If no Gemini API key is configured or the API experiences an outage, ScamShield automatically activates the **Deterministic Intent Reasoner**, ensuring user analyses never fail or return blank panels.

---

## 17. Testing & Verification

- **Automated Regression Suite**: 205 passed unit tests (`pytest backend/tests/unit/`).
- **Forensic Consistency Matrix**: 7/7 passed tests verifying that verdicts, demanded actions, kill chains, and evidence remain internally consistent across benign, urgency-only, OTP, LPG scam, and shortened URL scenarios.
- **Frontend Code Quality**: `npm run lint` passes with zero ESLint warnings; `npm run build` generates production bundle cleanly.
- **Real Browser Verification**: Live Chrome browser testing verified end-to-end rendering on both `/` and `/safe-link`.

---

## 18. Current Status & Known Limitations

- **AWS Deployment Status**: All deployment assets (`infrastructure/template.yaml`, `.aws-sam/build/AnalyzeFunction`, packaging scripts) have been compiled, linted with `sam validate --lint`, and validated offline. **Live deployment to AWS is pending user authentication of the local AWS CLI session (`aws configure`).**
- **Threat Intelligence**: Without an active Google Web Risk key, live reputation checks gracefully fall back to deterministic domain heuristics.
- **Experimental Android Prototype**: The initial Android notification prototype (`android/`) has been frozen in favor of the web/browser-first MVP.

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
