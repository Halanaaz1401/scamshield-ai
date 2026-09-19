# ScamShield AI — End-to-End System Architecture

## Architecture Overview

ScamShield AI is an explainable threat intelligence platform engineered to analyze unsolicited communications (SMS, WhatsApp, emails, social engineering messages) and untrusted web links.

The architecture is strictly **browser-first, serverless, and layered**, ensuring zero idle operating costs while delivering deterministic security verification alongside contextual AI intent reasoning.

```
                    ┌─────────────────────────┐
                    │     Client Browser      │
                    │ (Next.js 15 / Tailwind) │
                    └────────────┬────────────┘
                                 │
                                 │ HTTPS (Static & Edge SSR)
                                 ▼
                    ┌─────────────────────────┐
                    │   AWS Amplify Hosting   │
                    │  (Edge Global CDN / SSL)│
                    └────────────┬────────────┘
                                 │
                                 │ HTTPS REST API Calls
                                 ▼
                    ┌─────────────────────────┐
                    │  Amazon API Gateway     │
                    │ (Regional REST, Throttled)
                    └────────────┬────────────┘
                                 │
                                 │ Lambda Proxy Event
                                 ▼
                    ┌─────────────────────────┐
                    │    AWS Lambda Worker    │
                    │ (Python 3.12 / 512 MB)  │
                    └────────────┬────────────┘
                                 │
         ┌───────────────────────┴───────────────────────┐
         │                                               │
         ▼                                               ▼
┌──────────────────────────────┐        ┌──────────────────────────────┐
│ Deterministic Security Engine│        │  AI Intent Reasoning Layer   │
│  (21 Regex & URL Heuristics) │        │  (Google Gemini 2.5 Flash)   │
│  • High-risk keyword scans   │        │  • Plain-language intent     │
│  • Brand mismatch detection  │        │  • Psychological tactics     │
│  • TLD & Shortener heuristics│        │  • Strict evidence grounding │
└──────────────┬───────────────┘        └──────────────┬───────────────┘
               │                                       │
               └───────────────────┬───────────────────┘
                                   │
                                   ▼
                    ┌─────────────────────────┐
                    │   Risk Fusion Engine    │
                    │  (Authoritative Scoring)│
                    │  • Multi-signal weights │
                    │  • Hard security floors │
                    │  • Grounded attack chain│
                    └────────────┬────────────┘
                                 │
                                 │ Optional Threat Telemetry
                                 ▼
                    ┌─────────────────────────┐
                    │     Amazon DynamoDB     │
                    │(PAY_PER_REQUEST, $0 Idle│
                    └─────────────────────────┘
```

---

## 1. Clear Separation of Layers

### Layer 1: Authoritative Deterministic Security Engine
The deterministic engine is the foundational security layer and serves as **uncompromisable ground truth**:
- It inspects raw message text, character spacing, Unicode homoglyphs, and embedded URLs.
- It detects known threat patterns: OTP solicitation (`IND_OTP_SOLICIT`), reverse UPI fraud (`IND_REVERSE_UPI`), electricity disconnection threats (`IND_ELECTRICITY_DISCONNECT`), and direct APK downloads (`IND_MALICIOUS_APK`).
- It extracts objective facts (e.g. hostnames, TLDs, parameters).
- **Rule**: The deterministic engine cannot be overridden or hallucinated away by LLM outputs.

### Layer 2: AI Intent Reasoning Layer (Gemini 2.5 Flash)
The AI layer provides **explainability and human-centered context**:
- It deduces what the adversary is trying to make the recipient do (e.g. submit credentials, make a panic transfer, install a file).
- It labels psychological coercion (e.g. urgency coercion, fear of police/arrest, authority pretexting).
- **Anti-Hallucination Grounding Rule**: Every phrase the AI cites as evidence must match verbatim text in the input message. If ungrounded phrases are generated, the model output is rejected and falls back to deterministic intent heuristics.
- **Backend Isolation**: Operates exclusively in server-side Lambda memory. No API keys are exposed to the client or git.

### Layer 3: Risk Fusion Engine
The fusion layer combines technical findings with semantic intent:
- Synthesizes a calibrated risk score between `0.0` and `100.0`.
- Categorizes the communication into standard bands: `BENIGN`, `LOW_RISK`, `UNKNOWN_UNVERIFIED`, `SUSPICIOUS`, `HIGH_RISK`, `KNOWN_MALICIOUS`.
- **Enforces Security Floors**: If a critical indicator is present (e.g. asking for NetBanking password or OTP), the score is floored at $\ge 75.0$, preventing any model from falsely downgrading genuine attacks.
- **Strict Evidence Rule**: An attack stage is only rendered if an explicit finding ID and verified text snippet exists. If no action is demanded, no "Unauthorized Action" stage is ever synthesized.

---

## 2. Why AI Does Not Replace Technical Checks

In cybersecurity, large language models are susceptible to prompt injection, semantic manipulation, and hallucinations. ScamShield AI addresses this by ensuring:
1. **The LLM does not invent reputation**: The model cannot declare an unknown domain safe or malicious based on guesswork.
2. **The LLM does not invent evidence**: Text quotes must pass string-membership verification.
3. **Deterministic signals are authoritative**: Hardcoded indicators for credential harvesting and financial traps always dictate minimum threat posture.
4. **Graceful Offline Degradation**: When AI APIs are unreachable, the deterministic rule engine continues to provide complete, structured verdicts and recommendations without disruption.

---

## 3. Serverless Cloud Implementation (AWS "Ship It")

| Component | AWS Service | Sizing & Configuration | Cost Control Mechanism |
|---|---|---|---|
| **Frontend** | AWS Amplify Hosting | Next.js 15 SSR / Edge | Usage-based Free Tier, global edge caching |
| **API Entrypoint** | Amazon API Gateway | Regional REST API (`/prod`) | 20 req/s rate limit, 50 burst; no hourly charge |
| **Compute** | AWS Lambda | Python 3.12, 512 MB, 30s timeout | Zero cost when idle (1M free requests/month) |
| **Persistence** | Amazon DynamoDB | `PAY_PER_REQUEST` On-Demand | Zero fixed hourly fee, only pays per write/read |
| **Logging** | Amazon CloudWatch | 7-day log retention group | Automatic expiration prevents log storage growth |

---

## 4. Security & Trust Boundaries

```
[Untrusted Client Input]
          │
          ▼
[Input Validation Layer] ──── Reject if length > 4000 chars or invalid schema
          │
          ▼
[Private CIDR / SSRF Filter] ─ Block loopback, RFC1918 IPs, 169.254.169.254
          │
          ▼
[Deterministic Regex Scanner] ─ Fast O(N) regex evaluation on normalized text
          │
          ▼
[Isolated AI Subprocess] ──── Ephemeral prompt with strict output JSON schema
          │
          ▼
[Fusion & Sanitization] ───── Pydantic validation, HTML-safe escaping in React
          │
          ▼
[Structured Response to Client]
```
