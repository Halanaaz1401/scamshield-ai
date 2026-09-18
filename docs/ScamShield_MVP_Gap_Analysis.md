# ScamShield AI — Gap Analysis & MVP Prioritization

## Purpose

This document defines the product gaps identified by comparing ScamShield AI with relevant cybersecurity capabilities in the CarterPerez-dev/Cybersecurity-Projects repository, and prioritizes what should actually be built for the MVP.

The priority is **real problem-solving for Indian users**, not feature count.

---

## 1. Product Goal

ScamShield AI should help an Indian user answer four questions after receiving a suspicious message:

1. Is this dangerous?
2. Why is it suspicious?
3. What is the attacker trying to do?
4. What should I do right now?

Core flow:

```text
Suspicious Message
        ↓
Validation
        ↓
Deterministic Security Detection
        ↓
URL Intelligence
        ↓
Amazon Bedrock
        ↓
Risk Fusion
        ↓
Evidence + Attacker Intent
        ↓
Scam DNA / Attack Path
        ↓
Protective Action
```

---

## 2. Identified Gaps

### GAP 1 — Deep URL Intelligence

**Current state:** ScamShield detects suspicious URLs using signals such as suspicious TLDs, numeric IP URLs, URL shorteners, brand spoofing and suspicious URL patterns.

**Gap:** URL analysis is not yet deep enough to explain *how* a domain is trying to deceive the user.

**Potential capabilities:**
- Typosquatting
- Homoglyph / look-alike character detection
- Brand impersonation
- Suspicious subdomain analysis
- Deceptive URL path analysis
- URL obfuscation detection
- Shortened URL identification

**MVP priority: P0 — HIGH**

Build a lightweight local URL intelligence layer first. Do not build a complete domain intelligence platform.

---

### GAP 2 — Evidence Engine

**Current state:** ScamShield already produces indicators, explanations and red flags.

**Gap:** Every detection should have structured, traceable evidence.

Target model:

```text
Security Signal
      ↓
Evidence
      ↓
Why It Matters
      ↓
Attacker Objective
      ↓
Attack Stage
```

Example:

| Signal | Evidence | Why it matters | Objective |
|---|---|---|---|
| Urgency | "within 10 minutes" | Creates panic and suppresses verification | Force immediate action |
| Credential request | "enter your PIN" | Requests sensitive information | Account compromise |
| Suspicious URL | `sbi-verify-login.xyz` | Possible brand impersonation | Credential theft |

**MVP priority: P0 — HIGH**

This should become the foundation of the `Why We Flagged It` experience.

---

### GAP 3 — Indian Scam Pattern Intelligence

A generic phishing detector does not fully address the scam patterns commonly encountered by Indian users.

MVP scam categories:

```text
Indian Scam Pattern Layer
│
├── UPI / Payment Scam
├── Bank / KYC Scam
├── PAN / Account Suspension Scam
├── Fake Customer Support
├── Courier / Parcel Scam
├── Government / Police Impersonation
├── Job Scam
├── Investment Scam
├── Lottery / Reward Scam
├── Electricity / Utility Scam
└── SIM / KYC Suspension Scam
```

Examples:

```text
Payment request
+ urgency
+ external link
→ high-risk financial scam pattern
```

```text
Bank impersonation
+ KYC/PAN request
+ account suspension threat
→ likely credential/identity theft attempt
```

```text
Fake recruitment
+ registration fee
+ urgency
→ likely job scam
```

**MVP priority: P0 — VERY HIGH**

This is one of the strongest ways to make ScamShield solve a specific Indian problem instead of being another generic phishing classifier.

---

### GAP 4 — Attack-Path Reconstruction

ScamShield already has the Scam DNA concept.

**Gap:** The attack path should be generated from actual detected signals.

Target:

```text
Lure
  ↓
Authority / Trust
  ↓
Urgency
  ↓
Action Request
  ↓
Credential / Payment
  ↓
Attacker Objective
```

Example:

```text
Fake Bank Message
      ↓
KYC Suspension Threat
      ↓
Urgency
      ↓
Login Link
      ↓
Credential Theft
      ↓
Account Takeover
```

**MVP priority: P0 — HIGH**

Do not make this a decorative animation only. It should be backed by detected evidence.

---

### GAP 5 — Threat Intelligence

**Current state:** Detection is primarily based on local security rules + Bedrock reasoning.

Potential architecture:

```text
Extract URL
      ↓
Local URL Intelligence
      ↓
Threat Intelligence Lookup
      ↓
Known Malicious / Suspicious?
      ↓
Evidence
```

Potential intelligence sources should be evaluated based on availability, reliability, licensing and cost.

**MVP priority: P1 — MEDIUM**

First make the local URL intelligence layer reliable. Do not introduce multiple external APIs before the core pipeline works.

---

### GAP 6 — False-Positive Explanation

ScamShield should not only explain why something is dangerous. It should also explain why a low-risk message did not trigger major scam signals.

Example:

```text
LOW RISK

No major scam indicators detected.

✓ No OTP request
✓ No payment request
✓ No credential request
✓ No suspicious URL
✓ No coercive urgency

Still verify unexpected requests independently.
```

**MVP priority: P1 — MEDIUM/HIGH**

This improves user trust and reduces unnecessary fear.

---

### GAP 7 — Uncertainty / Confidence Handling

A risk score should not imply certainty.

ScamShield should distinguish:

```text
Risk Score
```

from:

```text
Evidence / Confidence
```

If evidence is weak or contradictory:

```text
INSUFFICIENT EVIDENCE

The message contains suspicious language,
but there is not enough evidence to confidently
classify it as a scam.
```

**MVP priority: P1 — MEDIUM**

Important for responsible security UX.

---

### GAP 8 — Obfuscation & Adversarial Text Handling

Scammers may deliberately modify text or URLs.

Potential detection:
- unusual spacing
- Unicode look-alikes
- zero-width characters
- altered URLs
- deliberate misspellings
- suspicious character substitutions

Some obfuscation handling already exists in the deterministic layer.

**MVP priority: P1 — MEDIUM**

Improve only where it directly strengthens scam detection.

---

## 3. MVP Priority Matrix

| Gap | Priority | MVP? | Reason |
|---|---:|---:|---|
| Deep URL Intelligence | P0 | YES | Major phishing/scam signal |
| Evidence Engine | P0 | YES | Makes detection explainable |
| Indian Scam Pattern Intelligence | P0 | YES | Direct Indian problem-solving |
| Attack-Path Reconstruction | P0 | YES | Converts signals into understandable attacker flow |
| False-Positive Explanation | P1 | YES if time | Improves user trust |
| Obfuscation Handling | P1 | YES if time | Helps against evasive scams |
| Confidence / Uncertainty | P1 | YES if time | Prevents overclaiming |
| Threat Intelligence | P1 | OPTIONAL | Valuable but external dependency |
| Redirect-chain analysis | P2 | NO | Adds network/safety complexity |
| WHOIS / domain age | P2 | NO | Infrastructure/API overhead |
| Certificate Transparency | P2 | NO | Not necessary for first MVP |
| QR / Quishing scanner | P2 | NO | Scope expansion |
| Custom ML model | P2 | NO | Not needed for current threat model |
| SIEM / network monitoring | P2 | NO | Different product |

---

## 4. Recommended MVP

The MVP should have five major security capabilities.

### 1. Message Scam Detection

Detect:
- OTP requests
- payment requests
- credential harvesting
- urgency
- threats
- impersonation
- reward/lottery
- job scams
- investment scams
- Indian scam patterns

### 2. URL Threat Analysis

Detect:
- suspicious URL
- shortener
- numeric IP
- suspicious TLD
- brand impersonation
- typosquatting
- homoglyphs
- suspicious subdomain
- URL obfuscation

### 3. Evidence-Based Explanation

Every important finding should expose:

```text
What we detected
+
Exact evidence
+
Why it matters
+
Attacker objective
```

### 4. Scam DNA

Build the attack path from real signals:

```text
Lure → Trust → Urgency → Action → Theft
```

The stages must be generated from the analysis rather than being a purely visual animation.

### 5. Protective Action Plan

Give situation-specific actions:

```text
DO NOT:
- click the link
- share OTP/PIN
- send money
- install requested software

DO:
- verify through the official channel
- block/report the sender
- contact the bank/provider through an official number
```

---

## 5. What NOT to Build for MVP

Do not add these simply because they exist in other cybersecurity projects:

- SIEM dashboard
- network traffic analyzer
- port scanner
- API security scanner
- custom ML ensemble
- QR scanner
- full WHOIS platform
- certificate transparency infrastructure
- massive threat-intelligence dashboard
- mobile application
- browser extension
- WhatsApp integration
- real-time SMS interception
- voice-cloning detection

These increase surface area without directly improving the core user journey.

---

## 6. Indian Problem-Solving Principle

ScamShield should be designed around the real decision a user faces:

> **"Mujhe ye message mila hai. Main ab kya karun?"**

Not:

> "Can we detect more cybersecurity indicators?"

Therefore the product should optimize for:

```text
DETECT
   ↓
EXPLAIN
   ↓
UNDERSTAND
   ↓
DECIDE
   ↓
RESPOND
```

The user should leave the analysis knowing:

```text
Risk
  +
Evidence
  +
Attacker Goal
  +
Attack Path
  +
Safe Next Action
```

---

## 7. Technical Architecture After MVP Upgrades

```text
                    USER MESSAGE
                         │
                         ↓
                    VALIDATION
                         │
                         ↓
              DETERMINISTIC ENGINE
                │                │
                ↓                ↓
         MESSAGE SIGNALS     URL EXTRACTION
                                  │
                                  ↓
                          URL INTELLIGENCE
                                  │
                                  ↓
                          EVIDENCE ENGINE
                                  │
                                  ↓
                            AMAZON BEDROCK
                                  │
                                  ↓
                              RISK FUSION
                                  │
                    ┌─────────────┼─────────────┐
                    ↓             ↓             ↓
                   RISK        INTENT       ATTACK PATH
                    └─────────────┼─────────────┘
                                  ↓
                           PROTECTIVE ACTION
                                  │
                                  ↓
                                 USER
```

---

## 8. Build Order

### Phase A — Must work first

1. Real AWS runtime
2. Message analyzer
3. Deterministic detection
4. Bedrock
5. Risk fusion
6. DynamoDB persistence
7. Production frontend/API

### Phase B — Highest-value product upgrades

8. Indian scam pattern layer
9. Deep URL intelligence
10. Evidence engine
11. Dynamic Scam DNA / attack path

### Phase C — Polish

12. False-positive explanation
13. Uncertainty/confidence handling
14. Adversarial/obfuscation improvements
15. UI/animation refinement
16. E2E testing

### Phase D — Only if time remains

17. One threat-intelligence integration
18. Additional domain intelligence
19. Report/export functionality

---

## 9. Definition of Done for MVP

ScamShield MVP is complete when a user can paste a realistic Indian scam message such as a fake KYC, UPI, job, courier, bank or government message and receive:

```text
✓ Risk Score
✓ Risk Level
✓ Scam Category
✓ Detected Indicators
✓ Exact Evidence
✓ Why It Is Suspicious
✓ Attacker Intent
✓ Attack Path / Scam DNA
✓ Protective Actions
✓ Safe fallback when AI is unavailable
```

The entire core flow should work through the actual AWS architecture:

```text
Frontend
 → API Gateway
 → Lambda
 → Detection
 → Bedrock
 → Risk Fusion
 → DynamoDB
 → Frontend
```

---

## 10. Final Priority

If time becomes limited, prioritize in this order:

**P0**
1. Indian Scam Pattern Intelligence
2. Deep URL Intelligence
3. Evidence Engine
4. Dynamic Attack-Path / Scam DNA
5. Real AWS end-to-end runtime

**P1**
6. False-positive explanation
7. Obfuscation improvements
8. Confidence / uncertainty
9. One threat-intelligence integration

**P2 / Post-MVP**
10. QR/quishing
11. WHOIS/domain-age intelligence
12. Redirect chains
13. CT/DNS enrichment
14. Custom ML
15. SIEM/network/API-security features

> **Core principle:** Don't compete by having more cybersecurity features. Compete by making ScamShield exceptionally good at understanding and preventing scams that Indian users actually encounter.
