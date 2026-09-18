# ScamShield AI — Product Requirements Document (PRD)

**Project:** ScamShield AI  
**Document:** Product Requirements Document  
**Status:** Pre-build / Hackathon MVP Specification  
**Version:** 1.0

---

## 1. Product Overview

ScamShield AI is an AI-assisted scam detection and prevention web application.

The MVP allows a user to submit a suspicious message and receive a structured security assessment containing:

- Risk score
- Risk level
- Scam category
- Detected indicators
- Human-readable explanation
- Recommended protective actions

The product combines a deterministic cybersecurity detection layer with Amazon Bedrock-based AI analysis. The AI is not treated as the sole security detector.

---

## 2. Problem Statement

People regularly receive suspicious messages through digital communication channels. Scam messages can use urgency, impersonation, financial requests, OTP requests, suspicious links, rewards, threats, job offers, or other social-engineering techniques.

Many users may recognize that a message feels suspicious but cannot quickly determine:

- What makes the message suspicious
- What type of scam it may represent
- How serious the risk is
- What action they should take next

ScamShield aims to make this assessment understandable and actionable through a focused web experience.

---

## 3. Target Users

### Primary User

A general internet or smartphone user who receives a suspicious message and wants a quick security assessment.

### Secondary User

Students, families, employees, and other users who want to understand common scam indicators and safer responses.

The MVP is designed for non-security-specialist users.

---

## 4. Product Goal

The MVP goal is to provide a simple flow:

```text
Paste suspicious message
        ↓
Analyze
        ↓
Understand the risk
        ↓
Take safer action
```

The product should prioritize clarity, explainability, and actionable prevention advice.

---

## 5. Core User Journey

```text
Landing Page
     ↓
Paste Message
     ↓
Analyze Message
     ↓
Validation
     ↓
Cybersecurity Detection
     ↓
AI Analysis
     ↓
Risk Fusion
     ↓
Risk Result
     ↓
Why We Flagged It
     ↓
What You Should Do
```

---

## 6. MVP Functional Requirements

### FR-01 — Message Input

The system shall provide a clear input area where users can paste or enter a suspicious message.

Requirements:

- Multiline input
- Clear character/input limit
- Clear primary action
- Input validation
- Empty-input handling

---

### FR-02 — Message Validation

The system shall validate submitted content before analysis.

Validation should include:

- Empty input detection
- Input length limits
- Malformed request handling
- Safe handling of untrusted content

---

### FR-03 — Deterministic Scam Detection

The system shall analyze the message using a deterministic cybersecurity detection layer.

Potential indicators include:

- OTP requests
- Payment requests
- Credential requests
- Urgency
- Threats
- Impersonation
- Suspicious URLs
- Reward/lottery language
- Job/investment scam patterns
- Social-engineering indicators
- Obfuscation or suspicious text patterns

The detection engine shall produce structured signals that can be used by the risk-fusion layer.

---

### FR-04 — AI Analysis

The system shall use Amazon Bedrock to provide contextual AI-assisted analysis.

The AI may assist with:

- Scam classification
- Contextual interpretation
- Explanation
- Identification of social-engineering patterns
- Recommended protective actions

The AI must receive clearly defined untrusted-data boundaries.

---

### FR-05 — Risk Fusion

The system shall combine deterministic detection signals and AI assessment into a final structured result.

The final result shall contain, where applicable:

- Risk score
- Risk level
- Scam category
- Indicators
- Explanation
- Recommended actions

The scoring methodology shall be defined and validated during implementation/testing rather than arbitrarily chosen for presentation.

---

### FR-06 — Risk Result

The result screen shall make the most important information immediately understandable.

Priority order:

```text
1. Risk
2. Scam Type
3. Why We Flagged It
4. What You Should Do
```

---

### FR-07 — Protective Actions

The system shall provide practical safety guidance based on the assessment.

Examples:

- Do not click suspicious links
- Do not share OTPs
- Do not provide passwords or credentials
- Verify the sender through an independent channel
- Do not send money based solely on the message
- Report/block the sender where appropriate

Advice must remain safety-focused and should not claim certainty beyond the available evidence.

---

### FR-08 — Loading / Analysis State

The interface shall communicate that analysis is in progress.

The UI may show stages such as:

```text
Checking suspicious patterns
        ↓
Analyzing threat indicators
        ↓
Generating security assessment
```

The loading experience should be clear without exposing internal secrets, credentials, or sensitive implementation details.

---

### FR-09 — Error Handling

The system shall handle:

- Empty input
- Input too long
- Invalid requests
- API failures
- AI service failures
- Database failures
- Timeout/failure conditions

Production errors must be safe and understandable.

Internal stack traces, credentials, infrastructure details, or sensitive debugging information must not be exposed to users.

---

## 7. UI/UX Requirements

The approved visual direction is:

- Dark-first
- Premium cybersecurity/SaaS aesthetic
- Large editorial typography
- High contrast
- Thin borders
- Restrained rounded containers
- Generous spacing
- Smooth scrolling
- Scroll-triggered content reveals
- Subtle technical visuals
- Original hero security animation
- Original final CTA animation
- Dark footer

Reference material is stored under:

```text
design-references/codeant/
design-references/wireframe-template/
```

These references are for visual inspiration only.

The implementation must not copy external branding, logos, text, proprietary graphics, exact layouts, or pixel-identical animations.

---

## 8. Required MVP Screens

### Screen 1 — Landing / Analyzer

Purpose:

Introduce ScamShield and allow the user to submit a suspicious message.

Primary elements:

- ScamShield branding
- Short value proposition
- Message input
- Analyze button
- Supporting security context
- Original hero visual

---

### Screen 2 — Analysis State

Purpose:

Provide feedback while analysis is running.

Primary elements:

- Progress/loading state
- Security-oriented animation
- Clear status messaging

---

### Screen 3 — Risk Result

Purpose:

Present the final assessment.

Primary elements:

- Risk score
- Risk level
- Scam category
- Key indicators
- Explanation
- Recommended actions

---

### Screen 4 — Final CTA

Purpose:

Provide a clear next step after the analysis experience.

The CTA may contain an original animated security visual inspired by the approved visual direction.

---

### Screen 5 — Footer

Requirements:

- Dark visual treatment
- Minimal navigation/information
- Consistent ScamShield branding
- No unnecessary footer complexity

---

## 9. Non-Functional Requirements

### NFR-01 — Security

The system must treat user-submitted messages as untrusted data.

Mandatory considerations:

- Input validation
- Input size limits
- Rate limiting
- Prompt-injection defense
- AI output validation
- Least-privilege IAM
- Secure secret handling
- CORS configuration
- Safe error handling
- Safe logging
- Minimal data retention

---

### NFR-02 — Performance

The application should provide responsive interaction and avoid unnecessary client-side processing.

The analysis workflow should clearly communicate delays when external AI or cloud services are processing the request.

---

### NFR-03 — Reliability

Failures in external services must produce controlled application behavior.

A temporary AI, API, or database failure must not expose internal infrastructure information.

---

### NFR-04 — Accessibility

The interface should support:

- Keyboard navigation
- Visible focus states
- Sufficient text contrast
- Semantic controls
- Accessible form labels
- Reduced-motion preferences

---

### NFR-05 — Responsiveness

The application must support:

- Desktop
- Tablet
- Mobile

The core analysis flow must remain usable on smaller screens.

---

## 10. AWS Requirements

AWS must be part of the actual product implementation.

The intended architecture is:

```text
Next.js
   ↓
Amazon API Gateway
   ↓
AWS Lambda
   ├── Validation
   ├── Detection Engine
   ├── Amazon Bedrock
   ├── Risk Fusion
   └── DynamoDB
   ↓
Structured Result
   ↓
Frontend
```

Potential frontend hosting:

```text
AWS Amplify Hosting
```

Infrastructure may be managed using:

```text
AWS SAM
```

Only AWS services with real product responsibilities should be included.

---

## 11. Data Requirements

The MVP should collect and store only the data required for the product.

Potential analysis record:

```json
{
  "analysis_id": "string",
  "timestamp": "ISO-8601 timestamp",
  "risk_score": 0,
  "risk_level": "LOW | MEDIUM | HIGH",
  "category": "string",
  "indicators": [],
  "explanation": "string",
  "recommended_actions": []
}
```

The detailed schema is defined separately in:

`docs/08-DATA-SCHEMA.md`

Sensitive user content should not be retained unnecessarily.

---

## 12. API Requirements

The MVP should provide a focused analysis API.

Initial conceptual endpoint:

```text
POST /analyze
```

The API must define:

- Request schema
- Response schema
- Validation
- Error responses
- Status codes
- Rate limiting
- CORS behavior

The authoritative API contract belongs in:

`docs/09-API-SPEC.md`

---

## 13. AI Requirements

Amazon Bedrock is used for contextual AI-assisted analysis.

The AI system must:

- Receive the suspicious message as untrusted data
- Not treat message content as system instructions
- Produce structured output
- Be validated before downstream use
- Avoid unsupported certainty
- Provide useful explanations
- Provide safe protective actions

The detailed AI behavior is defined in:

`docs/06-AI-SPEC.md`

---

## 14. Security Requirements

The security architecture must include:

```text
Untrusted Input
      ↓
Validation
      ↓
Security Controls
      ↓
Detection Engine
      ↓
AI Boundary
      ↓
AI Output Validation
      ↓
Risk Fusion
      ↓
Response
```

Security requirements include:

- Input validation
- Request limits
- Rate limiting
- Prompt-injection resistance
- Output schema validation
- Least-privilege IAM
- No secrets in frontend code
- No hardcoded credentials
- Safe production errors
- Controlled CORS
- Minimal sensitive logging
- Dependency security
- Minimal data retention

Detailed controls belong in:

`docs/07-SECURITY-SPEC.md`

---

## 15. Testing Requirements

The MVP must be evaluated using:

### Functional cases

- Banking scam
- UPI/payment scam
- Job scam
- Investment scam
- Lottery/reward scam
- Government impersonation
- Phishing
- Legitimate bank notification
- Legitimate delivery notification
- Legitimate job communication
- Legitimate payment notification

### Adversarial cases

- Hinglish
- Misspellings
- Obfuscated words
- Suspicious shortened URLs
- Emotional manipulation
- Authority impersonation
- Prompt-injection attempts
- Extremely long input
- Empty input
- Malformed requests

Testing must consider:

- False positives
- False negatives
- Classification accuracy
- Risk consistency
- Explanation quality
- Action quality
- Security behavior
- Failure handling

---

## 16. MVP Scope

### Must Have

- Suspicious message input
- Input validation
- Deterministic detection
- Amazon Bedrock analysis
- Risk fusion
- Risk score
- Risk level
- Scam category
- Indicators
- Explanation
- Protective actions
- AWS-backed API
- DynamoDB persistence where required
- Production deployment
- Responsive UI
- Security controls
- Test/evaluation cases

### Nice to Have — Only If Time Allows

- URL-specific analysis
- Analysis history
- Additional language support
- Evidence visualization
- Additional scam categories

These features must not delay the core MVP.

---

## 17. Explicitly Out of Scope

Do not implement the following in the initial hackathon MVP:

- Native mobile application
- Browser extension
- Real-time SMS interception
- WhatsApp integration
- Voice cloning
- QR scanner
- Large analytics dashboard
- Custom ML training pipeline
- Complex authentication system unless required
- Microservice architecture
- Unnecessary AWS services
- Large-scale user management
- Social network integrations

---

## 18. Success Criteria

The MVP is successful when a user can:

```text
Open ScamShield
      ↓
Paste a suspicious message
      ↓
Submit it
      ↓
Receive an analysis
      ↓
See the risk level
      ↓
Understand why it was flagged
      ↓
See what to do next
```

The deployed product must demonstrate real AWS usage rather than AWS appearing only in documentation.

---

## 19. Acceptance Criteria

### AC-01

A user can submit a non-empty suspicious message.

### AC-02

Invalid or excessive input is rejected safely.

### AC-03

The message passes through the deterministic detection layer.

### AC-04

Amazon Bedrock is used for the AI-assisted analysis.

### AC-05

AI output is validated before being used.

### AC-06

The system produces a structured risk result.

### AC-07

The result contains risk, category, indicators, explanation, and recommended actions where applicable.

### AC-08

The frontend clearly communicates analysis progress.

### AC-09

The application handles API/AI failures without exposing internal details.

### AC-10

The deployed system uses AWS services as part of the actual application flow.

### AC-11

The interface works on desktop and mobile.

### AC-12

Security and adversarial test cases are executed before submission.

### AC-13

The final demo can clearly show:

```text
User Input
   ↓
Detection
   ↓
Amazon Bedrock
   ↓
Risk Fusion
   ↓
Result
```

---

## 20. Product Constraints

1. Keep the MVP focused.
2. Working functionality takes priority over feature quantity.
3. Do not add AWS services without a real responsibility.
4. Do not treat AI output as automatically trustworthy.
5. Do not expose secrets or credentials.
6. Do not store unnecessary sensitive user content.
7. Do not copy external website designs or assets.
8. Preserve the approved UI/UX direction.
9. Do not introduce features outside the documented scope without an explicit decision.
10. Every major implementation decision should remain consistent with the project documentation.

---

## 21. Related Documents

| Document | Purpose |
|---|---|
| `01-PRODUCT-SPEC.md` | Product/problem/business requirements |
| `02-USER-FLOW.md` | User and system flows |
| `03-UI-UX-SPEC.md` | Visual and interaction specification |
| `04-ARCHITECTURE.md` | System architecture |
| `05-TECH-STACK.md` | Technology selection and responsibilities |
| `06-AI-SPEC.md` | AI behavior and Bedrock integration |
| `07-SECURITY-SPEC.md` | Security architecture and controls |
| `08-DATA-SCHEMA.md` | Data structures and DynamoDB design |
| `09-API-SPEC.md` | API contracts |
| `10-TESTING-PLAN.md` | Test strategy and evaluation |
| `11-IMPLEMENTATION-PLAN.md` | Build sequence |

---

## 22. Document Status

This PRD defines the ScamShield AI MVP requirements before implementation.

Implementation should follow the approved scope, architecture, technology stack, security requirements, and implementation plan.
