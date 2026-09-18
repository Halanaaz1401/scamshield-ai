# ScamShield AI — Technology Stack Specification

**Document Status:** Approved Planning Specification  
**Project:** ScamShield AI  
**Purpose:** Define the technologies, responsibilities, boundaries, and implementation constraints for the ScamShield MVP.

---

## 1. Technology Stack Overview

ScamShield is a focused AI-assisted scam detection web application.

The MVP technology stack is organized into these layers:

| Layer | Selected Technology | Primary Responsibility |
|---|---|---|
| Web Frontend | Next.js | User-facing ScamShield application |
| Frontend Language | TypeScript | Type-safe frontend development |
| Styling | Tailwind CSS | Responsive UI styling |
| UI Components | shadcn/ui / lightweight reusable components | Consistent interface components |
| Animation | Motion | Scroll, reveal, and interaction animation |
| Backend Language | Python | Detection, orchestration, validation, and risk logic |
| API | Amazon API Gateway | HTTPS API entry point |
| Compute | AWS Lambda | Serverless backend execution |
| AI | Amazon Bedrock | AI-assisted scam analysis and explanation |
| Detection | Python security detection engine | Deterministic scam indicators |
| Validation | Pydantic | Request and response schema validation |
| Risk Processing | Python risk-fusion layer | Combines deterministic and AI signals |
| Database | Amazon DynamoDB | Minimal analysis record persistence |
| Frontend Hosting | AWS Amplify Hosting | Production frontend hosting |
| Infrastructure | AWS SAM | Infrastructure-as-code for AWS resources |
| Testing | Pytest | Backend/unit/security testing |
| E2E Testing | Playwright | Browser-level application testing |
| Source Control | Git + GitHub | Version control and collaboration |
| CI | GitHub Actions | Automated validation |
| Development Environment | Antigravity IDE | AI-assisted implementation |
| Backup/Inspection IDE | VS Code | Manual inspection and fallback development |

---

# 2. Frontend Technology Stack

## 2.1 Next.js

**Purpose:** Build the ScamShield web application.

Responsibilities:

- Page structure
- Routing
- Server/client component boundaries where appropriate
- Frontend rendering
- Production web application

The frontend should remain focused on the core ScamShield experience rather than becoming a large dashboard.

## 2.2 TypeScript

**Purpose:** Type safety.

Use TypeScript for:

- API contracts
- UI component props
- Analysis result types
- Shared frontend models
- Application utilities

Important analysis types should be explicitly defined rather than relying on untyped API responses.

## 2.3 Tailwind CSS

**Purpose:** Styling and responsive layout.

The styling system should support the approved ScamShield visual direction:

- Dark-first interface
- High contrast
- Large typography
- Thin borders
- Restrained rounded containers
- Generous spacing
- Responsive layouts
- Accessible focus states

## 2.4 UI Components

Use a small reusable component system.

Potential foundation:

- shadcn/ui
- Radix-based primitives where appropriate
- Custom ScamShield components

Do not add a large component library without a concrete need.

## 2.5 Motion / Animation

Use a lightweight animation approach such as Motion for:

- Hero animation
- Scroll-triggered reveals
- Loading/scanning states
- Result transitions
- CTA animation
- Micro-interactions

Animations must support usability rather than distract from the security result.

Respect `prefers-reduced-motion`.

---

# 3. Backend Technology Stack

## 3.1 Python

Python is the backend implementation language.

Use it for:

- API handling
- Detection engine
- Input validation
- AI service integration
- Risk fusion
- Persistence
- Security controls
- Testing

## 3.2 AWS Lambda

Lambda is the primary serverless compute layer.

The Lambda orchestration flow is:

```text
Request
  ↓
Validation
  ↓
Security checks
  ↓
Detection Engine
  ↓
Amazon Bedrock
  ↓
Risk Fusion
  ↓
DynamoDB
  ↓
Structured Response
```

Keep Lambda responsibilities modular rather than putting all logic into one large handler.

## 3.3 Pydantic

Use Pydantic for:

- Request validation
- Response validation
- Internal structured models
- AI output validation

Untrusted external input must never be assumed to be valid.

---

# 4. Cybersecurity Detection Stack

The deterministic detection engine is a core ScamShield component.

It must operate independently of the LLM.

Potential indicators include:

- Urgency
- OTP requests
- Payment requests
- Credential requests
- Suspicious links
- Impersonation indicators
- Threat language
- Reward/lottery language
- Job/investment scam patterns
- Authority impersonation
- Financial manipulation
- Social-engineering patterns
- Obfuscated or suspicious text patterns

The engine should produce structured signals.

Example:

```json
{
  "signals": [
    {
      "type": "OTP_REQUEST",
      "severity": "HIGH",
      "evidence": "Share the OTP immediately"
    }
  ]
}
```

The exact detection rules must be implemented and evaluated during the hackathon.

---

# 5. AI Technology Stack

## 5.1 Amazon Bedrock

Amazon Bedrock provides the generative AI capability for ScamShield.

The AI layer is responsible for tasks such as:

- Scam classification assistance
- Contextual interpretation
- Explanation generation
- Identification of social-engineering patterns
- Structured assessment

The LLM must not be treated as the sole security detector.

The deterministic detection engine and AI analysis are complementary.

## 5.2 Structured AI Output

Bedrock responses must be converted into a defined schema before being trusted by downstream logic.

Expected conceptual output:

```json
{
  "category": "BANKING_SCAM",
  "risk_assessment": "HIGH",
  "indicators": [],
  "explanation": "",
  "recommended_actions": []
}
```

The exact production schema is defined in:

`docs/08-DATA-SCHEMA.md`

and:

`docs/09-API-SPEC.md`

## 5.3 AI Safety Boundary

User messages are untrusted data.

The AI system must be designed so that content inside a suspicious message is treated as data to analyze, not as instructions to follow.

Prompt-injection resistance is therefore a mandatory security requirement.

---

# 6. Risk-Fusion Technology

ScamShield combines two primary signal sources:

```text
Deterministic Detection
        +
AI Assessment
        ↓
Risk Fusion
        ↓
Final Risk Result
```

Risk fusion is responsible for producing the final:

- Risk score
- Risk level
- Scam category
- Indicators
- Explanation
- Recommended actions

The exact scoring formula must be determined through testing and evaluation.

Do not hard-code an arbitrary formula simply for presentation.

---

# 7. AWS Cloud Stack

## 7.1 Amazon API Gateway

**Purpose:** Public HTTPS API boundary.

Primary responsibility:

```text
Frontend → HTTPS → API Gateway → Lambda
```

Security considerations:

- Request validation
- Throttling/rate controls
- CORS
- Safe error handling
- Appropriate HTTP methods

## 7.2 AWS Lambda

**Purpose:** Serverless backend execution.

Lambda coordinates:

- Validation
- Detection
- AI analysis
- Risk fusion
- Persistence
- Response generation

## 7.3 Amazon Bedrock

**Purpose:** Managed generative AI.

Used for contextual scam analysis and explanation.

## 7.4 Amazon DynamoDB

**Purpose:** Minimal persistence.

Store only information required by the MVP.

Potential record fields:

- Analysis ID
- Timestamp
- Risk score
- Risk level
- Scam category
- Indicators
- Result metadata

Avoid storing sensitive user content unnecessarily.

## 7.5 AWS Amplify Hosting

**Purpose:** Host the production Next.js frontend.

The frontend must communicate with the deployed API through the configured API endpoint.

## 7.6 AWS SAM

**Purpose:** Infrastructure as code.

Use SAM to define and manage the serverless AWS resources required by the application.

Do not provision unnecessary services.

---

# 8. Security Technology Stack

Security is a first-class architecture layer.

| Security Requirement | Technology / Approach |
|---|---|
| Input validation | Pydantic + application validation |
| Request limits | API Gateway + Lambda validation |
| Rate limiting | API Gateway controls and/or backend controls |
| Authentication | Only if required by final MVP scope |
| Authorization | AWS IAM for AWS resource access |
| Secrets | Environment configuration / AWS secret mechanisms where required |
| AI prompt defense | Prompt boundary + input handling |
| AI output safety | Structured schema validation |
| CORS | API Gateway/application configuration |
| Error handling | Sanitized application errors |
| Logging | Structured logs without unnecessary sensitive content |
| Dependency security | Dependency review and vulnerability checks |
| AWS permissions | Least-privilege IAM |
| Data privacy | Minimal collection and retention |

### Security Trust Boundary

```text
UNTRUSTED USER MESSAGE
        ↓
INPUT VALIDATION
        ↓
SECURITY CONTROLS
        ↓
DETERMINISTIC DETECTION
        ↓
AI ANALYSIS BOUNDARY
        ↓
AI OUTPUT VALIDATION
        ↓
RISK FUSION
        ↓
STRUCTURED RESULT
```

No user-provided text should be treated as executable instructions.

---

# 9. Database Stack

## Amazon DynamoDB

DynamoDB is the selected persistence layer for the MVP.

Use a minimal design suitable for the analysis workflow.

The database should not become a separate product feature.

Primary requirements:

- Predictable access pattern
- Minimal stored data
- Appropriate partition-key design
- Server-side access only
- Least-privilege IAM
- No database credentials exposed to the browser

Detailed schema belongs in:

`docs/08-DATA-SCHEMA.md`

---

# 10. API Technology Stack

Primary API path:

```text
Next.js
   ↓
Amazon API Gateway
   ↓
AWS Lambda
   ↓
ScamShield Services
```

The MVP should initially center around an analysis operation such as:

```text
POST /analyze
```

The exact request/response contract belongs in:

`docs/09-API-SPEC.md`

The frontend must never directly access privileged AWS services.

---

# 11. Testing Stack

## 11.1 Pytest

Use Pytest for:

- Detection engine unit tests
- Validation tests
- Risk-fusion tests
- Security tests
- Backend integration tests

## 11.2 Playwright

Use Playwright where useful for:

- Analyzer flow
- Loading state
- Result rendering
- Error state
- Responsive browser behavior

## 11.3 AI Evaluation

AI behavior requires evaluation against curated cases.

Test categories:

- Banking scams
- UPI/payment scams
- Job scams
- Investment scams
- Lottery/reward scams
- Government impersonation
- Phishing
- Legitimate notifications
- Hinglish messages
- Misspellings
- Obfuscated content
- Prompt-injection attempts

Evaluate:

- Detection consistency
- Category correctness
- Risk assessment
- Explanation quality
- Recommended actions
- False positives
- False negatives

---

# 12. Development and DevOps Stack

## Git

Use Git for source control.

## GitHub

Use GitHub for:

- Repository hosting
- Version history
- Issues if needed
- Pull requests if a team is added
- Submission repository

## GitHub Actions

Use CI for automated checks such as:

```text
Push
 ↓
Lint
 ↓
Type Check
 ↓
Backend Tests
 ↓
Security Tests
```

Do not create a complicated CI/CD pipeline unless required.

## Antigravity IDE

Antigravity is the primary AI-assisted development environment.

It must follow:

`.ai/RULES.md`

and the documentation in:

`docs/`

AI coding assistance must be disclosed in the hackathon writeup as required by the event rules.

## VS Code

VS Code can be used as a manual inspection/fallback development environment.

---

# 13. Environment and Secret Management

Never commit:

- `.env`
- AWS credentials
- API keys
- Bedrock credentials
- private tokens
- production secrets

Commit only:

```text
.env.example
```

Example variable names may include:

```text
AWS_REGION=
AWS_ACCOUNT_ID=
BEDROCK_MODEL_ID=
DYNAMODB_TABLE_NAME=
NEXT_PUBLIC_API_BASE_URL=
```

Only variables actually required by the implementation should remain.

---

# 14. Dependency Policy

Dependencies must be:

1. Necessary
2. Maintained
3. Compatible with the selected stack
4. Justified by an actual project requirement

Do not install libraries simply because they are popular.

Avoid unnecessary abstractions.

Prefer a small dependency footprint suitable for a solo hackathon project.

---

# 15. Technologies Explicitly Not Required for the MVP

The following are outside the initial technology scope:

- PostgreSQL
- MongoDB
- Redis
- Kubernetes
- Terraform
- Microservice architecture
- Mobile application frameworks
- Browser-extension frameworks
- WhatsApp APIs
- Voice-cloning infrastructure
- QR-scanning infrastructure
- Custom ML training infrastructure
- Large analytics platforms
- Unnecessary AWS services

These may be considered in future versions only if the product requirements change.

---

# 16. Technology Selection Principles

ScamShield follows these principles:

### Principle 1 — Product first

Technology must serve the core scam-analysis flow.

### Principle 2 — AWS must be real

AWS services must perform actual product responsibilities, not exist only in documentation.

### Principle 3 — Security by design

Security controls must exist at the boundaries where untrusted data enters the system.

### Principle 4 — LLM is not the security boundary

The deterministic detection engine remains an independent signal source.

### Principle 5 — Minimal architecture

Avoid unnecessary services and infrastructure.

### Principle 6 — Observable and testable

Important behavior must be testable and failures must be visible.

### Principle 7 — Secrets never enter source control

Credentials and secrets must remain outside committed source code.

### Principle 8 — Hackathon scope matters

The stack must support a working MVP within the available solo development window.

---

# 17. Final Approved Stack

```text
FRONTEND
Next.js
TypeScript
Tailwind CSS
shadcn/ui / custom components
Motion

BACKEND
Python
AWS Lambda
Pydantic

CYBERSECURITY
Custom deterministic detection engine
Prompt-injection defenses
Input/output validation
Security test suite

AI
Amazon Bedrock

CLOUD
Amazon API Gateway
AWS Lambda
Amazon Bedrock
Amazon DynamoDB
AWS Amplify Hosting
AWS SAM

DATABASE
Amazon DynamoDB

TESTING
Pytest
Playwright
AI evaluation dataset

DEVOPS
Git
GitHub
GitHub Actions

DEVELOPMENT
Antigravity IDE
VS Code
```

---

# 18. Source-of-Truth Relationship

This document defines **which technologies are selected**.

Other project documents define how those technologies are used:

- `01-PRODUCT-SPEC.md` → what is being built
- `02-USER-FLOW.md` → how the user moves through it
- `03-UI-UX-SPEC.md` → how it looks and behaves
- `04-ARCHITECTURE.md` → how systems connect
- `05-TECH-STACK.md` → what technologies are used
- `06-AI-SPEC.md` → how AI is used
- `07-SECURITY-SPEC.md` → how the system is secured
- `08-DATA-SCHEMA.md` → what data is stored
- `09-API-SPEC.md` → frontend/backend contract
- `10-TESTING-PLAN.md` → how correctness and security are verified
- `11-IMPLEMENTATION-PLAN.md` → implementation sequence

If a later implementation decision conflicts with this document, update the documentation deliberately before changing the architecture.

---

## Document Status

**Technology stack is defined for the ScamShield MVP.**

Implementation details may be refined during the hackathon only when justified by actual technical constraints, testing results, or AWS deployment requirements.
