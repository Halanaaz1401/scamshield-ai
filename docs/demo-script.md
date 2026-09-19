# ScamShield AI — 3-Minute Hackathon Demo Script

> **Track**: First Commit Hackathon — AWS "Ship It" Track  
> **Total Duration**: Exactly 3 Minutes (180 Seconds)  
> **Speaker Role**: Founder / Lead Architect

---

### [0:00 – 0:20] 1. The Problem
- **Voiceover**:  
  *"Every day, millions of citizens across India receive alarming text messages: electricity power cuts tonight, blocked bank accounts, or fake gas subsidy updates. People panic and comply not because they are careless, but because traditional security tools only say 'safe' or 'malicious' without explaining what the attacker is actually trying to make them do. We built ScamShield AI to solve this."*
- **Visual**:  
  Slide showing real-world Indian scam messages (fake electricity disconnection SMS, PAN KYC update, reverse UPI collect).

---

### [0:20 – 0:35] 2. Show ScamShield Homepage
- **Voiceover**:  
  *"This is ScamShield AI. It is completely browser-first, zero-install, and designed for immediate human clarity. Anyone can paste a suspicious message or link and get an instant forensic breakdown."*
- **Visual**:  
  Show `http://localhost:3000` homepage with the dark-mode Threat Vector Inspection Console, Space Grotesk typography, and demo preset buttons.

---

### [0:35 – 0:50] 3. Normal Harmless Message (Benign Baseline)
- **Voiceover**:  
  *"Let's start with a normal personal message: 'Hey, are we still meeting for lunch today at 1 PM?' Notice how ScamShield doesn't fabricate threats. It immediately verifies the message as safe, scores it 0 out of 100, shows 'No Direct Action Demanded', and renders no attack progression."*
- **Visual**:  
  Click Preset or enter text -> Click **INSPECT COMMUNICATION** -> Show emerald-green result banner ("Message Appears Safe", Score: 0/100, Demanded Action: "No Direct Action Demanded").

---

### [0:50 – 1:15] 4. Urgent Banking OTP Phishing Scam
- **Voiceover**:  
  *"Now let's test an urgent phishing lure: 'Your bank account is suspended. Share the OTP immediately to restore access.' Instantly, ScamShield flags CRITICAL RISK (95/100). Look at the breakdown: it clearly identifies the demanded action—'Submit OTP / Verification Code'—identifies the manipulation tactic as 'Threat of Service Deactivation', and highlights the exact text evidence."*
- **Visual**:  
  Submit OTP message -> Highlight CRITICAL badge, score 95/100, Demanded Action badge, and the DO NOT column ("Do NOT share your OTP or banking PIN").

---

### [1:15 – 1:40] 5. LPG Gas Subsidy / KYC Lure
- **Voiceover**:  
  *"Here is a common Indian subsidy lure: 'Your LPG subsidy is pending. Update your KYC within 24 hours using this link.' ScamShield flags this as SUSPICIOUS (50/100), tags the demanded action as KYC verification, and explains the attacker's objective: tricking the victim into revealing Aadhaar or NetBanking credentials under the pretext of an energy subsidy."*
- **Visual**:  
  Submit LPG subsidy text -> Point to Attacker Goal explanation and Scam DNA Kill Chain showing Inbound Contact -> Psychological Trigger.

---

### [1:40 – 2:00] 6. Shortened Link & Calibrated Verdict
- **Voiceover**:  
  *"A major breakthrough in our forensic engine is handling shortened links like bit.ly. In cybersecurity, unknown does not equal safe. Notice that ScamShield doesn't falsely claim this link is safe, nor does it make an unproven claim that it's malware. It accurately outputs 'DESTINATION UNVERIFIED' in an amber caution box, warning the user that the destination was concealed."*
- **Visual**:  
  Show analysis of `https://bit.ly/3xY7z9` -> Highlight amber verdict banner `UNKNOWN_UNVERIFIED` and explanation.

---

### [2:00 – 2:25] 7. Grounded Attack Progression (Scam DNA) & Explainability
- **Voiceover**:  
  *"ScamShield adheres to a strict rule: NO EVIDENCE = NO CLAIM. In our Scam DNA visualizer, every attack step is tied to an explicit finding ID and verified text snippet. Notice that if no unauthorized action was demanded, our engine never fabricates one. It gives users clear, actionable DO NOT and DO columns."*
- **Visual**:  
  Scroll down through Scam DNA steps (Inbound Vector, Psychological Trigger, Unauthorized Action, Compromise) and technical telemetry drawer.

---

### [2:25 – 2:45] 8. Safe Link Gateway
- **Voiceover**:  
  *"Users can also use our dedicated Safe Link Gateway at /safe-link. It allows zero-click pre-flight verification of any link before opening, displaying threat scores and an isolated 'Continue to Destination' security modal."*
- **Visual**:  
  Navigate to `/safe-link`, demonstrate quick URL check, show the confirmation modal.

---

### [2:45 – 3:00] 9. AWS Architecture & Conclusion
- **Voiceover**:  
  *"Under the hood, ScamShield is engineered for the AWS Ship It track: a Next.js frontend hosted on AWS Amplify, backed by Amazon API Gateway and serverless Python 3.12 AWS Lambda functions, paired with Google Gemini 2.5 Flash for grounded intent extraction and on-demand DynamoDB. The entire deployment is fully packaged, validated via SAM CLI, and ready for deployment once AWS credentials are configured. ScamShield AI: Explainable Threat Defense for everyone. Thank you."*
- **Visual**:  
  Display the system architecture diagram showing Amplify -> API Gateway -> Lambda -> Gemini -> DynamoDB, and final closing slide with project links.

---

### Demo Checklist & Setup Notes
- **Local Dev Server**: `http://localhost:3000` (Frontend: `npm run dev`)
- **Local Backend**: `http://localhost:8000` (FastAPI Serverless Simulator: `python src/server.py`)
- **AWS Status**: SAM template and Lambda wheel packages validated offline; cloud deployment pending CLI authentication.
