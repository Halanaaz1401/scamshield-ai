# User Flow

## Primary flow

Landing/Analyzer → paste message → validate → Analyze → analysis state →
detection → Bedrock → risk fusion → result.

## Result hierarchy

**Risk → Scam Type → Why We Flagged It → What You Should Do**

## Analysis state

Use truthful progress stages such as: 1. Checking suspicious patterns 2.
Inspecting threat indicators 3. Analyzing context 4. Preparing
assessment

## Error states

Empty/invalid input → explain → correct. Backend/AI failure → safe error
→ retry.

## Edge cases

Test Hinglish, misspellings, short/long input, obfuscated or shortened
URLs, authority impersonation, emotional manipulation, legitimate
notifications and prompt injection.

## Navigation

Keep the MVP focused. It should feel like one security tool, not a large
dashboard.
