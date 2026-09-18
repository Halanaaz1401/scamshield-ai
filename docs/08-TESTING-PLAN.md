# Testing Plan

## Unit

Test validation, detection rules, category mapping, risk logic and
output schemas.

## Integration

Test Frontend → API Gateway → Lambda → Detection → Bedrock → Risk Fusion
→ DynamoDB.

## Functional cases

-   Known scam
-   Legitimate notification
-   Empty input
-   Oversized input
-   Malformed request
-   AI failure
-   Backend failure
-   Retry

## Security

Test prompt injection, HTML/script payloads, oversized requests,
unexpected fields, repeated requests, CORS, secret exposure and error
leakage.

## AI evaluation

Cover banking, payment, job, investment, reward, government
impersonation, phishing, legitimate messages, Hinglish, misspellings and
obfuscated links.

## UX

Verify first-time clarity, loading state, result hierarchy, actionable
recommendations, keyboard navigation, mobile layout and reduced-motion
behavior.

## Final smoke test

Open deployment → test scam → test legitimate case → test adversarial
case → test error → verify AWS integration → scan repository for secrets
→ record demo.
