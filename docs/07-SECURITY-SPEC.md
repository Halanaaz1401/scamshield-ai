# Security Specification

## Threat model

Assets: AWS credentials, API access, DynamoDB records, submitted
content, Bedrock access, availability and system instructions.

Threats: prompt injection, malicious payloads, oversized requests, API
abuse, credential exposure, IAM over-permission, data leakage, stored
sensitive content, CORS abuse and error leakage.

## Controls

-   Strict request schema and length limits
-   Rate limiting
-   Treat message content as untrusted
-   Separate system instructions from user content
-   Validate AI output against a schema
-   Least-privilege IAM
-   No AWS secrets in frontend or repository
-   Safe production errors
-   Intentional CORS
-   Minimal data retention
-   Avoid logging sensitive message content unnecessarily
-   Check dependencies and secrets before submission

## Acceptance

No secrets committed; limits and rate limiting tested; prompt injection
tested; output validation tested; IAM/CORS/errors reviewed.
