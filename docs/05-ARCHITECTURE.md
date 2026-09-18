# System Architecture

``` text
User
 ↓
Next.js Frontend / Amplify Hosting
 ↓ HTTPS
API Gateway
 ↓
Lambda Orchestrator
 ├─ Input Validation
 ├─ Detection Engine
 ├─ Amazon Bedrock
 ├─ Risk Fusion
 └─ DynamoDB
 ↓
Structured Result
 ↓
Frontend
```

## Responsibilities

API Gateway exposes `POST /analyze`. Lambda orchestrates validation,
detection, Bedrock, fusion, response validation and persistence. Bedrock
performs contextual analysis. DynamoDB stores only required analysis
data. Amplify may host the frontend.

## Trust boundary

Untrusted input → validation → detection → AI boundary → output
validation → response.

## API

Request:

``` json
{"message":"string"}
```

Response:

``` json
{"risk_score":0,"risk_level":"LOW","category":"string","indicators":[],"explanation":"string","actions":[]}
```

Do not add AWS services merely for appearance. Every service must have a
demonstrable responsibility.
