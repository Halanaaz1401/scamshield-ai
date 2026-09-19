"""Main Lambda request orchestrator for ScamShield AI threat analysis."""

import json
from typing import Any, Dict, Optional

from backend.src.detection import detect_threat_signals
from backend.src.detection.url_intelligence import extract_urls
from backend.src.detection.engine import DeterministicAnalysis
from backend.src.handlers.health import health_handler
from backend.src.models.response import AnalysisResponse
from backend.src.services.bedrock_service import analyze_with_bedrock
from backend.src.services.intent_reasoner import (
    analyze_intent,
    IntentReasonerService,
)
from backend.src.services.risk_fusion import fuse_risk_analysis
from backend.src.services.storage_service import persist_analysis_record
from backend.src.services.threat_intel_service import (
    check_url_threat_intel,
    threat_intel_to_indicator,
    ThreatIntelligenceService,
)
from backend.src.utils.errors import RequestValidationError, ScamShieldError
from backend.src.validation.request import validate_analysis_request


DEFAULT_CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Cache-Control": "no-store",
}


def run_pipeline(
    message: str,
    source_type: Optional[str] = None,
    bedrock_client: Optional[Any] = None,
    dynamodb_resource: Optional[Any] = None,
    threat_intel_service: Optional[ThreatIntelligenceService] = None,
    intent_service: Optional[IntentReasonerService] = None,
) -> Dict[str, Any]:
    """Execute the complete ScamShield AI threat-analysis pipeline.

    Pipeline:
        Validation
        -> Deterministic Detection
        -> Threat Intelligence
        -> AI Intent Reasoning
        -> AWS Bedrock Analysis
        -> Multi-layer Risk Fusion
        -> DynamoDB Persistence
    """

    # 1. Input validation
    request = validate_analysis_request(
        {
            "message": message,
            "sourceType": source_type or "message",
        }
    )

    # 2. Deterministic detection
    det_analysis = detect_threat_signals(
        request.message,
        request.source_type,
    )

    # 2b. External Threat Intelligence Lookup
    extracted_urls = extract_urls(request.message)

    threat_intel_result = None
    target_url = None

    if extracted_urls:
        target_url = extracted_urls[0]

        threat_intel_result = check_url_threat_intel(
            target_url,
            service=threat_intel_service,
        )

        if (
            threat_intel_result
            and threat_intel_result.is_known_malicious
        ):
            threat_ind = threat_intel_to_indicator(
                threat_intel_result,
                target_url,
            )

            if threat_ind and not any(
                ind.id == "IND_THREAT_INTEL_MALICIOUS"
                for ind in det_analysis.indicators
            ):
                aug_indicators = [
                    threat_ind
                ] + list(det_analysis.indicators)

                aug_rule_ids = [
                    "IND_THREAT_INTEL_MALICIOUS"
                ] + det_analysis.matched_rule_ids

                det_analysis = DeterministicAnalysis(
                    indicators=aug_indicators,
                    primary_category=det_analysis.primary_category,
                    deterministic_score=100.0,
                    is_benign=False,
                    signal_count=len(aug_indicators),
                    matched_rule_ids=aug_rule_ids,
                    explanation=(
                        "Threat intelligence confirmed active "
                        f"malicious indicator: {threat_ind.description}"
                    ),
                )

    # 2c. AI Intent Reasoning
    det_signals = {
        "url_reputation_score": (
            100.0
            if (
                threat_intel_result
                and threat_intel_result.is_known_malicious
            )
            else 0.0
        ),
        "structural_flags": [
            ind.id
            for ind in det_analysis.indicators
            if "URL" in ind.id
        ],
        "message_flags": [
            ind.id
            for ind in det_analysis.indicators
            if "URL" not in ind.id
        ],
        "indicators": [
            ind.model_dump(by_alias=True)
            for ind in det_analysis.indicators
        ],
        "is_benign": det_analysis.is_benign,
        "primary_category": det_analysis.primary_category.value,
        "deterministic_score": det_analysis.deterministic_score,
    }

    ai_intent_result = analyze_intent(
        input_text=request.message,
        input_url=target_url,
        deterministic_signals=det_signals,
        locale_hint="en-IN",
        service=intent_service,
    )

    # 3. AWS Bedrock contextual analysis
    bedrock_result = analyze_with_bedrock(
        message=request.message,
        deterministic_analysis=det_analysis,
        client=bedrock_client,
    )

    # 4. Multi-layer risk fusion
    fused_response: AnalysisResponse = fuse_risk_analysis(
        deterministic=det_analysis,
        bedrock=bedrock_result,
        source_type=request.source_type,
        message_length=len(request.message),
        threat_intel=threat_intel_result,
        ai_intent=ai_intent_result,
    )

    # 5. DynamoDB persistence
    persisted = persist_analysis_record(
        response=fused_response,
        message_length=len(request.message),
        source_type=request.source_type,
        ai_available=bedrock_result.ai_available,
        model_id=bedrock_result.model_id,
        dynamodb_resource=dynamodb_resource,
    )

    return {
        "status": "received",
        "length": len(request.message),
        "deterministic": {
            "category": det_analysis.primary_category.value,
            "deterministic_score": det_analysis.deterministic_score,
            "indicators": [
                ind.model_dump(by_alias=True)
                for ind in det_analysis.indicators
            ],
            "is_benign": det_analysis.is_benign,
        },
        "ai_intent": ai_intent_result.to_dict(),
        "bedrock": bedrock_result.to_dict(),
        "fusion": fused_response.model_dump(by_alias=True),
        "persisted": persisted,
        "response": fused_response,
    }


def handler(
    event: Dict[str, Any],
    context: Optional[Any] = None,
) -> Dict[str, Any]:
    """AWS Lambda proxy entry point.

    Routes:
        GET  /health    -> Health check
        POST /analyze   -> ScamShield threat analysis
        OPTIONS *       -> CORS preflight
    """

    event = event or {}

    http_method = (
        event.get("httpMethod", "POST") or "POST"
    ).upper()

    path = event.get("path", "/analyze") or "/analyze"

    # ---------------------------------------------------------
    # 1. CORS preflight
    # ---------------------------------------------------------
    if http_method == "OPTIONS":
        return {
            "statusCode": 200,
            "headers": DEFAULT_CORS_HEADERS,
            "body": "",
        }

    # ---------------------------------------------------------
    # 2. Health check
    # ---------------------------------------------------------
    if path == "/health" or (
        http_method == "GET"
        and path in ("/", "/health")
    ):
        return health_handler(event, context)

    # ---------------------------------------------------------
    # 3. Analyze endpoint
    # ---------------------------------------------------------
    if http_method == "POST" and path == "/analyze":
        try:
            raw_body = event.get("body") or event

            if isinstance(raw_body, str):
                parsed_body = json.loads(raw_body)

            elif isinstance(raw_body, dict):
                parsed_body = raw_body

            else:
                raise RequestValidationError(
                    "Malformed request body"
                )

            message = (
                parsed_body.get("message")
                or parsed_body.get("content")
                or ""
            )

            source_type = (
                parsed_body.get("sourceType")
                or parsed_body.get("source_type")
                or "message"
            )

            # Execute complete analysis pipeline
            pipeline_result = run_pipeline(
                message=message,
                source_type=source_type,
            )

            fused_response: AnalysisResponse = (
                pipeline_result["response"]
            )

            return {
                "statusCode": 200,
                "headers": DEFAULT_CORS_HEADERS,
                "body": fused_response.model_dump_json(
                    by_alias=True
                ),
            }

        except json.JSONDecodeError:
            return {
                "statusCode": 400,
                "headers": DEFAULT_CORS_HEADERS,
                "body": json.dumps(
                    {
                        "error": {
                            "code": "VALIDATION_ERROR",
                            "message": (
                                "Malformed JSON payload "
                                "in request body"
                            ),
                            "details": [
                                {
                                    "field": "body",
                                    "reason": (
                                        "Invalid JSON syntax"
                                    ),
                                }
                            ],
                        }
                    }
                ),
            }

        except RequestValidationError as exc:
            return {
                "statusCode": exc.status_code,
                "headers": DEFAULT_CORS_HEADERS,
                "body": json.dumps(exc.to_dict()),
            }

        except ScamShieldError as exc:
            return {
                "statusCode": exc.status_code,
                "headers": DEFAULT_CORS_HEADERS,
                "body": json.dumps(exc.to_dict()),
            }

        except Exception:
            # Never expose internal implementation details.
            return {
                "statusCode": 500,
                "headers": DEFAULT_CORS_HEADERS,
                "body": json.dumps(
                    {
                        "error": {
                            "code": "INTERNAL_SERVER_ERROR",
                            "message": (
                                "An unexpected error occurred "
                                "while processing the request"
                            ),
                            "details": [],
                        }
                    }
                ),
            }

    # ---------------------------------------------------------
    # 4. Method / route not allowed
    # ---------------------------------------------------------
    return {
        "statusCode": 405,
        "headers": DEFAULT_CORS_HEADERS,
        "body": json.dumps(
            {
                "error": {
                    "code": "METHOD_NOT_ALLOWED",
                    "message": (
                        f"HTTP method {http_method} "
                        f"is not allowed on {path}"
                    ),
                    "details": [],
                }
            }
        ),
    }


# Standard AWS Lambda handler alias
lambda_handler = handler