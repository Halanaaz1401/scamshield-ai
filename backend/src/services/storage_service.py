"""Amazon DynamoDB minimal persistence service for ScamShield AI.

Persists sanitized threat analysis metadata strictly adhering to zero-PII privacy rules.
Never persists raw user message content, system prompts, or raw AI output.
Handles persistence failures gracefully without failing the user-facing analysis response.
"""

import logging
import os
import time
from decimal import Decimal
from typing import Any, Dict, Optional, Tuple

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from backend.src.models.response import AnalysisResponse

logger = logging.getLogger("scamshield.storage")

DEFAULT_TABLE_NAME = "scamshield-analysis-reports"
DEFAULT_AWS_REGION = "us-east-1"
RETENTION_DAYS = 30


def get_storage_config() -> Tuple[str, str]:
    """Obtain DynamoDB table name and region from environment."""
    table_name = (
        os.environ.get("DYNAMODB_TABLE_NAME")
        or os.environ.get("REPORTS_TABLE")
        or DEFAULT_TABLE_NAME
    ).strip()
    region = (
        os.environ.get("AWS_REGION")
        or os.environ.get("AWS_DEFAULT_REGION")
        or DEFAULT_AWS_REGION
    ).strip()
    return table_name, region


def get_dynamodb_resource(region: Optional[str] = None) -> Any:
    """Create a boto3 DynamoDB resource configured with the appropriate region."""
    _, default_region = get_storage_config()
    target_region = region or default_region
    return boto3.resource("dynamodb", region_name=target_region)


def build_sanitized_record(
    response: AnalysisResponse,
    message_length: int = 0,
    source_type: str = "message",
    ai_available: bool = False,
    model_id: str = "",
) -> Dict[str, Any]:
    """Construct minimal sanitized DynamoDB record adhering to Zero-PII privacy principles.

    Explicitly excludes:
    - Raw user message content
    - Bedrock full prompts and raw text
    - User IP addresses or personal identifiers
    """
    now_epoch = int(time.time())
    ttl_epoch = now_epoch + (RETENTION_DAYS * 86400)

    # Convert indicators to compact metadata
    indicator_summary = [
        {"id": ind.id, "severity": ind.severity.value, "name": ind.name}
        for ind in response.red_flags
    ]

    return {
        "analysis_id": response.analysis_id,
        "timestamp": response.timestamp,
        "risk_score": Decimal(str(response.risk_score)),
        "risk_level": response.risk_level.value,
        "category": response.scam_category,
        "indicator_count": len(response.red_flags),
        "indicators": indicator_summary,
        "source_type": source_type,
        "message_length": message_length,
        "ai_available": ai_available,
        "model_id": model_id or "deterministic_only",
        "ttl": ttl_epoch,
    }


def persist_analysis_record(
    response: AnalysisResponse,
    message_length: int = 0,
    source_type: str = "message",
    ai_available: bool = False,
    model_id: str = "",
    dynamodb_resource: Optional[Any] = None,
) -> bool:
    """Safely persist sanitized analysis record into DynamoDB.

    Returns:
        bool: True if write succeeded, False if write failed or was skipped.
        Never raises exceptions to ensure core analysis flow is not interrupted.
    """
    table_name, region = get_storage_config()

    try:
        resource = dynamodb_resource
        if resource is None:
            resource = get_dynamodb_resource(region)

        table = resource.Table(table_name)
        item = build_sanitized_record(
            response=response,
            message_length=message_length,
            source_type=source_type,
            ai_available=ai_available,
            model_id=model_id,
        )

        table.put_item(Item=item)
        logger.info("Persisted sanitized analysis record: %s", response.analysis_id)
        return True

    except (ClientError, BotoCoreError) as aws_err:
        logger.warning(
            "DynamoDB write skipped or failed (safe degradation): %s",
            type(aws_err).__name__,
        )
        return False
    except Exception as exc:
        logger.warning("Unexpected storage failure (safe degradation): %s", type(exc).__name__)
        return False