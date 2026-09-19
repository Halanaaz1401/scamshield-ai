"""Health check Lambda handler for ScamShield AI."""

import json
from typing import Any, Dict, Optional


def health_handler(
    event: Optional[Dict[str, Any]] = None,
    context: Optional[Any] = None,
) -> Dict[str, Any]:
    """Return a minimal, safe health status response.

    This endpoint is intended for:
    - AWS API Gateway health checks
    - Uptime monitoring
    - Deployment verification

    It intentionally does NOT expose:
    - Environment variables
    - AWS account IDs
    - Filesystem paths
    - Dependency versions
    - Credentials
    - Internal infrastructure details
    """

    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type,Authorization",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
            "Cache-Control": "no-store",
        },
        "body": json.dumps(
            {
                "status": "ok",
                "service": "ScamShield AI",
            }
        ),
    }


# Standard AWS Lambda handler alias
handler = health_handler