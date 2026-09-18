"""Health check Lambda handler for ScamShield AI."""

import json
from typing import Any, Dict, Optional


def health_handler(
    event: Optional[Dict[str, Any]] = None,
    context: Optional[Any] = None,
) -> Dict[str, Any]:
    """Return a minimal, safe health status response.

    Guarantees no internal environment variables, AWS account IDs,
    filesystem paths, dependency versions, or credentials are leaked.

    Returns:
        Dict[str, Any]: Standard API Gateway proxy response with {"status": "ok"}.
    """
    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type,Authorization",
            "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        },
        "body": json.dumps({"status": "ok"}),
    }
