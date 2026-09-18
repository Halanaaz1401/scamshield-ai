"""Request validation module enforcing security boundaries on incoming data."""

import json
from typing import Any, Union
from pydantic import ValidationError

from backend.src.models.request import AnalysisRequest
from backend.src.utils.errors import (
    EmptyInputError,
    PayloadTooLargeError,
    RequestValidationError,
)

MAX_MESSAGE_LENGTH = 4000


def validate_analysis_request(payload: Union[str, bytes, dict, Any]) -> AnalysisRequest:
    """Parse and validate an untrusted incoming threat analysis request.

    Enforces:
    1. message must exist
    2. message must be a string
    3. message must not be empty
    4. message must not contain only whitespace
    5. maximum length = 4,000 characters
    6. leading/trailing whitespace is normalized safely
    7. no silent truncation
    8. structured error responses on failure
    9. prompt injection text is treated strictly as data

    Args:
        payload: Raw JSON string, bytes, or parsed dictionary.

    Returns:
        AnalysisRequest: Validated request model instance.

    Raises:
        EmptyInputError: If the message is empty or whitespace only.
        PayloadTooLargeError: If the message exceeds 4,000 characters.
        RequestValidationError: If the payload is malformed or invalid.
    """
    if payload is None:
        raise RequestValidationError(
            message="Invalid analysis request",
            details=[{"field": "message", "reason": "Missing required field: message"}],
        )

    # Parse JSON strings or bytes if necessary
    data: Any = payload
    if isinstance(payload, (str, bytes)):
        try:
            data = json.loads(payload)
        except (json.JSONDecodeError, UnicodeDecodeError) as err:
            raise RequestValidationError(
                message="Invalid analysis request",
                details=[{"field": "payload", "reason": f"Invalid JSON payload: {str(err)}"}],
            ) from err

    if not isinstance(data, dict):
        raise RequestValidationError(
            message="Invalid analysis request",
            details=[{"field": "payload", "reason": f"Expected JSON object, got {type(data).__name__}"}],
        )

    # Resolve message/content field
    raw_message = data.get("message")
    if raw_message is None and "content" in data:
        raw_message = data.get("content")

    if raw_message is None:
        raise RequestValidationError(
            message="Invalid analysis request",
            details=[{"field": "message", "reason": "Missing required field: message"}],
        )

    if not isinstance(raw_message, str):
        raise RequestValidationError(
            message="Invalid analysis request",
            details=[{"field": "message", "reason": f"Field 'message' must be a string, got {type(raw_message).__name__}"}],
        )

    stripped = raw_message.strip()
    if not stripped:
        raise EmptyInputError(reason="Message cannot be empty", field="message")

    if len(stripped) > MAX_MESSAGE_LENGTH:
        raise PayloadTooLargeError(
            max_length=MAX_MESSAGE_LENGTH,
            actual_length=len(stripped),
            field="message",
        )

    # Validate against Pydantic schema
    try:
        # Pass normalized data with 'message' field
        normalized_data = dict(data)
        normalized_data["message"] = stripped
        if "content" in normalized_data and "message" in normalized_data:
            normalized_data.pop("content")
        return AnalysisRequest.model_validate(normalized_data)
    except ValidationError as err:
        details = []
        for e in err.errors():
            field_name = ".".join(str(p) for p in e.get("loc", [])) or "message"
            reason = e.get("msg", "Invalid value")
            details.append({"field": field_name, "reason": reason})
        raise RequestValidationError(
            message="Invalid analysis request",
            details=details,
        ) from err