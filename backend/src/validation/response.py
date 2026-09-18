"""Response validation module enforcing schema integrity before client serialization."""

import json
from typing import Any, Union
from pydantic import ValidationError

from backend.src.models.response import AnalysisResponse
from backend.src.utils.errors import ResponseValidationError


def validate_analysis_response(payload: Union[str, bytes, dict, AnalysisResponse, Any]) -> AnalysisResponse:
    """Validate that generated analysis results strictly conform to the public API contract.

    Args:
        payload: AnalysisResponse instance, dictionary, or serialized JSON.

    Returns:
        AnalysisResponse: Validated response instance.

    Raises:
        ResponseValidationError: If the response fails schema or boundary checks.
    """
    if isinstance(payload, AnalysisResponse):
        return payload

    if payload is None:
        raise ResponseValidationError(
            message="Invalid analysis response",
            details=[{"field": "payload", "reason": "Response payload cannot be null"}],
        )

    data: Any = payload
    if isinstance(payload, (str, bytes)):
        try:
            data = json.loads(payload)
        except (json.JSONDecodeError, UnicodeDecodeError) as err:
            raise ResponseValidationError(
                message="Invalid analysis response",
                details=[{"field": "payload", "reason": f"Malformed response JSON: {str(err)}"}],
            ) from err

    if not isinstance(data, dict):
        raise ResponseValidationError(
            message="Invalid analysis response",
            details=[{"field": "payload", "reason": f"Expected dictionary response data, got {type(data).__name__}"}],
        )

    try:
        return AnalysisResponse.model_validate(data)
    except ValidationError as err:
        details = []
        for e in err.errors():
            loc = ".".join(str(p) for p in e.get("loc", [])) or "response"
            msg = e.get("msg", "Invalid value")
            details.append({"field": loc, "reason": msg})
        raise ResponseValidationError(
            message="Invalid analysis response",
            details=details,
        ) from err