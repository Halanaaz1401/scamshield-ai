"""Custom exceptions and structured error contracts for ScamShield AI."""

from typing import Any, Dict, List, Optional


class ScamShieldError(Exception):
    """Base exception for all ScamShield AI domain errors."""

    def __init__(
        self,
        message: str,
        code: str = "INTERNAL_ERROR",
        status_code: int = 500,
        details: Optional[List[Dict[str, str]]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or []

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to safe public API JSON dictionary."""
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "details": self.details,
            }
        }


class RequestValidationError(ScamShieldError):
    """Raised when a request fails schema or business validation rules."""

    def __init__(
        self,
        message: str = "Invalid analysis request",
        details: Optional[List[Dict[str, str]]] = None,
        code: str = "VALIDATION_ERROR",
    ) -> None:
        super().__init__(
            message=message,
            code=code,
            status_code=400,
            details=details or [],
        )


class EmptyInputError(RequestValidationError):
    """Raised when the submitted message is empty or whitespace only."""

    def __init__(
        self,
        reason: str = "Message cannot be empty",
        field: str = "message",
    ) -> None:
        super().__init__(
            message="Invalid analysis request",
            details=[{"field": field, "reason": reason}],
            code="VALIDATION_ERROR",
        )


class PayloadTooLargeError(RequestValidationError):
    """Raised when submitted message exceeds the 4,000-character threshold."""

    def __init__(
        self,
        max_length: int = 4000,
        actual_length: int = 0,
        field: str = "message",
    ) -> None:
        reason = (
            f"Message length ({actual_length} characters) exceeds the maximum "
            f"limit of {max_length} characters"
        )
        super().__init__(
            message="Invalid analysis request",
            details=[{"field": field, "reason": reason}],
            code="PAYLOAD_TOO_LARGE",
        )


class ResponseValidationError(ScamShieldError):
    """Raised when outbound assessment data violates response contract."""

    def __init__(
        self,
        message: str = "Invalid analysis response",
        details: Optional[List[Dict[str, str]]] = None,
    ) -> None:
        super().__init__(
            message=message,
            code="RESPONSE_VALIDATION_ERROR",
            status_code=500,
            details=details or [],
        )