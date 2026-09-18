"""Request data models for threat analysis."""

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class SourceType(str, Enum):
    """Supported threat source vectors."""

    SMS = "sms"
    EMAIL = "email"
    MESSAGE = "message"
    URL = "url"
    OTHER = "other"
    WHATSAPP = "whatsapp"
    TELEGRAM = "telegram"


class AnalysisRequest(BaseModel):
    """Analysis request payload model representing untrusted user submission."""

    model_config = ConfigDict(
        populate_by_name=True,
        str_strip_whitespace=True,
        extra="forbid",
    )

    message: str = Field(
        ...,
        description="The raw suspicious communication text to analyze.",
        min_length=1,
        max_length=4000,
    )
    source_type: Optional[SourceType] = Field(
        default=SourceType.MESSAGE,
        alias="sourceType",
        description="Communication channel or source format.",
    )

    @property
    def content(self) -> str:
        """Backward-compatible alias for frontend content field."""
        return self.message

    @model_validator(mode="before")
    @classmethod
    def resolve_aliases(cls, data: Any) -> Any:
        """Resolve 'content' alias to 'message' for unified handling."""
        if isinstance(data, dict):
            data = dict(data)
            if "message" not in data and "content" in data:
                data["message"] = data.pop("content")
            st = data.get("sourceType") or data.get("source_type")
            if st and isinstance(st, str):
                st_lower = st.lower().strip()
                valid_types = {s.value for s in SourceType}
                if st_lower not in valid_types:
                    data["sourceType"] = "other"
        return data

    @field_validator("message", mode="after")
    @classmethod
    def validate_message_bounds(cls, value: str) -> str:
        """Reject empty, whitespace-only, or oversized strings without truncating."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("Message cannot be empty")
        if len(stripped) > 4000:
            raise ValueError(
                f"Message length ({len(stripped)}) exceeds maximum limit of 4000 characters"
            )
        return stripped