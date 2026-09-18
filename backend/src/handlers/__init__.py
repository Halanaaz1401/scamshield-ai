"""ScamShield AI Handlers Package."""

from backend.src.handlers.analyze import handler
from backend.src.handlers.health import health_handler

__all__ = ["handler", "health_handler"]