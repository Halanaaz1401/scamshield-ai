"""Security controls regression suite for ScamShield AI (Phase 8 QA)."""

import json
from unittest.mock import MagicMock

import pytest

from backend.src.handlers.analyze import handler
from backend.src.services.storage_service import build_sanitized_record
from backend.src.models.response import AnalysisResponse, RiskLevel, ScamCategory


class TestSecurityControlsRegression:
    """Verifies all Phase 7 security controls remain active and non-regressed."""

    def test_zero_pii_storage_strictly_excludes_message_text(self):
        resp = AnalysisResponse(
            analysis_id="sec-101",
            risk_score=88.5,
            risk_level=RiskLevel.CRITICAL,
            scam_category=ScamCategory.PHISHING.value,
            red_flags=[],
            reasoning="Phishing credential harvest attempt",
            recommended_actions=["Block sender"],
        )
        record = build_sanitized_record(
            response=resp,
            message_length=150,
            source_type="sms",
            ai_available=True,
            model_id="claude-3-haiku",
        )
        # Assert key attributes
        assert "analysis_id" in record
        assert "risk_score" in record
        assert "ttl" in record
        assert "message" not in record
        assert "raw_message" not in record
        assert "user_message" not in record

    def test_api_handler_options_preflight_headers(self):
        event = {"httpMethod": "OPTIONS", "path": "/analyze"}
        res = handler(event, None)
        assert res["statusCode"] == 200
        headers = res["headers"]
        assert headers["Access-Control-Allow-Origin"] == "*"
        assert "POST" in headers["Access-Control-Allow-Methods"]
        assert "Content-Type" in headers["Access-Control-Allow-Headers"]