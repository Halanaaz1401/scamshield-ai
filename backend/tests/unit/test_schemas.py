"""Unit tests for ScamShield AI request/response Pydantic models."""

import pytest
from pydantic import ValidationError

from backend.src.models.request import AnalysisRequest, SourceType
from backend.src.models.response import (
    AnalysisResponse,
    AttackStep,
    Indicator,
    RedFlag,
    RiskLevel,
    ScamCategory,
    Severity,
)


class TestAnalysisRequestSchema:
    """Test schema behavior and constraints for AnalysisRequest."""

    def test_valid_request_with_message(self):
        req = AnalysisRequest(message="Your bank account is suspended. Call immediately.")
        assert req.message == "Your bank account is suspended. Call immediately."
        assert req.content == "Your bank account is suspended. Call immediately."
        assert req.source_type == SourceType.MESSAGE

    def test_valid_request_with_content_alias(self):
        req = AnalysisRequest.model_validate({"content": "Please send OTP to verify account."})
        assert req.message == "Please send OTP to verify account."
        assert req.content == "Please send OTP to verify account."

    def test_valid_request_with_custom_source_type(self):
        req = AnalysisRequest(message="http://suspicious-claim.xyz", sourceType="url")
        assert req.source_type == SourceType.URL

    def test_exactly_4000_characters(self):
        exact_content = "A" * 4000
        req = AnalysisRequest(message=exact_content)
        assert len(req.message) == 4000

    def test_over_4000_characters_fails(self):
        over_content = "B" * 4001
        with pytest.raises(ValidationError) as exc:
            AnalysisRequest(message=over_content)
        assert "4000" in str(exc.value)

    def test_empty_string_fails(self):
        with pytest.raises(ValidationError):
            AnalysisRequest(message="")

    def test_whitespace_only_fails(self):
        with pytest.raises(ValidationError):
            AnalysisRequest(message="   \n\t   ")


class TestAnalysisResponseSchema:
    """Test schema integrity, serialization, and frontend compatibility for AnalysisResponse."""

    def test_valid_minimal_response(self):
        resp = AnalysisResponse(
            riskScore=85.5,
            riskLevel=RiskLevel.HIGH,
            category=ScamCategory.BANKING_SCAM.value,
            reasoning="Demands OTP to authorize unauthorized debit transaction.",
            recommendedAction="Never provide your OTP to anyone over SMS or call.",
        )
        assert resp.risk_score == 85.5
        assert resp.risk_level == RiskLevel.HIGH
        assert resp.scam_category == "BANKING_SCAM"
        assert resp.analysis_id is not None
        assert resp.timestamp is not None
        assert resp.recommended_actions == [resp.recommended_action]

    def test_valid_full_response_with_indicators_and_attack_path(self):
        indicator = RedFlag(
            id="IND_OTP_REQUEST",
            name="OTP Extraction",
            description="The message requests a one-time password.",
            severity=Severity.CRITICAL,
            evidence="Send OTP to 9876543210",
        )
        step = AttackStep(
            step=1,
            stage="Lure & Urgency",
            description="Simulates bank alert threatening account closure.",
        )
        resp = AnalysisResponse(
            analysisId="test-uuid-1234",
            riskScore=92.0,
            riskLevel=RiskLevel.CRITICAL,
            category=ScamCategory.BANKING_SCAM.value,
            indicators=[indicator],
            reasoning="High probability credential and OTP harvesting scheme.",
            attackerIntent="Extract OTP to authorize fraudulent wire transfer.",
            attackPath=[step],
            recommendedAction="Do not share OTP.",
            recommendedActions=["Do not share OTP.", "Block sender.", "Alert bank."],
        )
        assert len(resp.red_flags) == 1
        assert resp.red_flags[0].severity == Severity.CRITICAL
        assert len(resp.attack_path) == 1
        assert resp.attack_path[0].stage == "Lure & Urgency"

    def test_frontend_camelcase_serialization(self):
        resp = AnalysisResponse(
            analysisId="fixed-uuid",
            riskScore=75.0,
            riskLevel=RiskLevel.MEDIUM,
            reasoning="Suspicious reward claim link.",
            recommendedAction="Do not click link.",
        )
        dumped = resp.model_dump(by_alias=True)

        # Confirm all camelCase keys expected by frontend/types/analysis.ts exist
        assert "analysisId" in dumped
        assert "riskScore" in dumped
        assert "riskLevel" in dumped
        assert "indicators" in dumped
        assert "reasoning" in dumped
        assert "recommendedAction" in dumped
        assert "timestamp" in dumped
        assert dumped["riskScore"] == 75.0
        assert dumped["riskLevel"] == "MEDIUM"

    def test_legacy_risk_level_mapping(self):
        # Maps legacy SAFE / SUSPICIOUS / MALICIOUS to LOW / MEDIUM / HIGH
        resp_safe = AnalysisResponse(
            riskScore=10.0,
            riskLevel="SAFE",
            reasoning="Safe",
            recommendedAction="None",
        )
        assert resp_safe.risk_level == RiskLevel.LOW

        resp_malicious = AnalysisResponse(
            riskScore=90.0,
            riskLevel="MALICIOUS",
            reasoning="Danger",
            recommendedAction="Block",
        )
        assert resp_malicious.risk_level == RiskLevel.HIGH

    def test_invalid_score_bounds(self):
        with pytest.raises(ValidationError):
            AnalysisResponse(
                riskScore=105.0,  # exceeds 100
                riskLevel=RiskLevel.HIGH,
                reasoning="Test",
                recommendedAction="Test",
            )

        with pytest.raises(ValidationError):
            AnalysisResponse(
                riskScore=-5.0,  # below 0
                riskLevel=RiskLevel.LOW,
                reasoning="Test",
                recommendedAction="Test",
            )