"""Unit tests for risk fusion calibration boundaries, score mapping, and category matrix (Phase 8 QA)."""

import pytest

from backend.src.detection.engine import DeterministicAnalysis
from backend.src.models.response import Indicator, RiskLevel, ScamCategory, Severity
from backend.src.services.bedrock_service import BedrockAnalysisResult
from backend.src.services.risk_fusion import (
    calibrate_risk_level,
    compute_fused_risk_score,
    fuse_risk_analysis,
    reconcile_category,
)


class TestRiskCalibrationBoundaries:
    """Verifies strict boundary thresholds for risk score to categorical level calibration."""

    @pytest.mark.parametrize(
        "score,expected_level",
        [
            (0.0, RiskLevel.LOW),
            (10.0, RiskLevel.LOW),
            (29.9, RiskLevel.LOW),
            (30.0, RiskLevel.MEDIUM),
            (45.0, RiskLevel.MEDIUM),
            (59.9, RiskLevel.MEDIUM),
            (60.0, RiskLevel.HIGH),
            (70.0, RiskLevel.HIGH),
            (79.9, RiskLevel.HIGH),
            (80.0, RiskLevel.CRITICAL),
            (95.0, RiskLevel.CRITICAL),
            (100.0, RiskLevel.CRITICAL),
        ],
    )
    def test_score_to_risk_level_exact_thresholds(self, score: float, expected_level: RiskLevel):
        """Test exact decimal boundary transitions."""
        assert calibrate_risk_level(score) == expected_level

    def test_score_clamping_below_zero_and_above_hundred(self):
        """Test scores outside [0, 100] clamp safely."""
        assert calibrate_risk_level(-5.0) == RiskLevel.LOW
        assert calibrate_risk_level(105.0) == RiskLevel.CRITICAL


class TestCategoryReconciliationMatrix:
    """Verifies deterministic vs AI category resolution rules."""

    def test_deterministic_takes_precedence_when_high_confidence_match(self):
        """High-confidence deterministic categories are preserved."""
        det = DeterministicAnalysis(
            primary_category=ScamCategory.BANKING_SCAM,
            deterministic_score=85.0,
            indicators=[],
            is_benign=False,
            signal_count=2,
            matched_rule_ids=["IND_OTP_SOLICIT", "IND_BANK_IMPERSONATION"],
            explanation="Banking fraud signals",
        )
        ai_res = BedrockAnalysisResult(
            category=ScamCategory.OTHER_SUSPICIOUS,
            risk_assessment=RiskLevel.HIGH,
            reasoning="AI found suspicious activity",
            ai_available=True,
        )
        resolved = reconcile_category(det, ai_res, final_score=85.0)
        assert resolved == ScamCategory.BANKING_SCAM

    def test_ai_specializes_broad_category_when_deterministic_is_generic(self):
        """Generic deterministic category adopts Bedrock's specific category."""
        det = DeterministicAnalysis(
            primary_category=ScamCategory.OTHER_SUSPICIOUS,
            deterministic_score=40.0,
            indicators=[],
            is_benign=False,
            signal_count=1,
            matched_rule_ids=["IND_URGENCY"],
            explanation="Generic suspicion",
        )
        ai_res = BedrockAnalysisResult(
            category=ScamCategory.JOB_SCAM,
            risk_assessment=RiskLevel.HIGH,
            reasoning="Task scam pattern on Telegram",
            ai_available=True,
        )
        resolved = reconcile_category(det, ai_res, final_score=60.0)
        assert resolved == ScamCategory.JOB_SCAM

    def test_benign_agreement_yields_benign(self):
        """When both engines indicate safe content, category is BENIGN."""
        det = DeterministicAnalysis(
            primary_category=ScamCategory.BENIGN,
            deterministic_score=5.0,
            indicators=[],
            is_benign=True,
            signal_count=0,
            matched_rule_ids=[],
            explanation="No threats found",
        )
        ai_res = BedrockAnalysisResult(
            category=ScamCategory.BENIGN,
            risk_assessment=RiskLevel.LOW,
            reasoning="Clean informational text",
            ai_available=True,
        )
        resolved = reconcile_category(det, ai_res, final_score=5.0)
        assert resolved == ScamCategory.BENIGN


class TestFusionScoringEdgeCases:
    """Verifies corner cases in blended scoring."""

    def test_multi_signal_corroboration_bonus(self):
        """When deterministic has >= 3 signals and AI agrees HIGH/CRITICAL, bonus applies."""
        det = DeterministicAnalysis(
            primary_category=ScamCategory.BANKING_SCAM,
            deterministic_score=75.0,
            indicators=[
                Indicator(id="IND_1", name="Sig 1", description="desc", severity=Severity.HIGH),
                Indicator(id="IND_2", name="Sig 2", description="desc", severity=Severity.HIGH),
                Indicator(id="IND_3", name="Sig 3", description="desc", severity=Severity.MEDIUM),
            ],
            is_benign=False,
            signal_count=3,
            matched_rule_ids=["IND_1", "IND_2", "IND_3"],
            explanation="Multiple signals",
        )
        ai_res = BedrockAnalysisResult(
            category=ScamCategory.BANKING_SCAM,
            risk_assessment=RiskLevel.HIGH,
            reasoning="Strong multi-signal corroboration",
            ai_available=True,
        )
        fused = compute_fused_risk_score(det, ai_res)
        assert fused >= 85.0

    def test_ai_unavailable_relies_purely_on_deterministic(self):
        """When Bedrock is offline, score matches deterministic score exactly."""
        det = DeterministicAnalysis(
            primary_category=ScamCategory.PHISHING,
            deterministic_score=68.5,
            indicators=[Indicator(id="IND_LINK", name="Link", description="desc", severity=Severity.HIGH)],
            is_benign=False,
            signal_count=1,
            matched_rule_ids=["IND_LINK"],
            explanation="Phishing link",
        )
        ai_res = BedrockAnalysisResult(
            category=ScamCategory.OTHER_SUSPICIOUS,
            risk_assessment=RiskLevel.LOW,
            reasoning="Offline fallback",
            ai_available=False,
        )
        assert compute_fused_risk_score(det, ai_res) == 68.5