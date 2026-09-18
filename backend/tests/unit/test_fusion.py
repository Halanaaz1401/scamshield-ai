"""Unit tests for ScamShield AI Phase 5 Risk Fusion and DynamoDB persistence."""

import json
from decimal import Decimal
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from backend.src.detection import detect_threat_signals
from backend.src.detection.engine import DeterministicAnalysis
from backend.src.handlers.analyze import handler, run_pipeline
from backend.src.models.response import (
    AnalysisResponse,
    AttackStep,
    Indicator,
    RiskLevel,
    ScamCategory,
    Severity,
)
from backend.src.services.bedrock_service import BedrockAnalysisResult
from backend.src.services.risk_fusion import (
    calibrate_risk_level,
    compute_fused_risk_score,
    fuse_risk_analysis,
    reconcile_category,
)
from backend.src.services.storage_service import (
    build_sanitized_record,
    get_storage_config,
    persist_analysis_record,
)


class TestRiskFusionScoring:
    """Test multi-layer score calibration and category reconciliation."""

    def test_strong_deterministic_and_high_ai_risk(self):
        """Test multi-signal scam with both deterministic and AI agreement."""
        det = DeterministicAnalysis(
            indicators=[
                Indicator(id="IND_OTP_SOLICIT", name="OTP Solicit", description="OTP", severity=Severity.CRITICAL),
                Indicator(id="IND_IMPERSONATION_BANK", name="Bank Spoof", description="Bank", severity=Severity.HIGH),
                Indicator(id="IND_URGENCY_TACTIC", name="Urgency", description="Urgent", severity=Severity.HIGH),
            ],
            primary_category=ScamCategory.BANKING_SCAM,
            deterministic_score=95.0,
            is_benign=False,
            signal_count=3,
            matched_rule_ids=["IND_OTP_SOLICIT", "IND_IMPERSONATION_BANK", "IND_URGENCY_TACTIC"],
            explanation="Multiple high-severity signals.",
        )
        ai = BedrockAnalysisResult(
            category=ScamCategory.BANKING_SCAM,
            risk_assessment=RiskLevel.CRITICAL,
            reasoning="Severe phishing threat targeting netbanking logins.",
            ai_available=True,
        )

        score = compute_fused_risk_score(det, ai)
        level = calibrate_risk_level(score)

        assert score >= 85.0
        assert score <= 100.0
        assert level == RiskLevel.CRITICAL

    def test_strong_deterministic_critical_floor_when_ai_hallucinates_low(self):
        """Test that AI cannot downgrade explicit credential/OTP solicitations below 80.0."""
        det = DeterministicAnalysis(
            indicators=[
                Indicator(id="IND_CREDENTIAL_SOLICIT", name="CVV Request", description="CVV", severity=Severity.CRITICAL),
            ],
            primary_category=ScamCategory.CREDENTIAL_THEFT,
            deterministic_score=45.0,
            is_benign=False,
            signal_count=1,
            matched_rule_ids=["IND_CREDENTIAL_SOLICIT"],
            explanation="Critical credential harvesting.",
        )
        ai = BedrockAnalysisResult(
            category=ScamCategory.BENIGN,
            risk_assessment=RiskLevel.LOW,
            reasoning="AI falsely thought this was benign.",
            ai_available=True,
        )

        score = compute_fused_risk_score(det, ai)
        level = calibrate_risk_level(score)

        # Critical rule floor must enforce CRITICAL minimum of 80.0
        assert score >= 80.0
        assert level == RiskLevel.CRITICAL

    def test_weak_deterministic_with_high_ai_risk_contextual_catch(self):
        """Test social engineering catch when rules find 0 cues but AI spots emotional manipulation."""
        det = DeterministicAnalysis(
            indicators=[],
            primary_category=ScamCategory.BENIGN,
            deterministic_score=0.0,
            is_benign=True,
            signal_count=0,
            matched_rule_ids=[],
            explanation="No deterministic indicators.",
        )
        ai = BedrockAnalysisResult(
            category=ScamCategory.JOB_SCAM,
            risk_assessment=RiskLevel.HIGH,
            reasoning="Deceptive recruitment scheme.",
            ai_available=True,
        )

        score = compute_fused_risk_score(det, ai)
        level = calibrate_risk_level(score)

        assert score >= 50.0
        assert score <= 75.0
        assert level in (RiskLevel.HIGH, RiskLevel.MEDIUM)

    def test_benign_agreement_yields_low_score(self):
        """Test that benign messages with 0 cues and LOW AI assessment remain LOW."""
        det = DeterministicAnalysis(
            indicators=[],
            primary_category=ScamCategory.BENIGN,
            deterministic_score=0.0,
            is_benign=True,
            signal_count=0,
            matched_rule_ids=[],
            explanation="Clean message.",
        )
        ai = BedrockAnalysisResult(
            category=ScamCategory.BENIGN,
            risk_assessment=RiskLevel.LOW,
            reasoning="Authentic conversational text.",
            ai_available=True,
        )

        score = compute_fused_risk_score(det, ai)
        level = calibrate_risk_level(score)

        assert score <= 10.0
        assert level == RiskLevel.LOW

    def test_deterministic_only_fallback_when_ai_offline(self):
        """Test score calculation when Bedrock is offline."""
        det = DeterministicAnalysis(
            indicators=[
                Indicator(id="IND_URGENCY_TACTIC", name="Urgent", description="Urgent", severity=Severity.HIGH),
            ],
            primary_category=ScamCategory.OTHER_SUSPICIOUS,
            deterministic_score=25.0,
            is_benign=False,
            signal_count=1,
            matched_rule_ids=["IND_URGENCY_TACTIC"],
            explanation="Urgent notice.",
        )
        ai = BedrockAnalysisResult(
            category=ScamCategory.OTHER_SUSPICIOUS,
            risk_assessment=RiskLevel.MEDIUM,
            reasoning="AI unavailable fallback.",
            ai_available=False,  # Offline!
        )

        score = compute_fused_risk_score(det, ai)
        assert score == 25.0

    def test_category_reconciliation_rules(self):
        """Test authoritative category reconciliation precedence."""
        det_kyc = DeterministicAnalysis(
            indicators=[Indicator(id="IND_KYC_SUSPENSION", name="KYC", description="KYC", severity=Severity.HIGH)],
            primary_category=ScamCategory.ACCOUNT_KYC_SCAM,
            deterministic_score=40.0,
            is_benign=False,
            signal_count=1,
            matched_rule_ids=["IND_KYC_SUSPENSION"],
            explanation="KYC",
        )
        ai_phish = BedrockAnalysisResult(
            category=ScamCategory.PHISHING,
            risk_assessment=RiskLevel.HIGH,
            reasoning="Phishing link.",
            ai_available=True,
        )
        # Deterministic KYC is specific ground truth
        assert reconcile_category(det_kyc, ai_phish, 65.0) == ScamCategory.ACCOUNT_KYC_SCAM

        # When deterministic is generic OTHER_SUSPICIOUS, AI category is adopted
        det_generic = DeterministicAnalysis(
            indicators=[],
            primary_category=ScamCategory.OTHER_SUSPICIOUS,
            deterministic_score=15.0,
            is_benign=False,
            signal_count=1,
            matched_rule_ids=[],
            explanation="Suspicious",
        )
        ai_job = BedrockAnalysisResult(
            category=ScamCategory.JOB_SCAM,
            risk_assessment=RiskLevel.HIGH,
            reasoning="Telegram task scam.",
            ai_available=True,
        )
        assert reconcile_category(det_generic, ai_job, 60.0) == ScamCategory.JOB_SCAM


class TestDynamoDBPersistence:
    """Test minimal, sanitized DynamoDB persistence service."""

    def test_sanitized_record_contains_no_raw_user_message(self):
        """Verify that stored record excludes raw message content and credentials."""
        response = AnalysisResponse(
            riskScore=88.0,
            riskLevel=RiskLevel.HIGH,
            category=ScamCategory.PAYMENT_SCAM.value,
            reasoning="Reverse UPI trap.",
            recommendedAction="Decline request.",
        )

        record = build_sanitized_record(
            response=response,
            message_length=140,
            source_type="whatsapp",
            ai_available=True,
            model_id="claude-3-5-sonnet",
        )

        # Confirm zero PII
        assert "message" not in record
        assert "raw_message" not in record
        assert "content" not in record
        assert "prompt" not in record
        assert "credentials" not in record

        # Confirm required fields
        assert record["analysis_id"] == response.analysis_id
        assert record["risk_score"] == Decimal("88.0")
        assert record["risk_level"] == "HIGH"
        assert record["category"] == "PAYMENT_SCAM"
        assert record["message_length"] == 140
        assert record["source_type"] == "whatsapp"
        assert "ttl" in record

    def test_successful_dynamodb_write_with_mock(self):
        """Test put_item invocation on mocked DynamoDB resource."""
        mock_table = MagicMock()
        mock_resource = MagicMock()
        mock_resource.Table.return_value = mock_table

        response = AnalysisResponse(
            riskScore=75.0,
            riskLevel=RiskLevel.HIGH,
            reasoning="Phishing link.",
            recommendedAction="Do not click.",
        )

        success = persist_analysis_record(
            response=response,
            message_length=95,
            source_type="sms",
            ai_available=True,
            model_id="claude-3-5-sonnet",
            dynamodb_resource=mock_resource,
        )

        assert success is True
        mock_table.put_item.assert_called_once()

    def test_dynamodb_failure_gracefully_degrades(self):
        """Test that DynamoDB write errors return False and do NOT raise exceptions."""
        mock_table = MagicMock()
        mock_table.put_item.side_effect = ClientError(
            error_response={"Error": {"Code": "ResourceNotFoundException", "Message": "Table not found"}},
            operation_name="PutItem",
        )
        mock_resource = MagicMock()
        mock_resource.Table.return_value = mock_table

        response = AnalysisResponse(
            riskScore=50.0,
            riskLevel=RiskLevel.MEDIUM,
            reasoning="Suspicious notice.",
            recommendedAction="Verify.",
        )

        # Must not raise an exception
        success = persist_analysis_record(
            response=response,
            dynamodb_resource=mock_resource,
        )
        assert success is False


class TestCompleteAnalyzePipeline:
    """Test full pipeline integration in POST /analyze Lambda handler."""

    def test_end_to_end_pipeline_with_mocked_clients(self):
        """Test POST /analyze handler executing end-to-end pipeline with mocked Bedrock and DynamoDB."""
        mock_bedrock = MagicMock()
        ai_payload = {
            "category": "ACCOUNT_KYC_SCAM",
            "risk_assessment": "CRITICAL",
            "reasoning": "Fake KYC deactivation threat stealing credentials.",
            "attacker_intent": "Steal netbanking login.",
            "attack_path": [
                {"step": 1, "stage": "Inbound SMS", "description": "PAN expired SMS."},
                {"step": 2, "stage": "Panic Pressure", "description": "2 hour ultimatum."},
            ],
            "recommended_actions": ["Do not click link", "Check official bank portal"],
        }
        mock_bedrock.converse.return_value = {
            "output": {"message": {"content": [{"text": json.dumps(ai_payload)}]}},
            "usage": {"totalTokens": 150},
        }

        mock_dynamo = MagicMock()

        msg = "Dear Customer, your HDFC bank account suspended due to PAN-KYC. Update at https://hdfc-kyc.xyz in 2 hours."
        pipeline_output = run_pipeline(
            message=msg,
            source_type="sms",
            bedrock_client=mock_bedrock,
            dynamodb_resource=mock_dynamo,
        )

        # Check returned pipeline structure
        assert pipeline_output["status"] == "received"
        assert pipeline_output["length"] == len(msg)
        assert "response" in pipeline_output

        fused: AnalysisResponse = pipeline_output["response"]
        assert fused.risk_score >= 80.0
        assert fused.risk_level == RiskLevel.CRITICAL
        assert fused.scam_category in (ScamCategory.ACCOUNT_KYC_SCAM.value, ScamCategory.BANKING_SCAM.value)
        assert len(fused.red_flags) >= 2
        assert len(fused.attack_path) >= 2
        assert len(fused.recommended_actions) >= 2

    def test_handler_post_analyze_full_response_contract(self):
        """Verify that handler returns full AnalysisResponse JSON adhering to contract."""
        event = {
            "httpMethod": "POST",
            "path": "/analyze",
            "body": json.dumps({
                "message": "Congratulations! You won ₹50,000 lottery. Approve collect request upi://pay?pa=prize@upi",
                "sourceType": "whatsapp",
            }),
        }

        resp = handler(event)
        assert resp["statusCode"] == 200

        data = json.loads(resp["body"])
        assert "riskScore" in data
        assert "riskLevel" in data
        assert "category" in data
        assert "indicators" in data
        assert "reasoning" in data
        assert "attackPath" in data
        assert "recommendedAction" in data
        assert "recommendedActions" in data
        assert "status" in data
        assert data["status"] == "received"
        assert data["length"] > 0
