"""Focused unit tests for Indian Scam Intelligence, Deep URL Intelligence, and Evidence Engine."""

import pytest
from backend.src.detection.engine import detect_threat_signals
from backend.src.detection.url_intelligence import analyze_url_deep
from backend.src.models.response import ScamCategory, RiskLevel
from backend.src.services.bedrock_service import BedrockAnalysisResult
from backend.src.services.risk_fusion import fuse_risk_analysis


class TestIndianScamIntelligence:
    """Tests covering realistic Indian cyber fraud scenarios."""

    def test_electricity_disconnect_scam(self):
        msg = "Dear consumer, your electricity power will be disconnected tonight at 9:30 PM from power office because your previous month bill was not updated. Please immediately contact our electricity officer at 9876543210."
        result = detect_threat_signals(msg)
        assert result.deterministic_score >= 60.0
        assert result.primary_category == ScamCategory.ELECTRICITY_SCAM
        assert any(ind.id == "IND_ELECTRICITY_DISCONNECT" for ind in result.indicators)

        # Verify Evidence Engine attributes
        elec_ind = next(ind for ind in result.indicators if ind.id == "IND_ELECTRICITY_DISCONNECT")
        assert elec_ind.why_it_matters is not None
        assert elec_ind.attacker_objective is not None
        assert elec_ind.attack_stage is not None

        # Verify dynamic attack path in risk fusion
        fused = fuse_risk_analysis(
            result,
            BedrockAnalysisResult(category=ScamCategory.OTHER_SUSPICIOUS, risk_assessment=RiskLevel.HIGH, reasoning="", ai_available=False),
            message_length=len(msg),
        )
        assert fused.scam_category == ScamCategory.ELECTRICITY_SCAM.value
        assert any("utility" in step.description.lower() or "power" in step.description.lower() for step in fused.attack_path)

    def test_courier_customs_digital_arrest_scam(self):
        msg = "DHL Express Notice: Your parcel AWB-98231 has been seized at customs Mumbai. Illegal narcotics and fake passports found. Case transferred to CBI Narcotics Bureau. You are under digital arrest, call officer immediately."
        result = detect_threat_signals(msg)
        assert result.deterministic_score >= 60.0
        assert result.primary_category == ScamCategory.COURIER_SCAM
        assert any(ind.id == "IND_COURIER_PARCEL" for ind in result.indicators)

        fused = fuse_risk_analysis(
            result,
            BedrockAnalysisResult(category=ScamCategory.OTHER_SUSPICIOUS, risk_assessment=RiskLevel.HIGH, reasoning="", ai_available=False),
        )
        assert fused.scam_category == ScamCategory.COURIER_SCAM.value
        assert any("arrest" in step.description.lower() or "parcel" in step.description.lower() for step in fused.attack_path)

    def test_sim_deactivation_scam(self):
        msg = "Dear Airtel user, your SIM card will be deactivated within 24 hrs because your KYC document expired. Immediately submit Aadhaar to avoid disconnection."
        result = detect_threat_signals(msg)
        assert result.deterministic_score >= 50.0
        assert result.primary_category == ScamCategory.SIM_DEACTIVATION_SCAM
        assert any(ind.id == "IND_SIM_DEACTIVATION" for ind in result.indicators)

    def test_fake_customer_support_scam(self):
        msg = "Google Pay toll free customer care helpline number 9876543210. 24x7 support for refund failed transaction issue."
        result = detect_threat_signals(msg)
        assert result.deterministic_score >= 25.0
        assert result.primary_category == ScamCategory.CUSTOMER_SUPPORT_SCAM
        assert any(ind.id == "IND_CUSTOMER_SUPPORT" for ind in result.indicators)

    def test_malicious_apk_scam(self):
        msg = "Download PM Yojna reward claim app immediately: https://sbi-rewards.xyz/update.apk to claim your 5000 cashback."
        result = detect_threat_signals(msg)
        assert result.deterministic_score >= 70.0
        assert any(ind.id == "IND_MALICIOUS_APK" for ind in result.indicators)

    def test_hinglish_upi_scam(self):
        msg = "Bhai jaldi se 5000 rupay receive karne ke liye apna UPI PIN enter karo is QR code par, turant paise credit honge."
        result = detect_threat_signals(msg)
        assert result.deterministic_score >= 60.0
        assert any(ind.id == "IND_REVERSE_UPI" for ind in result.indicators)

    def test_obfuscation_spaced_brand_and_zero_width(self):
        # S B I with zero-width characters and spaces
        msg = "Urgent: Your S\u200bB\u200bI NetBanking account is blocked. Verify KYC immediately at https://secure-login.xyz"
        result = detect_threat_signals(msg)
        assert result.deterministic_score >= 60.0
        # Brand impersonation indicator triggered
        assert any("impersonat" in ind.description.lower() or "brand" in ind.name.lower() or ind.id == "IND_SUSPICIOUS_URL" for ind in result.indicators)


class TestDeepUrlIntelligence:
    """Tests covering lightweight, deterministic deep URL intelligence."""

    def test_brand_impersonation_typosquatting(self):
        findings = analyze_url_deep("https://sbi-verify-login.xyz/login")
        assert len(findings) > 0
        rule_ids = [f["rule_id"] for f in findings]
        assert "IND_URL_BRAND_IMPERSONATION" in rule_ids
        assert "IND_URL_SUSPICIOUS_TLD" in rule_ids
        assert "IND_URL_DECEPTIVE_PATH" in rule_ids

    def test_homoglyph_cyrillic_lookalike(self):
        # 'раypal.com' using Cyrillic 'а' (\u0430)
        cyrillic_url = "https://p\u0430ypal.com/signin"
        findings = analyze_url_deep(cyrillic_url)
        assert any(f["rule_id"] == "IND_URL_HOMOGLYPH" for f in findings)

    def test_numeric_ip_host(self):
        findings = analyze_url_deep("http://192.168.1.1/banking/login")
        assert any(f["rule_id"] == "IND_URL_IP_HOST" for f in findings)

    def test_shortened_url(self):
        findings = analyze_url_deep("https://bit.ly/claim-prize-now")
        assert any(f["rule_id"] == "IND_URL_SHORTENER" for f in findings)

    def test_apk_download_path(self):
        findings = analyze_url_deep("https://reward-portal.online/app/install.apk")
        assert any(f["rule_id"] in ("IND_MALICIOUS_APK", "IND_URL_APK_DOWNLOAD") for f in findings)


class TestEvidenceEngineAndFalsePositiveChecks:
    """Tests verifying evidence tracing, confidence scoring, and false-positive checks."""

    def test_benign_message_generates_false_positive_checks(self):
        msg = "Hi Mom, I will be home around 7 PM for dinner tonight. See you soon!"
        result = detect_threat_signals(msg)
        assert result.is_benign is True
        assert result.deterministic_score <= 10.0

        fused = fuse_risk_analysis(
            result,
            BedrockAnalysisResult(category=ScamCategory.BENIGN, risk_assessment=RiskLevel.LOW, reasoning="Personal message", ai_available=False),
        )
        assert fused.risk_level == RiskLevel.LOW
        assert fused.scam_category == ScamCategory.BENIGN.value
        assert fused.false_positive_checks is not None
        assert len(fused.false_positive_checks) >= 3
        assert fused.confidence in ("HIGH", "MEDIUM")

    def test_evidence_traceability_on_banking_scam(self):
        msg = "Your HDFC Bank account 9210 will be blocked today due to pending KYC. Visit https://hdfc-kyc.top to avoid debit freeze."
        result = detect_threat_signals(msg)
        assert result.deterministic_score >= 60.0

        for ind in result.indicators:
            assert ind.name != ""
            assert ind.description != ""
            assert ind.why_it_matters is not None
            assert ind.attacker_objective is not None
            assert ind.attack_stage is not None

