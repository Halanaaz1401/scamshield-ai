"""Comprehensive URL Threat Intelligence & Heuristics Test Matrix (Categories A to J).

Mandatory test coverage verifying:
- Category A: Known malicious URLs (Simulated threat intelligence match)
- Category B: Known benign URLs (Whitelisted official institutional domains)
- Category C: URL shorteners (Cloaking identification)
- Category D: Suspicious newly structured domains (Excessive subdomains, high-abuse TLDs)
- Category E: Brand impersonation & domain deception (Counterfeit bank/brand domains)
- Category F: LPG / gas subsidy phishing (Context vs. destination mismatch)
- Category G: Bank / KYC phishing (Counterfeit netbanking verification)
- Category H: UPI / payment phishing (Fraudulent reward/cashback collect)
- Category I: Government & statutory impersonation (Fake police, tax, digilocker)
- Category J: Completely unknown arbitrary URLs (Verified: NEVER SAFE -> UNKNOWN_UNVERIFIED)
"""

from unittest.mock import MagicMock
import pytest

from backend.src.detection.engine import detect_threat_signals
from backend.src.detection.url_intelligence import (
    extract_urls,
    inspect_url_deep,
    is_authoritative_domain,
)
from backend.src.handlers.analyze import run_pipeline
from backend.src.models.response import RiskLevel, ScamCategory, Severity
from backend.src.services.bedrock_service import BedrockAnalysisResult
from backend.src.services.risk_fusion import (
    compute_calibrated_verdict,
    compute_fused_risk_score,
    fuse_risk_analysis,
)
from backend.src.services.threat_intel_service import (
    ThreatIntelligenceService,
    ThreatIntelResult,
)


class TestUrlThreatMatrixCategoriesAtoJ:
    """Rigorous evaluation matrix across all 10 required URL categories."""

    # ------------------------------------------------------------------------
    # Category A: Known Malicious URLs (External Threat Intelligence Match)
    # ------------------------------------------------------------------------
    def test_category_a_known_malicious_threat_intel(self):
        """Category A: URL with positive Google Web Risk match must receive KNOWN_MALICIOUS verdict."""
        mock_ti = MagicMock(spec=ThreatIntelligenceService)
        mock_ti.is_configured = True
        mock_ti.lookup_url.return_value = ThreatIntelResult(
            status="malicious",
            is_known_malicious=True,
            threat_types=["SOCIAL_ENGINEERING", "MALWARE"],
            provider="google_web_risk",
            details="Confirmed phishing kit and credential harvester",
        )

        res = run_pipeline(
            message="Please log in immediately: https://verified-threat-phish.xyz/login",
            threat_intel_service=mock_ti,
        )
        response = res["response"]

        assert response.risk_score >= 95.0
        assert response.risk_level == RiskLevel.CRITICAL
        assert response.verdict == "KNOWN_MALICIOUS"
        assert response.threat_intelligence is not None
        assert response.threat_intelligence["isKnownMalicious"] is True
        assert any(ind.id == "IND_THREAT_INTEL_MALICIOUS" for ind in response.indicators)

    # ------------------------------------------------------------------------
    # Category B: Known Benign URLs (Official Institutional Whitelist)
    # ------------------------------------------------------------------------
    def test_category_b_known_benign_official_domains(self):
        """Category B: Official authoritative domains must receive BENIGN / LOW risk."""
        benign_urls = [
            "https://www.onlinesbi.sbi",
            "https://netbanking.hdfcbank.com",
            "https://incometax.gov.in",
            "https://bluedart.com/track/12345",
            "https://www.google.com",
        ]
        for url in benign_urls:
            inds = inspect_url_deep(url)
            assert not any(ind.severity in (Severity.CRITICAL, Severity.HIGH) for ind in inds)
            assert not any(ind.id == "IND_URL_UNVERIFIED_DESTINATION" for ind in inds)
            assert is_authoritative_domain(url.split("//")[1].split("/")[0]) is True

            res = run_pipeline(f"Your official receipt: {url}")
            assert res["response"].risk_score <= 10.0
            assert res["response"].risk_level == RiskLevel.LOW
            assert res["response"].verdict in ("BENIGN", "LOW_RISK")

    # ------------------------------------------------------------------------
    # Category C: URL Shorteners (Cloaking Identification)
    # ------------------------------------------------------------------------
    def test_category_c_url_shorteners(self):
        """Category C: Link shorteners must be flagged as cloaking services."""
        shorteners = [
            "https://bit.ly/lpg-subsidy-2026",
            "https://tinyurl.com/sbi-kyc-verify",
            "https://t.co/urgent-claim",
            "https://is.gd/reward99",
        ]
        for url in shorteners:
            inds = inspect_url_deep(url)
            assert any(ind.id == "IND_URL_SHORTENER" for ind in inds)

            res = run_pipeline(f"Urgent update required: {url}")
            assert res["response"].risk_score >= 30.0
            assert res["response"].verdict in ("SUSPICIOUS", "HIGH_RISK", "UNKNOWN_UNVERIFIED")

    # ------------------------------------------------------------------------
    # Category D: Suspicious Newly Structured Domains
    # ------------------------------------------------------------------------
    def test_category_d_suspicious_domain_structures(self):
        """Category D: Non-standard TLDs and excessive subdomains must trigger high/medium heuristics."""
        url = "https://portal.update.verification.customer-check.cfd/auth"
        inds = inspect_url_deep(url)
        ind_ids = [i.id for i in inds]
        assert "IND_URL_SUSPICIOUS_TLD" in ind_ids  # .cfd
        assert "IND_URL_EXCESSIVE_SUBDOMAINS" in ind_ids
        assert "IND_URL_DECEPTIVE_PATH" in ind_ids  # /auth

        res = run_pipeline(f"Action required at {url}")
        assert res["response"].risk_score >= 60.0
        assert res["response"].risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)

    # ------------------------------------------------------------------------
    # Category E: Brand Impersonation & Subdomain Deception
    # ------------------------------------------------------------------------
    def test_category_e_brand_impersonation_subdomain(self):
        """Category E: Embedding brand in subdomains of untrusted root domains must be flagged."""
        url = "https://onlinesbi.sbi.co.in.customer-portal-service.online/login"
        inds = inspect_url_deep(url)
        ind_ids = [i.id for i in inds]
        assert "IND_URL_SUBDOMAIN_DECEPTION" in ind_ids or "IND_URL_BRAND_IMPERSONATION" in ind_ids
        assert "IND_URL_DECEPTIVE_PATH" in ind_ids

        res = run_pipeline(f"Verify SBI Netbanking: {url}")
        assert res["response"].risk_score >= 65.0
        assert res["response"].verdict in ("HIGH_RISK", "KNOWN_MALICIOUS")

    # ------------------------------------------------------------------------
    # Category F: LPG / Gas Subsidy Phishing (Context vs. Destination Mismatch)
    # ------------------------------------------------------------------------
    def test_category_f_lpg_subsidy_context_mismatch(self):
        """Category F: Message claiming LPG subsidy linking to unofficial domain must trigger mismatch."""
        msg = "Your LPG subsidy of Rs 3,500 is pending. Claim immediately at https://random-claim-portal.xyz/subsidy"
        det = detect_threat_signals(msg)
        ind_ids = [i.id for i in det.indicators]
        assert "IND_BRAND_DOMAIN_MISMATCH" in ind_ids or "IND_SUSPICIOUS_URL" in ind_ids

        res = run_pipeline(msg)
        response = res["response"]
        assert response.risk_score >= 60.0
        assert response.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        assert response.verdict == "HIGH_RISK"
        assert any("subsidy" in ind.description.lower() or "lpg" in ind.name.lower() or "mismatch" in ind.name.lower() or "tld" in ind.name.lower() for ind in response.indicators)

    # ------------------------------------------------------------------------
    # Category G: Bank / KYC Phishing
    # ------------------------------------------------------------------------
    def test_category_g_bank_kyc_phishing(self):
        """Category G: Bank account suspension and KYC verification lures must trigger CRITICAL/HIGH."""
        msg = "HDFC Alert: Your NetBanking account will be blocked today. Update your PAN card now: https://hdfc-pan-kyc.top/netbanking"
        res = run_pipeline(msg)
        response = res["response"]
        assert response.risk_score >= 80.0
        assert response.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        assert response.category in (ScamCategory.BANKING_SCAM.value, ScamCategory.ACCOUNT_KYC_SCAM.value)
        assert any("kyc" in ind.description.lower() or "brand" in ind.name.lower() or "deceptive" in ind.name.lower() for ind in response.indicators)

    # ------------------------------------------------------------------------
    # Category H: UPI / Payment Phishing
    # ------------------------------------------------------------------------
    def test_category_h_upi_payment_phishing(self):
        """Category H: Cashback and reverse UPI payment lures must trigger high threat score."""
        msg = "Congratulations! You won Rs 2,500 PhonePe cashback reward. Click to credit: https://phonepe-reward-collect.club/pay"
        res = run_pipeline(msg)
        response = res["response"]
        assert response.risk_score >= 60.0
        assert response.category in (ScamCategory.PAYMENT_SCAM.value, ScamCategory.PHISHING.value, ScamCategory.LOTTERY_REWARD_SCAM.value)
        assert response.verdict in ("HIGH_RISK", "SUSPICIOUS")

    # ------------------------------------------------------------------------
    # Category I: Government & Statutory Impersonation
    # ------------------------------------------------------------------------
    def test_category_i_government_impersonation(self):
        """Category I: Government authority / legal threat lures must trigger government scam category."""
        msg = "Income Tax Department Notice: Outstanding tax penalty demand issued. Download notice: https://incometax-notice-portal.site/download.apk"
        res = run_pipeline(msg)
        response = res["response"]
        assert response.risk_score >= 80.0
        assert response.risk_level == RiskLevel.CRITICAL
        assert any(ind.id == "IND_MALICIOUS_APK" for ind in response.indicators)

    # ------------------------------------------------------------------------
    # Category J: Completely Unknown Arbitrary URLs (CORE RULE: Unknown != SAFE)
    # ------------------------------------------------------------------------
    def test_category_j_arbitrary_unknown_url_is_never_safe(self):
        """Category J: An arbitrary unknown URL absent from threat intelligence MUST NOT receive a SAFE verdict."""
        # Unseen arbitrary domain without explicit exploit payload
        unknown_url = "https://untracked-arbitrary-blog-xyz9876.net/article"
        inds = inspect_url_deep(unknown_url)
        assert any(ind.id == "IND_URL_UNVERIFIED_DESTINATION" for ind in inds)

        res = run_pipeline(f"Please check out: {unknown_url}")
        response = res["response"]

        # MUST NOT be 0.0 and MUST NOT be SAFE / BENIGN
        assert response.risk_score >= 25.0
        assert response.verdict == "UNKNOWN_UNVERIFIED"
        assert response.verdict != "BENIGN"
        assert any("unverified" in ind.name.lower() or "unverified" in ind.description.lower() for ind in response.indicators)
        assert any("verify" in action.lower() or "caution" in action.lower() for action in response.recommended_actions)
