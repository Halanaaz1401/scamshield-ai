"""Strict Forensic Consistency Audit & Repair Test Matrix (Tests A through G).

Verifies the core principle: NO EVIDENCE = NO CLAIM.
- Test A: Normal benign communication
- Test B: Isolated urgency ('within 15 minutes')
- Test C: Credential / OTP solicitation
- Test D: Urgent bank transfer request
- Test E: Shortened URL (bit.ly) with unverified destination
- Test F: Known malicious / threat-intelligence hit
- Test G: Message with no demanded action
"""

import pytest
from backend.src.handlers.analyze import run_pipeline
from backend.src.models.response import AnalysisResponse, RiskLevel


class TestForensicConsistencyMatrix:
    """Automated verification matrix for evidence-backed forensic reasoning."""

    def test_a_completely_normal_communication(self):
        """TEST A: Completely normal communication.

        Expected:
        - Low / no risk (score < 20)
        - Verdict BENIGN or LOW_RISK
        - No attack chain (attack_path is empty)
        - No fabricated malicious intent
        - Demanded action is 'No Direct Action Demanded'
        """
        msg = "Hi Sarah, please remember our team lunch tomorrow at 1 PM at the cafe downtown."
        result = run_pipeline(message=msg, source_type="message")
        resp: AnalysisResponse = result["response"]

        assert resp.risk_score < 20.0, f"Expected risk score < 20 for benign message, got {resp.risk_score}"
        assert resp.risk_level in (RiskLevel.LOW,), f"Expected LOW risk, got {resp.risk_level}"
        assert resp.verdict in ("BENIGN", "LOW_RISK"), f"Expected BENIGN or LOW_RISK verdict, got {resp.verdict}"
        assert len(resp.attack_path) == 0, f"Attack path must be empty for benign message, got {resp.attack_path}"
        assert resp.demanded_action == "No Direct Action Demanded"
        assert resp.pressure_level in ("NONE", "LOW")
        intent_lower = resp.attacker_intent.lower()
        assert "no malicious" in intent_lower or "benign" in intent_lower or "normal communication" in intent_lower

    def test_b_message_containing_within_15_minutes(self):
        """TEST B: Message containing 'within 15 minutes'.

        Expected:
        - Urgency indicator may be detected (IND_URGENT_LANGUAGE)
        - Do NOT automatically classify as fraud or psychological coercion
        - Risk score remains low (< 20.0) in absence of threats or solicitations
        - No attack chain stages fabricated
        - Demanded action remains 'No Direct Action Demanded'
        """
        msg = "Please review the updated meeting agenda slides within 15 minutes before our call."
        result = run_pipeline(message=msg, source_type="message")
        resp: AnalysisResponse = result["response"]

        assert resp.risk_score < 20.0, f"Isolated urgency must not inflate risk score above 20, got {resp.risk_score}"
        assert resp.risk_level == RiskLevel.LOW
        assert resp.verdict in ("BENIGN", "LOW_RISK")
        assert len(resp.attack_path) == 0, f"Attack chain must be empty without attack evidence, got {resp.attack_path}"
        assert resp.demanded_action == "No Direct Action Demanded"
        # Must not claim psychological coercion
        assert resp.manipulation_tactic != "URGENCY_COERCION"
        assert "coercion" not in resp.manipulation_tactic.lower()
        # Pressure level should reflect calibrated urgency, not panic
        assert resp.pressure_level in ("LOW", "NONE")

    def test_c_message_requesting_otp(self):
        """TEST C: Message requesting OTP.

        Expected:
        - Credential/security-secret action detected
        - Elevated risk score (>= 60.0)
        - Demanded action accurately identifies OTP submission
        - Attack chain grounded in explicit evidence
        - Every attack stage references a valid finding_id
        """
        msg = "Dear customer, your SBI card has been locked. Share your OTP immediately to unlock."
        result = run_pipeline(message=msg, source_type="message")
        resp: AnalysisResponse = result["response"]

        assert resp.risk_score >= 60.0, f"OTP solicitation must produce high risk, got {resp.risk_score}"
        assert resp.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        assert "otp" in resp.demanded_action.lower() or "credential" in resp.demanded_action.lower()
        assert len(resp.attack_path) > 0, "Expected kill chain stages for high-risk OTP attack"

        # Verify strict grounding: every stage has a finding_id
        for step in resp.attack_path:
            assert step.finding_id is not None, f"Stage '{step.stage}' missing finding_id grounding"
            assert any(ind.finding_id == step.finding_id or ind.id == step.finding_id for ind in resp.indicators), (
                f"Stage finding_id '{step.finding_id}' not found in indicators"
            )

    def test_d_message_requesting_bank_transfer_urgently(self):
        """TEST D: Message requesting bank transfer urgently.

        Expected:
        - Financial action + urgency detected
        - Elevated risk (>= 60.0)
        - Threat or urgency acknowledged in pressure level
        """
        msg = (
            "URGENT: Your electricity power supply will be disconnected tonight at 9:30 PM. "
            "Immediately pay Rs 1,450 to avoid disconnection."
        )
        result = run_pipeline(message=msg, source_type="message")
        resp: AnalysisResponse = result["response"]

        assert resp.risk_score >= 60.0, f"Expected elevated risk >= 60, got {resp.risk_score}"
        assert resp.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        assert resp.pressure_level in ("HIGH", "CRITICAL")
        assert len(resp.attack_path) > 0
        assert any("payment" in step.stage.lower() or "action" in step.stage.lower() or "disconnection" in step.description.lower() for step in resp.attack_path)

    def test_e_shortened_bitly_url_with_unknown_destination(self):
        """TEST E: Shortened bit.ly URL with unknown destination.

        Expected:
        - Shortened URL indicator present (IND_URL_SHORTENER)
        - Verdict calibrated as UNKNOWN_UNVERIFIED (never LINK APPEARS SAFE or KNOWN_MALICIOUS)
        - Risk score in 20–39 range (caution / unverified)
        - Explanation distinguishes destination obfuscation from verified malware
        """
        msg = "View your documents here: https://bit.ly/3xY7z9"
        result = run_pipeline(message=msg, source_type="url")
        resp: AnalysisResponse = result["response"]

        assert any(ind.id == "IND_URL_SHORTENER" for ind in resp.indicators), "IND_URL_SHORTENER must be flagged"
        assert resp.verdict == "UNKNOWN_UNVERIFIED", f"Expected UNKNOWN_UNVERIFIED verdict, got {resp.verdict}"
        assert 20.0 <= resp.risk_score <= 39.0, f"Expected score in 20-39 range for unverified shortener, got {resp.risk_score}"
        assert resp.verdict != "KNOWN_MALICIOUS"
        assert resp.verdict != "SAFE"
        # Reasoning/indicator should indicate destination obfuscation
        shortener_ind = next(ind for ind in resp.indicators if ind.id == "IND_URL_SHORTENER")
        assert shortener_ind.type == "destination_obfuscation"

    def test_f_known_malicious_phishing_url(self):
        """TEST F: Known malicious / phishing URL with deterministic evidence.

        Expected:
        - High-confidence security finding (score >= 80)
        - Verdict KNOWN_MALICIOUS or HIGH_RISK
        - High confidence
        """
        msg = "Verify your account at http://login-sbi-security-update.fakebank.top/auth/verify"
        result = run_pipeline(message=msg, source_type="url")
        resp: AnalysisResponse = result["response"]

        assert resp.risk_score >= 80.0, f"Expected critical/high risk >= 80, got {resp.risk_score}"
        assert resp.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        assert resp.verdict in ("KNOWN_MALICIOUS", "HIGH_RISK", "SUSPICIOUS")
        assert resp.confidence == "HIGH"
        assert len(resp.indicators) > 0

    def test_g_message_with_no_demanded_action(self):
        """TEST G: Message with no demanded action.

        Expected:
        - demanded_action = 'No Direct Action Demanded'
        - NO 'Unauthorized Action' kill-chain stage unless explicit evidence proves it
        """
        msg = "Your monthly banking statement is available for download at your leisure."
        result = run_pipeline(message=msg, source_type="message")
        resp: AnalysisResponse = result["response"]

        assert resp.demanded_action == "No Direct Action Demanded"
        for step in resp.attack_path:
            assert step.stage != "Unauthorized Action", "Cannot have Unauthorized Action stage when no action is demanded"
            assert "unauthorized action" not in step.stage.lower()
