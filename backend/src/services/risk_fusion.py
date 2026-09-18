"""Multi-layer cybersecurity risk score fusion service for ScamShield AI.

Synthesizes:
1. Phase 3 Deterministic Technical Signals (Ground-truth evidence)
2. Phase 4 Amazon Bedrock Contextual Semantic Analysis

into an authoritative, calibrated AnalysisResponse strictly bounded to [0.0, 100.0].
"""

from typing import Any, Dict, List, Optional

from backend.src.detection.engine import DeterministicAnalysis
from backend.src.models.response import (
    AnalysisResponse,
    AttackStep,
    Indicator,
    RiskLevel,
    ScamCategory,
    Severity,
)
from backend.src.services.bedrock_service import BedrockAnalysisResult

# Contextual score translation for Bedrock categorical risk ratings
BEDROCK_RISK_SCORES = {
    RiskLevel.CRITICAL: 90.0,
    RiskLevel.HIGH: 75.0,
    RiskLevel.MEDIUM: 45.0,
    RiskLevel.LOW: 10.0,
}

# Critical indicators that enforce a hard risk score floor
CRITICAL_RULE_IDS = {
    "IND_OTP_SOLICIT",
    "IND_REVERSE_UPI",
    "IND_CREDENTIAL_SOLICIT",
    "IND_THREAT_LEGAL",
}


def compute_fused_risk_score(
    deterministic: DeterministicAnalysis,
    bedrock: BedrockAnalysisResult,
    threat_intel: Optional[Any] = None,
    ai_intent: Optional[Any] = None,
) -> float:
    """Compute the final calibrated risk score (0.0 - 100.0) combining rules, threat intel, and AI.

    Scoring Logic:
    1. Threat Intel Match: If confirmed malicious by external threat feeds, score is 100.0.
    2. Brand Domain Mismatch: If brand context mismatch detected, floor is 75.0.
    3. Unverified Destination: If arbitrary unknown URL without verified reputation, floor is 25.0.
    4. Offline AI Fallback: Uses deterministic score with threat intel/domain floors.
    5. Benign Case: If no malicious cues and authoritative whitelisted or safe content, score is <= 10.0.
    6. Code-Controlled Social-Engineering Calibration: When URL is clean or static rules find few cues,
       but AI Intent Reasoner identifies sensitive action solicitation (OTP/credentials/payment) + high urgency/coercion,
       code raises a social-engineering floor (65.0) without falsely claiming the URL itself is malicious.
    7. Corroborated Evidence: Blends deterministic evidence + AI contextual weight.
    """
    # 0. Check confirmed threat intelligence match
    has_threat_intel_match = any(ind.id == "IND_THREAT_INTEL_MALICIOUS" for ind in deterministic.indicators) or (
        threat_intel and getattr(threat_intel, "is_known_malicious", False)
    )
    if has_threat_intel_match:
        return 100.0

    has_brand_mismatch = any(ind.id == "IND_BRAND_DOMAIN_MISMATCH" for ind in deterministic.indicators)
    has_unverified_url = any(
        ind.id in ("IND_URL_UNVERIFIED_DESTINATION", "IND_URL_SHORTENER")
        for ind in deterministic.indicators
    )

    det_score = deterministic.deterministic_score
    if has_brand_mismatch:
        det_score = max(det_score, 75.0)
    elif has_unverified_url:
        det_score = max(det_score, 25.0)

    # 1. Safe Fallback: When AI is offline, rely purely on deterministic signals
    if not bedrock.ai_available and (ai_intent is None or not getattr(ai_intent, "ai_available", False)):
        # If AI intent has deterministic fallback with high urgency & sensitive action, apply minimal floor
        if ai_intent:
            req_act = getattr(ai_intent, "requested_action", "")
            urg = getattr(ai_intent, "urgency_level", "")
            if urg == "HIGH" and req_act in ("PROVIDE_OTP", "SHARE_CREDENTIALS", "MAKE_PAYMENT"):
                det_score = max(det_score, 60.0)
        return min(100.0, max(0.0, round(det_score, 1)))

    ai_base_score = BEDROCK_RISK_SCORES.get(bedrock.risk_assessment, 45.0)

    # 2. Benign Alignment: No deterministic cues and AI rates LOW/BENIGN (only when not unverified URL)
    if deterministic.is_benign and bedrock.risk_assessment == RiskLevel.LOW and not has_unverified_url:
        if ai_intent and getattr(ai_intent, "scam_category", "") not in ("BENIGN", ""):
            pass  # Don't short-circuit to 10 if AI intent detected specific scam
        else:
            return min(10.0, round(ai_base_score, 1))

    # 3. AI-Only Anomaly: Rules found nothing, but AI detected social engineering
    if deterministic.is_benign:
        if bedrock.risk_assessment in (RiskLevel.CRITICAL, RiskLevel.HIGH):
            raw_fused = min(75.0, round(ai_base_score * 0.70, 1))
        elif bedrock.risk_assessment == RiskLevel.MEDIUM:
            raw_fused = 35.0
        else:
            raw_fused = 10.0
    else:
        # 4. Standard Blended Fusion
        raw_fused = (0.55 * det_score) + (0.45 * ai_base_score)

    # 5. Code-Controlled AI Intent Evaluation
    if ai_intent:
        req_action = getattr(ai_intent, "requested_action", "")
        urgency = getattr(ai_intent, "urgency_level", "")
        intent_cat = getattr(ai_intent, "scam_category", "")
        tactics = getattr(ai_intent, "manipulation_tactics", [])

        is_sensitive_action = req_action in (
            "PROVIDE_OTP", "SHARE_CREDENTIALS", "VERIFY_IDENTITY", "MAKE_PAYMENT", "INSTALL_APP"
        )
        is_high_coercion = urgency == "HIGH" or len(tactics) >= 2

        if is_sensitive_action and is_high_coercion and intent_cat != "BENIGN":
            # Code enforces floor of 65.0 for clear social engineering solicitation
            raw_fused = max(raw_fused, 65.0)
        elif is_sensitive_action or is_high_coercion:
            raw_fused = max(raw_fused, 40.0)

    # 6. Critical Evidence Hard Floor: AI cannot downgrade explicit credential/OTP demands or brand mismatch
    has_critical_signal = any(
        ind.id in CRITICAL_RULE_IDS or ind.severity == Severity.CRITICAL
        for ind in deterministic.indicators
    )
    if has_critical_signal:
        raw_fused = max(raw_fused, 80.0)
    elif has_brand_mismatch:
        raw_fused = max(raw_fused, 75.0)
    elif det_score >= 60.0:
        raw_fused = max(raw_fused, 50.0)
    elif has_unverified_url:
        raw_fused = max(raw_fused, 25.0)

    # 7. Multi-Signal Corroboration Bonus
    if deterministic.signal_count >= 3 and bedrock.risk_assessment in (RiskLevel.HIGH, RiskLevel.CRITICAL):
        raw_fused = max(raw_fused, 85.0)

    return min(100.0, max(0.0, round(raw_fused, 1)))


def calibrate_risk_level(score: float) -> RiskLevel:
    """Map final calibrated score to authoritative categorical RiskLevel."""
    if score >= 80.0:
        return RiskLevel.CRITICAL
    elif score >= 60.0:
        return RiskLevel.HIGH
    elif score >= 30.0:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def reconcile_category(
    deterministic: DeterministicAnalysis,
    bedrock: BedrockAnalysisResult,
    final_score: float,
    ai_intent: Optional[Any] = None,
) -> ScamCategory:
    """Reconcile category between deterministic rules, Bedrock, and AI Intent Reasoner."""
    # If final score is clearly benign, map to BENIGN
    if final_score < 30.0 and deterministic.is_benign:
        return ScamCategory.BENIGN

    # If deterministic found strong category-specific indicators, prefer deterministic
    det_cat = deterministic.primary_category
    if det_cat in (
        ScamCategory.PAYMENT_SCAM,
        ScamCategory.ACCOUNT_KYC_SCAM,
        ScamCategory.BANKING_SCAM,
        ScamCategory.CREDENTIAL_THEFT,
        ScamCategory.GOVERNMENT_IMPERSONATION,
        ScamCategory.ELECTRICITY_SCAM,
        ScamCategory.COURIER_SCAM,
        ScamCategory.SIM_DEACTIVATION_SCAM,
        ScamCategory.CUSTOMER_SUPPORT_SCAM,
        ScamCategory.JOB_SCAM,
        ScamCategory.INVESTMENT_SCAM,
        ScamCategory.LOTTERY_REWARD_SCAM,
    ):
        return det_cat

    # Check AI Intent Reasoner category
    if ai_intent:
        intent_cat_str = getattr(ai_intent, "scam_category", "")
        if intent_cat_str and intent_cat_str not in ("OTHER_SUSPICIOUS", "BENIGN"):
            try:
                return ScamCategory(intent_cat_str)
            except ValueError:
                pass

    # If deterministic is generic, adopt Bedrock's specific category
    if bedrock.category != ScamCategory.OTHER_SUSPICIOUS and bedrock.category != ScamCategory.BENIGN:
        return bedrock.category

    # Fallback to deterministic primary category
    return det_cat if det_cat != ScamCategory.BENIGN else ScamCategory.OTHER_SUSPICIOUS


def generate_grounded_attack_chain(
    deterministic: DeterministicAnalysis,
    bedrock: BedrockAnalysisResult,
    category: ScamCategory,
    final_score: float,
    demanded_action: str,
    ai_intent: Optional[Any] = None,
) -> List[AttackStep]:
    """Generate evidence-grounded attack chain (Scam DNA).

    CORE PRINCIPLE: NO EVIDENCE = NO CLAIM.
    Every kill-chain stage must reference at least one supporting finding.
    If there is no supporting finding: DO NOT RENDER THE STAGE.

    Strict Gates:
    1. If final_score < 20.0 or category is BENIGN: return [] (no attack progression).
    2. Stages are only included if backed by an actual finding (finding_id).
    3. If demanded_action == "No Direct Action Demanded":
       stage "Unauthorized Action" MUST NOT be included unless another explicit finding proves it.
    """
    if final_score < 20.0 or category == ScamCategory.BENIGN:
        return []

    indicators = deterministic.indicators
    if not indicators and (not ai_intent or getattr(ai_intent, "scam_category", "") == "BENIGN"):
        return []

    steps: List[AttackStep] = []
    ind_map = {ind.id: ind for ind in indicators}

    # 1. Inbound Contact / Entry Vector
    inbound_ind = (
        ind_map.get("IND_URL_SHORTENER")
        or ind_map.get("IND_SUSPICIOUS_URL")
        or ind_map.get("IND_URL_UNVERIFIED_DESTINATION")
        or ind_map.get("IND_URL_SUSPICIOUS_TLD")
        or ind_map.get("IND_URL_BRAND_IMPERSONATION")
        or ind_map.get("IND_ELECTRICITY_DISCONNECT")
        or ind_map.get("IND_COURIER_PARCEL")
        or ind_map.get("IND_KYC_SUSPENSION")
        or (indicators[0] if indicators else None)
    )

    if inbound_ind:
        if inbound_ind.id == "IND_URL_SHORTENER":
            desc = "Unsolicited communication directs recipient to a shortened link concealing final target."
        elif "URL" in inbound_ind.id or inbound_ind.id == "IND_SUSPICIOUS_URL":
            desc = "Message contains an unverified external link directing recipient away from official apps."
        elif inbound_ind.id == "IND_ELECTRICITY_DISCONNECT":
            desc = "Pretext notice delivered claiming imminent electricity disconnection from power utility office."
        elif inbound_ind.id == "IND_COURIER_PARCEL":
            desc = "Unsolicited notice claiming an intercepted or detained courier parcel."
        else:
            desc = f"Unsolicited communication delivered to recipient: {inbound_ind.name}."

        steps.append(AttackStep(
            step=len(steps) + 1,
            stage="Inbound Contact",
            description=desc,
            finding_id=inbound_ind.finding_id or inbound_ind.id,
            source=inbound_ind.source or "deterministic_heuristic",
            evidence=inbound_ind.evidence,
        ))

    # 2. Pretexting & Impersonation
    impersonation_ind = (
        ind_map.get("IND_BRAND_DOMAIN_MISMATCH")
        or ind_map.get("IND_IMPERSONATION_BANK")
        or ind_map.get("IND_IMPERSONATION_GOVT")
        or ind_map.get("IND_URL_BRAND_IMPERSONATION")
        or ind_map.get("IND_URL_SUBDOMAIN_DECEPTION")
    )
    if impersonation_ind:
        steps.append(AttackStep(
            step=len(steps) + 1,
            stage="Pretexting & Impersonation",
            description=f"Masquerades as recognized entity or institution: {impersonation_ind.description}",
            finding_id=impersonation_ind.finding_id or impersonation_ind.id,
            source=impersonation_ind.source or "deterministic_heuristic",
            evidence=impersonation_ind.evidence,
        ))

    # 3. Psychological Trigger
    # ONLY allowed when evidence supports urgency, fear, authority pressure, emotional manipulation
    trigger_ind = (
        ind_map.get("IND_THREAT_LEGAL")
        or ind_map.get("IND_THREAT_CONSEQUENCE")
        or ind_map.get("IND_URGENCY_TACTIC")
        or ind_map.get("IND_KYC_SUSPENSION")
        or ind_map.get("IND_LOTTERY_REWARD")
    )
    if trigger_ind:
        if trigger_ind.id == "IND_THREAT_LEGAL":
            stg_name = "Legal Intimidation"
            desc = "Intimidates recipient with threats of police action, arrest, or severe penalties."
        elif trigger_ind.id in ("IND_THREAT_CONSEQUENCE", "IND_ELECTRICITY_DISCONNECT"):
            stg_name = "Threat of Service Deactivation"
            desc = "Creates panic by threatening immediate suspension of essential banking, electricity, or telecom services."
        elif trigger_ind.id == "IND_LOTTERY_REWARD":
            stg_name = "Reward Bait"
            desc = "Uses unrealistic prize or cashback lure to encourage immediate compliance."
        else:
            stg_name = "Psychological Trigger"
            desc = trigger_ind.description

        steps.append(AttackStep(
            step=len(steps) + 1,
            stage=stg_name,
            description=desc,
            finding_id=trigger_ind.finding_id or trigger_ind.id,
            source=trigger_ind.source or "deterministic_heuristic",
            evidence=trigger_ind.evidence,
        ))

    # 4. Exploitation / Delivery Vector
    vector_ind = (
        ind_map.get("IND_THREAT_INTEL_MALICIOUS")
        or ind_map.get("IND_MALICIOUS_APK")
        or ind_map.get("IND_URL_DECEPTIVE_PATH")
        or ind_map.get("IND_URL_SUSPICIOUS_TLD")
        or ind_map.get("IND_URL_IP_HOST")
        or ind_map.get("IND_URL_HOMOGLYPH")
        or ind_map.get("IND_URL_UNSAFE_SCHEME")
        or ind_map.get("IND_URL_UNVERIFIED_DESTINATION")
    )
    if vector_ind:
        if vector_ind.id == "IND_THREAT_INTEL_MALICIOUS":
            vec_desc = "Confirmed active phishing or malware distribution infrastructure."
        elif vector_ind.id == "IND_MALICIOUS_APK":
            vec_desc = "Distribution of untrusted Android package (.apk) file."
        elif "URL" in vector_ind.id:
            vec_desc = f"Directs user to suspicious web infrastructure: {vector_ind.name}."
        else:
            vec_desc = vector_ind.description

        steps.append(AttackStep(
            step=len(steps) + 1,
            stage="Exploitation Vector",
            description=vec_desc,
            finding_id=vector_ind.finding_id or vector_ind.id,
            source=vector_ind.source or "deterministic_heuristic",
            evidence=vector_ind.evidence,
        ))

    # 5. Unauthorized Action
    # STRICT EVIDENCE GATE:
    # Allowed ONLY when the message explicitly or semantically requests an action capable of causing compromise.
    # If demanded_action == "No Direct Action Demanded", MUST NOT contain "Unauthorized Action".
    action_ind = (
        ind_map.get("IND_OTP_SOLICIT")
        or ind_map.get("IND_CREDENTIAL_SOLICIT")
        or ind_map.get("IND_REVERSE_UPI")
        or ind_map.get("IND_PAYMENT_COLLECT")
        or ind_map.get("IND_MALICIOUS_APK")
    )
    if demanded_action != "No Direct Action Demanded" and action_ind:
        if action_ind.id == "IND_OTP_SOLICIT":
            act_desc = "Victim prompted to share SMS authentication code / 2FA OTP."
        elif action_ind.id == "IND_CREDENTIAL_SOLICIT":
            act_desc = "Victim prompted to enter banking password, PIN, or card security details."
        elif action_ind.id == "IND_REVERSE_UPI":
            act_desc = "Victim prompted to approve collect request or enter UPI PIN under false pretense."
        elif action_ind.id == "IND_PAYMENT_COLLECT":
            act_desc = "Victim prompted to transfer advance processing or clearance fee."
        elif action_ind.id == "IND_MALICIOUS_APK":
            act_desc = "Victim prompted to install external APK with device-level permissions."
        else:
            act_desc = f"Victim targeted for unauthorized action: {demanded_action}."

        steps.append(AttackStep(
            step=len(steps) + 1,
            stage="Unauthorized Action",
            description=act_desc,
            finding_id=action_ind.finding_id or action_ind.id,
            source=action_ind.source or "deterministic_heuristic",
            evidence=action_ind.evidence,
        ))

    # 6. Compromise / Impact
    # Grounded ONLY if Unauthorized Action was evidenced OR verified malicious payload
    if any(s.stage == "Unauthorized Action" for s in steps) or ind_map.get("IND_THREAT_INTEL_MALICIOUS"):
        comp_finding = action_ind or ind_map.get("IND_THREAT_INTEL_MALICIOUS")
        if action_ind and action_ind.id in ("IND_OTP_SOLICIT", "IND_CREDENTIAL_SOLICIT"):
            comp_desc = "Harvested credentials risk unauthorized NetBanking access and fraudulent transfers."
        elif action_ind and action_ind.id in ("IND_REVERSE_UPI", "IND_PAYMENT_COLLECT"):
            comp_desc = "Unauthorized fund debit executed directly from victim's bank account."
        elif action_ind and action_ind.id == "IND_MALICIOUS_APK":
            comp_desc = "Malicious app intercepts SMS OTPs, enabling device takeover and financial fraud."
        else:
            comp_desc = "Potential compromise of user credentials, sensitive data, or financial assets."

        steps.append(AttackStep(
            step=len(steps) + 1,
            stage="Asset or Credential Compromise",
            description=comp_desc,
            finding_id=comp_finding.finding_id if comp_finding else None,
            source=comp_finding.source if comp_finding else "threat_intelligence",
            evidence=comp_finding.evidence if comp_finding else None,
        ))

    return steps


# Alias for backward compatibility
synthesize_attack_path = generate_grounded_attack_chain


def derive_canonical_forensic_fields(
    deterministic: DeterministicAnalysis,
    final_score: float,
    verdict: str,
    category: ScamCategory,
    ai_intent: Optional[Any] = None,
) -> Dict[str, Any]:
    """Derive canonical, evidence-backed security fields for all UI sections."""
    indicators = deterministic.indicators
    ind_ids = {ind.id for ind in indicators}

    # 1. Demanded Action derivation
    if "IND_OTP_SOLICIT" in ind_ids:
        demanded_action = "Submit OTP / Verification Code"
    elif "IND_CREDENTIAL_SOLICIT" in ind_ids:
        demanded_action = "Disclose Passwords or Banking PIN"
    elif "IND_REVERSE_UPI" in ind_ids:
        demanded_action = "Approve Collect Request / Enter UPI PIN"
    elif "IND_PAYMENT_COLLECT" in ind_ids:
        demanded_action = "Transfer Advance Fee or Payment"
    elif "IND_MALICIOUS_APK" in ind_ids:
        demanded_action = "Download & Install Untrusted App (.apk)"
    elif ai_intent and getattr(ai_intent, "requested_action", "") not in ("NO_ACTION", ""):
        req = getattr(ai_intent, "requested_action", "")
        action_map = {
            "CLICK_LINK": "Click Web Link",
            "CALL_NUMBER": "Call Phone Number",
            "PROVIDE_OTP": "Submit OTP / Verification Code",
            "MAKE_PAYMENT": "Transfer Funds / Enter UPI PIN",
            "INSTALL_APP": "Download & Install Unverified App (.apk)",
            "SHARE_CREDENTIALS": "Enter NetBanking Passwords or Card Details",
            "VERIFY_IDENTITY": "Submit Personal Identity / KYC Details",
        }
        demanded_action = action_map.get(req, "No Direct Action Demanded")
    elif any("URL" in i for i in ind_ids) or "IND_SUSPICIOUS_URL" in ind_ids:
        demanded_action = "Click Web Link"
    else:
        demanded_action = "No Direct Action Demanded"

    # If benign or score < 20 and no explicit solicitation, enforce "No Direct Action Demanded"
    if (final_score < 20.0 or category == ScamCategory.BENIGN) and not any(
        i in ind_ids for i in ("IND_OTP_SOLICIT", "IND_CREDENTIAL_SOLICIT", "IND_REVERSE_UPI", "IND_PAYMENT_COLLECT")
    ):
        demanded_action = "No Direct Action Demanded"

    # 2. Pressure Level
    if "IND_THREAT_LEGAL" in ind_ids or "IND_THREAT_CONSEQUENCE" in ind_ids or ("IND_URGENCY_TACTIC" in ind_ids and final_score >= 60.0):
        pressure_level = "HIGH"
    elif "IND_URGENCY_TACTIC" in ind_ids or "IND_KYC_SUSPENSION" in ind_ids:
        pressure_level = "MEDIUM"
    elif "IND_URGENT_LANGUAGE" in ind_ids:
        pressure_level = "LOW"
    elif ai_intent and getattr(ai_intent, "urgency_level", "") in ("HIGH", "MEDIUM", "LOW"):
        pressure_level = getattr(ai_intent, "urgency_level", "NONE")
    else:
        pressure_level = "NONE"

    # 3. Manipulation Tactics
    tactics: List[str] = []
    if "IND_THREAT_LEGAL" in ind_ids:
        tactics.append("FEAR_OF_POLICE_INVOLVEMENT")
    if "IND_THREAT_CONSEQUENCE" in ind_ids:
        tactics.append("FEAR_OF_SERVICE_DISCONNECTION")
    if "IND_IMPERSONATION_BANK" in ind_ids or "IND_IMPERSONATION_GOVT" in ind_ids or "IND_BRAND_DOMAIN_MISMATCH" in ind_ids:
        tactics.append("AUTHORITY_IMPERSONATION")
    if "IND_REVERSE_UPI" in ind_ids:
        tactics.append("REVERSE_PAYMENT_TRICK")
    if "IND_LOTTERY_REWARD" in ind_ids:
        tactics.append("GREED_LURE")
    if "IND_URGENCY_TACTIC" in ind_ids:
        tactics.append("URGENCY_COERCION")
    if "IND_URGENT_LANGUAGE" in ind_ids:
        tactics.append("TIME_SENSITIVITY")
    if "IND_URL_SHORTENER" in ind_ids:
        tactics.append("DESTINATION_OBFUSCATION")

    if ai_intent and getattr(ai_intent, "manipulation_tactics", []):
        for t in getattr(ai_intent, "manipulation_tactics", []):
            if t not in tactics:
                tactics.append(t)

    # Primary manipulation tactic label
    if tactics:
        tactic_labels = {
            "FEAR_OF_POLICE_INVOLVEMENT": "Threat of Police or CBI Arrest",
            "FEAR_OF_SERVICE_DISCONNECTION": "Threat of Service Deactivation",
            "AUTHORITY_IMPERSONATION": "Institutional Impersonation",
            "REVERSE_PAYMENT_TRICK": "Reverse Payment Deception",
            "GREED_LURE": "Cashback / Prize Lure",
            "URGENCY_COERCION": "Manufactured Time Pressure & Urgency",
            "TIME_SENSITIVITY": "Urgent Language Detected",
            "DESTINATION_OBFUSCATION": "Destination Obfuscation",
        }
        manipulation_tactic = tactic_labels.get(tactics[0], tactics[0].replace("_", " ").title())
    else:
        manipulation_tactic = "None"

    # 4. Potential Impact
    impacts: List[str] = []
    if "IND_OTP_SOLICIT" in ind_ids or "IND_CREDENTIAL_SOLICIT" in ind_ids:
        impacts.append("Unauthorized netbanking access and account takeover.")
        impacts.append("Unauthorized electronic fund transfers.")
    elif "IND_REVERSE_UPI" in ind_ids or "IND_PAYMENT_COLLECT" in ind_ids:
        impacts.append("Immediate, irreversible financial debit from your bank account.")
    elif "IND_MALICIOUS_APK" in ind_ids:
        impacts.append("Device compromise and background interception of SMS/OTPs.")
    elif "IND_THREAT_INTEL_MALICIOUS" in ind_ids:
        impacts.append("Exposure to confirmed phishing or malware infrastructure.")
    elif "IND_URL_SHORTENER" in ind_ids or "IND_URL_UNVERIFIED_DESTINATION" in ind_ids:
        impacts.append("Redirection to unverified destination with unknown security standing.")
    elif final_score < 20.0 or category == ScamCategory.BENIGN:
        impacts.append("No immediate security risk or compromise identified from this communication.")
    else:
        impacts.append("Potential exposure to unsolicited or unverified communication.")

    # 5. Do Actions and Do Not Actions
    is_threat = final_score >= 40.0
    if is_threat:
        do_actions = [
            "Verify any urgent claims directly with the organization using verified contact details.",
            "Report suspicious messages to the National Cybercrime Portal (cybercrime.gov.in or 1930).",
        ]
        do_not_actions = [
            "Do NOT click unverified links or open shortened URLs in unsolicited messages.",
            "Do NOT share OTP, UPI PIN, ATM PIN, or NetBanking passwords with anyone.",
            "Do NOT transfer funds or pay advance clearance fees to unverified accounts.",
        ]
    elif verdict == "UNKNOWN_UNVERIFIED" or "IND_URL_SHORTENER" in ind_ids or "IND_URL_UNVERIFIED_DESTINATION" in ind_ids:
        do_actions = [
            "Independently verify the official website address using a trusted search engine before opening.",
            "Confirm sender identity through official channels.",
        ]
        do_not_actions = [
            "Do NOT enter passwords or confidential banking credentials on unverified websites.",
        ]
    else:
        do_actions = [
            "Follow standard digital awareness practices.",
            "Verify unexpected requests independently if sender identity is unknown.",
        ]
        do_not_actions = []

    return {
        "demanded_action": demanded_action,
        "pressure_level": pressure_level,
        "manipulation_tactic": manipulation_tactic,
        "manipulation_tactics": tactics,
        "potential_impact": impacts,
        "do_actions": do_actions,
        "do_not_actions": do_not_actions,
    }


def synthesize_false_positive_checks(
    deterministic: DeterministicAnalysis,
    bedrock: BedrockAnalysisResult,
    final_score: float,
) -> Optional[List[str]]:
    """Synthesize verifiable safety checklist for benign and low-risk messages."""
    if final_score < 30.0 or deterministic.is_benign:
        checks = [
            "No urgent threat of legal action, account suspension, or financial loss.",
            "No solicitation of confidential credentials (UPI PIN, passwords, OTP, card details).",
            "No suspicious look-alike URLs, numeric IP hosts, or deceptive shorteners.",
            "No instructions to install unverified APKs, AnyDesk, or screen-sharing software.",
            "Language follows standard professional or personal communication patterns without coercive pressure.",
        ]
        return checks
    return None


def compute_confidence(
    deterministic: DeterministicAnalysis,
    bedrock: BedrockAnalysisResult,
    final_score: float,
) -> str:
    """Compute confidence rating (HIGH, MEDIUM, LOW) based on evidence corroboration."""
    # When technical indicators are present with high score, confidence is HIGH
    if final_score >= 60.0 and deterministic.signal_count >= 2:
        return "HIGH"

    # When both deterministic and AI agree on benign classification
    if deterministic.is_benign and bedrock.risk_assessment == RiskLevel.LOW:
        return "HIGH"

    # When AI is offline, confidence is MEDIUM unless deterministic proof is overwhelming
    if not bedrock.ai_available:
        return "HIGH" if deterministic.signal_count >= 3 else "MEDIUM"

    # If deterministic and AI differ significantly (e.g. 0 signals vs CRITICAL)
    if deterministic.is_benign and bedrock.risk_assessment in (RiskLevel.CRITICAL, RiskLevel.HIGH):
        return "MEDIUM"

    return "HIGH" if final_score >= 40.0 else "MEDIUM"


def synthesize_attacker_intent(
    deterministic: DeterministicAnalysis,
    bedrock: BedrockAnalysisResult,
    category: ScamCategory,
) -> str:
    """Synthesize contextual attacker objective derived from analysis signals."""
    if bedrock.ai_available and bedrock.attacker_intent:
        return bedrock.attacker_intent

    # Category-specific grounded attacker intent
    if category == ScamCategory.ELECTRICITY_SCAM:
        return "Coerce victim into paying fraudulent utility arrears via unverified payment gateways or calling private mobile numbers under imminent threat of power disruption."
    elif category == ScamCategory.COURIER_SCAM:
        return "Intimidate victim with fictitious customs contraband and fake police/CBI arrest warrants to extort 'clearance' or 'verification' deposits."
    elif category == ScamCategory.SIM_DEACTIVATION_SCAM:
        return "Trick victim into revealing Aadhaar details, installing remote-access management tools (AnyDesk), or submitting credentials for SIM swap fraud."
    elif category == ScamCategory.CUSTOMER_SUPPORT_SCAM:
        return "Lure victim seeking refund or service assistance to call a fraudulent mobile helpline, guiding them to enter UPI PIN or install screen-sharing software."
    elif category == ScamCategory.PAYMENT_SCAM:
        return "Trick recipient into approving reverse UPI collect requests or entering UPI PIN under the fraudulent impression of receiving incoming money."
    elif category in (ScamCategory.BANKING_SCAM, ScamCategory.ACCOUNT_KYC_SCAM, ScamCategory.CREDENTIAL_THEFT):
        return "Harvest NetBanking usernames, passwords, card details, and 2FA OTPs through spoofed look-alike portals to conduct unauthorized electronic fund transfers."
    elif category == ScamCategory.JOB_SCAM:
        return "Entice victim with high-return simple tasks, establishing compliance with small payouts before extorting large 'VIP task' deposits."
    elif category == ScamCategory.INVESTMENT_SCAM:
        return "Lure victim into depositing capital into fictitious high-yield trading schemes or crypto doubling pools with zero withdrawal liquidity."
    elif category == ScamCategory.LOTTERY_REWARD_SCAM:
        return "Extort advance processing fees, GST, or delivery charges under the promise of a non-existent lottery win or luxury prize."
    elif category == ScamCategory.GOVERNMENT_IMPERSONATION:
        return "Exploit legal intimidation and authority pretexting (Police, Income Tax, CBI) to coerce immediate settlement payments."
    elif category == ScamCategory.PHISHING:
        return "Deceive victim into submitting confidential authentication tokens, credentials, or personal identity details on an unverified destination."
    elif category == ScamCategory.BENIGN:
        return "No malicious exploitation intent detected. Message appears consistent with normal personal or administrative communication."

    # Brand and threat intel intent specifics
    if any(ind.id == "IND_THREAT_INTEL_MALICIOUS" for ind in deterministic.indicators):
        return "Deliver an active exploitation payload, deploy malware, or execute credential harvesting on a confirmed malicious domain."
    if any(ind.id == "IND_BRAND_DOMAIN_MISMATCH" for ind in deterministic.indicators):
        return "Impersonate a legitimate institution or government scheme to lure recipient away from official channels and capture sensitive credentials or funds."
    if any(ind.id == "IND_URL_UNVERIFIED_DESTINATION" for ind in deterministic.indicators):
        return "Direct recipient to an unverified external destination. While no specific attack payload was detected, the destination has no established institutional trust."

    # Indicator-driven fallback
    for ind in deterministic.indicators:
        if ind.attacker_objective:
            return ind.attacker_objective

    return "Manipulate recipient into hasty compliance through psychological urgency or unverified claims."


def synthesize_recommended_actions(
    deterministic: DeterministicAnalysis,
    bedrock: BedrockAnalysisResult,
    final_level: RiskLevel,
) -> List[str]:
    """Compile prioritized, de-duplicated defensive action plan."""
    if final_level == RiskLevel.LOW or deterministic.is_benign:
        return [
            "Still verify unexpected requests independently through trusted channels.",
            "Never share passwords, banking PINs, or OTPs even if sender appears friendly.",
        ]

    actions = list(bedrock.recommended_actions) if bedrock.recommended_actions else []

    # Inject baseline safety directives based on indicators
    for ind in deterministic.indicators:
        if "THREAT_INTEL" in ind.id:
            actions.insert(0, "BLOCKED: Do not open this link under any circumstances. It is a verified malicious threat destination.")
        elif "BRAND_DOMAIN_MISMATCH" in ind.id:
            actions.insert(0, "Do NOT open this link. Access the service only via the organization's official verified portal or mobile app.")
            actions.append("Remember: Genuine banks and government bodies never use unofficial or high-risk domain extensions.")
        elif "UNVERIFIED_DESTINATION" in ind.id:
            actions.insert(0, "Exercise caution: This website destination has no established institutional verification.")
            actions.append("Independently confirm the official website address using a trusted search engine before entering any details.")
        elif "OTP" in ind.id:
            actions.append("Never share your OTP or verification code with anyone.")
        elif "UPI" in ind.id or "PAYMENT" in ind.id:
            actions.append("Never enter your UPI PIN to receive funds. Entering PIN always debits your account.")
        elif "CREDENTIAL" in ind.id:
            actions.append("Do not enter banking passwords or card numbers on unverified websites.")
        elif "URL" in ind.id:
            actions.append("Do not click links in unsolicited messages. Access portals only via verified bookmarks.")
        elif "ELECTRICITY" in ind.id:
            actions.append("Contact your electricity distribution company directly using their official bill or website.")
        elif "COURIER" in ind.id:
            actions.append("Track packages only through official carrier websites; police never conduct arrests over video calls.")
        elif "SIM" in ind.id:
            actions.append("Visit an official telecom operator store for SIM/KYC issues; never install remote-access apps.")
        elif "CUSTOMER_CARE" in ind.id:
            actions.append("Look up customer support numbers only on official bank/service websites or mobile apps.")
        elif "APK" in ind.id:
            actions.append("Never download or install .apk files from SMS or WhatsApp links.")

    if final_level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
        actions.append("Report suspected fraud to national cybercrime authorities (e.g. cybercrime.gov.in / 1930).")

    # De-duplicate while preserving order
    seen = set()
    deduped = []
    for act in actions:
        cleaned = act.strip()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            deduped.append(cleaned)

    if not deduped:
        deduped = ["Exercise standard caution and verify message details through official channels."]

    return deduped


def compute_calibrated_verdict(
    score: float,
    indicators: List[Indicator],
    threat_intel: Optional[Any] = None,
) -> str:
    """Determine the calibrated verdict across 6 distinct risk bands.

    Bands:
    - KNOWN_MALICIOUS: Confirmed match in threat intelligence or Trojan APK.
    - HIGH_RISK: Strong brand context mismatch, deceptive credential/payment paths, score >= 60.
    - SUSPICIOUS: Multiple suspicious heuristics, score >= 40.
    - UNKNOWN_UNVERIFIED: Unverified arbitrary destination or shortener with unknown reputation (score 20–39).
    - LOW_RISK: Established domain or low-level signal, clean context (score 10–19).
    - BENIGN: Normal communication, zero threats or official whitelisted domain (score < 10).
    """
    if (threat_intel and getattr(threat_intel, "is_known_malicious", False)) or any(
        ind.id == "IND_THREAT_INTEL_MALICIOUS" for ind in indicators
    ):
        return "KNOWN_MALICIOUS"

    has_brand_mismatch = any(ind.id == "IND_BRAND_DOMAIN_MISMATCH" for ind in indicators)
    has_malicious_apk = any(ind.id == "IND_MALICIOUS_APK" for ind in indicators)
    has_critical_solicit = any(
        ind.id in ("IND_OTP_SOLICIT", "IND_CREDENTIAL_SOLICIT", "IND_REVERSE_UPI")
        for ind in indicators
    )
    if has_brand_mismatch or has_malicious_apk or has_critical_solicit or score >= 60.0:
        return "HIGH_RISK"

    if score >= 40.0:
        return "SUSPICIOUS"

    has_unverified_url = any(
        ind.id in ("IND_URL_UNVERIFIED_DESTINATION", "IND_URL_SHORTENER")
        for ind in indicators
    )
    if has_unverified_url or (20.0 <= score < 40.0):
        return "UNKNOWN_UNVERIFIED"

    if score >= 10.0:
        return "LOW_RISK"

    return "BENIGN"


def fuse_risk_analysis(
    deterministic: DeterministicAnalysis,
    bedrock: BedrockAnalysisResult,
    source_type: Optional[str] = "message",
    message_length: Optional[int] = None,
    threat_intel: Optional[Any] = None,
    ai_intent: Optional[Any] = None,
) -> AnalysisResponse:
    """Execute risk fusion algorithm producing authoritative AnalysisResponse."""
    # 1. Compute calibrated score
    final_score = compute_fused_risk_score(deterministic, bedrock, threat_intel, ai_intent)

    # 2. Derive calibrated risk level
    final_risk_level = calibrate_risk_level(final_score)

    # 3. Reconcile authoritative category
    authoritative_category = reconcile_category(deterministic, bedrock, final_score, ai_intent)

    # 4. Calibrated verdict
    verdict = compute_calibrated_verdict(final_score, deterministic.indicators, threat_intel)

    # 5. Derive canonical forensic fields (demanded action, pressure level, tactics, impacts, do/do not)
    canonical = derive_canonical_forensic_fields(
        deterministic=deterministic,
        final_score=final_score,
        verdict=verdict,
        category=authoritative_category,
        ai_intent=ai_intent,
    )

    # 6. Generate grounded attack chain (strictly evidence-backed)
    attack_path = generate_grounded_attack_chain(
        deterministic=deterministic,
        bedrock=bedrock,
        category=authoritative_category,
        final_score=final_score,
        demanded_action=canonical["demanded_action"],
        ai_intent=ai_intent,
    )

    # 7. Synthesize explanation
    if ai_intent and getattr(ai_intent, "explanation", ""):
        reasoning = getattr(ai_intent, "explanation", "")
    elif bedrock.ai_available and bedrock.reasoning:
        reasoning = bedrock.reasoning
    else:
        reasoning = deterministic.explanation

    # 8. Protective actions
    actions = list(canonical["do_actions"])
    base_actions = synthesize_recommended_actions(deterministic, bedrock, final_risk_level)
    for act in base_actions:
        if act not in actions:
            actions.append(act)
    if ai_intent and getattr(ai_intent, "recommended_action", ""):
        rec_act = getattr(ai_intent, "recommended_action", "").strip()
        if rec_act and rec_act not in actions:
            actions.insert(0, rec_act)

    # 9. Attacker intent
    if final_score < 20.0 or authoritative_category == ScamCategory.BENIGN:
        attacker_intent = "No malicious exploitation intent detected. Message appears consistent with normal communication."
    elif any(ind.id == "IND_URL_SHORTENER" for ind in deterministic.indicators) and len(deterministic.indicators) == 1:
        attacker_intent = "Direct recipient to an unverified web destination via a shortened URL link."
    elif ai_intent and getattr(ai_intent, "attacker_intent", ""):
        attacker_intent = getattr(ai_intent, "attacker_intent", "")
    else:
        attacker_intent = synthesize_attacker_intent(deterministic, bedrock, authoritative_category)

    # 10. Confidence & FP checks
    confidence = compute_confidence(deterministic, bedrock, final_score)
    fp_checks = synthesize_false_positive_checks(deterministic, bedrock, final_score)

    threat_intel_summary = None
    if threat_intel:
        threat_intel_summary = {
            "status": getattr(threat_intel, "status", "unverified"),
            "isKnownMalicious": getattr(threat_intel, "is_known_malicious", False),
            "threatTypes": getattr(threat_intel, "threat_types", []),
            "provider": getattr(threat_intel, "provider", "google_web_risk"),
            "details": getattr(threat_intel, "details", ""),
        }

    ai_intent_summary = None
    if ai_intent:
        from backend.src.models.response import AIIntentResponse
        ai_intent_summary = AIIntentResponse(
            scamCategory=getattr(ai_intent, "scam_category", authoritative_category.value),
            attackerIntent=attacker_intent,
            manipulationTactics=canonical["manipulation_tactics"],
            requestedAction=getattr(ai_intent, "requested_action", "NO_ACTION"),
            urgencyLevel=getattr(ai_intent, "urgency_level", "LOW" if canonical["pressure_level"] == "LOW" else "NONE"),
            explanation=reasoning,
            potentialConsequence=canonical["potential_impact"][0] if canonical["potential_impact"] else "No security risk identified.",
            recommendedAction=actions[0] if actions else "Verify independently through official channels.",
            confidence=getattr(ai_intent, "confidence", confidence),
            evidencePhrases=getattr(ai_intent, "evidence_phrases", []),
            aiAvailable=getattr(ai_intent, "ai_available", True),
            modelId=getattr(ai_intent, "model_id", None),
            errorMessage=getattr(ai_intent, "error_message", None),
        )

    return AnalysisResponse(
        riskScore=final_score,
        riskLevel=final_risk_level,
        category=authoritative_category.value,
        indicators=deterministic.indicators,
        reasoning=reasoning,
        attackerIntent=attacker_intent,
        attackPath=attack_path,
        recommendedAction=actions[0] if actions else "Verify independently through official channels.",
        recommendedActions=actions,
        confidence=confidence,
        falsePositiveChecks=fp_checks,
        verdict=verdict,
        demandedAction=canonical["demanded_action"],
        pressureLevel=canonical["pressure_level"],
        manipulationTactic=canonical["manipulation_tactic"],
        manipulationTactics=canonical["manipulation_tactics"],
        potentialImpact=canonical["potential_impact"],
        doActions=canonical["do_actions"],
        doNotActions=canonical["do_not_actions"],
        threatIntelligence=threat_intel_summary,
        aiIntent=ai_intent_summary,
        status="received",
        length=message_length,
    )