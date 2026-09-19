"""Scam taxonomy and category resolution rules for deterministic detection."""

from typing import Set
from backend.src.models.response import ScamCategory


def resolve_primary_category(signal_ids: Set[str], text_lower: str = "") -> ScamCategory:
    """Resolve the most specific applicable scam category from triggered signal IDs.

    Rules evaluate in order of specificity and threat severity.
    """
    if not signal_ids or signal_ids == {"IND_URGENT_LANGUAGE"}:
        return ScamCategory.BENIGN

    # 1. Reverse UPI and payment trap signals
    if "IND_REVERSE_UPI" in signal_ids or "IND_PAYMENT_COLLECT" in signal_ids:
        return ScamCategory.PAYMENT_SCAM

    # 2. Utility / Electricity disconnection threats
    if "IND_ELECTRICITY_DISCONNECT" in signal_ids:
        return ScamCategory.ELECTRICITY_SCAM

    # 3. Courier / Parcel seizure & customs extortion
    if "IND_COURIER_PARCEL" in signal_ids:
        return ScamCategory.COURIER_SCAM

    # 4. SIM card block & telecom KYC fraud
    if "IND_SIM_DEACTIVATION" in signal_ids:
        return ScamCategory.SIM_DEACTIVATION_SCAM

    # 5. Fake customer care / helpline lure
    if "IND_CUSTOMER_SUPPORT" in signal_ids:
        return ScamCategory.CUSTOMER_SUPPORT_SCAM

    # 6. Account suspension / KYC specific threats
    if "IND_KYC_SUSPENSION" in signal_ids or "IND_KYC_EXPIRE" in signal_ids:
        return ScamCategory.ACCOUNT_KYC_SCAM

    # 7. Explicit credential theft / harvesting
    if "IND_CREDENTIAL_SOLICIT" in signal_ids:
        if "IND_IMPERSONATION_BANK" in signal_ids:
            return ScamCategory.BANKING_SCAM
        return ScamCategory.CREDENTIAL_THEFT

    # 8. Banking impersonation with urgency, links, or OTP
    if "IND_IMPERSONATION_BANK" in signal_ids and (
        "IND_OTP_SOLICIT" in signal_ids
        or "IND_SUSPICIOUS_URL" in signal_ids
        or "IND_THREAT_CONSEQUENCE" in signal_ids
    ):
        return ScamCategory.BANKING_SCAM

    # 9. Government / Police / Legal authority impersonation
    if "IND_IMPERSONATION_GOVT" in signal_ids or "IND_THREAT_LEGAL" in signal_ids:
        return ScamCategory.GOVERNMENT_IMPERSONATION

    # 10. Job offer / task extortion
    if "IND_JOB_SCAM" in signal_ids:
        return ScamCategory.JOB_SCAM

    # 11. Ponzi / investment doubling
    if "IND_INVESTMENT_SCAM" in signal_ids:
        return ScamCategory.INVESTMENT_SCAM

    # 12. Unsolicited lottery / cash reward
    if "IND_LOTTERY_REWARD" in signal_ids:
        return ScamCategory.LOTTERY_REWARD_SCAM

    # 13. Threat Intelligence match or Brand Domain Mismatch
    if "IND_THREAT_INTEL_MALICIOUS" in signal_ids or "IND_BRAND_DOMAIN_MISMATCH" in signal_ids:
        if "lpg" in text_lower or "subsidy" in text_lower:
            return ScamCategory.PHISHING
        if "IND_IMPERSONATION_BANK" in signal_ids or any(b in text_lower for b in ("sbi", "hdfc", "icici", "axis", "bank")):
            return ScamCategory.BANKING_SCAM
        if any(g in text_lower for g in ("incometax", "tax", "police", "aadhaar", "challan")):
            return ScamCategory.GOVERNMENT_IMPERSONATION
        if any(e in text_lower for e in ("electricity", "bijli", "power", "tneb", "bescom")):
            return ScamCategory.ELECTRICITY_SCAM
        return ScamCategory.PHISHING

    # 14. Generic phishing / credential link / unsafe schemes
    if (
        "IND_URL_UNSAFE_SCHEME" in signal_ids
        or "IND_SUSPICIOUS_URL" in signal_ids
        or "IND_URL_UNVERIFIED_DESTINATION" in signal_ids
        or "IND_OTP_SOLICIT" in signal_ids
    ):
        return ScamCategory.PHISHING

    # 15. Fallback for mixed or other suspicious patterns
    return ScamCategory.OTHER_SUSPICIOUS