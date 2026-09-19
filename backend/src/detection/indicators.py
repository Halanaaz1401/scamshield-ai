"""Deterministic cybersecurity threat indicator extractors and heuristic rules."""

import re
from typing import List, Tuple
from urllib.parse import urlparse

from backend.src.detection.url_intelligence import (
    extract_urls as deep_extract_urls,
    inspect_url_deep,
    is_authoritative_domain,
)
from backend.src.models.response import Indicator, Severity

# ---------------------------------------------------------------------------
# Pre-compiled Regex Patterns (Context-Aware, Backtracking-Safe)
# All patterns use flags=re.IGNORECASE for Python 3.14+ compatibility.
# ---------------------------------------------------------------------------

# 1. OTP Solicitations (Asking victim to share, tell, forward, or enter OTP)
# Avoid matching safety warnings like "do not share", "never share"
RE_OTP_SOLICIT = re.compile(
    r"(?<!do\snot\s)(?<!never\s)(?<!don't\s)(?<!not\s)\b(?:send|share|tell|give|provide|forward|enter|submit|batao|bhejo|share\s+karo|de\s+do)\b"
    r"[\s\w,.-]{0,40}\b(?:otp|one[- ]time\s+password|verification\s+code|mfa\s+code)\b|"
    r"\b(?:otp|one[- ]time\s+password|verification\s+code|mfa\s+code)\b"
    r"[\s\w,.-]{0,40}\b(?:batao|bhejo|share\s+karo|de\s+do|send|provide)\b",
    flags=re.IGNORECASE,
)

# Legitimate OTP delivery indicator (Used for false-positive suppression)
RE_OTP_BENIGN_DISPATCH = re.compile(
    r"(?:your\s+(?:one[- ]time\s+password|otp)\s+(?:for\s+[\w\s]+)?is\s+\d{4,8}|"
    r"use\s+(?:code|otp)\s+\d{4,8}|is\s+your\s+(?:secret\s+)?(?:otp|verification\s+code))\b.*?"
    r"(?:do\s+not\s+share|never\s+share|valid\s+for\s+\d+\s*(?:mins?|minutes?)|validity)",
    flags=re.IGNORECASE,
)

# 2. Reverse UPI & Collect Request Fraud
RE_REVERSE_UPI = re.compile(
    r"\b(?:approve|accept|click)\b[\s\w,.-]{0,30}\b(?:collect\s+request|collect\s+pay|request)\b|"
    r"\b(?:enter|put|type)\b[\s\w,.-]{0,30}\b(?:upi\s+pin|pin)\b[\s\w,.-]{0,40}\b(?:receive|get|claim|paane|credit)\b|"
    r"\bupi://pay\?[^\s]+|"
    r"\b(?:receive|paane\s+ke\s+liye)\b[\s\w,.-]{0,30}\b(?:upi\s+pin|pin)\b",
    flags=re.IGNORECASE,
)

# 3. Upfront Payment / Processing Fee Demands
RE_PAYMENT_COLLECT = re.compile(
    r"\b(?:pay|send|transfer|deposit)\b[\s\w,.-]{0,30}\b(?:fee|charge|advance|security\s+deposit|registration\s+fee|processing\s+fee)\b|"
    r"\b(?:registration|processing|security)\b[\s\w,.-]{0,20}\b(?:amount|charge|fee)\b[\s\w,.-]{0,30}\b(?:mandatory|required|before\s+payout)\b|"
    r"\b(?:registration|joining|activation)\s+fee\b[\s\w,.-]{0,20}(?:rs\.?|inr|₹)\s*[\d,]+",
    flags=re.IGNORECASE,
)

# 4. Credential Solicitation (Passwords, CVV, Card PIN, Netbanking)
RE_CREDENTIAL_SOLICIT = re.compile(
    r"\b(?:enter|share|update|provide|verify|send|submit)\b[\s\w,.-]{0,40}\b(?:password|netbanking\s+password|atm\s+pin|cvv|card\s+number|expiry\s+date|bank\s+credentials|login\s+details)\b|"
    r"\b(?:cvv|atm\s+pin|debit\s+card\s+pin)\b",
    flags=re.IGNORECASE,
)

# 5. Urgency & Coercive Pressure
RE_URGENCY = re.compile(
    r"\b(?:immediately|urgently|urgent\s+action|within\s+\d+\s*(?:hours?|hrs?|mins?|minutes?)|"
    r"immediate\s+action\s+required|last\s+chance|final\s+warning|expire(?:s|d)?\s+today|"
    r"jaldi\s+karein|turant|bina\s+deri|act\s+now|immediate\s+response)\b",
    flags=re.IGNORECASE,
)

# 6. Negative Consequences & Service Disruptions
RE_THREAT_CONSEQUENCE = re.compile(
    r"\b(?:accounts?|pan|pan[- ]kyc|kyc|cards?|sim|electricity|power|services?)\b[\s\w,.-]{0,30}"
    r"\b(?:block(?:ed)?|suspend(?:ed)?|deactivat(?:ed)?|terminat(?:ed|e)?|cancel(?:led)?|disconnected|cut\s+off)\b|"
    r"\b(?:block\s+ho\s+jayega|band\s+ho\s+jayega|kat\s+jayega|deactivate\s+ho\s+jayega)\b",
    flags=re.IGNORECASE,
)

# 7. Legal & Law Enforcement Threats
RE_THREAT_LEGAL = re.compile(
    r"\b(?:legal\s+action|police\s+(?:case|complaint)|arrest\s+warrant|court\s+notice|"
    r"cbi\s+investigation|customs\s+seizure|fir\s+registered|cyber\s+crime\s+notice|fine\s+of\s+(?:₹|rs\.?|inr)?[\d,]+|"
    r"digital\s+arrest|narcotics\s+department|money\s+laundering\s+case)\b",
    flags=re.IGNORECASE,
)

# 8. Bank & Financial Institution Impersonation
RE_IMPERSONATION_BANK = re.compile(
    r"\b(?:hdfc|sbi|state\s+bank\s+of\s+india|icici|axis\s+bank|punjab\s+national\s+bank|pnb|kotak|rbi|reserve\s+bank\s+of\s+india|bank\s+of\s+baroda|canara\s+bank|yono)\b",
    flags=re.IGNORECASE,
)

# 9. Government, Tax, & Courier Impersonation
RE_IMPERSONATION_GOVT = re.compile(
    r"\b(?:income\s+tax\s+department|it\s+department|customs\s+office|cbi|police\s+department|fedex|bluedart|india\s+post|delhivery|dhl)\b",
    flags=re.IGNORECASE,
)

# 10. KYC Expiration / PAN Verification / Subsidy Specific Lures
RE_KYC_SPECIFIC = re.compile(
    r"\b(?:pan[- ]?kyc|kyc\s+verification|update\s+(?:your\s+)?kyc|kyc\s+suspended|kyc\s+expired|kyc\s+pending|pending\s+kyc|lpg\s+subsidy|gas\s+subsidy|subsidy\s+is\s+pending|pan\s+card\s+link(?:ing)?|aadhaar\s+link(?:ing)?|link\s+pan\s+with\s+aadhaar)\b",
    flags=re.IGNORECASE,
)

# 11. Unsolicited Rewards, Lotteries, & Cashbacks
RE_LOTTERY_REWARD = re.compile(
    r"\b(?:congratulations|congrats|lucky\s+winner|you\s+have\s+won|you\s+have\s+received|won|selected\s+for)\b[\s\w,.-]{0,40}"
    r"(?:\b(?:rs\.?|inr|cashback|lottery|reward|prize|gift\s+card|bonus|jackpot)\b|₹|\$)|"
    r"(?:\b(?:reward|cashback|prize|lottery)\b|₹|\$)\s*(?:claim\s+karo|paane\s+ke\s+liye|jeet\s+gaye)\b",
    flags=re.IGNORECASE,
)

# 12. Task / Job Scams
RE_JOB_SCAM = re.compile(
    r"\b(?:part[- ]time\s+job|work\s+from\s+home|wfh|remote\s+job|job\s+vacancy)\b.{0,80}"
    r"\b(?:earn|salary|payout|daily\s+income)\b.{0,60}(?:rs\.?|inr|₹)\s*[\d,]+(?:[/-][\d,]+)?.{0,30}\bper\s+(?:day|month)|"
    r"\b(?:rating\s+hotels|liking\s+videos|youtube\s+likes|reviewing\s+products|google\s+maps\s+rating)\b|"
    r"\b(?:no\s+experience|no\s+skills?\s+required)\b[\s\w,.-]{0,30}\b(?:daily\s+payout|immediate\s+payment)\b",
    flags=re.IGNORECASE | re.DOTALL,
)

# 13. Investment & Money Doubling Scams
RE_INVESTMENT_SCAM = re.compile(
    r"\b(?:double\s+your\s+money|paisa\s+double|guaranteed\s+returns?|risk[- ]free\s+returns?|"
    r"daily\s+\d+%\s+profit|crypto\s+doubler|100%\s+guaranteed\s+return)\b|"
    r"\binvest\s*(?:₹|rs\.?)?\s*[\d,]+\s*and\s*get\s*(?:₹|rs\.?)?\s*[\d,]+",
    flags=re.IGNORECASE,
)

# 14. Off-Platform Steering (Telegram / WhatsApp)
RE_OFF_PLATFORM = re.compile(
    r"\b(?:contact|message|dm|join|reach)\b[\s\w,.-]{0,30}\b(?:on\s+telegram|on\s+whatsapp|telegram\s+channel|telegram\s+handle)\b|"
    r"(?:t\.me\/|wa\.me\/|telegram\s+@[\w_]+|whatsapp\s+(?:us\s+at\s+)?\+?[\d\s-]{10,})",
    flags=re.IGNORECASE,
)

# 15. Obfuscated Spaced Characters (e.g., 'o t p', 'p a s s w o r d', 'k y c')
RE_SPACED_OBFUSCATION = re.compile(
    r"\b(?:o\s+t\s+p|p\s+a\s+s\s+s\s+w\s+o\s+r\s+d|k\s+y\s+c|b\s+a\s+n\s+k|u\s+p\s+i|s\s+b\s+i|h\s+d\s+f\s+c)\b",
    flags=re.IGNORECASE,
)

# 16. Electricity / Utility Disconnection Threats (Indian Scam Pattern)
RE_ELECTRICITY_DISCONNECT = re.compile(
    r"\b(?:electricity|power|bijli|light)\b[\s\w,.-]{0,40}\b(?:bill|connection|supply|meter|consumer|subdivision)\b[\s\w,.-]{0,50}\b(?:disconnect(?:ed)?|cut\s+off|kat\s+jayega|kat\s+di\s+jayegi|suspend(?:ed)?|tonight\s+at\s+\d+)\b|"
    r"\b(?:power\s+will\s+be\s+disconnected|power\s+supply\s+will\s+be\s+disconnected|electricity\s+power\s+will\s+be\s+disconnected|electricity\s+officer|bijli\s+officer|contact\s+electricity\s+officer|contact\s+our\s+electricity\s+officer|call\s+electricity\s+officer|call\s+je)\b|"
    r"\b(?:dear\s+consumer|dear\s+customer)\b[\s\w,.-]{0,40}\b(?:disconnected\s+tonight|power\s+cut)\b",
    flags=re.IGNORECASE,
)

# 17. Courier / Parcel / Customs Seizure (Indian Scam Pattern)
RE_COURIER_PARCEL = re.compile(
    r"\b(?:parcel|package|shipment|consignment|courier)\b[\s\w,.-]{0,35}\b(?:seized|detained|held|stuck|stopped|intercepted|customs\s+clearance|clearance\s+fee|unpaid\s+duty|contraband|drugs|illegal)\b|"
    r"\b(?:fedex|bluedart|delhivery|india\s+post|dhl)\b[\s\w,.-]{0,35}\b(?:parcel|package|shipment|delivery|seized|customs|penalty)\b",
    flags=re.IGNORECASE,
)

# 18. SIM Card / Telecom KYC Suspension (Indian Scam Pattern)
RE_SIM_DEACTIVATION = re.compile(
    r"\b(?:sim|sim\s+card|esim|mobile\s+number)\b[\s\w,.-]{0,30}\b(?:deactivat(?:ed)?|block(?:ed)?|suspended|stopped|band\s+ho\s+jayega|expired)\b[\s\w,.-]{0,40}\b(?:within\s+\d+\s*(?:hours?|hrs?)|today|24\s*hrs?|kyc|call\s+customer\s+care)\b|"
    r"\b(?:jio|airtel|bsnl|vi)\b[\s\w,.-]{0,25}\b(?:sim\s+block|sim\s+deactivation|kyc\s+pending|document\s+verification)\b",
    flags=re.IGNORECASE,
)

# 19. Fake Customer Support / Refund Helpline Lure
RE_FAKE_CUSTOMER_CARE = re.compile(
    r"\b(?:for\s+refund|to\s+cancel|customer\s+care|helpline|support\s+executive|toll[- ]free|customer\s+support)\b[\s\w,.-]{0,30}\b(?:call\s+now|call\s+immediately|contact\s+at|dial)\b[\s\w,.-]{0,20}(?:\+?91[\s-]?)?[6-9]\d{9}\b|"
    r"\b(?:paytm|phonepe|gpay|google\s+pay|amazon)\b[\s\w,.-]{0,30}\b(?:customer\s+care|support\s+number|refund\s+helpline)\b",
    flags=re.IGNORECASE,
)

# 20. Malicious APK Android Application Vector
RE_MALICIOUS_APK = re.compile(
    r"\bhttps?://[^\s]+\.apk\b|\b(?:download|install|update)\b[\s\w,.-]{0,30}\b(?:apk\s+file|\.apk|support\s+app|kyc\s+app|bill\s+app)\b",
    flags=re.IGNORECASE,
)

# URL Pattern for legacy and fallback matching
RE_URL = re.compile(r"\b(?:https?://|www\.)[^\s<>'\"`]+", flags=re.IGNORECASE)

# Suspicious TLDs with elevated abuse patterns
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".link", ".club", ".work", ".click", ".buzz", ".rest",
    ".site", ".icu", ".cam", ".monster", ".vip", ".live",
    ".online", ".cc", ".ws",
}

# Known shortener services
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "ow.ly",
}

# High-risk brand keywords in spoofed hostnames
BRAND_KEYWORDS = {"hdfc", "sbi", "icici", "axis", "yono", "paytm", "phonepe", "gpay", "googlepay", "kyc", "pan"}


# ---------------------------------------------------------------------------
# Normalization & De-obfuscation Helpers
# ---------------------------------------------------------------------------

def normalize_obfuscated_keywords(text: str) -> str:
    """Normalize zero-width characters and spaced keywords for deterministic scanning."""
    # 1. Strip zero-width and invisible control characters
    cleaned = re.sub(r"[\u200B-\u200D\uFEFF]", "", text)

    # 2. Spaced keywords normalization
    replacements = {
        r"\bo\s+t\s+p\b": "otp",
        r"\bp\s+a\s+s\s+s\s+w\s+o\s+r\s+d\b": "password",
        r"\bk\s+y\s+c\b": "kyc",
        r"\bb\s+a\s+n\s+k\b": "bank",
        r"\bu\s+p\s+i\b": "upi",
        r"\bs\s+b\s+i\b": "sbi",
        r"\bh\s+d\s+f\s+c\b": "hdfc",
        r"\bp\s+a\s+y\s+t\s+m\b": "paytm",
    }
    for pattern, repl in replacements.items():
        cleaned = re.sub(pattern, repl, cleaned, flags=re.IGNORECASE)
    return cleaned


# ---------------------------------------------------------------------------
# Heuristic Feature Extractors
# ---------------------------------------------------------------------------

def inspect_urls(text: str) -> List[Tuple[str, Severity, str]]:
    """Detect suspicious URL structures, IP addresses, deceptive brand keywords, and abuse TLDs.

    Preserved for backward-compatibility; returns a list of (evidence_snippet, severity, description).
    """
    found_urls = deep_extract_urls(text)
    findings = []

    for raw_url in found_urls:
        url_inds = inspect_url_deep(raw_url)
        for ind in url_inds:
            findings.append((
                raw_url,
                ind.severity,
                ind.description,
            ))

    return findings


def is_legitimate_bank_notification(text: str) -> bool:
    """Identify authentic bank account debit/credit alerts to prevent false positives."""
    text_lower = text.lower()
    has_amount = bool(re.search(r"\b(?:inr|rs\.?)\s*[\d,]+(?:\.\d{2})?\b", text_lower))
    has_debit_credit = bool(re.search(r"\b(?:debited|credited)\b", text_lower))
    has_masked_acc = bool(re.search(r"\b(?:a\/c\s*(?:no\.?)?\s*|account\s*)(?:xx|\*{2,})[\da-z]+\b", text_lower))
    has_balance = bool(re.search(r"\b(?:avl\s+bal|balance|total\s+bal)\b", text_lower))
    has_urls = bool(RE_URL.search(text))

    # If it is a structured debit/credit notification without external links, it is authentic
    if has_amount and has_debit_credit and has_masked_acc and has_balance and not has_urls:
        return True

    return False


def is_legitimate_otp_notification(text: str) -> bool:
    """Identify authentic outbound OTP notifications that include standard security warnings.

    Authentic OTPs provide a code and explicitly warn the user NOT to share it.
    """
    has_dispatch = bool(RE_OTP_BENIGN_DISPATCH.search(text))
    has_safety_warning = bool(re.search(r"\b(?:do\s+not|never|don't)\s+share\b", text, flags=re.IGNORECASE))

    if has_dispatch and has_safety_warning:
        return True

    return False


# ---------------------------------------------------------------------------
# Indicator Collection Engine with Structured Evidence
# ---------------------------------------------------------------------------

def extract_threat_indicators(text: str) -> List[Indicator]:
    """Inspect untrusted message content and extract all matching deterministic security signals."""
    # 1. False Positive Suppression Check
    if is_legitimate_bank_notification(text):
        return []

    if is_legitimate_otp_notification(text):
        return []

    indicators: List[Indicator] = []

    # Check for spaced character obfuscation on original text
    match_obfuscated = RE_SPACED_OBFUSCATION.search(text)
    if match_obfuscated:
        indicators.append(Indicator(
            id="IND_OBFUSCATION",
            name="Character Spacing Obfuscation",
            description="Deliberately inserts spaces between characters to evade conventional keyword detection filters.",
            severity=Severity.MEDIUM,
            evidence=match_obfuscated.group(0).strip(),
            why_it_matters="Adversaries insert spaces within sensitive words (e.g. 'O T P', 'P A S S W O R D') to defeat signature matching filters.",
            attacker_objective="Evade automated carrier and device spam filters while remaining legible to the human victim.",
            attack_stage="Deception Layer",
        ))

    # Run detectors against de-obfuscated normalized text
    eval_text = normalize_obfuscated_keywords(text)

    # 2. OTP Solicitation (Malicious)
    match_otp = RE_OTP_SOLICIT.search(eval_text)
    if match_otp:
        indicators.append(Indicator(
            id="IND_OTP_SOLICIT",
            name="One-Time Passcode (OTP) Solicitation",
            description="Explicitly prompts recipient to share, forward, or input a secret OTP or verification code.",
            severity=Severity.CRITICAL,
            evidence=match_otp.group(0).strip(),
            why_it_matters="OTPs are second-factor authentication secrets. Legitimate institutions never ask users to share or forward them.",
            attacker_objective="Bypass two-factor authentication (2FA) to authorize fraudulent transactions or account takeovers.",
            attack_stage="Credential Harvesting",
        ))

    # 3. Reverse UPI Collect Request
    match_upi = RE_REVERSE_UPI.search(eval_text)
    if match_upi:
        indicators.append(Indicator(
            id="IND_REVERSE_UPI",
            name="Reverse UPI Collect Deception",
            description="Instructs recipient to approve a collect payment request or enter UPI PIN to receive money.",
            severity=Severity.CRITICAL,
            evidence=match_upi.group(0).strip(),
            why_it_matters="Entering a UPI PIN always debits funds from the account; receiving money via UPI never requires entering a PIN.",
            attacker_objective="Trick the recipient into authorizing an outbound fund transfer under the illusion of receiving a credit.",
            attack_stage="Payment Exfiltration",
        ))

    # 4. Upfront Payment / Processing Fee Demands
    match_pay_collect = RE_PAYMENT_COLLECT.search(eval_text)
    if match_pay_collect:
        indicators.append(Indicator(
            id="IND_PAYMENT_COLLECT",
            name="Upfront Advance Fee Demand",
            description="Requires an upfront security deposit, registration, or processing fee to release promised funds or jobs.",
            severity=Severity.HIGH,
            evidence=match_pay_collect.group(0).strip(),
            why_it_matters="Legitimate employers, lotteries, and buyers never require upfront advance fees before disbursing funds.",
            attacker_objective="Extract advance payments under fraudulent pretenses before terminating contact.",
            attack_stage="Payment Exfiltration",
        ))

    # 5. Sensitive Credential Harvesting
    match_cred = RE_CREDENTIAL_SOLICIT.search(eval_text)
    if match_cred:
        indicators.append(Indicator(
            id="IND_CREDENTIAL_SOLICIT",
            name="Sensitive Credential Harvesting",
            description="Requests passwords, NetBanking logins, ATM PINs, or debit/credit card CVV details.",
            severity=Severity.CRITICAL,
            evidence=match_cred.group(0).strip(),
            why_it_matters="Confidential banking credentials grant complete unauthorized access to financial accounts.",
            attacker_objective="Harvest credentials for unauthorized electronic fund transfers or identity theft.",
            attack_stage="Credential Harvesting",
        ))

    # 6. KYC Expiration / Suspension Lures
    match_kyc = RE_KYC_SPECIFIC.search(eval_text)
    if match_kyc:
        indicators.append(Indicator(
            id="IND_KYC_SUSPENSION",
            name="Urgent PAN/KYC Deactivation Claim",
            description="Fabricates sudden KYC or PAN account expiration to create an immediate verification panic.",
            severity=Severity.HIGH,
            evidence=match_kyc.group(0).strip(),
            why_it_matters="KYC compliance is a common regulatory obligation in India, making it an effective social engineering lure for panicking users.",
            attacker_objective="Induce urgency so the victim clicks a fake verification link without out-of-band verification.",
            attack_stage="Psychological Trigger",
        ))

    # 7. Artificial Urgency vs Calibrated Time Sensitivity
    match_urgency = RE_URGENCY.search(eval_text)
    if match_urgency:
        has_coercive_threat = bool(
            RE_THREAT_CONSEQUENCE.search(eval_text)
            or RE_THREAT_LEGAL.search(eval_text)
            or RE_CREDENTIAL_SOLICIT.search(eval_text)
            or RE_OTP_SOLICIT.search(eval_text)
            or RE_REVERSE_UPI.search(eval_text)
            or RE_LOTTERY_REWARD.search(eval_text)
            or RE_KYC_SPECIFIC.search(eval_text)
            or RE_PAYMENT_COLLECT.search(eval_text)
            or RE_MALICIOUS_APK.search(eval_text)
        )
        if has_coercive_threat:
            indicators.append(Indicator(
                id="IND_URGENCY_TACTIC",
                finding_id="URGENCY_001",
                type="coercive_deadline",
                source="deterministic_heuristic",
                confidence="HIGH",
                name="Coercive Urgency & Artificial Deadline",
                description="Imposes a tight deadline combined with threats or sensitive requests to bypass deliberate scrutiny.",
                severity=Severity.HIGH,
                evidence=match_urgency.group(0).strip(),
                why_it_matters="Manufactured time pressure combined with penalties induces cognitive overload, forcing hasty compliance.",
                attacker_objective="Force hasty compliance before the victim has time to consult their bank or family.",
                attack_stage="Psychological Trigger",
            ))
        else:
            indicators.append(Indicator(
                id="IND_URGENT_LANGUAGE",
                finding_id="URGENCY_001",
                type="artificial_deadline",
                source="deterministic_heuristic",
                confidence="HIGH",
                name="Urgent Language Detected",
                description="Contains time-sensitive phrasing (e.g. 'within 15 minutes'). Isolated time sensitivity is not inherently fraudulent.",
                severity=Severity.LOW,
                evidence=match_urgency.group(0).strip(),
                why_it_matters="Time-sensitive phrasing may be used in normal communication or to expedite response; requires contextual corroboration.",
                attacker_objective="Prompt prompt interaction or convey time sensitivity.",
                attack_stage="Time Sensitivity",
            ))

    # 8. Threat of Service Termination / Block
    match_threat = RE_THREAT_CONSEQUENCE.search(eval_text)
    if match_threat:
        indicators.append(Indicator(
            id="IND_THREAT_CONSEQUENCE",
            name="Imminent Account or Service Deactivation Threat",
            description="Threatens to immediately suspend banking access, deactivate SIM, or disconnect electricity.",
            severity=Severity.HIGH,
            evidence=match_threat.group(0).strip(),
            why_it_matters="Threatening deactivation of critical daily services (bank account, phone number, electricity) provokes instinctual panic.",
            attacker_objective="Manipulate the victim into taking immediate defensive action dictated by the attacker.",
            attack_stage="Psychological Trigger",
        ))

    # 9. Law Enforcement & Legal Intimidation / Digital Arrest
    match_legal = RE_THREAT_LEGAL.search(eval_text)
    if match_legal:
        indicators.append(Indicator(
            id="IND_THREAT_LEGAL",
            name="Law Enforcement & Legal Intimidation",
            description="Claims pending arrest warrants, police action, court orders, or severe fines to induce fear.",
            severity=Severity.CRITICAL,
            evidence=match_legal.group(0).strip(),
            why_it_matters="Impersonating police, CBI, or customs creates intense legal intimidation, which is the cornerstone of 'Digital Arrest' extortion.",
            attacker_objective="Isolate and terrorize the victim into compliance or fund transfers under fear of prosecution.",
            attack_stage="Psychological Trigger",
        ))

    # 10. Financial Institution Impersonation
    match_bank = RE_IMPERSONATION_BANK.search(eval_text)
    if match_bank and (match_urgency or match_threat or match_kyc or match_otp):
        indicators.append(Indicator(
            id="IND_IMPERSONATION_BANK",
            name="Banking Entity Impersonation",
            description="Illegitimately leverages names of reputable financial institutions (SBI, HDFC, ICICI, etc.) in an unauthenticated message.",
            severity=Severity.HIGH,
            evidence=match_bank.group(0).strip(),
            why_it_matters="Spoofing reputable bank brands exploits institutional trust to lend credibility to counterfeit instructions.",
            attacker_objective="Disarm user suspicion by posing as their trusted financial provider.",
            attack_stage="Deception Layer",
        ))

    # 11. Government / Authority Impersonation
    match_govt = RE_IMPERSONATION_GOVT.search(eval_text)
    if match_govt:
        # Check if the mention is purely within an authoritative domain without extortion cues
        is_purely_official = False
        all_found_urls = deep_extract_urls(eval_text)
        if all_found_urls and all(is_authoritative_domain(urlparse(u if "://" in u else f"https://{u}").hostname or "") for u in all_found_urls):
            if not (match_threat or match_legal or match_urgency or match_kyc):
                is_purely_official = True

        if not is_purely_official:
            indicators.append(Indicator(
                id="IND_IMPERSONATION_GOVT",
                name="Government or Courier Authority Impersonation",
                description="Falsely claims association with the Income Tax Department, Customs, Police, or India Post.",
                severity=Severity.HIGH,
                evidence=match_govt.group(0).strip(),
                why_it_matters="Government and courier authority claims pressure victims to resolve alleged regulatory violations or fees.",
                attacker_objective="Exploit perceived state authority to prevent questioning of fraudulent directives.",
                attack_stage="Deception Layer",
            ))

    # 12. Unsolicited Reward / Lottery Claims
    match_reward = RE_LOTTERY_REWARD.search(eval_text)
    if match_reward:
        indicators.append(Indicator(
            id="IND_LOTTERY_REWARD",
            name="Unsolicited Prize or Cashback Bait",
            description="Entices victim with unexpected lottery winnings, festive cash prizes, or high-value rewards.",
            severity=Severity.HIGH,
            evidence=match_reward.group(0).strip(),
            why_it_matters="Greed-based cognitive triggers tempt recipients into overlooking inconsistencies in order to claim promised funds.",
            attacker_objective="Bait the victim into engaging with the scammer and paying advance processing fees or sharing bank details.",
            attack_stage="Inbound Lure",
        ))

    # 13. Task & Part-Time Job Scams
    match_job = RE_JOB_SCAM.search(eval_text)
    if match_job:
        indicators.append(Indicator(
            id="IND_JOB_SCAM",
            name="Part-Time Remote Task Scam",
            description="Promises exaggerated daily earnings (e.g. ₹3,000-₹8,000) for trivial tasks like rating hotels or liking videos.",
            severity=Severity.HIGH,
            evidence=match_job.group(0).strip(),
            why_it_matters="Promises of easy income exploit job seekers, leading to task fraud where victims are eventually required to pay prepaid deposits.",
            attacker_objective="Entrap victim in a sunk-cost task scam where they deposit increasingly large sums to 'unlock' earnings.",
            attack_stage="Inbound Lure",
        ))

    # 14. Investment & Money Doubling
    match_invest = RE_INVESTMENT_SCAM.search(eval_text)
    if match_invest:
        indicators.append(Indicator(
            id="IND_INVESTMENT_SCAM",
            name="Guaranteed High-Return Investment Bait",
            description="Promises unrealistic risk-free profits or guaranteed money doubling schemes.",
            severity=Severity.HIGH,
            evidence=match_invest.group(0).strip(),
            why_it_matters="Guaranteed high-yield investment schemes are mathematically impossible and are hallmarks of Ponzi and crypto doubling fraud.",
            attacker_objective="Lure victim into transferring investment capital to an unregulated fake portfolio controlled by the scammer.",
            attack_stage="Inbound Lure",
        ))

    # 15. Off-Platform Channel Redirection (Telegram/WhatsApp)
    match_off_plat = RE_OFF_PLATFORM.search(eval_text)
    if match_off_plat:
        indicators.append(Indicator(
            id="IND_OFF_PLATFORM",
            name="Off-Platform Migration to Unmonitored Channel",
            description="Redirects conversation to encrypted, anonymous channels (Telegram/WhatsApp) to evade moderation.",
            severity=Severity.MEDIUM,
            evidence=match_off_plat.group(0).strip(),
            why_it_matters="Migrating to private messaging removes transaction audit trails and isolates the victim from security warnings.",
            attacker_objective="Conduct social engineering in an unmonitored environment free from spam and fraud filters.",
            attack_stage="Deception Layer",
        ))

    # 16. Utility / Electricity Disconnection (Indian Scam Pattern)
    match_electricity = RE_ELECTRICITY_DISCONNECT.search(eval_text)
    if match_electricity:
        indicators.append(Indicator(
            id="IND_ELECTRICITY_DISCONNECT",
            name="Utility/Electricity Disconnection Threat",
            description="Threatens an imminent electricity or utility cutoff tonight unless the recipient contacts a fake officer or pays immediately.",
            severity=Severity.HIGH,
            evidence=match_electricity.group(0).strip(),
            why_it_matters="Threatening immediate power cutoff provokes extreme distress regarding household disruption, driving victims to dial unauthorized mobile numbers.",
            attacker_objective="Force victim to call a fraudulent helpline or download remote-access software (AnyDesk/TeamViewer) under the pretext of bill payment.",
            attack_stage="Psychological Trigger",
        ))

    # 17. Courier / Parcel Seizure (Indian Scam Pattern)
    match_courier = RE_COURIER_PARCEL.search(eval_text)
    if match_courier:
        indicators.append(Indicator(
            id="IND_COURIER_PARCEL",
            name="Fraudulent Parcel Seizure / Delivery Alert",
            description="Claims an incoming or outgoing parcel has been seized, held, or detained due to customs penalties or illegal contraband.",
            severity=Severity.HIGH,
            evidence=match_courier.group(0).strip(),
            why_it_matters="Parcel interception claims are the primary entry point for Digital Arrest and customs extortion scams in India.",
            attacker_objective="Fabricate an escalating customs or narcotics violation to extort clearance payments from the victim.",
            attack_stage="Inbound Lure",
        ))

    # 18. SIM Card / Telecom KYC Suspension (Indian Scam Pattern)
    match_sim = RE_SIM_DEACTIVATION.search(eval_text)
    if match_sim:
        indicators.append(Indicator(
            id="IND_SIM_DEACTIVATION",
            name="SIM Card Deactivation & Telecom KYC Fraud",
            description="Fabricates an imminent SIM card suspension or expired telecom KYC to force urgent document or app verification.",
            severity=Severity.HIGH,
            evidence=match_sim.group(0).strip(),
            why_it_matters="Threatening phone number suspension causes urgent concern since mobile numbers are linked to bank accounts, OTPs, and personal identity.",
            attacker_objective="Coerce victim into installing malicious APKs or sharing sensitive identity documents for fraudulent SIM swaps.",
            attack_stage="Psychological Trigger",
        ))

    # 19. Fake Customer Support Helpline
    match_fake_support = RE_FAKE_CUSTOMER_CARE.search(eval_text)
    if match_fake_support:
        indicators.append(Indicator(
            id="IND_CUSTOMER_SUPPORT",
            name="Fake Customer Support Helpline Lure",
            description="Advertises an unverified direct mobile number as an official corporate or payment gateway customer support helpline.",
            severity=Severity.HIGH,
            evidence=match_fake_support.group(0).strip(),
            why_it_matters="Fraudulent helplines route unsuspecting victims seeking refunds directly to social engineers.",
            attacker_objective="Lure victim onto an unmonitored voice call to guide them through fraudulent UPI debits or remote access app downloads.",
            attack_stage="Inbound Lure",
        ))

    # 20. Malicious APK Android Application Vector
    match_apk = RE_MALICIOUS_APK.search(eval_text)
    if match_apk:
        indicators.append(Indicator(
            id="IND_MALICIOUS_APK",
            name="Malicious Android APK Application Payload",
            description="Prompts recipient to download an untrusted Android APK file outside official app stores.",
            severity=Severity.CRITICAL,
            evidence=match_apk.group(0).strip(),
            why_it_matters="Direct APK installations bypass Google Play Protect safeguards and are used to install SMS-stealing trojans that intercept 2FA banking OTPs.",
            attacker_objective="Compromise the victim's smartphone to forward SMS OTPs and execute unauthorized banking transactions.",
            attack_stage="Payload Action",
        ))

    # 21. Deep URL & Domain Intelligence
    found_urls = deep_extract_urls(eval_text)
    has_primary_url_indicator = any(ind.id == "IND_SUSPICIOUS_URL" for ind in indicators)
    for raw_url in found_urls:
        url_findings = inspect_url_deep(raw_url, context_text=eval_text)
        for u_ind in url_findings:
            indicators.append(u_ind)
            if not has_primary_url_indicator and u_ind.id != "IND_URL_UNVERIFIED_DESTINATION":
                indicators.append(Indicator(
                    id="IND_SUSPICIOUS_URL",
                    name=u_ind.name,
                    description=u_ind.description,
                    severity=u_ind.severity,
                    evidence=u_ind.evidence or raw_url,
                    why_it_matters=u_ind.why_it_matters,
                    attacker_objective=u_ind.attacker_objective,
                    attack_stage=u_ind.attack_stage,
                ))
                has_primary_url_indicator = True

    # Deduplicate logically identical indicators (same ID and same evidence)
    deduped_indicators: List[Indicator] = []
    seen_ind_keys = set()
    for ind in indicators:
        key = (ind.id, (ind.evidence or "").strip().lower())
        if key not in seen_ind_keys:
            seen_ind_keys.add(key)
            deduped_indicators.append(ind)

    return deduped_indicators