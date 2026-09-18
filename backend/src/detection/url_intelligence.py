"""Deep URL Threat Intelligence & Heuristics Engine for ScamShield AI.

Deterministic, safe, local-only URL analysis inspecting:
- Numeric IP hosts
- URL shortener identification
- High-abuse & suspicious TLD detection
- Structural anomalies (excessive length, excessive subdomains, subdomain brand deception)
- Brand & Context Impersonation (claimed organization/context vs. actual destination domain)
- Homoglyph / IDN look-alike character substitution & punycode
- Deceptive credential harvesting, payment lures, and urgency tokens in paths & queries
- Malicious Android APK download vectors
- Obfuscation techniques (@ userinfo, hex/percent encoding, non-standard ports, embedded URLs)
- Insecure HTTP usage for sensitive authentication/payment actions
- Unverified destination reputation tracking (ensuring unknown URLs are never classified as 'SAFE')
"""

import ipaddress
import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, unquote, urlparse

from backend.src.models.response import Indicator, Severity

# URL extraction pattern
RE_URL = re.compile(
    r"\b(?:https?://|www\.)[^\s<>'\"`]+|"
    r"\b[a-zA-Z0-9][-a-zA-Z0-9]*\.(?:xyz|top|tk|ml|ga|cf|gq|link|club|work|click|buzz|rest|site|icu|cam|monster|vip|live|online|app|cc|ws|cfd|sbs|quest|agency|date|racing|download|trade|bid|loan|party|cricket|fail|bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy)(?:/[^\s<>'\"`]*)?",
    flags=re.IGNORECASE,
)

# High-risk / high-abuse TLDs
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".link", ".club", ".work", ".click", ".buzz", ".rest",
    ".site", ".icu", ".cam", ".monster", ".vip", ".live",
    ".online", ".cc", ".ws", ".cfd", ".sbs", ".quest",
    ".agency", ".date", ".racing", ".download", ".trade",
    ".bid", ".loan", ".party", ".cricket", ".fail",
}

# Known URL shortener services
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly",
    "rb.gy", "ow.ly", "shorturl.at", "surl.li", "goo.gl",
    "buff.ly", "adf.ly", "bitly.com", "tiny.cc",
}

# Key targeted institutions & brands in Indian cyber threats
INDIAN_BRAND_KEYWORDS = {
    # Banks
    "sbi", "hdfc", "icici", "axis", "pnb", "kotak", "bob",
    "canara", "yono", "rbi", "statebank",
    # Payments & Fintech
    "paytm", "phonepe", "gpay", "googlepay", "bhim", "cred",
    # Utilities & Government
    "tneb", "bescom", "mahadiscom", "uppcl", "epfo", "incometax",
    "aadhaar", "uidai", "parivahan", "challan", "digilocker",
    # Couriers
    "indiapost", "fedex", "bluedart", "delhivery", "dhl",
    # Telecom
    "jio", "airtel", "bsnl", "vodafone",
    # LPG / Gas
    "indane", "hpgas", "bharatgas", "lpg",
}

# Legitimate authoritative root domains for whitelisting legitimate services
LEGITIMATE_BRAND_DOMAINS = {
    "sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbi.bank",
    "hdfcbank.com", "hdfc.com",
    "icicibank.com", "icici.com",
    "axisbank.com",
    "pnbindia.in",
    "kotak.com",
    "bankofbaroda.in",
    "canarabank.com",
    "rbi.org.in",
    "paytm.com",
    "phonepe.com",
    "google.com",
    "bhimupi.org.in",
    "cred.club",
    "incometax.gov.in",
    "incometaxindia.gov.in",
    "uidai.gov.in",
    "epfindia.gov.in",
    "indiapost.gov.in",
    "fedex.com",
    "bluedart.com",
    "delhivery.com",
    "dhl.com",
    "jio.com",
    "airtel.in", "airtel.com",
    "bsnl.co.in",
    "myvi.in",
    "iocl.com",
    "ebharatgas.com",
    "myhpgas.in",
    "pmuy.gov.in",
    "tnebnet.org",
    "mahadiscom.in",
    "uppcl.org",
}

# Recognized authoritative global domains (search, public web, official stores)
AUTHORITATIVE_GLOBAL_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.in", "amazon.com",
    "wikipedia.org", "github.com", "cloudflare.com", "play.google.com",
    "apps.apple.com", "youtube.com", "example.com", "example.org", "example.net",
}

# Claimed context categories for Brand & Context Impersonation detection
CLAIMED_CONTEXT_MAP = {
    "LPG / Gas Subsidy": {
        "keywords": ["lpg", "subsidy", "indane", "hp gas", "hpgas", "bharat gas", "bharatgas", "gas cylinder", "gas subsidy"],
        "valid_domains": {"iocl.com", "ebharatgas.com", "myhpgas.in", "pmuy.gov.in", "mopng.gov.in"},
        "entity_name": "LPG Gas Provider / Ministry of Petroleum",
    },
    "SBI / State Bank": {
        "keywords": ["sbi", "state bank", "yono"],
        "valid_domains": {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbi.bank"},
        "entity_name": "State Bank of India (SBI)",
    },
    "HDFC Bank": {
        "keywords": ["hdfc", "hdfcbank", "hdfc netbanking"],
        "valid_domains": {"hdfcbank.com", "hdfc.com"},
        "entity_name": "HDFC Bank",
    },
    "ICICI Bank": {
        "keywords": ["icici", "icicibank", "imobile"],
        "valid_domains": {"icicibank.com", "icici.com"},
        "entity_name": "ICICI Bank",
    },
    "Axis Bank": {
        "keywords": ["axis bank", "axisbank"],
        "valid_domains": {"axisbank.com"},
        "entity_name": "Axis Bank",
    },
    "Punjab National Bank": {
        "keywords": ["pnb", "punjab national bank"],
        "valid_domains": {"pnbindia.in"},
        "entity_name": "Punjab National Bank",
    },
    "Kotak Mahindra Bank": {
        "keywords": ["kotak", "kotak mahindra"],
        "valid_domains": {"kotak.com"},
        "entity_name": "Kotak Mahindra Bank",
    },
    "Paytm": {
        "keywords": ["paytm"],
        "valid_domains": {"paytm.com"},
        "entity_name": "Paytm",
    },
    "PhonePe": {
        "keywords": ["phonepe"],
        "valid_domains": {"phonepe.com"},
        "entity_name": "PhonePe",
    },
    "Electricity Utility": {
        "keywords": ["electricity", "bijli", "power disconnection", "power cutoff", "tneb", "bescom", "mahadiscom", "uppcl", "bill unpaid"],
        "valid_domains": {"tnebnet.org", "bescom.karnataka.gov.in", "mahadiscom.in", "uppcl.org"},
        "entity_name": "State Electricity Board / Utility",
    },
    "India Post / Courier": {
        "keywords": ["indiapost", "india post", "speedpost", "postal parcel", "post office parcel", "bluedart", "delhivery", "dhl", "fedex"],
        "valid_domains": {"indiapost.gov.in", "bluedart.com", "delhivery.com", "dhl.com", "fedex.com"},
        "entity_name": "Postal / Courier Delivery Service",
    },
    "Income Tax / Government": {
        "keywords": ["incometax", "it refund", "tax refund", "epfo", "pf balance", "aadhaar", "uidai", "digilocker", "parivahan", "echallan"],
        "valid_domains": {"incometax.gov.in", "incometaxindia.gov.in", "epfindia.gov.in", "uidai.gov.in", "digilocker.gov.in", "parivahan.gov.in"},
        "entity_name": "Government of India / Statutory Body",
    },
    "Telecom Provider": {
        "keywords": ["jio 5g", "jio sim", "airtel 5g", "airtel sim", "bsnl kyc", "vi sim", "sim deactivation", "sim blocked"],
        "valid_domains": {"jio.com", "airtel.in", "airtel.com", "bsnl.co.in", "myvi.in"},
        "entity_name": "Telecom Service Provider",
    },
}

# Cyrillic / Greek homoglyph mappings to latin equivalents
HOMOGLYPH_MAP = {
    "\u0430": "a",  # Cyrillic 'а'
    "\u0435": "e",  # Cyrillic 'е'
    "\u043e": "o",  # Cyrillic 'о'
    "\u0440": "p",  # Cyrillic 'р'
    "\u0441": "c",  # Cyrillic 'с'
    "\u0443": "y",  # Cyrillic 'у'
    "\u0445": "x",  # Cyrillic 'х'
    "\u0456": "i",  # Cyrillic 'і'
    "\u04bb": "h",  # Cyrillic 'һ'
    "\u0455": "s",  # Cyrillic 'ѕ'
}

# Deceptive path keywords indicating credential theft or verification lures
DECEPTIVE_PATH_KEYWORDS = {
    "login", "signin", "kyc", "pan", "verify", "verification",
    "netbanking", "update-kyc", "bill-pay", "claim-reward",
    "refund", "unblock", "restore", "security-check", "authenticate",
    "portal", "secure", "access", "activate", "claim", "auth",
}

# Payment path keywords
PAYMENT_PATH_KEYWORDS = {
    "pay", "upi", "collect", "refund", "reward", "cashback", "subsidy",
    "claim", "bill", "recharge", "disburse", "settle",
}

# Urgency keywords in path or query
URGENCY_TOKENS = {
    "urgent", "immediate", "block", "freeze", "suspend", "cutoff", "expire",
    "penalty", "action-required", "notice", "alert",
}


def is_authoritative_domain(hostname: str) -> bool:
    """Check if hostname belongs to an authoritative legitimate or government domain."""
    h = hostname.lower().strip()
    # Check official brand whitelist
    if any(h == d or h.endswith(f".{d}") for d in LEGITIMATE_BRAND_DOMAINS):
        return True
    # Check authoritative global platforms
    if any(h == d or h.endswith(f".{d}") for d in AUTHORITATIVE_GLOBAL_DOMAINS):
        return True
    # Check official Indian government domains
    if h.endswith(".gov.in") or h.endswith(".nic.in") or h.endswith(".ac.in"):
        return True
    return False


def extract_urls(text: str) -> List[str]:
    """Extract all distinct URLs and domain references from raw text."""
    if not text:
        return []
    matches = RE_URL.findall(text)
    seen = set()
    cleaned = []
    for m in matches:
        u = m.strip().rstrip(".,;!?'\"`)]}>")
        if u and u not in seen:
            seen.add(u)
            cleaned.append(u)

    # If no URL matched via RE_URL, check if single-token input is a URL or unsafe scheme
    stripped_text = text.strip()
    if not cleaned and " " not in stripped_text and (":" in stripped_text or "." in stripped_text):
        lower_s = stripped_text.lower()
        if lower_s.startswith(("http://", "https://", "javascript:", "data:", "file:", "vbscript:", "blob:")) or (
            re.match(r"^[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}(?:/[^\s]*)?$", stripped_text)
        ):
            cleaned.append(stripped_text)

    return cleaned


def has_homoglyphs(domain: str) -> Tuple[bool, str]:
    """Check if domain contains non-ASCII homoglyph characters mimicking Latin letters."""
    has_sub = False
    normalized = []
    for ch in domain:
        if ch in HOMOGLYPH_MAP:
            has_sub = True
            normalized.append(HOMOGLYPH_MAP[ch])
        else:
            normalized.append(ch)
    return has_sub, "".join(normalized)


def detect_brand_context_mismatch(context_text: str, hostname: str, raw_url: str) -> Optional[Indicator]:
    """Detect discrepancies between claimed organizational context and actual destination domain.

    Example:
    Message text references "LPG subsidy" or "State Bank of India",
    but destination domain is "random-claim-portal.xyz".
    """
    if is_authoritative_domain(hostname):
        return None

    clean_context = f"{context_text} {raw_url}".lower()

    for context_name, spec in CLAIMED_CONTEXT_MAP.items():
        # Check if context keywords appear in the message or URL
        has_context_cue = any(kw in clean_context for kw in spec["keywords"])
        if has_context_cue:
            # Check if actual destination domain is authorized for this organization
            is_valid_dest = any(
                hostname == vd or hostname.endswith(f".{vd}") or (hostname.endswith(".gov.in") and "gov.in" in vd)
                for vd in spec["valid_domains"]
            )
            if not is_valid_dest:
                entity_label = spec["entity_name"]
                return Indicator(
                    id="IND_BRAND_DOMAIN_MISMATCH",
                    name=f"Brand/Institutional Context Mismatch ({context_name})",
                    description=(
                        f"The communication claims or implies association with '{entity_label}', "
                        f"but links to destination '{hostname}', which does NOT belong to the official organization."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Claimed context: {context_name} -> Actual destination: {hostname}",
                    why_it_matters=(
                        f"Scammers frequently impersonate trusted institutions like {entity_label} "
                        "while directing users to look-alike or unofficial external websites to capture banking or personal details."
                    ),
                    attacker_objective=f"Deceive victim into believing this is an official {entity_label} portal to extract credentials or funds.",
                    attack_stage="Deception Layer",
                )

    return None


def inspect_url_deep(raw_url: str, context_text: Optional[str] = None) -> List[Indicator]:
    """Perform comprehensive local deep heuristic inspection of a URL.

    Evaluates structural, lexical, behavioral, and brand-impersonation indicators.
    Returns a list of structured Indicator objects.
    """
    indicators: List[Indicator] = []
    lower_raw = raw_url.strip().lower()

    # 0. Protocol Scheme Inspection (Immediate rejection of dangerous schemes)
    for scheme in ("javascript:", "data:", "file:", "vbscript:", "blob:"):
        if lower_raw.startswith(scheme):
            indicators.append(Indicator(
                id="IND_URL_UNSAFE_SCHEME",
                name="Disallowed Dangerous Protocol Scheme",
                description=f"URL uses dangerous non-web URI protocol scheme '{scheme}'.",
                severity=Severity.CRITICAL,
                evidence=raw_url,
                why_it_matters="Protocols like javascript:, data:, and file: are weaponized by attackers for cross-site scripting (XSS), arbitrary script execution, and local file access.",
                attacker_objective="Execute arbitrary script code or exploit client-side vulnerabilities in the victim's browser.",
                attack_stage="Payload Action",
            ))
            return indicators

    normalized_url = raw_url if raw_url.lower().startswith(("http://", "https://")) else f"https://{raw_url}"

    try:
        parsed = urlparse(normalized_url)
        hostname = (parsed.hostname or "").lower().strip()
        path = (parsed.path or "").lower()
        query = (parsed.query or "").lower()
        port = parsed.port
        scheme = (parsed.scheme or "").lower()
    except Exception:
        hostname = raw_url.lower()
        path = ""
        query = ""
        port = None
        scheme = "http"

    # If domain is authoritative, run minimal sanity checks and return
    is_authoritative = is_authoritative_domain(hostname)

    # 1. URL Obfuscation: Embedded credentials with '@'
    if "@" in normalized_url.split("/")[2] if len(normalized_url.split("/")) > 2 else False:
        indicators.append(Indicator(
            id="IND_URL_OBFUSCATION",
            name="URL Userinfo Authentication Deception",
            description="Uses an '@' symbol in the URL to display a trusted brand name while routing traffic to an attacker destination.",
            severity=Severity.HIGH,
            evidence=raw_url,
            why_it_matters="Browsers interpret everything before the '@' as authentication credentials, tricking victims into believing they are navigating to a legitimate site.",
            attacker_objective="Bypass human visual scrutiny and trick victim into navigating to an unvetted malicious domain.",
            attack_stage="Deception Layer",
        ))

    # 2. Numeric IP Host
    is_ip = False
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        indicators.append(Indicator(
            id="IND_URL_IP_HOST",
            name="Direct Numeric IP Hostname",
            description="Uses a raw numerical IP host instead of a registered domain name.",
            severity=Severity.CRITICAL,
            evidence=raw_url,
            why_it_matters="Legitimate institutions and services always use official registered domains. Raw IPs are used by scammers to deploy transient phishing servers that evade domain reputation checks.",
            attacker_objective="Host transient phishing portals that bypass DNS-based domain reputation and takedown systems.",
            attack_stage="Exploitation Vector",
        ))
        return indicators

    # 3. URL Shortener Service
    if hostname in URL_SHORTENERS:
        indicators.append(Indicator(
            id="IND_URL_SHORTENER",
            finding_id="SHORTENER_001",
            type="destination_obfuscation",
            source="deterministic_heuristic",
            confidence="HIGH",
            name="URL Shortening / Destination Obfuscation",
            description=f"Destination utilizes a link shortener ({hostname}) which obfuscates the final destination.",
            severity=Severity.MEDIUM,
            evidence=raw_url,
            why_it_matters="Shortened links conceal the ultimate destination. The true destination was not resolved and cannot be confirmed safe without out-of-band verification.",
            attacker_objective="Conceal final destination domain until link is clicked.",
            attack_stage="Inbound Lure",
        ))

    # 4. Homoglyph / Punycode Look-alike Character Detection
    if hostname.startswith("xn--"):
        indicators.append(Indicator(
            id="IND_URL_PUNYCODE",
            name="Internationalized Domain Name (Punycode)",
            description=f"Domain '{hostname}' uses Punycode encoding, often used to disguise look-alike counterfeit domains.",
            severity=Severity.HIGH,
            evidence=raw_url,
            why_it_matters="Punycode encoding allows attackers to visually register counterfeit domain names that look identical to genuine sites in browser address bars.",
            attacker_objective="Execute homograph spoofing attacks against unsuspecting users.",
            attack_stage="Deception Layer",
        ))
    else:
        homoglyph_detected, normalized_domain = has_homoglyphs(hostname)
        if homoglyph_detected:
            indicators.append(Indicator(
                id="IND_URL_HOMOGLYPH",
                name="Homoglyph Domain Impersonation",
                description=f"Domain '{hostname}' contains look-alike international characters mimicking legitimate domain '{normalized_domain}'.",
                severity=Severity.HIGH,
                evidence=raw_url,
                why_it_matters="Homograph attacks use look-alike Unicode characters (e.g. Cyrillic letters) to visually fake official institutional domains.",
                attacker_objective="Conceal phishing infrastructure by spoofing visual appearance of authentic domain names.",
                attack_stage="Deception Layer",
            ))

    # 5. High-Risk / Suspicious TLD
    matched_tld = None
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            matched_tld = tld
            break

    if matched_tld and not is_authoritative:
        indicators.append(Indicator(
            id="IND_URL_SUSPICIOUS_TLD",
            name="High-Abuse Non-Standard TLD",
            description=f"Destination uses top-level domain '{matched_tld}' associated with elevated spam and phishing abuse.",
            severity=Severity.HIGH,
            evidence=raw_url,
            why_it_matters="High-abuse TLDs are frequently chosen by scammers due to cheap registration and lack of strict registrar verification.",
            attacker_objective="Acquire low-cost, disposable domains for temporary phishing campaigns.",
            attack_stage="Exploitation Vector",
        ))

    # 6. Structural & Subdomain Heuristics
    host_parts = hostname.split(".")
    # Excessive subdomains (e.g. sbi.verify.account.update.fake.com)
    if len(host_parts) > 3 and not is_authoritative:
        indicators.append(Indicator(
            id="IND_URL_EXCESSIVE_SUBDOMAINS",
            name="Excessive Subdomain Stacking",
            description=f"Hostname contains {len(host_parts)-1} subdomain levels, typical of phishing infrastructure cloaking.",
            severity=Severity.MEDIUM,
            evidence=hostname,
            why_it_matters="Scammers nest multiple subdomains to mimic genuine URLs on mobile screens where the full domain name is truncated.",
            attacker_objective="Create visual illusion of legitimacy on narrow mobile displays.",
            attack_stage="Deception Layer",
        ))

    # Subdomain brand deception (e.g. sbi.co.in.attacker-host.com)
    if not is_authoritative and len(host_parts) >= 3:
        subdomain_part = ".".join(host_parts[:-2])
        for kw in INDIAN_BRAND_KEYWORDS:
            if kw in subdomain_part:
                indicators.append(Indicator(
                    id="IND_URL_SUBDOMAIN_DECEPTION",
                    name="Subdomain Brand Spoofing",
                    description=f"Subdomain '{subdomain_part}' embeds brand '{kw.upper()}' to mislead users away from actual root domain '{'.'.join(host_parts[-2:])}'.",
                    severity=Severity.HIGH,
                    evidence=hostname,
                    why_it_matters="Attackers place genuine bank or brand names in the subdomain of an attacker-owned domain to deceive victims.",
                    attacker_objective="Trick user into believing they are on an official portal while controlling the host.",
                    attack_stage="Deception Layer",
                ))
                break

    # Excessive URL length
    if len(raw_url) > 120 and not is_authoritative:
        indicators.append(Indicator(
            id="IND_URL_EXCESSIVE_LENGTH",
            name="Abnormally Long URL Structure",
            description=f"URL length ({len(raw_url)} characters) exceeds typical navigation norms, frequently used to obscure malicious parameters.",
            severity=Severity.LOW,
            evidence=f"{len(raw_url)} chars",
            why_it_matters="Phishing kits use padded parameters and long tokens to push the real destination off-screen.",
            attacker_objective="Conceal tracking parameters or deceive link inspectors.",
            attack_stage="Inbound Lure",
        ))

    # 7. Non-standard port
    if port is not None and port not in (80, 443) and not is_authoritative:
        indicators.append(Indicator(
            id="IND_URL_SUSPICIOUS_PORT",
            name="Non-Standard Network Port Destination",
            description=f"URL targets non-standard network port :{port} instead of standard web ports (80/443).",
            severity=Severity.HIGH,
            evidence=f"Port :{port}",
            why_it_matters="Standard institutional web services operate on ports 80 and 443. Non-standard ports frequently host rogue web servers or proxy tunnels.",
            attacker_objective="Bypass security gateways or connect to rogue staging servers.",
            attack_stage="Exploitation Vector",
        ))

    # 8. Embedded URL in Path or Query (Open Redirect / Cloaking)
    if ("http://" in path or "https://" in path or "http://" in query or "https://" in query) and not is_authoritative:
        indicators.append(Indicator(
            id="IND_URL_EMBEDDED_TARGET",
            name="Embedded URL Target Redirection",
            description="URL contains an embedded second URL inside its path or query string, indicating potential open redirect exploitation.",
            severity=Severity.MEDIUM,
            evidence=raw_url,
            why_it_matters="Open redirects are used to bounce victims through a trusted domain before delivering them to a malicious phishing page.",
            attacker_objective="Cloak the final phishing destination behind an intermediary redirector.",
            attack_stage="Deception Layer",
        ))

    # 9. Encoding Anomalies
    if ("%25" in raw_url or "%2f" in raw_url.lower() or "%40" in raw_url.lower()) and not is_authoritative:
        indicators.append(Indicator(
            id="IND_URL_ENCODING_ANOMALY",
            name="Suspicious Percent-Encoding Obfuscation",
            description="URL utilizes unusual percent-encoding (such as double encoding or encoded delimiters) to disguise content.",
            severity=Severity.MEDIUM,
            evidence=raw_url,
            why_it_matters="Encoding characters like '/' or '@' as hex escapes is a classic filter-evasion technique.",
            attacker_objective="Bypass Web Application Firewalls (WAFs) and automated threat filters.",
            attack_stage="Exploitation Vector",
        ))

    # 10. Malicious APK Download Vector
    if path.endswith(".apk") or ".apk?" in normalized_url or ("/download" in path and "apk" in normalized_url):
        indicators.append(Indicator(
            id="IND_MALICIOUS_APK",
            name="Malicious Android APK Application Payload",
            description="URL directs user to download a direct Android APK application file.",
            severity=Severity.CRITICAL,
            evidence=raw_url,
            why_it_matters="Official institutions distribute mobile apps exclusively via Google Play or Apple App Store. Direct APK downloads are a primary vector for banking trojans and SMS-forwarding malware.",
            attacker_objective="Install remote access trojan (RAT) or SMS forwarder to intercept OTPs and compromise banking apps.",
            attack_stage="Payload Action",
        ))

    # 11. Deceptive Credential Harvesting Path
    if not is_authoritative:
        for kw in DECEPTIVE_PATH_KEYWORDS:
            if kw in path:
                indicators.append(Indicator(
                    id="IND_URL_DECEPTIVE_PATH",
                    name="Credential Harvesting Path Vector",
                    description=f"URL path segment '{path}' targets sensitive authentication action '{kw.upper()}'.",
                    severity=Severity.HIGH,
                    evidence=raw_url,
                    why_it_matters="Attacker links direct victims directly to fake login, verification, or KYC update forms designed to extract secrets.",
                    attacker_objective="Harvest user credentials, payment details, or identification documents.",
                    attack_stage="Payload Action",
                ))
                break

    # 12. Payment & Financial Lure Path
    if not is_authoritative:
        for kw in PAYMENT_PATH_KEYWORDS:
            if kw in path:
                indicators.append(Indicator(
                    id="IND_URL_PAYMENT_PATH",
                    name="Financial Action / Payment Lure Vector",
                    description=f"URL path segment '{path}' solicits sensitive financial action '{kw.upper()}'.",
                    severity=Severity.MEDIUM,
                    evidence=raw_url,
                    why_it_matters="Phishing lures frequently prompt users to process urgent refunds, subsidies, or rewards through unverified portals.",
                    attacker_objective="Solicit unauthorized UPI payments, card details, or banking PINs.",
                    attack_stage="Payload Action",
                ))
                break

    # 13. Urgency Tokens in Path or Query
    if not is_authoritative:
        for token in URGENCY_TOKENS:
            if token in path or token in query:
                indicators.append(Indicator(
                    id="IND_URL_URGENCY_LURE",
                    name="Urgency Coercion in Link Target",
                    description=f"URL incorporates psychological urgency token '{token.upper()}' to rush the victim.",
                    severity=Severity.MEDIUM,
                    evidence=token,
                    why_it_matters="Creating synthetic panic (e.g. 'immediate', 'suspend') reduces critical evaluation and accelerates victim compliance.",
                    attacker_objective="Impel the victim to bypass rational verification before taking action.",
                    attack_stage="Urgency Coercion",
                ))
                break

    # 14. Insecure HTTP on Sensitive Action
    if scheme == "http" and not is_authoritative:
        has_sensitive_action = any(
            ind.id in ("IND_URL_DECEPTIVE_PATH", "IND_URL_PAYMENT_PATH") for ind in indicators
        )
        if has_sensitive_action:
            indicators.append(Indicator(
                id="IND_URL_INSECURE_HTTP",
                name="Insecure Plaintext HTTP Protocol for Sensitive Actions",
                description="URL requests credentials or financial actions over unencrypted HTTP.",
                severity=Severity.HIGH,
                evidence="http://",
                why_it_matters="Legitimate financial institutions never solicit credentials or payments over unencrypted HTTP.",
                attacker_objective="Transmit unencrypted data to disposable or intercepted infrastructure.",
                attack_stage="Exploitation Vector",
            ))

    # 15. Brand Name in Domain (Counterfeit brand look-alike domain)
    has_brand_in_domain = False
    if not is_authoritative:
        for kw in INDIAN_BRAND_KEYWORDS:
            brand_in_hostname = (
                f"-{kw}" in hostname
                or f"{kw}-" in hostname
                or f".{kw}." in hostname
                or hostname.startswith(f"{kw}.")
                or (kw in hostname and len(hostname.split(".")) > 1 and kw == hostname.split(".")[0])
                or (len(kw) >= 4 and kw in hostname)
            )
            if brand_in_hostname:
                has_brand_in_domain = True
                indicators.append(Indicator(
                    id="IND_URL_BRAND_IMPERSONATION",
                    name="Brand Impersonation in Domain Name",
                    description=f"Domain '{hostname}' incorporates trusted brand name '{kw.upper()}' without authorized domain ownership.",
                    severity=Severity.HIGH,
                    evidence=raw_url,
                    why_it_matters="Threat actors register counterfeit look-alike domains using bank and service names to trick victims into believing the link is official.",
                    attacker_objective="Deceive victim into submitting sensitive credentials, OTPs, or financial details on a clone website.",
                    attack_stage="Deception Layer",
                ))
                break

    # 16. Brand & Context Impersonation Check (Claimed Message Context vs Actual Destination)
    if context_text and not is_authoritative:
        mismatch_ind = detect_brand_context_mismatch(context_text, hostname, raw_url)
        if mismatch_ind:
            indicators.append(mismatch_ind)

    # 17. Unverified Destination Reputation (CORE PRINCIPLE: Unknown != Safe)
    # If the domain is NOT an authoritative institution and has no other indicators,
    # it must receive an unverified destination status so it can NEVER be classified as SAFE.
    if not is_authoritative and not indicators:
        indicators.append(Indicator(
            id="IND_URL_UNVERIFIED_DESTINATION",
            name="Unverified Destination Domain",
            description=f"Domain '{hostname}' is not a recognized or verified institutional domain.",
            severity=Severity.LOW,
            evidence=hostname,
            why_it_matters="New, obscure, or unverified domains have no established reputation. Absence from public blocklists does not guarantee safety.",
            attacker_objective="Host unmonitored content away from established reputation watchdogs.",
            attack_stage="Inbound Lure",
        ))

    return indicators


def analyze_url_deep(raw_url: str, context_text: Optional[str] = None) -> List[dict]:
    """Inspect URL and return structured dictionary findings for diagnostics and testing."""
    indicators = inspect_url_deep(raw_url, context_text)
    return [
        {
            "rule_id": ind.id,
            "name": ind.name,
            "description": ind.description,
            "severity": ind.severity.value,
            "evidence": ind.evidence,
            "why_it_matters": ind.why_it_matters,
            "attacker_objective": ind.attacker_objective,
            "attack_stage": ind.attack_stage,
        }
        for ind in indicators
    ]
