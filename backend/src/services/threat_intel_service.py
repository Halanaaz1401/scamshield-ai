"""Google Web Risk Lookup API integration for ScamShield AI.

Provides real-time external threat intelligence lookup for arbitrary URLs,
identifying known malware, social engineering, and unwanted software distributions.
"""

import json
import logging
import os
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional

from backend.src.models.response import Indicator, Severity
from backend.src.security.url_security import validate_url_for_safe_fetch

logger = logging.getLogger("scamshield.threat_intel")

# Supported Google Web Risk threat types
SUPPORTED_THREAT_TYPES = [
    "SOCIAL_ENGINEERING",
    "MALWARE",
    "UNWANTED_SOFTWARE",
]

DEFAULT_TIMEOUT_SECONDS = 3.0


@dataclass(frozen=True)
class ThreatIntelResult:
    """Structured result of an external threat intelligence lookup."""

    status: str  # "malicious", "no_threat_reported", "unverified", "error"
    is_known_malicious: bool
    threat_types: List[str] = field(default_factory=list)
    provider: str = "google_web_risk"
    details: str = ""
    error_message: Optional[str] = None


class ThreatIntelligenceService:
    """Service client for external threat intelligence reputation feeds."""

    def __init__(self, api_key: Optional[str] = None, timeout: float = DEFAULT_TIMEOUT_SECONDS):
        self.api_key = api_key or os.environ.get("GOOGLE_WEB_RISK_API_KEY", "").strip()
        self.timeout = timeout

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    def lookup_url(self, raw_url: str) -> ThreatIntelResult:
        """Query Google Web Risk API for reputation status of a target URL.

        Note: An empty threat result does NOT imply the URL is safe. It merely
        indicates absence from the threat database at the time of query.
        """
        # 1. Check if API key is configured
        if not self.is_configured:
            return ThreatIntelResult(
                status="unverified",
                is_known_malicious=False,
                threat_types=[],
                provider="google_web_risk",
                details="External threat intelligence unconfigured; reputation unverified.",
            )

        # 2. Validate URL and SSRF safety
        is_safe, normalized_url, error = validate_url_for_safe_fetch(raw_url)
        if not is_safe or not normalized_url:
            return ThreatIntelResult(
                status="error",
                is_known_malicious=False,
                threat_types=[],
                provider="google_web_risk",
                details=f"URL validation failed: {error}",
                error_message=error,
            )

        # 3. Construct Google Web Risk Lookup request
        base_endpoint = "https://webrisk.googleapis.com/v1/uris:search"
        query_params = [
            ("key", self.api_key),
            ("uri", normalized_url),
        ]
        for tt in SUPPORTED_THREAT_TYPES:
            query_params.append(("threatTypes", tt))

        full_query = urllib.parse.urlencode(query_params)
        request_url = f"{base_endpoint}?{full_query}"

        # 4. Dispatch HTTP request with strict timeout
        req = urllib.request.Request(
            request_url,
            headers={
                "Accept": "application/json",
                "User-Agent": "ScamShield-AI/1.0",
            },
            method="GET",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                if response.status != 200:
                    return ThreatIntelResult(
                        status="error",
                        is_known_malicious=False,
                        threat_types=[],
                        provider="google_web_risk",
                        details=f"Threat intelligence API returned HTTP {response.status}",
                        error_message=f"HTTP {response.status}",
                    )

                body = response.read().decode("utf-8", errors="replace")
                data = json.loads(body) if body else {}

                threat_data = data.get("threat")
                if threat_data and isinstance(threat_data, dict):
                    raw_types = threat_data.get("threatTypes", [])
                    return ThreatIntelResult(
                        status="malicious",
                        is_known_malicious=True,
                        threat_types=raw_types,
                        provider="google_web_risk",
                        details=f"Threat intelligence match: {', '.join(raw_types)}",
                    )
                else:
                    # Clean/No match in database
                    return ThreatIntelResult(
                        status="no_threat_reported",
                        is_known_malicious=False,
                        threat_types=[],
                        provider="google_web_risk",
                        details="No threat record found in Google Web Risk database.",
                    )

        except urllib.error.HTTPError as exc:
            logger.warning(f"Web Risk API HTTP error: {exc.code} {exc.reason}")
            return ThreatIntelResult(
                status="error",
                is_known_malicious=False,
                threat_types=[],
                provider="google_web_risk",
                details=f"Threat intelligence query error (HTTP {exc.code})",
                error_message=str(exc),
            )
        except urllib.error.URLError as exc:
            logger.warning(f"Web Risk API connection error: {exc.reason}")
            return ThreatIntelResult(
                status="error",
                is_known_malicious=False,
                threat_types=[],
                provider="google_web_risk",
                details="Threat intelligence connection unavailable; unverified status.",
                error_message=str(exc),
            )
        except Exception as exc:
            logger.warning(f"Unexpected error querying Web Risk API: {exc}")
            return ThreatIntelResult(
                status="error",
                is_known_malicious=False,
                threat_types=[],
                provider="google_web_risk",
                details="Threat intelligence error encountered during evaluation.",
                error_message=str(exc),
            )


# Global singleton service
default_threat_intel_service = ThreatIntelligenceService()


def check_url_threat_intel(url: str, service: Optional[ThreatIntelligenceService] = None) -> ThreatIntelResult:
    """Convenience helper to check a URL against external threat intelligence."""
    svc = service or default_threat_intel_service
    return svc.lookup_url(url)


def threat_intel_to_indicator(result: ThreatIntelResult, raw_url: str) -> Optional[Indicator]:
    """Convert a positive threat intelligence finding into a structured Indicator object."""
    if not result.is_known_malicious:
        return None

    threat_names = ", ".join(result.threat_types) if result.threat_types else "MALICIOUS"
    return Indicator(
        id="IND_THREAT_INTEL_MALICIOUS",
        name=f"Confirmed Threat Database Match ({threat_names})",
        description=f"External threat intelligence feed verified this destination as an active threat ({threat_names}).",
        severity=Severity.CRITICAL,
        evidence=raw_url,
        why_it_matters="Confirmed threat intelligence entries indicate verified active malicious campaigns, phishing kits, or malware payloads.",
        attacker_objective="Compromise user device, steal financial credentials, or execute social engineering exploits.",
        attack_stage="Exploitation Vector",
    )
