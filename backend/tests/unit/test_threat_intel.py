"""Unit tests for Google Web Risk threat intelligence lookup service & SSRF protection."""

import json
from unittest.mock import MagicMock, patch
import urllib.error
import pytest

from backend.src.security.url_security import (
    is_ip_restricted,
    validate_url_for_safe_fetch,
    BANNED_METADATA_HOSTS,
)
from backend.src.services.threat_intel_service import (
    ThreatIntelligenceService,
    ThreatIntelResult,
    check_url_threat_intel,
    threat_intel_to_indicator,
)
from backend.src.models.response import Severity


class TestUrlSecurityAndSsrfDefense:
    """Test suite verifying SSRF prevention and safe URL validation."""

    def test_restricted_loopback_ips(self):
        """Loopback addresses must be flagged as restricted."""
        assert is_ip_restricted("127.0.0.1") is True
        assert is_ip_restricted("127.0.1.5") is True
        assert is_ip_restricted("::1") is True

    def test_restricted_rfc1918_private_ips(self):
        """Private network IPs must be flagged as restricted."""
        assert is_ip_restricted("10.0.0.1") is True
        assert is_ip_restricted("172.16.5.2") is True
        assert is_ip_restricted("192.168.1.1") is True

    def test_restricted_cloud_metadata_ips(self):
        """AWS/GCP/Azure link-local metadata IP must be strictly restricted."""
        assert is_ip_restricted("169.254.169.254") is True
        assert is_ip_restricted("169.254.1.1") is True

    def test_public_ips_allowed(self):
        """Standard public IPs should not be flagged as restricted."""
        assert is_ip_restricted("8.8.8.8") is False
        assert is_ip_restricted("1.1.1.1") is False
        assert is_ip_restricted("142.250.190.46") is False

    def test_ssrf_blocks_localhost_and_metadata(self):
        """URL validator must block localhost, cloud metadata, and private IP targets."""
        is_safe, _, err = validate_url_for_safe_fetch("http://169.254.169.254/latest/meta-data/")
        assert is_safe is False
        assert "forbidden" in err.lower() or "ssrf" in err.lower()

        is_safe, _, err = validate_url_for_safe_fetch("http://localhost:8080/admin")
        assert is_safe is False

        is_safe, _, err = validate_url_for_safe_fetch("http://metadata.google.internal/computeMetadata/v1/")
        assert is_safe is False

        is_safe, _, err = validate_url_for_safe_fetch("http://192.168.1.1/router")
        assert is_safe is False

    def test_ssrf_blocks_unsafe_protocol_schemes(self):
        """Dangerous URI schemes must be blocked from network fetch."""
        is_safe, _, err = validate_url_for_safe_fetch("javascript:alert(1)")
        assert is_safe is False
        assert "dangerous" in err.lower()

        is_safe, _, err = validate_url_for_safe_fetch("file:///etc/passwd")
        assert is_safe is False

        is_safe, _, err = validate_url_for_safe_fetch("data:text/html,<script>")
        assert is_safe is False

    def test_ssrf_blocks_userinfo_credentials(self):
        """URLs containing @ userinfo must be rejected for outbound fetch."""
        is_safe, _, err = validate_url_for_safe_fetch("https://admin:pass@google.com/test")
        assert is_safe is False
        assert "userinfo" in err.lower()

    def test_valid_public_urls_accepted(self):
        """Legitimate public HTTP and HTTPS URLs must pass validation."""
        is_safe, norm, err = validate_url_for_safe_fetch("https://sbi.co.in/portal")
        assert is_safe is True
        assert norm == "https://sbi.co.in/portal"
        assert err is None


class TestThreatIntelligenceService:
    """Test suite for Google Web Risk Lookup API integration."""

    def test_unconfigured_api_key_returns_unverified_gracefully(self):
        """When API key is not configured, service must return unverified without raising errors."""
        svc = ThreatIntelligenceService(api_key="")
        result = svc.lookup_url("https://unknown-suspicious-domain.xyz/login")
        assert result.status == "unverified"
        assert result.is_known_malicious is False
        assert result.provider == "google_web_risk"

    @patch("urllib.request.urlopen")
    def test_positive_malicious_threat_response(self, mock_urlopen):
        """When Web Risk returns a threat match, service parses threat types correctly."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps({
            "threat": {
                "threatTypes": ["SOCIAL_ENGINEERING", "MALWARE"],
                "expireTime": "2026-09-18T12:00:00Z",
            }
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        svc = ThreatIntelligenceService(api_key="AIzaSyDummyKey12345")
        result = svc.lookup_url("https://confirmed-phishing-portal.com/login")

        assert result.status == "malicious"
        assert result.is_known_malicious is True
        assert "SOCIAL_ENGINEERING" in result.threat_types
        assert "MALWARE" in result.threat_types

        # Convert to Indicator
        ind = threat_intel_to_indicator(result, "https://confirmed-phishing-portal.com/login")
        assert ind is not None
        assert ind.id == "IND_THREAT_INTEL_MALICIOUS"
        assert ind.severity == Severity.CRITICAL
        assert "SOCIAL_ENGINEERING" in ind.name

    @patch("urllib.request.urlopen")
    def test_clean_response_reports_no_threat(self, mock_urlopen):
        """When Web Risk finds no record, service returns no_threat_reported (NOT safe)."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps({}).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        svc = ThreatIntelligenceService(api_key="AIzaSyDummyKey12345")
        result = svc.lookup_url("https://some-untracked-arbitrary-site.org/page")

        assert result.status == "no_threat_reported"
        assert result.is_known_malicious is False
        assert result.threat_types == []
        assert threat_intel_to_indicator(result, "https://some-untracked-arbitrary-site.org/page") is None

    @patch("urllib.request.urlopen")
    def test_http_error_handled_safely(self, mock_urlopen):
        """HTTP error from Google API must be handled gracefully without exception."""
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://webrisk.googleapis.com",
            code=403,
            msg="Forbidden",
            hdrs={},
            fp=None,
        )

        svc = ThreatIntelligenceService(api_key="AIzaSyDummyKey12345")
        result = svc.lookup_url("https://example.com")
        assert result.status == "error"
        assert result.is_known_malicious is False

    @patch("urllib.request.urlopen")
    def test_network_timeout_handled_safely(self, mock_urlopen):
        """Network timeout during API lookup must degrade to error status without hanging."""
        mock_urlopen.side_effect = TimeoutError("Connection timed out")

        svc = ThreatIntelligenceService(api_key="AIzaSyDummyKey12345")
        result = svc.lookup_url("https://example.com")
        assert result.status == "error"
        assert result.is_known_malicious is False
