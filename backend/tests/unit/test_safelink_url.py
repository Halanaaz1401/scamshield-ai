"""Unit tests for Safe Link Gateway URL Intelligence and Security Enforcements."""

import pytest
from backend.src.detection.url_intelligence import (
    extract_urls,
    inspect_url_deep,
    has_homoglyphs,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
)
from backend.src.detection.engine import detect_threat_signals
from backend.src.models.response import ScamCategory, Severity


class TestSafeLinkUrlIntelligence:
    """Test suite for URL intelligence detection rules and threat indicators."""

    def test_extract_urls_various_formats(self):
        """Verify extraction handles standard HTTPS, HTTP, and bare domain URLs."""
        text = "Visit https://sbi-login.xyz/portal and also http://insecure-link.top for details."
        urls = extract_urls(text)
        assert len(urls) == 2
        assert "https://sbi-login.xyz/portal" in urls
        assert "http://insecure-link.top" in urls

    def test_extract_urls_single_token_bare_domain(self):
        """Verify single bare domain without scheme is extracted cleanly."""
        text = "electricity-update.xyz/pay"
        urls = extract_urls(text)
        assert len(urls) == 1
        assert urls[0] == "electricity-update.xyz/pay"

    def test_unsafe_scheme_javascript_flagged(self):
        """Verify javascript: scheme is flagged with CRITICAL severity indicator."""
        indicators = inspect_url_deep("javascript:alert(1)")
        assert len(indicators) == 1
        assert indicators[0].id == "IND_URL_UNSAFE_SCHEME"
        assert indicators[0].severity == Severity.CRITICAL
        assert "javascript:" in indicators[0].description

    def test_unsafe_scheme_data_flagged(self):
        """Verify data: scheme is flagged as unsafe protocol."""
        indicators = inspect_url_deep("data:text/html,<script>alert(1)</script>")
        assert len(indicators) == 1
        assert indicators[0].id == "IND_URL_UNSAFE_SCHEME"
        assert indicators[0].severity == Severity.CRITICAL

    def test_unsafe_scheme_file_flagged(self):
        """Verify file: scheme is flagged as unsafe protocol."""
        indicators = inspect_url_deep("file:///etc/passwd")
        assert len(indicators) == 1
        assert indicators[0].id == "IND_URL_UNSAFE_SCHEME"
        assert indicators[0].severity == Severity.CRITICAL

    def test_suspicious_tld_detection(self):
        """Verify high-abuse TLDs like .xyz and .top trigger indicators."""
        indicators = inspect_url_deep("https://random-service.xyz/account")
        assert any(ind.id == "IND_URL_SUSPICIOUS_TLD" for ind in indicators)

    def test_brand_impersonation_sbi(self):
        """Verify counterfeit SBI domains trigger brand impersonation."""
        indicators = inspect_url_deep("https://sbi-kyc-verification.xyz/login")
        brand_ind = next((ind for ind in indicators if ind.id == "IND_URL_BRAND_IMPERSONATION"), None)
        assert brand_ind is not None
        assert "SBI" in brand_ind.description

    def test_brand_impersonation_hdfc(self):
        """Verify counterfeit HDFC domains trigger brand impersonation."""
        indicators = inspect_url_deep("https://hdfc-reward-points.top/claim")
        brand_ind = next((ind for ind in indicators if ind.id == "IND_URL_BRAND_IMPERSONATION"), None)
        assert brand_ind is not None
        assert "HDFC" in brand_ind.description

    def test_ip_hostname_detection(self):
        """Verify direct numerical IP hosts are flagged as CRITICAL risk."""
        indicators = inspect_url_deep("http://192.168.1.100/banking/login")
        ip_ind = next((ind for ind in indicators if ind.id == "IND_URL_IP_HOST"), None)
        assert ip_ind is not None
        assert ip_ind.severity == Severity.CRITICAL

    def test_url_shortener_detection(self):
        """Verify link shorteners like bit.ly trigger cloaking warnings."""
        indicators = inspect_url_deep("https://bit.ly/urgent-bill-pay")
        short_ind = next((ind for ind in indicators if ind.id == "IND_URL_SHORTENER"), None)
        assert short_ind is not None
        assert short_ind.severity == Severity.MEDIUM

    def test_embedded_credentials_obfuscation(self):
        """Verify @ userinfo trick is detected."""
        indicators = inspect_url_deep("https://onlinesbi.sbi@evil-attacker.xyz/login")
        obf_ind = next((ind for ind in indicators if ind.id == "IND_URL_OBFUSCATION"), None)
        assert obf_ind is not None
        assert obf_ind.severity == Severity.HIGH

    def test_deceptive_path_detection(self):
        """Verify sensitive paths like /kyc, /verify, /login on untrusted domains trigger indicators."""
        indicators = inspect_url_deep("https://service-update.xyz/kyc")
        path_ind = next((ind for ind in indicators if ind.id == "IND_URL_DECEPTIVE_PATH"), None)
        assert path_ind is not None

    def test_malicious_apk_download_path(self):
        """Verify direct APK download paths trigger CRITICAL severity."""
        indicators = inspect_url_deep("https://utility-bill.xyz/download/support.apk")
        apk_ind = next((ind for ind in indicators if ind.id == "IND_MALICIOUS_APK"), None)
        assert apk_ind is not None
        assert apk_ind.severity == Severity.CRITICAL

    def test_homoglyph_cyrillic_spoofing(self):
        """Verify cyrillic look-alike character substitution is caught."""
        # \u0430 is Cyrillic 'а' replacing Latin 'a'
        has_sub, norm = has_homoglyphs("p\u0430ytm.com")
        assert has_sub is True
        assert norm == "paytm.com"

        indicators = inspect_url_deep("http://p\u0430ytm.com/login")
        homo_ind = next((ind for ind in indicators if ind.id == "IND_URL_HOMOGLYPH"), None)
        assert homo_ind is not None

    def test_legitimate_bank_domains_not_flagged(self):
        """Verify authoritative bank root domains do not trigger brand impersonation or deceptive path."""
        indicators = inspect_url_deep("https://www.onlinesbi.sbi")
        assert not any(ind.id == "IND_URL_BRAND_IMPERSONATION" for ind in indicators)
        assert not any(ind.id == "IND_URL_SUSPICIOUS_TLD" for ind in indicators)

        hdfc_ind = inspect_url_deep("https://netbanking.hdfcbank.com/netbanking")
        assert not any(ind.id == "IND_URL_BRAND_IMPERSONATION" for ind in hdfc_ind)

    def test_detect_threat_signals_integration(self):
        """Verify detect_threat_signals processes Safe Link URL input end-to-end."""
        res = detect_threat_signals("https://sbi-verify-login-example.xyz/login", source_type="url")
        assert res.is_benign is False
        assert res.deterministic_score >= 60.0
        assert res.signal_count >= 2
        assert res.primary_category in (ScamCategory.BANKING_SCAM, ScamCategory.PHISHING)
