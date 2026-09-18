"""Input abuse and stress testing suite for ScamShield AI validation engine (Phase 8 QA)."""

import pytest

from backend.src.detection.engine import detect_threat_signals
from backend.src.utils.errors import EmptyInputError, PayloadTooLargeError, RequestValidationError
from backend.src.validation.request import validate_analysis_request


class TestInputAbuseAndFuzzing:
    """Stress testing input parser with boundary attacks, fuzzing strings, and control characters."""

    def test_null_byte_in_message_handled_cleanly(self):
        null_byte_payload = "Dear customer\x00your account is blocked"
        req = validate_analysis_request({"message": null_byte_payload})
        assert req.message == null_byte_payload
        det = detect_threat_signals(req.message)
        assert det is not None

    def test_control_characters_and_escapes(self):
        control_chars = "\r\n\t\b\f\vSpecial warning: OTP required"
        req = validate_analysis_request({"message": control_chars})
        assert "OTP required" in req.message
        det = detect_threat_signals(req.message)
        assert det is not None

    def test_unicode_homoglyphs_and_mixed_scripts(self):
        # Cyrillic letters looking like Latin: 'а' (Cyrillic U+0430) vs 'a'
        homoglyph_msg = "Updаte your bаnk KYC immediately"
        req = validate_analysis_request({"message": homoglyph_msg})
        assert req.message == homoglyph_msg
        det = detect_threat_signals(req.message)
        assert det is not None

    def test_extreme_repeated_characters_boundary_stress(self):
        # 4,000 continuous repeated characters without spaces
        repeated = "A" * 4000
        req = validate_analysis_request({"message": repeated})
        assert len(req.message) == 4000
        det = detect_threat_signals(req.message)
        assert det is not None
        assert det.is_benign is True

    def test_deeply_nested_or_non_dict_json_payloads(self):
        with pytest.raises(RequestValidationError):
            validate_analysis_request("[1, 2, 3, 4]")

        with pytest.raises(RequestValidationError):
            validate_analysis_request("12345")