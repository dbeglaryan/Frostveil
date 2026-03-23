"""Tests for session hijack analysis."""
import json
import pytest
from modules.session_hijack import (
    analyze_sessions, _is_session_cookie, _is_csrf_token,
    _looks_like_jwt, _decode_jwt, _identify_service, _calculate_risk,
)


class TestSessionCookieDetection:
    def test_known_cookie(self):
        assert _is_session_cookie("JSESSIONID", "abc123", "example.com") is True

    def test_session_in_name(self):
        assert _is_session_cookie("my_session_id", "value", "example.com") is True

    def test_auth_token(self):
        assert _is_session_cookie("auth_token", "xyz", "example.com") is True

    def test_normal_cookie(self):
        assert _is_session_cookie("theme", "dark", "example.com") is False

    def test_long_random_value(self):
        assert _is_session_cookie("x", "a" * 40, "example.com") is True


class TestCSRFDetection:
    def test_csrf_token(self):
        assert _is_csrf_token("csrftoken") is True
        assert _is_csrf_token("_xsrf") is True

    def test_not_csrf(self):
        assert _is_csrf_token("session") is False


class TestJWTHandling:
    def test_looks_like_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.rAwNkQEPTx8FEcMlIEhpqI6PeyKJt9IAUEM3brV_aMs"
        assert _looks_like_jwt(jwt) is True

    def test_not_jwt(self):
        assert _looks_like_jwt("not.a.jwt") is False
        assert _looks_like_jwt("") is False

    def test_decode_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QifQ.invalid"
        result = _decode_jwt(jwt)
        assert result is not None
        assert result["header"]["alg"] == "HS256"
        assert result["payload"]["sub"] == "1234567890"


class TestServiceIdentification:
    def test_google(self):
        assert _identify_service(".google.com", "SID") == "Google"

    def test_github(self):
        assert _identify_service("github.com", "session") == "GitHub"

    def test_unknown(self):
        result = _identify_service("mysite.example.org", "sid")
        assert result is not None  # Should extract domain name


class TestRiskCalculation:
    def test_high_value_active(self):
        risk = _calculate_risk("JSESSIONID", "abc123", True, True, "Strict", False, None)
        assert risk > 30

    def test_missing_all_flags(self):
        risk = _calculate_risk("session", "abc123", False, False, "None", False, None)
        assert risk > 30

    def test_expired_lower_risk(self):
        risk_active = _calculate_risk("token", "x", True, True, "Strict", False, None)
        risk_expired = _calculate_risk("token", "x", True, True, "Strict", True, None)
        assert risk_active > risk_expired


class TestAnalyzeSessions:
    def test_empty(self):
        result = analyze_sessions([])
        assert result["total_sessions"] == 0

    def test_with_session_cookies(self):
        rows = [
            {
                "artifact": "cookie",
                "browser": "chrome",
                "url": ".google.com",
                "title": "SID",
                "extra": json.dumps({
                    "value": "session_value_here",
                    "secure": True,
                    "httponly": True,
                    "samesite": "Lax",
                    "expires": None,
                }),
                "visit_time_utc": "2025-01-01T00:00:00",
            },
            {
                "artifact": "cookie",
                "browser": "chrome",
                "url": "github.com",
                "title": "user_session",
                "extra": json.dumps({
                    "value": "gh_session_abc123",
                    "secure": False,
                    "httponly": False,
                    "samesite": "unset",
                    "expires": None,
                }),
                "visit_time_utc": "2025-01-01T00:00:00",
            },
        ]
        result = analyze_sessions(rows)
        assert result["total_sessions"] >= 2
        assert result["security_issues"] > 0  # GitHub cookie missing flags

    def test_non_cookie_artifacts_ignored(self):
        rows = [
            {"artifact": "history", "browser": "chrome", "url": "https://google.com",
             "title": "", "extra": "", "visit_time_utc": None},
        ]
        result = analyze_sessions(rows)
        assert result["total_sessions"] == 0
