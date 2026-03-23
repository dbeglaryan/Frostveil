"""Tests for cloud account enumeration."""
import json
import pytest
from modules.cloud_accounts import enumerate_accounts, _is_valid_email, _is_jwt


class TestEmailValidation:
    def test_valid_email(self):
        assert _is_valid_email("user@example.org") is True

    def test_invalid_short(self):
        assert _is_valid_email("a@b") is False

    def test_false_positive_domains(self):
        assert _is_valid_email("test@example.com") is False
        assert _is_valid_email("user@localhost") is False

    def test_spaces(self):
        assert _is_valid_email("user @domain.com") is False


class TestJWTDetection:
    def test_valid_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        assert _is_jwt(jwt) is True

    def test_not_jwt(self):
        assert _is_jwt("not.a.jwt") is False
        assert _is_jwt("hello world") is False
        assert _is_jwt("") is False


class TestAccountEnumeration:
    def test_empty(self):
        result = enumerate_accounts([])
        assert result["total_accounts"] == 0
        assert result["total_emails"] == 0

    def test_google_cookie(self):
        rows = [{
            "artifact": "cookie",
            "browser": "chrome",
            "url": ".google.com",
            "title": "SID",
            "extra": json.dumps({"value": "some_session_value", "secure": True, "httponly": True}),
            "visit_time_utc": "2025-01-01T00:00:00",
        }]
        result = enumerate_accounts(rows)
        assert result["total_accounts"] > 0
        services = [a["service"] for a in result["accounts"]]
        assert "Google" in services

    def test_github_cookie(self):
        rows = [{
            "artifact": "cookie",
            "browser": "chrome",
            "url": "github.com",
            "title": "logged_in",
            "extra": json.dumps({"value": "yes"}),
            "visit_time_utc": "2025-01-01T00:00:00",
        }]
        result = enumerate_accounts(rows)
        services = [a["service"] for a in result["accounts"]]
        assert "GitHub" in services

    def test_credential_extraction(self):
        rows = [{
            "artifact": "credential",
            "browser": "chrome",
            "url": "https://github.com/login",
            "title": "user@gmail.com",
            "extra": json.dumps({"password": "secret123"}),
            "visit_time_utc": "2025-01-01T00:00:00",
        }]
        result = enumerate_accounts(rows)
        assert "user@gmail.com" in result["all_emails"]

    def test_sync_account(self):
        rows = [{
            "artifact": "preference",
            "browser": "chrome",
            "url": "user@gmail.com",
            "title": "sync_account",
            "extra": "",
            "visit_time_utc": None,
        }]
        result = enumerate_accounts(rows)
        assert "user@gmail.com" in result["all_emails"]
        assert result["total_accounts"] > 0
