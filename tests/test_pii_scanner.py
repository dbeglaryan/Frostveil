"""Tests for PII/sensitive data scanner — credit cards, API keys, secrets."""
import json
import pytest
from modules.pii_scanner import scan_all, _luhn_check


class TestLuhnValidation:
    def test_valid_visa(self):
        assert _luhn_check("4111111111111111") is True

    def test_valid_mastercard(self):
        assert _luhn_check("5500000000000004") is True

    def test_valid_amex(self):
        assert _luhn_check("340000000000009") is True

    def test_invalid_number(self):
        assert _luhn_check("4111111111111112") is False

    def test_too_short(self):
        assert _luhn_check("411111") is False

    def test_non_digits(self):
        assert _luhn_check("abcdefghijklm") is False


class TestPIIScanner:
    def _make_rows(self, *values):
        """Helper to create artifact rows with given URLs/extras."""
        rows = []
        for val in values:
            rows.append({
                "artifact": "history",
                "browser": "chrome",
                "url": val,
                "title": "",
                "extra": "",
                "visit_time_utc": None,
            })
        return rows

    def test_empty_scan(self):
        result = scan_all([])
        assert result["total_findings"] == 0

    def test_no_pii_in_normal_urls(self):
        rows = self._make_rows(
            "https://google.com",
            "https://github.com/user/repo",
            "https://stackoverflow.com/questions/12345",
        )
        result = scan_all(rows)
        # Should not find critical PII in normal URLs
        assert len(result.get("critical_findings", [])) == 0

    def test_detect_aws_key(self):
        rows = [{
            "artifact": "localstorage",
            "browser": "chrome",
            "url": "https://console.aws.amazon.com",
            "title": "aws_config",
            "extra": json.dumps({"value": "AKIAIOSFODNN7EXAMPLE"}),
            "visit_time_utc": None,
        }]
        result = scan_all(rows)
        aws_findings = [f for f in result["findings"] if "aws" in f["pattern"]]
        assert len(aws_findings) > 0

    def test_detect_github_token(self):
        rows = [{
            "artifact": "localstorage",
            "browser": "chrome",
            "url": "https://github.com",
            "title": "token",
            "extra": json.dumps({"value": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"}),
            "visit_time_utc": None,
        }]
        result = scan_all(rows)
        gh_findings = [f for f in result["findings"] if "github" in f["pattern"]]
        assert len(gh_findings) > 0

    def test_detect_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        rows = [{
            "artifact": "cookie",
            "browser": "chrome",
            "url": "example.com",
            "title": "auth_token",
            "extra": json.dumps({"value": jwt}),
            "visit_time_utc": None,
        }]
        result = scan_all(rows)
        jwt_findings = [f for f in result["findings"] if "jwt" in f["pattern"]]
        assert len(jwt_findings) > 0

    def test_credit_card_detection(self):
        rows = [{
            "artifact": "autofill",
            "browser": "chrome",
            "url": "",
            "title": "card",
            "extra": json.dumps({"value": "4111-1111-1111-1111"}),
            "visit_time_utc": None,
        }]
        result = scan_all(rows)
        cc_findings = [f for f in result["findings"] if "credit_card" in f["pattern"]]
        assert len(cc_findings) > 0

    def test_invalid_credit_card_rejected(self):
        rows = [{
            "artifact": "autofill",
            "browser": "chrome",
            "url": "",
            "title": "card",
            "extra": json.dumps({"value": "4111-1111-1111-1112"}),
            "visit_time_utc": None,
        }]
        result = scan_all(rows)
        cc_findings = [f for f in result["findings"] if "credit_card" in f["pattern"]]
        assert len(cc_findings) == 0

    def test_severity_distribution(self):
        rows = [{
            "artifact": "localstorage",
            "browser": "chrome",
            "url": "https://example.com",
            "title": "config",
            "extra": json.dumps({"value": "AKIAIOSFODNN7EXAMPLE rk_test_abcdef1234567890abcdef1"}),
            "visit_time_utc": None,
        }]
        result = scan_all(rows)
        assert "severity_distribution" in result
        dist = result["severity_distribution"]
        assert all(k in dist for k in ["critical", "high", "medium", "low"])
