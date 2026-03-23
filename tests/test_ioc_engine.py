"""Tests for IOC/threat intelligence engine — DGA, homoglyphs, typosquatting."""
import pytest
from modules.ioc_engine import (
    scan_url, _is_dga_domain, _detect_homoglyphs, _detect_typosquat,
)


class TestDGADetection:
    def test_normal_domain(self):
        is_dga, score, reason = _is_dga_domain("google.com")
        assert is_dga is False

    def test_normal_domain_with_words(self):
        is_dga, score, reason = _is_dga_domain("stackoverflow.com")
        assert is_dga is False

    def test_dga_random(self):
        # High entropy, high consonant ratio, unusual bigrams
        is_dga, score, reason = _is_dga_domain("qxzjvbnjmkpt.com")
        assert is_dga is True

    def test_dga_long_random(self):
        is_dga, score, reason = _is_dga_domain("qxzwvbnjmk.net")
        assert is_dga is True

    def test_short_domain(self):
        # Too short for DGA detection
        is_dga, score, reason = _is_dga_domain("ab.com")
        assert is_dga is False


class TestHomoglyphDetection:
    def test_clean_domain(self):
        # Use a domain with no characters that appear in the homoglyph fake lists
        result = _detect_homoglyphs("amazon.com")
        assert result == []

    def test_homoglyph_detected(self):
        # 'l' is listed as a homoglyph lookalike for 'i'
        result = _detect_homoglyphs("google.com")
        assert len(result) > 0


class TestTyposquatting:
    def test_exact_match(self):
        result = _detect_typosquat("google.com")
        # Exact match should not flag
        assert result == []

    def test_typosquat_google(self):
        result = _detect_typosquat("gooogle.com")
        assert len(result) > 0

    def test_unrelated_domain(self):
        result = _detect_typosquat("mycooldomain.com")
        # Very different from any major domain
        assert result == []


class TestURLScanning:
    def test_clean_url(self):
        # google.com is in the whitelist — use bare domain so netloc matches exactly
        result = scan_url("https://google.com/search?q=python")
        assert result == []

    def test_suspicious_ip_url(self):
        result = scan_url("http://192.168.1.100/login.php")
        assert len(result) > 0

    def test_data_uri(self):
        result = scan_url("data:text/html;base64,PHNjcmlwdD4=")
        assert len(result) > 0

    def test_empty_url(self):
        result = scan_url("")
        assert result == []
