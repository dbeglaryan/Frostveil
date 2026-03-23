"""Tests for password auditing — entropy, strength, patterns."""
import pytest
from modules.password_audit import (
    analyze_password, _shannon_entropy, _detect_patterns,
    _is_keyboard_walk, _score_to_strength, analyze_all,
)


class TestShannonEntropy:
    def test_empty(self):
        assert _shannon_entropy("") == 0.0

    def test_single_char(self):
        assert _shannon_entropy("aaaa") == 0.0

    def test_two_chars(self):
        e = _shannon_entropy("ab")
        assert 0.9 < e < 1.1  # Should be ~1.0

    def test_high_entropy(self):
        e = _shannon_entropy("aB3$xY9!kL")
        assert e > 3.0

    def test_low_entropy(self):
        e = _shannon_entropy("aaabbb")
        assert e < 1.5


class TestPasswordAnalysis:
    def test_empty_password(self):
        result = analyze_password("")
        assert result["score"] == 0
        assert "empty" in result["issues"]

    def test_common_password(self):
        result = analyze_password("password")
        assert result["is_common"] is True
        assert result["score"] < 20

    def test_strong_password(self):
        result = analyze_password("X7$mK9!pL2@nW4&q")
        assert result["score"] >= 60
        assert result["strength"] in ("GOOD", "STRONG")

    def test_very_short(self):
        result = analyze_password("abc")
        assert "very_short(3)" in result["issues"]

    def test_single_char_class(self):
        result = analyze_password("abcdefghij")
        assert "single_char_class" in result["issues"]

    def test_all_char_classes(self):
        result = analyze_password("aB3$efgh")
        assert "all_char_classes" in result["bonuses"]

    def test_leet_speak_detection(self):
        result = analyze_password("p@ssw0rd")
        assert "leet_of_common" in result["issues"]

    def test_date_detection(self):
        result = analyze_password("pass2024word")
        assert "contains_date" in result["issues"]

    def test_score_clamped(self):
        result = analyze_password("a")
        assert result["score"] >= 0
        result = analyze_password("X7$mK9!pL2@nW4&qR8#jT5%vB1*cF6^")
        assert result["score"] <= 100


class TestKeyboardWalk:
    def test_qwerty(self):
        assert _is_keyboard_walk("qwerty") is True

    def test_asdf(self):
        assert _is_keyboard_walk("asdf") is True

    def test_reverse_walk(self):
        assert _is_keyboard_walk("rewq") is True

    def test_not_walk(self):
        assert _is_keyboard_walk("xkcd") is False

    def test_short_string(self):
        assert _is_keyboard_walk("ab") is False


class TestPatternDetection:
    def test_repeated_chars(self):
        patterns = _detect_patterns("aaabbb")
        types = [p["type"] for p in patterns]
        assert any("repeated_chars" in t for t in types)

    def test_sequential_numbers(self):
        patterns = _detect_patterns("pass123word")
        types = [p["type"] for p in patterns]
        assert "sequential_numbers" in types

    def test_palindrome(self):
        patterns = _detect_patterns("abccba")
        types = [p["type"] for p in patterns]
        assert "palindrome" in types

    def test_no_patterns(self):
        patterns = _detect_patterns("X7mK9pL2")
        assert len(patterns) == 0


class TestScoreToStrength:
    def test_critical(self):
        assert _score_to_strength(10) == "CRITICAL"

    def test_weak(self):
        assert _score_to_strength(30) == "WEAK"

    def test_fair(self):
        assert _score_to_strength(50) == "FAIR"

    def test_good(self):
        assert _score_to_strength(70) == "GOOD"

    def test_strong(self):
        assert _score_to_strength(90) == "STRONG"


class TestAnalyzeAll:
    def test_empty_rows(self):
        result = analyze_all([])
        assert result["total_analyzed"] == 0

    def test_non_credential_rows(self):
        rows = [{"artifact": "history", "url": "https://example.com"}]
        result = analyze_all(rows)
        assert result["total_analyzed"] == 0

    def test_with_credentials(self):
        import json
        rows = [
            {
                "artifact": "credential",
                "title": "user@test.com",
                "url": "https://example.com",
                "extra": json.dumps({"password": "password123"}),
                "visit_time_utc": None,
            },
            {
                "artifact": "credential",
                "title": "admin@test.com",
                "url": "https://other.com",
                "extra": json.dumps({"password": "X7$mK9!pL2@nW4&q"}),
                "visit_time_utc": None,
            },
        ]
        result = analyze_all(rows)
        assert result["total_analyzed"] == 2
        assert "strength_distribution" in result
        assert "weakest_passwords" in result
