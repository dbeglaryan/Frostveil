"""
Frostveil Password Auditor — entropy analysis, strength scoring,
pattern detection, and breach correlation for extracted credentials.

Implements:
- Shannon entropy calculation
- Pattern detection (keyboard walks, sequences, repeats, dates)
- Password strength scoring (0-100)
- Credential reuse matrix
- Common password detection
- Password age analysis
"""
import math, re, json, collections, hashlib
from datetime import datetime
from . import utils

# Common weak passwords (top 100 from breach databases)
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
    "letmein", "trustno1", "dragon", "baseball", "iloveyou", "master", "sunshine",
    "ashley", "bailey", "passw0rd", "shadow", "123123", "654321", "superman",
    "qazwsx", "michael", "football", "password1", "password123", "welcome",
    "jesus", "ninja", "mustang", "password1!", "admin", "admin123", "root",
    "toor", "pass", "test", "guest", "master", "changeme", "fuckyou",
    "hello", "charlie", "donald", "passwd", "1234", "12345", "123456789",
    "1234567890", "0987654321", "qwerty123", "1q2w3e4r", "zaq1xsw2",
    "q1w2e3r4", "1qaz2wsx", "login", "starwars", "solo", "princess",
    "azerty", "000000", "111111", "121212", "131313", "aaaaaa", "access",
    "flower", "hottie", "loveme", "pepper", "robert", "samantha", "soccer",
    "summer", "thomas", "trustno", "12341234", "abcdef", "hockey", "ranger",
    "daniel", "hannah", "harley", "hunter", "jordan", "killer", "george",
    "matthew", "andrew", "jennifer", "joshua", "jessica", "olivia", "sophia",
    "P@ssw0rd", "P@ssword1", "Welcome1", "Passw0rd!", "Admin123!",
}

# Keyboard walk patterns
KEYBOARD_ROWS = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1234567890", "!@#$%^&*()",
]

def analyze_all(rows: list) -> dict:
    """Run full password audit on credential artifacts."""
    cred_rows = [r for r in rows if r.get("artifact") == "credential"]
    if not cred_rows:
        return {"total_analyzed": 0}

    results = []
    password_hashes = collections.defaultdict(list)  # hash → list of sites
    username_passwords = collections.defaultdict(list)  # user → passwords

    for r in cred_rows:
        extra = _parse_extra(r.get("extra", ""))
        password = extra.get("password", "")
        username = r.get("title", "")
        url = r.get("url", "")

        if not password or password.startswith("<"):
            continue

        analysis = analyze_password(password)
        analysis["url"] = url
        analysis["username"] = username
        analysis["timestamp"] = r.get("visit_time_utc")
        results.append(analysis)

        # Track reuse
        pwd_hash = hashlib.sha256(password.encode()).hexdigest()[:16]
        password_hashes[pwd_hash].append(url)
        username_passwords[username].append({"url": url, "strength": analysis["score"]})

    # Reuse analysis
    reused = {h: urls for h, urls in password_hashes.items() if len(urls) > 1}

    # Strength distribution
    scores = [r["score"] for r in results]
    strength_dist = {
        "critical": sum(1 for s in scores if s < 20),
        "weak": sum(1 for s in scores if 20 <= s < 40),
        "fair": sum(1 for s in scores if 40 <= s < 60),
        "good": sum(1 for s in scores if 60 <= s < 80),
        "strong": sum(1 for s in scores if s >= 80),
    }

    # Weakest passwords
    weakest = sorted(results, key=lambda r: r["score"])[:10]

    return {
        "total_analyzed": len(results),
        "average_score": round(sum(scores) / max(len(scores), 1), 1),
        "strength_distribution": strength_dist,
        "reused_passwords": len(reused),
        "reuse_details": {h: urls for h, urls in list(reused.items())[:10]},
        "common_passwords_found": sum(1 for r in results if r.get("is_common")),
        "weakest_passwords": [{
            "url": w["url"],
            "username": w["username"],
            "score": w["score"],
            "issues": w["issues"],
        } for w in weakest],
        "all_results": results,
    }

def analyze_password(password: str) -> dict:
    """Analyze a single password and return detailed assessment."""
    if not password:
        return {"score": 0, "issues": ["empty"], "entropy": 0}

    score = 0
    issues = []
    bonuses = []

    # Length scoring (most important factor)
    length = len(password)
    if length >= 16:
        score += 30
        bonuses.append("long(16+)")
    elif length >= 12:
        score += 25
    elif length >= 8:
        score += 15
    elif length >= 6:
        score += 8
    else:
        issues.append(f"very_short({length})")

    # Character class diversity
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[^a-zA-Z0-9]', password))

    classes = sum([has_lower, has_upper, has_digit, has_special])
    score += classes * 8
    if classes < 2:
        issues.append("single_char_class")
    if classes >= 4:
        bonuses.append("all_char_classes")

    # Entropy
    entropy = _shannon_entropy(password)
    if entropy >= 4.0:
        score += 15
        bonuses.append(f"high_entropy({entropy:.1f})")
    elif entropy >= 3.0:
        score += 8
    elif entropy < 2.0:
        score -= 10
        issues.append(f"low_entropy({entropy:.1f})")

    # Common password check
    is_common = password.lower() in COMMON_PASSWORDS
    if is_common:
        score -= 40
        issues.append("common_password")

    # Pattern detection
    patterns = _detect_patterns(password)
    for pattern in patterns:
        score -= pattern["penalty"]
        issues.append(pattern["type"])

    # Keyboard walk detection
    if _is_keyboard_walk(password):
        score -= 15
        issues.append("keyboard_walk")

    # Date pattern detection
    if re.search(r'(19|20)\d{2}', password) or re.search(r'\d{2}/\d{2}/\d{2,4}', password):
        score -= 5
        issues.append("contains_date")

    # Leet speak substitution (weak obfuscation)
    leet_map = {"@": "a", "3": "e", "1": "i", "0": "o", "$": "s", "!": "i"}
    deleet = password.lower()
    for l, r in leet_map.items():
        deleet = deleet.replace(l, r)
    if deleet in COMMON_PASSWORDS:
        score -= 25
        issues.append("leet_of_common")

    score = max(0, min(100, score))

    return {
        "score": score,
        "strength": _score_to_strength(score),
        "entropy": round(entropy, 2),
        "length": length,
        "char_classes": classes,
        "issues": issues,
        "bonuses": bonuses,
        "is_common": is_common,
    }

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = collections.Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())

def _detect_patterns(password: str) -> list:
    patterns = []
    lower = password.lower()

    # Repeated characters (aaa, 111)
    repeats = re.findall(r'(.)\1{2,}', lower)
    if repeats:
        patterns.append({"type": f"repeated_chars({''.join(repeats)})", "penalty": 8})

    # Sequential numbers (123, 321)
    for i in range(len(lower) - 2):
        if lower[i:i+3].isdigit():
            a, b, c = int(lower[i]), int(lower[i+1]), int(lower[i+2])
            if b - a == 1 and c - b == 1:
                patterns.append({"type": "sequential_numbers", "penalty": 10})
                break
            if a - b == 1 and b - c == 1:
                patterns.append({"type": "reverse_sequential", "penalty": 10})
                break

    # Sequential letters (abc, cba)
    for i in range(len(lower) - 2):
        if lower[i:i+3].isalpha():
            a, b, c = ord(lower[i]), ord(lower[i+1]), ord(lower[i+2])
            if b - a == 1 and c - b == 1:
                patterns.append({"type": "sequential_letters", "penalty": 8})
                break

    # Mirror/palindrome
    if len(lower) >= 6 and lower == lower[::-1]:
        patterns.append({"type": "palindrome", "penalty": 10})

    return patterns

def _is_keyboard_walk(password: str) -> bool:
    """Detect keyboard walk patterns (qwerty, asdf, zxcv)."""
    lower = password.lower()
    if len(lower) < 4:
        return False
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - 3):
            if row[i:i+4] in lower:
                return True
            if row[i:i+4][::-1] in lower:
                return True
    return False

def _score_to_strength(score: int) -> str:
    if score >= 80: return "STRONG"
    if score >= 60: return "GOOD"
    if score >= 40: return "FAIR"
    if score >= 20: return "WEAK"
    return "CRITICAL"

def _parse_extra(extra_str: str) -> dict:
    try:
        return json.loads(extra_str) if extra_str else {}
    except Exception:
        return {}
