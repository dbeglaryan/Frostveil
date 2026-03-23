"""
Frostveil IOC Engine — Indicators of Compromise detection, threat scoring,
and anomaly detection for browser forensics.

Implements:
- Known-malicious URL pattern matching (regex-based threat intel)
- Suspicious domain entropy analysis (DGA detection)
- Behavioral anomaly detection (unusual browsing patterns)
- Extension threat scoring (dangerous permissions)
- Data exfiltration heuristics
- Phishing domain detection (homoglyph/typosquatting)
"""
import re, math, json, collections
from datetime import datetime, timedelta
from urllib.parse import urlparse
from . import utils

# ---------------------------------------------------------------------------
# Threat Intelligence — URL/domain pattern matching
# ---------------------------------------------------------------------------

# Known suspicious URL patterns (extensible)
SUSPICIOUS_PATTERNS = [
    # Credential phishing
    (r"(?i)(login|signin|account|verify|secure|update|confirm|password|banking)"
     r".*\.(tk|ml|ga|cf|gq|xyz|top|pw|cc|ws|buzz)", "phishing_tld", 85),
    # Data exfiltration endpoints
    (r"(?i)(pastebin|paste\.ee|hastebin|ghostbin|rentry|dpaste|ix\.io)", "paste_site", 60),
    (r"(?i)(file\.io|transfer\.sh|wetransfer|gofile|anonfiles|bayfiles)", "file_sharing", 55),
    # C2/RAT indicators
    (r"(?i)(ngrok\.io|serveo\.net|localhost\.run|bore\.digital)", "tunnel_service", 75),
    (r"(?i)(webhook\.site|requestbin|pipedream|hookbin)", "webhook_exfil", 70),
    (r"(?i)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?/", "raw_ip_access", 65),
    # Crypto mining
    (r"(?i)(coinhive|cryptoloot|minero|webminer|coin-hive)", "cryptominer", 90),
    # Known exploit kit patterns
    (r"(?i)(exploit|payload|shell|reverse|bind|meterpreter|cobalt)", "exploit_keyword", 50),
    # Suspicious downloads
    (r"(?i)\.(exe|scr|bat|cmd|ps1|vbs|wsf|hta|msi|dll)\b", "suspicious_download", 70),
    (r"(?i)(base64|eval|document\.write|unescape|fromCharCode)", "obfuscation", 55),
    # Dark web / Tor
    (r"(?i)\.onion(/|$)", "tor_hidden_service", 80),
    # Encoded/obfuscated URLs
    (r"%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}", "heavy_encoding", 45),
]

# Dangerous extension permissions
DANGEROUS_PERMISSIONS = {
    "debugger": 95,
    "nativeMessaging": 90,
    "proxy": 85,
    "webRequestBlocking": 85,
    "webRequest": 75,
    "cookies": 70,
    "clipboardRead": 65,
    "clipboardWrite": 60,
    "downloads": 55,
    "management": 80,
    "privacy": 70,
    "tabs": 40,
    "history": 50,
    "bookmarks": 30,
    "<all_urls>": 80,
    "http://*/*": 70,
    "https://*/*": 70,
    "*://*/*": 85,
    "file:///*": 90,
}

# Top legitimate domains (reduced false positives)
WHITELIST_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
    "twitter.com", "instagram.com", "linkedin.com", "reddit.com", "github.com",
    "microsoft.com", "apple.com", "stackoverflow.com", "netflix.com", "yahoo.com",
    "bing.com", "mozilla.org", "cloudflare.com", "googleapis.com", "gstatic.com",
    "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
}

# ---------------------------------------------------------------------------
# DGA Detection — Shannon entropy + character distribution analysis
# ---------------------------------------------------------------------------

def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = collections.Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())

def _consonant_ratio(s: str) -> float:
    """Ratio of consonants to total alphabetic characters."""
    alpha = [c for c in s.lower() if c.isalpha()]
    if not alpha:
        return 0.0
    vowels = set("aeiou")
    consonants = sum(1 for c in alpha if c not in vowels)
    return consonants / len(alpha)

def _digit_ratio(s: str) -> float:
    """Ratio of digits to total characters."""
    if not s:
        return 0.0
    return sum(1 for c in s if c.isdigit()) / len(s)

def _is_dga_domain(domain: str) -> tuple:
    """
    Detect Domain Generation Algorithm (DGA) generated domains.
    Returns (is_dga: bool, confidence: float, reason: str).

    Uses multi-factor analysis:
    1. Shannon entropy (DGA domains typically >3.5)
    2. Consonant clustering (natural language has ~60% consonants, DGA has ~70%+)
    3. Digit mixing (DGA often mixes digits into domain labels)
    4. N-gram analysis (DGA produces unusual bigrams)
    """
    # Extract registrable domain (strip TLD)
    parts = domain.split(".")
    if len(parts) < 2:
        return False, 0.0, ""
    label = parts[0]  # Primary label
    if len(label) < 6:
        return False, 0.0, "too_short"

    entropy = _shannon_entropy(label)
    cons_ratio = _consonant_ratio(label)
    dig_ratio = _digit_ratio(label)

    score = 0.0
    reasons = []

    if entropy > 3.8:
        score += 35
        reasons.append(f"high_entropy({entropy:.2f})")
    elif entropy > 3.5:
        score += 20
        reasons.append(f"elevated_entropy({entropy:.2f})")

    if cons_ratio > 0.75:
        score += 25
        reasons.append(f"consonant_heavy({cons_ratio:.2f})")

    if dig_ratio > 0.3:
        score += 20
        reasons.append(f"digit_mixed({dig_ratio:.2f})")

    if len(label) > 15:
        score += 10
        reasons.append(f"long_label({len(label)})")

    # Check for unusual bigrams
    unusual_bigrams = {"qx", "xq", "zx", "jq", "qj", "xz", "zj", "vq", "qv"}
    label_lower = label.lower()
    bigrams = {label_lower[i:i+2] for i in range(len(label_lower)-1)}
    unusual_count = len(bigrams & unusual_bigrams)
    if unusual_count > 0:
        score += 15 * unusual_count
        reasons.append(f"unusual_bigrams({unusual_count})")

    return score >= 50, score, "+".join(reasons)

# ---------------------------------------------------------------------------
# Homoglyph / Typosquatting detection
# ---------------------------------------------------------------------------

HOMOGLYPHS = {
    "a": ["а", "ɑ", "α"],  # Cyrillic a, Latin alpha, Greek alpha
    "e": ["е", "ε", "ё"],
    "o": ["о", "ο", "0"],
    "c": ["с", "ϲ"],
    "p": ["р", "ρ"],
    "i": ["і", "ι", "1", "l"],
    "d": ["ԁ", "ɗ"],
    "g": ["ɡ", "ǥ"],
    "n": ["ɴ", "η"],
    "s": ["ѕ", "ꜱ"],
    "t": ["τ", "ţ"],
    "x": ["х", "χ"],
    "y": ["у", "γ"],
}

def _detect_homoglyphs(domain: str) -> list:
    """Detect homoglyph characters in domain that could indicate phishing."""
    findings = []
    for char in domain:
        for real_char, fakes in HOMOGLYPHS.items():
            if char in fakes:
                findings.append(f"homoglyph '{char}' looks like '{real_char}'")
    return findings

TOP_DOMAINS_FOR_TYPOSQUAT = [
    "google", "facebook", "amazon", "microsoft", "apple", "paypal",
    "netflix", "instagram", "twitter", "linkedin", "github", "yahoo",
    "outlook", "dropbox", "chase", "wellsfargo", "bankofamerica",
]

def _detect_typosquat(domain: str) -> list:
    """Detect possible typosquatting of popular domains."""
    findings = []
    label = domain.split(".")[0].lower()
    for target in TOP_DOMAINS_FOR_TYPOSQUAT:
        if label == target:
            continue
        dist = _levenshtein(label, target)
        if 1 <= dist <= 2:
            findings.append(f"possible typosquat of '{target}' (edit_distance={dist})")
    return findings

def _levenshtein(s1: str, s2: str) -> int:
    """Levenshtein edit distance."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]

# ---------------------------------------------------------------------------
# Behavioral anomaly detection
# ---------------------------------------------------------------------------

def _detect_time_anomalies(rows: list) -> list:
    """
    Detect unusual time-based patterns:
    - Burst activity (many visits in short window)
    - Unusual hours (2-5 AM local time)
    - Time gaps followed by mass activity
    """
    findings = []
    timestamps = []
    for r in rows:
        ts = r.get("visit_time_utc")
        if ts:
            try:
                timestamps.append(datetime.fromisoformat(ts.replace("Z", "")))
            except Exception:
                pass

    if len(timestamps) < 10:
        return findings

    timestamps.sort()

    # Detect bursts: >50 events in 60 seconds
    for i in range(len(timestamps) - 50):
        window = (timestamps[i + 50] - timestamps[i]).total_seconds()
        if window < 60:
            findings.append({
                "type": "burst_activity",
                "severity": 75,
                "timestamp": timestamps[i].isoformat(),
                "detail": f"{50}+ events in {window:.1f}s — possible automated browsing or scraping"
            })
            break  # One finding per type

    # Detect unusual hour activity (2-5 AM)
    night_activity = [ts for ts in timestamps if 2 <= ts.hour <= 4]
    if len(night_activity) > 20:
        findings.append({
            "type": "night_activity",
            "severity": 40,
            "timestamp": night_activity[0].isoformat(),
            "detail": f"{len(night_activity)} browsing events between 2-5 AM"
        })

    return findings

def _detect_exfil_patterns(rows: list) -> list:
    """
    Detect potential data exfiltration patterns:
    - Large numbers of visits to file-sharing/paste sites
    - Sequential access to internal resources followed by external uploads
    - Unusual download patterns
    """
    findings = []
    exfil_domains = collections.Counter()
    for r in rows:
        url = r.get("url", "")
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
        except Exception:
            continue
        for pattern, category, _ in SUSPICIOUS_PATTERNS:
            if category in ("paste_site", "file_sharing", "webhook_exfil"):
                if re.search(pattern, url):
                    exfil_domains[domain] += 1

    for domain, count in exfil_domains.most_common(10):
        if count >= 3:
            findings.append({
                "type": "data_exfiltration",
                "severity": min(90, 50 + count * 5),
                "detail": f"{count} visits to potential exfil endpoint: {domain}"
            })
    return findings

# ---------------------------------------------------------------------------
# Main analysis functions
# ---------------------------------------------------------------------------

def scan_url(url: str) -> list:
    """
    Scan a single URL against all threat intelligence rules.
    Returns list of findings with severity scores.
    """
    findings = []
    if not url:
        return findings

    # Pattern matching
    for pattern, category, severity in SUSPICIOUS_PATTERNS:
        if re.search(pattern, url):
            findings.append({
                "type": category,
                "severity": severity,
                "url": url[:200],
            })

    # Domain analysis
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().split(":")[0]  # Strip port
        if domain and domain not in WHITELIST_DOMAINS:
            # DGA detection
            is_dga, score, reason = _is_dga_domain(domain)
            if is_dga:
                findings.append({
                    "type": "dga_domain",
                    "severity": min(95, int(score)),
                    "url": url[:200],
                    "detail": f"Possible DGA domain: {reason}"
                })

            # Homoglyph detection
            homoglyphs = _detect_homoglyphs(domain)
            if homoglyphs:
                findings.append({
                    "type": "homoglyph_phishing",
                    "severity": 90,
                    "url": url[:200],
                    "detail": "; ".join(homoglyphs)
                })

            # Typosquatting
            typosquats = _detect_typosquat(domain)
            if typosquats:
                findings.append({
                    "type": "typosquatting",
                    "severity": 80,
                    "url": url[:200],
                    "detail": "; ".join(typosquats)
                })
    except Exception:
        pass

    return findings

def scan_extension(manifest_data: dict) -> dict:
    """
    Analyze a browser extension manifest for threat indicators.
    Returns threat assessment with score and flagged permissions.
    """
    score = 0
    flagged = []
    permissions = manifest_data.get("permissions", [])
    optional_perms = manifest_data.get("optional_permissions", [])
    all_perms = permissions + optional_perms

    for perm in all_perms:
        perm_str = str(perm) if not isinstance(perm, str) else perm
        if perm_str in DANGEROUS_PERMISSIONS:
            weight = DANGEROUS_PERMISSIONS[perm_str]
            score += weight
            flagged.append(f"{perm_str}(+{weight})")
        elif re.match(r"https?://", perm_str):
            score += 30
            flagged.append(f"host_perm:{perm_str[:50]}(+30)")

    # Check for content scripts on all URLs
    content_scripts = manifest_data.get("content_scripts", [])
    for cs in content_scripts:
        matches = cs.get("matches", [])
        for m in matches:
            if m in ("<all_urls>", "*://*/*", "http://*/*", "https://*/*"):
                score += 40
                flagged.append(f"content_script_all_urls(+40)")
                break

    # Background scripts / service workers (persistence)
    if manifest_data.get("background"):
        score += 15
        flagged.append("has_background(+15)")

    # Web-accessible resources (potential for exploitation)
    if manifest_data.get("web_accessible_resources"):
        score += 10
        flagged.append("web_accessible_resources(+10)")

    return {
        "threat_score": min(score, 100),
        "risk_level": _score_to_risk(score),
        "flagged_permissions": flagged,
        "name": manifest_data.get("name", "unknown"),
        "version": manifest_data.get("version", ""),
    }

def analyze_all(rows: list) -> dict:
    """
    Run full IOC analysis on all collected artifacts.
    Returns comprehensive threat report.
    """
    url_threats = []
    seen_urls = set()
    for r in rows:
        url = r.get("url", "")
        if url and url not in seen_urls:
            seen_urls.add(url)
            threats = scan_url(url)
            for t in threats:
                t["browser"] = r.get("browser", "")
                t["artifact"] = r.get("artifact", "")
            url_threats.extend(threats)

    time_anomalies = _detect_time_anomalies(rows)
    exfil_patterns = _detect_exfil_patterns(rows)

    # Aggregate by severity
    critical = [t for t in url_threats if t.get("severity", 0) >= 80]
    high = [t for t in url_threats if 60 <= t.get("severity", 0) < 80]
    medium = [t for t in url_threats if 40 <= t.get("severity", 0) < 60]

    overall_risk = _calculate_overall_risk(url_threats, time_anomalies, exfil_patterns)

    return {
        "overall_risk_score": overall_risk,
        "overall_risk_level": _score_to_risk(overall_risk),
        "total_iocs": len(url_threats),
        "critical_findings": critical[:50],
        "high_findings": high[:50],
        "medium_findings": medium[:50],
        "time_anomalies": time_anomalies,
        "exfiltration_indicators": exfil_patterns,
        "urls_scanned": len(seen_urls),
    }

def _score_to_risk(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "CLEAN"

def _calculate_overall_risk(url_threats, time_anomalies, exfil_patterns):
    """Weighted overall risk calculation."""
    if not url_threats and not time_anomalies and not exfil_patterns:
        return 0
    scores = [t.get("severity", 0) for t in url_threats]
    scores.extend(a.get("severity", 0) for a in time_anomalies)
    scores.extend(e.get("severity", 0) for e in exfil_patterns)
    if not scores:
        return 0
    # Weighted: max score * 0.5 + mean * 0.3 + density * 0.2
    max_score = max(scores)
    mean_score = sum(scores) / len(scores)
    density = min(len(scores) / 10, 1.0) * 100
    return min(100, int(max_score * 0.5 + mean_score * 0.3 + density * 0.2))
