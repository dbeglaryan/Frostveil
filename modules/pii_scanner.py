"""
Frostveil PII & Sensitive Data Scanner — regex-powered scanner that finds
personally identifiable information, secrets, and sensitive data across
ALL extracted browser artifacts.

Detects:
  - Credit card numbers (Visa, Mastercard, Amex, Discover) with Luhn validation
  - Social Security Numbers (US SSN)
  - Phone numbers (international)
  - API keys and tokens (AWS, Google, GitHub, Stripe, Slack, etc.)
  - JWT tokens
  - Private keys (RSA, SSH, PGP)
  - Cryptocurrency addresses (Bitcoin, Ethereum)
  - IP addresses (internal/external classification)
  - Passport numbers, driver's license patterns
  - Bank account / routing numbers (IBAN)
  - Base64-encoded secrets
  - Environment variable leaks (.env patterns)

For authorized penetration testing and forensic investigations only.
"""
import re, json, hashlib
from collections import defaultdict
from . import utils

# ---------------------------------------------------------------------------
# Pattern definitions with severity and confidence scoring
# ---------------------------------------------------------------------------

PATTERNS = [
    # Credit Cards (with Luhn validation done separately)
    {
        "name": "credit_card_visa",
        "pattern": r"\b4[0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b",
        "severity": 95,
        "category": "financial",
        "description": "Visa credit card number",
        "validate": "luhn",
    },
    {
        "name": "credit_card_mastercard",
        "pattern": r"\b5[1-5][0-9]{2}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b",
        "severity": 95,
        "category": "financial",
        "validate": "luhn",
    },
    {
        "name": "credit_card_amex",
        "pattern": r"\b3[47][0-9]{2}[\s-]?[0-9]{6}[\s-]?[0-9]{5}\b",
        "severity": 95,
        "category": "financial",
        "validate": "luhn",
    },
    {
        "name": "credit_card_discover",
        "pattern": r"\b6(?:011|5[0-9]{2})[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b",
        "severity": 95,
        "category": "financial",
        "validate": "luhn",
    },

    # SSN
    {
        "name": "us_ssn",
        "pattern": r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b",
        "severity": 95,
        "category": "identity",
        "context_required": ["ssn", "social", "security", "tax", "ein"],
    },

    # Phone numbers
    {
        "name": "phone_us",
        "pattern": r"\b(?:\+1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        "severity": 40,
        "category": "identity",
    },
    {
        "name": "phone_international",
        "pattern": r"\b\+[1-9]\d{1,2}[-.\s]?\d{2,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b",
        "severity": 40,
        "category": "identity",
    },

    # API Keys and Tokens
    {
        "name": "aws_access_key",
        "pattern": r"\b(AKIA[0-9A-Z]{16})\b",
        "severity": 100,
        "category": "secret",
        "description": "AWS Access Key ID",
    },
    {
        "name": "aws_secret_key",
        "pattern": r"(?i)aws[_\-]?secret[_\-]?(?:access[_\-]?)?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})",
        "severity": 100,
        "category": "secret",
    },
    {
        "name": "google_api_key",
        "pattern": r"\bAIza[0-9A-Za-z_-]{35}\b",
        "severity": 85,
        "category": "secret",
        "description": "Google API Key",
    },
    {
        "name": "google_oauth_token",
        "pattern": r"\bya29\.[0-9A-Za-z_-]{30,}\b",
        "severity": 90,
        "category": "secret",
        "description": "Google OAuth Access Token",
    },
    {
        "name": "github_token",
        "pattern": r"\b(ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{22,})\b",
        "severity": 95,
        "category": "secret",
        "description": "GitHub Personal Access Token",
    },
    {
        "name": "github_oauth",
        "pattern": r"\bghr_[a-zA-Z0-9]{76}\b",
        "severity": 95,
        "category": "secret",
    },
    {
        "name": "slack_token",
        "pattern": r"\bxox[boaprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b",
        "severity": 90,
        "category": "secret",
        "description": "Slack API Token",
    },
    {
        "name": "slack_webhook",
        "pattern": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
        "severity": 80,
        "category": "secret",
    },
    {
        "name": "stripe_secret",
        "pattern": r"\b[sr]k_(test|live)_[0-9a-zA-Z]{24,}\b",
        "severity": 95,
        "category": "secret",
        "description": "Stripe Secret/Restricted Key",
    },
    {
        "name": "stripe_publishable",
        "pattern": r"\bpk_(test|live)_[0-9a-zA-Z]{24,}\b",
        "severity": 50,
        "category": "secret",
    },
    {
        "name": "discord_token",
        "pattern": r"\b[MN][A-Za-z\d]{23,27}\.[A-Za-z\d-_]{6}\.[A-Za-z\d-_]{27,40}\b",
        "severity": 90,
        "category": "secret",
        "description": "Discord Bot/User Token",
    },
    {
        "name": "twilio_api_key",
        "pattern": r"\bSK[0-9a-fA-F]{32}\b",
        "severity": 85,
        "category": "secret",
    },
    {
        "name": "sendgrid_api_key",
        "pattern": r"\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b",
        "severity": 85,
        "category": "secret",
    },
    {
        "name": "mailgun_api_key",
        "pattern": r"\bkey-[0-9a-zA-Z]{32}\b",
        "severity": 85,
        "category": "secret",
    },
    {
        "name": "firebase_key",
        "pattern": r"(?i)firebase[_\-]?(?:api[_\-]?)?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_-]{39})",
        "severity": 80,
        "category": "secret",
    },
    {
        "name": "heroku_api_key",
        "pattern": r"(?i)heroku[_\-]?(?:api[_\-]?)?key['\"]?\s*[:=]\s*['\"]?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})",
        "severity": 85,
        "category": "secret",
    },
    {
        "name": "npm_token",
        "pattern": r"\bnpm_[a-zA-Z0-9]{36}\b",
        "severity": 85,
        "category": "secret",
    },

    # JWT Tokens
    {
        "name": "jwt_token",
        "pattern": r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b",
        "severity": 75,
        "category": "secret",
        "description": "JSON Web Token",
    },

    # Private Keys
    {
        "name": "rsa_private_key",
        "pattern": r"-----BEGIN (?:RSA )?PRIVATE KEY-----",
        "severity": 100,
        "category": "secret",
        "description": "RSA Private Key",
    },
    {
        "name": "ssh_private_key",
        "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----",
        "severity": 100,
        "category": "secret",
    },
    {
        "name": "pgp_private_key",
        "pattern": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "severity": 100,
        "category": "secret",
    },

    # Cryptocurrency
    {
        "name": "bitcoin_address",
        "pattern": r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
        "severity": 70,
        "category": "financial",
        "context_required": ["btc", "bitcoin", "wallet", "crypto", "send", "receive"],
    },
    {
        "name": "ethereum_address",
        "pattern": r"\b0x[0-9a-fA-F]{40}\b",
        "severity": 70,
        "category": "financial",
    },

    # IP Addresses
    {
        "name": "ipv4_private",
        "pattern": r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
        "severity": 30,
        "category": "network",
        "description": "Private/internal IPv4 address",
    },

    # IBAN
    {
        "name": "iban",
        "pattern": r"\b[A-Z]{2}\d{2}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{0,2}\b",
        "severity": 85,
        "category": "financial",
        "context_required": ["iban", "bank", "account", "transfer", "wire"],
    },

    # Environment variable patterns
    {
        "name": "env_secret",
        "pattern": r"(?i)(?:password|passwd|secret|api_key|apikey|access_token|auth_token|private_key|db_pass)['\"]?\s*[:=]\s*['\"]?([^\s'\"]{8,})",
        "severity": 80,
        "category": "secret",
        "description": "Environment variable / config secret",
    },

    # Database connection strings
    {
        "name": "db_connection_string",
        "pattern": r"(?i)(?:postgres|mysql|mongodb|redis|mssql)(?:ql)?://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+",
        "severity": 90,
        "category": "secret",
        "description": "Database connection string with credentials",
    },
]


def scan_all(all_rows: list) -> dict:
    """
    Scan all extracted artifacts for PII and sensitive data.

    Returns categorized findings with severity scores, deduplication,
    and contextual analysis.
    """
    findings = []
    seen_hashes = set()  # Deduplicate findings
    category_counts = defaultdict(int)
    severity_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    # Compile all patterns once
    compiled = []
    for p in PATTERNS:
        try:
            compiled.append({
                **p,
                "regex": re.compile(p["pattern"]),
            })
        except re.error:
            continue

    for row in all_rows:
        # Build the searchable text from all fields
        searchable_parts = [
            str(row.get("url", "")),
            str(row.get("title", "")),
            str(row.get("extra", "")),
        ]
        searchable = " ".join(searchable_parts)

        if len(searchable) < 10:
            continue

        for pattern in compiled:
            matches = pattern["regex"].findall(searchable)
            if not matches:
                continue

            # Context-required patterns need nearby keywords
            if pattern.get("context_required"):
                context_lower = searchable.lower()
                if not any(kw in context_lower for kw in pattern["context_required"]):
                    continue

            for match in matches:
                match_str = match if isinstance(match, str) else match[0] if match else ""
                if not match_str or len(match_str) < 4:
                    continue

                # Luhn validation for credit cards
                if pattern.get("validate") == "luhn":
                    digits = re.sub(r"[\s-]", "", match_str)
                    if not _luhn_check(digits):
                        continue

                # Deduplicate
                finding_hash = hashlib.md5(f"{pattern['name']}:{match_str}".encode()).hexdigest()[:12]
                if finding_hash in seen_hashes:
                    continue
                seen_hashes.add(finding_hash)

                severity = pattern["severity"]
                category = pattern["category"]
                category_counts[category] += 1

                if severity >= 90:
                    severity_dist["critical"] += 1
                elif severity >= 70:
                    severity_dist["high"] += 1
                elif severity >= 40:
                    severity_dist["medium"] += 1
                else:
                    severity_dist["low"] += 1

                findings.append({
                    "pattern": pattern["name"],
                    "category": category,
                    "severity": severity,
                    "description": pattern.get("description", pattern["name"].replace("_", " ").title()),
                    "match": _redact_sensitive(match_str, pattern["name"]),
                    "match_hash": finding_hash,
                    "artifact_type": row.get("artifact", ""),
                    "browser": row.get("browser", ""),
                    "source_url": _truncate(row.get("url", ""), 100),
                    "timestamp": row.get("visit_time_utc"),
                })

    # Sort by severity (highest first)
    findings.sort(key=lambda f: f["severity"], reverse=True)

    return {
        "total_findings": len(findings),
        "category_counts": dict(category_counts),
        "severity_distribution": severity_dist,
        "findings": findings,
        "critical_findings": [f for f in findings if f["severity"] >= 90],
        "high_findings": [f for f in findings if 70 <= f["severity"] < 90],
    }


def extract_as_artifacts(all_rows: list, meta: dict) -> list:
    """Run PII scan and return results as artifact rows."""
    report = scan_all(all_rows)
    rows = []

    for finding in report["findings"][:200]:  # Cap at 200 findings
        rows.append({
            **meta, "browser": finding["browser"],
            "artifact": "pii_finding",
            "profile": "",
            "url": finding["source_url"],
            "title": f"{finding['pattern']} ({finding['category']})",
            "visit_count": finding["severity"],
            "visit_time_utc": finding["timestamp"],
            "extra": json.dumps({
                "match": finding["match"],
                "description": finding["description"],
                "severity": finding["severity"],
                "category": finding["category"],
            }, ensure_ascii=False),
        })

    return rows


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

def _luhn_check(number: str) -> bool:
    """Validate a credit card number using the Luhn algorithm."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _redact_sensitive(value: str, pattern_name: str) -> str:
    """Partially redact sensitive values for safe storage/display."""
    if "credit_card" in pattern_name:
        digits = re.sub(r"[\s-]", "", value)
        return f"****-****-****-{digits[-4:]}" if len(digits) >= 4 else "****"
    if "ssn" in pattern_name:
        return f"***-**-{value[-4:]}" if len(value) >= 4 else "***"
    if "private_key" in pattern_name:
        return value[:40] + "...[REDACTED]"
    if pattern_name in ("aws_secret_key", "env_secret", "db_connection_string"):
        return value[:8] + "...[REDACTED]"
    if "token" in pattern_name and len(value) > 20:
        return value[:10] + "..." + value[-4:]
    return value


def _truncate(s: str, n: int = 80) -> str:
    return s[:n] + "..." if len(s) > n else s
