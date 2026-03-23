"""
Frostveil Session Hijack Validator — extract live session tokens and
assess their hijack potential.

Analyzes extracted cookies and tokens to determine:
  - Which sessions are still potentially active (not expired)
  - Security posture of each session (Secure, HttpOnly, SameSite flags)
  - Cookie-to-curl command generation for session replay
  - Token type identification (JWT decode, OAuth bearer, session ID)
  - Session age and expiry analysis
  - Missing security headers / flag analysis
  - Cross-site request forgery (CSRF) token inventory

For authorized penetration testing and forensic investigations only.
"""
import json, re, base64, time
from datetime import datetime, timezone
from collections import defaultdict
from . import utils


# High-value session cookie names by service
HIGH_VALUE_COOKIES = {
    # Cloud providers
    "JSESSIONID": "Java Session",
    "ASP.NET_SessionId": ".NET Session",
    "PHPSESSID": "PHP Session",
    "connect.sid": "Express.js Session",
    "laravel_session": "Laravel Session",
    "rack.session": "Ruby/Rails Session",
    "_rails_session": "Rails Session",

    # Major platforms
    "c_user": "Facebook User ID",
    "xs": "Facebook Session",
    "li_at": "LinkedIn Session",
    "auth_token": "Twitter/X Auth",
    "reddit_session": "Reddit Session",
    "user_session": "GitHub Session",
    "dotcom_user": "GitHub User",
    "_gh_sess": "GitHub Session",
    "d": "Slack Session",
    "sessionid": "Generic Session ID",
    "token": "Generic Token",
    "SID": "Google SID",
    "SSID": "Google Secure SID",
    "SAPISID": "Google API SID",
    "__Secure-1PSID": "Google Secure SID",
    "MSPAuth": "Microsoft Auth",
    "RPSSecAuth": "Microsoft/Outlook Auth",
    "OIDCAuthCookie": "Microsoft OIDC",
    "nf_jwt": "Netlify JWT",
    "CF_Authorization": "Cloudflare Auth",
    "__Host-next-auth.session-token": "NextAuth Session",
    "_shopify_s": "Shopify Session",
}


def analyze_sessions(all_rows: list) -> dict:
    """
    Analyze all extracted cookies and tokens for session hijack potential.

    Returns:
      - Active sessions with security assessment
      - Expired sessions (may still be replayable)
      - JWT token analysis with decoded payloads
      - Cookie security audit (missing flags)
      - curl commands for session replay testing
    """
    sessions = []
    csrf_tokens = []
    jwt_tokens = []
    security_issues = []
    service_sessions = defaultdict(list)

    now_ts = int(time.time())

    for row in all_rows:
        artifact = row.get("artifact", "")
        if artifact != "cookie":
            continue

        host = row.get("url", "")
        name = row.get("title", "")
        extra = _parse_extra(row.get("extra", ""))

        value = extra.get("value", "")
        secure = extra.get("secure", False)
        httponly = extra.get("httponly", False)
        samesite = extra.get("samesite", "unset")
        expires = extra.get("expires")

        # Skip empty or failed decryption
        if not value or value in ("<encrypted:no_key>", "<decryption_failed>"):
            continue

        # Determine if this is a session-relevant cookie
        is_session = _is_session_cookie(name, value, host)
        is_csrf = _is_csrf_token(name)

        if is_csrf:
            csrf_tokens.append({
                "name": name,
                "domain": host,
                "value_preview": value[:30] + "..." if len(value) > 30 else value,
                "browser": row.get("browser", ""),
            })
            continue

        if not is_session:
            continue

        # Expiry analysis
        is_expired = False
        expires_in = None
        if expires:
            try:
                # Parse the expiry timestamp
                exp_ts = _parse_expiry(expires)
                if exp_ts:
                    if exp_ts < now_ts:
                        is_expired = True
                    else:
                        expires_in = exp_ts - now_ts
            except Exception:
                pass

        # JWT detection and decode
        jwt_info = None
        if _looks_like_jwt(value):
            jwt_info = _decode_jwt(value)
            if jwt_info:
                jwt_tokens.append({
                    "domain": host,
                    "cookie_name": name,
                    "header": jwt_info.get("header", {}),
                    "payload_preview": {k: v for k, v in list(jwt_info.get("payload", {}).items())[:10]},
                    "expired": jwt_info.get("expired", False),
                    "issued_at": jwt_info.get("iat"),
                    "expires_at": jwt_info.get("exp"),
                    "algorithm": jwt_info.get("header", {}).get("alg", "unknown"),
                    "browser": row.get("browser", ""),
                })

        # Security flag analysis
        issues = []
        if not secure:
            issues.append("missing_secure_flag")
        if not httponly:
            issues.append("missing_httponly_flag")
        if samesite in ("unset", "None"):
            issues.append(f"samesite_{samesite.lower()}")

        if issues:
            security_issues.extend([{
                "domain": host,
                "cookie": name,
                "issue": issue,
                "severity": _issue_severity(issue),
            } for issue in issues])

        # Service identification
        service = _identify_service(host, name)

        # Risk score
        risk_score = _calculate_risk(name, value, secure, httponly,
                                      samesite, is_expired, jwt_info)

        session = {
            "domain": host,
            "cookie_name": name,
            "service": service,
            "value_length": len(value),
            "value_preview": value[:20] + "..." if len(value) > 20 else value,
            "is_expired": is_expired,
            "expires_in_seconds": expires_in,
            "expires_in_human": _human_time(expires_in) if expires_in else None,
            "secure": secure,
            "httponly": httponly,
            "samesite": samesite,
            "is_jwt": jwt_info is not None,
            "jwt_algorithm": jwt_info.get("header", {}).get("alg") if jwt_info else None,
            "security_issues": issues,
            "risk_score": risk_score,
            "browser": row.get("browser", ""),
            "high_value": name in HIGH_VALUE_COOKIES,
            "high_value_label": HIGH_VALUE_COOKIES.get(name, ""),
        }
        sessions.append(session)

        if service:
            service_sessions[service].append(session)

    # Sort by risk score
    sessions.sort(key=lambda s: s["risk_score"], reverse=True)

    # Generate curl commands for top sessions
    curl_commands = _generate_curl_commands(sessions[:20])

    # Active vs expired breakdown
    active = [s for s in sessions if not s["is_expired"]]
    expired = [s for s in sessions if s["is_expired"]]
    high_value = [s for s in sessions if s["high_value"]]

    return {
        "total_sessions": len(sessions),
        "active_sessions": len(active),
        "expired_sessions": len(expired),
        "high_value_sessions": len(high_value),
        "jwt_tokens_found": len(jwt_tokens),
        "csrf_tokens_found": len(csrf_tokens),
        "security_issues": len(security_issues),
        "sessions": sessions[:100],
        "active_high_value": [s for s in active if s["high_value"]][:20],
        "jwt_analysis": jwt_tokens[:20],
        "csrf_tokens": csrf_tokens[:20],
        "security_audit": security_issues[:50],
        "curl_commands": curl_commands,
        "service_summary": {svc: len(sess) for svc, sess in service_sessions.items()},
    }


def extract_as_artifacts(all_rows: list, meta: dict) -> list:
    """Run session analysis and return as artifact rows."""
    report = analyze_sessions(all_rows)
    rows = []

    for session in report.get("active_high_value", []):
        rows.append({
            **meta, "browser": session["browser"],
            "artifact": "session_hijack",
            "profile": "",
            "url": session["domain"],
            "title": f"{session['service'] or session['domain']} ({session['cookie_name']})",
            "visit_count": session["risk_score"],
            "visit_time_utc": None,
            "extra": json.dumps({
                "cookie_name": session["cookie_name"],
                "service": session["service"],
                "is_expired": session["is_expired"],
                "expires_in": session["expires_in_human"],
                "secure": session["secure"],
                "httponly": session["httponly"],
                "samesite": session["samesite"],
                "is_jwt": session["is_jwt"],
                "risk_score": session["risk_score"],
                "security_issues": session["security_issues"],
                "high_value_label": session["high_value_label"],
            }, ensure_ascii=False),
        })

    return rows


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_session_cookie(name: str, value: str, host: str) -> bool:
    """Determine if a cookie is session-relevant."""
    name_lower = (name or "").lower()

    # Direct name match
    if name in HIGH_VALUE_COOKIES:
        return True

    # Pattern-based detection
    session_patterns = [
        "session", "sess", "sid", "auth", "token", "jwt", "bearer",
        "login", "logged", "credential", "access", "refresh",
        "apikey", "api_key", "secret", "identity", "saml",
    ]
    if any(p in name_lower for p in session_patterns):
        return True

    # JWT-shaped values
    if _looks_like_jwt(value):
        return True

    # Long random-looking values (likely session IDs)
    if len(value) >= 32 and re.match(r'^[a-zA-Z0-9_-]+$', value):
        return True

    return False


def _is_csrf_token(name: str) -> bool:
    """Detect CSRF/XSRF tokens."""
    name_lower = (name or "").lower()
    return any(p in name_lower for p in ["csrf", "xsrf", "_token", "csrftoken"])


def _looks_like_jwt(value: str) -> bool:
    """Quick check if a value looks like a JWT."""
    parts = (value or "").strip().split(".")
    return len(parts) == 3 and parts[0].startswith("eyJ")


def _decode_jwt(token: str) -> dict:
    """Decode a JWT token (header + payload, no signature verification)."""
    try:
        parts = token.strip().split(".")
        if len(parts) != 3:
            return None

        # Decode header
        header = json.loads(_b64_decode_jwt(parts[0]))

        # Decode payload
        payload = json.loads(_b64_decode_jwt(parts[1]))

        # Check expiry
        exp = payload.get("exp")
        iat = payload.get("iat")
        now = int(time.time())

        return {
            "header": header,
            "payload": payload,
            "expired": exp < now if exp else None,
            "exp": datetime.fromtimestamp(exp, tz=timezone.utc).isoformat() if exp else None,
            "iat": datetime.fromtimestamp(iat, tz=timezone.utc).isoformat() if iat else None,
        }
    except Exception:
        return None


def _b64_decode_jwt(s: str) -> str:
    """Base64url decode a JWT segment."""
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s).decode("utf-8", errors="replace")


def _parse_expiry(expires) -> int:
    """Parse expiry value to Unix timestamp."""
    if isinstance(expires, (int, float)):
        if expires > 1e15:  # WebKit timestamp
            return int(expires / 1e6 - 11644473600)
        elif expires > 1e12:  # Milliseconds
            return int(expires / 1000)
        return int(expires)
    if isinstance(expires, str):
        try:
            dt = datetime.fromisoformat(expires.rstrip("Z"))
            return int(dt.timestamp())
        except Exception:
            pass
    return None


def _identify_service(host: str, name: str) -> str:
    """Identify the service from cookie domain and name."""
    host_lower = (host or "").lower()

    service_map = {
        "google": "Google", "youtube": "YouTube", "gmail": "Gmail",
        "facebook": "Facebook", "instagram": "Instagram",
        "microsoft": "Microsoft", "office": "Microsoft 365",
        "outlook": "Outlook", "azure": "Azure",
        "github": "GitHub", "gitlab": "GitLab",
        "twitter": "Twitter/X", "x.com": "Twitter/X",
        "linkedin": "LinkedIn", "reddit": "Reddit",
        "discord": "Discord", "slack": "Slack",
        "amazon": "Amazon", "aws": "AWS",
        "stripe": "Stripe", "paypal": "PayPal",
        "dropbox": "Dropbox", "notion": "Notion",
        "shopify": "Shopify", "cloudflare": "Cloudflare",
        "netlify": "Netlify", "vercel": "Vercel",
        "heroku": "Heroku", "twitch": "Twitch",
        "openai": "OpenAI", "anthropic": "Anthropic",
    }

    for pattern, service in service_map.items():
        if pattern in host_lower:
            return service

    # Extract domain name as service name
    m = re.search(r'\.?([a-zA-Z0-9-]+)\.[a-zA-Z]{2,}$', host_lower)
    if m:
        return m.group(1).capitalize()
    return None


def _calculate_risk(name, value, secure, httponly, samesite, is_expired, jwt_info):
    """Calculate hijack risk score (0-100)."""
    score = 0

    # High-value cookie
    if name in HIGH_VALUE_COOKIES:
        score += 30

    # Active (not expired) is riskier
    if not is_expired:
        score += 20

    # Missing security flags
    if not secure:
        score += 15
    if not httponly:
        score += 10
    if samesite in ("unset", "None"):
        score += 10

    # Long tokens are more likely to be session tokens
    if len(value) >= 64:
        score += 5

    # JWT with known claims
    if jwt_info and not jwt_info.get("expired"):
        score += 10

    return min(100, score)


def _issue_severity(issue: str) -> str:
    """Map security issues to severity levels."""
    severities = {
        "missing_secure_flag": "HIGH",
        "missing_httponly_flag": "MEDIUM",
        "samesite_none": "HIGH",
        "samesite_unset": "MEDIUM",
    }
    return severities.get(issue, "LOW")


def _generate_curl_commands(sessions: list) -> list:
    """Generate curl commands for session replay testing."""
    commands = []
    # Group cookies by domain
    domain_cookies = defaultdict(list)
    for s in sessions:
        if not s["is_expired"]:
            domain_cookies[s["domain"]].append(s)

    for domain, cookies in list(domain_cookies.items())[:10]:
        cookie_str = "; ".join(f"{c['cookie_name']}=<REDACTED>" for c in cookies)
        scheme = "https" if any(c["secure"] for c in cookies) else "http"
        host = domain.lstrip(".")
        cmd = f'curl -v -b "{cookie_str}" "{scheme}://{host}/"'
        commands.append({
            "domain": domain,
            "command": cmd,
            "cookies_count": len(cookies),
            "note": "Replace <REDACTED> with actual cookie values from extraction",
        })

    return commands


def _human_time(seconds: int) -> str:
    """Convert seconds to human-readable time."""
    if not seconds:
        return ""
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h {(seconds % 3600) // 60}m"
    days = seconds // 86400
    return f"{days}d {(seconds % 86400) // 3600}h"


def _parse_extra(extra_str):
    try:
        return json.loads(extra_str) if extra_str else {}
    except Exception:
        return {}
