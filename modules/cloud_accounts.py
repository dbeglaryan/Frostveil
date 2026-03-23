"""
Frostveil Cloud Account Enumerator — extract every logged-in account
from browser artifacts (cookies, Local Storage, autofill, preferences).

Identifies accounts on:
  Google, Microsoft, Apple, Facebook/Meta, GitHub, GitLab, AWS, Azure,
  Slack, Discord, Twitter/X, LinkedIn, Dropbox, Reddit, Twitch,
  PayPal, Stripe, Cloudflare, DigitalOcean, Heroku, Vercel, Netlify,
  and 50+ more services.

For authorized penetration testing and forensic investigations only.
"""
import json, re
from collections import defaultdict
from . import utils

# ---------------------------------------------------------------------------
# Service detection rules: cookie names, domains, and patterns
# ---------------------------------------------------------------------------

# Each entry: (service_name, cookie_domain_pattern, cookie_name_pattern, value_extractor)
# value_extractor is a regex that tries to pull an account identifier from the cookie value

COOKIE_RULES = [
    # Google
    ("Google", r"\.google\.", r"^(SAPISID|SID|SSID|APISID|HSID|NID|__Secure-1PSID)$", None),
    ("Google", r"\.google\.", r"^LSID$", None),
    ("Gmail", r"mail\.google\.com", r"^(COMPASS|GMAIL_AT)$", None),
    ("YouTube", r"\.youtube\.com", r"^(LOGIN_INFO|SID|VISITOR_INFO)$", None),
    ("Google Cloud", r"console\.cloud\.google\.com", r".*", None),

    # Microsoft
    ("Microsoft", r"\.microsoft\.com", r"^(MSPAuth|MSPProf|MUID|ANON)$", None),
    ("Microsoft 365", r"\.office\.com|\.office365\.com", r"^(OIDCAuthCookie|SignInStateCookie)$", None),
    ("Outlook", r"\.outlook\.(com|live\.com)", r"^(RPSSecAuth|OIDCAuthCookie)$", None),
    ("Azure", r"\.azure\.com|portal\.azure\.com", r".*auth.*", None),
    ("Teams", r"teams\.microsoft\.com", r"^(authtoken|SSOAUTH)$", None),

    # Meta / Facebook
    ("Facebook", r"\.facebook\.com", r"^(c_user|xs|datr|sb)$", None),
    ("Instagram", r"\.instagram\.com", r"^(sessionid|ds_user_id|csrftoken)$", None),
    ("WhatsApp Web", r"web\.whatsapp\.com", r".*", None),

    # Apple
    ("Apple", r"\.apple\.com|\.icloud\.com", r"^(myacinfo|DSID|itspod)$", None),

    # GitHub
    ("GitHub", r"\.github\.com|github\.com", r"^(logged_in|user_session|dotcom_user|_gh_sess)$", None),
    ("GitLab", r"gitlab\.", r"^(_gitlab_session|known_sign_in)$", None),
    ("Bitbucket", r"\.bitbucket\.org", r"^(cloud\.session\.token)$", None),

    # Dev tools
    ("NPM", r"\.npmjs\.(com|org)", r".*session.*", None),
    ("PyPI", r"pypi\.org", r".*session.*", None),
    ("Docker Hub", r"hub\.docker\.com", r".*", None),
    ("Vercel", r"\.vercel\.com", r"^(token|__Host-next-auth)$", None),
    ("Netlify", r"\.netlify\.com", r"^(nf_jwt)$", None),
    ("Heroku", r"\.heroku\.com", r"^(heroku-session-affinity|_heroku_session)$", None),

    # Cloud providers
    ("AWS Console", r"\.aws\.amazon\.com", r"^(aws-creds|aws-userInfo|JSESSIONID)$", None),
    ("Cloudflare", r"\.cloudflare\.com|dash\.cloudflare\.com", r"^(CF_Authorization|__cfduid)$", None),
    ("DigitalOcean", r"\.digitalocean\.com", r".*session.*", None),

    # Social media
    ("Twitter/X", r"\.(twitter|x)\.com", r"^(auth_token|ct0|twid)$", None),
    ("LinkedIn", r"\.linkedin\.com", r"^(li_at|JSESSIONID|li_mc)$", None),
    ("Reddit", r"\.reddit\.com", r"^(reddit_session|token_v2)$", None),
    ("Discord", r"\.discord\.com|discord\.com", r"^(__dcfduid|__sdcfduid|__cfruid)$", None),
    ("Twitch", r"\.twitch\.tv", r"^(auth-token|login|twilight-user)$", None),
    ("TikTok", r"\.tiktok\.com", r"^(sessionid|passport_csrf_token)$", None),
    ("Pinterest", r"\.pinterest\.com", r"^(_pinterest_sess|_auth)$", None),
    ("Snapchat", r"\.snapchat\.com", r".*", None),

    # Productivity
    ("Slack", r"\.slack\.com", r"^(d|d-s|lc)$", None),
    ("Notion", r"\.notion\.so", r"^(token_v2|notion_user_id)$", None),
    ("Trello", r"\.trello\.com", r"^(token|dsc)$", None),
    ("Jira", r"\.atlassian\.(net|com)", r"^(cloud\.session\.token|tenant\.session\.token)$", None),
    ("Confluence", r"\.atlassian\.(net|com)", r".*confluence.*", None),
    ("Asana", r"\.asana\.com", r".*session.*", None),
    ("Monday.com", r"\.monday\.com", r".*", None),

    # Finance / Payment
    ("PayPal", r"\.paypal\.com", r"^(login_email|X-PP-SILOVER|cookie_check)$", None),
    ("Stripe", r"\.stripe\.com|dashboard\.stripe\.com", r"^(__stripe_sid|__stripe_mid|machine_identifier)$", None),
    ("Coinbase", r"\.coinbase\.com", r"^(cb_session|device_id)$", None),
    ("Binance", r"\.binance\.(com|us)", r".*session.*", None),

    # Email
    ("ProtonMail", r"\.proton\.(me|mail)", r"^(Session-Id|AUTH)$", None),
    ("Yahoo Mail", r"\.yahoo\.com", r"^(Y|T|F)$", None),

    # Storage
    ("Dropbox", r"\.dropbox\.com", r"^(lid|__Host-js_csrf|t)$", None),
    ("Google Drive", r"drive\.google\.com", r".*", None),
    ("OneDrive", r"\.onedrive\.com|onedrive\.live\.com", r".*auth.*", None),
    ("Box", r"\.box\.com", r".*session.*", None),

    # Hosting / CMS
    ("WordPress", r"\.wordpress\.(com|org)", r"^(wordpress_logged_in|wp-settings)$", None),
    ("Shopify", r"\.shopify\.com|\.myshopify\.com", r"^(_shopify_s|_secure_session_id|_y)$", None),
    ("Wix", r"\.wix\.com", r"^(svSession|ssr-caching)$", None),
    ("Squarespace", r"\.squarespace\.com", r".*session.*", None),

    # Security / Infrastructure
    ("1Password", r"\.1password\.(com|eu|ca)", r".*session.*", None),
    ("LastPass", r"\.lastpass\.com", r"^(PHPSESSID|lp_login)$", None),
    ("Okta", r"\.okta\.com|\.oktapreview\.com", r"^(sid|DT)$", None),
    ("Auth0", r"\.auth0\.com", r"^(auth0|_legacy_auth0)$", None),

    # AI
    ("OpenAI/ChatGPT", r"\.openai\.com|chat\.openai\.com", r"^(__Secure-next-auth\.session-token|__Host-next-auth)$", None),
    ("Anthropic/Claude", r"\.anthropic\.com|claude\.ai", r".*session.*", None),
    ("Hugging Face", r"\.huggingface\.co", r".*token.*", None),
]

# URLs that indicate logged-in accounts in browsing history
ACCOUNT_URL_PATTERNS = [
    ("Google", r"myaccount\.google\.com|accounts\.google\.com/b/\d+"),
    ("Microsoft", r"account\.microsoft\.com|myaccount\.microsoft\.com"),
    ("Facebook", r"facebook\.com/settings|facebook\.com/me"),
    ("GitHub", r"github\.com/settings|github\.com/[a-zA-Z0-9_-]+\?tab=repositories"),
    ("Twitter/X", r"(twitter|x)\.com/settings|twitter\.com/home"),
    ("LinkedIn", r"linkedin\.com/in/[a-zA-Z0-9_-]+|linkedin\.com/feed"),
    ("AWS Console", r"console\.aws\.amazon\.com"),
    ("Azure Portal", r"portal\.azure\.com"),
    ("Slack", r"app\.slack\.com/client"),
    ("Discord", r"discord\.com/channels/@me"),
]

# Email patterns to extract from cookie values, URLs, and autofill
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

# Known OAuth/SSO patterns indicating account linkage
OAUTH_PATTERNS = [
    (r"accounts\.google\.com/o/oauth2/auth", "Google OAuth"),
    (r"login\.microsoftonline\.com", "Microsoft OAuth/Azure AD"),
    (r"github\.com/login/oauth", "GitHub OAuth"),
    (r"facebook\.com/v\d+\.\d+/dialog/oauth", "Facebook OAuth"),
    (r"api\.twitter\.com/oauth", "Twitter OAuth"),
    (r"slack\.com/oauth", "Slack OAuth"),
    (r"discord\.com/api/oauth2", "Discord OAuth"),
    (r"appleid\.apple\.com/auth", "Apple Sign In"),
    (r"login\.salesforce\.com", "Salesforce SSO"),
]


def enumerate_accounts(all_rows: list) -> dict:
    """
    Scan all extracted artifacts to enumerate cloud accounts.

    Returns a comprehensive account inventory with:
    - All detected services and their authentication state
    - Email addresses found across artifacts
    - OAuth/SSO relationships
    - Session token inventory with expiry info
    - Account linkage map (which accounts are connected)
    """
    accounts = defaultdict(lambda: {
        "service": "",
        "evidence": [],
        "emails": set(),
        "session_tokens": [],
        "last_activity": None,
        "browsers": set(),
    })

    emails_global = set()
    oauth_flows = []
    token_inventory = []

    for row in all_rows:
        artifact = row.get("artifact", "")
        url = row.get("url", "")
        title = row.get("title", "")
        extra_raw = row.get("extra", "")
        browser = row.get("browser", "")
        timestamp = row.get("visit_time_utc", "")

        extra = _parse_extra(extra_raw)

        # --- Cookie-based detection ---
        if artifact == "cookie":
            _check_cookie_rules(accounts, row, url, title, extra, browser, timestamp)

        # --- History-based detection ---
        if artifact in ("history", "url"):
            _check_url_patterns(accounts, url, browser, timestamp)
            _check_oauth_flows(oauth_flows, url, timestamp, browser)

        # --- Credential-based detection ---
        if artifact == "credential":
            _extract_credential_account(accounts, row, url, title, extra, browser, timestamp)

        # --- Autofill-based detection ---
        if artifact in ("autofill", "address"):
            _extract_autofill_emails(emails_global, extra)

        # --- Preference-based detection (sync accounts) ---
        if artifact == "preference" and title == "sync_account":
            email = url  # sync_account stores email in the url field
            if email and "@" in email:
                emails_global.add(email)
                service = _identify_email_service(email)
                acct = accounts[service]
                acct["service"] = service
                acct["evidence"].append({"type": "sync_account", "email": email, "browser": browser})
                acct["emails"].add(email)
                acct["browsers"].add(browser)

        # --- Session tokens from LocalStorage ---
        if artifact == "localstorage":
            _check_localstorage_tokens(token_inventory, row, url, title, extra, browser)

        # --- Extract emails from any URL or value ---
        for email in EMAIL_REGEX.findall(f"{url} {title} {extra_raw}"):
            if _is_valid_email(email):
                emails_global.add(email.lower())

    # Build the final report
    account_list = []
    for key, acct in accounts.items():
        if not acct["evidence"]:
            continue
        account_list.append({
            "service": acct["service"] or key,
            "evidence_count": len(acct["evidence"]),
            "emails": list(acct["emails"]),
            "session_tokens": len(acct["session_tokens"]),
            "has_active_session": any(t.get("active") for t in acct["session_tokens"]),
            "browsers": list(acct["browsers"]),
            "last_activity": acct["last_activity"],
            "evidence": acct["evidence"][:5],  # Top 5 evidence items
        })

    # Sort by evidence count (most authenticated services first)
    account_list.sort(key=lambda a: a["evidence_count"], reverse=True)

    # Build account linkage map (which services share the same email)
    linkage = defaultdict(list)
    for acct in account_list:
        for email in acct["emails"]:
            linkage[email].append(acct["service"])

    return {
        "total_accounts": len(account_list),
        "total_emails": len(emails_global),
        "accounts": account_list,
        "all_emails": sorted(emails_global),
        "oauth_flows": oauth_flows[:20],
        "token_inventory": token_inventory[:50],
        "account_linkage": {e: svcs for e, svcs in linkage.items() if len(svcs) > 1},
    }


def extract_as_artifacts(all_rows: list, meta: dict) -> list:
    """Run enumeration and return results as artifact rows for the main pipeline."""
    report = enumerate_accounts(all_rows)
    rows = []

    for acct in report["accounts"]:
        rows.append({
            **meta, "browser": ", ".join(acct["browsers"]),
            "artifact": "cloud_account",
            "profile": "",
            "url": ", ".join(acct["emails"]) if acct["emails"] else acct["service"],
            "title": acct["service"],
            "visit_count": acct["evidence_count"],
            "visit_time_utc": acct["last_activity"],
            "extra": json.dumps({
                "has_active_session": acct["has_active_session"],
                "session_tokens": acct["session_tokens"],
                "evidence": acct["evidence"],
            }, ensure_ascii=False, default=str),
        })

    return rows


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _check_cookie_rules(accounts, row, host, name, extra, browser, timestamp):
    """Match cookies against service detection rules."""
    for service, domain_pat, name_pat, _ in COOKIE_RULES:
        if re.search(domain_pat, host or "", re.I) and re.search(name_pat, name or "", re.I):
            acct = accounts[service]
            acct["service"] = service
            acct["evidence"].append({
                "type": "cookie",
                "cookie_name": name,
                "domain": host,
                "browser": browser,
            })
            acct["browsers"].add(browser)
            if timestamp and (not acct["last_activity"] or timestamp > acct["last_activity"]):
                acct["last_activity"] = timestamp

            # Check for session-type cookies
            value = extra.get("value", "")
            if any(s in (name or "").lower() for s in ("session", "auth", "token", "sid", "logged")):
                acct["session_tokens"].append({
                    "name": name,
                    "domain": host,
                    "active": bool(value and value not in ("<encrypted:no_key>", "<decryption_failed>")),
                    "secure": extra.get("secure", False),
                    "httponly": extra.get("httponly", False),
                })

            # Try to extract email from cookie value
            value_str = str(value)
            for email in EMAIL_REGEX.findall(value_str):
                if _is_valid_email(email):
                    acct["emails"].add(email.lower())

            # Facebook c_user gives numeric user ID
            if service == "Facebook" and name == "c_user" and value:
                acct["evidence"][-1]["user_id"] = value

            break  # Only match first rule per cookie


def _check_url_patterns(accounts, url, browser, timestamp):
    """Check browsing history URLs for account-related pages."""
    for service, pattern in ACCOUNT_URL_PATTERNS:
        if re.search(pattern, url or "", re.I):
            acct = accounts[service]
            acct["service"] = service
            acct["evidence"].append({
                "type": "history",
                "url": url[:200],
                "browser": browser,
            })
            acct["browsers"].add(browser)
            if timestamp and (not acct["last_activity"] or timestamp > acct["last_activity"]):
                acct["last_activity"] = timestamp

            # Extract email from URL if present
            for email in EMAIL_REGEX.findall(url):
                if _is_valid_email(email):
                    acct["emails"].add(email.lower())
            break


def _check_oauth_flows(oauth_flows, url, timestamp, browser):
    """Detect OAuth/SSO authentication flows in history."""
    for pattern, name in OAUTH_PATTERNS:
        if re.search(pattern, url or "", re.I):
            oauth_flows.append({
                "flow": name,
                "url": url[:200],
                "timestamp": timestamp,
                "browser": browser,
            })
            break


def _extract_credential_account(accounts, row, url, username, extra, browser, timestamp):
    """Extract account info from saved credentials."""
    if not url:
        return

    # Identify the service from the credential URL
    service = None
    for svc_name, domain_pat, _, _ in COOKIE_RULES:
        if re.search(domain_pat, url, re.I):
            service = svc_name
            break

    if not service:
        # Try to extract domain name as service name
        m = re.search(r'https?://(?:www\.)?([a-zA-Z0-9.-]+)', url)
        if m:
            domain = m.group(1)
            # Capitalize and clean up
            parts = domain.split(".")
            if len(parts) >= 2:
                service = parts[-2].capitalize()

    if not service:
        return

    acct = accounts[service]
    acct["service"] = service
    acct["evidence"].append({
        "type": "credential",
        "url": url[:200],
        "username": username,
        "browser": browser,
        "has_password": bool(extra.get("password") and
                           extra["password"] not in ("<encrypted:no_key>", "<decryption_failed>", "")),
    })
    acct["browsers"].add(browser)
    if timestamp and (not acct["last_activity"] or timestamp > acct["last_activity"]):
        acct["last_activity"] = timestamp

    if username and "@" in username:
        acct["emails"].add(username.lower())


def _extract_autofill_emails(emails_global, extra):
    """Pull email addresses from autofill data."""
    for key in ("value", "email", "email_address"):
        val = extra.get(key, "")
        for email in EMAIL_REGEX.findall(str(val)):
            if _is_valid_email(email):
                emails_global.add(email.lower())


def _check_localstorage_tokens(token_inventory, row, url, key, extra, browser):
    """Detect auth tokens stored in LocalStorage."""
    key_lower = (key or "").lower()
    token_keywords = ["token", "auth", "session", "jwt", "access_token",
                      "refresh_token", "id_token", "api_key", "bearer"]

    if any(kw in key_lower for kw in token_keywords):
        value = extra.get("value", "")
        token_inventory.append({
            "origin": url,
            "key": key,
            "type": "localstorage",
            "value_preview": str(value)[:50] + "..." if len(str(value)) > 50 else str(value),
            "is_jwt": _is_jwt(str(value)),
            "browser": browser,
        })


def _identify_email_service(email: str) -> str:
    """Identify the cloud service from an email domain."""
    domain = email.split("@")[-1].lower()
    mappings = {
        "gmail.com": "Google", "googlemail.com": "Google",
        "outlook.com": "Microsoft", "hotmail.com": "Microsoft",
        "live.com": "Microsoft", "msn.com": "Microsoft",
        "yahoo.com": "Yahoo", "yahoo.co.uk": "Yahoo",
        "icloud.com": "Apple", "me.com": "Apple", "mac.com": "Apple",
        "protonmail.com": "ProtonMail", "proton.me": "ProtonMail",
        "pm.me": "ProtonMail",
        "github.com": "GitHub",
    }
    return mappings.get(domain, f"Email ({domain})")


def _is_valid_email(email: str) -> bool:
    """Filter out false positive email matches."""
    if not email or len(email) < 5:
        return False
    # Filter common false positives
    false_domains = ["example.com", "test.com", "localhost", "0.0.0.0",
                     "sentry.io", "sentry-next.wixpress.com"]
    domain = email.split("@")[-1].lower()
    if domain in false_domains:
        return False
    if any(c in email for c in [" ", "<", ">", "(", ")"]):
        return False
    return True


def _is_jwt(value: str) -> bool:
    """Check if a value looks like a JWT token."""
    parts = value.strip().split(".")
    if len(parts) != 3:
        return False
    try:
        import base64
        # JWT header should be valid base64 JSON
        header = parts[0] + "=" * (4 - len(parts[0]) % 4)
        decoded = base64.urlsafe_b64decode(header)
        data = json.loads(decoded)
        return "alg" in data or "typ" in data
    except Exception:
        return False


def _parse_extra(extra_str):
    try:
        return json.loads(extra_str) if extra_str else {}
    except Exception:
        return {}
