"""
Frostveil Cookie Extraction — with Chromium AES-GCM decryption.

Decrypts encrypted_value blobs using the master key from Local State.
Falls back to plaintext for Firefox and pre-v80 Chromium.
"""
import sqlite3, json
from pathlib import Path
from . import utils, crypto

def extract(browser, path: Path, meta):
    rows = []
    if browser in ["chrome", "edge"]:
        _extract_chromium_cookies(browser, path, meta, rows)
    elif browser == "firefox":
        _extract_firefox_cookies(path, meta, rows)
    return rows

def _extract_chromium_cookies(browser, path, meta, rows):
    ck = path.parent / "Cookies"
    tmp = utils.safe_copy(ck)
    if not tmp:
        return

    master_key = crypto.get_chromium_master_key(path.parent)

    try:
        con = sqlite3.connect(str(tmp))
        cur = con.cursor()
        cur.execute("""
            SELECT host_key, name, value, encrypted_value,
                   path, expires_utc, is_secure, is_httponly,
                   last_access_utc, samesite, source_scheme
            FROM cookies
        """)
        for row_data in cur.fetchall():
            host, name, value, enc_value, cookie_path, expires, \
                is_secure, is_httponly, last_access, samesite, source = row_data

            # Decrypt the cookie value
            decrypted_value = value or ""
            if enc_value and master_key:
                result = crypto.decrypt_chromium_blob(enc_value, master_key)
                if result:
                    decrypted_value = result
                elif not value:
                    decrypted_value = "<decryption_failed>"
            elif enc_value and not value:
                decrypted_value = "<encrypted:no_key>"

            # Classify cookie purpose
            cookie_class = _classify_cookie(host, name, decrypted_value)

            rows.append({
                **meta, "browser": browser, "artifact": "cookie",
                "profile": str(path.parent),
                "url": host,
                "title": name,
                "visit_count": None,
                "visit_time_utc": utils.utc_from_webkit(last_access),
                "extra": json.dumps({
                    "value": decrypted_value[:500],
                    "path": cookie_path or "/",
                    "secure": bool(is_secure),
                    "httponly": bool(is_httponly),
                    "samesite": _samesite_str(samesite),
                    "expires": utils.utc_from_webkit(expires),
                    "classification": cookie_class,
                }, ensure_ascii=False)
            })
        con.close()
        utils.log_line(f"Cookies extracted from {ck} ({len(rows)} entries, key={'found' if master_key else 'missing'})")
    except Exception as e:
        utils.log_line(f"Error cookies {browser}: {e}")

def _extract_firefox_cookies(path, meta, rows):
    profs = path.glob("*.default*") if path.is_dir() else []
    for prof in profs:
        ck = prof / "cookies.sqlite"
        tmp = utils.safe_copy(ck)
        if not tmp:
            continue
        try:
            con = sqlite3.connect(str(tmp))
            cur = con.cursor()
            cur.execute("""
                SELECT host, name, value, path, expiry, isSecure, isHttpOnly,
                       lastAccessed, sameSite
                FROM moz_cookies
            """)
            for host, name, val, cookie_path, expiry, secure, httponly, last, samesite in cur.fetchall():
                cookie_class = _classify_cookie(host, name, val)
                rows.append({
                    **meta, "browser": "firefox", "artifact": "cookie",
                    "profile": str(prof),
                    "url": host,
                    "title": name,
                    "visit_count": None,
                    "visit_time_utc": utils.utc_from_unix(last),
                    "extra": json.dumps({
                        "value": (val or "")[:500],
                        "path": cookie_path or "/",
                        "secure": bool(secure),
                        "httponly": bool(httponly),
                        "samesite": _samesite_str(samesite),
                        "classification": cookie_class,
                    }, ensure_ascii=False)
                })
            con.close()
        except Exception as e:
            utils.log_line(f"Error cookies firefox {prof}: {e}")

# ---------------------------------------------------------------------------
# Cookie classification
# ---------------------------------------------------------------------------

TRACKING_PATTERNS = [
    "doubleclick", "facebook.com", "google-analytics", "scorecardresearch",
    "quantserve", "adnxs", "criteo", "outbrain", "taboola", "amazon-adsystem",
    "_ga", "_gid", "_fbp", "_gcl", "NID", "IDE", "DSID", "fr", "__utma",
]

SESSION_NAMES = ["session", "sess", "sid", "token", "auth", "jwt", "csrf", "xsrf"]

def _classify_cookie(host, name, value):
    """Classify cookie as tracking, session, authentication, or functional."""
    name_lower = (name or "").lower()
    host_lower = (host or "").lower()
    value_lower = (value or "").lower()

    for pattern in TRACKING_PATTERNS:
        if pattern in name_lower or pattern in host_lower:
            return "tracking"

    for pattern in SESSION_NAMES:
        if pattern in name_lower:
            return "session/auth"

    if len(value or "") > 100:
        return "data_heavy"

    return "functional"

def _samesite_str(val):
    if val == 0:
        return "None"
    if val == 1:
        return "Lax"
    if val == 2:
        return "Strict"
    return "unset"
