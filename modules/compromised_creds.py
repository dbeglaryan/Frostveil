"""
Frostveil Compromised Credentials Extraction — extract metadata about
compromised credentials from Chromium's Login Data database.

Does NOT extract or store actual passwords — only compromise metadata.
"""
import sqlite3, json
from pathlib import Path
from . import utils

_INSECURITY_TYPES = {0: "leaked", 1: "phished", 2: "weak", 3: "reused"}

def extract(browser, path: Path, meta):
    rows = []
    if browser not in ["chrome", "edge"]:
        return rows

    login_db = path.parent / "Login Data"
    tmp = utils.safe_copy(login_db)
    if not tmp:
        return rows

    try:
        con = sqlite3.connect(str(tmp))
        cur = con.cursor()

        # Determine which table exists
        table = None
        for candidate in ("insecure_credentials", "compromised_credentials"):
            try:
                cur.execute(f"SELECT 1 FROM {candidate} LIMIT 1")
                table = candidate
                break
            except sqlite3.OperationalError:
                continue

        if not table:
            con.close()
            return rows

        cur.execute(f"""
            SELECT l.origin_url, l.username_value, l.signon_realm,
                   c.insecurity_type, c.create_time, c.is_muted
            FROM {table} c
            JOIN logins l ON l.id = c.parent_id
        """)

        for origin_url, username, realm, itype, create_time, is_muted in cur.fetchall():
            rows.append({
                **meta,
                "browser": browser,
                "artifact": "compromised_credential",
                "profile": str(path.parent),
                "url": origin_url or "",
                "title": username or "",
                "visit_count": 0,
                "visit_time_utc": utils.utc_from_webkit(create_time),
                "extra": json.dumps({
                    "insecurity_type": _INSECURITY_TYPES.get(itype, f"unknown({itype})"),
                    "is_muted": bool(is_muted),
                    "signon_realm": realm or "",
                }, ensure_ascii=False),
            })

        con.close()
        utils.log_line(f"Compromised credentials extracted from {login_db} ({len(rows)} entries)")
    except Exception as e:
        utils.log_line(f"Error compromised_creds {browser} {path}: {e}")

    return rows


def summarize(rows):
    """Summarize compromised credential extraction results."""
    cc_rows = [r for r in rows if r.get("artifact") == "compromised_credential"]

    by_type = {}
    affected_sites = set()
    muted_count = 0

    for r in cc_rows:
        extra = json.loads(r.get("extra", "{}"))
        label = extra.get("insecurity_type", "unknown")
        by_type[label] = by_type.get(label, 0) + 1
        if r.get("url"):
            affected_sites.add(r["url"])
        if extra.get("is_muted"):
            muted_count += 1

    return {
        "total_compromised": len(cc_rows),
        "by_type": by_type,
        "affected_sites": len(affected_sites),
        "muted_count": muted_count,
    }
