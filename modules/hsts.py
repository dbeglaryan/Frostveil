import json
from pathlib import Path
from datetime import datetime
from . import utils

# Chromium-family browsers that use TransportSecurity
_CHROMIUM_BROWSERS = {"chrome", "edge", "brave", "opera", "opera_gx",
                      "vivaldi", "yandex", "chromium"}


def _unix_ts_to_iso(ts):
    """Convert a Unix timestamp (seconds, possibly float) to ISO format."""
    if not ts or ts == 0:
        return None
    try:
        return datetime.utcfromtimestamp(float(ts)).isoformat()
    except (OSError, ValueError, OverflowError):
        return None


def extract(browser, path: Path, meta):
    """
    Extract HSTS entries from Chromium's TransportSecurity JSON file.
    Firefox uses a different mechanism and is skipped.
    """
    rows = []

    if browser not in _CHROMIUM_BROWSERS:
        return rows

    ts_file = path.parent / "TransportSecurity"
    if not ts_file.exists():
        return rows

    try:
        raw = ts_file.read_text(encoding="utf-8")
        data = json.loads(raw)
    except Exception as e:
        utils.log_line(f"Error reading TransportSecurity {ts_file}: {e}")
        return rows

    for domain, entry in data.items():
        if not isinstance(entry, dict):
            continue

        expiry = entry.get("expiry")
        sts_observed = entry.get("sts_observed")
        mode = entry.get("mode", "")
        include_subs = entry.get("sts_include_subdomains", False)

        extra = json.dumps({
            "domain": domain,
            "mode": mode,
            "sts_include_subdomains": include_subs,
            "expiry": _unix_ts_to_iso(expiry),
            "sts_observed": _unix_ts_to_iso(sts_observed),
        })

        rows.append({
            **meta,
            "browser": browser,
            "artifact": "hsts_entry",
            "profile": str(path.parent),
            "url": domain,
            "title": mode,
            "visit_count": 0,
            "visit_time_utc": _unix_ts_to_iso(expiry),
            "extra": extra,
        })

    if rows:
        utils.log_line(f"HSTS extracted {len(rows)} entries from {ts_file}")

    return rows


def summarize(rows):
    """Summarize HSTS extraction results."""
    hsts_rows = [r for r in rows if r.get("artifact") == "hsts_entry"]
    now = datetime.utcnow()
    expired = 0
    active = 0
    subs_enforced = 0

    for r in hsts_rows:
        extra = json.loads(r.get("extra", "{}"))
        exp_str = extra.get("expiry")
        if exp_str:
            try:
                exp_dt = datetime.fromisoformat(exp_str)
                if exp_dt < now:
                    expired += 1
                else:
                    active += 1
            except ValueError:
                active += 1
        else:
            active += 1
        if extra.get("sts_include_subdomains"):
            subs_enforced += 1

    return {
        "total_entries": len(hsts_rows),
        "expired_count": expired,
        "active_count": active,
        "subdomains_enforced": subs_enforced,
    }
