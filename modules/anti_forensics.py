"""
Frostveil Anti-Forensics Detector — detect evidence of history clearing,
private browsing artifacts, timestamp manipulation, and data wiping.

Identifies:
- Cleared browser history (gaps, low counts vs. profile age)
- Private/incognito browsing residue
- Timestamp anomalies (future dates, impossible sequences)
- Selective deletion patterns
- Browser database vacuum indicators
"""
import sqlite3, json, os, stat
from pathlib import Path
from datetime import datetime, timedelta
from . import utils

def detect(browser, path: Path, meta):
    """Run anti-forensics detection on a browser profile."""
    rows = []
    if browser in ["chrome", "edge"]:
        _detect_chromium_clearing(browser, path, meta, rows)
        _detect_chromium_incognito_artifacts(browser, path, meta, rows)
        _detect_db_vacuum(browser, path, meta, rows)
    elif browser == "firefox":
        _detect_firefox_clearing(path, meta, rows)
        _detect_firefox_private(path, meta, rows)
    return rows

def detect_timestamp_anomalies(all_rows: list, meta: dict) -> list:
    """Detect timestamp anomalies across all collected artifacts."""
    findings = []
    timestamps = []

    for r in all_rows:
        ts = r.get("visit_time_utc")
        if not ts:
            continue
        try:
            dt = datetime.fromisoformat(ts.replace("Z", ""))
            timestamps.append((dt, r))
        except Exception:
            continue

    if not timestamps:
        return findings

    now = datetime.utcnow()
    timestamps.sort(key=lambda x: x[0])

    # Detect future timestamps
    future = [(dt, r) for dt, r in timestamps if dt > now + timedelta(hours=24)]
    if future:
        findings.append({
            **meta, "browser": "analysis", "artifact": "anti_forensics",
            "profile": "all",
            "url": f"{len(future)} future timestamps detected",
            "title": "TIMESTAMP_MANIPULATION",
            "visit_count": len(future),
            "visit_time_utc": future[0][0].isoformat(),
            "extra": json.dumps({
                "type": "future_timestamps",
                "severity": 85,
                "count": len(future),
                "earliest_future": future[0][0].isoformat(),
                "detail": "Timestamps set in the future suggest clock manipulation or data fabrication"
            })
        })

    # Detect large time gaps in history (possible selective deletion)
    history_ts = [(dt, r) for dt, r in timestamps if r.get("artifact") == "history"]
    if len(history_ts) > 100:
        gaps = []
        for i in range(1, len(history_ts)):
            gap = (history_ts[i][0] - history_ts[i-1][0]).total_seconds()
            if gap > 86400 * 3:  # >3 day gap
                gaps.append({
                    "from": history_ts[i-1][0].isoformat(),
                    "to": history_ts[i][0].isoformat(),
                    "gap_days": round(gap / 86400, 1),
                })

        if len(gaps) > 5:
            findings.append({
                **meta, "browser": "analysis", "artifact": "anti_forensics",
                "profile": "all",
                "url": f"{len(gaps)} suspicious gaps in browsing history",
                "title": "HISTORY_GAPS",
                "visit_count": len(gaps),
                "visit_time_utc": None,
                "extra": json.dumps({
                    "type": "history_gaps",
                    "severity": 60,
                    "gaps": gaps[:10],
                    "detail": "Multiple large gaps in browsing history may indicate selective clearing"
                })
            })

    # Detect timestamp clustering (data was created in bulk)
    if len(timestamps) > 50:
        # Check if suspiciously many entries share the exact same second
        from collections import Counter
        second_counts = Counter(dt.replace(microsecond=0) for dt, _ in timestamps)
        bulk_seconds = [(ts, c) for ts, c in second_counts.items() if c > 20]
        if bulk_seconds:
            findings.append({
                **meta, "browser": "analysis", "artifact": "anti_forensics",
                "profile": "all",
                "url": f"{len(bulk_seconds)} bulk-timestamp clusters detected",
                "title": "BULK_TIMESTAMP_ANOMALY",
                "visit_count": sum(c for _, c in bulk_seconds),
                "visit_time_utc": bulk_seconds[0][0].isoformat(),
                "extra": json.dumps({
                    "type": "bulk_timestamps",
                    "severity": 70,
                    "detail": "Many records share identical timestamps — suggests data import or fabrication"
                })
            })

    return findings

# ---------------------------------------------------------------------------
# Chromium anti-forensics
# ---------------------------------------------------------------------------

def _detect_chromium_clearing(browser, path, meta, rows):
    """Detect signs of cleared Chromium browser data."""
    try:
        tmp = utils.safe_copy(path)
        if not tmp:
            return

        con = sqlite3.connect(str(tmp))
        cur = con.cursor()

        # Check if urls table has very few entries relative to profile age
        cur.execute("SELECT COUNT(*) FROM urls")
        url_count = cur.fetchone()[0]

        cur.execute("SELECT MIN(last_visit_time), MAX(last_visit_time) FROM urls")
        min_ts, max_ts = cur.fetchone()

        con.close()

        # Check profile creation time from Preferences file
        prefs_file = path.parent / "Preferences"
        profile_created = None
        if prefs_file.exists():
            try:
                prefs = json.loads(prefs_file.read_text(encoding="utf-8"))
                # Profile creation time in Chromium epoch
                created_ts = prefs.get("profile", {}).get("creation_time")
                if created_ts:
                    profile_created = utils.utc_from_webkit(int(created_ts))
            except Exception:
                pass

        # Heuristic: very low count for an old profile suggests clearing
        if url_count < 50 and profile_created:
            try:
                created_dt = datetime.fromisoformat(profile_created.replace("Z", ""))
                age_days = (datetime.utcnow() - created_dt).days
                if age_days > 30 and url_count < 50:
                    rows.append({
                        **meta, "browser": browser, "artifact": "anti_forensics",
                        "profile": str(path.parent),
                        "url": f"history_count={url_count}",
                        "title": "HISTORY_CLEARED",
                        "visit_count": url_count,
                        "visit_time_utc": None,
                        "extra": json.dumps({
                            "type": "history_cleared",
                            "severity": 75,
                            "profile_age_days": age_days,
                            "history_entries": url_count,
                            "detail": f"Profile is {age_days} days old but has only {url_count} history entries"
                        })
                    })
            except Exception:
                pass

        # Check for Chromium's "clear_browsing_data" preferences
        if prefs_file.exists():
            try:
                prefs = json.loads(prefs_file.read_text(encoding="utf-8"))
                cbd = prefs.get("browser", {}).get("clear_data", {})
                last_clear = prefs.get("browser", {}).get("last_clear_browsing_data_time")
                if last_clear:
                    rows.append({
                        **meta, "browser": browser, "artifact": "anti_forensics",
                        "profile": str(path.parent),
                        "url": "clear_browsing_data_used",
                        "title": "CLEAR_DATA_TIMESTAMP",
                        "visit_count": None,
                        "visit_time_utc": utils.utc_from_webkit(int(last_clear)) if last_clear else None,
                        "extra": json.dumps({
                            "type": "clear_data_used",
                            "severity": 65,
                            "last_clear_time": utils.utc_from_webkit(int(last_clear)),
                            "detail": "User explicitly cleared browsing data"
                        })
                    })
            except Exception:
                pass

    except Exception as e:
        utils.log_line(f"Error anti-forensics chromium: {e}")

def _detect_chromium_incognito_artifacts(browser, path, meta, rows):
    """Detect artifacts that may have leaked from incognito/private sessions."""
    # Check for DNS prefetch data that survives incognito
    prefs_file = path.parent / "Preferences"
    if prefs_file.exists():
        try:
            prefs = json.loads(prefs_file.read_text(encoding="utf-8"))
            # DNS prefetch data can leak incognito activity
            dns_prefetch = prefs.get("dns_prefetching", {}).get("host_referral_list")
            if dns_prefetch and len(dns_prefetch) > 0:
                leaked_domains = []
                for entry in dns_prefetch[:20]:
                    if isinstance(entry, list) and len(entry) > 0:
                        leaked_domains.append(str(entry[0]))
                    elif isinstance(entry, str):
                        leaked_domains.append(entry)

                if leaked_domains:
                    rows.append({
                        **meta, "browser": browser, "artifact": "anti_forensics",
                        "profile": str(path.parent),
                        "url": f"{len(leaked_domains)} DNS prefetch entries",
                        "title": "INCOGNITO_DNS_LEAK",
                        "visit_count": len(leaked_domains),
                        "visit_time_utc": None,
                        "extra": json.dumps({
                            "type": "incognito_leak",
                            "severity": 55,
                            "leaked_domains": leaked_domains[:10],
                            "detail": "DNS prefetch data may reveal sites visited in incognito mode"
                        })
                    })
        except Exception:
            pass

def _detect_db_vacuum(browser, path, meta, rows):
    """Detect if database was vacuumed (evidence destruction)."""
    try:
        tmp = utils.safe_copy(path)
        if not tmp:
            return
        con = sqlite3.connect(str(tmp))
        cur = con.cursor()

        # Check freelist count (0 after VACUUM)
        cur.execute("PRAGMA freelist_count")
        freelist = cur.fetchone()[0]

        # Check page count
        cur.execute("PRAGMA page_count")
        page_count = cur.fetchone()[0]

        con.close()

        # Zero freelist with many pages suggests recent VACUUM
        if freelist == 0 and page_count > 100:
            rows.append({
                **meta, "browser": browser, "artifact": "anti_forensics",
                "profile": str(path.parent),
                "url": f"freelist=0,pages={page_count}",
                "title": "DATABASE_VACUUMED",
                "visit_count": None,
                "visit_time_utc": None,
                "extra": json.dumps({
                    "type": "db_vacuum",
                    "severity": 50,
                    "page_count": page_count,
                    "detail": "Database has been vacuumed — deleted records cannot be recovered"
                })
            })
    except Exception as e:
        utils.log_line(f"Error vacuum detection: {e}")

# ---------------------------------------------------------------------------
# Firefox anti-forensics
# ---------------------------------------------------------------------------

def _detect_firefox_clearing(path, meta, rows):
    """Detect signs of cleared Firefox browser data."""
    if not path.is_dir():
        return
    for prof in path.glob("*.default*"):
        # Check for sanitize.json (clear-on-shutdown settings)
        prefs_js = prof / "prefs.js"
        if prefs_js.exists():
            try:
                content = prefs_js.read_text(encoding="utf-8", errors="replace")
                if "privacy.sanitize.sanitizeOnShutdown" in content and "true" in content:
                    rows.append({
                        **meta, "browser": "firefox", "artifact": "anti_forensics",
                        "profile": str(prof),
                        "url": "sanitize_on_shutdown=true",
                        "title": "AUTO_CLEAR_ON_SHUTDOWN",
                        "visit_count": None,
                        "visit_time_utc": None,
                        "extra": json.dumps({
                            "type": "auto_clear",
                            "severity": 60,
                            "detail": "Firefox configured to automatically clear data on shutdown"
                        })
                    })
            except Exception:
                pass

def _detect_firefox_private(path, meta, rows):
    """Detect Firefox private browsing indicators."""
    if not path.is_dir():
        return
    for prof in path.glob("*.default*"):
        # Check for always-private browsing mode
        prefs_js = prof / "prefs.js"
        if prefs_js.exists():
            try:
                content = prefs_js.read_text(encoding="utf-8", errors="replace")
                if "browser.privatebrowsing.autostart" in content and "true" in content:
                    rows.append({
                        **meta, "browser": "firefox", "artifact": "anti_forensics",
                        "profile": str(prof),
                        "url": "always_private_mode",
                        "title": "PERMANENT_PRIVATE_BROWSING",
                        "visit_count": None,
                        "visit_time_utc": None,
                        "extra": json.dumps({
                            "type": "permanent_private",
                            "severity": 70,
                            "detail": "Firefox is configured to always use private browsing — no history is recorded"
                        })
                    })
            except Exception:
                pass
