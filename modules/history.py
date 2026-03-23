import sqlite3
from pathlib import Path
from . import utils

def extract(browser, path: Path, meta):
    """
    Extract browsing history from Chrome, Edge, and Firefox.
    Live records only (no deleted record carving).
    """
    rows = []

    # ---- Chromium family (Chrome/Edge) ----
    if browser in ["chrome", "edge"]:
        tmp = utils.safe_copy(path)
        if not tmp:
            return rows
        try:
            con = sqlite3.connect(str(tmp))
            cur = con.cursor()
            cur.execute("SELECT url, title, visit_count, last_visit_time FROM urls")
            for url, title, vc, ts in cur.fetchall():
                rows.append({
                    **meta,
                    "browser": browser,
                    "artifact": "history",
                    "profile": str(path.parent),
                    "url": url,
                    "title": title or "",
                    "visit_count": vc,
                    "visit_time_utc": utils.utc_from_webkit(ts),
                    "extra": ""
                })
            con.close()
            utils.log_line(f"History extracted from {path}")
        except Exception as e:
            utils.log_line(f"Error history {browser} {path}: {e}")

    # ---- Firefox ----
    elif browser == "firefox":
        if path.is_dir():
            for prof in path.glob("*.default*"):
                db = prof / "places.sqlite"
                tmp = utils.safe_copy(db)
                if not tmp:
                    continue
                try:
                    con = sqlite3.connect(str(tmp))
                    cur = con.cursor()
                    cur.execute("SELECT url, title, visit_count, last_visit_date FROM moz_places")
                    for url, title, vc, ts in cur.fetchall():
                        rows.append({
                            **meta,
                            "browser": "firefox",
                            "artifact": "history",
                            "profile": str(prof),
                            "url": url,
                            "title": title or "",
                            "visit_count": vc,
                            "visit_time_utc": utils.utc_from_unix(ts),
                            "extra": ""
                        })
                    con.close()
                    utils.log_line(f"History extracted from {db}")
                except Exception as e:
                    utils.log_line(f"Error history firefox {prof}: {e}")

    return rows
