import sqlite3
from pathlib import Path
from . import utils

def extract(browser, path: Path, meta):
    rows = []
    if browser in ["chrome","edge"]:
        tmp = utils.safe_copy(path)
        if not tmp: return rows
        try:
            con = sqlite3.connect(str(tmp))
            cur = con.cursor()
            cur.execute("SELECT tab_url, target_path, start_time FROM downloads JOIN downloads_url_chains ON downloads.id=downloads_url_chains.id")
            for url, target, ts in cur.fetchall():
                rows.append({
                    **meta, "browser": browser, "artifact": "download",
                    "profile": str(path.parent), "url": url, "title": target,
                    "visit_count": None, "visit_time_utc": utils.utc_from_webkit(ts), "extra": ""
                })
            con.close()
        except Exception as e:
            utils.log_line(f"Error downloads {browser}: {e}")
    elif browser=="firefox":
        profs = path.glob("*.default*") if path.is_dir() else []
        for prof in profs:
            dl = prof / "downloads.sqlite"
            tmp = utils.safe_copy(dl)
            if not tmp: continue
            try:
                con = sqlite3.connect(str(tmp))
                cur = con.cursor()
                cur.execute("SELECT source, target, startTime FROM moz_downloads")
                for src, tgt, ts in cur.fetchall():
                    rows.append({
                        **meta, "browser": "firefox", "artifact": "download",
                        "profile": str(prof), "url": src, "title": tgt,
                        "visit_count": None, "visit_time_utc": utils.utc_from_unix(ts), "extra": ""
                    })
                con.close()
            except Exception as e:
                utils.log_line(f"Error downloads firefox {prof}: {e}")
    return rows
