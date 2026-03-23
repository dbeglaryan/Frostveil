import json
from pathlib import Path
from . import utils

def extract(browser, path: Path, meta):
    rows = []
    if browser in ["chrome","edge"]:
        bm_file = path.parent / "Bookmarks"
        if bm_file.exists():
            try:
                data = json.loads(bm_file.read_text(encoding="utf-8"))
                def walk(node):
                    if isinstance(node, dict):
                        if node.get("type")=="url":
                            rows.append({
                                **meta, "browser": browser, "artifact": "bookmark",
                                "profile": str(path.parent), "url": node.get("url",""),
                                "title": node.get("name",""), "visit_count": None,
                                "visit_time_utc": None, "extra": ""
                            })
                        for v in node.values(): walk(v)
                    elif isinstance(node, list):
                        for v in node: walk(v)
                walk(data)
                utils.log_line(f"Bookmarks extracted from {bm_file}")
            except Exception as e:
                utils.log_line(f"Error bookmarks {browser}: {e}")
    elif browser=="firefox":
        profs = path.glob("*.default*") if path.is_dir() else []
        for prof in profs:
            bm_file = prof / "places.sqlite"
            tmp = utils.safe_copy(bm_file)
            if not tmp: continue
            try:
                import sqlite3
                con = sqlite3.connect(str(tmp))
                cur = con.cursor()
                cur.execute("SELECT url, title FROM moz_places WHERE title IS NOT NULL")
                for url, title in cur.fetchall():
                    rows.append({
                        **meta, "browser": "firefox", "artifact": "bookmark",
                        "profile": str(prof), "url": url, "title": title,
                        "visit_count": None, "visit_time_utc": None, "extra": ""
                    })
                con.close()
            except Exception as e:
                utils.log_line(f"Error bookmarks firefox {prof}: {e}")
    return rows
