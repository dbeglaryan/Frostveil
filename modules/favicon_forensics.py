"""
Frostveil Favicon Forensics — extract visited site evidence from favicon databases.

Browsers cache favicons (site icons) in a separate database that is often
NOT cleared when users clear their browsing history. This makes favicons
one of the most powerful forensic artifacts for proving a site was visited.

Supports:
- Chromium Favicons database (favicon_bitmaps + icon_mapping + favicons tables)
- Firefox favicons.sqlite (moz_icons + moz_pages_w_icons)
"""
import sqlite3, json, hashlib, base64
from pathlib import Path
from . import utils

def extract(browser, path: Path, meta) -> list:
    rows = []
    if browser in ("chrome", "edge"):
        _extract_chromium_favicons(browser, path, meta, rows)
    elif browser == "firefox":
        _extract_firefox_favicons(path, meta, rows)
    return rows

def _extract_chromium_favicons(browser, path, meta, rows):
    """
    Extract favicons from Chromium's Favicons database.
    Tables: favicons, favicon_bitmaps, icon_mapping
    """
    fav_db = path.parent / "Favicons"
    tmp = utils.safe_copy(fav_db)
    if not tmp:
        return

    try:
        con = sqlite3.connect(str(tmp))
        cur = con.cursor()

        # Get URL → favicon mappings with bitmap data
        cur.execute("""
            SELECT
                im.page_url,
                f.url AS icon_url,
                fb.last_updated,
                fb.width,
                fb.height,
                LENGTH(fb.image_data) as data_size
            FROM icon_mapping im
            JOIN favicons f ON im.icon_id = f.id
            LEFT JOIN favicon_bitmaps fb ON f.id = fb.icon_id
            ORDER BY fb.last_updated DESC
        """)

        seen_pages = set()
        for page_url, icon_url, last_updated, width, height, data_size in cur.fetchall():
            if page_url in seen_pages:
                continue
            seen_pages.add(page_url)

            rows.append({
                **meta, "browser": browser, "artifact": "favicon",
                "profile": str(path.parent),
                "url": page_url,
                "title": icon_url or "",
                "visit_count": None,
                "visit_time_utc": utils.utc_from_webkit(last_updated) if last_updated else None,
                "extra": json.dumps({
                    "icon_url": icon_url,
                    "width": width,
                    "height": height,
                    "data_size": data_size or 0,
                })
            })

        con.close()
        utils.log_line(f"Favicons extracted: {len(rows)} from {fav_db}")
    except Exception as e:
        utils.log_line(f"Error favicons {browser}: {e}")

def _extract_firefox_favicons(path, meta, rows):
    """Extract favicons from Firefox favicons.sqlite."""
    if not path.is_dir():
        return
    for prof in path.glob("*.default*"):
        fav_db = prof / "favicons.sqlite"
        tmp = utils.safe_copy(fav_db)
        if not tmp:
            continue

        try:
            con = sqlite3.connect(str(tmp))
            cur = con.cursor()

            cur.execute("""
                SELECT
                    pwi.page_url,
                    i.icon_url,
                    i.fixed_icon_url_hash,
                    i.width,
                    LENGTH(i.data) as data_size,
                    i.expire_ms
                FROM moz_pages_w_icons pwi
                JOIN moz_icons_to_pages itp ON pwi.id = itp.page_id
                JOIN moz_icons i ON itp.icon_id = i.id
                ORDER BY i.expire_ms DESC
            """)

            seen = set()
            for page_url, icon_url, icon_hash, width, data_size, expire_ms in cur.fetchall():
                if page_url in seen:
                    continue
                seen.add(page_url)

                rows.append({
                    **meta, "browser": "firefox", "artifact": "favicon",
                    "profile": str(prof),
                    "url": page_url,
                    "title": icon_url or "",
                    "visit_count": None,
                    "visit_time_utc": utils.utc_from_unix(expire_ms * 1000) if expire_ms else None,
                    "extra": json.dumps({
                        "icon_url": icon_url,
                        "width": width,
                        "data_size": data_size or 0,
                    })
                })

            con.close()
            utils.log_line(f"Firefox favicons: {len(rows)} from {fav_db}")
        except Exception as e:
            utils.log_line(f"Error favicons firefox {prof}: {e}")


def cross_reference_with_history(favicon_rows: list, history_rows: list) -> list:
    """
    Find favicons for sites NOT in history — proves visits after history clearing.
    This is the killer feature: evidence the user tried to erase.
    """
    history_urls = set()
    for r in history_rows:
        if r.get("artifact") == "history":
            history_urls.add(r.get("url", ""))

    ghost_visits = []
    for r in favicon_rows:
        if r.get("artifact") == "favicon":
            url = r.get("url", "")
            if url and url not in history_urls:
                ghost = dict(r)
                ghost["artifact"] = "ghost_visit"
                try:
                    extra = json.loads(ghost.get("extra", "{}"))
                    extra["evidence"] = "favicon_exists_but_history_cleared"
                    extra["forensic_significance"] = "HIGH"
                    ghost["extra"] = json.dumps(extra)
                except Exception:
                    pass
                ghost_visits.append(ghost)

    return ghost_visits
