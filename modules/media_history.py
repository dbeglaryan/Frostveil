import json
import sqlite3
from collections import Counter
from datetime import datetime
from pathlib import Path
from . import utils


def extract(browser, path: Path, meta):
    """
    Extract media playback history from Chromium's Media History database.
    Chromium-only (chrome, edge); Firefox does not use this database.
    """
    rows = []

    if browser not in ("chrome", "edge"):
        return rows

    media_db = path.parent / "Media History"
    tmp = utils.safe_copy(media_db)
    if not tmp:
        return rows

    try:
        con = sqlite3.connect(str(tmp))
        cur = con.cursor()

        # ---- playbackSession: media playback history ----
        cur.execute(
            "SELECT id, url, duration_ms, position_ms, title, artist, "
            "album, source_title, last_updated_time_s FROM playbackSession"
        )
        for sid, url, dur, pos, title, artist, album, source, ts in cur.fetchall():
            extra = {
                "session_id": sid,
                "duration_ms": dur,
                "position_ms": pos,
                "artist": artist or "",
                "album": album or "",
                "source_title": source or "",
            }
            rows.append({
                **meta,
                "browser": browser,
                "artifact": "media_playback",
                "profile": str(path.parent),
                "url": url,
                "title": title or "",
                "visit_time_utc": _utc_from_epoch_s(ts),
                "extra": json.dumps(extra),
            })

        # ---- origin: media watchtime per origin ----
        cur.execute(
            "SELECT id, origin, last_updated_time_s, "
            "audio_video_watchtime_s, media_image_count FROM origin"
        )
        for oid, origin, ts, watchtime, img_count in cur.fetchall():
            extra = {
                "origin_id": oid,
                "audio_video_watchtime_s": watchtime,
                "media_image_count": img_count,
            }
            rows.append({
                **meta,
                "browser": browser,
                "artifact": "media_watchtime",
                "profile": str(path.parent),
                "url": origin,
                "title": "",
                "visit_time_utc": _utc_from_epoch_s(ts),
                "extra": json.dumps(extra),
            })

        con.close()
        utils.log_line(f"Media History extracted from {media_db}")
    except Exception as e:
        utils.log_line(f"Error media_history {browser} {media_db}: {e}")

    return rows


def summarize(rows):
    """Return summary statistics for media history rows."""
    playbacks = [r for r in rows if r["artifact"] == "media_playback"]
    origins = [r for r in rows if r["artifact"] == "media_watchtime"]

    total_watchtime_s = 0
    watchtime_by_origin = Counter()
    for r in origins:
        extra = json.loads(r.get("extra", "{}"))
        wt = extra.get("audio_video_watchtime_s", 0) or 0
        total_watchtime_s += wt
        watchtime_by_origin[r["url"]] += wt

    top_origins = [
        {"origin": origin, "watchtime_s": wt}
        for origin, wt in watchtime_by_origin.most_common(10)
    ]

    unique_titles = {r["title"] for r in playbacks if r["title"]}

    return {
        "total_playbacks": len(playbacks),
        "total_origins": len(origins),
        "total_watchtime_hours": round(total_watchtime_s / 3600, 2),
        "top_origins": top_origins,
        "unique_media_titles": sorted(unique_titles),
    }


# ---- internal helper ----

def _utc_from_epoch_s(ts):
    """Convert Unix epoch seconds to UTC ISO string."""
    if not ts or ts == 0:
        return None
    try:
        return datetime.utcfromtimestamp(ts).isoformat()
    except (OSError, ValueError, OverflowError):
        return None
