"""
Frostveil Site Engagement — extract Chromium Site Engagement Scores
from the Preferences JSON file.

Site Engagement is a per-site score (0–100) that Chromium maintains
based on user interaction (clicks, scrolls, typing, media playback).
Forensically useful for establishing which sites a user actively
engaged with vs. passively visited.
"""
import json
from pathlib import Path
from . import utils


def extract(browser, path: Path, meta) -> list:
    """Extract site engagement scores from Chromium Preferences."""
    rows = []
    if browser == "firefox":
        return rows

    prefs_file = path.parent / "Preferences"
    if not prefs_file.exists():
        return rows

    try:
        prefs = json.loads(prefs_file.read_text(encoding="utf-8"))
        engagement = (
            prefs.get("profile", {})
                 .get("content_settings", {})
                 .get("exceptions", {})
                 .get("site_engagement", {})
        )
        if not engagement:
            return rows

        for key, value in engagement.items():
            site_url = key.rstrip(",*").rstrip(",")
            setting = value.get("setting", {}) if isinstance(value, dict) else {}
            raw_score = setting.get("rawScore", 0.0)
            points_today = setting.get("pointsAddedToday", 0.0)
            last_engagement = setting.get("lastEngagementTime", 0.0)

            last_engagement_utc = utils.utc_from_webkit(last_engagement) if last_engagement else None

            extra = json.dumps({
                "rawScore": raw_score,
                "pointsAddedToday": points_today,
                "lastEngagementTime": last_engagement_utc,
            })

            rows.append({
                **meta,
                "browser": browser,
                "artifact": "site_engagement",
                "profile": str(path.parent),
                "url": site_url,
                "title": str(raw_score),
                "visit_count": None,
                "visit_time_utc": last_engagement_utc,
                "extra": extra,
            })

        utils.log_line(f"Site engagement extracted from {prefs_file}")
    except Exception as e:
        utils.log_line(f"Error site_engagement {browser} {path}: {e}")

    return rows


def summarize(rows) -> dict:
    """Summarize site engagement rows."""
    engagement_rows = [r for r in rows if r.get("artifact") == "site_engagement"]
    if not engagement_rows:
        return {"total_sites": 0, "top_engaged": [], "average_score": 0.0, "high_engagement_count": 0}

    scores = []
    for r in engagement_rows:
        try:
            extra = json.loads(r.get("extra", "{}"))
            scores.append((r.get("url", ""), extra.get("rawScore", 0.0)))
        except (json.JSONDecodeError, TypeError):
            scores.append((r.get("url", ""), 0.0))

    scores.sort(key=lambda x: x[1], reverse=True)
    all_scores = [s for _, s in scores]

    return {
        "total_sites": len(scores),
        "top_engaged": [{"url": url, "score": score} for url, score in scores[:20]],
        "average_score": round(sum(all_scores) / len(all_scores), 2),
        "high_engagement_count": sum(1 for s in all_scores if s > 50),
    }
