"""
Frostveil Search Extraction — with URL resolution via JOIN.

Resolves search terms to their actual result URLs by joining
keyword_search_terms with the urls table.
"""
import sqlite3, json
from pathlib import Path
from . import utils

def extract(browser, path: Path, meta):
    rows = []
    if browser in ["chrome", "edge"]:
        _extract_chromium_searches(browser, path, meta, rows)
    elif browser == "firefox":
        _extract_firefox_searches(path, meta, rows)
    return rows

def _extract_chromium_searches(browser, path, meta, rows):
    tmp = utils.safe_copy(path)
    if not tmp:
        return
    try:
        con = sqlite3.connect(str(tmp))
        cur = con.cursor()
        # JOIN with urls table to resolve the actual search URL and timestamp
        cur.execute("""
            SELECT k.term, u.url, u.title, u.visit_count, u.last_visit_time
            FROM keyword_search_terms k
            JOIN urls u ON k.url_id = u.id
            ORDER BY u.last_visit_time DESC
        """)
        for term, url, title, visit_count, ts in cur.fetchall():
            # Extract search engine from URL
            engine = _identify_search_engine(url)
            rows.append({
                **meta, "browser": browser, "artifact": "search",
                "profile": str(path.parent),
                "url": url,
                "title": term,
                "visit_count": visit_count,
                "visit_time_utc": utils.utc_from_webkit(ts),
                "extra": json.dumps({
                    "search_engine": engine,
                    "result_title": title or "",
                })
            })
        con.close()
        utils.log_line(f"Searches extracted from {path} ({len(rows)} terms)")
    except Exception as e:
        utils.log_line(f"Error searches {browser}: {e}")

def _extract_firefox_searches(path, meta, rows):
    profs = path.glob("*.default*") if path.is_dir() else []
    for prof in profs:
        fh = prof / "formhistory.sqlite"
        tmp = utils.safe_copy(fh)
        if not tmp:
            continue
        try:
            con = sqlite3.connect(str(tmp))
            cur = con.cursor()
            cur.execute("""
                SELECT fieldname, value, timesUsed, firstUsed, lastUsed
                FROM moz_formhistory
                ORDER BY lastUsed DESC
            """)
            for fn, val, times, first_used, last_used in cur.fetchall():
                # Separate actual search fields from other form data
                is_search = fn.lower() in ("searchbar-history", "q", "query",
                                            "search", "search_query", "s",
                                            "search_term", "wd", "p")
                rows.append({
                    **meta, "browser": "firefox", "artifact": "search",
                    "profile": str(prof),
                    "url": "",
                    "title": val,
                    "visit_count": times,
                    "visit_time_utc": utils.utc_from_unix(last_used),
                    "extra": json.dumps({
                        "field_name": fn,
                        "is_search_field": is_search,
                        "first_used": utils.utc_from_unix(first_used),
                    })
                })
            con.close()
        except Exception as e:
            utils.log_line(f"Error searches firefox {prof}: {e}")

def _identify_search_engine(url: str) -> str:
    """Identify which search engine was used from the URL."""
    url_lower = url.lower()
    engines = {
        "google.com/search": "Google",
        "google.com/webhp": "Google",
        "bing.com/search": "Bing",
        "duckduckgo.com": "DuckDuckGo",
        "yahoo.com/search": "Yahoo",
        "yandex.com/search": "Yandex",
        "baidu.com/s": "Baidu",
        "search.brave.com": "Brave",
        "ecosia.org/search": "Ecosia",
        "startpage.com": "Startpage",
    }
    for pattern, name in engines.items():
        if pattern in url_lower:
            return name
    return "unknown"
