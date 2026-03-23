"""
Frostveil Visited Links — decode Chromium's Visited Links bloom filter.

Chromium stores a bloom filter of visited URLs in the "Visited Links" file.
This persists even after history is cleared and can be used to TEST whether
a specific URL was visited (probabilistic — false positives possible).

Also extracts "Top Sites" and "Network Action Predictor" data.
"""
import struct, hashlib, json
from pathlib import Path
from . import utils

def extract(browser, path: Path, meta) -> list:
    rows = []
    if browser in ("chrome", "edge"):
        _extract_top_sites(browser, path, meta, rows)
        _extract_network_predictor(browser, path, meta, rows)
        _extract_shortcuts(browser, path, meta, rows)
    return rows

# ---------------------------------------------------------------------------
# Top Sites
# ---------------------------------------------------------------------------

def _extract_top_sites(browser, path, meta, rows):
    """Extract Chromium Top Sites database — most visited pages."""
    top_sites = path.parent / "Top Sites"
    tmp = utils.safe_copy(top_sites)
    if not tmp:
        return

    try:
        import sqlite3
        con = sqlite3.connect(str(tmp))
        cur = con.cursor()

        # Try newer schema
        try:
            cur.execute("""
                SELECT url, url_rank, title, redirects
                FROM top_sites ORDER BY url_rank ASC
            """)
            for url, rank, title, redirects in cur.fetchall():
                rows.append({
                    **meta, "browser": browser, "artifact": "top_site",
                    "profile": str(path.parent),
                    "url": url,
                    "title": title or "",
                    "visit_count": rank,
                    "visit_time_utc": None,
                    "extra": json.dumps({"rank": rank, "redirects": redirects or ""})
                })
        except Exception:
            # Older schema
            try:
                cur.execute("SELECT url, title FROM thumbnails ORDER BY boring_score ASC")
                for url, title in cur.fetchall():
                    rows.append({
                        **meta, "browser": browser, "artifact": "top_site",
                        "profile": str(path.parent),
                        "url": url,
                        "title": title or "",
                        "visit_count": None,
                        "visit_time_utc": None,
                        "extra": '{"source":"thumbnails"}'
                    })
            except Exception:
                pass

        con.close()
        utils.log_line(f"Top Sites extracted: {len(rows)} from {top_sites}")
    except Exception as e:
        utils.log_line(f"Error top sites {browser}: {e}")

# ---------------------------------------------------------------------------
# Network Action Predictor
# ---------------------------------------------------------------------------

def _extract_network_predictor(browser, path, meta, rows):
    """
    Extract Chromium Network Action Predictor database.
    This contains URL predictions based on typing patterns —
    reveals what URLs the user frequently types.
    """
    predictor_db = path.parent / "Network Action Predictor"
    tmp = utils.safe_copy(predictor_db)
    if not tmp:
        return

    try:
        import sqlite3
        con = sqlite3.connect(str(tmp))
        cur = con.cursor()

        cur.execute("""
            SELECT user_text, url, number_of_hits, number_of_misses
            FROM resource_prefetch_predictor_url
            ORDER BY number_of_hits DESC
        """)

        for typed, url, hits, misses in cur.fetchall():
            rows.append({
                **meta, "browser": browser, "artifact": "url_prediction",
                "profile": str(path.parent),
                "url": url,
                "title": typed,
                "visit_count": hits,
                "visit_time_utc": None,
                "extra": json.dumps({
                    "typed_text": typed,
                    "hits": hits,
                    "misses": misses,
                    "confidence": round(hits / max(hits + misses, 1) * 100, 1),
                })
            })

        con.close()
    except Exception as e:
        utils.log_line(f"Error network predictor {browser}: {e}")

# ---------------------------------------------------------------------------
# Shortcuts (omnibox suggestions)
# ---------------------------------------------------------------------------

def _extract_shortcuts(browser, path, meta, rows):
    """
    Extract Chromium Shortcuts database — omnibox (address bar) suggestions.
    Contains URLs the user typed or selected from autocomplete.
    Persists after history clearing.
    """
    shortcuts_db = path.parent / "Shortcuts"
    tmp = utils.safe_copy(shortcuts_db)
    if not tmp:
        return

    try:
        import sqlite3
        con = sqlite3.connect(str(tmp))
        cur = con.cursor()

        cur.execute("""
            SELECT text, fill_into_edit, url, contents, description,
                   last_access_time, number_of_hits
            FROM omni_box_shortcuts
            ORDER BY number_of_hits DESC
        """)

        for text, fill, url, contents, desc, last_access, hits in cur.fetchall():
            rows.append({
                **meta, "browser": browser, "artifact": "shortcut",
                "profile": str(path.parent),
                "url": url,
                "title": text or contents or "",
                "visit_count": hits,
                "visit_time_utc": utils.utc_from_webkit(last_access),
                "extra": json.dumps({
                    "typed_text": text,
                    "fill_text": fill,
                    "description": desc or "",
                    "hits": hits,
                })
            })

        con.close()
        utils.log_line(f"Shortcuts extracted from {shortcuts_db}")
    except Exception as e:
        utils.log_line(f"Error shortcuts {browser}: {e}")

# ---------------------------------------------------------------------------
# Visited Links bloom filter probe
# ---------------------------------------------------------------------------

def _fingerprint_url(url: str) -> int:
    """
    Compute Chromium's visited-link fingerprint for a URL.
    Chromium uses a custom hash based on the URL.
    """
    h = hashlib.md5(url.encode("utf-8")).digest()
    return struct.unpack_from("<Q", h, 0)[0]

def load_visited_links(path: Path) -> dict:
    """
    Load the Visited Links bloom filter.
    Returns a dict with the filter data and parameters.
    """
    vl_path = path.parent / "Visited Links"
    if not vl_path.exists():
        return None

    try:
        data = vl_path.read_bytes()
        if len(data) < 24:
            return None

        # Header: hash_count(4) + salt(8) + table_size_bytes(4) + ...
        # The exact format varies by Chromium version
        return {
            "data": data,
            "size": len(data),
            "path": str(vl_path),
        }
    except Exception:
        return None

def probe_url(bloom_data: dict, url: str) -> bool:
    """
    Test if a URL was likely visited using the bloom filter.
    Returns True if the URL is probably in the filter (may have false positives).
    """
    if not bloom_data:
        return False
    # This is a simplified probe — exact Chromium bloom filter implementation
    # varies by version. The fingerprint approach gives an approximation.
    fp = _fingerprint_url(url)
    data = bloom_data["data"]
    # Check multiple bit positions derived from the fingerprint
    for i in range(3):
        bit_pos = (fp + i * 0x9e3779b97f4a7c15) % (len(data) * 8)
        byte_pos = bit_pos // 8
        bit_offset = bit_pos % 8
        if byte_pos < len(data):
            if not (data[byte_pos] & (1 << bit_offset)):
                return False
    return True
