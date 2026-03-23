"""
Frostveil Session Parser — extract actual tab/window data from browser sessions.

Supports:
- Chromium SNSS format (Session/Tabs files) — binary command-based format
- Firefox sessionstore.jsonlz4 — LZ4-compressed JSON
"""
import json, struct
from pathlib import Path
from . import utils

def extract(browser, path: Path, meta):
    rows = []
    if browser in ["chrome", "edge"]:
        _extract_chromium_sessions(browser, path, meta, rows)
    elif browser == "firefox":
        _extract_firefox_sessions(path, meta, rows)
    return rows

# ---------------------------------------------------------------------------
# Chromium SNSS session parser
# ---------------------------------------------------------------------------

# SNSS command IDs (subset)
SNSS_CMD_SET_TAB_WINDOW = 0
SNSS_CMD_UPDATE_TAB_NAV = 6
SNSS_CMD_SET_SELECTED_NAV = 7
SNSS_CMD_SET_TAB_EXTENSION = 9
SNSS_CMD_SET_PINNED = 12

def _parse_snss(data: bytes) -> list:
    """
    Parse Chromium SNSS (Session/Tab) binary format.
    Format: "SNSS" magic + version(4) + repeated [size(2) + command_id(1) + payload]
    Extracts tab URLs and navigation entries.
    """
    entries = []
    if len(data) < 8:
        return entries
    # Check magic
    if data[:4] != b"SNSS":
        return entries

    pos = 8  # Skip magic + version
    while pos + 2 < len(data):
        try:
            # Read payload size (2 bytes, little-endian)
            size = struct.unpack_from("<H", data, pos)[0]
            pos += 2
            if size == 0 or pos + size > len(data):
                break
            payload = data[pos:pos + size]
            pos += size

            if len(payload) < 1:
                continue
            cmd_id = payload[0]

            # Command 6: UpdateTabNavigation — contains URL
            if cmd_id == SNSS_CMD_UPDATE_TAB_NAV and len(payload) > 10:
                _parse_nav_entry(payload[1:], entries)

        except Exception:
            break

    return entries

def _parse_nav_entry(data: bytes, entries: list):
    """Extract URL and title from a navigation entry payload."""
    try:
        # Navigation entries have: tab_id(4) + index(4) + url_length(4) + url + ...
        if len(data) < 12:
            return
        # Try to find URL string in the payload
        # URLs are stored as length-prefixed strings
        text = data.decode("utf-8", errors="replace")
        # Extract URLs using pattern matching
        import re
        urls = re.findall(r'https?://[^\x00\x01\x02\x03\x04\x05\s]{5,500}', text)
        for url in urls:
            # Try to find title near the URL
            url_pos = text.find(url)
            # Get surrounding text as potential title
            after = text[url_pos + len(url):url_pos + len(url) + 200]
            title = ""
            # Title is often the next readable string
            readable = re.findall(r'[\x20-\x7e]{5,100}', after)
            if readable:
                title = readable[0].strip()

            entries.append({"url": url, "title": title})
    except Exception:
        pass

def _extract_chromium_sessions(browser, path, meta, rows):
    """Extract session data from Chromium Session and Tabs files."""
    session_dir = path.parent
    session_files = []

    # Current Tabs, Current Session, Last Tabs, Last Session
    for name in ["Current Tabs", "Current Session", "Last Tabs", "Last Session"]:
        sf = session_dir / name
        if sf.exists():
            session_files.append((name, sf))

    # Also check Sessions directory
    sessions_dir = session_dir / "Sessions"
    if sessions_dir.exists():
        for sf in sessions_dir.glob("*"):
            if sf.is_file() and sf.stat().st_size > 8:
                session_files.append((sf.name, sf))

    for sess_name, sess_file in session_files:
        try:
            raw = sess_file.read_bytes()
            entries = _parse_snss(raw)

            if entries:
                for entry in entries:
                    rows.append({
                        **meta, "browser": browser, "artifact": "session",
                        "profile": str(path.parent),
                        "url": entry.get("url", ""),
                        "title": entry.get("title", ""),
                        "visit_count": None,
                        "visit_time_utc": None,
                        "extra": json.dumps({
                            "source_file": sess_name,
                            "file_size": len(raw),
                        })
                    })
            else:
                # Fallback: extract URLs with regex from raw bytes
                _extract_urls_from_binary(raw, browser, path, meta, rows, sess_name)

        except Exception as e:
            utils.log_line(f"Error session {browser} {sess_name}: {e}")

def _extract_urls_from_binary(data: bytes, browser, path, meta, rows, source):
    """Fallback URL extraction from binary session data."""
    import re
    text = data.decode("utf-8", errors="replace")
    urls = set(re.findall(r'https?://[^\x00-\x1f\s"\'<>]{10,500}', text))
    for url in urls:
        rows.append({
            **meta, "browser": browser, "artifact": "session",
            "profile": str(path.parent),
            "url": url,
            "title": "",
            "visit_count": None,
            "visit_time_utc": None,
            "extra": json.dumps({"source_file": source, "method": "binary_regex"})
        })

# ---------------------------------------------------------------------------
# Firefox sessionstore.jsonlz4 parser
# ---------------------------------------------------------------------------

def _decompress_mozlz4(data: bytes) -> bytes:
    """
    Decompress Firefox mozlz4 format.
    Format: b'mozLz40\0' + lz4 block compressed data.
    Uses pure-Python LZ4 block decompression.
    """
    if data[:8] != b"mozLz40\0":
        raise ValueError("Not a mozlz4 file")
    compressed = data[8:]
    return _lz4_block_decompress(compressed)

def _lz4_block_decompress(data: bytes) -> bytes:
    """
    Pure-Python LZ4 block decompression.
    LZ4 block format: sequences of (token + [literal_length] + literals + [match_offset] + [match_length])
    """
    if len(data) < 4:
        return b""

    # First 4 bytes: original (uncompressed) size (little-endian)
    orig_size = struct.unpack_from("<I", data, 0)[0]
    pos = 4
    output = bytearray()

    while pos < len(data):
        token = data[pos]
        pos += 1

        # Literal length
        lit_len = (token >> 4) & 0x0F
        if lit_len == 15:
            while pos < len(data):
                extra = data[pos]
                pos += 1
                lit_len += extra
                if extra != 255:
                    break

        # Copy literals
        if pos + lit_len > len(data):
            output.extend(data[pos:])
            break
        output.extend(data[pos:pos + lit_len])
        pos += lit_len

        if pos >= len(data):
            break

        # Match offset (2 bytes, little-endian)
        if pos + 2 > len(data):
            break
        offset = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        if offset == 0:
            break

        # Match length
        match_len = (token & 0x0F) + 4
        if match_len == 19:  # 15 + 4
            while pos < len(data):
                extra = data[pos]
                pos += 1
                match_len += extra
                if extra != 255:
                    break

        # Copy match (may overlap)
        match_start = len(output) - offset
        if match_start < 0:
            break
        for i in range(match_len):
            output.append(output[match_start + i])

    return bytes(output[:orig_size])

def _extract_firefox_sessions(path, meta, rows):
    """Extract Firefox session data from sessionstore.jsonlz4."""
    if not path.is_dir():
        return
    for prof in path.glob("*.default*"):
        # Current session
        ss = prof / "sessionstore.jsonlz4"
        if ss.exists():
            _parse_firefox_session_file(ss, prof, meta, rows, "current")

        # Session backups
        backup_dir = prof / "sessionstore-backups"
        if backup_dir.exists():
            for backup in backup_dir.glob("*.jsonlz4"):
                _parse_firefox_session_file(backup, prof, meta, rows, backup.name)
            for backup in backup_dir.glob("*.json"):
                try:
                    data = json.loads(backup.read_text(encoding="utf-8"))
                    _extract_session_tabs(data, prof, meta, rows, backup.name)
                except Exception:
                    pass

def _parse_firefox_session_file(filepath, prof, meta, rows, source):
    """Parse a single Firefox session file."""
    try:
        raw = filepath.read_bytes()
        decompressed = _decompress_mozlz4(raw)
        data = json.loads(decompressed.decode("utf-8"))
        _extract_session_tabs(data, prof, meta, rows, source)
    except Exception as e:
        utils.log_line(f"Error firefox session {filepath}: {e}")

def _extract_session_tabs(session_data: dict, prof, meta, rows, source):
    """Extract tabs from Firefox session JSON data."""
    windows = session_data.get("windows", [])
    for win_idx, window in enumerate(windows):
        tabs = window.get("tabs", [])
        for tab in tabs:
            entries = tab.get("entries", [])
            for entry in entries:
                url = entry.get("url", "")
                title = entry.get("title", "")
                if url and url not in ("about:blank", "about:newtab", "about:home"):
                    rows.append({
                        **meta, "browser": "firefox", "artifact": "session",
                        "profile": str(prof),
                        "url": url,
                        "title": title,
                        "visit_count": None,
                        "visit_time_utc": None,
                        "extra": json.dumps({
                            "source": source,
                            "window": win_idx,
                            "scroll_position": entry.get("scroll", ""),
                        })
                    })

    # Also extract recently closed tabs
    closed_tabs = session_data.get("_closedTabs", [])
    for ct in closed_tabs:
        state = ct.get("state", {})
        entries = state.get("entries", [])
        for entry in entries:
            url = entry.get("url", "")
            title = entry.get("title", "")
            if url:
                rows.append({
                    **meta, "browser": "firefox", "artifact": "session",
                    "profile": str(prof),
                    "url": url,
                    "title": f"[CLOSED] {title}",
                    "visit_count": None,
                    "visit_time_utc": None,
                    "extra": json.dumps({"source": source, "status": "closed_tab"})
                })
