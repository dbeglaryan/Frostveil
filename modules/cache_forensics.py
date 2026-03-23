"""
Frostveil Cache Forensics — extract cached pages, images, API responses.

Chromium uses a custom disk cache format (blockfile or simple cache).
This module parses both formats to recover cached web content metadata.
"""
import struct, json, re, os, hashlib
from pathlib import Path
from datetime import datetime
from . import utils

def extract(browser, path: Path, meta) -> list:
    rows = []
    if browser in ("chrome", "edge"):
        _extract_chromium_cache(browser, path, meta, rows)
    elif browser == "firefox":
        _extract_firefox_cache(path, meta, rows)
    return rows

# ---------------------------------------------------------------------------
# Chromium Simple Cache parser
# ---------------------------------------------------------------------------

# Simple cache entry header (at the end of _0 stream files)
SIMPLE_EOF_MAGIC = 0xd4a018c8
SIMPLE_INITIAL_MAGIC = 0xfcfb6d1ba7725c30

def _extract_chromium_cache(browser, path, meta, rows):
    """Extract Chromium cache entries."""
    cache_dir = path.parent / "Cache" / "Cache_Data"
    if not cache_dir.exists():
        cache_dir = path.parent / "Cache"
    if not cache_dir.exists():
        return

    try:
        # Simple cache format: files named with hex hash
        # Each entry file has: key (URL) embedded in the data
        count = 0
        for entry_file in cache_dir.iterdir():
            if not entry_file.is_file():
                continue
            if entry_file.name in ("index", "index-dir", "the-real-index"):
                continue
            if entry_file.stat().st_size < 40:
                continue

            try:
                entry = _parse_simple_cache_entry(entry_file)
                if entry and entry.get("url"):
                    content_type = entry.get("content_type", "")
                    cache_size = entry.get("size", 0)

                    rows.append({
                        **meta, "browser": browser, "artifact": "cache",
                        "profile": str(path.parent),
                        "url": entry["url"],
                        "title": content_type or entry_file.name,
                        "visit_count": None,
                        "visit_time_utc": entry.get("timestamp"),
                        "extra": json.dumps({
                            "content_type": content_type,
                            "size": cache_size,
                            "file": entry_file.name,
                            "response_code": entry.get("response_code", ""),
                            "cache_control": entry.get("cache_control", ""),
                            "server": entry.get("server", ""),
                        })
                    })
                    count += 1
                    if count >= 5000:  # Safety limit
                        break
            except Exception:
                continue

        utils.log_line(f"Cache extracted: {count} entries from {cache_dir}")
    except Exception as e:
        utils.log_line(f"Error cache {browser}: {e}")

def _parse_simple_cache_entry(filepath: Path) -> dict:
    """
    Parse a Chromium simple cache entry file.

    Simple cache entry format:
    - Stream 0 data (HTTP headers as key-value)
    - Stream 1 data (HTTP response body)
    - EOF record at the end with metadata

    The URL (key) is stored at the beginning after the initial header.
    """
    try:
        data = filepath.read_bytes()
        if len(data) < 24:
            return None

        # Check for simple cache initial magic at the start
        initial_magic = struct.unpack_from("<Q", data, 0)[0]
        if initial_magic != SIMPLE_INITIAL_MAGIC:
            # Try to extract URL from raw data as fallback
            return _extract_url_from_raw_cache(data, filepath)

        # After magic: version(4) + key_length(4) + key_hash(4)
        key_length = struct.unpack_from("<I", data, 12)[0]
        if key_length > 2048 or key_length == 0:
            return None

        key_start = 20
        if key_start + key_length > len(data):
            return None

        url = data[key_start:key_start + key_length].decode("utf-8", errors="replace")
        if not url.startswith(("http://", "https://", "ftp://")):
            # Key might have a prefix like "1/" for sub-resources
            if "/" in url and url.split("/", 1)[1].startswith(("http://", "https://")):
                url = url.split("/", 1)[1]
            elif not re.match(r'^[\x20-\x7e]+$', url):
                return None

        result = {
            "url": url,
            "size": len(data),
            "timestamp": _file_time_to_iso(filepath),
        }

        # Try to parse HTTP headers from the data after the key
        headers_start = key_start + key_length
        _parse_http_headers(data[headers_start:], result)

        return result

    except Exception:
        return None

def _extract_url_from_raw_cache(data: bytes, filepath: Path) -> dict:
    """Fallback: extract URL from cache file by pattern matching."""
    text = data[:4096].decode("utf-8", errors="replace")
    urls = re.findall(r'(https?://[^\x00-\x1f\s"\'<>]{10,500})', text)
    if urls:
        result = {
            "url": urls[0],
            "size": len(data),
            "timestamp": _file_time_to_iso(filepath),
        }
        _parse_http_headers(data[:4096], result)
        return result
    return None

def _parse_http_headers(data: bytes, result: dict):
    """Extract HTTP response headers from cache data."""
    try:
        text = data[:4096].decode("utf-8", errors="replace")

        # Content-Type
        ct_match = re.search(r'content-type:\s*([^\r\n]+)', text, re.IGNORECASE)
        if ct_match:
            result["content_type"] = ct_match.group(1).strip()

        # Response code
        code_match = re.search(r'HTTP/[\d.]+\s+(\d{3})', text)
        if code_match:
            result["response_code"] = code_match.group(1)

        # Cache-Control
        cc_match = re.search(r'cache-control:\s*([^\r\n]+)', text, re.IGNORECASE)
        if cc_match:
            result["cache_control"] = cc_match.group(1).strip()

        # Server
        srv_match = re.search(r'server:\s*([^\r\n]+)', text, re.IGNORECASE)
        if srv_match:
            result["server"] = srv_match.group(1).strip()
    except Exception:
        pass

def _file_time_to_iso(filepath: Path) -> str:
    """Convert file modification time to ISO format."""
    try:
        mtime = filepath.stat().st_mtime
        return datetime.utcfromtimestamp(mtime).isoformat()
    except Exception:
        return None

# ---------------------------------------------------------------------------
# Firefox cache2 parser
# ---------------------------------------------------------------------------

def _extract_firefox_cache(path, meta, rows):
    """Extract Firefox cache entries from cache2."""
    if not path.is_dir():
        return
    for prof in path.glob("*.default*"):
        cache_dir = prof / "cache2" / "entries"
        if not cache_dir.exists():
            continue

        count = 0
        try:
            for entry_file in cache_dir.iterdir():
                if not entry_file.is_file() or entry_file.stat().st_size < 36:
                    continue

                try:
                    entry = _parse_firefox_cache_entry(entry_file)
                    if entry and entry.get("url"):
                        rows.append({
                            **meta, "browser": "firefox", "artifact": "cache",
                            "profile": str(prof),
                            "url": entry["url"],
                            "title": entry.get("content_type", entry_file.name),
                            "visit_count": None,
                            "visit_time_utc": entry.get("timestamp"),
                            "extra": json.dumps({
                                "content_type": entry.get("content_type", ""),
                                "size": entry.get("size", 0),
                                "file": entry_file.name,
                            })
                        })
                        count += 1
                        if count >= 5000:
                            break
                except Exception:
                    continue

            utils.log_line(f"Firefox cache: {count} entries from {cache_dir}")
        except Exception as e:
            utils.log_line(f"Error firefox cache {prof}: {e}")

def _parse_firefox_cache_entry(filepath: Path) -> dict:
    """
    Parse a Firefox cache2 entry.
    Metadata is stored at the end of the file in a fixed-size chunk.
    The URL is stored as part of the metadata key.
    """
    try:
        data = filepath.read_bytes()
        if len(data) < 36:
            return None

        # Firefox cache2 stores metadata at the end
        # Last 4 bytes: metadata offset (big-endian)
        meta_offset = struct.unpack_from(">I", data, len(data) - 4)[0]
        if meta_offset == 0 or meta_offset >= len(data):
            # Fallback: try to find URL in the data
            return _extract_url_from_raw_cache(data, filepath)

        metadata = data[meta_offset:-4]

        # Metadata format: version(4) + fetch_count(4) + last_fetched(4) + last_modified(4) + frecency(4) + expire(4) + key_size(4) + key
        if len(metadata) < 28:
            return None

        key_size = struct.unpack_from(">I", metadata, 24)[0]
        if key_size > 2048 or key_size == 0:
            return None

        key = metadata[28:28 + key_size].decode("utf-8", errors="replace")
        # Firefox keys are in format: ":<scheme>,<flags>,:http://example.com/path"
        url_match = re.search(r'(https?://[^\x00]+)', key)
        url = url_match.group(1) if url_match else key

        fetch_count = struct.unpack_from(">I", metadata, 4)[0]
        last_fetched = struct.unpack_from(">I", metadata, 8)[0]

        result = {
            "url": url,
            "size": len(data),
            "fetch_count": fetch_count,
            "timestamp": datetime.utcfromtimestamp(last_fetched).isoformat() if last_fetched else None,
        }

        _parse_http_headers(data[:4096], result)
        return result

    except Exception:
        return None
