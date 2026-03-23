"""
Frostveil LocalStorage Extraction — parse Chromium LevelDB and Firefox webappsstore.

LevelDB is a key-value store used by Chromium for LocalStorage, IndexedDB metadata,
and extension state. This module implements a pure-Python LevelDB log/table reader
without requiring the leveldb library.
"""
import struct, json, os
from pathlib import Path
from . import utils

def extract(browser, path: Path, meta):
    rows = []
    if browser in ["chrome", "edge"]:
        _extract_chromium_localstorage(browser, path, meta, rows)
        _extract_chromium_indexeddb_meta(browser, path, meta, rows)
    elif browser == "firefox":
        _extract_firefox_webappsstore(path, meta, rows)
    return rows

# ---------------------------------------------------------------------------
# LevelDB .log and .ldb/.sst reader (pure Python)
# ---------------------------------------------------------------------------

def _parse_leveldb_log(log_path: Path) -> list:
    """
    Parse a LevelDB .log (write-ahead log) file.
    Format: sequence of blocks (32KB each), each containing records.
    Record: checksum(4) + length(2) + type(1) + data(length)
    """
    entries = []
    try:
        data = log_path.read_bytes()
        pos = 0
        BLOCK_SIZE = 32768
        while pos < len(data):
            # Read record header
            if pos + 7 > len(data):
                break
            _crc = struct.unpack_from("<I", data, pos)[0]
            length = struct.unpack_from("<H", data, pos + 4)[0]
            rtype = data[pos + 6]
            pos += 7
            if pos + length > len(data):
                break
            payload = data[pos:pos + length]
            pos += length

            # Type 1 = full record, contains batch of puts/deletes
            if rtype in (1, 2, 3, 4) and len(payload) > 12:
                _parse_write_batch(payload, entries)

            # Align to block boundary for type 4 (last fragment)
            if rtype == 4 or rtype == 1:
                pass  # Continue
    except Exception:
        pass
    return entries

def _parse_write_batch(batch_data: bytes, entries: list):
    """Parse a LevelDB WriteBatch to extract key-value pairs."""
    try:
        if len(batch_data) < 12:
            return
        _seq = struct.unpack_from("<Q", batch_data, 0)[0]
        count = struct.unpack_from("<I", batch_data, 8)[0]
        pos = 12
        for _ in range(min(count, 10000)):  # Safety limit
            if pos >= len(batch_data):
                break
            op_type = batch_data[pos]
            pos += 1
            if op_type == 1:  # Put
                if pos + 4 > len(batch_data):
                    break
                key_len, pos = _read_varint(batch_data, pos)
                if key_len is None or pos + key_len > len(batch_data):
                    break
                key = batch_data[pos:pos + key_len]
                pos += key_len

                val_len, pos = _read_varint(batch_data, pos)
                if val_len is None or pos + val_len > len(batch_data):
                    break
                value = batch_data[pos:pos + val_len]
                pos += val_len

                try:
                    k = key.decode("utf-8", errors="replace")
                    v = value.decode("utf-8", errors="replace")
                    entries.append((k, v))
                except Exception:
                    pass
            elif op_type == 0:  # Delete
                key_len, pos = _read_varint(batch_data, pos)
                if key_len is None or pos + key_len > len(batch_data):
                    break
                pos += key_len
            else:
                break  # Unknown op
    except Exception:
        pass

def _read_varint(data: bytes, pos: int):
    """Read a LevelDB-style varint."""
    result = 0
    shift = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            return result, pos
        shift += 7
        if shift > 35:
            return None, pos
    return None, pos

def _parse_ldb_table(table_path: Path) -> list:
    """
    Parse a LevelDB .ldb/.sst table file for key-value data.
    Extracts strings from the data blocks (simplified parser).
    """
    entries = []
    try:
        data = table_path.read_bytes()
        if len(data) < 48:
            return entries
        # Read footer (last 48 bytes) to find metaindex and index handles
        footer = data[-48:]
        # Scan data blocks for readable key-value strings
        # This is a heuristic extractor — not a full table parser
        _extract_strings_from_blocks(data, entries)
    except Exception:
        pass
    return entries

def _extract_strings_from_blocks(data: bytes, entries: list):
    """Heuristic extraction of key-value pairs from LevelDB data blocks."""
    # Look for URL-like keys followed by values (LocalStorage pattern)
    # Keys in Chromium LocalStorage have format: _<origin>\x00<key>
    text = data.decode("utf-8", errors="replace")
    # Find sequences that look like stored data
    parts = text.split("\x00")
    i = 0
    while i < len(parts) - 1:
        part = parts[i].strip()
        if len(part) > 3 and not all(c in "\x00\x01\x02\x03\x04\x05" for c in part):
            next_part = parts[i + 1].strip() if i + 1 < len(parts) else ""
            if len(next_part) > 0:
                entries.append((part[-200:], next_part[:500]))
        i += 1

def _extract_chromium_localstorage(browser, path, meta, rows):
    ls_dir = path.parent / "Local Storage" / "leveldb"
    if not ls_dir.exists():
        return

    entries = []
    try:
        # Parse .log files (most recent data)
        for log_file in ls_dir.glob("*.log"):
            entries.extend(_parse_leveldb_log(log_file))

        # Parse .ldb table files
        for ldb_file in ls_dir.glob("*.ldb"):
            entries.extend(_parse_ldb_table(ldb_file))

        # Deduplicate and filter meaningful entries
        seen = set()
        for key, value in entries:
            if len(key) < 2 or len(value) < 1:
                continue
            sig = f"{key[:100]}:{value[:100]}"
            if sig in seen:
                continue
            seen.add(sig)

            # Extract origin from key if present
            origin = ""
            if "_http" in key:
                origin = key[key.index("_http"):]
                origin = origin.split("\x00")[0].split("\x01")[0]

            rows.append({
                **meta, "browser": browser, "artifact": "localstorage",
                "profile": str(path.parent),
                "url": origin,
                "title": key[:200],
                "visit_count": None,
                "visit_time_utc": None,
                "extra": json.dumps({"value": value[:1000]})
            })

        utils.log_line(f"LocalStorage extracted: {len(rows)} entries from {ls_dir}")
    except Exception as e:
        utils.log_line(f"Error localstorage {browser}: {e}")

def _extract_chromium_indexeddb_meta(browser, path, meta, rows):
    """Extract IndexedDB database metadata (which sites use IndexedDB)."""
    idb_base = path.parent / "IndexedDB"
    if not idb_base.exists():
        return
    try:
        for idb_dir in idb_base.iterdir():
            if idb_dir.is_dir():
                origin = idb_dir.name.replace("_0.indexeddb.leveldb", "")
                origin = origin.replace("_", "://", 1).replace("_", ".")
                # Count files and total size
                total_size = sum(f.stat().st_size for f in idb_dir.rglob("*") if f.is_file())
                rows.append({
                    **meta, "browser": browser, "artifact": "indexeddb",
                    "profile": str(path.parent),
                    "url": origin,
                    "title": idb_dir.name,
                    "visit_count": None,
                    "visit_time_utc": None,
                    "extra": json.dumps({"size_bytes": total_size})
                })
    except Exception as e:
        utils.log_line(f"Error indexeddb {browser}: {e}")

def _extract_firefox_webappsstore(path, meta, rows):
    if not path.is_dir():
        return
    for prof in path.glob("*.default*"):
        ws = prof / "webappsstore.sqlite"
        tmp = utils.safe_copy(ws)
        if not tmp:
            continue
        try:
            import sqlite3
            con = sqlite3.connect(str(tmp))
            cur = con.cursor()
            cur.execute("SELECT originAttributes, originKey, scope, key, value FROM webappsstore2")
            for attrs, origin_key, scope, key, value in cur.fetchall():
                # Reverse the originKey to get the actual origin
                origin = origin_key[::-1] if origin_key else ""
                rows.append({
                    **meta, "browser": "firefox", "artifact": "localstorage",
                    "profile": str(prof),
                    "url": origin,
                    "title": key,
                    "visit_count": None,
                    "visit_time_utc": None,
                    "extra": json.dumps({"value": value[:1000], "scope": scope})
                })
            con.close()
            utils.log_line(f"Firefox webappsstore extracted from {ws}")
        except Exception as e:
            utils.log_line(f"Error webappsstore firefox {prof}: {e}")
