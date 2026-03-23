"""
Frostveil WAL Forensics — recover deleted records from SQLite WAL/journal files.

SQLite Write-Ahead Log (WAL) and rollback journals contain records that were
deleted or overwritten. This module carves those records to recover browsing
history, cookies, credentials, and other artifacts that the user attempted
to erase.

This is a capability that most commercial forensic tools charge thousands for.
"""
import struct, re, sqlite3
from pathlib import Path
from . import utils

# SQLite page header constants
SQLITE_MAGIC = b"SQLite format 3\x00"
WAL_MAGIC_BE = 0x377f0682  # Big-endian WAL
WAL_MAGIC_LE = 0x377f0683  # Little-endian WAL

def recover_deleted(browser, path: Path, meta) -> list:
    """
    Recover deleted records from WAL and journal files.
    Returns rows in standard Frostveil artifact format.
    """
    rows = []
    if browser in ("chrome", "edge"):
        _recover_chromium(browser, path, meta, rows)
    elif browser == "firefox":
        _recover_firefox(path, meta, rows)
    return rows

# ---------------------------------------------------------------------------
# WAL file parser
# ---------------------------------------------------------------------------

def _parse_wal_file(wal_path: Path) -> list:
    """
    Parse a SQLite WAL file and extract page frames.
    WAL format:
      Header (32 bytes): magic(4) + version(4) + page_size(4) + ...
      Frames: frame_header(24) + page_data(page_size)
    """
    frames = []
    try:
        data = wal_path.read_bytes()
        if len(data) < 32:
            return frames

        magic = struct.unpack_from(">I", data, 0)[0]
        if magic not in (WAL_MAGIC_BE, WAL_MAGIC_LE):
            return frames

        big_endian = magic == WAL_MAGIC_BE
        fmt = ">" if big_endian else "<"

        page_size = struct.unpack_from(f"{fmt}I", data, 8)[0]
        if page_size < 512 or page_size > 65536:
            return frames

        pos = 32  # After WAL header
        frame_idx = 0

        while pos + 24 + page_size <= len(data):
            # Frame header: page_number(4) + commit_size(4) + salt1(4) + salt2(4) + checksum1(4) + checksum2(4)
            page_num = struct.unpack_from(f"{fmt}I", data, pos)[0]
            page_data = data[pos + 24: pos + 24 + page_size]
            frames.append({
                "page_number": page_num,
                "frame_index": frame_idx,
                "data": page_data,
            })
            pos += 24 + page_size
            frame_idx += 1

    except Exception as e:
        utils.log_line(f"WAL parse error {wal_path}: {e}")

    return frames

# ---------------------------------------------------------------------------
# Record carving from raw pages
# ---------------------------------------------------------------------------

def _carve_urls_from_pages(pages_data: list) -> list:
    """
    Carve URL records from raw SQLite page data.
    Looks for URL patterns in both active and free space.
    """
    carved = []
    seen = set()

    for page_info in pages_data:
        data = page_info["data"]
        text = data.decode("utf-8", errors="replace")

        # Find URLs
        urls = re.findall(r'(https?://[^\x00-\x1f\s"\'<>]{10,500})', text)
        for url in urls:
            if url in seen:
                continue
            seen.add(url)

            # Try to find a title near the URL
            url_pos = text.find(url)
            context = text[max(0, url_pos - 200):url_pos + len(url) + 200]

            # Look for readable title strings nearby
            title = ""
            readable = re.findall(r'[\x20-\x7e]{5,100}', context)
            for r in readable:
                if r != url and not r.startswith("http") and len(r) > 5:
                    title = r.strip()
                    break

            carved.append({
                "url": url,
                "title": title,
                "source": f"page_{page_info['page_number']}_frame_{page_info.get('frame_index', 'n/a')}",
            })

    return carved

def _carve_strings_from_pages(pages_data: list, min_length=8) -> list:
    """Extract all readable strings from page data (generic carving)."""
    strings = []
    seen = set()
    for page_info in pages_data:
        data = page_info["data"]
        text = data.decode("utf-8", errors="replace")
        found = re.findall(f'[\\x20-\\x7e]{{{min_length},500}}', text)
        for s in found:
            s = s.strip()
            if s and s not in seen and len(s) >= min_length:
                seen.add(s)
                strings.append(s)
    return strings

# ---------------------------------------------------------------------------
# SQLite freelist / unallocated page carving
# ---------------------------------------------------------------------------

def _carve_freelist(db_path: Path) -> list:
    """
    Extract data from SQLite freelist (deleted) pages.
    When records are deleted, their pages go to the freelist but data remains.
    """
    pages = []
    try:
        data = db_path.read_bytes()
        if len(data) < 100 or data[:16] != SQLITE_MAGIC:
            return pages

        page_size = struct.unpack_from(">H", data, 16)[0]
        if page_size == 1:
            page_size = 65536
        if page_size < 512:
            return pages

        # Read freelist trunk page from header (offset 32, 4 bytes)
        freelist_trunk = struct.unpack_from(">I", data, 32)[0]
        freelist_count = struct.unpack_from(">I", data, 36)[0]

        if freelist_count == 0 or freelist_trunk == 0:
            return pages

        # Walk the freelist
        visited = set()
        current_trunk = freelist_trunk

        while current_trunk != 0 and current_trunk not in visited:
            visited.add(current_trunk)
            trunk_offset = (current_trunk - 1) * page_size

            if trunk_offset + page_size > len(data):
                break

            trunk_data = data[trunk_offset:trunk_offset + page_size]

            # Trunk page: next_trunk(4) + leaf_count(4) + leaf_pages(4*count)
            next_trunk = struct.unpack_from(">I", trunk_data, 0)[0]
            leaf_count = struct.unpack_from(">I", trunk_data, 4)[0]

            # Extract data from trunk page itself
            pages.append({
                "page_number": current_trunk,
                "frame_index": "freelist_trunk",
                "data": trunk_data,
            })

            # Extract each leaf page
            for i in range(min(leaf_count, (page_size - 8) // 4)):
                leaf_page = struct.unpack_from(">I", trunk_data, 8 + i * 4)[0]
                if leaf_page == 0:
                    continue
                leaf_offset = (leaf_page - 1) * page_size
                if leaf_offset + page_size <= len(data):
                    pages.append({
                        "page_number": leaf_page,
                        "frame_index": "freelist_leaf",
                        "data": data[leaf_offset:leaf_offset + page_size],
                    })

            current_trunk = next_trunk

        utils.log_line(f"Freelist carving: {len(pages)} pages from {db_path.name}")
    except Exception as e:
        utils.log_line(f"Freelist carving error {db_path}: {e}")

    return pages

# ---------------------------------------------------------------------------
# SQLite unallocated space within pages
# ---------------------------------------------------------------------------

def _carve_unallocated_in_page(db_path: Path) -> list:
    """
    Scan all pages for unallocated space (between cell pointers and cell content).
    Deleted records often leave fragments in this gap.
    """
    pages = []
    try:
        data = db_path.read_bytes()
        if len(data) < 100 or data[:16] != SQLITE_MAGIC:
            return pages

        page_size = struct.unpack_from(">H", data, 16)[0]
        if page_size == 1:
            page_size = 65536
        total_pages = len(data) // page_size

        for pg in range(total_pages):
            offset = pg * page_size
            page_data = data[offset:offset + page_size]

            # Check if this is a leaf table page (type 0x0D)
            if len(page_data) < 8:
                continue
            page_type = page_data[0]
            if page_type != 0x0D:
                continue

            # Leaf table b-tree page header:
            # type(1) + first_freeblock(2) + cell_count(2) + cell_content_start(2) + fragmented_bytes(1)
            cell_count = struct.unpack_from(">H", page_data, 3)[0]
            cell_content_start = struct.unpack_from(">H", page_data, 5)[0]
            if cell_content_start == 0:
                cell_content_start = 65536

            # The unallocated space is between the end of cell pointers and cell_content_start
            header_end = 8 + cell_count * 2  # 8-byte header + 2 bytes per cell pointer
            if header_end < cell_content_start and cell_content_start < page_size:
                unalloc = page_data[header_end:cell_content_start]
                if len(unalloc) > 10:
                    pages.append({
                        "page_number": pg + 1,
                        "frame_index": "unallocated",
                        "data": unalloc,
                    })
    except Exception as e:
        utils.log_line(f"Unallocated carving error {db_path}: {e}")

    return pages

# ---------------------------------------------------------------------------
# Browser-specific recovery
# ---------------------------------------------------------------------------

def _recover_chromium(browser, path, meta, rows):
    """Recover deleted data from Chromium History database."""
    db_path = path  # path points to History file

    # 1. WAL recovery
    wal_path = Path(str(db_path) + "-wal")
    if wal_path.exists():
        frames = _parse_wal_file(wal_path)
        if frames:
            carved = _carve_urls_from_pages(frames)
            for c in carved:
                rows.append({
                    **meta, "browser": browser, "artifact": "recovered_history",
                    "profile": str(path.parent), "url": c["url"],
                    "title": c.get("title", ""), "visit_count": None,
                    "visit_time_utc": None,
                    "extra": f'{{"source":"wal","detail":"{c["source"]}"}}'
                })
            utils.log_line(f"WAL recovery: {len(carved)} URLs from {wal_path.name}")

    # 2. Journal recovery
    journal_path = Path(str(db_path) + "-journal")
    if journal_path.exists():
        try:
            journal_data = journal_path.read_bytes()
            pages = [{"page_number": 0, "frame_index": "journal", "data": journal_data}]
            carved = _carve_urls_from_pages(pages)
            for c in carved:
                rows.append({
                    **meta, "browser": browser, "artifact": "recovered_history",
                    "profile": str(path.parent), "url": c["url"],
                    "title": c.get("title", ""), "visit_count": None,
                    "visit_time_utc": None,
                    "extra": '{"source":"journal"}'
                })
        except Exception:
            pass

    # 3. Freelist carving from the database itself
    tmp = utils.safe_copy(db_path)
    if tmp:
        freelist_pages = _carve_freelist(tmp)
        if freelist_pages:
            carved = _carve_urls_from_pages(freelist_pages)
            for c in carved:
                rows.append({
                    **meta, "browser": browser, "artifact": "recovered_history",
                    "profile": str(path.parent), "url": c["url"],
                    "title": c.get("title", ""), "visit_count": None,
                    "visit_time_utc": None,
                    "extra": f'{{"source":"freelist","detail":"{c["source"]}"}}'
                })

        # 4. Unallocated space carving
        unalloc_pages = _carve_unallocated_in_page(tmp)
        if unalloc_pages:
            carved = _carve_urls_from_pages(unalloc_pages)
            for c in carved:
                rows.append({
                    **meta, "browser": browser, "artifact": "recovered_history",
                    "profile": str(path.parent), "url": c["url"],
                    "title": c.get("title", ""), "visit_count": None,
                    "visit_time_utc": None,
                    "extra": f'{{"source":"unallocated","detail":"{c["source"]}"}}'
                })

    # 5. Also check Cookies, Login Data WAL files
    for db_name in ["Cookies", "Login Data", "Web Data"]:
        other_db = path.parent / db_name
        other_wal = Path(str(other_db) + "-wal")
        if other_wal.exists():
            frames = _parse_wal_file(other_wal)
            if frames:
                strings = _carve_strings_from_pages(frames, min_length=12)
                for s in strings[:100]:
                    if re.match(r'https?://', s) or '@' in s or '.' in s:
                        rows.append({
                            **meta, "browser": browser, "artifact": "recovered_data",
                            "profile": str(path.parent), "url": "",
                            "title": s[:200], "visit_count": None,
                            "visit_time_utc": None,
                            "extra": f'{{"source":"wal_{db_name}"}}'
                        })

def _recover_firefox(path, meta, rows):
    """Recover deleted data from Firefox databases."""
    if not path.is_dir():
        return
    for prof in path.glob("*.default*"):
        places = prof / "places.sqlite"
        if not places.exists():
            continue

        # WAL recovery
        wal_path = Path(str(places) + "-wal")
        if wal_path.exists():
            frames = _parse_wal_file(wal_path)
            if frames:
                carved = _carve_urls_from_pages(frames)
                for c in carved:
                    rows.append({
                        **meta, "browser": "firefox", "artifact": "recovered_history",
                        "profile": str(prof), "url": c["url"],
                        "title": c.get("title", ""), "visit_count": None,
                        "visit_time_utc": None,
                        "extra": '{"source":"wal"}'
                    })

        # Freelist carving
        tmp = utils.safe_copy(places)
        if tmp:
            freelist_pages = _carve_freelist(tmp)
            unalloc_pages = _carve_unallocated_in_page(tmp)
            all_pages = freelist_pages + unalloc_pages
            if all_pages:
                carved = _carve_urls_from_pages(all_pages)
                for c in carved:
                    rows.append({
                        **meta, "browser": "firefox", "artifact": "recovered_history",
                        "profile": str(prof), "url": c["url"],
                        "title": c.get("title", ""), "visit_count": None,
                        "visit_time_utc": None,
                        "extra": f'{{"source":"freelist_unalloc"}}'
                    })
