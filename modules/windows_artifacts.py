"""
Windows OS-level artifact parsers for forensic analysis.

Parses Prefetch files, Jump Lists, LNK shortcut files, and Recycle Bin
metadata — all pure Python with no external dependencies.
"""

import json
import os
import re
import struct
import sys
from datetime import datetime, timedelta
from pathlib import Path

from .utils import log_line, progress

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Windows FILETIME epoch: 1601-01-01 00:00:00 UTC
_FILETIME_EPOCH = datetime(1601, 1, 1)

# Browser executable names we care about for prefetch filtering
_BROWSER_EXES = {
    "CHROME.EXE", "MSEDGE.EXE", "FIREFOX.EXE", "BRAVE.EXE",
    "OPERA.EXE", "VIVALDI.EXE", "IEXPLORE.EXE", "SAFARI.EXE",
    "CHROMIUM.EXE", "WATERFOX.EXE", "YANDEX.EXE", "OPERAGX.EXE",
    "BROWSER.EXE", "MICROSOFTEDGE.EXE",
}

# ---------------------------------------------------------------------------
# Helper: FILETIME conversion
# ---------------------------------------------------------------------------

def _filetime_to_utc(filetime_int):
    """Convert a Windows FILETIME (100-ns ticks since 1601-01-01) to ISO UTC string."""
    if not filetime_int or filetime_int <= 0:
        return None
    try:
        delta = timedelta(microseconds=filetime_int // 10)
        dt = _FILETIME_EPOCH + delta
        # Sanity check: reject dates before 1970 or far in the future
        if dt.year < 1970 or dt.year > 2100:
            return None
        return dt.isoformat()
    except (OSError, ValueError, OverflowError):
        return None


def _make_row(artifact, url="", title="", visit_time_utc=None, extra=None):
    """Build a standard row dict matching the project schema."""
    return {
        "browser": "windows",
        "artifact": artifact,
        "url": url,
        "title": title,
        "visit_time_utc": visit_time_utc,
        "extra": json.dumps(extra) if extra else "",
    }


def _is_windows():
    return sys.platform.startswith("win")


# ---------------------------------------------------------------------------
# 1. Prefetch Files
# ---------------------------------------------------------------------------

def parse_prefetch(prefetch_dir=None):
    """Parse Windows Prefetch (.pf) files for browser-related executions.

    Returns a list of row dicts with artifact type 'prefetch'.
    """
    if not _is_windows():
        return []

    rows = []
    pf_dir = Path(prefetch_dir) if prefetch_dir else Path(r"C:\Windows\Prefetch")

    if not pf_dir.is_dir():
        log_line(f"Prefetch directory not found: {pf_dir}")
        return rows

    try:
        pf_files = list(pf_dir.glob("*.pf"))
    except PermissionError:
        log_line(f"[ACCESS DENIED] Cannot list prefetch directory: {pf_dir}")
        return rows
    except Exception as e:
        log_line(f"Error listing prefetch directory: {e}")
        return rows

    for pf_path in pf_files:
        try:
            fname = pf_path.name.upper()
            # Extract exe name: everything before the last dash
            dash_idx = fname.rfind("-")
            if dash_idx <= 0:
                continue
            exe_name = fname[:dash_idx]

            # Filter to browser-related executables
            if exe_name not in _BROWSER_EXES:
                continue

            # Read header bytes for basic parsing
            run_count = None
            file_size = None
            version = None

            try:
                with open(pf_path, "rb") as f:
                    header = f.read(100)

                if len(header) >= 16:
                    # Verify magic bytes (Win10: SCCA = 0x41434353 little-endian at offset 4)
                    # Version at offset 0, signature at offset 4
                    version = struct.unpack_from("<I", header, 0)[0]
                    magic = header[4:8]
                    if magic != b"SCCA":
                        # Not a valid prefetch file, skip
                        continue
                    file_size = struct.unpack_from("<I", header, 12)[0]

                # Run count location varies by version:
                # Version 17 (XP): offset 90
                # Version 23 (Vista/Win7): offset 98
                # Version 26 (Win8): offset 208
                # Version 30 (Win10): offset 208
                if version and len(header) >= 100:
                    if version == 17 and len(header) >= 94:
                        run_count = struct.unpack_from("<I", header, 90)[0]
                    elif version == 23 and len(header) >= 102:
                        run_count = struct.unpack_from("<I", header, 98)[0]
            except PermissionError:
                log_line(f"[ACCESS DENIED] Cannot read prefetch file: {pf_path}")
                continue
            except Exception:
                # If we can't parse the binary, fall back to file metadata only
                pass

            # File system timestamps as fallback/supplement
            stat = pf_path.stat()
            created = datetime.utcfromtimestamp(stat.st_ctime).isoformat()
            modified = datetime.utcfromtimestamp(stat.st_mtime).isoformat()

            extra = {
                "file": str(pf_path),
                "exe_name": exe_name,
                "pf_file_size": file_size,
                "pf_version": version,
                "run_count": run_count,
                "file_created": created,
                "file_modified": modified,
            }

            rows.append(_make_row(
                artifact="prefetch",
                url=str(pf_path),
                title=exe_name,
                visit_time_utc=modified,
                extra=extra,
            ))

        except Exception as e:
            log_line(f"Error parsing prefetch file {pf_path}: {e}")
            continue

    progress(f"Prefetch: found {len(rows)} browser-related entries")
    return rows


# ---------------------------------------------------------------------------
# 2. Jump Lists
# ---------------------------------------------------------------------------

def parse_jump_lists(user_dir=None):
    """Parse Windows Jump List files for URLs and file paths.

    Jump list files are compound OLE documents. We use a simplified regex
    approach to extract URLs and file references from the raw bytes.

    Returns a list of row dicts with artifact type 'jump_list'.
    """
    if not _is_windows():
        return []

    rows = []

    if user_dir:
        jl_dir = Path(user_dir)
    else:
        appdata = os.environ.get("APPDATA", "")
        if not appdata:
            log_line("APPDATA environment variable not set")
            return rows
        jl_dir = Path(appdata) / "Microsoft" / "Windows" / "Recent" / "AutomaticDestinations"

    if not jl_dir.is_dir():
        log_line(f"Jump Lists directory not found: {jl_dir}")
        return rows

    # Regex patterns to find URLs and file paths in raw bytes
    url_pattern = re.compile(rb"(https?://[^\x00-\x1f\x7f-\x9f\"<>\s]{4,500})")
    # Match Windows file paths (drive letter paths) — encoded as UTF-16LE
    path_pattern_utf16 = re.compile(
        rb"([A-Z]\x00:\x00\\\x00(?:[^\x00]\x00){3,260})"
    )

    try:
        jl_files = list(jl_dir.glob("*.automaticDestinations-ms"))
    except PermissionError:
        log_line(f"[ACCESS DENIED] Cannot list jump list directory: {jl_dir}")
        return rows
    except Exception as e:
        log_line(f"Error listing jump list directory: {e}")
        return rows

    seen = set()

    for jl_path in jl_files:
        try:
            with open(jl_path, "rb") as f:
                data = f.read()
        except PermissionError:
            log_line(f"[ACCESS DENIED] Cannot read jump list: {jl_path}")
            continue
        except Exception as e:
            log_line(f"Error reading jump list {jl_path}: {e}")
            continue

        stat = jl_path.stat()
        modified = datetime.utcfromtimestamp(stat.st_mtime).isoformat()

        # Extract URLs (ASCII/UTF-8)
        for match in url_pattern.finditer(data):
            try:
                url = match.group(1).decode("utf-8", errors="ignore").rstrip("\x00")
            except Exception:
                continue
            if url in seen:
                continue
            seen.add(url)

            rows.append(_make_row(
                artifact="jump_list",
                url=url,
                title="",
                visit_time_utc=modified,
                extra={"source_file": str(jl_path)},
            ))

        # Extract file paths (UTF-16LE encoded)
        for match in path_pattern_utf16.finditer(data):
            try:
                raw = match.group(1)
                file_path = raw.decode("utf-16-le", errors="ignore").rstrip("\x00")
                # Basic validation: must contain a backslash and no control chars
                if "\\" not in file_path:
                    continue
                if any(ord(c) < 32 for c in file_path):
                    file_path = file_path.split("\x00")[0]
                    if len(file_path) < 4:
                        continue
            except Exception:
                continue

            if file_path in seen:
                continue
            seen.add(file_path)

            rows.append(_make_row(
                artifact="jump_list",
                url=file_path,
                title=Path(file_path).name if file_path else "",
                visit_time_utc=modified,
                extra={"source_file": str(jl_path)},
            ))

    progress(f"Jump Lists: found {len(rows)} entries")
    return rows


# ---------------------------------------------------------------------------
# 3. LNK (Shortcut) Files
# ---------------------------------------------------------------------------

def parse_lnk_files(recent_dir=None):
    """Parse Windows .lnk (Shell Link) files from the Recent folder.

    Extracts target paths and timestamps from the LNK binary header.

    Returns a list of row dicts with artifact type 'lnk_file'.
    """
    if not _is_windows():
        return []

    rows = []

    if recent_dir:
        lnk_dir = Path(recent_dir)
    else:
        appdata = os.environ.get("APPDATA", "")
        if not appdata:
            log_line("APPDATA environment variable not set")
            return rows
        lnk_dir = Path(appdata) / "Microsoft" / "Windows" / "Recent"

    if not lnk_dir.is_dir():
        log_line(f"LNK directory not found: {lnk_dir}")
        return rows

    _LNK_MAGIC = b"\x4c\x00\x00\x00"

    try:
        lnk_files = list(lnk_dir.glob("*.lnk"))
    except PermissionError:
        log_line(f"[ACCESS DENIED] Cannot list LNK directory: {lnk_dir}")
        return rows
    except Exception as e:
        log_line(f"Error listing LNK directory: {e}")
        return rows

    for lnk_path in lnk_files:
        try:
            with open(lnk_path, "rb") as f:
                data = f.read()

            if len(data) < 76:
                continue

            # Verify magic bytes at offset 0
            if data[0:4] != _LNK_MAGIC:
                continue

            # Timestamps from header (FILETIME, little-endian uint64)
            creation_ft = struct.unpack_from("<Q", data, 28)[0]
            access_ft = struct.unpack_from("<Q", data, 36)[0]
            write_ft = struct.unpack_from("<Q", data, 44)[0]

            creation_time = _filetime_to_utc(creation_ft)
            access_time = _filetime_to_utc(access_ft)
            write_time = _filetime_to_utc(write_ft)

            # Flags at offset 20
            flags = struct.unpack_from("<I", data, 20)[0]
            has_link_target = bool(flags & 0x01)
            has_link_info = bool(flags & 0x02)
            has_name = bool(flags & 0x04)
            has_relative_path = bool(flags & 0x08)
            has_working_dir = bool(flags & 0x10)

            # Try to extract target path from the data
            target_path = ""
            offset = 76  # end of ShellLinkHeader

            # Skip LinkTargetIDList if present
            if has_link_target and offset + 2 <= len(data):
                id_list_size = struct.unpack_from("<H", data, offset)[0]
                offset += 2 + id_list_size

            # LinkInfo section
            if has_link_info and offset + 4 <= len(data):
                link_info_size = struct.unpack_from("<I", data, offset)[0]
                if link_info_size > 0 and offset + link_info_size <= len(data):
                    link_info = data[offset:offset + link_info_size]

                    if len(link_info) >= 28:
                        li_flags = struct.unpack_from("<I", link_info, 8)[0]
                        local_base_offset = struct.unpack_from("<I", link_info, 16)[0]

                        # VolumeIDAndLocalBasePath
                        if (li_flags & 0x01) and local_base_offset < len(link_info):
                            # Local base path is a null-terminated ASCII string
                            end = link_info.find(b"\x00", local_base_offset)
                            if end > local_base_offset:
                                target_path = link_info[local_base_offset:end].decode(
                                    "ascii", errors="ignore"
                                )

                    offset += link_info_size

            # StringData sections (Unicode, counted strings)
            # Order: NAME, RELATIVE_PATH, WORKING_DIR, ...
            relative_path = ""
            for has_flag, field_name in [
                (has_name, "name"),
                (has_relative_path, "relative_path"),
                (has_working_dir, "working_dir"),
            ]:
                if not has_flag:
                    continue
                if offset + 2 > len(data):
                    break
                char_count = struct.unpack_from("<H", data, offset)[0]
                offset += 2
                byte_count = char_count * 2  # UTF-16LE
                if offset + byte_count > len(data):
                    break
                string_val = data[offset:offset + byte_count].decode(
                    "utf-16-le", errors="ignore"
                )
                offset += byte_count
                if field_name == "relative_path" and not target_path:
                    relative_path = string_val

            if not target_path and relative_path:
                target_path = relative_path

            # Use lnk filename as title fallback
            title = lnk_path.stem  # filename without .lnk

            extra = {
                "lnk_file": str(lnk_path),
                "target_path": target_path,
                "creation_time": creation_time,
                "access_time": access_time,
                "write_time": write_time,
            }

            rows.append(_make_row(
                artifact="lnk_file",
                url=target_path if target_path else str(lnk_path),
                title=title,
                visit_time_utc=access_time or write_time or creation_time,
                extra=extra,
            ))

        except PermissionError:
            log_line(f"[ACCESS DENIED] Cannot read LNK file: {lnk_path}")
            continue
        except Exception as e:
            log_line(f"Error parsing LNK file {lnk_path}: {e}")
            continue

    progress(f"LNK files: found {len(rows)} entries")
    return rows


# ---------------------------------------------------------------------------
# 4. Recycle Bin
# ---------------------------------------------------------------------------

def parse_recycle_bin(recycle_dir=None):
    """Parse Windows Recycle Bin $I metadata files.

    $I files contain: version (8 bytes), file_size (8 bytes),
    deletion_timestamp (8 bytes FILETIME), file_path (Unicode string).

    Returns a list of row dicts with artifact type 'recycle_bin'.
    """
    if not _is_windows():
        return []

    rows = []

    if recycle_dir:
        rb_base = Path(recycle_dir)
        search_dirs = [rb_base] if rb_base.is_dir() else []
    else:
        # Find current user's Recycle Bin SID folder
        rb_root = Path(r"C:\$Recycle.Bin")
        search_dirs = []
        if rb_root.is_dir():
            try:
                for sid_dir in rb_root.iterdir():
                    if sid_dir.is_dir():
                        search_dirs.append(sid_dir)
            except PermissionError:
                log_line("[ACCESS DENIED] Cannot list Recycle Bin root")
                return rows
            except Exception as e:
                log_line(f"Error listing Recycle Bin root: {e}")
                return rows

    if not search_dirs:
        log_line("No Recycle Bin directories found")
        return rows

    for rb_dir in search_dirs:
        try:
            i_files = list(rb_dir.glob("$I*"))
        except PermissionError:
            log_line(f"[ACCESS DENIED] Cannot list Recycle Bin dir: {rb_dir}")
            continue
        except Exception as e:
            log_line(f"Error listing Recycle Bin dir {rb_dir}: {e}")
            continue

        for i_path in i_files:
            try:
                with open(i_path, "rb") as f:
                    data = f.read()

                # Minimum size: 8 (version) + 8 (size) + 8 (timestamp) = 24 bytes
                if len(data) < 24:
                    continue

                version = struct.unpack_from("<Q", data, 0)[0]
                file_size = struct.unpack_from("<Q", data, 8)[0]
                deletion_ft = struct.unpack_from("<Q", data, 16)[0]
                deletion_time = _filetime_to_utc(deletion_ft)

                # File path starts at offset 24
                # Version 1: path is 520 bytes (260 UTF-16LE chars) starting at offset 24
                # Version 2: 4-byte length at offset 24, then UTF-16LE string
                original_path = ""
                if version == 2 and len(data) >= 28:
                    path_len = struct.unpack_from("<I", data, 24)[0]
                    path_bytes = data[28:28 + path_len * 2]
                    original_path = path_bytes.decode("utf-16-le", errors="ignore").rstrip("\x00")
                elif len(data) >= 24 + 520:
                    path_bytes = data[24:24 + 520]
                    original_path = path_bytes.decode("utf-16-le", errors="ignore").rstrip("\x00")

                # Corresponding $R file (actual deleted content)
                r_name = "$R" + i_path.name[2:]  # replace $I with $R
                r_path = rb_dir / r_name
                r_exists = r_path.exists()

                title = Path(original_path).name if original_path else i_path.name

                extra = {
                    "i_file": str(i_path),
                    "r_file": str(r_path) if r_exists else None,
                    "r_exists": r_exists,
                    "original_path": original_path,
                    "deleted_file_size": file_size,
                    "recycle_version": version,
                    "sid_folder": rb_dir.name,
                }

                rows.append(_make_row(
                    artifact="recycle_bin",
                    url=original_path if original_path else str(i_path),
                    title=title,
                    visit_time_utc=deletion_time,
                    extra=extra,
                ))

            except PermissionError:
                log_line(f"[ACCESS DENIED] Cannot read Recycle Bin file: {i_path}")
                continue
            except Exception as e:
                log_line(f"Error parsing Recycle Bin file {i_path}: {e}")
                continue

    progress(f"Recycle Bin: found {len(rows)} entries")
    return rows


# ---------------------------------------------------------------------------
# 5. Main entry point
# ---------------------------------------------------------------------------

def extract_all(meta):
    """Run all Windows artifact parsers and return combined results.

    Each parser is wrapped in its own try/except so a failure in one does
    not prevent the others from running.

    Args:
        meta: metadata dict (from utils.get_metadata).

    Returns:
        list of row dicts.
    """
    if not _is_windows():
        progress("Skipping Windows artifacts (not a Windows platform)")
        return []

    progress("Extracting Windows OS-level artifacts ...")
    all_rows = []
    errors = []

    parsers = [
        ("Prefetch", parse_prefetch),
        ("Jump Lists", parse_jump_lists),
        ("LNK Files", parse_lnk_files),
        ("Recycle Bin", parse_recycle_bin),
    ]

    for name, func in parsers:
        try:
            result = func()
            all_rows.extend(result)
        except Exception as e:
            msg = f"Windows artifact parser '{name}' failed: {e}"
            log_line(msg)
            errors.append(msg)

    progress(f"Windows artifacts: {len(all_rows)} total entries collected")
    return all_rows
