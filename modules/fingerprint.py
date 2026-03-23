"""
Frostveil Browser Fingerprint Reconstructor — rebuild the target's unique
browser fingerprint from extracted preferences, extensions, and system data.

Reconstructs:
  - User-Agent string (OS, browser version, platform)
  - Installed extensions (unique identifier)
  - Language and timezone settings
  - Screen resolution (from preferences)
  - Font enumeration (from content settings)
  - WebGL renderer (from GPU info in preferences)
  - Canvas fingerprint components
  - Do Not Track setting
  - Cookie behavior settings
  - Plugin list
  - Hardware concurrency (from preferences)
  - Device memory (from preferences)
  - Platform string
  - Touch support indicators

The reconstructed fingerprint can be used to:
  1. Correlate sessions across different accounts
  2. Detect if the same browser was used on different sites
  3. Identify the user across VPN/proxy changes
  4. Generate a fingerprint hash for cross-reference

For authorized penetration testing and forensic investigations only.
"""
import json, hashlib, re
from pathlib import Path
from collections import defaultdict
from . import utils


def reconstruct(all_rows: list, browsers: dict, meta: dict) -> dict:
    """
    Reconstruct the browser fingerprint from all available data.

    Returns a detailed fingerprint profile with a unique hash.
    """
    fingerprints = {}

    # Process each browser/profile combination
    for browser_name, paths in browsers.items():
        for path in paths:
            profile_path = path.parent if hasattr(path, 'parent') else Path(path)
            fp_key = f"{browser_name}:{profile_path.name}"

            fp = {
                "browser": browser_name,
                "profile": str(profile_path),
                "user_agent": None,
                "browser_version": None,
                "os_platform": None,
                "language": None,
                "languages": [],
                "timezone": None,
                "screen_resolution": None,
                "color_depth": None,
                "device_memory": None,
                "hardware_concurrency": None,
                "do_not_track": None,
                "cookie_enabled": True,
                "webgl_vendor": None,
                "webgl_renderer": None,
                "gpu_info": None,
                "extensions": [],
                "extension_count": 0,
                "fonts": [],
                "plugins": [],
                "touch_support": None,
                "pdf_viewer": None,
                "canvas_hash": None,
                "audio_hash": None,
            }

            # Extract from Preferences file
            _extract_from_preferences(fp, profile_path, browser_name)

            # Extract from Local State
            _extract_from_local_state(fp, profile_path, browser_name)

            # Enrich from artifact rows
            _enrich_from_artifacts(fp, all_rows, browser_name, str(profile_path))

            # Generate fingerprint hash
            fp["fingerprint_hash"] = _generate_hash(fp)

            # Calculate uniqueness score (how unique is this fingerprint?)
            fp["uniqueness_score"] = _calculate_uniqueness(fp)

            fingerprints[fp_key] = fp

    # Cross-profile correlation
    correlations = _correlate_fingerprints(fingerprints)

    return {
        "fingerprints": fingerprints,
        "total_profiles": len(fingerprints),
        "correlations": correlations,
        "system_info": {
            "hostname": meta.get("hostname", ""),
            "os": meta.get("os", ""),
            "arch": meta.get("arch", ""),
        },
    }


def extract_as_artifacts(all_rows: list, browsers: dict, meta: dict) -> list:
    """Run fingerprint reconstruction and return as artifact rows."""
    report = reconstruct(all_rows, browsers, meta)
    rows = []

    for fp_key, fp in report["fingerprints"].items():
        rows.append({
            **meta, "browser": fp["browser"],
            "artifact": "fingerprint",
            "profile": fp["profile"],
            "url": fp["fingerprint_hash"],
            "title": f"Browser Fingerprint ({fp['browser']})",
            "visit_count": fp["uniqueness_score"],
            "visit_time_utc": None,
            "extra": json.dumps({
                "user_agent": fp["user_agent"],
                "language": fp["language"],
                "timezone": fp["timezone"],
                "screen_resolution": fp["screen_resolution"],
                "gpu": fp["webgl_renderer"],
                "extensions": fp["extension_count"],
                "do_not_track": fp["do_not_track"],
                "uniqueness_score": fp["uniqueness_score"],
            }, ensure_ascii=False),
        })

    return rows


# ---------------------------------------------------------------------------
# Data extraction from browser files
# ---------------------------------------------------------------------------

def _extract_from_preferences(fp: dict, profile_path: Path, browser: str):
    """Extract fingerprint data from Chromium Preferences file."""
    prefs_file = profile_path / "Preferences"
    if not prefs_file.exists():
        return

    try:
        prefs = json.loads(prefs_file.read_text(encoding="utf-8"))

        # Language settings
        fp["language"] = prefs.get("intl", {}).get("accept_languages", "")
        if fp["language"]:
            fp["languages"] = [l.strip() for l in fp["language"].split(",")]

        # Screen/display from profile
        window = prefs.get("browser", {}).get("window_placement", {})
        if window:
            w = window.get("width", 0)
            h = window.get("height", 0)
            if w and h:
                fp["screen_resolution"] = f"{w}x{h}"

        # Do Not Track
        fp["do_not_track"] = prefs.get("enable_do_not_track", False)

        # Download behavior (reveals OS paths)
        dl_dir = prefs.get("download", {}).get("default_directory", "")
        if dl_dir:
            if "Windows" in dl_dir or "C:\\" in dl_dir or "Users\\" in dl_dir:
                fp["os_platform"] = "Windows"
            elif "/Users/" in dl_dir:
                fp["os_platform"] = "macOS"
            elif "/home/" in dl_dir:
                fp["os_platform"] = "Linux"

        # Extensions
        ext_settings = prefs.get("extensions", {}).get("settings", {})
        if ext_settings:
            for ext_id, ext_data in ext_settings.items():
                if isinstance(ext_data, dict) and ext_data.get("state") == 1:
                    name = ext_data.get("manifest", {}).get("name", ext_id)
                    fp["extensions"].append({
                        "id": ext_id,
                        "name": name,
                        "version": ext_data.get("manifest", {}).get("version", ""),
                    })
            fp["extension_count"] = len(fp["extensions"])

        # Content settings — font-related
        content = prefs.get("webkit", {}).get("webprefs", {})
        if content:
            fonts = {}
            for key in ("fixed_font_family", "serif_font_family", "sans_serif_font_family",
                       "standard_font_family", "cursive_font_family", "fantasy_font_family"):
                val = content.get(key)
                if val:
                    if isinstance(val, dict):
                        fonts[key] = list(val.values())
                    else:
                        fonts[key] = val
            if fonts:
                fp["fonts"] = fonts

        # PDF viewer
        pdf_plugin = prefs.get("plugins", {}).get("always_open_pdf_externally", False)
        fp["pdf_viewer"] = not pdf_plugin

        # Timezone from profile
        tz = prefs.get("profile", {}).get("timezone_id")
        if tz:
            fp["timezone"] = tz

        utils.log_line(f"Fingerprint: extracted preferences from {prefs_file}")
    except Exception as e:
        utils.log_line(f"Fingerprint: error reading prefs {browser}: {e}")


def _extract_from_local_state(fp: dict, profile_path: Path, browser: str):
    """Extract GPU/hardware info from Local State."""
    local_state = profile_path.parent / "Local State"
    if not local_state.exists():
        local_state = profile_path / "Local State"
    if not local_state.exists():
        return

    try:
        state = json.loads(local_state.read_text(encoding="utf-8"))

        # GPU info
        gpu = state.get("gpu", {})
        if gpu:
            devices = gpu.get("gpu_device", [])
            if devices and isinstance(devices, list):
                primary = devices[0] if devices else {}
                fp["webgl_vendor"] = primary.get("vendor_string", "")
                fp["webgl_renderer"] = primary.get("device_string", "")
                fp["gpu_info"] = {
                    "vendor_id": primary.get("vendor_id", ""),
                    "device_id": primary.get("device_id", ""),
                    "driver_version": primary.get("driver_version", ""),
                }
            # Machine model
            model = gpu.get("machine_model_name")
            if model:
                fp["gpu_info"] = fp.get("gpu_info") or {}
                fp["gpu_info"]["machine_model"] = model

        # Hardware concurrency (CPU cores)
        hw = state.get("hardware", {})
        if hw:
            fp["hardware_concurrency"] = hw.get("cpu_core_count")
            fp["device_memory"] = hw.get("memory_mb")

        # Browser version
        last_version = state.get("last_browser_version")
        if not last_version:
            last_version = state.get("browser", {}).get("last_version")
        if last_version:
            fp["browser_version"] = last_version

        # User-Agent reconstruction
        if fp["browser_version"]:
            fp["user_agent"] = _reconstruct_user_agent(browser, fp["browser_version"],
                                                        fp["os_platform"] or meta_os())

    except Exception as e:
        utils.log_line(f"Fingerprint: error reading Local State: {e}")


def _enrich_from_artifacts(fp: dict, all_rows: list, browser: str, profile: str):
    """Enrich fingerprint from extracted artifact rows."""
    for row in all_rows:
        if row.get("browser") != browser:
            continue

        artifact = row.get("artifact", "")

        # Extract timezone from cookie domains
        if artifact == "cookie":
            extra = _parse_extra(row.get("extra", ""))
            # Some cookies reveal timezone
            if row.get("title") in ("timezone", "tz", "time_zone"):
                val = extra.get("value", "")
                if val and not fp["timezone"]:
                    fp["timezone"] = val

        # Extract screen info from autofill if present
        if artifact == "preference":
            if row.get("title") == "privacy_settings":
                extra = _parse_extra(row.get("extra", ""))
                if extra.get("do_not_track") is not None:
                    fp["do_not_track"] = extra["do_not_track"]


# ---------------------------------------------------------------------------
# Fingerprint hashing and uniqueness
# ---------------------------------------------------------------------------

def _generate_hash(fp: dict) -> str:
    """Generate a stable fingerprint hash from the key components."""
    components = [
        fp.get("user_agent", ""),
        fp.get("language", ""),
        fp.get("timezone", ""),
        fp.get("screen_resolution", ""),
        str(fp.get("color_depth", "")),
        str(fp.get("device_memory", "")),
        str(fp.get("hardware_concurrency", "")),
        str(fp.get("do_not_track", "")),
        fp.get("webgl_vendor", ""),
        fp.get("webgl_renderer", ""),
        str(fp.get("extension_count", 0)),
        # Extension IDs contribute significantly to uniqueness
        ",".join(sorted(e["id"] for e in fp.get("extensions", []))),
        str(fp.get("pdf_viewer", "")),
    ]

    raw = "|".join(str(c) for c in components)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _calculate_uniqueness(fp: dict) -> int:
    """
    Estimate how unique this fingerprint is (0-100).
    Higher = more unique = easier to track.
    """
    score = 0

    # Extensions are the strongest fingerprint component
    ext_count = fp.get("extension_count", 0)
    if ext_count >= 10:
        score += 30
    elif ext_count >= 5:
        score += 20
    elif ext_count >= 2:
        score += 10

    # GPU info is highly unique
    if fp.get("webgl_renderer"):
        score += 15

    # Language list uniqueness
    langs = fp.get("languages", [])
    if len(langs) >= 3:
        score += 10
    elif len(langs) >= 2:
        score += 5

    # Timezone
    if fp.get("timezone"):
        score += 5

    # Screen resolution
    if fp.get("screen_resolution"):
        res = fp["screen_resolution"]
        common = ["1920x1080", "1366x768", "1440x900", "1536x864", "2560x1440"]
        if res not in common:
            score += 10
        else:
            score += 3

    # Hardware specs
    if fp.get("hardware_concurrency"):
        score += 5
    if fp.get("device_memory"):
        score += 5

    # Custom fonts
    if fp.get("fonts"):
        score += 10

    # Do Not Track (minority setting)
    if fp.get("do_not_track"):
        score += 5

    return min(100, score)


def _correlate_fingerprints(fingerprints: dict) -> list:
    """Find correlations between different browser profiles."""
    correlations = []
    keys = list(fingerprints.keys())

    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            fp1 = fingerprints[keys[i]]
            fp2 = fingerprints[keys[j]]

            shared = []
            if fp1.get("timezone") and fp1["timezone"] == fp2.get("timezone"):
                shared.append("timezone")
            if fp1.get("language") and fp1["language"] == fp2.get("language"):
                shared.append("language")
            if fp1.get("screen_resolution") and fp1["screen_resolution"] == fp2.get("screen_resolution"):
                shared.append("screen_resolution")
            if fp1.get("webgl_renderer") and fp1["webgl_renderer"] == fp2.get("webgl_renderer"):
                shared.append("gpu")

            # Shared extensions
            ext1 = {e["id"] for e in fp1.get("extensions", [])}
            ext2 = {e["id"] for e in fp2.get("extensions", [])}
            shared_ext = ext1 & ext2
            if shared_ext:
                shared.append(f"extensions({len(shared_ext)})")

            if len(shared) >= 2:
                correlations.append({
                    "profile_1": keys[i],
                    "profile_2": keys[j],
                    "shared_attributes": shared,
                    "correlation_strength": len(shared) / 6 * 100,
                })

    return correlations


def _reconstruct_user_agent(browser: str, version: str, os_platform: str) -> str:
    """Reconstruct the User-Agent string from components."""
    if "Windows" in os_platform:
        os_str = "Windows NT 10.0; Win64; x64"
    elif "mac" in os_platform.lower() or "darwin" in os_platform.lower():
        os_str = "Macintosh; Intel Mac OS X 10_15_7"
    elif "linux" in os_platform.lower():
        os_str = "X11; Linux x86_64"
    else:
        os_str = "Windows NT 10.0; Win64; x64"

    if browser in ("chrome", "brave", "opera"):
        return f"Mozilla/5.0 ({os_str}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version} Safari/537.36"
    elif browser == "edge":
        return f"Mozilla/5.0 ({os_str}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version} Safari/537.36 Edg/{version}"
    elif browser == "firefox":
        return f"Mozilla/5.0 ({os_str}; rv:{version}) Gecko/20100101 Firefox/{version}"
    return f"Mozilla/5.0 ({os_str})"


def meta_os():
    """Get current OS platform string."""
    import platform
    return platform.platform()


def _parse_extra(extra_str):
    try:
        return json.loads(extra_str) if extra_str else {}
    except Exception:
        return {}
