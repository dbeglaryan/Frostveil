"""
Frostveil Preference Mining — extract forensically relevant settings
from browser preference files.

Extracts:
- Default search engine, homepage
- Proxy settings
- Download directory
- Sync account (email)
- Privacy settings (Do Not Track, Safe Browsing)
- Extension installation sources
- Last session info
- Geolocation permissions
- Notification permissions
"""
import json, re
from pathlib import Path
from . import utils

def extract(browser, path: Path, meta) -> list:
    rows = []
    if browser in ("chrome", "edge"):
        _extract_chromium_prefs(browser, path, meta, rows)
        _extract_chromium_secure_prefs(browser, path, meta, rows)
    elif browser == "firefox":
        _extract_firefox_prefs(path, meta, rows)
    return rows

def _extract_chromium_prefs(browser, path, meta, rows):
    """Extract settings from Chromium Preferences file."""
    prefs_file = path.parent / "Preferences"
    if not prefs_file.exists():
        return

    try:
        prefs = json.loads(prefs_file.read_text(encoding="utf-8"))

        # Account / Sync info
        account = prefs.get("account_info", [])
        if account:
            for acct in account:
                _add(rows, meta, browser, path, "sync_account",
                     acct.get("email", ""),
                     f"Full name: {acct.get('full_name', '')}, "
                     f"given: {acct.get('given_name', '')}")

        # Profile name and avatar
        profile = prefs.get("profile", {})
        if profile.get("name"):
            _add(rows, meta, browser, path, "profile_name",
                 profile["name"], f"avatar_index={profile.get('avatar_index', '')}")

        # Default search engine
        dse = prefs.get("default_search_provider_data", {}).get("template_url_data", {})
        if dse:
            _add(rows, meta, browser, path, "default_search_engine",
                 dse.get("url", ""), dse.get("short_name", ""))

        # Homepage
        homepage = prefs.get("homepage")
        if homepage:
            _add(rows, meta, browser, path, "homepage", homepage, "")

        # Download directory
        download_dir = prefs.get("download", {}).get("default_directory") or \
                       prefs.get("savefile", {}).get("default_directory")
        if download_dir:
            _add(rows, meta, browser, path, "download_directory", download_dir, "")

        # Proxy settings
        proxy = prefs.get("proxy", {})
        if proxy:
            mode = proxy.get("mode", "")
            server = proxy.get("server", "")
            if mode and mode != "system":
                _add(rows, meta, browser, path, "proxy_setting",
                     server or mode,
                     json.dumps({"mode": mode, "server": server,
                                "bypass": proxy.get("bypass_list", "")}))

        # Privacy settings
        dns_prefetch = prefs.get("dns_prefetching", {}).get("enabled")
        safe_browsing = prefs.get("safebrowsing", {}).get("enabled")
        dnt = prefs.get("enable_do_not_track")

        privacy = {}
        if dns_prefetch is not None:
            privacy["dns_prefetch"] = dns_prefetch
        if safe_browsing is not None:
            privacy["safe_browsing"] = safe_browsing
        if dnt is not None:
            privacy["do_not_track"] = dnt

        if privacy:
            _add(rows, meta, browser, path, "privacy_settings",
                 "", json.dumps(privacy))

        # Content settings (permissions)
        content = prefs.get("profile", {}).get("content_settings", {}).get("exceptions", {})

        # Geolocation permissions
        geo = content.get("geolocation", {})
        for site, setting in list(geo.items())[:20]:
            val = setting.get("setting", "")
            _add(rows, meta, browser, path, "geolocation_permission",
                 site, f"setting={val}")

        # Notification permissions
        notif = content.get("notifications", {})
        for site, setting in list(notif.items())[:20]:
            val = setting.get("setting", "")
            _add(rows, meta, browser, path, "notification_permission",
                 site, f"setting={val}")

        # Camera/microphone permissions
        for perm_type in ("media_stream_camera", "media_stream_mic"):
            perms = content.get(perm_type, {})
            for site, setting in list(perms.items())[:10]:
                val = setting.get("setting", "")
                _add(rows, meta, browser, path, f"{perm_type}_permission",
                     site, f"setting={val}")

        utils.log_line(f"Preferences mined from {prefs_file}")
    except Exception as e:
        utils.log_line(f"Error prefs {browser}: {e}")

def _extract_chromium_secure_prefs(browser, path, meta, rows):
    """Extract from Secure Preferences (tamper-protected settings)."""
    secure_file = path.parent / "Secure Preferences"
    if not secure_file.exists():
        return

    try:
        prefs = json.loads(secure_file.read_text(encoding="utf-8"))

        # Extension settings and install sources
        ext_settings = prefs.get("extensions", {}).get("settings", {})
        for ext_id, ext_data in list(ext_settings.items())[:50]:
            if isinstance(ext_data, dict):
                install_time = ext_data.get("install_time")
                from_store = ext_data.get("from_webstore", False)
                state = ext_data.get("state", 0)
                name = ext_data.get("manifest", {}).get("name", ext_id)

                if state == 1:  # Enabled
                    _add(rows, meta, browser, path, "extension_install",
                         ext_id, json.dumps({
                             "name": name,
                             "from_webstore": from_store,
                             "install_time": install_time,
                             "state": "enabled" if state == 1 else "disabled",
                         }))

    except Exception as e:
        utils.log_line(f"Error secure prefs {browser}: {e}")

def _extract_firefox_prefs(path, meta, rows):
    """Extract Firefox preferences from prefs.js."""
    if not path.is_dir():
        return
    for prof in path.glob("*.default*"):
        prefs_js = prof / "prefs.js"
        if not prefs_js.exists():
            continue

        try:
            content = prefs_js.read_text(encoding="utf-8", errors="replace")

            # Parse user_pref() calls
            prefs = {}
            for match in re.finditer(r'user_pref\("([^"]+)",\s*(.+?)\);', content):
                key = match.group(1)
                val = match.group(2).strip().strip('"')
                prefs[key] = val

            # Interesting preferences
            interesting = {
                "browser.startup.homepage": "homepage",
                "browser.search.defaultenginename": "default_search_engine",
                "browser.download.dir": "download_directory",
                "network.proxy.type": "proxy_type",
                "network.proxy.http": "proxy_http",
                "network.proxy.http_port": "proxy_port",
                "privacy.donottrackheader.enabled": "do_not_track",
                "privacy.sanitize.sanitizeOnShutdown": "clear_on_shutdown",
                "browser.privatebrowsing.autostart": "always_private",
                "services.sync.username": "sync_account",
                "browser.newtabpage.pinned": "pinned_sites",
            }

            for pref_key, artifact_name in interesting.items():
                if pref_key in prefs:
                    val = prefs[pref_key]
                    _add(rows, meta, "firefox", prof, artifact_name,
                         val, f"pref={pref_key}")

            utils.log_line(f"Firefox prefs mined from {prefs_js}")
        except Exception as e:
            utils.log_line(f"Error firefox prefs {prof}: {e}")

def _add(rows, meta, browser, path, setting_name, value, extra):
    """Helper to add a preference row."""
    rows.append({
        **meta, "browser": browser, "artifact": "preference",
        "profile": str(path.parent) if hasattr(path, 'parent') else str(path),
        "url": value,
        "title": setting_name,
        "visit_count": None,
        "visit_time_utc": None,
        "extra": extra if isinstance(extra, str) else json.dumps(extra),
    })
