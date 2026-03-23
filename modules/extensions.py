"""
Frostveil Extension Analysis — with permission-based threat scoring.

Analyzes installed browser extensions for:
- Dangerous permission combinations
- Known malicious extension patterns
- Excessive host permissions
- Background persistence
"""
import json, zipfile, io
from pathlib import Path
from . import utils, ioc_engine

def extract(browser, path: Path, meta):
    rows = []
    if browser in ["chrome", "edge"]:
        _extract_chromium_extensions(browser, path, meta, rows)
    elif browser == "firefox":
        _extract_firefox_extensions(path, meta, rows)
    return rows

def _extract_chromium_extensions(browser, path, meta, rows):
    extdir = path.parent / "Extensions"
    if not extdir.exists():
        return

    for ext in extdir.glob("*/*/manifest.json"):
        try:
            manifest = json.loads(ext.read_text(encoding="utf-8"))
            threat = ioc_engine.scan_extension(manifest)

            # Get extension ID from path
            ext_id = ext.parent.parent.name

            permissions = manifest.get("permissions", [])
            optional_perms = manifest.get("optional_permissions", [])

            # Check for content scripts
            content_scripts = manifest.get("content_scripts", [])
            cs_matches = []
            for cs in content_scripts:
                cs_matches.extend(cs.get("matches", []))

            rows.append({
                **meta, "browser": browser, "artifact": "extension",
                "profile": str(path.parent),
                "url": manifest.get("homepage_url", ""),
                "title": manifest.get("name", ""),
                "visit_count": None,
                "visit_time_utc": None,
                "extra": json.dumps({
                    "version": manifest.get("version", ""),
                    "manifest_version": manifest.get("manifest_version", 2),
                    "extension_id": ext_id,
                    "description": (manifest.get("description", "") or "")[:200],
                    "permissions": [str(p) for p in permissions],
                    "optional_permissions": [str(p) for p in optional_perms],
                    "content_script_matches": cs_matches[:10],
                    "has_background": bool(manifest.get("background")),
                    "threat_score": threat["threat_score"],
                    "risk_level": threat["risk_level"],
                    "flagged_permissions": threat["flagged_permissions"],
                }, ensure_ascii=False)
            })
        except Exception as e:
            utils.log_line(f"Error extension {ext}: {e}")

def _extract_firefox_extensions(path, meta, rows):
    profs = path.glob("*.default*") if path.is_dir() else []
    for prof in profs:
        # Try extensions.json first (better metadata)
        ext_json = prof / "extensions.json"
        if ext_json.exists():
            try:
                data = json.loads(ext_json.read_text(encoding="utf-8"))
                for addon in data.get("addons", []):
                    permissions = addon.get("userPermissions", {})
                    all_perms = permissions.get("permissions", []) + permissions.get("origins", [])

                    # Build a pseudo-manifest for threat scoring
                    pseudo_manifest = {"permissions": all_perms}
                    threat = ioc_engine.scan_extension(pseudo_manifest)

                    rows.append({
                        **meta, "browser": "firefox", "artifact": "extension",
                        "profile": str(prof),
                        "url": addon.get("sourceURI", ""),
                        "title": addon.get("name", addon.get("defaultLocale", {}).get("name", "")),
                        "visit_count": None,
                        "visit_time_utc": None,
                        "extra": json.dumps({
                            "version": addon.get("version", ""),
                            "extension_id": addon.get("id", ""),
                            "description": (addon.get("description", "") or "")[:200],
                            "type": addon.get("type", ""),
                            "active": addon.get("active", False),
                            "permissions": all_perms,
                            "threat_score": threat["threat_score"],
                            "risk_level": threat["risk_level"],
                            "flagged_permissions": threat["flagged_permissions"],
                        }, ensure_ascii=False)
                    })
                continue  # Skip XPI parsing if we got extensions.json
            except Exception as e:
                utils.log_line(f"Error parsing extensions.json {prof}: {e}")

        # Fallback: parse XPI files
        extdir = prof / "extensions"
        if extdir.exists():
            for xpi in extdir.glob("*.xpi"):
                try:
                    with zipfile.ZipFile(xpi, "r") as zf:
                        if "manifest.json" in zf.namelist():
                            manifest = json.loads(zf.read("manifest.json"))
                            threat = ioc_engine.scan_extension(manifest)
                            rows.append({
                                **meta, "browser": "firefox", "artifact": "extension",
                                "profile": str(prof),
                                "url": "",
                                "title": manifest.get("name", xpi.name),
                                "visit_count": None,
                                "visit_time_utc": None,
                                "extra": json.dumps({
                                    "version": manifest.get("version", ""),
                                    "permissions": manifest.get("permissions", []),
                                    "threat_score": threat["threat_score"],
                                    "risk_level": threat["risk_level"],
                                    "flagged_permissions": threat["flagged_permissions"],
                                }, ensure_ascii=False)
                            })
                except Exception as e:
                    utils.log_line(f"Error extension xpi {xpi}: {e}")
