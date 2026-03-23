import os, sys, shutil, tempfile, hashlib, platform, getpass, socket, subprocess
from pathlib import Path
from datetime import datetime

# ---- Time helpers ----
def utc_from_webkit(ts):
    if not ts or ts == 0:
        return None
    try:
        return datetime.utcfromtimestamp(ts/1e6 - 11644473600).isoformat()
    except (OSError, ValueError, OverflowError):
        return None

def utc_from_unix(ts):
    if not ts or ts == 0:
        return None
    try:
        return datetime.utcfromtimestamp(ts/1e6).isoformat()
    except (OSError, ValueError, OverflowError):
        return None

# ---- Hashing ----
def sha256_file(path: Path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

# ---- Metadata ----
def get_metadata():
    meta = {
        "hostname": socket.gethostname(),
        "username": getpass.getuser(),
        "os": platform.platform(),
        "acquired_utc": datetime.utcnow().isoformat() + "Z",
    }
    # Extended metadata for forensic context
    try:
        meta["python_version"] = platform.python_version()
        meta["arch"] = platform.machine()
        meta["fqdn"] = socket.getfqdn()
    except Exception:
        pass
    return meta

# ---- Logging ----
_log_file = "frostveil.log"

def log_line(msg):
    with open(_log_file, "a", encoding="utf-8") as f:
        f.write(f"[{datetime.utcnow().isoformat()}Z] {msg}\n")

def progress(msg):
    print(f"[.] {msg}")

# ---- Manifest ----
def build_manifest(meta, outputs, all_rows, errors):
    import collections
    counts = collections.Counter(r["artifact"] for r in all_rows)
    return {
        "frostveil_version": "2.0.0",
        "metadata": meta,
        "outputs": {str(f): sha256_file(f) for f in outputs},
        "counts": dict(counts),
        "total_artifacts": len(all_rows),
        "errors": errors,
    }

def sign_manifest(path):
    """HMAC-SHA256 manifest signing with machine-derived key."""
    try:
        from .crypto import hmac_sign
        data = Path(path).read_bytes()
        sig = hmac_sign(data)
        sig_data = {
            "algorithm": "HMAC-SHA256",
            "signature": sig,
            "signed_at": datetime.utcnow().isoformat() + "Z",
            "signer": f"{getpass.getuser()}@{socket.gethostname()}",
        }
        import json
        Path(path + ".sig").write_text(json.dumps(sig_data, indent=2), encoding="utf-8")
        log_line("Manifest signed with HMAC-SHA256")
    except Exception as e:
        # Fallback to simple SHA256 if crypto module fails
        try:
            data = Path(path).read_bytes()
            sig = hashlib.sha256(data).hexdigest()
            Path(path + ".sig").write_text(sig, encoding="utf-8")
            log_line(f"Manifest signed with SHA256 fallback: {e}")
        except Exception as e2:
            log_line(f"Failed to sign manifest: {e2}")

# ---- File copy with VSS fallback ----
def copy_with_vss(path: Path) -> Path:
    shadow_path = Path(tempfile.gettempdir()) / f"fv_{os.getpid()}_{path.name}"
    try:
        output = subprocess.check_output(["vssadmin", "list", "shadows"], text=True, stderr=subprocess.DEVNULL)
        for line in output.splitlines():
            if "Shadow Copy Volume:" in line:
                vol = line.split(":",1)[1].strip()
                candidate = Path(vol) / str(path).lstrip("\\")
                if candidate.exists():
                    shutil.copy2(candidate, shadow_path)
                    return shadow_path
    except Exception as e:
        log_line(f"VSS fallback failed for {path}: {e}")
    return None

def safe_copy(path: Path) -> Path:
    if not path.exists():
        return None
    tmp = Path(tempfile.gettempdir()) / f"fv_{os.getpid()}_{path.name}"
    try:
        shutil.copy2(path, tmp)
        return tmp
    except PermissionError:
        log_line(f"Permission denied copying {path}, trying VSS")
        if sys.platform.startswith("win"):
            vss = copy_with_vss(path)
            if vss: return vss
    except Exception as e:
        log_line(f"Error copying {path}: {e}")
    return None

# ---- Temp file cleanup ----
def cleanup_temp():
    """Remove temporary artifact copies."""
    tmp_dir = Path(tempfile.gettempdir())
    cleaned = 0
    for f in tmp_dir.glob(f"fv_{os.getpid()}_*"):
        try:
            f.unlink()
            cleaned += 1
        except Exception:
            pass
    if cleaned:
        log_line(f"Cleaned up {cleaned} temp files")

# ---- User home discovery ----
def find_all_user_homes():
    homes = [Path.home()]
    plat = sys.platform
    if plat.startswith("win"):
        # Use HOMEDRIVE or SystemDrive to support non-C: installs
        drive = os.environ.get("HOMEDRIVE", os.environ.get("SystemDrive", "C:"))
        base = Path(f"{drive}/Users")
    elif plat == "darwin":
        base = Path("/Users")
    else:
        base = Path("/home")
    if base.exists():
        found = [p for p in base.iterdir() if p.is_dir()]
        if found:
            homes = found
    return homes

# ---- Browser profile discovery ----
def find_browsers():
    found = {}
    for home in find_all_user_homes():
        plat = sys.platform

        def add(name, path):
            try:
                if path.exists():
                    found.setdefault(name, []).append(path)
            except PermissionError:
                log_line(f"[ACCESS DENIED] Could not access {path} (user={home.name})")
            except Exception as e:
                log_line(f"[ERROR] Failed to check {path}: {e}")

        try:
            if plat.startswith("win"):
                base_local = home / "AppData/Local"
                base_roam  = home / "AppData/Roaming"

                # Chrome: all profiles
                chrome_base = base_local / "Google/Chrome/User Data"
                try:
                    if chrome_base.exists():
                        for prof in chrome_base.glob("*/History"):
                            add("chrome", prof)
                except PermissionError:
                    log_line(f"[ACCESS DENIED] Cannot list Chrome profiles for {home}")

                # Edge: all profiles
                edge_base = base_local / "Microsoft/Edge/User Data"
                try:
                    if edge_base.exists():
                        for prof in edge_base.glob("*/History"):
                            add("edge", prof)
                except PermissionError:
                    log_line(f"[ACCESS DENIED] Cannot list Edge profiles for {home}")

                # Brave
                brave_base = base_local / "BraveSoftware/Brave-Browser/User Data"
                try:
                    if brave_base.exists():
                        for prof in brave_base.glob("*/History"):
                            add("brave", prof)
                except PermissionError:
                    log_line(f"[ACCESS DENIED] Cannot list Brave profiles for {home}")

                # Opera
                opera_base = base_roam / "Opera Software/Opera Stable"
                try:
                    if opera_base.exists():
                        for prof in opera_base.glob("*/History"):
                            add("opera", prof)
                        # Opera stores History in the base dir too
                        hist = opera_base / "History"
                        if hist.exists():
                            add("opera", hist)
                except PermissionError:
                    log_line(f"[ACCESS DENIED] Cannot list Opera profiles for {home}")

                # Opera GX
                operagx_base = base_roam / "Opera Software/Opera GX Stable"
                try:
                    if operagx_base.exists():
                        for prof in operagx_base.glob("*/History"):
                            add("opera_gx", prof)
                        hist = operagx_base / "History"
                        if hist.exists():
                            add("opera_gx", hist)
                except PermissionError:
                    log_line(f"[ACCESS DENIED] Cannot list Opera GX profiles for {home}")

                # Vivaldi
                vivaldi_base = base_local / "Vivaldi/User Data"
                try:
                    if vivaldi_base.exists():
                        for prof in vivaldi_base.glob("*/History"):
                            add("vivaldi", prof)
                except PermissionError:
                    log_line(f"[ACCESS DENIED] Cannot list Vivaldi profiles for {home}")

                # Yandex
                yandex_base = base_local / "Yandex/YandexBrowser/User Data"
                try:
                    if yandex_base.exists():
                        for prof in yandex_base.glob("*/History"):
                            add("yandex", prof)
                except PermissionError:
                    log_line(f"[ACCESS DENIED] Cannot list Yandex profiles for {home}")

                # Chromium
                chromium_base = base_local / "Chromium/User Data"
                try:
                    if chromium_base.exists():
                        for prof in chromium_base.glob("*/History"):
                            add("chromium", prof)
                except PermissionError:
                    log_line(f"[ACCESS DENIED] Cannot list Chromium profiles for {home}")

                # Firefox
                add("firefox", base_roam / "Mozilla/Firefox/Profiles")

                # Waterfox
                add("waterfox", base_roam / "Waterfox/Profiles")

            elif plat == "darwin":
                chrome_base = home / "Library/Application Support/Google/Chrome"
                try:
                    if chrome_base.exists():
                        for prof in chrome_base.glob("*/History"):
                            add("chrome", prof)
                except PermissionError:
                    log_line(f"[ACCESS DENIED] Cannot list Chrome profiles for {home}")

                edge_base = home / "Library/Application Support/Microsoft Edge"
                try:
                    if edge_base.exists():
                        for prof in edge_base.glob("*/History"):
                            add("edge", prof)
                except PermissionError:
                    log_line(f"[ACCESS DENIED] Cannot list Edge profiles for {home}")

                add("safari", home / "Library/Safari/History.db")
                add("firefox", home / "Library/Application Support/Firefox/Profiles")

                # Brave macOS
                brave_base = home / "Library/Application Support/BraveSoftware/Brave-Browser"
                try:
                    if brave_base.exists():
                        for prof in brave_base.glob("*/History"):
                            add("brave", prof)
                except PermissionError:
                    pass

                # Vivaldi macOS
                vivaldi_base = home / "Library/Application Support/Vivaldi"
                try:
                    if vivaldi_base.exists():
                        for prof in vivaldi_base.glob("*/History"):
                            add("vivaldi", prof)
                except PermissionError:
                    pass

                # Chromium macOS
                chromium_base = home / "Library/Application Support/Chromium"
                try:
                    if chromium_base.exists():
                        for prof in chromium_base.glob("*/History"):
                            add("chromium", prof)
                except PermissionError:
                    pass

            else:  # Linux
                chrome_base = home / ".config/google-chrome"
                try:
                    if chrome_base.exists():
                        for prof in chrome_base.glob("*/History"):
                            add("chrome", prof)
                except PermissionError:
                    log_line(f"[ACCESS DENIED] Cannot list Chrome profiles for {home}")

                edge_base = home / ".config/microsoft-edge"
                try:
                    if edge_base.exists():
                        for prof in edge_base.glob("*/History"):
                            add("edge", prof)
                except PermissionError:
                    log_line(f"[ACCESS DENIED] Cannot list Edge profiles for {home}")

                add("firefox", home / ".mozilla/firefox")

                # Brave Linux
                brave_base = home / ".config/BraveSoftware/Brave-Browser"
                try:
                    if brave_base.exists():
                        for prof in brave_base.glob("*/History"):
                            add("brave", prof)
                except PermissionError:
                    pass

                # Vivaldi Linux
                vivaldi_base = home / ".config/vivaldi"
                try:
                    if vivaldi_base.exists():
                        for prof in vivaldi_base.glob("*/History"):
                            add("vivaldi", prof)
                except PermissionError:
                    pass

                # Chromium Linux
                chromium_base = home / ".config/chromium"
                try:
                    if chromium_base.exists():
                        for prof in chromium_base.glob("*/History"):
                            add("chromium", prof)
                except PermissionError:
                    pass

                # Yandex Linux
                yandex_base = home / ".config/yandex-browser"
                try:
                    if yandex_base.exists():
                        for prof in yandex_base.glob("*/History"):
                            add("yandex", prof)
                except PermissionError:
                    pass

        except PermissionError:
            log_line(f"[ACCESS DENIED] Skipping entire home directory {home}")
        except Exception as e:
            log_line(f"[ERROR] Unexpected error scanning {home}: {e}")

    return found
