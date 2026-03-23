"""
Frostveil Network Reconnaissance — extract WiFi profiles, DNS cache,
saved network credentials, and network configuration.

Pure Python, OS-native commands only.
"""
import subprocess, json, re, sys
from pathlib import Path
from . import utils

def extract(meta):
    """Extract network intelligence. Not browser-specific."""
    rows = []
    if sys.platform.startswith("win"):
        _extract_wifi_profiles_win(meta, rows)
        _extract_dns_cache_win(meta, rows)
        _extract_arp_table_win(meta, rows)
        _extract_network_interfaces_win(meta, rows)
    elif sys.platform == "darwin":
        _extract_wifi_profiles_mac(meta, rows)
        _extract_dns_cache_unix(meta, rows)
        _extract_arp_table_unix(meta, rows)
    else:
        _extract_wifi_profiles_linux(meta, rows)
        _extract_dns_cache_unix(meta, rows)
        _extract_arp_table_unix(meta, rows)
    return rows

# ---------------------------------------------------------------------------
# WiFi profiles
# ---------------------------------------------------------------------------

def _extract_wifi_profiles_win(meta, rows):
    """Extract saved WiFi profiles and passwords on Windows."""
    try:
        output = subprocess.check_output(
            ["netsh", "wlan", "show", "profiles"],
            text=True, stderr=subprocess.DEVNULL, timeout=15
        )
        profiles = re.findall(r"All User Profile\s*:\s*(.+)", output)
        for profile_name in profiles:
            profile_name = profile_name.strip()
            password = ""
            auth_type = ""
            try:
                detail = subprocess.check_output(
                    ["netsh", "wlan", "show", "profile",
                     f"name={profile_name}", "key=clear"],
                    text=True, stderr=subprocess.DEVNULL, timeout=10
                )
                pwd_match = re.search(r"Key Content\s*:\s*(.+)", detail)
                auth_match = re.search(r"Authentication\s*:\s*(.+)", detail)
                if pwd_match:
                    password = pwd_match.group(1).strip()
                if auth_match:
                    auth_type = auth_match.group(1).strip()
            except Exception:
                pass

            rows.append({
                **meta, "browser": "system", "artifact": "wifi_profile",
                "profile": "system",
                "url": "",
                "title": profile_name,
                "visit_count": None,
                "visit_time_utc": None,
                "extra": json.dumps({
                    "password": password,
                    "authentication": auth_type,
                })
            })
        utils.log_line(f"WiFi profiles extracted: {len(profiles)}")
    except Exception as e:
        utils.log_line(f"Error extracting WiFi profiles: {e}")

def _extract_wifi_profiles_mac(meta, rows):
    """Extract saved WiFi profiles on macOS."""
    try:
        output = subprocess.check_output(
            ["networksetup", "-listpreferredwirelessnetworks", "en0"],
            text=True, stderr=subprocess.DEVNULL, timeout=10
        )
        for line in output.splitlines()[1:]:
            ssid = line.strip()
            if ssid:
                rows.append({
                    **meta, "browser": "system", "artifact": "wifi_profile",
                    "profile": "system", "url": "", "title": ssid,
                    "visit_count": None, "visit_time_utc": None,
                    "extra": json.dumps({"password": "<keychain_protected>"})
                })
    except Exception as e:
        utils.log_line(f"Error WiFi profiles macOS: {e}")

def _extract_wifi_profiles_linux(meta, rows):
    """Extract saved WiFi profiles on Linux (NetworkManager)."""
    nm_path = Path("/etc/NetworkManager/system-connections")
    if not nm_path.exists():
        return
    try:
        for conn_file in nm_path.iterdir():
            if conn_file.is_file():
                try:
                    content = conn_file.read_text(errors="replace")
                    ssid = ""
                    psk = ""
                    for line in content.splitlines():
                        if line.startswith("ssid="):
                            ssid = line.split("=", 1)[1]
                        elif line.startswith("psk="):
                            psk = line.split("=", 1)[1]
                    if ssid:
                        rows.append({
                            **meta, "browser": "system", "artifact": "wifi_profile",
                            "profile": "system", "url": "", "title": ssid,
                            "visit_count": None, "visit_time_utc": None,
                            "extra": json.dumps({"password": psk})
                        })
                except PermissionError:
                    utils.log_line(f"Permission denied reading {conn_file}")
    except Exception as e:
        utils.log_line(f"Error WiFi profiles Linux: {e}")

# ---------------------------------------------------------------------------
# DNS cache
# ---------------------------------------------------------------------------

def _extract_dns_cache_win(meta, rows):
    """Extract Windows DNS resolver cache."""
    try:
        output = subprocess.check_output(
            ["ipconfig", "/displaydns"],
            text=True, stderr=subprocess.DEVNULL, timeout=15
        )
        current_name = ""
        for line in output.splitlines():
            line = line.strip()
            name_match = re.match(r"Record Name\s*:\s*(.+)", line)
            addr_match = re.match(r"A \(Host\) Record\s*:\s*(.+)", line)
            if name_match:
                current_name = name_match.group(1).strip()
            elif addr_match and current_name:
                ip = addr_match.group(1).strip()
                rows.append({
                    **meta, "browser": "system", "artifact": "dns_cache",
                    "profile": "system",
                    "url": current_name,
                    "title": ip,
                    "visit_count": None,
                    "visit_time_utc": None,
                    "extra": json.dumps({"record_type": "A"})
                })
                current_name = ""
        utils.log_line(f"DNS cache extracted")
    except Exception as e:
        utils.log_line(f"Error DNS cache: {e}")

def _extract_dns_cache_unix(meta, rows):
    """Extract DNS cache on Unix systems (limited — most don't cache by default)."""
    # Try systemd-resolve on Linux
    try:
        output = subprocess.check_output(
            ["resolvectl", "statistics"],
            text=True, stderr=subprocess.DEVNULL, timeout=10
        )
        rows.append({
            **meta, "browser": "system", "artifact": "dns_cache",
            "profile": "system", "url": "<statistics>", "title": "resolvectl",
            "visit_count": None, "visit_time_utc": None,
            "extra": json.dumps({"raw": output[:500]})
        })
    except Exception:
        pass

# ---------------------------------------------------------------------------
# ARP table
# ---------------------------------------------------------------------------

def _extract_arp_table_win(meta, rows):
    """Extract ARP table on Windows."""
    try:
        output = subprocess.check_output(
            ["arp", "-a"],
            text=True, stderr=subprocess.DEVNULL, timeout=10
        )
        for line in output.splitlines():
            match = re.match(r"\s*([\d.]+)\s+([\w-]+)\s+(\w+)", line)
            if match:
                ip, mac, arp_type = match.groups()
                if ip != "Interface:" and not ip.startswith("---"):
                    rows.append({
                        **meta, "browser": "system", "artifact": "arp_entry",
                        "profile": "system",
                        "url": ip,
                        "title": mac,
                        "visit_count": None,
                        "visit_time_utc": None,
                        "extra": json.dumps({"type": arp_type})
                    })
    except Exception as e:
        utils.log_line(f"Error ARP table: {e}")

def _extract_arp_table_unix(meta, rows):
    """Extract ARP table on Unix."""
    try:
        output = subprocess.check_output(
            ["arp", "-a"],
            text=True, stderr=subprocess.DEVNULL, timeout=10
        )
        for line in output.splitlines():
            match = re.match(r".*\(([\d.]+)\)\s+at\s+([\w:]+)", line)
            if match:
                ip, mac = match.groups()
                rows.append({
                    **meta, "browser": "system", "artifact": "arp_entry",
                    "profile": "system", "url": ip, "title": mac,
                    "visit_count": None, "visit_time_utc": None,
                    "extra": json.dumps({"type": "dynamic"})
                })
    except Exception as e:
        utils.log_line(f"Error ARP table: {e}")

# ---------------------------------------------------------------------------
# Network interfaces
# ---------------------------------------------------------------------------

def _extract_network_interfaces_win(meta, rows):
    """Extract network interface configuration on Windows."""
    try:
        output = subprocess.check_output(
            ["ipconfig", "/all"],
            text=True, stderr=subprocess.DEVNULL, timeout=10
        )
        current_adapter = ""
        for line in output.splitlines():
            adapter_match = re.match(r"^(\w.+adapter\s+.+):", line, re.IGNORECASE)
            if adapter_match:
                current_adapter = adapter_match.group(1).strip()
            ip_match = re.match(r"\s+IPv4 Address.*:\s*([\d.]+)", line)
            mac_match = re.match(r"\s+Physical Address.*:\s*([\w-]+)", line)
            if ip_match and current_adapter:
                rows.append({
                    **meta, "browser": "system", "artifact": "network_interface",
                    "profile": "system", "url": ip_match.group(1),
                    "title": current_adapter, "visit_count": None,
                    "visit_time_utc": None,
                    "extra": json.dumps({"type": "ipv4"})
                })
            if mac_match and current_adapter:
                rows.append({
                    **meta, "browser": "system", "artifact": "network_interface",
                    "profile": "system", "url": mac_match.group(1),
                    "title": current_adapter, "visit_count": None,
                    "visit_time_utc": None,
                    "extra": json.dumps({"type": "mac_address"})
                })
    except Exception as e:
        utils.log_line(f"Error network interfaces: {e}")
