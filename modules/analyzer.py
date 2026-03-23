"""
Frostveil Forensic Analyzer — cross-artifact correlation, pattern discovery,
and intelligence extraction.

Implements:
- Cross-artifact correlation (link history → downloads → credentials)
- Domain frequency analysis (most visited, unique per-day)
- Session reconstruction (browsing sessions from time gaps)
- Credential reuse detection
- Download risk assessment
- Privacy exposure scoring
"""
import json, re, collections, math
from datetime import datetime, timedelta
from urllib.parse import urlparse
from . import utils

def full_analysis(rows: list) -> dict:
    """Run all analysis passes on collected artifacts. Returns analysis report."""
    report = {
        "domain_intel": _domain_intelligence(rows),
        "session_reconstruction": _reconstruct_sessions(rows),
        "credential_analysis": _analyze_credentials(rows),
        "download_analysis": _analyze_downloads(rows),
        "privacy_exposure": _privacy_exposure(rows),
        "cross_correlation": _cross_correlate(rows),
        "browser_fingerprint": _browser_fingerprint(rows),
    }
    return report

# ---------------------------------------------------------------------------
# Domain intelligence
# ---------------------------------------------------------------------------

def _domain_intelligence(rows: list) -> dict:
    """Analyze domain visit patterns for intelligence."""
    domain_visits = collections.Counter()
    domain_first_seen = {}
    domain_last_seen = {}
    domain_by_day = collections.defaultdict(set)

    for r in rows:
        url = r.get("url", "")
        ts = r.get("visit_time_utc")
        if not url:
            continue
        try:
            domain = urlparse(url).netloc.lower().split(":")[0]
        except Exception:
            continue
        if not domain:
            continue

        domain_visits[domain] += 1
        if ts:
            if domain not in domain_first_seen or ts < domain_first_seen[domain]:
                domain_first_seen[domain] = ts
            if domain not in domain_last_seen or ts > domain_last_seen[domain]:
                domain_last_seen[domain] = ts
            day = ts[:10]
            domain_by_day[domain].add(day)

    top_domains = domain_visits.most_common(50)
    unique_domains = len(domain_visits)

    # Calculate domain diversity score (how spread out browsing is)
    if domain_visits:
        total = sum(domain_visits.values())
        probs = [c / total for c in domain_visits.values()]
        diversity = -sum(p * math.log2(p) for p in probs if p > 0)
    else:
        diversity = 0.0

    # Identify one-time domains (potentially suspicious)
    one_time_domains = [d for d, c in domain_visits.items() if c == 1]

    return {
        "unique_domains": unique_domains,
        "top_50_domains": [{"domain": d, "visits": c,
                            "first_seen": domain_first_seen.get(d),
                            "last_seen": domain_last_seen.get(d),
                            "active_days": len(domain_by_day.get(d, set()))}
                           for d, c in top_domains],
        "diversity_score": round(diversity, 2),
        "one_time_domains_count": len(one_time_domains),
        "one_time_domains_sample": one_time_domains[:20],
    }

# ---------------------------------------------------------------------------
# Session reconstruction
# ---------------------------------------------------------------------------

def _reconstruct_sessions(rows: list) -> dict:
    """
    Reconstruct browsing sessions from timestamp gaps.
    A new session starts after >30 minutes of inactivity.
    """
    SESSION_GAP = timedelta(minutes=30)

    timed_rows = []
    for r in rows:
        ts = r.get("visit_time_utc")
        if ts and r.get("artifact") == "history":
            try:
                dt = datetime.fromisoformat(ts.replace("Z", ""))
                timed_rows.append((dt, r))
            except Exception:
                pass

    if not timed_rows:
        return {"sessions": [], "total_sessions": 0}

    timed_rows.sort(key=lambda x: x[0])

    sessions = []
    current_session = {"start": timed_rows[0][0], "end": timed_rows[0][0],
                       "urls": [], "domains": set(), "count": 0}

    for i, (dt, row) in enumerate(timed_rows):
        if i > 0 and (dt - current_session["end"]) > SESSION_GAP:
            # Close current session
            current_session["duration_minutes"] = (
                current_session["end"] - current_session["start"]
            ).total_seconds() / 60
            current_session["domains"] = list(current_session["domains"])
            current_session["start"] = current_session["start"].isoformat()
            current_session["end"] = current_session["end"].isoformat()
            sessions.append(current_session)
            current_session = {"start": dt, "end": dt, "urls": [], "domains": set(), "count": 0}

        current_session["end"] = dt
        current_session["count"] += 1
        try:
            domain = urlparse(row.get("url", "")).netloc
            current_session["domains"].add(domain)
        except Exception:
            pass

    # Close last session
    if current_session["count"] > 0:
        current_session["duration_minutes"] = (
            current_session["end"] - current_session["start"]
        ).total_seconds() / 60
        current_session["domains"] = list(current_session["domains"])
        current_session["start"] = current_session["start"].isoformat()
        current_session["end"] = current_session["end"].isoformat()
        sessions.append(current_session)

    # Session statistics
    durations = [s["duration_minutes"] for s in sessions]
    avg_duration = sum(durations) / len(durations) if durations else 0
    avg_pages = sum(s["count"] for s in sessions) / len(sessions) if sessions else 0

    return {
        "total_sessions": len(sessions),
        "avg_duration_minutes": round(avg_duration, 1),
        "avg_pages_per_session": round(avg_pages, 1),
        "longest_session_minutes": round(max(durations), 1) if durations else 0,
        "sessions": sessions[:100],  # Limit output
    }

# ---------------------------------------------------------------------------
# Credential analysis
# ---------------------------------------------------------------------------

def _analyze_credentials(rows: list) -> dict:
    """Analyze credential patterns for security insights."""
    cred_rows = [r for r in rows if r.get("artifact") == "credential"]
    if not cred_rows:
        return {"total_credentials": 0}

    # Detect password reuse (same password hash across different sites)
    domain_usernames = collections.defaultdict(set)
    username_domains = collections.defaultdict(set)

    for r in cred_rows:
        url = r.get("url", "")
        username = r.get("title", "")
        try:
            domain = urlparse(url).netloc.lower()
        except Exception:
            domain = url
        if username:
            domain_usernames[domain].add(username)
            username_domains[username].add(domain)

    # Find reused usernames across domains
    reused_usernames = {u: list(domains) for u, domains in username_domains.items()
                       if len(domains) > 1}

    # Check for credential exposure in extra data
    decrypted_count = 0
    encrypted_count = 0
    for r in cred_rows:
        extra = r.get("extra", "")
        if "<encrypted" in extra or "<nss_encrypted" in extra or "<decryption_failed>" in extra:
            encrypted_count += 1
        elif '"password":' in extra:
            decrypted_count += 1

    return {
        "total_credentials": len(cred_rows),
        "unique_domains": len(domain_usernames),
        "reused_usernames": reused_usernames,
        "reuse_risk": len(reused_usernames) > 0,
        "decrypted_count": decrypted_count,
        "encrypted_count": encrypted_count,
    }

# ---------------------------------------------------------------------------
# Download analysis
# ---------------------------------------------------------------------------

RISKY_EXTENSIONS = {
    ".exe": 90, ".msi": 85, ".bat": 95, ".cmd": 95, ".ps1": 95,
    ".vbs": 95, ".wsf": 90, ".hta": 95, ".scr": 95, ".pif": 95,
    ".dll": 80, ".sys": 80, ".drv": 80,
    ".jar": 70, ".class": 70, ".jnlp": 75,
    ".dmg": 60, ".app": 60, ".pkg": 65,
    ".deb": 55, ".rpm": 55, ".appimage": 50,
    ".iso": 50, ".img": 50, ".vhd": 55,
    ".zip": 30, ".rar": 30, ".7z": 30, ".tar.gz": 25,
    ".doc": 45, ".docm": 75, ".xlsm": 75, ".pptm": 75,
    ".pdf": 20,
}

def _analyze_downloads(rows: list) -> dict:
    """Analyze downloads for risk indicators."""
    dl_rows = [r for r in rows if r.get("artifact") == "download"]
    if not dl_rows:
        return {"total_downloads": 0}

    risky_downloads = []
    source_domains = collections.Counter()

    for r in dl_rows:
        target = r.get("title", "")
        source = r.get("url", "")
        try:
            domain = urlparse(source).netloc.lower()
            source_domains[domain] += 1
        except Exception:
            domain = ""

        # Check file extension risk
        target_lower = target.lower()
        for ext, risk in RISKY_EXTENSIONS.items():
            if target_lower.endswith(ext):
                risky_downloads.append({
                    "file": target[-100:],
                    "source": source[:200],
                    "risk_score": risk,
                    "extension": ext,
                    "timestamp": r.get("visit_time_utc"),
                })
                break

    risky_downloads.sort(key=lambda x: x["risk_score"], reverse=True)

    return {
        "total_downloads": len(dl_rows),
        "risky_downloads": risky_downloads[:30],
        "top_download_sources": source_domains.most_common(20),
        "high_risk_count": sum(1 for d in risky_downloads if d["risk_score"] >= 70),
    }

# ---------------------------------------------------------------------------
# Privacy exposure scoring
# ---------------------------------------------------------------------------

def _privacy_exposure(rows: list) -> dict:
    """Calculate overall privacy exposure from collected artifacts."""
    scores = {}

    # Count each artifact type
    artifact_counts = collections.Counter(r.get("artifact") for r in rows)
    total_rows = len(rows)

    # History exposure
    history_count = artifact_counts.get("history", 0)
    scores["browsing_history"] = min(100, history_count // 50)

    # Cookie exposure
    cookie_count = artifact_counts.get("cookie", 0)
    scores["tracking_cookies"] = min(100, cookie_count // 10)

    # Credential exposure
    cred_count = artifact_counts.get("credential", 0)
    scores["stored_credentials"] = min(100, cred_count * 10)

    # Autofill exposure
    autofill_count = artifact_counts.get("autofill", 0)
    scores["form_data"] = min(100, autofill_count // 5)

    # Credit card exposure
    cc_count = artifact_counts.get("credit_card", 0)
    scores["financial_data"] = min(100, cc_count * 25)

    # LocalStorage exposure
    ls_count = artifact_counts.get("localstorage", 0)
    scores["web_storage"] = min(100, ls_count // 10)

    # Downloads exposure
    dl_count = artifact_counts.get("download", 0)
    scores["download_history"] = min(100, dl_count // 20)

    overall = sum(scores.values()) / max(len(scores), 1)

    return {
        "overall_exposure_score": round(overall, 1),
        "category_scores": scores,
        "total_artifacts": total_rows,
        "artifact_breakdown": dict(artifact_counts),
    }

# ---------------------------------------------------------------------------
# Cross-artifact correlation
# ---------------------------------------------------------------------------

def _cross_correlate(rows: list) -> dict:
    """
    Cross-correlate artifacts to find connected activity patterns.
    Links: visited site → saved credential → downloaded file → cookie tracking
    """
    domain_artifacts = collections.defaultdict(lambda: collections.defaultdict(list))

    for r in rows:
        url = r.get("url", "")
        artifact = r.get("artifact", "")
        try:
            domain = urlparse(url).netloc.lower().split(":")[0]
        except Exception:
            continue
        if domain and artifact:
            domain_artifacts[domain][artifact].append({
                "url": url[:200],
                "title": r.get("title", "")[:100],
                "timestamp": r.get("visit_time_utc"),
            })

    # Find domains with multi-artifact presence (more forensically interesting)
    multi_artifact_domains = {}
    for domain, artifacts in domain_artifacts.items():
        if len(artifacts) >= 3:  # Present in 3+ artifact types
            multi_artifact_domains[domain] = {
                atype: len(items) for atype, items in artifacts.items()
            }

    # Sort by total artifact count
    sorted_domains = sorted(
        multi_artifact_domains.items(),
        key=lambda x: sum(x[1].values()),
        reverse=True
    )[:30]

    return {
        "multi_artifact_domains": dict(sorted_domains),
        "total_correlated_domains": len(multi_artifact_domains),
    }

# ---------------------------------------------------------------------------
# Browser fingerprint
# ---------------------------------------------------------------------------

def _browser_fingerprint(rows: list) -> dict:
    """Build a profile fingerprint from browser artifacts."""
    browsers = set()
    profiles = set()
    extensions = []
    total_by_browser = collections.Counter()

    for r in rows:
        browser = r.get("browser", "")
        browsers.add(browser)
        profiles.add(r.get("profile", ""))
        total_by_browser[browser] += 1
        if r.get("artifact") == "extension":
            extensions.append({
                "name": r.get("title", ""),
                "browser": browser,
            })

    return {
        "browsers_found": list(browsers),
        "profile_count": len(profiles),
        "artifacts_by_browser": dict(total_by_browser),
        "extensions_installed": extensions[:50],
        "primary_browser": total_by_browser.most_common(1)[0][0] if total_by_browser else "unknown",
    }
