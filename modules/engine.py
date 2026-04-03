"""
Frostveil Concurrent Extraction Engine — parallel artifact collection.

Uses ThreadPoolExecutor for I/O-bound database reads across multiple
browser profiles simultaneously. Typically 5-10x faster than sequential.
"""
import concurrent.futures, time, collections
from pathlib import Path
from . import (history, bookmarks, cookies, downloads, searches, sessions,
               extensions, credentials, autofill, localstorage,
               anti_forensics, media_history, hsts, site_engagement,
               compromised_creds, utils)

# Map of extractor name → module
CORE_EXTRACTORS = {
    "history": history,
    "bookmarks": bookmarks,
    "cookies": cookies,
    "downloads": downloads,
    "searches": searches,
    "sessions": sessions,
    "extensions": extensions,
}

OPTIONAL_EXTRACTORS = {
    "credentials": credentials,
    "autofill": autofill,
    "localstorage": localstorage,
    "media_history": media_history,
    "hsts": hsts,
    "site_engagement": site_engagement,
    "compromised_creds": compromised_creds,
}

def _run_extractor(args):
    """Worker function for thread pool. Returns (rows, errors)."""
    extractor_name, extractor_mod, browser_type, path, meta = args
    rows = []
    errors = []
    try:
        rows = extractor_mod.extract(browser_type, path, meta)
    except Exception as e:
        msg = f"ERROR {extractor_name} {browser_type} {path}: {e}"
        errors.append(msg)
        utils.log_line(msg)
    return rows, errors

def _run_anti_forensics(args):
    """Worker for anti-forensics detection."""
    browser_type, path, meta = args
    rows = []
    errors = []
    try:
        rows = anti_forensics.detect(browser_type, path, meta)
    except Exception as e:
        msg = f"ERROR anti_forensics {browser_type}: {e}"
        errors.append(msg)
        utils.log_line(msg)
    return rows, errors

def resolve_browser_type(b):
    """Map browser name to its engine type."""
    if b in ("chrome", "edge", "firefox"):
        return b
    if b in ("waterfox",):
        return "firefox"
    if b == "safari":
        return "safari"
    return "chrome"  # Brave, Opera, Opera GX, Vivaldi, Chromium, Yandex, etc.

def extract_all(browsers: dict, meta: dict,
                enable_optional: set = None,
                enable_anti_forensics: bool = False,
                max_workers: int = 8,
                quiet: bool = False) -> tuple:
    """
    Extract all artifacts from all browsers concurrently.

    Args:
        browsers: dict from utils.find_browsers()
        meta: metadata dict
        enable_optional: set of optional extractor names to enable
        enable_anti_forensics: run anti-forensics detection
        max_workers: thread pool size
        quiet: suppress progress output

    Returns:
        (all_rows, errors, stats)
    """
    enable_optional = enable_optional or set()
    start_time = time.perf_counter()

    # Build work queue
    tasks = []
    af_tasks = []

    for browser_name, paths in browsers.items():
        bt = resolve_browser_type(browser_name)
        for path in paths:
            # Core extractors
            for name, mod in CORE_EXTRACTORS.items():
                tasks.append((name, mod, bt, path, meta))

            # Optional extractors
            for name, mod in OPTIONAL_EXTRACTORS.items():
                if name in enable_optional:
                    tasks.append((name, mod, bt, path, meta))

            # Anti-forensics
            if enable_anti_forensics:
                af_tasks.append((bt, path, meta))

    total_tasks = len(tasks) + len(af_tasks)
    if not quiet:
        print(f"[*] Dispatching {total_tasks} extraction tasks across {max_workers} threads")

    all_rows = []
    all_errors = []
    completed = 0

    # Run extraction tasks in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        # Submit all extraction tasks
        futures = {pool.submit(_run_extractor, task): task[0] for task in tasks}

        # Submit anti-forensics tasks
        for af_task in af_tasks:
            futures[pool.submit(_run_anti_forensics, af_task)] = "anti_forensics"

        # Collect results as they complete
        for future in concurrent.futures.as_completed(futures):
            name = futures[future]
            try:
                rows, errors = future.result()
                all_rows.extend(rows)
                all_errors.extend(errors)
            except Exception as e:
                all_errors.append(f"THREAD_ERROR {name}: {e}")

            completed += 1
            if not quiet and completed % 10 == 0:
                print(f"    [{completed}/{total_tasks}] tasks complete...")

    elapsed = time.perf_counter() - start_time

    # Build stats
    artifact_counts = collections.Counter(r.get("artifact", "unknown") for r in all_rows)
    browser_counts = collections.Counter(r.get("browser", "unknown") for r in all_rows)

    stats = {
        "total_tasks": total_tasks,
        "total_artifacts": len(all_rows),
        "elapsed_seconds": round(elapsed, 2),
        "artifacts_per_second": round(len(all_rows) / max(elapsed, 0.001), 1),
        "artifact_counts": dict(artifact_counts),
        "browser_counts": dict(browser_counts),
        "errors": len(all_errors),
        "workers": max_workers,
    }

    if not quiet:
        print(f"[+] Extraction complete: {len(all_rows):,} artifacts in {elapsed:.2f}s "
              f"({stats['artifacts_per_second']:,.0f} artifacts/sec)")

    return all_rows, all_errors, stats
