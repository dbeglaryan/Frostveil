"""
Example Frostveil Plugin — URL domain counter.

This plugin demonstrates the plugin interface by counting unique domains
found in extracted history rows and returning them as an analysis dict.

Every plugin must define these module-level attributes:
    PLUGIN_NAME        (str) — human-readable display name
    PLUGIN_VERSION     (str) — semantic version string
    PLUGIN_DESCRIPTION (str) — one-line summary of what the plugin does
    PLUGIN_TYPE        (str) — one of "extractor", "analyzer", "exporter"

And one callable:
    run(rows, meta, browsers=None) — main entry point

Return value depends on PLUGIN_TYPE:
    extractor  -> list of row dicts (same schema as core extractors)
    analyzer   -> dict (will be saved as a JSON report)
    exporter   -> list of str file paths written by the plugin
"""

from collections import Counter
from urllib.parse import urlparse

# ── Required metadata ──────────────────────────────────────────────
PLUGIN_NAME = "Domain Counter"
PLUGIN_VERSION = "1.0.0"
PLUGIN_DESCRIPTION = "Counts unique domains across extracted history artifacts."
PLUGIN_TYPE = "analyzer"  # "extractor" | "analyzer" | "exporter"


def run(rows, meta, browsers=None):
    """
    Analyse extracted rows and return a summary dict.

    Args:
        rows:     list of artifact dicts already collected by the engine.
        meta:     metadata dict (case info, timestamps, etc.).
        browsers: dict of discovered browsers (may be None).

    Returns:
        dict — analysis results (saved as JSON by the plugin manager).
    """
    domain_counts = Counter()
    for row in rows:
        url = row.get("url") or row.get("URL") or ""
        if url:
            try:
                host = urlparse(url).hostname
                if host:
                    domain_counts[host] += 1
            except Exception:
                continue

    top_20 = domain_counts.most_common(20)
    return {
        "plugin": PLUGIN_NAME,
        "version": PLUGIN_VERSION,
        "total_unique_domains": len(domain_counts),
        "total_urls_parsed": sum(domain_counts.values()),
        "top_20_domains": [{"domain": d, "count": c} for d, c in top_20],
    }
