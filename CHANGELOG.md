# Changelog

All notable changes to Frostveil are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-03-22

### Added
- **Media history extraction** -- Chromium media playback records with duration and source tracking
- **HSTS extraction** -- HTTP Strict Transport Security entries from TransportSecurity file
- **Site engagement scores** -- Chrome's internal site engagement scoring data
- **Compromised credentials** -- credentials flagged by Chrome as leaked, phished, weak, or reused
- **Windows artifact parsing** -- Prefetch, Jump Lists, LNK shortcut files, Recycle Bin metadata
- **Plugin architecture** -- community plugin system with extractor, analyzer, and exporter types
- **PDF report generation** -- pure-Python court-ready forensic reports (no dependencies)
- **STIX 2.1 export** -- threat intelligence bundles compatible with TAXII/MISP
- **Bodyfile export** -- Sleuthkit/mactime-compatible timeline format
- **CASE/UCO export** -- Cyber-investigation Analysis Standard Expression ontology
- **Elasticsearch export** -- bulk NDJSON for direct import into ES/OpenSearch/Splunk
- **App-Bound Encryption awareness** -- v20 blob detection for Chrome 127+/Edge
- CLI flags: `--cookies`, `--history`, `--downloads`, `--extensions`, `--bookmarks`, `--sessions` (core extractors, always active)
- CLI flags: `--media-history`, `--hsts`, `--site-engagement`, `--compromised-creds`, `--windows-artifacts`, `--plugins`
- CLI flags: `--pdf-report`, `--stix`, `--bodyfile`, `--case`, `--elasticsearch`
- Browser support: Vivaldi, Opera GX, Chromium, Yandex, Waterfox
- Dashboard views: media history, site engagement, compromised credentials, windows artifacts (26 total views)
- Export buttons in dashboard overview (JSON, CSV, Print)
- Hourly/daily activity charts in timeline view
- Example plugin (`plugins/example_plugin.py`)
- Full test suite (99 tests across 6 test files)
- CI pipeline (GitHub Actions: 3 OS x 4 Python versions)
- Docker support with non-root container
- `pyproject.toml` for pip installation
- Professional documentation: README, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT, CHANGELOG

### Fixed
- **DPAPI decryption on Python 3.12+** -- `ctypes.string_at()` and `LocalFree()` overflow with 64-bit pointers
- Plugin crash: `plug_analysis.items()` called on list instead of dict
- `outputs` NameError in plugins block (used before assignment)
- `--full` flag now enables ALL features (previously missed `--pdf-report`, `--case`, `--elasticsearch`)
- Dashboard renderers using non-existent `metrics-row` CSS class (changed to `metrics-grid`)
- `exportData` function not window-scoped (broke onclick handlers)
- Duplicate sidebar icons across unrelated views
- Duplicate anti-forensics timestamp analysis producing duplicate rows
- Hardcoded `C:/Users` path (now uses `HOMEDRIVE`/`SystemDrive` env vars)
- Dead `_3des_fallback` import in credentials.py
- `html_report.py` f-string syntax error in password audit section
- `getattr(args, 'case', False)` inconsistency

### Changed
- `--full` now truly enables everything including PDF, CASE, and Elasticsearch exports
- Anti-forensics timestamp analysis now deduplicates before appending
- NSS decryption chain replaced with functional 3DES-CBC implementation via Windows bcrypt.dll
- User home discovery uses environment variables instead of hardcoded paths

## [2.0.0] - 2026-03-20

### Added
- **Offline DPAPI decryption** -- decrypt Chromium passwords using known Windows login password/PIN via `--user-password`
- **Cloud account enumeration** -- 70+ service detection rules for logged-in cloud accounts
- **PII/secret scanning** -- credit cards (Luhn validated), API keys (AWS, GitHub, Stripe, Slack), JWTs, private keys, crypto addresses
- **Browser fingerprint reconstruction** -- rebuilds unique fingerprints from preferences, extensions, and hardware data
- **Session hijack analysis** -- cookie security audit, JWT decoding, risk scoring, curl replay commands
- **Password audit engine** -- entropy scoring, keyboard walk detection, pattern analysis, breach matching, reuse matrix
- **IOC/threat intelligence engine** -- DGA detection, homoglyph analysis, typosquatting, behavioral anomalies, data exfiltration heuristics
- **Forensic analysis engine** -- cross-artifact correlation, session reconstruction, domain intelligence, privacy exposure scoring
- **Network reconnaissance** -- WiFi profiles, DNS cache, ARP table, interface enumeration
- **Anti-forensics detection** -- history clearing, timestamp anomalies, selective deletion, vacuum detection
- **Deleted record recovery** -- WAL file carving, freelist page recovery, journal analysis
- **Favicon forensics** -- ghost visit detection (favicon present, history cleared)
- **Cache forensics** -- cached page and resource extraction
- **Deep extraction** -- top sites, shortcuts, URL predictions, typed URLs
- **Preference mining** -- browser settings, sync accounts, content settings
- **Self-contained HTML report** -- single-file forensic report with embedded CSS/JS
- **Interactive web dashboard** -- 22-view SPA with search, filtering, and drill-down
- **OPSEC features** -- stealth mode, AES-256-GCM encrypted bundles, trace cleanup
- **Manifest signing** -- HMAC-SHA256 signed integrity manifests for chain of custody
- Concurrent extraction engine with configurable thread pool
- Output formats: CSV, JSON, JSONL, SQLite
- Firefox credential extraction with NSS/PKCS#11 support

### Changed
- Complete rewrite from original ~663 line script to 15,000+ line professional toolkit
- All cryptographic operations use OS-native APIs (no third-party dependencies)
- Pure-Python AES-256-GCM implementation for cross-platform credential decryption

## [1.0.0] - 2025-01-01

### Added
- Initial release
- Basic browser history, cookie, and bookmark extraction
- CSV and JSON output
- Chrome and Firefox support
