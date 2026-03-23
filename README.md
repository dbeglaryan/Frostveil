# Frostveil

**Advanced browser forensics, credential extraction, and threat analysis toolkit.**

![CI](https://github.com/dbeglaryan/Frostveil/actions/workflows/ci.yml/badge.svg)
![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)

---

## Overview

Frostveil is a pure-Python browser forensics toolkit designed for penetration testers, DFIR analysts, and security researchers. It extracts, correlates, and analyzes browser artifacts across all major Chromium-based and Firefox browsers on Windows, macOS, and Linux. All extraction, analysis, and reporting runs without third-party dependencies.

**15,000+ lines of pure Python across 39 modules.**

## Features

### Artifact Extraction
- Browsing history, bookmarks, downloads, and search terms
- Cookies with Chromium AES-256-GCM decryption (DPAPI on Windows, Keychain on macOS)
- Saved credentials and autofill data (addresses, credit cards)
- LocalStorage and IndexedDB contents
- Installed extensions with manifest parsing
- Active and recent sessions
- Browser preferences and sync account metadata

### Advanced Forensics
- **Deleted record recovery** -- carves SQLite WAL files, journals, and freelist pages to recover erased history, cookies, and credentials
- **Favicon forensics** -- detects ghost visits (favicon exists but history was cleared)
- **Cache forensics** -- extracts cached pages, images, and resources
- **Deep extraction** -- top sites, shortcuts, URL predictions, and typed URLs
- **Anti-forensics detection** -- identifies history clearing, timestamp anomalies, selective deletion, and database vacuum indicators
- **Media history** -- extracts Chromium media playback records including watch duration, source origins, and session data
- **HSTS extraction** -- recovers HTTP Strict Transport Security entries from the TransportSecurity file
- **Site engagement scores** -- extracts Chrome's internal site engagement scoring data

### Threat Intelligence and Analysis
- **IOC engine** -- regex-based threat pattern matching, DGA domain detection via Shannon entropy, homoglyph/typosquatting detection, behavioral anomaly analysis, and data exfiltration heuristics
- **Forensic analyzer** -- cross-artifact correlation, session reconstruction, domain frequency analysis, credential reuse detection, download risk scoring, and privacy exposure assessment
- **Password audit** -- entropy scoring, pattern detection (keyboard walks, sequences, dates), common password matching, and reuse matrix

### Security Assessment
- **PII scanner** -- detects credit card numbers (with Luhn validation), SSNs, API keys (AWS, Google, GitHub, Stripe, Slack, and others), JWT tokens, private keys (RSA, SSH, PGP), cryptocurrency addresses, database connection strings, and environment variable leaks
- **Cloud account enumeration** -- identifies logged-in sessions across 60+ services (Google, Microsoft, AWS, GitHub, Slack, Discord, and more) via cookies, history, credentials, and LocalStorage tokens
- **Browser fingerprint reconstruction** -- rebuilds User-Agent, installed extensions, language/timezone, screen resolution, WebGL renderer, fonts, and hardware info from preferences
- **Session hijack analysis** -- evaluates session token security posture, identifies missing Secure/HttpOnly/SameSite flags, decodes JWTs, and generates session replay commands

### OS-Level Artifact Parsing
- **Windows Jump Lists** -- extracts recent/frequent application destinations from AutomaticDestinations
- **LNK shortcut analysis** -- parses Windows shortcut files for target paths, timestamps, and volume info
- **Recycle Bin forensics** -- recovers deleted file metadata from $Recycle.Bin entries
- **Prefetch correlation** -- identifies browser-related Prefetch entries indicating execution history

### Network Reconnaissance
- WiFi profile extraction (including saved passwords on Windows)
- DNS cache dump
- ARP table capture
- Network interface enumeration

### OPSEC
- Stealth mode with process name masking
- AES-256-GCM encrypted output bundles
- Execution trace cleanup
- In-memory database processing (no temp files on disk)

### Forensic Export Formats
- **STIX 2.1** -- threat intelligence bundle compatible with TAXII feeds and MISP
- **Bodyfile** -- Sleuthkit/mactime-compatible timeline format for integration with forensic suites
- **CASE/UCO** -- Cyber-investigation Analysis Standard Expression ontology format
- **Elasticsearch** -- bulk NDJSON for direct import into Elasticsearch/OpenSearch/Splunk
- **PDF report** -- court-ready forensic report with evidence chain documentation

### Plugin Architecture
- Community plugin system supporting extractor, analyzer, and exporter plugin types
- Drop-in Python modules in `plugins/` directory with automatic discovery
- Example plugin included for reference

## Supported Browsers

| Browser  | Windows | macOS | Linux |
|----------|---------|-------|-------|
| Chrome   | Yes     | Yes   | Yes   |
| Edge     | Yes     | Yes   | Yes   |
| Firefox  | Yes     | Yes   | Yes   |
| Brave    | Yes     | Yes   | Yes   |
| Opera    | Yes     | --    | --    |
| Safari   | --      | Yes   | --    |
| Vivaldi  | Yes     | Yes   | Yes   |
| Opera GX | Yes     | Yes   | Yes   |
| Chromium | Yes     | Yes   | Yes   |
| Yandex   | Yes     | --    | --    |
| Waterfox | Yes     | Yes   | Yes   |

All Chromium-based browsers sharing the standard profile structure (Vivaldi, Opera GX, etc.) are supported through automatic profile discovery.

## Quick Start

### Install from source

```bash
git clone https://github.com/dbeglaryan/Frostveil.git
cd frostveil
python main.py --help
```

No `pip install` of dependencies is required. Frostveil is pure Python with zero third-party packages.

### Install as a package

```bash
pip install .
frostveil --help
```

### Docker

```bash
docker build -t frostveil .
docker run -v /path/to/browser/data:/data -v $(pwd)/output:/output \
  frostveil --full --format json --out /output/evidence.json
```

### Basic usage

```bash
# Extract all artifacts from all detected browsers
python main.py --format json --out evidence.json

# Full extraction with all analysis modules
python main.py --full --format json --out evidence.json

# Extract credentials and run IOC scan
python main.py --credentials --ioc-scan --format json --out evidence.json

# Offline DPAPI decryption with known Windows password
python main.py --credentials --user-password "P@ssw0rd" --format json --out evidence.json
```

## CLI Reference

### Output Options

| Flag                | Description                                  |
|---------------------|----------------------------------------------|
| `--format FMT`      | Output format: `csv`, `json`, `jsonl`, `sqlite` (default: `csv`) |
| `--out FILE`        | Output file name (default: `artifacts_export.csv`) |
| `--per-browser`     | Split output files per browser               |
| `--split-artifacts` | Split output files per artifact type         |
| `--compress`        | Gzip compress output files                   |

### Feature Flags

| Flag                | Description                                  |
|---------------------|----------------------------------------------|
| `--cookies`         | Extract cookies (core; always active)        |
| `--history`         | Extract browsing history (core; always active) |
| `--downloads`       | Extract downloads (core; always active)       |
| `--extensions`      | Extract extensions (core; always active)      |
| `--bookmarks`       | Extract bookmarks (core; always active)       |
| `--sessions`        | Extract sessions (core; always active)        |
| `--credentials`     | Extract saved passwords                      |
| `--autofill`        | Extract autofill data, addresses, credit cards |
| `--localstorage`    | Extract LocalStorage and IndexedDB           |
| `--network`         | WiFi profiles, DNS cache, ARP table          |
| `--anti-forensics`  | Detect history clearing and tampering        |
| `--recover`         | Recover deleted records from WAL/freelist    |
| `--favicons`        | Favicon forensics and ghost visit detection  |
| `--cache`           | Cache forensics (cached pages and images)    |
| `--deep`            | Deep extraction (top sites, shortcuts, predictions) |
| `--prefs`           | Mine browser preferences and settings        |
| `--password-audit`  | Audit password strength and reuse            |
| `--cloud-accounts`  | Enumerate logged-in cloud accounts           |
| `--pii-scan`        | Scan artifacts for PII, API keys, and secrets |
| `--fingerprint`     | Reconstruct browser fingerprint              |
| `--session-hijack`  | Analyze session tokens for hijack potential   |
| `--media-history`   | Extract media playback history               |
| `--hsts`            | Extract HSTS transport security entries      |
| `--site-engagement` | Extract site engagement scores               |
| `--compromised-creds` | Extract compromised credential records     |
| `--windows-artifacts` | Parse Prefetch, Jump Lists, LNK, Recycle Bin |
| `--plugins`         | Run community plugins from plugins/ directory |
| `--user-password PASS` | Windows login password for offline DPAPI decryption |
| `--full`            | Enable ALL feature flags                     |

### Analysis Flags

| Flag          | Description                            |
|---------------|----------------------------------------|
| `--ioc-scan`  | IOC and threat intelligence scan       |
| `--analyze`   | Full forensic analysis engine          |
| `--timeline`  | Export unified event timeline as JSON  |
| `--report`    | Generate Markdown forensic report      |
| `--html-report` | Generate self-contained HTML report  |

### Export Flags

| Flag              | Description                                  |
|-------------------|----------------------------------------------|
| `--pdf-report`    | Generate PDF forensic report                 |
| `--stix`          | Export as STIX 2.1 threat intel bundle       |
| `--bodyfile`      | Export as bodyfile (Sleuthkit/mactime)        |
| `--case`          | Export as CASE/UCO ontology                  |
| `--elasticsearch` | Export as Elasticsearch bulk NDJSON          |

### OPSEC Flags

| Flag                        | Description                              |
|-----------------------------|------------------------------------------|
| `--stealth`                 | Stealth mode: mask process name, suppress output |
| `--encrypt PASS`            | Encrypt all outputs into an AES-256-GCM `.enc` bundle |
| `--decrypt BUNDLE PASS`     | Decrypt a `.enc` bundle                  |
| `--cleanup`                 | Remove all execution traces              |

### Performance Flags

| Flag              | Description                                |
|-------------------|--------------------------------------------|
| `--threads N`     | Extraction thread count (default: 8)       |
| `--sequential`    | Disable parallel extraction                |

### Dashboard

| Flag                  | Description                            |
|-----------------------|----------------------------------------|
| `--dashboard`         | Launch web dashboard after extraction  |
| `--dashboard-port N`  | Dashboard port (default: 8080)         |

## Dashboard

Frostveil includes a local web dashboard for interactive analysis of extraction results. It is a single-page application served by Python's built-in HTTP server with no external dependencies.

```bash
# Launch after extraction
python main.py --full --format json --out evidence.json --dashboard

# Launch standalone against existing data
python server.py --data evidence.json
python server.py --data evidence.json --port 9090 --no-open
```

The dashboard provides 26 views including:
- Summary view with artifact counts and risk scores
- Artifact browser with filtering by type and browser
- Search across all extracted data
- Timeline visualization
- IOC and threat analysis results
- Domain drill-down
- Media history and site engagement views
- Compromised credentials view
- Windows artifacts view
- Cloud accounts, PII, fingerprint, and session hijack views

API endpoints are available at `/api/artifacts`, `/api/ioc`, `/api/analysis`, `/api/timeline`, `/api/summary`, `/api/search`, and `/api/domain`.

## Modules

| Module               | Description                                                            |
|----------------------|------------------------------------------------------------------------|
| `history`            | Browsing history extraction with visit counts and timestamps           |
| `bookmarks`          | Bookmark tree extraction                                               |
| `cookies`            | Cookie extraction with Chromium AES-GCM and DPAPI decryption           |
| `downloads`          | Download history with file paths and referrers                         |
| `searches`           | Search term extraction from keyword tables                             |
| `sessions`           | Active and recent session data                                         |
| `extensions`         | Installed extension enumeration and manifest parsing                   |
| `credentials`        | Saved password extraction with platform-native decryption              |
| `autofill`           | Autofill entries, saved addresses, and credit cards                    |
| `localstorage`       | LocalStorage and IndexedDB key-value extraction                        |
| `network_recon`      | WiFi profiles, DNS cache, ARP table, network interfaces                |
| `anti_forensics`     | Detect history clearing, timestamp anomalies, selective deletion       |
| `ioc_engine`         | IOC scanning, DGA detection, homoglyph analysis, behavioral anomalies  |
| `analyzer`           | Cross-artifact correlation, session reconstruction, privacy scoring    |
| `password_audit`     | Password entropy, pattern detection, reuse analysis, breach matching   |
| `pii_scanner`        | PII and secret detection (credit cards, SSNs, API keys, private keys)  |
| `cloud_accounts`     | Cloud account enumeration across 60+ services                         |
| `fingerprint`        | Browser fingerprint reconstruction from preferences and extensions     |
| `session_hijack`     | Session token security analysis and hijack potential assessment         |
| `wal_forensics`      | Deleted record recovery from SQLite WAL files and freelists            |
| `favicon_forensics`  | Favicon analysis and ghost visit detection                             |
| `cache_forensics`    | Browser cache extraction and analysis                                  |
| `visited_links`      | Top sites, shortcuts, typed URLs, and URL predictions                  |
| `preference_mining`  | Browser preference and settings extraction                             |
| `dpapi_offline`      | Offline DPAPI master key decryption using known Windows passwords      |
| `crypto`             | Platform-native cryptographic operations (DPAPI, Keychain, AES-GCM)   |
| `media_history`      | Media playback history extraction                                      |
| `hsts`               | HTTP Strict Transport Security entry extraction                        |
| `site_engagement`    | Chrome site engagement score extraction                                |
| `compromised_creds`  | Compromised credential database extraction                             |
| `windows_artifacts`  | Windows Prefetch, Jump Lists, LNK files, Recycle Bin parsing           |
| `export_formats`     | STIX 2.1, bodyfile, CASE/UCO, and Elasticsearch bulk export            |
| `plugin_manager`     | Community plugin discovery, validation, and execution                   |
| `pdf_report`         | Pure-Python PDF forensic report generation                             |
| `opsec`              | Process masking, trace cleanup, encrypted output bundles               |
| `engine`             | Parallel extraction engine with thread pool                            |
| `report`             | Markdown report generation                                            |
| `html_report`        | Self-contained HTML report with embedded CSS and charts                |

## Output Formats

| Format   | Description                                                 |
|----------|-------------------------------------------------------------|
| `csv`    | Standard CSV with headers. Default output format.           |
| `json`   | Pretty-printed JSON array. Required for dashboard input.    |
| `jsonl`  | Newline-delimited JSON. One record per line.                |
| `sqlite` | SQLite database. Useful for ad-hoc SQL queries on results.  |

Additional outputs generated by analysis flags:

- `timeline.json` -- unified chronological event timeline
- `ioc_report.json` -- IOC scan results with risk scoring
- `analysis_report.json` -- full forensic analysis report
- `password_audit.json` -- password strength and reuse audit
- `cloud_accounts.json` -- cloud account inventory
- `pii_report.json` -- PII and secret scan results
- `fingerprint_report.json` -- reconstructed browser fingerprints
- `session_hijack.json` -- session token security analysis
- `media_history.json` -- media playback summary
- `site_engagement.json` -- site engagement scores
- `compromised_creds.json` -- compromised credential records
- `frostveil_report.pdf` -- PDF forensic report
- `frostveil_stix.json` -- STIX 2.1 threat intelligence bundle
- `frostveil_bodyfile.txt` -- bodyfile timeline (Sleuthkit format)
- `frostveil_case.json` -- CASE/UCO ontology export
- `frostveil_es_bulk.ndjson` -- Elasticsearch bulk import
- `report.md` -- Markdown summary report
- `frostveil_report.html` -- self-contained HTML report

## Forensic Integrity

Every extraction run produces a signed manifest (`manifest.json` + `manifest.json.sig`) containing:

- SHA-256 hashes of all output files
- Artifact counts by type
- Host metadata (hostname, username, OS, timestamp)
- Error log

The manifest is signed with HMAC-SHA256 using a machine-derived key, providing tamper detection for the output chain of custody. If the HMAC module is unavailable, Frostveil falls back to a SHA-256 hash of the manifest.

## Development

### Project structure

```
frostveil/
  main.py              # CLI entry point and orchestration
  server.py            # Dashboard web server
  pyproject.toml       # Package metadata and build config
  Dockerfile           # Container build
  modules/             # All extraction and analysis modules
  plugins/             # Community plugins (drop-in Python modules)
  ui/                  # Dashboard SPA (HTML, CSS, JS)
  tests/               # Test suite
```

### Running tests

```bash
python -m pytest tests/ -v
```

The CI pipeline (`.github/workflows/ci.yml`) runs tests across Python 3.8, 3.10, 3.12, and 3.13 on Ubuntu, Windows, and macOS. It also verifies module imports, syntax, and the Docker build.

### Requirements

- Python 3.8 or later
- No third-party dependencies (pure Python, stdlib only)
- OS-native crypto APIs are used where available (Windows DPAPI/bcrypt.dll, macOS Keychain, Linux libcrypto)

## Legal and Ethics

**Frostveil is intended for authorized security testing, forensic investigations, and incident response only.**

Do not use this tool to access, extract, or analyze browser data belonging to individuals or systems without explicit written authorization. Unauthorized access to computer data is a criminal offense in most jurisdictions.

The authors assume no liability for misuse of this software. Users are solely responsible for ensuring compliance with all applicable laws, regulations, and organizational policies.

## License

MIT License. See [LICENSE](LICENSE) for details.
