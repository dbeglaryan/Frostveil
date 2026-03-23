# Frostveil | Browser Forensics Toolkit – Usage Guide

## Overview
Frostveil is a forensic-ready browser artifact extractor that works across Chrome, Edge, and Firefox.  
It collects history, cookies, bookmarks, downloads, searches, sessions, and extensions in a safe and portable way.

---

## Installation
No dependencies required.

```bash
git clone https://github.com/YOUR_USERNAME/Frostveil.git
cd Frostveil
python main.py --help
```

Optional: create a venv:
```bash
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
.venv\Scripts\activate   # Windows
```

---

## Command Line Options
```
--format csv|json|jsonl|sqlite   Output format
--out <file>                     Output file name
--per-browser                    Split by browser
--split-artifacts                Split by artifact type
--compress                       Gzip compress output
--timeline                       Export unified timeline.json
--report                         Generate report.md
```

---

## Example Runs

### Basic Extraction
```bash
python main.py --format csv --out artifacts_export.csv
```

### Per-Browser Split
```bash
python main.py --format json --per-browser --out output.json
```

### Per-Artifact Split
```bash
python main.py --split-artifacts --out artifacts.csv
```

### Full Forensic Export
```bash
python main.py --format sqlite --report --timeline --compress
```

---

## Outputs

- **CSV / JSON / JSONL / SQLite** → All artifacts in chosen format
- **timeline.json** → Unified timeline by timestamp
- **report.md** → Human-readable summary
- **manifest.json / manifest.json.sig** → Forensic integrity verification
- **history_export.log** → Full acquisition log

---

## Troubleshooting
- **Access Denied** → Run as Administrator or sudo.
- **Encrypted cookies** → Chromium cookies marked `<encrypted>` require system APIs for decryption.
- **Empty results** → Ensure browser was installed and profile exists.

---

## Packaging (Optional)
Make a single-file executable:
```bash
pip install pyinstaller
pyinstaller --onefile main.py
```

---

## Forensics & Integrity
- Frostveil copies databases before reading to prevent modification.
- All outputs are hashed (SHA256) and recorded in `manifest.json`.
- Logs are timestamped in UTC.

---

## Supported Platforms
- Windows 10/11
- Linux (tested Ubuntu/Debian)
- macOS (partial, Safari support TBD)

---

## License
MIT License – see [LICENSE](../LICENSE).
