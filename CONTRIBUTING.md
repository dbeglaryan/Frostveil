# Contributing to Frostveil

Thank you for your interest in contributing to Frostveil. Contributions of all kinds are welcome — bug fixes, new extractor modules, plugins, tests, and documentation improvements. Please check the [issue tracker](https://github.com/dbeglaryan/Frostveil/issues) before starting work to avoid duplication.

---

## Table of Contents

- [Development Setup](#development-setup)
- [Code Style](#code-style)
- [Adding a New Extractor Module](#adding-a-new-extractor-module)
- [Writing Plugins](#writing-plugins)
- [Pull Request Process](#pull-request-process)
- [Reporting Issues](#reporting-issues)
- [Code of Conduct](#code-of-conduct)

---

## Development Setup

**Clone the repository:**

```bash
git clone https://github.com/dbeglaryan/Frostveil.git
cd frostveil
```

**Dependencies:**

Frostveil is pure Python 3.8+ with no third-party dependencies. No virtual environment or `pip install` step is required. Ensure you have Python 3.8 or later:

```bash
python --version
```

**Run the test suite:**

```bash
python -m pytest tests/ -v
```

**Run the tool:**

```bash
python main.py --help
```

---

## Code Style

Frostveil enforces a strict no-third-party-imports policy to keep the tool self-contained and deployable in restricted environments.

### General Rules

- **Standard library only.** Do not introduce any third-party imports. Every import must resolve against the Python 3.8 standard library.
- **4-space indentation.** No tabs, no 2-space indentation.
- **Module docstrings required.** Every `.py` file must begin with a module-level docstring describing its purpose.
- **Public API docstrings.** All functions that are part of a module's public interface must have a docstring. Internal helpers (prefixed with `_`) should have docstrings where the logic is non-obvious.

### Module Design

- Keep modules self-contained. Each file under `modules/` is responsible for exactly one browser artifact type (e.g., history, cookies, downloads). Cross-module dependencies should be avoided.
- Do not call `print()` directly. Use `utils.log_line()` for all console output so that verbosity and log formatting remain consistent across the tool.
- Do not open browser databases directly. Use `utils.safe_copy()` to copy the database to a temporary location before reading it. This avoids locking live browser files and prevents corruption.

### Example

```python
"""
modules/downloads.py

Extracts download history artifacts from Chromium-based browsers.
"""

from utils import log_line, safe_copy


def extract(browser, path, meta):
    """Extract download records from the browser's History database.

    Args:
        browser (str): Normalized browser identifier (e.g., 'chrome', 'edge').
        path (str): Path to the browser profile directory.
        meta (dict): Metadata passed from the engine (e.g., OS, username).

    Returns:
        list[dict]: A list of artifact dicts conforming to the standard schema.
    """
    log_line(f"Extracting downloads for {browser}")
    db_path = safe_copy(path, "History")
    # ... extraction logic ...
```

---

## Adding a New Extractor Module

Follow these steps to add support for a new artifact type.

### 1. Create the module

Create `modules/your_module.py`. The module must expose an `extract` function with this exact signature:

```python
def extract(browser, path, meta):
    ...
```

The function must return a list of dicts. Each dict must include the following standard keys:

| Key | Type | Description |
|---|---|---|
| `browser` | `str` | Normalized browser name (e.g., `"chrome"`) |
| `artifact` | `str` | Artifact type label (e.g., `"download"`) |
| `profile` | `str` | Profile directory name |
| `url` | `str` | Associated URL, or `None` |
| `title` | `str` | Page or item title, or `None` |
| `visit_count` | `int` | Number of visits/accesses, or `0` |
| `visit_time_utc` | `str` | ISO 8601 UTC timestamp, or `None` |
| `extra` | `dict` | Any artifact-specific fields not covered above |

### 2. Wire it into the engine

Register your module in `engine.py` so the extraction engine calls it during a run.

### 3. Wire it into the CLI

Add any relevant CLI flags or output handling to `main.py`.

### 4. Add a dashboard renderer

- Add a renderer function in `ui/app.js` that formats your artifact type for display.
- Add a navigation entry in `ui/index.html` so the artifact type appears in the sidebar.

### 5. Add tests

Create `tests/test_your_module.py`. Tests should cover at minimum:

- Normal extraction from a fixture database.
- Graceful handling of a missing or empty database.
- Correct field types and presence in returned dicts.

---

## Writing Plugins

Frostveil supports a plugin system for extending functionality without modifying core modules.

### Plugin Location

All plugins live in the `plugins/` directory. Each plugin is a single self-contained Python file.

### Plugin Interface

See `plugins/example_plugin.py` for a fully annotated reference implementation.

Every plugin must define a `PLUGIN_META` dict at the module level:

```python
PLUGIN_META = {
    "name": "My Plugin",
    "version": "1.0.0",
    "author": "Your Name",
    "type": "analyzer",          # one of: extractor, analyzer, exporter
    "description": "One-line description of what this plugin does.",
}
```

### Plugin Types

| Type | Purpose |
|---|---|
| `extractor` | Adds support for a new artifact source or browser not covered by core modules |
| `analyzer` | Processes and enriches extracted artifacts (e.g., clustering, scoring) |
| `exporter` | Outputs artifacts to a custom format or destination (e.g., SIEM, CSV variant) |

### Plugin Rules

- Plugins must be pure Python 3.8+ stdlib only, consistent with the core codebase.
- A plugin must not modify global state in the engine or other modules.
- Plugins are loaded dynamically; ensure your plugin does not execute side effects at import time.

---

## Pull Request Process

1. **Fork** the repository and create a feature branch from `main`:

   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Write tests** for any new functionality. PRs that reduce test coverage will not be merged.

3. **Ensure all tests pass** before submitting:

   ```bash
   python -m pytest tests/ -v
   ```

4. **Keep PRs focused.** One feature or fix per PR. Large PRs are difficult to review and slow down the process.

5. **Write a clear PR description** that explains:
   - What the change does.
   - Why the change is needed or what problem it solves.
   - Any relevant issue numbers (e.g., `Closes #42`).

6. A maintainer will review your PR. Be prepared to make changes based on feedback. Reviews are not rejections — they are part of the process.

---

## Reporting Issues

Use [GitHub Issues](https://github.com/dbeglaryan/Frostveil/issues) to report bugs.

Please include:

- Your operating system and version.
- Your Python version (`python --version`).
- The exact command you ran.
- The full traceback or error output, pasted as text (not a screenshot).
- A minimal reproduction case if possible.

Feature requests are also welcome via GitHub Issues. Tag them with the `enhancement` label.

---

## Code of Conduct

This project follows the standards described in [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). By participating, you agree to uphold those standards. Maintainers reserve the right to remove contributions or revoke access for violations.
