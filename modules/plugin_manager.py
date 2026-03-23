"""
Frostveil Plugin Manager — lightweight plugin/extension architecture.

Discovers, validates, and executes plugins from a ``plugins/`` directory.
Each plugin is a standalone Python file that exposes a fixed interface
(see ``plugins/example_plugin.py`` for the full contract).

Plugin types
------------
* **extractor** — returns extra rows to merge into the main artifact list.
* **analyzer**  — returns a dict that is saved as a JSON report.
* **exporter**  — writes its own output files and returns a list of paths.

Usage::

    from modules.plugin_manager import run_plugins

    extra_rows, analyses, export_files = run_plugins(
        rows=all_rows,
        meta=meta,
        browsers=browsers,
        plugin_dir="plugins",
    )
"""

import importlib
import importlib.util
import json
import sys
import traceback
from pathlib import Path

REQUIRED_ATTRS = ("PLUGIN_NAME", "PLUGIN_VERSION", "PLUGIN_DESCRIPTION", "PLUGIN_TYPE")
VALID_TYPES = {"extractor", "analyzer", "exporter"}


# ── helpers ────────────────────────────────────────────────────────

def _log(msg, quiet=False):
    if not quiet:
        print(msg)


def _load_module_from_path(filepath: Path):
    """Import a Python file as a module without touching sys.modules permanently."""
    module_name = f"_frostveil_plugin_{filepath.stem}"
    spec = importlib.util.spec_from_file_location(module_name, str(filepath))
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    # Temporarily register so relative imports inside the plugin work if needed
    sys.modules[module_name] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        sys.modules.pop(module_name, None)
        raise
    return mod


def _validate_plugin(mod, filepath: Path) -> list:
    """Return a list of validation error strings (empty == valid)."""
    errors = []
    for attr in REQUIRED_ATTRS:
        if not hasattr(mod, attr):
            errors.append(f"missing required attribute '{attr}'")
    if hasattr(mod, "PLUGIN_TYPE") and mod.PLUGIN_TYPE not in VALID_TYPES:
        errors.append(
            f"PLUGIN_TYPE '{mod.PLUGIN_TYPE}' invalid; must be one of {VALID_TYPES}"
        )
    if not callable(getattr(mod, "run", None)):
        errors.append("missing callable 'run(rows, meta, browsers=None)'")
    return errors


# ── public API ─────────────────────────────────────────────────────

def discover_plugins(plugin_dir: str = "plugins") -> list:
    """
    Scan *plugin_dir* for valid plugin files and return metadata.

    Parameters
    ----------
    plugin_dir : str
        Path to the plugins directory (relative to project root or absolute).

    Returns
    -------
    list[dict]
        Each dict contains: ``name``, ``version``, ``description``, ``type``,
        ``file``, ``module`` (the loaded module object), and ``errors``
        (list of validation issues — empty if the plugin is usable).
    """
    plugin_path = Path(plugin_dir)
    if not plugin_path.is_absolute():
        # Resolve relative to the project root (parent of modules/)
        project_root = Path(__file__).resolve().parent.parent
        plugin_path = project_root / plugin_dir

    plugins = []

    if not plugin_path.is_dir():
        return plugins

    for py_file in sorted(plugin_path.glob("*.py")):
        # Skip __init__.py and private/hidden files
        if py_file.name.startswith("_"):
            continue

        info = {
            "name": None,
            "version": None,
            "description": None,
            "type": None,
            "file": str(py_file),
            "module": None,
            "errors": [],
        }

        try:
            mod = _load_module_from_path(py_file)
            if mod is None:
                info["errors"].append("failed to create module spec")
                plugins.append(info)
                continue

            validation_errors = _validate_plugin(mod, py_file)
            info["errors"] = validation_errors
            info["module"] = mod
            info["name"] = getattr(mod, "PLUGIN_NAME", py_file.stem)
            info["version"] = getattr(mod, "PLUGIN_VERSION", "0.0.0")
            info["description"] = getattr(mod, "PLUGIN_DESCRIPTION", "")
            info["type"] = getattr(mod, "PLUGIN_TYPE", None)
        except Exception as exc:
            info["errors"].append(f"import error: {exc}")

        plugins.append(info)

    return plugins


def run_plugins(
    rows: list,
    meta: dict,
    browsers: dict = None,
    plugin_dir: str = "plugins",
    quiet: bool = False,
) -> tuple:
    """
    Discover and execute all valid plugins.

    Parameters
    ----------
    rows : list
        Artifact rows already collected by the core engine.
    meta : dict
        Case / run metadata.
    browsers : dict, optional
        Browser dict from ``utils.find_browsers()``.
    plugin_dir : str
        Directory to scan for plugins.
    quiet : bool
        Suppress progress output.

    Returns
    -------
    tuple[list, list, list]
        ``(extra_rows, analysis_results, export_files)``

        * *extra_rows* — new rows from extractor plugins (list of dicts).
        * *analysis_results* — dicts from analyzer plugins (list of dicts).
        * *export_files* — file paths written by exporter plugins (list of str).
    """
    plugins = discover_plugins(plugin_dir)

    if not plugins:
        _log("[*] No plugins found.", quiet)
        return [], [], []

    _log(f"[*] Discovered {len(plugins)} plugin(s).", quiet)

    extra_rows = []
    analysis_results = []
    export_files = []

    for info in plugins:
        label = info["name"] or info["file"]

        # Skip broken plugins
        if info["errors"]:
            for err in info["errors"]:
                _log(f"[!] Skipping plugin '{label}': {err}", quiet)
            continue

        mod = info["module"]
        ptype = info["type"]
        _log(f"[*] Running plugin '{label}' v{info['version']} ({ptype})...", quiet)

        try:
            result = mod.run(rows, meta, browsers=browsers)
        except Exception as exc:
            _log(f"[!] Plugin '{label}' failed: {exc}", quiet)
            traceback.print_exc()
            continue

        # Dispatch on plugin type
        if ptype == "extractor":
            if isinstance(result, list):
                extra_rows.extend(result)
                _log(f"    +{len(result)} rows from '{label}'.", quiet)
            else:
                _log(f"[!] Extractor plugin '{label}' did not return a list.", quiet)

        elif ptype == "analyzer":
            if isinstance(result, dict):
                analysis_results.append(result)
                _log(f"    Analysis from '{label}' captured.", quiet)
            else:
                _log(f"[!] Analyzer plugin '{label}' did not return a dict.", quiet)

        elif ptype == "exporter":
            if isinstance(result, list):
                export_files.extend(result)
                _log(f"    {len(result)} file(s) written by '{label}'.", quiet)
            else:
                _log(f"[!] Exporter plugin '{label}' did not return a list.", quiet)

    _log(
        f"[+] Plugins complete: {len(extra_rows)} extra rows, "
        f"{len(analysis_results)} analyses, {len(export_files)} exports.",
        quiet,
    )

    return extra_rows, analysis_results, export_files
