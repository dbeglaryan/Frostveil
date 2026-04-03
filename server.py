"""
Frostveil Dashboard Server — local-only web interface for forensic analysis.

Serves the SPA dashboard and provides a JSON API over the extraction results.
Zero dependencies — uses Python's built-in http.server.

Usage:
    python server.py                         # auto-detect latest results
    python server.py --data evidence.json    # specify data file
    python server.py --port 9090             # custom port
    python server.py --bind 0.0.0.0          # allow LAN access (careful)
"""
import argparse, json, os, sys, webbrowser, threading, mimetypes
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs

# Ensure correct MIME types
mimetypes.add_type("application/javascript", ".js")
mimetypes.add_type("text/css", ".css")

BASE_DIR = Path(__file__).parent
UI_DIR = BASE_DIR / "ui"


class FrostveilHandler(SimpleHTTPRequestHandler):
    """Custom handler that serves the UI and provides API endpoints."""

    data_cache = {}  # Class-level cache for loaded data

    def log_message(self, fmt, *args):
        # Quieter logging
        if "/api/" in (args[0] if args else ""):
            return
        super().log_message(fmt, *args)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # API routes
        if path.startswith("/api/"):
            self._handle_api(path, parsed)
            return

        # Serve UI files
        if path == "/" or path == "/index.html":
            self._serve_file(UI_DIR / "index.html", "text/html")
        elif path == "/app.js":
            self._serve_file(UI_DIR / "app.js", "application/javascript")
        elif path == "/style.css":
            self._serve_file(UI_DIR / "style.css", "text/css")
        else:
            # Try serving from UI directory with safe path resolution
            try:
                file_path = (UI_DIR / path.lstrip("/")).resolve()
                file_path.relative_to(UI_DIR.resolve())  # raises ValueError if outside UI_DIR
                if file_path.exists() and file_path.is_file():
                    content_type = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
                    self._serve_file(file_path, content_type)
                else:
                    # SPA fallback — serve index.html for client-side routing
                    self._serve_file(UI_DIR / "index.html", "text/html")
            except (ValueError, OSError):
                # Path traversal attempt or invalid path
                self.send_error(403, "Forbidden")

    def _handle_api(self, path, parsed):
        params = parse_qs(parsed.query)

        if path == "/api/artifacts":
            self._json_response(self._get_data("artifacts"))
        elif path == "/api/ioc":
            self._json_response(self._get_data("ioc"))
        elif path == "/api/analysis":
            self._json_response(self._get_data("analysis"))
        elif path == "/api/manifest":
            self._json_response(self._get_data("manifest"))
        elif path == "/api/timeline":
            self._json_response(self._get_data("timeline"))
        elif path == "/api/summary":
            self._json_response(self._build_summary())
        elif path == "/api/search":
            query = params.get("q", [""])[0].lower()
            self._json_response(self._search(query))
        elif path == "/api/artifacts/by_type":
            atype = params.get("type", [""])[0]
            self._json_response(self._filter_by_type(atype))
        elif path == "/api/artifacts/by_browser":
            browser = params.get("browser", [""])[0]
            self._json_response(self._filter_by_browser(browser))
        elif path == "/api/domain":
            domain = params.get("d", [""])[0]
            self._json_response(self._domain_detail(domain))
        else:
            self._json_response({"error": "unknown endpoint"}, 404)

    def _get_data(self, key):
        if key in self.data_cache:
            return self.data_cache[key]
        return {}

    def _build_summary(self):
        artifacts = self._get_data("artifacts")
        ioc = self._get_data("ioc")
        analysis = self._get_data("analysis")
        manifest = self._get_data("manifest")

        if not artifacts:
            return {"error": "no data loaded"}

        from collections import Counter
        type_counts = Counter(r.get("artifact", "") for r in artifacts)
        browser_counts = Counter(r.get("browser", "") for r in artifacts)

        return {
            "total_artifacts": len(artifacts),
            "artifact_types": dict(type_counts),
            "browsers": dict(browser_counts),
            "metadata": manifest.get("metadata", {}),
            "risk_level": ioc.get("overall_risk_level", "N/A") if ioc else "N/A",
            "risk_score": ioc.get("overall_risk_score", 0) if ioc else 0,
            "total_iocs": ioc.get("total_iocs", 0) if ioc else 0,
            "privacy_score": (analysis.get("privacy_exposure", {}).get("overall_exposure_score", 0)
                              if analysis else 0),
        }

    def _search(self, query):
        artifacts = self._get_data("artifacts")
        if not query or not artifacts:
            return []
        results = []
        for r in artifacts:
            searchable = f"{r.get('url','')} {r.get('title','')} {r.get('extra','')}".lower()
            if query in searchable:
                results.append(r)
            if len(results) >= 200:
                break
        return results

    def _filter_by_type(self, atype):
        artifacts = self._get_data("artifacts")
        return [r for r in artifacts if r.get("artifact") == atype]

    def _filter_by_browser(self, browser):
        artifacts = self._get_data("artifacts")
        return [r for r in artifacts if r.get("browser") == browser]

    def _domain_detail(self, domain):
        artifacts = self._get_data("artifacts")
        if not domain:
            return []
        results = []
        for r in artifacts:
            url = r.get("url", "")
            if domain in url:
                results.append(r)
        return results

    def _json_response(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def _serve_file(self, filepath, content_type):
        try:
            data = filepath.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", f"{content_type}; charset=utf-8")
            self.send_header("Content-Length", len(data))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(data)
        except FileNotFoundError:
            self.send_error(404, f"File not found: {filepath.name}")


def load_data(data_file=None):
    """Load extraction results into the handler's cache."""
    cache = FrostveilHandler.data_cache

    # Auto-detect files if not specified
    base = Path(".")

    # Artifacts data
    if data_file:
        p = Path(data_file)
        if p.exists():
            if p.suffix == ".json":
                cache["artifacts"] = json.loads(p.read_text(encoding="utf-8"))
            elif p.suffix == ".csv":
                import csv
                with open(p, "r", encoding="utf-8") as f:
                    cache["artifacts"] = list(csv.DictReader(f))
    else:
        # Auto-detect: look for common output names
        for candidate in ["artifacts_export.json", "artifacts_export.csv",
                          "evidence.json", "evidence.csv"]:
            p = base / candidate
            if p.exists():
                if p.suffix == ".json":
                    cache["artifacts"] = json.loads(p.read_text(encoding="utf-8"))
                elif p.suffix == ".csv":
                    import csv
                    with open(p, "r", encoding="utf-8") as f:
                        cache["artifacts"] = list(csv.DictReader(f))
                print(f"[+] Loaded artifacts from {candidate}")
                break

    # Load supplementary files
    for name, filename in [("ioc", "ioc_report.json"),
                           ("analysis", "analysis_report.json"),
                           ("manifest", "manifest.json"),
                           ("timeline", "timeline.json")]:
        p = base / filename
        if p.exists():
            try:
                cache[name] = json.loads(p.read_text(encoding="utf-8"))
                print(f"[+] Loaded {name} from {filename}")
            except Exception as e:
                print(f"[!] Failed to load {filename}: {e}")

    total = len(cache.get("artifacts", []))
    print(f"[+] Total artifacts in memory: {total:,}")
    return total


def main():
    ap = argparse.ArgumentParser(
        prog="frostveil-dashboard",
        description="Frostveil Dashboard — local web interface for forensic analysis"
    )
    ap.add_argument("--data", help="Path to artifacts JSON/CSV file")
    ap.add_argument("--port", type=int, default=8080, help="Server port (default: 8080)")
    ap.add_argument("--bind", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    ap.add_argument("--no-open", action="store_true", help="Don't auto-open browser")
    args = ap.parse_args()

    total = load_data(args.data)
    if total == 0:
        print("\n[!] No artifact data found. Run extraction first:")
        print("    python main.py --full --format json --out artifacts_export.json")
        print("    python server.py")
        print("\n    Or specify a data file:")
        print("    python server.py --data /path/to/artifacts.json")
        sys.exit(1)

    server = HTTPServer((args.bind, args.port), FrostveilHandler)
    url = f"http://{args.bind}:{args.port}"

    print(f"\n{'='*50}")
    print(f"  FROSTVEIL DASHBOARD")
    print(f"  {url}")
    print(f"  Press Ctrl+C to stop")
    print(f"{'='*50}\n")

    if not args.no_open:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Dashboard stopped.")
        server.server_close()


if __name__ == "__main__":
    main()
