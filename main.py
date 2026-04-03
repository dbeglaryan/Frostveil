import argparse, json, csv, sqlite3, gzip, sys, time
from pathlib import Path
from modules import (history, bookmarks, cookies, downloads, searches, sessions,
                     extensions, credentials, autofill, localstorage,
                     network_recon, anti_forensics, ioc_engine, analyzer,
                     opsec, utils, report, engine, wal_forensics,
                     favicon_forensics, cache_forensics, visited_links,
                     password_audit, preference_mining, html_report,
                     cloud_accounts, pii_scanner,
                     fingerprint, session_hijack, media_history,
                     hsts, site_engagement, compromised_creds,
                     export_formats, windows_artifacts, plugin_manager,
                     pdf_report)

def write_outputs(rows, fmt, out, compress=False, split_artifacts=False, per_browser=False):
    """Write extracted rows to disk in chosen format(s)."""
    outputs = []
    if not rows:
        return outputs

    def open_out(path):
        if compress:
            return gzip.open(path, "wt", encoding="utf-8")
        return open(path, "w", encoding="utf-8")

    if split_artifacts or per_browser:
        groups = {}
        for r in rows:
            key = []
            if per_browser:
                key.append(r["browser"])
            if split_artifacts:
                key.append(r["artifact"])
            groups.setdefault("_".join(key), []).append(r)
    else:
        groups = {"all": rows}

    for gname, grows in groups.items():
        outname = out
        stem, suf = Path(out).stem, Path(out).suffix
        if gname != "all":
            outname = f"{stem}_{gname}{suf}"
        outputs.append(Path(outname))

        if fmt == "csv":
            with open_out(outname) as f:
                w = csv.DictWriter(f, fieldnames=grows[0].keys())
                w.writeheader()
                for r in grows:
                    w.writerow(r)
        elif fmt == "json":
            with open_out(outname) as f:
                json.dump(grows, f, indent=2, ensure_ascii=False)
        elif fmt == "jsonl":
            with open_out(outname) as f:
                for r in grows:
                    f.write(json.dumps(r, ensure_ascii=False) + "\n")
        elif fmt == "sqlite":
            conn = sqlite3.connect(outname)
            cols = list(grows[0].keys())
            safe_cols = [c.replace('"', '""') for c in cols]
            col_defs = ", ".join(f'"{c}" TEXT' for c in safe_cols)
            conn.execute(f"CREATE TABLE IF NOT EXISTS data ({col_defs})")
            conn.executemany(
                f"INSERT INTO data VALUES ({','.join(['?']*len(cols))})",
                [tuple(r.get(c, "") for c in cols) for r in grows]
            )
            conn.commit()
            conn.close()

    return outputs

BANNER = r"""
 _______ ______  _____  _______ _______ _    _ _______ _____
 |______ |_____/ |     | |______    |     \  /  |______   |   |
 |       |    \_ |_____| ______|    |      \/   |______ __|__ |_____
                v2.1.0 — Penetration Testing Edition
"""

def main():
    ap = argparse.ArgumentParser(
        prog="frostveil",
        description="Frostveil v2.1 — Advanced browser forensics, credential extraction, "
                    "threat analysis, and network reconnaissance toolkit."
    )

    # Output
    out_g = ap.add_argument_group("Output")
    out_g.add_argument("--format", choices=["csv", "json", "jsonl", "sqlite"],
                       default="csv", help="Output format (default: csv)")
    out_g.add_argument("--out", default="artifacts_export.csv", help="Output file name")
    out_g.add_argument("--per-browser", action="store_true", help="Split outputs per browser")
    out_g.add_argument("--split-artifacts", action="store_true", help="Split per artifact type")
    out_g.add_argument("--compress", action="store_true", help="Gzip compress outputs")

    # Features
    feat_g = ap.add_argument_group("Features")
    feat_g.add_argument("--timeline", action="store_true", help="Export unified timeline JSON")
    feat_g.add_argument("--report", action="store_true", help="Generate Markdown report")
    feat_g.add_argument("--html-report", action="store_true", help="Generate self-contained HTML report")
    feat_g.add_argument("--cookies", action="store_true", help="Extract cookies (always on; flag for explicitness)")
    feat_g.add_argument("--history", action="store_true", help="Extract browsing history (always on; flag for explicitness)")
    feat_g.add_argument("--downloads", action="store_true", help="Extract download records (always on; flag for explicitness)")
    feat_g.add_argument("--extensions", action="store_true", help="Extract installed extensions (always on; flag for explicitness)")
    feat_g.add_argument("--bookmarks", action="store_true", help="Extract bookmarks (always on; flag for explicitness)")
    feat_g.add_argument("--sessions", action="store_true", help="Extract session/tab data (always on; flag for explicitness)")
    feat_g.add_argument("--credentials", action="store_true", help="Extract saved passwords")
    feat_g.add_argument("--autofill", action="store_true", help="Extract autofill, addresses, credit cards")
    feat_g.add_argument("--localstorage", action="store_true", help="Extract LocalStorage/IndexedDB")
    feat_g.add_argument("--network", action="store_true", help="WiFi profiles, DNS cache, ARP table")
    feat_g.add_argument("--anti-forensics", action="store_true", help="Detect data clearing/tampering")
    feat_g.add_argument("--recover", action="store_true", help="Recover deleted records (WAL/freelist)")
    feat_g.add_argument("--favicons", action="store_true", help="Favicon forensics (ghost visits)")
    feat_g.add_argument("--cache", action="store_true", help="Cache forensics (cached pages/images)")
    feat_g.add_argument("--deep", action="store_true", help="Deep extraction (top sites, shortcuts, predictions)")
    feat_g.add_argument("--prefs", action="store_true", help="Mine browser preferences/settings")
    feat_g.add_argument("--password-audit", action="store_true", help="Audit password strength/reuse")
    feat_g.add_argument("--cloud-accounts", action="store_true", help="Enumerate all logged-in cloud accounts")
    feat_g.add_argument("--pii-scan", action="store_true", help="Scan artifacts for PII, API keys, secrets")
    feat_g.add_argument("--fingerprint", action="store_true", help="Reconstruct browser fingerprint")
    feat_g.add_argument("--session-hijack", action="store_true", help="Analyze session tokens for hijack potential")
    feat_g.add_argument("--media-history", action="store_true", help="Extract media playback history")
    feat_g.add_argument("--hsts", action="store_true", help="Extract HSTS transport security entries")
    feat_g.add_argument("--site-engagement", action="store_true", help="Extract site engagement scores")
    feat_g.add_argument("--compromised-creds", action="store_true", help="Extract compromised credential records")
    feat_g.add_argument("--pdf-report", action="store_true", help="Generate PDF forensic report")
    feat_g.add_argument("--windows-artifacts", action="store_true", help="Parse Prefetch, Jump Lists, LNK, Recycle Bin")
    feat_g.add_argument("--plugins", action="store_true", help="Run community plugins from plugins/ directory")

    # Export formats
    exp_g = ap.add_argument_group("Export Formats")
    exp_g.add_argument("--stix", action="store_true", help="Export as STIX 2.1 bundle")
    exp_g.add_argument("--bodyfile", action="store_true", help="Export as bodyfile (Sleuthkit/mactime)")
    exp_g.add_argument("--case", action="store_true", help="Export as CASE/UCO ontology")
    exp_g.add_argument("--elasticsearch", action="store_true", help="Export as Elasticsearch bulk NDJSON")
    feat_g.add_argument("--user-password", metavar="PASS",
                        help="Windows login password/PIN for offline DPAPI decryption")

    # Analysis
    anl_g = ap.add_argument_group("Analysis")
    anl_g.add_argument("--ioc-scan", action="store_true", help="IOC/threat intelligence scan")
    anl_g.add_argument("--analyze", action="store_true", help="Full forensic analysis")

    # OPSEC
    ops_g = ap.add_argument_group("OPSEC")
    ops_g.add_argument("--stealth", action="store_true", help="Stealth mode: mask process, suppress output")
    ops_g.add_argument("--encrypt", metavar="PASS", help="Encrypt outputs into .enc bundle")
    ops_g.add_argument("--cleanup", action="store_true", help="Remove all execution traces")
    ops_g.add_argument("--decrypt", nargs=2, metavar=("BUNDLE", "PASS"), help="Decrypt .enc bundle")

    # Performance
    perf_g = ap.add_argument_group("Performance")
    perf_g.add_argument("--threads", type=int, default=8, help="Extraction thread count (default: 8)")
    perf_g.add_argument("--sequential", action="store_true", help="Disable parallel extraction")

    # Dashboard
    ap.add_argument("--dashboard", action="store_true", help="Launch web dashboard after extraction")
    ap.add_argument("--dashboard-port", type=int, default=8080, help="Dashboard port")
    ap.add_argument("--full", action="store_true", help="Enable ALL features")

    args = ap.parse_args()

    # Decrypt mode (standalone)
    if args.decrypt:
        bundle_path, passphrase = args.decrypt
        print(f"[*] Decrypting {bundle_path}...")
        try:
            extracted = opsec.extract_encrypted_bundle(bundle_path, passphrase)
            print(f"[+] Extracted {len(extracted)} files: {extracted}")
        except Exception as e:
            print(f"[!] Decryption failed: {e}")
        return

    # Stealth
    quiet = args.stealth
    if quiet:
        opsec.set_process_name(opsec.get_stealth_name())
        utils.progress = lambda msg: None
    else:
        print(BANNER)
        print("Frostveil | Browser Forensics & Pentest Toolkit\n")

    # --full enables everything
    if args.full:
        for attr in ("credentials", "autofill", "localstorage", "network",
                     "anti_forensics", "ioc_scan", "analyze", "timeline",
                     "report", "html_report", "recover", "favicons", "cache",
                     "deep", "prefs", "password_audit", "cloud_accounts",
                     "pii_scan", "fingerprint", "session_hijack",
                     "media_history", "hsts", "site_engagement",
                     "compromised_creds", "windows_artifacts", "plugins",
                     "stix", "bodyfile", "pdf_report", "case",
                     "elasticsearch"):
            setattr(args, attr, True)

    start_time = time.perf_counter()
    meta = utils.get_metadata()
    utils.log_line(f"=== Frostveil v2.1 started ===")

    # Offline DPAPI: if user provided Windows password, set it globally
    # so the crypto module can use it for credential decryption
    if args.user_password:
        if not quiet:
            print(f"[*] User password provided — enabling offline DPAPI decryption")
        # Store for credential extraction to pick up
        import modules.crypto as _crypto_mod
        _crypto_mod._user_password = args.user_password
        utils.log_line("[DPAPI] Offline decryption mode enabled with user-provided password")

    browsers = utils.find_browsers()
    all_rows, errors = [], []

    # =====================================================================
    # PHASE 1: Browser artifact extraction (parallel or sequential)
    # =====================================================================
    if not quiet:
        print(f"[*] Browsers: {', '.join(browsers.keys()) if browsers else 'none found'}")

    if not args.sequential and browsers:
        # Concurrent extraction
        optional = set()
        if args.credentials: optional.add("credentials")
        if args.autofill: optional.add("autofill")
        if args.localstorage: optional.add("localstorage")
        if args.media_history: optional.add("media_history")
        if args.hsts: optional.add("hsts")
        if args.site_engagement: optional.add("site_engagement")
        if args.compromised_creds: optional.add("compromised_creds")

        rows, errs, stats = engine.extract_all(
            browsers, meta,
            enable_optional=optional,
            enable_anti_forensics=args.anti_forensics,
            max_workers=args.threads,
            quiet=quiet
        )
        all_rows.extend(rows)
        errors.extend(errs)
    else:
        # Sequential fallback
        core_ex = [history, bookmarks, cookies, downloads, searches, sessions, extensions]
        opt_ex = []
        if args.credentials: opt_ex.append(credentials)
        if args.autofill: opt_ex.append(autofill)
        if args.localstorage: opt_ex.append(localstorage)
        if args.media_history: opt_ex.append(media_history)
        if args.hsts: opt_ex.append(hsts)
        if args.site_engagement: opt_ex.append(site_engagement)
        if args.compromised_creds: opt_ex.append(compromised_creds)

        for b, paths in browsers.items():
            bt = engine.resolve_browser_type(b)
            for p in paths:
                utils.progress(f"Processing {b} @ {p.parent.name}")
                for ex in core_ex + opt_ex:
                    try:
                        all_rows.extend(ex.extract(bt, p, meta))
                    except Exception as e:
                        errors.append(f"ERROR {b}: {e}")
                if args.anti_forensics:
                    try:
                        all_rows.extend(anti_forensics.detect(bt, p, meta))
                    except Exception as e:
                        errors.append(f"ERROR anti_forensics {b}: {e}")

    # =====================================================================
    # PHASE 2: Advanced forensic modules
    # =====================================================================

    # Deleted record recovery
    if args.recover:
        if not quiet: print("[*] Recovering deleted records (WAL/freelist/unallocated)...")
        for b, paths in browsers.items():
            bt = engine.resolve_browser_type(b)
            for p in paths:
                try:
                    recovered = wal_forensics.recover_deleted(bt, p, meta)
                    all_rows.extend(recovered)
                    if recovered and not quiet:
                        print(f"    {b}: {len(recovered)} deleted records recovered")
                except Exception as e:
                    errors.append(f"ERROR recovery {b}: {e}")

    # Favicon forensics
    if args.favicons:
        if not quiet: print("[*] Extracting favicons (ghost visit detection)...")
        fav_rows = []
        for b, paths in browsers.items():
            bt = engine.resolve_browser_type(b)
            for p in paths:
                try:
                    fav_rows.extend(favicon_forensics.extract(bt, p, meta))
                except Exception as e:
                    errors.append(f"ERROR favicons {b}: {e}")
        all_rows.extend(fav_rows)
        # Cross-reference with history to find ghost visits
        ghost = favicon_forensics.cross_reference_with_history(fav_rows, all_rows)
        all_rows.extend(ghost)
        if ghost and not quiet:
            print(f"    [!] {len(ghost)} ghost visits detected (favicon exists, history cleared)")

    # Cache forensics
    if args.cache:
        if not quiet: print("[*] Extracting browser cache...")
        for b, paths in browsers.items():
            bt = engine.resolve_browser_type(b)
            for p in paths:
                try:
                    cache_rows = cache_forensics.extract(bt, p, meta)
                    all_rows.extend(cache_rows)
                    if cache_rows and not quiet:
                        print(f"    {b}: {len(cache_rows)} cached entries")
                except Exception as e:
                    errors.append(f"ERROR cache {b}: {e}")

    # Deep extraction (top sites, shortcuts, predictions)
    if args.deep:
        if not quiet: print("[*] Deep extraction (top sites, shortcuts, predictions)...")
        for b, paths in browsers.items():
            bt = engine.resolve_browser_type(b)
            for p in paths:
                try:
                    all_rows.extend(visited_links.extract(bt, p, meta))
                except Exception as e:
                    errors.append(f"ERROR deep {b}: {e}")

    # Preference mining
    if args.prefs:
        if not quiet: print("[*] Mining browser preferences...")
        for b, paths in browsers.items():
            bt = engine.resolve_browser_type(b)
            for p in paths:
                try:
                    all_rows.extend(preference_mining.extract(bt, p, meta))
                except Exception as e:
                    errors.append(f"ERROR prefs {b}: {e}")

    # Network recon
    if args.network:
        if not quiet: print("[*] Network reconnaissance...")
        try:
            net = network_recon.extract(meta)
            all_rows.extend(net)
            if not quiet: print(f"    {len(net)} network artifacts")
        except Exception as e:
            errors.append(f"ERROR network: {e}")

    # Anti-forensics timestamp analysis (cross-artifact, runs after all extraction)
    if args.anti_forensics:
        try:
            anomalies = anti_forensics.detect_timestamp_anomalies(all_rows, meta)
            # Deduplicate: only add anomalies not already in all_rows
            existing_ids = {(r.get("url",""), r.get("visit_time_utc",""), r.get("artifact","")) for r in all_rows}
            new_anomalies = [a for a in anomalies if (a.get("url",""), a.get("visit_time_utc",""), a.get("artifact","")) not in existing_ids]
            all_rows.extend(new_anomalies)
        except Exception as e:
            errors.append(f"ERROR anti_forensics_timestamps: {e}")

    # Cloud account enumeration (runs on all collected artifacts)
    if args.cloud_accounts:
        if not quiet: print("[*] Enumerating cloud accounts...")
        try:
            acct_rows = cloud_accounts.extract_as_artifacts(all_rows, meta)
            all_rows.extend(acct_rows)
            if not quiet:
                report_data = cloud_accounts.enumerate_accounts(all_rows)
                print(f"    {report_data['total_accounts']} accounts, "
                      f"{report_data['total_emails']} emails found")
        except Exception as e:
            errors.append(f"ERROR cloud_accounts: {e}")

    # PII / Sensitive data scan (runs on all collected artifacts)
    if args.pii_scan:
        if not quiet: print("[*] Scanning for PII, API keys, secrets...")
        try:
            pii_rows = pii_scanner.extract_as_artifacts(all_rows, meta)
            all_rows.extend(pii_rows)
            if not quiet:
                pii_data = pii_scanner.scan_all(all_rows)
                print(f"    {pii_data['total_findings']} sensitive items found "
                      f"({len(pii_data.get('critical_findings',[]))} critical)")
        except Exception as e:
            errors.append(f"ERROR pii_scan: {e}")

    # Browser fingerprint reconstruction
    if args.fingerprint:
        if not quiet: print("[*] Reconstructing browser fingerprint...")
        try:
            fp_rows = fingerprint.extract_as_artifacts(all_rows, browsers, meta)
            all_rows.extend(fp_rows)
            if not quiet and fp_rows:
                print(f"    {len(fp_rows)} fingerprint(s) reconstructed")
        except Exception as e:
            errors.append(f"ERROR fingerprint: {e}")

    # Session hijack analysis
    if args.session_hijack:
        if not quiet: print("[*] Analyzing session tokens for hijack potential...")
        try:
            sj_rows = session_hijack.extract_as_artifacts(all_rows, meta)
            all_rows.extend(sj_rows)
            if not quiet:
                sj_data = session_hijack.analyze_sessions(all_rows)
                print(f"    {sj_data['active_sessions']} active sessions, "
                      f"{sj_data['high_value_sessions']} high-value, "
                      f"{sj_data['jwt_tokens_found']} JWTs")
        except Exception as e:
            errors.append(f"ERROR session_hijack: {e}")

    # Windows OS-level artifacts
    if args.windows_artifacts:
        if not quiet: print("[*] Parsing Windows artifacts (Prefetch, Jump Lists, LNK, Recycle Bin)...")
        try:
            win_rows = windows_artifacts.extract_all(meta)
            all_rows.extend(win_rows)
            if not quiet and win_rows:
                import collections as _c
                _wc = _c.Counter(r["artifact"] for r in win_rows)
                parts = ", ".join(f"{v} {k}" for k, v in _wc.most_common())
                print(f"    {len(win_rows)} Windows artifacts ({parts})")
        except Exception as e:
            errors.append(f"ERROR windows_artifacts: {e}")

    # Community plugins
    plugin_outputs = []
    if args.plugins:
        if not quiet: print("[*] Running community plugins...")
        try:
            plug_rows, plug_analysis, plug_exports = plugin_manager.run_plugins(
                all_rows, meta, browsers, quiet=quiet)
            all_rows.extend(plug_rows)
            for i, data in enumerate(plug_analysis):
                label = data.get("plugin", f"plugin_{i}") if isinstance(data, dict) else f"plugin_{i}"
                ppath = Path(f"plugin_{label}.json")
                with open(ppath, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False, default=str)
                plugin_outputs.append(ppath)
            for ep in plug_exports:
                plugin_outputs.append(Path(ep))
            if not quiet:
                print(f"    {len(plug_rows)} rows, {len(plug_analysis)} analyses, "
                      f"{len(plug_exports)} exports from plugins")
        except Exception as e:
            errors.append(f"ERROR plugins: {e}")

    # =====================================================================
    # PHASE 3: Output
    # =====================================================================
    if not quiet: print(f"\n[*] Writing {len(all_rows):,} artifacts to {args.out}")
    outputs = write_outputs(all_rows, args.format, args.out, compress=args.compress,
                            split_artifacts=args.split_artifacts, per_browser=args.per_browser)
    outputs.extend(plugin_outputs)

    if args.timeline:
        tpath = Path("timeline.json")
        timed = sorted([r for r in all_rows if r.get("visit_time_utc")],
                       key=lambda r: r["visit_time_utc"])
        with open(tpath, "w", encoding="utf-8") as f:
            json.dump(timed, f, indent=2, ensure_ascii=False)
        outputs.append(tpath)
        if not quiet: print(f"[*] Timeline: {len(timed):,} events")

    # =====================================================================
    # PHASE 4: Analysis
    # =====================================================================
    ioc_data = None
    if args.ioc_scan:
        if not quiet: print("[*] IOC/threat intelligence scan...")
        ioc_data = ioc_engine.analyze_all(all_rows)
        ioc_path = Path("ioc_report.json")
        with open(ioc_path, "w", encoding="utf-8") as f:
            json.dump(ioc_data, f, indent=2, ensure_ascii=False)
        outputs.append(ioc_path)
        if not quiet:
            print(f"    Risk: {ioc_data.get('overall_risk_level','?')} "
                  f"(Score: {ioc_data.get('overall_risk_score',0)}/100, "
                  f"{ioc_data.get('total_iocs',0)} IOCs)")

    analysis_data = None
    if args.analyze:
        if not quiet: print("[*] Forensic analysis engine...")
        analysis_data = analyzer.full_analysis(all_rows)
        with open("analysis_report.json", "w", encoding="utf-8") as f:
            json.dump(analysis_data, f, indent=2, ensure_ascii=False, default=str)
        outputs.append(Path("analysis_report.json"))
        if not quiet:
            si = analysis_data.get("session_reconstruction", {})
            di = analysis_data.get("domain_intel", {})
            ci = analysis_data.get("credential_analysis", {})
            pi = analysis_data.get("privacy_exposure", {})
            if si.get("total_sessions"): print(f"    Sessions: {si['total_sessions']:,}")
            if di.get("unique_domains"): print(f"    Domains: {di['unique_domains']:,}")
            if ci.get("total_credentials"): print(f"    Credentials: {ci['total_credentials']}")
            if ci.get("reuse_risk"): print(f"    [!] Password reuse across {len(ci.get('reused_usernames',{}))} accounts")
            if pi.get("overall_exposure_score"): print(f"    Privacy exposure: {pi['overall_exposure_score']}/100")

    pwd_audit = None
    if args.password_audit:
        if not quiet: print("[*] Password audit...")
        pwd_audit = password_audit.analyze_all(all_rows)
        with open("password_audit.json", "w", encoding="utf-8") as f:
            json.dump(pwd_audit, f, indent=2, ensure_ascii=False, default=str)
        outputs.append(Path("password_audit.json"))
        if not quiet and pwd_audit.get("total_analyzed"):
            print(f"    Analyzed: {pwd_audit['total_analyzed']}, "
                  f"Avg score: {pwd_audit['average_score']}/100, "
                  f"Reused: {pwd_audit['reused_passwords']}, "
                  f"Common: {pwd_audit['common_passwords_found']}")

    # Cloud accounts report
    cloud_data = None
    if args.cloud_accounts:
        cloud_data = cloud_accounts.enumerate_accounts(all_rows)
        with open("cloud_accounts.json", "w", encoding="utf-8") as f:
            json.dump(cloud_data, f, indent=2, ensure_ascii=False, default=str)
        outputs.append(Path("cloud_accounts.json"))

    # PII scan report
    pii_data = None
    if args.pii_scan:
        pii_data = pii_scanner.scan_all(all_rows)
        with open("pii_report.json", "w", encoding="utf-8") as f:
            json.dump(pii_data, f, indent=2, ensure_ascii=False, default=str)
        outputs.append(Path("pii_report.json"))

    # Fingerprint report
    fp_data = None
    if args.fingerprint:
        fp_data = fingerprint.reconstruct(all_rows, browsers, meta)
        with open("fingerprint_report.json", "w", encoding="utf-8") as f:
            json.dump(fp_data, f, indent=2, ensure_ascii=False, default=str)
        outputs.append(Path("fingerprint_report.json"))

    # Session hijack report
    session_data = None
    if args.session_hijack:
        session_data = session_hijack.analyze_sessions(all_rows)
        with open("session_hijack.json", "w", encoding="utf-8") as f:
            json.dump(session_data, f, indent=2, ensure_ascii=False, default=str)
        outputs.append(Path("session_hijack.json"))

    # Media history report
    media_data = None
    if args.media_history:
        media_data = media_history.summarize(all_rows)
        if media_data.get("total_playbacks") or media_data.get("total_origins"):
            with open("media_history.json", "w", encoding="utf-8") as f:
                json.dump(media_data, f, indent=2, ensure_ascii=False, default=str)
            outputs.append(Path("media_history.json"))

    # HSTS report
    hsts_data = None
    if args.hsts:
        hsts_data = hsts.summarize(all_rows)
        if hsts_data.get("total_entries"):
            with open("hsts_report.json", "w", encoding="utf-8") as f:
                json.dump(hsts_data, f, indent=2, ensure_ascii=False, default=str)
            outputs.append(Path("hsts_report.json"))

    # Site engagement report
    engagement_data = None
    if args.site_engagement:
        engagement_data = site_engagement.summarize(all_rows)
        if engagement_data.get("total_sites"):
            with open("site_engagement.json", "w", encoding="utf-8") as f:
                json.dump(engagement_data, f, indent=2, ensure_ascii=False, default=str)
            outputs.append(Path("site_engagement.json"))

    # Compromised credentials report
    comp_creds_data = None
    if args.compromised_creds:
        comp_creds_data = compromised_creds.summarize(all_rows)
        if comp_creds_data.get("total_compromised"):
            with open("compromised_creds.json", "w", encoding="utf-8") as f:
                json.dump(comp_creds_data, f, indent=2, ensure_ascii=False, default=str)
            outputs.append(Path("compromised_creds.json"))

    # =====================================================================
    # PHASE 5: Reports & signing
    # =====================================================================
    manifest = utils.build_manifest(meta, outputs, all_rows, errors)
    with open("manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    utils.sign_manifest("manifest.json")

    if args.report:
        report.generate(manifest, ioc_data, analysis_data)
        if not quiet: print("[*] Markdown report: report.md")

    if args.html_report:
        html_report.generate(manifest, ioc_data, analysis_data, pwd_audit)
        outputs.append(Path("frostveil_report.html"))
        if not quiet: print("[*] HTML report: frostveil_report.html")

    if args.pdf_report:
        try:
            pdf_path = pdf_report.generate(manifest, ioc_data, analysis_data, pwd_audit)
            outputs.append(Path(pdf_path))
            if not quiet: print(f"[*] PDF report: {pdf_path}")
        except Exception as e:
            errors.append(f"ERROR pdf_report: {e}")

    # Forensic export formats
    if args.stix:
        try:
            sp = export_formats.export_stix(all_rows)
            outputs.append(Path(sp))
            if not quiet: print(f"[*] STIX 2.1 bundle: {sp}")
        except Exception as e:
            errors.append(f"ERROR stix export: {e}")

    if args.bodyfile:
        try:
            bp = export_formats.export_bodyfile(all_rows)
            outputs.append(Path(bp))
            if not quiet: print(f"[*] Bodyfile: {bp}")
        except Exception as e:
            errors.append(f"ERROR bodyfile export: {e}")

    if args.case:
        try:
            cp = export_formats.export_case(all_rows)
            outputs.append(Path(cp))
            if not quiet: print(f"[*] CASE/UCO: {cp}")
        except Exception as e:
            errors.append(f"ERROR CASE export: {e}")

    if args.elasticsearch:
        try:
            ep = export_formats.export_elasticsearch(all_rows)
            outputs.append(Path(ep))
            if not quiet: print(f"[*] Elasticsearch bulk: {ep}")
        except Exception as e:
            errors.append(f"ERROR elasticsearch export: {e}")

    # OPSEC
    if args.encrypt:
        if not quiet: print("[*] Encrypting outputs...")
        all_files = [str(f) for f in outputs] + ["manifest.json", "manifest.json.sig"]
        if args.report: all_files.append("report.md")
        opsec.create_encrypted_bundle(all_files, args.encrypt)
        if not quiet: print(f"[+] Encrypted bundle: frostveil.enc")

    utils.cleanup_temp()

    if args.cleanup:
        if not quiet: print("[*] Cleaning traces...")
        cleaned = opsec.cleanup_all_traces(
            keep_output=not args.encrypt,
            output_files=outputs if args.encrypt else None
        )
        if not quiet: print(f"    Cleaned {len(cleaned)} items")

    # =====================================================================
    # SUMMARY
    # =====================================================================
    elapsed = time.perf_counter() - start_time

    if not quiet:
        import collections
        ac = collections.Counter(r["artifact"] for r in all_rows)

        print(f"\n{'='*60}")
        print(f"  FROSTVEIL EXTRACTION COMPLETE")
        print(f"{'='*60}")
        print(f"  Time:       {elapsed:.2f}s ({len(all_rows)/max(elapsed,.001):,.0f} artifacts/sec)")
        print(f"  Host:       {meta['hostname']}")
        print(f"  User:       {meta['username']}")
        print(f"  OS:         {meta['os']}")
        print(f"  Browsers:   {', '.join(browsers.keys()) if browsers else 'none'}")
        print(f"  Artifacts:  {len(all_rows):,} total")
        for atype, count in ac.most_common():
            print(f"              - {atype}: {count:,}")
        print(f"  Outputs:    {[str(x) for x in outputs]}")
        if ioc_data:
            print(f"  Threat:     {ioc_data.get('overall_risk_level','?')} ({ioc_data.get('total_iocs',0)} IOCs)")
        if pwd_audit and pwd_audit.get("total_analyzed"):
            print(f"  Passwords:  {pwd_audit['total_analyzed']} analyzed, avg score {pwd_audit['average_score']}/100")
        if cloud_data and cloud_data.get("total_accounts"):
            print(f"  Accounts:   {cloud_data['total_accounts']} cloud accounts, {cloud_data['total_emails']} emails")
        if pii_data and pii_data.get("total_findings"):
            crit = len(pii_data.get("critical_findings", []))
            print(f"  PII/Secrets:{pii_data['total_findings']} findings ({crit} critical)")
        if fp_data and fp_data.get("total_profiles"):
            print(f"  Fingerprint:{fp_data['total_profiles']} profile(s) reconstructed")
        if session_data and session_data.get("active_sessions"):
            print(f"  Sessions:   {session_data['active_sessions']} active, "
                  f"{session_data['high_value_sessions']} high-value")
        if media_data and media_data.get("total_playbacks"):
            print(f"  Media:      {media_data['total_playbacks']} playbacks, "
                  f"{media_data.get('total_watchtime_hours', 0):.1f}h watchtime")
        if hsts_data and hsts_data.get("total_entries"):
            print(f"  HSTS:       {hsts_data['total_entries']} entries "
                  f"({hsts_data['active_count']} active)")
        if engagement_data and engagement_data.get("total_sites"):
            print(f"  Engagement: {engagement_data['total_sites']} sites, "
                  f"avg score {engagement_data.get('average_score', 0)}")
        if comp_creds_data and comp_creds_data.get("total_compromised"):
            print(f"  Compromised:{comp_creds_data['total_compromised']} credentials flagged")
        if args.encrypt:
            print(f"  Bundle:     frostveil.enc (AES-256-GCM)")
        if errors:
            print(f"\n  [!] Errors: {len(errors)}")
            for e in errors[:5]:
                print(f"      - {e}")
            if len(errors) > 5:
                print(f"      ... and {len(errors)-5} more (see frostveil.log)")
        print()

    # Dashboard
    if args.dashboard:
        if not quiet: print(f"[*] Dashboard: http://127.0.0.1:{args.dashboard_port}")
        from server import load_data, FrostveilHandler
        from http.server import HTTPServer
        import webbrowser, threading
        load_data(args.out if args.format == "json" else None)
        srv = HTTPServer(("127.0.0.1", args.dashboard_port), FrostveilHandler)
        threading.Timer(0.5, lambda: webbrowser.open(f"http://127.0.0.1:{args.dashboard_port}")).start()
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            srv.server_close()


if __name__ == "__main__":
    main()
