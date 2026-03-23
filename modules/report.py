"""
Frostveil Report Generator — comprehensive forensic Markdown report
with threat analysis, risk scoring, and executive summary.
"""
from pathlib import Path
from datetime import datetime

def generate(manifest, ioc_report=None, analysis=None):
    out = Path("report.md")
    counts = manifest.get("counts", {})
    meta = manifest.get("metadata", {})
    md = []

    # Header
    md.append("# Frostveil Browser Forensics Report")
    md.append("")
    md.append(f"**Generated**: {datetime.utcnow().isoformat()}Z  ")
    md.append(f"**Frostveil Version**: {manifest.get('frostveil_version', '2.0.0')}  ")
    md.append("")

    # System info
    md.append("## System Information")
    md.append("")
    md.append(f"| Field | Value |")
    md.append(f"|-------|-------|")
    md.append(f"| **Host** | {meta.get('hostname', 'N/A')} |")
    md.append(f"| **User** | {meta.get('username', 'N/A')} |")
    md.append(f"| **OS** | {meta.get('os', 'N/A')} |")
    md.append(f"| **Architecture** | {meta.get('arch', 'N/A')} |")
    md.append(f"| **Acquired at** | {meta.get('acquired_utc', 'N/A')} |")
    md.append("")

    # Artifact summary
    md.append("## Artifact Summary")
    md.append("")
    md.append(f"**Total artifacts collected**: {manifest.get('total_artifacts', sum(counts.values()))}")
    md.append("")
    md.append("| Artifact Type | Count |")
    md.append("|--------------|-------|")
    for k, v in sorted(counts.items(), key=lambda x: x[1], reverse=True):
        md.append(f"| {k} | {v:,} |")
    md.append("")

    # Threat analysis
    if ioc_report:
        md.append("## Threat Analysis")
        md.append("")
        risk_level = ioc_report.get("overall_risk_level", "UNKNOWN")
        risk_score = ioc_report.get("overall_risk_score", 0)
        risk_emoji = {"CRITICAL": "[!!!]", "HIGH": "[!!]", "MEDIUM": "[!]",
                      "LOW": "[~]", "CLEAN": "[OK]"}.get(risk_level, "")

        md.append(f"### Overall Risk: {risk_emoji} {risk_level} (Score: {risk_score}/100)")
        md.append("")
        md.append(f"- **Total IOCs detected**: {ioc_report.get('total_iocs', 0)}")
        md.append(f"- **URLs scanned**: {ioc_report.get('urls_scanned', 0)}")
        md.append("")

        critical = ioc_report.get("critical_findings", [])
        if critical:
            md.append("### Critical Findings")
            md.append("")
            md.append("| Type | Severity | URL/Detail |")
            md.append("|------|----------|------------|")
            for f in critical[:20]:
                url = f.get("url", f.get("detail", ""))[:80]
                md.append(f"| {f.get('type', '')} | {f.get('severity', '')} | `{url}` |")
            md.append("")

        high = ioc_report.get("high_findings", [])
        if high:
            md.append("### High Severity Findings")
            md.append("")
            md.append("| Type | Severity | URL/Detail |")
            md.append("|------|----------|------------|")
            for f in high[:15]:
                url = f.get("url", f.get("detail", ""))[:80]
                md.append(f"| {f.get('type', '')} | {f.get('severity', '')} | `{url}` |")
            md.append("")

        time_anomalies = ioc_report.get("time_anomalies", [])
        if time_anomalies:
            md.append("### Behavioral Anomalies")
            md.append("")
            for a in time_anomalies:
                md.append(f"- **{a.get('type', '')}** (severity: {a.get('severity', '')}): {a.get('detail', '')}")
            md.append("")

        exfil = ioc_report.get("exfiltration_indicators", [])
        if exfil:
            md.append("### Data Exfiltration Indicators")
            md.append("")
            for e in exfil:
                md.append(f"- **{e.get('type', '')}** (severity: {e.get('severity', '')}): {e.get('detail', '')}")
            md.append("")

    # Forensic analysis
    if analysis:
        md.append("## Forensic Analysis")
        md.append("")

        # Domain intelligence
        domain_intel = analysis.get("domain_intel", {})
        if domain_intel:
            md.append("### Domain Intelligence")
            md.append("")
            md.append(f"- **Unique domains**: {domain_intel.get('unique_domains', 0):,}")
            md.append(f"- **Browsing diversity**: {domain_intel.get('diversity_score', 0)} bits")
            md.append(f"- **One-time domains**: {domain_intel.get('one_time_domains_count', 0):,}")
            md.append("")
            top = domain_intel.get("top_50_domains", [])[:15]
            if top:
                md.append("**Top 15 Domains:**")
                md.append("")
                md.append("| Domain | Visits | Active Days |")
                md.append("|--------|--------|-------------|")
                for d in top:
                    md.append(f"| {d['domain']} | {d['visits']:,} | {d.get('active_days', '-')} |")
                md.append("")

        # Session reconstruction
        sessions = analysis.get("session_reconstruction", {})
        if sessions.get("total_sessions"):
            md.append("### Session Analysis")
            md.append("")
            md.append(f"- **Total sessions**: {sessions['total_sessions']:,}")
            md.append(f"- **Avg duration**: {sessions.get('avg_duration_minutes', 0)} min")
            md.append(f"- **Avg pages/session**: {sessions.get('avg_pages_per_session', 0)}")
            md.append(f"- **Longest session**: {sessions.get('longest_session_minutes', 0)} min")
            md.append("")

        # Credential analysis
        creds = analysis.get("credential_analysis", {})
        if creds.get("total_credentials"):
            md.append("### Credential Analysis")
            md.append("")
            md.append(f"- **Total saved credentials**: {creds['total_credentials']}")
            md.append(f"- **Unique domains**: {creds.get('unique_domains', 0)}")
            md.append(f"- **Decrypted**: {creds.get('decrypted_count', 0)}")
            md.append(f"- **Password reuse detected**: {'YES' if creds.get('reuse_risk') else 'No'}")
            md.append("")
            if creds.get("reused_usernames"):
                md.append("**Reused credentials (cross-site):**")
                md.append("")
                for user, domains in list(creds["reused_usernames"].items())[:10]:
                    md.append(f"- `{user}` used on: {', '.join(domains[:5])}")
                md.append("")

        # Download analysis
        downloads = analysis.get("download_analysis", {})
        if downloads.get("total_downloads"):
            md.append("### Download Risk Assessment")
            md.append("")
            md.append(f"- **Total downloads**: {downloads['total_downloads']:,}")
            md.append(f"- **High-risk downloads**: {downloads.get('high_risk_count', 0)}")
            md.append("")
            risky = downloads.get("risky_downloads", [])[:10]
            if risky:
                md.append("| File | Extension | Risk | Source |")
                md.append("|------|-----------|------|--------|")
                for d in risky:
                    md.append(f"| `{d['file'][-50:]}` | {d['extension']} | {d['risk_score']} | `{d['source'][:50]}` |")
                md.append("")

        # Privacy exposure
        privacy = analysis.get("privacy_exposure", {})
        if privacy:
            md.append("### Privacy Exposure Score")
            md.append("")
            md.append(f"**Overall exposure**: {privacy.get('overall_exposure_score', 0)}/100")
            md.append("")
            cats = privacy.get("category_scores", {})
            if cats:
                md.append("| Category | Score |")
                md.append("|----------|-------|")
                for cat, score in sorted(cats.items(), key=lambda x: x[1], reverse=True):
                    bar = "#" * (score // 5) + "." * (20 - score // 5)
                    md.append(f"| {cat} | {score}/100 [{bar}] |")
                md.append("")

    # Output files
    md.append("## Output Files")
    md.append("")
    for f, h in manifest.get("outputs", {}).items():
        md.append(f"- `{f}` — SHA256: `{h}`")
    md.append("")

    # Errors
    errors = manifest.get("errors", [])
    if errors:
        md.append("## Errors & Access Denied")
        md.append("")
        md.append(f"**Total**: {len(errors)}")
        md.append("")
        for e in errors[:20]:
            md.append(f"- {e}")
        md.append("")

    # Footer
    md.append("---")
    md.append("*Generated by Frostveil v2.0.0 — Browser Forensics Toolkit*")
    md.append("")

    out.write_text("\n".join(md), encoding="utf-8")
    return out
