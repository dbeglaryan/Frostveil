"""
Frostveil HTML Report Generator — self-contained forensic report
with embedded CSS, charts, and interactive tables. No external dependencies.

Opens in any browser. Single file. Shareable.
"""
import json
from pathlib import Path
from datetime import datetime

def generate(manifest, ioc_report=None, analysis=None, password_audit=None,
             output_path="frostveil_report.html"):
    """Generate a self-contained HTML forensic report."""
    meta = manifest.get("metadata", {})
    counts = manifest.get("counts", {})
    total = manifest.get("total_artifacts", sum(counts.values()))

    risk_score = ioc_report.get("overall_risk_score", 0) if ioc_report else 0
    risk_level = ioc_report.get("overall_risk_level", "N/A") if ioc_report else "N/A"

    # Build chart data
    chart_data = json.dumps(counts)
    risk_color = "#ff4757" if risk_score >= 80 else "#ffa502" if risk_score >= 60 else "#eccc68" if risk_score >= 40 else "#2ed573"

    privacy = analysis.get("privacy_exposure", {}) if analysis else {}
    domain_intel = analysis.get("domain_intel", {}) if analysis else {}
    cred_analysis = analysis.get("credential_analysis", {}) if analysis else {}
    dl_analysis = analysis.get("download_analysis", {}) if analysis else {}
    sessions = analysis.get("session_reconstruction", {}) if analysis else {}

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Frostveil Forensic Report</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ background:#0a0e14; color:#c5d0dc; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; font-size:13px; padding:20px 40px; }}
h1 {{ color:#00d4ff; font-size:22px; margin-bottom:4px; letter-spacing:2px; }}
h2 {{ color:#e6edf5; font-size:16px; margin:24px 0 12px; padding-bottom:6px; border-bottom:1px solid #1e2a3a; }}
h3 {{ color:#c5d0dc; font-size:13px; margin:16px 0 8px; }}
.subtitle {{ color:#6b7d93; font-size:12px; margin-bottom:20px; }}
.card {{ background:#151d28; border:1px solid #1e2a3a; border-radius:6px; padding:16px; margin-bottom:16px; }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(160px,1fr)); gap:10px; margin-bottom:20px; }}
.metric {{ background:#151d28; border:1px solid #1e2a3a; border-radius:6px; padding:12px; text-align:center; }}
.metric .val {{ font-size:24px; font-weight:700; font-family:monospace; }}
.metric .lbl {{ font-size:10px; text-transform:uppercase; letter-spacing:1.5px; color:#6b7d93; margin-top:2px; }}
.accent {{ color:#00d4ff; }}
.red {{ color:#ff4757; }}
.orange {{ color:#ffa502; }}
.green {{ color:#2ed573; }}
table {{ width:100%; border-collapse:collapse; font-size:12px; }}
th {{ text-align:left; padding:6px 8px; border-bottom:1px solid #1e2a3a; color:#6b7d93; font-size:10px; text-transform:uppercase; letter-spacing:1px; }}
td {{ padding:5px 8px; border-bottom:1px solid #111820; }}
tr:hover td {{ background:#1a2332; }}
.mono {{ font-family:monospace; font-size:11px; }}
.dim {{ color:#6b7d93; }}
.sev {{ display:inline-block; font-family:monospace; font-size:10px; font-weight:600; padding:2px 6px; border-radius:3px; }}
.sev-crit {{ background:rgba(255,71,87,.15); color:#ff4757; }}
.sev-high {{ background:rgba(255,165,2,.12); color:#ffa502; }}
.sev-med {{ background:rgba(236,204,104,.12); color:#eccc68; }}
.sev-low {{ background:rgba(46,213,115,.12); color:#2ed573; }}
.bar {{ display:flex; align-items:center; gap:6px; margin:3px 0; }}
.bar-l {{ width:120px; text-align:right; font-size:11px; color:#6b7d93; font-family:monospace; }}
.bar-t {{ flex:1; height:14px; background:#0d1117; border-radius:3px; overflow:hidden; }}
.bar-f {{ height:100%; border-radius:3px; transition:width .5s; }}
.bar-v {{ width:40px; font-size:11px; font-family:monospace; color:#6b7d93; }}
.gauge {{ width:100px; height:100px; margin:0 auto; position:relative; }}
.gauge svg {{ width:100%; height:100%; transform:rotate(-90deg); }}
.gauge .track {{ fill:none; stroke:#1e2a3a; stroke-width:8; }}
.gauge .fill {{ fill:none; stroke-width:8; stroke-linecap:round; }}
.gauge .center {{ position:absolute; top:50%;left:50%; transform:translate(-50%,-50%); font-family:monospace; font-size:22px; font-weight:700; }}
.two {{ display:grid; grid-template-columns:1fr 1fr; gap:16px; }}
@media(max-width:900px) {{ .two {{ grid-template-columns:1fr; }} }}
footer {{ margin-top:30px; padding-top:12px; border-top:1px solid #1e2a3a; color:#6b7d93; font-size:11px; text-align:center; }}
</style>
</head>
<body>
<h1>FROSTVEIL FORENSIC REPORT</h1>
<div class="subtitle">Generated {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC &mdash; Frostveil v2.0</div>

<div class="grid">
  <div class="metric"><div class="val accent">{total:,}</div><div class="lbl">Total Artifacts</div></div>
  <div class="metric"><div class="val" style="color:{risk_color}">{risk_score}</div><div class="lbl">Risk Score</div></div>
  <div class="metric"><div class="val">{ioc_report.get('total_iocs', 0) if ioc_report else 0}</div><div class="lbl">IOCs Detected</div></div>
  <div class="metric"><div class="val orange">{cred_analysis.get('total_credentials', 0)}</div><div class="lbl">Credentials</div></div>
  <div class="metric"><div class="val">{domain_intel.get('unique_domains', 0):,}</div><div class="lbl">Domains</div></div>
  <div class="metric"><div class="val">{sessions.get('total_sessions', 0):,}</div><div class="lbl">Sessions</div></div>
</div>

<div class="two">
<div class="card">
<h3>System Information</h3>
<table>
<tr><td class="dim">Hostname</td><td class="mono">{_e(meta.get('hostname',''))}</td></tr>
<tr><td class="dim">Username</td><td class="mono">{_e(meta.get('username',''))}</td></tr>
<tr><td class="dim">OS</td><td class="mono">{_e(meta.get('os',''))}</td></tr>
<tr><td class="dim">Acquired</td><td class="mono">{_e(meta.get('acquired_utc',''))}</td></tr>
</table>
</div>

<div class="card">
<h3>Artifact Breakdown</h3>
{''.join(f'<div class="bar"><span class="bar-l">{k}</span><div class="bar-t"><div class="bar-f" style="width:{v/max(counts.values(),default=1)*100:.0f}%;background:#00d4ff"></div></div><span class="bar-v">{v:,}</span></div>' for k,v in sorted(counts.items(), key=lambda x:x[1], reverse=True))}
</div>
</div>
"""

    # Threat analysis
    if ioc_report:
        critical = ioc_report.get("critical_findings", [])
        high = ioc_report.get("high_findings", [])
        html += f"""
<h2>Threat Intelligence</h2>
<div class="card" style="border-left:3px solid {risk_color}">
<h3>Overall Risk: <span style="color:{risk_color}">{risk_level}</span> (Score: {risk_score}/100)</h3>
<p style="margin-top:6px;color:#6b7d93">Scanned {ioc_report.get('urls_scanned',0):,} URLs &mdash; {ioc_report.get('total_iocs',0)} indicators found</p>
</div>
"""
        if critical:
            html += '<div class="card"><h3>Critical Findings</h3><table><tr><th>Type</th><th>Severity</th><th>URL</th></tr>'
            for f in critical[:20]:
                html += f'<tr><td><span class="sev sev-crit">{_e(f.get("type",""))}</span></td><td class="mono">{f.get("severity","")}</td><td class="mono accent">{_e(_t(f.get("url",""),80))}</td></tr>'
            html += '</table></div>'

        if high:
            html += '<div class="card"><h3>High Severity</h3><table><tr><th>Type</th><th>Severity</th><th>URL</th></tr>'
            for f in high[:15]:
                html += f'<tr><td><span class="sev sev-high">{_e(f.get("type",""))}</span></td><td class="mono">{f.get("severity","")}</td><td class="mono">{_e(_t(f.get("url",""),80))}</td></tr>'
            html += '</table></div>'

    # Password audit
    if password_audit and password_audit.get("total_analyzed"):
        pa = password_audit
        avg_cls = "red" if pa["average_score"] < 40 else "orange" if pa["average_score"] < 60 else "green"

        # Build strength distribution bars outside f-string to avoid quoting issues
        dist_bars = ""
        for k, v in pa.get("strength_distribution", {}).items():
            pct = v / max(pa["total_analyzed"], 1) * 100
            bar_color = "#ff4757" if k in ("critical", "weak") else "#ffa502" if k == "fair" else "#2ed573"
            dist_bars += (f'<div class="bar"><span class="bar-l">{k.upper()}</span>'
                          f'<div class="bar-t"><div class="bar-f" style="width:{pct:.0f}%;background:{bar_color}"></div></div>'
                          f'<span class="bar-v">{v}</span></div>')

        html += f"""
<h2>Password Audit</h2>
<div class="grid">
  <div class="metric"><div class="val">{pa['total_analyzed']}</div><div class="lbl">Analyzed</div></div>
  <div class="metric"><div class="val {avg_cls}">{pa['average_score']}</div><div class="lbl">Avg Score</div></div>
  <div class="metric"><div class="val red">{pa['reused_passwords']}</div><div class="lbl">Reused</div></div>
  <div class="metric"><div class="val red">{pa['common_passwords_found']}</div><div class="lbl">Common PWDs</div></div>
</div>
<div class="card"><h3>Strength Distribution</h3>
{dist_bars}
</div>
"""
        weakest = pa.get("weakest_passwords", [])
        if weakest:
            html += '<div class="card"><h3>Weakest Credentials</h3><table><tr><th>URL</th><th>Username</th><th>Score</th><th>Issues</th></tr>'
            for w in weakest[:10]:
                html += f'<tr><td class="mono accent">{_e(_t(w.get("url",""),50))}</td><td class="mono">{_e(w.get("username",""))}</td><td class="mono red">{w.get("score","")}</td><td class="dim">{", ".join(w.get("issues",[]))}</td></tr>'
            html += '</table></div>'

    # Privacy exposure
    if privacy.get("category_scores"):
        html += '<h2>Privacy Exposure</h2><div class="card">'
        for cat, score in sorted(privacy["category_scores"].items(), key=lambda x: x[1], reverse=True):
            color = "#ff4757" if score >= 70 else "#ffa502" if score >= 40 else "#2ed573"
            html += f'<div class="bar"><span class="bar-l">{cat.replace("_"," ")}</span><div class="bar-t"><div class="bar-f" style="width:{score}%;background:{color}"></div></div><span class="bar-v" style="color:{color}">{score}</span></div>'
        html += '</div>'

    # Domain intel
    if domain_intel.get("top_50_domains"):
        html += '<h2>Top Domains</h2><div class="card"><table><tr><th>Domain</th><th>Visits</th><th>Days Active</th></tr>'
        for d in domain_intel["top_50_domains"][:20]:
            html += f'<tr><td class="mono accent">{_e(d["domain"])}</td><td class="mono">{d["visits"]:,}</td><td class="mono">{d.get("active_days","")}</td></tr>'
        html += '</table></div>'

    # Download risks
    if dl_analysis.get("risky_downloads"):
        html += '<h2>Risky Downloads</h2><div class="card"><table><tr><th>File</th><th>Ext</th><th>Risk</th></tr>'
        for d in dl_analysis["risky_downloads"][:15]:
            sev = "sev-crit" if d["risk_score"] >= 80 else "sev-high" if d["risk_score"] >= 60 else "sev-med"
            html += f'<tr><td class="mono">{_e(_t(d["file"],60))}</td><td><span class="sev {sev}">{d["extension"]}</span></td><td class="mono">{d["risk_score"]}</td></tr>'
        html += '</table></div>'

    # Output files
    html += '<h2>Output Files</h2><div class="card"><table><tr><th>File</th><th>SHA256</th></tr>'
    for f, h in manifest.get("outputs", {}).items():
        html += f'<tr><td class="mono">{_e(f)}</td><td class="mono dim">{h}</td></tr>'
    html += '</table></div>'

    # Errors
    errors = manifest.get("errors", [])
    if errors:
        html += f'<h2>Errors ({len(errors)})</h2><div class="card">'
        for e in errors[:20]:
            html += f'<div class="dim" style="margin-bottom:3px">{_e(e)}</div>'
        html += '</div>'

    html += """
<footer>Generated by Frostveil v2.0 &mdash; Browser Forensics &amp; Penetration Testing Toolkit</footer>
</body>
</html>"""

    Path(output_path).write_text(html, encoding="utf-8")
    return output_path

def _e(s):
    """Escape HTML."""
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")

def _t(s, n=80):
    """Truncate."""
    s = str(s)
    return s[:n] + "..." if len(s) > n else s
