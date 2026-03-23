/* ================================================================
   FROSTVEIL DASHBOARD — Interactive forensic analysis SPA
   ================================================================ */

const API = "";
const PAGE_SIZE = 100;

let state = {
  artifacts: [],
  ioc: null,
  analysis: null,
  manifest: null,
  summary: null,
  currentView: "overview",
  pages: {},
};

// ---- Bootstrap ----
document.addEventListener("DOMContentLoaded", async () => {
  setupNav();
  setupSearch();
  setupDetailPanel();
  await loadAllData();
  renderCurrentView();
});

async function loadAllData() {
  try {
    const [artifacts, ioc, analysis, manifest, summary] = await Promise.all([
      fetchJSON("/api/artifacts"),
      fetchJSON("/api/ioc"),
      fetchJSON("/api/analysis"),
      fetchJSON("/api/manifest"),
      fetchJSON("/api/summary"),
    ]);
    state.artifacts = Array.isArray(artifacts) ? artifacts : [];
    state.ioc = ioc && !ioc.error ? ioc : null;
    state.analysis = analysis && !analysis.error ? analysis : null;
    state.manifest = manifest && !manifest.error ? manifest : null;
    state.summary = summary && !summary.error ? summary : null;

    // Update topbar
    document.getElementById("artifact-count").textContent =
      `${state.artifacts.length.toLocaleString()} artifacts`;

    const risk = state.ioc?.overall_risk_level || state.summary?.risk_level || "N/A";
    const badge = document.getElementById("risk-badge");
    badge.textContent = risk;
    badge.className = "badge " + risk.toLowerCase();
  } catch (e) {
    console.error("Failed to load data:", e);
  }
}

async function fetchJSON(url) {
  try {
    const res = await fetch(API + url);
    if (!res.ok) return null;
    return await res.json();
  } catch { return null; }
}

// ---- Navigation ----
function setupNav() {
  document.querySelectorAll(".nav-item").forEach(item => {
    item.addEventListener("click", (e) => {
      e.preventDefault();
      const view = item.dataset.view;
      document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
      item.classList.add("active");
      state.currentView = view;
      renderCurrentView();
    });
  });
}

function renderCurrentView() {
  document.querySelectorAll(".view").forEach(v => v.classList.remove("active"));
  const el = document.getElementById(`view-${state.currentView}`);
  if (el) {
    el.classList.add("active");
    const renderers = {
      overview: renderOverview,
      timeline: renderTimeline,
      credentials: renderCredentials,
      cookies: renderCookies,
      history: renderHistory,
      downloads: renderDownloads,
      ioc: renderIOC,
      extensions: renderExtensions,
      network: renderNetwork,
      sessions: renderSessions,
      autofill: renderAutofill,
      storage: renderStorage,
      antiforensics: renderAntiForensics,
      search: renderSearches,
      recovered: renderRecovered,
      favicons: renderFavicons,
      cache: renderCache,
      prefs: renderPreferences,
      cloud: renderCloudAccounts,
      pii: renderPII,
      fingerprint: renderFingerprint,
      hijack: renderSessionHijack,
      media: renderMedia,
      engagement: renderEngagement,
      compromised: renderCompromised,
      windows: renderWindows,
    };
    if (renderers[state.currentView]) {
      renderers[state.currentView](el);
    }
  }
}

// ---- Search ----
function setupSearch() {
  const input = document.getElementById("global-search");
  let debounce;
  input.addEventListener("input", () => {
    clearTimeout(debounce);
    debounce = setTimeout(async () => {
      const q = input.value.trim();
      if (q.length < 2) return;
      const results = await fetchJSON(`/api/search?q=${encodeURIComponent(q)}`);
      if (results && results.length > 0) {
        // Switch to a search results view
        state.currentView = "history";
        renderFilteredTable(
          document.getElementById("view-history"),
          results,
          `Search results for "${q}"`,
          ["browser", "artifact", "url", "title", "visit_time_utc"]
        );
        document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
      }
    }, 300);
  });
}

// ---- Detail Panel ----
function setupDetailPanel() {
  document.getElementById("detail-close").addEventListener("click", closeDetail);
}

function openDetail(row) {
  const panel = document.getElementById("detail-panel");
  const body = document.getElementById("detail-body");
  const title = document.getElementById("detail-title");

  title.textContent = row.artifact?.toUpperCase() || "DETAIL";

  let html = "";
  const fields = [
    ["Browser", row.browser],
    ["Artifact", row.artifact],
    ["Profile", row.profile],
    ["URL", row.url, "url"],
    ["Title", row.title],
    ["Visit Count", row.visit_count],
    ["Timestamp", row.visit_time_utc],
  ];

  for (const [label, value, cls] of fields) {
    if (value !== null && value !== undefined && value !== "") {
      html += `<div class="detail-field">
        <div class="detail-field-label">${label}</div>
        <div class="detail-field-value ${cls || ""}">${escapeHtml(String(value))}</div>
      </div>`;
    }
  }

  // Parse and display extra JSON
  if (row.extra) {
    try {
      const extra = typeof row.extra === "string" ? JSON.parse(row.extra) : row.extra;
      for (const [k, v] of Object.entries(extra)) {
        const cls = k === "password" ? "password" : "";
        const displayVal = k === "password" && v && !v.startsWith("<")
          ? `<span class="password-masked" data-real="${escapeHtml(String(v))}">********</span> <span class="pwd-toggle" onclick="togglePwd(this)">show</span>`
          : escapeHtml(String(v));
        html += `<div class="detail-field">
          <div class="detail-field-label">${escapeHtml(k)}</div>
          <div class="detail-field-value ${cls}">${displayVal}</div>
        </div>`;
      }
    } catch {
      html += `<div class="detail-field">
        <div class="detail-field-label">Extra</div>
        <div class="detail-field-value">${escapeHtml(row.extra)}</div>
      </div>`;
    }
  }

  body.innerHTML = html;
  panel.classList.remove("hidden");
}

function closeDetail() {
  document.getElementById("detail-panel").classList.add("hidden");
}

window.togglePwd = function(el) {
  const span = el.previousElementSibling;
  if (span.textContent === "********") {
    span.textContent = span.dataset.real;
    el.textContent = "hide";
  } else {
    span.textContent = "********";
    el.textContent = "show";
  }
};

// ---- Utility functions ----
function escapeHtml(s) {
  const div = document.createElement("div");
  div.textContent = s;
  return div.innerHTML;
}

function byArtifact(type) {
  return state.artifacts.filter(r => r.artifact === type);
}

function severityClass(score) {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  if (score >= 20) return "low";
  return "clean";
}

function truncate(s, len = 80) {
  if (!s) return "";
  return s.length > len ? s.substring(0, len) + "..." : s;
}

function formatTime(ts) {
  if (!ts) return "";
  return ts.replace("T", " ").substring(0, 19);
}

function parseExtra(row) {
  if (!row.extra) return {};
  try {
    return typeof row.extra === "string" ? JSON.parse(row.extra) : row.extra;
  } catch { return {}; }
}

// ---- Pagination helper ----
function paginate(items, viewKey, page = 0) {
  const start = page * PAGE_SIZE;
  const end = start + PAGE_SIZE;
  const totalPages = Math.ceil(items.length / PAGE_SIZE);
  state.pages[viewKey] = page;

  let paginationHtml = "";
  if (totalPages > 1) {
    paginationHtml = `<div class="pagination">
      <button onclick="changePage('${viewKey}', ${page - 1})" ${page === 0 ? "disabled" : ""}>&lt; Prev</button>
      <span class="page-info">Page ${page + 1} of ${totalPages}</span>
      <button onclick="changePage('${viewKey}', ${page + 1})" ${page >= totalPages - 1 ? "disabled" : ""}>Next &gt;</button>
    </div>`;
  }

  return {
    items: items.slice(start, end),
    pagination: paginationHtml,
    total: items.length,
  };
}

window.changePage = function(viewKey, page) {
  state.pages[viewKey] = page;
  renderCurrentView();
};

// ================================================================
// VIEW RENDERERS
// ================================================================

// ---- Overview ----
function renderOverview(el) {
  const s = state.summary || {};
  const ioc = state.ioc || {};
  const analysis = state.analysis || {};
  const meta = s.metadata || state.manifest?.metadata || {};
  const types = s.artifact_types || {};
  const browsers = s.browsers || {};
  const privacy = analysis.privacy_exposure || {};
  const domainIntel = analysis.domain_intel || {};
  const credAnalysis = analysis.credential_analysis || {};

  const riskScore = s.risk_score || 0;
  const riskLevel = s.risk_level || "N/A";
  const circumference = 2 * Math.PI * 34;
  const offset = circumference - (riskScore / 100) * circumference;
  const riskColor = riskScore >= 80 ? "var(--red)" : riskScore >= 60 ? "var(--orange)" : riskScore >= 40 ? "var(--yellow)" : "var(--green)";

  let html = `
    <div class="section-title">Dashboard Overview</div>
    <div class="metrics-grid">
      <div class="metric">
        <div class="metric-value accent">${(s.total_artifacts || 0).toLocaleString()}</div>
        <div class="metric-label">Total Artifacts</div>
      </div>
      <div class="metric">
        <div class="metric-value purple">${Object.keys(browsers).length}</div>
        <div class="metric-label">Browsers</div>
      </div>
      <div class="metric">
        <div class="metric-value ${riskScore >= 60 ? 'red' : 'green'}">${s.total_iocs || 0}</div>
        <div class="metric-label">IOCs Detected</div>
      </div>
      <div class="metric">
        <div class="metric-value orange">${credAnalysis.total_credentials || 0}</div>
        <div class="metric-label">Credentials</div>
      </div>
      <div class="metric">
        <div class="metric-value">${domainIntel.unique_domains?.toLocaleString() || 0}</div>
        <div class="metric-label">Unique Domains</div>
      </div>
      <div class="metric">
        <div class="metric-value ${(s.privacy_score || 0) >= 50 ? 'orange' : 'green'}">${Math.round(s.privacy_score || 0)}</div>
        <div class="metric-label">Privacy Exposure</div>
      </div>
    </div>

    <div class="two-col">
      <div>
        <div class="risk-gauge">
          <div class="gauge-ring">
            <svg viewBox="0 0 80 80">
              <circle class="track" cx="40" cy="40" r="34"/>
              <circle class="fill" cx="40" cy="40" r="34"
                stroke="${riskColor}"
                stroke-dasharray="${circumference}"
                stroke-dashoffset="${offset}"/>
            </svg>
            <div class="gauge-center" style="color:${riskColor}">${riskScore}</div>
          </div>
          <div class="gauge-info">
            <h3>Threat Level: ${riskLevel}</h3>
            <p>${ioc.total_iocs || 0} indicators found across ${ioc.urls_scanned || 0} URLs</p>
          </div>
        </div>

        <div class="card">
          <div class="card-header">Artifacts by Type</div>
          <div class="bar-chart">
            ${Object.entries(types).sort((a,b) => b[1]-a[1]).map(([type, count]) => {
              const max = Math.max(...Object.values(types));
              const pct = (count / max * 100).toFixed(1);
              return `<div class="bar-row">
                <span class="bar-label">${type}</span>
                <div class="bar-track"><div class="bar-fill accent" style="width:${pct}%"></div></div>
                <span class="bar-value">${count.toLocaleString()}</span>
              </div>`;
            }).join("")}
          </div>
        </div>
      </div>

      <div>
        <div class="card">
          <div class="card-header">System Information</div>
          <table class="data-table">
            <tr><td class="dim">Hostname</td><td class="mono">${escapeHtml(meta.hostname || "")}</td></tr>
            <tr><td class="dim">Username</td><td class="mono">${escapeHtml(meta.username || "")}</td></tr>
            <tr><td class="dim">OS</td><td class="mono">${escapeHtml(meta.os || "")}</td></tr>
            <tr><td class="dim">Acquired</td><td class="mono">${escapeHtml(meta.acquired_utc || "")}</td></tr>
            <tr><td class="dim">Browsers</td><td class="mono">${Object.keys(browsers).join(", ")}</td></tr>
          </table>
        </div>

        ${privacy.category_scores ? `<div class="card">
          <div class="card-header">Privacy Exposure</div>
          ${Object.entries(privacy.category_scores).sort((a,b) => b[1]-a[1]).map(([cat, score]) => {
            const color = score >= 70 ? "var(--red)" : score >= 40 ? "var(--orange)" : "var(--green)";
            return `<div class="exposure-bar">
              <span class="exposure-label">${cat.replace(/_/g, " ")}</span>
              <div class="exposure-track"><div class="exposure-fill" style="width:${score}%;background:${color}"></div></div>
              <span class="exposure-score" style="color:${color}">${score}</span>
            </div>`;
          }).join("")}
        </div>` : ""}

        <div class="card">
          <div class="card-header">Browsers Detected</div>
          <div class="bar-chart">
            ${Object.entries(browsers).sort((a,b) => b[1]-a[1]).map(([browser, count]) => {
              const max = Math.max(...Object.values(browsers));
              const pct = (count / max * 100).toFixed(1);
              return `<div class="bar-row">
                <span class="bar-label">${browser}</span>
                <div class="bar-track"><div class="bar-fill purple" style="width:${pct}%"></div></div>
                <span class="bar-value">${count.toLocaleString()}</span>
              </div>`;
            }).join("")}
          </div>
        </div>
      </div>
    </div>
  `;

  html += `<div class="card" style="display:flex;gap:8px;flex-wrap:wrap;padding:12px">
    <button onclick="exportData('json')" class="btn">Export JSON</button>
    <button onclick="exportData('csv')" class="btn">Export CSV</button>
    <button onclick="window.print()" class="btn">Print Report</button>
  </div>`;

  el.innerHTML = html;
}

// ---- Timeline ----
function renderTimeline(el) {
  const timed = state.artifacts
    .filter(r => r.visit_time_utc)
    .sort((a, b) => (b.visit_time_utc || "").localeCompare(a.visit_time_utc || ""));

  const page = state.pages["timeline"] || 0;
  const { items, pagination, total } = paginate(timed, "timeline", page);

  let html = `<div class="section-title">Timeline <span class="count">${total.toLocaleString()} events</span></div>`;

  // Activity by hour chart
  const hourCounts = new Array(24).fill(0);
  timed.forEach(r => {
    try { hourCounts[new Date(r.visit_time_utc).getUTCHours()]++; } catch(e) {}
  });
  const maxHour = Math.max(...hourCounts, 1);
  html += `<div class="card"><h3>Activity by Hour (UTC)</h3>`;
  for (let h = 0; h < 24; h++) {
    const pct = (hourCounts[h] / maxHour) * 100;
    html += `<div style="display:flex;align-items:center;gap:6px;margin:2px 0">
      <span class="mono dim" style="min-width:30px">${String(h).padStart(2,'0')}:00</span>
      <div style="flex:1;background:var(--bg-tertiary);height:14px;border-radius:2px">
        <div style="width:${pct}%;background:var(--blue);height:100%;border-radius:2px"></div>
      </div>
      <span class="dim" style="min-width:50px;text-align:right">${hourCounts[h].toLocaleString()}</span>
    </div>`;
  }
  html += `</div>`;

  // Activity by day chart
  const dayCounts = {};
  timed.forEach(r => {
    try { const d = r.visit_time_utc.substring(0, 10); dayCounts[d] = (dayCounts[d] || 0) + 1; } catch(e) {}
  });
  const days = Object.keys(dayCounts).sort();
  if (days.length > 1) {
    const maxDay = Math.max(...Object.values(dayCounts), 1);
    html += `<div class="card"><h3>Activity by Day</h3>`;
    for (const d of days.slice(-60)) {  // Last 60 days
      const pct = (dayCounts[d] / maxDay) * 100;
      html += `<div style="display:flex;align-items:center;gap:6px;margin:1px 0">
        <span class="mono dim" style="min-width:80px">${d}</span>
        <div style="flex:1;background:var(--bg-tertiary);height:12px;border-radius:2px">
          <div style="width:${pct}%;background:var(--cyan);height:100%;border-radius:2px"></div>
        </div>
        <span class="dim" style="min-width:50px;text-align:right">${dayCounts[d].toLocaleString()}</span>
      </div>`;
    }
    html += `</div>`;
  }

  html += `<div class="timeline-container">`;
  for (const row of items) {
    const typeClass = row.artifact || "";
    html += `<div class="timeline-entry" onclick='openDetail(${JSON.stringify(row).replace(/'/g, "&#39;")})'>
      <span class="timeline-time">${formatTime(row.visit_time_utc)}</span>
      <span class="timeline-type ${typeClass}">${row.artifact}</span>
      <div class="timeline-content">
        <div class="timeline-url">${escapeHtml(truncate(row.url, 120))}</div>
        <div class="timeline-title">${escapeHtml(truncate(row.title, 80))}</div>
      </div>
    </div>`;
  }
  html += `</div>${pagination}`;
  el.innerHTML = html;
}

// ---- Credentials ----
function renderCredentials(el) {
  const creds = byArtifact("credential");
  const page = state.pages["credentials"] || 0;
  const { items, pagination, total } = paginate(creds, "credentials", page);
  const credAnalysis = state.analysis?.credential_analysis || {};

  let html = `<div class="section-title">Saved Credentials <span class="count">${total} found</span></div>`;

  if (credAnalysis.reuse_risk) {
    html += `<div class="card" style="border-color:var(--red)">
      <div class="card-header" style="color:var(--red)">Password Reuse Detected</div>
      <p style="color:var(--text);margin-bottom:8px">The following usernames are reused across multiple domains:</p>
      ${Object.entries(credAnalysis.reused_usernames || {}).map(([user, domains]) =>
        `<div style="margin-bottom:4px"><span class="mono" style="color:var(--orange)">${escapeHtml(user)}</span>
         <span class="dim"> used on: ${domains.map(d => escapeHtml(d)).join(", ")}</span></div>`
      ).join("")}
    </div>`;
  }

  html += `<div class="card"><table class="data-table">
    <thead><tr>
      <th>Browser</th><th>URL</th><th>Username</th><th>Password</th><th>Last Used</th><th>Count</th>
    </tr></thead><tbody>`;

  for (const row of items) {
    const extra = parseExtra(row);
    const pwd = extra.password || "";
    const pwdDisplay = pwd && !pwd.startsWith("<")
      ? `<span class="password-masked" data-real="${escapeHtml(pwd)}">********</span> <span class="pwd-toggle" onclick="togglePwd(this)">show</span>`
      : `<span class="dim">${escapeHtml(pwd)}</span>`;

    html += `<tr class="clickable" onclick='openDetail(${JSON.stringify(row).replace(/'/g, "&#39;")})'>
      <td class="mono">${row.browser}</td>
      <td class="url">${escapeHtml(truncate(row.url, 50))}</td>
      <td class="mono">${escapeHtml(row.title)}</td>
      <td>${pwdDisplay}</td>
      <td class="dim">${formatTime(row.visit_time_utc)}</td>
      <td class="mono">${row.visit_count || ""}</td>
    </tr>`;
  }

  html += `</tbody></table></div>${pagination}`;
  el.innerHTML = html;
}

// ---- Cookies ----
function renderCookies(el) {
  const cookies = byArtifact("cookie");
  const page = state.pages["cookies"] || 0;
  const { items, pagination, total } = paginate(cookies, "cookies", page);

  let html = `<div class="section-title">Cookies <span class="count">${total.toLocaleString()}</span></div>`;
  html += `<div class="card"><table class="data-table">
    <thead><tr>
      <th>Host</th><th>Name</th><th>Value</th><th>Class</th><th>Secure</th><th>HttpOnly</th><th>Last Access</th>
    </tr></thead><tbody>`;

  for (const row of items) {
    const extra = parseExtra(row);
    const cls = extra.classification || "";
    const clsClass = cls === "tracking" ? "sev medium" : cls === "session/auth" ? "sev high" : "";
    html += `<tr class="clickable" onclick='openDetail(${JSON.stringify(row).replace(/'/g, "&#39;")})'>
      <td class="url">${escapeHtml(truncate(row.url, 40))}</td>
      <td class="mono">${escapeHtml(truncate(row.title, 30))}</td>
      <td class="dim">${escapeHtml(truncate(extra.value || "", 40))}</td>
      <td><span class="${clsClass}">${cls}</span></td>
      <td class="mono">${extra.secure ? "Y" : ""}</td>
      <td class="mono">${extra.httponly ? "Y" : ""}</td>
      <td class="dim">${formatTime(row.visit_time_utc)}</td>
    </tr>`;
  }

  html += `</tbody></table></div>${pagination}`;
  el.innerHTML = html;
}

// ---- History ----
function renderHistory(el) {
  const hist = byArtifact("history").sort((a, b) =>
    (b.visit_time_utc || "").localeCompare(a.visit_time_utc || ""));
  renderFilteredTable(el, hist, "Browsing History", ["browser", "url", "title", "visit_count", "visit_time_utc"]);
}

function renderFilteredTable(el, rows, title, columns) {
  const page = state.pages[title] || 0;
  const { items, pagination, total } = paginate(rows, title, page);

  let html = `<div class="section-title">${escapeHtml(title)} <span class="count">${total.toLocaleString()}</span></div>`;
  html += `<div class="card"><table class="data-table">
    <thead><tr>${columns.map(c => `<th>${c}</th>`).join("")}</tr></thead><tbody>`;

  for (const row of items) {
    html += `<tr class="clickable" onclick='openDetail(${JSON.stringify(row).replace(/'/g, "&#39;")})'>`;
    for (const col of columns) {
      let val = row[col];
      let cls = "";
      if (col === "url") cls = "url";
      else if (col === "visit_time_utc") { cls = "dim"; val = formatTime(val); }
      else if (col === "visit_count") cls = "mono";
      else if (col === "browser") cls = "mono";
      html += `<td class="${cls}">${escapeHtml(truncate(String(val || ""), 80))}</td>`;
    }
    html += `</tr>`;
  }

  html += `</tbody></table></div>${pagination}`;
  el.innerHTML = html;
}

// ---- Downloads ----
function renderDownloads(el) {
  const dls = byArtifact("download").sort((a, b) =>
    (b.visit_time_utc || "").localeCompare(a.visit_time_utc || ""));
  const page = state.pages["downloads"] || 0;
  const { items, pagination, total } = paginate(dls, "downloads", page);
  const dlAnalysis = state.analysis?.download_analysis || {};

  let html = `<div class="section-title">Downloads <span class="count">${total.toLocaleString()}</span></div>`;

  if (dlAnalysis.high_risk_count > 0) {
    html += `<div class="card" style="border-color:var(--orange)">
      <div class="card-header" style="color:var(--orange)">Risky Downloads: ${dlAnalysis.high_risk_count}</div>
      <table class="data-table"><thead><tr><th>File</th><th>Ext</th><th>Risk</th><th>Source</th></tr></thead><tbody>`;
    for (const d of (dlAnalysis.risky_downloads || []).slice(0, 15)) {
      html += `<tr>
        <td class="mono">${escapeHtml(truncate(d.file, 50))}</td>
        <td><span class="sev ${severityClass(d.risk_score)}">${d.extension}</span></td>
        <td class="mono">${d.risk_score}</td>
        <td class="url">${escapeHtml(truncate(d.source, 60))}</td>
      </tr>`;
    }
    html += `</tbody></table></div>`;
  }

  html += `<div class="card"><table class="data-table">
    <thead><tr><th>Browser</th><th>Source URL</th><th>Target Path</th><th>Time</th></tr></thead><tbody>`;
  for (const row of items) {
    html += `<tr class="clickable" onclick='openDetail(${JSON.stringify(row).replace(/'/g, "&#39;")})'>
      <td class="mono">${row.browser}</td>
      <td class="url">${escapeHtml(truncate(row.url, 60))}</td>
      <td class="mono">${escapeHtml(truncate(row.title, 50))}</td>
      <td class="dim">${formatTime(row.visit_time_utc)}</td>
    </tr>`;
  }
  html += `</tbody></table></div>${pagination}`;
  el.innerHTML = html;
}

// ---- IOC / Threats ----
function renderIOC(el) {
  const ioc = state.ioc;
  if (!ioc) {
    el.innerHTML = `<div class="empty-state"><div class="icon">[!]</div>
      <p>No IOC scan data. Run with --ioc-scan flag.</p></div>`;
    return;
  }

  const riskScore = ioc.overall_risk_score || 0;
  const riskLevel = ioc.overall_risk_level || "N/A";
  const circumference = 2 * Math.PI * 34;
  const offset = circumference - (riskScore / 100) * circumference;
  const riskColor = riskScore >= 80 ? "var(--red)" : riskScore >= 60 ? "var(--orange)" : riskScore >= 40 ? "var(--yellow)" : "var(--green)";

  let html = `<div class="section-title">Threat Intelligence <span class="count">${ioc.total_iocs || 0} IOCs</span></div>`;

  html += `<div class="risk-gauge">
    <div class="gauge-ring">
      <svg viewBox="0 0 80 80">
        <circle class="track" cx="40" cy="40" r="34"/>
        <circle class="fill" cx="40" cy="40" r="34" stroke="${riskColor}"
          stroke-dasharray="${circumference}" stroke-dashoffset="${offset}"/>
      </svg>
      <div class="gauge-center" style="color:${riskColor}">${riskScore}</div>
    </div>
    <div class="gauge-info">
      <h3>Overall Risk: ${riskLevel}</h3>
      <p>${ioc.urls_scanned?.toLocaleString() || 0} URLs scanned</p>
    </div>
  </div>`;

  // Critical findings
  const critical = ioc.critical_findings || [];
  if (critical.length > 0) {
    html += `<div class="card" style="border-color:var(--red)">
      <div class="card-header" style="color:var(--red)">Critical Findings (${critical.length})</div>
      <table class="data-table"><thead><tr><th>Type</th><th>Severity</th><th>URL</th><th>Detail</th></tr></thead><tbody>`;
    for (const f of critical.slice(0, 30)) {
      html += `<tr>
        <td><span class="sev critical">${escapeHtml(f.type)}</span></td>
        <td class="mono">${f.severity}</td>
        <td class="url">${escapeHtml(truncate(f.url || "", 60))}</td>
        <td class="dim">${escapeHtml(truncate(f.detail || "", 50))}</td>
      </tr>`;
    }
    html += `</tbody></table></div>`;
  }

  // High findings
  const high = ioc.high_findings || [];
  if (high.length > 0) {
    html += `<div class="card" style="border-color:var(--orange)">
      <div class="card-header" style="color:var(--orange)">High Severity (${high.length})</div>
      <table class="data-table"><thead><tr><th>Type</th><th>Severity</th><th>URL</th></tr></thead><tbody>`;
    for (const f of high.slice(0, 20)) {
      html += `<tr>
        <td><span class="sev high">${escapeHtml(f.type)}</span></td>
        <td class="mono">${f.severity}</td>
        <td class="url">${escapeHtml(truncate(f.url || "", 80))}</td>
      </tr>`;
    }
    html += `</tbody></table></div>`;
  }

  // Medium findings
  const medium = ioc.medium_findings || [];
  if (medium.length > 0) {
    html += `<div class="card">
      <div class="card-header">Medium Severity (${medium.length})</div>
      <table class="data-table"><thead><tr><th>Type</th><th>Severity</th><th>URL</th></tr></thead><tbody>`;
    for (const f of medium.slice(0, 20)) {
      html += `<tr>
        <td><span class="sev medium">${escapeHtml(f.type)}</span></td>
        <td class="mono">${f.severity}</td>
        <td class="url">${escapeHtml(truncate(f.url || "", 80))}</td>
      </tr>`;
    }
    html += `</tbody></table></div>`;
  }

  // Time anomalies
  const anomalies = ioc.time_anomalies || [];
  if (anomalies.length > 0) {
    html += `<div class="card">
      <div class="card-header">Behavioral Anomalies</div>`;
    for (const a of anomalies) {
      html += `<div style="margin-bottom:8px">
        <span class="sev ${severityClass(a.severity)}">${a.type}</span>
        <span class="dim" style="margin-left:8px">${escapeHtml(a.detail || "")}</span>
      </div>`;
    }
    html += `</div>`;
  }

  // Exfiltration
  const exfil = ioc.exfiltration_indicators || [];
  if (exfil.length > 0) {
    html += `<div class="card" style="border-color:var(--red)">
      <div class="card-header" style="color:var(--red)">Data Exfiltration Indicators</div>`;
    for (const e of exfil) {
      html += `<div style="margin-bottom:6px">
        <span class="sev ${severityClass(e.severity)}">${e.severity}</span>
        <span style="margin-left:8px">${escapeHtml(e.detail || "")}</span>
      </div>`;
    }
    html += `</div>`;
  }

  el.innerHTML = html;
}

// ---- Extensions ----
function renderExtensions(el) {
  const exts = byArtifact("extension");
  const page = state.pages["extensions"] || 0;
  const { items, pagination, total } = paginate(exts, "extensions", page);

  let html = `<div class="section-title">Browser Extensions <span class="count">${total}</span></div>`;
  html += `<div class="card"><table class="data-table">
    <thead><tr><th>Browser</th><th>Name</th><th>Version</th><th>Threat</th><th>Risk</th><th>Flagged</th></tr></thead><tbody>`;

  for (const row of items) {
    const extra = parseExtra(row);
    const threat = extra.threat_score || 0;
    const risk = extra.risk_level || "";
    const flagged = (extra.flagged_permissions || []).join(", ");

    html += `<tr class="clickable" onclick='openDetail(${JSON.stringify(row).replace(/'/g, "&#39;")})'>
      <td class="mono">${row.browser}</td>
      <td>${escapeHtml(truncate(row.title, 40))}</td>
      <td class="mono dim">${escapeHtml(extra.version || "")}</td>
      <td class="mono">${threat}</td>
      <td><span class="sev ${severityClass(threat)}">${risk}</span></td>
      <td class="dim" style="max-width:300px">${escapeHtml(truncate(flagged, 60))}</td>
    </tr>`;
  }

  html += `</tbody></table></div>${pagination}`;
  el.innerHTML = html;
}

// ---- Network ----
function renderNetwork(el) {
  const wifi = byArtifact("wifi_profile");
  const dns = byArtifact("dns_cache");
  const arp = byArtifact("arp_entry");
  const ifaces = byArtifact("network_interface");

  let html = `<div class="section-title">Network Reconnaissance</div>`;

  if (wifi.length === 0 && dns.length === 0 && arp.length === 0) {
    html += `<div class="empty-state"><div class="icon">[@]</div>
      <p>No network data. Run with --network flag.</p></div>`;
    el.innerHTML = html;
    return;
  }

  // WiFi profiles
  if (wifi.length > 0) {
    html += `<div class="card">
      <div class="card-header">WiFi Profiles (${wifi.length})</div>
      <table class="data-table"><thead><tr><th>SSID</th><th>Password</th><th>Auth</th></tr></thead><tbody>`;
    for (const row of wifi) {
      const extra = parseExtra(row);
      const pwd = extra.password || "";
      const pwdDisplay = pwd && pwd !== "<keychain_protected>"
        ? `<span class="password-masked" data-real="${escapeHtml(pwd)}">********</span> <span class="pwd-toggle" onclick="togglePwd(this)">show</span>`
        : `<span class="dim">${escapeHtml(pwd)}</span>`;
      html += `<tr>
        <td class="mono">${escapeHtml(row.title)}</td>
        <td>${pwdDisplay}</td>
        <td class="dim">${escapeHtml(extra.authentication || "")}</td>
      </tr>`;
    }
    html += `</tbody></table></div>`;
  }

  // Network interfaces
  if (ifaces.length > 0) {
    html += `<div class="card">
      <div class="card-header">Network Interfaces (${ifaces.length})</div>
      <table class="data-table"><thead><tr><th>Adapter</th><th>Address</th><th>Type</th></tr></thead><tbody>`;
    for (const row of ifaces) {
      const extra = parseExtra(row);
      html += `<tr>
        <td>${escapeHtml(row.title)}</td>
        <td class="mono">${escapeHtml(row.url)}</td>
        <td class="dim">${escapeHtml(extra.type || "")}</td>
      </tr>`;
    }
    html += `</tbody></table></div>`;
  }

  // DNS cache
  if (dns.length > 0) {
    const dnsPage = state.pages["dns"] || 0;
    const dnsP = paginate(dns, "dns", dnsPage);
    html += `<div class="card">
      <div class="card-header">DNS Cache (${dns.length})</div>
      <table class="data-table"><thead><tr><th>Domain</th><th>IP</th></tr></thead><tbody>`;
    for (const row of dnsP.items) {
      html += `<tr><td class="url">${escapeHtml(row.url)}</td><td class="mono">${escapeHtml(row.title)}</td></tr>`;
    }
    html += `</tbody></table>${dnsP.pagination}</div>`;
  }

  // ARP table
  if (arp.length > 0) {
    html += `<div class="card">
      <div class="card-header">ARP Table (${arp.length})</div>
      <table class="data-table"><thead><tr><th>IP</th><th>MAC</th><th>Type</th></tr></thead><tbody>`;
    for (const row of arp) {
      const extra = parseExtra(row);
      html += `<tr>
        <td class="mono">${escapeHtml(row.url)}</td>
        <td class="mono">${escapeHtml(row.title)}</td>
        <td class="dim">${escapeHtml(extra.type || "")}</td>
      </tr>`;
    }
    html += `</tbody></table></div>`;
  }

  el.innerHTML = html;
}

// ---- Sessions ----
function renderSessions(el) {
  const sess = byArtifact("session");
  const page = state.pages["sessions"] || 0;
  const { items, pagination, total } = paginate(sess, "sessions", page);
  const sessAnalysis = state.analysis?.session_reconstruction || {};

  let html = `<div class="section-title">Sessions <span class="count">${total.toLocaleString()}</span></div>`;

  if (sessAnalysis.total_sessions) {
    html += `<div class="metrics-grid">
      <div class="metric"><div class="metric-value accent">${sessAnalysis.total_sessions}</div><div class="metric-label">Sessions</div></div>
      <div class="metric"><div class="metric-value">${sessAnalysis.avg_duration_minutes}</div><div class="metric-label">Avg Duration (min)</div></div>
      <div class="metric"><div class="metric-value">${sessAnalysis.avg_pages_per_session}</div><div class="metric-label">Avg Pages/Session</div></div>
      <div class="metric"><div class="metric-value orange">${sessAnalysis.longest_session_minutes}</div><div class="metric-label">Longest (min)</div></div>
    </div>`;
  }

  html += `<div class="card"><table class="data-table">
    <thead><tr><th>Browser</th><th>URL</th><th>Title</th><th>Source</th></tr></thead><tbody>`;
  for (const row of items) {
    const extra = parseExtra(row);
    html += `<tr class="clickable" onclick='openDetail(${JSON.stringify(row).replace(/'/g, "&#39;")})'>
      <td class="mono">${row.browser}</td>
      <td class="url">${escapeHtml(truncate(row.url, 70))}</td>
      <td>${escapeHtml(truncate(row.title, 40))}</td>
      <td class="dim">${escapeHtml(extra.source_file || extra.source || extra.method || "")}</td>
    </tr>`;
  }
  html += `</tbody></table></div>${pagination}`;
  el.innerHTML = html;
}

// ---- Autofill ----
function renderAutofill(el) {
  const autofill = byArtifact("autofill");
  const cards = byArtifact("credit_card");
  const addresses = byArtifact("address");

  let html = `<div class="section-title">Autofill Data</div>`;

  if (autofill.length === 0 && cards.length === 0 && addresses.length === 0) {
    html += `<div class="empty-state"><div class="icon">[%]</div>
      <p>No autofill data. Run with --autofill flag.</p></div>`;
    el.innerHTML = html;
    return;
  }

  // Credit cards
  if (cards.length > 0) {
    html += `<div class="card" style="border-color:var(--red)">
      <div class="card-header" style="color:var(--red)">Credit Cards (${cards.length})</div>
      <table class="data-table"><thead><tr><th>Name</th><th>Number</th><th>Expires</th><th>Uses</th></tr></thead><tbody>`;
    for (const row of cards) {
      const extra = parseExtra(row);
      html += `<tr>
        <td class="mono">${escapeHtml(row.title)}</td>
        <td class="password">${escapeHtml(extra.card_number || "")}</td>
        <td class="dim">${escapeHtml(extra.expiration || "")}</td>
        <td class="mono">${row.visit_count || ""}</td>
      </tr>`;
    }
    html += `</tbody></table></div>`;
  }

  // Addresses
  if (addresses.length > 0) {
    html += `<div class="card">
      <div class="card-header">Saved Addresses (${addresses.length})</div>
      <table class="data-table"><thead><tr><th>Name</th><th>Address</th></tr></thead><tbody>`;
    for (const row of addresses) {
      const extra = parseExtra(row);
      html += `<tr>
        <td class="mono">${escapeHtml(row.title)}</td>
        <td>${escapeHtml(extra.address || "")}</td>
      </tr>`;
    }
    html += `</tbody></table></div>`;
  }

  // Autofill entries
  if (autofill.length > 0) {
    const afPage = state.pages["autofill"] || 0;
    const afP = paginate(autofill, "autofill", afPage);
    html += `<div class="card">
      <div class="card-header">Form Autofill (${autofill.length})</div>
      <table class="data-table"><thead><tr><th>Browser</th><th>Field</th><th>Count</th><th>Last Used</th></tr></thead><tbody>`;
    for (const row of afP.items) {
      html += `<tr class="clickable" onclick='openDetail(${JSON.stringify(row).replace(/'/g, "&#39;")})'>
        <td class="mono">${row.browser}</td>
        <td class="mono">${escapeHtml(truncate(row.title, 60))}</td>
        <td class="mono">${row.visit_count || ""}</td>
        <td class="dim">${formatTime(row.visit_time_utc)}</td>
      </tr>`;
    }
    html += `</tbody></table>${afP.pagination}</div>`;
  }

  el.innerHTML = html;
}

// ---- Storage ----
function renderStorage(el) {
  const ls = byArtifact("localstorage");
  const idb = byArtifact("indexeddb");

  let html = `<div class="section-title">Web Storage</div>`;

  if (ls.length === 0 && idb.length === 0) {
    html += `<div class="empty-state"><div class="icon">[&]</div>
      <p>No storage data. Run with --localstorage flag.</p></div>`;
    el.innerHTML = html;
    return;
  }

  if (idb.length > 0) {
    html += `<div class="card">
      <div class="card-header">IndexedDB Databases (${idb.length})</div>
      <table class="data-table"><thead><tr><th>Origin</th><th>Database</th><th>Size</th></tr></thead><tbody>`;
    for (const row of idb) {
      const extra = parseExtra(row);
      const size = extra.size_bytes ? `${(extra.size_bytes / 1024).toFixed(1)} KB` : "";
      html += `<tr>
        <td class="url">${escapeHtml(truncate(row.url, 50))}</td>
        <td class="mono">${escapeHtml(truncate(row.title, 40))}</td>
        <td class="dim">${size}</td>
      </tr>`;
    }
    html += `</tbody></table></div>`;
  }

  if (ls.length > 0) {
    const lsPage = state.pages["storage"] || 0;
    const lsP = paginate(ls, "storage", lsPage);
    html += `<div class="card">
      <div class="card-header">LocalStorage (${ls.length})</div>
      <table class="data-table"><thead><tr><th>Origin</th><th>Key</th><th>Value</th></tr></thead><tbody>`;
    for (const row of lsP.items) {
      const extra = parseExtra(row);
      html += `<tr class="clickable" onclick='openDetail(${JSON.stringify(row).replace(/'/g, "&#39;")})'>
        <td class="url">${escapeHtml(truncate(row.url, 40))}</td>
        <td class="mono">${escapeHtml(truncate(row.title, 30))}</td>
        <td class="dim">${escapeHtml(truncate(extra.value || "", 50))}</td>
      </tr>`;
    }
    html += `</tbody></table>${lsP.pagination}</div>`;
  }

  el.innerHTML = html;
}

// ---- Anti-Forensics ----
function renderAntiForensics(el) {
  const af = byArtifact("anti_forensics");

  let html = `<div class="section-title">Anti-Forensics Detection <span class="count">${af.length} findings</span></div>`;

  if (af.length === 0) {
    html += `<div class="empty-state"><div class="icon">[?]</div>
      <p>No anti-forensics data. Run with --anti-forensics flag.</p></div>`;
    el.innerHTML = html;
    return;
  }

  for (const row of af) {
    const extra = parseExtra(row);
    const severity = extra.severity || 0;
    const sevClass = severityClass(severity);

    html += `<div class="card" style="border-left:3px solid var(--${severity >= 70 ? 'red' : severity >= 40 ? 'orange' : 'yellow'})">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
        <span class="mono" style="font-size:13px;font-weight:600">${escapeHtml(row.title)}</span>
        <span class="sev ${sevClass}">Severity: ${severity}</span>
      </div>
      <p style="margin-bottom:6px">${escapeHtml(extra.detail || "")}</p>
      <div class="dim" style="font-size:11px">
        <span>Browser: ${row.browser}</span>
        ${row.visit_time_utc ? `<span style="margin-left:12px">Time: ${formatTime(row.visit_time_utc)}</span>` : ""}
        ${extra.type ? `<span style="margin-left:12px">Type: ${extra.type}</span>` : ""}
      </div>
    </div>`;
  }

  el.innerHTML = html;
}

// ---- Searches ----
function renderSearches(el) {
  const searches = byArtifact("search").sort((a, b) =>
    (b.visit_time_utc || "").localeCompare(a.visit_time_utc || ""));
  const page = state.pages["searches"] || 0;
  const { items, pagination, total } = paginate(searches, "searches", page);

  let html = `<div class="section-title">Search History <span class="count">${total.toLocaleString()}</span></div>`;
  html += `<div class="card"><table class="data-table">
    <thead><tr><th>Browser</th><th>Search Term</th><th>Engine</th><th>URL</th><th>Count</th><th>Time</th></tr></thead><tbody>`;

  for (const row of items) {
    const extra = parseExtra(row);
    html += `<tr class="clickable" onclick='openDetail(${JSON.stringify(row).replace(/'/g, "&#39;")})'>
      <td class="mono">${row.browser}</td>
      <td style="font-weight:500">${escapeHtml(truncate(row.title, 50))}</td>
      <td class="dim">${escapeHtml(extra.search_engine || extra.field_name || "")}</td>
      <td class="url">${escapeHtml(truncate(row.url, 50))}</td>
      <td class="mono">${row.visit_count || ""}</td>
      <td class="dim">${formatTime(row.visit_time_utc)}</td>
    </tr>`;
  }

  html += `</tbody></table></div>${pagination}`;
  el.innerHTML = html;
}

// ---- Recovered (WAL/Deleted) ----
function renderRecovered(el) {
  const recovered = byArtifact("recovered_url");
  const page = state.pages["recovered"] || 0;
  const { items, pagination, total } = paginate(recovered, "recovered", page);

  let html = `<div class="section-title">Recovered / Deleted Records <span class="count">${total.toLocaleString()}</span></div>`;

  if (recovered.length === 0) {
    html += `<div class="empty-state"><div class="icon">[^]</div>
      <p>No recovered records. Run with <span class="mono">--recover</span> flag to scan WAL files, freelists, and unallocated pages.</p></div>`;
    el.innerHTML = html;
    return;
  }

  html += `<div class="card"><table class="data-table">
    <thead><tr><th>Browser</th><th>URL</th><th>Source</th><th>Method</th></tr></thead><tbody>`;

  for (const row of items) {
    const extra = parseExtra(row);
    html += `<tr class="clickable" onclick='openDetail(${JSON.stringify(row).replace(/'/g, "&#39;")})'>
      <td class="mono">${row.browser}</td>
      <td class="url">${escapeHtml(truncate(row.url, 70))}</td>
      <td class="dim">${escapeHtml(extra.source || "")}</td>
      <td class="dim">${escapeHtml(extra.method || extra.recovery_method || "")}</td>
    </tr>`;
  }

  html += `</tbody></table></div>${pagination}`;
  el.innerHTML = html;
}

// ---- Favicons (Ghost Visits) ----
function renderFavicons(el) {
  const favicons = byArtifact("favicon");
  const ghosts = favicons.filter(r => {
    const extra = parseExtra(r);
    return extra.ghost_visit || extra.is_ghost;
  });

  let html = `<div class="section-title">Favicon Forensics <span class="count">${favicons.length.toLocaleString()}</span></div>`;

  if (favicons.length === 0) {
    html += `<div class="empty-state"><div class="icon">[i]</div>
      <p>No favicon data. Run with <span class="mono">--favicons</span> flag to extract favicons and detect ghost visits.</p></div>`;
    el.innerHTML = html;
    return;
  }

  if (ghosts.length > 0) {
    html += `<div class="card" style="border-left:3px solid var(--red)">
      <div class="card-header" style="color:var(--red)">Ghost Visits Detected: ${ghosts.length}</div>
      <p class="dim" style="margin:6px 0">Sites visited after history was cleared — favicon still exists but no matching history entry.</p>
      <table class="data-table"><thead><tr><th>URL</th><th>Icon URL</th><th>Browser</th></tr></thead><tbody>`;
    for (const row of ghosts.slice(0, 50)) {
      const extra = parseExtra(row);
      html += `<tr>
        <td class="url">${escapeHtml(truncate(row.url, 60))}</td>
        <td class="dim">${escapeHtml(truncate(extra.icon_url || row.title || "", 40))}</td>
        <td class="mono">${row.browser}</td>
      </tr>`;
    }
    html += `</tbody></table></div>`;
  }

  const page = state.pages["favicons"] || 0;
  const fp = paginate(favicons, "favicons", page);
  html += `<div class="card">
    <div class="card-header">All Favicons (${favicons.length})</div>
    <table class="data-table"><thead><tr><th>Browser</th><th>Page URL</th><th>Icon URL</th><th>Ghost?</th></tr></thead><tbody>`;
  for (const row of fp.items) {
    const extra = parseExtra(row);
    const isGhost = extra.ghost_visit || extra.is_ghost;
    html += `<tr class="clickable" onclick='openDetail(${JSON.stringify(row).replace(/'/g, "&#39;")})'>
      <td class="mono">${row.browser}</td>
      <td class="url">${escapeHtml(truncate(row.url, 50))}</td>
      <td class="dim">${escapeHtml(truncate(extra.icon_url || row.title || "", 40))}</td>
      <td>${isGhost ? '<span class="sev sev-high">GHOST</span>' : ""}</td>
    </tr>`;
  }
  html += `</tbody></table>${fp.pagination}</div>`;
  el.innerHTML = html;
}

// ---- Cache ----
function renderCache(el) {
  const cache = byArtifact("cache_entry");
  const page = state.pages["cache"] || 0;
  const { items, pagination, total } = paginate(cache, "cache", page);

  let html = `<div class="section-title">Browser Cache <span class="count">${total.toLocaleString()}</span></div>`;

  if (cache.length === 0) {
    html += `<div class="empty-state"><div class="icon">[c]</div>
      <p>No cache data. Run with <span class="mono">--cache</span> flag to parse Chromium Simple Cache and Firefox cache2.</p></div>`;
    el.innerHTML = html;
    return;
  }

  const types = {};
  for (const row of cache) {
    const extra = parseExtra(row);
    const ct = extra.content_type || extra.mime || "unknown";
    const base = ct.split("/")[0] || "other";
    types[base] = (types[base] || 0) + 1;
  }
  html += `<div class="metrics-grid">
    <div class="metric"><div class="metric-value accent">${total.toLocaleString()}</div><div class="metric-label">Cached Entries</div></div>
    ${Object.entries(types).sort((a,b) => b[1]-a[1]).slice(0, 5).map(([t, c]) =>
      `<div class="metric"><div class="metric-value">${c.toLocaleString()}</div><div class="metric-label">${t}</div></div>`
    ).join("")}
  </div>`;

  html += `<div class="card"><table class="data-table">
    <thead><tr><th>Browser</th><th>URL</th><th>Content-Type</th><th>Size</th><th>Status</th></tr></thead><tbody>`;
  for (const row of items) {
    const extra = parseExtra(row);
    const size = extra.size || extra.content_length;
    const sizeStr = size ? (size > 1024*1024 ? `${(size/1024/1024).toFixed(1)} MB` : size > 1024 ? `${(size/1024).toFixed(1)} KB` : `${size} B`) : "";
    html += `<tr class="clickable" onclick='openDetail(${JSON.stringify(row).replace(/'/g, "&#39;")})'>
      <td class="mono">${row.browser}</td>
      <td class="url">${escapeHtml(truncate(row.url, 60))}</td>
      <td class="dim">${escapeHtml(extra.content_type || extra.mime || "")}</td>
      <td class="mono">${sizeStr}</td>
      <td class="mono">${extra.response_code || extra.status || ""}</td>
    </tr>`;
  }
  html += `</tbody></table></div>${pagination}`;
  el.innerHTML = html;
}

// ---- Preferences ----
function renderPreferences(el) {
  const prefs = byArtifact("preference");

  let html = `<div class="section-title">Browser Preferences <span class="count">${prefs.length}</span></div>`;

  if (prefs.length === 0) {
    html += `<div class="empty-state"><div class="icon">[.]</div>
      <p>No preference data. Run with <span class="mono">--prefs</span> flag to mine browser settings.</p></div>`;
    el.innerHTML = html;
    return;
  }

  const groups = {};
  for (const row of prefs) {
    const key = row.title || "unknown";
    if (!groups[key]) groups[key] = [];
    groups[key].push(row);
  }

  const priorityOrder = [
    "sync_account", "proxy_setting", "privacy_settings", "homepage",
    "default_search_engine", "download_directory", "profile_name",
    "always_private", "clear_on_shutdown", "do_not_track",
    "geolocation_permission", "notification_permission",
    "media_stream_camera_permission", "media_stream_mic_permission",
  ];

  const ordered = [
    ...priorityOrder.filter(k => groups[k]),
    ...Object.keys(groups).filter(k => !priorityOrder.includes(k)).sort(),
  ];

  for (const key of ordered) {
    const rows = groups[key];
    const label = key.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
    const isPrivacy = ["proxy_setting", "privacy_settings", "geolocation_permission",
                        "notification_permission", "media_stream_camera_permission",
                        "media_stream_mic_permission"].includes(key);

    html += `<div class="card"${isPrivacy ? ' style="border-left:3px solid var(--orange)"' : ""}>
      <div class="card-header">${label} (${rows.length})</div>
      <table class="data-table"><thead><tr><th>Browser</th><th>Value</th><th>Detail</th></tr></thead><tbody>`;
    for (const row of rows) {
      const detail = row.extra || "";
      html += `<tr class="clickable" onclick='openDetail(${JSON.stringify(row).replace(/'/g, "&#39;")})'>
        <td class="mono">${row.browser}</td>
        <td class="mono accent">${escapeHtml(truncate(row.url, 60))}</td>
        <td class="dim">${escapeHtml(truncate(typeof detail === "string" ? detail : JSON.stringify(detail), 60))}</td>
      </tr>`;
    }
    html += `</tbody></table></div>`;
  }

  el.innerHTML = html;
}

// ---- Cloud Accounts ----
function renderCloudAccounts(el) {
  const accounts = byArtifact("cloud_account");

  let html = `<div class="section-title">Cloud Account Inventory <span class="count">${accounts.length}</span></div>`;

  if (accounts.length === 0) {
    html += `<div class="empty-state"><div class="icon">[@]</div>
      <p>No cloud accounts detected. Run with <span class="mono">--cloud-accounts</span> flag.</p></div>`;
    el.innerHTML = html;
    return;
  }

  const services = new Set(accounts.map(a => a.title));
  const emails = new Set();
  accounts.forEach(a => { if (a.url && a.url.includes("@")) a.url.split(", ").forEach(e => emails.add(e)); });
  const activeSessions = accounts.filter(a => { const e = parseExtra(a); return e.has_active_session; });

  html += `<div class="metrics-grid">
    <div class="metric"><div class="metric-value accent">${services.size}</div><div class="metric-label">Services</div></div>
    <div class="metric"><div class="metric-value">${emails.size}</div><div class="metric-label">Emails</div></div>
    <div class="metric"><div class="metric-value orange">${activeSessions.length}</div><div class="metric-label">Active Sessions</div></div>
    <div class="metric"><div class="metric-value">${accounts.length}</div><div class="metric-label">Total Accounts</div></div>
  </div>`;

  if (emails.size > 0) {
    html += `<div class="card"><div class="card-header">Email Addresses</div>`;
    for (const email of [...emails].sort()) {
      html += `<div style="padding:3px 0"><span class="mono accent">${escapeHtml(email)}</span></div>`;
    }
    html += `</div>`;
  }

  html += `<div class="card"><table class="data-table">
    <thead><tr><th>Service</th><th>Email / ID</th><th>Evidence</th><th>Active?</th><th>Browsers</th></tr></thead><tbody>`;
  for (const row of accounts) {
    const extra = parseExtra(row);
    html += `<tr class="clickable" onclick='openDetail(${JSON.stringify(row).replace(/'/g, "&#39;")})'>
      <td style="font-weight:600">${escapeHtml(row.title)}</td>
      <td class="mono accent">${escapeHtml(truncate(row.url, 40))}</td>
      <td class="mono">${row.visit_count || 0}</td>
      <td>${extra.has_active_session ? '<span class="sev sev-high">ACTIVE</span>' : '<span class="dim">no</span>'}</td>
      <td class="dim">${escapeHtml(row.browser)}</td>
    </tr>`;
  }
  html += `</tbody></table></div>`;
  el.innerHTML = html;
}

// ---- PII / Secrets ----
function renderPII(el) {
  const findings = byArtifact("pii_finding");

  let html = `<div class="section-title">PII & Sensitive Data Scanner <span class="count">${findings.length} findings</span></div>`;

  if (findings.length === 0) {
    html += `<div class="empty-state"><div class="icon">[!]</div>
      <p>No PII/secrets detected. Run with <span class="mono">--pii-scan</span> flag.</p></div>`;
    el.innerHTML = html;
    return;
  }

  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  const catCounts = {};
  for (const row of findings) {
    const extra = parseExtra(row);
    const sev = extra.severity || 0;
    if (sev >= 90) sevCounts.critical++;
    else if (sev >= 70) sevCounts.high++;
    else if (sev >= 40) sevCounts.medium++;
    else sevCounts.low++;
    const cat = extra.category || "other";
    catCounts[cat] = (catCounts[cat] || 0) + 1;
  }

  html += `<div class="metrics-grid">
    <div class="metric"><div class="metric-value" style="color:var(--red)">${sevCounts.critical}</div><div class="metric-label">Critical</div></div>
    <div class="metric"><div class="metric-value orange">${sevCounts.high}</div><div class="metric-label">High</div></div>
    <div class="metric"><div class="metric-value" style="color:var(--yellow)">${sevCounts.medium}</div><div class="metric-label">Medium</div></div>
    <div class="metric"><div class="metric-value green">${sevCounts.low}</div><div class="metric-label">Low</div></div>
  </div>`;

  html += `<div class="card"><div class="card-header">By Category</div>`;
  for (const [cat, count] of Object.entries(catCounts).sort((a,b) => b[1]-a[1])) {
    const color = cat === "secret" ? "var(--red)" : cat === "financial" ? "var(--orange)" : "var(--accent)";
    html += `<div class="bar"><span class="bar-l">${cat}</span><div class="bar-t"><div class="bar-f" style="width:${count/findings.length*100}%;background:${color}"></div></div><span class="bar-v">${count}</span></div>`;
  }
  html += `</div>`;

  const page = state.pages["pii"] || 0;
  const fp = paginate(findings, "pii", page);
  html += `<div class="card"><table class="data-table">
    <thead><tr><th>Severity</th><th>Type</th><th>Match</th><th>Source</th><th>Browser</th></tr></thead><tbody>`;
  for (const row of fp.items) {
    const extra = parseExtra(row);
    const sev = extra.severity || 0;
    const sevClass = sev >= 90 ? "sev-crit" : sev >= 70 ? "sev-high" : sev >= 40 ? "sev-med" : "sev-low";
    html += `<tr class="clickable" onclick='openDetail(${JSON.stringify(row).replace(/'/g, "&#39;")})'>
      <td><span class="sev ${sevClass}">${sev}</span></td>
      <td style="font-weight:500">${escapeHtml(extra.description || row.title)}</td>
      <td class="mono password">${escapeHtml(truncate(extra.match || "", 40))}</td>
      <td class="url dim">${escapeHtml(truncate(row.url, 40))}</td>
      <td class="mono">${row.browser}</td>
    </tr>`;
  }
  html += `</tbody></table>${fp.pagination}</div>`;
  el.innerHTML = html;
}

// ---- Browser Fingerprint ----
function renderFingerprint(el) {
  const fps = byArtifact("fingerprint");

  let html = `<div class="section-title">Browser Fingerprint Reconstruction <span class="count">${fps.length} profile(s)</span></div>`;

  if (fps.length === 0) {
    html += `<div class="empty-state"><div class="icon">[#]</div>
      <p>No fingerprint data. Run with <span class="mono">--fingerprint</span> flag.</p></div>`;
    el.innerHTML = html;
    return;
  }

  for (const row of fps) {
    const extra = parseExtra(row);
    const uniqueness = extra.uniqueness_score || 0;
    const uColor = uniqueness >= 70 ? "var(--red)" : uniqueness >= 40 ? "var(--orange)" : "var(--green)";

    html += `<div class="card" style="border-left:3px solid ${uColor}">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <span style="font-size:14px;font-weight:600">${escapeHtml(row.browser)} — ${escapeHtml(row.profile?.split(/[/\\\\]/).pop() || "Default")}</span>
        <span class="mono" style="color:${uColor}">Uniqueness: ${uniqueness}/100</span>
      </div>
      <div class="mono dim" style="margin-bottom:8px">Hash: ${escapeHtml(row.url)}</div>
      <table class="data-table">
        <tr><td class="dim" style="width:180px">User-Agent</td><td class="mono">${escapeHtml(extra.user_agent || "unknown")}</td></tr>
        <tr><td class="dim">Language</td><td class="mono">${escapeHtml(extra.language || "unknown")}</td></tr>
        <tr><td class="dim">Timezone</td><td class="mono">${escapeHtml(extra.timezone || "unknown")}</td></tr>
        <tr><td class="dim">Screen Resolution</td><td class="mono">${escapeHtml(extra.screen_resolution || "unknown")}</td></tr>
        <tr><td class="dim">GPU / WebGL</td><td class="mono">${escapeHtml(extra.gpu || "unknown")}</td></tr>
        <tr><td class="dim">Extensions</td><td class="mono">${extra.extensions || 0} installed</td></tr>
        <tr><td class="dim">Do Not Track</td><td class="mono">${extra.do_not_track ? "enabled" : "disabled"}</td></tr>
      </table>
    </div>`;
  }
  el.innerHTML = html;
}

// ---- Session Hijack ----
function renderSessionHijack(el) {
  const sessions = byArtifact("session_hijack");

  let html = `<div class="section-title">Session Hijack Analysis <span class="count">${sessions.length} high-value sessions</span></div>`;

  if (sessions.length === 0) {
    html += `<div class="empty-state"><div class="icon">[*]</div>
      <p>No session data. Run with <span class="mono">--session-hijack</span> flag.</p></div>`;
    el.innerHTML = html;
    return;
  }

  const activeCount = sessions.filter(s => { const e = parseExtra(s); return !e.is_expired; }).length;
  html += `<div class="metrics-grid">
    <div class="metric"><div class="metric-value accent">${sessions.length}</div><div class="metric-label">High-Value Sessions</div></div>
    <div class="metric"><div class="metric-value orange">${activeCount}</div><div class="metric-label">Potentially Active</div></div>
  </div>`;

  html += `<div class="card"><table class="data-table">
    <thead><tr><th>Risk</th><th>Service</th><th>Domain</th><th>Cookie</th><th>Expires In</th><th>Flags</th></tr></thead><tbody>`;
  for (const row of sessions) {
    const extra = parseExtra(row);
    const risk = extra.risk_score || 0;
    const riskClass = risk >= 70 ? "sev-crit" : risk >= 50 ? "sev-high" : risk >= 30 ? "sev-med" : "sev-low";
    const flags = [];
    if (extra.secure) flags.push("Secure");
    if (extra.httponly) flags.push("HttpOnly");
    if (extra.samesite && extra.samesite !== "unset") flags.push(`SS:${extra.samesite}`);
    const issues = (extra.security_issues || []).length;

    html += `<tr class="clickable" onclick='openDetail(${JSON.stringify(row).replace(/'/g, "&#39;")})'>
      <td><span class="sev ${riskClass}">${risk}</span></td>
      <td style="font-weight:500">${escapeHtml(extra.service || "")}</td>
      <td class="url">${escapeHtml(truncate(row.url, 40))}</td>
      <td class="mono">${escapeHtml(extra.cookie_name || "")}</td>
      <td class="dim">${extra.is_expired ? '<span style="color:var(--red)">expired</span>' : escapeHtml(extra.expires_in || "unknown")}</td>
      <td class="dim">${flags.join(", ")}${issues ? ` <span style="color:var(--red)">(${issues} issues)</span>` : ""}</td>
    </tr>`;
  }
  html += `</tbody></table></div>`;
  el.innerHTML = html;
}

// ---- Export Helper ----
window.exportData = exportData;
function exportData(format) {
  if (format === 'json') {
    const blob = new Blob([JSON.stringify(state.artifacts, null, 2)], {type: 'application/json'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
    a.download = 'frostveil_export.json'; a.click();
  } else if (format === 'csv') {
    if (!state.artifacts.length) return;
    const keys = Object.keys(state.artifacts[0]);
    const csv = [keys.join(','), ...state.artifacts.map(r => keys.map(k => `"${String(r[k]||'').replace(/"/g,'""')}"`).join(','))].join('\n');
    const blob = new Blob([csv], {type: 'text/csv'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
    a.download = 'frostveil_export.csv'; a.click();
  }
}

// ---- Media History ----
function renderMedia(el) {
  const rows = state.artifacts.filter(a => a.artifact === "media_playback" || a.artifact === "media_watchtime");
  if (!rows.length) { el.innerHTML = '<div class="empty-state">No media history found</div>'; return; }
  const playbacks = rows.filter(a => a.artifact === "media_playback");
  const watchtime = rows.filter(a => a.artifact === "media_watchtime");

  let html = `<div class="section-title">Media History <span class="count">${playbacks.length} playbacks</span></div>
    <div class="metrics-grid">
      <div class="metric"><div class="metric-value">${playbacks.length}</div><div class="metric-label">Playbacks</div></div>
      <div class="metric"><div class="metric-value">${watchtime.length}</div><div class="metric-label">Origins Tracked</div></div>
    </div>`;

  html += `<div class="card"><h3>Recent Playbacks</h3><table class="data-table">
    <thead><tr><th>Title</th><th>URL</th><th>Duration</th><th>Time</th></tr></thead><tbody>`;
  for (const row of playbacks.slice(0, 100)) {
    const extra = parseExtra(row);
    const dur = extra.duration_ms ? `${(extra.duration_ms / 60000).toFixed(1)}m` : "";
    html += `<tr class="clickable" onclick='openDetail(${JSON.stringify(row).replace(/'/g, "&#39;")})'>
      <td style="font-weight:500">${escapeHtml(truncate(row.title || "(untitled)", 50))}</td>
      <td class="url">${escapeHtml(truncate(row.url, 60))}</td>
      <td class="dim">${dur}</td>
      <td class="dim">${escapeHtml(row.visit_time_utc || "")}</td>
    </tr>`;
  }
  html += `</tbody></table></div>`;
  el.innerHTML = html;
}

// ---- Site Engagement ----
function renderEngagement(el) {
  const rows = state.artifacts.filter(a => a.artifact === "site_engagement");
  if (!rows.length) { el.innerHTML = '<div class="empty-state">No site engagement data found</div>'; return; }

  // Sort by score descending
  const sorted = [...rows].sort((a, b) => {
    const sa = parseFloat(a.title) || 0;
    const sb = parseFloat(b.title) || 0;
    return sb - sa;
  });

  let html = `<div class="section-title">Site Engagement Scores <span class="count">${rows.length} sites</span></div>
    <div class="metrics-grid">
      <div class="metric"><div class="metric-value">${rows.length}</div><div class="metric-label">Sites Tracked</div></div>
    </div>`;

  // Bar chart visualization
  html += `<div class="card"><h3>Top Engaged Sites</h3>`;
  for (const row of sorted.slice(0, 30)) {
    const score = parseFloat(row.title) || 0;
    const pct = Math.min(score, 100);
    const color = score > 80 ? "var(--green)" : score > 40 ? "var(--orange)" : "var(--dim)";
    html += `<div style="display:flex;align-items:center;margin:4px 0;gap:8px">
      <span class="mono" style="min-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(truncate(row.url, 30))}</span>
      <div style="flex:1;background:var(--bg-tertiary);border-radius:3px;height:16px;position:relative">
        <div style="width:${pct}%;background:${color};height:100%;border-radius:3px"></div>
      </div>
      <span class="dim" style="min-width:40px;text-align:right">${score.toFixed(0)}</span>
    </div>`;
  }
  html += `</div>`;
  el.innerHTML = html;
}

// ---- Compromised Credentials ----
function renderCompromised(el) {
  const rows = state.artifacts.filter(a => a.artifact === "compromised_credential");
  if (!rows.length) { el.innerHTML = '<div class="empty-state">No compromised credentials detected</div>'; return; }

  const byType = {};
  rows.forEach(r => {
    const extra = parseExtra(r);
    const t = extra.insecurity_type || "unknown";
    byType[t] = (byType[t] || 0) + 1;
  });

  let html = `<div class="section-title">Compromised Credentials <span class="count">${rows.length} flagged</span></div>
    <div class="metrics-grid">
      <div class="metric"><div class="metric-value red">${rows.length}</div><div class="metric-label">Compromised</div></div>
      ${Object.entries(byType).map(([k,v]) => `<div class="metric"><div class="metric-value orange">${v}</div><div class="metric-label">${k}</div></div>`).join("")}
    </div>`;

  html += `<div class="card"><table class="data-table">
    <thead><tr><th>Type</th><th>Username</th><th>Site</th><th>Detected</th></tr></thead><tbody>`;
  for (const row of rows) {
    const extra = parseExtra(row);
    const typeClass = extra.insecurity_type === "leaked" ? "sev-crit" : extra.insecurity_type === "phished" ? "sev-high" : "sev-med";
    html += `<tr class="clickable" onclick='openDetail(${JSON.stringify(row).replace(/'/g, "&#39;")})'>
      <td><span class="sev ${typeClass}">${escapeHtml(extra.insecurity_type || "")}</span></td>
      <td style="font-weight:500">${escapeHtml(row.title || "")}</td>
      <td class="url">${escapeHtml(truncate(row.url, 50))}</td>
      <td class="dim">${escapeHtml(row.visit_time_utc || "")}</td>
    </tr>`;
  }
  html += `</tbody></table></div>`;
  el.innerHTML = html;
}

// ---- Windows Artifacts ----
function renderWindows(el) {
  const types = ["prefetch", "jump_list", "lnk_file", "recycle_bin"];
  const rows = state.artifacts.filter(a => types.includes(a.artifact));
  if (!rows.length) { el.innerHTML = '<div class="empty-state">No Windows artifacts found</div>'; return; }

  const counts = {};
  types.forEach(t => counts[t] = rows.filter(r => r.artifact === t).length);

  let html = `<div class="section-title">Windows Artifacts <span class="count">${rows.length} total</span></div>
    <div class="metrics-grid">
      ${types.map(t => `<div class="metric"><div class="metric-value">${counts[t]}</div><div class="metric-label">${t.replace("_", " ")}</div></div>`).join("")}
    </div>`;

  html += `<div class="card"><table class="data-table">
    <thead><tr><th>Type</th><th>Name</th><th>Path/URL</th><th>Time</th></tr></thead><tbody>`;
  for (const row of rows.slice(0, 200)) {
    html += `<tr class="clickable" onclick='openDetail(${JSON.stringify(row).replace(/'/g, "&#39;")})'>
      <td><span class="badge">${escapeHtml(row.artifact)}</span></td>
      <td style="font-weight:500">${escapeHtml(truncate(row.title || "", 40))}</td>
      <td class="url">${escapeHtml(truncate(row.url || "", 60))}</td>
      <td class="dim">${escapeHtml(row.visit_time_utc || "")}</td>
    </tr>`;
  }
  html += `</tbody></table></div>`;
  el.innerHTML = html;
}
