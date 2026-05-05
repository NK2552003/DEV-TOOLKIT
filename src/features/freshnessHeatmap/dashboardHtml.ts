import * as vscode from "vscode";

export function buildDashboardHtml(
  webview: vscode.Webview,
  extensionUri: vscode.Uri
): string {
  const nonce = getNonce();
  const codiconUri = webview.asWebviewUri(
    vscode.Uri.joinPath(
      extensionUri,
      "node_modules",
      "@vscode",
      "codicons",
      "dist",
      "codicon.css"
    )
  );
  const csp = [
    "default-src 'none'",
    `script-src 'nonce-${nonce}' https://cdn.jsdelivr.net`,
    `style-src ${webview.cspSource} 'unsafe-inline'`,
    `font-src ${webview.cspSource}`,
    `img-src ${webview.cspSource} data:`,
  ].join("; ");

  return /* html */`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Freshness Dashboard</title>
<link href="${codiconUri}" rel="stylesheet" />
<style>
  :root {
    --recent:   var(--vscode-charts-green, #4caf50);
    --moderate: var(--vscode-charts-yellow, #ff9800);
    --stale:    var(--vscode-charts-red, #f44336);
    --unknown:  var(--vscode-charts-gray, #9e9e9e);
    --bg:       var(--vscode-editor-background, #1e1e1e);
    --fg:       var(--vscode-editor-foreground, #d4d4d4);
    --card:     var(--vscode-editorWidget-background, #252526);
    --border:   var(--vscode-panel-border, #3c3c3c);
    --accent:   var(--vscode-focusBorder, #007acc);
    --subtle:   var(--vscode-descriptionForeground, rgba(255,255,255,0.6));
    --muted:    var(--vscode-disabledForeground, rgba(255,255,255,0.4));
    --button-bg:    var(--vscode-button-secondaryBackground, var(--border));
    --button-fg:    var(--vscode-button-secondaryForeground, var(--fg));
    --button-hover: var(--vscode-button-secondaryHoverBackground, var(--accent));
    --primary-bg:   var(--vscode-button-background, var(--accent));
    --primary-fg:   var(--vscode-button-foreground, #ffffff);
    --chart-grid:   var(--vscode-editorIndentGuide-background, rgba(255,255,255,0.08));
    --chart-tick:   var(--vscode-editorLineNumber-foreground, rgba(255,255,255,0.55));
    --font:     var(--vscode-font-family, 'Segoe UI', sans-serif);
    --mono:     var(--vscode-editor-font-family, 'Consolas', monospace);
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg); color: var(--fg);
    font-family: "IBM Plex Sans", "Space Grotesk", var(--font);
    font-size: 13px;
    padding: 16px; min-height: 100vh;
    position: relative; overflow-x: hidden;
  }
  body::before {
    content: "";
    position: fixed; inset: 0; pointer-events: none; z-index: 0;
    background:
      radial-gradient(600px 180px at 10% -10%, rgba(76, 175, 80, 0.10), transparent 60%),
      radial-gradient(520px 160px at 90% -15%, rgba(255, 152, 0, 0.10), transparent 60%);
  }
  body > * { position: relative; z-index: 1; }
  h2 { font-size: 15px; font-weight: 600; margin-bottom: 12px; opacity: 0.9; }
  .codicon { vertical-align: -2px; }
  .title-icon { margin-right: 6px; color: var(--accent); }
  .grid {
    display: grid;
    grid-template-columns: minmax(240px, 320px) minmax(300px, 1fr);
    grid-template-areas:
      "score charts"
      "authors charts"
      "stale stale";
    gap: 12px;
  }
  .card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 14px;
    box-shadow: 0 1px 0 rgba(255,255,255,0.03), 0 10px 24px rgba(0,0,0,0.25);
  }
  /* --- Score ring --- */
  .score-card {
    grid-area: score;
    display: flex; flex-direction: column; align-items: center;
    gap: 8px;
  }
  .ring-wrap { position: relative; width: clamp(96px, 20vw, 128px); height: clamp(96px, 20vw, 128px); }
  .ring-wrap svg { transform: rotate(-90deg); }
  .ring-bg   { fill: none; stroke: var(--border); stroke-width: 10; }
  .ring-fg   { fill: none; stroke-width: 10;
               stroke-linecap: round;
               transition: stroke-dashoffset 0.7s cubic-bezier(.4,0,.2,1),
                           stroke 0.4s; }
  .ring-label {
    position: absolute; inset: 0;
    display: flex; flex-direction: column;
    align-items: center; justify-content: center;
  }
  .ring-score  { font-size: 28px; font-weight: 700; line-height: 1; }
  .ring-grade  {
    font-size: 13px; font-weight: 600; margin-top: 2px;
    padding: 1px 6px; border-radius: 3px;
  }
  .file-name   { font-size: 11px; opacity: 0.6; text-align: center;
                  max-width: 220px; overflow: hidden; text-overflow: ellipsis;
                  white-space: nowrap; }
  .grade-label { font-size: 11px; opacity: 0.7; text-align: center; }

  /* --- Stats row --- */
  .stats-row { display: flex; gap: 10px; margin-top: 6px; flex-wrap: wrap; }
  .stat {
    flex: 1; min-width: 60px;
    background: var(--vscode-input-background, var(--border));
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 6px 8px; text-align: center;
  }
  .stat-val { font-size: 16px; font-weight: 700; }
  .stat-lbl { font-size: 10px; opacity: 0.6; margin-top: 2px; }

  /* --- Mode switcher --- */
  .mode-bar {
    display: flex; gap: 6px; flex-wrap: wrap;
    margin-bottom: 10px;
  }
  .mode-btn {
    flex: 1; padding: 5px 0;
    background: var(--button-bg); border: 1px solid transparent;
    border-radius: 4px; color: var(--button-fg);
    cursor: pointer; font-size: 12px;
    transition: background 0.15s, border-color 0.15s;
  }
  .mode-btn:hover   { background: var(--button-hover); border-color: var(--button-hover); color: var(--primary-fg); }
  .mode-btn.active  { background: var(--primary-bg); border-color: var(--primary-bg); color: var(--primary-fg); font-weight: 600; }
  .mode-btn .codicon { margin-right: 6px; }

  /* --- Charts --- */
  .charts-card {
    grid-area: charts;
    display: flex; flex-direction: column; gap: 12px;
  }
  .chart-row { display: flex; gap: 12px; flex-wrap: wrap; }
  .chart-box { flex: 1; min-width: 220px; }
  canvas { max-height: 180px; height: 180px !important; width: 100% !important; }

  /* --- Author table --- */
  .authors-card { grid-area: authors; }
  .author-row {
    display: flex; align-items: center; gap: 8px;
    padding: 5px 0;
    border-bottom: 1px solid var(--border);
  }
  .author-row:last-child { border-bottom: none; }
  .a-tint { width: 10px; height: 10px; border-radius: 2px; flex-shrink: 0; }
  .a-name { flex: 1; font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .a-pct  { font-size: 11px; opacity: 0.7; }
  .a-bar-wrap { width: 60px; height: 4px; background: var(--border); border-radius: 2px; }
  .a-bar  { height: 4px; border-radius: 2px; transition: width 0.4s; }

  /* --- Stale files --- */
  .stale-card { grid-area: stale; }
  #stale-table-wrap { overflow-x: auto; }
  .stale-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  .stale-table th {
    text-align: left; padding: 5px 8px;
    border-bottom: 1px solid var(--border);
    opacity: 0.6; font-weight: 500;
  }
  .stale-table td { padding: 5px 8px; }
  .stale-table tr:hover td { background: rgba(255,255,255,0.04); cursor: pointer; }
  .grade-badge {
    display: inline-block; width: 20px; text-align: center;
    font-weight: 700; border-radius: 3px; font-size: 11px; padding: 1px 3px;
  }
  .bar-cell { width: 100px; }
  .mini-bar-bg { height: 6px; background: var(--border); border-radius: 3px; overflow: hidden; }
  .mini-bar    { height: 6px; border-radius: 3px; transition: width 0.4s; }
  .stale-cards { display: none; gap: 10px; }
  .stale-card-row {
    border: 1px solid var(--border); border-radius: 6px;
    padding: 10px; display: flex; flex-direction: column; gap: 6px;
    background: var(--card); cursor: pointer;
  }
  .stale-row-top { display: flex; align-items: center; gap: 8px; }
  .stale-file {
    font-family: var(--mono); font-size: 12px; opacity: 0.9;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  }
  .stale-row-meta { display: flex; gap: 8px; flex-wrap: wrap; }
  .stale-chip {
    background: var(--button-bg); color: var(--button-fg);
    border: 1px solid var(--border);
    border-radius: 999px; padding: 2px 8px; font-size: 11px;
  }

  /* --- Top bar --- */
  .top-bar {
    display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
    margin-bottom: 14px;
  }
  .top-bar h1 { font-size: 16px; font-weight: 700; flex: 1; }
  .refresh-btn {
    padding: 4px 10px; background: transparent;
    border: 1px solid var(--button-hover); border-radius: 4px;
    color: var(--button-hover); cursor: pointer; font-size: 12px;
  }
  .refresh-btn:hover { background: var(--button-hover); color: var(--primary-fg); }
  .refresh-btn .codicon { margin-right: 6px; }
  .empty-state { opacity: 0.45; font-style: italic; padding: 20px 0; text-align: center; }

  @media (max-width: 900px) {
    .grid {
      grid-template-columns: 1fr;
      grid-template-areas:
        "score"
        "charts"
        "authors"
        "stale";
    }
    .chart-row { flex-direction: column; }
    .chart-box { min-width: unset; }
  }

  @media (max-width: 600px) {
    body { padding: 12px; }
    .top-bar h1 { font-size: 15px; }
    .file-name { max-width: 100%; }
    .stale-table { display: none; }
    .stale-cards { display: grid; }
  }
</style>
</head>
<body>

<div class="top-bar">
  <h1><span class="codicon codicon-flame title-icon"></span>Freshness Dashboard</h1>
  <button class="refresh-btn" onclick="vscPost('refresh')"><span class="codicon codicon-sync"></span>Refresh</button>
</div>

<!-- Mode switcher -->
<div class="mode-bar">
  <button class="mode-btn active" id="btn-age"    onclick="switchMode('age')"    title="Colour by last-modified date"><span class="codicon codicon-clock"></span>Age</button>
  <button class="mode-btn"        id="btn-churn"  onclick="switchMode('churn')"  title="Colour by modification frequency"><span class="codicon codicon-flame"></span>Churn</button>
  <button class="mode-btn"        id="btn-author" onclick="switchMode('author')" title="Colour by contributor"><span class="codicon codicon-person"></span>Author</button>
</div>

<div class="grid">

  <!-- Score ring -->
  <div class="card score-card" id="score-card">
    <div class="ring-wrap">
      <svg viewBox="0 0 120 120" width="120" height="120">
        <circle class="ring-bg" cx="60" cy="60" r="50"/>
        <circle class="ring-fg" id="ring-fg" cx="60" cy="60" r="50"
          stroke-dasharray="314.16" stroke-dashoffset="314.16"
          stroke="var(--stale)"/>
      </svg>
      <div class="ring-label">
        <span class="ring-score" id="ring-score">-</span>
        <span class="ring-grade" id="ring-grade">-</span>
      </div>
    </div>
    <div class="file-name" id="file-name">Open a file to analyse</div>
    <div class="grade-label" id="grade-label"></div>
    <div class="stats-row">
      <div class="stat"><div class="stat-val" id="stat-avg">-</div><div class="stat-lbl">avg age</div></div>
      <div class="stat"><div class="stat-val" id="stat-med">-</div><div class="stat-lbl">median</div></div>
      <div class="stat"><div class="stat-val" id="stat-auth">-</div><div class="stat-lbl">authors</div></div>
    </div>
  </div>

  <!-- Charts -->
  <div class="card charts-card">
    <div class="chart-row">
      <div class="chart-box">
        <h2>Tier Distribution</h2>
        <canvas id="donutChart"></canvas>
      </div>
      <div class="chart-box">
        <h2>8-Week Commit Activity</h2>
        <canvas id="sparkChart"></canvas>
      </div>
    </div>
  </div>

  <!-- Authors -->
  <div class="card authors-card">
    <h2>Contributors</h2>
    <div id="author-list"><div class="empty-state">No data yet</div></div>
  </div>

  <!-- Stale files -->
  <div class="card stale-card">
    <h2>Stalest Files in Workspace</h2>
    <div id="stale-table-wrap"><div class="empty-state">Workspace scan pending...</div></div>
  </div>

</div>

<script nonce="${nonce}" src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<script nonce="${nonce}">
const vscode = acquireVsCodeApi();
function vscPost(type, data) { vscode.postMessage({ type, ...data }); }

const theme = readThemeColors();

function readThemeColors() {
  const styles = getComputedStyle(document.documentElement);
  const pick = (name, fallback) => {
    const value = styles.getPropertyValue(name).trim();
    return value || fallback;
  };
  return {
    recent:   pick('--recent', '#4caf50'),
    moderate: pick('--moderate', '#ff9800'),
    stale:    pick('--stale', '#f44336'),
    unknown:  pick('--unknown', '#9e9e9e'),
    accent:   pick('--accent', '#007acc'),
    grid:     pick('--chart-grid', 'rgba(255,255,255,0.08)'),
    ticks:    pick('--chart-tick', 'rgba(255,255,255,0.55)'),
  };
}

function toRgba(color, alpha) {
  const c = (color || '').trim();
  if (c.startsWith('#')) {
    const hex = c.slice(1);
    const value = hex.length === 3
      ? hex.split('').map(ch => ch + ch).join('')
      : hex.padEnd(6, '0');
    const r = parseInt(value.slice(0, 2), 16);
    const g = parseInt(value.slice(2, 4), 16);
    const b = parseInt(value.slice(4, 6), 16);
    return "rgba(" + r + "," + g + "," + b + "," + alpha + ")";
  }
  if (c.startsWith('rgb(')) {
    return c.replace('rgb(', 'rgba(').replace(')', ', ' + alpha + ')');
  }
  if (c.startsWith('rgba(')) {
    return c.replace(/rgba\(([^,]+),([^,]+),([^,]+),[^)]+\)/, 'rgba($1,$2,$3,' + alpha + ')');
  }
  return c;
}

// --- Charts -------------------------------------------------------------------

let donutChart = null;
let sparkChart = null;
const CHART_OPTS = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: { legend: { display: false }, tooltip: { enabled: true } },
};

function initCharts() {
  const donutCtx = document.getElementById('donutChart').getContext('2d');
  donutChart = new Chart(donutCtx, {
    type: 'doughnut',
    data: {
      labels: ['Recent','Moderate','Stale','Unknown'],
      datasets:[{ data:[0,0,0,100],
        backgroundColor:[theme.recent, theme.moderate, theme.stale, theme.unknown],
        borderWidth: 0, hoverOffset: 4 }]
    },
    options: {
      ...CHART_OPTS,
      cutout: '68%',
      plugins: {
        ...CHART_OPTS.plugins,
        tooltip: { callbacks: { label: c => ' '+c.label+': '+c.raw.toFixed(1)+'%' } },
      },
    },
  });

  const sparkCtx = document.getElementById('sparkChart').getContext('2d');
  sparkChart = new Chart(sparkCtx, {
    type: 'bar',
    data: {
      labels: ['wk-7','wk-6','wk-5','wk-4','wk-3','wk-2','wk-1','now'],
      datasets:[{
        data: new Array(8).fill(0),
        backgroundColor: Array.from({ length: 8 }, (_, i) => {
          const alpha = Math.min(0.25 + i * 0.07, 0.85);
          return toRgba(theme.accent, alpha);
        }),
        borderRadius: 3, borderSkipped: false,
      }]
    },
    options: {
      ...CHART_OPTS,
      scales: {
        x: { grid:{ color: theme.grid }, ticks:{ color: theme.ticks, font:{size:10} } },
        y: { grid:{ color: theme.grid }, ticks:{ color: theme.ticks, font:{size:10} } },
      },
    },
  });
}

// --- Score ring ---------------------------------------------------------------

function updateRing(score, grade) {
  const circ  = 2 * Math.PI * 50;
  const fill  = circ * (score / 100);
  const fg    = document.getElementById('ring-fg');
  fg.style.strokeDashoffset = (circ - fill).toFixed(2);
  fg.style.stroke = gradeColor(grade);
  document.getElementById('ring-score').textContent = score;
  const gradeEl = document.getElementById('ring-grade');
  gradeEl.textContent = grade;
  gradeEl.style.background = gradeColor(grade) + '33';
  gradeEl.style.color = gradeColor(grade);
}

function gradeColor(g) {
  return {A: theme.recent, B: theme.moderate, C: theme.moderate, D: theme.stale, F: theme.stale}[g] ?? theme.unknown;
}

// --- Authors -----------------------------------------------------------------

function renderAuthors(authors) {
  const el = document.getElementById('author-list');
  if (!authors || !authors.length) {
    el.innerHTML = '<div class="empty-state">No author data</div>';
    return;
  }
  el.innerHTML = authors.map(a => \`
    <div class="author-row" title="Last touched: \${a.lastTouchDays}d ago">
      <div class="a-tint" style="background:\${a.tint}"></div>
      <div class="a-name">\${escHtml(a.name)}</div>
      <div class="a-bar-wrap"><div class="a-bar" style="width:\${a.pct.toFixed(1)}%;background:\${a.tint}"></div></div>
      <div class="a-pct">\${a.pct.toFixed(0)}%</div>
    </div>
  \`).join('');
}

// --- Stale files table -------------------------------------------------------

function renderStaleTable(files) {
  const wrap = document.getElementById('stale-table-wrap');
  if (!files || !files.length) {
    wrap.innerHTML = '<div class="empty-state">No stale files found - great job!</div>';
    return;
  }
  const rows = files.map(f => \`
    <tr onclick="vscPost('openFile',{path:\${JSON.stringify(f.fsPath)}})">
      <td><span class="grade-badge" style="background:\${gradeColor(f.grade)}22;color:\${gradeColor(f.grade)}">\${f.grade}</span></td>
      <td title="\${escHtml(f.fsPath)}" style="font-family:var(--mono);opacity:0.85">\${escHtml(f.relPath)}</td>
      <td>\${f.avgAgeDays}d</td>
      <td>\${f.stalePct.toFixed(0)}%</td>
      <td class="bar-cell">
        <div class="mini-bar-bg">
          <div class="mini-bar" style="width:\${f.stalePct.toFixed(0)}%;background:\${gradeColor(f.grade)}"></div>
        </div>
      </td>
    </tr>
  \`).join('');
  const cards = files.map(f => \`
    <div class="stale-card-row" onclick="vscPost('openFile',{path:\${JSON.stringify(f.fsPath)}})">
      <div class="stale-row-top">
        <span class="grade-badge" style="background:\${gradeColor(f.grade)}22;color:\${gradeColor(f.grade)}">\${f.grade}</span>
        <div class="stale-file" title="\${escHtml(f.fsPath)}">\${escHtml(f.relPath)}</div>
      </div>
      <div class="stale-row-meta">
        <span class="stale-chip">Avg age \${f.avgAgeDays}d</span>
        <span class="stale-chip">Stale \${f.stalePct.toFixed(0)}%</span>
      </div>
      <div class="mini-bar-bg">
        <div class="mini-bar" style="width:\${f.stalePct.toFixed(0)}%;background:\${gradeColor(f.grade)}"></div>
      </div>
    </div>
  \`).join('');
  wrap.innerHTML = \`
    <div class="stale-cards">\${cards}</div>
    <table class="stale-table">
      <thead><tr><th>Grade</th><th>File</th><th>Avg Age</th><th>Stale%</th><th></th></tr></thead>
      <tbody>\${rows}</tbody>
    </table>
  \`;
}

// --- Message handler ---------------------------------------------------------

window.addEventListener('message', ({ data }) => {
  if (data.type !== 'update') { return; }
  const { score, sparkData, staleList, currentFile, currentMode } = data;

  // Update mode buttons
  ['age','churn','author'].forEach(m => {
    document.getElementById('btn-'+m).classList.toggle('active', m === currentMode);
  });

  if (score) {
    updateRing(score.score, score.grade);
    document.getElementById('file-name').textContent = currentFile.split(/[\\/]/).pop() || currentFile;
    document.getElementById('grade-label').textContent = score.gradeLabel;
    document.getElementById('stat-avg').textContent = score.avgAgeDays + 'd';
    document.getElementById('stat-med').textContent = score.medianAgeDays + 'd';
    document.getElementById('stat-auth').textContent = score.uniqueAuthors;

    donutChart.data.datasets[0].data = [
      score.recentPct, score.moderatePct, score.stalePct, score.unknownPct
    ];
    donutChart.update('active');
    renderAuthors(score.authors);
  }

  if (sparkData) {
    sparkChart.data.datasets[0].data = sparkData.weeklyBuckets;
    sparkChart.update('active');
  }

  renderStaleTable(staleList);
});

// --- Mode switch -------------------------------------------------------------

function switchMode(mode) {
  vscPost('setMode', { mode });
}

// --- Utils -------------------------------------------------------------------

function escHtml(s) {
  return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

initCharts();
</script>
</body>
</html>`;
}

function getNonce(): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let text = "";
  for (let i = 0; i < 32; i++) {
    text += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return text;
}
