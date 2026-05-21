/* ═══ ZeroTrust CI Dashboard — dashboard.js ═══ */

// ─── Pipeline stages (synced avec votre Jenkinsfile) ─────────────────────────
const STAGES = [
  { id: 'prep',   name: 'Préparation', icon: 'ti-settings',      sub: 'Stage 0' },
  { id: 'sast',   name: 'SAST',        icon: 'ti-code',           sub: 'Semgrep' },
  { id: 'sca',    name: 'SCA',         icon: 'ti-package',        sub: 'Trivy' },
  { id: 'ai3a',   name: 'Anti-Tamper', icon: 'ti-shield-lock',    sub: 'Stage 3a' },
  { id: 'ai3b',   name: 'Remédiation', icon: 'ti-robot',          sub: 'Stage 3b' },
  { id: 'ai3c',   name: 'Rapport IA',  icon: 'ti-file-analytics', sub: 'Stage 3c' },
  { id: 'docker', name: 'Docker Build',icon: 'ti-box',            sub: 'Stage 4' },
  { id: 'scan',   name: 'Image Scan',  icon: 'ti-shield',         sub: 'Stage 5' },
  { id: 'dast',   name: 'DAST',        icon: 'ti-antenna',        sub: 'ZAP' },
  { id: 'cosign', name: 'Cosign',      icon: 'ti-certificate',    sub: 'Stage 6' },
  { id: 'pdf',    name: 'Rapport PDF', icon: 'ti-file-type-pdf',  sub: 'Stage 7' },
];

// ─── State ────────────────────────────────────────────────────────────────────
let allFindings  = [];
let currentFilter = 'all';
let fallbackActive = false;
let buildStartTime = Date.now();
let timerInterval;
let logQueue = [];
let isLogging = false;

// ─── Demo mode : status simulé quand pas de vrai Jenkins ─────────────────────
const DEMO_STAGE_STATUS = {
  prep: 'done', sast: 'done', sca: 'done',
  ai3a: 'done', ai3b: 'running', ai3c: 'waiting',
  docker: 'waiting', scan: 'waiting', dast: 'waiting',
  cosign: 'waiting', pdf: 'waiting',
};

// ─── Init ─────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  buildPipelineFlow();
  startTimer();
  refreshAll();
  setInterval(refreshAll, 30000); // auto-refresh toutes les 30s
  bootConsole();
});

// ─── Build pipeline flow ──────────────────────────────────────────────────────
function buildPipelineFlow(statusMap) {
  const track = document.getElementById('flowTrack');
  track.innerHTML = '';
  const sm = statusMap || DEMO_STAGE_STATUS;

  STAGES.forEach((s, i) => {
    const st = sm[s.id] || 'waiting';
    const el = document.createElement('div');
    el.className = `stage ${st}`;
    el.id = `stage-${s.id}`;
    el.title = `${s.name} [${st}]`;
    el.onclick = () => stageClicked(s);
    el.innerHTML = `
      <div class="stage-node">
        ${st === 'running' ? '<div class="pulse-ring"></div><div class="scan"></div>' : ''}
        <i class="ti ${s.icon} stage-icon"></i>
        <div class="stage-name">${s.name}</div>
      </div>
      <div class="stage-dur" id="dur-${s.id}">–</div>
    `;
    track.appendChild(el);

    if (i < STAGES.length - 1) {
      const c = document.createElement('div');
      c.className = 'connector';
      const lc = st === 'done' ? 'done' : st === 'running' ? 'running' : 'waiting';
      c.innerHTML = `<div class="conn-line ${lc}"></div>`;
      track.appendChild(c);
    }
  });

  // Progress bar
  const doneCount = Object.values(sm).filter(v => v === 'done').length;
  const pct = Math.round((doneCount / STAGES.length) * 100);
  document.getElementById('progressFill').style.width = pct + '%';
}

// ─── Timer ────────────────────────────────────────────────────────────────────
function startTimer() {
  buildStartTime = Date.now();
  clearInterval(timerInterval);
  timerInterval = setInterval(() => {
    const sec = Math.floor((Date.now() - buildStartTime) / 1000);
    const m = String(Math.floor(sec / 60)).padStart(2, '0');
    const s = String(sec % 60).padStart(2, '0');
    document.getElementById('timer').textContent = `${m}:${s}`;
  }, 1000);
}

// ─── Refresh all data from API ────────────────────────────────────────────────
async function refreshAll() {
  document.getElementById('lastRefresh').textContent =
    'Refresh: ' + new Date().toLocaleTimeString('fr-FR');
  await Promise.all([fetchStatus(), fetchFindings()]);
}

async function fetchStatus() {
  try {
    const r = await fetch('/api/status');
    if (!r.ok) throw new Error('no server');
    const d = await r.json();
    applyStatus(d);
  } catch {
    applyDemoStatus();
  }
}

function applyStatus(d) {
  document.getElementById('m-cve').textContent      = d.cve_total;
  document.getElementById('m-cve-sub').textContent  = `${d.cve_critical} critical · ${d.cve_high} high`;
  document.getElementById('m-sast').textContent     = d.sast_findings;
  document.getElementById('m-zap').textContent      = d.zap_alerts;
  document.getElementById('m-zap-sub').textContent  = `${d.zap_high} high severity`;
  document.getElementById('m-ai').textContent       = d.ai_provider || 'Claude';
  document.getElementById('aiCalls').textContent    = d.ai_calls || '–';
  document.getElementById('fallbackCount').textContent = d.fallback_count || '0';
  document.getElementById('buildTime').textContent  = new Date(d.timestamp).toLocaleTimeString('fr-FR');
}

function applyDemoStatus() {
  document.getElementById('m-cve').textContent      = '14';
  document.getElementById('m-cve-sub').textContent  = '3 critical · 6 high';
  document.getElementById('m-sast').textContent     = '3';
  document.getElementById('m-sast-sub').textContent = 'Semgrep analysis';
  document.getElementById('m-zap').textContent      = '7';
  document.getElementById('m-zap-sub').textContent  = '2 high severity';
  document.getElementById('m-ai').textContent       = 'Claude';
  document.getElementById('aiCalls').textContent    = '12';
  document.getElementById('fallbackCount').textContent = '0';
  document.getElementById('buildTime').textContent  = new Date().toLocaleTimeString('fr-FR');
}

// ─── Findings ─────────────────────────────────────────────────────────────────
async function fetchFindings() {
  try {
    const r = await fetch('/api/findings');
    if (!r.ok) throw new Error('no server');
    allFindings = await r.json();
  } catch {
    allFindings = DEMO_FINDINGS;
  }
  document.getElementById('findingsBadge').textContent = allFindings.length;
  document.getElementById('tabAll').textContent = `(${allFindings.length})`;
  renderFindings(currentFilter);
}

function filterFindings(filter, tabEl) {
  currentFilter = filter;
  if (tabEl) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    tabEl.classList.add('active');
  }
  renderFindings(filter);
}

function renderFindings(filter) {
  const list = document.getElementById('findingsList');
  let data = allFindings;

  if (filter === 'critical') data = data.filter(f => f.severity === 'critical');
  else if (filter === 'high')  data = data.filter(f => f.severity === 'high');
  else if (['SAST','SCA','DAST'].includes(filter)) data = data.filter(f => f.source === filter);

  if (!data.length) {
    list.innerHTML = '<div class="empty-state"><i class="ti ti-shield-check"></i><br>Aucun finding pour ce filtre</div>';
    return;
  }

  list.innerHTML = '';
  data.forEach(f => {
    const sev = f.severity || 'info';
    const iconMap = { critical: 'ti-alert-triangle', high: 'ti-alert-circle', medium: 'ti-info-circle', info: 'ti-check' };
    const el = document.createElement('div');
    el.className = 'finding flash';
    el.innerHTML = `
      <div class="finding-icon ${sev}"><i class="ti ${iconMap[sev] || 'ti-circle'}"></i></div>
      <div style="flex:1;min-width:0">
        <div class="finding-title">${escHtml(f.title)}</div>
        <div class="finding-meta">${escHtml(f.file || '')}</div>
        ${f.detail ? `<div class="finding-meta" style="margin-top:2px;color:var(--text3)">${escHtml(f.detail.slice(0,100))}${f.detail.length>100?'…':''}</div>` : ''}
        <span class="finding-badge ${sev}">${f.source} · ${sev}</span>
      </div>
    `;
    list.appendChild(el);
  });
}

// ─── Console ──────────────────────────────────────────────────────────────────
const BOOT_LOGS = [
  { ts:'00:01', stage:'PREP', cls:'i', text:'=== ZeroTrust CI/CD Pipeline v2.0 ===', c:'bright' },
  { ts:'00:02', stage:'PREP', cls:'i', text:'Jenkins build agent started', c:'' },
  { ts:'00:05', stage:'PREP', cls:'i', text:'Installing tools: semgrep, trivy, docker...', c:'' },
  { ts:'00:18', stage:'PREP', cls:'s', text:'✓ Python venv ready: /opt/zerotrust-venv', c:'green' },
  { ts:'00:20', stage:'PREP', cls:'s', text:'✓ Ollama client check: mistral:7b available', c:'green' },
  { ts:'00:22', stage:'SAST', cls:'s', text:'Semgrep scan started on test-app/', c:'' },
  { ts:'00:45', stage:'SAST', cls:'a', text:'⚠ SQLi found: app.py:42 — formatted-sql-query', c:'amber' },
  { ts:'00:46', stage:'SAST', cls:'a', text:'⚠ OS Injection: app.py:67 — shell=True', c:'amber' },
  { ts:'00:47', stage:'SAST', cls:'s', text:'Semgrep: 3 findings | Rapport: reports/semgrep-results.json', c:'green' },
  { ts:'01:10', stage:'SCA',  cls:'s', text:'Trivy FS scan: ./test-app', c:'' },
  { ts:'01:42', stage:'SCA',  cls:'e', text:'CVE-2023-44323 Pillow 9.0.0 — CVSS 8.8 CRITICAL', c:'red' },
  { ts:'01:43', stage:'SCA',  cls:'e', text:'CVE-2023-2650 cryptography 3.3.1 — HIGH', c:'red' },
  { ts:'01:44', stage:'SCA',  cls:'e', text:'CVE-2021-33503 urllib3 1.26.4 — HIGH', c:'red' },
  { ts:'01:45', stage:'SCA',  cls:'s', text:'Trivy: 14 CVE total | 3 CRITICAL | 6 HIGH', c:'amber' },
  { ts:'02:01', stage:'AI',   cls:'p', text:'→ Calling Claude API (claude-sonnet-4-5)...', c:'purple' },
  { ts:'02:02', stage:'AI',   cls:'p', text:'→ Provider: CLAUDE [PRIMARY — qualité supérieure]', c:'purple' },
  { ts:'02:03', stage:'AI',   cls:'p', text:'→ Analyzing pipeline: jenkinsfile integrity check...', c:'' },
  { ts:'02:18', stage:'AI',   cls:'s', text:'✓ Anti-tamper: aucune modification malveillante détectée', c:'green' },
  { ts:'02:20', stage:'AI',   cls:'p', text:'→ Remédiation CVE: génération des patches...', c:'purple' },
  { ts:'02:35', stage:'AI',   cls:'s', text:'✓ Patch: Pillow → 10.3.0 (CVE-2023-44323 fixé)', c:'green' },
  { ts:'02:36', stage:'AI',   cls:'s', text:'✓ Patch: SQL paramétrisé pour /user endpoint', c:'green' },
  { ts:'02:37', stage:'AI',   cls:'i', text:'[AUDIT] Provider: claude | Fallback: NOT activated', c:'blue' },
];

function bootConsole() {
  const body = document.getElementById('consoleBody');
  body.innerHTML = '';
  BOOT_LOGS.forEach((l, i) => {
    setTimeout(() => appendLog(l.ts, l.stage, l.cls, l.text, l.c), i * 60);
  });
  setTimeout(() => {
    appendCursor();
  }, BOOT_LOGS.length * 60 + 100);
}

function appendLog(ts, stage, cls, text, c) {
  const body = document.getElementById('consoleBody');
  // Remove old cursor if any
  const old = body.querySelector('.log-cursor-line');
  if (old) old.remove();

  const el = document.createElement('div');
  el.className = 'log-line';
  el.innerHTML = `<span class="log-ts">${ts}</span><span class="log-stage ${cls}">${stage}</span><span class="log-text ${c||''}">${escHtml(text)}</span>`;
  body.appendChild(el);
  body.scrollTop = body.scrollHeight;
}

function appendCursor() {
  const body = document.getElementById('consoleBody');
  const el = document.createElement('div');
  el.className = 'log-line log-cursor-line';
  el.innerHTML = `<span class="log-ts">–</span><span class="log-stage i">AI</span><span class="log-text"><span class="log-cursor"></span></span>`;
  body.appendChild(el);
  body.scrollTop = body.scrollHeight;
}

function clearConsole() {
  document.getElementById('consoleBody').innerHTML = '';
  appendLog('–', 'SYS', 'i', 'Console vidée', 'blue');
  appendCursor();
}

function scrollConsole() {
  const b = document.getElementById('consoleBody');
  b.scrollTop = b.scrollHeight;
}

function copyLogs() {
  const lines = [...document.querySelectorAll('#consoleBody .log-line')]
    .map(l => l.textContent).join('\n');
  navigator.clipboard.writeText(lines).catch(() => {});
  appendLog('–', 'SYS', 's', '✓ Logs copiés dans le presse-papier', 'green');
}

// ─── Fallback simulation ──────────────────────────────────────────────────────
function simulateFallback() {
  fallbackActive = !fallbackActive;
  const claude = document.getElementById('claudeChip');
  const ollama = document.getElementById('ollamaChip');

  if (fallbackActive) {
    claude.className = 'provider-status offline';
    claude.textContent = 'Offline';
    ollama.className = 'provider-status ollama-active';
    ollama.textContent = 'Actif';
    appendLog('now', 'AI', 'e', 'Claude API indisponible — timeout après 30s', 'red');
    setTimeout(() => appendLog('now', 'AI', 'a', '⚡ FALLBACK activé → Ollama local (mistral:7b)', 'amber'), 300);
    setTimeout(() => appendLog('now', 'AI', 'i', '[AUDIT] Provider: ollama | Données traitées LOCALEMENT', 'blue'), 600);
    setTimeout(() => appendLog('now', 'AI', 'p', '→ http://localhost:11434/api/generate ...', 'purple'), 900);
    const fc = document.getElementById('fallbackCount');
    fc.textContent = parseInt(fc.textContent || 0) + 1;
  } else {
    claude.className = 'provider-status ok';
    claude.textContent = 'Actif';
    ollama.className = 'provider-status standby';
    ollama.textContent = 'Standby';
    appendLog('now', 'AI', 's', '✓ Claude API restaurée — retour au provider primaire', 'green');
    appendLog('now', 'AI', 'i', '[AUDIT] Provider: claude | Fallback: désactivé', 'blue');
  }
  appendCursor();
}

// ─── Stage click ──────────────────────────────────────────────────────────────
function stageClicked(stage) {
  appendLog('–', 'UI', 'i', `Stage sélectionné: ${stage.name} [${stage.sub}]`, 'blue');
}

// ─── Download ─────────────────────────────────────────────────────────────────
function downloadFile(filename) {
  appendLog('–', 'DL', 's', `Téléchargement: ${filename}`, 'green');
  window.open(`/reports/${filename}`, '_blank');
}

// ─── Nav views ────────────────────────────────────────────────────────────────
function showView(view) {
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  appendLog('–', 'UI', 'i', `Vue: ${view}`, 'blue');
}

// ─── Utils ────────────────────────────────────────────────────────────────────
function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ─── Demo findings (fallback si pas de vrai serveur) ─────────────────────────
const DEMO_FINDINGS = [
  { source:'SAST', severity:'critical', title:'SQL Injection — /user endpoint',          file:'app.py:42 · f"SELECT … \'{username}\'"',       detail:'Paramètre username injecté directement dans la requête SQL sans échappement.' },
  { source:'SAST', severity:'critical', title:'OS Command Injection — /ping',            file:'app.py:67 · subprocess shell=True',             detail:'Input utilisateur passé à shell=True — RCE possible.' },
  { source:'SCA',  severity:'critical', title:'CVE-2023-44323 — Pillow 9.0.0',           file:'requirements.txt · fix: Pillow>=10.3.0',        detail:'Remote code execution via image malformée. CVSS 8.8.' },
  { source:'SCA',  severity:'high',     title:'CVE-2023-2650 — cryptography 3.3.1',      file:'requirements.txt · fix: cryptography>=41.0.0',  detail:'Denial of service via PKCS12. CVSS 7.5.' },
  { source:'SCA',  severity:'high',     title:'CVE-2021-33503 — urllib3 1.26.4',         file:'requirements.txt · fix: urllib3>=1.26.5',       detail:'Infinite loop via réponse HTTP malformée. CVSS 7.5.' },
  { source:'DAST', severity:'medium',   title:'Missing X-Content-Type-Options',           file:'Tous les endpoints · Header HTTP manquant',     detail:'Ajouter: response.headers["X-Content-Type-Options"] = "nosniff"' },
  { source:'DAST', severity:'medium',   title:'Flask debug mode exposé',                  file:'app.py · debug=True en production',             detail:'Le mode debug expose le debugger Werkzeug. Désactiver en production.' },
  { source:'DAST', severity:'medium',   title:'Missing Content-Security-Policy',          file:'Tous les endpoints · Header CSP absent',        detail:'Risque XSS sans CSP. Configurer flask-talisman ou équivalent.' },
  { source:'DAST', severity:'high',     title:'SQLi confirmée (live) — /user?username=\'', file:'ZAP active scan · Payload: \' OR 1=1--',     detail:'Injection SQL confirmée en runtime par OWASP ZAP.' },
];