/* ═══ ZeroTrust CI Dashboard — dashboard.js ═══ */

const REFRESH_INTERVAL = 8000;
const LOG_MAX_LINES    = 400;

let allFindings       = [];
let currentFilter     = 'all';
let fallbackActive    = false;
let timerInterval     = null;
let jenkinsAvailable  = false;
let lastLogText       = "";
let lastBuildNumber   = null;
let lastBuildFinished = false;
let syncInProgress    = false;

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  appendLog('–', 'SYS', 'i', 'Dashboard initialisé — connexion à Jenkins…', 'blue');
  appendCursor();
  refreshAll();
  fetchHistory();
  setInterval(refreshAll, REFRESH_INTERVAL);
});

// ── Refresh principal ─────────────────────────────────────────────────────────
async function refreshAll() {
  document.getElementById('lastRefresh').textContent =
    'MàJ: ' + new Date().toLocaleTimeString('fr-FR');

  await Promise.all([
    fetchJenkinsStatus(),
    fetchSecurityMetrics(),
    fetchFindings(),
    fetchConsoleLogs(),
  ]);
}

// ── Jenkins Status ────────────────────────────────────────────────────────────
async function fetchJenkinsStatus() {
  try {
    const r = await fetch('/api/jenkins/status');
    const d = await r.json();

    if (!d.jenkins_available) {
      setJenkinsUnavailable(d.error);
      return;
    }

    // Nouveau build détecté → reset console + sync rapports + reset métriques
    if (lastBuildNumber !== null && d.build_number !== lastBuildNumber) {
      lastLogText       = '';
      lastBuildFinished = false;
      document.getElementById('consoleBody').innerHTML = '';
      appendLog('–', 'SYS', 's', `✓ Nouveau build détecté : #${d.build_number}`, 'green');
      resetMetrics();
    }

    // Build vient de se terminer → sync automatique des rapports + refresh history
    if (d.build_finished && !lastBuildFinished && d.build_number === lastBuildNumber) {
      appendLog('–', 'SYS', 'i', `Build #${d.build_number} terminé — synchronisation des rapports…`, 'blue');
      autoSyncReports(d.build_number);
      setTimeout(fetchHistory, 2000);
    }

    // Premier chargement avec build déjà terminé → sync immédiate si rapports absents
    if (lastBuildNumber === null && d.build_finished) {
      autoSyncReports(d.build_number);
    }

    lastBuildNumber   = d.build_number;
    lastBuildFinished = d.build_finished;
    jenkinsAvailable  = true;

    document.getElementById('buildNum').textContent     = `Build #${d.build_number}`;
    document.getElementById('buildTitle').textContent   = d.branch || '–';
    document.getElementById('buildBranch').textContent  = d.branch || '–';
    document.getElementById('commitHash').textContent   = d.commit || '–';
    if (d.timestamp) {
      document.getElementById('buildTime').textContent =
        new Date(d.timestamp).toLocaleTimeString('fr-FR');
    }

    applyBuildStatus(d.build_status);
    startTimerFrom(d.elapsed_sec ?? 0, d.build_status === 'running');

    if (d.stages && d.stages.length > 0) {
      renderPipelineFlow(d.stages, d.done_count, d.stages_count);
    }

    const liveEl = document.getElementById('liveStatus');
    liveEl.className = 'chip ok';
    liveEl.innerHTML = '<span class="dot ok"></span>Jenkins connecté';

  } catch (e) {
    console.error('fetchJenkinsStatus:', e);
    setJenkinsUnavailable('Erreur réseau');
  }
}

// ── Sync automatique des rapports ─────────────────────────────────────────────
async function autoSyncReports(buildNumber) {
  if (syncInProgress) return;
  syncInProgress = true;
  try {
    const r = await fetch('/api/sync-reports');
    const d = await r.json();
    if (d.synced && d.synced.length > 0) {
      appendLog('–', 'SYS', 's', `✓ ${d.synced.length} rapport(s) synchronisé(s) : ${d.synced.join(', ')}`, 'green');
      await Promise.all([fetchSecurityMetrics(), fetchFindings()]);
    } else {
      appendLog('–', 'SYS', 'i', `Sync build #${buildNumber} — aucun rapport disponible encore`, 'blue');
    }
    if (d.errors && d.errors.length > 0) {
      appendLog('–', 'SYS', 'i', `Rapports non disponibles : ${d.errors.join(', ')}`, 'amber');
    }
  } catch (e) {
    appendLog('–', 'SYS', 'e', '✗ Erreur de synchronisation des rapports', 'red');
  } finally {
    syncInProgress = false;
    appendCursor();
  }
}

function setJenkinsUnavailable(msg) {
  jenkinsAvailable = false;
  const liveEl = document.getElementById('liveStatus');
  liveEl.className = 'chip amber';
  liveEl.innerHTML = '<span class="dot warn"></span>Jenkins hors ligne';
  document.getElementById('buildStatus').className = 'chip amber';
  document.getElementById('buildStatus').innerHTML = '<span class="dot warn"></span>Non connecté';
  if (msg) console.warn('[Jenkins]', msg);
}

function applyBuildStatus(status) {
  const el  = document.getElementById('buildStatus');
  const map = {
    running:  { cls: 'chip blue',  dot: '',     label: 'En cours…' },
    success:  { cls: 'chip ok',    dot: 'ok',   label: 'Succès ✓' },
    failure:  { cls: 'chip red',   dot: 'warn', label: 'Échec ✗' },
    aborted:  { cls: 'chip amber', dot: 'warn', label: 'Annulé' },
    unstable: { cls: 'chip amber', dot: 'warn', label: 'Instable' },
  };
  const s = map[status] || map.running;
  el.className = s.cls;
  el.innerHTML = s.dot ? `<span class="dot ${s.dot}"></span>${s.label}` : s.label;
}

// ── Pipeline Flow ─────────────────────────────────────────────────────────────
const STAGE_ICONS = {
  'préparation': 'ti-settings', 'preparation': 'ti-settings', 'setup': 'ti-settings',
  'checkout':    'ti-git-branch',
  'sast':        'ti-code',     'semgrep': 'ti-code',
  'sca':         'ti-package',  'trivy': 'ti-package',
  'anti-tamper': 'ti-shield-lock', 'anti tamper': 'ti-shield-lock', 'tampering': 'ti-shield-lock',
  'remédia':     'ti-robot',    'remediation': 'ti-robot',
  'agents':      'ti-robot',    'rapport ia': 'ti-file-analytics', 'explicatif': 'ti-file-analytics',
  'docker':      'ti-box',      'build': 'ti-box',
  'scan image':  'ti-shield',   'image scan': 'ti-shield',
  'dast':        'ti-antenna',  'zap': 'ti-antenna',
  'cosign':      'ti-certificate', 'signature': 'ti-certificate',
  'rapport pdf': 'ti-file-type-pdf', 'pdf': 'ti-file-type-pdf',
  'security':    'ti-shield-check', 'guard': 'ti-shield-check',
  'deploy':      'ti-rocket',   'production': 'ti-rocket', 'déploiement': 'ti-rocket',
  'staging':     'ti-server',
  'étape':       'ti-circle-dot',
};

function iconForStage(name) {
  const key = (name || '').toLowerCase();
  for (const [k, v] of Object.entries(STAGE_ICONS)) {
    if (key.includes(k)) return v;
  }
  return 'ti-circle-dot';
}

// ── FIX : truncate robuste — ne retourne jamais "Stage" si un vrai nom existe ─
function truncateStageName(name) {
  // Guard : nom null/undefined/vide
  if (!name || typeof name !== 'string' || !name.trim()) return 'Étape ?';

  const raw = name.trim();

  // Retire le préfixe numérique type "0. ", "3a. ", "1b. " etc.
  const cleaned = raw.replace(/^\d+[a-z]?\.\s*/i, '').trim();

  // Si après nettoyage c'est vide, retourne le nom brut tronqué
  const display = cleaned || raw;

  // Tronque à 14 caractères pour tenir dans la boîte 96px
  return display.length > 14 ? display.slice(0, 13) + '…' : display;
}

function renderPipelineFlow(stages, doneCount, total) {
  const track = document.getElementById('flowTrack');
  track.innerHTML = '';

  stages.forEach((s, i) => {
    const icon        = iconForStage(s.name);
    const displayName = truncateStageName(s.name);
    const el          = document.createElement('div');
    el.className      = `stage ${s.status}`;
    // Nom complet visible au survol (tooltip natif)
    el.title          = `${s.name} [${s.status}] — ${s.duration}`;
    el.onclick        = () => stageClicked(s);
    el.innerHTML = `
      <div class="stage-node">
        ${s.status === 'running' ? '<div class="pulse-ring"></div><div class="scan"></div>' : ''}
        <i class="ti ${icon} stage-icon"></i>
        <div class="stage-name">${escHtml(displayName)}</div>
      </div>
      <div class="stage-dur">${s.duration}</div>
    `;
    track.appendChild(el);

    if (i < stages.length - 1) {
      const conn = document.createElement('div');
      conn.className = 'connector';
      const lc = s.status === 'done' ? 'done' : s.status === 'running' ? 'running' : 'waiting';
      conn.innerHTML = `<div class="conn-line ${lc}"></div>`;
      track.appendChild(conn);
    }
  });

  const pct = total > 0 ? Math.round((doneCount / total) * 100) : 0;
  document.getElementById('progressFill').style.width = pct + '%';
}

// ── Timer ─────────────────────────────────────────────────────────────────────
function startTimerFrom(elapsedSec, running) {
  clearInterval(timerInterval);
  const base = Date.now() - elapsedSec * 1000;
  const tick = () => {
    const sec = Math.floor((Date.now() - base) / 1000);
    const m   = String(Math.floor(sec / 60)).padStart(2, '0');
    const s   = String(sec % 60).padStart(2, '0');
    document.getElementById('timer').textContent = `${m}:${s}`;
  };
  tick();
  if (running) timerInterval = setInterval(tick, 1000);
}

// ── Métriques sécurité ────────────────────────────────────────────────────────
async function fetchSecurityMetrics() {
  try {
    const r = await fetch('/api/status');
    const d = await r.json();

    document.getElementById('m-cve').textContent      = d.cve_total      ?? '–';
    document.getElementById('m-cve-sub').textContent  = `${d.cve_critical ?? '–'} critical · ${d.cve_high ?? '–'} high`;
    document.getElementById('m-sast').textContent     = d.sast_findings   ?? '–';
    document.getElementById('m-zap').textContent      = d.zap_alerts      ?? '–';
    document.getElementById('m-zap-sub').textContent  = `${d.zap_high     ?? '–'} high severity`;

    // Ne jamais écraser l'état UI AI si le fallback simulé est actif
    if (!fallbackActive) {
      const provider = (d.ai_provider || 'claude').toUpperCase();
      document.getElementById('m-ai').textContent          = provider;
      document.getElementById('m-ai-provider').textContent = provider;
      document.getElementById('aiCalls').textContent       = d.ai_calls ?? '–';
      document.getElementById('fallbackCount').textContent = d.fallback_count ?? 0;

      const claudeChip = document.getElementById('claudeChip');
      const ollamaChip = document.getElementById('ollamaChip');
      if (claudeChip && claudeChip.className !== 'provider-status ok') {
        claudeChip.className  = 'provider-status ok';
        claudeChip.textContent = 'Actif';
      }
      if (ollamaChip && ollamaChip.className !== 'provider-status standby') {
        ollamaChip.className  = 'provider-status standby';
        ollamaChip.textContent = 'Standby';
      }
    }

    document.getElementById('m-ai-sub').textContent = `${d.ai_calls ?? '–'} calls · ${d.fallback_count ?? 0} fallbacks`;

    if (d.reports_ready) {
      const ready = Object.values(d.reports_ready).filter(Boolean).length;
      const total = Object.keys(d.reports_ready).length;
      const badge = document.getElementById('stagesBadge');
      if (badge) badge.textContent = ready === total ? '✓' : `${ready}/${total}`;
    }
  } catch (e) {
    console.error('fetchSecurityMetrics:', e);
  }
}

// ── Findings ──────────────────────────────────────────────────────────────────
async function fetchFindings() {
  try {
    const r = await fetch('/api/findings');
    allFindings = await r.json();
  } catch (e) {
    allFindings = [];
  }

  const badge  = document.getElementById('findingsBadge');
  const tabAll = document.getElementById('tabAll');
  if (badge)  badge.textContent  = allFindings.length || '0';
  if (tabAll) tabAll.textContent = `(${allFindings.length})`;

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

  if (filter === 'critical')                       data = data.filter(f => f.severity === 'critical');
  else if (filter === 'high')                      data = data.filter(f => f.severity === 'high');
  else if (['SAST','SCA','DAST'].includes(filter)) data = data.filter(f => f.source === filter);

  if (!data.length) {
    const msg = allFindings.length === 0
      ? (jenkinsAvailable
          ? 'Aucun rapport disponible — cliquez sur Refresh ou attendez la fin du build'
          : 'Jenkins hors ligne — rapports indisponibles')
      : 'Aucun finding pour ce filtre ✓';
    list.innerHTML = `<div class="empty-state"><i class="ti ti-shield-check"></i><br>${msg}</div>`;
    return;
  }

  const iconMap = {
    critical: 'ti-alert-triangle',
    high:     'ti-alert-circle',
    medium:   'ti-info-circle',
    info:     'ti-check'
  };
  list.innerHTML = '';

  data.forEach(f => {
    const sev = f.severity || 'info';
    const el  = document.createElement('div');
    el.className = 'finding';
    el.innerHTML = `
      <div class="finding-icon ${sev}"><i class="ti ${iconMap[sev] || 'ti-circle'}"></i></div>
      <div style="flex:1;min-width:0">
        <div class="finding-title">${escHtml(f.title)}</div>
        <div class="finding-meta">${escHtml(f.file || '')}</div>
        ${f.detail ? `<div class="finding-detail">${escHtml(f.detail.slice(0,130))}${f.detail.length > 130 ? '…' : ''}</div>` : ''}
        <span class="finding-badge ${sev}">${f.source} · ${sev}</span>
      </div>
    `;
    list.appendChild(el);
  });
}

// ── Console Jenkins ───────────────────────────────────────────────────────────
async function fetchConsoleLogs() {
  try {
    const r = await fetch('/api/jenkins/logs');
    const d = await r.json();
    if (!d.available || !d.text) return;
    if (d.text === lastLogText)  return;

    lastLogText = d.text;
    const body  = document.getElementById('consoleBody');
    body.innerHTML = '';

    d.text.split('\n').slice(-LOG_MAX_LINES).forEach(raw => {
      if (!raw.trim()) return;
      const p  = parseJenkinsLine(raw);
      const el = document.createElement('div');
      el.className = 'log-line';
      el.innerHTML = `
        <span class="log-ts">${p.ts}</span>
        <span class="log-stage ${p.cls}">${p.stage}</span>
        <span class="log-text ${p.color}">${escHtml(p.text)}</span>
      `;
      body.appendChild(el);
    });

    body.scrollTop = body.scrollHeight;
    appendCursor();
  } catch (e) { /* silencieux */ }
}

function parseJenkinsLine(raw) {
  let ts = '–', stage = 'SYS', cls = 'i', text = raw, color = '';

  const tsM = raw.match(/\[(\d{2}:\d{2}:\d{2})\]/);
  if (tsM) { ts = tsM[1]; text = raw.slice(raw.indexOf(tsM[0]) + tsM[0].length).trim(); }

  const low = text.toLowerCase();
  if      (low.includes('[sast]')  || low.includes('semgrep'))                         { stage = 'SAST';  cls = 'i'; }
  else if (low.includes('[sca]')   || low.includes('trivy'))                           { stage = 'SCA';   cls = 'i'; }
  else if (low.includes('[dast]')  || low.includes('zap'))                             { stage = 'DAST';  cls = 'i'; }
  else if (low.includes('[ai]')    || low.includes('claude') || low.includes('ollama')){ stage = 'AI';    cls = 'p'; }
  else if (low.includes('[audit]'))                                                     { stage = 'AUDIT'; cls = 'i'; }
  else if (low.includes('[pipeline]'))                                                  { stage = 'PIPE';  cls = 'i'; }
  else if (low.includes('error')   || low.includes('failed'))                          { stage = 'ERR';   cls = 'e'; }
  else if (low.includes('stage('))                                                      { stage = 'STGE';  cls = 's'; }

  if      (low.includes('error')   || low.includes('failed') || low.includes('✗'))  color = 'red';
  else if (low.includes('warn')    || low.includes('cve'))                            color = 'amber';
  else if (low.includes('success') || low.includes('✓') || low.includes('done'))     color = 'green';
  else if (low.includes('claude')  || low.includes('ollama') || low.includes('fallback')) color = 'purple';
  else if (low.includes('[pipeline]'))                                                 color = 'blue';
  else if (low.includes('===')     || low.startsWith('+ '))                           color = 'bright';

  return { ts, stage, cls, text, color };
}

// ── Reset métriques au démarrage d'un nouveau build ───────────────────────────
function resetMetrics() {
  ['m-cve','m-sast','m-zap','m-ai'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = '–';
  });
  document.getElementById('m-cve-sub')  && (document.getElementById('m-cve-sub').textContent  = '– critical · – high');
  document.getElementById('m-sast-sub') && (document.getElementById('m-sast-sub').textContent = 'Semgrep analysis');
  document.getElementById('m-zap-sub')  && (document.getElementById('m-zap-sub').textContent  = '– high severity');
  document.getElementById('m-ai-sub')   && (document.getElementById('m-ai-sub').textContent   = '– calls · 0 fallbacks');
  document.getElementById('aiCalls')    && (document.getElementById('aiCalls').textContent    = '–');
  document.getElementById('fallbackCount') && (document.getElementById('fallbackCount').textContent = '0');
  allFindings = [];
  renderFindings('all');
  appendLog('–', 'SYS', 'i', '↺ Métriques réinitialisées — nouveau build en cours', 'blue');
}

// ── Historique des builds ─────────────────────────────────────────────────────
async function fetchHistory() {
  try {
    const r = await fetch('/api/history');
    const data = await r.json();
    renderHistory(data);
  } catch (e) { /* silencieux */ }
}

function renderHistory(builds) {
  const container = document.getElementById('historyList');
  if (!container) return;

  if (!builds || builds.length === 0) {
    container.innerHTML = `<div class="history-empty"><i class="ti ti-history"></i><br>Aucun build archivé</div>`;
    return;
  }

  container.innerHTML = '';
  builds.forEach(b => {
    const statusClass = {
      SUCCESS: 'done', FAILURE: 'fail', UNSTABLE: 'warn', ABORTED: 'warn'
    }[b.build_result] || 'wait';

    const statusIcon  = { done: 'ti-circle-check', fail: 'ti-circle-x', warn: 'ti-alert-circle', wait: 'ti-clock' }[statusClass];
    const statusColor = { done: 'green', fail: 'red', warn: 'amber', wait: '' }[statusClass];

    const date = b.timestamp ? new Date(b.timestamp).toLocaleString('fr-FR', {
      day:'2-digit', month:'2-digit', hour:'2-digit', minute:'2-digit'
    }) : '–';

    const dur = b.duration_ms > 0
      ? `${Math.floor(b.duration_ms/60000)}m${String(Math.floor((b.duration_ms%60000)/1000)).padStart(2,'0')}s`
      : '–';

    const el = document.createElement('div');
    el.className = 'history-item';
    el.innerHTML = `
      <div class="history-header">
        <div class="history-build">
          <i class="ti ${statusIcon} ${statusColor}"></i>
          <span class="history-num">#${b.build_number}</span>
          <span class="history-branch mono">${escHtml(b.branch || '–')}</span>
        </div>
        <span class="history-dur">${dur}</span>
      </div>
      <div class="history-date">${date} · ${escHtml(b.commit || '–')}</div>
      <div class="history-stats">
        <span class="hstat red"><i class="ti ti-bug"></i>${b.cve_total}</span>
        <span class="hstat amber"><i class="ti ti-code"></i>${b.sast_findings}</span>
        <span class="hstat blue"><i class="ti ti-antenna"></i>${b.zap_alerts}</span>
        <span class="hstat purple"><i class="ti ti-brain"></i>${(b.ai_provider||'–').toUpperCase()}</span>
      </div>
    `;
    el.onclick = () => expandHistoryBuild(b, el);
    container.appendChild(el);
  });
}

function expandHistoryBuild(b, el) {
  // toggle detail panel
  const existing = el.querySelector('.history-detail');
  if (existing) { existing.remove(); return; }
  document.querySelectorAll('.history-detail').forEach(d => d.remove());

  const detail = document.createElement('div');
  detail.className = 'history-detail';
  detail.innerHTML = `
    <div class="hdetail-row"><span>CVEs</span><span>${b.cve_total} total · ${b.cve_critical} critical · ${b.cve_high} high</span></div>
    <div class="hdetail-row"><span>SAST</span><span>${b.sast_findings} findings</span></div>
    <div class="hdetail-row"><span>ZAP</span><span>${b.zap_alerts} alerts · ${b.zap_high} high</span></div>
    <div class="hdetail-row"><span>AI</span><span>${(b.ai_provider||'–').toUpperCase()} · ${b.ai_calls} calls · ${b.fallback_count} fallbacks</span></div>
    <div class="hdetail-downloads">
      <a href="/api/history/${b.build_number}/reports/trivy-report.json" target="_blank" class="hdl-btn"><i class="ti ti-package"></i> Trivy</a>
      <a href="/api/history/${b.build_number}/reports/semgrep-results.json" target="_blank" class="hdl-btn"><i class="ti ti-code"></i> Semgrep</a>
      <a href="/api/history/${b.build_number}/reports/rapport-zerotrust.pdf" target="_blank" class="hdl-btn"><i class="ti ti-file-type-pdf"></i> PDF</a>
    </div>
  `;
  el.appendChild(detail);
}

// ── Trigger pipeline ──────────────────────────────────────────────────────────
async function triggerPipeline(btn) {
  if (btn) { btn.disabled = true; btn.textContent = 'Lancement…'; }
  try {
    const r = await fetch('/api/jenkins/trigger', { method: 'POST' });
    const d = await r.json();
    if (d.success) {
      appendLog('–', 'SYS', 's', `✓ ${d.message}`, 'green');
      lastBuildFinished = false;
      resetMetrics();
      setTimeout(refreshAll, 3000);
    } else {
      appendLog('–', 'SYS', 'e', `✗ Erreur : ${d.error}`, 'red');
    }
  } catch (e) {
    appendLog('–', 'SYS', 'e', '✗ Impossible de contacter le serveur', 'red');
  } finally {
    if (btn) { btn.disabled = false; btn.innerHTML = '<i class="ti ti-player-play"></i>Lancer pipeline'; }
    appendCursor();
  }
}

// ── Sync manuelle ─────────────────────────────────────────────────────────────
async function manualSync() {
  appendLog('–', 'SYS', 'i', 'Synchronisation manuelle des rapports…', 'blue');
  await autoSyncReports(lastBuildNumber);
}

// ── Simulate Fallback ─────────────────────────────────────────────────────────
function simulateFallback() {
  fallbackActive = !fallbackActive;

  const claude      = document.getElementById('claudeChip') || document.querySelectorAll('.provider-status')[0];
  const ollama      = document.getElementById('ollamaChip') || document.querySelectorAll('.provider-status')[1];
  const mAi         = document.getElementById('m-ai');
  const mAiProvider = document.getElementById('m-ai-provider');
  const fc          = document.getElementById('fallbackCount');

  if (fallbackActive) {
    if (claude) { claude.className = 'provider-status offline';      claude.textContent = 'Offline'; }
    if (ollama) { ollama.className = 'provider-status ollama-active'; ollama.textContent = 'Actif'; }
    if (mAi)         mAi.textContent         = 'OLLAMA';
    if (mAiProvider) mAiProvider.textContent = 'OLLAMA';
    if (fc)          fc.textContent          = String(parseInt(fc.textContent || '0') + 1);
    appendLog('–', 'AI', 'e', '✗ Claude API indisponible — timeout réseau simulé', 'red');
    setTimeout(() => appendLog('–', 'AI', 'i', '⚡ FALLBACK → Ollama Mistral 7B (local)', 'amber'), 300);
    setTimeout(() => appendLog('–', 'AI', 'i', '[AUDIT] provider=ollama | données traitées localement', 'blue'), 600);
  } else {
    if (claude) { claude.className = 'provider-status ok';      claude.textContent = 'Actif'; }
    if (ollama) { ollama.className = 'provider-status standby'; ollama.textContent = 'Standby'; }
    if (mAi)         mAi.textContent         = 'CLAUDE';
    if (mAiProvider) mAiProvider.textContent = 'CLAUDE';
    appendLog('–', 'AI', 's', '✓ Claude API restaurée — provider primaire actif', 'green');
    setTimeout(() => appendLog('–', 'AI', 'i', '[AUDIT] provider=claude | fallback désactivé', 'blue'), 300);
  }
  appendCursor();
}

// ── Console helpers ───────────────────────────────────────────────────────────
function appendLog(ts, stage, cls, text, color) {
  const body = document.getElementById('consoleBody');
  body.querySelector('.log-cursor-line')?.remove();
  const el = document.createElement('div');
  el.className = 'log-line';
  el.innerHTML = `
    <span class="log-ts">${ts}</span>
    <span class="log-stage ${cls}">${stage}</span>
    <span class="log-text ${color || ''}">${escHtml(text)}</span>
  `;
  body.appendChild(el);
  while (body.children.length > LOG_MAX_LINES) body.removeChild(body.firstChild);
  body.scrollTop = body.scrollHeight;
}

function appendCursor() {
  const body = document.getElementById('consoleBody');
  body.querySelector('.log-cursor-line')?.remove();
  const el = document.createElement('div');
  el.className = 'log-line log-cursor-line';
  el.innerHTML = `<span class="log-ts">–</span><span class="log-stage i">–</span><span class="log-text"><span class="log-cursor"></span></span>`;
  body.appendChild(el);
  body.scrollTop = body.scrollHeight;
}

function clearConsole() {
  document.getElementById('consoleBody').innerHTML = '';
  lastLogText = '';
  appendLog('–', 'SYS', 'i', 'Console vidée', 'blue');
  appendCursor();
}

function scrollConsole() { document.getElementById('consoleBody').scrollTop = 99999; }

function copyLogs() {
  const lines = [...document.querySelectorAll('#consoleBody .log-line')]
    .map(l => l.textContent.trim()).join('\n');
  navigator.clipboard.writeText(lines).catch(() => {});
  appendLog('–', 'SYS', 's', '✓ Logs copiés', 'green');
}

// ── Navigation ────────────────────────────────────────────────────────────────
function showView(view, evt) {
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  if (evt?.currentTarget) evt.currentTarget.classList.add('active');
}

function stageClicked(stage) {
  appendLog('–', 'UI', 'i', `Stage: ${stage.name} [${stage.status}] — ${stage.duration}`, 'blue');
}

function downloadFile(filename) { window.open(`/reports/${filename}`, '_blank'); }

// ── Utils ─────────────────────────────────────────────────────────────────────
function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}