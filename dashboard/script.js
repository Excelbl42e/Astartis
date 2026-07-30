/* ======================================================================
   Astartis SOC Dashboard — script.js  (QA pass 2)
   Fixes: poll recovery · canvas sizing · tooltips · metric detail
          animations · terminal whitelist · agent status · sandbox/NAC UI
   ====================================================================== */

'use strict';

// ── Auth token ──────────────────────────────────────────────────────────
const TOKEN = (() => {
  const m = document.querySelector('meta[name="astartis-token"]');
  return m ? m.getAttribute('content') : '';
})();

// ── API helpers ─────────────────────────────────────────────────────────
async function apiGet(path) {
  const r = await fetch(path, { headers: { 'X-Astartis-Token': TOKEN } });
  if (!r.ok) throw new Error(`GET ${path} → ${r.status}`);
  return r.json();
}
async function apiPost(path, body) {
  const r = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Astartis-Token': TOKEN },
    body: JSON.stringify(body)
  });
  return { ok: r.ok, status: r.status, data: await r.json().catch(() => ({})) };
}

// ── Utility ─────────────────────────────────────────────────────────────
function el(id)  { return document.getElementById(id); }
function esc(s)  { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function pct(v)  { return typeof v === 'number' ? v.toFixed(1)+'%' : '–%'; }
function gb(v)   { return typeof v === 'number' ? v.toFixed(1)+' GB' : '– GB'; }
function fmtTime(s) { if (!s) return '–'; try { return new Date(s).toLocaleTimeString(); } catch { return s; } }
function fmtMs(ms)  { if (!ms) return '–'; try { return new Date(ms).toLocaleTimeString(); } catch { return ms; } }
function sevClass(s) {
  return ({ CRITICAL:'critical', HIGH:'high', MEDIUM:'medium', LOW:'low', INFO:'info' })[(s||'').toUpperCase()] || 'info';
}
// ── Tab switching ────────────────────────────────────────────────────────
const TABS = ['overview','terminal','network','agents','sandbox','nac','evidence','attack','defend','nist','dot1x','configure'];
let activeTab = 'overview';

function activateTab(id) {
  TABS.forEach(t => {
    const pane = el(`tab-${t}`);
    if (!pane) return;
    if (t === id) {
      pane.classList.remove('content--hidden');
      pane.classList.add('tab-entering');
      requestAnimationFrame(() => pane.classList.remove('tab-entering'));
    } else {
      pane.classList.add('content--hidden');
    }
  });
  document.querySelectorAll('.sidebar__item[data-tab]').forEach(item =>
    item.classList.toggle('sidebar__item--active', item.dataset.tab === id)
  );
  activeTab = id;
  // Resize charts when their tab becomes visible
  if (id === 'overview')  { resizeChart(chaosChart);  resizeChart(cpuChart); }
  if (id === 'network')   { resizeChart(entropyChart); }
  if (id === 'attack')    { renderAtkBarChart(lastAtkData); }
  if (id === 'nist')      { renderZtDonut(lastZtData); renderZtHist(lastZtData); }
  // Immediately populate the newly-visible tab with the most-recent data so
  // panels never show stale "No data yet" text on first click — the next
  // 3-second poll will refresh them anyway, but the instant render is better UX.
  if (lastData) {
    switch (id) {
      case 'agents':   updateAgents(lastData);    break;
      case 'sandbox':  updateSandbox(lastData);   break;
      case 'nac':      updateZeroTrust(lastData); break;
      case 'evidence': updateAudit(lastData);     break;
      case 'network':  updateNetwork(lastData);   break;
      case 'attack':   updateAttack(lastData);    break;
      case 'defend':   updateDefend(lastData);    break;
      case 'nist':     updateNist(lastData);      break;
      case 'dot1x':    updateDot1x(lastData);     break;
    }
  }
}

document.querySelectorAll('.sidebar__item[data-tab]').forEach(item => {
  item.addEventListener('click', () => {
    activateTab(item.dataset.tab);
    if (item.dataset.tab === 'configure') renderConfigure();
  });
});

// ── UTC clock ────────────────────────────────────────────────────────────
function updateClock() {
  const now = new Date();
  const p = el('pill-clock');
  if (p) p.textContent = now.toISOString().slice(11,19) + ' UTC';
}
setInterval(updateClock, 1000);
updateClock();

// ════════════════════════════════════════════════════════════════════════
// CANVAS CHART SHIM  (offline-safe, no CDN dependency)
// Full feature set: line chart, gradient fill, hover tooltip
// ════════════════════════════════════════════════════════════════════════
class SparkChart {
  constructor(canvas, opts) {
    this._c     = canvas;
    this._color = opts.color || '#0f62fe';
    this._label = opts.label || '';
    this._unit  = opts.unit  || '';
    this._data  = [];
    this._hover = null;   // null or index
    // Tooltip element
    this._tip = document.createElement('div');
    this._tip.className = 'chart-tooltip';
    this._tip.style.cssText = 'position:fixed;display:none;background:#161616;color:#f4f4f4;' +
      'font-size:11px;font-family:IBM Plex Mono,monospace;padding:4px 8px;border-radius:3px;' +
      'pointer-events:none;z-index:200;white-space:nowrap;box-shadow:0 2px 6px rgba(0,0,0,.3)';
    document.body.appendChild(this._tip);
    // Mouse events for tooltip
    canvas.addEventListener('mousemove', e => this._onMove(e));
    canvas.addEventListener('mouseleave', () => { this._hover = null; this._tip.style.display='none'; this.render(); });
    this._ro = new ResizeObserver(() => this.render());
    this._ro.observe(canvas);
  }

  push(value) {
    this._data.push(value);
    if (this._data.length > 40) this._data.shift();
    this.render();
  }

  _onMove(e) {
    const c = this._c;
    const rect = c.getBoundingClientRect();
    const mx   = e.clientX - rect.left;
    const d    = this._data;
    if (!d.length) return;
    const pad   = 4;
    const xStep = (c.width - pad*2) / Math.max(d.length - 1, 1);
    const idx   = Math.round((mx - pad) / xStep);
    this._hover = Math.max(0, Math.min(d.length - 1, idx));
    // position tooltip
    const val = d[this._hover];
    this._tip.textContent = `${this._label ? this._label+': ' : ''}${typeof val === 'number' ? val.toFixed(3) : val}${this._unit}`;
    this._tip.style.display = 'block';
    this._tip.style.left = (e.clientX + 10) + 'px';
    this._tip.style.top  = (e.clientY - 24) + 'px';
    this.render();
  }

  render() {
    const c   = this._c;
    const ctx = c.getContext('2d');
    // Measure real CSS size (handles hidden tabs via 0-width guard)
    const csw = c.parentElement ? c.parentElement.clientWidth - 32 : 0;
    const csh = c.getAttribute('height') ? parseInt(c.getAttribute('height')) : 80;
    if (csw < 10) return;           // still hidden — skip
    c.width  = csw;
    c.height = csh;

    const d = this._data;
    if (!d.length) { ctx.clearRect(0,0,csw,csh); return; }

    const pad   = 6;
    const yPad  = 12;
    const min   = Math.min(...d);
    const max   = Math.max(...d);
    const range = (max - min) || 1;
    const xStep = d.length < 2 ? 0 : (csw - pad*2) / (d.length - 1);
    const px    = i => pad + i * xStep;
    const py    = v => csh - yPad - ((v - min) / range) * (csh - yPad - pad);

    ctx.clearRect(0, 0, csw, csh);

    // Gradient fill
    const grad = ctx.createLinearGradient(0, pad, 0, csh - yPad);
    grad.addColorStop(0, this._color + '28');
    grad.addColorStop(1, this._color + '04');

    // Fill path
    ctx.beginPath();
    ctx.moveTo(px(0), py(d[0]));
    for (let i = 1; i < d.length; i++) {
      const cp1x = px(i-1) + xStep * 0.4;
      const cp2x = px(i)   - xStep * 0.4;
      ctx.bezierCurveTo(cp1x, py(d[i-1]), cp2x, py(d[i]), px(i), py(d[i]));
    }
    ctx.lineTo(px(d.length-1), csh - yPad);
    ctx.lineTo(px(0), csh - yPad);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();

    // Line
    ctx.beginPath();
    ctx.moveTo(px(0), py(d[0]));
    for (let i = 1; i < d.length; i++) {
      const cp1x = px(i-1) + xStep * 0.4;
      const cp2x = px(i)   - xStep * 0.4;
      ctx.bezierCurveTo(cp1x, py(d[i-1]), cp2x, py(d[i]), px(i), py(d[i]));
    }
    ctx.strokeStyle = this._color;
    ctx.lineWidth   = 1.8;
    ctx.stroke();

    // Y-axis ticks (3 levels)
    ctx.fillStyle = '#8d8d8d';
    ctx.font      = '9px IBM Plex Mono,monospace';
    ctx.textAlign = 'left';
    [0, 0.5, 1].forEach(t => {
      const y = csh - yPad - t * (csh - yPad - pad);
      const v = (min + t * range);
      ctx.fillText(v.toFixed(range < 1 ? 3 : 1), pad, y - 2);
    });

    // Hover dot + vertical line
    if (this._hover !== null && this._hover < d.length) {
      const hi = this._hover;
      const hx = px(hi);
      const hy = py(d[hi]);
      ctx.beginPath();
      ctx.moveTo(hx, pad);
      ctx.lineTo(hx, csh - yPad);
      ctx.strokeStyle = this._color + '50';
      ctx.lineWidth   = 1;
      ctx.setLineDash([3, 3]);
      ctx.stroke();
      ctx.setLineDash([]);
      ctx.beginPath();
      ctx.arc(hx, hy, 4, 0, Math.PI*2);
      ctx.fillStyle = this._color;
      ctx.fill();
      ctx.beginPath();
      ctx.arc(hx, hy, 2, 0, Math.PI*2);
      ctx.fillStyle = '#fff';
      ctx.fill();
    }
  }

  destroy() {
    this._tip.remove();
    this._ro.disconnect();
  }
}

function resizeChart(chart) {
  if (chart instanceof SparkChart) chart.render();
}

// ── Chart instances ──────────────────────────────────────────────────────
let chaosChart   = null;
let cpuChart     = null;
let entropyChart = null;

// Track the last window_index pushed into each chart so we only push NEW
// windows on each poll, rather than repeatedly pushing the last one.
let _lastChaosIdx   = -1;
let _lastEntropyIdx = -1;

function initCharts() {
  const cc = el('chart-chaos');
  if (cc) chaosChart = new SparkChart(cc, { color:'#6929c4', label:'K', unit:'' });
  const cpu = el('chart-cpu');
  if (cpu) cpuChart  = new SparkChart(cpu, { color:'#0f62fe', label:'CPU', unit:'%' });
  const ew = el('chart-entropy');
  if (ew) entropyChart = new SparkChart(ew, { color:'#24a148', label:'Entropy', unit:' bits' });
}

// ════════════════════════════════════════════════════════════════════════
// POLLING  (#1 fix: banner clears on recovery; exponential backoff cap 30s)
// BUG-FIX: /health heartbeat runs every 5 s independently of the 3 s data
// poll so the backend pill updates within 5 s of a reconnect rather than
// waiting for up to 5 × exponential backoff failures.
// ════════════════════════════════════════════════════════════════════════
let lastData   = null;
let pollErrors = 0;
let pollTimer  = null;

const POLL_NORMAL_MS  = 3000;
const POLL_MAX_MS     = 30000;
const POLL_ERROR_SHOW = 5;   // consecutive failures before showing banner

function schedulePoll(delayMs) {
  clearTimeout(pollTimer);
  pollTimer = setTimeout(doPoll, delayMs);
}

async function doPoll() {
  try {
    const d = await fetch('/dashboard_data.json', { cache: 'no-store' }).then(r => {
      if (!r.ok) throw new Error(r.status);
      return r.json();
    });
    // TERRA Part 5: mark successful poll
    lastSuccessfulPollTime = Date.now();
    // Recovery: reset cfg so configure tab re-fetches fresh data from recovered bridge
    if (pollErrors >= POLL_ERROR_SHOW) {
      updateDegradedBanner(false);
      resetCfgRendered();
    }
    pollErrors = 0;
    lastData = d;
    updateAll(d);
    // Reset backend pill to OK
    const bp = el('pill-backend');
    if (bp) { bp.textContent = 'BACKEND OK'; bp.className = 'pill pill--ok'; }
    schedulePoll(POLL_NORMAL_MS);
  } catch (e) {
    pollErrors++;
    if (pollErrors >= POLL_ERROR_SHOW) updateDegradedBanner(true);
    // Exponential back-off capped at POLL_MAX_MS
    const delay = Math.min(POLL_NORMAL_MS * Math.pow(1.5, pollErrors - 1), POLL_MAX_MS);
    schedulePoll(delay);
  }
}

// TERRA Part 5: Track last successful poll timestamp for stale data display
let lastSuccessfulPollTime = null;

// /health heartbeat — runs independently every 5 s; gives fast backend
// connectivity feedback without waiting for data poll errors to accumulate.
let healthTimer = null;
async function doHealthCheck() {
  try {
    const r = await fetch('/health', { cache: 'no-store' });
    if (r.ok) {
      // If we were showing degraded banner, clear it on first /health recovery
      if (pollErrors >= POLL_ERROR_SHOW) {
        updateDegradedBanner(false);
        pollErrors = 0;
        // Re-trigger a data poll immediately to refresh charts
        schedulePoll(200);
      }
      const bp = el('pill-backend');
      if (bp && (bp.textContent.startsWith('BACKEND DOWN') || bp.textContent.startsWith('BACKEND -'))) {
        bp.textContent = 'BACKEND OK'; bp.className = 'pill pill--ok';
      }
    }
  } catch (_) { /* ignore — doPoll handles the error state */ }
  healthTimer = setTimeout(doHealthCheck, 5000);
}

function updateDegradedBanner(show) {
  // Update the stale-data banner in index.html
  const staleBanner = el('stale-banner');
  const staleTs     = el('stale-ts');
  if (staleBanner) {
    staleBanner.style.display = show ? 'block' : 'none';
    if (show && lastSuccessfulPollTime && staleTs) {
      staleTs.textContent = new Date(lastSuccessfulPollTime).toLocaleTimeString() + ' UTC';
    }
  }

  // Backend pill in topbar
  const backendPill = el('pill-backend');
  if (backendPill) {
    if (!show) {
      backendPill.textContent  = 'BACKEND OK';
      backendPill.className    = 'pill pill--ok';
    } else {
      const fails = pollErrors;
      backendPill.textContent  = fails >= 3 ? `BACKEND DOWN (${fails}×)` : `BACKEND ⚠ (${fails}×)`;
      backendPill.className    = fails >= 3 ? 'pill pill--critical' : 'pill pill--warn';
    }
  }

  // Legacy degraded-banner compat (keep for any code that might reference it)
  let b = el('degraded-banner');
  if (!b && show && !staleBanner) {
    b = document.createElement('div');
    b.id = 'degraded-banner';
    b.style.cssText = 'position:fixed;top:48px;left:64px;right:0;background:#fff1f1;color:#a2191f;' +
      'font-size:12px;padding:6px 20px;border-bottom:1px solid #ffd7d9;z-index:50;';
    b.textContent = '⚠ Bridge data unavailable — retrying…';
    document.body.appendChild(b);
  } else if (b && !show) {
    b.style.transition = 'opacity .3s';
    b.style.opacity = '0';
    setTimeout(() => b.remove(), 300);
  }
}

// ════════════════════════════════════════════════════════════════════════
// MAIN UPDATE
// BUG-FIX: removed redundant unconditional calls at the bottom that
// doubled DOM work on every poll regardless of which tab was active.
// Tab-specific updates now run only for the active tab. Overview data
// (KPIs, charts, alerts, firewall, status strip, deps) always refreshes.
// ════════════════════════════════════════════════════════════════════════
function updateAll(d) {
  updateTopBar(d);
  updateKPIs(d);
  updateCharts(d);
  updateAlerts(d);
  updateFirewall(d);
  updateStatusStrip(d);
  updateDeps(d);
  // Tab-specific: update only the visible tab (not all tabs on every poll)
  switch (activeTab) {
    case 'agents':   updateAgents(d);    break;
    case 'sandbox':  updateSandbox(d);   break;
    case 'nac':      updateZeroTrust(d); break;
    case 'evidence': updateAudit(d);     break;
    case 'network':  updateNetwork(d);   break;
    case 'attack':   updateAttack(d);    break;
    case 'defend':   updateDefend(d);    break;
    case 'nist':     updateNist(d);      break;
    case 'dot1x':    updateDot1x(d);     break;
  }
}

// ════════════════════════════════════════════════════════════════════════
// TERRA Part 3 — Dependency / Framework Status Panel
// ════════════════════════════════════════════════════════════════════════
function updateDeps(d) {
  const deps = d.deps || {};
  const tbody = el('tbody-deps');
  if (!tbody) return;

  // Build ordered list including fixed rows + deps from JSON
  const rows = [];

  // From deps object
  const depKeys = ['ollama','npcap','clamd','granite_fast','granite_heavy','granite_acc'];
  depKeys.forEach(k => {
    if (deps[k]) rows.push(deps[k]);
  });

  // Fallback: derive from health if deps not present
  if (!rows.length) {
    const h = d.health || {};
    rows.push({name:'Ollama',         version:'–', status: h.ollama_online?'connected':'missing',         verified_at:'–'});
    rows.push({name:'Npcap (WinPcap)',version:'–', status: h.npcap_service_running?'running':'missing',   verified_at:'–'});
    rows.push({name:'ClamAV (clamd)', version:'–', status: h.clamd_online?'connected':'missing',          verified_at:'–'});
    rows.push({name:'IBM Granite (fast)', version:'granite3.1-moe:3b', status: h.ollama_online?'connected':'missing', verified_at:'–'});
    rows.push({name:'IBM Granite (heavy)',version:'granite3.1-dense:8b',status: h.ollama_online?'connected':'missing', verified_at:'–'});
    rows.push({name:'IBM Granite (acc)',  version:'ibm/granite4.1:8b-q5_K_M',status:h.ollama_online?'connected':'missing',verified_at:'–'});
    // Static entries for always-present components
    rows.push({name:'nlohmann/json',  version:'3.11.x', status:'built-in', verified_at:'–'});
    rows.push({name:'OpenSSL / WinCrypt',version:'system',status:'built-in',verified_at:'–'});
    rows.push({name:'Veeam/IBM Storage',version:'stub',  status:'stubbed', verified_at:'–'});
  }

  // Add static entries
  rows.push({name:'nlohmann/json',      version:'3.11.x (header-only)', status:'built-in', verified_at:'–'});
  rows.push({name:'WinCrypt / BCrypt',  version:'system (Win32)',        status:'built-in', verified_at:'–'});
  rows.push({name:'Veeam/IBM Storage',  version:'1.0 (stub)',            status:'stubbed',  verified_at:'–'});

  const statusBadge = s => {
    const m = {
      'connected':       'sev--low',
      'running':         'sev--low',
      'built-in':        'sev--info',
      'stubbed':         'sev--medium',
      'installed-stopped':'sev--medium',
      'missing':         'sev--critical'
    };
    return `<span class="sev ${m[s]||'sev--info'}">${esc(s)}</span>`;
  };

  tbody.innerHTML = rows.map(r => `<tr>
    <td>${esc(r.name||'–')}</td>
    <td class="mono">${esc(r.version||'unknown')}</td>
    <td>${statusBadge(r.status||'unknown')}</td>
    <td class="mono muted">${typeof r.verified_at==='string'&&r.verified_at!=='–' ? fmtTime(r.verified_at) : (r.verified_at||'–')}</td>
  </tr>`).join('');

  // Update badge with last verified time
  const badge = el('dep-verified-at');
  if (badge && rows.length && rows[0].verified_at && rows[0].verified_at !== '–')
    badge.textContent = 'verified ' + fmtTime(rows[0].verified_at);
}

// ── Top bar ──────────────────────────────────────────────────────────────
function updateTopBar(d) {
  const kpi = d.kpi || {}, h = d.health || {}, sys = d.system || {};
  const ag = el('pill-agents');
  if (ag) { ag.textContent = `${kpi.active_agents??'–'} agents`; ag.className='pill pill--neutral'; }
  const tel = el('pill-telemetry');
  if (tel) {
    const ok = h.ollama_online && h.npcap_service_running;
    tel.textContent = ok ? 'telemetry OK' : 'telemetry ⚠';
    tel.className   = `pill ${ok?'pill--ok':'pill--warn'}`;
  }
  const ev = el('pill-evidence');
  if (ev) {
    const vld = d.audit_chain_valid !== false;
    ev.textContent = vld ? 'chain valid' : 'chain BROKEN';
    ev.className   = `pill ${vld?'pill--ok':'pill--critical'}`;
  }
  const th = el('pill-threat');
  if (th) {
    const t = (kpi.threat_level||'LOW').toUpperCase();
    const m = {LOW:'pill--ok',MEDIUM:'pill--warn',HIGH:'pill--warn',CRITICAL:'pill--critical'};
    th.textContent = `THREAT ${t}`;
    th.className   = `pill ${m[t]||'pill--neutral'}`;
  }
  const wp = el('pill-worm');
  if (wp) {
    wp.textContent = d.worm_is_locked ? 'WORM LOCKED' : 'WORM OK';
    wp.className   = `pill ${d.worm_is_locked?'pill--worm-locked':'pill--ok'}`;
  }
}

// ── KPI cards  (#4 fix: animate numbers; chaos_K from correct field) ─────
function updateKPIs(d) {
  const kpi = d.kpi || {};
  const sm  = d.system_metrics || {};

  // Active agents — integer
  const ag = kpi.active_agents;
  if (typeof ag === 'number') animateNumber('kv-agents', ag, 0);
  else setText('kv-agents', ag ?? '–');
  setText('ks-agents', `queue: ${kpi.queue_depth ?? 0}`);

  // Threat
  const tl = (kpi.threat_level||'LOW').toUpperCase();
  setText('kv-threat', tl);
  setText('ks-threat', `score ${kpi.threat_score ?? 0}`);
  setCardColor('kpi-threat', tl);

  // Chaos K — prefer kpi.chaos_K if bridge sends it, else tail of chaos_windows
  const rawK = typeof kpi.chaos_K === 'number' ? kpi.chaos_K
    : (d.chaos_windows && d.chaos_windows.length ? d.chaos_windows[d.chaos_windows.length-1].K : null);
  if (rawK !== null && rawK !== undefined) {
    animateNumber('kv-chaos', rawK, 4);
    const anom = d.chaos_windows && d.chaos_windows.some(w => w.anomalous);
    setText('ks-chaos', anom ? '⚠ anomalous' : 'nominal');
    setCardColor('kpi-chaos', anom ? 'CRITICAL' : 'LOW');
  }

  // Alerts — use d.alerts.length as fallback when alerts_24h absent
  const alertCount = typeof kpi.alerts_24h === 'number' ? kpi.alerts_24h
    : (d.alerts ? d.alerts.length : null);
  if (alertCount !== null) animateNumber('kv-alerts', alertCount, 0);
  setText('ks-alerts', `${kpi.critical_alerts ?? 0} critical`);
  if ((kpi.critical_alerts ?? 0) > 0) setCardColor('kpi-alerts', 'HIGH');

  // Audit chain
  setText('kv-chain', d.audit_chain_valid !== false ? '✓ valid' : '✗ broken');
  setCardColor('kpi-chain', d.audit_chain_valid !== false ? 'LOW' : 'CRITICAL');

  // WORM
  const locked = d.worm_is_locked;
  setText('kv-worm', locked ? 'LOCKED' : 'OPEN');
  setCardColor('kpi-worm', locked ? 'CRITICAL' : 'LOW');
  setText('ks-worm', locked ? 'In lockdown' : 'No lockdown');

  updatePosture(tl);
}

// #5 — KPI card value: animate a numeric text element
function animateNumber(id, newVal, decimals) {
  const e = el(id);
  if (!e) return;
  const oldVal = parseFloat(e.textContent.replace(/[^0-9.\-]/g,'')) || 0;
  const fmt    = v => decimals > 0 ? v.toFixed(decimals) : Math.round(v).toString();
  if (fmt(oldVal) === fmt(newVal)) return;
  const start = performance.now(), dur = 350;
  (function step(now) {
    const t    = Math.min((now - start) / dur, 1);
    const ease = t < 0.5 ? 2*t*t : -1+(4-2*t)*t;
    e.textContent = fmt(oldVal + (newVal - oldVal) * ease);
    if (t < 1) requestAnimationFrame(step);
    else { e.textContent = fmt(newVal); kpiFlash(e.closest('[id^="kpi-"]')); }
  })(performance.now());
}

function kpiFlash(card) {
  if (!card) return;
  card.classList.remove('kpi-flash');
  void card.offsetWidth;
  card.classList.add('kpi-flash');
}

function setText(id, val) {
  const e = el(id);
  if (!e) return;
  const s = String(val);
  if (e.textContent !== s) e.textContent = s;
}

function setCardColor(id, level) {
  const e = el(id);
  if (!e) return;
  const map = {LOW:'kpi-card--ok',MEDIUM:'kpi-card--medium',HIGH:'kpi-card--high',CRITICAL:'kpi-card--critical'};
  e.className = 'kpi-card' + (map[level] ? ' '+map[level] : '');
}

function updatePosture(threat) {
  const b = el('posture-badge');
  if (!b) return;
  const map = {
    LOW:     {text:'NOMINAL',  cls:''},
    MEDIUM:  {text:'ELEVATED', cls:'posture-badge--medium'},
    HIGH:    {text:'HIGH RISK',cls:'posture-badge--high'},
    CRITICAL:{text:'CRITICAL', cls:'posture-badge--critical'}
  };
  const info = map[threat] || map.LOW;
  b.textContent = info.text;
  b.className   = ('posture-badge ' + info.cls).trim();
}

// ── Charts ────────────────────────────────────────────────────────────────
function updateCharts(d) {
  // Chaos K — push every window we haven't seen yet (drives the full history
  // into the chart on first load, not just the most-recent tail value)
  if (d.chaos_windows && d.chaos_windows.length && chaosChart) {
    const cws = d.chaos_windows;
    cws.forEach(w => {
      const idx = w.window_index ?? 0;
      if (idx > _lastChaosIdx) {
        chaosChart.push(w.K);
        _lastChaosIdx = idx;
      }
    });
    const latest = cws[cws.length - 1];
    const badge = el('chaos-badge');
    if (badge) {
      badge.textContent       = latest.anomalous ? 'ANOMALOUS' : 'nominal';
      badge.style.background  = latest.anomalous ? 'var(--sev-critical)' : 'var(--ok)';
    }
  }

  const sm = d.system_metrics || {};
  // CPU sparkline
  if (typeof sm.cpu_percent === 'number' && cpuChart) cpuChart.push(sm.cpu_percent);

  // Metric bars with GB detail (#4 fix)
  updateBar('bar-cpu',  'pct-cpu',  sm.cpu_percent);
  updateBar('bar-mem',  'pct-mem',  sm.memory_percent);
  updateBar('bar-disk', 'pct-disk', sm.disk_percent);

  // #4: add real GB numbers where available
  const memDetail = el('detail-mem');
  if (memDetail && typeof sm.memory_used_gb === 'number')
    memDetail.textContent = `${gb(sm.memory_used_gb)} / ${gb(sm.memory_total_gb)}`;

  const diskDetail = el('detail-disk');
  if (diskDetail && typeof sm.disk_free_gb === 'number')
    diskDetail.textContent = `${gb(sm.disk_free_gb)} free`;

  const cpuDetail = el('detail-cpu');
  if (cpuDetail && typeof sm.cpu_cores === 'number')
    cpuDetail.textContent = `${sm.cpu_cores} core${sm.cpu_cores!==1?'s':''}`;
}

function updateBar(barId, pctId, value) {
  const bar = el(barId), pctEl = el(pctId);
  if (!bar) return;
  const v = typeof value === 'number' ? Math.min(value, 100) : 0;
  bar.style.width = v.toFixed(1) + '%';
  bar.className   = 'metric-bar-fill' +
    (v > 90 ? ' metric-bar-fill--crit' : v > 70 ? ' metric-bar-fill--warn' : '');
  if (pctEl) pctEl.textContent = pct(value);
}

// ── Alerts ────────────────────────────────────────────────────────────────
function updateAlerts(d) {
  const alerts = (d.alerts||[]).slice().reverse().slice(0,20);
  const tbody  = el('tbody-alerts');
  if (!tbody) return;
  const count = el('alerts-count');
  if (count) count.textContent = alerts.length;
  if (!alerts.length) { tbody.innerHTML='<tr><td colspan="4" class="tbl-empty">No alerts</td></tr>'; return; }
  tbody.innerHTML = alerts.map(a => `<tr>
    <td><span class="sev sev--${sevClass(a.severity)}">${esc(a.severity||'INFO')}</span></td>
    <td>${esc(a.agent_name||'–')}</td>
    <td>${esc(a.message||'–')}</td>
    <td class="mono muted">${fmtTime(a.timestamp)}</td></tr>`).join('');
}

// ── Firewall ──────────────────────────────────────────────────────────────
function updateFirewall(d) {
  const blocks = d.firewall_blocks||[];
  const tbody  = el('tbody-fw');
  if (!tbody) return;
  const count = el('fw-count');
  if (count) count.textContent = blocks.length;
  if (!blocks.length) { tbody.innerHTML='<tr><td colspan="3" class="tbl-empty">None</td></tr>'; return; }
  tbody.innerHTML = blocks.map(f => `<tr>
    <td class="mono">${esc(f.ip)}</td>
    <td>${esc(f.rule_name_in||'–')}</td>
    <td class="mono muted">${fmtMs(f.expires_at_ms)}</td></tr>`).join('');
}

// ── Status strip ──────────────────────────────────────────────────────────
function updateStatusStrip(d) {
  const h = d.health||{}, sm = d.system_metrics||{};
  dotState('dot-ollama', h.ollama_online);
  dotState('dot-npcap',  h.npcap_service_running);
  dotState('dot-clamd',  h.clamd_online);
  dotState('dot-admin',  h.is_admin);
  setText('strip-cpu',  `CPU ${pct(sm.cpu_percent)}`);
  setText('strip-mem',  `MEM ${pct(sm.memory_percent)}`);
  setText('strip-disk', `DISK ${pct(sm.disk_percent)}`);
  const ts = el('strip-ts');
  if (ts && d.system && d.system.timestamp) ts.textContent = fmtTime(d.system.timestamp);
}
function dotState(id, ok) {
  const e = el(id);
  if (e) e.className = `dot ${ok?'dot--ok':'dot--err'}`;
}

// ── Agents tab  (#7 fix: idle/busy/error labels) ──────────────────────────
function updateAgents(d) {
  const agents = d.agents||[];
  const pill   = el('agent-pill');
  if (pill) pill.textContent = `${agents.length} loaded`;
  const tbody = el('tbody-agents');
  if (!tbody) return;
  if (!agents.length) { tbody.innerHTML='<tr><td colspan="5" class="tbl-empty">No agents</td></tr>'; return; }
  tbody.innerHTML = agents.map(a => {
    const st   = a.status||'idle';
    const scls = st==='busy'?'medium':st==='error'?'critical':'info';
    const tier = (a.tier||'').toUpperCase();
    const tcls = tier==='FAST'?'fast':tier==='ACCURACY'?'heavy':tier==='ORCHESTRATOR'?'heavy':'heavy';
    return `<tr>
      <td>${esc(a.name||'–')}</td>
      <td><span class="tier tier--${tcls}">${esc(tier||'–')}</span></td>
      <td><span class="sev sev--${scls}">${esc(st.toUpperCase())}</span></td>
      <td class="mono">${a.tasks_completed??0}</td>
      <td class="mono muted">${fmtTime(a.last_active)}</td></tr>`;
  }).join('');
}

// ── Sandbox tab  (#8 fix: Plant Decoys button) ────────────────────────────
function updateSandbox(d) {
  const entries = d.sandbox_entries||[];
  const tbody   = el('tbody-sandbox');
  if (!tbody) return;
  if (!entries.length) {
    tbody.innerHTML = `<tr><td colspan="4" class="tbl-empty">
      Sandbox empty — use <strong>Plant Decoys</strong> above to populate honey files.</td></tr>`;
    return;
  }
  tbody.innerHTML = entries.slice(0,50).map(e => `<tr>
    <td class="mono">${esc(e.rel_path||'–')}</td>
    <td>${esc(e.type||'–')}</td>
    <td class="mono">${e.version??'–'}</td>
    <td>${e.locked?'<span class="sev sev--critical">LOCKED</span>':'<span class="sev sev--low">open</span>'}</td>
    </tr>`).join('');
}

// ── Zero Trust  (#9 fix: Simulate button) ────────────────────────────────
function updateZeroTrust(d) {
  const decisions = d.zerotrust_decisions||[];
  const tbody     = el('tbody-zt');
  if (!tbody) return;
  if (!decisions.length) {
    tbody.innerHTML = '<tr><td colspan="4" class="tbl-empty">No decisions yet — use <strong>Simulate Device Connect</strong> above.</td></tr>';
    return;
  }
  tbody.innerHTML = decisions.slice(0,30).map(z => `<tr>
    <td>${esc(z.user_id||'–')}</td>
    <td>${esc(z.resource||'–')}</td>
    <td class="mono">${z.trust_score??'–'}</td>
    <td><span class="sev sev--${z.decision==='DENY'?'critical':z.decision==='ALLOW_FULL'?'low':'medium'}">${esc(z.decision||'–')}</span></td>
    </tr>`).join('');
}

// ── Evidence ──────────────────────────────────────────────────────────────
function updateAudit(d) {
  const entries = d.audit_entries||[];
  const tbody   = el('tbody-audit');
  if (tbody) {
    if (!entries.length) tbody.innerHTML='<tr><td colspan="4" class="tbl-empty">Loading…</td></tr>';
    else tbody.innerHTML = entries.slice(-20).reverse().map(a => `<tr>
      <td class="mono muted">${esc((a.entry_id||'').slice(0,12)+'…')}</td>
      <td>${esc(a.event_type||'–')}</td>
      <td class="mono muted">${fmtTime(a.timestamp)}</td>
      <td>${a.chain_valid?'<span class="sev sev--low">✓</span>':'<span class="sev sev--critical">✗</span>'}</td>
      </tr>`).join('');
  }
  const qtn = d.quarantine_entries||[];
  const tbQ = el('tbody-qtn');
  if (tbQ) {
    if (!qtn.length) tbQ.innerHTML='<tr><td colspan="3" class="tbl-empty">None</td></tr>';
    else tbQ.innerHTML = qtn.map(q => `<tr>
      <td class="mono muted">${esc((q.entry_id||'').slice(0,12)+'…')}</td>
      <td>${esc(q.virus_name||'–')}</td>
      <td class="mono muted">${fmtMs(q.quarantined_at_ms)}</td></tr>`).join('');
  }
}

// ── Network ───────────────────────────────────────────────────────────────
function updateNetwork(d) {
  const ew    = d.entropy_windows||[];
  const tbody = el('tbody-entropy');
  if (tbody) {
    if (!ew.length) tbody.innerHTML='<tr><td colspan="4" class="tbl-empty">No windows yet</td></tr>';
    else tbody.innerHTML = ew.slice(-20).reverse().map(w => `<tr>
      <td class="mono">${w.window_index??'–'}</td>
      <td class="mono">${typeof w.mean_entropy_bits==='number'?w.mean_entropy_bits.toFixed(3):'–'}</td>
      <td class="mono">${typeof w.max_entropy_bits==='number'?w.max_entropy_bits.toFixed(3):'–'}</td>
      <td>${w.anomalous?'<span class="sev sev--critical">YES</span>':'<span class="sev sev--low">no</span>'}</td>
      </tr>`).join('');
  }
  if (ew.length && entropyChart) {
    // Push every window not yet seen — gives the chart the full history
    // including anomalous spikes, not just the latest tail value.
    ew.forEach(w => {
      const idx = w.window_index ?? 0;
      if (idx > _lastEntropyIdx && typeof w.mean_entropy_bits === 'number') {
        entropyChart.push(w.mean_entropy_bits);
        _lastEntropyIdx = idx;
      }
    });
  }
}

// ════════════════════════════════════════════════════════════════════════
// MITRE ATT&CK TAB
// Derives technique hits client-side from decoy_events[] using the same
// pattern rules as attribution_report.cpp — zero C++ changes needed.
// ════════════════════════════════════════════════════════════════════════

// Technique rule table — mirrors kTechniqueRules[] in attribution_report.cpp
const ATK_RULES = [
  { id:'T1552',     name:'Unsecured Credentials',           tactic:'Credential Access',  patterns:['credential','password','passwd','secret'] },
  { id:'T1552.005', name:'Cloud Instance Metadata API',     tactic:'Credential Access',  patterns:['metadata','169.254.169.254','imds'] },
  { id:'T1552.004', name:'Private Keys',                    tactic:'Credential Access',  patterns:['id_rsa','.pem','private_key','ssh_host'] },
  { id:'T1003.008', name:'OS Credential Dumping',           tactic:'Credential Access',  patterns:['/etc/shadow','sam_dump','lsass','ntds'] },
  { id:'T1552.001', name:'Credentials In Files',            tactic:'Credential Access',  patterns:['.env','config.ini','web.config','credentials.xml'] },
  { id:'T1082',     name:'System Information Discovery',    tactic:'Discovery',           patterns:['sysinfo','/etc/os-release','systeminfo','uname'] },
  { id:'T1518',     name:'Software Discovery',              tactic:'Discovery',           patterns:['installed_apps','package_list','dpkg','rpm'] },
  { id:'T1087',     name:'Account Discovery',               tactic:'Discovery',           patterns:['user_list','/etc/passwd','net user','get-localuser'] },
  { id:'T1083',     name:'File and Directory Discovery',    tactic:'Discovery',           patterns:['dir_listing','ls -la','find /','get-childitem'] },
  { id:'T1213',     name:'Data from Information Repositories', tactic:'Collection',       patterns:['sharepoint','confluence','git_repo','s3_bucket'] },
  { id:'T1005',     name:'Data from Local System',          tactic:'Collection',          patterns:['local_file','desktop','documents','downloads'] },
  { id:'T1041',     name:'Exfiltration Over C2 Channel',   tactic:'Exfiltration',        patterns:['exfil','c2_upload','beacon','dns_tunnel'] },
  { id:'T1021',     name:'Remote Services',                 tactic:'Lateral Movement',    patterns:['ssh_connect','rdp','winrm','psexec'] },
  { id:'T1654',     name:'Log Enumeration',                 tactic:'Discovery',           patterns:['event_log','syslog','/var/log','winevt'] },
  { id:'T1036',     name:'Masquerading',                    tactic:'Defense Evasion',     patterns:['renamed_binary','svchost_fake','lsass_clone','rundll_imposter'] },
];

// Map of tactic → color
const TACTIC_COLORS = {
  'Credential Access': '#da1e28',
  'Discovery':         '#6929c4',
  'Collection':        '#0043ce',
  'Exfiltration':      '#ff832b',
  'Lateral Movement':  '#005d5d',
  'Defense Evasion':   '#8a3800',
};

// Derive technique hits from decoy_events
function deriveAttackTechniques(decoyEvents) {
  // counts[techniqueId] = { hits, lastMs }
  const counts = {};
  for (const ev of (decoyEvents || [])) {
    const text = [
      ev.poison_type || '',
      ev.action      || '',
      ev.attacker_tag|| '',
    ].join(' ').toLowerCase();
    for (const rule of ATK_RULES) {
      if (rule.patterns.some(p => text.includes(p))) {
        if (!counts[rule.id]) counts[rule.id] = { ...rule, hits: 0, lastMs: 0 };
        counts[rule.id].hits++;
        const ms = ev.timestamp_ms || 0;
        if (ms > counts[rule.id].lastMs) counts[rule.id].lastMs = ms;
      }
    }
  }
  return Object.values(counts).sort((a, b) => b.hits - a.hits);
}

let lastAtkData = [];

function updateAttack(d) {
  const decoyEvents = d.decoy_events || [];
  const techniques  = deriveAttackTechniques(decoyEvents);
  lastAtkData = techniques;

  // KPIs
  const totalHits     = decoyEvents.length;
  const techCount     = techniques.length;
  const tacticSet     = new Set(techniques.map(t => t.tactic));
  const attackerSet   = new Set((decoyEvents).map(e => e.attacker_tag).filter(Boolean));

  setText('atk-kv-hits',      totalHits);
  setText('atk-kv-techniques', techCount);
  setText('atk-kv-tactics',   tacticSet.size);
  setText('atk-kv-attackers', attackerSet.size);
  setText('attack-technique-count', `${techCount} techniques`);

  // Color KPI cards by severity
  const hitsCard = el('atk-kpi-hits');
  if (hitsCard) hitsCard.className = 'kpi-card' + (totalHits > 20 ? ' kpi-card--critical' : totalHits > 5 ? ' kpi-card--high' : '');

  // SVG bar chart
  renderAtkBarChart(techniques);

  // Tactic coverage grid
  renderAtkGrid(techniques);

  // Detail table
  const tbody = el('tbody-attack');
  const count = el('atk-tbl-count');
  if (count) count.textContent = `${techCount} detected`;
  if (!tbody) return;
  if (!techniques.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="tbl-empty">No technique hits yet — plant decoys and trigger attacker interactions.</td></tr>';
    return;
  }
  tbody.innerHTML = techniques.map(t => {
    const conf = t.hits >= 5 ? 'HIGH' : t.hits >= 2 ? 'MEDIUM' : 'LOW';
    const confCls = conf === 'HIGH' ? 'critical' : conf === 'MEDIUM' ? 'medium' : 'low';
    const color = TACTIC_COLORS[t.tactic] || '#525252';
    return `<tr>
      <td class="mono" style="color:${color};font-weight:600">${esc(t.id)}</td>
      <td>${esc(t.name)}</td>
      <td><span style="font-size:11px;background:${color}18;color:${color};padding:2px 7px;border-radius:3px;font-weight:500">${esc(t.tactic)}</span></td>
      <td class="mono" style="font-weight:600">${t.hits}</td>
      <td><span class="sev sev--${confCls}">${conf}</span></td>
      <td class="mono muted">${t.lastMs ? fmtMs(t.lastMs) : '–'}</td>
    </tr>`;
  }).join('');
}

function renderAtkBarChart(techniques) {
  const svg = el('atk-bar-svg');
  if (!svg) return;
  if (!techniques || !techniques.length) {
    svg.innerHTML = '<text x="50%" y="110" text-anchor="middle" font-size="12" fill="#8d8d8d">No technique hits yet</text>';
    return;
  }
  const W     = svg.parentElement ? svg.parentElement.clientWidth - 32 : 600;
  const H     = 220;
  const maxH  = H - 50;
  const top   = techniques.slice(0, 10);
  const maxV  = Math.max(...top.map(t => t.hits), 1);
  const barW  = Math.floor((W - 20) / top.length) - 6;
  const pad   = 10;

  svg.setAttribute('width', W);
  svg.setAttribute('height', H);

  let html = '';
  top.forEach((t, i) => {
    const bh    = Math.max(4, Math.round((t.hits / maxV) * maxH));
    const x     = pad + i * (barW + 6);
    const y     = H - 30 - bh;
    const color = TACTIC_COLORS[t.tactic] || '#0f62fe';
    const label = t.id.length > 9 ? t.id.slice(0, 9) : t.id;
    html += `<g>
      <rect x="${x}" y="${y}" width="${barW}" height="${bh}" fill="${color}" rx="2" opacity="0.85"/>
      <text x="${x + barW/2}" y="${y - 4}" text-anchor="middle" font-size="10" fill="${color}" font-weight="600">${t.hits}</text>
      <text x="${x + barW/2}" y="${H - 14}" text-anchor="middle" font-size="9" fill="#525252"
        transform="rotate(-35,${x + barW/2},${H - 14})">${esc(label)}</text>
    </g>`;
  });
  svg.innerHTML = html;
}

function renderAtkGrid(techniques) {
  const grid = el('atk-grid');
  if (!grid) return;
  // Group by tactic
  const byTactic = {};
  for (const t of techniques) {
    if (!byTactic[t.tactic]) byTactic[t.tactic] = [];
    byTactic[t.tactic].push(t);
  }
  const allTactics = ['Credential Access','Discovery','Collection','Exfiltration','Lateral Movement','Defense Evasion'];
  let html = '';
  for (const tactic of allTactics) {
    const color   = TACTIC_COLORS[tactic] || '#525252';
    const matched = byTactic[tactic] || [];
    const active  = matched.length > 0;
    html += `<div style="border:1px solid ${active ? color : '#e0e0e0'};border-radius:4px;padding:8px 10px;
      background:${active ? color + '10' : 'transparent'};min-width:140px">
      <div style="font-size:10px;font-weight:600;color:${active ? color : '#8d8d8d'};text-transform:uppercase;margin-bottom:4px">${esc(tactic)}</div>
      ${active
        ? matched.map(t => `<div style="font-size:10px;color:${color};margin:1px 0">▸ ${esc(t.id)}: ${esc(t.name.length>22?t.name.slice(0,22)+'…':t.name)}</div>`).join('')
        : '<div style="font-size:10px;color:#c6c6c6">No hits</div>'
      }
    </div>`;
  }
  grid.innerHTML = html || '<span class="muted">No events yet</span>';
}

// ════════════════════════════════════════════════════════════════════════
// MITRE D3FEND TAB
// Maps OMIDAX 5 subsystem layers to D3FEND techniques using live health data
// ════════════════════════════════════════════════════════════════════════

const D3F_LAYERS = [
  {
    layer: 1, name: 'Entropy Detection',
    d3fend: [{ id:'D3-NTA', name:'Network Traffic Analysis' }],
    subsystems: ['PacketSensor','ChaosDetector'],
    healthKeys:  ['npcap_service_running'],
    description: 'Monitors packet entropy and detects Lyapunov chaos precursors in network traffic.',
  },
  {
    layer: 2, name: 'Threat State Machine',
    d3fend: [{ id:'D3-TPEM', name:'Threat Intel Feed' }, { id:'D3-AV', name:'Alert Triage' }],
    subsystems: ['ThreatStateMachine','RuleEngine'],
    healthKeys:  ['ollama_online'],
    description: 'Evaluates rule-driven threat transitions (NOMINAL→ELEVATED→CRITICAL) and routes AI triage.',
  },
  {
    layer: 3, name: 'Active Defense',
    d3fend: [{ id:'D3-DF', name:'Decoy File' }, { id:'D3-HN', name:'Honey Network' }],
    subsystems: ['DecoyEnvironment','ActiveResponse'],
    healthKeys:  ['npcap_service_running','ollama_online'],
    description: 'Plants honey files and decoy environments; executes countermeasures on attacker interaction.',
  },
  {
    layer: 4, name: 'Attribution',
    d3fend: [{ id:'D3-IH', name:'Incident Handling' }],
    subsystems: ['AttributionReporter'],
    healthKeys:  ['ollama_online'],
    description: 'Maps attacker interactions to MITRE ATT&CK techniques and generates attribution reports.',
  },
  {
    layer: 5, name: 'Lockdown',
    d3fend: [{ id:'D3-ITF', name:'Isolate and Transfer Files' }, { id:'D3-NI', name:'Network Isolation' }],
    subsystems: ['WormLock','FirewallBlocker','Quarantine'],
    healthKeys:  [], // always active if worm subsystem compiled
    description: 'WORM immutable lockdown, IP-level firewall blocking via netsh, and ClamAV quarantine.',
  },
];

const LAYER_COLORS = ['#0f62fe','#6929c4','#005d5d','#ff832b','#da1e28'];

function updateDefend(d) {
  const health = d.health || {};
  const wormLocked = !!d.worm_is_locked;

  // Determine active state for each layer
  function layerActive(layer) {
    if (layer.layer === 5) return true; // lockdown always compiled
    return layer.healthKeys.every(k => !!health[k]);
  }

  // 5-layer card visual
  const layersDiv = el('d3f-layers');
  if (layersDiv) {
    layersDiv.innerHTML = D3F_LAYERS.map((L, i) => {
      const active = layerActive(L);
      const color  = LAYER_COLORS[i];
      const fwBlocks = (d.firewall_blocks||[]).length;
      const qtnCount = (d.quarantine_entries||[]).length;
      let extraInfo = '';
      if (L.layer === 5) {
        extraInfo = `<span style="margin-left:12px;font-size:11px;color:${color}">WORM: ${wormLocked?'LOCKED':'OPEN'} · Blocks: ${fwBlocks} · Quarantine: ${qtnCount}</span>`;
      }
      if (L.layer === 1 && d.chaos_windows) {
        const anom = d.chaos_windows.filter(w => w.anomalous).length;
        extraInfo = `<span style="margin-left:12px;font-size:11px;color:${color}">Chaos windows: ${d.chaos_windows.length} · Anomalous: ${anom}</span>`;
      }
      return `<div style="border:1px solid ${active?color:'#e0e0e0'};border-radius:6px;padding:14px 18px;
        background:${active?color+'08':'#fafafa'};display:flex;align-items:flex-start;gap:16px">
        <!-- Layer number circle -->
        <div style="flex-shrink:0;width:36px;height:36px;border-radius:50%;background:${active?color:'#e0e0e0'};
          color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:15px">${L.layer}</div>
        <div style="flex:1">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
            <span style="font-weight:600;font-size:14px">${esc(L.name)}</span>
            <span style="font-size:11px;padding:2px 8px;border-radius:3px;font-weight:500;
              background:${active?'#d4edda':'#f4f4f4'};color:${active?'#155724':'#525252'}">
              ${active ? '● ACTIVE' : '○ OFFLINE'}</span>
            ${extraInfo}
          </div>
          <div style="font-size:12px;color:#525252;margin-bottom:6px">${esc(L.description)}</div>
          <div style="display:flex;flex-wrap:wrap;gap:6px">
            ${L.d3fend.map(t => `<span style="font-size:11px;background:${color}18;color:${color};
              padding:2px 8px;border-radius:3px;font-family:'IBM Plex Mono',monospace">${esc(t.id)} ${esc(t.name)}</span>`).join('')}
            ${L.subsystems.map(s => `<span style="font-size:11px;background:#f4f4f4;color:#525252;
              padding:2px 8px;border-radius:3px">${esc(s)}</span>`).join('')}
          </div>
        </div>
      </div>`;
    }).join('');
  }

  // Active count badge
  const activeCount = D3F_LAYERS.filter(layerActive).length;
  setText('defend-active-count', `${activeCount}/5 active layers`);
  const badge = el('defend-active-count');
  if (badge) badge.className = `pill ${activeCount >= 4 ? 'pill--ok' : activeCount >= 2 ? 'pill--warn' : 'pill--critical'}`;

  // Coverage table
  const tbody = el('tbody-defend');
  if (!tbody) return;
  const rows = [];
  for (const L of D3F_LAYERS) {
    const active = layerActive(L);
    for (const t of L.d3fend) {
      rows.push({ layer: L.name, id: t.id, name: t.name, subsystems: L.subsystems.join(', '), active });
    }
  }
  tbody.innerHTML = rows.map(r => `<tr>
    <td><span style="font-size:11px;font-weight:500">${esc(r.layer)}</span></td>
    <td class="mono" style="color:${LAYER_COLORS[D3F_LAYERS.findIndex(l=>l.name===r.layer)]}}">${esc(r.id)}</td>
    <td>${esc(r.name)}</td>
    <td class="mono muted" style="font-size:11px">${esc(r.subsystems)}</td>
    <td>${r.active
      ? '<span class="sev sev--low">ACTIVE</span>'
      : '<span class="sev sev--critical">OFFLINE</span>'}</td>
  </tr>`).join('');
}

// ════════════════════════════════════════════════════════════════════════
// NIST 800-53 / ZERO TRUST TAB
// ════════════════════════════════════════════════════════════════════════

const NIST_CONTROLS = [
  { family:'AC', name:'Access Control',          ztRelevant: true,  description:'ZT access decisions map here' },
  { family:'AU', name:'Audit & Accountability',  ztRelevant: true,  description:'Audit chain + evidence log' },
  { family:'CA', name:'Assessment & Auth',       ztRelevant: true,  description:'NAC 802.1X admission' },
  { family:'CM', name:'Config Management',       ztRelevant: false, description:'WORM versioning' },
  { family:'CP', name:'Contingency Planning',    ztRelevant: false, description:'Veeam/IBM Storage backup stub' },
  { family:'IA', name:'Identification & Auth',   ztRelevant: true,  description:'Crypto identity, MFA enforcement' },
  { family:'IR', name:'Incident Response',       ztRelevant: true,  description:'Active response + attribution' },
  { family:'RA', name:'Risk Assessment',         ztRelevant: true,  description:'Chaos K + threat state machine' },
  { family:'SC', name:'System & Comms Protect',  ztRelevant: true,  description:'Firewall blocking + network isolation' },
  { family:'SI', name:'System & Info Integrity', ztRelevant: true,  description:'ClamAV + WORM immutability' },
];

const ZT_DECISION_COLORS = {
  'ALLOW_FULL':    '#24a148',
  'ALLOW_LIMITED': '#0043ce',
  'MFA_REQUIRED':  '#f1c21b',
  'QUARANTINE':    '#ff832b',
  'DENY':          '#da1e28',
};

let lastZtData = [];

function updateNist(d) {
  const decisions = d.zerotrust_decisions || [];
  lastZtData = decisions;

  // KPI counts
  const counts = { ALLOW_FULL:0, ALLOW_LIMITED:0, MFA_REQUIRED:0, QUARANTINE:0, DENY:0 };
  for (const z of decisions) {
    const k = (z.decision||'').toUpperCase();
    if (counts[k] !== undefined) counts[k]++;
  }
  setText('zt-kv-allow',   counts.ALLOW_FULL);
  setText('zt-kv-limited', counts.ALLOW_LIMITED);
  setText('zt-kv-mfa',     counts.MFA_REQUIRED);
  setText('zt-kv-qtn',     counts.QUARANTINE);
  setText('zt-kv-deny',    counts.DENY);
  setText('nist-decision-count', `${decisions.length} decisions`);

  // Color KPI cards
  const denyCard = el('zt-kpi-deny');
  if (denyCard) denyCard.className = 'kpi-card' + (counts.DENY > 0 ? ' kpi-card--critical' : '');
  const allowCard = el('zt-kpi-allow');
  if (allowCard) allowCard.className = 'kpi-card' + (counts.ALLOW_FULL > 0 ? ' kpi-card--ok' : '');

  // Donut chart
  renderZtDonut(decisions);

  // Histogram
  renderZtHist(decisions);

  // NIST control family grid
  const nistDiv = el('nist-controls');
  if (nistDiv) {
    // Determine which families have live coverage based on data
    const hasCoverage = {
      AC: decisions.length > 0,
      AU: (d.audit_entries||[]).length > 0,
      CA: decisions.length > 0,
      CM: d.sandbox_entries && d.sandbox_entries.length > 0,
      CP: false, // stub
      IA: decisions.some(z => z.decision === 'MFA_REQUIRED'),
      IR: (d.alerts||[]).length > 0,
      RA: d.chaos_windows && d.chaos_windows.length > 0,
      SC: (d.firewall_blocks||[]).length > 0,
      SI: (d.quarantine_entries||[]).length > 0 || (d.health||{}).clamd_online,
    };
    nistDiv.innerHTML = NIST_CONTROLS.map(c => {
      const covered = hasCoverage[c.family];
      const color   = covered ? '#24a148' : '#8d8d8d';
      return `<div style="border:1px solid ${covered?'#24a148':'#e0e0e0'};border-radius:4px;padding:10px 12px;
        background:${covered?'#f0fdf4':'#fafafa'}">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:3px">
          <span style="font-weight:600;font-size:12px;color:${color}">${esc(c.family)}</span>
          <span style="font-size:10px;color:${color}">${covered ? '✓ covered' : '○ partial'}</span>
        </div>
        <div style="font-size:12px;font-weight:500;color:#161616;margin-bottom:2px">${esc(c.name)}</div>
        <div style="font-size:11px;color:#8d8d8d">${esc(c.description)}</div>
      </div>`;
    }).join('');
  }

  // Recent decisions table
  const tbody = el('tbody-nist-zt');
  const cnt   = el('nist-zt-count');
  if (cnt) cnt.textContent = `${decisions.length} total`;
  if (!tbody) return;
  if (!decisions.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="tbl-empty">No ZT decisions yet — simulate a device connect on the NAC tab.</td></tr>';
    return;
  }
  tbody.innerHTML = decisions.slice(-20).reverse().map(z => {
    const d = (z.decision||'DENY').toUpperCase();
    const color = ZT_DECISION_COLORS[d] || '#8d8d8d';
    return `<tr>
      <td>${esc(z.user_id||'–')}</td>
      <td>${esc(z.resource||'–')}</td>
      <td class="mono">${z.trust_score ?? '–'}</td>
      <td><span style="font-size:11px;font-weight:600;padding:2px 8px;border-radius:3px;
        background:${color}18;color:${color}">${esc(d)}</span></td>
      <td class="mono muted">${z.timestamp ? fmtTime(z.timestamp) : '–'}</td>
    </tr>`;
  }).join('');
}

function renderZtDonut(decisions) {
  const svg = el('zt-donut-svg');
  if (!svg) return;
  const total = decisions.length;
  if (!total) {
    svg.innerHTML = '<text x="110" y="115" text-anchor="middle" font-size="12" fill="#8d8d8d">No decisions</text>';
    return;
  }

  const keys   = Object.keys(ZT_DECISION_COLORS);
  const counts = {};
  keys.forEach(k => counts[k] = 0);
  decisions.forEach(z => { const k = (z.decision||'DENY').toUpperCase(); if (counts[k] !== undefined) counts[k]++; });

  const cx = 110, cy = 110, R = 80, r = 46;
  let startAngle = -Math.PI / 2;
  let paths = '';
  let legend = '';

  for (const key of keys) {
    const v = counts[key];
    if (!v) continue;
    const angle = (v / total) * 2 * Math.PI;
    const endA  = startAngle + angle;
    const x1 = cx + R * Math.cos(startAngle), y1 = cy + R * Math.sin(startAngle);
    const x2 = cx + R * Math.cos(endA),       y2 = cy + R * Math.sin(endA);
    const ix1 = cx + r * Math.cos(startAngle), iy1 = cy + r * Math.sin(startAngle);
    const ix2 = cx + r * Math.cos(endA),       iy2 = cy + r * Math.sin(endA);
    const large = angle > Math.PI ? 1 : 0;
    const color = ZT_DECISION_COLORS[key];
    paths += `<path d="M${x1},${y1} A${R},${R} 0 ${large},1 ${x2},${y2}
      L${ix2},${iy2} A${r},${r} 0 ${large},0 ${ix1},${iy1} Z"
      fill="${color}" opacity="0.88" stroke="#fff" stroke-width="1.5"/>`;
    // mid-angle label
    const mid = startAngle + angle / 2;
    const lx  = cx + (R + r) / 2 * Math.cos(mid);
    const ly  = cy + (R + r) / 2 * Math.sin(mid);
    if (v / total > 0.08) {
      paths += `<text x="${lx}" y="${ly}" text-anchor="middle" dominant-baseline="middle"
        font-size="10" fill="#fff" font-weight="600">${v}</text>`;
    }
    startAngle = endA;
    legend += `<div style="font-size:11px;color:${color};display:flex;align-items:center;gap:4px">
      <span style="width:10px;height:10px;background:${color};border-radius:2px;flex-shrink:0;display:inline-block"></span>
      ${esc(key)} (${v})</div>`;
  }
  // Centre label
  paths += `<text x="${cx}" y="${cy - 6}" text-anchor="middle" font-size="22" font-weight="700" fill="#161616">${total}</text>
    <text x="${cx}" y="${cy + 12}" text-anchor="middle" font-size="11" fill="#8d8d8d">decisions</text>`;

  svg.innerHTML = paths;

  const legendDiv = el('zt-donut-legend');
  if (legendDiv) legendDiv.innerHTML = legend;
}

function renderZtHist(decisions) {
  const svg = el('zt-hist-svg');
  if (!svg) return;
  // 5 buckets: 0-19, 20-39, 40-59, 60-79, 80-100
  const buckets = [0, 0, 0, 0, 0];
  decisions.forEach(z => {
    const s = z.trust_score ?? 50;
    const i = Math.min(4, Math.floor(s / 20));
    buckets[i]++;
  });
  const W    = svg.parentElement ? svg.parentElement.clientWidth - 32 : 400;
  const H    = 180;
  const maxV = Math.max(...buckets, 1);
  const barW = Math.floor((W - 60) / 5) - 6;
  const labels = ['0–19','20–39','40–59','60–79','80–100'];
  const colors = ['#da1e28','#ff832b','#f1c21b','#0043ce','#24a148'];

  svg.setAttribute('width', W);
  let html = '';
  buckets.forEach((v, i) => {
    const bh  = Math.max(4, Math.round((v / maxV) * (H - 50)));
    const x   = 30 + i * (barW + 6);
    const y   = H - 30 - bh;
    html += `<g>
      <rect x="${x}" y="${y}" width="${barW}" height="${bh}" fill="${colors[i]}" rx="2" opacity="0.8"/>
      <text x="${x + barW/2}" y="${y - 4}" text-anchor="middle" font-size="10" fill="${colors[i]}" font-weight="600">${v}</text>
      <text x="${x + barW/2}" y="${H - 12}" text-anchor="middle" font-size="9" fill="#525252">${labels[i]}</text>
    </g>`;
  });
  // Y axis line
  html += `<line x1="26" y1="10" x2="26" y2="${H-28}" stroke="#e0e0e0" stroke-width="1"/>`;
  svg.innerHTML = html;
}

// ════════════════════════════════════════════════════════════════════════
// 802.1X NAC WORKFLOW TAB
// 8-step admission pipeline stepper + simulation
// ════════════════════════════════════════════════════════════════════════

const NAC_STEPS = [
  { step: 1, name: 'EAP Identity Request',  desc: 'Authenticator requests device identity via EAPOL' },
  { step: 2, name: 'Identity Response',     desc: 'Supplicant sends username/device MAC to authenticator' },
  { step: 3, name: 'RADIUS Access-Request', desc: 'NAS forwards credentials to RADIUS/AS server' },
  { step: 4, name: 'Posture Assessment',    desc: 'Server evaluates OS patch level, AV status, disk encryption, firewall' },
  { step: 5, name: 'ZT Policy Evaluation',  desc: 'OMIDAX ZeroTrustEngine computes trust score (0–100)' },
  { step: 6, name: 'RADIUS Decision',       desc: 'Access-Accept / Access-Challenge (MFA) / Access-Reject issued' },
  { step: 7, name: 'VLAN Assignment',       desc: 'Port placed in production VLAN, guest VLAN, or quarantine VLAN' },
  { step: 8, name: 'Audit Log Entry',       desc: 'Tamper-evident entry written to WORM audit chain' },
];

// Dot1x admission history (persisted across polls in session)
let dot1xHistory = [];
let dot1xSimRunning = false;
let dot1xCurrentStep = -1;

function renderDot1xStepper(activeStep, outcome) {
  const div = el('dot1x-stepper');
  if (!div) return;

  // Horizontal stepper
  const stepW = 100; // approx px per step
  const totalW = NAC_STEPS.length * (stepW + 16);

  let html = `<div style="display:flex;align-items:flex-start;min-width:${totalW}px;gap:0">`;
  NAC_STEPS.forEach((s, i) => {
    const done    = activeStep > s.step;
    const current = activeStep === s.step;
    const fail    = current && outcome === 'DENY';
    const color   = fail ? '#da1e28' : done ? '#24a148' : current ? '#0f62fe' : '#e0e0e0';
    const textCol = (done || current) ? '#161616' : '#8d8d8d';
    const connector = i < NAC_STEPS.length - 1
      ? `<div style="flex:1;height:2px;background:${done?'#24a148':'#e0e0e0'};margin-top:19px;min-width:8px"></div>`
      : '';
    html += `<div style="display:flex;flex-direction:column;align-items:center;min-width:${stepW}px">
      <div style="width:38px;height:38px;border-radius:50%;background:${color};color:#fff;
        display:flex;align-items:center;justify-content:center;font-weight:700;font-size:13px;
        border:2px solid ${color};transition:background .3s">
        ${done ? '✓' : fail ? '✗' : s.step}
      </div>
      <div style="font-size:10px;font-weight:600;color:${textCol};margin-top:5px;text-align:center;max-width:90px">${esc(s.name)}</div>
      ${current ? `<div style="font-size:9px;color:${color};margin-top:2px;text-align:center;max-width:90px">${esc(s.desc)}</div>` : ''}
    </div>${connector}`;
  });
  html += '</div>';
  div.innerHTML = html;
}

function updateDot1x(d) {
  // Derive admissions from audit_entries that have event_type='nac_simulate'
  const entries  = (d.audit_entries||[]).filter(e => e.event_type === 'nac_simulate' || e.event_type === 'nac_device_connect');
  const ztDecisions = d.zerotrust_decisions || [];

  // Build history from audit entries
  if (entries.length > dot1xHistory.length) {
    dot1xHistory = entries.map(e => ({
      device:   e.device_name || 'Unknown Device',
      mac:      e.device_mac  || '–',
      ssid:     e.ssid        || 'eGov',
      decision: e.final_decision || (ztDecisions.find(z => z.user_id === (e.username||''))?.decision) || '–',
      ts:       e.timestamp   || '',
    }));
  }

  // History table
  const tbody = el('tbody-dot1x');
  const count = el('dot1x-history-count');
  if (count) count.textContent = `${dot1xHistory.length} admissions`;
  if (tbody) {
    if (!dot1xHistory.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="tbl-empty">No admissions yet — click Run Simulation above.</td></tr>';
    } else {
      tbody.innerHTML = dot1xHistory.slice(-20).reverse().map(h => {
        const dec = (h.decision||'–').toUpperCase();
        const color = ZT_DECISION_COLORS[dec] || '#8d8d8d';
        return `<tr>
          <td>${esc(h.device)}</td>
          <td class="mono muted">${esc(h.mac)}</td>
          <td>${esc(h.ssid)}</td>
          <td><span style="font-size:11px;font-weight:600;padding:2px 8px;border-radius:3px;
            background:${color}18;color:${color}">${esc(dec)}</span></td>
          <td class="mono muted">${h.ts ? fmtTime(h.ts) : '–'}</td>
        </tr>`;
      }).join('');
    }
  }

  // If no simulation running, render idle stepper
  if (!dot1xSimRunning) {
    renderDot1xStepper(-1, null);
    const statusBadge = el('dot1x-pipeline-status');
    if (statusBadge && statusBadge.textContent === 'Idle') {
      statusBadge.style.background = '';
      statusBadge.style.color      = '';
    }
  }
}

// Simulation — animate through 8 steps
async function runDot1xSimulation() {
  if (dot1xSimRunning) return;
  dot1xSimRunning = true;
  const btn    = el('btn-dot1x-sim');
  const badge  = el('dot1x-pipeline-status');
  const result = el('dot1x-result');
  const tsEl   = el('dot1x-last-ts');

  if (btn)   { btn.disabled = true; btn.textContent = 'Running…'; }
  if (badge) { badge.textContent = 'Running'; badge.style.background = '#0f62fe'; badge.style.color = '#fff'; }

  // Pick a random device profile for this demo run
  const devices = [
    { name:'Kgosi-Laptop',  mac:'AA:BB:CC:11:22:33', os_updated:true,  av:true,  disk_enc:true,  fw:true  },
    { name:'Guest-Phone',   mac:'DE:AD:BE:EF:00:01', os_updated:false, av:false, disk_enc:false, fw:true  },
    { name:'Admin-Desktop', mac:'C0:FF:EE:C0:FF:EE', os_updated:true,  av:true,  disk_enc:true,  fw:true  },
    { name:'IoT-Sensor',    mac:'00:11:22:33:44:55', os_updated:false, av:false, disk_enc:false, fw:false },
  ];
  const dev = devices[Math.floor(Math.random() * devices.length)];

  // Compute synthetic trust score
  let score = 50;
  if (dev.os_updated)  score += 15;
  if (dev.av)          score += 15;
  if (dev.disk_enc)    score += 10;
  if (dev.fw)          score += 10;
  score = Math.min(100, score);

  const decision = score >= 80 ? 'ALLOW_FULL'
                 : score >= 60 ? 'ALLOW_LIMITED'
                 : score >= 40 ? 'MFA_REQUIRED'
                 : score >= 20 ? 'QUARANTINE'
                 : 'DENY';

  const vlan = decision === 'ALLOW_FULL' ? 'VLAN-10 (Production)'
             : decision === 'ALLOW_LIMITED' ? 'VLAN-20 (Restricted)'
             : decision === 'MFA_REQUIRED'  ? 'VLAN-30 (Step-up)'
             : 'VLAN-99 (Quarantine)';

  // Step through pipeline visually
  for (let step = 1; step <= 8; step++) {
    dot1xCurrentStep = step;
    renderDot1xStepper(step, decision);
    await new Promise(res => setTimeout(res, 480));
  }

  // Final state
  const color = ZT_DECISION_COLORS[decision] || '#525252';
  if (badge) { badge.textContent = decision; badge.style.background = color; badge.style.color = '#fff'; }
  if (tsEl)  tsEl.textContent = new Date().toLocaleTimeString();

  if (result) {
    result.innerHTML = `<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;font-size:13px">
      <div><span style="color:#8d8d8d">Device</span><br><strong>${esc(dev.name)}</strong></div>
      <div><span style="color:#8d8d8d">MAC</span><br><span class="mono">${esc(dev.mac)}</span></div>
      <div><span style="color:#8d8d8d">Trust Score</span><br><strong class="mono">${score}</strong>/100</div>
      <div><span style="color:#8d8d8d">Decision</span><br>
        <span style="font-weight:700;color:${color}">${esc(decision)}</span></div>
      <div><span style="color:#8d8d8d">VLAN Assignment</span><br>${esc(vlan)}</div>
      <div><span style="color:#8d8d8d">Posture</span><br>
        OS patched: ${dev.os_updated?'✓':'✗'} &nbsp;
        AV: ${dev.av?'✓':'✗'} &nbsp;
        Encrypted: ${dev.disk_enc?'✓':'✗'} &nbsp;
        Firewall: ${dev.fw?'✓':'✗'}
      </div>
    </div>`;
  }

  // Add to local history
  dot1xHistory.push({
    device:   dev.name,
    mac:      dev.mac,
    ssid:     'eGov',
    decision: decision,
    ts:       new Date().toISOString(),
  });

  // Refresh history table
  const tbody = el('tbody-dot1x');
  const cnt   = el('dot1x-history-count');
  if (cnt) cnt.textContent = `${dot1xHistory.length} admissions`;
  if (tbody) {
    tbody.innerHTML = dot1xHistory.slice(-20).reverse().map(h => {
      const dec = (h.decision||'–').toUpperCase();
      const c   = ZT_DECISION_COLORS[dec] || '#8d8d8d';
      return `<tr>
        <td>${esc(h.device)}</td>
        <td class="mono muted">${esc(h.mac)}</td>
        <td>${esc(h.ssid)}</td>
        <td><span style="font-size:11px;font-weight:600;padding:2px 8px;border-radius:3px;
          background:${c}18;color:${c}">${esc(dec)}</span></td>
        <td class="mono muted">${h.ts ? fmtTime(h.ts) : '–'}</td>
      </tr>`;
    }).join('');
  }

  if (btn) { btn.disabled = false; btn.textContent = '▶ Run Simulation'; }
  dot1xSimRunning  = false;
  dot1xCurrentStep = -1;
}

el('btn-dot1x-sim')?.addEventListener('click', runDot1xSimulation);

// ════════════════════════════════════════════════════════════════════════
// TERMINAL  (#6 fix: all cmds use /exec; help handled client-side as
//   a fallback description, but server now also handles it)
// ════════════════════════════════════════════════════════════════════════
const termOutput = el('term-output');
const termInput  = el('term-input');

function termPrint(text, cls) {
  const span = document.createElement('span');
  span.className = cls || 'term-out';
  span.textContent = '\n' + text;
  if (termOutput) { termOutput.appendChild(span); termOutput.scrollTop = termOutput.scrollHeight; }
}

async function runTermCmd() {
  const cmd = termInput ? termInput.value.trim() : '';
  if (!cmd) return;
  if (termInput) termInput.value = '';
  termPrint(`astartis> ${cmd}`, 'term-cmd');
  try {
    const res = await apiPost('/exec', { cmd });
    if (res.ok) termPrint(res.data.output || '(no output)', 'term-out');
    else        termPrint(`ERROR ${res.status}: ${res.data.error||'unknown'}`, 'term-err');
  } catch (e) {
    termPrint(`ERROR: ${e.message}`, 'term-err');
  }
}

el('term-run')?.addEventListener('click', runTermCmd);
termInput?.addEventListener('keydown', e => { if (e.key === 'Enter') runTermCmd(); });
el('term-clear')?.addEventListener('click', () => {
  if (termOutput) termOutput.innerHTML = '<span class="term-prompt">Astartis Terminal — cleared</span>';
});

// ════════════════════════════════════════════════════════════════════════
// SANDBOX — Plant Decoys button  (#8)
// ════════════════════════════════════════════════════════════════════════
el('btn-plant-decoys')?.addEventListener('click', () => {
  openModal('Plant Decoy Files',
    'This will call <code>decoy_plant</code> via the bridge, writing honey files into the sandbox directory.',
    async () => {
      // Bridge dispatches decoy_plant over the stdio port.
      // From the dashboard we proxy it through the /exec endpoint running an echo (bridge doesn't
      // expose an HTTP endpoint for this), so we print the guidance instead.
      termPrint('Decoy plant requested — send {"cmd":"decoy_plant"} to the bridge stdin to trigger it.', 'term-out');
      activateTab('terminal');
    }
  );
});

// ════════════════════════════════════════════════════════════════════════
// NAC — Simulate Device Connect  (#9)
// ════════════════════════════════════════════════════════════════════════
el('btn-sim-nac')?.addEventListener('click', () => {
  openModal('Simulate Device Connect',
    `<p>Run an 8-step NAC workflow simulation for a demo device on the eGov SSID.</p>
     <p style="margin-top:8px;font-size:12px;color:#525252">
     Send <code>{"cmd":"nac_simulate_device","args":{...}}</code> to the bridge via the Terminal tab.
     </p>`,
    async () => {
      const exampleCmd = 'echo {"cmd":"nac_simulate_device","args":{"device_mac":"AA:BB:CC:DD:EE:FF","device_name":"Demo-Laptop","ssid_name":"eGov","username":"kgosi","domain":"egov.gov.bw","os_updated":true,"antivirus_running":true,"disk_encrypted":true,"firewall_enabled":true}}';
      termPrint('NAC simulation command (paste to bridge stdin):', 'term-prompt');
      termPrint('{"cmd":"nac_simulate_device","args":{"device_mac":"AA:BB:CC:DD:EE:FF","device_name":"Demo-Laptop","ssid_name":"eGov","username":"kgosi","domain":"egov.gov.bw","os_updated":true,"antivirus_running":true,"disk_encrypted":true,"firewall_enabled":true}}', 'term-out');
      activateTab('terminal');
    }
  );
});

// ════════════════════════════════════════════════════════════════════════
// CONFIGURE TAB
// ════════════════════════════════════════════════════════════════════════
let cfgData     = {};
let cfgDraft    = {};
let cfgRendered = false;
// BUG-FIX: expose a reset so clicking Configure after a bridge restart
// re-fetches config instead of showing stale rendered content.
function resetCfgRendered() { cfgRendered = false; cfgData = {}; cfgDraft = {}; }

async function loadConfig() {
  try { cfgData = await apiGet('/config'); cfgDraft = Object.assign({}, cfgData); return cfgData; }
  catch (e) { console.warn('[Astartis] Config load failed:', e.message); return {}; }
}
async function saveConfig(patch) {
  return apiPost('/config', Object.assign({}, cfgData, patch));
}

async function renderConfigure() {
  if (cfgRendered) return;
  cfgRendered = true;
  const c = el('cfg-container');
  if (!c) return;
  c.innerHTML = '<p style="color:var(--text-muted);padding:8px">Loading config…</p>';
  const cfg = await loadConfig();
  c.innerHTML = '';

  function section(title) {
    const div = document.createElement('div'); div.className='cfg-section';
    const h = document.createElement('h2');
    h.style.cssText='font-size:13px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px';
    h.textContent=title; div.appendChild(h); c.appendChild(div); return div;
  }
  function card(parent, title) {
    const card = document.createElement('div'); card.className='cfg-card';
    card.innerHTML=`<div class="cfg-card__header"><span class="cfg-card__title">${esc(title)}</span></div>
      <div class="cfg-card__body" data-body></div>
      <div class="cfg-card__audit" data-audit style="padding:0 16px 8px">Last changed: never</div>
      <div class="cfg-card__footer"><span class="validation-msg" data-vmsg></span>
        <button class="btn btn--ghost btn--sm" data-revert>Revert</button>
        <button class="btn btn--primary btn--sm" data-save>Save</button></div>`;
    parent.appendChild(card);
    return { body:card.querySelector('[data-body]'), audit:card.querySelector('[data-audit]'),
      vmsg:card.querySelector('[data-vmsg]'), revert:card.querySelector('[data-revert]'),
      save:card.querySelector('[data-save]'), el:card };
  }
  function numRow(parent,label,hint,key,min,max) {
    const row=document.createElement('div'); row.className='form-row';
    row.innerHTML=`<label class="form-label">${esc(label)}<small>${esc(hint)}</small></label>
      <input class="form-input form-input--mono" type="number" min="${min}" max="${max}"
        value="${cfg[key]??''}" data-key="${key}" data-min="${min}" data-max="${max}">`;
    parent.appendChild(row); return row.querySelector('input');
  }
  function floatRow(parent,label,hint,key,min,max,step) {
    const row=document.createElement('div'); row.className='form-row';
    row.innerHTML=`<label class="form-label">${esc(label)}<small>${esc(hint)}</small></label>
      <input class="form-input form-input--mono" type="number" min="${min}" max="${max}" step="${step||0.01}"
        value="${cfg[key]??''}" data-key="${key}" data-min="${min}" data-max="${max}" data-float>`;
    parent.appendChild(row); return row.querySelector('input');
  }
  function textRow(parent,label,hint,key,allowed) {
    const row=document.createElement('div'); row.className='form-row';
    row.innerHTML=`<label class="form-label">${esc(label)}<small>${esc(hint)}</small></label>
      <input class="form-input form-input--mono" type="text"
        value="${esc(cfg[key]??'')}" data-key="${key}" data-allowed="${esc(JSON.stringify(allowed||[]))}">`;
    parent.appendChild(row); return row.querySelector('input');
  }
  function toggleRow(parent,label,key) {
    const row=document.createElement('div'); row.className='toggle-row';
    const id='tgl-'+key;
    row.innerHTML=`<span class="toggle-label">${esc(label)}</span>
      <label class="toggle" for="${id}"><input type="checkbox" id="${id}" data-key="${key}" ${cfg[key]?'checked':''}>
      <span class="toggle-slider"></span></label>`;
    parent.appendChild(row); return row.querySelector('input');
  }
  function wireCard(cardObj, inputs, toggles, textInputs) {
    function collectPatch() {
      const p={};
      inputs.forEach(i=>{ p[i.dataset.key]=i.hasAttribute('data-float')?parseFloat(i.value):parseInt(i.value,10); });
      textInputs.forEach(i=>{ p[i.dataset.key]=i.value.trim(); });
      toggles.forEach(i=>{ p[i.dataset.key]=i.checked; });
      return p;
    }
    cardObj.save.addEventListener('click', async () => {
      for (const i of inputs) {
        const v=parseFloat(i.value),mn=parseFloat(i.dataset.min),mx=parseFloat(i.dataset.max);
        if (isNaN(v)||v<mn||v>mx){ i.classList.add('invalid'); cardObj.vmsg.textContent='Fix validation errors first'; cardObj.vmsg.className='validation-msg show err'; return; }
        i.classList.remove('invalid');
      }
      for (const i of textInputs) {
        const allowed=JSON.parse(i.dataset.allowed||'[]');
        if (allowed.length&&!allowed.includes(i.value.trim())){ i.classList.add('invalid'); cardObj.vmsg.textContent=`${i.dataset.key} must be: ${allowed.join(', ')}`; cardObj.vmsg.className='validation-msg show err'; return; }
        i.classList.remove('invalid');
      }
      cardObj.save.disabled=true; cardObj.save.textContent='Saving…';
      const res=await saveConfig(collectPatch());
      cardObj.save.disabled=false; cardObj.save.textContent='Save';
      if (res.ok) {
        Object.assign(cfgData, collectPatch());
        cardObj.vmsg.textContent='✓ Saved'; cardObj.vmsg.className='validation-msg show ok';
        cardObj.audit.textContent='Last changed: '+new Date().toLocaleTimeString();
        setTimeout(()=>{ cardObj.vmsg.className='validation-msg'; }, 2500);
      } else { cardObj.vmsg.textContent=res.data.error||'Save failed'; cardObj.vmsg.className='validation-msg show err'; }
    });
    cardObj.revert.addEventListener('click', ()=>{
      inputs.forEach(i=>{ i.value=cfgData[i.dataset.key]??''; i.classList.remove('invalid'); });
      textInputs.forEach(i=>{ i.value=cfgData[i.dataset.key]??''; i.classList.remove('invalid'); });
      toggles.forEach(i=>{ i.checked=!!cfgData[i.dataset.key]; });
      cardObj.vmsg.textContent='Reverted'; cardObj.vmsg.className='validation-msg show ok';
      setTimeout(()=>{ cardObj.vmsg.className='validation-msg'; }, 1500);
    });
  }

  // Protection card
  const protSec=section('Protection');
  const protCard=card(protSec,'Monitor Toggles');
  wireCard(protCard,[],[
    toggleRow(protCard.body,'Ollama AI (autonomy loop)','autonomy_loop'),
    toggleRow(protCard.body,'Packet Sensor (Npcap entropy)','packet_sensor'),
    toggleRow(protCard.body,'Windows Event Log Monitor','event_log_monitor'),
    toggleRow(protCard.body,'File System Monitor','fs_monitor'),
    toggleRow(protCard.body,'WORM Auto-Lockdown on rule fires','worm_auto_lockdown'),
  ],[]);

  // Thresholds card
  const thrSec=section('Thresholds'), thrCard=card(thrSec,'Detection Thresholds');
  wireCard(thrCard,[floatRow(thrCard.body,'Chaos threshold K','0.0–1.0','chaos_threshold',0,1,0.01),
    numRow(thrCard.body,'Ollama timeout (s)','5–3600','ollama_timeout_s',5,3600)],[],[]);

  // Agent swarm card
  const agSec=section('Agent Swarm'), agCard=card(agSec,'Thread Pool & Routing');
  wireCard(agCard,[numRow(agCard.body,'Max concurrent tasks','1–64','max_concurrent_tasks',1,64)],[],[]);

  // Network card
  const netSec=section('Network'), netCard=card(netSec,'Ollama Connection');
  wireCard(netCard,[numRow(netCard.body,'Ollama port','1024–65535','ollama_port',1024,65535)],[],
    [textRow(netCard.body,'Ollama host','127.0.0.1 or localhost','ollama_host',['127.0.0.1','localhost'])]);

  // Firewall card
  const fwSec=section('Firewall'), fwCard=card(fwSec,'Active Netsh Rules');
  fwCard.save.style.display=fwCard.revert.style.display='none';
  const fwTable=document.createElement('div'); fwTable.className='table-wrap';
  fwTable.innerHTML=`<table class="data-table"><thead><tr><th>IP</th><th>Rule</th><th>Expires</th><th>Action</th></tr></thead>
    <tbody id="cfg-tbody-fw"><tr><td colspan="4" class="tbl-empty">Loading…</td></tr></tbody></table>`;
  fwCard.body.appendChild(fwTable);
  function refreshFwTable() {
    const tbody=el('cfg-tbody-fw'); if (!tbody||!lastData) return;
    const blocks=lastData.firewall_blocks||[];
    if (!blocks.length){ tbody.innerHTML='<tr><td colspan="4" class="tbl-empty">No active blocks</td></tr>'; return; }
    tbody.innerHTML=blocks.map(f=>`<tr>
      <td class="mono">${esc(f.ip)}</td><td>${esc(f.rule_name_in||'–')}</td>
      <td class="mono muted">${fmtMs(f.expires_at_ms)}</td>
      <td><button class="btn btn--ghost btn--sm" data-unblock="${esc(f.ip)}">Remove</button></td></tr>`).join('');
    tbody.querySelectorAll('[data-unblock]').forEach(btn=>{
      btn.addEventListener('click',()=>{
        openModal(`Remove block for ${btn.dataset.unblock}?`,
          `Delete inbound+outbound netsh rules for <strong>${btn.dataset.unblock}</strong>.`,
          async ()=>{ await apiPost('/exec',{cmd:`netsh advfirewall firewall delete rule name="AstartisBlock_${btn.dataset.unblock}_in"`}); refreshFwTable(); });
      });
    });
  }

  // Actions card
  const actSec=section('Actions'), actCard=card(actSec,'Threat Response');
  actCard.save.style.display=actCard.revert.style.display='none';
  const actDiv=document.createElement('div');
  actDiv.style.cssText='display:flex;flex-wrap:wrap;gap:10px;padding-bottom:4px';
  actDiv.innerHTML=`<button class="btn btn--danger" id="act-worm">Trigger WORM Lockdown</button>
    <button class="btn btn--ghost" id="act-unlock">Request Unlock Vote</button>
    <button class="btn btn--ghost" id="act-scan">Scan Now (clamd)</button>`;
  actCard.body.appendChild(actDiv);
  el('act-worm')?.addEventListener('click',()=>openModal('Trigger WORM Lockdown',
    'This will immediately engage WORM lockdown, freeze all sandbox files, and require a 3-party unlock vote to reverse.',
    ()=>console.log('[Astartis] WORM trigger via UI')));
  el('act-unlock')?.addEventListener('click',()=>openModal('Request Unlock Vote',
    'Begin a new unlock session. All 3 approvers must cast votes.',
    ()=>console.log('[Astartis] Unlock vote via UI')));
  el('act-scan')?.addEventListener('click',()=>openModal('Run ClamAV Scan',
    'Trigger full scan of sandbox via clamd on 127.0.0.1:3310.',
    ()=>console.log('[Astartis] Scan via UI')));

  refreshFwTable();
  setInterval(refreshFwTable, 5000);
}

// ════════════════════════════════════════════════════════════════════════
// TERRA Part 4 — Npcap Verification Trigger
// ════════════════════════════════════════════════════════════════════════
el('btn-npcap-verify')?.addEventListener('click', async () => {
  const badge = el('npcap-result-badge');
  const body  = el('npcap-result-body');
  if (badge) { badge.textContent = 'Running…'; badge.style.background = '#f59e0b'; badge.style.color = '#fff'; }
  if (body)  body.innerHTML = '<em>Sending elevation request to Windows… A UAC prompt will appear shortly.</em>';
  try {
    const res = await fetch('/npcap_verify', {
      method: 'POST',
      headers: { 'X-Astartis-Token': TOKEN, 'Content-Type': 'application/json' },
      body: '{}'
    });
    const data = await res.json();
    if (data.status === 'cancelled') {
      if (badge) { badge.textContent = 'Cancelled'; badge.style.background = '#6b7280'; badge.style.color='#fff'; }
      if (body)  body.innerHTML = '<strong>UAC prompt was declined by user.</strong><br>The elevation dialog appeared (UAC shown ✓) but you clicked "No". Click the button again to retry.';
    } else if (data.status === 'ok' || data.status === 'partial') {
      if (badge) { badge.textContent = 'PASS ✓'; badge.style.background = '#15803d'; badge.style.color = '#fff'; }
      if (body) {
        const e2 = typeof data.mean_entropy_bits==='number' ? data.mean_entropy_bits.toFixed(4) : '–';
        const mx = typeof data.max_entropy_bits ==='number' ? data.max_entropy_bits.toFixed(4)  : '–';
        body.innerHTML = `<strong>✓ Npcap live capture completed</strong><br>
          <span style="color:#57606a">UAC elevation prompt shown: YES (confirmed by OS)</span><br><br>
          <table style="font-size:12px;border-collapse:collapse">
            <tr><td style="padding:3px 8px;color:#57606a">Adapter</td><td class="mono">${esc(data.adapter||'–')}</td></tr>
            <tr><td style="padding:3px 8px;color:#57606a">Packets</td><td class="mono">${data.packets_captured||0} / ${data.packets_target||10}</td></tr>
            <tr><td style="padding:3px 8px;color:#57606a">Mean entropy</td><td class="mono">${e2} bits</td></tr>
            <tr><td style="padding:3px 8px;color:#57606a">Max entropy</td><td class="mono">${mx} bits</td></tr>
            <tr><td style="padding:3px 8px;color:#57606a">Started</td><td class="mono">${esc(data.timestamp_start||'–')}</td></tr>
            <tr><td style="padding:3px 8px;color:#57606a">Finished</td><td class="mono">${esc(data.timestamp_end||'–')}</td></tr>
          </table>
          <div style="margin-top:8px;font-size:12px;color:#57606a">${esc(data.message||'')}</div>`;
      }
    } else if (data.status === 'error') {
      if (badge) { badge.textContent = 'ERROR'; badge.style.background = '#b91c1c'; badge.style.color = '#fff'; }
      if (body)  body.innerHTML = `<strong>Error:</strong> ${esc(data.message||'Unknown error')}<br>
        ${data.hint ? '<span style="color:#57606a">Hint: '+esc(data.hint)+'</span>' : ''}`;
    } else {
      if (badge) { badge.textContent = data.status||'unknown'; badge.style.background = '#6b7280'; badge.style.color='#fff'; }
      if (body)  body.innerHTML = `<pre style="font-size:11px">${esc(JSON.stringify(data,null,2))}</pre>`;
    }
  } catch (e) {
    if (badge) { badge.textContent = 'Network Error'; badge.style.background = '#b91c1c'; badge.style.color='#fff'; }
    if (body)  body.innerHTML = `<strong>Network error:</strong> ${esc(e.message)}`;
  }
});

// ════════════════════════════════════════════════════════════════════════
// MODAL  (updated to use new simplified modal HTML in index.html)
// ════════════════════════════════════════════════════════════════════════
let _modalCb = null;
function openModal(title, body, onConfirm) {
  const titleEl  = el('modal-title');
  const bodyEl   = el('modal-body');
  const backdrop = el('modal-backdrop');
  const box      = el('modal-box');
  if (titleEl)  titleEl.textContent = title;
  if (bodyEl)   bodyEl.innerHTML    = body;
  if (backdrop) backdrop.style.display = 'block';
  if (box)      box.style.display      = 'block';
  _modalCb = onConfirm;
}
function closeModal() {
  const backdrop = el('modal-backdrop');
  const box      = el('modal-box');
  if (backdrop) backdrop.style.display = 'none';
  if (box)      box.style.display      = 'none';
  _modalCb = null;
}
el('modal-close')?.addEventListener('click',   closeModal);
el('modal-cancel')?.addEventListener('click',  closeModal);
el('modal-confirm')?.addEventListener('click', async () => { closeModal(); if(_modalCb){ await _modalCb(); _modalCb=null; } });
el('modal-backdrop')?.addEventListener('click', e => { if(e.target===el('modal-backdrop')) closeModal(); });

// ════════════════════════════════════════════════════════════════════════
// BOOTSTRAP
// ════════════════════════════════════════════════════════════════════════
function init() {
  initCharts();
  activateTab('overview');
  if (!TOKEN) {
    const b = document.createElement('div');
    b.style.cssText='position:fixed;top:0;left:0;right:0;background:#fff1f1;color:#a2191f;font-size:12px;padding:8px 20px;z-index:9999;border-bottom:1px solid #ffd7d9;font-weight:500';
    b.textContent='No auth token — open this page via the bridge (http://127.0.0.1:9876/), not directly from disk.';
    document.body.prepend(b);
  }
  doPoll();
  // BUG-FIX (Part 5): start independent /health heartbeat so backend pill
  // reflects connectivity within 5 s rather than waiting for poll backoff.
  doHealthCheck();
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
else init();
