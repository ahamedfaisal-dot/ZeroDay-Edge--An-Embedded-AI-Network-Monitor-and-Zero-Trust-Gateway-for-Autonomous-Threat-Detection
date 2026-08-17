/**
 * app.js — ZeroDay-Edge RPi5 Node SPA
 *
 * Responsibilities:
 *  - Clock update every second
 *  - Tab navigation (5 pages, no scroll)
 *  - Dashboard polling every 4 s (stats + mini-feed)
 *  - Alerts polling every 8 s
 *  - Blocked polling every 10 s (when page active)
 *  - Network devices refresh on tab open + every 30 s
 *  - XAI select population + bar chart rendering
 *  - Unblock button handler
 */

'use strict';

/* ── Constants ────────────────────────────────────────────────────────── */
const API = {
  stats:     '/api/stats',
  alerts:    '/api/alerts',
  network:   '/api/network',
  blocked:   '/api/blocked',
  iot:       '/api/iot',
  iotTrust:  (mac) => `/api/iot/${encodeURIComponent(mac)}/trust`,
  iotBlock:  (mac) => `/api/iot/${encodeURIComponent(mac)}/block`,
  xai:       (id)  => `/api/xai/${id}`,
  block:     (ip)  => `/api/block/${encodeURIComponent(ip)}`,
  unblock:   (ip)  => `/api/unblock/${encodeURIComponent(ip)}`,
  clear:     '/api/clear',
};

/* ── State ────────────────────────────────────────────────────────────── */
let activePage = 'dashboard';
let threatAlerts = [];   // cached for XAI dropdown population

/* ── Utilities ────────────────────────────────────────────────────────── */
function esc(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function escAttr(s) {
  return esc(s).replace(/'/g, '&#39;');
}

function fmtNum(n) {
  n = Number(n) || 0;
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
  return String(n);
}

function fmtPct(f) {
  return ((Number(f) || 0) * 100).toFixed(0) + '%';
}

function fmtTime(iso) {
  if (!iso) return '--:--';
  try {
    const d = new Date(iso.includes('Z') ? iso : iso + 'Z');
    if (isNaN(d)) return '--:--';
    const hh = String(d.getHours()).padStart(2, '0');
    const mm = String(d.getMinutes()).padStart(2, '0');
    const ss = String(d.getSeconds()).padStart(2, '0');
    return `${hh}:${mm}:${ss}`;
  } catch { return '--:--'; }
}

function threatColour(cls) {
  if (!cls) return 'success';
  const lc = cls.toLowerCase();
  if (lc === 'benign' || lc === 'normal') return 'success';
  if (lc.includes('scan') || lc.includes('ddos')) return 'warning';
  return 'danger';
}

async function fetchJSON(url) {
  try {
    const r = await fetch(url);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return await r.json();
  } catch (e) {
    console.warn('fetchJSON', url, e.message);
    return null;
  }
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function setHTML(id, html) {
  const el = document.getElementById(id);
  if (el) el.innerHTML = html;
}

/* ── Clock ────────────────────────────────────────────────────────────── */
function tickClock() {
  const now = new Date();
  const h = String(now.getHours()).padStart(2, '0');
  const m = String(now.getMinutes()).padStart(2, '0');
  const s = String(now.getSeconds()).padStart(2, '0');
  setText('clock', `${h}:${m}:${s}`);
}
setInterval(tickClock, 1000);
tickClock();

/* ── Navigation ───────────────────────────────────────────────────────── */
function switchPage(page) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));

  const pageEl = document.getElementById(`p-${page}`);
  const tabEl  = document.getElementById(`t-${page}`);
  if (pageEl) pageEl.classList.add('active');
  if (tabEl)  tabEl.classList.add('active');

  activePage = page;

  // Trigger immediate data refresh for newly visible page
  if (page === 'alerts')  renderAlerts(threatAlerts);
  if (page === 'blocked') fetchBlocked();
  if (page === 'network') fetchNetwork();
  if (page === 'xai')     populateXaiSelect();
}

document.querySelectorAll('.nav-tab').forEach(tab => {
  tab.addEventListener('click', () => switchPage(tab.dataset.page));
});

/* ══════════════════════════════════════════════════════════════════════ */
/* DASHBOARD                                                               */
/* ══════════════════════════════════════════════════════════════════════ */

async function fetchStats() {
  const data = await fetchJSON(API.stats);
  if (!data) return;

  setText('kpi-flows',   fmtNum(data.total_flows));
  setText('kpi-threats', fmtNum(data.total_threats));
  setText('kpi-blocked', fmtNum(data.threats_blocked));
  setText('rpi-ip', data.rpi_ip || '—');

  // Confidence bar
  const conf = Number(data.avg_confidence) || 0;
  const fill = document.getElementById('conf-fill');
  if (fill) fill.style.width = `${(conf * 100).toFixed(0)}%`;
  setText('conf-pct', `${(conf * 100).toFixed(0)}%`);

  // Last threat
  renderLastThreat(data.last_alert);
}

function renderLastThreat(alert) {
  const el = document.getElementById('last-threat-body');
  if (!el) return;

  if (!alert) {
    el.innerHTML = '<span class="c-dim" style="font-size:11px">No threats detected yet</span>';
    return;
  }

  const conf = fmtPct(alert.confidence);
  const col  = threatColour(alert.threat_class);

  el.innerHTML = `
    <div class="last-threat-row">
      <span class="threat-ip">${esc(alert.source_ip)}</span>
      <span class="threat-class">${esc(alert.threat_class)}</span>
      <span class="threat-conf c-${col}">${conf}</span>
    </div>
    <div class="threat-model">${esc(alert.detected_by || '')}${alert.is_blocked ? ' · <span style="color:var(--danger)">BLOCKED</span>' : ''}</div>
  `;
}

async function fetchDashboardFeed() {
  const data = await fetchJSON(API.alerts + '?limit=5&threats_only=true');
  if (!data) return;

  const feed = document.getElementById('mini-feed');
  if (!feed) return;

  if (data.length === 0) {
    feed.innerHTML = '<div class="feed-item"><span class="c-dim" style="font-size:11px">No threats in this session</span></div>';
    return;
  }

  feed.innerHTML = data.map(a => {
    const col  = threatColour(a.threat_class);
    const pct  = fmtPct(a.confidence);
    const time = fmtTime(a.timestamp);
    return `<div class="feed-item">
      <span class="feed-time">${time}</span>
      <span class="feed-src c-danger">${esc(a.source_ip)}</span>
      <span class="feed-cls">${esc(a.threat_class)}</span>
      <span class="feed-pct c-${col}">${pct}</span>
    </div>`;
  }).join('');
}

/* ══════════════════════════════════════════════════════════════════════ */
/* ALERTS PAGE                                                             */
/* ══════════════════════════════════════════════════════════════════════ */

async function fetchAlerts() {
  const data = await fetchJSON(API.alerts + '?limit=20&threats_only=true');
  if (!data) return;
  threatAlerts = data;  // cache for XAI dropdown

  const badge = document.getElementById('alert-badge');
  if (badge) badge.textContent = data.length;

  if (activePage === 'alerts') renderAlerts(data);
}

function renderAlerts(data) {
  const el = document.getElementById('alert-list');
  if (!el) return;

  if (!data || data.length === 0) {
    el.innerHTML = '<div class="empty">No threat alerts recorded</div>';
    return;
  }

  // Show up to 4 cards in the 228px content area
  el.innerHTML = data.slice(0, 4).map(a => {
    const conf  = fmtPct(a.confidence);
    const col   = threatColour(a.threat_class);
    const time  = fmtTime(a.timestamp);
    const blocked = a.is_blocked
      ? '<span class="blocked-tag">BLOCKED</span>'
      : '';

    return `<div class="alert-card">
      <div class="alert-r1">
        <span class="threat-pill pill-${col}">${esc(a.threat_class)}</span>
        <span class="model-name">${esc(a.detected_by || '')}</span>
        <span class="conf-inline">${conf}</span>
      </div>
      <div class="alert-r2">
        <span class="ip-pair">${esc(a.source_ip)} → ${esc(a.dest_ip)}</span>
        ${blocked}
        <span class="ts-small">${time}</span>
      </div>
    </div>`;
  }).join('');
}

/* ══════════════════════════════════════════════════════════════════════ */
/* NETWORK PAGE — ZERO TRUST GATEWAY                                       */
/* ══════════════════════════════════════════════════════════════════════ */

async function fetchNetwork() {
  const data = await fetchJSON(API.iot);
  if (!data) return;

  const el = document.getElementById('device-list');
  if (!el) return;

  // Update header count pills
  const unverified = data.filter(d => d.status === 'unverified').length;
  const trusted    = data.filter(d => d.status === 'trusted').length;
  const blocked    = data.filter(d => d.status === 'blocked').length;

  setText('zt-unverified', `${unverified} Unverified`);
  setText('zt-trusted',    `${trusted} Trusted`);
  setText('zt-blocked-ct', `${blocked} Blocked`);

  if (data.length === 0) {
    el.innerHTML = '<div class="empty">No devices found — tap Scan to begin</div>';
    return;
  }

  el.innerHTML = data.slice(0, 4).map(d => {
    const score  = Number(d.trust_score) || 0;
    const scoreW = score.toFixed(0) + '%';
    const fillCls = score >= 60 ? 'high' : score >= 30 ? 'med' : 'low';
    const stLabel = d.status || 'unverified';
    const badgeCls = `zt-badge-${stLabel}`;
    const alertsCls = (d.alert_count || 0) > 0 ? 'has-alerts' : '';

    // Only show Trust button for non-trusted, non-blocked devices
    const trustBtn = stLabel === 'unverified'
      ? `<button class="btn-trust" data-mac="${escAttr(d.mac)}" title="Mark as trusted">Trust</button>`
      : '';

    // Block button only if not already blocked
    const blockBtn = stLabel !== 'blocked'
      ? `<button class="btn-zt-block" data-mac="${escAttr(d.mac)}" title="Block this device">Block</button>`
      : '';

    return `<div class="zt-device status-${stLabel}">
      <div class="zt-r1">
        <span class="zt-hostname">${esc(d.hostname || 'unknown')}</span>
        <span class="zt-ip">${esc(d.ip || '?')}</span>
        <span class="zt-badge ${badgeCls}">${stLabel}</span>
      </div>
      <div class="zt-r2">
        <div class="trust-track"><div class="trust-fill ${fillCls}" style="width:${scoreW}"></div></div>
        <span class="trust-pct">${score.toFixed(0)}</span>
        <span class="zt-alerts ${alertsCls}">${d.alert_count || 0} ⚠</span>
        ${trustBtn}${blockBtn}
      </div>
    </div>`;
  }).join('');

  // Bind Trust buttons
  el.querySelectorAll('.btn-trust').forEach(btn => {
    btn.addEventListener('click', async () => {
      const mac = btn.dataset.mac;
      btn.textContent = '…';
      btn.disabled = true;
      await fetch(API.iotTrust(mac), { method: 'POST' });
      await fetchNetwork();
    });
  });

  // Bind Block buttons
  el.querySelectorAll('.btn-zt-block').forEach(btn => {
    btn.addEventListener('click', async () => {
      const mac = btn.dataset.mac;
      btn.textContent = '…';
      btn.disabled = true;
      await fetch(API.iotBlock(mac), { method: 'POST' });
      await fetchNetwork();
      await fetchBlocked();  // refresh blocked list too
    });
  });
}

document.getElementById('btn-scan')?.addEventListener('click', async () => {
  const btn = document.getElementById('btn-scan');
  if (btn) { btn.textContent = '…'; btn.disabled = true; }
  // Trigger ARP scan via the /api/network endpoint (scanner drains & refreshes)
  await fetchJSON(API.network);
  await fetchNetwork();
  if (btn) { btn.textContent = 'Scan'; btn.disabled = false; }
});

document.getElementById('btn-clear')?.addEventListener('click', async () => {
  if (!confirm('Clear all alerts, flows, blocked IPs, and device registry? This cannot be undone.')) return;
  const btn = document.getElementById('btn-clear');
  if (btn) { btn.textContent = '…'; btn.disabled = true; }
  await fetch(API.clear, { method: 'POST' });
  await Promise.all([pollDashboard(), pollAlerts(), fetchBlocked(), fetchNetwork()]);
  if (btn) { btn.textContent = 'Clear'; btn.disabled = false; }
});

/* ══════════════════════════════════════════════════════════════════════ */
/* BLOCKED PAGE                                                            */
/* ══════════════════════════════════════════════════════════════════════ */

async function fetchBlocked() {
  const data = await fetchJSON(API.blocked);
  if (!data) return;

  const badge = document.getElementById('blocked-badge');
  if (badge) {
    badge.textContent = data.length;
    badge.className = 'badge' + (data.length > 0 ? ' badge-danger' : '');
  }

  if (activePage !== 'blocked') return;

  const el = document.getElementById('blocked-list');
  if (!el) return;

  if (data.length === 0) {
    el.innerHTML = '<div class="empty">No IPs currently blocked</div>';
    return;
  }

  el.innerHTML = data.slice(0, 4).map(b => {
    const type = b.auto_blocked ? 'AUTO' : 'MANUAL';
    const time = fmtTime(b.blocked_at);
    return `<div class="blocked-row">
      <span class="blocked-ip">${esc(b.ip)}</span>
      <span class="block-type">${type}</span>
      <span class="block-time">${time}</span>
      <button class="btn-unblock" data-ip="${escAttr(b.ip)}">Unblock</button>
    </div>`;
  }).join('');

  // Bind unblock buttons
  el.querySelectorAll('.btn-unblock').forEach(btn => {
    btn.addEventListener('click', async () => {
      const ip = btn.dataset.ip;
      btn.textContent = '…';
      btn.disabled = true;
      await fetch(API.unblock(ip), { method: 'POST' });
      await fetchBlocked();
    });
  });
}

/* ══════════════════════════════════════════════════════════════════════ */
/* XAI PAGE                                                                */
/* ══════════════════════════════════════════════════════════════════════ */

function populateXaiSelect() {
  const sel = document.getElementById('xai-select');
  if (!sel) return;

  if (!threatAlerts || threatAlerts.length === 0) {
    sel.innerHTML = '<option value="">No threat alerts available</option>';
    return;
  }

  sel.innerHTML = '<option value="">Select threat alert…</option>' +
    threatAlerts.slice(0, 30).map(a => {
      const time = fmtTime(a.timestamp);
      const conf = fmtPct(a.confidence);
      return `<option value="${a.id}">${esc(a.source_ip)} — ${esc(a.threat_class)} (${conf}) @ ${time}</option>`;
    }).join('');
}

document.getElementById('xai-select')?.addEventListener('change', async function () {
  const id = this.value;
  if (!id) {
    setHTML('xai-meta', '');
    setHTML('xai-bars', '<div class="empty">Select an alert to see AI explanation</div>');
    return;
  }

  const data = await fetchJSON(API.xai(id));
  if (!data) return;
  renderXai(data);
});

function renderXai(data) {
  const col  = threatColour(data.threat_class);
  const conf = fmtPct(data.confidence);

  setHTML('xai-meta', `
    <span><b>${esc(data.threat_class)}</b></span>
    <span>${conf} confidence</span>
    <span class="c-dim">${esc(data.detected_by || '')}</span>
    ${data.is_blocked ? '<span class="c-danger">● BLOCKED</span>' : ''}
  `);

  const bars = document.getElementById('xai-bars');
  if (!bars) return;

  const features = data.xai_features || [];

  if (features.length === 0) {
    bars.innerHTML = '<div class="empty">No feature data stored for this alert</div>';
    return;
  }

  const maxImpact = Math.max(...features.map(f => Math.abs(f.impact || 0)), 0.001);

  // Render top 7 features as horizontal bars
  const labelRow = `<div class="shap-label">Feature Contributions</div>`;

  const rows = features.slice(0, 7).map(f => {
    const imp    = Number(f.impact) || 0;
    const isPos  = imp >= 0;
    const pct    = ((Math.abs(imp) / maxImpact) * 100).toFixed(1);
    const valStr = (imp >= 0 ? '+' : '') + imp.toFixed(3);
    const name   = (f.name || '').length > 17
      ? (f.name || '').slice(0, 16) + '…'
      : (f.name || '');

    return `<div class="shap-row">
      <span class="shap-name">${esc(name)}</span>
      <div class="shap-track">
        <div class="shap-fill ${isPos ? 'pos' : 'neg'}" style="width:${pct}%"></div>
      </div>
      <span class="shap-val ${isPos ? 'pos' : 'neg'}">${valStr}</span>
    </div>`;
  }).join('');

  bars.innerHTML = labelRow + rows;
}

/* ══════════════════════════════════════════════════════════════════════ */
/* POLLING INTERVALS                                                       */
/* ══════════════════════════════════════════════════════════════════════ */

async function pollDashboard() {
  await fetchStats();
  await fetchDashboardFeed();
}

async function pollAlerts() {
  await fetchAlerts();
}

// Initial load
pollDashboard();
pollAlerts();
fetchBlocked();

// Recurring polls
setInterval(pollDashboard, 4000);   // stats + mini feed every 4 s
setInterval(pollAlerts,    8000);   // alerts list every 8 s
setInterval(fetchBlocked,  10000);  // blocked IPs every 10 s

// Network page auto-refresh when visible
setInterval(() => {
  if (activePage === 'network') fetchNetwork();
}, 30000);
