import { escapeHtml } from './config.js';

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

// ---------------------------------------------------------------- console log
const MAX_LOG = 500;
let logCount = 0;

export function appendLog(module, level, text) {
  const c = $('#console');
  if (!c) return;
  const ts = new Date().toLocaleTimeString('vi');
  const div = document.createElement('div');
  div.className = 'log';
  div.innerHTML = `<span class="log-ts">${ts}</span><span class="log-mod">[${escapeHtml(module)}]</span><span class="log-${level}">${escapeHtml(text)}</span>`;
  c.appendChild(div);
  logCount++;
  if (logCount > MAX_LOG) {
    c.firstChild?.remove();
    logCount--;
  }
  c.scrollTop = c.scrollHeight;
}

export function clearLog() {
  const c = $('#console');
  if (c) { c.innerHTML = ''; logCount = 0; }
}

// ---------------------------------------------------------------- scan results
let scannedHosts = [];

export function getScannedHosts() { return scannedHosts; }

export function renderScanResults(hosts) {
  scannedHosts = hosts;
  const tbody = $('#scan-body');
  const wrap = $('#scan-results');
  if (!tbody || !wrap) return;
  wrap.hidden = false;
  tbody.innerHTML = '';
  hosts.forEach((h, i) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><input type="checkbox" class="host-cb" data-idx="${i}" data-ip="${escapeHtml(h.ip)}"></td>
      <td class="ip-cell">${escapeHtml(h.ip)}</td>
      <td>${escapeHtml(h.hostname || '—')}</td>
      <td class="mono">${escapeHtml(h.mac || '—')}</td>
      <td>${escapeHtml(h.vendor || '—')}</td>
      <td>${h.rtt_ms ? h.rtt_ms + 'ms' : '—'}</td>`;
    tbody.appendChild(tr);
  });
}

export function getSelectedIPs() {
  return [...$$('.host-cb:checked')].map(cb => cb.dataset.ip);
}

// ---------------------------------------------------------------- individual creds
export function renderIndividualCreds(ips) {
  const wrap = $('#individual-creds');
  if (!wrap) return;
  wrap.innerHTML = '';
  ips.forEach(ip => {
    const div = document.createElement('div');
    div.className = 'ind-cred-row';
    div.innerHTML = `
      <span class="ip-label">${escapeHtml(ip)}</span>
      <input class="inp sm mono ind-user" data-ip="${escapeHtml(ip)}" placeholder="root" value="root">
      <input class="inp sm mono ind-pass" data-ip="${escapeHtml(ip)}" placeholder="password" type="password" value="vnpt@123">`;
    wrap.appendChild(div);
  });
}

export function getIndividualCreds() {
  const creds = [];
  $$('.ind-cred-row').forEach(row => {
    const ip = row.querySelector('.ind-user')?.dataset.ip;
    const user = row.querySelector('.ind-user')?.value || 'root';
    const pass = row.querySelector('.ind-pass')?.value || '';
    if (ip) creds.push({ ip, username: user, password: pass });
  });
  return creds;
}

// ---------------------------------------------------------------- binary table
export function renderBinaryStatus(results, cameraStatus) {
  const tbody = $('#binary-body');
  if (!tbody) return;
  tbody.innerHTML = '';

  const connectedIPs = Object.keys(cameraStatus || {});
  const checkMap = {};
  (results || []).forEach(r => { checkMap[r.ip] = r; });

  connectedIPs.forEach(ip => {
    const cam = cameraStatus[ip];
    const bin = checkMap[ip];
    const tr = document.createElement('tr');
    const online = cam?.connected ? '<span class="st-online">Online</span>' : '<span class="st-offline">Offline</span>';
    let dosStatus = '<span class="st-missing">—</span>';
    let toolsStatus = '<span class="st-missing">—</span>';
    let actions = '';
    if (bin) {
      if (bin.exists) {
        dosStatus = `<span class="st-exists">✓ ${escapeHtml(bin.size || '?')}B</span>`;
        actions += `<button class="btn btn-crit btn-sm del-bin" data-ip="${escapeHtml(ip)}">Xóa DoS</button> `;
      } else {
        dosStatus = '<span class="st-missing">✗</span>';
        actions += `<button class="btn btn-accent btn-sm deploy-bin" data-ip="${escapeHtml(ip)}">Deploy DoS</button> `;
      }
      if (bin.tools_exists) {
        toolsStatus = bin.tools_size
          ? `<span class="st-exists">✓ ${escapeHtml(bin.tools_size)}B</span>`
          : '<span class="st-exists">✓</span>';
        actions += `<button class="btn btn-crit btn-sm del-tools" data-ip="${escapeHtml(ip)}">Xóa Tools</button>`;
      } else {
        toolsStatus = '<span class="st-missing">✗</span>';
        actions += `<button class="btn btn-accent btn-sm deploy-tools" data-ip="${escapeHtml(ip)}">Deploy Tools</button>`;
      }
    }
    tr.innerHTML = `
      <td class="ip-cell">${escapeHtml(ip)}</td>
      <td>${online}</td>
      <td>${dosStatus}</td>
      <td>${toolsStatus}</td>
      <td>${actions}</td>`;
    tbody.appendChild(tr);
  });
}

// ---------------------------------------------------------------- credential DB table
export function renderCredentials(credentials) {
  const tbody = $('#db-body');
  if (!tbody) return;
  tbody.innerHTML = '';
  credentials.forEach(c => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="ip-cell">${escapeHtml(c.ip)}</td>
      <td>${escapeHtml(c.username)}</td>
      <td class="mono">${escapeHtml(c.password)}</td>
      <td>${escapeHtml(c.label || '')}</td>
      <td>${escapeHtml(c.group || '')}</td>
      <td>${escapeHtml(c.last_connected || '—')}</td>
      <td>${escapeHtml(c.notes || '')}</td>
      <td><button class="btn btn-crit btn-sm del-cred" data-ip="${escapeHtml(c.ip)}">Xóa</button></td>`;
    tbody.appendChild(tr);
  });
}

// ---------------------------------------------------------------- connection chip
export function updateConnChip(state) {
  const chip = $('#conn');
  if (!chip) return;
  const dot = chip.querySelector('.dot');
  if (state === 'up') {
    chip.className = 'chip live';
    chip.innerHTML = '<span class="dot"></span>Trực tuyến';
    if (dot) dot.style.background = '';
  } else {
    chip.className = 'chip down';
    chip.innerHTML = '<span class="dot"></span>Mất kết nối';
  }
}

export function updateCamCount(n) {
  const el = $('#cam-count');
  if (el) el.textContent = `${n} camera`;
}

export function updateScanBadge(state, text) {
  const el = $('#scan-badge');
  if (!el) return;
  if (state === 'running') {
    el.className = 'badge warn';
    el.textContent = text || 'Đang quét…';
  } else {
    el.className = 'badge ok';
    el.textContent = text || '';
  }
}

// ---------------------------------------------------------------- exec camera list
export function renderExecCameras(cameraStatus, binaryResults) {
  const tbody = $('#exec-cam-body');
  if (!tbody) return;

  const prevChecked = new Set([...$$('.exec-cb:checked')].map(cb => cb.dataset.ip));

  tbody.innerHTML = '';

  const connectedIPs = Object.keys(cameraStatus || {});
  const checkMap = {};
  (binaryResults || []).forEach(r => { checkMap[r.ip] = r; });

  if (connectedIPs.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;opacity:.5">Chưa có camera nào kết nối</td></tr>';
    return;
  }

  connectedIPs.forEach(ip => {
    const cam = cameraStatus[ip];
    const bin = checkMap[ip];
    const online = cam?.connected ? '<span class="st-online">Online</span>' : '<span class="st-offline">Offline</span>';
    let binStatus = '<span class="st-missing">—</span>';
    if (bin) {
      binStatus = bin.exists
        ? '<span class="st-exists">&#10003;</span>'
        : '<span class="st-missing">&#10007;</span>';
    }
    const checked = prevChecked.has(ip) ? ' checked' : '';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><input type="checkbox" class="exec-cb" data-ip="${escapeHtml(ip)}"${checked}></td>
      <td class="ip-cell">${escapeHtml(ip)}</td>
      <td>${online}</td>
      <td>${binStatus}</td>`;
    tbody.appendChild(tr);
  });
}

export function getSelectedExecIPs() {
  return [...$$('.exec-cb:checked')].map(cb => cb.dataset.ip);
}

export function setupExecSelectAll() {
  const sa = $('#exec-select-all');
  if (!sa) return;
  sa.addEventListener('change', () => {
    $$('.exec-cb').forEach(cb => { cb.checked = sa.checked; });
  });
}

// ---------------------------------------------------------------- select all
export function setupSelectAll() {
  const sa = $('#select-all');
  if (!sa) return;
  sa.addEventListener('change', () => {
    $$('.host-cb').forEach(cb => { cb.checked = sa.checked; });
  });
}

// ---------------------------------------------------------------- theme toggle
export function setupTheme() {
  const btn = $('#theme');
  if (!btn) return;
  const root = document.documentElement;
  btn.addEventListener('click', () => {
    const current = root.getAttribute('data-theme');
    if (current === 'dark') {
      root.setAttribute('data-theme', 'light');
    } else {
      root.setAttribute('data-theme', 'dark');
    }
  });
}

// ---------------------------------------------------------------- exec monitor panel
export function showMonitorPanel(visible) {
  const panel = $('#monitor-panel');
  if (panel) panel.hidden = !visible;
  if (!visible) {
    const cards = $('#monitor-cards');
    if (cards) cards.innerHTML = '';
  }
}

export function updateMonitorPanel(data) {
  const panel = $('#monitor-panel');
  if (!panel || panel.hidden) return;
  const cards = $('#monitor-cards');
  const elapsedEl = $('#monitor-elapsed');
  if (!cards) return;

  const ips = Object.keys(data).sort();
  if (ips.length === 0) return;

  if (elapsedEl) {
    const first = data[ips[0]];
    const s = first?.elapsed || 0;
    const m = Math.floor(s / 60);
    elapsedEl.textContent = m > 0 ? `${m}m ${s % 60}s` : `${s}s`;
  }

  cards.innerHTML = '';
  ips.forEach(ip => {
    const d = data[ip];
    const card = document.createElement('div');
    card.className = 'mon-card';

    const statusClass = d.status === 'running' ? 'mon-running' :
                        d.status === 'stopped' ? 'mon-stopped' : 'mon-waiting';
    const statusLabel = d.status === 'running' ? 'Running' :
                        d.status === 'stopped' ? 'Stopped' :
                        d.status === 'error' ? 'Error' : 'Waiting';
    const modes = (d.modes || []).map(m =>
      m === 'udp' ? 'UDP' : m === 'icmp' ? 'ICMP' : m === 'syn' ? 'SYN' : 'Slowloris'
    ).join(' + ') || '—';

    let metricsHTML = '';

    if (d.udp_total !== undefined) {
      metricsHTML += `
        <div class="mon-metric">
          <span class="mon-label">UDP Sent</span>
          <span class="mon-value">${fmtNum(d.udp_total)}</span>
        </div>
        <div class="mon-metric">
          <span class="mon-label">UDP pkt/s</span>
          <span class="mon-value mon-highlight">${fmtNum(d.udp_pps)}</span>
        </div>`;
      if (d.udp_drop !== undefined) {
        metricsHTML += `
        <div class="mon-metric">
          <span class="mon-label">Drop</span>
          <span class="mon-value ${d.udp_drop > 0 ? 'mon-warn' : ''}">${fmtNum(d.udp_drop)} (${d.udp_drop_pct}%)</span>
        </div>`;
      }
    }

    if (d.icmp_total !== undefined) {
      metricsHTML += `
        <div class="mon-metric">
          <span class="mon-label">ICMP Sent</span>
          <span class="mon-value">${fmtNum(d.icmp_total)}</span>
        </div>
        <div class="mon-metric">
          <span class="mon-label">ICMP pkt/s</span>
          <span class="mon-value mon-highlight">${fmtNum(d.icmp_pps)}</span>
        </div>`;
    }

    if (d.sl_held !== undefined) {
      metricsHTML += `
        <div class="mon-metric">
          <span class="mon-label">Connections</span>
          <span class="mon-value">${d.sl_held}/${d.sl_target}</span>
        </div>
        <div class="mon-metric">
          <span class="mon-label">Port</span>
          <span class="mon-value">${d.sl_port}</span>
        </div>
        <div class="mon-metric">
          <span class="mon-label">Success</span>
          <span class="mon-value">${d.sl_rate}</span>
        </div>
        <div class="mon-metric">
          <span class="mon-label">Health</span>
          <span class="mon-value ${d.sl_health === 'UNAVAILABLE' ? 'mon-crit' : d.sl_health === 'DEGRADED' ? 'mon-warn' : 'mon-good'}">${escapeHtml(d.sl_health)}</span>
        </div>
        <div class="mon-metric">
          <span class="mon-label">Latency</span>
          <span class="mon-value">${escapeHtml(d.sl_latency)}</span>
        </div>`;
    }

    if (!metricsHTML) {
      metricsHTML = '<div class="mon-metric"><span class="mon-label">Waiting for data…</span></div>';
    }

    card.innerHTML = `
      <div class="mon-card-head">
        <span class="mon-ip">${escapeHtml(ip)}</span>
        <span class="mon-status ${statusClass}">${statusLabel}</span>
      </div>
      <div class="mon-modes">${escapeHtml(modes)}</div>
      <div class="mon-metrics">${metricsHTML}</div>`;
    cards.appendChild(card);
  });
}

function fmtNum(n) {
  if (n === undefined || n === null) return '—';
  if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
  if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
  return String(n);
}

// ---------------------------------------------------------------- add cred dialog
export function promptAddCred() {
  const ip = prompt('IP camera:');
  if (!ip) return null;
  const username = prompt('Username:', 'root') || 'root';
  const password = prompt('Password:', 'vnpt@123') || '';
  const label = prompt('Label (tên camera):', '') || '';
  return { ip, username, password, label, group: '', last_connected: '', notes: '' };
}
