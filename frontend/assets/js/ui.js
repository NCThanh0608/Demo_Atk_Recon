// ui.js — pure DOM rendering. No network, no business logic.

import { MODULES } from './config.js';

const $ = (id) => document.getElementById(id);
const el = { mods: $('mods'), console: $('console'), runTag: $('run-tag'),
  conn: $('conn'), modeFlag: $('mode-flag'), scopeBadge: $('scope-badge'), scopeNote: $('scope-note'),
  range: $('range'), rangeErr: $('range-err') };

// Elapsed-time counters: show "đang chạy… Xs" while a module is running.
// setModuleSummary() stops the counter when the backend sends a better summary.
const _timers = new Map();

function _stopTimer(id) {
  const t = _timers.get(id);
  if (t) { clearInterval(t); _timers.delete(id); }
}

function _startTimer(id) {
  _stopTimer(id);
  const b = el.mods.querySelector(`.mod[data-mod="${id}"]`);
  const s = b && b.querySelector('[data-stat]');
  if (!s) return;
  const t0 = Date.now();
  _timers.set(id, setInterval(() => {
    if (!_timers.has(id)) return;
    const e = Math.floor((Date.now() - t0) / 1000);
    s.textContent = `đang chạy… ${e}s`;
  }, 1000));
}

const ICONS = (cls) => cls === 'ok' ? '✓' : cls === 'err' ? '✗' : cls === 'warn-c' ? '!' : '▸';
const LEVEL = { info: 'in', ok: 'ok', warn: 'warn-c', error: 'err', err: 'err' };
const MAX_LOG_LINES = 500;   // cap console DOM so long sessions don't grow unbounded

export function renderModules(onToggle) {
  el.mods.innerHTML = '';
  MODULES.forEach(m => {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'mod ' + m.id + (m.danger ? ' dos' : '');
    b.dataset.mod = m.id;
    b.setAttribute('aria-pressed', 'false');
    b.innerHTML =
      `<span class="mod-ic" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${m.icon}</svg></span>` +
      `<span class="mod-main"><span class="mod-name">${m.name}</span><span class="mod-stat" data-stat>Idle</span></span>` +
      `<span class="sw" aria-hidden="true"></span>`;
    b.addEventListener('click', () => onToggle(m, b));
    el.mods.appendChild(b);
  });
}

export function setModuleState(moduleId, on, summary) {
  const b = el.mods.querySelector(`.mod[data-mod="${moduleId}"]`);
  if (!b) return;
  b.setAttribute('aria-pressed', on ? 'true' : 'false');
  const s = b.querySelector('[data-stat]');
  if (on) {
    s.textContent = summary != null ? summary : 'đang chạy…';
    _startTimer(moduleId);
  } else {
    _stopTimer(moduleId);
    s.textContent = summary != null ? summary : 'Idle';
  }
}

export function setModuleSummary(moduleId, summary) {
  const b = el.mods.querySelector(`.mod[data-mod="${moduleId}"]`);
  if (!b || b.getAttribute('aria-pressed') !== 'true') return;
  // Backend sent a live summary (e.g. DOS "~2000 pkt") — stop local timer, use backend text.
  _stopTimer(moduleId);
  b.querySelector('[data-stat]').textContent = summary;
}

export function setLocked(moduleId, locked) {
  const b = el.mods.querySelector(`.mod[data-mod="${moduleId}"]`);
  if (b) {
    b.classList.toggle('locked', locked);
    b.setAttribute('aria-disabled', locked ? 'true' : 'false');
  }
}

// Reflect scan-range validity on the input (red border + hint).
export function setRangeValid(ok) {
  if (el.range) el.range.classList.toggle('bad', !ok);
  if (el.rangeErr) el.rangeErr.hidden = ok;
}

// Render the custom victim dropdown from hosts discovered by scan_ip.
// onPick(ip) is called when the operator chooses an entry.
export function renderHostList(hosts, onPick) {
  const ul = document.getElementById('victim-list');
  if (!ul) return;
  ul.innerHTML = '';
  if (!hosts || !hosts.length) {
    const li = document.createElement('li');
    li.className = 'combo-empty';
    li.textContent = 'Chưa có IP — bấm để tự quét dải đang chọn…';
    ul.appendChild(li);
    return;
  }
  hosts.forEach(h => {
    const li = document.createElement('li');
    li.className = 'combo-item';
    li.setAttribute('role', 'option');
    const meta = [h.hostname, h.vendor || h.mac].filter(Boolean).join(' · ');
    li.innerHTML = `<span class="combo-ip">${escapeHtml(h.ip)}</span>` +
      (meta ? `<span class="combo-meta">${escapeHtml(meta)}</span>` : '');
    li.addEventListener('click', () => onPick(h.ip));
    ul.appendChild(li);
  });
}

export function openHostList(show) {
  const ul = document.getElementById('victim-list');
  const caret = document.getElementById('victim-caret');
  if (ul) ul.hidden = !show;
  if (caret) caret.setAttribute('aria-expanded', show ? 'true' : 'false');
}

export function isHostListOpen() {
  const ul = document.getElementById('victim-list');
  return !!ul && !ul.hidden;
}

// Render the IP -> open-ports table. rows: [{ip, hostname, vendor, mac, ports}]
// ports: null = chưa quét cổng; [] = không có cổng mở; [{port, proto, service, version}]
export function renderResults(rows, onPickIp) {
  const body = document.getElementById('results-body');
  const empty = document.getElementById('results-empty');
  if (!body) return;
  body.innerHTML = '';
  if (!rows || !rows.length) { if (empty) empty.hidden = false; return; }
  if (empty) empty.hidden = true;
  rows.forEach(r => {
    const tr = document.createElement('tr');
    if (onPickIp) {
      tr.className = 'row-pick';
      tr.title = 'Bấm để chọn IP này làm mục tiêu';
      tr.addEventListener('click', () => onPickIp(r.ip));
    }
    const meta = [r.hostname, r.vendor || r.mac].filter(Boolean).join(' · ');
    let ports;
    if (r.ports == null) ports = '<span class="cell-muted">chưa quét cổng</span>';
    else if (!r.ports.length) ports = '<span class="cell-muted">không có cổng nào mở</span>';
    else ports = r.ports.map(p =>
      `<span class="port-chip"><b>${escapeHtml(String(p.port))}</b>`
      + `<span class="port-proto">/${escapeHtml(p.proto || 'tcp')}</span></span>`
    ).join('');
    let creds;
    if (r.creds == null) creds = '<span class="cell-muted">chưa dò</span>';
    else if (!r.creds.length) creds = '<span class="cell-muted">không có</span>';
    else creds = r.creds.map(c =>
      `<span class="cell-cred">${escapeHtml(c.username)} : ${escapeHtml(c.password)}</span>`
    ).join('');
    tr.innerHTML =
      `<td><div class="cell-ip">${escapeHtml(r.ip)}</div>`
      + (meta ? `<div class="cell-meta">${escapeHtml(meta)}</div>` : '') + '</td>'
      + `<td><div class="cell-ports">${ports}</div></td>`
      + `<td><div class="cell-creds">${creds}</div></td>`;
    body.appendChild(tr);
  });
}

// Small hint under the victim field (e.g. "đang tự quét…" / "N IP sẵn sàng").
export function setVictimHint(text, isError) {
  const h = document.getElementById('victim-hint');
  if (!h) return;
  h.textContent = text || '';
  h.hidden = !text;
  h.classList.toggle('bad', !!isError);
}

export function log(moduleId, text, level = 'info') {
  const cls = LEVEL[level] || 'in';
  const row = document.createElement('div');
  row.className = 'ln';
  const t = new Date().toTimeString().slice(0, 8);
  row.innerHTML = `<span class="t">${t}</span> <span class="${cls}">${ICONS(cls)}</span> ` +
    `<span class="mod-ref">[${moduleId}]</span> ${escapeHtml(text)}`;
  el.console.appendChild(row);
  while (el.console.childElementCount > MAX_LOG_LINES) el.console.removeChild(el.console.firstChild);
  el.console.scrollTop = el.console.scrollHeight;
}

export function setRunningCount(n) { el.runTag.textContent = `${n}/${MODULES.length} đang chạy`; }

export function setMode(mode) {
  // mode: 'live' | 'mock' | 'down'. The bottom mode-flag was removed, so guard it.
  const flag = (cls, text) => { if (el.modeFlag) { el.modeFlag.className = cls; el.modeFlag.textContent = text; } };
  if (mode === 'live') {
    el.conn.className = 'chip live'; el.conn.innerHTML = '<span class="dot"></span>Backend trực tuyến';
    flag('demo-flag live', '● Live');
  } else if (mode === 'down') {
    el.conn.className = 'chip down'; el.conn.innerHTML = '<span class="dot"></span>Mất kết nối';
    flag('demo-flag down', '● Mất kết nối');
  } else {
    el.conn.className = 'chip mock'; el.conn.innerHTML = '<span class="dot"></span>Mock (chưa có backend)';
    flag('demo-flag', '● Demo');
  }
}

export function setScope(ok, value) {
  const b = el.scopeBadge, n = el.scopeNote;
  if (!value) {                       // empty target -> neutral, not a red "công cộng"
    b.className = 'badge neutral';
    b.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/></svg>Chưa chọn mục tiêu';
    n.textContent = 'Chọn IP đã quét hoặc nhập tay.';
    return;
  }
  if (ok) {
    b.className = 'badge ok';
    b.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>Nội bộ';
    n.textContent = 'Mục tiêu thuộc mạng nội bộ (RFC1918).';
  } else {
    b.className = 'badge bad';
    b.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18M6 6l12 12"/></svg>IP công cộng';
    n.textContent = 'IP công cộng — DoS bị khóa.';
  }
}

function escapeHtml(s) { return String(s).replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c])); }
