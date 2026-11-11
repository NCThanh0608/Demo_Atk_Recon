// ui.js — pure DOM rendering. No network, no business logic.

import { MODULES } from './config.js';

const $ = (id) => document.getElementById(id);
const el = { mods: $('mods'), console: $('console'), runTag: $('run-tag'),
  conn: $('conn'), modeFlag: $('mode-flag'), scopeBadge: $('scope-badge'), scopeNote: $('scope-note') };

const ICONS = (cls) => cls === 'ok' ? '✓' : cls === 'err' ? '✗' : cls === 'warn-c' ? '!' : '▸';
const LEVEL = { info: 'in', ok: 'ok', warn: 'warn-c', error: 'err', err: 'err' };

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
  if (summary != null) s.textContent = summary;
  else if (!on) s.textContent = 'Idle';
}

export function setModuleSummary(moduleId, summary) {
  const b = el.mods.querySelector(`.mod[data-mod="${moduleId}"]`);
  if (b && b.getAttribute('aria-pressed') === 'true') b.querySelector('[data-stat]').textContent = summary;
}

export function setLocked(moduleId, locked) {
  const b = el.mods.querySelector(`.mod[data-mod="${moduleId}"]`);
  if (b) b.classList.toggle('locked', locked);
}

export function log(moduleId, text, level = 'info') {
  const cls = LEVEL[level] || 'in';
  const row = document.createElement('div');
  row.className = 'ln';
  const t = new Date().toTimeString().slice(0, 8);
  row.innerHTML = `<span class="t">${t}</span> <span class="${cls}">${ICONS(cls)}</span> ` +
    `<span class="mod-ref">[${moduleId}]</span> ${escapeHtml(text)}`;
  el.console.appendChild(row);
  el.console.scrollTop = el.console.scrollHeight;
}

export function setRunningCount(n) { el.runTag.textContent = `${n}/${MODULES.length} đang chạy`; }

export function setMode(mode) {
  // mode: 'live' | 'mock' | 'down'
  if (mode === 'live') {
    el.conn.className = 'chip live'; el.conn.innerHTML = '<span class="dot"></span>Backend trực tuyến';
    el.modeFlag.className = 'demo-flag live'; el.modeFlag.textContent = '● Live';
  } else if (mode === 'down') {
    el.conn.className = 'chip down'; el.conn.innerHTML = '<span class="dot"></span>Mất kết nối';
  } else {
    el.conn.className = 'chip mock'; el.conn.innerHTML = '<span class="dot"></span>Mock (chưa có backend)';
    el.modeFlag.className = 'demo-flag'; el.modeFlag.textContent = '● Demo';
  }
}

export function setScope(ok) {
  const b = el.scopeBadge, n = el.scopeNote;
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
