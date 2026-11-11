// app.js — wires the UI to the transport client. Entry point (loaded as a module).

import { CONFIG, MODULES, isPrivateIPv4 } from './config.js';
import { createClient } from './api.js';
import * as ui from './ui.js';

const rangeEl = document.getElementById('range');
const victimEl = document.getElementById('victim');
const running = new Set();
let client = null;

const range = () => rangeEl.value.trim();
const victim = () => victimEl.value.trim();

// Build the control-message params for a module from the two inputs.
function paramsFor(mod) {
  return mod.input === 'range'
    ? { scan_range: range(), target: victim() }
    : { target: victim(), scan_range: range() };
}

function refreshScope() {
  const ok = isPrivateIPv4(victim());
  ui.setScope(ok);
  const dos = MODULES.find(m => m.scopeRequired);
  if (dos) {
    ui.setLocked(dos.id, !ok);
    if (!ok && running.has(dos.id)) toggle(dos, document.querySelector(`.mod[data-mod="${dos.id}"]`));
  }
}

async function toggle(mod, btn) {
  if (btn.classList.contains('locked')) {
    ui.log(mod.id, 'bị khóa — IP mục tiêu phải là mạng nội bộ', 'error');
    return;
  }
  const on = running.has(mod.id);
  try {
    if (!on) {
      if (mod.scopeRequired && !isPrivateIPv4(victim())) {
        ui.log(mod.id, 'từ chối — IP công cộng', 'error'); return;
      }
      await client.start(mod.id, paramsFor(mod));
      running.add(mod.id);
      ui.setModuleState(mod.id, true, 'running…');
      ui.log(mod.id, `start · ${mod.input === 'range' ? range() : victim()}`, 'info');
    } else {
      await client.stop(mod.id);
      running.delete(mod.id);
      ui.setModuleState(mod.id, false);
      ui.log(mod.id, 'dừng', 'warn');
    }
  } catch (err) {
    ui.log(mod.id, `lỗi: ${err.code || ''} ${err.message || err}`.trim(), 'error');
    ui.setModuleState(mod.id, running.has(mod.id));
  }
  ui.setRunningCount(running.size);
}

// Telemetry from backend (live) or mock: update console + tile summary/state.
function onEvent(msg) {
  if (!msg || !msg.module) return;
  if (msg.module === '_conn' && msg.state === 'down') { ui.setMode('down'); return; }
  if (msg.type === 'log') ui.log(msg.module, msg.text, msg.level);
  else if (msg.type === 'status') {
    if (msg.state === 'idle') { running.delete(msg.module); ui.setModuleState(msg.module, false); }
    else if (msg.summary) ui.setModuleSummary(msg.module, msg.summary);
    ui.setRunningCount(running.size);
  } else if (msg.type === 'result') {
    ui.log(msg.module, 'kết quả: ' + JSON.stringify(msg.data), 'ok');
  }
}

function initTheme() {
  const root = document.documentElement, order = ['light', 'dark'];
  let cur = null; try { cur = localStorage.getItem('rtops-theme'); } catch {}
  if (cur) root.setAttribute('data-theme', cur);
  document.getElementById('theme').addEventListener('click', () => {
    const i = order.indexOf(root.getAttribute('data-theme'));
    const next = order[(i + 1) % order.length];
    root.setAttribute('data-theme', next);
    try { localStorage.setItem('rtops-theme', next); } catch {}
  });
}

async function main() {
  initTheme();
  document.getElementById('backend-url').textContent = CONFIG.apiBase;
  ui.renderModules(toggle);
  ui.setRunningCount(0);
  victimEl.addEventListener('input', refreshScope);
  refreshScope();

  client = await createClient();
  client.onEvent?.(onEvent);
  ui.setMode(client.mode);
  ui.log('system', `console sẵn sàng · chế độ ${client.mode.toUpperCase()} · engagement ${CONFIG.engagement}`, 'info');
}

main();
