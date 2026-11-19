// app.js — wires the UI to the transport client. Entry point (loaded as a module).

import { CONFIG, MODULES, isPrivateIPv4, isIPv4OrCIDRv4 } from './config.js';
import { createClient, openCamFmp4 } from './api.js';
import * as ui from './ui.js';

const rangeEl = document.getElementById('range');
const victimEl = document.getElementById('victim');
const running = new Set();
let client = null;

let discoveredHosts = [];     // hosts from the latest scan_ip result
let hostAutoScan = false;     // guard: auto-scan the victim list only once per range
const results = new Map();    // ip -> {ip, hostname, vendor, mac, ports: null|[]} for the results table

// Camera viewer state
let _camRefreshTimer = null;
let _camFmp4 = null;
let _camCtx = null;           // { ip, user, pass, path, type }

async function openCamViewer(ip, user, pass) {
  if (_camRefreshTimer) { clearInterval(_camRefreshTimer); _camRefreshTimer = null; }
  if (_camFmp4) { try { _camFmp4.close(); } catch { /* noop */ } _camFmp4 = null; }
  ui.showCamPanel(ip, user);
  ui.log('cam', `mở camera ${ip} (${user}:${pass})`, 'info');
  try {
    const r = await fetch(
      `/api/cam/probe?host=${encodeURIComponent(ip)}&user=${encodeURIComponent(user)}&pass=${encodeURIComponent(pass)}`
    );
    const info = await r.json();
    _camCtx = { ip, user, pass, ...info };
    if (info.type === 'none') {
      ui.setCamStatus('Không tìm thấy stream camera tại ' + ip, 'error');
      ui.log('cam', `không tìm thấy stream tại ${ip}`, 'warn');
      return;
    }
    const mkUrl = (ts) =>
      `/api/cam/stream?host=${encodeURIComponent(ip)}&user=${encodeURIComponent(user)}&pass=${encodeURIComponent(pass)}&path=${encodeURIComponent(info.path)}&_t=${ts || Date.now()}`;
    if (info.type === 'rtsp') {
      // fMP4 + MSE: ffmpeg encodes H.264 baseline, browser plays via MediaSource
      const videoEl = document.getElementById('cam-video');
      ui.showCamVideo(true);
      const chip = document.getElementById('cam-chip');
      if (chip) { chip.textContent = '● RTSP → fMP4'; chip.className = 'chip cam-chip live'; }
      _camFmp4 = openCamFmp4(ip, user, pass, info.path, videoEl,
        () => {
          const load = document.getElementById('cam-loading');
          if (load) load.hidden = true;
        },
        (err) => {
          ui.setCamStatus('Stream lỗi: ' + err, 'error');
          ui.log('cam', 'fMP4 lỗi: ' + err, 'error');
          _camFmp4 = null;
        }
      );
      ui.log('cam', `RTSP → fMP4 stream tại ${ip}`, 'ok');
    } else if (info.type === 'mjpeg') {
      ui.setCamStream(mkUrl(), 'MJPEG live');
      ui.log('cam', `MJPEG stream tại ${ip}`, 'ok');
    } else if (info.type === 'snapshot') {
      ui.setCamStream(mkUrl(), 'Snapshot auto-refresh');
      ui.log('cam', `snapshot tại ${ip}${info.path} — tự làm mới mỗi 1.5s`, 'ok');
      _camRefreshTimer = setInterval(() => ui.refreshCamStream(mkUrl()), 1500);
    } else {
      ui.setCamStatus(`Không hỗ trợ hiển thị inline — thử mở http://${ip} trong tab mới`, 'error');
      ui.log('cam', `fallback: mở http://${ip} trong trình duyệt`, 'warn');
    }
  } catch (e) {
    ui.setCamStatus('Lỗi kết nối: ' + (e.message || e), 'error');
    ui.log('cam', `lỗi probe: ${e.message || e}`, 'error');
  }
}

function closeCamViewer() {
  if (_camRefreshTimer) { clearInterval(_camRefreshTimer); _camRefreshTimer = null; }
  if (_camFmp4) { try { _camFmp4.close(); } catch { /* noop */ } _camFmp4 = null; }
  _camCtx = null;
  ui.hideCamPanel();
  ui.log('cam', 'đã đóng camera viewer', 'info');
}

// Merge discovered hosts into the results table (keep any ports already scanned).
function upsertHosts(hosts) {
  hosts.forEach(h => {
    const cur = results.get(h.ip) || { ip: h.ip, ports: null };
    results.set(h.ip, { ...cur, ip: h.ip, hostname: h.hostname, vendor: h.vendor, mac: h.mac });
  });
  ui.renderResults([...results.values()], pickHost, openCamViewer);
}

// Attach scan_port results to the matching IP row (create the row if new).
function setPorts(ip, ports) {
  if (!ip) return;
  const cur = results.get(ip) || { ip, ports: null };
  results.set(ip, { ...cur, ip, ports: Array.isArray(ports) ? ports : [] });
  ui.renderResults([...results.values()], pickHost, openCamViewer);
}

// Attach brute-force credentials found for an IP to its row.
function setCreds(ip, found) {
  if (!ip) return;
  const cur = results.get(ip) || { ip, ports: null };
  results.set(ip, { ...cur, ip, creds: Array.isArray(found) ? found : [] });
  ui.renderResults([...results.values()], pickHost, openCamViewer);
}

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
  ui.setScope(ok, victim());
  ui.setRangeValid(isIPv4OrCIDRv4(range()));
  const dos = MODULES.find(m => m.scopeRequired);
  if (dos) {
    // IMPORTANT: if a scoped attack is live and the target just went public,
    // actually STOP it *before* locking the tile. Going through toggle() here
    // would hit the `locked` early-return and never send stop() to the backend.
    if (!ok && running.has(dos.id)) {
      stopMod(dos, 'tự dừng — IP mục tiêu ra ngoài RFC1918')
        .catch(err => ui.log(dos.id, `lỗi dừng: ${err.code || ''} ${err.message || err}`.trim(), 'error'))
        .finally(() => ui.setRunningCount(running.size));
    }
    ui.setLocked(dos.id, !ok);
  }
}

async function startMod(mod) {
  // Modules that act on a single target need a valid private IP first.
  if (mod.input === 'target') {
    const t = victim();
    if (!t) {
      ui.setVictimHint('⚠ Hãy chọn hoặc nhập IP mục tiêu trước', true);
      victimEl.focus();
      openHostPicker();
      ui.log(mod.id, 'cần IP mục tiêu — hãy chọn từ danh sách đã quét', 'error');
      return;
    }
    if (!isPrivateIPv4(t)) {
      ui.setVictimHint('⚠ IP mục tiêu phải thuộc mạng nội bộ (RFC1918)', true);
      victimEl.focus();
      ui.log(mod.id, 'từ chối — IP mục tiêu ngoài RFC1918', 'error');
      return;
    }
  }
  await client.start(mod.id, paramsFor(mod));
  running.add(mod.id);
  ui.setModuleState(mod.id, true, 'running…');
  ui.log(mod.id, `start · ${mod.input === 'range' ? range() : victim()}`, 'info');
}

async function stopMod(mod, reason) {
  await client.stop(mod.id);
  running.delete(mod.id);
  ui.setModuleState(mod.id, false);
  ui.log(mod.id, reason || 'dừng', 'warn');
}

async function toggle(mod, btn) {
  if (btn.classList.contains('locked')) {
    ui.log(mod.id, 'bị khóa — IP mục tiêu phải là mạng nội bộ', 'error');
    return;
  }
  try {
    if (running.has(mod.id)) await stopMod(mod);
    else await startMod(mod);
  } catch (err) {
    ui.log(mod.id, `lỗi: ${err.code || ''} ${err.message || err}`.trim(), 'error');
    ui.setModuleState(mod.id, running.has(mod.id));
  }
  ui.setRunningCount(running.size);
}

// Emergency stop: ask the backend to kill every job, then clear local state.
async function stopAll() {
  try {
    await client.stopAll?.();
  } catch (err) {
    ui.log('system', `stop_all lỗi: ${err.code || ''} ${err.message || err}`.trim(), 'error');
  }
  [...running].forEach(id => { running.delete(id); ui.setModuleState(id, false); });
  ui.setRunningCount(0);
  ui.log('system', 'DỪNG KHẨN — đã gửi stop_all tới mọi module', 'warn');
}

// Telemetry from backend (live) or mock: update console + tile summary/state.
function onEvent(msg) {
  if (!msg || !msg.module) return;
  if (msg.module === '_conn') {
    if (msg.state === 'down') ui.setMode('down');
    else if (msg.state === 'up') ui.setMode('live');       // telemetry reconnected
    return;
  }
  if (msg.type === 'log') ui.log(msg.module, msg.text, msg.level);
  else if (msg.type === 'status') {
    if (msg.state === 'idle') { running.delete(msg.module); ui.setModuleState(msg.module, false); }
    else if (msg.summary) ui.setModuleSummary(msg.module, msg.summary);
    ui.setRunningCount(running.size);
  } else if (msg.type === 'result') {
    if (msg.module === 'scan_ip' && msg.data && Array.isArray(msg.data.hosts)) {
      discoveredHosts = msg.data.hosts;
      ui.renderHostList(discoveredHosts, pickHost);
      upsertHosts(discoveredHosts);                 // fill IP column of the results table
      if (discoveredHosts.length) {
        ui.setVictimHint(`${discoveredHosts.length} IP đã quét — bấm ▾ để chọn`);
        ui.log('scan_ip', `${discoveredHosts.length} IP sẵn sàng chọn ở ô mục tiêu`, 'ok');
      } else {
        ui.setVictimHint('không thấy host sống trong dải');
      }
    } else if (msg.module === 'scan_port' && msg.data && Array.isArray(msg.data.open_ports)) {
      setPorts(msg.data.target || victim(), msg.data.open_ports);   // fill port column
      ui.log('scan_port', `${msg.data.open_ports.length} cổng mở trên ${msg.data.target || victim()}`, 'ok');
    } else if (msg.module === 'brute' && msg.data && Array.isArray(msg.data.found)) {
      const ip = msg.data.target || victim();
      setCreds(ip, msg.data.found);                                 // show found credentials on the IP row
      const n = msg.data.found.length;
      ui.log('brute', n ? `${n} đăng nhập hợp lệ trên ${ip}` : `không tìm thấy đăng nhập (${ip})`, n ? 'ok' : 'warn');
    } else {
      ui.log(msg.module, 'kết quả: ' + JSON.stringify(msg.data), 'ok');
    }
  }
}

// Fill the target field from the dropdown and close it.
function pickHost(ip) {
  victimEl.value = ip;
  ui.openHostList(false);
  ui.setVictimHint(`✓ mục tiêu: ${ip}`);   // confirm selection (from dropdown or table)
  refreshScope();
}

// Open the dropdown; with no hosts yet it kicks off an auto-scan to fill it.
function openHostPicker() {
  ui.renderHostList(discoveredHosts, pickHost);
  ui.openHostList(true);
  if (!discoveredHosts.length) maybeAutoScan();
}

function toggleHostList() {
  if (ui.isHostListOpen()) { ui.openHostList(false); return; }
  openHostPicker();
}

// Auto-run scan_ip on the chosen range to populate the list (once per range).
function maybeAutoScan() {
  if (discoveredHosts.length || running.has('scan_ip') || hostAutoScan) return;
  const scanIp = MODULES.find(m => m.id === 'scan_ip');
  if (!scanIp || !isIPv4OrCIDRv4(range())) return;
  hostAutoScan = true;
  ui.setVictimHint(`đang tự quét ${range()} để lấy danh sách IP…`);
  ui.log('scan_ip', `tự quét ${range()} để lấy danh sách IP mục tiêu…`, 'info');
  startMod(scanIp)
    .catch(err => ui.log('scan_ip', `lỗi: ${err.code || ''} ${err.message || err}`.trim(), 'error'))
    .finally(() => ui.setRunningCount(running.size));
}

// Range changed -> old host list is stale; clear it and allow a fresh auto-scan.
function onRangeInput() {
  discoveredHosts = [];
  hostAutoScan = false;
  ui.renderHostList([], pickHost);
  ui.openHostList(false);
  ui.setVictimHint('');
  refreshScope();
}

function initTheme() {
  const root = document.documentElement;
  const order = ['auto', 'light', 'dark'];
  const label = { auto: '◐ Auto', light: '☀ Light', dark: '☾ Dark' };
  const btn = document.getElementById('theme');
  let cur = 'auto'; try { cur = localStorage.getItem('rtops-theme') || 'auto'; } catch { }

  const apply = (t) => {
    if (t === 'auto') root.removeAttribute('data-theme');       // follow OS prefers-color-scheme
    else root.setAttribute('data-theme', t);
    btn.textContent = label[t] || label.auto;
    try { localStorage.setItem('rtops-theme', t); } catch { }
  };
  apply(cur);

  btn.addEventListener('click', () => {
    cur = order[(order.indexOf(cur) + 1) % order.length];
    apply(cur);
  });
}

// Pull a snapshot from the backend so the UI reflects jobs already running
// after a page reload (WEB.MD §6). No-op in mock mode.
async function syncFromBackend() {
  let snap;
  try { snap = await client.status(); } catch { return; }
  if (!snap) return;
  if (snap.config) {
    if (snap.config.scan_range) rangeEl.value = snap.config.scan_range;
    // Do NOT restore config.target: the victim field stays empty until the
    // operator picks/enters one, so it never shows a stale IP from a past scan.
  }
  if (snap.modules) {
    Object.entries(snap.modules).forEach(([id, st]) => {
      if (st && st.state === 'running') {
        running.add(id);
        ui.setModuleState(id, true, st.summary || 'running…');
      }
    });
  }
  refreshScope();
  ui.setRunningCount(running.size);
}

async function main() {
  initTheme();
  ui.renderModules(toggle);
  ui.setRunningCount(0);
  victimEl.addEventListener('input', () => { ui.openHostList(false); refreshScope(); });
  document.getElementById('victim-caret').addEventListener('click', toggleHostList);
  // Close the dropdown when clicking anywhere outside the combo.
  document.addEventListener('click', (e) => {
    const combo = document.getElementById('victim-combo');
    if (combo && !combo.contains(e.target)) ui.openHostList(false);
  });
  rangeEl.addEventListener('input', onRangeInput);
  document.getElementById('stop-all').addEventListener('click', stopAll);

  document.getElementById('cam-close')?.addEventListener('click', closeCamViewer);

  // Activity log is hidden by default; a small button reveals it for debug/RD.
  const logBtn = document.getElementById('log-toggle');
  const logPanel = document.getElementById('log-panel');
  logBtn.addEventListener('click', () => {
    const show = logPanel.hidden;
    logPanel.hidden = !show;
    logBtn.setAttribute('aria-expanded', show ? 'true' : 'false');
    logBtn.textContent = (show ? '⌃' : '⌄') + ' Nhật ký';
  });
  refreshScope();

  client = await createClient();
  client.onEvent?.(onEvent);
  ui.setMode(client.mode);
  if (client.mode === 'live') await syncFromBackend();
  ui.log('system', `console sẵn sàng · chế độ ${client.mode.toUpperCase()} · engagement ${CONFIG.engagement}`, 'info');
}

main();
