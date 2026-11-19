// api.js — transport layer between the web console and the Raspberry Pi backend.
//
// Two interchangeable clients expose the SAME interface:
//   - LiveClient : talks to the real backend over REST (+ WebSocket telemetry).
//   - MockClient : simulates the backend so the UI is fully usable with no Pi.
//
// createClient() probes GET /api/health; on success it returns LiveClient,
// otherwise MockClient. The rest of the app does not care which one it got.
//
// Control-message shapes and endpoints are specified in WEB.MD. Keep them in sync.

import { CONFIG } from './config.js';

function envelope(moduleId, action, params) {
  // The control message the Pi receives. See WEB.MD §Control messages.
  return {
    request_id: (crypto?.randomUUID?.() || String(Date.now()) + '-' + Math.random().toString(16).slice(2)),
    ts: Math.floor(Date.now() / 1000),
    engagement: CONFIG.engagement,
    module: moduleId,
    action,                       // 'start' | 'stop'
    params: params || {},
  };
}

/* ------------------------------------------------------------------ Live */
class LiveClient {
  constructor() {
    this.mode = 'live'; this._listeners = new Set(); this._ws = null;
    this._backoff = 1000; this._stopped = false; this._retryT = null;
  }

  async _post(path, body) {
    const res = await fetch(CONFIG.apiBase + path, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || data.accepted === false) {
      const err = data.error || { code: 'http_' + res.status, message: res.statusText };
      throw err;
    }
    return data;
  }

  start(moduleId, params) { return this._post(`/ops/${moduleId}/start`, envelope(moduleId, 'start', params)); }
  stop(moduleId) { return this._post(`/ops/${moduleId}/stop`, envelope(moduleId, 'stop', {})); }

  // Emergency stop: kill every running job (WEB.MD §3.2 — body is {request_id, ts}).
  stopAll() {
    return this._post('/ops/stop_all', {
      request_id: (crypto?.randomUUID?.() || String(Date.now()) + '-' + Math.random().toString(16).slice(2)),
      ts: Math.floor(Date.now() / 1000),
    });
  }

  async status() {
    const res = await fetch(CONFIG.apiBase + '/status');
    if (!res.ok) throw { code: 'http_' + res.status, message: res.statusText };
    return res.json();
  }

  onEvent(cb) { this._listeners.add(cb); return () => this._listeners.delete(cb); }

  _emit(msg) { this._listeners.forEach(cb => cb(msg)); }

  connectStream() {
    // Telemetry pushed by the Pi: log / result / status messages. See WEB.MD §Telemetry.
    // Auto-reconnects with exponential backoff so telemetry survives a dropped AP link.
    const url = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + CONFIG.streamPath;
    const open = () => {
      if (this._stopped) return;
      try {
        this._ws = new WebSocket(url);
        this._ws.onopen = () => {
          this._backoff = 1000;                                   // reset backoff on success
          this._emit({ type: 'status', module: '_conn', state: 'up' });
        };
        this._ws.onmessage = (e) => {
          let msg; try { msg = JSON.parse(e.data); } catch { return; }
          this._emit(msg);
        };
        this._ws.onerror = () => { try { this._ws.close(); } catch { /* noop */ } };
        this._ws.onclose = () => {
          this._emit({ type: 'status', module: '_conn', state: 'down' });
          this._scheduleReconnect(open);
        };
      } catch {
        this._scheduleReconnect(open);
      }
    };
    open();
  }

  _scheduleReconnect(open) {
    if (this._stopped) return;
    clearTimeout(this._retryT);
    const delay = this._backoff;
    this._backoff = Math.min(delay * 2, 15000);                   // 1s → 2s → … → 15s cap
    this._retryT = setTimeout(open, delay);
  }

  disconnect() {
    this._stopped = true;
    clearTimeout(this._retryT);
    try { this._ws?.close(); } catch { /* noop */ }
  }
}

/* ------------------------------------------------------------------ Mock */
// Scripted output per module so the demo looks alive without a backend.
const SCRIPT = {
  scan_ip: (p) => [
    ['in', `arp-scan ${p.scan_range}`],
    ['ok', `6 host phản hồi · 248 im lặng`],
    ['in', `phân giải vendor (OUI)… xong`],
    ['done', '6 host sống · 2 camera'],
  ],
  scan_port: (p) => [
    ['in', `tcp connect ${p.target} · top-1000`],
    ['ok', `554/rtsp · 80/http · 3306/mysql mở`],
    ['warn', '8080 filtered'],
    ['done', '554 rtsp · 80 http · +1 mở'],
  ],
  brute: (p) => [
    ['in', `ssh ${p.target} · wordlist 1k`],
    ['err', `admin:123456 · admin:password sai`],
    ['ok', `admin:sunshine2024 — ĐĂNG NHẬP OK`],
    ['done', 'admin:sunshine2024 ✓'],
  ],
  dos: (p) => [
    ['in', `conn-exhaust + syn-flood ${p.target}:554`],
    ['warn', `probe rtsp 120ms → 480ms`],
    ['err', `UNAVAILABLE (2/2) — camera offline`],
    ['done', 'RTSP UNAVAILABLE'],
  ],
};

class MockClient {
  constructor() { this.mode = 'mock'; this._listeners = new Set(); this._timers = {}; }

  onEvent(cb) { this._listeners.add(cb); return () => this._listeners.delete(cb); }
  _emit(msg) { this._listeners.forEach(cb => cb(msg)); }

  async start(moduleId, params) {
    const steps = (SCRIPT[moduleId] || (() => []))(params);
    this._timers[moduleId] = [];
    steps.forEach(([level, text], i) => {
      const id = setTimeout(() => {
        if (level === 'done') this._emit({ type: 'status', module: moduleId, state: 'running', summary: text });
        else this._emit({ type: 'log', module: moduleId, level, text });
      }, 250 + i * 550);
      this._timers[moduleId].push(id);
    });
    // scan_ip also emits a structured result so the victim dropdown populates in mock mode.
    if (moduleId === 'scan_ip') {
      const base = (String(params.scan_range || '192.168.1.0').match(/^(\d+\.\d+\.\d+)\./) || [, '192.168.1'])[1];
      const hosts = [
        { ip: `${base}.1`, hostname: 'gateway', mac: 'C4:2C:7B:6A:3C:28', vendor: 'TP-Link', rtt_ms: 1 },
        { ip: `${base}.30`, hostname: 'cam-01', mac: 'AC:CC:8E:12:34:56', vendor: 'Axis', rtt_ms: 4 },
        { ip: `${base}.42`, hostname: 'nvr', mac: '00:1A:2B:AA:BB:CC', vendor: 'Hikvision', rtt_ms: 6 },
      ];
      const id = setTimeout(() => this._emit({ type: 'result', module: 'scan_ip', data: { hosts } }),
        250 + steps.length * 550);
      this._timers[moduleId].push(id);
    }
    if (moduleId === 'scan_port') {
      const open_ports = [
        { port: 554, proto: 'tcp', service: 'rtsp', version: '' },
        { port: 80, proto: 'tcp', service: 'http', version: 'nginx 1.24' },
        { port: 3306, proto: 'tcp', service: 'mysql', version: '' },
      ];
      const id = setTimeout(() => this._emit({
        type: 'result', module: 'scan_port', data: { target: params.target, open_ports },
      }), 250 + steps.length * 550);
      this._timers[moduleId].push(id);
    }
    if (moduleId === 'brute') {
      const found = [{ service: 'ssh', username: 'admin', password: 'sunshine2024' }];
      const id = setTimeout(() => this._emit({
        type: 'result', module: 'brute', data: { target: params.target, service: 'ssh', found },
      }), 250 + steps.length * 550);
      this._timers[moduleId].push(id);
    }
    return { request_id: 'mock', accepted: true, module: moduleId, state: 'running', job_id: 'mock-' + moduleId };
  }

  async stop(moduleId) {
    (this._timers[moduleId] || []).forEach(clearTimeout);
    this._timers[moduleId] = [];
    this._emit({ type: 'status', module: moduleId, state: 'idle', summary: 'Idle' });
    return { request_id: 'mock', accepted: true, module: moduleId, state: 'idle' };
  }

  async stopAll() {
    Object.keys(this._timers).forEach(moduleId => {
      (this._timers[moduleId] || []).forEach(clearTimeout);
      this._timers[moduleId] = [];
      this._emit({ type: 'status', module: moduleId, state: 'idle', summary: 'Idle' });
    });
    return { request_id: 'mock', accepted: true };
  }

  async status() { return { modules: {}, config: {} }; }
  connectStream() { /* mock pushes events inline from start()/stop() */ }
  disconnect() { /* no persistent connection in mock */ }
}

/* ---------------------------------------------------- Camera fMP4 / MSE */
export function openCamFmp4(host, user, pass, path, videoEl, onReady, onError) {
  const params = new URLSearchParams({ host, user, pass, path });
  const url = `/api/cam/fmp4?${params}`;
  const mime = 'video/mp4; codecs="avc1.42E01E"';

  if (!('MediaSource' in window) || !MediaSource.isTypeSupported(mime)) {
    onError('Trình duyệt không hỗ trợ MSE / H.264');
    return null;
  }

  const ms = new MediaSource();
  const objUrl = URL.createObjectURL(ms);
  videoEl.src = objUrl;

  let aborted = false;
  let controller = null;

  const cleanup = () => {
    aborted = true;
    try { controller?.abort(); } catch {}
    try { if (ms.readyState === 'open') ms.endOfStream(); } catch {}
    videoEl.pause();
    videoEl.src = '';
    videoEl.load();
  };

  ms.addEventListener('sourceopen', async () => {
    URL.revokeObjectURL(objUrl);
    let sb;
    try {
      sb = ms.addSourceBuffer(mime);
      sb.mode = 'sequence';
    } catch (e) { onError('MSE addSourceBuffer: ' + e.message); return; }

    controller = new AbortController();
    try {
      const res = await fetch(url, { signal: controller.signal });
      if (!res.ok) { onError('HTTP ' + res.status); return; }
      const reader = res.body.getReader();
      let first = true;

      (async () => {
        while (!aborted) {
          const { done, value } = await reader.read();
          if (done || aborted) break;
          if (sb.updating) await new Promise(r => sb.addEventListener('updateend', r, { once: true }));
          if (aborted) break;
          try { sb.appendBuffer(value); } catch {}
          if (first) { first = false; onReady(); }
        }
      })().catch(e => { if (!aborted && e.name !== 'AbortError') onError(e.message || String(e)); });
    } catch (e) {
      if (!aborted && e.name !== 'AbortError') onError(e.message || String(e));
    }
  }, { once: true });

  return { close: cleanup };
}

/* --------------------------------------------------------------- Factory */
export async function createClient() {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), CONFIG.healthTimeoutMs);
    const res = await fetch(CONFIG.apiBase + '/health', { signal: ctrl.signal });
    clearTimeout(t);
    if (res.ok) { const c = new LiveClient(); c.connectStream(); return c; }
  } catch { /* backend not up yet */ }
  return new MockClient();
}
