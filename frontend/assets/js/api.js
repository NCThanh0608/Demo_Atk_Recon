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
  constructor() { this.mode = 'live'; this._listeners = new Set(); this._ws = null; }

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
  stop(moduleId)          { return this._post(`/ops/${moduleId}/stop`,  envelope(moduleId, 'stop',  {})); }

  async status() {
    const res = await fetch(CONFIG.apiBase + '/status');
    return res.json();
  }

  onEvent(cb) { this._listeners.add(cb); return () => this._listeners.delete(cb); }

  connectStream() {
    // Telemetry pushed by the Pi: log / result / status messages. See WEB.MD §Telemetry.
    const url = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + CONFIG.streamPath;
    try {
      this._ws = new WebSocket(url);
      this._ws.onmessage = (e) => {
        let msg; try { msg = JSON.parse(e.data); } catch { return; }
        this._listeners.forEach(cb => cb(msg));
      };
      this._ws.onclose = () => { this._listeners.forEach(cb => cb({ type: 'status', module: '_conn', state: 'down' })); };
    } catch { /* telemetry optional; control still works over REST */ }
  }
}

/* ------------------------------------------------------------------ Mock */
// Scripted output per module so the demo looks alive without a backend.
const SCRIPT = {
  scan_ip: (p) => [
    ['in',  `arp-scan ${p.scan_range}`],
    ['ok',  `6 host phản hồi · 248 im lặng`],
    ['in',  `phân giải vendor (OUI)… xong`],
    ['done','6 host sống · 2 camera'],
  ],
  scan_port: (p) => [
    ['in',  `tcp connect ${p.target} · top-1000`],
    ['ok',  `554/rtsp · 80/http · 3306/mysql mở`],
    ['warn','8080 filtered'],
    ['done','554 rtsp · 80 http · +1 mở'],
  ],
  brute: (p) => [
    ['in',  `ssh ${p.target} · wordlist 1k`],
    ['err', `admin:123456 · admin:password sai`],
    ['ok',  `admin:sunshine2024 — ĐĂNG NHẬP OK`],
    ['done','admin:sunshine2024 ✓'],
  ],
  dos: (p) => [
    ['in',  `conn-exhaust + syn-flood ${p.target}:554`],
    ['warn',`probe rtsp 120ms → 480ms`],
    ['err', `UNAVAILABLE (2/2) — camera offline`],
    ['done','RTSP UNAVAILABLE'],
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
    return { request_id: 'mock', accepted: true, module: moduleId, state: 'running', job_id: 'mock-' + moduleId };
  }

  async stop(moduleId) {
    (this._timers[moduleId] || []).forEach(clearTimeout);
    this._timers[moduleId] = [];
    this._emit({ type: 'status', module: moduleId, state: 'idle', summary: 'Idle' });
    return { request_id: 'mock', accepted: true, module: moduleId, state: 'idle' };
  }

  async status() { return { modules: {}, config: {} }; }
  connectStream() { /* mock pushes events inline from start()/stop() */ }
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
