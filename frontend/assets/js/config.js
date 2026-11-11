// config.js — shared constants & module catalog.
// IMPORTANT: module ids and param names here MUST match the backend contract in WEB.MD.
// Do not rename without updating WEB.MD and notifying the backend owner.

export const CONFIG = {
  // Backend is served by the Raspberry Pi on the same origin (AP mode).
  // Relative paths => no CORS, no hard-coded AP IP.
  apiBase: '/api',
  streamPath: '/api/stream',     // WebSocket for telemetry (Pi -> client)
  healthTimeoutMs: 1500,         // if /api/health fails within this, fall back to MOCK
  engagement: 'VQEC-RT-01',
};

// The four operations. `input` says which field is sent as the primary parameter.
// `danger` + `scopeRequired` gate the DoS tile behind the RFC1918 scope check.
export const MODULES = [
  {
    id: 'scan_ip',   name: 'Scan IP',     kind: 'recon',
    input: 'range',  desc: 'Phát hiện host sống trong subnet',
    icon: '<path d="M2 12h3m14 0h3M12 2v3m0 14v3"/><circle cx="12" cy="12" r="6"/>',
  },
  {
    id: 'scan_port', name: 'Scan Port',   kind: 'recon',
    input: 'target', desc: 'Liệt kê cổng mở trên mục tiêu',
    icon: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18M7 13h2m3 0h5m-10 3h8"/>',
  },
  {
    id: 'brute',     name: 'Brute Force', kind: 'attack',
    input: 'target', desc: 'Dò thông tin đăng nhập dịch vụ',
    icon: '<circle cx="8" cy="15" r="4"/><path d="M10.8 12.2 20 3m-3 0 2 2m-5 2 2 2"/>',
  },
  {
    id: 'dos',       name: 'DoS',         kind: 'attack',
    input: 'target', desc: 'Tấn công thể tích vào mục tiêu',
    icon: '<path d="M12 2 2 20h20z"/><path d="M12 9v5m0 3h.01"/>',
    danger: true, scopeRequired: true,
  },
];

// RFC1918 private ranges. The DoS tile is locked unless the target is private.
// NOTE: this is a client-side UX guard only. The backend MUST re-validate (see WEB.MD §Scope).
export function isPrivateIPv4(ip) {
  const m = String(ip).trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const o = m.slice(1).map(Number);
  if (o.some(x => x > 255)) return false;
  return o[0] === 10
      || (o[0] === 172 && o[1] >= 16 && o[1] <= 31)
      || (o[0] === 192 && o[1] === 168);
}
