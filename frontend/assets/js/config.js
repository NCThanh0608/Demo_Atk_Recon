export const CONFIG = {
  apiBase: '/api',
  streamPath: '/api/stream',
  healthTimeoutMs: 1500,
};

export function isPrivateIPv4(ip) {
  const m = String(ip).trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const o = m.slice(1).map(Number);
  if (o.some(x => x > 255)) return false;
  return o[0] === 10
      || (o[0] === 172 && o[1] >= 16 && o[1] <= 31)
      || (o[0] === 192 && o[1] === 168);
}

export function isIPv4OrCIDRv4(s) {
  const m = String(s).trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/);
  if (!m) return false;
  if ([m[1], m[2], m[3], m[4]].map(Number).some(x => x > 255)) return false;
  if (m[5] != null && Number(m[5]) > 32) return false;
  return true;
}

export function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
