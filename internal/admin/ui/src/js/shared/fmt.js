// ── Shared: formatage ───────────────────────────────────────────────────
// Extrait de pages-all.js — phase 2.

function fmtUptime(secs) {
  if (!secs) return '—';
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  if (h >= 24) return Math.floor(h/24) + 'j' + (h%24) + 'h';
  return h + 'h' + String(m).padStart(2,'0') + 'm';
}

function fmtBytes(n) {
  if (!n) return '0 B';
  if (n < 1024) return n + ' B';
  if (n < 1024*1024) return (n/1024).toFixed(1) + ' KB';
  return (n/1024/1024).toFixed(2) + ' MB';
}

// ── Géo : réseau local toujours en fin de classement ────────────────────────
// Le code pays "LO" (Local / Private, voir internal/admin/analytics/geoip.go) désigne les IPs
// privées/loopback qu'aucune résolution GeoIP ne peut rattacher à un pays. On les garde dans le
// même classement (pas de carte à part) mais toujours après les vrais pays, quel que soit leur
// volume — mélangées au tri normal, elles écraseraient souvent les pays qui suivent.
function isLocalGeo(cc) { return cc === 'LO'; }

function geoSortLocalLast(list, valueFn) {
  const real = [], local = [];
  for (const e of list) (isLocalGeo(e.country_code) ? local : real).push(e);
  const byValue = (a, b) => valueFn(b) - valueFn(a);
  return [...real.sort(byValue), ...local.sort(byValue)];
}
