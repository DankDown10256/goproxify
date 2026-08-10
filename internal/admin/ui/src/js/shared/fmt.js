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
