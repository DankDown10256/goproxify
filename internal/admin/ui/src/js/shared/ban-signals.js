// Explication d'un ban automatique (Ephor, WAF) : les signaux qui l'ont causé, avec leurs points et la valeur observée
// (ADR 0011). Fournie par l'API sous `signals: [{ name, points, value }]` ; absente des bans manuels et des autres sources.

function banSignalLabel(name) {
  const key = 'bansig.' + name;
  const label = t(key);
  return label === key ? name : label;
}

function banSignalPoints(p) {
  return (Math.round((Number(p) || 0) * 10) / 10).toString();
}

// Texte brut, pour une infobulle : « Chemin de la liste 6 — /wp-login.php ; Erreurs 4xx 2.5 — 404 /x ».
function banSignalsText(signals) {
  if (!Array.isArray(signals) || !signals.length) return '';
  return signals.map(s => `${banSignalLabel(s.name)} ${banSignalPoints(s.points)}${s.value ? ' — ' + s.value : ''}`).join(' ; ');
}

// Une pastille par signal (nom lisible et points), la valeur observée en infobulle.
function banSignalsHTML(signals) {
  if (!Array.isArray(signals) || !signals.length) return '';
  const total = signals.reduce((n, s) => n + (Number(s.points) || 0), 0);
  const chips = signals.map(s => `<span class="tag tag-neutral" style="font-size:10px" title="${esc(s.value || '')}">${esc(banSignalLabel(s.name))} <b>${esc(banSignalPoints(s.points))}</b></span>`).join('');
  return `<div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:4px" title="${esc(t('bansig.total', { n: banSignalPoints(total) }))}">${chips}</div>`;
}

// Le User-Agent que la passerelle a vu en dernier pour l'IP au moment du ban automatique.
function banUserAgentHTML(ua) {
  if (!ua) return '';
  return `<div class="tr-mono" style="margin-top:4px;font-size:10.5px;color:var(--text3);word-break:break-all" title="${esc(t('trace.ua'))}">${esc(ua)}</div>`;
}

// Une ligne par signal : nom, points et valeur observée en clair.
function banSignalsDetailHTML(signals) {
  if (!Array.isArray(signals) || !signals.length) return '';
  const rows = signals.map(s => `<div style="display:flex;gap:8px;align-items:baseline"><b>${esc(banSignalLabel(s.name))}</b>
    <span class="tr-mono">${esc(banSignalPoints(s.points))}</span>${s.value ? `<span class="tr-mono" style="color:var(--text3);overflow:hidden;text-overflow:ellipsis">${esc(s.value)}</span>` : ''}</div>`).join('');
  return `<div class="tr-row"><div style="color:var(--text3);font-size:11px">${esc(t('bansig.title'))}</div>${rows}</div>`;
}
