// ── Formats d'import config (nginx, Traefik, Caddy, …) ───────────────────
// Source unique pour Trafic, Import/Restore, onboarding et proxy-form.

const CONFIG_FORMAT_SVG = {
  nginx:         { svg: `<svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" viewBox="0 0 24 24"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>`, color: '#22c55e' },
  'traefik-yaml':{ svg: `<svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" viewBox="0 0 24 24"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>`, color: '#3b82f6' },
  'traefik-toml':{ svg: `<svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" viewBox="0 0 24 24"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>`, color: '#60a5fa' },
  caddy:         { svg: `<svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`, color: '#06b6d4' },
  haproxy:       { svg: `<svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" viewBox="0 0 24 24"><rect x="2" y="2" width="9" height="9" rx="1"/><rect x="13" y="2" width="9" height="9" rx="1"/><rect x="2" y="13" width="9" height="9" rx="1"/><rect x="13" y="13" width="9" height="9" rx="1"/></svg>`, color: '#f59e0b' },
  goproxify:     { svg: `<svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>`, color: '#7c3aed' },
  json:          { svg: `<svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="12" y2="17"/></svg>`, color: '#8b949e' },
};

const CONFIG_FORMATS = [
  { id: 'nginx',        label: 'nginx',         hint: 'Blocs server { }' },
  { id: 'traefik-yaml', label: 'Traefik YAML',  hint: 'http.routers + services' },
  { id: 'traefik-toml', label: 'Traefik TOML',  hint: 'Format TOML' },
  { id: 'caddy',        label: 'Caddy',          hint: 'Caddyfile' },
  { id: 'haproxy',      label: 'HAProxy',        hint: 'frontend / backend' },
  { id: 'goproxify',    label: 'Goproxify JSON', hint: 'Export natif' },
  { id: 'json',         label: 'JSON générique', hint: 'host + backends' },
];

/** Icône + couleur pour un format (svg à la taille demandée). */
function configFormatMeta(id, size = 20) {
  const m = CONFIG_FORMAT_SVG[id] || { svg: '', color: 'var(--accent)' };
  return {
    color: m.color,
    svg: (m.svg || '').replace(/width="\d+"\s+height="\d+"/g, `width="${size}" height="${size}"`),
  };
}

/**
 * Grille de sélection de format.
 * @param {string|null} selectedId
 * @param {(id: string) => string} onclickAttr  ex. id => `impSelFmt('${id}')`
 * @param {{ compact?: boolean }} [opts]
 */
function configFormatPickerHtml(selectedId, onclickAttr, opts = {}) {
  const iconSize = opts.compact ? 20 : 22;
  return CONFIG_FORMATS.map(f => {
    const meta = configFormatMeta(f.id, iconSize);
    const sel = selectedId === f.id;
    return `<div class="infra-card${sel ? ' selected' : ''}" data-format="${esc(f.id)}" onclick="${onclickAttr(f.id)}"
      style="padding:14px 10px;gap:8px;cursor:pointer;text-align:center;align-items:center;position:relative">
      <div style="width:40px;height:40px;border-radius:10px;display:flex;align-items:center;justify-content:center;margin:0 auto;
        background:${meta.color}18;border:1.5px solid ${meta.color}30;color:${meta.color}">
        ${meta.svg}
      </div>
      <div class="infra-card-name" style="font-size:12px;font-weight:700;color:${sel ? 'var(--accent)' : 'var(--text)'}">${esc(f.label)}</div>
      <div class="infra-card-desc" style="font-size:10px;line-height:1.3">${esc(f.hint)}</div>
    </div>`;
  }).join('');
}
