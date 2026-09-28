// ── PAGE: Logs (Admin + Passerelle) ──────────────────────────────────────────
// Une seule vue ; les entrées de menu ne font que poser des filtres.
//
// Convention store :
//   kind=access  → status>0  (HTTP proxies / domaines)
//   kind=system  → status=0  (process edge / admin / agent)
//
// logsFilters doit exister avant trafic.js (liens domaine → logs).

const logsFilters = {
  level: '', component: '', node_name: '', kind: 'access',
  domain: '', ip: '', method: '', status: '', path: '',
  search: '', date_from: '', date_to: '',
};

// Passerelles disponibles pour le sélecteur de nœud en portée Admin (non verrouillée).
let logsAllEdges = null;
async function ensureLogsEdges() {
  if (logsAllEdges) return logsAllEdges;
  logsAllEdges = ((await api('GET', '/nodes').catch(() => [])) || []).filter(n => n.role === 'edge');
  return logsAllEdges;
}

/** Portée posée par le menu (conservée pendant toute la visite de la page). */
let logsScope = { kind: 'access', component: '', node_name: '', node_id: '', lockComp: false };

let logsActiveTab = 'static';
let logsSSE = null;
let liveRows = [];
let livePaused = false;

// Keyset pagination : pile des curseurs pour navigation arrière.
let logsCursorStack = [];   // before_id values pour revenir en arrière
let logsCurrentLastID = 0;  // min id de la page courante (pour "suivant")

// Couleur déterministe (hash du nom) pour repérer une passerelle d'un coup d'œil
// dans les chips de sélection et la colonne "Passerelle" du tableau.
function nodeColor(name) {
  let h = 0;
  const s = name || '';
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return `hsl(${h % 360} 62% 52%)`;
}

// Horodatage sur deux lignes (date puis heure, avec secondes) pour la colonne/carte
// "Horodatage" des logs — plus précis et plus lisible que la ligne unique de fmtDate,
// utile ici pour distinguer l'ordre des entrées à la seconde près.
function logsTsParts(iso) {
  if (!iso) return { d: '—', h: '' };
  const loc = typeof gpxBCP47 === 'function' ? gpxBCP47() : 'en-US';
  const tz = state.timezone ? { timeZone: state.timezone } : {};
  try {
    const dt = new Date(iso);
    return {
      d: dt.toLocaleDateString(loc, { ...tz, dateStyle: 'short' }),
      h: dt.toLocaleTimeString(loc, { ...tz, timeStyle: 'medium' }),
    };
  } catch { return { d: fmtDate(iso), h: '' }; }
}

function logsTsCellHTML(iso) {
  const { d, h } = logsTsParts(iso);
  return `<span class="logs-ts-cell"><span class="logs-ts-date">${esc(d)}</span><span class="logs-ts-time mono">${esc(h)}</span></span>`;
}

// Horodatage à la milliseconde, pour le tiroir de détail (une seule ligne de requête,
// la précision compte plus que dans la liste). e.ts est déjà formaté en RFC3339Nano de
// bout en bout (voir accesslog.go côté passerelle), les millisecondes sont donc réelles.
function logsTsPrecise(iso) {
  if (!iso) return '—';
  try {
    const dt = new Date(iso);
    const loc = typeof gpxBCP47 === 'function' ? gpxBCP47() : 'en-US';
    const tz = state.timezone ? { timeZone: state.timezone } : {};
    const d = dt.toLocaleDateString(loc, { ...tz, dateStyle: 'short' });
    const h = dt.toLocaleTimeString(loc, { ...tz, timeStyle: 'medium' });
    const ms = String(dt.getMilliseconds()).padStart(3, '0');
    return `${d} ${h}.${ms}`;
  } catch { return fmtDate(iso); }
}

// Convertit un code pays ISO-3166 alpha-2 (ex. "FR") en emoji drapeau.
function countryFlag(cc) {
  if (!cc || cc.length !== 2) return '';
  const up = cc.toUpperCase();
  const A = 0x1F1E6;
  return String.fromCodePoint(A + (up.charCodeAt(0) - 65), A + (up.charCodeAt(1) - 65));
}

function stopLogsSSE() {
  if (logsSSE) {
    logsSSE.close();
    logsSSE = null;
  }
}

function logFilterLabels() {
  const labels = {
    domain: t('logs.domain'), ip: t('logs.ip'), method: t('logs.method'), status: t('logs.status'),
    path: t('logs.path'), level: t('logs.level'), search: t('logs.search'),
    date_from: t('logs.from'), date_to: t('logs.to'),
  };
  if (!logsScope.lockComp) labels.node_name = t('logs.node');
  return labels;
}

function edgeLogNodeName() {
  const c = state.selectedEdge;
  return (c?.node_name || c?.display_name || c?.id || '').trim();
}

// edgeLogNodeID retourne l'identifiant stable de la passerelle sélectionnée (token/id
// en base), utilisé pour filtrer les logs à la place de node_name : un
// renommage du nœud (ex. après un re-pairing suite à une passerelle.json régénéré)
// ne fait alors plus disparaître son historique de logs.
function edgeLogNodeID() {
  return (state.selectedEdge?.id || '').trim();
}

function hasActiveLogFilters() {
  return !!(logsFilters.domain || logsFilters.ip || logsFilters.method ||
    logsFilters.status || logsFilters.path || logsFilters.search ||
    logsFilters.date_from || logsFilters.date_to || logsFilters.level ||
    (!logsScope.lockComp && logsFilters.node_name));
}

/**
 * Pose les filtres puis rend la vue Logs.
 * @param {{kind?:string, component?:string, node_name?:string, node_id?:string, lockComp?:boolean, keepDomain?:boolean, keepFilters?:boolean}} preset
 */
function openLogs(preset = {}) {
  const node = preset.node_name || '';
  const nodeID = preset.node_id || '';
  const comp = preset.component || '';
  logsScope = {
    kind: preset.kind || 'access',
    component: comp,
    node_name: node,
    node_id: nodeID,
    // Passerelle : component + nœud verrouillés. Admin : composant filtrable.
    lockComp: preset.lockComp === true || (!!node && !!comp),
  };
  logsFilters.kind = logsScope.kind;
  logsFilters.component = logsScope.component;
  // Portée passerelle : nœud verrouillé. Portée Admin : le sélecteur de nœud garde la main,
  // on ne l'écrase donc pas ici (sinon toute sélection d'un nœud serait perdue au rendu).
  if (logsScope.lockComp) logsFilters.node_name = logsScope.node_name;
  const keep = preset.keepFilters === true || preset.keepDomain === true || hasActiveLogFilters();
  if (!keep) {
    logsFilters.level = '';
    logsFilters.domain = '';
    logsFilters.ip = '';
    logsFilters.method = '';
    logsFilters.status = '';
    logsFilters.path = '';
    logsFilters.search = '';
    logsFilters.date_from = '';
    logsFilters.date_to = '';
    if (!logsScope.lockComp) logsFilters.node_name = '';
  }
  renderLogsPage();
}
window.openLogs = openLogs;

/** Ouvre les logs d'accès avec des filtres pré-remplis (depuis Prism / cellules). */
window.openLogsFiltered = function(opts = {}) {
  const keys = ['domain', 'ip', 'method', 'status', 'path', 'level', 'search', 'date_from', 'date_to'];
  for (const k of keys) {
    if (opts[k] !== undefined && opts[k] !== null) logsFilters[k] = String(opts[k]);
  }
  if (state.selectedEdge) navigate('edge-logs-access');
  else navigate('logs');
};

// Admin — toutes les passerelles / composants
pages.logs = function() {
  openLogs({ kind: 'access', keepFilters: hasActiveLogFilters() });
};
pages['logs-system'] = function() {
  logsFilters.ip = '';
  logsFilters.method = '';
  logsFilters.status = '';
  logsFilters.path = '';
  openLogs({ kind: 'system', keepFilters: !!(logsFilters.domain || logsFilters.search || logsFilters.level) });
};

// Passerelle — scoped au nœud sélectionné
pages['edge-logs-access'] = function() {
  openLogs({ kind: 'access', component: 'edge', node_name: edgeLogNodeName(), node_id: edgeLogNodeID(), lockComp: true, keepFilters: hasActiveLogFilters() });
};
// Menu Observabilité (passerelle et Admin) → atterrit sur la Synthèse
pages['edge-observability'] = function() {
  navigate('edge-obs-synthese');
};
pages['admin-observability'] = function() {
  navigate('obs-synthese');
};
pages['edge-logs-system'] = function() {
  logsFilters.ip = '';
  logsFilters.method = '';
  logsFilters.status = '';
  logsFilters.path = '';
  openLogs({ kind: 'system', component: 'edge', node_name: edgeLogNodeName(), node_id: edgeLogNodeID(), lockComp: true, keepFilters: !!(logsFilters.domain || logsFilters.search || logsFilters.level) });
};

function isSystemLogs() {
  return logsFilters.kind === 'system';
}

function logsScopeBanner() {
  const kind = logsFilters.kind;
  const node = logsFilters.node_name;
  let text = '';
  if (kind === 'access') {
    text = node
      ? t('logs.banner_access_edge')
      : t('logs.banner_access_all');
  } else if (kind === 'system') {
    text = node
      ? t('logs.banner_sys_edge')
      : t('logs.banner_sys_all');
  }
  if (node) {
    return `<div style="margin-bottom:12px;padding:8px 12px;background:color-mix(in srgb,var(--accent) 8%,transparent);border:1px solid color-mix(in srgb,var(--accent) 22%,transparent);border-radius:6px;font-size:12px;color:var(--text2);">
      ${t('logs.filtered_edge')} <strong style="color:var(--text)">${esc(node)}</strong>${text ? ' — ' + esc(text) : ''}
    </div>`;
  }
  if (text) {
    return `<div style="margin-bottom:12px;padding:8px 12px;background:color-mix(in srgb,var(--accent) 8%,transparent);border:1px solid color-mix(in srgb,var(--accent) 22%,transparent);border-radius:6px;font-size:12px;color:var(--text2);">${esc(text)}</div>`;
  }
  return '';
}

function renderLogsPage() {
  stopLogsSSE();
  livePaused = false;
  liveRows = [];
  logsCursorStack = [];
  logsCurrentLastID = 0;
  logsActiveTab = 'static';
  // État de vue (période rapide, masquage du trafic interne) : propre à chaque page, ne
  // doit pas survivre à un changement de portée (Admin ↔ passerelle), sinon un filtre
  // laissé actif ailleurs peut vider silencieusement la vue suivante (ex. "masquer le
  // trafic interne" coché en Admin, puis plus aucune ligne sur une passerelle dont le
  // trafic est presque entièrement local).
  logsQuickMs = 0;
  logsHideInternal = true;

  document.getElementById('topbar-actions').innerHTML = `
    <button type="button" class="btn btn-ghost btn-icon btn-sm" onclick="exportLogs('json')" title="${esc(t('logs.export_json'))}">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M9 15l1.5 3L12 15l1.5 3L15 15"/></svg>
    </button>
    <button type="button" class="btn btn-ghost btn-icon btn-sm" onclick="exportLogs('csv')" title="${esc(t('logs.export_csv'))}">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M8 17v-4M12 17v-4M16 17v-4"/></svg>
    </button>
    <button type="button" id="btn-logs-live" class="btn btn-ghost btn-icon btn-sm" onclick="toggleLogsLive()" title="${esc(t('logs.tab_live'))}">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" stroke="none"><path d="M13 2 3 14h7l-1 8 10-12h-7l1-8z"/></svg>
    </button>
    <button type="button" class="btn btn-ghost btn-icon btn-sm" onclick="openLogsSettingsModal()" title="${esc(t('logs.tab_settings'))}">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
    </button>`;

  const content = document.getElementById('content');
  content.innerHTML = `
    ${logsScopeBanner()}
    <div id="logs-tab-content"></div>`;

  // Délégation : filtres cliquables + corrélation (évite les onclick cassés par les guillemets)
  if (!content.dataset.logsWired) {
    content.dataset.logsWired = '1';
    content.addEventListener('click', onLogsClick);
  }

  renderStaticLogs();
}

function onLogsClick(e) {
  if (onLogsQuickClick(e)) return;
  const prismBtn = e.target.closest('[data-log-prism]');
  if (prismBtn && document.getElementById('content')?.contains(prismBtn)) {
    e.preventDefault();
    const domain = prismBtn.getAttribute('data-log-prism') || '';
    const ip = prismBtn.getAttribute('data-log-ip') || '';
    openPrismFromLogs({ proxy: domain, ip });
    return;
  }
  const link = e.target.closest('[data-log-filter]');
  if (link && document.getElementById('content')?.contains(link)) {
    e.preventDefault();
    applyLogCellFilter(link.getAttribute('data-log-filter'), link.getAttribute('data-log-value') || '', e.shiftKey);
    return;
  }
  const chipX = e.target.closest('[data-log-chip-clear]');
  if (chipX && document.getElementById('content')?.contains(chipX)) {
    e.preventDefault();
    clearLogFilter(chipX.getAttribute('data-log-chip-clear'));
  }
}

window.applyLogCellFilter = function(field, value, additive) {
  if (!field || value == null || value === '') return;
  if (!additive) {
    // Toggle : recliquer la même valeur retire le filtre
    if (logsFilters[field] === value) {
      logsFilters[field] = '';
    } else {
      logsFilters[field] = value;
    }
  } else {
    logsFilters[field] = value;
  }
  syncLogFilterInputs();
  renderFilterChips();
  loadStaticLogs(0);
};

window.clearLogFilter = function(field) {
  if (!field) return;
  if (field === '*') {
    for (const k of Object.keys(logFilterLabels())) logsFilters[k] = '';
  } else {
    logsFilters[field] = '';
  }
  syncLogFilterInputs();
  renderFilterChips();
  loadStaticLogs(0);
};

function syncLogFilterInputs() {
  const el = document.getElementById('lf-search');
  if (el) el.value = logsFilters.search || '';
}

function renderFilterChips() {
  const el = document.getElementById('logs-filter-chips');
  if (!el) return;
  const chips = [];
  for (const [k, label] of Object.entries(logFilterLabels())) {
    const v = logsFilters[k];
    if (!v) continue;
    chips.push(`<span class="filter-chip">${esc(label)}: <b>${esc(v)}</b>
      <button type="button" class="filter-chip-x" data-log-chip-clear="${esc(k)}" title="${esc(t('logs.remove'))}">✕</button></span>`);
  }
  if (!chips.length) {
    el.innerHTML = '';
    el.hidden = true;
    return;
  }
  el.hidden = false;
  el.innerHTML = chips.join('') +
    `<button type="button" class="btn btn-ghost btn-sm" style="font-size:11px" data-log-chip-clear="*">${t('logs.clear_all')}</button>`;
}

function logCellFilter(field, value, display) {
  if (value == null || value === '' || value === '—') {
    return `<span style="color:var(--text3)">—</span>`;
  }
  const shown = display != null ? display : value;
  const active = logsFilters[field] === String(value) ? ' is-active' : '';
  return `<button type="button" class="log-filter-link${active}" data-log-filter="${esc(field)}" data-log-value="${esc(String(value))}" title="${esc(t('logs.filter_title'))}">${shown}</button>`;
}

function openPrismFromLogs(opts = {}) {
  const node = logsScope.node_name || edgeLogNodeName();
  window._prismProxyInit = opts.proxy || logsFilters.domain || '';
  window._prismIpInit = opts.ip || logsFilters.ip || '';
  window._prismPathInit = opts.path || logsFilters.path || '';
  if (!node && !state.selectedEdge) {
    navigate('prism');
    return;
  }
  if (state.selectedEdge) {
    navigate('edge-prism');
    return;
  }
  // Sélectionne la passerelle par node_name si possible
  const edges = window._edgeNodes || [];
  const idx = edges.findIndex(c => c.node_name === node || c.display_name === node || c.id === node);
  if (idx >= 0) {
    selectEdge(edges[idx], 'edge-prism');
    return;
  }
  toast(t('logs.prism_need_edge'), 'error');
}

// Remplace les anciens onglets Statique/Temps réel/Paramètres : un bouton bascule le
// contenu de la page en direct, un autre ouvre les réglages de rétention en modale.
window.toggleLogsLive = function() {
  const goingLive = logsActiveTab !== 'live';
  logsActiveTab = goingLive ? 'live' : 'static';
  const btn = document.getElementById('btn-logs-live');
  if (btn) btn.classList.toggle('is-active', goingLive);
  if (logsSSE) { logsSSE.close(); logsSSE = null; }
  livePaused = false;
  liveRows = [];
  if (goingLive) renderLiveLogs();
  else renderStaticLogs();
};

function componentFilterHTML(idPrefix) {
  if (logsScope.lockComp) {
    return `<input type="hidden" id="${idPrefix}comp" value="${esc(logsFilters.component)}">
      <span class="chip" style="font-size:11px">${esc(logsFilters.component || 'edge')}</span>`;
  }
  return `<select id="${idPrefix}comp" class="input" onchange="${idPrefix === 'lf-live-' ? 'restartSSE()' : 'logsFilter()'}">
      <option value="">${t('logs.comp_ph')}</option>
      <option${logsFilters.component==='admin'?' selected':''}>admin</option>
      <option${logsFilters.component==='agent'?' selected':''}>agent</option>
      <option${logsFilters.component==='edge'?' selected':''}>edge</option>
    </select>`;
}

// Chips de sélection des passerelles (onglet Statique, portée Admin uniquement) : une
// pastille de couleur par nœud + "Toutes". En portée passerelle, le nœud est déjà
// verrouillé et annoncé par le bandeau de portée — pas de chips.
function nodeChipsHTML() {
  if (logsScope.lockComp) return '';
  const edges = logsAllEdges || [];
  if (!edges.length) return '';
  const cur = logsFilters.node_name;
  const chip = (v, label) => `<button type="button" class="chip${cur === v ? ' active' : ''}" data-log-node="${esc(v)}">${v ? `<span class="logs-node-dot" style="background:${nodeColor(v)}"></span>` : ''}${esc(label)}</button>`;
  return `<div class="logs-node-chips">
    <span class="logs-node-chips-label">${esc(t('logs.node'))}</span>
    ${edges.map(n => { const v = n.node_name || n.display_name || n.id; return chip(v, n.display_name || n.node_name || n.id); }).join('')}
    ${chip('', t('logs.node_all'))}
  </div>`;
}

// Sélecteur de passerelle (select), utilisé pour le flux Live et comme repli. Uniquement
// en portée Admin (en portée passerelle le nœud est verrouillé et déjà annoncé par le
// bandeau de portée).
function nodeFilterHTML(idPrefix) {
  if (logsScope.lockComp) return '';
  const edges = logsAllEdges || [];
  return `<select id="${idPrefix}node" class="input" onchange="${idPrefix === 'lf-live-' ? 'restartSSE()' : 'logsFilter()'}">
      <option value="">${t('logs.node_ph')}</option>
      ${edges.map(n => { const v = n.node_name || n.display_name || n.id; return `<option value="${esc(v)}"${v === logsFilters.node_name ? ' selected' : ''}>${esc(n.display_name || n.node_name || n.id)}</option>`; }).join('')}
    </select>`;
}

async function renderStaticLogs() {
  if (!logsScope.lockComp) await ensureLogsEdges();
  await ensureLogsRetention();
  const c = document.getElementById('logs-tab-content');
  if (!c) return; // navigation entre-temps
  const isSystem = isSystemLogs();
  const head = isSystem
    ? `<th>${t('logs.ts')}</th><th>${t('logs.level')}</th><th>${t('logs.component')}</th><th>${t('logs.node')}</th><th>${t('logs.context')}</th><th>${t('logs.message')}</th>`
    : accessLogHead();
  const cols = isSystem ? 6 : (logsScope.lockComp ? 7 : 8);
  c.innerHTML = `
    <div class="card blueprint logs-filterbar">
      <div class="logs-filter-row">
        <div id="logs-node-chips-wrap" style="flex:1;min-width:0">${nodeChipsHTML()}</div>
        <div id="logs-period-seg">${logsPeriodSegHTML()}</div>
      </div>
      <div class="logs-filter-row" style="margin-top:10px">
        <input id="lf-search" class="input search-input" style="flex:1;max-width:none;min-width:180px" placeholder="${esc(t('logs.search_ph'))}" value="${esc(logsFilters.search)}" oninput="logsFilter()">
        <div id="logs-status-chips">${logsStatusChipsHTML()}</div>
        ${isSystem ? '' : `
        <label class="logs-toggle-inline">
          <span class="toggle"><input type="checkbox" id="lf-hide-internal" ${logsHideInternal ? 'checked' : ''} onchange="toggleHideInternal()"><span class="toggle-slider"></span></span>
          ${esc(t('logs.hide_internal'))}
        </label>`}
      </div>
      <div id="logs-hist"></div>
      <div id="logs-filter-chips" class="filter-chips" hidden></div>
    </div>
    <div class="logs-split">
      <div class="card blueprint logs-table-card" style="padding:0;overflow:hidden">
        <div class="logs-desktop table-wrap">
          <table>
            <thead><tr>${head}</tr></thead>
            <tbody id="logs-tbody"><tr><td colspan="${cols}" class="empty"><p>${t('common.loading')}</p></td></tr></tbody>
          </table>
        </div>
        <div id="logs-list" class="logs-mobile logs-list"><div class="logs-empty">${t('common.loading')}</div></div>
        <div id="logs-pager" class="logs-pager"></div>
      </div>
      <aside class="card blueprint logs-detail-col" id="logs-detail-col" hidden></aside>
    </div>`;
  renderFilterChips();
  loadStaticLogs(0);
  loadLogsHist();
}

function logEntrySep() {
  return `<span class="log-entry-sep">·</span>`;
}

function renderAccessLogEntry(e, i) {
  const parts = [];
  if (e.domain || e.path) parts.push(`<span class="mono">${e.domain ? logCellFilter('domain', e.domain) : ''}${e.path ? logCellFilter('path', e.path) : ''}</span>`);
  if (e.ip) parts.push(`<span class="mono">${logCellFilter('ip', e.ip)}</span>`);
  if (e.country) parts.push(`<span>${countryFlag(e.country)} ${esc(e.country)}</span>`);
  if (!logsScope.lockComp && e.node_name) parts.push(`<span class="mono"><span class="logs-node-dot" style="background:${nodeColor(e.node_name)}"></span>${esc(nodeDisplayName(e.node_name))}</span>`);
  if (e.latency_ms != null && e.latency_ms !== '') parts.push(`<span>${esc(String(e.latency_ms))}ms</span>`);
  return `<article class="log-entry" data-log-i="${i}" style="border-left:3px solid ${e.level==='error'?'var(--red)':e.level==='warn'?'var(--yellow)':'transparent'}">
    <div class="log-entry-top">
      <span class="log-entry-ts">${logsTsCellHTML(e.ts)}</span>
      ${e.method ? `<b>${logCellFilter('method', e.method)}</b>` : ''}
      ${e.status ? logCellFilter('status', String(e.status), httpStatusBadge(e.status)) : ''}
    </div>
    ${parts.length ? `<div class="log-entry-mid">${parts.join(logEntrySep())}</div>` : ''}
    ${e.message ? `<div class="log-entry-msg" title="${esc(e.message)}">${esc(e.message)}</div>` : ''}
  </article>`;
}

function renderSystemLogEntry(e, i) {
  const parts = [];
  if (e.component) parts.push(`<span class="chip" style="font-size:11px">${esc(e.component)}</span>`);
  if (e.node_name) parts.push(`<span class="mono">${esc(nodeDisplayName(e.node_name))}</span>`);
  if (e.domain) parts.push(`<span class="mono">${logCellFilter('domain', e.domain)}</span>`);
  return `<article class="log-entry" data-log-i="${i}">
    <div class="log-entry-top">
      <span class="log-entry-ts">${logsTsCellHTML(e.ts)}</span>
      ${logLvlBadge(e.level)}
      ${parts.join(logEntrySep())}
    </div>
    ${e.message ? `<div class="log-entry-msg" title="${esc(e.message)}">${esc(e.message)}</div>` : ''}
  </article>`;
}

// En-tête du tableau Logs d'accès (statique + Live) : colonne Passerelle masquée en
// portée passerelle (déjà annoncée par le bandeau de portée) — un seul jeu de colonnes
// pour les deux contextes, seule la portée change ce qui est affiché.
function accessLogHead() {
  const node = logsScope.lockComp ? '' : `<th>${t('logs.node')}</th>`;
  return `<th>${t('logs.ts')}</th>${node}<th>${t('logs.status')}</th><th>${t('logs.method')}</th><th>${t('logs.host_path')}</th><th>${t('logs.ip')}</th><th>${t('logs.country')}</th><th>${t('logs.latency')}</th>`;
}

// Le nom affiché doit être le nom lisible de la passerelle (display_name), pas le
// node_name technique stocké sur la ligne de log — cherché dans la liste des passerelles
// (portée Admin) ou la passerelle sélectionnée (portée verrouillée) ; à défaut, node_name.
function nodeDisplayName(nodeName) {
  if (!nodeName) return '';
  if (logsScope.lockComp) {
    const sel = state.selectedEdge;
    if (sel && (sel.node_name === nodeName || sel.id === nodeName)) return sel.display_name || nodeName;
    return nodeName;
  }
  const found = (logsAllEdges || []).find(n => n.node_name === nodeName || n.id === nodeName);
  return found?.display_name || nodeName;
}

function nodeCellHTML(e) {
  if (!e.node_name) return '<span style="color:var(--text3)">—</span>';
  return `<span class="logs-node-badge"><span class="logs-node-dot" style="background:${nodeColor(e.node_name)}"></span>${logCellFilter('node_name', e.node_name, esc(nodeDisplayName(e.node_name)))}</span>`;
}

function countryCellHTML(e) {
  if (!e.country) return '<span style="color:var(--text3)">—</span>';
  // "LO" = IP réseau local/privée (voir geoip_cache) : pas un vrai pays ISO, pas de drapeau.
  if (e.country === 'LO') return `<span style="color:var(--text3);font-size:11px">${esc(t('logs.local_network'))}</span>`;
  return `<span title="${esc(e.country)}">${countryFlag(e.country)} <span style="color:var(--text3);font-size:11px">${esc(e.country)}</span></span>`;
}

function renderAccessLogRow(e, i) {
  const lvlBorder = e.level === 'error' ? 'var(--red)' : e.level === 'warn' ? 'var(--yellow)' : 'transparent';
  const nodeCell = logsScope.lockComp ? '' : `<td>${nodeCellHTML(e)}</td>`;
  const domainPart = e.domain ? logCellFilter('domain', e.domain) : '';
  const pathPart = e.path ? logCellFilter('path', e.path) : '';
  const hostPath = (domainPart || pathPart) ? `${domainPart}${pathPart}` : '<span style="color:var(--text3)">—</span>';
  return `<tr data-log-i="${i}" style="border-left:3px solid ${lvlBorder}" title="${esc(e.level||'info')}${e.message ? ' — ' + e.message : ''}">
    <td style="white-space:nowrap">${logsTsCellHTML(e.ts)}</td>
    ${nodeCell}
    <td>${e.status ? logCellFilter('status', String(e.status), httpStatusBadge(e.status)) : '<span style="color:var(--text3)">—</span>'}</td>
    <td><b>${logCellFilter('method', e.method)}</b></td>
    <td class="mono logs-cell-clip" style="font-size:11px;max-width:340px">${hostPath}</td>
    <td class="mono" style="font-size:11px">${logCellFilter('ip', e.ip)}</td>
    <td style="font-size:11px">${countryCellHTML(e)}</td>
    <td style="color:var(--text2);font-size:11px">${e.latency_ms}ms</td>
  </tr>`;
}

function renderSystemLogRow(e, i) {
  return `<tr data-log-i="${i}">
    <td style="white-space:nowrap">${logsTsCellHTML(e.ts)}</td>
    <td>${logLvlBadge(e.level)}</td>
    <td><span class="chip" style="font-size:11px">${esc(e.component||'—')}</span></td>
    <td class="mono" style="font-size:11px">${e.node_name ? esc(nodeDisplayName(e.node_name)) : '—'}</td>
    <td class="mono" style="font-size:11px">${logCellFilter('domain', e.domain)}</td>
    <td class="logs-cell-clip" style="font-size:12px;max-width:480px" title="${esc(e.message)}">${esc(e.message||'—')}</td>
  </tr>`;
}

// Pas de filtres avancés séparés : la recherche libre couvre déjà domaine, chemin, IP,
// méthode, code, niveau et nœud (voir buildWhere côté backend) ; le filtrage précis par
// champ reste possible en cliquant une cellule (logCellFilter / applyLogCellFilter).
window.logsFilter = function() {
  logsFilters.search = document.getElementById('lf-search')?.value || '';
  renderFilterChips();
  loadStaticLogs(0);
};

function prismIconBtn(domain, ip) {
  if (!domain && !ip) return '';
  return `<button type="button" class="btn btn-ghost btn-icon btn-sm" data-log-prism="${esc(domain||'')}" data-log-ip="${esc(ip||'')}" title="${esc(t('logs.prism'))}">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 20V10M12 20V4M6 20v-6"/></svg>
  </button>`;
}

// loadStaticLogs charge une page de logs.
// beforeID=0 → première page (réinitialise le curseur).
// beforeID>0 → page suivante via keyset (id < beforeID).
// beforeID<0 → page précédente (dépile logsCursorStack).
async function loadStaticLogs(beforeID) {
  if (beforeID === 0) {
    logsCursorStack = [];
    logsCurrentLastID = 0;
  } else if (beforeID < 0) {
    // Retour arrière : dépiler
    beforeID = logsCursorStack.pop() || 0;
    logsCurrentLastID = 0;
  }

  const params = new URLSearchParams({ page_size: 50 });
  if (beforeID > 0) params.set('before_id', beforeID);
  params.set('kind', logsScope.kind || logsFilters.kind || 'access');
  if (logsScope.node_id) { params.set('node_id', logsScope.node_id); if (logsScope.node_name) params.set('node_name', logsScope.node_name); }
  else if (logsScope.node_name) params.set('node_name', logsScope.node_name);
  else if (!logsScope.lockComp && logsFilters.node_name) params.set('node_name', logsFilters.node_name);
  if (logsScope.lockComp && logsScope.component) params.set('component', logsScope.component);
  else if (logsFilters.component) params.set('component', logsFilters.component);
  for (const [k, v] of Object.entries(logsFilters)) {
    if (!v || k === 'kind' || k === 'node_name' || k === 'component') continue;
    params.set(k, v);
  }
  const isSystem = isSystemLogs();
  if (logsHideInternal && !isSystem) params.set('exclude_internal', '1');
  const cols = isSystem ? 6 : (logsScope.lockComp ? 7 : 8);
  try {
    const data = await api('GET', '/logs?' + params);
    const entries = data?.entries || [];
    const hasMore = data?.has_more || false;
    const lastID = data?.last_id || 0;
    logsCurrentLastID = lastID;

    const tbody = document.getElementById('logs-tbody');
    const list = document.getElementById('logs-list');
    if (!entries.length) {
      if (tbody) tbody.innerHTML = `<tr><td colspan="${cols}" class="empty"><p>${t('logs.none')}</p></td></tr>`;
      if (list) list.innerHTML = `<div class="logs-empty">${t('logs.none')}</div>`;
    } else if (isSystem) {
      logsRows = entries;
      if (tbody) tbody.innerHTML = entries.map((e, i) => renderSystemLogRow(e, i)).join('');
      if (list) list.innerHTML = entries.map((e, i) => renderSystemLogEntry(e, i)).join('');
    } else {
      logsRows = entries;
      if (tbody) tbody.innerHTML = entries.map((e, i) => renderAccessLogRow(e, i)).join('');
      if (list) list.innerHTML = entries.map((e, i) => renderAccessLogEntry(e, i)).join('');
    }
    const hasPrev = logsCursorStack.length > 0;
    const pager = document.getElementById('logs-pager');
    if (pager) pager.innerHTML =
      `${hasPrev ? `<button class="btn btn-secondary btn-sm" onclick="loadStaticLogs(-1)">${t('logs.prev')}</button>` : ''}
       ${hasMore ? `<button class="btn btn-secondary btn-sm" onclick="logsCursorStack.push(${beforeID||0});loadStaticLogs(${lastID})">${t('logs.next')}</button>` : ''}`;
  } catch(e) { toast(e.message, 'error'); }
}
window.loadStaticLogs = loadStaticLogs;

// Réglages de rétention : modale (remplace l'ancien onglet Paramètres). Les deux durées
// (accès / système) sont celles réellement lues par le backend (GET/PUT /logs/settings) —
// l'ancienne UI n'en exposait qu'une sous un nom `retention_days` que l'API n'a jamais eu,
// ce qui faisait que la sauvegarde ne prenait jamais effet.
window.openLogsSettingsModal = async function() {
  modal(t('logs.tab_settings'), `<div class="spinner" style="margin:20px auto"></div>`);
  try {
    const s = await api('GET', '/logs/settings') || {};
    const body = `
      <div class="field" style="margin-bottom:14px">
        <label class="field-label">${t('logs.retention_access')}</label>
        <input id="log-retention-access" type="number" class="input" value="${s.retention_access_days ?? 30}" min="1" max="3650" style="width:120px">
      </div>
      <div class="field">
        <label class="field-label">${t('logs.retention_system')}</label>
        <input id="log-retention-system" type="number" class="input" value="${s.retention_system_days ?? 90}" min="1" max="3650" style="width:120px">
      </div>
      <p style="font-size:12px;color:var(--text2);margin-top:10px">${t('logs.retention_hint')}</p>`;
    modal(t('logs.tab_settings'), body,
      `<button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel')}</button>
       <button class="btn btn-primary" onclick="saveLogsSettings()">${t('common.save')}</button>`);
  } catch(e) { modal(t('logs.tab_settings'), `<p style="color:var(--red)">${esc(e.message)}</p>`); }
};

window.saveLogsSettings = async function() {
  const access = parseInt(document.getElementById('log-retention-access')?.value) || 30;
  const sys = parseInt(document.getElementById('log-retention-system')?.value) || 90;
  try {
    await api('PUT', '/logs/settings', { retention_access_days: access, retention_system_days: sys });
    toast(t('logs.settings_saved'), 'success');
    closeModal();
    logsRetention = { access, system: sys };
    logsRetentionLoaded = true;
    if (logsActiveTab === 'static') refreshLogsView();
  } catch(e) { toast(e.message, 'error'); }
};

async function renderLiveLogs() {
  if (!logsScope.lockComp) await ensureLogsEdges();
  const c = document.getElementById('logs-tab-content');
  if (!c || logsActiveTab !== 'live') return; // navigation entre-temps
  const isSystem = isSystemLogs();
  const head = isSystem
    ? `<th>${t('logs.ts')}</th><th>${t('logs.level')}</th><th>${t('logs.component')}</th><th>${t('logs.node')}</th><th>${t('logs.message')}</th>`
    : accessLogHead();
  c.innerHTML = `
    <div class="search-bar" style="gap:8px;margin-bottom:12px">
      <input id="lf-live-search" class="input search-input" placeholder="${esc(t('logs.filter_text'))}" oninput="restartSSE()">
      <select id="lf-live-level" class="input" onchange="restartSSE()">
        <option value="">${t('logs.level_ph')}</option>
        <option>info</option><option>warn</option><option>error</option><option>debug</option>
      </select>
      ${componentFilterHTML('lf-live-')}
      ${nodeFilterHTML('lf-live-')}
      ${isSystem ? '' : `<input id="lf-live-domain" class="input" placeholder="${esc(t('logs.domain_ph'))}" value="${esc(logsFilters.domain)}" oninput="restartSSE()">`}
      <button id="btn-pause-live" class="btn btn-secondary btn-sm" onclick="toggleLivePause()">${t('logs.pause_btn')}</button>
      <button class="btn btn-secondary btn-sm" onclick="clearLiveStream()">🗑 ${t('logs.clear')}</button>
    </div>
    <div class="logs-live-bar">
      <div class="logs-live-dot"></div>
      <span id="live-status">${t('logs.connecting')}</span>
    </div>
    <div class="logs-split">
      <div class="card blueprint logs-table-card" style="padding:0;overflow:hidden">
        <div class="logs-desktop table-wrap">
          <table>
            <thead><tr>${head}</tr></thead>
            <tbody id="live-tbody"></tbody>
          </table>
        </div>
        <div id="live-list" class="logs-mobile logs-list"></div>
      </div>
      <aside class="card blueprint logs-detail-col" id="logs-detail-col" hidden></aside>
    </div>`;
  startSSE();
}

window.restartSSE = function() {
  stopLogsSSE();
  startSSE();
};

function startSSE() {
  const params = new URLSearchParams();
  // Portée menu = source de vérité (kind / nœud / composant passerelle).
  params.set('kind', logsScope.kind || logsFilters.kind || 'access');
  if (logsScope.node_id) { params.set('node_id', logsScope.node_id); if (logsScope.node_name) params.set('node_name', logsScope.node_name); }
  else if (logsScope.node_name) params.set('node_name', logsScope.node_name);
  else if (!logsScope.lockComp && logsFilters.node_name) params.set('node_name', logsFilters.node_name);

  const lvl    = document.getElementById('lf-live-level')?.value;
  const search = document.getElementById('lf-live-search')?.value;
  const domain = document.getElementById('lf-live-domain')?.value;
  let comp = '';
  if (logsScope.lockComp) {
    comp = logsScope.component;
  } else {
    comp = document.getElementById('lf-live-comp')?.value || '';
  }
  if (lvl)    params.set('level', lvl);
  if (comp)   params.set('component', comp);
  if (domain) params.set('domain', domain);
  if (search) params.set('search', search);
  params.set('_auth', state.token);

  logsSSE = new EventSource('/api/v1/logs/live?' + params);
  logsSSE.onopen = () => {
    const el = document.getElementById('live-status');
    if (el) el.textContent = t('logs.connected');
  };
  logsSSE.onmessage = (ev) => {
    try {
      const e = JSON.parse(ev.data);
      if (!livePaused) appendLiveRow(e);
      else liveRows.push(e);
    } catch {}
  };
  logsSSE.onerror = () => {
    const el = document.getElementById('live-status');
    if (el) el.textContent = t('logs.reconnecting');
  };
}

// Tampon pour regrouper les insertions DOM en un seul frame.
let _livePending = [];
let _liveRaf = null;

function _flushLiveRows() {
  const tbody = document.getElementById('live-tbody');
  const list  = document.getElementById('live-list');
  if (!tbody && !list) { _livePending = []; _liveRaf = null; return; }
  const isSystem = isSystemLogs();
  const fragTbody = document.createDocumentFragment();
  const fragList  = document.createDocumentFragment();
  // Le plus récent en premier, comme la vue statique : on parcourt le lot du plus
  // récent au plus vieux (arrivés dans _livePending en ordre chronologique croissant)
  // et on l'insère en tête, plutôt que de l'empiler en bas.
  for (let idx = _livePending.length - 1; idx >= 0; idx--) {
    const e = _livePending[idx];
    if (tbody) {
      // innerHTML sur <tr> ne fonctionne pas directement — on passe par un wrapper
      const tmp = document.createElement('tbody');
      tmp.innerHTML = isSystem ? renderSystemLogRow(e) : renderAccessLogRow(e);
      if (tmp.firstElementChild) fragTbody.appendChild(tmp.firstElementChild);
    }
    if (list) {
      const wrap = document.createElement('div');
      wrap.innerHTML = isSystem ? renderSystemLogEntry(e) : renderAccessLogEntry(e);
      if (wrap.firstElementChild) fragList.appendChild(wrap.firstElementChild);
    }
  }
  if (tbody) {
    tbody.insertBefore(fragTbody, tbody.firstChild);
    while (tbody.children.length > 500) tbody.removeChild(tbody.lastChild);
  }
  if (list) {
    list.insertBefore(fragList, list.firstChild);
    while (list.children.length > 500) list.removeChild(list.lastChild);
  }
  _livePending = [];
  _liveRaf = null;
}

function appendLiveRow(e) {
  _livePending.push(e);
  if (!_liveRaf) _liveRaf = requestAnimationFrame(_flushLiveRows);
}

window.toggleLivePause = function() {
  livePaused = !livePaused;
  const btn = document.getElementById('btn-pause-live');
  if (btn) btn.textContent = livePaused ? t('logs.resume_btn') : t('logs.pause_btn');
  if (!livePaused) {
    liveRows.forEach(appendLiveRow);
    liveRows = [];
  }
};

window.clearLiveStream = function() {
  const tbody = document.getElementById('live-tbody');
  const list  = document.getElementById('live-list');
  if (tbody) tbody.innerHTML = '';
  if (list)  list.innerHTML  = '';
  liveRows = [];
  _livePending = [];
};

function logLvlBadge(lvl) {
  const m = { info: 'tag-neutral', warn: 'tag-yellow', error: 'tag-red', debug: 'tag-neutral' };
  return `<span class="tag ${m[lvl]||'tag-neutral'}" style="font-size:10px">${esc(lvl||'info')}</span>`;
}

function httpStatusBadge(code) {
  if (!code) return '<span style="color:var(--text3)">—</span>';
  const cls = code >= 500 ? 'tag-red' : code >= 400 ? 'tag-yellow' : code >= 200 ? 'tag-green' : 'tag-neutral';
  return `<span class="tag ${cls}" style="font-size:11px">${code}</span>`;
}

window.exportLogs = function(fmt) {
  const params = new URLSearchParams({ format: fmt });
  params.set('kind', logsScope.kind || logsFilters.kind || 'access');
  if (logsScope.node_id) { params.set('node_id', logsScope.node_id); if (logsScope.node_name) params.set('node_name', logsScope.node_name); }
  else if (logsScope.node_name) params.set('node_name', logsScope.node_name);
  else if (!logsScope.lockComp && logsFilters.node_name) params.set('node_name', logsFilters.node_name);
  if (logsScope.lockComp && logsScope.component) params.set('component', logsScope.component);
  else if (logsFilters.component) params.set('component', logsFilters.component);
  for (const [k, v] of Object.entries(logsFilters)) {
    if (!v || k === 'kind' || k === 'node_name' || k === 'component') continue;
    params.set(k, v);
  }
  fetch('/api/v1/logs/export?' + params, { headers: { 'Authorization': 'Bearer ' + state.token } })
    .then(r => r.blob())
    .then(blob => {
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = 'logs.' + fmt;
      a.click(); URL.revokeObjectURL(url);
    }).catch(e => toast('Export impossible : ' + e.message, 'error'));
};

// ── Logs d'accès : périodes rapides, classes de statut, histogramme, tiroir de détail ──

let logsQuickMs = 0;
let logsRows = [];

// Rétention effective (jours), chargée depuis GET /logs/settings — conditionne les
// tranches de temps proposées (pas la peine d'offrir "1 an" si tout est purgé à 30 jours).
let logsRetention = { access: 30, system: 90 };
let logsRetentionLoaded = false;
async function ensureLogsRetention() {
  if (logsRetentionLoaded) return logsRetention;
  try {
    const s = await api('GET', '/logs/settings');
    logsRetention = { access: s?.retention_access_days || 30, system: s?.retention_system_days || 90 };
  } catch { /* défauts conservés */ }
  logsRetentionLoaded = true;
  return logsRetention;
}

// Échelle de temps courte, fixe (< 1 mois) — `days` = ancienneté couverte (0 = toujours
// proposée quelle que soit la rétention, ce sont des fenêtres < 1 jour).
const LOGS_PERIOD_SHORT = [
  { label: '15m', ms: 9e5, days: 0 },
  { label: '1h', ms: 3.6e6, days: 0 },
  { label: '6h', ms: 2.16e7, days: 0 },
  { label: '24h', ms: 8.64e7, days: 1 },
  { label: '7d', ms: 7 * 8.64e7, days: 7 },
  { label: '14d', ms: 14 * 8.64e7, days: 14 },
];
// Au-delà, en mois puis en années — pas de plafond : la rétention peut dépasser 1 an
// (jusqu'à 3650 jours, la limite du champ dans la modale de réglages).
const LOGS_PERIOD_LONG_DAYS = [30, 90, 180, 365, 730, 1095, 1825, 2555, 3650];

function logsPeriodLabel(days) {
  if (days >= 365) {
    const n = Math.round(days / 365);
    return `${n} ${n === 1 ? t('lg.year') : t('lg.years')}`;
  }
  const n = Math.round(days / 30);
  return `${n} ${n === 1 ? t('lg.month') : t('lg.months')}`;
}

function logsPeriodCandidates() {
  const long = LOGS_PERIOD_LONG_DAYS.map(d => ({ label: logsPeriodLabel(d), ms: d * 8.64e7, days: d }));
  return [...LOGS_PERIOD_SHORT, ...long];
}

function logsPeriodsForRetention(retentionDays) {
  const r = retentionDays > 0 ? retentionDays : 3650;
  return logsPeriodCandidates().filter(c => c.days === 0 || c.days <= r);
}

// Toggle de période (segmenté, façon maquette), échelonné selon la rétention configurée.
function logsPeriodSegHTML() {
  const retention = isSystemLogs() ? logsRetention.system : logsRetention.access;
  const periods = logsPeriodsForRetention(retention);
  const per = periods.map(c => `<button type="button" class="seg-btn${logsQuickMs === c.ms ? ' active' : ''}" data-log-quick="${c.ms}">${c.label}</button>`).join('');
  const all = `<button type="button" class="seg-btn${logsQuickMs ? '' : ' active'}" data-log-quick="0">${esc(t('lg.q_all'))}</button>`;
  return `<div class="logs-seg">${per}${all}</div>`;
}

// Chips de classe de statut (ou niveau en logs système) : Tous/2xx/3xx/4xx/5xx.
function logsStatusChipsHTML() {
  const set = isSystemLogs() ? ['warn', 'error'] : ['2xx', '3xx', '4xx', '5xx'];
  const key = isSystemLogs() ? 'level' : 'status';
  const all = `<button type="button" class="chip${logsFilters[key] ? '' : ' active'}" data-log-cls="">${esc(t('lg.status_all'))}</button>`;
  const cls = set.map(c => `<button type="button" class="chip${logsFilters[key] === c ? ' active' : ''}" data-log-cls="${c}">${c}</button>`).join('');
  return `<div class="logs-quick-g">${all}${cls}</div>`;
}

function refreshLogsView() {
  syncLogFilterInputs();
  renderFilterChips();
  const seg = document.getElementById('logs-period-seg');
  if (seg) seg.innerHTML = logsPeriodSegHTML();
  const st = document.getElementById('logs-status-chips');
  if (st) st.innerHTML = logsStatusChipsHTML();
  loadStaticLogs(0);
  loadLogsHist();
}

// Toggle « Masquer le trafic interne » : exclusion appliquée côté serveur
// (exclude_internal, voir Store.buildWhere) pour que la pagination reste cohérente —
// filtrer après coup une page déjà limitée à 50 lignes pouvait la vider ou la
// clairsemer sans que ce soit visible pour l'utilisateur.
let logsHideInternal = true;

window.toggleHideInternal = function() {
  logsHideInternal = !!document.getElementById('lf-hide-internal')?.checked;
  loadStaticLogs(0);
};

// Retourne true si le clic a été traité (période, classe de statut, ligne → tiroir, actions du tiroir).
function onLogsQuickClick(e) {
  const content = document.getElementById('content');
  const within = el => el && content?.contains(el);
  const nodeChip = e.target.closest('[data-log-node]');
  if (within(nodeChip)) {
    const v = nodeChip.getAttribute('data-log-node') || '';
    logsFilters.node_name = logsFilters.node_name === v ? '' : v;
    const w = document.getElementById('logs-node-chips-wrap');
    if (w) w.innerHTML = nodeChipsHTML();
    refreshLogsView();
    return true;
  }
  const q = e.target.closest('[data-log-quick]');
  if (within(q)) {
    logsQuickMs = parseInt(q.getAttribute('data-log-quick'), 10) || 0;
    logsFilters.date_from = logsQuickMs ? new Date(Date.now() - logsQuickMs).toISOString() : '';
    logsFilters.date_to = '';
    refreshLogsView();
    return true;
  }
  const st = e.target.closest('[data-log-cls]');
  if (within(st)) {
    const c = st.getAttribute('data-log-cls'), key = isSystemLogs() ? 'level' : 'status';
    logsFilters[key] = logsFilters[key] === c ? '' : c;
    refreshLogsView();
    return true;
  }
  const bar = e.target.closest('[data-log-bucket]');
  if (within(bar)) {
    const r = gpxBucketISO(bar.getAttribute('data-log-bucket'), bar.getAttribute('data-unit'));
    if (r) {
      logsQuickMs = 0;
      logsFilters.date_from = r.from;
      logsFilters.date_to = r.to;
      refreshLogsView();
    }
    return true;
  }
  const act = e.target.closest('[data-log-dact]');
  if (within(act)) {
    logDrawerAction(act.getAttribute('data-log-dact'), parseInt(act.getAttribute('data-log-di'), 10));
    return true;
  }
  if (e.target.closest('#logs-detail-col')) return true;
  const row = e.target.closest('[data-log-i]');
  if (within(row) && !e.target.closest('button, a, input')) {
    openLogDrawer(logsRows[parseInt(row.getAttribute('data-log-i'), 10)], parseInt(row.getAttribute('data-log-i'), 10));
    return true;
  }
  return false;
}

async function loadLogsHist() {
  const el = document.getElementById('logs-hist');
  if (!el) return;
  const to = logsFilters.date_to ? new Date(logsFilters.date_to) : new Date();
  const from = logsFilters.date_from ? new Date(logsFilters.date_from) : new Date(to - 86400000);
  const unit = to - from <= 21600000 ? 'minute' : 'hour';
  let pts = [];
  if (isSystemLogs()) {
    const p = new URLSearchParams({ kind: 'system', bucket: unit, date_from: from.toISOString(), date_to: to.toISOString() });
    if (logsScope.node_id) { p.set('node_id', logsScope.node_id); if (logsScope.node_name) p.set('node_name', logsScope.node_name); }
    else if (logsScope.node_name) p.set('node_name', logsScope.node_name);
    else if (!logsScope.lockComp && logsFilters.node_name) p.set('node_name', logsFilters.node_name);
    if (logsScope.lockComp && logsScope.component) p.set('component', logsScope.component);
    else if (logsFilters.component) p.set('component', logsFilters.component);
    for (const k of ['level', 'domain', 'search']) if (logsFilters[k]) p.set(k, logsFilters[k]);
    pts = (await api('GET', '/logs/histogram?' + p).catch(() => null))?.points || [];
  } else {
    const p = new URLSearchParams({ from: from.toISOString(), to: to.toISOString(), bucket: unit });
    if (logsFilters.domain) p.set('proxy', logsFilters.domain);
    if (logsFilters.ip) p.set('ip', logsFilters.ip);
    if (logsFilters.path) p.set('path', logsFilters.path);
    if (logsScope.node_name) p.set('node_name', logsScope.node_name);
    else if (!logsScope.lockComp && logsFilters.node_name) p.set('node_name', logsFilters.node_name);
    const raw = await api('GET', '/prism/timeline?' + p).catch(() => []);
    pts = (Array.isArray(raw) ? raw : []).map(x => ({ bucket: x.bucket, total: x.requests, warn: 0, error: x.errors }));
  }
  if (!document.getElementById('logs-hist')) return;
  el.innerHTML = gpxHistHTML(pts, unit, { attr: 'data-log-bucket', title: t('lg.hist_title'), hint: t('lg.hist_hint') });
}

function closeLogDrawer() {
  const col = document.getElementById('logs-detail-col');
  if (col) { col.innerHTML = ''; col.hidden = true; }
  document.querySelectorAll('[data-log-i].is-selected').forEach(el => el.classList.remove('is-selected'));
}

function markSelectedLogRow(i) {
  document.querySelectorAll('[data-log-i].is-selected').forEach(el => el.classList.remove('is-selected'));
  document.querySelector(`[data-log-i="${i}"]`)?.classList.add('is-selected');
}

function openLogDrawer(en, i) {
  if (!en) return;
  if (isSystemLogs()) { openSysLogDrawer(en, i); return; }
  const col = document.getElementById('logs-detail-col');
  if (!col) return;
  markSelectedLogRow(i);
  const row = (k, v) => v === '' || v == null ? '' : `<div class="prism-dstat"><span>${esc(k)}</span><b style="font-size:13px;word-break:break-all">${v}</b></div>`;
  const iconBtn = (act, svg, title, extra = '') => `<button type="button" class="btn btn-ghost btn-icon btn-sm" ${extra} data-log-dact="${act}" data-log-di="${i}" title="${esc(title)}">${svg}</button>`;
  const icoCopy = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`;
  const icoBan = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>`;
  const icoPrism = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 20V10M12 20V4M6 20v-6"/></svg>`;
  // Badges de sécurité : qui a traité cette requête (WAF / Sentinel), vert quand rien ne
  // s'est déclenché plutôt que de simplement masquer la ligne — l'absence de signal est
  // une information en soi ("j'ai vérifié, rien à signaler"). Regroupés avec la réputation
  // IP (chargée juste en dessous) dans une seule section Sécurité, avec l'action Bannir.
  const wafBadge = (en.waf_matches || []).length
    ? `<span class="tag tag-red" style="font-size:11px" title="${esc(t('lg.waf_matches'))}">${esc(t('lg.waf_matches'))}: ${en.waf_matches.map(esc).join(', ')}</span>`
    : `<span class="tag tag-green" style="font-size:11px">${esc(t('lg.waf_clean'))}</span>`;
  const sentinelBadge = en.threat_signal
    ? `<span class="tag tag-red" style="font-size:11px" title="${esc(t('lg.threat_signal'))}">${esc(t('lg.threat_signal'))}: ${esc(en.threat_signal)}</span>`
    : `<span class="tag tag-green" style="font-size:11px">${esc(t('lg.sentinel_clean'))}</span>`;

  col.hidden = false;
  col.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <span class="prism-panel-title" style="margin:0">${esc(t('lg.detail'))}</span>
      <button type="button" class="btn btn-ghost btn-sm" data-log-dact="close" data-log-di="${i}">✕</button>
    </div>
    <div style="margin-bottom:10px">${en.status ? httpStatusBadge(en.status) : ''} <b>${esc(en.method || '')}</b> <span class="mono" style="word-break:break-all">${esc(en.domain || '')}${en.path ? logCellFilter('path', en.path) : ''}</span></div>
    <div class="logs-security-card">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
        <span class="prism-panel-title" style="margin:0">${esc(t('lg.security_badges'))}</span>
        ${en.ip ? iconBtn('ban', icoBan, t('lg.ban_ip'), 'style="color:var(--red)"') : ''}
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap">${wafBadge}${sentinelBadge}</div>
      <div id="log-drawer-scan" style="margin-top:10px;padding-top:10px;border-top:1px solid var(--border)"></div>
    </div>
    <div class="prism-dstats" style="grid-template-columns:1fr">
      ${row(t('logs.ts'), esc(logsTsPrecise(en.ts)))}
      ${row(t('logs.node'), en.node_name ? esc(nodeDisplayName(en.node_name)) : '')}
      ${row(t('logs.component'), esc(en.component || ''))}
      ${row(t('logs.ip'), en.ip ? `<span class="mono">${logCellFilter('ip', en.ip)}</span>` : '')}
      ${row(t('logs.country'), en.country ? countryCellHTML(en) : '')}
      ${row(t('lg.latency'), en.latency_ms != null ? esc(String(en.latency_ms)) + ' ms' : '')}
      ${row(t('lg.bytes'), en.bytes ? esc(String(en.bytes)) + ' B' : '')}
      ${row(t('lg.request_id'), en.request_id ? `<span class="mono">${esc(en.request_id)}</span>` : '')}
      ${row(t('logs.message'), esc(en.message || ''))}
    </div>
    <div class="logs-detail-actions">
      <div style="display:flex;gap:8px">
        <button type="button" class="btn btn-primary btn-sm logs-prism-btn" data-log-dact="prism" data-log-di="${i}">${icoPrism}${esc(t('lg.open_prism'))}</button>
        ${en.domain ? iconBtn('curl', icoCopy, t('lg.copy_curl')) : ''}
      </div>
    </div>`;
  if (en.ip) {
    api('GET', '/prism/ip-scan?ip=' + encodeURIComponent(en.ip)).then(d => {
      const box = document.getElementById('log-drawer-scan');
      if (!box || !d) return;
      const v = { banned: [t('pz.v_banned'), 'var(--red)'], suspect: [t('pz.v_suspect'), '#f59e0b'], clean: [t('pz.v_clean'), 'var(--green)'] }[d.verdict] || ['—', 'var(--text3)'];
      box.innerHTML = `<div style="font-size:11px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.03em;margin-bottom:6px">${esc(t('lg.scan'))}</div>
        <span class="prism-verdict" style="--v:${v[1]}">${esc(v[0])}</span>
        <span style="color:var(--text3);font-size:12px;margin-left:8px">${esc(t('pz.past_bans'))} ${d.ban_history || 0} · ${esc(t('pz.threat_decisions'))} ${(d.threats || []).length}</span>`;
    }).catch(() => {});
  }
}

async function logDrawerAction(act, i) {
  const en = logsRows[i];
  if (act === 'close') { closeLogDrawer(); return; }
  if (!en) return;
  if (act === 'copymsg' || act === 'copyjson') {
    const txt = act === 'copymsg' ? (en.message || '') : JSON.stringify(en, null, 2);
    try { await navigator.clipboard.writeText(txt); toast(t('lg.copied'), 'success'); } catch { toast(txt.slice(0, 200), 'info'); }
  }
  else if (act === 'prism') openPrismFromLogs({ proxy: en.domain, ip: en.ip, path: en.path });
  else if (act === 'curl') {
    const cmd = `curl -i -X ${en.method || 'GET'} 'https://${en.domain}${en.path || '/'}'`;
    try { await navigator.clipboard.writeText(cmd); toast(t('lg.copied'), 'success'); } catch { toast(cmd, 'info'); }
  } else if (act === 'ban') {
    if (!confirm(t('prism.ban_confirm', { ip: en.ip }))) return;
    try {
      await api('POST', '/security/bans', { ip: en.ip, reason: t('prism.ban_reason'), source: 'native' });
      toast(t('security.ban_success'), 'success');
    } catch (err) { toast(err.message, 'error'); }
  }
}

// Tiroir d'un log système : message complet, contexte et actions de filtrage.
function openSysLogDrawer(en, i) {
  const col = document.getElementById('logs-detail-col');
  if (!col) return;
  markSelectedLogRow(i);
  const row = (k, v) => v === '' || v == null ? '' : `<div class="prism-dstat"><span>${esc(k)}</span><b style="font-size:13px;word-break:break-word">${v}</b></div>`;
  const iconBtn = (act, svg, title) => `<button type="button" class="btn btn-ghost btn-icon btn-sm" data-log-dact="${act}" data-log-di="${i}" title="${esc(title)}">${svg}</button>`;
  const icoCopy = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`;
  const icoJson = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M8 3H6a2 2 0 0 0-2 2v3a2 2 0 0 1-2 2 2 2 0 0 1 2 2v3a2 2 0 0 0 2 2h2M16 3h2a2 2 0 0 1 2 2v3a2 2 0 0 0 2 2 2 2 0 0 0-2 2v3a2 2 0 0 1-2 2h-2"/></svg>`;
  col.hidden = false;
  col.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <span class="prism-panel-title" style="margin:0">${esc(t('lg.sys_detail'))}</span>
      <button type="button" class="btn btn-ghost btn-sm" data-log-dact="close" data-log-di="${i}">✕</button>
    </div>
    <div style="margin-bottom:10px">${logLvlBadge(en.level)} ${en.component ? logCellFilter('component', en.component) : ''}</div>
    <pre class="mono" style="white-space:pre-wrap;word-break:break-word;background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius);padding:10px;font-size:12px;margin:0 0 12px">${esc(en.message || '—')}</pre>
    <div class="prism-dstats" style="grid-template-columns:1fr">
      ${row(t('logs.ts'), esc(logsTsPrecise(en.ts)))}
      ${row(t('logs.node'), en.node_name ? esc(nodeDisplayName(en.node_name)) : '')}
      ${row(t('logs.domain'), en.domain ? `<span class="mono">${logCellFilter('domain', en.domain)}</span>` : '')}
      ${row(t('lg.request_id'), en.request_id ? `<span class="mono">${esc(en.request_id)}</span>` : '')}
    </div>
    <div style="display:flex;gap:6px;margin-top:14px">
      ${iconBtn('copymsg', icoCopy, t('lg.copy_message'))}
      ${iconBtn('copyjson', icoJson, t('lg.copy_json'))}
    </div>`;
}
