// ── PAGE: Logs (Admin + Core) ──────────────────────────────────────────
// Une seule vue ; les entrées de menu ne font que poser des filtres.
//
// Convention store :
//   kind=access  → status>0  (HTTP proxies / domaines)
//   kind=system  → status=0  (process core / admin / agent)
//
// logsFilters doit exister avant trafic.js (liens domaine → logs).

const logsFilters = {
  level: '', component: '', node_name: '', kind: 'access',
  domain: '', ip: '', method: '', status: '', path: '',
  search: '', date_from: '', date_to: '',
};

/** Portée posée par le menu (conservée pendant toute la visite de la page). */
let logsScope = { kind: 'access', component: '', node_name: '', lockComp: false };

let logsActiveTab = 'static';
let logsSSE = null;
let liveRows = [];
let livePaused = false;

function logFilterLabels() {
  return {
    domain: t('logs.domain'), ip: t('logs.ip'), method: t('logs.method'), status: t('logs.status'),
    path: t('logs.path'), level: t('logs.level'), search: t('logs.search'),
    date_from: t('logs.from'), date_to: t('logs.to'),
  };
}

function coreLogNodeName() {
  const c = state.selectedCore;
  return (c?.node_name || c?.display_name || c?.id || '').trim();
}

function hasActiveLogFilters() {
  return !!(logsFilters.domain || logsFilters.ip || logsFilters.method ||
    logsFilters.status || logsFilters.path || logsFilters.search ||
    logsFilters.date_from || logsFilters.date_to || logsFilters.level);
}

/**
 * Pose les filtres puis rend la vue Logs.
 * @param {{kind?:string, component?:string, node_name?:string, lockComp?:boolean, keepDomain?:boolean, keepFilters?:boolean}} preset
 */
function openLogs(preset = {}) {
  const node = preset.node_name || '';
  const comp = preset.component || '';
  logsScope = {
    kind: preset.kind || 'access',
    component: comp,
    node_name: node,
    // Core : component + nœud verrouillés. Admin : composant filtrable.
    lockComp: preset.lockComp === true || (!!node && !!comp),
  };
  logsFilters.kind = logsScope.kind;
  logsFilters.component = logsScope.component;
  logsFilters.node_name = logsScope.node_name;
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
  if (state.selectedCore) navigate('core-logs-access');
  else navigate('logs');
};

// Admin — tous les Cores / composants
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

// Core — scoped au nœud sélectionné
pages['core-logs-access'] = function() {
  openLogs({ kind: 'access', component: 'core', node_name: coreLogNodeName(), lockComp: true, keepFilters: hasActiveLogFilters() });
};
// Menu Observabilité Core → atterrit sur les logs d'accès
pages['core-observability'] = function() {
  navigate('core-logs-access');
};
// Menu Observabilité Admin → atterrit sur les logs d'accès
pages['admin-observability'] = function() {
  navigate('logs');
};
pages['core-logs-system'] = function() {
  logsFilters.ip = '';
  logsFilters.method = '';
  logsFilters.status = '';
  logsFilters.path = '';
  openLogs({ kind: 'system', component: 'core', node_name: coreLogNodeName(), lockComp: true, keepFilters: !!(logsFilters.domain || logsFilters.search || logsFilters.level) });
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
      ? t('logs.banner_access_core')
      : t('logs.banner_access_all');
  } else if (kind === 'system') {
    text = node
      ? t('logs.banner_sys_core')
      : t('logs.banner_sys_all');
  }
  if (node) {
    return `<div style="margin-bottom:12px;padding:8px 12px;background:color-mix(in srgb,var(--accent) 8%,transparent);border:1px solid color-mix(in srgb,var(--accent) 22%,transparent);border-radius:6px;font-size:12px;color:var(--text2);">
      ${t('logs.filtered_core')} <strong style="color:var(--text)">${esc(node)}</strong>${text ? ' — ' + esc(text) : ''}
    </div>`;
  }
  if (text) {
    return `<div style="margin-bottom:12px;padding:8px 12px;background:color-mix(in srgb,var(--accent) 8%,transparent);border:1px solid color-mix(in srgb,var(--accent) 22%,transparent);border-radius:6px;font-size:12px;color:var(--text2);">${esc(text)}</div>`;
  }
  return '';
}

function renderLogsPage() {
  if (logsSSE) { logsSSE.close(); logsSSE = null; }
  livePaused = false;
  liveRows = [];
  logsActiveTab = 'static';

  document.getElementById('topbar-actions').innerHTML = `
    <button class="btn btn-secondary btn-sm" onclick="exportLogs('json')">${t('logs.export_json')}</button>
    <button class="btn btn-secondary btn-sm" onclick="exportLogs('csv')">${t('logs.export_csv')}</button>`;

  const content = document.getElementById('content');
  content.innerHTML = `
    ${logsScopeBanner()}
    <div class="tabs">
      <div class="tab active" id="tab-static" onclick="switchLogsTab('static')">${t('logs.tab_static')}</div>
      <div class="tab" id="tab-live" onclick="switchLogsTab('live')">${t('logs.tab_live')}</div>
      <div class="tab" id="tab-logsettings" onclick="switchLogsTab('settings')">${t('logs.tab_settings')}</div>
    </div>
    <div id="logs-tab-content"></div>`;

  // Délégation : filtres cliquables + corrélation (évite les onclick cassés par les guillemets)
  if (!content.dataset.logsWired) {
    content.dataset.logsWired = '1';
    content.addEventListener('click', onLogsClick);
  }

  renderStaticLogs();
}

function onLogsClick(e) {
  const corr = e.target.closest('[data-log-corr]');
  if (corr && document.getElementById('content')?.contains(corr)) {
    e.preventDefault();
    showCorrelate(corr.getAttribute('data-log-corr') || '', corr.getAttribute('data-log-ts') || '');
    return;
  }
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
  loadStaticLogs(1);
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
  loadStaticLogs(1);
};

function syncLogFilterInputs() {
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v || ''; };
  set('lf-search', logsFilters.search);
  set('lf-level', logsFilters.level);
  set('lf-domain', logsFilters.domain);
  set('lf-ip', logsFilters.ip);
  set('lf-method', logsFilters.method);
  set('lf-status', logsFilters.status);
  set('lf-path', logsFilters.path);
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
  const node = logsScope.node_name || coreLogNodeName();
  if (!node && !state.selectedCore) {
    toast(t('logs.prism_need_core'), 'error');
    return;
  }
  window._prismProxyInit = opts.proxy || logsFilters.domain || '';
  window._prismIpInit = opts.ip || logsFilters.ip || '';
  window._prismPathInit = opts.path || logsFilters.path || '';
  if (state.selectedCore) {
    navigate('core-prism');
    return;
  }
  // Sélectionne le Core par node_name si possible
  const cores = window._coreNodes || [];
  const idx = cores.findIndex(c => c.node_name === node || c.display_name === node || c.id === node);
  if (idx >= 0) {
    selectCore(cores[idx], 'core-prism');
    return;
  }
  toast(t('logs.prism_need_core'), 'error');
}

function switchLogsTab(tab) {
  logsActiveTab = tab;
  document.getElementById('tab-static')?.classList.toggle('active', tab === 'static');
  document.getElementById('tab-live')?.classList.toggle('active', tab === 'live');
  document.getElementById('tab-logsettings')?.classList.toggle('active', tab === 'settings');
  if (logsSSE) { logsSSE.close(); logsSSE = null; }
  livePaused = false;
  liveRows = [];
  if (tab === 'static') renderStaticLogs();
  else if (tab === 'live') renderLiveLogs();
  else renderLogsSettings();
}

function componentFilterHTML(idPrefix) {
  if (logsScope.lockComp) {
    return `<input type="hidden" id="${idPrefix}comp" value="${esc(logsFilters.component)}">
      <span class="chip" style="font-size:11px">${esc(logsFilters.component || 'core')}</span>`;
  }
  return `<select id="${idPrefix}comp" class="input" onchange="${idPrefix === 'lf-live-' ? 'restartSSE()' : 'logsFilter()'}">
      <option value="">${t('logs.comp_ph')}</option>
      <option${logsFilters.component==='admin'?' selected':''}>admin</option>
      <option${logsFilters.component==='agent'?' selected':''}>agent</option>
      <option${logsFilters.component==='core'?' selected':''}>core</option>
    </select>`;
}

function renderStaticLogs() {
  const c = document.getElementById('logs-tab-content');
  const isSystem = isSystemLogs();
  const head = isSystem
    ? `<th>${t('logs.ts')}</th><th>${t('logs.level')}</th><th>${t('logs.component')}</th><th>${t('logs.node')}</th><th>${t('logs.context')}</th><th>${t('logs.message')}</th>`
    : `<th>${t('logs.ts')}</th><th>${t('logs.level')}</th><th>${t('logs.component')}</th><th>${t('logs.node')}</th><th>${t('logs.domain')}</th><th>${t('logs.method')}</th><th>${t('logs.path')}</th><th>${t('logs.status')}</th><th>${t('logs.ip')}</th><th>${t('logs.latency')}</th><th>${t('logs.msg')}</th><th></th>`;
  const cols = isSystem ? 6 : 12;
  c.innerHTML = `
    <div class="search-bar" style="gap:8px;margin-bottom:8px">
      <input id="lf-search" class="input search-input" placeholder="${esc(t('logs.search_ph'))}" value="${esc(logsFilters.search)}" oninput="logsFilter()">
      <select id="lf-level" class="input" onchange="logsFilter()">
        <option value="">${t('logs.level_ph')}</option>
        <option${logsFilters.level==='info'?' selected':''}>info</option>
        <option${logsFilters.level==='warn'?' selected':''}>warn</option>
        <option${logsFilters.level==='error'?' selected':''}>error</option>
        <option${logsFilters.level==='debug'?' selected':''}>debug</option>
      </select>
      <input type="hidden" id="lf-kind" value="${esc(logsFilters.kind)}">
      ${componentFilterHTML('lf-')}
      ${isSystem ? '' : `
      <input id="lf-domain" class="input" placeholder="${esc(t('logs.domain_ph'))}" value="${esc(logsFilters.domain)}" oninput="logsFilter()">
      <input id="lf-ip" class="input" placeholder="${esc(t('logs.ip_ph'))}" value="${esc(logsFilters.ip)}" oninput="logsFilter()">
      <input id="lf-path" class="input" placeholder="${esc(t('logs.path_ph'))}" value="${esc(logsFilters.path)}" oninput="logsFilter()">
      <select id="lf-method" class="input" onchange="logsFilter()">
        <option value="">${t('logs.method_ph')}</option>
        ${['GET','POST','PUT','DELETE','PATCH','HEAD'].map(m=>`<option${logsFilters.method===m?' selected':''}>${m}</option>`).join('')}
      </select>
      <input id="lf-status" class="input" placeholder="${esc(t('logs.status_ph'))}" value="${esc(logsFilters.status)}" oninput="logsFilter()">
      `}
    </div>
    <div id="logs-filter-chips" class="filter-chips" hidden></div>
    <p style="font-size:11px;color:var(--text3);margin:0 0 10px">${t('logs.filter_hint')}</p>
    <div class="card blueprint" style="padding:0;overflow:hidden">
      <div class="logs-desktop table-wrap">
        <table>
          <thead><tr>${head}</tr></thead>
          <tbody id="logs-tbody"><tr><td colspan="${cols}" class="empty"><p>${t('common.loading')}</p></td></tr></tbody>
        </table>
      </div>
      <div id="logs-list" class="logs-mobile logs-list"><div class="logs-empty">${t('common.loading')}</div></div>
      <div id="logs-pager" class="logs-pager"></div>
    </div>`;
  renderFilterChips();
  loadStaticLogs(1);
}

function logEntrySep() {
  return `<span class="log-entry-sep">·</span>`;
}

function renderAccessLogEntry(e) {
  const parts = [];
  if (e.domain) parts.push(`<span class="mono">${logCellFilter('domain', e.domain)}</span>`);
  if (e.path) parts.push(`<span class="log-entry-path">${logCellFilter('path', e.path)}</span>`);
  if (e.ip) parts.push(`<span class="mono">${logCellFilter('ip', e.ip)}</span>`);
  if (e.node_name) parts.push(`<span class="mono">${esc(e.node_name)}</span>`);
  if (e.latency_ms != null && e.latency_ms !== '') parts.push(`<span>${esc(String(e.latency_ms))}ms</span>`);
  return `<article class="log-entry">
    <div class="log-entry-top">
      <span class="log-entry-ts">${esc(fmtDate(e.ts))}</span>
      ${logLvlBadge(e.level)}
      <span class="chip" style="font-size:11px">${esc(e.component||'—')}</span>
      ${e.method ? `<b>${logCellFilter('method', e.method)}</b>` : ''}
      ${e.status ? logCellFilter('status', String(e.status), httpStatusBadge(e.status)) : ''}
      <span class="log-entry-actions">${corrIconBtn(e.domain, e.ts)}${prismIconBtn(e.domain, e.ip)}</span>
    </div>
    ${parts.length ? `<div class="log-entry-mid">${parts.join(logEntrySep())}</div>` : ''}
    ${e.message ? `<div class="log-entry-msg" title="${esc(e.message)}">${esc(e.message)}</div>` : ''}
  </article>`;
}

function renderSystemLogEntry(e) {
  const parts = [];
  if (e.component) parts.push(`<span class="chip" style="font-size:11px">${esc(e.component)}</span>`);
  if (e.node_name) parts.push(`<span class="mono">${esc(e.node_name)}</span>`);
  if (e.domain) parts.push(`<span class="mono">${logCellFilter('domain', e.domain)}</span>`);
  return `<article class="log-entry">
    <div class="log-entry-top">
      <span class="log-entry-ts">${esc(fmtDate(e.ts))}</span>
      ${logLvlBadge(e.level)}
      ${parts.join(logEntrySep())}
    </div>
    ${e.message ? `<div class="log-entry-msg" title="${esc(e.message)}">${esc(e.message)}</div>` : ''}
  </article>`;
}

function renderAccessLogRow(e) {
  return `<tr>
    <td class="mono" style="font-size:11px;white-space:nowrap">${esc(fmtDate(e.ts))}</td>
    <td>${logLvlBadge(e.level)}</td>
    <td><span class="chip" style="font-size:11px">${esc(e.component||'—')}</span></td>
    <td class="mono" style="font-size:11px">${esc(e.node_name||'—')}</td>
    <td class="mono" style="font-size:11px">${logCellFilter('domain', e.domain)}</td>
    <td><b>${logCellFilter('method', e.method)}</b></td>
    <td class="mono logs-cell-clip" style="font-size:11px;max-width:180px">${logCellFilter('path', e.path)}</td>
    <td>${e.status ? logCellFilter('status', String(e.status), httpStatusBadge(e.status)) : '<span style="color:var(--text3)">—</span>'}</td>
    <td class="mono" style="font-size:11px">${logCellFilter('ip', e.ip)}</td>
    <td style="color:var(--text2);font-size:11px">${e.latency_ms}ms</td>
    <td class="logs-cell-clip" style="color:var(--text2);font-size:11px;max-width:200px" title="${esc(e.message)}">${esc(e.message||'—')}</td>
    <td style="white-space:nowrap">${corrIconBtn(e.domain, e.ts)}${prismIconBtn(e.domain, e.ip)}</td>
  </tr>`;
}

function renderSystemLogRow(e) {
  return `<tr>
    <td class="mono" style="font-size:11px;white-space:nowrap">${esc(fmtDate(e.ts))}</td>
    <td>${logLvlBadge(e.level)}</td>
    <td><span class="chip" style="font-size:11px">${esc(e.component||'—')}</span></td>
    <td class="mono" style="font-size:11px">${esc(e.node_name||'—')}</td>
    <td class="mono" style="font-size:11px">${logCellFilter('domain', e.domain)}</td>
    <td class="logs-cell-clip" style="font-size:12px;max-width:480px" title="${esc(e.message)}">${esc(e.message||'—')}</td>
  </tr>`;
}

window.logsFilter = function() {
  logsFilters.search = document.getElementById('lf-search')?.value || '';
  logsFilters.level  = document.getElementById('lf-level')?.value || '';
  logsFilters.kind   = document.getElementById('lf-kind')?.value || logsScope.kind || 'access';
  // Ne pas laisser l'UI écraser le composant verrouillé (vue Core).
  if (!logsScope.lockComp) {
    logsFilters.component = document.getElementById('lf-comp')?.value || '';
  } else {
    logsFilters.component = logsScope.component;
  }
  logsFilters.node_name = logsScope.node_name;
  logsFilters.domain = document.getElementById('lf-domain')?.value || '';
  logsFilters.ip     = document.getElementById('lf-ip')?.value || '';
  logsFilters.path   = document.getElementById('lf-path')?.value || '';
  logsFilters.method = document.getElementById('lf-method')?.value || '';
  logsFilters.status = document.getElementById('lf-status')?.value || '';
  renderFilterChips();
  loadStaticLogs(1);
};

function corrIconBtn(domain, ts) {
  if (!domain || !ts) return '';
  const tsStr = typeof ts === 'string' ? ts : (ts?.toISOString?.() || String(ts));
  return `<button type="button" class="btn btn-ghost btn-icon btn-sm" data-log-corr="${esc(domain)}" data-log-ts="${esc(tsStr)}" title="${esc(t('logs.correlate'))}">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
  </button>`;
}

function prismIconBtn(domain, ip) {
  if (!domain && !ip) return '';
  return `<button type="button" class="btn btn-ghost btn-icon btn-sm" data-log-prism="${esc(domain||'')}" data-log-ip="${esc(ip||'')}" title="${esc(t('logs.prism'))}">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 20V10M12 20V4M6 20v-6"/></svg>
  </button>`;
}

async function loadStaticLogs(page) {
  const params = new URLSearchParams({ page, page_size: 50 });
  // Portée menu toujours appliquée.
  params.set('kind', logsScope.kind || logsFilters.kind || 'access');
  if (logsScope.node_name) params.set('node_name', logsScope.node_name);
  if (logsScope.lockComp && logsScope.component) params.set('component', logsScope.component);
  else if (logsFilters.component) params.set('component', logsFilters.component);
  for (const [k, v] of Object.entries(logsFilters)) {
    if (!v || k === 'kind' || k === 'node_name' || k === 'component') continue;
    params.set(k, v);
  }
  const isSystem = isSystemLogs();
  const cols = isSystem ? 6 : 12;
  try {
    const data = await api('GET', '/logs?' + params);
    const entries = data?.entries || [];
    const total = data?.total || 0;
    const tbody = document.getElementById('logs-tbody');
    const list = document.getElementById('logs-list');
    if (!entries.length) {
      if (tbody) tbody.innerHTML = `<tr><td colspan="${cols}" class="empty"><p>${t('logs.none')}</p></td></tr>`;
      if (list) list.innerHTML = `<div class="logs-empty">${t('logs.none')}</div>`;
    } else if (isSystem) {
      if (tbody) tbody.innerHTML = entries.map(renderSystemLogRow).join('');
      if (list) list.innerHTML = entries.map(renderSystemLogEntry).join('');
    } else {
      if (tbody) tbody.innerHTML = entries.map(renderAccessLogRow).join('');
      if (list) list.innerHTML = entries.map(renderAccessLogEntry).join('');
    }
    const pager = document.getElementById('logs-pager');
    if (pager) pager.innerHTML = `<span style="color:var(--text2);font-size:12px">${t('logs.entries', { n: total })}</span>
      ${page > 1 ? `<button class="btn btn-secondary btn-sm" onclick="loadStaticLogs(${page-1})">${t('logs.prev')}</button>` : ''}
      ${page * 50 < total ? `<button class="btn btn-secondary btn-sm" onclick="loadStaticLogs(${page+1})">${t('logs.next')}</button>` : ''}`;
  } catch(e) { toast(e.message, 'error'); }
}
window.loadStaticLogs = loadStaticLogs;

window.showCorrelate = async function(domain, ts) {
  const modal = document.createElement('div');
  modal.className = 'modal-overlay';
  modal.innerHTML = `<div class="modal" style="max-width:720px">
    <div class="modal-header"><h3>${t('logs.correlation', { domain: esc(domain) })}</h3><button class="modal-close" onclick="this.closest('.modal-overlay').remove()">✕</button></div>
    <div class="modal-body">
      <p style="font-size:12px;color:var(--text2);margin-bottom:12px">${t('logs.corr_window', { ts: esc(ts) })}</p>
      <div id="corr-result"><div class="spinner" style="margin:20px auto"></div></div>
    </div>
  </div>`;
  document.body.appendChild(modal);
  try {
    const params = new URLSearchParams({ domain, ts, window: 30 });
    const entries = await api('GET', '/logs/correlate?' + params) || [];
    const el = document.getElementById('corr-result');
    if (!el) return;
    el.innerHTML = entries.length ? `<div class="logs-list" style="border:1px solid var(--border);border-radius:var(--radius);overflow:hidden">
      ${entries.map(e => `<article class="log-entry">
        <div class="log-entry-top">
          <span class="log-entry-ts">${esc(fmtDate(e.ts))}</span>
          ${logLvlBadge(e.level)}
          <span class="chip" style="font-size:11px">${esc(e.component||'—')}</span>
          ${e.node_name ? `<span class="mono" style="font-size:11px">${esc(e.node_name)}</span>` : ''}
          ${e.domain ? `<span class="mono" style="font-size:11px">${esc(e.domain)}</span>` : ''}
        </div>
        ${e.message ? `<div class="log-entry-msg" title="${esc(e.message)}">${esc(e.message)}</div>` : ''}
      </article>`).join('')}
    </div>
    <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">
      <button type="button" class="btn btn-secondary btn-sm" id="corr-goto-system" data-corr-domain="${esc(domain)}">${t('logs.see_system')}</button>
    </div>` : '<p style="color:var(--text3);font-size:13px">' + t('logs.corr_empty') + '<br><span style="font-size:11px">' + t('logs.corr_hint') + '</span></p>';
    document.getElementById('corr-goto-system')?.addEventListener('click', (ev) => {
      const d = ev.currentTarget.getAttribute('data-corr-domain') || domain;
      modal.remove();
      logsFilters.domain = d;
      navigate('logs-system');
      // Réapplique le filtre domaine après le reset partiel de logs-system
      setTimeout(() => {
        logsFilters.domain = d;
        if (typeof logsFilter === 'function') logsFilter();
      }, 50);
    });
  } catch(err) {
    const el = document.getElementById('corr-result');
    if (el) el.innerHTML = `<p style="color:var(--red)">${esc(err.message)}</p>`;
  }
};

async function renderLogsSettings() {
  const c = document.getElementById('logs-tab-content');
  c.innerHTML = `<div class="spinner" style="margin:40px auto"></div>`;
  try {
    const s = await api('GET', '/logs/settings') || {};
    c.innerHTML = `
      <div class="card blueprint" style="max-width:480px">
        <h3 style="margin-bottom:16px">${t('logs.retention')}</h3>
        <div class="field">
          <label class="field-label">${t('logs.retention_days')}</label>
          <input id="log-retention-days" type="number" class="input" value="${s.retention_days ?? 30}" min="1" max="3650" style="width:120px">
          <p style="font-size:12px;color:var(--text2);margin-top:4px">${t('logs.retention_hint')}</p>
        </div>
        <button class="btn btn-primary" onclick="saveLogsSettings()">${t('common.save')}</button>
      </div>`;
  } catch(e) { c.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`; }
}

window.saveLogsSettings = async function() {
  const days = parseInt(document.getElementById('log-retention-days')?.value) || 30;
  try {
    await api('PUT', '/logs/settings', { retention_days: days });
    toast(t('logs.settings_saved'), 'success');
  } catch(e) { toast(e.message, 'error'); }
};

function renderLiveLogs() {
  const c = document.getElementById('logs-tab-content');
  const isSystem = isSystemLogs();
  c.innerHTML = `
    <div class="search-bar" style="gap:8px;margin-bottom:12px">
      <input id="lf-live-search" class="input search-input" placeholder="${esc(t('logs.filter_text'))}" oninput="restartSSE()">
      <select id="lf-live-level" class="input" onchange="restartSSE()">
        <option value="">${t('logs.level_ph')}</option>
        <option>info</option><option>warn</option><option>error</option><option>debug</option>
      </select>
      ${componentFilterHTML('lf-live-')}
      ${isSystem ? '' : `<input id="lf-live-domain" class="input" placeholder="${esc(t('logs.domain_ph'))}" value="${esc(logsFilters.domain)}" oninput="restartSSE()">`}
      <button id="btn-pause-live" class="btn btn-secondary btn-sm" onclick="toggleLivePause()">${t('logs.pause_btn')}</button>
      <button class="btn btn-secondary btn-sm" onclick="clearLiveStream()">🗑 ${t('logs.clear')}</button>
    </div>
    <div class="logs-live-bar">
      <div class="logs-live-dot"></div>
      <span id="live-status">${t('logs.connecting')}</span>
    </div>
    <div id="logs-stream" class="logs-stream"></div>`;
  startSSE();
}

window.restartSSE = function() {
  if (logsSSE) { logsSSE.close(); logsSSE = null; }
  startSSE();
};

function startSSE() {
  const params = new URLSearchParams();
  // Portée menu = source de vérité (kind / nœud / composant Core).
  params.set('kind', logsScope.kind || logsFilters.kind || 'access');
  if (logsScope.node_name) params.set('node_name', logsScope.node_name);

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

function appendLiveRow(e) {
  const stream = document.getElementById('logs-stream');
  if (!stream) return;
  const row = document.createElement('div');
  row.className = 'log-row';
  const ts = e.ts ? new Date(e.ts).toLocaleTimeString(typeof gpxBCP47==='function'?gpxBCP47():'en-US') : '—';
  const lvlClass = e.level === 'error' ? 'log-lvl-error' : e.level === 'warn' ? 'log-lvl-warn' : e.level === 'debug' ? 'log-lvl-debug' : 'log-lvl-info';
  const meta = [e.method, e.path, e.status ? e.status : ''].filter(Boolean).join(' ');
  const node = e.node_name ? ` · ${e.node_name}` : '';
  row.innerHTML = `<span class="log-ts">${esc(ts)}</span><span class="log-lvl ${lvlClass}">${esc(e.level||'info')}</span><span class="log-comp">${esc(e.component||'')}${esc(node)}</span><span class="log-msg">${esc(e.message||meta||'')}</span>${meta&&e.message?`<span class="log-meta">${esc(meta)}</span>`:''}`;
  stream.appendChild(row);
  while (stream.children.length > 500) stream.removeChild(stream.firstChild);
  stream.scrollTop = stream.scrollHeight;
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
  const stream = document.getElementById('logs-stream');
  if (stream) stream.innerHTML = '';
  liveRows = [];
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
  if (logsScope.node_name) params.set('node_name', logsScope.node_name);
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
