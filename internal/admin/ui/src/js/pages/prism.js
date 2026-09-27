// ── PAGE: Prism (Admin + Passerelle) ─────────────────────────────────────────
// Une seule vue ; les entrées de menu ne font que poser des filtres.
//   Admin (prism)      → toutes les passerelles / proxies / domaines
//   Passerelle  (edge-prism) → filtre node_name verrouillé sur la passerelle sélectionnée
// Extrait de pages-all.js — phase 3. Dépend de shared/fmt.js (fmtBytes).

// Contrôleur de la carte Leaflet (shared/geomap.js), détruit à chaque nouveau rendu de la page
let _prismGeoCtl = null;
let _prismAbortCtrl = null;
let _prismLiveTimer = null;

/** Portée posée par le menu (conservée pendant toute la visite de la page). */
let prismScope = { node_name: '', lockNode: false };

/** Présélection de filtres (proxy / IP / path / période) avant d'ouvrir la vue. */
let prismPreset = null;

function edgePrismNodeName() {
  const c = state.selectedEdge;
  return (c?.node_name || c?.display_name || c?.id || '').trim();
}

/**
 * Pose la portée + filtres puis rend Prism.
 * @param {{node_name?:string, lockNode?:boolean, proxy?:string, ip?:string, path?:string, from?:string, to?:string}} opts
 */
function openPrism(opts = {}) {
  const node = (opts.node_name || '').trim();
  prismScope = {
    node_name: node,
    lockNode: opts.lockNode === true || !!node,
  };
  prismPreset = {
    proxy: opts.proxy || window._prismProxyInit || '',
    ip: opts.ip || window._prismIpInit || '',
    path: opts.path || window._prismPathInit || '',
    from: opts.from || window._prismFromInit || '',
    to: opts.to || window._prismToInit || '',
  };
  window._prismFromInit = '';
  window._prismToInit = '';
  window._prismProxyInit = '';
  window._prismIpInit = '';
  window._prismPathInit = '';
  renderPrismPage();
}
window.openPrism = openPrism;

/** Raccourci Trafic : ouvre Prism pour un proxy (Admin global ou passerelle sélectionnée). */
window.openPrismForProxy = function(host, edgeId) {
  window._prismProxyInit = host || '';
  if (state.selectedEdge) {
    navigate('edge-prism');
    return;
  }
  // Admin : vue globale filtrée sur le proxy (pas besoin de sélectionner une passerelle)
  navigate('prism');
};

// Admin — vue d'ensemble (toutes les passerelles / proxies)
pages.prism = function() {
  openPrism({
    proxy: window._prismProxyInit || '',
    ip: window._prismIpInit || '',
    path: window._prismPathInit || '',
  });
};

// Passerelle — scoped au nœud sélectionné
pages['edge-prism'] = function() {
  openPrism({
    node_name: edgePrismNodeName(),
    lockNode: true,
    proxy: window._prismProxyInit || '',
    ip: window._prismIpInit || '',
    path: window._prismPathInit || '',
  });
};

function prismScopeBanner() {
  const node = prismScope.node_name;
  if (node) {
    const label = state.selectedEdge?.display_name || state.selectedEdge?.node_name || node;
    return `<div style="margin-bottom:12px;padding:8px 12px;background:color-mix(in srgb,var(--accent) 8%,transparent);border:1px solid color-mix(in srgb,var(--accent) 22%,transparent);border-radius:6px;font-size:12px;color:var(--text2);">
      ${t('prism.banner_edge', { name: esc(label) })}
    </div>`;
  }
  return `<div style="margin-bottom:12px;padding:8px 12px;background:color-mix(in srgb,var(--accent) 8%,transparent);border:1px solid color-mix(in srgb,var(--accent) 22%,transparent);border-radius:6px;font-size:12px;color:var(--text2);">
    ${t('prism.banner_all')}
  </div>`;
}

async function renderPrismPage() {
  if (_prismGeoCtl) { _prismGeoCtl.destroy(); _prismGeoCtl = null; }
  const initProxy = prismPreset?.proxy || '';
  const initIp = prismPreset?.ip || '';
  const initPath = prismPreset?.path || '';
  const initFrom = prismPreset?.from || '';
  const initTo = prismPreset?.to || '';
  prismPreset = null;

  // Alimente le sélecteur passerelle (vue Admin) si pas encore en cache
  if (!prismScope.lockNode && !(window._edgeNodes || []).length) {
    try {
      const nodes = await api('GET', '/nodes').catch(() => []);
      window._edgeNodes = (nodes || []).filter(n => n.role === 'edge');
    } catch { /* ignore */ }
  }



  const main = document.getElementById('content');
  main.innerHTML = `
    ${prismScopeBanner()}

    <div id="prism-root"><div class="spinner" style="margin:60px auto"></div></div>`;
  const prismRoot = document.getElementById('prism-root');

  let proxies = [], selProxy = initProxy, selIp = initIp, selPathFilter = initPath;
  let deployMarkers = []; // annotations de la courbe : changements de config de proxy sur la période
  let selFrom = '', selTo = '', pathSearch = '', pathOffset = 0;
  // Filtre passerelle libre en vue Admin (verrouillé si menu passerelle)
  let selNode = prismScope.node_name || '';
  const pathLimit = 20;
  let liveMode = false;
  let liveStartedAt = null; // Date précise du démarrage live
  let compareOpen = false;
  let bannedIPs = new Set();
  const LIVE_WINDOW_MS = 3600000;
  const LIVE_INTERVAL_MS = 5000;
  const lockNode = prismScope.lockNode;
  const icoRescan = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 1 1-2.64-6.36"/><polyline points="21 3 21 9 15 9"/></svg>`;
  const icoBan = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>`;

  if (_prismLiveTimer) { clearInterval(_prismLiveTimer); _prismLiveTimer = null; }

  // datetime-local exige l'heure locale (pas UTC via toISOString)
  function toLocalInput(d) {
    const pad = n => String(n).padStart(2, '0');
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate())
      + 'T' + pad(d.getHours()) + ':' + pad(d.getMinutes());
  }

  // C : fenêtre par défaut 1 h (au lieu de 24 h)
  const now = new Date();
  selTo   = initTo || toLocalInput(now);
  selFrom = initFrom || toLocalInput(new Date(now - 3600000));

  function liveFromDate() {
    if (!liveStartedAt) return null;
    const t = Date.now();
    if (t - liveStartedAt.getTime() > LIVE_WINDOW_MS) return new Date(t - LIVE_WINDOW_MS);
    return liveStartedAt;
  }

  function qp() {
    const p = new URLSearchParams();
    if (selNode) p.set('node_name', selNode);
    if (selProxy) p.set('proxy', selProxy);
    if (selIp) p.set('ip', selIp);
    if (selPathFilter) p.set('path', selPathFilter);
    if (liveMode && liveStartedAt) {
      const from = liveFromDate();
      if (from) p.set('from', from.toISOString());
      p.set('to', new Date().toISOString());
    } else {
      if (selFrom) {
        const t = new Date(selFrom);
        if (!isNaN(t)) p.set('from', t.toISOString());
      }
      if (selTo) {
        const t = new Date(selTo);
        if (!isNaN(t)) p.set('to', t.toISOString());
      }
    }
    return p.toString();
  }

  function prismFilterChipsHtml() {
    const chips = [];
    if (selNode && !lockNode) chips.push(['node', 'Edge', selNode]);
    if (selProxy) chips.push(['proxy', 'Proxy', selProxy]);
    if (selIp) chips.push(['ip', 'IP', selIp]);
    if (selPathFilter) chips.push(['path', t('pz.path'), selPathFilter]);
    if (!chips.length) return '<div id="prism-filter-chips"></div>';
    return `<div id="prism-filter-chips" class="filter-chips" style="margin-bottom:12px">${chips.map(([k,l,v]) =>
      `<span class="filter-chip">${esc(l)}: <b>${esc(v)}</b>
        <button type="button" class="filter-chip-x" data-prism="clear-filter" data-key="${esc(k)}" title="${esc(t('pz.remove'))}">✕</button></span>`
    ).join('')}
    <button type="button" class="btn btn-ghost btn-sm" style="font-size:11px" data-prism="clear-filter" data-key="*">${esc(t('pz.clear_all'))}</button>
    <button type="button" class="btn btn-secondary btn-sm" data-prism="to-logs" title="${esc(t('prism.to_logs'))}">→ Logs</button>
    </div>`;
  }

  // C — annule les requêtes en cours et retourne un signal pour le nouveau chargement
  function newLoad() {
    if (_prismAbortCtrl) _prismAbortCtrl.abort();
    _prismAbortCtrl = new AbortController();
    return _prismAbortCtrl.signal;
  }

  function apiP(method, url, signal) {
    return api(method, url, undefined, { signal }).catch(e => {
      if (e && e.name === 'AbortError') throw e;
      if (url.includes('/paths')) return { paths: [], has_more: false };
      if (url.includes('/kpis') || url.includes('/unique-ips')) return {};
      return [];
    });
  }

  const upd = (id, html) => { const el = document.getElementById(id); if (el) el.innerHTML = html; };
  const spin = `<div class="spinner" style="margin:24px auto"></div>`;

  function applyQuickRange(ms) {
    const t = new Date();
    selTo = toLocalInput(t);
    selFrom = toLocalInput(new Date(t - ms));
    pathOffset = 0;
    loadAll();
  }

  function doRefresh() {
    stopLiveMode();
    pathOffset = 0;
    loadAll();
  }

  function stopLiveMode() {
    liveMode = false;
    liveStartedAt = null;
    if (_prismLiveTimer) { clearInterval(_prismLiveTimer); _prismLiveTimer = null; }
    if (_liveMapTimer)  { clearInterval(_liveMapTimer);   _liveMapTimer = null; }
  }

  function syncFilterLiveState() {
    const liveBtn = document.getElementById('prism-live-btn');
    if (liveBtn) {
      liveBtn.classList.toggle('is-active', liveMode);
      liveBtn.setAttribute('aria-pressed', liveMode ? 'true' : 'false');
      liveBtn.title = liveMode ? t('prism.stop_live') : t('prism.live');
    }
    const cmpBtn = document.getElementById('prism-compare-btn');
    if (cmpBtn) {
      cmpBtn.classList.toggle('is-active', compareOpen);
      cmpBtn.setAttribute('aria-pressed', compareOpen ? 'true' : 'false');
      cmpBtn.title = compareOpen ? t('prism.hide_compare') : t('prism.compare');
    }
    const ind = document.getElementById('prism-live-indicator');
    if (ind) ind.style.display = liveMode ? 'inline-flex' : 'none';
    const fromEl = document.getElementById('prism-from');
    const toEl = document.getElementById('prism-to');
    if (fromEl) { fromEl.disabled = liveMode; if (liveMode) fromEl.value = selFrom; }
    if (toEl) { toEl.disabled = liveMode; if (liveMode) toEl.value = selTo; }
    document.querySelectorAll('[data-prism="quick"]').forEach(b => { b.disabled = liveMode; });
  }

  function emptyLiveKpis() {
    return {
      requests: 0, bandwidth: 0, error_rate: 0, unique_ips: 0,
      avg_latency_ms: 0, bot_share: 0,
      requests_delta: 0, bandwidth_delta: 0, error_rate_delta: 0,
    };
  }

  function resetLiveBody() {
    const body = document.getElementById('prism-body');
    if (!body) return;
    body.innerHTML = prismBodyHtml(emptyLiveKpis(), [], []);
  }

  function syncLiveRangeInputs() {
    const from = liveFromDate() || new Date();
    const to = new Date();
    selFrom = toLocalInput(from);
    selTo = toLocalInput(to);
    const fromEl = document.getElementById('prism-from');
    const toEl = document.getElementById('prism-to');
    if (fromEl) fromEl.value = selFrom;
    if (toEl) toEl.value = selTo;
  }

  function toggleLiveMode() {
    if (liveMode) {
      stopLiveMode();
      stopLiveMap();
      syncFilterLiveState();
      return;
    }
    liveMode = true;
    liveStartedAt = new Date();
    syncLiveRangeInputs();
    resetLiveBody();
    syncFilterLiveState();
    const tick = () => {
      if (!liveMode) return;
      syncLiveRangeInputs();
      pathOffset = 0;
      loadAll({ soft: true });
    };
    tick();
    _prismLiveTimer = setInterval(tick, LIVE_INTERVAL_MS);
    startLiveMap();
  }

  const PRISM_TABS = [
    ['paths', t('pz.tab_paths'), 'px-paths'], ['ips', 'IP', 'px-ips'], ['sources', t('pz.tab_sources'), 'px-sources'],
    ['countries', t('pz.tab_countries'), 'px-countries'],
  ];

  let activeTab = 'paths';

  function tabsHtml() {
    return `<div class="prism-tabs" id="prism-tabs">${PRISM_TABS.map(([k, l]) =>
      `<button type="button" class="${k === activeTab ? 'on' : ''}" data-prism="tab" data-tab="${k}">${l}</button>`).join('')}<button type="button" class="prism-tab-link" data-prism="to-bans" title="${esc(t('pz.bans_title'))}">${esc(t('pz.bans_link'))}</button></div>
      ${PRISM_TABS.map(([k, , id]) => `<div class="prism-pane" id="${id}" ${k === activeTab ? '' : 'hidden'}>${spin}</div>`).join('')}`;
  }

  function setTab(k) {
    activeTab = k;
    document.querySelectorAll('#prism-tabs button').forEach(b => b.classList.toggle('on', b.dataset.tab === k));
    PRISM_TABS.forEach(([key, , id]) => { const el = document.getElementById(id); if (el) el.hidden = key !== k; });
  }

  function prismBodyHtml(kpis, timeline, status) {
    return `
      <div id="px-kpis">${kpisHtml(kpis)}</div>
      <div class="prism-hero">
        <div class="prism-panel prism-mapcard" id="prism-geo-panel" style="min-height:80px">${spin}</div>
        <div class="prism-rail">
          <div class="prism-panel"><div class="prism-panel-title">${esc(t('obs.syn.anoms'))}</div><div id="px-anoms"><p class="prism-muted">${esc(t('pz.analyzing'))}</p></div></div>
          <div class="prism-panel"><div class="prism-panel-title">${esc(t('obs.syn.countries'))}</div><div id="px-topc"><p class="prism-muted">…</p></div></div>
        </div>
      </div>
      <div class="prism-two">
        <div class="prism-panel" id="px-timeline">${timelineHtml(timeline)}</div>
        <div class="prism-panel" id="px-status">${statusHtml(status)}</div>
      </div>
      <div class="prism-panel prism-tabcard">${tabsHtml()}</div>`;
  }

  // Courbe conservée pour les sparklines des indicateurs
  const anomData = { timeline: [] };

  function fetchSecondaryPanels(q, signal) {
    const guard = fn => e => { if (e && e.name === 'AbortError') return; fn(); };

    apiP('GET', '/prism/anomalies?' + q, signal)
      .then(list => upd('px-anoms', obsAnomaliesHtml(Array.isArray(list) ? list : [], { limit: 5 })))
      .catch(guard(() => upd('px-anoms', obsAnomaliesHtml([]))));

    apiP('GET', '/prism/unique-ips?' + q, signal)
      .then(d => {
        const el = document.getElementById('prism-kpi-unique-ips');
        if (el && d && d.unique_ips != null) el.textContent = fmtNum(d.unique_ips);
      })
      .catch(() => {});

    Promise.all([
      apiP('GET', '/prism/agents?' + q + '&limit=30', signal),
      apiP('GET', '/prism/referrers?' + q + '&limit=20', signal),
    ])
      .then(([a, r]) => upd('px-sources', sourcesHtml(a, r)))
      .catch(guard(() => upd('px-sources', sourcesHtml([], []))));

    apiP('GET', `/prism/paths?${q}&limit=${pathLimit}&offset=${pathOffset}&search=${encodeURIComponent(pathSearch)}`, signal)
      .then(d => upd('px-paths', pathsHtml(d)))
      .catch(guard(() => upd('px-paths', pathsHtml({paths:[],has_more:false}))));

    Promise.all([
      apiP('GET', '/prism/ips?' + q + '&limit=50', signal),
      apiP('GET', '/security/bans?active=true', signal).catch(() => []),
    ])
      .then(([ips, bans]) => {
        bannedIPs = new Set((bans || []).map(b => b.ip).filter(Boolean));
        upd('px-ips', ipsHtml(ips));
      })
      .catch(guard(() => upd('px-ips', ipsHtml([]))));


    apiP('GET', '/prism/geo?' + q, signal)
      .then(d => {
        // En Live la carte est conservée : on ne reconstruit le panneau que si son conteneur a été remplacé
        if (!_prismGeoCtl || document.getElementById('prism-geo-map') !== _prismGeoCtl.el) upd('prism-geo-panel', geoHtml(d));
        renderChoropleth(d);
      })
      .catch(guard(() => upd('prism-geo-panel', geoHtml([]))));

    apiP('GET', '/prism/geo/points?' + q + '&limit=1000', signal)
      .then(d => { _lastGeoPoints = Array.isArray(d) ? d : []; applyGeo(); })
      .catch(() => {});



  }

  async function loadAll(opts = {}) {
    const soft = opts.soft === true && !!document.getElementById('prism-body');
    const q = qp();
    const signal = newLoad();

    // Feedback immédiat sur la barre de filtres si elle existe déjà
    const fromEl = document.getElementById('prism-from');
    const toEl = document.getElementById('prism-to');
    if (fromEl) fromEl.value = selFrom;
    if (toEl) toEl.value = selTo;
    const refreshBtn = document.getElementById('prism-refresh-btn');
    if (refreshBtn && !soft) { refreshBtn.disabled = true; refreshBtn.textContent = '…'; }

    // Passe 1 : données critiques (above-fold) — toutes en parallèle
    let kpis, timeline, status, freshProxies, freshDeploys;
    try {
      [[kpis, timeline, status], freshProxies, freshDeploys] = await Promise.all([
        Promise.all([
          apiP('GET', '/prism/kpis?' + q, signal),
          apiP('GET', '/prism/timeline?' + q + '&bucket=' + (liveMode ? 'minute' : 'hour'), signal),
          apiP('GET', '/prism/status?' + q, signal),
        ]),
        apiP('GET', '/prism/proxies?' + (selNode ? 'node_name=' + encodeURIComponent(selNode) : ''), signal),
        apiP('GET', '/prism/deploys?' + q, signal),
      ]);
    } catch(e) {
      if (e && e.name === 'AbortError') return;
      if (refreshBtn) { refreshBtn.disabled = false; refreshBtn.textContent = t('obs.syn.refresh'); }
      toast('Prism : ' + (e.message || t('prism.load_err')), 'error');
      return;
    }

    if (freshProxies && Array.isArray(freshProxies)) proxies = freshProxies;
    if (Array.isArray(freshDeploys)) deployMarkers = freshDeploys;
    anomData.timeline = Array.isArray(timeline) ? timeline : [];

    const root = document.getElementById('prism-root');
    if (!root) return;

    if (soft) {
      const body = document.getElementById('prism-body');
      if (body) {
        upd('px-kpis', kpisHtml(kpis));
        upd('px-timeline', timelineHtml(timeline));
        upd('px-status', statusHtml(status));
      }
      const chips = document.getElementById('prism-filter-chips');
      if (chips) chips.outerHTML = prismFilterChipsHtml();
      syncFilterLiveState();
    } else {
      root.innerHTML = `
        ${filtersHtml()}
        ${prismFilterChipsHtml()}
        ${toolbarHtml()}
        <div id="prism-compare-panel" style="display:${compareOpen ? 'block' : 'none'};margin-bottom:16px"></div>
        <div id="prism-body">${prismBodyHtml(kpis, timeline, status)}</div>`;
      syncFilterLiveState();
      if (compareOpen) showCompare(true);
      root.insertAdjacentHTML('beforeend', '<aside class="prism-drawer" id="prism-drawer"></aside>');
      const btn = document.getElementById('prism-refresh-btn');
      if (btn) { btn.disabled = false; btn.textContent = t('obs.syn.refresh'); }
    }

    // D — Passe 2 : chaque panneau s'affiche dès que sa requête répond (indépendants)
    fetchSecondaryPanels(q, signal);
  }

  // B — pagination et recherche : rechargent uniquement le panneau paths
  async function loadPaths() {
    const signal = newLoad();
    const q = qp();
    upd('px-paths', spin);
    try {
      const d = await apiP('GET', `/prism/paths?${q}&limit=${pathLimit}&offset=${pathOffset}&search=${encodeURIComponent(pathSearch)}`, signal);
      upd('px-paths', pathsHtml(d));
    } catch(e) { if (e && e.name !== 'AbortError') upd('px-paths', pathsHtml({paths:[],has_more:false})); }
  }

  function filtersHtml() {
    const proxyOpts = proxies.map(p=>`<option value="${esc(p.domain)}" ${p.domain===selProxy?'selected':''}>${esc(p.domain)}</option>`).join('');
    const edges = (window._edgeNodes || []).filter(n => n.role === 'edge' || !n.role);
    const edgeOpts = edges.map(c => {
      const name = c.node_name || c.display_name || c.id || '';
      const label = c.display_name || c.node_name || c.id || '—';
      return `<option value="${esc(name)}" ${name===selNode?'selected':''}>${esc(label)}</option>`;
    }).join('');
    const edgeSelect = lockNode ? '' : `
        <select id="prism-node" class="form-input" style="max-width:180px" data-prism="node" title="${esc(t('prism.filter_edge'))}">
          <option value="">${esc(t('obs.syn.all_edges'))}</option>
          ${edgeOpts}
        </select>`;
    const icoCompare = `<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M8 3L4 7l4 4"/><path d="M4 7h16"/><path d="M16 21l4-4-4-4"/><path d="M20 17H4"/></svg>`;
    const icoLive = `<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>`;
    const quickBtns = [['15 min',900000],['1h',3600000],['6h',21600000],['24h',86400000],['7j',604800000]].map(([lbl,ms])=>
      `<button type="button" class="btn btn-secondary btn-sm" data-prism="quick" data-ms="${ms}"${liveMode ? ' disabled' : ''}>${lbl}</button>`
    ).join('');
    return `
      <div class="prism-filters">
        <div class="prism-fg">
          ${edgeSelect}
          <select id="prism-proxy" class="form-input" style="max-width:160px" data-prism="proxy">
            <option value="">${esc(t('pz.all_proxies'))}</option>
            ${proxyOpts}
          </select>
        </div>
        <div class="prism-fg-sep"></div>
        <div class="prism-fg">
          <span class="prism-fg-label">De</span>
          <input type="datetime-local" id="prism-from" class="form-input" style="max-width:168px" value="${esc(selFrom)}" data-prism="from"${liveMode ? ' disabled' : ''}>
          <span class="prism-fg-label">à</span>
          <input type="datetime-local" id="prism-to" class="form-input" style="max-width:168px" value="${esc(selTo)}" data-prism="to"${liveMode ? ' disabled' : ''}>
        </div>
        <div class="prism-fg-sep"></div>
        <div class="prism-fg" style="gap:4px">${quickBtns}</div>
        <div class="prism-fg prism-fg-end" style="gap:4px">
          <button type="button" class="btn btn-primary btn-sm" id="prism-refresh-btn" data-prism="refresh">${esc(t('obs.syn.refresh'))}</button>
          <span id="prism-live-indicator" class="prism-live-indicator" style="display:${liveMode ? 'inline-flex' : 'none'};margin:0 4px">
            <span class="logs-live-dot"></span>Live
          </span>
          <button type="button" class="btn btn-ghost btn-icon btn-sm${compareOpen ? ' is-active' : ''}" id="prism-compare-btn" data-prism="compare" title="${compareOpen ? t('prism.hide_compare') : t('prism.compare')}" aria-pressed="${compareOpen ? 'true' : 'false'}">${icoCompare}</button>
          <button type="button" class="btn btn-ghost btn-icon btn-sm${liveMode ? ' is-active' : ''}" id="prism-live-btn" data-prism="live" title="${liveMode ? t('prism.stop_live') : t('prism.live')}" aria-pressed="${liveMode ? 'true' : 'false'}">${icoLive}</button>
          <div class="prism-fg-sep" style="height:18px;align-self:auto;margin:0 4px"></div>
          <button type="button" class="btn btn-ghost btn-sm" style="font-size:11px;color:var(--text3)" data-prism="export" data-fmt="csv">CSV</button>
          <button type="button" class="btn btn-ghost btn-sm" style="font-size:11px;color:var(--text3)" data-prism="export" data-fmt="json">JSON</button>
        </div>
      </div>`;
  }

  function toolbarHtml() {
    return '';
  }

  function kpisHtml(k) { return obsKpisHtml(k, anomData.timeline); }
  function timelineHtml(pts) { return obsTimelineHtml(pts, { live: liveMode, bucketUnit: liveMode ? 'minute' : 'hour', deploys: deployMarkers }); }
  function statusHtml(groups) { return obsStatusHtml(groups); }

  function agentsHtml(agents) {
    if (!agents||agents.length===0) return `<div class="prism-panel-title">${t('prism.components')}</div><p style="color:var(--text3);font-size:13px">${t('prism.no_data')}</p>`;
    const maxR = Math.max(...agents.map(a=>a.requests),1);
    return `
      <div class="prism-panel-title">${esc(t('pz.components'))}</div>
      <table class="prism-table">
        <thead><tr><th>${esc(t('pz.component'))}</th><th>${esc(t('prism.req_short'))}</th><th>${esc(t('prism.share'))}</th></tr></thead>
        <tbody>${agents.slice(0,15).map(a=>`
          <tr>
            <td>${esc(a.name)} ${a.is_bot?'<span class="prism-bot-badge">BOT</span>':''}</td>
            <td>${fmtNum(a.requests)}</td>
            <td><span class="prism-bar-bg"><span class="prism-bar-fill" style="width:${(a.requests/maxR*100).toFixed(1)}%"></span></span> <span style="font-size:11px;color:var(--text3)">${a.pct.toFixed(1)}%</span></td>
          </tr>`).join('')}</tbody>
      </table>`;
  }

  function pathsHtml(data) {
    const list = data?.paths || [], hasMore = !!data?.has_more;
    const maxR = Math.max(...list.map(p=>p.requests),1);
    const page = Math.floor(pathOffset/pathLimit)+1;
    return `
      <div class="prism-panel-title">${esc(t('pz.top_paths'))}</div>
      <div class="prism-search">
        <input type="text" id="prism-path-search" class="form-input" placeholder="${esc(t('prism.filter_ph'))}" value="${esc(pathSearch)}" style="flex:1" data-prism="path-search-input">
        <button type="button" class="btn btn-secondary btn-sm" data-prism="path-search">${esc(t('pz.search'))}</button>
      </div>
      <table class="prism-table">
        <thead><tr><th>${esc(t('pz.path'))}</th><th>${esc(t('prism.req_short'))}</th><th>${esc(t('pz.err_short'))}</th><th>${esc(t('prism.lat_avg'))}</th><th>${esc(t('pz.volume'))}</th><th></th></tr></thead>
        <tbody>${list.map(p=>`
          <tr>
            <td style="font-family:monospace;font-size:11px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(p.path)}">
              <button type="button" class="log-filter-link${selPathFilter===p.path?' is-active':''}" data-prism="filter-path" data-path="${esc(p.path)}">${esc(p.path)}</button>
            </td>
            <td>${fmtNum(p.requests)}</td>
            <td style="color:${p.errors>0?'var(--red)':'var(--text3)'}">${fmtNum(p.errors)}</td>
            <td>${p.avg_lat_ms.toFixed(0)} ms</td>
            <td><span class="prism-bar-bg"><span class="prism-bar-fill" style="width:${(p.requests/maxR*100).toFixed(1)}%"></span></span></td>
            <td><button type="button" class="btn btn-ghost btn-icon btn-sm" data-prism="to-logs" data-path="${esc(p.path)}" title="${esc(t('prism.filter_logs'))}">
              <svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M7 8h10M7 12h10M7 16h6"/></svg>
            </button></td>
          </tr>`).join('')}</tbody>
      </table>
      <div class="prism-pagination">
        <button type="button" class="btn btn-secondary btn-sm" data-prism="path-prev" ${pathOffset===0?'disabled':''}>${esc(t('pz.prev'))}</button>
        <span style="color:var(--text3)">${t('pz.page', { n: page })}</span>
        <button type="button" class="btn btn-secondary btn-sm" data-prism="path-next" ${hasMore?'':'disabled'}>${esc(t('pz.next'))}</button>
      </div>`;
  }

  function ipsHtml(ips) {
    if (!ips||ips.length===0) return `<div class="prism-panel-title">${t('prism.top_ips')}</div><p style="color:var(--text3);font-size:13px">${t('prism.no_data')}</p>`;
    const maxR = Math.max(...ips.map(i=>i.requests),1);
    return `
      <div class="prism-panel-title">${t('prism.top_ips')}</div>
      <table class="prism-table">
        <thead><tr><th>IP</th><th>Req.</th><th>Err.</th><th>Volume</th><th></th></tr></thead>
        <tbody>${ips.slice(0,20).map(i=>{
          const banned = bannedIPs.has(i.ip);
          return `
          <tr>
            <td style="font-family:monospace">
              <button type="button" class="log-filter-link${selIp===i.ip?' is-active':''}" data-prism="filter-ip" data-ip="${esc(i.ip)}">${esc(i.ip)}</button>
              ${banned ? `<span class="tag tag-red" style="margin-left:6px;font-size:9px;padding:1px 6px;vertical-align:middle">${esc(t('prism.banned'))}</span>` : ''}
            </td>
            <td>${fmtNum(i.requests)}</td>
            <td style="color:${i.errors>0?'var(--red)':'var(--text3)'}">${fmtNum(i.errors)}</td>
            <td><span class="prism-bar-bg"><span class="prism-bar-fill ${i.errors/Math.max(i.requests,1)>.5?'err':''}" style="width:${(i.requests/maxR*100).toFixed(1)}%"></span></span></td>
            <td style="white-space:nowrap">
              <button type="button" class="btn btn-ghost btn-icon btn-sm" data-prism="to-logs" data-ip="${esc(i.ip)}" title="${esc(t('prism.filter_logs'))}">
                <svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M7 8h10M7 12h10M7 16h6"/></svg>
              </button>
              <button type="button" class="btn btn-ghost btn-icon btn-sm" data-prism="rescan" data-ip="${esc(i.ip)}" title="${esc(t('pz.rescan_ip'))}">${icoRescan}</button>
              ${banned
                ? `<span class="btn btn-ghost btn-icon btn-sm" title="${esc(t('prism.banned'))}" style="color:var(--red);opacity:.9;cursor:default;pointer-events:none">${icoBan}</span>`
                : `<button type="button" class="btn btn-ghost btn-icon btn-sm" data-prism="ban" data-ip="${esc(i.ip)}" title="${esc(t('prism.ban'))}">${icoBan}</button>`}
            </td>
          </tr>`;
        }).join('')}</tbody>
      </table>`;
  }

  // Live map : état
  let _liveMapLastTs = null;       // dernier timestamp ISO poolé
  let _liveMapTimer  = null;       // setInterval live map
  let _liveMapFeed   = [];         // buffer des événements récents (50 max)
  const LIVE_MAP_INTERVAL_MS = 4000;
  const LIVE_MAP_FEED_MAX = 50;

  // Mode actif de la choroplèthe : 'requests' | 'error_rate' | 'banned_ips'
  let geoViewMode = 'requests';
  let geoStyle = 'zones';
  let selCountry = '';


  function geoHtml(geo) {
    const liveFeedHtml = liveMode ? `
      <div id="prism-live-feed-wrap" style="border-top:1px solid var(--border);margin-top:10px;padding-top:8px">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
          <span class="logs-live-dot"></span>
          <span style="font-size:11px;font-weight:600;color:var(--text2)">${esc(t('pz.live_conns'))}</span>
        </div>
        <div id="prism-live-feed" style="max-height:200px;overflow-y:auto;font-size:11px">
          <div style="color:var(--text3);font-size:12px;padding:8px 0">${esc(t('prism.wait_traffic'))}</div>
        </div>
      </div>` : '';
    return `
      <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:8px;flex-wrap:wrap">
        <span class="prism-panel-title" style="margin:0">${esc(t('pz.by_country'))}${liveMode ? ' <span class="logs-live-dot" style="margin-left:6px"></span>' : ''}</span>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <div class="btn-group" role="group" aria-label="Vue">
            <button type="button" class="btn btn-xs geo-mode-btn ${geoViewMode==='requests'?'active':''}" data-prism="geo-mode" data-mode="requests">${esc(t('prism.requests'))}</button>
            <button type="button" class="btn btn-xs geo-mode-btn ${geoViewMode==='error_rate'?'active':''}" data-prism="geo-mode" data-mode="error_rate">${esc(t('pz.err_rate_short'))}</button>
            <button type="button" class="btn btn-xs geo-mode-btn ${geoViewMode==='banned_ips'?'active':''}" data-prism="geo-mode" data-mode="banned_ips">${esc(t('pz.banned_ips'))}</button>
          </div>
          <div class="btn-group" role="group" aria-label="Style">
            <button type="button" class="btn btn-xs geo-style-btn ${geoStyle==='zones'?'active':''}" data-prism="geo-style" data-style="zones">${esc(t('sy.atk_zones'))}</button>
            <button type="button" class="btn btn-xs geo-style-btn ${geoStyle==='cities'?'active':''}" data-prism="geo-style" data-style="cities">${esc(t('sy.atk_cities'))}</button>
            <button type="button" class="btn btn-xs geo-style-btn ${geoStyle==='regions'?'active':''}" data-prism="geo-style" data-style="regions">${esc(t('sy.atk_regions'))}</button>
          </div>
        </div>
      </div>
      <div id="prism-geo-map" class="prism-mapbox gm-box" style="min-height:200px"><div class="spinner" style="margin:80px auto"></div></div>
      ${liveFeedHtml}`;
  }

  let _lastGeoData = null;
  let _lastGeoPoints = [];
  let _geoBuilding = false;

  // Pousse les données courantes vers la carte Leaflet et les panneaux liés (Top pays, onglet Pays)
  function applyGeo() {
    if (!_lastGeoData) return;
    document.querySelectorAll('.geo-mode-btn').forEach(b => b.classList.toggle('active', b.dataset.mode === geoViewMode));
    document.querySelectorAll('.geo-style-btn').forEach(b => b.classList.toggle('active', b.dataset.style === geoStyle));
    if (_prismGeoCtl) _prismGeoCtl.update({ countries: _lastGeoData, points: _lastGeoPoints, mode: geoViewMode, style: geoStyle, selected: selCountry });
    renderGeoSide(_lastGeoData);
  }

  function renderGeoSide(geo) {
    const mode = geoViewMode;
    const [r, g, b] = GEO_PALETTES[mode] || GEO_PALETTES.requests;
    const maxVal = Math.max(...geo.map(e => _geoValue(e, mode)), 0);

    const topEl = document.getElementById('px-topc');
    if (topEl) {
      const flagOf = cc => (!cc || cc.length !== 2 || cc === 'XX' || cc === 'LO') ? '🌐' : String.fromCodePoint(0x1F1E6 + cc.charCodeAt(0) - 65, 0x1F1E6 + cc.charCodeAt(1) - 65);
      const top = geoSortLocalLast(geo.filter(e => _geoValue(e, mode) > 0), e => _geoValue(e, mode)).slice(0, 8);
      topEl.innerHTML = top.length ? top.map((e, i) => {
        const v = _geoValue(e, mode);
        const label = mode === 'error_rate' ? v.toFixed(1) + '%' : fmtNum(v);
        const sep = isLocalGeo(e.country_code) && i > 0 && !isLocalGeo(top[i - 1].country_code)
          ? `<div class="prism-toprow-sep">${esc(t('pz.local_sep'))}</div>` : '';
        return `${sep}<button type="button" class="prism-toprow${e.country_code === selCountry ? ' sel' : ''}" data-prism="country" data-cc="${esc(e.country_code)}">
          <span class="prism-toprow-flag">${flagOf(e.country_code)}</span>
          <span class="prism-toprow-main"><span class="prism-toprow-head"><span>${esc(e.country_name)}</span><b>${label}</b></span>
          <span class="prism-bar-bg"><span class="prism-bar-fill" style="width:${(v / maxVal * 100).toFixed(1)}%;background:rgb(${r},${g},${b})"></span></span></span>
        </button>`;
      }).join('') : `<p class="prism-muted">${t('prism.no_data')}</p>`;
    }

    const flag = cc => {
      if (!cc || cc.length !== 2 || cc === 'XX' || cc === 'LO') return '';
      return String.fromCodePoint(0x1F1E6+cc.charCodeAt(0)-65, 0x1F1E6+cc.charCodeAt(1)-65) + ' ';
    };
    const maxR = Math.max(...geo.map(g => g.requests), 1);
    const pane = document.getElementById('px-countries');
    if (!pane) return;
    const sorted = geoSortLocalLast(geo, e => e.requests || 0).slice(0, 15);
    pane.innerHTML = `<div class="prism-panel-title">${esc(t('pz.by_country'))}</div>
      <div class="geo-stats-table" style="overflow-x:auto;border-top:1px solid var(--border)">
      <table class="prism-table">
        <thead><tr>
          <th>${esc(t('pz.tab_countries'))}</th><th>${esc(t('prism.req_short'))}</th><th>${esc(t('prism.share'))}</th>
          <th>${esc(t('prism.errors'))}</th><th>${esc(t('pz.err_rate_abbr'))}</th><th>${esc(t('pz.banned_ips'))}</th>
        </tr></thead>
        <tbody>${sorted.map((entry, i) => {
          const errRateHigh = (entry.error_rate || 0) >= 5;
          const hasBans = (entry.banned_ips || 0) > 0;
          const sep = isLocalGeo(entry.country_code) && i > 0 && !isLocalGeo(sorted[i - 1].country_code)
            ? `<tr class="prism-geo-sep-row"><td colspan="6">${esc(t('pz.local_sep'))}</td></tr>` : '';
          return `${sep}<tr>
            <td><span style="font-size:15px">${flag(entry.country_code)}</span><span style="color:var(--text3);font-size:10px;margin-right:4px">${esc(entry.country_code)}</span>${esc(entry.country_name)}</td>
            <td>${fmtNum(entry.requests)}</td>
            <td><span class="prism-bar-bg"><span class="prism-bar-fill" style="width:${(entry.requests/maxR*100).toFixed(1)}%"></span></span> <span style="font-size:11px;color:var(--text3)">${(entry.pct||0).toFixed(1)}%</span></td>
            <td>${fmtNum(entry.errors || 0)}</td>
            <td style="color:${errRateHigh?'var(--red)':'inherit'};font-weight:${errRateHigh?'600':'400'}">${(entry.error_rate||0).toFixed(1)}%</td>
            <td style="color:${hasBans?'var(--yellow,#d97706)':'inherit'};font-weight:${hasBans?'600':'400'}">${fmtNum(entry.banned_ips || 0)}</td>
          </tr>`;
        }).join('')}
        </tbody>
      </table></div>`;
  }

  // Panneau détail pays (données du /prism/geo déjà chargées)
  function openCountry(cc) {
    const e = (_lastGeoData || []).find(g => g.country_code === cc);
    const dr = document.getElementById('prism-drawer');
    if (!e || !dr) return;
    selCountry = cc;
    applyGeo();
    const flagOf = (!cc || cc.length !== 2 || cc === 'XX' || cc === 'LO') ? '🌐' : String.fromCodePoint(0x1F1E6 + cc.charCodeAt(0) - 65, 0x1F1E6 + cc.charCodeAt(1) - 65);
    const stat = (l, v, warn) => `<div class="prism-dstat"><span>${l}</span><b${warn ? ' style="color:var(--red)"' : ''}>${v}</b></div>`;
    dr.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <span class="prism-panel-title" style="margin:0">${esc(t('pz.country_detail'))}</span>
        <button type="button" class="btn btn-ghost btn-sm" data-prism="close-drawer">✕</button>
      </div>
      <div style="font-size:36px;line-height:1">${flagOf}</div>
      <div style="font-size:22px;font-weight:700;letter-spacing:-.02em;margin:4px 0">${esc(e.country_name)} <span style="font-size:12px;color:var(--text3);font-weight:500">${esc(cc)}</span></div>
      <div style="color:var(--text3);margin-bottom:14px">${t('pz.req_share', { n: fmtNum(e.requests), pct: (e.pct || 0).toFixed(1) })}</div>
      <div class="prism-dstats">
        ${stat(t('prism.errors'), fmtNum(e.errors || 0))}
        ${stat(t('prism.error_rate'), (e.error_rate || 0).toFixed(1) + '%', (e.error_rate || 0) >= 10)}
        ${stat(t('pz.banned_ips'), fmtNum(e.banned_ips || 0), (e.banned_ips || 0) > 0)}
      </div>`;
    dr.classList.add('open');
  }

  // Ré-analyse une IP à la demande (bans actifs, historique, décisions Sentinel/CrowdSec, activité)
  async function rescanIP(ip, btn) {
    const dr = document.getElementById('prism-drawer');
    if (!ip || !dr) return;
    btn?.classList.add('is-spinning');
    dr.classList.add('open');
    dr.innerHTML = `<div class="spinner" style="margin:40px auto"></div>`;
    try {
      const d = await api('GET', '/prism/ip-scan?' + qp().replace(/(^|&)ip=[^&]*/, '') + '&ip=' + encodeURIComponent(ip));
      const verdict = { banned: [t('pz.v_banned'), 'var(--red)'], suspect: [t('pz.v_suspect'), '#f59e0b'], clean: [t('pz.v_clean'), 'var(--green)'] }[d.verdict] || ['—', 'var(--text3)'];
      const when = s => s ? s.replace('T', ' ').slice(0, 16) : '—';
      dr.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
          <span class="prism-panel-title" style="margin:0">${esc(t('pz.ip_scan'))}</span>
          <button type="button" class="btn btn-ghost btn-sm" data-prism="close-drawer">✕</button>
        </div>
        <div class="mono" style="font-size:18px;font-weight:700">${esc(d.ip)}</div>
        <div style="margin:6px 0 14px"><span class="prism-verdict" style="--v:${verdict[1]}">${verdict[0]}</span>
          <span style="color:var(--text3);font-size:11px;margin-left:8px">${esc(t('pz.scanned_at', { when: when(d.scanned_at) }))}</span></div>
        <div class="prism-dstats">
          <div class="prism-dstat"><span>${esc(t('pz.requests_period'))}</span><b>${fmtNum(d.requests)}</b></div>
          <div class="prism-dstat"><span>${esc(t('prism.errors'))}</span><b${d.errors ? ' style="color:var(--red)"' : ''}>${fmtNum(d.errors)}</b></div>
          <div class="prism-dstat"><span>${esc(t('pz.past_bans'))}</span><b>${d.ban_history}</b></div>
          <div class="prism-dstat"><span>${esc(t('pz.last_activity'))}</span><b style="font-size:13px">${esc(when(d.last_seen))}</b></div>
        </div>
        <div class="prism-panel-title" style="margin:16px 0 6px">${esc(t('pz.active_bans'))}</div>
        ${(d.bans || []).length ? d.bans.map(b => `<div class="prism-bansrc">
            <div class="prism-bansrc-head"><span class="prism-src-badge${b.sentinel ? ' sentinel' : ''}">${esc(b.source_label)}</span>${b.sentinel ? `<span class="prism-src-origin">${esc(t('pz.source_sentinel'))}</span>` : ''}</div>
            <div class="prism-bantech"><span>${esc(b.technique)}</span><span style="color:var(--text3)">${esc(when(b.since))}</span></div>
          </div>`).join('') : `<p class="prism-muted">${t('pz.no_active_ban')}</p>`}
        <div class="prism-panel-title" style="margin:16px 0 6px">${esc(t('pz.threat_decisions'))}</div>
        ${(d.threats || []).length ? d.threats.map(x => `<div class="prism-bantech"><span>${esc(x.scenario)} <span style="color:var(--text3)">· ${esc(x.origin)}</span></span><b>×${x.occurrences}</b></div>`).join('') : `<p class="prism-muted">${t('pz.no_decision')}</p>`}
        <div class="prism-panel-title" style="margin:16px 0 6px">${esc(t('pz.top_targeted'))}</div>
        ${(d.top_paths || []).length ? d.top_paths.map(x => `<div class="prism-bantech"><span class="mono" style="overflow:hidden;text-overflow:ellipsis" title="${esc(x.path)}">${esc(x.path)}</span><b>${x.requests}${x.errors ? ` <span style="color:var(--red);font-weight:500">(${x.errors} err.)</span>` : ''}</b></div>`).join('') : `<p class="prism-muted">${t('pz.no_request')}</p>`}
        <div style="display:flex;gap:8px;margin-top:18px;flex-wrap:wrap">
          <button type="button" class="btn btn-secondary btn-sm" data-prism="rescan" data-ip="${esc(d.ip)}">${icoRescan} ${esc(t('pz.rescan'))}</button>
          <button type="button" class="btn btn-secondary btn-sm" data-prism="to-logs" data-ip="${esc(d.ip)}">→ Logs</button>
          ${d.verdict !== 'banned' ? `<button type="button" class="btn btn-ghost btn-sm" style="color:var(--red)" data-prism="ban" data-ip="${esc(d.ip)}">${esc(t('pz.ban_btn'))}</button>` : ''}
        </div>`;
    } catch (e) {
      dr.innerHTML = `<p style="color:var(--red)">${esc(t('prism.error'))}: ${esc(e.message || '')}</p>`;
    } finally {
      btn?.classList.remove('is-spinning');
    }
  }

  function closeCountry() {
    selCountry = '';
    document.getElementById('prism-drawer')?.classList.remove('open');
    applyGeo();
  }

  // ── Live map ────────────────────────────────────────────────────────────

  function startLiveMap() {
    _liveMapLastTs = new Date().toISOString();
    _liveMapFeed = [];
    if (_liveMapTimer) clearInterval(_liveMapTimer);
    _liveMapTimer = setInterval(tickLiveMap, LIVE_MAP_INTERVAL_MS);
    tickLiveMap();
  }

  function stopLiveMap() {
    if (_liveMapTimer) { clearInterval(_liveMapTimer); _liveMapTimer = null; }
    _liveMapFeed = [];
    _liveMapLastTs = null;
    if (_prismGeoCtl) _prismGeoCtl.clearLive();
    renderLiveFeed([]);
  }

  async function tickLiveMap() {
    if (!liveMode) return;
    const since = _liveMapLastTs || new Date(Date.now() - LIVE_MAP_INTERVAL_MS * 2).toISOString();
    const q = new URLSearchParams({ since, limit: '100' });
    if (selProxy)   q.set('proxy', selProxy);
    if (selNode)    q.set('node_name', selNode);
    try {
      const events = await api('GET', '/prism/live-ips?' + q.toString()).catch(() => []);
      if (!Array.isArray(events) || !events.length) return;
      // Ne conserver que les events plus récents que since (tri desc, on prend le plus récent comme prochain since)
      _liveMapLastTs = events[0].ts || new Date().toISOString();
      // Filtrer les doublons déjà dans le feed
      const newEvts = events.filter(e => !_liveMapFeed.some(f => f.ip === e.ip && f.ts === e.ts));
      if (!newEvts.length) return;
      _liveMapFeed = [...newEvts, ..._liveMapFeed].slice(0, LIVE_MAP_FEED_MAX);
      renderLiveFeed(_liveMapFeed);
      placeLiveDots(newEvts);
    } catch { /* ignore */ }
  }

  function placeLiveDots(events) {
    if (_prismGeoCtl) _prismGeoCtl.pulse(events);
  }

  function renderLiveFeed(events) {
    const container = document.getElementById('prism-live-feed');
    if (!container) return;
    if (!events.length) {
      container.innerHTML = '<div style="color:var(--text3);font-size:12px;padding:8px 0">En attente de trafic…</div>';
      return;
    }
    const flag = cc => {
      if (!cc || cc.length !== 2 || cc === 'XX' || cc === '?') return '🌐';
      try { return String.fromCodePoint(0x1F1E6+cc.charCodeAt(0)-65, 0x1F1E6+cc.charCodeAt(1)-65); } catch { return '🌐'; }
    };
    const kindColor = k => k === 'banned' ? 'var(--red)' : k === 'error' ? 'var(--yellow)' : 'var(--accent)';
    const kindLabel = k => k === 'banned' ? 'BAN' : k === 'error' ? 'ERR' : 'OK';
    container.innerHTML = events.slice(0, 20).map(ev => {
      const ts = ev.ts ? ev.ts.replace('T',' ').slice(11,19) : '';
      return `<div class="live-feed-row">
        <span class="live-feed-kind" style="color:${kindColor(ev.kind)}">${kindLabel(ev.kind)}</span>
        <span class="live-feed-flag">${flag(ev.country_code)}</span>
        <code class="live-feed-ip">${esc(ev.ip)}</code>
        <span class="live-feed-domain" title="${esc(ev.domain)}">${esc(ev.domain)}</span>
        <span class="live-feed-ts">${ts}</span>
      </div>`;
    }).join('');
  }

  // ── Fin Live map ─────────────────────────────────────────────────────────

  async function renderChoropleth(geo) {
    _lastGeoData = geo;
    const container = document.getElementById('prism-geo-map');
    if (!container) return;

    if (!geo || geo.length === 0) {
      if (_prismGeoCtl) { _prismGeoCtl.destroy(); _prismGeoCtl = null; }
      container.innerHTML = `<p style="color:var(--text3);font-size:13px;padding:16px">${t('prism.wait_geo')}<br><span style="font-size:11px">${t('prism.geo_bg')}</span></p>`;
      upd('px-topc', `<p class="prism-muted">${t('prism.no_data')}</p>`);
      upd('px-countries', `<p class="prism-muted">${t('prism.no_data')}</p>`);
      return;
    }

    if (!_prismGeoCtl || _prismGeoCtl.el !== container) {
      if (_geoBuilding) return; // applyGeo() sera rejoué à la fin de la construction avec les dernières données
      _geoBuilding = true;
      if (_prismGeoCtl) _prismGeoCtl.destroy();
      _prismGeoCtl = null;
      container.innerHTML = '';
      try {
        const ctl = await gpxGeoMap(container, { onCountry: cc => openCountry(cc), onPoint: pt => openPoint(pt) });
        ctl.el = container;
        _prismGeoCtl = ctl;
      } catch {
        container.innerHTML = `<p style="color:var(--text3);font-size:13px;padding:16px">${t('pz.map_unavailable')}</p>`;
        return;
      } finally {
        _geoBuilding = false;
      }
    }
    applyGeo();
  }

  // Détail d'une ville de la carte (mode « Villes »)
  function openPoint(pt) {
    const dr = document.getElementById('prism-drawer');
    if (!dr) return;
    const place = [pt.city, pt.region].filter(Boolean).join(', ') || pt.country_name;
    const stat = (l, v, warn) => `<div class="prism-dstat"><span>${l}</span><b${warn ? ' style="color:var(--red)"' : ''}>${v}</b></div>`;
    dr.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <span class="prism-panel-title" style="margin:0">${esc(t('pz.city_detail'))}</span>
        <button type="button" class="btn btn-ghost btn-sm" data-prism="close-drawer">✕</button>
      </div>
      <div style="font-size:22px;font-weight:700;letter-spacing:-.02em;margin:4px 0">${esc(place)} <span style="font-size:12px;color:var(--text3);font-weight:500">${esc(pt.country_code)}</span></div>
      <div style="color:var(--text3);margin-bottom:14px">${t('pz.req_ips', { n: fmtNum(pt.requests), ips: fmtNum(pt.ips) })}</div>
      <div class="prism-dstats">
        ${stat(t('prism.errors'), fmtNum(pt.errors || 0))}
        ${stat(t('prism.error_rate'), (pt.error_rate || 0).toFixed(1) + '%', (pt.error_rate || 0) >= 10)}
        ${stat(t('pz.banned_ips'), fmtNum(pt.banned_ips || 0), (pt.banned_ips || 0) > 0)}
      </div>
      <p class="prism-muted" style="margin-top:14px">${t('pz.approx_pos')}</p>`;
    dr.classList.add('open');
  }

  function sourcesHtml(agents, refs) {
    return `<div class="prism-two"><div>${agentsHtml(agents)}</div><div>${referrersHtml(refs)}</div></div>`;
  }

  function referrersHtml(refs) {
    if (!refs || refs.length === 0) return `<div class="prism-panel-title">${t('prism.top_refs')}</div><p style="color:var(--text3);font-size:13px">${t('prism.no_refs')}</p>`;
    const maxR = Math.max(...refs.map(r=>r.requests), 1);
    return `
      <div class="prism-panel-title">${esc(t('prism.top_refs'))}</div>
      <table class="prism-table">
        <thead><tr><th>${t('prism.referrer')}</th><th>${t('prism.req_short')}</th><th>${t('prism.share')}</th></tr></thead>
        <tbody>${refs.map(r=>`
          <tr>
            <td style="font-size:12px;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(r.referrer)}">${esc(r.referrer)}</td>
            <td>${fmtNum(r.requests)}</td>
            <td><span class="prism-bar-bg"><span class="prism-bar-fill" style="width:${(r.requests/maxR*100).toFixed(1)}%"></span></span> <span style="font-size:11px;color:var(--text3)">${r.pct.toFixed(1)}%</span></td>
          </tr>`).join('')}</tbody>
      </table>`;
  }

  function showCompare(forceOpen) {
    const panel = document.getElementById('prism-compare-panel');
    if (!panel) return;
    if (forceOpen !== true && compareOpen) {
      compareOpen = false;
      panel.style.display = 'none';
      panel.innerHTML = '';
      syncFilterLiveState();
      return;
    }
    compareOpen = true;
    syncFilterLiveState();
    const n = new Date();
    const cmp1f = toLocalInput(new Date(n - 172800000)), cmp1t = toLocalInput(new Date(n - 86400000));
    const cmp2f = toLocalInput(new Date(n - 86400000)), cmp2t = toLocalInput(n);
    panel.style.display = 'block';
    panel.innerHTML = `
      <div class="prism-panel">
        <div class="prism-panel-title">${t('prism.compare_title')}</div>
        <div style="display:flex;flex-wrap:wrap;gap:12px;margin-bottom:12px">
          <div>
            <div style="font-size:11px;color:var(--text3);margin-bottom:4px">${t('prism.period1')}</div>
            <input type="datetime-local" id="cmp1f" class="form-input" style="max-width:160px" value="${cmp1f}">
            <span style="color:var(--text3);font-size:12px">→</span>
            <input type="datetime-local" id="cmp1t" class="form-input" style="max-width:160px" value="${cmp1t}">
          </div>
          <div>
            <div style="font-size:11px;color:var(--text3);margin-bottom:4px">${t('prism.period2')}</div>
            <input type="datetime-local" id="cmp2f" class="form-input" style="max-width:160px" value="${cmp2f}">
            <span style="color:var(--text3);font-size:12px">→</span>
            <input type="datetime-local" id="cmp2t" class="form-input" style="max-width:160px" value="${cmp2t}">
          </div>
          <button type="button" class="btn btn-primary btn-sm" data-prism="run-compare" style="align-self:flex-end">Comparer</button>
        </div>
        <div id="cmp-result"></div>
      </div>`;
  }

  async function runCompare() {
    const v = id => document.getElementById(id)?.value || '';
    const q = `proxy=${encodeURIComponent(selProxy)}&node_name=${encodeURIComponent(selNode)}&from1=${encodeURIComponent(new Date(v('cmp1f')).toISOString())}&to1=${encodeURIComponent(new Date(v('cmp1t')).toISOString())}&from2=${encodeURIComponent(new Date(v('cmp2f')).toISOString())}&to2=${encodeURIComponent(new Date(v('cmp2t')).toISOString())}`;
    const out = document.getElementById('cmp-result');
    if (!out) return;
    out.innerHTML = '<div class="spinner" style="margin:20px auto"></div>';
    try {
      const d = await api('GET', '/prism/compare?' + q);
      const kpiRow = (label, k1, k2, field, fmt) => {
        const v1 = k1[field], v2 = k2[field];
        const diff = v1 > 0 ? ((v2 - v1) / v1 * 100).toFixed(1) : '—';
        const cls = v2 >= v1 ? 'up' : 'down';
        return `<tr><td style="color:var(--text3)">${label}</td><td>${fmt(v1)}</td><td>${fmt(v2)}</td><td class="prism-kpi-delta ${cls}">${typeof diff==='string'?diff:(diff>0?'+'+diff:diff)+'%'}</td></tr>`;
      };
      const fn = v => fmtNum(Math.round(v));
      const ff = v => (Number(v) || 0).toFixed(1) + '%';
      const fl = v => (Number(v) || 0).toFixed(0) + ' ms';
      const k1 = d.period1.kpis, k2 = d.period2.kpis;
      const lbl1 = new Date(d.period1.from).toLocaleDateString() + ' → ' + new Date(d.period1.to).toLocaleDateString();
      const lbl2 = new Date(d.period2.from).toLocaleDateString() + ' → ' + new Date(d.period2.to).toLocaleDateString();
      out.innerHTML = `
        <table class="prism-table">
          <thead><tr><th>${t('prism.metric')}</th><th>${esc(lbl1)}</th><th>${esc(lbl2)}</th><th>Δ</th></tr></thead>
          <tbody>
            ${kpiRow(t('prism.requests'), k1, k2, 'requests', fn)}
            ${kpiRow(t('prism.bandwidth'), k1, k2, 'bandwidth', v => fmtBytes(v))}
            ${kpiRow(t('prism.error_rate'), k1, k2, 'error_rate', ff)}
            ${kpiRow(t('prism.unique_ips'), k1, k2, 'unique_ips', fn)}
            ${kpiRow(t('prism.latency'), k1, k2, 'avg_latency_ms', fl)}
          </tbody>
        </table>`;
    } catch(e) { out.innerHTML = `<p style="color:var(--red)">${t('prism.error')}: ${esc(e.message)}</p>`; }
  }



  function startLive() {
    toggleLiveMode();
  }



  function doExport(fmt) {
    fetch('/api/v1/prism/export?' + qp() + '&format=' + fmt, { headers: { 'Authorization': 'Bearer ' + state.token } })
      .then(r => r.blob()).then(blob => {
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `prism-export.${fmt}`;
        a.click();
      }).catch(e => toast(t('prism.export_fail') + ' ' + e.message, 'error'));
  }

  async function banIP(ip) {
    if (!ip || bannedIPs.has(ip) || !confirm(t('prism.ban_confirm', { ip }))) return;
    try {
      await api('POST', '/security/bans', {
        ip,
        reason: t('prism.ban_reason'),
        source: 'native',
      });
      bannedIPs.add(ip);
      const panel = document.getElementById('px-ips');
      if (panel) {
        // Re-render with current rows if still present; otherwise soft-reload IPs.
        const q = qp();
        api('GET', '/prism/ips?' + q + '&limit=50')
          .then(d => upd('px-ips', ipsHtml(d)))
          .catch(() => { /* keep current */ });
      }
      toast(t('security.ban_success'), 'success');
    } catch(e) { toast(t('prism.error') + ': ' + e.message, 'error'); }
  }

  function searchPath() {
    pathSearch = document.getElementById('prism-path-search')?.value || '';
    pathOffset = 0;
    loadPaths();
  }

  function goToLogs(extra = {}) {
    const opts = {
      domain: extra.domain || selProxy || '',
      ip: extra.ip || selIp || '',
      path: extra.path || selPathFilter || '',
      status: extra.status || '',
      date_from: selFrom ? new Date(selFrom).toISOString() : '',
      date_to: selTo ? new Date(selTo).toISOString() : '',
    };
    if (typeof openLogsFiltered === 'function') openLogsFiltered(opts);
    else {
      Object.assign(logsFilters, opts);
      if (selNode) logsFilters.node_name = selNode;
      navigate(state.selectedEdge ? 'edge-logs-access' : 'logs');
    }
  }

  function applyBucketZoom(bucket) {
    if (!bucket) return;
    // bucket localtime: "2026-08-07T14:00" ou "2026-08-07"
    let start;
    if (bucket.length === 10) {
      start = new Date(bucket + 'T00:00:00');
      selFrom = toLocalInput(start);
      selTo = toLocalInput(new Date(start.getTime() + 86400000 - 60000));
    } else {
      // hourly
      const normalized = bucket.length === 16 ? bucket + ':00' : bucket;
      start = new Date(normalized);
      if (isNaN(start)) return;
      selFrom = toLocalInput(start);
      selTo = toLocalInput(new Date(start.getTime() + 3600000 - 60000));
    }
    pathOffset = 0;
    loadAll();
  }

  function clearPrismFilter(key) {
    if ((key === '*' || key === 'node') && !lockNode) selNode = '';
    if (key === '*' || key === 'proxy') selProxy = '';
    if (key === '*' || key === 'ip') selIp = '';
    if (key === '*' || key === 'path') selPathFilter = '';
    const nodeSel = document.getElementById('prism-node');
    if (nodeSel) nodeSel.value = selNode;
    const proxySel = document.getElementById('prism-proxy');
    if (proxySel) proxySel.value = selProxy;
    pathOffset = 0;
    loadAll();
  }

  // Délégation d'événements : survit au re-render innerHTML (contrairement aux onclick globaux)
  if (prismRoot && !prismRoot.dataset.prismWired) {
    prismRoot.dataset.prismWired = '1';
    prismRoot.addEventListener('click', e => {
      const el = e.target.closest('[data-prism]');
      if (!el || !prismRoot.contains(el)) return;
      const act = el.getAttribute('data-prism');
      if (act === 'refresh') { e.preventDefault(); doRefresh(); }
      else if (act === 'tab') { e.preventDefault(); setTab(el.getAttribute('data-tab') || 'paths'); }
      else if (act === 'country') { e.preventDefault(); openCountry(el.getAttribute('data-cc') || ''); }
      else if (act === 'rescan') { e.preventDefault(); rescanIP(el.getAttribute('data-ip') || '', el); }
      else if (act === 'close-drawer') { e.preventDefault(); closeCountry(); }
      else if (act === 'geo-style') { e.preventDefault(); geoStyle = el.dataset.style || 'zones'; applyGeo(); }
      else if (act === 'geo-mode') { e.preventDefault(); geoViewMode = el.dataset.mode || 'requests'; applyGeo(); }
      else if (act === 'to-bans') { e.preventDefault(); navigate(state.selectedEdge ? 'edge-security-bans' : 'security-bans'); }
      else if (act === 'quick') { e.preventDefault(); applyQuickRange(parseInt(el.getAttribute('data-ms'), 10) || 3600000); }
      else if (act === 'path-search') { e.preventDefault(); searchPath(); }
      else if (act === 'path-prev') { e.preventDefault(); pathOffset = Math.max(0, pathOffset - pathLimit); loadPaths(); }
      else if (act === 'path-next') { e.preventDefault(); pathOffset += pathLimit; loadPaths(); }
      else if (act === 'ban') { e.preventDefault(); banIP(el.getAttribute('data-ip') || ''); }
      else if (act === 'compare') { e.preventDefault(); showCompare(); }
      else if (act === 'run-compare') { e.preventDefault(); runCompare(); }
      else if (act === 'export') { e.preventDefault(); doExport(el.getAttribute('data-fmt') || 'csv'); }

      else if (act === 'live') { e.preventDefault(); startLive(); }
      else if (act === 'filter-ip') {
        e.preventDefault();
        const ip = el.getAttribute('data-ip') || '';
        selIp = selIp === ip ? '' : ip;
        pathOffset = 0;
        loadAll();
      }
      else if (act === 'filter-path') {
        e.preventDefault();
        const path = el.getAttribute('data-path') || '';
        selPathFilter = selPathFilter === path ? '' : path;
        pathOffset = 0;
        loadAll();
      }
      else if (act === 'filter-proxy') {
        e.preventDefault();
        const proxy = el.getAttribute('data-proxy') || '';
        selProxy = selProxy === proxy ? '' : proxy;
        const proxySel = document.getElementById('prism-proxy');
        if (proxySel) proxySel.value = selProxy;
        pathOffset = 0;
        loadAll();
      }
      else if (act === 'bucket') { e.preventDefault(); applyBucketZoom(el.getAttribute('data-bucket') || ''); }
      else if (act === 'clear-filter') { e.preventDefault(); clearPrismFilter(el.getAttribute('data-key') || '*'); }
      else if (act === 'to-logs') {
        e.preventDefault();
        goToLogs({
          domain: el.getAttribute('data-domain') || '',
          ip: el.getAttribute('data-ip') || '',
          path: el.getAttribute('data-path') || '',
          status: el.getAttribute('data-status') || '',
        });
      }
      else if (act === 'to-logs-status') {
        e.preventDefault();
        goToLogs({ status: el.getAttribute('data-status') || '' });
      }
    });
    prismRoot.addEventListener('change', e => {
      const el = e.target.closest('[data-prism]');
      if (!el || !prismRoot.contains(el)) return;
      const act = el.getAttribute('data-prism');
      if (act === 'node') { selNode = el.value; pathOffset = 0; loadAll(); }
      else if (act === 'proxy') { selProxy = el.value; loadAll(); }
      else if (act === 'from') { selFrom = el.value; }
      else if (act === 'to') { selTo = el.value; }
    });
    prismRoot.addEventListener('keydown', e => {
      if (e.key !== 'Enter') return;
      const el = e.target.closest('[data-prism="path-search-input"]');
      if (!el || !prismRoot.contains(el)) return;
      e.preventDefault();
      searchPath();
    });
  }

  function fmtNum(n) {
    if (n==null) return '0';
    if (n>=1e6) return (n/1e6).toFixed(1)+'M';
    if (n>=1e3) return (n/1e3).toFixed(1)+'k';
    return String(n);
  }
  function fmtBytes(b) {
    if (!b) return '0 B';
    if (b>=1e9) return (b/1e9).toFixed(1)+' GB';
    if (b>=1e6) return (b/1e6).toFixed(1)+' MB';
    if (b>=1e3) return (b/1e3).toFixed(1)+' KB';
    return b+' B';
  }

  await loadAll();
}

