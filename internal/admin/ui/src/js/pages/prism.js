// ── PAGE: Prism (Admin + Core) ─────────────────────────────────────────
// Une seule vue ; les entrées de menu ne font que poser des filtres.
//   Admin (prism)      → tous les Cores / proxies / domaines
//   Core  (core-prism) → filtre node_name verrouillé sur le Core sélectionné
// Extrait de pages-all.js — phase 3. Dépend de shared/fmt.js (fmtBytes).

// A — Cache SVG monde en dehors de la fonction pour survivre aux navigations
let _worldSvgCache = null;
let _prismAbortCtrl = null;
let _prismLiveTimer = null;

/** Portée posée par le menu (conservée pendant toute la visite de la page). */
let prismScope = { node_name: '', lockNode: false };

/** Présélection de filtres (proxy / IP / path / période) avant d'ouvrir la vue. */
let prismPreset = null;

function corePrismNodeName() {
  const c = state.selectedCore;
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
    from: opts.from || '',
    to: opts.to || '',
  };
  window._prismProxyInit = '';
  window._prismIpInit = '';
  window._prismPathInit = '';
  renderPrismPage();
}
window.openPrism = openPrism;

/** Raccourci Trafic : ouvre Prism pour un proxy (Admin global ou Core sélectionné). */
window.openPrismForProxy = function(host, coreId) {
  window._prismProxyInit = host || '';
  if (state.selectedCore) {
    navigate('core-prism');
    return;
  }
  // Admin : vue globale filtrée sur le proxy (pas besoin de sélectionner un Core)
  navigate('prism');
};

// Admin — vue d'ensemble (tous les Cores / proxies)
pages.prism = function() {
  openPrism({
    proxy: window._prismProxyInit || '',
    ip: window._prismIpInit || '',
    path: window._prismPathInit || '',
  });
};

// Core — scoped au nœud sélectionné
pages['core-prism'] = function() {
  openPrism({
    node_name: corePrismNodeName(),
    lockNode: true,
    proxy: window._prismProxyInit || '',
    ip: window._prismIpInit || '',
    path: window._prismPathInit || '',
  });
};

function prismScopeBanner() {
  const node = prismScope.node_name;
  if (node) {
    const label = state.selectedCore?.display_name || state.selectedCore?.node_name || node;
    return `<div style="margin-bottom:12px;padding:8px 12px;background:color-mix(in srgb,var(--accent) 8%,transparent);border:1px solid color-mix(in srgb,var(--accent) 22%,transparent);border-radius:6px;font-size:12px;color:var(--text2);">
      ${t('prism.banner_core', { name: esc(label) })}
    </div>`;
  }
  return `<div style="margin-bottom:12px;padding:8px 12px;background:color-mix(in srgb,var(--accent) 8%,transparent);border:1px solid color-mix(in srgb,var(--accent) 22%,transparent);border-radius:6px;font-size:12px;color:var(--text2);">
    ${t('prism.banner_all')}
  </div>`;
}

async function renderPrismPage() {
  const initProxy = prismPreset?.proxy || '';
  const initIp = prismPreset?.ip || '';
  const initPath = prismPreset?.path || '';
  const initFrom = prismPreset?.from || '';
  const initTo = prismPreset?.to || '';
  prismPreset = null;

  // Alimente le sélecteur Core (vue Admin) si pas encore en cache
  if (!prismScope.lockNode && !(window._coreNodes || []).length) {
    try {
      const nodes = await api('GET', '/nodes').catch(() => []);
      window._coreNodes = (nodes || []).filter(n => n.role === 'core');
    } catch { /* ignore */ }
  }

  const main = document.getElementById('content');
  main.innerHTML = `
    ${prismScopeBanner()}
    <div id="prism-root"><div class="spinner" style="margin:60px auto"></div></div>`;
  const prismRoot = document.getElementById('prism-root');

  let proxies = [], selProxy = initProxy, selIp = initIp, selPathFilter = initPath;
  let selFrom = '', selTo = '', pathSearch = '', pathOffset = 0;
  // Filtre Core libre en vue Admin (verrouillé si menu Core)
  let selNode = prismScope.node_name || '';
  const pathLimit = 20;
  let liveMode = false;
  let liveStartedAt = null; // Date précise du démarrage live
  let compareOpen = false;
  let bannedIPs = new Set();
  const LIVE_WINDOW_MS = 3600000;
  const LIVE_INTERVAL_MS = 5000;
  const lockNode = prismScope.lockNode;
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
    if (selNode && !lockNode) chips.push(['node', 'Core', selNode]);
    if (selProxy) chips.push(['proxy', 'Proxy', selProxy]);
    if (selIp) chips.push(['ip', 'IP', selIp]);
    if (selPathFilter) chips.push(['path', 'Chemin', selPathFilter]);
    if (!chips.length) return '<div id="prism-filter-chips"></div>';
    return `<div id="prism-filter-chips" class="filter-chips" style="margin-bottom:12px">${chips.map(([k,l,v]) =>
      `<span class="filter-chip">${esc(l)}: <b>${esc(v)}</b>
        <button type="button" class="filter-chip-x" data-prism="clear-filter" data-key="${esc(k)}" title="Retirer">✕</button></span>`
    ).join('')}
    <button type="button" class="btn btn-ghost btn-sm" style="font-size:11px" data-prism="clear-filter" data-key="*">Tout effacer</button>
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
  }

  function prismBodyHtml(kpis, timeline, status) {
    return `
      ${kpisHtml(kpis)}
      <div class="prism-grid">
        <div class="prism-panel prism-grid-wide">${timelineHtml(timeline)}</div>
        <div class="prism-panel">${statusHtml(status)}</div>
        <div class="prism-panel" id="px-agents">${spin}</div>
        <div class="prism-panel prism-grid-wide" id="prism-geo-panel" style="min-height:80px">${spin}</div>
        <div class="prism-panel" id="px-refs">${spin}</div>
        <div class="prism-panel prism-grid-wide" id="px-paths">${spin}</div>
        <div class="prism-panel prism-grid-wide" id="px-ips">${spin}</div>
        <div class="prism-panel prism-grid-wide" id="px-berrs">${spin}</div>
      </div>`;
  }

  function fetchSecondaryPanels(q, signal) {
    const guard = fn => e => { if (e && e.name === 'AbortError') return; fn(); };

    apiP('GET', '/prism/unique-ips?' + q, signal)
      .then(d => {
        const el = document.getElementById('prism-kpi-unique-ips');
        if (el && d && d.unique_ips != null) el.textContent = fmtNum(d.unique_ips);
      })
      .catch(() => {});

    apiP('GET', '/prism/agents?' + q + '&limit=30', signal)
      .then(d => upd('px-agents', agentsHtml(d)))
      .catch(guard(() => upd('px-agents', agentsHtml([]))));

    apiP('GET', '/prism/referrers?' + q + '&limit=20', signal)
      .then(d => upd('px-refs', referrersHtml(d)))
      .catch(guard(() => upd('px-refs', referrersHtml([]))));

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

    apiP('GET', '/prism/backend-errors?' + q, signal)
      .then(d => upd('px-berrs', backendErrorsHtml(d)))
      .catch(guard(() => upd('px-berrs', backendErrorsHtml([]))));

    apiP('GET', '/prism/geo?' + q, signal)
      .then(d => { upd('prism-geo-panel', geoHtml(d)); renderChoropleth(d); })
      .catch(guard(() => upd('prism-geo-panel', geoHtml([]))));
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
    let kpis, timeline, status, freshProxies;
    try {
      [[kpis, timeline, status], freshProxies] = await Promise.all([
        Promise.all([
          apiP('GET', '/prism/kpis?' + q, signal),
          apiP('GET', '/prism/timeline?' + q + '&bucket=' + (liveMode ? 'minute' : 'hour'), signal),
          apiP('GET', '/prism/status?' + q, signal),
        ]),
        apiP('GET', '/prism/proxies?' + (selNode ? 'node_name=' + encodeURIComponent(selNode) : ''), signal),
      ]);
    } catch(e) {
      if (e && e.name === 'AbortError') return;
      if (refreshBtn) { refreshBtn.disabled = false; refreshBtn.textContent = 'Actualiser'; }
      toast('Prism : ' + (e.message || t('prism.load_err')), 'error');
      return;
    }

    if (freshProxies && Array.isArray(freshProxies)) proxies = freshProxies;

    const root = document.getElementById('prism-root');
    if (!root) return;

    if (soft) {
      const body = document.getElementById('prism-body');
      if (body) {
        const oldKpis = body.querySelector('.prism-kpis');
        const newKpis = kpisHtml(kpis);
        if (oldKpis && newKpis) {
          const wrap = document.createElement('div');
          wrap.innerHTML = newKpis;
          if (wrap.firstElementChild) oldKpis.replaceWith(wrap.firstElementChild);
        }
        const grid = body.querySelector('.prism-grid');
        if (grid) {
          if (grid.children[0]) grid.children[0].innerHTML = timelineHtml(timeline);
          if (grid.children[1]) grid.children[1].innerHTML = statusHtml(status);
        }
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
      const btn = document.getElementById('prism-refresh-btn');
      if (btn) { btn.disabled = false; btn.textContent = 'Actualiser'; }
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
    const cores = (window._coreNodes || []).filter(n => n.role === 'core' || !n.role);
    const coreOpts = cores.map(c => {
      const name = c.node_name || c.display_name || c.id || '';
      const label = c.display_name || c.node_name || c.id || '—';
      return `<option value="${esc(name)}" ${name===selNode?'selected':''}>${esc(label)}</option>`;
    }).join('');
    const coreSelect = lockNode ? '' : `
        <select id="prism-node" class="form-input" style="max-width:180px" data-prism="node" title="${esc(t('prism.filter_core'))}">
          <option value="">Tous les Cores</option>
          ${coreOpts}
        </select>`;
    const icoCompare = `<svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M8 3L4 7l4 4"/><path d="M4 7h16"/><path d="M16 21l4-4-4-4"/><path d="M20 17H4"/></svg>`;
    const icoLive = `<svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>`;
    return `
      <div class="prism-filters">
        ${coreSelect}
        <select id="prism-proxy" class="form-input" style="max-width:180px" data-prism="proxy">
          <option value="">Tous les proxies</option>
          ${proxyOpts}
        </select>
        <div style="display:flex;align-items:center;gap:6px;font-size:12px;flex-wrap:wrap">
          <span style="color:var(--text3)">De</span>
          <input type="datetime-local" id="prism-from" class="form-input" style="max-width:175px" value="${esc(selFrom)}" data-prism="from"${liveMode ? ' disabled' : ''}>
          <span style="color:var(--text3)">à</span>
          <input type="datetime-local" id="prism-to" class="form-input" style="max-width:175px" value="${esc(selTo)}" data-prism="to"${liveMode ? ' disabled' : ''}>
        </div>
        <div style="display:flex;gap:6px;flex-wrap:wrap">
          ${[['1h',3600000],['6h',21600000],['24h',86400000],['7j',604800000]].map(([lbl,ms])=>
            `<button type="button" class="btn btn-secondary btn-sm" data-prism="quick" data-ms="${ms}"${liveMode ? ' disabled' : ''}>${lbl}</button>`
          ).join('')}
        </div>
        <button type="button" class="btn btn-primary btn-sm" id="prism-refresh-btn" data-prism="refresh">Actualiser</button>
        <div class="prism-filters-actions">
          <span id="prism-live-indicator" class="prism-live-indicator" style="display:${liveMode ? 'inline-flex' : 'none'}">
            <span class="logs-live-dot"></span>Live
          </span>
          <button type="button" class="btn btn-ghost btn-icon btn-sm${compareOpen ? ' is-active' : ''}" id="prism-compare-btn" data-prism="compare" title="${compareOpen ? t('prism.hide_compare') : t('prism.compare')}" aria-pressed="${compareOpen ? 'true' : 'false'}">${icoCompare}</button>
          <button type="button" class="btn btn-ghost btn-icon btn-sm${liveMode ? ' is-active' : ''}" id="prism-live-btn" data-prism="live" title="${liveMode ? t('prism.stop_live') : t('prism.live')}" aria-pressed="${liveMode ? 'true' : 'false'}">${icoLive}</button>
        </div>
      </div>`;
  }

  function toolbarHtml() {
    return `
      <div class="prism-toolbar">
        <div class="prism-toolbar-group prism-toolbar-exports">
          <span class="prism-toolbar-label">${t('prism.export')}</span>
          <button type="button" class="btn btn-secondary btn-sm" data-prism="export" data-fmt="csv">CSV</button>
          <button type="button" class="btn btn-secondary btn-sm" data-prism="export" data-fmt="json">JSON</button>
          <button type="button" class="btn btn-secondary btn-sm" data-prism="export" data-fmt="html">HTML</button>
        </div>
      </div>`;
  }

  function kpisHtml(k) {
    if (!k || typeof k !== 'object' || Array.isArray(k)) return '';
    const delta = (v, inv) => {
      const n = Number(v) || 0;
      if (n === 0) return `<span class="prism-kpi-delta neu">—</span>`;
      const cls = (n > 0) === !inv ? 'up' : 'down';
      return `<span class="prism-kpi-delta ${cls}">${n>0?'+':''}${n.toFixed(1)}%</span>`;
    };
    const uniqueVal = (Number(k.unique_ips) > 0) ? fmtNum(k.unique_ips) : '…';
    const errRate = Number(k.error_rate) || 0;
    const avgLat = Number(k.avg_latency_ms) || 0;
    const botShare = Number(k.bot_share) || 0;
    return `<div class="prism-kpis">
      <div class="prism-kpi"><div class="prism-kpi-label">${t('prism.requests')}</div><div class="prism-kpi-val">${fmtNum(k.requests)}</div>${delta(k.requests_delta,false)}</div>
      <div class="prism-kpi"><div class="prism-kpi-label">${t('prism.bandwidth')}</div><div class="prism-kpi-val">${fmtBytes(k.bandwidth)}</div>${delta(k.bandwidth_delta,false)}</div>
      <div class="prism-kpi"><div class="prism-kpi-label">${t('prism.error_rate')}</div><div class="prism-kpi-val">${errRate.toFixed(1)}%</div>${delta(k.error_rate_delta,true)}</div>
      <div class="prism-kpi"><div class="prism-kpi-label">${t('prism.unique_ips')}</div><div class="prism-kpi-val" id="prism-kpi-unique-ips">${uniqueVal}</div></div>
      <div class="prism-kpi"><div class="prism-kpi-label">${t('prism.latency')}</div><div class="prism-kpi-val">${avgLat.toFixed(0)} ms</div></div>
      <div class="prism-kpi"><div class="prism-kpi-label">${t('prism.bot_share')}</div><div class="prism-kpi-val">${botShare.toFixed(1)}%</div></div>
    </div>`;
  }

  function timelineHtml(pts) {
    const bucketLabel = liveMode ? 'minute' : 'heure';
    if (!pts || pts.length === 0) return `<div class="prism-panel-title">${t('prism.requests_per', { bucket: bucketLabel })}</div><p style="color:var(--text3);font-size:13px">${liveMode ? t('prism.wait_traffic') : t('prism.no_period')}</p>`;
    const max = Math.max(...pts.map(p=>p.requests), 1);
    const W = 600, H = 120, pad = 4;
    const xStep = pts.length > 1 ? (W - pad*2) / (pts.length - 1) : W - pad*2;
    const toX = i => pad + i * xStep;
    const toY = v => H - pad - (v / max) * (H - pad*2);

    const reqLine = pts.map((p,i)=>`${i===0?'M':'L'}${toX(i).toFixed(1)},${toY(p.requests).toFixed(1)}`).join(' ');
    const errLine = pts.length > 1 ? pts.map((p,i)=>`${i===0?'M':'L'}${toX(i).toFixed(1)},${toY(p.errors).toFixed(1)}`).join(' ') : '';
    const area = reqLine + ` L${toX(pts.length-1).toFixed(1)},${H-pad} L${pad},${H-pad} Z`;

    const step = Math.ceil(pts.length / 8);
    const xLabels = pts.filter((_,i)=>i%step===0||i===pts.length-1).map(p=>{
      const i = pts.indexOf(p);
      const label = p.bucket.includes('T') ? p.bucket.split('T')[1].slice(0,5) : p.bucket.slice(5);
      return `<text x="${toX(i).toFixed(1)}" y="${H+14}" text-anchor="middle" font-size="9" fill="var(--text3)">${esc(label)}</text>`;
    });

    const dots = pts.map((p,i) => {
      const x = toX(i).toFixed(1), y = toY(p.requests).toFixed(1);
      return `<circle cx="${x}" cy="${y}" r="5" fill="var(--accent)" fill-opacity="0.01" stroke="transparent" stroke-width="12" style="cursor:pointer"
        data-prism="bucket" data-bucket="${esc(p.bucket)}" title="${esc(p.bucket)} — ${p.requests} req"/>`;
    }).join('');

    return `
      <div class="prism-panel-title">${t('prism.requests_per', { bucket: bucketLabel })} <span style="font-weight:400;color:var(--text3);font-size:11px">· ${t('prism.click_zoom')}</span></div>
      <svg class="prism-svg" viewBox="0 0 ${W} ${H+20}" preserveAspectRatio="none">
        <defs><linearGradient id="pg" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="var(--accent)" stop-opacity=".2"/><stop offset="100%" stop-color="var(--accent)" stop-opacity="0"/></linearGradient></defs>
        <path d="${area}" fill="url(#pg)"/>
        <path d="${reqLine}" fill="none" stroke="var(--accent)" stroke-width="2"/>
        ${errLine ? `<path d="${errLine}" fill="none" stroke="var(--red)" stroke-width="1.5" stroke-dasharray="4,2"/>` : ''}
        ${dots}
        ${xLabels.join('')}
      </svg>
      <div style="display:flex;gap:16px;font-size:11px;color:var(--text3);margin-top:2px">
        <span><span style="display:inline-block;width:12px;height:2px;background:var(--accent);vertical-align:middle;margin-right:4px"></span>Requêtes</span>
        <span><span style="display:inline-block;width:12px;height:2px;background:var(--red);vertical-align:middle;margin-right:4px"></span>${t('prism.errors')}</span>
      </div>`;
  }

  function statusHtml(groups) {
    if (!groups || groups.length === 0) return `<div class="prism-panel-title">${t('prism.http_codes')}</div><p style="color:var(--text3);font-size:13px">${t('prism.no_data')}</p>`;
    const colors = {'2xx':'var(--green)','3xx':'#60a5fa','4xx':'#f59e0b','5xx':'var(--red)'};
    const byGroup = Object.fromEntries(groups.map(g => [g.group, g]));
    const leftGroups = ['4xx', '5xx'].map(k => byGroup[k]).filter(Boolean);
    const rightGroups = ['2xx', '3xx'].map(k => byGroup[k]).filter(Boolean);
    const total = groups.reduce((s,g)=>s+g.count,0);
    const R=44, CX=56, CY=56, sw=22, circum=2*Math.PI*R;
    let offset = 0;
    const arcs = groups.map(g => {
      const pct = total>0 ? g.count/total : 0;
      const a = {g:g.group,pct,offset,color:colors[g.group]||'#999'}; offset+=pct; return a;
    }).filter(a=>a.pct>0).map(a=>{
      const dash=a.pct*circum, gap=circum-dash, rot=a.offset*360-90;
      return `<circle cx="${CX}" cy="${CY}" r="${R}" fill="none" stroke="${a.color}" stroke-width="${sw}" stroke-dasharray="${dash.toFixed(2)} ${gap.toFixed(2)}" transform="rotate(${rot.toFixed(2)} ${CX} ${CY})"/>`;
    });
    const legendCol = (list) => `
      <div class="prism-donut-legend">
        ${list.map(g=>`
          <div style="display:flex;align-items:center;gap:6px">
            <div class="prism-legend-dot" style="background:${colors[g.group]||'#999'}"></div>
            <button type="button" class="log-filter-link" data-prism="to-logs-status" data-status="${esc(g.group)}" title="Voir dans les logs"><b style="color:var(--text)">${g.group}</b></button>
            <span style="color:var(--text3)">${fmtNum(g.count)} (${g.pct.toFixed(1)}%)</span>
          </div>
          ${(g.breakdown||[]).slice(0,4).map(b=>`<div style="padding-left:16px;font-size:11px;color:var(--text3)">
            <button type="button" class="log-filter-link" data-prism="to-logs-status" data-status="${b.code}" title="${esc(t('prism.filter_logs'))}">${b.code}</button> — ${fmtNum(b.count)}
          </div>`).join('')}`).join('')}
      </div>`;
    return `
      <div class="prism-panel-title">Codes HTTP</div>
      <div class="prism-donut">
        ${legendCol(leftGroups)}
        <svg width="112" height="112" viewBox="0 0 112 112" style="flex-shrink:0">
          <circle cx="${CX}" cy="${CY}" r="${R}" fill="none" stroke="var(--bg3)" stroke-width="${sw}"/>
          ${arcs.join('')}
          <text x="${CX}" y="${CY+4}" text-anchor="middle" font-size="11" fill="var(--text2)">${fmtNum(total)}</text>
        </svg>
        ${legendCol(rightGroups)}
      </div>`;
  }

  function agentsHtml(agents) {
    if (!agents||agents.length===0) return `<div class="prism-panel-title">${t('prism.components')}</div><p style="color:var(--text3);font-size:13px">${t('prism.no_data')}</p>`;
    const maxR = Math.max(...agents.map(a=>a.requests),1);
    return `
      <div class="prism-panel-title">Composants / Bots</div>
      <table class="prism-table">
        <thead><tr><th>Composant</th><th>Req.</th><th>Part</th></tr></thead>
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
      <div class="prism-panel-title">Top chemins</div>
      <div class="prism-search">
        <input type="text" id="prism-path-search" class="form-input" placeholder="${esc(t('prism.filter_ph'))}" value="${esc(pathSearch)}" style="flex:1" data-prism="path-search-input">
        <button type="button" class="btn btn-secondary btn-sm" data-prism="path-search">Chercher</button>
      </div>
      <table class="prism-table">
        <thead><tr><th>Chemin</th><th>Req.</th><th>Err.</th><th>Lat. moy.</th><th>Volume</th><th></th></tr></thead>
        <tbody>${list.map(p=>`
          <tr>
            <td style="font-family:monospace;font-size:11px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(p.path)}">
              <button type="button" class="log-filter-link${selPathFilter===p.path?' is-active':''}" data-prism="filter-path" data-path="${esc(p.path)}">${esc(p.path)}</button>
            </td>
            <td>${fmtNum(p.requests)}</td>
            <td style="color:${p.errors>0?'var(--red)':'var(--text3)'}">${fmtNum(p.errors)}</td>
            <td>${p.avg_lat_ms.toFixed(0)} ms</td>
            <td><span class="prism-bar-bg"><span class="prism-bar-fill" style="width:${(p.requests/maxR*100).toFixed(1)}%"></span></span></td>
            <td><button type="button" class="btn btn-ghost btn-icon btn-sm" data-prism="to-logs" data-path="${esc(p.path)}" title="Voir dans les logs">
              <svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M7 8h10M7 12h10M7 16h6"/></svg>
            </button></td>
          </tr>`).join('')}</tbody>
      </table>
      <div class="prism-pagination">
        <button type="button" class="btn btn-secondary btn-sm" data-prism="path-prev" ${pathOffset===0?'disabled':''}>← Préc.</button>
        <span style="color:var(--text3)">Page ${page}</span>
        <button type="button" class="btn btn-secondary btn-sm" data-prism="path-next" ${hasMore?'':'disabled'}>Suiv. →</button>
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
              ${banned
                ? `<span class="btn btn-ghost btn-icon btn-sm" title="${esc(t('prism.banned'))}" style="color:var(--red);opacity:.9;cursor:default;pointer-events:none">${icoBan}</span>`
                : `<button type="button" class="btn btn-ghost btn-icon btn-sm" data-prism="ban" data-ip="${esc(i.ip)}" title="${esc(t('prism.ban'))}">${icoBan}</button>`}
            </td>
          </tr>`;
        }).join('')}</tbody>
      </table>`;
  }

  function geoHtml(geo) {
    return `<div class="prism-panel-title">Trafic par pays</div><div id="prism-geo-map" class="wm-wrap" style="min-height:200px"><div class="spinner" style="margin:80px auto"></div></div>`;
  }

  async function renderChoropleth(geo) {
    const container = document.getElementById('prism-geo-map');
    if (!container) return;

    if (!_worldSvgCache) {
      try {
        const res = await fetch('/world.svg');
        _worldSvgCache = await res.text();
      } catch(e) {
        container.innerHTML = '<p style="color:var(--text3);font-size:13px;padding:16px">Carte indisponible.</p>';
        return;
      }
    }

    if (!geo || geo.length === 0) {
      container.innerHTML = `<p style="color:var(--text3);font-size:13px;padding:16px">${t('prism.wait_geo')}<br><span style="font-size:11px">${t('prism.geo_bg')}</span></p>`;
      return;
    }

    const byCC = {};
    let maxReq = 0;
    for (const g of geo) {
      byCC[g.country_code] = g;
      if (g.requests > maxReq) maxReq = g.requests;
    }

    const parser = new DOMParser();
    const svgDoc = parser.parseFromString(_worldSvgCache, 'image/svg+xml');
    const svgEl = svgDoc.documentElement;
    svgEl.style.cssText = 'display:block;width:100%;height:auto;border-radius:6px 6px 0 0';

    const sphere = svgEl.querySelector('.wm-sphere');
    if (sphere) sphere.setAttribute('fill', 'var(--bg3)');

    const grat = svgEl.querySelector('.wm-graticule');
    if (grat) { grat.setAttribute('fill', 'none'); grat.setAttribute('stroke', 'var(--border)'); grat.setAttribute('stroke-width', '0.3'); grat.setAttribute('opacity', '0.5'); }

    const border = svgEl.querySelector('.wm-border');
    if (border) { border.setAttribute('fill', 'none'); border.setAttribute('stroke', 'var(--border)'); border.setAttribute('stroke-width', '0.8'); border.setAttribute('opacity', '0.6'); }

    const paths = svgEl.querySelectorAll('.wm-countries path');
    for (const p of paths) {
      const entry = byCC[p.id];
      if (entry && maxReq > 0) {
        const t = entry.requests / maxReq;
        // accent-tinted fill, 8 intensity steps
        const alpha = (0.12 + t * 0.83).toFixed(2);
        p.setAttribute('fill', `rgba(89,128,166,${alpha})`);
        p.setAttribute('stroke', 'var(--bg)');
        p.setAttribute('stroke-width', '0.5');
        p.dataset.cc   = p.id;
        p.dataset.name = entry.country_name;
        p.dataset.req  = entry.requests;
        p.dataset.pct  = entry.pct.toFixed(1);
        p.style.cursor = 'pointer';
      } else {
        p.setAttribute('fill', 'var(--bg2)');
        p.setAttribute('stroke', 'var(--border)');
        p.setAttribute('stroke-width', '0.3');
      }
    }

    // Tooltip
    let tip = document.getElementById('wm-tooltip');
    if (!tip) {
      tip = document.createElement('div');
      tip.id = 'wm-tooltip';
      document.body.appendChild(tip);
    }

    svgEl.addEventListener('mousemove', e => {
      const p = e.target.closest && e.target.closest('path[data-cc]');
      if (p) {
        tip.style.display = 'block';
        tip.style.left = (e.clientX + 16) + 'px';
        tip.style.top  = (e.clientY - 12) + 'px';
        const entry = byCC[p.dataset.cc];
        tip.innerHTML = `<b style="color:var(--text)">${esc(p.dataset.name)}</b> <span style="color:var(--text3);font-size:10px">${p.dataset.cc}</span><br><span style="color:var(--text2)">${fmtNum(parseInt(p.dataset.req))} req &nbsp;·&nbsp; <b>${p.dataset.pct}%</b> du trafic</span>`;
      } else {
        tip.style.display = 'none';
      }
    });
    svgEl.addEventListener('mouseleave', () => { if (tip) tip.style.display = 'none'; });

    svgEl.addEventListener('mouseover', e => {
      const p = e.target.closest && e.target.closest('path[data-cc]');
      if (p) { p._fill = p.getAttribute('fill'); p.setAttribute('fill', 'var(--accent)'); }
    });
    svgEl.addEventListener('mouseout', e => {
      const p = e.target.closest && e.target.closest('path[data-cc]');
      if (p && p._fill) p.setAttribute('fill', p._fill);
    });

    container.innerHTML = '';
    container.style.minHeight = '';
    container.appendChild(svgEl);

    // Table below the map
    const maxR = maxReq;
    const flag = cc => {
      if (!cc || cc.length !== 2 || cc === 'XX' || cc === 'LO') return '';
      return String.fromCodePoint(0x1F1E6+cc.charCodeAt(0)-65, 0x1F1E6+cc.charCodeAt(1)-65) + ' ';
    };
    const tableWrap = document.createElement('div');
    tableWrap.style.cssText = 'overflow-x:auto;border-top:1px solid var(--border)';
    tableWrap.innerHTML = `
      <table class="prism-table">
        <thead><tr><th>Pays</th><th>Req.</th><th>Part</th></tr></thead>
        <tbody>${geo.slice(0, 15).map(g => `
          <tr>
            <td><span style="font-size:15px">${flag(g.country_code)}</span><span style="color:var(--text3);font-size:10px;margin-right:4px">${esc(g.country_code)}</span>${esc(g.country_name)}</td>
            <td>${fmtNum(g.requests)}</td>
            <td><span class="prism-bar-bg"><span class="prism-bar-fill" style="width:${(g.requests/maxR*100).toFixed(1)}%"></span></span> <span style="font-size:11px;color:var(--text3)">${g.pct.toFixed(1)}%</span></td>
          </tr>`).join('')}
        </tbody>
      </table>`;
    container.appendChild(tableWrap);
  }

  function referrersHtml(refs) {
    if (!refs || refs.length === 0) return `<div class="prism-panel-title">${t('prism.top_refs')}</div><p style="color:var(--text3);font-size:13px">${t('prism.no_refs')}</p>`;
    const maxR = Math.max(...refs.map(r=>r.requests), 1);
    return `
      <div class="prism-panel-title">Top référents</div>
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

  function backendErrorsHtml(rows) {
    if (!rows || rows.length === 0) return `<div class="prism-panel-title">${t('prism.backends_err')}</div><p style="color:var(--text3);font-size:13px">${t('prism.no_data_avail')}</p>`;
    const maxRate = Math.max(...rows.map(r=>r.error_rate), 1);
    return `
      <div class="prism-panel-title">${t('prism.backends_err')}</div>
      <table class="prism-table">
        <thead><tr><th>Proxy</th><th>${t('prism.domain')}</th><th>Backend</th><th>${t('prism.requests')}</th><th>${t('prism.errors')}</th><th>${t('prism.rate')}</th><th>${t('prism.lat_avg')}</th><th></th></tr></thead>
        <tbody>${rows.map(r=>`<tr>
          <td style="font-size:12px">${esc(r.name)}</td>
          <td style="font-size:12px"><button type="button" class="log-filter-link" data-prism="filter-proxy" data-proxy="${esc(r.domain||'')}">${esc(r.domain||'—')}</button></td>
          <td style="font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text2)" title="${esc(r.backend_url)}">${esc(r.backend_url||'—')}</td>
          <td>${fmtNum(r.total)}</td>
          <td style="color:${r.errors>0?'var(--red)':'var(--text2)'}">${fmtNum(r.errors)}</td>
          <td><span class="prism-bar-bg"><span class="prism-bar-fill" style="width:${(r.error_rate/maxRate*100).toFixed(1)}%;background:var(--red)"></span></span> <span style="font-size:11px;color:${r.error_rate>10?'var(--red)':r.error_rate>5?'var(--yellow)':'var(--text3)'}">${r.error_rate.toFixed(1)}%</span></td>
          <td style="color:var(--text2);font-size:12px">${r.avg_lat_ms}ms</td>
          <td><button type="button" class="btn btn-ghost btn-icon btn-sm" data-prism="to-logs" data-domain="${esc(r.domain||'')}" data-status="5" title="${esc(t('prism.error_logs'))}">
            <svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M7 8h10M7 12h10M7 16h6"/></svg>
          </button></td>
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
      navigate(state.selectedCore ? 'core-logs-access' : 'logs');
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

