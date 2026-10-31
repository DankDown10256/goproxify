// ── PAGE: Poste de contrôle proxy (Admin + Passerelle) ───────────────────────
// Menu Observabilité > Vue Proxy : aucun proxy n'est affiché d'office. La barre du haut
// (recherche + période + Live + masquage du trafic interne, même style que les Logs)
// ajoute des proxies à la sélection ; la page agrège ensuite ceux qui sont sélectionnés
// (tuiles par proxy, KPIs, carte, anomalies, courbe, statuts, chemins, IP).
// Le flux temps réel n'est lancé que par le bouton Live.
//   Admin (proxy-inspector)      → tous les proxies, toutes passerelles
//   Passerelle (edge-proxy-inspector) → node_name verrouillé
// Les endpoints /prism/* acceptent plusieurs domaines séparés par des virgules.
// Réutilise gpxGeoMap (shared/geomap.js), obs*Html (shared/obs-widgets.js),
// openPrismForProxy et openLogsFiltered.

let _pxiGeoCtl = null;
let _pxiLiveTimer = null;
let _pxiLiveLastTs = null;
let _pxiLiveFeed = [];
let _pxiLiveTick = 0;
let _pxiLoadSeq = 0;
const PXI_LIVE_INTERVAL_MS = 4000;
const PXI_LIVE_REFRESH_TICKS = 5;
const PXI_LIVE_FEED_MAX = 40;
const PXI_PERIODS = [
  { label: '15m', ms: 9e5 }, { label: '1h', ms: 3.6e6 }, { label: '6h', ms: 2.16e7 },
  { label: '24h', ms: 8.64e7 }, { label: '7d', ms: 7 * 8.64e7 }, { label: '14d', ms: 14 * 8.64e7 },
  { label: '30d', ms: 30 * 8.64e7 }, { label: '90d', ms: 90 * 8.64e7 },
];

let pxiScope = { node_name: '', lock: false };
let pxiSelected = [];          // domaines sélectionnés (cumulables)
let pxiPeriodMs = 8.64e7;
let pxiLive = false;
let pxiGeoMode = 'requests';   // 'requests' | 'error_rate' | 'banned_ips'
let pxiGeoStyle = 'zones';     // 'zones' | 'cities' | 'regions'
let pxiHideInternal = true;

function edgePxiNodeName() {
  const c = state.selectedEdge;
  return (c?.node_name || c?.display_name || c?.id || '').trim();
}

pages['proxy-inspector'] = function() {
  pxiScope = { node_name: '', lock: false };
  renderProxyInspector();
};
pages['edge-proxy-inspector'] = function() {
  pxiScope = { node_name: edgePxiNodeName(), lock: true };
  renderProxyInspector();
};

function pxiStopLive() {
  if (_pxiLiveTimer) { clearInterval(_pxiLiveTimer); _pxiLiveTimer = null; }
  _pxiLiveFeed = [];
  _pxiLiveLastTs = null;
  _pxiLiveTick = 0;
}

async function renderProxyInspector() {
  if (_pxiGeoCtl) { _pxiGeoCtl.destroy(); _pxiGeoCtl = null; }
  pxiStopLive();
  pxiLive = false;
  const seq = ++_pxiLoadSeq;

  const main = document.getElementById('content');
  main.innerHTML = `<div class="pxi-root"><div class="spinner" style="margin:60px auto"></div></div>`;

  const proxiesPath = pxiScope.lock && pxiScope.node_name
    ? `/proxies?edge=${encodeURIComponent(pxiScope.node_name)}`
    : '/proxies';
  const [proxiesRaw, metrics0, containersRaw] = await Promise.all([
    api('GET', proxiesPath).catch(() => []),
    api('GET', '/metrics/proxies?points=30').catch(() => null),
    api('GET', '/discovered-containers').catch(() => []),
  ]);
  if (seq !== _pxiLoadSeq || !document.getElementById('content')) return;

  const getCfg = p => {
    if (!p.config) return {};
    if (typeof p.config === 'object') return p.config;
    try { return JSON.parse(p.config) || {}; } catch { return {}; }
  };
  const proxies = (proxiesRaw || []).map(p => {
    const cfg = getCfg(p);
    const domain = cfg.host || p.host || p.name || p.id || '';
    const backends = (cfg.backends || p.backends || []).map(b => b.url || b).filter(Boolean);
    return { id: p.id, domain, name: p.name || '', backends, enabled: p.enabled !== false, aliases: cfg.aliases || [] };
  }).filter(p => p.domain);

  // Les routes issues des labels d'un conteneur sont des domaines servis comme les proxies. Un hôte déjà servi
  // par un proxy configuré reste celui du proxy ; un conteneur arrêté n'a pas de route.
  const served = new Set(proxies.flatMap(p => [p.domain, ...p.aliases]).map(h => String(h).trim().toLowerCase()));
  const edgeFilter = pxiScope.lock ? pxiScope.node_name : '';
  for (const c of Array.isArray(containersRaw) ? containersRaw : []) {
    if (c.inactive || c.shadowed_by) continue;
    if (edgeFilter && (c.edge_name || c.edge_label) !== edgeFilter) continue;
    const backends = (c.backends || []).map(b => b.url || b).filter(Boolean);
    for (const host of [c.host, ...(c.aliases || [])]) {
      const key = String(host || '').trim().toLowerCase();
      if (!key || served.has(key)) continue;
      served.add(key);
      proxies.push({ id: '', domain: host, name: c.name || '', backends, enabled: !c.disabled, container: true });
    }
  }
  const byDomain = new Map(proxies.map(p => [p.domain, p]));
  pxiSelected = pxiSelected.filter(d => byDomain.has(d));

  let metricsByHost = new Map((metrics0?.proxies || []).map(m => [(m.host || '').toLowerCase(), m]));
  const metricOf = d => metricsByHost.get(d.toLowerCase()) || null;

  const icoLogs = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 6h16M4 12h16M4 18h10"/></svg>`;
  const icoFull = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 20V10M12 20V4M6 20v-6"/></svg>`;
  const icoPurge = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 1 1-2.64-6.36"/><polyline points="21 3 21 9 15 9"/></svg>`;
  const icoPause = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/></svg>`;
  const icoPlay = `<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" stroke="none"><path d="M7 4l13 8-13 8z"/></svg>`;
  const icoBan = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>`;

  const flagOf = cc => (!cc || cc.length !== 2 || cc === 'XX' || cc === 'LO') ? '🌐'
    : String.fromCodePoint(0x1F1E6 + cc.charCodeAt(0) - 65, 0x1F1E6 + cc.charCodeAt(1) - 65);
  const num = n => gmNum(Number(n) || 0);
  const wait = () => `<div class="pxi-feed-empty">${esc(t('pxi.wait_traffic'))}</div>`;
  const upd = (id, html) => { const el = document.getElementById(id); if (el) el.innerHTML = html; };

  function proxyStatus(p) {
    const m = metricOf(p.domain);
    if (!p.enabled) return { c: 'var(--text3)', label: t('pxi.disabled') };
    const er = m?.error_rate || 0;
    const p95 = m?.p95_ms || 0;
    if (er > 0.05) return { c: 'var(--red)', label: t('pxi.status_error') };
    if (er > 0.01 || p95 > 300) return { c: 'var(--yellow)', label: t('pxi.status_degraded') };
    return { c: 'var(--green)', label: t('pxi.status_ok') };
  }

  // ── Squelette ────────────────────────────────────────────────────────────
  main.innerHTML = `
    <div class="pxi-root" id="pxi-root">
      <div class="pxi-bar">
        <div class="pxi-bar-row">
          <div class="pxi-chips" id="pxi-chips"></div>
          <div class="logs-seg" id="pxi-period"></div>
        </div>
        <div class="pxi-bar-row">
          <div class="pxi-search-wrap">
            <input type="text" id="pxi-search" class="input search-input" style="max-width:none" autocomplete="off" placeholder="${esc(t('pxi.search'))}">
            <div class="pxi-suggest" id="pxi-suggest" hidden></div>
          </div>
          <button type="button" class="btn btn-secondary btn-sm pxi-live-btn" id="pxi-live-btn" data-pxi="live"></button>
          <label class="logs-toggle-inline" style="margin-left:0">
            <span class="toggle"><input type="checkbox" id="pxi-hide-internal" ${pxiHideInternal ? 'checked' : ''}><span class="toggle-slider"></span></span>
            ${esc(t('logs.hide_internal'))}
          </label>
        </div>
        <div class="pxi-hint" id="pxi-count-hint"></div>
      </div>
      <div class="pxi-empty" id="pxi-empty"><b>${esc(t('pxi.empty_title'))}</b>${esc(t('pxi.empty_hint', { n: proxies.length }))}</div>
      <div class="pxi-dash" id="pxi-dash" hidden>
        <div class="pxi-tiles" id="pxi-tiles"></div>
        <div id="px-kpis"></div>
        <div class="prism-hero">
          <div class="prism-panel prism-mapcard pxi-mapwrap">
            <div class="pxi-mapbar">
              <span class="prism-panel-title" style="margin:0">${esc(t('pz.by_country'))}</span>
              <div style="display:flex;gap:8px;flex-wrap:wrap">
                <div class="btn-group" role="group">
                  <button type="button" class="btn btn-xs geo-mode-btn" data-pxi="mode" data-mode="requests">${esc(t('prism.requests'))}</button>
                  <button type="button" class="btn btn-xs geo-mode-btn" data-pxi="mode" data-mode="error_rate">${esc(t('pz.err_rate_short'))}</button>
                  <button type="button" class="btn btn-xs geo-mode-btn" data-pxi="mode" data-mode="banned_ips">${esc(t('pz.banned_ips'))}</button>
                </div>
                <div class="btn-group" role="group">
                  <button type="button" class="btn btn-xs geo-style-btn" data-pxi="style" data-style="zones" title="${esc(t('sy.atk_zones'))}" aria-label="${esc(t('sy.atk_zones'))}">${gmStyleIcon('zones')}</button>
                  <button type="button" class="btn btn-xs geo-style-btn" data-pxi="style" data-style="cities" title="${esc(t('sy.atk_cities'))}" aria-label="${esc(t('sy.atk_cities'))}">${gmStyleIcon('cities')}</button>
                  <button type="button" class="btn btn-xs geo-style-btn" data-pxi="style" data-style="regions" title="${esc(t('sy.atk_regions'))}" aria-label="${esc(t('sy.atk_regions'))}">${gmStyleIcon('regions')}</button>
                </div>
              </div>
            </div>
            <div id="pxi-geo-map" class="prism-mapbox gm-box" style="min-height:300px"></div>
          </div>
          <div class="prism-rail">
            <div class="prism-panel"><div class="prism-panel-title">${esc(t('obs.syn.anoms'))}</div><div id="px-anoms"></div></div>
            <div class="prism-panel"><div class="prism-panel-title">${esc(t('obs.syn.countries'))}</div><div id="px-topc"></div></div>
          </div>
        </div>
        <div class="prism-panel" id="pxi-live-panel" hidden>
          <div class="prism-panel-title"><span style="display:flex;align-items:center;gap:8px"><span class="logs-live-dot"></span>${esc(t('pz.live_conns'))}</span></div>
          <div class="pxi-feed" id="pxi-live-feed"></div>
        </div>
        <div class="prism-two">
          <div class="prism-panel" id="px-timeline"></div>
          <div class="prism-panel" id="px-status"></div>
        </div>
        <div class="prism-two" style="grid-template-columns:repeat(2,minmax(0,1fr))">
          <div class="prism-panel" id="px-paths"></div>
          <div class="prism-panel" id="px-ips"></div>
        </div>
      </div>
    </div>`;

  // ── Barre : puces, période, Live ─────────────────────────────────────────
  function renderBar() {
    upd('pxi-chips', pxiSelected.length
      ? pxiSelected.map(d => {
          const p = byDomain.get(d);
          const dot = proxyStatus(p);
          return `<span class="chip active"><span class="pxi-dot" style="background:${dot.c}" title="${esc(dot.label)}"></span>${esc(d)}<button type="button" class="chip-x" data-pxi-remove="${esc(d)}" aria-label="${esc(t('pxi.remove'))}" title="${esc(t('pxi.remove'))}">×</button></span>`;
        }).join('') + `<button type="button" class="chip" data-pxi="clear">${esc(t('pxi.clear'))}</button>`
      : `<span class="pxi-hint">${esc(t('pxi.sel_none'))}</span>`);
    upd('pxi-period', PXI_PERIODS.map(c => `<button type="button" class="seg-btn${pxiPeriodMs === c.ms ? ' active' : ''}" data-pxi-period="${c.ms}">${c.label}</button>`).join(''));
    const lb = document.getElementById('pxi-live-btn');
    if (lb) {
      lb.classList.toggle('is-active', pxiLive);
      lb.innerHTML = `<span class="logs-live-dot"></span>${esc(pxiLive ? t('pxi.live_stop') : t('pxi.live'))}`;
      lb.disabled = !pxiSelected.length;
    }
    upd('pxi-count-hint', esc(t('pxi.count_hint', { sel: pxiSelected.length, total: proxies.length })));
    document.querySelectorAll('#pxi-root .geo-mode-btn').forEach(b => b.classList.toggle('active', b.dataset.mode === pxiGeoMode));
    document.querySelectorAll('#pxi-root .geo-style-btn').forEach(b => b.classList.toggle('active', b.dataset.style === pxiGeoStyle));
  }

  // ── Recherche / suggestions ──────────────────────────────────────────────
  let sgItems = [];
  let sgHl = 0;
  function matches(q) {
    q = q.trim().toLowerCase();
    if (!q) return [];
    return proxies.filter(p => !pxiSelected.includes(p.domain)
      && (p.domain.toLowerCase().includes(q) || p.name.toLowerCase().includes(q) || p.backends.some(b => b.toLowerCase().includes(q))));
  }
  function renderSuggest() {
    const box = document.getElementById('pxi-suggest');
    const input = document.getElementById('pxi-search');
    if (!box || !input) return;
    const q = input.value;
    if (!q.trim()) { box.hidden = true; sgItems = []; return; }
    sgItems = matches(q);
    sgHl = Math.min(sgHl, Math.max(sgItems.length - 1, 0));
    box.hidden = false;
    if (!sgItems.length) { box.innerHTML = `<div class="pxi-sg-none">${esc(t('pxi.none'))}</div>`; return; }
    const all = sgItems.length > 1
      ? `<button type="button" class="pxi-sg pxi-sg-all" data-pxi="add-all">${esc(t('pxi.add_all', { n: sgItems.length }))}</button>` : '';
    box.innerHTML = all + sgItems.slice(0, 12).map((p, i) => {
      const dot = proxyStatus(p);
      return `<button type="button" class="pxi-sg${i === sgHl ? ' hl' : ''}" data-pxi-add="${esc(p.domain)}">
        <span class="pxi-dot" style="background:${dot.c}"></span>
        <span class="pxi-sg-main"><span class="pxi-sg-name">${esc(p.domain)}</span><span class="pxi-sg-sub mono">${esc(p.backends[0] || '—')}</span></span>
        ${p.container ? `<span class="chip">${esc(t('pxi.container'))}</span>` : ''}
      </button>`;
    }).join('');
  }
  function addProxies(domains) {
    let added = false;
    for (const d of domains) if (!pxiSelected.includes(d)) { pxiSelected.push(d); added = true; }
    const input = document.getElementById('pxi-search');
    if (input) input.value = '';
    renderSuggest();
    if (added) selectionChanged();
  }
  function selectionChanged() {
    if (!pxiSelected.length && pxiLive) toggleLive(false);
    renderBar();
    loadAll();
  }

  // ── Actions par tuile ────────────────────────────────────────────────────
  async function onTileAction(act, p, btn) {
    if (act === 'logs') {
      if (typeof openLogsFiltered === 'function') openLogsFiltered({ domain: p.domain, node_name: pxiScope.node_name || '' });
    } else if (act === 'prism') {
      if (typeof window.openPrismForProxy === 'function') window.openPrismForProxy(p.domain, pxiScope.node_name);
    } else if (act === 'bans') {
      navigate(state.selectedEdge ? 'edge-security-bans' : 'security-bans');
    } else if (act === 'purge-cache') {
      if (!p.id) return;
      btn.disabled = true;
      try {
        const res = await api('POST', `/proxies/${encodeURIComponent(p.id)}/cache/purge`);
        toast(t('pxi.purge_done', { n: res?.purged ?? 0 }), 'success');
      } catch (e) {
        toast(t('pxi.purge_err') + (e?.message ? ' : ' + e.message : ''), 'error');
      } finally {
        btn.disabled = false;
      }
    } else if (act === 'maintenance') {
      if (!p.id && !p.container) return;
      const nextEnabled = !p.enabled;
      btn.disabled = true;
      try {
        if (p.container) await api('PUT', '/discovered-containers/enabled', { host: p.domain, enabled: nextEnabled });
        else await api('PATCH', `/proxies/${encodeURIComponent(p.id)}`, { enabled: nextEnabled });
        p.enabled = nextEnabled;
        toast(nextEnabled ? t('pxi.reactivate_done') : t('pxi.maintenance_done'), 'success');
        renderBar();
        renderTiles();
      } catch (e) {
        toast(t('pxi.maintenance_err') + (e?.message ? ' : ' + e.message : ''), 'error');
        btn.disabled = false;
      }
    }
  }

  // ── Tuiles des proxies sélectionnés ──────────────────────────────────────
  function sparkline(series) {
    const s = (series || []).map(Number).filter(Number.isFinite);
    if (s.length < 2) return '';
    const max = Math.max(...s, 0.0001);
    const pts = s.map((v, i) => `${(i / (s.length - 1) * 100).toFixed(1)},${(26 - v / max * 24).toFixed(1)}`).join(' ');
    return `<svg class="pxi-spark" viewBox="0 0 100 28" preserveAspectRatio="none"><polyline points="${pts}" fill="none" stroke="var(--accent)" stroke-width="1.5" vector-effect="non-scaling-stroke"/></svg>`;
  }

  function renderTiles() {
    upd('pxi-tiles', pxiSelected.map(d => {
      const p = byDomain.get(d);
      const m = metricOf(d);
      const dot = proxyStatus(p);
      const er = m ? (m.error_rate * 100).toFixed(2) + '%' : '—';
      const maintLabel = p.enabled ? t('pxi.act_maintenance') : t('pxi.act_reactivate');
      const extra = p.backends.length > 1 ? ` +${p.backends.length - 1}` : '';
      const btn = (act, ico, label) => `<button type="button" class="btn btn-ghost btn-icon btn-sm" data-pxi-tile="${act}" data-domain="${esc(d)}" title="${esc(label)}" aria-label="${esc(label)}">${ico}</button>`;
      return `<div class="pxi-tile${p.enabled ? '' : ' off'}">
        <div class="pxi-tile-head">
          <span class="pxi-dot" style="background:${dot.c}" title="${esc(dot.label)}"></span>
          <span class="pxi-tile-name" title="${esc(d)}">${esc(d)}</span>
          ${p.container ? `<span class="chip">${esc(t('pxi.container'))}</span>` : ''}
          <button type="button" class="chip-x" data-pxi-remove="${esc(d)}" aria-label="${esc(t('pxi.remove'))}" title="${esc(t('pxi.remove'))}">×</button>
        </div>
        <div class="pxi-tile-sub mono" title="${esc(p.backends.join(', '))}">${esc((p.backends[0] || '—') + extra)}${pxiScope.node_name ? ' · ' + esc(pxiScope.node_name) : ''}</div>
        <div class="pxi-tile-metrics">
          <div><span>${esc(t('pxi.kpi_rps'))}</span><b>${m ? dashRps(m.requests_per_second) : '—'}</b></div>
          <div><span>${esc(t('pxi.kpi_p95'))}</span><b>${m?.p95_ms ? Math.round(m.p95_ms) + ' ms' : '—'}</b></div>
          <div><span>${esc(t('pxi.kpi_err'))}</span><b style="${m && m.error_rate > 0.01 ? 'color:var(--red)' : ''}">${er}</b></div>
        </div>
        ${sparkline(m?.series)}
        <div class="pxi-tile-actions">
          ${btn('logs', icoLogs, t('pxi.act_logs'))}
          ${btn('prism', icoFull, t('pxi.act_full'))}
          ${p.container ? '' : btn('purge-cache', icoPurge, t('pxi.act_purge'))}
          ${btn('maintenance', p.enabled ? icoPause : icoPlay, maintLabel)}
          ${btn('bans', icoBan, t('pxi.act_bans'))}
        </div>
      </div>`;
    }).join(''));
  }

  async function refreshMetrics() {
    const m = await api('GET', '/metrics/proxies?points=30').catch(() => null);
    if (!m) return;
    metricsByHost = new Map((m.proxies || []).map(x => [(x.host || '').toLowerCase(), x]));
    renderTiles();
    renderBar();
  }

  // ── Données agrégées (période) ───────────────────────────────────────────
  let lastGeo = [];
  let lastPoints = [];

  function baseQuery() {
    const to = new Date(), from = new Date(to - pxiPeriodMs);
    const p = new URLSearchParams({ proxy: pxiSelected.join(','), from: from.toISOString(), to: to.toISOString() });
    if (pxiScope.node_name) p.set('node_name', pxiScope.node_name);
    return p.toString();
  }

  function loadAll() {
    const empty = !pxiSelected.length;
    document.getElementById('pxi-empty').hidden = !empty;
    document.getElementById('pxi-dash').hidden = empty;
    if (empty) return;
    const mySeq = ++_pxiLoadSeq;
    const live = () => mySeq === _pxiLoadSeq && document.getElementById('pxi-root');
    const q = baseQuery();
    const bucket = pxiPeriodMs <= 3.6e6 ? 'minute' : 'hour';
    renderTiles();
    initMap();

    Promise.all([
      api('GET', '/prism/kpis?unique_ips=1&' + q).catch(() => null),
      api('GET', `/prism/timeline?bucket=${bucket}&` + q).catch(() => []),
    ]).then(([kpis, timeline]) => {
      if (!live()) return;
      upd('px-kpis', obsKpisHtml(kpis, Array.isArray(timeline) ? timeline : []));
      upd('px-timeline', obsTimelineHtml(timeline, { live: bucket === 'minute', bucketUnit: bucket }));
    });
    api('GET', '/prism/status?' + q).then(g => live() && upd('px-status', obsStatusHtml(g))).catch(() => {});
    api('GET', '/prism/anomalies?' + q).then(list => live() && upd('px-anoms', obsAnomaliesHtml(Array.isArray(list) ? list : [], { limit: 5 })))
      .catch(() => live() && upd('px-anoms', obsAnomaliesHtml([])));
    api('GET', '/prism/geo?' + q).then(d => { if (!live()) return; lastGeo = Array.isArray(d) ? d : []; applyGeo(); }).catch(() => {});
    api('GET', '/prism/geo/points?limit=1000&' + q).then(d => { if (!live()) return; lastPoints = Array.isArray(d) ? d : []; applyGeo(); }).catch(() => {});
    api('GET', '/prism/paths?limit=10&' + q).then(d => live() && upd('px-paths', pathsHtml(d?.paths || []))).catch(() => live() && upd('px-paths', pathsHtml([])));
    api('GET', '/prism/ips?limit=10&' + q).then(d => live() && upd('px-ips', ipsHtml(Array.isArray(d) ? d : []))).catch(() => live() && upd('px-ips', ipsHtml([])));
    refreshMetrics();
  }

  function pathsHtml(list) {
    const title = `<div class="prism-panel-title">${esc(t('pz.top_paths'))}</div>`;
    if (!list.length) return title + `<p class="prism-muted">${esc(t('prism.no_data'))}</p>`;
    const maxR = Math.max(...list.map(p => p.requests), 1);
    return title + `<table class="prism-table"><thead><tr><th>${esc(t('pxi.path'))}</th><th>${esc(t('prism.req_short'))}</th><th>${esc(t('pxi.kpi_err'))}</th></tr></thead><tbody>${list.map(p => `
      <tr><td class="mono" style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(p.path)}">${esc(p.path)}</td>
        <td>${num(p.requests)} <span class="prism-bar-bg" style="display:inline-block;width:50px;vertical-align:middle"><span class="prism-bar-fill" style="width:${(p.requests / maxR * 100).toFixed(1)}%"></span></span></td>
        <td style="${p.errors ? 'color:var(--red)' : 'color:var(--text3)'}">${num(p.errors)}</td></tr>`).join('')}</tbody></table>`;
  }

  function ipsHtml(list) {
    const title = `<div class="prism-panel-title">${esc(t('pxi.top_ips'))}</div>`;
    if (!list.length) return title + `<p class="prism-muted">${esc(t('prism.no_data'))}</p>`;
    const maxR = Math.max(...list.map(p => p.requests), 1);
    return title + `<table class="prism-table"><thead><tr><th>IP</th><th>${esc(t('prism.req_short'))}</th><th>${esc(t('pxi.kpi_err'))}</th></tr></thead><tbody>${list.map(p => `
      <tr><td class="mono">${esc(p.ip)}</td>
        <td>${num(p.requests)} <span class="prism-bar-bg" style="display:inline-block;width:50px;vertical-align:middle"><span class="prism-bar-fill" style="width:${(p.requests / maxR * 100).toFixed(1)}%"></span></span></td>
        <td style="${p.errors ? 'color:var(--red)' : 'color:var(--text3)'}">${num(p.errors)}</td></tr>`).join('')}</tbody></table>`;
  }

  // ── Carte ────────────────────────────────────────────────────────────────
  async function initMap() {
    if (_pxiGeoCtl) return;
    const container = document.getElementById('pxi-geo-map');
    if (!container) return;
    try {
      container.innerHTML = '';
      const ctl = await gpxGeoMap(container, {});
      ctl.el = container;
      _pxiGeoCtl = ctl;
      applyGeo();
    } catch {
      container.innerHTML = `<p style="color:var(--text3);font-size:12px;padding:16px">${esc(t('pxi.map_unavailable'))}</p>`;
    }
  }

  function applyGeo() {
    document.querySelectorAll('#pxi-root .geo-mode-btn').forEach(b => b.classList.toggle('active', b.dataset.mode === pxiGeoMode));
    document.querySelectorAll('#pxi-root .geo-style-btn').forEach(b => b.classList.toggle('active', b.dataset.style === pxiGeoStyle));
    const keep = e => !(pxiHideInternal && e.country_code === 'LO');
    const countries = lastGeo.filter(keep);
    if (_pxiGeoCtl) _pxiGeoCtl.update({ countries, points: lastPoints.filter(keep), mode: pxiGeoMode, style: pxiGeoStyle, selected: '' });
    renderTopCountries(countries);
  }

  function renderTopCountries(list) {
    const top = geoSortLocalLast(list.filter(e => _geoValue(e, pxiGeoMode) > 0), e => _geoValue(e, pxiGeoMode)).slice(0, 6);
    if (!top.length) { upd('px-topc', wait()); return; }
    const maxV = Math.max(...top.map(e => _geoValue(e, pxiGeoMode)), 1);
    upd('px-topc', top.map((e, i) => {
      const v = _geoValue(e, pxiGeoMode);
      const label = pxiGeoMode === 'error_rate' ? v.toFixed(1) + '%' : num(v);
      const sep = isLocalGeo(e.country_code) && i > 0 && !isLocalGeo(top[i - 1].country_code)
        ? `<div class="prism-toprow-sep">${esc(t('pz.local_sep'))}</div>` : '';
      return `${sep}<div class="prism-toprow" style="cursor:default">
        <span class="prism-toprow-flag">${flagOf(e.country_code)}</span>
        <span class="prism-toprow-main"><span class="prism-toprow-head"><span>${esc(e.country_name)}</span><b>${label}</b></span>
        <span class="prism-bar-bg"><span class="prism-bar-fill" style="width:${(v / maxV * 100).toFixed(1)}%"></span></span></span>
      </div>`;
    }).join(''));
  }

  // ── Live (uniquement sur demande) ────────────────────────────────────────
  function toggleLive(on) {
    pxiLive = on;
    pxiStopLive();
    document.getElementById('pxi-live-panel').hidden = !on;
    if (on) {
      _pxiLiveLastTs = new Date().toISOString();
      upd('pxi-live-feed', wait());
      _pxiLiveTimer = setInterval(tickLive, PXI_LIVE_INTERVAL_MS);
      tickLive();
    }
    renderBar();
  }

  // Fusionne les événements consécutifs identiques (même IP/domaine/kind) en une ligne
  // avec un compteur (même logique que Prism).
  function collapseLiveFeed(events) {
    const out = [];
    for (const ev of events) {
      const last = out[out.length - 1];
      if (last && last.ip === ev.ip && last.domain === ev.domain && last.kind === ev.kind) last.count = (last.count || 1) + 1;
      else out.push({ ...ev, count: 1 });
    }
    return out;
  }

  async function tickLive() {
    if (!document.getElementById('pxi-root')) { pxiStopLive(); return; }
    if (!pxiLive || !pxiSelected.length) return;
    // Les agrégats de la période suivent le flux : rafraîchis toutes les ~20 s.
    if (++_pxiLiveTick % PXI_LIVE_REFRESH_TICKS === 0) loadAll();
    const since = _pxiLiveLastTs || new Date(Date.now() - PXI_LIVE_INTERVAL_MS * 2).toISOString();
    const qs = new URLSearchParams({ since, limit: '50', proxy: pxiSelected.join(',') });
    if (pxiScope.node_name) qs.set('node_name', pxiScope.node_name);
    const events = await api('GET', '/prism/live-ips?' + qs.toString()).catch(() => []);
    if (!pxiLive || !Array.isArray(events) || !events.length) return;
    _pxiLiveLastTs = events[0].ts || new Date().toISOString();
    const visible = events.filter(e => !(pxiHideInternal && e.country_code === 'LO'));
    const fresh = visible.filter(e => !_pxiLiveFeed.some(f => f.ip === e.ip && f.ts === e.ts));
    if (!fresh.length) return;
    _pxiLiveFeed = collapseLiveFeed([...fresh, ..._pxiLiveFeed]).slice(0, PXI_LIVE_FEED_MAX);
    renderFeed();
    if (_pxiGeoCtl) _pxiGeoCtl.pulse(fresh);
  }

  function renderFeed() {
    if (!_pxiLiveFeed.length) { upd('pxi-live-feed', wait()); return; }
    const kindColor = k => k === 'banned' ? 'var(--red)' : k === 'error' ? 'var(--yellow)' : 'var(--accent)';
    const kindLabel = k => k === 'banned' ? 'BAN' : k === 'error' ? 'ERR' : 'OK';
    upd('pxi-live-feed', _pxiLiveFeed.slice(0, 25).map(ev => {
      const ts = ev.ts ? ev.ts.replace('T', ' ').slice(11, 19) : '';
      return `<div class="live-feed-row">
        <span class="live-feed-kind" style="color:${kindColor(ev.kind)}">${kindLabel(ev.kind)}</span>
        <span class="live-feed-flag">${flagOf(ev.country_code)}</span>
        <code class="live-feed-ip">${esc(ev.ip)}</code>
        <span class="live-feed-domain" title="${esc(ev.domain || '')}">${esc(ev.domain || '')}</span>
        ${ev.count > 1 ? `<span class="live-feed-count" title="${ev.count} occurrences">×${ev.count}</span>` : ''}
        <span class="live-feed-ts">${ts}</span>
      </div>`;
    }).join(''));
  }

  // ── Événements ───────────────────────────────────────────────────────────
  const root = document.getElementById('pxi-root');
  const search = document.getElementById('pxi-search');

  search.addEventListener('input', () => { sgHl = 0; renderSuggest(); });
  search.addEventListener('focus', renderSuggest);
  search.addEventListener('keydown', e => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      if (!sgItems.length) return;
      e.preventDefault();
      sgHl = (sgHl + (e.key === 'ArrowDown' ? 1 : -1) + Math.min(sgItems.length, 12)) % Math.min(sgItems.length, 12);
      renderSuggest();
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (e.shiftKey) addProxies(sgItems.map(p => p.domain));
      else if (sgItems[sgHl]) addProxies([sgItems[sgHl].domain]);
    } else if (e.key === 'Escape') {
      search.value = '';
      renderSuggest();
    }
  });
  document.addEventListener('click', e => {
    if (!document.getElementById('pxi-root')) return;
    if (!e.target.closest('.pxi-search-wrap')) { const b = document.getElementById('pxi-suggest'); if (b) b.hidden = true; }
  });

  root.addEventListener('change', e => {
    if (e.target.id !== 'pxi-hide-internal') return;
    pxiHideInternal = !!e.target.checked;
    applyGeo();
  });

  root.addEventListener('click', e => {
    const add = e.target.closest('[data-pxi-add]');
    if (add) { addProxies([add.getAttribute('data-pxi-add')]); return; }
    const rem = e.target.closest('[data-pxi-remove]');
    if (rem) {
      pxiSelected = pxiSelected.filter(d => d !== rem.getAttribute('data-pxi-remove'));
      selectionChanged();
      return;
    }
    const per = e.target.closest('[data-pxi-period]');
    if (per) {
      pxiPeriodMs = parseInt(per.getAttribute('data-pxi-period'), 10) || 8.64e7;
      renderBar();
      loadAll();
      return;
    }
    const tile = e.target.closest('[data-pxi-tile]');
    if (tile) {
      const p = byDomain.get(tile.getAttribute('data-domain'));
      if (p) onTileAction(tile.getAttribute('data-pxi-tile'), p, tile);
      return;
    }
    const act = e.target.closest('[data-pxi]');
    if (!act) return;
    const a = act.getAttribute('data-pxi');
    if (a === 'live') toggleLive(!pxiLive);
    else if (a === 'clear') { pxiSelected = []; selectionChanged(); }
    else if (a === 'add-all') addProxies(sgItems.map(p => p.domain));
    else if (a === 'mode') { pxiGeoMode = act.dataset.mode || 'requests'; applyGeo(); }
    else if (a === 'style') { pxiGeoStyle = act.dataset.style || 'zones'; applyGeo(); }
  });

  renderBar();
  loadAll();
}
