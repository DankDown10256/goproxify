// ── PAGE: Poste de contrôle proxy (Admin + Passerelle) ───────────────────────
// Remplace l'ancien menu "Explorer" : sélection d'un proxy dans une liste, puis
// visualisation temps réel (carte, flux de requêtes live, KPIs, sécurité).
//   Admin (proxy-inspector)      → tous les proxies, toutes passerelles
//   Passerelle (edge-proxy-inspector) → node_name verrouillé
// Réutilise gpxGeoMap (shared/geomap.js), obsAnomaliesHtml (shared/obs-widgets.js),
// openPrismForProxy et openLogsFiltered.

let _pxiGeoCtl = null;
let _pxiLiveTimer = null;
let _pxiLiveLastTs = null;
let _pxiLiveFeed = [];
const PXI_LIVE_INTERVAL_MS = 4000;
const PXI_LIVE_FEED_MAX = 40;

let pxiScope = { node_name: '', lock: false };

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

async function renderProxyInspector() {
  if (_pxiGeoCtl) { _pxiGeoCtl.destroy(); _pxiGeoCtl = null; }
  if (_pxiLiveTimer) { clearInterval(_pxiLiveTimer); _pxiLiveTimer = null; }

  const main = document.getElementById('content');
  main.innerHTML = `<div class="pxi-root"><div class="spinner" style="margin:60px auto"></div></div>`;

  const proxiesPath = pxiScope.lock && pxiScope.node_name
    ? `/proxies?edge=${encodeURIComponent(pxiScope.node_name)}`
    : '/proxies';
  const [proxiesRaw, metrics] = await Promise.all([
    api('GET', proxiesPath).catch(() => []),
    api('GET', '/metrics/proxies?points=1').catch(() => null),
  ]);

  const byHost = new Map((metrics?.proxies || []).map(m => [(m.host || '').toLowerCase(), m]));
  const getCfg = p => {
    if (!p.config) return {};
    if (typeof p.config === 'object') return p.config;
    try { return JSON.parse(p.config) || {}; } catch { return {}; }
  };
  let proxies = (proxiesRaw || []).map(p => {
    const cfg = getCfg(p);
    const domain = cfg.host || p.host || p.name || p.id || '';
    const backends = (cfg.backends || p.backends || []).map(b => b.url || b).filter(Boolean);
    return {
      domain, target: backends[0] || '', enabled: p.enabled !== false,
      m: byHost.get(domain.toLowerCase()) || null,
    };
  }).filter(p => p.domain);

  let search = '';
  let selected = proxies.find(p => p.enabled)?.domain || proxies[0]?.domain || '';

  const root = document.getElementById('content');
  root.innerHTML = `
    <div class="pxi-root">
      <div class="pxi-list">
        <div class="pxi-list-head">
          <div class="pxi-list-title">${esc(t('pxi.title'))} <span class="pxi-count">${proxies.length}</span></div>
          <input type="text" id="pxi-search" class="form-input" style="width:100%" placeholder="${esc(t('pxi.search'))}">
        </div>
        <div id="pxi-list-body" class="pxi-list-body"></div>
      </div>
      <div id="pxi-detail" class="pxi-detail"></div>
    </div>`;

  function pxiDot(p) {
    if (!p.enabled) return { c: 'var(--text3)', label: t('pxi.disabled') };
    const er = p.m?.error_rate || 0;
    const p95 = p.m?.p95_ms || 0;
    if (er > 0.05) return { c: 'var(--red)', label: t('pxi.status_error') };
    if (er > 0.01 || p95 > 300) return { c: 'var(--yellow)', label: t('pxi.status_degraded') };
    return { c: 'var(--green)', label: t('pxi.status_ok') };
  }

  function renderList() {
    const body = document.getElementById('pxi-list-body');
    if (!body) return;
    const q = search.trim().toLowerCase();
    const filtered = q ? proxies.filter(p => p.domain.toLowerCase().includes(q)) : proxies;
    const sorted = [...filtered].sort((a, b) => (b.m?.requests_per_second || 0) - (a.m?.requests_per_second || 0));
    if (!sorted.length) {
      body.innerHTML = `<div class="pxi-empty">${esc(t('pxi.none'))}</div>`;
      return;
    }
    body.innerHTML = sorted.map(p => {
      const dot = pxiDot(p);
      const rps = p.m ? dashRps(p.m.requests_per_second) : '—';
      const p95 = p.m?.p95_ms ? Math.round(p.m.p95_ms) + ' ms' : '—';
      return `<button type="button" class="pxi-row${p.domain === selected ? ' active' : ''}" data-pxi-select="${esc(p.domain)}">
        <span class="pxi-dot" style="background:${dot.c}" title="${esc(dot.label)}"></span>
        <span class="pxi-row-main">
          <span class="pxi-row-name">${esc(p.domain)}</span>
          <span class="pxi-row-sub mono">${esc(p.target || '—')}</span>
        </span>
        <span class="pxi-row-metrics">
          <span class="mono">${rps}</span>
          <span class="mono" style="color:var(--text3)">${p95}</span>
        </span>
      </button>`;
    }).join('');
  }

  renderList();

  document.getElementById('pxi-search')?.addEventListener('input', e => {
    search = e.target.value || '';
    renderList();
  });
  document.getElementById('pxi-list-body')?.addEventListener('click', e => {
    const btn = e.target.closest('[data-pxi-select]');
    if (!btn) return;
    selected = btn.getAttribute('data-pxi-select') || '';
    renderList();
    renderDetail();
  });

  async function renderDetail() {
    stopLive();
    const p = proxies.find(x => x.domain === selected);
    const det = document.getElementById('pxi-detail');
    if (!det) return;
    if (!p) { det.innerHTML = `<div class="pxi-empty" style="padding:60px 0">${esc(t('pxi.pick_one'))}</div>`; return; }

    const dot = pxiDot(p);
    const rps = p.m ? dashRps(p.m.requests_per_second) : '—';
    const p95 = p.m?.p95_ms ? Math.round(p.m.p95_ms) + ' ms' : '—';
    const er = p.m ? (p.m.error_rate * 100).toFixed(2) + '%' : '—';

    det.innerHTML = `
      <div class="pxi-dhead">
        <div>
          <div class="pxi-dtitle-row">
            <h1 class="pxi-dtitle">${esc(p.domain)}</h1>
            <span class="pxi-badge" style="--c:${dot.c}"><span class="pxi-dot" style="background:${dot.c}"></span>${esc(dot.label)}</span>
          </div>
          <div class="mono pxi-dsub">${esc(p.target || '—')}${pxiScope.node_name ? ' · ' + esc(pxiScope.node_name) : ''}</div>
        </div>
        <div class="pxi-dactions">
          <button type="button" class="btn btn-secondary btn-sm" data-pxi="logs">${esc(t('pxi.act_logs'))}</button>
          <button type="button" class="btn btn-primary btn-sm" data-pxi="prism">${esc(t('pxi.act_full'))}</button>
        </div>
      </div>

      <div class="pxi-dbody">
        <div class="pxi-dcenter">
          <div class="pxi-panel" style="padding:0;overflow:hidden">
            <div class="pxi-panel-title" style="padding:14px 16px 0">${esc(t('pxi.map_title'))} <span class="logs-live-dot" style="margin-left:6px"></span></div>
            <div id="pxi-geo-map" class="prism-mapbox gm-box" style="height:300px;margin:10px 14px 0;width:calc(100% - 28px)"><div class="spinner" style="margin:100px auto"></div></div>
            <div class="pxi-feed-wrap">
              <div class="pxi-panel-title" style="padding:0 16px">${esc(t('pxi.feed_title'))}</div>
              <div id="pxi-live-feed" class="pxi-feed">${spinnerSmall()}</div>
            </div>
          </div>
        </div>
        <div class="pxi-dside">
          <div class="pxi-kpis">
            <div class="pxi-kpi"><span>${esc(t('pxi.kpi_rps'))}</span><b>${rps}</b></div>
            <div class="pxi-kpi"><span>${esc(t('pxi.kpi_p95'))}</span><b>${p95}</b></div>
            <div class="pxi-kpi"><span>${esc(t('pxi.kpi_err'))}</span><b style="${p.m && p.m.error_rate > 0.01 ? 'color:var(--red)' : ''}">${er}</b></div>
          </div>
          <div class="pxi-panel">
            <div class="pxi-panel-title">${esc(t('pxi.security_title'))}</div>
            <div id="pxi-anoms"><p class="prism-muted">${esc(t('pxi.loading'))}</p></div>
          </div>
          <div class="pxi-panel">
            <div class="pxi-panel-title">${esc(t('pxi.actions_title'))}</div>
            <div class="pxi-quick-actions">
              <button type="button" class="btn btn-secondary btn-sm" data-pxi="bans">${esc(t('pxi.act_bans'))}</button>
              <button type="button" class="btn btn-secondary btn-sm" data-pxi="prism">${esc(t('pxi.act_analytics'))}</button>
            </div>
          </div>
        </div>
      </div>`;

    det.querySelectorAll('[data-pxi]').forEach(btn => {
      btn.addEventListener('click', () => {
        const act = btn.getAttribute('data-pxi');
        if (act === 'logs') {
          if (typeof openLogsFiltered === 'function') openLogsFiltered({ domain: p.domain, node_name: pxiScope.node_name || '' });
        } else if (act === 'prism' || act === 'act_analytics') {
          if (typeof window.openPrismForProxy === 'function') window.openPrismForProxy(p.domain, pxiScope.node_name);
        } else if (act === 'bans') {
          navigate(state.selectedEdge ? 'edge-security-bans' : 'security-bans');
        }
      });
    });

    const nodeQS = pxiScope.node_name ? '&node_name=' + encodeURIComponent(pxiScope.node_name) : '';
    const to = new Date(), from = new Date(to - 3600000);
    const q = `proxy=${encodeURIComponent(p.domain)}${nodeQS}&from=${from.toISOString()}&to=${to.toISOString()}`;

    api('GET', '/prism/anomalies?' + q).then(list => {
      const el = document.getElementById('pxi-anoms');
      if (el) el.innerHTML = obsAnomaliesHtml(Array.isArray(list) ? list : [], { limit: 4 });
    }).catch(() => {
      const el = document.getElementById('pxi-anoms');
      if (el) el.innerHTML = obsAnomaliesHtml([]);
    });

    api('GET', '/prism/geo?' + q).then(geo => buildMap(geo || [])).catch(() => buildMap([]));

    startLive(p.domain);
  }

  async function buildMap(geo) {
    const container = document.getElementById('pxi-geo-map');
    if (!container) return;
    if (!geo.length) {
      container.innerHTML = `<p style="color:var(--text3);font-size:12px;padding:16px">${esc(t('pxi.map_empty'))}</p>`;
      return;
    }
    try {
      container.innerHTML = '';
      const ctl = await gpxGeoMap(container, {});
      ctl.el = container;
      _pxiGeoCtl = ctl;
      ctl.update({ countries: geo, points: [], mode: 'requests', style: 'zones', selected: '' });
    } catch {
      container.innerHTML = `<p style="color:var(--text3);font-size:12px;padding:16px">${esc(t('pxi.map_unavailable'))}</p>`;
    }
  }

  function spinnerSmall() { return `<div style="color:var(--text3);font-size:12px;padding:8px 0">${esc(t('pxi.wait_traffic'))}</div>`; }

  function stopLive() {
    if (_pxiLiveTimer) { clearInterval(_pxiLiveTimer); _pxiLiveTimer = null; }
    if (_pxiGeoCtl) { _pxiGeoCtl.destroy(); _pxiGeoCtl = null; }
    _pxiLiveFeed = [];
    _pxiLiveLastTs = null;
  }

  function startLive(domain) {
    _pxiLiveLastTs = new Date().toISOString();
    _pxiLiveFeed = [];
    _pxiLiveTimer = setInterval(() => tickLive(domain), PXI_LIVE_INTERVAL_MS);
    tickLive(domain);
  }

  async function tickLive(domain) {
    if (selected !== domain) return;
    const since = _pxiLiveLastTs || new Date(Date.now() - PXI_LIVE_INTERVAL_MS * 2).toISOString();
    const qs = new URLSearchParams({ since, limit: '50', proxy: domain });
    if (pxiScope.node_name) qs.set('node_name', pxiScope.node_name);
    try {
      const events = await api('GET', '/prism/live-ips?' + qs.toString()).catch(() => []);
      if (!Array.isArray(events) || !events.length) return;
      _pxiLiveLastTs = events[0].ts || new Date().toISOString();
      const newEvts = events.filter(e => !_pxiLiveFeed.some(f => f.ip === e.ip && f.ts === e.ts));
      if (!newEvts.length) return;
      _pxiLiveFeed = [...newEvts, ..._pxiLiveFeed].slice(0, PXI_LIVE_FEED_MAX);
      renderFeed();
      if (_pxiGeoCtl) _pxiGeoCtl.pulse(newEvts);
    } catch { /* ignore */ }
  }

  function renderFeed() {
    const el = document.getElementById('pxi-live-feed');
    if (!el) return;
    if (!_pxiLiveFeed.length) { el.innerHTML = spinnerSmall(); return; }
    const flag = cc => {
      if (!cc || cc.length !== 2 || cc === 'XX' || cc === 'LO') return '🌐';
      try { return String.fromCodePoint(0x1F1E6 + cc.charCodeAt(0) - 65, 0x1F1E6 + cc.charCodeAt(1) - 65); } catch { return '🌐'; }
    };
    const kindColor = k => k === 'banned' ? 'var(--red)' : k === 'error' ? 'var(--yellow)' : 'var(--accent)';
    const kindLabel = k => k === 'banned' ? 'BAN' : k === 'error' ? 'ERR' : 'OK';
    el.innerHTML = _pxiLiveFeed.slice(0, 20).map(ev => {
      const ts = ev.ts ? ev.ts.replace('T', ' ').slice(11, 19) : '';
      return `<div class="live-feed-row">
        <span class="live-feed-kind" style="color:${kindColor(ev.kind)}">${kindLabel(ev.kind)}</span>
        <span class="live-feed-flag">${flag(ev.country_code)}</span>
        <code class="live-feed-ip">${esc(ev.ip)}</code>
        <span class="live-feed-domain" title="${esc(ev.domain || '')}">${esc(ev.domain || '')}</span>
        <span class="live-feed-ts">${ts}</span>
      </div>`;
    }).join('');
  }

  renderDetail();
}
