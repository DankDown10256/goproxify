// ── PAGE: Poste de contrôle proxy (Admin + Passerelle) ───────────────────────
// Menu Observabilité > Vue Proxy : sélection d'un proxy dans une liste, puis
// visualisation temps réel (carte "Trafic par pays" — même config que Prism —
// avec flux de connexions en direct intégré, KPIs, anomalies, actions rapides).
//   Admin (proxy-inspector)      → tous les proxies, toutes passerelles
//   Passerelle (edge-proxy-inspector) → node_name verrouillé
// Réutilise gpxGeoMap (shared/geomap.js), obsAnomaliesHtml (shared/obs-widgets.js),
// openPrismForProxy et openLogsFiltered.

let _pxiGeoCtl = null;
let _pxiLiveTimer = null;
let _pxiLiveLastTs = null;
let _pxiLiveFeed = [];
let _pxiCountryStats = new Map(); // country_code -> {country_code, country_name, requests, errors, bannedIPs:Set}
const PXI_LIVE_INTERVAL_MS = 4000;
const PXI_LIVE_FEED_MAX = 40;

let pxiScope = { node_name: '', lock: false };
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
      id: p.id, domain, target: backends[0] || '', enabled: p.enabled !== false,
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

  // ── Icônes (actions rapides) ───────────────────────────────────────────────
  const icoFull = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 20V10M12 20V4M6 20v-6"/></svg>`;
  const icoPurge = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 1 1-2.64-6.36"/><polyline points="21 3 21 9 15 9"/></svg>`;
  const icoPause = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/></svg>`;
  const icoPlay = `<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" stroke="none"><path d="M7 4l13 8-13 8z"/></svg>`;
  const icoBan = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>`;

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
    const maintLabel = p.enabled ? t('pxi.act_maintenance') : t('pxi.act_reactivate');

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
          <div class="pxi-panel" id="pxi-geo-panel" style="min-height:80px">${spinnerSmall()}</div>
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
              <button type="button" class="btn btn-ghost btn-icon btn-sm" data-pxi="purge-cache" title="${esc(t('pxi.act_purge'))}" aria-label="${esc(t('pxi.act_purge'))}">${icoPurge}</button>
              <button type="button" class="btn btn-ghost btn-icon btn-sm" data-pxi="maintenance" title="${esc(maintLabel)}" aria-label="${esc(maintLabel)}">${p.enabled ? icoPause : icoPlay}</button>
              <button type="button" class="btn btn-ghost btn-icon btn-sm" data-pxi="bans" title="${esc(t('pxi.act_bans'))}" aria-label="${esc(t('pxi.act_bans'))}">${icoBan}</button>
              <button type="button" class="btn btn-ghost btn-icon btn-sm" data-pxi="prism" title="${esc(t('pxi.act_analytics'))}" aria-label="${esc(t('pxi.act_analytics'))}">${icoFull}</button>
            </div>
          </div>
        </div>
      </div>`;

    det.querySelectorAll('[data-pxi]').forEach(btn => {
      btn.addEventListener('click', () => onDetailAction(btn.getAttribute('data-pxi'), p, btn));
    });

    const nodeQS = pxiScope.node_name ? '&node_name=' + encodeURIComponent(pxiScope.node_name) : '';
    const to = new Date(), from = new Date(to - 3600000);
    const q = `proxy=${encodeURIComponent(p.domain)}${nodeQS}&from=${from.toISOString()}&to=${to.toISOString()}`;

    document.getElementById('pxi-geo-panel').innerHTML = geoPanelHtml();
    wireGeoPanel();
    initMap();

    api('GET', '/prism/anomalies?' + q).then(list => {
      const el = document.getElementById('pxi-anoms');
      if (el) el.innerHTML = obsAnomaliesHtml(Array.isArray(list) ? list : [], { limit: 4 });
    }).catch(() => {
      const el = document.getElementById('pxi-anoms');
      if (el) el.innerHTML = obsAnomaliesHtml([]);
    });

    startLive(p.domain);
  }

  async function onDetailAction(act, p, btn) {
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
      if (!p.id) return;
      const nextEnabled = !p.enabled;
      btn.disabled = true;
      try {
        await api('PATCH', `/proxies/${encodeURIComponent(p.id)}`, { enabled: nextEnabled });
        p.enabled = nextEnabled;
        toast(nextEnabled ? t('pxi.reactivate_done') : t('pxi.maintenance_done'), 'success');
        renderList();
        renderDetail();
      } catch (e) {
        toast(t('pxi.maintenance_err') + (e?.message ? ' : ' + e.message : ''), 'error');
        btn.disabled = false;
      }
    }
  }

  // ── Carte "Trafic par pays" (même configuration que Prism) + flux live ────
  function geoPanelHtml() {
    const liveFeedHtml = `
      <div id="pxi-live-feed-wrap" style="border-top:1px solid var(--border);margin-top:10px;padding-top:8px">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap">
          <span class="logs-live-dot"></span>
          <span style="font-size:11px;font-weight:600;color:var(--text2)">${esc(t('pz.live_conns'))}</span>
          <label class="logs-toggle-inline" style="margin-left:auto">
            <span class="toggle"><input type="checkbox" id="pxi-hide-internal" ${pxiHideInternal ? 'checked' : ''} data-pxi-geo="hide-internal"><span class="toggle-slider"></span></span>
            ${esc(t('logs.hide_internal'))}
          </label>
        </div>
        <div id="pxi-live-feed" style="max-height:220px;overflow-y:auto;font-size:11px">${spinnerSmall()}</div>
      </div>`;
    return `
      <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:8px;flex-wrap:wrap">
        <span class="prism-panel-title" style="margin:0">${esc(t('pz.by_country'))} <span class="logs-live-dot" style="margin-left:6px"></span></span>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <div class="btn-group" role="group" aria-label="Vue">
            <button type="button" class="btn btn-xs geo-mode-btn ${pxiGeoMode === 'requests' ? 'active' : ''}" data-pxi-geo="mode" data-mode="requests">${esc(t('prism.requests'))}</button>
            <button type="button" class="btn btn-xs geo-mode-btn ${pxiGeoMode === 'error_rate' ? 'active' : ''}" data-pxi-geo="mode" data-mode="error_rate">${esc(t('pz.err_rate_short'))}</button>
            <button type="button" class="btn btn-xs geo-mode-btn ${pxiGeoMode === 'banned_ips' ? 'active' : ''}" data-pxi-geo="mode" data-mode="banned_ips">${esc(t('pz.banned_ips'))}</button>
          </div>
          <div class="btn-group" role="group" aria-label="Style">
            <button type="button" class="btn btn-xs geo-style-btn ${pxiGeoStyle === 'zones' ? 'active' : ''}" data-pxi-geo="style" data-style="zones">${esc(t('sy.atk_zones'))}</button>
            <button type="button" class="btn btn-xs geo-style-btn ${pxiGeoStyle === 'cities' ? 'active' : ''}" data-pxi-geo="style" data-style="cities">${esc(t('sy.atk_cities'))}</button>
            <button type="button" class="btn btn-xs geo-style-btn ${pxiGeoStyle === 'regions' ? 'active' : ''}" data-pxi-geo="style" data-style="regions">${esc(t('sy.atk_regions'))}</button>
          </div>
        </div>
      </div>
      <div id="pxi-geo-map" class="prism-mapbox gm-box" style="min-height:260px"><div class="spinner" style="margin:80px auto"></div></div>
      <div id="pxi-geo-top" style="margin-top:10px">${spinnerSmall()}</div>
      ${liveFeedHtml}`;
  }

  function wireGeoPanel() {
    const panel = document.getElementById('pxi-geo-panel');
    if (!panel || panel.dataset.pxiWired) return;
    panel.dataset.pxiWired = '1';
    panel.addEventListener('click', e => {
      const el = e.target.closest('[data-pxi-geo]');
      if (!el) return;
      const act = el.getAttribute('data-pxi-geo');
      if (act === 'mode') { pxiGeoMode = el.dataset.mode || 'requests'; applyGeo(); }
      else if (act === 'style') { pxiGeoStyle = el.dataset.style || 'zones'; applyGeo(); }
    });
    panel.addEventListener('change', e => {
      const el = e.target.closest('[data-pxi-geo="hide-internal"]');
      if (!el) return;
      pxiHideInternal = !!el.checked;
    });
  }

  // Regroupement des IP publiques par pays — calculé uniquement à partir du flux
  // live (/prism/live-ips), jamais d'un agrégat historique : la Vue Proxy est un
  // poste de contrôle temps réel, pas un outil d'analyse a posteriori (→ Prism).
  function countryStatsList() {
    const list = [];
    for (const s of _pxiCountryStats.values()) {
      const requests = s.requests;
      list.push({
        country_code: s.country_code, country_name: s.country_name,
        requests, errors: s.errors, error_rate: requests ? (s.errors / requests * 100) : 0,
        banned_ips: s.bannedIPs.size,
      });
    }
    const total = list.reduce((sum, e) => sum + e.requests, 0) || 1;
    for (const e of list) e.pct = e.requests / total * 100;
    return list;
  }

  function accumulateGeo(events) {
    for (const ev of events) {
      const cc = ev.country_code || 'XX';
      let s = _pxiCountryStats.get(cc);
      if (!s) {
        s = { country_code: cc, country_name: ev.country_name || cc, requests: 0, errors: 0, bannedIPs: new Set() };
        _pxiCountryStats.set(cc, s);
      }
      s.requests++;
      if (ev.kind === 'error') s.errors++;
      if (ev.kind === 'banned' && ev.ip) s.bannedIPs.add(ev.ip);
    }
  }

  async function initMap() {
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
    document.querySelectorAll('#pxi-geo-panel .geo-mode-btn').forEach(b => b.classList.toggle('active', b.dataset.mode === pxiGeoMode));
    document.querySelectorAll('#pxi-geo-panel .geo-style-btn').forEach(b => b.classList.toggle('active', b.dataset.style === pxiGeoStyle));
    const list = countryStatsList();
    if (_pxiGeoCtl) _pxiGeoCtl.update({ countries: list, points: [], mode: pxiGeoMode, style: pxiGeoStyle, selected: '' });
    renderTopCountries(list);
  }

  function renderTopCountries(list) {
    const el = document.getElementById('pxi-geo-top');
    if (!el) return;
    if (!list.length) { el.innerHTML = spinnerSmall(); return; }
    const flagOf = cc => (!cc || cc.length !== 2 || cc === 'XX' || cc === 'LO') ? '🌐' : String.fromCodePoint(0x1F1E6 + cc.charCodeAt(0) - 65, 0x1F1E6 + cc.charCodeAt(1) - 65);
    const top = geoSortLocalLast(list.filter(e => _geoValue(e, pxiGeoMode) > 0), e => _geoValue(e, pxiGeoMode)).slice(0, 6);
    if (!top.length) { el.innerHTML = spinnerSmall(); return; }
    const maxV = Math.max(...top.map(e => _geoValue(e, pxiGeoMode)), 1);
    el.innerHTML = top.map((e, i) => {
      const v = _geoValue(e, pxiGeoMode);
      const label = pxiGeoMode === 'error_rate' ? v.toFixed(1) + '%' : fmtNum(v);
      const sep = isLocalGeo(e.country_code) && i > 0 && !isLocalGeo(top[i - 1].country_code)
        ? `<div class="prism-toprow-sep">${esc(t('pz.local_sep'))}</div>` : '';
      return `${sep}<div class="prism-toprow" style="cursor:default">
        <span class="prism-toprow-flag">${flagOf(e.country_code)}</span>
        <span class="prism-toprow-main"><span class="prism-toprow-head"><span>${esc(e.country_name)}</span><b>${label}</b></span>
        <span class="prism-bar-bg"><span class="prism-bar-fill" style="width:${(v / maxV * 100).toFixed(1)}%"></span></span></span>
      </div>`;
    }).join('');
  }

  function spinnerSmall() { return `<div style="color:var(--text3);font-size:12px;padding:8px 0">${esc(t('pxi.wait_traffic'))}</div>`; }

  function stopLive() {
    if (_pxiLiveTimer) { clearInterval(_pxiLiveTimer); _pxiLiveTimer = null; }
    if (_pxiGeoCtl) { _pxiGeoCtl.destroy(); _pxiGeoCtl = null; }
    _pxiLiveFeed = [];
    _pxiLiveLastTs = null;
  }

  const isInternalLiveEvent = e => pxiHideInternal && e.country_code === 'LO';

  // Fusionne les événements consécutifs identiques (même IP/domaine/kind — scan ou
  // tentative répétée) en une seule ligne avec un compteur (même logique que Prism).
  function collapseLiveFeed(events) {
    const out = [];
    for (const ev of events) {
      const last = out[out.length - 1];
      if (last && last.ip === ev.ip && last.domain === ev.domain && last.kind === ev.kind) {
        last.count = (last.count || 1) + 1;
      } else {
        out.push({ ...ev, count: 1 });
      }
    }
    return out;
  }

  function startLive(domain) {
    _pxiLiveLastTs = new Date().toISOString();
    _pxiLiveFeed = [];
    _pxiCountryStats = new Map();
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

      // Regroupement par pays (carte + Top pays) : sur tous les événements, IP internes incluses.
      accumulateGeo(events);
      applyGeo();

      const visible = events.filter(e => !isInternalLiveEvent(e));
      const newEvts = visible.filter(e => !_pxiLiveFeed.some(f => f.ip === e.ip && f.ts === e.ts));
      if (!newEvts.length) return;
      _pxiLiveFeed = collapseLiveFeed([...newEvts, ..._pxiLiveFeed]).slice(0, PXI_LIVE_FEED_MAX);
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
        ${ev.count > 1 ? `<span class="live-feed-count" title="${ev.count} occurrences">×${ev.count}</span>` : ''}
        <span class="live-feed-ts">${ts}</span>
      </div>`;
    }).join('');
  }

  renderDetail();
}
