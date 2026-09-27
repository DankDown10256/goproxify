// ── PAGE: Observabilité › Synthèse (Admin + Passerelle) ─────────────────────
// Une seule vue ; le menu ne pose qu'un filtre de périmètre.
//   Admin (obs-synthese)            → toutes les passerelles
//   Passerelle (edge-obs-synthese)  → node_name verrouillé sur la passerelle sélectionnée
// Les blocs (KPI, courbe, codes HTTP, anomalies) sont ceux de Prism (shared/obs-widgets.js).

const OBS_RANGES = [['15 min', 900000], ['1h', 3600000], ['6h', 21600000], ['24h', 86400000], ['7j', 604800000]];
let _obsSynRangeMs = 86400000;
let _obsSynNode = '';

pages['obs-synthese'] = function() { renderObsSynthese({ node_name: '', lock: false }); };
pages['edge-obs-synthese'] = function() { renderObsSynthese({ node_name: edgePrismNodeName(), lock: true }); };

async function renderObsSynthese(scope) {
  const main = document.getElementById('content');
  const node = scope.lock ? scope.node_name : _obsSynNode;
  const now = new Date();
  const from = new Date(now - _obsSynRangeMs);
  const q = new URLSearchParams({ from: from.toISOString(), to: now.toISOString() });
  if (node) q.set('node_name', node);
  const qs = q.toString();
  const bucket = _obsSynRangeMs <= 21600000 ? 'minute' : 'hour';

  main.innerHTML = `<div class="spinner" style="margin:60px auto"></div>`;

  const allEdges = scope.lock ? [] : ((await api('GET', '/nodes').catch(() => [])) || []).filter(n => n.role === 'edge');
  const [kpis, uniq, timeline, status, geo, anoms, backends, domains, slo, edgeKpis] = await Promise.all([
    api('GET', '/prism/kpis?' + qs).catch(() => ({})),
    api('GET', '/prism/unique-ips?' + qs).catch(() => ({})),
    api('GET', `/prism/timeline?${qs}&bucket=${bucket}`).catch(() => []),
    api('GET', '/prism/status?' + qs).catch(() => []),
    api('GET', '/prism/geo?' + qs).catch(() => []),
    api('GET', '/prism/anomalies?' + qs).catch(() => []),
    api('GET', '/prism/backend-errors?' + qs).catch(() => []),
    api('GET', '/domains').catch(() => []),
    api('GET', '/prism/slo' + (node ? '?node_name=' + encodeURIComponent(node) : '')).catch(() => null),
    Promise.all((node ? [] : allEdges.slice(0, 12)).map(n => {
      const p = new URLSearchParams({ from: from.toISOString(), to: now.toISOString(), node_name: n.node_name || n.display_name || n.id });
      return api('GET', '/prism/kpis?' + p).catch(() => ({}));
    })),
  ]);

  const rangeBtns = OBS_RANGES.map(([l, ms]) =>
    `<button type="button" class="btn btn-secondary btn-sm${ms === _obsSynRangeMs ? ' is-active' : ''}" data-obs="range" data-ms="${ms}">${l}</button>`).join('');
  const nodeSel = scope.lock ? '' : `
    <select class="form-input" style="max-width:200px" data-obs="node">
      <option value="">${esc(t('obs.syn.all_edges'))}</option>
      ${allEdges.map(n => { const v = n.node_name || n.display_name || n.id; return `<option value="${esc(v)}" ${v === node ? 'selected' : ''}>${esc(n.display_name || n.node_name || n.id)}</option>`; }).join('')}
    </select>`;

  const anomRows = Array.isArray(anoms) ? anoms : [];
  const timelinePts = Array.isArray(timeline) ? timeline : [];
  const watch = (Array.isArray(backends) ? backends : []).filter(r => r.error_rate > 0).slice(0, 6);
  const topCountries = (Array.isArray(geo) ? geo : []).slice(0, 5);
  const now0 = Date.now();
  const certs = (Array.isArray(domains) ? domains : [])
    .filter(d => d.cert_expires_at)
    .map(d => ({ name: d.domain || d.name, days: Math.round((new Date(d.cert_expires_at) - now0) / 86400000) }))
    .filter(c => c.days < 30).sort((a, b) => a.days - b.days).slice(0, 5);

  const fleet = !node && allEdges.length ? `
    <div class="prism-panel">
      <div class="prism-panel-title">${esc(t('obs.syn.fleet'))} <span style="font-weight:400;color:var(--text3);font-size:11px">· ${esc(t('obs.syn.fleet_hint'))}</span></div>
      <table class="prism-table">
        <thead><tr><th>${esc(t('obs.syn.col_edge'))}</th><th>${esc(t('obs.syn.col_status'))}</th><th>${esc(t('prism.requests'))}</th><th>${esc(t('prism.error_rate'))}</th><th>${esc(t('prism.latency'))}</th></tr></thead>
        <tbody>${allEdges.slice(0, 12).map((n, i) => {
          const k = edgeKpis[i] || {};
          const online = n.status === 'online';
          const er = Number(k.error_rate) || 0;
          return `<tr style="cursor:pointer" data-obs="edge" data-i="${i}">
            <td><b>${esc(n.display_name || n.node_name || n.id)}</b></td>
            <td><span class="tag ${online ? 'tag-green' : 'tag-red'}">${esc(online ? t('obs.syn.online') : t('obs.syn.offline'))}</span></td>
            <td>${obsNum(k.requests || 0)}</td>
            <td style="color:${er >= 10 ? 'var(--red)' : er >= 5 ? 'var(--yellow)' : 'inherit'}">${er.toFixed(1)}%</td>
            <td>${Math.round(Number(k.avg_latency_ms) || 0)} ms</td>
          </tr>`;
        }).join('')}</tbody>
      </table>
    </div>` : '';

  const watchCard = `
    <div class="prism-panel">
      <div class="prism-panel-title">${esc(t('obs.syn.watch'))}</div>
      ${watch.length ? `<table class="prism-table">
        <thead><tr><th>${esc(t('obs.syn.col_proxy'))}</th><th>${esc(t('prism.requests'))}</th><th>${esc(t('prism.rate'))}</th><th>${esc(t('prism.lat_avg'))}</th></tr></thead>
        <tbody>${watch.map(r => `<tr style="cursor:pointer" data-obs="proxy" data-proxy="${esc(r.domain || '')}">
          <td style="font-size:12px">${esc(r.domain || r.name)}</td>
          <td>${obsNum(r.total)}</td>
          <td style="color:${r.error_rate > 10 ? 'var(--red)' : r.error_rate > 5 ? 'var(--yellow)' : 'inherit'}">${r.error_rate.toFixed(1)}%</td>
          <td>${r.avg_lat_ms} ms</td></tr>`).join('')}</tbody>
      </table>` : `<p class="prism-muted">${esc(t('obs.syn.watch_none'))}</p>`}
    </div>`;

  const countriesCard = `
    <div class="prism-panel">
      <div class="prism-panel-title">${esc(t('obs.syn.countries'))}</div>
      ${topCountries.length ? topCountries.map(g => `
        <button type="button" class="prism-toprow" data-obs="prism">
          <span class="prism-toprow-flag">${esc(g.country_code)}</span>
          <span class="prism-toprow-main"><span class="prism-toprow-head"><span>${esc(g.country_name)}</span><b>${obsNum(g.requests)}</b></span>
          <span class="prism-bar-bg"><span class="prism-bar-fill" style="width:${(g.requests / topCountries[0].requests * 100).toFixed(1)}%"></span></span></span>
        </button>`).join('') : `<p class="prism-muted">${esc(t('prism.no_data'))}</p>`}
    </div>`;

  const certsCard = `
    <div class="prism-panel">
      <div class="prism-panel-title">${esc(t('obs.syn.certs'))}</div>
      ${certs.length ? certs.map(c => `
        <div style="display:flex;justify-content:space-between;gap:8px;font-size:13px;padding:3px 0">
          <span>${esc(c.name)}</span>
          <b style="color:${c.days < 7 ? 'var(--red)' : 'var(--yellow)'}">${c.days < 0 ? esc(t('obs.syn.expired')) : c.days + ' j'}</b>
        </div>`).join('') : `<p class="prism-muted">${esc(t('obs.syn.certs_none'))}</p>`}
    </div>`;

  const sloCard = obsSloCardHTML(slo);

  main.innerHTML = `<div id="obs-syn-root">
    <div class="prism-filters">
      <div class="prism-fg">${nodeSel}</div>
      ${nodeSel ? '<div class="prism-fg-sep"></div>' : ''}
      <div class="prism-fg" style="gap:4px">${rangeBtns}</div>
      <div class="prism-fg prism-fg-end" style="gap:4px">
        <button type="button" class="btn btn-primary btn-sm" data-obs="refresh">${esc(t('obs.syn.refresh'))}</button>
        <button type="button" class="btn btn-secondary btn-sm" data-obs="prism">${esc(t('obs.syn.open_prism'))}</button>
      </div>
    </div>
    ${anomRows.length ? `<div class="prism-panel" style="margin-bottom:14px">
      <div class="prism-panel-title">${esc(t('obs.syn.anoms'))}</div>
      ${obsAnomaliesHtml(anomRows, { limit: 3 })}
    </div>` : ''}
    ${sloCard}
    ${obsKpisHtml({ ...kpis, unique_ips: uniq?.unique_ips ?? kpis?.unique_ips }, timelinePts)}
    <div class="prism-two">
      <div class="prism-panel">${obsTimelineHtml(timelinePts, { live: bucket === 'minute' })}</div>
      <div class="prism-panel">${obsStatusHtml(Array.isArray(status) ? status : [])}</div>
    </div>
    <div class="prism-two">${fleet}${watchCard}</div>
    <div class="prism-two">${countriesCard}${certsCard}</div></div>`;
  const root = document.getElementById('obs-syn-root');

  const openPrism_ = (opts = {}) => {
    window._prismProxyInit = opts.proxy || '';
    window._prismIpInit = opts.ip || '';
    window._prismFromInit = opts.from || '';
    window._prismToInit = opts.to || '';
    if (scope.lock) { navigate('edge-prism'); return; }
    if (node) { const e = allEdges.find(n => (n.node_name || n.display_name || n.id) === node); if (e) { selectEdge(e, 'edge-prism'); return; } }
    navigate('prism');
  };

  root.onclick = e => {
    const el = e.target.closest('[data-obs],[data-prism]');
    if (!el || !root.contains(el)) return;
    const obs = el.getAttribute('data-obs');
    const act = el.getAttribute('data-prism');
    if (obs === 'range') { _obsSynRangeMs = parseInt(el.dataset.ms, 10) || 86400000; renderObsSynthese(scope); }
    else if (obs === 'refresh') renderObsSynthese(scope);
    else if (obs === 'prism') openPrism_();
    else if (obs === 'proxy') openPrism_({ proxy: el.dataset.proxy || '' });
    else if (obs === 'edge') { const n = allEdges[parseInt(el.dataset.i, 10)]; if (n) selectEdge(n, 'edge-obs-synthese'); }
    else if (act === 'to-logs-status') {
      const opts = { status: el.getAttribute('data-status') || '', date_from: from.toISOString(), date_to: now.toISOString() };
      if (typeof openLogsFiltered === 'function') openLogsFiltered(opts);
    }
    else if (act === 'bucket') openPrism_(obsBucketRange(el.getAttribute('data-bucket') || '', bucket));
    else if (act === 'ban') openPrism_({ ip: el.getAttribute('data-ip') || '' });
    else if (act === 'filter-proxy') openPrism_({ proxy: el.getAttribute('data-proxy') || '' });
    else if (act) openPrism_();
    if (el.hasAttribute('data-obs') || act) e.preventDefault();
  };
  root.onchange = e => {
    const sl = e.target.closest('[data-obs="slo-target"]');
    if (sl) {
      api('PUT', '/prism/slo/config', { target: parseFloat(sl.value) })
        .catch(err => toast(err.message, 'error'))
        .finally(() => renderObsSynthese(scope));
      return;
    }
    const el = e.target.closest('[data-obs="node"]');
    if (!el) return;
    _obsSynNode = el.value;
    renderObsSynthese(scope);
  };
}

// Tranche de la courbe (heure locale du serveur, « AAAA-MM-JJTHH:MM ») → période datetime-local pour Prism.
function obsBucketRange(b, unit) {
  const start = new Date(b.length === 10 ? b + 'T00:00' : b);
  if (isNaN(start)) return {};
  const p = n => String(n).padStart(2, '0');
  const fmt = d => `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
  const span = b.length === 10 ? 86400000 : unit === 'minute' ? 60000 : 3600000;
  return { from: fmt(start), to: fmt(new Date(start.getTime() + span - 60000 + (unit === 'minute' ? 60000 : 0))) };
}
