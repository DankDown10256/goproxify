// ── PAGE: Observabilité › Métriques (Admin) ──────────────────────────────────
// Vue de la flotte à partir des métriques Prometheus relevées sur les passerelles
// (GET /metrics/summary et GET /metrics/proxies). Le détail d'une passerelle reste
// dans sa page Métriques (edge-metrics), ouverte d'un clic sur sa ligne.

let _obsMSort = 'p95';
let _obsMFilter = '';

pages['obs-metrics'] = async function() {
  const main = document.getElementById('content');
  main.innerHTML = `<div class="spinner" style="margin:60px auto"></div>`;
  const [sum, prox, nodes] = await Promise.all([
    api('GET', '/metrics/summary').catch(() => null),
    api('GET', '/metrics/proxies?points=60').catch(() => null),
    api('GET', '/nodes').catch(() => []),
  ]);
  const edges = ((nodes || []).filter(n => n.role === 'edge'));
  const g = sum?.global || {};
  const has = !!(sum && (sum.edges || []).length) || !!(prox?.proxies || []).length;

  const card = (label, val, foot = '') => `<div class="card kpi pk"><small>${esc(label)}</small><strong>${val}</strong>${foot ? `<em class="note">${foot}</em>` : '<em>&nbsp;</em>'}</div>`;
  const rps = v => v == null ? '—' : v < 1 ? v.toFixed(2) : v < 10 ? v.toFixed(1) : Math.round(v).toLocaleString();
  const pctv = v => v == null ? '—' : (v * (v <= 1 ? 100 : 1)).toFixed(2) + '%';
  const errColor = v => (v > 0.05 ? 'var(--red)' : v > 0.01 ? 'var(--yellow)' : 'inherit');

  const kpis = `<div class="grid g6" style="margin-bottom:14px">
    ${card(t('om.rps'), rps(g.requests_per_second))}
    ${card(t('om.err5'), pctv(g.error_rate_5xx))}
    ${card(t('om.bytes_in'), obsBytes(g.bytes_in_total || 0))}
    ${card(t('om.bytes_out'), obsBytes(g.bytes_out_total || 0))}
    ${card(t('om.ws'), obsNum((sum?.ws?.admin_connections || 0) + (sum?.ws?.agent_connections || 0)), `${sum?.ws?.admin_connections || 0} admin · ${sum?.ws?.agent_connections || 0} agent`)}
    ${card(t('om.peers'), sum?.peers ? Math.round(sum.peers.avg_sync_ms) + ' ms' : '—')}
  </div>`;

  const edgeRows = (sum?.edges || []).map(e => {
    const n = edges.find(x => (x.node_name || x.id) === e.edge_name);
    return { e, n };
  });
  const edgesCard = `<div class="prism-panel" style="margin-bottom:14px">
    <div class="prism-panel-title"><span>${esc(t('om.edges'))}</span><span class="note">${esc(t('om.click_edge'))}</span></div>
    ${edgeRows.length ? `<table class="prism-table"><thead><tr><th>${esc(t('obs.syn.col_edge'))}</th><th>${esc(t('obs.syn.col_status'))}</th><th>${esc(t('om.rps'))}</th><th>${esc(t('om.err5'))}</th><th>p95</th></tr></thead><tbody>
      ${edgeRows.map(({ e, n }, i) => `<tr style="cursor:pointer" data-om="edge" data-i="${i}">
        <td><b>${esc((n && (n.display_name || n.node_name)) || e.edge_name)}</b></td>
        <td>${n ? `<span class="tag ${n.status === 'online' ? 'tag-green' : 'tag-red'}">${esc(t(n.status === 'online' ? 'obs.syn.online' : 'obs.syn.offline'))}</span>` : '—'}</td>
        <td>${rps(e.requests_per_second)}</td>
        <td style="color:${errColor(e.error_rate)}">${pctv(e.error_rate)}</td>
        <td>${e.p95_ms ? Math.round(e.p95_ms) + ' ms' : '—'}</td></tr>`).join('')}</tbody></table>`
      : `<p class="prism-muted">${esc(t('om.no_data'))}</p>`}
  </div>`;

  const spark_ = v => {
    const mx = Math.max(...v), mn = Math.min(...v), sp = (mx - mn) || 1, w = 90, h = 22;
    const p = v.map((a, i) => `${i ? 'L' : 'M'}${(i * w / (v.length - 1)).toFixed(1)},${(h - 2 - (a - mn) / sp * (h - 4)).toFixed(1)}`).join('');
    return `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" aria-hidden="true"><path d="${p}" fill="none" stroke="var(--accent)" stroke-width="1.5"/></svg>`;
  };
  const proxiesBody = () => {
    const key = { p95: p => p.p95_ms || 0, err: p => p.error_rate || 0, rps: p => p.requests_per_second || 0 }[_obsMSort];
    const list = (prox?.proxies || []).filter(p => !_obsMFilter || p.host.includes(_obsMFilter)).sort((a, b) => key(b) - key(a)).slice(0, 25);
    return list.length ? `<div class="tw"><table class="prism-table"><thead><tr><th>${esc(t('obs.syn.col_proxy'))}</th><th>${esc(t('om.rps'))}</th><th></th><th>${esc(t('om.err5'))}</th><th>p95</th></tr></thead><tbody>
      ${list.map(p => `<tr><td class="mono" style="font-size:12px">${esc(p.host)}</td><td>${rps(p.requests_per_second)}</td><td>${p.series && p.series.length > 2 ? spark_(p.series) : ''}</td>
        <td style="color:${errColor(p.error_rate)}">${pctv(p.error_rate)}</td><td>${p.p95_ms ? Math.round(p.p95_ms) + ' ms' : '—'}</td></tr>`).join('')}</tbody></table></div>`
      : `<p class="prism-muted">${esc(t('om.no_data'))}</p>`;
  };
  const sortChips = () => [['p95', 'p95'], ['err', '5xx'], ['rps', t('om.rps')]].map(([k, l]) => `<button type="button" class="chip${_obsMSort === k ? ' active' : ''}" data-om="sort" data-v="${k}">${esc(l)}</button>`).join('');
  const proxiesCard = `<div class="prism-panel" style="margin-bottom:14px">
    <div class="prism-panel-title"><span>${esc(t('om.proxies'))}</span>
      <span style="display:flex;gap:6px;align-items:center;flex-wrap:wrap">
        <input type="text" class="form-input" style="max-width:170px" placeholder="${esc(t('om.filter'))}" value="${esc(_obsMFilter)}" data-om="filter">
        <span id="om-sort" style="display:flex;gap:6px">${sortChips()}</span>
      </span></div>
    <div id="om-prox">${proxiesBody()}</div>
  </div>`;

  const certs = (sum?.tls?.certs || []).slice().sort((a, b) => a.expires_in_seconds - b.expires_in_seconds).slice(0, 8);
  const certsCard = `<div class="prism-panel">
    <div class="prism-panel-title">${esc(t('om.certs'))}</div>
    ${certs.length ? certs.map(c => {
      const d = Math.floor(c.expires_in_seconds / 86400);
      return `<div style="display:flex;justify-content:space-between;gap:8px;font-size:13px;padding:3px 0"><span class="mono">${esc(c.domain)}${c.handshake_p95_ms ? ` <span class="note">${Math.round(c.handshake_p95_ms)} ms</span>` : ''}</span><b style="color:${d < 7 ? 'var(--red)' : d < 30 ? 'var(--yellow)' : 'inherit'}">${d < 0 ? esc(t('obs.syn.expired')) : d + ' j'}</b></div>`;
    }).join('') : `<p class="prism-muted">${esc(t('obs.syn.certs_none'))}</p>`}
  </div>`;

  const sec = [];
  (sum?.pipeline || []).forEach(p => sec.push([p.stage, p.blocked_total]));
  if (sum?.f2b) sec.push(['Fail2Ban · ' + t('om.bans'), sum.f2b.bans_total]);
  if (sum?.crowdsec) sec.push(['CrowdSec · ' + t('om.decisions'), sum.crowdsec.decisions_new]);
  if (sum?.waf) sec.push([t('om.waf'), sum.waf.profiles_active]);
  const secCard = `<div class="prism-panel">
    <div class="prism-panel-title">${esc(t('om.security'))}</div>
    ${sec.length ? sec.map(([k, v]) => `<div style="display:flex;justify-content:space-between;font-size:13px;padding:3px 0"><span>${esc(k)}</span><b class="mono">${obsNum(v || 0)}</b></div>`).join('') : `<p class="prism-muted">${esc(t('om.no_data'))}</p>`}
  </div>`;

  main.innerHTML = `<div id="obs-m-root">
    <div class="prism-filters"><div class="prism-fg prism-fg-end"><button type="button" class="btn btn-primary btn-sm" data-om="refresh">${esc(t('obs.syn.refresh'))}</button></div></div>
    ${has ? '' : `<div class="prism-panel" style="margin-bottom:14px"><p style="margin:0;font-size:13px;color:var(--text2)">${t('edgepage.metrics.prometheus_desc')}</p></div>`}
    ${kpis}${edgesCard}${proxiesCard}<div class="prism-two">${certsCard}${secCard}</div></div>`;

  const root = document.getElementById('obs-m-root');
  root.onclick = e => {
    const el = e.target.closest('[data-om]');
    if (!el) return;
    const a = el.getAttribute('data-om');
    if (a === 'refresh') pages['obs-metrics']();
    else if (a === 'sort') { _obsMSort = el.dataset.v; document.getElementById('om-sort').innerHTML = sortChips(); document.getElementById('om-prox').innerHTML = proxiesBody(); }
    else if (a === 'edge') {
      const { e: ed, n } = edgeRows[parseInt(el.dataset.i, 10)] || {};
      if (n) selectEdge(n, 'edge-metrics');
    }
  };
  root.oninput = e => {
    if (!e.target.closest('[data-om="filter"]')) return;
    _obsMFilter = e.target.value;
    document.getElementById('om-prox').innerHTML = proxiesBody();
  };
};
