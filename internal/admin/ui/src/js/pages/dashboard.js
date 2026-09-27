// ── PAGE: Dashboard — trois vues (Santé, Cockpit, Carte) sur un même jeu de données.

const DASH_TAB_KEY = 'gpx_dash_tab';
const DASH_TABS = ['health', 'cockpit', 'map'];
let _dashWorldSvg = null;

const dashLocale = () => (typeof gpxBCP47 === 'function' ? gpxBCP47() : 'en-US');
const dashInt = n => n == null ? '—' : Math.round(n).toLocaleString(dashLocale());
const dashRps = v => v == null ? '—' : (v < 1 ? v.toFixed(2) : v < 10 ? v.toFixed(1) : Math.round(v)) + ' req/s';
const dashPct = v => v == null ? '—' : (v * 100).toFixed(1) + '%';
const dashBytes = v => {
  if (v == null) return '—';
  if (v < 1024) return v + ' B';
  if (v < 1048576) return (v / 1024).toFixed(1) + ' KB';
  if (v < 1073741824) return (v / 1048576).toFixed(1) + ' MB';
  return (v / 1073741824).toFixed(2) + ' GB';
};
const dashAgo = iso => {
  if (!iso) return '—';
  const d = new Date(iso), diff = Math.round((Date.now() - d) / 1000);
  if (diff < 60) return t('dash.ago_s', { n: diff });
  if (diff < 3600) return t('dash.ago_m', { n: Math.round(diff / 60) });
  if (diff < 86400) return t('dash.ago_h', { n: Math.round(diff / 3600) });
  return d.toLocaleDateString(dashLocale());
};
const dashFlag = cc => (!cc || cc.length !== 2 || cc === 'XX' || cc === 'LO') ? ''
  : String.fromCodePoint(0x1F1E6 + cc.charCodeAt(0) - 65, 0x1F1E6 + cc.charCodeAt(1) - 65) + ' ';

async function dashLoad() {
  const [health, proxies, nodes, domains, audit, summary, hostMetrics, backends, geo] = await Promise.all([
    api('GET', '/health').catch(() => null),
    api('GET', '/proxies').catch(() => []),
    api('GET', '/nodes').catch(() => []),
    api('GET', '/domains').catch(() => []),
    api('GET', '/audit?limit=8').catch(() => null),
    api('GET', '/metrics/summary').catch(() => null),
    api('GET', '/metrics/proxies?points=360').catch(() => null),
    api('GET', '/backends/health').catch(() => null),
    api('GET', '/prism/geo').catch(() => null),
  ]);

  const allNodes = nodes || [];
  const edgeNodes = allNodes.filter(n => n.role === 'edge');
  const agentNodes = allNodes.filter(n => n.role === 'agent');
  const allProxies = proxies || [];
  const allDomains = domains || [];
  const now = Date.now();

  const certsExpired = allDomains.filter(d => d.cert_expires_at && new Date(d.cert_expires_at) < now);
  const certsSoon = allDomains.filter(d => d.cert_expires_at && new Date(d.cert_expires_at) >= now && (new Date(d.cert_expires_at) - now) / 86400000 < 30);
  const nodesOffline = allNodes.filter(n => n.status !== 'online');
  const edgesOffline = nodesOffline.filter(n => n.role === 'edge');
  const backendsDown = Object.values(backends?.backends || {}).filter(s => s === 'down').length;

  const promCerts = summary?.tls?.certs || [];
  const promCertsSoon = promCerts.filter(c => c.expires_in_seconds != null && c.expires_in_seconds < 7 * 86400);
  const seen = new Set(promCertsSoon.map(c => c.domain));

  const ico = p => `<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">${p}</svg>`;
  const shield = ico('<path d="M12 2l5 3v4c0 3-2.5 5.5-5 6.5C9.5 14.5 7 12 7 9V5l5-3z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>');
  const alertIco = ico('<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>');

  const attention = [
    ...promCertsSoon.map(c => ({
      icon: shield, color: 'var(--red)',
      text: t('dash.cert_soon', { domain: esc(c.domain), days: Math.max(0, Math.round(c.expires_in_seconds / 86400)) }),
      page: 'acme-monitor', label: t('dash.renew'),
    })),
    ...nodesOffline.map(n => ({
      icon: alertIco, color: n.role === 'edge' ? 'var(--red)' : 'var(--yellow)',
      text: t('dash.node_offline', { role: n.role === 'edge' ? 'Passerelle' : 'Agent', name: esc(n.display_name || n.node_name) }),
      page: 'infrastructure', label: t('dash.see'),
    })),
    ...certsExpired.filter(d => !seen.has(d.domain)).map(d => ({
      icon: shield, color: 'var(--red)', text: t('dash.cert_expired', { domain: esc(d.domain) }),
      page: 'acme-monitor', label: t('dash.renew'),
    })),
    ...certsSoon.filter(d => !seen.has(d.domain)).map(d => {
      const days = Math.round((new Date(d.cert_expires_at) - now) / 86400000);
      return { icon: shield, color: days < 7 ? 'var(--red)' : 'var(--yellow)', text: t('dash.cert_soon', { domain: esc(d.domain), days }), page: 'acme-monitor', label: t('dash.see') };
    }),
  ];
  if (backendsDown > 0) {
    attention.push({ icon: alertIco, color: 'var(--yellow)', text: `${t('dash.backends_down')} : ${backendsDown}`, page: 'admin-trafic', label: t('dash.see') });
  }

  const hasCritical = certsExpired.length > 0 || edgesOffline.length > 0 || promCertsSoon.length > 0;
  const hasWarning = !hasCritical && (attention.length > 0 || (health && health.status !== 'ok'));

  // Série de débit total : les séries par host sont alignées sur leur fin.
  const hostSeries = (hostMetrics?.proxies || []).map(p => p.series || []);
  const len = Math.max(0, ...hostSeries.map(s => s.length));
  const total = Array.from({ length: len }, (_, i) =>
    hostSeries.reduce((sum, s) => sum + (s[i - (len - s.length)] || 0), 0));

  const edgeMetrics = summary?.edges || [];
  const onlineEdges = edgeNodes.filter(n => n.status === 'online');
  const p95s = edgeMetrics.map(e => e.p95_ms).filter(v => v != null && v > 0);

  return {
    health, allNodes, edgeNodes, agentNodes, allProxies, allDomains, attention,
    enabledCnt: allProxies.filter(p => p.enabled !== false).length,
    edgesOnline: onlineEdges.length, agentsOnline: agentNodes.filter(n => n.status === 'online').length,
    hasCritical, hasWarning, edgesOffline, backendsDown,
    certsExpired, certsSoon,
    audit: audit?.entries || [],
    global: summary?.global || {}, edgeMetrics, certs: promCerts,
    pipeline: summary?.pipeline || [], f2b: summary?.f2b, crowdsec: summary?.crowdsec,
    hosts: [...(hostMetrics?.proxies || [])].sort((a, b) => b.requests_per_second - a.requests_per_second),
    total, hasMetrics: !!(summary?.global || hostMetrics?.sampled_at),
    p95: p95s.length ? p95s.reduce((a, b) => a + b, 0) / p95s.length : null,
    geo: Array.isArray(geo) ? geo : [],
  };
}

// ── Petits composants SVG / HTML ────────────────────────────────────────────

function dashSpark(vals, color, h) {
  if (!vals || vals.length < 2) return `<div style="height:${h}px"></div>`;
  const w = 200, p = 3, mx = Math.max(...vals), mn = Math.min(...vals), r = (mx - mn) || 1;
  const pts = vals.map((v, i) => [p + i * (w - 2 * p) / (vals.length - 1), h - p - (v - mn) / r * (h - 2 * p)]);
  const line = pts.map((q, i) => (i ? 'L' : 'M') + q[0].toFixed(1) + ' ' + q[1].toFixed(1)).join('');
  const last = pts[pts.length - 1];
  return `<svg viewBox="0 0 ${w} ${h}" width="100%" height="${h}" preserveAspectRatio="none" aria-hidden="true">
    <path d="${line}L${w - p} ${h}L${p} ${h}Z" style="fill:${color};opacity:.12"/>
    <path d="${line}" style="fill:none;stroke:${color};stroke-width:1.6" vector-effect="non-scaling-stroke"/>
    <circle cx="${last[0]}" cy="${last[1]}" r="2.5" style="fill:${color}"/></svg>`;
}

function dashChart(vals) {
  if (!vals || vals.length < 2) return `<div class="gp-d-empty">${t('dash.no_metrics')}</div>`;
  const cw = (document.getElementById("content")?.clientWidth || 800) - 72;
  const W = Math.max(280, Math.min(720, cw)), H = W < 460 ? 180 : 230, L = 40, R = 10, T = 12, B = 26;
  const peak = Math.max(...vals), step = Math.pow(10, Math.floor(Math.log10(Math.max(peak, 1e-6))));
  const top = [1, 2, 2.5, 5, 10].map(m => m * step).find(v => v >= peak * 1.05) || 1;
  const x = i => L + i * (W - L - R) / (vals.length - 1);
  const y = v => T + (1 - v / top) * (H - T - B);
  const fmt = v => v >= 100 ? String(Math.round(v)) : v >= 10 ? v.toFixed(0) : v.toFixed(1);
  let g = '';
  [0, top / 2, top].forEach(v => {
    g += `<line x1="${L}" x2="${W - R}" y1="${y(v)}" y2="${y(v)}" style="stroke:var(--border)"/>
      <text x="${L - 8}" y="${y(v) + 4}" text-anchor="end" font-size="11" style="fill:var(--text2)">${fmt(v)}</text>`;
  });
  const mins = Math.round(vals.length * 10 / 60);
  [[0, `−${mins} min`, 'start'], [(vals.length - 1) / 2, `−${Math.round(mins / 2)} min`, 'middle'], [vals.length - 1, '0', 'end']].forEach(([i, lbl, anchor]) => {
    g += `<text x="${x(i)}" y="${H - 8}" text-anchor="${anchor}" font-size="11" style="fill:var(--text2)">${lbl}</text>`;
  });
  const line = vals.map((v, i) => (i ? 'L' : 'M') + x(i).toFixed(1) + ' ' + y(v).toFixed(1)).join('');
  const pk = vals.indexOf(peak);
  g += `<path d="${line}L${x(vals.length - 1)} ${y(0)}L${x(0)} ${y(0)}Z" style="fill:var(--accent);opacity:.13"/>
    <path d="${line}" style="fill:none;stroke:var(--accent);stroke-width:2"/>
    <circle cx="${x(vals.length - 1)}" cy="${y(vals[vals.length - 1])}" r="4" style="fill:var(--accent)"/>
    <circle cx="${x(pk)}" cy="${y(peak)}" r="3" style="fill:var(--bg2);stroke:var(--accent);stroke-width:1.5"/>`;
  return `<div class="gp-d-chart"><div style="font-size:11px;opacity:.6;text-align:right;margin-bottom:2px">${t('dash.peak', { v: dashRps(peak) })}</div>
    <svg viewBox="0 0 ${W} ${H}" role="img" aria-label="${t('dash.traffic_1h')}">${g}</svg></div>`;
}

const dashPill = (label, color) => `<span class="gp-d-pill" style="--c:${color}">${label}</span>`;
const dashBar = (pct, color) => `<div class="gp-d-bar" ${color ? `style="--c:${color}"` : ''}><i style="width:${Math.max(0, Math.min(100, pct))}%"></i></div>`;
const dashCard = (title, action, body) => `
  <div class="card blueprint" style="overflow:hidden">
    <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
    <div class="card-header"><span class="card-title">${title}</span>${action || ''}</div>
    ${body}
  </div>`;
const dashLink = (page, label) => `<button class="btn btn-ghost btn-sm" onclick="navigate('${page}')" style="font-size:11px">${label}</button>`;

function dashTodoList(d, compact) {
  if (!d.attention.length) return `<div class="gp-d-empty">${t('dash.health_ok_sub')}</div>`;
  return d.attention.map(a => `
    <div class="gp-d-todo">
      <span class="gp-d-ico" style="--c:${a.color}">${a.icon}</span>
      <div class="body">${a.text}</div>
      ${compact ? '' : `<button class="btn btn-ghost btn-sm" onclick="navigate('${a.page}')" style="flex-shrink:0;font-size:11px">${a.label} →</button>`}
    </div>`).join('');
}

function dashEdgeList(d) {
  if (!d.edgeNodes.length) {
    return `<div class="gp-d-empty">${t('dash.no_edges')}
      <button class="btn btn-primary btn-sm" style="display:block;margin:12px auto 0" onclick="navigate('tokens')">${t('dash.create_token')}</button></div>`;
  }
  return d.edgeNodes.map((n, i) => {
    const online = n.status === 'online';
    const cpu = n.cpu_pct != null ? Math.round(n.cpu_pct) : null;
    const mem = n.mem_pct != null ? Math.round(n.mem_pct) : null;
    const col = v => v > 85 ? 'var(--red)' : v > 65 ? 'var(--yellow)' : 'var(--accent)';
    const em = d.edgeMetrics.find(p => p.edge_name === (n.node_name || n.id));
    return `<div class="gp-d-row" style="cursor:pointer" onclick="selectEdge(window._edgeNodes[${i}])">
      <span style="width:8px;height:8px;border-radius:50%;background:${online ? 'var(--green)' : 'var(--red)'};flex:none"></span>
      <div style="flex:1;min-width:0">
        <div style="font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(n.display_name || n.node_name)}</div>
        <div class="sub">${em ? `${dashRps(em.requests_per_second)}${em.p95_ms ? ' · p95 ' + Math.round(em.p95_ms) + ' ms' : ''}` : esc(n.endpoint || '—')}</div>
      </div>
      ${online && cpu != null ? `<div style="display:grid;grid-template-columns:auto 70px;gap:3px 8px;align-items:center;font-size:10px;opacity:.75">
        <span>CPU ${cpu}%</span>${dashBar(cpu, col(cpu))}<span>RAM ${mem ?? '—'}%</span>${dashBar(mem || 0, col(mem))}</div>`
        : `<span style="font-size:11px;color:var(--red)">${online ? '' : t('common.offline')}</span>`}
    </div>`;
  }).join('');
}

function dashAudit(d) {
  if (!d.audit.length) return `<div class="gp-d-empty">${t('dash.no_activity')}</div>`;
  return d.audit.map(e => {
    const c = e.severity === 'error' ? 'var(--red)' : e.severity === 'warning' ? 'var(--yellow)' : 'var(--accent)';
    return `<div class="gp-d-row" style="align-items:flex-start;justify-content:flex-start">
      <span style="width:6px;height:6px;border-radius:50%;background:${c};margin-top:6px;flex:none"></span>
      <div style="flex:1;min-width:0"><div style="font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(e.action || '—')}</div>
      <div class="sub">${esc(e.actor || t('dash.system'))} · ${dashAgo(e.created_at)}</div></div>
      <span class="tag tag-neutral" style="font-size:10px;flex:none">${esc(e.resource_type || e.component || 'admin')}</span></div>`;
  }).join('');
}

function dashHosts(d) {
  const hosts = d.hosts.filter(h => h.requests_per_second > 0).slice(0, 6);
  if (!hosts.length) return `<div class="gp-d-empty">${t('dash.no_metrics')}</div>`;
  const max = hosts[0].requests_per_second || 1;
  return hosts.map(h => `<div class="gp-d-brow">
    <div style="display:flex;justify-content:space-between;gap:8px;font-size:13px;margin-bottom:5px">
      <span style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(h.host)}</span>
      <span style="font-variant-numeric:tabular-nums;white-space:nowrap">${dashRps(h.requests_per_second)}${h.error_rate > 0.01 ? ` <b style="color:var(--red)">${dashPct(h.error_rate)}</b>` : ''}</span></div>
    ${dashBar(h.requests_per_second / max * 100)}</div>`).join('');
}

function dashCerts(d) {
  const certs = [...d.certs].filter(c => c.expires_in_seconds != null).sort((a, b) => a.expires_in_seconds - b.expires_in_seconds).slice(0, 6);
  if (!certs.length) return `<div class="gp-d-empty">${t('dash.no_certs')}</div>`;
  return certs.map(c => {
    const days = Math.round(c.expires_in_seconds / 86400);
    const col = days < 7 ? 'var(--red)' : days < 30 ? 'var(--yellow)' : 'var(--green)';
    return `<div class="gp-d-row"><span style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(c.domain)}</span>${dashPill(t('dash.days', { n: days }), col)}</div>`;
  }).join('');
}

function dashBlocked(d) {
  const rows = d.pipeline.filter(p => p.blocked_total > 0).sort((a, b) => b.blocked_total - a.blocked_total).map(p => [esc(p.stage), p.blocked_total]);
  if (d.f2b) rows.push(['Fail2Ban', d.f2b.bans_total]);
  if (d.crowdsec) rows.push(['CrowdSec', d.crowdsec.decisions_new]);
  const shown = rows.filter(r => r[1] > 0);
  if (!shown.length) return `<div class="gp-d-empty">${t('dash.no_metrics')}</div>`;
  const max = Math.max(...shown.map(r => r[1]));
  return shown.map(r => `<div class="gp-d-brow">
    <div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:5px"><span>${r[0]}</span><span style="font-variant-numeric:tabular-nums">${dashInt(r[1])}</span></div>
    ${dashBar(r[1] / max * 100, 'var(--red)')}</div>`).join('');
}

// ── Vue Santé ───────────────────────────────────────────────────────────────

function dashViewHealth(d) {
  const color = d.hasCritical ? 'var(--red)' : d.hasWarning ? 'var(--yellow)' : 'var(--green)';
  const title = d.hasCritical ? t('dash.health_crit') : d.hasWarning ? t('dash.health_warn') : t('dash.health_ok');
  const sub = d.attention.length ? t('dash.health_n_sub', { n: d.attention.length }) : t('dash.health_ok_sub');
  const glyph = d.hasCritical ? '!' : d.hasWarning ? '~' : '✓';
  const g = d.global;
  const pill = (ok, label) => dashPill(label, ok ? 'var(--green)' : 'var(--red)');
  const certsBad = d.certsExpired.length + d.certsSoon.length;

  return `
    <div class="card blueprint gp-d-hero">
      <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
      <span class="gp-d-ico" style="--c:${color};width:56px;height:56px;font-size:28px">${glyph}</span>
      <div><h2>${title}</h2><p>${sub}</p></div>
      <div class="gp-d-facts">
        <div class="gp-d-fact"><b>${d.enabledCnt}<span style="font-size:14px;opacity:.5;text-transform:none;letter-spacing:0"> / ${d.allProxies.length}</span></b><span>${t('dash.proxies_active')}</span></div>
        <div class="gp-d-fact"><b>${dashRps(g.requests_per_second)}</b><span>${t('dash.rps')}</span></div>
        <div class="gp-d-fact"><b>${dashPct(g.error_rate_5xx)}</b><span>${t('dash.error_rate')}</span></div>
      </div>
    </div>

    ${d.attention.length ? `<div style="margin-bottom:16px">${dashCard(t('dash.attention'), `<span style="font-size:11px;opacity:.55">${t('dash.items', { n: d.attention.length })}</span>`, dashTodoList(d))}</div>` : ''}

    <div class="gp-d-grid">
      ${dashCard(t('dash.services'), '', `
        <div class="gp-d-row"><span>${t('nav.edges')}</span>${d.edgeNodes.length ? pill(!d.edgesOffline.length, `${d.edgesOnline} / ${d.edgeNodes.length}`) : '<span class="sub">—</span>'}</div>
        <div class="gp-d-row"><span>${t('dash.svc_agents')}</span>${d.agentNodes.length ? pill(d.agentsOnline === d.agentNodes.length, `${d.agentsOnline} / ${d.agentNodes.length}`) : '<span class="sub">—</span>'}</div>
        <div class="gp-d-row"><span>${t('dash.svc_backends')}</span>${pill(!d.backendsDown, d.backendsDown ? `${d.backendsDown} ↓` : t('dash.svc_ok'))}</div>
        <div class="gp-d-row"><span>${t('dash.svc_certs')}</span>${pill(!certsBad, certsBad ? String(certsBad) : t('dash.svc_ok'))}</div>
        <div class="gp-d-row"><span>Admin</span><span class="sub">v${esc(d.health?.version || '—')}</span></div>`)}
      ${dashCard(t('dash.traffic_1h'), dashLink('admin-trafic', t('dash.see_all')), d.total.length > 1
        ? `<div class="gp-d-sparkwrap">${dashSpark(d.total, 'var(--accent)', 84)}<div class="card-meta">${t('dash.peak', { v: dashRps(Math.max(...d.total)) })}</div></div>`
        : `<div class="gp-d-empty">${t('dash.no_metrics')}</div>`)}
      ${dashCard(t('dash.recent'), dashLink('audit', t('dash.full_journal')), dashAudit(d))}
    </div>`;
}

// ── Vue Cockpit ─────────────────────────────────────────────────────────────

function dashViewCockpit(d) {
  const g = d.global;
  const errColor = (g.error_rate_5xx || 0) > 0.05 ? 'var(--red)' : (g.error_rate_5xx || 0) > 0.01 ? 'var(--yellow)' : 'var(--accent)';
  const kpi = (label, value, spark, color) => `
    <div class="card blueprint gp-d-kpi"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
      <div class="card-kicker">${label}</div><div class="v">${value}</div>${spark || '<div style="height:32px"></div>'}</div>`;
  return `
    <div class="gp-d-kpis">
      ${kpi(t('dash.rps'), dashRps(g.requests_per_second), dashSpark(d.total, 'var(--accent)', 32))}
      ${kpi(t('dash.error_rate'), `<span style="color:${errColor}">${dashPct(g.error_rate_5xx)}</span>`, '')}
      ${kpi('p95', d.p95 != null ? Math.round(d.p95) + ' ms' : '—', '')}
      ${kpi(t('dash.bytes_out'), dashBytes(g.bytes_out_total), `<div class="card-meta">${t('dash.bytes_in')} ${dashBytes(g.bytes_in_total)}</div>`)}
    </div>
    <div class="gp-d-split">
      ${dashCard(t('dash.traffic_1h'), '', dashChart(d.total))}
      ${dashCard(t('dash.attention'), d.attention.length ? dashPill(String(d.attention.length), d.hasCritical ? 'var(--red)' : 'var(--yellow)') : '', dashTodoList(d, true))}
    </div>
    <div class="gp-d-grid">
      ${dashCard(t('nav.edges'), dashLink('infrastructure', t('dash.see_all')), dashEdgeList(d))}
      ${dashCard(t('dash.top_hosts'), '', dashHosts(d))}
      ${dashCard(t('dash.cert_expiry'), dashLink('acme-monitor', t('dash.see_all')), dashCerts(d))}
    </div>`;
}

// ── Vue Carte ───────────────────────────────────────────────────────────────

const DASH_GEO_MODES = {
  requests: { key: 'requests', color: 'var(--accent)', label: 'dash.geo_requests' },
  error_rate: { key: 'error_rate', color: 'var(--red)', label: 'dash.geo_errors' },
  banned_ips: { key: 'banned_ips', color: 'var(--yellow)', label: 'dash.geo_bans' },
};

function dashViewMap(d, mode) {
  const g = d.global;
  const modes = Object.entries(DASH_GEO_MODES).map(([k, m]) =>
    `<button type="button" class="btn btn-xs dash-geo-mode ${k === mode ? 'active' : ''}" data-mode="${k}">${t(m.label)}</button>`).join('');
  const lat = d.edgeMetrics.filter(e => e.p95_ms > 0);
  const latMax = Math.max(1, ...lat.map(e => e.p95_ms));
  const top = geoSortLocalLast(d.geo, c => c.requests || 0).slice(0, 6);
  const topMax = Math.max(1, ...top.map(c => c.requests || 0));

  return `
    <div class="card blueprint" style="overflow:hidden;margin-bottom:16px">
      <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
      <div class="gp-d-mapbar">
        <div class="gp-d-facts" style="margin-left:0">
          <div class="gp-d-fact"><b>${dashRps(g.requests_per_second)}</b><span>${t('dash.rps')}</span></div>
          <div class="gp-d-fact"><b>${dashPct(g.error_rate_5xx)}</b><span>${t('dash.error_rate')}</span></div>
          <div class="gp-d-fact"><b>${dashInt(d.geo.reduce((s, c) => s + (c.banned_ips || 0), 0))}</b><span>${t('dash.geo_bans')}</span></div>
        </div>
        <div class="btn-group" role="group">${modes}</div>
      </div>
      <div id="dash-geo-map" class="gp-d-map wm-wrap">${d.geo.length ? '<div class="spinner" style="margin:80px auto"></div>' : `<div class="gp-d-empty">${t('dash.no_geo')}</div>`}</div>
      ${d.geo.length ? '<div class="gp-d-mapinfo sub" id="dash-geo-info"></div>' : ''}
    </div>
    <div class="gp-d-grid">
      ${dashCard(t('dash.geo_top'), dashLink('prism', 'Prism →'), top.length ? top.map(c => `
        <div class="gp-d-brow">
          <div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:5px"><span>${dashFlag(c.country_code)}${esc(c.country_name || c.country_code)}</span>
          <span style="font-variant-numeric:tabular-nums">${dashInt(c.requests)} · ${(c.pct || 0).toFixed(1)}%</span></div>${dashBar((c.requests || 0) / topMax * 100)}</div>`).join('')
        : `<div class="gp-d-empty">${t('dash.no_geo')}</div>`)}
      ${dashCard(t('dash.blocked_layer'), dashLink('security', t('dash.see_all')), dashBlocked(d))}
      ${dashCard(t('dash.latency_edge'), '', lat.length ? lat.map(e => {
        const c = e.p95_ms > 500 ? 'var(--red)' : e.p95_ms > 200 ? 'var(--yellow)' : 'var(--accent)';
        return `<div class="gp-d-brow">
          <div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:5px"><span>${esc(e.edge_name)}</span><span style="font-variant-numeric:tabular-nums">${Math.round(e.p95_ms)} ms</span></div>
          ${dashBar(e.p95_ms / latMax * 100, c)}</div>`;
      }).join('') : `<div class="gp-d-empty">${t('dash.no_metrics')}</div>`)}
    </div>`;
}

async function dashDrawMap(d, mode) {
  const box = document.getElementById('dash-geo-map');
  if (!box || !d.geo.length) return;
  if (!_dashWorldSvg) {
    try { _dashWorldSvg = await (await fetch('/world.svg')).text(); }
    catch { box.innerHTML = `<div class="gp-d-empty">${t('dash.no_geo')}</div>`; return; }
  }
  if (!document.getElementById('dash-geo-map')) return;
  const svg = new DOMParser().parseFromString(_dashWorldSvg, 'image/svg+xml').documentElement;
  svg.removeAttribute('width'); svg.removeAttribute('height');
  const sphere = svg.querySelector('.wm-sphere');
  if (sphere) sphere.setAttribute('fill', 'var(--bg3)');
  const grat = svg.querySelector('.wm-graticule');
  if (grat) { grat.setAttribute('fill', 'none'); grat.setAttribute('stroke', 'var(--border)'); grat.setAttribute('stroke-width', '0.3'); grat.setAttribute('opacity', '0.5'); }
  const border = svg.querySelector('.wm-border');
  if (border) { border.setAttribute('fill', 'none'); border.setAttribute('stroke', 'var(--border)'); border.setAttribute('stroke-width', '0.8'); border.setAttribute('opacity', '0.6'); }

  const m = DASH_GEO_MODES[mode];
  const val = c => m.key === 'error_rate' ? (c.error_rate || 0) : (c[m.key] || 0);
  const byCC = Object.fromEntries(d.geo.map(c => [c.country_code, c]));
  const max = Math.max(...d.geo.map(val), 0);
  svg.querySelectorAll('.wm-countries path').forEach(p => {
    const c = byCC[p.id];
    const v = c ? val(c) : 0;
    const share = max > 0 && v > 0 ? Math.round(14 + v / max * 80) : 0;
    p.style.fill = share ? `color-mix(in srgb, ${m.color} ${share}%, var(--bg2))` : 'var(--bg2)';
    if (c) {
      const ti = document.createElementNS('http://www.w3.org/2000/svg', 'title');
      ti.textContent = `${c.country_name || c.country_code} · ${dashInt(c.requests)} req · ${(c.pct || 0).toFixed(1)}% · ${(c.error_rate || 0).toFixed(1)}% err · ${c.banned_ips || 0} bans`;
      p.appendChild(ti);
    }
  });
  const info = document.getElementById('dash-geo-info');
  svg.addEventListener('click', e => {
    const c = byCC[e.target.closest('path')?.id];
    if (!c || !info) return;
    info.innerHTML = `<b>${dashFlag(c.country_code)}${esc(c.country_name || c.country_code)}</b> · ${dashInt(c.requests)} req · ${(c.pct || 0).toFixed(1)}% · ${(c.error_rate || 0).toFixed(1)}% err · ${c.banned_ips || 0} ${t('dash.geo_bans').toLowerCase()}`;
  });
  box.innerHTML = '';
  box.appendChild(svg);
  box.scrollLeft = (box.scrollWidth - box.clientWidth) / 2;
}

// ── Page ────────────────────────────────────────────────────────────────────

pages.dashboard = async function() {
  const content = document.getElementById('content');
  content.innerHTML = '<p style="color:var(--text2)">' + t('common.loading') + '</p>';
  try {
    const d = await dashLoad();
    window._edgeNodes = d.edgeNodes;
    window.openEdge = function(i, page) { selectEdge(window._edgeNodes[i], page); };

    let tab = 'health';
    try { const s = localStorage.getItem(DASH_TAB_KEY); if (DASH_TABS.includes(s)) tab = s; } catch {}
    let geoMode = 'requests';

    content.innerHTML = `
      <div id="dash-root">
        <div class="tabs" role="tablist">
          ${DASH_TABS.map(k => `<button type="button" role="tab" class="tab" data-tab="${k}">${t('dash.tab_' + k)}</button>`).join('')}
        </div>
        <div id="dash-body"></div>
      </div>`;

    const draw = () => {
      content.querySelectorAll('[data-tab]').forEach(b => {
        const on = b.dataset.tab === tab;
        b.classList.toggle('active', on);
        b.setAttribute('aria-selected', on);
      });
      const body = document.getElementById('dash-body');
      if (tab === 'health') body.innerHTML = dashViewHealth(d);
      else if (tab === 'cockpit') body.innerHTML = dashViewCockpit(d);
      else { body.innerHTML = dashViewMap(d, geoMode); dashDrawMap(d, geoMode); }
    };

    document.getElementById('dash-root').addEventListener('click', e => {
      const tb = e.target.closest('[data-tab]');
      if (tb) {
        tab = tb.dataset.tab;
        try { localStorage.setItem(DASH_TAB_KEY, tab); } catch {}
        draw();
        return;
      }
      const gm = e.target.closest('.dash-geo-mode');
      if (gm) { geoMode = gm.dataset.mode; draw(); }
    });

    draw();
    const mq = matchMedia("(max-width:600px)");
    if (window._dashMq) window._dashMq[0].removeEventListener("change", window._dashMq[1]);
    const onMq = () => { if (document.getElementById("dash-root")) draw(); };
    mq.addEventListener("change", onMq);
    window._dashMq = [mq, onMq];
    if (typeof refreshNavEdges === 'function') refreshNavEdges();
  } catch (e) { content.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`; }
};
