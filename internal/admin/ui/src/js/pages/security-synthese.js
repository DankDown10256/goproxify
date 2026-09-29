// ── PAGE PARTAGÉE: Sécurité › Synthèse (Admin + passerelle) + fenêtre « Moteurs de sécurité » ──
// ctx = { mode: 'admin'|'edge' }. Admin : agrégat de toutes les passerelles. Passerelle : données
// filtrées sur ses proxies / domaines (resolveSecurityEdgeCtx), réglages Sentinel propres à la passerelle.

const _syn = { mode: 'admin', tl: 'all', tlN: 8, events: [], atkLive: true, atkStyle: 'zones', atkMode: 'errors', atkHideInternal: true, atkTimer: null };

// Carte des attaques : requêtes en erreur et IPs bannies des 24 dernières heures (couche fixe,
// mode Erreurs/IPs bannies + styles Zones/Villes/Régions — mêmes fonctionnalités que la carte
// « Trafic par pays » de Prism : détail pays/ville au clic, top attaquants, masquage du trafic interne),
// puis flux temps réel des événements « error » / « banned » (pulsations sur la ville source).
async function synAttackMap(mode) {
  if (_syn.atkTimer) { clearInterval(_syn.atkTimer); _syn.atkTimer = null; }
  const box = document.getElementById('sy-atk-map');
  if (!box) return;
  const node = mode === 'edge' ? edgePrismNodeName() : '';
  const to = new Date();
  const q = new URLSearchParams({ from: new Date(to - 86400000).toISOString(), to: to.toISOString() });
  if (node) q.set('node_name', node);
  const [geo, pts] = await Promise.all([
    api('GET', '/prism/geo?' + q).catch(() => []),
    api('GET', '/prism/geo/points?' + q + '&limit=1000').catch(() => []),
  ]);
  let lastGeo = Array.isArray(geo) ? geo : [];
  let lastPts = Array.isArray(pts) ? pts : [];

  let ctl;
  try { ctl = await gpxGeoMap(box, { onCountry: cc => openCountry(cc), onPoint: pt => openPoint(pt) }); } catch { box.innerHTML = ''; return; }

  const atkVal = e => _syn.atkMode === 'banned_ips' ? (e.banned_ips || 0) : (e.errors || 0);

  function renderTop() {
    const topEl = document.getElementById('sy-atk-top');
    if (!topEl) return;
    const flagOf = cc => (!cc || cc.length !== 2 || cc === 'XX' || cc === 'LO') ? '🌐' : String.fromCodePoint(0x1F1E6 + cc.charCodeAt(0) - 65, 0x1F1E6 + cc.charCodeAt(1) - 65);
    const top = geoSortLocalLast(lastGeo.filter(e => atkVal(e) > 0), atkVal).slice(0, 8);
    const maxVal = Math.max(...top.map(atkVal), 1);
    topEl.innerHTML = top.length ? top.map(e => `<button type="button" class="prism-toprow${e.country_code === selCc ? ' sel' : ''}" data-cc="${esc(e.country_code)}" onclick="synAtkOpenCountry('${esc(e.country_code)}')">
      <span class="prism-toprow-flag">${flagOf(e.country_code)}</span>
      <span class="prism-toprow-main"><span class="prism-toprow-head"><span>${esc(e.country_name)}</span><b>${fmtNum(atkVal(e))}</b></span>
      <span class="prism-bar-bg"><span class="prism-bar-fill" style="width:${(atkVal(e) / maxVal * 100).toFixed(1)}%"></span></span></span>
    </button>`).join('') : `<p class="prism-muted">${esc(t('sy.atk_wait'))}</p>`;
  }

  let selCc = '';
  const push = () => {
    ctl.update({ countries: lastGeo, points: lastPts, mode: _syn.atkMode, style: _syn.atkStyle, selected: selCc });
    renderTop();
  };
  push();

  function openCountry(cc) {
    const e = lastGeo.find(g => g.country_code === cc);
    const dr = document.getElementById('sy-atk-drawer');
    if (!e || !dr) return;
    selCc = cc;
    push();
    const flagOf = (!cc || cc.length !== 2 || cc === 'XX' || cc === 'LO') ? '🌐' : String.fromCodePoint(0x1F1E6 + cc.charCodeAt(0) - 65, 0x1F1E6 + cc.charCodeAt(1) - 65);
    const stat = (l, v, warn) => `<div class="prism-dstat"><span>${l}</span><b${warn ? ' style="color:var(--red)"' : ''}>${v}</b></div>`;
    dr.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <span class="prism-panel-title" style="margin:0">${esc(t('pz.country_detail'))}</span>
        <button type="button" class="btn btn-ghost btn-sm" onclick="synAtkCloseDrawer()">✕</button>
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

  function openPoint(pt) {
    const dr = document.getElementById('sy-atk-drawer');
    if (!dr) return;
    const place = [pt.city, pt.region].filter(Boolean).join(', ') || pt.country_name;
    const stat = (l, v, warn) => `<div class="prism-dstat"><span>${l}</span><b${warn ? ' style="color:var(--red)"' : ''}>${v}</b></div>`;
    dr.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <span class="prism-panel-title" style="margin:0">${esc(t('pz.city_detail'))}</span>
        <button type="button" class="btn btn-ghost btn-sm" onclick="synAtkCloseDrawer()">✕</button>
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

  window.synAtkOpenCountry = openCountry;
  window.synAtkCloseDrawer = () => { selCc = ''; document.getElementById('sy-atk-drawer')?.classList.remove('open'); push(); };

  const feedEl = document.getElementById('sy-atk-feed');
  let feed = [];
  let since = new Date().toISOString();
  const isInternalEvent = e => _syn.atkHideInternal && e.country_code === 'LO';
  // Fusionne les events consécutifs identiques (même IP/domaine/kind — scan ou tentative répétée
  // bannie) en une seule ligne avec un compteur (même mécanique que le flux live de Prism, 0.63.4).
  const collapseLiveFeed = events => {
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
  };
  const renderFeed = () => {
    if (!feedEl) return;
    feedEl.innerHTML = feed.length ? feed.map(ev => `<div class="live-feed-row">
      <span class="live-feed-kind" style="color:${ev.kind === 'banned' ? 'var(--red)' : 'var(--yellow)'}">${ev.kind === 'banned' ? 'BAN' : 'ERR'}</span>
      <span class="live-feed-flag">${esc(ev.country_code || '')}</span>
      <code class="live-feed-ip">${esc(ev.ip)}</code>
      <span class="live-feed-domain" title="${esc(ev.domain)}">${esc(ev.domain)}</span>
      ${ev.count > 1 ? `<span class="live-feed-count" title="${ev.count} occurrences">×${ev.count}</span>` : ''}
      <span class="live-feed-ts">${esc((ev.ts || '').replace('T', ' ').slice(11, 19))}</span></div>`).join('')
      : `<div style="color:var(--text3);font-size:12px;padding:8px 0">${esc(t('sy.atk_wait'))}</div>`;
  };
  renderFeed();

  window.synAtkStyle = s => {
    _syn.atkStyle = s;
    push();
    document.querySelectorAll('.sy-atk-style').forEach(b => b.classList.toggle('active', b.dataset.style === s));
  };
  window.synAtkMode = m => {
    _syn.atkMode = m;
    push();
    document.querySelectorAll('.sy-atk-mode').forEach(b => b.classList.toggle('active', b.dataset.mode === m));
  };
  window.synAtkHideInternal = on => { _syn.atkHideInternal = on; };
  window.synAtkLive = () => {
    _syn.atkLive = !_syn.atkLive;
    const b = document.getElementById('sy-atk-live');
    if (b) { b.classList.toggle('is-active', _syn.atkLive); b.setAttribute('aria-pressed', String(_syn.atkLive)); }
  };

  _syn.atkTimer = setInterval(async () => {
    if (!box.isConnected) { clearInterval(_syn.atkTimer); _syn.atkTimer = null; ctl.destroy(); return; }
    if (!_syn.atkLive) return;
    const p = new URLSearchParams({ since, limit: '100' });
    if (node) p.set('node_name', node);
    const ev = await api('GET', '/prism/live-ips?' + p).catch(() => []);
    if (!Array.isArray(ev) || !ev.length) return;
    since = ev[0].ts || since;
    const visible = ev.filter(e => e.kind !== 'visit' && !isInternalEvent(e));
    const fresh = visible.filter(e => !feed.some(f => f.ip === e.ip && f.ts === e.ts));
    if (!fresh.length) return;
    ctl.pulse(fresh);
    feed = collapseLiveFeed([...fresh, ...feed]).slice(0, 8);
    renderFeed();
  }, 4000);
}

function synCertScore(certs) {
  if (!certs.length) return 100;
  const bad = certs.filter(c => c.status === 'expired' || c.status === 'expiring').length;
  return Math.round(100 * (certs.length - bad) / certs.length);
}

// Combine risque CVE, en-têtes et certificats : 50 % / 30 % / 20 %. Calculé dans le navigateur.
function synScore(cves, headers, certs) {
  const risk = vsRiskScore(cves);
  const hdr = headers.length ? Math.round(headers.reduce((s, h) => s + (h.score || 0), 0) / headers.length) : risk;
  return { total: Math.round(risk * 0.5 + hdr * 0.3 + synCertScore(certs) * 0.2), headers: hdr };
}

function synRingHTML(score) {
  const color = score >= 80 ? 'var(--green)' : score >= 55 ? 'var(--yellow)' : 'var(--red)';
  return `<div class="vs-ring sy-ring" style="--p:${score};--c:${color}" role="img" aria-label="${esc(t('sy.score'))} ${score}/100" title="${esc(t('sy.score_formula'))}"><div><span><b>${score}</b><small>/100</small></span></div></div>`;
}

function synRankHTML(cves, isAdmin) {
  const open = cves.filter(vsIsOpen);
  const map = new Map();
  for (const c of open) {
    const k = isAdmin ? (c.edge_name || '—') : (c.backend_url || '—');
    if (!map.has(k)) map.set(k, []);
    map.get(k).push(c);
  }
  const rows = [...map.entries()].map(([k, l]) => ({ k, l, score: vsRiskScore(l) })).sort((a, b) => a.score - b.score).slice(0, 5);
  if (!rows.length) return `<div class="empty"><p>${esc(t('sy.rank_empty'))}</p></div>`;
  return `<div class="sy-rank">${rows.map(r => `<div class="sy-rank-row">
    <span class="mono sy-rank-n">${esc(r.k)}</span>${vsSevBar(r.l)}
    <span class="sy-rank-c">${esc(t('sy.cve_short', { n: r.l.length }))} · <b>${r.score}</b></span></div>`).join('')}</div>`;
}

function synTimelineHTML() {
  const all = _syn.events;
  const types = [['all', 'sy.tl_all'], ['ban', 'sy.tl_ban'], ['threat', 'sy.tl_threat'], ['cve', 'sy.tl_cve'], ['cert', 'sy.tl_cert']];
  const chips = types.map(([k, key]) => {
    const n = k === 'all' ? all.length : all.filter(e => e.type === k).length;
    return `<button type="button" class="chip${_syn.tl === k ? ' active' : ''}" aria-pressed="${_syn.tl === k}" onclick="synSetTl('${k}')">${esc(t(key))}<span class="chip-n">${n}</span></button>`;
  }).join('');
  const list = all.filter(e => _syn.tl === 'all' || e.type === _syn.tl);
  const tagCls = { ban: 'ban', threat: 'threat', cve: 'cve', cert: 'cert' };
  const rows = list.slice(0, _syn.tlN).map(e => `<div class="sy-ev">
      <span class="sy-tag sy-${tagCls[e.type] || 'ban'}">${esc(t('sy.tl_' + (tagCls[e.type] || 'ban')))}</span>
      <div class="sy-ev-txt">${esc(e.summary || '')}${e.ip ? `<span class="mono">${esc(e.ip)}</span>` : ''}</div>
      <span class="sy-ev-time">${e.created_at ? esc(fmtDate(e.created_at)) : ''}</span>
      ${e.edge_name && _syn.mode === 'admin' ? `<span class="sy-ev-gw mono">${esc(e.edge_name)}</span>` : ''}
    </div>`).join('');
  return `<div class="vs-chips" role="group" aria-label="${esc(t('sy.timeline'))}">${chips}</div>
    <div class="sy-tl">${rows || `<div class="empty"><p>${esc(t('security.no_events'))}</p></div>`}</div>
    ${list.length > _syn.tlN ? `<button type="button" class="btn btn-ghost btn-sm" onclick="synMoreTl()">${esc(t('sy.tl_more', { n: list.length - _syn.tlN }))}</button>` : ''}`;
}

window.synSetTl = function(k) { _syn.tl = k; _syn.tlN = 8; const el = document.getElementById('sy-tl-box'); if (el) el.innerHTML = synTimelineHTML(); };
window.synMoreTl = function() { _syn.tlN += 12; const el = document.getElementById('sy-tl-box'); if (el) el.innerHTML = synTimelineHTML(); };

function synEnginesHTML(f2b, cs, threat, rules, isAdmin) {
  const engines = [
    { id: 'sentinel', label: 'Sentinel', on: !!threat?.enabled },
    { id: isAdmin ? 'f2b' : 'ips', label: 'Fail2Ban', on: !!f2b?.enabled },
    { id: isAdmin ? 'cs' : 'ips', label: 'CrowdSec', on: !!cs?.enabled },
  ];
  if (isAdmin) {
    const active = rules.filter(r => r.enabled).length;
    engines.push({ id: 'rules', label: t('security.rules.tab_rules'), on: active > 0, sub: `${active}/${rules.length}` });
  }
  const openN = engines.filter(e => e.on).length;
  return `<div class="card blueprint sy-card">
    <div class="sy-card-h"><h3>${esc(t('sm.title'))} <span class="sy-muted">· ${esc(t('sy.engines_count', { n: openN, m: engines.length }))}</span></h3>
      <button type="button" class="btn btn-ghost btn-sm" onclick="secEnginesOpen('sentinel')">${esc(t('sy.engines_manage'))}</button></div>
    <div class="sy-engines">${engines.map(e => `<button type="button" class="sy-eng${e.on ? ' on' : ''}" onclick="secEnginesOpen('${e.id}')"><i></i>${esc(e.label)}<small>${esc(e.sub || t(e.on ? 'security.engine_active' : 'security.engine_inactive'))}</small></button>`).join('')}</div>
  </div>`;
}

async function renderSecuritySynthese(ctx) {
  const mode = ctx?.mode || 'admin';
  const isAdmin = mode === 'admin';
  const content = document.getElementById('content');
  content.innerHTML = '<p style="color:var(--text2)">' + t('common.loading') + '</p>';
  const ta = document.getElementById('topbar-actions');
  if (ta) ta.innerHTML = '';

  try {
    const edgeCtx = await resolveSecurityEdgeCtx(mode);
    if (!isAdmin && edgeCtx?.missing) {
      content.innerHTML = '<p style="color:var(--text2)">' + t('trafic.no_edge') + '</p>';
      return;
    }
    const edgeQ = edgeCtx?.edgeRef ? `?edge=${encodeURIComponent(edgeCtx.edgeRef)}` : '';
    window._secEdgeQ = edgeQ;
    const [ovData, timeline, bansRaw, cvesRaw, threatCfg, f2bCfg, csCfg, rulesRaw] = await Promise.all([
      api('GET', '/security/overview').catch(() => ({})),
      api('GET', '/security/timeline?limit=100&source=all').catch(() => []),
      api('GET', '/security/bans?active=true').catch(() => []),
      api('GET', '/security/cves').catch(() => []),
      api('GET', `/security/threat-config${edgeQ}`).catch(() => null),
      api('GET', '/security/fail2ban').catch(() => null),
      api('GET', '/security/crowdsec').catch(() => null),
      isAdmin ? api('GET', '/rules-engine/rules').catch(() => []) : Promise.resolve([]),
    ]);
    const ov = ovData?.overview || {};
    const headers = filterSecHeaders(ov.headers || [], edgeCtx);
    const certs = filterSecCerts(ovData?.certs || [], edgeCtx);
    const cves = filterSecCVEs(cvesRaw || [], edgeCtx);
    const bans = filterSecBans(bansRaw || [], edgeCtx);
    const events = filterSecTimeline(timeline || [], edgeCtx);
    const rules = Array.isArray(rulesRaw) ? rulesRaw : (rulesRaw?.rules || []);

    _syn.mode = mode;
    _syn.events = events;
    if (_syn.scope !== mode + ':' + (edgeCtx?.edgeRef || '')) { _syn.scope = mode + ':' + (edgeCtx?.edgeRef || ''); _syn.tl = 'all'; _syn.tlN = 8; }

    const openCves = cves.filter(vsIsOpen);
    const critical = openCves.filter(c => vsSev(c.cvss_score) === 'crit').length;
    const certsExpired = certs.filter(c => c.status === 'expired').length;
    const certsExpiring = certs.filter(c => c.status === 'expiring').length;
    const certsOk = certs.length - certsExpired - certsExpiring;
    const sc = synScore(cves, headers, certs);
    const threats = ov.active_threats || 0;
    const navBans = securityPageId('bans', mode);
    const navVulns = securityPageId('vulns', mode);
    const navPosture = securityPageId('posture', mode);
    const gwCount = new Set(cves.map(c => c.edge_name).filter(Boolean)).size;
    const sub = isAdmin ? t('security.vs.sub_admin', { n: gwCount || (edgeCtx ? 1 : '—') }) : t('security.vs.sub_edge', { name: esc(edgeCtx.edgeLabel) });
    const tileClick = p => `onclick="navigate('${p}')"`;
    const tileClickTab = (p, tab) => `onclick="navigateBansTab('${p}','${tab}')"`;

    content.innerHTML = `
      ${securityEdgeBanner(edgeCtx)}
      <div class="vs-page-head">
        <div><h2 class="vs-title">${esc(t('sec.tab.overview'))}</h2><div class="vs-sub">${sub}</div></div>
        <div class="sy-head-acts">
          <button type="button" class="btn btn-ghost btn-icon" onclick="reloadCurrentSecurityPage()" title="${esc(t('sy.refresh'))}" aria-label="${esc(t('sy.refresh'))}"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><polyline points="23 4 23 10 17 10"/><path d="M20.5 15a9 9 0 11-2.1-9.4L23 10"/></svg></button>
          <button type="button" class="btn btn-ghost btn-icon" onclick="secEnginesOpen('sentinel')" title="${esc(t('sm.title'))}" aria-label="${esc(t('sm.title'))}"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 01-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg></button>
        </div>
      </div>

      <div class="sy-top">
        <div class="card blueprint sy-card"><div class="sy-card-h"><h3>${esc(t('sy.score'))}</h3></div>
          <div class="sy-score">${synRingHTML(sc.total)}<ul>
            <li>${esc(t('sy.score_open'))} <b>${openCves.length}</b></li>
            <li>${esc(t('sy.score_headers'))} <b>${sc.headers}/100</b></li>
            <li>${esc(t('sy.score_certs'))} <b>${certsExpired + certsExpiring}</b></li></ul></div></div>
        <div class="sy-kpis">
          <button type="button" class="sec-tile sy-kpi" ${tileClick(navBans)}><span class="sec-tile-label">${esc(t('sy.k_bans'))}</span><span class="sec-tile-value" style="color:${bans.length ? 'var(--red)' : 'var(--green)'}">${bans.length}</span><span class="sec-tile-sub">${esc(t('sy.k_bans_s'))}</span></button>
          <button type="button" class="sec-tile sy-kpi" ${tileClickTab(navBans, 'crowdsec')}><span class="sec-tile-label">${esc(t('sy.k_threats'))}</span><span class="sec-tile-value" style="color:${threats ? 'var(--red)' : 'var(--green)'}">${threats}</span><span class="sec-tile-sub">${esc(t('sy.k_threats_s'))}</span></button>
          <button type="button" class="sec-tile sy-kpi" ${tileClick(navVulns)}><span class="sec-tile-label">${esc(t('sy.k_cves'))}</span><span class="sec-tile-value" style="color:${critical ? 'var(--orange,#d97706)' : 'var(--green)'}">${critical}</span><span class="sec-tile-sub">${esc(t('sy.k_cves_open', { n: openCves.length }))}</span></button>
          <button type="button" class="sec-tile sy-kpi" ${tileClick(navPosture)}><span class="sec-tile-label">${esc(t('sy.k_certs'))}</span><span class="sec-tile-value" style="color:${certsExpired ? 'var(--red)' : certsExpiring ? 'var(--yellow)' : 'var(--green)'}">${certs.length}</span><span class="sec-tile-sub">${esc(t('sy.k_certs_s', { a: certsExpiring, b: certsExpired }))}</span></button>
        </div>
      </div>

      ${synEnginesHTML(f2bCfg, csCfg, threatCfg, rules, isAdmin)}

      <div class="card blueprint sy-card"><div class="sy-card-h"><h3>${esc(t('sy.atk_title'))} <span class="vs-hint" style="font-weight:400">${esc(t('sy.atk_sub'))}</span></h3>
        <span style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
          <button type="button" id="sy-atk-live" class="btn btn-ghost btn-sm${_syn.atkLive ? ' is-active' : ''}" aria-pressed="${_syn.atkLive}" onclick="synAtkLive()">${esc(t('sy.atk_live'))}</button>
          <span class="btn-group" role="group" aria-label="Vue">
            <button type="button" class="btn btn-xs sy-atk-mode${_syn.atkMode === 'errors' ? ' active' : ''}" data-mode="errors" onclick="synAtkMode('errors')">${esc(t('sy.atk_mode_err'))}</button>
            <button type="button" class="btn btn-xs sy-atk-mode${_syn.atkMode === 'banned_ips' ? ' active' : ''}" data-mode="banned_ips" onclick="synAtkMode('banned_ips')">${esc(t('sy.atk_mode_ban'))}</button>
          </span>
          <span class="btn-group" role="group" aria-label="Style">
            <button type="button" class="btn btn-xs sy-atk-style${_syn.atkStyle === 'zones' ? ' active' : ''}" data-style="zones" onclick="synAtkStyle('zones')">${esc(t('sy.atk_zones'))}</button>
            <button type="button" class="btn btn-xs sy-atk-style${_syn.atkStyle === 'cities' ? ' active' : ''}" data-style="cities" onclick="synAtkStyle('cities')">${esc(t('sy.atk_cities'))}</button>
            <button type="button" class="btn btn-xs sy-atk-style${_syn.atkStyle === 'regions' ? ' active' : ''}" data-style="regions" onclick="synAtkStyle('regions')">${esc(t('sy.atk_regions'))}</button>
          </span>
          <a onclick="navigate('${isAdmin ? 'prism' : 'edge-prism'}')">${esc(t('sy.atk_prism'))}</a>
        </span></div>
        <div class="prism-hero" style="margin-top:8px">
          <div class="prism-panel prism-mapcard" style="padding:0"><div id="sy-atk-map" class="prism-mapbox gm-box" style="height:340px"><div class="spinner" style="margin:120px auto"></div></div></div>
          <div class="prism-rail">
            <div class="prism-panel"><div class="prism-panel-title">${esc(t('sy.atk_top'))}</div><div id="sy-atk-top"><p class="prism-muted">…</p></div></div>
          </div>
        </div>
        <div style="display:flex;align-items:center;gap:8px;margin-top:10px;flex-wrap:wrap">
          <span class="logs-live-dot"></span>
          <span style="font-size:11px;font-weight:600;color:var(--text2)">${esc(t('pz.live_conns'))}</span>
          <label class="logs-toggle-inline" style="margin-left:auto">
            <span class="toggle"><input type="checkbox" id="sy-atk-hide-internal" ${_syn.atkHideInternal ? 'checked' : ''} onchange="synAtkHideInternal(this.checked)"><span class="toggle-slider"></span></span>
            ${esc(t('logs.hide_internal'))}
          </label>
        </div>
        <div id="sy-atk-feed" class="live-feed" style="max-height:170px;overflow-y:auto;font-size:11px;margin-top:4px"></div>
        <aside class="prism-drawer" id="sy-atk-drawer"></aside></div>

      <div class="card blueprint sy-card"><div class="sy-card-h"><h3>${esc(t('security.overview_activity_24h'))}</h3></div>${secActivityChartHTML(events)}</div>

      <div class="sy-grid2">
        <div class="card blueprint sy-card"><div class="sy-card-h"><h3>${esc(t('security.overview_bans_by_source'))}</h3><a onclick="navigate('${navBans}')">${esc(t('sy.view_bans'))}</a></div>${secBansBySourceHTML(bans)}</div>
        <div class="card blueprint sy-card"><div class="sy-card-h"><h3>${esc(t('security.overview_top_threats'))}</h3><a onclick="navigate('${navBans}')">${esc(t('sy.view_all'))}</a></div><div class="sy-threats">${secTopThreatsHTML(events.slice(0, 20), navBans)}</div></div>
      </div>

      <div class="sy-grid2">
        <div class="card blueprint sy-card"><div class="sy-card-h"><h3>${esc(t(isAdmin ? 'sy.rank_gw' : 'sy.rank_be'))}</h3><a onclick="navigate('${navVulns}')">${esc(t('sec.tab.vulns'))}</a></div>${synRankHTML(cves, isAdmin)}<div class="vs-hint">${esc(t(isAdmin ? 'sy.rank_hint_gw' : 'sy.rank_hint_be'))}</div></div>
        <div class="card blueprint sy-card"><div class="sy-card-h"><h3>${esc(t('sy.posture'))}</h3><a onclick="navigate('${navPosture}')">${esc(t('sec.tab.posture'))}</a></div>
          <div class="sy-posture">
            <div><b style="color:${scoreColor(sc.headers)}">${sc.headers}/100</b><span>${esc(t('sy.posture_headers'))}</span></div>
            <div><b>${certsOk}</b><span>${esc(t('sy.posture_valid'))}</span></div>
            <div><b style="color:${certsExpiring ? 'var(--yellow)' : 'inherit'}">${certsExpiring}</b><span>${esc(t('sy.posture_soon'))}</span></div>
            <div><b style="color:${certsExpired ? 'var(--red)' : 'inherit'}">${certsExpired}</b><span>${esc(t('sy.posture_expired'))}</span></div>
          </div></div>
      </div>

      <div class="card blueprint sy-card"><div class="sy-card-h"><h3>${esc(t('sy.timeline'))}</h3></div><div id="sy-tl-box">${synTimelineHTML()}</div></div>`;
    synAttackMap(mode);
  } catch (e) { toast(e.message, 'error'); }
}

pages.security = () => renderSecuritySynthese({ mode: 'admin' });
pages['edge-security'] = () => renderSecuritySynthese({ mode: 'edge' });

// ── Fenêtre « Moteurs de sécurité » ─────────────────────────────────────────────────
// Chaque interrupteur s'applique immédiatement (comme les anciens interrupteurs de moteur) :
// lecture-modification-écriture de la configuration du moteur, puis toast.
// Fail2Ban, CrowdSec et le scanner sont des réglages globaux (Admin) ; Sentinel et le moteur IPS
// actif sont propres à la passerelle (`?edge=`).

const _sm = { open: false, tab: 'sentinel', mode: 'admin', q: '', f2b: {}, cs: {}, threat: {}, provider: 'native', rules: [], scan: {}, prev: {}, pendingNum: null, dirty: false };

// Caps dont la valeur est un nombre à saisir (pas un simple on/off) : le champ du réglage tombe à
// une valeur « désactivée » (0, ou permanent) quand on bascule, donc le chiffre d'origine est perdu —
// réactiver la limite ne doit jamais deviner un chiffre à sa place (voir smSentinelCap / smF2BCap).
// `promptOn` : état du switch (true/false) qui déclenche la demande de valeur.
const SM_NUM_CAPS = {
  smSentinelCap: {
    rate:    { field: 'rate_limit',      unitKey: 'sm.unit_reqs',   min: 0.5, step: 0.5, promptOn: true },
    errors:  { field: 'error_threshold', unitKey: 'sm.unit_errs',   min: 1,   step: 1,   promptOn: true },
    global:  { field: 'global_rps',      unitKey: 'sm.unit_reqs',   min: 1,   step: 1,   promptOn: true },
  },
  smF2BCap: {
    // « Ban permanent » à false = ban temporaire : il faut alors une durée (en heures, converties en
    // secondes). Désactiver l'interrupteur (permanent → false) est donc l'état qui demande une valeur.
    permanent: { field: 'ban_duration_sec', unitKey: 'sm.unit_hours', min: 1, step: 1, promptOn: false, toSeconds: 3600 },
  },
};

function smSentinelCaps() {
  const c = _sm.threat || {};
  const lists = c.lists || {};
  return [
    { key: 'block', label: t('sm.cap.block'), desc: t('sm.cap.block_d'), on: (c.mode || 'block') === 'block' },
    { key: 'ip', label: t('sm.cap.ip'), desc: t('sm.cap.ip_d'), on: !!lists.ip_enabled },
    { key: 'ua', label: t('sm.cap.ua'), desc: t('sm.cap.ua_d'), on: !!lists.ua_enabled },
    { key: 'path', label: t('sm.cap.path'), desc: t('sm.cap.path_d'), on: !!lists.path_enabled },
    { key: 'rate', label: t('sm.cap.rate'), desc: t('sm.cap.rate_d'), on: (c.rate_limit || 0) > 0, val: c.rate_limit > 0 ? `${c.rate_limit} req/s` : '' },
    { key: 'errors', label: t('sm.cap.errors'), desc: t('sm.cap.errors_d'), on: (c.error_threshold || 0) > 0, val: c.error_threshold > 0 ? `${c.error_threshold} / ${c.error_window || '10s'}` : '' },
    { key: 'global', label: t('sm.cap.global'), desc: t('sm.cap.global_d'), on: (c.global_rps || 0) > 0, val: c.global_rps > 0 ? `${c.global_rps} req/s` : '' },
    { key: 'tarpit', label: t('sm.cap.tarpit'), desc: t('sm.cap.tarpit_d'), on: !!c.tarpit?.enabled, val: c.tarpit?.enabled ? `${(c.tarpit.delay_ms || 5000) / 1000} s` : '' },
  ];
}

// value : uniquement pour un cap numérique (SM_NUM_CAPS) qu'on active avec une valeur saisie
// explicitement (voir smSentinelCapValue) — jamais devinée.
function smApplySentinelCap(cfg, key, on, value) {
  const next = { ...cfg, lists: { ...(cfg.lists || {}) }, tarpit: { ...(cfg.tarpit || {}) } };
  const num = field => {
    if (on) next[field] = value;
    else { if (cfg[field] > 0) _sm.prev[field] = cfg[field]; next[field] = 0; }
  };
  if (key === 'block') next.mode = on ? 'block' : 'detect';
  else if (key === 'ip') next.lists.ip_enabled = on;
  else if (key === 'ua') next.lists.ua_enabled = on;
  else if (key === 'path') next.lists.path_enabled = on;
  else if (key === 'rate') num('rate_limit');
  else if (key === 'errors') num('error_threshold');
  else if (key === 'global') num('global_rps');
  else if (key === 'tarpit') next.tarpit.enabled = on;
  return next;
}

function smF2BCaps() {
  const c = _sm.f2b || {};
  const permanent = !(c.ban_duration_sec > 0);
  return [
    { key: 'xff', label: t('sm.cap.xff'), desc: t('sm.cap.xff_d'), on: !!c.trust_forwarded_for },
    { key: 'permanent', label: t('sm.cap.permanent'), desc: t('sm.cap.permanent_d'), on: permanent, val: permanent ? '' : `${Math.round(c.ban_duration_sec / 3600)} h` },
    { key: 'window', label: t('sm.cap.f2b_window'), desc: t('sm.cap.f2b_window_d'), fixed: true, val: `${c.max_errors || 20} / ${c.window_sec || 300} s` },
  ];
}

function smSwitch(on, handler, label, disabled) {
  return `<label class="sm-sw"><input type="checkbox" ${on ? 'checked' : ''} ${disabled ? 'disabled' : ''} onchange="${handler}" aria-label="${esc(label)}"><span></span></label>`;
}

// pendingKey : identifiant unique du cap en attente de saisie, tous moteurs confondus
// (ex. "smF2BCap:permanent"), pour ne jamais confondre deux caps de moteurs différents.
function smNumCapPendingKey(handler, key) { return handler + ':' + key; }
function smNumCapValueHandler(handler) { return handler === 'smF2BCap' ? 'smF2BCapValue' : 'smSentinelCapValue'; }
function smNumCapCancelHandler(handler) { return handler === 'smF2BCap' ? 'smF2BCapCancel' : 'smSentinelCapCancel'; }

function smCapsHTML(caps, handler, enabled) {
  const numCaps = SM_NUM_CAPS[handler];
  return `<div class="sm-caps${enabled ? '' : ' off'}">${caps.map(c => {
    const numCap = numCaps ? numCaps[c.key] : null;
    const pendingKey = smNumCapPendingKey(handler, c.key);
    if (numCap && _sm.pendingNum === pendingKey) {
      return `<div class="sm-cap sm-cap-pending">
        <div class="sm-cap-d"><b>${esc(c.label)}</b>${c.desc ? `<span>${esc(c.desc)}</span>` : ''}</div>
        <div class="sm-cap-input-row">
          <div class="sm-cap-r sm-cap-input">
            <input type="number" class="input" id="sm-num-${pendingKey}" min="${numCap.min}" step="${numCap.step}" placeholder="${esc(t(numCap.unitKey))}" autofocus
              onkeydown="if(event.key==='Enter'){event.preventDefault();${smNumCapValueHandler(handler)}('${c.key}')}">
            <button type="button" class="btn btn-primary btn-sm" onclick="${smNumCapValueHandler(handler)}('${c.key}')">${esc(t('sm.activate'))}</button>
            <button type="button" class="btn btn-ghost btn-sm" onclick="${smNumCapCancelHandler(handler)}()">${esc(t('common.cancel'))}</button>
          </div>
          <p class="sm-cap-input-hint">${esc(t('sm.no_default_hint'))}</p>
        </div>
      </div>`;
    }
    return `<div class="sm-cap">
    <div class="sm-cap-d"><b>${esc(c.label)}</b>${c.desc ? `<span>${esc(c.desc)}</span>` : ''}</div>
    <div class="sm-cap-r">${c.val ? `<span class="sm-val">${esc(c.val)}</span>` : ''}${c.fixed ? '' : smSwitch(c.on, `${handler}('${c.key}',this.checked)`, c.label)}</div>
  </div>`;
  }).join('')}</div>`;
}

function smMasterHTML(name, desc, on, handler, disabledNote) {
  return `<div class="sm-master"><div><b>${esc(name)}</b><p>${esc(desc)}</p>${disabledNote ? `<p class="sm-note">${esc(disabledNote)}</p>` : ''}</div>${smSwitch(on, `${handler}(this.checked)`, name, !!disabledNote)}</div>`;
}

function smTabs() {
  const admin = _sm.mode === 'admin';
  const rulesOn = _sm.rules.some(r => r.enabled);
  const list = [{ id: 'sentinel', label: 'Sentinel', on: !!_sm.threat?.enabled }];
  if (admin) {
    list.push({ id: 'f2b', label: 'Fail2Ban', on: !!_sm.f2b?.enabled }, { id: 'cs', label: 'CrowdSec', on: !!_sm.cs?.enabled }, { id: 'rules', label: t('security.rules.tab_rules'), on: rulesOn });
  } else {
    list.push({ id: 'ips', label: t('sm.tab.ips'), on: _sm.provider !== 'native' || !!_sm.f2b?.enabled || !!_sm.cs?.enabled });
  }
  list.push({ id: 'scan', label: t('sm.tab.scan'), on: null });
  return list;
}

function smPanelHTML() {
  const admin = _sm.mode === 'admin';
  switch (_sm.tab) {
    case 'sentinel': {
      const on = !!_sm.threat?.enabled;
      const caps = smSentinelCaps();
      const n = caps.filter(c => c.on).length;
      return `${smMasterHTML('Sentinel', t('sm.sentinel_d'), on, 'smMaster_sentinel')}
        ${smCapsHTML(caps, 'smSentinelCap', on)}
        <div class="vs-hint">${esc(on ? t('sm.caps_count', { n, m: caps.length }) : t('sm.off_hint'))} ${esc(t('sm.tune_hint'))}</div>
        <div><button type="button" class="btn btn-ghost btn-sm" onclick="smClose();navigate('${securityPageId('sentinel', _sm.mode)}')">${esc(t('sm.open_sentinel'))} →</button></div>`;
    }
    case 'f2b': {
      const on = !!_sm.f2b?.enabled;
      return `${smMasterHTML('Fail2Ban', t('sm.f2b_d'), on, 'smMaster_f2b')}
        ${smCapsHTML(smF2BCaps(), 'smF2BCap', on)}
        <details class="sm-more"><summary>${esc(t('sm.advanced'))}</summary>${f2bPanel(_sm.f2b)}</details>`;
    }
    case 'cs': {
      const on = !!_sm.cs?.enabled;
      return `${smMasterHTML('CrowdSec', t('sm.cs_d'), on, 'smMaster_cs')}
        <div class="sm-caps"><div class="sm-cap"><div class="sm-cap-d"><b>${esc(t('sm.cs_lapi'))}</b><span>${esc(t('sm.cs_lapi_d'))}</span></div><div class="sm-cap-r"><span class="sm-val">${esc(_sm.cs?.api_url || '—')}</span></div></div></div>
        <details class="sm-more"><summary>${esc(t('sm.advanced'))}</summary>${crowdSecPanel(_sm.cs)}</details>`;
    }
    case 'ips': {
      const opts = [['native', t('sm.prov_native'), t('sm.prov_native_d')], ['fail2ban', 'Fail2Ban', t('sm.prov_f2b_d')], ['crowdsec', 'CrowdSec', t('sm.prov_cs_d')]];
      return `<div class="sm-master"><div><b>${esc(t('sm.tab.ips'))}</b><p>${esc(t('sm.ips_d'))}</p></div></div>
        <div class="sm-caps">${opts.map(([k, l, d]) => `<button type="button" class="sm-radio${_sm.provider === k ? ' on' : ''}" onclick="smProvider('${k}')" aria-pressed="${_sm.provider === k}"><i></i><span><b>${esc(l)}</b><small>${esc(d)}</small></span></button>`).join('')}</div>
        <p class="vs-hint">${esc(t('sm.global_note', { f2b: t(_sm.f2b?.enabled ? 'security.engine_active' : 'security.engine_inactive'), cs: t(_sm.cs?.enabled ? 'security.engine_active' : 'security.engine_inactive') }))}</p>`;
    }
    case 'rules': {
      const rules = _sm.rules;
      return `<div class="sm-master"><div><b>${esc(t('security.rules.tab_rules'))}</b><p>${esc(t('sm.rules_d'))}</p></div></div>
        ${rules.length ? `<div class="sm-caps">${rules.map(r => `<div class="sm-cap"><div class="sm-cap-d"><b>${esc(r.name || r.id)}</b><span>${esc(_condLabel(r))}</span></div><div class="sm-cap-r">${smSwitch(!!r.enabled, `smRule('${esc(r.id)}',this.checked)`, r.name || r.id)}</div></div>`).join('')}</div>` : `<div class="empty"><p>${esc(t('sm.rules_empty'))}</p></div>`}
        <div><button type="button" class="btn btn-ghost btn-sm" onclick="smClose();navigate('security-rules')">${esc(t('sm.open_rules'))} →</button></div>`;
    }
    case 'scan': {
      const s = _sm.sla || {};
      const dis = admin ? '' : 'disabled';
      return `<div class="sm-master"><div><b>${esc(t('sm.tab.scan'))}</b><p>${esc(t('sm.scan_d'))}</p></div></div>
        <div class="sm-caps"><div class="sm-cap"><div class="sm-cap-d"><b>${esc(t('security.vulnscan.allow_private'))}</b><span>${esc(t('security.vulnscan.allow_private_help'))}</span></div><div class="sm-cap-r">${smSwitch(!!_sm.scan?.allow_private, 'smScanPrivate(this.checked)', t('security.vulnscan.allow_private'), !admin)}</div></div></div>
        ${admin ? '' : `<p class="vs-hint">${esc(t('sm.scan_global'))}</p>`}
        <div class="sm-master"><div><b>${esc(t('sm.sla_title'))}</b><p>${esc(t('sm.sla_hint'))}</p></div></div>
        <form class="sm-sla-form" onsubmit="smSaveSla(event)">
          <div class="sm-sla-grid">
            <label>${esc(t('security.vulns.f_critical'))}<input type="number" class="input" min="1" id="sm-sla-crit" value="${s.critical_days || 7}" ${dis}></label>
            <label>${esc(t('security.vulns.f_high'))}<input type="number" class="input" min="1" id="sm-sla-high" value="${s.high_days || 14}" ${dis}></label>
            <label>${esc(t('security.vs.s_med_full'))}<input type="number" class="input" min="1" id="sm-sla-med" value="${s.medium_days || 30}" ${dis}></label>
            <label>${esc(t('security.vs.s_low_full'))}<input type="number" class="input" min="1" id="sm-sla-low" value="${s.low_days || 90}" ${dis}></label>
          </div>
          ${admin ? `<button type="submit" class="btn btn-primary btn-sm">${esc(t('common.save'))}</button>` : `<p class="vs-hint">${esc(t('sm.sla_global'))}</p>`}
        </form>`;
    }
  }
  return '';
}

function smRender() {
  const root = document.getElementById('sm-root');
  if (!root) return;
  const admin = _sm.mode === 'admin';
  const tabs = smTabs();
  if (!tabs.some(x => x.id === _sm.tab)) _sm.tab = tabs[0].id;
  root.innerHTML = `<div class="sm-scrim" onclick="if(event.target===this)smClose()">
    <div class="sm-modal" role="dialog" aria-modal="true" aria-labelledby="sm-title">
      <div class="sm-head"><div><h2 id="sm-title">${esc(t('sm.title'))}</h2><p>${esc(admin ? t('sm.scope_admin') : t('sm.scope_edge', { name: _sm.edgeLabel || '' }))}</p></div>
        <button type="button" class="btn btn-ghost btn-icon sm-x" onclick="smClose()" aria-label="${esc(t('common.close'))}">✕</button></div>
      <div class="sm-body">
        <div class="sm-nav" role="tablist">${tabs.map(x => `<button type="button" role="tab" aria-selected="${x.id === _sm.tab}" onclick="smTab('${x.id}')">${x.on === null ? '' : `<i class="${x.on ? 'on' : ''}"></i>`}${esc(x.label)}</button>`).join('')}</div>
        <div class="sm-panel" id="sm-panel">${smPanelHTML()}</div>
      </div>
      <div class="sm-foot"><span class="vs-hint">${esc(t('sm.apply_hint'))}</span><button type="button" class="btn btn-primary" onclick="smClose()">${esc(t('common.close'))}</button></div>
    </div></div>`;
}

function _condLabel(r) {
  const type = r.condition?.type || "";
  return _COND_TYPES.find(x => x.value === type)?.label || type;
}

window.secEnginesOpen = async function(tab) {
  const mode = _syn.mode;
  const edgeQ = window._secEdgeQ || '';
  Object.assign(_sm, { open: true, tab: tab || 'sentinel', mode, dirty: false, prev: {}, edgeLabel: state.selectedEdge?.display_name || state.selectedEdge?.node_name || '' });
  let root = document.getElementById('sm-root');
  if (!root) { root = document.createElement('div'); root.id = 'sm-root'; document.body.appendChild(root); }
  root.innerHTML = `<div class="sm-scrim"><div class="sm-modal"><p style="padding:24px;color:var(--text2)">${esc(t('common.loading'))}</p></div></div>`;
  const [threat, f2b, cs, provider, rules, scan, sla] = await Promise.all([
    api('GET', `/security/threat-config${edgeQ}`).catch(() => ({})),
    api('GET', '/security/fail2ban').catch(() => ({})),
    api('GET', '/security/crowdsec').catch(() => ({})),
    api('GET', `/security/ips-provider${edgeQ}`).catch(() => ({ provider: 'native' })),
    mode === 'admin' ? api('GET', '/rules-engine/rules').catch(() => []) : Promise.resolve([]),
    api('GET', '/security/vulnscan/config').catch(() => ({})),
    api('GET', '/security/sla-config').catch(() => ({})),
  ]);
  _sm.threat = threat || {};
  _sm.f2b = f2b || {};
  _sm.cs = cs || {};
  _sm.provider = provider?.provider || 'native';
  _sm.rules = Array.isArray(rules) ? rules : (rules?.rules || []);
  _sm.scan = scan || {};
  _sm.sla = sla || {};
  window._f2bCfg = _sm.f2b;
  window._csCfg = _sm.cs;
  window._reRules = _sm.rules;
  smRender();
  document.addEventListener('keydown', smKey);
};

function smKey(e) { if (e.key === 'Escape') smClose(); }

window.smClose = function() {
  document.removeEventListener('keydown', smKey);
  document.getElementById('sm-root')?.remove();
  _sm.open = false;
  if (_sm.dirty) reloadCurrentSecurityPage();
};

window.smTab = function(id) { _sm.tab = id; smRender(); };

async function smSave(fn, ok) {
  try {
    await fn();
    _sm.dirty = true;
    toast(ok || t('sm.saved'), 'success');
  } catch (e) { toast(e.message, 'error'); }
  smRender();
}

window.smMaster_sentinel = function(on) {
  const cfg = { ..._sm.threat, enabled: on };
  return smSave(async () => { await api('PUT', `/security/threat-config${window._secEdgeQ || ''}`, cfg); _sm.threat = cfg; }, t(on ? 'security.engine_enabled' : 'security.engine_disabled'));
};
window.smSentinelCap = function(key, on) {
  const numCap = SM_NUM_CAPS.smSentinelCap[key];
  if (numCap && on === numCap.promptOn) {
    const remembered = _sm.prev[numCap.field];
    if (!(remembered > 0)) {
      // Jamais réglée (ou valeur perdue en désactivant hors de cette ouverture de fenêtre) :
      // on ne devine rien, on demande la valeur avant tout appel API.
      _sm.pendingNum = smNumCapPendingKey('smSentinelCap', key);
      smRender();
      document.getElementById('sm-num-' + _sm.pendingNum)?.focus();
      return;
    }
  }
  const cfg = smApplySentinelCap(_sm.threat, key, on, on ? _sm.prev[numCap?.field] : undefined);
  return smSave(async () => { await api('PUT', `/security/threat-config${window._secEdgeQ || ''}`, cfg); _sm.threat = cfg; });
};
window.smSentinelCapValue = function(key) {
  const pendingKey = smNumCapPendingKey('smSentinelCap', key);
  const input = document.getElementById('sm-num-' + pendingKey);
  const value = parseFloat(input?.value);
  if (!(value > 0)) { input?.focus(); return; }
  _sm.pendingNum = null;
  const cfg = smApplySentinelCap(_sm.threat, key, true, value);
  return smSave(async () => { await api('PUT', `/security/threat-config${window._secEdgeQ || ''}`, cfg); _sm.threat = cfg; });
};
window.smSentinelCapCancel = function() {
  _sm.pendingNum = null;
  smRender();
};
window.smMaster_f2b = function(on) {
  const cfg = { ..._sm.f2b, enabled: on };
  return smSave(async () => { await api('PUT', '/security/fail2ban', cfg); _sm.f2b = cfg; window._f2bCfg = cfg; }, t(on ? 'security.engine_enabled' : 'security.engine_disabled'));
};
window.smF2BCap = function(key, on) {
  if (key === 'xff') {
    const cfg = { ..._sm.f2b, trust_forwarded_for: on };
    return smSave(async () => { await api('PUT', '/security/fail2ban', cfg); _sm.f2b = cfg; window._f2bCfg = cfg; });
  }
  if (key === 'permanent') {
    const numCap = SM_NUM_CAPS.smF2BCap.permanent;
    if (on === numCap.promptOn && !(_sm.prev.f2bDuration > 0)) {
      // « Ban permanent » désactivé sans durée jamais réglée : on demande la durée, on ne devine rien.
      _sm.pendingNum = smNumCapPendingKey('smF2BCap', key);
      smRender();
      document.getElementById('sm-num-' + _sm.pendingNum)?.focus();
      return;
    }
    const cfg = { ..._sm.f2b };
    if (on) { if (cfg.ban_duration_sec > 0) _sm.prev.f2bDuration = cfg.ban_duration_sec; cfg.ban_duration_sec = 0; }
    else cfg.ban_duration_sec = _sm.prev.f2bDuration;
    return smSave(async () => { await api('PUT', '/security/fail2ban', cfg); _sm.f2b = cfg; window._f2bCfg = cfg; });
  }
};
window.smF2BCapValue = function(key) {
  const pendingKey = smNumCapPendingKey('smF2BCap', key);
  const input = document.getElementById('sm-num-' + pendingKey);
  const hours = parseFloat(input?.value);
  if (!(hours > 0)) { input?.focus(); return; }
  _sm.pendingNum = null;
  const cfg = { ..._sm.f2b, ban_duration_sec: Math.round(hours * SM_NUM_CAPS.smF2BCap.permanent.toSeconds) };
  return smSave(async () => { await api('PUT', '/security/fail2ban', cfg); _sm.f2b = cfg; window._f2bCfg = cfg; });
};
window.smF2BCapCancel = function() {
  _sm.pendingNum = null;
  smRender();
};
window.smMaster_cs = function(on) {
  const cfg = { ..._sm.cs, enabled: on };
  return smSave(async () => { await api('PUT', '/security/crowdsec', cfg); _sm.cs = cfg; window._csCfg = cfg; }, t(on ? 'security.engine_enabled' : 'security.engine_disabled'));
};
window.smProvider = function(p) {
  return smSave(async () => { await api('PUT', `/security/ips-provider${window._secEdgeQ || ''}`, { provider: p }); _sm.provider = p; });
};
window.smRule = function(id, enabled) {
  const rule = _sm.rules.find(r => String(r.id) === String(id));
  if (!rule) return;
  return smSave(async () => { await api('PUT', `/rules-engine/rules/${id}`, { ...rule, enabled }); rule.enabled = enabled; });
};
window.smScanPrivate = function(on) {
  return smSave(async () => { await api('PUT', '/security/vulnscan/config', { allow_private: on }); _sm.scan = { ..._sm.scan, allow_private: on }; window._vsConfig = _sm.scan; });
};
window.smSaveSla = function(e) {
  e.preventDefault();
  const num = (id, def) => { const v = parseInt(document.getElementById(id)?.value, 10); return Number.isFinite(v) && v > 0 ? v : def; };
  const cfg = {
    critical_days: num('sm-sla-crit', 7),
    high_days: num('sm-sla-high', 14),
    medium_days: num('sm-sla-med', 30),
    low_days: num('sm-sla-low', 90),
  };
  return smSave(async () => { await api('PUT', '/security/sla-config', cfg); _sm.sla = cfg; }, t('sm.sla_saved'));
};
