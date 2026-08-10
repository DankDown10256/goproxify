// ── PAGE PARTAGÉE: Sécurité (Admin + Core) ───────────────────────────────
// ctx = { mode: 'admin'|'core' }
// Mode core : même UI ; données filtrées sur les proxies / domaines du Core
// sélectionné (GET /proxies?core=…). Config Fail2Ban / CrowdSec = admin only.

function securityPageId(variant, mode) {
  const isCore = mode === 'core';
  const map = {
    overview: isCore ? 'core-security' : 'security',
    bans:     isCore ? 'core-security-bans' : 'security-bans',
    vulns:    isCore ? 'core-security-vulns' : 'security-vulns',
    posture:  isCore ? 'core-security-posture' : 'security-posture',
  };
  return map[variant] || map.overview;
}

function securityModeFromPage(page) {
  return (page || '').startsWith('core-security') ? 'core' : 'admin';
}

function reloadCurrentSecurityPage() {
  const p = state.page;
  if (p && SECURITY_PAGES.has(p) && typeof pages[p] === 'function') {
    pages[p]();
  } else if (typeof pages.security === 'function') {
    pages.security();
  }
}

function _secParseCfg(p) {
  if (!p?.config) return {};
  if (typeof p.config === 'object') return p.config;
  return (typeof tryJSON === 'function' ? tryJSON(p.config) : null) || {};
}

function _secBuildCoreFilter(proxies) {
  const proxyIds = new Set();
  const domains = new Set();
  const backends = new Set();
  for (const p of proxies || []) {
    if (p.id) proxyIds.add(p.id);
    const cfg = _secParseCfg(p);
    const host = String(cfg.host || p.host || '').toLowerCase().trim();
    if (host) domains.add(host);
    for (const b of (cfg.backends || p.backends || [])) {
      const url = String(typeof b === 'string' ? b : (b?.url || '')).toLowerCase().trim();
      if (url) backends.add(url);
    }
  }
  return { proxyIds, domains, backends };
}

function _secDomainMatch(domain, domains) {
  if (!domain || !domains?.size) return false;
  const d = String(domain).toLowerCase().trim();
  if (domains.has(d)) return true;
  for (const x of domains) {
    if (d === x || d.endsWith('.' + x) || x.endsWith('.' + d)) return true;
  }
  return false;
}

function _secBackendMatch(url, backends) {
  if (!url || !backends?.size) return false;
  const u = String(url).toLowerCase().trim();
  if (backends.has(u)) return true;
  for (const b of backends) {
    if (u.includes(b) || b.includes(u)) return true;
  }
  return false;
}

async function resolveSecurityCoreCtx(mode) {
  if (mode !== 'core') return null;
  const core = state.selectedCore;
  if (!core) return { missing: true };
  const tokens = await api('GET', '/tokens?role=core').catch(() => []);
  const match = (tokens || []).filter(tok => !tok.revoked && (
    tok.id === core.id || tok.node_name === core.node_name || tok.node_name === core.id
  ));
  const best = match.find(tok => tok.id === core.id)
    || match.find(tok => tok.node_endpoint)
    || match[0]
    || null;
  const coreRef = best?.id || core.node_name || core.id || '';
  if (!coreRef) return { missing: true };
  const proxies = await api('GET', `/proxies?core=${encodeURIComponent(coreRef)}`).catch(() => []);
  const filter = _secBuildCoreFilter(proxies);
  return {
    core,
    coreRef,
    coreLabel: core.display_name || core.node_name || core.id || '—',
    proxies: proxies || [],
    ...filter,
  };
}

function securityCoreBanner(coreCtx) {
  if (!coreCtx?.coreLabel) return '';
  return `<div style="margin-bottom:14px;padding:10px 12px;background:color-mix(in srgb,var(--accent) 7%,transparent);border:1px solid color-mix(in srgb,var(--accent) 22%,transparent);border-radius:6px;font-size:12px;color:var(--text2);">
    <strong style="color:var(--text1);">${t('security.core_banner_title')}</strong> —
    ${t('security.core_banner_body', { name: esc(coreCtx.coreLabel) })}
  </div>`;
}

function filterSecHeaders(headers, coreCtx) {
  if (!coreCtx) return headers || [];
  return (headers || []).filter(h => coreCtx.proxyIds.has(h.proxy_id));
}

function filterSecCerts(certs, coreCtx) {
  if (!coreCtx) return certs || [];
  return (certs || []).filter(c => _secDomainMatch(c.domain, coreCtx.domains));
}

function filterSecBans(bans, coreCtx) {
  if (!coreCtx) return bans || [];
  return (bans || []).filter(b => !b.domain || _secDomainMatch(b.domain, coreCtx.domains));
}

function filterSecCVEs(cves, coreCtx) {
  if (!coreCtx) return cves || [];
  return (cves || []).filter(c => _secBackendMatch(c.backend_url, coreCtx.backends));
}

function filterSecTimeline(events, coreCtx) {
  if (!coreCtx) return events || [];
  return (events || []).filter(e => {
    if (e.type === 'threat') return true;
    if (e.type === 'ban' || e.type === 'cert') {
      return !e.domain || _secDomainMatch(e.domain, coreCtx.domains);
    }
    if (e.type === 'cve') {
      const summary = String(e.summary || '').toLowerCase();
      for (const b of coreCtx.backends) {
        if (summary.includes(b)) return true;
      }
      return false;
    }
    return true;
  });
}

function filterVulnscanState(st, coreCtx) {
  if (!coreCtx || !st) return st;
  const results = Array.isArray(st.results)
    ? st.results.filter(r => _secBackendMatch(r.url, coreCtx.backends))
    : [];
  const found = results.reduce((n, r) => n + (r.cves_found || 0), 0);
  return {
    ...st,
    results,
    total_n: results.length || (st.running ? st.total_n : results.length),
    scanned_n: results.length,
    found_cves: found,
  };
}

async function renderSecurityOverview(ctx) {
  const mode = ctx?.mode || 'admin';
  const isAdmin = mode === 'admin';
  const content = document.getElementById('content');
  content.innerHTML = '<p style="color:var(--text2)">' + t('common.loading') + '</p>';
  const ta = document.getElementById('topbar-actions');
  if (ta) ta.innerHTML = '';

  try {
    const coreCtx = await resolveSecurityCoreCtx(mode);
    if (!isAdmin && coreCtx?.missing) {
      content.innerHTML = '<p style="color:var(--text2)">' + t('trafic.no_core') + '</p>';
      return;
    }

    const fetches = [
      api('GET', '/security/overview'),
      api('GET', '/security/timeline?limit=40&source=all'),
    ];
    if (coreCtx) {
      fetches.push(api('GET', '/security/bans?active=true').catch(() => []));
      fetches.push(api('GET', '/security/cves').catch(() => []));
    }
    const [ovData, timeline, bansRaw, cvesRaw] = await Promise.all(fetches);
    const ov = ovData?.overview || {};
    let headers = filterSecHeaders(ov.headers || [], coreCtx);
    let certs = filterSecCerts(ovData?.certs || [], coreCtx);
    let events = filterSecTimeline(timeline || [], coreCtx).slice(0, 20);

    let activeBans = ov.active_bans || 0;
    let activeThreats = ov.active_threats || 0;
    let openCVEs = ov.open_cves || 0;
    let criticalCVEs = ov.critical_cves || 0;
    let avgScore = Math.round(ov.avg_header_score || 0);
    let certsExpired = ov.certs_expired || 0;
    let certsExpiring = ov.certs_expiring || 0;

    if (coreCtx) {
      const bans = filterSecBans(bansRaw || [], coreCtx);
      const cves = filterSecCVEs(cvesRaw || [], coreCtx);
      activeBans = bans.length;
      openCVEs = cves.filter(c => c.status === 'open').length;
      criticalCVEs = cves.filter(c => c.status === 'open' && (c.cvss_score || 0) >= 7).length;
      avgScore = headers.length
        ? Math.round(headers.reduce((s, h) => s + (h.score || 0), 0) / headers.length)
        : 0;
      certsExpired = certs.filter(c => c.status === 'expired').length;
      certsExpiring = certs.filter(c => c.status === 'expiring').length;
    }
    const avgGrade = scoreGrade(avgScore);
    const navBans = securityPageId('bans', mode);
    const navVulns = securityPageId('vulns', mode);
    const navPosture = securityPageId('posture', mode);

    content.innerHTML = `
      ${securityCoreBanner(coreCtx)}
      <div class="sec-grid">
        <div class="sec-tile" style="cursor:pointer" onclick="navigate('${navBans}')" title="${t('security.view_bans')}">
          <div class="sec-tile-label">${t('security.active_bans')}</div>
          <div class="sec-tile-value" style="color:${activeBans>0?'var(--red)':'var(--green)'}">${activeBans}</div>
          <div class="sec-tile-sub">${t('security.bans_sub')}</div>
        </div>
        <div class="sec-tile" style="cursor:pointer" onclick="navigate('${navBans}')" title="${t('security.view_crowdsec')}">
          <div class="sec-tile-label">${t('security.crowdsec_threats')}</div>
          <div class="sec-tile-value" style="color:${activeThreats>0?'var(--red)':'var(--green)'}">${activeThreats}</div>
          <div class="sec-tile-sub">${t('security.active_decisions')}</div>
        </div>
        <div class="sec-tile" style="cursor:pointer" onclick="navigate('${navVulns}')" title="${t('security.view_vulns')}">
          <div class="sec-tile-label">${t('security.open_cves')}</div>
          <div class="sec-tile-value" style="color:${openCVEs>0?'var(--yellow)':'var(--green)'}">${openCVEs}</div>
          <div class="sec-tile-sub">${t('security.critical_cves_sub', { n: criticalCVEs })}</div>
        </div>
        <div class="sec-tile" style="cursor:pointer" onclick="navigate('${navPosture}')" title="${t('security.view_posture')}">
          <div class="sec-tile-label">${t('security.avg_header_score')}</div>
          <div class="sec-tile-value" style="color:${scoreColor(avgScore)}">${avgScore}<span style="font-size:16px;font-weight:400;color:var(--text2)">/100</span></div>
          <div class="sec-tile-sub">${t('security.avg_grade', { grade: avgGrade })}</div>
        </div>
        <div class="sec-tile">
          <div class="sec-tile-label">${t('security.certs')}</div>
          <div class="sec-tile-value" style="color:${certsExpired>0?'var(--red)':certsExpiring>0?'var(--yellow)':'var(--green)'}">${certs.length}</div>
          <div class="sec-tile-sub">${t('security.certs_sub', { expired: certsExpired, expiring: certsExpiring })}</div>
        </div>
      </div>

      <div class="card blueprint" style="margin-bottom:20px">
        <div class="card-header"><span class="card-title"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px;margin-right:6px"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>${t('security.timeline')}</span></div>
        ${timelineHTML(events)}
      </div>`;
  } catch(e) { toast(e.message,'error'); }
}

async function renderSecurityBans(ctx) {
  const mode = ctx?.mode || 'admin';
  const isAdmin = mode === 'admin';
  const content = document.getElementById('content');
  content.innerHTML = '<p style="color:var(--text2)">' + t('common.loading') + '</p>';
  const ta = document.getElementById('topbar-actions');
  if (ta) ta.innerHTML = '';

  try {
    const coreCtx = await resolveSecurityCoreCtx(mode);
    if (!isAdmin && coreCtx?.missing) {
      content.innerHTML = '<p style="color:var(--text2)">' + t('trafic.no_core') + '</p>';
      return;
    }

    const fetches = [
      api('GET', '/security/bans?active=true'),
      api('GET', '/security/threats?limit=500'),
    ];
    if (isAdmin) {
      fetches.push(api('GET', '/security/fail2ban').catch(() => null));
      fetches.push(api('GET', '/security/crowdsec').catch(() => null));
    }
    const [bansRaw, threats, f2bCfg, csCfg] = await Promise.all(fetches);
    const bans = filterSecBans(bansRaw || [], coreCtx);

    window._secBans = bans;
    window._secThreats = threats || [];
    window._secMode = mode;
    if (isAdmin) {
      window._f2bCfg = f2bCfg || {};
      window._csCfg = csCfg || {};
    }

    content.innerHTML = `
      ${securityCoreBanner(coreCtx)}
      ${isAdmin ? bansConfigBanner(f2bCfg, csCfg) : ''}
      <div class="sec-bans-list-stack">
        <div class="card blueprint">
          <div class="card-header">
            <span class="card-title"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px;margin-right:6px"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>${t('security.bans_title')}</span>
            <button class="btn btn-primary btn-sm" onclick="openBanModal()">${t('security.ban_add')}</button>
          </div>
          <div id="sec-bans-panel">${bansPanelHTML()}</div>
        </div>
        <div class="card blueprint">
          <div class="card-header"><span class="card-title"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px;margin-right:6px"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>${t('security.crowdsec_decisions')}</span></div>
          <div id="sec-threats-panel">${threatsPanelHTML()}</div>
        </div>
      </div>`;
  } catch(e) { toast(e.message,'error'); }
}

async function renderSecurityVulns(ctx) {
  const mode = ctx?.mode || 'admin';
  const isAdmin = mode === 'admin';
  const content = document.getElementById('content');
  content.innerHTML = '<p style="color:var(--text2)">' + t('common.loading') + '</p>';
  const ta = document.getElementById('topbar-actions');
  if (ta) ta.innerHTML = '';

  try {
    const coreCtx = await resolveSecurityCoreCtx(mode);
    if (!isAdmin && coreCtx?.missing) {
      content.innerHTML = '<p style="color:var(--text2)">' + t('trafic.no_core') + '</p>';
      return;
    }

    const [cvesRaw, vsStateRaw] = await Promise.all([
      api('GET', '/security/cves'),
      api('GET', '/security/vulnscan').catch(() => null),
    ]);
    const cves = filterSecCVEs(cvesRaw || [], coreCtx);
    const vsState = filterVulnscanState(vsStateRaw, coreCtx);
    window._secCoreCtx = coreCtx;
    window._secMode = mode;

    content.innerHTML = `
      ${securityCoreBanner(coreCtx)}
      <div class="card blueprint" style="margin-bottom:20px">
        <div class="card-header"><span class="card-title"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px;margin-right:6px"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>${t('security.vulns_title')}</span></div>
        ${cveTable(cves)}
      </div>

      <div class="card blueprint">
        <div class="card-header">
          <span class="card-title"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px;margin-right:6px"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>${t('security.scanner_title')}</span>
          ${isAdmin ? `<button id="vulnscan-btn" class="btn btn-primary btn-sm" onclick="triggerVulnscan()" ${vsState?.running?'disabled':''}>${t('security.scan_now')}</button>` : ''}
        </div>
        <div class="card-body" id="vulnscan-body">${vulnscanPanel(vsState)}</div>
      </div>`;
    window._secCVEs = cves;
    if (vsState?.running) startVulnscanPoll();
  } catch(e) { toast(e.message,'error'); }
}

async function renderSecurityPosture(ctx) {
  const mode = ctx?.mode || 'admin';
  const isAdmin = mode === 'admin';
  const content = document.getElementById('content');
  content.innerHTML = '<p style="color:var(--text2)">' + t('common.loading') + '</p>';
  const ta = document.getElementById('topbar-actions');
  if (ta) ta.innerHTML = '';

  try {
    const coreCtx = await resolveSecurityCoreCtx(mode);
    if (!isAdmin && coreCtx?.missing) {
      content.innerHTML = '<p style="color:var(--text2)">' + t('trafic.no_core') + '</p>';
      return;
    }

    const ovData = await api('GET', '/security/overview');
    const headers = filterSecHeaders(ovData?.overview?.headers || [], coreCtx);
    content.innerHTML = `
      ${securityCoreBanner(coreCtx)}
      <div class="card blueprint" style="margin-bottom:20px">
        <div class="card-header" style="align-items:flex-start;flex-wrap:wrap;gap:8px;">
          <div>
            <span class="card-title"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px;margin-right:6px"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>${t('security.posture_title')}</span>
            <div id="sec-posture-subtitle" style="font-size:11px;color:var(--text2);margin-top:3px;"></div>
          </div>
        </div>
        <div id="sec-posture-body">${headersGrid(headers)}</div>
      </div>`;
    window._secHeaders = headers || [];
    window._secMode = mode;
    refreshSecPostureSubtitle();
  } catch(e) { toast(e.message,'error'); }
}

pages.security = () => renderSecurityOverview({ mode: 'admin' });
pages['security-bans'] = () => renderSecurityBans({ mode: 'admin' });
pages['security-vulns'] = () => renderSecurityVulns({ mode: 'admin' });
pages['security-posture'] = () => renderSecurityPosture({ mode: 'admin' });

pages['core-security'] = () => renderSecurityOverview({ mode: 'core' });
pages['core-security-bans'] = () => renderSecurityBans({ mode: 'core' });
pages['core-security-vulns'] = () => renderSecurityVulns({ mode: 'core' });
pages['core-security-posture'] = () => renderSecurityPosture({ mode: 'core' });

function secProxyCountLabel(n, total) {
  const suffix = n === 1 ? t('security.proxy_count', { n }) : t('security.proxy_count_n', { n });
  return total != null && n !== total ? `${suffix} / ${total}` : suffix;
}

function bansConfigBanner(f2bCfg, csCfg) {
  const f2bOn = !!f2bCfg?.enabled;
  const csOn = !!csCfg?.enabled;
  return `<div class="sec-bans-config">
    <div class="sec-bans-config-head">
      <div>
        <div class="sec-bans-config-title">${t('security.bans_config_title')}</div>
        <div class="sec-bans-config-sub">${t('security.bans_config_sub')}</div>
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;">
        <span class="sec-bans-status ${f2bOn?'on':'off'}">Fail2Ban · ${f2bOn?t('common.enabled'):t('common.disabled')}</span>
        <span class="sec-bans-status ${csOn?'on':'off'}">CrowdSec · ${csOn?t('common.enabled'):t('common.disabled')}</span>
      </div>
    </div>
    <div class="sec-bans-config-grid">
      <div class="sec-bans-engine">
        <div class="sec-bans-engine-head">
          <span class="sec-bans-engine-name"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z"/></svg>${t('security.fail2ban_native')}</span>
        </div>
        ${f2bPanel(f2bCfg)}
      </div>
      <div class="sec-bans-engine">
        <div class="sec-bans-engine-head">
          <span class="sec-bans-engine-name"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>${t('security.crowdsec')}</span>
        </div>
        ${crowdSecPanel(csCfg)}
      </div>
    </div>
  </div>`;
}

function _secLocaleCompare(a, b) {
  return String(a || '').localeCompare(String(b || ''), typeof gpxBCP47 === 'function' ? gpxBCP47() : undefined);
}

function _banIsPermanent(b) {
  return !b.expires_at;
}

function _banExpiresMs(b) {
  if (!b.expires_at) return Number.POSITIVE_INFINITY;
  const ms = Date.parse(b.expires_at);
  return Number.isFinite(ms) ? ms : Number.POSITIVE_INFINITY;
}

function filterSecBansList(bans) {
  const q = (window._secBansQ || '').trim().toLowerCase();
  const source = window._secBansSource || '';
  const expiry = window._secBansExpiry || '';
  const sort = window._secBansSort || 'expires_asc';
  let list = [...(bans || [])];

  if (q) {
    list = list.filter(b => {
      const hay = `${b.ip || ''} ${b.domain || ''} ${b.source || ''} ${b.reason || ''}`.toLowerCase();
      return hay.includes(q);
    });
  }
  if (source) list = list.filter(b => (b.source || '') === source);
  if (expiry === 'permanent') list = list.filter(_banIsPermanent);
  else if (expiry === 'temporary') list = list.filter(b => !_banIsPermanent(b));

  list.sort((a, b) => {
    if (sort === 'ip_asc') return _secLocaleCompare(a.ip, b.ip);
    if (sort === 'ip_desc') return _secLocaleCompare(b.ip, a.ip);
    if (sort === 'source') return _secLocaleCompare(a.source, b.source) || _secLocaleCompare(a.ip, b.ip);
    if (sort === 'expires_desc') {
      const ea = _banExpiresMs(a), eb = _banExpiresMs(b);
      if (ea !== eb) return eb - ea;
      return _secLocaleCompare(a.ip, b.ip);
    }
    const ea = _banExpiresMs(a), eb = _banExpiresMs(b);
    if (ea !== eb) return ea - eb;
    return _secLocaleCompare(a.ip, b.ip);
  });
  return list;
}

function filterSecThreatsList(threats) {
  const q = (window._secThreatsQ || '').trim().toLowerCase();
  const type = window._secThreatsType || '';
  const sort = window._secThreatsSort || 'date_desc';
  let list = [...(threats || [])];

  if (q) {
    list = list.filter(th => {
      const hay = `${th.ip || ''} ${th.scenario || ''} ${th.origin || ''} ${th.type || ''}`.toLowerCase();
      return hay.includes(q);
    });
  }
  if (type) list = list.filter(th => (th.type || '') === type);

  list.sort((a, b) => {
    if (sort === 'ip_asc') return _secLocaleCompare(a.ip, b.ip);
    if (sort === 'ip_desc') return _secLocaleCompare(b.ip, a.ip);
    if (sort === 'scenario') return _secLocaleCompare(a.scenario, b.scenario) || _secLocaleCompare(a.ip, b.ip);
    if (sort === 'date_asc') {
      const da = Date.parse(a.created_at) || 0, db = Date.parse(b.created_at) || 0;
      return da - db || _secLocaleCompare(a.ip, b.ip);
    }
    const da = Date.parse(a.created_at) || 0, db = Date.parse(b.created_at) || 0;
    return db - da || _secLocaleCompare(a.ip, b.ip);
  });
  return list;
}

function _secBansChip(active, key, label, onclick) {
  return `<button type="button" class="sec-bans-chip${active === key ? ' is-on' : ''}" onclick="${onclick}">${label}</button>`;
}

function bansToolbarHTML(total, shown) {
  const sort = window._secBansSort || 'expires_asc';
  const source = window._secBansSource || '';
  const expiry = window._secBansExpiry || '';
  const q = window._secBansQ || '';
  const countLabel = shown === total
    ? t('security.bans_count', { n: shown })
    : t('security.bans_count_filtered', { shown, total });
  return `<div class="sec-bans-toolbar">
    <div class="sec-bans-toolbar-row">
      <input id="sec-bans-search" class="input search-input" placeholder="${t('security.search_ban_ph')}" value="${esc(q)}" oninput="setSecBansSearch(this.value)" style="max-width:240px;">
      <span id="sec-bans-count" class="sec-bans-count">${countLabel}</span>
      <select id="sec-bans-sort" onchange="setSecBansSort(this.value)" style="height:30px;font-size:12px;padding:0 6px;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg2);color:var(--text);cursor:pointer;margin-left:auto;">
        <option value="expires_asc" ${sort==='expires_asc'?'selected':''}>${t('security.sort.expires_asc')}</option>
        <option value="expires_desc" ${sort==='expires_desc'?'selected':''}>${t('security.sort.expires_desc')}</option>
        <option value="ip_asc" ${sort==='ip_asc'?'selected':''}>${t('security.sort.ip_asc')}</option>
        <option value="ip_desc" ${sort==='ip_desc'?'selected':''}>${t('security.sort.ip_desc')}</option>
        <option value="source" ${sort==='source'?'selected':''}>${t('security.sort.source')}</option>
      </select>
    </div>
    <div class="sec-bans-toolbar-row">
      <span style="font-size:11px;color:var(--text3);">${t('security.filter_source')}</span>
      ${_secBansChip(source, '', t('security.filter.all'), "setSecBansSource('')")}
      ${_secBansChip(source, 'native', t('security.source.native'), "setSecBansSource('native')")}
      ${_secBansChip(source, 'fail2ban', t('security.source.fail2ban'), "setSecBansSource('fail2ban')")}
      ${_secBansChip(source, 'crowdsec', t('security.source.crowdsec'), "setSecBansSource('crowdsec')")}
      <span style="font-size:11px;color:var(--text3);margin-left:6px;">${t('security.filter_expiry')}</span>
      ${_secBansChip(expiry, '', t('security.filter.all'), "setSecBansExpiry('')")}
      ${_secBansChip(expiry, 'permanent', t('security.filter.permanent'), "setSecBansExpiry('permanent')")}
      ${_secBansChip(expiry, 'temporary', t('security.filter.temporary'), "setSecBansExpiry('temporary')")}
    </div>
  </div>`;
}

function threatsToolbarHTML(total, shown, types) {
  const sort = window._secThreatsSort || 'date_desc';
  const type = window._secThreatsType || '';
  const q = window._secThreatsQ || '';
  const countLabel = shown === total
    ? t('security.threats_count', { n: shown })
    : t('security.threats_count_filtered', { shown, total });
  const typeChips = [_secBansChip(type, '', t('security.filter.all'), "setSecThreatsType('')")]
    .concat((types || []).map(tp => _secBansChip(type, tp, esc(tp), `setSecThreatsType('${esc(tp)}')`)))
    .join('');
  return `<div class="sec-bans-toolbar">
    <div class="sec-bans-toolbar-row">
      <input id="sec-threats-search" class="input search-input" placeholder="${t('security.search_threat_ph')}" value="${esc(q)}" oninput="setSecThreatsSearch(this.value)" style="max-width:240px;">
      <span id="sec-threats-count" class="sec-bans-count">${countLabel}</span>
      <select id="sec-threats-sort" onchange="setSecThreatsSort(this.value)" style="height:30px;font-size:12px;padding:0 6px;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg2);color:var(--text);cursor:pointer;margin-left:auto;">
        <option value="date_desc" ${sort==='date_desc'?'selected':''}>${t('security.sort.date_desc')}</option>
        <option value="date_asc" ${sort==='date_asc'?'selected':''}>${t('security.sort.date_asc')}</option>
        <option value="ip_asc" ${sort==='ip_asc'?'selected':''}>${t('security.sort.ip_asc')}</option>
        <option value="ip_desc" ${sort==='ip_desc'?'selected':''}>${t('security.sort.ip_desc')}</option>
        <option value="scenario" ${sort==='scenario'?'selected':''}>${t('security.sort.scenario')}</option>
      </select>
    </div>
    <div class="sec-bans-toolbar-row">
      <span style="font-size:11px;color:var(--text3);">${t('security.filter_type')}</span>
      ${typeChips}
    </div>
  </div>`;
}

function bansTableRows(list) {
  if (!list.length) {
    const emptyKey = (window._secBans || []).length ? 'security.no_ban_filter_match' : 'security.no_bans';
    return `<div class="empty"><p>${t(emptyKey)}</p></div>`;
  }
  return `<div class="table-wrap sec-bans-table-scroll"><table>
    <thead><tr><th>${t('logs.ip')}</th><th>${t('security.col.domain')}</th><th>${t('security.col.source')}</th><th>${t('security.col.reason')}</th><th>${t('security.col.expires')}</th><th></th></tr></thead>
    <tbody>${list.map((b) => `<tr>
      <td class="mono">${esc(b.ip)}</td>
      <td>${esc(b.domain||'—')}</td>
      <td><span class="tag tag-neutral">${esc(b.source)}</span></td>
      <td style="color:var(--text2);font-size:12px">${esc(b.reason||'—')}</td>
      <td style="font-size:11px">${b.expires_at ? fmtDate(b.expires_at) : t('common.permanent')}</td>
      <td style="display:flex;gap:4px;justify-content:flex-end">
        ${b.expires_at ? `<button type="button" class="btn btn-ghost btn-icon btn-sm" onclick="makeBanPermanent('${esc(String(b.id))}','${esc(b.ip)}')" title="${esc(t('security.ban_make_permanent'))}" aria-label="${esc(t('security.ban_make_permanent'))}"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg></button>` : ''}
        <button type="button" class="btn btn-ghost btn-icon btn-sm" onclick="deleteBan('${esc(String(b.id))}','${esc(b.ip)}')" title="${esc(t('security.unban'))}" aria-label="${esc(t('security.unban'))}" style="color:var(--red)"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/><path d="M12 16v2"/></svg></button>
      </td>
    </tr>`).join('')}</tbody>
  </table></div>`;
}

function threatsTableRows(list) {
  if (!list.length) {
    const emptyKey = (window._secThreats || []).length ? 'security.no_threat_filter_match' : 'security.no_crowdsec';
    return `<div class="empty"><p>${t(emptyKey)}</p></div>`;
  }
  return `<div class="table-wrap sec-bans-table-scroll"><table>
    <thead><tr><th>${t('logs.ip')}</th><th>${t('security.col.scenario')}</th><th>${t('security.col.origin')}</th><th>${t('security.col.type')}</th><th>${t('common.date')}</th></tr></thead>
    <tbody>${list.map(th => `<tr>
      <td class="mono">${esc(th.ip)}</td>
      <td style="font-size:12px">${esc(th.scenario)}</td>
      <td style="font-size:12px">${esc(th.origin)}</td>
      <td><span class="tag tag-red">${esc(th.type)}</span></td>
      <td style="font-size:11px">${fmtDate(th.created_at)}</td>
    </tr>`).join('')}</tbody>
  </table></div>`;
}

function bansPanelHTML() {
  const all = window._secBans || [];
  const filtered = filterSecBansList(all);
  return `${bansToolbarHTML(all.length, filtered.length)}<div id="sec-bans-table">${bansTableRows(filtered)}</div>`;
}

function threatsPanelHTML() {
  const all = window._secThreats || [];
  const filtered = filterSecThreatsList(all);
  const types = [...new Set(all.map(th => th.type).filter(Boolean))].sort(_secLocaleCompare);
  return `${threatsToolbarHTML(all.length, filtered.length, types)}<div id="sec-threats-table">${threatsTableRows(filtered)}</div>`;
}

function renderSecBansPanel(opts = {}) {
  const panel = document.getElementById('sec-bans-panel');
  if (!panel) return;
  const all = window._secBans || [];
  const filtered = filterSecBansList(all);
  if (opts.rebuildToolbar || !document.getElementById('sec-bans-search')) {
    panel.innerHTML = bansPanelHTML();
    return;
  }
  const table = document.getElementById('sec-bans-table');
  const count = document.getElementById('sec-bans-count');
  if (table) table.innerHTML = bansTableRows(filtered);
  if (count) {
    count.textContent = filtered.length === all.length
      ? t('security.bans_count', { n: filtered.length })
      : t('security.bans_count_filtered', { shown: filtered.length, total: all.length });
  }
  const source = window._secBansSource || '';
  const expiry = window._secBansExpiry || '';
  panel.querySelectorAll('button[onclick^="setSecBansSource"]').forEach(btn => {
    const m = /setSecBansSource\('([^']*)'\)/.exec(btn.getAttribute('onclick') || '');
    btn.classList.toggle('is-on', (m ? m[1] : '') === source);
  });
  panel.querySelectorAll('button[onclick^="setSecBansExpiry"]').forEach(btn => {
    const m = /setSecBansExpiry\('([^']*)'\)/.exec(btn.getAttribute('onclick') || '');
    btn.classList.toggle('is-on', (m ? m[1] : '') === expiry);
  });
}

function renderSecThreatsPanel(opts = {}) {
  const panel = document.getElementById('sec-threats-panel');
  if (!panel) return;
  const all = window._secThreats || [];
  const filtered = filterSecThreatsList(all);
  if (opts.rebuildToolbar || !document.getElementById('sec-threats-search')) {
    panel.innerHTML = threatsPanelHTML();
    return;
  }
  const table = document.getElementById('sec-threats-table');
  const count = document.getElementById('sec-threats-count');
  if (table) table.innerHTML = threatsTableRows(filtered);
  if (count) {
    count.textContent = filtered.length === all.length
      ? t('security.threats_count', { n: filtered.length })
      : t('security.threats_count_filtered', { shown: filtered.length, total: all.length });
  }
  const type = window._secThreatsType || '';
  panel.querySelectorAll('button[onclick^="setSecThreatsType"]').forEach(btn => {
    const m = /setSecThreatsType\('([^']*)'\)/.exec(btn.getAttribute('onclick') || '');
    btn.classList.toggle('is-on', (m ? m[1] : '') === type);
  });
}

window.setSecBansSearch = function(v) {
  window._secBansQ = v || '';
  renderSecBansPanel();
};
window.setSecBansSort = function(v) {
  window._secBansSort = v || 'expires_asc';
  renderSecBansPanel({ rebuildToolbar: true });
};
window.setSecBansSource = function(v) {
  window._secBansSource = v || '';
  renderSecBansPanel();
};
window.setSecBansExpiry = function(v) {
  window._secBansExpiry = v || '';
  renderSecBansPanel();
};
window.setSecThreatsSearch = function(v) {
  window._secThreatsQ = v || '';
  renderSecThreatsPanel();
};
window.setSecThreatsSort = function(v) {
  window._secThreatsSort = v || 'date_desc';
  renderSecThreatsPanel({ rebuildToolbar: true });
};
window.setSecThreatsType = function(v) {
  window._secThreatsType = v || '';
  renderSecThreatsPanel();
};

function bansTable(bans) {
  window._secBans = Array.isArray(bans) ? bans : [];
  return bansPanelHTML();
}

function threatsTable(threats) {
  window._secThreats = Array.isArray(threats) ? threats : [];
  return threatsPanelHTML();
}

function cveTable(cves) {
  if (!cves.length) return '<div class="empty"><p>' + t('security.no_cves') + '</p></div>';
  return `<div class="table-wrap"><table>
    <thead><tr><th>CVE</th><th>CVSS</th><th>${t('security.col.backend')}</th><th>${t('security.col.description')}</th><th>${t('security.col.status')}</th><th></th></tr></thead>
    <tbody>${cves.map(c => `<tr>
      <td><a href="https://nvd.nist.gov/vuln/detail/${esc(c.cve_id)}" target="_blank" style="color:var(--accent)">${esc(c.cve_id)}</a></td>
      <td><span class="tag ${c.cvss_score>=7?'tag-red':c.cvss_score>=4?'tag-yellow':'tag-neutral'}">${c.cvss_score.toFixed(1)}</span></td>
      <td class="mono" style="font-size:11px">${esc(c.backend_url)}</td>
      <td style="font-size:12px;color:var(--text2);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(c.description)}</td>
      <td><span class="tag ${c.status==='open'?'tag-yellow':c.status==='fixed'?'tag-green':'tag-neutral'}">${esc(c.status)}</span></td>
      <td style="display:flex;gap:4px">
        ${c.status!=='ignored'?`<button type="button" class="btn btn-ghost btn-icon btn-sm" onclick="updateCVE(${c.id},'ignored')" title="${esc(t('security.cve_ignore'))}" aria-label="${esc(t('security.cve_ignore'))}"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg></button>`:''}
        ${c.status!=='fixed'?`<button type="button" class="btn btn-ghost btn-icon btn-sm" onclick="updateCVE(${c.id},'fixed')" title="${esc(t('security.cve_fixed'))}" aria-label="${esc(t('security.cve_fixed'))}"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg></button>`:''}
      </td>
    </tr>`).join('')}</tbody>
  </table></div>`;
}

function _secPostureMissing(h) {
  return (h.checks || []).filter(c => !c.present).length;
}

function filterSecPostureHeaders(headers) {
  const q = (window._secPostureQ || '').trim().toLowerCase();
  const sort = window._secPostureSort || 'score_asc';
  const filter = window._secPostureFilter || '';
  let list = [...(headers || [])];

  if (q) {
    list = list.filter(h => {
      const hay = `${h.proxy_name || ''} ${h.domain || ''} ${h.grade || ''}`.toLowerCase();
      return hay.includes(q);
    });
  }
  if (filter === 'complete') list = list.filter(h => _secPostureMissing(h) === 0);
  else if (filter === 'incomplete') list = list.filter(h => _secPostureMissing(h) > 0);
  else if (filter === 'low') list = list.filter(h => (h.score || 0) < 70);
  else if (filter === 'critical') list = list.filter(h => (h.score || 0) < 40);

  const nameOf = h => (h.proxy_name || h.domain || '').toLowerCase();
  list.sort((a, b) => {
    if (sort === 'score_desc') return (b.score || 0) - (a.score || 0) || nameOf(a).localeCompare(nameOf(b), typeof gpxBCP47==='function'?gpxBCP47():undefined);
    if (sort === 'name_asc') return nameOf(a).localeCompare(nameOf(b), typeof gpxBCP47==='function'?gpxBCP47():undefined);
    if (sort === 'name_desc') return nameOf(b).localeCompare(nameOf(a), typeof gpxBCP47==='function'?gpxBCP47():undefined);
    if (sort === 'missing') return _secPostureMissing(b) - _secPostureMissing(a) || (a.score || 0) - (b.score || 0);
    return (a.score || 0) - (b.score || 0) || nameOf(a).localeCompare(nameOf(b), typeof gpxBCP47==='function'?gpxBCP47():undefined);
  });
  return list;
}

function secPostureToolbar(total, shown) {
  const sort = window._secPostureSort || 'score_asc';
  const filter = window._secPostureFilter || '';
  const q = window._secPostureQ || '';
  const chip = (key, label) => {
    const on = filter === key;
    return `<button type="button" onclick="setSecPostureFilter('${key}')" style="font-size:11px;padding:3px 9px;border-radius:99px;border:1px solid ${on?'var(--accent)':'var(--border)'};background:${on?'color-mix(in srgb,var(--accent) 12%,transparent)':'transparent'};color:${on?'var(--accent)':'var(--text2)'};cursor:pointer;">${label}</button>`;
  };
  return `<div style="padding:0 14px 10px;display:flex;flex-direction:column;gap:8px;">
    <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
      <input id="sec-posture-search" class="input search-input" placeholder="${t('security.search_proxy_ph')}" value="${esc(q)}" oninput="setSecPostureSearch(this.value)" style="max-width:220px;">
      <span id="sec-posture-count" style="font-size:12px;color:var(--text2);white-space:nowrap;">${secProxyCountLabel(shown, shown !== total ? total : null)}</span>
      <select id="sec-posture-sort" onchange="setSecPostureSort(this.value)" style="height:30px;font-size:12px;padding:0 6px;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg2);color:var(--text);cursor:pointer;">
        <option value="score_asc" ${sort==='score_asc'?'selected':''}>${t('security.sort.score_asc')}</option>
        <option value="score_desc" ${sort==='score_desc'?'selected':''}>${t('security.sort.score_desc')}</option>
        <option value="missing" ${sort==='missing'?'selected':''}>${t('security.sort.missing')}</option>
        <option value="name_asc" ${sort==='name_asc'?'selected':''}>${t('security.sort.name_asc')}</option>
        <option value="name_desc" ${sort==='name_desc'?'selected':''}>${t('security.sort.name_desc')}</option>
      </select>
    </div>
    <div style="display:flex;flex-wrap:wrap;gap:5px;align-items:center;">
      <span style="font-size:11px;color:var(--text3);">${t('security.filter_label')}</span>
      ${chip('', t('security.filter.all'))}${chip('incomplete', t('security.filter.incomplete'))}${chip('complete', t('security.filter.complete'))}${chip('low', t('security.filter.low'))}${chip('critical', t('security.filter.critical'))}
    </div>
  </div>`;
}

function headersGrid(headers) {
  const all = headers || [];
  if (!all.length) return '<div class="empty"><p>' + t('security.no_active_proxies') + '</p></div>';
  const filtered = filterSecPostureHeaders(all);
  return `${secPostureToolbar(all.length, filtered.length)}<div id="sec-posture-cards">${secPostureCardsHTML(filtered)}</div>`;
}

function secPostureChecksLabel(presentN, total, missing) {
  if (missing <= 0) return t('security.posture_complete');
  const key = missing === 1 ? 'security.checks_ok' : 'security.checks_ok_n';
  return t(key, { present: presentN, total, missing });
}

function secPostureCardsHTML(filtered) {
  if (!filtered.length) return `<div class="empty"><p>${t('security.no_filter_match')}</p></div>`;
  return `<div style="padding:4px 14px 14px;display:grid;grid-template-columns:repeat(auto-fill,minmax(min(190px,100%),1fr));gap:10px;">
    ${filtered.map(h => {
      const grade     = h.grade || 'F';
      const gc        = grade.replace('+', 'p');
      const checks    = h.checks || [];
      const missing   = checks.filter(c => !c.present);
      const presentN  = checks.length - missing.length;
      const color     = scoreColor(h.score);
      const pid       = esc(h.proxy_id || '');
      const missList  = missing.length
        ? `<ul style="margin:0;padding-left:14px;font-size:10px;color:var(--text2);line-height:1.45;">${missing.map(c => `<li>${esc(c.name)}</li>`).join('')}</ul>`
        : '';
      return `<div style="border:1px solid var(--border);border-radius:8px;padding:12px;display:flex;flex-direction:column;gap:8px;">
        <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:6px;">
          <div style="min-width:0;flex:1;">
            <div style="font-size:13px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="${esc(h.proxy_name)}">${esc(h.proxy_name)}</div>
            <div style="font-family:monospace;font-size:10px;color:var(--text2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:2px;" title="${esc(h.domain||'')}">${esc(h.domain||'—')}</div>
          </div>
          <span class="grade-badge grade-${gc}" style="width:32px;height:32px;font-size:13px;flex-shrink:0;">${esc(grade)}</span>
        </div>
        <div style="display:flex;align-items:center;gap:6px;">
          <div class="score-bar" style="flex:1;"><div class="score-fill" style="width:${h.score}%;background:${color};"></div></div>
          <span style="font-size:12px;font-weight:700;color:${color};min-width:26px;text-align:right;">${h.score}</span>
        </div>
        <div style="font-size:10px;color:${missing.length>0?'var(--text2)':'var(--green)'};">
          ${secPostureChecksLabel(presentN, checks.length, missing.length)}
        </div>
        ${missList}
        <div style="display:flex;gap:2px;margin-top:auto;justify-content:flex-end;">
          <button class="btn btn-ghost btn-icon" title="${t('security.proxy_settings')}" onclick="openProxyModal('${pid}')">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
          </button>
          <button class="btn btn-ghost btn-icon" title="${t('security.proxy_security')}" onclick="openProxySecModal('${pid}')">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4" stroke-width="2"/></svg>
          </button>
        </div>
      </div>`;
    }).join('')}
  </div>`;
}

function refreshSecPostureSubtitle() {
  const el = document.getElementById('sec-posture-subtitle');
  if (!el) return;
  const all = window._secHeaders || [];
  if (!all.length) { el.textContent = ''; return; }
  const shown = filterSecPostureHeaders(all).length;
  if (shown === all.length) {
    el.textContent = all.length === 1
      ? t('security.posture_subtitle_all', { n: all.length })
      : t('security.posture_subtitle_all_n', { n: all.length });
  } else {
    el.textContent = all.length === 1
      ? t('security.posture_subtitle_filtered', { shown, total: all.length })
      : t('security.posture_subtitle_filtered_n', { shown, total: all.length });
  }
}

function renderSecPostureGrid(opts = {}) {
  const all = window._secHeaders || [];
  const filtered = filterSecPostureHeaders(all);
  const cards = document.getElementById('sec-posture-cards');
  const count = document.getElementById('sec-posture-count');
  if (cards && document.getElementById('sec-posture-search') && !opts.rebuildToolbar) {
    cards.innerHTML = secPostureCardsHTML(filtered);
    if (count) count.textContent = secProxyCountLabel(filtered.length, filtered.length !== all.length ? all.length : null);
    const filter = window._secPostureFilter || '';
    document.querySelectorAll('#sec-posture-body button[onclick^="setSecPostureFilter"]').forEach(btn => {
      const m = /setSecPostureFilter\('([^']*)'\)/.exec(btn.getAttribute('onclick') || '');
      const key = m ? m[1] : '';
      const on = filter === key;
      btn.style.borderColor = on ? 'var(--accent)' : 'var(--border)';
      btn.style.background = on ? 'color-mix(in srgb,var(--accent) 12%,transparent)' : 'transparent';
      btn.style.color = on ? 'var(--accent)' : 'var(--text2)';
    });
  } else {
    const body = document.getElementById('sec-posture-body');
    if (body) body.innerHTML = headersGrid(all);
  }
  refreshSecPostureSubtitle();
}

window.setSecPostureSearch = function(v) {
  window._secPostureQ = v || '';
  renderSecPostureGrid();
};
window.setSecPostureSort = function(v) {
  window._secPostureSort = v || 'score_asc';
  renderSecPostureGrid({ rebuildToolbar: true });
};
window.setSecPostureFilter = function(v) {
  window._secPostureFilter = v || '';
  renderSecPostureGrid();
};

function timelineHTML(events) {
  if (!events.length) return '<div class="empty"><p>' + t('security.no_events') + '</p></div>';
  const colors = { ban: 'var(--yellow)', threat: 'var(--red)', cve: 'var(--purple)', cert: 'var(--blue)' };
  return `<div>${events.map(e => `
    <div class="timeline-item">
      <div class="timeline-dot" style="background:${colors[e.type]||'var(--text3)'}"></div>
      <div style="flex:1">
        <div style="font-size:12px">${esc(e.summary)}</div>
        <div style="font-size:11px;color:var(--text3);margin-top:2px">${fmtDate(e.created_at)}</div>
      </div>
      <span class="tag ${e.severity==='critical'?'tag-red':e.severity==='warning'?'tag-yellow':'tag-neutral'}" style="font-size:10px">${esc(e.severity)}</span>
    </div>`).join('')}</div>`;
}

function f2bPanel(cfg) {
  if (!cfg) return '<p style="color:var(--text2);font-size:12px;margin:0">' + t('common.not_available') + '</p>';
  return `<form onsubmit="saveF2BConfig(event)">
    <label style="display:flex;align-items:center;gap:8px;margin-bottom:10px;font-size:12.5px">
      <input type="checkbox" id="f2b-enabled" ${cfg.enabled?'checked':''}>
      <span>${t('security.f2b.enable')}</span>
    </label>
    <div class="sec-bans-engine-fields">
      <div class="field" style="margin:0">
        <label class="field-label">${t('security.f2b.window')}</label>
        <input id="f2b-window" type="number" class="input" value="${cfg.window_sec||300}" min="60" max="3600">
      </div>
      <div class="field" style="margin:0">
        <label class="field-label">${t('security.f2b.max_errors')}</label>
        <input id="f2b-max" type="number" class="input" value="${cfg.max_errors||20}" min="1" max="1000">
      </div>
      <div class="field" style="margin:0">
        <label class="field-label">${t('security.f2b.ban_duration')}</label>
        <input id="f2b-dur" type="number" class="input" value="${cfg.ban_duration_sec??0}" min="0" title="${esc(t('security.f2b.ban_duration_hint'))}">
      </div>
    </div>
    <label style="display:flex;align-items:center;gap:8px;margin-bottom:8px;font-size:12.5px">
      <input type="checkbox" id="f2b-xff" ${cfg.trust_forwarded_for?'checked':''}>
      <span>${t('security.f2b.trust_xff')}</span>
    </label>
    <div class="field" style="margin-bottom:10px">
      <label class="field-label">${t('security.f2b.whitelist')}</label>
      <textarea id="f2b-whitelist" class="input" rows="2" placeholder="10.0.0.0/8&#10;203.0.113.10">${(cfg.whitelist||[]).join('\n')}</textarea>
    </div>
    <button class="btn btn-primary btn-sm" type="submit">${t('common.save')}</button>
  </form>`;
}

function crowdSecPanel(cfg) {
  if (!cfg) return '<p style="color:var(--text2);font-size:12px;margin:0">' + t('common.not_available') + '</p>';
  return `<form onsubmit="saveCrowdSecConfig(event)">
    <label style="display:flex;align-items:center;gap:8px;margin-bottom:10px;font-size:12.5px">
      <input type="checkbox" id="cs-enabled" ${cfg.enabled?'checked':''}>
      <span>${t('security.cs.enable')}</span>
    </label>
    <div class="field">
      <label class="field-label">${t('security.cs.lapi_url')}</label>
      <input id="cs-url" class="input" value="${esc(cfg.api_url||'http://localhost:8080')}" placeholder="http://localhost:8080">
    </div>
    <div class="field">
      <label class="field-label">${t('security.cs.api_key')}</label>
      <input id="cs-key" class="input" type="password" value="${esc(cfg.api_key||'')}" placeholder="••••••••">
    </div>
    <button class="btn btn-primary btn-sm" type="submit">${t('common.save')}</button>
  </form>`;
}

function vulnscanStepLabel(step) {
  const key = 'security.vulnscan.step.' + step;
  const v = t(key);
  return v === key ? (step || '—') : v;
}

function vulnscanStatusLabel(status) {
  const key = 'security.vulnscan.status.' + status;
  const v = t(key);
  return v === key ? (status || '—') : v;
}

function vulnscanStatusColor(status) {
  return ({
    ok: 'var(--green)',
    unreachable: 'var(--red)',
    no_headers: 'var(--yellow)',
    probing: 'var(--accent)',
    pending: 'var(--text3)',
  })[status] || 'var(--text2)';
}

function vulnscanPanel(st) {
  if (!st) return '<p style="color:var(--text2)">' + t('common.not_available') + '</p>';
  const lastScan = st.last_scan && st.last_scan !== '0001-01-01T00:00:00Z' ? fmtDate(st.last_scan) : t('common.never');
  const finished = st.finished_at && st.finished_at !== '0001-01-01T00:00:00Z' ? fmtDate(st.finished_at) : null;
  const total = st.total_n || 0;
  const done = st.scanned_n || 0;
  const pct = st.progress_pct != null ? st.progress_pct : (total ? Math.round(done * 100 / total) : 0);
  const statusBadge = st.running
    ? '<span class="tag tag-yellow">' + t('security.vulnscan.running') + '</span>'
    : (total || st.last_scan ? '<span class="tag tag-neutral">' + t('security.vulnscan.finished') + '</span>' : '<span class="tag tag-neutral">' + t('security.vulnscan.idle') + '</span>');

  const progressBlock = st.running ? `
    <div style="margin:12px 0 4px">
      <div style="display:flex;justify-content:space-between;gap:12px;font-size:12px;margin-bottom:6px">
        <span style="color:var(--text2)">${t('security.vulnscan.progress', { done, total })}</span>
        <b>${pct}%</b>
      </div>
      <div style="height:8px;background:var(--border);border-radius:4px;overflow:hidden">
        <div style="height:100%;width:${pct}%;background:var(--accent);transition:width .3s"></div>
      </div>
      <div style="margin-top:8px;font-size:12px;color:var(--text2)">
        <div><span style="color:var(--text3)">${t('security.vulnscan.step_label')}</span> ${esc(vulnscanStepLabel(st.current_step))}</div>
        ${st.current_url ? `<div style="margin-top:2px;font-family:var(--font-mono,monospace);font-size:11px;word-break:break-all"><span style="color:var(--text3)">${t('security.vulnscan.target_label')}</span> ${esc(st.current_url)}</div>` : ''}
      </div>
    </div>` : '';

  const summary = `
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(min(140px,100%),1fr));gap:10px 16px;margin-top:12px;font-size:12.5px">
      <div><span style="color:var(--text3);display:block;font-size:10px;text-transform:uppercase;letter-spacing:.06em">${t('security.vulnscan.last_scan')}</span><b>${lastScan}</b></div>
      ${finished && !st.running ? `<div><span style="color:var(--text3);display:block;font-size:10px;text-transform:uppercase;letter-spacing:.06em">${t('security.vulnscan.finished_at')}</span><b>${finished}</b></div>` : ''}
      <div><span style="color:var(--text3);display:block;font-size:10px;text-transform:uppercase;letter-spacing:.06em">${t('security.vulnscan.backends')}</span><b>${done}${total ? ' / ' + total : ''}</b></div>
      <div><span style="color:var(--text3);display:block;font-size:10px;text-transform:uppercase;letter-spacing:.06em">${t('security.vulnscan.reachable')}</span><b style="color:var(--green)">${st.reachable_n||0}</b></div>
      <div><span style="color:var(--text3);display:block;font-size:10px;text-transform:uppercase;letter-spacing:.06em">${t('security.vulnscan.unreachable')}</span><b style="color:${(st.unreachable_n||0)>0?'var(--red)':'var(--text)'}">${st.unreachable_n||0}</b></div>
      <div><span style="color:var(--text3);display:block;font-size:10px;text-transform:uppercase;letter-spacing:.06em">${t('security.vulnscan.no_headers')}</span><b style="color:${(st.no_headers_n||0)>0?'var(--yellow)':'var(--text)'}">${st.no_headers_n||0}</b></div>
      <div><span style="color:var(--text3);display:block;font-size:10px;text-transform:uppercase;letter-spacing:.06em">${t('security.vulnscan.nvd_queries')}</span><b>${st.nvd_queries||0}</b></div>
      <div><span style="color:var(--text3);display:block;font-size:10px;text-transform:uppercase;letter-spacing:.06em">${t('security.vulnscan.cves_found')}</span><b style="color:${(st.found_cves||0)>0?'var(--yellow)':'var(--green)'}">${st.found_cves||0}</b></div>
    </div>`;

  const results = Array.isArray(st.results) ? st.results : [];
  const resultsBlock = results.length ? `
    <div style="margin-top:16px">
      <div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--text3);margin-bottom:8px">${t('security.vulnscan.detail_title')}</div>
      <div class="table-wrap"><table>
        <thead><tr><th>${t('security.col.backend')}</th><th>${t('security.col.status')}</th><th>${t('security.vulnscan.col.headers')}</th><th>CVEs</th></tr></thead>
        <tbody>${results.map(r => `<tr>
          <td class="mono" style="font-size:11px;max-width:280px;word-break:break-all">${esc(r.url||'')}</td>
          <td><span style="color:${vulnscanStatusColor(r.status)};font-size:12px">${esc(vulnscanStatusLabel(r.status))}</span>${r.error ? `<div style="font-size:10px;color:var(--text3);max-width:200px;overflow:hidden;text-overflow:ellipsis" title="${esc(r.error)}">${esc(r.error)}</div>` : ''}</td>
          <td style="font-size:11px;color:var(--text2)">${(r.headers||[]).length ? (r.headers||[]).map(h => `<span class="tag tag-neutral" style="font-size:10px;margin:1px">${esc(h)}</span>`).join(' ') : '—'}</td>
          <td><b style="color:${(r.cves_found||0)>0?'var(--yellow)':'var(--text)'}">${r.cves_found||0}</b></td>
        </tr>`).join('')}</tbody>
      </table></div>
    </div>` : (st.running || total ? '' : '<p style="color:var(--text2);font-size:13px;margin:12px 0 0">' + t('security.vulnscan.no_backends') + '</p>');

  return `<div>
    <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap">${statusBadge}</div>
    ${progressBlock}
    ${summary}
    ${st.last_error ? `<div style="margin-top:10px;color:var(--red);font-size:12px">${esc(st.last_error)}</div>` : ''}
    ${resultsBlock}
  </div>`;
}

function stopVulnscanPoll() {
  if (window._vulnscanPoll) {
    clearInterval(window._vulnscanPoll);
    window._vulnscanPoll = null;
  }
}

async function refreshVulnscanPanel() {
  const body = document.getElementById('vulnscan-body');
  const btn = document.getElementById('vulnscan-btn');
  if (!body) { stopVulnscanPoll(); return null; }
  try {
    let st = await api('GET', '/security/vulnscan');
    if (window._secCoreCtx) st = filterVulnscanState(st, window._secCoreCtx);
    body.innerHTML = vulnscanPanel(st);
    if (btn) btn.disabled = !!st?.running;
    return st;
  } catch (err) {
    return null;
  }
}

function startVulnscanPoll() {
  stopVulnscanPoll();
  window._vulnscanPoll = setInterval(async () => {
    const page = typeof state !== 'undefined' ? state.page : '';
    if (page !== 'security-vulns' && page !== 'core-security-vulns') {
      stopVulnscanPoll();
      return;
    }
    const st = await refreshVulnscanPanel();
    if (st && !st.running) {
      stopVulnscanPoll();
      const mode = securityModeFromPage(page);
      if (typeof renderSecurityVulns === 'function') renderSecurityVulns({ mode });
    }
  }, 2000);
}

window.saveF2BConfig = async function(e) {
  e.preventDefault();
  const whitelist = (document.getElementById('f2b-whitelist')?.value||'').split('\n').map(s=>s.trim()).filter(Boolean);
  const cfg = {
    enabled: document.getElementById('f2b-enabled')?.checked || false,
    window_sec: parseInt(document.getElementById('f2b-window')?.value)||300,
    max_errors: parseInt(document.getElementById('f2b-max')?.value)||20,
    ban_duration_sec: (() => { const v = parseInt(document.getElementById('f2b-dur')?.value, 10); return Number.isFinite(v) && v >= 0 ? v : 0; })(),
    trust_forwarded_for: document.getElementById('f2b-xff')?.checked || false,
    whitelist,
  };
  try {
    await api('PUT', '/security/fail2ban', cfg);
    toast(t('security.f2b.saved'), 'success');
    reloadCurrentSecurityPage();
  } catch(err) { toast(err.message, 'error'); }
};

window.saveCrowdSecConfig = async function(e) {
  e.preventDefault();
  const cfg = {
    enabled: document.getElementById('cs-enabled')?.checked || false,
    api_url: document.getElementById('cs-url')?.value.trim() || 'http://localhost:8080',
    api_key: document.getElementById('cs-key')?.value || '',
  };
  try {
    await api('PUT', '/security/crowdsec', cfg);
    toast(t('security.cs.saved'), 'success');
    reloadCurrentSecurityPage();
  } catch(err) { toast(err.message, 'error'); }
};

window.triggerVulnscan = async function() {
  const btn = document.getElementById('vulnscan-btn');
  if (btn) btn.disabled = true;
  try {
    await api('POST', '/security/vulnscan');
    toast(t('security.vulnscan.started'), 'success');
    await refreshVulnscanPanel();
    startVulnscanPoll();
  } catch(err) {
    if (btn) btn.disabled = false;
    toast(err.message, 'error');
  }
};

function scoreColor(s) {
  if (s >= 85) return 'var(--green)';
  if (s >= 60) return 'var(--yellow)';
  return 'var(--red)';
}

function scoreGrade(s) {
  if (s >= 95) return 'A+';
  if (s >= 85) return 'A';
  if (s >= 70) return 'B';
  if (s >= 55) return 'C';
  if (s >= 40) return 'D';
  if (s >= 25) return 'E';
  return 'F';
}

// Compat : anciennes actions Détails/Corriger → modales proxy (rapport page Sécurité)
window.showHeaderDetail = function(h) {
  if (typeof h === 'string') { try { h = JSON.parse(h); } catch {} }
  if (h?.proxy_id) openProxySecModal(h.proxy_id);
};
window.showHeaderFix = function(h) {
  if (typeof h === 'string') { try { h = JSON.parse(h); } catch {} }
  if (h?.proxy_id) openProxyModal(h.proxy_id);
};
window.applyProxyHeaderFix = async function(proxyId) {
  if (proxyId) await openProxySecModal(proxyId);
};

window.openBanModal = function() {
  modal(t('security.ban_modal.title'),
    `<div class="field"><label class="field-label">${t('security.ban_modal.ip')}</label><input id="ban-ip" class="input" placeholder="${t('security.ban_modal.ip_ph')}"></div>
     <div class="field"><label class="field-label">${t('security.ban_modal.domain')}</label><input id="ban-domain" class="input" placeholder="${t('security.ban_modal.domain_ph')}"></div>
     <div class="field"><label class="field-label">${t('security.ban_modal.reason')}</label><input id="ban-reason" class="input" placeholder="${t('security.ban_modal.reason_ph')}"></div>
     <div class="field"><label class="field-label">${t('security.ban_modal.expires')}</label><input id="ban-exp" type="datetime-local" class="input"></div>`,
    `<button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel')}</button>
     <button class="btn btn-danger" onclick="submitBan()">${t('security.ban_modal.submit')}</button>`);
};

window.submitBan = async function() {
  const ip = document.getElementById('ban-ip')?.value.trim();
  if (!ip) { toast(t('security.ban_ip_required'), 'error'); return; }
  const body = {
    ip,
    domain: document.getElementById('ban-domain')?.value.trim() || '',
    reason: document.getElementById('ban-reason')?.value.trim() || '',
    source: 'native',
  };
  const exp = document.getElementById('ban-exp')?.value;
  if (exp) body.expires_at = new Date(exp).toISOString();
  try {
    await api('POST', '/security/bans', body);
    closeModal();
    toast(t('security.ban_success'), 'success');
    reloadCurrentSecurityPage();
  } catch(e) { toast(e.message, 'error'); }
};

window.deleteBan = async function(id, ip) {
  if (!confirm(t('security.unban_confirm', { ip }))) return;
  try {
    await api('DELETE', `/security/bans/${id}`);
    toast(t('security.unban_success'), 'success');
    reloadCurrentSecurityPage();
  } catch(e) { toast(e.message, 'error'); }
};

window.makeBanPermanent = async function(id, ip) {
  if (!confirm(t('security.ban_make_permanent_confirm', { ip }))) return;
  try {
    await api('PATCH', `/security/bans/${id}`, { permanent: true });
    toast(t('security.ban_make_permanent_success'), 'success');
    reloadCurrentSecurityPage();
  } catch(e) { toast(e.message, 'error'); }
};

window.updateCVE = async function(id, status) {
  try {
    await api('PATCH', `/security/cves/${id}`, { status });
    toast(t('security.cve_updated'), 'success');
    reloadCurrentSecurityPage();
  } catch(e) { toast(e.message, 'error'); }
};
