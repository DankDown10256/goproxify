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
    sentinel: isCore ? 'core-security-sentinel' : 'security-sentinel',
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

function secActivityChartHTML(events) {
  const now = Date.now();
  const H = 24;
  const nowH = new Date().getHours();
  const buckets = Array.from({ length: H }, (_, i) => ({
    ban: 0, threat: 0, cve: 0, other: 0,
    label: String((nowH - (H - 1 - i) + 24) % 24).padStart(2, '0') + 'h',
  }));
  for (const e of events) {
    const ms = new Date(e.created_at).getTime();
    const hoursAgo = (now - ms) / 3600000;
    if (hoursAgo < 0 || hoursAgo >= H) continue;
    const idx = H - 1 - Math.floor(hoursAgo);
    const key = e.type === 'ban' ? 'ban' : e.type === 'threat' ? 'threat' : e.type === 'cve' ? 'cve' : 'other';
    buckets[idx][key]++;
  }
  const maxVal = Math.max(1, ...buckets.map(b => b.ban + b.threat + b.cve + b.other));
  const colors = { ban: 'var(--yellow)', threat: 'var(--red)', cve: 'var(--purple)', other: 'var(--text3)' };
  const layers = ['other', 'cve', 'ban', 'threat'];
  const totalEvents = buckets.reduce((s, b) => s + b.ban + b.threat + b.cve + b.other, 0);
  const showLabel = new Set([0, 6, 12, 18, 23]);

  const legend = ['ban', 'threat', 'cve'].map(k => `
    <span style="display:inline-flex;align-items:center;gap:4px;font-size:10px;color:var(--text2)">
      <span style="width:8px;height:8px;border-radius:2px;background:${colors[k]};display:inline-block"></span>
      ${k === 'ban' ? (t('security.overview_leg_ban')||'Ban') : k === 'threat' ? (t('security.overview_leg_threat')||'Menace') : 'CVE'}
    </span>`).join('');

  if (totalEvents === 0) {
    return `<div style="text-align:center;padding:20px 0;color:var(--text3);font-size:12px">${t('security.no_data')||'Aucune donnée'}</div>`;
  }

  const barDivs = buckets.map((b, i) => {
    const total = b.ban + b.threat + b.cve + b.other;
    const tip = total === 0 ? '' : [
      total + ' evt',
      b.ban ? 'Ban: ' + b.ban : '',
      b.threat ? 'Threat: ' + b.threat : '',
      b.cve ? 'CVE: ' + b.cve : '',
    ].filter(Boolean).join(' · ');
    const inner = total === 0
      ? `<div style="position:absolute;bottom:0;left:0;right:0;height:2px;background:var(--border);border-radius:1px;opacity:.4"></div>`
      : layers.map(k => {
          const h = Math.round((b[k] / maxVal) * 100);
          return h ? `<div style="width:100%;height:${h}%;background:${colors[k]}"></div>` : '';
        }).join('');
    const tipAttr = tip ? ` onmouseenter="secChartTip(event,'${tip.replace(/'/g,'&#39;')}')" onmouseleave="secChartTipHide()"` : '';
    return `<div style="flex:1;min-width:0;height:72px;position:relative;display:flex;flex-direction:column-reverse;border-radius:3px 3px 0 0;overflow:hidden;cursor:${tip?'default':'default'}"${tipAttr}>${inner}</div>`;
  }).join('');

  const labelDivs = buckets.map((b, i) =>
    `<div style="flex:1;min-width:0;font-size:9px;color:var(--text3);text-align:center;padding-top:3px;white-space:nowrap;overflow:hidden">${showLabel.has(i) ? b.label : ''}</div>`
  ).join('');

  return `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
      <div style="display:flex;gap:12px">${legend}</div>
      <span style="font-size:10px;color:var(--text3)">${totalEvents} ${t('security.overview_events')||'événements'}</span>
    </div>
    <div style="display:flex;gap:3px;align-items:flex-end;width:100%">${barDivs}</div>
    <div style="display:flex;gap:3px;width:100%">${labelDivs}</div>`;
}

window.secChartTip = function(e, text) {
  let tip = document.getElementById('_sec-chart-tip');
  if (!tip) {
    tip = document.createElement('div');
    tip.id = '_sec-chart-tip';
    tip.style.cssText = 'position:fixed;z-index:9999;background:var(--bg1,#1a1a2e);color:var(--text1,#fff);border:1px solid var(--border);border-radius:5px;padding:4px 8px;font-size:11px;pointer-events:none;white-space:nowrap;box-shadow:0 2px 8px rgba(0,0,0,.25)';
    document.body.appendChild(tip);
  }
  tip.textContent = text;
  tip.style.display = 'block';
  const r = e.currentTarget.getBoundingClientRect();
  tip.style.left = Math.min(r.left + r.width / 2 - tip.offsetWidth / 2, window.innerWidth - tip.offsetWidth - 8) + 'px';
  tip.style.top = (r.top - tip.offsetHeight - 6) + 'px';
};
window.secChartTipHide = function() {
  const tip = document.getElementById('_sec-chart-tip');
  if (tip) tip.style.display = 'none';
};

function secBansBySourceHTML(bans) {
  if (!bans.length) return `<div style="text-align:center;padding:20px 0;color:var(--text3);font-size:12px">${t('security.no_data')||'Aucune donnée'}</div>`;
  const counts = { native: 0, fail2ban: 0, crowdsec: 0, threat: 0, manual: 0 };
  for (const b of bans) counts[b.source] = (counts[b.source] || 0) + 1;
  const total = bans.length || 1;
  const labels = { native: 'Natif', fail2ban: 'Fail2Ban', crowdsec: 'CrowdSec', threat: 'Sentinel', manual: 'Manuel' };
  const colors = { native: 'var(--text3)', fail2ban: 'var(--blue)', crowdsec: 'var(--purple)', threat: 'var(--red)', manual: 'var(--yellow)' };
  return Object.entries(counts)
    .filter(([, c]) => c > 0)
    .sort(([,a],[,b]) => b - a)
    .map(([src, c]) => {
      const pct = Math.round((c / total) * 100);
      return `<div style="margin-bottom:10px">
        <div style="display:flex;justify-content:space-between;font-size:11.5px;margin-bottom:3px">
          <span style="color:var(--text1)">${labels[src]||src}</span>
          <span style="color:var(--text2)">${c} <span style="color:var(--text3)">(${pct}%)</span></span>
        </div>
        <div style="height:5px;border-radius:3px;background:var(--bg2);overflow:hidden">
          <div style="height:100%;width:${pct}%;background:${colors[src]||'var(--accent)'};border-radius:3px;transition:width .3s"></div>
        </div>
      </div>`;
    }).join('');
}

function secTopThreatsHTML(events, navBans) {
  const threats = events.filter(e => e.type === 'ban' || e.type === 'threat').slice(0, 5);
  if (!threats.length) return `<div style="text-align:center;padding:20px 0;color:var(--text3);font-size:12px">${t('security.no_data')||'Aucune donnée'}</div>`;
  const srcColor = { ban: 'var(--yellow)', threat: 'var(--red)', cve: 'var(--purple)' };
  return threats.map(e => `
    <div style="display:flex;align-items:center;gap:10px;padding:7px 16px;border-bottom:1px solid var(--border)">
      <span class="tag" style="background:${srcColor[e.type]||'var(--bg2)'};color:#fff;font-size:9px;min-width:36px;text-align:center;padding:1px 5px;border-radius:3px">${(e.type||'').toUpperCase()}</span>
      <div style="flex:1;min-width:0">
        <div style="font-size:12px;font-weight:500;color:var(--text1);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(e.summary||'')}</div>
        <div style="font-size:10px;color:var(--text3)">${fmtDate(e.created_at)}</div>
      </div>
      <span class="tag ${e.severity==='critical'?'tag-red':e.severity==='warning'?'tag-yellow':'tag-neutral'}" style="font-size:9px">${esc(e.severity||'')}</span>
    </div>`).join('');
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

    const coreQ = coreCtx?.coreRef ? `?core=${encodeURIComponent(coreCtx.coreRef)}` : '';
    const fetches = [
      api('GET', '/security/overview'),
      api('GET', '/security/timeline?limit=40&source=all'),
      api('GET', `/security/ips-provider${coreQ}`).catch(() => null),
      api('GET', `/security/threat-config${coreQ}`).catch(() => null),
      api('GET', '/security/fail2ban').catch(() => null),
      api('GET', '/security/crowdsec').catch(() => null),
      isAdmin ? api('GET', '/rules-engine/rules').catch(() => []) : Promise.resolve([]),
    ];
    if (coreCtx) {
      fetches.push(api('GET', '/security/bans?active=true').catch(() => []));
      fetches.push(api('GET', '/security/cves').catch(() => []));
    }
    const [ovData, timeline, ipsProvider, threatCfg, f2bCfg, csCfg, rulesRaw, bansRaw, cvesRaw] = await Promise.all(fetches);
    const ov = ovData?.overview || {};
    let headers = filterSecHeaders(ov.headers || [], coreCtx);
    let certs = filterSecCerts(ovData?.certs || [], coreCtx);
    const allEvents = filterSecTimeline(timeline || [], coreCtx);
    const recentEvents = allEvents.slice(0, 20);

    let activeBans = ov.active_bans || 0;
    let activeThreats = ov.active_threats || 0;
    let openCVEs = ov.open_cves || 0;
    let criticalCVEs = ov.critical_cves || 0;
    let avgScore = Math.round(ov.avg_header_score || 0);
    let certsExpired = ov.certs_expired || 0;
    let certsExpiring = ov.certs_expiring || 0;
    let filteredBans = [];

    if (coreCtx) {
      filteredBans = filterSecBans(bansRaw || [], coreCtx);
      const cves = filterSecCVEs(cvesRaw || [], coreCtx);
      activeBans = filteredBans.length;
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
    const navSentinel = securityPageId('sentinel', mode);
    const allRules = Array.isArray(rulesRaw) ? rulesRaw : (rulesRaw?.rules || []);
    const activeRules = allRules.filter(r => r.enabled).length;

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
        <div class="sec-tile" style="cursor:pointer" onclick="navigate('${navSentinel}')" title="${t('security.sentinel_title')||'Sentinel'}">
          <div class="sec-tile-label">${t('security.sentinel_tile_label')||'Sentinel'}</div>
          <div class="sec-tile-value" style="color:${threatCfg?.enabled?'var(--green)':'var(--text3)'};font-size:22px">&#x1f6e1;</div>
          <div class="sec-tile-sub">${threatCfg?.enabled ? (t('security.engine_active')||'Actif') : (t('security.engine_inactive')||'Inactif')}</div>
        </div>
        ${isAdmin ? `<div class="sec-tile" style="cursor:pointer" onclick="navigate('security-rules')" title="${t('security.rules.tab_rules')||'Règles'}">
          <div class="sec-tile-label">${t('security.rules.tab_rules')||'Règles automatiques'}</div>
          <div class="sec-tile-value" style="color:${activeRules>0?'var(--accent)':'var(--text3)'}">${activeRules}</div>
          <div class="sec-tile-sub">${allRules.length} ${t('common.total')||'total'}</div>
        </div>` : ''}
      </div>

      ${!isAdmin ? ipsProviderBanner(ipsProvider?.provider || 'native', f2bCfg, csCfg) : enginesStatusHTML(ipsProvider?.provider || 'native', threatCfg || {}, navBans, navSentinel, activeRules, allRules.length)}

      <div class="card blueprint" style="margin-bottom:20px">
        <div class="card-header">
          <span class="card-title"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px;margin-right:6px"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>${t('security.overview_activity_24h')||'Activité — 24 dernières heures'}</span>
        </div>
        <div style="padding:10px 16px 6px">
          ${secActivityChartHTML(allEvents)}
        </div>
      </div>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px">
        <div class="card blueprint">
          <div class="card-header"><span class="card-title"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px;margin-right:6px"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>${t('security.overview_bans_by_source')||'Bans actifs par source'}</span></div>
          <div style="padding:12px 16px 16px">${secBansBySourceHTML(filteredBans.length ? filteredBans : (bansRaw || []))}</div>
        </div>
        <div class="card blueprint">
          <div class="card-header">
            <span class="card-title"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px;margin-right:6px"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>${t('security.overview_top_threats')||'Menaces récentes'}</span>
            <a onclick="navigate('${navBans}')" style="font-size:11px;color:var(--accent);cursor:pointer;text-decoration:none">${t('security.view_all_bans')||'Voir tous'}</a>
          </div>
          <div style="padding:4px 0 8px">${secTopThreatsHTML(recentEvents, navBans)}</div>
        </div>
      </div>

      <details class="card blueprint" style="margin-bottom:20px">
        <summary style="padding:12px 16px;cursor:pointer;list-style:none;display:flex;align-items:center;gap:8px;font-size:13px;font-weight:600;color:var(--text1)">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="transition:transform .2s"><polyline points="9 18 15 12 9 6"/></svg>
          ${t('security.timeline')}
          <span style="margin-left:auto;font-size:11px;font-weight:400;color:var(--text3)">${recentEvents.length} ${t('security.overview_events')||'événements'}</span>
        </summary>
        <div style="padding:0 0 4px">${timelineHTML(recentEvents)}</div>
      </details>`;
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

    const coreQ = coreCtx?.coreRef ? `?core=${encodeURIComponent(coreCtx.coreRef)}` : '';
    const [bansRaw, threats, bansHistoryRaw, threatCfg] = await Promise.all([
      api('GET', '/security/bans?active=true'),
      api('GET', '/security/threats?limit=500'),
      api('GET', '/security/bans?active=false&limit=200').catch(() => []),
      api('GET', `/security/threat-config${coreQ}`).catch(() => null),
    ]);
    const bans = filterSecBans(bansRaw || [], coreCtx);
    const bansHistory = filterSecBans(bansHistoryRaw || [], coreCtx);

    window._secBans = bans;
    window._secBansHistory = bansHistory;
    window._secThreats = threats || [];
    window._secMode = mode;
    window._secCoreQ = coreQ;
    window._threatCfg = threatCfg || {};
    window._bansTab = window._bansTab || 'active';

    const bySource = { native: 0, fail2ban: 0, crowdsec: 0, threat: 0, manual: 0 };
    bans.forEach(b => { const s = b.source||'native'; bySource[s] = (bySource[s]||0)+1; });
    const expiringIn1h = bans.filter(b => b.expires_at && (new Date(b.expires_at)-Date.now()) < 3600000 && (new Date(b.expires_at)-Date.now()) > 0).length;
    const kpiSvgBan = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>`;
    const kpiSvgPie = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2a10 10 0 1 0 10 10H12V2z"/><path d="M12 2a10 10 0 0 1 10 10"/></svg>`;
    const kpiSvgCS  = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`;
    const kpiSvgClock=`<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`;

    const sourceBreakdown = Object.entries(bySource).filter(([,v])=>v>0).map(([s,v])=>`<span style="font-size:11px;color:var(--text2)">${_secSourceLabel(s)}: <b style="color:var(--text)">${v}</b></span>`).join(' · ') || '—';

    content.innerHTML = `
      ${securityCoreBanner(coreCtx)}
      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px">
        <div style="display:flex;align-items:center;gap:12px;background:var(--card-bg);border:1px solid var(--border);border-radius:8px;padding:12px 16px">
          <div style="flex-shrink:0;color:var(--red)">${kpiSvgBan}</div>
          <div>
            <div style="font-size:20px;font-weight:700;line-height:1.2">${bans.length}</div>
            <div style="font-size:12px;color:var(--text2)">${t('security.bans.kpi_active')}</div>
          </div>
        </div>
        <div style="display:flex;align-items:center;gap:12px;background:var(--card-bg);border:1px solid var(--border);border-radius:8px;padding:12px 16px">
          <div style="flex-shrink:0;color:var(--accent)">${kpiSvgPie}</div>
          <div>
            <div style="font-size:13px;font-weight:600;line-height:1.4">${sourceBreakdown}</div>
            <div style="font-size:12px;color:var(--text2)">${t('security.bans.kpi_by_source')}</div>
          </div>
        </div>
        <div style="display:flex;align-items:center;gap:12px;background:var(--card-bg);border:1px solid var(--border);border-radius:8px;padding:12px 16px">
          <div style="flex-shrink:0;color:var(--blue)">${kpiSvgCS}</div>
          <div>
            <div style="font-size:20px;font-weight:700;line-height:1.2">${(threats||[]).length}</div>
            <div style="font-size:12px;color:var(--text2)">${t('security.bans.kpi_crowdsec')}</div>
          </div>
        </div>
        <div style="display:flex;align-items:center;gap:12px;background:var(--card-bg);border:1px solid var(--border);border-radius:8px;padding:12px 16px">
          <div style="flex-shrink:0;color:${expiringIn1h>0?'var(--yellow)':'var(--text3)'}">${kpiSvgClock}</div>
          <div>
            <div style="font-size:20px;font-weight:700;line-height:1.2;color:${expiringIn1h>0?'var(--yellow)':'inherit'}">${expiringIn1h}</div>
            <div style="font-size:12px;color:var(--text2)">${t('security.bans.kpi_expiring')}</div>
          </div>
        </div>
      </div>
      <div class="card blueprint">
        <div class="card-header" style="align-items:flex-start;flex-wrap:wrap;gap:8px">
          <span class="card-title"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px;margin-right:6px"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>${t('security.bans_title')}</span>
          <div style="display:flex;gap:6px;margin-left:auto;align-items:center">
            ${['active','crowdsec','history'].map(tab=>`<button class="btn btn-sm${window._bansTab===tab?' btn-primary':' btn-ghost'}" onclick="setBansTab('${tab}')">${t('security.bans.tab_'+tab)}</button>`).join('')}
            <button class="btn btn-primary btn-sm" onclick="openBanModal()" style="margin-left:8px">${t('security.ban_add')}</button>
          </div>
        </div>
        <div id="sec-bans-tab-body">${_bansTabBody()}</div>
      </div>`;
  } catch(e) { toast(e.message,'error'); }
}

function _bansTabBody() {
  const tab = window._bansTab || 'active';
  if (tab === 'crowdsec') return `<div id="sec-threats-panel">${threatsPanelHTML()}</div>`;
  if (tab === 'history') return _bansHistoryHTML();
  return `<div id="sec-bans-panel">${bansPanelHTML()}</div>`;
}

function _bansHistoryHTML() {
  const list = window._secBansHistory || [];
  if (!list.length) return '<div class="empty"><p>' + t('security.bans.no_history') + '</p></div>';
  return `<div class="table-wrap sec-bans-table-scroll"><table>
    <thead><tr>
      <th>${t('logs.ip')}</th>
      <th>${t('security.col.domain')}</th>
      <th>${t('security.col.source')}</th>
      <th>${t('security.col.reason')}</th>
      <th>${t('security.col.expires')}</th>
      <th>${t('common.date')}</th>
    </tr></thead>
    <tbody>${list.map(b=>`<tr>
      <td class="mono">${esc(b.ip)}</td>
      <td>${esc(b.domain||'—')}</td>
      <td><span class="tag tag-neutral">${esc(_secSourceLabel(b.source))}</span></td>
      <td style="color:var(--text2);font-size:12px">${esc(b.reason||'—')}</td>
      <td style="font-size:11px">${b.expires_at ? fmtDate(b.expires_at) : t('common.permanent')}</td>
      <td style="font-size:11px;color:var(--text3)">${b.created_at ? fmtDate(b.created_at) : '—'}</td>
    </tr>`).join('')}</tbody>
  </table></div>`;
}

window.setBansTab = function(v) {
  window._bansTab = v;
  const body = document.getElementById('sec-bans-tab-body');
  if (!body) return;
  body.innerHTML = _bansTabBody();
  // update tab buttons
  document.querySelectorAll('[onclick^="setBansTab"]').forEach(btn => {
    const bv = btn.getAttribute('onclick').replace(/setBansTab\('(.+)'\)/,'$1');
    btn.className = 'btn btn-sm' + (bv === v ? ' btn-primary' : ' btn-ghost');
  });
};

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

    const [cvesRaw, vsStateRaw, vsConfigRaw] = await Promise.all([
      api('GET', '/security/cves'),
      api('GET', '/security/vulnscan').catch(() => null),
      isAdmin ? api('GET', '/security/vulnscan/config').catch(() => null) : Promise.resolve(null),
    ]);
    const cves = filterSecCVEs(cvesRaw || [], coreCtx);
    const vsState = filterVulnscanState(vsStateRaw, coreCtx);
    window._secCoreCtx = coreCtx;
    window._secMode = mode;
    window._vsConfig = vsConfigRaw || {};
    window._secCVEs = cves;
    window._vulnTab = window._vulnTab || 'list';
    window._vulnFilter = window._vulnFilter || '';

    const critical = cves.filter(c => (c.cvss_score||0) >= 9);
    const high     = cves.filter(c => (c.cvss_score||0) >= 7 && (c.cvss_score||0) < 9);
    const open     = cves.filter(c => c.status === 'open');
    const backends = new Set(cves.map(c => c.backend_url)).size;

    content.innerHTML = `
      ${securityCoreBanner(coreCtx)}

      <div class="sec-grid" style="margin-bottom:20px">
        <div class="sec-tile" style="border-left:3px solid var(--red)">
          <div class="sec-tile-label">${t('security.vulns.kpi_critical')||'Critiques (≥9)'}</div>
          <div class="sec-tile-value" style="color:${critical.length?'var(--red)':'var(--green)'}">${critical.length}</div>
          <div class="sec-tile-sub">CVSS ≥ 9.0</div>
        </div>
        <div class="sec-tile" style="border-left:3px solid var(--yellow)">
          <div class="sec-tile-label">${t('security.vulns.kpi_high')||'Élevées (7–9)'}</div>
          <div class="sec-tile-value" style="color:${high.length?'var(--yellow)':'var(--green)'}">${high.length}</div>
          <div class="sec-tile-sub">CVSS 7.0 – 8.9</div>
        </div>
        <div class="sec-tile" style="border-left:3px solid var(--accent)">
          <div class="sec-tile-label">${t('security.vulns.kpi_open')||'À corriger'}</div>
          <div class="sec-tile-value" style="color:${open.length?'var(--accent)':'var(--green)'}">${open.length}</div>
          <div class="sec-tile-sub">${t('security.vulns.kpi_open_sub')||'statut open'}</div>
        </div>
        <div class="sec-tile">
          <div class="sec-tile-label">${t('security.vulns.kpi_backends')||'Backends affectés'}</div>
          <div class="sec-tile-value" style="color:${backends?'var(--yellow)':'var(--green)'}">${backends}</div>
          <div class="sec-tile-sub">${t('security.vulns.kpi_backends_sub')||'avec au moins 1 CVE'}</div>
        </div>
      </div>

      <div class="card blueprint" style="margin-bottom:20px">
        <div class="card-header" style="flex-wrap:wrap;gap:8px">
          <span class="card-title">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px;margin-right:6px"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            ${t('security.vulns_title')}
          </span>
          <div style="display:flex;gap:4px;margin-left:auto">
            ${['list','backends'].map(v => `<button type="button" onclick="setVulnTab('${v}')" id="vulntab-${v}" style="font-size:11px;padding:3px 10px;border-radius:99px;border:1px solid ${window._vulnTab===v?'var(--accent)':'var(--border)'};background:${window._vulnTab===v?'color-mix(in srgb,var(--accent) 12%,transparent)':'transparent'};color:${window._vulnTab===v?'var(--accent)':'var(--text2)'};cursor:pointer">${v==='list'?(t('security.vulns.tab_list')||'Par CVE'):(t('security.vulns.tab_backends')||'Par backend')}</button>`).join('')}
          </div>
        </div>
        <div style="padding:8px 14px 4px;display:flex;gap:6px;flex-wrap:wrap;border-bottom:1px solid var(--border)">
          ${[['','Tous'],['open',t('security.vulns.f_open')||'Ouvertes'],['critical',t('security.vulns.f_critical')||'Critiques'],['high',t('security.vulns.f_high')||'Élevées'],['fixed',t('security.vulns.f_fixed')||'Corrigées'],['ignored',t('security.vulns.f_ignored')||'Ignorées']].map(([v,l]) => `
            <button type="button" onclick="setVulnFilter('${v}')" id="vulnf-${v||'all'}" style="font-size:11px;padding:2px 9px;border-radius:99px;border:1px solid ${window._vulnFilter===v?'var(--accent)':'var(--border)'};background:${window._vulnFilter===v?'color-mix(in srgb,var(--accent) 12%,transparent)':'transparent'};color:${window._vulnFilter===v?'var(--accent)':'var(--text2)'};cursor:pointer">${l}</button>`).join('')}
        </div>
        <div id="vulns-body">${renderVulnsBody()}</div>
      </div>

      <div class="card blueprint">
        <div class="card-header">
          <span class="card-title">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px;margin-right:6px"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            ${t('security.scanner_title')}
          </span>
          <div style="display:flex;align-items:center;gap:8px">
            ${vsState?.running ? '<span class="tag tag-yellow">' + (t('security.vulnscan.running')||'En cours') + '</span>' : (vsState?.last_scan && vsState.last_scan !== '0001-01-01T00:00:00Z' ? '<span style="font-size:11px;color:var(--text3)">' + (t('security.vulnscan.last_scan')||'Dernier scan') + ' ' + fmtDate(vsState.last_scan) + '</span>' : '')}
            ${isAdmin ? `<button id="vulnscan-btn" class="btn btn-primary btn-sm" onclick="triggerVulnscan()" ${vsState?.running?'disabled':''}>${t('security.scan_now')}</button>` : ''}
          </div>
        </div>
        <div class="card-body" id="vulnscan-body">${vulnscanPanelV2(vsState, window._vsConfig, isAdmin)}</div>
      </div>`;

    if (vsState?.running) startVulnscanPoll();
  } catch(e) { toast(e.message,'error'); }
}

function renderVulnsBody() {
  const cves = window._secCVEs || [];
  const tab = window._vulnTab || 'list';
  const filter = window._vulnFilter || '';

  const filtered = cves.filter(c => {
    if (filter === 'open') return c.status === 'open';
    if (filter === 'fixed') return c.status === 'fixed';
    if (filter === 'ignored') return c.status === 'ignored';
    if (filter === 'critical') return (c.cvss_score||0) >= 9;
    if (filter === 'high') return (c.cvss_score||0) >= 7 && (c.cvss_score||0) < 9;
    return true;
  }).sort((a, b) => (b.cvss_score||0) - (a.cvss_score||0));

  if (!filtered.length) return '<div class="empty"><p>' + (t('security.no_cves')||'Aucune CVE') + '</p></div>';

  if (tab === 'backends') return cveByBackendHTML(filtered);
  return cveListHTML(filtered);
}

function cveScoreBadge(score) {
  const s = Number(score) || 0;
  const cls = s >= 9 ? 'tag-red' : s >= 7 ? 'tag-yellow' : s >= 4 ? 'tag-neutral' : 'tag-green';
  return `<span class="tag ${cls}" style="min-width:36px;text-align:center;font-variant-numeric:tabular-nums">${s.toFixed(1)}</span>`;
}

function cveListHTML(cves) {
  return `<div class="table-wrap"><table>
    <thead><tr>
      <th>CVE</th><th>CVSS</th>
      <th>${t('security.col.backend')}</th>
      <th>${t('security.col.description')}</th>
      <th>${t('security.col.status')}</th>
      <th></th>
    </tr></thead>
    <tbody>${cves.map(c => `
      <tr id="cve-row-${c.id}" style="cursor:pointer" onclick="toggleCveDetail(${c.id})">
        <td><a href="https://nvd.nist.gov/vuln/detail/${esc(c.cve_id)}" target="_blank" style="color:var(--accent)" onclick="event.stopPropagation()">${esc(c.cve_id)}</a></td>
        <td>${cveScoreBadge(c.cvss_score)}</td>
        <td class="mono" style="font-size:11px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(c.backend_url)}">${esc(c.backend_url)}</td>
        <td style="font-size:12px;color:var(--text2);max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(c.description)}">${esc(c.description)}</td>
        <td><span class="tag ${c.status==='open'?'tag-yellow':c.status==='fixed'?'tag-green':'tag-neutral'}">${esc(c.status)}</span></td>
        <td style="white-space:nowrap">
          ${c.status!=='ignored'?`<button type="button" class="btn btn-ghost btn-icon btn-sm" onclick="event.stopPropagation();updateCVE(${c.id},'ignored')" title="${esc(t('security.cve_ignore'))}"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg></button>`:''}
          ${c.status!=='fixed'?`<button type="button" class="btn btn-ghost btn-icon btn-sm" onclick="event.stopPropagation();updateCVE(${c.id},'fixed')" title="${esc(t('security.cve_fixed'))}"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg></button>`:''}
          ${c.status!=='open'?`<button type="button" class="btn btn-ghost btn-icon btn-sm" onclick="event.stopPropagation();updateCVE(${c.id},'open')" title="${t('security.cve_reopen')||'Réouvrir'}"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-3.36"/></svg></button>`:''}
        </td>
      </tr>
      <tr id="cve-detail-${c.id}" style="display:none;background:var(--bg2)">
        <td colspan="6" style="padding:10px 16px 12px">
          <div style="font-size:12.5px;color:var(--text1);line-height:1.6;margin-bottom:8px">${esc(c.description)}</div>
          <div style="display:flex;gap:16px;flex-wrap:wrap;font-size:11px;color:var(--text3)">
            <span><b style="color:var(--text2)">${t('security.col.backend')}</b> <span class="mono">${esc(c.backend_url)}</span></span>
            ${c.published_at ? `<span><b style="color:var(--text2)">${t('security.vulns.published')||'Publié'}</b> ${fmtDate(c.published_at)}</span>` : ''}
            ${c.updated_at ? `<span><b style="color:var(--text2)">${t('security.vulns.updated')||'Mis à jour'}</b> ${fmtDate(c.updated_at)}</span>` : ''}
          </div>
        </td>
      </tr>`).join('')}
    </tbody>
  </table></div>`;
}

function cveByBackendHTML(cves) {
  const map = new Map();
  for (const c of cves) {
    if (!map.has(c.backend_url)) map.set(c.backend_url, []);
    map.get(c.backend_url).push(c);
  }
  const backends = [...map.entries()].sort((a, b) => {
    const maxA = Math.max(...a[1].map(c => c.cvss_score||0));
    const maxB = Math.max(...b[1].map(c => c.cvss_score||0));
    return maxB - maxA;
  });

  return backends.map(([url, bcves]) => {
    const maxScore = Math.max(...bcves.map(c => c.cvss_score||0));
    const openCount = bcves.filter(c => c.status === 'open').length;
    return `
      <details style="border-bottom:1px solid var(--border)">
        <summary style="padding:10px 16px;cursor:pointer;list-style:none;display:flex;align-items:center;gap:10px;user-select:none">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="flex-shrink:0;transition:transform .15s"><polyline points="9 18 15 12 9 6"/></svg>
          <span class="mono" style="font-size:12px;flex:1;color:var(--text1);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(url)}</span>
          <span style="display:flex;gap:6px;align-items:center;flex-shrink:0">
            ${cveScoreBadge(maxScore)}
            <span class="tag ${openCount?'tag-yellow':'tag-neutral'}" style="font-size:10px">${openCount} ${t('security.vulns.open_short')||'open'}</span>
            <span style="font-size:11px;color:var(--text3)">${bcves.length} CVE${bcves.length>1?'s':''}</span>
          </span>
        </summary>
        <div class="table-wrap" style="margin:0;border-radius:0">
          <table style="margin:0">
            <thead><tr><th>CVE</th><th>CVSS</th><th>${t('security.col.description')}</th><th>${t('security.col.status')}</th><th></th></tr></thead>
            <tbody>${bcves.map(c => `<tr>
              <td><a href="https://nvd.nist.gov/vuln/detail/${esc(c.cve_id)}" target="_blank" style="color:var(--accent)">${esc(c.cve_id)}</a></td>
              <td>${cveScoreBadge(c.cvss_score)}</td>
              <td style="font-size:12px;color:var(--text2);max-width:320px">${esc(c.description)}</td>
              <td><span class="tag ${c.status==='open'?'tag-yellow':c.status==='fixed'?'tag-green':'tag-neutral'}">${esc(c.status)}</span></td>
              <td style="white-space:nowrap">
                ${c.status!=='ignored'?`<button type="button" class="btn btn-ghost btn-icon btn-sm" onclick="updateCVE(${c.id},'ignored')" title="${esc(t('security.cve_ignore'))}"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg></button>`:''}
                ${c.status!=='fixed'?`<button type="button" class="btn btn-ghost btn-icon btn-sm" onclick="updateCVE(${c.id},'fixed')" title="${esc(t('security.cve_fixed'))}"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg></button>`:''}
                ${c.status!=='open'?`<button type="button" class="btn btn-ghost btn-icon btn-sm" onclick="updateCVE(${c.id},'open')" title="${t('security.cve_reopen')||'Réouvrir'}"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-3.36"/></svg></button>`:''}
              </td>
            </tr>`).join('')}
            </tbody>
          </table>
        </div>
      </details>`;
  }).join('');
}

window.toggleCveDetail = function(id) {
  const row = document.getElementById('cve-detail-' + id);
  if (row) row.style.display = row.style.display === 'none' ? '' : 'none';
};
window.setVulnTab = function(v) {
  window._vulnTab = v;
  document.getElementById('vulns-body').innerHTML = renderVulnsBody();
  ['list','backends'].forEach(k => {
    const btn = document.getElementById('vulntab-' + k);
    if (!btn) return;
    const on = k === v;
    btn.style.borderColor = on ? 'var(--accent)' : 'var(--border)';
    btn.style.background = on ? 'color-mix(in srgb,var(--accent) 12%,transparent)' : 'transparent';
    btn.style.color = on ? 'var(--accent)' : 'var(--text2)';
  });
};
window.setVulnFilter = function(v) {
  window._vulnFilter = v;
  document.getElementById('vulns-body').innerHTML = renderVulnsBody();
  [['','all'],['open','open'],['critical','critical'],['high','high'],['fixed','fixed'],['ignored','ignored']].forEach(([val, key]) => {
    const btn = document.getElementById('vulnf-' + key);
    if (!btn) return;
    const on = v === val;
    btn.style.borderColor = on ? 'var(--accent)' : 'var(--border)';
    btn.style.background = on ? 'color-mix(in srgb,var(--accent) 12%,transparent)' : 'transparent';
    btn.style.color = on ? 'var(--accent)' : 'var(--text2)';
  });
};

function vulnscanPanelV2(st, cfg, isAdmin) {
  if (!st) return '<p style="color:var(--text2);padding:12px 16px">' + t('common.not_available') + '</p>';
  const total = st.total_n || 0;
  const done = st.scanned_n || 0;
  const pct = st.progress_pct != null ? st.progress_pct : (total ? Math.round(done * 100 / total) : 0);

  const kpis = [
    { label: t('security.vulnscan.backends')||'Scannés', val: `${done}${total?' / '+total:''}`, color: 'var(--text1)' },
    { label: t('security.vulnscan.reachable')||'Joignables', val: st.reachable_n||0, color: 'var(--green)' },
    { label: t('security.vulnscan.unreachable')||'Inaccessibles', val: st.unreachable_n||0, color: (st.unreachable_n||0)>0?'var(--red)':'var(--text1)' },
    { label: t('security.vulnscan.no_headers')||'Sans en-têtes', val: st.no_headers_n||0, color: (st.no_headers_n||0)>0?'var(--yellow)':'var(--text1)' },
    { label: t('security.vulnscan.nvd_queries')||'Requêtes NVD', val: st.nvd_queries||0, color: 'var(--text1)' },
    { label: t('security.vulnscan.cves_found')||'CVEs trouvées', val: st.found_cves||0, color: (st.found_cves||0)>0?'var(--yellow)':'var(--green)' },
  ];

  const progressBlock = st.running ? `
    <div style="margin:0 0 14px">
      <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:5px">
        <span style="color:var(--text2)">${t('security.vulnscan.progress', { done, total })||done+' / '+total}</span>
        <b>${pct}%</b>
      </div>
      <div style="height:6px;background:var(--border);border-radius:3px;overflow:hidden">
        <div style="height:100%;width:${pct}%;background:var(--accent);transition:width .4s;border-radius:3px"></div>
      </div>
      ${st.current_url ? `<div style="margin-top:6px;font-family:var(--font-mono,monospace);font-size:11px;color:var(--text3);word-break:break-all">${esc(st.current_url)}</div>` : ''}
    </div>` : '';

  const results = Array.isArray(st.results) ? st.results : [];
  const resultsBlock = results.length ? `
    <details style="margin-top:12px">
      <summary style="cursor:pointer;font-size:12px;color:var(--text2);user-select:none;list-style:none;display:flex;align-items:center;gap:6px">
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"/></svg>
        ${t('security.vulnscan.detail_title')||'Détail par backend'} (${results.length})
      </summary>
      <div class="table-wrap" style="margin-top:8px">
        <table>
          <thead><tr><th>${t('security.col.backend')}</th><th>${t('security.col.status')}</th><th>${t('security.vulnscan.col.headers')||'En-têtes'}</th><th>CVEs</th></tr></thead>
          <tbody>${results.map(r => `<tr>
            <td class="mono" style="font-size:11px;max-width:260px;word-break:break-all">${esc(r.url||'')}</td>
            <td><span style="color:${vulnscanStatusColor(r.status)};font-size:12px">${esc(vulnscanStatusLabel(r.status))}</span>${r.error?`<div style="font-size:10px;color:var(--text3);max-width:180px;overflow:hidden;text-overflow:ellipsis" title="${esc(r.error)}">${esc(r.error)}</div>`:''}</td>
            <td style="font-size:11px;color:var(--text2)">${(r.headers||[]).length?(r.headers||[]).map(h=>`<span class="tag tag-neutral" style="font-size:10px;margin:1px">${esc(h)}</span>`).join(' '):'—'}</td>
            <td><b style="color:${(r.cves_found||0)>0?'var(--yellow)':'var(--text)'}">${r.cves_found||0}</b></td>
          </tr>`).join('')}
          </tbody>
        </table>
      </div>
    </details>` : (!st.running && !total ? '<p style="color:var(--text2);font-size:13px;margin:4px 0 0">' + (t('security.vulnscan.no_backends')||'Aucun backend scanné') + '</p>' : '');

  const allowPrivate = !!(cfg && cfg.allow_private);
  const configBlock = isAdmin ? `
    <div style="margin-top:14px;padding:10px 12px;background:var(--surface2,var(--surface));border-radius:6px;border:1px solid var(--border)">
      <label style="display:flex;align-items:center;gap:10px;cursor:pointer;font-size:12.5px">
        <input type="checkbox" id="vulnscan-allow-private" ${allowPrivate?'checked':''} onchange="saveVulnscanConfig()" style="width:14px;height:14px;cursor:pointer">
        <span>
          <b>${t('security.vulnscan.allow_private')}</b>
          <span style="display:block;font-size:11px;color:var(--text2);margin-top:1px">${t('security.vulnscan.allow_private_help')}</span>
        </span>
      </label>
    </div>` : '';

  return `<div style="padding:4px 0 2px">
    ${progressBlock}
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(110px,1fr));gap:8px 12px;padding:4px 0 10px">
      ${kpis.map(k => `<div style="font-size:12px">
        <div style="font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--text3);margin-bottom:2px">${k.label}</div>
        <b style="color:${k.color}">${k.val}</b>
      </div>`).join('')}
    </div>
    ${st.last_error ? `<div style="margin-bottom:10px;color:var(--red);font-size:12px">${esc(st.last_error)}</div>` : ''}
    ${resultsBlock}
    ${configBlock}
  </div>`;
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
pages['security-ips-engines'] = () => renderSecurityIpsEngines();
pages['security-rules'] = () => renderSecurityRules();

pages['core-security'] = () => renderSecurityOverview({ mode: 'core' });
pages['core-security-bans'] = () => renderSecurityBans({ mode: 'core' });
pages['core-security-vulns'] = () => renderSecurityVulns({ mode: 'core' });
pages['core-security-posture'] = () => renderSecurityPosture({ mode: 'core' });
pages['security-sentinel'] = () => renderSentinelDashboard({ mode: 'admin' });
pages['core-security-sentinel'] = () => renderSentinelDashboard({ mode: 'core' });

async function renderSecurityIpsEngines() {
  const content = document.getElementById('content');
  content.innerHTML = '<p style="color:var(--text2)">' + t('common.loading') + '</p>';
  const ta = document.getElementById('topbar-actions');
  if (ta) ta.innerHTML = '';

  try {
    const [ipsProvider, f2bCfg, csCfg] = await Promise.all([
      api('GET', '/security/ips-provider').catch(() => null),
      api('GET', '/security/fail2ban').catch(() => null),
      api('GET', '/security/crowdsec').catch(() => null),
    ]);

    window._ipsProvider = ipsProvider?.provider || 'native';
    window._f2bCfg = f2bCfg || {};
    window._csCfg = csCfg || {};

    const f2bActive = window._ipsProvider === 'fail2ban';
    const csActive  = window._ipsProvider === 'crowdsec';

    const svgWrench = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z"/></svg>`;
    const svgShield = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`;
    const svgNative = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>`;

    const statusDot = (active) => `<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${active?'var(--green)':'var(--text3)'};margin-right:6px"></span>`;

    content.innerHTML = `
      <div style="max-width:760px">
        <div class="card blueprint" style="margin-bottom:16px">
          <div class="card-header">
            <span class="card-title">${t('security.ips_engines.selector_title')}</span>
          </div>
          <div style="padding:0 16px 16px">
            ${ipsProviderBanner(window._ipsProvider, window._f2bCfg, window._csCfg)}
          </div>
        </div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px">
          <div class="card blueprint">
            <div class="card-header">
              <span class="card-title">${svgWrench} Fail2Ban ${statusDot(f2bActive)}<span style="font-size:11px;font-weight:400;color:${f2bActive?'var(--green)':'var(--text3)'}">${f2bActive ? t('security.engine_active') : t('security.engine_inactive')}</span></span>
            </div>
            <div style="padding:0 16px 16px">
              <p style="font-size:12px;color:var(--text2);margin:0 0 12px">${t('security.ips_engines.f2b_desc')}</p>
              ${f2bPanel(window._f2bCfg)}
            </div>
          </div>
          <div class="card blueprint">
            <div class="card-header">
              <span class="card-title">${svgShield} CrowdSec ${statusDot(csActive)}<span style="font-size:11px;font-weight:400;color:${csActive?'var(--green)':'var(--text3)'}">${csActive ? t('security.engine_active') : t('security.engine_inactive')}</span></span>
            </div>
            <div style="padding:0 16px 16px">
              <p style="font-size:12px;color:var(--text2);margin:0 0 12px">${t('security.ips_engines.cs_desc')}</p>
              ${crowdSecPanel(window._csCfg)}
            </div>
          </div>
        </div>
      </div>`;
  } catch(e) { toast(e.message,'error'); }
}

async function renderSentinelDashboard({ mode }) {
  const content = document.getElementById('content');
  content.innerHTML = `<div style="padding:20px 0"><div class="spinner"></div></div>`;
  try {
    const coreCtx = await resolveSecurityCoreCtx(mode);
    if (mode === 'core' && coreCtx?.missing) {
      content.innerHTML = '<p style="color:var(--text2)">' + t('trafic.no_core') + '</p>';
      return;
    }
    const coreQ = coreCtx?.coreRef ? `?core=${encodeURIComponent(coreCtx.coreRef)}` : '';

    const [bansRaw, threatsRaw, cfg] = await Promise.all([
      api('GET', `/security/bans?active=true&source=threat${coreQ ? '&' + coreQ.slice(1) : ''}`).catch(() => []),
      api('GET', `/security/threats?limit=500${coreQ ? '&' + coreQ.slice(1) : ''}`).catch(() => []),
      api('GET', `/security/threat-config${coreQ}`).catch(() => null),
    ]);

    const sentinelBans = filterSecBans(bansRaw || [], coreCtx);
    const threats = threatsRaw || [];
    const threatCfg = cfg || {};

    // IPs bannies vs IPs détectées non encore bannies
    const bannedIPs = new Set(sentinelBans.map(b => b.ip));
    const detectedIPs = new Set(threats.map(t => t.ip));
    const pendingCount = [...detectedIPs].filter(ip => !bannedIPs.has(ip)).length;

    // Taux de conversion détection → ban
    const conversionRate = detectedIPs.size > 0
      ? Math.round((bannedIPs.size / detectedIPs.size) * 100)
      : 0;

    // Analyse des scénarios : déclenchements, IPs uniques, dernière occurrence
    const scenariosMap = {};
    for (const th of threats) {
      const s = th.scenario || th.type || 'unknown';
      if (!scenariosMap[s]) scenariosMap[s] = { count: 0, ips: new Set(), last: null };
      scenariosMap[s].count++;
      scenariosMap[s].ips.add(th.ip);
      const d = new Date(th.created_at);
      if (!isNaN(d) && (!scenariosMap[s].last || d > scenariosMap[s].last)) scenariosMap[s].last = d;
    }
    const scenarios = Object.entries(scenariosMap)
      .map(([name, d]) => ({ name, count: d.count, ips: d.ips.size, last: d.last }))
      .sort((a, b) => b.count - a.count);

    // Top IPs par nombre de menaces (pas de bans — c'est la vue Sentinel)
    const ipThreatMap = {};
    for (const th of threats) ipThreatMap[th.ip] = (ipThreatMap[th.ip] || 0) + 1;
    const topIPs = Object.entries(ipThreatMap).sort((a, b) => b[1] - a[1]).slice(0, 12);

    // Décisions récentes : 20 dernières menaces triées par date
    const recentDecisions = [...threats]
      .filter(d => d.created_at)
      .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
      .slice(0, 20);

    // Listes de détection
    const lists = threatCfg.lists || {};
    const custom = threatCfg.custom_lists || {};
    const whitelist = threatCfg.whitelist || {};
    const listItems = [
      { label: 'IPs malveillantes', enabled: lists.ip_enabled, custom: (custom.ips || []).length, wl: (whitelist.ips || []).length },
      { label: 'User-Agents',       enabled: lists.ua_enabled, custom: (custom.uas || []).length, wl: (whitelist.uas || []).length },
      { label: 'Paths',             enabled: lists.path_enabled, custom: (custom.paths || []).length, wl: (whitelist.paths || []).length },
    ];

    const cfgEnabled = !!threatCfg.enabled;
    const cfgMode = threatCfg.mode || 'block';
    const noData = `<p style="color:var(--text2);font-size:13px;padding-top:8px">${t('security.no_data') || 'Aucune donnée'}</p>`;
    const svgGear = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>`;

    content.innerHTML = `
      ${securityCoreBanner(coreCtx)}
      <div class="page-header" style="display:flex;align-items:center;gap:10px;margin-bottom:20px">
        <h1 class="page-title" style="margin:0">&#x26a1; Sentinel</h1>
        <span class="tag ${cfgEnabled ? 'tag-green' : 'tag-neutral'}">${cfgEnabled ? t('common.active') || 'Actif' : t('common.inactive') || 'Inactif'}</span>
        <span class="tag ${cfgMode === 'block' ? 'tag-red' : 'tag-yellow'}">${cfgMode === 'block' ? 'Block' : 'Detect'}</span>
        <button class="btn btn-ghost btn-sm" style="margin-left:auto;display:flex;align-items:center;gap:6px" onclick="openSentinelSettings()">${svgGear} ${t('common.settings') || 'Paramètres'}</button>
      </div>

      <!-- Tuiles moteur -->
      <div class="sec-grid" style="grid-template-columns:repeat(4,1fr);margin-bottom:16px">
        <div class="sec-tile">
          <div class="sec-tile-label">Score seuil</div>
          <div class="sec-tile-value">${threatCfg.score_threshold || 0}</div>
          <div style="font-size:11px;color:var(--text3);margin-top:2px">${threatCfg.score_threshold === 0 ? 'premier signal' : 'cumulatif'}</div>
        </div>
        <div class="sec-tile">
          <div class="sec-tile-label">Rate limit</div>
          <div class="sec-tile-value" style="color:${threatCfg.rate_limit > 0 ? 'var(--primary)' : 'var(--text3)'}">${threatCfg.rate_limit > 0 ? threatCfg.rate_limit + ' req/s' : '—'}</div>
        </div>
        <div class="sec-tile">
          <div class="sec-tile-label">Durée ban</div>
          <div class="sec-tile-value">${threatCfg.ban_duration || '24h'}</div>
        </div>
        <div class="sec-tile">
          <div class="sec-tile-label">Seuil erreurs 4xx</div>
          <div class="sec-tile-value">${threatCfg.error_threshold || 20}</div>
          <div style="font-size:11px;color:var(--text3);margin-top:2px">sur ${threatCfg.error_window || '10s'}</div>
        </div>
      </div>

      <!-- Tuiles activité -->
      <div class="sec-grid" style="grid-template-columns:repeat(4,1fr);margin-bottom:20px">
        <div class="sec-tile">
          <div class="sec-tile-label">Bans Sentinel actifs</div>
          <div class="sec-tile-value" style="color:${sentinelBans.length > 0 ? 'var(--red)' : 'var(--green)'}">${sentinelBans.length}</div>
        </div>
        <div class="sec-tile">
          <div class="sec-tile-label">Menaces enregistrées</div>
          <div class="sec-tile-value" style="color:${threats.length > 0 ? 'var(--yellow)' : 'var(--green)'}">${threats.length}</div>
          <div style="font-size:11px;color:var(--text3);margin-top:2px">${detectedIPs.size} IP${detectedIPs.size > 1 ? 's' : ''} uniques</div>
        </div>
        <div class="sec-tile">
          <div class="sec-tile-label">IPs détectées, non bannies</div>
          <div class="sec-tile-value" style="color:${pendingCount > 0 ? 'var(--yellow)' : 'var(--green)'}">${pendingCount}</div>
          <div style="font-size:11px;color:var(--text3);margin-top:2px">${cfgMode === 'detect' ? 'mode detect' : 'en approche du seuil'}</div>
        </div>
        <div class="sec-tile">
          <div class="sec-tile-label">Taux blocage</div>
          <div class="sec-tile-value" style="color:${conversionRate > 0 ? 'var(--primary)' : 'var(--text3)'}">${detectedIPs.size > 0 ? conversionRate + '%' : '—'}</div>
          <div style="font-size:11px;color:var(--text3);margin-top:2px">détect. → ban</div>
        </div>
      </div>

      <!-- Scénarios déclenchés -->
      <div class="card blueprint" style="margin-bottom:20px">
        <div class="card-header"><span class="card-title">&#x1f4cb; Scénarios déclenchés</span></div>
        <div style="padding:0 16px 16px">
          ${scenarios.length === 0 ? noData :
            `<table style="width:100%;border-collapse:collapse;font-size:13px">
              <thead><tr>
                <th style="text-align:left;padding:8px 6px;border-bottom:1px solid var(--border)">Scénario</th>
                <th style="text-align:right;padding:8px 6px;border-bottom:1px solid var(--border)">Décl.</th>
                <th style="text-align:right;padding:8px 6px;border-bottom:1px solid var(--border)">IPs uniques</th>
                <th style="text-align:right;padding:8px 6px;border-bottom:1px solid var(--border)">Dernière occurrence</th>
              </tr></thead>
              <tbody>${scenarios.map(s => `
                <tr style="border-bottom:1px solid var(--border)">
                  <td style="padding:6px;font-family:monospace;font-size:12px;color:var(--text1)">${esc(s.name)}</td>
                  <td style="text-align:right;padding:6px"><span class="tag tag-red">${s.count}</span></td>
                  <td style="text-align:right;padding:6px"><span class="tag tag-yellow">${s.ips}</span></td>
                  <td style="text-align:right;padding:6px;font-size:11px;color:var(--text3)">${s.last ? fmtDate(s.last.toISOString()) : '—'}</td>
                </tr>`).join('')}
              </tbody>
            </table>`}
        </div>
      </div>

      <!-- Décisions récentes + Top IPs -->
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px">
        <div class="card blueprint">
          <div class="card-header"><span class="card-title">&#x23f1; Décisions récentes</span></div>
          <div style="padding:0 16px 16px">
            ${recentDecisions.length === 0 ? noData :
              `<div style="display:flex;flex-direction:column;gap:5px;margin-top:8px">
                ${recentDecisions.map(d => {
                  const isBanned = bannedIPs.has(d.ip);
                  return `<div style="display:flex;align-items:center;gap:8px;font-size:12px;padding:5px 8px;border-radius:6px;background:var(--bg2)">
                    <span class="tag ${isBanned ? 'tag-red' : 'tag-yellow'}" style="min-width:52px;text-align:center;font-size:10px">${isBanned ? 'BAN' : 'DETECT'}</span>
                    <span style="font-family:monospace;color:var(--text1);flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(d.ip)}">${esc(d.ip)}</span>
                    <span style="color:var(--text3);font-size:11px;white-space:nowrap;min-width:0">${fmtDate(d.created_at)}</span>
                  </div>`;
                }).join('')}
              </div>`}
          </div>
        </div>
        <div class="card blueprint">
          <div class="card-header"><span class="card-title">&#x1f4ca; Top IPs par menaces</span></div>
          <div style="padding:0 16px 16px">
            ${topIPs.length === 0 ? noData :
              `<table style="width:100%;border-collapse:collapse;font-size:13px">
                <thead><tr>
                  <th style="text-align:left;padding:8px 6px;border-bottom:1px solid var(--border)">IP</th>
                  <th style="text-align:right;padding:8px 6px;border-bottom:1px solid var(--border)">Menaces</th>
                  <th style="text-align:right;padding:8px 6px;border-bottom:1px solid var(--border)">Statut</th>
                </tr></thead>
                <tbody>${topIPs.map(([ip, n]) => `
                  <tr style="border-bottom:1px solid var(--border)">
                    <td style="padding:6px;font-family:monospace;font-size:12px">${esc(ip)}</td>
                    <td style="text-align:right;padding:6px"><span class="tag tag-yellow">${n}</span></td>
                    <td style="text-align:right;padding:6px">${bannedIPs.has(ip) ? '<span class="tag tag-red">Banni</span>' : '<span class="tag tag-neutral">Libre</span>'}</td>
                  </tr>`).join('')}
                </tbody>
              </table>`}
          </div>
        </div>
      </div>

      <!-- Listes de détection -->
      <div class="card blueprint" style="margin-bottom:20px">
        <div class="card-header"><span class="card-title">&#x1f4cb; Listes de détection</span></div>
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;padding:12px 16px 16px">
          ${listItems.map(li => `
            <div style="padding:10px 12px;border-radius:8px;background:var(--bg2);border:1px solid ${li.enabled ? 'var(--green)' : 'var(--border)'}">
              <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
                <span style="width:8px;height:8px;min-width:8px;border-radius:50%;background:${li.enabled ? 'var(--green)' : 'var(--text3)'}"></span>
                <span style="font-size:12.5px;font-weight:600;color:${li.enabled ? 'var(--text1)' : 'var(--text2)'}">${li.label}</span>
              </div>
              <div style="font-size:11px;color:var(--text3);display:flex;flex-direction:column;gap:3px">
                <span>${li.enabled ? 'Liste active' : 'Désactivée'}</span>
                ${li.custom > 0 ? `<span>${li.custom} entrée${li.custom > 1 ? 's' : ''} inline</span>` : ''}
                ${li.wl > 0 ? `<span>${li.wl} en whitelist</span>` : ''}
              </div>
            </div>`).join('')}
        </div>
      </div>

      <!-- Lien vers les bans -->
      <div style="text-align:right;margin-bottom:20px">
        <button class="btn btn-ghost btn-sm" onclick="navigate('${securityPageId('bans', mode)}')">${t('security.view_all_bans') || 'Voir tous les bans'} &rarr;</button>
      </div>

      <!-- Modal paramètres Sentinel -->
      <div id="sentinel-settings-overlay" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:1000;overflow-y:auto" onclick="if(event.target===this)closeSentinelSettings()">
        <div style="background:var(--bg);border-radius:10px;max-width:720px;margin:40px auto;padding:0;box-shadow:0 8px 32px rgba(0,0,0,.25)">
          <div style="display:flex;align-items:center;justify-content:space-between;padding:16px 20px;border-bottom:1px solid var(--border)">
            <h3 style="margin:0;font-size:15px">&#x26a1; ${t('security.threat.title') || 'Sentinel'} — ${t('common.settings') || 'Paramètres'}</h3>
            <button class="btn btn-ghost btn-sm" onclick="closeSentinelSettings()" style="padding:4px 8px;font-size:16px;line-height:1">&#x2715;</button>
          </div>
          <div style="padding:16px 20px" id="sentinel-settings-body">
            ${threatEngineBanner(threatCfg)}
          </div>
        </div>
      </div>`;

  } catch(e) { toast(e.message, 'error'); }
}

function secProxyCountLabel(n, total) {
  const suffix = n === 1 ? t('security.proxy_count', { n }) : t('security.proxy_count_n', { n });
  return total != null && n !== total ? `${suffix} / ${total}` : suffix;
}

function enginesStatusHTML(provider, threatCfg, navBans, navSentinel, activeRules, totalRules) {
  const sentinelOn = !!threatCfg.enabled;
  const engines = [
    {
      key: 'fail2ban',
      label: t('security.fail2ban_native'),
      active: provider === 'fail2ban',
      nav: navBans,
    },
    {
      key: 'crowdsec',
      label: t('security.crowdsec'),
      active: provider === 'crowdsec',
      nav: navBans,
    },
    {
      key: 'sentinel',
      label: t('security.sentinel_tile_label') || 'Sentinel',
      active: sentinelOn,
      nav: navSentinel,
    },
    {
      key: 'rules',
      label: t('security.rules.tab_rules') || 'Règles automatiques',
      active: (activeRules || 0) > 0,
      sub: `${activeRules || 0} / ${totalRules || 0}`,
      nav: 'security-rules',
    },
  ];
  return `<div class="card blueprint" style="margin-bottom:20px">
    <div class="card-header"><span class="card-title">${t('security.engines_status') || 'Moteurs de sécurité'}</span></div>
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;padding:12px">
      ${engines.map(e => `
        <div onclick="navigate('${e.nav}')" style="cursor:pointer;display:flex;align-items:flex-start;gap:10px;padding:10px 12px;border-radius:8px;background:var(--bg2);border:1px solid ${e.active ? 'var(--green)' : 'var(--border)'};transition:border-color .15s">
          <span style="margin-top:2px;width:8px;height:8px;min-width:8px;border-radius:50%;background:${e.active ? 'var(--green)' : 'var(--text3)'}"></span>
          <div style="min-width:0">
            <div style="font-size:12.5px;font-weight:600;color:${e.active ? 'var(--text1)' : 'var(--text2)'}">${esc(e.label)}</div>
            <div style="font-size:11px;color:var(--text3);margin-top:2px">${e.sub !== undefined ? e.sub : (e.active ? (t('security.engine_active') || 'Actif') : (t('security.engine_inactive') || 'Inactif'))}</div>
          </div>
        </div>`).join('')}
    </div>
  </div>`;
}

function ipsProviderBanner(provider, f2bCfg, csCfg) {
  const svgWrench = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z"/></svg>`;
  const svgShield = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`;
  const svgOff = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>`;

  const options = [
    { value: 'native',   icon: svgOff,    label: t('security.ips.native'),      desc: t('security.ips.native_desc') },
    { value: 'fail2ban', icon: svgWrench, label: t('security.fail2ban_native'), desc: t('security.ips.f2b_desc') },
    { value: 'crowdsec', icon: svgShield, label: t('security.crowdsec'),         desc: t('security.ips.cs_desc') },
  ];

  const configPanel = provider === 'fail2ban' ? `
    <div class="ips-config-panel">
      <div class="ips-config-panel-head">
        <span class="ips-config-panel-name">${svgWrench}${t('security.fail2ban_native')}</span>
      </div>
      ${f2bPanel(f2bCfg)}
    </div>` : provider === 'crowdsec' ? `
    <div class="ips-config-panel">
      <div class="ips-config-panel-head">
        <span class="ips-config-panel-name">${svgShield}${t('security.crowdsec')}</span>
      </div>
      ${crowdSecPanel(csCfg)}
    </div>` : `
    <div class="ips-config-panel">
      <button class="btn btn-primary btn-sm" onclick="selectIPSProvider('native')">${t('common.save')}</button>
    </div>`;

  return `<div class="sec-bans-config">
    <div class="sec-bans-config-head">
      <div>
        <div class="sec-bans-config-title">${t('security.bans_config_title')}</div>
        <div class="sec-bans-config-sub">${t('security.ips.selector_sub')}</div>
      </div>
    </div>
    <div class="ips-selector">
      ${options.map(o => `<button class="ips-option${provider===o.value?' is-active':''}" onclick="ipsSelectLocal('${o.value}')">
        <div class="ips-option-top">
          <div class="ips-option-radio"></div>
          <span class="ips-option-name">${o.icon} ${o.label}</span>
        </div>
        <div class="ips-option-desc">${o.desc}</div>
      </button>`).join('')}
    </div>
    <div id="ips-provider-panel">${configPanel}</div>
  </div>`;
}

function threatEngineBanner(cfg) {
  const enabled = !!cfg.enabled;
  const mode = cfg.mode || 'block';
  const svgBolt = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>`;

  const wl = cfg.whitelist || {};
  const lists = cfg.lists || {};
  const custom = cfg.custom_lists || {};

  return `<div class="sec-bans-config" style="margin-top:12px">
    <div class="sec-bans-config-head">
      <div>
        <div class="sec-bans-config-title">${svgBolt} ${t('security.threat.title')}</div>
        <div class="sec-bans-config-sub">${t('security.threat.sub')}</div>
      </div>
      <label class="toggle" style="margin-left:auto">
        <input type="checkbox" id="threat-enabled" ${enabled ? 'checked' : ''} onchange="saveThreatConfig()">
        <span class="toggle-slider"></span>
      </label>
    </div>
    <div id="threat-engine-body" style="${enabled ? '' : 'display:none'}">
      <form onsubmit="saveThreatConfig(event)" style="margin-top:12px">

        <div style="display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap;margin-bottom:12px">
          <div class="field" style="margin:0;min-width:140px">
            <label class="field-label">Mode</label>
            <select id="threat-mode" class="input" style="height:32px">
              <option value="block" ${mode==='block'?'selected':''}>Block — bannir</option>
              <option value="detect" ${mode==='detect'?'selected':''}>Detect — journaliser</option>
            </select>
          </div>
          <div class="field" style="margin:0;min-width:140px">
            <label class="field-label">Score seuil <span style="font-weight:400;color:var(--text3)">(0 = premier signal)</span></label>
            <input id="threat-score" type="number" class="input" value="${cfg.score_threshold||0}" min="0" placeholder="0">
          </div>
        </div>

        <div class="sec-bans-engine-fields" style="grid-template-columns:repeat(3,1fr)">
          <div class="field" style="margin:0">
            <label class="field-label">${t('security.threat.rate_limit')} <span style="font-weight:400;color:var(--text3)">(req/s par IP, 0 = désactivé)</span></label>
            <input id="threat-rate" type="number" class="input" value="${cfg.rate_limit||0}" min="0" step="0.5" placeholder="0 = désactivé">
          </div>
          <div class="field" style="margin:0">
            <label class="field-label">Fenêtre rate <span style="font-weight:400;color:var(--text3)">(ex: 1s)</span></label>
            <input id="threat-rate-window" class="input" value="${cfg.rate_window||'1s'}" placeholder="1s">
          </div>
          <div class="field" style="margin:0">
            <label class="field-label">Ban auto rate — seuil <span style="font-weight:400;color:var(--text3)">(déclenchements avant ban, 1 = immédiat)</span></label>
            <input id="threat-rate-ban-threshold" type="number" class="input" value="${cfg.rate_ban_threshold||1}" min="1" placeholder="1">
          </div>
          <div class="field" style="margin:0">
            <label class="field-label">Ban auto rate — fenêtre <span style="font-weight:400;color:var(--text3)">(ex: 10s)</span></label>
            <input id="threat-rate-ban-window" class="input" value="${cfg.rate_ban_window||''}" placeholder="= fenêtre rate">
          </div>
          <div class="field" style="margin:0">
            <label class="field-label">${t('security.threat.error_threshold')}</label>
            <input id="threat-errs" type="number" class="input" value="${cfg.error_threshold||20}" min="1">
          </div>
          <div class="field" style="margin:0">
            <label class="field-label">${t('security.threat.error_window')}</label>
            <input id="threat-ewin" class="input" value="${cfg.error_window||'10s'}" placeholder="10s">
          </div>
          <div class="field" style="margin:0">
            <label class="field-label">${t('security.threat.ban_duration')}</label>
            <input id="threat-dur" class="input" value="${cfg.ban_duration||'24h'}" placeholder="24h">
          </div>
          <div class="field" style="margin:0">
            <label class="field-label">${t('security.threat.refresh')}</label>
            <input id="threat-refresh" class="input" value="${lists.refresh_interval||'6h'}" placeholder="6h">
          </div>
        </div>

        <div style="margin-top:14px">
          <div style="font-size:12px;font-weight:600;color:var(--text2);margin-bottom:6px">Limite globale (anti-DDoS volumétrique)</div>
          <div class="sec-bans-engine-fields" style="grid-template-columns:repeat(3,1fr)">
            <div class="field" style="margin:0">
              <label class="field-label">Global req/s max <span style="font-weight:400;color:var(--text3)">(toutes IPs, 0 = désactivé)</span></label>
              <input id="threat-global-rps" type="number" class="input" value="${cfg.global_rps||0}" min="0" step="10" placeholder="0 = désactivé">
            </div>
            <div class="field" style="margin:0">
              <label class="field-label">Global burst <span style="font-weight:400;color:var(--text3)">(0 = 2×global req/s)</span></label>
              <input id="threat-global-burst" type="number" class="input" value="${cfg.global_burst||0}" min="0" step="10" placeholder="0 = 2×RPS">
            </div>
          </div>
        </div>

        <div style="margin-top:12px;display:flex;gap:16px;flex-wrap:wrap">
          <label style="display:flex;align-items:center;gap:6px;font-size:12.5px">
            <input type="checkbox" id="threat-ua" ${lists.ua_enabled?'checked':''}>
            ${t('security.threat.list_ua')}
          </label>
          <label style="display:flex;align-items:center;gap:6px;font-size:12.5px">
            <input type="checkbox" id="threat-path" ${lists.path_enabled?'checked':''}>
            ${t('security.threat.list_path')}
          </label>
          <label style="display:flex;align-items:center;gap:6px;font-size:12.5px">
            <input type="checkbox" id="threat-ip" ${lists.ip_enabled?'checked':''}>
            ${t('security.threat.list_ip')}
          </label>
        </div>

        <div style="margin-top:14px">
          <div style="font-size:12px;font-weight:600;color:var(--text2);margin-bottom:6px">Listes personnalisées (inline)</div>
          <div class="sec-bans-engine-fields" style="grid-template-columns:repeat(3,1fr)">
            <div class="field" style="margin:0">
              <label class="field-label">IPs / CIDRs bloqués</label>
              <textarea id="threat-custom-ips" class="input" rows="3" placeholder="192.168.1.0/24&#10;1.2.3.4">${(custom.ips||[]).join('\n')}</textarea>
            </div>
            <div class="field" style="margin:0">
              <label class="field-label">User-Agents bloqués</label>
              <textarea id="threat-custom-uas" class="input" rows="3" placeholder="badbot&#10;scrapy">${(custom.uas||[]).join('\n')}</textarea>
            </div>
            <div class="field" style="margin:0">
              <label class="field-label">Paths bloqués (préfixes)</label>
              <textarea id="threat-custom-paths" class="input" rows="3" placeholder="/admin/secret&#10;/phpmyadmin">${(custom.paths||[]).join('\n')}</textarea>
            </div>
          </div>
        </div>

        <div style="margin-top:14px">
          <div style="font-size:12px;font-weight:600;color:var(--text2);margin-bottom:6px">${t('security.threat.whitelist')}</div>
          <div class="sec-bans-engine-fields" style="grid-template-columns:repeat(3,1fr)">
            <div class="field" style="margin:0">
              <label class="field-label">${t('security.threat.wl_ips')}</label>
              <textarea id="threat-wl-ips" class="input" rows="2" placeholder="10.0.0.0/8&#10;203.0.113.1">${(wl.ips||[]).join('\n')}</textarea>
            </div>
            <div class="field" style="margin:0">
              <label class="field-label">${t('security.threat.wl_uas')}</label>
              <textarea id="threat-wl-uas" class="input" rows="2" placeholder="mon-crawler&#10;pingdom">${(wl.uas||[]).join('\n')}</textarea>
            </div>
            <div class="field" style="margin:0">
              <label class="field-label">${t('security.threat.wl_paths')}</label>
              <textarea id="threat-wl-paths" class="input" rows="2" placeholder="/healthz&#10;/.well-known/">${(wl.paths||[]).join('\n')}</textarea>
            </div>
          </div>
        </div>

        <button class="btn btn-primary btn-sm" type="submit" style="margin-top:10px">${t('common.save')}</button>
      </form>
    </div>
  </div>`;
}

window.saveThreatConfig = async function(e) {
  if (e) e.preventDefault();
  const enabled = document.getElementById('threat-enabled')?.checked ?? false;

  // Afficher/masquer le corps au toggle.
  const body = document.getElementById('threat-engine-body');
  if (body) body.style.display = enabled ? '' : 'none';

  const splitLines = id => (document.getElementById(id)?.value || '').split('\n').map(s => s.trim()).filter(Boolean);

  const cfg = {
    enabled,
    mode: document.getElementById('threat-mode')?.value || 'block',
    score_threshold: parseInt(document.getElementById('threat-score')?.value || '0', 10) || 0,
    rate_limit: parseFloat(document.getElementById('threat-rate')?.value || '0') || 0,
    rate_window: document.getElementById('threat-rate-window')?.value || '1s',
    rate_ban_threshold: parseInt(document.getElementById('threat-rate-ban-threshold')?.value || '1', 10) || 1,
    rate_ban_window: document.getElementById('threat-rate-ban-window')?.value || '',
    global_rps: parseFloat(document.getElementById('threat-global-rps')?.value || '0') || 0,
    global_burst: parseInt(document.getElementById('threat-global-burst')?.value || '0', 10) || 0,
    error_threshold: parseInt(document.getElementById('threat-errs')?.value || '20', 10),
    error_window: document.getElementById('threat-ewin')?.value || '10s',
    ban_duration: document.getElementById('threat-dur')?.value || '24h',
    lists: {
      refresh_interval: document.getElementById('threat-refresh')?.value || '6h',
      ua_enabled: document.getElementById('threat-ua')?.checked ?? false,
      path_enabled: document.getElementById('threat-path')?.checked ?? false,
      ip_enabled: document.getElementById('threat-ip')?.checked ?? false,
    },
    custom_lists: {
      ips:   splitLines('threat-custom-ips'),
      uas:   splitLines('threat-custom-uas'),
      paths: splitLines('threat-custom-paths'),
    },
    whitelist: {
      ips:   splitLines('threat-wl-ips'),
      uas:   splitLines('threat-wl-uas'),
      paths: splitLines('threat-wl-paths'),
    },
  };

  try {
    await api('PUT', `/security/threat-config${window._secCoreQ || ''}`, cfg);
    window._threatCfg = cfg;
    toast(t('security.threat.saved'), 'success');
    closeSentinelSettings();
  } catch(err) { toast(err.message, 'error'); }
};

window.openSentinelSettings = function() {
  const overlay = document.getElementById('sentinel-settings-overlay');
  if (overlay) overlay.style.display = '';
};

window.closeSentinelSettings = function() {
  const overlay = document.getElementById('sentinel-settings-overlay');
  if (overlay) overlay.style.display = 'none';
};

// ── Timeouts HTTP/QUIC ────────────────────────────────────────────────────────

function serverTimeoutsBanner(cfg) {
  return `<div class="card blueprint" style="margin-bottom:12px">
    <div class="card-header">
      <span class="card-title">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px;margin-right:6px"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
        Timeouts HTTP / QUIC
      </span>
    </div>
    <div style="padding:12px 16px">
      <div style="margin-bottom:10px;padding:8px 10px;background:var(--warning-bg,#fff8e1);border-radius:6px;font-size:12px;color:var(--warning-text,#7a5c00)">
        ⚠️ Ces valeurs sont sauvegardées dans <code>core.json</code> — un <strong>redémarrage du Core</strong> est nécessaire pour les appliquer.
      </div>
      <form onsubmit="saveServerConfig(event)" style="display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap">
        <div class="field" style="margin:0">
          <label class="field-label">ReadHeader (s) <span style="font-weight:400;color:var(--text3)">anti-Slowloris</span></label>
          <input id="srv-read-header" type="number" class="input" style="width:110px" value="${cfg.read_header_seconds||10}" min="1" placeholder="10">
        </div>
        <div class="field" style="margin:0">
          <label class="field-label">Read (s)</label>
          <input id="srv-read" type="number" class="input" style="width:110px" value="${cfg.read_seconds||30}" min="1" placeholder="30">
        </div>
        <div class="field" style="margin:0">
          <label class="field-label">Write (s)</label>
          <input id="srv-write" type="number" class="input" style="width:110px" value="${cfg.write_seconds||60}" min="1" placeholder="60">
        </div>
        <div class="field" style="margin:0">
          <label class="field-label">Idle (s)</label>
          <input id="srv-idle" type="number" class="input" style="width:110px" value="${cfg.idle_seconds||120}" min="1" placeholder="120">
        </div>
        <button class="btn btn-primary btn-sm" type="submit" style="margin-bottom:1px">Sauvegarder</button>
      </form>
    </div>
  </div>`;
}

window.saveServerConfig = async function(e) {
  if (e) e.preventDefault();
  const cfg = {
    read_header_seconds: parseInt(document.getElementById('srv-read-header')?.value || '10', 10) || 10,
    read_seconds:        parseInt(document.getElementById('srv-read')?.value        || '30', 10) || 30,
    write_seconds:       parseInt(document.getElementById('srv-write')?.value       || '60', 10) || 60,
    idle_seconds:        parseInt(document.getElementById('srv-idle')?.value        || '120', 10) || 120,
  };
  try {
    await api('PUT', `/security/server-config${window._secCoreQ || ''}`, cfg);
    window._serverCfg = cfg;
    toast('Timeouts sauvegardés — redémarrez le Core pour les appliquer', 'success');
  } catch(err) { toast(err.message, 'error'); }
};

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
    if (sort === 'source' || sort === 'source_asc') return _secLocaleCompare(a.source, b.source) || _secLocaleCompare(a.ip, b.ip);
    if (sort === 'source_desc') return _secLocaleCompare(b.source, a.source) || _secLocaleCompare(a.ip, b.ip);
    if (sort === 'date_asc') {
      const da = Date.parse(a.created_at) || 0, db = Date.parse(b.created_at) || 0;
      return da - db || _secLocaleCompare(a.ip, b.ip);
    }
    if (sort === 'date_desc') {
      const da = Date.parse(a.created_at) || 0, db = Date.parse(b.created_at) || 0;
      return db - da || _secLocaleCompare(a.ip, b.ip);
    }
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

function _secSourceLabel(source) {
  if (!source) return '—';
  const v = t('security.source.' + source);
  return v.startsWith('security.source.') ? source : v;
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
    </div>
    <div class="sec-bans-toolbar-row">
      <span style="font-size:11px;color:var(--text3);">${t('security.filter_source')}</span>
      ${_secBansChip(source, '', t('security.filter.all'), "setSecBansSource('')")}
      ${_secBansChip(source, 'native', t('security.source.native'), "setSecBansSource('native')")}
      ${_secBansChip(source, 'fail2ban', t('security.source.fail2ban'), "setSecBansSource('fail2ban')")}
      ${_secBansChip(source, 'crowdsec', t('security.source.crowdsec'), "setSecBansSource('crowdsec')")}
      ${_secBansChip(source, 'threat', t('security.source.threat'), "setSecBansSource('threat')")}
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
  const _bsort = window._secBansSort || 'expires_asc';
  const _bthStyle = 'cursor:pointer;user-select:none;white-space:nowrap';
  const _bind = (col, asc, desc) => {
    const active = _bsort === asc || _bsort === desc;
    const arrow = _bsort === asc ? ' ↑' : _bsort === desc ? ' ↓' : '';
    return `onclick="setSecBansSortCol('${col}')" style="${_bthStyle}${active?';color:var(--accent)':''}" title="${t('common.sort')||'Trier'}"${arrow ? ` data-sorted="${_bsort === asc ? 'asc' : 'desc'}"` : ''}`;
  };
  return `<div class="table-wrap sec-bans-table-scroll"><table>
    <thead><tr>
      <th ${_bind('ip','ip_asc','ip_desc')}>${t('logs.ip')}${_bsort==='ip_asc'?' ↑':_bsort==='ip_desc'?' ↓':''}</th>
      <th>${t('security.col.domain')}</th>
      <th ${_bind('source','source_asc','source_desc')}>${t('security.col.source')}${_bsort==='source_asc'||_bsort==='source'?' ↑':_bsort==='source_desc'?' ↓':''}</th>
      <th>${t('security.col.reason')}</th>
      <th ${_bind('expires','expires_asc','expires_desc')}>${t('security.col.expires')}${_bsort==='expires_asc'?' ↑':_bsort==='expires_desc'?' ↓':''}</th>
      <th ${_bind('date','date_asc','date_desc')}>${t('common.date')}${_bsort==='date_asc'?' ↑':_bsort==='date_desc'?' ↓':''}</th>
      <th></th>
    </tr></thead>
    <tbody>${list.map((b) => `<tr>
      <td class="mono">${esc(b.ip)}</td>
      <td>${esc(b.domain||'—')}</td>
      <td><span class="tag tag-neutral">${esc(_secSourceLabel(b.source))}</span></td>
      <td style="color:var(--text2);font-size:12px">${esc(b.reason||'—')}</td>
      <td style="font-size:11px">${b.expires_at ? fmtDate(b.expires_at) : t('common.permanent')}</td>
      <td style="font-size:11px;color:var(--text3)">${b.created_at ? fmtDate(b.created_at) : '—'}</td>
      <td style="display:flex;gap:4px;justify-content:flex-end">
        <button type="button" class="btn btn-ghost btn-icon btn-sm" onclick="openPrismForBanIP('${esc(b.ip)}')" title="Voir dans Prism" aria-label="Voir dans Prism"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg></button>
        <button type="button" class="btn btn-ghost btn-icon btn-sm" onclick="showBanHistory('${esc(b.ip)}')" title="${esc(t('security.ban_history'))}" aria-label="${esc(t('security.ban_history'))}"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg></button>
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

window.setSecBansSortCol = function(col) {
  const sort = window._secBansSort || 'expires_asc';
  const ascKey = col + '_asc';
  const descKey = col + '_desc';
  const isAsc = sort === ascKey || (col === 'source' && sort === 'source');
  window._secBansSort = isAsc ? descKey : ascKey;
  renderSecBansPanel();
};

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

function vulnscanPanel(st, cfg, isAdmin) {
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

  const allowPrivate = !!(cfg && cfg.allow_private);
  const configBlock = isAdmin ? `
    <div style="margin-top:14px;padding:10px 12px;background:var(--surface2,var(--surface));border-radius:6px;border:1px solid var(--border)">
      <label style="display:flex;align-items:center;gap:10px;cursor:pointer;font-size:13px">
        <input type="checkbox" id="vulnscan-allow-private" ${allowPrivate ? 'checked' : ''} onchange="saveVulnscanConfig()" style="width:15px;height:15px;cursor:pointer">
        <span>
          <b>${t('security.vulnscan.allow_private')}</b>
          <span style="display:block;font-size:11px;color:var(--text2);margin-top:1px">${t('security.vulnscan.allow_private_help')}</span>
        </span>
      </label>
    </div>` : '';

  return `<div>
    <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap">${statusBadge}</div>
    ${progressBlock}
    ${summary}
    ${st.last_error ? `<div style="margin-top:10px;color:var(--red);font-size:12px">${esc(st.last_error)}</div>` : ''}
    ${resultsBlock}
    ${configBlock}
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
    enabled: true,
    window_sec: parseInt(document.getElementById('f2b-window')?.value)||300,
    max_errors: parseInt(document.getElementById('f2b-max')?.value)||20,
    ban_duration_sec: (() => { const v = parseInt(document.getElementById('f2b-dur')?.value, 10); return Number.isFinite(v) && v >= 0 ? v : 0; })(),
    trust_forwarded_for: document.getElementById('f2b-xff')?.checked || false,
    whitelist,
  };
  try {
    await Promise.all([
      api('PUT', `/security/ips-provider${window._secCoreQ || ''}`, { provider: 'fail2ban' }),
      api('PUT', '/security/fail2ban', cfg),
    ]);
    toast(t('security.ips.saved'), 'success');
    reloadCurrentSecurityPage();
  } catch(err) { toast(err.message, 'error'); }
};

window.saveCrowdSecConfig = async function(e) {
  e.preventDefault();
  const cfg = {
    enabled: true,
    api_url: document.getElementById('cs-url')?.value.trim() || 'http://localhost:8080',
    api_key: document.getElementById('cs-key')?.value || '',
  };
  try {
    await Promise.all([
      api('PUT', `/security/ips-provider${window._secCoreQ || ''}`, { provider: 'crowdsec' }),
      api('PUT', '/security/crowdsec', cfg),
    ]);
    toast(t('security.ips.saved'), 'success');
    reloadCurrentSecurityPage();
  } catch(err) { toast(err.message, 'error'); }
};

window.selectIPSProvider = async function(provider) {
  try {
    await api('PUT', `/security/ips-provider${window._secCoreQ || ''}`, { provider });
    window._ipsProvider = provider;
    toast(t('security.ips.saved'), 'success');
    reloadCurrentSecurityPage();
  } catch(err) { toast(err.message, 'error'); }
};

window.ipsSelectLocal = function(provider) {
  // Met à jour l'UI localement sans appel API : active la carte, montre le bon panneau
  document.querySelectorAll('.ips-option').forEach(el => {
    el.classList.toggle('is-active', el.getAttribute('onclick')?.includes(`'${provider}'`));
  });
  const panel = document.getElementById('ips-provider-panel');
  if (!panel) return;
  const f2bCfg = window._f2bCfg || {};
  const csCfg = window._csCfg || {};
  const svgWrench = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z"/></svg>`;
  const svgShield = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`;
  if (provider === 'fail2ban') {
    panel.innerHTML = `<div class="ips-config-panel"><div class="ips-config-panel-head"><span class="ips-config-panel-name">${svgWrench}${t('security.fail2ban_native')}</span></div>${f2bPanel(f2bCfg)}</div>`;
  } else if (provider === 'crowdsec') {
    panel.innerHTML = `<div class="ips-config-panel"><div class="ips-config-panel-head"><span class="ips-config-panel-name">${svgShield}${t('security.crowdsec')}</span></div>${crowdSecPanel(csCfg)}</div>`;
  } else {
    panel.innerHTML = `<div class="ips-config-panel"><button class="btn btn-primary btn-sm" onclick="selectIPSProvider('native')">${t('common.save')}</button></div>`;
  }
};

window.saveVulnscanConfig = async function() {
  const cb = document.getElementById('vulnscan-allow-private');
  if (!cb) return;
  try {
    await api('PUT', '/security/vulnscan/config', { allow_private: cb.checked });
    window._vsConfig = { ...(window._vsConfig || {}), allow_private: cb.checked };
    toast(t('security.vulnscan.config_saved'), 'success');
  } catch(err) {
    toast(err.message, 'error');
    cb.checked = !cb.checked;
  }
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

window.openPrismForBanIP = function(ip) {
  window._prismIpInit = ip;
  if (state.selectedCore) {
    navigate('core-prism');
    return;
  }
  const cores = window._coreNodes || [];
  if (cores.length === 1) {
    selectCore(cores[0], 'core-prism');
    return;
  }
  if (cores.length > 1) {
    toast('Sélectionnez un Core pour ouvrir Prism', 'info');
    navigate('infrastructure');
    return;
  }
  toast(t('logs.prism_need_core'), 'error');
};

window.showBanHistory = async function(ip) {
  // Récupère la timeline unifiée et le profil WAF en parallèle
  const [events, wafProfile] = await Promise.all([
    api('GET', `/security/ip-timeline?ip=${encodeURIComponent(ip)}`).catch(() => []),
    (async () => {
      const coreId = state.selectedCore || window._selectedCoreId;
      if (!coreId) return null;
      try {
        const profiles = await coreProxy(coreId, 'GET', '/internal/v1/waf/behavior/profiles');
        return (profiles || {})[ip] || null;
      } catch { return null; }
    })(),
  ]);

  const kindCfg = {
    ban:    { color: 'var(--red)',    icon: '🔒', label: 'Ban' },
    unban:  { color: 'var(--text3)', icon: '🔓', label: 'Débannissement' },
    threat: { color: 'var(--orange)', icon: '⚠️', label: 'Détection' },
  };

  const timelineRows = events.length
    ? events.map(e => {
        const cfg = kindCfg[e.kind] || kindCfg.threat;
        return `<tr>
          <td style="font-size:11px;color:var(--text3);white-space:nowrap">${fmtDate(e.created_at)}</td>
          <td style="white-space:nowrap">
            <span style="display:inline-flex;align-items:center;gap:5px;font-size:12px;font-weight:600;color:${cfg.color}">
              ${cfg.icon} ${cfg.label}
            </span>
          </td>
          <td style="font-size:12px;color:var(--text2)">${esc(_secSourceLabel(e.source))}</td>
          <td style="font-size:12px">${esc(e.reason||'—')}</td>
        </tr>`;
      }).join('')
    : `<tr><td colspan="4" style="text-align:center;color:var(--text3);padding:24px">${t('security.ban_history_empty')}</td></tr>`;

  let wafHtml = '';
  if (wafProfile) {
    const scoreColor = wafProfile.score >= 8 ? 'var(--red)' : wafProfile.score >= 4 ? 'var(--orange)' : 'var(--text2)';
    const signals = (wafProfile.signals || []).map(s =>
      `<span style="display:inline-block;background:var(--bg2);border:1px solid var(--border);border-radius:4px;padding:1px 7px;font-size:11px;margin:2px">${esc(s.name)} <span style="color:var(--orange)">+${s.score}</span></span>`
    ).join('');
    wafHtml = `
      <div style="margin-top:16px;padding:12px 16px;background:var(--bg2);border-radius:6px;border:1px solid var(--border)">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
          <span style="font-size:12px;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:.06em">Profil WAF Sentinel</span>
          <span style="background:${scoreColor};color:#fff;font-size:12px;font-weight:700;padding:1px 8px;border-radius:4px">Score ${wafProfile.score}</span>
        </div>
        <div>${signals || '<span style="font-size:12px;color:var(--text3)">Aucun signal actif</span>'}</div>
      </div>`;
  }

  modal(
    `Sécurité · <span style="font-family:monospace">${esc(ip)}</span>`,
    `<div class="table-wrap"><table><thead><tr>
      <th>${t('common.date')}</th>
      <th>Événement</th>
      <th>${t('security.col.source')}</th>
      <th>${t('security.col.reason')}</th>
    </tr></thead><tbody>${timelineRows}</tbody></table></div>${wafHtml}`,
    '',
    true
  );
};

// ── WAF Profils comportementaux ──────────────────────────────────────────────

async function renderWAFBehaviorProfiles(ctx) {
  const el = document.getElementById('page-content');
  if (!el) return;

  const coreCtx = ctx?.mode === 'core' ? ctx : null;
  const coreId = coreCtx?.coreId || window._selectedCoreId;

  let profiles = {};
  try {
    if (coreId) {
      profiles = await coreProxy(coreId, 'GET', '/internal/v1/waf/behavior/profiles') || {};
    }
  } catch(e) { /* ignore */ }

  const rows = Object.entries(profiles).sort((a, b) => b[1].score - a[1].score);

  const scoreColor = (s) => s >= 8 ? 'var(--red)' : s >= 4 ? 'var(--orange)' : 'var(--text3)';
  const signalBadges = (sigs) => (sigs || []).map(s =>
    `<span style="display:inline-block;background:var(--bg2);border:1px solid var(--border);border-radius:4px;padding:1px 6px;font-size:11px;margin:1px;">${s.name}<span style="color:var(--text2);margin-left:3px;">+${s.score}</span></span>`
  ).join('');

  el.innerHTML = `
    <div style="max-width:960px;margin:0 auto;padding:24px 16px;">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;">
        <h2 style="font-size:18px;font-weight:700;margin:0;">Profils comportementaux WAF</h2>
        <button class="btn btn-sm" onclick="renderWAFBehaviorProfiles(${JSON.stringify(ctx||{})})">Actualiser</button>
      </div>
      ${rows.length === 0
        ? `<div style="text-align:center;padding:48px;color:var(--text2);font-size:13px;">Aucun profil actif</div>`
        : `<table style="width:100%;border-collapse:collapse;font-size:13px;">
          <thead><tr style="border-bottom:2px solid var(--border);">
            <th style="text-align:left;padding:8px 12px;font-weight:600;">IP</th>
            <th style="text-align:right;padding:8px 12px;font-weight:600;">Score</th>
            <th style="text-align:left;padding:8px 12px;font-weight:600;">Signaux</th>
            <th style="text-align:center;padding:8px 12px;font-weight:600;">Crédit</th>
            <th style="padding:8px 12px;"></th>
          </tr></thead>
          <tbody>
            ${rows.map(([ip, info]) => `
              <tr style="border-bottom:1px solid var(--border);">
                <td style="padding:8px 12px;font-family:monospace;">${ip}</td>
                <td style="padding:8px 12px;text-align:right;">
                  <span style="background:${scoreColor(info.score)};color:#fff;padding:2px 8px;border-radius:4px;font-weight:600;">${info.score}</span>
                </td>
                <td style="padding:8px 12px;">${signalBadges(info.signals)}</td>
                <td style="padding:8px 12px;text-align:center;color:var(--text2);font-size:12px;">
                  ${info.trust_bonus > 0
                    ? `<span title="${info.clean_requests} req propres" style="color:var(--green);font-weight:600;">+${info.trust_bonus}</span>`
                    : `<span title="${info.clean_requests} req propres">–</span>`}
                </td>
                <td style="padding:8px 12px;text-align:right;">
                  <button class="btn btn-sm" style="color:var(--red)" onclick="deleteWAFBehaviorProfile('${ip}', ${JSON.stringify(coreId||'')}, ${JSON.stringify(ctx||{})})">Supprimer</button>
                </td>
              </tr>`).join('')}
          </tbody>
        </table>`}
    </div>`;
}

window.deleteWAFBehaviorProfile = async function(ip, coreId, ctx) {
  try {
    if (coreId) {
      await coreProxy(coreId, 'DELETE', `/internal/v1/waf/behavior/profiles/${encodeURIComponent(ip)}`);
    }
    toast('Profil supprimé', 'success');
    renderWAFBehaviorProfiles(ctx);
  } catch(e) { toast(e.message, 'error'); }
};

pages['core-security-waf-profiles'] = (ctx) => renderWAFBehaviorProfiles({ ...ctx, mode: 'core' });

window.updateCVE = async function(id, status) {
  try {
    await api('PATCH', `/security/cves/${id}`, { status });
    toast(t('security.cve_updated'), 'success');
    reloadCurrentSecurityPage();
  } catch(e) { toast(e.message, 'error'); }
};

// ── Moteur de règles ────────────────────────────────────────────────────────

const _COND_TYPES = [
  { value: 'cve_critical',     label: 'CVE critique sur proxy actif' },
  { value: 'ban_spike',        label: 'Pic de bans' },
  { value: 'engine_silent',    label: 'Moteur IPS silencieux' },
  { value: 'proxy_error_rate', label: 'Taux d\'erreurs proxy' },
  { value: 'ban_repeat',       label: 'IP récidiviste (multi-ban)' },
];

const _ACTION_TYPES = [
  { value: 'disable_proxy',  label: 'Désactiver le proxy' },
  { value: 'ban_ip',         label: 'Bannir l\'IP' },
  { value: 'notify',         label: 'Notifier' },
  { value: 'enable_strict',  label: 'Mode strict Fail2Ban (temporaire)' },
];

async function renderSecurityRules() {
  const content = document.getElementById('content');
  content.innerHTML = '<p style="color:var(--text2)">' + t('common.loading') + '</p>';
  const ta = document.getElementById('topbar-actions');
  if (ta) ta.innerHTML = `<button class="btn btn-primary btn-sm" onclick="openRuleModal(null)">${t('security.rules.add')}</button>`;

  try {
    const [rules, history] = await Promise.all([
      api('GET', '/rules-engine/rules'),
      api('GET', '/rules-engine/history'),
    ]);
    window._reRules = rules || [];
    window._reHistory = history || [];
    window._reTab = window._reTab || 'rules';
    content.innerHTML = _rulesPageHTML();
  } catch(e) { toast(e.message, 'error'); }
}

function _rulesPageHTML() {
  const tab = window._reTab || 'rules';
  const tabs = [
    { v: 'rules',   label: t('security.rules.tab_rules') },
    { v: 'history', label: t('security.rules.tab_history') },
  ];
  const tabBar = `<div style="display:flex;gap:6px;margin-bottom:16px">
    ${tabs.map(t2=>`<button class="btn btn-sm${tab===t2.v?' btn-primary':' btn-ghost'}" onclick="setReTab('${t2.v}')">${t2.label}</button>`).join('')}
  </div>`;
  return tabBar + (tab === 'history' ? _reHistoryHTML() : _reRulesHTML());
}

function _reRulesHTML() {
  const rules = window._reRules || [];
  if (!rules.length) return `<div class="empty"><p>${t('security.rules.no_rules')}</p></div>`;

  const condLabel = (type) => _COND_TYPES.find(c=>c.value===type)?.label || type;
  const actionLabel = (type) => _ACTION_TYPES.find(a=>a.value===type)?.label || type;
  const svgFire = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2c0 6-8 6-8 12a8 8 0 0016 0c0-6-8-6-8-12z"/></svg>`;

  return `<div style="display:flex;flex-direction:column;gap:10px">
    ${rules.map(r => `
    <div class="card blueprint" style="padding:14px 16px">
      <div style="display:flex;align-items:flex-start;gap:12px">
        <div style="flex:1;min-width:0">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
            <span style="font-weight:600;font-size:13.5px">${esc(r.name)}</span>
            <span class="tag ${r.enabled?'tag-green':'tag-neutral'}" style="font-size:10px">${r.enabled ? t('security.rules.enabled') : t('security.rules.disabled')}</span>
            ${r.fire_count ? `<span class="tag tag-yellow" style="font-size:10px">${svgFire} ${r.fire_count}x</span>` : ''}
          </div>
          ${r.description ? `<p style="font-size:12px;color:var(--text2);margin:4px 0 0">${esc(r.description)}</p>` : ''}
          <div style="display:flex;gap:16px;margin-top:8px;flex-wrap:wrap">
            <div style="font-size:11.5px">
              <span style="color:var(--text3)">${t('security.rules.condition')}: </span>
              <span class="tag tag-neutral" style="font-size:10px">${condLabel(r.condition?.type)}</span>
              ${_condSummary(r.condition)}
            </div>
            <div style="font-size:11.5px">
              <span style="color:var(--text3)">${t('security.rules.action')}: </span>
              <span class="tag tag-accent" style="font-size:10px">${actionLabel(r.action?.type)}</span>
              ${_actionSummary(r.action)}
            </div>
            <div style="font-size:11px;color:var(--text3)">
              ${t('security.rules.cooldown')}: ${r.cooldown_sec ? Math.round(r.cooldown_sec/60)+'min' : '5min'}
              ${r.last_fired_at ? ` · ${t('security.rules.last_fired')}: ${fmtDate(r.last_fired_at)}` : ''}
            </div>
          </div>
        </div>
        <div style="display:flex;gap:6px;align-items:center;flex-shrink:0">
          <button class="btn btn-ghost btn-sm" onclick="runRuleNow('${esc(r.id)}','${esc(r.name)}')" title="${t('security.rules.run_now')}">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
          </button>
          <button class="btn btn-ghost btn-sm" onclick="openRuleModal(${JSON.stringify(JSON.stringify(r))})" title="${t('common.edit')}">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
          </button>
          <label class="toggle" title="${r.enabled ? t('security.rules.disable') : t('security.rules.enable')}">
            <input type="checkbox" ${r.enabled?'checked':''} onchange="toggleRule('${esc(r.id)}',this.checked)">
            <span class="toggle-slider"></span>
          </label>
          <button class="btn btn-ghost btn-sm" onclick="deleteRule('${esc(r.id)}','${esc(r.name)}')" style="color:var(--red)" title="${t('common.delete')}">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6"/><path d="M10 11v6M14 11v6"/></svg>
          </button>
        </div>
      </div>
    </div>`).join('')}
  </div>`;
}

function _condSummary(c) {
  if (!c) return '';
  const parts = [];
  if (c.cvss_threshold) parts.push(`CVSS ≥ ${c.cvss_threshold}`);
  if (c.ban_count) parts.push(`> ${c.ban_count} bans`);
  if (c.ban_window) parts.push(`/${c.ban_window}`);
  if (c.engine_type) parts.push(c.engine_type);
  if (c.silent_minutes) parts.push(`> ${c.silent_minutes}min`);
  if (c.error_rate_threshold) parts.push(`> ${c.error_rate_threshold}%`);
  if (c.repeat_count) parts.push(`≥ ${c.repeat_count}x`);
  return parts.length ? `<span style="font-size:11px;color:var(--text2);margin-left:4px">${parts.join(' ')}</span>` : '';
}

function _actionSummary(a) {
  if (!a) return '';
  const parts = [];
  if (a.proxy_id) parts.push(`proxy:${a.proxy_id.slice(0,8)}`);
  if (a.ban_duration) parts.push(a.ban_duration);
  if (a.strict_duration) parts.push(a.strict_duration);
  if (a.notify_severity) parts.push(a.notify_severity);
  return parts.length ? `<span style="font-size:11px;color:var(--text2);margin-left:4px">${parts.join(' ')}</span>` : '';
}

function _reHistoryHTML() {
  const hist = window._reHistory || [];
  if (!hist.length) return `<div class="empty"><p>${t('security.rules.no_history')}</p></div>`;
  return `<div class="table-wrap"><table>
    <thead><tr>
      <th>${t('common.date')}</th>
      <th>${t('security.rules.rule')}</th>
      <th>${t('security.rules.col_matched')}</th>
      <th>${t('security.rules.col_action')}</th>
      <th>${t('security.rules.col_detail')}</th>
    </tr></thead>
    <tbody>${hist.map(h=>`<tr>
      <td style="font-size:11px;white-space:nowrap">${fmtDate(h.fired_at)}</td>
      <td style="font-size:12px">${esc(h.rule_name||h.rule_id)}</td>
      <td>${h.cond_result ? '<span class="tag tag-green" style="font-size:10px">oui</span>' : '<span class="tag tag-neutral" style="font-size:10px">non</span>'}</td>
      <td>${h.action_taken ? '<span class="tag tag-accent" style="font-size:10px">exécutée</span>' : '—'}${h.error?`<span style="font-size:10px;color:var(--red);margin-left:4px" title="${esc(h.error)}">⚠</span>`:''}</td>
      <td style="font-size:11px;color:var(--text2);max-width:260px;overflow:hidden;text-overflow:ellipsis">${esc(h.detail||'')}</td>
    </tr>`).join('')}</tbody>
  </table></div>`;
}

window.setReTab = function(v) {
  window._reTab = v;
  const content = document.getElementById('content');
  if (content) content.innerHTML = _rulesPageHTML();
};

window.toggleRule = async function(id, enabled) {
  const rule = (window._reRules||[]).find(r=>r.id===id);
  if (!rule) return;
  try {
    await api('PUT', `/rules-engine/rules/${id}`, { ...rule, enabled });
    rule.enabled = enabled;
    const content = document.getElementById('content');
    if (content) content.innerHTML = _rulesPageHTML();
  } catch(e) { toast(e.message,'error'); }
};

window.deleteRule = async function(id, name) {
  if (!confirm(t('security.rules.delete_confirm', { name }))) return;
  try {
    await api('DELETE', `/rules-engine/rules/${id}`);
    toast(t('security.rules.deleted'), 'success');
    renderSecurityRules();
  } catch(e) { toast(e.message,'error'); }
};

window.runRuleNow = async function(id, name) {
  try {
    const res = await api('POST', `/rules-engine/rules/${id}/run?dry_run=true`);
    const msg = res.matched
      ? `✓ Condition vraie — action non exécutée (dry-run)\n${JSON.stringify(res.detail||{}, null, 2)}`
      : '✗ Condition non remplie actuellement';
    alert(`[${name}]\n${msg}`);
  } catch(e) { toast(e.message,'error'); }
};

window.openRuleModal = function(ruleJSON) {
  const rule = ruleJSON ? JSON.parse(ruleJSON) : null;
  const isEdit = !!rule;
  const cond = rule?.condition || {};
  const act = rule?.action || {};

  const condOptions = _COND_TYPES.map(c=>`<option value="${c.value}"${cond.type===c.value?' selected':''}>${c.label}</option>`).join('');
  const actOptions = _ACTION_TYPES.map(a=>`<option value="${a.value}"${act.type===a.value?' selected':''}>${a.label}</option>`).join('');

  const modal = document.createElement('div');
  modal.className = 'modal-backdrop';
  modal.innerHTML = `
    <div class="modal" style="max-width:540px;width:100%">
      <div class="modal-header">
        <span class="modal-title">${isEdit ? t('security.rules.edit') : t('security.rules.add')}</span>
        <button class="btn-close" onclick="this.closest('.modal-backdrop').remove()">✕</button>
      </div>
      <div class="modal-body" style="display:flex;flex-direction:column;gap:12px">
        <div class="field" style="margin:0">
          <label class="field-label">${t('security.rules.name')}</label>
          <input id="re-name" class="input" value="${esc(rule?.name||'')}" placeholder="${t('security.rules.name_ph')}">
        </div>
        <div class="field" style="margin:0">
          <label class="field-label">${t('security.rules.description')}</label>
          <input id="re-desc" class="input" value="${esc(rule?.description||'')}" placeholder="${t('security.rules.desc_ph')}">
        </div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
          <div class="field" style="margin:0">
            <label class="field-label">${t('security.rules.condition')}</label>
            <select id="re-cond-type" class="input" style="height:32px" onchange="_reUpdateCondFields(this.value)">${condOptions}</select>
          </div>
          <div class="field" style="margin:0">
            <label class="field-label">${t('security.rules.action')}</label>
            <select id="re-act-type" class="input" style="height:32px" onchange="_reUpdateActFields(this.value)">${actOptions}</select>
          </div>
        </div>

        <div id="re-cond-fields" style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
          ${_reCondFieldsHTML(cond.type||'cve_critical', cond)}
        </div>
        <div id="re-act-fields" style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
          ${_reActFieldsHTML(act.type||'notify', act)}
        </div>

        <div class="field" style="margin:0">
          <label class="field-label">${t('security.rules.cooldown')} <span style="font-weight:400;color:var(--text3)">(secondes, défaut 300)</span></label>
          <input id="re-cooldown" type="number" class="input" value="${rule?.cooldown_sec||300}" min="60">
        </div>

        <label style="display:flex;align-items:center;gap:8px;font-size:12.5px">
          <input type="checkbox" id="re-enabled" ${(rule?.enabled!==false)?'checked':''}>
          <span>${t('security.rules.activate_now')}</span>
        </label>
      </div>
      <div class="modal-footer">
        <button class="btn btn-ghost" onclick="this.closest('.modal-backdrop').remove()">${t('common.cancel')}</button>
        <button class="btn btn-primary" onclick="_reSaveRule('${isEdit?rule.id:''}')">${t('common.save')}</button>
      </div>
    </div>`;
  document.body.appendChild(modal);
};

function _reCondFieldsHTML(type, cond = {}) {
  switch(type) {
    case 'cve_critical': return `
      <div class="field" style="margin:0"><label class="field-label">CVSS seuil minimum</label>
        <input id="re-cvss" type="number" class="input" value="${cond.cvss_threshold||9}" min="0" max="10" step="0.1"></div>
      <div class="field" style="margin:0"><label class="field-label">Proxy ID (vide = tous)</label>
        <input id="re-proxy-id" class="input" value="${esc(cond.proxy_id||'')}"></div>`;
    case 'ban_spike': return `
      <div class="field" style="margin:0"><label class="field-label">Nombre de bans déclenchant</label>
        <input id="re-ban-count" type="number" class="input" value="${cond.ban_count||20}" min="1"></div>
      <div class="field" style="margin:0"><label class="field-label">Fenêtre (ex: 1h, 30m)</label>
        <input id="re-ban-window" class="input" value="${esc(cond.ban_window||'1h')}"></div>`;
    case 'engine_silent': return `
      <div class="field" style="margin:0"><label class="field-label">Moteur</label>
        <select id="re-engine-type" class="input" style="height:32px">
          <option value="fail2ban"${(cond.engine_type||'fail2ban')==='fail2ban'?' selected':''}>Fail2Ban</option>
          <option value="crowdsec"${cond.engine_type==='crowdsec'?' selected':''}>CrowdSec</option>
        </select></div>
      <div class="field" style="margin:0"><label class="field-label">Silence > (minutes)</label>
        <input id="re-silent-min" type="number" class="input" value="${cond.silent_minutes||10}" min="1"></div>`;
    case 'proxy_error_rate': return `
      <div class="field" style="margin:0"><label class="field-label">Taux d'erreurs % (500+)</label>
        <input id="re-err-rate" type="number" class="input" value="${cond.error_rate_threshold||20}" min="1" max="100"></div>
      <div class="field" style="margin:0"><label class="field-label">Fenêtre (ex: 5m)</label>
        <input id="re-err-window" class="input" value="${esc(cond.error_rate_window||'5m')}"></div>`;
    case 'ban_repeat': return `
      <div class="field" style="margin:0"><label class="field-label">Bans répétés minimum</label>
        <input id="re-repeat-count" type="number" class="input" value="${cond.repeat_count||3}" min="2"></div>
      <div class="field" style="margin:0"><label class="field-label">Fenêtre (ex: 24h)</label>
        <input id="re-repeat-window" class="input" value="${esc(cond.repeat_window||'24h')}"></div>`;
    default: return '';
  }
}

function _reActFieldsHTML(type, act = {}) {
  switch(type) {
    case 'disable_proxy': return `
      <div class="field" style="margin:0;grid-column:span 2"><label class="field-label">Proxy ID (vide = proxy issu de la condition)</label>
        <input id="re-act-proxy-id" class="input" value="${esc(act.proxy_id||'')}"></div>`;
    case 'ban_ip': return `
      <div class="field" style="margin:0"><label class="field-label">Durée du ban (ex: 24h, vide = permanent)</label>
        <input id="re-act-ban-dur" class="input" value="${esc(act.ban_duration||'')}"></div>
      <div class="field" style="margin:0"><label class="field-label">Raison</label>
        <input id="re-act-ban-reason" class="input" value="${esc(act.ban_reason||'')}"></div>`;
    case 'notify': return `
      <div class="field" style="margin:0"><label class="field-label">Sévérité</label>
        <select id="re-act-sev" class="input" style="height:32px">
          <option value="info"${(act.notify_severity||'warning')==='info'?' selected':''}>Info</option>
          <option value="warning"${(act.notify_severity||'warning')==='warning'?' selected':''}>Warning</option>
          <option value="critical"${act.notify_severity==='critical'?' selected':''}>Critical</option>
        </select></div>
      <div class="field" style="margin:0"><label class="field-label">Message</label>
        <input id="re-act-msg" class="input" value="${esc(act.notify_message||'')}"></div>`;
    case 'enable_strict': return `
      <div class="field" style="margin:0;grid-column:span 2"><label class="field-label">Durée mode strict (ex: 30m)</label>
        <input id="re-act-strict-dur" class="input" value="${esc(act.strict_duration||'30m')}"></div>`;
    default: return '';
  }
}

window._reUpdateCondFields = function(type) {
  const el = document.getElementById('re-cond-fields');
  if (el) el.innerHTML = _reCondFieldsHTML(type, {});
};
window._reUpdateActFields = function(type) {
  const el = document.getElementById('re-act-fields');
  if (el) el.innerHTML = _reActFieldsHTML(type, {});
};

window._reSaveRule = async function(existingId) {
  const name = document.getElementById('re-name')?.value?.trim();
  if (!name) { toast(t('security.rules.name_required'), 'error'); return; }

  const condType = document.getElementById('re-cond-type')?.value;
  const actType  = document.getElementById('re-act-type')?.value;

  const condition = { type: condType };
  if (condType === 'cve_critical') {
    condition.cvss_threshold = parseFloat(document.getElementById('re-cvss')?.value||'9');
    condition.proxy_id = document.getElementById('re-proxy-id')?.value||'';
  } else if (condType === 'ban_spike') {
    condition.ban_count = parseInt(document.getElementById('re-ban-count')?.value||'20');
    condition.ban_window = document.getElementById('re-ban-window')?.value||'1h';
  } else if (condType === 'engine_silent') {
    condition.engine_type = document.getElementById('re-engine-type')?.value||'fail2ban';
    condition.silent_minutes = parseInt(document.getElementById('re-silent-min')?.value||'10');
  } else if (condType === 'proxy_error_rate') {
    condition.error_rate_threshold = parseFloat(document.getElementById('re-err-rate')?.value||'20');
    condition.error_rate_window = document.getElementById('re-err-window')?.value||'5m';
  } else if (condType === 'ban_repeat') {
    condition.repeat_count = parseInt(document.getElementById('re-repeat-count')?.value||'3');
    condition.repeat_window = document.getElementById('re-repeat-window')?.value||'24h';
  }

  const action = { type: actType };
  if (actType === 'disable_proxy') {
    action.proxy_id = document.getElementById('re-act-proxy-id')?.value||'';
  } else if (actType === 'ban_ip') {
    action.ban_duration = document.getElementById('re-act-ban-dur')?.value||'';
    action.ban_reason   = document.getElementById('re-act-ban-reason')?.value||'';
  } else if (actType === 'notify') {
    action.notify_severity = document.getElementById('re-act-sev')?.value||'warning';
    action.notify_message  = document.getElementById('re-act-msg')?.value||'';
  } else if (actType === 'enable_strict') {
    action.strict_duration = document.getElementById('re-act-strict-dur')?.value||'30m';
  }

  const payload = {
    name,
    description: document.getElementById('re-desc')?.value||'',
    enabled: document.getElementById('re-enabled')?.checked !== false,
    condition,
    action,
    cooldown_sec: parseInt(document.getElementById('re-cooldown')?.value||'300'),
  };

  try {
    if (existingId) {
      await api('PUT', `/rules-engine/rules/${existingId}`, payload);
    } else {
      await api('POST', '/rules-engine/rules', payload);
    }
    document.querySelector('.modal-backdrop')?.remove();
    toast(t('common.saved'), 'success');
    renderSecurityRules();
  } catch(e) { toast(e.message,'error'); }
};
