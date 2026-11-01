// ── PAGE PARTAGÉE: Sécurité (Admin + Passerelle) ───────────────────────────────
// ctx = { mode: 'admin'|'edge' }
// Mode edge : même UI ; données filtrées sur les proxies / domaines de la passerelle
// sélectionné (GET /proxies?edge=…). Config Seuils multi-passerelles / CrowdSec = admin only.

function securityPageId(variant, mode) {
  const isEdge = mode === 'edge';
  const map = {
    overview: isEdge ? 'edge-security' : 'security',
    bans:     isEdge ? 'edge-security-bans' : 'security-bans',
    vulns:    isEdge ? 'edge-security-vulns' : 'security-vulns',
    posture:  isEdge ? 'edge-security-posture' : 'security-posture',
    ephor: isEdge ? 'edge-security-ephor' : 'security-ephor',
  };
  return map[variant] || map.overview;
}

function securityModeFromPage(page) {
  return (page || '').startsWith('edge-security') ? 'edge' : 'admin';
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

function _secBuildEdgeFilter(proxies) {
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

async function resolveSecurityEdgeCtx(mode) {
  if (mode !== 'edge') return null;
  const edge = state.selectedEdge;
  if (!edge) return { missing: true };
  const tokens = await api('GET', '/tokens?role=edge').catch(() => []);
  const match = (tokens || []).filter(tok => !tok.revoked && (
    tok.id === edge.id || tok.node_name === edge.node_name || tok.node_name === edge.id
  ));
  const best = match.find(tok => tok.id === edge.id)
    || match.find(tok => tok.node_endpoint)
    || match[0]
    || null;
  const edgeRef = best?.id || edge.node_name || edge.id || '';
  if (!edgeRef) return { missing: true };
  const proxies = await api('GET', `/proxies?edge=${encodeURIComponent(edgeRef)}`).catch(() => []);
  const filter = _secBuildEdgeFilter(proxies);
  const groups = await api('GET', '/architecture/groups').catch(() => null);
  const group = _secFindHAGroup(groups, [edgeRef, edge.node_name, edge.id]);
  return {
    edge,
    edgeRef,
    edgeLabel: edge.display_name || edge.node_name || edge.id || '—',
    proxies: proxies || [],
    group,
    ...filter,
  };
}

// _secFindHAGroup : groupe HA (déclaré dans architecture.json) qui contient la passerelle, ou null.
function _secFindHAGroup(groups, refs) {
  for (const [name, members] of Object.entries(groups || {})) {
    const list = members || [];
    if (list.some(m => refs.includes(m.id) || refs.includes(m.name))) {
      return { name, members: list.map(m => m.name) };
    }
  }
  return null;
}

function securityEdgeBanner(edgeCtx) {
  if (!edgeCtx?.edgeLabel) return '';
  const groupNote = edgeCtx.group
    ? `<div style="margin-top:6px;">${t('security.edge_group_note', { group: esc(edgeCtx.group.name), members: edgeCtx.group.members.map(esc).join(', ') })}</div>`
    : '';
  return `<div style="margin-bottom:14px;padding:10px 12px;background:color-mix(in srgb,var(--accent) 7%,transparent);border:1px solid color-mix(in srgb,var(--accent) 22%,transparent);border-radius:6px;font-size:12px;color:var(--text2);">
    <strong style="color:var(--text1);">${t('security.edge_banner_title')}</strong> —
    ${t('security.edge_banner_body', { name: esc(edgeCtx.edgeLabel) })}${groupNote}
  </div>`;
}

function filterSecHeaders(headers, edgeCtx) {
  if (!edgeCtx) return headers || [];
  return (headers || []).filter(h => edgeCtx.proxyIds.has(h.proxy_id));
}

function filterSecCerts(certs, edgeCtx) {
  if (!edgeCtx) return certs || [];
  return (certs || []).filter(c => _secDomainMatch(c.domain, edgeCtx.domains));
}

function filterSecBans(bans, edgeCtx) {
  if (!edgeCtx) return bans || [];
  return (bans || []).filter(b => !b.domain || _secDomainMatch(b.domain, edgeCtx.domains));
}

function filterSecCVEs(cves, edgeCtx) {
  if (!edgeCtx) return cves || [];
  return (cves || []).filter(c => _secBackendMatch(c.backend_url, edgeCtx.backends));
}

function filterSecTimeline(events, edgeCtx) {
  if (!edgeCtx) return events || [];
  return (events || []).filter(e => {
    if (e.type === 'threat') return true;
    if (e.type === 'ban' || e.type === 'cert') {
      return !e.domain || _secDomainMatch(e.domain, edgeCtx.domains);
    }
    if (e.type === 'cve') {
      const summary = String(e.summary || '').toLowerCase();
      for (const b of edgeCtx.backends) {
        if (summary.includes(b)) return true;
      }
      return false;
    }
    return true;
  });
}

function filterVulnscanState(st, edgeCtx) {
  if (!edgeCtx || !st) return st;
  const results = Array.isArray(st.results)
    ? st.results.filter(r => _secBackendMatch(r.url, edgeCtx.backends))
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
  const counts = { native: 0, fleet: 0, crowdsec: 0, threat: 0, manual: 0 };
  for (const b of bans) counts[b.source] = (counts[b.source] || 0) + 1;
  const total = bans.length || 1;
  const labels = { native: 'Natif', fleet: 'Seuils multi-passerelles', crowdsec: 'CrowdSec', threat: 'Ephor', manual: 'Manuel' };
  const colors = { native: 'var(--text3)', fleet: 'var(--blue)', crowdsec: 'var(--purple)', threat: 'var(--red)', manual: 'var(--yellow)' };
  return Object.entries(counts)
    .filter(([, c]) => c > 0)
    .sort(([,a],[,b]) => b - a)
    .map(([src, c]) => {
      const pct = Math.round((c / total) * 100);
      return `<div style="margin-bottom:10px">
        <div style="display:flex;justify-content:space-between;font-size:11.5px;margin-bottom:3px">
          <span style="color:var(--text1)">${labels[src]||_secSourceLabel(src)}</span>
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

// ── PAGE PARTAGÉE: Vulnérabilités (vue Parc / vue Liste + tiroir de détail) ───────
// Admin : une carte par passerelle. Passerelle : une carte par backend. Même code, seule
// l'unité de regroupement et la colonne « Passerelle » changent.

const VS_VIEW_KEY = 'gpx_vulns_view';
const _vs = { view: 'parc', sev: '', st: 'open', q: '', gw: '', kevOnly: false, open: null, sel: null, cves: [], mode: 'admin' };
try { _vs.view = localStorage.getItem(VS_VIEW_KEY) === 'list' ? 'list' : 'parc'; } catch (_) {}

function vsSev(score) {
  const s = Number(score) || 0;
  return s >= 9 ? 'crit' : s >= 7 ? 'high' : s >= 4 ? 'med' : 'low';
}

function vsIsOpen(c) { return c.status === 'open'; }

// 100 = rien d'ouvert ; chaque CVE ouverte retire des points selon sa gravité, +8 si exploitée
// activement (KEV) : une CVE exploitée pèse plus que son seul CVSS, quelle que soit sa gravité.
function vsRiskScore(list) {
  let penalty = 0;
  for (const c of list) if (vsIsOpen(c)) {
    const sev = vsSev(c.cvss_score);
    penalty += sev === 'crit' ? 14 : sev === 'high' ? 7 : 3;
    if (c.kev) penalty += 8;
  }
  return Math.max(0, 100 - penalty);
}

// SLA de correction : jours restants (positif) ou de retard (négatif) sur la CVE.
// null si pas de date (ex. CVE fermée sans sla_due_at renvoyé) ou statut non pertinent.
function vsSlaDays(c) {
  if (!c.sla_due_at) return null;
  return Math.ceil((new Date(c.sla_due_at).getTime() - Date.now()) / 86400000);
}
function vsSlaBadge(c) {
  if (c.status !== 'open') return '';
  const days = vsSlaDays(c);
  if (days == null) return '';
  return days < 0
    ? `<span class="tag tag-red vs-sla-badge">${esc(t('security.vs.sla_overdue', { n: -days }))}</span>`
    : `<span class="tag tag-neutral vs-sla-badge">${esc(t('security.vs.sla_due', { n: days }))}</span>`;
}
function vsKevBadge(c) {
  return c.kev ? `<span class="tag tag-red vs-kev-badge" title="${esc(t('security.vs.kev_full'))}">KEV</span>` : '';
}
function vsEpssHTML(c) {
  return c.epss_score > 0 ? `<span class="vs-epss" title="${esc(t('security.vs.epss_full'))}">${Math.round(c.epss_score * 100)}% EPSS</span>` : '';
}

function vsUnitKey(c) { return _vs.mode === 'admin' ? (c.edge_name || '—') : (c.backend_url || '—'); }
function vsCveKey(c) { return String(c.id); }

function vsFiltered() {
  const q = _vs.q.trim().toLowerCase();
  return _vs.cves.filter(c => {
    if (_vs.st && c.status !== _vs.st) return false;
    if (_vs.sev && vsSev(c.cvss_score) !== _vs.sev) return false;
    if (_vs.gw && (c.edge_name || '—') !== _vs.gw) return false;
    if (_vs.kevOnly && !c.kev) return false;
    if (q && !(`${c.cve_id} ${c.backend_url} ${c.description} ${c.edge_name || ''}`.toLowerCase().includes(q))) return false;
    return true;
  }).sort((a, b) => (b.kev ? 1 : 0) - (a.kev ? 1 : 0) || (b.cvss_score || 0) - (a.cvss_score || 0));
}

function vsSevBar(list) {
  const open = list.filter(vsIsOpen);
  if (!open.length) return '<div class="vs-bar" aria-hidden="true"></div>';
  const seg = ['crit', 'high', 'med', 'low'].map(s => {
    const n = open.filter(c => vsSev(c.cvss_score) === s).length;
    return n ? `<i class="vs-${s}" style="flex:${n}"></i>` : '';
  }).join('');
  return `<div class="vs-bar" aria-hidden="true">${seg}</div>`;
}

function vsRing(score, size) {
  const color = score >= 80 ? 'var(--green)' : score >= 55 ? 'var(--yellow)' : 'var(--red)';
  const inner = size - 12;
  return `<div class="vs-ring" style="--p:${score};--c:${color};width:${size}px;height:${size}px" role="img" aria-label="${esc(t('security.vs.risk'))} ${score}/100" title="${esc(t('security.vs.risk_formula'))}"><div style="width:${inner}px;height:${inner}px"><b>${score}</b></div></div>`;
}

function vsStatusTag(status) {
  const cls = status === 'open' ? 'tag-yellow' : status === 'fixed' ? 'tag-green' : 'tag-neutral';
  const label = t('security.vulns.f_' + status);
  return `<span class="tag ${cls}">${esc(label === 'security.vulns.f_' + status ? status : label)}</span>`;
}

function vsRowHTML(c, showGw) {
  const sev = vsSev(c.cvss_score);
  return `<button type="button" class="vs-row${_vs.sel === vsCveKey(c) ? ' sel' : ''}" onclick="vsSelect('${esc(vsCveKey(c))}')" aria-label="${esc(c.cve_id)}">
    <span class="vs-c-cve mono">${esc(c.cve_id)}${vsKevBadge(c)}</span>
    <span class="vs-c-score"><span class="vs-score vs-${sev}">${(Number(c.cvss_score) || 0).toFixed(1)}</span>${vsEpssHTML(c)}</span>
    <span class="vs-c-be mono" title="${esc(c.backend_url)}">${esc(c.backend_url)}</span>
    ${showGw ? `<span class="vs-c-gw">${esc(c.edge_name || '—')}</span>` : ''}
    <span class="vs-c-desc" title="${esc(c.description)}">${esc(c.description)}</span>
    <span class="vs-c-st">${vsStatusTag(c.status)}${vsSlaBadge(c)}</span>
  </button>`;
}

function vsListHTML(list, showGw) {
  if (!list.length) return `<div class="empty"><p>${esc(t('security.no_cves'))}</p></div>`;
  return `<div class="vs-list${showGw ? ' vs-with-gw' : ''}" role="list">
    <div class="vs-head" aria-hidden="true"><span>CVE</span><span>CVSS</span><span>${esc(t('security.col.backend'))}</span>${showGw ? `<span>${esc(t('security.col.edge'))}</span>` : ''}<span>${esc(t('security.col.description'))}</span><span>${esc(t('security.col.status'))}</span></div>
    ${list.map(c => vsRowHTML(c, showGw)).join('')}
  </div>`;
}

function vsUnits(list) {
  const map = new Map();
  for (const c of list) {
    const k = vsUnitKey(c);
    if (!map.has(k)) map.set(k, []);
    map.get(k).push(c);
  }
  return [...map.entries()].map(([k, l]) => ({ k, l, score: vsRiskScore(l) })).sort((a, b) => a.score - b.score || b.l.length - a.l.length);
}

function vsUnitCardHTML(u) {
  const open = u.l.filter(vsIsOpen);
  const n = s => open.filter(c => vsSev(c.cvss_score) === s).length;
  const kevN = open.filter(c => c.kev).length;
  const expanded = _vs.open === u.k;
  const meta = _vs.mode === 'admin'
    ? t('security.vs.backends_n', { n: new Set(u.l.map(c => c.backend_url)).size })
    : t('security.vs.cves_n', { n: u.l.length });
  return `<button type="button" class="vs-unit" data-unit="${esc(u.k)}" aria-expanded="${expanded}" onclick="window.open(this.dataset.url, '_blank', 'noopener,noreferrer')"> 
    <span class="vs-unit-top">
      <span class="vs-unit-id"><span class="vs-unit-name mono">${esc(u.k)}</span><span class="vs-unit-meta">${esc(meta)}</span></span>
      ${vsRing(u.score, 52)}
    </span>
    ${vsSevBar(u.l)}
    <span class="vs-counts"><span class="vs-crit-t">${n('crit')} ${esc(t('security.vs.s_crit'))}</span><span class="vs-high-t">${n('high')} ${esc(t('security.vs.s_high'))}</span><span class="vs-med-t">${n('med')} ${esc(t('security.vs.s_med'))}</span><span class="vs-low-t">${n('low')} ${esc(t('security.vs.s_low'))}</span>${kevN ? `<span class="vs-kev-t">${kevN} KEV</span>` : ''}</span>
  </button>`;
}

function vsDrawerHTML() {
  const c = _vs.cves.find(x => vsCveKey(x) === _vs.sel);
  if (!c) return `<aside class="vs-drawer" id="vs-drawer" aria-live="polite"><div class="vs-drawer-empty">${esc(t('security.vs.detail_empty'))}</div></aside>`;
  const sev = vsSev(c.cvss_score);
  const slaDays = vsSlaDays(c);
  const rows = [
    [t('security.col.backend'), c.backend_url],
    c.product ? [t('security.vs.application'), `${c.product}${c.version ? ' ' + c.version : ''} (${t(c.source === 'image' ? 'security.vs.app_image' : 'security.vs.app_headers')}). ${t('security.vs.app_hint')}`] : null,
    _vs.mode === 'admin' ? [t('security.col.edge'), c.edge_name || '—'] : null,
    c.epss_score > 0 ? [t('security.vs.epss'), `${(c.epss_score * 100).toFixed(1)} %`] : null,
    c.status === 'open' && slaDays != null ? [t('security.vs.sla_due_label'), slaDays < 0 ? t('security.vs.sla_overdue', { n: -slaDays }) : t('security.vs.sla_due', { n: slaDays })] : null,
    c.published_at ? [t('security.vulns.published'), fmtDate(c.published_at)] : null,
    c.updated_at ? [t('security.vulns.updated'), fmtDate(c.updated_at)] : null,
  ].filter(Boolean);
  return `<aside class="vs-drawer open" id="vs-drawer" aria-live="polite">
    <div class="vs-drawer-head">
      <a class="mono vs-drawer-cve" href="https://nvd.nist.gov/vuln/detail/${esc(c.cve_id)}" target="_blank" rel="noopener">${esc(c.cve_id)}</a>
      <span class="vs-score vs-${sev}">${(Number(c.cvss_score) || 0).toFixed(1)}</span>
      <button type="button" class="btn btn-ghost btn-icon btn-sm vs-drawer-close" onclick="vsSelect(null)" aria-label="${esc(t('common.close'))}">✕</button>
    </div>
    <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">${vsStatusTag(c.status)}${c.kev ? `<span class="vs-drawer-kev">⚠ ${esc(t('security.vs.kev_full'))}</span>` : ''}</div>
    <p class="vs-drawer-desc">${esc(c.description)}</p>
    <dl class="vs-dl">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd class="mono">${esc(v)}</dd>`).join('')}</dl>
    <div class="vs-acts">
      ${c.status !== 'fixed' ? `<button type="button" class="btn btn-primary btn-sm" onclick="vsSetStatus(${Number(c.id)},'fixed')">${esc(t('security.cve_fixed'))}</button>` : ''}
      ${c.status !== 'ignored' ? `<button type="button" class="btn btn-secondary btn-sm" onclick="vsSetStatus(${Number(c.id)},'ignored')">${esc(t('security.cve_ignore'))}</button>` : ''}
      ${c.status !== 'open' ? `<button type="button" class="btn btn-secondary btn-sm" onclick="vsSetStatus(${Number(c.id)},'open')">${esc(t('security.cve_reopen'))}</button>` : ''}
      <a class="btn btn-ghost btn-sm" href="https://nvd.nist.gov/vuln/detail/${esc(c.cve_id)}" target="_blank" rel="noopener">${esc(t('security.vs.nvd'))}</a>
    </div>
  </aside>`;
}

function vsBodyHTML() {
  const list = vsFiltered();
  const showGw = _vs.mode === 'admin';
  if (!list.length) return `<div class="vs-main"><div class="empty"><p>${esc(t('security.no_cves'))}</p></div></div>${vsDrawerHTML()}`;
  if (_vs.view === 'list') {
    return `<div class="vs-main">${vsListHTML(list, showGw)}<div class="vs-hint">${esc(t('security.vs.results', { n: list.length }))}</div></div>${vsDrawerHTML()}`;
  }
  const units = vsUnits(list);
  const opened = units.find(u => u.k === _vs.open);
  return `<div class="vs-main">
      <div class="vs-cards">${units.map(vsUnitCardHTML).join('')}</div>
      ${opened
        ? `<div class="vs-unit-detail card blueprint"><div class="vs-unit-detail-head"><b class="mono">${esc(opened.k)}</b><span class="vs-hint">${esc(t('security.vs.results', { n: opened.l.length }))}</span></div>${vsListHTML(opened.l, false)}</div>`
        : `<div class="vs-hint">${esc(t(showGw ? 'security.vs.hint_parc_admin' : 'security.vs.hint_parc_edge'))}</div>`}
    </div>${vsDrawerHTML()}`;
}

function vsChipsHTML() {
  const open = _vs.cves.filter(vsIsOpen);
  const chips = [['', t('security.vs.f_all'), null], ['crit', t('security.vulns.f_critical'), 'crit'], ['high', t('security.vulns.f_high'), 'high'], ['med', t('security.vs.s_med_full'), 'med'], ['low', t('security.vs.s_low_full'), 'low']];
  const sevChips = chips.map(([k, label, sev]) => {
    const n = sev ? open.filter(c => vsSev(c.cvss_score) === sev).length : null;
    return `<button type="button" class="chip${_vs.sev === k ? ' active' : ''}" aria-pressed="${_vs.sev === k}" onclick="vsSetSev('${k}')">${esc(label)}${n != null ? `<span class="chip-n">${n}</span>` : ''}</button>`;
  }).join('');
  const kevN = open.filter(c => c.kev).length;
  const kevChip = `<button type="button" class="chip${_vs.kevOnly ? ' active' : ''}" aria-pressed="${_vs.kevOnly}" onclick="vsToggleKev()" title="${esc(t('security.vs.kev_full'))}">${esc(t('security.vs.kev'))}<span class="chip-n">${kevN}</span></button>`;
  return sevChips + kevChip;
}

function vsPaint() {
  const body = document.getElementById('vs-body');
  if (body) body.innerHTML = vsBodyHTML();
  const chips = document.getElementById('vs-chips');
  if (chips) chips.innerHTML = vsChipsHTML();
  const scrim = document.getElementById('vs-scrim');
  if (scrim) scrim.classList.toggle('open', !!_vs.sel);
  document.querySelectorAll('.vs-view-btn').forEach(b => {
    const on = b.dataset.view === _vs.view;
    b.classList.toggle('active', on);
    b.setAttribute('aria-pressed', on ? 'true' : 'false');
  });
}

window.vsSetView = function(v) {
  _vs.view = v;
  try { localStorage.setItem(VS_VIEW_KEY, v); } catch (_) {}
  vsPaint();
};
window.vsSetSev = function(v) { _vs.sev = v; vsPaint(); };
window.vsToggleKev = function() { _vs.kevOnly = !_vs.kevOnly; vsPaint(); };
window.vsSetStatusFilter = function(v) { _vs.st = v; vsPaint(); };
window.vsSetGw = function(v) { _vs.gw = v; vsPaint(); };
window.vsSetQuery = function(v) { _vs.q = v; vsPaint(); };
window.vsToggleUnit = function(k) {
  _vs.open = _vs.open === k ? null : k;
  _vs.sel = null;
  vsPaint();
  if (_vs.open) document.querySelector('.vs-unit-detail')?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
};
window.vsSelect = function(id) {
  _vs.sel = id && _vs.sel !== id ? id : (id ? _vs.sel : null);
  vsPaint();
};
window.vsSetStatus = async function(id, status) {
  try {
    await api('PATCH', `/security/cves/${id}`, { status });
    const c = _vs.cves.find(x => Number(x.id) === Number(id));
    if (c) c.status = status;
    toast(t('security.cve_updated'), 'success');
    vsPaint();
    vsPaintKpis();
  } catch (e) { toast(e.message, 'error'); }
};

function vsKpisHTML() {
  const cves = _vs.cves;
  const open = cves.filter(vsIsOpen);
  const crit = open.filter(c => vsSev(c.cvss_score) === 'crit').length;
  const high = open.filter(c => vsSev(c.cvss_score) === 'high').length;
  const kevN = open.filter(c => c.kev).length;
  const overdue = open.filter(c => (vsSlaDays(c) ?? 0) < 0).length;
  const units = new Set(open.map(vsUnitKey)).size;
  const score = vsRiskScore(cves);
  const scoreColor = score >= 80 ? 'var(--green)' : score >= 55 ? 'var(--yellow)' : 'var(--red)';
  return `
    <div class="sec-tile vs-kpi" style="border-left:3px solid var(--red)"><div class="sec-tile-label">${esc(t('security.vulns.kpi_critical'))}</div><div class="sec-tile-value" style="color:${crit ? 'var(--red)' : 'var(--green)'}">${crit}</div><div class="sec-tile-sub">CVSS ≥ 9.0</div></div>
    <div class="sec-tile vs-kpi" style="border-left:3px solid var(--red)" title="${esc(t('security.vs.kev_full'))}"><div class="sec-tile-label">${esc(t('security.vs.kpi_kev'))}</div><div class="sec-tile-value" style="color:${kevN ? 'var(--red)' : 'var(--green)'}">${kevN}</div><div class="sec-tile-sub">${esc(t('security.vs.kpi_kev_sub'))}</div></div>
    <div class="sec-tile vs-kpi" style="border-left:3px solid var(--yellow)"><div class="sec-tile-label">${esc(t('security.vulns.kpi_high'))}</div><div class="sec-tile-value" style="color:${high ? 'var(--yellow)' : 'var(--green)'}">${high}</div><div class="sec-tile-sub">CVSS 7.0 – 8.9</div></div>
    <div class="sec-tile vs-kpi" style="border-left:3px solid var(--accent)"><div class="sec-tile-label">${esc(t('security.vulns.kpi_open'))}</div><div class="sec-tile-value" style="color:${open.length ? 'var(--accent)' : 'var(--green)'}">${open.length}</div><div class="sec-tile-sub">${esc(overdue ? t('security.vs.kpi_open_overdue', { n: overdue }) : t('security.vulns.kpi_open_sub'))}</div></div>
    <div class="sec-tile vs-kpi"><div class="sec-tile-label">${esc(t(_vs.mode === 'admin' ? 'security.vs.kpi_gw' : 'security.vulns.kpi_backends'))}</div><div class="sec-tile-value" style="color:${units ? 'var(--yellow)' : 'var(--green)'}">${units}</div><div class="sec-tile-sub">${esc(t('security.vs.risk'))} <b style="color:${scoreColor}">${score}/100</b></div></div>`;
}

function vsPaintKpis() {
  const el = document.getElementById('vs-kpis');
  if (el) el.innerHTML = vsKpisHTML();
}

async function renderSecurityVulns(ctx) {
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

    const [cvesRaw, vsStateRaw, vsConfigRaw] = await Promise.all([
      api('GET', '/security/cves'),
      api('GET', '/security/vulnscan').catch(() => null),
      api('GET', '/security/vulnscan/config').catch(() => null),
    ]);
    const vsState = filterVulnscanState(vsStateRaw, edgeCtx);
    window._secEdgeCtx = edgeCtx;
    window._secMode = mode;
    window._vsConfig = vsConfigRaw || {};

    const scope = mode + ':' + (edgeCtx?.edgeRef || '');
    if (_vs.scope !== scope) Object.assign(_vs, { scope, sev: '', st: 'open', q: '', gw: '', kevOnly: false, open: null, sel: null });
    _vs.mode = mode;
    _vs.cves = filterSecCVEs(cvesRaw || [], edgeCtx);
    if (_vs.sel && !_vs.cves.some(c => vsCveKey(c) === _vs.sel)) _vs.sel = null;

    const gateways = [...new Set(_vs.cves.map(c => c.edge_name || '—'))].sort();
    const sub = isAdmin
      ? t('security.vs.sub_admin', { n: gateways.length })
      : t('security.vs.sub_edge', { name: esc(edgeCtx?.edgeLabel || '') });
    const lastScan = vsState?.last_scan && vsState.last_scan !== '0001-01-01T00:00:00Z' ? fmtDate(vsState.last_scan) : '';
    const statuses = [['open', t('security.vulns.f_open')], ['fixed', t('security.vulns.f_fixed')], ['ignored', t('security.vulns.f_ignored')], ['', t('security.vs.st_all')]].filter(s => s[1]);

    content.innerHTML = `
      ${securityEdgeBanner(edgeCtx)}
      <div class="vs-page-head">
        <div><h2 class="vs-title">${esc(t('page.' + (isAdmin ? 'security-vulns' : 'edge-security-vulns')))}</h2><div class="vs-sub">${sub}${lastScan ? ` · ${esc(t('security.vulnscan.last_scan'))} ${esc(lastScan)}` : ''}</div></div>
        ${!isAdmin ? `<div class="vs-head-acts">${vsState?.running ? `<span class="tag tag-yellow">${esc(t('security.vulnscan.running'))}</span>` : ''}<button id="vulnscan-btn" class="btn btn-primary btn-sm" onclick="triggerVulnscan()" ${vsState?.running ? 'disabled' : ''}>${esc(t('security.scan_now'))}</button></div>` : ''}
      </div>
      <div class="sec-grid vs-kpis" id="vs-kpis">${vsKpisHTML()}</div>
      <div class="vs-toolbar">
        <div class="vs-view" role="group" aria-label="${esc(t('security.vs.view'))}">
          <button type="button" class="vs-view-btn" data-view="parc" onclick="vsSetView('parc')">${esc(t('security.vs.view_parc'))}</button>
          <button type="button" class="vs-view-btn" data-view="list" onclick="vsSetView('list')">${esc(t('security.vs.view_list'))}</button>
        </div>
        <input type="search" class="input vs-search" id="vs-q" placeholder="${esc(t('security.vs.search_ph'))}" aria-label="${esc(t('security.vs.search_ph'))}" value="${esc(_vs.q)}" oninput="vsSetQuery(this.value)">
        <select class="input vs-select" id="vs-st" aria-label="${esc(t('security.col.status'))}" onchange="vsSetStatusFilter(this.value)">${statuses.map(([v, l]) => `<option value="${v}" ${_vs.st === v ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select>
        ${isAdmin ? `<select class="input vs-select" id="vs-gw" aria-label="${esc(t('security.col.edge'))}" onchange="vsSetGw(this.value)"><option value="">${esc(t('security.vs.all_gw'))}</option>${gateways.map(g => `<option ${_vs.gw === g ? 'selected' : ''}>${esc(g)}</option>`).join('')}</select>` : ''}
        <div class="vs-chips" id="vs-chips">${vsChipsHTML()}</div>
      </div>
      <div class="vs-split" id="vs-body">${vsBodyHTML()}</div>
      <div class="vs-scrim${_vs.sel ? ' open' : ''}" id="vs-scrim" onclick="vsSelect(null)"></div>

      ${!isAdmin ? `<details class="card blueprint vs-scanner">
        <summary>${esc(t('security.scanner_title'))}</summary>
        <div class="card-body" id="vulnscan-body">${vulnscanPanelV2(vsState, window._vsConfig, true)}</div>
      </details>` : ''}`;

    vsPaint();
    if (!isAdmin) loadVulnscanCoverage();
    if (!isAdmin && vsState?.running) startVulnscanPoll();
  } catch(e) { toast(e.message,'error'); }
}

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
          <thead><tr><th>${t('security.col.backend')}</th><th>${t('security.col.status')}</th><th>${t('security.vulnscan.col.detected')}</th><th>CVEs</th></tr></thead>
          <tbody>${results.map(r => `<tr>
            <td class="mono" style="font-size:11px;max-width:260px;word-break:break-all">${esc(r.url||'')}</td>
            <td><span style="color:${vulnscanStatusColor(r.status)};font-size:12px">${esc(vulnscanStatusLabel(r.status))}</span>${r.error?`<div style="font-size:10px;color:var(--text3);max-width:180px;overflow:hidden;text-overflow:ellipsis" title="${esc(r.error)}">${esc(r.error)}</div>`:''}</td>
            <td style="font-size:11px;color:var(--text2)">${[...(r.apps||[]), ...(r.headers||[])].length?[...(r.apps||[]), ...(r.headers||[])].map(h=>`<span class="tag tag-neutral" style="font-size:10px;margin:1px">${esc(h)}</span>`).join(' '):'—'}</td>
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
    <div id="vulnscan-coverage"></div>
    ${configBlock}
  </div>`;
}

// Ce que la recherche de CVE ne peut pas traiter dans l'inventaire des applications, et pourquoi (ADR 0017). Lu sur les passerelles,
// gardé 30 s : le panneau se redessine pendant un scan.
async function loadVulnscanCoverage() {
  const box = document.getElementById('vulnscan-coverage');
  if (!box) return;
  if (!window._vsCov || Date.now() - window._vsCov.at > 30000) {
    try {
      const r = await api('GET', '/security/inventory');
      window._vsCov = { at: Date.now(), cov: r && r.coverage };
    } catch { return; }
  }
  const cov = window._vsCov.cov;
  if (!cov || !cov.total || !document.getElementById('vulnscan-coverage')) { box.innerHTML = ''; return; }
  const gaps = cov.gaps || [];
  const rows = gaps.map(g => `<tr>
      <td class="mono" style="font-size:11px;word-break:break-all">${esc(g.name)}</td>
      <td style="font-size:12px">${esc(t('security.vs.cov_reason.' + g.reason))}</td>
      <td class="mono" style="font-size:11px;color:var(--text2);word-break:break-all">${esc(g.evidence || '')}</td>
      <td style="font-size:11px;color:var(--text2)">${esc((g.hosts || []).join(', '))}</td>
    </tr>`).join('');
  box.innerHTML = `<details style="margin-top:12px">
    <summary style="cursor:pointer;font-size:12px;color:var(--text2);user-select:none">${esc(t('security.vs.cov_title', { covered: cov.covered, total: cov.total }))}</summary>
    ${gaps.length ? `<p style="font-size:12px;color:var(--text2);margin:8px 0">${esc(t('security.vs.cov_help'))}</p>
    <div class="table-wrap"><table>
      <thead><tr><th>${esc(t('security.vs.cov_col_name'))}</th><th>${esc(t('security.vs.cov_col_reason'))}</th><th>${esc(t('security.vs.cov_col_evidence'))}</th><th>${esc(t('security.col.backend'))}</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>` : `<p style="font-size:12px;color:var(--text2);margin:8px 0">${esc(t('security.vs.cov_none'))}</p>`}
  </details>`;
}

async function renderSecurityPosture(ctx) {
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

    const ovData = await api('GET', '/security/overview');
    const headers = filterSecHeaders(ovData?.overview?.headers || [], edgeCtx);
    content.innerHTML = `
      ${securityEdgeBanner(edgeCtx)}
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

pages['security-vulns'] = () => renderSecurityVulns({ mode: 'admin' });
pages['security-posture'] = () => renderSecurityPosture({ mode: 'admin' });
// security-rules : liste des flux à condition ou événement (automation-lists.js).

pages['edge-security-vulns'] = () => renderSecurityVulns({ mode: 'edge' });
pages['edge-security-posture'] = () => renderSecurityPosture({ mode: 'edge' });
pages['security-ephor'] = () => renderEphorDashboard({ mode: 'admin' });
pages['edge-security-ephor'] = () => renderEphorDashboard({ mode: 'edge' });

function secProxyCountLabel(n, total) {
  const suffix = n === 1 ? t('security.proxy_count', { n }) : t('security.proxy_count_n', { n });
  return total != null && n !== total ? `${suffix} / ${total}` : suffix;
}

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
        ⚠️ Ces valeurs sont sauvegardées dans <code>edge.json</code> — un <strong>redémarrage de la passerelle</strong> est nécessaire pour les appliquer.
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
    await api('PUT', `/security/server-config${window._secEdgeQ || ''}`, cfg);
    window._serverCfg = cfg;
    toast('Timeouts sauvegardés — redémarrez la passerelle pour les appliquer', 'success');
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

function _threatDate(th) { return th.last_seen_at || th.created_at; }

function filterSecThreatsList(threats) {
  const q = (window._secThreatsQ || '').trim().toLowerCase();
  const type = window._secThreatsType || '';
  const sort = window._secThreatsSort || 'date_desc';
  let list = [...(threats || [])];

  if (q) {
    list = list.filter(th => {
      const hay = `${th.ip || ''} ${th.scenario || ''} ${th.origin || ''} ${th.type || ''} ${th.edge_name || ''}`.toLowerCase();
      return hay.includes(q);
    });
  }
  if (type) list = list.filter(th => (th.type || '') === type);

  list.sort((a, b) => {
    if (sort === 'ip_asc') return _secLocaleCompare(a.ip, b.ip);
    if (sort === 'ip_desc') return _secLocaleCompare(b.ip, a.ip);
    if (sort === 'scenario') return _secLocaleCompare(a.scenario, b.scenario) || _secLocaleCompare(a.ip, b.ip);
    if (sort === 'edge') return _secLocaleCompare(a.edge_name, b.edge_name) || _secLocaleCompare(a.ip, b.ip);
    if (sort === 'occurrences') return (b.occurrences||0) - (a.occurrences||0) || _secLocaleCompare(a.ip, b.ip);
    if (sort === 'date_asc') {
      const da = Date.parse(_threatDate(a)) || 0, db = Date.parse(_threatDate(b)) || 0;
      return da - db || _secLocaleCompare(a.ip, b.ip);
    }
    const da = Date.parse(_threatDate(a)) || 0, db = Date.parse(_threatDate(b)) || 0;
    return db - da || _secLocaleCompare(a.ip, b.ip);
  });
  return list;
}

function _secSourceLabel(source) {
  if (!source) return '—';
  if (source.startsWith('plugin:') && source.length > 7) return source[7].toUpperCase() + source.slice(8);
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
      ${_secBansChip(source, 'fleet', t('security.source.fleet'), "setSecBansSource('fleet')")}
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
        <option value="edge" ${sort==='edge'?'selected':''}>${t('security.col.edge')||'Passerelle'}</option>
        <option value="occurrences" ${sort==='occurrences'?'selected':''}>${t('security.col.occurrences')||'Occurrences'}</option>
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
        ${trBtn(b.ip)}
        <button type="button" class="btn btn-ghost btn-icon btn-sm" onclick="showBanHistory('${esc(b.ip)}')" title="${esc(t('security.ban_history'))}" aria-label="${esc(t('security.ban_history'))}"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg></button>
        ${b.expires_at ? `<button type="button" class="btn btn-ghost btn-icon btn-sm" onclick="makeBanPermanent('${esc(String(b.id))}','${esc(b.ip)}')" title="${esc(t('security.ban_make_permanent'))}" aria-label="${esc(t('security.ban_make_permanent'))}"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg></button>` : ''}
        <button type="button" class="btn btn-ghost btn-icon btn-sm" onclick="deleteBan('${esc(String(b.id))}','${esc(b.ip)}')" title="${esc(t('security.unban'))}" aria-label="${esc(t('security.unban'))}" style="color:var(--red)"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/><path d="M12 16v2"/></svg></button>
      </td>
    </tr>`).join('')}</tbody>
  </table></div>`;
}

function threatsTableRows(list, showEdge) {
  if (!list.length) {
    const emptyKey = (window._secThreats || []).length ? 'security.no_threat_filter_match' : 'security.no_crowdsec';
    return `<div class="empty"><p>${t(emptyKey)}</p></div>`;
  }
  const _tsort = window._secThreatsSort || 'date_desc';
  const _tthStyle = 'cursor:pointer;user-select:none;white-space:nowrap';
  const _tind = (col, asc, desc) => {
    const active = _tsort === asc || _tsort === desc || _tsort === col;
    const arrow = _tsort === asc ? ' ↑' : (_tsort === desc || _tsort === col) ? ' ↓' : '';
    return { attr: `onclick="setSecThreatsSortCol('${col}')" style="${_tthStyle}${active?';color:var(--accent)':''}" title="${t('common.sort')||'Trier'}"`, arrow };
  };
  const ip = _tind('ip', 'ip_asc', 'ip_desc');
  const scenario = _tind('scenario', 'scenario', 'scenario');
  const edge = _tind('edge', 'edge', 'edge');
  const occ = _tind('occurrences', 'occurrences', 'occurrences');
  const date = _tind('date', 'date_asc', 'date_desc');
  return `<div class="table-wrap sec-bans-table-scroll"><table>
    <thead><tr>
      <th ${ip.attr}>${t('logs.ip')}${ip.arrow}</th>
      <th ${scenario.attr}>${t('security.col.scenario')}${scenario.arrow}</th>
      <th>${t('security.col.origin')}</th>
      <th>${t('security.col.type')}</th>
      ${showEdge ? `<th ${edge.attr}>${t('security.col.edge')||'Passerelle'}${edge.arrow}</th>` : ''}
      <th ${occ.attr}>${t('security.col.occurrences')||'Occurrences'}${occ.arrow}</th>
      <th ${date.attr}>${t('common.date')}${date.arrow}</th>
    </tr></thead>
    <tbody>${list.map(th => `<tr>
      <td class="mono">${esc(th.ip)} ${trBtn(th.ip)}</td>
      <td style="font-size:12px">${esc(th.scenario||'—')}</td>
      <td style="font-size:12px">${esc(th.origin||'—')}</td>
      <td><span class="tag tag-red">${esc(th.type)}</span></td>
      ${showEdge ? `<td style="font-size:12px;color:var(--text2)">${esc(th.edge_name||'—')}</td>` : ''}
      <td style="font-size:12px;text-align:center">${th.occurrences||1}</td>
      <td style="font-size:11px">${_threatDate(th) ? fmtDate(_threatDate(th)) : '—'}</td>
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
  const showEdge = window._secThreatsShowEdge !== false;
  return `${threatsToolbarHTML(all.length, filtered.length, types)}<div id="sec-threats-table">${threatsTableRows(filtered, showEdge)}</div>`;
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
  if (table) table.innerHTML = threatsTableRows(filtered, window._secThreatsShowEdge !== false);
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
window.setSecThreatsSortCol = function(col) {
  const sort = window._secThreatsSort || 'date_desc';
  const ascKey = col === 'ip' ? 'ip_asc' : col === 'date' ? 'date_asc' : col;
  const descKey = col === 'ip' ? 'ip_desc' : col === 'date' ? 'date_desc' : col;
  const isAsc = sort === ascKey;
  window._secThreatsSort = (ascKey === descKey) ? ascKey : (isAsc ? descKey : ascKey);
  renderSecThreatsPanel();
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

// secCheckLabel : libellé localisé d'un contrôle de posture. `key` est un identifiant stable
// (ex. "tls") ajouté par le backend (Admin 0.52.3+) ; les données mises en cache avant cet ajout
// (aucun `key`) retombent sur le nom brut, envoyé en français par le backend.
function secCheckLabel(c) {
  if (!c.key) return c.name;
  const label = t('security.posture.check.' + c.key);
  return label === 'security.posture.check.' + c.key ? c.name : label;
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
        ? `<ul style="margin:0;padding-left:14px;font-size:10px;color:var(--text2);line-height:1.45;">${missing.map(c => `<li>${esc(secCheckLabel(c))}</li>`).join('')}</ul>`
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

function fleetPanel(cfg) {
  if (!cfg) return '<p style="color:var(--text2);font-size:12px;margin:0">' + t('common.not_available') + '</p>';
  return `<form onsubmit="saveFleetConfig(event)">
    <div class="sec-bans-engine-fields">
      <div class="field" style="margin:0">
        <label class="field-label">${t('security.fleet.window')}</label>
        <input id="fleet-window" type="number" class="input" value="${cfg.window_sec||300}" min="60" max="3600">
      </div>
      <div class="field" style="margin:0">
        <label class="field-label">${t('security.fleet.max_errors')}</label>
        <input id="fleet-max" type="number" class="input" value="${cfg.max_errors||20}" min="1" max="1000">
      </div>
      <div class="field" style="margin:0">
        <label class="field-label">${t('security.fleet.ban_duration')}</label>
        <input id="fleet-dur" type="number" class="input" value="${cfg.ban_duration_sec??0}" min="0" title="${esc(t('security.fleet.ban_duration_hint'))}">
      </div>
    </div>
    <label style="display:flex;align-items:center;gap:8px;margin-bottom:8px;font-size:12.5px">
      <input type="checkbox" id="fleet-xff" ${cfg.trust_forwarded_for?'checked':''}>
      <span>${t('security.fleet.trust_xff')}</span>
    </label>
    <div class="field" style="margin-bottom:10px">
      <label class="field-label">${t('security.fleet.whitelist')}</label>
      <textarea id="fleet-whitelist" class="input" rows="2" placeholder="10.0.0.0/8&#10;203.0.113.10">${(cfg.whitelist||[]).join('\n')}</textarea>
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
    inventory: 'var(--green)',
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
        <thead><tr><th>${t('security.col.backend')}</th><th>${t('security.col.status')}</th><th>${t('security.vulnscan.col.detected')}</th><th>CVEs</th></tr></thead>
        <tbody>${results.map(r => `<tr>
          <td class="mono" style="font-size:11px;max-width:280px;word-break:break-all">${esc(r.url||'')}</td>
          <td><span style="color:${vulnscanStatusColor(r.status)};font-size:12px">${esc(vulnscanStatusLabel(r.status))}</span>${r.error ? `<div style="font-size:10px;color:var(--text3);max-width:200px;overflow:hidden;text-overflow:ellipsis" title="${esc(r.error)}">${esc(r.error)}</div>` : ''}</td>
          <td style="font-size:11px;color:var(--text2)">${[...(r.apps||[]), ...(r.headers||[])].length ? [...(r.apps||[]), ...(r.headers||[])].map(h => `<span class="tag tag-neutral" style="font-size:10px;margin:1px">${esc(h)}</span>`).join(' ') : '—'}</td>
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
    if (window._secEdgeCtx) st = filterVulnscanState(st, window._secEdgeCtx);
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
    if (page !== 'security-vulns' && page !== 'edge-security-vulns') {
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

window.saveFleetConfig = async function(e) {
  e.preventDefault();
  const whitelist = (document.getElementById('fleet-whitelist')?.value||'').split('\n').map(s=>s.trim()).filter(Boolean);
  const cfg = {
    enabled: !!(window._fleetCfg?.enabled),
    window_sec: parseInt(document.getElementById('fleet-window')?.value)||300,
    max_errors: parseInt(document.getElementById('fleet-max')?.value)||20,
    ban_duration_sec: (() => { const v = parseInt(document.getElementById('fleet-dur')?.value, 10); return Number.isFinite(v) && v >= 0 ? v : 0; })(),
    trust_forwarded_for: document.getElementById('fleet-xff')?.checked || false,
    whitelist,
  };
  try {
    await api('PUT', '/security/fleet', cfg);
    toast(t('security.ips.saved'), 'success');
    reloadCurrentSecurityPage();
  } catch(err) { toast(err.message, 'error'); }
};

window.saveCrowdSecConfig = async function(e) {
  e.preventDefault();
  const cfg = {
    enabled: !!(window._csCfg?.enabled),
    api_url: document.getElementById('cs-url')?.value.trim() || 'http://localhost:8080',
    api_key: document.getElementById('cs-key')?.value || '',
  };
  try {
    await api('PUT', '/security/crowdsec', cfg);
    toast(t('security.ips.saved'), 'success');
    reloadCurrentSecurityPage();
  } catch(err) { toast(err.message, 'error'); }
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

window.exportBansCSV = function() {
  const edge = window._secMode === 'edge' && window._secEdgeQ ? '&' + window._secEdgeQ.slice(1) : '';
  fetch('/api/v1/security/bans/export?format=csv' + edge, { headers: { 'Authorization': 'Bearer ' + state.token } })
    .then(r => r.blob()).then(blob => {
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'bans-export.csv';
      a.click();
    }).catch(e => toast('Export : ' + e.message, 'error'));
};

window.openBanModal = function() {
  modal(t('security.ban_modal.title'),
    `<div class="field"><label class="field-label">${t('security.ban_modal.ip')}</label><input id="ban-ip" class="input" placeholder="${t('security.ban_modal.ip_ph')}"></div>
     <div id="ban-preview"></div>
     <div class="field"><label class="field-label">${t('security.ban_modal.domain')}</label><input id="ban-domain" class="input" placeholder="${t('security.ban_modal.domain_ph')}"></div>
     <div class="field"><label class="field-label">${t('security.ban_modal.reason')}</label><input id="ban-reason" class="input" placeholder="${t('security.ban_modal.reason_ph')}"></div>
     <div class="field"><label class="field-label">${t('security.ban_modal.expires')}</label><input id="ban-exp" type="datetime-local" class="input"></div>
     <div class="field"><label class="field-label">${t('security.ban_modal.scope')}</label><select id="ban-scope" class="input"><option value="">${esc(t('security.ban_modal.scope_all'))}</option></select></div>`,
    `<button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel')}</button>
     <button class="btn btn-secondary" onclick="previewBan()">${t('security.ban_modal.preview')}</button>
     <button class="btn btn-danger" onclick="submitBan()">${t('security.ban_modal.submit')}</button>`);
  fillBanScopes();
};

// Passerelles et groupes HA proposés pour limiter un ban ; la liste reste réduite à « toutes » si le chargement échoue.
window.fillBanScopes = async function(selId = 'ban-scope') {
  const sel = document.getElementById(selId);
  if (!sel) return;
  const [nodes, groups] = await Promise.all([
    api('GET', '/nodes').catch(() => []),
    api('GET', '/architecture/groups').catch(() => ({})),
  ]);
  const opts = Object.keys(groups || {}).sort().map(g => `<option value="group:${esc(g)}">${esc(t('security.ban_modal.scope_group', { name: g }))}</option>`);
  for (const n of nodes || []) {
    if (n.role === 'edge' && n.node_name) opts.push(`<option value="${esc(n.node_name)}">${esc(n.display_name || n.node_name)}</option>`);
  }
  sel.insertAdjacentHTML('beforeend', opts.join(''));
};

// Mesure ce qu'un ban couperait (trafic récent, bans et profils qui recoupent la cible, risques)
// avant de le créer.
window.previewBan = async function() {
  const ip = document.getElementById('ban-ip')?.value.trim();
  const box = document.getElementById('ban-preview');
  if (!box) return;
  if (!ip) { toast(t('security.ban_ip_required'), 'error'); return; }
  box.innerHTML = '<div style="font-size:12.5px;color:var(--text3);margin-bottom:10px">…</div>';
  try {
    const r = await api('GET', '/security/bans/preview?ip=' + encodeURIComponent(ip));
    const warns = (r.warnings || []).map(w => `<li>${esc(w)}</li>`).join('');
    box.innerHTML = `<div style="font-size:12.5px;line-height:1.5;padding:8px 10px;border:1px solid var(--border);border-radius:6px;margin-bottom:10px">
      <strong>${esc(t('security.ban_modal.preview_title', { target: r.target, addresses: Math.round(r.addresses) }))}</strong><br>
      ${esc(t('security.ban_modal.preview_traffic', { hours: r.hours, requests: r.requests, ips: r.ips, blocked: r.blocked, ok: r.ok_requests, okips: r.ok_ips }))}
      ${warns
        ? `<ul style="margin:6px 0 0 16px;padding:0;color:var(--yellow)">${warns}</ul>`
        : `<div style="color:var(--green);margin-top:4px">${esc(t('security.ban_modal.preview_none'))}</div>`}
    </div>`;
  } catch (e) {
    box.innerHTML = `<div style="font-size:12.5px;color:var(--red);margin-bottom:10px">${esc(e.message)}</div>`;
  }
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
  const scope = document.getElementById('ban-scope')?.value;
  if (scope) body.target_scope = scope;
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
  if (state.selectedEdge) {
    navigate('edge-prism');
    return;
  }
  const edges = window._edgeNodes || [];
  if (edges.length === 1) {
    selectEdge(edges[0], 'edge-prism');
    return;
  }
  if (edges.length > 1) {
    toast('Sélectionnez une passerelle pour ouvrir Prism', 'info');
    navigate('infrastructure');
    return;
  }
  toast(t('logs.prism_need_edge'), 'error');
};

window.showBanHistory = async function(ip) {
  // Récupère la timeline unifiée et le profil WAF en parallèle
  const [events, wafProfile] = await Promise.all([
    api('GET', `/security/ip-timeline?ip=${encodeURIComponent(ip)}`).catch(() => []),
    (async () => {
      const edgeId = state.selectedEdge || window._selectedEdgeId;
      if (!edgeId) return null;
      try {
        const profiles = await edgeProxy(edgeId, 'GET', '/internal/v1/waf/behavior/profiles');
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
          <span style="font-size:12px;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:.06em">Profil WAF Ephor</span>
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
    `<button class="btn btn-primary" onclick="openIPTrace('${esc(ip)}')">${esc(t('trace.open'))} →</button>`,
    true
  );
};

// ── WAF Profils comportementaux ──────────────────────────────────────────────

async function renderWAFBehaviorProfiles(ctx) {
  const el = document.getElementById('content');
  if (!el) return;

  const edgeCtx = ctx?.mode === 'edge' ? ctx : null;
  const edgeId = edgeCtx?.edgeId || window._selectedEdgeId;

  let profiles = {};
  try {
    if (edgeId) {
      profiles = await edgeProxy(edgeId, 'GET', '/internal/v1/waf/behavior/profiles') || {};
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
                  <button class="btn btn-sm" style="color:var(--red)" onclick="deleteWAFBehaviorProfile('${ip}', ${JSON.stringify(edgeId||'')}, ${JSON.stringify(ctx||{})})">Supprimer</button>
                </td>
              </tr>`).join('')}
          </tbody>
        </table>`}
    </div>`;
}

window.deleteWAFBehaviorProfile = async function(ip, edgeId, ctx) {
  try {
    if (edgeId) {
      await edgeProxy(edgeId, 'DELETE', `/internal/v1/waf/behavior/profiles/${encodeURIComponent(ip)}`);
    }
    toast('Profil supprimé', 'success');
    renderWAFBehaviorProfiles(ctx);
  } catch(e) { toast(e.message, 'error'); }
};

pages['edge-security-waf-profiles'] = (ctx) => renderWAFBehaviorProfiles({ ...ctx, mode: 'edge' });

window.updateCVE = async function(id, status) {
  try {
    await api('PATCH', `/security/cves/${id}`, { status });
    toast(t('security.cve_updated'), 'success');
    reloadCurrentSecurityPage();
  } catch(e) { toast(e.message, 'error'); }
};
