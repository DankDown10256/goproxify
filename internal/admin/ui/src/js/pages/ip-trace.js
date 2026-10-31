// Page Traçage IP : parcours complet d'une IP ou d'un CIDR (requêtes, détections, bans, débans)
// sur une longue période. Données : GET /security/ip-trace.

const TR_PAGE = 300;
const TR_PERIODS = { '24h': 1, '7d': 7, '30d': 30, '90d': 90, '365d': 365, all: 0 };
const TR_KIND = {
  activity: { color: 'var(--accent)', icon: '↔' },
  ban: { color: 'var(--red)', icon: '⛔' },
  unban: { color: 'var(--green)', icon: '✓' },
  threat: { color: 'var(--orange,#d97706)', icon: '⚠' },
  system: { color: 'var(--text3)', icon: '•' },
};

const _tr = { target: '', scope: 'ip', period: '30d', node: '', edges: null, from: '', to: '', order: 'desc', data: null, steps: [], loading: false };

function trDay(iso) {
  const opts = { dateStyle: 'full' };
  if (state.timezone) opts.timeZone = state.timezone;
  try { return new Date(iso).toLocaleDateString(typeof gpxBCP47 === 'function' ? gpxBCP47() : 'en-US', opts); } catch { return iso.slice(0, 10); }
}

function trTime(iso) {
  const opts = { timeStyle: 'medium' };
  if (state.timezone) opts.timeZone = state.timezone;
  try { return new Date(iso).toLocaleTimeString(typeof gpxBCP47 === 'function' ? gpxBCP47() : 'en-US', opts); } catch { return iso; }
}

function trDuration(a, b) {
  const s = Math.max(0, Math.round((Date.parse(b) - Date.parse(a)) / 1000));
  if (s < 60) return s + ' s';
  if (s < 3600) return Math.round(s / 60) + ' min';
  return (s / 3600).toFixed(1).replace(/\.0$/, '') + ' h';
}

function trQuery(offset) {
  const q = new URLSearchParams({ target: _tr.target, order: _tr.order, limit: TR_PAGE, offset });
  if (_tr.scope !== 'ip') q.set('scope', _tr.scope);
  if (_tr.node) q.set('node', _tr.node);
  if (_tr.period === 'custom') {
    if (_tr.from) q.set('from', _tr.from);
    if (_tr.to) q.set('to', _tr.to);
  } else if (_tr.period === 'all') {
    q.set('from', '2000-01-01');
  } else {
    q.set('from', new Date(Date.now() - TR_PERIODS[_tr.period] * 864e5).toISOString());
  }
  return '/security/ip-trace?' + q;
}

function trChips(list, color) {
  return (list || []).map(c => `<span class="tr-chip"${color ? ` style="color:${color}"` : ''}>${esc(c.value ?? c)}${c.count != null ? ` <i>×${c.count}</i>` : ''}</span>`).join('');
}

// Le client qui a provoqué le ban : sans lui, « ua », « path » ou « score cumulé » n'expliquent pas qui était visé.
function trUserAgentHTML(ua) {
  if (!ua) return '';
  return `<div class="tr-row tr-ua"><span class="tr-ua-label">${esc(t('trace.ua'))}</span><span class="tr-mono" title="${esc(ua)}">${esc(ua)}</span></div>`;
}

function trStepHTML(s) {
  const k = TR_KIND[s.kind] || TR_KIND.system;
  let title, body = '';
  if (s.kind === 'activity') {
    const b = s.burst;
    title = t('trace.step.activity', { n: b.requests });
    const meta = [];
    if (b.blocked) meta.push(`<b style="color:var(--red)">${t('trace.step.blocked', { n: b.blocked })}</b>`);
    meta.push(trDuration(s.ts, s.end));
    if (b.ip_count > 1) meta.push(t('trace.step.ips', { n: b.ip_count }));
    const st = Object.entries(b.statuses || {}).sort().map(([c, n]) => `${esc(c)} <i>×${n}</i>`).join(' · ');
    body = `<div class="tr-meta">${meta.join(' · ')}${st ? ' · ' + st : ''}</div>
      ${b.ip_count > 1 ? `<div class="tr-row">${trChips(b.ips || [])}${b.ip_count > (b.ips || []).length ? '<span class="tr-chip">…</span>' : ''}</div>` : ''}
      <div class="tr-row">${trChips(b.domains)}</div>
      <div class="tr-row tr-mono">${trChips(b.top_paths)}</div>
      ${b.waf_matches?.length ? `<div class="tr-row">${trChips(b.waf_matches, 'var(--red)')}</div>` : ''}
      ${b.threat_signals?.length ? `<div class="tr-row">${trChips(b.threat_signals, 'var(--orange,#d97706)')}</div>` : ''}`;
  } else {
    title = t('trace.step.' + s.kind);
    const ua = trUserAgentHTML(s.user_agent);
    const src = s.source ? (typeof _secSourceLabel === 'function' ? _secSourceLabel(s.source) : s.source) : '';
    body = `<div class="tr-meta">${[s.ip && `<span class="tr-mono">${esc(s.ip)}</span>`, s.domain && esc(s.domain), src && esc(src), s.occurrences > 1 && `×${s.occurrences}`].filter(Boolean).join(' · ')}</div>
      ${s.reason ? `<div class="tr-row">${esc(s.reason)}</div>` : ''}${ua}${banSignalsDetailHTML(s.signals)}`;
  }
  return `<div class="tr-step"><span class="tr-dot" style="background:${k.color}">${k.icon}</span>
    <div class="tr-card"><div class="tr-head"><b style="color:${k.color}">${esc(title)}</b><time>${esc(trTime(s.ts))}</time></div>${body}</div></div>`;
}

function trTimelineHTML() {
  if (!_tr.steps.length) return `<p class="tr-empty">${esc(t('trace.no_events'))}</p>`;
  let day = '', out = '';
  for (const s of _tr.steps) {
    const d = trDay(s.ts);
    if (d !== day) { day = d; out += `<div class="tr-day">${esc(d)}</div>`; }
    out += trStepHTML(s);
  }
  const more = _tr.data.has_more
    ? `<button class="btn btn-secondary btn-sm" onclick="trLoadMore()">${esc(t('trace.load_more', { n: _tr.data.total_steps - _tr.steps.length }))}</button>` : '';
  return `<div class="tr-line">${out}</div><div style="text-align:center;margin-top:12px">${more}</div>`;
}

function trDaysChart(days) {
  if (!days.length) return '';
  const max = Math.max(...days.map(d => d.requests));
  const bars = days.map(d => {
    const h = Math.max(2, Math.round(d.requests / max * 56));
    const bh = d.blocked ? Math.max(2, Math.round(d.blocked / max * 56)) : 0;
    return `<span class="tr-bar" title="${esc(d.day)} · ${d.requests} req · ${d.blocked} ${esc(t('trace.blocked_short'))}"><i style="height:${h}px"></i>${bh ? `<u style="height:${bh}px"></u>` : ''}</span>`;
  }).join('');
  return `<div class="tr-chart">${bars}</div><div class="tr-axis"><span>${esc(days[0].day)}</span><span>${esc(days[days.length - 1].day)}</span></div>`;
}

function trSummaryHTML() {
  const d = _tr.data, s = d.summary;
  const tile = (v, label, color) => `<div class="bn-kpi"><b style="color:${color || 'var(--text1)'}">${v}</b><span>${esc(label)}</span></div>`;
  const state_ = [
    ...(s.active_bans || []).map(b => `<span class="tr-badge" style="--c:var(--red)" title="${esc([banSignalsText(b.signals), b.user_agent && t('trace.ua') + ' : ' + b.user_agent].filter(Boolean).join(' — '))}">⛔ ${esc(t('trace.state.banned'))} · ${esc(b.ip)}${b.expires_at ? '' : ' · ' + esc(t('trace.state.permanent'))}</span>`),
    ...(s.profiles || []).map(p => `<span class="tr-badge" style="--c:var(--orange,#d97706)">${esc(t('trace.state.profile'))} · ${esc(p.name)} (${esc(p.mode)})</span>`),
  ].join('');
  const list = (title, items, mono, link) => items?.length ? `<div class="tr-list"><h4>${esc(title)}</h4>${items.map(i => `<div><span${mono ? ' class="tr-mono"' : ''}>${link ? `<a href="#" onclick="openIPTrace('${esc(i.value)}');return false">${esc(i.value)}</a>` : esc(i.value)}</span><b>${i.count}</b></div>`).join('')}</div>` : '';
  return `<div class="bn-kpis">
      ${tile(s.requests, t('trace.kpi.requests'))}
      ${tile(s.blocked, t('trace.kpi.blocked'), s.blocked ? 'var(--red)' : '')}
      ${tile(s.ip_count, t('trace.kpi.ips'))}
      ${tile(s.episodes, t('trace.kpi.episodes'))}
      ${tile(`${s.bans} / ${s.unbans}`, t('trace.kpi.bans'), s.bans ? 'var(--orange,#d97706)' : '')}
      ${tile(s.threats, t('trace.kpi.threats'), s.threats ? 'var(--orange,#d97706)' : '')}
    </div>
    <div class="card blueprint" style="padding:16px;margin-bottom:16px">
      <div class="tr-meta" style="margin-bottom:8px">${esc(t('trace.first_seen'))} <b>${esc(fmtDate(s.first_seen))}</b> · ${esc(t('trace.last_seen'))} <b>${esc(fmtDate(s.last_seen))}</b>${d.kind === 'cidr' ? ' · ' + esc(t('trace.kind_cidr')) : ''}${d.scope !== 'ip' ? ' · ' + esc(d.scope_label || '') : ''}</div>
      ${state_ ? `<div class="tr-row" style="margin-bottom:10px">${state_}</div>` : ''}
      ${trDaysChart(s.days || [])}
      <div class="tr-lists">
        ${d.kind === 'cidr' || d.scope !== 'ip' ? list(t('trace.top_ips'), s.top_ips, true, true) : ''}
        ${list(t('trace.top_domains'), s.top_domains)}
        ${list(t('trace.top_paths'), s.top_paths, true)}
        ${list(t('trace.top_waf'), s.waf_matches)}
        ${list(t('trace.top_signals'), s.threat_signals)}
        ${list(t('trace.top_countries'), s.countries)}
      </div>
      ${s.scan_limited ? `<p class="tr-meta" style="color:var(--orange,#d97706);margin-top:10px">${esc(t('trace.scan_limited'))}</p>` : ''}
    </div>`;
}

const TR_SEG = [['24h', '24h'], ['7d', '7d'], ['30d', '30d'], ['90d', '90d'], ['365d', '1y'], ['all', null]];

// Bandeau de filtres (même présentation que les logs) : passerelle, période, cible. Les filtres relancent le parcours quand une cible est saisie.
function trFormHTML() {
  const edges = _tr.edges || [];
  const nodeChip = (v, label) => `<button type="button" class="chip${_tr.node === v ? ' active' : ''}" onclick="trSetNode(this.dataset.n)" data-n="${esc(v)}">${v && typeof nodeColor === 'function' ? `<span class="logs-node-dot" style="background:${nodeColor(v)}"></span>` : ''}${esc(label)}</button>`;
  const nodes = edges.length ? `<div class="logs-node-chips"><span class="logs-node-chips-label">${esc(t('logs.node'))}</span>
      ${edges.map(n => { const v = n.node_name || n.display_name || n.id; return nodeChip(v, n.display_name || n.node_name || n.id); }).join('')}
      ${nodeChip('', t('logs.node_all'))}</div>` : '';
  const seg = TR_SEG.map(([k, label]) => `<button type="button" class="seg-btn${_tr.period === k ? ' active' : ''}" onclick="trPeriod('${k}')">${esc(label || t('lg.q_all'))}</button>`).join('')
    + `<button type="button" class="seg-btn${_tr.period === 'custom' ? ' active' : ''}" onclick="trPeriod('custom')">${esc(t('trace.period.custom'))}</button>`;
  return `<form class="card blueprint logs-filterbar" onsubmit="trSubmit(event)">
    <div class="logs-filter-row">
      <div style="flex:1;min-width:0">${nodes}</div>
      <div class="logs-seg">${seg}</div>
    </div>
    <div class="logs-filter-row" style="margin-top:10px">
      <input id="tr-target" class="input search-input tr-mono" placeholder="${esc(t('trace.placeholder'))}" value="${esc(_tr.target)}" autocomplete="off" spellcheck="false" style="flex:1;max-width:none;min-width:220px">
      <span id="tr-custom" style="display:${_tr.period === 'custom' ? 'inline-flex' : 'none'};gap:6px">
        <input id="tr-from" type="date" class="input" value="${esc(_tr.from)}"><input id="tr-to" type="date" class="input" value="${esc(_tr.to)}">
      </span>
      <button class="btn btn-primary" type="submit">${esc(t('trace.go'))}</button>
    </div>
  </form>`;
}

async function trLoadEdges() {
  if (_tr.edges) return;
  _tr.edges = ((await api('GET', '/nodes').catch(() => [])) || []).filter(n => n.role === 'edge');
}

function trRefilter() {
  _tr.target = document.getElementById('tr-target')?.value.trim() || _tr.target;
  _tr.from = document.getElementById('tr-from')?.value || '';
  _tr.to = document.getElementById('tr-to')?.value || '';
  if (_tr.target) trRun(); else trPaint(`<p class="tr-empty">${esc(t('trace.empty_hint'))}</p>`);
}

window.trSetNode = v => { _tr.node = _tr.node === v ? '' : v; trRefilter(); };

function trPaint(body) {
  const content = document.getElementById('content');
  if (!content) return;
  content.innerHTML = `<div class="tr-page"><p class="tr-meta" style="margin:0 0 10px">${esc(t('trace.subtitle'))}</p>${trFormHTML()}${body}</div>`;
}

// Opérateur de l'adresse (base ASN) : on bascule entre l'IP seule et tout son ASN, sans connaître le CIDR. Absent quand la base ASN n'est pas installée ou ne connaît pas l'adresse.
function trAsnBarHTML() {
  const c = _tr.data.asn_context;
  if (!c || !c.asn) return '';
  const a = c.asn;
  const chip = (scope, label, title) => `<button type="button" class="btn btn-sm ${_tr.scope === scope ? 'btn-primary' : 'btn-secondary'}" onclick="trSetScope('${scope}')" title="${esc(title || '')}">${esc(label)}</button>`;
  const addrs = a.v4_addresses >= 1e6 ? (a.v4_addresses / 1e6).toFixed(1) + ' M' : a.v4_addresses >= 1e3 ? Math.round(a.v4_addresses / 1e3) + ' k' : Math.round(a.v4_addresses);
  return `<div class="card blueprint" style="padding:10px 14px;margin-bottom:12px;display:flex;gap:10px;flex-wrap:wrap;align-items:center;font-size:12.5px">
    <span style="color:var(--text3)">${esc(t('trace.asn.label'))}</span>
    <b>AS${a.asn}</b><span>${esc(a.name)} <span style="opacity:.6">${esc(a.country || '')}</span></span>
    <span style="color:var(--text3)">${a.ranges} plage${a.ranges > 1 ? 's' : ''} · ${addrs} adresses IPv4</span>
    <span style="margin-left:auto;display:inline-flex;gap:6px;flex-wrap:wrap">
      ${chip('ip', t('trace.scope.ip'))}
      ${chip('asn', t('trace.scope.asn'), `AS${a.asn}`)}
      <button type="button" class="btn btn-ghost btn-sm" onclick="openBanAsn('${a.asn}')">${esc(t('trace.asn.ban'))}</button>
    </span></div>`;
}

window.trSetScope = function(scope) {
  _tr.scope = scope;
  trRun();
};

function trPaintResult() {
  const d = _tr.data;
  const order = `<button class="btn btn-ghost btn-sm" onclick="trToggleOrder()">${esc(t(_tr.order === 'desc' ? 'trace.order_desc' : 'trace.order_asc'))}</button>`;
  const widen = d.kind === 'ip' && d.scope === 'ip' && trIsPublic(d.target) ? trRanges(d.target.split('/')[0]).slice(1).map(([l, x]) => `<button type="button" class="btn btn-ghost btn-sm" onclick="openIPTrace('${esc(x)}')">${esc(t('trace.widen'))} ${esc(l)}</button>`).join('') : '';
  trPaint(`<h3 class="tr-title"><span class="tr-mono">${esc(d.scope !== 'ip' && d.scope_label ? d.scope_label : d.target)}</span> ${widen}</h3>${trAsnBarHTML()}${trSummaryHTML()}
    <div class="card blueprint" style="padding:16px"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <h4 style="margin:0">${esc(t('trace.timeline'))} <span class="tr-meta">(${d.total_steps})</span></h4>${order}</div>${trTimelineHTML()}</div>`);
}

async function trRun() {
  trPaint(`<p style="color:var(--text2)">${esc(t('common.loading'))}</p>`);
  try {
    _tr.data = await api('GET', trQuery(0));
    _tr.steps = _tr.data.steps;
    trPaintResult();
  } catch (e) {
    toast(e.message, 'error');
    if (_tr.scope !== 'ip' && _tr.data) { _tr.scope = 'ip'; return trPaintResult(); }
    trPaint('');
  }
}

window.trSubmit = function(ev) {
  ev.preventDefault();
  _tr.target = document.getElementById('tr-target').value.trim();
  _tr.scope = 'ip';
  _tr.from = document.getElementById('tr-from')?.value || '';
  _tr.to = document.getElementById('tr-to')?.value || '';
  if (_tr.target) trRun();
};

window.trPeriod = function(v) {
  _tr.period = v;
  if (v === 'custom') {
    trRefilterPaint();
    return;
  }
  trRefilter();
};

function trRefilterPaint() {
  _tr.target = document.getElementById('tr-target')?.value.trim() || _tr.target;
  if (_tr.data) trPaintResult(); else trPaint('');
}

window.trToggleOrder = function() {
  _tr.order = _tr.order === 'desc' ? 'asc' : 'desc';
  trRun();
};

window.trLoadMore = async function() {
  try {
    const more = await api('GET', trQuery(_tr.steps.length));
    _tr.steps = _tr.steps.concat(more.steps);
    _tr.data = { ...more, summary: _tr.data.summary, steps: _tr.steps };
    trPaintResult();
  } catch (e) { toast(e.message, 'error'); }
};

// Ouvre le parcours d'une IP/CIDR depuis une autre page (liste des bans, historique d'une IP).
window.openIPTrace = function(target, period, scope) {
  window._traceInit = { target, period, scope };
  closeModal?.();
  navigate('security-trace');
};

pages['security-trace'] = async () => {
  await trLoadEdges();
  const ta = document.getElementById('topbar-actions');
  if (ta) ta.innerHTML = '';
  const init = window._traceInit;
  window._traceInit = null;
  if (init?.target) {
    Object.assign(_tr, { target: init.target, scope: init.scope || 'ip', period: init.period || '90d' });
    return trRun();
  }
  if (_tr.data) return trPaintResult();
  trPaint(`<p class="tr-empty">${esc(t('trace.empty_hint'))}</p>`);
};

// ── Raccourci « Analyser » depuis les pages qui affichent des IP ─────────────────

// Adresse (ou base d'un CIDR) publique : les plages privées, loopback, link-local, CGNAT et
// documentation n'ont rien à tracer côté attaquant.
function trIsPublic(target) {
  const ip = String(target || '').split('/')[0].trim();
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const [a, b] = [+m[1], +m[2]];
    if ([+m[1], +m[2], +m[3], +m[4]].some(n => n > 255)) return false;
    return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
      (a === 192 && b === 0 && +m[3] <= 2) || (a === 198 && (b === 18 || b === 19)));
  }
  if (!ip.includes(':') || !/^[0-9a-f:.]+$/i.test(ip)) return false;
  const l = ip.toLowerCase();
  return !(l === '::' || l === '::1' || /^f[cdef]/.test(l) || l.startsWith('2001:db8'));
}

// Plages proposées autour d'une IP : [libellé, cible].
function trRanges(ip) {
  const m = ip.match(/^(\d+)\.(\d+)\.(\d+)\.\d+$/);
  if (m) return [[ip, ip], [`${m[1]}.${m[2]}.${m[3]}.0/24`, `${m[1]}.${m[2]}.${m[3]}.0/24`], [`${m[1]}.${m[2]}.0.0/16`, `${m[1]}.${m[2]}.0.0/16`]];
  const [head, tail = ''] = ip.split('::');
  const g = head.split(':').filter(Boolean);
  const rest = tail.split(':').filter(Boolean);
  if (ip.includes('::')) while (g.length + rest.length < 8) g.push('0');
  const full = ip.includes('::') ? g.concat(rest) : head.split(':');
  const pre = n => full.slice(0, n).join(':') + '::/' + n * 16;
  return [[ip, ip], [pre(4), pre(4)], [pre(3), pre(3)]];
}

function trBtn(target, cls = 'btn btn-ghost btn-icon btn-sm') {
  if (!trIsPublic(target)) return '';
  const label = t('trace.analyze');
  return `<button type="button" class="${cls}" onclick="openIPTrace('${esc(target)}')" title="${esc(label)}" aria-label="${esc(label)}"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg></button>`;
}
