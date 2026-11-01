// Page Bans, partagée entre l'admin (toutes les passerelles) et le menu d'une passerelle.
// ctx = { mode: 'admin'|'edge' }. Le mode edge verrouille la passerelle : les bans d'une passerelle et les
// bans globaux sont demandés au serveur (?edge=…) et la colonne Passerelle est remplacée par le domaine.

const BN_TABS = ['actifs', 'historique', 'crowdsec'];
const BN_TAB_LABELS = { actifs: 'Actifs', historique: 'Historique', crowdsec: 'CrowdSec' };
const BN_PAGE = 50;
const BN_SRC_COLORS = { fleet: 'var(--orange,#d97706)', crowdsec: 'var(--blue,#3b82f6)', threat: 'var(--purple,#8b5cf6)', rules_engine: 'var(--accent)', native: 'var(--text3)' };

const _bn = {
  mode: 'admin', edgeCtx: null, tab: 'actifs',
  edgeNames: new Map(), bans: [], history: [], kpis: {}, timeline: [], byReason: [], countries: [], rec: new Map(),
  q: '', src: '', exp: '', edge: '', sort: 'created_desc', shown: BN_PAGE, sel: new Set(), showAsn: false,
};

const BN_ICONS = {
  prism: '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
  history: '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
  extend: '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/>',
  permanent: '<polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>',
  unban: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/><path d="M12 16v2"/>',
};

function bnIcon(name, onclick, title, extra = '') {
  return `<button type="button" class="btn btn-ghost btn-icon btn-sm" ${extra} onclick="${onclick}" title="${esc(title)}" aria-label="${esc(title)}"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">${BN_ICONS[name]}</svg></button>`;
}

// SQLite renvoie parfois « YYYY-MM-DD HH:MM:SS » (UTC, sans fuseau) : sans normalisation, JS l'interprète en heure locale.
function bnTime(s) {
  if (!s) return null;
  const v = /^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$/.test(s) ? s.replace(' ', 'T') + 'Z' : s;
  const ms = Date.parse(v);
  return Number.isNaN(ms) ? null : ms;
}

const bnExpiry = b => bnTime(b.expires_at);
const bnEdge = name => _bn.edgeNames.get(name) || name;
const bnScopeLabel = scope => scope.startsWith('group:') ? t('security.ban_modal.scope_group', { name: scope.slice(6) }) : bnEdge(scope);
const bnScopeTag = b => b.target_scope
  ? ` <span class="tag tag-yellow" title="${esc(t('security.ban_scope_title', { scope: bnScopeLabel(b.target_scope) }))}">→ ${esc(bnScopeLabel(b.target_scope))}</span>` : '';
const bnSrc = b => { const s = String(b.source || 'native'); return s.startsWith('plugin:') ? s : s.split(':')[0]; };
const bnSrcColor = k => BN_SRC_COLORS[k] || (k.startsWith('plugin:') ? 'var(--red)' : 'var(--text3)');

function bnRemaining(ms) {
  if (ms <= 0) return 'expiré';
  const min = Math.ceil(ms / 60000);
  if (min < 60) return `${min} min`;
  const h = Math.floor(min / 60);
  if (h < 48) return `${h} h ${String(min % 60).padStart(2, '0')}`;
  return `${Math.floor(h / 24)} j`;
}

function bnTtlCell(b) {
  const exp = bnExpiry(b);
  if (exp == null) return '<span class="tag tag-red">Permanent</span>';
  const left = exp - Date.now();
  const total = exp - (bnTime(b.created_at) || exp);
  const pct = total > 0 ? Math.max(0, Math.min(100, Math.round(left / total * 100))) : 0;
  const soon = left <= 3600000;
  return `<div style="display:flex;flex-direction:column;gap:4px;min-width:84px" title="${esc(fmtDate(b.expires_at))}">
    <span style="font-size:12px;${soon ? 'color:var(--yellow);font-weight:600' : ''}">${bnRemaining(left)}</span>
    <span class="bn-bar" style="width:70px"><i style="width:${pct}%;background:${soon ? 'var(--red)' : 'var(--yellow)'}"></i></span></div>`;
}

// ── Chargement ────────────────────────────────────────────────────────────────

async function bnLoad(mode) {
  const edgeCtx = await resolveSecurityEdgeCtx(mode);
  if (mode === 'edge' && edgeCtx?.missing) return { edgeCtx };
  const q = edgeCtx?.edgeRef ? 'edge=' + encodeURIComponent(edgeCtx.edgeRef) : '';
  window._secMode = mode;
  window._secEdgeQ = q ? '?' + q : '';
  const url = base => q ? `${base}${base.includes('?') ? '&' : '?'}${q}` : base;
  const [nodes, bans, history, threats, kpis, byReason, timeline, countries, topIPs] = await Promise.all([
    api('GET', '/nodes').catch(() => []),
    api('GET', url('/security/bans?active=true')),
    api('GET', url('/security/bans?active=false')).catch(() => []),
    api('GET', '/security/threats?limit=300').catch(() => []),
    api('GET', url('/security/bans/intel/kpis')).catch(() => ({})),
    api('GET', url('/security/bans/intel/by-reason')).catch(() => []),
    api('GET', url('/security/bans/intel/timeline?hours=48')).catch(() => []),
    api('GET', url('/security/bans/countries')).catch(() => []),
    api('GET', url('/security/bans/intel/top-ips?limit=100')).catch(() => []),
  ]);
  window._secThreats = threats || [];
  window._secThreatsShowEdge = mode === 'admin';
  return {
    edgeCtx,
    edgeNames: new Map((nodes || []).filter(n => n.node_name && n.display_name).map(n => [n.node_name, n.display_name])),
    bans: filterSecBans(bans || [], edgeCtx),
    history: filterSecBans(history || [], edgeCtx),
    kpis: kpis || {}, byReason: byReason || [], timeline: timeline || [], countries: countries || [],
    rec: new Map((topIPs || []).filter(e => e.total_bans >= 3).map(e => [e.ip, e.total_bans])),
  };
}

// ── Filtrage et tri ───────────────────────────────────────────────────────────

function bnFiltered() {
  const { q, src, exp, edge, sort } = _bn;
  const now = Date.now();
  const needle = q.trim().toLowerCase();
  const list = _bn.bans.filter(b => {
    if (b.asn && !_bn.showAsn) return false;
    if (src && bnSrc(b) !== src) return false;
    if (edge && (b.edge_name || '') !== (edge === '__global' ? '' : edge)) return false;
    const e = bnExpiry(b);
    if (exp === 'permanent' && e != null) return false;
    if (exp === 'temporary' && e == null) return false;
    if (exp === 'soon' && !(e != null && e - now <= 3600000)) return false;
    if (exp === 'recurring' && !_bn.rec.has(b.ip)) return false;
    if (needle && !`${b.ip} ${b.domain || ''} ${b.reason || ''} ${b.edge_name || ''} ${bnEdge(b.edge_name || '')}`.toLowerCase().includes(needle)) return false;
    return true;
  });
  const [col, dir] = sort.split('_');
  const key = {
    ip: b => b.ip, source: b => bnSrc(b), edge: b => b.edge_name || '',
    expires: b => bnExpiry(b) ?? Infinity, created: b => bnTime(b.created_at) || 0,
  }[col];
  const sign = dir === 'asc' ? 1 : -1;
  return list.sort((a, b) => {
    const x = key(a), y = key(b);
    return (x < y ? -1 : x > y ? 1 : 0) * sign;
  });
}

// ── Sections d'analyse ────────────────────────────────────────────────────────

function bnKpisHTML() {
  const bans = _bn.bans, now = Date.now();
  const soon = bans.filter(b => { const e = bnExpiry(b); return e != null && e > now && e - now <= 3600000; }).length;
  const perm = bans.filter(b => bnExpiry(b) == null).length;
  const rec = _bn.kpis.recurring_ips ?? _bn.rec.size;
  const rot = _bn.kpis.rotation_ratio != null ? Math.round(_bn.kpis.rotation_ratio * 100) + ' %' : '—';
  const tile = (v, label, color, filter) => `<div class="bn-kpi"${filter ? ` style="cursor:pointer" onclick="bnSetExp('${filter}')" title="Filtrer la liste"` : ''}>
    <b style="color:${color}">${v}</b><span>${label}</span></div>`;
  return `<div class="bn-kpis">
    ${tile(bans.length, 'Bans actifs', bans.length ? 'var(--red)' : 'var(--green)')}
    ${tile(soon, 'Expirent sous 1 h', soon ? 'var(--yellow)' : 'var(--text3)', 'soon')}
    ${tile(perm, 'Permanents', 'var(--text1)', 'permanent')}
    ${tile(rec, 'Récidivistes (≥ 3 bans)', rec ? 'var(--orange,#d97706)' : 'var(--text1)', 'recurring')}
    ${tile(rot, 'Ratio déban / ban', 'var(--text1)')}</div>`;
}

function bnTimelineHTML() {
  const hours = 48;
  const counts = new Map(_bn.timeline.map(e => [String(e.hour).slice(0, 13), e.count]));
  const series = [];
  for (let i = hours - 1; i >= 0; i--) {
    const key = new Date(Date.now() - i * 3600000).toISOString().slice(0, 13);
    series.push({ key, n: counts.get(key) || 0 });
  }
  const total = series.reduce((s, x) => s + x.n, 0);
  if (!total) return '<span style="font-size:12px;color:var(--text3)">Aucun ban sur les dernières 48 heures.</span>';
  const max = Math.max(...series.map(x => x.n), 3);
  const W = 480, H = 110, top = 6, bw = W / hours;
  const grid = [0, .5, 1].map(f => {
    const y = top + (H - top) * (1 - f);
    return `<line x1="0" y1="${y}" x2="${W}" y2="${y}" stroke="var(--border)" stroke-width="1"/>
      <text x="${W + 4}" y="${y + 3}" font-size="9" fill="var(--text3)">${Math.round(max * f)}</text>`;
  }).join('');
  const bars = series.map((x, i) => {
    const h = x.n ? Math.max(2, (H - top) * x.n / max) : 0;
    return `<rect x="${(i * bw + 1).toFixed(1)}" y="${(H - h).toFixed(1)}" width="${(bw - 2).toFixed(1)}" height="${h.toFixed(1)}" rx="1.5" fill="var(--red)" opacity=".85"><title>${x.key.slice(11)}h · ${x.n} ban${x.n > 1 ? 's' : ''}</title></rect>`;
  }).join('');
  return `<svg viewBox="0 0 ${W + 24} ${H + 16}" style="width:100%;height:auto;display:block" role="img" aria-label="Bans par heure sur 48 heures, ${total} au total">
    ${grid}${bars}
    <text x="0" y="${H + 12}" font-size="9" fill="var(--text3)">−48 h</text>
    <text x="${W / 2}" y="${H + 12}" font-size="9" fill="var(--text3)" text-anchor="middle">−24 h</text>
    <text x="${W}" y="${H + 12}" font-size="9" fill="var(--text3)" text-anchor="end">maintenant</text></svg>`;
}

// rows : [{ label, n, color, onclick? }] ; barres proportionnelles au maximum.
function bnRankHTML(rows, empty) {
  if (!rows.length) return `<span style="font-size:12px;color:var(--text3)">${empty}</span>`;
  const max = Math.max(...rows.filter(r => !r.sep).map(r => r.n), 1);
  return rows.map(r => {
    if (r.sep) return `<div class="prism-toprow-sep" style="margin:6px 2px 2px">${esc(r.label)}</div>`;
    const inner = `<span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text2)" title="${esc(r.label)}">${esc(r.label)}</span>
      <span class="bn-bar"><i style="width:${Math.round(r.n / max * 100)}%;background:${r.color}"></i></span><b style="text-align:right">${r.n}</b>`;
    return r.onclick
      ? `<button type="button" class="bn-rank" onclick="${r.onclick}" title="Filtrer la liste">${inner}</button>`
      : `<div class="bn-rank">${inner}</div>`;
  }).join('');
}

function bnCountBy(list, keyFn) {
  const c = new Map();
  list.forEach(b => { const k = keyFn(b); c.set(k, (c.get(k) || 0) + 1); });
  return [...c.entries()].sort((a, b) => b[1] - a[1]);
}

function bnCard(title, body, extra = '') {
  return `<div class="card blueprint bn-card"${extra}><h3>${title}</h3>${body}</div>`;
}

function bnAnalysisHTML() {
  const admin = _bn.mode === 'admin';
  const geoSorted = geoSortLocalLast(_bn.countries, c => c.count || 0).slice(0, 6);
  const geoRows = geoSorted.map((c, i) => {
    const row = {
      label: c.country_code === 'XX' ? 'Inconnu' : `${c.country_name || c.country_code} (${c.country_code})`,
      n: c.count, color: 'var(--accent)',
    };
    return isLocalGeo(c.country_code) && i > 0 && !isLocalGeo(geoSorted[i - 1].country_code)
      ? [{ sep: true, label: t('pz.local_sep') }, row] : [row];
  }).flat();
  const geo = bnRankHTML(geoRows, 'Aucune géolocalisation disponible.');
  const sources = bnRankHTML(bnCountBy(_bn.bans, bnSrc).map(([k, n]) => ({
    label: _secSourceLabel(k), n, color: bnSrcColor(k), onclick: `bnSetSource('${esc(k)}')`,
  })), 'Aucun ban actif.');
  const where = admin
    ? bnRankHTML(bnCountBy(_bn.bans, b => b.edge_name || '__global').slice(0, 6).map(([k, n]) => ({
      label: k === '__global' ? 'Global' : bnEdge(k), n, color: 'var(--red)', onclick: `bnSetEdge('${esc(k)}')`,
    })), 'Aucun ban actif.')
    : bnRankHTML(bnCountBy(_bn.bans, b => b.domain || '(tous les domaines)').slice(0, 6).map(([k, n]) => ({
      label: k, n, color: 'var(--red)',
    })), 'Aucun ban actif.');
  const reasons = bnRankHTML(_bn.byReason.slice(0, 6).map(r => ({ label: r.reason || 'Inconnue', n: r.count, color: 'var(--yellow)' })), 'Aucune donnée.');
  return `<div class="bn-grid two">
      ${bnCard('Bans par heure · 48 dernières heures', bnTimelineHTML())}
      ${bnCard('Origine géographique', geo)}
    </div>
    <div class="bn-grid three">
      ${bnCard('Par source', sources)}
      ${bnCard(admin ? 'Par passerelle' : 'Par domaine', where)}
      ${bnCard('Raisons fréquentes <span style="font-weight:400;color:var(--text3)">(historique)</span>', reasons)}
    </div>`;
}

// ── Table ─────────────────────────────────────────────────────────────────────

function bnChipsHTML() {
  const chip = (on, label, fn) => `<button type="button" class="sec-bans-chip${on ? ' is-on' : ''}" onclick="${fn}">${label}</button>`;
  const sources = [...new Set(_bn.bans.map(bnSrc))];
  return `<span style="font-size:11px;color:var(--text3)">Source</span>
    ${chip(!_bn.src, 'Toutes', "bnSetSource('')")}
    ${sources.map(s => chip(_bn.src === s, esc(_secSourceLabel(s)), `bnSetSource('${esc(s)}')`)).join('')}
    <span style="font-size:11px;color:var(--text3);margin-left:6px">Durée</span>
    ${chip(!_bn.exp, 'Toutes', "bnSetExp('')")}
    ${chip(_bn.exp === 'soon', 'Expire sous 1 h', "bnSetExp('soon')")}
    ${chip(_bn.exp === 'temporary', 'Temporaires', "bnSetExp('temporary')")}
    ${chip(_bn.exp === 'permanent', 'Permanents', "bnSetExp('permanent')")}
    ${chip(_bn.exp === 'recurring', 'Récidivistes', "bnSetExp('recurring')")}`;
}

function bnEdgeSelectHTML() {
  if (_bn.mode !== 'admin') return '';
  const names = [...new Set(_bn.bans.map(b => b.edge_name).filter(Boolean))].sort();
  return `<select id="bn-edge" class="input" style="height:30px;width:auto;font-size:12px;padding:0 8px" onchange="bnSetEdge(this.value)" aria-label="Passerelle">
    <option value="">Toutes les passerelles</option>
    <option value="__global"${_bn.edge === '__global' ? ' selected' : ''}>Global</option>
    ${names.map(n => `<option value="${esc(n)}"${_bn.edge === n ? ' selected' : ''}>${esc(bnEdge(n))}</option>`).join('')}</select>`;
}

function bnThSort(col, label) {
  const [c, d] = _bn.sort.split('_');
  const on = c === col;
  return `<th onclick="bnSortBy('${col}')" style="cursor:pointer;user-select:none;white-space:nowrap${on ? ';color:var(--accent)' : ''}" title="Trier">${label}${on ? (d === 'asc' ? ' ↑' : ' ↓') : ''}</th>`;
}

function bnRowHTML(b) {
  const admin = _bn.mode === 'admin';
  const id = esc(String(b.id)), ip = esc(b.ip);
  const rec = _bn.rec.get(b.ip);
  const temp = bnExpiry(b) != null;
  return `<tr>
    <td class="bn-c-sel"><input type="checkbox" ${_bn.sel.has(b.id) ? 'checked' : ''} onchange="bnToggle('${id}',this.checked)" aria-label="Sélectionner ${ip}"></td>
    <td class="mono bn-c-ip">${ip}${rec ? ` <span class="tag tag-yellow" title="${rec} bans sur l'historique">×${rec}</span>` : ''}${b.exempt ? ' <span class="tag tag-green" title="Entièrement couvert par la liste blanche : ce ban ne s\'applique pas">Exempté</span>' : ''}</td>
    <td data-label="Source"><span class="tag tag-neutral"><i class="sent-dot" style="background:${bnSrcColor(bnSrc(b))};margin-right:5px"></i>${esc(_secSourceLabel(bnSrc(b)))}</span></td>
    ${admin ? `<td data-label="Passerelle" style="font-size:12px">${b.edge_name ? esc(bnEdge(b.edge_name)) : '<span class="tag tag-neutral">Global</span>'}${bnScopeTag(b)}</td>` : `<td data-label="Domaine" style="color:var(--text2)">${esc(b.domain || '—')}</td>`}
    <td data-label="Raison" style="color:var(--text2);font-size:12px;max-width:260px" title="${esc(b.reason || '')}">${esc(b.reason || '—')}${banSignalsHTML(b.signals)}${banUserAgentHTML(b.user_agent)}</td>
    <td data-label="Restant">${bnTtlCell(b)}</td>
    <td class="bn-actions">
      ${bnIcon('prism', `openPrismForBanIP('${ip}')`, 'Voir dans Prism')}
      ${trBtn(b.ip)}
      ${bnIcon('history', `showBanHistory('${ip}')`, 'Historique de cette IP')}
      ${temp ? bnIcon('extend', `bnProlong(['${id}'])`, 'Prolonger de 24 h') : ''}
      ${temp ? bnIcon('permanent', `makeBanPermanent('${id}','${ip}')`, 'Rendre permanent') : ''}
      ${bnIcon('unban', `deleteBan('${id}','${ip}')`, 'Lever le ban', 'style="color:var(--red)"')}
    </td></tr>`;
}

function bnBulkHTML() {
  if (!_bn.sel.size) return '';
  return `<div class="bn-bulk"><b>${_bn.sel.size} sélectionné${_bn.sel.size > 1 ? 's' : ''}</b>
    <span style="margin-left:auto;display:flex;gap:2px">
      ${bnIcon('extend', 'bnBulk("extend")', 'Prolonger de 24 h')}
      ${bnIcon('permanent', 'bnBulk("permanent")', 'Rendre permanent')}
      ${bnIcon('unban', 'bnBulk("unban")', 'Lever les bans sélectionnés', 'style="color:var(--red)"')}
      <button type="button" class="btn btn-ghost btn-sm" onclick="bnClearSel()">Annuler</button></span></div>`;
}

function bnActiveTableHTML() {
  const list = bnFiltered();
  const page = list.slice(0, _bn.shown);
  if (!list.length) {
    return `<div class="empty" style="padding:30px 20px"><p>${_bn.bans.length ? 'Aucun ban ne correspond aux filtres.' : 'Aucun ban actif.'}</p></div>`;
  }
  const allOn = page.length && page.every(b => _bn.sel.has(b.id));
  const admin = _bn.mode === 'admin';
  return `<div class="table-wrap sec-bans-table-scroll"><table class="bn-table">
    <thead><tr>
      <th style="width:28px"><input type="checkbox" ${allOn ? 'checked' : ''} onchange="bnToggleAll(this.checked)" aria-label="Tout sélectionner"></th>
      ${bnThSort('ip', 'IP')}${bnThSort('source', 'Source')}
      ${admin ? bnThSort('edge', 'Passerelle') : '<th>Domaine</th>'}
      <th>Raison</th>${bnThSort('expires', 'Restant')}<th></th>
    </tr></thead>
    <tbody>${page.map(bnRowHTML).join('')}</tbody></table></div>
    ${list.length > page.length ? `<div style="text-align:center;padding:10px"><button type="button" class="btn btn-ghost btn-sm" onclick="bnMore()">Afficher plus (${list.length - page.length} restants)</button></div>` : ''}`;
}

function bnHistoryTableHTML() {
  const list = _bn.history;
  if (!list.length) return '<div class="empty" style="padding:30px 20px"><p>Aucun ban expiré.</p></div>';
  const admin = _bn.mode === 'admin';
  return `<div class="table-wrap sec-bans-table-scroll"><table class="bn-table">
    <thead><tr><th>IP</th><th>Source</th>${admin ? '<th>Passerelle</th>' : '<th>Domaine</th>'}<th>Raison</th><th>Expiré le</th><th>Créé le</th></tr></thead>
    <tbody>${list.map(b => `<tr>
      <td class="mono bn-c-ip">${esc(b.ip)}</td>
      <td data-label="Source"><span class="tag tag-neutral">${esc(_secSourceLabel(bnSrc(b)))}</span></td>
      ${admin ? `<td data-label="Passerelle" style="font-size:12px">${b.edge_name ? esc(bnEdge(b.edge_name)) : '<span class="tag tag-neutral">Global</span>'}${bnScopeTag(b)}</td>` : `<td data-label="Domaine" style="color:var(--text2)">${esc(b.domain || '—')}</td>`}
      <td data-label="Raison" style="color:var(--text2);font-size:12px">${esc(b.reason || '—')}${banSignalsHTML(b.signals)}${banUserAgentHTML(b.user_agent)}</td>
      <td data-label="Expiré le" style="font-size:11px">${fmtDate(b.expires_at)}</td>
      <td data-label="Créé le" style="font-size:11px;color:var(--text3)">${fmtDate(b.created_at)}</td></tr>`).join('')}</tbody></table></div>`;
}

function bnListCardHTML() {
  const tabs = BN_TABS.map(k => `<button type="button" role="tab" class="tab${_bn.tab === k ? ' active' : ''}" onclick="bnSetTab('${k}')">${BN_TAB_LABELS[k]}${k === 'actifs' ? ` <span class="sec-bans-count">${_bn.bans.length}</span>` : k === 'historique' ? ` <span class="sec-bans-count">${_bn.history.length}</span>` : ''}</button>`).join('');
  const toolbar = _bn.tab === 'actifs' ? `<div class="sec-bans-toolbar" style="padding-top:12px">
      <div class="sec-bans-toolbar-row">
        <input id="bn-search" class="input search-input" placeholder="IP, domaine, raison…" value="${esc(_bn.q)}" oninput="bnSearch(this.value)" style="max-width:260px">
        ${bnEdgeSelectHTML()}
        <span id="bn-views" style="display:inline-flex;gap:6px;align-items:center">${bnViewsHTML()}</span>
        <span id="bn-count" class="sec-bans-count" style="margin-left:auto"></span>
      </div>
      <div class="sec-bans-toolbar-row" id="bn-chips"></div>
    </div><div id="bn-asn"></div><div id="bn-bulk"></div>` : '';
  return `<div class="card blueprint" style="padding:0">
    <div class="tabs" role="tablist" style="margin:0;padding:0 8px">${tabs}</div>
    ${toolbar}<div id="bn-body"></div></div>`;
}

function bnPaint() {
  const body = document.getElementById('bn-body');
  if (!body) return;
  if (_bn.tab === 'crowdsec') {
    body.innerHTML = `<div id="sec-threats-panel">${threatsPanelHTML()}</div>`;
    return;
  }
  if (_bn.tab === 'historique') {
    body.innerHTML = bnHistoryTableHTML();
    return;
  }
  const chips = document.getElementById('bn-chips');
  if (chips) chips.innerHTML = bnChipsHTML();
  const asnBox = document.getElementById('bn-asn');
  if (asnBox) asnBox.innerHTML = bnAsnStripHTML();
  const total = _bn.bans.length, shown = bnFiltered().length;
  const count = document.getElementById('bn-count');
  if (count) count.textContent = shown === total ? `${total} ban${total > 1 ? 's' : ''}` : `${shown} sur ${total}`;
  const bulk = document.getElementById('bn-bulk');
  if (bulk) bulk.innerHTML = bnBulkHTML();
  body.innerHTML = bnActiveTableHTML();
}

// ── Filtres enregistrés ───────────────────────────────────────────────────────
// Combinaisons de filtres (recherche, source, expiration, passerelle, tri) gardées dans ce navigateur,
// séparément pour l'Admin et pour chaque menu de passerelle.

const BN_VIEW_KEYS = ['q', 'src', 'exp', 'edge', 'sort'];
const bnViewsStore = () => 'gpx.bans.views.' + (_bn.mode || 'admin');

function bnViewsLoad() {
  try {
    const v = JSON.parse(localStorage.getItem(bnViewsStore()) || '[]');
    return Array.isArray(v) ? v.filter(x => x && typeof x.name === 'string' && x.filter) : [];
  } catch { return []; }
}

function bnViewsSave(list) {
  try { localStorage.setItem(bnViewsStore(), JSON.stringify(list)); } catch { /* stockage indisponible */ }
}

function bnViewsHTML() {
  const views = bnViewsLoad();
  const cur = _bn.view || '';
  const sel = views.length
    ? `<select class="input" style="height:30px;width:auto;font-size:12px;padding:0 8px" onchange="bnViewApply(this.value)" aria-label="Filtres enregistrés">
        <option value="">Filtres enregistrés…</option>
        ${views.map(v => `<option value="${esc(v.name)}"${v.name === cur ? ' selected' : ''}>${esc(v.name)}</option>`).join('')}</select>`
    : '';
  const del = cur ? `<button type="button" class="btn btn-ghost btn-sm" onclick="bnViewDelete()" title="Supprimer ce filtre enregistré">Supprimer</button>` : '';
  return sel + `<button type="button" class="btn btn-ghost btn-sm" onclick="bnViewSave()" title="Enregistrer les filtres actuels">Enregistrer</button>` + del;
}

function bnViewsRepaint() {
  const box = document.getElementById('bn-views');
  if (box) box.innerHTML = bnViewsHTML();
}

window.bnViewSave = function() {
  if (!['q', 'src', 'exp', 'edge'].some(k => _bn[k])) { toast('Aucun filtre actif à enregistrer', 'error'); return; }
  const name = (prompt('Nom du filtre enregistré') || '').trim().slice(0, 40);
  if (!name) return;
  const filter = Object.fromEntries(BN_VIEW_KEYS.map(k => [k, _bn[k]]));
  const list = bnViewsLoad().filter(v => v.name !== name);
  list.push({ name, filter });
  list.sort((a, b) => a.name.localeCompare(b.name));
  bnViewsSave(list);
  _bn.view = name;
  bnViewsRepaint();
  toast('Filtre « ' + name + ' » enregistré', 'success');
};

window.bnViewApply = function(name) {
  const v = bnViewsLoad().find(x => x.name === name);
  _bn.view = v ? name : '';
  if (v) {
    for (const k of BN_VIEW_KEYS) _bn[k] = v.filter[k] ?? (k === 'sort' ? 'created_desc' : '');
    const search = document.getElementById('bn-search');
    if (search) search.value = _bn.q;
    const edge = document.getElementById('bn-edge');
    if (edge) edge.value = _bn.edge;
  }
  bnViewsRepaint();
  bnRefilter();
};

window.bnViewDelete = function() {
  if (!_bn.view) return;
  bnViewsSave(bnViewsLoad().filter(v => v.name !== _bn.view));
  _bn.view = '';
  bnViewsRepaint();
};

// ── Actions ───────────────────────────────────────────────────────────────────

const bnRefilter = () => { _bn.shown = BN_PAGE; bnPaint(); };
window.bnSearch = v => { _bn.q = v || ''; bnRefilter(); };
window.bnSetSource = v => { _bn.src = _bn.src === v ? '' : v; bnRefilter(); };
window.bnSetExp = v => { _bn.exp = _bn.exp === v ? '' : v; bnRefilter(); };
window.bnSetEdge = v => {
  _bn.edge = _bn.edge === v ? '' : v;
  const sel = document.getElementById('bn-edge');
  if (sel) sel.value = _bn.edge;
  bnRefilter();
};
window.bnSortBy = col => {
  const [c, d] = _bn.sort.split('_');
  _bn.sort = `${col}_${c === col && d === 'asc' ? 'desc' : 'asc'}`;
  bnPaint();
};
window.bnMore = () => { _bn.shown += BN_PAGE; bnPaint(); };
window.bnToggle = (id, on) => { on ? _bn.sel.add(id) : _bn.sel.delete(id); bnPaint(); };
window.bnToggleAll = on => {
  bnFiltered().slice(0, _bn.shown).forEach(b => on ? _bn.sel.add(b.id) : _bn.sel.delete(b.id));
  bnPaint();
};
window.bnClearSel = () => { _bn.sel.clear(); bnPaint(); };
window.bnSetTab = tab => {
  if (!BN_TABS.includes(tab)) return;
  _bn.tab = tab;
  bnMount();
};

const bnIso = ms => new Date(ms).toISOString().replace(/\.\d+Z$/, 'Z');

window.bnProlong = async function(ids) {
  const bans = _bn.bans.filter(b => ids.includes(String(b.id)) && bnExpiry(b) != null);
  if (!bans.length) return;
  const res = await Promise.allSettled(bans.map(b =>
    api('PATCH', `/security/bans/${encodeURIComponent(b.id)}`, { expires_at: bnIso(Math.max(bnExpiry(b), Date.now()) + 86400000) })));
  const failed = res.filter(r => r.status === 'rejected').length;
  toast(failed ? `${failed} prolongation(s) en échec` : `${bans.length} ban${bans.length > 1 ? 's' : ''} prolongé${bans.length > 1 ? 's' : ''} de 24 h`, failed ? 'error' : 'success');
  reloadCurrentSecurityPage();
};

window.bnBulk = async function(kind) {
  const bans = _bn.bans.filter(b => _bn.sel.has(b.id));
  if (!bans.length) return;
  if (kind === 'extend') return window.bnProlong(bans.map(b => String(b.id)));
  const label = kind === 'unban' ? 'Lever' : 'Rendre permanent';
  if (!confirm(`${label} ${bans.length} ban${bans.length > 1 ? 's' : ''} ?`)) return;
  const res = await Promise.allSettled(bans.map(b => kind === 'unban'
    ? api('DELETE', `/security/bans/${encodeURIComponent(b.id)}`)
    : api('PATCH', `/security/bans/${encodeURIComponent(b.id)}`, { permanent: true })));
  const failed = res.filter(r => r.status === 'rejected').length;
  toast(failed ? `${failed} action(s) en échec sur ${bans.length}` : `${bans.length} ban${bans.length > 1 ? 's' : ''} traité${bans.length > 1 ? 's' : ''}`, failed ? 'error' : 'success');
  _bn.sel.clear();
  reloadCurrentSecurityPage();
};

// ── Page ──────────────────────────────────────────────────────────────────────

function bnMount() {
  const content = document.getElementById('content');
  if (!content) return;
  content.innerHTML = `${securityEdgeBanner(_bn.edgeCtx)}${bnKpisHTML()}${bnAnalysisHTML()}${bnListCardHTML()}`;
  bnPaint();
}

async function renderBans({ mode }) {
  const content = document.getElementById('content');
  content.innerHTML = '<p style="color:var(--text2)">' + t('common.loading') + '</p>';
  const ta = document.getElementById('topbar-actions');
  if (ta) ta.innerHTML = `
    <button class="btn btn-ghost btn-sm" style="font-size:11px" onclick="exportBansCSV()">Export CSV</button>
    <button class="btn btn-ghost btn-sm" style="font-size:11px" onclick="openBanImport()" title="Créer des bans (ou des entrées de la liste blanche) depuis une liste d'adresses et de CIDR">Importer</button>
    <button class="btn btn-ghost btn-sm" style="font-size:11px" onclick="openBanWhitelist()" title="Adresses et plages qu'aucun ban n'atteint">Liste blanche</button>
    <button class="btn btn-ghost btn-sm" style="font-size:11px" onclick="openBanAsn()" title="Bannir toutes les plages d'un opérateur (système autonome)">+ ASN</button>
    <button class="btn btn-primary btn-sm" onclick="openBanModal()">+ Ban</button>
    <button class="btn btn-secondary btn-sm" onclick="reloadCurrentSecurityPage()" title="Actualiser" aria-label="Actualiser">↺</button>`;
  try {
    const d = await bnLoad(mode);
    if (mode === 'edge' && d.edgeCtx?.missing) {
      content.innerHTML = '<p style="color:var(--text2)">' + t('trafic.no_edge') + '</p>';
      return;
    }
    // Les filtres survivent à un rechargement de la même vue, pas à un changement de passerelle ou de mode.
    const scope = mode + ':' + (d.edgeCtx?.edgeRef || '');
    if (_bn.scope !== scope) Object.assign(_bn, { scope, q: '', src: '', exp: '', edge: '', shown: BN_PAGE, tab: 'actifs' });
    // Ouverture directe sur un onglet précis (ex. raccourci « Menaces actives » de la Synthèse).
    if (window._bnOpenTab) { if (BN_TABS.includes(window._bnOpenTab)) _bn.tab = window._bnOpenTab; window._bnOpenTab = null; }
    const ids = new Set(d.bans.map(b => b.id));
    _bn.sel = new Set([..._bn.sel].filter(id => ids.has(id)));
    Object.assign(_bn, d, { mode });
    window._secBans = _bn.bans;
    bnMount();
  } catch (e) { toast(e.message, 'error'); }
}

// ── Liste blanche ─────────────────────────────────────────────────────────────
// Adresses et plages qu'aucun ban n'atteint (manuel, Seuils, CrowdSec, Ephor, règles) et que
// Ephor n'évalue pas. Gérée ici : le profil IP qui la porte n'est pas modifiable depuis Profils IP.

function bnWhitelistBodyHTML(list) {
  const rows = list.length
    ? list.map(e => `<tr>
        <td class="mono">${esc(e.value)}</td>
        <td style="color:var(--text2);font-size:12px">${esc(e.comment || '—')}${e.bans_exempted ? ` <span class="tag tag-yellow" title="Bans actifs rendus sans effet par cette entrée">${e.bans_exempted} ban${e.bans_exempted > 1 ? 's' : ''} neutralisé${e.bans_exempted > 1 ? 's' : ''}</span>` : ''}</td>
        <td style="text-align:right"><button type="button" class="btn btn-ghost btn-sm" style="color:var(--red)" data-wl="${esc(e.value)}" onclick="bnWhitelistRemove(this.dataset.wl)">Retirer</button></td></tr>`).join('')
    : '<tr><td colspan="3" style="color:var(--text3);padding:14px 4px">Liste blanche vide.</td></tr>';
  return `<p style="font-size:12.5px;color:var(--text2);margin:0 0 10px">Une adresse ou une plage en liste blanche n'est jamais bloquée par un ban (manuel, Seuils, CrowdSec, Ephor, règles) et n'est pas évaluée par Ephor. Les bans existants ne sont pas supprimés : ils cessent de s'appliquer à ces adresses.</p>
    <div class="table-wrap"><table class="bn-table"><tbody>${rows}</tbody></table></div>
    <div style="display:flex;gap:8px;margin-top:12px;align-items:flex-end;flex-wrap:wrap">
      <div class="field" style="margin:0;flex:1;min-width:180px"><label class="field-label">Adresse ou plage CIDR</label><input id="wl-ip" class="input" placeholder="203.0.113.10 ou 203.0.113.0/24"></div>
      <div class="field" style="margin:0;flex:1;min-width:150px"><label class="field-label">Commentaire (optionnel)</label><input id="wl-comment" class="input" placeholder="bureau Paris, supervision…"></div>
      <button type="button" class="btn btn-primary" onclick="bnWhitelistAdd()">Ajouter</button>
    </div>`;
}

async function bnWhitelistRepaint() {
  const list = await api('GET', '/security/bans/whitelist');
  const box = document.getElementById('bn-wl-box');
  if (box) box.innerHTML = bnWhitelistBodyHTML(list);
}

window.openBanWhitelist = async function() {
  try {
    const list = await api('GET', '/security/bans/whitelist');
    modal('Liste blanche des bans', `<div id="bn-wl-box">${bnWhitelistBodyHTML(list)}</div>`,
      '<button class="btn btn-secondary" onclick="closeModal();reloadCurrentSecurityPage()">Fermer</button>');
  } catch (e) { toast(e.message, 'error'); }
};

window.bnWhitelistAdd = async function() {
  const ip = document.getElementById('wl-ip')?.value.trim();
  if (!ip) { toast(t('security.ban_ip_required'), 'error'); return; }
  try {
    const r = await api('POST', '/security/bans/whitelist', { ip, comment: document.getElementById('wl-comment')?.value.trim() || '' });
    toast(r.added === false ? `Déjà couvert par ${r.covered_by}` : 'Ajouté à la liste blanche', r.added === false ? 'info' : 'success');
    await bnWhitelistRepaint();
  } catch (e) { toast(e.message, 'error'); }
};

window.bnWhitelistRemove = async function(value) {
  if (!confirm(`Retirer ${value} de la liste blanche ? Les bans qu'elle neutralisait s'appliqueront de nouveau.`)) return;
  try {
    await api('DELETE', '/security/bans/whitelist?ip=' + encodeURIComponent(value));
    toast('Retiré de la liste blanche', 'success');
    await bnWhitelistRepaint();
  } catch (e) { toast(e.message, 'error'); }
};

// ── Bans par ASN ──────────────────────────────────────────────────────────────
// Un ban d'ASN crée un ban par plage annoncée (souvent des centaines) : la liste les masque et les
// résume dans un bandeau, une ligne par ASN, avec « Lever » pour les retirer ensemble.

function bnAsnStripHTML() {
  const groups = new Map();
  for (const b of _bn.bans) {
    if (!b.asn) continue;
    const g = groups.get(b.asn) || { asn: b.asn, n: 0, name: '' };
    g.n++;
    if (!g.name) g.name = String(b.reason || '').replace(/^AS\d+\s*/, '');
    groups.set(b.asn, g);
  }
  if (!groups.size) return '';
  const total = [...groups.values()].reduce((s, g) => s + g.n, 0);
  const chips = [...groups.values()].sort((a, b) => b.n - a.n).map(g => `<span class="tag tag-neutral" style="display:inline-flex;gap:8px;align-items:center;padding:3px 8px">
      <b>AS${g.asn}</b>${g.name ? ' ' + esc(g.name) : ''} · ${g.n} plage${g.n > 1 ? 's' : ''}
      <button type="button" class="btn btn-ghost btn-sm" style="font-size:11px;padding:0 6px" onclick="bnAsnUnban(${g.asn})" title="Retirer les ${g.n} bans de cet ASN">Lever</button></span>`).join(' ');
  return `<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;padding:8px 12px;border-bottom:1px solid var(--border);font-size:12px">
    <span style="color:var(--text3)">Bans par ASN :</span>${chips}
    <button type="button" class="btn btn-ghost btn-sm" style="font-size:11px;margin-left:auto" onclick="bnToggleAsn()">${_bn.showAsn ? 'Masquer' : 'Afficher'} les ${total} plages dans la liste</button></div>`;
}

window.bnToggleAsn = () => { _bn.showAsn = !_bn.showAsn; bnRefilter(); };

window.bnAsnUnban = async function(asn) {
  if (!confirm('Retirer tous les bans de l\'ASN AS' + asn + ' ?')) return;
  try {
    const r = await api('DELETE', '/security/asn/ban?asn=' + encodeURIComponent(asn));
    toast(`${r.removed} plage(s) débannie(s)`, 'success');
    reloadCurrentSecurityPage();
  } catch (e) { toast(e.message, 'error'); }
};

let _bnAsn = { sel: null };

window.openBanAsn = function(prefill) {
  _bnAsn = { sel: null };
  modal('Bannir un ASN', `
    <p style="font-size:12.5px;color:var(--text2);margin:0 0 10px">Un ASN est l'ensemble des adresses d'un opérateur (hébergeur, fournisseur d'accès…). Chercher par numéro (<code>AS16276</code>), par adresse IP ou par nom, puis mesurer l'impact avant de bannir. Chaque plage annoncée devient un ban ; relancer plus tard ajoute les nouvelles plages.</p>
    <div style="display:flex;gap:8px;margin-bottom:8px"><input id="asn-q" class="input" placeholder="AS16276, 51.77.0.1 ou OVH" style="flex:1" onkeydown="if(event.key==='Enter')bnAsnSearch()"><button class="btn btn-secondary" onclick="bnAsnSearch()">Chercher</button></div>
    <div id="asn-results"></div>
    <div id="asn-form" style="display:none">
      <div class="field"><label class="field-label">Motif (optionnel)</label><input id="asn-reason" class="input" placeholder="AS… nom de l'opérateur"></div>
      <div style="display:flex;gap:10px;flex-wrap:wrap">
        <div class="field" style="flex:1;min-width:190px;margin:0"><label class="field-label">Expire le (optionnel, vide = permanent)</label><input id="asn-exp" type="datetime-local" class="input"></div>
        <div class="field" style="flex:1;min-width:190px;margin:0"><label class="field-label">${t('security.ban_modal.scope')}</label><select id="asn-scope" class="input"><option value="">${esc(t('security.ban_modal.scope_all'))}</option></select></div>
      </div>
    </div>
    <div id="asn-preview" style="margin-top:12px"></div>`,
    `<button class="btn btn-secondary" onclick="closeModal();reloadCurrentSecurityPage()">Fermer</button>
     <button id="asn-ban-btn" class="btn btn-danger" style="display:none" onclick="bnAsnBan()">Bannir cet ASN</button>`, true);
  window.fillBanScopes?.('asn-scope');
  const q = document.getElementById('asn-q');
  if (prefill && q) { q.value = 'AS' + prefill; bnAsnSearch(); } else q?.focus();
};

window.bnAsnSearch = async function() {
  const q = document.getElementById('asn-q')?.value.trim();
  const box = document.getElementById('asn-results');
  if (!q || !box) return;
  box.innerHTML = '<div style="font-size:12.5px;color:var(--text3)">…</div>';
  try {
    const list = await api('GET', '/security/asn?q=' + encodeURIComponent(q));
    if (!list.length) { box.innerHTML = '<div style="font-size:12.5px;color:var(--text3)">Aucun ASN trouvé.</div>'; return; }
    box.innerHTML = `<div style="max-height:180px;overflow:auto;border:1px solid var(--border);border-radius:6px">${list.map(a => `
      <div style="display:flex;gap:10px;align-items:center;padding:6px 10px;cursor:pointer;font-size:12.5px;border-bottom:1px solid var(--border)" onclick="bnAsnPick(${a.asn})">
        <b style="min-width:80px">AS${a.asn}</b><span style="flex:1">${esc(a.name)} <span style="opacity:.6">${esc(a.country || '')}</span></span>
        <span style="color:var(--text3)">${gmNumFmt(a.v4_addresses)} adresses IPv4 · ${a.ranges} plages${a.banned_ranges ? ' · <span class="tag tag-yellow">' + a.banned_ranges + ' bannies</span>' : ''}</span></div>`).join('')}</div>`;
    if (list.length === 1) bnAsnPick(list[0].asn);
  } catch (e) {
    box.innerHTML = `<div style="font-size:12.5px;color:var(--red)">${esc(e.message)}</div>`;
  }
};

const gmNumFmt = n => n >= 1e6 ? (n / 1e6).toFixed(1) + ' M' : n >= 1e3 ? (n / 1e3).toFixed(1) + ' k' : String(Math.round(n || 0));

window.bnAsnPick = async function(asn) {
  _bnAsn.sel = asn;
  const form = document.getElementById('asn-form'), btn = document.getElementById('asn-ban-btn'), box = document.getElementById('asn-preview');
  if (form) form.style.display = '';
  if (btn) btn.style.display = '';
  if (!box) return;
  box.innerHTML = '<div style="font-size:12.5px;color:var(--text3)">Analyse de l\'impact…</div>';
  try {
    const r = await api('GET', '/security/asn/preview?asn=' + encodeURIComponent(asn));
    const warns = (r.warnings || []).map(w => `<li>${esc(w)}</li>`).join('');
    const reason = document.getElementById('asn-reason');
    if (reason && !reason.value) reason.placeholder = `AS${r.asn.asn} ${r.asn.name}`;
    if (btn) btn.disabled = !!r.requester_in;
    box.innerHTML = `<div style="font-size:12.5px;line-height:1.55;padding:8px 10px;border:1px solid var(--border);border-radius:6px">
      <strong>AS${r.asn.asn} ${esc(r.asn.name)}</strong> — ${r.would_create} plage${r.would_create > 1 ? 's' : ''} à bannir${r.skipped_count ? `, ${r.skipped_count} ignorée${r.skipped_count > 1 ? 's' : ''}` : ''}${r.rejected_count ? `, ${r.rejected_count} rejetée${r.rejected_count > 1 ? 's' : ''}` : ''}<br>
      Trafic ${r.hours} h : ${r.requests} requête(s) de ${r.ips} adresse(s), dont ${r.ok_requests} réussie(s) qui seraient coupées
      ${warns ? `<ul style="margin:6px 0 0 16px;padding:0;color:var(--yellow)">${warns}</ul>` : '<div style="color:var(--green);margin-top:4px">Aucun avertissement.</div>'}</div>`;
  } catch (e) {
    box.innerHTML = `<div style="font-size:12.5px;color:var(--red)">${esc(e.message)}</div>`;
  }
};

window.bnAsnBan = async function() {
  if (!_bnAsn.sel) return;
  const body = { asn: String(_bnAsn.sel) };
  const reason = document.getElementById('asn-reason')?.value.trim();
  if (reason) body.reason = reason;
  const exp = document.getElementById('asn-exp')?.value;
  if (exp) body.expires_at = new Date(exp).toISOString();
  const scope = document.getElementById('asn-scope')?.value;
  if (scope) body.scope = scope;
  try {
    const r = await api('POST', '/security/asn/ban', body);
    closeModal();
    toast(`${r.created} plage(s) bannie(s) pour AS${r.asn} ${r.name}`, 'success');
    reloadCurrentSecurityPage();
  } catch (e) { toast(e.message, 'error'); }
};

// ── Import de liste ───────────────────────────────────────────────────────────
// Crée des bans (ou des entrées de la liste blanche) depuis une liste : texte (une adresse ou un CIDR par
// ligne, comme les listes publiques), CSV (dont l'export des bans) ou JSON. « Analyser » ne crée rien.

window.openBanImport = function() {
  modal('Importer une liste', `
    <p style="font-size:12.5px;color:var(--text2);margin:0 0 10px">Une adresse ou un CIDR par ligne (commentaires <code>#</code> et <code>;</code>), ou un CSV / JSON, y compris l'export des bans. Chaque entrée est validée comme un ban unitaire ; les doublons et les cibles déjà couvertes sont ignorés. 10 000 entrées et 2 Mo au plus.</p>
    <div style="display:flex;gap:14px;margin-bottom:8px;font-size:12.5px">
      <label><input type="radio" name="imp-target" value="bans" checked onchange="bnImportTarget()"> Créer des bans</label>
      <label><input type="radio" name="imp-target" value="whitelist" onchange="bnImportTarget()"> Ajouter à la liste blanche</label>
    </div>
    <div class="field"><textarea id="imp-content" class="input" rows="8" placeholder="203.0.113.5&#10;198.51.100.0/24 ; scanner&#10;# commentaire" style="font-family:var(--mono,monospace);font-size:12px"></textarea></div>
    <div class="field"><label class="field-label">Ou un fichier (.txt, .csv, .json)</label><input type="file" accept=".txt,.csv,.json,.list,.netset,text/plain" onchange="bnImportFile(this)"></div>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <div class="field" style="flex:1;min-width:160px;margin:0"><label class="field-label" id="imp-reason-label">Motif par défaut</label><input id="imp-reason" class="input" placeholder="import"></div>
      <div class="field" id="imp-exp-box" style="flex:1;min-width:190px;margin:0"><label class="field-label">Expire le (optionnel, vide = permanent)</label><input id="imp-exp" type="datetime-local" class="input"></div>
      <div class="field" id="imp-scope-box" style="flex:1;min-width:190px;margin:0"><label class="field-label">${t('security.ban_modal.scope')}</label><select id="imp-scope" class="input"><option value="">${esc(t('security.ban_modal.scope_all'))}</option></select></div>
    </div>
    <div id="imp-result" style="margin-top:12px"></div>`,
    `<button class="btn btn-secondary" onclick="closeModal();reloadCurrentSecurityPage()">Fermer</button>
     <button class="btn btn-secondary" onclick="bnImportRun(true)">Analyser</button>
     <button class="btn btn-danger" onclick="bnImportRun(false)">Importer</button>`, true);
  window.fillBanScopes?.('imp-scope');
};

window.bnImportTarget = function() {
  const wl = document.querySelector('input[name="imp-target"]:checked')?.value === 'whitelist';
  const box = document.getElementById('imp-exp-box');
  if (box) box.style.display = wl ? 'none' : '';
  const scopeBox = document.getElementById('imp-scope-box');
  if (scopeBox) scopeBox.style.display = wl ? 'none' : '';
  const label = document.getElementById('imp-reason-label');
  if (label) label.textContent = wl ? 'Commentaire par défaut' : 'Motif par défaut';
};

window.bnImportFile = function(input) {
  const f = input.files?.[0];
  if (!f) return;
  if (f.size > 2 * 1024 * 1024) { toast('Fichier trop volumineux (2 Mo au plus)', 'error'); input.value = ''; return; }
  const rd = new FileReader();
  rd.onload = () => { const ta = document.getElementById('imp-content'); if (ta) ta.value = String(rd.result || ''); };
  rd.readAsText(f);
};

function bnImportIssues(title, list, color) {
  if (!list?.length) return '';
  const shown = list.slice(0, 20);
  return `<div style="margin-top:8px"><strong style="color:${color}">${title}</strong>
    <ul style="margin:4px 0 0 16px;padding:0;font-size:12px;color:var(--text2)">${shown.map(i =>
      `<li>ligne ${i.line} — <span class="mono">${esc(i.value)}</span> : ${esc(i.reason)}</li>`).join('')}
    ${list.length > shown.length ? `<li>… ${list.length - shown.length} de plus</li>` : ''}</ul></div>`;
}

window.bnImportRun = async function(dry) {
  const content = document.getElementById('imp-content')?.value || '';
  const box = document.getElementById('imp-result');
  if (!content.trim()) { toast('Liste vide', 'error'); return; }
  const target = document.querySelector('input[name="imp-target"]:checked')?.value || 'bans';
  const body = { content, target, dry_run: dry, reason: document.getElementById('imp-reason')?.value.trim() || '' };
  const exp = document.getElementById('imp-exp')?.value;
  if (exp && target === 'bans') body.expires_at = new Date(exp).toISOString();
  const scope = document.getElementById('imp-scope')?.value;
  if (scope && target === 'bans') body.scope = scope;
  if (box) box.innerHTML = '<div style="font-size:12.5px;color:var(--text3)">…</div>';
  try {
    const r = await api('POST', '/security/bans/import', body);
    const what = target === 'whitelist' ? 'entrée(s) de liste blanche' : 'ban(s)';
    const head = dry
      ? `Analyse : ${r.created} ${what} seraient créé(s) (${Math.round(r.addresses)} adresse(s)) sur ${r.total} entrée(s) lue(s). Rien n'a été créé.`
      : `${r.created} ${what} créé(s) sur ${r.total} entrée(s) lue(s).`;
    if (box) box.innerHTML = `<div style="font-size:12.5px;line-height:1.5;padding:8px 10px;border:1px solid var(--border);border-radius:6px">
      <strong>${esc(head)}</strong><br>${r.skipped_count} ignorée(s), ${r.rejected_count} rejetée(s).
      ${bnImportIssues('Rejetées', r.rejected, 'var(--red)')}${bnImportIssues('Ignorées', r.skipped, 'var(--yellow)')}</div>`;
    if (!dry && r.created > 0) toast(`${r.created} ${what} créé(s)`, 'success');
  } catch (e) {
    if (box) box.innerHTML = `<div style="font-size:12.5px;color:var(--red)">${esc(e.message)}</div>`;
  }
};

pages['security-bans'] = () => renderBans({ mode: 'admin' });
pages['edge-security-bans'] = () => renderBans({ mode: 'edge' });

// Ouvre la page Bans directement sur un onglet (ex. onclick="navigateBansTab('${navBans}','crowdsec')").
window.navigateBansTab = function(page, tab) {
  window._bnOpenTab = tab;
  navigate(page);
};
