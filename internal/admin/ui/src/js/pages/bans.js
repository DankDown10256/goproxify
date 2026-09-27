// Page Bans, partagée entre l'admin (toutes les passerelles) et le menu d'une passerelle.
// ctx = { mode: 'admin'|'edge' }. Le mode edge verrouille la passerelle : les bans d'une passerelle et les
// bans globaux sont demandés au serveur (?edge=…) et la colonne Passerelle est remplacée par le domaine.

const BN_TABS = ['actifs', 'historique', 'crowdsec'];
const BN_TAB_LABELS = { actifs: 'Actifs', historique: 'Historique', crowdsec: 'CrowdSec' };
const BN_PAGE = 50;
const BN_SRC_COLORS = { fail2ban: 'var(--orange,#d97706)', crowdsec: 'var(--blue,#3b82f6)', threat: 'var(--purple,#8b5cf6)', rules_engine: 'var(--accent)', native: 'var(--text3)' };

const _bn = {
  mode: 'admin', edgeCtx: null, tab: 'actifs',
  edgeNames: new Map(), bans: [], history: [], kpis: {}, timeline: [], byReason: [], countries: [], rec: new Map(),
  q: '', src: '', exp: '', edge: '', sort: 'created_desc', shown: BN_PAGE, sel: new Set(),
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
const bnSrc = b => String(b.source || 'native').split(':')[0];

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
    label: _secSourceLabel(k), n, color: BN_SRC_COLORS[k] || 'var(--text3)', onclick: `bnSetSource('${esc(k)}')`,
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
    <td class="mono bn-c-ip">${ip}${rec ? ` <span class="tag tag-yellow" title="${rec} bans sur l'historique">×${rec}</span>` : ''}</td>
    <td data-label="Source"><span class="tag tag-neutral"><i class="sent-dot" style="background:${BN_SRC_COLORS[bnSrc(b)] || 'var(--text3)'};margin-right:5px"></i>${esc(_secSourceLabel(bnSrc(b)))}</span></td>
    ${admin ? `<td data-label="Passerelle" style="font-size:12px">${b.edge_name ? esc(bnEdge(b.edge_name)) : '<span class="tag tag-neutral">Global</span>'}</td>` : `<td data-label="Domaine" style="color:var(--text2)">${esc(b.domain || '—')}</td>`}
    <td data-label="Raison" style="color:var(--text2);font-size:12px;max-width:260px" title="${esc(b.reason || '')}">${esc(b.reason || '—')}</td>
    <td data-label="Restant">${bnTtlCell(b)}</td>
    <td class="bn-actions">
      ${bnIcon('prism', `openPrismForBanIP('${ip}')`, 'Voir dans Prism')}
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
      ${admin ? `<td data-label="Passerelle" style="font-size:12px">${b.edge_name ? esc(bnEdge(b.edge_name)) : '<span class="tag tag-neutral">Global</span>'}</td>` : `<td data-label="Domaine" style="color:var(--text2)">${esc(b.domain || '—')}</td>`}
      <td data-label="Raison" style="color:var(--text2);font-size:12px">${esc(b.reason || '—')}</td>
      <td data-label="Expiré le" style="font-size:11px">${fmtDate(b.expires_at)}</td>
      <td data-label="Créé le" style="font-size:11px;color:var(--text3)">${fmtDate(b.created_at)}</td></tr>`).join('')}</tbody></table></div>`;
}

function bnListCardHTML() {
  const tabs = BN_TABS.map(k => `<button type="button" role="tab" class="tab${_bn.tab === k ? ' active' : ''}" onclick="bnSetTab('${k}')">${BN_TAB_LABELS[k]}${k === 'actifs' ? ` <span class="sec-bans-count">${_bn.bans.length}</span>` : k === 'historique' ? ` <span class="sec-bans-count">${_bn.history.length}</span>` : ''}</button>`).join('');
  const toolbar = _bn.tab === 'actifs' ? `<div class="sec-bans-toolbar" style="padding-top:12px">
      <div class="sec-bans-toolbar-row">
        <input id="bn-search" class="input search-input" placeholder="IP, domaine, raison…" value="${esc(_bn.q)}" oninput="bnSearch(this.value)" style="max-width:260px">
        ${bnEdgeSelectHTML()}
        <span id="bn-count" class="sec-bans-count" style="margin-left:auto"></span>
      </div>
      <div class="sec-bans-toolbar-row" id="bn-chips"></div>
    </div><div id="bn-bulk"></div>` : '';
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
  const total = _bn.bans.length, shown = bnFiltered().length;
  const count = document.getElementById('bn-count');
  if (count) count.textContent = shown === total ? `${total} ban${total > 1 ? 's' : ''}` : `${shown} sur ${total}`;
  const bulk = document.getElementById('bn-bulk');
  if (bulk) bulk.innerHTML = bnBulkHTML();
  body.innerHTML = bnActiveTableHTML();
}

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

pages['security-bans'] = () => renderBans({ mode: 'admin' });
pages['edge-security-bans'] = () => renderBans({ mode: 'edge' });

// Ouvre la page Bans directement sur un onglet (ex. onclick="navigateBansTab('${navBans}','crowdsec')").
window.navigateBansTab = function(page, tab) {
  window._bnOpenTab = tab;
  navigate(page);
};
