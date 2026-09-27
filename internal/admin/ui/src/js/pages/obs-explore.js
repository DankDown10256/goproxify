// ── PAGE: Observabilité › Explorer (Admin + Passerelle) ──────────────────────
// Une seule vue sur les logs d'accès et système : recherche libre, facettes cliquables,
// histogramme (clic sur une barre pour zoomer), vues enregistrées (par navigateur).
//   Admin (logs-explore)            → toutes les passerelles, facette Passerelle
//   Passerelle (edge-logs-explore)  → node_name verrouillé, pas de facette Passerelle
// Réutilise les badges et icônes de logs.js (logLvlBadge, httpStatusBadge, corrIconBtn, prismIconBtn).

const EXPL_PERIODS = [['15m', 900000], ['1h', 3600000], ['6h', 21600000], ['24h', 86400000], ['7d', 604800000]];
const EXPL_FACETS = ['level', 'component', 'node_name', 'domain', 'method'];
const EXPL_VIEWS_KEY = 'gpx_log_views';

function explLoadViews() {
  try { return JSON.parse(localStorage.getItem(EXPL_VIEWS_KEY) || '[]'); } catch { return []; }
}
function explSaveViews(list) {
  try { localStorage.setItem(EXPL_VIEWS_KEY, JSON.stringify(list.slice(0, 30))); } catch { /* stockage indisponible */ }
}

pages['logs-explore'] = function() { renderExplorer({ node_name: '', lock: false }); };
pages['edge-logs-explore'] = function() { renderExplorer({ node_name: edgeLogNodeName(), lock: true }); };

async function renderExplorer(scope) {
  const main = document.getElementById('content');
  const q = window._explQ || (window._explQ = { kind: '', search: '', quickMs: 3600000, from: '', to: '', level: '', component: '', node_name: scope.node_name || '', domain: '', method: '' });
  if (scope.lock) q.node_name = scope.node_name;
  let rows = [];
  let cursorStack = [];
  let lastID = 0;

  function fq(extra = {}) {
    const p = new URLSearchParams(extra);
    p.set('kind', q.kind);
    if (q.search) p.set('search', q.search);
    if (q.from) p.set('date_from', q.from);
    if (q.to) p.set('date_to', q.to);
    for (const f of EXPL_FACETS) if (q[f]) p.set(f, q[f]);
    return p;
  }

  async function loadRows(beforeID) {
    if (beforeID === 0) { cursorStack = []; lastID = 0; }
    else if (beforeID < 0) { beforeID = cursorStack.pop() || 0; lastID = 0; }
    const p = fq({ page_size: 50 });
    if (beforeID > 0) p.set('before_id', beforeID);
    const data = await api('GET', '/logs?' + p).catch(() => null);
    rows = data?.entries || [];
    lastID = data?.last_id || 0;
    const tbody = document.getElementById('expl-tbody');
    const list = document.getElementById('expl-list');
    if (!rows.length) {
      if (tbody) tbody.innerHTML = `<tr><td colspan="7" class="empty"><p>${t('logs.none')}</p></td></tr>`;
      if (list) list.innerHTML = `<div class="logs-empty">${t('logs.none')}</div>`;
    } else {
      if (tbody) tbody.innerHTML = rows.map((e, i) => explRow(e, i)).join('');
      if (list) list.innerHTML = rows.map((e, i) => explEntry(e, i)).join('');
    }
    const hasPrev = cursorStack.length > 0, hasMore = !!data?.has_more;
    const pager = document.getElementById('expl-pager');
    if (pager) pager.innerHTML = `${hasPrev ? `<button type="button" class="btn btn-secondary btn-sm" data-expl="prev">${t('logs.prev')}</button>` : ''}
      ${hasMore ? `<button type="button" class="btn btn-secondary btn-sm" data-expl="next" data-before="${beforeID || 0}">${t('logs.next')}</button>` : ''}`;
  }

  async function loadHist() {
    const el = document.getElementById('expl-hist');
    if (!el) return;
    const to = q.to ? new Date(q.to) : new Date();
    const from = q.from ? new Date(q.from) : new Date(to - 86400000);
    const unit = to - from <= 21600000 ? 'minute' : 'hour';
    const p = fq({ bucket: unit });
    p.set('date_from', from.toISOString());
    p.set('date_to', to.toISOString());
    const data = await api('GET', '/logs/histogram?' + p).catch(() => null);
    if (!document.getElementById('expl-hist')) return;
    el.innerHTML = gpxHistHTML(data?.points || [], unit, { attr: 'data-expl-bucket', title: t('ex.hist_title'), hint: t('lg.hist_hint') });
  }

  async function loadFacets() {
    const el = document.getElementById('expl-facets');
    if (!el) return;
    const fields = scope.lock ? EXPL_FACETS.filter(f => f !== 'node_name') : EXPL_FACETS;
    const p = fq({ fields: fields.join(',') });
    const data = await api('GET', '/logs/facets?' + p).catch(() => ({}));
    if (!document.getElementById('expl-facets')) return;
    const label = { level: t('logs.level'), component: t('logs.component'), node_name: t('obs.syn.col_edge'), domain: t('logs.domain'), method: t('logs.method') };
    el.innerHTML = fields.map(f => {
      const items = data[f] || [];
      if (!items.length) return '';
      return `<div class="expl-facet"><h4>${esc(label[f])}</h4>${items.map(c => `
        <button type="button" class="expl-fv${q[f] === c.value ? ' active' : ''}" data-expl-facet="${f}" data-v="${esc(c.value)}">
          <span>${esc(c.value)}</span><span class="mono">${c.count}</span>
        </button>`).join('')}</div>`;
    }).join('') || `<p class="prism-muted">${esc(t('logs.none'))}</p>`;
  }

  function refresh() {
    loadRows(0);
    loadHist();
    loadFacets();
    renderChips();
    renderViews();
    const kindSel = document.getElementById('expl-kind');
    if (kindSel) kindSel.value = q.kind;
    const search = document.getElementById('expl-search');
    if (search) search.value = q.search;
    document.querySelectorAll('[data-expl-quick]').forEach(b => b.classList.toggle('active', parseInt(b.dataset.explQuick, 10) === q.quickMs));
  }

  function renderChips() {
    const el = document.getElementById('expl-chips');
    if (!el) return;
    const label = { level: t('logs.level'), component: t('logs.component'), node_name: t('obs.syn.col_edge'), domain: t('logs.domain'), method: t('logs.method') };
    const chips = EXPL_FACETS.filter(f => q[f] && !(scope.lock && f === 'node_name')).map(f =>
      `<span class="filter-chip">${esc(label[f])}: <b>${esc(q[f])}</b><button type="button" class="filter-chip-x" data-expl="clear" data-f="${f}" title="${esc(t('logs.remove'))}">✕</button></span>`);
    if (q.search) chips.push(`<span class="filter-chip">${esc(t('logs.search'))}: <b>${esc(q.search)}</b><button type="button" class="filter-chip-x" data-expl="clear" data-f="search" title="${esc(t('logs.remove'))}">✕</button></span>`);
    el.innerHTML = chips.length ? chips.join('') + `<button type="button" class="btn btn-ghost btn-sm" style="font-size:11px" data-expl="clearall">${t('logs.clear_all')}</button>` : '';
  }

  function renderViews() {
    const el = document.getElementById('expl-views');
    if (!el) return;
    const views = explLoadViews();
    el.innerHTML = views.map((v, i) => `<span class="chip" data-expl="loadview" data-i="${i}">${esc(v.name)}<button type="button" class="chip-x" data-expl="delview" data-i="${i}" title="${esc(t('ex.delete_view'))}">✕</button></span>`).join('')
      || `<span class="prism-muted" style="font-size:12px">${esc(t('ex.no_views'))}</span>`;
  }

  main.innerHTML = `<div id="expl-root">
    <div class="prism-filters">
      <div class="prism-fg">
        <select id="expl-kind" class="form-input" style="max-width:150px" data-expl="kind">
          <option value="">${t('ex.kind_all')}</option>
          <option value="access">${t('logs.tab_static')} · ${t('page.logs')}</option>
          <option value="system">${t('page.logs-system')}</option>
        </select>
      </div>
      <div class="prism-fg-sep"></div>
      <div class="prism-fg" style="gap:4px">${EXPL_PERIODS.map(([l, ms]) => `<button type="button" class="btn btn-secondary btn-sm" data-expl-quick="${ms}">${l}</button>`).join('')}</div>
      <div class="prism-fg prism-fg-end" style="gap:6px">
        <button type="button" class="btn btn-secondary btn-sm" data-expl="save">${t('ex.save_view')}</button>
        <button type="button" class="btn btn-secondary btn-sm" onclick="exportLogs('csv')">${t('logs.export_csv')}</button>
        <button type="button" class="btn btn-secondary btn-sm" onclick="exportLogs('json')">${t('logs.export_json')}</button>
      </div>
    </div>
    <div id="expl-views" class="logs-quick" style="margin-bottom:10px"></div>
    <div class="qbar" style="display:flex;gap:8px;margin-bottom:10px">
      <input type="text" id="expl-search" class="input search-input" style="flex:1" placeholder="${esc(t('ex.search_ph'))}" value="${esc(q.search)}">
    </div>
    <div id="expl-chips" class="filter-chips" style="margin-bottom:10px"></div>
    <div id="expl-hist" style="margin-bottom:12px"></div>
    <div class="explore-grid">
      <div id="expl-facets" class="expl-facets card blueprint" style="padding:14px"></div>
      <div class="card blueprint" style="padding:0;overflow:hidden;min-width:0">
        <div class="logs-desktop table-wrap">
          <table>
            <thead><tr><th>${t('logs.ts')}</th><th>${t('logs.level')}</th><th>${t('ex.col_where')}</th><th>${t('ex.col_summary')}</th><th></th></tr></thead>
            <tbody id="expl-tbody"><tr><td colspan="5" class="empty"><p>${t('common.loading')}</p></td></tr></tbody>
          </table>
        </div>
        <div id="expl-list" class="logs-mobile logs-list"></div>
        <div id="expl-pager" class="logs-pager"></div>
      </div>
    </div>
  </div>`;

  const root = document.getElementById('expl-root');
  root.addEventListener('click', ev => {
    const bar = ev.target.closest('[data-expl-bucket]');
    if (bar) {
      const r = gpxBucketISO(bar.getAttribute('data-expl-bucket'), bar.getAttribute('data-unit'));
      if (r) { q.quickMs = 0; q.from = r.from; q.to = r.to; refresh(); }
      return;
    }
    const quick = ev.target.closest('[data-expl-quick]');
    if (quick) {
      q.quickMs = parseInt(quick.dataset.explQuick, 10);
      q.from = new Date(Date.now() - q.quickMs).toISOString();
      q.to = '';
      refresh();
      return;
    }
    const fv = ev.target.closest('[data-expl-facet]');
    if (fv) {
      const f = fv.getAttribute('data-expl-facet'), v = fv.getAttribute('data-v');
      q[f] = q[f] === v ? '' : v;
      refresh();
      return;
    }
    const row = ev.target.closest('[data-expl-i]');
    if (row && !ev.target.closest('button,a')) { explOpenDrawer(rows[parseInt(row.dataset.explI, 10)], parseInt(row.dataset.explI, 10)); return; }
    const act = ev.target.closest('[data-expl]');
    if (!act) return;
    const a = act.getAttribute('data-expl');
    if (a === 'prev') loadRows(-1);
    else if (a === 'next') { cursorStack.push(parseInt(act.dataset.before, 10) || 0); loadRows(lastID); }
    else if (a === 'kind') { q.kind = act.value; refresh(); }
    else if (a === 'clear') { q[act.dataset.f] = ''; refresh(); }
    else if (a === 'clearall') { for (const f of EXPL_FACETS) q[f] = ''; q.search = ''; refresh(); }
    else if (a === 'save') {
      const name = prompt(t('ex.view_name_ph'));
      if (!name) return;
      const views = explLoadViews();
      views.unshift({ name, q: { ...q } });
      explSaveViews(views);
      renderViews();
      toast(t('ex.view_saved'), 'success');
    }
    else if (a === 'loadview') {
      const v = explLoadViews()[parseInt(act.dataset.i, 10)];
      if (v) { Object.assign(q, v.q); if (scope.lock) q.node_name = scope.node_name; refresh(); }
    }
    else if (a === 'delview') {
      const views = explLoadViews();
      views.splice(parseInt(act.dataset.i, 10), 1);
      explSaveViews(views);
      renderViews();
    }
    else if (a === 'dclose') explCloseDrawer();
    else if (a === 'dcorr') { explCloseDrawer(); showCorrelate(act.dataset.domain, act.dataset.ts); }
    else if (a === 'dprism') { explCloseDrawer(); openPrismFromLogs({ proxy: act.dataset.domain, ip: act.dataset.ip }); }
  });
  root.addEventListener('change', ev => { if (ev.target.id === 'expl-kind') { q.kind = ev.target.value; refresh(); } });
  root.addEventListener('input', ev => {
    if (ev.target.id !== 'expl-search') return;
    q.search = ev.target.value;
    clearTimeout(root._t);
    root._t = setTimeout(() => { loadRows(0); loadHist(); loadFacets(); renderChips(); }, 350);
  });
  root.addEventListener('keydown', ev => { if (ev.key === 'Enter' && ev.target.id === 'expl-search') { clearTimeout(root._t); loadRows(0); loadHist(); loadFacets(); renderChips(); } });

  refresh();
}

function explRow(e, i) {
  const isSys = !e.status;
  return `<tr data-expl-i="${i}" style="cursor:pointer">
    <td class="mono" style="font-size:11px;white-space:nowrap">${esc(fmtDate(e.ts))}</td>
    <td>${logLvlBadge(e.level)}</td>
    <td class="mono" style="font-size:11px">${esc(e.node_name || e.component || '—')}</td>
    <td class="logs-cell-clip" style="font-size:12px;max-width:420px">${isSys
      ? esc(e.message || '—')
      : `<b>${esc(e.method || '')}</b> ${esc((e.domain || '') + (e.path || ''))} ${httpStatusBadge(e.status)}`}</td>
    <td style="white-space:nowrap">${corrIconBtn(e.domain, e.ts)}${prismIconBtn(e.domain, e.ip)}</td>
  </tr>`;
}

function explEntry(e, i) {
  const isSys = !e.status;
  return `<article class="log-entry" data-expl-i="${i}">
    <div class="log-entry-top">
      <span class="log-entry-ts">${esc(fmtDate(e.ts))}</span>
      ${logLvlBadge(e.level)}
      <span class="chip" style="font-size:11px">${esc(e.node_name || e.component || '—')}</span>
      ${!isSys ? httpStatusBadge(e.status) : ''}
    </div>
    <div class="log-entry-msg">${isSys ? esc(e.message || '—') : esc((e.method || '') + ' ' + (e.domain || '') + (e.path || ''))}</div>
  </article>`;
}

function explOpenDrawer(e, i) {
  explCloseDrawer();
  const isSys = !e.status;
  const row = (k, v) => v ? `<div class="prism-dstat"><span>${esc(k)}</span><b style="font-size:13px;word-break:break-word">${v}</b></div>` : '';
  const dr = document.createElement('aside');
  dr.id = 'expl-drawer';
  dr.className = 'prism-drawer open';
  dr.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <span class="prism-panel-title" style="margin:0">${esc(t('lg.detail'))}</span>
      <button type="button" class="btn btn-ghost btn-sm" data-expl="dclose">✕</button>
    </div>
    <div style="margin-bottom:10px">${logLvlBadge(e.level)} ${!isSys ? httpStatusBadge(e.status) : ''} ${!isSys ? `<b>${esc(e.method || '')}</b> <span class="mono" style="word-break:break-all">${esc((e.domain || '') + (e.path || ''))}</span>` : ''}</div>
    <div class="prism-dstats" style="grid-template-columns:1fr">
      ${row(t('logs.ts'), esc(fmtDate(e.ts)))}
      ${row(t('logs.node'), esc(e.node_name || ''))}
      ${row(t('logs.component'), esc(e.component || ''))}
      ${row(t('logs.ip'), e.ip ? `<span class="mono">${esc(e.ip)}</span>` : '')}
      ${row(t('lg.latency'), e.latency_ms != null ? esc(String(e.latency_ms)) + ' ms' : '')}
      ${row(t('lg.request_id'), e.request_id ? `<span class="mono">${esc(e.request_id)}</span>` : '')}
    </div>
    <pre class="mono" style="white-space:pre-wrap;word-break:break-word;background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius);padding:10px;font-size:12px;margin:12px 0">${esc(e.message || '—')}</pre>
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      ${!isSys ? `<button type="button" class="btn btn-secondary btn-sm" data-expl="dprism" data-domain="${esc(e.domain || '')}" data-ip="${esc(e.ip || '')}">${esc(t('lg.open_prism'))}</button>` : ''}
      ${e.domain && e.ts ? `<button type="button" class="btn btn-secondary btn-sm" data-expl="dcorr" data-domain="${esc(e.domain)}" data-ts="${esc(e.ts)}">${esc(t('logs.correlate'))}</button>` : ''}
    </div>`;
  document.getElementById('expl-root').appendChild(dr);
}
function explCloseDrawer() { document.getElementById('expl-drawer')?.remove(); }
