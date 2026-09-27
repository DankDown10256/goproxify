// ── PAGE: Journal d'audit ─────────────────────────────────────────────────────
// Filtres (composant, action, acteur, gravité), périodes rapides, histogramme des actions
// et tiroir de détail. Le tableau, l'histogramme et l'export partagent les mêmes filtres.

const AUDIT_PERIODS = [['1h', 3600000], ['24h', 86400000], ['7d', 604800000], ['30d', 2592000000]];
const AUDIT_PAGE = 50;

pages.audit = async function() {
  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML = `
    <button class="btn btn-secondary btn-sm" onclick="exportAudit('json')">${t('logs.export_json')}</button>
    <button class="btn btn-secondary btn-sm" onclick="exportAudit('csv')">${t('logs.export_csv')}</button>`;

  let rows = [];
  let offset = 0;
  window._auditQ = { component: '', action: '', actor: '', severity: '', from: '', to: '', quickMs: 0 };
  const q = window._auditQ;

  function params(extra = {}) {
    const p = new URLSearchParams(extra);
    for (const k of ['component', 'action', 'actor', 'severity', 'from', 'to']) if (q[k]) p.set(k, q[k]);
    return p;
  }

  function quickHTML() {
    const per = AUDIT_PERIODS.map(([k, ms]) => `<button type="button" class="chip${q.quickMs === ms ? ' active' : ''}" data-aud-quick="${ms}">${k}</button>`).join('')
      + `<button type="button" class="chip${q.quickMs ? '' : ' active'}" data-aud-quick="0">${esc(t('lg.q_all'))}</button>`;
    const sev = ['info', 'warning', 'critical'].map(s => `<button type="button" class="chip${q.severity === s ? ' active' : ''}" data-aud-sev="${s}">${s}</button>`).join('');
    return `<div class="logs-quick"><div class="logs-quick-g">${per}</div><div class="logs-quick-g">${sev}</div></div>`;
  }

  async function loadHist() {
    const el = document.getElementById('aud-hist');
    if (!el) return;
    const to = q.to ? new Date(q.to) : new Date();
    const from = q.from ? new Date(q.from) : new Date(to - 86400000);
    const unit = to - from <= 21600000 ? 'minute' : to - from > 8 * 86400000 ? 'day' : 'hour';
    const p = params({ bucket: unit });
    p.set('from', from.toISOString());
    if (q.to) p.set('to', to.toISOString());
    const data = await api('GET', '/audit/histogram?' + p).catch(() => null);
    if (!document.getElementById('aud-hist')) return;
    const pts = (data?.points || []).map(x => ({ bucket: x.bucket, total: x.total, warn: x.warn, error: x.critical }));
    el.innerHTML = gpxHistHTML(pts, unit, { attr: 'data-aud-bucket', title: t('au.hist_title'), hint: t('lg.hist_hint') });
  }

  async function loadAudit(off = 0) {
    offset = off;
    try {
      const data = await api('GET', '/audit?' + params({ limit: AUDIT_PAGE, offset }));
      const entries = data?.entries || [];
      const total = data?.total || 0;
      rows = entries;
      const tbody = document.getElementById('audit-tbody');
      if (!tbody) return;
      tbody.innerHTML = entries.length ? entries.map((e, i) => `<tr data-aud-i="${i}">
        <td class="mono">${esc(e.created_at && !String(e.created_at).startsWith('0001') ? new Date(e.created_at).toLocaleString(typeof gpxBCP47==='function'?gpxBCP47():'en-US') : '—')}</td>
        <td><span class="tag tag-neutral">${esc(e.component)}</span></td>
        <td>${esc(e.actor || '—')}</td>
        <td>${esc(e.ip || '—')}</td>
        <td><b>${esc(e.action)}</b>${e.resource_type ? ` <span style="color:var(--text3)">${esc(e.resource_type)}${e.resource_id ? ':'+esc(e.resource_id) : ''}</span>` : ''}</td>
        <td>${auditSevBadge(e.severity)}</td>
        <td style="color:var(--text2);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(e.detail)}">${esc(e.detail || '—')}</td>
      </tr>`).join('') : `<tr><td colspan="7" class="empty"><p>${t('audit.empty')}</p></td></tr>`;
      const pager = document.getElementById('audit-pager');
      if (pager) pager.innerHTML = `<span style="color:var(--text2);font-size:12px">${t('audit.events', { n: total })}</span>
        ${offset > 0 ? `<button class="btn btn-secondary btn-sm" onclick="auditPage(${offset - AUDIT_PAGE})">${t('logs.prev')}</button>` : ''}
        ${offset + AUDIT_PAGE < total ? `<button class="btn btn-secondary btn-sm" onclick="auditPage(${offset + AUDIT_PAGE})">${t('logs.next')}</button>` : ''}`;
    } catch(e) { toast(e.message, 'error'); }
  }

  function syncInputs() {
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v || ''; };
    set('aud-comp', q.component); set('aud-act', q.action); set('aud-actor', q.actor); set('aud-sev', q.severity);
  }

  function refresh() {
    syncInputs();
    const w = document.getElementById('aud-quick');
    if (w) w.innerHTML = quickHTML();
    loadAudit(0);
    loadHist();
  }

  function closeDrawer() { document.getElementById('aud-drawer')?.remove(); }

  function openDrawer(e, i) {
    closeDrawer();
    const line = (k, v) => v ? `<div class="prism-dstat"><span>${esc(k)}</span><b style="font-size:13px;word-break:break-word">${v}</b></div>` : '';
    let detail = esc(e.detail || '—');
    try {
      const j = JSON.parse(e.detail);
      if (j && typeof j === 'object') detail = esc(JSON.stringify(j, null, 2));
    } catch { /* détail en texte libre */ }
    const btn = (act, label, extra = '') => `<button type="button" class="btn btn-secondary btn-sm" ${extra} data-aud-act="${act}" data-aud-di="${i}">${esc(label)}</button>`;
    const dr = document.createElement('aside');
    dr.id = 'aud-drawer';
    dr.className = 'prism-drawer open';
    dr.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <span class="prism-panel-title" style="margin:0">${esc(t('au.detail'))}</span>
        <button type="button" class="btn btn-ghost btn-sm" data-aud-act="close" data-aud-di="${i}">✕</button>
      </div>
      <div style="margin-bottom:10px">${auditSevBadge(e.severity)} <b>${esc(e.action)}</b></div>
      <div class="prism-dstats" style="grid-template-columns:1fr">
        ${line(t('audit.col_date'), esc(e.created_at ? new Date(e.created_at).toLocaleString(typeof gpxBCP47==='function'?gpxBCP47():'en-US') : ''))}
        ${line(t('logs.component'), esc(e.component))}
        ${line(t('audit.col_actor'), esc(e.actor || ''))}
        ${line(t('logs.ip'), e.ip ? `<span class="mono">${esc(e.ip)}</span>` : '')}
        ${line(t('au.resource'), e.resource_type ? `<span class="mono">${esc(e.resource_type)}${e.resource_id ? ':' + esc(e.resource_id) : ''}</span>` : '')}
      </div>
      <div class="prism-panel-title" style="margin:14px 0 6px">${esc(t('audit.col_detail'))}</div>
      <pre class="mono" style="white-space:pre-wrap;word-break:break-word;background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius);padding:10px;font-size:12px;margin:0">${detail}</pre>
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:14px">
        ${e.actor ? btn('actor', t('au.filter_actor')) : ''}
        ${e.action ? btn('action', t('au.filter_action')) : ''}
        ${e.ip ? btn('iplogs', t('au.view_ip_logs')) : ''}
        ${btn('copy', t('lg.copy_json'))}
      </div>`;
    document.getElementById('audit-root').appendChild(dr);
  }

  async function onDrawerAct(act, i) {
    const e = rows[i];
    if (act === 'close') { closeDrawer(); return; }
    if (!e) return;
    if (act === 'actor') { closeDrawer(); q.actor = e.actor; refresh(); }
    else if (act === 'action') { closeDrawer(); q.action = e.action; refresh(); }
    else if (act === 'iplogs') { if (typeof openLogsFiltered === 'function') openLogsFiltered({ ip: e.ip }); }
    else if (act === 'copy') {
      const txt = JSON.stringify(e, null, 2);
      try { await navigator.clipboard.writeText(txt); toast(t('lg.copied'), 'success'); } catch { toast(txt.slice(0, 200), 'info'); }
    }
  }

  window.auditPage = (off) => loadAudit(off);
  window.auditFilter = () => {
    q.component = document.getElementById('aud-comp')?.value || '';
    q.action    = document.getElementById('aud-act')?.value || '';
    q.actor     = document.getElementById('aud-actor')?.value || '';
    q.severity  = document.getElementById('aud-sev')?.value || '';
    const w = document.getElementById('aud-quick');
    if (w) w.innerHTML = quickHTML();
    loadAudit(0);
    loadHist();
  };

  content.innerHTML = `<div id="audit-root">
    <div id="aud-quick">${quickHTML()}</div>
    <div id="aud-hist"></div>
    <div class="search-bar" style="flex-wrap:wrap;gap:8px">
      <select id="aud-comp" class="input" style="max-width:140px" onchange="auditFilter()">
        <option value="">${t('logs.comp_ph')}</option>
        <option>admin</option><option>edge</option><option>agent</option>
      </select>
      <input id="aud-act" class="input search-input" placeholder="${esc(t('audit.action_ph'))}" oninput="auditFilter()">
      <input id="aud-actor" class="input search-input" placeholder="${esc(t('audit.actor_ph'))}" oninput="auditFilter()">
      <select id="aud-sev" class="input" style="max-width:130px" onchange="auditFilter()">
        <option value="">${t('audit.severity_ph')}</option>
        <option>info</option><option>warning</option><option>critical</option>
      </select>
    </div>
    <div class="card blueprint" style="padding:0">
      <div class="table-wrap">
        <table>
          <thead><tr><th>${t('audit.col_date')}</th><th>${t('logs.component')}</th><th>${t('audit.col_actor')}</th><th>${t('logs.ip')}</th><th>${t('audit.col_action')}</th><th>${t('audit.col_severity')}</th><th>${t('audit.col_detail')}</th></tr></thead>
          <tbody id="audit-tbody"><tr><td colspan="7" class="empty"><p>${t('common.loading')}</p></td></tr></tbody>
        </table>
      </div>
      <div id="audit-pager" style="padding:12px 16px;display:flex;align-items:center;gap:8px"></div>
    </div></div>`;

  document.getElementById('audit-root').addEventListener('click', ev => {
    const quick = ev.target.closest('[data-aud-quick]');
    if (quick) {
      q.quickMs = parseInt(quick.getAttribute('data-aud-quick'), 10) || 0;
      q.from = q.quickMs ? new Date(Date.now() - q.quickMs).toISOString() : '';
      q.to = '';
      refresh();
      return;
    }
    const sev = ev.target.closest('[data-aud-sev]');
    if (sev) {
      const s = sev.getAttribute('data-aud-sev');
      q.severity = q.severity === s ? '' : s;
      refresh();
      return;
    }
    const bar = ev.target.closest('[data-aud-bucket]');
    if (bar) {
      const r = gpxBucketISO(bar.getAttribute('data-aud-bucket'), bar.getAttribute('data-unit'));
      if (r) { q.quickMs = 0; q.from = r.from; q.to = r.to; refresh(); }
      return;
    }
    const act = ev.target.closest('[data-aud-act]');
    if (act) { onDrawerAct(act.getAttribute('data-aud-act'), parseInt(act.getAttribute('data-aud-di'), 10)); return; }
    if (ev.target.closest('#aud-drawer')) return;
    const row = ev.target.closest('tr[data-aud-i]');
    if (row) { const i = parseInt(row.getAttribute('data-aud-i'), 10); openDrawer(rows[i], i); }
  });
  loadAudit(0);
  loadHist();
};

function auditSevBadge(s) {
  const m = { info: 'tag-neutral', warning: 'tag-yellow', critical: 'tag-red' };
  return `<span class="tag ${m[s]||'tag-neutral'}">${esc(s||'info')}</span>`;
}

// L'export applique les filtres de la page (composant, action, acteur, gravité, période).
window.exportAudit = function(fmt) {
  const q = window._auditQ || {};
  const params = new URLSearchParams({ format: fmt });
  for (const k of ['component', 'action', 'actor', 'severity', 'from', 'to']) if (q[k]) params.set(k, q[k]);
  api('GET', '/audit/export?' + params).then(data => {
    if (!data) return;
    const blob = new Blob([fmt === 'csv' ? data : JSON.stringify(data, null, 2)], { type: fmt === 'csv' ? 'text/csv' : 'application/json' });
    const url = URL.createObjectURL(blob);
    const a2 = document.createElement('a'); a2.href = url; a2.download = 'audit.' + fmt;
    a2.click(); URL.revokeObjectURL(url);
  }).catch(e => toast(t('audit.export_failed', { msg: e.message }), 'error'));
};
