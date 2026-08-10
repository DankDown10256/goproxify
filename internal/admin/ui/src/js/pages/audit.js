// ── PAGE: Audit Log
// Extrait de pages-all.js — phase 4.

// ── PAGE: Audit Log ────────────────────────────────────────────────────────
pages.audit = async function() {
  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML = `
    <button class="btn btn-secondary btn-sm" onclick="exportAudit('json')">${t('logs.export_json')}</button>
    <button class="btn btn-secondary btn-sm" onclick="exportAudit('csv')">${t('logs.export_csv')}</button>`;

  const q = { component: '', action: '', actor: '', severity: '' };

  async function loadAudit(offset = 0) {
    const params = new URLSearchParams({ limit: 50, offset });
    if (q.component) params.set('component', q.component);
    if (q.action) params.set('action', q.action);
    if (q.actor) params.set('actor', q.actor);
    if (q.severity) params.set('severity', q.severity);
    try {
      const data = await api('GET', '/audit?' + params);
      const entries = data?.entries || [];
      const total = data?.total || 0;
      const tbody = document.getElementById('audit-tbody');
      if (!tbody) return;
      tbody.innerHTML = entries.length ? entries.map(e => `<tr>
        <td class="mono">${esc(e.created_at ? new Date(e.created_at).toLocaleString(typeof gpxBCP47==='function'?gpxBCP47():'en-US') : '—')}</td>
        <td><span class="tag tag-neutral">${esc(e.component)}</span></td>
        <td>${esc(e.actor || '—')}</td>
        <td>${esc(e.ip || '—')}</td>
        <td><b>${esc(e.action)}</b>${e.resource_type ? ` <span style="color:var(--text3)">${esc(e.resource_type)}${e.resource_id ? ':'+esc(e.resource_id) : ''}</span>` : ''}</td>
        <td>${auditSevBadge(e.severity)}</td>
        <td style="color:var(--text2);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(e.detail)}">${esc(e.detail || '—')}</td>
      </tr>`).join('') : `<tr><td colspan="7" class="empty"><p>${t('audit.empty')}</p></td></tr>`;
      const pager = document.getElementById('audit-pager');
      if (pager) pager.innerHTML = `<span style="color:var(--text2);font-size:12px">${t('audit.events', { n: total })}</span>
        ${offset > 0 ? `<button class="btn btn-secondary btn-sm" onclick="auditPage(${offset - 50})">${t('logs.prev')}</button>` : ''}
        ${offset + 50 < total ? `<button class="btn btn-secondary btn-sm" onclick="auditPage(${offset + 50})">${t('logs.next')}</button>` : ''}`;
    } catch(e) { toast(e.message, 'error'); }
  }

  window.auditPage = (off) => loadAudit(off);
  window.auditFilter = () => {
    q.component = document.getElementById('aud-comp')?.value || '';
    q.action    = document.getElementById('aud-act')?.value || '';
    q.actor     = document.getElementById('aud-actor')?.value || '';
    q.severity  = document.getElementById('aud-sev')?.value || '';
    loadAudit(0);
  };

  content.innerHTML = `
    <div class="search-bar" style="flex-wrap:wrap;gap:8px">
      <select id="aud-comp" class="input" style="max-width:140px" onchange="auditFilter()">
        <option value="">${t('logs.comp_ph')}</option>
        <option>admin</option><option>core</option><option>agent</option>
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
    </div>`;
  loadAudit(0);
};

function auditSevBadge(s) {
  const m = { info: 'tag-neutral', warning: 'tag-yellow', critical: 'tag-red' };
  return `<span class="tag ${m[s]||'tag-neutral'}">${esc(s||'info')}</span>`;
}

window.exportAudit = function(fmt) {
  const params = new URLSearchParams({ format: fmt });
  const a = document.createElement('a');
  a.href = '/api/v1/audit/export?' + params + '&_auth=' + encodeURIComponent(state.token);
  a.download = 'audit.' + fmt;
  // Export via fetch pour inclure l'Authorization header
  api('GET', '/audit/export?' + params).then(data => {
    if (!data) return;
    const blob = new Blob([fmt === 'csv' ? data : JSON.stringify(data, null, 2)], { type: fmt === 'csv' ? 'text/csv' : 'application/json' });
    const url = URL.createObjectURL(blob);
    const a2 = document.createElement('a'); a2.href = url; a2.download = 'audit.' + fmt;
    a2.click(); URL.revokeObjectURL(url);
  }).catch(e => toast(t('audit.export_failed', { msg: e.message }), 'error'));
};
