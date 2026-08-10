// ── PAGE: Snippets
// Extrait de pages-all.js — phase 4.

// ── PAGE: Snippets ─────────────────────────────────────────────────────────
const SNIPPET_TYPES = ['ip_filter','rate_limit','cors','headers','tls','geo_ip','bot','waf'];
pages.snippets = async function() {
  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML =
    `<button class="btn btn-primary" onclick="openSnippetModal()">${t('snippets.new')}</button>`;
  await refreshSnippets(content);
};

async function refreshSnippets(content) {
  content = content || document.getElementById('content');
  try {
    const list = await api('GET', '/snippets') || [];
    content.innerHTML = `
      <div class="search-bar">
        <select class="input" style="width:160px" onchange="filterSnippetType(this.value)">
          <option value="">${t('snippets.all_types')}</option>
          ${SNIPPET_TYPES.map(st=>`<option value="${st}">${st}</option>`).join('')}
        </select>
      </div>
      <div class="card blueprint">
        <div class="table-wrap">
          <table>
            <thead><tr><th>${t('snippets.col.name')}</th><th>${t('snippets.col.type')}</th><th>${t('snippets.col.description')}</th><th>${t('snippets.col.modified')}</th><th>${t('snippets.col.actions')}</th></tr></thead>
            <tbody id="snippet-tbody">
              ${list.length ? list.map(s=>`<tr data-type="${esc(s.type)}">
                <td><b>${esc(s.name)}</b></td>
                <td><span class="tag tag-neutral">${esc(s.type)}</span></td>
                <td style="color:var(--text2)">${esc(s.description||'—')}</td>
                <td>${fmtDate(s.updated_at)}</td>
                <td>
                  <button class="btn btn-ghost btn-icon btn-sm" onclick="openSnippetModal('${esc(s.id)}')" title="${esc(t('common.edit'))}"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>
                  <button class="btn btn-ghost btn-icon btn-sm" onclick="deleteSnippet('${esc(s.id)}')" title="${esc(t('common.delete'))}"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg></button>
                </td>
              </tr>`).join('') : `<tr><td colspan="5" class="empty"><p>${t('snippets.empty')}</p></td></tr>`}
            </tbody>
          </table>
        </div>
      </div>`;
  } catch(e) { content.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`; }
}

window.filterSnippetType = function(type) {
  document.querySelectorAll('#snippet-tbody tr').forEach(tr => {
    tr.style.display = !type || tr.dataset.type === type ? '' : 'none';
  });
};

window.openSnippetModal = async function(id) {
  let existing = null;
  if (id) { try { existing = await api('GET',`/snippets/${id}`); } catch {} }
  modal(id ? t('snippets.edit') : t('snippets.new_modal'), `
    <div class="form-row">
      <div class="field">
        <label class="field-label">${t('snippets.name')}</label>
        <input id="s-name" class="input" placeholder="mon-snippet" value="${esc(existing?.name||'')}">
      </div>
      <div class="field">
        <label class="field-label">${t('snippets.type')}</label>
        <select id="s-type" class="input">
          ${SNIPPET_TYPES.map(st=>`<option value="${st}" ${existing?.type===st?'selected':''}>${st}</option>`).join('')}
        </select>
      </div>
    </div>
    <div class="field">
      <label class="field-label">${t('snippets.description')}</label>
      <input id="s-desc" class="input" placeholder="${esc(t('snippets.desc_ph'))}" value="${esc(existing?.description||'')}">
    </div>
    <div class="field">
      <label class="field-label">${t('snippets.config')}</label>
      <textarea id="s-config" class="input" rows="8" placeholder='{"cidrs":["10.0.0.0/8"],"mode":"allow"}'>${esc(existing?.config ? JSON.stringify(JSON.parse(existing.config),null,2) : '')}</textarea>
    </div>`,
    `<button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel')}</button>
     <button class="btn btn-primary" onclick="saveSnippet('${esc(id||'')}')">${t('common.save')}</button>`);
};

window.saveSnippet = async function(id) {
  const payload = {
    name: document.getElementById('s-name').value.trim(),
    type: document.getElementById('s-type').value,
    description: document.getElementById('s-desc').value.trim(),
    config: document.getElementById('s-config').value.trim(),
  };
  try {
    if (id) await api('PUT', `/snippets/${id}`, payload);
    else await api('POST', '/snippets', payload);
    toast(t('snippets.saved'), 'success');
    closeModal();
    refreshSnippets();
  } catch(e) { toast(e.message, 'error'); }
};
window.deleteSnippet = function(id) {
  confirm_(t('snippets.delete_confirm'), async () => {
    try { await api('DELETE', `/snippets/${id}`); toast(t('snippets.deleted'),'success'); refreshSnippets(); }
    catch(e) { toast(e.message,'error'); }
  });
};

