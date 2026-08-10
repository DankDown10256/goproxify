// ── PAGE: Templates HTML Access (clés stables KTD2)
pages['portal-templates'] = async function() {
  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML =
    `<button class="btn btn-secondary" id="ptpl-push">${esc(t('portal.tpl_push') || 'Pousser aux Cores')}</button>`;
  await refreshPortalTemplates(content);
  const pushBtn = document.getElementById('ptpl-push');
  if (pushBtn) pushBtn.onclick = async () => {
    try {
      await api('POST', '/portal-page-templates/push');
      toast(t('portal.tpl_pushed') || 'Templates poussés.', 'success');
    } catch (e) { toast(e.message || String(e), 'error'); }
  };
};

async function refreshPortalTemplates(content) {
  content = content || document.getElementById('content');
  try {
    const d = await api('GET', '/portal-page-templates') || {};
    const list = d.templates || [];
    content.innerHTML = `
      <div class="card blueprint" style="margin-bottom:16px;padding:14px 16px;font-size:12px;color:var(--text2);line-height:1.5">
        ${t('portal.tpl_banner') || 'Templates HTML Access (clés stables). Placeholders : <code>{{brand}}</code> <code>{{user_email}}</code> <code>{{core_name}}</code> <code>{{csrf}}</code> <code>{{content}}</code>. Corps vide = fallback embarqué (SPA).'}
      </div>
      <div class="card blueprint">
        <div class="table-wrap">
          <table>
            <thead><tr>
              <th>${esc(t('portal.tpl_col_key') || 'Clé')}</th>
              <th>${esc(t('portal.tpl_col_name') || 'Nom')}</th>
              <th>${esc(t('portal.tpl_col_status') || 'État')}</th>
              <th>${esc(t('portal.tpl_col_modified') || 'Modifié')}</th>
              <th></th>
            </tr></thead>
            <tbody>
              ${list.map(tpl => {
                const custom = !!(tpl.body && String(tpl.body).trim());
                return `<tr>
                  <td><code>${esc(tpl.key)}</code></td>
                  <td>${esc(tpl.name || tpl.key)}</td>
                  <td>${custom ? (t('portal.tpl_custom') || 'Personnalisé') : (t('portal.tpl_default') || 'Fallback')}</td>
                  <td>${tpl.updated_at ? fmtDate(tpl.updated_at) : '—'}</td>
                  <td>
                    <button class="btn btn-ghost btn-sm" onclick="openPortalTemplateModal('${esc(tpl.key)}')">${esc(t('common.edit') || 'Éditer')}</button>
                    ${custom ? `<button class="btn btn-ghost btn-sm" onclick="resetPortalTemplate('${esc(tpl.key)}')">${esc(t('portal.tpl_reset') || 'Reset')}</button>` : ''}
                  </td>
                </tr>`;
              }).join('')}
            </tbody>
          </table>
        </div>
      </div>`;
  } catch (e) {
    content.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`;
  }
}

window.resetPortalTemplate = async function(key) {
  if (!confirm(t('portal.tpl_reset_confirm') || 'Revenir au fallback embarqué ?')) return;
  try {
    await api('DELETE', '/portal-page-templates/' + encodeURIComponent(key));
    await refreshPortalTemplates();
  } catch (e) { toast(e.message || String(e), 'error'); }
};

window.openPortalTemplateModal = async function(key) {
  let tpl = { key, name: key, body: '' };
  try {
    tpl = await api('GET', '/portal-page-templates/' + encodeURIComponent(key)) || tpl;
  } catch (_) {}
  modal(t('portal.tpl_edit') || 'Template Access', `
    <div class="field">
      <label class="field-label">Clé</label>
      <input class="input" id="ptpl-key" value="${esc(tpl.key)}" disabled>
    </div>
    <div class="field">
      <label class="field-label">Nom</label>
      <input class="input" id="ptpl-name" value="${esc(tpl.name || key)}">
    </div>
    <div class="field">
      <label class="field-label">HTML</label>
      <textarea class="input" id="ptpl-body" rows="16" style="font-family:ui-monospace,monospace;font-size:12px">${esc(tpl.body || '')}</textarea>
    </div>
    <p style="font-size:11px;color:var(--text3);margin:0">{{brand}} {{user_email}} {{core_name}} {{csrf}} {{content}}</p>
  `,
  `<button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel') || 'Annuler'}</button>
   <button class="btn btn-primary" onclick="savePortalTemplate('${esc(key)}')">${t('common.save') || 'Enregistrer'}</button>`,
  true);
};

window.savePortalTemplate = async function(key) {
  try {
    await api('PUT', '/portal-page-templates/' + encodeURIComponent(key), {
      name: document.getElementById('ptpl-name').value.trim() || key,
      body: document.getElementById('ptpl-body').value,
    });
    closeModal();
    await refreshPortalTemplates();
    toast(t('common.saved') || 'Enregistré', 'success');
  } catch (e) { toast(e.message || String(e), 'error'); }
};
