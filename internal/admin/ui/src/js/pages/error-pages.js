// ── PAGE: Pages d'erreur (bibliothèque Admin)
pages['error-pages'] = async function() {
  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML =
    `<button class="btn btn-primary" onclick="openErrorPageModal()">${t('errpages.new')}</button>`;
  await refreshErrorPages(content);
};

async function refreshErrorPages(content) {
  content = content || document.getElementById('content');
  try {
    const list = await api('GET', '/error-page-templates') || [];
    content.innerHTML = `
      <div class="card blueprint" style="margin-bottom:16px;padding:14px 16px;font-size:12px;color:var(--text2);line-height:1.5">
        ${t('errpages.banner')}
      </div>
      <div class="card blueprint">
        <div class="table-wrap">
          <table>
            <thead><tr><th>${t('errpages.col.name')}</th><th>${t('errpages.col.description')}</th><th>${t('errpages.col.assets')}</th><th>${t('errpages.col.modified')}</th><th>${t('errpages.col.actions')}</th></tr></thead>
            <tbody>
              ${list.length ? list.map(tpl => `<tr>
                <td><b>${esc(tpl.name)}</b></td>
                <td style="color:var(--text2)">${esc(tpl.description || '—')}</td>
                <td>${(tpl.assets||[]).length}</td>
                <td>${fmtDate(tpl.updated_at)}</td>
                <td>
                  <button class="btn btn-ghost btn-icon btn-sm" onclick="openErrorPageModal('${esc(tpl.id)}')" title="${esc(t('common.edit'))}"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>
                  <button class="btn btn-ghost btn-icon btn-sm" onclick="deleteErrorPage('${esc(tpl.id)}')" title="${esc(t('common.delete'))}"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg></button>
                </td>
              </tr>`).join('') : `<tr><td colspan="5" class="empty"><p>${t('errpages.empty')}</p></td></tr>`}
            </tbody>
          </table>
        </div>
      </div>`;
  } catch (e) {
    content.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`;
  }
}

window._epPendingAssets = [];

window.openErrorPageModal = async function(id) {
  let existing = null;
  if (id) {
    try { existing = await api('GET', `/error-page-templates/${id}`); } catch {}
  }
  window._epPendingAssets = [];
  const assets = existing?.assets || [];
  const assetList = assets.map(a =>
    `<div style="display:flex;gap:8px;align-items:center;font-size:12px;margin-bottom:4px">
      <code>${esc(a.filename)}</code>
      <span style="color:var(--text3)">${esc(a.content_type)} · ${a.size||0} o</span>
      <code style="color:var(--text3);font-size:10px">/_goproxify/error-pages/${esc(existing.id)}/${esc(a.filename)}</code>
      <button type="button" class="btn-icon" onclick="deleteErrorPageAsset('${esc(id)}','${esc(a.filename)}')">×</button>
    </div>`
  ).join('') || `<div style="font-size:12px;color:var(--text3)">${t('errpages.no_assets')}</div>`;

  modal(id ? t('errpages.edit') : t('errpages.new_modal'), `
    <div class="form-row">
      <div class="field" style="flex:1">
        <label class="field-label">${t('errpages.name')}</label>
        <input id="ep-name" class="input" placeholder="${esc(t('errpages.name_ph'))}" value="${esc(existing?.name||'')}">
      </div>
    </div>
    <div class="field">
      <label class="field-label">${t('errpages.description')}</label>
      <input id="ep-desc" class="input" placeholder="${esc(t('errpages.desc_ph'))}" value="${esc(existing?.description||'')}">
    </div>
    <div class="field">
      <label class="field-label">${t('errpages.html')}</label>
      <textarea id="ep-body" class="input" rows="12" placeholder="<!DOCTYPE html>…">${esc(existing?.body||defaultErrorPageBody())}</textarea>
    </div>
    <div class="field">
      <label class="field-label">${t('errpages.assets')}</label>
      <div id="ep-assets-list" style="margin-bottom:8px">${assetList}</div>
      <div id="ep-dropzone" style="border:2px dashed var(--border);border-radius:var(--radius);padding:18px;text-align:center;cursor:pointer;margin-bottom:8px;transition:border-color .2s,background .2s"
        onclick="document.getElementById('ep-asset-file').click()"
        ondragover="event.preventDefault();event.stopPropagation();this.style.borderColor='var(--accent)';this.style.background='var(--bg3)'"
        ondragleave="event.preventDefault();event.stopPropagation();this.style.borderColor='var(--border)';this.style.background=''"
        ondrop="event.preventDefault();event.stopPropagation();this.style.borderColor='var(--border)';this.style.background='';window._epAddPendingAssets(event.dataTransfer.files)">
        <svg width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24" style="opacity:.45;margin-bottom:6px"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
        <p style="font-size:12px;color:var(--text3);margin:0">${t('errpages.drop_hint')}</p>
        <input type="file" id="ep-asset-file" style="display:none" multiple accept="image/*,.css,.woff,.woff2,.svg,.ico"
          onchange="window._epAddPendingAssets(this.files);this.value=''">
      </div>
      <div id="ep-pending-assets" style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:4px"></div>
      <div style="font-size:11px;color:var(--text3);margin-top:4px">${t('errpages.upload_hint')}</div>
    </div>
    <div class="field">
      <label class="field-label">${t('errpages.preview')}</label>
      <iframe id="ep-preview" sandbox="" style="width:100%;height:220px;border:1px solid var(--border);border-radius:8px;background:#fff"></iframe>
    </div>`,
    `<button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel')}</button>
     <button class="btn btn-primary" onclick="saveErrorPage('${esc(id||'')}')">${t('common.save')}</button>`,
    true);

  const bodyEl = document.getElementById('ep-body');
  const refreshPreview = () => {
    const iframe = document.getElementById('ep-preview');
    if (!iframe || !bodyEl) return;
    let html = bodyEl.value
      .replace(/\{\{\s*status\s*\}\}/g, '502')
      .replace(/\{\{\s*title\s*\}\}/g, t('errpages.preview_title'))
      .replace(/\{\{\s*message\s*\}\}/g, t('errpages.preview_message'))
      .replace(/\{\{\s*host\s*\}\}/g, t('errpages.preview_host'))
      .replace(/\{\{\s*request_id\s*\}\}/g, 'abc123')
      .replace(/\{\{\s*log_url\s*\}\}/g, '#');
    iframe.srcdoc = html;
  };
  bodyEl?.addEventListener('input', refreshPreview);
  refreshPreview();
  renderEpPendingAssets();
};

function renderEpPendingAssets() {
  const el = document.getElementById('ep-pending-assets');
  if (!el) return;
  const files = window._epPendingAssets || [];
  if (!files.length) {
    el.innerHTML = '';
    return;
  }
  el.innerHTML = files.map((f, i) =>
    `<span style="display:inline-flex;align-items:center;gap:5px;padding:3px 8px;background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius);font-size:12px">
      <svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M13 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>
      ${esc(f.name)}
      <button type="button" onclick="window._epRemovePendingAsset(${i})" style="background:none;border:none;cursor:pointer;color:var(--text3);padding:0;font-size:14px;line-height:1" title="${esc(t('errpages.remove'))}">×</button>
    </span>`
  ).join('');
}

window._epAddPendingAssets = function(fileList) {
  if (!fileList || !fileList.length) return;
  if (!window._epPendingAssets) window._epPendingAssets = [];
  for (const f of fileList) {
    if (!f || !f.name) continue;
    if (window._epPendingAssets.some(x => x.name === f.name)) continue;
    window._epPendingAssets.push(f);
  }
  renderEpPendingAssets();
};

window._epRemovePendingAsset = function(idx) {
  if (!window._epPendingAssets) return;
  window._epPendingAssets.splice(idx, 1);
  renderEpPendingAssets();
};

function defaultErrorPageBody() {
  return `<!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8"><title>{{status}} {{title}}</title>
<style>body{font-family:system-ui;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0;background:#f7f8fa;color:#1a1d23}
.card{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:40px;max-width:420px}
.badge{font-size:12px;color:#6b7280;margin-bottom:12px}h1{margin:0 0 8px;font-size:22px}p{color:#6b7280;line-height:1.6}
.meta{margin-top:24px;font-size:11px;font-family:monospace;color:#9ca3af}</style></head>
<body><div class="card">
  <div class="badge">Erreur {{status}}</div>
  <h1>{{title}}</h1>
  <p>{{message}}</p>
  <div class="meta">{{host}} · {{request_id}}</div>
</div></body></html>`;
}

window.saveErrorPage = async function(id) {
  const name = document.getElementById('ep-name')?.value.trim();
  const description = document.getElementById('ep-desc')?.value.trim() || '';
  const body = document.getElementById('ep-body')?.value || '';
  if (!name || !body.trim()) { toast(t('errpages.required'), 'error'); return; }
  try {
    let tplId = id;
    if (id) {
      await api('PUT', `/error-page-templates/${id}`, { name, description, body });
    } else {
      const created = await api('POST', '/error-page-templates', { name, description, body });
      tplId = created?.id;
    }
    const files = window._epPendingAssets || [];
    if (tplId && files.length) {
      for (const f of files) {
        const b64 = await fileToBase64(f);
        await api('POST', `/error-page-templates/${tplId}/assets`, {
          filename: f.name,
          content_type: f.type || 'application/octet-stream',
          content_b64: b64,
        });
      }
      window._epPendingAssets = [];
    }
    toast(t('errpages.saved'), 'success');
    closeModal();
    refreshErrorPages();
  } catch (e) { toast(e.message, 'error'); }
};

function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const s = String(reader.result || '');
      const i = s.indexOf(',');
      resolve(i >= 0 ? s.slice(i + 1) : s);
    };
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

window.deleteErrorPage = async function(id) {
  if (!confirm(t('errpages.delete_confirm'))) return;
  try {
    await api('DELETE', `/error-page-templates/${id}`);
    toast(t('errpages.deleted'), 'success');
    refreshErrorPages();
  } catch (e) { toast(e.message, 'error'); }
};

window.deleteErrorPageAsset = async function(tplId, filename) {
  if (!tplId || !confirm(t('errpages.asset_delete_confirm'))) return;
  try {
    await api('DELETE', `/error-page-templates/${tplId}/assets/${encodeURIComponent(filename)}`);
    toast(t('errpages.asset_deleted'), 'success');
    openErrorPageModal(tplId);
  } catch (e) { toast(e.message, 'error'); }
};
