// ── PAGE: Tokens d'appairage
// Extrait de pages-all.js — phase 4.

// ── PAGE: Tokens ───────────────────────────────────────────────────────────
pages.tokens = async function() {
  document.getElementById('topbar-actions').innerHTML = '';
  await refreshTokens();
};

function _tokenStatus(tok) {
  if (tok.revoked) return { label: t('tokens.status_revoked'), cls: 'tag-red' };
  if (tok.expires_at && new Date(tok.expires_at) < new Date()) return { label: t('tokens.status_expired'), cls: 'tag-yellow' };
  return { label: t('tokens.status_active'), cls: 'tag-green' };
}

function _rbacBadge(r) {
  const m = { admin: 'tag-accent', operator: 'tag-outline', viewer: 'tag-neutral' };
  return `<span class="tag ${m[r]||'tag-neutral'}" style="font-size:10px">${esc(r||'admin')}</span>`;
}

function _scopeTagCls(type) {
  return { domain:'tag-blue', server:'tag-orange', proxy:'tag-accent', core:'tag-outline' }[type] || 'tag-neutral';
}

function _tokenScopeTypeLabels() {
  return {
    domain: t('tokens.scope_type_domain'),
    server: t('tokens.scope_type_server'),
    proxy: t('tokens.scope_type_proxy'),
    core: t('tokens.scope_type_core'),
  };
}

async function refreshTokens() {
  const content = document.getElementById('content');
  try {
    const list = await api('GET', '/tokens') || [];
    const now = new Date();
    const actifs  = list.filter(tok => !tok.revoked && (!tok.expires_at || new Date(tok.expires_at) > now)).length;
    const revokes = list.filter(tok => tok.revoked).length;
    const expires = list.filter(tok => !tok.revoked && tok.expires_at && new Date(tok.expires_at) <= now).length;

    const statPill = (n, label, color) => `
      <div style="display:flex;align-items:center;gap:8px;padding:10px 16px;background:var(--bg2);border:1px solid var(--border);border-radius:8px;min-width:90px">
        <span style="font-size:20px;font-weight:700;font-variant-numeric:tabular-nums;color:${color||'var(--text)'}">${n}</span>
        <span style="font-size:11px;color:var(--text2);line-height:1.3">${label}</span>
      </div>`;

    const checkSvg  = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--green)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>`;
    const crossSvg  = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--red)"   stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`;
    const partSvg   = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--yellow,#f59e0b)" stroke-width="2.5"><circle cx="12" cy="12" r="1"/><circle cx="12" cy="6" r="1"/><circle cx="12" cy="18" r="1"/></svg>`;

    content.innerHTML = `
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:20px">
        <div>
          <h1 style="margin:0 0 4px;font-size:28px;font-family:var(--font-heading);font-weight:600;">${t('tokens.title')}</h1>
          <p style="margin:0;opacity:0.65;font-size:14px;">${t('tokens.subtitle')}</p>
        </div>
        <button class="btn btn-primary blueprint" onclick="openTokenModal()">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
          ${t('tokens.create')}
        </button>
      </div>

      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px">
        ${statPill(list.length, t('tokens.stat_total'))}
        ${statPill(actifs,  t('tokens.stat_active'),    'var(--green)')}
        ${statPill(revokes, t('tokens.stat_revoked'),  'var(--red)')}
        ${statPill(expires, t('tokens.stat_expired'),   'var(--yellow,#f59e0b)')}
      </div>

      <div class="card blueprint" style="margin-bottom:16px;padding:16px 20px">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <h6 style="margin:0 0 10px;font-size:11px;text-transform:uppercase;letter-spacing:0.09em;opacity:0.5;">${t('tokens.rbac_title')}</h6>
        <div style="overflow-x:auto">
          <table class="table" style="font-size:12px">
            <thead><tr>
              <th>${t('users.col.role')}</th>
              <th style="text-align:center">${t('tokens.col_read_proxies')}</th>
              <th style="text-align:center">${t('tokens.col_modify_proxies')}</th>
              <th style="text-align:center">${t('common.delete')}</th>
              <th style="text-align:center">${t('tokens.col_certs')}</th>
              <th style="text-align:center">${t('tokens.col_settings')}</th>
            </tr></thead>
            <tbody>
              <tr>
                <td>${_rbacBadge('admin')}</td>
                <td style="text-align:center">${checkSvg}</td><td style="text-align:center">${checkSvg}</td>
                <td style="text-align:center">${checkSvg}</td><td style="text-align:center">${checkSvg}</td>
                <td style="text-align:center">${checkSvg}</td>
              </tr>
              <tr>
                <td>${_rbacBadge('operator')}</td>
                <td style="text-align:center">${checkSvg}</td><td style="text-align:center">${checkSvg}</td>
                <td style="text-align:center">${crossSvg}</td><td style="text-align:center">${checkSvg}</td>
                <td style="text-align:center">${crossSvg}</td>
              </tr>
              <tr>
                <td>${_rbacBadge('viewer')}</td>
                <td style="text-align:center">${checkSvg}</td><td style="text-align:center">${crossSvg}</td>
                <td style="text-align:center">${crossSvg}</td><td style="text-align:center">${partSvg}</td>
                <td style="text-align:center">${crossSvg}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p style="margin:8px 0 0;font-size:11px;color:var(--text2);">${t('tokens.rbac_hint')}</p>
      </div>

      <div class="card blueprint" style="margin-bottom:16px">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div class="table-wrap">
          <table>
            <thead><tr>
              <th>${t('tokens.col_name')}</th><th>${t('tokens.col_node')}</th><th>${t('tokens.col_api_rights')}</th><th>${t('tokens.col_endpoint')}</th><th>${t('tokens.col_expires')}</th><th>${t('trafic.status')}</th><th>${t('trafic.actions')}</th>
            </tr></thead>
            <tbody>
              ${list.length ? list.map(tok => {
                const st = _tokenStatus(tok);
                const isActive = !tok.revoked && (!tok.expires_at || new Date(tok.expires_at) > now);
                return `<tr>
                  <td>
                    <div style="font-weight:600;font-size:13px">${esc(tok.node_name)}</div>
                    <div style="font-size:10px;color:var(--text2);font-family:monospace;margin-top:2px">${esc((tok.token||'').substring(0,16))}…</div>
                  </td>
                  <td><span class="tag ${tok.role==='core'?'tag-blue':'tag-yellow'}" style="font-size:10px">${esc(tok.role)}</span></td>
                  <td>${_rbacBadge(tok.rbac_role)}</td>
                  <td class="mono" style="font-size:11px;color:var(--text2)">${esc(tok.node_endpoint||'—')}</td>
                  <td style="font-size:12px">${tok.expires_at ? fmtDate(tok.expires_at) : `<span class="tag tag-neutral" style="font-size:10px">${t('tokens.never')}</span>`}</td>
                  <td><span class="tag ${st.cls}" style="font-size:10px">${esc(st.label)}</span></td>
                  <td>
                    <div style="display:flex;gap:2px;align-items:center">
                      <button class="btn-icon" onclick="copyToken('${esc(tok.token||'')}')" title="${esc(t('tokens.copy'))}">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
                      </button>
                      ${isActive ? `<button class="btn-icon" title="${esc(t('tokens.scopes'))}" onclick="toggleScopeRow('${esc(tok.id)}')">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 010 20M12 2a15.3 15.3 0 000 20"/></svg>
                      </button>` : ''}
                      ${isActive ? `<button class="btn-icon" title="${esc(t('tokens.revoke'))}" onclick="revokeToken('${esc(tok.id)}')">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
                      </button>` : ''}
                      <button class="btn-icon" title="${esc(t('tokens.delete_permanent'))}" onclick="deleteTokenPermanent('${esc(tok.id)}','${esc(tok.node_name)}')" style="color:var(--red);opacity:0.7" onmouseover="this.style.opacity=1" onmouseout="this.style.opacity=0.7">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/></svg>
                      </button>
                    </div>
                  </td>
                </tr>
                <tr id="scope-row-${esc(tok.id)}" style="display:none">
                  <td colspan="7" style="padding:10px 18px 14px;background:var(--bg2);border-top:none">
                    <div id="scope-content-${esc(tok.id)}">${t('common.loading')}</div>
                  </td>
                </tr>`;
              }).join('') : `<tr><td colspan="7" class="empty"><p>${t('tokens.empty')}</p></td></tr>`}
            </tbody>
          </table>
        </div>
      </div>

      <div class="card blueprint" style="padding:18px 20px">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <h6 style="margin:0 0 6px;font-size:11px;text-transform:uppercase;letter-spacing:0.09em;opacity:0.5;">${t('tokens.maintenance')}</h6>
        <p style="margin:0 0 14px;font-size:13px;color:var(--text2)">${t('tokens.purge_hint')}</p>
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
          <input id="purge-days" type="number" min="1" value="30" class="input" style="width:80px">
          <span style="font-size:13px">${t('tokens.days')}</span>
          <button class="btn btn-secondary" onclick="purgeExpiredTokens()">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-1px;margin-right:5px"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/></svg>
            ${t('tokens.purge_now')}
          </button>
        </div>
        <p style="margin:10px 0 0;font-size:11px;color:var(--text2);opacity:0.7">${t('tokens.purge_warning')}</p>
      </div>`;
  } catch(e) { content.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`; }
}

window.toggleScopeRow = async function(tokenId) {
  const row = document.getElementById(`scope-row-${tokenId}`);
  if (!row) return;
  if (row.style.display !== 'none') { row.style.display = 'none'; return; }
  row.style.display = '';
  await renderScopeContent(tokenId);
};

async function renderScopeContent(tokenId) {
  const el = document.getElementById(`scope-content-${tokenId}`);
  if (!el) return;
  try {
    const scopes = await api('GET', `/tokens/${tokenId}/scopes`) || [];
    const scopeTypeLabels = _tokenScopeTypeLabels();
    el.innerHTML = `
      <div style="margin-bottom:10px">
        <div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.07em;color:var(--text2);margin-bottom:6px">${t('tokens.scope_active_title')}</div>
        <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;min-height:24px">
          ${scopes.length ? scopes.map(s => `
            <span class="tag ${_scopeTagCls(s.scope_type)}" style="gap:6px;display:inline-flex;align-items:center;font-size:11px">
              <span style="opacity:0.6">${esc(scopeTypeLabels[s.scope_type]||s.scope_type)}</span> ${esc(s.value)}
              <button onclick="removeScopeFromToken('${esc(tokenId)}','${esc(s.id)}')" style="background:none;border:none;cursor:pointer;color:inherit;padding:0;line-height:1;font-size:14px" title="${esc(t('tokens.scope_remove'))}">×</button>
            </span>`).join('') : `<span style="color:var(--text2);font-size:12px">${t('tokens.scope_none')}</span>`}
        </div>
        <p style="margin:8px 0 0;font-size:11px;color:var(--text2);">${t('tokens.scope_hint')}</p>
      </div>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <select id="scope-type-${esc(tokenId)}" class="input" style="width:110px;height:32px;font-size:12px">
          <option value="domain">${t('tokens.scope_type_domain')}</option>
          <option value="server">${t('tokens.scope_type_server')}</option>
          <option value="proxy">${t('tokens.scope_type_proxy_id')}</option>
          <option value="core">${t('tokens.scope_type_core')}</option>
        </select>
        <input id="scope-input-${esc(tokenId)}" class="input" style="width:200px;height:32px;font-size:13px" placeholder="${esc(t('tokens.scope_ph'))}">
        <button class="btn btn-primary" style="height:32px;padding:0 12px;font-size:13px" onclick="addScopeToToken('${esc(tokenId)}')">${t('tokens.scope_add')}</button>
      </div>`;
  } catch(e) { el.innerHTML = `<span style="color:var(--red)">${esc(e.message)}</span>`; }
}

window.addScopeToToken = async function(tokenId) {
  const typeEl  = document.getElementById(`scope-type-${tokenId}`);
  const input   = document.getElementById(`scope-input-${tokenId}`);
  const type    = typeEl?.value || 'domain';
  const val     = input?.value.trim();
  if (!val) return;
  try {
    await api('POST', `/tokens/${tokenId}/scopes`, { scope_type: type, value: val });
    toast(t('tokens.scope_added', { type, val }), 'success');
    if (input) input.value = '';
    await renderScopeContent(tokenId);
  } catch(e) { toast(e.message, 'error'); }
};

window.removeScopeFromToken = async function(tokenId, scopeId) {
  try {
    await api('DELETE', `/tokens/${tokenId}/scopes/${scopeId}`);
    toast(t('tokens.scope_removed'), 'success');
    await renderScopeContent(tokenId);
  } catch(e) { toast(e.message, 'error'); }
};

window.openTokenModal = function() {
  const rbacHints = {
    admin: t('tokens.rbac_admin_hint'),
    operator: t('tokens.rbac_operator_hint'),
    viewer: t('tokens.rbac_viewer_hint'),
  };
  window._tokenRbacHints = rbacHints;
  modal(t('tokens.modal_title'), `
    <div class="form-row">
      <div class="field">
        <label class="field-label">${t('tokens.field_node_name')}</label>
        <input id="t-name" class="input" placeholder="${esc(t('tokens.node_name_ph'))}">
      </div>
      <div class="field">
        <label class="field-label">${t('tokens.field_node_type')}</label>
        <select id="t-role" class="input">
          <option value="core">Core</option>
          <option value="agent">Agent</option>
        </select>
      </div>
    </div>
    <div class="field">
      <label class="field-label">${t('tokens.field_rbac')}</label>
      <select id="t-rbac" class="input" onchange="document.getElementById('t-rbac-hint').textContent=(window._tokenRbacHints||{})[this.value]||''">
        <option value="admin">${t('tokens.rbac_admin_opt')}</option>
        <option value="operator">${t('tokens.rbac_operator_opt')}</option>
        <option value="viewer">${t('tokens.rbac_viewer_opt')}</option>
      </select>
      <p id="t-rbac-hint" class="form-hint" style="margin-top:4px">${t('tokens.rbac_admin_hint')}</p>
    </div>
    <div class="field">
      <label class="field-label">${t('tokens.field_endpoint')}</label>
      <input id="t-endpoint" class="input" placeholder="${esc(t('tokens.endpoint_ph'))}">
      <p class="form-hint">${t('tokens.endpoint_hint')}</p>
    </div>
    <div class="form-row">
      <div class="field">
        <label class="field-label">${t('tokens.field_ttl')}</label>
        <select id="t-ttl-preset" class="input" onchange="(function(){const v=document.getElementById('t-ttl-preset').value;document.getElementById('t-ttl-custom').style.display=v==='custom'?'':'none';})()">
          <option value="0">${t('tokens.ttl_unlimited')}</option>
          <option value="24">${t('tokens.ttl_24h')}</option>
          <option value="168">${t('tokens.ttl_7d')}</option>
          <option value="720">${t('tokens.ttl_30d')}</option>
          <option value="2160">${t('tokens.ttl_90d')}</option>
          <option value="custom">${t('tokens.ttl_custom')}</option>
        </select>
      </div>
      <div class="field">
        <label class="field-label">${t('tokens.field_ttl_custom')}</label>
        <input id="t-ttl-custom" type="number" min="1" class="input" placeholder="${esc(t('tokens.ttl_custom_ph'))}" style="display:none">
      </div>
    </div>`,
    `<button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel')}</button>
     <button class="btn btn-primary" onclick="createToken()">${t('common.create')}</button>`);
};

window.createToken = async function() {
  const preset = document.getElementById('t-ttl-preset')?.value;
  const ttlHours = preset === 'custom'
    ? parseInt(document.getElementById('t-ttl-custom')?.value) || 0
    : parseInt(preset) || 0;
  const payload = {
    node_name:     document.getElementById('t-name').value.trim(),
    role:          document.getElementById('t-role').value,
    rbac_role:     document.getElementById('t-rbac').value,
    node_endpoint: document.getElementById('t-endpoint').value.trim(),
    ttl_hours:     ttlHours,
  };
  try {
    const res = await api('POST', '/tokens', payload);
    closeModal();
    toast(t('tokens.created'), 'success');
    if (res?.token) {
      modal(t('tokens.created_modal_title'), `
        <p style="color:var(--text2);margin-bottom:12px;font-size:13px">${t('tokens.created_modal_hint')}</p>
        <div class="code-block" style="word-break:break-all;font-size:12px">${esc(res.token)}</div>`,
        `<button class="btn btn-primary" onclick="copyToken('${esc(res.token)}');closeModal()">
           <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-1px;margin-right:5px"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
           ${t('tokens.copy_close')}
         </button>`);
    }
    refreshTokens();
  } catch(e) { toast(e.message, 'error'); }
};

window.copyToken = function(token) { copyText(token, t('tokens.copied')); };

window.revokeToken = function(id) {
  confirm_(t('tokens.revoke_confirm'), async () => {
    try { await api('DELETE', `/tokens/${id}`); toast(t('tokens.revoked'), 'success'); refreshTokens(); }
    catch(e) { toast(e.message, 'error'); }
  });
};

window.deleteTokenPermanent = function(id, name) {
  confirm_(t('tokens.delete_confirm', { name }), async () => {
    try { await api('DELETE', `/tokens/${id}?permanent=true`); toast(t('tokens.deleted'), 'success'); refreshTokens(); }
    catch(e) { toast(e.message, 'error'); }
  });
};

window.purgeExpiredTokens = async function() {
  const days = parseInt(document.getElementById('purge-days')?.value) || 30;
  if (days < 1) { toast(t('tokens.purge_min'), 'error'); return; }
  confirm_(t('tokens.purge_confirm', { n: days }), async () => {
    try {
      const res = await api('POST', '/tokens/purge-expired', { days });
      toast(t('tokens.purged', { n: res.deleted || 0 }), 'success');
      refreshTokens();
    } catch(e) { toast(e.message, 'error'); }
  });
};
