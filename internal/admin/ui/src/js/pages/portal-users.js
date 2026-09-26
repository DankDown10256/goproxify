// ── PAGE PARTAGÉE: Users portail Access (Admin + Passerelle)
async function renderPortalUsersPage(ctx) {
  const mode = ctx.mode || 'admin';
  const isAdmin = mode === 'admin';
  const edge = isAdmin ? null : state.selectedEdge;
  const edgeName = edge?.node_name || '';
  const edgeLabel = edge ? (edge.display_name || edgeName || '—') : '';

  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML = '';
  content.innerHTML = `<div style="display:flex;align-items:center;gap:10px;color:var(--text2);padding:32px 0">
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="animation:spin 1s linear infinite"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>
    ${esc(t('common.loading') || 'Chargement…')}
  </div>`;

  if (!isAdmin && !edgeName) {
    content.innerHTML = `<div class="empty"><p>${esc(t('portal.need_edge') || 'Sélectionnez une passerelle')}</p></div>`;
    return;
  }

  try {
    const path = isAdmin ? '/portal/users' : '/portal/users?edge=' + encodeURIComponent(edgeName);
    const [usersRes, nodesRes] = await Promise.all([
      api('GET', path).catch(() => ({ users: [] })),
      isAdmin ? api('GET', '/nodes').catch(() => []) : Promise.resolve([]),
    ]);
    let users = usersRes.users || [];
    if (!Array.isArray(users)) users = [];
    const edges = (nodesRes || []).filter(n => n.role === 'edge');
    window._portalUsersAll = users;
    window._portalUsersEdges = edges;
    if (!window._puFilter) window._puFilter = { edge: '', status: '', q: '' };

    const filtered = () => {
      const f = window._puFilter;
      return (window._portalUsersAll || []).filter(u => {
        if (f.edge && u.home_edge !== f.edge) return false;
        if (f.status && u.status !== f.status) return false;
        if (f.q) {
          const hay = [u.email, u.home_edge, ...(u.tags || [])].join(' ').toLowerCase();
          if (!hay.includes(f.q.toLowerCase())) return false;
        }
        return true;
      });
    };

    const statusBadge = (st) => {
      const colors = {
        active: 'var(--accent)',
        invited: 'var(--warn, #b45309)',
        disabled: 'var(--text2)',
      };
      const c = colors[st] || 'var(--text2)';
      return `<span class="badge" style="border:1px solid ${c};color:${c};font-size:11px;padding:2px 8px;border-radius:999px">${esc(st)}</span>`;
    };

    const render = () => {
      const items = filtered();
      document.getElementById('topbar-actions').innerHTML = `
        <button class="btn btn-primary" id="pu-invite">${esc(t('pusers.invite') || 'Inviter')}</button>`;

      const chips = isAdmin ? edges.map(c => {
        const nn = c.node_name || c.id;
        const active = window._puFilter.edge === nn;
        return `<button type="button" class="chip" data-edge="${esc(nn)}" style="cursor:pointer;${active ? 'border-color:var(--accent);color:var(--accent)' : ''}">${esc(c.display_name || nn)}</button>`;
      }).join('') : '';

      content.innerHTML = `
        <div style="margin-bottom:16px">
          <h1 style="margin:0 0 4px;font-size:22px;font-family:var(--font-heading);font-weight:600">
            ${esc(t('pusers.title') || 'Users Access')}
          </h1>
          <p style="margin:0;font-size:13px;color:var(--text2)">
            ${isAdmin
              ? esc(t('pusers.sub_admin') || 'Comptes portail — invitation par email (SMTP requis).')
              : (t('pusers.sub_edge') || 'Comptes de {name}.').replace('{name}', '<strong>' + esc(edgeLabel) + '</strong>')}
          </p>
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:14px;align-items:center">
          <input class="input" id="pu-q" placeholder="${esc(t('pusers.search') || 'Rechercher…')}" value="${esc(window._puFilter.q)}" style="max-width:220px"/>
          <select class="input" id="pu-status" style="max-width:140px">
            <option value="">${esc(t('pusers.all_status') || 'Tous statuts')}</option>
            <option value="invited" ${window._puFilter.status === 'invited' ? 'selected' : ''}>invited</option>
            <option value="active" ${window._puFilter.status === 'active' ? 'selected' : ''}>active</option>
            <option value="disabled" ${window._puFilter.status === 'disabled' ? 'selected' : ''}>disabled</option>
          </select>
          ${isAdmin ? `<div style="display:flex;flex-wrap:wrap;gap:6px;align-items:center">
            <button type="button" class="chip" data-edge="" style="cursor:pointer;${!window._puFilter.edge ? 'border-color:var(--accent);color:var(--accent)' : ''}">${esc(t('pcatalog.all_edges') || 'Tous')}</button>
            ${chips}
          </div>` : ''}
        </div>
        <div class="card blueprint" style="padding:0;overflow:hidden">
          <div class="table-wrap">
          <table style="width:100%;border-collapse:collapse;font-size:13px">
            <thead>
              <tr style="text-align:left;border-bottom:1px solid var(--border);color:var(--text2)">
                <th style="padding:10px 14px">Email</th>
                ${isAdmin ? '<th style="padding:10px 14px">Passerelle</th>' : ''}
                <th style="padding:10px 14px">Tags</th>
                <th style="padding:10px 14px">Status</th>
                <th style="padding:10px 14px"></th>
              </tr>
            </thead>
            <tbody>
              ${items.length ? items.map(u => `
                <tr style="border-bottom:1px solid var(--border)">
                  <td style="padding:10px 14px;font-weight:500">${esc(u.email)}</td>
                  ${isAdmin ? `<td style="padding:10px 14px;color:var(--text2)">${esc(u.home_edge)}</td>` : ''}
                  <td style="padding:10px 14px">${(u.tags || []).map(tg => `<span class="chip" style="font-size:11px">${esc(tg)}</span>`).join(' ') || '—'}</td>
                  <td style="padding:10px 14px">${statusBadge(u.status)}</td>
                  <td style="padding:10px 14px;text-align:right;white-space:nowrap">
                    <button type="button" class="btn btn-ghost btn-icon btn-sm" data-edit="${esc(u.id)}" title="${esc(t('common.edit') || 'Modifier')}">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                    </button>
                    ${u.status !== 'active' ? `<button type="button" class="btn btn-ghost btn-icon btn-sm" data-resend="${esc(u.id)}" title="${esc(t('pusers.resend') || 'Renvoyer')}">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
                    </button>` : ''}
                    <button type="button" class="btn btn-ghost btn-icon btn-sm" data-del="${esc(u.id)}" title="${esc(t('common.delete') || 'Supprimer')}" style="color:var(--danger,#c45c5c)">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
                    </button>
                  </td>
                </tr>`).join('') : `<tr><td colspan="${isAdmin ? 5 : 4}" style="padding:40px 24px;text-align:center">
                  <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="var(--text2)" stroke-width="1.5" style="display:block;margin:0 auto 12px"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
                  <p style="margin:0 0 12px;color:var(--text2);font-size:13px">${esc(t('pusers.empty') || 'Aucun utilisateur portal')}</p>
                  <button type="button" class="btn btn-primary btn-sm" id="pu-empty-invite">${esc(t('pusers.invite') || 'Inviter le premier utilisateur')}</button>
                </td></tr>`}
            </tbody>
          </table>
          </div>
        </div>`;

      document.getElementById('pu-q').oninput = (e) => { window._puFilter.q = e.target.value; render(); };
      document.getElementById('pu-status').onchange = (e) => { window._puFilter.status = e.target.value; render(); };
      content.querySelectorAll('[data-edge]').forEach(btn => {
        btn.onclick = () => { window._puFilter.edge = btn.getAttribute('data-edge') || ''; render(); };
      });
      document.getElementById('pu-invite').onclick = () => openInviteModal();
      const emptyInvite = document.getElementById('pu-empty-invite');
      if (emptyInvite) emptyInvite.onclick = () => openInviteModal();
      content.querySelectorAll('[data-edit]').forEach(btn => {
        btn.onclick = () => {
          const u = (window._portalUsersAll || []).find(x => x.id === btn.getAttribute('data-edit'));
          if (u) openEditModal(u);
        };
      });
      content.querySelectorAll('[data-resend]').forEach(btn => {
        btn.onclick = async () => {
          try {
            await api('POST', '/portal/users/' + btn.getAttribute('data-resend') + '/resend');
            toast(t('pusers.resent') || 'Invitation renvoyée.');
            renderPortalUsersPage(ctx);
          } catch (e) { toast(e.message || e, true); }
        };
      });
      content.querySelectorAll('[data-del]').forEach(btn => {
        btn.onclick = async () => {
          if (!confirm(t('pusers.confirm_del') || 'Supprimer cet utilisateur ?')) return;
          try {
            await api('DELETE', '/portal/users/' + btn.getAttribute('data-del'));
            renderPortalUsersPage(ctx);
          } catch (e) { toast(e.message || e, true); }
        };
      });
    };

    function toast(msg, err) {
      const el = document.createElement('div');
      el.textContent = msg;
      el.style.cssText = 'position:fixed;bottom:20px;right:20px;padding:10px 14px;border-radius:8px;z-index:9999;font-size:13px;background:' + (err ? 'var(--danger,#c45c5c)' : 'var(--accent)') + ';color:#fff';
      document.body.appendChild(el);
      setTimeout(() => el.remove(), 3200);
    }

    function openInviteModal() {
      const defaultEdge = isAdmin ? (window._puFilter.edge || (edges[0] && (edges[0].node_name || edges[0].id)) || '') : edgeName;
      const edgeOpts = isAdmin
        ? edges.map(c => {
            const nn = c.node_name || c.id;
            return `<option value="${esc(nn)}" ${nn === defaultEdge ? 'selected' : ''}>${esc(c.display_name || nn)}</option>`;
          }).join('')
        : `<option value="${esc(edgeName)}">${esc(edgeLabel)}</option>`;
      const overlay = document.createElement('div');
      overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.35);z-index:1000;display:flex;align-items:center;justify-content:center;padding:16px';
      overlay.innerHTML = `
        <div class="card blueprint" style="width:min(440px,100%);padding:18px 20px;background:var(--bg)">
          <div style="font-weight:700;font-size:16px;margin-bottom:12px">${esc(t('pusers.invite') || 'Inviter')}</div>
          <div class="field" style="margin-bottom:10px"><label class="field-label">Email</label><input class="input" id="pu-email" type="email"/></div>
          <div class="field" style="margin-bottom:10px"><label class="field-label">Tags</label><input class="input" id="pu-tags" placeholder="prod, ops"/></div>
          <div class="field" style="margin-bottom:10px"><label class="field-label">Passerelle</label><select class="input" id="pu-edge">${edgeOpts}</select></div>
          <div id="pu-modal-err" style="font-size:12px;color:var(--danger,#c45c5c);min-height:1.2em;margin-bottom:8px"></div>
          <div style="display:flex;gap:8px;justify-content:flex-end">
            <button class="btn btn-secondary" id="pu-cancel">${esc(t('common.cancel') || 'Annuler')}</button>
            <button class="btn btn-primary" id="pu-ok">${esc(t('pusers.send') || 'Envoyer')}</button>
          </div>
        </div>`;
      document.body.appendChild(overlay);
      overlay.querySelector('#pu-cancel').onclick = () => overlay.remove();
      overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };
      overlay.querySelector('#pu-ok').onclick = async () => {
        const errEl = overlay.querySelector('#pu-modal-err');
        const okBtn = overlay.querySelector('#pu-ok');
        errEl.textContent = '';
        okBtn.disabled = true;
        okBtn.textContent = '…';
        try {
          const tags = (overlay.querySelector('#pu-tags').value || '').split(',').map(s => s.trim()).filter(Boolean);
          await api('POST', '/portal/users/invite', {
            email: overlay.querySelector('#pu-email').value.trim(),
            tags,
            home_edge: overlay.querySelector('#pu-edge').value,
          });
          overlay.remove();
          toast(t('pusers.invited') || 'Invitation envoyée.');
          renderPortalUsersPage(ctx);
        } catch (e) {
          errEl.textContent = e.message || String(e);
          okBtn.disabled = false;
          okBtn.textContent = esc(t('pusers.send') || 'Envoyer');
        }
      };
    }

    function openEditModal(u) {
      const overlay = document.createElement('div');
      overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.35);z-index:1000;display:flex;align-items:center;justify-content:center;padding:16px';
      overlay.innerHTML = `
        <div class="card blueprint" style="width:min(440px,100%);padding:18px 20px;background:var(--bg)">
          <div style="font-weight:700;font-size:16px;margin-bottom:4px">${esc(u.email)}</div>
          <div class="field" style="margin:12px 0 10px"><label class="field-label">Tags</label>
            <input class="input" id="pu-etags" value="${esc((u.tags || []).join(', '))}"/></div>
          <div class="field" style="margin-bottom:10px"><label class="field-label">Status</label>
            <select class="input" id="pu-estatus">
              <option value="invited" ${u.status === 'invited' ? 'selected' : ''}>invited</option>
              <option value="active" ${u.status === 'active' ? 'selected' : ''}>active</option>
              <option value="disabled" ${u.status === 'disabled' ? 'selected' : ''}>disabled</option>
            </select>
          </div>
          <div id="pu-modal-err" style="font-size:12px;color:var(--danger,#c45c5c);min-height:1.2em;margin-bottom:8px"></div>
          <div style="display:flex;gap:8px;justify-content:flex-end">
            <button class="btn btn-secondary" id="pu-cancel">${esc(t('common.cancel') || 'Annuler')}</button>
            <button class="btn btn-primary" id="pu-ok">${esc(t('common.save') || 'Enregistrer')}</button>
          </div>
        </div>`;
      document.body.appendChild(overlay);
      overlay.querySelector('#pu-cancel').onclick = () => overlay.remove();
      overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };
      overlay.querySelector('#pu-ok').onclick = async () => {
        const errEl = overlay.querySelector('#pu-modal-err');
        const okBtn = overlay.querySelector('#pu-ok');
        errEl.textContent = '';
        okBtn.disabled = true;
        okBtn.textContent = '…';
        try {
          const tags = (overlay.querySelector('#pu-etags').value || '').split(',').map(s => s.trim()).filter(Boolean);
          await api('PUT', '/portal/users/' + u.id, {
            tags,
            status: overlay.querySelector('#pu-estatus').value,
          });
          overlay.remove();
          renderPortalUsersPage(ctx);
        } catch (e) {
          errEl.textContent = e.message || String(e);
          okBtn.disabled = false;
          okBtn.textContent = esc(t('common.save') || 'Enregistrer');
        }
      };
    }

    render();
  } catch (e) {
    content.innerHTML = `<div class="err">${esc(e.message || e)}</div>`;
  }
}

pages['admin-portal-users'] = async function() {
  await renderPortalUsersPage({ mode: 'admin' });
};
pages['edge-portal-users'] = async function() {
  await renderPortalUsersPage({ mode: 'edge' });
};
