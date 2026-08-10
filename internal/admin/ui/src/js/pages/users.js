// ── PAGE: Users & Teams
// Grants = (type, value, access_mode read|write) sur user et/ou team.

pages.users = async function() {
  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML = '';
  await refreshUsers(content);
};

async function refreshUsers(content) {
  content = content || document.getElementById('content');
  try {
    const [users, teams] = await Promise.all([
      api('GET', '/users').catch(() => []),
      api('GET', '/teams').catch(() => []),
    ]);
    const list = users || [];
    const teamList = teams || [];

    function roleTag(r) {
      if (r === 'admin' || r === 'superadmin') return 'tag-accent';
      return 'tag-neutral';
    }
    function teamNames(u) {
      return u.team_names || '—';
    }

    content.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:20px">
        <div>
          <h1 style="margin:0 0 4px;font-size:28px;font-family:var(--font-heading);font-weight:600;">${t('users.title')}</h1>
          <p style="margin:0;opacity:0.65;font-size:14px;">${t('users.subtitle')}</p>
        </div>
        <button class="btn btn-primary blueprint" onclick="openUserModal()">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
          ${t('users.new')}
        </button>
      </div>

      <div class="card blueprint" style="padding:18px 20px;margin-bottom:16px;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <h6 style="margin:0 0 8px;font-size:11px;text-transform:uppercase;letter-spacing:0.09em;opacity:0.5;">${t('users.model')}</h6>
        <p style="margin:0 0 12px;font-size:12.5px;line-height:1.55;opacity:0.75;">${t('users.model_p1')}</p>
        <h6 style="margin:0 0 10px;font-size:11px;text-transform:uppercase;letter-spacing:0.09em;opacity:0.5;">${t('users.platform_role')}</h6>
        <table class="table">
          <thead><tr><th>${t('users.col.role')}</th><th>${t('users.col.users_tokens')}</th><th>${t('users.col.proxies')}</th></tr></thead>
          <tbody>
            <tr>
              <td><span class="tag tag-accent">admin</span></td>
              <td>${t('users.yes')}</td>
              <td>${t('users.admin_proxies')}</td>
            </tr>
            <tr>
              <td><span class="tag tag-neutral">user</span></td>
              <td>${t('users.no')}</td>
              <td>${t('users.user_proxies')}</td>
            </tr>
          </tbody>
        </table>
        <p style="margin:10px 0 0;font-size:11.5px;opacity:0.5;line-height:1.45;">${t('users.team_inherit')}</p>
      </div>

      <div style="display:flex;flex-direction:column;gap:10px;margin-bottom:24px;">
        <h6 style="margin:0;">${t('users.accounts')}</h6>
        <div class="card blueprint" style="overflow:hidden;">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <div class="table-wrap">
          <table class="table">
            <thead><tr><th>${t('users.col.email')}</th><th>${t('users.col.role')}</th><th>${t('users.col.teams')}</th><th>${t('users.col.created')}</th><th></th></tr></thead>
            <tbody>
              ${list.length ? list.map(u => `<tr>
                <td style="font-weight:500;font-family:monospace;font-size:13px;">${esc(u.email)}</td>
                <td><span class="tag ${roleTag(u.role)}">${esc(u.role||'user')}</span></td>
                <td style="opacity:0.7;font-size:12px;">${esc(teamNames(u))}</td>
                <td style="opacity:0.6;font-size:12px;">${fmtDate(u.created_at)}</td>
                <td style="text-align:right;"><div style="display:inline-flex;gap:6px;">
                  <button class="btn btn-ghost btn-icon" onclick="openUserModal('${esc(u.id)}')" title="${esc(t('common.edit'))}"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>
                  ${u.role==='superadmin'?'':`<button class="btn btn-ghost btn-icon" onclick="deleteUser('${esc(u.id)}')" title="${esc(t('common.delete'))}"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3 6h18"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg></button>`}
                </div></td>
              </tr>`).join('') : `<tr><td colspan="5" class="empty"><p>${t('users.empty')}</p></td></tr>`}
            </tbody>
          </table>
          </div>
        </div>
      </div>

      <div style="display:flex;flex-direction:column;gap:10px;">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;">
          <div>
            <h6 style="margin:0 0 2px;">${t('users.teams_title')}</h6>
            <p style="margin:0;font-size:12px;opacity:0.55;">${t('users.teams_sub')}</p>
          </div>
          <button class="btn btn-secondary blueprint" onclick="openTeamModal()">
            <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            ${t('users.new_team')}
          </button>
        </div>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(min(260px,100%),1fr));gap:12px;" id="teams-grid">
          ${teamList.length ? teamList.map(team => `
          <div class="card blueprint" style="display:flex;flex-direction:column;gap:0;padding:0;overflow:hidden;">
            <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
            <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;padding:14px 16px 12px;">
              <div class="card-title" style="font-size:14px;font-weight:600;">${esc(team.name)}</div>
              <div style="display:inline-flex;gap:4px;flex-shrink:0;">
                <button class="btn btn-ghost btn-icon" onclick="openTeamModal('${esc(team.id)}')" title="${esc(t('common.edit'))}"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>
                <button class="btn btn-ghost btn-icon" onclick="deleteTeam('${esc(team.id)}')" title="${esc(t('common.delete'))}"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3 6h18"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg></button>
              </div>
            </div>
            <div style="display:flex;gap:0;border-top:1px solid var(--border);">
              <div style="flex:1;display:flex;flex-direction:column;align-items:center;padding:10px 8px;gap:2px;border-right:1px solid var(--border);">
                <span style="font-size:18px;font-weight:700;line-height:1;">${team.member_count||0}</span>
                <span style="font-size:10px;opacity:0.5;text-transform:uppercase;letter-spacing:0.07em;">${(team.member_count||0)!==1?t('users.members_lbl'):t('users.member_lbl')}</span>
              </div>
              <div style="flex:1;display:flex;flex-direction:column;align-items:center;padding:10px 8px;gap:2px;">
                <span style="font-size:18px;font-weight:700;line-height:1;">${team.scope_count||0}</span>
                <span style="font-size:10px;opacity:0.5;text-transform:uppercase;letter-spacing:0.07em;">${(team.scope_count||0)!==1?t('users.grants_lbl'):t('users.grant_lbl')}</span>
              </div>
            </div>
          </div>`).join('') : `
          <div class="card blueprint" style="padding:28px;text-align:center;grid-column:1/-1;">
            <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
            <p style="margin:0;opacity:0.6;font-size:13px;line-height:1.5;">${t('users.no_team_html')}</p>
          </div>`}
        </div>
      </div>
      <div id="user-modal-container"></div>
      <div id="team-modal-container"></div>`;
  } catch(e) { content.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`; }
}

function grantListHtml(scopes, listId, removeFn) {
  if (!scopes.length) return '<span style="font-size:12px;opacity:0.45;">' + t('users.no_grant') + '</span>';
  return scopes.map((sc, i) => {
    const mode = sc.mode || sc.access_mode || 'read';
    return `<div style="display:flex;align-items:center;gap:8px;font-size:12.5px;padding:6px 10px;border:1px solid var(--border);">
      <span class="tag tag-outline" style="font-size:10px;">${esc(sc.type||sc.scope_type)}</span>
      <code style="flex:1;">${esc(sc.value||sc.scope_value)}</code>
      <span class="tag ${mode==='write'?'tag-accent':'tag-neutral'}" style="font-size:10px;">${mode==='write'?t('users.ecriture'):t('users.lecture')}</span>
      <button class="btn btn-ghost btn-icon" onclick="${removeFn}(${i})"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
    </div>`;
  }).join('');
}

window.openUserModal = async function(id) {
  let u = null;
  let teams = [];
  try {
    if (id) u = await api('GET', `/users/${id}`);
    teams = await api('GET', '/teams').catch(() => []) || [];
  } catch {}
  const userTeams = u?.teams || [];
  window._userOrigTeams = userTeams;
  let role = u?.role || 'user';
  if (role === 'operator' || role === 'viewer') role = 'user';
  const isSuper = role === 'superadmin';
  const scopes = (u?.scopes || []).map(sc => ({
    id: sc.id,
    type: sc.scope_type,
    value: sc.value,
    mode: sc.access_mode || 'read',
  }));
  window._userScopes = scopes;
  window._userScopesOrig = [...scopes];

  const renderUserScopes = () => {
    const el = document.getElementById('um-scopes-list');
    if (el) el.innerHTML = grantListHtml(window._userScopes, 'um-scopes-list', 'window._removeUserScope');
  };

  const roleField = isSuper
    ? `<div class="field"><label>${t('users.platform_role')}</label>
        <div style="padding:8px 10px;border:1px solid var(--border);border-radius:6px;font-size:13px;">
          <span class="tag tag-accent">superadmin</span>
          <span style="margin-left:8px;opacity:0.6;font-size:12px;">${t('users.role_protected')}</span>
        </div>
      </div>`
    : `<div class="field"><label>${t('users.platform_role')}</label>
            <div style="display:flex;flex-direction:column;gap:6px;margin-top:2px;">
              <label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer;font-size:13px;padding:8px 10px;border:1px solid var(--border);border-radius:6px;${role==='admin'?'border-color:var(--accent);background:var(--accent-alpha,rgba(58,134,255,0.06));':''}">
                <input type="radio" name="um-role" value="admin" ${role==='admin'?'checked':''} style="margin-top:2px;">
                <div><strong>admin</strong> — ${t('users.role_admin_desc')}</div>
              </label>
              <label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer;font-size:13px;padding:8px 10px;border:1px solid var(--border);border-radius:6px;${role!=='admin'?'border-color:var(--accent);background:var(--accent-alpha,rgba(58,134,255,0.06));':''}">
                <input type="radio" name="um-role" value="user" ${role!=='admin'?'checked':''} style="margin-top:2px;">
                <div><strong>user</strong> — ${t('users.role_user_desc')}</div>
              </label>
            </div>
          </div>`;

  document.getElementById('user-modal-container').innerHTML = `
    <div class="dialog-backdrop" style="position:fixed;inset:0;z-index:9999;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.55);">
      <div class="dialog blueprint" role="dialog" aria-modal="true" style="width:min(560px,96vw);max-width:none;max-height:92vh;overflow:auto;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div class="dialog-title">${id ? t('users.edit_user') : t('users.new_user')}</div>
        <div class="dialog-body" style="display:flex;flex-direction:column;gap:16px;">
          <div class="field"><label>${t('users.col.email')}</label><input class="input" id="u-email" type="email" placeholder="alice@corp.io" value="${esc(u?.email||'')}"></div>
          <div class="field"><label>${id ? (t('users.new_password') + ' <span style="opacity:0.5;font-weight:400;">' + t('users.pass_unchanged') + '</span>') : t('users.password')}</label><input class="input" id="u-pass" type="password" placeholder="••••••••" autocomplete="new-password"></div>
          ${roleField}
          <div class="field">
            <label>${t('users.personal_grants')}</label>
            <div id="um-scopes-list" style="display:flex;flex-direction:column;gap:4px;margin:6px 0;"></div>
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
              <select id="um-sc-type" style="font-size:12px;padding:4px 6px;border:1px solid var(--border);border-radius:4px;background:var(--input-bg,var(--card-bg));color:var(--text);">
                <option value="domain">domain</option>
                <option value="server">server</option>
                <option value="proxy">proxy</option>
                <option value="core">core</option>
              </select>
              <input class="input" id="um-sc-val" placeholder="*.corp.io" style="flex:1;min-width:120px;">
              <select id="um-sc-mode" style="font-size:12px;padding:4px 6px;border:1px solid var(--border);border-radius:4px;background:var(--input-bg,var(--card-bg));color:var(--text);">
                <option value="read">${t('users.read_opt')}</option>
                <option value="write">${t('users.write_opt')}</option>
              </select>
              <button class="btn btn-ghost btn-icon" onclick="window._addUserScope()" title="${esc(t('users.add'))}"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/></svg></button>
            </div>
          </div>
          ${teams.length ? `<div class="field"><label>${t('users.col.teams')}</label>
            <div style="display:flex;flex-direction:column;gap:6px;margin-top:2px;">
              ${teams.map(team => {
                const checked = !!userTeams.find(ut => ut.team_id === team.id);
                return `<label style="display:flex;align-items:center;gap:10px;padding:8px 10px;border:1px solid var(--border);border-radius:6px;cursor:pointer;font-size:13px;">
                  <input type="checkbox" name="um-team" value="${esc(team.id)}" ${checked?'checked':''} style="flex-shrink:0;">
                  <span style="flex:1;font-weight:500;">${esc(team.name)}</span>
                  <span style="font-size:11px;opacity:0.45;">${team.scope_count||0} ${(team.scope_count||0)!==1?t('users.grants_lbl'):t('users.grant_lbl')}</span>
                </label>`;
              }).join('')}
            </div>
            <p style="margin:6px 0 0;font-size:11px;opacity:0.55;">${t('users.team_inherit_modal')}</p>
          </div>` : ''}
        </div>
        <div class="dialog-actions">
          <button class="btn btn-secondary blueprint" onclick="document.getElementById('user-modal-container').innerHTML=''"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>${t('common.cancel')}</button>
          <button class="btn btn-primary blueprint" onclick="saveUser('${esc(id||'')}', ${isSuper})"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>${id ? t('common.save') : t('common.create')}</button>
        </div>
      </div>
    </div>`;
  renderUserScopes();
  window._addUserScope = function() {
    const type = document.getElementById('um-sc-type')?.value || 'domain';
    const value = document.getElementById('um-sc-val')?.value?.trim();
    const mode = document.getElementById('um-sc-mode')?.value || 'read';
    if (!value) return;
    window._userScopes.push({ type, value, mode });
    document.getElementById('um-sc-val').value = '';
    renderUserScopes();
  };
  window._removeUserScope = function(i) {
    window._userScopes.splice(i, 1);
    renderUserScopes();
  };
};

window.saveUser = async function(id, isSuper) {
  const checkedEls = [...document.querySelectorAll('input[name="um-team"]:checked')];
  const scopes = (window._userScopes || []).map(sc => ({
    scope_type: sc.type || sc.scope_type,
    value: sc.value || sc.scope_value,
    access_mode: sc.mode || sc.access_mode || 'read',
    id: sc.id,
  }));
  const payload = {
    email: document.getElementById('u-email').value.trim(),
    role: isSuper ? 'admin' : (document.querySelector('input[name="um-role"]:checked')?.value || 'user'),
    password: document.getElementById('u-pass').value,
    scopes,
  };
  // Le backend ignore le rôle demandé pour un superadmin ; on envoie quand même un rôle valide.
  if (!payload.password && id) delete payload.password;
  try {
    let uid = id;
    if (id) {
      await api('PUT', `/users/${id}`, payload);
    } else {
      const created = await api('POST', '/users', payload);
      uid = created.id;
    }

    const checkedIds = new Set(checkedEls.map(cb => cb.value));
    for (const cb of checkedEls) {
      await api('POST', `/teams/${cb.value}/members`, { user_id: uid }).catch(() => {});
    }
    for (const orig of (window._userOrigTeams || [])) {
      if (!checkedIds.has(orig.team_id)) {
        await api('DELETE', `/teams/${orig.team_id}/members/${uid}`).catch(() => {});
      }
    }

    toast(t('users.saved'), 'success');
    document.getElementById('user-modal-container').innerHTML = '';
    refreshUsers();
  } catch(e) { toast(e.message, 'error'); }
};

window.deleteUser = function(id) {
  confirm_(t('users.delete_confirm'), async () => {
    try { await api('DELETE', `/users/${id}`); toast(t('users.deleted'),'success'); refreshUsers(); }
    catch(e) { toast(e.message,'error'); }
  });
};

window.openTeamModal = async function(id) {
  let team = null;
  if (id) { try { team = await api('GET', `/teams/${id}`); } catch {} }
  let scopes = [];
  if (id) {
    try {
      const raw = await api('GET', `/teams/${id}/scopes`);
      scopes = (raw || []).map(sc => ({
        id: sc.id,
        type: sc.scope_type,
        value: sc.value,
        mode: sc.access_mode || 'read',
      }));
    } catch {}
  }
  window._scopesOrig = [...scopes];

  let _acProxies = [];
  try { _acProxies = await api('GET', '/proxies').catch(() => []); } catch {}
  let _acNodes = [];
  try { _acNodes = (await api('GET', '/nodes').catch(() => [])).filter(n => n.role === 'core'); } catch {}

  const renderScopes = () => {
    const el = document.getElementById('tm-scopes-list');
    if (el) el.innerHTML = grantListHtml(window._scopes || scopes, 'tm-scopes-list', 'window._removeScope');
  };

  document.getElementById('team-modal-container').innerHTML = `
    <style>
      #tm-ac-list { position:absolute;z-index:10001;background:var(--card-bg,#1a1a2e);border:1px solid var(--border);border-top:none;max-height:160px;overflow-y:auto;width:100%;box-sizing:border-box;display:none; }
      #tm-ac-list .ac-item { padding:6px 10px;font-size:12.5px;cursor:pointer;font-family:monospace; }
      #tm-ac-list .ac-item:hover, #tm-ac-list .ac-item.ac-active { background:var(--accent,#3a86ff22); }
      #tm-sc-wrap { position:relative;flex:1;min-width:120px; }
    </style>
    <div class="dialog-backdrop" style="position:fixed;inset:0;z-index:9999;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.55);">
      <div class="dialog blueprint" role="dialog" aria-modal="true" style="width:min(520px,96vw);max-width:none;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div class="dialog-title">${id ? t('users.edit_team') : t('users.new_team')}</div>
        <div class="dialog-body" style="display:flex;flex-direction:column;gap:14px;">
          <div class="field"><label>${t('users.team_name')}</label><input class="input" id="tm-name" placeholder="Backend" value="${esc(team?.name||'')}"></div>
          <div style="display:flex;flex-direction:column;gap:8px;">
            <label style="font-size:13px;font-weight:500;">${t('users.grants_scope')}</label>
            <p style="margin:0;font-size:11px;opacity:0.55;">${t('users.team_grants_hint')}</p>
            <div id="tm-scopes-list" style="display:flex;flex-direction:column;gap:4px;"></div>
            <div style="display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap;">
              <div class="seg">
                <label class="seg-opt"><input type="radio" name="tm-sc-type" value="domain" checked>domain</label>
                <label class="seg-opt"><input type="radio" name="tm-sc-type" value="server">server</label>
                <label class="seg-opt"><input type="radio" name="tm-sc-type" value="proxy">proxy</label>
                <label class="seg-opt"><input type="radio" name="tm-sc-type" value="core">core</label>
              </div>
              <div id="tm-sc-wrap">
                <input class="input" id="tm-sc-val" autocomplete="off" style="width:100%;box-sizing:border-box;" placeholder="*.corp.io">
                <div id="tm-ac-list"></div>
              </div>
              <select id="tm-sc-mode" style="font-size:12px;padding:4px 6px;border:1px solid var(--border);border-radius:4px;background:var(--input-bg,var(--card-bg));color:var(--text);">
                <option value="read">${t('users.read_opt')}</option>
                <option value="write" selected>${t('users.write_opt')}</option>
              </select>
              <button class="btn btn-ghost btn-icon" onclick="window._addScope()" title="${esc(t('users.add_grant'))}" style="flex-shrink:0;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/></svg>
              </button>
            </div>
          </div>
        </div>
        <div class="dialog-actions">
          <button class="btn btn-secondary blueprint" onclick="document.getElementById('team-modal-container').innerHTML=''"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>${t('common.cancel')}</button>
          <button class="btn btn-primary blueprint" onclick="saveTeam('${esc(id||'')}')"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>${id ? t('common.save') : t('common.create')}</button>
        </div>
      </div>
    </div>`;

  window._scopes = scopes;
  renderScopes();

  const acInput = document.getElementById('tm-sc-val');
  const acList  = document.getElementById('tm-ac-list');
  let acActive  = -1;

  function acSuggestions(type, q) {
    q = (q || '').toLowerCase();
    let items = [];
    if (type === 'proxy') {
      items = _acProxies.map(p => p.id);
    } else if (type === 'domain') {
      const hosts = new Set();
      _acProxies.forEach(p => { try { const r = JSON.parse(p.config||'{}'); if (r.host) hosts.add(r.host); } catch {} });
      items = [...hosts];
    } else if (type === 'server') {
      const urls = new Set();
      _acProxies.forEach(p => { try { const r = JSON.parse(p.config||'{}'); (r.backends||[]).forEach(b => { if (b.url) urls.add(b.url); }); } catch {} });
      items = [...urls];
    } else if (type === 'core') {
      items = _acNodes.map(n => n.node_name || n.display_name || n.id).filter(Boolean);
    }
    return items.filter(s => !q || s.toLowerCase().includes(q));
  }

  function acRender(items) {
    if (!items.length) { acList.style.display = 'none'; return; }
    acActive = -1;
    acList.innerHTML = items.slice(0, 20).map((s, i) =>
      `<div class="ac-item" data-val="${esc(s)}" onmousedown="event.preventDefault();window._acPick(${i})">${esc(s)}</div>`
    ).join('');
    acList.style.display = 'block';
  }

  window._acPick = function(i) {
    const items = acList.querySelectorAll('.ac-item');
    if (items[i]) acInput.value = items[i].dataset.val;
    acList.style.display = 'none';
  };

  acInput.addEventListener('input', () => {
    const type = document.querySelector('input[name="tm-sc-type"]:checked')?.value || 'domain';
    acRender(acSuggestions(type, acInput.value));
  });

  acInput.addEventListener('keydown', e => {
    const items = acList.querySelectorAll('.ac-item');
    if (!items.length) return;
    if (e.key === 'ArrowDown') { e.preventDefault(); acActive = Math.min(acActive+1, items.length-1); items.forEach((el,i) => el.classList.toggle('ac-active', i===acActive)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); acActive = Math.max(acActive-1, 0); items.forEach((el,i) => el.classList.toggle('ac-active', i===acActive)); }
    else if (e.key === 'Enter' && acActive >= 0) { e.preventDefault(); window._acPick(acActive); }
    else if (e.key === 'Escape') { acList.style.display = 'none'; }
  });

  acInput.addEventListener('blur', () => { setTimeout(() => { acList.style.display = 'none'; }, 150); });

  document.querySelectorAll('input[name="tm-sc-type"]').forEach(r => {
    r.addEventListener('change', () => {
      const placeholders = { domain: '*.corp.io', server: 'http://10.0.0.*', proxy: 'uuid…', core: 'core-paris-*' };
      acInput.placeholder = placeholders[r.value] || '';
      acList.style.display = 'none';
      acInput.value = '';
    });
  });

  window._addScope = function() {
    const type = document.querySelector('input[name="tm-sc-type"]:checked')?.value || 'domain';
    const value = acInput?.value?.trim();
    const mode = document.getElementById('tm-sc-mode')?.value || 'read';
    if (!value) return;
    window._scopes.push({ type, value, mode });
    acInput.value = '';
    acList.style.display = 'none';
    renderScopes();
  };

  window._removeScope = function(i) { window._scopes.splice(i, 1); renderScopes(); };
};

window.saveTeam = async function(id) {
  const name = document.getElementById('tm-name').value.trim();
  if (!name) { toast(t('users.name_required'), 'error'); return; }
  try {
    let tid = id;
    if (id) {
      await api('PUT', `/teams/${id}`, { name });
    } else {
      const created = await api('POST', '/teams', { name });
      tid = created.id;
    }

    const currentScopes = window._scopes || [];
    const origScopes = window._scopesOrig || [];

    // Remplace tous les grants (mode inclus)
    for (const orig of origScopes) {
      if (orig.id) await api('DELETE', `/teams/${tid}/scopes/${orig.id}`).catch(() => {});
    }
    for (const sc of currentScopes) {
      await api('POST', `/teams/${tid}/scopes`, {
        scope_type: sc.type || sc.scope_type,
        value: sc.value || sc.scope_value,
        access_mode: sc.mode || sc.access_mode || 'read',
      }).catch(() => {});
    }

    toast(t('users.team_saved'), 'success');
    document.getElementById('team-modal-container').innerHTML = '';
    refreshUsers();
  } catch(e) { toast(e.message, 'error'); }
};

window.deleteTeam = function(id) {
  confirm_(t('users.team_delete_confirm'), async () => {
    try { await api('DELETE', `/teams/${id}`); toast(t('users.team_deleted'),'success'); refreshUsers(); }
    catch(e) { toast(e.message,'error'); }
  });
};
