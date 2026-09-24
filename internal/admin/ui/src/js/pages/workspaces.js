// ── Gestion d'équipe : fusion Utilisateurs & équipes + Espaces de travail ──
// Deux onglets dans une même page. `pages.users` reste accessible en direct
// (liens internes access-policies.js / infrastructure.js) et rend refreshUsers()
// en plein écran, sans onglets.

pages.workspaces = async function() {
  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML = '';
  content.innerHTML = `
    <div style="margin-bottom:20px;">
      <h1 style="margin:0 0 4px;font-size:28px;font-family:var(--font-heading);font-weight:600;">${t('workspaces.title')}</h1>
      <p style="margin:0;opacity:0.65;font-size:14px;">${t('workspaces.subtitle')}</p>
    </div>
    <div style="display:flex;gap:0;border-bottom:1px solid var(--border);margin-bottom:20px;" id="wsteam-tabs">
      <button class="btn btn-ghost" style="border-radius:0;border-bottom:2px solid transparent;font-size:13px;padding:8px 14px;" id="wsteam-tab-btn-users" onclick="wsTeamSwitchTab('users')">${t('users.title')}</button>
      <button class="btn btn-ghost" style="border-radius:0;border-bottom:2px solid transparent;font-size:13px;padding:8px 14px;" id="wsteam-tab-btn-spaces" onclick="wsTeamSwitchTab('spaces')">${t('workspaces.tab_spaces')}</button>
    </div>
    <div id="wsteam-tab-body"></div>`;
  await wsTeamSwitchTab(window._wsTeamActiveTab || 'users');
};

window.wsTeamSwitchTab = async function(tab) {
  window._wsTeamActiveTab = tab;
  ['users', 'spaces'].forEach(k => {
    const btn = document.getElementById('wsteam-tab-btn-' + k);
    if (btn) btn.style.borderBottom = k === tab ? '2px solid var(--accent)' : '2px solid transparent';
  });
  const body = document.getElementById('wsteam-tab-body');
  if (!body) return;
  if (tab === 'users') {
    await refreshUsers(body);
  } else {
    await renderWorkspacesGrid(body);
  }
};

async function renderWorkspacesGrid(container) {
  container.innerHTML = `<p style="opacity:0.5;font-size:13px;">${t('common.loading')}</p>`;
  try {
    const [workspaces, proxies, nodes, teams, users] = await Promise.all([
      api('GET', '/workspaces').catch(() => []),
      api('GET', '/proxies').catch(() => []),
      api('GET', '/nodes').catch(() => []),
      api('GET', '/teams').catch(() => []),
      api('GET', '/users').catch(() => []),
    ]);
    window._wsProxies = proxies || [];
    window._wsNodes = nodes || [];
    window._wsTeams = teams || [];
    window._wsUsers = users || [];

    const list = workspaces || [];
    container.innerHTML = `
      <div style="display:flex;justify-content:flex-end;margin-bottom:16px;">
        <button class="btn btn-primary blueprint" onclick="openWorkspaceModal()">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          ${t('workspaces.new')}
        </button>
      </div>
      <div id="workspaces-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(min(320px,100%),1fr));gap:16px;">
        ${list.length ? list.map(ws => workspaceCard(ws)).join('') : `
          <div style="grid-column:1/-1;text-align:center;padding:48px 16px;opacity:0.5;font-size:14px;">
            <svg width="40" height="40" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24" style="margin-bottom:12px;opacity:0.4;"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
            <p>${t('workspaces.empty')}</p>
          </div>`}
      </div>`;
  } catch(e) {
    container.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`;
  }
}

function _refreshWorkspacesTab() {
  const body = document.getElementById('wsteam-tab-body');
  if (body) renderWorkspacesGrid(body);
}

function workspaceCard(ws) {
  return `<div class="card blueprint" style="padding:0;cursor:pointer;" onclick="openWorkspaceDetail('${esc(ws.id)}')">
    <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
    <div style="padding:16px 18px 12px;">
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px;margin-bottom:8px;">
        <h3 style="margin:0;font-size:16px;font-weight:600;line-height:1.3;">${esc(ws.name)}</h3>
        <div style="display:flex;gap:6px;flex-shrink:0;" onclick="event.stopPropagation()">
          <button class="btn btn-ghost btn-icon" onclick="openWorkspaceModal('${esc(ws.id)}')" title="${esc(t('common.edit'))}"><svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>
          <button class="btn btn-ghost btn-icon" onclick="deleteWorkspace('${esc(ws.id)}')" title="${esc(t('common.delete'))}"><svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24"><path d="M3 6h18"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg></button>
        </div>
      </div>
      ${ws.description ? `<p style="margin:0 0 12px;font-size:13px;opacity:0.65;line-height:1.45;">${esc(ws.description)}</p>` : ''}
    </div>
    <div style="display:flex;gap:0;border-top:1px solid var(--border);">
      <div style="flex:1;padding:10px 14px;text-align:center;border-right:1px solid var(--border);">
        <div style="font-size:22px;font-weight:700;line-height:1;">${ws.member_count || 0}</div>
        <div style="font-size:10px;opacity:0.5;text-transform:uppercase;letter-spacing:0.07em;margin-top:2px;">${(ws.member_count||0)!==1?t('workspaces.members_lbl'):t('workspaces.member_lbl')}</div>
      </div>
      <div style="flex:1;padding:10px 14px;text-align:center;">
        <div style="font-size:22px;font-weight:700;line-height:1;">${ws.resource_count || 0}</div>
        <div style="font-size:10px;opacity:0.5;text-transform:uppercase;letter-spacing:0.07em;margin-top:2px;">${(ws.resource_count||0)!==1?t('workspaces.resources_lbl'):t('workspaces.resource_lbl')}</div>
      </div>
    </div>
  </div>`;
}

window.openWorkspaceModal = async function(id) {
  document.getElementById('ws-modal-backdrop')?.remove();
  let ws = null;
  if (id) {
    try { ws = await api('GET', `/workspaces/${id}`); } catch {}
  }
  document.body.insertAdjacentHTML('beforeend', `
    <div id="ws-modal-backdrop" class="dialog-backdrop" style="background:rgba(0,0,0,0.55);">
      <div class="dialog blueprint" role="dialog" aria-modal="true" style="width:min(460px,96vw);max-width:none;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div class="dialog-title">${id ? t('workspaces.edit') : t('workspaces.new')}</div>
        <div class="dialog-body" style="display:flex;flex-direction:column;gap:14px;">
          <div class="field"><label>${t('workspaces.name_lbl')}</label><input class="input" id="ws-name" placeholder="${esc(t('workspaces.name_ph'))}" value="${esc(ws?.name||'')}"></div>
          <div class="field"><label>${t('workspaces.desc_lbl')}</label><textarea class="input" id="ws-desc" rows="2" style="resize:vertical;">${esc(ws?.description||'')}</textarea></div>
        </div>
        <div class="dialog-footer">
          <button class="btn btn-secondary" onclick="document.getElementById('ws-modal-backdrop').remove()">${t('common.cancel')}</button>
          <button class="btn btn-primary blueprint" onclick="saveWorkspace('${esc(id||'')}')"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>${id ? t('common.save') : t('common.create')}</button>
        </div>
      </div>
    </div>`);
};

window.saveWorkspace = async function(id) {
  const name = document.getElementById('ws-name')?.value?.trim();
  const desc = document.getElementById('ws-desc')?.value || '';
  if (!name) return;
  try {
    if (id) {
      await api('PUT', `/workspaces/${id}`, { name, description: desc });
    } else {
      await api('POST', '/workspaces', { name, description: desc });
    }
    document.getElementById('ws-modal-backdrop')?.remove();
    _refreshWorkspacesTab();
  } catch(e) { alert(e.message); }
};

window.deleteWorkspace = function(id) {
  if (!confirm(t('workspaces.confirm_delete'))) return;
  api('DELETE', `/workspaces/${id}`).then(() => _refreshWorkspacesTab()).catch(e => alert(e.message));
};

window.openWorkspaceDetail = async function(id) {
  document.getElementById('ws-detail-backdrop')?.remove();
  document.body.insertAdjacentHTML('beforeend', `<div id="ws-detail-backdrop" class="dialog-backdrop" style="align-items:flex-start;justify-content:flex-end;background:rgba(0,0,0,0.4);">
    <div style="width:min(540px,98vw);height:100vh;overflow:auto;background:var(--card-bg);border-left:1px solid var(--border);padding:24px 20px;">
      <p style="opacity:0.5;font-size:13px;">${t('common.loading')}</p>
    </div>
  </div>`);
  try {
    const ws = await api('GET', `/workspaces/${id}`);
    _renderWorkspacePanel(ws);
  } catch(e) {
    document.getElementById('ws-detail-backdrop')?.remove();
    alert(e.message);
  }
};

function _renderWorkspacePanel(ws) {
  const container = document.getElementById('ws-detail-backdrop');
  const teams = window._wsTeams || [];
  const users = window._wsUsers || [];
  const proxies = window._wsProxies || [];
  const nodes = window._wsNodes || [];

  const memberOptions = [
    ...teams.map(t => `<option value="team/${esc(t.id)}">[${esc('équipe')}] ${esc(t.name)}</option>`),
    ...users.map(u => `<option value="user/${esc(u.id)}">[${esc('user')}] ${esc(u.email)}</option>`),
  ].join('');

  const resourceOptions = [
    ...proxies.map(p => `<option value="proxy/${esc(p.id)}">[proxy] ${esc(p.name)}</option>`),
    ...nodes.filter(n => n.role === 'core').map(n => `<option value="core/${esc(n.id)}">[core] ${esc(n.node_name||n.name||n.id)}</option>`),
    `<option value="domain/">domain: (saisir manuellement)</option>`,
  ].join('');

  container.innerHTML = `
    <div id="ws-detail-backdrop" class="dialog-backdrop" style="align-items:flex-start;justify-content:flex-end;background:rgba(0,0,0,0.4);" onclick="if(event.target===this)document.getElementById('ws-detail-backdrop').remove()">
      <div style="width:min(540px,98vw);height:100vh;overflow:auto;background:var(--card-bg);border-left:1px solid var(--border);padding:24px 20px;" onclick="event.stopPropagation()">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;">
          <div>
            <h2 style="margin:0 0 4px;font-size:20px;font-weight:700;">${esc(ws.name)}</h2>
            ${ws.description ? `<p style="margin:0;font-size:13px;opacity:0.6;">${esc(ws.description)}</p>` : ''}
          </div>
          <button class="btn btn-ghost btn-icon" onclick="document.getElementById('ws-detail-backdrop').remove()"><svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </div>

        <!-- Membres -->
        <div style="margin-bottom:24px;">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;">
            <h3 style="margin:0;font-size:13px;text-transform:uppercase;letter-spacing:0.08em;opacity:0.55;">${t('workspaces.members_section')}</h3>
          </div>
          <div id="ws-members-list" style="display:flex;flex-direction:column;gap:4px;margin-bottom:10px;">
            ${ws.members.length ? ws.members.map(m => `
              <div style="display:flex;align-items:center;gap:8px;padding:7px 10px;border:1px solid var(--border);border-radius:6px;font-size:13px;">
                <span class="tag tag-outline" style="font-size:10px;">${esc(m.entity_type)}</span>
                <span style="flex:1;">${esc(m.entity_name||m.entity_id)}</span>
                <button class="btn btn-ghost btn-icon" onclick="wsRemoveMember('${esc(ws.id)}','${esc(m.entity_type)}','${esc(m.entity_id)}')"><svg width="11" height="11" fill="none" stroke="currentColor" stroke-width="1.5"><line x1="10" y1="2" x2="2" y2="10"/><line x1="2" y1="2" x2="10" y2="10"/></svg></button>
              </div>`).join('') : `<p style="margin:0;font-size:12px;opacity:0.45;">${t('workspaces.no_member')}</p>`}
          </div>
          <div style="display:flex;gap:6px;">
            <select id="ws-add-member" class="input" style="flex:1;font-size:12px;">
              <option value="">${t('workspaces.select_member')}</option>
              ${memberOptions}
            </select>
            <button class="btn btn-secondary btn-sm" onclick="wsAddMember('${esc(ws.id)}')">${t('common.add')}</button>
          </div>
        </div>

        <!-- Ressources -->
        <div>
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;">
            <h3 style="margin:0;font-size:13px;text-transform:uppercase;letter-spacing:0.08em;opacity:0.55;">${t('workspaces.resources_section')}</h3>
          </div>
          <div id="ws-resources-list" style="display:flex;flex-direction:column;gap:4px;margin-bottom:10px;">
            ${ws.resources.length ? ws.resources.map(r => `
              <div style="display:flex;align-items:center;gap:8px;padding:7px 10px;border:1px solid var(--border);border-radius:6px;font-size:13px;">
                <span class="tag tag-outline" style="font-size:10px;">${esc(r.resource_type)}</span>
                <code style="flex:1;font-size:12px;">${esc(r.resource_name||r.resource_id)}</code>
                <button class="btn btn-ghost btn-icon" onclick="wsRemoveResource('${esc(ws.id)}','${esc(r.resource_type)}','${esc(r.resource_id)}')"><svg width="11" height="11" fill="none" stroke="currentColor" stroke-width="1.5"><line x1="10" y1="2" x2="2" y2="10"/><line x1="2" y1="2" x2="10" y2="10"/></svg></button>
              </div>`).join('') : `<p style="margin:0;font-size:12px;opacity:0.45;">${t('workspaces.no_resource')}</p>`}
          </div>
          <div style="display:flex;gap:6px;flex-wrap:wrap;">
            <select id="ws-add-res-type-sel" class="input" style="flex:1;min-width:180px;font-size:12px;">
              <option value="">${t('workspaces.select_resource')}</option>
              ${resourceOptions}
            </select>
            <input class="input" id="ws-add-res-custom" placeholder="id ou pattern (domain:*.corp.io)" style="flex:1;min-width:140px;font-size:12px;display:none;">
            <button class="btn btn-secondary btn-sm" onclick="wsAddResource('${esc(ws.id)}')">${t('common.add')}</button>
          </div>
          <p style="margin:6px 0 0;font-size:11px;opacity:0.45;">${t('workspaces.domain_hint')}</p>
        </div>
      </div>
    </div>`;

  document.getElementById('ws-add-res-type-sel')?.addEventListener('change', function() {
    const custom = document.getElementById('ws-add-res-custom');
    if (this.value.startsWith('domain/')) {
      custom.style.display = '';
      custom.placeholder = '*.corp.io';
    } else {
      custom.style.display = 'none';
    }
  });
}

window.wsAddMember = async function(wsId) {
  const sel = document.getElementById('ws-add-member');
  if (!sel?.value) return;
  const [entityType, entityId] = sel.value.split('/');
  try {
    await api('POST', `/workspaces/${wsId}/members`, { entity_type: entityType, entity_id: entityId });
    const ws = await api('GET', `/workspaces/${wsId}`);
    _renderWorkspacePanel(ws);
    _refreshWorkspaceGrid(ws);
  } catch(e) { alert(e.message); }
};

window.wsRemoveMember = async function(wsId, entityType, entityId) {
  try {
    await api('DELETE', `/workspaces/${wsId}/members/${entityType}/${entityId}`);
    const ws = await api('GET', `/workspaces/${wsId}`);
    _renderWorkspacePanel(ws);
    _refreshWorkspaceGrid(ws);
  } catch(e) { alert(e.message); }
};

window.wsAddResource = async function(wsId) {
  const sel = document.getElementById('ws-add-res-type-sel');
  if (!sel?.value) return;
  let [resourceType, resourceId] = sel.value.split('/');
  if (resourceType === 'domain') {
    const custom = document.getElementById('ws-add-res-custom');
    resourceId = custom?.value?.trim();
    if (!resourceId) return;
  }
  try {
    await api('POST', `/workspaces/${wsId}/resources`, { resource_type: resourceType, resource_id: resourceId });
    const ws = await api('GET', `/workspaces/${wsId}`);
    _renderWorkspacePanel(ws);
    _refreshWorkspaceGrid(ws);
  } catch(e) { alert(e.message); }
};

window.wsRemoveResource = async function(wsId, resourceType, resourceId) {
  try {
    await api('DELETE', `/workspaces/${wsId}/resources/${resourceType}/${resourceId}`);
    const ws = await api('GET', `/workspaces/${wsId}`);
    _renderWorkspacePanel(ws);
    _refreshWorkspaceGrid(ws);
  } catch(e) { alert(e.message); }
};

function _refreshWorkspaceGrid(ws) {
  const grid = document.getElementById('workspaces-grid');
  if (!grid) return;
  const card = grid.querySelector(`[onclick*="${ws.id}"]`);
  if (card) card.outerHTML = workspaceCard(ws);
}
