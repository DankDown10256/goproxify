// ── PAGE PARTAGÉE: Catalogue portail Access (Admin + Core)
// ctx = { mode: 'admin'|'core' }

async function renderPortalCatalogPage(ctx) {
  const mode = ctx.mode || 'admin';
  const isAdmin = mode === 'admin';
  const core = isAdmin ? null : state.selectedCore;
  const coreName = core?.node_name || '';
  const coreLabel = core ? (core.display_name || coreName || '—') : '';

  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML = '';
  content.innerHTML = '<p style="color:var(--text2)">' + t('common.loading') + '</p>';

  if (!isAdmin && !coreName) {
    content.innerHTML = `<div class="empty"><p>${esc(t('portal.need_core') || 'Sélectionnez un Core')}</p></div>`;
    return;
  }

  try {
    const destPath = isAdmin ? '/portal/destinations' : '/portal/destinations?core=' + encodeURIComponent(coreName);
    const [destRes, nodesRes, containersRes] = await Promise.all([
      api('GET', destPath).catch(() => ({ destinations: [] })),
      isAdmin ? api('GET', '/nodes').catch(() => []) : Promise.resolve([]),
      api('GET', '/discovered-containers').catch(() => []),
    ]);

    let destinations = destRes.destinations || destRes || [];
    if (!Array.isArray(destinations)) destinations = [];
    const cores = (nodesRes || []).filter(n => n.role === 'core');
    window._portalCatalogCores = cores;
    window._portalCatalogAll = destinations;
    window._portalDiscovered = containersRes || [];

    if (!window._pcFilter) window._pcFilter = { core: '', kind: '', q: '' };

    const filtered = () => {
      const f = window._pcFilter;
      return (window._portalCatalogAll || []).filter(d => {
        if (f.core && d.core_name !== f.core) return false;
        if (f.kind && d.kind !== f.kind) return false;
        if (f.q) {
          const hay = [d.name, d.host, d.agent_name, d.container, ...(d.tags || [])].join(' ').toLowerCase();
          if (!hay.includes(f.q.toLowerCase())) return false;
        }
        return true;
      });
    };

    const render = () => {
      const items = filtered();
      const chips = isAdmin ? cores.map(c => {
        const nn = c.node_name || c.id;
        const active = window._pcFilter.core === nn;
        return `<button type="button" class="chip" data-core="${esc(nn)}" style="cursor:pointer;${active ? 'border-color:var(--accent);color:var(--accent)' : ''}">${esc(c.display_name || nn)}</button>`;
      }).join('') : '';

      document.getElementById('topbar-actions').innerHTML = `
        <button class="btn btn-primary" id="pc-add">${esc(t('pcatalog.add') || 'Nouvelle destination')}</button>`;

      content.innerHTML = `
        <div style="margin-bottom:16px">
          <h1 style="margin:0 0 4px;font-size:22px;font-family:var(--font-heading);font-weight:600">
            ${esc(t('pcatalog.title') || 'Catalogue Access')}
          </h1>
          <p style="margin:0;font-size:13px;color:var(--text2)">
            ${isAdmin
              ? esc(t('pcatalog.sub_admin') || 'Destinations de tous les Cores.')
              : (t('pcatalog.sub_core') || 'Destinations de {name}.').replace('{name}', '<strong>' + esc(coreLabel) + '</strong>')}
          </p>
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:14px;align-items:center">
          <input class="input" id="pc-q" placeholder="${esc(t('pcatalog.search') || 'Rechercher…')}" value="${esc(window._pcFilter.q)}" style="max-width:220px"/>
          <select class="input" id="pc-kind" style="max-width:140px">
            <option value="">${esc(t('pcatalog.all_kinds') || 'Tous types')}</option>
            <option value="ssh" ${window._pcFilter.kind === 'ssh' ? 'selected' : ''}>SSH</option>
            <option value="docker" ${window._pcFilter.kind === 'docker' ? 'selected' : ''}>Docker</option>
          </select>
          ${isAdmin ? `<div style="display:flex;flex-wrap:wrap;gap:6px;align-items:center">
            <button type="button" class="chip" data-core="" style="cursor:pointer;${!window._pcFilter.core ? 'border-color:var(--accent);color:var(--accent)' : ''}">${esc(t('pcatalog.all_cores') || 'Tous')}</button>
            ${chips}
          </div>` : ''}
          <div style="display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-left:auto">
            <input class="input" id="pc-preview-tags" placeholder="${esc(t('pcatalog.preview_tags') || 'Preview tags…')}" value="${esc(window._pcPreviewTags || '')}" style="max-width:160px"/>
            <button type="button" class="btn btn-secondary btn-sm" id="pc-preview">${esc(t('pcatalog.preview') || 'Preview filtre')}</button>
            ${window._pcPreview ? `<button type="button" class="btn btn-ghost btn-sm" id="pc-preview-clear">${esc(t('pcatalog.preview_clear') || 'Effacer')}</button>` : ''}
          </div>
        </div>
        ${window._pcPreview ? `<div style="margin-bottom:12px;font-size:12px;color:var(--text2)">
          ${(t('pcatalog.preview_result') || 'Visible {v} · masqué {h} pour tags [{tags}]')
            .replace('{v}', String(window._pcPreview.visible_n || 0))
            .replace('{h}', String(window._pcPreview.hidden_n || 0))
            .replace('{tags}', esc((window._pcPreview.user_tags || []).join(', ') || '—'))}
        </div>` : ''}
        <div id="pc-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(min(240px,100%),1fr));gap:12px">
          ${items.length ? items.map(tileHTML).join('') : `
            <div style="grid-column:1/-1;padding:24px;text-align:center;color:var(--text2);border:1px dashed var(--border);border-radius:8px">
              ${esc(t('pcatalog.empty') || 'Aucune destination')}
            </div>`}
        </div>
        <div id="pc-modal" style="display:none"></div>`;

      document.getElementById('pc-q').oninput = (e) => { window._pcFilter.q = e.target.value; render(); };
      document.getElementById('pc-kind').onchange = (e) => { window._pcFilter.kind = e.target.value; render(); };
      content.querySelectorAll('[data-core]').forEach(btn => {
        btn.onclick = () => { window._pcFilter.core = btn.getAttribute('data-core') || ''; render(); };
      });
      document.getElementById('pc-add').onclick = () => openEditor(null);
      document.getElementById('pc-preview').onclick = async () => {
        window._pcPreviewTags = document.getElementById('pc-preview-tags').value.trim();
        try {
          let path = '/portal/destinations/preview?tags=' + encodeURIComponent(window._pcPreviewTags);
          const c = isAdmin ? window._pcFilter.core : coreName;
          if (c) path += '&core=' + encodeURIComponent(c);
          window._pcPreview = await api('GET', path);
          render();
        } catch (e) { alert(e.message || e); }
      };
      const clr = document.getElementById('pc-preview-clear');
      if (clr) clr.onclick = () => { window._pcPreview = null; window._pcPreviewTags = ''; render(); };
      content.querySelectorAll('[data-edit]').forEach(btn => {
        btn.onclick = () => {
          const d = (window._portalCatalogAll || []).find(x => x.id === btn.getAttribute('data-edit'));
          if (d) openEditor(d);
        };
      });
      content.querySelectorAll('[data-del]').forEach(btn => {
        btn.onclick = async () => {
          if (!confirm(t('pcatalog.confirm_del') || 'Supprimer ?')) return;
          try {
            await api('DELETE', '/portal/destinations/' + encodeURIComponent(btn.getAttribute('data-del')));
            window._portalCatalogAll = (window._portalCatalogAll || []).filter(x => x.id !== btn.getAttribute('data-del'));
            render();
          } catch (e) { alert(e.message || e); }
        };
      });
    };

    function tileHTML(d) {
      const tags = (d.tags || []).map(tg => `<span class="tag tag-neutral" style="font-size:10px">${esc(tg)}</span>`).join(' ');
      const meta = d.kind === 'docker'
        ? `${esc(d.agent_name || '')} / ${esc(d.container || '')}`
        : `${esc(d.host || '')}:${d.port || 22}`;
      const coreChip = isAdmin ? `<span class="tag tag-outline" style="font-size:10px">${esc(d.core_name)}</span>` : '';
      let opacity = '';
      if (window._pcPreview) {
        const hid = (window._pcPreview.hidden || []).some(x => x.id === d.id);
        if (hid) opacity = 'opacity:.38';
      }
      return `
        <div class="card blueprint" style="padding:14px 16px;display:flex;flex-direction:column;gap:8px;min-height:130px;${opacity}">
          <div style="display:flex;justify-content:space-between;gap:8px;align-items:flex-start">
            <div style="font-weight:600;font-size:14px;word-break:break-word">${esc(d.name)}</div>
            <span class="tag ${d.kind === 'docker' ? 'tag-neutral' : 'tag-accent'}" style="font-size:10px;text-transform:uppercase">${esc(d.kind)}</span>
          </div>
          <div style="font-family:ui-monospace,monospace;font-size:11px;color:var(--text2);word-break:break-all">${meta}</div>
          <div style="display:flex;flex-wrap:wrap;gap:4px">${coreChip}${tags}</div>
          <div style="display:flex;gap:4px;margin-top:auto;justify-content:flex-end">
            <button type="button" class="btn btn-ghost btn-icon btn-sm" data-edit="${esc(d.id)}" title="${esc(t('common.edit') || 'Modifier')}">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
            </button>
            <button type="button" class="btn btn-ghost btn-icon btn-sm" data-del="${esc(d.id)}" title="${esc(t('common.delete') || 'Supprimer')}" style="color:var(--danger,#c45c5c)">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
            </button>
          </div>
        </div>`;
    }

    function openEditor(dest) {
      const isNew = !dest;
      const d = dest ? { ...dest } : {
        core_name: isAdmin ? (window._pcFilter.core || (cores[0]?.node_name || '')) : coreName,
        kind: 'ssh', name: '', host: '', port: 22, agent_name: '', container: '', tags: [], enabled: true,
      };
      const discovered = (window._portalDiscovered || []).filter(c =>
        !d.core_name || c.core_name === d.core_name
      );
      const coreOptions = isAdmin
        ? cores.map(c => {
            const nn = c.node_name || c.id;
            return `<option value="${esc(nn)}" ${d.core_name === nn ? 'selected' : ''}>${esc(c.display_name || nn)}</option>`;
          }).join('')
        : `<option value="${esc(coreName)}" selected>${esc(coreLabel)}</option>`;

      const suggestOpts = discovered.map((c, i) => {
        const cid = (c.container_ids && c.container_ids[0]) || c.id || '';
        const label = `${c.agent_name || '?'} — ${c.host || cid}`.slice(0, 80);
        return `<option value="${i}">${esc(label)}</option>`;
      }).join('');

      const modal = document.getElementById('pc-modal');
      modal.style.display = 'block';
      modal.innerHTML = `
        <div style="position:fixed;inset:0;background:rgba(0,0,0,.35);z-index:80;display:flex;align-items:center;justify-content:center;padding:16px" id="pc-backdrop">
          <div class="card blueprint" style="width:min(520px,100%);max-height:90vh;overflow:auto;padding:18px;background:var(--bg)">
            <div style="font-weight:700;font-size:16px;margin-bottom:12px">${esc(isNew ? (t('pcatalog.add') || 'Nouvelle destination') : (t('common.edit') || 'Éditer'))}</div>
            <div class="field" style="margin-bottom:8px"><label class="field-label">Core</label>
              <select class="input" id="pe-core" ${isAdmin ? '' : 'disabled'}>${coreOptions}</select>
            </div>
            <div class="field" style="margin-bottom:8px"><label class="field-label">${esc(t('pcatalog.name') || 'Nom')}</label>
              <input class="input" id="pe-name" value="${esc(d.name || '')}"/>
            </div>
            <div class="field" style="margin-bottom:8px"><label class="field-label">Type</label>
              <select class="input" id="pe-kind">
                <option value="ssh" ${d.kind === 'ssh' ? 'selected' : ''}>SSH</option>
                <option value="docker" ${d.kind === 'docker' ? 'selected' : ''}>Docker</option>
              </select>
            </div>
            <div id="pe-ssh">
              <div class="field" style="margin-bottom:8px"><label class="field-label">Host</label><input class="input" id="pe-host" value="${esc(d.host || '')}"/></div>
              <div class="field" style="margin-bottom:8px"><label class="field-label">Port</label><input class="input" id="pe-port" type="number" value="${d.port || 22}"/></div>
            </div>
            <div id="pe-docker" class="hidden">
              <div class="field" style="margin-bottom:8px"><label class="field-label">${esc(t('pcatalog.suggest') || 'Depuis découverte')}</label>
                <select class="input" id="pe-suggest"><option value="">—</option>${suggestOpts}</select>
              </div>
              <div class="field" style="margin-bottom:8px"><label class="field-label">Agent</label><input class="input" id="pe-agent" value="${esc(d.agent_name || '')}"/></div>
              <div class="field" style="margin-bottom:8px"><label class="field-label">Container</label><input class="input" id="pe-container" value="${esc(d.container || '')}"/></div>
            </div>
            <div class="field" style="margin-bottom:8px"><label class="field-label">Tags</label>
              <input class="input" id="pe-tags" value="${esc((d.tags || []).join(', '))}" placeholder="prod, devops"/>
            </div>
            <label style="display:flex;align-items:center;gap:8px;margin:10px 0;font-size:13px">
              <input type="checkbox" id="pe-enabled" ${d.enabled !== false ? 'checked' : ''}/> ${esc(t('common.enabled') || 'Activé')}
            </label>
            <div id="pe-msg" style="font-size:12px;min-height:1.1em;color:var(--danger,#c45c5c)"></div>
            <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:12px">
              <button type="button" class="btn btn-ghost" id="pe-cancel">${esc(t('common.cancel') || 'Annuler')}</button>
              <button type="button" class="btn btn-primary" id="pe-save">${esc(t('common.save') || 'Enregistrer')}</button>
            </div>
          </div>
        </div>`;

      const syncKind = () => {
        const docker = document.getElementById('pe-kind').value === 'docker';
        document.getElementById('pe-docker').classList.toggle('hidden', !docker);
        document.getElementById('pe-ssh').classList.toggle('hidden', docker);
      };
      syncKind();
      document.getElementById('pe-kind').onchange = syncKind;
      document.getElementById('pe-suggest').onchange = (e) => {
        const i = e.target.value;
        if (i === '') return;
        const c = discovered[+i];
        if (!c) return;
        document.getElementById('pe-agent').value = c.agent_name || '';
        const cid = (c.container_ids && c.container_ids[0]) || '';
        document.getElementById('pe-container').value = cid || (c.id || '').replace(/^docker:/, '').split(':')[0] || '';
        if (!document.getElementById('pe-name').value) {
          document.getElementById('pe-name').value = c.host || document.getElementById('pe-container').value;
        }
        document.getElementById('pe-kind').value = 'docker';
        syncKind();
      };
      document.getElementById('pe-cancel').onclick = () => { modal.style.display = 'none'; modal.innerHTML = ''; };
      document.getElementById('pc-backdrop').onclick = (ev) => {
        if (ev.target.id === 'pc-backdrop') { modal.style.display = 'none'; modal.innerHTML = ''; }
      };
      document.getElementById('pe-save').onclick = async () => {
        const msg = document.getElementById('pe-msg');
        try {
          const body = {
            core_name: document.getElementById('pe-core').value,
            name: document.getElementById('pe-name').value.trim(),
            kind: document.getElementById('pe-kind').value,
            host: document.getElementById('pe-host').value.trim(),
            port: +document.getElementById('pe-port').value || 22,
            agent_name: document.getElementById('pe-agent').value.trim(),
            container: document.getElementById('pe-container').value.trim(),
            tags: document.getElementById('pe-tags').value.split(',').map(s => s.trim()).filter(Boolean),
            enabled: document.getElementById('pe-enabled').checked,
          };
          let saved;
          if (isNew) {
            saved = await api('POST', '/portal/destinations', body);
            window._portalCatalogAll = [...(window._portalCatalogAll || []), saved];
          } else {
            saved = await api('PUT', '/portal/destinations/' + encodeURIComponent(d.id), body);
            window._portalCatalogAll = (window._portalCatalogAll || []).map(x => x.id === d.id ? saved : x);
          }
          modal.style.display = 'none';
          modal.innerHTML = '';
          render();
        } catch (e) {
          msg.textContent = e.message || String(e);
        }
      };
    }

    render();
  } catch (e) {
    content.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`;
  }
}

pages['admin-portal-catalog'] = async function() {
  await renderPortalCatalogPage({ mode: 'admin' });
};

pages['core-portal-catalog'] = async function() {
  await renderPortalCatalogPage({ mode: 'core' });
};
