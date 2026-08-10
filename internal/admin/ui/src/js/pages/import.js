// ── PAGE: Import / Restore
// Extrait de pages-all.js — phase 4.

// ── PAGE: Import / Restore ─────────────────────────────────────────────────
pages.import = function() {
  const main = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML = '';
  let activeTab = 'backup'; // backup | migrate | export
  let backupData = null, backupSummary = null, configProxies = null;
  let selectedFmt = null;

  const IMP_TABS = [
    {
      id: 'backup',
      titleKey: 'import.tab.restore.title',
      descKey: 'import.tab.restore.desc',
      icon: '<path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>',
    },
    {
      id: 'migrate',
      titleKey: 'import.tab.migrate.title',
      descKey: 'import.tab.migrate.desc',
      icon: '<polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>',
    },
    {
      id: 'export',
      titleKey: 'import.tab.export.title',
      descKey: 'import.tab.export.desc',
      icon: '<path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>',
    },
  ];

  const IMP_ENTITIES = [
    ['imp-users', 'import.entity.users', '<circle cx="8" cy="6" r="3"/><path d="M2 14c0-3 2.7-5 6-5s6 2 6 5"/>'],
    ['imp-tokens', 'import.entity.tokens', '<path d="M7 11a4 4 0 100-8 4 4 0 000 8zM11 11l4 4"/>'],
    ['imp-snippets', 'import.entity.snippets', '<polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>'],
    ['imp-channels', 'import.entity.channels', '<path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 01-3.46 0"/>'],
    ['imp-rules', 'import.entity.rules', '<path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>'],
  ];

  const IMP_EXPORT_TILES = [
    ['<path d="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z"/>', 'import.export.tile.proxies', 'import.export.tile.proxies_desc'],
    ['<circle cx="8" cy="6" r="3"/><path d="M2 14c0-3 2.7-5 6-5s6 2 6 5"/>', 'import.export.tile.users', 'import.export.tile.users_desc'],
    ['<polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>', 'import.export.tile.snippets', 'import.export.tile.snippets_desc'],
    ['<path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/>', 'import.export.tile.alerts', 'import.export.tile.alerts_desc'],
  ];

  // Helper: stat tile
  const kpi = (val, label) =>
    `<div class="sec-tile"><div class="sec-tile-value">${val}</div><div class="sec-tile-label">${label}</div></div>`;

  // Helper: téléchargement authentifié
  function authDownload(url, filename) {
    fetch(url, {headers:{'Authorization':'Bearer '+state.token}})
      .then(r => r.blob())
      .then(blob => {
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = filename;
        a.click();
        URL.revokeObjectURL(a.href);
        toast(t('common.download_started'), 'success');
      }).catch(e => toast(t('common.error_msg', { msg: e.message }), 'error'));
  }

  function conflictSelect(id) {
    return `<div class="field" style="max-width:240px;margin-bottom:20px">
      <label>${t('import.conflict')}</label>
      <select id="${id}" class="input">
        <option value="skip">${t('trafic.skip_keep')}</option>
        <option value="overwrite">${t('trafic.overwrite')}</option>
      </select>
    </div>`;
  }

  function render() {
    main.innerHTML = `
      <div class="imp-nav" role="tablist" aria-label="${t('import.nav_aria')}">
        ${IMP_TABS.map(tab => `
          <button type="button" role="tab" class="imp-nav-item${activeTab===tab.id?' active':''}"
            aria-selected="${activeTab===tab.id}" onclick="impTab('${tab.id}')">
            <span class="imp-nav-icon" aria-hidden="true">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${tab.icon}</svg>
            </span>
            <span>
              <div class="imp-nav-title">${t(tab.titleKey)}</div>
              <div class="imp-nav-desc">${t(tab.descKey)}</div>
            </span>
          </button>`).join('')}
      </div>
      <div id="imp-body">${renderTab()}</div>`;
    bindTabEvents();
  }

  function renderTab() {
    if (activeTab === 'backup') return backupTabHtml();
    if (activeTab === 'migrate') return migrateTabHtml();
    return exportTabHtml();
  }

  // ── Onglet Restaurer ──────────────────────────────────────────────────────
  function backupTabHtml() {
    if (!backupSummary) return `
      <div class="card blueprint" style="max-width:560px">
        <div class="card-kicker">${t('import.restore.kicker')}</div>
        <div class="card-title">${t('import.restore.title')}</div>
        <p style="color:var(--text2);font-size:13px;margin:12px 0 16px">${t('import.restore.hint')}</p>
        <input type="file" id="imp-bk-file" accept=".gpx-admin-backup,.json" style="display:none" onchange="impLoadBackup(this)">
        <div id="imp-drop-zone"
          style="border:2px dashed var(--border);border-radius:var(--radius-lg);padding:36px 20px;text-align:center;cursor:pointer;transition:border-color .2s,background .2s"
          onclick="document.getElementById('imp-bk-file').click()"
          ondragover="event.preventDefault();this.style.borderColor='var(--accent)';this.style.background='var(--bg3)'"
          ondragleave="this.style.borderColor='var(--border)';this.style.background=''"
          ondrop="event.preventDefault();this.style.borderColor='var(--border)';this.style.background='';impDropBackup(event)">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="color:var(--text3);margin-bottom:10px"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
          <div style="font-weight:600;font-size:13px;margin-bottom:4px">${t('import.drop.title')}</div>
          <div style="font-size:12px;color:var(--text2)">${t('import.drop.browse')}</div>
          <div style="font-size:11px;color:var(--text3);margin-top:8px">${t('import.drop.max_size')}</div>
        </div>
        <div id="imp-bk-loading" style="display:none;padding:16px;text-align:center;color:var(--text2);font-size:13px">${t('import.analyzing')}</div>
      </div>`;

    const s = backupSummary;
    const proxies = s.proxies || [];
    const createdAt = s.created_at ? new Date(s.created_at).toLocaleString(typeof gpxBCP47==='function'?gpxBCP47():'en-US') : '—';
    return `
      <div class="card blueprint" style="max-width:720px">
        <div class="card-kicker">${t('import.content.kicker')}</div>
        <div class="card-title">${esc(s.version||'Goproxify')} — ${createdAt}</div>
        <div class="gp-kpi-grid" style="margin:16px 0 20px">
          ${kpi(proxies.length, t('trafic.proxies'))}${kpi(s.user_count||0, t('import.entity.users'))}${kpi(s.token_count||0, t('import.entity.tokens'))}
          ${kpi(s.snippet_count||0, t('import.entity.snippets'))}${kpi(s.channel_count||0, t('import.entity.channels'))}${kpi(s.rule_count||0, t('import.entity.rules'))}
        </div>

        <div style="margin-bottom:16px">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
            <label style="font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--text2)">${t('import.proxies_to_import', { n: proxies.length })}</label>
            <label style="font-size:12px;cursor:pointer;display:flex;align-items:center;gap:5px">
              <input type="checkbox" id="imp-all-px" onchange="impToggleAllPx(this.checked)" checked> ${t('trafic.select_all')}
            </label>
          </div>
          <div style="max-height:200px;overflow-y:auto;border:1px solid var(--border);border-radius:var(--radius-lg);padding:6px 8px">
            ${proxies.length ? proxies.map(p => `
              <label style="display:flex;align-items:center;gap:8px;padding:5px 0;font-size:13px;cursor:pointer;border-bottom:1px solid var(--border);last-child{border:0}">
                <input type="checkbox" class="imp-px-cb" value="${esc(p.id)}" checked>
                <span style="font-weight:600;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(p.name||p.host||p.id)}</span>
                <span style="color:var(--text2);font-size:12px">${esc(p.host||'')}</span>
                <span class="tag ${p.enabled?'tag-accent':'tag-neutral'}">${p.enabled ? t('trafic.active') : t('trafic.inactive')}</span>
              </label>`).join('') : '<p style="color:var(--text2);font-size:13px;padding:8px 0;margin:0">' + t('import.no_proxies_in_backup') + '</p>'}
          </div>
        </div>

        <div style="margin-bottom:20px">
          <label style="font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--text2);display:block;margin-bottom:10px">${t('import.other_entities')}</label>
          <div style="display:flex;flex-wrap:wrap;gap:8px">
            ${IMP_ENTITIES.map(([id, labelKey, path])=>`
              <label style="display:flex;align-items:center;gap:7px;font-size:13px;cursor:pointer;padding:7px 12px;border:1px solid var(--border);border-radius:var(--radius-lg);background:var(--bg3)" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'">
                <input type="checkbox" id="${id}">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;opacity:0.6">${path}</svg>
                ${t(labelKey)}
              </label>`).join('')}
          </div>
        </div>

        ${conflictSelect('imp-conflict')}

        <div style="display:flex;gap:8px">
          <button class="btn btn-ghost" onclick="impResetBackup()">${t('import.choose_other')}</button>
          <button class="btn btn-primary" onclick="impApplyBackup()">${t('import.apply_selection')}</button>
        </div>
      </div>`;
  }

  // ── Onglet Migrer ─────────────────────────────────────────────────────────
  function migrateTabHtml() {
    if (!configProxies) return `
      <div class="card blueprint" style="max-width:700px">
        <div class="card-kicker">${t('import.migrate.kicker')}</div>
        <div class="card-title">${t('import.migrate.title')}</div>
        <p style="color:var(--text2);font-size:13px;margin:8px 0 16px;line-height:1.5">${t('import.migrate.hint')}</p>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(min(120px,100%),1fr));gap:8px;margin-bottom:16px">
          ${configFormatPickerHtml(selectedFmt, id => `impSelFmt('${id}')`)}
        </div>

        <input type="file" id="imp-cfg-file" style="display:none" onchange="impLoadCfgFile(this)" accept=".conf,.nginx,.yaml,.yml,.toml,.json,.txt,Caddyfile">
        <div style="margin-bottom:14px">
          <label style="font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--text2);display:block;margin-bottom:8px">${t('import.file_upload')}</label>
          <div id="imp-cfg-drop-zone"
            style="border:2px dashed var(--border);border-radius:var(--radius-lg);padding:28px 20px;text-align:center;cursor:pointer;transition:border-color .2s,background .2s"
            onclick="document.getElementById('imp-cfg-file').click()"
            ondragover="event.preventDefault();this.style.borderColor='var(--accent)';this.style.background='var(--bg3)'"
            ondragleave="this.style.borderColor='var(--border)';this.style.background=''"
            ondrop="event.preventDefault();this.style.borderColor='var(--border)';this.style.background='';impDropCfgFile(event)">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="color:var(--text3);margin-bottom:8px"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
            <div style="font-weight:600;font-size:13px;margin-bottom:4px">${t('import.drop.title')}</div>
            <div style="font-size:12px;color:var(--text2)">${t('import.drop.browse')}</div>
            <div style="font-size:11px;color:var(--text3);margin-top:8px">${t('import.drop.extensions')}</div>
          </div>
        </div>
        <div class="field" style="margin-bottom:14px">
          <label>${t('import.paste_label')}</label>
          <textarea id="imp-cfg-text" class="input" rows="9" placeholder="${t('import.paste_ph')}" style="font-family:monospace;font-size:12px;resize:vertical"></textarea>
        </div>
        <div style="display:flex;align-items:center;gap:12px">
          <button class="btn btn-primary" onclick="impParseConfig()">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-1px;margin-right:5px"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            ${t('trafic.analyze')}
          </button>
          <span id="imp-fmt-hint" style="font-size:12px;color:var(--accent);font-style:italic"></span>
        </div>
      </div>`;

    return `
      <div class="card blueprint" style="max-width:640px">
        <div class="card-kicker">${t('import.detected.kicker')}</div>
        <div class="card-title">${t('import.detected.title', { n: configProxies.length })}</div>
        <div style="display:flex;align-items:center;justify-content:space-between;margin:14px 0 8px">
          <span style="font-size:12px;color:var(--text2)">${t('import.entries', { n: configProxies.length })}</span>
          <label style="font-size:12px;cursor:pointer;display:flex;align-items:center;gap:5px">
            <input type="checkbox" id="imp-all-cfg" onchange="impToggleAllCfg(this.checked)" checked> ${t('trafic.select_all')}
          </label>
        </div>
        <div style="max-height:260px;overflow-y:auto;border:1px solid var(--border);border-radius:var(--radius-lg);padding:6px 8px;margin-bottom:16px">
          ${configProxies.map((p,i)=>`
            <label style="display:flex;align-items:flex-start;gap:8px;padding:7px 0;font-size:13px;cursor:pointer;border-bottom:1px solid var(--border)">
              <input type="checkbox" class="imp-cfg-cb" value="${i}" checked style="margin-top:2px;flex-shrink:0">
              <div style="min-width:0;flex:1">
                <div style="font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(p.host||p.name||'—')}</div>
                <div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:4px">
                  <span class="tag tag-outline">${esc(p.source||'?')}</span>
                  ${p.tls?'<span class="tag tag-accent">TLS</span>':''}
                  ${(p.backends||[]).slice(0,2).map(b=>`<span class="tag tag-neutral" style="font-family:monospace;font-size:10px">${esc(b)}</span>`).join('')}
                  ${(p.backends||[]).length>2?`<span style="color:var(--text3);font-size:11px">+${p.backends.length-2}</span>`:''}
                </div>
              </div>
            </label>`).join('')}
        </div>
        ${conflictSelect('imp-cfg-conflict')}
        <div style="display:flex;gap:8px">
          <button class="btn btn-ghost" onclick="impResetConfig()">${t('import.edit_config')}</button>
          <button class="btn btn-primary" onclick="impApplyConfig()">${t('trafic.import_go')}</button>
        </div>
      </div>`;
  }

  // ── Onglet Exporter ───────────────────────────────────────────────────────
  function exportTabHtml() {
    return `
      <div class="card blueprint" style="max-width:520px">
        <div class="card-kicker">${t('import.export.kicker')}</div>
        <div class="card-title">${t('import.export.title')}</div>
        <p style="color:var(--text2);font-size:13px;margin:10px 0 16px;line-height:1.6">
          ${t('import.export.desc')}
        </p>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(min(180px,100%),1fr));gap:8px;margin-bottom:20px">
          ${IMP_EXPORT_TILES.map(([icon, titleKey, descKey]) => `
            <div style="padding:12px 14px;background:var(--bg3);border:1px solid var(--border);border-radius:8px">
              <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2">${icon}</svg>
                <span style="font-size:12px;font-weight:600">${t(titleKey)}</span>
              </div>
              <div style="font-size:11px;color:var(--text2)">${t(descKey)}</div>
            </div>`).join('')}
        </div>
        <button class="btn btn-primary" onclick="impDoExport()">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-2px;margin-right:5px"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          ${t('import.export.download')}
        </button>
      </div>`;
  }

  // ── Résultat import sauvegarde ────────────────────────────────────────────
  function backupResultHtml(result) {
    return `
      <div class="card blueprint" style="max-width:560px">
        <div class="card-kicker">${t('import.result.kicker')}</div>
        <div class="card-title" style="color:var(--green)">${t('import.result.restore_ok')}</div>
        <div class="gp-kpi-grid" style="margin:16px 0">
          ${kpi(result.proxies||0, t('trafic.proxies'))}${kpi(result.users||0, t('import.entity.users'))}${kpi(result.tokens||0, t('import.entity.tokens'))}
          ${kpi(result.snippets||0, t('import.entity.snippets'))}${kpi(result.channels||0, t('import.result.channels'))}${kpi(result.rules||0, t('import.result.rules'))}
        </div>
        ${result.skipped>0?`<p style="color:var(--text2);font-size:13px;margin-bottom:16px">${t('import.result.skipped', { n: result.skipped })}</p>`:''}
        <div style="display:flex;gap:8px">
          <button class="btn btn-primary" onclick="navigate('admin-trafic')">${t('trafic.see_proxies')}</button>
          <button class="btn btn-ghost" onclick="pages.import()">${t('import.result.other_import')}</button>
        </div>
      </div>`;
  }

  function migrateResultHtml(res) {
    return `
      <div class="card blueprint" style="max-width:480px">
        <div class="card-kicker">${t('import.migrate.kicker_done')}</div>
        <div class="card-title" style="color:var(--green)">${t('import.migrate.ok')}</div>
        <div class="gp-kpi-grid" style="margin:16px 0">
          ${kpi(res.imported||0, t('import.migrate.imported'))}${kpi(res.skipped||0, t('import.migrate.skipped'))}${kpi(res.errors||0, t('trafic.errors'))}
        </div>
        <div style="display:flex;gap:8px">
          <button class="btn btn-primary" onclick="navigate('admin-trafic')">${t('trafic.see_proxies')}</button>
          <button class="btn btn-ghost" onclick="pages.import()">${t('import.migrate.other')}</button>
        </div>
      </div>`;
  }

  // ── Événements ────────────────────────────────────────────────────────────
  function bindTabEvents() {
    window.impTab = function(tabId) { activeTab = tabId; backupData = null; backupSummary = null; configProxies = null; selectedFmt = null; render(); };
    window.impResetBackup = function() { backupData = null; backupSummary = null; document.getElementById('imp-body').innerHTML = backupTabHtml(); bindTabEvents(); };
    window.impResetConfig = function() { configProxies = null; selectedFmt = null; document.getElementById('imp-body').innerHTML = migrateTabHtml(); bindTabEvents(); };

    async function doLoadBackup(text, fileName) {
      backupData = text;
      const loading = document.getElementById('imp-bk-loading');
      const dropZone = document.getElementById('imp-drop-zone');
      if (loading) loading.style.display = 'block';
      if (dropZone) dropZone.style.display = 'none';
      try {
        const r = await fetch('/api/v1/import/backup/preview', {
          method: 'POST', headers: {'Content-Type':'application/json','Authorization':'Bearer '+state.token}, body: text
        });
        const res = await r.json();
        if (!r.ok) throw new Error(res.error || 'Error');
        backupSummary = res;
        document.getElementById('imp-body').innerHTML = backupTabHtml();
        bindTabEvents();
      } catch(e) { toast(t('import.error_backup', { msg: e.message }), 'error'); backupData = null; if (loading) loading.style.display='none'; if (dropZone) dropZone.style.display=''; }
    }

    window.impLoadBackup = async function(input) {
      const file = input.files[0]; if (!file) return;
      doLoadBackup(await file.text(), file.name);
    };

    window.impDropBackup = async function(event) {
      const file = event.dataTransfer.files[0]; if (!file) return;
      doLoadBackup(await file.text(), file.name);
    };

    window.impToggleAllPx = function(checked) {
      document.querySelectorAll('.imp-px-cb').forEach(cb => cb.checked = checked);
    };

    window.impApplyBackup = async function() {
      const ids = [...document.querySelectorAll('.imp-px-cb:checked')].map(cb => cb.value);
      const sel = {
        proxy_ids: ids,
        import_users:          document.getElementById('imp-users')?.checked    || false,
        import_tokens:         document.getElementById('imp-tokens')?.checked   || false,
        import_snippets:       document.getElementById('imp-snippets')?.checked || false,
        import_alert_channels: document.getElementById('imp-channels')?.checked || false,
        import_alert_rules:    document.getElementById('imp-rules')?.checked    || false,
        on_conflict:           document.getElementById('imp-conflict')?.value   || 'skip',
      };
      try {
        const r = await fetch('/api/v1/import/backup/apply', {
          method: 'POST', headers: {'Content-Type':'application/json','Authorization':'Bearer '+state.token},
          body: JSON.stringify({data: JSON.parse(backupData), selection: sel})
        });
        const result = await r.json();
        if (!r.ok) throw new Error(result.error || 'Error');
        toast(t('import.toast_backup', { proxies: result.proxies, users: result.users }), 'success');
        backupData = null; backupSummary = null;
        document.getElementById('imp-body').innerHTML = backupResultHtml(result);
      } catch(e) { toast(t('import.error_import', { msg: e.message }), 'error'); }
    };

    window.impSelFmt = function(id) {
      selectedFmt = id;
      document.querySelectorAll('#imp-body .infra-card[data-format]').forEach(el => {
        el.classList.toggle('selected', el.getAttribute('data-format') === id);
      });
      const fmt = CONFIG_FORMATS.find(f => f.id === id);
      const hint = document.getElementById('imp-fmt-hint');
      if (hint && fmt) hint.textContent = fmt.hint || '';
    };

    async function doLoadCfgFile(file) {
      if (!file) return;
      const text = await file.text();
      const ta = document.getElementById('imp-cfg-text');
      if (ta) ta.value = text;
      const base = file.name.split('/').pop().toLowerCase();
      const ext = base === 'caddyfile' ? 'caddyfile' : base.split('.').pop();
      const extMap = {conf:'nginx',nginx:'nginx',yaml:'traefik-yaml',yml:'traefik-yaml',toml:'traefik-toml',caddyfile:'caddy',cfg:'haproxy',json:'goproxify'};
      if (extMap[ext]) window.impSelFmt(extMap[ext]);
    }

    window.impLoadCfgFile = async function(input) {
      await doLoadCfgFile(input.files[0]);
    };

    window.impDropCfgFile = async function(event) {
      await doLoadCfgFile(event.dataTransfer.files[0]);
    };

    window.impParseConfig = async function() {
      const content = document.getElementById('imp-cfg-text')?.value || '';
      if (!content.trim()) { toast(t('import.paste_first'), 'error'); return; }
      try {
        const res = await api('POST', '/import/config/parse', {format: selectedFmt || '', content});
        configProxies = res.proxies || [];
        if (configProxies.length === 0) { toast(t('trafic.no_proxy_detected'), 'error'); return; }
        document.getElementById('imp-body').innerHTML = migrateTabHtml();
        bindTabEvents();
      } catch(e) { toast(t('import.error_parse', { msg: e.message }), 'error'); }
    };

    window.impToggleAllCfg = function(checked) {
      document.querySelectorAll('.imp-cfg-cb').forEach(cb => cb.checked = checked);
    };

    window.impApplyConfig = async function() {
      const selected = [...document.querySelectorAll('.imp-cfg-cb:checked')].map(cb => parseInt(cb.value));
      const proxies = selected.map(i => configProxies[i]);
      const onConflict = document.getElementById('imp-cfg-conflict')?.value || 'skip';
      try {
        const res = await api('POST', '/import/config/apply', {proxies, on_conflict: onConflict});
        toast(t('import.toast_migrate', { imported: res.imported, skipped: res.skipped }), 'success');
        configProxies = null;
        document.getElementById('imp-body').innerHTML = migrateResultHtml(res);
      } catch(e) { toast(t('import.error_import', { msg: e.message }), 'error'); }
    };

    window.impDoExport = function() {
      const ts = new Date().toISOString().slice(0,10);
      authDownload('/api/v1/import/export', `goproxify-backup-${ts}.gpx-admin-backup`);
    };
  }

  render();
};
