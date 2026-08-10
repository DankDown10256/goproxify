// ── PAGE: Options portail Access (scopé au Core sélectionné)
pages.portal = async function() {
  const core = state.selectedCore;
  const coreName = core?.node_name || '';
  const coreLabel = core?.display_name || coreName || '—';
  if (!coreName) {
    document.getElementById('topbar-actions').innerHTML = '';
    document.getElementById('content').innerHTML = `
      <div class="empty">
        <p style="font-size:15px;font-weight:600">${esc(t('portal.need_core') || 'Sélectionnez un Core')}</p>
        <p style="font-size:13px;margin-top:4px;color:var(--text2)">${esc(t('portal.need_core_hint') || 'Le portail se configure par Core.')}</p>
      </div>`;
    return;
  }

  document.getElementById('topbar-actions').innerHTML = `
    <button class="btn btn-secondary" id="portal-top-push">${esc(t('portal.push') || 'Pousser au Core')}</button>
    <button class="btn btn-primary" id="portal-top-save">${esc(t('common.save') || 'Enregistrer')}</button>`;
  const content = document.getElementById('content');
  content.innerHTML = `<div class="muted">${esc(t('common.loading') || '…')}</div>`;
  try {
    const cfg = await api('GET', '/portal?core=' + encodeURIComponent(coreName)) || {};
    renderPortalPage(cfg, coreName, coreLabel);
  } catch (e) {
    content.innerHTML = `<div class="err">${esc(e.message || e)}</div>`;
  }
};

function renderPortalPage(cfg, coreName, coreLabel) {
  const content = document.getElementById('content');
  const enabled = !!cfg.enabled;
  const host = cfg.public_host || '';
  const q = '?core=' + encodeURIComponent(coreName);

  content.innerHTML = `
    <div class="card blueprint" style="margin-bottom:16px;padding:16px 18px">
      <div style="display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;align-items:flex-start">
        <div style="min-width:220px;flex:1">
          <div style="font-family:var(--font-heading);font-size:18px;font-weight:700;letter-spacing:.01em;margin-bottom:4px">
            ${esc(t('portal.title') || 'Portail d\'accès')}
          </div>
          <div style="font-size:13px;color:var(--text2);line-height:1.45;max-width:52ch">
            ${esc(t('portal.desc') || 'Active le portail public sur ce Core (UI HTTPS + SSH UUID).')}
            <span style="display:block;margin-top:6px;color:var(--text);font-weight:500">${esc(coreLabel)}</span>
          </div>
        </div>
        <div style="display:flex;flex-direction:column;gap:8px;align-items:flex-end">
          <span class="badge" style="
            background:${enabled ? 'color-mix(in srgb,var(--accent) 16%,transparent)' : 'var(--bg3)'};
            border:1px solid ${enabled ? 'color-mix(in srgb,var(--accent) 40%,var(--border))' : 'var(--border)'};
            color:${enabled ? 'var(--accent)' : 'var(--text2)'};
            font-size:11px;font-weight:600;padding:4px 10px;border-radius:999px">
            ${enabled ? 'Actif' : 'Inactif'}
          </span>
          ${host ? `<code style="font-size:11px;color:var(--text2)">https://${esc(host)}</code>` : ''}
        </div>
      </div>
    </div>

    <div class="card blueprint" style="padding:16px 18px;max-width:640px;margin-bottom:14px">
      <div style="font-size:13px;font-weight:600;margin-bottom:12px">Activation</div>
      <label style="display:flex;align-items:center;gap:10px;margin-bottom:14px;cursor:pointer">
        <input type="checkbox" id="portal-enabled" ${enabled ? 'checked' : ''}/>
        <span style="font-size:13px">${esc(t('portal.enabled') || 'Activer le portail')}</span>
      </label>
      <label style="display:flex;align-items:center;gap:10px;margin-bottom:14px;cursor:pointer">
        <input type="checkbox" id="portal-personal" ${cfg.allow_personal_targets ? 'checked' : ''}/>
        <span style="font-size:13px">${esc(t('portal.allow_personal') || 'Autoriser les cibles personnelles')}</span>
      </label>
      <label style="display:flex;align-items:center;gap:10px;margin-bottom:14px;cursor:pointer">
        <input type="checkbox" id="portal-require-2fa" ${cfg.require_2fa ? 'checked' : ''}/>
        <span style="font-size:13px">${esc(t('portal.require_2fa') || 'Exiger la 2FA')}</span>
      </label>
      <div class="gp-cols-2">
        <div class="field">
          <label class="field-label">${esc(t('portal.public_host') || 'Hôte public')}</label>
          <input class="input" id="portal-host" value="${esc(host)}" placeholder="sshportal.example.fr"/>
        </div>
        <div class="field">
          <label class="field-label">${esc(t('portal.auth_provider') || 'Auth provider ID')}</label>
          <input class="input" id="portal-auth" value="${esc(cfg.auth_provider_id || '')}" placeholder="(optionnel)"/>
        </div>
        <div class="field">
          <label class="field-label">SSH port</label>
          <input class="input" id="portal-ssh" type="number" value="${cfg.ssh_port || 2222}"/>
        </div>
        <div class="field">
          <label class="field-label">HTTP port (interne)</label>
          <input class="input" id="portal-http" type="number" value="${cfg.http_port || 8444}"/>
        </div>
        <div class="field">
          <label class="field-label">${esc(t('portal.session_ttl') || 'TTL session UUID (s)')}</label>
          <input class="input" id="portal-ttl" type="number" min="5" max="3600" value="${cfg.session_ttl_sec || 60}"/>
        </div>
        <div class="field">
          <label class="field-label">${esc(t('portal.session_mode') || 'Mode UUID')}</label>
          <select class="input" id="portal-mode">
            <option value="one_shot" ${(cfg.session_mode || 'one_shot') === 'one_shot' ? 'selected' : ''}>${esc(t('portal.mode_one_shot') || 'One-shot (défaut)')}</option>
            <option value="multi" ${cfg.session_mode === 'multi' ? 'selected' : ''}>${esc(t('portal.mode_multi') || 'Multi-essai')}</option>
          </select>
        </div>
      </div>
      <div id="portal-msg" style="margin-top:12px;font-size:13px;min-height:1.2em"></div>
    </div>`;

  const save = async () => {
    const msg = document.getElementById('portal-msg');
    try {
      const body = {
        enabled: document.getElementById('portal-enabled').checked,
        allow_personal_targets: document.getElementById('portal-personal').checked,
        require_2fa: document.getElementById('portal-require-2fa').checked,
        public_host: document.getElementById('portal-host').value.trim(),
        auth_provider_id: document.getElementById('portal-auth').value.trim(),
        ssh_port: +document.getElementById('portal-ssh').value || 2222,
        http_port: +document.getElementById('portal-http').value || 8444,
        session_ttl_sec: +document.getElementById('portal-ttl').value || 60,
        session_mode: document.getElementById('portal-mode').value || 'one_shot',
        core_name: coreName,
      };
      const saved = await api('PUT', '/portal' + q, body);
      msg.textContent = t('portal.saved') || 'Enregistré et poussé.';
      msg.style.color = 'var(--accent)';
      renderPortalPage(saved || body, coreName, coreLabel);
      bindPortalTopActions();
    } catch (e) {
      msg.textContent = e.message || String(e);
      msg.style.color = 'var(--danger, #c45c5c)';
    }
  };

  const push = async () => {
    const msg = document.getElementById('portal-msg');
    try {
      await api('POST', '/portal/push' + q);
      msg.textContent = t('portal.pushed') || 'Config poussée.';
      msg.style.color = 'var(--accent)';
    } catch (e) {
      msg.textContent = e.message || String(e);
      msg.style.color = 'var(--danger, #c45c5c)';
    }
  };

  function bindPortalTopActions() {
    const topSave = document.getElementById('portal-top-save');
    const topPush = document.getElementById('portal-top-push');
    if (topSave) topSave.onclick = save;
    if (topPush) topPush.onclick = push;
  }
  bindPortalTopActions();
}

// ── PAGE: Audit Access (scopé au Core sélectionné)
pages['portal-audit'] = async function() {
  const core = state.selectedCore;
  const coreName = core?.node_name || '';
  const coreLabel = core?.display_name || coreName || '—';
  const content = document.getElementById('content');
  if (!coreName) {
    document.getElementById('topbar-actions').innerHTML = '';
    content.innerHTML = `
      <div class="empty">
        <p style="font-size:15px;font-weight:600">${esc(t('portal.need_core') || 'Sélectionnez un Core')}</p>
        <p style="font-size:13px;margin-top:4px;color:var(--text2)">${esc(t('portal.need_core_hint') || 'Le portail se configure par Core.')}</p>
      </div>`;
    return;
  }

  document.getElementById('topbar-actions').innerHTML = `
    <button class="btn btn-secondary" id="portal-audit-refresh">${esc(t('common.refresh') || 'Actualiser')}</button>`;

  content.innerHTML = `
    <div class="card blueprint" style="padding:16px 18px;max-width:720px">
      <div style="margin-bottom:10px">
        <div style="font-family:var(--font-heading);font-size:18px;font-weight:700;letter-spacing:.01em;margin-bottom:4px">
          ${esc(t('portal.audit_title') || 'Audit Access')}
        </div>
        <p class="muted" style="font-size:12px;margin:0;line-height:1.45">
          ${esc(t('portal.audit_hint') || 'Métadonnées de session uniquement (pas de terminal ni secrets).')}
          <span style="display:block;margin-top:6px;color:var(--text);font-weight:500">${esc(coreLabel)}</span>
        </p>
      </div>
      <div id="portal-audit-list" class="muted" style="font-size:12px">…</div>
    </div>`;

  const loadAudit = async () => {
    const box = document.getElementById('portal-audit-list');
    if (!box) return;
    box.textContent = '…';
    try {
      const d = await api('GET', '/portal/audit?core=' + encodeURIComponent(coreName) + '&limit=50') || {};
      const events = d.events || [];
      if (!events.length) {
        box.textContent = t('portal.audit_empty') || 'Aucun événement.';
        return;
      }
      box.innerHTML = '<table class="table" style="width:100%;font-size:12px"><thead><tr>' +
        '<th>ts</th><th>acteur</th><th>cible</th><th>façade</th><th>ok</th><th>détail</th></tr></thead><tbody>' +
        events.map(e => '<tr>' +
          '<td>' + esc(e.ts || '') + '</td>' +
          '<td>' + esc(e.actor || '') + '</td>' +
          '<td><code>' + esc(e.target_id || '') + '</code></td>' +
          '<td>' + esc(e.facade || '') + '</td>' +
          '<td>' + (e.success ? '✓' : '✗') + '</td>' +
          '<td>' + esc(e.detail || '') + '</td></tr>').join('') +
        '</tbody></table>';
    } catch (e) {
      box.textContent = e.message || String(e);
    }
  };
  document.getElementById('portal-audit-refresh').onclick = loadAudit;
  loadAudit();
};
