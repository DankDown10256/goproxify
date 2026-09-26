// ── PAGE: Synthèse portail Access (scopé à la passerelle sélectionnée)
pages.portal = async function() {
  const edgeName = state.selectedEdge?.node_name || '';
  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML = '';
  if (!edgeName) {
    content.innerHTML = `
      <div class="empty">
        <p style="font-size:15px;font-weight:600">${esc(t('portal.need_edge') || 'Sélectionnez une passerelle')}</p>
        <p style="font-size:13px;margin-top:4px;color:var(--text2)">${esc(t('portal.need_edge_hint') || 'Le portail se configure par passerelle.')}</p>
      </div>`;
    return;
  }
  const q = '?edge=' + encodeURIComponent(edgeName);
  content.innerHTML = `<div class="muted">${esc(t('common.loading') || '…')}</div>`;
  const [cfg, dest, usr, aud, live, apr] = await Promise.all([
    api('GET', '/portal' + q).catch(() => ({})),
    api('GET', '/portal/destinations' + q).catch(() => ({})),
    api('GET', '/portal/users' + q).catch(() => ({})),
    api('GET', '/portal/audit' + q + '&limit=50').catch(() => ({})),
    api('GET', '/portal/sessions' + q).catch(() => ({})),
    api('GET', '/portal/access-requests' + q + '&status=pending').catch(() => ({})),
  ]);
  const dests = Array.isArray(dest) ? dest : (dest.destinations || []);
  const users = usr.users || [];
  const events = aud.events || [];
  const liveList = live.sessions || [];
  const sessActive = liveList.length;
  const pendingCount = (apr.requests || []).length;
  const failures = events.filter(e => !e.success).length;
  const enabled = !!cfg.enabled;
  const tile = (v, label, color) => `
    <div class="card blueprint" style="padding:14px 16px">
      <div style="font-size:26px;font-weight:700;font-variant-numeric:tabular-nums;${color ? 'color:' + color : ''}">${v}</div>
      <div style="font-size:12px;color:var(--text2)">${esc(label)}</div>
    </div>`;
  const recent = events.slice(0, 6).map(e => `
    <div style="display:grid;grid-template-columns:150px 1fr auto;gap:10px;padding:7px 0;border-bottom:1px solid var(--border);font-size:12px;align-items:center">
      <span class="muted">${esc(e.ts || '')}</span>
      <span><b>${esc(e.actor || '—')}</b> → <code>${esc(e.target_id || '')}</code> ${esc(e.detail || '')}</span>
      <span style="color:${e.success ? 'var(--accent)' : 'var(--danger, #c45c5c)'}">${e.success ? '✓' : '✗'}</span>
    </div>`).join('') || `<div class="muted" style="font-size:12px">${esc(t('portal.audit_empty') || 'Aucun événement.')}</div>`;

  content.innerHTML = `
    <div class="card blueprint" style="padding:16px 18px;margin-bottom:14px;display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;align-items:center">
      <div>
        <div style="font-family:var(--font-heading);font-size:18px;font-weight:700;margin-bottom:4px">${esc(t('portal.title') || 'Portail d\'accès')}</div>
        <div style="font-size:12px;color:var(--text2)">${cfg.public_host ? `<code>https://${esc(cfg.public_host)}</code> · ` : ''}SSH :${cfg.ssh_port || 2222} · ${cfg.session_mode === 'multi' ? 'multi-essai' : 'usage unique'} · 2FA ${cfg.require_2fa ? 'exigée' : 'facultative'}</div>
      </div>
      <div style="display:flex;gap:8px;align-items:center">
        <span class="badge" style="font-size:11px;font-weight:600;padding:4px 10px;border-radius:999px;border:1px solid var(--border);color:${enabled ? 'var(--accent)' : 'var(--text2)'}">${enabled ? 'Actif' : 'Inactif'}</span>
        <button class="btn btn-secondary" onclick="navigate('portal-settings')">Réglages</button>
      </div>
    </div>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-bottom:14px">
      ${tile(sessActive, 'sessions en direct')}
      ${tile(dests.length, 'destinations')}
      ${tile(users.length, 'utilisateurs')}
      ${tile(pendingCount, "demandes d'accès en attente", pendingCount ? 'var(--accent)' : '')}
      ${tile(failures, 'échecs récents', failures ? 'var(--danger, #c45c5c)' : '')}
    </div>
    <div class="card blueprint" style="padding:14px 16px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
        <div style="font-size:13px;font-weight:600">Derniers événements</div>
        <button class="btn btn-secondary btn-sm" onclick="navigate('portal-audit')">Tout l'audit</button>
      </div>
      ${recent}
    </div>`;
};

// ── PAGE: Réglages portail Access (scopé à la passerelle sélectionnée)
pages['portal-settings'] = async function() {
  const edge = state.selectedEdge;
  const edgeName = edge?.node_name || '';
  const edgeLabel = edge?.display_name || edgeName || '—';
  if (!edgeName) {
    document.getElementById('topbar-actions').innerHTML = '';
    document.getElementById('content').innerHTML = `
      <div class="empty">
        <p style="font-size:15px;font-weight:600">${esc(t('portal.need_edge') || 'Sélectionnez une passerelle')}</p>
        <p style="font-size:13px;margin-top:4px;color:var(--text2)">${esc(t('portal.need_edge_hint') || 'Le portail se configure par passerelle.')}</p>
      </div>`;
    return;
  }

  document.getElementById('topbar-actions').innerHTML = `
    <button class="btn btn-secondary" id="portal-top-push">${esc(t('portal.push') || 'Pousser à la passerelle')}</button>
    <button class="btn btn-primary" id="portal-top-save">${esc(t('common.save') || 'Enregistrer')}</button>`;
  const content = document.getElementById('content');
  content.innerHTML = `<div class="muted">${esc(t('common.loading') || '…')}</div>`;
  try {
    const [cfg, metricsPt] = await Promise.all([
      api('GET', '/portal?edge=' + encodeURIComponent(edgeName)).catch(() => ({})),
      api('GET', '/metrics/summary').catch(() => null),
    ]);
    renderPortalPage(cfg || {}, edgeName, edgeLabel, metricsPt);
  } catch (e) {
    content.innerHTML = `<div class="err">${esc(e.message || e)}</div>`;
  }
};

function renderPortalPage(cfg, edgeName, edgeLabel, metricsData) {
  const content = document.getElementById('content');
  const enabled = !!cfg.enabled;
  const host = cfg.public_host || '';
  const q = '?edge=' + encodeURIComponent(edgeName);
  const pSessions = metricsData?.portal?.sessions || {};
  const sessOneShot = pSessions.one_shot ?? null;
  const sessMulti = pSessions.multi ?? null;
  const sessKPI = (sessOneShot != null || sessMulti != null) ? `
    <div style="display:flex;gap:16px;padding:8px 0 0;font-size:11px;color:var(--text2)">
      ${sessOneShot!=null?`<span>One-shot : <b style="color:var(--text1)">${sessOneShot}</b></span>`:''}
      ${sessMulti!=null?`<span>Multi : <b style="color:var(--text1)">${sessMulti}</b></span>`:''}
    </div>` : '';

  content.innerHTML = `
    <div class="card blueprint" style="margin-bottom:16px;padding:16px 18px">
      <div style="display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;align-items:flex-start">
        <div style="min-width:220px;flex:1">
          <div style="font-family:var(--font-heading);font-size:18px;font-weight:700;letter-spacing:.01em;margin-bottom:4px">
            ${esc(t('portal.title') || 'Portail d\'accès')}
          </div>
          <div style="font-size:13px;color:var(--text2);line-height:1.45;max-width:52ch">
            ${esc(t('portal.desc') || 'Active le portail public sur cette passerelle (UI HTTPS + SSH UUID).')}
            <span style="display:block;margin-top:6px;color:var(--text);font-weight:500">${esc(edgeLabel)}</span>
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
          ${sessKPI}
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
        ${haSessionField(cfg)}
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
        ha_session_mode: document.getElementById('portal-ha-sessions')?.value || undefined,
        edge_name: edgeName,
      };
      const saved = await api('PUT', '/portal' + q, body);
      msg.textContent = t('portal.saved') || 'Enregistré et poussé.';
      msg.style.color = 'var(--accent)';
      renderPortalPage(saved || body, edgeName, edgeLabel);
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

// ── PAGE: Audit Access (scopé à la passerelle sélectionnée)
pages['portal-audit'] = async function() {
  const edge = state.selectedEdge;
  const edgeName = edge?.node_name || '';
  const edgeLabel = edge?.display_name || edgeName || '—';
  const content = document.getElementById('content');
  if (!edgeName) {
    document.getElementById('topbar-actions').innerHTML = '';
    content.innerHTML = `
      <div class="empty">
        <p style="font-size:15px;font-weight:600">${esc(t('portal.need_edge') || 'Sélectionnez une passerelle')}</p>
        <p style="font-size:13px;margin-top:4px;color:var(--text2)">${esc(t('portal.need_edge_hint') || 'Le portail se configure par passerelle.')}</p>
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
          <span style="display:block;margin-top:6px;color:var(--text);font-weight:500">${esc(edgeLabel)}</span>
        </p>
      </div>
      <div id="portal-audit-list" class="muted" style="font-size:12px">…</div>
    </div>`;

  const loadAudit = async () => {
    const box = document.getElementById('portal-audit-list');
    if (!box) return;
    box.textContent = '…';
    try {
      const d = await api('GET', '/portal/audit?edge=' + encodeURIComponent(edgeName) + '&limit=50') || {};
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

// haSessionField : dans un groupe HA, la config du portail est celle du groupe ; les sessions web peuvent
// rester sur la passerelle qui les a émises (sticky, défaut) ou être répliquées entre les membres (shared).
function haSessionField(cfg) {
  if (!cfg || !cfg.ha_group) return '';
  const members = (cfg.ha_members || []).map(esc).join(', ');
  const mode = cfg.ha_session_mode === 'shared' ? 'shared' : 'sticky';
  return `
        <div class="field" style="grid-column:1/-1">
          <div style="margin-bottom:8px;padding:10px 12px;background:color-mix(in srgb,var(--accent) 7%,transparent);border:1px solid color-mix(in srgb,var(--accent) 22%,transparent);border-radius:6px;font-size:12px;color:var(--text2);">
            ${t('portal.ha_banner', { group: esc(cfg.ha_group), members })}
          </div>
          <label class="field-label">${esc(t('portal.ha_session_mode'))}</label>
          <select class="input" id="portal-ha-sessions">
            <option value="sticky" ${mode === 'sticky' ? 'selected' : ''}>${esc(t('portal.ha_session_sticky'))}</option>
            <option value="shared" ${mode === 'shared' ? 'selected' : ''}>${esc(t('portal.ha_session_shared'))}</option>
          </select>
          <div style="margin-top:6px;font-size:12px;color:var(--text3)">${esc(t('portal.ha_session_hint'))}</div>
        </div>`;
}

// ── PAGE: Sessions Access en direct (scopé à la passerelle sélectionnée)
pages['portal-sessions'] = async function() {
  const edgeName = state.selectedEdge?.node_name || '';
  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML = `<button class="btn btn-secondary" id="psess-refresh">${esc(t('common.refresh') || 'Actualiser')}</button>`;
  if (!edgeName) {
    content.innerHTML = `<div class="empty"><p style="font-size:15px;font-weight:600">${esc(t('portal.need_edge') || 'Sélectionnez une passerelle')}</p></div>`;
    return;
  }
  content.innerHTML = `
    <div class="card blueprint" style="padding:16px 18px">
      <div style="font-family:var(--font-heading);font-size:18px;font-weight:700;margin-bottom:4px">Sessions en direct</div>
      <p class="muted" style="font-size:12px;margin:0 0 12px">Connexions SSH et web en cours sur cette passerelle. La liste se met à jour toute seule.</p>
      <div id="psess-list" class="muted" style="font-size:12px">…</div>
    </div>`;

  const since = (iso) => {
    const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
    return s < 60 ? s + ' s' : s < 3600 ? Math.floor(s / 60) + ' min' : Math.floor(s / 3600) + ' h ' + Math.floor((s % 3600) / 60) + ' min';
  };
  const load = async () => {
    const box = document.getElementById('psess-list');
    if (!box) return;
    try {
      const d = await api('GET', '/portal/sessions?edge=' + encodeURIComponent(edgeName)) || {};
      const list = d.sessions || [];
      if (!list.length) { box.textContent = 'Aucune session en cours.'; return; }
      box.innerHTML = '<table class="table" style="width:100%;font-size:12px"><thead><tr>' +
        '<th>Utilisateur</th><th>Destination</th><th>Façade</th><th>Source</th><th>Durée</th><th></th></tr></thead><tbody>' +
        list.map(s => '<tr>' +
          '<td><b>' + esc(s.actor || '') + '</b></td>' +
          '<td><code>' + esc(s.target_id || '') + '</code></td>' +
          '<td>' + esc(s.facade || '') + '</td>' +
          '<td><code>' + esc(s.remote || '') + '</code></td>' +
          '<td>' + esc(since(s.since)) + '</td>' +
          '<td style="white-space:nowrap"><button class="btn btn-secondary btn-sm" data-watch="' + esc(s.id) + '">Observer</button> <button class="btn btn-secondary btn-sm" data-kill="' + esc(s.id) + '">Terminer</button></td></tr>').join('') +
        '</tbody></table>';
      box.querySelectorAll('[data-watch]').forEach(b => {
        b.onclick = () => gpxWatchSession(edgeName, list.find(x => x.id === b.dataset.watch));
      });
      box.querySelectorAll('[data-kill]').forEach(b => {
        b.onclick = async () => {
          if (!confirm('Terminer cette session ?')) return;
          try {
            await api('DELETE', '/portal/sessions/' + encodeURIComponent(b.dataset.kill) + '?edge=' + encodeURIComponent(edgeName));
            toast('Session terminée.', 'success');
            setTimeout(load, 500);
          } catch (e) { toast(e.message || e, 'error'); }
        };
      });
    } catch (e) {
      box.textContent = e.message || String(e);
    }
  };
  document.getElementById('psess-refresh').onclick = load;
  await load();
  const timer = setInterval(() => {
    if (state.page !== 'portal-sessions') { clearInterval(timer); return; }
    load();
  }, 5000);
};

// ── PAGE: Approbations Access (demandes d'accès temporaire)
pages['portal-approvals'] = async function() {
  const edgeName = state.selectedEdge?.node_name || '';
  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML = `<button class="btn btn-secondary" id="papp-refresh">${esc(t('common.refresh') || 'Actualiser')}</button>`;
  if (!edgeName) {
    content.innerHTML = `<div class="empty"><p style="font-size:15px;font-weight:600">${esc(t('portal.need_edge') || 'Sélectionnez une passerelle')}</p></div>`;
    return;
  }
  const q = '?edge=' + encodeURIComponent(edgeName);
  content.innerHTML = `
    <div class="card blueprint" style="padding:16px 18px;margin-bottom:14px">
      <div style="font-family:var(--font-heading);font-size:18px;font-weight:700;margin-bottom:4px">Demandes en attente</div>
      <p class="muted" style="font-size:12px;margin:0 0 12px">Les utilisateurs demandent l'accès à une destination qu'ils ne voient pas. L'accès accordé expire tout seul.</p>
      <div id="papp-pending" class="muted" style="font-size:12px">…</div>
    </div>
    <div class="card blueprint" style="padding:16px 18px">
      <div style="font-size:13px;font-weight:600;margin-bottom:8px">Historique</div>
      <div id="papp-history" class="muted" style="font-size:12px">…</div>
    </div>`;

  const fmt = (iso) => iso ? new Date(iso).toLocaleString() : '';
  const statusLabel = { approved: 'accordé', denied: 'refusé', revoked: 'révoqué', expired: 'expiré', pending: 'en attente' };
  const decide = async (id, action, body) => {
    try {
      await api('POST', '/portal/access-requests/' + encodeURIComponent(id) + '/' + action, body || {});
      toast(action === 'approve' ? 'Accès accordé.' : action === 'deny' ? 'Demande refusée.' : 'Accès révoqué.', 'success');
      load();
    } catch (e) { toast(e.message || e, 'error'); }
  };
  const load = async () => {
    const pendingBox = document.getElementById('papp-pending');
    const histBox = document.getElementById('papp-history');
    if (!pendingBox || !histBox) return;
    try {
      const d = await api('GET', '/portal/access-requests' + q) || {};
      const all = d.requests || [];
      const pending = all.filter(r => r.status === 'pending');
      const done = all.filter(r => r.status !== 'pending');
      pendingBox.innerHTML = pending.length ? pending.map(r => `
        <div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:center;padding:10px 0;border-bottom:1px solid var(--border)">
          <div style="min-width:220px;flex:1">
            <div style="font-size:13px"><b>${esc(r.username)}</b> demande <b>${esc(r.target_name || r.target_id)}</b></div>
            <div style="font-size:12px;color:var(--text2);margin-top:2px">${esc(r.reason)} · ${r.duration_min} min · ${esc(fmt(r.created_at))}</div>
          </div>
          <div style="display:flex;gap:8px;align-items:center">
            <select class="input" data-dur="${esc(r.id)}" style="width:auto">
              ${[30, 60, 240, 480].map(m => `<option value="${m}" ${m === r.duration_min ? 'selected' : ''}>${m >= 60 ? (m / 60) + ' h' : m + ' min'}</option>`).join('')}
              ${[30, 60, 240, 480].includes(r.duration_min) ? '' : `<option value="${r.duration_min}" selected>${r.duration_min} min</option>`}
            </select>
            <button class="btn btn-primary btn-sm" data-approve="${esc(r.id)}">Approuver</button>
            <button class="btn btn-secondary btn-sm" data-deny="${esc(r.id)}">Refuser</button>
          </div>
        </div>`).join('') : 'Aucune demande en attente.';
      histBox.innerHTML = done.length ? '<table class="table" style="width:100%;font-size:12px"><thead><tr>' +
        '<th>Date</th><th>Utilisateur</th><th>Destination</th><th>Statut</th><th>Décidé par</th><th>Expire</th><th></th></tr></thead><tbody>' +
        done.map(r => '<tr>' +
          '<td>' + esc(fmt(r.created_at)) + '</td>' +
          '<td>' + esc(r.username) + '</td>' +
          '<td><code>' + esc(r.target_name || r.target_id) + '</code></td>' +
          '<td>' + esc(statusLabel[r.status] || r.status) + '</td>' +
          '<td>' + esc(r.decided_by || '') + '</td>' +
          '<td>' + esc(r.status === 'approved' ? fmt(r.expires_at) : '') + '</td>' +
          '<td>' + (r.status === 'approved' ? '<button class="btn btn-secondary btn-sm" data-revoke="' + esc(r.id) + '">Révoquer</button>' : '') + '</td></tr>').join('') +
        '</tbody></table>' : 'Aucune décision pour le moment.';
      content.querySelectorAll('[data-approve]').forEach(b => {
        b.onclick = () => {
          const sel = content.querySelector('[data-dur="' + b.dataset.approve + '"]');
          decide(b.dataset.approve, 'approve', { duration_min: parseInt(sel.value, 10) });
        };
      });
      content.querySelectorAll('[data-deny]').forEach(b => { b.onclick = () => decide(b.dataset.deny, 'deny'); });
      content.querySelectorAll('[data-revoke]').forEach(b => {
        b.onclick = () => { if (confirm('Révoquer cet accès ?')) decide(b.dataset.revoke, 'revoke'); };
      });
    } catch (e) {
      pendingBox.textContent = e.message || String(e);
    }
  };
  document.getElementById('papp-refresh').onclick = load;
  await load();
};

// ── PAGE: Politiques Access (plages horaires, IP autorisées, inactivité)
pages['portal-policy'] = async function() {
  const edgeName = state.selectedEdge?.node_name || '';
  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML = `<button class="btn btn-primary" id="ppol-save">${esc(t('common.save') || 'Enregistrer')}</button>`;
  if (!edgeName) {
    content.innerHTML = `<div class="empty"><p style="font-size:15px;font-weight:600">${esc(t('portal.need_edge') || 'Sélectionnez une passerelle')}</p></div>`;
    return;
  }
  const q = '?edge=' + encodeURIComponent(edgeName);
  const p = await api('GET', '/portal/policy' + q).catch(() => ({})) || {};
  const days = ['Dim', 'Lun', 'Mar', 'Mer', 'Jeu', 'Ven', 'Sam'];
  const activeDays = new Set(p.days && p.days.length ? p.days : [1, 2, 3, 4, 5]);

  content.innerHTML = `
    <div class="card blueprint" style="padding:16px 18px;max-width:640px;margin-bottom:14px">
      <div style="font-size:13px;font-weight:600;margin-bottom:4px">Plages horaires</div>
      <p class="muted" style="font-size:12px;margin:0 0 12px">Hors de la plage, la connexion au portail et l'ouverture d'une session sont refusées. Les sessions déjà ouvertes continuent.</p>
      <label style="display:flex;align-items:center;gap:10px;margin-bottom:12px;cursor:pointer">
        <input type="checkbox" id="ppol-hours" ${p.hours_enabled ? 'checked' : ''}/>
        <span style="font-size:13px">Limiter les accès à certains horaires</span>
      </label>
      <div id="ppol-hours-box" style="${p.hours_enabled ? '' : 'opacity:.5'}">
        <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px">
          ${days.map((d, i) => `<label style="display:flex;align-items:center;gap:4px;font-size:12px;cursor:pointer"><input type="checkbox" data-day="${i}" ${activeDays.has(i) ? 'checked' : ''}/>${d}</label>`).join('')}
        </div>
        <div class="gp-cols-2">
          <div class="field"><label class="field-label">Début</label><input class="input" id="ppol-start" type="time" value="${esc(p.start_time || '07:00')}"/></div>
          <div class="field"><label class="field-label">Fin</label><input class="input" id="ppol-end" type="time" value="${esc(p.end_time || '20:00')}"/></div>
          <div class="field" style="grid-column:1/-1"><label class="field-label">Fuseau horaire</label><input class="input" id="ppol-tz" value="${esc(p.timezone || 'Europe/Paris')}" placeholder="Europe/Paris"/></div>
        </div>
      </div>
    </div>
    <div class="card blueprint" style="padding:16px 18px;max-width:640px;margin-bottom:14px">
      <div style="font-size:13px;font-weight:600;margin-bottom:4px">Adresses IP autorisées</div>
      <p class="muted" style="font-size:12px;margin:0 0 12px">Une adresse ou une plage CIDR par ligne. Vide : toutes les adresses sont acceptées. S'applique au portail web et à la connexion SSH.</p>
      <textarea class="input" id="ppol-ip" rows="4" placeholder="203.0.113.0/24&#10;198.51.100.7" style="width:100%;font-family:var(--font-mono, monospace)">${esc((p.ip_allow || []).join('\n'))}</textarea>
    </div>
    <div class="card blueprint" style="padding:16px 18px;max-width:640px;margin-bottom:14px">
      <div style="font-size:13px;font-weight:600;margin-bottom:4px">Enregistrement des sessions</div>
      <p class="muted" style="font-size:12px;margin:0 0 12px">Garde la sortie du terminal de chaque nouvelle session (jamais la saisie), chiffrée sur la passerelle, pour la rejouer dans l'onglet Enregistrements. Prévenez vos utilisateurs.</p>
      <label style="display:flex;align-items:center;gap:10px;margin-bottom:12px;cursor:pointer">
        <input type="checkbox" id="ppol-rec" ${p.record_sessions ? 'checked' : ''}/>
        <span style="font-size:13px">Enregistrer les sessions</span>
      </label>
      <div class="field" style="max-width:220px"><label class="field-label">Conservation (jours, 0 = illimitée)</label><input class="input" id="ppol-ret" type="number" min="0" max="3650" value="${p.record_retention_days || 0}"/></div>
    </div>
    <div class="card blueprint" style="padding:16px 18px;max-width:640px">
      <div style="font-size:13px;font-weight:600;margin-bottom:4px">Inactivité</div>
      <p class="muted" style="font-size:12px;margin:0 0 12px">Ferme une session quand l'utilisateur ne tape plus rien depuis ce délai. 0 : pas de limite.</p>
      <div class="field" style="max-width:220px"><label class="field-label">Minutes</label><input class="input" id="ppol-idle" type="number" min="0" max="1440" value="${p.idle_timeout_min || 0}"/></div>
      <div id="ppol-msg" style="margin-top:12px;font-size:13px;min-height:1.2em"></div>
    </div>`;

  document.getElementById('ppol-hours').onchange = (e) => {
    document.getElementById('ppol-hours-box').style.opacity = e.target.checked ? '' : '.5';
  };
  document.getElementById('ppol-save').onclick = async () => {
    const msg = document.getElementById('ppol-msg');
    const body = {
      hours_enabled: document.getElementById('ppol-hours').checked,
      days: [...content.querySelectorAll('[data-day]')].filter(c => c.checked).map(c => +c.dataset.day),
      start_time: document.getElementById('ppol-start').value,
      end_time: document.getElementById('ppol-end').value,
      timezone: document.getElementById('ppol-tz').value.trim(),
      ip_allow: document.getElementById('ppol-ip').value.split('\n').map(s => s.trim()).filter(Boolean),
      idle_timeout_min: +document.getElementById('ppol-idle').value || 0,
      record_sessions: document.getElementById('ppol-rec').checked,
      record_retention_days: +document.getElementById('ppol-ret').value || 0,
    };
    try {
      await api('PUT', '/portal/policy' + q, body);
      msg.textContent = 'Politique enregistrée et poussée à la passerelle.';
      msg.style.color = 'var(--accent)';
    } catch (e) {
      msg.textContent = e.message || String(e);
      msg.style.color = 'var(--danger, #c45c5c)';
    }
  };
};
