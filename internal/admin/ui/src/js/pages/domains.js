// ── PAGE PARTAGÉE: Certificats TLS (Admin + Core) ─────────────────────────
// ctx = { mode: 'admin'|'core' }
//
// Les deux modes partagent exactement le même design (bandeau, table, actions).
// Différences : mode core filtre sur le Core sélectionné ; pas de colonne
// « Core d'entrée » (contexte déjà connu) ; bouton « + Ajouter » admin only.

async function renderCertsPage(ctx) {
  const mode    = ctx?.mode || 'admin';
  const isAdmin = mode === 'admin';
  const core    = isAdmin ? null : state.selectedCore;
  const coreLabel = core ? (core.display_name || core.node_name || core.id || '—') : '';

  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML = isAdmin
    ? `<button class="btn btn-primary" onclick="openDomainModal()">${t('domains.add')}</button>`
    : '';
  content.innerHTML = `<p style="color:var(--text2)">${t('common.loading')}</p>`;

  if (!isAdmin && !core) {
    content.innerHTML = `<p style="color:var(--text2)">${t('trafic.no_core')}</p>`;
    return;
  }

  try {
    const [allDomains, tokens, nodes] = await Promise.all([
      api('GET', '/domains').catch(() => []),
      api('GET', '/tokens?role=core').catch(() => []),
      api('GET', '/nodes').catch(() => []),
    ]);
    const cores = _buildDomainCores(tokens, nodes);
    const coreName = id => {
      const c = cores.find(c => c.id === id || c.node_name === id);
      return c ? (c.display_name || c.node_name || c.id) : (id || '—');
    };

    let rows = allDomains || [];
    if (!isAdmin) {
      const refs = new Set([core?.id, core?.node_name, core?.display_name].filter(Boolean));
      const matchingTokens = (tokens || []).filter(tok => !tok.revoked && (
        refs.has(tok.id) || refs.has(tok.node_name)
      ));
      const tokenIds = new Set(matchingTokens.map(tok => tok.id));
      refs.forEach(r => tokenIds.add(r));

      let scopes = [];
      let rbacRole = (matchingTokens[0]?.rbac_role || 'admin').toLowerCase();
      await Promise.all(matchingTokens.map(async tok => {
        try {
          const sc = await api('GET', `/tokens/${encodeURIComponent(tok.id)}/scopes`) || [];
          scopes = scopes.concat(sc);
          if (tok.rbac_role) rbacRole = String(tok.rbac_role).toLowerCase();
        } catch (_) {}
      }));
      const domainScopes = scopes.filter(s => s.scope_type === 'domain').map(s => s.value || s.scope_value).filter(Boolean);
      const hasCoreScope = scopes.some(s => s.scope_type === 'core');
      const receiveAll = matchingTokens.length > 0 &&
        (rbacRole === 'admin' || rbacRole === 'superadmin') && scopes.length === 0;
      const coversDomain = (domain) => domainScopes.some(v => _domainScopeCovers(v, domain));
      rows = rows.filter(d => {
        if (tokenIds.has(d.core_id) || tokenIds.has(d.delegated_to_core_id)) return true;
        if (matchingTokens.length && (receiveAll || hasCoreScope)) return true;
        if (matchingTokens.length && coversDomain(d.domain)) return true;
        return false;
      });
    }

    const emptyMsg = isAdmin
      ? t('domains.empty_admin')
      : t('domains.empty_core', { name: esc(coreLabel) });
    const colSpan = isAdmin ? 6 : 5;

    content.innerHTML = `
      <div style="margin-bottom:14px;padding:10px 12px;background:color-mix(in srgb,var(--accent) 7%,transparent);border:1px solid color-mix(in srgb,var(--accent) 22%,transparent);border-radius:6px;font-size:12px;color:var(--text2);">
        <strong style="color:var(--text1);">${t('domains.banner_title')}</strong> —
        ${t('domains.banner_body')}
        ${!isAdmin ? `<br><span style="opacity:.85">${t('domains.banner_filtered', { name: esc(coreLabel) })}</span>` : ''}
      </div>
      <div class="card blueprint">
        <div class="table-wrap">
          <table>
            <thead><tr>
              <th>${t('trafic.domain')}</th>${isAdmin ? `<th>${t('domains.col.entry_core')}</th>` : ''}<th>${t('domains.col.dns_provider')}</th><th>${t('domains.col.certificate')}</th><th>${t('domains.col.delegation')}</th><th>${t('trafic.actions')}</th>
            </tr></thead>
            <tbody>
              ${rows.length ? rows.map(d => {
                const exp = d.cert_expires_at ? new Date(d.cert_expires_at) : null;
                const days = exp ? Math.round((exp - Date.now()) / 86400000) : null;
                const certTag = days == null ? `<span class="tag tag-neutral">—</span>`
                  : days < 0   ? `<span class="tag tag-red">${t('domains.cert_expired')}</span>`
                  : days < 7   ? `<span class="tag tag-red">${t('domains.cert_days_warn', { n: days })}</span>`
                  : days < 30  ? `<span class="tag tag-yellow">${t('domains.cert_days_left', { n: days })}</span>`
                  :              `<span class="tag tag-green">${t('domains.cert_valid', { n: days })}</span>`;
                const prov = DNS_PROVIDERS.find(p => p.id === d.dns_provider);
                const provLabel = prov && d.dns_provider !== 'none' ? prov.name : 'HTTP-01';
                const delegLabel = d.delegated_to_core_id
                  ? `<span class="tag tag-accent" title="${esc(d.delegated_endpoint||'')}">→ ${esc(coreName(d.delegated_to_core_id))}</span>`
                  : `<span style="color:var(--text3);font-size:12px">—</span>`;
                return `<tr>
                  <td><b>${esc(d.domain)}</b></td>
                  ${isAdmin ? `<td><span class="tag tag-neutral">${esc(coreName(d.core_id))}</span></td>` : ''}
                  <td style="color:var(--text2);font-size:12px">${esc(provLabel)}</td>
                  <td>${certTag}</td>
                  <td>${delegLabel}</td>
                  <td><div style="display:inline-flex;gap:4px">
                    <button class="btn btn-ghost btn-icon btn-sm" onclick="openDomainModal('${esc(d.id)}')" title="${esc(t('common.edit'))}"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>
                    <button class="btn btn-ghost btn-icon btn-sm" onclick="renewDomainCert('${esc(d.id)}')" title="${esc(t('domains.renew'))}"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg></button>
                    <button class="btn btn-ghost btn-icon btn-sm" onclick="deleteDomain('${esc(d.id)}','${esc(d.domain)}')" title="${esc(t('common.delete'))}"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg></button>
                  </div></td>
                </tr>`;
              }).join('') : `<tr><td colspan="${colSpan}" class="empty"><p>${emptyMsg}</p></td></tr>`}
            </tbody>
          </table>
        </div>
      </div>`;
  } catch(e) { content.innerHTML = `<p style="color:var(--red)">${t('domains.error', { msg: esc(e.message) })}</p>`; }
}

pages.certs = async function() {
  await renderCertsPage({ mode: 'admin' });
};

pages['core-certs'] = async function() {
  await renderCertsPage({ mode: 'core' });
};

async function refreshDomains() {
  const mode = state.page === 'core-certs' ? 'core' : 'admin';
  return renderCertsPage({ mode });
}

/** Cores réels pour le sélecteur Domaines : tokens actifs (+ endpoint ou nœud online), dédup node_name. */
function _buildDomainCores(tokens, nodes) {
  const now = Date.now();
  const onlineNames = new Set(
    (nodes || [])
      .filter(n => n.role === 'core' && n.status === 'online')
      .map(n => (n.node_name || n.display_name || '').trim())
      .filter(Boolean)
  );
  const coreMap = new Map();
  for (const tok of (tokens || [])) {
    if (tok.revoked) continue;
    if (tok.expires_at && new Date(tok.expires_at).getTime() <= now) continue;
    const nn = (tok.node_name || '').trim();
    if (!nn) continue;
    const endpoint = (tok.node_endpoint || '').trim();
    if (!endpoint && !onlineNames.has(nn)) continue;
    const existing = coreMap.get(nn);
    if (!existing || (!existing.node_endpoint && endpoint)) {
      coreMap.set(nn, {
        id: tok.id,
        node_name: nn,
        display_name: nn,
        node_endpoint: endpoint,
        rbac_role: tok.rbac_role || 'admin',
      });
    }
  }
  return [...coreMap.values()];
}

function _domainHostCovered(host, pattern) {
  host = String(host || '').toLowerCase().trim();
  pattern = String(pattern || '').toLowerCase().trim();
  if (!host || !pattern) return false;
  if (host === pattern) return true;
  if (pattern.startsWith('*.')) {
    const suffix = pattern.slice(1);
    if (!host.endsWith(suffix) || host.length <= suffix.length) return false;
    const rest = host.slice(0, host.length - suffix.length);
    return rest !== '' && !rest.includes('.');
  }
  return false;
}

/** Chevauchement approximatif domaine déclaré ↔ scope token. */
function _domainScopeCovers(scopeVal, domain) {
  const s = String(scopeVal || '').toLowerCase().trim();
  const d = String(domain || '').toLowerCase().trim();
  if (!s || !d) return false;
  if (s === d) return true;
  if (_domainHostCovered(d.replace(/^\*\./, 'x.'), s)) return true;
  if (_domainHostCovered(s.replace(/^\*\./, 'x.'), d)) return true;
  // Même apex wildcard : *.a.fr vs *.a.fr déjà couvert ; *.a.fr vs a.fr
  if (s.startsWith('*.') && d === s.slice(2)) return true;
  if (d.startsWith('*.') && s === d.slice(2)) return true;
  return false;
}

window.openDomainModal = async function(id) {
  let existing = null;
  let cores = [];
  let tokens = [];
  let scopeByToken = {};
  try {
    const [d, toks, nodes] = await Promise.all([
      id ? api('GET', `/domains/${id}`).catch(()=>null) : Promise.resolve(null),
      api('GET', '/tokens?role=core').catch(() => []),
      api('GET', '/nodes').catch(() => []),
    ]);
    existing = d;
    tokens = toks || [];
    cores = _buildDomainCores(tokens, nodes);
    // Charger les scopes domaine pour les alertes douces
    await Promise.all(cores.map(async c => {
      try {
        const scopes = await api('GET', `/tokens/${c.id}/scopes`) || [];
        scopeByToken[c.id] = scopes.filter(s => s.scope_type === 'domain').map(s => s.value);
      } catch (_) {
        scopeByToken[c.id] = [];
      }
    }));
  } catch {}

  window._dmCores = cores;
  window._dmScopeByToken = scopeByToken;

  const sel = existing?.dns_provider || 'none';
  const provider = DNS_PROVIDERS.find(p => p.id === sel);
  const hasDelegation = !!existing?.delegated_to_core_id;
  const certMethod = existing?.cert_method || (sel !== 'none' ? 'dns' : 'http');
  const matchesCore = (c, ref) => !!ref && (c.id === ref || c.node_name === ref || c.display_name === ref);
  const selectedCore = cores.find(c => matchesCore(c, existing?.core_id));
  const selectedDelegatedCore = cores.find(c => matchesCore(c, existing?.delegated_to_core_id));
  const selectedCoreValue = selectedCore ? selectedCore.id : '';
  const selectedDelegatedCoreValue = selectedDelegatedCore ? selectedDelegatedCore.id : '';
  const coreOptions = [
    `<option value="">${t('domains.choose_core')}</option>`,
    ...cores.map(c => `<option value="${esc(c.id)}" ${selectedCoreValue===c.id?'selected':''}>${esc(c.display_name||c.node_name||c.id)}</option>`),
  ].join('');
  const delegatedCoreOptions = [
    `<option value="">${t('domains.choose_target_core')}</option>`,
    ...cores.map(c => `<option value="${esc(c.id)}" ${selectedDelegatedCoreValue===c.id?'selected':''}>${esc(c.display_name||c.node_name||c.id)}</option>`),
  ].join('');

  modal(id ? t('domains.modal_edit', { domain: existing?.domain || '' }) : t('domains.modal_add'), `
    <div style="display:flex;flex-direction:column;gap:16px">
      <div style="padding:10px 12px;background:color-mix(in srgb,var(--accent) 7%,transparent);border:1px solid color-mix(in srgb,var(--accent) 22%,transparent);border-radius:6px;font-size:12px;color:var(--text2);">
        <strong style="color:var(--text1);">${t('domains.modal_banner_title')}</strong> —
        ${t('domains.modal_banner_body')}
      </div>
      <div id="dm-soft-warn" style="display:none;padding:10px 12px;border-radius:6px;font-size:12px;"></div>
      <div class="field">
        <label class="field-label">${t('trafic.domain')}</label>
        <input id="dm-domain" class="input" placeholder="${esc(t('domains.domain_ph'))}" value="${esc(existing?.domain||'')}" oninput="dmRefreshSoftWarn()">
      </div>
      <div class="field">
        <label class="field-label">${t('domains.field_entry_core')}</label>
        <div style="font-size:11px;color:var(--text3);margin-bottom:6px">${t('domains.entry_core_hint')}</div>
        <select id="dm-core" class="input" onchange="dmRefreshSoftWarn()">
          ${coreOptions}
        </select>
      </div>
      <div class="field">
        <label class="field-label">${t('domains.field_dns')}</label>
        <div style="font-size:11px;color:var(--text3);margin-bottom:8px">${t('domains.dns_hint')}</div>
        <div style="display:flex;flex-wrap:wrap;gap:6px">
          ${DNS_PROVIDERS.map(p => `<button type="button" id="dm-pill-${p.id}" onclick="dmSelectProvider('${p.id}')"
            style="padding:5px 12px;font-size:11px;font-weight:600;border-radius:6px;cursor:pointer;transition:all .15s;border:1.5px solid ${p.id===sel?'var(--accent)':'var(--border)'};background:${p.id===sel?'color-mix(in srgb,var(--accent) 8%,transparent)':'var(--bg2)'};color:${p.id===sel?'var(--accent)':'var(--text2)'}">${p.name}</button>`).join('')}
        </div>
        <input type="hidden" id="dm-provider" value="${esc(sel)}">
      </div>
      <div id="dm-provider-fields" style="display:flex;flex-direction:column;gap:12px">
        ${!provider || sel === 'none' ? '' : provider.fields.map(f => `
          <div class="field">
            <label class="field-label">${f.label}</label>
            <input id="dm-field-${f.id}" class="input" type="${f.type||'text'}" placeholder="${f.placeholder||''}" value="${esc(String(existing?.dns_credentials?.[f.id]||''))}">
          </div>`).join('')}
      </div>
      <div class="field" id="dm-method-section" style="display:${sel==='none'?'':'none'}">
        <label class="field-label">${t('domains.field_cert_validation')}</label>
        <div style="display:flex;flex-direction:column;gap:6px;margin-top:4px">
          <label class="radio ${certMethod==='http'?'selected':''}" id="dm-cert-http" onclick="dmSelectCertMethod('http')">
            <input type="radio" name="dm-cert-method" value="http" ${certMethod==='http'?'checked':''}><div class="dot"></div>
            <div><div class="radio-label">${t('domains.cert_http')}</div><div class="radio-hint">${t('domains.cert_http_hint')}</div></div>
          </label>
          <label class="radio ${certMethod==='manual'?'selected':''}" id="dm-cert-manual" onclick="dmSelectCertMethod('manual')">
            <input type="radio" name="dm-cert-method" value="manual" ${certMethod==='manual'?'checked':''}><div class="dot"></div>
            <div><div class="radio-label">${t('domains.cert_manual')}</div><div class="radio-hint">${t('domains.cert_manual_hint')}</div></div>
          </label>
        </div>
      </div>
      <div id="dm-manual-fields" style="display:${certMethod==='manual'?'flex':'none'};flex-direction:column;gap:12px">
        <div class="field"><label class="field-label">${t('domains.field_cert_pem')}</label><textarea id="dm-cert-pem" class="input" rows="3" placeholder="${esc(t('domains.cert_pem_ph'))}">${esc(existing?.cert_pem||'')}</textarea></div>
        <div class="field"><label class="field-label">${t('domains.field_key_pem')}</label><textarea id="dm-key-pem" class="input" rows="3" placeholder="${esc(t('domains.key_pem_ph'))}">${esc(existing?.key_pem||'')}</textarea></div>
      </div>
      <div style="padding-top:12px;border-top:1px solid var(--border)">
        <label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:13px;font-weight:600;margin-bottom:8px">
          <input type="checkbox" id="dm-delegate-check" onchange="dmToggleDelegate(this.checked)" ${hasDelegation?'checked':''}>
          ${t('domains.delegate_label')}
        </label>
        <div style="font-size:11px;color:var(--text3);margin-bottom:8px">${t('domains.delegate_hint')}</div>
        <div id="dm-delegate-section" style="display:${hasDelegation?'flex':'none'};flex-direction:column;gap:10px">
          <div class="field">
            <label class="field-label">${t('domains.field_target_core')}</label>
            <select id="dm-delegate-core" class="input">
              ${delegatedCoreOptions}
            </select>
          </div>
          <div class="field">
            <label class="field-label">${t('domains.field_internal_endpoint')}</label>
            <input id="dm-delegate-endpoint" class="input" placeholder="${esc(t('domains.endpoint_ph'))}" value="${esc(existing?.delegated_endpoint||'')}">
            <div style="font-size:11px;color:var(--text3);margin-top:4px">${t('domains.endpoint_hint')}</div>
          </div>
          <div class="field">
            <label class="field-label">${t('domains.field_delegation_mode')}</label>
            <div style="display:flex;flex-direction:column;gap:10px;margin-top:6px">
              <label style="display:flex;align-items:flex-start;gap:8px;cursor:pointer">
                <input type="radio" name="dm-delegation-mode" value="passthrough" ${(existing?.delegation_mode||'passthrough')==='passthrough'?'checked':''} style="margin-top:3px">
                <span>${t('domains.mode_passthrough')}</span>
              </label>
              <label style="display:flex;align-items:flex-start;gap:8px;cursor:pointer">
                <input type="radio" name="dm-delegation-mode" value="terminate" ${existing?.delegation_mode==='terminate'?'checked':''} style="margin-top:3px">
                <span>${t('domains.mode_terminate')}</span>
              </label>
            </div>
          </div>
        </div>
      </div>
    </div>`,
    `<button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel')}</button>
     <button class="btn btn-primary" onclick="saveDomain(${id?`'${id}'`:'null'})">${id ? t('common.save') : t('common.create')}</button>`
  );
  setTimeout(() => dmRefreshSoftWarn(), 0);
};

window.dmRefreshSoftWarn = function() {
  const el = document.getElementById('dm-soft-warn');
  if (!el) return;
  const domain = (document.getElementById('dm-domain')?.value || '').trim();
  const coreId = document.getElementById('dm-core')?.value || '';
  const cores = window._dmCores || [];
  const scopeByToken = window._dmScopeByToken || {};
  if (!domain && !coreId) {
    el.style.display = 'none';
    el.innerHTML = '';
    return;
  }
  const msgs = [];
  if (domain && !coreId) {
    msgs.push(t('domains.warn_pick_core', { domain: esc(domain) }));
  }
  if (domain && coreId) {
    const core = cores.find(c => c.id === coreId);
    const scopes = scopeByToken[coreId] || [];
    const role = (core?.rbac_role || 'admin').toLowerCase();
    const hasCovering = scopes.some(v => _domainScopeCovers(v, domain));
    const globalAdmin = role === 'admin' && scopes.length === 0;
    if (!globalAdmin && !hasCovering) {
      msgs.push(t('domains.warn_no_scope', { core: esc(core?.node_name || coreId), domain: esc(domain) }));
    }
    const others = cores.filter(c => c.id !== coreId).filter(c => {
      const sc = scopeByToken[c.id] || [];
      return sc.some(v => _domainScopeCovers(v, domain));
    });
    if (others.length) {
      msgs.push(t('domains.warn_other_scopes', { cores: others.map(c => `<code>${esc(c.node_name)}</code>`).join(', ') }));
    }
  }
  if (!msgs.length) {
    el.style.display = 'none';
    el.innerHTML = '';
    return;
  }
  el.style.display = 'block';
  el.style.background = 'color-mix(in srgb,var(--yellow,#f59e0b) 12%,transparent)';
  el.style.border = '1px solid color-mix(in srgb,var(--yellow,#f59e0b) 35%,transparent)';
  el.style.color = 'var(--text2)';
  el.innerHTML = msgs.map(m => `<div style="margin-bottom:4px">${m}</div>`).join('');
};

window.dmSelectProvider = function(id) {
  document.getElementById('dm-provider').value = id;
  DNS_PROVIDERS.forEach(p => {
    const btn = document.getElementById('dm-pill-' + p.id);
    if (!btn) return;
    const active = p.id === id;
    btn.style.borderColor = active ? 'var(--accent)' : 'var(--border)';
    btn.style.background   = active ? 'color-mix(in srgb,var(--accent) 8%,transparent)' : 'var(--bg2)';
    btn.style.color        = active ? 'var(--accent)' : 'var(--text2)';
  });
  const provider = DNS_PROVIDERS.find(p => p.id === id);
  const fieldsEl = document.getElementById('dm-provider-fields');
  if (fieldsEl) {
    fieldsEl.innerHTML = (!provider || id === 'none') ? '' : provider.fields.map(f => `
      <div class="field">
        <label class="field-label">${f.label}</label>
        <input id="dm-field-${f.id}" class="input" type="${f.type||'text'}" placeholder="${f.placeholder||''}">
      </div>`).join('');
  }
  const methodSection = document.getElementById('dm-method-section');
  const manualFields  = document.getElementById('dm-manual-fields');
  if (methodSection) methodSection.style.display = id === 'none' ? '' : 'none';
  if (manualFields && id !== 'none') manualFields.style.display = 'none';
};

window.dmSelectCertMethod = function(method) {
  ['http','manual'].forEach(m => {
    const el = document.getElementById('dm-cert-' + m);
    if (!el) return;
    el.classList.toggle('selected', m === method);
    el.querySelector('input[type=radio]').checked = m === method;
  });
  const mf = document.getElementById('dm-manual-fields');
  if (mf) mf.style.display = method === 'manual' ? 'flex' : 'none';
};

window.dmToggleDelegate = function(checked) {
  const el = document.getElementById('dm-delegate-section');
  if (el) el.style.display = checked ? 'flex' : 'none';
};

window.saveDomain = async function(id) {
  const domain      = document.getElementById('dm-domain')?.value.trim();
  const core_id     = document.getElementById('dm-core')?.value;
  const dns_provider= document.getElementById('dm-provider')?.value || 'none';
  const cert_method = dns_provider !== 'none' ? 'dns'
    : (document.querySelector('input[name="dm-cert-method"]:checked')?.value || 'http');
  const delegated   = document.getElementById('dm-delegate-check')?.checked;

  if (!domain) { toast(t('domains.err_domain_required'), 'error'); return; }
  if (!core_id) { toast(t('domains.err_entry_core_required'), 'error'); return; }

  const payload = { domain, core_id, dns_provider, cert_method };

  const provider = DNS_PROVIDERS.find(p => p.id === dns_provider);
  if (provider?.fields) {
    const creds = {};
    provider.fields.forEach(f => {
      const el = document.getElementById('dm-field-' + f.id);
      if (el) creds[f.id] = el.value;
    });
    payload.dns_credentials = creds;
  }

  if (cert_method === 'manual') {
    payload.cert_pem = document.getElementById('dm-cert-pem')?.value.trim();
    payload.key_pem  = document.getElementById('dm-key-pem')?.value.trim();
    if (!payload.cert_pem || !payload.key_pem) { toast(t('domains.err_cert_required'), 'error'); return; }
  }

  if (delegated) {
    payload.delegated_to_core_id = document.getElementById('dm-delegate-core')?.value;
    payload.delegated_endpoint   = document.getElementById('dm-delegate-endpoint')?.value.trim();
    const modeEl = document.querySelector('input[name="dm-delegation-mode"]:checked');
    payload.delegation_mode = modeEl ? modeEl.value : 'passthrough';
    if (!payload.delegated_to_core_id) { toast(t('domains.err_target_core_required'), 'error'); return; }
    if (!payload.delegated_endpoint) { toast(t('domains.err_endpoint_required'), 'error'); return; }
    if (payload.delegated_to_core_id === core_id) {
      toast(t('domains.err_target_different'), 'error');
      return;
    }
  } else {
    payload.delegated_to_core_id = '';
    payload.delegated_endpoint = '';
    payload.delegation_mode = 'passthrough';
  }

  try {
    let res;
    if (id) {
      res = await api('PUT', `/domains/${id}`, payload);
      toast(t('domains.updated'), 'success');
    } else {
      res = await api('POST', '/domains', payload);
      toast(t('domains.added'), 'success');
    }
    const ensured = (res && res.scopes_ensured) || [];
    if (ensured.length) {
      toast(t('domains.scopes_ensured', { scopes: ensured.join(', ') }), 'info');
    }
    closeModal();
    refreshDomains();
  } catch(e) { toast(e.message, 'error'); }
};

window.renewDomainCert = async function(id) {
  try {
    await api('POST', `/domains/${id}/renew`);
    toast(t('domains.renewing'), 'info');
  } catch(e) { toast(e.message, 'error'); }
};

window.deleteDomain = function(id, domain) {
  confirm_(t('domains.delete_confirm', { domain }), async () => {
    try {
      await api('DELETE', `/domains/${id}`);
      toast(t('domains.deleted'), 'success');
      refreshDomains();
    } catch(e) { toast(e.message, 'error'); }
  });
};
