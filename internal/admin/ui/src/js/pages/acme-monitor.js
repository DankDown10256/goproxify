// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

let _acmeRefreshTimer = null;

const PROVIDER_LABELS = {
  ovh: 'OVH', cloudflare: 'Cloudflare', route53: 'Route 53',
  hetzner: 'Hetzner', gandi: 'Gandi', none: '—', '': '—',
};
const PROVIDER_COLORS = {
  ovh: '#0050d5', cloudflare: '#f38020', route53: '#ff9900',
  hetzner: '#d50000', gandi: '#ff6600',
};

// Champs attendus par provider type (label, clé params, required, placeholder)
const PROVIDER_FIELDS = {
  cloudflare: [
    { key: 'api_token',  label: 'API Token',  required: true,  ph: 'Bearer token Cloudflare' },
    { key: 'zone_id',    label: 'Zone ID',     required: false, ph: 'Optionnel — résolu automatiquement si vide' },
  ],
  ovh: [
    { key: 'endpoint',     label: 'Endpoint',        required: false, ph: 'https://eu.api.ovh.com/1.0' },
    { key: 'app_key',      label: 'Application Key', required: true,  ph: '' },
    { key: 'app_secret',   label: 'Application Secret', required: true, ph: '' },
    { key: 'consumer_key', label: 'Consumer Key',    required: true,  ph: '' },
    { key: 'zone',         label: 'Zone DNS',        required: true,  ph: 'example.com' },
  ],
  gandi: [
    { key: 'api_key', label: 'API Key', required: true, ph: 'Clé API Gandi LiveDNS' },
  ],
  hetzner: [
    { key: 'api_token', label: 'API Token', required: true,  ph: 'Token Hetzner DNS' },
    { key: 'zone_id',   label: 'Zone ID',   required: true,  ph: 'ID de la zone Hetzner' },
  ],
  route53: [
    { key: 'hosted_zone_id', label: 'Hosted Zone ID', required: true, ph: 'Z1234567890' },
  ],
};

pages['acme-monitor'] = async function () {
  if (_acmeRefreshTimer) { clearInterval(_acmeRefreshTimer); _acmeRefreshTimer = null; }
  const root = document.getElementById('content');
  root.innerHTML = `
    <div style="padding:24px 28px;">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;flex-wrap:wrap;gap:12px;">
        <div>
          <h2 style="margin:0;font-size:20px;">${t('acme_monitor.title')}</h2>
          <p style="margin:4px 0 0;font-size:13px;opacity:0.55;">${t('acme_monitor.subtitle')}</p>
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;">
          <button class="btn btn-primary" style="font-size:12px;" onclick="openNewCertModal()">${t('acme_monitor.new_cert_btn')}</button>
          <button class="btn btn-ghost" style="font-size:12px;" onclick="openImportCertModal()">${t('acme_monitor.import_btn')}</button>
          <button class="btn btn-ghost" style="font-size:12px;" onclick="acmeMonitorLoad()">↻ ${t('common.refresh')}</button>
        </div>
      </div>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px;">
        <div id="acme-config-section"></div>
        <div id="acme-providers-section"></div>
      </div>

      <div id="acme-kpis" style="display:flex;gap:14px;flex-wrap:wrap;margin-bottom:24px;"></div>
      <div id="acme-table-wrap"></div>
    </div>`;
  await Promise.all([acmeConfigLoad(), acmeProvidersLoad(), acmeMonitorLoad()]);
  _acmeRefreshTimer = setInterval(acmeMonitorLoad, 60_000);
  const obs = new MutationObserver(() => {
    if (!document.getElementById('acme-kpis')) {
      clearInterval(_acmeRefreshTimer); _acmeRefreshTimer = null; obs.disconnect();
    }
  });
  obs.observe(document.getElementById('content'), { childList: true });
};

// ── Config ACME (email + CA) ─────────────────────────────────────────────────

window.acmeConfigLoad = async function () {
  const el = document.getElementById('acme-config-section');
  if (!el) return;
  const cfg = await api('GET', '/settings/acme').catch(() => null);
  if (!cfg) { el.innerHTML = ''; return; }
  el.innerHTML = `
    <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:16px 20px;height:100%;box-sizing:border-box;">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">
        <div style="display:flex;align-items:center;gap:8px;">
          <span style="width:8px;height:8px;border-radius:50%;background:${cfg.enabled ? '#22c55e' : '#6b7280'};flex-shrink:0;"></span>
          <span style="font-size:13px;font-weight:600;">${t('acme_monitor.config_title')}</span>
        </div>
        <button class="btn btn-ghost" style="font-size:11px;" onclick="openAcmeConfigModal()">${t('acme_monitor.config_edit')}</button>
      </div>
      <div style="display:flex;flex-direction:column;gap:6px;font-size:12px;">
        <div style="display:flex;justify-content:space-between;">
          <span style="opacity:0.55;">${t('acme_monitor.config_email')}</span>
          <strong>${cfg.email || '—'}</strong>
        </div>
        <div style="display:flex;justify-content:space-between;">
          <span style="opacity:0.55;">CA</span>
          <span style="opacity:0.7;font-family:monospace;font-size:10px;">${cfg.directory_url || 'Let\'s Encrypt (prod)'}</span>
        </div>
      </div>
    </div>`;
};

window.openAcmeConfigModal = async function () {
  const cfg = await api('GET', '/settings/acme').catch(() => ({}));
  document.getElementById('acme-config-modal-backdrop')?.remove();
  document.body.insertAdjacentHTML('beforeend', `
    <div id="acme-config-modal-backdrop" class="dialog-backdrop" style="background:rgba(0,0,0,0.55);">
      <div class="dialog blueprint" role="dialog" aria-modal="true" style="width:min(480px,96vw);max-width:none;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div class="dialog-title">${t('acme_monitor.config_title')}</div>
        <div class="dialog-body" style="display:flex;flex-direction:column;gap:14px;">
          <label style="display:flex;align-items:center;gap:10px;cursor:pointer;font-size:13px;">
            <input type="checkbox" id="acme-cfg-enabled" ${cfg.enabled ? 'checked' : ''}>
            ${t('acme_monitor.config_enabled')}
          </label>
          <div class="field">
            <label>${t('acme_monitor.config_email')}</label>
            <input class="input" id="acme-cfg-email" type="email" placeholder="admin@example.com" value="${esc(cfg.email||'')}">
          </div>
          <div class="field">
            <label>${t('acme_monitor.config_dir')} <span style="opacity:0.5;font-size:11px;">(${t('common.optional')})</span></label>
            <input class="input" id="acme-cfg-dir" placeholder="https://acme-v02.api.letsencrypt.org/directory" value="${esc(cfg.directory_url||'')}">
            <p style="margin:4px 0 0;font-size:11px;opacity:0.45;">Laisser vide pour Let's Encrypt production.</p>
          </div>
        </div>
        <div class="dialog-footer">
          <button class="btn btn-secondary" onclick="document.getElementById('acme-config-modal-backdrop').remove()">${t('common.cancel')}</button>
          <button class="btn btn-primary blueprint" onclick="saveAcmeConfig()">
            <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
            ${t('acme_monitor.config_save')}
          </button>
        </div>
      </div>
    </div>`);
};

window.saveAcmeConfig = async function () {
  const enabled = document.getElementById('acme-cfg-enabled')?.checked || false;
  const email = document.getElementById('acme-cfg-email')?.value?.trim() || '';
  const directory_url = document.getElementById('acme-cfg-dir')?.value?.trim() || '';
  try {
    await api('PUT', '/settings/acme', { enabled, email, dns_type: '', directory_url });
    document.getElementById('acme-config-modal-backdrop')?.remove();
    toast(t('acme_monitor.config_saved'), 'success');
    acmeConfigLoad();
  } catch (e) {
    toast(e.message || t('common.error'), 'error');
  }
};

// ── Providers DNS ─────────────────────────────────────────────────────────────

window.acmeProvidersLoad = async function () {
  const el = document.getElementById('acme-providers-section');
  if (!el) return;
  const providers = await api('GET', '/acme/providers').catch(() => null);
  if (!providers) { el.innerHTML = ''; return; }

  const rows = providers.map(p => {
    const pColor = PROVIDER_COLORS[p.type];
    const pLabel = PROVIDER_LABELS[p.type] || p.type;
    const badge = pColor
      ? `<span style="background:${pColor}22;color:${pColor};border:1px solid ${pColor}44;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:600;">${pLabel}</span>`
      : `<span style="font-size:11px;opacity:0.6;">${esc(pLabel)}</span>`;
    return `<tr>
      <td style="padding:6px 8px;font-size:12px;font-weight:500;">${esc(p.name)}</td>
      <td style="padding:6px 8px;">${badge}</td>
      <td style="text-align:right;padding:6px 8px;white-space:nowrap;">
        <button class="btn btn-ghost" title="${t('acme_monitor.providers_edit')}" style="padding:4px 6px;"
          onclick="openAcmeProviderModal(${JSON.stringify(p).replace(/</g,'\\u003c').replace(/>/g,'\\u003e')})">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
        </button>
        <button class="btn btn-ghost" title="${t('acme_monitor.providers_delete')}" style="padding:4px 6px;color:var(--red);"
          onclick="deleteAcmeProvider('${esc(p.id)}','${esc(p.name)}')">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
        </button>
      </td>
    </tr>`;
  }).join('');

  el.innerHTML = `
    <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:16px 20px;height:100%;box-sizing:border-box;">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">
        <span style="font-size:13px;font-weight:600;">${t('acme_monitor.providers_title')}</span>
        <button class="btn btn-ghost" style="font-size:11px;" onclick="openAcmeProviderModal(null)">${t('acme_monitor.providers_add')}</button>
      </div>
      ${providers.length === 0
        ? `<p style="margin:0;font-size:12px;opacity:0.5;text-align:center;padding:16px 0;">${t('acme_monitor.providers_empty')}</p>`
        : `<table style="width:100%;border-collapse:collapse;">
            <tbody>${rows}</tbody>
          </table>`
      }
    </div>`;
};

// Rendu des champs dynamiques selon le type de provider
function providerFieldsHTML(type, params) {
  const fields = PROVIDER_FIELDS[type] || [];
  if (!fields.length) return `<p style="font-size:12px;opacity:0.5;">${t('acme_monitor.providers_no_fields')}</p>`;
  return fields.map(f => `
    <div class="field">
      <label>${esc(f.label)}${f.required ? '' : ` <span style="opacity:0.5;font-size:11px;">(${t('common.optional')})</span>`}</label>
      <input class="input" id="pf-${esc(f.key)}" type="${f.key.includes('secret') || f.key.includes('token') || f.key.includes('key') ? 'password' : 'text'}"
        autocomplete="off" placeholder="${esc(f.ph)}" value="${esc(params?.[f.key]||'')}">
    </div>`).join('');
}

window.openAcmeProviderModal = function (provider) {
  const isEdit = !!provider;
  const currentType = provider?.type || 'cloudflare';
  document.getElementById('acme-provider-modal-backdrop')?.remove();
  document.body.insertAdjacentHTML('beforeend', `
    <div id="acme-provider-modal-backdrop" class="dialog-backdrop" style="background:rgba(0,0,0,0.55);">
      <div class="dialog blueprint" role="dialog" aria-modal="true" style="width:min(500px,96vw);max-width:none;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div class="dialog-title">${isEdit ? t('acme_monitor.providers_modal_edit') : t('acme_monitor.providers_modal_create')}</div>
        <div class="dialog-body" style="display:flex;flex-direction:column;gap:14px;">
          <div class="field">
            <label>${t('acme_monitor.providers_name')}</label>
            <input class="input" id="prov-name" placeholder="${t('acme_monitor.providers_name_ph')}" value="${esc(provider?.name||'')}">
          </div>
          <div class="field">
            <label>${t('acme_monitor.providers_type')}</label>
            <select class="input" id="prov-type" onchange="acmeProviderTypeChange(${JSON.stringify(provider?.params||null).replace(/</g,'\\u003c')})">
              ${['cloudflare','ovh','gandi','hetzner','route53'].map(v =>
                `<option value="${v}" ${currentType===v?'selected':''}>${PROVIDER_LABELS[v]||v}</option>`
              ).join('')}
            </select>
          </div>
          <div id="prov-fields">
            ${providerFieldsHTML(currentType, provider?.params)}
          </div>
        </div>
        <div class="dialog-footer">
          <button class="btn btn-secondary" onclick="document.getElementById('acme-provider-modal-backdrop').remove()">${t('common.cancel')}</button>
          <button class="btn btn-primary blueprint" onclick="saveAcmeProvider('${esc(provider?.id||'')}')">
            <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
            ${t('acme_monitor.config_save')}
          </button>
        </div>
      </div>
    </div>`);
};

window.acmeProviderTypeChange = function (existingParams) {
  const type = document.getElementById('prov-type')?.value;
  const el = document.getElementById('prov-fields');
  if (el) el.innerHTML = providerFieldsHTML(type, existingParams);
};

window.saveAcmeProvider = async function (id) {
  const name = document.getElementById('prov-name')?.value?.trim() || '';
  const type = document.getElementById('prov-type')?.value || '';
  if (!name || !type) { toast(t('acme_monitor.providers_name_required'), 'error'); return; }
  // Collecte les champs dynamiques
  const params = {};
  for (const f of (PROVIDER_FIELDS[type] || [])) {
    const val = document.getElementById(`pf-${f.key}`)?.value?.trim() || '';
    if (val) params[f.key] = val;
    else if (f.required) {
      toast(`${f.label} ${t('common.required')}`, 'error');
      return;
    }
  }
  try {
    if (id) {
      await api('PUT', `/acme/providers/${id}`, { name, type, params });
    } else {
      await api('POST', '/acme/providers', { name, type, params });
    }
    document.getElementById('acme-provider-modal-backdrop')?.remove();
    toast(t('acme_monitor.providers_saved'), 'success');
    acmeProvidersLoad();
  } catch (e) {
    toast(e.message || t('common.error'), 'error');
  }
};

window.deleteAcmeProvider = async function (id, name) {
  if (!confirm(t('acme_monitor.providers_delete_confirm').replace('{name}', name))) return;
  try {
    await api('DELETE', `/acme/providers/${id}`);
    toast(t('acme_monitor.providers_deleted'), 'success');
    acmeProvidersLoad();
  } catch (e) {
    toast(e.message || t('common.error'), 'error');
  }
};

// ── Nouveau certificat ────────────────────────────────────────────────────────

window.openNewCertModal = async function () {
  const providers = await api('GET', '/acme/providers').catch(() => []);
  document.getElementById('acme-new-cert-backdrop')?.remove();
  const provOptions = providers.length
    ? providers.map(p => {
        const pColor = PROVIDER_COLORS[p.type];
        return `<option value="${esc(p.id)}">${esc(p.name)} (${PROVIDER_LABELS[p.type]||p.type})</option>`;
      }).join('')
    : `<option value="" disabled selected>${t('acme_monitor.new_cert_no_provider')}</option>`;

  document.body.insertAdjacentHTML('beforeend', `
    <div id="acme-new-cert-backdrop" class="dialog-backdrop" style="background:rgba(0,0,0,0.55);">
      <div class="dialog blueprint" role="dialog" aria-modal="true" style="width:min(460px,96vw);max-width:none;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div class="dialog-title">${t('acme_monitor.new_cert_title')}</div>
        <div class="dialog-body" style="display:flex;flex-direction:column;gap:14px;">
          ${!providers.length ? `
          <div style="background:#fef3c7;border:1px solid #fde68a;border-radius:8px;padding:10px 14px;font-size:12px;color:#92400e;">
            ${t('acme_monitor.new_cert_provider_hint')}
          </div>` : ''}
          <div class="field">
            <label>${t('acme_monitor.new_cert_domain')}</label>
            <input class="input" id="nc-domain" placeholder="*.example.com ou example.com">
            <p style="margin:4px 0 0;font-size:11px;opacity:0.45;">${t('acme_monitor.new_cert_domain_hint')}</p>
          </div>
          <div class="field">
            <label>${t('acme_monitor.new_cert_provider')}</label>
            <select class="input" id="nc-provider">
              ${provOptions}
            </select>
          </div>
        </div>
        <div class="dialog-footer">
          <button class="btn btn-secondary" onclick="document.getElementById('acme-new-cert-backdrop').remove()">${t('common.cancel')}</button>
          <button class="btn btn-primary blueprint" onclick="submitNewCert()" ${!providers.length?'disabled':''}>
            <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
            ${t('acme_monitor.new_cert_submit')}
          </button>
        </div>
      </div>
    </div>`);
};

window.submitNewCert = async function () {
  const domain = document.getElementById('nc-domain')?.value?.trim() || '';
  const providerId = document.getElementById('nc-provider')?.value || '';
  if (!domain) { toast(t('acme_monitor.new_cert_domain_required'), 'error'); return; }
  try {
    await api('POST', '/certs', { domain, acme_provider_id: providerId });
    document.getElementById('acme-new-cert-backdrop')?.remove();
    toast(t('acme_monitor.renew_started').replace('{domain}', domain), 'success');
    setTimeout(acmeMonitorLoad, 2000);
  } catch (e) {
    toast(e.message || t('common.error'), 'error');
  }
};

// ── Monitor table ─────────────────────────────────────────────────────────────

window.acmeMonitorLoad = async function () {
  const data = await api('GET', '/certs/acme-monitor').catch(() => null);
  if (!data) {
    document.getElementById('acme-table-wrap').innerHTML =
      `<p style="opacity:0.5;text-align:center;padding:40px 0;">${t('acme_monitor.load_error')}</p>`;
    return;
  }

  const kpis = [
    { label: t('acme_monitor.kpi_total'),    value: data.total,    color: 'var(--text)' },
    { label: t('acme_monitor.kpi_ok'),       value: data.ok,       color: '#22c55e' },
    { label: t('acme_monitor.kpi_warning'),  value: data.warning,  color: '#f59e0b' },
    { label: t('acme_monitor.kpi_critical'), value: data.critical, color: '#ef4444' },
    { label: t('acme_monitor.kpi_expired'),  value: data.expired,  color: '#6b7280' },
  ];
  document.getElementById('acme-kpis').innerHTML = kpis.map(k => `
    <div style="background:var(--bg2);border-radius:10px;padding:16px 22px;min-width:110px;flex:1;">
      <div style="font-size:26px;font-weight:700;color:${k.color};">${k.value}</div>
      <div style="font-size:12px;opacity:0.6;margin-top:2px;">${k.label}</div>
    </div>`).join('');

  if (!data.certs.length) {
    document.getElementById('acme-table-wrap').innerHTML =
      `<p style="opacity:0.5;text-align:center;padding:40px 0;">${t('acme_monitor.no_certs')}</p>`;
    return;
  }

  const rows = data.certs.map(c => {
    const badge = statusBadge(c.status, c.days_left);
    const exp = new Date(c.expires_at).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
    const upd = new Date(c.updated_at).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
    const provLabel = PROVIDER_LABELS[c.dns_provider] || c.dns_provider || '—';
    const provColor = PROVIDER_COLORS[c.dns_provider];
    const provBadge = provColor
      ? `<span style="background:${provColor}22;color:${provColor};border:1px solid ${provColor}44;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:600;">${provLabel}</span>`
      : `<span style="font-size:11px;opacity:0.5;">${provLabel}</span>`;
    return `<tr style="cursor:pointer;" onclick="openAcmeCertDetail(${JSON.stringify(c).replace(/</g,'\\u003c').replace(/>/g,'\\u003e')})">
      <td style="font-weight:500;padding:10px 10px;">${esc(c.domain)}</td>
      <td style="padding:10px 10px;"><span style="font-size:11px;opacity:0.65;">${esc(c.issuer)}</span></td>
      <td style="padding:10px 10px;">${provBadge}</td>
      <td style="padding:10px 10px;">${exp}</td>
      <td style="padding:10px 10px;">${upd}</td>
      <td style="text-align:center;padding:10px 10px;">${badge}</td>
      <td style="text-align:right;padding:10px 10px;" onclick="event.stopPropagation()">
        <button class="btn btn-ghost" title="${t('acme_monitor.deploy')}" style="padding:4px 6px;"
          onclick="openCertDeployPanel('${esc(c.id)}','${esc(c.domain)}')">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
        </button>
        <button class="btn btn-ghost" title="${t('acme_monitor.edit')}" style="padding:4px 6px;${c.domain_id ? '' : 'opacity:0.35;cursor:not-allowed;'}"
          ${c.domain_id ? `onclick="openDomainModal('${esc(c.domain_id)}')"` : `onclick="toast(t('acme_monitor.edit_no_domain'),'info')"`}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
        </button>
        <button class="btn btn-ghost" title="${t('acme_monitor.renew')}" style="padding:4px 6px;"
          onclick="acmeRenew('${esc(c.domain)}')">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
        </button>
        <button class="btn btn-ghost" title="${t('acme_monitor.delete')}" style="padding:4px 6px;color:var(--red);"
          onclick="acmeDeleteCert('${esc(c.domain)}')">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
        </button>
      </td>
    </tr>`;
  }).join('');

  document.getElementById('acme-table-wrap').innerHTML = `
    <div style="overflow-x:auto;">
      <table style="width:100%;border-collapse:collapse;font-size:13px;">
        <thead>
          <tr style="border-bottom:1px solid var(--border);opacity:0.6;font-size:11px;text-transform:uppercase;letter-spacing:0.06em;">
            <th style="text-align:left;padding:8px 10px;">${t('acme_monitor.col_domain')}</th>
            <th style="text-align:left;padding:8px 10px;">${t('acme_monitor.col_issuer')}</th>
            <th style="text-align:left;padding:8px 10px;">${t('acme_monitor.col_provider')}</th>
            <th style="text-align:left;padding:8px 10px;">${t('acme_monitor.col_expires')}</th>
            <th style="text-align:left;padding:8px 10px;">${t('acme_monitor.col_renewed')}</th>
            <th style="text-align:center;padding:8px 10px;">${t('acme_monitor.col_status')}</th>
            <th></th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
};

// ── Detail panel ──────────────────────────────────────────────────────────────

window.openAcmeCertDetail = function (cert) {
  document.getElementById('acme-cert-detail-backdrop')?.remove();
  const provLabel = PROVIDER_LABELS[cert.dns_provider] || cert.dns_provider || '—';
  const provColor = PROVIDER_COLORS[cert.dns_provider];
  const exp = new Date(cert.expires_at).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });

  document.body.insertAdjacentHTML('beforeend', `
    <div id="acme-cert-detail-backdrop" class="dialog-backdrop" style="align-items:flex-start;justify-content:flex-end;background:rgba(0,0,0,0.4);" onclick="if(event.target===this)document.getElementById('acme-cert-detail-backdrop').remove()">
      <div style="width:min(400px,98vw);height:100vh;overflow:auto;background:var(--bg2);border-left:1px solid var(--border);padding:24px 20px;" onclick="event.stopPropagation()">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;">
          <div>
            <h2 style="margin:0 0 4px;font-size:17px;font-weight:700;">${esc(cert.domain)}</h2>
            <p style="margin:0;font-size:12px;opacity:0.5;">${t('acme_monitor.detail_title')}</p>
          </div>
          <button class="btn btn-ghost btn-icon" onclick="document.getElementById('acme-cert-detail-backdrop').remove()">✕</button>
        </div>
        <div style="display:flex;flex-direction:column;gap:10px;font-size:13px;">
          ${[
            [t('acme_monitor.col_status'),   statusBadge(cert.status, cert.days_left)],
            [t('acme_monitor.col_issuer'),   esc(cert.issuer)],
            [t('acme_monitor.col_expires'),  exp],
            [t('acme_monitor.detail_provider'), provColor
              ? `<span style="background:${provColor}22;color:${provColor};border:1px solid ${provColor}44;padding:2px 9px;border-radius:4px;font-size:11px;font-weight:600;">${provLabel}</span>`
              : provLabel],
          ].map(([k,v]) => `
            <div style="display:flex;justify-content:space-between;align-items:center;padding:10px 12px;background:var(--bg2);border-radius:8px;">
              <span style="opacity:0.6;">${k}</span><span>${v}</span>
            </div>`).join('')}
        </div>
        <div style="margin-top:24px;display:flex;flex-direction:column;gap:8px;">
          <button class="btn btn-primary blueprint" style="width:100%;" onclick="openCertDeployPanel('${esc(cert.id)}','${esc(cert.domain)}')">
            <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
            ${t('acme_monitor.deploy')}
          </button>
          ${cert.domain_id ? `
          <button class="btn btn-ghost" style="width:100%;font-size:12px;" onclick="document.getElementById('acme-cert-detail-backdrop').remove();openDomainModal('${esc(cert.domain_id)}')">
            ${t('acme_monitor.edit')}
          </button>` : ''}
          <button class="btn btn-ghost" style="width:100%;font-size:12px;opacity:0.7;" onclick="acmeRenew('${esc(cert.domain)}')">
            ${t('acme_monitor.renew')}
          </button>
          <button class="btn btn-ghost" style="width:100%;font-size:12px;color:var(--red);" onclick="acmeDeleteCert('${esc(cert.domain)}');document.getElementById('acme-cert-detail-backdrop').remove()">
            ${t('acme_monitor.delete')}
          </button>
        </div>
      </div>
    </div>`);
};

// ── Actions ───────────────────────────────────────────────────────────────────

function statusBadge(status, daysLeft) {
  const styles = {
    ok:       'background:#dcfce7;color:#166534;',
    warning:  'background:#fef3c7;color:#92400e;',
    critical: 'background:#fee2e2;color:#991b1b;',
    expired:  'background:#f3f4f6;color:#374151;',
  };
  const labels = {
    ok:       `OK — ${daysLeft}j`,
    warning:  `${daysLeft}j restants`,
    critical: `${daysLeft}j restants`,
    expired:  'Expiré',
  };
  const s = styles[status] || styles.ok;
  const l = labels[status] || status;
  return `<span style="font-size:11px;padding:2px 8px;border-radius:4px;${s}">${l}</span>`;
}

window.acmeRenew = async function (domain) {
  try {
    await api('POST', '/certs', { domain });
    toast(t('acme_monitor.renew_started').replace('{domain}', domain), 'success');
  } catch (e) {
    toast(e.message || t('common.error'), 'error');
  }
};

window.acmeDeleteCert = async function (domain) {
  if (!confirm(t('acme_monitor.delete_confirm').replace('{domain}', domain))) return;
  try {
    await api('DELETE', `/certs/${domain}`);
    toast(t('acme_monitor.deleted'), 'success');
    acmeMonitorLoad();
  } catch (e) {
    toast(e.message || t('common.error'), 'error');
  }
};

window.openImportCertModal = function () {
  document.getElementById('acme-import-modal-backdrop')?.remove();
  document.body.insertAdjacentHTML('beforeend', `
    <div id="acme-import-modal-backdrop" class="dialog-backdrop" style="background:rgba(0,0,0,0.55);">
      <div class="dialog blueprint" role="dialog" aria-modal="true" style="width:min(520px,96vw);max-width:none;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div class="dialog-title">${t('acme_monitor.import_title')}</div>
        <div class="dialog-body" style="display:flex;flex-direction:column;gap:14px;">
          <p style="margin:0;font-size:13px;opacity:0.65;">${t('acme_monitor.import_hint')}</p>
          <div class="field">
            <label>${t('acme_monitor.import_cert_label')}</label>
            <textarea class="input" id="imp-cert" rows="8" placeholder="-----BEGIN CERTIFICATE-----\n..." style="font-family:monospace;font-size:11px;resize:vertical;"></textarea>
          </div>
          <div class="field">
            <label>${t('acme_monitor.import_key_label')}</label>
            <textarea class="input" id="imp-key" rows="6" placeholder="-----BEGIN PRIVATE KEY-----\n..." style="font-family:monospace;font-size:11px;resize:vertical;"></textarea>
          </div>
          <div class="field">
            <label>${t('acme_monitor.import_issuer_label')} <span style="opacity:0.5;font-size:11px;">${t('common.optional')}</span></label>
            <input class="input" id="imp-issuer" placeholder="custom">
          </div>
        </div>
        <div class="dialog-footer">
          <button class="btn btn-secondary" onclick="document.getElementById('acme-import-modal-backdrop').remove()">${t('common.cancel')}</button>
          <button class="btn btn-primary blueprint" onclick="submitImportCert()">
            <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
            ${t('acme_monitor.import_submit')}
          </button>
        </div>
      </div>
    </div>`);
};

window.submitImportCert = async function () {
  const certPEM = document.getElementById('imp-cert')?.value.trim() || '';
  const keyPEM  = document.getElementById('imp-key')?.value.trim() || '';
  const issuer  = document.getElementById('imp-issuer')?.value.trim() || '';
  if (!certPEM || !keyPEM) { toast(t('acme_monitor.import_missing'), 'error'); return; }
  try {
    const res = await api('POST', '/certs/import', { cert_pem: certPEM, key_pem: keyPEM, issuer });
    document.getElementById('acme-import-modal-backdrop')?.remove();
    toast(t('acme_monitor.import_ok').replace('{domain}', res.domain), 'success');
    await acmeMonitorLoad();
  } catch (e) {
    toast(e.message || t('common.error'), 'error');
  }
};
