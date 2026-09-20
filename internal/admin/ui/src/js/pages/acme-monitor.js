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
          <button class="btn btn-primary" style="font-size:12px;" onclick="openImportCertModal()">${t('acme_monitor.import_btn')}</button>
          <button class="btn btn-ghost" style="font-size:12px;" onclick="acmeMonitorLoad()">↻ ${t('common.refresh')}</button>
        </div>
      </div>
      <div id="acme-config-section" style="margin-bottom:24px;"></div>
      <div id="acme-providers-section" style="margin-bottom:24px;"></div>
      <div id="acme-kpis" style="display:flex;gap:14px;flex-wrap:wrap;margin-bottom:24px;"></div>
      <div id="acme-table-wrap"></div>
    </div>`;
  await Promise.all([acmeConfigLoad(), acmeProvidersLoad(), acmeMonitorLoad()]);
  _acmeRefreshTimer = setInterval(acmeMonitorLoad, 60_000);
  const obs = new MutationObserver(() => {
    if (!document.getElementById('acme-kpis')) {
      clearInterval(_acmeRefreshTimer);
      _acmeRefreshTimer = null;
      obs.disconnect();
    }
  });
  obs.observe(document.getElementById('content'), { childList: true });
};

// ── ACME config section ──────────────────────────────────────────────────────

window.acmeConfigLoad = async function () {
  const el = document.getElementById('acme-config-section');
  if (!el) return;
  const cfg = await api('GET', '/settings/acme').catch(() => null);
  if (!cfg) { el.innerHTML = ''; return; }
  const pLabel = PROVIDER_LABELS[cfg.dns_type] || cfg.dns_type || t('acme_monitor.config_not_set');
  const pColor = PROVIDER_COLORS[cfg.dns_type];
  el.innerHTML = `
    <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:16px 20px;display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;">
      <div style="display:flex;align-items:center;gap:20px;flex-wrap:wrap;">
        <div style="display:flex;align-items:center;gap:6px;">
          <span style="width:8px;height:8px;border-radius:50%;background:${cfg.enabled ? '#22c55e' : '#6b7280'};flex-shrink:0;"></span>
          <span style="font-size:13px;font-weight:600;">${t('acme_monitor.config_title')}</span>
        </div>
        <div style="font-size:12px;opacity:0.65;">${t('acme_monitor.config_email')} : <strong>${cfg.email || '—'}</strong></div>
        <div style="font-size:12px;opacity:0.65;">${t('acme_monitor.config_provider')} :
          ${pColor ? `<span style="background:${pColor}22;color:${pColor};border:1px solid ${pColor}44;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;">${pLabel}</span>` : `<strong>${pLabel}</strong>`}
        </div>
        ${cfg.directory_url ? `<div style="font-size:11px;opacity:0.4;font-family:monospace;">${esc(cfg.directory_url)}</div>` : ''}
      </div>
      <button class="btn btn-ghost" style="font-size:12px;" onclick="openAcmeConfigModal()">${t('acme_monitor.config_edit')}</button>
    </div>`;
};

window.openAcmeConfigModal = async function () {
  const cfg = await api('GET', '/settings/acme').catch(() => ({}));
  document.getElementById('acme-config-modal-backdrop')?.remove();
  document.body.insertAdjacentHTML('beforeend', `
    <div id="acme-config-modal-backdrop" class="dialog-backdrop" style="background:rgba(0,0,0,0.55);">
      <div class="dialog blueprint" role="dialog" aria-modal="true" style="width:min(520px,96vw);max-width:none;">
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
            <label>${t('acme_monitor.config_provider')}</label>
            <select class="input" id="acme-cfg-dns-type" onchange="acmeCfgProviderChange()">
              <option value="" ${!cfg.dns_type?'selected':''}>— ${t('acme_monitor.provider_none')} —</option>
              <option value="cloudflare" ${cfg.dns_type==='cloudflare'?'selected':''}>Cloudflare</option>
              <option value="ovh" ${cfg.dns_type==='ovh'?'selected':''}>OVH</option>
              <option value="gandi" ${cfg.dns_type==='gandi'?'selected':''}>Gandi</option>
              <option value="hetzner" ${cfg.dns_type==='hetzner'?'selected':''}>Hetzner DNS</option>
              <option value="route53" ${cfg.dns_type==='route53'?'selected':''}>AWS Route 53</option>
            </select>
          </div>
          <div class="field">
            <label>${t('acme_monitor.config_dir')} <span style="opacity:0.5;font-size:11px;">(${t('common.optional')})</span></label>
            <input class="input" id="acme-cfg-dir" placeholder="https://acme-v02.api.letsencrypt.org/directory" value="${esc(cfg.directory_url||'')}">
            <p style="margin:4px 0 0;font-size:11px;opacity:0.45;">Laisser vide pour Let's Encrypt production.</p>
          </div>
        </div>
        <div class="dialog-footer">
          <button class="btn btn-secondary" onclick="document.getElementById('acme-config-modal-backdrop').remove()">${t('common.cancel')}</button>
          <button class="btn btn-primary blueprint" onclick="saveAcmeConfig()"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>${t('acme_monitor.config_save')}</button>
        </div>
      </div>
    </div>`);
};

window.acmeCfgProviderChange = function () {
  // Placeholder : pourrait afficher des champs de credentials inline
};

window.saveAcmeConfig = async function () {
  const enabled = document.getElementById('acme-cfg-enabled')?.checked || false;
  const email = document.getElementById('acme-cfg-email')?.value?.trim() || '';
  const dns_type = document.getElementById('acme-cfg-dns-type')?.value || '';
  const directory_url = document.getElementById('acme-cfg-dir')?.value?.trim() || '';
  try {
    await api('PUT', '/settings/acme', { enabled, email, dns_type, directory_url });
    document.getElementById('acme-config-modal-backdrop')?.remove();
    toast(t('acme_monitor.config_saved'), 'success');
    acmeConfigLoad();
  } catch (e) {
    toast(e.message || t('common.error'), 'error');
  }
};

// ── Providers section ────────────────────────────────────────────────────────

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
      <td style="padding:8px 10px;font-weight:500;">${esc(p.name)}</td>
      <td style="padding:8px 10px;">${badge}</td>
      <td style="text-align:right;padding:8px 10px;">
        <button class="btn btn-ghost" style="font-size:11px;padding:4px 8px;"
          onclick="openAcmeProviderModal(${JSON.stringify(p).replace(/</g,'\\u003c').replace(/>/g,'\\u003e')})">${t('acme_monitor.providers_edit')}</button>
        <button class="btn btn-ghost" style="font-size:11px;padding:4px 8px;color:var(--red);"
          onclick="deleteAcmeProvider('${esc(p.id)}','${esc(p.name)}')">${t('acme_monitor.providers_delete')}</button>
      </td>
    </tr>`;
  }).join('');

  el.innerHTML = `
    <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:16px 20px;">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;flex-wrap:wrap;gap:8px;">
        <div>
          <div style="font-size:13px;font-weight:600;">${t('acme_monitor.providers_title')}</div>
          <div style="font-size:11px;opacity:0.55;margin-top:2px;">${t('acme_monitor.providers_subtitle')}</div>
        </div>
        <button class="btn btn-ghost" style="font-size:12px;" onclick="openAcmeProviderModal(null)">${t('acme_monitor.providers_add')}</button>
      </div>
      ${providers.length === 0
        ? `<p style="margin:0;font-size:12px;opacity:0.5;text-align:center;padding:12px 0;">${t('acme_monitor.providers_empty')}</p>`
        : `<table style="width:100%;border-collapse:collapse;font-size:13px;">
            <thead>
              <tr style="border-bottom:1px solid var(--border);opacity:0.6;font-size:11px;text-transform:uppercase;letter-spacing:0.06em;">
                <th style="text-align:left;padding:6px 10px;">${t('acme_monitor.providers_col_name')}</th>
                <th style="text-align:left;padding:6px 10px;">${t('acme_monitor.providers_col_type')}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>${rows}</tbody>
          </table>`
      }
    </div>`;
};

window.openAcmeProviderModal = function (provider) {
  const isEdit = !!provider;
  const paramsStr = provider?.params ? JSON.stringify(provider.params, null, 2) : '{}';
  document.getElementById('acme-provider-modal-backdrop')?.remove();
  document.body.insertAdjacentHTML('beforeend', `
    <div id="acme-provider-modal-backdrop" class="dialog-backdrop" style="background:rgba(0,0,0,0.55);">
      <div class="dialog blueprint" role="dialog" aria-modal="true" style="width:min(520px,96vw);max-width:none;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div class="dialog-title">${isEdit ? t('acme_monitor.providers_modal_edit') : t('acme_monitor.providers_modal_create')}</div>
        <div class="dialog-body" style="display:flex;flex-direction:column;gap:14px;">
          <div class="field">
            <label>${t('acme_monitor.providers_name')}</label>
            <input class="input" id="prov-name" placeholder="${t('acme_monitor.providers_name_ph')}" value="${esc(provider?.name||'')}">
          </div>
          <div class="field">
            <label>${t('acme_monitor.providers_type')}</label>
            <select class="input" id="prov-type">
              <option value="cloudflare" ${provider?.type==='cloudflare'?'selected':''}>Cloudflare</option>
              <option value="ovh"        ${provider?.type==='ovh'?'selected':''}>OVH</option>
              <option value="gandi"      ${provider?.type==='gandi'?'selected':''}>Gandi</option>
              <option value="hetzner"    ${provider?.type==='hetzner'?'selected':''}>Hetzner DNS</option>
              <option value="route53"    ${provider?.type==='route53'?'selected':''}>AWS Route 53</option>
            </select>
          </div>
          <div class="field">
            <label>${t('acme_monitor.providers_credentials')}</label>
            <textarea class="input" id="prov-params" rows="6" style="font-family:monospace;font-size:11px;resize:vertical;"
              placeholder="${esc(t('acme_monitor.providers_credentials_ph'))}">${esc(paramsStr)}</textarea>
            <p style="margin:4px 0 0;font-size:11px;opacity:0.45;">${t('acme_monitor.providers_credentials_hint')}</p>
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

window.saveAcmeProvider = async function (id) {
  const name = document.getElementById('prov-name')?.value?.trim() || '';
  const type = document.getElementById('prov-type')?.value || '';
  const paramsRaw = document.getElementById('prov-params')?.value?.trim() || '{}';
  let params;
  try { params = JSON.parse(paramsRaw); } catch {
    toast('Invalid JSON in credentials.', 'error');
    return;
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

// ── Monitor table ────────────────────────────────────────────────────────────

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
    const methodBadge = c.cert_method
      ? `<span style="font-size:10px;opacity:0.55;padding:1px 5px;border:1px solid var(--border);border-radius:3px;">${esc(c.cert_method)}</span>`
      : '';
    return `<tr style="cursor:pointer;" onclick="openAcmeCertDetail(${JSON.stringify(c).replace(/</g,'\\u003c').replace(/>/g,'\\u003e')})">
      <td style="font-weight:500;padding:10px 10px;">${esc(c.domain)}</td>
      <td style="padding:10px 10px;"><span style="font-size:11px;opacity:0.65;">${esc(c.issuer)}</span></td>
      <td style="padding:10px 10px;">${provBadge} ${methodBadge}</td>
      <td style="padding:10px 10px;">${exp}</td>
      <td style="padding:10px 10px;">${upd}</td>
      <td style="text-align:center;padding:10px 10px;">${badge}</td>
      <td style="text-align:right;padding:10px 10px;" onclick="event.stopPropagation()">
        <button class="btn btn-ghost" style="font-size:11px;padding:4px 8px;"
          onclick="acmeRenew('${esc(c.domain)}')">${t('acme_monitor.renew')}</button>
        <button class="btn btn-ghost" style="font-size:11px;padding:4px 8px;color:var(--red);"
          onclick="acmeDeleteCert('${esc(c.domain)}')">${t('acme_monitor.delete')}</button>
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

// ── Detail panel ─────────────────────────────────────────────────────────────

window.openAcmeCertDetail = function (cert) {
  document.getElementById('acme-cert-detail-backdrop')?.remove();
  const provLabel = PROVIDER_LABELS[cert.dns_provider] || cert.dns_provider || '—';
  const provColor = PROVIDER_COLORS[cert.dns_provider];
  const exp = new Date(cert.expires_at).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  const hasDomain = !!(cert.dns_provider || cert.cert_method);

  document.body.insertAdjacentHTML('beforeend', `
    <div id="acme-cert-detail-backdrop" class="dialog-backdrop" style="align-items:flex-start;justify-content:flex-end;background:rgba(0,0,0,0.4);" onclick="if(event.target===this)document.getElementById('acme-cert-detail-backdrop').remove()">
      <div style="width:min(440px,98vw);height:100vh;overflow:auto;background:var(--card-bg);border-left:1px solid var(--border);padding:24px 20px;" onclick="event.stopPropagation()">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;">
          <div>
            <h2 style="margin:0 0 4px;font-size:18px;font-weight:700;">${esc(cert.domain)}</h2>
            <p style="margin:0;font-size:12px;opacity:0.5;">${t('acme_monitor.detail_title')}</p>
          </div>
          <button class="btn btn-ghost btn-icon" onclick="document.getElementById('acme-cert-detail-backdrop').remove()">
            <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </button>
        </div>

        <div style="display:flex;flex-direction:column;gap:12px;font-size:13px;">
          <div style="display:flex;justify-content:space-between;padding:10px 12px;background:var(--bg2);border-radius:8px;">
            <span style="opacity:0.6;">${t('acme_monitor.col_status')}</span>
            <span>${statusBadge(cert.status, cert.days_left)}</span>
          </div>
          <div style="display:flex;justify-content:space-between;padding:10px 12px;background:var(--bg2);border-radius:8px;">
            <span style="opacity:0.6;">${t('acme_monitor.col_issuer')}</span>
            <span>${esc(cert.issuer)}</span>
          </div>
          <div style="display:flex;justify-content:space-between;padding:10px 12px;background:var(--bg2);border-radius:8px;">
            <span style="opacity:0.6;">${t('acme_monitor.col_expires')}</span>
            <span>${exp}</span>
          </div>
          <div style="display:flex;justify-content:space-between;align-items:center;padding:10px 12px;background:var(--bg2);border-radius:8px;">
            <span style="opacity:0.6;">${t('acme_monitor.detail_provider')}</span>
            <span>${provColor
              ? `<span style="background:${provColor}22;color:${provColor};border:1px solid ${provColor}44;padding:2px 9px;border-radius:4px;font-size:11px;font-weight:600;">${provLabel}</span>`
              : provLabel
            }</span>
          </div>
          ${cert.cert_method ? `
          <div style="display:flex;justify-content:space-between;padding:10px 12px;background:var(--bg2);border-radius:8px;">
            <span style="opacity:0.6;">${t('acme_monitor.detail_method')}</span>
            <span style="font-size:12px;padding:1px 7px;border:1px solid var(--border);border-radius:4px;">${esc(cert.cert_method)}</span>
          </div>` : ''}
        </div>

        ${!hasDomain ? `
        <div style="margin-top:20px;padding:12px;border:1px dashed var(--border);border-radius:8px;font-size:12px;opacity:0.6;text-align:center;">
          ${t('acme_monitor.detail_no_domain')}
        </div>` : ''}

        <div style="margin-top:24px;display:flex;flex-direction:column;gap:8px;">
          <button class="btn btn-primary blueprint" style="width:100%;" onclick="acmeRenew('${esc(cert.domain)}')">
            <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
            ${t('acme_monitor.renew')}
          </button>
          <button class="btn btn-ghost" style="width:100%;font-size:12px;opacity:0.7;" onclick="navigate('domains')">
            ${t('acme_monitor.detail_go_domain')} →
          </button>
          <button class="btn btn-ghost" style="width:100%;font-size:12px;color:var(--red);" onclick="acmeDeleteCert('${esc(cert.domain)}');document.getElementById('acme-cert-detail-backdrop').remove()">
            ${t('acme_monitor.delete')}
          </button>
        </div>
      </div>
    </div>`);
};

// ── Actions ──────────────────────────────────────────────────────────────────

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
            <input class="input" id="imp-issuer" placeholder="custom" style="font-size:13px;">
          </div>
        </div>
        <div class="dialog-footer">
          <button class="btn btn-secondary" onclick="document.getElementById('acme-import-modal-backdrop').remove()">${t('common.cancel')}</button>
          <button class="btn btn-primary blueprint" onclick="submitImportCert()"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>${t('acme_monitor.import_submit')}</button>
        </div>
      </div>
    </div>`);
};

window.submitImportCert = async function () {
  const certPEM = document.getElementById('imp-cert')?.value.trim() || '';
  const keyPEM  = document.getElementById('imp-key')?.value.trim() || '';
  const issuer  = document.getElementById('imp-issuer')?.value.trim() || '';
  if (!certPEM || !keyPEM) {
    toast(t('acme_monitor.import_missing'), 'error');
    return;
  }
  try {
    const res = await api('POST', '/certs/import', { cert_pem: certPEM, key_pem: keyPEM, issuer });
    document.getElementById('acme-import-modal-backdrop')?.remove();
    toast(t('acme_monitor.import_ok').replace('{domain}', res.domain), 'success');
    await acmeMonitorLoad();
  } catch (e) {
    toast(e.message || t('common.error'), 'error');
  }
};
