// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

let _acmeRefreshTimer = null;

pages['acme-monitor'] = async function () {
  if (_acmeRefreshTimer) { clearInterval(_acmeRefreshTimer); _acmeRefreshTimer = null; }
  const root = document.getElementById('content');
  root.innerHTML = `
    <div style="padding:24px 28px;">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;">
        <div>
          <h2 style="margin:0;font-size:20px;">${t('acme_monitor.title')}</h2>
          <p style="margin:4px 0 0;font-size:13px;opacity:0.55;">${t('acme_monitor.subtitle')}</p>
        </div>
        <div style="display:flex;gap:8px;">
          <button class="btn btn-primary" style="font-size:12px;" onclick="openImportCertModal()">${t('acme_monitor.import_btn')}</button>
          <button class="btn btn-ghost" style="font-size:12px;" onclick="acmeMonitorLoad()">↻ ${t('common.refresh')}</button>
        </div>
      </div>
      <div id="acme-kpis" style="display:flex;gap:14px;flex-wrap:wrap;margin-bottom:24px;"></div>
      <div id="acme-table-wrap"></div>
    </div>`;
  await acmeMonitorLoad();
  _acmeRefreshTimer = setInterval(acmeMonitorLoad, 60_000);
  // Nettoie le timer si on navigue vers une autre page
  const obs = new MutationObserver(() => {
    if (!document.getElementById('acme-kpis')) {
      clearInterval(_acmeRefreshTimer);
      _acmeRefreshTimer = null;
      obs.disconnect();
    }
  });
  obs.observe(document.getElementById('content'), { childList: true });
};

window.acmeMonitorLoad = async function () {
  const data = await api('GET', '/certs/acme-monitor').catch(() => null);
  if (!data) {
    document.getElementById('acme-table-wrap').innerHTML =
      `<p style="opacity:0.5;text-align:center;padding:40px 0;">${t('acme_monitor.load_error')}</p>`;
    return;
  }

  // KPI tiles
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

  // Table
  if (!data.certs.length) {
    document.getElementById('acme-table-wrap').innerHTML =
      `<p style="opacity:0.5;text-align:center;padding:40px 0;">${t('acme_monitor.no_certs')}</p>`;
    return;
  }

  const rows = data.certs.map(c => {
    const badge = statusBadge(c.status, c.days_left);
    const exp = new Date(c.expires_at).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
    const upd = new Date(c.updated_at).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
    return `<tr>
      <td style="font-weight:500;">${esc(c.domain)}</td>
      <td><span style="font-size:11px;opacity:0.65;">${esc(c.issuer)}</span></td>
      <td>${exp}</td>
      <td>${upd}</td>
      <td style="text-align:center;">${badge}</td>
      <td style="text-align:right;">
        <button class="btn btn-ghost" style="font-size:11px;padding:4px 8px;"
          onclick="acmeRenew('${esc(c.domain)}')">${t('acme_monitor.renew')}</button>
      </td>
    </tr>`;
  }).join('');

  document.getElementById('acme-table-wrap').innerHTML = `
    <div style="overflow-x:auto;">
      <table style="width:100%;border-collapse:collapse;font-size:13px;">
        <thead>
          <tr style="border-bottom:1px solid var(--border);opacity:0.6;">
            <th style="text-align:left;padding:8px 10px;">${t('acme_monitor.col_domain')}</th>
            <th style="text-align:left;padding:8px 10px;">${t('acme_monitor.col_issuer')}</th>
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
    showToast(t('acme_monitor.renew_started').replace('{domain}', domain), 'success');
  } catch (e) {
    showToast(e.message || t('common.error'), 'error');
  }
};

window.openImportCertModal = function () {
  modal(
    t('acme_monitor.import_title'),
    `<div style="display:flex;flex-direction:column;gap:14px;">
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
    </div>`,
    `<button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel')}</button>
     <button class="btn btn-primary" onclick="submitImportCert()">${t('acme_monitor.import_submit')}</button>`,
    false
  );
};

window.submitImportCert = async function () {
  const certPEM = document.getElementById('imp-cert')?.value.trim() || '';
  const keyPEM  = document.getElementById('imp-key')?.value.trim() || '';
  const issuer  = document.getElementById('imp-issuer')?.value.trim() || '';
  if (!certPEM || !keyPEM) {
    showToast(t('acme_monitor.import_missing'), 'error');
    return;
  }
  try {
    const res = await api('POST', '/certs/import', { cert_pem: certPEM, key_pem: keyPEM, issuer });
    closeModal();
    showToast(t('acme_monitor.import_ok').replace('{domain}', res.domain), 'success');
    await acmeMonitorLoad();
  } catch (e) {
    showToast(e.message || t('common.error'), 'error');
  }
};
