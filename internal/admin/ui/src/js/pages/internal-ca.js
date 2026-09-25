// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Section CA interne — fusionnée dans "Domaines & certificats" (acme-monitor.js).
// Génère et gère une autorité de certification interne (hors ACME) pour émettre
// des certificats serveur/client internes.

window.acmeInternalCALoad = async function () {
  const el = document.getElementById('acme-internal-ca-section');
  if (!el) return;
  const cas = await api('GET', '/internal-ca').catch(() => null);
  if (!cas) { el.innerHTML = ''; return; }

  const rows = cas.map(ca => `
    <tr style="cursor:pointer;" onclick="openInternalCACertsPanel('${esc(ca.id)}','${esc(ca.name)}')">
      <td style="padding:6px 8px;font-size:12px;font-weight:500;">${esc(ca.name)}</td>
      <td style="padding:6px 8px;font-size:11px;opacity:0.7;">${esc(ca.subject)}</td>
      <td style="padding:6px 8px;font-size:11px;opacity:0.6;white-space:nowrap;">${fmtDate(ca.not_after)}</td>
      <td style="text-align:right;padding:6px 8px;white-space:nowrap;">
        <button class="btn btn-ghost" style="padding:4px 6px;font-size:11px;" onclick="event.stopPropagation();openInternalCACertsPanel('${esc(ca.id)}','${esc(ca.name)}')">${t('internal_ca.manage')}</button>
      </td>
    </tr>`).join('');

  el.innerHTML = `
    <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:16px 20px;box-sizing:border-box;">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">
        <div>
          <span style="font-size:13px;font-weight:600;">${t('internal_ca.title')}</span>
          <p style="margin:2px 0 0;font-size:11px;opacity:0.5;">${t('internal_ca.subtitle')}</p>
        </div>
        <button class="btn btn-ghost" style="font-size:11px;" onclick="openInternalCAModal()">${t('internal_ca.create_btn')}</button>
      </div>
      ${!cas.length
        ? `<p style="margin:0;font-size:12px;opacity:0.5;text-align:center;padding:16px 0;">${t('internal_ca.empty')}</p>`
        : `<table style="width:100%;border-collapse:collapse;">
            <thead>
              <tr style="text-align:left;">
                <th style="padding:4px 8px;font-size:10px;opacity:0.5;font-weight:500;">${t('internal_ca.col_name')}</th>
                <th style="padding:4px 8px;font-size:10px;opacity:0.5;font-weight:500;">${t('internal_ca.col_subject')}</th>
                <th style="padding:4px 8px;font-size:10px;opacity:0.5;font-weight:500;">${t('internal_ca.col_expiry')}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>${rows}</tbody>
          </table>`
      }
    </div>`;
};

function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d)) return '—';
  return d.toLocaleDateString();
}

// ── Création d'une CA racine ───────────────────────────────────────────────

window.openInternalCAModal = function () {
  document.getElementById('internal-ca-modal-backdrop')?.remove();
  document.body.insertAdjacentHTML('beforeend', `
    <div id="internal-ca-modal-backdrop" class="dialog-backdrop" style="background:rgba(0,0,0,0.55);">
      <div class="dialog blueprint" role="dialog" aria-modal="true" style="width:min(460px,96vw);max-width:none;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div class="dialog-title">${t('internal_ca.modal_create_title')}</div>
        <div class="dialog-body" style="display:flex;flex-direction:column;gap:14px;">
          <div class="field">
            <label>${t('internal_ca.name')}</label>
            <input class="input" id="ica-name" placeholder="root">
          </div>
          <div class="field">
            <label>${t('internal_ca.common_name')}</label>
            <input class="input" id="ica-cn" placeholder="GoProxify Internal Root">
          </div>
          <div class="field">
            <label>${t('internal_ca.validity_years')}</label>
            <input class="input" id="ica-years" type="number" min="1" max="30" value="10">
          </div>
        </div>
        <div class="dialog-footer">
          <button class="btn btn-secondary" onclick="document.getElementById('internal-ca-modal-backdrop').remove()">${t('common.cancel')}</button>
          <button class="btn btn-primary blueprint" onclick="submitInternalCA()">
            <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
            ${t('internal_ca.modal_create_submit')}
          </button>
        </div>
      </div>
    </div>`);
};

window.submitInternalCA = async function () {
  const name = document.getElementById('ica-name')?.value?.trim() || '';
  const common_name = document.getElementById('ica-cn')?.value?.trim() || '';
  const validity_years = parseInt(document.getElementById('ica-years')?.value, 10) || 10;
  if (!name || !common_name) { toast(t('internal_ca.err_required'), 'error'); return; }
  try {
    await api('POST', '/internal-ca', { name, common_name, validity_years });
    document.getElementById('internal-ca-modal-backdrop')?.remove();
    toast(t('internal_ca.created'), 'success');
    acmeInternalCALoad();
  } catch (e) {
    toast(e.message || t('common.error'), 'error');
  }
};

// ── Drawer certificats émis par une CA ──────────────────────────────────────

window.openInternalCACertsPanel = async function (caId, caName) {
  document.getElementById('internal-ca-panel-overlay')?.remove();

  const overlay = document.createElement('div');
  overlay.id = 'internal-ca-panel-overlay';
  overlay.className = 'dialog-backdrop';
  overlay.style.cssText = 'align-items:flex-start;justify-content:flex-end;background:rgba(0,0,0,0.45);';
  overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };

  const drawer = document.createElement('div');
  drawer.style.cssText = 'background:var(--bg);border-left:1px solid var(--border);width:min(560px,100vw);height:100vh;overflow-y:auto;padding:24px;display:flex;flex-direction:column;gap:0;';
  drawer.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;">
      <div>
        <h2 style="margin:0 0 2px;font-size:18px;font-weight:600;">${esc(caName)}</h2>
        <p style="margin:0;font-size:12px;opacity:0.55;">${t('internal_ca.panel_subtitle')}</p>
      </div>
      <button class="btn btn-ghost btn-icon" onclick="document.getElementById('internal-ca-panel-overlay').remove()"><svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6 6 18M6 6l12 12"/></svg></button>
    </div>
    <div style="margin-bottom:16px;display:flex;justify-content:flex-end;">
      <button class="btn btn-primary" style="font-size:12px;" onclick="openIssueInternalCertModal('${esc(caId)}')">${t('internal_ca.issue_btn')}</button>
    </div>
    <div id="internal-ca-certs-list"></div>`;

  overlay.appendChild(drawer);
  document.body.appendChild(overlay);

  await icaLoadCerts(caId);
};

async function icaLoadCerts(caId) {
  const el = document.getElementById('internal-ca-certs-list');
  if (!el) return;
  el.innerHTML = `<p style="opacity:0.5;font-size:13px;">${t('common.loading')}</p>`;
  const certs = await api('GET', `/internal-ca/${caId}/certs`).catch(() => []);

  if (!(certs || []).length) {
    el.innerHTML = `<p style="opacity:0.5;font-size:13px;text-align:center;padding:32px 0;">${t('internal_ca.no_certs')}</p>`;
    return;
  }

  el.innerHTML = `<div style="display:flex;flex-direction:column;gap:10px;">
    ${certs.map(c => icaCertRow(c, caId)).join('')}
  </div>`;
}

function icaCertRow(c, caId) {
  const usageColor = c.usage === 'client' ? '#8b5cf6' : '#0ea5e9';
  const statusBadge = c.revoked
    ? `<span style="background:#ef444422;color:#ef4444;border:1px solid #ef444444;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:600;">${t('internal_ca.revoked')}</span>`
    : `<span style="background:#22c55e22;color:#22c55e;border:1px solid #22c55e44;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:600;">${t('internal_ca.active')}</span>`;
  return `
    <div style="border:1px solid var(--border);border-radius:8px;padding:12px 14px;">
      <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:6px;">
        <strong style="font-size:13px;">${esc(c.common_name)}</strong>
        <div style="display:flex;align-items:center;gap:6px;">
          <span style="background:${usageColor}22;color:${usageColor};border:1px solid ${usageColor}44;padding:2px 7px;border-radius:4px;font-size:10px;font-weight:600;">${esc(c.usage)}</span>
          ${statusBadge}
        </div>
      </div>
      <div style="font-size:11px;opacity:0.6;display:flex;flex-direction:column;gap:2px;">
        ${(c.sans||[]).length ? `<span>SAN: ${esc((c.sans||[]).join(', '))}</span>` : ''}
        <span>${t('internal_ca.col_expiry')}: ${fmtDate(c.not_after)}</span>
      </div>
      ${!c.revoked ? `
      <div style="margin-top:8px;text-align:right;">
        <button class="btn btn-ghost" style="font-size:11px;color:var(--red);" onclick="revokeInternalCert('${esc(caId)}','${esc(c.id)}')">${t('internal_ca.revoke')}</button>
      </div>` : ''}
    </div>`;
}

window.revokeInternalCert = async function (caId, certID) {
  if (!confirm(t('internal_ca.revoke_confirm'))) return;
  try {
    await api('DELETE', `/internal-ca/${caId}/certs/${certID}`);
    toast(t('internal_ca.revoked_toast'), 'success');
    icaLoadCerts(caId);
  } catch (e) {
    toast(e.message || t('common.error'), 'error');
  }
};

// ── Émission d'un certificat ─────────────────────────────────────────────────

window.openIssueInternalCertModal = function (caId) {
  document.getElementById('internal-ca-issue-backdrop')?.remove();
  document.body.insertAdjacentHTML('beforeend', `
    <div id="internal-ca-issue-backdrop" class="dialog-backdrop" style="background:rgba(0,0,0,0.55);">
      <div class="dialog blueprint" role="dialog" aria-modal="true" style="width:min(460px,96vw);max-width:none;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div class="dialog-title">${t('internal_ca.issue_title')}</div>
        <div class="dialog-body" style="display:flex;flex-direction:column;gap:14px;">
          <div class="field">
            <label>${t('internal_ca.cert_common_name')}</label>
            <input class="input" id="icc-cn" placeholder="svc.internal.local">
          </div>
          <div class="field">
            <label>${t('internal_ca.cert_sans')} <span style="opacity:0.5;font-size:11px;">(${t('common.optional')})</span></label>
            <input class="input" id="icc-sans" placeholder="svc.internal.local, 10.0.0.5">
          </div>
          <div class="field">
            <label>${t('internal_ca.cert_usage')}</label>
            <select class="input" id="icc-usage">
              <option value="server">${t('internal_ca.usage_server')}</option>
              <option value="client">${t('internal_ca.usage_client')}</option>
            </select>
          </div>
          <div class="field">
            <label>${t('internal_ca.cert_validity_days')}</label>
            <input class="input" id="icc-days" type="number" min="1" max="3650" value="397">
          </div>
        </div>
        <div class="dialog-footer">
          <button class="btn btn-secondary" onclick="document.getElementById('internal-ca-issue-backdrop').remove()">${t('common.cancel')}</button>
          <button class="btn btn-primary blueprint" onclick="submitIssueInternalCert('${esc(caId)}')">
            <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
            ${t('internal_ca.issue_submit')}
          </button>
        </div>
      </div>
    </div>`);
};

window.submitIssueInternalCert = async function (caId) {
  const common_name = document.getElementById('icc-cn')?.value?.trim() || '';
  const sansRaw = document.getElementById('icc-sans')?.value?.trim() || '';
  const usage = document.getElementById('icc-usage')?.value || 'server';
  const validity_days = parseInt(document.getElementById('icc-days')?.value, 10) || 397;
  if (!common_name) { toast(t('internal_ca.err_cn_required'), 'error'); return; }
  const sans = sansRaw ? sansRaw.split(',').map(s => s.trim()).filter(Boolean) : [];
  try {
    await api('POST', `/internal-ca/${caId}/certs`, { common_name, sans, usage, validity_days });
    document.getElementById('internal-ca-issue-backdrop')?.remove();
    toast(t('internal_ca.issued'), 'success');
    icaLoadCerts(caId);
  } catch (e) {
    toast(e.message || t('common.error'), 'error');
  }
};
