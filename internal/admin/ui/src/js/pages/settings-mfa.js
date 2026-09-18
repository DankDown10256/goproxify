// ── PAGE: Paramètres MFA (admin)

pages['settings-mfa'] = async function() {
  const content = document.getElementById('content');
  content.innerHTML = `<p style="color:var(--text2)">${t('common.loading')}</p>`;

  let [sms, webauthn] = [{}, {}];
  try {
    [sms, webauthn] = await Promise.all([
      api('GET', '/settings/mfa/sms').catch(() => ({})),
      api('GET', '/settings/mfa/webauthn').catch(() => ({})),
    ]);
  } catch (_) {}

  const SMS_PROVIDERS = ['twilio', 'ovh', 'vonage'];

  content.innerHTML = `
    <div style="display:flex;flex-direction:column;gap:20px;max-width:640px">

      <div class="card blueprint">
        <div class="card-header"><span class="card-title">${t('settings.mfa.sms_title')}</span></div>
        <div style="padding:16px;display:flex;flex-direction:column;gap:12px">
          <div class="field">
            <label class="field-label">${t('settings.mfa.provider')}</label>
            <select id="mfa-sms-provider" class="input" onchange="mfaSmsProviderChange()">
              ${SMS_PROVIDERS.map(p => `<option value="${p}"${sms.provider===p?' selected':''}>${p.charAt(0).toUpperCase()+p.slice(1)}</option>`).join('')}
            </select>
          </div>
          <div class="field">
            <label class="field-label" id="mfa-sms-accountid-label">${t('settings.mfa.account_id')}</label>
            <input id="mfa-sms-accountid" class="input" value="${esc(sms.account_id||'')}" placeholder="AccountSID / serviceName / APIKey">
          </div>
          <div class="field">
            <label class="field-label" id="mfa-sms-apikey-label">${t('settings.mfa.api_key')}</label>
            <input id="mfa-sms-apikey" class="input" value="${esc(sms.api_key||'')}" placeholder="AuthToken / appKey">
          </div>
          <div class="field" id="mfa-sms-secret-field">
            <label class="field-label">${t('settings.mfa.api_secret')}</label>
            <input id="mfa-sms-secret" class="input" type="password" value="${esc(sms.api_secret||'')}" placeholder="appSecret:consumerKey">
          </div>
          <div class="field">
            <label class="field-label">${t('settings.mfa.from')}</label>
            <input id="mfa-sms-from" class="input" value="${esc(sms.from||'')}" placeholder="+33612345678">
          </div>
          <div class="field">
            <label class="field-label" style="display:flex;align-items:center;gap:8px">
              ${t('common.enabled')}
              <label class="toggle"><input type="checkbox" id="mfa-sms-enabled" ${sms.enabled?'checked':''}><span class="toggle-slider"></span></label>
            </label>
          </div>
          <div>
            <button class="btn btn-primary" id="mfa-sms-save" onclick="saveMFASMS()">${t('common.save')}</button>
          </div>
        </div>
      </div>

      <div class="card blueprint">
        <div class="card-header"><span class="card-title">${t('settings.mfa.webauthn_title')}</span></div>
        <div style="padding:16px;display:flex;flex-direction:column;gap:12px">
          <div class="field">
            <label class="field-label">${t('settings.mfa.rp_id')}</label>
            <input id="mfa-wa-rpid" class="input" value="${esc(webauthn.rp_id||'')}" placeholder="admin.example.fr">
            <div style="font-size:11px;color:var(--text2);margin-top:4px">${t('settings.mfa.rp_id_hint')}</div>
          </div>
          <div class="field">
            <label class="field-label">${t('settings.mfa.rp_origin')}</label>
            <input id="mfa-wa-origin" class="input" value="${esc(webauthn.rp_origin||'')}" placeholder="https://admin.example.fr">
          </div>
          <div class="field">
            <label class="field-label">${t('settings.mfa.display_name')}</label>
            <input id="mfa-wa-display" class="input" value="${esc(webauthn.display_name||'')}" placeholder="GoProxify Admin">
          </div>
          <div>
            <button class="btn btn-primary" id="mfa-wa-save" onclick="saveMFAWebAuthn()">${t('common.save')}</button>
          </div>
        </div>
      </div>

    </div>`;

  mfaSmsProviderChange();
};

window.mfaSmsProviderChange = function() {
  const provider = document.getElementById('mfa-sms-provider')?.value;
  const secretField = document.getElementById('mfa-sms-secret-field');
  const keyLabel = document.getElementById('mfa-sms-apikey-label');
  const accountLabel = document.getElementById('mfa-sms-accountid-label');
  if (!provider) return;
  if (secretField) secretField.style.display = provider === 'ovh' ? '' : 'none';
  if (accountLabel) accountLabel.textContent = provider === 'twilio' ? 'Account SID' : provider === 'ovh' ? 'Service Name' : 'API Key';
  if (keyLabel) keyLabel.textContent = provider === 'twilio' ? 'Auth Token' : provider === 'ovh' ? 'App Key' : 'API Secret';
};

window.saveMFASMS = async function() {
  const btn = document.getElementById('mfa-sms-save');
  if (btn) { btn.disabled = true; btn.textContent = '…'; }
  try {
    await api('PUT', '/settings/mfa/sms', {
      provider:   document.getElementById('mfa-sms-provider')?.value,
      account_id: document.getElementById('mfa-sms-accountid')?.value,
      api_key:    document.getElementById('mfa-sms-apikey')?.value,
      api_secret: document.getElementById('mfa-sms-secret')?.value || '',
      from:       document.getElementById('mfa-sms-from')?.value,
      enabled:    document.getElementById('mfa-sms-enabled')?.checked ?? false,
    });
    toast(t('common.saved'), 'success');
  } catch(e) { toast(e.message, 'error'); }
  if (btn) { btn.disabled = false; btn.textContent = t('common.save'); }
};

window.saveMFAWebAuthn = async function() {
  const btn = document.getElementById('mfa-wa-save');
  if (btn) { btn.disabled = true; btn.textContent = '…'; }
  try {
    await api('PUT', '/settings/mfa/webauthn', {
      rp_id:        document.getElementById('mfa-wa-rpid')?.value,
      rp_origin:    document.getElementById('mfa-wa-origin')?.value,
      display_name: document.getElementById('mfa-wa-display')?.value,
    });
    toast(t('common.saved'), 'success');
  } catch(e) { toast(e.message, 'error'); }
  if (btn) { btn.disabled = false; btn.textContent = t('common.save'); }
};
