// ── PAGE: Compte (profil + PAT + WebAuthn)
// Extrait de pages-all.js — phase 4.

// ── PAGE: Mon profil ───────────────────────────────────────────────────────
pages.profile = async function() {
  const content = document.getElementById('content');
  content.innerHTML = '<p style="color:var(--text2)">' + t('common.loading') + '</p>';

  let me = null, mfaData = null;
  try {
    [me, mfaData] = await Promise.all([
      api('GET', '/me').catch(() => null),
      api('GET', '/auth/mfa').catch(() => null),
    ]);
  } catch(e) { content.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`; return; }

  const email     = me?.email || state.user?.email || '—';
  const role      = me?.role  || state.user?.role  || '—';
  const createdAt = me?.created_at ? fmtDate(me.created_at) : '—';
  const activeSet = new Set((mfaData?.methods || []).filter(m => m.verified).map(m => m.method));
  const backupLeft = mfaData?.backup_codes_left ?? 0;

  content.innerHTML = `
    <div style="margin-bottom:20px">
      <h1 style="margin:0 0 4px;font-size:28px;font-family:var(--font-heading);font-weight:600;">${t('profile.title')}</h1>
      <p style="margin:0;opacity:0.65;font-size:14px;">${t('profile.subtitle')} <strong id="profile-email-title">${esc(email)}</strong>.</p>
    </div>

    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(min(320px,100%),1fr));gap:16px;margin-bottom:28px;">

      <div class="card blueprint" style="padding:20px;display:flex;flex-direction:column;gap:14px;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <h6 style="margin:0;">${t('profile.account')}</h6>
        <div class="field">
          <label for="me-email">${t('profile.email')}</label>
          <input class="input" id="me-email" type="email" value="${esc(email)}">
        </div>
        <div class="field">
          <label>${t('profile.role')}</label>
          <input class="input" value="${esc(role)}" readonly style="opacity:0.6;cursor:default;">
        </div>
        <div class="field">
          <label>${t('profile.created')}</label>
          <input class="input" value="${esc(createdAt)}" readonly style="opacity:0.6;cursor:default;">
        </div>
        <div class="field">
          <label for="me-locale">${t('profile.language')}</label>
          <select class="input" id="me-locale" onchange="profileSetLocale(this.value)">
            <option value="auto"${!gpxHasLocaleOverride() ? ' selected' : ''}>${t('profile.lang_auto')}</option>
            <option value="en"${gpxHasLocaleOverride() && gpxResolveLocale()==='en' ? ' selected' : ''}>${t('lang.en')}</option>
            <option value="fr"${gpxHasLocaleOverride() && gpxResolveLocale()==='fr' ? ' selected' : ''}>${t('lang.fr')}</option>
            <option value="es"${gpxHasLocaleOverride() && gpxResolveLocale()==='es' ? ' selected' : ''}>${t('lang.es')}</option>
            <option value="de"${gpxHasLocaleOverride() && gpxResolveLocale()==='de' ? ' selected' : ''}>${t('lang.de')}</option>
          </select>
          <div style="font-size:11.5px;opacity:.55;margin-top:4px;">${t('profile.language_hint')}</div>
        </div>
        <div id="me-email-msg" style="font-size:12.5px;display:none;"></div>
        <button class="btn btn-primary blueprint" style="align-self:flex-start;" onclick="saveEmail()">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          ${t('common.save')}
        </button>
      </div>

      <div class="card blueprint" style="padding:20px;display:flex;flex-direction:column;gap:14px;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <h6 style="margin:0;">${t('account.password')}</h6>
        <div class="field"><label for="pw-current">${t('account.password_current')}</label><input class="input" id="pw-current" type="password" placeholder="••••••••"></div>
        <div class="field"><label for="pw-new">${t('users.new_password')}</label><input class="input" id="pw-new" type="password" placeholder="••••••••"></div>
        <div class="field"><label for="pw-confirm">${t('account.password_confirm')}</label><input class="input" id="pw-confirm" type="password" placeholder="••••••••"></div>
        <div id="pw-msg" style="font-size:12.5px;display:none;"></div>
        <button class="btn btn-primary blueprint" style="align-self:flex-start;" onclick="savePassword()">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          ${t('account.password_update')}
        </button>
      </div>

      <div class="card blueprint" style="padding:20px;display:flex;flex-direction:column;gap:14px;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <h6 style="margin:0;">${t('account.pat_title')}</h6>
        <p style="margin:0;font-size:13px;color:var(--text2);line-height:1.45">
          ${t('account.pat_desc')}
        </p>
        <button class="btn btn-primary blueprint" style="align-self:flex-start;" onclick="navigate('api-tokens')">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          ${t('account.pat_manage')}
        </button>
      </div>
    </div>

    <h6 style="margin:0 0 12px;">${t('account.mfa_title')}</h6>
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(min(280px,100%),1fr));gap:12px;">

      <div class="card blueprint" style="display:flex;flex-direction:column;gap:12px;padding:18px;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div>
          <div class="card-title" style="font-size:15px;">${t('account.mfa_totp')}</div>
          <div class="card-meta">${t('account.mfa_totp_meta')}</div>
        </div>
        <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;">
          <span class="tag ${activeSet.has('totp') ? 'tag-green' : 'tag-neutral'}">${activeSet.has('totp') ? t('account.mfa_active') : t('account.mfa_not_configured')}</span>
          <div style="display:flex;gap:6px;">
            <button class="btn btn-ghost btn-sm" onclick="setupTOTP()">
              ${activeSet.has('totp') ? t('account.mfa_reconfigure') : t('account.mfa_configure')}
            </button>
            ${activeSet.has('totp') ? `<button class="btn btn-ghost btn-sm" style="color:var(--red)" onclick="deleteMFA('totp')">${t('common.delete')}</button>` : ''}
          </div>
        </div>
      </div>

      <div class="card blueprint" style="display:flex;flex-direction:column;gap:12px;padding:18px;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div>
          <div class="card-title" style="font-size:15px;">${t('account.mfa_webauthn')}</div>
          <div class="card-meta">${t('account.mfa_webauthn_meta')}</div>
        </div>
        <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;">
          <span class="tag ${activeSet.has('webauthn') ? 'tag-green' : 'tag-neutral'}">${activeSet.has('webauthn') ? t('account.mfa_active') : t('account.mfa_not_configured')}</span>
          <div style="display:flex;gap:6px;">
            <button class="btn btn-ghost btn-sm" onclick="setupWebAuthn()">
              ${activeSet.has('webauthn') ? t('account.mfa_reconfigure') : t('account.mfa_register')}
            </button>
            ${activeSet.has('webauthn') ? `<button class="btn btn-ghost btn-sm" style="color:var(--red)" onclick="deleteMFA('webauthn')">${t('common.delete')}</button>` : ''}
          </div>
        </div>
      </div>

      <div class="card blueprint" style="display:flex;flex-direction:column;gap:12px;padding:18px;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div>
          <div class="card-title" style="font-size:15px;">${t('account.mfa_backup')}</div>
          <div class="card-meta">${t('account.mfa_backup_meta')}</div>
        </div>
        <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;">
          <span class="tag ${backupLeft > 0 ? 'tag-green' : 'tag-neutral'}" id="backup-tag">
            ${backupLeft > 0 ? t('account.mfa_backup_remaining', { n: backupLeft }) : t('account.mfa_backup_not_generated')}
          </span>
          <div style="display:flex;gap:6px;">
            <button class="btn btn-ghost btn-sm" onclick="generateBackupCodes()">${backupLeft > 0 ? t('account.mfa_regenerate') : t('account.mfa_generate')}</button>
            ${backupLeft > 0 ? `<button class="btn btn-ghost btn-sm" style="color:var(--red)" onclick="deleteMFA('backup')">${t('common.delete')}</button>` : ''}
          </div>
        </div>
      </div>

    </div>`;

  window.saveEmail = async function() {
    const el  = document.getElementById('me-email');
    const msg = document.getElementById('me-email-msg');
    msg.style.display = 'none';
    const emailVal = el?.value?.trim();
    if (!emailVal) { msg.textContent = t('account.email_invalid'); msg.style.color = 'var(--red)'; msg.style.display = ''; return; }
    try {
      await api('PATCH', '/me', { email: emailVal });
      msg.textContent = t('account.email_updated'); msg.style.color = 'var(--text2)'; msg.style.display = '';
      document.getElementById('profile-email-title').textContent = emailVal;
      updateSidebarUser({ email: emailVal, role });
    } catch(e) { msg.textContent = e.message; msg.style.color = 'var(--red)'; msg.style.display = ''; }
  };

  window.savePassword = async function() {
    const cur  = document.getElementById('pw-current')?.value;
    const next = document.getElementById('pw-new')?.value;
    const conf = document.getElementById('pw-confirm')?.value;
    const msg  = document.getElementById('pw-msg');
    msg.style.display = 'none';
    if (!cur || !next) { msg.textContent = t('account.password_fill'); msg.style.color='var(--red)'; msg.style.display=''; return; }
    if (next !== conf) { msg.textContent = t('setup.err.match'); msg.style.color='var(--red)'; msg.style.display=''; return; }
    try {
      await api('POST', '/me/change-password', { current_password: cur, new_password: next });
      msg.textContent = t('account.password_updated'); msg.style.color='var(--text2)'; msg.style.display='';
      document.getElementById('pw-current').value = '';
      document.getElementById('pw-new').value = '';
      document.getElementById('pw-confirm').value = '';
    } catch(e) { msg.textContent = e.message; msg.style.color='var(--red)'; msg.style.display=''; }
  };

  window.deleteMFA = async function(method) {
    if (!confirm(t('account.mfa_delete_confirm', { method }))) return;
    try {
      await api('DELETE', `/auth/mfa/${method}`);
      toast(t('account.mfa_deleted'), 'success');
      pages.profile();
    } catch(e) { toast(e.message, 'error'); }
  };

  window.setupTOTP = async function() {
    let secret, uri, qrCode;
    try {
      const r = await api('POST', '/auth/mfa/totp/setup');
      secret = r.secret; uri = r.provision_uri; qrCode = r.qr_code;
    } catch(e) { toast(e.message, 'error'); return; }

    const body = `
      <p style="margin:0 0 14px;font-size:13.5px;opacity:0.8;">${t('account.mfa_totp_setup_hint')}</p>
      <div style="display:flex;justify-content:center;margin-bottom:14px;">
        <img src="${esc(qrCode)}" alt="${esc(t('account.mfa_totp_qr_alt'))}" width="256" height="256" style="display:block;background:#fff;padding:8px;">
      </div>
      <div style="margin-bottom:14px;">
        <a href="${esc(uri)}" style="display:inline-block;padding:8px 14px;background:var(--surface2);font-size:13px;word-break:break-all;" target="_blank">
          ${t('account.mfa_totp_open_app')}
        </a>
      </div>
      <div class="field" style="margin-bottom:14px;">
        <label style="font-size:12px;opacity:0.7;">${t('account.mfa_totp_secret')}</label>
        <div style="display:flex;gap:6px;align-items:center;">
          <input class="input" id="totp-secret-display" value="${esc(secret)}" readonly style="font-family:monospace;font-size:13px;letter-spacing:1px;flex:1;">
          <button class="btn btn-ghost btn-sm" onclick="copyText('${esc(secret)}','${esc(t('account.mfa_secret_copied'))}')">${t('account.mfa_copy_secret')}</button>
        </div>
      </div>
      <div class="field">
        <label for="totp-code">${t('account.mfa_totp_code')}</label>
        <input class="input" id="totp-code" type="text" inputmode="numeric" maxlength="6" placeholder="123456" autocomplete="one-time-code">
      </div>
      <div id="totp-msg" style="font-size:12.5px;color:var(--red);display:none;margin-top:8px;"></div>`;

    const footer = `
      <button class="btn btn-ghost" onclick="closeModal()">${t('common.cancel')}</button>
      <button class="btn btn-primary blueprint" onclick="verifyTOTP()">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        ${t('account.mfa_verify_activate')}
      </button>`;
    modal(t('account.mfa_totp_setup_title'), body, footer);
    setTimeout(() => document.getElementById('totp-code')?.focus(), 100);
  };

  window.verifyTOTP = async function() {
    const code = document.getElementById('totp-code')?.value?.trim();
    const msg  = document.getElementById('totp-msg');
    msg.style.display = 'none';
    if (!code || code.length !== 6) { msg.textContent = t('account.mfa_code_6digits'); msg.style.display=''; return; }
    try {
      await api('POST', '/auth/mfa/totp/verify', { code });
      closeModal();
      toast(t('account.mfa_totp_activated'), 'success');
      pages.profile();
    } catch(e) { msg.textContent = e.message || t('account.mfa_invalid_code'); msg.style.display=''; }
  };

  window.setupWebAuthn = async function() {
    if (!window.PublicKeyCredential) {
      toast(t('account.mfa_webauthn_unavailable'), 'error'); return;
    }
    try {
      const { options } = await api('POST', '/auth/mfa/webauthn/register/begin');
      const challengeID = options.publicKey?.challenge;

      const pk = options.publicKey;
      pk.challenge = b64url(pk.challenge);
      pk.user.id   = b64url(pk.user.id);
      if (pk.excludeCredentials) {
        pk.excludeCredentials = pk.excludeCredentials.map(c => ({ ...c, id: b64url(c.id) }));
      }

      const cred = await navigator.credentials.create({ publicKey: pk });
      if (!cred) { toast(t('account.mfa_webauthn_cancelled'), 'info'); return; }

      const resp = {
        id: cred.id, rawId: b64encode(cred.rawId), type: cred.type,
        response: {
          attestationObject: b64encode(cred.response.attestationObject),
          clientDataJSON:    b64encode(cred.response.clientDataJSON),
        },
      };
      await api('POST', `/auth/mfa/webauthn/register/finish?challenge=${encodeURIComponent(challengeID)}`, resp);
      toast(t('account.mfa_webauthn_activated'), 'success');
      pages.profile();
    } catch(e) { toast(e.message || t('account.mfa_webauthn_error'), 'error'); }
  };

  window.generateBackupCodes = async function() {
    const alreadyHas = backupLeft > 0;
    if (alreadyHas && !confirm(t('account.mfa_backup_regen_confirm'))) return;
    try {
      const r = await api('POST', '/auth/mfa/backup-codes/generate');
      const codes = r.codes || [];
      const body = `
        <div style="margin-bottom:12px;">
          <div class="alert alert-warning" style="font-size:13px;">
            ${t('account.mfa_backup_warning')}
          </div>
        </div>
        <div class="gp-cols-2" style="gap:6px;font-family:monospace;font-size:14px;letter-spacing:1px;margin-bottom:14px;">
          ${codes.map(c => `<div style="background:var(--surface2);padding:7px 10px;min-width:0;overflow-wrap:anywhere;">${esc(c)}</div>`).join('')}
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;">
          <button class="btn btn-ghost btn-sm" onclick="copyText('${esc(codes.join('\\n'))}','${esc(t('account.mfa_codes_copied'))}')">${t('account.mfa_backup_copy_all')}</button>
          <button class="btn btn-ghost btn-sm" onclick="window.print()">${t('account.mfa_backup_print')}</button>
        </div>`;
      const footer = `<button class="btn btn-primary blueprint" onclick="closeModal();pages.profile();">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        ${t('account.mfa_backup_saved')}
      </button>`;
      modal(t('account.mfa_backup_title'), body, footer);
    } catch(e) { toast(e.message, 'error'); }
  };
};

// ── PAGE: Mes tokens API (PAT) ─────────────────────────────────────────────
pages['api-tokens'] = async function() {
  const content = document.getElementById('content');
  content.innerHTML = `<p style="color:var(--text2)">${t('common.loading')}</p>`;

  let tokens = [], scopes = [];
  try {
    [tokens, scopes] = await Promise.all([
      api('GET', '/me/tokens').catch(() => []),
      api('GET', '/me/tokens/scopes').catch(() => []),
    ]);
  } catch(e) {
    content.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`;
    return;
  }

  const available = (scopes || []).filter(s => s.available);

  async function refresh() {
    tokens = await api('GET', '/me/tokens').catch(() => []);
    render();
  }

  function render() {
    const rows = (tokens || []).map(tok => {
      const status = tok.revoked
        ? `<span class="tag tag-neutral">${t('account.pat_revoked')}</span>`
        : (tok.expires_at && new Date(tok.expires_at) < new Date()
          ? `<span class="tag tag-neutral">${t('account.pat_expired')}</span>`
          : `<span class="tag tag-green">${t('account.pat_status_active')}</span>`);
      const exp = tok.expires_at ? fmtDate(tok.expires_at) : t('account.pat_never');
      const used = tok.last_used_at ? fmtDate(tok.last_used_at) : '—';
      const scopeTags = (tok.scopes || []).map(s =>
        `<span class="tag tag-neutral" style="font-family:monospace;font-size:10px;font-weight:500;white-space:nowrap">${esc(s)}</span>`
      ).join('');
      return `<tr>
        <td style="min-width:120px;max-width:180px;vertical-align:top">
          <strong>${esc(tok.label)}</strong>
          <div style="font-size:11px;opacity:0.55;font-family:monospace;word-break:break-all">${esc(tok.prefix)}</div>
        </td>
        <td style="vertical-align:top">
          <div style="display:flex;flex-wrap:wrap;gap:4px;max-width:420px">${scopeTags || '—'}</div>
        </td>
        <td style="white-space:nowrap;vertical-align:top">${status}</td>
        <td style="font-size:12px;white-space:nowrap;vertical-align:top">${esc(exp)}</td>
        <td style="font-size:12px;white-space:nowrap;vertical-align:top">${esc(used)}</td>
        <td style="white-space:nowrap;vertical-align:top">
          ${!tok.revoked ? `<button class="btn btn-sm btn-danger" onclick="revokeApiToken('${esc(tok.id)}')">${t('account.pat_revoke')}</button>` : ''}
        </td>
      </tr>`;
    }).join('') || `<tr><td colspan="6" style="opacity:0.5">${t('account.pat_empty')}</td></tr>`;

    content.innerHTML = `
      <div style="margin-bottom:20px;display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap">
        <div>
          <h1 style="margin:0 0 4px;font-size:28px;font-family:var(--font-heading);font-weight:600;">${t('account.pat_page_title')}</h1>
          <p style="margin:0;opacity:0.65;font-size:14px;">${t('account.pat_page_sub')}</p>
        </div>
        <button class="btn btn-primary" onclick="createApiTokenModal()">${t('account.pat_new')}</button>
      </div>
      <div class="card" style="overflow-x:auto">
        <table class="table" style="width:100%;table-layout:auto">
          <thead><tr>
            <th>${t('account.pat_col_label')}</th><th>${t('account.pat_col_scopes')}</th><th>${t('account.pat_col_status')}</th><th>${t('account.pat_col_expires')}</th><th>${t('account.pat_col_last_used')}</th><th></th>
          </tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
  }

  window.revokeApiToken = function(id) {
    confirm_(t('account.pat_revoke_confirm'), async () => {
      try {
        await api('DELETE', `/me/tokens/${id}`);
        toast(t('account.pat_revoked_toast'), 'success');
        await refresh();
      } catch(e) { toast(e.message, 'error'); }
    });
  };

  window.createApiTokenModal = function() {
    const checks = available.map(s => `
      <label style="display:flex;align-items:flex-start;gap:8px;margin:6px 0;font-size:13px;cursor:pointer">
        <input type="checkbox" class="pat-scope" value="${esc(s.id)}" style="margin-top:3px">
        <span><code>${esc(s.id)}</code><div style="opacity:0.6;font-size:12px">${esc(s.description || '')}</div></span>
      </label>`).join('') || `<p style="opacity:0.6">${t('account.pat_no_scopes')}</p>`;

    const body = `
      <div class="field"><label>${t('account.pat_label')}</label>
        <input class="input" id="pat-label" placeholder="${esc(t('account.pat_label_ph'))}">
      </div>
      <div class="field"><label>${t('account.pat_expires')}</label>
        <input class="input" id="pat-expires" type="datetime-local">
        <div style="font-size:11px;opacity:0.55;margin-top:4px">${t('account.pat_expires_hint')}</div>
      </div>
      <div class="field"><label>${t('account.pat_scopes')}</label>
        <div style="max-height:240px;overflow:auto;border:1px solid var(--border);border-radius:6px;padding:8px 10px">${checks}</div>
      </div>`;
    const footer = `<button class="btn btn-primary" onclick="submitApiToken()">${t('common.create')}</button>`;
    modal(t('account.pat_new_modal'), body, footer);
  };

  window.submitApiToken = async function() {
    const label = document.getElementById('pat-label')?.value?.trim();
    const expEl = document.getElementById('pat-expires')?.value;
    const selected = [...document.querySelectorAll('.pat-scope:checked')].map(el => el.value);
    if (!label) { toast(t('account.pat_label_required'), 'error'); return; }
    if (!selected.length) { toast(t('account.pat_scope_required'), 'error'); return; }
    const payload = { label, scopes: selected };
    if (expEl) {
      payload.expires_at = new Date(expEl).toISOString();
    }
    try {
      const res = await api('POST', '/me/tokens', payload);
      closeModal();
      const token = res.token || '';
      window.__lastPatSecret = token;
      const body = `
        <div class="alert alert-warning" style="font-size:13px;margin-bottom:12px">
          ${t('account.pat_copy_warning')}
        </div>
        <div style="font-family:monospace;font-size:13px;word-break:break-all;background:var(--surface2);padding:12px;border-radius:6px;margin-bottom:12px">${esc(token)}</div>
        <button class="btn btn-ghost btn-sm" onclick="copyText(window.__lastPatSecret||'','${esc(t('account.pat_token_copied'))}')">${t('account.pat_copy')}</button>`;
      modal(t('account.pat_created_title'), body, `<button class="btn btn-primary" onclick="closeModal()">${t('account.pat_closed')}</button>`);
      await refresh();
    } catch(e) { toast(e.message, 'error'); }
  };

  render();
};

// ── Helpers WebAuthn base64
function b64url(v) {
  if (typeof v === 'string') {
    const b = atob(v.replace(/-/g,'+').replace(/_/g,'/'));
    const a = new Uint8Array(b.length);
    for (let i=0;i<b.length;i++) a[i]=b.charCodeAt(i);
    return a.buffer;
  }
  return v;
}
function b64encode(buf) {
  const b = new Uint8Array(buf);
  return btoa(String.fromCharCode(...b)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}


function profileSetLocale(val) {
  if (val === 'auto') gpxClearLocaleOverride();
  else gpxSetLocale(val);
  gpxRefreshUILocale();
}
