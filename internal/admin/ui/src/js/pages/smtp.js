// ── PAGE: SMTP (Paramètres)
pages.smtp = async function() {
  document.getElementById('topbar-actions').innerHTML = `
    <button class="btn btn-secondary" id="smtp-test">${esc(t('smtp.test') || 'Envoyer un test')}</button>
    <button class="btn btn-primary" id="smtp-save">${esc(t('common.save') || 'Enregistrer')}</button>`;
  const content = document.getElementById('content');
  content.innerHTML = `<div class="muted">${esc(t('common.loading') || '…')}</div>`;
  try {
    const d = await api('GET', '/settings/smtp') || {};
    const s = d.smtp || {};
    content.innerHTML = `
      <div class="card blueprint" style="padding:16px 18px;max-width:640px">
        <div style="font-family:var(--font-heading);font-size:18px;font-weight:700;margin-bottom:4px">${esc(t('smtp.title') || 'SMTP')}</div>
        <p style="font-size:13px;color:var(--text2);margin:0 0 16px;line-height:1.45">${esc(t('smtp.desc') || 'Utilisé pour MFA Admin, invitations portail Access et OTP email.')}</p>
        <div style="margin-bottom:12px">
          <span class="badge" style="font-size:11px;padding:4px 10px;border-radius:999px;border:1px solid var(--border);color:${d.configured ? 'var(--accent)' : 'var(--text2)'}">
            ${d.configured ? (t('smtp.configured') || 'Configuré') : (t('smtp.missing') || 'Non configuré')}
          </span>
        </div>
        <div class="field" style="margin-bottom:10px"><label class="field-label">Host</label><input class="input" id="smtp-host" value="${esc(s.host || '')}" placeholder="smtp.example.com"/></div>
        <div class="field" style="margin-bottom:10px"><label class="field-label">Port</label><input class="input" id="smtp-port" type="number" value="${s.port || 587}"/></div>
        <div class="field" style="margin-bottom:10px"><label class="field-label">Username</label><input class="input" id="smtp-user" value="${esc(s.username || '')}" autocomplete="off"/></div>
        <div class="field" style="margin-bottom:10px"><label class="field-label">Password</label><input class="input" id="smtp-pass" type="password" value="${esc(s.password || '')}" autocomplete="new-password"/></div>
        <div class="field" style="margin-bottom:10px"><label class="field-label">From</label><input class="input" id="smtp-from" value="${esc(s.from || '')}" placeholder="noreply@example.com"/></div>
        <div class="field" style="margin-bottom:10px"><label class="field-label">${esc(t('smtp.test_to') || 'Email de test')}</label><input class="input" id="smtp-to" placeholder="you@example.com"/></div>
        <div id="smtp-msg" style="font-size:13px;min-height:1.2em;margin-top:8px"></div>
      </div>`;
    const msg = (text, ok) => {
      const el = document.getElementById('smtp-msg');
      el.textContent = text;
      el.style.color = ok ? 'var(--accent)' : 'var(--danger, #c45c5c)';
    };
    document.getElementById('smtp-save').onclick = async () => {
      try {
        await api('PUT', '/settings/smtp', {
          host: document.getElementById('smtp-host').value.trim(),
          port: +document.getElementById('smtp-port').value || 587,
          username: document.getElementById('smtp-user').value.trim(),
          password: document.getElementById('smtp-pass').value,
          from: document.getElementById('smtp-from').value.trim(),
        });
        msg(t('smtp.saved') || 'Enregistré.', true);
        pages.smtp();
      } catch (e) { msg(e.message || String(e), false); }
    };
    document.getElementById('smtp-test').onclick = async () => {
      try {
        const to = document.getElementById('smtp-to').value.trim();
        if (!to) throw new Error(t('smtp.test_to_required') || 'Email de test requis');
        await api('POST', '/settings/smtp/test', { to });
        msg(t('smtp.test_ok') || 'Email de test envoyé.', true);
      } catch (e) { msg(e.message || String(e), false); }
    };
  } catch (e) {
    content.innerHTML = `<div class="err">${esc(e.message || e)}</div>`;
  }
};
