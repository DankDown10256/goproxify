// ── Démarrage de l'application ─────────────────────────────────────────────

// Inject branding from APP_CONFIG into static elements
(function applyBranding() {
  const b = APP_CONFIG.branding || {};
  const name = b.name || '';
  const tagline = b.tagline || '';
  ['setup-branding-name','login-branding-name','sidebar-brand-name'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = name;
  });
  const tl = document.getElementById('login-branding-tagline');
  if (tl) tl.textContent = (typeof t === 'function' ? t('brand.tagline') : (tagline || 'Administration'));
  if (typeof applyStaticI18n === 'function') applyStaticI18n();
})();

document.getElementById('login-pass')?.addEventListener('keydown', e => {
  if (e.key === 'Enter') doLogin();
});
document.getElementById('mfa-code')?.addEventListener('keydown', e => {
  if (e.key === 'Enter') doMFAChallenge();
});

(async function boot() {
  try {
    const res = await fetch('/api/v1/setup/status');
    if (res.ok) {
      const data = await res.json();
      if (!data.initialized) { showSetupPage(); return; }
    }
  } catch { /* ignore, continue to login */ }
  if (!state.token) { showLogin(); return; }
  try {
    const me = await fetch('/api/v1/auth/me', { headers:{'Authorization':'Bearer '+state.token} });
    if (me.status === 401) { showLogin(); return; }
    const userData = await me.json().catch(() => null);
    if (userData) { state.user = userData; }
  } catch { showLogin(); return; }
  await afterLogin();
})();
