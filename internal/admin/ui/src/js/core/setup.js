// ── Setup initial (premier admin) ───────────────────────────────────────
// Chargé avant core/boot.js (showSetupPage).
// Extrait de pages-all.js — phase 2.

// ── Setup ──────────────────────────────────────────────────────────────────
function showSetupPage() {
  document.getElementById('setup-page').style.display = 'flex';
  document.getElementById('login-page').style.display = 'none';
  document.getElementById('app').style.display = 'none';
  if (typeof applyStaticI18n === 'function') applyStaticI18n();
}
async function doSetup() {
  const email = document.getElementById('setup-email').value.trim();
  const pass  = document.getElementById('setup-pass').value;
  const pass2 = document.getElementById('setup-pass2').value;
  const errEl = document.getElementById('setup-error');
  errEl.style.display = 'none';
  if (!email || !pass) { errEl.textContent = t('setup.err.fill'); errEl.style.display='block'; return; }
  if (pass !== pass2) { errEl.textContent = t('setup.err.match'); errEl.style.display='block'; return; }
  try {
    const res = await fetch('/api/v1/setup/init', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({email, password:pass}) });
    if (res.status === 201) {
      document.getElementById('setup-page').style.display = 'none';
      document.getElementById('login-email').value = email;
      showLogin();
    } else if (res.status === 409) {
      errEl.textContent = t('setup.err.exists'); errEl.style.display='block';
    } else {
      const txt = await res.text(); errEl.textContent = txt || t('setup.err.create'); errEl.style.display='block';
    }
  } catch { errEl.textContent = t('setup.err.server'); errEl.style.display='block'; }
}
document.getElementById('setup-pass2')?.addEventListener('keydown', e => { if (e.key==='Enter') doSetup(); });
