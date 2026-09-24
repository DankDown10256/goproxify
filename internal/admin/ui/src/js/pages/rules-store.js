// ── PAGE: Store de règles préconfigurées
// Catalogue de templates de règles automatiques (condition → action) qu'un
// admin peut installer en un clic, puis affiner dans "Règles automatiques".

const RULES_STORE_CATEGORY_LABEL = {
  security: 'Sécurité',
  reliability: 'Fiabilité',
  compliance: 'Conformité',
};

pages['rules-store'] = async function() {
  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML =
    `<button class="btn btn-ghost" onclick="navigate('security-rules')">${t('automation.view_rules') || 'Voir mes règles'}</button>`;
  content.innerHTML = `<p style="color:var(--text2)">${t('common.loading')}</p>`;

  let templates = [], installedNames = new Set();
  try {
    const [tpls, rules] = await Promise.all([
      api('GET', '/rules-engine/templates').catch(() => []),
      api('GET', '/rules-engine/rules').catch(() => []),
    ]);
    templates = tpls || [];
    installedNames = new Set((rules || []).map(r => r.name));
  } catch {}

  const byCategory = {};
  for (const tpl of templates) {
    (byCategory[tpl.category] ||= []).push(tpl);
  }

  content.innerHTML = `
    <div class="page-header">
      <h1 style="margin:0 0 4px;font-size:28px;font-family:var(--font-heading);font-weight:600;">${t('rules_store.title') || 'Store de règles'}</h1>
      <p style="margin:0;opacity:0.65;font-size:14px;">${t('rules_store.subtitle') || 'Règles automatiques préconfigurées, prêtes à installer.'}</p>
    </div>

    ${Object.keys(byCategory).length ? Object.entries(byCategory).map(([cat, tpls]) => `
      <h6 style="margin:20px 0 10px;font-size:11px;text-transform:uppercase;letter-spacing:0.09em;opacity:0.5;">${RULES_STORE_CATEGORY_LABEL[cat] || cat}</h6>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px">
        ${tpls.map(tpl => {
          const installed = installedNames.has(tpl.name);
          return `
          <div class="card" style="padding:16px 18px;display:flex;flex-direction:column;gap:10px">
            <div style="font-weight:600;font-size:14px">${esc(tpl.name)}</div>
            <p style="margin:0;font-size:12px;color:var(--text2);line-height:1.5;flex:1">${esc(tpl.description)}</p>
            <div style="display:flex;align-items:center;justify-content:space-between;gap:8px">
              <span class="tag tag-neutral" style="font-size:10px">${t('rules_store.cooldown', { n: tpl.cooldown_sec }) || `Cooldown ${tpl.cooldown_sec}s`}</span>
              <button class="btn btn-sm ${installed ? 'btn-ghost' : 'btn-primary'}" ${installed ? 'disabled' : ''}
                onclick="installRuleTemplate('${esc(tpl.id)}')">
                ${installed ? (t('rules_store.installed') || 'Installée') : (t('rules_store.install') || 'Installer')}
              </button>
            </div>
          </div>`;
        }).join('')}
      </div>
    `).join('') : `<div class="card" style="padding:20px"><p style="opacity:0.6;margin:0">${t('rules_store.empty') || 'Aucun template disponible.'}</p></div>`}
  `;
};

window.installRuleTemplate = async function(tplId) {
  try {
    await api('POST', `/rules-engine/templates/${tplId}/install`, {});
    toast(t('rules_store.install_ok') || 'Règle installée', 'success');
    navigate('rules-store');
  } catch (e) {
    toast(e?.message || (t('rules_store.install_err') || 'Échec de l\'installation'), 'error');
  }
};
