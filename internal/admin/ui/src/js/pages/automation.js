// ── PAGE: Automatisation — vue d'ensemble
// Sous-menus : Règles automatiques (security-rules), Canaux d'alerte
// (alert-channels), Store de règles préconfigurées (rules-store).

pages.automation = async function() {
  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML = '';
  content.innerHTML = `<p style="color:var(--text2)">${t('common.loading')}</p>`;

  let rules = [], channels = [], templates = [];
  try {
    [rules, channels, templates] = await Promise.all([
      api('GET', '/rules-engine/rules').catch(() => []),
      api('GET', '/alert-channels').catch(() => []),
      api('GET', '/rules-engine/templates').catch(() => []),
    ]);
  } catch {}

  const activeRules = (rules || []).filter(r => r.enabled).length;
  const activeChannels = (channels || []).filter(c => c.enabled !== false).length;

  content.innerHTML = `
    <div class="page-header">
      <h1 style="margin:0 0 4px;font-size:28px;font-family:var(--font-heading);font-weight:600;">${t('automation.title') || 'Automatisation'}</h1>
      <p style="margin:0;opacity:0.65;font-size:14px;">${t('automation.subtitle') || 'Règles automatiques, canaux d\'alerte et store de règles préconfigurées.'}</p>
    </div>

    <div class="sec-tiles" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px;margin:20px 0">
      <div class="sec-tile" style="cursor:pointer" onclick="navigate('security-rules')">
        <div class="sec-tile-label">${t('automation.tile_rules') || 'Règles automatiques'}</div>
        <div class="sec-tile-value" style="color:${activeRules>0?'var(--accent)':'var(--text3)'}">${activeRules}</div>
        <div class="sec-tile-sub">${(rules||[]).length} ${t('common.total') || 'total'}</div>
      </div>
      <div class="sec-tile" style="cursor:pointer" onclick="navigate('alert-channels')">
        <div class="sec-tile-label">${t('automation.tile_channels') || 'Canaux d\'alerte'}</div>
        <div class="sec-tile-value" style="color:${activeChannels>0?'var(--green)':'var(--text3)'}">${activeChannels}</div>
        <div class="sec-tile-sub">${(channels||[]).length} ${t('common.total') || 'total'}</div>
      </div>
      <div class="sec-tile" style="cursor:pointer" onclick="navigate('rules-store')">
        <div class="sec-tile-label">${t('automation.tile_store') || 'Store de règles'}</div>
        <div class="sec-tile-value" style="color:var(--accent)">${(templates||[]).length}</div>
        <div class="sec-tile-sub">${t('automation.tile_store_sub') || 'Règles préconfigurées prêtes à installer'}</div>
      </div>
    </div>

    <div class="card" style="padding:18px 20px">
      <p style="margin:0;font-size:13px;color:var(--text2);line-height:1.6">
        ${t('automation.help') || 'Les règles automatiques déclenchent des actions (désactiver un proxy, bannir une IP, activer le mode strict) selon des conditions observées sur vos Cores. Les canaux d\'alerte définissent où sont envoyées les notifications (email, webhook, ntfy, gotify). Le store propose des règles préconfigurées prêtes à installer en un clic.'}
      </p>
    </div>
  `;
};
