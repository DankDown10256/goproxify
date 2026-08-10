// ── PAGE: Paramètres (hub Admin)
// Rendu via renderSettingsHub (partagé avec Paramètres Core).

pages.settings = async function() {
  const content = document.getElementById('content');
  const sections = [
    {
      label: t('settings.sec.access'),
      desc: t('settings.sec.access_desc'),
      items: [
        { page: 'tokens', icon: '<path d="M7 11a4 4 0 100-8 4 4 0 000 8zM11 11l4 4"/>', label: gpxPageLabel('tokens'), desc: t('settings.item.tokens_desc') },
        { page: 'api-tokens', icon: '<path d="M7 11a4 4 0 100-8 4 4 0 000 8zM11 11l4 4M3 13l4 4"/>', label: gpxPageLabel('api-tokens'), desc: t('settings.item.api_tokens_desc') },
        { page: 'users', icon: '<circle cx="8" cy="6" r="3"/><path d="M2 14c0-3 2.7-5 6-5s6 2 6 5"/>', label: gpxPageLabel('users'), desc: t('settings.item.users_desc') },
        { page: 'profile', icon: '<circle cx="8" cy="6" r="3"/><path d="M2 14c0-3 2.7-5 6-5s6 2 6 5"/><path d="M12 3l2 2-2 2"/>', label: gpxPageLabel('profile'), desc: t('settings.item.profile_desc') },
        { page: 'smtp', icon: '<path d="M2 4h12v10H2zM2 4l6 5 6-5"/>', label: gpxPageLabel('smtp', 'SMTP'), desc: t('settings.item.smtp_desc') || 'Email sortant (MFA, portail Access)' },
      ]
    },
    {
      label: t('settings.sec.proxy'),
      desc: t('settings.sec.proxy_desc'),
      items: [
        { page: 'certs', icon: '<path d="M12 2H4a1 1 0 00-1 1v10a1 1 0 001 1h8a1 1 0 001-1V3a1 1 0 00-1-1zM9 7H7m2 3H7"/>', label: gpxPageLabel('certs'), desc: t('settings.item.certs_desc') },
        { page: 'admin-portal-catalog', icon: '<rect x="3" y="5" width="10" height="8" rx="1"/><path d="M6 8h6"/>', label: gpxPageLabel('admin-portal-catalog', 'Catalogue Access'), desc: t('settings.item.pcatalog_desc') || t('coresettings.item.pcatalog_desc') || 'Destinations SSH / Docker et tags' },
        { page: 'snippets', icon: '<path d="M4 6l4-4 4 4M4 10l4 4 4-4"/>', label: gpxPageLabel('snippets'), desc: t('settings.item.snippets_desc') },
        { page: 'error-pages', icon: '<path d="M8 2v4M6 8h4M4 14h8M4 18h5"/><rect x="2" y="6" width="12" height="14" rx="2"/>', label: gpxPageLabel('error-pages'), desc: t('settings.item.error_pages_desc') },
        { page: 'portal-templates', icon: '<path d="M4 3h8v12H4zM6 6h4M6 9h4"/><path d="M10 15l2 2 4-4"/>', label: gpxPageLabel('portal-templates', 'Templates Access'), desc: t('settings.item.portal_tpl_desc') || 'HTML Access (login, catalogue…) poussé aux Cores' },
        { page: 'ip-profiles', icon: '<path d="M8 2a6 6 0 100 12A6 6 0 008 2zM8 6v4M8 10h.01"/>', label: gpxPageLabel('ip-profiles'), desc: t('settings.item.ip_profiles_desc') },
      ]
    },
    {
      label: t('settings.sec.alerts'),
      desc: t('settings.sec.alerts_desc'),
      items: [
        { page: 'alerts', icon: '<path d="M8 2a6 6 0 016 6c0 4-1.5 5-1.5 5H3.5S2 12 2 8a6 6 0 016-6zm-1 12h2"/>', label: gpxPageLabel('alerts'), desc: t('settings.item.alerts_desc') },
        { page: 'alert-channels', icon: '<path d="M3 8h10M8 3v10"/><circle cx="8" cy="8" r="6"/>', label: gpxPageLabel('alert-channels'), desc: t('settings.item.channels_desc') },
      ]
    },
    {
      label: t('settings.sec.data'),
      desc: t('settings.sec.data_desc'),
      items: [
        { page: 'backups', icon: '<path d="M4 7h8M4 11h8M4 3h8"/><rect x="2" y="1" width="12" height="14" rx="2"/>', label: gpxPageLabel('backups'), desc: t('settings.item.backups_desc') },
        { page: 'import', icon: '<path d="M8 3v9M5 9l3 3 3-3"/><path d="M3 14h10"/>', label: gpxPageLabel('import'), desc: t('settings.item.import_desc') },
        { page: 'onboarding', icon: '<circle cx="8" cy="8" r="6"/><path d="M8 5v3l2 2"/>', label: gpxPageLabel('onboarding'), desc: t('settings.item.onboarding_desc') },
      ]
    },
  ];

  let health = null;
  try { health = await api('GET', '/health'); } catch (_) { /* ignore */ }

  const aboutRow = (label, value) => `
    <div style="display:flex;justify-content:space-between;gap:16px;padding:10px 0;border-bottom:1px solid var(--border);">
      <span style="font-size:12px;color:var(--text2)">${esc(label)}</span>
      <span style="font-size:12px;font-family:monospace;font-weight:600">${esc(value || '—')}</span>
    </div>`;

  const footerHtml = `
    <div style="margin-bottom:28px">
      <div style="margin-bottom:12px">
        <div style="font-size:13px;font-weight:600;color:var(--text);margin-bottom:2px">${esc(t('settings.sec.about'))}</div>
        <div style="font-size:12px;color:var(--text2)">${esc(t('settings.sec.about_desc'))}</div>
      </div>
      <div class="card" style="padding:4px 16px;max-width:480px">
        ${aboutRow(t('settings.about.admin'), health?.version ? 'v' + health.version : '—')}
        ${aboutRow(t('settings.about.webapp'), health?.webapp ? 'v' + health.webapp : '—')}
        ${aboutRow(t('settings.about.commit'), health?.commit && health.commit !== 'unknown' ? health.commit : '—')}
        ${aboutRow(t('settings.about.built'), health?.built && health.built !== 'unknown' ? health.built : '—')}
      </div>
    </div>`;

  renderSettingsHub({ contentEl: content, sections, footerHtml });
};
