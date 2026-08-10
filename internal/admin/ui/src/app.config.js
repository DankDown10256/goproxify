// ── Configuration centrale de l'application ───────────────────────────────
// Modifier ce fichier pour changer : branding, skins, navigation, pages.
// Aucune autre modification de code n'est nécessaire.

const APP_CONFIG = {

  // ── Branding ─────────────────────────────────────────────────────────────
  branding: {
    name:    'GOPROXIFY',
    tagline: 'Administration',
    fonts: [
      'https://fonts.googleapis.com/css2?family=Barlow:wght@400;500;700&family=Barlow+Condensed:wght@400;600&display=swap',
    ],
  },

  // ── Skin par défaut ───────────────────────────────────────────────────────
  // Doit correspondre à un id dans APP_CONFIG.skins.
  skin: 'flat',

  // ── Catalogue de skins ────────────────────────────────────────────────────
  // Chaque skin a ses propres palettes d'accent.
  // Le CSS est embarqué dans le HTML au build (src/themes/<id>.css).
  skins: [
    {
      id: 'flat',
      label: 'Flat',
      accents: [
        { name: 'Indigo',  color: '#4f46e5', hover: '#4338ca' },
        { name: 'Émeraude',color: '#059669', hover: '#047857' },
        { name: 'Rose',    color: '#e11d48', hover: '#be123c' },
        { name: 'Ambre',   color: '#d97706', hover: '#b45309' },
      ],
    },
    {
      id: 'industry-ds',
      label: 'Industry DS',
      // Palettes d'accent propres à ce skin
      accents: [
        { name: 'Acier',    color: '#5980a6', hover: '#4a6d8f' },
        { name: 'Sarcelle', color: '#0e8a7c', hover: '#0a6b5f' },
        { name: 'Bronze',   color: '#8c6d2f', hover: '#7a5e27' },
        { name: 'Ardoise',  color: '#5a6675', hover: '#49535f' },
      ],
    },
  ],

  // ── Navigation admin (liste plate, même shape que coreNav) ───────────────
  // guard(user) : item visible si true. Ordre : Dashboard…Paramètres (6e).
  nav: [
    {
      page: 'dashboard',
      label: 'Dashboard',
      icon: '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="5" height="5" rx="1"/><rect x="9" y="2" width="5" height="5" rx="1"/><rect x="2" y="9" width="5" height="5" rx="1"/><rect x="9" y="9" width="5" height="5" rx="1"/></svg>',
    },
    {
      page: 'infrastructure',
      label: 'Infrastructure',
      icon: '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><circle cx="8" cy="4" r="1.5"/><circle cx="3" cy="12" r="1.5"/><circle cx="13" cy="12" r="1.5"/><path d="M8 5.5v3M8 8.5L3 10.5M8 8.5L13 10.5"/></svg>',
    },
    {
      page: 'admin-trafic',
      label: 'Trafic',
      icon: '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 8h12M9 4l5 4-5 4"/></svg>',
    },
    {
      page: 'admin-observability',
      label: 'Observabilité',
      icon: '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M18 20V10M12 20V4M6 20v-6"/></svg>',
      children: [
        {
          page: 'logs',
          label: 'Logs d\'accès',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 5h8M4 8h6M4 11h4"/><rect x="2" y="2" width="12" height="12" rx="2"/></svg>',
        },
        {
          page: 'logs-system',
          label: 'Logs système',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12l4-4 4 4 4-6"/></svg>',
        },
        {
          page: 'prism',
          label: 'Prism',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M18 20V10M12 20V4M6 20v-6"/></svg>',
        },
        {
          page: 'audit',
          label: 'Journal d\'audit',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 2h6l4 4v8a1 1 0 01-1 1H4a1 1 0 01-1-1V3a1 1 0 011-1z"/><path d="M9 2v4h4M5 9h6M5 12h4"/></svg>',
          guard: (u) => u?.role === 'superadmin' || u?.role === 'admin',
        },
      ],
    },
    {
      page: 'security',
      label: 'Sécurité',
      icon: '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M8 2l5 3v4c0 3-2.5 5.5-5 6.5C5.5 14.5 3 12 3 9V5l5-3z"/></svg>',
      guard: (u) => u?.role === 'superadmin' || u?.role === 'admin',
      children: [
        {
          page: 'security-vulns',
          label: 'Vulnérabilités',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M7 1.5L1.2 12a1 1 0 00.9 1.5h11.8a1 1 0 00.9-1.5L8.8 1.5a1 1 0 00-1.8 0z"/><path d="M7 5.5v3.5M7 11h.01"/></svg>',
        },
        {
          page: 'security-posture',
          label: 'Posture',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="7" width="12" height="7" rx="1.5"/><path d="M4.5 7V4.5a2.5 2.5 0 015 0V7"/></svg>',
        },
        {
          page: 'security-bans',
          label: 'Bans',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><circle cx="8" cy="8" r="6"/><path d="M4.5 4.5l7 7"/></svg>',
        },
      ],
    },
    {
      page: 'settings',
      label: 'Paramètres',
      icon: '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><circle cx="8" cy="8" r="3"/><path d="M8 1v2M8 13v2M1 8h2M13 8h2M3.2 3.2l1.4 1.4M11.4 11.4l1.4 1.4M3.2 12.8l1.4-1.4M11.4 4.6l1.4-1.4"/></svg>',
      guard: (u) => (u?.role === 'superadmin') || (u?.role === 'admin' && !(u?.effective_scopes?.length > 0)),
    },
  ],

  // ── Liste des Cores dans la sidebar ───────────────────────────────────────
  // Affiche les cores accessibles (RBAC) sous une section dédiée.
  // Au-delà de `overflowAt`, la liste passe en mode compact : recherche + scroll
  // pour ne pas écraser le menu admin / observabilité.
  navCores: {
    overflowAt: 6,       // seuil « trop de cores »
    listMaxHeight: 220,  // px — hauteur max de la liste scrollable
  },

  // ── Navigation contextuelle Core ──────────────────────────────────────────
  // guard({ hasCoreScope }) : hasCoreScope = true si l'user a un scope "core" explicite
  // sur le Core sélectionné (ou est superadmin / admin global).
  coreNav: [
    {
      page: 'core-trafic',
      label: 'Trafic',
      icon: '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M3 17h2.5a3 3 0 0 0 2.4-1.2l6.2-8.6A3 3 0 0 1 16.5 6H21"/><path d="m17.5 3 3.5 3-3.5 3"/><path d="M3 7h2.5a3 3 0 0 1 2.4 1.2l1 1.4"/><path d="M14.5 15.4l1 1.4A3 3 0 0 0 17.9 18H21"/><path d="m17.5 15 3.5 3-3.5 3"/></svg>',
    },
    {
      page: 'portal',
      label: 'Portail Access',
      icon: '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="5" width="10" height="8" rx="1"/><path d="M6 13v2M10 13v2M5 9h6"/></svg>',
      guard: ({ hasCoreScope }) => hasCoreScope,
      children: [
        {
          page: 'core-portal-catalog',
          label: 'Catalogue Access',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="5" width="10" height="8" rx="1"/><path d="M6 8h6"/></svg>',
        },
        {
          page: 'core-portal-users',
          label: 'Users Access',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><circle cx="8" cy="5" r="2.5"/><path d="M3 13c0-2.2 2.2-4 5-4s5 1.8 5 4"/></svg>',
        },
        {
          page: 'portal-templates',
          label: 'Templates Access',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 3h8v12H4zM6 6h4M6 9h4"/><path d="M10 15l2 2 4-4"/></svg>',
        },
        {
          page: 'portal-audit',
          label: 'Audit Access',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 2h6l4 4v8a1 1 0 01-1 1H4a1 1 0 01-1-1V3a1 1 0 011-1z"/><path d="M9 2v4h4M5 9h6M5 12h4"/></svg>',
        },
      ],
    },
    {
      // Atterrissage dédié (évite que gpxPageLabel écrase le label par « Logs d'accès »)
      page: 'core-observability',
      label: 'Observabilité',
      icon: '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M18 20V10M12 20V4M6 20v-6"/></svg>',
      children: [
        {
          page: 'core-logs-access',
          label: 'Logs d\'accès',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 6h8M4 9h6M4 12h4"/><rect x="2" y="2" width="12" height="12" rx="2"/></svg>',
        },
        {
          page: 'core-logs-system',
          label: 'Logs système',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12l4-4 4 4 4-6"/></svg>',
        },
        {
          page: 'core-prism',
          label: 'Prism',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M18 20V10M12 20V4M6 20v-6"/></svg>',
        },
        {
          page: 'core-metrics',
          label: 'Métriques',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><polyline points="2,12 6,7 10,9 14,3"/><circle cx="6" cy="7" r="1" fill="currentColor"/><circle cx="10" cy="9" r="1" fill="currentColor"/><circle cx="14" cy="3" r="1" fill="currentColor"/></svg>',
        },
      ],
    },
    {
      page: 'core-security',
      label: 'Sécurité',
      icon: '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M8 2l5 3v4c0 3-2.5 5.5-5 6.5C5.5 14.5 3 12 3 9V5l5-3z"/></svg>',
      children: [
        {
          page: 'core-security-vulns',
          label: 'Vulnérabilités',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M7 1.5L1.2 12a1 1 0 00.9 1.5h11.8a1 1 0 00.9-1.5L8.8 1.5a1 1 0 00-1.8 0z"/><path d="M7 5.5v3.5M7 11h.01"/></svg>',
        },
        {
          page: 'core-security-posture',
          label: 'Posture',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="7" width="12" height="7" rx="1.5"/><path d="M4.5 7V4.5a2.5 2.5 0 015 0V7"/></svg>',
        },
        {
          page: 'core-security-bans',
          label: 'Bans',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><circle cx="8" cy="8" r="6"/><path d="M4.5 4.5l7 7"/></svg>',
        },
      ],
    },
    {
      page: 'core-settings',
      label: 'Paramètres Core',
      icon: '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><circle cx="8" cy="8" r="3"/><path d="M8 1v2M8 13v2M1 8h2M13 8h2M3.2 3.2l1.4 1.4M11.4 11.4l1.4 1.4M3.2 12.8l1.4-1.4M11.4 4.6l1.4-1.4"/></svg>',
      guard: ({ hasCoreScope }) => hasCoreScope,
    },
  ],

  // ── Titres de pages ───────────────────────────────────────────────────────
  pageTitles: {
    dashboard:          'Dashboard',
    infrastructure:     'Infrastructure',
    'admin-trafic':     'Trafic',
    logs:               'Logs d\'accès',
    'logs-system':      'Logs système',
    settings:           'Paramètres',
    users:              'Utilisateurs',
    certs:              'Certificats TLS',
    snippets:           'Snippets',
    'error-pages':      'Pages d\'erreur',
    'docker-labels':    'Labels Docker / Kubernetes',
    tokens:             'Tokens d\'appairage',
    'api-tokens':        'Mes tokens API',
    prism:              'Prism — Analyse',
    'core-prism':       'Prism',
    alerts:             'Règles d\'alertes',
    'alert-channels':   'Canaux de notification',
    audit:              'Journal d\'audit',
    security:           'Sécurité',
    'security-vulns':   'Vulnérabilités',
    'security-posture': 'Posture',
    'security-bans':    'Bans',
    backups:            'Sauvegardes',
    import:             'Import / Restore',
    onboarding:         'Assistant d\'intégration',
    'core-trafic':      'Trafic',
    'core-certs':       'Certificats TLS',
    'core-logs-access': 'Logs d\'accès',
    'core-logs-system': 'Logs système',
    'core-prism':       'Prism',
    'admin-observability': 'Observabilité',
    'core-observability': 'Observabilité',
    'core-metrics':     'Métriques',
    'core-security':           'Sécurité',
    'core-security-vulns':     'Vulnérabilités',
    'core-security-posture':   'Posture',
    'core-security-bans':      'Bans',
    'core-cluster':     'Nœuds / Raft',
    'core-settings':    'Paramètres Core',
    'core-general':     'Paramètres généraux',
    'core-waf':         'WAF',
    'core-ipfilter':    'IP / GeoIP / Bot',
    'ip-profiles':      'Profils IP (Threat Feeds)',
    'core-auth':        'Auth / SSO',
    portal:             'Portail Access',
    'portal-templates': 'Templates Access',
    'portal-audit':     'Audit Access',
    'admin-portal-catalog': 'Catalogue Access',
    'core-portal-catalog':  'Catalogue Access',
    'admin-portal-users':   'Users Access',
    'core-portal-users':    'Users Access',
    smtp:               'SMTP',
    profile:            'Mon profil',
  },
};
