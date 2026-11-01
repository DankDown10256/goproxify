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
      fonts: [
        'https://fonts.googleapis.com/css2?family=Barlow:wght@400;500;700&family=Barlow+Condensed:wght@400;600&display=swap',
      ],
      // Palettes d'accent propres à ce skin
      accents: [
        { name: 'Acier',    color: '#5980a6', hover: '#4a6d8f' },
        { name: 'Sarcelle', color: '#0e8a7c', hover: '#0a6b5f' },
        { name: 'Bronze',   color: '#8c6d2f', hover: '#7a5e27' },
        { name: 'Ardoise',  color: '#5a6675', hover: '#49535f' },
      ],
    },
    {
      id: 'console',
      label: 'Console',
      accents: [
        { name: 'Sarcelle',  color: '#0b6e5a', hover: '#09594a', dark: { color: '#3ecfae', hover: '#5fdcc0' } },
        { name: 'Graphite',  color: '#3f4750', hover: '#2f363d', dark: { color: '#b4bcc6', hover: '#cdd3da' } },
        { name: 'Bleu nuit', color: '#1d4f91', hover: '#173f74', dark: { color: '#7aaaea', hover: '#9bc0f0' } },
        { name: 'Cuivre',    color: '#a8501f', hover: '#8c4219', dark: { color: '#e59660', hover: '#eeaa7c' } },
      ],
    },
  ],

  // ── Navigation admin (liste plate, même shape que edgeNav) ───────────────
  // guard(user) : item visible si true. Ordre : Dashboard…Paramètres (6e).
  nav: [
    {
      page: 'dashboard',
      label: 'Dashboard',
      icon: '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="5" height="5" rx="1"/><rect x="9" y="2" width="5" height="5" rx="1"/><rect x="2" y="9" width="5" height="5" rx="1"/><rect x="9" y="9" width="5" height="5" rx="1"/></svg>',
    },
    {
      page: 'admin-trafic',
      label: 'Proxies',
      icon: '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 8h12M9 4l5 4-5 4"/></svg>',
    },
    {
      page: 'admin-observability',
      label: 'Observabilité',
      icon: '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M18 20V10M12 20V4M6 20v-6"/></svg>',
      children: [
        {
          page: 'obs-synthese',
          label: 'Synthèse',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="5" height="5" rx="1"/><rect x="9" y="2" width="5" height="5" rx="1"/><rect x="2" y="9" width="5" height="5" rx="1"/><rect x="9" y="9" width="5" height="5" rx="1"/></svg>',
        },
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
          page: 'proxy-inspector',
          label: 'Vue Proxy',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18M8 9v11"/><circle cx="14.5" cy="6.5" r=".6" fill="currentColor" stroke="none"/></svg>',
        },
        {
          page: 'obs-metrics',
          label: 'Métriques',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><polyline points="2,12 6,7 10,9 14,3"/><circle cx="6" cy="7" r="1" fill="currentColor"/><circle cx="10" cy="9" r="1" fill="currentColor"/><circle cx="14" cy="3" r="1" fill="currentColor"/></svg>',
        },
        {
          page: 'obs-alerts',
          label: 'Alertes et SLO',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M8 2a4 4 0 00-4 4v3l-1.5 2.5h11L12 9V6a4 4 0 00-4-4zM6.5 13a1.5 1.5 0 003 0"/></svg>',
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
    },
    {
      page: 'infrastructure',
      label: 'Infrastructure',
      section: 'Plateforme',
      icon: '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><circle cx="8" cy="4" r="1.5"/><circle cx="3" cy="12" r="1.5"/><circle cx="13" cy="12" r="1.5"/><path d="M8 5.5v3M8 8.5L3 10.5M8 8.5L13 10.5"/></svg>',
      children: [
        {
          page: 'infrastructure',
          navKey: 'nav.auto.overview',
          label: 'Vue d\'ensemble',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z"/></svg>',
        },
        {
          page: 'tokens',
          label: 'Appairage',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M7 11a4 4 0 100-8 4 4 0 000 8zM11 11l4 4"/></svg>',
          guard: (u) => u?.role === 'superadmin' || u?.role === 'admin',
        },
      ],
    },
    {
      page: 'automation',
      label: 'Automatisation',
      section: 'Plateforme',
      icon: '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0h10a2 2 0 002-2v-4M9 21H5a2 2 0 01-2-2v-4m0 0h18"/></svg>',
      guard: (u) => u?.role === 'superadmin' || u?.role === 'admin',
      children: [
        {
          page: 'automation',
          navKey: 'nav.auto.overview',
          label: 'Vue d\'ensemble',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z"/></svg>',
          guard: (u) => u?.role === 'superadmin' || u?.role === 'admin',
        },
        {
          page: 'security-rules',
          navKey: 'nav.auto.rules',
          label: 'Automatisations',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0h10a2 2 0 002-2v-4M9 21H5a2 2 0 01-2-2v-4m0 0h18"/></svg>',
          guard: (u) => u?.role === 'superadmin' || u?.role === 'admin',
        },
        {
          page: 'alert-channels',
          navKey: 'nav.auto.alerts',
          label: 'Alertes',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.7 21a2 2 0 01-3.4 0"/></svg>',
          guard: (u) => u?.role === 'superadmin' || u?.role === 'admin',
        },
        {
          page: 'automation-history',
          navKey: 'nav.auto.journal',
          label: 'Journal',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M4 6h16M4 12h16M4 18h10"/></svg>',
          guard: (u) => u?.role === 'superadmin' || u?.role === 'admin',
        },
      ],
    },
    {
      page: 'access',
      label: 'Accès',
      section: 'Plateforme',
      icon: '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><circle cx="8" cy="8" r="3"/><path d="M2 18c0-3 2.7-5 6-5"/><path d="M16 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z"/><path d="M16 14v4M14 16h4"/></svg>',
      guard: (u) => u?.role === 'superadmin' || u?.role === 'admin',
      children: [
        {
          page: 'workspaces',
          label: 'Gestion d\'équipe',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><circle cx="6" cy="5" r="2.5"/><path d="M1 13c0-2.5 2.2-4 5-4s5 1.5 5 4"/><circle cx="13" cy="5" r="2"/><path d="M18 13c0-2-1.8-3.2-4-3.2"/></svg>',
        },
        {
          page: 'acme-monitor',
          label: 'Domaines & certificats',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>',
          guard: (u) => u?.role === 'superadmin' || u?.role === 'admin',
        },
        {
          page: 'mcp-access',
          label: 'Accès MCP',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="2"/><path d="M9 9h.01M15 9h.01M9 15h6"/></svg>',
          guard: (u) => u?.role === 'superadmin' || u?.role === 'admin',
        },
      ],
    },
    {
      page: 'settings',
      label: 'Paramètres',
      section: 'Plateforme',
      icon: '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><circle cx="8" cy="8" r="3"/><path d="M8 1v2M8 13v2M1 8h2M13 8h2M3.2 3.2l1.4 1.4M11.4 11.4l1.4 1.4M3.2 12.8l1.4-1.4M11.4 4.6l1.4-1.4"/></svg>',
      guard: (u) => (u?.role === 'superadmin') || (u?.role === 'admin' && !(u?.effective_scopes?.length > 0)),
    },
  ],

  // ── Liste des passerelles dans la sidebar ───────────────────────────────────────
  // Affiche les passerelles accessibles (RBAC) sous une section dédiée.
  // Au-delà de `overflowAt`, la liste passe en mode compact : recherche + scroll
  // pour ne pas écraser le menu admin / observabilité.
  navEdges: {
    overflowAt: 6,       // seuil « trop de edges »
    listMaxHeight: 220,  // px — hauteur max de la liste scrollable
  },

  // ── Navigation contextuelle passerelle ──────────────────────────────────────────
  // guard({ hasEdgeScope }) : hasEdgeScope = true si l'user a un scope "edge" explicite
  // sur la passerelle sélectionnée (ou est superadmin / admin global).
  edgeNav: [
    {
      page: 'edge-trafic',
      label: 'Proxies',
      icon: '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M3 17h2.5a3 3 0 0 0 2.4-1.2l6.2-8.6A3 3 0 0 1 16.5 6H21"/><path d="m17.5 3 3.5 3-3.5 3"/><path d="M3 7h2.5a3 3 0 0 1 2.4 1.2l1 1.4"/><path d="M14.5 15.4l1 1.4A3 3 0 0 0 17.9 18H21"/><path d="m17.5 15 3.5 3-3.5 3"/></svg>',
    },
    {
      page: 'portal',
      label: 'Portail Access',
      section: 'Passerelle',
      icon: '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="5" width="10" height="8" rx="1"/><path d="M6 13v2M10 13v2M5 9h6"/></svg>',
      guard: ({ hasEdgeScope }) => hasEdgeScope,
    },
    {
      // Atterrissage dédié (évite que gpxPageLabel écrase le label par « Logs d'accès »)
      page: 'edge-observability',
      label: 'Observabilité',
      icon: '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M18 20V10M12 20V4M6 20v-6"/></svg>',
      children: [
        {
          page: 'edge-obs-synthese',
          label: 'Synthèse',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="5" height="5" rx="1"/><rect x="9" y="2" width="5" height="5" rx="1"/><rect x="2" y="9" width="5" height="5" rx="1"/><rect x="9" y="9" width="5" height="5" rx="1"/></svg>',
        },
        {
          page: 'edge-logs-access',
          label: 'Logs d\'accès',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 6h8M4 9h6M4 12h4"/><rect x="2" y="2" width="12" height="12" rx="2"/></svg>',
        },
        {
          page: 'edge-logs-system',
          label: 'Logs système',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12l4-4 4 4 4-6"/></svg>',
        },
        {
          page: 'edge-prism',
          label: 'Prism',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M18 20V10M12 20V4M6 20v-6"/></svg>',
        },
        {
          page: 'edge-proxy-inspector',
          label: 'Vue Proxy',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18M8 9v11"/><circle cx="14.5" cy="6.5" r=".6" fill="currentColor" stroke="none"/></svg>',
        },
        {
          page: 'edge-metrics',
          label: 'Métriques',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><polyline points="2,12 6,7 10,9 14,3"/><circle cx="6" cy="7" r="1" fill="currentColor"/><circle cx="10" cy="9" r="1" fill="currentColor"/><circle cx="14" cy="3" r="1" fill="currentColor"/></svg>',
        },
        {
          page: 'edge-obs-alerts',
          label: 'Alertes et SLO',
          icon: '<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M8 2a4 4 0 00-4 4v3l-1.5 2.5h11L12 9V6a4 4 0 00-4-4zM6.5 13a1.5 1.5 0 003 0"/></svg>',
        },
      ],
    },
    {
      page: 'edge-tunnel',
      label: 'Tunnel L4',
      section: 'Passerelle',
      icon: '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M4 12h16M4 12c0-3.3 3.6-6 8-6s8 2.7 8 6M4 12c0 3.3 3.6 6 8 6s8-2.7 8-6"/></svg>',
      guard: ({ hasEdgeScope }) => hasEdgeScope,
    },
    {
      page: 'edge-security',
      label: 'Sécurité',
      icon: '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M8 2l5 3v4c0 3-2.5 5.5-5 6.5C5.5 14.5 3 12 3 9V5l5-3z"/></svg>',
    },
    {
      page: 'edge-settings',
      label: 'Paramètres',
      labelPage: 'settings',
      section: 'Passerelle',
      icon: '<svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><circle cx="8" cy="8" r="3"/><path d="M8 1v2M8 13v2M1 8h2M13 8h2M3.2 3.2l1.4 1.4M11.4 11.4l1.4 1.4M3.2 12.8l1.4-1.4M11.4 4.6l1.4-1.4"/></svg>',
      guard: ({ hasEdgeScope }) => hasEdgeScope,
    },
  ],

  // ── Onglets de page ─────────────────────────────────────────────────────────
  // Un groupe = une rubrique de la sidebar dont les sous-pages s'affichent en onglets.
  // `root` est l'entrée de la sidebar (surlignée quel que soit l'onglet actif).
  pageTabs: [
    {
      root: 'portal',
      tabs: [
        { page: 'portal',              key: 'p_overview',  label: 'Synthèse' },
        { page: 'edge-portal-catalog', key: 'p_dest',      label: 'Destinations' },
        { page: 'edge-portal-users',   key: 'p_users',     label: 'Utilisateurs' },
        { page: 'portal-sessions',     key: 'p_sessions',  label: 'Sessions' },
        { page: 'portal-approvals',    key: 'p_approvals', label: 'Approbations' },
        { page: 'portal-policy',       key: 'p_policy',    label: 'Politiques' },
        { page: 'portal-recordings',   key: 'p_recordings', label: 'Enregistrements' },
        { page: 'portal-templates',    key: 'p_templates', label: 'Modèles' },
        { page: 'portal-audit',        key: 'p_audit',     label: 'Audit' },
        { page: 'portal-settings',     key: 'p_settings',  label: 'Réglages' },
      ],
    },
    {
      root: 'security',
      tabs: [
        { page: 'security',          key: 'overview', label: 'Synthèse' },
        { page: 'security-vulns',    key: 'vulns',    label: 'Vulnérabilités' },
        { page: 'security-bans',     key: 'bans',     label: 'Bans' },
        { page: 'security-trace',    key: 'trace',    label: 'Traçage IP' },
        { page: 'security-ephor', key: 'ephor', label: 'Ephor' },
        { page: 'security-posture',  key: 'posture',  label: 'Score par proxy' },
      ],
    },
    {
      root: 'security-rules',
      tabs: [
        { page: 'security-rules',      key: 'a_rules', label: 'Règles' },
        { page: 'automation-flow',     key: 'a_flow',  label: 'Éditeur de flux' },
        { page: 'automation-schedules', key: 'a_sched', label: 'Planifications' },
        { page: 'automation-playbooks', key: 'a_pb',    label: 'Playbooks' },
        { page: 'rules-store',         key: 'a_store', label: 'Modèles' },
      ],
    },
    {
      root: 'alert-channels',
      tabs: [
        { page: 'alert-channels',     key: 'a_channels', label: 'Canaux' },
        { page: 'alerts',             key: 'a_routing',  label: 'Routage des alertes' },
        { page: 'automation-silences', key: 'a_silences', label: 'Mises en sourdine' },
      ],
    },
    {
      root: 'edge-security',
      tabs: [
        { page: 'edge-security',          key: 'overview', label: 'Synthèse' },
        { page: 'edge-security-vulns',    key: 'vulns',    label: 'Vulnérabilités' },
        { page: 'edge-security-bans',     key: 'bans',     label: 'Bans' },
        { page: 'edge-security-ephor', key: 'ephor', label: 'Ephor' },
        { page: 'edge-security-posture',  key: 'posture',  label: 'Score par proxy' },
      ],
    },
  ],

  // ── Titres de pages ───────────────────────────────────────────────────────
  pageTitles: {
    dashboard:          'Dashboard',
    infrastructure:     'Infrastructure',
    architecture:       'Infrastructure',
    'admin-trafic':     'Proxies',
    logs:               'Logs d\'accès',
    'logs-system':      'Logs système',
    settings:           'Paramètres',
    users:              'Utilisateurs',
    'acme-monitor':     'Domaines & certificats',
    snippets:           'Snippets',
    'auth-providers':   'Authentification (SSO)',
    plugins:            'Plugins WebAssembly',
    'error-pages':      'Pages d\'erreur',
    'docker-labels':    'Labels Docker / Kubernetes',
    tokens:             'Appairage',
    'edge-tokens':      'Appairage',
    'api-tokens':        'Mes tokens API',
    access:              'Accès',
    'access-policies':   'Politiques d\'accès',
    workspaces:          'Gestion d\'équipe',
    prism:              'Prism — Analyse',
    'edge-prism':       'Prism',
    alerts:             'Règles d\'alertes',
    'alert-channels':   'Canaux de notification',
    audit:              'Journal d\'audit',
    security:               'Sécurité — Vue globale',
    'security-bans':        'Bans — toutes les passerelles',
    'security-trace':       'Traçage IP — parcours complet',
    'security-vulns':       'Vulnérabilités — toutes les passerelles',
    'security-rules':       'Règles',
    'automation-flow':      'Éditeur de flux',
    'automation-history':   'Journal d\'automatisation',
    'automation-silences':  'Mises en sourdine',
    'automation-schedules': 'Planifications',
    'automation-playbooks': 'Playbooks',
    'rules-store':          'Modèles de flux',
    'mcp-access':           'Accès MCP',
    automation:             'Automatisation',
    backups:            'Sauvegardes',
    import:             'Import / Restore',
    onboarding:         'Assistant d\'intégration',
    'edge-trafic':      'Proxies',
    'edge-certs':       'Certificats TLS',
    'edge-logs-access': 'Logs d\'accès',
    'edge-logs-system': 'Logs système',
    'edge-prism':       'Prism',
    'admin-observability': 'Observabilité',
    'edge-observability': 'Observabilité',
    'obs-synthese':     'Synthèse',
    'edge-obs-synthese': 'Synthèse',
    'proxy-inspector':  'Vue Proxy',
    'edge-proxy-inspector': 'Vue Proxy',
    'obs-metrics':      'Métriques',
    'obs-alerts':       'Alertes et SLO',
    'edge-obs-alerts':  'Alertes et SLO',
    'edge-metrics':     'Métriques',
    'edge-tunnel':      'Tunnel L4 mTLS',
    'edge-security':           'Sécurité',
    'edge-security-vulns':     'Vulnérabilités',
    'edge-security-posture':   'Score par proxy',
    'edge-security-bans':      'Bans',
    'edge-cluster':     'Nœuds / Raft',
    'edge-settings':    'Paramètres passerelle',
    'edge-general':     'Paramètres généraux',
    'edge-waf':         'WAF',
    'edge-ipfilter':    'IP / GeoIP / Bot',
    'ip-profiles':      'Profils IP (Threat Feeds)',
    'edge-auth':        'Auth / SSO',
    portal:             'Portail Access',
    'portal-settings':  'Réglages Access',
    'portal-sessions':  'Sessions Access',
    'portal-approvals': 'Approbations Access',
    'portal-policy':    'Politiques Access',
    'portal-recordings': 'Enregistrements Access',
    'portal-templates': 'Templates Access',
    'portal-audit':     'Audit Access',
    'admin-portal-catalog': 'Catalogue Access',
    'edge-portal-catalog':  'Catalogue Access',
    'admin-portal-users':   'Users Access',
    'edge-portal-users':    'Users Access',
    smtp:               'SMTP',
    profile:            'Mon profil',
  },

  // ── Mots-clés de la recherche (Ctrl+K) ─────────────────────────────────────
  // Termes FR + EN qu'un utilisateur peut taper pour retrouver une page.
  // Ajouter ici toute nouvelle fonctionnalité qui vit dans une page existante.
  searchKeywords: {
    dashboard:            'accueil home vue d\'ensemble overview kpi',
    infrastructure:       'architecture topologie schéma topology diagram nœuds nodes agents passerelles gateways ha cluster',
    'admin-trafic':       'proxy proxies routage routing domaine host backend upstream load balancer répartition tcp udp stream l4 l7 alias redirection yaml dupliquer duplicate dry run rate limit limitation débit cache compression header en-têtes max_body_size timeout retry circuit breaker mirror',
    'edge-trafic':        'proxy proxies routage routing domaine host backend upstream load balancer répartition tcp udp stream l4 l7 alias redirection yaml dupliquer duplicate dry run rate limit limitation débit cache compression header en-têtes max_body_size timeout retry circuit breaker mirror',
    logs:                 'access logs requêtes requests http status ip live temps réel sse export',
    'edge-logs-access':   'access logs requêtes requests http status ip live temps réel sse export',
    'logs-system':        'system logs journaux système erreurs errors debug',
    'edge-logs-system':   'system logs journaux système erreurs errors debug',
    prism:                'analyse analytics carte map pays country géolocalisation geoip trafic top ips user-agent bots',
    'edge-prism':         'analyse analytics carte map pays country géolocalisation geoip trafic top ips user-agent bots',
    'obs-synthese':       'observabilité observability synthèse summary santé health latence latency erreurs',
    'edge-obs-synthese':  'observabilité observability synthèse summary santé health latence latency erreurs',
    'obs-metrics':        'métriques metrics prometheus grafana graphiques charts latence débit cpu mémoire',
    'edge-metrics':       'métriques metrics prometheus grafana graphiques charts latence débit cpu mémoire',
    'obs-alerts':         'alertes alerts slo sli objectifs budget d\'erreur error budget',
    'edge-obs-alerts':    'alertes alerts slo sli objectifs budget d\'erreur error budget',
    'proxy-inspector':    'vue proxy inspector détail requêtes par proxy',
    'edge-proxy-inspector': 'vue proxy inspector détail requêtes par proxy',
    audit:                'journal audit qui a fait quoi historique modifications traçabilité compliance',
    security:             'sécurité security synthèse waf ips bans attaques menaces',
    'security-vulns':     'vulnérabilités vulnerabilities cve scan trivy dépendances images',
    'edge-security-vulns': 'vulnérabilités vulnerabilities cve scan trivy dépendances images',
    'security-bans':      'bans ban ip bannir unban débannir blocklist seuils ephor',
    'security-trace':     'traçage trace tracer ip cidr parcours historique suivi attaquant malveillant timeline investigation forensic',
    'edge-security-bans': 'bans ban ip bannir unban débannir blocklist seuils ephor',
    'security-ephor':  'ephor détection comportementale anomalies auto-ban scoring',
    'edge-security-ephor': 'ephor détection comportementale anomalies auto-ban scoring',
    'security-posture':   'score par proxy posture note grade en-têtes headers hsts csp',
    'edge-security-posture': 'score par proxy posture note grade en-têtes headers hsts csp',
    'security-rules':     'automatisations règles rules automation si alors trigger action condition événement métrique seuil flux',
    'automation-flow':    'éditeur de flux flow editor visuel nœuds no-code workflow étapes approbation si sinon attente variables simulation',
    'automation-history': 'journal automatisation historique exécutions runs',
    'automation-silences': 'silences maintenance fenêtre mute suspendre alertes',
    'automation-schedules': 'planifications schedules cron planifié récurrent',
    'automation-playbooks': 'playbooks runbooks scénarios réponse incident manuel paramètres lancer',
    'rules-store':        'store modèles templates règles flux paramètres catalogue installer',
    automation:           'automatisation automation vue d\'ensemble',
    alerts:               'règles d\'alertes routage alert routing seuils thresholds',
    'alert-channels':     'canaux channels notification email slack teams discord telegram webhook pagerduty ntfy',
    'mcp-access':         'mcp ia ai claude assistant llm outils tools agent token',
    tokens:               'tokens appairage pairing enrôlement enroll rejoindre join nouvelle passerelle agent',
    'edge-tokens':        'tokens appairage pairing enrôlement enroll rejoindre join',
    'api-tokens':         'tokens api clé key bearer cli automatisation personnel',
    workspaces:           'équipe team espaces de travail workspaces scopes rbac rôles roles permissions groupes',
    users:                'utilisateurs users comptes accounts rôles roles admin operator viewer invitation',
    'access-policies':    'politiques d\'accès matrice domaines sujets rbac permissions',
    access:               'accès rbac équipes tokens certificats mcp',
    'acme-monitor':       'domaines certificats certificates domains acme let\'s encrypt tls ssl renouvellement renewal wildcard dns-01 http-01 expiration',
    'edge-certs':         'certificats tls ssl acme let\'s encrypt pem import renouvellement renewal expiration mtls',
    'edge-tunnel':        'tunnel l4 mtls mutual tls vpn site à site tcp chiffré',
    'edge-waf':           'waf pare-feu applicatif firewall owasp coraza règles rules sql injection xss mode détection blocage',
    'edge-ipfilter':      'ip filtre filter geoip pays country allowlist denylist liste blanche noire bot anti-bot crawler asn',
    'ip-profiles':        'profils ip threat feeds listes de menaces reputation blocklist abuseipdb spamhaus',
    'edge-auth':          'auth sso oidc oauth saml ldap authentification basic mfa forward auth login',
    'edge-cluster':       'nœuds raft cluster ha haute disponibilité réplication leader élection quorum pairs',
    'edge-general':       'paramètres généraux general settings ports http https hsts http2 http3 quic ocsp',
    'edge-http-timeouts': 'timeouts délais http read write idle header keepalive',
    'edge-settings':      'paramètres passerelle gateway settings waf ip auth certificats cluster snippets',
    settings:             'paramètres settings smtp mfa ha sauvegardes backups import profils ip snippets pages d\'erreur',
    'settings-mfa':       'mfa 2fa totp double authentification two-factor webauthn passkey',
    'ha-status':          'ha haute disponibilité high availability groupe group bascule failover pairs clé de groupe',
    smtp:                 'smtp email mail serveur d\'envoi notifications relais',
    backups:              'sauvegardes backups restauration restore snapshot export chiffré',
    import:               'import restore restauration migration nginx traefik caddy npm nginx proxy manager yaml json',
    onboarding:           'assistant d\'intégration onboarding premiers pas getting started wizard',
    plugins:              'plugins webassembly wasm extension règle auth signature wazero hooks sandbox',
    'auth-providers':     'sso oidc oauth saml ldap github google authelia authentik fournisseurs authentification basic forward auth',
    snippets:             'snippets extraits config réutilisable blocs en-têtes headers fragments',
    'error-pages':        'pages d\'erreur error pages 404 502 503 maintenance personnalisée html',
    'docker-labels':      'docker kubernetes labels étiquettes découverte discovery auto conteneurs containers swarm',
    portal:               'portail access portal zero trust ssh bastion sso destinations sessions accès distant',
    'portal-settings':    'réglages access portal settings domaine session durée mfa',
    'portal-sessions':    'sessions access connexions actives ssh terminate',
    'portal-approvals':   'approbations approvals validation demande d\'accès just-in-time jit',
    'portal-policy':      'politiques access policies règles qui peut accéder groupes',
    'portal-recordings':  'enregistrements recordings sessions ssh rejeu replay asciinema',
    'portal-templates':   'templates modèles html login catalogue personnalisation thème brand',
    'portal-audit':       'audit access journal connexions traçabilité',
    'admin-portal-catalog': 'catalogue destinations ssh docker tags access portal',
    'edge-portal-catalog':  'catalogue destinations ssh docker tags access portal',
    'admin-portal-users': 'utilisateurs access portail comptes invités',
    'edge-portal-users':  'utilisateurs access portail comptes invités',
    profile:              'mon profil profile mot de passe password langue language mfa avatar',
  },
};
