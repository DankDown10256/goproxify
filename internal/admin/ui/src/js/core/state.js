// ── État global de l'application ───────────────────────────────────────────
const state = {
  token:        localStorage.getItem('gpx_token') || '',
  page:         'dashboard',
  selectedCore: null,
  user:         null, // rempli après login : { id, email, role, is_super, teams, effective_scopes }
  timezone:     localStorage.getItem('gpx_tz') || '', // IANA (ex. Europe/Paris) — sync via /health
};

// ── Helpers de rôle (utilisent state.user) ────────────────────────────────
const Role = {
  isSuperAdmin: () => state.user?.role === 'superadmin',
  isAdmin:      () => state.user?.role === 'admin' || state.user?.role === 'superadmin',
  isOperator:   () => ['superadmin','admin','operator'].includes(state.user?.role),
  isViewer:     () => !!state.user,

  // Admin global = admin/superadmin sans scopes d'équipe
  isGlobalAdmin: () => Role.isAdmin() && !(state.user?.effective_scopes?.length > 0),

  // L'utilisateur peut-il supprimer ?
  canDelete: () => Role.isAdmin(),

  // L'utilisateur peut-il écrire (créer/modifier/désactiver) ?
  canWrite: () => Role.isOperator(),

  // L'utilisateur a-t-il un scope de type "core" explicite sur ce Core ?
  hasCoreScope: (nodeName) => {
    if (Role.isGlobalAdmin() || Role.isSuperAdmin()) return true;
    return (state.user?.effective_scopes || []).some(s =>
      s.type === 'core' && _globMatch(s.value, nodeName)
    );
  },

  // L'utilisateur a-t-il accès (via n'importe quel scope) à au moins un domaine de ce Core ?
  hasAccessToCore: (core) => {
    if (Role.isGlobalAdmin() || Role.isSuperAdmin()) return true;
    const scopes = state.user?.effective_scopes || [];
    return scopes.some(s => s.type === 'core' && _globMatch(s.value, core.node_name || core.id));
    // Note : l'accès via domain/proxy/server s'affiche aussi dans le Core qui héberge le domaine,
    // mais ce filtrage fin est géré à l'affichage des proxies, pas de la nav.
  },
};

// Mini glob-match JS (supporte * et ?)
function _globMatch(pattern, str) {
  if (!pattern || !str) return false;
  if (pattern === '*') return true;
  const re = new RegExp('^' + pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$');
  return re.test(str);
}
