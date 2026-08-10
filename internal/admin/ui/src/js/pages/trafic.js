// ── PAGE PARTAGÉE: Trafic (Admin + Core) ─────────────────────────────────
// ctx = { mode: 'admin'|'core' }
//
// Les deux modes partagent exactement le même design (toolbar, filtres, tuiles).
// Différences : mode core ajoute un bandeau statut Core ; pas de chips Core
// sur les cartes (contexte déjà connu) ; bouton "Nouveau flux" admin only.
//
// État persistant (survive la navigation) : window._tv, _tc, _tg, _ts, _tf
    // Mode Core : GET /proxies?core=… filtre par les périmètres (token_scopes) du Core.
async function renderTraficPage(ctx) {
  const mode    = ctx.mode || 'admin';
  const isAdmin = mode === 'admin';
  const core    = isAdmin ? null : (state.selectedCore);
  const coreLabel = core ? (core.display_name || core.node_name || core.id || '—') : '';

  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML = '';
  content.innerHTML = '<p style="color:var(--text2)">' + t('common.loading') + '</p>';

  // Persistent view state
  if (!window._tv)              window._tv = 'tuiles'; // 'tuiles' | 'table'
  if (!window._tc)              window._tc = 3;
  if (window._tg === undefined) window._tg = '';
  if (!window._ts)              window._ts = 'name';
  if (!window._tf)              window._tf = { status: '', type: '', source: '' };

  try {
    // Résoudre l'UUID token (évite nodes.id aléatoire / doublons node_name).
    let coreRef = '';
    if (!isAdmin && core) {
      const tokens = await api('GET', '/tokens?role=core').catch(() => []);
      const match = (tokens || []).filter(t => !t.revoked && (
        t.id === core.id || t.node_name === core.node_name || t.node_name === core.id
      ));
      // Préférer id exact, sinon token avec endpoint, sinon le premier (liste déjà triée).
      const best = match.find(t => t.id === core.id)
        || match.find(t => t.node_endpoint)
        || match[0]
        || null;
      coreRef = best?.id || core.node_name || core.id || '';
    }
    if (!isAdmin && !coreRef) {
      content.innerHTML = '<p style="color:var(--text2)">' + t('trafic.no_core') + '</p>';
      return;
    }
    const proxiesPath = (!isAdmin && coreRef)
      ? `/proxies?core=${encodeURIComponent(coreRef)}`
      : '/proxies';
    const [allProxies, nodesRes, domainsRes, tokensRes, healthRes] = await Promise.all([
      api('GET', proxiesPath).catch(() => []),
      isAdmin ? api('GET', '/nodes').catch(() => []) : Promise.resolve([]),
      isAdmin ? api('GET', '/domains').catch(() => []) : Promise.resolve([]),
      isAdmin ? api('GET', '/tokens?role=core').catch(() => []) : Promise.resolve([]),
      api('GET', '/backends/health').catch(() => ({ backends: {} })),
    ]);
    window._backendHealth = (healthRes && healthRes.backends) || {};

    const cores = (nodesRes || []).filter(n => n.role === 'core');
    window._coreNodes = cores;
    window._traficAll = allProxies || [];
    const allP = window._traficAll;

    // Droits Core (token scopes + délégation) — pour n'afficher que les Cores qui reçoivent vraiment la route.
    const domains = domainsRes || [];
    const now = Date.now();
    const coreTokens = (tokensRes || []).filter(t =>
      !t.revoked && !(t.expires_at && new Date(t.expires_at).getTime() <= now)
    );
    const coreAccessList = [];
    if (isAdmin && cores.length) {
      await Promise.all(cores.map(async (cr) => {
        const match = coreTokens.filter(t =>
          t.id === cr.id || t.node_name === cr.node_name || t.node_name === cr.id
        );
        const best = match.find(t => t.id === cr.id)
          || match.find(t => t.node_endpoint)
          || match[0]
          || null;
        // Sans token actif → aucun droit de réception (ne pas afficher le Core).
        if (!best) return;
        let scopes = [];
        try {
          scopes = await api('GET', `/tokens/${encodeURIComponent(best.id)}/scopes`) || [];
        } catch (_) {}
        coreAccessList.push({
          core: cr,
          tokenId: best.id,
          role: String(best.rbac_role || 'admin').toLowerCase(),
          scopes: (scopes || []).map(s => ({
            type: s.scope_type || s.type || '',
            value: s.value || s.scope_value || '',
          })),
        });
      }));
    }

    // ── Classification ──────────────────────────────────────────────────────
    // p.config peut être un objet JS (depuis l'API JSON) ou une string — on normalise ici.
    const getCfg = (p) => {
      if (!p.config) return {};
      if (typeof p.config === 'object') return p.config;
      return tryJSON(p.config) || {};
    };
    const getType   = (p) => (getCfg(p).type || p.type || 'http').toLowerCase();
    const isStreamP = (p) => { const t = getType(p); return t === 'tcp' || t === 'udp' || t === 'both'; };
    const isDockerP = (p) => (p.id||'').startsWith('docker:');
    const isK8sP    = (p) => (p.id||'').startsWith('k8s:');
    const getSrc    = (p) => isDockerP(p) ? 'docker' : isK8sP(p) ? 'k8s' : 'managed';

    const proxyItems  = allP.filter(p => !isStreamP(p));
    const streamItems = allP.filter(p =>  isStreamP(p));

    // ── Helpers ──────────────────────────────────────────────────────────────
    function rootDomain(host) {
      if (!host || host === '—') return '—';
      const h = host.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
      const parts = h.split('.');
      return parts.length > 2 ? parts.slice(-2).join('.') : h;
    }

    const typeBadge = (type) => {
      const t = (type || 'http').toUpperCase();
      const cls = t === 'HTTPS' ? 'tag-accent' : t === 'HTTP' ? 'tag-outline' : 'tag-neutral';
      return `<span class="tag ${cls}">${esc(t)}</span>`;
    };

    const featureBadges = (cfg) => {
      const sec = cfg.security || {};
      const a = 'width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"';
      const chip = (label, color, bg, svg) =>
        `<span title="${label}" style="display:inline-flex;align-items:center;gap:3px;padding:2px 6px 2px 5px;border-radius:99px;background:${bg};color:${color};font-size:10px;font-weight:500;white-space:nowrap;"><svg ${a}>${svg}</svg>${label}</span>`;
      const out = [];
      if (cfg.tls_enabled || cfg.tls_passthrough)
        out.push(chip('TLS','#a78bfa','rgba(167,139,250,.12)','<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>'));
      if (sec.jwt?.enabled || cfg.jwt?.enabled || cfg.mtls?.enabled || cfg.sso?.enabled || sec.sso?.enabled || cfg.auth || cfg.auth_provider_id)
        out.push(chip('Auth','#f472b6','rgba(244,114,182,.12)','<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>'));
      if (sec.waf?.enabled || cfg.waf?.enabled || sec.bot_protection?.enabled || cfg.bot?.enabled || cfg.rate_limit || cfg.ip_filter || cfg.geo_ip || cfg.cors || (cfg.snippet_ids&&cfg.snippet_ids.length))
        out.push(chip(t('trafic.security'),'#fb923c','rgba(251,146,60,.12)','<path d="M12 2 2 7l.01 5c0 5.55 3.84 10.74 9.99 12 6.15-1.26 9.99-6.45 9.99-12L22 7z"/>'));
      if (cfg.circuit_breaker || cfg.retry || cfg.canary?.backend || cfg.shadow?.backend || cfg.sticky_cookie)
        out.push(chip(t('trafic.resilience'),'#34d399','rgba(52,211,153,.12)','<path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/>'));
      if (cfg.lb === 'adaptive')
        out.push(chip(t('trafic.lb_adaptive'),'#fbbf24','rgba(251,191,36,.14)','<path d="M12 3v18"/><path d="M5 8h14"/><path d="M5 16h14"/><circle cx="8" cy="8" r="2" fill="currentColor" stroke="none"/><circle cx="16" cy="16" r="2" fill="currentColor" stroke="none"/>'));
      if (cfg.locations?.length)
        out.push(chip('Locations','#60a5fa','rgba(96,165,250,.12)','<path d="M3 3h6l3 3 3-3h6v6l-3 3 3 3v6h-6l-3-3-3 3H3v-6l3-3-3-3z"/>'));
      if (cfg.logging && cfg.logging.format !== 'off')
        out.push(chip('Logs','#94a3b8','rgba(148,163,184,.12)','<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>'));
      if (cfg.observability?.metrics?.prometheus?.enabled)
        out.push(chip('Prism','#818cf8','rgba(129,140,248,.12)','<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>'));
      if (cfg.websocket)
        out.push(chip('WS','#22d3ee','rgba(34,211,238,.12)','<path d="M5 12h14M12 5l7 7-7 7"/>'));
      return out.join('');
    };

    // Host couvert par un motif domaine (wildcard DNS 1 label) — aligné backend.
    const hostCovered = (host, pattern) => {
      if (typeof _domainHostCovered === 'function') return _domainHostCovered(host, pattern);
      host = String(host || '').toLowerCase().trim();
      pattern = String(pattern || '').toLowerCase().trim();
      if (!host || !pattern) return false;
      if (host === pattern) return true;
      if (pattern.startsWith('*.')) {
        const suffix = pattern.slice(1);
        if (!host.endsWith(suffix) || host.length <= suffix.length) return false;
        const rest = host.slice(0, host.length - suffix.length);
        return rest !== '' && !rest.includes('.');
      }
      return false;
    };

    const globMatch = (pattern, value) => {
      const p = String(pattern || '').toLowerCase();
      const v = String(value || '').toLowerCase();
      if (!p || !v) return false;
      if (p === v) return true;
      const re = new RegExp('^' + p.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$');
      return re.test(v);
    };

    // Même sémantique que rbac.RouteAllowedByToken.
    const routeAllowedByAccess = (acc, p, cfg) => {
      const role = acc.role || '';
      const scopes = acc.scopes || [];
      if (role === 'superadmin' || (role === 'admin' && scopes.length === 0)) return true;
      if (!scopes.length) return false;
      const hosts = [cfg.host || p.host, ...(cfg.aliases || [])].filter(Boolean);
      const backends = (cfg.backends || p.backends || []).map(b => b.url || b).filter(Boolean);
      return scopes.some(s => {
        if (s.type === 'core') return true;
        if (s.type === 'proxy') return s.value === p.id;
        if (s.type === 'domain') return hosts.some(h => hostCovered(h, s.value));
        if (s.type === 'server') return backends.some(u => globMatch(s.value, u));
        return false;
      });
    };

    const coreRefMatch = (acc, ref) => {
      ref = String(ref || '').trim();
      if (!ref) return false;
      const cr = acc.core;
      return cr.id === ref || cr.node_name === ref || acc.tokenId === ref;
    };

    // Cores qui reçoivent réellement la route (scopes + exclusion délégation).
    const coresForProxy = (p) => {
      const cfg = getCfg(p);
      const hosts = [cfg.host || p.host, ...(cfg.aliases || [])].filter(Boolean);
      const bindings = domains.filter(d => d.delegated_to_core_id && d.delegated_endpoint);

      return coreAccessList.filter(acc => {
        if (!routeAllowedByAccess(acc, p, cfg)) return false;
        for (const b of bindings) {
          const covered = hosts.some(h => hostCovered(h, b.domain));
          if (!covered) continue;
          // Seul le Core cible de la délégation conserve la route.
          return coreRefMatch(acc, b.delegated_to_core_id);
        }
        return true;
      }).map(acc => acc.core);
    };

    // Core chip — admin uniquement ; uniquement les Cores autorisés (pas tous les nœuds).
    const coreChipHtml = (p) => {
      if (!isAdmin) return '';
      const mkChip = (cr) => {
        const i = cores.indexOf(cr);
        const n = cr.display_name || cr.node_name || cr.id || 'Core';
        const dot = `<span style="display:inline-block;width:5px;height:5px;border-radius:50%;background:${cr.status==='online'?'var(--green)':'var(--text3)'};flex-shrink:0;margin-right:3px"></span>`;
        const click = i >= 0 ? `onclick="selectCore(window._coreNodes[${i}],'core-trafic')"` : '';
        return `<span ${click} title="Core : ${esc(n)}" style="display:inline-flex;align-items:center;font-size:10px;color:var(--text2);background:var(--bg3);padding:1px 6px;border-radius:4px;border:1px solid var(--border);${i>=0?'cursor:pointer;':''}white-space:nowrap">${dot}⚙ ${esc(n)}</span>`;
      };

      // Lien explicite legacy (si présent) — sinon dériver des droits.
      const coreId = p.node_id || p.core_id;
      if (coreId) {
        const acc = coreAccessList.find(a => coreRefMatch(a, coreId));
        const c = acc?.core || cores.find(x => x.id === coreId || x.node_name === coreId);
        if (c) return mkChip(c);
        return `<span style="font-size:10px;color:var(--text2);background:var(--bg3);padding:1px 6px;border-radius:4px;border:1px solid var(--border);white-space:nowrap">⚙ ${esc(coreId)}</span>`;
      }

      const allowed = coresForProxy(p);
      if (allowed.length) return allowed.map(mkChip).join('');
      return '';
    };

    // ── Filtres / Tri ─────────────────────────────────────────────────────────
    function applyFilters(items) {
      const af = window._tf;
      const q  = (document.getElementById('trafic-search')?.value || '').toLowerCase();
      return items.filter(p => {
        const cfg  = getCfg(p);
        const pType = getType(p);
        const src   = getSrc(p);
        const host  = cfg.host || p.host || p.name || '';
        const backs = (cfg.backends || p.backends || []).map(b => b.url || b).join(' ');
        const srch  = [host, p.name||'', backs, (cfg.aliases||[]).join(' ')].join(' ').toLowerCase();
        if (af.status === 'actif'   && p.enabled === false) return false;
        if (af.status === 'inactif' && p.enabled !== false) return false;
        if (af.type   && af.type !== pType) return false;
        if (af.source && af.source !== src)  return false;
        if (q && !srch.includes(q)) return false;
        return true;
      });
    }

    function sortItems(items) {
      const sb = window._ts || 'name';
      return [...items].sort((a, b) => {
        const ha = (getCfg(a).host || a.host || a.name || '');
        const hb = (getCfg(b).host || b.host || b.name || '');
        if (sb === 'name')         return ha.localeCompare(hb);
        if (sb === 'name_desc')    return hb.localeCompare(ha);
        if (sb === 'created_desc') return new Date(b.created_at||0) - new Date(a.created_at||0);
        if (sb === 'created_asc')  return new Date(a.created_at||0) - new Date(b.created_at||0);
        if (sb === 'status')       return ((b.enabled!==false)?1:0) - ((a.enabled!==false)?1:0);
        return 0;
      });
    }

    function getGroupKey(p) {
      const gb = window._tg || '';
      if (!gb) return null;
      const cfg = getCfg(p);
      if (gb === 'status') return p.enabled !== false ? t('trafic.active') : t('trafic.inactive');
      if (gb === 'type')   return getType(p).toUpperCase();
      if (gb === 'source') return getSrc(p);
      if (gb === 'domain') return rootDomain(cfg.host || p.host || p.name || '');
      return '—';
    }

    // ── Sélection (locale) ───────────────────────────────────────────────────
    const proxySel  = new Set();
    const streamSel = new Set();

    // ── Sécurité : alerte alignée sur ComputeHeaderScore (computeProxyHeaderScore) ─
    function proxySecAlert(cfg) {
      if (typeof computeProxyHeaderScore !== 'function') {
        const hasTLS = cfg.tls_enabled || cfg.tls_passthrough || cfg.type === 'https';
        if (!hasTLS) return { level: 'critical', label: t('trafic.no_tls') };
        return null;
      }
      const { score, checks } = computeProxyHeaderScore(cfg);
      const tls = checks.find(c => c.name === 'TLS activé');
      if (tls && !tls.present) return { level: 'critical', label: t('trafic.no_tls') };
      const missing = checks.filter(c => !c.present);
      if (missing.length >= 5 || score < 40)
        return { level: 'warning', label: t('trafic.sec_score', { score, n: missing.length }) };
      if (!checks.find(c => c.name === 'WAF activé')?.present
          && !checks.find(c => c.name === 'Authentification')?.present
          && !checks.find(c => c.name === 'Rate Limiting')?.present
          && !checks.find(c => c.name === 'Filtrage IP')?.present)
        return { level: 'warning', label: t('trafic.no_protection') };
      return null;
    }

    // ── Helper lien domaine ────────────────────────────────────────────────────
    function domainLink(d, isMaster, hasTLS) {
      const scheme = hasTLS ? 'https' : 'http';
      const href   = `${scheme}://${d}`;
      const fw     = isMaster ? '600' : '400';
      const fs     = isMaster ? '13px' : '11px';
      const col    = isMaster ? 'inherit' : 'var(--text2)';
      return `<a href="${esc(href)}" target="_blank" rel="noopener noreferrer"
        onclick="event.stopPropagation()"
        title="${esc(d)}"
        style="display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:${fw};font-size:${fs};color:${col};text-decoration:none;"
        onmouseover="this.style.textDecoration='underline'"
        onmouseout="this.style.textDecoration='none'">${esc(d)}</a>`;
    }

    // ── Helper liens backends (grille 2 col. + pastille santé) ─────────────────
    function backendURL(b) {
      return (typeof b === 'string' ? b : (b && b.url)) || '';
    }
    function backendHref(url) {
      if (!url) return '#';
      return /^[a-z][a-z0-9+.-]*:/i.test(url) ? url : 'http://' + url;
    }
    function backendStatus(url) {
      const map = window._backendHealth || {};
      // Aligné sur IsHealthy : inconnu = considéré UP jusqu'à preuve du contraire.
      return map[url] || 'up';
    }
    function backendStatusLabel(st) {
      if (st === 'up') return t('trafic.backend_up');
      if (st === 'down') return t('trafic.backend_down');
      if (st === 'degraded') return t('trafic.backend_degraded');
      return t('trafic.backend_unknown');
    }
    // Chaque chip est un <a href> vers CE backend ; pastille à gauche (col 0) ou à droite (col 1).
    function backendChip(b, index) {
      const url = backendURL(b);
      if (!url) return '';
      const st = backendStatus(url);
      const side = (index % 2 === 0) ? 'left' : 'right';
      const title = `${esc(url)} — ${backendStatusLabel(st)}`;
      const dot = `<span class="trafic-be-dot ${esc(st)}" aria-hidden="true"></span>`;
      const label = `<span class="trafic-be-url">${esc(url)}</span>`;
      return `<a class="trafic-be is-${side}" href="${esc(backendHref(url))}" target="_blank" rel="noopener noreferrer"
        onclick="event.stopPropagation()" title="${title}">${side === 'left' ? dot + label : label + dot}</a>`;
    }
    function backendsGridHtml(allBackends) {
      if (!allBackends.length) {
        return `<div class="trafic-backends"><span class="trafic-be-empty">—</span></div>`;
      }
      return `<div class="trafic-backends">${allBackends.map((b, i) => backendChip(b, i)).join('')}</div>`;
    }
    // Compat mode tableau / anciens appels.
    function backendLink(b) {
      return backendChip(b, 0);
    }

    // ── Rendu tuile ──────────────────────────────────────────────────────────
    function buildTile(p, selSet) {
      const cfg = getCfg(p);
      const type = getType(p);
      const host = cfg.host || p.host || p.name || '—';
      const enabled = p.enabled !== false;
      const isAuto  = isDockerP(p) || isK8sP(p);
      const isStr   = isStreamP(p);
      const isSel   = selSet.has(p.id);
      const hasTLS  = cfg.tls_enabled || cfg.tls_passthrough || type === 'https';
      const allDomains = [host, ...(cfg.aliases||[])].filter(Boolean);
      const allBackends = (cfg.backends || p.backends || []).filter(Boolean);
      const chips = coreChipHtml(p);
      const badges = featureBadges(cfg);
      const stype = isStr ? 'stream' : 'proxy';
      const secAlert = !isStr ? proxySecAlert(cfg) : null;

      const toggleEl = Role.canWrite()
        ? `<label class="toggle" style="flex-shrink:0;margin:0;"><input type="checkbox" ${enabled?'checked':''} ${isAuto?'disabled':''} onchange="traficToggle('${esc(p.id)}',${enabled})"><span class="toggle-slider"></span></label>`
        : `<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${enabled?'var(--green)':'var(--text3)'};flex-shrink:0;"></span>`;
      const editBtn = Role.canWrite() && !isAuto && !isStr
        ? `<button class="btn btn-ghost btn-icon" onclick="openProxyModal('${esc(p.id)}')" title="${esc(t('common.edit'))}"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>` : '';
      const delBtn = Role.canDelete() && !isAuto
        ? `<button class="btn btn-ghost btn-icon" onclick="traficDelete('${esc(p.id)}')" title="${esc(t('common.delete'))}"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3 6h18"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg></button>` : '';

      const secBadgeColor = secAlert?.level === 'critical' ? 'var(--red)' : 'var(--yellow,#f59e0b)';
      const secBtn = !isStr
        ? `<button class="btn btn-ghost btn-icon" onclick="openProxySecModal('${esc(p.id)}')" title="${secAlert ? t('trafic.security_prefix') + secAlert.label : t('trafic.security')}" style="position:relative;">
             <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="color:${secAlert?secBadgeColor:'var(--text2)'}"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>${secAlert?'':'<path d="m9 12 2 2 4-4" stroke-width="2"/>'}</svg>
             ${secAlert ? `<span style="position:absolute;top:0px;right:0px;width:7px;height:7px;border-radius:50%;background:${secBadgeColor};border:1.5px solid var(--bg2);pointer-events:none;"></span>` : ''}
           </button>` : '';

      const labelsBtn = `<button class="btn btn-ghost btn-icon" onclick="openDockerLabelsFromProxy('${esc(p.id)}')" title="${esc(t('trafic.docker_labels'))}"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="2" y="8" width="20" height="10" rx="2"/><path d="M6 8V6h3v2M11 8V5h3v3M16 8V6h3v2"/></svg></button>`;
      const flowBtn = `<button class="btn btn-ghost btn-icon" onclick="openTrafficFlowModal('proxy','${esc(p.id)}')" title="${esc(t('trafic.flow_title'))}"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="19" r="2"/><circle cx="18" cy="5" r="2"/><circle cx="6" cy="5" r="2"/><path d="M18 7v4a2 2 0 0 1-2 2H8a2 2 0 0 0-2 2v2"/></svg></button>`;

      const domainsHtml = allDomains.map((d, i) => domainLink(d, i === 0, hasTLS)).join('');

      return `<div class="trafic-tile${isSel?' is-selected':''}" onmouseover="if(!${isSel})this.style.borderColor='var(--accent)'" onmouseout="if(!${isSel})this.style.borderColor='var(--border)'">
        <div class="trafic-tile-head">
          <input type="checkbox" ${isSel?'checked':''} onchange="traficSelToggle('${esc(p.id)}','${stype}')" style="width:14px;height:14px;cursor:pointer;accent-color:var(--accent);flex-shrink:0">
          ${toggleEl}
          ${typeBadge(type)}
          <div class="trafic-tile-actions">
            <button class="btn btn-ghost btn-icon" onclick="logsFilters.domain='${esc(host)}';navigate('logs')" title="${esc(t('trafic.access_logs'))}"><svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M7 8h10M7 12h10M7 16h6"/></svg></button>
            <button class="btn btn-ghost btn-icon" onclick="openPrismForProxy('${esc(host)}','${esc(p.node_id||p.core_id||'')}')" title="Prism"><svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M18 20V10M12 20V4M6 20v-6"/></svg></button>
            ${flowBtn}${labelsBtn}${secBtn}${editBtn}${delBtn}
          </div>
        </div>
        <div style="min-width:0;margin-bottom:7px">${domainsHtml}${chips?`<div style="margin-top:4px;display:flex;flex-wrap:wrap;gap:3px">${chips}</div>`:''}</div>
        ${badges?`<div style="display:flex;flex-wrap:wrap;gap:3px;margin-bottom:7px">${badges}</div>`:''}
        ${backendsGridHtml(allBackends)}
      </div>`;
    }

    // ── Rendu ligne tableau ──────────────────────────────────────────────────
    function buildRow(p, selSet) {
      const cfg = getCfg(p);
      const type = getType(p);
      const host = cfg.host || p.host || p.name || '—';
      const enabled = p.enabled !== false;
      const isAuto  = isDockerP(p) || isK8sP(p);
      const isStr   = isStreamP(p);
      const isSel   = selSet.has(p.id);
      const hasTLS  = cfg.tls_enabled || cfg.tls_passthrough || type === 'https';
      const chips = coreChipHtml(p);
      const badges = featureBadges(cfg);
      const stype = isStr ? 'stream' : 'proxy';
      const allBackends = (cfg.backends || p.backends || []).filter(Boolean);
      const secAlert = !isStr ? proxySecAlert(cfg) : null;

      const toggleEl = Role.canWrite()
        ? `<label class="toggle" style="margin:0 4px;"><input type="checkbox" ${enabled?'checked':''} ${isAuto?'disabled':''} onchange="traficToggle('${esc(p.id)}',${enabled})"><span class="toggle-slider"></span></label>`
        : `<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${enabled?'var(--green)':'var(--text3)'};margin:0 10px;"></span>`;
      const editBtn = Role.canWrite() && !isAuto && !isStr
        ? `<button class="btn btn-ghost btn-icon" onclick="openProxyModal('${esc(p.id)}')" title="${esc(t('common.edit'))}"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>` : '';
      const delBtn = Role.canDelete() && !isAuto
        ? `<button class="btn btn-ghost btn-icon" onclick="traficDelete('${esc(p.id)}')" title="${esc(t('common.delete'))}"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3 6h18"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg></button>` : '';

      const secBadgeColor = secAlert?.level === 'critical' ? 'var(--red)' : 'var(--yellow,#f59e0b)';
      const secBtn = !isStr
        ? `<button class="btn btn-ghost btn-icon" onclick="openProxySecModal('${esc(p.id)}')" title="${secAlert ? t('trafic.security_prefix') + secAlert.label : t('trafic.security')}" style="position:relative;">
             <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="color:${secAlert?secBadgeColor:'var(--text2)'}"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>${secAlert?'':'<path d="m9 12 2 2 4-4" stroke-width="2"/>'}</svg>
             ${secAlert ? `<span style="position:absolute;top:0px;right:0px;width:7px;height:7px;border-radius:50%;background:${secBadgeColor};border:1.5px solid var(--bg2);pointer-events:none;"></span>` : ''}
           </button>` : '';

      const labelsBtn = `<button class="btn btn-ghost btn-icon" onclick="openDockerLabelsFromProxy('${esc(p.id)}')" title="${esc(t('trafic.docker_labels'))}"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="2" y="8" width="20" height="10" rx="2"/><path d="M6 8V6h3v2M11 8V5h3v3M16 8V6h3v2"/></svg></button>`;
      const flowBtn = `<button class="btn btn-ghost btn-icon" onclick="openTrafficFlowModal('proxy','${esc(p.id)}')" title="${esc(t('trafic.flow_title'))}"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="19" r="2"/><circle cx="18" cy="5" r="2"/><circle cx="6" cy="5" r="2"/><path d="M18 7v4a2 2 0 0 1-2 2H8a2 2 0 0 0-2 2v2"/></svg></button>`;

      const hostLink = `<a href="${hasTLS?'https':'http'}://${esc(host)}" target="_blank" rel="noopener noreferrer"
        onclick="event.stopPropagation()"
        style="display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:500;color:inherit;text-decoration:none;"
        onmouseover="this.style.textDecoration='underline'" onmouseout="this.style.textDecoration='none'"
        title="${esc(host)}">${esc(host)}</a>`;

      const beLinksHtml = allBackends.length
        ? allBackends.map((b, i) => {
            const url = backendURL(b);
            const st = backendStatus(url);
            return `<a href="${esc(backendHref(url))}" target="_blank" rel="noopener noreferrer"
              onclick="event.stopPropagation()"
              style="display:inline-flex;align-items:center;gap:4px;font-family:monospace;font-size:11px;color:var(--text2);text-decoration:none;max-width:100%;"
              onmouseover="this.style.textDecoration='underline'" onmouseout="this.style.textDecoration='none'"
              title="${esc(url)} — ${backendStatusLabel(st)}"><span class="trafic-be-dot ${esc(st)}" style="display:inline-block;"></span><span style="overflow:hidden;text-overflow:ellipsis;">${esc(url)}</span></a>`;
          }).join('<span style="color:var(--text3);padding:0 2px;"> </span>')
        : '—';

      return `<tr style="border-bottom:1px solid var(--border);transition:background .12s;${isSel?'background:var(--accent-dim,rgba(99,102,241,.07))':''}" onmouseover="this.style.background='var(--bg2)'" onmouseout="this.style.background='${isSel?'var(--accent-dim,rgba(99,102,241,.07))':''}'">
        <td style="padding:8px 10px;white-space:nowrap">
          <div style="display:flex;align-items:center;gap:4px">
            <input type="checkbox" ${isSel?'checked':''} onchange="traficSelToggle('${esc(p.id)}','${stype}')" style="width:13px;height:13px;cursor:pointer;accent-color:var(--accent)">
            ${toggleEl}
          </div>
        </td>
        <td style="padding:8px 10px">${typeBadge(type)}</td>
        <td style="padding:8px 10px;font-size:12px;max-width:220px">
          ${hostLink}
          ${chips?`<div style="display:flex;flex-wrap:wrap;gap:3px;margin-top:3px">${chips}</div>`:''}
        </td>
        <td style="padding:8px 10px;font-size:11px;color:var(--text2);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${beLinksHtml}</td>
        <td style="padding:8px 10px"><div style="display:flex;flex-wrap:wrap;gap:2px">${badges||'<span style="color:var(--text3);font-size:11px">—</span>'}</div></td>
        <td style="padding:8px 10px;white-space:nowrap;text-align:right">
          <button class="btn btn-ghost btn-icon" onclick="logsFilters.domain='${esc(host)}';navigate('logs')" title="${esc(t('trafic.access_logs'))}"><svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M7 8h10M7 12h10M7 16h6"/></svg></button>
          <button class="btn btn-ghost btn-icon" onclick="openPrismForProxy('${esc(host)}','${esc(p.node_id||p.core_id||'')}')" title="Prism"><svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M18 20V10M12 20V4M6 20v-6"/></svg></button>
          ${flowBtn}${labelsBtn}${secBtn}${editBtn}${delBtn}
        </td>
      </tr>`;
    }

    // ── Rendu section (tuiles ou tableau avec groupes) ────────────────────────
    function renderSectionContent(label, icon, items, newBtn, stype) {
      const filtered = applyFilters(items);
      const sorted   = sortItems(filtered);
      const gb   = window._tg || '';
      const cols = window._tc || 3;
      const selSet = stype === 'stream' ? streamSel : proxySel;

      const selCount = [...selSet].filter(id => items.some(p => p.id === id)).length;
      const bulkHtml = selCount ? (() => {
        const enableBtns = Role.canWrite()
          ? `<button class="btn btn-secondary btn-sm" onclick="traficBulkEnable('${stype}',true)">${t('trafic.enable')}</button><button class="btn btn-secondary btn-sm" onclick="traficBulkEnable('${stype}',false)">${t('trafic.disable')}</button>` : '';
        const delBtn = Role.canDelete()
          ? `<button class="btn btn-secondary btn-sm" style="color:var(--red);border-color:var(--red);" onclick="traficBulkDelete('${stype}')">${t('common.delete')}</button>` : '';
        return `<div class="trafic-bulk-bar">
          <span style="font-weight:600;color:var(--accent)">${t('trafic.selected', { n: selCount })}</span>
          <div style="width:1px;height:16px;background:var(--border);margin:0 2px;"></div>
          ${enableBtns}${delBtn}
          <button class="btn btn-ghost btn-sm" style="margin-left:auto;" onclick="traficSelClear('${stype}')">${t('common.cancel')}</button>
        </div>`;
      })() : '';

      const headerHtml = `
        <div class="trafic-section-head">
          ${icon}
          <span style="font-size:15px;font-weight:600;font-family:var(--font-heading)">${label}</span>
          <span style="font-size:11px;color:var(--text2);background:var(--bg3);padding:1px 8px;border-radius:99px;border:1px solid var(--border)">${filtered.length}</span>
          ${newBtn?`<div class="trafic-section-actions">${newBtn}</div>`:''}
        </div>`;

      if (window._tv === 'table') {
        const rows = sorted.map(p => buildRow(p, selSet)).join('');
        const tableHtml = sorted.length ? `<div class="card blueprint" style="overflow:hidden"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <div class="table-wrap"><table class="table"><thead><tr>
            <th style="width:60px"></th><th>${t('trafic.type')}</th><th>${t('trafic.domain')}</th><th>${t('trafic.backends')}</th><th>${t('trafic.features')}</th><th style="text-align:right">${t('trafic.actions')}</th>
          </tr></thead><tbody>${rows}</tbody></table></div></div>`
          : `<p style="color:var(--text2);font-size:13px;padding:8px 2px">${t('trafic.no_match')}</p>`;
        return headerHtml + bulkHtml + tableHtml;
      }

      // Tuiles
      if (!sorted.length) {
        return headerHtml + `<p style="color:var(--text2);font-size:13px;padding:8px 2px">${t('trafic.no_match')}</p>`;
      }

      if (!gb) {
        return headerHtml + bulkHtml +
          `<div class="trafic-grid" data-cols="${cols}">${sorted.map(p => buildTile(p, selSet)).join('')}</div>`;
      }

      // Groupés
      const gmap = {};
      sorted.forEach(p => {
        const k = getGroupKey(p) || '—';
        if (!gmap[k]) gmap[k] = [];
        gmap[k].push(p);
      });
      const gkeys = Object.keys(gmap).sort((a,b) => a.localeCompare(b));
      const subHtml = gkeys.map(k =>
        `<div style="margin-bottom:18px">
          <div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.04em;color:var(--text3);margin-bottom:8px;padding-bottom:4px;border-bottom:1px solid var(--border)">${esc(k)} <span style="font-weight:400">${gmap[k].length}</span></div>
          <div class="trafic-grid" data-cols="${cols}">${gmap[k].map(p => buildTile(p, selSet)).join('')}</div>
        </div>`
      ).join('');
      return headerHtml + bulkHtml + subHtml;
    }

    // ── Bandeau Core (mode core uniquement) ──────────────────────────────────
    const coreBannerHtml = () => {
      if (isAdmin || !core) return '';
      const statusOk = core.status === 'online';
      const statusHtml = statusOk
        ? `<span class="tag tag-green" style="font-size:11px;">${t('trafic.online')}</span>`
        : `<span class="tag tag-red" style="font-size:11px;">${t('trafic.offline')}</span>`;
      const cpuHtml = core.cpu_pct != null
        ? `<div style="text-align:center;"><div style="font-size:18px;font-weight:700;font-family:var(--font-heading)">${Math.round(core.cpu_pct)}%</div><div style="font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:var(--text3)">CPU</div></div>` : '';
      const memHtml = core.mem_pct != null
        ? `<div style="text-align:center;"><div style="font-size:18px;font-weight:700;font-family:var(--font-heading)">${Math.round(core.mem_pct)}%</div><div style="font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:var(--text3)">${t('trafic.memory')}</div></div>` : '';
      return `<div class="card blueprint" style="padding:16px 20px;display:flex;align-items:center;gap:20px;flex-wrap:wrap;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div style="flex:1;min-width:0;">
          <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:4px;">
            <span style="font-size:10px;text-transform:uppercase;letter-spacing:.07em;font-weight:600;color:var(--text3)">Data Plane</span>
            ${statusHtml}
            ${core.version ? `<span style="font-size:10px;color:var(--text3);font-family:monospace">${esc(core.version)}</span>` : ''}
          </div>
          <div style="font-size:20px;font-weight:700;font-family:var(--font-heading);margin-bottom:2px;">${esc(coreLabel)}</div>
          ${core.endpoint ? `<div style="font-size:11px;color:var(--text3);font-family:monospace;">${esc(core.endpoint)}</div>` : ''}
        </div>
        ${(cpuHtml || memHtml) ? `<div style="display:flex;gap:24px;padding:0 8px;border-left:1px solid var(--border);">${cpuHtml}${memHtml}</div>` : ''}
        <div style="display:flex;gap:8px;flex-wrap:wrap;">
          <button class="btn btn-secondary btn-sm blueprint" onclick="navigate('core-logs-access')"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>Logs</button>
          <button class="btn btn-secondary btn-sm blueprint" onclick="navigate('core-metrics')"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>${t('trafic.metrics')}</button>
        </div>
      </div>`;
    };

    // ── Toolbar et filter chips HTML ─────────────────────────────────────────
    const fchip = (key, val, label) => {
      const active = window._tf[key] === val;
      return `<button onclick="traficFilter('${key}','${val}')" style="font-size:11px;padding:3px 10px;border-radius:99px;border:1px solid ${active?'var(--accent)':'var(--border)'};background:${active?'var(--accent)':'transparent'};color:${active?'#fff':'var(--text2)'};cursor:pointer;transition:all .15s">${label}</button>`;
    };

    const colsSelector = () => [2,3,4,5].map((n,i) =>
      `<div style="display:flex;align-items:center">${i>0?'<div style="width:12px;height:2px;background:var(--border)"></div>':''}<button data-cols="${n}" onclick="setTraficCols(${n})" title="${t('trafic.cols', { n })}" style="width:12px;height:12px;border-radius:50%;border:2px solid ${window._tc===n?'var(--accent)':'var(--border)'};background:${window._tc===n?'var(--accent)':'var(--bg)'};cursor:pointer;padding:0;transition:all .15s;flex-shrink:0"></button></div>`
    ).join('');

    const iconGrid  = `<svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="3" y="3" width="8" height="8" rx="1"/><rect x="13" y="3" width="8" height="8" rx="1"/><rect x="3" y="13" width="8" height="8" rx="1"/><rect x="13" y="13" width="8" height="8" rx="1"/></svg>`;
    const iconTable = `<svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18M3 15h18M9 3v18"/></svg>`;

    const isTile  = window._tv === 'tuiles';
    const isTable = window._tv === 'table';

    const importBtn = `<button class="btn btn-secondary btn-sm" onclick="openTraficImport()" title="${esc(t('trafic.import_hint'))}"><svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="margin-right:4px"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>${t('trafic.import')}</button>`;
    const csvBtn   = `<button class="btn btn-secondary btn-sm" onclick="traficExportCSV()" title="${esc(t('trafic.export_csv'))}"><svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="margin-right:4px"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>CSV</button>`;

    const toolbarHtml = `
      <div class="trafic-toolbar">
        <input id="trafic-search" class="input search-input trafic-search" placeholder="${esc(t('trafic.search_proxy'))}" oninput="renderPage()">
        <span id="trafic-count" style="font-size:12px;color:var(--text2);white-space:nowrap">${allP.length!==1?t('trafic.proxy_count_n',{n:allP.length}):t('trafic.proxy_count',{n:allP.length})}</span>
        <select id="trafic-groupby" onchange="setTraficGroupBy(this.value)" style="height:30px;font-size:12px;padding:0 6px;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg2);color:var(--text);cursor:pointer;max-width:100%">
          <option value="" ${!window._tg?'selected':''}>${t('trafic.group_none')}</option>
          <option value="status" ${window._tg==='status'?'selected':''}>${t('trafic.group_status')}</option>
          <option value="type"   ${window._tg==='type'  ?'selected':''}>${t('trafic.group_type')}</option>
          <option value="source" ${window._tg==='source'?'selected':''}>${t('trafic.group_source')}</option>
          <option value="domain" ${window._tg==='domain'?'selected':''}>${t('trafic.group_domain')}</option>
        </select>
        <select id="trafic-sortby" onchange="setTraficSortBy(this.value)" style="height:30px;font-size:12px;padding:0 6px;border:1px solid var(--border);border-radius:var(--radius);background:var(--bg2);color:var(--text);cursor:pointer;max-width:100%">
          <option value="name"         ${(window._ts||'name')==='name'        ?'selected':''}>${t('trafic.sort_name')}</option>
          <option value="name_desc"    ${window._ts==='name_desc'             ?'selected':''}>${t('trafic.sort_name_desc')}</option>
          <option value="created_desc" ${window._ts==='created_desc'          ?'selected':''}>${t('trafic.sort_recent')}</option>
          <option value="created_asc"  ${window._ts==='created_asc'           ?'selected':''}>${t('trafic.sort_oldest')}</option>
          <option value="status"       ${window._ts==='status'                ?'selected':''}>${t('trafic.sort_active')}</option>
        </select>
        <div class="trafic-toolbar-actions">
          ${importBtn}
          <span class="trafic-toolbar-sep"></span>
          ${csvBtn}
          <span class="trafic-toolbar-sep"></span>
          <button onclick="setTraficView('tuiles')" title="${esc(t('trafic.view_tiles'))}" style="padding:5px 7px;border:1px solid ${isTile?'var(--accent)':'var(--border)'};background:${isTile?'var(--bg3)':'transparent'};border-radius:var(--radius);cursor:pointer;color:var(--text);display:flex;align-items:center">${iconGrid}</button>
          ${isTile ? `<span class="trafic-toolbar-sep"></span><div class="trafic-cols-selector" title="${esc(t('trafic.cols', { n: window._tc || 3 }))}">${colsSelector()}</div><span class="trafic-toolbar-sep"></span>` : ''}
          <button onclick="setTraficView('table')" title="${esc(t('trafic.view_table'))}" style="padding:5px 7px;border:1px solid ${isTable?'var(--accent)':'var(--border)'};background:${isTable?'var(--bg3)':'transparent'};border-radius:var(--radius);cursor:pointer;color:var(--text);display:flex;align-items:center">${iconTable}</button>
        </div>
      </div>`;

    const filterChipsHtml = `
      <div class="trafic-filters">
        <span style="font-size:11px;color:var(--text3)">${t('trafic.status_lbl')}</span>
        ${fchip('status','',t('trafic.all'))}${fchip('status','actif',t('trafic.active'))}${fchip('status','inactif',t('trafic.inactive'))}
        <span class="trafic-filters-sep"></span>
        <span style="font-size:11px;color:var(--text3)">${t('trafic.type_lbl')}</span>
        ${fchip('type','',t('trafic.all'))}${fchip('type','http','HTTP')}${fchip('type','https','HTTPS')}${fchip('type','tcp','TCP')}${fchip('type','udp','UDP')}${fchip('type','both','TCP+UDP')}
        <span class="trafic-filters-sep"></span>
        <span style="font-size:11px;color:var(--text3)">${t('trafic.source_lbl')}</span>
        ${fchip('source','',t('trafic.all'))}${fchip('source','docker','Docker')}${fchip('source','k8s','K8s')}${fchip('source','managed','Managed')}
      </div>`;

    // ── HTML principal ───────────────────────────────────────────────────────
    content.innerHTML = `
      <div class="trafic-page">
        <div>
          <h1 class="trafic-page-title">${t('trafic.title')}</h1>
          <p class="trafic-page-sub">${isAdmin ? t('trafic.sub_admin') : t('trafic.sub_core', { name: '<strong>'+esc(coreLabel)+'</strong>' })}</p>
        </div>

        ${coreBannerHtml()}

        ${toolbarHtml}
        ${filterChipsHtml}

        <div id="trafic-proxies-section"></div>
        <div id="trafic-streams-section"></div>

        <div id="trafic-containers-section" style="display:flex;flex-direction:column;gap:16px;min-width:0;">
          <div class="trafic-section-head" style="margin-bottom:0;justify-content:space-between;">
            <h2 style="margin:0;font-size:18px;font-family:var(--font-heading);">${t('trafic.containers')}<span id="trafic-containers-count" style="font-size:13px;font-weight:400;opacity:.55;font-family:var(--font-body);margin-left:8px;"></span></h2>
            <button class="btn btn-secondary btn-sm trafic-section-actions" onclick="loadContainers()">${t('trafic.refresh')}</button>
          </div>
          <div id="trafic-containers-content"><p style="color:var(--text2);font-size:13px;">${t('common.loading')}</p></div>
        </div>
      </div>
      <div id="trafic-modal-container"></div>`;

    // ── renderPage (re-render sections) ──────────────────────────────────────
    const renderPage = () => {
      const af = window._tf;
      const typeF = af.type;
      const showProxies = !typeF || typeF === 'http' || typeF === 'https';
      const showStreams  = !typeF || typeF === 'tcp'  || typeF === 'udp' || typeF === 'both';

      const filtTotal = applyFilters(allP).length;
      const cntEl = document.getElementById('trafic-count');
      if (cntEl) cntEl.textContent = filtTotal!==1 ? t('trafic.proxy_count_n', { n: filtTotal }) : t('trafic.proxy_count', { n: filtTotal });

      const proxyIcon  = `<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M2 8h12M9 4l5 4-5 4"/></svg>`;
      const streamIcon = `<svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M5 12h14M15 6l6 6-6 6"/></svg>`;

      const newProxyBtn = Role.canWrite()
        ? `<button class="btn btn-primary btn-sm" onclick="openProxyModal()"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:4px"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>${t('trafic.new_proxy')}</button>` : '';
      const newStreamBtn = isAdmin && Role.canWrite()
        ? `<button class="btn btn-primary btn-sm" onclick="openNewStreamModal()"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:4px"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>${t('trafic.new_stream')}</button>` : '';

      const pSec = document.getElementById('trafic-proxies-section');
      const sSec = document.getElementById('trafic-streams-section');
      if (pSec) {
        pSec.style.display = showProxies ? '' : 'none';
        if (showProxies) pSec.innerHTML = renderSectionContent(t('trafic.proxies'), proxyIcon, proxyItems, newProxyBtn, 'proxy');
      }
      if (sSec) {
        sSec.style.display = showStreams ? '' : 'none';
        if (showStreams) sSec.innerHTML = renderSectionContent(t('trafic.streams'), streamIcon, streamItems, newStreamBtn, 'stream');
      }
    };

    // ── window.* handlers ────────────────────────────────────────────────────
    window.renderPage = renderPage;

    window.traficFilter = (key, val) => {
      window._tf[key] = val;
      content.querySelectorAll('[onclick*="traficFilter"]').forEach(btn => {
        const m = btn.getAttribute('onclick').match(/traficFilter\('(\w+)','([^']*)'\)/);
        if (!m) return;
        const active = window._tf[m[1]] === m[2];
        btn.style.borderColor = active ? 'var(--accent)' : 'var(--border)';
        btn.style.background  = active ? 'var(--accent)' : 'transparent';
        btn.style.color       = active ? '#fff' : 'var(--text2)';
      });
      renderPage();
    };

    window.setTraficView = (v) => {
      window._tv = v;
      // Rebuild full page to update toolbar icons (view buttons + col selector)
      renderTraficPage(ctx);
    };
    window.setTraficCols = (n) => {
      window._tc = n;
      renderTraficPage(ctx);
    };
    window.setTraficGroupBy = (v) => { window._tg = v; renderPage(); };
    window.setTraficSortBy  = (v) => { window._ts = v; renderPage(); };

    window.traficToggle = async (id, currently) => {
      await api('PATCH', `/proxies/${id}`, { enabled: !currently });
      const p = allP.find(x => x.id === id);
      if (p) p.enabled = !currently;
      renderPage();
    };

    window.traficDelete = async (id) => {
      if (!confirm(t('trafic.delete_proxy'))) return;
      await api('DELETE', `/proxies/${id}`);
      allP.splice(0, allP.length, ...allP.filter(p => p.id !== id));
      proxyItems.splice(0, proxyItems.length,  ...proxyItems.filter(p => p.id !== id));
      streamItems.splice(0, streamItems.length, ...streamItems.filter(p => p.id !== id));
      renderPage();
    };

    window.traficSelToggle = (id, stype) => {
      const set = stype === 'stream' ? streamSel : proxySel;
      set.has(id) ? set.delete(id) : set.add(id);
      renderPage();
    };
    window.traficSelClear = (stype) => {
      if (stype === 'stream') streamSel.clear(); else proxySel.clear();
      renderPage();
    };

    window.traficBulkEnable = async (stype, enabled) => {
      const set = stype === 'stream' ? streamSel : proxySel;
      await Promise.all([...set].map(id => api('PATCH', `/proxies/${id}`, { enabled })));
      allP.forEach(p => { if (set.has(p.id)) p.enabled = enabled; });
      set.clear(); renderPage();
    };
    window.traficBulkDelete = async (stype) => {
      const set = stype === 'stream' ? streamSel : proxySel;
      if (!set.size || !confirm(t('trafic.delete_n', { n: set.size }))) return;
      await Promise.all([...set].map(id => api('DELETE', `/proxies/${id}`)));
      const ids = [...set];
      allP.splice(0, allP.length, ...allP.filter(p => !ids.includes(p.id)));
      proxyItems.splice(0, proxyItems.length,  ...proxyItems.filter(p => !ids.includes(p.id)));
      streamItems.splice(0, streamItems.length, ...streamItems.filter(p => !ids.includes(p.id)));
      set.clear(); renderPage();
    };

    window.traficExportCSV = () => {
      const af = window._tf;
      const q  = (document.getElementById('trafic-search')?.value || '').toLowerCase();
      const filtered = allP.filter(p => {
        const cfg = getCfg(p);
        const pType = getType(p);
        const src   = getSrc(p);
        const host  = cfg.host || p.host || p.name || '';
        const backs = (cfg.backends || p.backends || []).map(b => b.url || b).join(' ');
        const srch  = [host, p.name||'', backs].join(' ').toLowerCase();
        if (af.status === 'actif'   && p.enabled === false) return false;
        if (af.status === 'inactif' && p.enabled !== false) return false;
        if (af.type   && af.type !== pType) return false;
        if (af.source && af.source !== src)  return false;
        if (q && !srch.includes(q)) return false;
        return true;
      });
      const csvLines = ['id,nom,type,actif,backends,tls,source'];
      for (const p of filtered) {
        const cfg  = getCfg(p);
        const host = cfg.host || p.host || p.name || '';
        const type = getType(p);
        const tls  = !!(cfg.tls_enabled || cfg.tls_passthrough);
        const src  = getSrc(p);
        const backs = (cfg.backends || p.backends || []).map(b => b.url || b).join(';');
        csvLines.push([`"${p.id||''}"`,`"${host}"`,type,p.enabled!==false,`"${backs}"`,tls,src].join(','));
      }
      const blob = new Blob([csvLines.join('\n')], { type: 'text/csv;charset=utf-8' });
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href = url; a.download = 'proxies.csv'; a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    };

    window.openNewProxyModal  = () => openProxyModal();
    window.openNewStreamModal = () => {
      document.getElementById('trafic-modal-container').innerHTML = `
        <div class="dialog-backdrop" style="position:fixed;inset:0;z-index:9999;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.55);">
          <div class="dialog blueprint" role="dialog" aria-modal="true" style="width:min(420px,94vw);">
            <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
            <div class="dialog-title">${t('trafic.new_stream')}</div>
            <div class="dialog-body" style="display:flex;flex-direction:column;gap:14px;">
              <div class="field"><label class="field-label">${t('trafic.name')}</label><input class="input" id="ns2-name" placeholder="Redis cache"></div>
              <div class="field"><label class="field-label">${t('trafic.port_local')}</label><input class="input" id="ns2-port" placeholder="6379" type="number" min="1" max="65535"></div>
              <div class="field"><label class="field-label">${t('trafic.backend')}</label><input class="input" id="ns2-target" placeholder="10.0.4.40:6379"></div>
              <div class="field"><label class="field-label">${t('trafic.protocol')}</label>
                <div style="display:flex;gap:16px;margin-top:4px;">
                  <label style="display:flex;align-items:center;gap:6px;cursor:pointer;font-size:13px;">
                    <input type="checkbox" id="ns2-tcp" checked> TCP
                  </label>
                  <label style="display:flex;align-items:center;gap:6px;cursor:pointer;font-size:13px;">
                    <input type="checkbox" id="ns2-udp"> UDP
                  </label>
                </div>
              </div>
            </div>
            <div class="dialog-actions">
              <button class="btn btn-secondary blueprint" onclick="document.getElementById('trafic-modal-container').innerHTML=''"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>${t('common.cancel')}</button>
              <button class="btn btn-primary blueprint" onclick="traficCreateStream()"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>${t('common.create')}</button>
            </div>
          </div>
        </div>`;
    };
    window.traficCreateStream = async () => {
      const name   = (document.getElementById('ns2-name')?.value || '').trim();
      const port   = parseInt(document.getElementById('ns2-port')?.value || '0');
      const target = (document.getElementById('ns2-target')?.value || '').trim();
      const useTCP = document.getElementById('ns2-tcp')?.checked;
      const useUDP = document.getElementById('ns2-udp')?.checked;
      if (!port || port < 1 || port > 65535) { toast(t('trafic.port_invalid'), 'error'); return; }
      if (!target) { toast(t('trafic.backend_required'), 'error'); return; }
      if (!useTCP && !useUDP) { toast(t('trafic.proto_required'), 'error'); return; }
      const protos = [...(useTCP ? ['tcp'] : []), ...(useUDP ? ['udp'] : [])];
      try {
        for (const proto of protos) {
          const host = name || (proto + '_' + port);
          const config = { type: proto, host, listen_port: port, backends: [{ url: target }] };
          const created = await api('POST', '/proxies', { config, enabled: true });
          if (created) { allP.unshift(created); streamItems.unshift(created); }
        }
        document.getElementById('trafic-modal-container').innerHTML = '';
        renderPage();
        toast(protos.length > 1 ? t('trafic.streams_created', { n: protos.length }) : t('trafic.stream_created'), 'success');
      } catch(e) { toast(e.message || t('trafic.create_error'), 'error'); }
    };

    // Import wizard (4 étapes)
    window.openTraficImport = function() {
      const tim = { step: 1, format: null, text: '', files: [], proxies: [], result: null };
      const STEPS = [t('trafic.step_format'), t('trafic.step_config'), t('trafic.step_select'), t('trafic.step_result')];
      const close = () => document.getElementById('trafic-modal-container').innerHTML = '';
      const stepsBar = () => STEPS.map((s,i) => {
        const n=i+1, active=n===tim.step, done=n<tim.step;
        return `<div style="display:flex;align-items:center;gap:6px">
          <span style="width:20px;height:20px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;flex-shrink:0;
            background:${done?'var(--green)':active?'var(--accent)':'var(--bg3)'};color:${done||active?'#fff':'var(--text3)'};
            border:1.5px solid ${done?'var(--green)':active?'var(--accent)':'var(--border)'};">${done?'✓':n}</span>
          <span style="font-size:11px;font-weight:600;${active?'color:var(--text)':'color:var(--text3)'}">${s}</span>
          ${i<STEPS.length-1?'<span style="width:20px;height:1px;background:var(--border);flex-shrink:0"></span>':''}
        </div>`;
      }).join('');
      const render = () => {
        const body = (() => {
          if (tim.step === 1) return `
            <p style="font-size:13px;color:var(--text2);margin:0 0 16px">${t('trafic.choose_format')}</p>
            <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(min(120px,100%),1fr));gap:10px;margin-bottom:4px">
              ${configFormatPickerHtml(tim.format, id => `window._tim.format='${id}';window._tim_render()`)}
            </div>`;
          if (tim.step === 2) {
            const fmt = CONFIG_FORMATS.find(f => f.id === tim.format) || {};
            const fmtSvg = configFormatMeta(tim.format, 20);
            const fileList = tim.files || [];
            return `
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;padding:10px 14px;background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius)">
              <div style="width:32px;height:32px;border-radius:8px;display:flex;align-items:center;justify-content:center;background:${fmtSvg.color}18;color:${fmtSvg.color};flex-shrink:0">
                ${fmtSvg.svg}
              </div>
              <div style="min-width:0;flex:1">
                <div style="font-size:13px;font-weight:700">${esc(fmt.label||tim.format)}</div>
                <div style="font-size:11px;color:var(--text3)">${esc(fmt.hint||'')}</div>
              </div>
              <button type="button" onclick="window._tim.step=1;window._tim_render()" style="background:none;border:none;cursor:pointer;color:var(--text3);font-size:11px;padding:4px 8px">${t('trafic.change')}</button>
            </div>
            <div id="tim-dropzone" style="border:2px dashed var(--border);border-radius:var(--radius);padding:16px;text-align:center;cursor:pointer;margin-bottom:10px;transition:border-color .2s"
              onclick="document.getElementById('tim-file').click()"
              ondragover="event.preventDefault();this.style.borderColor='var(--accent)'"
              ondragleave="this.style.borderColor='var(--border)'"
              ondrop="event.preventDefault();this.style.borderColor='var(--border)';window._timLoadFiles(event.dataTransfer.files)">
              <svg width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24" style="opacity:.5;margin-bottom:6px"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
              <p style="font-size:12px;color:var(--text3);margin:0">${t('trafic.drop_files')}</p>
              <input type="file" id="tim-file" style="display:none" accept=".conf,.yaml,.yml,.toml,.json,.txt,.caddyfile" multiple onchange="window._timLoadFiles(this.files)">
            </div>
            ${fileList.length ? `<div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px">${fileList.map((f,i)=>`<span style="display:inline-flex;align-items:center;gap:5px;padding:3px 8px;background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius);font-size:12px">${esc(f.name)}<button type="button" onclick="window._timRemoveFile(${i})" style="background:none;border:none;cursor:pointer;color:var(--text3);padding:0;font-size:13px;line-height:1">×</button></span>`).join('')}</div>` : ''}
            <div class="field" style="margin-bottom:0">
              <label class="field-label">${t('trafic.or_paste')}</label>
              <textarea id="tim-text" class="input" rows="${fileList.length ? 4 : 9}" placeholder="${esc(t('trafic.paste_ph'))}" style="font-family:monospace;font-size:12px;resize:vertical">${esc(tim.text)}</textarea>
            </div>`;
          }
          if (tim.step === 3) {
            if (!tim.proxies.length) return `<div style="text-align:center;padding:32px 0"><div style="font-size:36px;margin-bottom:12px">🤔</div><div style="font-size:16px;font-weight:700;margin-bottom:8px">${t('trafic.no_proxy_detected')}</div><p style="color:var(--text2);font-size:13px">${t('trafic.check_format')}</p></div>`;
            return `
            <div style="display:flex;align-items:center;gap:8px;padding:8px 4px;border-bottom:1px solid var(--border);margin-bottom:4px;font-size:12px">
              <label style="display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" id="tim-all" checked onchange="document.querySelectorAll('.tim-cb').forEach(c=>{c.checked=this.checked;window._tim.proxies[+c.dataset.i]._sel=this.checked})"><b>${t('trafic.select_all')}</b></label>
              <span style="color:var(--text3);margin-left:auto">${tim.proxies.length>1?t('trafic.detected_n',{n:tim.proxies.length}):t('trafic.detected',{n:tim.proxies.length})}</span>
            </div>
            <div style="background:var(--bg3);border-radius:var(--radius);max-height:260px;overflow-y:auto;border:1px solid var(--border)">
              ${tim.proxies.map((p,i) => `<label style="display:flex;align-items:flex-start;gap:10px;padding:8px 10px;border-bottom:1px solid var(--border);cursor:pointer;font-size:12px">
                <input type="checkbox" class="tim-cb" data-i="${i}" ${p._sel!==false?'checked':''} style="margin-top:2px" onchange="window._tim.proxies[${i}]._sel=this.checked;document.getElementById('tim-all').indeterminate=window._tim.proxies.some(x=>!x._sel)&&window._tim.proxies.some(x=>x._sel!==false)">
                <div style="flex:1;min-width:0"><div style="font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(p.host||p.name||'—')}</div>
                <div style="color:var(--text3);margin-top:2px;font-size:11px">${(p.backends||[]).map(b=>`<span class="chip" style="font-size:10px">${esc(typeof b==='string'?b:b.url||'')}</span>`).join(' ')||'—'}</div></div>
                ${p.tls?'<span class="tag tag-green" style="font-size:10px">TLS</span>':''}
              </label>`).join('')}
            </div>
            <div class="field" style="margin-top:12px;margin-bottom:0;display:flex;align-items:center;gap:10px">
              <label class="field-label" style="margin:0;white-space:nowrap">${t('trafic.on_conflict')}</label>
              <select id="tim-conflict" class="input" style="max-width:200px"><option value="skip">${t('trafic.skip_keep')}</option><option value="overwrite">${t('trafic.overwrite')}</option></select>
            </div>`;
          }
          const r = tim.result || {};
          return `<div style="text-align:center;padding:28px 16px"><div style="font-size:44px;margin-bottom:14px">${(r.errors||0)>0?'⚠️':'✅'}</div>
            <div style="font-size:17px;font-weight:700;margin-bottom:6px">${(r.errors||0)>0?t('trafic.import_err'):t('trafic.import_ok')}</div>
            <div style="display:flex;justify-content:center;gap:28px;margin:20px auto">
              <div style="text-align:center"><div style="font-size:26px;font-weight:700;color:var(--green)">${r.imported||0}</div><div style="color:var(--text2);font-size:12px">${t('trafic.imported')}</div></div>
              <div style="text-align:center"><div style="font-size:26px;font-weight:700;color:var(--text3)">${r.skipped||0}</div><div style="color:var(--text2);font-size:12px">${t('trafic.skipped')}</div></div>
              ${(r.errors||0)>0?`<div style="text-align:center"><div style="font-size:26px;font-weight:700;color:var(--red)">${r.errors}</div><div style="color:var(--text2);font-size:12px">${t('trafic.errors')}</div></div>`:''}
            </div></div>`;
        })();
        const actions = (() => {
          if (tim.step === 1) return `<button class="btn btn-secondary blueprint" onclick="window._timClose()"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>${t('common.cancel')}</button><button class="btn btn-primary blueprint" onclick="window._timNext()" ${tim.format?'':'disabled'}><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>${t('trafic.next')}</button>`;
          if (tim.step === 2) return `<button class="btn btn-secondary blueprint" onclick="window._timClose()"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>${t('common.cancel')}</button><button class="btn btn-secondary blueprint" onclick="window._tim.step=1;window._tim_render()"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>${t('trafic.back')}</button><button id="tim-btn-parse" class="btn btn-primary blueprint" onclick="window._timParse()"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>${t('trafic.analyze')}</button>`;
          if (tim.step === 3) return `<button class="btn btn-secondary blueprint" onclick="window._timClose()"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>${t('common.cancel')}</button><button class="btn btn-secondary blueprint" onclick="window._tim.step=2;window._tim_render()"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>${t('trafic.back')}</button><button class="btn btn-primary blueprint" onclick="window._timApply()"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>${t('trafic.import_go')}</button>`;
          return `<button class="btn btn-secondary blueprint" onclick="window._tim.step=1;window._tim.format=null;window._tim.text='';window._tim.files=[];window._tim.proxies=[];window._tim_render()"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>${t('trafic.new_import')}</button><button class="btn btn-primary blueprint" onclick="window._timClose();refreshProxies()"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>${t('trafic.see_proxies')}</button>`;
        })();
        document.getElementById('trafic-modal-container').innerHTML = `
          <div class="dialog-backdrop" style="position:fixed;inset:0;z-index:9999;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.6);">
            <div class="dialog blueprint" role="dialog" aria-modal="true" style="width:min(680px,96vw);max-height:90vh;display:flex;flex-direction:column">
              <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
              <div class="dialog-title" style="display:flex;align-items:center;gap:16px;flex-shrink:0">
                <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                ${t('trafic.import_title')}
                <div style="display:flex;align-items:center;gap:4px;margin-left:auto">${stepsBar()}</div>
              </div>
              <div class="dialog-body" style="flex:1;overflow-y:auto;display:flex;flex-direction:column;gap:12px">${body}</div>
              <div class="dialog-actions" style="flex-shrink:0">${actions}</div>
            </div>
          </div>`;
      };
      window._tim = tim; window._tim_render = render; window._timClose = close;
      window._timLoadFiles = (fileList) => {
        if (!fileList || !fileList.length) return;
        const extMap = { yaml:'traefik-yaml', yml:'traefik-yaml', toml:'traefik-toml', conf:'nginx' };
        if (!tim.files) tim.files = [];
        const files = Array.from(fileList);
        const ext = files[0].name.split('.').pop().toLowerCase();
        if (extMap[ext] && !tim.format) tim.format = extMap[ext];
        let pending = files.length;
        const newContents = new Array(files.length);
        files.forEach((file, i) => {
          if (tim.files.some(f => f.name === file.name)) { pending--; if (!pending) render(); return; }
          tim.files.push({ name: file.name });
          const reader = new FileReader();
          reader.onload = e => { newContents[i] = e.target.result; pending--; if (!pending) { tim.text += (tim.text ? '\n\n' : '') + newContents.filter(Boolean).join('\n\n'); render(); } };
          reader.readAsText(file);
        });
      };
      window._timRemoveFile = (idx) => { if (!tim.files) return; tim.files.splice(idx, 1); if (!tim.files.length) tim.text = ''; render(); };
      window._timNext = () => { tim.step = 2; render(); };
      window._timParse = async () => {
        tim.text = document.getElementById('tim-text')?.value || '';
        if (!tim.text.trim()) { toast(t('trafic.no_config'), 'error'); return; }
        const btn = document.getElementById('tim-btn-parse');
        if (btn) { btn.disabled = true; btn.textContent = t('trafic.analyzing'); }
        try {
          const res = await api('POST', '/import/config/parse', { format: tim.format, content: tim.text });
          tim.proxies = (res?.proxies || []).map(p => ({ ...p, _sel: true }));
          tim.step = 3; render();
        } catch(e) {
          toast(t('trafic.parse_err', { msg: e.message }), 'error');
          if (btn) { btn.disabled = false; btn.innerHTML = '<i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>' + t('trafic.analyze'); }
        }
      };
      window._timApply = async () => {
        const selected = tim.proxies.filter(p => p._sel !== false);
        if (!selected.length) { toast(t('trafic.no_proxy_sel'), 'error'); return; }
        const onConflict = document.getElementById('tim-conflict')?.value || 'skip';
        try { const res = await api('POST', '/import/config/apply', { proxies: selected, on_conflict: onConflict }); tim.result = res; tim.step = 4; render(); }
        catch(e) { toast(t('trafic.import_err_msg', { msg: e.message }), 'error'); }
      };
      render();
    };

    // ── Tuile conteneur découvert (style proxy, actions Docker utiles) ───────
    // Pas de sélection / toggle / edit / delete / sécu : géré via labels Docker.
    // Une tuile = un conteneur (plusieurs hosts possibles) ; LB = une tuile multi-hosts + multi-backends.
    function groupDiscoveredContainers(items) {
      const tiles = [];
      const pending = new Map();
      for (const c of items) {
        const backends = (c.backends || []).filter(Boolean);
        const ids = (c.container_ids || []).filter(Boolean);
        const hosts = [c.host, ...(c.aliases || [])].filter(Boolean);
        const isLB = backends.length >= 2 || ids.length >= 2;
        if (isLB) {
          tiles.push({ ...c, hosts, backends: [...backends] });
          continue;
        }
        const cid = ids[0] || '';
        const key = cid
          ? `${c.core_name || ''}|${c.source || ''}|cid:${cid}`
          : `${c.core_name || ''}|${c.source || ''}|be:${backends[0] || c.id || ''}`;
        const existing = pending.get(key);
        if (!existing) {
          pending.set(key, { ...c, hosts: [...hosts], backends: [...backends] });
          continue;
        }
        for (const h of hosts) {
          if (h && !existing.hosts.includes(h)) existing.hosts.push(h);
        }
        for (const b of backends) {
          if (b && !existing.backends.includes(b)) existing.backends.push(b);
        }
        if (c.tls) existing.tls = true;
        if (c.config && typeof c.config === 'object') {
          existing.config = Object.assign({}, existing.config || {}, c.config);
        }
        if (ids.length && !(existing.container_ids || []).length) {
          existing.container_ids = [...ids];
        }
      }
      for (const tile of pending.values()) {
        // Badge LB uniquement si le regroupement a réellement plusieurs destinataires.
        if ((tile.backends || []).length < 2 && tile.config) {
          const cfg = { ...tile.config };
          delete cfg.lb;
          tile.config = cfg;
        }
        tiles.push(tile);
      }
      return tiles;
    }

    function buildContainerTile(c) {
      const hosts = (c.hosts && c.hosts.length) ? c.hosts : [c.host || '—'].filter(Boolean);
      const host = hosts[0] || '—';
      const hasTLS  = !!c.tls;
      const type    = hasTLS ? 'https' : 'http';
      const allBackends = (c.backends || []).filter(Boolean);
      const statusDot = `<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--green);flex-shrink:0;" title="${esc(t('trafic.discovered'))}"></span>`;

      let chips = '';
      if (isAdmin && c.core_name) {
        chips = `<span style="display:inline-flex;align-items:center;font-size:10px;color:var(--text2);background:var(--bg3);padding:1px 6px;border-radius:4px;border:1px solid var(--border);white-space:nowrap">⚙ ${esc(c.core_name)}</span>`;
      }

      const cfg = Object.assign(
        { tls_enabled: hasTLS },
        (c.config && typeof c.config === 'object') ? c.config : {}
      );
      if (hasTLS) cfg.tls_enabled = true;
      // Pas de faux badge LB : seulement si pool multi-backends + algo adaptive.
      if (allBackends.length < 2) delete cfg.lb;
      const badges = featureBadges(cfg);

      const domainsHtml = hosts.map((d, i) => domainLink(d, i === 0, hasTLS)).join('');

      const flowKey = c.id || `${c.core_name || ''}|${c.source || ''}|${hosts.join(',')}|${allBackends.join(',')}`;
      window._traficContainers = window._traficContainers || {};
      window._traficContainers[flowKey] = c;
      const flowBtn = `<button class="btn btn-ghost btn-icon" onclick="openTrafficFlowModal('container','${esc(flowKey)}')" title="${esc(t('trafic.flow_title'))}"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="19" r="2"/><circle cx="18" cy="5" r="2"/><circle cx="6" cy="5" r="2"/><path d="M18 7v4a2 2 0 0 1-2 2H8a2 2 0 0 0-2 2v2"/></svg></button>`;

      return `<div class="trafic-tile" title="${esc(c.id||'')}" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'">
        <div class="trafic-tile-head">
          ${statusDot}
          ${typeBadge(type)}
          <div class="trafic-tile-actions">
            <button class="btn btn-ghost btn-icon" onclick="logsFilters.domain='${esc(host)}';navigate('logs')" title="${esc(t('trafic.access_logs'))}"><svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M7 8h10M7 12h10M7 16h6"/></svg></button>
            <button class="btn btn-ghost btn-icon" onclick="openPrismForProxy('${esc(host)}','${esc(c.core_id||c.core_name||'')}')" title="Prism"><svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M18 20V10M12 20V4M6 20v-6"/></svg></button>
            ${flowBtn}
          </div>
        </div>
        <div style="min-width:0;margin-bottom:7px">${domainsHtml}${chips?`<div style="margin-top:4px;display:flex;flex-wrap:wrap;gap:3px">${chips}</div>`:''}</div>
        ${badges?`<div style="display:flex;flex-wrap:wrap;gap:3px;margin-bottom:7px">${badges}</div>`:''}
        ${backendsGridHtml(allBackends)}
      </div>`;
    }

    // ── Conteneurs découverts ────────────────────────────────────────────────
    window.loadContainers = async () => {
      const el  = document.getElementById('trafic-containers-content');
      const cnt = document.getElementById('trafic-containers-count');
      if (!el) return;
      el.innerHTML = '<p style="color:var(--text2);font-size:13px;">' + t('common.loading') + '</p>';
      try {
        const all = await api('GET', '/discovered-containers') || [];
        const coreName = core ? (core.node_name || core.display_name || '') : '';
        const raw = coreName ? all.filter(c => c.core_name === coreName) : all;
        const items = groupDiscoveredContainers(raw);
        window._traficContainers = {};
        if (cnt) cnt.textContent = items.length ? items.length : '';
        if (!items.length) {
          el.innerHTML = `<div style="background:var(--bg2);border:1.5px solid var(--border);border-radius:var(--radius);padding:20px 16px;text-align:center;color:var(--text3);font-size:13px;">
            ${t('trafic.no_containers')}
          </div>`; return;
        }
        const srcColor = { docker:'#0ea5e9', k8s:'#326ce5' };
        const srcLabel = { docker:'Docker', k8s:'Kubernetes' };
        const bySource = {};
        for (const c of items) { (bySource[c.source] = bySource[c.source] || []).push(c); }
        const cols = window._tc || 3;
        let html = '';
        for (const [src, group] of Object.entries(bySource)) {
          html += `<div style="margin-bottom:20px"><div style="display:flex;align-items:center;gap:8px;margin-bottom:10px"><span style="font-size:12px;font-weight:700;color:${srcColor[src]||'var(--text2)'}">${srcLabel[src]||src}</span><span class="chip">${group.length}</span></div>
            <div class="trafic-grid" data-cols="${cols}">`;
          for (const c of group) html += buildContainerTile(c);
          html += `</div></div>`;
        }
        el.innerHTML = html;
      } catch(e) { if (el) el.innerHTML = `<p style="color:var(--red);font-size:13px">${esc(e.message)}</p>`; }
    };

    renderPage();
    window.loadContainers();

  } catch(e) { content.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`; }
}

// ── Enregistrement des pages ──────────────────────────────────────────────
pages['admin-trafic'] = async function() {
  await renderTraficPage({ mode: 'admin' });
};

pages['core-trafic'] = async function() {
  await renderTraficPage({ mode: 'core' });
};

async function refreshProxies() {
  if (state.page === 'admin-trafic' || state.page === 'core-trafic') {
    return renderTraficPage({ mode: state.page === 'admin-trafic' ? 'admin' : 'core' });
  }
}

// ── Modale « chemin du trafic » (proxy / stream / conteneur) ───────────────
window.openTrafficFlowModal = function(kind, ref) {
  let info = null;
  if (kind === 'proxy') {
    const p = (window._traficAll || []).find(x => x.id === ref);
    if (!p) { toast(t('trafic.flow_not_found'), 'error'); return; }
    const cfg = (typeof p.config === 'object' && p.config) ? p.config : (tryJSON(p.config) || {});
    const type = String(cfg.type || p.type || 'http').toLowerCase();
    const host = cfg.host || p.host || p.name || '—';
    const backends = (cfg.backends || p.backends || []).map(b => b.url || b).filter(Boolean);
    const src = String(p.id || '').startsWith('docker:') ? 'docker'
      : String(p.id || '').startsWith('k8s:') ? 'k8s' : 'managed';
    info = {
      host,
      aliases: cfg.aliases || [],
      type,
      listenPort: cfg.listen_port || p.listen_port || null,
      backends,
      coreName: p.core_name || p.node_name || '',
      source: src,
      tlsEnabled: !!(cfg.tls_enabled || type === 'https'),
      tlsPassthrough: !!cfg.tls_passthrough,
      lb: cfg.lb || '',
      agentName: '',
      isStream: type === 'tcp' || type === 'udp' || type === 'both',
      isDiscovered: src === 'docker' || src === 'k8s',
    };
  } else if (kind === 'container') {
    const c = (window._traficContainers || {})[ref];
    if (!c) { toast(t('trafic.flow_not_found'), 'error'); return; }
    const hosts = (c.hosts && c.hosts.length) ? c.hosts : [c.host, ...(c.aliases || [])].filter(Boolean);
    const cfg = (c.config && typeof c.config === 'object') ? c.config : {};
    const backends = (c.backends || []).map(b => b.url || b).filter(Boolean);
    info = {
      host: hosts[0] || c.host || '—',
      aliases: hosts.slice(1),
      type: c.tls ? 'https' : 'http',
      listenPort: null,
      backends,
      coreName: c.core_name || '',
      source: c.source || 'docker',
      tlsEnabled: !!c.tls || !!cfg.tls_enabled,
      tlsPassthrough: !!cfg.tls_passthrough,
      lb: (backends.length >= 2 && cfg.lb) ? cfg.lb : '',
      agentName: c.agent_name || '',
      isStream: false,
      isDiscovered: true,
    };
  } else {
    return;
  }

  const ico = (paths) =>
    `<svg class="tf-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">${paths}</svg>`;
  const ICONS = {
    client: ico('<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>'),
    dns: ico('<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/><path d="M11 8v6M8 11h6"/>'),
    core: ico('<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M6 21h12M8 17v4M16 17v4M6 8h.01M10 8h.01"/>'),
    tls: ico('<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/><circle cx="12" cy="16" r="1.2" fill="currentColor" stroke="none"/>'),
    tlsPass: ico('<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9.5 12h5M12 9.5v5"/>'),
    tlsOff: ico('<path d="m2 2 20 20"/><path d="M10.6 10.6A2 2 0 0 0 12 14h2a2 2 0 0 0 1.9-2.6"/><path d="M17 17H7a2 2 0 0 1-2-2V9c0-.3.1-.6.2-.9"/><path d="M8.7 4.7A6 6 0 0 1 18 9v1"/>'),
    route: ico('<circle cx="6" cy="19" r="2"/><circle cx="18" cy="5" r="2"/><circle cx="6" cy="5" r="2"/><path d="M18 7v4a2 2 0 0 1-2 2H8a2 2 0 0 0-2 2v2"/>'),
    backend: ico('<path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><path d="M3.3 7 12 12l8.7-5M12 22V12"/>'),
    agent: ico('<path d="M12 2a7 7 0 0 1 7 7c0 3.5-2.5 6.4-5.8 7.1L12 22l-1.2-5.9A7 7 0 0 1 12 2z"/><circle cx="12" cy="9" r="2.2"/>'),
    stream: ico('<path d="M4 8h16M4 16h16"/><path d="m8 5-3 3 3 3M16 13l3 3-3 3"/>'),
  };

  const chip = (label) => `<span class="tf-chip">${esc(label)}</span>`;
  const code = (v) => `<code class="tf-code">${esc(v)}</code>`;

  const sourceKey = info.source === 'docker' ? 'trafic.flow_source_docker'
    : info.source === 'k8s' ? 'trafic.flow_source_k8s'
    : 'trafic.flow_source_managed';

  /** @type {{id:string,tone:string,icon:string,title:string,desc:string,meta:string,pill:string}[]} */
  const nodes = [];

  nodes.push({
    id: 'client', tone: 'sky', icon: ICONS.client,
    title: t('trafic.flow_step_client'),
    desc: t('trafic.flow_step_client_desc'),
    meta: '', pill: t('trafic.flow_pill_internet'),
  });

  if (info.isStream) {
    const port = info.listenPort || '?';
    const proto = String(info.type || 'tcp').toUpperCase();
    nodes.push({
      id: 'core', tone: 'accent', icon: ICONS.stream,
      title: t('trafic.flow_step_core'),
      desc: t('trafic.flow_step_core_stream', { type: proto, port }),
      meta: [
        chip(`${proto} :${port}`),
        info.coreName ? chip(info.coreName) : '',
      ].filter(Boolean).join(''),
      pill: `:${port}`,
    });
  } else {
    nodes.push({
      id: 'dns', tone: 'violet', icon: ICONS.dns,
      title: t('trafic.flow_step_dns'),
      desc: t('trafic.flow_step_dns_desc', { host: info.host }),
      meta: [
        code(info.host),
        ...info.aliases.map(a => code(a)),
      ].join(''),
      pill: 'DNS',
    });
    nodes.push({
      id: 'core', tone: 'accent', icon: ICONS.core,
      title: t('trafic.flow_step_core'),
      desc: t('trafic.flow_step_core_http'),
      meta: [
        chip(':80'), chip(':443'),
        info.coreName ? chip(info.coreName) : '',
      ].filter(Boolean).join(''),
      pill: 'Core',
    });

    let tlsIcon = ICONS.tlsOff;
    let tlsTone = 'amber';
    let tlsDesc = t('trafic.flow_step_tls_none');
    let tlsPill = 'HTTP';
    if (info.tlsPassthrough) {
      tlsIcon = ICONS.tlsPass; tlsTone = 'cyan';
      tlsDesc = t('trafic.flow_step_tls_pass'); tlsPill = 'SNI';
    } else if (info.tlsEnabled) {
      tlsIcon = ICONS.tls; tlsTone = 'green';
      tlsDesc = t('trafic.flow_step_tls_term'); tlsPill = 'TLS';
    }
    nodes.push({
      id: 'tls', tone: tlsTone, icon: tlsIcon,
      title: t('trafic.flow_step_tls'),
      desc: tlsDesc, meta: '', pill: tlsPill,
    });
  }

  nodes.push({
    id: 'route', tone: 'orange', icon: ICONS.route,
    title: t('trafic.flow_step_route'),
    desc: t('trafic.flow_step_route_desc'),
    meta: '', pill: t('trafic.flow_pill_match'),
  });

  let beDesc = t('trafic.flow_step_backend_desc');
  if (info.lb && info.backends.length >= 2) {
    beDesc = t('trafic.flow_step_backend_lb', { lb: info.lb, n: info.backends.length });
  }
  const beMeta = [
    ...(info.backends.length ? info.backends.map(u => code(u)) : [chip('—')]),
    info.isDiscovered ? chip(t('trafic.flow_pill_private_net')) : '',
    info.agentName ? chip(`${t('trafic.flow_agent')}: ${info.agentName}`) : '',
  ].filter(Boolean).join('');

  nodes.push({
    id: 'backend', tone: 'teal', icon: ICONS.backend,
    title: t('trafic.flow_step_backend'),
    desc: beDesc,
    meta: beMeta,
    pill: info.backends.length > 1 ? `${info.backends.length}×` : t('trafic.flow_pill_service'),
  });

  const overview = nodes.map((n, i) => `
    <div class="tf-ov-node tone-${n.tone}">
      <div class="tf-ov-icon">${n.icon}</div>
      <div class="tf-ov-label">${esc(n.pill)}</div>
    </div>
    ${i < nodes.length - 1 ? `<div class="tf-ov-link" aria-hidden="true"><span></span></div>` : ''}
  `).join('');

  const timeline = nodes.map((n, i) => `
    <div class="tf-node tone-${n.tone}">
      <div class="tf-rail">
        <div class="tf-badge">${n.icon}</div>
        ${i < nodes.length - 1 ? '<div class="tf-rail-line" aria-hidden="true"></div>' : ''}
      </div>
      <div class="tf-card">
        <div class="tf-card-head">
          <span class="tf-card-title">${esc(n.title)}</span>
          <span class="tf-card-idx">${String(i + 1).padStart(2, '0')}</span>
        </div>
        <p class="tf-card-desc">${esc(n.desc)}</p>
        ${n.meta ? `<div class="tf-card-meta">${n.meta}</div>` : ''}
      </div>
    </div>
  `).join('');

  const discoveryNote = info.isDiscovered
    ? `<div class="tf-note">
        <div class="tf-note-icon">${ICONS.agent}</div>
        <div>
          <div class="tf-note-title">${t('trafic.flow_step_agent')}</div>
          <div class="tf-note-desc">${t('trafic.flow_step_agent_desc')}</div>
          <div class="tf-card-meta" style="margin-top:8px">${chip(t('trafic.flow_step_backend_docker'))}</div>
        </div>
      </div>`
    : '';

  const typeCls = info.isStream ? 'neutral' : (info.tlsEnabled ? 'secure' : 'plain');
  const body = `
    <div class="tf-modal">
      <p class="tf-intro">${t('trafic.flow_hint')}</p>
      <div class="tf-hero tone-${typeCls}">
        <div class="tf-hero-top">
          <span class="tf-hero-type">${esc((info.type || 'http').toUpperCase())}</span>
          <span class="tf-hero-src">${t(sourceKey)}</span>
        </div>
        <div class="tf-hero-host">${esc(info.host)}</div>
        ${info.coreName ? `<div class="tf-hero-core">${esc(info.coreName)}</div>` : ''}
      </div>
      <div class="tf-overview" role="img" aria-label="${esc(t('trafic.flow_title'))}">${overview}</div>
      <div class="tf-timeline">${timeline}</div>
      ${discoveryNote}
    </div>`;

  modal(
    t('trafic.flow_title'),
    body,
    `<button class="btn btn-primary" onclick="closeModal()">${t('common.close')}</button>`,
    true
  );
};
