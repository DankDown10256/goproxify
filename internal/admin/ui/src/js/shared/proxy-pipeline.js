// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Navigation de la modale proxy : parcours d'une requête (étapes) → liste des réglages → un réglage à la fois.
// Les champs restent ceux de proxy-form.js (leurs id servent à l'enregistrement) : chaque carte est retrouvée par un
// champ-ancre, rangée dans #pm-stash, puis déplacée dans #pm-detail quand on la sélectionne.

(function () {
  const ICONS = {
    globe: '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
    shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
    route: '<circle cx="6" cy="19" r="3"/><path d="M9 19h8.5a3.5 3.5 0 0 0 0-7h-11a3.5 3.5 0 0 1 0-7H15"/><circle cx="18" cy="5" r="3"/>',
    shuffle: '<polyline points="16 3 21 3 21 8"/><line x1="4" y1="20" x2="21" y2="3"/><polyline points="21 16 21 21 16 21"/><line x1="15" y1="15" x2="21" y2="21"/><line x1="4" y1="4" x2="9" y2="9"/>',
    server: '<rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>',
    refresh: '<polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>',
    file: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>',
    left: '<line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/>',
    right: '<line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/>',
  };
  const ic = (n, s = 16) => `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[n]}</svg>`;

  const STAGES = [
    { id: 'entry', label: 'Entrée', icon: 'globe', desc: 'Qui peut joindre cette route, et comment.', idle: 'Domaines, TLS' },
    { id: 'sec', label: 'Sécurité', icon: 'shield', desc: 'Ce qui est filtré avant d\'atteindre l\'application.', idle: 'Aucune protection' },
    { id: 'route', label: 'Routage', icon: 'route', desc: 'Quel backend reçoit quelle requête.', idle: 'Tout vers les backends' },
    { id: 'tr', label: 'Transformation', icon: 'shuffle', desc: 'Ce qui est modifié à l\'aller et au retour.', idle: 'Rien de modifié' },
    { id: 'back', label: 'Backends', icon: 'server', desc: 'Les serveurs et la façon de leur parler.', idle: 'Backends' },
    { id: 'res', label: 'Résilience', icon: 'refresh', desc: 'Que faire quand un backend ralentit ou tombe.', idle: 'Aucune règle' },
    { id: 'obs', label: 'Observabilité', icon: 'file', desc: 'Journaux, métriques et pages d\'erreur.', idle: 'Journal par défaut' },
  ];

  const $ = id => document.getElementById(id);
  const val = id => $(id)?.value.trim() || '';
  const num = id => parseInt($(id)?.value, 10) || 0;
  const ck = id => !!$(id)?.checked;
  const count = sel => document.querySelectorAll(sel).length;
  const filled = sel => [...document.querySelectorAll(sel)].filter(i => i.value.trim()).length;
  const lines = id => val(id).split('\n').filter(s => s.trim()).length;
  const opt = id => { const s = $(id); return s?.options?.[s.selectedIndex]?.text || ''; };
  const rules = (n, sing = 'règle', plur = 'règles') => n ? `${n} ${n > 1 ? plur : sing}` : '';
  const ctx = { active: [], score: null };
  const names = tab => ctx.active.filter(f => f[2] === tab).map(f => f[0]);

  // item(id, étape, titre, ancre, options) — options : on(), sum(), short (texte ou fonction), toggle(), always, full, kw
  const items = [];
  const item = (id, stage, title, anchor, o = {}) => items.push({ id, stage, title, anchor, ...o });
  const prout = (key, stage, title, kw) => item(key, stage, title, `[data-prout="${key}"]`, {
    toggle: () => document.querySelector(`[data-prout="${key}"] input[type=checkbox]`),
    on() { return !!this.toggle()?.checked; },
    sum() { return this.on() ? 'Activé' : 'Désactivé' },
    kw,
  });

  item('domains', 'entry', 'Domaines', '#p-domains-list', {
    always: true, kw: 'host alias hostname dns',
    short: () => rules(filled('.p-domain-val'), 'domaine', 'domaines'),
    sum() { const n = filled('.p-domain-val'); return n ? `${[...document.querySelectorAll('.p-domain-val')].find(i => i.value.trim()).value.trim()}${n > 1 ? ` · ${n - 1} alias` : ''}` : 'Aucun domaine' },
  });
  item('https', 'entry', 'HTTPS entrant', '#p-https', {
    toggle: () => $('p-https'), on: () => ck('p-https'), short: 'TLS', kw: 'tls ssl certificat let\'s encrypt',
    sum: () => ck('p-https') ? (opt('p-cert') || 'Certificat automatique') : 'HTTP uniquement',
  });
  item('protocols', 'entry', 'Protocoles et tags', '#p-ws', {
    kw: 'websocket http3 quic grpc tags',
    on: () => ck('p-ws') || ck('p-http3') || ck('p-grpc'),
    short: () => [ck('p-ws') && 'WebSocket', ck('p-http3') && 'HTTP/3', ck('p-grpc') && 'gRPC'].filter(Boolean).join(' · '),
    sum() { return this.short() || 'Aucun protocole optionnel' },
  });

  item('protection', 'sec', 'Protection', '#ptab-protection', {
    full: true, count: () => names('protection').length, kw: 'hsts bots rate limit ip filter geoip jwt mtls snippets headers bans timeline score',
    on: () => names('protection').length > 0,
    short: () => names('protection').join(' · '),
    sum() { return this.short() || 'Aucune protection active' },
  });
  item('waf', 'sec', 'WAF', '#ptab-waf', {
    full: true, kw: 'pare-feu owasp crs paranoia',
    on: () => names('waf').length > 0, short: 'WAF',
    sum() { return this.on() ? 'Activé' : 'Désactivé' },
  });
  item('auth', 'sec', 'Auth / SSO', '#p-sso-provider', {
    kw: 'oidc sso oauth authentik authelia pocket basic forward', on: () => !!val('p-sso-provider'), short: 'SSO',
    sum: () => val('p-sso-provider') ? opt('p-sso-provider') : 'Désactivé',
  });
  item('limit_conn', 'sec', 'Connexions simultanées', '#p-limit-conn', {
    kw: 'limit_conn ip', on: () => num('p-limit-conn') > 0, short: 'Connexions',
    sum: () => num('p-limit-conn') > 0 ? `${num('p-limit-conn')} par IP` : 'Désactivé',
  });
  prout('signed_url', 'sec', 'URLs signées', 'hmac signature expiration');
  prout('graphql', 'sec', 'Garde-fous GraphQL', 'introspection profondeur alias');
  prout('request_schema', 'sec', 'Validation JSON Schema', 'schema json requête');
  prout('openapi', 'sec', 'Validation OpenAPI', 'swagger spécification');
  prout('surface', 'sec', 'Apprentissage de la surface', 'surface profil chemins méthodes apprentissage learn');

  item('locations', 'route', 'Locations — routage par chemin', '#p-locations-list', {
    kw: 'chemin path prefix regex rewrite réécriture', on: () => count('.p-loc-row') > 0, short: 'Locations',
    sum: () => rules(count('.p-loc-row')) || 'Aucune location',
  });
  item('conditions', 'route', 'Routage conditionnel', '#p-conditions-list', {
    kw: 'header cookie query method condition', on: () => count('.p-cond-row') > 0, short: 'Conditions',
    sum: () => rules(count('.p-cond-row')) || 'Aucune condition',
  });
  prout('split', 'route', 'Split pondéré (A/B)', 'ab test variantes poids');
  prout('maintenance', 'route', 'Mode maintenance', '503 retry-after');
  prout('static', 'route', 'Fichiers statiques', 'dossier spa index');
  prout('grpc_web', 'route', 'gRPC-Web', 'grpc navigateur');
  prout('grpc_transcode', 'route', 'Transcodage REST ↔ gRPC', 'proto rest json');

  item('hdr_fwd', 'tr', 'En-têtes transmis au backend', '.p-fwd-header', {
    kw: 'x-forwarded-for x-real-ip proxy_set_header request-id',
    sum() { const all = count('.p-fwd-header'), on = count('.p-fwd-header:checked'); return `${on}/${all} en-têtes${ck('p-request-id') ? ' · X-Request-ID' : ''}` },
  });
  item('hdr_req', 'tr', 'En-têtes de la requête', '#p-req-set-headers', {
    kw: 'header requête ajouter retirer masquer', on: () => lines('p-req-set-headers') + lines('p-req-hide-headers') > 0, short: 'En-têtes requête',
    sum: () => [rules(lines('p-req-set-headers'), 'ajouté', 'ajoutés'), rules(lines('p-req-hide-headers'), 'retiré', 'retirés')].filter(Boolean).join(' · ') || 'Aucun',
  });
  item('hdr_resp', 'tr', 'En-têtes de la réponse', '#p-resp-headers', {
    kw: 'header réponse custom csp', on: () => lines('p-resp-headers') > 0, short: 'En-têtes réponse',
    sum: () => rules(lines('p-resp-headers'), 'en-tête', 'en-têtes') || 'Aucun',
  });
  item('redirects', 'tr', 'Réécriture Location — proxy_redirect', '#p-redirects-list', {
    kw: 'location 3xx redirection', on: () => count('.p-redirect-row') > 0, short: 'proxy_redirect',
    sum: () => rules(count('.p-redirect-row')) || 'Aucune règle',
  });
  item('cookies', 'tr', 'Cookies — domain / path', '#p-cookie-rewrites-list', {
    kw: 'set-cookie proxy_cookie_domain proxy_cookie_path', on: () => count('.p-cookie-row') > 0, short: 'Cookies',
    sum: () => rules(count('.p-cookie-row')) || 'Aucune règle',
  });
  item('subfilters', 'tr', 'Réécriture du corps — sub_filter', '#p-subfilters-list', {
    kw: 'body corps remplacer', on: () => count('.p-sf-row') > 0, short: 'sub_filter',
    sum: () => rules(count('.p-sf-row')) || 'Aucune règle',
  });
  item('reqvars', 'tr', 'Variables de requête — map', '#p-reqvars-list', {
    kw: 'map variables', on: () => count('.p-rv-row') > 0, short: 'Variables',
    sum: () => rules(count('.p-rv-row'), 'variable', 'variables') || 'Aucune variable',
  });
  item('perf', 'tr', 'Performance — cache, compression', '#p-cache-enabled', {
    kw: 'cache compression gzip brotli zstd body taille',
    on: () => ck('p-cache-enabled') || ck('p-comp-enabled'),
    short: () => [ck('p-cache-enabled') && 'Cache', ck('p-comp-enabled') && 'Compression'].filter(Boolean).join(' · '),
    sum() { return this.short() || 'Désactivé' },
  });
  item('cache_adv', 'tr', 'Cache avancé — proxy_cache_valid', '#p-cache-rules-list', {
    kw: 'ttl bypass', on: () => count('.p-cache-rule-row') > 0, short: 'Règles de cache',
    sum: () => rules(count('.p-cache-rule-row')) || 'TTL par défaut',
  });
  prout('redact_json', 'tr', 'Masquage de champs JSON', 'redact masque');
  prout('html_inject', 'tr', 'Injection dans les pages HTML', 'script nonce csp');

  item('backends', 'back', 'Backends', '#p-backends-list', {
    always: true, kw: 'upstream serveur load balancing poids round robin',
    short: () => rules(filled('.p-backend-url'), 'backend', 'backends'),
    sum() { const n = filled('.p-backend-url'); return n ? `${rules(n, 'backend', 'backends')} · ${opt('p-lb')}` : 'Aucun backend' },
  });
  item('backendopts', 'back', 'Vers le backend', '#p-preserve-host', {
    kw: 'host certificat auto-signé proxmox passthrough ssl',
    on: () => ck('p-skip-verify') || ck('p-passthrough'),
    short: () => [ck('p-skip-verify') && 'Certificat ignoré', ck('p-passthrough') && 'Passthrough'].filter(Boolean).join(' · '),
    sum() { return [ck('p-preserve-host') && 'Host conservé', this.short()].filter(Boolean).join(' · ') || 'Options par défaut' },
  });
  item('timeouts', 'back', 'Timeouts backend', '#p-connect-timeout', {
    kw: 'timeout connexion réponse envoi buffer', on: () => ['p-connect-timeout', 'p-response-timeout', 'p-send-timeout', 'p-buffer-size'].some(id => val(id)),
    short: 'Timeouts',
    sum: () => `connexion ${val('p-connect-timeout') || $('p-connect-timeout')?.placeholder || '10'} s · réponse ${val('p-response-timeout') || $('p-response-timeout')?.placeholder || '30'} s`,
  });
  item('backpressure', 'back', 'Backpressure', '#p-bp-max', {
    kw: 'file attente inflight 503', on: () => num('p-bp-max') > 0, short: 'Backpressure',
    sum: () => num('p-bp-max') > 0 ? `${num('p-bp-max')} requêtes simultanées` : 'Désactivé',
  });
  prout('bandwidth', 'back', 'Plafond de débit', 'bande passante');

  item('health', 'res', 'Health check', '#p-hc-path', {
    kw: 'sonde santé', on: () => !!val('p-hc-path'), short: 'Health check',
    sum: () => val('p-hc-path') ? `${val('p-hc-path')}${val('p-hc-interval') ? ' · ' + val('p-hc-interval') : ''}` : 'Désactivé',
  });
  item('circuit', 'res', 'Circuit breaker', '#p-cb-enabled', {
    kw: 'disjoncteur', toggle: () => $('p-cb-enabled'), on: () => ck('p-cb-enabled'), short: 'Circuit breaker',
    sum: () => ck('p-cb-enabled') ? `seuil ${val('p-cb-threshold') || '50'} %` : 'Désactivé',
  });
  item('retry', 'res', 'Retry', '#p-retry-max', {
    kw: 'nouvel essai tentatives', on: () => num('p-retry-max') > 0 || !!val('p-retry-on'), short: 'Retry',
    sum: () => num('p-retry-max') > 0 ? `${num('p-retry-max')} tentatives` : (val('p-retry-on') ? 'Activé' : 'Désactivé'),
  });
  item('sticky', 'res', 'Sticky session', '#p-sticky-cookie', {
    kw: 'affinité cookie', on: () => !!val('p-sticky-cookie'), short: 'Sticky',
    sum: () => val('p-sticky-cookie') || 'Désactivé',
  });
  item('slowstart', 'res', 'Slow-start', '#p-slow-start', {
    kw: 'montée en charge', on: () => num('p-slow-start') > 0, short: 'Slow-start',
    sum: () => num('p-slow-start') > 0 ? `${num('p-slow-start')} s` : 'Désactivé',
  });
  item('canary', 'res', 'Canary et Shadow Mirror', '#p-canary-backend', {
    kw: 'canary mirror miroir déploiement progressif', on: () => !!val('p-canary-backend') || !!val('p-shadow-backend'),
    short: () => [val('p-canary-backend') && 'Canary', val('p-shadow-backend') && 'Mirror'].filter(Boolean).join(' · '),
    sum() { return this.short() || 'Désactivé' },
  });
  prout('hedge', 'res', 'Requêtes « hedged »', 'doublon latence');

  item('logging', 'obs', 'Journalisation par route', '#p-log-enabled', {
    kw: 'access log prometheus métriques', toggle: () => $('p-log-enabled'), on: () => ck('p-log-enabled'), short: 'Access log',
    sum: () => (ck('p-log-enabled') ? `Access log ${opt('p-log-format')}` : 'Access log désactivé') + (ck('p-prom-enabled') ? ' · Prometheus' : ''),
  });
  item('errorpages', 'obs', 'Pages d\'erreur personnalisées', '#p-error-pages-list', {
    kw: 'erreur 404 502 503 template', on: () => !!$('p-error-pages-list')?.children.length, short: 'Pages d\'erreur',
    sum: () => rules($('p-error-pages-list')?.children.length || 0, 'page', 'pages') || 'Pages par défaut',
  });
  item('quickerr', 'obs', 'Pages d\'erreur rapides', '#p-err-404', {
    kw: 'erreur 404 502 503 url', on: () => !!val('p-err-404') || !!val('p-err-502'), short: 'Erreurs rapides',
    sum: () => [val('p-err-404') && '404', val('p-err-502') && '502/503'].filter(Boolean).join(' · ') || 'Par défaut',
  });

  const byId = Object.fromEntries(items.map(i => [i.id, i]));
  const stageOf = id => STAGES.find(s => s.id === byId[id].stage);
  // Réglages rarement utilisés, masqués hors mode expert (core/expert.js) — sauf s'ils sont configurés ou ouverts.
  ['limit_conn', 'signed_url', 'graphql', 'request_schema', 'openapi', 'surface',
    'conditions', 'split', 'static', 'grpc_web', 'grpc_transcode',
    'redirects', 'cookies', 'subfilters', 'reqvars', 'cache_adv', 'redact_json', 'html_inject',
    'backpressure', 'bandwidth', 'slowstart', 'canary', 'hedge', 'quickerr',
  ].forEach(id => { byId[id].expert = true; });

  const flow = STAGES.flatMap(s => items.filter(i => i.stage === s.id));
  const last = {};
  let cur = null, timer = 0, poppedHits = [], hi = 0;

  const isOn = it => !!(it.on ? it.on() : it.always);
  const shown = it => !!it.card && (!it.expert || Expert.on || isOn(it) || it.id === cur);
  const shortOf = it => { const s = typeof it.short === 'function' ? it.short() : it.short; return s || it.title };
  const esc2 = s => (typeof esc === 'function' ? esc(s) : String(s ?? ''));

  function cardOf(it) {
    const el = document.querySelector(it.anchor);
    if (!el) return null;
    if (el.id?.startsWith('ptab-') || el.matches('details.prout-card')) return el;
    return el.closest('div[style*="border-radius:10px"]');
  }

  function renderPipe() {
    const pipe = $('pm-pipe');
    if (!pipe) return;
    const curStage = cur && byId[cur].stage;
    pipe.innerHTML = STAGES.map(s => {
      const its = items.filter(i => i.stage === s.id && i.card);
      const act = its.filter(isOn);
      const n = act.filter(i => !i.always).reduce((a, i) => a + (i.count ? i.count() : 1), 0);
      const nm = act.map(shortOf).filter(Boolean);
      const score = s.id === 'sec' && ctx.score ? `<span class="pm-pn-score" style="--c:${ctx.gradeColor}">Score ${esc2(ctx.score.grade)}</span>` : '';
      return `<button type="button" class="pm-pn${s.id === curStage ? ' act' : ''}" data-pm-stage="${s.id}"><span class="pm-pn-t">${ic(s.icon)}${s.label}${n ? `<span class="pm-pn-n">${n}</span>` : ''}</span><span class="pm-pn-s${nm.length ? ' has' : ''}">${nm.length ? esc2(nm.join(' · ')) : s.idle}</span>${score}</button>`;
    }).join('');
  }

  function renderList() {
    const list = $('pm-list');
    if (!list || !cur) return;
    const s = stageOf(cur);
    const hidden = items.filter(i => i.stage === s.id && i.card && !shown(i)).length;
    list.innerHTML = `<div class="pm-ls-h"><h2>${s.label}</h2><p>${s.desc}</p></div>` + items.filter(i => i.stage === s.id && shown(i)).map(i => {
      const tg = i.toggle?.();
      return `<div class="pm-li${i.id === cur ? ' sel' : ''}${isOn(i) ? ' on' : ''}" data-pm-sel="${i.id}"><span class="pm-li-dot"></span><div class="pm-li-m"><div class="pm-li-t">${esc2(i.title)}</div><div class="pm-li-s">${esc2(i.sum ? i.sum() : '')}</div></div>${tg ? `<label class="toggle pm-lt"><input type="checkbox" data-pm-tg="${i.id}" ${tg.checked ? 'checked' : ''}><span class="toggle-slider"></span></label>` : ''}</div>`;
    }).join('') + (hidden ? `<button type="button" class="pm-more" data-pm-expert>${hidden} réglage${hidden > 1 ? 's' : ''} avancé${hidden > 1 ? 's' : ''} masqué${hidden > 1 ? 's' : ''} — afficher (mode expert)</button>` : '');
    list.querySelector('.sel')?.scrollIntoView({ block: 'nearest' });
  }

  function show(id) {
    const it = byId[id], stash = $('pm-stash'), detail = $('pm-detail');
    if (!it?.card || !detail) return;
    if (cur && byId[cur].card) stash.appendChild(byId[cur].card);
    cur = id; last[it.stage] = id; window._pmCurId = id;
    const seq = flow.filter(shown), s = stageOf(id), k = seq.indexOf(it), p = seq[k - 1], n = seq[k + 1];
    detail.className = 'pm-detail' + (it.full ? ' is-full' : '');
    document.querySelector('.pm-shell')?.classList.toggle('has-full', !!it.full);
    detail.innerHTML = '';
    const crumb = document.createElement('div');
    crumb.className = 'pm-crumb';
    crumb.innerHTML = `${ic(s.icon, 13)}<b>${s.label}</b> › ${esc2(it.title)}`;
    const inner = document.createElement('div');
    inner.className = 'pm-detail-in';
    if (it.card.matches('details')) it.card.open = true;
    if (it.card.id === 'ptab-protection') it.card.style.display = 'block';
    else if (it.card.id === 'ptab-waf') it.card.style.display = 'flex';
    if (it.full) { detail.append(crumb, it.card); }
    else {
      inner.append(crumb, it.card);
      const nav = document.createElement('div');
      nav.className = 'pm-nav-row';
      nav.innerHTML = (p ? `<button type="button" class="btn btn-ghost" data-pm-sel="${p.id}">${ic('left', 14)}<span>${esc2(p.title)}</span></button>` : '<span></span>')
        + (n ? `<button type="button" class="btn btn-ghost" data-pm-sel="${n.id}"><span>${esc2(n.title)}</span>${ic('right', 14)}</button>` : '');
      inner.append(nav);
      detail.append(inner);
    }
    detail.scrollTop = 0;
    renderPipe(); renderList();
  }

  function refresh() { clearTimeout(timer); timer = setTimeout(() => { if (cur) { renderPipe(); renderList(); } }, 60); }

  function view(v) {
    const shell = document.querySelector('.pm-shell');
    if (!shell) return;
    const yaml = v === 'yaml';
    shell.classList.toggle('is-yaml', yaml);
    const ta = $('ptab-yaml');
    if (ta) ta.style.display = yaml ? 'flex' : 'none';
    document.querySelectorAll('.pm-view button').forEach(b => b.classList.toggle('on', b.dataset.view === (yaml ? 'yaml' : 'flow')));
    if (yaml && typeof window._refreshYamlTab === 'function') window._refreshYamlTab();
  }

  function search(q) {
    const pop = $('pm-pop');
    q = q.toLowerCase().trim();
    if (!q) { pop.hidden = true; return; }
    poppedHits = items.filter(i => i.card && `${i.title} ${i.kw || ''}`.toLowerCase().includes(q));
    hi = 0;
    renderPop();
  }
  function renderPop() {
    const pop = $('pm-pop');
    pop.innerHTML = poppedHits.length
      ? poppedHits.map((i, k) => `<button type="button" class="pm-r${k === hi ? ' h' : ''}" data-pm-sel="${i.id}">${esc2(i.title)}${shown(i) ? '' : '<span class="pm-x">expert</span>'}<small>${stageOf(i.id).label} · ${esc2(i.sum ? i.sum() : '')}</small></button>`).join('')
      : '<div class="pm-none">Aucun réglage ne correspond.</div>';
    pop.hidden = false;
  }

  window._pmMount = function (c) {
    Object.assign(ctx, c);
    const stash = $('pm-stash'), root = $('modal-overlay');
    if (!stash || !root) return;
    cur = null;
    items.forEach(it => { it.card = cardOf(it); if (it.card) stash.appendChild(it.card); else console.warn('pm: carte introuvable', it.id); });
    flow.length = 0;
    STAGES.forEach(s => items.filter(i => i.stage === s.id && i.card).forEach(i => flow.push(i)));
    items.forEach(i => { if (!last[i.stage] && i.card) last[i.stage] = i.id; });

    root.addEventListener('click', e => {
      if (e.target.closest('.toggle')) return;
      if (e.target.closest('[data-pm-expert]')) { Expert.set(true); return; }
      const st = e.target.closest('[data-pm-stage]');
      if (st) { show(last[st.dataset.pmStage]); return; }
      const sel = e.target.closest('[data-pm-sel]');
      if (sel) { show(sel.dataset.pmSel); $('pm-pop').hidden = true; const q = $('pm-q'); if (q) q.value = ''; return; }
      const vw = e.target.closest('.pm-view button');
      if (vw) { view(vw.dataset.view); return; }
      refresh();
    });
    root.addEventListener('change', e => {
      const tg = e.target.dataset?.pmTg;
      if (tg) {
        const real = byId[tg].toggle();
        if (real) { real.checked = e.target.checked; real.dispatchEvent(new Event('change', { bubbles: true })); }
      }
      refresh();
    });
    root.addEventListener('input', refresh);
    const q = $('pm-q');
    if (q) {
      q.addEventListener('input', () => search(q.value));
      q.addEventListener('keydown', e => {
        if (e.key === 'Escape') { q.value = ''; $('pm-pop').hidden = true; q.blur(); e.stopPropagation(); }
        else if (e.key === 'ArrowDown' && poppedHits.length) { hi = (hi + 1) % poppedHits.length; renderPop(); e.preventDefault(); }
        else if (e.key === 'ArrowUp' && poppedHits.length) { hi = (hi - 1 + poppedHits.length) % poppedHits.length; renderPop(); e.preventDefault(); }
        else if (e.key === 'Enter' && !$('pm-pop').hidden && poppedHits.length) { show(poppedHits[hi].id); q.value = ''; $('pm-pop').hidden = true; q.blur(); }
      });
    }
    show('domains');
  };

  if (!window._pmKeys) {
    window._pmKeys = true;
    document.addEventListener('gpx:expert', refresh);
    document.addEventListener('keydown', e => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k' && $('pm-q')) { e.preventDefault(); $('pm-q').focus(); }
    });
  }

  window._pmShow = show;
  window._pmRefresh = refresh;
  window._pmView = view;
  window._pmItemOfTab = tab => ({ general: 'domains', entetes: 'hdr_fwd', auth: 'auth', protection: 'protection', waf: 'waf', resilience: 'health', avance: 'perf' }[tab] || tab);
})();
