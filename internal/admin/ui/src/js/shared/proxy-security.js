// ── Shared: modale Sécurité proxy + GeoIP + score headers ──────────────────
// Chargé avant pages/* (trafic.js dépend de openProxySecModal, computeProxyHeaderScore).
// Extrait de pages-all.js — phase 1 du plan split pages-all.

// ── Modale Sécurité du proxy ──────────────────────────────────────────────────
/** Types de snippets exposés dans la modale Sécurité. */
const PSEC_SNIPPET_TYPES = [
  { type: 'ip_filter',  label: 'Filtrage IP (CIDR)' },
  { type: 'geo_ip',     label: 'GeoIP' },
  { type: 'rate_limit', label: 'Rate limiting' },
  { type: 'headers',    label: 'Headers natifs' },
  { type: 'tls',        label: 'TLS' },
  { type: 'cors',       label: 'CORS' },
  { type: 'waf',        label: 'WAF' },
  { type: 'bot',        label: 'Protection bot' },
];

/** Miroir client de ResolveSnippets — la config inline du proxy prime. */
window.resolveCfgWithSnippets = function(cfg, snippets, ids) {
  const out = { ...(cfg || {}) };
  const list = Array.isArray(snippets) ? snippets : [];
  const byId = Object.fromEntries(list.map(s => [s.id, s]));
  const idList = Array.isArray(ids) ? ids : [];
  for (const id of idList) {
    const sn = byId[id];
    if (!sn) continue;
    let conf = sn.config;
    if (typeof conf === 'string') { try { conf = JSON.parse(conf); } catch { conf = {}; } }
    if (!conf || typeof conf !== 'object' || Array.isArray(conf)) conf = {};
    switch (sn.type) {
      case 'ip_filter':  if (!out.ip_filter)  out.ip_filter  = conf; break;
      case 'geo_ip':
        if (!out.geo_ip) {
          out.geo_ip = { ...conf };
          // Alias legacy snippets (page IP / GeoIP / Bot)
          if (!(out.geo_ip.countries || []).length && (conf.blocked_countries || []).length)
            out.geo_ip.countries = [...conf.blocked_countries];
        }
        break;
      case 'rate_limit': if (!out.rate_limit) out.rate_limit = conf; break;
      case 'headers': {
        // Inline prime sur les champs typés ; custom : clés inline gagnent, snippet complète le reste
        if (!out.headers) {
          out.headers = { ...conf };
        } else {
          const h = { ...out.headers };
          const snCustom = conf.custom || {};
          const inlineCustom = h.custom || {};
          const mergedCustom = { ...snCustom, ...inlineCustom };
          if (Object.keys(mergedCustom).length) h.custom = mergedCustom;
          if (!h.hsts && conf.hsts) {
            h.hsts = true;
            if (conf.hsts_max_age != null) h.hsts_max_age = conf.hsts_max_age;
          }
          if (!h.x_frame_options && conf.x_frame_options) h.x_frame_options = conf.x_frame_options;
          if (!h.hide_server && conf.hide_server) h.hide_server = true;
          out.headers = h;
        }
        break;
      }
      case 'cors':       if (!out.cors)       out.cors       = conf; break;
      case 'waf':
        if (!out.waf && conf.enabled) out.waf = { ...conf };
        break;
      case 'bot':
        if (!out.bot && (conf.enabled || conf.mode)) out.bot = { ...conf };
        break;
      case 'tls':
        if (conf.tls_enabled != null && out.tls_enabled == null) out.tls_enabled = conf.tls_enabled;
        break;
    }
  }
  return out;
};

window.psecSnippetsHTML = function(snippets, selectedIds, cfg) {
  const sel = new Set(Array.isArray(selectedIds) ? selectedIds : []);
  const byType = {};
  for (const s of (Array.isArray(snippets) ? snippets : [])) {
    if (!s || !s.type) continue;
    (byType[s.type] = byType[s.type] || []).push(s);
  }
  const inlineHint = (type) => {
    if (type === 'ip_filter' && cfg?.ip_filter) return 'inline CIDR actif — snippet ignoré pour ce champ';
    if (type === 'geo_ip' && cfg?.geo_ip) return 'inline GeoIP actif — snippet ignoré pour ce champ';
    if (type === 'rate_limit' && cfg?.rate_limit) return 'inline rate limit actif — snippet ignoré pour ce champ';
    if (type === 'waf' && cfg?.waf?.enabled) return 'inline WAF actif — snippet ignoré pour ce champ';
    if (type === 'bot' && cfg?.bot?.enabled) return 'inline bot actif — snippet ignoré pour ce champ';
    if (type === 'headers' && cfg?.headers && (cfg.headers.hsts || cfg.headers.hide_server || cfg.headers.x_frame_options || (cfg.headers.custom && Object.keys(cfg.headers.custom).length)))
      return 'inline headers actif — champs typés/custom inline primaires ; custom snippet complète les clés manquantes';
    return '';
  };
  const types = (typeof PSEC_SNIPPET_TYPES !== 'undefined' ? PSEC_SNIPPET_TYPES : []);
  const blocks = types.map(({ type, label }) => {
    const list = byType[type] || [];
    const hint = inlineHint(type);
    return `<div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:12px 14px;">
      <div style="display:flex;align-items:baseline;justify-content:space-between;gap:8px;margin-bottom:8px;">
        <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);">${esc(label)}</div>
        ${hint ? `<div style="font-size:10px;color:#f59e0b;">${esc(hint)}</div>` : ''}
      </div>
      ${list.length ? list.map(s => {
        const on = sel.has(s.id);
        return `<label style="display:flex;align-items:flex-start;gap:8px;padding:7px 0;cursor:pointer;border-top:1px solid var(--border);">
          <input type="checkbox" class="psec-snip-cb" data-sid="${esc(s.id)}" ${on?'checked':''}
            onchange="psecToggleSnippet('${esc(s.id)}',this.checked)" style="margin-top:2px;accent-color:var(--accent);">
          <div style="min-width:0;flex:1;">
            <div style="font-size:13px;font-weight:500;">${esc(s.name || s.id)}</div>
            <div style="font-size:11px;color:var(--text3);">${esc(s.description || '—')}</div>
          </div>
        </label>`;
      }).join('') : `<div style="font-size:12px;color:var(--text3);">Aucun snippet <code>${esc(type)}</code> — créez-en dans Snippets.</div>`}
    </div>`;
  }).join('');
  return blocks || '<div style="font-size:13px;color:var(--text3);">Bibliothèque vide.</div>';
};

window.psecToggleSnippet = function(id, on) {
  if (!window._psecSnippetIds) window._psecSnippetIds = new Set();
  if (on) window._psecSnippetIds.add(id);
  else window._psecSnippetIds.delete(id);
};

window.psecGetSnippetIds = function() {
  return [...(window._psecSnippetIds || [])];
};

// ── Phase B : unification headers (typed + custom + legacy response_add_header) ─

/** Parse des lignes "Name: value" → map (dernière gagne, clé = nom tel quel). */
window.parseResponseAddHeader = function(lines) {
  const out = {};
  for (const raw of (lines || [])) {
    const line = String(raw || '').trim();
    if (!line) continue;
    const c = line.indexOf(':');
    if (c <= 0) continue;
    out[line.slice(0, c).trim()] = line.slice(c + 1).trim();
  }
  return out;
};

/**
 * Vue unifiée des headers de réponse (lookup lowercase → { name, value }).
 * Priorité : champs typés > headers.custom > legacy response_add_header.
 */
window.mergeHeadersFromConfig = function(cfg) {
  cfg = cfg || {};
  const byLower = {};
  const put = (name, value, overwrite) => {
    if (name == null || value == null || value === '') return;
    const k = String(name).toLowerCase();
    if (!overwrite && byLower[k]) return;
    byLower[k] = { name: String(name), value: String(value) };
  };
  const legacy = cfg.headers_manipulation?.response_add_header || [];
  for (const [n, v] of Object.entries(parseResponseAddHeader(legacy))) put(n, v, false);
  for (const [n, v] of Object.entries(cfg.headers?.custom || {})) put(n, v, true);
  const h = cfg.headers || {};
  if (h.hsts) {
    const age = h.hsts_max_age || 31536000;
    put('Strict-Transport-Security', `max-age=${age}; includeSubDomains`, true);
  }
  if (h.x_frame_options) put('X-Frame-Options', h.x_frame_options, true);
  return byLower;
};

/** Lignes pour le textarea « en-têtes réponse » (custom + legacy, hors HSTS/XFO typés). */
window.customHeadersToLines = function(cfg) {
  cfg = cfg || {};
  const lines = [];
  const seen = new Set();
  const add = (name, value) => {
    const k = String(name).toLowerCase();
    if (k === 'strict-transport-security' || k === 'x-frame-options') return;
    if (seen.has(k) || value == null || value === '') return;
    seen.add(k);
    lines.push(`${name}: ${value}`);
  };
  for (const [n, v] of Object.entries(cfg.headers?.custom || {})) add(n, v);
  for (const [n, v] of Object.entries(parseResponseAddHeader(cfg.headers_manipulation?.response_add_header || []))) add(n, v);
  return lines;
};

/** Applique un header nommé dans cfg.headers (typé ou custom) et retire le legacy. */
window.applySecurityHeaderToCfg = function(cfg, name, value) {
  const out = { ...(cfg || {}) };
  const headers = { ...(out.headers || {}) };
  const custom = { ...(headers.custom || {}) };
  const lower = String(name || '').toLowerCase();
  const stripCustom = (k) => {
    Object.keys(custom).forEach(key => { if (key.toLowerCase() === k) delete custom[key]; });
  };
  const stripLegacy = (k) => {
    const manip = out.headers_manipulation ? { ...out.headers_manipulation } : {};
    const resp = [...(manip.response_add_header || [])].filter(line => {
      const c = String(line).indexOf(':');
      return c <= 0 || line.slice(0, c).trim().toLowerCase() !== k;
    });
    if (resp.length) manip.response_add_header = resp;
    else delete manip.response_add_header;
    if (Array.isArray(manip.forwarded_headers) || manip.response_add_header || manip.request_set_header || (manip.request_hide_header || []).length) out.headers_manipulation = manip;
    else delete out.headers_manipulation;
  };

  if (lower === 'strict-transport-security') {
    headers.hsts = true;
    const m = String(value).match(/max-age\s*=\s*(\d+)/i);
    headers.hsts_max_age = m ? parseInt(m[1], 10) : (headers.hsts_max_age || 31536000);
    stripCustom(lower);
  } else if (lower === 'x-frame-options') {
    headers.x_frame_options = String(value);
    stripCustom(lower);
  } else {
    stripCustom(lower);
    custom[name] = String(value);
  }
  stripLegacy(lower);
  if (Object.keys(custom).length) headers.custom = custom;
  else delete headers.custom;
  out.headers = headers;
  return out;
};

/** Migre tout response_add_header restant vers headers (+ custom / typés). */
window.migrateHeadersConfig = function(cfg) {
  let out = { ...(cfg || {}) };
  const legacy = [...(out.headers_manipulation?.response_add_header || [])];
  if (!legacy.length) return out;
  for (const line of legacy) {
    const c = String(line).indexOf(':');
    if (c > 0) out = applySecurityHeaderToCfg(out, line.slice(0, c).trim(), line.slice(c + 1).trim());
  }
  if (out.headers_manipulation) {
    const manip = { ...out.headers_manipulation };
    delete manip.response_add_header;
    if (Array.isArray(manip.forwarded_headers) || manip.request_set_header || (manip.request_hide_header || []).length) out.headers_manipulation = manip;
    else delete out.headers_manipulation;
  }
  return out;
};

/** True si un filtrage réseau est actif : CIDR (inline/snippet) et/ou GeoIP (inline/snippet). */
window.hasProxyIPFiltering = function(cfg) {
  cfg = cfg || {};
  const cidrs = cfg.ip_filter?.cidrs || [];
  const geo = cfg.geo_ip || {};
  const countries = geo.countries || geo.blocked_countries || [];
  return cidrs.length > 0 || countries.length > 0;
};

/** Miroir client de ComputeHeaderScore (internal/admin/security/security.go). */
window.computeProxyHeaderScore = function(cfg) {
  cfg = cfg || {};
  const h = cfg.headers || {};
  const wafCfg = cfg.waf || cfg.security?.waf;
  const botCfg = cfg.bot || cfg.security?.bot_protection;
  const jwtCfg = cfg.jwt || cfg.security?.jwt;
  const checks = [
    { name: 'TLS activé',       present: !!(cfg.tls_enabled),                                                         points: 20, tab: 'params' },
    { name: 'HSTS',             present: !!h.hsts,                                                                    points: 15, tab: 'params' },
    { name: 'X-Frame-Options',  present: !!(h.x_frame_options),                                                       points: 12, tab: 'params' },
    { name: 'Masquer Server',   present: !!h.hide_server,                                                             points: 8,  tab: 'params' },
    { name: 'Rate Limiting',    present: !!cfg.rate_limit,                                                            points: 10, tab: 'params' },
    { name: 'WAF activé',       present: !!(wafCfg?.enabled),                                                         points: 15, tab: 'params' },
    { name: 'Protection bot',   present: !!(botCfg?.enabled),                                                         points: 10, tab: 'params' },
    // CIDR + GeoIP (config inline ou snippets déjà résolus via resolveCfgWithSnippets)
    { name: 'Filtrage IP',      present: hasProxyIPFiltering(cfg),                                                    points: 5,  tab: 'params' },
    { name: 'Authentification', present: !!(jwtCfg?.enabled || cfg.sso?.enabled || cfg.mtls?.enabled),                points: 5,  tab: 'params' },
  ];
  let score = 0;
  for (const c of checks) if (c.present) score += c.points;
  if (score > 100) score = 100;
  const grade = score >= 95 ? 'A+' : score >= 85 ? 'A' : score >= 70 ? 'B' : score >= 55 ? 'C' : score >= 40 ? 'D' : score >= 25 ? 'E' : 'F';
  return { score, grade, checks, wafCfg, botCfg, jwtCfg };
};

window._psecMount = async function(id, initialTab, embedEl) {
  try {
  let existing = null;
  let allSnippets = [];
  try {
    const [ex, snips] = await Promise.all([
      api('GET', `/proxies/${encodeURIComponent(id)}`).catch(() => null),
      api('GET', '/snippets').catch(() => []),
    ]);
    existing = ex;
    allSnippets = Array.isArray(snips) ? snips : [];
  } catch {}
  let cfg = {};
  if (existing) {
    if (typeof existing.config === 'string') cfg = tryJSON(existing.config) || {};
    else if (existing.config && typeof existing.config === 'object') cfg = existing.config;
    else cfg = existing;
  }
  if (!cfg || typeof cfg !== 'object') cfg = {};
  const host = cfg.host || id;
  const sec = cfg.security || {};
  const selectedSnippetIds = Array.isArray(cfg.snippet_ids) ? [...cfg.snippet_ids] : [];
  window._psecSnippetIds = new Set(selectedSnippetIds);
  window._psecAllSnippets = allSnippets;
  // Score avec résolution snippets (inline prime — même logique que ResolveSnippets)
  const resolvedCfg = resolveCfgWithSnippets(cfg, allSnippets, selectedSnippetIds);
  const scored = computeProxyHeaderScore(resolvedCfg);
  const wafCfg = scored.wafCfg;
  // Détection heuristique de plateforme depuis l'URL upstream
  const _upstream = (cfg.upstream || cfg.backend || cfg.target || '').toLowerCase();
  const _detectPlatform = () => {
    if (/wordpress|wp-content|wp-admin|woocommerce/.test(_upstream)) return 'wordpress';
    if (/drupal/.test(_upstream)) return 'drupal';
    if (/joomla|com_content|com_users/.test(_upstream)) return 'joomla';
    if (/magento|mage|adminhtml/.test(_upstream)) return 'magento';
    if (/prestashop|presta/.test(_upstream)) return 'prestashop';
    if (/ghost/.test(_upstream)) return 'ghost';
    if (/strapi/.test(_upstream)) return 'strapi';
    if (/\/_next\/|__nextjs/.test(_upstream)) return 'nextjs';
    if (/laravel/.test(_upstream)) return 'laravel';
    if (/symfony/.test(_upstream)) return 'symfony';
    if (/django/.test(_upstream)) return 'django';
    if (/nextcloud|owncloud/.test(_upstream)) return 'nextcloud';
    if (/dokuwiki/.test(_upstream)) return 'dokuwiki';
    if (/mattermost/.test(_upstream)) return 'mattermost';
    if (/discourse/.test(_upstream)) return 'discourse';
    if (/rocket\.chat|rocketchat/.test(_upstream)) return 'rocketchat';
    if (/gitea/.test(_upstream)) return 'gitea';
    if (/forgejo/.test(_upstream)) return 'forgejo';
    if (/portainer/.test(_upstream)) return 'portainer';
    if (/proxmox/.test(_upstream)) return 'proxmox';
    if (/grafana/.test(_upstream)) return 'grafana';
    if (/zabbix/.test(_upstream)) return 'zabbix';
    if (/odoo/.test(_upstream)) return 'odoo';
    if (/n8n/.test(_upstream)) return 'n8n';
    if (/keycloak/.test(_upstream)) return 'keycloak';
    if (/jellyfin/.test(_upstream)) return 'jellyfin';
    if (/immich/.test(_upstream)) return 'immich';
    if (/vaultwarden|bitwarden/.test(_upstream)) return 'vaultwarden';
    if (/cpanel|whm/.test(_upstream)) return 'cpanel';
    return null;
  };
  const _detectedPlatform = _detectPlatform();
  const _storedPlatforms = Array.isArray(wafCfg?.exclude_platforms) ? wafCfg.exclude_platforms : [];
  const _autoMode = _storedPlatforms.includes('auto');
  const _activePlatforms = new Set(_autoMode ? [] : _storedPlatforms);
  // True si le proxy a une config WAF propre (pas seulement héritage passerelle)
  const _hasOwnWaf = !!(cfg.waf?.enabled !== undefined || cfg.waf?.mode || cfg.waf?.exclude_platforms?.length);
  const botCfg = scored.botCfg;
  const jwtCfg = scored.jwtCfg;
  const hdrCfg = cfg.headers || {};
  const rlCfg = cfg.rate_limit || {};
  const ipfCfg = cfg.ip_filter || {};
  const geoCfg = cfg.geo_ip || {};
  const score = scored.score;
  const grade = scored.grade;
  const gradeColor = grade.startsWith('A') ? '#34d399' : grade === 'B' ? '#4ade80' : grade === 'C' ? '#f59e0b' : grade === 'D' ? '#f97316' : '#ef4444';

  // Badges protections actives (checks ComputeHeaderScore + détail auth)
  const prot = [];
  if (cfg.tls_enabled || resolvedCfg.tls_enabled) prot.push(['TLS', '#a78bfa']);
  if (hdrCfg.hsts || resolvedCfg.headers?.hsts) prot.push(['HSTS', '#34d399']);
  if (hdrCfg.x_frame_options || resolvedCfg.headers?.x_frame_options) prot.push(['XFO', '#60a5fa']);
  if (hdrCfg.hide_server || resolvedCfg.headers?.hide_server) prot.push(['Server masqué', '#94a3b8']);
  if (cfg.rate_limit || resolvedCfg.rate_limit) prot.push(['Rate limit', '#f59e0b']);
  if (wafCfg?.enabled) prot.push(['WAF ' + (wafCfg.mode || 'block').toUpperCase(), '#fb923c']);
  if (botCfg?.enabled) prot.push(['Bots', '#f472b6']);
  if ((ipfCfg.cidrs||[]).length || (resolvedCfg.ip_filter?.cidrs||[]).length) prot.push(['IP filter', '#38bdf8']);
  if ((geoCfg.countries || []).length || (resolvedCfg.geo_ip?.countries||[]).length) prot.push(['GeoIP', '#22d3ee']);
  if (selectedSnippetIds.length) prot.push([`${selectedSnippetIds.length} snippet${selectedSnippetIds.length>1?'s':''}`, '#a3e635']);
  if (jwtCfg?.enabled) prot.push(['JWT', '#60a5fa']);
  if (cfg.sso?.enabled || cfg.sso?.provider) prot.push([(cfg.sso.provider || 'SSO').toUpperCase(), '#34d399']);
  if (cfg.mtls?.enabled) prot.push(['mTLS', '#c084fc']);
  const protBadges = prot.map(([l, c]) =>
    `<span style="display:inline-flex;align-items:center;padding:4px 12px;border-radius:99px;background:${c}22;color:${c};font-size:11px;font-weight:600;">${esc(l)}</span>`
  ).join('');

  const missing = scored.checks.filter(c => !c.present);
  const issueItems = missing.length ? missing.map(c => {
    const level = c.points >= 15 ? 'critical' : c.points >= 10 ? 'warning' : 'info';
    const color = level === 'critical' ? '#ef4444' : level === 'warning' ? '#f59e0b' : 'var(--text3)';
    const icon = level === 'critical'
      ? '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>'
      : '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>';
    return `<div style="display:flex;align-items:center;gap:8px;padding:8px 12px;border-radius:8px;background:${color}14;margin-bottom:6px;border:1px solid ${color}30;cursor:pointer;" onclick="switchSecTab('${c.tab||'params'}')">
      <span style="color:${color};flex-shrink:0;">${icon}</span>
      <span style="font-size:12.5px;flex:1;">${esc(c.name)}</span>
      <span style="font-size:11px;color:${color};font-weight:600;">+${c.points} pts</span>
    </div>`;
  }).join('') : `<div style="display:flex;align-items:center;gap:8px;padding:8px 12px;border-radius:8px;background:#34d39914;border:1px solid #34d39930;font-size:12.5px;color:#34d399;">
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
    Aucun problème détecté
  </div>`;

  // ── Headers de sécurité ──────────────────────────────────────────────────
  const hasTLS = cfg.tls_enabled || cfg.type === 'https';
  const SEC_HEADERS = [
    { name: 'Strict-Transport-Security', recommended: 'max-age=31536000; includeSubDomains; preload', risk: 'critical', desc: 'Force HTTPS — protège contre les attaques de downgrade SSL/TLS', tlsOnly: true },
    { name: 'Content-Security-Policy',   recommended: "default-src 'self'; script-src 'self'; object-src 'none'", risk: 'high',     desc: 'Prévient les injections XSS et le chargement de ressources non autorisées' },
    { name: 'X-Frame-Options',           recommended: 'DENY',                                              risk: 'high',     desc: 'Prévient le clickjacking via iframes malveillantes' },
    { name: 'X-Content-Type-Options',    recommended: 'nosniff',                                           risk: 'medium',   desc: 'Empêche le MIME-sniffing par le navigateur' },
    { name: 'Referrer-Policy',           recommended: 'strict-origin-when-cross-origin',                   risk: 'medium',   desc: 'Contrôle les informations de référent transmises aux tiers' },
    { name: 'Permissions-Policy',        recommended: 'camera=(), microphone=(), geolocation=()',           risk: 'medium',   desc: 'Restreint l\'accès aux API sensibles du navigateur' },
    { name: 'Cross-Origin-Opener-Policy',recommended: 'same-origin',                                       risk: 'medium',   desc: 'Isole le contexte de navigation contre les attaques cross-origin' },
    { name: 'X-XSS-Protection',          recommended: '1; mode=block',                                     risk: 'low',      desc: 'Protection XSS réflectif pour les navigateurs anciens (héritage)' },
  ];

  // Parsing unifié : headers typés + custom + legacy response_add_header
  const _parsedHdr = {};
  for (const [k, v] of Object.entries(mergeHeadersFromConfig(cfg))) {
    _parsedHdr[k] = v.value;
  }

  const _riskColor = r => r === 'critical' ? '#ef4444' : r === 'high' ? '#f97316' : r === 'medium' ? '#f59e0b' : 'var(--text3)';

  const _hdrItems = SEC_HEADERS.filter(h => !h.tlsOnly || hasTLS).map(h => {
    const cur = _parsedHdr[h.name.toLowerCase()];
    const present = cur !== undefined;
    const optimal = present && cur.toLowerCase().startsWith(h.recommended.split(';')[0].trim().toLowerCase());
    const stColor = present && optimal ? '#34d399' : present ? '#f59e0b' : _riskColor(h.risk);
    const stIcon  = present && optimal ? '✓' : present ? '⚠' : '✗';
    const stLabel = present && optimal ? 'OK' : present ? 'À réviser' : 'Absent';
    const needsFix = !present || !optimal;
    return `<div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:12px 14px;">
      <div style="display:flex;align-items:flex-start;gap:10px;">
        <span style="flex-shrink:0;width:22px;height:22px;border-radius:50%;background:${stColor}22;color:${stColor};font-size:11px;font-weight:700;display:flex;align-items:center;justify-content:center;">${stIcon}</span>
        <div style="flex:1;min-width:0;">
          <div style="display:flex;align-items:center;gap:7px;flex-wrap:wrap;margin-bottom:3px;">
            <code style="font-size:12px;font-weight:600;">${esc(h.name)}</code>
            <span style="padding:1px 7px;border-radius:99px;background:${_riskColor(h.risk)}18;color:${_riskColor(h.risk)};font-size:10px;font-weight:600;">${h.risk}</span>
            <span style="font-size:11px;color:${stColor};margin-left:auto;white-space:nowrap;">${stLabel}</span>
          </div>
          <div style="font-size:11px;color:var(--text3);margin-bottom:${needsFix?'6':'0'}px;">${esc(h.desc)}</div>
          ${present ? `<div style="font-size:11px;margin-bottom:3px;"><span style="color:var(--text3);">Actuel :</span> <code style="background:var(--bg3);padding:1px 5px;border-radius:4px;">${esc(cur)}</code></div>` : ''}
          ${needsFix ? `<div style="font-size:11px;"><span style="color:var(--text3);">Recommandé :</span> <code style="background:#34d39914;color:#34d399;padding:1px 5px;border-radius:4px;">${esc(h.recommended)}</code></div>` : ''}
        </div>
        ${needsFix ? `<label style="display:flex;align-items:center;gap:5px;cursor:pointer;flex-shrink:0;padding-top:1px;"><input type="checkbox" class="psec-hdr-fix" data-hname="${esc(h.name)}" data-hval="${esc(h.recommended)}" checked style="accent-color:var(--accent);width:14px;height:14px;"><span style="font-size:11px;color:var(--text2);white-space:nowrap;">Corriger</span></label>` : ''}
      </div>
    </div>`;
  }).join('');

  const _fixCount = SEC_HEADERS.filter(h => {
    if (h.tlsOnly && !hasTLS) return false;
    const cur = _parsedHdr[h.name.toLowerCase()];
    return cur === undefined || !cur.toLowerCase().startsWith(h.recommended.split(';')[0].trim().toLowerCase());
  }).length;

  // Helper pour les items de la sidebar
  const stab = (key, label, svgPath) => `
    <div data-stab="${key}" onclick="switchSecTab('${key}')" style="display:flex;align-items:center;gap:9px;padding:9px 14px;cursor:pointer;font-size:12.5px;color:var(--text2);font-weight:400;border-left:2.5px solid transparent;border-right:2.5px solid transparent;">
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">${svgPath}</svg>
      ${label}
    </div>`;

  const body = `
    <div style="display:flex;height:100%;overflow:hidden;">
      <!-- Sidebar sécurité -->
      <div id="psec-tabs" style="width:145px;flex-shrink:0;border-right:1px solid var(--border);overflow-y:auto;padding:8px 0;background:var(--bg);">
        ${stab('recap', 'Récap', '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4" stroke-width="2.5"/>')}
        ${stab('params', 'Paramètres', '<circle cx="12" cy="12" r="3"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14M4.93 4.93a10 10 0 0 0 0 14.14"/>')}
        ${stab('snippets', `Snippets${selectedSnippetIds.length ? ` <span style="display:inline-flex;align-items:center;justify-content:center;min-width:16px;height:16px;padding:0 4px;border-radius:99px;background:var(--accent);color:#000;font-size:9px;font-weight:800;margin-left:2px;">${selectedSnippetIds.length}</span>` : ''}`, '<polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>')}
        ${stab('headers', `Headers${_fixCount > 0 ? ` <span style="display:inline-flex;align-items:center;justify-content:center;width:16px;height:16px;border-radius:50%;background:#f59e0b;color:#000;font-size:9px;font-weight:800;margin-left:2px;">${_fixCount}</span>` : ''}`, '<polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>')}
        ${stab('waf', `WAF${wafCfg?.enabled ? ` <span style="display:inline-flex;align-items:center;justify-content:center;width:8px;height:8px;border-radius:50%;background:#34d399;margin-left:2px;"></span>` : ''}`, '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>')}
        ${stab('bans', 'Bans & Blocs', '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>')}
        ${stab('timeline', 'Timeline', '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>')}
      </div>
      <!-- Panneaux de contenu -->
      <div style="flex:1;overflow-y:auto;">

        <!-- Récap -->
        <div id="psectab-recap" style="padding:20px;display:flex;flex-direction:column;gap:14px;">
          <div style="display:flex;gap:14px;align-items:stretch;">
            <div style="background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:20px 24px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:4px;min-width:110px;">
              <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--text3);margin-bottom:2px;">Score</div>
              <div style="font-size:52px;font-weight:900;line-height:1;color:${gradeColor};font-family:monospace;">${esc(grade)}</div>
              <div style="font-size:11px;color:var(--text3);">${score}/100</div>
            </div>
            <div style="background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:16px 18px;flex:1;display:flex;flex-direction:column;gap:10px;">
              <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);">Protections actives</div>
              <div style="display:flex;flex-wrap:wrap;gap:6px;">${protBadges || '<span style="font-size:12px;color:var(--text3);">Aucune protection active</span>'}</div>
              <div style="border-top:1px solid var(--border);padding-top:10px;margin-top:auto;">
                <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:4px;">Domaine</div>
                <div style="font-size:13px;font-family:monospace;">${esc(host)}</div>
              </div>
            </div>
          </div>
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:16px 18px;">
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:10px;">Contrôles de posture</div>
            <div style="display:flex;flex-direction:column;gap:4px;margin-bottom:12px;">
              ${scored.checks.map(c => `
                <div style="display:flex;align-items:center;gap:8px;padding:4px 0;font-size:12px;">
                  <span style="color:${c.present?'#34d399':'var(--text3)'};width:14px;">${c.present?'✓':'✗'}</span>
                  <span style="flex:1;${c.present?'':'color:var(--text3)'}">${esc(c.name)}</span>
                  <span style="color:${c.present?'#34d399':'var(--text3)'};font-size:11px;">+${c.points}</span>
                </div>`).join('')}
            </div>
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:10px;">Problèmes détectés</div>
            ${issueItems}
          </div>
          ${_fixCount > 0 ? `<div style="background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:14px 16px;display:flex;align-items:center;justify-content:space-between;gap:10px;cursor:pointer;" onclick="switchSecTab('headers')">
            <div>
              <div style="font-size:12px;font-weight:600;">Headers HTTP avancés</div>
              <div style="font-size:11px;color:var(--text3);margin-top:2px;">${_fixCount} header${_fixCount>1?'s':''} absent${_fixCount>1?'s':''} ou à réviser (CSP, Referrer-Policy…)</div>
            </div>
            <span style="font-size:11px;color:var(--accent);font-weight:600;">Voir →</span>
          </div>` : ''}
          <div id="psec-crowdsec-card" style="background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:16px 18px;">
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:8px;">CrowdSec</div>
            <div style="font-size:12.5px;color:var(--text3);">Chargement…</div>
          </div>
        </div>

        <!-- Paramètres de sécurité -->
        <div id="psectab-params" style="display:none;padding:16px 20px;flex-direction:column;gap:14px;">
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 16px;">
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:12px;">Headers natifs</div>
            <div style="display:flex;flex-direction:column;gap:10px;">
              <label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer;">
                <input type="checkbox" id="psec-hsts" ${hdrCfg.hsts?'checked':''} onchange="document.getElementById('psec-hsts-maxage-row').style.display=this.checked?'flex':'none'" style="margin-top:2px;accent-color:var(--accent);">
                <div><div style="font-size:13px;font-weight:500;">HSTS</div><div style="font-size:11px;color:var(--text3);">Strict-Transport-Security — force HTTPS</div></div>
              </label>
              <div id="psec-hsts-maxage-row" style="display:${hdrCfg.hsts?'flex':'none'};align-items:center;gap:8px;padding-left:26px;">
                <label class="field-label" style="font-size:11px;margin:0;">max-age</label>
                <input id="psec-hsts-maxage" type="number" class="input" style="width:140px;font-size:12px;padding:4px 8px;" value="${hdrCfg.hsts_max_age||31536000}" min="0">
              </div>
              <label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer;">
                <input type="checkbox" id="psec-hide-server" ${hdrCfg.hide_server?'checked':''} style="margin-top:2px;accent-color:var(--accent);">
                <div><div style="font-size:13px;font-weight:500;">Masquer Server</div><div style="font-size:11px;color:var(--text3);">Retire l'empreinte serveur des réponses</div></div>
              </label>
              <div class="field" style="margin:0;">
                <label class="field-label" style="font-size:11px">X-Frame-Options</label>
                <select id="psec-xfo" class="input">
                  <option value="" ${!hdrCfg.x_frame_options?'selected':''}>Désactivé</option>
                  <option value="DENY" ${hdrCfg.x_frame_options==='DENY'?'selected':''}>DENY</option>
                  <option value="SAMEORIGIN" ${hdrCfg.x_frame_options==='SAMEORIGIN'?'selected':''}>SAMEORIGIN</option>
                </select>
              </div>
            </div>
          </div>
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:12px 16px;cursor:pointer;" onclick="switchSecTab('waf')">
            <div style="display:flex;align-items:center;justify-content:space-between;">
              <div style="display:flex;align-items:center;gap:8px;">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
                <span style="font-size:12.5px;font-weight:600;">WAF</span>
                ${wafCfg?.enabled ? `<span style="font-size:10px;padding:2px 7px;border-radius:99px;background:#34d39918;color:#34d399;border:1px solid #34d39930;">${wafCfg.mode||'block'}</span>` : `<span style="font-size:10px;color:var(--text3);">${_hasOwnWaf?'Désactivé':'Hérite de la passerelle'}</span>`}
              </div>
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--text3)"><polyline points="9 18 15 12 9 6"/></svg>
            </div>
          </div>
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 16px;">
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:12px;">Protection bot</div>
            <div style="display:flex;gap:16px;align-items:flex-start;">
              <label style="display:flex;align-items:center;gap:8px;cursor:pointer;padding-top:2px;">
                <label class="toggle"><input type="checkbox" id="psec-bot-enabled" ${botCfg?.enabled?'checked':''}><span class="toggle-slider"></span></label>
                <span style="font-size:13px;font-weight:500;">Activé</span>
              </label>
              <div class="field" style="flex:1;margin:0;">
                <label class="field-label" style="font-size:11px">Mode</label>
                <select id="psec-bot-mode" class="input"><option value="block" ${(!(botCfg?.js_challenge)&& (botCfg?.mode||'block')==='block')?'selected':''}>Bloquer</option><option value="challenge" ${(botCfg?.js_challenge || botCfg?.mode==='challenge')?'selected':''}>Challenge JS</option><option value="log" ${(botCfg?.mode==='log'||botCfg?.mode==='monitor')?'selected':''}>Journaliser</option></select>
              </div>
            </div>
          </div>
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 16px;">
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:12px;">Sentinel — whitelist</div>
            <div class="field" style="margin:0;">
              <label class="field-label" style="font-size:11px">IPs / CIDRs exemptés du Sentinel (séparés par virgule)</label>
              <input id="psec-sentinel-whitelist" type="text" class="input" value="${esc((cfg.sentinel_whitelist||[]).join(', '))}" placeholder="10.0.0.0/8, 192.168.1.5">
              <div style="font-size:10px;color:var(--text3);margin-top:2px;">Ces IPs/CIDRs seront ajoutés à la whitelist globale du Sentinel pour toutes les requêtes vers ce proxy. Utile pour les health-checkers ou les systèmes de monitoring.</div>
            </div>
          </div>
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 16px;">
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:12px;">Rate limiting</div>
            <div style="display:flex;gap:16px;align-items:flex-start;margin-bottom:10px;">
              <label style="display:flex;align-items:center;gap:8px;cursor:pointer;padding-top:22px;">
                <label class="toggle"><input type="checkbox" id="psec-rl-enabled" ${cfg.rate_limit?'checked':''} onchange="document.getElementById('psec-rl-fields').style.opacity=this.checked?'1':'0.45'"><span class="toggle-slider"></span></label>
                <span style="font-size:13px;font-weight:500;">Activé</span>
              </label>
              <div id="psec-rl-fields" class="form-row" style="flex:1;gap:8px;opacity:${cfg.rate_limit?'1':'0.45'};">
                <div class="field" style="flex:1;margin:0;"><label class="field-label" style="font-size:11px">Req/s (rps)</label><input id="psec-rl-rps" class="input" type="number" min="0" step="0.1" value="${rlCfg.rps ?? 10}"></div>
                <div class="field" style="flex:1;margin:0;"><label class="field-label" style="font-size:11px">Burst</label><input id="psec-rl-burst" class="input" type="number" min="0" value="${rlCfg.burst ?? 20}"></div>
              </div>
            </div>
          </div>
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 16px;">
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:12px;">Filtrage IP</div>
            <div style="display:flex;gap:16px;align-items:flex-start;margin-bottom:14px;">
              <label style="display:flex;align-items:center;gap:8px;cursor:pointer;padding-top:22px;">
                <label class="toggle"><input type="checkbox" id="psec-ipf-enabled" ${(ipfCfg.cidrs||[]).length?'checked':''} onchange="document.getElementById('psec-ipf-fields').style.opacity=this.checked?'1':'0.45'"><span class="toggle-slider"></span></label>
                <span style="font-size:13px;font-weight:500;">CIDR</span>
              </label>
              <div id="psec-ipf-fields" style="flex:1;opacity:${(ipfCfg.cidrs||[]).length?'1':'0.45'};">
                <div class="field" style="margin:0 0 8px;">
                  <label class="field-label" style="font-size:11px">Mode</label>
                  <select id="psec-ipf-mode" class="input"><option value="deny" ${(ipfCfg.mode||'deny')==='deny'?'selected':''}>Deny (bloquer la liste)</option><option value="allow" ${ipfCfg.mode==='allow'?'selected':''}>Allow (autoriser uniquement la liste)</option></select>
                </div>
                <div class="field" style="margin:0;">
                  <label class="field-label" style="font-size:11px">CIDRs (une par ligne)</label>
                  <textarea id="psec-ipf-cidrs" class="input" rows="3" placeholder="10.0.0.0/8&#10;203.0.113.10/24">${esc((ipfCfg.cidrs||[]).join('\n'))}</textarea>
                </div>
              </div>
            </div>
            <div style="border-top:1px solid var(--border);padding-top:14px;">
              <div style="display:flex;gap:16px;align-items:flex-start;margin-bottom:10px;">
                <div style="display:flex;align-items:center;gap:8px;padding-top:22px;">
                  <label class="toggle"><input type="checkbox" id="psec-geo-enabled" ${(geoCfg.countries||[]).length?'checked':''} onchange="psecGeoToggleEnabled(this.checked)"><span class="toggle-slider"></span></label>
                  <span style="font-size:13px;font-weight:500;">GeoIP</span>
                </div>
                <div class="field" style="flex:1;margin:0;">
                  <label class="field-label" style="font-size:11px">Mode</label>
                  <select id="psec-geo-mode" class="input"><option value="deny" ${(geoCfg.mode||'deny')==='deny'?'selected':''}>Deny — bloquer les pays sélectionnés</option><option value="allow" ${geoCfg.mode==='allow'?'selected':''}>Allow — n'autoriser que les pays sélectionnés</option></select>
                </div>
              </div>
              <div id="psec-geo-fields" style="opacity:${(geoCfg.countries||[]).length?'1':'0.45'};">
                <div class="field" style="margin:0 0 8px;">
                  <label class="field-label" style="font-size:11px">Base MaxMind (.mmdb)</label>
                  <input id="psec-geo-db" class="input" placeholder="${esc((typeof GPX_GEO_DEFAULT_DB!=='undefined'&&GPX_GEO_DEFAULT_DB)||'/etc/goproxify/geoip/GeoLite2-Country.mmdb')}" value="${esc(geoCfg.db_path||'')}">
                  <div style="font-size:10px;color:var(--text3);margin-top:3px;">Requis sur la passerelle. Laisser vide pour utiliser le chemin par défaut.</div>
                </div>
                <div id="psec-geo-picker"></div>
              </div>
            </div>
          </div>
          <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 16px;">
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:12px;">JWT</div>
            <div style="display:flex;gap:16px;align-items:flex-start;margin-bottom:10px;">
              <label style="display:flex;align-items:center;gap:8px;cursor:pointer;padding-top:22px;">
                <label class="toggle"><input type="checkbox" id="psec-jwt-enabled" ${jwtCfg?.enabled?'checked':''}><span class="toggle-slider"></span></label>
                <span style="font-size:13px;font-weight:500;">Activé</span>
              </label>
              <div class="field" style="flex:1;margin:0;"><label class="field-label" style="font-size:11px">JWKS URL</label><input id="psec-jwt-jwks" class="input" placeholder="https://idp.example.com/.well-known/jwks.json" value="${esc(jwtCfg?.jwks_url||'')}"></div>
            </div>
            <div class="form-row" style="gap:8px;">
              <div class="field" style="flex:1;"><label class="field-label" style="font-size:11px">Audience</label><input id="psec-jwt-aud" class="input" value="${esc(jwtCfg?.audience||sec.jwt?.audience||'')}"></div>
              <div class="field" style="flex:1;"><label class="field-label" style="font-size:11px">Issuer</label><input id="psec-jwt-iss" class="input" value="${esc(jwtCfg?.issuer||sec.jwt?.issuer||'')}"></div>
            </div>
          </div>
        </div>

        <!-- Snippets réutilisables -->
        <div id="psectab-snippets" style="display:none;padding:16px 20px;flex-direction:column;gap:12px;">
          <div style="font-size:12px;color:var(--text3);line-height:1.45;">
            Profils de la bibliothèque <b>Snippets</b>. La config <b>inline</b> (onglet Paramètres) prime toujours sur un snippet du même type.
            <a href="#" onclick="event.preventDefault();closeModal();navigate('snippets')" style="color:var(--accent);margin-left:4px;">Gérer les snippets →</a>
          </div>
          <div id="psec-snippets-list" style="font-size:12.5px;color:var(--text3);">Chargement…</div>
        </div>

        <!-- Headers HTTP (Phase B : canal unique cfg.headers + custom, appliqué par SecurityHeaders) -->
        <div id="psectab-headers" style="display:none;padding:16px 20px;flex-direction:column;gap:10px;">
          <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-bottom:2px;">
            <div>
              <div style="font-size:13px;font-weight:600;">Analyse des headers HTTP de sécurité</div>
              <div style="font-size:11px;color:var(--text3);margin-top:2px;">Canal unique <code>headers</code> / <code>headers.custom</code> — HSTS et X-Frame-Options aussi éditables dans Paramètres.</div>
            </div>
            ${_fixCount > 0 ? `<button class="btn btn-primary btn-sm" onclick="applySecHeaders('${esc(id)}')">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="margin-right:4px;"><polyline points="20 6 9 17 4 12"/></svg>
              Appliquer les corrections sélectionnées
            </button>` : `<span style="font-size:11px;color:#34d399;font-weight:600;">✓ Tous les headers sont optimaux</span>`}
          </div>
          ${_hdrItems}
          ${_fixCount > 0 ? `<div style="font-size:11px;color:var(--text3);padding-top:4px;">Les headers cochés seront écrits dans <code>headers</code> et appliqués aux réponses clients par le Edge.</div>` : ''}
        </div>

        <!-- WAF -->
        <div id="psectab-waf" style="display:none;padding:16px 20px;flex-direction:column;gap:14px;">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:2px;">
            <div style="font-size:13px;font-weight:700;">Web Application Firewall</div>
            <div style="display:flex;gap:6px;">
              ${_hasOwnWaf ? `<button type="button" class="btn btn-ghost btn-sm" style="font-size:10px;color:var(--text3);" onclick="psecResetWafToEdge('${esc(id)}')">↩ Hériter du Edge</button>` : ''}
              <button type="button" class="btn btn-ghost btn-sm" style="font-size:10px;" onclick="psecToggleWAFAdvanced()">Avancé ▾</button>
            </div>
          </div>
          ${!_hasOwnWaf ? `
          <div style="display:flex;align-items:center;gap:8px;padding:9px 12px;background:color-mix(in srgb,var(--green) 8%,transparent);border:1px solid color-mix(in srgb,var(--green) 25%,var(--border));border-radius:8px;font-size:11.5px;color:var(--text2);">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="color:var(--green);flex-shrink:0"><polyline points="20 6 9 17 4 12"/></svg>
            <span>Hérite de la config WAF du Edge — <button type="button" onclick="psecActivateOwnWaf()" style="background:none;border:none;padding:0;cursor:pointer;color:var(--accent);font-size:11.5px;text-decoration:underline;">Personnaliser pour ce proxy</button></span>
          </div>` : ''}
          <div id="psec-waf-own" style="display:${_hasOwnWaf?'flex':'none'};flex-direction:column;gap:14px;">
            <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 16px;">
              <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:12px;">Activation</div>
              <div style="display:flex;gap:16px;align-items:flex-start;">
                <label style="display:flex;align-items:center;gap:8px;cursor:pointer;padding-top:2px;">
                  <label class="toggle"><input type="checkbox" id="psec-waf-enabled" ${wafCfg?.enabled?'checked':''}><span class="toggle-slider"></span></label>
                  <span style="font-size:13px;font-weight:500;">Activé</span>
                </label>
                <div class="field" style="flex:1;margin:0;">
                  <label class="field-label" style="font-size:11px">Mode</label>
                  <select id="psec-waf-mode" class="input">
                    <option value="block" ${(wafCfg?.mode||'block')==='block'?'selected':''}>Bloquer (403)</option>
                    <option value="detect" ${wafCfg?.mode==='detect'?'selected':''}>Détecter (log seul)</option>
                  </select>
                </div>
              </div>
            </div>
            <!-- Exclusions plateforme -->
            <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 16px;">
              <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px;">
                <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--text3);">Plateforme applicative</div>
                ${_detectedPlatform ? `<span style="font-size:10px;padding:2px 7px;border-radius:99px;background:color-mix(in srgb,var(--blue) 12%,transparent);color:var(--blue);border:1px solid color-mix(in srgb,var(--blue) 25%,var(--border));">✦ Détecté : ${_detectedPlatform}</span>` : ''}
              </div>
              <div style="font-size:11px;color:var(--text3);margin-bottom:10px;">Optionnel — sélectionner un CMS exclut les règles WAF connues pour générer des faux positifs sur cette plateforme. Ne rien sélectionner = toutes les règles actives.</div>
              <div style="margin-bottom:8px;">
                <label style="display:flex;align-items:center;gap:8px;padding:8px 10px;border:1px solid ${_autoMode?'var(--accent)':'var(--border)'};border-radius:7px;cursor:pointer;background:${_autoMode?'color-mix(in srgb,var(--accent) 6%,transparent)':'transparent'};" id="psec-pcard-auto" onclick="psecToggleAutoPlatform(this)">
                  <input type="checkbox" name="psec-platform-auto" id="psec-platform-auto" ${_autoMode?'checked':''} style="accent-color:var(--accent);">
                  <div>
                    <div style="font-size:12px;font-weight:500;">Auto-détection${_detectedPlatform ? ` <span style="font-size:10px;color:var(--blue);">(${_detectedPlatform} détecté)</span>` : ' <span style="font-size:10px;color:var(--text3);">(aucune plateforme détectée)</span>'}</div>
                    <div style="font-size:10px;color:var(--text3);line-height:1.3;">Détermine automatiquement les exclusions depuis l'URL upstream</div>
                  </div>
                </label>
              </div>
              <div id="psec-waf-platforms" style="display:flex;flex-direction:column;gap:12px;">
                ${[
                  { label: 'CMS & E-commerce', platforms: [
                    { id: 'wordpress',  name: 'WordPress',  desc: 'Gutenberg, REST API, WooCommerce' },
                    { id: 'drupal',     name: 'Drupal',     desc: 'Form tokens, AJAX, éditeur riche' },
                    { id: 'joomla',     name: 'Joomla',     desc: 'Éditeur JCE, composants com_*' },
                    { id: 'magento',    name: 'Magento',    desc: 'Catalogue, checkout, API REST' },
                    { id: 'prestashop', name: 'PrestaShop', desc: 'Boutique, back-office, modules' },
                    { id: 'ghost',      name: 'Ghost',      desc: 'Éditeur Mobiledoc/Lexical, API Content' },
                    { id: 'strapi',     name: 'Strapi',     desc: 'CMS headless, rich content JSON' },
                  ]},
                  { label: 'Frameworks', platforms: [
                    { id: 'nextjs',  name: 'Next.js', desc: 'API routes, Server Actions, JSON' },
                    { id: 'laravel', name: 'Laravel', desc: 'CSRF, Eloquent, Sanctum/Passport' },
                    { id: 'symfony', name: 'Symfony', desc: 'Forms, Doctrine, API Platform' },
                    { id: 'django',  name: 'Django',  desc: 'ORM, forms, DRF' },
                  ]},
                  { label: 'Collaboration & fichiers', platforms: [
                    { id: 'nextcloud',  name: 'Nextcloud',   desc: 'WebDAV, PROPFIND, partage fichiers' },
                    { id: 'dokuwiki',   name: 'DokuWiki',    desc: 'Syntaxe wiki, upload médias' },
                    { id: 'mattermost', name: 'Mattermost',  desc: 'Messages riches, code snippets' },
                    { id: 'discourse',  name: 'Discourse',   desc: 'Éditeur Markdown, BBCode' },
                    { id: 'rocketchat', name: 'Rocket.Chat', desc: 'Messages, fichiers joints' },
                  ]},
                  { label: 'DevOps & Infra', platforms: [
                    { id: 'gitea',     name: 'Gitea',     desc: 'Diffs, commits, code dans l\'UI' },
                    { id: 'forgejo',   name: 'Forgejo',   desc: 'Fork Gitea, même profil' },
                    { id: 'portainer', name: 'Portainer', desc: 'Commandes Docker, env vars' },
                    { id: 'proxmox',   name: 'Proxmox',   desc: 'Shell VMs, config hyperviseur' },
                    { id: 'grafana',   name: 'Grafana',   desc: 'PromQL, SQL-like queries' },
                    { id: 'zabbix',    name: 'Zabbix',    desc: 'Triggers SQL-like, items' },
                  ]},
                  { label: 'Outils métier', platforms: [
                    { id: 'odoo',     name: 'Odoo',     desc: 'ERP, formulaires complexes, ORM' },
                    { id: 'n8n',      name: 'n8n',      desc: 'Workflows JSON, expressions JS' },
                    { id: 'keycloak', name: 'Keycloak', desc: 'SSO, tokens OIDC, auth flows' },
                  ]},
                  { label: 'Médias & Selfhosted', platforms: [
                    { id: 'jellyfin',    name: 'Jellyfin',    desc: 'Chemins médias, API streaming' },
                    { id: 'immich',      name: 'Immich',      desc: 'Upload photos, EXIF metadata' },
                    { id: 'vaultwarden', name: 'Vaultwarden', desc: 'Champs password, JSON vault' },
                  ]},
                  { label: 'Administration', platforms: [
                    { id: 'cpanel', name: 'cPanel', desc: 'DNS, comptes email, zones WHM' },
                  ]},
                ].map(cat => `
                  <div>
                    <div style="font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--text3);margin-bottom:6px;">${cat.label}</div>
                    <div style="display:grid;grid-template-columns:1fr 1fr;gap:5px;">
                      ${cat.platforms.map(p => {
                        const active = _activePlatforms.has(p.id);
                        return `<label style="display:flex;align-items:flex-start;gap:8px;padding:7px 9px;border:1px solid ${active?'var(--accent)':'var(--border)'};border-radius:7px;cursor:pointer;background:${active?'color-mix(in srgb,var(--accent) 6%,transparent)':'transparent'};transition:border-color .15s;" id="psec-pcard-${p.id}" onclick="psecTogglePlatform('${p.id}',this)">
                          <input type="checkbox" name="psec-platform" value="${p.id}" ${active?'checked':''} style="margin-top:2px;flex-shrink:0;accent-color:var(--accent);">
                          <div><div style="font-size:11.5px;font-weight:500;">${p.name}</div><div style="font-size:10px;color:var(--text3);line-height:1.3;">${p.desc}</div></div>
                        </label>`;
                      }).join('')}
                    </div>
                  </div>`).join('')}
              </div>
            </div>
            <!-- Paramètres avancés WAF -->
            <div id="psec-waf-advanced" style="display:none;flex-direction:column;gap:10px;">
              <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 16px;display:flex;flex-direction:column;gap:10px;">
                <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);">Réglages avancés</div>
                <div class="form-row" style="gap:8px;">
                  <div class="field" style="flex:1;margin:0;">
                    <label class="field-label" style="font-size:11px">Score anomalie (0 = premier match)</label>
                    <input id="psec-waf-threshold" type="number" class="input" min="0" max="50" value="${wafCfg?.anomaly_threshold ?? 0}" placeholder="0">
                    <div style="font-size:10px;color:var(--text3);margin-top:2px;">OWASP recommande 5 (Critical=5, High=4, Medium=3, Low=1)</div>
                  </div>
                  <div class="field" style="flex:1;margin:0;">
                    <label class="field-label" style="font-size:11px">Max body (Mo)</label>
                    <input id="psec-waf-maxbody" type="number" class="input" min="1" max="100" value="${wafCfg?.max_body_mb ?? 10}">
                  </div>
                </div>
                <div class="field" style="margin:0;">
                  <label class="field-label" style="font-size:11px">IDs de règles à exclure (séparés par virgule)</label>
                  <input id="psec-waf-excludeids" class="input" placeholder="942100, 941110" value="${esc((wafCfg?.exclude_ids||[]).join(', '))}">
                </div>
                <div class="field" style="margin:0;">
                  <label class="field-label" style="font-size:11px">Règles custom (une par ligne : <code>id|category|severity|targets|pattern|message</code>)</label>
                  <div style="font-size:10px;color:var(--text3);margin-bottom:4px;">Targets : uri, args, body, headers, cookies (séparés par +). Severity : critical, high, medium, low.</div>
                  <textarea id="psec-waf-customrules" class="input" rows="4" style="font-family:monospace;font-size:11px;" placeholder="99001|sqli|high|args+body|(?i)evil-payload|Payload interdit">${esc((wafCfg?.custom_rules||[]).map(r => [r.id,r.category,r.severity,(r.targets||[]).join('+'),r.pattern,r.message].join('|')).join('\n'))}</textarea>
                </div>
              </div>
              <!-- Analyse comportementale -->
              <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:14px 16px;display:flex;flex-direction:column;gap:10px;">
                <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);">Analyse comportementale</div>
                <div style="font-size:11px;color:var(--text2);">Détecte les attaques fragmentées, les scans et les bots par accumulation de signaux sur une fenêtre glissante par IP.</div>
                <div style="display:flex;align-items:center;gap:8px;">
                  <label class="toggle" style="flex-shrink:0;"><input type="checkbox" id="psec-waf-behavior-enabled" ${wafCfg?.behavior_enabled?'checked':''}><span class="toggle-slider"></span></label>
                  <span style="font-size:12px;font-weight:500;">Activé</span>
                </div>
                <div class="form-row" style="gap:8px;">
                  <div class="field" style="flex:1;margin:0;">
                    <label class="field-label" style="font-size:11px">Fenêtre (secondes)</label>
                    <input id="psec-waf-behavior-window" type="number" class="input" min="10" max="3600" value="${wafCfg?.behavior_window_s ?? 60}" placeholder="60">
                    <div style="font-size:10px;color:var(--text3);margin-top:2px;">Durée d'observation par IP</div>
                  </div>
                  <div class="field" style="flex:1;margin:0;">
                    <label class="field-label" style="font-size:11px">Score seuil</label>
                    <input id="psec-waf-behavior-threshold" type="number" class="input" min="1" max="30" value="${wafCfg?.behavior_threshold ?? 8}" placeholder="8">
                    <div style="font-size:10px;color:var(--text3);margin-top:2px;">Signaux : 4xx élevé=4, burst=4, WAF cumulé=3-5, path scan=3, rotation UA=3, POST élevé=2</div>
                  </div>
                </div>
                <div class="field" style="margin:0;">
                  <label class="field-label" style="font-size:11px">Proxies de confiance (CIDRs)</label>
                  <input id="psec-waf-trusted-proxies" type="text" class="input" value="${(wafCfg?.trusted_proxies||[]).join(', ')}" placeholder="10.0.0.0/8, 172.16.0.0/12, 127.0.0.1">
                  <div style="font-size:10px;color:var(--text3);margin-top:2px;">IPs/CIDRs dont les headers X-Forwarded-For sont acceptés. Vide = RemoteAddr direct (plus sécurisé).</div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Bans & Blocs -->
        <div id="psectab-bans" style="display:none;padding:16px 20px;flex-direction:column;gap:8px;">
          <div id="psec-bans-content" style="font-size:12.5px;color:var(--text3);">Chargement…</div>
        </div>

        <!-- Timeline -->
        <div id="psectab-timeline" style="display:none;padding:16px 20px;flex-direction:column;gap:4px;">
          <div id="psec-timeline-content" style="font-size:12.5px;color:var(--text3);">Chargement…</div>
        </div>

      </div>
    </div>`;

  embedEl.innerHTML = body;
  switchSecTab(initialTab && ['recap','params','snippets','headers','waf','bans','timeline'].includes(initialTab) ? initialTab : 'recap');
  try { psecGeoInit(geoCfg.countries || [], 'psec-geo-picker'); } catch (e) { console.warn('psecGeoInit', e); }
  try {
    const snipList = document.getElementById('psec-snippets-list');
    if (snipList) snipList.innerHTML = psecSnippetsHTML(allSnippets, selectedSnippetIds, cfg);
  } catch (e) {
    console.warn('psecSnippetsHTML', e);
    const snipList = document.getElementById('psec-snippets-list');
    if (snipList) snipList.innerHTML = '<div style="font-size:12px;color:var(--red);">Impossible de charger les snippets.</div>';
  }
  // CrowdSec (async)
  api('GET', '/security/crowdsec').then(cs => {
    const card = document.getElementById('psec-crowdsec-card');
    if (!card) return;
    const enabled = cs?.enabled !== false;
    const apiKeyStatus = cs?.api_key ? '✓ Configurée' : '✗ Manquante';
    card.innerHTML = `
      <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:8px;">CrowdSec</div>
      <div style="display:flex;align-items:center;gap:10px;">
        <span style="padding:4px 12px;border-radius:99px;background:${enabled?'#34d39922':'var(--bg3)'};color:${enabled?'#34d399':'var(--text3)'};font-size:11px;font-weight:600;">${enabled ? '● Activé' : '○ Désactivé'}</span>
        <span style="font-size:11px;color:var(--text3);">Clé API : ${apiKeyStatus}${cs?.api_url ? ' · ' + esc(cs.api_url) : ''}</span>
      </div>`;
  }).catch(() => {
    const card = document.getElementById('psec-crowdsec-card');
    if (card) card.querySelector('div:last-child').textContent = 'Non disponible';
  });

  // Bans (async, filtré par domaine)
  const bansQ = host ? `?domain=${encodeURIComponent(host)}&active=true` : '?active=true';
  api('GET', `/security/bans${bansQ}`).then(bans => {
    const el = document.getElementById('psec-bans-content');
    if (!el) return;
    if (!bans?.length) {
      el.innerHTML = '<div style="font-size:13px;color:var(--text3);padding:24px 0;text-align:center;">Aucun ban actif pour ce domaine</div>';
      return;
    }
    el.innerHTML = bans.map(b => {
      const exp = b.expires_at ? `Expire ${fmtDate(b.expires_at)}` : 'Permanent';
      const srcColor = b.source === 'crowdsec' ? '#fb923c' : b.source === 'waf' ? '#f472b6' : 'var(--accent)';
      return `<div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:12px 16px;display:flex;align-items:center;gap:12px;">
        <div style="flex:1;min-width:0;">
          <div style="font-family:monospace;font-size:13px;font-weight:600;">${esc(b.ip)}</div>
          <div style="font-size:11px;color:var(--text3);margin-top:2px;">${esc(b.reason||'—')} · ${exp}</div>
        </div>
        <span style="padding:2px 8px;border-radius:99px;background:${srcColor}22;color:${srcColor};font-size:10px;font-weight:600;white-space:nowrap;">${esc(b.source||'manual')}</span>
        <span style="font-size:11px;color:var(--text3);white-space:nowrap;flex-shrink:0;">${fmtDate(b.created_at)}</span>
      </div>`;
    }).join('');
  }).catch(() => {
    const el = document.getElementById('psec-bans-content');
    if (el) el.textContent = 'Impossible de charger les bans.';
  });

  // Timeline (async, filtré par domaine)
  api('GET', '/security/timeline?source=all&limit=50').then(events => {
    const el = document.getElementById('psec-timeline-content');
    if (!el) return;
    const rootDom = host.split('.').slice(-2).join('.');
    const filtered = (events || []).filter(e => e.domain && (e.domain === host || e.domain.endsWith('.' + rootDom)));
    if (!filtered.length) {
      el.innerHTML = '<div style="font-size:13px;color:var(--text3);padding:24px 0;text-align:center;">Aucun événement de sécurité pour ce proxy</div>';
      return;
    }
    const sevColor = s => s === 'critical' ? '#ef4444' : s === 'high' ? '#f97316' : s === 'medium' ? '#f59e0b' : 'var(--text3)';
    el.innerHTML = filtered.map(e => `
      <div style="display:flex;gap:10px;align-items:flex-start;padding:8px 2px;border-bottom:1px solid var(--border);">
        <div style="width:6px;height:6px;border-radius:50%;background:${sevColor(e.severity)};margin-top:5px;flex-shrink:0;"></div>
        <div style="flex:1;min-width:0;">
          <div style="font-size:12.5px;font-weight:500;">${esc(e.summary||e.type||'—')}</div>
          <div style="font-size:11px;color:var(--text3);margin-top:1px;">${e.ip ? esc(e.ip) + ' · ' : ''}${fmtDate(e.created_at)}</div>
        </div>
        <span style="padding:2px 7px;border-radius:99px;background:${sevColor(e.severity)}22;color:${sevColor(e.severity)};font-size:10px;font-weight:600;white-space:nowrap;flex-shrink:0;">${esc(e.severity||'info')}</span>
      </div>`).join('');
  }).catch(() => {
    const el = document.getElementById('psec-timeline-content');
    if (el) el.textContent = 'Impossible de charger la timeline.';
  });
  } catch (e) {
    console.error('_psecMount', e);
    toast(e.message || 'Impossible de charger l\'onglet Protection', 'error');
  }
};

// La sécurité n'a plus de modale propre : c'est l'onglet « Protection » de la modale du proxy.
window.openProxySecModal = function(id, initialTab) {
  return openProxyModal(id, 'protection', initialTab);
};

window.psecToggleWAFAdvanced = function() {
  const el = document.getElementById('psec-waf-advanced');
  if (!el) return;
  el.style.display = el.style.display === 'none' ? 'flex' : 'none';
};

window.psecActivateOwnWaf = function() {
  const own = document.getElementById('psec-waf-own');
  if (own) own.style.display = 'flex';
  const inheritBanner = document.querySelector('[onclick*="psecActivateOwnWaf"]')?.closest('div[style*="background"]');
  if (inheritBanner) inheritBanner.style.display = 'none';
  switchSecTab('waf');
};

window.psecTogglePlatform = function(id, label) {
  const card = document.getElementById('psec-pcard-' + id);
  const cb = card?.querySelector('input[type=checkbox]');
  if (!card || !cb) return;
  const active = cb.checked;
  card.style.borderColor = active ? 'var(--accent)' : 'var(--border)';
  card.style.background = active ? 'color-mix(in srgb,var(--accent) 6%,transparent)' : 'transparent';
  if (active) {
    const autoCb = document.getElementById('psec-platform-auto');
    if (autoCb) autoCb.checked = false;
    const autoCard = document.getElementById('psec-pcard-auto');
    if (autoCard) { autoCard.style.borderColor = 'var(--border)'; autoCard.style.background = 'transparent'; }
  }
};

window.psecResetWafToEdge = async function(id) {
  if (!confirm('Supprimer la config WAF propre de ce proxy et hériter de la passerelle ?')) return;
  if (!await saveProxy(id, { keepOpen: true })) return;
  try {
    const existing = await api('GET', `/proxies/${encodeURIComponent(id)}`);
    let cfg = existing ? (typeof existing.config === 'string' ? tryJSON(existing.config) : existing.config || existing) : {};
    delete cfg.waf;
    await api('PUT', `/proxies/${encodeURIComponent(id)}`, { ...existing, config: cfg });
    toast('Config WAF réinitialisée — héritage passerelle active', 'success');
    await openProxyModal(id, 'protection', 'waf');
  } catch(e) { toast(e.message, 'error'); }
};

window.psecToggleAutoPlatform = function(label) {
  const cb = document.getElementById('psec-platform-auto');
  const card = document.getElementById('psec-pcard-auto');
  const checked = cb?.checked;
  if (card) {
    card.style.borderColor = checked ? 'var(--accent)' : 'var(--border)';
    card.style.background = checked ? 'color-mix(in srgb,var(--accent) 6%,transparent)' : 'transparent';
  }
  if (checked) {
    document.querySelectorAll('input[name="psec-platform"]').forEach(inp => {
      inp.checked = false;
      const c = document.getElementById('psec-pcard-' + inp.value);
      if (c) { c.style.borderColor = 'var(--border)'; c.style.background = 'transparent'; }
    });
  }
};

window.psecParseCustomRules = function(text) {
  const rules = [];
  for (const line of (text || '').split('\n')) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const parts = t.split('|');
    if (parts.length < 5) continue;
    const [id, category, severity, targets, ...rest] = parts;
    const pattern = rest.slice(0, -1).join('|');
    const message = rest[rest.length - 1] || '';
    const numId = parseInt(id, 10);
    if (!numId || !pattern) continue;
    rules.push({
      id: numId,
      category: category.trim() || 'custom',
      severity: severity.trim() || 'medium',
      targets: targets.trim().split('+').map(s => s.trim()).filter(Boolean),
      pattern: pattern.trim(),
      message: message.trim(),
    });
  }
  return rules;
};

window.switchSecTab = function(tab) {
  ['recap','params','snippets','headers','waf','bans','timeline'].forEach(t => {
    const panel = document.getElementById('psectab-' + t);
    if (panel) panel.style.display = t === tab ? 'flex' : 'none';
  });
  document.querySelectorAll('#psec-tabs [data-stab]').forEach(el => {
    const active = el.dataset.stab === tab;
    el.style.color = active ? 'var(--accent)' : 'var(--text2)';
    el.style.fontWeight = active ? '600' : '400';
    el.style.background = active ? 'color-mix(in srgb,var(--accent) 8%,transparent)' : '';
    el.style.borderLeft = active ? '2.5px solid var(--accent)' : '2.5px solid transparent';
  });
  // (Re)monter le sélecteur GeoIP à chaque ouverture de Paramètres
  if (tab === 'params') {
    try { psecGeoInit(psecGeoGetSelected(), 'psec-geo-picker'); } catch (e) { console.warn('psecGeoInit', e); }
  }
};

// ── Sélecteur GeoIP (pays + regroupements + recherche) ─────────────────────
// Racine DOM configurable (modale Sécurité = psec-geo-picker, page passerelle = edge-geo-picker)
window.psecGeoRoot = function() {
  return document.getElementById(window._psecGeoRootId || 'psec-geo-picker');
};

window.psecGeoInit = function(codes, rootId) {
  if (rootId) window._psecGeoRootId = rootId;
  else if (!window._psecGeoRootId) window._psecGeoRootId = 'psec-geo-picker';
  const incoming = (codes || []).map(c => String(c).toUpperCase().trim()).filter(Boolean);
  window._psecGeoSelected = new Set(incoming.length ? incoming : []);
  window._psecGeoQuery = '';
  psecGeoRender();
  const en = document.getElementById('psec-geo-enabled') || document.getElementById('edge-geo-enabled');
  psecGeoToggleEnabled(!!(en?.checked || window._psecGeoSelected.size));
};

window.psecGeoToggleEnabled = function(on) {
  const box = document.getElementById('psec-geo-fields') || document.getElementById('edge-geo-fields');
  if (box) box.style.opacity = on ? '1' : '0.45';
  const en = document.getElementById('psec-geo-enabled') || document.getElementById('edge-geo-enabled');
  if (en && en.checked !== !!on) en.checked = !!on;
  if (on) psecGeoRender();
};

window.psecGeoGetSelected = function() {
  return [...(window._psecGeoSelected || [])].sort();
};

window.psecGeoToggle = function(code, ev) {
  if (ev) { ev.preventDefault(); ev.stopPropagation(); }
  code = String(code).toUpperCase();
  if (!window._psecGeoSelected) window._psecGeoSelected = new Set();
  if (window._psecGeoSelected.has(code)) window._psecGeoSelected.delete(code);
  else window._psecGeoSelected.add(code);
  if (window._psecGeoSelected.size) psecGeoToggleEnabled(true);
  psecGeoSyncUI();
};

window.psecGeoSyncUI = function() {
  const root = psecGeoRoot();
  if (!root) return;
  const selected = psecGeoGetSelected();
  const sel = root.querySelector('.psec-geo-selected');
  if (sel) {
    sel.innerHTML = selected.length ? selected.map(c => `
      <span style="display:inline-flex;align-items:center;gap:5px;padding:3px 8px;border-radius:99px;background:var(--accent)18;color:var(--accent);font-size:11px;font-weight:600;">
        ${esc(psecGeoName(c))} <span style="opacity:.7;font-weight:500;">${c}</span>
        <button type="button" onclick="psecGeoToggle('${c}',event)" style="border:none;background:transparent;color:inherit;cursor:pointer;padding:0;line-height:1;font-size:13px;" title="Retirer">×</button>
      </span>`).join('') : `<span style="font-size:11px;color:var(--text3);">Aucun pays sélectionné — cherchez ou utilisez un regroupement</span>`;
  }
  const countEl = root.querySelector('.psec-geo-count');
  if (countEl) countEl.textContent = `${selected.length} sélectionné${selected.length!==1?'s':''}`;
  const clearBtn = root.querySelector('.psec-geo-clear');
  if (clearBtn) clearBtn.style.display = selected.length ? '' : 'none';
  root.querySelectorAll('.psec-geo-list [data-cc]').forEach(row => {
    const on = window._psecGeoSelected.has(row.dataset.cc);
    row.dataset.on = on ? '1' : '0';
    row.style.background = on ? 'color-mix(in srgb,var(--accent) 8%,transparent)' : 'transparent';
    const mark = row.querySelector('[data-mark]');
    if (mark) {
      mark.textContent = on ? '✓' : '';
      mark.style.background = on ? 'var(--accent)' : 'var(--bg3)';
      mark.style.color = on ? '#000' : 'transparent';
    }
  });
  root.querySelectorAll('.psec-geo-groups [data-gid]').forEach(btn => {
    const gid = btn.dataset.gid;
    const countries = (window.GPX_GEO_COUNTRIES || []).filter(p => p.g.includes(gid));
    const selectedIn = countries.filter(p => window._psecGeoSelected.has(p.c)).length;
    const allIn = selectedIn === countries.length && countries.length > 0;
    btn.className = `btn btn-sm ${allIn ? 'btn-primary' : 'btn-secondary'}`;
    const base = btn.dataset.label || btn.textContent.split(' · ')[0];
    btn.dataset.label = base;
    btn.textContent = selectedIn ? `${base} · ${selectedIn}` : base;
  });
};

window.psecGeoAddGroup = function(groupId, ev) {
  if (ev) { ev.preventDefault(); ev.stopPropagation(); }
  if (!window._psecGeoSelected) window._psecGeoSelected = new Set();
  (window.GPX_GEO_COUNTRIES || []).forEach(p => {
    if (p.g.includes(groupId)) window._psecGeoSelected.add(p.c);
  });
  psecGeoToggleEnabled(true);
  psecGeoRender();
};

window.psecGeoRemoveGroup = function(groupId, ev) {
  if (ev) { ev.preventDefault(); ev.stopPropagation(); }
  if (!window._psecGeoSelected) return;
  (window.GPX_GEO_COUNTRIES || []).forEach(p => {
    if (p.g.includes(groupId)) window._psecGeoSelected.delete(p.c);
  });
  psecGeoRender();
};

window.psecGeoClear = function(ev) {
  if (ev) { ev.preventDefault(); ev.stopPropagation(); }
  window._psecGeoSelected = new Set();
  psecGeoRender();
};

window.psecGeoSearch = function(q) {
  window._psecGeoQuery = (q || '').trim().toLowerCase();
  psecGeoRenderList();
};

window.psecGeoName = function(code) {
  return window.GPX_GEO_BY_CODE?.[code]?.n || code;
};

window.psecGeoRender = function() {
  const root = psecGeoRoot();
  if (!root) return;
  const selected = psecGeoGetSelected();
  const groups = window.GPX_GEO_GROUPS || [];
  const countries = window.GPX_GEO_COUNTRIES || [];
  if (!countries.length) {
    root.innerHTML = `<div style="padding:12px;border:1px solid color-mix(in srgb,var(--red) 40%,var(--border));border-radius:8px;background:color-mix(in srgb,var(--red) 8%,transparent);font-size:12px;color:var(--red);line-height:1.45;">
      Catalogue pays indisponible — <code>js/data/countries-geo.js</code> non chargé.
      Vérifiez que ce fichier est servi par l’Admin (rebuild / redéploiement requis).
    </div>`;
    return;
  }
  root.innerHTML = `
    <div style="margin-bottom:8px;">
      <div style="font-size:11px;color:var(--text3);margin-bottom:6px;">Regroupements — clic pour ajouter · Alt+clic pour retirer</div>
      <div class="psec-geo-groups" style="display:flex;flex-wrap:wrap;gap:6px;">
        ${groups.map(g => {
          const n = countries.filter(p => p.g.includes(g.id)).length;
          const selectedIn = countries.filter(p => p.g.includes(g.id) && window._psecGeoSelected?.has(p.c)).length;
          const allIn = selectedIn === n && n > 0;
          const label = g.name;
          return `<button type="button" class="btn btn-sm ${allIn?'btn-primary':'btn-secondary'}" data-gid="${esc(g.id)}" data-label="${esc(label)}"
            title="${esc(g.hint||'')} (${n} pays)"
            onclick="if(event.altKey)psecGeoRemoveGroup('${g.id}',event);else psecGeoAddGroup('${g.id}',event)"
            style="font-size:11px;padding:4px 8px;">${esc(label)}${selectedIn?` · ${selectedIn}`:''}</button>`;
        }).join('')}
      </div>
    </div>
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap;">
      <input class="psec-geo-search input" style="flex:1;min-width:160px;" placeholder="Rechercher un pays (nom ou code)…"
        value="${esc(window._psecGeoQuery||'')}" oninput="psecGeoSearch(this.value)" autocomplete="off">
      <span class="psec-geo-count" style="font-size:11px;color:var(--text3);white-space:nowrap;">${selected.length} sélectionné${selected.length!==1?'s':''}</span>
      <button type="button" class="psec-geo-clear btn btn-ghost btn-sm" onclick="psecGeoClear(event)" style="font-size:11px;${selected.length?'':'display:none'}">Tout retirer</button>
    </div>
    <div class="psec-geo-selected" style="display:flex;flex-wrap:wrap;gap:5px;min-height:28px;margin-bottom:8px;">
      ${selected.length ? selected.map(code => `
        <span style="display:inline-flex;align-items:center;gap:5px;padding:3px 8px;border-radius:99px;background:var(--accent)18;color:var(--accent);font-size:11px;font-weight:600;">
          ${esc(psecGeoName(code))} <span style="opacity:.7;font-weight:500;">${code}</span>
          <button type="button" onclick="psecGeoToggle('${code}',event)" style="border:none;background:transparent;color:inherit;cursor:pointer;padding:0;line-height:1;font-size:13px;" title="Retirer">×</button>
        </span>`).join('') : `<span style="font-size:11px;color:var(--text3);">Aucun pays sélectionné — cherchez ou utilisez un regroupement</span>`}
    </div>
    <div class="psec-geo-list" style="max-height:220px;overflow-y:auto;border:1px solid var(--border);border-radius:8px;background:var(--bg);"></div>`;
  psecGeoRenderList();
};

window.psecGeoRenderList = function() {
  const root = psecGeoRoot();
  const list = root?.querySelector('.psec-geo-list');
  if (!list) return;
  const q = (window._psecGeoQuery || '').toLowerCase();
  const rows = (window.GPX_GEO_COUNTRIES || []).filter(p => {
    if (!q) return true;
    return p.n.toLowerCase().includes(q) || p.c.toLowerCase().includes(q)
      || (window.GPX_GEO_GROUPS||[]).some(g => p.g.includes(g.id) && g.name.toLowerCase().includes(q));
  });
  if (!rows.length) {
    list.innerHTML = '<div style="padding:16px;font-size:12px;color:var(--text3);text-align:center;">Aucun pays ne correspond</div>';
    return;
  }
  list.innerHTML = rows.slice(0, 120).map(p => {
    const on = window._psecGeoSelected?.has(p.c);
    return `<div data-cc="${p.c}" data-on="${on?'1':'0'}" role="button" tabindex="0"
      onclick="psecGeoToggle('${p.c}',event)"
      onkeydown="if(event.key==='Enter'||event.key===' '){psecGeoToggle('${p.c}',event)}"
      style="display:flex;align-items:center;gap:8px;padding:7px 10px;cursor:pointer;border-bottom:1px solid var(--border);background:${on?'color-mix(in srgb,var(--accent) 8%,transparent)':'transparent'};user-select:none;">
      <span data-mark style="flex-shrink:0;width:18px;height:18px;border-radius:4px;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;background:${on?'var(--accent)':'var(--bg3)'};color:${on?'#000':'transparent'};">${on?'✓':''}</span>
      <span style="flex:1;font-size:12.5px;">${esc(p.n)}</span>
      <code style="font-size:10px;color:var(--text3);">${p.c}</code>
    </div>`;
  }).join('') + (rows.length > 120
    ? `<div style="padding:8px 10px;font-size:11px;color:var(--text3);">Affichage de 120 / ${rows.length} — affinez la recherche</div>`
    : '');
};

// Lit les champs de l'onglet Protection (psec-*) et les applique sur `baseCfg`.
// Utilisé par l'enregistrement unique de la modale proxy (saveProxy).
window._psecBuildConfig = function(baseCfg) {
  const jwtEnabled = document.getElementById('psec-jwt-enabled')?.checked;
  const jwtJwks = document.getElementById('psec-jwt-jwks')?.value.trim();
  const wafEnabled = document.getElementById('psec-waf-enabled')?.checked;
  const botEnabled = document.getElementById('psec-bot-enabled')?.checked;
  const wafMode = document.getElementById('psec-waf-mode')?.value || 'block';
  const botMode = document.getElementById('psec-bot-mode')?.value || 'block';
  const wafThreshold = parseInt(document.getElementById('psec-waf-threshold')?.value || '0', 10) || 0;
  const wafMaxBody = parseInt(document.getElementById('psec-waf-maxbody')?.value || '10', 10) || 10;
  const wafExcludeRaw = (document.getElementById('psec-waf-excludeids')?.value || '').split(',').map(s => parseInt(s.trim(), 10)).filter(n => n > 0);
  const wafCustomRules = typeof psecParseCustomRules === 'function' ? psecParseCustomRules(document.getElementById('psec-waf-customrules')?.value || '') : [];
  const wafBehaviorEnabled = document.getElementById('psec-waf-behavior-enabled')?.checked ?? false;
  const wafBehaviorWindow = parseInt(document.getElementById('psec-waf-behavior-window')?.value || '60', 10) || 60;
  const wafBehaviorThreshold = parseInt(document.getElementById('psec-waf-behavior-threshold')?.value || '8', 10) || 8;
  const wafTrustedProxies = (document.getElementById('psec-waf-trusted-proxies')?.value || '').split(',').map(s => s.trim()).filter(Boolean);
  const wafAutoDetect = document.getElementById('psec-platform-auto')?.checked;
  const wafPlatforms = wafAutoDetect ? ['auto'] : [...document.querySelectorAll('input[name="psec-platform"]:checked')].map(cb => cb.value);
  const sentinelWhitelist = (document.getElementById('psec-sentinel-whitelist')?.value || '').split(',').map(s => s.trim()).filter(Boolean);
  const hsts = document.getElementById('psec-hsts')?.checked;
  const hideServer = document.getElementById('psec-hide-server')?.checked;
  const xfo = document.getElementById('psec-xfo')?.value || '';
  const rlEnabled = document.getElementById('psec-rl-enabled')?.checked;
  const ipfEnabled = document.getElementById('psec-ipf-enabled')?.checked;
  const cidrs = (document.getElementById('psec-ipf-cidrs')?.value || '').split('\n').map(s => s.trim()).filter(Boolean);
  const geoEnabled = document.getElementById('psec-geo-enabled')?.checked;
  const geoCountries = psecGeoGetSelected();
  const geoDb = document.getElementById('psec-geo-db')?.value.trim();
  const cfg = migrateHeadersConfig({ ...(baseCfg || {}) });
  // Chemins canoniques lus par ComputeHeaderScore (headers, rate_limit, ip_filter, waf, bot, jwt)
  const updatedConfig = {
    ...cfg,
    headers: {
      ...(cfg.headers || {}),
      hsts: !!hsts,
      hsts_max_age: hsts ? (parseInt(document.getElementById('psec-hsts-maxage')?.value, 10) || 31536000) : (cfg.headers?.hsts_max_age || 31536000),
      hide_server: !!hideServer,
      x_frame_options: xfo || '',
    },
    waf: wafEnabled ? {
      enabled: true,
      mode: wafMode === 'detect' ? 'detect' : 'block',
      anomaly_threshold: wafThreshold || undefined,
      max_body_mb: wafMaxBody !== 10 ? wafMaxBody : undefined,
      exclude_ids: wafExcludeRaw.length ? wafExcludeRaw : undefined,
      custom_rules: wafCustomRules.length ? wafCustomRules : undefined,
      behavior_enabled: wafBehaviorEnabled || undefined,
      behavior_window_s: wafBehaviorEnabled ? wafBehaviorWindow : undefined,
      behavior_threshold: wafBehaviorEnabled ? wafBehaviorThreshold : undefined,
      trusted_proxies: wafTrustedProxies.length ? wafTrustedProxies : undefined,
      exclude_platforms: wafPlatforms.length ? wafPlatforms : undefined,
    } : undefined,
    bot: botEnabled ? {
      enabled: true,
      mode: botMode === 'challenge' ? 'challenge' : (botMode === 'log' ? 'log' : 'block'),
      js_challenge: botMode === 'challenge',
    } : undefined,
    jwt: (jwtEnabled || jwtJwks) ? {
      enabled: !!jwtEnabled,
      jwks_url: jwtJwks || undefined,
      audience: document.getElementById('psec-jwt-aud')?.value.trim() || undefined,
      issuer: document.getElementById('psec-jwt-iss')?.value.trim() || undefined,
    } : undefined,
    rate_limit: rlEnabled ? {
      rps: parseFloat(document.getElementById('psec-rl-rps')?.value) || 10,
      burst: parseInt(document.getElementById('psec-rl-burst')?.value, 10) || 20,
    } : undefined,
    ip_filter: (ipfEnabled && cidrs.length) ? {
      mode: document.getElementById('psec-ipf-mode')?.value || 'deny',
      cidrs,
    } : undefined,
    geo_ip: (geoEnabled && geoCountries.length) ? {
      mode: document.getElementById('psec-geo-mode')?.value || 'deny',
      countries: geoCountries,
      db_path: geoDb || cfg.geo_ip?.db_path || (typeof GPX_GEO_DEFAULT_DB !== 'undefined' ? GPX_GEO_DEFAULT_DB : '/etc/goproxify/geoip/GeoLite2-Country.mmdb'),
    } : undefined,
    sentinel_whitelist: sentinelWhitelist.length ? sentinelWhitelist : undefined,
    snippet_ids: (() => {
      const ids = typeof psecGetSnippetIds === 'function' ? psecGetSnippetIds() : (cfg.snippet_ids || []);
      return ids.length ? ids : undefined;
    })(),
  };
  // Nettoyer custom des doublons HSTS/XFO (gérés en typés)
  if (updatedConfig.headers?.custom) {
    const custom = { ...updatedConfig.headers.custom };
    Object.keys(custom).forEach(k => {
      const lk = k.toLowerCase();
      if (lk === 'strict-transport-security' || lk === 'x-frame-options') delete custom[k];
    });
    if (Object.keys(custom).length) updatedConfig.headers.custom = custom;
    else delete updatedConfig.headers.custom;
  }
  return updatedConfig;
};

window.applySecHeaders = async function(id) {
  const checks = [...document.querySelectorAll('.psec-hdr-fix:checked')];
  if (!checks.length) { toast('Aucun header sélectionné', 'error'); return; }
  // Les autres onglets sont enregistrés d'abord : la modale est rechargée depuis le serveur ensuite.
  if (!await saveProxy(id, { keepOpen: true })) return;
  try {
    const existing = await api('GET', `/proxies/${encodeURIComponent(id)}`);
    const cfg = existing ? (typeof existing.config === 'string' ? tryJSON(existing.config) : existing.config || existing) : {};
    const toApply = checks.map(cb => ({ name: cb.dataset.hname, val: cb.dataset.hval }));
    let updatedConfig = migrateHeadersConfig({ ...cfg });
    for (const h of toApply) {
      updatedConfig = applySecurityHeaderToCfg(updatedConfig, h.name, h.val);
    }
    await api('PUT', `/proxies/${encodeURIComponent(id)}`, { config: updatedConfig, enabled: existing.enabled !== false });
    toast(`${checks.length} header${checks.length > 1 ? 's' : ''} de sécurité appliqué${checks.length > 1 ? 's' : ''}`, 'success');
    await openProxyModal(id, 'protection', 'headers');
  } catch(e) { toast(e.message || 'Erreur lors de l\'application', 'error'); }
};
