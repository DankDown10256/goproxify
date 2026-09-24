// ── PAGE: Contexte Core (waf, ipfilter, certs, auth, metrics, cluster…) ─
// Extrait de pages-all.js — phase 3. Trafic Core reste dans trafic.js.

const _stubPage = (label) => function() {
  document.getElementById('content').innerHTML = `
    <div class="empty">
      <svg width="48" height="48" fill="none" stroke="currentColor" stroke-width="1.5" viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="3"/><path d="M9 12h6M12 9v6"/></svg>
      <p style="font-size:15px;font-weight:600;margin-top:8px">${esc(label)}</p>
      <p style="font-size:13px;margin-top:4px">${t('corepage.wip_soon')}</p>
    </div>`;
};

// ── PAGE: WAF ──────────────────────────────────────────────────────────────
pages['core-waf'] = async function() {
  const content = document.getElementById('content');
  content.innerHTML = '<p style="color:var(--text2)">' + t('common.loading') + '</p>';
  try {
    const core = state.selectedCore;
    const coreLabel = core?.display_name || core?.node_name || core?.id || '—';
    const snippets = await api('GET', '/snippets').catch(() => []) || [];
    const wafSnippets = snippets.filter(s => s.type === 'waf' || s.profile_type === 'waf');
    const parseCfg = (s) => {
      if (!s) return {};
      if (typeof s.config === 'string') { try { return JSON.parse(s.config); } catch { return {}; } }
      return s.config || {};
    };
    const wafPrimary = parseCfg(wafSnippets[0]);
    let wafMode = wafPrimary.mode || (wafPrimary.enabled === false ? 'off' : (wafPrimary.enabled ? 'block' : 'off'));
    if (wafPrimary.enabled === false) wafMode = 'off';
    if (wafMode !== 'block' && wafMode !== 'detect' && wafMode !== 'off') wafMode = wafPrimary.enabled ? 'block' : 'off';
    const excluded = new Set(Array.isArray(wafPrimary.exclude_categories) ? wafPrimary.exclude_categories : []);
    // Compat : exclude_ids → catégories
    const CAT_IDS = {
      sqli:        [942100, 942110, 942120],
      xss:         [941100, 941110, 941120],
      traversal:   [930100, 930110],
      rce:         [932100, 932110],
      php:         [933100],
      ssrf:        [934100],
      scanner:     [913100],
      java:        [944100, 944110, 944120],
      rfi:         [931100, 931110],
      nodejs:      [934200, 934210],
      smuggling:   [920200, 920210],
      restricted:  [930200, 930210, 930220],
      leakage:     [951100, 951110, 951120, 951130],
      ssi:         [935100, 935110, 935120],
      blocklist:   [938100, 938110, 938120],
      fakebot:     [913110, 913120],
      dos:         [912100, 912110, 912120],
      generic:     [936100, 936110, 936120],
    };
    if (Array.isArray(wafPrimary.exclude_ids) && wafPrimary.exclude_ids.length) {
      const idSet = new Set(wafPrimary.exclude_ids);
      Object.entries(CAT_IDS).forEach(([cat, ids]) => {
        if (ids.every(id => idSet.has(id))) excluded.add(cat);
      });
    }

    const decompressBody = wafPrimary.decompress_body === true;
    const activePlatforms = new Set(Array.isArray(wafPrimary.exclude_platforms) ? wafPrimary.exclude_platforms : []);

    const PLATFORM_IDS = {
      wordpress:   [941100, 941110, 941120, 942100, 942110, 942120],
      drupal:      [941100, 941110, 942100, 942110],
      joomla:      [941100, 941110, 942100, 942110],
      magento:     [941100, 941110, 942100, 942110, 942120],
      prestashop:  [941100, 942100, 942110],
      ghost:       [941100, 941110, 941120],
      strapi:      [941100, 942100, 942110],
      nextjs:      [942100, 942110, 934200, 934210],
      laravel:     [942100, 942110, 942120],
      symfony:     [942100, 942110, 942120],
      django:      [942100, 942110],
      nextcloud:   [941100, 930100, 930110],
      dokuwiki:    [941100, 941110],
      mattermost:  [941100, 942100],
      discourse:   [941100, 941110, 941120],
      rocketchat:  [941100, 942100],
      gitea:       [941100, 941110, 942100, 930100],
      forgejo:     [941100, 941110, 942100, 930100],
      portainer:   [932100, 942100],
      proxmox:     [932100, 932110, 933100],
      grafana:     [942100, 942110],
      zabbix:      [942100, 942110],
      odoo:        [942100, 942110, 941100],
      n8n:         [934200, 942100, 941100],
      keycloak:    [942100, 920100],
      jellyfin:    [930100, 930110],
      immich:      [930100, 941100],
      vaultwarden: [942100, 941110],
      cpanel:      [941100, 941110, 920100],
    };

    const PLATFORM_CATEGORIES = [
      { label: 'CMS & E-commerce', platforms: [
        { id: 'wordpress',  name: 'WordPress',  desc: "Gutenberg, REST API, WooCommerce — XSS/SQLi/form tokens." },
        { id: 'drupal',     name: 'Drupal',     desc: "Form tokens, AJAX, éditeur riche — XSS/SQLi/path." },
        { id: 'joomla',     name: 'Joomla',     desc: "Éditeur JCE, composants com_* — XSS/SQLi." },
        { id: 'magento',    name: 'Magento',    desc: "Catalogue, checkout, API REST — SQLi/XSS." },
        { id: 'prestashop', name: 'PrestaShop', desc: "Boutique, back-office, modules — XSS/SQLi." },
        { id: 'ghost',      name: 'Ghost',      desc: "Éditeur Mobiledoc/Lexical, API Content — XSS." },
        { id: 'strapi',     name: 'Strapi',     desc: "CMS headless, rich content JSON — XSS/SQLi." },
      ]},
      { label: 'Frameworks', platforms: [
        { id: 'nextjs',   name: 'Next.js',  desc: "API routes, Server Actions, JSON — SQLi/NodeJS injection." },
        { id: 'laravel',  name: 'Laravel',  desc: "CSRF, Eloquent, Sanctum/Passport — SQLi/form tokens." },
        { id: 'symfony',  name: 'Symfony',  desc: "Forms, Doctrine, API Platform — SQLi/form tokens." },
        { id: 'django',   name: 'Django',   desc: "ORM, forms, DRF — SQLi/form tokens." },
      ]},
      { label: 'Collaboration & fichiers', platforms: [
        { id: 'nextcloud',  name: 'Nextcloud',   desc: "WebDAV, PROPFIND, partage fichiers — LFI/path." },
        { id: 'dokuwiki',   name: 'DokuWiki',    desc: "Syntaxe wiki, upload médias — XSS." },
        { id: 'mattermost', name: 'Mattermost',  desc: "Messages riches, code snippets — XSS/SQLi." },
        { id: 'discourse',  name: 'Discourse',   desc: "Éditeur Markdown, BBCode — XSS." },
        { id: 'rocketchat', name: 'Rocket.Chat', desc: "Messages, fichiers joints — XSS/SQLi." },
      ]},
      { label: 'DevOps & Infra', platforms: [
        { id: 'gitea',     name: 'Gitea',     desc: "Diffs, commits, code dans l'UI — XSS/SQLi/LFI." },
        { id: 'forgejo',   name: 'Forgejo',   desc: "Fork Gitea, même profil de faux positifs." },
        { id: 'portainer', name: 'Portainer', desc: "Commandes Docker, env vars — RCE/SQLi." },
        { id: 'proxmox',   name: 'Proxmox',   desc: "Shell VMs, config — RCE/PHP injection." },
        { id: 'grafana',   name: 'Grafana',   desc: "PromQL, SQL-like queries — SQLi." },
        { id: 'zabbix',    name: 'Zabbix',    desc: "Triggers SQL-like, items — SQLi." },
      ]},
      { label: 'Outils métier', platforms: [
        { id: 'odoo',     name: 'Odoo',     desc: "ERP, formulaires, ORM — SQLi/XSS." },
        { id: 'n8n',      name: 'n8n',      desc: "Workflows JSON, expressions JS — NodeJS/SQLi." },
        { id: 'keycloak', name: 'Keycloak', desc: "SSO, tokens OIDC — SQLi/protocol." },
      ]},
      { label: 'Médias & Selfhosted', platforms: [
        { id: 'jellyfin',    name: 'Jellyfin',    desc: "Chemins médias, API — LFI." },
        { id: 'immich',      name: 'Immich',      desc: "Upload photos, EXIF metadata — LFI/XSS." },
        { id: 'vaultwarden', name: 'Vaultwarden', desc: "Champs password, JSON vault — SQLi/XSS." },
      ]},
      { label: 'Administration', platforms: [
        { id: 'cpanel',   name: 'cPanel',   desc: "DNS, comptes email, zones WHM — XSS/protocol." },
      ]},
    ];
    const PLATFORMS = PLATFORM_CATEGORIES.flatMap(c => c.platforms);

    const RULES = [
      { id: 'sqli',       name: 'SQL Injection',               category: 'OWASP CRS-4', ids: '942100–942999', desc: "Détecte ' OR 1=1, UNION SELECT, --, xp_cmdshell, blind SQLi temporelle et encodages SQL alternatifs." },
      { id: 'xss',        name: 'Cross-Site Scripting',        category: 'OWASP CRS-4', ids: '941100–941999', desc: "Détecte <script>, handlers d'événements (onerror=), javascript:, et leurs variantes encodées (HTML entities, URL, Unicode)." },
      { id: 'traversal',  name: 'Path Traversal / LFI',        category: 'OWASP CRS-4', ids: '930100–930199', desc: 'Détecte ../../etc/passwd, null-byte injection (%00) et traversées de répertoire dans les paramètres de chemin.' },
      { id: 'rce',        name: 'Command Injection',           category: 'OWASP CRS-4', ids: '932100–932999', desc: "Détecte les tentatives d'exécution système : ; cat /etc/passwd, backticks, $(cmd), exec(). Couvre Unix et Windows." },
      { id: 'php',        name: 'PHP Injection',               category: 'OWASP CRS-4', ids: '933100–933999', desc: 'Détecte php://, eval(), désérialisation PHP et wrappers dangereux comme php://input ou phar://.' },
      { id: 'ssrf',       name: 'SSRF',                        category: 'OWASP CRS-4', ids: '934100–934199', desc: 'Détecte les tentatives de redirection vers des ressources internes (169.254.x.x, localhost, métadonnées cloud).' },
      { id: 'scanner',    name: 'Scanner Detection',           category: 'OWASP CRS-4', ids: '913100–913999', desc: 'Reconnaît les signatures de Nikto, Nessus, sqlmap, Burp Suite via leurs User-Agents et patterns de requête caractéristiques.' },
      { id: 'java',       name: 'Java / Log4Shell',            category: 'OWASP CRS-4', ids: '944100–944999', desc: 'Détecte Log4Shell (${jndi:), désérialisation Java (gadget chains), expressions EL/OGNL. Couvre les CVE critiques depuis 2017.' },
      { id: 'rfi',        name: 'Remote File Inclusion',       category: 'OWASP CRS-4', ids: '931100–931999', desc: "Détecte ?page=http://evil.com/shell.php et inclusions d'URLs externes dans des paramètres contrôlant des chemins de fichiers." },
      { id: 'nodejs',     name: 'NodeJS / Prototype Pollution', category: 'OWASP CRS-4', ids: '934200–934999', desc: 'Détecte la pollution de prototype (__proto__, constructor.prototype), injections dans child_process et template injection Node.' },
      { id: 'smuggling',  name: 'HTTP Request Smuggling',      category: 'OWASP CRS-4', ids: '920200–920999', desc: 'Bloque HTTP Request Smuggling, Response Splitting et header injection. Critique sur les architectures proxy/reverse-proxy.' },
      { id: 'restricted', name: 'Restricted / Sensitive Files', category: 'OWASP CRS-4', ids: '930200–930999', desc: "Bloque l'accès aux fichiers sensibles : .env, .git/, wp-config.php, /etc/passwd, clés SSH et fichiers de configuration." },
      { id: 'leakage',    name: 'Response Data Leakage',       category: 'OWASP CRS-4', ids: '951100–951999', desc: "Détecte les messages d'erreur SQL, stack traces Java/PHP et erreurs IIS dans les réponses sortantes pour éviter la fuite d'informations." },
      { id: 'ssi',        name: 'Server-Side Include Injection', category: 'OWASP CRS-4', ids: '935100–935999', desc: "Détecte les injections SSI : <!--#exec cmd=...>, directives SSI dans Apache/Nginx. Vecteur souvent oublié sur les serveurs legacy." },
      { id: 'blocklist',  name: 'Extension Blocklist',         category: 'OWASP CRS-4', ids: '938100–938999', desc: "Bloque les uploads d'extensions exécutables : .php, .asp, .jsp, .cgi. À combiner avec la vérification du Content-Type réel." },
      { id: 'fakebot',    name: 'Fake Bot Detection',          category: 'OWASP CRS-4', ids: '913110–913999', desc: "Détecte les bots qui usurpent des User-Agents légitimes (Googlebot, Bingbot) via vérification des signatures connues." },
      { id: 'dos',        name: 'DoS Protection (HTTP Flood)', category: 'OWASP CRS-4', ids: '912100–912999', desc: "Détecte les floods HTTP applicatifs par fenêtre glissante par IP. Complémentaire au rate limiting réseau de la page Sécurité." },
      { id: 'generic',    name: 'Generic Injection',           category: 'OWASP CRS-4', ids: '936100–936999', desc: "Catch-all pour les injections de template (Jinja2, Twig, Freemarker) et les payloads polyglots non couverts par les règles spécialisées." },
    ];

    content.innerHTML = `
      <div style="margin-bottom:20px">
        <h1 style="margin:0 0 4px;font-size:28px;font-family:var(--font-heading);font-weight:600;">${t('page.core-waf')}</h1>
        <p style="margin:0;opacity:0.65;font-size:14px;">${t('corepage.waf.subtitle', { core: esc(coreLabel) })}</p>
      </div>
      <div style="display:flex;align-items:flex-start;gap:10px;padding:10px 14px;background:color-mix(in srgb,var(--blue) 8%,transparent);border:1px solid color-mix(in srgb,var(--blue) 25%,var(--border));border-radius:8px;font-size:12.5px;color:var(--text2);margin-bottom:20px">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;margin-top:1px;color:var(--blue)"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        <span>Cette configuration s'applique à <strong>tous les proxies</strong> de ce Core par défaut. Un proxy peut définir sa propre config WAF via un <strong>snippet de type <code>waf</code></strong> — dans ce cas, la config du Core ne s'applique plus à ce proxy.</span>
      </div>
      <div class="card blueprint" style="padding:18px;display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:20px">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div>
          <div class="card-kicker">${t('corepage.waf.global_mode')}</div>
          <div class="card-title" style="font-size:16px;" id="waf-mode-label">${t(wafMode==='detect'?'corepage.mode.detect_only':(wafMode==='off'?'common.disabled':'corepage.mode.block'))}</div>
        </div>
        <div class="seg">
          <label class="seg-opt"><input type="radio" name="waf-mode" value="block" ${wafMode==='block'?'checked':''} onchange="updateWafModeLabel(this.value)">${t('corepage.mode.block')}</label>
          <label class="seg-opt"><input type="radio" name="waf-mode" value="detect" ${wafMode==='detect'?'checked':''} onchange="updateWafModeLabel(this.value)">${t('corepage.mode.detect')}</label>
          <label class="seg-opt"><input type="radio" name="waf-mode" value="off" ${wafMode==='off'?'checked':''} onchange="updateWafModeLabel(this.value)">${t('common.disabled')}</label>
        </div>
      </div>
      <div class="card blueprint" style="padding:14px 18px;display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:20px;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div>
          <div class="card-kicker">Inspection body gzip</div>
          <div style="font-size:13px;color:var(--text2);margin-top:2px;">Décompresse les corps gzip avant analyse — contourne l'évasion par compression des payloads malveillants.</div>
        </div>
        <label class="toggle" style="flex-shrink:0;">
          <input type="checkbox" id="waf-decompress" ${decompressBody ? 'checked' : ''}>
          <span class="toggle-track"></span>
        </label>
      </div>
      <div style="margin-bottom:20px;">
        <h6 style="margin:0 0 4px;">Exclusions plateforme</h6>
        <p style="margin:0 0 12px;font-size:12px;opacity:0.6;">Sélectionnez le CMS ou la plateforme derrière ce proxy — les règles générant des faux positifs connus seront exclues automatiquement.</p>
        <div style="display:flex;flex-direction:column;gap:16px;">
          ${PLATFORM_CATEGORIES.map(cat => `
          <div>
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--text3);margin-bottom:8px;">${esc(cat.label)}</div>
            <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(min(200px,100%),1fr));gap:6px;">
              ${cat.platforms.map(p => `
              <label style="display:flex;align-items:flex-start;gap:10px;padding:10px 12px;border:1px solid var(--border);border-radius:8px;cursor:pointer;transition:border-color .15s;" class="platform-card" id="platform-card-${p.id}">
                <input type="checkbox" name="platform-exclusion" value="${p.id}" ${activePlatforms.has(p.id)?'checked':''} style="margin-top:2px;flex-shrink:0;" onchange="togglePlatformCard('${p.id}',this.checked)">
                <div>
                  <div style="font-weight:500;font-size:13px;">${esc(p.name)}</div>
                  <div style="font-size:11px;opacity:0.55;margin-top:2px;line-height:1.4;">${esc(p.desc)}</div>
                </div>
              </label>`).join('')}
            </div>
          </div>`).join('')}
        </div>
      </div>
      <div>
        <h6 style="margin:0 0 12px;">${t('corepage.waf.rules_heading')}</h6>
        <div class="card blueprint" style="overflow:hidden;">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <div class="table-wrap">
          <table class="table">
            <thead><tr><th>${t('corepage.col.rule')}</th><th>${t('corepage.col.category')}</th><th>IDs</th><th>${t('corepage.col.status')}</th><th></th></tr></thead>
            <tbody>
              ${RULES.map(r => {
                const active = !excluded.has(r.id);
                return `<tr>
                <td>
                  <div style="font-weight:500;">${esc(r.name)}</div>
                  ${r.desc ? `<div style="font-size:11.5px;opacity:0.55;margin-top:2px;line-height:1.45;max-width:380px;">${esc(r.desc)}</div>` : ''}
                </td>
                <td style="opacity:0.7;white-space:nowrap;">${esc(r.category)}</td>
                <td style="font-family:monospace;font-size:12px;opacity:0.65;">${esc(r.ids)}</td>
                <td><span class="tag ${active?'tag-green':'tag-neutral'}" id="waf-status-${r.id}">${active?t('corepage.status.active'):t('trafic.inactive')}</span></td>
                <td style="text-align:right;"><button class="btn btn-ghost" onclick="toggleWafRule('${r.id}')">${active?t('corepage.action.disable'):t('common.enable')}</button></td>
              </tr>`;
              }).join('')}
            </tbody>
          </table>
          </div>
        </div>
      </div>
      <div style="margin-top:16px;display:flex;justify-content:flex-end;">
        <button type="button" class="btn btn-primary" id="core-waf-save" onclick="saveCoreWaf()">${t('common.save')}</button>
      </div>
      ${wafSnippets.length ? `
      <div style="margin-top:20px;">
        <h6 style="margin:0 0 12px;">${t('corepage.waf.profiles_heading')}</h6>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(min(300px,100%),1fr));gap:14px;">
          ${wafSnippets.map(s => `
          <div class="card blueprint" style="padding:14px 16px;">
            <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
            <div class="card-title" style="font-size:13.5px;">${esc(s.name)}</div>
            <div class="card-meta">${esc(s.description||t('corepage.waf.profile_default'))}</div>
          </div>`).join('')}
        </div>
      </div>` : ''}
      <div style="margin-top:32px;">
        <h6 style="margin:0 0 4px;">Détection comportementale (AppSensor)</h6>
        <p style="margin:0 0 14px;font-size:12px;opacity:0.6;">Analyse stateful par fenêtre glissante — chaque IP accumule un score comportemental indépendant du score WAF par requête.</p>
        <div class="card blueprint" style="overflow:hidden;margin-bottom:20px;">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <div class="table-wrap">
          <table class="table">
            <thead><tr><th>Signal</th><th>Seuil de déclenchement</th><th style="text-align:right;">Score ajouté</th></tr></thead>
            <tbody>
              <tr><td><div style="font-weight:500;">high_4xx_rate</div><div style="font-size:11.5px;opacity:0.55;margin-top:2px;">Taux de réponses 4xx élevé</div></td><td style="font-size:12px;opacity:0.7;">&gt; 40 % de réponses 4xx sur ≥ 5 requêtes</td><td style="text-align:right;font-family:monospace;color:var(--orange);">+4</td></tr>
              <tr><td><div style="font-weight:500;">path_scanning</div><div style="font-size:11.5px;opacity:0.55;margin-top:2px;">Scan de chemins</div></td><td style="font-size:12px;opacity:0.7;">&gt; 15 chemins uniques dans la fenêtre</td><td style="text-align:right;font-family:monospace;color:var(--orange);">+3</td></tr>
              <tr><td><div style="font-weight:500;">waf_score_accumulation</div><div style="font-size:11.5px;opacity:0.55;margin-top:2px;">Accumulation de score WAF</div></td><td style="font-size:12px;opacity:0.7;">Score WAF cumulé ≥ 8 (critique : ≥ 15)</td><td style="text-align:right;font-family:monospace;color:var(--orange);">+3 / +5</td></tr>
              <tr><td><div style="font-weight:500;">ua_rotation</div><div style="font-size:11.5px;opacity:0.55;margin-top:2px;">Rotation de User-Agent</div></td><td style="font-size:12px;opacity:0.7;">&gt; 3 User-Agents distincts (bot qui se camoufle)</td><td style="text-align:right;font-family:monospace;color:var(--orange);">+3</td></tr>
              <tr><td><div style="font-weight:500;">request_burst</div><div style="font-size:11.5px;opacity:0.55;margin-top:2px;">Rafale de requêtes</div></td><td style="font-size:12px;opacity:0.7;">&gt; 30 requêtes dans les 10 dernières secondes</td><td style="text-align:right;font-family:monospace;color:var(--orange);">+4</td></tr>
              <tr><td><div style="font-weight:500;">high_post_ratio</div><div style="font-size:11.5px;opacity:0.55;margin-top:2px;">Ratio POST anormal</div></td><td style="font-size:12px;opacity:0.7;">&gt; 70 % de méthodes POST/PUT/PATCH sur ≥ 10 req</td><td style="text-align:right;font-family:monospace;color:var(--orange);">+2</td></tr>
              <tr><td><div style="font-weight:500;">high_path_entropy</div><div style="font-size:11.5px;opacity:0.55;margin-top:2px;">Entropie des chemins élevée</div></td><td style="font-size:12px;opacity:0.7;">Entropie &gt; 0.85 sur ≥ 20 requêtes (fuzzing)</td><td style="text-align:right;font-family:monospace;color:var(--orange);">+2</td></tr>
            </tbody>
          </table>
          </div>
        </div>
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;">
          <h6 style="margin:0;">Profils IP actifs</h6>
          <button class="btn btn-sm" id="waf-behavior-refresh" onclick="loadWafBehaviorProfiles()">Actualiser</button>
        </div>
        <div id="waf-behavior-profiles"><p style="color:var(--text2);font-size:13px;">Chargement…</p></div>
      </div>`;

    window._coreWafSnippetId = wafSnippets[0]?.id || null;
    window._coreWafSnippetName = wafSnippets[0]?.name || 'WAF Core';
    window._wafExcluded = excluded;
    window._wafCatIds = CAT_IDS;
    window._wafPlatformIds = PLATFORM_IDS;
    window.togglePlatformCard = function(id, checked) {
      const card = document.getElementById('platform-card-' + id);
      if (card) card.style.borderColor = checked ? 'var(--accent)' : 'var(--border)';
    };
    PLATFORMS.forEach(p => { if (activePlatforms.has(p.id)) window.togglePlatformCard(p.id, true); });
    window.updateWafModeLabel = function(val) {
      const labels = { block: t('corepage.mode.block'), detect: t('corepage.mode.detect_only'), off: t('common.disabled') };
      document.getElementById('waf-mode-label').textContent = labels[val] || val;
    };
    window.toggleWafRule = function(id) {
      const el = document.getElementById('waf-status-' + id);
      const btn = el?.closest('tr')?.querySelector('button');
      if (!el) return;
      const active = el.classList.contains('tag-green');
      el.className = active ? 'tag tag-neutral' : 'tag tag-green';
      el.textContent = active ? t('trafic.inactive') : t('corepage.status.active');
      if (btn) btn.textContent = active ? t('common.enable') : t('corepage.action.disable');
      if (active) window._wafExcluded.add(id); else window._wafExcluded.delete(id);
    };
    window.saveCoreWaf = async function() {
      const mode = document.querySelector('input[name="waf-mode"]:checked')?.value || 'off';
      const excludeCategories = [...(window._wafExcluded || [])];
      const excludeIds = excludeCategories.flatMap(cat => (window._wafCatIds?.[cat] || []));
      const excludePlatforms = [...document.querySelectorAll('input[name="platform-exclusion"]:checked')].map(el => el.value);
      const platformIds = excludePlatforms.flatMap(p => (window._wafPlatformIds?.[p] || []));
      const allExcludeIds = [...new Set([...excludeIds, ...platformIds])];
      const config = {
        mode: mode === 'off' ? 'block' : mode,
        enabled: mode !== 'off',
        exclude_categories: excludeCategories,
        exclude_ids: allExcludeIds,
        exclude_platforms: excludePlatforms,
        decompress_body: document.getElementById('waf-decompress')?.checked === true,
      };
      const btn = document.getElementById('core-waf-save');
      if (btn) { btn.disabled = true; btn.textContent = t('common.saving') || '…'; }
      try {
        const payload = {
          name: window._coreWafSnippetName || 'WAF Core',
          type: 'waf',
          description: t('corepage.waf.profile_default'),
          config,
        };
        const id = window._coreWafSnippetId;
        if (id) {
          await api('PUT', `/snippets/${encodeURIComponent(id)}`, payload);
        } else {
          const created = await api('POST', '/snippets', payload);
          if (created?.id) {
            window._coreWafSnippetId = created.id;
            window._coreWafSnippetName = created.name || payload.name;
          }
        }
        toast(t('common.saved') || 'WAF enregistré', 'success');
        navigate('core-waf');
      } catch (e) {
        toast(e.message || t('common.error'), 'error');
      } finally {
        if (btn) { btn.disabled = false; btn.textContent = t('common.save'); }
      }
    };
    const coreId = core?.id || core;
    window.loadWafBehaviorProfiles = async function() {
      const el = document.getElementById('waf-behavior-profiles');
      if (!el) return;
      let profiles = {};
      try {
        if (coreId) profiles = await coreProxy(coreId, 'GET', '/internal/v1/waf/behavior/profiles') || {};
      } catch { /* ignore */ }
      const rows = Object.entries(profiles).sort((a, b) => b[1].score - a[1].score);
      const scoreColor = (s) => s >= 8 ? 'var(--red)' : s >= 4 ? 'var(--orange)' : 'var(--text3)';
      const signalLabels = {
        high_4xx_rate: 'Taux 4xx élevé',
        path_scanning: 'Scan de chemins',
        waf_score_accumulation: 'Accumulation WAF',
        ua_rotation: 'Rotation UA',
        request_burst: 'Rafale',
        high_post_ratio: 'Ratio POST',
        high_path_entropy: 'Entropie paths',
        distributed_scan: 'Scan distribué',
      };
      const ipRows = rows.filter(([k]) => !k.startsWith('subnet:'));
      const subnetRows = rows.filter(([k]) => k.startsWith('subnet:'));
      if (rows.length === 0) {
        el.innerHTML = `<div style="text-align:center;padding:32px;color:var(--text2);font-size:13px;border:1px solid var(--border);border-radius:8px;">Aucun profil comportemental actif</div>`;
        return;
      }
      const renderRows = (list, isSubnet) => list.map(([key, info]) => {
        const display = isSubnet ? key.replace('subnet:', '') : key;
        const canDelete = !isSubnet;
        return `<tr>
          <td style="font-family:monospace;">
            ${isSubnet ? `<span style="display:inline-block;background:var(--orange);color:#fff;font-size:10px;padding:1px 5px;border-radius:3px;margin-right:4px;vertical-align:middle;">SUBNET</span>` : ''}
            ${esc(display)}
          </td>
          <td style="text-align:right;">
            <span style="background:${scoreColor(info.score)};color:#fff;padding:2px 8px;border-radius:4px;font-weight:600;font-size:12px;">${info.score}</span>
          </td>
          <td>
            ${(info.signals||[]).map(s => `
              <span style="display:inline-flex;align-items:center;gap:3px;background:var(--bg2);border:1px solid var(--border);border-radius:4px;padding:1px 7px;font-size:11px;margin:1px;">
                ${esc(signalLabels[s.name]||s.name)}
                <span style="opacity:0.6;">+${s.score}</span>
              </span>`).join('')}
          </td>
          <td style="text-align:center;font-size:12px;">
            ${!isSubnet && info.trust_bonus > 0
              ? `<span style="color:var(--green);font-weight:600;" title="${info.clean_requests} req propres">+${info.trust_bonus}</span>`
              : `<span style="opacity:0.4;">–</span>`}
          </td>
          <td style="text-align:right;">
            ${canDelete ? `<button class="btn btn-ghost" style="color:var(--red);font-size:12px;" onclick="deleteWafBehaviorProfile('${esc(key)}')">Supprimer</button>` : ''}
          </td>
        </tr>`;
      }).join('');
      el.innerHTML = `
        <div class="card blueprint" style="overflow:hidden;">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <div class="table-wrap">
          <table class="table">
            <thead><tr>
              <th>IP / Sous-réseau</th>
              <th style="text-align:right;">Score</th>
              <th>Signaux déclenchés</th>
              <th style="text-align:center;">Crédit confiance</th>
              <th></th>
            </tr></thead>
            <tbody>
              ${renderRows(ipRows, false)}
              ${renderRows(subnetRows, true)}
            </tbody>
          </table>
          </div>
        </div>`;
    };
    window.deleteWafBehaviorProfile = async function(ip) {
      try {
        if (coreId) await coreProxy(coreId, 'DELETE', `/internal/v1/waf/behavior/profiles/${encodeURIComponent(ip)}`);
        toast('Profil supprimé', 'success');
        loadWafBehaviorProfiles();
      } catch(e) { toast(e.message, 'error'); }
    };
    loadWafBehaviorProfiles();
  } catch(e) { content.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`; }
};

// ── PAGE: IP / GeoIP / Bot ─────────────────────────────────────────────────
pages['core-ipfilter'] = async function() {
  const content = document.getElementById('content');
  content.innerHTML = '<p style="color:var(--text2)">' + t('common.loading') + '</p>';
  try {
    const core = state.selectedCore;
    const coreLabel = core?.display_name || core?.node_name || core?.id || '—';
    const snippets = await api('GET', '/snippets').catch(() => []) || [];
    const parseCfg = (s) => {
      if (!s) return {};
      if (typeof s.config === 'string') { try { return JSON.parse(s.config); } catch { return {}; } }
      return s.config || {};
    };
    const ipSnippets = snippets.filter(s => s.type === 'ip_filter' || s.profile_type === 'ip_filter');
    const geoSnippets = snippets.filter(s => s.type === 'geo_ip' || s.profile_type === 'geo_ip');
    const botSnippets = snippets.filter(s => s.type === 'bot' || s.profile_type === 'bot');
    const geoCodes = [...new Set(geoSnippets.flatMap(s => {
      const c = parseCfg(s);
      return [...(c.countries || []), ...(c.blocked_countries || [])];
    }).map(c => String(c).toUpperCase().trim()).filter(Boolean))];
    const geoPrimary = parseCfg(geoSnippets[0]);
    const geoMode = geoPrimary.mode || 'deny';
    const geoDb = geoPrimary.db_path || '';
    const geoDefaultDb = (typeof GPX_GEO_DEFAULT_DB !== 'undefined' && GPX_GEO_DEFAULT_DB) || '/etc/goproxify/geoip/GeoLite2-Country.mmdb';
    const botPrimary = parseCfg(botSnippets[0]);
    let botMode = botPrimary.mode || (botPrimary.enabled ? 'block' : 'off');
    if (botMode === 'log') botMode = 'monitor';
    if (!botPrimary.enabled && botMode !== 'off' && botMode !== 'monitor' && botMode !== 'block') botMode = 'off';
    if (botPrimary.enabled === false) botMode = 'off';
    const botChallenge = !!(botPrimary.js_challenge || botPrimary.challenge);

    content.innerHTML = `
      <div style="margin-bottom:20px">
        <h1 style="margin:0 0 4px;font-size:28px;font-family:var(--font-heading);font-weight:600;">${t('page.core-ipfilter')}</h1>
        <p style="margin:0;opacity:0.65;font-size:14px;">${t('corepage.ipfilter.subtitle', { core: esc(coreLabel) })}</p>
        <p style="margin:4px 0 0;opacity:0.55;font-size:12.5px;">${t('corepage.ipfilter.defaults_hint')}</p>
      </div>

      <div class="card blueprint" style="padding:20px;display:flex;flex-direction:column;gap:14px;margin-bottom:16px;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap;">
          <h6 style="margin:0;">${t('corepage.ipfilter.manual_list')}</h6>
          <button class="btn btn-ghost" onclick="openIpRuleModal()">${t('corepage.ipfilter.new_rule')}</button>
        </div>
        <div class="table-wrap">
        <table class="table">
          <thead><tr><th>${t('corepage.col.cidr')}</th><th>${t('corepage.col.type')}</th><th>${t('common.note')}</th><th></th></tr></thead>
          <tbody id="ip-rules-body"><tr><td colspan="4" class="empty"><p>${t('corepage.ipfilter.no_rules')}</p></td></tr></tbody>
        </table>
        </div>
      </div>

      ${ipSnippets.length ? `
      <div style="margin-bottom:16px;">
        <h6 style="margin:0 0 8px;">${t('corepage.ipfilter.threat_feeds')}</h6>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(min(200px,100%),1fr));gap:12px;">
          ${ipSnippets.map(s => `
          <div class="card blueprint" style="padding:14px 16px;">
            <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
            <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px;">
              <div class="card-title" style="font-size:13.5px;">${esc(s.name)}</div>
              <span class="tag tag-outline" style="font-size:10px;">${s.config?.mode === 'allow' ? 'ALLOW' : 'DENY'}</span>
            </div>
            <div class="card-meta" style="font-size:11px;">${esc(s.description||'')}</div>
          </div>`).join('')}
        </div>
      </div>` : ''}

      <div class="card blueprint" style="padding:20px;display:flex;flex-direction:column;gap:14px;margin-bottom:16px;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <h6 style="margin:0;">${t('corepage.geo.title')}</h6>
        <p style="margin:0;font-size:12.5px;color:var(--text3);">${t('corepage.geo.picker_hint')}</p>
        <div style="display:flex;gap:16px;align-items:flex-start;">
          <div style="display:flex;align-items:center;gap:8px;padding-top:22px;">
            <label class="toggle"><input type="checkbox" id="core-geo-enabled" ${geoCodes.length?'checked':''} onchange="psecGeoToggleEnabled(this.checked)"><span class="toggle-slider"></span></label>
            <span style="font-size:13px;font-weight:500;">${t('corepage.geo.label')}</span>
          </div>
          <div class="field" style="flex:1;margin:0;">
            <label class="field-label" style="font-size:11px">${t('corepage.geo.mode_label')}</label>
            <select id="core-geo-mode" class="input">
              <option value="deny" ${geoMode!=='allow'?'selected':''}>${t('corepage.geo.mode_deny')}</option>
              <option value="allow" ${geoMode==='allow'?'selected':''}>${t('corepage.geo.mode_allow')}</option>
            </select>
          </div>
        </div>
        <div id="core-geo-fields" style="opacity:${geoCodes.length?'1':'0.45'};">
          <div class="field" style="margin:0 0 8px;">
            <label class="field-label" style="font-size:11px">${t('corepage.geo.db_label')}</label>
            <input id="core-geo-db" class="input" placeholder="${esc(geoDefaultDb)}" value="${esc(geoDb)}">
            <div style="font-size:10px;color:var(--text3);margin-top:3px;">${t('corepage.geo.db_hint')}</div>
          </div>
          <div id="core-geo-picker"></div>
        </div>
        ${geoSnippets.length ? `<div style="font-size:11px;color:var(--text3);border-top:1px solid var(--border);padding-top:10px;">
          ${t('corepage.geo.linked_snippets')} ${geoSnippets.map(s => `<code>${esc(s.name||s.id)}</code>`).join(', ')}
        </div>` : ''}
        <div style="display:flex;justify-content:flex-end;gap:8px;border-top:1px solid var(--border);padding-top:12px;margin-top:4px;">
          <button type="button" class="btn btn-primary" id="core-geo-save" onclick="saveCoreGeoIP()">${t('corepage.geo.save')}</button>
        </div>
      </div>

      <div class="card blueprint" style="padding:20px;display:flex;flex-direction:column;gap:14px;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <h6 style="margin:0;">${t('corepage.bot.title')}</h6>
        <div class="seg" style="align-self:flex-start;">
          <label class="seg-opt"><input type="radio" name="bot-mode" value="off" ${botMode==='off'?'checked':''} onchange="updateBotMode(this.value)">${t('common.disabled')}</label>
          <label class="seg-opt"><input type="radio" name="bot-mode" value="monitor" ${botMode==='monitor'?'checked':''} onchange="updateBotMode(this.value)">${t('corepage.bot.mode_monitor')}</label>
          <label class="seg-opt"><input type="radio" name="bot-mode" value="block" ${botMode==='block'?'checked':''} onchange="updateBotMode(this.value)">${t('corepage.bot.mode_block')}</label>
        </div>
        <div style="display:flex;align-items:center;gap:10px;">
          <span style="font-size:13px;opacity:0.75;">${t('corepage.bot.js_challenge')}</span>
          <span class="tag ${botChallenge?'tag-accent':'tag-neutral'}" id="bot-challenge-tag" style="cursor:pointer;" onclick="toggleBotChallenge()">${botChallenge ? t('common.enabled') : t('common.disabled')}</span>
        </div>
        <div style="display:flex;justify-content:flex-end;gap:8px;border-top:1px solid var(--border);padding-top:12px;margin-top:4px;">
          <button type="button" class="btn btn-primary" id="core-bot-save" onclick="saveCoreBot()">${t('corepage.bot.save')}</button>
        </div>
      </div>

`;

    try { psecGeoInit(geoCodes, 'core-geo-picker'); } catch (e) { console.warn('core geo init', e); }
    window._coreGeoSnippetId = geoSnippets[0]?.id || null;
    window._coreGeoSnippetName = geoSnippets[0]?.name || 'GeoIP Core';
    window.saveCoreGeoIP = async function() {
      const enabled = !!document.getElementById('core-geo-enabled')?.checked;
      const mode = document.getElementById('core-geo-mode')?.value || 'deny';
      const dbPath = (document.getElementById('core-geo-db')?.value || '').trim();
      const countries = enabled ? psecGeoGetSelected() : [];
      if (enabled && !countries.length) {
        toast(t('corepage.geo.toast_select_country'), 'error');
        return;
      }
      const config = {
        mode,
        countries,
        blocked_countries: countries, // alias legacy (page / affichages anciens)
        db_path: dbPath || undefined,
      };
      const id = window._coreGeoSnippetId;
      if (!enabled && !countries.length && !id) {
        toast(t('corepage.geo.toast_already_inactive'), 'info');
        return;
      }
      const btn = document.getElementById('core-geo-save');
      if (btn) { btn.disabled = true; btn.textContent = t('corepage.geo.saving'); }
      try {
        const payload = {
          name: window._coreGeoSnippetName || 'GeoIP Core',
          type: 'geo_ip',
          description: t('corepage.geo_default_desc'),
          config,
        };
        if (id) {
          await api('PUT', `/snippets/${encodeURIComponent(id)}`, payload);
        } else {
          const created = await api('POST', '/snippets', payload);
          if (created?.id) {
            window._coreGeoSnippetId = created.id;
            window._coreGeoSnippetName = created.name || payload.name;
          }
        }
        toast(enabled ? t('corepage.geo.toast_saved', { n: countries.length }) : t('corepage.geo.toast_disabled'), 'success');
        navigate('core-ipfilter');
      } catch (e) {
        toast(e.message || t('corepage.geo.toast_error'), 'error');
      } finally {
        if (btn) { btn.disabled = false; btn.textContent = t('corepage.geo.save'); }
      }
    };
    window._ipRules = [];
    window.renderIpRules = function() {
      const body = document.getElementById('ip-rules-body');
      if (!body) return;
      body.innerHTML = window._ipRules.length ? window._ipRules.map((r,i) => `<tr>
        <td style="font-family:monospace;">${esc(r.cidr)}</td>
        <td><span class="tag ${r.type==='allow'?'tag-green':'tag-red'}">${r.type==='allow'?t('corepage.ipfilter.allow'):t('corepage.ipfilter.deny')}</span></td>
        <td style="opacity:0.7;">${esc(r.note||'')}</td>
        <td style="text-align:right;"><button class="btn btn-ghost btn-icon" onclick="removeIpRule(${i})" title="${t('common.delete')}"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3 6h18"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg></button></td>
      </tr>`).join('') : '<tr><td colspan="4" class="empty"><p>' + t('corepage.ipfilter.no_rules') + '</p></td></tr>';
    };
    window.openIpRuleModal = function() {
      document.getElementById('ip-rule-modal-backdrop')?.remove();
      document.body.insertAdjacentHTML('beforeend', `
        <div id="ip-rule-modal-backdrop" class="dialog-backdrop" style="background:rgba(0,0,0,0.55);">
          <div class="dialog blueprint" role="dialog" aria-modal="true">
            <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
            <div class="dialog-title">${t('corepage.ipfilter.modal_title')}</div>
            <div class="dialog-body" style="display:flex;flex-direction:column;gap:14px;">
              <div class="field"><label>${t('corepage.ipfilter.cidr_label')}</label><input class="input" id="nr-cidr" placeholder="${t('corepage.ipfilter.cidr_ph')}"></div>
              <div class="field"><label>${t('corepage.col.type')}</label><div class="seg">
                <label class="seg-opt"><input type="radio" name="nr-type" value="allow" checked>${t('corepage.ipfilter.allow')}</label>
                <label class="seg-opt"><input type="radio" name="nr-type" value="deny">${t('corepage.ipfilter.deny')}</label>
              </div></div>
              <div class="field"><label>${t('common.note')}</label><input class="input" id="nr-note" placeholder="${t('corepage.ipfilter.note_ph')}"></div>
            </div>
            <div class="dialog-actions">
              <button class="btn btn-secondary blueprint" onclick="document.getElementById('ip-rule-modal-backdrop').remove()"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>${t('common.cancel')}</button>
              <button class="btn btn-primary blueprint" onclick="createIpRule()"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>${t('corepage.ipfilter.add_rule')}</button>
            </div>
          </div>
        </div>`);
    };
    window.createIpRule = function() {
      const cidr = document.getElementById('nr-cidr')?.value;
      const type = document.querySelector('input[name="nr-type"]:checked')?.value || 'deny';
      const note = document.getElementById('nr-note')?.value;
      if (!cidr) return;
      window._ipRules.push({ cidr, type, note });
      document.getElementById('ip-rule-modal-backdrop')?.remove();
      renderIpRules();
    };
    window.removeIpRule = function(i) { window._ipRules.splice(i,1); renderIpRules(); };
    window._coreBotSnippetId = botSnippets[0]?.id || null;
    window._coreBotSnippetName = botSnippets[0]?.name || 'Bot Core';
    window.updateBotMode = function(val) {
      const tag = document.getElementById('bot-challenge-tag');
      if (!tag) return;
      if (val === 'off') {
        tag.className = 'tag tag-neutral';
        tag.textContent = t('common.disabled');
        tag.style.opacity = '0.45';
        tag.style.pointerEvents = 'none';
      } else {
        tag.style.opacity = '1';
        tag.style.pointerEvents = '';
      }
    };
    window.toggleBotChallenge = function() {
      const el = document.getElementById('bot-challenge-tag');
      if (!el || el.style.pointerEvents === 'none') return;
      const active = el.classList.contains('tag-accent');
      el.className = active ? 'tag tag-neutral' : 'tag tag-accent';
      el.textContent = active ? t('common.disabled') : t('common.enabled');
    };
    window.saveCoreBot = async function() {
      const mode = document.querySelector('input[name="bot-mode"]:checked')?.value || 'off';
      const challenge = !!document.getElementById('bot-challenge-tag')?.classList.contains('tag-accent') && mode !== 'off';
      const config = {
        mode,
        enabled: mode !== 'off',
        js_challenge: challenge,
      };
      const btn = document.getElementById('core-bot-save');
      if (btn) { btn.disabled = true; btn.textContent = t('corepage.bot.saving'); }
      try {
        const payload = {
          name: window._coreBotSnippetName || 'Bot Core',
          type: 'bot',
          description: t('corepage.bot_default_desc'),
          config,
        };
        const id = window._coreBotSnippetId;
        if (id) {
          await api('PUT', `/snippets/${encodeURIComponent(id)}`, payload);
        } else {
          const created = await api('POST', '/snippets', payload);
          if (created?.id) {
            window._coreBotSnippetId = created.id;
            window._coreBotSnippetName = created.name || payload.name;
          }
        }
        const modeLabels = { off: t('corepage.bot.mode_off'), monitor: t('corepage.bot.mode_monitor_short'), block: t('corepage.bot.mode_block_short') };
        const detail = (modeLabels[mode] || mode) + (challenge ? t('corepage.bot.challenge_suffix') : '');
        toast(t('corepage.bot.toast_saved', { detail }), 'success');
        navigate('core-ipfilter');
      } catch (e) {
        toast(e.message || t('corepage.bot.toast_error'), 'error');
      } finally {
        if (btn) { btn.disabled = false; btn.textContent = t('corepage.bot.save'); }
      }
    };
    try { updateBotMode(botMode); } catch (_) {}
  } catch(e) { content.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`; }
};

// Certificats TLS Core → pages['core-certs'] dans domains.js (renderCertsPage)

// ── PAGE: Tokens d'appairage (récap lecture seule) ───────────────────────
// La CRUD complète (création, scopes, révocation) reste dans Accès → Tokens :
// un token sert à appairer un Core qui n'existe pas encore, la gestion ne
// peut donc pas être scopée à un Core déjà appairé.
pages['core-tokens'] = async function() {
  const content = document.getElementById('content');
  const core = state.selectedCore;
  const coreLabel = core?.display_name || core?.node_name || '—';
  content.innerHTML = '<p style="color:var(--text2)">' + t('common.loading') + '</p>';
  if (!core) { content.innerHTML = `<p style="color:var(--text2)">${t('trafic.no_core')}</p>`; return; }

  try {
    const tokens = await api('GET', '/tokens?role=core').catch(() => []);
    const refs = new Set([core.id, core.node_name, core.display_name].filter(Boolean));
    const matching = (tokens || []).filter(tok => refs.has(tok.id) || refs.has(tok.node_name));

    const scopeTypeLabels = _tokenScopeTypeLabels();
    const rows = await Promise.all(matching.map(async tok => {
      const scopes = await api('GET', `/tokens/${encodeURIComponent(tok.id)}/scopes`).catch(() => []);
      const status = _tokenStatus(tok);
      const scopeTags = (scopes || []).length
        ? scopes.map(s => `<span class="tag ${_scopeTagCls(s.scope_type)}" style="font-size:10px;">${esc(scopeTypeLabels[s.scope_type] || s.scope_type)}: ${esc(s.value || s.scope_value)}</span>`).join(' ')
        : `<span style="font-size:12px;color:var(--text3);">${t('coretokens.no_scope')}</span>`;
      return `<div class="card blueprint" style="padding:14px 16px;margin-bottom:10px;">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-bottom:8px;">
          <div style="display:flex;align-items:center;gap:8px;">
            <span class="tag ${status.cls}" style="font-size:10px;">${esc(status.label)}</span>
            ${_rbacBadge(tok.rbac_role)}
          </div>
          <span style="font-size:11px;color:var(--text3);">${tok.expires_at ? t('tokens.col_expires') + ' ' + esc(new Date(tok.expires_at).toLocaleDateString()) : t('tokens.no_expiry')}</span>
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:6px;">${scopeTags}</div>
      </div>`;
    }));

    content.innerHTML = `
      <div style="margin-bottom:16px;">
        <h1 style="margin:0 0 4px;font-size:24px;font-family:var(--font-heading);font-weight:600;">${t('coretokens.title')}</h1>
        <p style="margin:0;font-size:13px;color:var(--text2);">${t('coretokens.subtitle', { core: esc(coreLabel) })}</p>
      </div>
      <div style="margin-bottom:16px;padding:10px 12px;background:color-mix(in srgb,var(--accent) 7%,transparent);border:1px solid color-mix(in srgb,var(--accent) 22%,transparent);border-radius:6px;font-size:12px;color:var(--text2);display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;">
        <span>${t('coretokens.banner')}</span>
        <button class="btn btn-secondary btn-sm" onclick="navigate('tokens')">${t('coretokens.manage_btn')}</button>
      </div>
      ${rows.length ? rows.join('') : `<p style="color:var(--text3);font-size:13px;">${t('coretokens.empty')}</p>`}`;
  } catch(e) {
    content.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`;
  }
};

// ── PAGE: Auth / SSO ───────────────────────────────────────────────────────
pages['core-auth'] = async function() {
  const content = document.getElementById('content');
  content.innerHTML = '<p style="color:var(--text2)">' + t('common.loading') + '</p>';
  try {
    const core = state.selectedCore;
    const coreLabel = core?.display_name || core?.node_name || core?.id || '—';
    const providers = await api('GET', '/auth-providers').catch(() => []) || [];

    const forwardAuth = providers.filter(p => ['authentik','authelia','forward','basic'].includes(p.type));
    const oidc = providers.filter(p => p.type === 'oidc');
    const native = providers.filter(p => ['jwt','mtls','ldap','saml','github_oauth'].includes(p.type));

    function providerCard(p) {
      const active = p.enabled !== false;
      return `<div class="card blueprint" style="display:flex;flex-direction:column;gap:10px;padding:16px 18px;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:10px;">
          <div class="card-title" style="font-size:15px;">${esc(p.name||p.type)}</div>
          <span class="tag ${active?'tag-green':'tag-neutral'}">${active ? t('trafic.active') : t('trafic.inactive')}</span>
        </div>
        <code style="font-size:11px;opacity:0.6;">${esc(p.type)}</code>
        <div class="card-meta">${esc(p.forward_auth_url||p.issuer_url||p.server||p.description||'')}</div>
        <div style="display:flex;align-items:center;gap:8px;margin-top:2px;">
          <button class="btn btn-ghost" onclick="navigate('snippets')">${t('corepage.auth.configure')}</button>
        </div>
      </div>`;
    }

    content.innerHTML = `
      <div style="margin-bottom:20px">
        <h1 style="margin:0 0 4px;font-size:28px;font-family:var(--font-heading);font-weight:600;">${t('page.core-auth')}</h1>
        <p style="margin:0;opacity:0.65;font-size:14px;">${t('corepage.auth.subtitle', { core: esc(coreLabel) })}</p>
      </div>

      <div style="display:flex;flex-direction:column;gap:8px;margin-bottom:20px;">
        <h6 style="margin:0;">${t('corepage.auth.forward_title')}</h6>
        <p style="margin:0 0 4px;opacity:0.6;font-size:12.5px;">${t('corepage.auth.forward_desc')}</p>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(min(220px,100%),1fr));gap:14px;">
          ${forwardAuth.length ? forwardAuth.map(providerCard).join('') : `
          <div class="card blueprint" style="padding:28px;display:flex;flex-direction:column;align-items:center;gap:10px;text-align:center;grid-column:1/-1;">
            <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
            <span class="tag tag-neutral">${t('corepage.auth.no_forward')}</span>
            <p style="margin:0;font-size:12.5px;opacity:0.6;max-width:40ch;">${t('corepage.auth.no_forward_hint')}</p>
            <button class="btn btn-secondary blueprint" onclick="navigate('snippets')"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>${t('corepage.auth.manage_snippets')}</button>
          </div>`}
        </div>
      </div>

      ${native.length ? `<div style="display:flex;flex-direction:column;gap:8px;margin-bottom:20px;">
        <h6 style="margin:0;">${t('corepage.auth.native_title')}</h6>
        <p style="margin:0 0 4px;opacity:0.6;font-size:12.5px;">${t('corepage.auth.native_desc')}</p>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(min(220px,100%),1fr));gap:14px;">
          ${native.map(providerCard).join('')}
        </div>
      </div>` : ''}

      ${oidc.length ? `<div style="display:flex;flex-direction:column;gap:8px;margin-bottom:20px;">
        <h6 style="margin:0;">${t('corepage.auth.oidc_title')}</h6>
        <p style="margin:0 0 4px;opacity:0.6;font-size:12.5px;">${t('corepage.auth.oidc_desc')}</p>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(min(220px,100%),1fr));gap:14px;">
          ${oidc.map(providerCard).join('')}
        </div>
      </div>` : ''}

      <div class="card blueprint" style="padding:20px;display:flex;flex-direction:column;gap:14px;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <h6 style="margin:0;">${t('corepage.auth.local_policy')}</h6>
        <div style="display:flex;align-items:center;gap:10px;">
          <span style="font-size:13px;opacity:0.75;">${t('corepage.auth.mfa_label')}</span>
          <span class="tag tag-neutral" id="mfa-tag" style="cursor:pointer;" onclick="toggle2FA()">${t('corepage.auth.mfa_not_required')}</span>
        </div>
        <div class="field" style="max-width:220px;">
          <label for="session-duration">${t('corepage.auth.session_duration')}</label>
          <select class="input" id="session-duration">
            <option value="1h">${t('corepage.auth.session_1h')}</option>
            <option value="8h" selected>${t('corepage.auth.session_8h')}</option>
            <option value="24h">${t('corepage.auth.session_24h')}</option>
            <option value="7d">${t('corepage.auth.session_7d')}</option>
          </select>
        </div>
      </div>`;

    window.toggle2FA = function() {
      const el = document.getElementById('mfa-tag');
      if (!el) return;
      const active = el.classList.contains('tag-accent');
      el.className = active ? 'tag tag-neutral' : 'tag tag-accent';
      el.textContent = active ? t('corepage.auth.mfa_not_required') : t('corepage.auth.mfa_required');
    };
  } catch(e) { content.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`; }
};

// ── PAGE: Métriques ────────────────────────────────────────────────────────
pages['core-metrics'] = async function() {
  const content = document.getElementById('content');
  content.innerHTML = '<p style="color:var(--text2)">' + t('common.loading') + '</p>';
  try {
    const core = state.selectedCore;
    const coreLabel = core?.display_name || core?.node_name || core?.id || '—';

    if (!core?.id) {
      content.innerHTML = `<p style="color:var(--text2)">${t('common.no_core_selected')}</p>`;
      return;
    }

    const m = await api('GET', `/nodes/${core.id}/metrics-summary`).catch(() => null);

    const fmtNum = (v, suffix='') => v != null && v !== undefined ? `${typeof v === 'number' ? (v < 10 ? v.toFixed(1) : v.toFixed(0)) : v}${suffix}` : '—';
    const fmtMs = v => v != null ? `${v.toFixed(1)} ms` : '—';
    const errRatePct = (m && m.requests_total > 0) ? ((m.errors_total / m.requests_total) * 100) : null;
    const errRateStr = errRatePct != null ? fmtNum(errRatePct, '%') : '—';

    const backendRows = (m?.backends || []).map(b => {
      const errPct = b.requests > 0 ? ((b.errors / b.requests) * 100).toFixed(1) + '%' : '—';
      const errClass = b.error_rate > 0.1 ? 'color:var(--red)' : b.error_rate > 0.01 ? 'color:var(--orange,#f59e0b)' : '';
      return `<tr>
        <td style="font-family:var(--font-mono,monospace);font-size:12px;">${esc(b.backend)}</td>
        <td>${b.requests}</td>
        <td style="${errClass}">${errPct}</td>
        <td>${fmtMs(b.p95_ms)}</td>
      </tr>`;
    }).join('');

    const DAY_WARN = 7 * 24 * 3600;
    const certRows = (m?.certs || []).map(c => {
      const days = Math.floor(c.exp_secs / 86400);
      const warn = c.exp_secs < DAY_WARN;
      const color = c.exp_secs <= 0 ? 'var(--red)' : warn ? 'var(--orange,#f59e0b)' : 'var(--green,#22c55e)';
      const label = c.exp_secs <= 0 ? 'EXPIRED' : warn ? `${days}d` : `${days}d`;
      return `<tr>
        <td style="font-family:var(--font-mono,monospace);font-size:12px;">${esc(c.domain)}</td>
        <td style="color:${color};font-weight:600;">${label}</td>
      </tr>`;
    }).join('');

    const pipeline = m?.pipeline || [];
    const maxPipelineCount = pipeline.reduce((acc, p) => Math.max(acc, p.count), 1);
    const pipelineRows = pipeline.map(p => {
      const pct = Math.round((p.count / maxPipelineCount) * 100);
      return `<tr>
        <td style="font-family:var(--font-mono,monospace);font-size:12px;">${esc(p.stage)}</td>
        <td style="width:40%;">
          <div style="background:var(--accent);opacity:0.8;height:14px;width:${pct}%;min-width:2px;border-radius:2px;"></div>
        </td>
        <td style="font-size:12px;opacity:0.8;text-align:right;">${p.count}</td>
      </tr>`;
    }).join('');

    content.innerHTML = `
      <div style="margin-bottom:20px">
        <h1 style="margin:0 0 4px;font-size:28px;font-family:var(--font-heading);font-weight:600;">${t('page.core-metrics')}</h1>
        <p style="margin:0;opacity:0.65;font-size:14px;">${t('corepage.metrics.subtitle', { core: esc(coreLabel) })}</p>
      </div>
      <div class="gp-stat-grid" style="margin-bottom:20px;">
        <div class="card blueprint">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <div class="card-kicker">${t('corepage.metrics.latency_p95')}</div>
          <div class="card-title">${fmtMs(m?.p95_ms)}</div>
          <div class="card-meta">p50: ${fmtMs(m?.p50_ms)} · p99: ${fmtMs(m?.p99_ms)}</div>
        </div>
        <div class="card blueprint">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <div class="card-kicker">TTFB p95</div>
          <div class="card-title">${fmtMs(m?.backend_ttfb_p95_ms)}</div>
          <div class="card-meta">${t('corepage.metrics.latency_meta')}</div>
        </div>
        <div class="card blueprint">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <div class="card-kicker">${t('corepage.metrics.error_rate')}</div>
          <div class="card-title">${errRateStr}</div>
          <div class="card-meta">${t('corepage.metrics.error_meta')} · ${fmtNum(m?.requests_total)} req</div>
        </div>
        <div class="card blueprint">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <div class="card-kicker">Active requests</div>
          <div class="card-title">${fmtNum(m?.active_requests)}</div>
          <div class="card-meta">${fmtNum(m?.routes_total)} routes</div>
        </div>
      </div>
      ${backendRows ? `
      <div class="card blueprint" style="padding:20px;margin-bottom:16px;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <h6 style="margin:0 0 12px;">Backends upstream</h6>
        <table style="width:100%;border-collapse:collapse;font-size:13px;">
          <thead><tr style="opacity:0.55;text-align:left;">
            <th style="padding:4px 8px 8px 0;">Backend</th>
            <th style="padding:4px 8px 8px 0;">Requests</th>
            <th style="padding:4px 8px 8px 0;">Error rate</th>
            <th style="padding:4px 8px 8px 0;">p95 latency</th>
          </tr></thead>
          <tbody>${backendRows}</tbody>
        </table>
      </div>` : ''}
      ${certRows ? `
      <div class="card blueprint" style="padding:20px;margin-bottom:16px;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <h6 style="margin:0 0 12px;">TLS certificates</h6>
        <table style="width:100%;border-collapse:collapse;font-size:13px;">
          <thead><tr style="opacity:0.55;text-align:left;">
            <th style="padding:4px 8px 8px 0;">Domain</th>
            <th style="padding:4px 8px 8px 0;">Expiry</th>
          </tr></thead>
          <tbody>${certRows}</tbody>
        </table>
      </div>` : ''}
      ${pipelineRows ? `
      <div class="card blueprint" style="padding:20px;margin-bottom:16px;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <h6 style="margin:0 0 12px;">Security pipeline blocks</h6>
        <table style="width:100%;border-collapse:collapse;font-size:13px;">
          <tbody>${pipelineRows}</tbody>
        </table>
      </div>` : ''}
      ${!m ? `<div class="card blueprint" style="padding:20px;"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <p style="margin:0;font-size:13px;opacity:0.7;">${t('corepage.metrics.prometheus_desc')}</p>
      </div>` : ''}`;
  } catch(e) { content.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`; }
};

// ── PAGE: Nœuds / Raft (Cluster) ───────────────────────────────────────────
pages['core-cluster'] = async function() {
  const content = document.getElementById('content');
  content.innerHTML = '<p style="color:var(--text2)">' + t('common.loading') + '</p>';
  try {
    const core = state.selectedCore;
    const coreLabel = core?.display_name || core?.node_name || core?.id || '—';
    const nodes = await api('GET', '/nodes').catch(() => []) || [];
    const coreNodes = nodes.filter(n => n.role === 'core');
    const defaultGroup = t('corepage.cluster.default_group');
    const groupName = core?.group_name || defaultGroup;
    const groupNodes = coreNodes.filter(n => (n.group_name || defaultGroup) === groupName);

    content.innerHTML = `
      <div style="margin-bottom:20px">
        <h1 style="margin:0 0 4px;font-size:28px;font-family:var(--font-heading);font-weight:600;">${t('page.core-cluster')}</h1>
        <p style="margin:0;opacity:0.65;font-size:14px;">${t('corepage.cluster.subtitle', { core: esc(coreLabel) })}</p>
      </div>

      <div class="gp-core-grid" style="margin-bottom:20px;">
        <div class="card blueprint">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <div class="card-kicker">${t('corepage.cluster.nodes_in_group')}</div>
          <div class="card-title">${groupNodes.filter(n=>n.status==='online').length} / ${groupNodes.length}</div>
          <div class="card-meta">${t('corepage.cluster.group', { name: esc(groupName) })}</div>
        </div>
        <div class="card blueprint">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <div class="card-kicker">${t('corepage.cluster.raft_state')}</div>
          <div class="card-title">${groupNodes.length > 1 ? t('corepage.cluster.mode_cluster') : t('corepage.cluster.mode_standalone')}</div>
          <div class="card-meta">${groupNodes.length > 1 ? t('corepage.cluster.consensus_active') : t('corepage.cluster.single_node')}</div>
        </div>
        <div class="card blueprint">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <div class="card-kicker">${t('corepage.cluster.all_groups')}</div>
          <div class="card-title">${[...new Set(coreNodes.map(n=>n.group_name||defaultGroup))].length}</div>
          <div class="card-meta">${t('corepage.cluster.cores_total', { n: coreNodes.length })}</div>
        </div>
      </div>

      <h6 style="margin:0 0 12px;">${t('corepage.cluster.group_members', { name: esc(groupName) })}</h6>
      <div class="card blueprint" style="overflow:hidden;margin-bottom:20px;padding:0;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div class="table-wrap">
        <table class="table">
          <thead><tr><th>${t('corepage.col.node')}</th><th>${t('corepage.col.address')}</th><th>${t('corepage.col.raft_role')}</th><th>${t('corepage.metrics.cpu')}</th><th>${t('corepage.col.memory')}</th><th>${t('corepage.col.status')}</th></tr></thead>
          <tbody>
            ${groupNodes.length ? groupNodes.map(n => `<tr>
              <td><strong>${esc(n.display_name||n.node_name||n.id)}</strong>${n.id===core?.id?' <span class="tag tag-accent-2" style="font-size:10px;">' + t('corepage.cluster.this_node') + '</span>':''}</td>
              <td style="font-family:monospace;font-size:12px;">${esc(n.node_endpoint||n.api_host||'—')}</td>
              <td><span class="tag tag-neutral">${n.raft_role||'Follower'}</span></td>
              <td>${n.cpu_pct!=null?n.cpu_pct.toFixed(1)+'%':'—'}</td>
              <td>${n.mem_pct!=null?n.mem_pct.toFixed(1)+'%':'—'}</td>
              <td>${n.status==='online'?'<span class="tag tag-green">' + t('corepage.cluster.online') + '</span>':'<span class="tag tag-red">' + t('corepage.cluster.offline') + '</span>'}</td>
            </tr>`).join('') : '<tr><td colspan="6" class="empty"><p>' + t('corepage.cluster.no_nodes') + '</p></td></tr>'}
          </tbody>
        </table>
        </div>
      </div>

      <div class="card blueprint" style="padding:18px;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <h6 style="margin:0 0 8px;">${t('corepage.cluster.raft_arch_title')}</h6>
        <p style="margin:0;font-size:13px;opacity:0.7;">
          ${t('corepage.cluster.raft_arch_desc')}
        </p>
      </div>`;
  } catch(e) { content.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`; }
};

// ── PAGE: Paramètres Core ─────────────────────────────────────────────────
pages['core-settings'] = function() {
  const content = document.getElementById('content');
  const core = state.selectedCore;
  const coreLabel = core?.display_name || core?.node_name || '—';
  const sections = [
    {
      label: t('coresettings.section.security'),
      desc: t('coresettings.section.security_desc'),
      items: [
        { page: 'core-waf',      icon: '<path d="M8 2l5 3v4c0 3-2.5 5.5-5 6.5C5.5 14.5 3 12 3 9V5l5-3z"/><path d="M6 8h4M8 6v4"/>', label: t('coresettings.item.waf'), desc: t('coresettings.item.waf_desc') },
        { page: 'core-ipfilter', icon: '<circle cx="8" cy="8" r="6"/><path d="M5 8h6M8 5v6"/>', label: t('coresettings.item.ipfilter'), desc: t('coresettings.item.ipfilter_desc') },
        { page: 'core-auth',     icon: '<rect x="4" y="8" width="8" height="6" rx="1"/><path d="M6 8V6a2 2 0 014 0v2"/>', label: t('coresettings.item.auth'), desc: t('coresettings.item.auth_desc') },
        { page: 'core-tokens',   icon: '<path d="M7 11a4 4 0 100-8 4 4 0 000 8zM11 11l4 4"/>', label: t('coresettings.item.tokens'), desc: t('coresettings.item.tokens_desc') },
      ]
    },
    {
      label: t('coresettings.section.tls'),
      desc: t('coresettings.section.tls_desc'),
      items: [
        { page: 'core-certs', icon: '<path d="M12 2H4a1 1 0 00-1 1v10a1 1 0 001 1h8a1 1 0 001-1V3a1 1 0 00-1-1zM9 7H7m2 3H7"/>', label: t('coresettings.item.certs'), desc: t('coresettings.item.certs_desc') },
      ]
    },
    {
      label: t('coresettings.section.routing'),
      desc: t('coresettings.section.routing_desc'),
      items: [
        { page: 'snippets',  icon: '<path d="M4 6l4-4 4 4M4 10l4 4 4-4"/>', label: t('coresettings.item.snippets'), desc: t('coresettings.item.snippets_desc') },
      ]
    },
    {
      label: t('coresettings.section.infra'),
      desc: t('coresettings.section.infra_desc'),
      items: [
        { page: 'core-cluster', icon: '<circle cx="8" cy="8" r="2"/><circle cx="2" cy="4" r="1.5"/><circle cx="14" cy="4" r="1.5"/><circle cx="8" cy="14" r="1.5"/><path d="M3.2 4.8L6.5 7M9.5 7l3.3-2.2M8 9.5V12"/>', label: t('coresettings.item.cluster'), desc: t('coresettings.item.cluster_desc') },
        { page: 'core-portal-catalog', icon: '<rect x="3" y="5" width="10" height="8" rx="1"/><path d="M6 8h6"/>', label: t('coresettings.item.pcatalog'), desc: t('coresettings.item.pcatalog_desc') },
        { page: 'core-portal-users', icon: '<circle cx="8" cy="5" r="2.5"/><path d="M3 13c0-2.2 2.2-4 5-4s5 1.8 5 4"/>', label: t('coresettings.item.pusers'), desc: t('coresettings.item.pusers_desc') },
        { page: 'core-general', icon: '<circle cx="8" cy="8" r="3"/><path d="M8 1v2M8 13v2M1 8h2M13 8h2M3.2 3.2l1.4 1.4M11.4 11.4l1.4 1.4M3.2 12.8l1.4-1.4M11.4 4.6l1.4-1.4"/>', label: t('coresettings.item.general'), desc: t('coresettings.item.general_desc') },
        { page: 'core-http-timeouts', icon: '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>', label: t('coresettings.item.http_timeouts'), desc: t('coresettings.item.http_timeouts_desc') },
      ]
    },
  ];

  const headerHtml = `
    <div style="margin-bottom:20px">
      <h1 style="margin:0 0 4px;font-size:24px;font-family:var(--font-heading);font-weight:600;">${t('coresettings.title', { core: esc(coreLabel) })}</h1>
      <p style="margin:0;font-size:13px;color:var(--text2);">${t('coresettings.subtitle')}</p>
      <div style="margin-top:10px;display:inline-flex;align-items:center;gap:8px;padding:6px 12px;background:var(--bg2);border:1px solid var(--border);border-radius:8px;font-size:12px;">
        <span style="color:var(--text2)">${t('coresettings.version_banner')}</span>
        <strong style="font-family:monospace;">v${esc(core?.version || '—')}</strong>
      </div>
    </div>`;

  renderSettingsHub({ contentEl: content, sections, headerHtml });
};

pages['core-general'] = async function() {
  const content = document.getElementById('content');
  content.innerHTML = '<p style="color:var(--text2)">' + t('common.loading') + '</p>';
  try {
    const core = state.selectedCore;
    if (!core) { content.innerHTML = '<p style="color:var(--text2)">' + t('corepage.general.no_core') + '</p>'; return; }
    const coreLabel = core.display_name || core.node_name || core.id || '—';

    const statusOnline  = core.status === 'online';
    const statusPending = core.status === 'pending';
    const statusColor   = statusOnline ? 'var(--green)' : statusPending ? 'var(--yellow,#f59e0b)' : 'var(--red)';
    const statusLabel   = statusOnline ? t('corepage.general.status_connected') : statusPending ? t('corepage.general.status_pending') : t('corepage.general.status_offline');
    const lastSeen      = core.last_seen_at ? fmtDate(core.last_seen_at) : '—';
    const tagsVal       = Array.isArray(core.tags) ? core.tags.join(', ') : (core.tags || '');

    const infraCell = (port, label, envVar) => `
      <div style="background:var(--bg2,rgba(128,128,128,0.07));border-radius:6px;padding:10px 14px;">
        <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.07em;opacity:0.45;margin-bottom:5px;">${label}</div>
        <div style="font-family:monospace;font-size:15px;font-weight:700;">:${port}</div>
        <div style="font-size:10px;opacity:0.35;margin-top:3px;font-family:monospace;">${envVar}</div>
      </div>`;

    content.innerHTML = `
      <div style="margin-bottom:20px">
        <button onclick="navigate('core-settings')" style="background:none;border:none;color:var(--text2);cursor:pointer;font-size:12px;padding:0;margin-bottom:8px;">${t('corepage.general.back', { core: esc(coreLabel) })}</button>
        <h1 style="margin:0 0 4px;font-size:24px;font-family:var(--font-heading);font-weight:600;">${t('page.core-general')}</h1>
        <p style="margin:0;font-size:13px;color:var(--text2);">${t('corepage.general.subtitle')}</p>
      </div>
      <div style="display:flex;flex-direction:column;gap:16px;max-width:720px;">

        <!-- Plan de contrôle WebSocket -->
        <div class="card blueprint" style="padding:20px;display:flex;flex-direction:column;gap:14px;">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;">
            <div>
              <h6 style="margin:0 0 3px;font-size:11px;text-transform:uppercase;letter-spacing:0.09em;opacity:0.5;">${t('corepage.general.ws_control')}</h6>
              <div style="font-size:12px;color:var(--text2);">${t('corepage.general.ws_tunnel')}</div>
            </div>
            <div style="display:flex;align-items:center;gap:7px;">
              <span style="width:8px;height:8px;border-radius:50%;background:${statusColor};display:inline-block;flex-shrink:0;${statusOnline?'box-shadow:0 0 0 3px rgba(74,222,128,0.22);':''}"></span>
              <span style="font-size:13px;font-weight:600;color:${statusColor}">${esc(statusLabel)}</span>
            </div>
          </div>
          <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(min(155px,100%),1fr));gap:10px;padding-top:10px;border-top:1px solid var(--border);">
            <div>
              <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.07em;opacity:0.4;margin-bottom:3px;">${t('corepage.general.endpoint')}</div>
              <div style="font-family:monospace;font-size:11px;word-break:break-all;opacity:0.85;">${esc(core.endpoint||'—')}</div>
            </div>
            <div>
              <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.07em;opacity:0.4;margin-bottom:3px;">${t('corepage.general.version')}</div>
              <div style="font-family:monospace;font-size:12px;">${esc(core.version||'—')}</div>
            </div>
            <div>
              <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.07em;opacity:0.4;margin-bottom:3px;">${t('corepage.general.last_seen')}</div>
              <div style="font-size:12px;">${esc(lastSeen)}</div>
            </div>
            <div>
              <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.07em;opacity:0.4;margin-bottom:3px;">${t('corepage.general.cpu_mem')}</div>
              <div style="font-size:12px;font-family:monospace;">${core.cpu_pct != null ? Math.round(core.cpu_pct)+'%' : '—'} / ${core.mem_pct != null ? Math.round(core.mem_pct)+'%' : '—'}</div>
            </div>
          </div>
        </div>

        <!-- Identité — champs modifiables -->
        <div class="card blueprint" style="padding:20px;display:flex;flex-direction:column;gap:16px;">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <h6 style="margin:0;font-size:11px;text-transform:uppercase;letter-spacing:0.09em;opacity:0.5;">${t('corepage.general.identity')}</h6>
          <div class="gp-split-2" style="gap:10px;">
            <div class="field">
              <label>Node name <span style="font-size:10px;opacity:0.4;font-style:italic;">${t('corepage.general.node_name_ro')}</span></label>
              <input class="input" value="${esc(core.node_name||'')}" readonly tabindex="-1" style="opacity:0.5;cursor:default;">
            </div>
            <div class="field">
              <label for="cs-display">${t('corepage.general.display_name')}</label>
              <input class="input" id="cs-display" value="${esc(core.display_name||'')}" placeholder="${esc(core.node_name||'core-1')}">
            </div>
          </div>
          <div class="gp-split-2" style="gap:10px;">
            <div class="field">
              <label for="cs-region">${t('corepage.general.region')}</label>
              <input class="input" id="cs-region" value="${esc(core.region||'')}" placeholder="eu-west-1">
            </div>
            <div class="field">
              <label for="cs-env">${t('corepage.general.environment')}</label>
              <input class="input" id="cs-env" value="${esc(core.environment||'')}" placeholder="production">
            </div>
          </div>
          <div class="field">
            <label for="cs-tags">Tags <span style="font-size:11px;opacity:0.4;">${t('corepage.general.tags_hint')}</span></label>
            <input class="input" id="cs-tags" value="${esc(tagsVal)}" placeholder="ha, ssl-offload, edge">
          </div>
        </div>

        <!-- Infrastructure — lecture seule -->
        <div class="card blueprint" style="padding:20px;display:flex;flex-direction:column;gap:14px;">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:6px;">
            <h6 style="margin:0;font-size:11px;text-transform:uppercase;letter-spacing:0.09em;opacity:0.5;">${t('corepage.general.infra')}</h6>
            <span style="font-size:10px;opacity:0.35;font-style:italic;">${t('corepage.general.infra_env_only')}</span>
          </div>
          <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(min(160px,100%),1fr));gap:8px;">
            ${infraCell(80,  'HTTP',       'GPX_NETWORK_HTTP_PORT')}
            ${infraCell(443, 'HTTPS',      'GPX_NETWORK_HTTPS_PORT')}
            ${infraCell(8000,'Hub WS / API','GPX_NETWORK_INTERNAL_API_PORT')}
            <div style="background:var(--bg2,rgba(128,128,128,0.07));border-radius:6px;padding:10px 14px;">
              <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.07em;opacity:0.45;margin-bottom:5px;">${t('corepage.general.log_level')}</div>
              <div style="font-family:monospace;font-size:12px;font-weight:600;">GPX_ENGINE_LOG_LEVEL</div>
              <div style="font-size:10px;opacity:0.35;margin-top:3px;">${t('corepage.general.log_default')}</div>
            </div>
          </div>
        </div>

        <button class="btn btn-primary blueprint" style="align-self:flex-start;" onclick="saveCoreGeneral('${esc(core.id||'')}')">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          ${t('common.save')}
        </button>
      </div>`;

    window.saveCoreGeneral = async function(id) {
      if (!id) { toast(t('corepage.general.toast_no_core'),'error'); return; }
      const tagsRaw = document.getElementById('cs-tags')?.value || '';
      const payload = {
        display_name: document.getElementById('cs-display')?.value?.trim() || '',
        region:       document.getElementById('cs-region')?.value?.trim() || '',
        environment:  document.getElementById('cs-env')?.value?.trim() || '',
        tags:         tagsRaw.split(',').map(t => t.trim()).filter(Boolean),
      };
      try {
        await api('PATCH', `/nodes/${id}`, payload);
        toast(t('corepage.general.toast_saved'), 'success');
        if (state.selectedCore) {
          Object.assign(state.selectedCore, payload);
        }
      } catch(e) { toast(t('common.error_msg', { msg: e.message }), 'error'); }
    };
  } catch(e) { content.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`; }
};

pages['core-http-timeouts'] = async function() {
  const content = document.getElementById('content');
  content.innerHTML = '<p style="color:var(--text2)">' + t('common.loading') + '</p>';
  try {
    const core = state.selectedCore;
    if (!core) { content.innerHTML = '<p style="color:var(--text2)">' + t('corepage.general.no_core') + '</p>'; return; }
    const coreLabel = core.display_name || core.node_name || core.id || '—';
    const tokens = await api('GET', '/tokens?role=core').catch(() => []);
    const match = (tokens || []).filter(tok => !tok.revoked && (
      tok.id === core.id || tok.node_name === core.node_name || tok.node_name === core.id
    ));
    const best = match.find(tok => tok.id === core.id) || match.find(tok => tok.node_endpoint) || match[0] || null;
    const coreRef = best?.id || core.node_name || core.id || '';
    const coreQ = coreRef ? `?core=${encodeURIComponent(coreRef)}` : '';
    window._secCoreQ = coreQ;

    const cfg = await api('GET', `/security/server-config${coreQ}`).catch(() => null) || {};

    content.innerHTML = `
      <div style="margin-bottom:20px">
        <button onclick="navigate('core-settings')" style="background:none;border:none;color:var(--text2);cursor:pointer;font-size:12px;padding:0;margin-bottom:8px;">${t('corepage.general.back', { core: esc(coreLabel) })}</button>
        <h1 style="margin:0 0 4px;font-size:24px;font-family:var(--font-heading);font-weight:600;">${t('coresettings.item.http_timeouts')}</h1>
        <p style="margin:0;font-size:13px;color:var(--text2)">${t('coresettings.item.http_timeouts_desc')}</p>
      </div>
      ${serverTimeoutsBanner(cfg)}`;
  } catch(e) { content.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`; }
};

// ── B2 : Tunnel L4 mTLS Core↔Core ────────────────────────────────────────────
pages['core-tunnel'] = async function(content) {
  content = content || document.getElementById('content');
  const spin = `<div class="spinner"></div>`;
  content.innerHTML = `<h1 style="margin:0 0 20px;font-size:24px;font-family:var(--font-heading);font-weight:600">Tunnel L4 mTLS</h1>${spin}`;

  const coreId = (state.selectedCore || window._selectedCore)?.id;
  if (!coreId) {
    content.innerHTML = `<h1 style="margin:0 0 20px;font-size:24px;font-family:var(--font-heading);font-weight:600">Tunnel L4 mTLS</h1><p style="color:var(--text2)">Aucun Core sélectionné.</p>`;
    return;
  }

  let cfg = {};
  try {
    cfg = await api('GET', `/nodes/${encodeURIComponent(coreId)}/tunnel-config`);
  } catch(e) {
    cfg = {};
  }

  const peers = Array.isArray(cfg.peers) ? cfg.peers : [];

  function render(peers, saving) {
    const rows = peers.map((p, i) => `<tr>
      <td style="padding:6px 8px"><input data-field="name" data-idx="${i}" value="${esc(p.name||'')}" style="width:100%;box-sizing:border-box" placeholder="nom-peer"></td>
      <td style="padding:6px 8px"><input data-field="addr" data-idx="${i}" value="${esc(p.addr||'')}" style="width:100%;box-sizing:border-box" placeholder="host:port"></td>
      <td style="padding:6px 8px"><button data-rm="${i}" style="background:none;border:none;color:var(--red);cursor:pointer;font-size:18px">×</button></td>
    </tr>`).join('');

    content.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px">
      <h1 style="margin:0;font-size:24px;font-family:var(--font-heading);font-weight:600">Tunnel L4 mTLS</h1>
    </div>
    <p style="font-size:13px;color:var(--text2);margin-bottom:20px">Configurez les peers mTLS que ce Core peut joindre via tunnel L4 chiffré (TLS 1.3).</p>
    <div style="border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:16px">
      <table style="width:100%;border-collapse:collapse;font-size:13px" id="tunnel-peers-table">
        <thead><tr style="color:var(--text2)"><th style="padding:6px 8px;text-align:left">Nom</th><th style="padding:6px 8px;text-align:left">Adresse</th><th style="width:40px"></th></tr></thead>
        <tbody>${rows || '<tr><td colspan="3" style="padding:12px 8px;color:var(--text3);text-align:center">Aucun peer configuré</td></tr>'}</tbody>
      </table>
      <button id="tunnel-add-peer" style="margin-top:12px;background:none;border:1px dashed var(--border);border-radius:6px;padding:6px 12px;cursor:pointer;font-size:13px;color:var(--text2);width:100%">+ Ajouter un peer</button>
    </div>
    <div style="display:flex;gap:8px">
      <button id="tunnel-save" style="background:var(--accent);color:#fff;border:none;border-radius:6px;padding:8px 16px;cursor:pointer;font-size:13px"${saving?' disabled':''}>Enregistrer</button>
    </div>
    ${saving ? `<p style="font-size:12px;color:var(--text3);margin-top:8px">Sauvegarde en cours…</p>` : ''}`;

    document.getElementById('tunnel-add-peer')?.addEventListener('click', () => {
      peers.push({ name: '', addr: '' });
      render(peers, false);
    });

    document.querySelectorAll('[data-rm]').forEach(btn => {
      btn.addEventListener('click', () => {
        peers.splice(parseInt(btn.dataset.rm), 1);
        render(peers, false);
      });
    });

    document.querySelectorAll('[data-field]').forEach(inp => {
      inp.addEventListener('input', () => {
        peers[parseInt(inp.dataset.idx)][inp.dataset.field] = inp.value;
      });
    });

    document.getElementById('tunnel-save')?.addEventListener('click', async () => {
      render(peers, true);
      try {
        await api('PUT', `/nodes/${encodeURIComponent(coreId)}/tunnel-config`, { peers });
        render(peers, false);
      } catch(e) {
        render(peers, false);
        alert('Erreur : ' + e.message);
      }
    });
  }

  render(peers, false);
};

