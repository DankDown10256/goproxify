# Changelog Goproxify

Toutes les modifications notables sont documentées ici.
Format : [Semantic Versioning](https://semver.org/) — `MAJOR.MINOR.PATCH`

---

## [Unreleased]

### Ajouté

- **Menu "Automatisation" restructuré en 3 sous-menus + store de règles préconfigurées** : le menu Automatisation regroupe désormais "Règles automatiques" (`security-rules`, inchangé), "Canaux d'alerte" (`alert-channels`, déplacé depuis le menu Sécurité) et un nouveau "Store de règles" (`rules-store`) — un catalogue de 5 règles condition→action préconfigurées (CVE critique, pic de bans, IP récidiviste, moteur IPS silencieux, taux d'erreur anormal) installables en un clic depuis l'UI (`internal/admin/rulesengine/templates.go`, `GET/POST /api/v1/rules-engine/templates`). Une page de vue d'ensemble (`pages.automation`) résume l'état des trois. (Admin `0.12.0`, Webapp `0.10.0`)
- **Page admin "Accès MCP"** (menu Accès → `mcp-access`) : vue d'ensemble en lecture seule du périmètre d'accès exposé par le serveur MCP — catalogue de scopes PAT avec les outils MCP couverts par chacun (`rbac.ToolsForScope`, dérivé de `ToolRequiredScope`), et liste des PAT actifs sur l'instance tous porteurs confondus (`GET /api/v1/mcp-access/scopes`, `GET /api/v1/mcp-access/tokens`, admin uniquement). La création/édition des scopes d'un PAT reste self-service sur "Mes tokens API" — un PAT est personnel à son porteur ; cette page ne fait qu'exposer la vue globale à l'admin. (Admin `0.12.0`, Webapp `0.10.0`)

### Corrigé

- **Modale "Historique" du proxy — "Aucun historique pour ce proxy." alors qu'il y en a un** : la modale unifiée (`openProxyVersionsModal`, `trafic.js`, fusionnée récemment avec l'ancien "Diff config") ne lisait que `GET /backups/proxy-history/{id}`, une table SQLite côté Admin (`proxy_history`) qui n'enregistre une version qu'à chaque création/modification faite *via l'API Admin*. Un proxy jamais retouché depuis l'Admin (créé/synchronisé côté Core, ou modifié avant l'introduction de cette table) y a zéro ligne — alors que l'historique réel existe bien côté Core (`proxystore`, un fichier de révision à chaque création/dry-run/promote), déjà exposé par `GET /proxies/{id}/revisions/diff` (champ `revisions`, utilisé jusqu'ici seulement pour calculer un diff, jamais pour lister). La modale retombe désormais sur ces révisions Core quand `proxy_history` est vide, avec la config déjà incluse dans chaque révision (pas d'appel réseau supplémentaire). Le bouton "Restaurer" est masqué sur ces lignes (aucun endpoint Admin ne permet de restaurer une révision Core arbitraire) et une note indique la provenance Core-only. La comparaison de config, elle, fonctionne à l'identique dans les deux cas. (Webapp `0.9.8`)

### Retiré

- **Menu Core "Health checks" (`pages['core-health']`)** : la page dupliquait, par backend, une information déjà disponible dans "Trafic" (statut up/down par backend, via `GET /backends/health`) sans apporter de valeur propre. Entrée de nav, route (`app.config.js`, `router.js`) et implémentation (`core.js`) supprimées. L'endpoint `/api/v1/backends/health` reste utilisé par la page Trafic, inchangé. (Admin `0.11.4`, Webapp `0.9.7`)

### Changé

- **Historique de proxies + Diff config fusionnés en une seule modale** : les deux boutons distincts de la liste des proxies (`trafic.js`) ouvraient chacun leur propre modale, l'une listant les versions (restaurer), l'autre comparant deux révisions issues d'un système distinct (révisions Core via `revisions/diff`), sans lien entre les deux. Un seul bouton "Historique" ouvre désormais `openProxyVersionsModal` : la liste des versions (`proxy_history`) à gauche, un panneau de diff à droite. Cliquer sur une version affiche sa diff face à la configuration actuelle ; cliquer sur une deuxième version affiche la diff entre les deux versions sélectionnées (badges A/B sur les lignes) ; recliquer désélectionne, un 3ᵉ clic repart d'une sélection neuve. L'icône restaurer reste sur chaque ligne. Nouvel endpoint `GET /api/v1/backups/proxy-history/{id}/config` (config brute d'une version, pour calculer la diff côté client) ; le diff n'utilise plus l'historique des révisions Core (`revisions/diff`, toujours actif mais plus appelé depuis l'UI). (Admin `0.11.3`, Webapp `0.9.6`)

### Corrigé

- **Vue Admin "Menaces" — Core d'origine et raison absents, date jamais mise à jour, aucun tri/filtre** : la page (`renderAdminSecurityThreats`, `pages['security-threats']`) était une implémentation dupliquée et jamais raccordée aux vraies données — elle lisait `t.active`, `t.source`, `t.reason`, `t.core_name`/`t.core_id`, `e.ts`, `e.core_name`, `e.reason`/`e.detail`, aucun de ces champs n'existant sur `security.Threat` (`id, ip, scenario, origin, type, duration, created_at`) ni sur l'objet `event` de `/security/timeline` (`type, created_at, ip, domain, summary, severity, source`). Résultat : le bloc "Menaces actives" ne s'affichait jamais (`t.active` toujours `undefined`), la colonne Core toujours "—", la colonne Raison toujours "—", et la date de la timeline toujours "—". Par ailleurs `security_threats` a une contrainte unique `(ip, scenario)` et l'ingestion utilisait `INSERT OR IGNORE` : une même menace réémise plusieurs fois par CrowdSec ne créait jamais de nouvelle ligne et ne rafraîchissait jamais sa date — la date affichée restait celle de la toute première observation. Corrigé : nouvelles colonnes `security_threats.core_name` (résolu côté serveur depuis le token d'appairage de l'appelant, comme pour les CVE), `occurrences` et `last_seen_at` ; `handleInternalThreats` fait maintenant un upsert (`ON CONFLICT (ip, scenario) DO UPDATE`) qui incrémente `occurrences` et rafraîchit `last_seen_at`/`core_name` à chaque réception au lieu d'ignorer les doublons. La page Admin réutilise désormais le tableau Menaces mutualisé avec la vue Core (`threatsPanelHTML`/`threatsTableRows`/`filterSecThreatsList`), déjà doté de recherche, tri et filtre par type — avec une colonne Core en plus côté Admin (masquée côté Core, déjà scopé à un seul Core) et une colonne Occurrences. La timeline générique (bans/menaces/CVE tous types) affiche maintenant la vraie date (`e.created_at`) et le vrai résumé (`e.summary`) au lieu de champs inexistants. Les menaces enregistrées avant cette migration affichent Core "—" et 1 occurrence (valeurs jamais renseignées auparavant). (Admin `0.11.2`, Webapp `0.9.5`)

### Changé

- **Vue Admin "Vulnérabilités (CVE)" — carte "Scanner CVE" retirée, colonne Core ajoutée à la liste** : côté Admin, la carte affichait l'état d'un scan par backend (bouton "Scanner maintenant" déjà masqué, mais KPIs et détail par backend restaient visibles) alors que le scan est une action et un état propres à chaque Core — sans intérêt agrégé côté Admin, qui ne peut de toute façon rien y déclencher ni configurer. La carte "Scanner CVE" ne s'affiche plus que côté Core (`pages['core-security-vulns']`). En contrepartie, la liste des CVE (utile de façon transverse) affiche désormais une colonne "Core" en vue Admin, indiquant le Core d'origine de chaque CVE — résolu côté serveur (`handleInternalCVEs`, via le token d'appairage de l'appelant) et stocké dans une nouvelle colonne `security_cves.core_name`, exposée par `GET /security/cves`. Colonne masquée côté Core (déjà filtré sur ce Core, donc redondante). Les CVE existantes avant cette migration affichent "—" (Core inconnu, jamais renseigné). (Admin `0.11.1`, Webapp `0.9.4`)

### Corrigé

- **Volet "Domaines & certificats" (Deploy Targets / Pull Tokens) — fond transparent, contenu superposé à la page en dessous** : `openCertDeployPanel` (`cert-deploy.js`) fixait le fond du drawer avec `var(--bg1)`, une variable jamais définie dans les thèmes (`--bg`, `--bg2`, `--bg3` sont les seules qui existent). Sans valeur de repli, `background` restait transparent et laissait voir la page sous-jacente (horloge, liste des certificats) à travers tout le panneau, avec les boutons de la page ("+ Nouveau certificat", rafraîchir) qui se superposaient visuellement à ceux du drawer ("+ Nouveau target"). Remplacé par `var(--bg)`, cohérent avec le fond plein écran utilisé ailleurs pour ce type de panneau. (Webapp `0.9.3`)

- **Section "Scanner CVE" (bouton de scan manuel + coche réseau privé) inversée entre Admin et Core** : `renderSecurityVulns` conditionnait ces deux contrôles à `isAdmin` (`mode === 'admin'`), donc affichés côté Admin — qui ne doit montrer que l'agrégat des résultats de tous les Cores — et absents côté Core (`pages['core-security-vulns']`), qui est pourtant le seul endroit pertinent pour déclencher un scan et autoriser l'accès réseau privé de ce Core. Le bouton "Scanner maintenant" et la coche "Autoriser l'accès au réseau privé" ne s'affichent plus qu'en vue Core ; la vue Admin ne conserve que les KPIs, la liste des CVEs et le détail des résultats en lecture seule. (Webapp `0.9.1`)

- **Page Admin "Vulnérabilités" (`pages['security-vulns']`) — colonnes Package/Proxy/Core toujours à "—"** : cette page utilisait une implémentation historique distincte (`renderAdminSecurityVulns`), non touchée par le partage de code Admin/Core fait au-dessus, dont le tableau lisait `c.package`, `c.proxy_name`/`c.proxy_id` et `c.core_name` — des champs qui n'ont jamais existé dans la réponse de `GET /security/cves` (`security.CVE` n'expose que `id`, `backend_url`, `cve_id`, `cvss_score`, `description`, `status`, `detected_at`), d'où un tableau vide en pratique. `pages['security-vulns']` appelle maintenant la même `renderSecurityVulns({ mode: 'admin' })` que la vue Core (résultats agrégés tous Cores, sans le bouton de scan ni la coche réseau privé), qui affiche `backend_url` et `description` — les seules informations réellement renvoyées par l'API. L'ancienne fonction dupliquée est supprimée. (Webapp `0.9.2`)

### Changé

- **Politiques d'accès retiré de la 3ᵉ section de "Gestion d'équipe"** : maintenant qu'elle a sa propre landing (clic sur le groupe "Accès"), plus besoin de la dupliquer dans "Gestion d'équipe" — qui revient à 2 sections (Utilisateurs & équipes, Espaces de travail). (Webapp `0.9.0`)

- **Clic sur le groupe "Accès" → Politiques d'accès (au lieu de Gestion d'équipe)** : la vue matricielle croisée domaines × sujets offre une meilleure vue globale du périmètre d'accès et convient mieux comme landing du groupe nav. `pages.access` redirige désormais vers `access-policies`. (Webapp `0.9.0`)

### Corrigé

- **Health checks (Paramètres Core) — le rafraîchissement 30s écrasait la page courante après navigation** : `pages['core-health']` démarre un `setInterval(refresh, 30000)` qui écrit directement dans le `#content` capturé à l'ouverture de la page, et prévoyait bien un hook `content._cleanup` pour l'arrêter — mais le routeur ne l'appelait jamais. Le timer continuait de tourner indéfiniment après avoir quitté la page, et toutes les 30 s remplaçait le contenu affiché (n'importe quelle autre page) par "Health checks". Le routeur (`navigate()`) invoque désormais `content._cleanup()` sur la page sortante avant de charger la nouvelle — mécanisme générique réutilisable par toute page qui démarre un timer. (Webapp `0.9.0`)

- **`var(--card-bg)` — variable CSS jamais définie, fond transparent sur 15 usages dans 4 fichiers** : ni `--card-bg` ni `--input-bg` n'existent dans `themes/flat.css`/`industry-ds.css` (seuls `--bg`, `--bg2`, `--bg3` sont définis). Une variable CSS custom non définie et sans valeur de repli statique rend la propriété `background` transparente, laissant la page sous-jacente transparaître à travers le panneau/la carte censée avoir un fond opaque. Le plus visible : le volet détail d'un espace de travail (`workspaces.js`, `#ws-detail-panel`) laissait voir le contenu de la page en dessous (dates, boutons "+ Nouvel espace"/"+ Nouvelle équipe") à travers tout le panneau, pas seulement dans la marge assombrie du backdrop. Même bug dans le volet détail certificat ACME (`acme-monitor.js`), 7 cartes d'info dans `security.js`, et les `<select>` des modales Utilisateur/Équipe (`users.js`, repli sur `--input-bg` tout aussi indéfini). Remplacé par `var(--bg2)` — la variable réellement utilisée partout ailleurs (`.card`) pour les surfaces de carte. (Webapp `0.9.0`)

### Ajouté

- **"Politiques d'accès" intégré à Gestion d'équipe** : la matrice domaines × sujets (utilisateurs, équipes, tokens Core), purement en lecture seule (aucune action d'écriture, juste deux raccourcis de navigation), devient une 3ᵉ section de la page, après Utilisateurs & équipes et Espaces de travail. Son entrée sidebar dans Accès est retirée ; la tuile Paramètres (`settings.js`) et `pages['access-policies']` restent accessibles en direct (rendu identique, plein écran). La redirection de l'entrée parente "Accès" (clic sur le groupe lui-même) pointe désormais vers `workspaces` au lieu de `users`, cohérent avec le nouveau contenu. (Webapp `0.9.0`)

### Corrigé

- **`users.js` — erreur de syntaxe cassant tout le fichier (page Utilisateurs & équipes entièrement non fonctionnelle)** : le commit `a7d625a` (20/09, migration des backdrops de modale vers `document.body`) a changé `elt.innerHTML = \`...\`` (une affectation) en `document.body.insertAdjacentHTML('beforeend', \`...\`)` (un appel de fonction) pour les modales Utilisateur et Équipe, mais sans ajouter le `)` de fermeture correspondant à la fin du template literal. Un `SyntaxError` sur un fichier `<script>` classique empêche l'exécution de **tout son contenu** : `pages.users`, `refreshUsers`, `openUserModal`, `saveUser`, `openTeamModal`, `saveTeam`, etc. n'existaient tout simplement jamais. C'est la cause racine de "il n'y a rien dans l'onglet Utilisateurs" et, une fois les onglets retirés, de la page "Gestion d'équipe" entièrement vide (le premier appel `refreshUsers(...)` levait un `ReferenceError` avant même que la section Espaces de travail ne s'affiche). `node --check` sur ce fichier échouait déjà avant tout changement de cette session — non détecté plus tôt car jamais vérifié isolément. (Webapp `0.9.0`)

- **Gestion d'équipe — backdrop imbriqué en double sur le volet détail d'un espace de travail** : `_renderWorkspacePanel` récupérait le conteneur `#ws-detail-backdrop` (l'overlay plein écran lui-même) puis réinjectait dedans un **second** `<div id="ws-detail-backdrop" class="dialog-backdrop">` identique. Deux overlays semi-transparents superposés = fond anormalement sombre, IDs dupliqués dans le DOM. Le clic pour fermer en cliquant à l'extérieur n'était de plus jamais attaché sur le premier rendu (skeleton de chargement). Corrigé : l'overlay est créé une seule fois (avec son handler de fermeture), `_renderWorkspacePanel` ne remplace plus que le contenu du panneau interne (`#ws-detail-panel`). (Webapp `0.9.0`)

### Changé

- **Gestion d'équipe — onglets remplacés par des sections en scroll** : la bascule par onglets ("Utilisateurs & équipes" / "Espaces de travail") laisse place à une page unique : les deux blocs s'affichent l'un après l'autre, sans clic pour changer de vue. Simplifie aussi le rendu (plus d'état d'onglet actif à synchroniser). (Webapp `0.9.0`)

### Ajouté

- **Paramètres Core → Tokens d'appairage (récap lecture seule)** : nouvelle tuile dans la section Sécurité de Paramètres Core, affichant le(s) token(s) `role=core` appairés à ce nœud (statut actif/expiré/révoqué, rôle RBAC, scopes). La CRUD complète (création, édition des scopes, révocation) reste dans **Accès → Tokens d'appairage**, avec un bouton de raccourci — un token sert justement à appairer un Core qui n'existe pas encore, la gestion complète ne peut donc pas être scopée à un Core déjà appairé. (Webapp `0.9.0`)

### Corrigé

- **Menu Accès — libellé "Utilisateurs & équipes" jamais affiché** : `gpxPageLabel(page, fallback)` (i18n.js) donne toujours priorité à la clé `page.<page>` si elle existe, en ignorant totalement le `fallback` passé par `app.config.js`. La clé `page.users` valait encore `'Utilisateurs'` (FR) / `'Users'` (EN) / `'Usuarios'` (ES) / `'Benutzer'` (DE) dans les 4 langues — écrasant silencieusement le libellé `'Utilisateurs & équipes'` défini dans le sous-menu Accès depuis la fusion Users/Teams. Le libellé n'a donc jamais pu s'afficher, dans aucune langue, indépendamment du rôle ou du cache navigateur. Clés `page.users` mises à jour dans les 4 locales. (Webapp `0.9.0`)
- **Catalogue Access — modale d'édition mal empilée** : `portal-catalog.js` construisait son propre backdrop (`z-index:80`) injecté dans un conteneur `#pc-modal` à l'intérieur de `#content`, au lieu du composant partagé `.dialog-backdrop` (z-index 9999, `document.body`). Contrairement aux autres pages (Users, Workspaces, Cert Deploy, Trafic, Core) déjà corrigées en septembre, celle-ci n'avait jamais été migrée — cause probable de superpositions/z-index récurrentes sur cette modale. Migré vers le pattern standard. (Webapp `0.9.0`)
- **`docker-compose.yml` — tags d'images par défaut obsolètes** : `GOPROXIFY_ADMIN_TAG`, `GOPROXIFY_CORE_TAG` et `GOPROXIFY_AGENT_TAG` par défaut pointaient vers des versions périmées (`0.3.3`/`0.3.94`/`0.3.50`) désynchronisées de `versions.json`. Alignés sur `preview`, comme `docker-compose.quickstart.yml`, pour éviter que les défauts se re-périment à chaque release.
- **HA Admin — `/ha/status` renvoyait le mauvais `node_id`** : `ha.Manager.HandleStatus` retournait `LeaderID()` à la place de l'ID propre du nœud interrogé, faisant apparaître tous les nœuds (leader et followers) avec le même Node ID dans la page Statut HA. Ajout de `raft.Node.ID()` et correction du handler pour retourner l'identité réelle du nœud.
- **HA — Core backup ne recevait jamais le `full_sync` Admin** : `GPX_CORE_EXTRA_ENDPOINTS` était documenté mais non implémenté. `ConnectFromEnv` supporte désormais cette variable (format CSV `name=http://host:port`). L'Admin se connecte à chaque Core extra au démarrage et pousse le `full_sync`. (Admin `0.10.1`)

### Corrigé

- **Menu Accès — libellé "Tokens Core & Agent" jamais affiché** : même piège que `page.users`/`page.acme-monitor` — `app.config.js` déclarait `'Tokens Core & Agent'` pour l'entrée `tokens`, mais la clé i18n `page.tokens` (`'Tokens d'appairage'`, cohérente avec le titre de page et les 4 langues) l'écrasait silencieusement via `gpxPageLabel()`. Libellé du menu aligné sur ce qui s'affiche réellement. Audit des 4 entrées d'Accès (`tokens`, `access-policies`, `workspaces`, `acme-monitor`) : plus aucun écart config/i18n. (Webapp `0.9.0`)

### Ajouté

- **"Monitoring ACME" renommé "Domaines & certificats"** : reflète le périmètre élargi depuis la fusion avec Certificats/Déploiement (actions Déployer/Éditer ajoutées précédemment). Clé `page.acme-monitor` mise à jour en FR/EN (piège identique à celui corrigé pour `page.users` : `gpxPageLabel()` priorise toujours la traduction sur le libellé d'`app.config.js`). (Webapp `0.9.0`)
- **"Espaces de travail" renommé "Gestion d'équipe" et fusionné avec "Utilisateurs & équipes"** : l'entrée sidebar "Utilisateurs & équipes" est retirée d'Accès. Sa page (CRUD utilisateurs/équipes, grants, scopes) est intégrée comme onglet dans la page renommée **Accès → Gestion d'équipe**, aux côtés de l'onglet "Espaces de travail" (inchangé : conteneurs regroupant ressources + membres). `pages.users` reste accessible directement (liens internes depuis Politiques d'accès et Infrastructure) et continue de s'afficher en plein écran sans onglets. Aucun changement d'API. (Webapp `0.9.0`)
- **Fusion des pages certificats dans Monitoring ACME** : les menus "Certificats" (tuile Paramètres) et "Déploiement certificats" (sidebar Accès) sont retirés — tout se passe désormais depuis **Accès → Monitoring ACME**. Chaque ligne de certificat gagne deux actions : **Déployer** (ouvre le drawer de déploiement — webhook signé HMAC / SSH exec, tokens de pull HTTP existants, inchangés) et **Éditer** (ouvre la modale du domaine source — provider DNS, PEM manuel, Core d'entrée, délégation ; désactivé si le certificat n'a pas de domaine déclaré, ex. import manuel). Le lien mort "Aller au domaine" (`navigate('domains')`, page inexistante) est supprimé. Nouveau champ `domain_id` dans `GET /api/v1/certs/acme-monitor` pour relier certificat émis et domaine source. La page "Certificats TLS" du contexte Core (`Paramètres Core`) est inchangée, elle gère un périmètre différent (par Core). (Admin `0.11.0`, Webapp `0.9.0`)

- **Pseudonymisation IP RGPD + scope `gdpr:reveal`** : nouveau mode `ip_pseudonymize` dans les settings Logs. Le Core tronque l'IP dans son fichier local ; l'Admin reçoit l'IP réelle et la chiffre en AES-GCM 256 bits (clé générée à la table `gdpr_keys`). Nouveau scope RBAC `gdpr:reveal` (super-admin par défaut, délégable). Endpoint `POST /api/v1/logs/reveal-ip` : révèle l'IP d'une entrée avec motif obligatoire, crée une entrée d'audit `gdpr_reveal_ip`. Commande CLI `goproxify logs reveal-ip --entry-id xxx --reason "…"`. Documentation dans `docs/rgpd.md` §3 bis.

- **Anonymisation IP dans les access logs** : option `engine.ip_anonymize` dans `core.json` (et toggle Admin UI → Logs → Settings). IPv4 : dernier octet remplacé par 0 ; IPv6 : 80 derniers bits masqués. Fail2Ban et Sentinel reçoivent toujours l'IP réelle. Propagé en temps réel aux Cores via WS `push_settings`.
- **WAF — whitelist IP par route** : champ `waf_whitelist_ips` (tableau CIDRs) dans `WAFConfig`. Les IPs correspondantes bypassent complètement le WAF pour cette route (Fail2Ban/Sentinel restent actifs).
- **WAF — hot-reload depuis fichier externe** : champ `engine.waf_custom_rules_path` dans `core.json`. Le Core surveille le fichier toutes les 10 s et recharge les règles custom sans redémarrage.
- **Doc RGPD** : `docs/rgpd.md` — inventaire complet des données collectées, options de minimisation (anonymisation, rétention, droit à l'effacement), checklist opérateur, mesures de sécurité.
- **Benchmark** : `docs/benchmark.md` — méthodologie k6, résultats HTTP/1.1 passthrough et WAF vs Nginx/Caddy, instructions pour reproduire.

### Ajouté

- **Monitoring ACME — multi-fournisseurs** : la page "Monitoring ACME" peut désormais gérer plusieurs fournisseurs DNS nommés (ex: "cloudflare-prod", "ovh-zone2"). Nouvelle table `acme_providers` (id, name, type, params JSON). Nouveaux endpoints CRUD `/api/v1/acme/providers`. Section "DNS Providers" dans l'UI avec liste des providers configurés, badges colorés, formulaire d'ajout/édition (nom, type, credentials JSON) et suppression par provider.

- **Prism — carte live** : en mode Live, la carte monde affiche désormais des points pulsants animés par pays au fil des connexions entrantes (bleu = visite, rouge = ban, orange = erreur). Un flux "Connexions temps réel" scrollant apparaît sous la carte avec IP, pays, domaine, statut et horodatage. Nouveau endpoint backend `/api/v1/prism/live-ips` (polling toutes les 4 s) et fonction analytics `GetLiveIPs` qui joint `logs`, `geoip_cache` et `security_bans` pour classifier chaque événement.

### Amélioré

- **UI Monitoring ACME** : la page affiche désormais le fournisseur DNS associé à chaque certificat (via jointure avec la table `domains`), avec un badge coloré par provider (Cloudflare, OVH, Gandi, Hetzner, Route 53). Ajout d'un panneau "Configuration ACME" en haut permettant de visualiser et modifier la config globale (activé, email, provider, directory URL). Ajout du bouton "Supprimer" par certificat. Nouveau panel détail latéral (clic sur une ligne) avec lien vers la section Domaines. Toutes les modales utilisent `document.body` pour éviter les problèmes de stacking context.

### Ajouté

- **UI Modale sécurité proxy — section WAF** : indicateur d'héritage Core (bannière verte "Hérite de la config WAF du Core"), détection automatique de plateforme depuis l'URL upstream (WordPress, Drupal, Nextcloud, DokuWiki, cPanel), liste manuelle de plateformes avec cases à cocher, bouton "↩ Hériter du Core" pour réinitialiser. Champ `exclude_platforms` persisté dans la config WAF du proxy.
- **API / Modèle** : champ `exclude_platforms []string` ajouté à `WAFConfig` dans `route.go` — plateformes applicatives pour lesquelles les règles WAF générant des faux positifs seront exclues automatiquement (union avec `ExcludeIDs`).

### Corrigé

- **i18n ACME** : traductions ES et DE complètes pour toutes les clés `acme_monitor.*` (providers, new_cert) — la page s'affichait en anglais pour ces locales. Ajout de `common.optional` et `common.required` en ES et DE.
- **ACME — icônes actions** : les boutons texte "Edit"/"Delete" (providers DNS) et "Renew"/"Delete" (certificats) remplacés par des icônes SVG avec tooltip `title`.
- **Wizard — fournisseurs ACME dynamiques** : le wizard chargé depuis `/acme/providers` la liste des fournisseurs nommés configurés ; le sélecteur DNS affiche désormais ces providers réels ("cloudflare-prod (cloudflare)") au lieu d'une liste statique générique. Fallback sur la liste statique si aucun provider n'est configuré.

- **UI Sentinel (sécurité Core)** : clés i18n `page.core-security-sentinel` et `common.active`/`common.inactive` manquantes dans les 4 locales — les étiquettes affichaient le nom de clé brut. Icônes améliorées pour Fail2Ban (stylo/édition), CrowdSec (bouclier avec alerte) et Sentinel (œil de surveillance).
- **UI Tunnel L4 mTLS** : double préfixe `/api/v1` dans les appels `api()` — GET et PUT `tunnel-config` échouaient silencieusement
- **UI modales (transparence)** : tous les backdrops `position:fixed` rendus dans `#content` échappaient à la fenêtre si le conteneur parent créait un nouveau contexte d'empilement — modales déplacées directement dans `document.body` (`insertAdjacentHTML('beforeend')`) dans `workspaces.js`, `cert-deploy.js`, `users.js`, `trafic.js` et `core.js`
- **UI Workspaces** : padding et bordure manquants dans le footer du modal "Nouvel espace" — la classe CSS `dialog-footer` n'était pas définie (alias vers `dialog-actions` ajouté)
- **UI modales** : harmonisation du z-index sur toutes les modales/panels (cert-deploy, workspaces, trafic, core, users) — cert-deploy utilisait z-index:9990 au lieu de 9999 ; nettoyage des inline styles redondants avec la classe `dialog-backdrop`
- **i18n** : ajout de la clé `common.add` manquante (EN/FR/ES/DE) — les boutons "Ajouter" affichaient le nom de clé brut dans le panel Workspaces
- **UI Health checks** : groupement par proxy cassé — regex supposait un format d'URL inexistant ; cross-référence correcte via les backends déclarés dans chaque proxy ; rendu amélioré (chips colorés au lieu d'un tableau)


### Ajouté — MCP server étendu : outils Certificate Hub (`admin`)

- **`get_cert_status`** : statut d'expiration de tous les certs avec KPIs (ok/warning/critical/expired) + filtre domaine optionnel ; resource URI `goproxify://certs/monitor`
- **`list_cert_deploy_targets`** : liste les cibles de déploiement d'un cert (webhook, ssh_exec) avec dernier statut
- **`trigger_cert_deploy`** : déclenche immédiatement le déploiement d'un cert vers une cible spécifique
- **`import_cert`** : importe un certificat externe (PEM + clé) — extraction automatique du domaine (SAN/CN), upsert en DB

### Ajouté — Import de certificats externes (`webapp` · `admin`)

- **Endpoint `POST /api/v1/certs/import`** : accepte `{cert_pem, key_pem, issuer?}`, valide le bloc PEM, extrait domaine (SAN/CN) et `expires_at` depuis le certificat, upsert en DB — écrase un cert existant sur le même domaine
- Après import, le certificat est poussé en temps réel aux Cores via `CertImportPusher` (même chemin que les certs ACME)
- **Page Admin `acme-monitor`** : bouton "+ Importer un certificat" → modal PEM (cert + clé + émetteur optionnel) ; auto-refresh 60s avec nettoyage du timer à la navigation

### Ajouté — Monitoring ACME & alertes d'expiration (`webapp` · `admin`)

- **Endpoint `GET /api/v1/certs/acme-monitor`** — retourne par cert : `days_left`, `status` (`ok`/`warning`/`critical`/`expired`) + KPIs résumés (`total`, `ok`, `warning`, `critical`, `expired`)
- **Alertes automatiques** : callback `OnCertExpiring` dans `acme.Manager` — déclenché à chaque cycle 12h pour tous les certs expirant dans ≤ 30 jours → émission de `TriggerCertExpiringSoon` (warning ≤30j, critical ≤7j) vers le moteur d'alertes existant
- **Page Admin `acme-monitor`** : 5 tuiles KPI (total / valides / ≤30j / ≤7j / expirés), tableau avec badge statut coloré, date d'expiration, date de dernier renouvellement, bouton "Renouveler" inline — accessible via Accès → Monitoring ACME

### Ajouté — Certificate Deploy Hub (`webapp` · `admin`)

- **3 nouvelles tables SQLite** : `cert_deploy_targets` (webhook, pull_token, ssh_exec), `cert_pull_tokens` (tokens signés HMAC, TTL, max_uses), `cert_deploy_history` (audit de chaque déploiement)
- **Deploy targets** : CRUD `GET|POST /api/v1/certs/{id}/deploy-targets`, `DELETE /…/{targetID}`, `POST /…/{targetID}/trigger`, `GET /…/{targetID}/history` — déclenchement automatique à chaque renouvellement ACME ou manuel
- **Webhook push** : POST HMAC-SHA256 signé (`X-GoProxify-Signature: sha256=…`) vers n'importe quelle URL avec retry — payload JSON `{domain, cert_pem, key_pem, chain_pem, fingerprint, expires_at}`
- **Pull tokens** : génération de tokens sécurisés (hash HMAC-SHA256, TTL, max_uses) — `GET /api/v1/cert-bundle?token=xxx&format=pem|key|fullchain|json` — endpoint **public** sans auth, téléchargeable par simple `curl`
- **Hook OnCertObtained** dans `acme.Manager` — déclenche automatiquement `certdeploy.Deployer.TriggerForCert` après chaque renouvellement
- **SSH exec target** : déploiement via SSH vers n'importe quelle machine — GoProxify SSHe à la cible et exécute un script configurable avec les variables `GPX_CERT_PEM / GPX_KEY_PEM / GPX_DOMAIN / GPX_EXPIRES_AT` injectées
- **Package `certformat`** : conversion PEM→DER, DER clé (PKCS#8), PKCS#12/PFX (`software.sslmate.com/src/go-pkcs12`), fullchain, JSON — endpoint `cert-bundle` utilise désormais `certformat.Convert` avec validation du format à la création du token
- **Page Admin** `cert-deploy` : liste des certificats, drawer de gestion par cert, onglets "Deploy Targets" / "Pull Tokens", modal de création target (webhook + ssh_exec), modal de création token avec tous les formats (PEM/DER/PKCS#12/JSON) + champ mot de passe PKCS#12 conditionnel + exemple `curl` affiché one-time

### Ajouté — Workspaces : espaces de travail multi-tenant (`webapp` · `admin`)

- **3 nouvelles tables SQLite** : `workspaces` (nom, description, créateur), `workspace_members` (user/team), `workspace_resources` (proxy/domain/core)
- **API CRUD** `GET|POST /api/v1/workspaces`, `GET|PUT|DELETE /api/v1/workspaces/{id}`, gestion membres (`POST|DELETE /api/v1/workspaces/{id}/members/{type}/{id}`) et ressources (`POST|DELETE /api/v1/workspaces/{id}/resources/{type}/{id}`)
- **Page Admin** `workspaces` : grille de cards avec compteurs membres/ressources, panneau latéral de détail — ajout/suppression membres (équipes + utilisateurs) et ressources (proxies, cores, domaines par pattern)
- Accessible via le menu **Accès → Espaces de travail** (réservé admin/superadmin)

### Ajouté — Ban Intelligence : dashboard IP rejetées (`webapp` · `admin`)

- **5 endpoints** `GET /api/v1/security/bans/intel/{kpis,by-reason,by-source,timeline,top-ips}` — analyse historique sur `security_ban_history` + `security_bans`
- **Vue Admin** (`security-bans`) refonte complète : 4 KPIs, sparkline 48h, donut raisons (SVG), barres par source, top 20 IPs récidivistes avec débannissement en 1 clic
- **Vue Core** (`core-security-bans`) : bans actifs + intelligence fusionnés — onglets Actifs / Analyse / CrowdSec / Historique sur la même page

### Ajouté — UX opérateur avancée — B1/B2/B3 (`webapp` · `admin`)

- **B1 — Page Health checks par route** (`core-health`) : tableau des backends groupés par proxy avec statut up/down, paramètres HealthCheck (path, interval, seuils), rafraîchissement auto 30 s
- **B2 — Tunnel L4 mTLS complet** (`core-tunnel`) : UI + API Admin `GET/PUT /api/v1/nodes/{id}/tunnel-config` + table `node_tunnel_configs` + **WS push Admin→Core** (`push_tunnel_config`) — les peers configurés sont désormais poussés en temps réel au Core et appliqués via `tunnel.Manager.SetPeers`
- **B3 — Diff de config proxy** : endpoint `GET /api/v1/proxies/{id}/revisions/diff?from=&to=` + **bouton "Diff config" dans trafic.js** — modal interactif avec sélecteurs de révisions, tableau de diff champ par champ (avant/après mis en évidence)
- **UX Sécurité Core** : "Moteurs de sécurité" devient une section de configuration inline dans la page `core-security` (toggles Fail2Ban/CrowdSec/Sentinel avec leurs panels) — le sous-menu "Moteurs IPS" est supprimé
- Client `coreproxy` : ajout de `ListRevisions(ctx, target, id)` (proxy vers `GET /internal/v1/proxies/{id}/revisions`)

### Ajouté — Observabilité bans dans Prism (`webapp` · `admin`)

- **Section "Bans IP" dans Prism** : timeline bans/heure (SVG sparkline), répartition par source (barres), top 15 IPs les plus bannies
- **API Prism** : 3 nouveaux endpoints — `GET /api/v1/prism/bans/timeline`, `GET /api/v1/prism/bans/by-source`, `GET /api/v1/prism/bans/top-ips` — alimentés depuis `security_ban_history` et `security_bans`
- **Export CSV bans** : bouton "CSV" sur la page Bans + endpoint `GET /api/v1/security/bans/export?format=csv|json` (10 000 bans max, fichier `bans-export-<ts>.csv`)
- **Export CSV bans dans Prism** : lien "Export CSV" dans le panneau Bans de Prism

### Documentation

- **README translated to English**: `README.md` is now in English, with a user-centered introduction (value proposition, concrete use case, 7 differentiators). The French version is preserved as `README.fr.md`.
- **Docs translated to English**: `docs/faq.md`, `docs/architecture.md`, `docs/fonctionnalites.md` fully translated from French to English for an international audience.

---

## [0.4.0] — 2026-09-19

### Corrigé — Agrégation complète des bans Rules Engine dans l'Admin (`admin`)

- **`internal/core/ws/messages.go`** : ajout de `ActionType` dans `RuleFiredPayload` (propagé depuis `ExecLog`)
- **`internal/core/rulesengine/types.go`** : ajout de `ActionType string` dans `ExecLog`
- **`internal/core/rulesengine/engine.go`** : `evalRule` peuple `ActionType` dans le log d'exécution
- **`internal/core/rulesengine/actions.go`** : `execBanIP` enrichit `Detail` avec `ban_reason`, `ban_expires_at`, `ban_duration` — permet à l'Admin de reconstruire le ban
- **`internal/admin/corews/manager.go`** : `handleRuleFired` insère maintenant dans `security_bans` + `security_ban_history` quand `action_type == ban_ip` — complète l'agrégation des 4 sources (F2B, CrowdSec, Threat, Rules Engine)

### Ajouté — Base de données SQLite bans dans le Core (`core`)

- **`internal/core/bansdb/`** : nouveau package SQLite local (CGO-free, `modernc.org/sqlite`)
  - Table `bans` : bans actifs par source (admin, fail2ban, crowdsec, rules_engine, threat) avec expiration
  - Table `ban_history` : historique complet (remplace le ring buffer de 2000 entrées), indexé par IP + date
  - Table `proxy_errors` : journal HTTP par domaine (remplace le ring buffer de 5000 entrées), purgé toutes les 48h
  - Écriture atomique WAL + synchronisation NORMAL
  - `ActiveBans()`, `UpsertBan()`, `DeleteBan()`, `DeleteBansBySource()`, `RecordBanEvent()`, `RecentBanCount()`, `RepeatBanIP()`, `BanHistorySince()`, `RecordProxyEvent()`, `ProxyErrorRate()`, purge par source/date
- **`internal/core/server.go`** : champ `bansDB *bansdb.DB` ; suppression des ring buffers `banEvents`/`proxyErrLog` et de `lastBanList` ; initialisation au démarrage + fermeture à l'arrêt
- **`internal/core/persistence.go`** : `applyBans` persiste via DB (source "admin") ; `loadBansFromDisk` lit depuis DB ; `bansDBPurgeLoop` purge toutes les heures (expirés + historique > 30j + proxy_errors > 48h)
- **`internal/core/internalapi.go`** : helper `reloadBanStore()` reconstruit le BanStore en mémoire depuis DB + pendingThreatBans ; `onF2BBan`, `onCrowdSecBansChanged`, `addRuleBan` utilisent la DB ; `addBanEvent`, `recentBanCount`, `repeatBanIP`, `recordProxyEvent`, `proxyErrorRate` délèguent à la DB
- **API interne Core** : nouveaux endpoints `GET /internal/v1/bans`, `GET /internal/v1/bans/history`, `DELETE /internal/v1/bans/{id}`

### Ajouté — Moteur de règles automatiques autonome dans le Core (`core`)

- **`internal/core/rulesengine/`** : nouveau package — moteur de règles entièrement autonome dans le Core
  - `types.go` : `Rule`, `Condition`, `Action`, `ExecLog` (miroir du moteur Admin, sans champs DB)
  - `evaluators.go` : évaluation via callbacks Deps (`GetRecentBanCount`, `GetRepeatBanIP`, `GetF2BLastActivity`, `GetCrowdSecLastSync`, `GetProxyErrorRate`) ; `CondCVECritical` retourne toujours false (pas de données CVE dans le Core)
  - `actions.go` : actions via Deps (`DisableProxy`, `BanIP`, `EmitNotify`, `EnableStrictF2B`)
  - `engine.go` : tick toutes les 60 s, cooldown par règle, `ReplaceRules` dynamique, `OnRuleFired` callback
  - Fonctionne **sans l'Admin** — le Core évalue les règles en autonomie
- **`internal/core/server.go`** : ring buffer `banEvents` (2 000 entrées) alimenté depuis F2B, CrowdSec et le moteur de règles lui-même ; ring buffer `proxyErrLog` (5 000 entrées) alimenté via `accessLog.SetProxyTap` ; wiring complet des Deps ; `EnableStrictF2B` réduit `MaxErrors` à 5 pendant la durée configurée
- **`internal/core/logger/accesslog.go`** : ajout de `SetProxyTap(func(domain string, status int))` pour alimenter le taux d'erreur proxy
- **`internal/core/fail2ban/fail2ban.go`** : ajout de `LastBan() time.Time` pour la condition `EngineSilent`
- **`internal/core/router/table.go`** : ajout de `DisableByIDOrHost(idOrHost string)` pour l'action `disable_proxy`
- **`corews`** : nouveaux messages `TypePushAutoRules` (Admin→Core) et `TypeRuleFired` (Core→Admin) + `RuleFiredPayload`
- **`internal/core/wshandlers.go`** : handler `TypePushAutoRules` → `rulesEngine.ReplaceRules`
- **`internal/core/internalapi.go`** : méthodes `addBanEvent`, `recentBanCount`, `repeatBanIP`, `recordProxyEvent`, `proxyErrorRate`, `addRuleBan`, `onRuleFired`, `onRuleNotify`
- **Admin `corews/manager`** : handler `handleRuleFired` qui persiste dans `rules_engine_history` et met à jour `last_fired_at`/`fire_count` ; méthode `PushAutoRules` pour envoyer les règles à tous les Cores au connect

### Ajouté — Moteur CrowdSec autonome dans le Core (`core`)

- **`internal/core/crowdsec/`** : nouveau bouncer CrowdSec entièrement autonome dans le Core
  - État en mémoire (`[]Decision`) + snapshot JSON (`/etc/goproxify/crowdsec/threats.json`) chargé au démarrage
  - Synchronisation LAPI HTTP toutes les 60 s, `SyncNow` immédiat sur changement de config
  - `OnBansChanged` : reconstruit la liste de bans actifs + notifie le `banStore` local
  - `OnDecisions` : notifie l'Admin des nouvelles/supprimées décisions via WS (`TypeCrowdSecDecisions`)
  - Fonctionne **sans l'Admin** — le Core banne en autonomie
- **`corews`** : nouveaux messages `TypePushCrowdSecConfig` (Admin→Core) et `TypeCrowdSecDecisions` (Core→Admin)
- **Admin `corews/manager`** : handler `handleCrowdSecDecisions` qui persiste dans `security_threats`/`security_bans`
- **Admin `corews/manager`** : méthode `PushCrowdSecConfig` pour synchroniser la config vers un ou tous les Cores

### Ajouté — Moteur Fail2Ban autonome dans le Core (`core`)

- **`internal/core/fail2ban/`** : nouveau moteur Fail2Ban entièrement autonome dans le Core
  - Fenêtre glissante en mémoire par IP (pas de DB), alimenté directement depuis l'`AccessLogger` via un tap non-bloquant
  - Config persistée sur le volume Core en JSON (`/etc/goproxify/fail2ban/config.json`)
  - `OnBan` : applique le ban immédiatement dans le `banStore` local + persiste dans `bans.json` + notifie l'Admin via WS (`TypeF2BBan`)
  - Fonctionne **sans l'Admin** — le Core banne en autonomie, l'Admin reçoit une notification s'il est connecté
- **`AccessLogger`** : ajout de `SetF2BTap(func(ip, status))` pour alimenter le moteur sans overhead
- **`corews`** : nouveaux messages `TypePushF2BConfig` (Admin→Core) et `TypeF2BBan` (Core→Admin)
- **Admin `corews/manager`** : handler `handleF2BBan` qui persiste le ban dans `security_bans` et émet une alerte
- **Admin `corews/manager`** : méthode `PushF2BConfig` pour synchroniser la config vers un ou tous les Cores

### Ajouté — Dashboard sécurité agrégé Admin (`webapp`)

- **Admin > Sécurité** (vue globale) : KPIs agrégés tous Cores (bans actifs, décisions CrowdSec, CVEs critiques, score posture moyen), état engines IPS (F2B/CrowdSec/WAF), alertes certificats, tableau rapide des Cores avec lien "Voir ce Core"
- **Admin > Sécurité > Bans** : bans actifs agrégés tous Cores avec répartition par source (F2B/CrowdSec/natif) et par Core, historique
- **Admin > Sécurité > Vulnérabilités** : CVEs classées par sévérité (critiques/élevées/moyennes/corrigées) tous Cores, badge CVSS coloré, lien proxy + Core
- **Admin > Sécurité > Menaces** : timeline événements tous Cores (100 derniers), menaces actives avec source et Core
- **Admin > Automatisation** : Règles automatiques (globales, moteur Admin)

### Modifié — Réorganisation navigation admin/core (`webapp`)

- **Admin** : suppression des doublons de sécurité (`security-vulns`, `security-posture`, `security-bans`, `security-sentinel`) — ces pages existent uniquement dans le menu Core
- **Admin** : groupe "Sécurité" remplacé par "Automatisation" (contient uniquement les Règles automatiques, qui restent globales)
- **Core** : ajout de "Moteurs IPS" (`core-security-ips-engines`) dans le menu Sécurité du Core — la config F2B/CrowdSec/WAF est poussée aux Cores, elle se configure donc par Core
- Principe : Admin = gestion plateforme + vues agrégées ; Core = tout ce qui tourne dans un Core

### Ajouté — Intégration métriques Prometheus dans l'UI admin (`webapp` 0.4.5)

- **Dashboard** : bande temps réel (req/s global, taux d'erreur 5xx, bytes in/out) ; sparklines p95 latence + req/s sur chaque nœud Core ; alertes cert expiry Prometheus (<7j) ; indicateur backends dégradés
- **Trafic/Proxies** : bande métriques par proxy sur chaque tuile (req/s, taux d'erreur, p95, backends up)
- **Sécurité Overview** : 4 tuiles métriques (Fail2Ban bans/scans, CrowdSec new/deleted, WAF profils actifs, Pipeline top 3 stages)
- **Moteur de règles** : bande métriques (cycles/min, durée moy., règles actives, actions déclenchées)
- **Infrastructure** : bande métriques cluster (WS Admin/Agent connections, peer sync moyen)
- **Domaines/TLS** : enrichissement cert expiry depuis Prometheus + p95 handshake et connexions actives
- **Portal** : KPI sessions actives (one_shot vs multi) depuis `gpx_portal_sessions_active`
- **Prism** : section top proxies (p95 latence + taux d'erreur) depuis `/internal/v1/metrics/summary`

### Ajouté — Métriques complètes tous services (`core` 0.3.96 · `admin` 0.3.5)

- **Backend health** : `gpx_backend_up{backend}` (gauge 0/1) — `MarkUp`/`MarkDown` instrumentés dans `proxy/healthcheck.go`
- **Peer sync** : `gpx_peer_sync_duration_seconds{peer}` (histogram) — `syncPeer()` instrumenté dans `gateway_peers.go`
- **WAF comportemental** : `gpx_waf_profiles_active` (gauge) — mis à jour dans `behavior/store.go` après chaque GC
- **Portal sessions** : `gpx_portal_sessions_active{type}` (gauge) — mis à jour dans `portal/session.go` après chaque mutation
- **Admin HTTP** : `gpx_admin_http_requests_total{method,status}` et `gpx_admin_http_request_duration_seconds{method}` — `logMiddleware` instrumenté
- **VulnScan** : `gpx_vulnscan_cves_detected_total{severity}`, `gpx_vulnscan_scans_total{result}`, `gpx_vulnscan_scan_duration_seconds` — scanner instrumenté
- **Rules Engine** : `gpx_rulesengine_eval_duration_seconds` (histogram), `gpx_rulesengine_active_rules` (gauge) — `evalAll()` instrumenté

### Ajouté — Métriques par proxy (`core` 0.3.95 · `admin` 0.3.4)

- **Option A** — `handleMetricsSummary` (`GET /internal/v1/metrics/summary`) : nouveau champ `proxies[]` avec détail par host : `requests`, `errors`, `error_rate`, `p95_ms`, `active_requests`, `bytes_in`, `bytes_out`, `blocked_total`
- **Option B** — Prometheus : 2 nouveaux CounterVec `gpx_core_bytes_received_by_host_total{host}` et `gpx_core_bytes_sent_by_host_total{host}` pour tracer les octets par proxy ; `dispatch.go` mis à jour
- **Option C** — Métriques Prometheus des moteurs Admin (`internal/admin/adminmetrics`) :
  - `gpx_f2b_bans_total` / `gpx_f2b_scans_total` (Fail2Ban)
  - `gpx_crowdsec_decisions_total{action}` / `gpx_crowdsec_syncs_total{result}` (CrowdSec)
  - `gpx_rulesengine_evals_total` / `gpx_rulesengine_actions_total{action,result}` (moteur de règles)

### Modifié — Moteurs de ban indépendants (`webapp` 0.4.4)

- **Page Moteurs de ban** : remplacement du sélecteur radio exclusif (native/fail2ban/crowdsec) par 3 cartes indépendantes avec toggle — Fail2Ban, CrowdSec et Sentinel peuvent être activés simultanément
- Chaque carte reflète l'état réel (`enabled`) de chaque moteur et permet de le toggler instantanément sans rechargement
- Carte Sentinel ajoutée sur la page moteurs avec lien vers le dashboard avancé
- **Overview sécurité** : grille des moteurs utilise désormais les états réels (`f2bCfg.enabled`, `csCfg.enabled`, `threatCfg.enabled`) et non plus le provider radio
- i18n : nouveaux clés `engine_enabled`, `engine_disabled`, `ips_engines.multi_hint`, `sentinel_desc/hint/config` dans 4 locales

### Ajouté — Moteur de règles automatiques IPS (`admin` 0.3.0 · `webapp` 0.4.0)

- **Moteur de règles** (`internal/admin/rulesengine`) : boucle de poll 60 s, évaluation par condition, cooldown par règle, `EvalNow()` dry-run
- **5 types de conditions** : CVE critique (seuil CVSS), pic de bans (fenêtre glissante), moteur silencieux (F2B/CrowdSec inactif), taux d'erreur proxy (5xx), IP récidiviste (N bans en M minutes)
- **4 types d'actions** : désactiver proxy, bannir IP, alerte, activer mode strict F2B
- **API REST** `/api/v1/rules-engine` : CRUD règles, historique d'exécution, lancement à la demande, descripteurs de conditions
- **Migration DB** : tables `rules_engine_rules` et `rules_engine_history`
- **Wiring** `server.go` : deps injectées (DisableProxy, CreateBan, EmitAlert, LastActivity, LastSync)
- **Méthodes** `LastActivity()` sur `fail2ban.Engine`, `LastSync()` sur `crowdsec.Bouncer`
- **UI Admin** : page "Règles automatiques" (admin/superadmin), nav entry, liste avec toggle/run/edit/delete, modal de création dynamique, onglet historique
- **Page Bans refonte** : 4 tuiles KPI (bans actifs, par source, décisions CrowdSec, expirant dans 1h), 3 onglets (Actifs / CrowdSec / Historique)
- **Page Moteurs IPS** : sélecteur unifié Fail2Ban / CrowdSec avec panneaux de configuration
- **Overview sécurité** : tuile "Règles automatiques" + grille moteurs 4 colonnes (F2B, CrowdSec, Sentinel, Règles)
- i18n ajouté dans les 4 locales (EN/FR/ES/DE) : `security.rules.*`, `security.ips_engines.*`, `security.bans.kpi_*`, `security.bans.tab_*`

### Ajouté — WAF : 6 nouveaux jeux de règles OWASP CRS-4

- **Java / Log4Shell (944xxx)** : détection JNDI injection (`${jndi:ldap://...}`), Spring EL (`#{Runtime.exec()}`), gadgets de désérialisation Java
- **Remote File Inclusion (931xxx)** : URLs distantes dans les paramètres, wrappers PHP (`php://filter`, `phar://`, `data://`)
- **NodeJS / Prototype Pollution (934xxx)** : injection `__proto__`, `constructor.prototype`, modules Node (`require()`, `child_process`)
- **HTTP Request Smuggling (920xxx)** : coexistence TE+CL, chunked encoding obfusqué
- **Fichiers sensibles / Restricted Files (930xxx)** : accès à `.env`, `.git/`, `wp-config.php`, dumps SQL, fichiers de debug (`phpinfo.php`, `composer.json`…)
- **Fuite de données en réponse (951xxx)** : erreurs SQL dans les réponses, stack traces PHP/Java, clés AWS (`AKIA…`)

**Nouveau — Inspection des réponses** : le moteur WAF peut désormais analyser les corps de réponse (règles `TargetResponse`). En mode `block`, une réponse contenant une fuite est bloquée avant transmission au client. En mode `detect`, la fuite est loguée sans bloquer.

**UI Admin** : le tableau des jeux de règles WAF (page Core > WAF) affiche les 13 catégories (anciennement 7). La désactivation par catégorie couvre les nouveaux IDs.

### Ajouté — Diagnostic trafic

- **Test du chemin de trafic à la demande** (`feat(trafic)`) : exécution étape par étape du chemin d'une requête depuis l'Admin pour diagnostiquer les configurations de routage

### Corrigé

- `fix(auth)` : garde `checkNeedOnboarding` contre le script non chargé — évite une erreur JS au démarrage si le module d'onboarding est absent
- `fix(bans)` : historique de ban — entrées manquantes pour les re-bans et source affichée en brut corrigées

### Documentation

- `docs/security.md` créé : documentation complète des moteurs de sécurité (WAF 13 règles, Sentinel, bans, GeoIP, timeouts, scanner CVE, métriques Prometheus)
- Landing page : carte « Moteurs de sécurité » ajoutée dans la section Documentation ; bullets WAF/Sentinel mis à jour (EN/FR/ES/DE)
- `README.md` et `suivi/roadmap-public.md` mis à jour pour refléter la v0.3

---

## [0.3.1] — 2026-09-17

### Ajouté — Sécurité : Sentinel, WAF, anti-DDoS

**Sentinel — ban immédiat sur signal comportemental**
- `Check()` appelle désormais `banFn` immédiatement dès qu'un signal non-rate (`path`, `ip`, `ua`, `custom_*`) dépasse le seuil. Avant ce fix, une IP pouvait scanner indéfiniment : chaque requête était rejetée individuellement mais l'IP n'était jamais bannie en base.

**Sentinel — paramètres exposés dans l'UI**
- Formulaire Sentinel : fenêtre rate (`rate_window`), seuil ban auto rate (`rate_ban_threshold` + `rate_ban_window`), limite globale anti-DDoS (`global_rps` + `global_burst`)

**Anti-DDoS — timeouts serveur HTTP/QUIC configurables**
- Paramètres `ReadTimeout`, `WriteTimeout`, `IdleTimeout`, `ReadHeaderTimeout` configurables depuis l'Admin (section Sécurité > Paramètres serveur)
- Propagation via WS (`TypePushServerConfig`) et push HTTP legacy
- Avertissement UI : redémarrage requis pour que les timeouts prennent effet

**Vulnscan — autorisation optionnelle des backends IP privées**
- Toggle admin dans le panel Scanner CVE : autorise le scan de backends sur des IPs privées (SSRF opt-in, désactivé par défaut)
- Configurable via UI ou variable d'environnement `GPX_VULNSCAN_ALLOW_PRIVATE`
- API `GET/PUT /security/vulnscan/config` exposée

**Indicateurs d'état des moteurs de sécurité**
- Vue d'ensemble Sécurité : badges d'état pour chaque moteur (WAF, Sentinel, CrowdSec, Fail2Ban, GeoIP)

**Bans — accès rapide Prism depuis la table**
- Bouton « Prism » dans la table des bans actifs : ouvre Prism filtré sur l'IP bannie

### Corrigé

- `fix(security)` : dates `created_at` affichées en `01/01/0001` — normalisées via `strftime` SQLite

---

## [0.3.0] — 2026-09-12

### Ajouté — WAF avancé + moteur Sentinel

**WAF — inspection et scoring (Core `0.3.72`)**
- Scoring anomalie par requête : chaque règle contribue un score, seuil configurable avant blocage
- Inspection corps JSON et form-data (pas uniquement les headers/URI)
- Règles custom hot-reload (rechargement sans redémarrage)
- Métriques WAF exposées (`goproxify_waf_*`) : hits par règle, scores, bloqués vs détectés
- Access log WAF : chaque décision tracée dans les logs d'accès

**Sentinel — moteur de détection comportementale**
- Analyse comportementale stateful par IP : fenêtre glissante configurable (taux d'erreurs, fréquence, patterns)
- Scoring anomalie Sentinel indépendant du WAF (complémentaire)
- Detect mode : log sans bloquer, pour calibrer les seuils avant mise en production
- Listes custom IP allowlist/denylist intégrées au moteur Sentinel
- Métriques Sentinel : événements, scores, décisions
- Propagation de la config Sentinel de l'Admin vers tous les Cores (WS)

**UI Admin**
- Nom « Sentinel » déployé dans l'interface (remplace l'ancienne appellation générique)
- Page et section dédiées WAF/Sentinel dans les paramètres de sécurité
- Section **Accès centralisée** + page **Politiques d'accès** : vue unifiée des règles IP/GeoIP/Bot par proxy
- Fix badges cert et alignement en-têtes colonnes dans la page Politiques d'accès

### Ajouté — Logs : corrélation et performances

**Corrélation exacte par `request_id` (Admin `0.2.122`, Core `0.3.69`)**
- Chaque requête porte un `request_id` unique ; les logs Admin et Core sont corrélés par cet identifiant
- Fix : `RealIP` appliqué dans le middleware admin pour éviter la double IP dans les logs
- Corrélation élargie aux logs admin (même identifiant visible dans Prism et les logs d'accès)

**Performances et affichage (Admin `0.2.121`, Webapp `0.3.102`)**
- Keyset pagination sur la table des logs : performances constantes quelle que soit la profondeur
- Index partiels SQLite sur les colonnes de filtrage fréquentes
- Vue live logs : format `log-row` compact restauré sur desktop ; tableau desktop + cards mobile alignés

### Amélioré — Prism

- Taux d'erreurs et IPs bannies affichés par pays (carte GeoIP)

### Amélioré — Admin : port local de secours

- `local_port` configurable sur l'Admin : accès direct à l'Admin sans passer par le Core (utile si le Core est injoignable)

### Refactorisé — Topologie dans le backup global

- Les snapshots de topologie (`topology_snapshots`) sont désormais intégrés au backup global Admin
- Table `topology_snapshots` supprimée — simplification du schéma

### Corrigé

- Core : gestion des IPs/CIDRs de confiance (`trusted_proxies`) corrigée (parsing CIDR + IPv6)
- Admin : `iconConfig` défini dans `infraAgentCard` (corrige une `ReferenceError` JS)

---

## [0.2.3] — 2026-08-30

### Ajouté — Relay Core→Core multi-hôtes (Portainer / délégation)

**Relay Portainer multi-hôtes**
- `endpoint_cores` : routage par endpoint Portainer vers un Core alternatif — chaque endpoint distant peut être servi par le Core le plus proche
- `skip_endpoints` : liste d'endpoints à ignorer lors de la découverte Portainer
- Connexion automatique du Core aux réseaux Docker des endpoints locaux Portainer
- Utilisation du port hôte publié pour les endpoints distants (au lieu du port conteneur)
- Purge automatique des routes Portainer masquées par la délégation après chaque upsert

**Relay Core→Core**
- Les routes Agent sont relayées vers les Cores délégués (Core→Core sans Admin)
- Relay via `DelegateAPIEndpoint` (endpoint interne `:8000`) avec peer tokens
- Vérification des aliases pour la correspondance de délégation
- Logs diagnostics de délégation dans `PushDelegations` (WS)

**Session WS Agent**
- Restauration de la session WS d'un Agent via `auth_token` quand le join token est consommé
- Auto-push de la config déclarée (`declared_config`) vers l'Agent à la première connexion

### Ajouté — UI Endpoint (Admin webapp)

- Sélecteur « Core cible » dans le modal `agentConfigure`
- Pré-remplissage du modal depuis `declared_config` quand l'Agent est hors ligne
- Pré-population du sélecteur `endpoint_cores` avec les Cores connus
- Pré-remplissage du modal de configuration depuis la config live (Agent connecté)
- Fix : échappement des guillemets dans le payload JSON `onclick` d'`agentConfigure`

### Corrigé

- Migration `agent.json` : ajout des sections `docker`/`portainer` si absentes au démarrage (agents antérieurs au write-through)
- 4 erreurs silencieuses corrigées suite à l'audit dead-code
- Fonctions dupliquées et appels `t()` non évalués supprimés

---

## [0.2.2] — 2026-08-09

### Modifié — Proxies YAML uniquement (suppression SQLite comme source de proxies)

- `GPX_PROXY_STORE` supprimé : les proxies sont **toujours** stockés en fichiers YAML sur le Core (`proxies/*.yaml`, `proxies-revisions/*.yaml`)
- `FilesEnabled()` retourne `true` en dur ; `StoreMode`, `ModeSQLite`, `ModeFiles` supprimés
- `loadFromSQLite` retiré de `coreproxy/load.go` ; Admin lit les proxies via l'API Core
- `PushRoutes` ne pousse plus de routes WS (`full_sync` sans clé `routes`) — le Core lit ses propres fichiers YAML
- Tests MCP et vulnscan migrent de lectures SQLite directes vers un faux serveur Core `httptest`
- `WriteProd` supprime automatiquement le `.json` legacy après écriture `.yaml`
- Panneau YAML de l'éditeur proxy repositionné dans la zone de contenu (corrige décalage visuel)

### Corrigé — Labels Docker multi-hôtes / chemins d'URL

- `goproxify.host` CSV : un seul proxy (premier hostname + aliases) au lieu d'une route par entrée — les pages hors `/` fonctionnent sur tous les domaines
- Normalisation `https://`, port, casse ; un chemin (`https://app.example.fr/admin`) devient une location avec strip-prefix
- Repli des anciennes routes `docker-host:` du même conteneur en aliases

### Ajouté — Wizard architecture + tickets bootstrap (Admin `0.2.35`)

- Toile d'architecture (hôtes + palette) : Core, Agent, Admin, Access-sur-Core, Portainer/K8s, multi-Core / groupe HA
- Packs install par hôte + tickets QR / lien `/i/{token}` + one-liner `curl|bash` (`POST /api/v1/bootstrap-tickets`)
- Auto-accept des nœuds déclarés issus du wizard ; reprise des nœuds existants ; région / autoscale / domaines-TLS
- Ancien wizard Infrastructure scénarisé retiré (entrée « + Ajouter » = toile)
- Landing : présentation de l'assistant d'architecture
- Plan : `docs/plans/2026-08-09-001-feat-architecture-wizard-qr-plan.md`

### Ajouté — MCP + CLI Infrastructure / bootstrap

- MCP : `list_declared_nodes`, `create_declared_node`, `delete_declared_node`, `create_bootstrap_ticket`, `accept_node`, `reject_node`
- Ressource MCP : `goproxify://declared-nodes`
- CLI : `goproxify nodes list|accept|reject`, `goproxify declared list|create|delete`, `goproxify bootstrap create`

### Modifié — Navigation Portail Access

- Sous-menu Core : Catalogue Access, Users Access, Templates Access, Audit Access
- Page dédiée Audit Access (contenu extrait de la page config portail)

### Ajouté — Préparation publication publique

- `NOTICE`, `CONTRIBUTING.md` (DCO), `CODE_OF_CONDUCT.md`, templates `.github/`
- `suivi/roadmap-public.md` ; badges README ; tags quickstart alignés sur `versions.json`
- Pipeline clean : exclude `docs/audits`, `ALLOW_PRIVATE_IPS=false`, includes communauté
- Pipeline Harness `publish-ghcr` : `public/main` → images GHCR (SemVer + `:preview`, pas `:latest`)
- Secret GHCR dédié `github_ghcr_token` (séparé de `github_publish_token` / droits repo)
- Tags quickstart / landing / release-notes réalignés sur `versions.json` (admin 0.2.28 / core 0.3.17 / agent 0.3.13)
- Scrub surface publique : defaults GHCR (Admin UI / Helm), IPs doc RFC5737 dans tests ; materialize+validate OK
- Publication GitHub/GHCR : reste volontairement **privée** pour l'instant (passage Public différé)
- `DISCLAIMER.md` : préversion 0.x, refus de garantie et de responsabilité d'usage
- Site vitrine : **goproxify.dev** sur Cloudflare Pages (plus de `.io`)
- Runbook : `docs/audits/publication/host-runbook.md`, `ci/prepublish-host.sh`

### Modifié — UI 2FA Access en tuiles (Core `0.3.3`)

- Compte Access : une tuile par méthode (TOTP, OTP email) avec badge Actif/Inactif
- Actions en icônes (QR/configurer, activer, désactiver) ; setup TOTP intégré dans la tuile

### Ajouté — QR code TOTP Access (Core `0.3.2`)

- `POST /api/2fa/totp/setup` renvoie `qr_code` (PNG data URL) en plus de `secret` / `otpauth_uri`
- UI Compte Access : affichage du QR + lien otpauth + clé manuelle

### Ajouté — MCP + CLI Access (Admin `0.2.15`)

- Scopes PAT `portal:read` / `portal:write` (API `/api/v1/portal*`, `/api/v1/portal-page-templates*`)
- Outils MCP Access : config, destinations, users/invite, audit, templates, push
- Ressources MCP : `goproxify://portal/{destinations,users,templates,audit}`
- CLI : `goproxify access config|destinations|users|audit|templates …`

### Ajouté — GoProxify Access (portail SSH / shell)

- Portail public Core : UI HTTPS + SSH UUID (dual façade), pont VM/`sshd` ou Docker via Agent
- Admin : catalogue destinations Trafic-like, users invite SMTP, tags, options par Core
- Coffre utilisateur : login SSH + mot de passe ou clé privée (chiffré sur Core ; jamais renvoyé)
- 2FA Access (TOTP / OTP email), sessions TTL/mode/révocation, audit métadonnées
- UX Access : tuiles, recherche, favoris, onglets ; templates HTML Access (fallback SPA)
- Plans : `docs/plans/2026-08-08-001-…`, `docs/plans/2026-08-08-002-…` (U1–U10)

### Modifié — Docs & landing (Access)

- `suivi/roadmap.md` : Jalon 23 ; README / changelog / landing alignés
- Landing : carte fonctionnalité Access + badge ; Users Access Admin : actions en icônes

### Ajouté — MCP enrichi (Admin `0.2.14`)

- Outils proxies : `update_proxy`, `set_proxy_enabled` ; `create_proxy` accepte `type` / `lb`
- Outils Agents : `list_agents`, `approve_agent`, `revoke_agent` (WS)
- Outils sécurité : `get_security_overview`, `list_security_bans`, `create_security_ban`, `delete_security_ban`, `list_security_threats`, `list_security_cves`
- Ressources MCP : `goproxify://agents`, `goproxify://security/{bans,threats,cves}`
- Docs : `docs/mcp.md`, `docs/mcp-implementation.md`, `docs/fonctionnalites.md` (PAT + MCP)

### Ajouté — WS étape 4 sécu + métriques Prometheus

- `gpx_join_*` usage unique (`JoinTokenStore` persisté) ; révocation locale du token après première connexion WS
- Tokens Agent Admin générés en `gpx_join_*` (rôle `agent`)
- Révocation Agent : `revoke_agent` Admin→Cores, `Hub.RevokeAgent` (ferme WS + invalide HMAC) ; `POST/DELETE /api/v1/agents/{id}/revoke` ; révocation token `role=agent` déclenche le même flux
- Métriques Core : `goproxify_ws_connections_active{role}` et `goproxify_ws_messages_sent_total{role,type}`

### Clarifié — Roadmap produit finalisée

- Jalons 0–22 clos ; versions Admin `0.2.13` / Core `0.3.1` / Agent `0.3.0` / Webapp `0.3.0`
- Backlog produit réduit à l'hygiène CI optionnelle ; dette technique WS/P95 isolée en bas de `suivi/roadmap.md`

### Corrigé — Générateur Labels Docker/K8s

- Champ « URL backend » remplacé par « Port » (`goproxify.port`) — l'Agent construit l'URL depuis l'IP du conteneur / ClusterIP
- Snippets : sélection par toggles depuis la bibliothèque Admin (plus de saisie libre d'IDs) ; résolution Core par nom ou ID
- Labels sécurité complets : GeoIP, IP filter, CORS, rate burst, WAF block/detect, HTTPS backend, passthrough, canary/shadow, prune ; auth via liste déroulante
- Préremplissage Trafic : host + aliases → `goproxify.host` CSV
- Snippets : plus de doublon WAF/Bot/GeoIP/… (réservés aux champs Sécurité natifs) ; webapp `0.3.1`
- Générateur Labels : page détachée → modale (Trafic / proxy / assistant infra), onglets parité Sécurité proxy ; webapp `0.3.2`

### Ajouté — CrowdSec bouncer bout-en-bout (Admin `0.2.13`, Core `0.3.1`)

- Stream LAPI `/v1/decisions/stream` (snapshot + deltas), dédup menaces, rebuild `security_bans`
- Push `push_bans` Admin→Core (full_sync + HTTP legacy) ; BanStore Core avec persistance disque
- Rejet 403 des IPs bannies (CrowdSec / Fail2Ban / natif) ; profils IP allow et IPs privées exemptés
- Alertes `crowdsec_critical` / `fail2ban_ban` à la création de bans
- Désactivation CrowdSec : purge menaces/bans + resync Core ; menaces internes agent → bans

### Corrigé — WAF / rate limit / bot (Core + Admin)

- Modale Sécurité : WAF enregistré en mode `block`/`detect` (plus forcé en `detect`)
- Bot : mapping `mode` → `js_challenge` ; modes monitor/log ; challenge cookie HMAC (anti-bypass)
- Challenge JS : URI échappée (anti-XSS) ; secret de signature
- Rate limit / IP filter / GeoIP : IP client via `RealIP` (CF / XFF) ; `Retry-After` ; refresh rps/burst ; éviction buckets inactifs
- WAF : `exclude_ids` par route respectés ; snippet type `waf` résolu au dispatch
- Page Core WAF : persistance mode + catégories via snippet

### Ajouté — Sécurité des proxies conteneur via labels (Core `0.3.0`, Agent `0.3.0`, Webapp `0.3.0`)

- Labels appliqués sur les routes `docker-host:` : `rate_limit`, `ip_filter`, `cors`, `geo_ip`, `snippets`, `auth_provider`, `waf`, `bot`
- Générateur de labels UI : snippets, auth provider, WAF, bot ; `rate_limit` au format `N/s`
- Snippets type `bot` résolus au dispatch ; fallback chemin GeoIP DB Core
- Package `internal/labels` pour le parsing partagé Agent/Core

### Clarifié — Backlog produit allégé

- Retirés (hors scope) : DEB/RPM, cron `docker exec`, terminal distant UI, E2E Playwright
- Conservés : labels Canary/Shadow auto (cohérence discovery) ; scan CI optionnel (hygiène)
- Reste technique documenté sous Jalon 18 (WS sécurité / retrait HTTP) et auto-scale P95

### Modifié — Landing v0.1.1 (présentation produit)

- Version affichée `v0.2.12` / Go 1.25 ; badges WebSocket, Adaptive LB, i18n
- Cartes fonctionnalités : LB adaptatif, gateway inter-Cores, délégation, pages d'erreur, CLI, Prism Admin+Core
- Schéma architecture : hub WS, métriques Agent, gateway
- Stack : ligne WebSocket control plane ; textes EN par défaut
- Docs : carte délégation → `docs/delegation.md`
- i18n EN/FR/ES/DE : sous-titres de sections + cartes docs

### Ajouté — i18n EN / FR / ES / DE (Admin `0.2.12`, Webapp `0.2.5`)

- Socle `internal/i18n` : résolution `Accept-Language`, catalogues EN (source) + FR/ES/DE, fallback EN
- Pages d'erreur Core localisées pour les visiteurs
- Admin UI : `t()` + override `localStorage` + sélecteur de langue
- Couverture : shell, dashboard, settings, Trafic, Users, Logs, account, erreurs API, emails
- Landing : switcher multi-langue + contenus marketing
- Plan : `docs/plans/2026-08-07-003-feat-multilingual-i18n-plan.md`

### Ajouté — LB adaptatif WS + gateway inter-Cores (Core)

- Métriques conteneur Agent→Core via WS ; merge de pools par host ; poids LB dynamiques
- Tunnel gateway `POST /internal/v1/gateway/tunnel` pour joindre un backend distant via le Core propriétaire
- Failover : après échec proxy, essai du reste du pool + quarantaine courte (évite 502 immédiat)
- Doc architecture : `docs/architecture.md`

### Ajouté — Bibliothèque de pages d'erreur

- Templates Admin (placeholders + assets drag-and-drop multi-fichiers)
- Sync WS vers `/etc/goproxify/error-pages` sur le volume Core (dispo si Admin HS)
- Sélecteur de template sur le formulaire proxy ; application avant matching de routes
- Lien ID log → Admin (pas l'hôte proxyfié)

### Amélioré — CLI opérationnel (token, backup, alert, import)

- `goproxify token create/list/revoke` branché sur `/api/v1/tokens` (TTL `24h`/`7d`, `-endpoint`, `-rbac-role`)
- `goproxify backup create/list/restore` via snapshots Admin + export routage + restore fichier `.gpx-admin-backup`
- `goproxify alert test -channel|-all` via `POST /api/v1/alert-channels/{id}/test`
- `goproxify import` : parse local (`importer.ParseConfig`) + apply HTTP ; `-dry-run` offline ; formats alignés (plus de zoraxy/bunkerweb/csv fantômes)
- Auth commune `-admin-url` / `-token` (ou variables `GPX_CONTROLPLANE_*`)

### Amélioré — Sauvegardes multi-planifications

- Jusqu'à 5 planifications indépendantes (fréquence lisible + rétention dédiée)
- Navigation Sauvegardes par cartes : Snapshots / Planification / Routage / Historique

### Amélioré — Menus unifiés Admin ↔ Core

- Menu **Sécurité** (dashboard, vulnérabilités, posture, bans) dupliqué dans la nav contextuelle Core
- Code unifié `mode: admin|core` (même pattern que Trafic / Certs) ; données filtrées via `/proxies?core=`
- Config Fail2Ban / CrowdSec et déclenchement du scanner réservés à la vue admin globale
- Lien « Dashboard sécurité » dans le hub Paramètres Core
- **Prism unifié** : vue globale Admin + filtre Core (`node_name`) ; légende Codes HTTP pleine tuile
- **Logs** d'accès / système unifiés Admin+Core ; live SSE corrigé
- **Certificats** unifiés via `renderCertsPage`
- Cores accessibles listés dans la sidebar

### Amélioré — UI Sécurité / Bans / Labels / Alertes

- Sous-menus Sécurité : Vulnérabilités / Posture / Bans ; Fail2Ban+CrowdSec dans Bans ; Certificats retirés du dashboard
- Page Bans : bandeau config + filtres
- Prism : IPs déjà bannies marquées ; « Bannir » en icône
- Générateur Labels Docker/K8s redesigné et déplacé dans le wizard Infrastructure
- Sélecteur de type des canaux d'alerte redesigné
- Zone de dépôt fichiers pour migration de config proxy
- Menu burger / responsive admin corrigé
- Vulnscan : progression live + résumé détaillé

### Amélioré — Interactions Logs ↔ Prism

- Bouton **Corréler** remplacé par une icône (délégation d'événements) : corrigé le `onclick` cassé par les guillemets JSON
- Corrélation élargie : logs Agent/système (±30 s) via domaine, message, ou nom de conteneur (variantes dots→tirets)
- Logs : cellules cliquables (IP, domaine, code, méthode, chemin) + chips de filtres actifs (Maj+clic pour cumuler)
- Logs → Prism : icône analyse sur chaque ligne ; Prism → Logs : icône / clic depuis Top IPs, chemins, codes HTTP, backends
- Prism : drill-down IP / chemin / proxy, zoom timeline au clic sur un point, filtre API `ip` / `path`
- Filtre status logs : accepte `5xx` / `5` (famille) en plus du code exact
- Ingestion access logs Core → Admin via WS

### Documenté — Délégation Passthrough vs Terminate

- Nouveau guide [docs/delegation.md](../docs/delegation.md) : schémas, IP client, prérequis Terminate
- Liens dans README, architecture, fonctionnalités, FAQ
- Aide UI Domaines enrichie (modes + endpoint)

### Corrigé — Délégation Terminate (SNI vhost)

- Re-TLS Core d'entrée → Core cible : SNI = Host virtuel (domaine), plus l'IP de l'endpoint
- Alignement `PreserveHost` sur le push WS ; `X-Forwarded-For` via `RealIP`

### Amélioré — RBAC grants (scopes + mode lecture/écriture)

- Primitive unifiée : grant `(type, valeur, read|write)` sur **user** et/ou **équipe**
- Rôle plateforme réduit à `admin` / `user` (plus de plafond operator/viewer pour les proxies)
- Membership d'équipe sans rôle : héritage intégral des grants de l'équipe
- Migration B' : équipes mixtes operator/viewer scindées en équipe write + `… (lecture)`
- UI Utilisateurs : éditeur de grants personnels et d'équipe

### Amélioré — Clarification rôle global vs droits d'équipe (UI Utilisateurs)

- Libellés distincts : niveau de compte (plafond) vs droit d'équipe (« Peut modifier » / « Lecture seule »)
- Aide conditionnelle selon admin / operator / viewer ; empty state corrigé (sans équipe → aucun proxy pour operator/viewer)

### Amélioré — Profils IP persistés sur le volume Core

- Snapshot runtime écrit sous `/etc/goproxify/ip-profiles/profiles.json` à chaque push / full_sync
- Chargé au démarrage Core (survit à un redémarrage sans Admin)
- Config + refresh feeds restent dans l'Admin (SQLite) ; surcharge chemin : `GPX_IP_PROFILES_PATH`

### Amélioré — Formats d'import unifiés + onglets Import / Restore

- `CONFIG_FORMATS` / `CONFIG_FORMAT_SVG` centralisés dans `shared/config-formats.js` (Trafic, Import, onboarding, proxy-form)
- Helper `configFormatPickerHtml` / `configFormatMeta` pour un rendu unique des cartes format
- Onglets Import / Restore : navigation en cartes (icône + titre + description) à la place de `tab-btn` sans styles

### Corrigé — Bans actifs vides + icônes Importer (Trafic)

- Cause bans : `security.Ban.ID` était `int64` alors que la table utilise des UUID `TEXT` → Scan échouait en silence
- UI : `deleteBan` quote correctement l'id string
- Importer Trafic : cartes format avec `CONFIG_FORMAT_SVG` (icônes manquantes à l'étape 1)

### Supprimé — Pipeline UI `build.sh` / `dist/`

- L'Admin sert uniquement `src/` via `go:embed` : suppression de `build.sh`, `dist/index.html`, `shell.html`
- Dockerfile admin : plus de copie vers `/etc/goproxify/storage/webapp/`
- Découpage `pages-all.js` en modules dédiés (proxy, infra, onboarding, sécurité, core, logs, prism)

### Corrigé — Horloge admin absente (embed `src/`)

- L'Admin sert l'UI via `go:embed src`, pas `dist/` : l'horloge était dans `shell.html`/`dist` mais manquait dans `src/index.html`

### Corrigé — Fuseau horaire (TZ) effectif sur Core / Admin / Agent

- Cause : `TZ=Europe/Paris` était injecté mais ineffectif (Core `scratch` sans zoneinfo ; Admin/Agent Alpine sans `tzdata`)
- Fix : embed `time/tzdata` dans le binaire ; `apk add tzdata` sur Admin/Agent ; `TZ` ajouté au chart Helm (`global.timezone`)
- Horloge dans la topbar admin (fuseau serveur via `/api/v1/health` → `timezone` / `time`)
- Timeline Prism : buckets SQLite en heure locale (`strftime(..., 'localtime')`)
- `fmtDate` UI aligne l'affichage sur le TZ serveur

### Changé — Chemin GeoIP MaxMind sur le volume Core

- Défaut UI : `/etc/goproxify/geoip/GeoLite2-Country.mmdb` (au lieu de `/usr/share/GeoIP/...`)
- Le Core crée `/etc/goproxify/geoip` au démarrage et **télécharge** `GeoLite2-Country.mmdb` s'il est absent
- Config Core `geoip.db_url` / `geoip.db_path` / `geoip.auto_download` (défaut miroir P3TERX) — surcharge env `GPX_GEOIP_*`
- Les snippets / configs existants avec l'ancien `db_path` restent inchangés : mettre à jour le champ « Base MaxMind » puis ré-enregistrer

### Fait — Phase B : unification headers runtime

- Canal unique `cfg.headers` (+ `headers.custom`) pour natifs et avancés (CSP, Referrer-Policy, …)
- `applySecHeaders` / édition proxy écrivent dans `headers` ; legacy `response_add_header` migré à la lecture/sauvegarde
- Runtime inchangé : `SecurityHeaders` applique déjà `Custom`
- Merge snippets `headers` : custom fusionné (inline prime), typés complétés si vides

### Amélioré — Page Core « IP / GeoIP / Bot » : sélecteur pays unifié

- Section « Pays bloqués (GeoIP) » : même UI que la modale Sécurité (mode, base MaxMind, regroupements, recherche, liste)
- Sélecteur GeoIP factorisé avec racine DOM configurable (`psec-geo-picker` / `core-geo-picker`)
- Bouton **Enregistrer GeoIP** : crée ou met à jour le snippet `geo_ip` correspondant

### Corrigé — Score « Filtrage IP » : GeoIP + snippets

- Récap / `computeProxyHeaderScore` : le contrôle « Filtrage IP » (+5) compte aussi GeoIP (`countries` / `blocked_countries`) et les snippets déjà résolus (`ip_filter` / `geo_ip`)
- Miroir Go `ComputeHeaderScore` + normalisation `blocked_countries` → `countries` à la résolution de snippets

### Corrigé — Catalogue pays GeoIP non chargé dans l'UI Admin

- L'Admin sert `src/` (go:embed), pas `dist/` : `countries-geo.js` n'était pas référencé dans `src/index.html`
- Ajout du `<script src="js/data/countries-geo.js">` avant `pages-all.js` — la liste pays / regroupements s'affiche dans Paramètres → Filtrage IP → GeoIP

### Amélioré — Phase A : Sécurité proxy centralisée dans la modale Trafic

- Modale Sécurité : Récap aligné sur `ComputeHeaderScore` (TLS, HSTS, XFO, Server, rate limit, WAF, bot, IP filter, auth)
- Paramètres enrichis : headers natifs, rate limiting (`rps`/`burst`), filtrage IP (mode + CIDRs)
- Page Sécurité : grille « Posture par proxy » en lecture ; Détails/Corriger ouvrent la modale proxy
- Alertes bouclier Trafic alignées sur le même score

### Clarifié — Domaines : Tokens = droits, Core d'entrée = routage (Admin `0.2.11`)

- « Core responsable » renommé **Core d'entrée** (routage / délégation / ACME) — ne confère pas les droits
- Notices UI Domaines + Tokens : périmètres token = droits de réception routes/certs
- Sélecteur Domaines : uniquement tokens Core actifs (endpoint ou nœud online), sans declared/pending/fantômes
- Alertes douces si scope domaine manquant sur le token du Core d'entrée
- `resolveCoreRef` : plus d'auto-création de token fantôme ; token Core actif requis

### Corrigé — Core auto sans token visible : affectation domaine possible (Admin `0.2.10`)

- Domaines: la sélection des Cores inclut aussi les Cores détectés dans `/nodes` même sans token actif
- API Domaines: un `core_id` fourni en `node_name` est résolu, et un token Core est auto-créé si absent
- Permet de définir un domaine/périmètre pour un Core auto-connecté sans passage manuel préalable par la page Tokens

### Amélioré — Assistant Agent : stack unifié Core+Agent (Admin `0.2.9`)

- Scénario **Agent seul** avec Core existant : docker-compose / Portainer / CLI générés incluent **Core + Agent** (comme le scénario full)
- Réutilise la config déclarée du Core si disponible ; sinon valeurs par défaut du nœud
- Agent branché sur `http://<core>:8000` dans le même réseau Docker

### Corrigé — Assistant Infrastructure Core+Agent (Admin `0.2.8`)

- Scénario **full** : hôte joignable requis + création du **token Core** (`node_endpoint`) + affichage du token à la fin
- Notice corrigée (plus de fausse « acceptation Infrastructure » pour le Core)
- `GPX_PAIRING_SECRET` = secret Admin uniquement (plus de secret aléatoire divergent)
- Page Infrastructure : section **En attente d'acceptation** (Accepter / Rejeter)
- Domaines du wizard → `token_scopes` domaine sur le token créé

### Corrigé — Sans périmètre = tous les domaines (Admin `0.2.7`)

- Ne plus préférer / basculer vers un token jumeau qui a des scopes : admin sans `token_scopes` retrouve l'accès global

### Corrigé — Périmètres Core réellement appliqués (Admin `0.2.6`)

- Résolution token : préfère l'UUID avec endpoint (évite doublons `node_name` / `id=node_name`)
- Push WS / full_sync / certs : scopes lus sur le token de l'entrée WS (`LoadCoreAccess`)
- `Register` : un seul client par `node_name` ; refuse `id=node_name` (fail-open historique `ConnectFromEnv`)
- Wildcards DNS à un seul label (`*.example.com` ≠ `app.dev.example.com`) — aligné `ByHost`
- UI Trafic Core : résout l'UUID token avant `?core=`
- **Sans périmètre domaine** (scopes vides) + admin → **tous les domaines** (pas de bascule vers un jumeau scopé)

### Corrigé — Périmètres Core / proxies (Admin)

- `GET /api/v1/proxies?core=` filtre la liste selon les `token_scopes` du Core (même règle que le push runtime)
- Ajout / retrait d'un périmètre token → re-push immédiat des routes et certificats aux Cores
- Matching domaine RBAC : aliases + `HostCoveredByPattern` (aligné délégation)
- Page Trafic mode Core : n'affiche plus tous les proxies globaux
- `build.sh` réinclut `js/pages/trafic.js` dans `dist/index.html`

### Ajouté — Tokens API utilisateur (PAT)

**Admin**
- Table `user_api_tokens` / `user_api_token_scopes` — PAT `gpx_pat_*` hashés (SHA-256), aperçu UI, expiration optionnelle, révocation immédiate
- API self-service (session JWT) : `GET/POST /api/v1/me/tokens`, `DELETE /api/v1/me/tokens/:id`, `GET /api/v1/me/tokens/scopes`
- Middleware `RequireAuth` (JWT ou PAT) sur l'API REST ; `EnforcePATScope` borne les appels PAT aux scopes ressource
- Middleware `RequirePAT` sur `/mcp` — le JWT de session UI n'est plus accepté pour le MCP
- Scopes catalogue v1 partagés API + MCP (`proxies:read|write|delete`, `nodes:read`, `users:read`, …) ; autorisation = scopes PAT ∩ droits courants du compte (rôle)
- Audit : acteur `userID via pat:<id>`

**Webapp**
- Page **Mes tokens API** (Paramètres + lien depuis Mon profil) — création avec sélection de scopes, affichage unique du secret, liste / révocation

**Documentation**
- `docs/mcp.md`, `docs/api_specs.md`, `docs/mcp-implementation.md` — auth PAT
- Plan produit : `docs/plans/2026-08-05-001-feat-user-api-tokens-plan.md`
- Landing : cartes Admin/Sécurité/Agent, stack MCP+PAT, liens docs, version `0.2.4` / Go `1.25`

*Versions actuelles (`versions.json`) : admin `0.2.12`, core `0.2.4`, agent `0.2.0`, webapp `0.2.5`, landing `0.1.0`.*

## [0.2.3-core] — 2026-08-05

### Corrigé — Délégation passthrough plus robuste (Core `0.2.3`)
- Force `tls_passthrough=true` sur les routes `deleg-*` wildcard (sauf backend http/https = terminate)
- La purge des conflits se base sur l'ID `deleg-*`, pas seulement sur le booléen
- Log `délégation appliquée` avec host / backend / tls_passthrough

## [0.2.2-core] — 2026-08-05

### Corrigé — Purge des proxies masqués par délégation (Core `0.2.2`)
- À l'application des `deleg-*` / full_sync / push routes, les proxies exacts locaux couverts par un wildcard `tls_passthrough` sont retirés
- Évite le 502 quand le Core responsable conserve encore `api.example.fr` alors qu'une délégation `*.example.fr` est active

## [0.2.4] — 2026-08-05

### Corrigé — Push certificats selon périmètres token (Admin `0.2.4`)
- Les certificats ne sont plus diffusés à tous les Cores
- Admin **sans** périmètre → reçoit tout (défaut)
- Admin **avec** périmètre `domain` → uniquement les certs couverts ; scope `core` → tout
- Aligné sur la sémantique RBAC des routes

## [0.2.3] — 2026-08-05

### Corrigé — Passthrough délégation vs proxy exact (Core `0.2.1`)
- Au SNI, une route wildcard `tls_passthrough` (délégation) est préférée même si un proxy exact local existe pour le même host
- Corrige le 502 quand le Core responsable terminait encore le TLS à cause d'un match exact

### Modifié — Admin `0.2.3`
- Log `routes poussées` avec `filtered_out` pour tracer l'exclusion des hosts délégués

## [0.2.2] — 2026-08-05

### Corrigé — Délégation de domaines (Admin `0.2.2`)
- Les proxies dont le host est couvert par un domaine délégué ne sont plus poussés au Core responsable
- Ils restent uniquement sur le Core cible (`delegated_to_core_id`), pour que le passthrough TLS ne soit plus court-circuité
- Appliqué sur `PushRoutes`, `full_sync`, `GET /internal/v1/routes`, et à la sauvegarde/suppression d'un domaine

### Corrigé — Pages d'erreur par défaut (Core)
- Remplacement de l'affichage du nom/version du Core par un ID de log cliquable (`X-Request-ID`) vers `/api/v1/logs`

### Modifié — Documentation de suivi
- `README.md` : ajout des liens vers `suivi/changelog.md` et `suivi/versioning.md` dans la section Documentation
- `suivi/roadmap.md` : ajout d'une section "Suivi documentaire" pour tracer les mises à jour des documents de référence
- `suivi/versioning.md` : clarification de la règle pour les changements "documentation only"

### Ajouté — Autonomie complète du Core

**Architecture Core-first**
- Démarrage cache-first : le Core charge son cache local en priorité, puis synchronise avec l'Admin en arrière-plan (plus aucun blocage au démarrage si l'Admin est injoignable)
- Auto-enregistrement du Core auprès de l'Admin au démarrage via `POST /internal/v1/cores/register` — remplit automatiquement `node_endpoint` dans la table tokens
- Le cache chiffré AES-256-GCM (`/etc/goproxify/core-cache.gpx`) contient désormais : routes, certificats TLS (cert + clé privée), snippets et fournisseurs d'authentification

**Snippets dans le Core**
- `SnippetStore` thread-safe avec remplacement atomique (`Replace`)
- Endpoint interne `POST /internal/v1/snippets` sur le Core
- Snippets persistés dans le cache chiffré
- Champ `SnippetIDs []string` dans `Route` pour référencer les snippets par ID

**Fournisseurs d'authentification dans le Core**
- `AuthProviderStore` thread-safe avec remplacement atomique (`Replace`)
- Endpoint interne `POST /internal/v1/auth-providers` sur le Core
- Fournisseurs persistés dans le cache chiffré
- Champ `AuthProviderID string` dans `Route` pour référencer le fournisseur par ID

**Push Admin → Core amélioré**
- `DeleteRoute(ctx, id)` dans le pusher : suppression immédiate d'une route sur tous les Cores lors d'un DELETE proxy côté Admin
- `PushSnippets(ctx)` et `PushAuthProviders(ctx)` dans le pusher
- `PushAll(ctx)` : déclenche routes + snippets + fournisseurs en parallèle après enregistrement d'un Core
- Interface `RoutePusher` étendue avec `DeleteRoute`
- Sémantique Replace dans `handlePushRoutes` du Core (remplacement atomique total au lieu d'Upsert individuel)

**TLS cache**
- `CachedCert` (cert PEM + clé PEM) dans le `CertStore` du Core
- `AllPEMs()` pour export vers le cache chiffré — clés privées jamais en DB Admin

### Corrigé
- `navigator.clipboard.writeText` indisponible en contexte HTTP (non-HTTPS) : fallback `execCommand('copy')` dans `copyText()` (ERR-006)
- `DELETE /api/v1/proxies/ 405` causé par un ID proxy vide dans `deleteProxy()` : garde ajoutée
- DNS `network is unreachable` dans les conteneurs Core/Agent sous Portainer : `dns: 127.0.0.11` ajouté dans docker-compose.yml

### Ajouté — SSO & Authentification Étendue (Jalon 15)

**Nouveaux providers Core (middleware par route)**
- **GitHub OAuth2** (`provider: github`) — flow complet OAuth2, vérification org/team, cookie HMAC-SHA256
- **LDAP / Active Directory** (`provider: ldap`, `ldap_ad`) — Basic Auth → bind LDAP, LDAPS + STARTTLS, filtrage groupe DN/CN
- **SAML 2.0** (`provider: saml`) — SP mode via `crewjam/saml`, ACS handler, métadonnées IdP URL ou XML
- **Presets OIDC** : `google`, `microsoft`, `entra`, `auth0`, `okta`, `keycloak`, `zitadel`, `casdoor`, `dex` — IssuerURL pré-remplie, configurable
- Dispatch SSO unifié dans `sso.go` : tous les providers routés vers leur middleware

**Admin**
- Table `auth_providers` — CRUD fournisseurs SSO réutilisables entre proxies
- API `GET/POST /api/v1/auth-providers`, `GET/PUT/DELETE /api/v1/auth-providers/{id}`

**Dépendances**
- `github.com/crewjam/saml v0.5.1`

### Ajouté — Double Authentification (2FA/MFA — Jalon 14)

**Méthodes MFA**
- TOTP (RFC 6238, pur Go), Email OTP, SMS OTP (Twilio/OVH/Vonage), Push ntfy/Gotify, WebAuthn/Passkey, Codes de secours, Appareils de confiance
- Flow JWT intermédiaire `mfa_pending` (5 min) → challenge → JWT complet

### Ajouté — Initialisation
- Structure initiale du projet (arborescence, Docker Compose, documentation)
- Schéma canonique de configuration JSON v4.3
- Roadmap, changelog, dictionnaire d'erreurs

---

## [0.2.1] — 2026-07-31

### Modifié — Refonte RBAC & Page Trafic unifiée

**RBAC (Admin `0.2.1`)**
- Refonte complète de `internal/admin/rbac/rbac.go` : méthodes `canReadProxy`, `canWriteProxy`, `canDeleteProxy` centralisées, vérification par périmètre d'équipe (domain glob / server glob / proxy ID)
- `GET /api/v1/me` retourne le rôle RBAC et les scopes d'équipe — utilisé par l'UI pour initialiser `state.role`
- Middleware proxy : filtre RBAC appliqué sur `list`, `get`, `create`, `update`, `delete`

**Page Trafic (Webapp `0.2.1`)**
- `renderTraficPage({mode})` unique pour Admin et Core — le design Admin fait référence, Core hérite sans duplication
- Toolbar : recherche, compteur, Grouper (aucun/statut/type/source/domaine), Trier (nom A→Z/Z→A/récent/ancien/actif), Import, CSV, vue tuiles + sélecteur colonnes (2-5), vue table
- Filtres Statut (Tous/Actif/Inactif), Type (Tous/HTTP/HTTPS/TCP/UDP/TCP+UDP), Source (Tous/Docker/K8s/Managed)
- Vue tuiles par défaut avec groupBy et sortBy
- Adaptations mode Core : bandeau statut (nom/CPU/mém/raccourcis), pas de chips Core sur les cartes, pas de bouton "Nouveau flux"
- Extraction dans `js/pages/trafic.js` (module dédié, chargé après `pages-all.js`)
- État persistant survit à la navigation (`window._tv/_tc/_tg/_ts/_tf`)

---

<!-- Template pour les prochaines entrées :

## [X.Y.Z] — YYYY-MM-DD

### Ajouté
- ...

### Modifié
- ...

### Corrigé
- ...

### Supprimé
- ...

-->

### Corrigé (suite)

- **Diff config proxy** : double préfixe `/api/v1` dans l'appel JS → 404 systématique (corrigé)
- **Diff config proxy** : `revisionsDiff` n'essayait que `targets[0]` — proxy non trouvé si sur un autre Core ; utilise désormais `fetchProd()` qui parcourt tous les Cores
