# Changelog Goproxify

Toutes les modifications notables sont documentées ici.
Format : [Semantic Versioning](https://semver.org/) — `MAJOR.MINOR.PATCH`

---

## [Unreleased]

### Ajouté — Wizard architecture + tickets bootstrap (Admin `0.2.35`)

- Toile d’architecture (hôtes + palette) : Core, Agent, Admin, Access-sur-Core, Portainer/K8s, multi-Core / groupe HA
- Packs install par hôte + tickets QR / lien `/i/{token}` + one-liner `curl|bash` (`POST /api/v1/bootstrap-tickets`)
- Auto-accept des nœuds déclarés issus du wizard ; reprise des nœuds existants ; région / autoscale / domaines-TLS
- Ancien wizard Infrastructure scénarisé retiré (entrée « + Ajouter » = toile)
- Landing : présentation de l’assistant d’architecture
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
- Publication GitHub/GHCR : reste volontairement **privée** pour l’instant (passage Public différé)
- `DISCLAIMER.md` : préversion 0.x, refus de garantie et de responsabilité d’usage
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
- Backlog produit réduit à l’hygiène CI optionnelle ; dette technique WS/P95 isolée en bas de `suivi/roadmap.md`

### Corrigé — Générateur Labels Docker/K8s

- Champ « URL backend » remplacé par « Port » (`goproxify.port`) — l’Agent construit l’URL depuis l’IP du conteneur / ClusterIP
- Snippets : sélection par toggles depuis la bibliothèque Admin (plus de saisie libre d’IDs) ; résolution Core par nom ou ID
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

- Bouton **Corréler** remplacé par une icône (délégation d’événements) : corrigé le `onclick` cassé par les guillemets JSON
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
- Membership d’équipe sans rôle : héritage intégral des grants de l’équipe
- Migration B' : équipes mixtes operator/viewer scindées en équipe write + `… (lecture)`
- UI Utilisateurs : éditeur de grants personnels et d’équipe

### Amélioré — Clarification rôle global vs droits d’équipe (UI Utilisateurs)

- Libellés distincts : niveau de compte (plafond) vs droit d’équipe (« Peut modifier » / « Lecture seule »)
- Aide conditionnelle selon admin / operator / viewer ; empty state corrigé (sans équipe → aucun proxy pour operator/viewer)

### Amélioré — Profils IP persistés sur le volume Core

- Snapshot runtime écrit sous `/etc/goproxify/ip-profiles/profiles.json` à chaque push / full_sync
- Chargé au démarrage Core (survit à un redémarrage sans Admin)
- Config + refresh feeds restent dans l’Admin (SQLite) ; surcharge chemin : `GPX_IP_PROFILES_PATH`

### Amélioré — Formats d’import unifiés + onglets Import / Restore

- `CONFIG_FORMATS` / `CONFIG_FORMAT_SVG` centralisés dans `shared/config-formats.js` (Trafic, Import, onboarding, proxy-form)
- Helper `configFormatPickerHtml` / `configFormatMeta` pour un rendu unique des cartes format
- Onglets Import / Restore : navigation en cartes (icône + titre + description) à la place de `tab-btn` sans styles

### Corrigé — Bans actifs vides + icônes Importer (Trafic)

- Cause bans : `security.Ban.ID` était `int64` alors que la table utilise des UUID `TEXT` → Scan échouait en silence
- UI : `deleteBan` quote correctement l’id string
- Importer Trafic : cartes format avec `CONFIG_FORMAT_SVG` (icônes manquantes à l’étape 1)

### Supprimé — Pipeline UI `build.sh` / `dist/`

- L’Admin sert uniquement `src/` via `go:embed` : suppression de `build.sh`, `dist/index.html`, `shell.html`
- Dockerfile admin : plus de copie vers `/etc/goproxify/storage/webapp/`
- Découpage `pages-all.js` en modules dédiés (proxy, infra, onboarding, sécurité, core, logs, prism)

### Corrigé — Horloge admin absente (embed `src/`)

- L’Admin sert l’UI via `go:embed src`, pas `dist/` : l’horloge était dans `shell.html`/`dist` mais manquait dans `src/index.html`

### Corrigé — Fuseau horaire (TZ) effectif sur Core / Admin / Agent

- Cause : `TZ=Europe/Paris` était injecté mais ineffectif (Core `scratch` sans zoneinfo ; Admin/Agent Alpine sans `tzdata`)
- Fix : embed `time/tzdata` dans le binaire ; `apk add tzdata` sur Admin/Agent ; `TZ` ajouté au chart Helm (`global.timezone`)
- Horloge dans la topbar admin (fuseau serveur via `/api/v1/health` → `timezone` / `time`)
- Timeline Prism : buckets SQLite en heure locale (`strftime(..., 'localtime')`)
- `fmtDate` UI aligne l’affichage sur le TZ serveur

### Changé — Chemin GeoIP MaxMind sur le volume Core

- Défaut UI : `/etc/goproxify/geoip/GeoLite2-Country.mmdb` (au lieu de `/usr/share/GeoIP/...`)
- Le Core crée `/etc/goproxify/geoip` au démarrage et **télécharge** `GeoLite2-Country.mmdb` s’il est absent
- Config Core `geoip.db_url` / `geoip.db_path` / `geoip.auto_download` (défaut miroir P3TERX) — surcharge env `GPX_GEOIP_*`
- Les snippets / configs existants avec l’ancien `db_path` restent inchangés : mettre à jour le champ « Base MaxMind » puis ré-enregistrer

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

### Corrigé — Catalogue pays GeoIP non chargé dans l’UI Admin

- L’Admin sert `src/` (go:embed), pas `dist/` : `countries-geo.js` n’était pas référencé dans `src/index.html`
- Ajout du `<script src="js/data/countries-geo.js">` avant `pages-all.js` — la liste pays / regroupements s’affiche dans Paramètres → Filtrage IP → GeoIP

### Amélioré — Phase A : Sécurité proxy centralisée dans la modale Trafic

- Modale Sécurité : Récap aligné sur `ComputeHeaderScore` (TLS, HSTS, XFO, Server, rate limit, WAF, bot, IP filter, auth)
- Paramètres enrichis : headers natifs, rate limiting (`rps`/`burst`), filtrage IP (mode + CIDRs)
- Page Sécurité : grille « Posture par proxy » en lecture ; Détails/Corriger ouvrent la modale proxy
- Alertes bouclier Trafic alignées sur le même score

### Clarifié — Domaines : Tokens = droits, Core d’entrée = routage (Admin `0.2.11`)

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

- Ne plus préférer / basculer vers un token jumeau qui a des scopes : admin sans `token_scopes` retrouve l’accès global

### Corrigé — Périmètres Core réellement appliqués (Admin `0.2.6`)

- Résolution token : préfère l’UUID avec endpoint (évite doublons `node_name` / `id=node_name`)
- Push WS / full_sync / certs : scopes lus sur le token de l’entrée WS (`LoadCoreAccess`)
- `Register` : un seul client par `node_name` ; refuse `id=node_name` (fail-open historique `ConnectFromEnv`)
- Wildcards DNS à un seul label (`*.example.com` ≠ `app.dev.example.com`) — aligné `ByHost`
- UI Trafic Core : résout l’UUID token avant `?core=`
- **Sans périmètre domaine** (scopes vides) + admin → **tous les domaines** (pas de bascule vers un jumeau scopé)

### Corrigé — Périmètres Core / proxies (Admin)

- `GET /api/v1/proxies?core=` filtre la liste selon les `token_scopes` du Core (même règle que le push runtime)
- Ajout / retrait d’un périmètre token → re-push immédiat des routes et certificats aux Cores
- Matching domaine RBAC : aliases + `HostCoveredByPattern` (aligné délégation)
- Page Trafic mode Core : n’affiche plus tous les proxies globaux
- `build.sh` réinclut `js/pages/trafic.js` dans `dist/index.html`

### Ajouté — Tokens API utilisateur (PAT)

**Admin**
- Table `user_api_tokens` / `user_api_token_scopes` — PAT `gpx_pat_*` hashés (SHA-256), aperçu UI, expiration optionnelle, révocation immédiate
- API self-service (session JWT) : `GET/POST /api/v1/me/tokens`, `DELETE /api/v1/me/tokens/:id`, `GET /api/v1/me/tokens/scopes`
- Middleware `RequireAuth` (JWT ou PAT) sur l’API REST ; `EnforcePATScope` borne les appels PAT aux scopes ressource
- Middleware `RequirePAT` sur `/mcp` — le JWT de session UI n’est plus accepté pour le MCP
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
