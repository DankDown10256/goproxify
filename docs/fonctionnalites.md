# Fonctionnalités GoProxify

## 1. Vue d'ensemble

GoProxify est un **reverse proxy distribué et sécurisé**, compilé en un **binaire Go unique** sans dépendance runtime. La personnalité de l'instance est déterminée au démarrage par la sous-commande CLI ou la variable d'environnement `GOPROXIFY_MODE`.

Le produit se décline en **trois personnalités complémentaires** :

| Composant | Rôle | Persistance | Ports exposés |
|---|---|---|---|
| **Core** | Data Plane — moteur de routage haute performance + hub WS (+ Access optionnel) | RAM + cache chiffré | `:80`, `:443` TCP+UDP, `:8000` interne + WS ; Access `:2222` / `:8444` si activé |
| **Administration** | Control Plane — UI, API, MCP, alerting, Access | SQLite | `:9443` |
| **Agent** | Discovery & Telemetry — sidecar Docker | Volatile | `:9191` Prometheus, `:51820` WireGuard (pas de port entrant pour le plan de contrôle) |

---

## 2. Core — Data Plane

### Protocoles supportés

| Protocole | Détails |
|---|---|
| HTTP/1.1 | Reverse proxy complet avec gestion des en-têtes |
| HTTP/2 | Multiplexage de flux, négociation ALPN |
| HTTP/3 QUIC | Transport UDP, négociation `Alt-Svc` |
| WebSocket | Upgrade HTTP → WS géré nativement |
| gRPC | Proxy transparent sur HTTP/2 |
| TCP L4 | Stream pur : port local → host:port distant, SSL passthrough natif, load balancing L4 |
| UDP L4 | Tunnel pur, métriques bytes in/out |

### TLS

- **Terminaison TLS** : certificats poussés en RAM uniquement via `GetCertificate` — jamais écrits sur disque
- **SSL Passthrough SNI** : détection passive par lecture des 5 premiers octets du Client Hello (sans déchiffrement)
- **Négociation ALPN** : `h2` et `http/1.1`
- **mTLS client** : validation de certificats clients (Jalon 5)
- **Délégation inter-Cores** : un Core d'entrée peut transférer un domaine vers un autre Core — modes **Passthrough** (tunnel TLS brut) ou **Terminate** (TLS sur l'entrée + proxy HTTP(S) + `X-Forwarded-For`). Voir [docs/delegation.md](delegation.md).

### Autonomie sans Administration

Le Core peut fonctionner **de façon autonome** si l'Administration est temporairement injoignable :

- Sauvegarde automatique de la table de routage et des certificats dans un **cache local chiffré** (`/etc/goproxify/core-cache.gpx`)
- Déclenchement à chaque push reçu depuis l'Admin + intervalle configurable
- Au démarrage sans Administration joignable : chargement automatique depuis le cache
- **Reconnexion automatique** dès que l'Administration redevient disponible → mise à jour du cache
- Log explicite indiquant le mode de démarrage (live / cache local)

### Performance

- `sync.Map` pour la table de routage : mises à jour atomiques **sans interruption de connexion**
- `sync.Pool` de buffers réseau : stabilité P99 sous charge, pression GC réduite
- Compression Gzip configurable
- Cache proxy sur disque (prévu)

### Sécurité

| Fonctionnalité | Détails |
|---|---|
| Filtrage IP/CIDR | Profils intégrés : Cloudflare, Tor, Bogons, plages personnalisées |
| Géo-IP | Autorisation ou blocage par pays (MaxMind GeoLite2 ; auto-download au démarrage) |
| Rate limiting | Token bucket par IP ou utilisateur authentifié — champ `key_by` : `ip` (défaut), `jwt_sub`, `jwt_email`, `jwt_claim:<nom>` |
| Headers de sécurité HTTP | HSTS, X-Frame-Options, Content-Security-Policy, etc. |
| CORS | Origines, méthodes et en-têtes configurables |
| Masquage du fingerprint serveur | Suppression des en-têtes révélateurs (`Server`, `X-Powered-By`) |
| WAF | Moteur natif Go, 13 jeux de règles OWASP CRS-4, inspection requête **et réponse**, detect/block mode, règles custom hot-reload — voir [docs/security.md](security.md#waf-web-application-firewall) |
| Sentinel | Détection comportementale par IP : fenêtre glissante, ban immédiat sur signal, anti-DDoS global RPS — voir [docs/security.md](security.md#sentinel-moteur-de-détection-comportementale) |
| Fail2Ban natif Go | Bannissement automatique après N échecs, sans dépendance externe |
| CrowdSec | Bouncer LAPI stream → bans poussés au Core (403), compatible Docker |
| Moteur de règles automatiques | Conditions pilotées (CVE critique, pic de bans, moteur silencieux, taux d'erreur, IP récidiviste) → actions (désactiver proxy, bannir IP, alerte, mode strict) ; cooldown, dry-run, historique — voir [docs/security.md](security.md#moteur-de-règles-automatiques) |
| SSO | GitHub OAuth2, LDAP/Active Directory, SAML 2.0, OIDC (Google, Microsoft/Entra, Auth0, Okta, Keycloak, Zitadel, Casdoor, Dex, Authentik, Authelia) |
| JWT validation | JWKS (prévue) |

### Pipeline de transformation de requête

Chaque route peut déclarer un bloc `RequestTransform` (UI Admin → proxy → onglet **Transform**) :

| Champ | Description |
|---|---|
| `rewrite_from` / `rewrite_to` | Réécriture de préfixe URL (ex : `/api/v1` → `/v1`) |
| `add_request_headers` | En-têtes à injecter dans la requête upstream |
| `remove_request_headers` | En-têtes à supprimer de la requête upstream |
| `add_response_headers` | En-têtes à injecter dans la réponse cliente |
| `remove_response_headers` | En-têtes à supprimer de la réponse cliente |

Le middleware s'applique en premier dans la chaîne, avant le WAF et le routage upstream. Hot-reload sans redémarrage du Core.

### Tunnel L4 mTLS Core↔Core

Le package `internal/core/tunnel` fournit un canal TCP chiffré persistant entre deux Cores (trafic L4 inter-datacenter, relay de backends inaccessibles depuis le Core d'entrée).

**Architecture :**
```
Core A (client)          Core B (serveur)
   │                          │
   ├─ mTLS TLS 1.3 ──────────▶│:9443
   │   CONNECT-like :          │
   │   "host:port\n"  ──────▶  │ dial TCP target
   │   ◀── "OK\n"              │ pipe bidirectionnel
   │   [flux L4]     ◁────────▶│
```

- **Manager** (côté client) : pool de pairs `PeerConfig{Name, Addr, CACert, CertPEM, KeyPEM}`, reconnexion automatique, failover vers les autres pairs enregistrés
- **Serve** (côté serveur) : listener mTLS `RequireAndVerifyClientCert`, TLS 1.3 min, protocole CONNECT-like sur une ligne ASCII
- Utilisation : `Manager.Dial(peerName, targetAddr)` retourne un `net.Conn` prêt à l'emploi pour le proxy ou l'accès L4

### Résilience

- **Load balancing** : Round Robin, Weighted, **Adaptatif** (CPU×0.5 + mem×0.3 + IO disque×0.2 via métriques Agent WS)
- **Health checks actifs configurables** : `HealthCheckConfig` par route — `path`, `interval`, `timeout`, `healthy_threshold`, `unhealthy_threshold` ; `StartChecksFromRoutes` remplace l'appel global à intervalle fixe
- **Failover** : quarantaine courte + essai du backend suivant sur échec dial/proxy
- **Circuit Breaker** : thread-safe (mutex), `RecordSuccess`/`RecordFailure` appelés depuis le handler après chaque tentative ; isolation automatique des backends défaillants
- **Retry policy** avec backoff exponentiel configurable
- **Sticky sessions** par cookie
- **Timeouts serveur configurables** : `ReadTimeout`, `WriteTimeout`, `IdleTimeout`, `ReadHeaderTimeout` HTTP/QUIC — configurables depuis l'Admin (Sécurité > Paramètres serveur) et propagés aux Cores via WebSocket

### Observabilité

- **Access log JSON asynchrone** : IP client, domaine, méthode, code HTTP, durée, upstream, version HTTP
- **System log JSON structuré** pour tous les composants, avec rotation
- **Métriques Prometheus** exposées sur `/metrics` — instrumentation complète de tous les services : `gpx_core_*`, `gpx_backend_*`, `gpx_backend_up`, `gpx_peer_sync_duration_seconds`, `gpx_waf_profiles_active`, `gpx_portal_sessions_active`, `gpx_pipeline_*`, `gpx_tls_*`, `gpx_auth_*`, `gpx_ratelimit_*`, `gpx_traffic_*`, `gpx_routing_*`, `gpx_f2b_*`, `gpx_crowdsec_*`, `gpx_rulesengine_*`, `gpx_vulnscan_*`, `gpx_admin_http_*` — voir `docs/services.md`
- **Tracing OpenTelemetry** (prévu)
- **Audit log JSON** : traçabilité de toutes les opérations

### GoProxify Access (portail SSH / shell)

Portail opérateur servi par le **Core** (pas l'Admin) :

- **Dual façade** : terminal web (xterm.js) + client `ssh` standard avec jeton UUID (`ssh -p 2222 <uuid>@<core>`)
- **Cibles** : VM / bare-metal (`sshd`) ou conteneurs Docker (`docker exec` via Agent)
- **Coffre** : login SSH + mot de passe ou clé privée, chiffrés sur le Core (jamais exposés à l'Admin)
- **2FA** optionnelle (TOTP / OTP email) ; sessions TTL / one-shot / révocation ; audit métadonnées
- Config & catalogue poussés depuis l'Admin (voir §3)

---

## 3. Administration — Control Plane

### Premier démarrage

- Détection automatique de l'absence de base SQLite au premier lancement
- **Écran d'initialisation guidé** : saisie de l'email et du mot de passe administrateur
- Génération de la clé ECDSA P-256 pour la signature des tokens JWT

### API REST

Endpoints sur `:9443` — deux familles :

- `/api/v1/` — authentification session JWT (administrateurs humains) **ou** PAT `gpx_pat_*`
- `/internal/v1/` — authentification par token d'appairage (Cores et Agents, rétrocompat)

| Ressource | Opérations |
|---|---|
| Proxies (HTTP, TCP, UDP) | CRUD complet + push immédiat vers le(s) Core(s) |
| Utilisateurs | Création, modification, suppression, réinitialisation mot de passe |
| Équipes | Organisation des accès par scope |
| Tokens d'appairage | Génération, liste, révocation (`gpx_core_*`, `gpx_join_*`) |
| Tokens API utilisateur (PAT) | Self-service `/api/v1/me/tokens` — scopes ressource, expiration optionnelle |
| Snippets | Profils réutilisables : IP, TLS, CORS, rate-limit, auth providers, DNS providers |
| Nœuds | Enregistrement, état du cluster, accept/reject pending |
| Agents | Liste, approbation / révocation (workflow pending → approved) |
| Declared / bootstrap | Nœuds déclarés wizard ; tickets QR `/i/{token}` + `curl|bash` |
| Domaines | Apex / wildcards, Core d'entrée, ACME DNS, **délégation** Passthrough ou Terminate vers un autre Core |
| Sécurité | Bans, menaces CrowdSec, CVE, Fail2Ban, overview |
| Access | Catalogue destinations, users invite SMTP, templates HTML, options portail par Core, audit |

### Serveur MCP

Endpoint `https://<admin>:9443/mcp` — protocole MCP `2025-03-26`, JSON-RPC 2.0 + SSE.

- **Auth :** PAT uniquement (`Authorization: Bearer gpx_pat_…`) — le JWT de session UI est refusé
- **Scopes :** chaque outil exige un scope (`proxies:read|write|delete`, `nodes:read|write`, `audit:read` pour la sécurité, `portal:read|write` pour Access, …) ∩ droits courants du compte
- **Lecture :** proxies, nœuds, agents, declared-nodes, alertes, métriques, backups, users, snippets, domaines, certs, logs, teams, audit, bans / menaces / CVE, alert channels/rules, auth providers, IP profiles, Access (config, catalogue, users, templates, audit)
- **Écriture :** `create_proxy`, `update_proxy`, `set_proxy_enabled`, `delete_proxy`, `approve_agent`, `revoke_agent`, `create_declared_node`, `create_bootstrap_ticket`, `accept_node` / `reject_node`, `create_security_ban`, `delete_security_ban`, `create_alert_channel`, `delete_alert_channel`, `create_alert_rule`, `delete_alert_rule`, `create_auth_provider`, `delete_auth_provider`, `create_ip_profile`, `delete_ip_profile`, `create_snippet`, `delete_snippet`, `create_domain`, `renew_domain`, `obtain_cert`, outils Access (`update_portal_*`, `invite_portal_user`, `push_portal`, templates…)
- Documentation : [docs/mcp.md](mcp.md)

### Wizard architecture

L’entrée **Infrastructure → + Ajouter** ouvre une **toile d’architecture** (hôtes + palette) : placement Core / Agent / Admin, options Access / Portainer / K8s, multi-Core et groupe HA. Pour chaque hôte, packs install collables + ticket bootstrap (QR / lien `/i/{token}` / `curl|bash`) ancré au Core. Les nœuds déclarés depuis la toile peuvent être **auto-acceptés** à la connexion. Voir le plan `docs/plans/2026-08-09-001-feat-architecture-wizard-qr-plan.md`.

### Délégation multi-Core

Un domaine peut être **délégué** : le Core d'entrée (DNS / IP publique) transfère le trafic vers un Core cible.

| Mode | Comportement | IP client sur le Core cible |
|---|---|---|
| **Passthrough** | Tunnel TLS brut (SNI) | IP du Core d'entrée |
| **Terminate** | TLS terminé à l'entrée + proxy HTTP(S) + `X-Forwarded-For` | IP publique (si vue par l'entrée) |

Documentation détaillée : [delegation.md](delegation.md).

### Plan de contrôle WebSocket

L'Administration maintient une **connexion WS persistante** vers chaque Core enregistré (Admin→Core). Cette connexion remplace les appels HTTP push vers `/internal/v1/*` :

- **Reconnexion automatique** : backoff exponentiel 1 s → 60 s + jitter
- **Full-sync à la reconnexion** : état complet renvoyé automatiquement
- **Queue de messages** : les messages émis pendant une déconnexion sont mis en attente et livrés à la reconnexion
- **Propagation immédiate** : tout changement de config est envoyé en temps réel au Core concerné

### Approbation des Agents

Les Agents qui se connectent pour la première fois via `JOIN_TOKEN` apparaissent en statut `pending`. L'opérateur approuve via l'UI ou l'API (`POST /api/v1/agents/:id/approve`). Le Core envoie immédiatement le premier `agent_hmac` via WS.

### Gestion TLS / ACME DNS-01

- Émission de **certificats wildcard Let's Encrypt** via le challenge DNS-01
- Fournisseurs DNS supportés : **OVH, Cloudflare, Gandi, Route53, Hetzner**
- Renouvellement automatique 30 jours avant expiration
- Push des certificats décodés au Core en RAM uniquement (jamais sur disque côté Core)

### Certificate Hub (v0.8)

Suite de fonctionnalités autour du cycle de vie des certificats TLS.

**Monitoring ACME**
- Dashboard `/acme-monitor` : statut par cert (`ok` / `warning ≤30j` / `critical ≤7j` / `expired`), KPIs globaux, bouton de renouvellement inline
- Alertes automatiques : `cert_expiring_soon` (warning ≤30j, critical ≤7j) émises vers le moteur d'alertes existant

**Import de certificats externes**
- `POST /api/v1/certs/import` : upload PEM + clé privée — domaine extrait automatiquement du SAN/CN, upsert en DB, push temps-réel aux Cores
- Interface modale dans la page `acme-monitor`

**Deploy Hub**
- **Deploy targets** : webhook (POST HMAC-SHA256 signé) ou `ssh_exec` (script exécuté sur la machine cible avec `GPX_CERT_PEM / GPX_KEY_PEM / GPX_DOMAIN`)
- Déclenchement automatique à chaque renouvellement ACME + déclenchement manuel
- Historique d'audit par target (`cert_deploy_history`)
- Alerte `cert_deploy_failed` en cas d'échec

**Pull tokens**
- Tokens sécurisés (HMAC-SHA256, TTL, max_uses) pour téléchargement en pull via `curl`
- 7 formats de sortie : `pem`, `key`, `fullchain`, `der`, `der_key`, `pkcs12` (password), `json`
- Endpoint public `GET /api/v1/cert-bundle?token=…&format=…`

### Alerting granulaire

Modèle inspiré d'Alertmanager : chaque règle définit indépendamment son scope, ses déclencheurs et ses canaux. Un même événement peut notifier plusieurs équipes sur des canaux différents.

**Scope d'une règle** :
- Node(s) ciblé(s)
- Pattern de domaine (glob : `infra.*.fr`, `*.prod.*`)
- Équipe(s)
- Composant (`core` / `agent` / `admin`)
- Sévérité minimale (`info` / `warning` / `critical`)

**Déclencheurs configurables** :
- Node Core/Agent hors ligne
- Certificat expirant dans < N jours
- CVE détectée sur un backend
  - Le scanner HTTP refuse par défaut les cibles privées (RFC1918/ULA), localhost et metadata cloud (anti-SSRF). Pour scanner des backends Docker/LAN : `GPX_VULNSCAN_ALLOW_PRIVATE=true` sur l’Admin, ou via le toggle dans l’UI Admin (Sécurité > Scanner CVE, accès administrateurs uniquement).
- Nouveau ban Fail2Ban (seuil : N bans/heure)
- Décision CrowdSec critique
- Modification de configuration sensible
- Échec de sauvegarde planifiée
- Taux d'erreurs HTTP > seuil sur un proxy
- Latence P95 > seuil sur un proxy
- N tentatives de connexion admin échouées

**Qualité de service** : anti-spam par rate limiting par déclencheur, regroupement d'alertes similaires (cooldown configurable).

### Sauvegardes planifiées

- **Core** : snapshot de la table de routage (JSON), versioning par proxy, historique navigable, retour arrière par proxy
- **Administration** : dump JSON (utilisateurs, équipes, métadonnées tokens sans secrets, snippets) ; secrets rédigés ; chiffrement AES-GCM optionnel via `GPX_BACKUP_KEY`
- Planification **cron configurable**, rétention configurable (nombre de snapshots)
- Restauration avec prévisualisation des différences avant application
- CLI : `goproxify backup create/list/restore`

### Import de configurations tierces

Détection automatique du format source. Deux modes : coller le contenu ou importer un/plusieurs fichiers. Prévisualisation avant validation, import partiel possible.

Formats supportés : nginx, HAProxy, Traefik YAML, Traefik TOML, Traefik Labels, Caddy, Zoraxy, BunkerWeb, CSV, JSON natif GoProxify.

### Mise à jour coordonnée du cluster

- Détection des incohérences de versions entre nœuds (via heartbeat)
- Alerte si des Cores ou Agents tournent sur des versions différentes
- Déclenchement depuis l'UI (par nœud ou tout le cluster) ou via CLI
- Mise à jour progressive configurable (un nœud à la fois, validation entre chaque)
- Rollback cluster orchestré depuis l'Administration

### Interface Web

- Dashboard : état du cluster, métriques temps réel
- Vue liste unifiée des proxies (HTTP/HTTPS + TCP + UDP) — labels Docker grisés en lecture seule
- Formulaire création/édition adaptatif selon le type de proxy
- Générateur de labels Docker Compose interactif (HTTP, TCP, UDP)
- Gestion certificats TLS, snippets, tokens, utilisateurs, équipes
- Intégration : Prism (analyse trafic), Dashboard Sécurité, Sauvegardes, Import
- **Logs** : vue agrégée (access + system + audit), filtres, pagination, mode live via WebSocket
- **Prism** : KPIs, courbes temporelles, carte GeoIP, codes HTTP, top IPs/chemins/référents, exports CSV/JSON/HTML/PDF

---

## 4. Agent — Discovery & Telemetry

### Découverte Docker

- Écoute des événements Docker via socket Unix (`/var/run/docker.sock`, monté en lecture seule)
- Détection des labels `goproxify.*` sur les conteneurs au démarrage et en temps réel (start/stop/die)
- Connexion **à chaud** du Core au réseau bridge Docker privé de l'application (les apps n'exposent aucun port sur l'hôte)
- Transmission de la configuration réseau à l'Administration (token validé)
- Proxies découverts marqués `source: "label"` → lecture seule dans l'UI

### Labels Docker supportés

> Référence complète : [docs/labels.md](labels.md)

Exemples essentiels :

```yaml
goproxify.enable: "true"
goproxify.host: "app.example.fr"
goproxify.port: "3000"
goproxify.tls: "true"
goproxify.waf: "block"
goproxify.sentinel.whitelist: "10.0.0.0/8"
goproxify.canary: "true"
goproxify.canary.weight: "10"
```

### Découverte Kubernetes

Symétriquement au mode Docker, l'Agent peut découvrir les ressources Kubernetes annotées :

- Scrute les ressources `Ingress` et `Service` portant les annotations `goproxify.*`
- Même sémantique d'annotations que les labels Docker (`goproxify.enable`, `goproxify.host`, `goproxify.port`, etc.)
- Proxies créés en lecture seule dans l'UI (source `k8s`)
- Nécessite un `ServiceAccount` avec accès `get/watch/list` sur `ingresses` et `services`
- Compatible avec les déploiements Kubernetes multi-namespaces ; namespace ciblé configurable dans `agent.json`

```json
{
  "kubernetes": {
    "enabled": true,
    "kubeconfig": "/etc/goproxify/kubeconfig",
    "namespaces": ["production", "staging"]
  }
}
```

### Auto-scaling horizontal

- Déclencheurs configurables : CPU conteneur (télémétrie Agent) et/ou taux de requêtes / latence P95 (métriques Core)
- Décision coordonnée par l'Administration (règles min/max instances)
- Création/suppression d'instances via `docker compose up --scale` ou `docker run`
- Ajout à chaud dans la table de routage du Core sans interruption
- Compatible load balancing resource-weighted adaptatif
- Cooldown configurable entre deux décisions (anti-flapping)

### Health escalation

Logique de récupération progressive pour les conteneurs `unhealthy` :

1. **Restart simple** (`docker restart`)
2. **Recreate** si toujours unhealthy après délai configurable (`docker rm` + `docker run`)
3. **Rollback** vers l'image précédente
4. **Quarantaine** : retrait du pool de load balancing + alerte opérateur

Délais et seuils configurables par conteneur via labels `goproxify.healthcheck.*`.

### Gestion du cycle de vie des images

- Détection de mises à jour disponibles (comparaison digest local vs registre)
- Stratégies par conteneur : `auto`, `scheduled` (cron), `manual`
- Pull + recréation sans interruption si plusieurs réplicas
- Rollback automatique si le conteneur ne repasse pas `healthy` dans le délai configuré
- Prune optionnel après mise à jour réussie

### Log forwarding

- Collecte des logs des conteneurs labellisés (`docker logs --follow`) en opt-in (`goproxify.logs: "true"`)
- Streaming en temps réel vers l'Administration
- Corrélation avec les logs Core/Agent/Admin dans la vue Logs
- Rotation et rétention configurables par conteneur

### Télémétrie système

- Lecture de `/proc/stat` et `/proc/meminfo`
- Export Prometheus sur `:9191/metrics`
- Données utilisées par le load balancing adaptatif du Core (host + conteneurs via WS)

### Connectivité WS persistante

L'Agent maintient une **connexion WS persistante** vers le Core (Agent→Core). Cette connexion :

- **Remplace le heartbeat HTTP 30 s** : heartbeat envoyé via WS si connecté, HTTP en fallback
- **Transmet les conteneurs découverts** en temps réel via message `containers`
- **Streame les métriques** par conteneur (CPU, mém, latence) via message `metrics` toutes les 10 s
- **Envoie les événements** de cycle de vie (start, stop, scale, die) via message `event`
- **Reconnexion automatique** : backoff exponentiel 1 s → 60 s + jitter
- L'Agent n'expose **aucun port entrant** pour le plan de contrôle

**Authentification :**
1. Premier démarrage : `JOIN_TOKEN` (TTL 24 h) → état `pending`
2. Après approbation Admin : `agent_hmac` rotatif (rotation automatique toutes les heures)

### LB Adaptatif

Les métriques Docker (**CPU**, **mémoire**, **IO disque**) des conteneurs `goproxify.enable` sont streamées au Core toutes les **10 s** via WS (`metrics`). Score par IP :

`cpu×0.5 + mem×0.3 + disk_io×0.2` — le backend au score le plus bas reçoit la requête.

- **Pool local** : plusieurs conteneurs avec le même `goproxify.host` → une route `docker-host:…` multi-backends.
- **Failover** : échec proxy → quarantaine ~15 s → essai d’un autre backend du pool (pas de 502 tant qu’il en reste un sain).
- **Cross-Core** : si le même host est découvert sur Core A et Core B, sync des peers + tunnel `gateway/tunnel` vers l’IP distante via le Core propriétaire (voir [architecture.md](architecture.md#load-balancing-adaptatif)).

Latence P95 / error_rate : champs prévus dans le payload, non utilisés dans le score v1.

### Canary et Shadow Mirror

Configuration **manuelle** sur le proxy (UI / API) : `CanaryConfig` (poids %, header, cookie) et `ShadowConfig` (miroir fire-and-forget).

Labels Docker `goproxify.canary` / `goproxify.shadow` : détection automatique via la discovery Agent — le Core active `CanaryConfig` / `ShadowConfig` sur la route `docker-host:` sans config manuelle. Le conteneur canary/shadow reste hors du pool LB (même `goproxify.host` que les backends normaux).

### Connectivité réseau

- Tunnels **WireGuard** optionnels pour la communication inter-nœuds (port `:51820` UDP)

---

## 5. Canaux d'alerte

Tous les canaux sont cumulables dans une même règle.

| Canal | Description |
|---|---|
| **Email** | SMTP configurable, notification directe aux opérateurs |
| **Webhook** | Webhook générique — compatible Slack, Discord, Teams, n8n, etc. |
| **ntfy.sh** | Push mobile, instance self-hosted ou publique |
| **Gotify** | Push mobile, self-hosted |
| **Jira** | Création automatique d'issue dans un projet Jira |
| **Linear** | Création automatique d'issue dans Linear |
| **GitHub Issues** | Ouverture d'issue dans un dépôt GitHub |
| **GitLab Issues** | Ouverture d'issue dans un projet GitLab |
| **Zammad** | Création de ticket dans le système de ticketing open-source Zammad |
| **GLPI** | Création de ticket via l'API REST de GLPI |

Chaque canal dispose d'un bouton "Tester" dans l'interface d'administration.

---

## 6. Import de configurations

| Format | Notes |
|---|---|
| **nginx** | Blocs `server {}` |
| **HAProxy** | Sections `frontend` / `backend` |
| **Traefik YAML** | Routes, middlewares, configuration TLS |
| **Traefik TOML** | Équivalent TOML |
| **Traefik Labels** | Guide interactif de conversion vers la config GoProxify |
| **Caddy** | Caddyfile |
| **Zoraxy** | JSON natif Zoraxy |
| **BunkerWeb** | Configuration BunkerWeb |
| **CSV** | Colonnes : domaine, backend, options |
| **JSON** | Format natif GoProxify ou JSON générique |

---

## 7. CLI

```
goproxify <commande> [options]
```

| Commande | Rôle |
|---|---|
| `admin` | Démarre l’Administration (Control Plane + Web UI) |
| `core` | Démarre le Core (Data Plane — Reverse Proxy) |
| `agent` | Démarre l’Agent (Discovery & Télémétrie) |
| `token create/list/revoke` | Tokens d’appairage Core/Agent (API Admin) |
| `backup create/list/restore` | Snapshots Admin + export routage (API Admin) |
| `import` | Import nginx/Traefik/Caddy/HAProxy (parse local, apply remote) |
| `proxy list/get/enable/disable/delete` | Gestion des routes proxy |
| `cert list/obtain/delete` | Certificats TLS |
| `user list/get/create/update/passwd/delete` | Comptes utilisateurs Admin |
| `audit list/export` | Journal d’audit des actions |
| `logs list/export` | Logs d’accès et système |
| `alert channels/rules/test` | Canaux et règles d’alerte |
| `snippet list/get/create/update/delete` | Snippets middleware réutilisables |
| `domain list/get/create/renew/delete` | Domaines ACME gérés |
| `agent-mgmt list/get/approve/revoke/delete` | Agents Docker enregistrés (gestion) |
| `settings smtp/mfa` | Config Admin : SMTP, MFA (SMS, WebAuthn) |
| `auth-provider list/get/create/update/enable/disable/delete` | Fournisseurs auth externe (OIDC, SAML…) |
| `teams list/get/create/update/delete + members` | Équipes RBAC |
| `workspaces list/get/create/update/delete + members + resources` | Espaces de travail (multi-tenant) |
| `ip-profile list/get/create/update/delete` | Profils IP (allowlist/blocklist CIDR, GeoIP) |
| `containers list` | Conteneurs Docker découverts (lecture seule) |
| `me get/update/passwd + me tokens` | Profil courant + tokens API personnels (PAT) |
| `security threat/bans/waf` | Sécurité : Sentinel, bans IP, WAF par proxy |
| `status` | État du cluster (nœuds, versions, santé) |
| `access` | GoProxify Access (config, catalogue, users, templates, audit) |
| `nodes` | Liste / accept / reject des nœuds (Infrastructure) |
| `declared` | Nœuds déclarés du wizard architecture |
| `bootstrap` | Tickets QR / curl\|bash d’intégration d’hôtes |
| `core cache show/refresh/export/clear` | Gestion du cache local du Core |
| `update check/apply/rollback` | Mises à jour d’images Docker (via Agent) |
| `version` | Affiche la version du binaire |
| `help` | Affiche l’aide |

Options communes : `-config <chemin>`, `-admin-url <url>`, `-token <token>` (ou `GPX_CONTROLPLANE_ADMIN_ENDPOINT` / `GPX_CONTROLPLANE_AUTH_TOKEN`).

---

## 8. Haute Disponibilité

### Core — Groupes indépendants

- Les Cores s'organisent en **groupes** (par datacenter, région, client...)
- Chaque groupe élit son **coordinateur via l'algorithme Raft** (majorité requise)
- Toute modification de config est validée par la majorité du groupe avant application
- Si le réseau partitionne un groupe, seule la moitié majoritaire peut élire un coordinateur
- En cas de perte d'accès à l'Administration, chaque Core bascule sur son **cache local chiffré**

### Administration — rqlite

- **3 instances d'Administration** synchronisées en permanence via rqlite (SQLite distribué sur Raft)
- Les écritures passent par le **nœud leader**, les lectures sur n'importe quel nœud
- Si une instance tombe, les deux autres continuent sans interruption
- Bascule automatique de leader en quelques secondes

### Connectivité inter-nœuds

- Tunnels WireGuard gérés par l'Agent pour la communication sécurisée entre groupes
- Load balancing adaptatif basé sur les métriques remontées par les Agents

---

## 9. Déploiement

| Mode | Détails |
|---|---|
| **Docker Compose** | `docker compose up -d` — recommandé, fichiers `docker-compose.yml` et `docker-compose-dev.yml` fournis |
| **Bare-metal** | Script interactif `setup.sh` — sélection des modules (Admin / Core / Agent) |
| **systemd** | Service hardened (unités systemd avec sandboxing) |
| **setcap** | `setcap cap_net_bind_service` pour écouter sur les ports < 1024 sans root |

Configuration : fichiers JSON dans `config/` (`admin.json`, `core.json`, `agent.json`) + variables d'environnement préfixées `GPX_*` (priorité prod).

---

## 10. Stack technique

| Domaine | Choix |
|---|---|
| Langage | Go — binaire unique, zéro dépendance runtime |
| Protocoles | HTTP/1.1, HTTP/2, HTTP/3 QUIC (UDP), WebSocket, gRPC, TCP/UDP L4 |
| **Plan de contrôle** | **WebSocket persistant (nhooyr.io/websocket) — Admin→Core(WS), Agent→Core(WS)** |
| TLS | `crypto/tls` + `GetCertificate` (RAM uniquement), passthrough SNI passif, ACME DNS-01 wildcard |
| Table de routage | `sync.Map` — mises à jour atomiques sans interruption |
| Persistance | SQLite embarqué `modernc.org/sqlite` (CGO-free) — Administration uniquement |
| HA Administration | rqlite (SQLite distribué, 3 nœuds, Raft) |
| HA Core | Algorithme Raft par groupe, cache local chiffré |
| Configuration | Viper — JSON + surcharge `GPX_*` env vars |
| Discovery | Docker Engine API via socket Unix (`/var/run/docker.sock`) |
| Métriques | Prometheus (`/metrics`), OpenTelemetry |
| Auth | JWT ECDSA P-256, bcrypt mots de passe, HMAC-SHA256 plan de contrôle WS, JOIN_TOKEN lifecycle, PAT `gpx_pat_*` (API + MCP) |
| Sécurité applicative | Fail2Ban natif Go, CrowdSec bouncer LAPI, WAF natif Go (OWASP CRS-4, 13 règles) |
| Intégrations LLM | Serveur MCP JSON-RPC 2.0 + SSE (`/mcp`, auth PAT) |
| Déploiement | Binaire unique · Docker Compose · systemd (hardening) · `setcap cap_net_bind_service` |
