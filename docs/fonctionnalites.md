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
| Géo-IP | Autorisation ou blocage par pays (prévu) |
| Rate limiting | Token bucket par IP, seuils configurables |
| Headers de sécurité HTTP | HSTS, X-Frame-Options, Content-Security-Policy, etc. |
| CORS | Origines, méthodes et en-têtes configurables |
| Masquage du fingerprint serveur | Suppression des en-têtes révélateurs (`Server`, `X-Powered-By`) |
| WAF | ModSecurity / OWASP CRS-4 (Jalon 5) |
| Fail2Ban natif Go | Bannissement automatique après N échecs, sans dépendance externe |
| CrowdSec | Bouncer LAPI stream → bans poussés au Core (403), compatible Docker |
| JWT validation | JWKS (Jalon 5) |
| SSO | Authentik, Authelia, Basic Auth (Jalon 5) |

### Résilience

- **Load balancing** : Round Robin, Weighted, **Adaptatif** (CPU×0.5 + mem×0.3 + IO disque×0.2 via métriques Agent WS)
- **Health checks actifs** sur les backends
- **Failover** : quarantaine courte + essai du backend suivant sur échec dial/proxy
- **Circuit Breaker** : isolation automatique des backends défaillants
- **Retry policy** avec backoff exponentiel configurable
- **Sticky sessions** par cookie

### Observabilité

- **Access log JSON asynchrone** : IP client, domaine, méthode, code HTTP, durée, upstream, version HTTP
- **System log JSON structuré** pour tous les composants, avec rotation
- **Métriques Prometheus** exposées sur `/metrics`
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
- **Lecture :** proxies, nœuds, agents, declared-nodes, alertes, métriques, backups, users, snippets, domaines, certs, logs, teams, audit, bans / menaces / CVE, Access (config, catalogue, users, templates, audit)
- **Écriture :** `create_proxy`, `update_proxy`, `set_proxy_enabled`, `delete_proxy`, `approve_agent`, `revoke_agent`, `create_declared_node`, `create_bootstrap_ticket`, `accept_node` / `reject_node`, `create_security_ban`, `delete_security_ban`, outils Access (`update_portal_*`, `invite_portal_user`, `push_portal`, templates…)
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
  - Le scanner HTTP refuse par défaut les cibles privées (RFC1918/ULA), localhost et metadata cloud (anti-SSRF). Pour scanner des backends Docker/LAN : `GPX_VULNSCAN_ALLOW_PRIVATE=true` sur l’Admin.
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

```yaml
# Proxy
goproxify.enable: "true"
goproxify.type: "http"              # http | tcp | udp
goproxify.host: "app.example.fr"
goproxify.port: "3000"
goproxify.tls: "true"

# Sécurité (appliquée sur la route docker-host)
goproxify.rate_limit: "100/s"                    # ou "100/s:50" (burst)
goproxify.ip_filter: "allow:10.0.0.0/8,203.0.113.10/16"
goproxify.cors: "true"                           # ou origins CSV
goproxify.geo_ip: "allow:FR,DE"                  # ou deny:CN,RU
goproxify.snippets: "waf-default,headers-secure" # IDs snippets Admin
goproxify.auth_provider: "authentik-prod"        # ID fournisseur auth Admin
goproxify.waf: "block"                           # true|block|detect
goproxify.bot: "true"

# Mises à jour d'images
goproxify.update.auto: "true"
goproxify.update.schedule: "0 3 * * *"
goproxify.update.prune: "true"
goproxify.update.rollback_timeout: "60s"

# Log forwarding
goproxify.logs: "true"

# Auto-scaling
goproxify.scale.min: "1"
goproxify.scale.max: "5"
goproxify.scale.cpu_threshold: "80"
goproxify.scale.cooldown: "120s"

# Canary (reçoit un pourcentage du trafic)
goproxify.canary: "true"
goproxify.canary.weight: "10"       # % du trafic (défaut: 10)

# Shadow Mirror (copie silencieuse du trafic)
goproxify.shadow: "true"
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
| `admin` | Démarre l'Administration (Control Plane + Web UI) |
| `core` | Démarre le Core (Data Plane — Reverse Proxy) |
| `agent` | Démarre l'Agent (Discovery & Télémétrie) |
| `token create/list/revoke` | Tokens d'appairage Core/Agent (API Admin) |
| `backup create/list/restore` | Snapshots Admin + export routage (API Admin) |
| `import` | Import nginx/Traefik/Caddy/HAProxy (parse local, apply remote) |
| `alert test` | Test des canaux de notification |
| `status` | État du cluster (nœuds, versions, santé) |
| `access` | GoProxify Access (config, catalogue, users, templates, audit) |
| `nodes` | Liste / accept / reject des nœuds (Infrastructure) |
| `declared` | Nœuds déclarés du wizard architecture |
| `bootstrap` | Tickets QR / curl\|bash d’intégration d’hôtes |
| `core cache show/refresh/export/clear` | Gestion du cache local du Core |
| `update check/apply/rollback` | Mises à jour d'images Docker (via Agent) |
| `version` | Affiche la version du binaire |
| `help` | Affiche l'aide |

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
| Sécurité applicative | Fail2Ban natif Go, CrowdSec bouncer LAPI, WAF ModSecurity/OWASP CRS-4 |
| Intégrations LLM | Serveur MCP JSON-RPC 2.0 + SSE (`/mcp`, auth PAT) |
| Déploiement | Binaire unique · Docker Compose · systemd (hardening) · `setcap cap_net_bind_service` |
