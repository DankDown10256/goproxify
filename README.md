# GoProxify

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-preview%20%2F%200.x-orange.svg)](DISCLAIMER.md)
[![Go](https://img.shields.io/badge/go-1.23+-00ADD8.svg)](go.mod)
[![GHCR](https://img.shields.io/badge/GHCR-ghcr.io%2Fvincamok%2Fgoproxify-black)](https://github.com/Vincamok/goproxify/pkgs/container/goproxify%2Fadmin)
[![Release](https://img.shields.io/github/v/release/Vincamok/goproxify?display_name=tag&sort=semver)](https://github.com/Vincamok/goproxify/releases)

> **Préversion (non production).** GoProxify est en **0.x / preview**.  
> Toute utilisation se fait **à vos seuls risques**. Aucune garantie ; les
> auteurs **déclinents toute responsabilité** liée à l’usage (pertes, sécurité,
> interruption, etc.). Détail : [DISCLAIMER.md](DISCLAIMER.md) · licence
> [Apache-2.0](LICENSE) (« AS IS »).

Reverse proxy distribué compilé en un seul binaire Go. Un même exécutable joue trois rôles selon son mode de démarrage : **Core** (data plane), **Admin** (control plane) ou **Agent** (discovery Docker).

Le **Core est la source de vérité** — il porte ses routes, certificats et configuration localement. L'Admin est une interface de gestion qui peut être reconstruite à partir des Cores. Un Core démarre et route le trafic même si l'Admin est injoignable.

Images officielles : `ghcr.io/vincamok/goproxify/{admin,core,agent}` — quickstart en tag flottant **`preview`** (pas de `:latest`) ; SemVer optionnel via `versions.json`. Contribuer : [CONTRIBUTING.md](CONTRIBUTING.md) · Support : [Discussions](https://github.com/Vincamok/goproxify/discussions) · Roadmap : [suivi/roadmap-public.md](suivi/roadmap-public.md).

---

## Architecture

```
                        ┌──────────────────────────────────┐
                        │  ADMIN  (Control Plane)          │
                        │  UI Web · API REST · MCP · :9443 │
                        │  SQLite · ACME · Alerting        │
                        │  reconstructible depuis les Cores│
                        └──────────┬───────────────────────┘
                                   │ WS persistant Admin→Core
                                   │ (push routes/certs/config)
                                   ▼
┌──────────────┐    ┌──────────────────────────────────────┐
│   INTERNET   │───►│  CORE  (Data Plane · hub WS central) │
│  :80 / :443  │    │  HTTP/1·2·3 QUIC · TCP/UDP L4        │
│  HTTP/1·2·3  │    │  TLS en RAM · cache AES-256 local    │
└──────────────┘    │  Zéro reload · autonome sans Admin   │
                    │  :80 :443 :443/UDP :8000+WS (interne)│
                    └────────────▲─────────────────────────┘
                                 │ WS persistant Agent→Core
                                 │ (heartbeat/métriques/events)
                    ┌────────────┴─────────────────────────┐
                    │  AGENT  (Docker Discovery)           │
                    │  Lit docker.sock (lecture seule)     │
                    │  Détecte labels goproxify.*          │
                    │  Prometheus :9191/metrics            │
                    │  Aucun port entrant plan de contrôle │
                    └──────────────────────────────────────┘
```

| Composant | Rôle | Persistance | Ports exposés |
|-----------|------|-------------|---------------|
| **Core** | Data Plane — routage, TLS, L4 · hub WS plan de contrôle | RAM + cache local chiffré | `:80`, `:443` (TCP+UDP), `:8000` (interne + WS) |
| **Admin** | Control Plane — UI, API, alerting | SQLite | `:9443` |
| **Agent** | Discovery Docker & métriques | Volatile | `:9191` (Prometheus) — **aucun port entrant WS** |

---

## Démarrage rapide

> Preview uniquement — lire [DISCLAIMER.md](DISCLAIMER.md) avant tout déploiement.

### Docker Compose (recommandé)

```bash
# 1. Télécharger le fichier compose tout-en-un
curl -LO https://github.com/vincamok/goproxify/raw/main/docker-compose.quickstart.yml
curl -LO https://github.com/vincamok/goproxify/raw/main/.env.example

# 2. Générer les secrets obligatoires
cp .env.example .env
# Éditer .env — au minimum :
#   GPX_JWT_SECRET=$(openssl rand -hex 32)
#   GPX_PAIRING_SECRET=$(openssl rand -hex 32)
#   GPX_FIRST_ADMIN_EMAIL=admin@example.com
#   GPX_FIRST_ADMIN_PASSWORD=change-me

# 3. Démarrer — Admin + Core + Agent (tire les images GHCR)
docker compose -f docker-compose.quickstart.yml up -d
```

Les images sont publiées sur **GHCR** (`ghcr.io/vincamok/goproxify`). Défaut quickstart :
tag flottant **`preview`**. Pour pinner un SemVer : `GOPROXIFY_ADMIN_TAG`,
`GOPROXIFY_CORE_TAG`, `GOPROXIFY_AGENT_TAG` (voir `versions.json` / `.env.example`).

L'interface d'administration est disponible sur **http://localhost:9443**.

Le Core et l'Agent s'apairent automatiquement avec l'Admin via `GPX_PAIRING_SECRET` — aucun token manuel à copier.

### Portainer

1. **Stacks → Add stack → Repository**
2. URL : `https://github.com/vincamok/goproxify`
3. Compose path : `docker-compose.quickstart.yml`
4. Variables d'environnement : `GPX_JWT_SECRET`, `GPX_PAIRING_SECRET`, `GPX_FIRST_ADMIN_EMAIL`, `GPX_FIRST_ADMIN_PASSWORD` (générez les secrets avec `openssl rand -hex 32`)
5. **Deploy the stack**

### Binaire

```bash
# Compiler
git clone https://github.com/vincamok/goproxify && cd goproxify
go build -o goproxify ./cmd/goproxify

# Démarrer l'Admin
GPX_SECURITY_JWT_SECRET=<secret> ./goproxify admin

# Démarrer un Core (token généré depuis l'UI Admin)
GPX_CONTROL_PLANE_ADMIN_ENDPOINT=http://localhost:9443 \
GPX_CORE_TOKEN=gpx_... \
./goproxify core

# Démarrer l'Agent (optionnel)
GPX_CONTROL_PLANE_CORE_ENDPOINT=http://localhost:8000 \
./goproxify agent
```

---

## Appairage Core / Agent

### Core → Admin

Deux méthodes pour connecter un Core à un Admin :

| Méthode | Usage | Variable |
|---------|-------|----------|
| **Secret partagé** | Stack tout-en-un (même machine / même compose) | `GPX_PAIRING_SECRET` |
| **Token explicite** | Core distant, multi-site | `GPX_CORE_TOKEN` |

Le secret partagé est la méthode recommandée pour un déploiement standard. Le token explicite est généré depuis l'UI Admin → Paramètres → Tokens.

### Agent → Core (WS)

Le plan de contrôle Agent↔Core utilise un tunnel WebSocket persistant. L'Agent se connecte au Core — pas l'inverse.

| Étape | Description | Variable |
|-------|-------------|----------|
| 1. **JOIN_TOKEN** | Premier démarrage — l'Agent se connecte et entre en état `pending` | `GPX_CONTROL_PLANE_JOIN_TOKEN` |
| 2. **Approbation** | L'opérateur approuve l'Agent dans l'UI Admin | — |
| 3. **agent_hmac** | Le Core envoie un secret HMAC via WS → l'Agent est `approved` | auto-négocié |
| 4. **Rotation** | Le Core régénère l'`agent_hmac` toutes les heures | automatique |

Pour générer un `JOIN_TOKEN` : Admin UI → Tokens → Créer → rôle `agent`, TTL `24h`.

---

## CLI

```
goproxify <commande> [options]

Modes de service :
  admin    Démarre l'Administration (Control Plane + Web UI)
  core     Démarre le Core (Data Plane — Reverse Proxy)
  agent    Démarre l'Agent (Discovery Docker)
  landing  Démarre la landing page (optionnel)

Commandes opérationnelles :
  token      Gestion des tokens d'appairage Core/Agent
  backup     Sauvegardes et restauration
  import     Import de configurations (nginx, Traefik, Caddy, HAProxy…)
  alert      Test des canaux d'alerte
  status     État du cluster
  access     GoProxify Access (config, catalogue, users, templates)
  nodes      Nœuds Infrastructure (list / accept / reject)
  declared   Nœuds déclarés wizard architecture
  bootstrap  Tickets QR / curl|bash d'intégration

  version  Version du binaire
  help     Aide
```

### Exemples

Les commandes opérationnelles (`token`, `backup`, `alert`, `import`, `status`, `access`, `nodes`, `declared`, `bootstrap`) parlent à l’Admin via HTTP. Auth : `-admin-url` / `-token`, ou `GPX_CONTROLPLANE_ADMIN_ENDPOINT` / `GPX_CONTROLPLANE_AUTH_TOKEN` (JWT session ou PAT).

```bash
# Tokens d'appairage Core/Agent
goproxify token create -role core  -node "prod-1" -endpoint http://core:8000
goproxify token create -role agent -node "app-2" -ttl 24h
goproxify token list
goproxify token revoke <token-id>

# Sauvegardes (JSON .gpx-admin-backup / .gpx-core-backup)
goproxify backup create
goproxify backup create -target admin -output /var/backups/goproxify
goproxify backup list
goproxify backup restore -file backup-2026-07-15.gpx-admin-backup -yes

# Import de configurations
goproxify import -file nginx.conf -dry-run
goproxify import -file traefik.yml -format traefik-yaml

# Cache local du Core
goproxify core cache show
goproxify core cache refresh
goproxify core cache clear

# Test des canaux d'alerte
goproxify alert test -channel <channel-id>
goproxify alert test -all

# État du cluster
goproxify status

# GoProxify Access
goproxify access config get -core core-a
goproxify access destinations list -core core-a
goproxify access users list
goproxify access templates list

# Infrastructure / wizard
goproxify nodes list
goproxify declared list
goproxify bootstrap create -host edge-1 -core-endpoint http://192.0.2.10:8000 -node-names core-edge -no-qr
```

---

## Fonctionnalités

### Core (Data Plane)

- Routage **HTTP/1.1, HTTP/2, HTTP/3 QUIC** (UDP)
- Stream **TCP et UDP (L4)**
- Terminaison TLS + SSL Passthrough par détection passive du SNI
- Routes et certificats stockés **en RAM** (`sync.Map`, `GetCertificate`) — aucune clé privée sur disque
- **Cache local chiffré AES-256-GCM** — démarre et route sans Admin disponible
- Rechargement de configuration à chaud, zéro interruption de connexion
- Load balancing (Round Robin, Weighted, adaptatif CPU/mem/IO + failover + gateway inter-Cores), Circuit Breaker, Retry
- Rate limiting, filtrage IP/CIDR, Géo-IP, WAF OWASP CRS-4, headers de sécurité HTTP
- Authentification Basic, Forward Auth, JWT par route
- Access log JSON asynchrone, métriques Prometheus, tracing OpenTelemetry
- **GoProxify Access** — portail opérateur sur le Core : terminal web + `ssh` UUID vers VMs/`sshd` et conteneurs Docker (`docker exec` via Agent) ; coffre login SSH + secrets ; 2FA ; sessions TTL

### Admin (Control Plane)

- **Interface web + API REST** — CRUD proxies, snippets, tokens, utilisateurs
- **GoProxify Access** — catalogue destinations (vue globale / par Core), invite users par email (SMTP), tags, templates HTML Access, options portail par Core
- **Tokens API utilisateur (PAT)** — `gpx_pat_*` self-service à scopes (`proxies:read`, …) pour scripts et clients MCP ; distincts des tokens d’appairage Core/Agent
- **Serveur MCP** — JSON-RPC 2.0 + SSE ; authentification **PAT uniquement** (pas de JWT de session)
- **Wizard architecture** — toile hôtes + palette, multi-Core/HA, tickets QR / `curl|bash` pour intégrer un hôte
- **Premier démarrage guidé** — wizard de configuration initiale
- Gestion ACME DNS-01 wildcard (OVH, Cloudflare, Gandi, Route53, Hetzner)
- Push des certificats au Core (RAM uniquement, jamais persistés côté Core)
- **Alerting granulaire** — règles par node/domaine/équipe, 10 canaux : Email, Webhook, ntfy.sh, Gotify, Jira, Linear, GitHub Issues, GitLab Issues, Zammad, GLPI
- Audit log structuré pour tous les composants
- Sauvegardes planifiées et restauration
- Import : nginx, HAProxy, Traefik, Caddy, CSV, JSON

### Agent (Docker Discovery)

- Lit `/var/run/docker.sock` en **lecture seule**
- Détecte les labels `goproxify.*` sur les conteneurs en temps réel
- Envoie les routes, métriques et événements au Core via **tunnel WS persistant** (Agent→Core)
- Heartbeat HTTP en fallback si la connexion WS est indisponible
- Labels Canary (`goproxify.canary`) et Shadow Mirror (`goproxify.shadow`) supportés
- Export Prometheus sur `:9191/metrics`
- **Aucun port entrant** nécessaire pour le plan de contrôle

---

## Ports

| Port | Protocole | Composant | Exposition |
|------|-----------|-----------|------------|
| `80` | TCP | Core | Publique |
| `443` | TCP | Core | Publique |
| `443` | UDP | Core | Publique (HTTP/3 QUIC) |
| `8000` | TCP | Core | **Interne uniquement** |
| `2222` | TCP | Core (Access) | Portail SSH UUID (si Access activé ; configurable) |
| `8444` | TCP | Core (Access) | UI Access interne (si Access activé ; configurable) |
| `9443` | TCP | Admin | Opérateur |
| `9191` | TCP | Agent | Interne (Prometheus) |

> Le port `8000` (API interne du Core) ne doit **pas** être exposé publiquement.  
> Restreindre son accès : `ufw allow from <ip-admin> to any port 8000`

---

## Variables d'environnement

Les variables `GPX_*` ont priorité sur les fichiers de configuration JSON.  
Voir `.env.example` pour la liste complète.

| Variable | Composant | Description |
|----------|-----------|-------------|
| `GPX_SECURITY_JWT_SECRET` | Admin | Clé de signature JWT (obligatoire) |
| `GPX_SECURITY_CLUSTER_SYNC_KEY` | Admin | Clé de synchronisation cluster |
| `GPX_PAIRING_SECRET` | Admin / Core / Agent | Secret partagé pour appairage automatique (HMAC WebSocket) |
| `GPX_CORE_TOKEN` | Core | Token explicite (alternative au secret partagé) |
| `GPX_IDENTITY_CORE_NODE_NAME` | Admin | Hostname/IP du Core joignable (Admin → `http://<valeur>:8000`) |
| `GPX_CONTROL_PLANE_CORE_ENDPOINT` | Agent | URL du Core vue par l'Agent (`http://<core>:8000`) |
| `GPX_ENGINE_LOG_LEVEL` | Tous | Niveau de log (`debug`/`info`/`warn`/`error`) |
| `GPX_VULNSCAN_ALLOW_PRIVATE` | Admin | `true`/`1`/`yes` : autorise le scanner CVE sur backends privés (RFC1918/ULA). Défaut : refusé (anti-SSRF). Localhost et metadata cloud restent bloqués. |
| `GPX_BACKUP_KEY` | Admin | (optionnel) Chiffre les snapshots Admin (AES-GCM). Sans clé : JSON rédigé des secrets, non chiffré. |
| `GPX_NODE_TOKEN_KEY` | Admin | (optionnel) Chiffre les tokens nœuds au repos. Sinon dérivé du secret JWT. |

---

## Stack technique

| Domaine | Choix |
|---------|-------|
| Langage | Go 1.23 — binaire statique unique, zéro dépendance runtime |
| Protocoles | HTTP/1.1, HTTP/2, HTTP/3 QUIC (quic-go), TCP/UDP L4 |
| **Plan de contrôle** | **WebSocket persistant `nhooyr.io/websocket` — Admin→Core(WS), Agent→Core(WS)** |
| TLS | Terminaison SSL + Passthrough SNI, ACME DNS-01 wildcard |
| Persistance Admin | SQLite CGO-free (`modernc.org/sqlite`) — option Raft HA |
| Persistance Core | Cache local AES-256-GCM (routes + certs) |
| Configuration | Variables d'environnement `GPX_*` + JSON optionnel |
| Discovery | Docker Engine API via socket Unix (lecture seule) |
| Métriques | Prometheus `/metrics`, OpenTelemetry (OTLP) |
| Sécurité | WAF OWASP CRS-4, Rate limiting, Géo-IP, JWT ECDSA P-256, HMAC-SHA256 WS |
| Déploiement | Binaire unique · Docker Compose · systemd |

---

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture détaillée](docs/architecture.md) | Flux de données, décisions techniques |
| [Délégation inter-Cores](docs/delegation.md) | Modes Passthrough vs Terminate, IP client, prérequis |
| [Fonctionnalités](docs/fonctionnalites.md) | Catalogue des capacités produit |
| [Spécifications API](docs/api_specs.md) | Contrat REST complet |
| [MCP](docs/mcp.md) | Serveur MCP — outils, auth PAT, clients Claude/Cursor |
| [Schéma de configuration](docs/config_schema.json) | Schéma JSON des proxies |
| [FAQ](docs/faq.md) | Premier démarrage, reset mot de passe, labels Docker, délégation |
| [Changelog](suivi/changelog.md) | Historique des changements par version |
| [Versioning](suivi/versioning.md) | Règles de bump de version (SemVer) |
| [Roadmap publique](suivi/roadmap-public.md) | Jalons haut niveau |
| [Contributing](CONTRIBUTING.md) | PR, tests, DCO |
| [Code of Conduct](CODE_OF_CONDUCT.md) | Contributor Covenant |
| [Sécurité](SECURITY.md) | Signalement des vulnérabilités |
| [Licence](LICENSE) | Apache License 2.0 |
| [NOTICE](NOTICE) | Copyright et notices tierces |
| [Avertissement](DISCLAIMER.md) | Préversion, sans garantie ni responsabilité d’usage |
