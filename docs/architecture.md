# Architecture Goproxify

## Vue d'ensemble

Goproxify se déploie via un **binaire Go unique**. La personnalité de l'instance est déterminée au démarrage par `GOPROXIFY_MODE` (ou la sous-commande CLI).

```
  ┌──────────────────────────────────────────────────────────┐
  │  ADMIN  (Control Plane)                                  │
  │  UI Web · API REST · :9443                               │
  │  SQLite · ACME · Alerting                                │
  └────────────────────────┬─────────────────────────────────┘
                           │  WS persistant (Admin initie)
                           │  HMAC-SHA256
                           ▼
  ┌──────────────────────────────────────────────────────────┐
  │  CORE  (Data Plane — Hub WS central)                     │
  │  HTTP/1·2·3 QUIC · TCP/UDP L4                            │
  │  TLS en RAM · cache AES-256 local                        │
  │  :80 :443 :443/UDP  :8000 (hub WS interne)               │
  └────────────────────────▲─────────────────────────────────┘
                           │  WS persistant (Agent initie)
                           │  JOIN_TOKEN → HMAC rotatif
  ┌──────────────────────────────────────────────────────────┐
  │  AGENT  (Docker Discovery)                               │
  │  Lit docker.sock · labels goproxify.*                    │
  │  Streame métriques CPU/mém/IO disque via WS (LB adaptatif) │
  │  Prometheus :9191/metrics                                │
  └──────────────────────────────────────────────────────────┘
```

Le Core est le **hub de connexion unique** — seul lui a besoin d'un port accessible. Admin et Agent initialisent la connexion WS de leur côté ; le Core n'effectue aucun appel sortant vers eux.

---

## Composants

### Core (Data Plane)

**Responsabilité :** Moteur réseau haute performance. Ne persiste rien sur disque.

**Points clés :**
- Table de routage `sync.Map` — mises à jour atomiques sans coupure de connexion
- Certificats TLS poussés en RAM via `GetCertificate` (pas de rechargement)
- `sync.Pool` pour les buffers réseau — P99 stable sous charge
- Passthrough SNI par détection passive (décode 5 bytes du Client Hello, pas le payload)

**Ports :** `:80` (HTTP), `:443` (HTTPS + HTTP/3 UDP)

### Administration (Control Plane)

**Responsabilité :** Orchestrateur central. Source de vérité persistante (SQLite).

**Points clés :**
- Détecte l'absence de SQLite au premier lancement → écran d'initialisation obligatoire
- Deux sources de config : Manuelle (UI/API) et Déclarative (labels Docker via Agent)
- Les proxies issus de labels apparaissent en **lecture seule** (grisés) dans l'UI
- Acquiert les certificats Wildcard via ACME DNS-01 et les pousse décodés au Core
- Génère les tokens cryptographiques d'appairage (`gpx_core_*`, `gpx_join_*`)
- Maintient une **connexion WS sortante** vers chaque Core — aucun port entrant requis côté Admin

**Port :** `:9443`

**Wizard architecture :** l’UI compose une topologie (hôtes + services), dérive les packs d’install et émet des tickets bootstrap (`/i/{token}`) ancrés au Core. Admin reste l’interface ; le Core est la cible d’intégration.

### Agent (Discovery & Telemetry)

**Responsabilité :** Traducteur Docker local. Ultra-léger, sans état persistant.

**Points clés :**
- Scrute `/var/run/docker.sock` — les apps n'exposent **aucun port** sur l'hôte
- Connecte à chaud le conteneur Core au réseau bridge privé de l'application
- Lit `/proc/stat` et `/proc/meminfo` (heartbeat) et les stats Docker par conteneur (CPU / mémoire / IO disque) pour le LB adaptatif
- Streame les métriques via WS (`metrics`, toutes les 10 s) vers le Core
- Labels Canary / Shadow : configuration manuelle proxy (auto-détection labels prévue)
- Export Prometheus sur `:9191/metrics`
- **Aucun port entrant requis** — l'Agent initie la connexion WS vers Core

---

## Load balancing adaptatif

Le mode `lb: adaptive` (UI : « Adaptatif ») choisit le backend le **moins chargé** à chaque requête, d’après les métriques Agent — pas des poids fixes.

### Score

Pour chaque IP de conteneur (et en secours l’IP hôte Agent) :

```
score = cpu×0.5 + mem×0.3 + disk_io×0.2   # 0–100, le plus bas gagne
```

- **Agent** : `GET /containers/{id}/stats?stream=false` pour les conteneurs `goproxify.enable=true`, puis message WS `metrics`.
- **Core** : `AgentMetricsStore` alimenté par WS (plus de poll Admin HTTP pour le LB).

### Pool local (même Core)

Plusieurs conteneurs avec le **même** `goproxify.host`, découverts par un ou plusieurs Agents branchés sur **ce** Core, sont fusionnés en une route `docker-host:<hostname>` multi-backends (`LBAdaptive` par défaut).

```
Agent(s) ──containers──▶ Core
                              └── route docker-host:app.example.fr
                                    backends: [IP_A:port, IP_B:port]
                                    lb: adaptive
```

Le Core joint les IP Docker via le réseau bridge (ports **non** publiés sur l’hôte).

### Failover immédiat

Si le dial / proxy vers un backend échoue :

1. quarantaine courte (~15 s) de ce backend ;
2. essai du **suivant** dans le pool (préférence adaptive, puis les autres) ;
3. 502 seulement si **tous** les backends du pool ont échoué.

Sans ≥ 2 backends, pas de bascule possible.

### Cross-Core (Agent A / Core A + Agent B / Core B)

Objectif : le **même site** joignable via un conteneur derrière chaque stack, sans mesh VXLAN produit.

```
                    ┌─ dial local ──────────────▶ conteneur A (IP Docker)
 Client ──▶ Core A ─┤
                    └─ OwnerCoreEndpoint=B ──tunnel──▶ Core B ──▶ conteneur B
```

1. **Admin** pousse `push_gateway_peers` : liste `{name, endpoint, token}` de chaque Core.
2. Chaque Core **synchronise** (~15 s) `GET /internal/v1/agent/containers` et `GET /internal/v1/lb/scores` chez ses pairs.
3. Si le même host existe en local **et** chez un pair → backends distants annotés `owner_core_endpoint`.
4. Dial distant : `POST /internal/v1/gateway/tunnel` `{target:"IP:port"}` (Bearer du Core owner) → pipe TCP. Seules les IP **possédées localement** par l’owner sont autorisées.

Prérequis : endpoints internes `:8000` joignables entre Cores ; tokens Core enregistrés dans l’Admin.

Ce mécanisme est **distinct** de la [délégation de domaine](delegation.md) (entrée DNS → un Core cible pour tout un domaine).

---

## Flux réseau : déploiement par labels

```
1. App démarre avec labels    →  2. Agent détecte (socket Unix)
   (ports non publiés)
                                           ↓
5. Requête HTTPS routée       ←  4. Core reçoit config + cert (RAM)
   (réseau Docker privé)              ↑
                                  3. Admin valide, ACME DNS-01, push
```

Exemple de labels Docker Compose :
```yaml
labels:
  goproxify.enable: "true"
  goproxify.host: "monapp.example.fr"
  goproxify.port: "8080"
  goproxify.tls: "true"
  goproxify.snippets: "headers-secure"   # IDs snippets Admin
  goproxify.waf: "block"
```

---

## Ports et réseaux

| Port | Protocole | Composant | Exposition | Usage |
|---|---|---|---|---|
| 80 | TCP | Core | Publique | HTTP (redirect ou plaintext) |
| 443 | TCP | Core | Publique | HTTPS (TLS termination) |
| 443 | UDP | Core | Publique | HTTP/3 QUIC |
| 8000 | TCP | Core | Interne uniquement | Hub WS + API interne — reçoit les connexions WS d'Admin et Agent |
| 9443 | TCP | Administration | Opérateur | API REST + Interface Web |
| 9191 | TCP | Agent | Interne uniquement | Métriques Prometheus |
| 51820 | UDP | Agent | Interne uniquement | WireGuard (optionnel) |

> **Règle d'or :** seul le port 8000 du Core doit être accessible depuis les réseaux Admin et Agent. Admin et Agent n'ont aucun port entrant requis pour le plan de contrôle.

---

## Délégation inter-Cores

Plusieurs Cores peuvent se partager les domaines. Le **Core d'entrée** reçoit le trafic public ; le **Core cible** héberge les proxies applicatifs.

Deux modes (page Domaines dans l'Admin) :

| Mode | Flux | Certificat client | Logs IP sur le Core cible |
|---|---|---|---|
| **Passthrough** | Tunnel TCP TLS (SNI) | Core cible | IP du Core d'entrée |
| **Terminate** | TLS sur l'entrée → proxy HTTPS vers la cible | Core d'entrée | IP client via `X-Forwarded-For` |

Guide complet : [delegation.md](delegation.md).

---

## Arborescence `/etc/goproxify/`

```
/etc/goproxify/
├── certs/
│   ├── live/
│   │   └── *.example.fr/
│   │       ├── fullchain.pem
│   │       └── privkey.pem
│   └── ca.pem                    # Pour mTLS client
├── database/
│   └── goproxify.db              # SQLite (Administration uniquement)
├── storage/
│   ├── errors/                   # Pages d'erreur HTTP personnalisées
│   │   ├── 400.html … 504.html
│   ├── pages/
│   │   ├── maintenance.html
│   │   └── disabled.html
│   └── static/                   # Assets statiques fallback
├── cache/
│   └── proxy/                    # Cache disque du Core
└── logs/
    ├── admin.log                 # Audit Administration (JSON)
    ├── agent.log                 # Événements Agent (JSON)
    ├── core_system.log           # Système Core (JSON)
    └── core_access.log           # Requêtes HTTP (JSON, asynchrone)
```

---

## Formats de logs

### Log système (`admin.log`, `agent.log`, `core_system.log`)

```json
{
  "time": "2026-07-15T23:54:12.456Z",
  "level": "INFO",
  "component": "administration",
  "msg": "Nouveau certificat wildcard Let's Encrypt généré",
  "domain": "*.example.fr",
  "provider": "ovh"
}
```

### Log d'accès HTTP (`core_access.log`)

```json
{
  "time": "2026-07-15T23:55:01.123Z",
  "component": "core-router",
  "client_ip": "193.56.21.10",
  "host": "termix.example.fr",
  "method": "GET",
  "path": "/api/v1/status",
  "status": 200,
  "duration_ms": 14.2,
  "bytes_sent": 1024,
  "user_agent": "Mozilla/5.0...",
  "upstream_backend": "http://172.18.0.5:8880",
  "http_version": "HTTP/3"
}
```

---

## Plan de contrôle WebSocket

### Protocole de messages

Tous les messages WS utilisent une enveloppe JSON :
```json
{ "seq": 42, "type": "push_routes", "payload": { ... } }
```

Le champ `seq` est un compteur croissant par émetteur. Un trou dans la séquence déclenche un `full_sync` automatique.

### Flux Admin → Core

1. Admin ouvre `GET ws://core:8000/ws/admin` avec header `X-Goproxify-Signature: hmac-sha256 <timestamp>.<sig>`
2. Core valide le HMAC-SHA256 et accepte la connexion
3. Core répond immédiatement par un `full_sync` pour aligner l'état
4. Admin envoie des messages au fil des changements de configuration : `push_routes`, `push_cert`, `delete_route`…
5. Si la connexion est perdue : Admin reconnecte en backoff exponentiel 1 s → 60 s + jitter

### Flux Agent → Core

1. Premier démarrage : Agent présente son `JOIN_TOKEN` (généré par l'UI Admin, TTL 24 h) en header WS upgrade
2. Core crée l'entrée Agent en état `pending` et notifie Admin via la connexion WS Admin
3. Opérateur approuve dans l'UI → Core envoie un message `approve` avec le premier `agent_hmac`
4. Agent stocke le `agent_hmac` et l'utilise pour toutes les reconnexions futures
5. Core émet un message `rotate_hmac` toutes les heures ; l'Agent adopte le nouveau secret sans interruption
6. Agent streame en continu : `heartbeat` (30 s), `containers` (au changement), `metrics` (10 s), `event`, `log`
7. Core → Agent : `command` (restart, update), `rescan`

### Résilience

- Ping/pong applicatif toutes les 30 s ; 3 pings sans réponse → reconnexion
- Déconnexion Admin → Core conserve le cache ; zéro interruption trafic
- Déconnexion Agent → backends marqués `unhealthy` après 90 s d'absence

---

## Sécurité par tokens

```
Administration  ─HMAC-SHA256──►  Core (ws/admin)
                                      │
                                      │  message: approve
                                      ▼
                Agent (JOIN_TOKEN) ──►  Core (ws/agent)  ──► agent_hmac rotatif (1h)
```

| Token | Format | Usage | Durée |
|-------|--------|-------|-------|
| `gpx_join_*` | Opaque aléatoire | Première connexion Agent → Core | 24 h (usage unique) |
| `agent_hmac` | HMAC-SHA256 secret | Reconnexions Agent → Core | Rotation 1 h |
| `admin_hmac_secret` | Clé symétrique | Handshake Admin → Core | Statique, configurable |
| JWT ECDSA P-256 | JWT signé | Sessions UI Admin | 8 h |
| `gpx_api_*` | Opaque révocable | Accès API externe | Permanent ou TTL configuré |
