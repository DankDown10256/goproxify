# Spécifications API — Goproxify Administration

Base URL : `https://<admin-host>:9443`

Toutes les réponses sont en JSON. Authentification par `Authorization: Bearer <token>` sauf les endpoints publics marqués `[PUBLIC]`.

---

## Authentification

### `POST /api/v1/auth/login` `[PUBLIC]`

Échange email/mot de passe contre un JWT de session.

**Corps :**
```json
{ "email": "admin@example.fr", "password": "..." }
```

**Réponse 200 :**
```json
{ "token": "eyJ...", "expires_at": "2026-07-16T09:00:00Z" }
```

---

### `POST /api/v1/auth/logout`

Invalide le token de session courant.

---

## Tokens API utilisateur (PAT)

Les PAT (`gpx_pat_*`) sont créés en self-service. Ils authentifient l’API REST (scopes) et sont **obligatoires** pour `/mcp`. Distincts des tokens d’appairage `/api/v1/tokens`.

### `GET /api/v1/me/tokens`

Liste les PAT de l’utilisateur connecté (métadonnées ; pas de secret). Session JWT uniquement.

### `GET /api/v1/me/tokens/scopes`

Catalogue des scopes avec indicateur `available` selon le rôle courant.

### `POST /api/v1/me/tokens`

Crée un PAT. Le secret en clair n’est retourné qu’une fois.

**Corps :**
```json
{
  "label": "Claude Desktop",
  "scopes": ["proxies:read", "nodes:read"],
  "expires_at": "2027-01-01T00:00:00Z"
}
```

`expires_at` est optionnel (RFC3339). Scopes bornés aux droits du compte.

**Réponse 201 :** inclut `token` (`gpx_pat_…`).

### `DELETE /api/v1/me/tokens/:id`

Révoque immédiatement le PAT.

---

## Initialisation (First Boot)

### `GET /api/v1/setup/status` `[PUBLIC]`

Indique si l'Administration est initialisée.

**Réponse 200 :**
```json
{ "initialized": false }
```

### `POST /api/v1/setup/init` `[PUBLIC]`

Crée le compte administrateur initial (uniquement si `initialized: false`).

**Corps :**
```json
{ "email": "admin@example.fr", "password": "..." }
```

---

## Tokens d'appairage

### `POST /api/v1/tokens`

Génère un token cryptographique pour un Core ou un Agent.

**Corps :**
```json
{ "role": "core", "node": "serveur-production-1", "ttl": "0" }
```

`role` : `core` | `agent`
`ttl` : durée de validité (ex: `"24h"`) ou `"0"` pour permanent.

**Réponse 201 :**
```json
{
  "token": "gpx_core_a1b2c3d4e5f6...",
  "node": "serveur-production-1",
  "role": "core",
  "created_at": "2026-07-15T10:00:00Z"
}
```

### `GET /api/v1/tokens`

Liste les tokens générés.

### `DELETE /api/v1/tokens/:id`

Révoque un token.

---

## Proxies

### `GET /api/v1/proxies`

Liste tous les proxies (manuels + labels).

**Réponse 200 :**
```json
[
  {
    "id": "uuid",
    "domain": "myapp.example.fr",
    "source": "manual",
    "enabled": true,
    "meta": { "nom": "Interface myapp", "environment": "production" }
  },
  {
    "id": "uuid",
    "domain": "termix.example.fr",
    "source": "label",
    "readonly": true,
    "meta": { "container": "termix_app_1" }
  }
]
```

`source` : `manual` | `label`
`readonly: true` pour les proxies issus de labels.

### `POST /api/v1/proxies`

Crée un proxy manuel. Corps : objet conforme au schéma canonique (section `proxies`).

### `GET /api/v1/proxies/:domain`

Détail complet d'un proxy.

### `PUT /api/v1/proxies/:domain`

Met à jour un proxy manuel (interdit sur `source: "label"`).

### `DELETE /api/v1/proxies/:domain`

Supprime un proxy manuel.

### `POST /api/v1/proxies/:domain/enable`
### `POST /api/v1/proxies/:domain/disable`

Active/désactive un proxy à chaud.

---

## Certificats

### `GET /api/v1/certs`

Liste les certificats gérés.

### `POST /api/v1/certs/request`

Demande un certificat ACME DNS-01.

**Corps :**
```json
{ "domain": "*.example.fr", "dns_provider": "ovh_prod" }
```

### `POST /api/v1/certs/:domain/renew`

Force le renouvellement d'un certificat.

### `DELETE /api/v1/certs/:domain`

Supprime un certificat.

---

## Snippets

### `GET /api/v1/snippets/:section`

`section` : `ip_profiles` | `security_headers` | `tls_profiles` | `rate_limit_policies` | `cors_policies` | `timeout_profiles` | `auth_providers` | `dns_providers`

### `POST /api/v1/snippets/:section`

Crée un snippet custom (`builtin: false` uniquement).

### `PUT /api/v1/snippets/:section/:key`
### `DELETE /api/v1/snippets/:section/:key`

Modification/suppression (interdite sur `builtin: true`).

---

## Nodes (Cores & Agents enregistrés)

### `GET /api/v1/nodes`

Liste les Cores et Agents enregistrés avec leur état.

**Réponse 200 :**
```json
[
  {
    "id": "core-1",
    "role": "core",
    "node": "serveur-production-1",
    "ip": "203.0.113.10",
    "status": "healthy",
    "last_seen": "2026-07-15T23:54:00Z"
  }
]
```

### `DELETE /api/v1/nodes/:id`

Désenregistre un node.

---

## Agents en attente d'approbation

Les Agents qui se connectent pour la première fois via un `JOIN_TOKEN` apparaissent en statut `pending` jusqu'à approbation explicite.

### `GET /api/v1/agents`

Liste tous les Agents (online, pending, offline).

**Réponse 200 :**
```json
[
  {
    "agent_id": "agent-prod-1",
    "name": "agent-prod-1",
    "version": "0.1.0",
    "status": "pending",
    "last_seen_at": "2026-07-30T10:00:00Z"
  }
]
```

### `POST /api/v1/agents/:id/approve`

Approuve un Agent en attente. Le Core lui envoie immédiatement son `agent_hmac` via la connexion WS active.

**Réponse 200 :**
```json
{ "approved": true }
```

---

## Nœuds déclarés & tickets bootstrap

### `GET /api/v1/declared-nodes`

Liste les nœuds déclarés via le wizard architecture (pas encore connectés, ou reprise de nœuds live).

### `POST /api/v1/declared-nodes`

Déclare un nœud (`role`: `core`|`agent`, `name`, `region`, `environment`, `config`). Upsert par `(role, name)`.

### `DELETE /api/v1/declared-nodes/:id`

Supprime un nœud déclaré.

### `POST /api/v1/bootstrap-tickets` `[AUTH]`

Crée un ticket one-shot pour intégrer un hôte (QR + lien + script).

**Body :**
```json
{
  "host_name": "edge-1",
  "core_endpoint": "http://192.0.2.10:8000",
  "payload": {},
  "ttl_hours": 24,
  "auto_accept": true,
  "node_names": ["core-edge"]
}
```

**Réponse 200 :** `token`, `url` (`/i/{token}`), `script_url`, `install_cmd`, `qr_code` (PNG data URL), `expires_at`.

### `GET /i/{token}` / `GET /i/{token}.sh` / `GET /api/v1/bootstrap/{token}` `[PUBLIC]`

Page HTML, script bash (`docker compose up -d`), ou JSON public du ticket.

### `POST /api/v1/nodes/:id/accept` / `POST /api/v1/nodes/:id/reject`

Accepte ou rejette un nœud en attente (`pending_nodes`) après présentation du pairing secret.

---

## Santé

### `GET /health` `[PUBLIC]`

```json
{ "status": "ok", "version": "0.1.0" }
```

### `GET /api/v1/cluster/status`

État du cluster (nodes, leader, sync).

---

## API interne Core ↔ Administration

*Ces endpoints ne sont pas exposés publiquement. Authentification par token d'appairage.*

### `POST /internal/v1/register`

Enregistrement d'un Core ou Agent.

### `GET /internal/v1/config`

Récupère la configuration complète (routes + certs) pour un Core.

### `POST /internal/v1/telemetry`

Soumission des métriques d'un Agent.

### `POST /internal/v1/discovery`

Soumission d'un proxy découvert par labels (depuis un Agent).

> **Note de migration :** Ces endpoints HTTP sont conservés pour la rétrocompatibilité pendant la migration. La nouvelle architecture utilise les tunnels WebSocket décrits ci-dessous.

---

## Protocole WebSocket

Le plan de contrôle utilise des tunnels WebSocket persistants initiés par Admin et Agent vers le Core. Le Core est le seul hub de connexion.

### `GET /ws/admin` — Connexion Admin↔Core

**Authentification :** header `X-Goproxify-Signature: hmac-sha256 <timestamp>.<hex_sig>`

La signature est calculée sur `"<ts>:<method>:<path>"` avec la clé `GPX_CONTROL_PLANE_ADMIN_HMAC_SECRET`. Fenêtre de rejeu ±5 min.

**Header requis :** `X-Node-ID: <nodeID>` — identifiant unique de l'instance Admin.

### `GET /ws/agent` — Connexion Agent↔Core

**Premier démarrage :** header `X-Join-Token: gpx_join_*` (TTL 24h). L'Agent passe en état `pending` jusqu'à approbation via `POST /api/v1/agents/:id/approve`.

**Après approbation :** header `X-Agent-HMAC: <secret>` (rotatif toutes les heures, envoyé par le Core via message `rotate_hmac`).

---

### Format d'enveloppe JSON

Tous les messages WS utilisent l'enveloppe suivante :

```json
{
  "seq": 42,
  "type": "heartbeat",
  "payload": { ... }
}
```

| Champ | Type | Description |
|---|---|---|
| `seq` | int64 | Numéro de séquence croissant (détection de gap → full_sync) |
| `type` | string | Type de message (voir tables ci-dessous) |
| `payload` | JSON | Corps du message, spécifique au type |

---

### Types de messages Admin→Core

| Type | Description |
|---|---|
| `push_routes` | Pousse la table de routage complète (ou partielle RBAC) |
| `delete_route` | Supprime une route par ID |
| `push_cert` | Pousse un certificat TLS (PEM cert + key) |
| `push_snippets` | Pousse tous les snippets actifs |
| `push_auth_providers` | Pousse les fournisseurs d'authentification |
| `push_ip_profiles` | Pousse les profils IP/CIDR |
| `push_settings` | Pousse les paramètres runtime (log level, tracing, etc.) |
| `push_cluster_peers` | Pousse la topologie Raft |
| `push_delegations` | Pousse les routes de délégation multi-Core |
| `full_sync` | Full sync : envoie toutes les données en une seule enveloppe |
| `approve_agent` | Demande au Core d'approuver un Agent en attente |

### Types de messages Agent→Core

| Type | Description |
|---|---|
| `register` | Premier message après upgrade WS — enregistrement de l'Agent |
| `heartbeat` | CPU%, mém%, runtimes actifs (toutes les 30 s) |
| `containers` | Liste des conteneurs avec labels goproxify.* |
| `metrics` | Métriques par conteneur (CPU, mém, latence, erreurs) pour LB adaptatif |
| `event` | Événement de cycle de vie conteneur (start, stop, die, scale, etc.) |
| `log` | Batch de logs de conteneurs (log forwarding) |

### Types de messages Core→Agent

| Type | Description |
|---|---|
| `approve` | Approbation de l'Agent + premier `agent_hmac` |
| `rotate_hmac` | Nouveau `agent_hmac` (rotation toutes les heures) |
| `command` | Commande à exécuter sur l'Agent (restart conteneur, pull image, etc.) |
| `rescan` | Demande un rescan Docker immédiat |
| `ping` | Ping keepalive (répondu par `pong`) |

### Types de messages Core→Admin

| Type | Description |
|---|---|
| `agent_pending` | Un Agent attend l'approbation (notification UI) |
| `node_update` | Mise à jour de l'état d'un Agent (online/offline/metrics) |
