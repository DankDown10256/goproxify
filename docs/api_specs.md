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

### `GET /api/v1/certs/:id/deploy-targets`

Liste les deploy targets d'un certificat. Réponse : `[{id, cert_id, name, type, config, trigger_on, last_deploy, last_status, created_at}]` — les champs `secret` des configs webhook sont masqués (`***`).

### `POST /api/v1/certs/:id/deploy-targets`

Crée un deploy target. Corps : `{name, type ("webhook"), config {url, secret?}, trigger_on ("on_renewal"|"manual")}`.

### `DELETE /api/v1/certs/:id/deploy-targets/:targetID`

Supprime un deploy target.

### `POST /api/v1/certs/:id/deploy-targets/:targetID/trigger`

Déclenche manuellement le déploiement vers ce target.

### `GET /api/v1/certs/:id/deploy-targets/:targetID/history`

Retourne les 50 derniers résultats de déploiement pour ce target.

### `GET /api/v1/certs/:id/pull-tokens`

Liste les pull tokens d'un certificat (valeur du token non retournée, seulement les métadonnées).

### `POST /api/v1/certs/:id/pull-tokens`

Génère un nouveau pull token. Corps : `{name?, format ("pem"|"key"|"fullchain"|"json"), max_uses (0=illimité), ttl_hours (0=pas d'expiration)}`. Réponse : `{id, token, format}` — le token est retourné **une seule fois**.

### `DELETE /api/v1/certs/:id/pull-tokens/:tokenID`

Révoque un pull token.

### `GET /api/v1/cert-bundle` *(endpoint public)*

Télécharge un bundle de certificat via un token. Paramètres : `token` (requis), `format` (`pem`|`key`|`fullchain`|`json`). Pas d'authentification — le token fait office d'autorisation. Vérifie TTL et max_uses.

```bash
curl -s "https://admin.example.com/api/v1/cert-bundle?token=TOKEN&format=fullchain" -o fullchain.pem
```

---

### `GET /api/v1/proxies/:id/revisions`

Liste les révisions sauvegardées d'un proxy. Réponse : `[{"revision":"<uuid>","status":"production|draft","updated_at":"...","created_by":"..."}]`.

### `GET /api/v1/proxies/:id/revisions/diff`

Compare deux révisions d'un proxy. Paramètres : `from` (id de révision ou `"production"`) et `to` (id de révision ou `"latest"`).

Réponse :
```json
{
  "from": {"revision":"...","status":"production","updated_at":"...","created_by":"..."},
  "to":   {"revision":"...","status":"draft","updated_at":"...","created_by":"..."},
  "diffs": [{"key":"backends[0].addr","from":"10.0.0.1:8080","to":"10.0.0.2:8080"}],
  "revisions": [...]
}
```

---

### `GET /api/v1/backups/proxy-history/:proxyID`

Liste les versions sauvegardées (`proxy_history`, 50 dernières) d'un proxy — indépendant du système de révisions Core ci-dessus. Réponse : `[{"id","proxy_id","note","created_at"}]` (sans la config).

### `GET /api/v1/backups/proxy-history/:versionID/config`

Retourne la config brute (JSON) d'une version de l'historique — utilisé pour calculer un diff côté client entre deux versions, ou entre une version et la config actuelle.

### `POST /api/v1/backups/proxy-history/:versionID/restore`

Restaure la config de cette version sur le proxy.

---

## Certificats

### `GET /api/v1/certs`

Liste les certificats gérés.

### `POST /api/v1/certs/import`

Importe un certificat externe (non-ACME).

**Corps :**
```json
{
  "cert_pem": "-----BEGIN CERTIFICATE-----\n...",
  "key_pem":  "-----BEGIN PRIVATE KEY-----\n...",
  "issuer":   "custom"
}
```

Le domaine est extrait automatiquement depuis le SAN/CN du certificat. Upsert sur le domaine existant. Le cert est ensuite poussé aux Cores connectés.

**Réponse 201 :**
```json
{ "id": "abc123", "domain": "*.example.fr", "expires_at": "2027-09-15T00:00:00Z" }
```

### `GET /api/v1/certs/acme-monitor`

Retourne le statut d'expiration de tous les certificats.

**Réponse :**
```json
{
  "total": 5, "ok": 3, "warning": 1, "critical": 1, "expired": 0,
  "certs": [
    {
      "id": "abc123", "domain": "*.example.fr", "domain_id": "dom456", "issuer": "letsencrypt",
      "expires_at": "2026-10-15T00:00:00Z", "updated_at": "2026-09-15T02:00:00Z",
      "days_left": 26, "status": "warning", "dns_provider": "cloudflare", "cert_method": "dns"
    }
  ]
}
```

`status` : `ok` (>30j) · `warning` (≤30j) · `critical` (≤7j) · `expired`
`domain_id` référence `domains.id` (voir `GET/PUT /api/v1/domains/{id}`) — vide si le certificat n'a pas de domaine déclaré correspondant (ex. import manuel via `POST /api/v1/certs/import`).

### `GET /api/v1/acme/providers`

Liste les fournisseurs DNS ACME nommés. Admin uniquement.

**Réponse :**
```json
[
  { "id": "abc123", "name": "cloudflare-prod", "type": "cloudflare", "params": {"api_token": "..."} }
]
```

### `POST /api/v1/acme/providers`

Crée un nouveau fournisseur DNS nommé.

**Corps :**
```json
{ "name": "cloudflare-prod", "type": "cloudflare", "params": {"api_token": "tok_xxx"} }
```

**Réponse :** `201 Created` avec `{"id": "..."}`

### `GET /api/v1/acme/providers/{id}`

Retourne un fournisseur DNS par identifiant.

### `PUT /api/v1/acme/providers/{id}`

Met à jour un fournisseur DNS existant (même corps que POST).

### `DELETE /api/v1/acme/providers/{id}`

Supprime un fournisseur DNS nommé.

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

### `GET /api/v1/nodes/:id/tunnel-config`

Retourne la configuration Tunnel L4 mTLS du nœud. Réponse : `{"peers":[{"name":"core-b","addr":"10.0.0.2:9443"},...]}`.

### `PUT /api/v1/nodes/:id/tunnel-config`

Met à jour la liste des peers Tunnel L4 du nœud. Corps : `{"peers":[{"name":"...","addr":"..."}]}`. Déclenche un push WS `push_tunnel_config` vers le Core connecté pour application immédiate via `tunnel.Manager.SetPeers`.

---

## Sécurité

### `GET /api/v1/security/overview`

Compteurs globaux : `active_bans`, `active_threats`, `open_cves`, `critical_cves`, `avg_header_score`, `certs_expired`, `certs_expiring`.

### `GET /api/v1/security/bans`

Liste les bans. Paramètres : `active=true|false`, `limit`, `source` (`native|fail2ban|crowdsec`).

### `POST /api/v1/security/bans`

Crée un ban manuel. Corps : `{ "ip", "domain", "reason", "expires_at" }`.

### `DELETE /api/v1/security/bans/:id`

Supprime un ban par ID.

### `GET /api/v1/security/threats`

Liste les menaces CrowdSec (`security_threats`), triées par `last_seen_at` décroissant. Paramètre : `limit`. Une même menace (`ip`+`scenario`) est dédupliquée : chaque nouvelle occurrence rafraîchit `last_seen_at` et incrémente `occurrences` au lieu de créer une ligne ignorée à date figée. Chaque entrée inclut aussi `core_name` — le Core d'origine, résolu côté serveur depuis le token d'appairage à la réception (vide pour les données antérieures à cette colonne).

### `GET /api/v1/security/cves`

Liste les CVE détectées (`security_cves`). Paramètres : `status` (`open|ignored|fixed`), `critical=true` (CVSS ≥ 7). Chaque entrée inclut `core_name` — le Core d'origine ayant remonté la CVE (résolu côté serveur depuis le token d'appairage à la réception, vide pour les données antérieures à cette colonne). Vue Admin : agrégat de tous les Cores, colonne Core affichée. Vue Core : déjà filtrée sur ce Core via les backends de ses proxies, colonne masquée (redondante).

### `PATCH /api/v1/security/cves/:id`

Change le statut d'une CVE. Corps : `{ "status": "open|ignored|fixed" }`.

### `GET /api/v1/security/fail2ban` · `PUT /api/v1/security/fail2ban`

Lit ou met à jour la configuration Fail2Ban (`enabled`, `window_sec`, `max_errors`, `ban_duration_sec`, `whitelist`).

### `GET /api/v1/security/crowdsec` · `PUT /api/v1/security/crowdsec`

Lit ou met à jour la configuration CrowdSec (`enabled`, `api_url`, `api_key`).

### `POST /api/v1/security/crowdsec/sync`

Déclenche une synchronisation LAPI immédiate.

## Moteur de règles automatiques

### `GET /api/v1/rules-engine/rules`

Liste toutes les règles. Réponse : tableau `Rule[]`.

### `POST /api/v1/rules-engine/rules`

Crée une règle. Corps : `{ name, description, enabled, condition, action, cooldown_sec }`.

### `PUT /api/v1/rules-engine/rules/:id`

Met à jour une règle existante.

### `DELETE /api/v1/rules-engine/rules/:id`

Supprime une règle.

### `POST /api/v1/rules-engine/rules/:id/run`

Déclenche une évaluation immédiate. Paramètre : `?dry_run=true` (défaut). Réponse : `{ matched, action_taken, detail, error }`.

### `GET /api/v1/rules-engine/history`

Historique des exécutions. Paramètre : `limit`.

### `GET /api/v1/rules-engine/condition-types`

Liste les descripteurs de types de conditions disponibles (nom, paramètres, descriptions).

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

---

## Workspaces — `/api/v1/workspaces`

> Accès : admin / superadmin uniquement.

| Méthode | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/workspaces` | Liste tous les espaces de travail (avec compteurs membres/ressources) |
| POST | `/api/v1/workspaces` | Crée un espace (`name`, `description`) |
| GET | `/api/v1/workspaces/{id}` | Détail complet : membres + ressources |
| PUT | `/api/v1/workspaces/{id}` | Renomme / modifie la description |
| DELETE | `/api/v1/workspaces/{id}` | Supprime (en cascade membres + ressources) |
| POST | `/api/v1/workspaces/{id}/members` | Ajoute un membre (`entity_type`: `user`/`team`, `entity_id`) |
| DELETE | `/api/v1/workspaces/{id}/members/{type}/{entityID}` | Retire un membre |
| POST | `/api/v1/workspaces/{id}/resources` | Ajoute une ressource (`resource_type`: `proxy`/`domain`/`core`, `resource_id`) |
| DELETE | `/api/v1/workspaces/{id}/resources/{type}/{resourceID}` | Retire une ressource |

---

## Logs RGPD — `/api/v1/logs`

| Méthode | Endpoint | Scope requis | Description |
|---|---|---|---|
| GET | `/api/v1/logs/settings` | `logs:read` | Paramètres de rétention et de pseudonymisation |
| PUT | `/api/v1/logs/settings` | admin | Modifier rétention, `ip_anonymize`, `ip_pseudonymize` |
| POST | `/api/v1/logs/reveal-ip` | `gdpr:reveal` | Révéler l'IP réelle d'une entrée pseudonymisée |
| DELETE | `/api/v1/logs/by-ip/{ip}` | admin | Effacement RGPD Art.17 par IP |
| DELETE | `/api/v1/logs/by-user/{user_id}` | admin | Effacement RGPD Art.17 par utilisateur |

### POST `/api/v1/logs/reveal-ip`

Body :
```json
{ "entry_id": 4821, "reason": "Réquisition judiciaire n°2026/1234" }
```

Réponse `200` :
```json
{
  "entry_id": 4821,
  "ip": "203.0.113.42",
  "requested_by": "dpo@exemple.fr",
  "reason": "Réquisition judiciaire n°2026/1234",
  "ts": "2026-09-20T14:32:01Z"
}
```

Codes d'erreur :
- `403` — scope `gdpr:reveal` manquant
- `400` — `entry_id` ou `reason` manquant
- `422` — entrée non pseudonymisée ou clé non chargée
