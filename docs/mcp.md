# MCP Goproxify — Référence des outils et ressources

Le serveur MCP (Model Context Protocol) de Goproxify expose l'Administration à tout client compatible MCP (Claude Desktop, Claude Code, etc.). Il permet à un LLM de lire l'état de l'infrastructure et d'agir dessus sans passer par l'interface web.

**Endpoint :** `https://<admin-host>:9443/mcp`  
**Protocole :** MCP `2025-03-26`, JSON-RPC 2.0 over HTTP  
**Authentification :** `Authorization: Bearer <gpx_pat_…>` — token API utilisateur (PAT) créé depuis **Paramètres → Mes tokens API**. Le JWT de session UI n’est **pas** accepté sur `/mcp`.  
**SSE (streaming) :** `GET /mcp/sse` — keepalive toutes les 15 s

Les scopes du PAT (`proxies:read`, `nodes:read`, …) bornent les outils MCP ; l’autorisation effective est toujours l’intersection avec les droits actuels du compte.

---

## Connexion depuis Claude Desktop

1. Connectez-vous à l’Admin → **Paramètres → Mes tokens API** → créez un token avec les scopes nécessaires.
2. Copiez le secret `gpx_pat_…` (affiché une seule fois).
3. Ajoutez le bloc suivant dans `claude_desktop_config.json` :

```json
{
  "mcpServers": {
    "goproxify": {
      "url": "https://<admin-host>:9443/mcp",
      "headers": {
        "Authorization": "Bearer gpx_pat_<votre-token>"
      }
    }
  }
}
```

Depuis Claude Code (CLI) :

```bash
claude mcp add goproxify \
  --transport http \
  --url https://<admin-host>:9443/mcp \
  --header "Authorization: Bearer gpx_pat_<votre-token>"
```

---

## Outils (tools)

### `list_proxies`

Liste toutes les routes proxy configurées.

**Paramètres :** aucun

**Réponse exemple :**
```json
[
  {
    "id": "px_01abc",
    "name": "app.example.com",
    "enabled": true,
    "host": "app.example.com",
    "type": "http",
    "tls": true
  }
]
```

---

### `get_proxy`

Retourne la configuration complète d'un proxy.

| Paramètre | Type   | Requis | Description                          |
|-----------|--------|--------|--------------------------------------|
| `id`      | string | ✓      | ID, nom ou domaine du proxy          |

**Réponse :** objet JSON complet du proxy (backends, LB, headers, snippets…)

---

### `create_proxy`

Crée une nouvelle route proxy (HTTP, TCP ou UDP).

| Paramètre     | Type    | Requis | Description                                           |
|---------------|---------|--------|-------------------------------------------------------|
| `host`        | string  | ✓      | Domaine cible (ex : `app.example.com`)                 |
| `backend`     | string  | ✓      | URL du backend (ex : `http://10.0.0.5:3000`)          |
| `tls_enabled` | boolean | —      | Active HTTPS (défaut : `false`)                        |
| `type`        | string  | —      | `http` (défaut), `tcp`, `udp`                          |
| `lb`          | string  | —      | `round_robin` (défaut), `weighted`, `adaptive`         |

**Réponse exemple :**
```json
{ "id": "px_02def", "host": "app.example.com", "backend": "http://10.0.0.5:3000", "type": "http", "lb": "round_robin" }
```

---

### `update_proxy`

Met à jour un proxy existant (champs partiels).

| Paramètre     | Type    | Requis | Description                                    |
|---------------|---------|--------|------------------------------------------------|
| `id`          | string  | ✓      | ID, nom ou domaine du proxy                    |
| `host`        | string  | —      | Nouveau domaine                                |
| `backend`     | string  | —      | Remplace la liste `backends` par une URL       |
| `tls_enabled` | boolean | —      | Active ou désactive HTTPS                      |
| `lb`          | string  | —      | `round_robin`, `weighted`, `adaptive`          |
| `enabled`     | boolean | —      | Active ou désactive la route                   |

**Réponse :** `{ "id", "name", "enabled", "config" }`

---

### `set_proxy_enabled`

Active ou désactive un proxy sans modifier sa configuration.

| Paramètre | Type    | Requis | Description                         |
|-----------|---------|--------|-------------------------------------|
| `id`      | string  | ✓      | ID, nom ou domaine                  |
| `enabled` | boolean | ✓      | `true` = activer, `false` = couper  |

---

### `delete_proxy`

Supprime un proxy par son ID.

| Paramètre | Type   | Requis | Description              |
|-----------|--------|--------|--------------------------|
| `id`      | string | ✓      | ID du proxy à supprimer  |

**Réponse :** `{ "deleted": "px_01abc" }`

---

### `list_nodes`

Liste les nœuds Core et Agent avec leurs métriques en temps réel.

**Paramètres :** aucun

**Réponse exemple :**
```json
[
  {
    "id": "nd_01",
    "node_name": "core-eu-west",
    "role": "core",
    "version": "1.4.2",
    "status": "online",
    "cpu_pct": 12.5,
    "mem_pct": 38.2,
    "last_seen_at": "2026-08-02T10:00:00Z"
  }
]
```

---

### `list_agents`

Liste les Agents vus via le plan de contrôle WebSocket (`pending`, `approved`, `revoked`).

**Paramètres :** aucun  
**Scope :** `nodes:read`

**Réponse exemple :**
```json
[
  { "id": "agent-1", "name": "agent-1", "version": "0.3.0", "status": "pending", "seen_at": "2026-08-08T10:00:00Z" }
]
```

---

### `approve_agent`

Approuve un Agent en attente (broadcast `approve_agent` aux Cores).

| Paramètre | Type   | Requis | Description        |
|-----------|--------|--------|--------------------|
| `id`      | string | ✓      | ID de l'Agent      |

**Scope :** `nodes:read`

---

### `revoke_agent`

Révoque un Agent (ferme la session WS et invalide le HMAC).

| Paramètre | Type   | Requis | Description        |
|-----------|--------|--------|--------------------|
| `id`      | string | ✓      | ID de l'Agent      |

**Scope :** `nodes:read`

---

### `list_alerts`

Liste les règles d'alerting avec leurs déclencheurs et canaux de notification.

**Paramètres :** aucun

**Réponse exemple :**
```json
[
  {
    "id": "al_01",
    "name": "CPU critique",
    "enabled": true,
    "scope": {},
    "triggers": ["cpu_pct > 90"],
    "channels": ["email-ops"],
    "cooldown_sec": 300,
    "priority": 1
  }
]
```

---

### `get_metrics`

Retourne les KPIs de trafic des dernières 24 heures.

| Paramètre | Type   | Requis | Description                                             |
|-----------|--------|--------|---------------------------------------------------------|
| `proxy`   | string | —      | Domaine à filtrer (laisser vide = tout le trafic)       |

**Réponse exemple :**
```json
{
  "requests": 142800,
  "errors": 214,
  "error_rate": 0.15,
  "avg_latency_ms": 42,
  "unique_ips": 3812,
  "window": "24h"
}
```

---

### `list_backups`

Liste les 20 derniers snapshots de sauvegarde.

**Paramètres :** aucun

**Réponse exemple :**
```json
[
  {
    "id": "bk_01",
    "name": "backup-2026-08-02",
    "size_bytes": 2097152,
    "created_at": "2026-08-02T03:00:00Z"
  }
]
```

---

### `list_users`

Liste les comptes utilisateurs avec leur rôle. Les données sensibles (hash du mot de passe) ne sont jamais exposées.

**Paramètres :** aucun

**Réponse exemple :**
```json
[
  { "id": "usr_01", "email": "admin@example.fr", "role": "superadmin", "created_at": "2026-01-10T08:00:00Z" },
  { "id": "usr_02", "email": "ops@example.fr",   "role": "operator",   "created_at": "2026-02-15T09:30:00Z" }
]
```

**Rôles possibles :** `superadmin`, `admin`, `operator`, `viewer`

---

### `list_snippets`

Liste les snippets middleware réutilisables (rate-limit, en-têtes de sécurité, authentification…).

**Paramètres :** aucun

**Réponse exemple :**
```json
[
  {
    "id": "sn_01",
    "name": "rate-limit-api",
    "type": "rate_limit",
    "config": { "requests_per_second": 100, "burst": 200 },
    "created_at": "2026-03-01T10:00:00Z"
  }
]
```

---

### `list_domains`

Liste les domaines gérés avec leur fournisseur DNS et l'état du certificat.

**Paramètres :** aucun

**Réponse exemple :**
```json
[
  {
    "id": "dm_01",
    "domain": "example.fr",
    "core_id": "nd_01",
    "dns_provider": "cloudflare",
    "cert_method": "dns",
    "delegation_mode": "passthrough",
    "cert_expires_at": "2026-11-01T00:00:00Z",
    "created_at": "2026-01-01T00:00:00Z"
  }
]
```

`delegation_mode` : `passthrough` (tunnel TLS) ou `terminate` (TLS sur le Core d'entrée + proxy HTTP(S)). Voir [delegation.md](delegation.md).

---

### `list_certs`

Liste les certificats TLS gérés avec leur émetteur et leur durée de validité restante.

**Paramètres :** aucun

**Réponse exemple :**
```json
[
  {
    "id": "ct_01",
    "domain": "app.example.fr",
    "issuer": "Let's Encrypt",
    "expires_at": "2026-11-01T00:00:00Z",
    "days_until_expiry": 91,
    "updated_at": "2026-08-01T04:00:00Z"
  }
]
```

Un `days_until_expiry` négatif indique un certificat expiré.

---

### `list_logs`

Retourne les 100 derniers logs d'accès, filtrables par domaine et niveau.

| Paramètre | Type   | Requis | Description                                           |
|-----------|--------|--------|-------------------------------------------------------|
| `domain`  | string | —      | Filtrer par domaine proxy                             |
| `level`   | string | —      | Filtrer par niveau : `info`, `warn`, `error`          |

**Réponse exemple :**
```json
[
  {
    "ts": "2026-08-02T10:01:05Z",
    "level": "info",
    "component": "core",
    "domain": "app.example.fr",
    "method": "GET",
    "path": "/api/users",
    "status": 200,
    "ip": "1.2.3.4",
    "latency_ms": 38,
    "message": ""
  }
]
```

---

### `list_teams`

Liste les équipes avec leur nombre de membres.

**Paramètres :** aucun

**Réponse exemple :**
```json
[
  { "id": "tm_01", "name": "ops-eu", "member_count": 4, "created_at": "2026-02-01T00:00:00Z" }
]
```

---

### `get_audit_log`

Retourne le journal d'audit des actions administratives.

| Paramètre | Type   | Requis | Description                                     |
|-----------|--------|--------|-------------------------------------------------|
| `limit`   | number | —      | Nombre d'entrées (défaut : 50, max : 200)        |

**Réponse exemple :**
```json
[
  {
    "actor": "admin@example.fr",
    "action": "delete",
    "resource": "proxy/px_01abc",
    "detail": "suppression proxy app.example.com",
    "severity": "warn",
    "created_at": "2026-08-02T09:55:00Z"
  }
]
```

---

### `get_security_overview`

Compteurs sécurité : bans actifs, menaces CrowdSec, CVE ouvertes, certificats expirant sous 30 jours.

**Paramètres :** aucun  
**Scope :** `audit:read` (même mapping que `/api/v1/security`)

---

### `list_security_bans`

Liste les bans IP (Fail2Ban, CrowdSec, natif).

| Paramètre      | Type    | Requis | Description                                      |
|----------------|---------|--------|--------------------------------------------------|
| `ip`           | string  | —      | Filtrer par IP (sous-chaîne)                     |
| `source`       | string  | —      | `native`, `fail2ban`, `crowdsec`                 |
| `active_only`  | boolean | —      | Uniquement les bans non expirés                  |

---

### `create_security_ban`

Crée un ban IP natif (**permanent** si `expires_at` omis) et pousse les bans aux Cores.

| Paramètre     | Type   | Requis | Description                         |
|---------------|--------|--------|-------------------------------------|
| `ip`          | string | ✓      | Adresse IP                          |
| `reason`      | string | —      | Motif                               |
| `domain`      | string | —      | Domaine ciblé (vide = global)       |
| `expires_at`  | string | —      | Expiration RFC3339 ; omit = permanent |

---

### `delete_security_ban`

| Paramètre | Type   | Requis | Description   |
|-----------|--------|--------|---------------|
| `id`      | string | ✓      | ID du ban     |

---

### `list_security_threats`

Décisions CrowdSec synchronisées (`security_threats`).

| Paramètre | Type   | Requis | Description                          |
|-----------|--------|--------|--------------------------------------|
| `limit`   | number | —      | Défaut 100, max 500                  |

---

### `list_security_cves`

CVE détectées sur les backends.

| Paramètre         | Type    | Requis | Description                          |
|-------------------|---------|--------|--------------------------------------|
| `status`          | string  | —      | `open`, `ignored`, `resolved`        |
| `critical_only`   | boolean | —      | CVSS ≥ 7 uniquement                  |

---

## Infrastructure / wizard architecture

Scopes PAT : `nodes:read` (lecture) / `nodes:write` (écriture). Alignés sur `/api/v1/declared-nodes`, `/api/v1/bootstrap-tickets`, `/api/v1/nodes/{id}/accept|reject`.

### `list_declared_nodes`

Liste les nœuds déclarés (toile architecture) pas encore connectés.

**Paramètres :** aucun

---

### `create_declared_node`

Déclare (ou met à jour) un nœud Core/Agent pour le suivi wizard / auto-accept.

| Paramètre       | Type   | Requis | Description                |
|-----------------|--------|--------|----------------------------|
| `role`          | string | ✓      | `core` ou `agent`          |
| `name`          | string | ✓      | Nom du nœud                |
| `region`        | string | —      | Région                     |
| `environment`   | string | —      | Environnement              |
| `config`        | object | —      | Config JSON libre          |

---

### `delete_declared_node`

| Paramètre | Type   | Requis | Description        |
|-----------|--------|--------|--------------------|
| `id`      | string | ✓      | ID (`dn_…`)        |

---

### `create_bootstrap_ticket`

Crée un ticket one-shot : URL `/i/{token}`, script `.sh`, QR PNG, commande `curl|bash`.

| Paramètre         | Type    | Requis | Description                          |
|-------------------|---------|--------|--------------------------------------|
| `host_name`       | string  | —      | Nom d’hôte affiché                   |
| `core_endpoint`   | string  | —      | Endpoint Core cible                  |
| `payload`         | object  | —      | Payload JSON (compose / options)     |
| `ttl_hours`       | number  | —      | 1–168 (défaut 24)                    |
| `auto_accept`     | boolean | —      | Auto-accept des nœuds liés (défaut true) |
| `node_names`      | array   | —      | Noms de nœuds pour l’auto-accept     |

---

### `accept_node` / `reject_node`

Accepte ou rejette un nœud en attente (`pending_nodes`) après présentation du pairing secret.

| Paramètre | Type   | Requis | Description              |
|-----------|--------|--------|--------------------------|
| `id`      | string | ✓      | ID du nœud pending       |

---

## GoProxify Access (portail)

Scopes PAT : `portal:read` (lecture) / `portal:write` (écriture + push). Réservés aux rôles admin.

### `get_portal_config` / `update_portal_config` / `push_portal`

| Paramètre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `core` | string | ✓ | Nom du nœud Core |
| `enabled`, `ssh_port`, `http_port`, `public_host`, `allow_personal_targets`, `require_2fa`, `session_ttl_sec`, `session_mode` | — | — | Champs optionnels pour `update_portal_config` |

### Catalogue — `list_portal_destinations`, `create_portal_destination`, `update_portal_destination`, `delete_portal_destination`, `preview_portal_destinations`

Création / mise à jour : `core_name`, `name`, `kind` (`ssh`\|`docker`), `host`, `port`, `agent_name`, `container`, `tags`.

### Users — `list_portal_users`, `invite_portal_user`, `update_portal_user`, `delete_portal_user`, `resend_portal_invite`

Invitation : `email`, `home_core`, `tags` (SMTP Admin requis).

### `list_portal_audit`

| Paramètre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `core` | string | — | Filtrer par Core |
| `limit` | number | — | Défaut 100, max 500 |

### Templates — `list_portal_templates`, `get_portal_template`, `upsert_portal_template`, `delete_portal_template`, `push_portal_templates`

Clés stables (`login`, `vault`, …). `upsert` : `key`, `body`, `name` optionnel.

---

## Ressources (resources)

Les ressources permettent à un client MCP d'accéder aux données sans construire d'appel d'outil explicite.

| URI                            | Description                              |
|--------------------------------|------------------------------------------|
| `goproxify://proxies`          | Liste de toutes les routes proxy         |
| `goproxify://nodes`            | Nœuds Core et Agent                      |
| `goproxify://agents`           | Agents WS (pending / approved)           |
| `goproxify://alerts`           | Règles d'alerting                        |
| `goproxify://users`            | Comptes utilisateurs et rôles            |
| `goproxify://snippets`         | Middlewares réutilisables                |
| `goproxify://domains`          | Domaines gérés et état TLS               |
| `goproxify://certs`            | Certificats TLS et expiration            |
| `goproxify://logs`             | 100 derniers logs d'accès                |
| `goproxify://security/bans`    | Bans IP actifs                           |
| `goproxify://security/threats` | Décisions CrowdSec                       |
| `goproxify://security/cves`    | CVE ouvertes                             |
| `goproxify://portal/destinations` | Catalogue destinations Access         |
| `goproxify://portal/users`     | Utilisateurs Access                      |
| `goproxify://portal/templates` | Templates HTML Access                    |
| `goproxify://portal/audit`     | Journal d'audit Access                   |
| `goproxify://declared-nodes`   | Nœuds déclarés (wizard architecture)     |

Toutes les ressources retournent `mimeType: application/json`.

---

## Gestion des erreurs

Les erreurs suivent le standard JSON-RPC 2.0 :

| Code    | Signification            |
|---------|--------------------------|
| -32700  | Erreur de décodage JSON  |
| -32601  | Méthode ou outil inconnu |
| -32602  | Paramètres invalides     |
| -32603  | Erreur interne           |
| -32002  | Ressource introuvable    |

Les erreurs d'outil (proxy introuvable, backend SQL) sont retournées avec `isError: true` dans le contenu, sans code d'erreur JSON-RPC — le LLM reçoit le message et peut proposer une correction.
