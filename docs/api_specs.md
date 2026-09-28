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

Génère un token cryptographique pour une passerelle ou un Agent.

**Corps :**
```json
{ "role": "edge", "node": "serveur-production-1", "ttl": "0" }
```

`role` : `edge` | `agent`
`ttl` : durée de validité (ex: `"24h"`) ou `"0"` pour permanent.

**Réponse 201 :**
```json
{
  "token": "gpx_edge_a1b2c3d4e5f6...",
  "node": "serveur-production-1",
  "role": "edge",
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

### `PATCH /api/v1/proxies/{id}`

Corps `{"enabled": bool}`. Active/désactive le proxy (republié sur toutes les passerelles qui l'hébergent). Utilisé notamment par la Vue Proxy pour « Mettre en maintenance » / « Réactiver ».

### `POST /api/v1/proxies/{id}/cache/purge`

Vide le cache disque de ce proxy sur toutes les passerelles qui l'hébergent (best-effort, un proxy peut être répliqué sur plusieurs Edges). No-op si le cache n'est pas activé pour ce proxy. Réponse `{"purged": <nombre d'entrées supprimées>}`. Relaie en interne `POST /internal/v1/proxies/{id}/cache/purge` sur chaque Edge (le cache est stocké par route, un répertoire dédié par proxy — voir `router.Route.Cache`).

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

### `GET /api/v1/metrics/proxies`

Débit, erreurs et latence **par host**, avec un historique récent. L'Admin relève toutes les
passerelles actives toutes les 10 s (`GET /internal/v1/metrics/summary`), calcule la différence
entre deux relevés successifs (une remise à zéro des compteurs après redémarrage est détectée),
additionne les passerelles et garde 1 h de série par host **en mémoire** : la série repart de zéro
au redémarrage de l'Admin. Scope PAT : `metrics:read`.

| Paramètre | Description |
|-----------|-------------|
| `points`  | Nombre de points de la série (défaut 60, max 360 ; un point = 10 s) |

**Réponse 200 :**
```json
{
  "interval_s": 10,
  "sampled_at": "2026-09-26T13:11:37+02:00",
  "proxies": [
    {
      "host": "myapp.example.fr",
      "requests_per_second": 3.8,
      "error_rate": 0.002,
      "p95_ms": 9.3,
      "series": [3.7, 4.0, 3.8]
    }
  ]
}
```

`error_rate` est une **fraction** (0..1) de réponses 5xx sur le dernier intervalle ; `p95_ms` est le
p95 de la latence sur ce même intervalle ; `series` est le débit (req/s) des derniers relevés, du
plus ancien au plus récent. `proxies` est vide (et `sampled_at` nul) tant qu'aucune passerelle n'a
été relevée deux fois.

En plus des séries par host, la réponse porte les agrégats du tableau de bord :

```json
{
  "global": { "requests_per_second": 4.0, "error_rate_5xx": 0.0, "bytes_in_total": 0, "bytes_out_total": 1005480 },
  "edges": [ { "edge_name": "localhost", "requests_per_second": 4.0, "p95_ms": 9.5 } ],
  "tls": { "certs": [ { "domain": "myapp.example.fr", "expires_in_seconds": 5184000 } ] }
}
```

`global` = débit et taux de 5xx du dernier intervalle, toutes passerelles et tous hosts confondus ;
`bytes_*_total` = octets cumulés depuis le démarrage des passerelles ; `edges` = dernier intervalle
par passerelle ; `tls.certs` = plus proche expiration par domaine, lue dans les métriques des passerelles.

### `GET /api/v1/metrics/summary`

Synthèse lue par les pages Dashboard, Prism, Domaines/TLS, Infrastructure, Portail et Sécurité :
agrégats du dernier relevé des passerelles (voir `GET /api/v1/metrics/proxies`) et métriques du
processus Admin. Une section est **absente** tant que sa source n'a rien publié. Scope PAT : `metrics:read`.

| Clé | Contenu |
|-----|---------|
| `global`, `edges`, `tls.certs` | comme `/metrics/proxies` ; chaque entrée de `tls.certs` porte en plus `handshake_p95_ms` (pire passerelle) et `active_connections` (somme) quand le domaine a servi des connexions TLS ; `edges[]` ajoute `error_rate` (fraction) |
| `ws` | `admin_connections`, `agent_connections` — connexions WebSocket du plan de contrôle, somme des passerelles |
| `peers` | `avg_sync_ms` — durée moyenne de synchronisation entre passerelles pairs (absent sans pair) |
| `portal.sessions` | `one_shot`, `multi` — sessions du portail actives |
| `waf` | `profiles_active` — profils comportementaux en mémoire |
| `pipeline` | `[{stage, blocked_total}]` — requêtes bloquées par étape du pipeline de sécurité |
| `f2b` | `bans_total`, `scans_total` — Fail2Ban (processus Admin) |
| `crowdsec` | `decisions_new`, `decisions_deleted` — CrowdSec (processus Admin) |
| `rules_engine` | `active_rules`, `actions_total`, `avg_duration_ms`, `evals_per_minute` (nul sans deux relevés) — moteur de règles |

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

Liste les versions sauvegardées (`proxy_history`, 50 dernières) d'un proxy — indépendant du système de révisions passerelle ci-dessus. Réponse : `[{"id","proxy_id","note","created_at"}]` (sans la config).

### `GET /api/v1/backups/proxy-history/:versionID/config`

Retourne la config brute (JSON) d'une version de l'historique — utilisé pour calculer un diff côté client entre deux versions, ou entre une version et la config actuelle.

### `POST /api/v1/backups/proxy-history/:versionID/restore`

Restaure la config de cette version sur le proxy.

---

## Sauvegardes & imports

Contenu détaillé : [sauvegardes.md](sauvegardes.md).

### `POST /api/v1/backups/snapshots/:id/restore`

Restaure un snapshot. Corps optionnel `{"selection": {…}}` (mêmes champs que `import/backup/apply`) ; **sans corps**, restauration complète en mode `overwrite` (utilisateurs, tokens, PAT, snippets, canaux, règles, tables de configuration). En `overwrite`, un snapshot de sécurité `avant-restauration-<date>` est pris d'abord ; s'il échoue, la restauration est annulée (500). Réponse : `ImportResult`.

### `POST /api/v1/import/backup/preview`

Corps : JSON de sauvegarde (32 Mo max). Réponse : résumé (`proxies[]`, `user_count`, `token_count`, `pat_count`, `snippet_count`, `channel_count`, `rule_count`, `declared_node_count`, `config_row_count`, `config_tables{table: n}`). Une `version` ≠ `1` est refusée (400).

### `POST /api/v1/import/backup/apply`

Corps : `{"data": <sauvegarde>, "selection": {"proxy_ids", "import_users", "import_tokens", "import_pats", "import_snippets", "import_alert_channels", "import_alert_rules", "import_config", "on_conflict": "skip|overwrite"}}` (32 Mo max). En `overwrite`, un snapshot `avant-import-<date>` est pris d'abord. Réponse : `{proxies, users, tokens, pats, snippets, channels, rules, config, declared_nodes, skipped, errors}`.
---

## Certificats

### `GET /api/v1/certs`

Liste les certificats gérés.

### `GET /api/v1/certs/{domain}/pem`

Renvoie le certificat public (PEM, `Content-Type: application/x-pem-file`) d'un domaine géré. La clé privée n'est jamais exposée. `404` si le domaine n'a pas de certificat.

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

Le domaine est extrait automatiquement depuis le SAN/CN du certificat. Upsert sur le domaine existant. Le cert est ensuite poussé aux passerelles connectées.

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

## CA interne — `/api/v1/internal-ca`

Génération et gestion d'une autorité de certification interne (hors ACME), pour émettre des certificats serveur/client internes. Admin uniquement.

### `GET /api/v1/internal-ca`

Liste les autorités internes.

**Réponse :**
```json
[
  { "id": "abc123", "name": "root", "subject": "GoProxify Internal Root", "cert_pem": "-----BEGIN CERTIFICATE-----\n...", "not_after": "2036-09-24T00:00:00Z", "created_at": "2026-09-24T00:00:00Z" }
]
```

### `POST /api/v1/internal-ca`

Crée une nouvelle CA racine auto-signée (clé ECDSA P-256).

**Corps :**
```json
{ "name": "root", "common_name": "GoProxify Internal Root", "validity_years": 10 }
```

**Réponse 201 :** objet CA (voir ci-dessus).

### `GET /api/v1/internal-ca/{id}/certs`

Liste les certificats émis par la CA `{id}`.

**Réponse :**
```json
[
  { "id": "cert123", "ca_id": "abc123", "common_name": "svc.internal.local", "usage": "server",
    "sans": ["svc.internal.local", "10.0.0.5"], "serial": "1a2b3c...", "cert_pem": "-----BEGIN CERTIFICATE-----\n...",
    "not_after": "2027-10-26T00:00:00Z", "revoked": false, "created_at": "2026-09-24T00:00:00Z" }
]
```

### `POST /api/v1/internal-ca/{id}/certs`

Émet un certificat serveur ou client signé par la CA `{id}`.

**Corps :**
```json
{ "common_name": "svc.internal.local", "sans": ["svc.internal.local", "10.0.0.5"], "usage": "server", "validity_days": 397 }
```

`usage` : `server` (`ExtKeyUsageServerAuth`) ou `client` (`ExtKeyUsageClientAuth`).

**Réponse 201 :** objet certificat (voir ci-dessus).

### `DELETE /api/v1/internal-ca/{id}/certs/{certID}`

Révoque un certificat émis (marqué `revoked`, ne supprime pas la ligne).

---

## Profils IP

### `GET /api/v1/ip-profiles` · `GET /api/v1/ip-profiles/:id`

Liste / détail des profils IP (`id`, `name`, `profile_type`, `mode`, `feed_urls`, `feed_format`, `refresh_interval_h`, `cidrs`, `enabled`, `last_updated_at`…). Champs d'état du rafraîchissement automatique :

| Champ | Description |
|---|---|
| `last_updated_at` | Dernier rafraîchissement **réussi** (un échec ne le modifie pas) |
| `last_error` | Cause du dernier échec ; absent après un succès |
| `consecutive_failures` | Nombre d'échecs consécutifs ; absent (0) après un succès |
| `next_attempt_at` | Prochaine tentative automatique (UTC) après un échec ; absent sinon |

Après un échec (réseau, HTTP ≠ 200, parsing, liste rejetée par le garde-fou), les CIDRs déjà stockés restent appliqués et le profil est retenté avec un délai de 15 min doublé à chaque échec, plafonné à 6 h et à `refresh_interval_h`.

### `POST /api/v1/ip-profiles/:id/refresh`

Force un rafraîchissement complet (téléchargement inconditionnel, garde-fou de taille ignoré). `200 {"status":"refreshed"}`, ou `400 {"error":…}` en cas d'échec (profil sans feed, feed injoignable…). Le rafraîchissement automatique rejette une nouvelle liste qui perd plus de la moitié d'une liste d'au moins 10 entrées (feed vide ou tronqué) : la liste actuelle est conservée et l'échec est enregistré ; ce endpoint permet de l'accepter.

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

## Nodes (Passerelles & Agents enregistrés)

### `GET /api/v1/nodes`

Liste les passerelles et Agents enregistrés avec leur état.

**Réponse 200 :**
```json
[
  {
    "id": "edge-1",
    "role": "edge",
    "node": "serveur-production-1",
    "ip": "203.0.113.10",
    "status": "healthy",
    "last_seen": "2026-07-15T23:54:00Z"
  }
]
```

### `GET /api/v1/nodes/live`

État temps réel de la topologie : santé, débit et risque de chaque passerelle et Agent. Scope PAT : `nodes:read`. L'UI (Infrastructure → Topologie) l'interroge toutes les 5 s.

**Réponse 200 :**
```json
{
  "window_sec": 60,
  "generated_at": "2026-09-24T20:40:00Z",
  "bans_active": 12,
  "nodes": [
    {
      "node_name": "edge-a", "role": "edge", "status": "online",
      "cpu_pct": 12.5, "mem_pct": 40.1,
      "requests": 600, "rps": 10, "blocked_pct": 33.3, "error_pct": 0,
      "low_traffic": false,
      "risk": 67, "risk_level": "high", "risk_factor": "blocked"
    }
  ]
}
```

Débit et taux viennent des access logs de la dernière minute (`window_sec`), par `node_name`, hors logs de l'Admin. `blocked_pct` = part de `403`/`429`, `error_pct` = part de `5xx`.

**Score de risque (0-100)** : le plus élevé de plusieurs facteurs indépendants, pour que la cause reste lisible (`risk_factor`) :

| Facteur | Score |
|---|---|
| `offline` | 100 si le nœud n'est pas `online` |
| `blocked` | 2 × `blocked_pct` (50 % de refus = 100) |
| `errors` | 4 × `error_pct` (25 % d'erreurs = 100) |
| `resources` | CPU ou mémoire : 0 à 70 %, 100 à 100 % |

`risk_level` : `low` (< 25), `medium` (< 60), `high`. Sous 20 requêtes dans la fenêtre (`low_traffic`), les taux `blocked` et `errors` sont ignorés (bruit statistique). `bans_active` est global (il compte tous les bans, sans filtre par passerelle).

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

Approuve un Agent en attente. La passerelle lui envoie immédiatement son `agent_hmac` via la connexion WS active.

**Réponse 200 :**
```json
{ "approved": true }
```

---

## Nœuds déclarés & tickets bootstrap

### `GET /api/v1/declared-nodes`

Liste les nœuds déclarés via le wizard architecture (pas encore connectés, ou reprise de nœuds live).

### `POST /api/v1/declared-nodes`

Déclare un nœud (`role`: `edge`|`agent`, `name`, `region`, `environment`, `config`). Upsert par `(role, name)`.

### `DELETE /api/v1/declared-nodes/:id`

Supprime un nœud déclaré.

### `GET /api/v1/architecture` `[AUTH]`

Rôle admin requis. Retourne le contenu de `architecture.json`, référentiel de la topologie : c'est la source de la vue Infrastructure et du wizard (l'état live n'est qu'une surcouche). Fichier absent = architecture vide.

**Réponse :**
```json
{
  "schema_version": 1,
  "nodes": [
    {"id": "dn_1", "role": "edge", "name": "edge-1", "region": "eu-west",
     "config": {"host": "vps-paris", "internet_exposed": true, "cluster": true, "cluster_group": "ha-1"}}
  ],
  "domains": []
}
```

`config.host` est le nom de l'hôte qui porte le nœud ; les nœuds qui partagent un `host` sont posés sur la même machine.

### `GET /api/v1/architecture/groups` `[AUTH]`

Groupes HA déclarés par le wizard (`config.cluster: true` et `config.cluster_group`) : nom du groupe → membres `{id, name}`. Lecture seule, sans secret ; l'UI s'en sert pour indiquer qu'un réglage de sécurité s'applique à tout le groupe.

### `GET /api/v1/architecture/versions/{name}` `[AUTH]`

Rôle admin requis. Lit une version conservée (même format que `GET /api/v1/architecture`) sans la restaurer. Un nom qui n'est pas une version conservée renvoie `404`.

### `GET /api/v1/architecture/versions` `[AUTH]`

Rôle admin requis. Liste les versions conservées de `architecture.json` (la plus récente d'abord). Une version est enregistrée à chaque écriture qui change le fichier (50 conservées).

**Réponse :**
```json
[{"name": "architecture-20260926T070623359846127Z.json", "saved_at": "2026-09-26T07:06:23Z", "size": 384}]
```

### `POST /api/v1/architecture/restore` `[AUTH]`

Rôle admin requis. Remet en place une version conservée, réaligne la base dessus et reconnecte les passerelles qu'elle décrit. L'état remplacé est lui-même conservé : une restauration est réversible.

**Body :** `{"name": "architecture-20260926T070623359846127Z.json"}`

**Réponse :** `{"restored": "<name>", "applied": {"declared": 2, "removed": 0, "scopes": 0, "domains": 0}}`. Un nom qui n'est pas une version conservée renvoie `404`.

### `POST /api/v1/bootstrap-tickets` `[AUTH]`

Crée un ticket one-shot pour intégrer un hôte (QR + lien + script).

**Body :**
```json
{
  "host_name": "host-1",
  "edge_endpoint": "http://192.0.2.10:8000",
  "payload": {},
  "ttl_hours": 24,
  "auto_accept": true,
  "node_names": ["edge-main"]
}
```

**Réponse 200 :** `token`, `url` (`/i/{token}`), `script_url`, `install_cmd`, `qr_code` (PNG data URL), `expires_at`.

### `GET /i/{token}` / `GET /i/{token}.sh` / `GET /api/v1/bootstrap/{token}` `[PUBLIC]`

Page HTML, script bash (`docker compose up -d`), ou JSON public du ticket.

### `POST /api/v1/nodes/:id/accept` / `POST /api/v1/nodes/:id/reject`

Accepte ou rejette un nœud en attente (`pending_nodes`) après présentation du pairing secret.

### `GET /api/v1/nodes/:id/tunnel-config`

Retourne la configuration Tunnel L4 mTLS du nœud. Réponse : `{"peers":[{"name":"edge-b","addr":"10.0.0.2:9443"},...]}`.

### `PUT /api/v1/nodes/:id/tunnel-config`

Met à jour la liste des peers Tunnel L4 du nœud. Corps : `{"peers":[{"name":"...","addr":"..."}]}`. Déclenche un push WS `push_tunnel_config` vers la passerelle connectée pour application immédiate via `tunnel.Manager.SetPeers`.

---

## Sécurité

### `GET /api/v1/security/overview`

Compteurs globaux : `active_bans`, `active_threats`, `open_cves`, `critical_cves`, `avg_header_score`, `certs_expired`, `certs_expiring`. `headers[].checks[]` (contrôles de posture par proxy) porte depuis Admin `0.52.4` un champ `key` (identifiant stable non traduit, ex. `"tls"`, `"waf"`) en plus de `name` (toujours en français) : le frontend traduit l'affichage depuis `key` et ne retombe sur `name` que pour des données mises en cache avant son ajout.

### `GET /api/v1/security/bans`

Liste les bans (500 au plus, du plus récent au plus ancien). Paramètres : `active=true` (non expirés) ou `active=false` (expirés uniquement), `ip` (sous-chaîne), `domain`, `source` (`native|fail2ban|crowdsec|threat|rules_engine:<nœud>`), `edge` (nom du nœud ou id du token : les bans de cette passerelle **et** les bans globaux). Chaque entrée porte `edge_name`, la passerelle d'origine (vide = ban global : créé depuis l'Admin ou antérieur à cette colonne).

`GET /security/bans/countries`, `GET /security/bans/export` (CSV ou JSON, colonne `edge_name` ajoutée) et `GET /security/bans/intel/{kpis,by-reason,by-source,timeline,top-ips}` acceptent le même paramètre `edge`. `intel/kpis` renvoie `recurring_ips`, le nombre d'IP ayant au moins 3 bans.

### `POST /api/v1/security/bans`

Crée un ban manuel. Corps : `{ "ip", "domain", "reason", "expires_at" }`.

### `DELETE /api/v1/security/bans/:id`

Supprime un ban par ID.

### `GET /api/v1/security/threats`

Liste les menaces CrowdSec (`security_threats`), triées par `last_seen_at` décroissant. Paramètre : `limit`. Une même menace (`ip`+`scenario`) est dédupliquée : chaque nouvelle occurrence rafraîchit `last_seen_at` et incrémente `occurrences` au lieu de créer une ligne ignorée à date figée. Chaque entrée inclut aussi `edge_name` — la passerelle d'origine, résolu côté serveur depuis le token d'appairage à la réception (vide pour les données antérieures à cette colonne).

### `GET /api/v1/security/cves`

Liste les CVE détectées (`security_cves`). Paramètres : `status` (`open|ignored|fixed`), `critical=true` (CVSS ≥ 7). Chaque entrée inclut `edge_name` — la passerelle d'origine ayant remonté la CVE (résolu côté serveur depuis le token d'appairage à la réception, vide pour les données antérieures à cette colonne). Vue Admin : agrégat de toutes les passerelles, colonne passerelle affichée. Vue passerelle : déjà filtrée sur cette passerelle via les backends de ses proxies, colonne masquée (redondante).

Depuis Admin `0.52.3`, chaque entrée inclut aussi :
- `kev` (bool) — exploitation activement observée (catalogue CISA Known Exploited Vulnerabilities), rafraîchi en fin de scan (`internal/admin/vulnscan`), catalogue entier mis en cache 24h en mémoire.
- `epss_score` (0-1) et `epss_updated_at` — probabilité d'exploitation sous 30 jours (modèle EPSS, FIRST.org), rafraîchi en fin de scan par lots de 100 CVE.
- `sla_days` et `sla_due_at` — délai de correction attendu et échéance calculée (`detected_at` + `sla_days`), selon la gravité CVSS et le réglage `GET/PUT /api/v1/security/sla-config`. Recalculés à la lecture (jamais stockés), pour refléter immédiatement un changement de seuils. Non significatifs si `status != "open"`.

Les deux enrichissements (KEV, EPSS) sont du meilleur effort : un réseau externe indisponible au moment du scan laisse simplement `kev=false` / `epss_score=0` sans faire échouer le scan.

### `PATCH /api/v1/security/cves/:id`

Change le statut d'une CVE. Corps : `{ "status": "open|ignored|fixed" }`.

### `GET /api/v1/security/sla-config` · `PUT /api/v1/security/sla-config`

Délai de correction attendu (en jours après détection), par tranche de gravité CVSS — réglage global (pas de portée par passerelle : la politique de correction est la même pour tout le parc). Corps / réponse : `{ "critical_days": 7, "high_days": 14, "medium_days": 30, "low_days": 90 }` (CVSS ≥ 9 / ≥ 7 / ≥ 4 / < 4). Valeurs par défaut si le réglage n'a jamais été enregistré ; une valeur ≤ 0 envoyée au `PUT` retombe sur son défaut plutôt que d'être acceptée telle quelle.

### `GET /api/v1/security/fail2ban` · `PUT /api/v1/security/fail2ban`

Lit ou met à jour la configuration Fail2Ban (`enabled`, `window_sec`, `max_errors`, `ban_duration_sec`, `whitelist`).

### `GET /api/v1/security/crowdsec` · `PUT /api/v1/security/crowdsec`

Lit ou met à jour la configuration CrowdSec (`enabled`, `api_url`, `api_key`).

### `POST /api/v1/security/crowdsec/sync`

Déclenche une synchronisation LAPI immédiate.

### `GET /api/v1/security/threat-config` · `PUT /api/v1/security/threat-config`

Configuration du moteur Sentinel. Paramètre optionnel `edge=<id ou nom>` :

- passerelle **membre d'un groupe HA** (déclaré dans `architecture.json`, `config.cluster` + `config.cluster_group`) : la configuration est **celle du groupe** — lue et écrite une seule fois, poussée à tous les membres, et rejouée à la connexion d'un membre qui la manquait ;
- passerelle hors groupe : configuration propre à la passerelle ;
- sans `edge` : configuration globale.

Lecture : valeur du groupe, sinon valeur propre à la passerelle (antérieure aux groupes), sinon globale. Au démarrage, la valeur d'un groupe qui n'en a pas encore est reprise du premier membre (dans l'ordre d'`architecture.json`) qui en avait une ; un désaccord entre membres est signalé dans le log de l'Admin, jamais écrasé.

### `POST /api/v1/security/threat-config/simulate`

Dry-run Sentinel depuis l'interface (bouton « Simuler » du tiroir de réglages) : rejoue les access logs récents contre une config candidate et la compare à la config actuelle, **sans rien enregistrer ni pousser**. Même moteur et même réponse que l'outil MCP `simulate_sentinel_config`. Paramètre optionnel `edge=<id ou nom>` (même règle de portée que `threat-config` : la config actuelle est celle du groupe HA si la passerelle en fait partie).

Corps :

```json
{ "config": { "rate_limit": 20, "custom_lists": { "paths": ["/wp-admin"] } }, "hours": 6, "domain": "app.example.com" }
```

- `config` (requis) : champs Sentinel surchargés sur la config actuelle, mêmes noms que `threat-config` ;
- `hours` : fenêtre rejouée, défaut `1`, max `24` ; `domain` : limite le rejeu à un domaine.

Réponse `200` : `current` et `candidate` (`events`, `blocked`, `blocked_by_ban`, `legit_blocked`, `blocked_ips`, `by_reason`, `bans`, `top_ips`), `delta` (candidat − actuel), `events_replayed`, `truncated`, `skipped_unattributable_ip`, `not_simulated`, `note`. `400` si `config` est absent ou invalide. Non simulé : listes par défaut, `global_rps`, règles User-Agent, WAF.

### `GET /api/v1/security/ips-provider` · `PUT /api/v1/security/ips-provider`

Fournisseur IPS actif (`native|fail2ban|crowdsec`). Même règle de portée que `threat-config`.

### `GET /api/v1/security/server-config` · `PUT /api/v1/security/server-config`

Timeouts HTTP/QUIC (`read_header_seconds`, `read_seconds`, `write_seconds`, `idle_seconds`, redémarrage de la passerelle requis). Même règle de portée que `threat-config` ; une passerelle qui rejoint le groupe reçoit ceux du groupe à sa connexion.

## Portail d'accès — `/api/v1/portal`

Le paramètre `edge=<id ou nom>` désigne une passerelle. Dans un **groupe HA** (`config.cluster` + `config.cluster_group` dans `architecture.json`), la configuration du portail est **celle du groupe** : lue et écrite une seule fois, poussée à tous les membres (config, destinations, utilisateurs invités). L'activation reste une propriété du nœud : un membre qui n'héberge pas le portail (`config.portal: false`) reçoit la config du groupe **en attente** (`ha_standby`), sans écouter, et réplique le magasin pour pouvoir prendre le relais.

### `GET /api/v1/portal?edge=` · `PUT /api/v1/portal?edge=`

Config du portail (`enabled`, `ssh_port`, `http_port`, `public_host`, `auth_provider_id`, `allow_personal_targets`, `require_2fa`, `session_ttl_sec`, `session_mode`, catalogue, utilisateurs). Pour une passerelle membre d'un groupe HA, la réponse ajoute :

| Champ | Description |
|-------|-------------|
| `ha_group`, `ha_members` | Groupe et membres (calculés, non modifiables) |
| `ha_session_mode` | `sticky` (défaut : une session web reste sur la passerelle qui l'a émise, affinité à assurer sur le répartiteur) ou `shared` (sessions répliquées entre les membres ; à choisir avec un DNS round-robin) |

La clé de réplication du groupe (`ha_key`) n'est jamais renvoyée : l'Admin la génère, la conserve scellée et ne la pousse qu'aux passerelles du groupe.

### `POST /api/v1/portal/push?edge=`

Repousse la config du portail à la passerelle (à tous les membres du groupe HA).

### `GET /api/v1/portal/sessions?edge=` · `DELETE /api/v1/portal/sessions/{id}?edge=`

Connexions SSH et web pontées en cours sur une passerelle. La passerelle envoie l'instantané à chaque connexion ou déconnexion, et toutes les 30 s tant qu'une connexion est ouverte. `GET` renvoie `{"sessions":[{id, actor, target_id, facade, remote, since}]}`. `DELETE` demande à la passerelle de fermer la connexion (`204`, `404` si elle est déjà terminée) et journalise l'action dans l'audit Admin. Portée `portal:read` pour lire, `portal:write` pour terminer.

### `GET /api/v1/portal/sessions/{id}/watch?edge=`

Observe en direct la sortie d'une connexion en cours (flux `text/event-stream`). Chaque événement `data:` porte un morceau de sortie du terminal en base64, précédé de la fin déjà émise (32 Kio) à l'ouverture ; `event: end` annonce la fin de la session. On voit ce que l'utilisateur voit, jamais ce qu'il tape. L'observation est journalisée dans l'audit Admin (`watch`) et dans l'audit du portail (`observed_by_admin`). Elle exige la portée `portal:write`, comme la lecture d'un enregistrement, car elle donne accès au contenu d'un terminal. `404` si la connexion est déjà terminée. La CLI l'expose avec `goproxify access sessions watch`.

### Accès temporaires — `/api/v1/portal/access-requests`

Un utilisateur du portail demande l'accès à une destination qu'il ne voit pas (motif obligatoire, durée de 5 à 480 minutes) ; la passerelle transmet la demande à l'Admin, qui prévient par email les comptes admin et superadmin si le SMTP est configuré. Un administrateur l'approuve ou la refuse. L'accès approuvé est poussé à la passerelle (à tous les membres d'un groupe HA) et expire tout seul.

| Méthode | Chemin | Description |
|---------|--------|-------------|
| `GET` | `/api/v1/portal/access-requests?edge=&status=` | Demandes de la passerelle (`pending`, `approved`, `denied`, `revoked` ; une demande accordée échue est renvoyée `expired`) |
| `POST` | `/api/v1/portal/access-requests/{id}/approve` | Corps optionnel `{"duration_min": n}` (1 à 1440, défaut : durée demandée) |
| `POST` | `/api/v1/portal/access-requests/{id}/deny` | Refuse une demande en attente |
| `POST` | `/api/v1/portal/access-requests/{id}/revoke` | Retire un accès accordé avant son terme |

Réponse `204` ; `409` si la demande n'est plus dans le bon état, `404` si elle n'existe pas. Une demande en attente pour le même utilisateur et la même destination n'est pas dupliquée. Portée `portal:read` pour lire, `portal:write` pour décider. Côté portail utilisateur : `GET /api/access/requestable` (destinations demandables) et `POST /api/access/requests` (`target_id`, `reason`, `duration_min`).

### `GET /api/v1/portal/policy?edge=` · `PUT /api/v1/portal/policy?edge=`

Politique d'accès du portail, enregistrée avec la config de la passerelle (celle du groupe pour un groupe HA) et poussée à chaque `PUT`. Le formulaire `PUT /api/v1/portal` ne la modifie pas.

| Champ | Description |
|-------|-------------|
| `hours_enabled` | Active la limitation horaire |
| `days` | Jours autorisés, `0` = dimanche à `6` = samedi |
| `start_time`, `end_time` | `HH:MM`, la fin suit le début (pas de plage sur minuit) |
| `timezone` | Nom IANA (`Europe/Paris`), UTC si vide |
| `ip_allow` | Adresses ou plages CIDR autorisées ; vide = toutes |
| `idle_timeout_min` | Ferme une session après N minutes sans saisie de l'utilisateur ; `0` = jamais |
| `record_sessions` | Enregistre la sortie des terminaux (voir ci-dessous) |
| `record_retention_days` | Jours de conservation des enregistrements ; `0` = illimitée |

`400` avec le motif si la politique est invalide. Hors plage horaire ou depuis une adresse non autorisée, la passerelle refuse la connexion au portail, l'ouverture d'une session et la connexion SSH (`403`), et journalise le refus dans l'audit. Les sessions déjà ouvertes ne sont coupées que par l'inactivité. Derrière la passerelle, l'adresse du client est la dernière entrée de `X-Forwarded-For`. Portée `portal:read` pour lire, `portal:write` pour modifier.

### Enregistrements de sessions — `/api/v1/portal/recordings`

Quand `record_sessions` est actif dans la politique, la passerelle enregistre la sortie du terminal de chaque nouvelle session (SSH, web, Docker) au format asciicast v2. La saisie de l'utilisateur n'est jamais gardée. Les fichiers restent sur la passerelle, chiffrés au repos avec une clé dérivée du secret du portail ; l'Admin les relaie à la demande. Un enregistrement est limité à 8 Mio de sortie (marqué `truncated` au-delà) et n'est écrit qu'à la fin de la session. `record_retention_days` supprime automatiquement les plus anciens (`0` = conservation illimitée).

| Méthode | Chemin | Description |
|---------|--------|-------------|
| `GET` | `/api/v1/portal/recordings?edge=` | `{"recordings":[{id, actor, target_id, facade, remote, started, duration_sec, bytes, truncated}]}`, du plus récent au plus ancien |
| `GET` | `/api/v1/portal/recordings/{id}?edge=` | Fichier asciicast (`application/x-asciicast`), lecture journalisée dans l'audit Admin |
| `DELETE` | `/api/v1/portal/recordings/{id}?edge=` | Suppression définitive (`204`), journalisée |

`502` si la passerelle est injoignable, `404` si l'enregistrement n'existe pas. Portée `portal:read` pour lister ; `portal:write` pour lire le contenu d'un enregistrement ou le supprimer. Le contenu n'est pas exposé en MCP.

Les destinations (`/api/v1/portal/destinations`) et les utilisateurs (`/api/v1/portal/users`) suivent la même règle : rattachés au groupe, visibles et modifiables depuis n'importe quel membre. Au démarrage, les données propres aux membres d'avant les groupes sont rattachées au groupe (config du premier membre, destinations en double retirées, un désaccord de config est signalé dans le log, jamais écrasé).

## Moteur de règles automatiques

### `GET /api/v1/rules-engine/rules`

Liste toutes les règles. Réponse : tableau `Rule[]`.

### `POST /api/v1/rules-engine/rules`

Crée une règle. Corps : `{ name, description, enabled, condition, action, cooldown_sec, require_approval }`. `require_approval` (défaut `false`) : si vrai, l'action attend une décision humaine (`GET/POST /rules-engine/pending…`) au lieu de s'exécuter.

### `PUT /api/v1/rules-engine/rules/:id`

Met à jour une règle existante.

### `DELETE /api/v1/rules-engine/rules/:id`

Supprime une règle.

### `POST /api/v1/rules-engine/rules/:id/run`

Déclenche une évaluation immédiate. Paramètre : `?dry_run=true` (défaut). Réponse : `{ matched, action_taken, detail, error }`.

### `GET /api/v1/rules-engine/history`

Historique des exécutions. Paramètre : `limit`.

### `POST /api/v1/rules-engine/history/:id/replay`

Rejoue l'action d'une entrée d'historique en échec, en réutilisant le `detail` capturé au déclenchement d'origine (la condition n'est pas réévaluée). `400` si l'entrée n'a jamais déclenché de tentative d'action ou si la règle a été supprimée depuis. Réponse : `{ ok: true }`.

### `GET /api/v1/rules-engine/rules/:id/versions`

Liste l'historique des versions d'une règle (20 dernières), la plus récente en premier. Réponse : tableau `{ version, name, description, enabled, condition, action, cooldown_sec, created_at }`.

### `POST /api/v1/rules-engine/rules/:id/versions/:version/restore`

Restaure la règle à l'état de la version indiquée (condition, action, cooldown, activation, nom, description). La restauration ajoute elle-même une nouvelle version. `404` si la règle ou la version n'existe pas. Réponse : `{ ok: true }`.

### `GET /api/v1/rules-engine/condition-types`

Liste les descripteurs de types de conditions disponibles (nom, paramètres, descriptions).

### `GET /api/v1/rules-engine/action-types`

Liste les descripteurs de types d'actions disponibles (nom, paramètres, descriptions).

### `GET /api/v1/rules-engine/templates`

Store de règles préconfigurées. Réponse : tableau `Template[]` (`id, category, name, description, cooldown_sec, condition, action`).

### `POST /api/v1/rules-engine/templates/:id/install`

Installe un template : crée une `Rule` concrète à partir de ses valeurs par défaut. Corps optionnel : `{ name, enabled }` (nom personnalisé, activée par défaut). Réponse : `{ id }` (201).

### `GET /api/v1/rules-engine/silences`

Liste les silences. Réponse : tableau `Silence[]` (`id, name, rule_ids, starts_at, ends_at, created_at`), `rule_ids` vide = toutes les règles des deux moteurs (moteur de règles et moteur d'alertes — voir [docs/security.md](security.md#silences--maintenance)).

### `POST /api/v1/rules-engine/silences`

Crée un silence. Corps : `{ name, starts_at, ends_at, rule_ids }` (`starts_at`/`ends_at` en RFC3339, `rule_ids` optionnel — IDs de `rules_engine_rules` et/ou `alert_rules`, vide = toutes les règles). `400` si `ends_at <= starts_at`. Réponse : `{ id }` (201).

### `DELETE /api/v1/rules-engine/silences/:id`

Supprime un silence (`204`).

### `GET /api/v1/rules-engine/pending?[status=pending|approved|rejected]`

Liste les actions mises en attente par une règle `require_approval` (sans filtre : tous les statuts). Réponse : tableau `{ id, rule_id, rule_name, action, detail, status, created_at, decided_at, decided_by }`.

### `POST /api/v1/rules-engine/pending/:id/approve`

Approuve une action en attente : elle est exécutée immédiatement (avec le détail capturé au déclenchement, la condition n'est pas réévaluée) et le résultat rejoint l'historique de la règle. `400` si l'action n'est plus `pending`. Réponse : `{ ok: true }`.

### `POST /api/v1/rules-engine/pending/:id/reject`

Refuse une action en attente : elle ne sera jamais exécutée. `400` si l'action n'est plus `pending`. Réponse : `{ ok: true }`.

### `GET /api/v1/rules-engine/export`

Exporte en YAML toute la configuration d'automatisation : `{ version, rules[], channels[], silences[] }` (`Content-Type: application/x-yaml`, pièce jointe `automation.yaml`). Les canaux exportent leur `config` en clair.

### `POST /api/v1/rules-engine/import`

Importe un document YAML au format de l'export ci-dessus. Corps : le document YAML brut. Règles et canaux upsertés par nom ; silences toujours créés. Réponse : `{ rules_created, rules_updated, channels_created, channels_updated, silences_created }`.

---

## Planifications (cron)

### `GET /api/v1/scheduled-tasks`

Liste les planifications. Réponse : tableau `{ id, name, cron_expr, action, enabled, last_run_at, created_at, updated_at }`.

### `POST /api/v1/scheduled-tasks`

Crée une planification. Corps : `{ name, cron_expr, action, enabled }` (`cron_expr` : expression cron 5 champs, `action` : mêmes types que le moteur de règles — `condition-types`/`action-types`). `400` si `cron_expr` est invalide. Réponse : `{ id }` (201).

### `PUT /api/v1/scheduled-tasks/:id`

Met à jour une planification existante. Même corps que la création.

### `DELETE /api/v1/scheduled-tasks/:id`

Supprime une planification (`204`).

### `POST /api/v1/scheduled-tasks/:id/run`

Exécute immédiatement l'action de la planification, indépendamment de son expression cron. Réponse : `{ ok: true }`.

### `GET /api/v1/scheduled-tasks/:id/runs`

Historique des 100 dernières exécutions (30 jours conservés). Réponse : tableau `{ id, success, error, ran_at }`.

---

## Playbooks

### `GET /api/v1/playbooks`

Liste les playbooks. Réponse : tableau `{ id, name, description, steps, enabled, created_at, updated_at }`.

### `POST /api/v1/playbooks`

Crée un playbook. Corps : `{ name, description, steps, enabled }`. `steps` : tableau non vide de `{ type: "action"|"wait"|"condition"|"approval", action?, wait_sec?, condition?, note? }`. `400` si `name` vide ou `steps` vide. Réponse : `{ id }` (201).

### `PUT /api/v1/playbooks/:id`

Met à jour un playbook existant. Même corps que la création.

### `DELETE /api/v1/playbooks/:id`

Supprime un playbook (`204`).

### `POST /api/v1/playbooks/:id/run`

Démarre une exécution depuis la première étape. Réponse : `{ run_id }`.

### `GET /api/v1/playbooks/:id/runs`

Liste les 50 dernières exécutions du playbook. Réponse : tableau `{ id, current_step, status, log, started_at, updated_at, finished_at }` (`status` : `running`, `waiting_approval`, `completed`, `failed`, `stopped`).

### `GET /api/v1/playbooks/runs/:run_id`

Détail d'une exécution : `{ id, playbook_id, playbook_name, steps, current_step, status, log, context, started_at, updated_at, finished_at }`.

### `POST /api/v1/playbooks/runs/:run_id/approve`

Approuve une exécution suspendue à une étape `approval` : reprend à l'étape suivante. `400` si l'exécution n'est pas `waiting_approval`. Réponse : `{ ok: true }`.

### `POST /api/v1/playbooks/runs/:run_id/reject`

Refuse une exécution suspendue à une étape `approval` : l'exécution passe au statut `stopped`. `400` si l'exécution n'est pas `waiting_approval`. Réponse : `{ ok: true }`.

---

## Accès MCP (admin)

Périmètre d'accès du serveur MCP, admin uniquement (`RequireAdmin`).

### `GET /api/v1/mcp-access/allowed-ips`

Allowlist d'IP/CIDR sources autorisées à appeler `/mcp`. Réponse : `{ ips: string[] }`. Liste vide = aucune restriction (comportement historique).

### `PUT /api/v1/mcp-access/allowed-ips`

Remplace l'allowlist. Corps : `{ ips: string[] }` — chaque entrée est une IP (`203.0.113.4`) ou un CIDR (`10.0.0.0/24`), validée côté serveur (400 si invalide). Appliquée immédiatement par `internal/admin/mcp.Handler.ServeHTTP` (403 pour toute requête `/mcp` hors liste, avant même l'authentification PAT).

### `GET /api/v1/mcp-access/allowed-backends`

Allowlist des destinations vers lesquelles les outils MCP `create_proxy` / `update_proxy` peuvent pointer un backend (protection contre le détournement de trafic par prompt injection). Réponse : `{ backends: string[] }`. Défaut tant que jamais enregistrée : RFC 1918, loopback, ULA IPv6, `*.internal`, `*.local`, `*.svc`, `*.cluster.local` ; les noms d'hôte à label unique (services Docker/Kubernetes) sont toujours acceptés. Liste vide = aucune restriction. Ne s'applique pas à l'API REST admin ni à l'UI.

### `PUT /api/v1/mcp-access/allowed-backends`

Remplace l'allowlist. Corps : `{ backends: string[] }` — chaque entrée est une IP, un CIDR, un hôte exact (`api.corp.example`) ou un suffixe (`*.corp.example`) ; 400 si invalide. Un backend refusé renvoie une erreur d'outil MCP.

### `GET /api/v1/mcp-access/tokens`

Liste tous les PAT actifs (non révoqués) sur l'instance, tous porteurs confondus, avec leurs scopes — la vue "quels utilisateurs peuvent utiliser le MCP". Réponse : tableau `{ id, label, owner_email, scopes[], expires_at?, last_used_at?, created_at }`. La gestion (création/révocation) reste self-service sur `/api/v1/me/tokens` — un PAT est personnel.

### `GET /api/v1/mcp-access/scopes`

Catalogue des scopes PAT avec les outils MCP couverts par chacun, pour référence. Réponse : tableau `{ id, description, tools[] }`.

---

## Santé

### `GET /health` `[PUBLIC]`

```json
{ "status": "ok", "version": "0.1.0" }
```

### `GET /api/v1/cluster/status`

État du cluster (nodes, leader, sync).

---

## API interne passerelle ↔ Administration

*Ces endpoints ne sont pas exposés publiquement. Authentification par token d'appairage.*

### `POST /internal/v1/register`

Enregistrement d'une passerelle ou Agent.

### `GET /internal/v1/config`

Récupère la configuration complète (routes + certs) pour une passerelle.

### `POST /internal/v1/telemetry`

Soumission des métriques d'un Agent.

### `POST /internal/v1/discovery`

Soumission d'un proxy découvert par labels (depuis un Agent).

### `GET|POST /internal/v1/portal/replica`

Réplication du magasin du portail entre passerelles d'un même groupe HA (comptes, mot de passe et 2FA, coffres, cibles perso, favoris, et sessions web en mode `shared`). L'état échangé est **chiffré (AES-256-GCM) par la clé du groupe** poussée par l'Admin : il ne circule jamais en clair et une clé différente ne déchiffre rien. Fusion « dernier écrit gagne » par clé avec suppressions propagées ; envoi immédiat à chaque modification locale et tirage toutes les 15 s. Répond `204` hors groupe. Sans `GPX_PORTAL_MASTER_KEY` identique sur les membres, les coffres des comptes SSO répliqués ne sont pas déchiffrables ailleurs (un avertissement est journalisé).

### `POST /internal/v1/bans/gossip`

Un ban décidé localement (Sentinel, Fail2Ban) est transmis aux passerelles pairs sans passer par l'Admin ; chaque passerelle récupère aussi périodiquement les bans actifs de ses pairs (`GET /internal/v1/bans`). Les bans expirés, sans IP ou déjà connus (même identifiant ou même IP) sont ignorés ; un ban reçu d'un pair n'est jamais réémis. Ce circuit prend le relais quand l'Admin est indisponible.

### `GET /internal/v1/threat-lists/export` · `POST /internal/v1/threat-lists/sync`

Listes de référence Sentinel (`ua.txt`, `paths.txt`, `ips.txt`) : échangées entre passerelles pairs à chaque cycle de synchronisation, la plus récente l'emporte.

> **Note de migration :** Ces endpoints HTTP sont conservés pour la rétrocompatibilité pendant la migration. La nouvelle architecture utilise les tunnels WebSocket décrits ci-dessous.

---

## Protocole WebSocket

Le plan de contrôle utilise des tunnels WebSocket persistants initiés par Admin et Agent vers la passerelle. La passerelle est le seul hub de connexion.

### `GET /ws/admin` — Connexion Admin↔Passerelle

**Authentification :** header `X-Goproxify-Signature: hmac-sha256 <timestamp>.<hex_sig>`

La signature est calculée sur `"<ts>:<method>:<path>"` avec la clé `GPX_CONTROL_PLANE_ADMIN_HMAC_SECRET`. Fenêtre de rejeu ±5 min.

**Header requis :** `X-Node-ID: <nodeID>` — identifiant unique de l'instance Admin.

### `GET /ws/agent` — Connexion Agent↔Passerelle

**Premier démarrage :** header `X-Join-Token: gpx_join_*` (TTL 24h). L'Agent passe en état `pending` jusqu'à approbation via `POST /api/v1/agents/:id/approve`.

**Après approbation :** header `X-Agent-HMAC: <secret>` (rotatif toutes les heures, envoyé par la passerelle via message `rotate_hmac`).

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

### Types de messages Admin→Passerelle

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
| `push_delegations` | Pousse les routes de délégation multi-passerelle |
| `full_sync` | Full sync : envoie toutes les données en une seule enveloppe |
| `approve_agent` | Demande à la passerelle d'approuver un Agent en attente |

### Types de messages Agent→Passerelle

| Type | Description |
|---|---|
| `register` | Premier message après upgrade WS — enregistrement de l'Agent |
| `heartbeat` | CPU%, mém%, runtimes actifs (toutes les 30 s) |
| `containers` | Liste des conteneurs avec labels goproxify.* |
| `metrics` | Métriques par conteneur (CPU, mém, latence, erreurs) pour LB adaptatif |
| `event` | Événement de cycle de vie conteneur (start, stop, die, scale, etc.) |
| `log` | Batch de logs de conteneurs (log forwarding) |

### Types de messages passerelle→Agent

| Type | Description |
|---|---|
| `approve` | Approbation de l'Agent + premier `agent_hmac` |
| `rotate_hmac` | Nouveau `agent_hmac` (rotation toutes les heures) |
| `command` | Commande à exécuter sur l'Agent (restart conteneur, pull image, etc.) |
| `rescan` | Demande un rescan Docker immédiat |
| `ping` | Ping keepalive (répondu par `pong`) |

### Types de messages passerelle→Admin

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
| POST | `/api/v1/workspaces/{id}/resources` | Ajoute une ressource (`resource_type`: `proxy`/`domain`/`edge`, `resource_id`) |
| DELETE | `/api/v1/workspaces/{id}/resources/{type}/{resourceID}` | Retire une ressource |

---

## Logs RGPD — `/api/v1/logs`

| Méthode | Endpoint | Scope requis | Description |
|---|---|---|---|
| GET | `/api/v1/logs` | `logs:read` | Liste paginée (curseur `before_id`, `page_size`) : filtres `kind` (`access`/`system`), `level`, `component`, `node_name`/`node_id`, `domain`, `ip`, `method`, `status`, `path`, `search`, `date_from`, `date_to`, `exclude_internal` (`1`/`true` : exclut les IP de réseau privé/loopback — RFC 1918, loopback, link-local IPv4/IPv6 — appliqué en SQL avant `LIMIT`, donc `has_more`/`page_size` restent cohérents) → `{has_more, last_id, entries:[Entry]}`. Chaque `Entry` porte `country` (code ISO alpha-2, résolu au mieux depuis le cache géo-IP déjà alimenté par le tableau de bord/Prism/Bans ; absent si l'IP n'a pas encore été résolue — pas d'appel réseau synchrone sur cette route), `request_id` (identifiant de la requête d'origine, transmis par la passerelle — voir `/logs/correlate?request_id=`), `waf_matches` (catégories de règles WAF déclenchées, tableau, absent si aucune) et `threat_signal` (signal Sentinel déclenché, absent sinon). `exclude_internal` s'applique aussi à `/logs/histogram`, `/logs/facets`, `/logs/export` et `/logs/live` (mêmes filtres) |
| GET | `/api/v1/logs/live` | `logs:read` | Flux SSE des nouvelles entrées, mêmes filtres que la liste (`?_auth=<token>` requis, `EventSource` ne pose pas d'en-tête `Authorization`) |
| GET | `/api/v1/logs/export?format=json\|csv` | `logs:read` | Export des entrées filtrées (mêmes filtres que la liste) |
| GET | `/api/v1/logs/correlate` | `logs:read` | Entrées voisines d'un événement : `request_id`, ou `domain`+`ts`+`window` (secondes, défaut 30) |
| GET | `/api/v1/logs/settings` | `logs:read` | Paramètres de rétention et de pseudonymisation |
| PUT | `/api/v1/logs/settings` | admin | Modifier rétention, `ip_anonymize`, `ip_pseudonymize` |
| POST | `/api/v1/logs/reveal-ip` | `gdpr:reveal` | Révéler l'IP réelle d'une entrée pseudonymisée |
| DELETE | `/api/v1/logs/by-ip/{ip}` | admin | Effacement RGPD Art.17 par IP |
| DELETE | `/api/v1/logs/by-user/{user_id}` | admin | Effacement RGPD Art.17 par utilisateur |
| GET | `/api/v1/logs/histogram` | `logs:read` | Entrées par tranche de temps et par niveau : mêmes filtres que la liste plus `bucket` (`minute`, `hour`, `day` ; défaut selon l'étendue, 24 h sans `date_from`) → `{bucket, points:[{bucket, total, warn, error}]}` |
| GET | `/api/v1/logs/facets` | `logs:read` | Comptage des entrées filtrées par valeur, pour l'explorateur de logs : mêmes filtres que la liste plus `fields` (CSV parmi `level`, `component`, `node_name`, `domain`, `method` ; par défaut les cinq) → `{<field>: [{value, count}]}`, 12 valeurs les plus fréquentes par champ, valeurs vides exclues |
| GET | `/api/v1/audit/histogram` | authentifié | Actions du journal d'audit par tranche et par gravité : filtres `component`, `action`, `actor`, `severity`, `from`, `to` (RFC 3339) plus `bucket` → `{bucket, points:[{bucket, total, warn, critical}]}` |

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
  "requested_by": "dpo@example.com",
  "reason": "Réquisition judiciaire n°2026/1234",
  "ts": "2026-09-20T14:32:01Z"
}
```

Codes d'erreur :
- `403` — scope `gdpr:reveal` manquant
- `400` — `entry_id` ou `reason` manquant
- `422` — entrée non pseudonymisée ou clé non chargée

## Prism — bans et scan d'IP

- `GET /api/v1/prism/bans/breakdown` — bans actifs ventilés par source puis par technique de détection : `[{source, source_label, sentinel, technique, label, count}]`. `sentinel: true` pour la source `threat` (moteur Sentinel de la passerelle : techniques `ip`, `ua`, `path`, `rate` et leurs variantes `custom_*`) ; Fail2Ban est rapporté en `errors`, CrowdSec par scénario.
- `GET /api/v1/prism/ip-scan?ip=<ip>[&from&to]` — ré-analyse à la demande d'une IP : `verdict` (`banned` | `suspect` | `clean`), bans actifs (avec source/technique), nombre de bans passés, décisions de menace, requêtes/erreurs sur la période et chemins les plus visés.
- `GET /api/v1/prism/geo/points?[from&to&proxy&node_name&limit]` — trafic agrégé par ville, les plus actives d'abord (`limit` 300 par défaut, 1000 max) : `[{city, region, country_code, country_name, lat, lon, requests, errors, error_rate, ips, banned_ips}]`. La position est approximative (géolocalisation IP, précision de l'ordre de la ville) ; les IPs pas encore localisées sont ignorées.
- `GET /api/v1/prism/anomalies?[from&to&proxy&node_name]` — écarts détectés sur la période, critiques d'abord : `[{kind, level, subject, label, value, baseline, count, banned?}]`. `kind` : `error_spike` (point de la courbe > moyenne + 2,5 écarts-types, au moins 10 erreurs ; `subject` = tranche horaire), `dominant_ip` (au moins 20 % des requêtes et 50 requêtes ; `banned` si déjà bannie), `country_errors` (au moins 20 % d'erreurs sur 50 requêtes, 2 max), `backend_errors` (plus de 10 % d'erreurs sur 20 requêtes, 2 max), `bot_share` (au moins 30 %). `level` : `critical` | `warning`.
- `GET /api/v1/prism/slo?[target&days&proxy&node_name]` — SLO de disponibilité (réponses non-5xx) sur une fenêtre glissante (`target` en % : objectif enregistré, 99.9 par défaut ; `days` : 30 par défaut, 90 max ; `from`/`to` ignorés) : `{target, days, requests, errors, availability, budget_total, budget_left_pct, burn_1h, burn_6h, state}`. `burn_*` vaut 1 quand le budget est consommé exactement au rythme de l'objectif. `state` : `exhausted` (budget consommé), `critical` (burn ≥ 14,4 sur 1 h et ≥ 6 sur 6 h), `warning` (burn ≥ 3 sur 6 h), sinon `ok`.
- `GET /api/v1/alert-events?[days&limit&trigger&node]` — alertes déclenchées (30 jours conservés, plus récente d'abord) : `[{id, rule_id, rule_name, trigger, detail, channels, title, body, priority, silenced, fired_at}]` ; `node` filtre sur le nom de passerelle du détail. `silenced=true` : la règle correspondait mais un silence actif (`Automatisation > Alertes > Silences & maintenance`) a bloqué l'envoi — `channels` est alors vide.
- `GET /api/v1/prism/slo/config` → `{target}` ; `PUT /api/v1/prism/slo/config` `{target}` (admin, entre 90 et 99.999) — objectif SLO enregistré (réglage `slo.target`, 99.9 par défaut), utilisé par l'écran, `GET /prism/slo` sans `target`, l'outil MCP `get_prism_slo` et l'alerte `slo_burn`.
- `GET /api/v1/prism/live-ips` renvoie en plus `city`, `lat`, `lon` (0/0 tant que l'IP n'est pas localisée).
