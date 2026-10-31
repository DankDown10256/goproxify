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

### Scope PAT exigé par route

Une requête authentifiée par PAT doit porter le scope de la route (`403 scope insuffisant: <scope>` sinon), en plus du rôle exigé par la route (`adminOnly` : admin/superadmin). Les sessions UI (JWT) ne sont soumises qu'au rôle. `GET` = lecture, toute autre méthode = écriture.

| Préfixe de route | Lecture (`GET`) | Écriture |
|---|---|---|
| `/api/v1/proxies` | `proxies:read` | `proxies:write` (`DELETE` : `proxies:delete`) |
| `/api/v1/nodes`, `/declared-nodes`, `/bootstrap-tickets`, `/hosts`, `/node-events`, `/discovered-containers`, `/backends/health`, `/agents` | `nodes:read` | `nodes:write` |
| `/api/v1/alert-channels`, `/alert-channel-types`, `/alert-rules`, `/alert-events` | `alerts:read` | `alerts:write` |
| `/api/v1/domains` | `domains:read` | `domains:write` |
| `/api/v1/certs` (dont `deploy-targets`, `pull-tokens`), `/api/v1/internal-ca`, `/api/v1/ech` | `certs:read` | `certs:write` |
| `/api/v1/snippets` | `snippets:read` | `snippets:write` |
| `/api/v1/security`, `/ip-profiles`, `/auth-providers`, `/automation` | `audit:read` | `security:write` |
| `/api/v1/import` | `audit:read` | `import:write` |
| `/api/v1/portal`, `/portal-page-templates` | `portal:read` | `portal:write` (contenu d'un terminal — rejeu, observation — : `portal:write` même en `GET`) |
| `/api/v1/prism`, `/metrics/proxies`, `/metrics/summary` | `metrics:read` | idem |
| `/api/v1/logs` (`/logs/reveal-ip` : `gdpr:reveal`) | `logs:read` | `logs:write` |
| `/api/v1/backups` · `/users` · `/tokens` · `/teams` · `/audit` · `/pairing-secret` | `backups:read` · `users:read` · `users:read` · `teams:read` · `audit:read` · `pairing:read` | idem |

Depuis Admin `0.70.0` : les écritures sur `/alert-*`, `/domains`, `/certs` exigent `alerts:write`, `domains:write`, `certs:write` (le scope de lecture suffisait auparavant), `/internal-ca` exige `certs:read` / `certs:write`, et `/rules-engine`, `/scheduled-tasks`, `/playbooks` exigent `audit:read` / `security:write` (aucun scope n'était vérifié auparavant, seul le rôle admin). Ces scopes d'écriture sont réservés aux rôles admin et superadmin ; un PAT existant ne les reçoit pas, il faut en créer un nouveau.

Depuis Admin `0.70.4` : les écritures sur `/logs` (réglages, effacement RGPD) exigent `logs:write`, réservé aux rôles admin et superadmin ; `logs:read` suffisait auparavant.

### Rôle exigé pour les écritures

Routes ouvertes en lecture à tout compte authentifié mais dont les écritures sont réservées à certains rôles. Le contrôle s'applique aux sessions UI (JWT) comme aux PAT, en plus du scope PAT ci-dessus.

| Routes | Lecture (`GET`) | Écriture (toute autre méthode) |
|---|---|---|
| `/api/v1/certs` (dont `deploy-targets`, `pull-tokens`), `/domains`, `/alert-channels`, `/alert-rules` (dont `simulate`), `/alert-events` (`ack`), `/ip-profiles` (dont `refresh`) | tout compte | admin / superadmin — sinon `403 accès réservé aux administrateurs` |
| `/api/v1/snippets` | tout compte | admin / superadmin, ou `user` disposant d'au moins un grant `write` (équipe ou direct) — sinon `403 accès insuffisant` |
| `/api/v1/logs` (`settings`, `by-ip`, `by-user`, `subject-export`) | tout compte | admin / superadmin — sinon `403 accès réservé aux administrateurs` |
| `/api/v1/logs/reveal-ip` | — | détenteur de `gdpr:reveal` (superadmin, rôle `dpo`, droit accordé en propre ou via une équipe), admin ou non — sinon `403` (depuis Admin `0.78.0` ; superadmin seul auparavant) |

Depuis Admin `0.70.4` pour `/logs` : un compte `user` pouvait désactiver l'anonymisation ou la pseudonymisation des IP, réduire la rétention et effacer des logs par IP ou par utilisateur.

Depuis Admin `0.70.2` : jusque-là, seul le scope PAT était vérifié sur ces écritures ; un compte `user` connecté à l'interface pouvait obtenir, importer ou supprimer des certificats, générer un pull token (et donc récupérer la clé privée via `/cert-bundle`), créer ou renouveler des domaines, et créer ou supprimer des canaux et règles d'alerte.

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

**Proxies implicites** (Admin `0.151.0`, Edge `0.67.0`) : les routes que GoProxify génère lui-même — hôtes du portail Access (`gpx-portal-public`, `gpx-portal-public:<hôte>`) et délégations de domaine en terminaison TLS (`deleg-<id>`) — sont listées avec `"implicit": true`. Elles se lisent (`GET /api/v1/proxies/{id}`) et se modifient (`PUT`, `PATCH` pour l'activation) comme les autres, mais seule leur **surcouche** est prise en compte : l'hôte, les alias, les backends et le TLS entrant restent ceux du générateur (ils suivent le réglage du portail ou de la délégation), les champs qui détournent le trafic (`static`, `split`, `canary`, `shadow`) sont ignorés, tout le reste (WAF, limites de débit, en-têtes, filtre IP, cache…) s'applique. `enabled: false` retire la route. `DELETE` supprime la surcouche et rend la route à son état généré ; la route elle-même n'est supprimée que par son réglage d'origine. Un passthrough TLS (délégation) n'est pas listé : aucun réglage HTTP à surcharger. La surcouche est un fichier `proxies/<id>.yaml` sur la passerelle : elle survit à une coupure de l'Admin et à un redémarrage.

### `GET /api/v1/proxies/{id}/labels`

Labels qui reproduisent un proxy (Admin `0.152.0`), pour le déclarer sur un conteneur Docker, une Stack Portainer ou un Service Kubernetes. Scope `proxies:read`. La conversion se fait côté serveur, sur tout le vocabulaire de [labels.md](labels.md) (sécurité, résilience, en-têtes, timeouts, cache, JWT/mTLS, plugins, snippets…) ; elle est vérifiée par un test qui relit les labels produits avec le vrai parseur de l'Agent et de la passerelle.

**Réponse 200 :**
```json
{
  "labels": [{ "key": "goproxify.host", "value": "app.example.fr" }, { "key": "goproxify.headers.add", "value": "Authorization:${GPX_HDR_AUTHORIZATION}" }],
  "env": ["GPX_HDR_AUTHORIZATION"],
  "unsupported": ["locations", "compression"],
  "formats": {
    "compose": { "text": "services:\n  app: …", "env": "GPX_HDR_AUTHORIZATION=\n" },
    "portainer": { "text": "…", "env": "…" },
    "portainer_inline": { "text": "…" },
    "docker_run": { "text": "…", "env": "export GPX_HDR_AUTHORIZATION=\n" },
    "kubernetes": { "text": "…" }
  }
}
```

- **Secrets** : la valeur d'un en-tête `Authorization`/`X-Api-Key`…, ou d'une clé de plugin dont le nom est sensible, ne sort jamais. Elle devient `${GPX_…}` (`env` les liste ; `compose`, `portainer` et `docker_run` livrent le fichier de variables) ou `CHANGE_ME` (`portainer_inline`, `kubernetes`).
- **`unsupported`** : réglages du proxy qu'aucun label ne porte, ou qu'il porte en partie (locations, compression, split, maintenance, TLS vers le backend non vérifié, clé ou quota de rate limit, backends multiples, flux TCP/UDP…).
- `409` pour un proxy implicite (généré par GoProxify) ; `404` s'il n'existe pas.

### `GET /api/v1/discovered-containers`

Routes découvertes par les labels (Docker, Podman, Portainer, Kubernetes…), agrégées sur les passerelles connectées. Scope `nodes:read`. Chaque entrée : `id`, `host`, `aliases`, `backends`, `container_ids`, `tls`, `source`, `edge_name`, `agent_name`, `config` (réglages issus des labels) et, depuis Admin `0.153.0`, **`shadowed_by`** : l'ID du proxy configuré qui sert l'hôte à la place de la route des labels (absent quand c'est la route des labels qui sert).

Depuis Admin `0.155.0`, chaque entrée porte aussi **`missing`** : les contrôles de sécurité absents de la route parmi `tls`, `waf`, `rate_limit` (les snippets de la route sont fusionnés avant le jugement).

Depuis Admin `0.173.1`, chaque entrée porte **`edge_label`** (nom affiché de la passerelle, repli sur `edge_name`) et **`group`** (groupe HA de la passerelle, absent hors groupe). `edge_name` reste le nom de connexion et la clé des filtres. Les membres d'un groupe annoncent la même route : l'interface la fusionne en une seule tuile, et `detail` ou `from-discovered` n'exigent plus `edge` quand tous les membres qui l'annoncent sont du même groupe.

Depuis Admin `0.186.0` (passerelle `0.99.0`, Agent `0.16.0`), une entrée peut décrire un conteneur **inactif** (arrêté, en pause, qui redémarre) : `inactive: true`, `state` (`exited`, `paused`, `restarting`, `created`, `dead`) et `name`, avec un `id` préfixé `inactive:`, aucun `backend` et pas de config de proxy. Elle ne crée aucune route : `detail` et `from-discovered` répondent `404` pour elle, et le proxy converti depuis un conteneur arrêté n'est pas listé par `/orphans`. L'entrée est absente quand un conteneur qui tourne sert déjà le même hôte. Docker, Podman et Portainer en produisent depuis Agent `0.16.0` ; Kubernetes (Service dont l'objet `Endpoints` n'a aucune adresse prête, `state: no-endpoints`) et les annuaires Consul (contrôle `warning` ou `critical`) et ECS (tâche `pending`, `unhealthy`…) depuis Agent `0.17.0`. Nomad et etcd n'exposent pas de santé et n'en produisent pas.

Depuis Admin `0.220.0` (passerelle `0.131.0`), une entrée peut décrire une route **désactivée** : `disabled: true`. La passerelle ne la sert plus mais la garde listée d'après le dernier état complet de l'Agent (`backends`, `container_ids`, `source` et `agent_name` renseignés, pas de config de proxy : `detail` et `from-discovered` répondent `404`). Un hôte désactivé qu'aucune passerelle n'annonce plus est listé par l'Admin seul, avec un `id` préfixé `disabled:` et sans passerelle.

### `PUT /api/v1/discovered-containers/enabled`

Active ou désactive la route issue des labels d'un hôte (Admin `0.220.0`). Scope `proxies:write` + droit d'écriture sur le domaine.

Corps : `{ "host": "app.example.fr", "enabled": false }`. L'interrupteur s'applique à l'hôte, donc à tous les conteneurs du pool, sur toutes les passerelles. L'Admin enregistre la liste des hôtes désactivés et la pousse en entier aux passerelles (message `push_disabled_routes`) ; chaque passerelle la retient dans son journal local chiffré et la réplique à son groupe HA. Elle retire alors la route de sa table de routage : ni trafic, ni sonde de santé, ni certificat. Ni le scan suivant de l'Agent ni un démarrage de conteneur ne la ramènent ; la réactiver la remet en table à partir du dernier état de l'Agent. Un proxy configuré n'est pas concerné (`PATCH /proxies/{id}`).

Réponses : `204`, `400` (corps invalide, `enabled` requis), `403` (hors périmètre), `404` (désactivation d'un hôte qu'aucune passerelle n'annonce ; réactiver est toujours accepté).

### `GET /api/v1/discovered-containers/detail?id=<id ou hôte>&edge=<passerelle>`

Vue complète d'une route découverte (Admin `0.155.0`, scope `nodes:read`). `edge` n'est requis que si plusieurs passerelles annoncent la même route (`409` sinon ; `404` si elle est introuvable).

```json
{
  "container": { "id": "docker-host:app.example.fr", "host": "app.example.fr", "backends": ["http://10.0.0.5:80"], "edge_name": "edge-1", "missing": ["waf", "rate_limit"] },
  "config": { "host": "app.example.fr", "tls_enabled": true },
  "labels": { "labels": [{ "key": "goproxify.host", "value": "app.example.fr" }], "env": [], "unsupported": [], "formats": { "compose": { "text": "…" } } },
  "fixed_labels": { "labels": [], "env": [], "unsupported": [], "formats": { "compose": { "text": "…" } } },
  "audit": {
    "score": 55, "grade": "C",
    "checks": [{ "key": "tls", "name": "TLS activé", "present": true, "points": 20 }],
    "missing": ["waf", "rate_limit"],
    "added": [{ "key": "goproxify.waf", "value": "block" }, { "key": "goproxify.rate_limit", "value": "100/s:50" }]
  }
}
```

- **`config`** : la route telle que la passerelle la sert, secrets masqués.
- **`labels`** : les labels qui la reproduisent, dans les mêmes formats que `GET /proxies/{id}/labels` (Compose, Portainer, `docker run`, Kubernetes).
- **`audit`** : même score que la posture de sécurité d'un proxy, snippets fusionnés. `added` liste les labels à ajouter ou à changer pour combler `missing` (**modèle de sécurité**) : TLS (`goproxify.tls=true`), et pour le WAF et le rate limit un **snippet de l'Admin du bon type s'il en existe** (`goproxify.snippets=<ids>`), sinon WAF en blocage (`goproxify.waf=block`) et `100/s:50`.
- **`fixed_labels`** : les mêmes labels avec le modèle appliqué, prêts à coller dans le Compose ; absent quand rien ne manque. Rien n'est modifié sur le conteneur ni sur la passerelle.

### `GET /api/v1/discovered-containers/orphans`

Proxies créés par `POST /proxies/from-discovered` dont la route d'origine n'est plus annoncée par sa passerelle (Admin `0.155.0`, scope `nodes:read`) : `[{ "proxy_id", "host", "enabled", "origin": { "id", "edge" } }]`. Le proxy converti garde son `origin` (`{ id, edge }`) dans sa config, sans effet sur le routage. Une passerelle qui ne répond pas n'a pas de liste à comparer : ses proxys ne sont jamais déclarés orphelins.

**Priorité sur un hôte** (Edge `0.68.0`) : un proxy configuré (créé depuis l'Admin, portail, délégation) passe toujours avant la route issue des labels du même hôte ou alias, quel que soit l'ordre d'arrivée du conteneur et des poussées de l'Admin. La route des labels reste dans la table et reprend l'hôte quand le proxy est **désactivé ou supprimé**.

### `POST /api/v1/proxies/from-discovered`

Convertit une route découverte en proxy configuré (Admin `0.153.0`). Scope `proxies:write` + droit d'écriture sur le domaine.

Corps : `{ "id": "docker-host:app.example.fr", "edge": "edge-1" }` — `id` est l'`id` de `GET /discovered-containers` **ou** l'hôte ; `edge` (nom de la passerelle) n'est requis que si plusieurs passerelles annoncent la même route.

Le proxy reprend la configuration complète de la route (hôte, alias, backends, TLS, sécurité, timeouts, locations… tout ce que portent les labels) et est publié comme n'importe quel proxy. Ne sont pas repris : les liens au conteneur (identifiants de conteneur et d'Agent), le canary et le shadow. Les backends restent les adresses du conteneur, à revoir si elles changent à chaque redémarrage.

Réponses : `201` (le proxy créé, secrets masqués), `404` (route introuvable), `409` (déjà remplacée par un proxy, ou plusieurs passerelles : préciser `edge`), `403` (hors périmètre).

### `POST /api/v1/proxies/dry-run`

Valide une config de proxy **sans rien enregistrer ni pousser** (éditeur YAML de la modale proxy, bouton « Tester (dry run) »). Scope `proxies:write` + droit d'écriture sur le domaine.

Corps : `{ "id": "<uuid, optionnel>", "config": {…}, "enabled": true, "probe": false }`.
`probe: true` ajoute une sonde réseau (DNS, TLS, connexion des backends).

Réponse : `{ "ok": bool, "summary": {…}, "checks": [{ "check", "status": "ok|warning|error|skip", "message", "details": [] }], "probes": [{ "step", "status", "message", "latency_ms" }], "route": {…} }`.
Contrôles : `syntax`, `structure` (type, host, backends, URLs, et — depuis Edge `0.51.0` — blocs `ip_filter`, `geo_ip`, `bot`, `waf` validés comme les snippets : mode, CIDR, code pays, expression WAF ; voir `GET /api/v1/detector-types`), `conflicts` (host/alias/port face aux proxies en production des passerelles ; `warning` si aucune passerelle ne répond), `enabled`. (Admin `0.72.0`)

### `POST /api/v1/proxies`

Crée un proxy manuel. Corps : objet conforme au schéma canonique (section `proxies`).

Options avancées de la configuration (Edge 0.37.0, détail dans [fonctionnalites.md](fonctionnalites.md)) : `split`, `maintenance`, `signed_url`, `graphql`, `bandwidth`, `redact_json`, `html_inject` (Edge 0.61.0 : `position` `head_end`/`body_end`, `content` ≤ 16 Kio, `csp_nonce`), `rate_limit.quota` / `quota_period` / `key_by` (`header:<nom>`, `cookie:<nom>`), condition `jwt_claim`, et pour `sso` : `provider: "oauth2_proxy"`, `forward_auth_signin_url`, `forward_auth_timeout_ms`.

### `GET /api/v1/proxies/:domain`

Détail complet d'un proxy.

### `PUT /api/v1/proxies/:domain`

Met à jour un proxy manuel (interdit sur `source: "label"`).

### `DELETE /api/v1/proxies/:domain`

Supprime un proxy manuel.

### `PATCH /api/v1/proxies/{id}`

Corps `{"enabled": bool}`. Active/désactive le proxy (republié sur toutes les passerelles qui l'hébergent). Utilisé notamment par la Vue Proxy pour « Mettre en maintenance » / « Réactiver ».

### `POST /api/v1/proxies/{id}/cache/purge`

Vide le cache disque de ce proxy sur toutes les passerelles qui l'hébergent (best-effort, un proxy peut être répliqué sur plusieurs Edges). No-op si le cache n'est pas activé pour ce proxy. Corps JSON optionnel `{"tags": ["news"], "paths": ["/blog/*", "/a?x=1"]}` : sans corps, tout le cache est vidé ; sinon seules les entrées portant l'un des tags (en-tête `Cache-Tag` ou `Surrogate-Key` de la réponse backend, retiré avant l'envoi au client) ou correspondant à l'un des chemins (avec ou sans query, suffixe `*` = préfixe) sont supprimées. Réponse `{"purged": <nombre d'entrées supprimées>}`. Relaie en interne `POST /internal/v1/proxies/{id}/cache/purge` (même corps) sur chaque Edge (le cache est stocké par route, un répertoire dédié par proxy — voir `router.Route.Cache`).

Options de cache par proxy (`cache`) : `stale_while_revalidate` (ex. `"30s"` : une entrée expirée est servie `X-Cache: STALE` pendant qu'une seule requête la revalide en arrière-plan), `stale_if_error` (ex. `"1h"` : une entrée expirée remplace une réponse 5xx du backend), `disable_coalescing` (par défaut, les requêtes simultanées sur un même MISS sont regroupées : une seule atteint le backend, les autres reçoivent `X-Cache: COALESCED`). Les directives `stale-while-revalidate` / `stale-if-error` du backend ont priorité sur ces valeurs.

Champ `proxy_protocol` de la config d'un proxy (`"v1"` ou `"v2"`, vide = désactivé) : la passerelle écrit l'en-tête PROXY (IP du client) au début de chaque connexion vers le backend HTTP ou le passthrough TLS ; le backend doit l'attendre. Une route HTTP ouvre alors une connexion backend par requête (pas de keep-alive). Toute autre valeur est refusée par la validation (dry-run). La lecture de l'en-tête en entrée se règle dans la configuration de la passerelle (`network.proxy_protocol: { enabled, trusted_cidrs }`), pas via l'API.

### `POST /api/v1/proxies/:domain/enable`
### `POST /api/v1/proxies/:domain/disable`

Active/désactive un proxy à chaud.

Écritures sur les deploy targets et pull tokens (`POST`, `DELETE`, `trigger`) : admin / superadmin (voir [Rôle exigé pour les écritures](#rôle-exigé-pour-les-écritures)).

### `GET /api/v1/certs/:id/deploy-targets`

Liste les deploy targets d'un certificat. Réponse : `[{id, cert_id, name, type, config, trigger_on, last_deploy, last_status, created_at}]`. Les champs `secret` du manifeste du type sont masqués (`••••••••`) : secret HMAC d'un webhook et **clé privée SSH** d'un `ssh_exec` — avant Admin `0.125.0`, seul `secret` l'était et la clé privée SSH était renvoyée en clair.

### `POST /api/v1/certs/:id/deploy-targets`

Crée un deploy target. Corps : `{name, type ("webhook"|"ssh_exec"), config, trigger_on ("on_renewal"|"manual")}`. `400` si le type est inconnu, un champ requis est vide ou la config contient une clé absente du manifeste (voir `GET /api/v1/cert-deploy-types`).|"manual")}`.

### `PUT /api/v1/certs/:id/deploy-targets/:targetID`

Modifie une cible (`name`, `config`, `trigger_on` ; le type ne change pas). La configuration envoyée **remplace** l'ancienne, sauf les secrets du manifeste (clé privée SSH, secret HMAC) : absents, vides ou égaux au masque, ils sont conservés. Omettre `host_fingerprint` relance la mémorisation de la clé d'hôte SSH à la prochaine connexion. `400` (champ requis vide, clé inconnue, `trigger_on` invalide), `404` (cible inconnue).

### `DELETE /api/v1/certs/:id/deploy-targets/:targetID`

Supprime un deploy target.

### `POST /api/v1/certs/:id/deploy-targets/:targetID/trigger`

Déclenche manuellement le déploiement vers ce target.

### `GET /api/v1/cert-deploy-types`

Manifestes des types de cible de déploiement, dans l'ordre d'affichage : `webhook`, `ssh_exec`. Chaque type est un **module** du registre commun (`internal/admin/certdeploy`, ADR 0007) ; `fields` décrit sa configuration (`key`, `kind`, `secret`, `required`, `multiline`). Un type ajouté au code de l'Admin apparaît ici et dans le formulaire sans autre modification. Lecture pour tout compte authentifié (`certs:read` pour un PAT).

- **`webhook`** : `url` (requise), `secret` (HMAC-SHA256, en-tête `X-GoProxify-Signature`). Les schémas non HTTP, les adresses link-local et les métadonnées cloud sont refusés (`URL refusée`) ; le réseau interne reste permis.
- **`ssh_exec`** : `host`, `user`, `private_key`, `script` (requis), `host_fingerprint` (optionnel, `SHA256:…` comme `ssh-keygen -lf`). **Confiance à la première utilisation** (Admin `0.126.0`) : laissé vide, l'empreinte de la clé d'hôte vue à la première connexion authentifiée est mémorisée dans la cible puis vérifiée aux déploiements suivants ; une clé d'hôte qui change (machine usurpée ou réinstallée) fait échouer le déploiement jusqu'à ce que l'empreinte soit corrigée (`PUT`) ou remplacée par `ignore`, qui désactive la vérification (machines éphémères). Avant, la clé d'hôte n'était jamais vérifiée. Le script reçoit `GPX_DOMAIN`, `GPX_CERT_PEM`, `GPX_KEY_PEM` et `GPX_EXPIRES_AT` (RFC 3339, UTC). Depuis Admin `0.125.0`, les valeurs sont transmises telles quelles, retours à la ligne compris : avant, le PEM arrivait avec des `\n` littéraux et `GPX_EXPIRES_AT` était toujours vide.

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
p95 de la latence sur ce même intervalle (hors WebSocket, et `0` — « inconnu » — sous 5 requêtes
mesurées dans l'intervalle) ; `series` est le débit (req/s) des derniers relevés, du
plus ancien au plus récent. `proxies` est vide (et `sampled_at` nul) tant qu'aucune passerelle n'a
été relevée deux fois.

En plus des séries par host, la réponse porte les agrégats du tableau de bord :

```json
{
  "global": { "requests_per_second": 4.0, "error_rate_5xx": 0.0, "bytes_in_total": 0, "bytes_out_total": 1005480 },
  "edges": [ { "edge_name": "localhost", "requests_per_second": 4.0, "error_rate": 0.0, "p95_ms": 9.5 } ],
  "tls": { "certs": [ { "domain": "myapp.example.fr", "expires_in_seconds": 5184000 } ] }
}
```

`global` = débit et taux de 5xx du dernier intervalle, toutes passerelles et tous hosts confondus ;
`bytes_*_total` = octets cumulés depuis le démarrage des passerelles ; `edges` = dernier intervalle
par passerelle (la page Infrastructure y lit la latence p95 affichée dans le panneau d'une passerelle) ;
`tls.certs` = plus proche expiration par domaine, lue dans les métriques des passerelles.

### `GET /api/v1/metrics/summary`

Synthèse lue par les pages Dashboard, Prism, Domaines/TLS, Infrastructure, Portail et Sécurité :
agrégats du dernier relevé des passerelles (voir `GET /api/v1/metrics/proxies`) et métriques du
processus Admin. Une section est **absente** tant que sa source n'a rien publié. Scope PAT : `metrics:read`.

| Clé | Contenu |
|-----|---------|
| `global`, `edges`, `tls.certs` | comme `/metrics/proxies` ; chaque entrée de `tls.certs` porte en plus `handshake_p95_ms` (pire passerelle) et `active_connections` (somme) quand le domaine a servi des connexions TLS ; `edges[]` ajoute `error_rate` (fraction) |
| `ws` | `admin_connections`, `agent_connections` — connexions WebSocket du plan de contrôle, somme des passerelles |
| `peers` | `avg_sync_ms` — durée moyenne des dernières synchronisations entre passerelles pairs, moyennée sur les passerelles (absent tant qu'aucune synchronisation n'a abouti) |
| `portal.sessions` | `one_shot`, `multi` — sessions du portail actives |
| `waf` | `profiles_active` — profils comportementaux en mémoire |
| `pipeline` | `[{stage, blocked_total}]` — requêtes bloquées par étape du pipeline de sécurité |
| `f2b` | `bans_total`, `scans_total` — Fail2Ban (processus Admin) |
| `crowdsec` | `decisions_new`, `decisions_deleted` — CrowdSec (processus Admin) |
| `automation` | `active_flows`, `actions_total`, `avg_duration_ms`, `evals_per_minute` (nul sans deux relevés) — flux d'automatisation |

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

### `GET /api/v1/backups/snapshots/:id/summary`

Résumé du contenu d'un snapshot, sans rien écrire — même format que `import/backup/preview` (`proxies[]`, `user_count`, `token_count`, `pat_count`, `snippet_count`, `channel_count`, `rule_count`, `declared_node_count`, `declared_nodes[]` (`id`, `role`, `name`, `region`, `environment`), `config_row_count`, `config_tables{table: n}`). Utilisé par la fenêtre « Restaurer » de l'Admin. 404 si le snapshot n'existe pas.

Le résumé expose aussi, quand la clé de chiffrement permet de lire les sections chiffrées, `secrets_detail` (`tables`, `files`, `gateways[]` = passerelles dont l'état est sauvegardé, `config_files[]`) et `history_detail` (`tables`, `truncated`) ; `secrets_locked` / `history_locked` valent `true` si la section existe mais ne se déchiffre pas.

### `POST /api/v1/backups/snapshots/:id/restore`

Restaure un snapshot. Corps optionnel `{"selection": {…}}` (mêmes champs que `import/backup/apply`) ; **sans corps**, restauration complète en mode `overwrite` (utilisateurs, tokens, PAT, snippets, canaux, règles, tables de configuration). En `overwrite`, un snapshot de sécurité `avant-restauration-<date>` est pris d'abord ; s'il échoue, la restauration est annulée (500). Réponse : `ImportResult` (dont `secret_rows`, `secret_files`, `secrets_error`). Avec `selection.import_secrets` (ou sans corps, si le snapshot a une section `secrets` et que l'appelant est superadmin), restaure la section secrets chiffrée de `GPX_BACKUP_KEY` : hash des mots de passe, MFA, clés, CA interne, fichiers `state/` et `certs/`. Superadmin seulement (`secrets_error` sinon).

### `POST /api/v1/backups/snapshots`

Crée un snapshot **en arrière-plan** : répond `202 {"status":"started","name":"…"}` aussitôt (une sauvegarde complète peut durer plusieurs dizaines de secondes, au-delà du délai d'un reverse proxy), `409` si une sauvegarde est déjà en cours. L'avancement et le résultat sont dans `GET /backups/status` (`running`, `last_run` : `name`, `ok`, `error`, `at`). Corps optionnel `{"name":"…","history":true}` : `history` joint la section historique chiffrée (journaux, audit, bans passés…, `GPX_BACKUP_KEY` requise). Les planifications portent `include_history`. Restauration (`selection`) : `import_secrets` (hash des mots de passe, MFA, clés, CA interne, fichiers `state/` et `certs/`, config HA dans `restored-config/`, **état des passerelles** renvoyé à chacune), `import_history` (ajout sans écrasement). Les deux sont réservés au superadmin ; la réponse ajoute `secret_rows`, `secret_files`, `gateways[]` (`gateway`, `written`, `rejected`, `error`, `restart_required`), `history_rows`, `secrets_error`, `history_error`.

**Interne (Admin → passerelle)** : `GET /internal/v1/backup/export` renvoie `{files:{chemin: contenu}, skipped:[…]}` ; `POST /internal/v1/backup/restore` réécrit ces fichiers (chemins relatifs filtrés) et répond `{written, rejected, restart_required}`.

### `/api/v1/backups/key`

Clé de chiffrement des sauvegardes. `GET` : `{source: env|file|none, fingerprint, can_change, retired:[{fingerprint, retired_at}]}` (jamais la clé). Superadmin uniquement pour le reste : `POST|PUT` avec `{"action":"generate"}` (clé générée, renvoyée **cette seule fois** dans `key`) ou `{"key":"…"}` (16 caractères au moins) — renvoie `{fingerprint, rotated}`, l'ancienne clé active passant parmi les retirées ; `DELETE` désactive la clé active (conservée parmi les retirées, 204) ; `POST /key/reveal` avec `{"password":"…","fingerprint":"…"}` (empreinte vide = clé active) renvoie la clé après vérification du mot de passe du superadmin ; `POST /key/retired` avec `{"key":"…"}` ajoute une ancienne clé ; `DELETE /key/retired/{fingerprint}` l'oublie. `409` si la clé active vient de `GPX_BACKUP_KEY` (ni changement, ni désactivation, ni révélation), `403` si l'appelant n'est pas superadmin ou si le mot de passe est faux. Toutes ces actions sont auditées.

### `GET /api/v1/backups/status`

État des sauvegardes : `key_set` (GPX_BACKUP_KEY définie), `last_snapshot_at`, `last_verified_at`, `stale[]` (planifications dont une exécution a été manquée), `destinations[]` (`last_ok_at`, `last_error`, `copies`), `running` (présent seulement si une sauvegarde ou une copie externe est en cours : `name`, `phase` parmi `waiting|export|secrets|history|encrypt|store|verify`, `started_at`, `delivering[]` = destinations en cours d'envoi). `launcher_image` (Admin 0.226.0) : l'image du launcher de cette installation (`GPX_DEPLOY_REGISTRY`, `GPX_DEPLOY_TAG`), dont la page Sauvegardes tire la commande qui reconstruit l'Admin sur une machine neuve ; absent si l'Admin ne la connaît pas.

### `POST /api/v1/backups/snapshots/:id/verify`

Relit le snapshot stocké : somme de contrôle SHA-256, déchiffrement, format et, s'il existe, déchiffrement de la section secrets. Réponse `{"ok":true}` ou `{"ok":false,"error":"…"}`. `GET /backups/snapshots` expose `sha256`, `verified_at` et `deliveries[]` (copies externes).

### `/api/v1/backups/destinations`

Copies hors serveur de chaque snapshot (10 au plus). `GET` liste ; `POST` crée ; `PUT /:id` modifie ; `DELETE /:id` supprime (les copies déjà déposées sont conservées) ; `POST /:id/test` écrit, relit et supprime un objet (`{"ok":…}`). Corps : `{"name","type":"dir|webdav|s3","enabled","retention","config":{…}}`. `config` — `dir` : `path` (absolu) ; `webdav` : `url`, `username`, `password` ; `s3` : `endpoint`, `bucket`, `access_key`, `secret_key`, `region`, `prefix`, `path_style` (`false` = adressage par sous-domaine). `password` et `secret_key` ne sont jamais renvoyés (`password_set` / `secret_key_set`) ; vides en mise à jour, ils conservent la valeur existante. Admin uniquement.

### `POST /api/v1/import/backup/preview`

Corps : JSON de sauvegarde (512 Mio au plus depuis Admin `0.180.1`, 32 Mo auparavant : un snapshot avec états de passerelles et secrets pèse une centaine de Mo ; au-delà, `413` avec la limite dans `error`, plus de connexion coupée). Les délais de lecture et d'écriture de cette requête passent à 15 minutes (envoi lent, restauration longue). Réponse : résumé (`proxies[]`, `user_count`, `token_count`, `pat_count`, `snippet_count`, `channel_count`, `rule_count`, `declared_node_count`, `config_row_count`, `config_tables{table: n}`). Une `version` ≠ `1` est refusée (400).

### `POST /api/v1/import/backup/apply`

Corps : `{"data": <sauvegarde>, "selection": {"proxy_ids", "import_users", "import_tokens", "import_pats", "import_snippets", "import_alert_channels", "import_alert_rules", "skip_nodes", "import_config", "import_secrets", "on_conflict": "skip|overwrite"}}` (32 Mo max). `proxy_ids` : identifiants des proxies à restaurer (vide = tous, `[""]` = aucun) ; `skip_nodes: true` ne recrée pas la topologie déclarée (restaurée par défaut). En `overwrite`, un snapshot `avant-import-<date>` est pris d'abord. Réponse : `{proxies, users, tokens, pats, snippets, channels, rules, config, declared_nodes, skipped, errors}`.

### `GET /api/v1/import/config-formats`

Formats de configuration tierce pris en charge, dans l'ordre d'affichage. Chaque format est un **module** du registre (`internal/modules`, ADR 0007) ; la CLI (`goproxify import formats`) et le sélecteur de l'Admin en dérivent.

```json
[{ "type": "nginx", "label": "nginx", "fields": [],
   "attrs": { "hint": "Blocs server { }", "extensions": [".conf"], "name_contains": ["nginx"] } }]
```

Formats : `nginx`, `traefik-yaml`, `traefik-toml`, `caddy`, `haproxy`, `goproxify` (export natif), `json` (générique : `host` + `backends`). `attrs` : `hint`, et pour la détection par nom de fichier `extensions`, `basenames`, `name_contains`, `suffixes`.

### `POST /api/v1/import/config/parse` · `POST /api/v1/import/config/apply`

`parse` : corps `{"format", "content"}` ; un `format` inconnu est traité comme du JSON générique. `apply` : corps `{"proxies": [...], "on_conflict": "skip"|"overwrite"}`.

---

## Certificats

Lecture pour tout compte authentifié ; obtention, import et suppression réservés aux admins / superadmins.

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

Liste les fournisseurs DNS ACME nommés. Admin uniquement ; scope PAT `certs:read` pour `GET`, `certs:write` pour `POST`, `PUT` et `DELETE` sur `/api/v1/acme/*` (depuis Admin `0.145.0` ; avant, aucun scope n'était exigé et un token d'admin de lecture pouvait modifier un fournisseur). CLI `goproxify acme`, MCP `list_dns_providers` et `list_dns_provider_types`.

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

### `GET /api/v1/acme/provider-types`

Manifestes des fournisseurs DNS ACME, dans l'ordre d'affichage. Admin uniquement. Chaque fournisseur est un **module** du registre (`internal/modules`, ADR 0007) ; le formulaire de l'Admin, la validation et la lecture de l'environnement en découlent.

```json
[{ "type": "cloudflare", "label": "Cloudflare", "fields": [
  { "key": "api_token", "label": "API Token", "kind": "password", "secret": true, "required": true, "env": "CF_API_TOKEN" },
  { "key": "zone_id", "label": "Zone ID", "kind": "text", "env": "CF_ZONE_ID" } ] }]
```

`env` : variable d'environnement qui fournit la valeur quand un domaine ne la renseigne pas. `attrs.status = "not_implemented"` : réservé à un fournisseur déclaré mais incapable d'émettre (aucun aujourd'hui ; Route 53, qui l'était, fonctionne depuis Admin `0.123.0`). Types natifs : `ovh`, `cloudflare`, `route53`, `hetzner`, `gandi`. Depuis Admin `0.143.0`, 28 fournisseurs [libdns](https://github.com/libdns) s'y ajoutent (`attrs.engine = "libdns"`) : `azure`, `bunny`, `cloudns`, `desec`, `digitalocean`, `dnsimple`, `duckdns`, `dynu`, `easydns`, `gcore`, `godaddy`, `googleclouddns`, `he`, `infomaniak`, `inwx`, `ionos`, `linode`, `loopia`, `luadns`, `namecheap`, `namedotcom`, `netcup`, `netlify`, `njalla`, `porkbun`, `powerdns`, `scaleway`, `vercel`. Les clés des paramètres sont les étiquettes JSON de la configuration du fournisseur libdns ; chacun accepte en plus `zone` (facultatif : déduite du domaine enregistrable, à renseigner pour une zone déléguée). Les adresses d'API saisies (`api_url`, `endpoint_url`, `server_url`…) doivent être en HTTPS et ne pas viser un réseau interne ni les métadonnées du cloud (`400` sinon) ; PowerDNS, auto-hébergé, accepte http et un réseau privé, jamais le lien local.

À partir d'Admin `0.122.0`, `POST` et `PUT /api/v1/acme/providers` renvoient `400` pour un type inconnu, un paramètre requis vide ou une clé inconnue ; `GET` masque les paramètres `secret` (`••••••••`) et `PUT` conserve un secret absent, vide ou égal au masque. Avant, la liste renvoyait les jetons en clair.

### `POST /api/v1/certs/request`

Demande un certificat ACME. La méthode suit `domains.cert_method` du domaine : DNS-01 (`dns` + `dns_provider`), HTTP-01 (`acme-http`) ou TLS-ALPN-01 (`acme-tls-alpn`). Avec HTTP-01 / TLS-ALPN-01, l'Admin pose la réponse du challenge sur les passerelles connectées (port 80 / 443 publics du domaine) ; un wildcard est refusé (`400` sur `POST`/`PUT /api/v1/domains`, `cert_method` `acme-http` ou `acme-tls-alpn`).

`edge_id` (passerelle d'entrée) accepte un token passerelle, un `node_name`, ou `ha:<groupe>` pour un groupe HA déclaré dans `architecture.json` : le périmètre domaine est alors posé sur tous les membres et les délégations sont poussées à chacun. Un groupe sans membre renvoie `400 groupe HA introuvable`. `delegated_to_edge_id` reste une passerelle unique. Une délégation relie **deux groupes différents** (Admin `0.187.0` ; ADR 0014, section 2) : `POST` et `PUT` renvoient `400 une délégation relie deux groupes HA différents` quand la source (passerelle d'entrée ou groupe `ha:<groupe>`) et la cible sont dans le même groupe, et `400 une délégation relie deux passerelles différentes` quand elles sont la même passerelle. Une passerelle seule peut déléguer à un groupe, et un groupe à une passerelle seule. Les délégations déjà enregistrées entre membres d'un même groupe ne sont pas modifiées : elles sont refusées à leur prochaine modification.

**Corps :**
```json
{ "domain": "*.example.fr", "acme_provider_id": "abc123" }
```

`acme_provider_id` (facultatif) : identifiant d'un fournisseur DNS nommé (`GET /api/v1/acme/providers`). Depuis Admin `0.123.0` il est réellement utilisé — avant, il était accepté puis ignoré. Priorité à l'émission : **fournisseur nommé > méthode et identifiants du domaine > fournisseur par défaut**. `400` si l'identifiant n'existe pas. Le fournisseur nommé est mémorisé sur le certificat et **réutilisé au renouvellement automatique** ; s'il est supprimé entre-temps, le renouvellement retombe sur les identifiants du domaine.

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

## Encrypted Client Hello — `/api/v1/ech`

ECH chiffre le nom du site (SNI) dans le handshake TLS : un observateur réseau ne voit que le **nom public** configuré. Les clés sont générées par l'Admin, poussées aux passerelles (message WS `push_ech_keys`) qui les gardent dans leur cache chiffré. Les clés privées ne sont jamais renvoyées. Admin uniquement.

### `GET /api/v1/ech`

```json
{
  "enabled": true, "public_name": "ech.example.fr",
  "active_config_id": 142,
  "config_list_b64": "AEn+DQBF…",
  "https_record": "ech=\"AEn+DQBF…\"",
  "keys": [{ "id": "…", "config_id": 142, "public_name": "ech.example.fr", "created_at": "…", "retired": false }],
  "warnings": []
}
```

`https_record` est le paramètre à ajouter à l'enregistrement DNS HTTPS (type 65) de chaque domaine protégé (ex. `1 . alpn=h2 ech="…"`). `warnings` contient `no_certificate_for_public_name` quand aucun certificat stocké ne couvre le nom public (une passerelle ne pourrait pas présenter de certificat valide à un client qui rafraîchit sa config).

### `PUT /api/v1/ech`

Corps : `{ "enabled": true, "public_name": "ech.example.fr" }`. Activer sans clé active, ou changer le nom public (gravé dans la config publiée), génère une nouvelle clé et retire l'ancienne. `400` si le nom public est invalide (wildcard, IP, un seul label). Désactiver pousse un jeu vide : les passerelles n'acceptent plus ECH. Répond comme `GET`.

### `POST /api/v1/ech/rotate`

Nouvelle clé active ; l'ancienne devient **retirée** : plus publiée, mais toujours acceptée par les passerelles le temps que les caches DNS expirent. `409` si ECH n'est pas activé. Répond comme `GET`.

### `DELETE /api/v1/ech/keys/{id}`

Supprime une clé **retirée** (`204`) ; `404` pour une clé inconnue ou active.

Limites : ECH n'est servi qu'en TCP (HTTP/1.1, h2), pas en QUIC/HTTP3 ; il est incompatible avec les hôtes en SNI passthrough (le nom interne chiffré n'est pas lisible pour choisir la route).

---

## Canaux de notification — `/api/v1/alert-channels`

Chaque type de canal est un **module** du registre (`internal/modules`) : son manifeste déclare les champs de configuration, ceux qui sont secrets et ceux qui sont requis. L'API, le masquage des secrets et le formulaire de l'interface en découlent.

### `GET /api/v1/alert-channel-types`

Manifestes des types de canal, dans l'ordre d'affichage. Lecture pour tout compte authentifié (`alerts:read`).

```json
[{ "type": "telegram", "label": "Telegram", "fields": [
  { "key": "bot_token", "label": "Bot token", "kind": "password", "secret": true, "required": true },
  { "key": "chat_id", "label": "Chat ID", "placeholder": "-1001234567890", "kind": "text", "required": true } ] }]
```

`kind` : `text`, `password`, `number`, `list` (tableau de chaînes). Types fournis : `email`, `webhook`, `ntfy`, `gotify`, `jira`, `linear`, `github`, `gitlab`, `zammad`, `glpi`, `slack`, `teams`, `telegram`, `sms`.

### `GET /api/v1/auth-provider-types`

Manifestes des 20 types de fournisseur d'authentification (`oidc`, `pocket_id`, `google`, `microsoft`, `entra`, `auth0`, `okta`, `keycloak`, `zitadel`, `casdoor`, `dex`, `github`, `ldap`, `ldap_ad`, `saml`, `basic`, `forward`, `authentik`, `authelia`, `oauth2_proxy`). Les clés sont des chemins pointés (`oidc.client_secret`) ; `basic_users` est une liste dont le mot de passe est secret, clé d'élément `username`. Admin uniquement.

### `/api/v1/auth-providers`

- `GET` (liste) et `GET /:id` : les secrets du manifeste (dont les mots de passe Basic) sont remplacés par `••••••••`. Avant Admin `0.127.0`, la configuration complète était renvoyée en clair.
- `POST` : `400` si le type est inconnu, un champ requis est vide ou une clé est absente du manifeste.
- `PUT /:id` : un secret omis, vide ou masqué est conservé (mots de passe Basic appariés par nom d'utilisateur) tant que le type ne change pas ; `provider` et `name` omis gardent leur valeur.
- `PATCH /:id` `{"enabled": bool}` : active ou désactive sans toucher à la configuration (`204`).

### `GET /api/v1/alert-channels`

Liste des canaux. Les champs `secret` du manifeste sont remplacés par `••••••••`. Avant Admin `0.120.0`, la liste de clés masquées oubliait `webhook_url` (Slack, Teams), `bot_token` (Telegram) et `auth_token` (SMS) : ces secrets étaient renvoyés en clair.

### `POST /api/v1/alert-channels`

Corps : `{ "name", "type", "config", "enabled" }`. `400` si le type est inconnu, si un champ requis manque ou est vide, ou si `config` contient une clé absente du manifeste. Les canaux déjà enregistrés ne sont jamais revalidés.

### `PUT /api/v1/alert-channels/{id}`

Corps : `{ "name", "config", "enabled" }` (le type ne change pas). Un secret absent, vide ou égal au masque est **conservé** : modifier un canal ne l'efface plus. `400` si la configuration obtenue ne passe pas la validation ; `404` si le canal n'existe pas.

### `POST /api/v1/alert-channels/{id}/test`

Envoie un message de test. `DELETE /api/v1/alert-channels/{id}` supprime le canal.

---

## Profils IP

Lecture pour tout compte authentifié ; création, modification, suppression et `refresh` réservés aux admins / superadmins.

> **Sources (Admin `0.135.5`)** : `feed_urls` doit être en http(s) et ne viser aucune adresse interne (`GPX_IPPROFILE_ALLOW_PRIVATE=1` pour l'autoriser) ; 10 sources au plus ; `feed_format` ∈ `plain`, `json-aws`, `json-gcp`, `json-fastly`, `tsv-dshield` ; `refresh_interval_h` dans [0, 8760]. La connexion vers une adresse interne est aussi refusée au moment de lire la source (rebinding DNS).

### `GET /api/v1/ip-profiles` · `GET /api/v1/ip-profiles/:id`

Liste / détail des profils IP (`id`, `name`, `profile_type`, `mode`, `feed_urls`, `feed_format`, `refresh_interval_h`, `cidrs`, `enabled`, `last_updated_at`…). Champs d'état du rafraîchissement automatique :

| Champ | Description |
|---|---|
| `last_updated_at` | Dernier rafraîchissement **réussi** (un échec ne le modifie pas) |
| `last_error` | Cause du dernier échec ; absent après un succès |
| `consecutive_failures` | Nombre d'échecs consécutifs ; absent (0) après un succès |
| `next_attempt_at` | Prochaine tentative automatique (UTC) après un échec ; absent sinon |

Après un échec (réseau, HTTP ≠ 200, parsing, liste rejetée par le garde-fou), les CIDRs déjà stockés restent appliqués et le profil est retenté avec un délai de 15 min doublé à chaque échec, plafonné à 6 h et à `refresh_interval_h`.

### `POST /api/v1/ip-profiles` · `PUT /api/v1/ip-profiles/:id`

Création / modification. Une liste vient soit d'un feed (`feed_urls`, `feed_format`, `refresh_interval_h`), soit d'une saisie manuelle (`cidrs` : IP ou CIDR, validés, dédupliqués et agrégés). Les deux sont exclusifs, car un rafraîchissement remplacerait la liste manuelle, et un profil manuel n'est jamais rafraîchi. `mode` : `deny` (défaut) ou `allow` ; `profile_type` vaut `custom` par défaut. Un profil s'applique à tout le trafic de chaque passerelle, `allow` prime sur `deny`, les adresses privées ne sont jamais bloquées.

| Cas | Réponse |
|---|---|
| CIDR invalide, `mode` inconnu, `cidrs` avec `feed_urls`, ni `feed_urls` ni `cidrs` (création) | `400 {"error":…}` |
| Création réussie | `201 {"id":…}` |
| Modification réussie | `204` ; sans `cidrs` dans le corps, la liste stockée est conservée |

### `POST /api/v1/ip-profiles/:id/refresh`

Force un rafraîchissement complet (téléchargement inconditionnel, garde-fou de taille ignoré). `200 {"status":"refreshed"}`, ou `400 {"error":…}` en cas d'échec (profil sans feed, feed injoignable…). Le rafraîchissement automatique rejette une nouvelle liste qui perd plus de la moitié d'une liste d'au moins 10 entrées (feed vide ou tronqué) : la liste actuelle est conservée et l'échec est enregistré ; ce endpoint permet de l'accepter.

---

## Snippets

Lecture pour tout compte authentifié ; écritures réservées aux admins / superadmins et aux comptes `user` disposant d'au moins un grant `write`.

### Plugins intégrés (Admin `0.137.0`, `coraza` ajouté en `0.138.0`)

`GET /api/v1/plugin-repos/catalog` ajoute toujours les entrées du dépôt intégré (`repo_id` `builtin`, `repo_name` « Exemples intégrés », `builtin: true`, jamais `signed`) ; `?repo=builtin` ne renvoie qu'elles et ne contacte aucun dépôt distant, `?repo=<autre id>` les écarte. `POST /api/v1/plugin-repos/install` avec `repo_id: "builtin"` installe l'exemple nommé sans signature (`201`, ou `200` s'il remplace une version installée ; `404` si le nom est inconnu) ; `signed_by` vaut `builtin`.

### `/api/v1/plugins`

Plugins WebAssembly (voir [plugins.md](plugins.md), ADR 0008). **Admin uniquement** ; scope PAT `audit:read` (lecture) / `security:write` (écriture), car installer un plugin fait exécuter du code sur les passerelles.

- `GET` : liste (`name`, `version`, `api_version`, `hooks`, `on_error`, `limits`, `fields`, `sha256`, `size`, `updated_at`) ; le module n'est jamais renvoyé. `GET /:name` : un plugin.
- `POST` : `{"manifest": {…}, "sha256": "<empreinte du module>", "wasm": "<base64>"}`. `201` ; `409` si le nom existe ; `400` si l'empreinte manque ou diffère, si le module dépasse 2 Mio, n'est pas du WebAssembly valide, importe autre chose que `gpx.log` ou n'exporte pas ce que le manifeste déclare, ou si le manifeste est invalide. Le module est compilé avant tout enregistrement.
- `PUT /:name` : remplace (`200`, `404` si inconnu, `400` si le nom du manifeste diffère).
- `DELETE /:name` : `204`. Les routes qui référencent un plugin supprimé refusent le trafic (`503`).

Chaque changement est poussé à toutes les passerelles (liste complète). Une route référence un plugin par `plugins: [{"name", "config"}]` ; le dry-run refuse un plugin inconnu, en double, ou une configuration qui ne respecte pas son manifeste.

### `/api/v1/plugin-repos`

Dépôts de plugins (voir [plugins.md](plugins.md)). Admin uniquement ; scopes PAT comme `/plugins`.

- `GET` : `[{id, name, url, allow_private, created_at}]`. `POST` `{name, url, allow_private}` : `201`, `409` si l'URL existe, `400` si l'URL n'est pas HTTPS (HTTP seulement avec `allow_private`) ou vise une adresse interne sans `allow_private`. `DELETE /:id` : `204` (les plugins installés restent).
- `GET /catalog[?repo=id]` : `{entries: [{repo_id, repo_name, name, version, description, homepage, hooks, sha256, signed, installed_version, update_available}], errors: [{repo_id, repo_name, error}]}` ; un dépôt injoignable est signalé sans bloquer les autres. Plus récente version d'abord.
- `POST /install` `{repo_id, name, version?}` : l'index est relu côté serveur, le module téléchargé, son empreinte et sa signature vérifiées selon la politique de `/plugins` ; `201` (installé) ou `200` (remplacé), `404` (dépôt ou plugin inconnu), `400` (empreinte, signature, module ou manifeste refusés), `502` (dépôt injoignable, entrée incohérente).

### `/api/v1/plugin-keys`

Clés publiques Ed25519 de confiance pour la signature des plugins. Admin uniquement ; mêmes scopes PAT que `/plugins`.

- `GET` : `[{id, name, public_key, created_at}]` (`id` = 8 premiers octets du SHA-256 de la clé, en hexadécimal).
- `POST` `{"name", "public_key": "<base64, 32 octets>"}` : `201` ; `409` si la clé existe ; `400` si elle est illisible.
- `DELETE /:id` : `204`. Les plugins déjà installés ne sont pas retirés.

**Politique de signature** de `POST`/`PUT /api/v1/plugins` (champ `signature`, Ed25519 en base64 sur le manifeste normalisé et l'empreinte du module) : sans clé de confiance, la signature est facultative mais, fournie, elle est refusée (`400`) car invérifiable ; avec au moins une clé, elle est obligatoire et doit se vérifier avec l'une d'elles. La réponse et la liste portent `signed_by` (identifiant de la clé).

### `GET /api/v1/security/engine-types`

Manifestes des moteurs de sécurité globaux : `ephor` (champs dérivés de la configuration, chemins pointés), `fail2ban`, `crowdsec` (`api_key` secret), `waf` (interrupteur maître : `enabled`). Admin uniquement. Outil MCP `list_security_engine_types`, CLI `goproxify security engines`.

### `PUT /api/v1/security/threat-config`, `/fail2ban`, `/crowdsec` — validation

Les trois configurations sont validées avant enregistrement (`400` avec le motif, rien n'est écrit ni poussé) : clé inconnue à tous les niveaux, valeur du mauvais type, durée illisible ou négative, seuil négatif, IP ou CIDR invalide, mode Ephor hors `block|detect`, code d'erreur HTTP hors 400-599, source de liste non http(s), chemin sans `/` initial, `tarpit.delay_ms` au-delà de 30000 ; CrowdSec activé exige `api_url` (http/https) et `api_key`. `GET /security/crowdsec` remplace `api_key` par `••••••••` (avant Admin `0.130.0`, la clé du bouncer était renvoyée en clair) ; omise, vide ou masquée dans un `PUT`, elle est conservée.

### `GET /api/v1/detector-types`

Manifestes des détecteurs par route : `ip_filter`, `geo_ip`, `bot`, `waf` (champs, secrets, requis). Scope `snippets:read`.

### `/api/v1/snippets` — détecteurs

- `POST` / `PUT` : la configuration d'un snippet `ip_filter`, `geo_ip`, `bot` ou `waf` est validée par son manifeste — clé inconnue, champ requis vide, mode hors `allow|deny` (`ip_filter`, `geo_ip`) ou `block|detect` (`waf`), CIDR invalide, code pays qui n'est pas ISO 3166-1 alpha-2, expression de règle WAF invalide, fournisseur de défi inconnu ⇒ `400`. Les autres types gardent une configuration libre.
- `GET` : `challenge_secret` et `challenge_provider_secret` (bot) sont remplacés par `••••••••` ; omis ou masqués à la modification, ils sont conservés. `PUT` sans `type` conserve le type enregistré ; `404` si le snippet n'existe pas.

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

Liste les passerelles et Agents enregistrés avec leur état. Un Agent connu de plusieurs membres d'un groupe HA n'y figure qu'une fois (la plus récemment vue, Admin `0.182.0`) ; `target_edge` est alors la passerelle du groupe qui le tient.

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

### `GET /api/v1/discovery-sources`

Manifestes des sources de découverte de l'Agent, dans l'ordre de démarrage : `docker`, `portainer`, `kubernetes`, puis (Admin `0.144.0`) les annuaires de services `consul`, `nomad`, `etcd` et `ecs`. Admin uniquement (`nodes:read` pour un PAT). Chaque source est un **module** du registre commun (`internal/agent/sources`, ADR 0007) ; le champ `fields` décrit sa configuration dans `agent.json` (clé, genre, `secret`, `required`). Une source ajoutée au code de l'Agent apparaît ici sans autre modification.

```json
[{ "type": "kubernetes", "label": "Kubernetes", "fields": [
  { "key": "api_server", "label": "API server (empty = in-cluster)", "kind": "text" },
  { "key": "token", "label": "Bearer token (empty = service account)", "kind": "password", "secret": true } ] }]
```

Une source qui n'a pas de section dédiée dans `agent.json` se configure sous `sources.<type>`, validée par son manifeste (champ requis manquant ou clé inconnue : source ignorée, journalisée). Le heartbeat de l'Agent expose désormais la section `kubernetes` (secrets masqués) en plus de `docker` et `portainer`.

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

Réservé aux administrateurs (`403` sinon, depuis Admin `0.135.18` ; aucun contrôle de rôle avant). Déclare un nœud (`role`: `edge`|`agent`, `name`, `region`, `environment`, `config`). Upsert par `(role, name)`.

### `DELETE /api/v1/declared-nodes/:id`

Supprime un nœud déclaré. Réservé aux administrateurs.

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

### `POST /api/v1/architecture/recover` `[AUTH]`

Rôle admin requis (Admin `0.187.0` ; ADR 0014, section 8). Reconstitue `architecture.json` à partir des **fiches de groupe** que détiennent les passerelles : un Admin neuf, connecté à au moins une passerelle, retrouve les groupes HA, leurs membres (identifiant, nom, adresse) et leurs domaines, identifiants DNS compris. Ce que le fichier connaît déjà (même identifiant ou même nom pour un nœud, même identifiant ou même domaine pour un domaine) n'est pas modifié ; une passerelle connue mais sans configuration rejoint son groupe. La version de fiche retenue pour un groupe est la plus haute vue. La base est ensuite réalignée sur le fichier et les passerelles reconnectées. Prérequis d'un Admin neuf : le même `GPX_PAIRING_SECRET` et l'adresse d'au moins une passerelle (`GPX_IDENTITY_EDGE_NODE_NAME`, `GPX_EDGE_EXTRA_ENDPOINTS`), les autres membres étant découverts par les pairs ; l'Admin se connecte par la signature HMAC et crée ses propres jetons, sans approbation. Les jetons que l'ancien Admin avait poussés restent valables sur les passerelles.

**Body (facultatif) :** `{"edges": ["frontal", "backup"]}` : les passerelles à interroger par nom ou identifiant de jeton ; vide = toutes les passerelles appairées.

**Réponse :** `{"cards": 2, "unreachable": ["backup : …"], "added": {"groups": ["ha-1"], "nodes": 1, "joined": 1, "domains": 3, "skipped": 0}, "applied": {…}}`. `unreachable` liste les passerelles qui n'ont pas répondu : la reconstitution est alors partielle et peut être rejouée.

### `POST /api/v1/bootstrap-tickets` `[AUTH]`

Crée un ticket one-shot pour intégrer un hôte (QR + lien + script). Réservé aux administrateurs (`403` sinon, depuis Admin `0.135.18`).

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

### `GET /api/v1/hosts` `[AUTH]`

Rôle admin requis (Admin `0.221.0` ; [ADR 0019](adr/0019-launcher-bootstrap-multi-hotes.md), étape 4). Les hôtes déclarés dans `architecture.json` : les nœuds qui partagent `config.host` forment un hôte, dont l'adresse est `config.reachable_host` (sans le port du hub).

**Réponse 200 :**
```json
[
  {"name": "nas", "addr": "192.168.1.50", "roles": ["agent"], "status": "pending",
   "nodes": [{"name": "goproxify-agent", "role": "agent", "status": "declared"}],
   "ticket": {"expires_at": "2026-10-30T17:46:15Z"}}
]
```

`status` vaut `joined` (tous les nœuds en ligne), `partial` ou `pending` (aucun). `ticket` n'apparaît que pour un hôte pas encore intégré qui a un ticket valide ; le jeton n'est jamais relisible. L'état des Agents est demandé aux passerelles avec un délai de 2 secondes : une passerelle qui ne répond pas (pas encore installée) laisse ses Agents à `declared`.

### `POST /api/v1/hosts/{name}/join-ticket` `[AUTH]`

Rôle admin requis (Admin `0.221.0`). Crée pour l'hôte `{name}` un ticket d'installation **de 15 minutes**, à usage unique, qui remplace le précédent de l'hôte (un seul ticket valide par hôte). Tant qu'il vaut, les nœuds de l'hôte sont acceptés automatiquement ; il est consommé quand chacun est arrivé (l'Agent à son approbation, la passerelle à sa première connexion avec l'Admin).

**Réponse 200 :**
```json
{
  "host": "nas",
  "node_names": ["goproxify-agent"],
  "token": "f44279b7…",
  "expires_at": "2026-10-30T17:46:15Z",
  "spec_url": "https://192.168.1.10:9443/api/v1/join/f44279b7…",
  "fingerprint": "01934a860d5accf2…",
  "trigger_url": "http://192.168.1.50:8080/join?admin=https%3A%2F%2F192.168.1.10%3A9443&fp=01934a86…&host=nas&roles=agent&token=f44279b7…",
  "qr_code": "data:image/png;base64,…",
  "listen_command": "docker run --rm -p 8080:8080 -v /var/run/docker.sock:/var/run/docker.sock ghcr.io/vincamok/goproxify/launcher:preview",
  "join_command": "docker run --rm -v /var/run/docker.sock:/var/run/docker.sock ghcr.io/vincamok/goproxify/launcher:preview join https://192.168.1.10:9443/api/v1/join/f44279b7… --fingerprint 01934a86…"
}
```

- `spec_url` est bâtie sur l'URL publique de l'Admin. `fingerprint` est le SHA-256 (hexadécimal) du certificat que l'Admin sert lui-même, à comparer avant de présenter le jeton ; vide derrière un reverse proxy.
- `trigger_url` est ce que le QR code encode (Admin `0.222.0`) : la page de confirmation du launcher de l'hôte, en attente sur son port 8080 (`http://<adresse de l'hôte>:8080/join`), avec l'Admin, le jeton, l'empreinte et, à titre d'indication affichée, le nom et les rôles de l'hôte. `qr_code` est son PNG en data URL. Le scan n'ouvre qu'une page : l'installation démarre au clic sur « Installer ».
- `listen_command` lance le launcher de l'hôte en attente de ce lien ; `join_command` installe l'hôte tout de suite, sans QR code. Les images viennent de `GPX_DEPLOY_REGISTRY` et `GPX_DEPLOY_TAG`.
- Si l'Admin n'a pas d'adresse publique en https (`GPX_ADMIN_PUBLIC_URL`), `trigger_url` et `qr_code` sont absents et `warning` le dit : le launcher refuse un Admin en clair.
- `404` si l'hôte n'est pas dans l'architecture, `409` s'il est déjà intégré.

### `GET /api/v1/join/{token}` `[PUBLIC]`

Le ticket (secret, 15 minutes) fait foi. Rend la description structurée de l'hôte (`version`, `networks`, `volumes`, `containers`, voir `internal/deploy`), que le launcher applique par l'API Docker : images, variables, ports, montages, réseaux. Elle contient les **clés dérivées** de l'hôte (clé des Agents, clé de canal de sa passerelle, clé du portail), jamais le secret racine. Lire la description ne consomme pas le ticket. `Cache-Control: no-store`. `404` si le ticket est inconnu, expiré ou d'une autre nature (un ticket d'intégration `/i/{token}` n'ouvre pas cette route), `500` si l'Admin n'a pas de secret racine. À ne servir qu'en TLS. Les images viennent de `GPX_DEPLOY_REGISTRY` et `GPX_DEPLOY_TAG` de l'Admin (le launcher les y pose).

### `POST /api/v1/nodes/revoke-stale-admin-tokens` `[AUTH]`

Rôle admin requis (Admin `0.188.0` ; ADR 0015, éviction d'urgence). Un Admin que l'on remplace laisse sur les passerelles le jeton qu'il leur avait poussé (message `admin_token`) : il reste valable tant que personne ne le retire. Cet appel fait révoquer, par chaque passerelle connectée, **tous les jetons poussés par un Admin sauf celui de l'Admin qui appelle** (message `revoke_stale_admin_tokens` : la passerelle enregistre d'abord le jeton à garder, l'appelant ne se coupe donc jamais l'accès). Les jetons d'amorçage de la configuration (`admin-<nœud>`) ne sont pas touchés. À lancer après avoir remplacé l'Admin ou quand l'ancien est compromis ; **pas à lancer si deux Admins vivent ensemble avec des jetons différents** (le second perdrait l'accès). Une passerelle hors ligne le fait à sa prochaine connexion seulement si l'appel est relancé : l'appel ne retient rien. Réponse : `{"gateways": 2}`, le nombre de passerelles sollicitées. Journalisé dans l'audit.

### `POST /api/v1/nodes/:id/rotate-token` `[AUTH]`

Rôle admin requis (Admin `0.191.0` ; ADR 0015, éviction d'urgence d'un nœud). Remplace le jeton que l'Admin a pour la passerelle `:id` (identifiant ou nom), le lui pousse (`admin_token`), lui fait révoquer l'ancien (`revoke_stale_admin_tokens`, à sa reconnexion si elle est hors ligne) et redonne la liste des pairs à toutes les passerelles, qui s'appellent avec ces jetons. Un membre sorti d'un groupe connaît les jetons de ses pairs : l'Admin le fait **automatiquement** pour chaque membre restant quand un membre quitte un groupe (après la rotation de la clé du groupe). Réponse : `{"rotated": "<id>"}` ; `404` si l'Admin ne connaît pas cette passerelle. Journalisé dans l'audit. Cela n'évince pas la machine elle-même : pour cela, supprimez le nœud (son jeton est révoqué) et migrez ou faites tourner le secret racine.

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

Liste tous les bans correspondant aux filtres, du plus récent au plus ancien. Paramètres : `active=true` (non expirés) ou `active=false` (expirés uniquement), `ip` (sous-chaîne), `domain`, `source` (`native|fail2ban|crowdsec|threat|automation|automation:<nœud>|plugin:<nom>`, ce dernier pour les bans d'un plugin de détection comme `plugin:coraza`), `edge` (nom du nœud ou id du token : les bans de cette passerelle **et** les bans globaux). Chaque entrée porte `edge_name`, la passerelle d'origine (vide = ban global : créé depuis l'Admin ou antérieur à cette colonne).

*(Admin `0.193.0`, Edge `0.107.0`)* Un ban posé par Ephor ou par le WAF comportemental porte aussi `signals` : la liste des signaux qui l'ont causé, `[{ "name", "points", "value" }]`, du plus lourd au plus léger. `name` est le signal (`custom_path`, `ua`, `rate`, `error4xx`, `tls_fp`… ; pour le WAF `path_scanning`, `request_burst`…), `points` ce qu'il a apporté (leur somme explique la décision : sur un score cumulé, c'est le score au moment du ban, décru de la demi-vie), `value` ce qui l'a déclenché (chemin, User-Agent, empreinte TLS, `> 5 req/s`…), borné à 200 caractères. Absent pour les autres sources. Ils viennent de la passerelle qui a banni, qui les garde dans sa base locale, les relaie à ses pairs HA et les envoie à l'Admin (`security_bans.signals`, `security_ban_history.signals`).

*(Admin `0.207.0`, Edge `0.121.0`)* Un ban automatique porte aussi `user_agent` : le dernier User-Agent que la passerelle a vu pour l'IP au moment où elle l'a bannie, quel que soit le moteur (Ephor, WAF, Fail2Ban, plugin de détection, règle automatique). Il dit quel client a provoqué le ban, là où la raison seule (`threat: score cumulé`, `trop d'erreurs 4xx`…) ne le dit pas. Absent des bans manuels, importés ou CrowdSec (aucune requête n'a été vue par la passerelle), et quand l'IP n'a envoyé aucun User-Agent ; borné à 300 caractères, caractères de contrôle remplacés par `?`. Il suit le ban comme les signaux (copie locale de la passerelle, pairs HA, `security_bans.user_agent` et `security_ban_history.user_agent`).

`GET /security/bans/countries`, `GET /security/bans/export` (CSV ou JSON, colonne `edge_name` ajoutée) et `GET /security/bans/intel/{kpis,by-reason,by-source,timeline,top-ips}` acceptent le même paramètre `edge`. `intel/kpis` renvoie `history_total` (bans posés), `unbanned` (débans), `rotation_ratio` (`unbanned / history_total`) et `recurring_ips`, le nombre d'IP ayant au moins 3 bans ; le nombre de bans actifs est la longueur de `GET /security/bans?active=true`.

### `POST /api/v1/security/bans`

Crée un ban manuel. Corps : `{ "ip", "domain", "reason", "expires_at", "target_scope" }`. Réponse `201` : `{ "id" }`.

`target_scope` limite les passerelles qui appliquent le ban : vide (défaut) = toutes, sinon le nom (ou l'id du jeton) d'une passerelle enregistrée, ou `group:<nom>` pour les membres d'un groupe HA existant (`400` si inconnu). L'Admin ne pousse à chaque passerelle que les bans globaux, ceux de sa portée et ceux de son groupe. La portée est renvoyée par `GET /security/bans` (`target_scope`) et filtrable par `?scope=<valeur exacte>`.

`ip` est une adresse IPv4/IPv6 **ou une plage CIDR**. La valeur est validée et normalisée avant d'être enregistrée : une plage est ramenée à son adresse de réseau (`203.0.113.7/24` → `203.0.113.0/24`), une adresse seule reste telle quelle (`/32` et `/128` retirés, IPv6 en minuscules, IPv4 mappée dépliée). Une valeur illisible, avec zone IPv6 ou composée (`1.2.3.1-9`) renvoie `400` (avant, elle était enregistrée puis ignorée sans rien dire par les passerelles). Sont aussi refusées : une plage plus large que `/16` en IPv4 ou `/32` en IPv6 (`400` — pour une plage plus large, un profil IP) et une plage qui **contient l'adresse de l'appelant** (`409`, pour ne pas se couper soi-même ; l'adresse est lue dans `X-Forwarded-For` sinon l'adresse distante, et le contrôle ne vise pas une adresse seule). Les passerelles appliquent la plage à toute adresse qu'elle contient, hors réseaux privés. Débannir une adresse située dans une plage bannie ne lève pas le ban de la plage : supprimer la plage elle-même (`DELETE`), ou créer un profil IP en mode allow, qui l'emporte sur les bans.

### `GET|POST|DELETE /api/v1/security/bans/whitelist`

**Liste blanche des bans** : adresses et plages qu'aucun ban n'atteint (manuel, Fail2Ban, CrowdSec, Ephor, règles automatiques) et que Ephor n'évalue pas. Réservée aux administrateurs.

- `GET` : `[{ "value", "comment", "added_by", "added_at", "bans_exempted" }]`, `bans_exempted` étant le nombre de bans actifs entièrement couverts par l'entrée (donc sans effet).
- `POST { "ip", "comment" }` : ajoute une adresse ou un CIDR, validé et normalisé comme pour un ban (`400` si illisible ou plus large que `/16` IPv4 / `/32` IPv6). `201 { "added": true, "entry": {…} }` ; si une entrée existante couvre déjà la cible, `200 { "added": false, "covered_by": "<entrée>" }` et rien ne change ; les entrées plus précises que la nouvelle sont retirées (redondantes).
- `DELETE ?ip=<valeur enregistrée>` : retire l'entrée (`204`, `404` si elle n'existe pas). Les bans qu'elle neutralisait s'appliquent de nouveau.

Les bans existants ne sont jamais supprimés par un ajout : ils cessent seulement de s'appliquer, et `GET /security/bans` les marque `"exempt": true` quand la liste blanche couvre toute leur cible. Les entrées sont recopiées dans un profil IP en mode `allow` d'identifiant `bans-whitelist` (nom « Liste blanche (bans) ») que les passerelles reçoivent et conservent : elles l'appliquent sans l'Admin, y compris après un redémarrage. Ce profil est **géré ici** : `PUT` et `DELETE /ip-profiles/bans-whitelist` renvoient `409`. À la différence d'un profil allow ordinaire, il exempte aussi de la détection Ephor (requêtes non évaluées ni comptées). Un ban dont la cible est entièrement en liste blanche est refusé (`409`) ; une plage qui ne fait que recouper une entrée reste permise, l'entrée en restant exemptée. Outils MCP `list_ban_whitelist`, `add_ban_whitelist`, `remove_ban_whitelist` ; CLI `goproxify security bans whitelist`.

### `GET /api/v1/security/asn` · `GET /preview` · `POST /ban` · `DELETE /ban` · `GET /info` · `POST /refresh`

**Bans par ASN.** Bannir un ASN crée un ban par plage qu'il annonce (CIDR), comme un import de liste. Réservé aux administrateurs. Les données viennent du jeu public ip2asn (iptoasn.com), téléchargé par l'Admin au premier usage (`503` s'il est absent et injoignable).

- `GET /security/asn?q=<AS16276|16276|adresse IP|nom>` : `[{ "asn", "name", "country", "ranges", "v4_addresses", "v6_ranges", "banned_ranges" }]` ; une adresse IP donne l'ASN qui l'annonce, un nom jusqu'à 20 ASN (les plus grands d'abord) ; `banned_ranges` = bans actifs déjà créés pour cet ASN.
- `GET /security/asn/preview?asn=<ASN>&hours=24` : aperçu sans rien créer. `would_create`, `skipped_count`, `rejected_count` (avec `skipped` / `rejected` : `[{ "line", "value", "reason" }]`), `prefixes`, `too_wide`, trafic de la période (`requests`, `blocked`, `ok_requests`, `ips`, `ok_ips`, `top_ips`, `countries`), `requester_in` et `warnings`.
- `POST /security/asn/ban` : corps `{ "asn", "reason", "domain", "expires_at", "scope", "dry_run" }`. Réponse : l'ASN (`asn`, `name`, `country`, `announced_ranges`, `prefixes`, `too_wide`) et le rapport d'import (`created`, `skipped_count`, `rejected_count`, `skipped`, `rejected`, `dry_run`). `reason` vaut par défaut « AS<numéro> <nom> » ; `scope` se comporte comme `target_scope` d'un ban. Les plages plus larges que `/16` (IPv4) sont découpées en `/16` (une plage qui donnerait plus de 1 024 morceaux est ignorée : `too_wide`) ; les plages déjà bannies, en liste blanche ou privées sont ignorées. `409` si l'ASN contient l'adresse de l'appelant ; `404` si l'ASN est inconnu ; `400` pour une valeur invalide. Un seul envoi aux passerelles pour tout le lot. Le ban est un instantané : relancer la même requête ajoute les plages annoncées depuis.
- `DELETE /security/asn/ban?asn=<ASN>` : supprime les bans créés pour l'ASN (historique alimenté) et les lève sur les passerelles en un seul envoi. Réponse `{ "asn", "removed" }`.
- `GET /security/asn/info` : état de la base (`installed`, `updated_at`, `size_bytes`, `asns`, `ranges`) ; `POST /security/asn/refresh` la télécharge à nouveau.

`GET /security/bans` renvoie `asn` (numéro, absent hors ban d'ASN) pour chaque ban créé de cette façon.

### `POST /api/v1/security/bans/import`

**Import de liste** : crée des bans (ou des entrées de la [liste blanche](#getpostdelete-apiv1securitybanswhitelist)) à partir d'une liste d'adresses IP et de CIDR. Corps JSON : `content` (le texte de la liste, 2 Mo et 10 000 entrées au plus), `scope` (portée des bans créés, comme `target_scope` de `POST /security/bans` ; ignorée pour la liste blanche), `format` (`auto` par défaut, `text`, `csv` ou `json`), `target` (`bans` par défaut, ou `whitelist`), `reason` (motif des bans, ou commentaire des entrées, sans motif propre ; `import` par défaut), `domain` (domaine ciblé par les bans sans domaine propre), `expires_at` (expiration RFC3339 des bans sans expiration propre ; vide = permanent) et `dry_run`.

Formats : **texte** (une adresse ou un CIDR par ligne, commentaires `#` et `;` ; le commentaire d'une ligne devient son motif — `1.10.16.0/20 ; SBL256894`, liste Spamhaus DROP, donne le motif `SBL256894` —, ce qui permet d'importer les listes publiques FireHOL, blocklist.de ou Spamhaus), **CSV** (colonne `ip`, `cidr` ou `address` ; colonnes facultatives `reason`, `domain`, `expires_at` ; les autres colonnes sont ignorées, donc le CSV de `GET /security/bans/export` se réimporte tel quel ; sans en-tête : `ip[,reason]`) et **JSON** (tableau de chaînes, ou d'objets `ip`/`cidr`, `reason`, `domain`, `expires_at`, donc l'export JSON aussi). Le format est détecté quand `format` est absent.

Chaque entrée est validée comme à la création unitaire : normalisation (`203.0.113.7/24` → `203.0.113.0/24`), plage plus large que `/16` (IPv4) ou `/32` (IPv6) **rejetée**, plage qui contient l'adresse de l'appelant **rejetée** (pour les bans seulement), expiration illisible **rejetée**. Sont **ignorées** (valides mais sans objet) : un doublon dans la liste, une entrée couverte par une plage plus large de la même liste, une cible déjà couverte par un ban actif ou par la liste blanche, une plage privée ou locale (jamais bloquée par les passerelles). Les bans sont créés en une transaction (source `native`, historique alimenté) puis poussés **une seule fois** aux passerelles ; l'import est audité (`import_bans`).

Réponse `200` : `dry_run`, `target`, `format`, `total` (entrées lues), `created` (créées, ou qui le seraient en `dry_run`), `addresses` (adresses couvertes), `skipped` / `rejected` (`[{ "line", "value", "reason" }]`, 200 premières lignes) avec `skipped_count` / `rejected_count` exacts, et `sample` (quelques valeurs créées). `400` si la liste est vide, trop volumineuse, illisible dans le format demandé, ou si `target`, `format` ou `expires_at` sont invalides. Avec `dry_run`, rien n'est écrit ni poussé : à utiliser d'abord. Outil MCP `import_security_bans`, CLI `goproxify security bans import`, bouton « Importer » de la page Bans.

### `GET /api/v1/security/bans/preview`

Aperçu de l'impact d'un ban **avant de le créer**, sans rien modifier. *(Admin `0.172.0`)* Le trafic de la cible est lu dans les bases de logs des passerelles : les comptes sont exacts (plus de plafond de lignes lues), `scan_limited` n'indique plus qu'une passerelle partielle, et un avertissement nomme les passerelles injoignables. Paramètres : `ip` (adresse ou CIDR, validé comme à la création, `400` sinon) et `hours` (période de trafic analysée, défaut 24, max 168). Réponse : `target` (forme normalisée), `kind` (`ip|cidr`), `prefix_bits`, `addresses` (nombre d'adresses), `private` (réseau privé ou local, jamais bloqué par les passerelles) ; le trafic de la cible sur la période — `requests`, `blocked` (403, 429, WAF ou Ephor), `ok_requests` et `ok_ips` (requêtes réussies, donc probablement légitimes, et leurs adresses : ce que le ban couperait), `ips`, `top_ips`, `countries`, `scan_limited` ; `existing_bans` (bans actifs qui recoupent la cible, avec `relation` : `same`, `covers` — la cible est déjà couverte —, `inside` — le nouveau ban les englobe — ou `overlaps`) ; `profiles` (profils IP actifs qui la recoupent, un profil `allow` l'emporte sur un ban) ; `requester_in` (la plage contient l'appelant : la création serait refusée) ; `whitelist` (entrées de la [liste blanche](#get-post-delete-apiv1securitybanswhitelist) qui recoupent la cible) et `whitelisted` (la cible est entièrement exemptée : la création serait refusée) ; et `warnings`, une liste de messages lisibles. Mêmes droits que la liste des bans ; outil MCP `preview_security_ban`, CLI `goproxify security bans preview`.

`expires_at` est une date RFC3339 (décalage horaire et fractions de seconde acceptés), enregistrée en UTC à la seconde (`2026-12-31T23:59:59Z`) ; absent, `null` ou `""` → ban permanent. Depuis Admin `0.69.5`, une date illisible renvoie `400` au lieu d'être enregistrée telle quelle (le ban n'était alors jamais actif). Il n'y a pas de champ `ttl` : une durée se convertit en `expires_at` côté client, comme le fait `goproxify security bans add -ttl`.

### `PATCH /api/v1/security/bans/:id`

Modifie l'expiration d'un ban. Corps : `{ "expires_at": "<RFC3339>" }` (même validation et normalisation qu'à la création, `""` → permanent) ou `{ "permanent": true }`. Réponse `204` ; `400` si l'expiration est illisible ou si le corps ne porte aucun des deux champs.

### `DELETE /api/v1/security/bans/:id`

Supprime un ban par ID.

### `GET /api/v1/security/threats`

Liste les menaces CrowdSec (`security_threats`), triées par `last_seen_at` décroissant. Paramètre : `limit`. Une même menace (`ip`+`scenario`) est dédupliquée : chaque nouvelle occurrence rafraîchit `last_seen_at` et incrémente `occurrences` au lieu de créer une ligne ignorée à date figée. Chaque entrée inclut aussi `edge_name` — la passerelle d'origine, résolu côté serveur depuis le token d'appairage à la réception (vide pour les données antérieures à cette colonne).

### `GET /api/v1/security/ip-trace`

*(Admin `0.172.0`, Edge `0.82.0`)* Les lignes viennent des bases de logs des passerelles (accès et système, jusqu'à 400 000, les plus récentes d'abord ; `summary.scan_limited` si la limite coupe la lecture) ; `summary.partial` et `summary.unreachable` disent quelles passerelles manquent. Sans passerelle enregistrée la trace est vide (depuis Admin `0.176.0` l'Admin n'a plus de copie des accès à lire).

**Étendue ASN.** La réponse contient `scope`, `scope_label` (par exemple `5.0.0.0 – 5.0.1.255 (AS64500 EXEMPLE)` ou `AS64500 EXEMPLE`) et `asn_context` : `{ "asn": { "asn", "name", "country", "ranges", "v4_addresses", "v6_ranges", "banned_ranges" } }`. `asn_context` n'est renseigné que si la base ASN est **déjà installée** (un traçage simple ne la télécharge jamais), sinon `null` ; avec `scope=asn` elle est chargée, et téléchargée au besoin.

Parcours complet d'une IP ou d'un CIDR (rôle admin). Reconstitue, sur la période demandée, les requêtes d'accès (logs), les détections (`security_threats`), les bans et débans (`security_ban_history`), les bans en cours et les profils IP qui contiennent la cible.

| Paramètre | Description |
|-----------|-------------|
| `target` (alias `ip`) | **Requis** (sauf avec `asn`). IP (`203.0.113.7`, `2001:db8::1`) ou CIDR (`198.51.100.0/24`). `400` si invalide |
| `scope` | Étendue du parcours : `ip` (défaut, la cible seule) ou `asn` (toutes les plages de l'ASN de l'adresse). `404` si l'adresse est inconnue de la base (privée, réservée), `503` si la base ASN est indisponible, `400` si la valeur est inconnue |
| `asn` | Numéro d'ASN (`AS16276`) à tracer en entier, à la place d'une adresse ; exige `scope=asn`. `404` si l'ASN n'annonce aucune plage |
| `node` | Ne garde que les requêtes vues par cette passerelle (nom du nœud). Les bans et détections ne sont pas filtrés |
| `from`, `to` | RFC3339 ou `AAAA-MM-JJ` (`to` en date seule inclut la journée). Défaut : 30 derniers jours jusqu'à maintenant. `400` si `from` ≥ `to` |
| `order` | `desc` (défaut : le plus récent d'abord) ou `asc` (chronologique) |
| `limit`, `offset` | Pagination des étapes (défaut 500, max 2000) |

Réponse : `target` (normalisé), `kind` (`ip` ou `cidr`), `from`, `to`, `total_steps`, `offset`, `has_more`, et :

- `summary` : (`active_bans` et les étapes `ban` portent `signals` et `user_agent`, comme `GET /security/bans`) `first_seen`, `last_seen`, `requests`, `blocked` (403, 429 ou protection déclenchée), `ip_count`, `episodes`, `bans`, `unbans`, `threats`, `statuses` (par classe `2xx`…), `days` (`day`, `requests`, `blocked`), `top_ips`, `top_domains`, `top_paths`, `waf_matches`, `threat_signals`, `countries` (depuis `geoip_cache`), `active_bans`, `profiles` (profils IP activés dont une entrée recoupe la cible), `scan_limited` (plus de 2 000 000 requêtes : période à réduire). Les totaux couvrent toute la période, pas seulement la page.
- `steps` : étapes datées `ts`, de `kind` `activity` (épisode : `end` et `burst` avec `requests`, `blocked`, `ips`, `ip_count`, `domains`, `nodes`, `statuses`, `top_paths`, `waf_matches`, `threat_signals` ; deux requêtes séparées de moins de 10 min appartiennent au même épisode), `ban`, `unban`, `threat` (`occurrences`) ou `system` (événement de log lié à l'IP, 500 max), avec `ip`, `domain`, `source`, `reason`.

*(Admin `0.207.0`, Edge `0.121.0`)* Le parcours est rendu **du plus récent au plus ancien** par défaut (`order=asc` pour l'ordre chronologique). Une étape `ban` d'un ban automatique porte `user_agent`, le client qui l'a provoqué (voir `GET /security/bans`), pour comprendre l'événement sans ouvrir les logs.

Un ban ou déban recoupant la cible compte dans le parcours (un ban sur un `/24` apparaît pour une IP qu'il contient, et inversement). Les requêtes ne remontent pas plus loin que la rétention des logs d'accès ; les IP pseudonymisées ou tronquées ne sont pas retrouvées. Équivalents : `goproxify security trace`, outil MCP `trace_ip`.

### `GET /api/v1/security/cves`

Liste les CVE détectées (`security_cves`). Paramètres : `status` (`open|ignored|fixed`), `critical=true` (CVSS ≥ 7). Chaque entrée inclut `edge_name` — la passerelle d'origine ayant remonté la CVE (résolu côté serveur depuis le token d'appairage à la réception, vide pour les données antérieures à cette colonne). Vue Admin : agrégat de toutes les passerelles, colonne passerelle affichée. Vue passerelle : déjà filtrée sur cette passerelle via les backends de ses proxies, colonne masquée (redondante).

Depuis Admin `0.52.3`, chaque entrée inclut aussi :
- `kev` (bool) — exploitation activement observée (catalogue CISA Known Exploited Vulnerabilities), rafraîchi en fin de scan (`internal/admin/vulnscan`), catalogue entier mis en cache 24h en mémoire.
- `epss_score` (0-1) et `epss_updated_at` — probabilité d'exploitation sous 30 jours (modèle EPSS, FIRST.org), rafraîchi en fin de scan par lots de 100 CVE.
- `sla_days` et `sla_due_at` — délai de correction attendu et échéance calculée (`detected_at` + `sla_days`), selon la gravité CVSS et le réglage `GET/PUT /api/v1/security/sla-config`. Recalculés à la lecture (jamais stockés), pour refléter immédiatement un changement de seuils. Non significatifs si `status != "open"`.

Les deux enrichissements (KEV, EPSS) sont du meilleur effort : un réseau externe indisponible au moment du scan laisse simplement `kev=false` / `epss_score=0` sans faire échouer le scan.

*(Admin `0.208.0`)* Chaque entrée porte aussi `host` (proxy), `product`, `version` et `source` (`image` : inventaire des conteneurs de la passerelle ; `headers` : en-têtes des réponses du backend ou sonde ; `html` : générateur déclaré dans la page), vides pour les CVE antérieures. Un résultat est **à vérifier, pas une preuve** : une distribution peut rétroporter un correctif sans changer la version. Quand un conteneur est mis à jour, les CVE ouvertes de l'ancienne version qui ne concernent pas la nouvelle passent à `fixed`.

### `GET /api/v1/security/inventory`

*(Admin `0.208.0`, Edge `0.122.0`, Agent `0.19.0` ; empreinte des réponses : Admin `0.209.0`, Edge `0.123.0`)* Applications que chaque passerelle reconnaît derrière ses proxies, d'après l'image du conteneur annoncée par l'Agent (proxys créés par labels) et d'après ce que les réponses du backend annoncent, lu avant `hide_server` (tous les proxys). Paramètres facultatifs : `route` (identifiant ou hôte d'un proxy), `edge` (une seule passerelle). Réponse : `{ "gateways": [{ "node_id", "node_name", "entries": [ … ] }], "unreachable": […] }`. Chaque entrée : `route`, `host`, `backend`, `container`, `source` (`image` : image du conteneur ; `headers` : en-tête `Server`, `X-Powered-By`, `X-Generator`… ; `html` : `<meta name="generator">`), `evidence` (la référence d'image, l'en-tête ou la balise lue), `note` (désaccord entre l'image et les réponses du backend), et, quand l'image est dans la table des produits connus, `product`, `cpe` (`vendor:product` NVD, absent si le produit est connu sans identifiant sûr : « non couvert »), `version` (absente si l'étiquette n'est pas une version : `latest`, condensat…), `partial` (la version n'a que deux composantes). Une entrée sans `product` est une image non reconnue. Une seule entrée par (backend, produit) : celle qui porte une version l'emporte, l'image à égalité. Chaque entrée porte `coverage` *(Admin `0.210.0`)* : `covered` (CPE et version : cherché dans NVD), `no_version`, `no_cpe` (produit reconnu sans identifiant sûr) ou `unknown` (absent de la table ; un logiciel versionné d'un en-tête est consigné sans `product`). La réponse porte aussi `coverage` : `{ total, covered, partial, no_version, no_cpe, unknown, gaps: [{ reason, name, evidence, entries, hosts }] }`, les `gaps` regroupant ce qui n'est pas cherché par raison et par nom, le plus fréquent d'abord ; les surcharges de CPE sont déjà appliquées. Scope `audit:read`, rôle admin. C'est ce que lit le scanner de vulnérabilités.

### `GET|PUT /api/v1/security/cpe-overrides`

*(Admin `0.210.0`)* Identifiants CPE donnés par l'administrateur aux produits que la table embarquée ne couvre pas (voir `coverage.gaps` de `GET /api/v1/security/inventory`). `GET` rend `{ "overrides": [{ "match", "cpe" }] }` ; `PUT` remplace la liste (`204`). `match` : le nom tel que le rapport le donne (produit reconnu, dépôt d'image — le dernier segment suffit —, nom d'un logiciel d'en-tête), sans tenir compte de la casse. `cpe` : `vendor:product` de NVD (`dani-garcia:vaultwarden`). Une surcharge complète une entrée sans CPE (et lit sa version dans l'étiquette ou le jeton) ; **elle ne corrige jamais un CPE de la table**. Refusé (`400`) : `match` vide ou de plus de 128 caractères, CPE mal formé, doublon, plus de 200 surcharges. Gardées sur l'Admin ; le scanner et le rapport les appliquent.

### `PATCH /api/v1/security/cves/:id`

Change le statut d'une CVE. Corps : `{ "status": "open|ignored|fixed" }`.

### `GET /api/v1/security/sla-config` · `PUT /api/v1/security/sla-config`

Délai de correction attendu (en jours après détection), par tranche de gravité CVSS — réglage global (pas de portée par passerelle : la politique de correction est la même pour tout le parc). Corps / réponse : `{ "critical_days": 7, "high_days": 14, "medium_days": 30, "low_days": 90 }` (CVSS ≥ 9 / ≥ 7 / ≥ 4 / < 4). Valeurs par défaut si le réglage n'a jamais été enregistré ; une valeur ≤ 0 envoyée au `PUT` retombe sur son défaut plutôt que d'être acceptée telle quelle.

### `GET /api/v1/security/fail2ban` · `PUT /api/v1/security/fail2ban`

Lit ou met à jour la configuration Fail2Ban (`enabled`, `window_sec`, `max_errors`, `ban_duration_sec`, `whitelist`). `whitelist` accepte des IPv4, IPv6 et CIDR des deux familles. Depuis Admin `0.69.3` / Edge `0.17.5`, Fail2Ban banne aussi les IPv6, par /64 : l'`ip` d'un tel ban (source `fail2ban`) dans `GET /security/bans` est le préfixe, par exemple `2a01:e0a:1:2::/64` (l'adresse seule si la liste blanche recoupe ce /64) — voir [Fail2Ban natif Go](security.md#fail2ban-natif-go). Depuis Admin `0.71.1` / Edge `0.17.12`, le Fail2Ban de l'Admin ignore les entrées de log dont l'IP a été tronquée par la passerelle (champ `ip_truncated` des logs envoyés à l'Admin, posé en anonymisation comme en pseudonymisation) et ne bannit plus depuis les logs tant que `ip_anonymize` ou `ip_pseudonymize` est actif (`PUT /logs/settings`) ; le Fail2Ban de chaque passerelle bannit sur l'IP réelle.

### `GET /api/v1/security/crowdsec` · `PUT /api/v1/security/crowdsec`

Lit ou met à jour la configuration CrowdSec (`enabled`, `api_url`, `api_key`).

### `POST /api/v1/security/crowdsec/sync`

Déclenche une synchronisation LAPI immédiate.

### `GET /api/v1/security/threat-config` · `PUT /api/v1/security/threat-config`

Configuration du moteur Ephor. `custom_lists` accepte `ips`, `uas`, `paths` et `tls_fingerprints` : signatures **JA3** (MD5, 32 caractères hexadécimaux) ou **JA4** (ex. `t13d1516h2_8daaf6152771_02713d6af862`, insensible à la casse) dont le client est banni (signal `tls_fp`, score critique comme une IP de liste de menaces). L'empreinte est calculée par la passerelle depuis le ClientHello TLS ; elle ne s'applique ni au HTTP clair ni à HTTP/3, et chaque requête loguée porte `tls_ja3` / `tls_ja4` dans le log d'accès de la passerelle (pour repérer la signature d'un scanner ou d'un scraper avant de la lister). Paramètre optionnel `edge=<id ou nom>` :

- passerelle **membre d'un groupe HA** (déclaré dans `architecture.json`, `config.cluster` + `config.cluster_group`) : la configuration est **celle du groupe** — lue et écrite une seule fois, poussée à tous les membres, et rejouée à la connexion d'un membre qui la manquait ;
- passerelle hors groupe : configuration propre à la passerelle ;
- sans `edge` : configuration globale.

Lecture : valeur du groupe, sinon valeur propre à la passerelle (antérieure aux groupes), sinon globale. Au démarrage, la valeur d'un groupe qui n'en a pas encore est reprise du premier membre (dans l'ordre d'`architecture.json`) qui en avait une ; un désaccord entre membres est signalé dans le log de l'Admin, jamais écrasé.

Chaque passerelle garde une copie chiffrée de la configuration reçue (`/etc/goproxify/threat-config.gpx`) et la recharge à son démarrage : Ephor reste actif si l'Admin est injoignable. Un nouvel enregistrement remplace cette copie.

Les scores cumulés et les fenêtres d'erreurs 4xx et de déclenchements `rate` d'Ephor ont leur propre copie chiffrée (`/etc/goproxify/threat-state.gpx`, `GPX_THREAT_STATE_PATH`), écrite toutes les 5 minutes et à l'arrêt, relue au démarrage sans l'Admin : un redémarrage de la passerelle ne remet plus les IP suspectes à zéro. Les entrées périmées à la relecture (score décru sous 0,1, événements hors fenêtre) sont ignorées ; les jetons du limiteur de débit ne sont pas conservés.

*(Admin `0.194.0`, Edge `0.108.0`)* Section `behavior` : la note commune d'Ephor (voir [security.md](security.md#note-commune-et-signaux-de-comportement-adr-0011)).

| Champ | Description |
|---|---|
| `behavior.mode` | Mode des signaux non réglés : `detect` (défaut), `block`, `off` (Ephor ne verse plus rien au magasin) |
| `behavior.signals` | `{ "<signal>": "off" \| "detect" \| "block" }` ; signaux : `high_4xx_rate`, `path_scanning`, `waf_score_accumulation`, `ua_rotation`, `request_burst`, `high_post_ratio`, `high_path_entropy`, `distributed_scan`, `ua_tls_mismatch`, `no_assets`, `regular_interval`, `scan_breadth`, `asn_aggregate`, `rate_deviation`, `fail2ban`, `crowdsec`, `surface_violation`. Un nom inconnu : `400` |
| `behavior.tls_families` | `{ "chromium": ["8daaf6152771"] }` : complète la table User-Agent ↔ JA4 (12 caractères hexadécimaux) |
| `behavior.no_trust` | `true` coupe le bonus de confiance |
| `behavior.reference_min_age` | Ancienneté minimale d'une route avant que ses références apprises comptent (défaut `24h`, max 30 j) |

### `GET /api/v1/security/threat-references`

*(Admin `0.194.0`, Edge `0.108.0`)* Ce que chaque passerelle a appris pour la note commune d'Ephor. Paramètre optionnel `edge=<id ou nom>`. Réponse : `{ "gateways": [{ "node_id", "node_name", "references": [{ "route", "hour", "median", "threshold", "samples", "ready", "since", "updated" }], "profiles", "asn": { "version", "v4_ranges", "v6_ranges" }, "tls_table" }] }`, plus `partial` et `unreachable` si une passerelle n'a pas répondu (`503` si aucune n'est enregistrée). `hour` est l'heure du jour en UTC ; `median` et `threshold` sont en requêtes par minute et par IP ; `ready` dit si la référence compte (au moins 30 minutes observées pour l'heure et 24 h d'ancienneté de la route) ; elle ne contient aucune IP. Même réponse que l'outil MCP `get_ephor_references`. La passerelle l'expose en `GET /internal/v1/ephor/references`.

### `GET /api/v1/security/surface`

*(Admin `0.197.0`, Edge `0.111.0`, [ADR 0016](adr/0016-apprentissage-de-la-surface-d-un-proxy.md))* Les proxies dont chaque passerelle apprend la surface. Paramètre optionnel `edge=<id ou nom>`. Réponse : `{ "gateways": [{ "node_id", "node_name", "proxies": [{ "route", "host", "mode", "members", "requests", "learned", "excluded", "templates", "since", "last", "converged" }] }] }`, plus `partial` et `unreachable` si une passerelle n'a pas répondu (`502` si aucune n'est enregistrée). `members` vaut le nombre de profils fusionnés (la passerelle et ses pairs de groupe HA). Scope `audit:read`, rôle admin.

### `GET /api/v1/security/surface/report`

*(Admin `0.197.0`, Edge `0.111.0`)* Rapport de surface d'un proxy. Paramètre `route` (identifiant ou hôte du proxy, obligatoire), `edge` facultatif. Réponse : `{ "gateways": [{ "node_id", "node_name", "report": <rapport ou null> }] }`, `report` valant `null` pour une passerelle qui n'a aucun profil pour ce proxy (ce n'est pas une panne). Le rapport : `route`, `host`, `mode`, `members`, `since`, `last`, `requests` (vues), `learned` (entrées dans le profil), `excluded` (IP suspecte), `failed` (par statut), `methods`, `headers` (noms seulement), `protocols`, `tls`, `countries`, `asns`, `clients` (distincts, estimés), `template_count`, `templates` (jusqu'à 500, les plus demandés d'abord : `path` (`/api/users/{int}`), `requests`, `first`, `last`, `methods`, `statuses`, `request_media`, `response_media`, `body_max`, `body_p99`, `params` (`name`, `count`, `kinds`, `max_len`, `distinct`, `enum`), `clients`, `days`, `low_support`) et `convergence` (`converged`, `age_seconds`, `min_age_seconds`, `learned`, `min_learned`, `new_templates`, `quiet_seconds`, `overflow`, `reasons`). Le profil ne contient aucune valeur de paramètre ni d'en-tête, aucune IP. Scope `audit:read`, rôle admin.

### `GET /api/v1/security/surface/proposals`

*(Admin `0.198.0`, Edge `0.112.0`)* Réglages que le profil de surface d'un proxy permet de proposer. Paramètre `route` (identifiant ou hôte, obligatoire), `edge` facultatif. Réponse : `{ "gateways": [{ "node_id", "node_name", "proposals": <propositions ou null> }] }`, `proposals` valant `null` pour une passerelle sans profil. Les propositions : `route`, `host`, `members`, `learned`, `convergence` (comme le rapport), `items` et `skipped`. Un élément de `items` : `setting` (`max_body_size`, `rate_limit`, `geo_ip`, `ip_filter` ou `cors`), `option` et `value` (la clé et la valeur de configuration du proxy), `command` (la commande `goproxify proxy option` qui la pose), `current`, `summary`, `evidence` (ce que le profil a vu), `cautions` (ce que le réglage ne sait pas dire), `would_refuse` sur `of` requêtes apprises quand `measured` est vrai. Un élément de `skipped` : `setting` et `reason`. Un réglage que le proxy a déjà, snippets compris, n'est jamais proposé. **Rien n'est appliqué.** Sous 100 requêtes apprises, tout est dans `skipped`. Scope `audit:read`, rôle admin.

### `GET /api/v1/security/surface/openapi`

*(Admin `0.199.0`, Edge `0.113.0`, [ADR 0016](adr/0016-apprentissage-de-la-surface-d-un-proxy.md) étape 3)* La politique positive d'un proxy : une spécification OpenAPI 3.1 générée à partir de son profil de surface, sous la forme du réglage `openapi` du proxy. Paramètres : `route` (identifiant ou hôte, obligatoire), `include_low_support=1` (garde aussi les chemins vus par moins de 3 clients ou sur moins de 2 jours), `edge` facultatif. Réponse : `{ "gateways": [{ "node_id", "node_name", "openapi": <politique ou null> }] }`. La politique : `route`, `host`, `members`, `learned`, `convergence`, `ready` (le profil est convergé), `config` (`{ "enabled": true, "mode": "detect", "unknown_paths": "block", "spec": {…} }`, à poser tel quel dans `openapi`), `command`, `paths`, `operations`, `parameters`, `replaces` (le proxy a déjà un contrôle openapi actif), `excluded` (`path`, `reason`), `cautions` et `error` quand rien n'a pu être généré (moins de 100 requêtes apprises, aucun chemin assez soutenu). La spécification déclare chemins, méthodes, paramètres typés et types de contenu, pas les corps. **Rien n'est appliqué.** Scope `audit:read`, rôle admin.

Le rapport de surface (`…/surface/report`) porte en plus `violation_totals` (par raison) et `violations` (jusqu'à 50 : `reason`, `method`, `path` normalisé, `count`, `legit`, `clients`, `first`, `last`, `likely_legit`) : les requêtes que le contrôle openapi du proxy a jugées hors de la spécification, même en mode `detect`.

### `GET /api/v1/security/surface/suggestions`

*(Admin `0.201.0`, Edge `0.115.0`, [ADR 0016](adr/0016-apprentissage-de-la-surface-d-un-proxy.md) étape 5)* Les ajouts que le profil suggère pour la politique d'un proxy. Paramètres : `route` (obligatoire), `edge` facultatif. Réponse : `{ "gateways": [{ "node_id", "node_name", "members", "converged", "suggestions": [{ "key", "reason", "method", "path", "confidence", "count", "legit", "blocked", "clean_clients", "days", "first", "last", "why", "cautions" }] }] }`. `key` (« raison MÉTHODE chemin ») désigne la suggestion ; `reason` vaut `unknown_path` ou `unknown_method` ; `path` est normalisé (`/nouveau/{int}`). `confidence` : `high` (le backend a servi ces requêtes, depuis 3 clients propres au moins, sur 2 jours au moins) ou `low` (le contrôle les refuse, 5 clients propres au moins pendant 3 jours au moins : à examiner). Les chemins que visent les scanners ne sont jamais suggérés. Le rapport de surface porte la même liste (`suggestions`) et le résumé de chaque proxy leur nombre (`suggestions`). Scope `audit:read`, rôle admin.

### `POST /api/v1/security/surface/accept`

*(Admin `0.201.0`, Edge `0.115.0`)* Ajoute des suggestions à la spécification openapi du proxy. Paramètres : `route` (obligatoire), `edge` facultatif. Corps : `{ "keys": ["unknown_path GET /nouveau/{int}"], "all_high": false, "dry_run": false }` (`all_high` : toutes les suggestions de confiance haute). Seules les suggestions actuelles du profil sont acceptées. Le chemin ou la méthode est **ajouté**, rien n'est retiré ; un chemin de même forme reçoit la méthode, son paramètre est élargi en texte si le type diffère. La spécification doit être du JSON (objet, ou chaîne JSON) : un texte YAML est refusé. Les violations ajoutées sont effacées des profils de toutes les passerelles. Réponse : `{ "route", "applied", "dry_run", "added": [{ "key", "method", "path" }], "skipped": [{ "key", "reason" }], "blockers", "warnings", "spec", "forgotten" }` (`spec` : la spécification après l'ajout). `200` appliqué ou simulé ; `409` refusé (`blockers` : pas de politique active, spécification YAML, aucune suggestion) ; `400` requête incomplète. Consigné à l'audit (`surface_accept`). Scope `security:write`, rôle admin.

### `POST /api/v1/security/surface/enforce`

*(Admin `0.200.0`, Edge `0.114.0`, [ADR 0016](adr/0016-apprentissage-de-la-surface-d-un-proxy.md) étape 4)* Fait refuser par le contrôle `openapi` du proxy les violations de certains types, les autres restant seulement comptées. Paramètres : `route` (identifiant ou hôte, obligatoire), `edge` facultatif. Corps : `{ "reasons": ["unknown_path", …], "force": false, "dry_run": false }` ; raisons : `unknown_path` (404), `unknown_method` (405), `invalid_param` (400), `invalid_body` (422), `unsupported_media` (415), `too_large` (413). Écrit `mode: "detect"` et `block_reasons` dans le réglage `openapi` du proxy (et `unknown_paths: "block"` pour `unknown_path` et `unknown_method`), puis pousse aux passerelles. Garde-fous : politique openapi active et profil de surface (jamais passés outre), profil convergé, aucun chemin `likely_legit` pour les types demandés, pas de débordement du profil ; `force` passe outre les trois derniers et le consigne à l'audit (`surface_enforce_forced`). Réponse : `{ "route", "applied", "dry_run", "forced", "mode", "unknown_paths", "block_reasons", "blockers", "warnings", "impact": [{ "reason", "total", "legit", "blocked", "likely_legit" }] }`. `200` appliqué ou simulé ; **`409` refusé par les garde-fous** (`blockers`), rien n'est modifié ; `400` raison inconnue ; `502` aucune passerelle. Scope `security:write`, rôle admin.

### `POST /api/v1/security/surface/relax`

*(Admin `0.200.0`)* Repasse le contrôle `openapi` du proxy en `detect` : plus rien n'est refusé, `block_reasons` est retiré, la spécification est conservée. Paramètre `route` (obligatoire). Même forme de réponse ; `409` si le proxy n'a pas de politique openapi active. Consigné à l'audit (`surface_relax`). Scope `security:write`, rôle admin.

Les propositions (`…/surface/proposals`) incluent, pour un proxy dont le WAF se déclenche sur des clients ordinaires, un réglage `waf` : la configuration `waf` complète du proxy, avec **une exclusion par chemin** (`waf.exclusions`) pour chaque règle dont les déclenchements se circonscrivent à des préfixes de chemin, jamais une exclusion pour tout le proxy. Pour une règle dont les chemins ne se laissent pas circonscrire (racine, premier segment variable, chemins non retenus), la proposition règle à la place `anomaly_threshold` à 10 (et signale le mode `detect` comme dernier recours) ; un WAF déjà en `detect` ou à 10 ou plus ne reçoit pas de conseil. Seuils : au moins 10 requêtes servies par le backend, 3 clients propres, 2 jours, 3 déclenchements par client ; 10 refus, 5 clients, 3 jours si le WAF bloque. Jamais pour une règle déjà exclue (pour tout le proxy ou sous le même préfixe) ni personnalisée, ni pour un WAF défini par un snippet. Le rapport de surface porte `waf` (`id`, `category`, `message`, `targets`, `hits`, `clean`, `served`, `blocked`, `clients`, `days`, `paths`) et `waf_overflow`.

Le rapport de surface porte aussi `blocked_totals` (violations refusées, par raison) et `blocked` sur chaque violation. Le réglage `openapi` du proxy accepte `block_reasons` (liste de raisons, sans effet en mode `block`).

### `POST /api/v1/security/surface/reset`

*(Admin `0.197.0`, Edge `0.111.0`)* Efface le profil d'un proxy : l'apprentissage repart de zéro. Paramètre `route` (obligatoire), `edge` facultatif ; sans `edge`, **toutes** les passerelles sont remises à zéro (dans un groupe HA, chaque membre doit l'être, sinon un pair rendrait son profil à celui qui vient de l'oublier). Réponse : `{ "gateways": [{ "node_id", "node_name", "reset" }] }`. Ne modifie ni le trafic ni la configuration du proxy. Scope `security:write`, rôle admin.

**Activer l'apprentissage** : champ `surface` de la configuration du proxy (`PUT /api/v1/proxies/{id}`), `{ "mode": "learn", "type": "api" }` (`mode` : `off` par défaut ; `detect` et `enforce` sont refusés). `type` *(Admin `0.204.0`, Edge `0.118.0`)* : `api` (surface fermée), `site` (contenu ouvert : la convergence ne dépend plus des chemins, aucune politique de chemins ni suggestion n'est proposée) ou vide (traité comme une API) ; tout autre valeur est refusée à l'enregistrement. Le rapport de surface porte `type`, `type_hint` (`site` ou `api`, vide sous 100 requêtes) et `type_hint_why`, et pour le proxy entier `request_media`, `response_media`, `body_max`, `body_p99`. Les propositions portent `type` et `notes` ; la politique générée (`…/surface/openapi`) d'un site renvoie `error` sans configuration.

### WAF : exclusions de règles par chemin (`waf.exclusions`)

**Exclusions par chemin** *(champ `waf.exclusions` d'un proxy)* : liste d'objets `{ "paths": ["/wp-admin/"], "rule_ids": [942100], "platform": "wordpress", "note": "…" }`. Sous un chemin, les règles de `rule_ids` et celles de `platform` sont retirées du WAF ; partout ailleurs elles s'appliquent. Un chemin est un préfixe sur frontière de segment ; `/` est refusé (utilisez `exclude_ids`). Refusé à l'enregistrement : aucun chemin, chemin ne commençant pas par `/`, ni `rule_ids` ni `platform`, plateforme inconnue, identifiant de règle invalide. Le champ `exclude_platforms` (règles d'une plateforme retirées pour tout le proxy) n'existe plus depuis Admin `0.211.0` / Edge `0.125.0` : il est ignoré s'il figure encore dans une configuration. Utilisez `exclude_ids` pour tout le proxy ou une exclusion par chemin.

### `GET /api/v1/security/threat-config/suggestions`

*(Admin `0.194.0`)* Seuils proposés à partir des cumuls par minute (ADR 0010, sans IP). Paramètres : `days` (défaut 7, max 90), `edge` (portée de la configuration actuelle). Réponse : `{ "suggestions": [{ "node_name", "days", "minutes_observed", "ready", "rps_median", "rps_p99", "rps_p999", "rps_max", "error_share", "current_global_rps", "suggested_global_rps", "why" }], "note" }`. `suggested_global_rps` vaut quatre fois le 99,9ᵉ centile du débit par minute, arrondi au palier 1-2-5 supérieur ; sans 6 h de minutes actives, `ready` est faux et rien n'est proposé. **Rien n'est appliqué.** Même réponse que l'outil MCP `suggest_ephor_thresholds`.

### `POST /api/v1/security/threat-config/simulate`

Dry-run Ephor depuis l'interface (bouton « Simuler » du tiroir de réglages) : rejoue les access logs récents contre une config candidate et la compare à la config actuelle, **sans rien enregistrer ni pousser**. Le rejeu inclut la note commune de comportement (magasin sur l'horloge des événements, méthode, route et empreinte JA4 des logs) : c'est lui qui dit si un signal peut passer en `block` ; `asn_aggregate` n'est pas rejoué (`not_simulated`). Même moteur et même réponse que l'outil MCP `simulate_ephor_config`. Paramètre optionnel `edge=<id ou nom>` (même règle de portée que `threat-config` : la config actuelle est celle du groupe HA si la passerelle en fait partie).

Corps :

```json
{ "config": { "rate_limit": 20, "custom_lists": { "paths": ["/wp-admin"] } }, "hours": 6, "domain": "app.example.com" }
```

- `config` (requis) : champs Ephor surchargés sur la config actuelle, mêmes noms que `threat-config` ;
- `hours` : fenêtre rejouée, défaut `1`, max `24` ; `domain` : limite le rejeu à un domaine.
- *(Admin `0.173.0`, Edge `0.83.0`)* **La simulation tourne sur les passerelles** : chacune rejoue ses propres accès (agents utilisateur compris : les règles `user_agent` sont évaluées) contre les deux configurations, comme elle les traite en production, et l'Admin additionne les rapports (`gateways` : nombre de passerelles ayant répondu ; `partial` et `unreachable` si certaines manquent ; `top_ips` fusionne les dix premières de chacune ; une IP vue par deux passerelles compte pour chacune). `truncated` : une passerelle a plus de 200 000 accès sur la fenêtre. Sans passerelle enregistrée, ou face à des passerelles d'avant `0.83.0`, la simulation est refusée (`400`, rien à rejouer) ; depuis Admin `0.176.0` l'Admin ne rejoue plus de copie de lignes.

Réponse `200` : `current` et `candidate` (`events`, `blocked`, `blocked_by_ban`, `legit_blocked`, `blocked_ips`, `by_reason`, `bans`, `top_ips`), `delta` (candidat − actuel), `events_replayed`, `truncated`, `skipped_unattributable_ip` (entrées écartées : IP pseudonymisée, ou tronquée par l'anonymisation RGPD), `not_simulated`, `note`. `400` si `config` est absent ou invalide. Non simulé : listes par défaut, `global_rps`, règles User-Agent, WAF.

### `GET /api/v1/security/waf-config` · `PUT /api/v1/security/waf-config`

Interrupteur du WAF, moteur de sécurité d'une passerelle : `{ "enabled": true|false }`. Même règle de portée que `threat-config` (`?edge=`, groupe HA, valeur globale), même validation (clé inconnue ou valeur du mauvais type : `400`).

- **Sans réglage enregistré, le WAF est actif** (`{"enabled":true}`) : chaque route décide ensuite d'en faire usage (label `goproxify.waf=detect|block` ou snippet), comme avant.
- **`enabled: false`** coupe le WAF de **toutes** les routes de la passerelle, à chaud, sans toucher à leur réglage (mode, seuils, règles) : réactivé, elles reprennent telles quelles. Le moteur comportemental du WAF ne bannit plus non plus ; les bans déjà posés restent.
- Poussé aux passerelles visées (message WebSocket `push_waf_config`) et rejoué à leur connexion.
- Autonomie : chaque passerelle garde une copie chiffrée du réglage (`/etc/goproxify/waf-config.gpx`, surchargeable par `GPX_WAF_CONFIG_PATH`) et la recharge à son démarrage sans l'Admin. Copie absente ou illisible : le WAF reste actif.
- CLI : `goproxify security waf-engine get|set`.

### `GET /api/v1/security/waf-activity`

Requêtes que le WAF a signalées (colonne `waf_matches` des journaux d'accès) : onglet WAF de la fenêtre « Moteurs de sécurité ». Paramètres : `hours` (défaut `24`, max `168`), `edge` (id du jeton ou nom du nœud ; sans lui, toutes les passerelles).

```json
{ "hours": 24, "requests": 4, "blocked": 3, "detected": 1,
  "top_rules": [{ "name": "942100", "count": 3 }], "top_domains": [{ "name": "a.test", "count": 2 }] }
```

- `blocked` : requêtes refusées (403) ; `detected` : les autres, passées (route en mode détection). `top_rules` et `top_domains` : 8 au plus. Les entrées de `top_rules` sont les identifiants de règle du WAF, ou le nom d'un plugin de détection (ex. `coraza`).
- `truncated: true` quand plus de 50 000 requêtes signalées tombent dans la fenêtre : seules les plus récentes sont comptées.
- Lu dans l'index partiel `idx_logs_waf_ts` (requêtes signalées seulement), sans parcourir la table des journaux.
- CLI : `goproxify security waf-engine activity [-hours N] [-edge <id>]`.

### `GET /api/v1/security/server-config` · `PUT /api/v1/security/server-config`

Timeouts HTTP/QUIC (`read_header_seconds`, `read_seconds`, `write_seconds`, `idle_seconds`, redémarrage de la passerelle requis). Même règle de portée que `threat-config` ; une passerelle qui rejoint le groupe reçoit ceux du groupe à sa connexion.

## Portail d'accès — `/api/v1/portal`

Le paramètre `edge=<id ou nom>` désigne une passerelle. Dans un **groupe HA** (`config.cluster` + `config.cluster_group` dans `architecture.json`), la configuration du portail est **celle du groupe** : lue et écrite une seule fois, poussée à tous les membres (config, destinations, utilisateurs invités). L'activation reste une propriété du nœud : un membre qui n'héberge pas le portail (`config.portal: false`) reçoit la config du groupe **en attente** (`ha_standby`), sans écouter, et réplique le magasin pour pouvoir prendre le relais.

### `GET /api/v1/portal?edge=` · `PUT /api/v1/portal?edge=`

Config du portail (`enabled`, `ssh_port`, `http_port`, `public_host`, `auth_provider_id`, `allow_personal_targets`, `require_2fa`, `session_ttl_sec`, `session_mode`, `theme`, catalogue, utilisateurs). Pour une passerelle membre d'un groupe HA, la réponse ajoute :

`theme` : apparence de l'interface du portail Access, choisie côté Admin et appliquée par la passerelle (`auto` — défaut, suit le système —, `clair`, `sombre`, `ocean`, `foret`, `amethyste`, `contraste`). Toute autre valeur est ramenée à `auto`. Appliqué à la page servie par la passerelle (copie locale chiffrée : fonctionne Admin coupé, y compris après redémarrage).

`views` : liste d'**entrées dédiées** du portail — même passerelle, même annuaire et mêmes destinations, mais une URL, un thème, un titre et un périmètre propres. Absent à l'enregistrement = liste inchangée ; `[]` la vide. Chaque vue :

| Champ | Description |
|-------|-------------|
| `slug` | Chemin : `prestataire` → `https://<hôte public>/prestataire` (minuscules, chiffres, tirets ; `api`, `assets`, `static` réservés) |
| `host` | Hôte dédié optionnel (ex. `presta.example.fr`) : la passerelle publie une route HTTPS supplémentaire vers le portail. Sans `slug`, l'hôte entier est la vue |
| `name`, `title`, `tagline` | Libellé d'administration, titre et sous-titre affichés (défauts : ceux du portail) |
| `theme` | Thème de la vue (même liste que `theme`) ; vide = thème du portail |
| `auth_provider_id` | Fournisseur d'authentification (annuaire) de la vue ; vide = celui du portail |
| `users` | Identifiants (email ou identifiant d'annuaire, comparés sans casse) autorisés sur l'entrée |
| `groups` | Identifiants de groupes Access (voir ci-dessous) autorisés sur l'entrée. Sans `users` ni `groups`, l'entrée est ouverte à tous les comptes du portail. Un jeton émis sur une entrée n'est valable que sur cette entrée |
| `target_ids` | Destinations de l'entrée (identifiants du catalogue). Cochées, elles sont offertes à tous les utilisateurs autorisés de l'entrée, sans condition de tags ; vide = destinations habituelles de l'utilisateur (tags) |
| `dest_groups` | Groupes de destinations de l'entrée (identifiants, voir `/api/v1/portal/destination-groups`) ; toutes leurs destinations sont offertes, en plus de `target_ids` |
| `require_2fa` | `true`/`false` pour surcharger le réglage du portail ; absent = hérité |

Une entrée s'adresse par un chemin (`domaine.fr/prestataire`), un sous-domaine ou domaine dédié (`presta.domaine.fr`), ou les deux. Un hôte égal à l'hôte public est ramené à un simple chemin. Les groupes et destinations inconnus de la passerelle sont ignorés à l'enregistrement. La passerelle ne reçoit que la liste résolue des membres (utilisateurs + membres des groupes).

Un couple hôte/`slug` ne peut apparaître qu'une fois (`400` sinon). La page du portail envoie la vue courante dans l'en-tête `X-Portal-View` ; l'accès SSH direct (port 2222) n'est pas concerné par les vues.

| Champ | Description |
|-------|-------------|
| `ha_group`, `ha_members` | Groupe et membres (calculés, non modifiables) |
| `ha_session_mode` | `sticky` (défaut : une session web reste sur la passerelle qui l'a émise, affinité à assurer sur le répartiteur) ou `shared` (sessions répliquées entre les membres ; à choisir avec un DNS round-robin) |

La clé de réplication du groupe (`ha_key`) n'est jamais renvoyée : l'Admin la génère, la conserve scellée et ne la pousse qu'aux passerelles du groupe. Quand un membre quitte un groupe (composition déclarée dans l'architecture, relue toutes les 30 s, Admin `0.184.0`), l'Admin renouvelle la clé et pousse la configuration du portail, avec la liste des membres à jour, aux membres restants ; le membre sorti reçoit la configuration de son propre groupe. Un membre ajouté reçoit la liste à jour sans changement de clé.

### `POST /api/v1/portal/push?edge=`

Repousse la config du portail à la passerelle (à tous les membres du groupe HA).

### `GET /api/v1/portal/sessions?edge=` · `DELETE /api/v1/portal/sessions/{id}?edge=`

Connexions SSH et web pontées en cours sur une passerelle. La passerelle envoie l'instantané à chaque connexion ou déconnexion, et toutes les 30 s tant qu'une connexion est ouverte. `GET` renvoie `{"sessions":[{id, actor, target_id, facade, remote, since}]}`. `DELETE` demande à la passerelle de fermer la connexion (`204`, `404` si elle est déjà terminée) et journalise l'action dans l'audit Admin. Portée `portal:read` pour lire, `portal:write` pour terminer.

### `GET /api/v1/portal/sessions/{id}/watch?edge=`

Observe en direct la sortie d'une connexion en cours (flux `text/event-stream`). Chaque événement `data:` porte un morceau de sortie du terminal en base64, précédé de la fin déjà émise (32 Kio) à l'ouverture ; `event: end` annonce la fin de la session. On voit ce que l'utilisateur voit, jamais ce qu'il tape. L'observation est journalisée dans l'audit Admin (`watch`) et dans l'audit du portail (`observed_by_admin`). Elle exige la portée `portal:write`, comme la lecture d'un enregistrement, car elle donne accès au contenu d'un terminal. `404` si la connexion est déjà terminée. La CLI l'expose avec `goproxify access sessions watch`.

### Groupes Access — `/api/v1/portal/groups`

Groupes d'utilisateurs du portail, propres à une passerelle (ou à son groupe HA) ; ils donnent des droits sur les entrées (`views`). Une modification est poussée à la passerelle.

| Méthode | Chemin | Description |
|---------|--------|-------------|
| `GET` | `/api/v1/portal/groups?edge=` | Groupes de la passerelle : `id`, `name`, `description`, `members` |
| `POST` | `/api/v1/portal/groups?edge=` | Crée un groupe : `name` (unique par passerelle, `409` sinon), `description`, `members` (identifiants de connexion, normalisés en minuscules) |
| `PUT` | `/api/v1/portal/groups/{id}` | Met à jour `name`, `description`, `members` (la liste remplace l'existante) |
| `DELETE` | `/api/v1/portal/groups/{id}` | Supprime le groupe et le retire des entrées qui l'utilisaient |

Les utilisateurs (`/api/v1/portal/users`) exposent `groups` (identifiants des groupes dont ils sont membres) ; `invite` et `PUT` acceptent `groups` pour aligner l'appartenance.

### Groupes de destinations Access — `/api/v1/portal/destination-groups`

Groupes de destinations du catalogue, propres à une passerelle (ou à son groupe HA). Une entrée (`views[].dest_groups`) offre toutes les destinations de ses groupes, en plus de ses `target_ids` ; l'Admin développe les groupes en `target_ids` à l'envoi, la passerelle ne les connaît pas. Une modification est poussée à la passerelle.

| Méthode | Chemin | Description |
|---------|--------|-------------|
| `GET` | `/api/v1/portal/destination-groups?edge=` | Groupes de la passerelle : `id`, `name`, `description`, `targets` (identifiants de destinations) |
| `POST` | `/api/v1/portal/destination-groups?edge=` | Crée un groupe : `name` (unique par passerelle, `409` sinon), `description`, `targets` (les identifiants absents du catalogue de la passerelle sont ignorés) |
| `PUT` | `/api/v1/portal/destination-groups/{id}` | Met à jour `name`, `description`, `targets` (la liste remplace l'existante) |
| `DELETE` | `/api/v1/portal/destination-groups/{id}` | Supprime le groupe et le retire des entrées qui l'utilisaient |

Supprimer une destination (`DELETE /api/v1/portal/destinations/{id}`) la retire de ses groupes.

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
| `record_retention_days` | Jours de conservation des enregistrements ; `0` ou absent = 90 jours, `-1` = illimitée |

`400` avec le motif si la politique est invalide. Hors plage horaire ou depuis une adresse non autorisée, la passerelle refuse la connexion au portail, l'ouverture d'une session et la connexion SSH (`403`), et journalise le refus dans l'audit. Les sessions déjà ouvertes ne sont coupées que par l'inactivité. Derrière la passerelle, l'adresse du client est la dernière entrée de `X-Forwarded-For`. Portée `portal:read` pour lire, `portal:write` pour modifier.

### Enregistrements de sessions — `/api/v1/portal/recordings`

Quand `record_sessions` est actif dans la politique, la passerelle enregistre la sortie du terminal de chaque nouvelle session (SSH, web, Docker) au format asciicast v2. La saisie de l'utilisateur n'est jamais gardée. Les fichiers restent sur la passerelle, chiffrés au repos avec une clé dérivée du secret du portail ; l'Admin les relaie à la demande. Un enregistrement est limité à 8 Mio de sortie (marqué `truncated` au-delà) et n'est écrit qu'à la fin de la session. `record_retention_days` supprime automatiquement les plus anciens (`0` ou absent : 90 jours ; `-1` : conservation illimitée).

| Méthode | Chemin | Description |
|---------|--------|-------------|
| `GET` | `/api/v1/portal/recordings?edge=` | `{"recordings":[{id, actor, target_id, facade, remote, started, duration_sec, bytes, truncated}]}`, du plus récent au plus ancien |
| `GET` | `/api/v1/portal/recordings/{id}?edge=` | Fichier asciicast (`application/x-asciicast`), lecture journalisée dans l'audit Admin |
| `DELETE` | `/api/v1/portal/recordings/{id}?edge=` | Suppression définitive (`204`), journalisée |

`502` si la passerelle est injoignable, `404` si l'enregistrement n'existe pas. Portée `portal:read` pour lister ; `portal:write` pour lire le contenu d'un enregistrement ou le supprimer. Le contenu n'est pas exposé en MCP.

Les destinations (`/api/v1/portal/destinations`) et les utilisateurs (`/api/v1/portal/users`) suivent la même règle : rattachés au groupe, visibles et modifiables depuis n'importe quel membre. Au démarrage, les données propres aux membres d'avant les groupes sont rattachées au groupe (config du premier membre, destinations en double retirées, un désaccord de config est signalé dans le log, jamais écrasé).

## Flux d'automatisation (Admin 0.139.0)

Règles, planifications et playbooks sont un seul objet, le **flux** : un déclencheur, un garde-fou et une suite d'étapes (ADR 0009). Toutes les routes sont sous `/api/v1/automation/`, réservées aux admins (`RequireAdmin`), en lecture `audit:read` et en écriture `security:write` pour un PAT. Elles remplacent `/rules-engine`, `/scheduled-tasks` et `/playbooks`, supprimées.

Erreurs : `400` pour une saisie invalide (le corps explique la cause), `404` si l'objet n'existe pas, `409` si on modifie la définition d'un flux issu d'un modèle.

### Format d'un flux

```json
{
  "id": "…", "name": "Couper un proxy en échec", "description": "", "enabled": true,
  "trigger": {
    "kind": "condition",
    "condition": { "all": [ { "type": "proxy_error_rate", "config": { "error_rate_threshold": 40 } },
                            { "not": { "type": "node_offline", "config": {} } } ] },
    "interval_sec": 60
  },
  "guard": { "cooldown_sec": 1800, "cooldown_key": "{{detail.proxy_id}}", "max_concurrent": 1, "placement": "auto" },
  "steps": [
    { "id": "s1", "type": "approval", "config": { "message": "Couper {{detail.proxy_name}} ?", "timeout": "30m", "on_timeout": "reject" } },
    { "id": "s2", "type": "action", "action": { "type": "disable_proxy", "config": {} } },
    { "id": "s3", "type": "if", "condition": { "type": "cve_critical", "config": {} },
      "then": [ { "id": "s4", "type": "call", "config": { "flow_id": "…", "wait": true, "inputs": { "proxy_id": "{{detail.proxy_id}}" } } } ],
      "else": [] }
  ],
  "origin": { "kind": "manual" }
}
```

- **Déclencheur** (`trigger.kind`) :
  - `condition` : arbre de conditions (`type` + `config`, ou un groupe `all` / `any` / `not`), évalué toutes les `interval_sec` secondes (60 par défaut, 30 au minimum) ;
  - `event` : `{ event, nodes, domain_glob, min_severity, match }`, un événement du moteur d'alertes (mêmes déclencheurs que les règles de routage, plus `automation_notify`), filtré par périmètre et par motifs sur le détail ;
  - `schedule` : `{ cron }`, 5 champs, à l'heure locale de l'Admin ; une exécution manquée pendant un arrêt n'est pas rattrapée ;
  - `manual` : `{ inputs: [champs de manifeste] }`, paramètres saisis au lancement.
- **Garde-fou** (`guard`) :
  - `cooldown_sec` : délai minimum entre deux déclenchements automatiques, 300 s par défaut pour une condition ou un événement ;
  - `cooldown_key` : délai par valeur, par exemple `{{detail.ip}}` ;
  - `max_concurrent` : exécutions simultanées (1 par défaut) ;
  - `placement` : `auto` ou `admin`.
  Un lancement manuel ignore les garde-fous.
- **Étapes** (`steps[].type`) :
  - `action` : `action: { type, config }` ;
  - `wait` : `{ duration }` ;
  - `if` : `condition`, branches `then` / `else` ;
  - `approval` : `{ message, timeout, on_timeout: reject|approve }` ;
  - `call` : `{ flow_id, wait, inputs }`, lance un flux à déclenchement manuel ;
  - `stop` : `{ status: stopped|completed|failed, reason }`.
  `on_error: continue` poursuit l'exécution après une étape en échec. Au plus 50 étapes, 5 niveaux d'imbrication et 5 appels en chaîne ; un appel circulaire est refusé.
- **Variables** : `{{detail.x}}` (sorties du déclencheur, paramètres d'un playbook), `{{steps.<id>.x}}` (sorties d'une étape exécutée avant), `{{flow.id}}`, `{{flow.name}}`, `{{run.id}}`. Une chaîne réduite à une variable garde le type de la valeur.
- **Placement** (lecture seule) : `edge` quand la passerelle exécute le flux seule. Il faut une condition simple qu'elle sait évaluer (`ban_spike`, `engine_silent`, `proxy_error_rate`, `ban_repeat`), une seule action qu'elle sait exécuter (`disable_proxy`, `ban_ip`, `notify`, `enable_strict`), aucune autre étape et aucune clé de délai. Ces flux sont envoyés à chaque modification et l'Admin ne les évalue pas ; `placement_reason` explique un placement `admin`.
- **Secrets** : les champs secrets des actions (`webhook_signed.secret`, `pagerduty.routing_key`…) et les paramètres mot de passe d'un modèle sont renvoyés masqués (`••••••••`). Renvoyer le masque, ou ne pas renseigner le champ, conserve la valeur ; une action est retrouvée par l'identifiant de son étape. Un masque sur une étape nouvelle est refusé (`400`).
- **Origine** : `manual` (éditeur) ou `template` (`template_id`, `template_version`, `params`). En lecture, un flux issu d'un modèle porte `template` : `{ name, current_version, outdated, missing }`. `outdated` signale un modèle changé depuis l'installation, que réenregistrer les paramètres applique ; `missing` signale un modèle qui n'existe plus (seul le détachement permet alors de modifier le flux) (Admin 0.141.0).

### Flux

| Méthode | Route | Rôle |
|---|---|---|
| `GET` | `/automation/flows?trigger=condition,event` | Liste, filtrée par déclencheur. Chaque flux porte `state` : `fire_count`, `last_fired_at`, `last_run_status`, `next_run_at` (planification), `waiting` |
| `POST` | `/automation/flows` | Crée un flux de l'éditeur. Réponse : le flux |
| `GET` | `/automation/flows/{id}` | Un flux |
| `PUT` | `/automation/flows/{id}` | Remplace la définition (nouvelle version). Pour un flux issu d'un modèle : corps `{ name, description, enabled, origin: { kind: "template", params } }`, qui le reconstruit avec la version courante du modèle ; une définition complète donne `409` |
| `PATCH` | `/automation/flows/{id}` | `{ enabled }`, sans nouvelle version |
| `DELETE` | `/automation/flows/{id}` | `204` ; `400` si un autre flux l'appelle |
| `POST` | `/automation/flows/{id}/run` | `{ inputs, dry_run }`. Un flux à condition l'évalue d'abord (`{ matched: false }` si elle est fausse). Avec `dry_run`, simulation (voir ci-dessous). Réponse : `{ run_id, matched, detail }` |
| `POST` | `/automation/flows/{id}/detach` | Détache le flux de son modèle : il devient un flux de l'éditeur |
| `GET` | `/automation/flows/{id}/versions` | 20 dernières versions : `{ version, flow, created_by, created_at, changes }`. `changes` liste les différences avec la version précédente : `{ kind, step_id, detail }`, avec `kind` parmi `name`, `description`, `enabled`, `trigger_kind`, `trigger`, `guard`, `origin`, `params`, `step_added`, `step_removed`, `step_changed`, `step_moved`, ou `created` / `earliest_kept` pour la plus ancienne. Les valeurs ne sont pas reprises (Admin 0.141.0) |
| `POST` | `/automation/flows/{id}/versions/{v}/restore` | Rétablit une version (nouvelle version) |
| `POST` | `/automation/simulate` | `{ flow, inputs }` : simule un flux, enregistré ou brouillon |

**Simulation** : les conditions sont évaluées pour de vrai, aucune action n'est exécutée, les attentes sont sautées et les approbations supposées accordées. Un appel de playbook est parcouru lui aussi. Réponse : `{ matched, detail, silenced, placement, placement_reason, trace: [{ step_id, type, status, detail, output, flow }] }`. `output` montre la configuration résolue de l'action, secrets masqués.

### Exécutions

| Méthode | Route | Rôle |
|---|---|---|
| `GET` | `/automation/runs?flow_id=&status=a,b&source=edge&since=1h&limit=100` | Journal, le plus récent d'abord (500 au plus). `status=waiting_approval` liste les approbations en attente, avec `pending.message` |
| `GET` | `/automation/runs/{id}` | Une exécution et le journal de ses étapes (`steps`) |
| `POST` | `/automation/runs/{id}/approve` · `/reject` | Décide une approbation. L'acteur est enregistré. `400` si l'exécution n'attend pas d'approbation ou si la décision est déjà prise |
| `POST` | `/automation/runs/{id}/cancel` | Annule une exécution en cours ou en attente, ainsi que les playbooks qu'elle attend |
| `POST` | `/automation/runs/{id}/replay` | Relance le flux avec le détail d'une exécution terminée |

- **Statuts** :
  - en cours : `running`, `waiting`, `waiting_approval`, `waiting_child` ;
  - terminés : `completed`, `stopped`, `failed`, `rejected`, `cancelled`, `silenced` (déclenchement automatique en sourdine), `interrupted` (l'Admin s'est arrêté pendant une étape).
- **Sources** : `admin`, `edge:<nœud>` (flux exécuté par une passerelle), `manual:<acteur>`, `call:<run>`.
- **Reprise** : les attentes et les approbations reprennent après un redémarrage de l'Admin. Une étape en cours au moment d'un arrêt n'est jamais relancée d'office : l'exécution passe à `interrupted`, et `replay` la relance à la main. Les exécutions terminées sont purgées après 30 jours.

### Catalogue et valeurs

- `GET /automation/catalog` : `{ triggers, events, conditions, actions, steps, metrics, variables }`.
  - Chaque brique est un manifeste `{ type, label, fields, attrs }` : `attrs.edge` (la passerelle sait l'exécuter), `attrs.outputs` (variables produites), `attrs.category`.
  - Les champs suivent `modules.Field`, avec en plus `options` / `source` pour un champ `select`, `default`, `help`, et le genre `duration`.
- `GET /automation/options/{source}` : valeurs d'un champ à source dynamique, sous forme `[{ value, label }]`. Sources : `proxies`, `nodes`, `domains`, `alert_channels`, `flows:manual`, `events`, `metrics`, `metric_entities`.

**Condition `metric_threshold`** :
- Champs : `metric`, `entity` (vide = n'importe laquelle), `aggregation` (`avg|max|min|last|increase|rate`), `window` (1 h au plus), `operator`, `value`, `min_samples` (3 par défaut).
- Séries : une heure d'historique, relevée toutes les 10 s, sur le trafic des proxies et des passerelles (`proxy.rps`, `proxy.error_rate_pct`, `proxy.p95_ms`, `edge.*`, `global.*`), le TLS (`tls.cert_expires_days`, `tls.handshake_p95_ms`, `tls.active_connections`), les connexions, le portail, le WAF, les étapes du pipeline et quelques compteurs de l'Admin.
- Sans assez de points, la condition est fausse. Le détail porte `value`, `threshold` et `entity`, plus `host`, `proxy_id` et `proxy_name` pour une métrique de proxy, `node_name` pour une métrique de passerelle, `domain` pour un certificat.
- `metrics[].edge` (catalogue, Admin 0.142.0) : chaque passerelle calcule aussi cette métrique sur son propre trafic. Un flux simple qui en surveille une s'exécute sur les passerelles (`placement: edge`). Ces métriques sont `proxy.error_rate_pct`, `proxy.p95_ms`, `edge.rps`, `edge.error_rate_pct`, `edge.p95_ms`, `tls.cert_expires_days`, `tls.handshake_p95_ms` et `tls.active_connections`. Sur une passerelle, `proxy_id` vaut le domaine du proxy.

### Modèles

| Méthode | Route | Rôle |
|---|---|---|
| `GET` | `/automation/templates` | `{ id, category, version, name, description, kind, params, flow, installed }` |
| `POST` | `/automation/templates/{id}/preview` | `{ params, flow_id }` : le flux rendu, validé, non enregistré. Avec `flow_id` (un flux issu de ce modèle), la réponse porte aussi `changes`, ce que l'enregistrement de ces paramètres changerait, version courante du modèle comprise (Admin 0.141.0) |
| `POST` | `/automation/templates/{id}/install` | `{ name, enabled, params }` : crée le flux (paramètres absents : valeurs par défaut) |

### Mises en sourdine, export, statistiques

- **Mises en sourdine** : `GET`/`POST /automation/silences`, `DELETE /automation/silences/{id}`.
  - Corps : `{ name, starts_at, ends_at, rule_ids }`, dates RFC3339 avec n'importe quel décalage, stockées en UTC.
  - `rule_ids` vise des flux et des règles de routage d'alertes ; vide, il couvre tout.
  - Un déclenchement automatique en sourdine est journalisé (`silenced`) sans être exécuté, y compris sur les passerelles : chaque création ou suppression renvoie aux passerelles leurs flux avec les fenêtres qui les visent (`silence_windows` du message `push_auto_rules`) ; une passerelle remonte un déclenchement ignoré par `rule_fired` avec `silenced: true`.
- **Export** : `GET /automation/export` renvoie un YAML `version: 2` contenant flux, canaux d'alerte et mises en sourdine, secrets masqués.
- **Import** : `POST /automation/import` (corps YAML).
  - Flux et canaux sont mis à jour par nom (secrets conservés) ou créés ; les playbooks sont importés d'abord.
  - Les mises en sourdine sont ajoutées.
  - Réponse : `{ flows_created, flows_updated, flows_rejected, channels_created, channels_updated, silences_created, errors }`.
- **Statistiques** : `GET /automation/stats` renvoie `{ flows (par déclencheur), enabled, runs_24h, failed_24h, waiting_approval, hourly[24], templates }`.

---

## Accès MCP (admin)

Périmètre d'accès du serveur MCP, admin uniquement (`RequireAdmin`).

Le endpoint `/mcp` lui-même accepte le paramètre `?toolsets=a,b` (groupes d'outils annoncés par `tools/list`, voir [docs/mcp.md](mcp.md#groupes-doutils-toolsets)) ; `tools/list` n'annonce que les outils autorisés à l'appelant.

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

**Secret d'appairage et clé des Agents (Admin `0.135.20`, passerelle `0.58.9`, Agent `0.9.6`)** : `GET /api/v1/pairing-secret` renvoie `{ "secret": "…", "agent_key": "…" }`, et `edge_channel_key` (avec `node_id`) quand on passe `?node=<identifiant ou nom de la passerelle>` (Admin `0.189.1` ; `404` si l'Admin ne la connaît pas), ainsi que `edge_channel_key_by_name`, la clé dérivée du **nom** de la passerelle (Admin `0.192.0`), que l'Admin essaie après celle de l'identifiant : c'est la seule qu'un déploiement automatisé (Helm, démarrage rapide) puisse calculer d'avance ; `agent_key` = SHA-256 de `goproxify/agent-pairing/v1:` suivi du secret. `POST /internal/v1/pair` (Admin) : une passerelle (`role: edge`) présente le secret racine ; un Agent (`role: agent`) présente `agent_key` — ou le secret racine tant que `GPX_AGENT_PAIRING_ROOT` n'est pas `false`. Sur la passerelle, `POST /internal/v1/pair` suit la même règle et, sauf pour le bon secret, compte les échecs par adresse (5 échecs : `429` pendant 15 minutes). L'Admin et la passerelle appellent les Agents avec `agent_key` en Bearer, jamais avec le secret racine. Le WebSocket `/ws/admin` est signé par l'Admin avec la **clé du canal de la passerelle** (`edge_channel_key` = SHA-256 de `goproxify/edge-channel/v1:` suivi de l'identifiant de la passerelle (`dn_…`, celui que l'Admin lui connaît), de `:` et du secret racine) ; la passerelle la vérifie avec `GPX_EDGE_CHANNEL_KEY`, et accepte encore le secret racine tant qu'elle le détient (passerelle `0.103.0`). Pendant une rotation du secret racine (`GPX_PAIRING_SECRET_PREVIOUS`), l'Admin signe avec la clé du secret courant puis, si la passerelle la refuse, avec celle de l'ancien secret (Admin `0.190.0`) ; la passerelle accepte `GPX_EDGE_CHANNEL_KEY` et `GPX_EDGE_CHANNEL_KEY_PREVIOUS` et le journalise quand une signature passe par une valeur précédente. Si une passerelle refuse la clé dérivée (`401`/`403`), l'Admin se reconnecte avec le secret racine, sauf `GPX_EDGE_CHANNEL_ROOT_FALLBACK=false`. Une passerelle qui n'a que sa clé dérivée et `GPX_AGENT_PAIRING_KEY` fonctionne sans `GPX_PAIRING_SECRET` : elle ne peut ni se faire passer pour l'Admin auprès d'une autre passerelle, ni remonter au secret racine.

**Rôle du jeton (passerelle `0.58.8`)** : un jeton d'**Agent** n'ouvre que `POST /internal/v1/agent/heartbeat`, `/agent/events`, `/agent/logs`, `/agent/containers`, `PUT /internal/v1/agent/state`, `DELETE /internal/v1/agent/containers` et `DELETE /internal/v1/routes/{id}` pour une route issue de la découverte (identifiant commençant par `docker:`, `docker-host:`, `k8s:`, `portainer:` ou `podman:`) ; tout autre appel répond `403`. Un jeton d'administration ouvre toute l'API.

**Lots envoyés à l'Admin (`0.135.19`)** : `POST /internal/v1/security/bans` et `/security/threats` acceptent 1 000 entrées au plus (`413` sinon) ; une entrée dont l'adresse est illisible, plus large que `/16` (IPv4) ou `/32` (IPv6), couverte par la liste blanche des bans, ou dont `expires_at` n'est pas RFC 3339, est ignorée sans faire échouer le lot. `/logs` et `/security/cves` : 5 000 entrées au plus ; les champs libres sont tronqués à 2 048 octets. `POST /internal/v1/heartbeat` : `endpoint` ignoré s'il n'est pas une URL http(s) publique ou privée hors lien local et métadonnées du cloud.

### `POST /internal/v1/pair` (Admin, public)

Appairage d'un nœud avec l'Admin (Admin `0.185.0` ; ADR 0015). Corps : `{ "secret", "node_name", "role", "version", "token_id" }`, `Authorization: Bearer <jeton>` facultatif. Le secret est la clé d'Agent (rôle `agent`) ou le secret racine (rôle `edge`).

- **Nœud qui a déjà un jeton** : il le retrouve (`200 { "status": "accepted", "token" }`) seulement s'il le présente en `Authorization: Bearer` ; un renommage par `token_id` exige la même preuve. Sans preuve, la demande passe par l'approbation (ci-dessous) : le secret ne fait plus rendre un jeton existant.
- **Nœud sans jeton** : accepté tout de suite (`200`, jeton dans la réponse) seulement s'il est déclaré avec `auto_accept` ou couvert par un ticket d'installation valide (`node_names`). Le ticket sert une fois par nom, puis le nom sort de la liste et le ticket disparaît quand elle est vide. Sinon `202 { "status": "pending", "pending_id" }` : la demande attend l'approbation d'un opérateur (`POST /api/v1/nodes/:id/accept`).
- **Après approbation**, le jeton est remis une fois, à la demande suivante de `/pair` ou à `GET /internal/v1/pair/status?pending_id=…` (`410 { "status": "delivered" }` ensuite). Approuver un nœud qui avait un jeton révoque l'ancien.
- Les échecs de secret sont comptés par adresse (`429` après 20 essais).

### `POST /internal/v1/register`

Enregistrement d'une passerelle ou Agent.

### `GET /internal/v1/config`

Récupère la configuration complète (routes + certs) pour une passerelle.

### `POST /internal/v1/telemetry`

Soumission des métriques d'un Agent.

### `POST /internal/v1/discovery`

Soumission d'un proxy découvert par labels (depuis un Agent).

### `PUT /internal/v1/agent/state`

État complet d'une source de découverte, envoyé par l'Agent à la fin d'un scan complet (passerelle `0.91.0`, Agent `0.13.0` ; ADR 0014, étape 2). Les `POST` et `DELETE` de `/agent/containers` ne disent que ce qui change : un retrait manqué laisse une route obsolète. Ici l'Agent dit tout ce que la source publie, et la passerelle retire ce qu'elle gardait de cet Agent pour cette source et qui n'y figure plus.

Corps : `{ "agent_name", "source", "scope", "generation", "routes": [ … ], "inactive": [ … ] }`. `inactive` (passerelle `0.99.0`, Agent `0.16.0`, absent quand rien n'est inactif) liste les conteneurs de la source qui existent sans tourner : `{ "id", "host", "aliases", "container_id", "name", "state" }`. Champ séparé de `routes` pour qu'une passerelle ancienne l'ignore : ces entrées ne créent ni route ni backend et ne sont jamais élaguées par l'état ; elles sont remplacées à chaque état complet de la source et répliquées dans le groupe. Une entrée sans hôte ou sans `container_id` est écartée. `source` : `docker`, `portainer`, `k8s`, ou le nom d'un annuaire (`consul`, `nomad`, `etcd`, `ecs`… : minuscules, chiffres, `-` et `_`, 32 caractères au plus ; `podman` est refusé). Kubernetes et les annuaires sont acceptés depuis Edge `0.92.0` et Agent `0.14.0`. `scope` : l'identifiant de l'endpoint pour Portainer (un endpoint dont la liste a échoué n'envoie rien, ses routes ne sont pas touchées), vide pour Docker. `generation` croît à chaque envoi pour un même (Agent, source, scope) : l'Agent la tient d'un fichier (`agent-state-generation`) avec l'horloge pour plancher. `routes` reprend la charge utile du `POST /agent/containers`, avec les mêmes contrôles de sécurité des labels : une route refusée reste déclarée, la route existante n'est pas retirée.

Réponses : `200 { "applied", "rejected", "pruned" }` ; `409` si la génération est déjà dépassée (l'envoi est ignoré, l'Agent le tient pour pris) ; `400` pour un état incohérent (source inconnue, route d'un autre Agent, d'une autre source ou hors de l'endpoint) ; `404` ou `405` d'une passerelle d'avant cet appel, sur quoi l'Agent publie route par route. Un état vide retire toutes les routes de l'Agent pour cette source.

Seuls sont élagués les backends et routes de l'Agent qui viennent de la source : les backends d'un autre Agent, d'une autre source (Docker : identifiant hexadécimal ; Kubernetes : `k8s:ns/nom` ; annuaire : `empreinte@source`) ou d'une passerelle voisine ne sont jamais touchés. Les identifiants de Kubernetes et des annuaires se comparent en entier, ceux de Docker sur leurs 12 premiers caractères. Un jeton d'Agent peut appeler cet endpoint ; il n'ouvre toujours pas le reste de l'API interne.

### `GET|POST /internal/v1/portal/replica`

Réplication du magasin du portail entre passerelles d'un même groupe HA (comptes, mot de passe et 2FA, coffres, cibles perso, favoris, et sessions web en mode `shared`). L'état échangé est **chiffré (AES-256-GCM) par la clé du groupe** poussée par l'Admin : il ne circule jamais en clair et une clé différente ne déchiffre rien. Fusion « dernier écrit gagne » par clé avec suppressions propagées ; envoi immédiat à chaque modification locale et tirage toutes les 15 s. Répond `204` hors groupe. Sans `GPX_PORTAL_MASTER_KEY` identique sur les membres, les coffres des comptes SSO répliqués ne sont pas déchiffrables ailleurs (un avertissement est journalisé).

### `GET|POST /internal/v1/agents/replica`

Réplication des secrets HMAC des Agents approuvés entre passerelles d'un même groupe HA : un Agent approuvé sur un membre est accepté par tous, il peut donc se reconnecter à un autre membre si sa passerelle tombe, sans l'Admin. L'état est **chiffré (AES-256-GCM) par une clé dérivée de la clé du groupe** (préfixe propre, distinct de celle du portail) ; une autre clé ne déchiffre rien (`400` à l'import). Chaque HMAC porte une estampille et une révocation laisse une pierre tombale : la modification la plus récente l'emporte, une révocation se propage et ferme la connexion de l'Agent sur les autres membres, une rotation horaire se propage. Envoi immédiat à chaque modification locale et tirage toutes les 15 s, entre membres du groupe seulement. Répond `204` hors groupe.

### `GET|POST /internal/v1/agent/state/replica`

Réplication des états complets des Agents (`PUT /internal/v1/agent/state`) entre passerelles d'un même groupe HA (passerelle `0.93.0` ; ADR 0014, étape 3). Un état accepté par un membre atteint les autres, qui l'appliquent comme si l'Agent le leur avait envoyé (mêmes contrôles de sécurité des labels, même élagage, même règle de génération) : un Agent qui bascule, ou une route découverte par un seul membre, devient servie par tout le groupe. Corps **chiffré (AES-256-GCM) par une clé dérivée de la clé du groupe** (préfixe propre) : un document d'un autre groupe est refusé (`400`).

`POST` : un pair transmet les états qu'il vient d'accepter ; ils sont appliqués s'ils dépassent la génération déjà vue pour leur (Agent, source, scope), et ne repartent pas vers les autres membres (chacun reçoit de celui qui a eu l'état de l'Agent). `GET` : les derniers états acceptés ; `If-None-Match` avec le condensé des générations connues du demandeur répond `304` quand elles sont identiques. Un membre tire ses pairs à chaque tour de synchronisation (15 s) : un membre redémarré ou revenu d'une panne rattrape ses routes sans l'Agent ni l'Admin. Seuls les pairs membres du groupe sont servis ; un jeton d'Agent n'ouvre pas ces appels.

### `GET /internal/v1/agent/nodes/replica`

Liste et état des Agents, partagés entre passerelles d'un même groupe HA (passerelle `0.95.0` ; ADR 0014, étape 3). Un membre ne voyait que les Agents qui lui parlaient ; il tire maintenant la liste de ses pairs à chaque tour de synchronisation (15 s) et adopte, pour chaque Agent, l'entrée dont `last_seen_at` est la plus récente. Corps **chiffré (AES-256-GCM) par une clé dérivée de la clé du groupe** (préfixe propre) : un document d'une autre clé est refusé. `GET /internal/v1/nodes` renvoie les mêmes entrées avec `connected_via`, le nom de la passerelle du groupe qui a vu l'Agent en dernier (celle qui répond pour un Agent qui lui parle). L'état `offline` reste calculé d'après `last_seen_at` ; une entrée répliquée ne crée aucune connexion. `POST /internal/v1/agent/{name}/command` transmet la commande au membre `connected_via` quand l'Agent n'est pas tenu ici (en-tête `X-Gpx-Forwarded` : jamais retransmise).

### `GET /internal/v1/replica/proxies`

Proxys configurés en production, partagés entre passerelles d'un même groupe HA (passerelle `0.97.0` ; ADR 0014, étape 3). L'Admin publie chaque modification sur chaque passerelle séparément : un membre absent gardait l'ancienne version. Un membre tire donc les proxys de ses pairs à chaque tour de synchronisation (15 s) et adopte, par identifiant, la version dont `updated_at` est la plus récente ; une suppression plus récente que la version d'un membre la retire, une version plus récente qu'une suppression revient. Corps **chiffré (AES-256-GCM) par une clé dérivée de la clé du groupe** (préfixe propre) : `{ "proxies": [enveloppe…], "tombstones": [{ "id", "deleted_at" }] }`. `If-None-Match` avec le condensé des versions du demandeur répond `304` quand elles sont identiques. Les suppressions sont retenues 30 jours (`tombstones.json`). Les révisions (copies d'audit) ne sont pas échangées. Un jeton d'Agent n'ouvre pas cet appel.

### `POST /internal/v1/group/rule-fired`

Un membre d'un groupe HA confie à l'**exécutant du groupe** le déclenchement d'une règle automatique d'action `notify` qu'il a vu (passerelle `0.101.0` ; ADR 0014, section 7). Les règles s'évaluent sur les données de chaque membre : un même incident déclenchait une notification par membre. L'exécutant est le premier membre de la fiche (ordre de l'identifiant du nœud) vu vivant, c'est-à-dire ayant répondu à l'un des derniers échanges entre pairs (45 s) ; chaque membre le calcule seul. Corps **chiffré par la clé du groupe** (préfixe propre) : un `RuleFiredPayload` de notification, `400` pour tout autre contenu ou un corps non chiffré par cette clé, `404` hors groupe HA. L'exécutant le remonte à l'Admin, avec le nom du membre qui l'a vu, une seule fois par fenêtre de 90 s et par règle. Si l'exécutant ne répond pas, le membre qui a vu l'incident le remonte lui-même : une alerte n'est jamais perdue pour éviter un doublon. Dans une partition réseau, deux membres peuvent se croire exécutant et remonter chacun l'incident. Le ban, la désactivation d'un proxy et le mode strict de Fail2Ban restent locaux (idempotents ; les bans se répliquent déjà).

### `GET /internal/v1/group-card`

Fiche du groupe HA de la passerelle (passerelle `0.101.0` ; ADR 0014, section 3), lue par l'Admin qui se reconstitue (`POST /api/v1/architecture/recover`). `{"group": "ha-1", "version": 5, "members": [{"id", "name", "endpoint"}], "domains": [{"id", "domain", "edge_id", "dns_provider", "dns_credentials", "cert_method", "delegated_to_edge_id", "delegated_endpoint", "delegation_mode", "edge_name", "delegated_to_name"}]}`. `404` tant que l'Admin n'a pas poussé de fiche. L'Admin la calcule à partir d'`architecture.json` et de la base, la fait monter de version à chaque changement de composition ou de domaines (dans `architecture.json`, section `groups`) et la pousse à chaque membre (message `push_group_card`, aussi à chaque connexion). Une passerelle ne remplace sa fiche que par une version supérieure (une plus ancienne poussée par l'Admin est refusée) ; la fiche est conservée chiffrée (`group-card.gpx`, `GPX_GROUP_CARD_PATH`) et se rattrape entre les membres avec le reste de la configuration poussée (`/internal/v1/replica/pushed`, la version décide, pas la date de réception). Les identifiants DNS y figurent comme dans `architecture.json` : les copies sur disque sont chiffrées par la clé du nœud, les échanges entre pairs par la clé du groupe. Seuls les groupes déclarés (`config.cluster_group`) ont une fiche ; une passerelle sans groupe n'en a pas encore.

### `GET /internal/v1/replica/pushed`

Configuration poussée par l'Admin, rattrapée entre passerelles d'un même groupe HA (passerelle `0.100.0` ; ADR 0014, étape 3). L'Admin publie chaque document sur chaque passerelle, une par une : un membre absent à ce moment gardait l'ancienne version. Chaque membre retient le dernier document reçu pour chaque type réplicable (certificats par nom, plugins, snippets, fournisseurs d'authentification, profils IP, CrowdSec, Fail2Ban, Ephor, WAF, pages d'erreur, modèles Access, règles automatiques, délégations) avec son instant de réception, dans un journal local chiffré (`GPX_PUSHED_JOURNAL_PATH`, `/etc/goproxify/pushed-journal.gpx` par défaut) qui survit à un redémarrage sans l'Admin. Un membre tire ce journal de ses pairs à chaque tour de synchronisation et rejoue, par le chemin d'une poussée de l'Admin, les documents plus récents que les siens. Corps **chiffré (AES-256-GCM) par une clé dérivée de la clé du groupe** (préfixe propre), `Authorization` de pair, `If-None-Match` sur le condensé des contenus (`304` si identiques, même quand les dates de réception diffèrent). `204` hors groupe HA. Un pair ne peut faire appliquer que ces types : un autre type, une clé qui ne correspond pas au type ou un contenu qui ne correspond pas à son condensé est ignoré. Les réglages d'exploitation, les délais du serveur, la rétention des logs et l'export SIEM (valeur par passerelle), les pairs et le jeton Admin ne sont pas répliqués.

### `GET|POST /internal/v1/ech/replica`

Réplication du jeu de clés ECH (clés privées comprises) entre passerelles d'un même groupe HA, sans l'Admin. Corps **chiffré (AES-256-GCM) par une clé dérivée de la clé du groupe** (préfixe propre) : une autre clé ne déchiffre rien (`400` à l'import). Le jeu porte une estampille (ns) ; le plus récent l'emporte, une désactivation (jeu vide) plus récente aussi, un jeu de version égale ou plus ancienne est ignoré. Envoi après chaque push de l'Admin, tirage à chaque synchro entre pairs. Répond `204` hors groupe ou sans jeu.

### `POST /internal/v1/bans/gossip`

Un ban décidé localement (Ephor, Fail2Ban) est transmis aux passerelles pairs sans passer par l'Admin ; chaque passerelle récupère aussi périodiquement les bans actifs de ses pairs (`GET /internal/v1/bans`). Les bans expirés, sans IP ou déjà connus (même identifiant ou même IP) sont ignorés ; un ban reçu d'un pair n'est jamais réémis. Ce circuit prend le relais quand l'Admin est indisponible.

### `GET /internal/v1/threat-lists/export` · `POST /internal/v1/threat-lists/sync`

Listes de référence Ephor (`ua.txt`, `paths.txt`, `ips.txt`) : échangées entre passerelles pairs à chaque cycle de synchronisation, la plus récente l'emporte.

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
| `push_settings` | Pousse les paramètres runtime (log level, tracing, protection des IP, etc.) ; la passerelle en garde une copie chiffrée (`edge-settings.gpx`) rechargée au démarrage, un envoi partiel ne modifie que les champs présents |
| `push_delegations` | Pousse les routes de délégation multi-passerelle |
| `full_sync` | Full sync : envoie toutes les données en une seule enveloppe |
| `approve_agent` | Demande à la passerelle d'approuver un Agent en attente |
| `push_log_retention` | Impose à la passerelle la conservation de ses logs, `{"access_days": N, "system_days": M}` (1 à 3650) : appliquée à la prochaine purge, gardée chiffrée (`log-retention.gpx`) et relue au démarrage avant `edge.json` (Edge `0.96.0`) |
| `log_ack` | *(Admin `0.215.0`, Edge `0.128.0`)* Positions que l'Admin a rangées dans son volume de logs, par flux : `{"cursors": {"access": N, "system": M, "minute": P, "iperr": Q}}`. Envoyé quelques secondes après chaque rafale de lots, seulement par un Admin qui a un volume de logs. La passerelle fait avancer ses positions acquittées (jamais reculer : une remise en arrière passe par `log_resume`) et supprime une période acquittée 7 jours après sa fin, une période non acquittée après 30 jours. |
| `log_info` | Conservation des logs appliquée par la passerelle, toutes les 30 s : `{"node_name", "access_days", "system_days", "access_last", "system_last", "buffer_active", "unacked_days", "buffer_max_days"}`. `buffer_active`, `unacked_days` (âge en jours de la plus ancienne ligne non acquittée) et `buffer_max_days` *(Edge `0.128.0`)* décrivent le tampon ; `access_last` et `system_last` *(Edge `0.127.0`)* sont les derniers identifiants que sa base a attribués : l'Admin les compare à la position de sa copie pour savoir si elle est à jour (lecture `auto`). |
| `log_resume` | Annonce les positions que l'Admin a déjà enregistrées par flux de logs (`{"cursors": {"access": N, "system": M}}`, 0 ou absent : depuis le début). `stored` *(Edge `0.128.0`)* vaut vrai quand l'Admin range les lignes dans son volume de logs : les positions valent alors acquittement et la passerelle peut purger son tampon (sinon elles ne protègent ni ne purgent rien). Envoyé à chaque connexion et chaque fois qu'un lot est refusé ; la passerelle reprend l'envoi après ces positions (Edge `0.75.0`, Admin `0.165.0`). La passerelle envoie **toutes** ses lignes, accès ordinaires compris (Edge `0.126.0`, Admin `0.213.0`, [ADR 0018](adr/0018-logs-geres-par-l-admin.md)) : avec un volume de logs, la position annoncée est la plus basse de celle de la table `logs` et de celle du store de la passerelle. Le champ `access` et le réglage `ship_access` ont disparu (Admin `0.178.1`, Edge `0.88.1`) |

### Types de messages Passerelle→Admin

| Type | Description |
|---|---|
| `log_stream` | Lot de lignes contiguës lues dans la base de logs de la passerelle : `{"stream": "access"\|"system", "after": N, "entries": [...]}`. Chaque entrée porte `seq`, son identifiant dans la base (numéro de période << 40 \| rowid), croissant. `after` est la position qui précède la première ligne : l'Admin n'accepte le lot que si elle n'est pas au-delà de la sienne (sinon il manque des lignes et il renvoie `log_resume`), dédoublonne par `seq`, et enregistre lignes et position dans la même transaction (dans le store de la passerelle du volume de logs, Admin `0.213.0`). Chaque entrée peut porter `user_agent` (Edge `0.126.0`). Au plus 500 lignes par lot. Une passerelle sans base de logs locale envoie encore `access_log` (tableau d'entrées sans `seq`, perdu si aucun Admin n'est connecté) Une passerelle d'avant Edge `0.126.0` n'envoie que les événements de sécurité et peut porter `through`, la dernière position examinée : l'Admin y avance son curseur même sans ligne reçue. Un lot sans ligne porteur de `"reset": true` *(Admin `0.180.0`, Edge `0.90.0`)* signale que `after`, la position de l'Admin, dépasse tout ce que la base de la passerelle a attribué (base remplacée : état restauré sans les logs, disque neuf) : l'Admin ramène la position de ce flux à 0 (seulement si `after` est bien la sienne) et la passerelle renvoie sa base depuis le début |
| `agg_stream` | Lot de cumuls par minute calculés par la passerelle avec ses lignes : `{"after": N, "rows": [{"minute", "node_name", "domain", "status", "requests", "bytes", "latency_ms_sum", "bots", "seq"}]}`. `seq` est le numéro de la dernière mise à jour de la ligne (croissant, indépendant du fichier de période) ; une minute qui change revient avec sa valeur à jour, que l'Admin **remplace** dans `logs_minute` au lieu de l'additionner. Mêmes règles de position (`after`) et de reprise que `log_stream`, flux `minute` de `log_resume`. Aucune IP ni chemin (Edge `0.77.0`, Admin `0.166.0`) |
| `ip_stream` | Lot de compteurs d'erreurs client (4xx hors 404) par IP et par minute, pour le Fail2Ban global : `{"after": N, "rows": [{"minute", "ip", "errors", "seq"}]}`. Même contrat que `agg_stream` (valeur à jour qui remplace, position `after`, flux `iperr` de `log_resume`). Jamais envoyé pour une IP tronquée par l'anonymisation ou la pseudonymisation. Gardés 48 h sur la passerelle, 24 h sur l'Admin, et effacés avec l'IP (`ip_counters_deleted`) (Edge `0.78.0`, Admin `0.167.0`) |
| `log_live` (Admin → passerelle) | `{"ttl_sec": N}` : une vue Live est ouverte ; la passerelle envoie ses nouvelles lignes (accès et système, 500 par seconde au plus) pendant `ttl_sec` secondes (60 au plus), renouvelé toutes les 10 s par l'Admin tant qu'une vue est ouverte (Edge `0.84.0`, Admin `0.174.0`) |
| `log_live_rows` (passerelle → Admin) | `{"entries": [...], "dropped": bool}` : lignes récentes pour les vues Live, diffusées sans être enregistrées ; `dropped` : la passerelle en a sauté faute de débit |
| `edge_traffic` (passerelle → Admin) | `{"node_name", "window_sec": 60, "requests", "blocked", "errors"}` toutes les 5 s : le débit de la dernière minute de la passerelle (accès traités, refusés 403/429, erreurs 5xx), lu dans sa base de logs. L'Admin le sert à la carte de topologie (`GET /nodes/live`) et l'oublie après 20 s de silence (Edge `0.85.0`, Admin `0.175.0`) |

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
| `edge_endpoints` | Adresses des **autres** membres du groupe HA de la passerelle (`{"endpoints": [...]}`), envoyées à l'approbation, à chaque connexion et quand la composition du groupe change. L'Agent les conserve (`/etc/goproxify/agent-edges.json`) et bascule vers l'un d'eux si sa passerelle reste injoignable (3 échecs consécutifs) : il s'y reconnecte avec son HMAC, répliqué dans le groupe, et republie tous ses conteneurs. Absent hors groupe. |
| `command` | Commande à exécuter sur l'Agent (restart conteneur, pull image, etc.) |
| `rescan` | Demande un rescan Docker immédiat |
| `ping` | Ping keepalive (répondu par `pong`) |

### Types de messages passerelle→Admin

| Type | Description |
|---|---|
| `agent_pending` | Un Agent attend l'approbation (notification UI) |
| `node_update` | Mise à jour de l'état d'un Agent (online/offline/metrics) |

---

## Utilisateurs, équipes et permissions — `/api/v1/users`, `/api/v1/teams`

Routes réservées aux admins (`adminOnly`, scope PAT `users:read` / `teams:read`). Rôles plateforme : `superadmin` (unique, non attribuable), `admin`, `user`, `dpo`. Le rôle `dpo` a les droits d'un compte `user` plus la permission `gdpr:reveal`.

**Permissions** : droits de capacité, distincts des grants de ressources (`domain`, `server`, `proxy`, `edge`). Seule permission connue : `gdpr:reveal` (révéler l'IP réelle d'une entrée de log pseudonymisée, voir [Logs RGPD](#logs-rgpd--apiv1logs)). Elle est détenue par le superadmin, par le rôle `dpo`, en propre (`user_permissions`) ou via une équipe (`team_permissions`). Une permission inconnue renvoie `400`.

| Méthode | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/users` · `/api/v1/users/{id}` | Comptes ; chaque compte porte `permissions` (accordées en propre) et `effective_permissions` (y compris rôle et équipes) |
| POST | `/api/v1/users` | `{email, password, role, scopes?, permissions?}` |
| PUT | `/api/v1/users/{id}` | `{email, role, password?, scopes?, permissions?}` ; `permissions` absent = inchangé, `[]` = retirées |
| PUT | `/api/v1/users/{id}/password` | `{password}` |
| DELETE | `/api/v1/users/{id}` | — |
| GET | `/api/v1/teams` · `/api/v1/teams/{id}` | Équipes ; chacune porte `permissions` (accordées à ses membres) |
| GET · PUT | `/api/v1/teams/{id}/permissions` | `{permissions: [...]}` ; `PUT` remplace la liste |
| POST · DELETE | `/api/v1/teams/{id}/members[/{user_id}]` | Membres |
| GET | `/api/v1/me` | Compte courant ; `permissions` = permissions effectives |

Règles (depuis Admin `0.78.0`), contrôlées pour les sessions UI comme pour les PAT :

- **attribuer ou retirer** une permission est réservé au superadmin : rôle `dpo` donné ou retiré, `permissions` d'un compte modifiées, `PUT /teams/{id}/permissions`, ajout ou retrait de membres et suppression d'une équipe qui porte une permission — sinon `403` (`api.err.superadmin_required`). Chaque attribution est auditée (`set_permissions`) ;
- **compte protégé** : un compte superadmin ou détenteur d'une permission (par n'importe quelle voie) ne peut être modifié (`PUT /users/{id}`), voir son mot de passe changé ou être supprimé que par le superadmin — sinon `403` (`api.err.protected_account`). Auparavant, un admin pouvait changer le mot de passe de n'importe quel compte, superadmin compris.

Les permissions sont copiées dans `users.yaml` (comptes et équipes). Elles ne font pas partie des sauvegardes de configuration (`team_permissions` est exclue de la section standard ; elle est dans la section `secrets` chiffrée, restaurable par le seul superadmin). Un import ou une restauration (`POST /api/v1/import/backup/apply`, `POST /api/v1/backups/snapshots/{id}/restore`) lancé par un admin n'attribue jamais le rôle `superadmin` ni `dpo` (compte créé en `user`, rôle d'un compte existant conservé), ne modifie pas le rôle du superadmin ni d'un `dpo`, et n'ajoute aucun membre à une équipe qui porte une permission. Lancé par le superadmin, il restaure le rôle `dpo` et ces membres ; le rôle `superadmin` n'est jamais importé. Auparavant, un import en `overwrite` réécrivait le rôle de tout compte existant, superadmin compris.

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
| GET | `/api/v1/logs` | `logs:read` | Liste paginée (curseur `before_id`, `page_size`) : filtres `kind` (`access`/`system`), `level`, `component`, `node_name`/`node_id`, `domain`, `ip`, `method`, `status`, `path`, `tls_ja3`, `tls_ja4` (égalité exacte sur l'empreinte TLS du client, depuis Admin `0.115.0`), `search`, `date_from`, `date_to`, `exclude_internal` (`1`/`true` : exclut les IP de réseau privé/loopback — RFC 1918, loopback, link-local IPv4/IPv6 — appliqué en SQL avant `LIMIT`, donc `has_more`/`page_size` restent cohérents) → `{has_more, last_id, entries:[Entry]}`. Chaque `Entry` porte `country` (code ISO alpha-2, résolu au mieux depuis le cache géo-IP déjà alimenté par le tableau de bord/Prism/Bans ; absent si l'IP n'a pas encore été résolue — pas d'appel réseau synchrone sur cette route), `request_id` (identifiant de la requête d'origine, transmis par la passerelle — voir `/logs/correlate?request_id=`), `waf_matches` (catégories de règles WAF déclenchées, tableau, absent si aucune), `threat_signal` (signal Ephor déclenché, absent sinon), `tls_ja3` / `tls_ja4` (empreintes TLS calculées par la passerelle, absentes en HTTP clair, en HTTP/3 ou pour une entrée antérieure à Admin `0.115.0` / Edge `0.44.0`) et, depuis Admin `0.71.2`, `ip_truncated` (`true` quand la passerelle a tronqué l'IP par l'anonymisation ou la pseudonymisation RGPD — `x.x.x.0`, préfixe /48 `2a01:e0a:1::` — : la valeur regroupe plusieurs clients et ne doit être ni bannie ni analysée ; absent sinon, et absent des entrées stockées avant Admin `0.71.1` ou envoyées par une passerelle antérieure à Edge `0.17.12`). Une entrée pseudonymisée porte aussi `ip_truncated` (son `ip` vaut `[pseudonymisé]`). `exclude_internal` s'applique aussi à `/logs/histogram`, `/logs/facets`, `/logs/export` et `/logs/live` (mêmes filtres) |
| GET | `/api/v1/logs/live` | `logs:read` | Flux SSE des nouvelles entrées, mêmes filtres et mêmes champs que la liste, `ip_truncated` compris (`?_auth=<token>` requis, `EventSource` ne pose pas d'en-tête `Authorization`). L'ouverture du flux fait envoyer leurs nouvelles lignes par les passerelles (non enregistrées), tant que le flux est ouvert |
| GET | `/api/v1/logs/export?format=json\|csv` | `logs:read` | Export des entrées filtrées (mêmes filtres que la liste) |
| GET | `/api/v1/logs/correlate` | `logs:read` | Entrées voisines d'un événement : `request_id`, ou `domain`+`ts`+`window` (secondes, défaut 30) |
| GET | `/api/v1/logs/settings` | `logs:read` | Paramètres de rétention (`retention_access_days`, `retention_system_days`, `retention_ban_days`) et de pseudonymisation. L'Admin ne reçoit des accès que ceux signalés par le WAF ou Ephor (`ship_access`, retiré en Admin `0.178.1`) : ses `retention_access_days` et `retention_system_days` ne portent que sur cette copie et sur ses propres logs. *(Admin `0.183.0`, Edge `0.96.0`)* `edge_retention` donne la conservation des logs **dans les passerelles**, où vivent les accès HTTP : `{configured, access_days, system_days, nodes:{<passerelle>:{access_days, system_days}}, edges:[{node_name, access_days, system_days, reported_at, stale?}], defaults}`. `access_days` / `system_days` sont la valeur commune (365 et 90 par défaut), `nodes` les exceptions par passerelle (une durée à 0 ou absente : la valeur commune), `edges` ce que chaque passerelle a annoncé appliquer (`stale` : muette depuis 90 s), `configured` faux tant que personne n'a rien réglé (chaque passerelle garde alors son `edge.json`) `read_source` *(Admin `0.214.0`, [ADR 0018](adr/0018-logs-geres-par-l-admin.md))* : d'où l'Admin lit les logs d'accès des passerelles, `auto` (défaut : la copie de son volume de logs quand elle a rattrapé ce que la passerelle annonce, sinon la passerelle), `gateway` (toujours la passerelle) ou `admin` (toujours la copie). `vault_retention` *(Admin `0.217.0`)* : `{access_days, system_days, defaults}`, la conservation de l'historique dans le volume de logs de l'Admin (365 et 90 jours par défaut). |
| PUT | `/api/v1/logs/settings` | `logs:write` + admin | `edge_retention` *(Admin `0.183.0`)* : même forme que la lecture (sans `edges`), `400` si une durée sort de 1 à 3650 jours ; enregistré, audité (`logs_edge_retention`, avec les durées et le nombre d'exceptions), puis poussé à chaque passerelle (`push_log_retention`) et à sa connexion : elle l'applique seule à sa prochaine purge horaire, en garde une copie chiffrée et la relit au démarrage, Admin éteint ; **réduire une durée supprime définitivement les lignes les plus anciennes**. Modifier la rétention (`retention_access_days`, `retention_system_days`, `retention_ban_days` : historique et bans expirés, 365 jours par défaut ; le cache GeoIP suit `retention_access_days`), `ip_anonymize`, `ip_pseudonymize`. Les deux modes sont exclusifs : `400` si la requête les laisserait actifs ensemble (en tenant compte de la valeur déjà enregistrée ; envoyer les deux champs pour basculer). Un mode modifié est audité (`logs_ip_anonymize`, `logs_ip_pseudonymize`) et poussé aux passerelles en un seul message `push_settings` portant les deux champs ; une valeur inchangée n'est ni auditée ni poussée. Une entrée pseudonymisée a `ip` = `[pseudonymisé]` dans `GET /logs` `read_source` : `auto`, `gateway` ou `admin` (`400` sinon), audité (`logs_read_source`). `vault_retention` : `{access_days, system_days}`, de 1 à 3650 jours (`400` sinon), audité (`logs_vault_retention`), appliqué à la prochaine purge horaire de chaque passerelle du volume ; **réduire une durée supprime définitivement les lignes les plus anciennes**. |
| GET | `/api/v1/logs/siem` | `logs:read` + admin | *(Admin `0.178.0`, Edge `0.87.0`, [ADR 0012](adr/0012-logs-proprietaire-edge.md))* Configuration de l'**exporteur SIEM** : `{enabled, destinations:[{id, name, type, address, tls, ca_pem, headers, kinds, min_level, security_only, backfill_hours, alert_after_minutes, facility, nodes}]}`. `type` : `syslog` (`address` `hôte:port`, RFC 5424 sur TCP, TLS avec `tls`, cadrage par comptage d'octets RFC 6587), `http` (`address` URL http(s), un lot NDJSON par `POST`, 2xx = accusé) ou `otlp` *(Admin `0.179.0`, Edge `0.89.0`)* (OTLP/HTTP en JSON : `address` est l'URL complète du collecteur, par exemple `http://collector.example.com:4318/v1/logs`, un `ExportLogsServiceRequest` par `POST`, attributs sémantiques OpenTelemetry comme `http.response.status_code`, `client.address`, `url.path`, `log.id`). `nodes` *(Admin `0.179.0`)* : noms des passerelles qui exportent vers cette destination (vide : toutes) ; l'Admin n'envoie à chaque passerelle que ses destinations, une destination qui ne la vise plus y est éteinte avec son curseur. `kinds` : `access` et/ou `system` (vide = les deux) ; `min_level` : `info` (défaut), `warn`, `error` ; `security_only` : seuls les accès signalés par le WAF ou Ephor (les logs système ne sont pas filtrés par là) ; `backfill_hours` : à la création, repart de N heures en arrière au lieu de « maintenant » ; `alert_after_minutes` : retard déclenchant l'alerte `siem_export_lag` (60 par défaut) ; `ca_pem` : autorité de confiance en plus de celles du système. **Les valeurs de `headers` (jetons) sont masquées** (`********`) |
| PUT | `/api/v1/logs/siem` | `logs:write` + admin | Enregistre la configuration (corps de même forme ; au plus 8 destinations, `400` avec la raison si une destination est invalide ou un identifiant en double). Une valeur d'en-tête renvoyée masquée garde le jeton enregistré ; une destination sans `id` en reçoit un (le curseur d'une destination est attaché à son `id` : retirée ou éteinte, elle le perd). Audité (`logs_siem_config`, sans aucun secret). La configuration est poussée à chaque passerelle (`push_siem_config`), qui en garde une copie chiffrée et exporte seule ensuite, même Admin éteint ; elle l'est aussi à la connexion d'une passerelle. Réponse : la configuration enregistrée, masquée |
| GET | `/api/v1/logs/siem/status` | `logs:read` + admin | État rapporté par chaque passerelle toutes les 30 s : `{nodes:[{node_name, reported_at, stale?, destinations:[{id, name, type, state, last_error?, last_error_at?, delivered, last_sent?, lag_sec, at_risk?, alert_after_min}]}]}`. `state` : `starting`, `ok`, `retrying` (le dernier envoi a échoué, il est renvoyé tel quel après attente), `stopped`. `lag_sec` : âge de la plus ancienne ligne pas encore livrée (0 : à jour). `at_risk` : le retard dépasse 80 % de la conservation, des lignes vont être purgées avant livraison. `stale` : la passerelle n'a rien rapporté depuis 90 s |
| POST | `/api/v1/logs/reveal-ip` | `gdpr:reveal` (superadmin, rôle `dpo`, droit délégué — voir [Utilisateurs, équipes et permissions](#utilisateurs-équipes-et-permissions--apiv1users-apiv1teams)) | Révéler l'IP réelle d'une entrée pseudonymisée |
| DELETE | `/api/v1/logs/by-ip/{ip}` | `logs:write` + admin | Effacement RGPD Art.17 par IP, entrées pseudonymisées comprises (empreinte `ip_hmac`), IPv6 quelle que soit sa notation → `{deleted, bans_deleted, ban_history_deleted, geoip_cache_deleted, ip_counters_deleted, audit_ip_cleared, ip}` : supprime aussi les bans de l'IP, leur historique, son entrée du cache GeoIP et ses compteurs d'erreurs du Fail2Ban global, vide son adresse dans le journal d'audit (l'entrée reste), lève ses bans sur les passerelles et ordonne aux passerelles d'effacer ses lignes d'access log et son historique de bans (`erase_ips`, rejoué à la reconnexion des passerelles hors ligne pendant 365 jours, IP chiffrée dans la file) (Admin `0.163.0`, Edge `0.73.0`). *(Admin `0.177.0`, Edge `0.86.0`)* L'ordre est aussi envoyé à chaque passerelle joignable par `POST /internal/v1/logs/erase` : elle efface les lignes de sa base de logs (accès **et** logs système, pseudonymisées comprises, par adresse et par empreinte) et rend ce qu'elle a supprimé ; la réponse porte `gateways: [{node_name, status, log_lines, ban_rows, error?}]` avec `status` `erased` (la passerelle a répondu avec ses comptes : c'est la preuve de l'effacement chez elle) ou `pending` (elle n'a pas répondu, l'ordre mis en file lui sera rejoué), et l'audit en garde le total. `{ip}` doit être une adresse IP (`400` sinon). L'audit (`rgpd_erasure_ip`) et le log système ne contiennent que l'empreinte de l'IP (`hmac:…`) |
| DELETE | `/api/v1/logs/by-user/{user_id}` | `logs:write` + admin | Effacement RGPD Art.17 par utilisateur |
| POST | `/api/v1/logs/subject-export` | `logs:write` + admin | Export RGPD d'accès et de portabilité (Art. 15 et 20) : corps `{"ip"}` ou `{"user_id"}` (un seul des deux, `400` sinon ; `reason` facultatif). Réponse JSON à télécharger : pour une IP, logs (entrées pseudonymisées comprises, retrouvées par empreinte), bans, historique des bans, position GeoIP et entrées d'audit portant l'adresse ; pour un compte, profil (jamais le mot de passe), équipes, logs attribués et entrées d'audit. Logs plafonnés à 100 000 lignes (`logs_truncated`). *(Admin `0.173.0`)* Pour une IP, les lignes d'accès viennent de la base de chaque passerelle (les plus récentes d'abord) ; `gateways_missing` nomme celles qui n'ont pas répondu : l'export est alors incomplet. Audité (`rgpd_export_ip`, `rgpd_export_user`) sans l'IP en clair |
| GET | `/api/v1/logs/histogram` | `logs:read` | Entrées par tranche de temps et par niveau : mêmes filtres que la liste plus `bucket` (`minute`, `hour`, `day` ; défaut selon l'étendue, 24 h sans `date_from`) → `{bucket, points:[{bucket, total, warn, error}]}` |
| GET | `/api/v1/logs/facets` | `logs:read` | Comptage des entrées filtrées par valeur, pour l'explorateur de logs : mêmes filtres que la liste plus `fields` (CSV parmi `level`, `component`, `node_name`, `domain`, `method`, `tls_ja4`, `tls_ja3` ; par défaut les cinq premiers) → `{<field>: [{value, count}]}`, 12 valeurs les plus fréquentes par champ, valeurs vides exclues |
| GET | `/api/v1/audit/histogram` | authentifié | Actions du journal d'audit par tranche et par gravité : filtres `component`, `action`, `actor`, `severity`, `from`, `to` (RFC 3339) plus `bucket` → `{bucket, points:[{bucket, total, warn, critical}]}` |

### Recherche dans les logs des passerelles (`source=edge`)

*(Admin `0.168.0`, Edge `0.79.0`, [ADR 0012](adr/0012-logs-proprietaire-edge.md))* Les lignes brutes vivent dans la base de logs de chaque passerelle. Avec `source=edge`, `GET /api/v1/logs`, `/logs/facets`, `/logs/histogram`, `/logs/export` et `POST /logs/reveal-ip` interrogent toutes les passerelles visées et fusionnent leurs réponses ; sans ce paramètre l'Admin répond depuis sa propre base, comme avant (tant qu'il garde les accès bruts, les deux sources donnent les mêmes résultats). Les lignes propres de l'Admin (audit, logs de son process, requêtes de son API : `component=admin`), qui ne sont que dans sa base, sont **fusionnées** dans la même réponse, avec `node_name: "admin"` et un `id` de la forme `admin:<type>:<id>` ; un filtre `component=admin` n'interroge que l'Admin, et viser une passerelle (`node_id` / `node_name`) exclut ses lignes. C'est la source que l'interface utilise depuis Admin `0.169.0` (le mode Live, lui, lit encore la copie de l'Admin).

Mêmes filtres que la liste locale (`level`, `component`, `domain`, `ip`, `method`, `status` — code ou classe `4xx` —, `path`, `tls_ja3`, `tls_ja4`, `search`, `request_id` (corrélation exacte), `date_from` / `date_to` en RFC3339, `kind`, `exclude_internal`), plus `node_id` ou `node_name` pour viser une seule passerelle. Une date illisible ou un `cursor` corrompu répondent `400`.

| Route | Réponse `source=edge` |
|---|---|
| `GET /logs` | `{source, entries, has_more, cursor, partial, unreachable, page_size}` — `page_size` de 1 à 500 (défaut 50), pagination par le **`cursor`** de la réponse (pas de `before_id`). Du plus récent au plus ancien. Chaque entrée garde les champs d'une entrée locale, avec `id` = référence `<passerelle>:<type>:<id>` de la ligne chez sa passerelle, `kind` (`access` ou `system`), `node_id`, `node_name`, `pseudonymized` |
| `GET /logs/facets` | `{source, facets: {champ: [{value, count}]}, partial, unreachable}` — `node_name` donne le nombre de lignes de chaque passerelle ; les autres champs sont additionnés |
| `GET /logs/histogram` | `{source, bucket, points, partial, unreachable}` — tranches à l'heure locale de l'Admin |
| `GET /logs/export` | CSV ou JSON des lignes de toutes les passerelles (au plus 100 000) ; l'en-tête `X-Unreachable-Nodes` donne le nombre de passerelles qui n'ont pas répondu |
| `POST /logs/reveal-ip` | corps `{"entry_ref": "<passerelle>:<type>:<id>", "reason": "…"}` au lieu de `entry_id` ; l'IP est déchiffrée **chez la passerelle** qui la garde, avec la clé de celle-ci |

`partial: true` : une passerelle a atteint son délai (8 s) avant d'avoir parcouru toute la période demandée, il faut affiner le filtre. `unreachable` liste les passerelles qui n'ont pas répondu (`node_id`, `node_name`, `error`) : leurs lignes manquent dans la réponse, et leur position est conservée dans le `cursor` pour la page suivante. Une passerelle déjà occupée par deux recherches répond `429` et apparaît dans `unreachable`.

**API interne de la passerelle** (appelée par l'Admin avec son jeton ; un jeton d'Agent n'y a pas accès) : `POST /internal/v1/ephor/simulate` (Edge `0.83.0` : `{current, candidate, hours, domain}` → `{current, candidate, events, skipped, truncated, partial}`, rapports de `threat.Simulate` sur les accès de la passerelle), `GET /internal/v1/logs/search`, `GET /internal/v1/logs/histogram`, `GET /internal/v1/logs/facets`, `POST /internal/v1/logs/reveal`, `POST /internal/v1/logs/top` et `GET /internal/v1/logs/unique-ips` (Edge `0.81.0`).

`POST /internal/v1/logs/top` (filtres de la recherche en paramètres, plus `domains` — liste séparée par des virgules —, `path_prefix`, et, depuis Edge `0.82.0`, `ip_from` / `ip_to` (intervalle de la colonne texte `ip`, un sur-ensemble de la plage à raffiner), `ip_ranges` (jusqu'à 400 intervalles `de|à` séparés par des virgules) et `attributable=1` (écarte les IP tronquées) ; ces trois filtres valent aussi pour `search`) regroupe les accès par champ ; corps `{dim, mode, k?, min?, values?, with_ips?}` avec `dim` parmi `path`, `ip`, `component`, `referrer`, `tls_ja4`, `domain`, `status` et `all` (un seul groupe : les totaux de la sélection) et `mode` : `best` (les `k` valeurs les plus fréquentes), `above` (toutes celles vues au moins `min` fois, 200 000 au plus) ou `exact` (les comptes des `values`, avec `with_ips` : le résumé des IP attribuables de chacune). Réponse `{items:[{value, requests, errors, bytes, latency_sum, flagged?, blocked?, ok?, first_seen?, last_seen?, ip_truncated?, ja3?, ips?}], complete, partial}` ; tous les compteurs s'additionnent d'une passerelle à l'autre, ce que l'Admin utilise pour classer exactement (algorithme de seuil, [ADR 0012](adr/0012-logs-proprietaire-edge.md)). `GET /internal/v1/logs/unique-ips` rend `{ips:{exact:[…]} | {hll:"…"}, partial}`, le résumé des IP distinctes de la période : liste jusqu'à 2 000 adresses, sketch HyperLogLog au-delà. Mêmes filtres, plus `cursor`, `limit` (500 au plus, jusqu'à 100 000 avec `bulk=1`, un seul export à la fois) ; `tz_offset_min` et `bucket` pour l'histogramme. Recherche bornée à deux requêtes simultanées. Une recherche par IP retrouve aussi les lignes pseudonymisées, par leur empreinte. Ces lectures ne portent que les lignes de la passerelle (ou de sa copie dans le volume de logs de l'Admin). La réplication des lignes entre les membres d'un groupe HA (Edge `0.109.0`) est retirée (Edge `0.129.0`, Admin `0.217.0`, [ADR 0018](adr/0018-logs-geres-par-l-admin.md)) : `scope`, `origin` et `/internal/v1/replica/logs` n'existent plus.

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

La révélation reste possible après la désactivation de la pseudonymisation, tant que l'entrée est conservée.

Codes d'erreur :
- `403` — scope `gdpr:reveal` manquant
- `400` — `entry_id` ou `reason` manquant
- `404` — entrée introuvable
- `422` — entrée non pseudonymisée
- `500` — clé de pseudonymisation non chargée

## Prism — bans et scan d'IP

- `GET /api/v1/prism/bans/breakdown` — bans actifs ventilés par source puis par technique de détection : `[{source, source_label, ephor, technique, label, count}]`. `ephor: true` pour la source `threat` (moteur Ephor de la passerelle : techniques `ip`, `ua`, `path`, `rate` et leurs variantes `custom_*`) ; Fail2Ban est rapporté en `errors`, CrowdSec par scénario.
- `GET /api/v1/prism/ip-scan?ip=<ip>[&from&to]` — ré-analyse à la demande d'une IP *(depuis Admin `0.172.0`, lue dans les bases de logs des passerelles)* : `verdict` (`banned` | `suspect` | `clean`), bans actifs (avec source/technique), nombre de bans passés, décisions de menace, requêtes/erreurs sur la période et chemins les plus visés. `ip_truncated: true` (depuis Admin `0.71.2`) quand les logs de la période portent cette valeur tronquée par l'anonymisation RGPD : requêtes et erreurs sont alors celles de tout un /24 ou /48, et l'interface ne propose pas de bannir.
- `GET /api/v1/prism/tls-fingerprints?[from&to&proxy&node_name&ip&path&limit]` — empreintes TLS (JA4) les plus actives (`limit` 30 par défaut, depuis Admin `0.117.0`) : `[{ja4, ja3, requests, errors, flagged, unique_ips}]` ; `flagged` compte les requêtes signalées par le WAF ou Ephor, `unique_ips` ignore les IP tronquées ou pseudonymisées ; les requêtes sans empreinte (HTTP clair, HTTP/3, entrées antérieures) sont ignorées. Scope `logs:read`
- `GET /api/v1/prism/ips?[from&to&proxy&node_name&ip&path&limit]` — IP les plus actives (`limit` 50 par défaut) : `[{ip, requests, errors, bytes, ip_truncated?}]`. `ip_truncated: true` (depuis Admin `0.71.2`) signale une IP tronquée par l'anonymisation ou la pseudonymisation RGPD, qui regroupe plusieurs clients : l'interface la marque « Tronquée » et n'y propose ni ré-analyse ni ban.
- `GET /api/v1/prism/geo/points?[from&to&proxy&node_name&limit]` — trafic agrégé par ville, les plus actives d'abord (`limit` 300 par défaut, 1000 max) : `[{city, region, country_code, country_name, lat, lon, requests, errors, error_rate, ips, banned_ips}]`. La position est approximative (géolocalisation IP, précision de l'ordre de la ville) ; les IPs pas encore localisées sont ignorées.
- Le paramètre `proxy` des endpoints `/prism/*` (kpis, timeline, status, paths, ips, geo, geo/points, anomalies, live-ips) accepte plusieurs domaines séparés par des virgules (depuis Admin `0.101.0`) : les résultats agrègent tous les domaines listés. Utilisé par la Vue Proxy (sélection cumulable).
- `GET /api/v1/prism/anomalies?[from&to&proxy&node_name]` — écarts détectés sur la période, critiques d'abord : `[{kind, level, subject, label, value, baseline, count, banned?}]`. `kind` : `error_spike` (point de la courbe > moyenne + 2,5 écarts-types, au moins 10 erreurs ; `subject` = tranche horaire), `dominant_ip` (au moins 20 % des requêtes et 50 requêtes ; `banned` si déjà bannie ; depuis Admin `0.71.2`, seules les IP attribuables comptent — une IP tronquée par l'anonymisation RGPD ou `[pseudonymisé]` regroupe plusieurs clients et n'est jamais retenue), `country_errors` (au moins 20 % d'erreurs sur 50 requêtes, 2 max), `backend_errors` (plus de 10 % d'erreurs sur 20 requêtes, 2 max), `bot_share` (au moins 30 %). `level` : `critical` | `warning`.
- `GET /api/v1/prism/slo?[target&days&proxy&node_name]` — SLO de disponibilité (réponses non-5xx) sur une fenêtre glissante (`target` en % : objectif enregistré, 99.9 par défaut ; `days` : 30 par défaut, 90 max ; `from`/`to` ignorés) : `{target, days, requests, errors, availability, budget_total, budget_left_pct, burn_1h, burn_6h, state}`. `burn_*` vaut 1 quand le budget est consommé exactement au rythme de l'objectif. `state` : `exhausted` (budget consommé), `critical` (burn ≥ 14,4 sur 1 h et ≥ 6 sur 6 h), `warning` (burn ≥ 3 sur 6 h), sinon `ok`.
- `GET /api/v1/alert-events?[days&limit&trigger&node]` — alertes déclenchées (30 jours conservés, plus récente d'abord) : `[{id, rule_id, rule_name, trigger, detail, channels, title, body, priority, silenced, fired_at}]` ; `node` filtre sur le nom de passerelle du détail. `silenced=true` : la règle correspondait mais un silence actif (`Automatisation > Alertes > Silences & maintenance`) a bloqué l'envoi — `channels` est alors vide. `POST /api/v1/alert-events/{id}/ack` (acquittement) est réservé aux admins / superadmins.
- `GET /api/v1/prism/slo/config` → `{target}` ; `PUT /api/v1/prism/slo/config` `{target}` (admin, entre 90 et 99.999) — objectif SLO enregistré (réglage `slo.target`, 99.9 par défaut), utilisé par l'écran, `GET /prism/slo` sans `target`, l'outil MCP `get_prism_slo` et l'alerte `slo_burn`.
- `GET /api/v1/prism/live-ips` renvoie en plus `city`, `lat`, `lon` (0/0 tant que l'IP n'est pas localisée).
- *(Admin `0.171.0`, Edge `0.81.0`)* Les classements (`paths`, `ips`, `agents`, `referrers`, `tls-fingerprints`), `unique-ips` (et `unique_ips` de `kpis` et `compare`), `geo`, `geo/points` et `live-ips` sont calculés à partir de la base de logs de chaque passerelle : les classements sont exacts (algorithme de seuil), le nombre d'IP uniques est l'union des IP de chaque passerelle (exact jusqu'à 2 000 adresses, estimé à environ 1 % au-delà). *(Admin `0.176.0`)* L'Admin ne garde plus de copie des accès ordinaires : le paramètre `source=admin` et le repli sur ses lignes n'existent plus. Sans passerelle enregistrée, les listes sont vides et les totaux nuls ; des passerelles d'avant `0.81.0` (route absente) donnent une erreur `502` explicite, pas des chiffres faux. Les KPIs, la courbe, les codes HTTP, le SLO et les erreurs par backend d'une sélection globale se lisent dans les cumuls par minute que les passerelles envoient. Quand des passerelles manquent ou n'ont pas fini leur lecture, la réponse porte les en-têtes `X-Prism-Source: edge`, `X-Prism-Unreachable` (noms séparés par des virgules), `X-Prism-Partial: 1` et `X-Prism-Estimated: 1` ; les réponses en objet (`paths`, `unique-ips`) répètent `partial` et `unreachable` dans le corps, et `unique-ips` porte `estimated`. Les IP du pays et de la carte qui ne sont pas encore dans le cache de géolocalisation y sont ajoutées à la demande. *(Admin `0.173.0`)* `GET /prism/export?format=csv|json|html` lit aussi les passerelles : les 50 000 lignes d'accès les plus récentes de l'ensemble des passerelles, fusionnées par date (le message de chaque ligne est celui que la passerelle compose pour un accès), ou le rapport HTML avec les classements exacts. *(Admin `0.175.1`)* Avec un filtre `ip` ou `path`, `kpis`, `timeline`, `status` et `anomalies` sont aussi calculés par les passerelles (les cumuls par minute ne portent pas ces filtres) ; l'écart des KPIs avec la période précédente applique le même filtre.

### Changement de mot de passe (Admin `0.135.14`)

`POST /api/v1/me/change-password` révoque toutes les sessions (JWT) émises avant l'appel et répond `200 { "token": "…" }` — une session neuve pour l'appelant — quand l'appel est fait avec une session ; avec un jeton API la réponse reste `204`. Même révocation quand un administrateur définit le mot de passe d'un autre compte.

### Inscription d'une clé de sécurité (Admin `0.135.12`)

`POST /api/v1/auth/mfa/webauthn/register/begin` renvoie `{ "options": <PublicKeyCredentialCreationOptions>, "challenge_id": "…" }` ; `POST …/register/finish?challenge=<challenge_id>` consomme ce défi (lié à l'utilisateur, à usage unique, 5 minutes). Les codes de secours se saisissent avec ou sans tirets, en majuscules ou en minuscules.

### Envoi du code à la connexion (Admin `0.136.0`)

`POST /api/v1/auth/mfa/send` `{ "mfa_token": "…", "method": "email|sms|push_ntfy|push_gotify" }` — public, authentifié par le `mfa_token` de `POST /auth/login`. `202` : code émis (6 chiffres, 5 minutes, usage unique) vers le destinataire enregistré à l'activation, à saisir via `POST /auth/mfa/challenge`. `400` : méthode sans code (TOTP, clé de sécurité, codes de secours), absente ou non confirmée ; `401` : `mfa_token` invalide ; `429` : limite d'envois ou second facteur verrouillé ; `502` : envoi impossible (SMTP, fournisseur SMS, canal push).

### Second facteur : envois de codes et canal push (Admin `0.135.17`)

`email/setup`, `sms/setup`, `push/setup` et `push/verify` : 3 envois par compte et par 10 minutes, 60 par heure au total — `429` avec `Retry-After` au-delà. `sms/setup` exige un numéro au format international (`^\+[1-9][0-9]{7,14}$`), `400` sinon. `push/setup` : `url` en http(s) ne visant ni le lien local ni les métadonnées du cloud (adresses privées permises), `topic` ntfy en `[A-Za-z0-9_-]{1,64}`, `400` sinon ; `502 push injoignable` sans détail. `email/verify` et `sms/verify` : 5 codes faux verrouillent 15 minutes (`429`), sans effet sur la connexion.

### Second facteur : ce que la réponse ne contient plus, clés clonées (Admin `0.135.16`)

`methods` (réponse `202` de `POST /api/v1/auth/login` et `GET /api/v1/auth/mfa`) ne liste que `id`, `user_id`, `method`, `enabled`, `verified`. Le champ `config` — qui contenait le secret TOTP — n'est plus jamais renvoyé : avant cette version, le mot de passe seul donnait de quoi calculer le code. Le compteur de signatures d'une clé de sécurité est enregistré à chaque connexion ; un compteur qui n'augmente pas (clé clonée) est refusé avec `401`, comme un mauvais code.

### Second facteur à la connexion (Admin `0.135.11`)

**Appareil de confiance** (Admin `0.146.2`) : avec `"trust_device": true` (et `device_name` facultatif), `POST /api/v1/auth/mfa/challenge` et `/api/v1/auth/mfa/webauthn/login/finish` enregistrent l'appareil pour 7 jours et posent le cookie `_gpx_device` (HttpOnly, SameSite=Strict, `Path=/api/v1/auth`, Secure en HTTPS ou derrière un proxy qui envoie `X-Forwarded-Proto: https`). `POST /api/v1/auth/login` le lit (ou l'en-tête `X-Device-Token`) et délivre alors directement le JWT, sans second facteur. Le token n'est plus renvoyé dans le corps (`device_token`) ; WebAuthn ignorait `trust_device`. L'appareil est conservé en base : il survit à un redémarrage de l'Admin. `GET /api/v1/auth/mfa/trusted-devices` les liste, `DELETE /api/v1/auth/mfa/trusted-devices/{id}` en révoque un.

Gestion (Admin `0.147.1`), pour l'utilisateur courant uniquement (JWT complet) :

| Méthode | Route | Réponse |
|---|---|---|
| `GET` | `/api/v1/auth/mfa/trusted-devices` | `200` — `[{ "id", "name", "expires_at", "created_at" }]` (plus récent d'abord, expirés inclus ; `null` si aucun) |
| `DELETE` | `/api/v1/auth/mfa/trusted-devices/{id}` | `204` — sans effet sur l'appareil d'un autre utilisateur |
| `DELETE` | `/api/v1/auth/mfa/trusted-devices` | `204` — révoque tous les appareils de l'utilisateur |

Révocation automatique de tous les appareils d'un utilisateur : `POST /api/v1/me/change-password`, `PUT /api/v1/users/{id}/password`, `PUT /api/v1/users/{id}` avec `password`, et `DELETE /api/v1/auth/mfa/{method}` quand plus aucune méthode vérifiée ne reste (MFA désactivée).

`POST /api/v1/auth/mfa/challenge` et `/api/v1/auth/mfa/webauthn/login/finish` : 5 échecs sur un compte (toutes méthodes confondues) le verrouillent 15 minutes — réponse `429` avec `Retry-After`, y compris pour le bon code. Un code TOTP accepté ne peut plus être rejoué dans sa fenêtre de validité.

### SMTP (Admin `0.135.4`)

`PUT /api/v1/settings/smtp` : `password` omis ou `••••••••` conserve la valeur enregistrée ; `"password": ""` l'efface.

### SMS MFA (Admin `0.135.3`)

`GET /api/v1/settings/mfa/sms` renvoie `api_key` et `api_secret` sous la forme `••••••••`. `PUT` conserve la valeur enregistrée quand un de ces champs est masqué ou omis.

### Secrets d'une route (Admin `0.135.2`)

Les lectures de route (`GET /api/v1/proxies`, `/{id}`, réponses de `POST`/`PUT`, `revisions/diff`, historique de versions, MCP `get_proxy`) remplacent par `••••••••` les secrets : `client_secret`, `session_secret`, `bind_password`, `challenge_secret`, `challenge_provider_secret`, `key_pem`, `secret` (URL signées), `password` (Basic), `bypass_header`, en-têtes `Authorization`/`Proxy-Authorization`/`X-Api-Key` et champs secrets de la configuration d'un plugin. `PUT` et `POST /proxies/dry-run` rétablissent la valeur de la production quand le masque est renvoyé ; un masque sans valeur d'origine est refusé (`400`).

### Identifiants DNS d'un domaine (Admin `0.135.1`)

`GET /api/v1/domains` et `GET /api/v1/domains/{id}` renvoient `dns_credentials` avec les champs secrets du fournisseur sous la forme `••••••••` (`api_token`, `secret_access_key`…). `PUT` conserve la valeur enregistrée quand un secret est omis ou renvoyé masqué (et quand `dns_credentials` est omis, si le fournisseur est inchangé) ; changer de fournisseur ne reprend aucun secret de l'ancien.
