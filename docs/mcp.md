# MCP Goproxify — Référence des outils et ressources

Le serveur MCP (Model Context Protocol) de Goproxify expose l'Administration à tout client compatible MCP (Claude Desktop, Claude Code, etc.). Il permet à un LLM de lire l'état de l'infrastructure et d'agir dessus sans passer par l'interface web.

**Endpoint :** `https://<admin-host>:9443/mcp`  
**Protocole :** MCP `2025-03-26`, JSON-RPC 2.0 over HTTP  
**Authentification :** `Authorization: Bearer <gpx_pat_…>` — token API utilisateur (PAT) créé depuis **Paramètres → Mes tokens API**. Le JWT de session UI n’est **pas** accepté sur `/mcp`.  
**SSE (streaming) :** `GET /mcp/sse` — keepalive toutes les 15 s

Les scopes du PAT (`proxies:read`, `nodes:read`, …) bornent les outils MCP ; l’autorisation effective est toujours l’intersection avec les droits actuels du compte.

**Allowlist IP :** la page **Accès → Accès MCP** (`/mcp-access`, admin uniquement) permet de restreindre `/mcp` à une liste d'IP/CIDR sources (`GET`/`PUT /api/v1/mcp-access/allowed-ips`). Liste vide (défaut) = pas de restriction. Le contrôle s'applique **avant** l'authentification PAT — une requête hors liste reçoit un 403 immédiat, PAT valide ou non.

**Vue d'ensemble admin :** la même page affiche la liste des utilisateurs porteurs d'un PAT actif sur l'instance (tous porteurs confondus) avec leurs scopes, ainsi que le catalogue de scopes et les outils MCP que chacun couvre, pour référence. C'est une vue en lecture seule côté scopes — la création et le choix des scopes d'un PAT restent self-service depuis **Paramètres → Mes tokens API**.

### Contrôle d'accès des outils

Chaque outil exige un scope, le même que sa route REST équivalente. Les outils marqués † s'appuient sur une route REST réservée aux administrateurs : ils exigent en plus le rôle `admin` ou `superadmin`, comme l'API. Une ressource (`resources/read`) applique les mêmes règles que l'outil qu'elle expose. Un outil sans scope déclaré est refusé : aucun outil n'est appelable sans contrôle (depuis Admin `0.70.0` ; 56 outils n'étaient auparavant soumis à aucun scope).

| Scope | Outils |
|-------|--------|
| `proxies:read` | `list_proxies`, `get_proxy`, `get_proxy_labels`, `get_discovered_container`, `list_orphan_proxies` |
| `proxies:write` | `create_proxy`, `convert_discovered_container`, `set_container_route_enabled`, `update_proxy`, `set_proxy_enabled`, `purge_proxy_cache` |
| `proxies:delete` | `delete_proxy` |
| `nodes:read` | `list_nodes`, `list_declared_nodes`, `list_hosts`, `get_topology_live`, `list_agents` †, `get_architecture` †, `list_discovery_sources` † |
| `nodes:write` | `create_declared_node`, `delete_declared_node`, `create_bootstrap_ticket`, `create_host_join_ticket`, `accept_node`, `reject_node`, `approve_agent` †, `revoke_agent` † |
| `alerts:read` | `list_alerts`, `list_alert_events`, `list_alert_channels`, `list_alert_channel_types`, `list_alert_rules` |
| `alerts:write` | `create_alert_channel`, `delete_alert_channel`, `create_alert_rule`, `delete_alert_rule`, `ack_alert_event` |
| `metrics:read` | `get_metrics`, `get_proxy_metrics` |
| `backups:read` | `list_backups` † |
| `users:read` | `list_users` † |
| `teams:read` | `list_teams` † |
| `snippets:read` | `list_snippets`, `list_detector_types` |
| `snippets:write` | `create_snippet`, `delete_snippet` |
| `domains:read` | `list_domains` |
| `domains:write` | `create_domain`, `renew_domain`, `rotate_cert` |
| `certs:read` | `list_certs`, `get_cert_status`, `list_cert_deploy_targets`, `list_cert_deploy_types`, `list_internal_cas` †, `list_internal_certs` †, `get_ech_status` †, `list_dns_providers` †, `list_dns_provider_types` † |
| `certs:write` | `obtain_cert`, `import_cert`, `trigger_cert_deploy`, `create_internal_ca` †, `issue_internal_cert` †, `revoke_internal_cert` † |
| `logs:read` | `list_logs`, `get_siem_status` †, `get_prism_anomalies`, `get_prism_geo`, `get_prism_tls_fingerprints`, `get_prism_slo`, `simulate_ephor_config` †, `get_ephor_references` †, `suggest_ephor_thresholds` †, `trace_ip` †, `preview_security_ban` †, `preview_asn_ban` † |
| `audit:read` | `get_audit_log`, `list_ip_profiles`, `get_security_overview` †, `list_security_bans` †, `list_security_engine_types` †, `get_waf_activity` †, `list_plugins` †, `lookup_asn` †, `list_ban_whitelist` †, `list_security_threats` †, `list_security_cves` †, `get_proxy_surface` †, `get_app_inventory` †, `get_entry_rejections` †, `get_traffic_reference` †, `get_proxy_surface_proposals` †, `get_proxy_surface_openapi` †, `get_proxy_surface_suggestions` †, `list_auth_providers` †, `list_auth_provider_types` †, `list_flows` †, `get_flow` †, `list_flow_versions` †, `list_flow_runs` †, `get_flow_run` †, `get_automation_catalog` †, `list_flow_templates` †, `list_silences` †, `export_automation` † |
| `security:write` | `create_ip_profile`, `delete_ip_profile`, `reset_proxy_surface` †, `enforce_proxy_surface` †, `accept_proxy_surface_suggestions` †, `relax_proxy_surface` †, `create_security_ban` †, `delete_security_ban` †, `ban_ip` †, `unban_ip` †, `add_ban_whitelist` †, `remove_ban_whitelist` †, `import_security_bans` †, `ban_asn` †, `unban_asn` †, `create_auth_provider` †, `delete_auth_provider` †, `create_flow` †, `update_flow` †, `set_flow_enabled` †, `delete_flow` †, `run_flow` †, `simulate_flow` †, `restore_flow_version` †, `detach_flow` †, `update_flow_params` †, `decide_flow_run` †, `cancel_flow_run` †, `replay_flow_run` †, `install_flow_template` †, `create_silence` †, `delete_silence` †, `import_automation` † |
| `portal:read` / `portal:write` | outils Access (`*_portal_*`, `push_portal`) † — voir [GoProxify Access](#goproxify-access-portail) |

Les scopes d'écriture (`proxies:delete`, `nodes:write`, `alerts:write`, `domains:write`, `certs:write`, `security:write`, `import:write`) ainsi que `users:read`, `teams:read` et `portal:*` sont réservés aux rôles admin et superadmin (`proxies:write` et `snippets:write` sont aussi ouverts à un compte `user` qui a un droit d'écriture). Un refus est renvoyé comme erreur d'outil (`isError: true`) :

- `Erreur: scope insuffisant: <scope>` : le PAT n'a pas ce scope, ou le compte ne peut plus le détenir ;
- `Erreur: accès réservé aux administrateurs` : outil † appelé par un compte `user` ;
- `Erreur: outil sans scope déclaré: <outil>` : outil exposé sans entrée dans la table outil → scope (bug serveur, refusé par sécurité).

`tools/list` n'annonce que les outils que l'appelant peut appeler (mêmes contrôles : scope du PAT ∩ droits du compte, rôle admin pour les outils †). Un PAT limité à quelques scopes réduit donc d'autant la liste envoyée au modèle.

### Groupes d'outils (`?toolsets=`)

La liste complète (plus de 150 outils) pèse environ 17 000 tokens, ce qui dépasse la fenêtre d'un modèle local à petit contexte (llama.cpp, Ollama, LM Studio à 8k : erreur `exceed_context_size_error`). Le paramètre `toolsets` de l'URL restreint `tools/list` à certains groupes :

```
https://<admin-host>:9443/mcp?toolsets=proxies,observability
```

| Groupe | Contenu | Taille approx. |
|--------|---------|----------------|
| `proxies` | routes proxy, purge du cache | ~850 tokens |
| `nodes` | passerelles, Agents, nœuds déclarés, topologie | ~1 200 |
| `alerts` | règles, canaux, événements d'alerte | ~1 100 |
| `observability` | métriques, logs, Prism (anomalies, géo, empreintes TLS, SLO) | ~1 200 |
| `domains` | domaines, renouvellement | ~300 |
| `certs` | certificats, déploiements, CA interne, ECH, fournisseurs DNS | ~1 300 |
| `security` | bans, ASN, liste blanche, profils IP, fournisseurs d'auth, menaces, CVE, plugins, simulation Ephor, `trace_ip` | ~4 500 |
| `automation` | flux, exécutions, modèles, silences, import/export | ~2 600 |
| `snippets` | snippets, types de détecteurs | ~300 |
| `portal` | GoProxify Access | ~3 900 |
| `admin` | sauvegardes, utilisateurs, équipes, journal d'audit | ~200 |

Les noms sont séparés par des virgules, sans tenir compte de la casse ; paramètre absent = tous les groupes. Un nom inconnu renvoie une erreur JSON-RPC `-32602` qui liste les groupes disponibles. Avec le transport SSE, le paramètre posé sur `GET /mcp/sse?toolsets=…` est reporté dans l'URL d'envoi annoncée au client. Le filtre ne porte que sur la liste : il réduit ce que le modèle voit, il ne restreint pas les droits (`tools/call` d'un outil hors groupe reste soumis aux seuls scopes). Pour restreindre les droits, limiter les scopes du PAT.

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

Liste toutes les routes proxy : celles gérées depuis l'Admin (`source: "managed"`), les proxies implicites générés par GoProxify — portail Access, délégations — dont seule la surcouche est modifiable (`source: "implicit"`) et celles découvertes par les labels des conteneurs (`source: "docker"`, `"k8s"`…, `read_only: true`, avec `aliases`, `backends`, `edge`, `agent`, `inactive` / `state` (conteneur arrêté, en pause ou qui redémarre : sans route ni backend, non convertible) et `shadowed_by`, l'ID du proxy configuré qui sert l'hôte à la place de la route des labels).

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
    "tls": true,
    "source": "managed"
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

### `get_proxy_labels`

Donne les labels qui reproduisent un proxy : de quoi le déclarer sur un conteneur Docker, une Stack Portainer ou un Service Kubernetes. Les secrets (valeur d'un en-tête `Authorization`, clé de plugin sensible…) ne sortent jamais : ils deviennent des variables `${GPX_…}` à renseigner. `unsupported` liste les réglages du proxy qu'aucun label ne porte, ou qu'il porte en partie. Refusé pour un proxy implicite (généré par GoProxify).

| Paramètre | Type   | Requis | Description |
|-----------|--------|--------|-------------|
| `id`      | string | ✓      | ID, nom ou domaine du proxy |
| `format`  | string | —      | `compose`, `portainer` (avec `stack.env`), `portainer_inline` (sans), `docker_run`, `kubernetes` ; omis : tous |

**Réponse :** avec `format`, `{ format, text, env, unsupported }` ; sans, `{ labels, env, unsupported, formats }`.

---

### `get_discovered_container`

Détail d'une route découverte par les labels d'un conteneur : config servie par la passerelle (secrets masqués), labels qui la reproduisent, bilan de sécurité (score, contrôles, manques parmi TLS / WAF / rate limit) et **labels corrigés** avec le modèle de sécurité appliqué (un snippet de l'Admin du bon type s'il existe, sinon WAF en blocage et 100 req/s). Même contenu que `GET /api/v1/discovered-containers/detail`. `list_proxies` ajoute `edge_label` et `group` aux routes découvertes ; `edge` n'est plus requis quand tous les membres qui annoncent la route sont du même groupe HA.

| Paramètre | Type   | Requis | Description |
|-----------|--------|--------|-------------|
| `id`      | string | ✓      | `id` de la route découverte (`list_proxies`) ou son domaine |
| `edge`    | string | —      | Nom de la passerelle, si plusieurs annoncent la même route |
| `format`  | string | —      | `compose`, `portainer`, `portainer_inline`, `docker_run`, `kubernetes` : ne garde que ce format (défaut : tous) |

**Réponse :** `{ container, config, labels, fixed_labels, audit }` (`fixed_labels` absent quand rien ne manque).

---

### `list_orphan_proxies`

Proxys créés par `convert_discovered_container` dont le conteneur d'origine n'est plus annoncé par sa passerelle. Une passerelle injoignable n'en fait déclarer aucun.

**Paramètres :** aucun — **Réponse :** `[{ proxy_id, host, enabled, origin: { id, edge } }]`.

---

### `convert_discovered_container`

Convertit une route découverte par les labels d'un conteneur (`list_proxies`, `source` `docker`, `k8s`…) en proxy configuré modifiable, avec sa configuration actuelle (hôte, alias, backends, TLS, sécurité, timeouts…). Le proxy prend la place de la route des labels sur son hôte ; désactivé ou supprimé, il la lui rend. Les backends doivent appartenir à l'allowlist de destinations MCP, comme pour `create_proxy`.

| Paramètre | Type   | Requis | Description |
|-----------|--------|--------|-------------|
| `id`      | string | ✓      | `id` de la route découverte (`list_proxies`) ou son domaine |
| `edge`    | string | —      | Nom de la passerelle, si plusieurs annoncent la même route |

**Réponse :** `{ id, host, backends, converted_from }`. Refusé si la route est déjà remplacée par un proxy.

---

### `set_container_route_enabled`

Active ou désactive la route issue des labels d'un conteneur (Docker, Portainer, Podman, Kubernetes, annuaires) sans toucher au conteneur. Désactivée, la route ne sert plus de trafic sur aucune passerelle mais reste listée (`list_proxies` : `enabled: false`) pour être réactivée. L'interrupteur s'applique à l'hôte, donc à tout le pool de conteneurs derrière lui. Un proxy configuré se gère avec `set_proxy_enabled`. Droit d'écriture sur le domaine requis ; la désactivation d'un hôte qu'aucune passerelle n'annonce est refusée.

| Paramètre | Type    | Requis | Description |
|-----------|---------|--------|-------------|
| `host`    | string  | ✓      | Domaine de la route découverte (`host` de `list_proxies`) |
| `enabled` | boolean | ✓      | `true` = activer, `false` = désactiver |

**Réponse :** `{ host, enabled }`.

---

### `create_proxy`

Crée une nouvelle route proxy (HTTP, TCP ou UDP). Le `backend` doit appartenir à l'allowlist de destinations MCP (`GET/PUT /api/v1/mcp-access/allowed-backends` ; défaut : réseaux privés et suffixes `*.internal`/`*.local`/`*.svc`) — même règle pour `update_proxy`.

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
| `options`     | object  | —      | Options avancées à poser (`null` = retirer) : `split`, `maintenance`, `signed_url`, `graphql`, `bandwidth`, `redact_json`, `html_inject`, `hedge`, `static`, `request_schema`, `openapi`, `grpc_transcode`, `surface`, `max_body_size`, `ip_filter`, `geo_ip`, `cors`, `waf`, `grpc_web`, `rate_limit`, `conditions` ; clé inconnue refusée |

**Réponse :** `{ "id", "name", "enabled", "config" }`

---

### `set_proxy_enabled`

Active ou désactive un proxy sans modifier sa configuration.

| Paramètre | Type    | Requis | Description                         |
|-----------|---------|--------|-------------------------------------|
| `id`      | string  | ✓      | ID, nom ou domaine                  |
| `enabled` | boolean | ✓      | `true` = activer, `false` = couper  |

---

### `purge_proxy_cache`

Vide le cache HTTP d'un proxy sur toutes les passerelles : tout le cache, ou seulement certaines entrées.

| Paramètre | Type   | Requis | Description |
|-----------|--------|--------|-------------|
| `id`      | string | ✓      | ID, nom ou domaine |
| `tags`    | string |        | Tags à purger (`Cache-Tag` / `Surrogate-Key` de la réponse), séparés par des virgules |
| `paths`   | string |        | Chemins à purger (avec ou sans query ; suffixe `*` = préfixe), séparés par des virgules |

**Réponse :** `{ "purged": 3 }`

---

### `delete_proxy`

Supprime un proxy par son ID.

| Paramètre | Type   | Requis | Description              |
|-----------|--------|--------|--------------------------|
| `id`      | string | ✓      | ID du proxy à supprimer  |

**Réponse :** `{ "deleted": "px_01abc" }`

---

### `list_nodes`

Liste les nœuds passerelle et Agent avec leurs métriques en temps réel.

**Paramètres :** aucun

**Réponse exemple :**
```json
[
  {
    "id": "nd_01",
    "node_name": "edge-eu-west",
    "role": "edge",
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
**Scope :** `nodes:read` + rôle admin

**Réponse exemple :**
```json
[
  { "id": "agent-1", "name": "agent-1", "version": "0.3.0", "status": "pending", "seen_at": "2026-08-08T10:00:00Z" }
]
```

---

### `list_discovery_sources`

Sources de découverte de l'Agent — Docker/Podman, Portainer, Kubernetes, Consul, Nomad, etcd, Amazon ECS — avec leurs champs de configuration (clé, `secret`, `required`) pour la section `sources.<type>` de `agent.json`. Même source que `GET /api/v1/discovery-sources` et `goproxify agent-mgmt sources`.

_Aucun paramètre._

**Scope :** `nodes:read` + rôle admin

---

### `approve_agent`

Approuve un Agent en attente (broadcast `approve_agent` aux passerelles).

| Paramètre | Type   | Requis | Description        |
|-----------|--------|--------|--------------------|
| `id`      | string | ✓      | ID de l'Agent      |

**Scope :** `nodes:write` + rôle admin

---

### `revoke_agent`

Révoque un Agent (ferme la session WS et invalide le HMAC).

| Paramètre | Type   | Requis | Description        |
|-----------|--------|--------|--------------------|
| `id`      | string | ✓      | ID de l'Agent      |

**Scope :** `nodes:write` + rôle admin

---

### `list_alert_events`

Alertes déclenchées (30 jours conservés), la plus récente d'abord. Scope : `alerts:read`.

| Paramètre | Type   | Requis | Description                                                  |
|-----------|--------|--------|--------------------------------------------------------------|
| `days`    | number | —      | Fenêtre en jours (défaut 30, max 30)                         |
| `trigger` | string | —      | Déclencheur, ex. `slo_burn`, `high_error_rate`, `node_offline` |
| `node`    | string | —      | Nom de passerelle (lu dans le détail de l'événement)         |
| `limit`   | number | —      | Événements max (défaut 100, max 500)                         |

Chaque événement : `id`, `rule_id`, `rule_name`, `trigger`, `detail`, `channels`, `title`, `body`, `priority`, `silenced`, `acked`, `acked_by`, `acked_at`, `fired_at`. `silenced: true` : bloqué par un silence actif (`list_silences`), `channels` vide. `acked: true` : accusé de réception (`ack_alert_event`), les paliers d'escalade restants ne renotifient plus.

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

Retourne les KPIs de trafic des dernières 24 heures. Les requêtes, erreurs et latence viennent des cumuls par minute ; les IP uniques sont l'union des IP de chaque passerelle (`unique_ips_estimated: true` quand le nombre dépasse 2 000 et n'est plus qu'une estimation à environ 1 %).

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

### `get_proxy_metrics`

Retourne, par host, le débit, le taux d'erreurs 5xx et le p95 du dernier relevé, avec la série de
débit récente. L'Admin relève les passerelles toutes les 10 s et garde 1 h d'historique en mémoire
(vide juste après un démarrage de l'Admin). Scope requis : `metrics:read`.

| Paramètre | Type   | Requis | Description                                              |
|-----------|--------|--------|----------------------------------------------------------|
| `host`    | string | —      | Host à filtrer (laisser vide = tous)                     |
| `points`  | number | —      | Points de la série, un toutes les 10 s (défaut 60, max 360) |

**Réponse exemple :**
```json
{
  "interval_s": 10,
  "sampled_at": "2026-09-26T13:11:37+02:00",
  "proxies": [
    { "host": "myapp.example.fr", "requests_per_second": 3.8, "error_rate": 0.002, "p95_ms": 9.3, "series": [3.7, 4.0, 3.8] }
  ]
}
```

---

### `list_backups`

Liste les 20 derniers snapshots de sauvegarde.

**Paramètres :** aucun  
**Scope :** `backups:read` + rôle admin

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

### `list_detector_types`

Types de détecteur par route (`ip_filter`, `geo_ip`, `bot`, `waf`) avec leurs champs de configuration (secrets, requis). Même source que `GET /api/v1/detector-types`. `create_snippet` valide la configuration de ces types avec le même manifeste et refuse un type de snippet inconnu. Scope `snippets:read`.

**Paramètres :** aucun

---

### `list_plugins`

Plugins WebAssembly installés (manifeste, empreinte, taille). Lecture seule : installer un plugin passe par l'API ou `goproxify plugin`. Scope `audit:read` (rôle admin).

**Paramètres :** aucun

---

### `list_security_engine_types`

Moteurs de sécurité globaux (Ephor, Seuils multi-passerelles, CrowdSec, WAF — interrupteur maître par passerelle) avec les champs de leur configuration. Même source que `GET /api/v1/security/engine-types`. Scope `audit:read` (rôle admin).

**Paramètres :** aucun

### `get_waf_activity`

Activité du WAF sur les dernières heures : requêtes signalées (`blocked` refusées en 403, `detected` passées en mode détection), 8 règles les plus déclenchées (`top_rules`, identifiants de règle ou nom d'un plugin de détection) et 8 domaines les plus visés (`top_domains`). Utile pour repérer des faux positifs avant de couper le WAF d'une passerelle (`PUT /api/v1/security/waf-config`, CLI `goproxify security waf-engine set`). Même source que `GET /api/v1/security/waf-activity`. Scope `audit:read` (rôle admin), lecture seule.

| Paramètre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `hours`   | number | | Fenêtre en heures (défaut 24, max 168) |
| `edge`    | string | | ID du jeton ou nom de la passerelle (défaut : toutes) |

`truncated: true` : plus de 50 000 requêtes signalées dans la fenêtre, seules les plus récentes sont comptées.

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
    "description": "Limite l'API publique",
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
    "edge_id": "nd_01",
    "dns_provider": "cloudflare",
    "cert_method": "dns",
    "delegation_mode": "passthrough",
    "cert_expires_at": "2026-11-01T00:00:00Z",
    "created_at": "2026-01-01T00:00:00Z"
  }
]
```

`delegation_mode` : `passthrough` (tunnel TLS) ou `terminate` (TLS sur la passerelle d'entrée + proxy HTTP(S)). Voir [delegation.md](delegation.md).

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

Retourne les 100 derniers logs d'accès, filtrables par domaine, niveau, `request_id` ou empreinte TLS. Chaque entrée porte `tls_ja4` / `tls_ja3` quand la passerelle a terminé le TLS.

| Paramètre    | Type   | Requis | Description                                                        |
|--------------|--------|--------|--------------------------------------------------------------------|
| `domain`     | string | —      | Filtrer par domaine proxy                                          |
| `level`      | string | —      | Filtrer par niveau : `info`, `warn`, `error`                       |
| `request_id` | string | —      | Corrélation exacte : retourne tous les logs portant cet identifiant|
| `tls_ja4`    | string | —      | Filtrer par empreinte TLS JA4 : retrouver un même outil ou botnet quelle que soit son IP |
| `tls_ja3`    | string | —      | Filtrer par empreinte TLS JA3 (MD5)                                |
| `source`     | string | —      | `admin` (défaut) : copie des logs gardée par l'Admin, 100 entrées max ; `edge` : base de logs de chaque passerelle, fusionnée par l'Admin avec ses propres logs, 500 entrées par page, du plus récent au plus ancien (Admin `0.169.0`) |
| `node`       | string | —      | Avec `source=edge` : nom d'une seule passerelle                      |
| `cursor`     | string | —      | Avec `source=edge` : jeton `cursor` de la page précédente, pour la page suivante |

Avec `source=edge`, la réponse est un objet `{entries, has_more, cursor, partial, unreachable, page_size}` au lieu d'un tableau : `partial` signale qu'une passerelle a atteint son délai (affiner le filtre), `unreachable` liste les passerelles qui n'ont pas répondu (leurs lignes manquent). Chaque entrée porte `node_name` et `node_id`.

**Réponse exemple :**
```json
[
  {
    "ts": "2026-09-12T10:01:05Z",
    "level": "info",
    "component": "edge",
    "domain": "app.example.fr",
    "method": "GET",
    "path": "/api/users",
    "status": 200,
    "ip": "1.2.3.4",
    "latency_ms": 38,
    "request_id": "req_01jx4z8k",
    "message": ""
  }
]
```

Le champ `request_id` est présent quand le proxy cible a l'option **Injection request_id** activée. Utilisez-le comme filtre pour récupérer l'ensemble des entrées (Admin + Passerelle) d'une même requête HTTP.

Depuis Admin `0.71.2`, `ip_truncated: true` signale une IP tronquée par la passerelle (anonymisation ou pseudonymisation RGPD : `x.x.x.0`, préfixe /48 `2a01:e0a:1::`). Cette valeur regroupe plusieurs clients : `ban_ip` dessus ne bannirait personne (IPv4) ou pas le bon client (IPv6). Le champ est absent pour une IP complète.

---

### `get_siem_status`

*(Admin `0.178.0`, Edge `0.87.0`, [ADR 0012](adr/0012-logs-proprietaire-edge.md) ; scope `logs:read`, rôle admin)* Exporteur SIEM des passerelles : la configuration et l'état rapporté par chaque passerelle. Aucun paramètre.

Réponse : `{config, nodes}`. `config` est la configuration enregistrée (`enabled`, `destinations` syslog RFC 5424 sur TCP/TLS, HTTP NDJSON ou OTLP/HTTP JSON, filtres par type, niveau et « sécurité seulement »), dont les valeurs d'en-têtes (jetons) sont masquées. `nodes` liste, par passerelle (`node_name`, `reported_at`, `stale` si elle est muette depuis 90 s), chaque destination avec son `state` (`starting`, `ok`, `retrying`, `stopped`), `delivered`, `lag_sec` (âge de la plus ancienne ligne non livrée), `at_risk` (le retard menace des lignes qui vont être purgées avant livraison), `last_error`. Chaque passerelle exporte seule, avec son propre curseur, même Admin éteint ; un retard au-delà du seuil de la destination déclenche l'alerte `siem_export_lag`. La configuration se modifie par `PUT /api/v1/logs/siem` ou `goproxify logs siem set`, pas par MCP.

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
    "action": "update",
    "resource": "proxy:px_01abc",
    "detail": "app.example.com",
    "severity": "info",
    "created_at": "2026-08-02T09:55:00Z"
  }
]
```

---

### `get_security_overview`

Compteurs sécurité : bans actifs, menaces CrowdSec, CVE ouvertes, certificats expirant sous 30 jours.

**Paramètres :** aucun  
**Scope :** `audit:read` + rôle admin (comme `GET /api/v1/security`)

---

### `list_security_bans`

Liste les bans IP (Seuils multi-passerelles, CrowdSec, Ephor, plugins de détection comme Coraza, natif).

| Paramètre      | Type    | Requis | Description                                      |
|----------------|---------|--------|--------------------------------------------------|
| `ip`           | string  | —      | Filtrer par IP (sous-chaîne)                     |
| `source`       | string  | —      | `native`, `fleet`, `crowdsec`, `threat`, `plugin:<nom>` (ex. `plugin:coraza`) |
| `active_only`  | boolean | —      | Uniquement les bans non expirés                  |
| `edge`         | string  | —      | Passerelle (nom du nœud ou id du token) : ses bans et les bans globaux |

Chaque ban renvoyé porte `edge_name` (passerelle d'origine, vide = ban global). Un ban automatique d'Ephor ou du WAF porte aussi `signals` : la liste des signaux qui l'ont causé, chacun avec `name`, `points` et `value` (ce qui l'a déclenché : chemin, User-Agent, empreinte…), dont la somme explique la décision. Absent des autres sources. `trace_ip` les renvoie aussi, sur les bans en cours et sur les étapes de ban. Un ban automatique porte de même `user_agent` (le dernier User-Agent vu pour l'IP au moment du ban), absent des bans manuels ou importés.

**Scope :** `audit:read` + rôle admin

---

### `create_security_ban`

Crée un ban IP natif (**permanent** si `expires_at` omis) et pousse les bans aux passerelles.

| Paramètre     | Type   | Requis | Description                         |
|---------------|--------|--------|-------------------------------------|
| `ip`          | string | ✓      | Adresse IP ou plage CIDR (normalisée ; plus large que /16 IPv4 ou /32 IPv6, ou contenant l'appelant → erreur) |
| `reason`      | string | —      | Motif                               |
| `domain`      | string | —      | Domaine ciblé (vide = global)       |
| `expires_at`  | string | —      | Expiration RFC3339, enregistrée en UTC ; omis = permanent ; date illisible → erreur |
| `scope`       | string | —      | Passerelles qui appliquent le ban : nom d'une passerelle ou `group:<nom>` d'un groupe HA ; omis = toutes ; inconnu → erreur |

**Scope :** `security:write`

---

### `preview_security_ban`

*(Admin `0.172.0`)* Trafic lu dans les bases de logs des passerelles : chiffres exacts, avertissement si une passerelle est injoignable.

Aperçu de l'impact d'un ban IP ou CIDR **avant de le créer**, sans rien modifier : trafic récent de la cible (requêtes bloquées, requêtes réussies qui seraient coupées, adresses distinctes, pays), bans actifs et profils IP qui la recoupent, et avertissements (plage privée, profil allow, déjà couverte, auto-verrouillage). La cible est normalisée comme à la création ; une plage plus large que `/16` (IPv4) ou `/32` (IPv6) est refusée. Même réponse que `GET /api/v1/security/bans/preview`.

| Paramètre | Type   | Requis | Description |
|-----------|--------|--------|-------------|
| `ip`      | string | ✓      | IP ou CIDR (`203.0.113.7`, `198.51.100.0/24`, `2001:db8::/32`) |
| `hours`   | number | —      | Période de trafic analysée en heures (défaut 24, max 168) |

**Scope :** `logs:read` † (lit les logs d'accès, comme `trace_ip`)

---

### `import_security_bans`

Importe une liste d'adresses IP et de CIDR : crée des bans natifs, ou des entrées de la liste blanche avec `target=whitelist`, en une seule opération (une seule poussée vers les passerelles). Formats : texte (une adresse ou un CIDR par ligne, commentaires `#` et `;`, comme les listes publiques FireHOL ou Spamhaus DROP), CSV (le CSV de l'export des bans se réimporte tel quel) ou JSON. Chaque entrée est validée comme pour `create_security_ban` ; doublons, cibles déjà couvertes et plages privées sont ignorés. Avec `dry_run`, rien n'est créé. Même rapport que `POST /api/v1/security/bans/import`.

| Paramètre    | Type    | Requis | Description |
|--------------|---------|--------|-------------|
| `content`    | string  | ✓      | Contenu de la liste (2 Mo, 10 000 entrées au plus) |
| `format`     | string  | —      | `auto` (défaut), `text`, `csv` ou `json` |
| `target`     | string  | —      | `bans` (défaut) ou `whitelist` |
| `reason`     | string  | —      | Motif des bans (ou commentaire des entrées) sans motif propre ; défaut `import` |
| `domain`     | string  | —      | Domaine ciblé par les bans sans domaine propre (vide = global) |
| `expires_at` | string  | —      | Expiration RFC3339 des bans sans expiration propre ; omis = permanents |
| `scope`      | string  | —      | Passerelles qui appliquent les bans : nom d'une passerelle ou `group:<nom>` ; omis = toutes |
| `dry_run`    | boolean | —      | `true` : analyser sans rien créer |

**Scope :** `security:write` †  
**Réponse :** `{ "dry_run", "target", "format", "total", "created", "addresses", "skipped": [{ "line", "value", "reason" }], "skipped_count", "rejected": […], "rejected_count", "sample": […] }`

---

### `lookup_asn`

Cherche un système autonome (ASN) par numéro (`AS16276`), par adresse IP (l'ASN qui l'annonce) ou par nom. Retourne le numéro, le nom, le pays, le nombre de plages annoncées, d'adresses IPv4 et de plages IPv6, et le nombre de plages déjà bannies. Données publiques ip2asn, installées sur l'Admin au premier usage.

| Paramètre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `q` | string | ✓ | Numéro d'ASN, adresse IP ou nom |

**Scope :** `audit:read` †

---

### `preview_asn_ban`

*(Admin `0.172.0`)* Trafic de l'ASN lu dans les bases de logs des passerelles : chiffres exacts, avertissement si une passerelle est injoignable.

Aperçu de l'impact d'un ban d'ASN, sans rien modifier : plages bannies, ignorées ou rejetées, trafic récent de l'ASN (dont les requêtes réussies qui seraient coupées) et avertissements (l'ASN contient l'appelant, plages trop larges, aucune requête récente).

| Paramètre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `asn` | string | ✓ | Numéro d'ASN (`AS16276` ou `16276`) |
| `hours` | number | — | Période de trafic analysée (défaut 24, max 168) |

**Scope :** `logs:read` †

---

### `ban_asn`

Bannit un ASN : un ban par plage qu'il annonce, en une opération et un seul envoi aux passerelles. Plages plus larges que `/16` (IPv4) découpées ; plages déjà bannies, en liste blanche ou privées ignorées ; refusé si l'ASN contient l'adresse de l'appelant. Instantané des plages annoncées : relancer l'outil ajoute les nouvelles. Mesurer l'impact avant avec `preview_asn_ban`.

| Paramètre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `asn` | string | ✓ | Numéro d'ASN (`AS16276` ou `16276`) |
| `reason` | string | — | Motif ; défaut `AS<numéro> <nom>` |
| `domain` | string | — | Domaine ciblé (vide = global) |
| `expires_at` | string | — | Expiration RFC3339 ; omis = permanent |
| `scope` | string | — | Nom d'une passerelle ou `group:<nom>` ; omis = toutes |
| `dry_run` | boolean | — | `true` : simuler sans rien créer |

**Scope :** `security:write` †

---

### `unban_asn`

Lève les bans créés pour un ASN (toutes ses plages) sur les passerelles, en un seul envoi. Ne touche pas aux autres bans.

| Paramètre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `asn` | string | ✓ | Numéro d'ASN (`AS16276` ou `16276`) |

**Scope :** `security:write` †

---

### `list_ban_whitelist`

Liste la **liste blanche des bans** : adresses et plages qu'aucun ban n'atteint (manuel, Seuils, CrowdSec, Ephor, règles) et que Ephor n'évalue pas. Aucun paramètre. Réponse : `[{ "value", "comment", "added_by", "added_at" }]`.

**Scope :** `audit:read` †

---

### `add_ban_whitelist`

Ajoute une adresse IP ou une plage CIDR à la liste blanche et l'envoie aux passerelles. La cible est normalisée (`203.0.113.7/24` → `203.0.113.0/24`) ; plus large que `/16` (IPv4) ou `/32` (IPv6) → erreur. Si une entrée existante la couvre déjà : `{ "added": false, "covered_by": "…" }` ; les entrées plus précises sont retirées. Les bans existants ne sont pas supprimés : ils cessent de s'appliquer à ces adresses. Voir [Liste blanche des bans](security.md#liste-blanche-des-bans).

| Paramètre | Type   | Requis | Description |
|-----------|--------|--------|-------------|
| `ip`      | string | ✓      | Adresse IP ou plage CIDR à exempter |
| `comment` | string | —      | Pourquoi (ex. « bureau Paris ») |

**Scope :** `security:write` †  
**Réponse :** `{ "added": true, "value": "…", "comment": "…" }`

---

### `remove_ban_whitelist`

Retire une entrée de la liste blanche (valeur exacte telle qu'enregistrée) et l'envoie aux passerelles ; les bans qu'elle neutralisait s'appliquent de nouveau. Erreur si l'entrée n'existe pas.

| Paramètre | Type   | Requis | Description |
|-----------|--------|--------|-------------|
| `ip`      | string | ✓      | Adresse IP ou plage CIDR à retirer |

**Scope :** `security:write` †

---

### `delete_security_ban`

Supprime le ban et lève tous les bans de son IP sur chaque passerelle, y compris ceux posés localement (Ephor, plugins, règles) — voir [Déban](security.md#déban).

| Paramètre | Type   | Requis | Description   |
|-----------|--------|--------|---------------|
| `id`      | string | ✓      | ID du ban     |

**Scope :** `security:write`

---

### `ban_ip`

Banne une IP directement depuis le MCP (insère dans `security_bans`, pousse aux passerelles). Un seul ban par IP, d'id `mcp-<ip>` : un nouvel appel pour la même IP remplace son motif et son expiration.

| Paramètre    | Type   | Requis | Description                               |
|--------------|--------|--------|-------------------------------------------|
| `ip`         | string | ✓      | Adresse IP ou plage CIDR à bannir (mêmes règles que `create_security_ban`) |
| `reason`     | string | —      | Motif du ban                              |
| `expires_at` | string | —      | Expiration RFC3339, enregistrée en UTC ; omis = permanent ; date illisible → erreur |

**Scope :** `security:write` (depuis Admin `0.69.6` ; aucun scope n'était vérifié auparavant)  
**Réponse :** `{ "id": "mcp-<ip>", "ip": "<ip>", "reason": "…", "permanent": true|false }` (`reason` vaut `mcp_ban` si omis)

---

### `unban_ip`

Lève le ban d'une IP (supprime de `security_bans`) et tous ses bans sur chaque passerelle, y compris ceux posés localement (Ephor, plugins, règles) même si l'Admin ne les connaît pas — voir [Déban](security.md#déban). La correspondance est exacte : un ban posé sur une plage se lève en passant la plage telle que la renvoie `list_security_bans` (`2a01:e0a:1:2::/64`), pas une adresse qu'elle contient.

| Paramètre | Type   | Requis | Description         |
|-----------|--------|--------|---------------------|
| `ip`      | string | ✓      | Adresse IP ou plage CIDR à débannir, telle qu'enregistrée (débannir une adresse d'une plage bannie ne lève pas la plage) |

**Scope :** `security:write` (depuis Admin `0.69.6` ; aucun scope n'était vérifié auparavant)  
**Réponse :** `{ "ip": "<ip>", "deleted": <n> }` (`deleted` : nombre de bans supprimés de `security_bans`, `0` si l'Admin n'en connaissait aucun — le déban est tout de même envoyé aux passerelles)

---

### Flux d'automatisation (Admin 0.139.0)

Règles, planifications et playbooks sont des **flux** : un déclencheur (`condition`, `event`, `schedule`, `manual`), un garde-fou et des étapes (action, attente, si/sinon, approbation, appel d'un playbook, arrêt). Le format est décrit dans `docs/api_specs.md` (section « Flux d'automatisation »). Les outils ci-dessous remplacent `list_rules`, `run_rule`, les outils `*_scheduled_task*`, `*_playbook*` et `*_pending_action`.

Tous sont réservés au rôle admin, comme `/api/v1/automation`. Scope `audit:read` pour lire, `security:write` pour modifier ou lancer. Les secrets des actions et des paramètres de modèle sont toujours renvoyés masqués ; les renvoyer masqués à `update_flow` les conserve. L'acteur enregistré (lancement, décision) est l'adresse du titulaire du jeton, suivie de `via pat:<id>`.

| Outil | Paramètres | Rôle |
|---|---|---|
| `get_automation_catalog` | — | Déclencheurs, événements, conditions, actions, types d'étape (manifestes avec leurs champs) et métriques disponibles (`edge: true` : calculée aussi par chaque passerelle, un flux simple qui la surveille s'y exécute). À lire avant `create_flow` |
| `list_flows` | `trigger` (ex. `condition,event`) | Flux avec état (`fire_count`, `next_run_at`, `waiting`…), `placement` (`edge` : exécuté par les passerelles) et, pour un flux issu d'un modèle, `template.outdated` / `template.missing` |
| `get_flow` | `id` | Un flux |
| `create_flow` | `flow` (objet) | Crée un flux de l'éditeur |
| `update_flow` | `id`, `flow` | Remplace la définition (nouvelle version). Refusé pour un flux issu d'un modèle : utiliser `update_flow_params`, ou `detach_flow` |
| `set_flow_enabled` | `id`, `enabled` | Active ou désactive |
| `delete_flow` | `id` | Supprime (refusé si un autre flux l'appelle) |
| `run_flow` | `id`, `inputs`, `dry_run` | Lance à la main, sans garde-fous ; un flux à condition l'évalue d'abord. `dry_run` : simulation |
| `simulate_flow` | `flow`, `inputs` | Simule un flux non enregistré : conditions évaluées, aucune action exécutée. Réponse : `matched`, `trace` étape par étape, `placement` |
| `list_flow_versions` | `id` | 20 dernières versions, chacune avec `changes` : ce qui a changé depuis la précédente (Admin 0.141.0) |
| `restore_flow_version` | `id`, `version` | Rétablit une version |
| `detach_flow` | `id` | Détache un flux de son modèle |
| `update_flow_params` | `id`, `params`, `name`, `enabled` | Reconstruit un flux issu d'un modèle avec de nouveaux paramètres |
| `list_flow_templates` | — | Modèles avec leurs paramètres |
| `install_flow_template` | `template_id`, `params`, `name`, `enabled` | Crée un flux depuis un modèle |
| `list_flow_runs` | `flow_id`, `status`, `limit` | Journal des exécutions. `status=waiting_approval` : approbations en attente (avec `pending.message`) |
| `get_flow_run` | `run_id` | Une exécution et ses étapes |
| `decide_flow_run` | `run_id`, `approve` | Approuve ou refuse |
| `cancel_flow_run` | `run_id` | Annule une exécution en cours ou en attente |
| `replay_flow_run` | `run_id` | Relance avec le détail d'une exécution terminée |
| `list_silences` | — | Mises en sourdine (flux et règles d'alerte) |
| `create_silence` | `name`, `starts_at`, `ends_at` (RFC3339), `rule_ids` | Met en sourdine des flux et/ou des règles d'alerte (vide = tout) |
| `delete_silence` | `id` | Supprime une mise en sourdine |
| `export_automation` | — | YAML `version: 2` : flux, canaux, mises en sourdine (secrets masqués). Réponse : `{ yaml }` |
| `import_automation` | `yaml` | Flux et canaux mis à jour par nom ou créés, mises en sourdine ajoutées. Réponse : compteurs et `errors` |

---

### `rotate_cert`

Force le renouvellement ACME d'un domaine en vidant la date d'expiration en base (le prochain cycle d'auto-renouvellement émettra un nouveau certificat) et pousse les routes aux passerelles.

| Paramètre | Type   | Requis | Description                              |
|-----------|--------|--------|------------------------------------------|
| `domain`  | string | ✓      | Domaine cible (ex : `app.example.fr`)    |

**Scope :** `domains:write` (comme `POST /api/v1/domains/:id/renew`)  
**Réponse :** `{ "domain": "<domain>", "status": "renew_requested" }` (le domaine est créé s'il n'était pas encore géré)

---

### `get_cert_status`

Retourne le statut d'expiration de tous les certificats avec KPIs globaux (ok / warning / critical / expired).

| Paramètre | Type   | Requis | Description                                    |
|-----------|--------|--------|------------------------------------------------|
| `domain`  | string | —      | Filtrer sur un domaine spécifique              |

**Scope :** `certs:read`  
**Réponse :** `{ "certs": [...], "total": N, "ok": N, "warning": N, "critical": N, "expired": N }`

---

### `list_cert_deploy_targets`

Liste les cibles de déploiement configurées pour un certificat (webhook, ssh_exec) avec leur dernier statut.

| Paramètre | Type   | Requis | Description       |
|-----------|--------|--------|-------------------|
| `cert_id` | string | ✓      | ID du certificat  |

**Scope :** `certs:read`

---

### `list_cert_deploy_types`

Types de cible de déploiement de certificats (`webhook`, `ssh_exec`…) avec leurs champs de configuration (clé, libellé, `secret`, `required`, `multiline`).

_Aucun paramètre._

**Scope :** `certs:read`

---

### `list_dns_providers`

Fournisseurs DNS nommés du challenge ACME DNS-01 : identifiant, nom, type et paramètres, **secrets masqués** (`••••••••`). Un certificat en désigne un par `acme_provider_id`. Même source que `GET /api/v1/acme/providers`.

_Aucun paramètre._

**Scope :** `certs:read` + rôle admin

```json
[{ "id": "3f9c2a1b", "name": "do-prod", "type": "digitalocean", "params": { "auth_token": "••••••••" } }]
```

---

### `list_dns_provider_types`

Types de fournisseur DNS (cinq natifs et 28 modules libdns, `attrs.engine = "libdns"`) avec leurs paramètres : clé, `secret`, `required`, variable d'environnement (`env`). Même source que `GET /api/v1/acme/provider-types`.

| Paramètre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `q` | string | — | Filtre sur le type ou le libellé (sous-chaîne, insensible à la casse) |

**Scope :** `certs:read` + rôle admin

Lecture seule : un fournisseur se crée dans l'interface, par l'API ou par `goproxify acme providers add`, pour que ses identifiants ne transitent pas par un client IA.

---

### `trigger_cert_deploy`

Déclenche immédiatement le déploiement d'un certificat vers une cible spécifique.

| Paramètre   | Type   | Requis | Description                     |
|-------------|--------|--------|---------------------------------|
| `target_id` | string | ✓      | ID de la cible de déploiement   |

**Scope :** `certs:write`  
**Réponse :** `{ "target_id": "...", "cert_id": "...", "type": "webhook|ssh_exec", "status": "triggered" }`

---

### `import_cert`

Importe un certificat externe (non-ACME) en fournissant le PEM et la clé privée. Le domaine est extrait automatiquement du CN ou des SAN.

| Paramètre  | Type   | Requis | Description                                          |
|------------|--------|--------|------------------------------------------------------|
| `cert_pem` | string | ✓      | Certificat PEM (`-----BEGIN CERTIFICATE-----`)       |
| `key_pem`  | string | ✓      | Clé privée PEM                                       |
| `issuer`   | string | —      | Émetteur (défaut : `custom`)                         |

**Scope :** `certs:write`  
**Réponse :** `{ "domain": "...", "issuer": "...", "expires_at": "...", "status": "imported" }`

---

### `create_internal_ca`

Crée une nouvelle autorité de certification interne (CA racine auto-signée ECDSA P-256), pour émettre des certificats serveur/client internes hors ACME.

| Paramètre        | Type   | Requis | Description                              |
|------------------|--------|--------|-------------------------------------------|
| `name`           | string | ✓      | Nom de la CA (identifiant lisible)         |
| `common_name`    | string | ✓      | Common Name du certificat racine           |
| `validity_years` | number | —      | Durée de validité en années (défaut : 10)  |

Tous les outils de CA interne sont réservés au rôle admin, comme `/api/v1/internal-ca`.

**Scope :** `certs:write` + rôle admin  
**Réponse :** objet CA (`id`, `name`, `subject`, `cert_pem`, `not_after`, `created_at`).

---

### `list_internal_cas`

Liste les autorités de certification internes.

_Aucun paramètre._

**Scope :** `certs:read` + rôle admin

---

### `get_ech_status`

État d'Encrypted Client Hello : activation, nom public, clés (jamais les clés privées) et valeur `ech=` à publier dans l'enregistrement DNS HTTPS.

_Aucun paramètre._

**Scope :** `certs:read` + rôle admin

---

### `issue_internal_cert`

Émet un certificat serveur ou client signé par une CA interne.

| Paramètre       | Type   | Requis | Description                                  |
|-----------------|--------|--------|------------------------------------------------|
| `ca_id`         | string | ✓      | ID de la CA interne émettrice                  |
| `common_name`   | string | ✓      | Common Name du certificat                      |
| `sans`          | array  | —      | Noms alternatifs (DNS ou IP)                   |
| `usage`         | string | —      | `server` ou `client` (défaut : `server`)       |
| `validity_days` | number | —      | Durée de validité en jours (défaut : 397)      |

**Scope :** `certs:write` + rôle admin  
**Réponse :** objet certificat (`id`, `ca_id`, `common_name`, `usage`, `sans`, `serial`, `cert_pem`, `not_after`, `revoked`, `created_at`).

---

### `list_internal_certs`

Liste les certificats émis par une CA interne.

| Paramètre | Type   | Requis | Description          |
|-----------|--------|--------|------------------------|
| `ca_id`   | string | ✓      | ID de la CA interne    |

**Scope :** `certs:read` + rôle admin

---

### `revoke_internal_cert`

Révoque un certificat émis par une CA interne.

| Paramètre | Type   | Requis | Description                |
|-----------|--------|--------|------------------------------|
| `cert_id` | string | ✓      | ID du certificat émis        |

**Scope :** `certs:write` + rôle admin  
**Réponse :** `{ "cert_id": "...", "status": "revoked" }`

---

### `list_security_threats`

Décisions CrowdSec synchronisées (`security_threats`).

| Paramètre | Type   | Requis | Description                          |
|-----------|--------|--------|--------------------------------------|
| `limit`   | number | —      | Défaut 100, max 500                  |

Trié par `last_seen_at` décroissant. Chaque résultat inclut `edge_name` (Passerelle d'origine) et `occurrences` (nombre de fois où cette menace ip+scenario a été observée ; `last_seen_at` reflète la plus récente).

**Scope :** `audit:read` + rôle admin

---

### `get_entry_rejections`

*(Admin `0.228.0`, Edge `0.135.0`)* Ce que l'entrée de chaque passerelle a refusé depuis son démarrage ([ADR 0020](adr/0020-reference-saisonniere-seuils-et-visibilite-amont.md), étape 1.c) : poignées de main TLS ratées (accès par l'IP, nom sans certificat, pas du TLS), connexions coupées avant le ClientHello, requêtes HTTP sur un hôte sans route. Par passerelle : totaux par raison (`unknown_sni`, `no_sni`, `ip_literal`, `not_tls`, `bad_clienthello`, `timeout`, `too_many_pending`, `handshake_failed`, `unknown_host`), premiers noms demandés avec le nombre d'IP distinctes qui les demandent (un nom demandé par beaucoup d'IP est plutôt un proxy oublié qu'un scanner), premières IP, premières empreintes JA4 et `probes` (IP aux accès à cadence régulière : des sondes probables, à exempter par `unknown_host.probes`). Les classements sont approchés, tenus en mémoire et repartent de zéro au redémarrage de la passerelle. Ne modifie rien et ne bannit rien.

| Paramètre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `edge` | string | | ID du jeton ou nom de la passerelle (défaut : toutes) |

---

### `get_traffic_reference`

*(Admin `0.233.0`, Edge `0.140.0`)* La référence saisonnière du trafic de chaque passerelle ([ADR 0020](adr/0020-reference-saisonniere-seuils-et-visibilite-amont.md), étape 3.a) : pour chaque route et pour l'entrée, le débit réel de la dernière minute, le débit attendu à cette heure de cette journée et sa borne haute, les IP distinctes, si le créneau est assez observé (`warm`) et le niveau d'alerte (`none`, `warning`, `probable`), avec les alertes en cours et les derniers changements d'état. Ne modifie rien. Voir [Référence saisonnière du trafic](security.md#référence-saisonnière-du-trafic).

| Paramètre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `edge` | string | | ID du jeton ou nom de la passerelle (défaut : toutes) |

---

### `get_app_inventory`

*(Admin `0.208.0`)* Applications que chaque passerelle reconnaît derrière ses proxies ([ADR 0017](adr/0017-inventaire-des-applications-et-cve.md)) : produit, version, identifiant CPE et ce qui les a fait reconnaître : l'image du conteneur (annoncée par l'Agent, proxies créés par labels) ou les réponses du backend lues avant `hide_server` (en-têtes `Server`, `X-Powered-By`, `X-Generator`, `<meta name="generator">`, tous les proxies). C'est ce que le scanner de vulnérabilités cherche dans NVD : un produit sans version (étiquette `latest`) est sondé sur le backend, un produit sans CPE sûr est listé sans être cherché. Même source que `GET /api/v1/security/inventory`, rapport de couverture (`coverage` : ce qui n'est pas cherché dans NVD et pourquoi) compris. Scope `audit:read` (rôle admin), lecture seule.

| Paramètre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `proxy` | string | | Identifiant ou hôte d'un proxy (défaut : tous) |
| `edge` | string | | ID du jeton ou nom de la passerelle (défaut : toutes) |

---

### `list_security_cves`

CVE détectées sur les backends.

| Paramètre         | Type    | Requis | Description                          |
|-------------------|---------|--------|--------------------------------------|
| `status`          | string  | —      | `open`, `ignored`, `resolved`        |
| `critical_only`   | boolean | —      | CVSS ≥ 7 uniquement                  |
| `kev_only`        | boolean | —      | Uniquement les CVE du catalogue CISA KEV (exploitation active) |

Chaque résultat inclut désormais `edge_name` — la passerelle d'origine ayant remonté la CVE (vide pour les entrées antérieures à cette colonne) — ainsi que `kev` (bool, exploitation activement observée, catalogue CISA) et `epss_score` (0-1, probabilité d'exploitation sous 30 jours, modèle EPSS de FIRST.org), rafraîchis en fin de scan (Admin `0.52.3`). Depuis Admin `0.208.0` : `host` (proxy), `product`, `version` et `source` (`image`, `headers` ou `html`) disent sur quoi la CVE a été trouvée ; à vérifier, pas une preuve (correctifs rétroportés).

**Scope :** `audit:read` + rôle admin

---

### `get_prism_anomalies`

Anomalies détectées par Prism : pic d'erreurs, IP dominante, pays en erreur, backend en difficulté, part de bots élevée. Scope : `logs:read`.

| Paramètre | Type   | Requis | Description                                              |
|-----------|--------|--------|----------------------------------------------------------|
| `hours`   | number | —      | Fenêtre analysée en heures (défaut 24, max 720)          |
| `edge`    | string | —      | Passerelle (nom du nœud ou id du token) ; omis = toutes  |
| `proxy`   | string | —      | Domaine du proxy ; omis = tous                           |

Chaque résultat : `kind`, `level` (`critical` | `warning`), `subject`, `label`, `value`, `baseline`, `count`. Mêmes règles que `GET /api/v1/prism/anomalies` : l'IP dominante n'est jamais une IP tronquée par l'anonymisation RGPD ni `[pseudonymisé]`.

---

### `get_prism_slo`

SLO de disponibilité (réponses non-5xx) sur une fenêtre glissante : disponibilité, budget d'erreur restant, vitesse de consommation sur 1 h et 6 h, état (`ok`, `warning`, `critical`, `exhausted`). Scope : `logs:read`.

| Paramètre | Type   | Requis | Description                                              |
|-----------|--------|--------|----------------------------------------------------------|
| `target`  | number | —      | Objectif en % (défaut : objectif enregistré, 99.9)       |
| `days`    | number | —      | Fenêtre en jours (défaut 30, max 90)                     |
| `edge`    | string | —      | Passerelle (nom du nœud ou id du token) ; omis = toutes  |
| `proxy`   | string | —      | Domaine du proxy ; omis = tous                           |

---

### `get_prism_geo`

Trafic par pays (requêtes, erreurs, taux d'erreur, IPs bannies) ou par ville (position approximative issue de la géolocalisation IP). Calculé à partir des bases de logs des passerelles (Admin `0.171.0`) ; une passerelle injoignable n'y figure pas. Scope : `logs:read`.

| Paramètre | Type   | Requis | Description                                                        |
|-----------|--------|--------|--------------------------------------------------------------------|
| `level`   | string | —      | `country` (défaut) ou `city`                                       |
| `hours`   | number | —      | Fenêtre analysée en heures (défaut 24, max 720)                    |
| `edge`    | string | —      | Passerelle (nom du nœud ou id du token) ; omis = toutes            |
| `proxy`   | string | —      | Domaine du proxy ; omis = tous                                     |
| `limit`   | number | —      | Villes retournées (défaut 300, max 1000) ; ignoré au niveau pays   |

---

### `get_prism_tls_fingerprints`

Empreintes TLS (JA4, avec le JA3 associé) les plus actives sur la période : requêtes, erreurs, requêtes signalées par le WAF ou Ephor, IP distinctes. Un JA4 très signalé et partagé par beaucoup d'IP est la signature d'un scanner ou d'un botnet, à ajouter à `custom_lists.tls_fingerprints` d'Ephor. Uniquement le trafic TLS terminé par une passerelle (ni HTTP clair ni HTTP/3). Scope : `logs:read`. Classement exact fusionné depuis les bases de logs des passerelles (Admin `0.171.0`).

| Paramètre | Type   | Requis | Description                                                        |
|-----------|--------|--------|--------------------------------------------------------------------|
| `hours`   | number | —      | Fenêtre analysée en heures (défaut 24, max 720)                    |
| `edge`    | string | —      | Passerelle (nom du nœud ou id du token) ; omis = toutes            |
| `proxy`   | string | —      | Domaine du proxy ; omis = tous                                     |
| `limit`   | number | —      | Empreintes retournées (défaut 30)                                  |

---

### `get_ephor_references`

Ce que chaque passerelle a appris pour la note commune d'Ephor (ADR 0011) : références de débit par IP, route par route et heure par heure (médiane, seuil, minutes observées, fiable ou en apprentissage), base ASN et table d'empreintes TLS, nombre de profils en cours.

| Paramètre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `edge` | string | — | Passerelle (nom du nœud ou id du token) ; défaut : toutes |

**Scope :** `logs:read` + rôle admin

---

### `get_proxy_surface`

Apprentissage de la surface d'un proxy ([ADR 0016](adr/0016-apprentissage-de-la-surface-d-un-proxy.md)) : ce que son trafic légitime utilise réellement. Sans `proxy`, liste par passerelle les proxies en apprentissage (requêtes vues et apprises, gabarits de chemin, convergence). Avec `proxy`, rapport complet : méthodes, gabarits de chemin (`/api/users/{int}`) avec méthodes, statuts, types de contenu, taille des corps, paramètres, clients distincts et jours de présence, en-têtes, pays et AS, requêtes exclues (IP suspecte) ou en échec, et indicateur de convergence (7 jours, 1 000 requêtes, 48 h sans nouveau gabarit). Un gabarit `low_support` a peu de clients ou de jours : à confirmer. Le mode `learn` se pose par proxy (`update_proxy`, option `surface` : `{"mode":"learn"}`) et ne bloque rien.

| Paramètre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `proxy` | string | — | Identifiant ou hôte du proxy ; vide = liste des proxies en apprentissage |
| `edge` | string | — | Passerelle (nom du nœud ou id du token) ; défaut : toutes |

**Scope :** `audit:read` + rôle admin

---

### `get_proxy_surface_proposals`

Réglages que le profil de surface d'un proxy permet de proposer ([ADR 0016](adr/0016-apprentissage-de-la-surface-d-un-proxy.md), étape 2) : `max_body_size`, `rate_limit`, `geo_ip`, `ip_filter`, `cors` et `waf` (règles du WAF qui se déclenchent de façon répétée sur des clients ordinaires : la configuration `waf` complète avec une **exclusion par chemin** pour une règle qui se circonscrit à des préfixes, ou à défaut un `anomaly_threshold` de 10 conseillé ; jamais une exclusion pour tout le proxy, ni pour une règle personnalisée ni un WAF de snippet). Le rapport de surface liste aussi les règles du WAF déclenchées. Chaque proposition donne la valeur, la commande qui la pose, ce que le profil a vu, ce qu'elle aurait refusé sur le trafic appris (`would_refuse` sur `of`, quand c'est mesurable) et ses limites. Un réglage que le proxy a déjà n'est jamais remplacé ; un réglage non proposé est dans `skipped` avec sa raison. Tant que `convergence.converged` est faux, le profil n'est pas fiable. Ne modifie rien : pour appliquer, `update_proxy` avec `options` (même clé, même valeur).

| Paramètre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `proxy` | string | ✓ | Identifiant ou hôte du proxy |
| `edge` | string | — | Passerelle (nom du nœud ou id du token) ; défaut : toutes |

**Scope :** `audit:read` + rôle admin

---

### `get_proxy_surface_openapi`

Politique positive d'un proxy ([ADR 0016](adr/0016-apprentissage-de-la-surface-d-un-proxy.md), étape 3) : une spécification OpenAPI générée à partir de son profil de surface, sous la forme du réglage `openapi` du proxy, en mode `detect` (rien n'est refusé, les requêtes hors de la politique sont comptées et listées dans le rapport de surface, `get_proxy_surface`). Chemins (`/api/users/{users_id}`), méthodes, paramètres typés et types de contenu appris ; pas les corps. Les chemins vus par trop peu de clients ou de jours sont dans `excluded` (`include_low_support` les garde). Tant que `ready` est faux, le profil n'est pas fiable. Ne modifie rien : pour poser la politique, `update_proxy` avec `options` `{"openapi": <config>}`.

| Paramètre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `proxy` | string | ✓ | Identifiant ou hôte du proxy |
| `include_low_support` | boolean | — | Garder aussi les chemins à faible soutien (défaut : non) |
| `edge` | string | — | Passerelle (nom du nœud ou id du token) ; défaut : toutes |

**Scope :** `audit:read` + rôle admin

---

### `get_proxy_surface_suggestions`

Ajouts suggérés à la politique de surface d'un proxy ([ADR 0016](adr/0016-apprentissage-de-la-surface-d-un-proxy.md), étape 5) : un chemin ou une méthode hors politique (`unknown_path`, `unknown_method`) qui revient de plusieurs clients propres sur plusieurs jours, avec sa preuve. Confiance `high` : le backend a servi ces requêtes (3 clients propres, 2 jours). Confiance `low` : le contrôle les refuse, seuls des clients propres reviennent (5 clients, 3 jours) : un scanner distribué ressemble à cela, à examiner. Les chemins de scanner connus ne sont jamais suggérés. Ne modifie rien.

| Paramètre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `proxy` | string | ✓ | Identifiant ou hôte du proxy |
| `edge` | string | — | Passerelle (nom du nœud ou id du token) ; défaut : toutes |

**Scope :** `audit:read` + rôle admin

---

### `accept_proxy_surface_suggestions`

Ajoute des suggestions à la politique openapi d'un proxy : le chemin ou la méthode est ajouté à la spécification, rien n'est retiré, les violations correspondantes sont effacées du profil. Seules les suggestions actuelles du profil (clés de `get_proxy_surface_suggestions`) peuvent être ajoutées ; la spécification doit être en JSON (un texte YAML est refusé, sans rien modifier). Un refus ne modifie rien et dit pourquoi (`blockers`).

| Paramètre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `proxy` | string | ✓ | Identifiant ou hôte du proxy |
| `keys` | array | — | Clés des suggestions à ajouter (« raison MÉTHODE chemin ») |
| `all_high` | boolean | — | Ajouter toutes les suggestions de confiance haute |
| `dry_run` | boolean | — | Calculer le résultat sans rien écrire |
| `edge` | string | — | Passerelle (nom du nœud ou id du token) ; défaut : toutes |

**Scope :** `security:write` + rôle admin

---

### `enforce_proxy_surface`

Passe en block la politique de surface d'un proxy, type de violation par type de violation ([ADR 0016](adr/0016-apprentissage-de-la-surface-d-un-proxy.md), étape 4) : le contrôle `openapi` du proxy refuse les violations de ces types et laisse passer, en les comptant, les autres. Garde-fous : politique openapi active et profil de surface (`get_proxy_surface_openapi` d'abord, en detect), profil convergé, aucun chemin `likely_legit` pour ces types, pas de débordement. Un refus des garde-fous ne modifie rien et le dit (`blockers`). `force` passe outre le profil non convergé et les chemins à ajouter (consigné à l'audit) ; `dry_run` calcule sans écrire. Retour : `relax_proxy_surface`.

| Paramètre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `proxy` | string | ✓ | Identifiant ou hôte du proxy |
| `reasons` | array | ✓ | `unknown_path`, `unknown_method`, `invalid_param`, `invalid_body`, `unsupported_media`, `too_large` |
| `dry_run` | boolean | — | Calculer le résultat sans rien écrire |
| `force` | boolean | — | Passer outre les garde-fous qui peuvent l'être (audit) |
| `edge` | string | — | Passerelle (nom du nœud ou id du token) ; défaut : toutes |

**Scope :** `security:write` + rôle admin

---

### `relax_proxy_surface`

Remet le contrôle `openapi` d'un proxy en `detect` : plus rien n'est refusé, les violations restent comptées. La spécification est conservée.

| Paramètre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `proxy` | string | ✓ | Identifiant ou hôte du proxy |

**Scope :** `security:write` + rôle admin

---

### `reset_proxy_surface`

Efface le profil de surface d'un proxy sur toutes les passerelles (ou sur `edge`) : l'apprentissage repart de zéro. À faire quand l'application a changé. Ne touche ni au trafic ni à la configuration.

| Paramètre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `proxy` | string | ✓ | Identifiant ou hôte du proxy |
| `edge` | string | — | Passerelle (nom du nœud ou id du token) ; défaut : toutes |

**Scope :** `security:write` + rôle admin

---

### `suggest_ephor_thresholds`

Propose des seuils Ephor à partir des cumuls par minute (sans IP) : par passerelle, débit normal (médiane, p99, p99,9, max, part d'erreurs) et limite globale proposée (quatre fois le p99,9, arrondie). Ne modifie rien.

| Paramètre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `days` | number | — | Fenêtre lue en jours (défaut 7, max 90) |
| `edge` | string | — | Passerelle dont la configuration (ou celle de son groupe HA) sert de base |

**Scope :** `logs:read` + rôle admin

---

### `simulate_ephor_config`

*(Admin `0.173.0`)* La simulation tourne sur les passerelles : chacune rejoue son propre trafic, agents utilisateur compris, et l'Admin additionne les rapports.

Dry-run Ephor : rejoue les access logs récents contre une config candidate et la compare à la config actuelle, **sans rien modifier**. Permet de répondre à « si j'applique cette règle, combien de requêtes légitimes auraient été bloquées dans la dernière heure ? » avant de faire `PUT /security/threat-config`. Scope : `logs:read` + rôle admin (la route REST équivalente est réservée aux admins).

| Paramètre | Type    | Requis | Description |
|-----------|---------|--------|-------------|
| `config`  | object  | ✓      | Champs Ephor à surcharger sur la config actuelle (mêmes noms que `threat-config`, config du groupe HA si la passerelle en fait partie : `rate_limit`, `rate_window`, `rate_ban_threshold`, `error_threshold`, `error_window`, `custom_lists`, `whitelist`, `score_threshold`, `ip_score` (`enabled`, `ban_threshold`, `half_life`, `errors` : `enabled`, `weights`, `default_weight`, `routes`), `escalation` (`enabled`, `factor`, `window`, `max_duration`), `ban_duration`) |
| `hours`   | number  | —      | Fenêtre rejouée (défaut `1`, max `24` ; `168` avec la référence saisonnière) |
| `domain`  | string  | —      | Limiter le rejeu à un domaine |
| `edge`    | string  | —      | Passerelle dont la config actuelle sert de base (défaut : config globale) |

Réponse : `current` et `candidate` (`events`, `blocked`, `blocked_by_ban`, `legit_blocked`, `blocked_ips`, `by_reason`, `bans`, `top_ips`), `delta` (candidat − actuel), `events_replayed`, `truncated` (plafond 200 000 événements, les plus récents sont conservés), `skipped_unattributable_ip`.

- Le rejeu utilise le moteur Ephor réel sur l'horloge des logs, en mode `block` ; une IP bannie pendant le rejeu reste bloquée pour la durée du ban.
- `legit_blocked` compte les requêtes bloquées qui avaient reçu un statut `< 400` : indicateur de faux positifs, pas une certitude.
- **Non simulé** : listes par défaut (UA/path/IP téléchargées), `global_rps`, règles User-Agent (l'UA n'est pas conservé dans les logs Admin) et WAF (ni en-têtes ni corps conservés). Les IP pseudonymisées ou tronquées par l'anonymisation (RGPD) sont ignorées et comptées dans `skipped_unattributable_ip`.
- *(Admin `0.236.0`)* Avec `seasonal.mode` en `detect` ou `block` dans la config, la fenêtre va jusqu'à `168` h et les rapports portent `seasonal` (par route : `warm`, `warnings`, `probables`, `alert_seconds`, et en `block` `hardened_requests` / `hardened_served`). Une route `warm: false` n'a pas assez d'historique dans la fenêtre pour être jugée. Voir [Référence saisonnière du trafic](security.md#référence-saisonnière-du-trafic).
- Équivalent REST (bouton « Simuler » de la page Ephor) : `POST /api/v1/security/threat-config/simulate`, voir `docs/api_specs.md`. Équivalent CLI : `goproxify security threat simulate`.

---

### `trace_ip`

*(Admin `0.172.0`)* Lit les bases de logs des passerelles (jusqu'à 400 000 lignes, `scan_limited` au-delà) ; `summary.unreachable` nomme celles qui manquent.

Parcours complet d'une IP ou d'un CIDR sur une longue période : requêtes d'accès regroupées en épisodes (domaines, chemins, statuts, catégories WAF, signaux Ephor), détections CrowdSec/Ephor, bans et débans, bans en cours et profils IP qui contiennent la cible. Répond à « que fait cette IP depuis des semaines ? ».

| Paramètre | Type   | Requis | Description |
|-----------|--------|--------|-------------|
| `target`  | string | ✓      | IP ou CIDR (`203.0.113.7`, `198.51.100.0/24`, `2001:db8::/32`) ; facultatif avec `scope=asn` et `asn` |
| `scope`   | string | —      | `ip` (défaut) ou `asn` (tout l'ASN de l'adresse) ; nécessite la base ASN |
| `asn`     | string | —      | Numéro d'ASN (`AS16276`) à tracer en entier, avec `scope=asn` |
| `from`    | string | —      | RFC3339 ou `AAAA-MM-JJ` (défaut : 30 jours avant `to`) |
| `to`      | string | —      | RFC3339 ou `AAAA-MM-JJ` (défaut : maintenant) |
| `order`   | string | —      | `desc` (défaut : le plus récent d'abord) ou `asc` (chronologique) |
| `limit`   | number | —      | Étapes par page (défaut 500, max 2000) |
| `offset`  | number | —      | Décalage de pagination |

Réponse : `summary` (totaux sur toute la période, activité par jour, tops) et `steps` (voir `GET /api/v1/security/ip-trace` dans `docs/api_specs.md`). Les requêtes remontent aussi loin que la rétention des logs d'accès ; les IP pseudonymisées ou tronquées (RGPD) ne sont pas retrouvées. Chaque étape `ban` (et chaque ban en cours) porte `user_agent`, le client qui a provoqué le ban. Équivalent CLI : `goproxify security trace`.

**Scope :** `logs:read` + rôle admin

---

## Infrastructure / wizard architecture

Scopes PAT : `nodes:read` (lecture) / `nodes:write` (écriture). Alignés sur `/api/v1/declared-nodes`, `/api/v1/bootstrap-tickets`, `/api/v1/nodes/{id}/accept|reject`.

### `get_architecture`

Architecture déclarée (`architecture.json`, référentiel de la topologie) : nœuds passerelle / Agent avec leur hôte (`config.host`), région et capacités (HA, TLS, Docker, Portainer…), plus les domaines et, pour chaque groupe HA, la version de sa fiche (`groups`). Scope : `nodes:read` + rôle admin (comme `GET /api/v1/architecture`). La reconstitution de l'architecture à partir des fiches (`goproxify architecture recover`) reste une opération volontaire de l'opérateur, hors MCP.

| Paramètre | Type   | Requis | Description |
|-----------|--------|--------|-------------|
| `version` | string | —      | Nom d'une version conservée (`architecture-….json`, voir `goproxify architecture versions`) ; vide = version courante |

Retourne `{schema_version, nodes, domains}` (même format que `GET /api/v1/architecture`). Une version qui n'existe pas renvoie une erreur ; rien n'est restauré.

---

### `get_topology_live`

État temps réel de la topologie : pour chaque passerelle et Agent, santé, CPU/mémoire, débit (req/s sur 60 s), taux de refus (403/429) et d'erreurs 5xx, score de risque 0-100 avec son facteur dominant, plus le nombre de bans actifs. Même réponse que `GET /api/v1/nodes/live` (formule du score : voir [api_specs.md](api_specs.md)). Scope `nodes:read`.

**Paramètres :** aucun

---

### `list_declared_nodes`

Liste les nœuds déclarés (toile architecture) pas encore connectés.

**Paramètres :** aucun

---

### `create_declared_node`

Déclare (ou met à jour) un nœud passerelle/Agent pour le suivi wizard / auto-accept.

| Paramètre       | Type   | Requis | Description                |
|-----------------|--------|--------|----------------------------|
| `role`          | string | ✓      | `edge` ou `agent`          |
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
| `edge_endpoint`   | string  | —      | Endpoint passerelle cible                  |
| `payload`         | object  | —      | Payload JSON (compose / options)     |
| `ttl_hours`       | number  | —      | 1–168 (défaut 24)                    |
| `auto_accept`     | boolean | —      | Auto-accept des nœuds liés (défaut true) |
| `node_names`      | array   | —      | Noms de nœuds pour l’auto-accept     |

---

### `list_hosts`

Liste les hôtes déclarés dans `architecture.json` (adresse, rôles, groupe HA), leur état (`pending`, `partial`, `joined`), leurs nœuds et le ticket d'installation en cours (échéance seulement). Aucun paramètre. Voir `GET /api/v1/hosts`.

---

### `create_host_join_ticket`

Crée pour un hôte déclaré un ticket d'installation de 15 minutes (il remplace le précédent) : jeton, `spec_url` où le launcher récupère la description de l'hôte, `fingerprint` du certificat de l'Admin à vérifier, `trigger_url` et `qr_code` (PNG en data URL) du QR code à scanner vers le launcher de l'hôte en attente, `listen_command` et `join_command` à lancer sur l'hôte. Refusé si l'hôte est inconnu ou déjà intégré. Voir `POST /api/v1/hosts/{name}/join-ticket`.

| Paramètre | Type   | Requis | Description              |
|-----------|--------|--------|--------------------------|
| `host`    | string | ✓      | Nom de l'hôte déclaré    |

---

### `accept_node` / `reject_node`

Accepte ou rejette un nœud en attente (`pending_nodes`) après présentation du pairing secret.

| Paramètre | Type   | Requis | Description              |
|-----------|--------|--------|--------------------------|
| `id`      | string | ✓      | ID du nœud pending       |

---

## Canaux et règles d'alerte

Scopes PAT : `alerts:read` (lecture) / `alerts:write` (création, suppression, accusé de réception), alignés sur `/api/v1/alert-channels`, `/api/v1/alert-rules` et `/api/v1/alert-events`.

### `list_alert_channels`

Liste les canaux de notification (email, webhook, ntfy, Gotify, Jira…).

**Paramètres :** aucun

---

### `list_alert_channel_types`

Types de canal de notification avec leurs champs (clé, libellé, `secret`, `required`, `kind`). À consulter avant `create_alert_channel`.

_Aucun paramètre._

**Scope :** `alerts:read`

---

### `create_alert_channel`

Crée un canal de notification.

| Paramètre | Type   | Requis | Description                                    |
|-----------|--------|--------|------------------------------------------------|
| `name`    | string | ✓      | Nom du canal                                   |
| `type`    | string | ✓      | `email`, `webhook`, `ntfy`, `gotify`, `jira`, `linear`, `github`, `gitlab`, `zammad`, `glpi`, `slack`, `teams`, `telegram`, `sms` |
| `config`  | object | ✓      | Configuration dépendant du type (champs : `list_alert_channel_types`) ; refusée si un champ requis manque ou si une clé est inconnue |

**Réponse :** `{ "id": "ac_…", "name": "…", "type": "…" }`

---

### `delete_alert_channel`

| Paramètre | Type   | Requis | Description         |
|-----------|--------|--------|---------------------|
| `id`      | string | ✓      | ID du canal         |

---

### `list_alert_rules`

Liste les règles d'alerte avec leurs déclencheurs, scopes et canaux associés.

**Paramètres :** aucun

---

### `create_alert_rule`

Crée une règle d'alerte.

| Paramètre          | Type    | Requis | Description                                          |
|--------------------|---------|--------|------------------------------------------------------|
| `name`             | string  | ✓      | Nom de la règle                                      |
| `channels`         | array   | ✓      | IDs des canaux de notification                       |
| `triggers`         | array   | ✓      | Déclencheurs (`list_alert_triggers`)                 |
| `enabled`          | boolean | —      | Activée par défaut (`true`)                          |
| `cooldown_sec`     | number  | —      | Délai anti-spam en secondes (défaut : 300)           |
| `priority`         | number  | —      | Priorité (0 = normale, plus élevé = plus urgent)     |
| `group_window_sec` | number  | —      | Fenêtre de regroupement en secondes (défaut 0 = désactivé) — fusionne les événements correspondants en une seule notification |
| `escalation`       | array   | —      | Paliers `[{"after_sec":900,"channels":["id"]}]` : sans accusé de réception (`ack_alert_event`) avant `after_sec`, renotifie (`channels` vide = ceux de la règle) |
| `scope`            | object  | —      | Scope : `nodes`, `domain_glob`, `components`, `min_severity`, etc. |

**Réponse :** `{ "id": "ar_…", "name": "…", "enabled": true }`

---

### `ack_alert_event`

Accuse réception d'un événement d'alerte : les paliers d'escalade déjà programmés le revérifient à leur échéance et ne renotifient plus.

| Paramètre | Type   | Requis | Description                       |
|-----------|--------|--------|--------------------------------------|
| `id`      | string | Oui    | ID de l'événement (`list_alert_events`) |

**Réponse :** `{ ok: true }`

---

### `delete_alert_rule`

| Paramètre | Type   | Requis | Description         |
|-----------|--------|--------|---------------------|
| `id`      | string | ✓      | ID de la règle      |

---

## Fournisseurs d'authentification

Scopes PAT : `audit:read` (lecture) / `security:write` (écriture), plus le rôle admin, comme `/api/v1/auth-providers`.

### `list_auth_providers`

Liste les fournisseurs d'authentification externe (OIDC, SAML, LDAP…).

**Paramètres :** aucun

**Réponse exemple :**
```json
[
  { "id": "ap_01", "name": "Google", "provider": "google", "enabled": true, "config": { "oidc": { "client_secret": "••••••••" } } }
]
```

Les secrets (`client_secret`, `session_secret`, mot de passe de liaison LDAP, mots de passe Basic) sont masqués.

### `list_auth_provider_types`

Liste les types de fournisseur et leurs champs (clés imbriquées `oidc.client_secret`, secrets, requis). Même source que `GET /api/v1/auth-provider-types`. Scope `audit:read`.

**Paramètres :** aucun

---

### `create_auth_provider`

Crée un fournisseur d'authentification.

| Paramètre | Type    | Requis | Description                                  |
|-----------|---------|--------|----------------------------------------------|
| `name`    | string  | ✓      | Nom du fournisseur                            |
| `provider` | string | ✓      | Type : voir `list_auth_provider_types` (`oidc`, `google`, `github`, `ldap`, `saml`, `basic`, `authelia`…) |
| `config`  | object  | ✓      | Configuration groupée par section (`{"oidc":{…}}`), validée par le manifeste du type |
| `enabled` | boolean | —      | Activé par défaut (`true`)                   |

---

### `delete_auth_provider`

| Paramètre | Type   | Requis | Description                |
|-----------|--------|--------|----------------------------|
| `id`      | string | ✓      | ID du fournisseur          |

---

## Profils IP

Scopes PAT : `audit:read` (lecture) / `security:write` (écriture), comme `/api/v1/ip-profiles`.

### `list_ip_profiles`

Liste les profils IP (listes blanches/noires CIDR, GeoIP, réputation).

Chaque profil inclut l'état du rafraîchissement automatique : `last_updated_at` (dernier succès), `last_error`, `consecutive_failures` et `next_attempt_at` (vides / 0 quand le feed est à jour).

**Paramètres :** aucun

---

### `create_ip_profile`

Crée un profil IP.

| Paramètre     | Type   | Requis | Description                           |
|---------------|--------|--------|---------------------------------------|
| `name`        | string | ✓      | Nom du profil                         |
| `action`      | string | ✓      | `allow` ou `block`                    |
| `cidrs`       | array  | —      | Liste de CIDRs/IPs                    |
| `countries`   | array  | —      | Codes pays ISO 3166-1 alpha-2         |
| `description` | string | —      | Description libre                     |

---

### `delete_ip_profile`

| Paramètre | Type   | Requis | Description        |
|-----------|--------|--------|--------------------|
| `id`      | string | ✓      | ID du profil IP    |

---

## Snippets

Scopes PAT : `snippets:read` (lecture, `list_snippets`) / `snippets:write` (écriture), comme `/api/v1/snippets`.

### `create_snippet`

Crée un snippet middleware réutilisable (WAF, rate-limit, headers…).

| Paramètre | Type   | Requis | Description                                      |
|-----------|--------|--------|--------------------------------------------------|
| `name`    | string | ✓      | Nom du snippet                                   |
| `type`    | string | ✓      | `waf`, `rate_limit`, `headers`, `cors`, `auth`   |
| `config`  | object | ✓      | Configuration dépendant du type                  |

---

### `delete_snippet`

| Paramètre | Type   | Requis | Description       |
|-----------|--------|--------|-------------------|
| `id`      | string | ✓      | ID du snippet     |

---

## Domaines

Scopes PAT : `domains:read` (lecture, `list_domains`) / `domains:write` (écriture, y compris `rotate_cert`), comme `/api/v1/domains`.

### `create_domain`

Déclare un nouveau domaine géré (ACME DNS-01).

| Paramètre | Type   | Requis | Description                            |
|-----------|--------|--------|----------------------------------------|
| `domain`  | string | ✓      | Domaine (ex : `app.example.fr`)        |
| `edge_id` | string | —      | ID de la passerelle d'entrée                    |

**Réponse :** `{ "id": "dm_…", "domain": "app.example.fr", "edge_id": "…" }`

---

### `renew_domain`

Force le renouvellement du certificat d'un domaine.

| Paramètre | Type   | Requis | Description       |
|-----------|--------|--------|-------------------|
| `id`      | string | ✓      | ID du domaine     |

---

## Certificats

### `obtain_cert`

Déclenche l'émission ACME d'un certificat pour un domaine.

| Paramètre | Type   | Requis | Description                     |
|-----------|--------|--------|---------------------------------|
| `domain`  | string | ✓      | Domaine cible                   |

**Scope :** `certs:write` (comme `POST /api/v1/certs`)

---

## GoProxify Access (portail)

Scopes PAT : `portal:read` (lecture) / `portal:write` (écriture + push). Réservés aux rôles admin.

### `get_portal_config` / `update_portal_config` / `push_portal`

| Paramètre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `edge` | string | ✓ | Nom du nœud passerelle |
| `enabled`, `ssh_port`, `http_port`, `public_host`, `allow_personal_targets`, `require_2fa`, `session_ttl_sec`, `session_mode`, `theme`, `views`, `ha_session_mode` | — | — | Champs optionnels pour `update_portal_config` (`theme` : `auto`, `clair`, `sombre`, `ocean`, `foret`, `amethyste` ou `contraste`) (`ha_session_mode` : `sticky` ou `shared`, groupe HA) |

### Catalogue — `list_portal_destinations`, `create_portal_destination`, `update_portal_destination`, `delete_portal_destination`, `preview_portal_destinations`

Création / mise à jour : `edge_name`, `name`, `kind` (`ssh`\|`docker`), `host`, `port`, `agent_name`, `container`, `tags`.

### Users — `list_portal_users`, `invite_portal_user`, `update_portal_user`, `delete_portal_user`, `resend_portal_invite`

Invitation : `email`, `home_edge`, `tags`, `groups` (IDs de groupes ; SMTP Admin requis). `update_portal_user` accepte aussi `groups` (remplace l'appartenance).

### Groupes — `list_portal_groups`, `create_portal_group`, `update_portal_group`, `delete_portal_group`

Groupes d'utilisateurs Access par passerelle, utilisés pour donner des droits sur les entrées du portail (`views` de `update_portal_config` : `users`, `groups`, `target_ids`, `theme`, `slug`/`host`…). `list_portal_groups` (`edge`, scope `portal:read`) ; `create_portal_group` (`edge`, `name`, `description`, `members`), `update_portal_group` (`id`, `name`, `description`, `members` — la liste remplace l'existante), `delete_portal_group` (`id`) (scope `portal:write`).

### Groupes de destinations — `list_portal_destination_groups`, `create_portal_destination_group`, `update_portal_destination_group`, `delete_portal_destination_group`

Groupes de destinations (machines du catalogue) par passerelle : une entrée du portail (`views[].dest_groups` de `update_portal_config`) offre toutes les destinations de ses groupes. `list_portal_destination_groups` (`edge`, scope `portal:read`) ; `create_portal_destination_group` (`edge`, `name`, `description`, `targets` = IDs de destinations), `update_portal_destination_group` (`id`, `name`, `description`, `targets` — la liste remplace l'existante), `delete_portal_destination_group` (`id`) (scope `portal:write`).

### Sessions en direct — `list_portal_sessions`, `terminate_portal_session`

`list_portal_sessions` (`edge`, scope `portal:read`) liste les connexions en cours ; `terminate_portal_session` (`edge`, `id`, scope `portal:write`) en ferme une.

### Accès temporaires — `list_portal_access_requests`, `decide_portal_access_request`

`list_portal_access_requests` (`edge`, `status` optionnel, scope `portal:read`) liste les demandes ; `decide_portal_access_request` (`id`, `decision` = `approve`\|`deny`\|`revoke`, `duration_min` optionnel pour `approve`, scope `portal:write`) tranche une demande.

### Politique d'accès — `get_portal_policy`, `set_portal_policy`

`get_portal_policy` (`edge`, scope `portal:read`) lit la politique ; `set_portal_policy` (`edge` + `hours_enabled`, `days`, `start_time`, `end_time`, `timezone`, `ip_allow`, `idle_timeout_min`, `record_sessions`, `record_retention_days` : 0 = 90 jours, -1 = illimitée, scope `portal:write`) la remplace en entier : un champ absent revient à « pas de restriction ».

### Enregistrements — `list_portal_recordings`, `delete_portal_recording`

`list_portal_recordings` (`edge`, scope `portal:read`) liste les métadonnées ; `delete_portal_recording` (`edge`, `id`, scope `portal:write`) supprime un enregistrement. Le contenu se rejoue dans l'interface ou s'exporte avec la CLI.

### `list_portal_audit`

| Paramètre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `edge` | string | — | Filtrer par passerelle |
| `limit` | number | — | Défaut 100, max 500 |

### Templates — `list_portal_templates`, `get_portal_template`, `upsert_portal_template`, `delete_portal_template`, `push_portal_templates`

Clés stables (`login`, `vault`, …). `upsert` : `key`, `body`, `name` optionnel.

---

## Ressources (resources)

Les ressources permettent à un client MCP d'accéder aux données sans construire d'appel d'outil explicite.

| URI                            | Description                              |
|--------------------------------|------------------------------------------|
| `goproxify://proxies`          | Liste de toutes les routes proxy         |
| `goproxify://nodes`            | Nœuds passerelle et Agent                      |
| `goproxify://agents`           | Agents WS (pending / approved)           |
| `goproxify://alerts`           | Règles d'alerting                        |
| `goproxify://users`            | Comptes utilisateurs et rôles            |
| `goproxify://snippets`         | Middlewares réutilisables                |
| `goproxify://domains`          | Domaines gérés et état TLS               |
| `goproxify://certs`            | Certificats TLS et expiration            |
| `goproxify://certs/monitor`    | Statut d'expiration avec KPIs (ok/warning/critical/expired) |
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

Lire une ressource exige les mêmes droits que l'outil qu'elle expose (`goproxify://users` → `list_users`, `goproxify://security/bans` → `list_security_bans`, `goproxify://certs/monitor` → `get_cert_status`, etc. ; voir [Contrôle d'accès des outils](#contrôle-daccès-des-outils)). Un refus renvoie une erreur JSON-RPC `-32603` dont le message est `scope insuffisant: <scope>` ou `accès réservé aux administrateurs` (depuis Admin `0.70.0` ; les ressources n'étaient auparavant soumises à aucun contrôle).

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

Les erreurs d'outil (proxy introuvable, backend SQL) sont retournées avec `isError: true` dans le contenu, sans code d'erreur JSON-RPC — le LLM reçoit le message et peut proposer une correction. Les refus d'autorisation (`scope insuffisant`, `accès réservé aux administrateurs`, `outil sans scope déclaré`) suivent le même format, voir [Contrôle d'accès des outils](#contrôle-daccès-des-outils).

**Secrets (Admin `0.135.0`, flux depuis `0.139.0`)** : `list_flows`, `get_flow`, `list_flow_versions`, `export_automation` et les simulations renvoient les secrets des actions (`webhook_signed`, `pagerduty`) et des canaux d'alerte sous la forme `••••••••` ; `import_automation` et les mises à jour conservent la valeur enregistrée quand le secret est omis ou masqué.

`get_proxy` renvoie la configuration de la route avec ses secrets (OIDC, LDAP, URL signées, Basic, plugins…) sous la forme `••••••••` (Admin `0.135.2`).
