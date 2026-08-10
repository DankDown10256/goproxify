# Politique de versioning Goproxify

## Format : `MAJOR.MINOR.PATCH`

| Incrément | Quand l'utiliser | Exemples |
|-----------|-----------------|---------|
| **MAJOR** | Changement incompatible : rupture d'API REST, format de config, schéma DB incompatible, retrait d'une fonctionnalité | Renommer un champ JSON de l'API, changer le format du token d'appairage |
| **MINOR** | Nouvelle fonctionnalité backward-compatible : nouvel endpoint, nouveau provider, nouveau mode de routage | Ajout MCP server, tokens API utilisateur (PAT), support Podman, canary routing |
| **PATCH** | Correction de bug, amélioration de performance, sécurité, mise à jour de dépendance sans impact fonctionnel | Fix d'un race condition, correction d'un calcul de score LB |

## Règle d'application

**Toute modification mergée sur `main` DOIT faire l'objet d'un bump de version dans `versions.json` pour le(s) service(s) concerné(s).**

| Fichiers modifiés | Service à bumper |
|---|---|
| `internal/admin/` (hors `ui/`) | `admin` |
| `internal/admin/ui/` | `webapp` |
| `internal/core/` | `core` |
| `internal/agent/` | `agent` |
| `internal/landing/` ou `services/landing/` | `landing` |
| Modification multi-service | chaque service concerné indépendamment |
| Documentation uniquement (`README.md`, `docs/`, `suivi/`) | aucun bump requis (sauf si une release fonctionnelle est publiée en même temps) |

Les services sont **versionnés indépendamment** : `admin` peut être en `0.3.1` pendant que `core` est en `0.2.0`.

### Bump automatique CI (PATCH)

Le pipeline [`.harness/build.yaml`](../.harness/build.yaml) (`bump_version`) :

1. Calcule le diff depuis le dernier commit `ci: bump versions`
2. Mappe les chemins modifiés vers les services (table ci-dessus ; `cmd/goproxify/`, `go.mod` → binaires admin/core/agent/landing)
3. Incrémente **uniquement le PATCH** des services touchés (y compris `landing`)
4. Si seuls des fichiers hors-scope (docs, etc.) ont changé → **aucun commit de bump**
5. Stage `build_all` : si `versions.json` est inchangé vs `HEAD~1` → **skip compile + pushes** images (marqueur `.skip-image-push`)

Les incréments **MINOR** et **MAJOR** restent **manuels** (édition de `versions.json` avant merge).

### Préversion (`0.x`)

Tant que le major reste à **0**, le projet est traité comme **preview / non production**
(voir `DISCLAIMER.md`). Les GitHub Releases correspondantes doivent être cochées
**Pre-release** (pas « Latest » stable). Sur GHCR public, les images portent le
SemVer **et** le tag flottant `:preview` (pas `:latest`). Le passage en **`1.0.0`**
est l’acte qui retire ce statut (et pourra réintroduire `:latest` si souhaité).

### Cas "docs only"

Quand un changement ne touche que la documentation (README, docs techniques, roadmap, changelog, procédures), il est suivi dans `suivi/changelog.md` sous `[Unreleased]`, mais ne force pas de bump dans `versions.json`.

## Source de vérité

Le fichier [`versions.json`](../versions.json) à la racine du dépôt est l'unique source de vérité. Il est lu par :
- `Makefile` — inject via `-ldflags` au build binaire local ; cible `make sync-versions`
- `ci/sync-versions.sh` — SemVer pour l’affichage ; tag flottant **`preview`** pour quickstart / landing install / Helm
- `scripts/quickstart.sh` — écrit `GOPROXIFY_*_TAG=preview` dans `.env`
- `services/*/Dockerfile` — ARG passé au build Docker
- Pipeline Harness `.harness/build.yaml` (`bump_version`) — bump PATCH puis `sync-versions.sh`
- Pipeline Harness `.harness/publish-ghcr.yaml` — tags SemVer **et** `:preview` sur `ghcr.io`

Les versions ldflags sont exposées au runtime via `internal/buildinfo` : bandeau de démarrage des services, `GET /api/v1/health` (admin + webapp), heartbeats Core/Agent (tuiles Infrastructure), Paramètres Admin / Core.

---

## Changelog

### [Unreleased] — Interactions Logs ↔ Prism

Bump au merge : **`admin` PATCH** `0.2.11` → `0.2.12`, **`webapp` PATCH** `0.2.4` → `0.2.5`.

#### Admin (PATCH)
- Corrélation logs : matching Agent élargi (message + variantes nom conteneur) ; filtre status `5xx` / préfixe
- Prism API : paramètres `ip` et `path` sur les agrégations

#### Webapp (PATCH)
- Logs : icône Corréler (fix onclick), cellules cliquables, chips, pont Prism
- Prism : drill-down IP/chemin/timeline, liens vers Logs

---

### [Unreleased] — Tokens API utilisateur (PAT)

À bumper au merge fonctionnel : **`admin` MINOR** (ex. `0.2.4` → `0.3.0`), **`webapp` MINOR** (ex. `0.2.1` → `0.3.0`). Core / Agent / Landing inchangés.

#### Admin (MINOR)
- PAT self-service `gpx_pat_*` : CRUD `/api/v1/me/tokens`, scopes ressource, hash SHA-256, expiration optionnelle
- API REST : `RequireAuth` (JWT session **ou** PAT) + gate de scopes pour les PAT
- MCP `/mcp` : **PAT uniquement** ; chaque outil MCP exige le scope correspondant ; intersection avec le rôle courant
- Distinct des tokens d’appairage `gpx_core_*` / `gpx_agent_*`

#### Webapp (MINOR)
- UI **Mes tokens API** — création (scopes + expiration), copie unique du secret, liste, révocation

#### Notes de compatibilité
- **Breaking soft MCP** : un client MCP configuré avec un JWT de session UI doit être migrés vers un PAT (Paramètres → Mes tokens API)
- L’API REST continue d’accepter le JWT de session ; les PAT sont un canal additionnel

---

### [0.2.1] — 2026-07-31

#### Admin `0.2.1`
- **Refonte RBAC complète** : rôles `admin`/`operator`/`viewer` avec vérifications de périmètre par équipe ; méthodes `Role.canRead()`, `Role.canWrite()`, `Role.canDelete()` exposées à l'UI via `state.role` ; contrôle d'accès appliqué sur tous les endpoints proxies, utilisateurs, équipes
- `GET /api/v1/me` retourne désormais le rôle RBAC et les scopes d'équipe pour initialiser `state.role`
- `internal/admin/rbac/rbac.go` : logique de vérification centralisée (canReadProxy, canWriteProxy, canDeleteProxy)

#### Webapp `0.2.1`
- **Page Trafic partagée Admin/Core** : `renderTraficPage({mode})` unique ; toolbar complète (Grouper/Trier/Import/CSV/sélecteur colonnes 2-5), filtres Statut/Type(HTTP·HTTPS·TCP·UDP·TCP+UDP)/Source(Docker·K8s·Managed), vue tuiles par défaut
- Mode Core : bandeau statut Core (nom/CPU/mém), pas de chips Core sur les cartes, pas de bouton "Nouveau flux" (admin only)
- État persistant (`window._tv/_tc/_tg/_ts/_tf`) survit à la navigation entre pages
- Extraction de `trafic.js` dans un module dédié `js/pages/trafic.js` (hors `pages-all.js`)
- Tous les boutons d'action conditionnés par `Role.canWrite()` / `Role.canDelete()`

---

### [0.2.0] — 2026-07-16

#### Admin `0.2.0`
- Serveur MCP (Model Context Protocol) JSON-RPC 2.0 + SSE, spec `2025-03-26`
  - 8 outils : `list_proxies`, `get_proxy`, `create_proxy`, `delete_proxy`, `list_nodes`, `list_alerts`, `get_metrics`, `list_backups`
  - 3 ressources : `goproxify://proxies`, `goproxify://nodes`, `goproxify://alerts`
- Nouvel endpoint `GET /internal/v1/nodes/metrics` (CPU/mém par nœud, utilisé par le LB adaptatif)
- Endpoint `GET /api/v1/logs/correlate` — corrélation temporelle des logs par domaine
- Endpoint `GET|PUT /api/v1/logs/settings` — gestion de la rétention des logs
- Endpoint `GET /api/v1/prism/backend-errors` — erreurs backend (Prism)

#### Core `0.2.0`
- **Load balancing adaptatif** : score = CPU×0.6 + Mém×0.4, poll `/internal/v1/nodes/metrics` toutes les 15 s
- **Canary routing** : `CanaryConfig` (weight %, sélection par header/cookie/pourcentage)
- **Shadow mirror** : duplication de requête en goroutine, timeout 5 s, sans bloquer la réponse
- **Routage conditionnel** : `Condition[]` — types `header`, `cookie`, `query`, `method`, `path_prefix`, `path_regex`
- **Middleware OIDC** : Authorization Code Flow complet, session HMAC-SHA256, provider `pocket_id`/`oidc`
- `SSOConfig` étendu : champ `OIDC *OIDCConfig` avec `issuer_url`, `client_id`, `client_secret`, `redirect_url`, `session_secret`, `username_claim`

#### Agent `0.2.0`
- **Support Podman** : auto-détection socket Docker/Podman ; rootless via `$XDG_RUNTIME_DIR/podman/podman.sock`
- **Support Kubernetes** : discovery via Watch API (`?watch=1`), in-cluster autodetect (SA token + CA), label `goproxify.enabled=true`
- Config : nouveau champ `docker.runtime` (`auto|docker|podman`) et section `kubernetes`

#### Webapp `0.2.0`
- Accordéon "Trafic avancé" dans la modale proxy : canary (backend, weight, header, cookie), shadow backend, conditions (ajout/suppression dynamique)
- Accordéon "Authentification SSO / OIDC" : provider select incluant `pocket_id`/`oidc`, champs OIDC complets
- `saveProxy()` collecte et envoie les champs canary/shadow/conditions/SSO vers l'API
- Onglet "Paramètres" dans la page Logs (rétention)
- Bouton "Corréler" sur chaque ligne de log avec modal de corrélation cross-service
- Panel "Erreurs backend" dans la section Prism

---

### [0.1.0] — 2026-07-15 *(release initiale)*

#### Tous les services `0.1.0` (admin, core, agent, webapp, landing)
- Structure du projet, binaire unique multi-composants
- Admin : API REST complète, UI Web (proxies, nœuds, logs, Prism, certificats, alertes, backups, cluster)
- Core : HTTP/HTTPS/HTTP2/HTTP3, WebSocket, gRPC, TCP/UDP L4, TLS terminaison + passthrough, WAF, rate limiting, cache Prism, mode cluster Raft
- Agent : discovery Docker (labels), télémétrie CPU/mémoire, mise à jour automatique, VPN WireGuard
- Landing : site vitrine statique servi par Nginx (`services/landing/`)
- Cache local Core (autonomie sans Admin), import de configs (nginx, Traefik, Caddy…)
- CLI : `admin`, `core`, `agent`, `token`, `backup`, `import`, `update`, `alert`, `status`, `access`, `nodes`, `declared`, `bootstrap`, `version`
