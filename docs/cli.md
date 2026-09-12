# GoProxify — Référence CLI

Le binaire `goproxify` regroupe tous les rôles et commandes opérationnelles.

```
goproxify <commande> [options]
```

---

## Commandes de service

Ces commandes démarrent un composant en tant que processus long.

| Commande | Rôle |
|----------|------|
| `admin` | Control Plane — UI Web, API REST, MCP, alerting |
| `core` | Data Plane — Reverse proxy HTTP/1·2·3, TCP/UDP L4 |
| `agent` | Discovery Docker & métriques |
| `landing` | Page de présentation (optionnel) |

### `goproxify admin`

```
goproxify admin [-config <chemin>]
```

Options spéciales :

```
goproxify admin -reset-password -email <email> -password <nouveau-mdp>
```

Réinitialise le mot de passe d'un utilisateur sans démarrer le serveur.

### `goproxify core`

```
goproxify core [-config <chemin>]
```

Sous-commandes locales (sans accès Admin) :

```
goproxify core cache show
goproxify core cache refresh
goproxify core cache export [-output <fichier>]
goproxify core cache clear

goproxify core token create -name <nom> [-role admin|agent] [-ttl <durée>]
goproxify core token list
goproxify core token revoke <id>
```

**`core cache`** — gestion du cache local (table de routage + certs sauvegardés).
Le Core charge ce cache au démarrage si l'Admin est injoignable.

**`core token`** — tokens d'authentification **locaux** du Core (API interne port 8000).
Distinct de `goproxify token` qui parle à l'Admin.

Variables d'environnement :

| Variable | Défaut |
|----------|--------|
| `GPX_CORE_CACHE_PATH` | `/etc/goproxify/core-cache.gpx` |
| `GPX_CORE_TOKENS_PATH` | `/etc/goproxify/core-tokens.db` |
| `GPX_CONTROL_PLANE_AUTH_TOKEN` | — (dérive la clé de déchiffrement du cache) |

### `goproxify agent`

```
goproxify agent [-config <chemin>]
goproxify agent pair -core <url> -join-token <token>
goproxify agent approve <agent-id> [-admin-url <url>] [-token <token>]
```

**Workflow appairage Agent → Core :**

1. Admin UI → Tokens → Créer → rôle `agent`, TTL `24h` → obtenir `gpx_join_*`
2. `goproxify agent pair -core http://core:8000 -join-token gpx_join_xxx`
3. `goproxify agent` → l'Agent se connecte, statut `pending`
4. `goproxify agent approve <agent-id>` (ou approbation dans l'UI)
5. L'Agent reçoit son secret HMAC et passe en statut `approved`

---

## Commandes opérationnelles

Ces commandes parlent à l'Admin via HTTP.

**Auth commune :**

```
-admin-url <url>   URL Admin (ou GPX_CONTROLPLANE_ADMIN_ENDPOINT)
-token <token>     JWT session ou PAT (ou GPX_CONTROLPLANE_AUTH_TOKEN)
```

---

### `goproxify token`

Gestion des tokens d'appairage Core/Agent enregistrés dans l'Admin.

```
goproxify token create -role core|agent -node <nom> [options]
  -role        core | agent
  -node        Nom du nœud (ex: prod-core-1)
  -ttl         Durée de validité (ex: 24h, 7d, 0 = permanent)
  -endpoint    URL du Core (enregistrée si role=core)
  -rbac-role   admin | operator | viewer (défaut: admin)

goproxify token list [-role core|agent]
goproxify token revoke <id>
```

Exemples :

```bash
goproxify token create -role core  -node prod-1 -endpoint http://core:8000
goproxify token create -role agent -node app-2  -ttl 24h
goproxify token list
goproxify token revoke <id>
```

> Distinct de `goproxify core token` (tokens locaux du Core, sans Admin).

---

### `goproxify backup`

Sauvegardes et restauration.

```
goproxify backup create [-target admin|core|all] [-output <dir>]
  -target  admin : snapshot SQLite Admin (.gpx-admin-backup)
           core  : export table de routage (.gpx-core-backup)
           all   : les deux (défaut)
  -output  Répertoire de destination (défaut: .)

goproxify backup list

goproxify backup restore -file <chemin> [-yes]
goproxify backup restore -id <snapshot-id>  [-yes]
```

Exemples :

```bash
goproxify backup create
goproxify backup create -target admin -output /var/backups/goproxify
goproxify backup list
goproxify backup restore -file backup-2026-08-01.gpx-admin-backup -yes
```

---

### `goproxify import`

Import de configurations existantes (nginx, Traefik, Caddy, HAProxy, CSV, JSON).

```
goproxify import -file <chemin> [-format <format>] [-dry-run]
  -file     Fichier de configuration source
  -format   nginx (défaut auto) | traefik-yaml | caddy | haproxy | csv | json
  -dry-run  Affiche ce qui serait importé sans appliquer
```

Exemples :

```bash
goproxify import -file nginx.conf -dry-run
goproxify import -file traefik.yml -format traefik-yaml
```

---

### `goproxify alert`

Test des canaux de notification.

```
goproxify alert test -channel <channel-id>
goproxify alert test -all
```

---

### `goproxify status`

État du cluster — nœuds (Core, Agent HTTP) et agents WS.

```
goproxify status [-short]
  -short   Résumé compact (compteurs uniquement)
```

Exemples :

```bash
goproxify status
goproxify status -short
```

---

### `goproxify access`

GoProxify Access — portail opérateur (terminal web, SSH UUID, coffre secrets).

```
goproxify access config get        -core <nom>
goproxify access config set        -core <nom> -enabled true|false [-public-host <host>]
goproxify access config push       -core <nom>

goproxify access destinations list   -core <nom>
goproxify access destinations create -core <nom> -name <n> -kind ssh|docker -host <h> -port <p> [-tags a,b]
goproxify access destinations delete -id <uuid>

goproxify access users list          [-core <nom>]
goproxify access users invite        -email <email> -home-core <nom> [-tags a,b]
goproxify access users update        -id <uuid> -status active|disabled
goproxify access users resend        -id <uuid>
goproxify access users delete        -id <uuid>

goproxify access audit list          [-core <nom>] [-limit <n>]

goproxify access templates list
goproxify access templates get  -key <clé>
goproxify access templates set  -key <clé> -body-file <chemin>
goproxify access templates push
```

---

### `goproxify nodes`

Nœuds Infrastructure — liste, acceptation et rejet des nœuds en attente.

```
goproxify nodes list         [-role core|agent]
goproxify nodes accept       -id <pending-id>
goproxify nodes reject       -id <pending-id>
```

---

### `goproxify declared`

Nœuds déclarés via le wizard d'architecture (upsert par rôle + nom).

```
goproxify declared list
goproxify declared create -role core|agent -name <nom> [-region <r>] [-environment <e>] [-config '<json>']
goproxify declared delete  -id <dn_...>
```

---

### `goproxify bootstrap`

Tickets QR / `curl|bash` pour intégrer un hôte (lien `/i/{token}`).

```
goproxify bootstrap create [options]
  -host <nom>              Nom de l'hôte
  -core-endpoint <url>     Endpoint Core (ex: http://192.0.2.10:8000)
  -ttl <heures>            TTL du ticket (défaut 24, max 168)
  -auto-accept true|false  Auto-accept des nœuds liés (défaut true)
  -node-names a,b          Noms pré-approuvés
  -payload '{...}'         Payload JSON
  -payload-file <path>     Payload depuis un fichier JSON
  -no-qr                   Omet le champ qr_code (base64) dans la sortie
```

Exemples :

```bash
goproxify bootstrap create -host edge-1 -core-endpoint http://192.0.2.10:8000 -node-names core-edge -no-qr
curl -fsSL "$(goproxify bootstrap create -host h1 -no-qr | jq -r .script_url)" | bash
```

---

### `goproxify update`

Mise à jour des images Docker (via l'Agent — non encore implémenté).

```
goproxify update check    [-container <nom>]
goproxify update apply    -container <nom> | -all [-prune] [-dry-run]
goproxify update rollback -container <nom>
```

---

### `goproxify migrate-yaml`

Convertit les fichiers de configuration proxy du format JSON (legacy) vers YAML.

```
goproxify migrate-yaml
```

Lit tous les fichiers `*.json` dans le répertoire de données (`/etc/goproxify` ou `GPX_DATA_PATH`) et les convertit en `*.yaml`. Les fichiers JSON d'origine sont conservés ; une erreur de conversion est signalée sans interrompre les autres fichiers.

Variables d'environnement :

| Variable | Usage |
|----------|-------|
| `GPX_DATA_PATH` | Répertoire racine des données (prioritaire) |
| `GPX_CORE_CACHE_PATH` | Utilisé pour déduire le répertoire si `GPX_DATA_PATH` absent |

> Cette commande est destinée à la migration ponctuelle depuis les versions < 0.2. Les nouvelles installations utilisent directement le format YAML.

---

### `goproxify version`

Affiche les versions de tous les composants embarqués.

---

## Variables d'environnement communes

| Variable | Usage |
|----------|-------|
| `GPX_CONTROLPLANE_ADMIN_ENDPOINT` | URL Admin (remplace `-admin-url`) |
| `GPX_CONTROLPLANE_AUTH_TOKEN` | Token / PAT Admin (remplace `-token`) |
| `GPX_<SECTION>_<KEY>` | Surcharge n'importe quelle clé de config JSON |

Voir `.env.example` pour la liste complète des variables de configuration.

---

## Configuration JSON

Chaque composant accepte un fichier JSON optionnel (défaut : `./internal/<composant>/config.json`).

```
goproxify admin  -config /etc/goproxify/admin.json
goproxify core   -config /etc/goproxify/core.json
goproxify agent  -config /etc/goproxify/agent.json
```

Les variables `GPX_*` ont priorité sur les valeurs du fichier de config.
