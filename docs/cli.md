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

### `goproxify proxy`

Gestion des proxies (lecture et cycle de vie).

```
goproxify proxy list    [-admin-url …] [-token …]
goproxify proxy get     <id> [-admin-url …] [-token …]
goproxify proxy enable  <id> [-admin-url …] [-token …]
goproxify proxy disable <id> [-admin-url …] [-token …]
goproxify proxy delete  <id> [-y] [-admin-url …] [-token …]
  -y  Confirmation automatique
```

Exemples :

```bash
goproxify proxy list
goproxify proxy get app.example.fr
goproxify proxy disable app.example.fr
goproxify proxy delete app.example.fr -y
```

---

### `goproxify cert`

Gestion des certificats TLS (ACME / Let's Encrypt).

```
goproxify cert list   [-admin-url …] [-token …]
goproxify cert obtain <domaine> [-admin-url …] [-token …]
goproxify cert delete <domaine> [-admin-url …] [-token …]
```

`list` affiche le domaine, le statut, le nombre de jours avant expiration (⚠ si < 14 j) et l'émetteur.

Exemples :

```bash
goproxify cert list
goproxify cert obtain app.example.fr
goproxify cert delete old.example.fr
```

---

### `goproxify user`

Gestion des utilisateurs de l'Administration.

```
goproxify user list   [-admin-url …] [-token …]
goproxify user get    <id> [-admin-url …] [-token …]
goproxify user create -email <email> [-password <mdp>] [-role admin|operator|viewer] [-admin-url …] [-token …]
goproxify user update <id> [-role admin|operator|viewer] [-status active|disabled] [-admin-url …] [-token …]
goproxify user passwd <id> -password <nouveau-mdp> [-admin-url …] [-token …]
goproxify user delete <id> [-y] [-admin-url …] [-token …]
```

Exemples :

```bash
goproxify user list
goproxify user create -email ops@example.fr -role operator
goproxify user update <id> -status disabled
goproxify user passwd <id> -password s3cret
goproxify user delete <id> -y
```

---

### `goproxify audit`

Journal d'audit des actions administratives.

```
goproxify audit list   [-actor <email>] [-action <action>] [-limit <n>] [-admin-url …] [-token …]
goproxify audit export [-output <fichier.csv>] [-admin-url …] [-token …]
```

Exemples :

```bash
goproxify audit list -actor admin@example.fr -limit 20
goproxify audit export -output /var/log/audit-2026.csv
```

---

### `goproxify logs`

Logs d'accès et logs système.

```
goproxify logs list
  [-level debug|info|warn|error]
  [-domain <host>]
  [-ip <ip>]
  [-method GET|POST|…]
  [-status <code>]
  [-path <préfixe>]
  [-search <texte>]
  [-from <RFC3339>]  [-to <RFC3339>]
  [-limit <n>]  [-page <n>]
  [-admin-url …] [-token …]

goproxify logs export
  [-format csv|json]
  [-output <fichier>]
  [-level …] [-domain …] [-ip …] [-from …] [-to …]
  [-admin-url …] [-token …]
```

Exemples :

```bash
goproxify logs list -domain app.example.fr -status 5xx -limit 100
goproxify logs list -ip 1.2.3.4 -from 2026-09-01T00:00:00Z
goproxify logs export -format json -output access.json
```

---

### `goproxify alert`

Canaux de notification, règles d'alerte, et tests.

```
# Canaux
goproxify alert channels list   [-admin-url …] [-token …]
goproxify alert channels get    <id> [-admin-url …] [-token …]
goproxify alert channels create -file <channel.json> [-admin-url …] [-token …]
goproxify alert channels update <id> -file <channel.json> [-admin-url …] [-token …]
goproxify alert channels delete <id> [-y] [-admin-url …] [-token …]

# Règles
goproxify alert rules list   [-admin-url …] [-token …]
goproxify alert rules get    <id> [-admin-url …] [-token …]
goproxify alert rules create -file <rule.json> [-admin-url …] [-token …]
goproxify alert rules update <id> -file <rule.json> [-admin-url …] [-token …]
goproxify alert rules delete <id> [-y] [-admin-url …] [-token …]

# Tests
goproxify alert test -channel <id> [-admin-url …] [-token …]
goproxify alert test -all          [-admin-url …] [-token …]
```

Exemples :

```bash
goproxify alert channels list
goproxify alert channels create -file slack-channel.json
goproxify alert rules create -file cpu-alert.json
goproxify alert test -channel <id>
goproxify alert test -all
```

---

### `goproxify snippet`

Snippets de sécurité réutilisables (WAF, Sentinel, rate-limit…).

```
goproxify snippet list   [-admin-url …] [-token …]
goproxify snippet get    <id> [-admin-url …] [-token …]
goproxify snippet create -file <snippet.json> [-admin-url …] [-token …]
goproxify snippet update <id> -file <snippet.json> [-admin-url …] [-token …]
goproxify snippet delete <id> [-admin-url …] [-token …]
```

Exemple de fichier `snippet.json` :

```json
{
  "name": "waf-strict",
  "type": "waf",
  "config": { "enabled": true, "mode": "block", "anomaly_threshold": 5 }
}
```

Exemples :

```bash
goproxify snippet list
goproxify snippet create -file waf-strict.json
goproxify snippet update <id> -file waf-strict.json
goproxify snippet delete <id>
```

---

### `goproxify domain`

Domaines gérés par ACME (certificats Let's Encrypt dédiés).

```
goproxify domain list   [-admin-url …] [-token …]
goproxify domain get    <id> [-admin-url …] [-token …]
goproxify domain create <domaine> [-core <core-id>] [-admin-url …] [-token …]
goproxify domain renew  <id> [-admin-url …] [-token …]
goproxify domain delete <id> [-y] [-admin-url …] [-token …]
  -y  Confirmation automatique
```

`list` affiche l'expiration en jours (⚠ si < 14 j) et le Core associé.

Exemples :

```bash
goproxify domain list
goproxify domain create app.example.fr -core prod-core-1
goproxify domain renew <id>
goproxify domain delete <id> -y
```

---

### `goproxify agent-mgmt`

Agents Docker enregistrés auprès de l'Admin (distinct de `goproxify agent` qui démarre le processus).

```
goproxify agent-mgmt list    [-admin-url …] [-token …]
goproxify agent-mgmt get     <id> [-admin-url …] [-token …]
goproxify agent-mgmt approve <id> [-admin-url …] [-token …]
goproxify agent-mgmt revoke  <id> [-admin-url …] [-token …]
goproxify agent-mgmt delete  <id> [-y] [-admin-url …] [-token …]
```

Exemples :

```bash
goproxify agent-mgmt list
goproxify agent-mgmt approve <id>
goproxify agent-mgmt revoke  <id>
```

---

### `goproxify settings`

Configuration de l'Admin.

```
goproxify settings smtp get  [-admin-url …] [-token …]
goproxify settings smtp set  -file <smtp.json> [-admin-url …] [-token …]
goproxify settings smtp test [-admin-url …] [-token …]
```

Exemple de fichier `smtp.json` :

```json
{
  "host": "smtp.example.fr",
  "port": 587,
  "username": "noreply@example.fr",
  "password": "s3cret",
  "from": "GoProxify <noreply@example.fr>",
  "tls": true
}
```

Exemples :

```bash
goproxify settings smtp get
goproxify settings smtp set -file smtp.json
goproxify settings smtp test
```

#### MFA serveur

```
goproxify settings mfa sms     get [-admin-url …] [-token …]
goproxify settings mfa sms     set -file <sms.json> [-admin-url …] [-token …]
goproxify settings mfa webauthn get [-admin-url …] [-token …]
goproxify settings mfa webauthn set -file <webauthn.json> [-admin-url …] [-token …]
```

Exemple `sms.json` :

```json
{ "provider": "twilio", "api_sid": "AC…", "api_secret": "…", "from": "+33600000000" }
```

Exemple `webauthn.json` :

```json
{ "rp_id": "admin.example.fr", "rp_origin": "https://admin.example.fr", "display_name": "GoProxify" }
```

> **Cas de déblocage** : si `rp_origin` est incorrect, personne ne peut se connecter via WebAuthn.
> Corrigez-le avec `settings mfa webauthn set` sans passer par l'UI.

```bash
goproxify settings mfa webauthn get
goproxify settings mfa webauthn set -file webauthn.json
goproxify settings mfa sms get
goproxify settings mfa sms set -file sms.json
```

---

### `goproxify auth-provider`

Fournisseurs d'authentification externe (OIDC, SAML, LDAP…).

```
goproxify auth-provider list    [-admin-url …] [-token …]
goproxify auth-provider get     <id> [-admin-url …] [-token …]
goproxify auth-provider create  -file <provider.json> [-admin-url …] [-token …]
goproxify auth-provider update  <id> -file <provider.json> [-admin-url …] [-token …]
goproxify auth-provider enable  <id> [-admin-url …] [-token …]
goproxify auth-provider disable <id> [-admin-url …] [-token …]
goproxify auth-provider delete  <id> [-y] [-admin-url …] [-token …]
```

Exemple de fichier `provider.json` (OIDC) :

```json
{
  "name": "Google",
  "type": "oidc",
  "enabled": true,
  "config": {
    "client_id": "xxx.apps.googleusercontent.com",
    "client_secret": "GOCSPX-…",
    "issuer": "https://accounts.google.com"
  }
}
```

Exemples :

```bash
goproxify auth-provider list
goproxify auth-provider create -file google-oidc.json
goproxify auth-provider enable  <id>
goproxify auth-provider disable <id>
goproxify auth-provider delete  <id> -y
```

---

### `goproxify teams`

Équipes RBAC — regroupement d'utilisateurs avec un rôle commun.

```
goproxify teams list   [-admin-url …] [-token …]
goproxify teams get    <id> [-admin-url …] [-token …]
goproxify teams create <nom> [-role admin|operator|viewer] [-admin-url …] [-token …]
goproxify teams update <id> [-name <nom>] [-role admin|operator|viewer] [-admin-url …] [-token …]
goproxify teams delete <id> [-y] [-admin-url …] [-token …]

goproxify teams members list   <team-id> [-admin-url …] [-token …]
goproxify teams members add    <team-id> -user <user-id> [-admin-url …] [-token …]
goproxify teams members remove <team-id> -user <user-id> [-admin-url …] [-token …]
```

Exemples :

```bash
goproxify teams list
goproxify teams create ops-team -role operator
goproxify teams members list   <team-id>
goproxify teams members add    <team-id> -user <user-id>
goproxify teams members remove <team-id> -user <user-id>
goproxify teams delete <team-id> -y
```

---

### `goproxify ip-profile`

Profils IP — listes blanches/noires basées sur CIDR, pays (GeoIP) ou réputation.

```
goproxify ip-profile list   [-admin-url …] [-token …]
goproxify ip-profile get    <id> [-admin-url …] [-token …]
goproxify ip-profile create -file <profile.json> [-admin-url …] [-token …]
goproxify ip-profile update <id> -file <profile.json> [-admin-url …] [-token …]
goproxify ip-profile delete <id> [-y] [-admin-url …] [-token …]
```

Exemple de fichier `profile.json` :

```json
{
  "name": "blocklist-scanners",
  "action": "block",
  "cidrs": ["1.2.3.0/24", "5.6.7.8"],
  "countries": ["CN", "RU"],
  "description": "IPs de scanners connus"
}
```

Exemples :

```bash
goproxify ip-profile list
goproxify ip-profile create -file blocklist.json
goproxify ip-profile update <id> -file blocklist.json
goproxify ip-profile delete <id> -y
```

---

### `goproxify security`

Sentinel (threat engine global), gestion des bans, et config WAF par proxy.

```
# Config du moteur Sentinel
goproxify security threat get  [-core <id>] [-admin-url …] [-token …]
goproxify security threat set  [-core <id>] -file <threat-config.json> [-admin-url …] [-token …]

# Bans
goproxify security bans list   [-admin-url …] [-token …]
goproxify security bans add    -ip <ip> [-reason <raison>] [-ttl <durée>] [-admin-url …] [-token …]
goproxify security bans delete -id <ban-id> [-admin-url …] [-token …]

# WAF par proxy
goproxify security waf get -proxy <proxy-id> [-admin-url …] [-token …]
goproxify security waf set -proxy <proxy-id> -file <waf-config.json> [-admin-url …] [-token …]
```

**`security threat`** — lit ou écrit la configuration du moteur Sentinel (fail2ban, seuils, whitelist globale…). Le paramètre `-core` cible un Core spécifique dans un cluster multi-Core.

**`security bans`** — liste, ajoute ou supprime des IPs bannies manuellement. `-ttl` accepte des durées Go (`1h`, `24h`, `7d`).

**`security waf`** — lit (`get`) ou met à jour (`set`) les champs `waf` et `sentinel_whitelist` d'un proxy sans toucher au reste de sa configuration. Le fichier JSON peut contenir uniquement les clés à modifier :

```json
{
  "waf": {
    "enabled": true,
    "mode": "block",
    "anomaly_threshold": 10,
    "behavior_enabled": true
  },
  "sentinel_whitelist": ["10.0.0.0/8", "192.168.1.5"]
}
```

Exemples :

```bash
goproxify security threat get
goproxify security threat set -file threat.json

goproxify security bans list
goproxify security bans add -ip 1.2.3.4 -reason "scan" -ttl 24h
goproxify security bans delete -id <ban-id>

goproxify security waf get -proxy app.example.fr
goproxify security waf set -proxy app.example.fr -file waf.json
```

---

### `goproxify containers`

Conteneurs Docker découverts par les Agents (lecture seule). Agrège les résultats de tous les Cores connectés.

```
goproxify containers [list] [-admin-url …] [-token …]
```

Affiche pour chaque conteneur : le host, TLS, le Core source, l'Agent et les backends.

Exemples :

```bash
goproxify containers
goproxify containers list
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
