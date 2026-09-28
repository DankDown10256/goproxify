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
| `edge` | Data Plane — Reverse proxy HTTP/1·2·3, TCP/UDP L4 |
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

### `goproxify edge`

```
goproxify edge [-config <chemin>]
```

Sous-commandes locales (sans accès Admin) :

```
goproxify edge cache show
goproxify edge cache refresh
goproxify edge cache export [-output <fichier>]
goproxify edge cache clear

goproxify edge token create -name <nom> [-role admin|agent] [-ttl <durée>]
goproxify edge token list
goproxify edge token revoke <id>
```

**`edge cache`** — gestion du cache local (table de routage + certs sauvegardés).
La passerelle charge ce cache au démarrage si l'Admin est injoignable.

**`edge token`** — tokens d'authentification **locaux** de la passerelle (API interne port 8000).
Distinct de `goproxify token` qui parle à l'Admin.

Variables d'environnement :

| Variable | Défaut |
|----------|--------|
| `GPX_EDGE_CACHE_PATH` | `/etc/goproxify/edge-cache.gpx` |
| `GPX_EDGE_TOKENS_PATH` | `/etc/goproxify/edge-tokens.db` |
| `GPX_CONTROL_PLANE_AUTH_TOKEN` | — (dérive la clé de déchiffrement du cache) |

### `goproxify agent`

```
goproxify agent [-config <chemin>]
goproxify agent pair -edge <url> -join-token <token>
goproxify agent approve <agent-id> [-admin-url <url>] [-token <token>]
```

**Workflow appairage Agent → passerelle :**

1. Admin UI → Tokens → Créer → rôle `agent`, TTL `24h` → obtenir `gpx_join_*`
2. `goproxify agent pair -edge http://edge:8000 -join-token gpx_join_xxx`
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

Gestion des tokens d'appairage passerelle/Agent enregistrés dans l'Admin.

```
goproxify token create -role edge|agent -node <nom> [options]
  -role        edge | agent
  -node        Nom du nœud (ex: prod-edge-1)
  -ttl         Durée de validité (ex: 24h, 7d, 0 = permanent)
  -endpoint    URL de la passerelle (enregistrée si role=edge)
  -rbac-role   admin | operator | viewer (défaut: admin)

goproxify token list [-role edge|agent]
goproxify token revoke <id>
```

Exemples :

```bash
goproxify token create -role edge  -node prod-1 -endpoint http://edge:8000
goproxify token create -role agent -node app-2  -ttl 24h
goproxify token list
goproxify token revoke <id>
```

> Distinct de `goproxify edge token` (tokens locaux de la passerelle, sans Admin).

---

### `goproxify backup`

Sauvegardes et restauration.

```
goproxify backup create [-target admin|edge|all] [-output <dir>]
  -target  admin : snapshot SQLite Admin (.gpx-admin-backup)
           edge  : export table de routage (.gpx-edge-backup)
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
goproxify proxy metrics [-admin-url …] [-token …]
goproxify proxy delete  <id> [-y] [-admin-url …] [-token …]
  -y  Confirmation automatique
```

Exemples :

```bash
goproxify proxy list
goproxify proxy get app.example.fr
goproxify proxy metrics
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

### `goproxify architecture`

Contenu et historique de `architecture.json` (fichier de vérité de l'architecture : nœuds du wizard avec leur hôte et leurs capacités, Passerelles, périmètres, domaines). Chaque écriture qui change le fichier en conserve la version précédente.

```
goproxify architecture show [-version <nom>]
goproxify architecture versions
goproxify architecture restore -name <version>
```

`show` affiche l'architecture courante en JSON, ou une version conservée avec `-version` (sans la restaurer).

Exemple :

```bash
goproxify architecture show
goproxify architecture versions
goproxify architecture show -version architecture-20260926T070623359846127Z.json
goproxify architecture restore -name architecture-20260926T070623359846127Z.json
```

---

### `goproxify internal-ca`

Génère et gère une autorité de certification (CA) interne, pour émettre des certificats serveur/client internes hors ACME (services internes sans exposition publique).

```
goproxify internal-ca create-ca -name <nom> -cn <common-name> [-years N]
goproxify internal-ca list-ca
goproxify internal-ca issue -ca <id> -cn <cn> [-sans a,b] [-usage server|client] [-days N]
goproxify internal-ca list-certs -ca <id>
goproxify internal-ca revoke -ca <id> <certID>
```

Exemples :

```bash
goproxify internal-ca create-ca -name root -cn "GoProxify Internal Root" -years 10
goproxify internal-ca list-ca
goproxify internal-ca issue -ca abc123 -cn svc.internal.local -sans svc.internal.local,10.0.0.5 -usage server
goproxify internal-ca list-certs -ca abc123
goproxify internal-ca revoke -ca abc123 cert456
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

### `goproxify prism`

Analyse du trafic (mêmes données que la page Prism).

```
goproxify prism anomalies
  [-hours <n>]  [-edge <nœud>]  [-proxy <hôte>]
  [-admin-url …] [-token …]

goproxify prism geo
  [-level country|city]  [-limit <n>]
  [-hours <n>]  [-edge <nœud>]  [-proxy <hôte>]
  [-admin-url …] [-token …]
```

Exemples :

```bash
goproxify prism anomalies -hours 6 -edge paris-01
goproxify prism geo -level city -limit 20
```

---

### `goproxify alert`

Canaux de notification, règles d'alerte, et tests.

```
# Canaux
goproxify alert events [-days <n>] [-trigger <id>] [-node <passerelle>] [-limit <n>] [-admin-url …] [-token …]   # alertes déclenchées (30 jours)
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

# Événements et accusé de réception
goproxify alert events [-days N] [-trigger <t>] [-node <n>] [-limit N] [-admin-url …] [-token …]
goproxify alert ack <event-id> [-admin-url …] [-token …]
```

Types de canal (`alert channels create -file`, champ `type`) : `email`, `webhook`, `slack`, `teams`, `telegram`, `sms` (Twilio), `ntfy`, `gotify`, `jira`, `linear`, `github`, `gitlab`, `zammad`, `glpi`. `alert rules create`/`update` acceptent `group_window_sec` (secondes, défaut 0 = désactivé) : les événements qui correspondent à la règle dans cette fenêtre sont fusionnés en une seule notification au lieu d'une par événement. Ils acceptent aussi `escalation` (tableau `{after_sec, channels}`) : si l'événement n'est pas acquitté (`alert ack <event-id>`) avant `after_sec` secondes, il est renotifié vers `channels` (vide = canaux de la règle) ; les paliers déjà programmés se désactivent d'eux-mêmes dès l'accusé de réception.

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
goproxify domain create <domaine> [-edge <edge-id>] [-admin-url …] [-token …]
goproxify domain renew  <id> [-admin-url …] [-token …]
goproxify domain delete <id> [-y] [-admin-url …] [-token …]
  -y  Confirmation automatique
```

`list` affiche l'expiration en jours (⚠ si < 14 j) et la passerelle associé.

Exemples :

```bash
goproxify domain list
goproxify domain create app.example.fr -edge prod-edge-1
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

`list` affiche une colonne `ETAT` : `ok`, ou `échec xN` après N échecs consécutifs du rafraîchissement automatique (détail : `ip-profile get <id>`, champs `last_error` et `next_attempt_at`).

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

Sentinel (threat engine global), gestion des bans, config WAF par proxy, et moteur de règles automatiques.

```
# Config du moteur Sentinel
goproxify security threat get  [-edge <id>] [-admin-url …] [-token …]   # passerelle d'un groupe HA : config du groupe
goproxify security threat set  [-edge <id>] -file <threat-config.json> [-admin-url …] [-token …]
goproxify security threat simulate -file <threat-config.json> [-hours N] [-domain <d>] [-edge <id>] [-admin-url …] [-token …]   # dry-run : rejoue les logs, n'enregistre rien
# -edge : pour une passerelle membre d'un groupe HA, la config lue/écrite est celle du groupe (poussée à tous les membres)

# Bans
goproxify security bans list   [-edge <passerelle>] [-source <source>] [-active true|false] [-admin-url …] [-token …]
goproxify security bans add    -ip <ip> [-reason <raison>] [-ttl <durée>] [-admin-url …] [-token …]
goproxify security bans delete -id <ban-id> [-admin-url …] [-token …]

# WAF par proxy
goproxify security waf get -proxy <proxy-id> [-admin-url …] [-token …]
goproxify security waf set -proxy <proxy-id> -file <waf-config.json> [-admin-url …] [-token …]

# SLA de correction des CVE (délai attendu selon la gravité)
goproxify security cve sla get [-admin-url …] [-token …]
goproxify security cve sla set -file <sla.json> [-admin-url …] [-token …]
```

**`security threat`** — lit ou écrit la configuration du moteur Sentinel (fail2ban, seuils, whitelist globale…). Le paramètre `-edge` cible une passerelle spécifique dans un cluster multi-passerelle.

**`security threat simulate`** — rejoue les access logs récents (`-hours`, défaut 1, max 24 ; `-domain` pour un seul domaine) contre la config candidate du fichier, surchargée sur la config actuelle, et affiche le résultat en JSON : requêtes bloquées, faux positifs probables (`legit_blocked`), IP et bans, actuel vs candidat. Ne modifie rien. Voir `POST /api/v1/security/threat-config/simulate`.

**`security bans`** — liste, ajoute ou supprime des IPs bannies manuellement. `-ttl` accepte des durées Go (`1h`, `24h`, `7d`). `list` accepte `-edge` (nom du nœud ou id du token : les bans de cette passerelle et les bans globaux), `-source` et `-active true` (non expirés) ou `false` (expirés) ; la passerelle d’origine est affichée entre crochets.

**`security cve sla`** — lit ou écrit le délai de correction attendu des CVE (en jours après détection), par tranche de gravité CVSS ; réglage global (Admin `0.52.3`). Fichier `sla.json` :

```json
{ "critical_days": 7, "high_days": 14, "medium_days": 30, "low_days": 90 }
```

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

goproxify security cve sla get
goproxify security cve sla set -file sla.json

# Moteur de règles automatiques
goproxify security rules list   [-admin-url …] [-token …]
goproxify security rules get    <id> [-admin-url …] [-token …]
goproxify security rules create -file <rule.json> [-admin-url …] [-token …]
goproxify security rules update <id> -file <rule.json> [-admin-url …] [-token …]
goproxify security rules delete <id> [-y] [-admin-url …] [-token …]
goproxify security rules run    <id> [-dry-run] [-admin-url …] [-token …]

goproxify security rules silence list   [-admin-url …] [-token …]
goproxify security rules silence add    -name <nom> -starts <RFC3339> -ends <RFC3339> [-rules <id1,id2>] [-admin-url …] [-token …]
goproxify security rules silence delete <id> [-y] [-admin-url …] [-token …]

goproxify security rules history list          [-admin-url …] [-token …]
goproxify security rules history replay <id>   [-admin-url …] [-token …]

goproxify security rules pending list            [-admin-url …] [-token …]
goproxify security rules pending approve <id>    [-admin-url …] [-token …]
goproxify security rules pending reject  <id>    [-admin-url …] [-token …]

goproxify security rules export [-out <fichier.yaml>] [-admin-url …] [-token …]
goproxify security rules import -file <automation.yaml> [-admin-url …] [-token …]
```

**`security rules`** — CRUD sur les règles du moteur de règles automatiques. `rules run` déclenche une évaluation immédiate ; `-dry-run` (défaut) affiche le résultat de la condition sans exécuter l'action. `rules silence` gère les fenêtres de silence, communes au moteur de règles et au moteur d'alertes : `add` sans `-rules` s'applique à toutes les règles des deux moteurs ; avec `-rules id1,id2` (IDs `security rules list` et/ou `alert rules list`), seulement à celles-ci. `rules history` consulte le journal d'exécution ; `replay` rejoue l'action d'une entrée en échec sans réévaluer la condition. Une règle créée avec `"require_approval": true` (`rule.json`) met son action en attente au lieu de l'exécuter ; `rules pending list` liste les actions en attente, `approve`/`reject` décident. `rules export`/`import` échangent règles, canaux et silences en un document YAML (GitOps) ; `export` sans `-out` écrit sur la sortie standard ; `import` upserte par nom. `rules versions` consulte les instantanés d'une règle (un par création/modification/restauration, 20 derniers conservés) et permet un retour arrière (`restore`, qui devient lui-même une nouvelle version).

Exemple de fichier règle (`rule.json`) :

```json
{
  "name": "CVE critique → désactiver proxy",
  "enabled": true,
  "condition": { "type": "cve_critical", "threshold": 9.0 },
  "action":    { "type": "disable_proxy" },
  "cooldown_sec": 600
}
```

**`security schedule`** — planifications (cron) : exécutent une action du moteur de règles à heure fixe (`notify`, `ban_ip`, `disable_proxy`, `enable_strict`, `webhook_call`, `run_backup`), sans condition à évaluer. `cron_expr` est une expression standard à 5 champs (`minute heure jour-du-mois mois jour-de-semaine`, ex. `0 3 * * *` = tous les jours à 3h). `run` déclenche l'action immédiatement, indépendamment du cron. `history` liste les 100 dernières exécutions.

Exemple de fichier planification (`task.json`) :

```json
{
  "name": "Sauvegarde nocturne",
  "cron_expr": "0 3 * * *",
  "action": { "type": "run_backup", "backup_retention": 7 },
  "enabled": true
}
```

**`security playbook`** — enchaîne plusieurs étapes (`action`, `wait`, `condition`, `approval`), contrairement à une règle (une condition → une action). Déclenché comme action d'une règle ou d'une planification (`{ "type": "run_playbook", "playbook_id": "…" }`), ou manuellement (`run`). `history` liste les exécutions (`playbook_runs`) avec leur statut (`running`, `waiting_approval`, `completed`, `failed`, `stopped`) et leur journal détaillé ; `approve`/`reject` décident d'une exécution suspendue à une étape `approval` (`<run-id>`, pas l'ID du playbook).

Exemple de fichier playbook (`playbook.json`) :

```json
{
  "name": "Incident CVE critique",
  "steps": [
    { "type": "action", "action": { "type": "notify", "notify_severity": "critical", "notify_message": "CVE critique détectée" } },
    { "type": "approval" },
    { "type": "action", "action": { "type": "disable_proxy" } },
    { "type": "wait", "wait_sec": 900 },
    { "type": "condition", "condition": { "type": "cve_critical", "cvss_threshold": 9.0 } },
    { "type": "action", "action": { "type": "run_backup", "backup_retention": 5 } }
  ],
  "enabled": true
}
```

---

### `goproxify containers`

Conteneurs Docker découverts par les Agents (lecture seule). Agrège les résultats de toutes les passerelles connectées.

```
goproxify containers [list] [-admin-url …] [-token …]
```

Affiche pour chaque conteneur : le host, TLS, la passerelle source, l'Agent et les backends.

Exemples :

```bash
goproxify containers
goproxify containers list
```

---

### `goproxify me`

Profil de l'utilisateur connecté et gestion de ses tokens API personnels (PAT `gpx_pat_*`).

```
goproxify me get    [-admin-url …] [-token …]
goproxify me update [-email <email>] [-admin-url …] [-token …]
goproxify me passwd -current <mdp-actuel> -password <nouveau-mdp> [-admin-url …] [-token …]

goproxify me tokens list   [-admin-url …] [-token …]
goproxify me tokens scopes [-admin-url …] [-token …]
goproxify me tokens create -label <nom> -scopes <s1,s2,…> [-expires <RFC3339>] [-admin-url …] [-token …]
goproxify me tokens revoke <id> [-admin-url …] [-token …]
```

`tokens scopes` liste les scopes disponibles pour votre compte (dépend de votre rôle).
`tokens create` affiche la valeur du token une seule fois à la création.

Exemples :

```bash
goproxify me get
goproxify me tokens list
goproxify me tokens scopes
goproxify me tokens create -label "CI pipeline" -scopes "proxies:read,logs:read"
goproxify me tokens create -label "tmp" -scopes "proxies:read" -expires 2026-12-31T23:59:59Z
goproxify me tokens revoke <id>
```

---

### `goproxify status`

État du cluster — nœuds (Passerelle, Agent HTTP) et agents WS.

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
goproxify access config get        -edge <nom>
goproxify access config set        -edge <nom> -enabled true|false [-public-host <host>] [-ha-session-mode sticky|shared]
goproxify access config push       -edge <nom>

goproxify access destinations list   -edge <nom>
goproxify access destinations create -edge <nom> -name <n> -kind ssh|docker -host <h> -port <p> [-tags a,b]
goproxify access destinations delete -id <uuid>

goproxify access users list          [-edge <nom>]
goproxify access users invite        -email <email> -home-edge <nom> [-tags a,b]
goproxify access users update        -id <uuid> -status active|disabled
goproxify access users resend        -id <uuid>
goproxify access users delete        -id <uuid>

goproxify access policy get           -edge <nom>
goproxify access policy set           -edge <nom> [-hours true -days 1,2,3,4,5 -start 07:00 -end 20:00 -tz Europe/Paris -ip <cidr,…> -idle <min> -record true -retention <jours>]
goproxify access recordings list     -edge <nom>
goproxify access recordings get      -edge <nom> -id <uuid> > session.cast
goproxify access recordings delete   -edge <nom> -id <uuid>
goproxify access requests list        -edge <nom> [-status pending]
goproxify access requests approve     -id <uuid> [-minutes <n>]
goproxify access requests deny        -id <uuid>
goproxify access requests revoke      -id <uuid>
goproxify access sessions list        -edge <nom>
goproxify access sessions watch       -edge <nom> -id <uuid>
goproxify access sessions terminate   -edge <nom> -id <uuid>
goproxify access audit list          [-edge <nom>] [-limit <n>]

goproxify access templates list
goproxify access templates get  -key <clé>
goproxify access templates set  -key <clé> -body-file <chemin>
goproxify access templates push
```

---

### `goproxify nodes`

Nœuds Infrastructure — liste, état temps réel (`live` : santé, débit req/s et score de risque sur 60 s, cf. `GET /api/v1/nodes/live`), acceptation et rejet des nœuds en attente.

```
goproxify nodes list         [-role edge|agent]
goproxify nodes live
goproxify nodes accept       -id <pending-id>
goproxify nodes reject       -id <pending-id>
```

---

### `goproxify declared`

Nœuds déclarés via le wizard d'architecture (upsert par rôle + nom).

```
goproxify declared list
goproxify declared create -role edge|agent -name <nom> [-region <r>] [-environment <e>] [-config '<json>']
goproxify declared delete  -id <dn_...>
```

---

### `goproxify bootstrap`

Tickets QR / `curl|bash` pour intégrer un hôte (lien `/i/{token}`).

```
goproxify bootstrap create [options]
  -host <nom>              Nom de l'hôte
  -edge-endpoint <url>     Endpoint passerelle (ex: http://192.0.2.10:8000)
  -ttl <heures>            TTL du ticket (défaut 24, max 168)
  -auto-accept true|false  Auto-accept des nœuds liés (défaut true)
  -node-names a,b          Noms pré-approuvés
  -payload '{...}'         Payload JSON
  -payload-file <path>     Payload depuis un fichier JSON
  -no-qr                   Omet le champ qr_code (base64) dans la sortie
```

Exemples :

```bash
goproxify bootstrap create -host host-1 -edge-endpoint http://192.0.2.10:8000 -node-names edge-main -no-qr
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
| `GPX_EDGE_CACHE_PATH` | Utilisé pour déduire le répertoire si `GPX_DATA_PATH` absent |

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
goproxify edge   -config /etc/goproxify/edge.json
goproxify agent  -config /etc/goproxify/agent.json
```

Les variables `GPX_*` ont priorité sur les valeurs du fichier de config.
