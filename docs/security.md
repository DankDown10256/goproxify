# Sécurité

GoProxify embarque plusieurs moteurs de sécurité indépendants, complémentaires et configurables sans redémarrage (sauf timeouts serveur).

---

## Architecture des couches de sécurité

Les moteurs s'appliquent dans cet ordre sur chaque connexion entrante :

```
Connexion TCP/TLS
      │
      ▼
 [1] Sentinel         — avant tout routage : rate limit global, signaux comportementaux, listes IP
      │
      ▼
 [2] Bans IP          — IP bannie en base (Sentinel, Fail2Ban, CrowdSec, manuel) → 403 immédiat
      │
      ▼
 [3] Routage / proxy  — résolution de la route, correspondance du proxy
      │
      ▼
 [4] WAF              — inspection de la requête (et de la réponse) par règles OWASP CRS-4
      │
      ▼
 Backend applicatif
```

---

## WAF (Web Application Firewall)

Moteur natif Go, sans dépendance ModSecurity ni CGO. Inspiré de l'OWASP CRS-4.

### Modes

| Mode | Comportement |
|------|-------------|
| `block` | Bloque la requête (403) dès qu'une règle se déclenche |
| `detect` | Laisse passer, journalise les règles déclenchées dans l'access log et les métriques |
| désactivé | Aucune inspection |

### Scoring anomalie

Chaque règle contribue un score (1–5 selon la sévérité). Le seuil `anomaly_threshold` définit le score cumulatif à partir duquel la requête est bloquée. À `0` (défaut), le premier déclenchement bloque.

| Sévérité | Score |
|----------|-------|
| CRITICAL | 5 |
| HIGH     | 4 |
| MEDIUM   | 3 |
| LOW      | 1 |

### Jeux de règles OWASP CRS-4

| ID catégorie | IDs | Description |
|---|---|---|
| `sqli` | 942100–942999 | SQL Injection (UNION SELECT, opérateurs logiques, time-based blind) |
| `xss` | 941100–941999 | Cross-Site Scripting (balises script, événements JS, DOM manipulation) |
| `lfi` / `traversal` | 930100–930199 | Path Traversal, Local File Inclusion (`../../`, `/etc/passwd`) |
| `rce` | 932100–932999 | Command Injection (`;bash`, `\|cmd`, `$()`, shell bypass) |
| `php` | 933100–933999 | PHP Injection (`<?php`, `eval()`, `shell_exec()`, `base64_decode()`) |
| `ssrf` | 934100–934199 | SSRF (schemes `file://`, `gopher://`, `dict://`, IPs internes) |
| `scanner` | 913100–913999 | Détection de scanners (nikto, sqlmap, nuclei, burpsuite…) via User-Agent |
| `java` | 944100–944999 | Java / Log4Shell (`${jndi:ldap://…}`), Spring EL, gadgets de désérialisation |
| `rfi` | 931100–931999 | Remote File Inclusion (URLs distantes, wrappers PHP : `php://filter`, `phar://`) |
| `nodejs` | 934200–934999 | NodeJS / Prototype Pollution (`__proto__`, `constructor.prototype`, `require()`) |
| `smuggling` | 920200–920999 | HTTP Request Smuggling (TE+CL simultanés, chunked encoding obfusqué) |
| `restricted` | 930200–930999 | Accès à des fichiers sensibles (`.env`, `.git/`, `wp-config.php`, dumps SQL, `phpinfo.php`) |
| `leakage` | 951100–951999 | **Inspection de la réponse** : erreurs SQL, stack traces PHP/Java, clés AWS dans les corps de réponse |

Les jeux de règles sont activés par défaut. Chaque catégorie peut être désactivée individuellement dans l'UI Admin (page Core > WAF) ou via `exclude_ids`.

### Inspection de la réponse (CRS 951xxx)

Les règles de la catégorie `leakage` s'appliquent au corps de la **réponse** (pas de la requête). En mode `block`, si la réponse contient une fuite (erreur SQL, clé AWS…), elle est bloquée avant d'être transmise au client. En mode `detect`, la fuite est loguée et la réponse passe normalement.

### Analyse comportementale par IP

Activée via `behavior_enabled`. Le moteur maintient un profil par IP sur une fenêtre glissante :

- Taux d'erreurs 4xx élevé
- Scanning de chemins (entropie élevée des URIs)
- Rotation de User-Agent
- Score WAF accumulé
- Burst de requêtes

Quand le score comportemental dépasse `behavior_threshold`, l'IP est bannie immédiatement via le callback de ban (inscrit en base pour les requêtes suivantes).

### Configuration (labels Docker)

```yaml
goproxify.waf: "block"                      # true|block|detect
goproxify.waf.anomaly_threshold: "10"       # 0 = premier match bloque
goproxify.waf.max_body_mb: "10"             # taille max du corps analysé
goproxify.waf.exclude_ids: "942100,941100"  # IDs à désactiver (CSV)
goproxify.waf.behavior: "true"              # analyse comportementale
goproxify.waf.behavior.window: "60"         # fenêtre en secondes
goproxify.waf.behavior.threshold: "8"       # score avant ban
goproxify.waf.trusted_proxies: "10.0.0.0/8" # CIDRs pour X-Forwarded-For
```

### Règles custom

Format dans l'UI Admin ou via snippet : `id|category|severity|targets|pattern|message`

```
99001|sqli|high|args+body|(?i)evil-payload|Payload interdit
```

Targets disponibles : `uri`, `args`, `body`, `headers`, `cookies`, `response`.

### Métriques Prometheus

```
gpx_waf_matches_total{host, category, severity, action}
gpx_waf_requests_inspected_total{host}
gpx_waf_behavior_signals_total{host, signal}
```

---

## Sentinel (moteur de détection comportementale)

Le Sentinel s'applique **avant le routage**, indépendamment des proxies. Il analyse chaque requête au niveau du Core.

### Signaux détectés

| Signal | Description |
|--------|-------------|
| `rate` | Dépassement du rate limit par IP (`rate_limit` req/s) |
| `path` | Scanning de chemins suspects (répertoires, extensions sensibles) |
| `ip` | IP connue malveillante (listes custom denylist) |
| `ua` | User-Agent suspect (scanners, bots malveillants) |
| `custom_*` | Règles custom définies dans l'Admin |

Dès qu'un signal (hors `rate`) dépasse le seuil, l'IP est bannie immédiatement. Le signal `rate` utilise `rate_ban_threshold` (nombre de dépassements avant ban).

Les compteurs (rate, erreurs 4xx) sont **bornés en mémoire** (~262 k IPs suivies, éviction au-delà, métrique `gpx_threat_counter_evictions_total`) et les **IPv6 sont comptées par /64** ; le ban, lui, vise l'IP exacte. Le score n'est pas conservé entre deux requêtes : `score_threshold` ne cumule que les signaux d'une même requête.

### Paramètres configurables (UI Admin > Sécurité > Sentinel)

| Paramètre | Défaut | Description |
|---|---|---|
| `score_threshold` | 0 | Score cumulatif avant blocage |
| `mode` | `block` | `block` ou `detect` |
| `rate_limit` | 0 | Req/s par IP, 0 = désactivé |
| `rate_window` | `1s` | Tolérance de pic : burst max = `rate_limit × rate_window` requêtes |
| `rate_ban_threshold` | 1 | Déclenchements avant ban (1 = immédiat) |
| `rate_ban_window` | = `rate_window` | Fenêtre de comptage pour le ban rate |
| `error_threshold` | 20 | Nb d'erreurs 4xx/5xx avant signal |
| `error_window` | `10s` | Fenêtre de comptage des erreurs |
| `global_rps` | 0 | Limite globale toutes IPs confondues (anti-DDoS), 0 = désactivé |
| `global_burst` | 0 | Burst associé (0 = 2×RPS) |
| `ban_duration` | `24h` | Durée du ban automatique |
| `tarpit.enabled` | `false` | Retient la réponse aux IP bloquées ou bannies par Sentinel au lieu de refuser aussitôt |
| `tarpit.delay_ms` | 5000 | Durée de rétention (max 30000, sous les timeouts d'écriture usuels) |
| `tarpit.max_concurrent` | 200 | Requêtes retenues simultanément ; au-delà, refus immédiat (`403`) |

### Tarpit

Avec `tarpit.enabled`, une requête bloquée par Sentinel (signal en mode `block`) ou venant d'une IP bannie par Sentinel (ban dont la source est `threat`, y compris les bans posés par le WAF) n'est pas refusée aussitôt : la connexion est retenue `delay_ms` avant la réponse `403`. Un bot qui attend chaque réponse immobilise ses propres connexions et perd du débit.

- **Borné** : au plus `max_concurrent` requêtes retenues en même temps. Au-delà, ou tarpit désactivé, le refus est immédiat comme avant : le tarpit ne peut pas épuiser les connexions du Core.
- Un client qui se déconnecte libère son slot aussitôt.
- Les bans Fail2Ban, CrowdSec et manuels, ainsi que les profils IP, ne sont **pas** retenus.
- Chaque requête retenue garde une goroutine et un socket ouverts : garder `max_concurrent` raisonnable, et `delay_ms` inférieur au `WriteTimeout` du serveur (max 30 s).

```
gpx_threat_tarpit_active
gpx_threat_tarpit_total{result}   # held | full
```

### Simuler une config avant de l'appliquer (MCP)

L'outil MCP `simulate_sentinel_config` rejoue les access logs récents (1 à 24 h) contre une config candidate et la compare à la config en production : requêtes bloquées en plus, bans, IP les plus touchées, et `legit_blocked` (requêtes qui auraient été bloquées alors qu'elles avaient abouti, signe probable de faux positifs). Rien n'est modifié. Les listes par défaut, `global_rps` et les règles User-Agent ne sont pas simulées ; voir [docs/mcp.md](mcp.md#simulate_sentinel_config).

### Whitelist par route (labels Docker)

```yaml
goproxify.sentinel.whitelist: "192.168.1.5,10.0.0.0/8"
goproxify.sentinel.whitelist.self: "true"     # IP actuelle du conteneur
goproxify.sentinel.whitelist.network: "true"  # sous-réseau Docker du conteneur
```

---

## Backpressure par route

Protège les backends (et la mémoire du Core) quand ils ralentissent : au-delà d'un plafond de requêtes simultanées, les requêtes attendent dans une file bornée puis sont rejetées.

```json
"backpressure": { "max_inflight": 200, "queue": 100, "queue_timeout_ms": 1000 }
```

| Champ | Description |
|---|---|
| `max_inflight` | Requêtes traitées en parallèle sur la route. `0` = désactivé |
| `queue` | Requêtes en attente au-delà du plafond. `0` = rejet immédiat |
| `queue_timeout_ms` | Attente maximale en file (défaut `1000`) |

Une requête rejetée (file pleine, délai dépassé, client parti) reçoit `503` avec `Retry-After: 1`. Les upgrades WebSocket ne consomment pas de slot. Le plafond est propre à chaque instance de Core (non partagé en cluster) et repart de zéro à chaque rechargement de la route.

```
gpx_backpressure_inflight{host}
gpx_backpressure_queued{host}
gpx_backpressure_rejected_total{host, reason}   # queue_full | timeout | canceled
```

---

## Gestion des bans

Les bans sont centralisés dans l'Admin et propagés aux Cores via WebSocket.

### Sources de ban

| Source | Description |
|--------|-------------|
| `native` | Ban manuel depuis l'UI Admin |
| `waf` | Ban automatique par le moteur comportemental WAF |
| `threat` | Ban automatique par le Sentinel |
| `fail2ban` | Ban reçu de Fail2Ban natif Go |
| `crowdsec` | Décision LAPI CrowdSec (stream push) |

### Fail2Ban natif Go

Détection d'échecs d'authentification sans dépendance externe. Configurable : seuil de tentatives, fenêtre de temps, durée de ban. Notification d'alerte déclenchable sur N bans/heure.

### CrowdSec

Bouncer LAPI en mode stream : les décisions CrowdSec sont poussées en temps réel au Core (ban 403). Compatible déploiement Docker.

---

## Moteur de règles automatiques

Le moteur de règles (`Admin > Automatisation > Règles automatiques`) permet de définir des **réponses automatiques** à des événements détectés périodiquement (poll toutes les 60 s). Un catalogue de règles préconfigurées est disponible dans `Automatisation > Store de règles`.

### Conditions disponibles

| Type | Description | Paramètres |
|---|---|---|
| `cve_critical` | CVE ouverte avec score CVSS ≥ seuil sur un backend | `cvss_threshold` (défaut 9.0), `proxy_id` optionnel |
| `ban_spike` | Pic de nouveaux bans sur une fenêtre de temps | `ban_count`, `ban_window`, `ban_source` optionnel |
| `engine_silent` | Fail2Ban ou CrowdSec inactif depuis N minutes | `engine_type` (`fail2ban`\|`crowdsec`), `silent_minutes` |
| `proxy_error_rate` | Taux d'erreurs 5xx d'un proxy > seuil | `proxy_id` optionnel, `error_rate_threshold`, `error_rate_window` |
| `ban_repeat` | IP bannie N fois ou plus sur une période | `repeat_count`, `repeat_window` |
| `node_offline` | Core/Agent sans heartbeat depuis N minutes (`nodes.last_seen_at`) | `node_name` optionnel (vide = tous), `offline_minutes` (défaut 5) |
| `cert_expiring` | Certificat TLS expirant sous N jours (`certs.expires_at`) | `domain` optionnel (vide = tous), `days_left` (défaut 15) |

### Actions disponibles

| Type | Description | Paramètres |
|---|---|---|
| `disable_proxy` | Désactive le proxy lié à la condition | `proxy_id` optionnel (détecté automatiquement pour CVE) |
| `ban_ip` | Bannit une IP identifiée par la condition | `ban_duration` (vide = permanent), `ban_reason` |
| `notify` | Émet une alerte via le moteur d'alertes | `notify_severity`, `notify_message` |
| `enable_strict` | Active le mode strict Fail2Ban (max_errors=5) | `strict_duration` (défaut 30m) |
| `webhook_call` | POST JSON générique vers une URL externe (`{rule, condition, action, detail, fired_at}`) | `webhook_url` |
| `run_backup` | Déclenche un snapshot de sauvegarde immédiat | `backup_retention` (0 = pas de purge automatique) |

### Cooldown

Chaque règle dispose d'un cooldown (défaut 5 min) pour éviter les déclenchements en boucle. Le timer repart à chaque exécution.

### Test à la demande

Le bouton **Tester maintenant** lance un `dry_run` : la condition est évaluée et le résultat est affiché sans exécuter l'action.

### Historique

Chaque évaluation (condition satisfaite ou non, action effectuée, erreur éventuelle) est stockée dans `rules_engine_history` et consultable depuis l'onglet **Historique** de la page.

---

## Timeouts serveur HTTP/QUIC

Configurable depuis l'UI Admin (Sécurité > Timeouts HTTP/QUIC). Propagé aux Cores via WebSocket et persisté dans `core.json`.

> ⚠️ Un **redémarrage du Core** est nécessaire pour appliquer les timeouts.

| Paramètre | Défaut | Description |
|---|---|---|
| `read_header_seconds` | 10 | Protection anti-Slowloris : temps max pour lire les headers |
| `read_seconds` | 30 | Temps max pour lire la requête complète |
| `write_seconds` | 60 | Temps max pour envoyer la réponse |
| `idle_seconds` | 120 | Temps max d'inactivité sur une connexion keep-alive |
| `max_header_kb` | 32 | Taille max cumulée des en-têtes de requête (Ko) ; au-delà : `431`. `0` = défaut |

Le Core refuse aussi les méthodes `TRACE` et `TRACK` (`405`) sur toutes les routes.

---

## Dashboard Sentinel — répartition géographique des bans

L'endpoint `GET /api/v1/security/bans/countries` retourne le nombre de bans actifs par pays, en croisant la table `security_bans` avec le cache GeoIP. Utilisé par la vue **Prism → Heatmap bans** et le widget **Accès rapide** de la table des bans.

**Réponse exemple :**
```json
[
  { "cc": "CN", "name": "China", "cnt": 142 },
  { "cc": "RU", "name": "Russia", "cnt": 87 },
  { "cc": "XX", "name": "Unknown", "cnt": 14 }
]
```

`cc: "XX"` regroupe les IPs sans entrée GeoIP. Les bans expirés sont exclus.

---

## Webhooks sur événements de sécurité

Deux déclencheurs sont disponibles dans les règles d'alerte (Admin → **Alerting → Règles**) :

| Déclencheur | Événement |
|-------------|-----------|
| `sentinel_ban` | Nouvelle IP bannie par le Sentinel (automatique ou signal comportemental) |
| `backend_down` | Un backend passe de `healthy` à `unhealthy` (callback `OnDown` du health-check) |

Le payload du webhook `backend_down` contient :
```json
{ "url": "http://10.0.0.5:3000", "node_name": "core-eu-west" }
```

Ces événements peuvent être routés vers n'importe quel canal d'alerte (email, Slack webhook, ntfy, Jira…) via les règles d'alerte standard.

---

## Scanner CVE

Analyse les backends HTTP configurés à la recherche de vulnérabilités connues (CVEs). Disponible dans l'Admin (Sécurité > Scanner CVE).

- Refuse par défaut les cibles sur IPs privées (RFC1918, localhost, metadata cloud) — protection anti-SSRF
- Option **Autoriser les backends IP privées** (toggle admin) : permet de scanner des backends Docker/LAN
  - Configurable aussi via `GPX_VULNSCAN_ALLOW_PRIVATE=true` sur l'Admin
- Déclenchable manuellement ; intégrable aux alertes (notification sur CVE détectée)

---

## Headers de sécurité HTTP

Configurables par proxy via snippets ou labels :

| Header | Valeur recommandée |
|--------|-------------------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` |
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; object-src 'none'` |
| `X-Frame-Options` | `DENY` |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | selon besoins |

Le masquage du fingerprint serveur (`Server`, `X-Powered-By`) est activable indépendamment.

---

## Profils IP et GeoIP

- **Profils IP** : listes de blocage ou d'autorisation avec mise à jour automatique depuis des sources publiques (Tor, Cloudflare, AWS, Spamhaus, FireHOL…). Les profils `deny` bloquent sur tous les Cores ; les profils `allow` servent au filtrage CDN. Les CIDRs sont agrégés (doublons et préfixes contenus fusionnés), les plages privées sont exclues des profils `deny` et les feeds inchangés ne sont pas retéléchargés (ETag / 304). Spamhaus DROP, DShield et Feodo sont désactivés par défaut car inclus dans FireHOL Level 1. Un feed en échec est retenté avec un backoff (15 min → 6 h max), la dernière liste valide reste appliquée, l'état est visible dans l'UI, et une mise à jour qui perd plus de la moitié d'une liste (feed vide ou tronqué) est rejetée. Après N échecs consécutifs (3 par défaut, réglage `ipprofile.alert_after_failures`, `0` = désactivé), le déclencheur d'alerte `ip_profile_refresh_failed` est émis une fois par série.
- **GeoIP** : autorisation ou blocage par pays (MaxMind GeoLite2, téléchargé automatiquement au démarrage).

---

## Métriques et observabilité

Tous les moteurs exposent des métriques Prometheus sur `/metrics` :

```
# WAF
gpx_waf_matches_total
gpx_waf_requests_inspected_total
gpx_waf_behavior_signals_total

# Sentinel
gpx_threat_*

# Bans
gpx_bans_active_total
```

L'access log JSON inclut les décisions WAF (`waf_matches`, `waf_score`) sur chaque requête. La page **Prism** permet d'analyser le trafic par IP, code HTTP et domaine, avec accès direct aux bans depuis la table des IPs.

---

## Proxies de confiance (`GPX_TRUSTED_PROXIES`)

Le Core lit l'IP réelle du client depuis `X-Forwarded-For`, `X-Real-IP` ou `CF-Connecting-IP` **uniquement si la connexion directe provient d'un proxy de confiance**. Sans cette restriction, n'importe quel client pourrait forger ces headers et contourner les bans IP, le rate-limit et la pseudonymisation RGPD.

**Défaut** : loopback (`127.0.0.0/8`, `::1`) + réseaux privés RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`).

**Risque derrière un load balancer public** : si votre LB est à une IP publique (AWS ALB, GCP LB, HAProxy sur VPS...) mais se connecte au Core depuis une IP privée (10.x, 172.x...), la valeur par défaut est trop permissive — n'importe quelle IP du même sous-réseau privé peut usurper `X-Real-IP`. Le Core émet un avertissement au démarrage si `GPX_TRUSTED_PROXIES` n'est pas défini explicitement.

**Configuration** (variable d'environnement du Core) :

```bash
# Un seul LB
GPX_TRUSTED_PROXIES=203.0.113.10

# Plusieurs LB ou plage
GPX_TRUSTED_PROXIES=203.0.113.10,198.51.100.0/24

# Cloudflare (plages officielles à vérifier sur https://www.cloudflare.com/ips/)
GPX_TRUSTED_PROXIES=103.21.244.0/22,103.22.200.0/22,...

# "*" — tout croire (déconseillé, brise toute protection IP)
GPX_TRUSTED_PROXIES=*
```

**Règle par route** : `goproxify.waf.trusted_proxies` (labels Docker / snippet) surcharge les défauts pour une route spécifique dans le contexte WAF. `GPX_TRUSTED_PROXIES` contrôle l'extraction de l'IP cliente pour les logs, le rate-limit et les bans.

**Vérification** : dans les logs d'access, le champ `ip` doit afficher l'IP publique du visiteur, pas l'IP interne du LB. Si `ip` vaut l'IP du LB, le Core n'a pas reçu de header d'IP client valide (header absent ou proxye non de confiance).
