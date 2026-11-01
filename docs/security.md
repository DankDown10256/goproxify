# Sécurité

GoProxify embarque plusieurs moteurs de sécurité indépendants, complémentaires et configurables sans redémarrage (sauf timeouts serveur).

---

## Architecture des couches de sécurité

Les moteurs s'appliquent dans cet ordre sur chaque requête entrante :

```
Connexion TCP/TLS
      │
      ▼
 [1] Ephor, limite globale — débit global de la passerelle dépassé → 503
      │
      ▼
 [2] Profils IP            — IP en liste de blocage → 403
      │
      ▼
 [3] Bans IP               — IP bannie (Ephor, WAF, Seuils, CrowdSec, manuel) → 403 ;
      │                      les profils allow et les IP privées y échappent
      ▼
 [4] Ephor, détection      — signaux comportementaux, blocage éventuel ;
      │                      sauté pour les IP en liste blanche
      ▼
 [5] Routage / proxy       — résolution de la route (hôte, snippets, location) ;
      │                      hôte inconnu → réponse neutre (voir « Porte d'entrée »)
      │
      ▼
 [6] Chaîne de la route    — étapes triées par rang, de la première à la plus proche du backend :
      │                      WAF (700) → bot (800) → rate limit (1200) → filtre IP (1300)
      │                      → plugins (1400) → GeoIP (1500) → mTLS (1800) → JWT (1900)
      │                      → SSO (2000) → OpenAPI / schéma / GraphQL (2100–2300)
      ▼
 Backend applicatif
```

Après la réponse, l'apprentissage de la surface observe la requête, puis Ephor la verse à son magasin comportemental (ce qui nourrit les bans suivants). Les rangs sont définis dans `internal/edge/dispatch_stages.go` et `internal/edge/middleware/detector_exec.go`.

---

## WAF (Web Application Firewall)

Moteur natif Go, sans dépendance ModSecurity ni CGO. Inspiré de l'OWASP CRS-4.

### Modes

| Mode | Comportement |
|------|-------------|
| `block` | Bloque la requête (403) dès qu'une règle se déclenche |
| `detect` | Laisse passer, journalise les règles déclenchées dans l'access log et les métriques |
| désactivé | Aucune inspection |

### Interrupteur par passerelle

Le WAF est aussi un moteur de sécurité de la passerelle (*Sécurité › Moteurs de sécurité*, `GET/PUT /api/v1/security/waf-config`, `goproxify security waf-engine`). Désactivé, aucune route de la passerelle (ou de son groupe HA) n'exécute le WAF et son moteur comportemental ne bannit plus ; le mode et les règles de chaque route sont conservés. Activé (défaut), chaque route décide : le réglage par route ci-dessus s'applique. La passerelle garde le réglage chiffré (`waf-config.gpx`) et le retrouve après un redémarrage sans l'Admin ; copie absente ou illisible, le WAF reste actif.

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
| `ssti` | 934300 | Server-Side Template Injection (`{{7*7}}`, `{{config.…}}`, `${7*7}`, `<%=`) |
| `smuggling` | 920200–920999 | HTTP Request Smuggling (TE+CL simultanés, chunked encoding obfusqué) |
| `restricted` | 930200–930999 | Accès à des fichiers sensibles (`.env`, `.git/`, `wp-config.php`, dumps SQL, `phpinfo.php`) |
| `leakage` | 951100–951999 | **Inspection de la réponse** : erreurs SQL, stack traces PHP/Java, clés AWS dans les corps de réponse |

Les jeux de règles sont activés par défaut. Chaque catégorie peut être désactivée individuellement dans l'UI Admin (page passerelle > WAF) ou via `exclude_ids`.

Les cookies (lus bruts, y compris espaces et guillemets) et les corps `x-www-form-urlencoded` (valeurs décodées) sont inspectés par les règles SQLi, injection de commande (`932120` substitution `$(cmd)` / backticks, `932130` `|| cmd`, commandes connues uniquement) et SSTI (`934300`). La règle SQLi `select … from` exige un contexte SQL (guillemet, `;`, commentaire, `*`, liste de colonnes, `distinct`…) : une phrase comme « select an option from the list » passe.

**Exclusions de plateforme** : une application qui accepte des gabarits saisis par l'utilisateur (jinja, twig, handlebars, mustache, EJS, éditeur d'e-mails) doit exclure `934300` sur la route concernée. `{{variable}}` seul n'est de toute façon pas bloqué ; seules les expressions (`{{7*7}}`, `{{config.x}}`) le sont. Voir la section suivante : préférez une exclusion **par chemin**.

#### Exclure des règles sans désarmer le proxy

Certaines applications envoient légitimement ce que les règles arrêtent : l'éditeur de WordPress poste du HTML à `/wp-admin/`, Adminer envoie du SQL, les nœuds de code de n8n envoient du JavaScript. En mode `block` l'application devient inutilisable (un 403 à chaque enregistrement). Deux outils, du plus sûr au plus large :

| Outil | Portée | Quand |
|-------|--------|-------|
| `waf.exclusions` | **Sous des chemins seulement** ; les règles restent actives partout ailleurs | Le cas général : l'administration d'un CMS, une console, un endpoint de recherche |
| `waf.exclude_ids` | Tout le proxy | Une règle qui se trompe sur l'ensemble de l'application, sans chemin à isoler |

```json
{ "waf": { "enabled": true, "mode": "block",
  "exclusions": [ { "paths": ["/wp-admin/", "/wp-json/"], "platform": "wordpress", "note": "éditeur d'articles" } ] } }
```

- Un chemin est un préfixe sur une frontière de segment (`/wp-admin/` couvre `/wp-admin/post.php` ; `/api/search` couvre `/api/search/x`, pas `/api/searchx`). `/` est refusé : ce serait `exclude_ids`.
- **Une exclusion peut nommer une plateforme** (`"platform": "wordpress"`) : ce sont alors ses règles habituelles (celles qui se trompent d'ordinaire sur elle) qui sont retirées **sous ses chemins**, et nulle part ailleurs. La passerelle ne devine jamais la plateforme d'un proxy, et il n'existe plus de choix de plateforme valable pour tout le proxy (Admin `0.211.0`) : retirer les règles d'injection de tout un site pour qu'un éditeur enregistre ses articles le laisse sans défense, et savoir quelle application tourne ne change rien à ce qu'un WAF doit bloquer.
- Le reste du proxy garde toutes ses règles. **Sous un chemin exclu** la protection baisse : réservez-le à une zone déjà protégée autrement (authentification, filtre d'IP, Access, forward-auth).
- Pas de chemin net (application dont les requêtes problématiques sont dispersées) : n'excluez pas la règle pour tout le proxy. Relevez d'abord `anomaly_threshold` (10 : une règle seule ne suffit plus à refuser, plusieurs concordantes si), et en dernier recours passez le WAF en `detect` (il journalise sans refuser). L'[apprentissage de la surface](adr/0016-apprentissage-de-la-surface-d-un-proxy.md) fait cette proposition à partir du trafic réel.
- Pas de label Docker pour `exclusions` : proxy option, API, CLI ou modale.

### Inspection de la réponse (CRS 951xxx)

Les règles de la catégorie `leakage` s'appliquent au corps de la **réponse** (pas de la requête). En mode `block`, si la réponse contient une fuite (erreur SQL, clé AWS…), elle est bloquée avant d'être transmise au client. En mode `detect`, la fuite est loguée et la réponse passe normalement.

### Analyse comportementale par IP

Le magasin comportemental est **celui de la passerelle**, alimenté par Ephor sans activation par route (voir [Note commune](#note-commune-et-signaux-de-comportement-adr-0011)). `behavior_enabled` ne décide plus que du **blocage par le WAF** sur la route : refus des IP dont le score dépasse `behavior_threshold` et ban par le WAF. Le moteur maintient un profil par IP sur une fenêtre glissante :

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
goproxify.waf.max_body_mb: "1"              # taille max du corps analysé (défaut : 128 Kio ; le coût croît avec elle)
goproxify.waf.exclude_ids: "942100,941100"  # IDs à désactiver (CSV)
goproxify.waf.behavior: "true"              # analyse comportementale
goproxify.waf.behavior.window: "60"         # ignoré : la fenêtre est celle de la passerelle (60 s)
goproxify.waf.behavior.threshold: "8"       # score avant ban
goproxify.waf.trusted_proxies: "10.0.0.0/8" # CIDRs pour X-Forwarded-For
```

### Règles custom

Format dans l'UI Admin ou via snippet : `id|category|severity|targets|pattern|message`

```
99001|sqli|high|args+body|(?i)evil-payload|Payload interdit
```

Targets disponibles : `uri`, `args`, `body`, `headers`, `cookies`, `response`.

Les `custom_rules` d'une route (`waf.custom_rules`) ne s'appliquent qu'à cette route et sont rechargées à chaque mise à jour de la route ; les règles du fichier `custom_rules_path` sont globales à la passerelle.

### Métriques Prometheus

```
gpx_waf_matches_total{host, category, severity, action}
gpx_waf_requests_inspected_total{host}
gpx_waf_behavior_signals_total{host, signal}
```

---

## Ephor (moteur de détection comportementale)

L'Ephor s'applique **avant le routage**, indépendamment des proxies. Il analyse chaque requête au niveau de la passerelle.

### Signaux détectés

| Signal | Description |
|--------|-------------|
| `rate` | Dépassement du rate limit par IP (`rate_limit` req/s) |
| `path` | Scanning de chemins suspects (répertoires, extensions sensibles) |
| `ip` | IP présente dans les listes de réputation (score 5) |
| `ua` | User-Agent suspect (scanners, bots malveillants) (score 3) |
| `path` | Scanning de chemins suspects (score 2) |
| `custom_ip`, `custom_ua`, `custom_path` | Entrées inline définies dans l'Admin, mêmes scores que les listes |
| `decoy` | Accès à un chemin-leurre que l'application n'utilise jamais (score 8) — voir [Leurres](#leurres) |
| `threshold:<nom>` | Dépassement d'un Seuil (règle « N événements en T ») : le ban porte le nom du Seuil, le nombre d'événements et la fenêtre — voir [Seuils](#seuils) |
| `unknown_host` | Accès par l'IP ou à un nom que la passerelle ne sert pas (points modérés, jamais un ban au premier accès) — voir [Hôte inconnu](#hôte-inconnu-signal-unknown_host) |
| `rate` | Dépassement du rate limit par IP (score 4) |
| `error4xx` | `error_threshold` erreurs 4xx en `error_window` : ban direct, hors score ; avec `ip_score.errors`, chaque 4xx verse des points pondérés au score cumulé |
| `waf` | Score WAF cumulé par IP au-delà du seuil comportemental : ban direct, hors score |
| *limite globale* | `global_rps` dépassé : `503` pour tous, sans ban |

Dès qu'un signal (hors `rate`) dépasse le seuil, l'IP est bannie immédiatement. Le signal `rate` utilise `rate_ban_threshold` (nombre de dépassements avant ban). La page Ephor de l'Edge liste ces détections avec leur état et le nombre de bans actifs par motif.

Les compteurs (rate, erreurs 4xx) sont **bornés en mémoire** (~262 k IPs suivies, éviction au-delà, métrique `gpx_threat_counter_evictions_total`) et les **IPv6 sont comptées par /64** ; le ban, lui, vise l'IP exacte. Par défaut le score n'est pas conservé entre deux requêtes : `score_threshold` ne cumule que les signaux d'une même requête.

#### Bans graduels (`escalation`, optionnel)

Avec `escalation.enabled`, une IP déjà bannie par Ephor dans la fenêtre l'est plus longtemps : durée = `ban_duration` × `factor`^n, n étant le nombre de ses bans Ephor précédents (avec les valeurs par défaut : 24 h, 48 h, 96 h… jusqu'à 30 jours). Cela vaut pour tous les bans Ephor (signal, score cumulé, rate, erreurs 4xx). La récidive est lue dans l'historique des bans de la passerelle, conservé 30 jours et qui survit à un redémarrage ; les bans reçus d'un pair HA ne comptent pas. Un **déban manuel remet le compteur à zéro** (un faux positif corrigé n'alourdit pas le ban suivant). Le rejeu `security threat simulate` applique les durées graduelles.

#### Score cumulé par IP avec décroissance (`ip_score`, optionnel)

Avec `ip_score.enabled`, les points de chaque requête qui déclenche Ephor s'additionnent **d'une requête à l'autre** pour une même IP, et le score **est divisé par deux à chaque `half_life`** (décroissance exponentielle). L'IP n'est bannie que lorsque son score dépasse `ban_threshold` : quelques signaux isolés (un 404 sur un chemin sensible, un User-Agent suspect) s'estompent, une série rapprochée mène au ban. Les requêtes qui déclenchent restent bloquées avant le ban, le score est remis à zéro au ban et au débannissement.

- Les IP présentes dans les listes de menaces (`ip`, `custom_ip`) restent **bannies immédiatement**.
- Le signal `rate` passe par le score : `rate_ban_threshold` est alors ignoré.
- Les erreurs 4xx (`error_threshold`) et le WAF gardent leur propre décision, sauf si `ip_score.errors` est activé (ci-dessous).
- Le score est en mémoire (borné comme les autres compteurs, oublié quand il est quasi nul) : il n'est ni conservé après un redémarrage ni partagé entre passerelles, contrairement aux bans.
- Le rejeu `security threat simulate` applique la décroissance sur l'horloge des logs rejoués.

##### Erreurs 4xx pondérées (`ip_score.errors`, optionnel)

Avec `ip_score.enabled` et `ip_score.errors.enabled`, chaque réponse 4xx verse des **points pondérés par code et par route** au score cumulé de l'IP, au lieu du compteur `error_threshold` / `error_window` (ignorés alors). Un 404 isolé pèse peu, une rafale de 400 ou 405 mène au ban ; les erreurs s'additionnent aux autres signaux et s'estompent avec la demi-vie.

- **Par code** (défaut) : 400, 405, 414, 431 → 1 ; 404 → 0,5 ; autres 4xx → `default_weight` (0,5). **401, 403 et 429 ne comptent pas** : échecs d'authentification, refus déjà prononcés par un ban, le WAF ou une limite, dont d'autres moteurs décident. `weights` (`{"404": 0.2, "403": 1}`) surcharge un code, 0 le neutralise, et peut réintroduire 401/403/429.
- **Par route** : `routes` (`[{"prefix": "/login", "factor": 3}, {"prefix": "/api/", "factor": 0.5}]`) multiplie les points selon le préfixe du chemin ; le préfixe le plus long l'emporte, 0 ignore les erreurs de la route. Les chemins de la liste blanche ne comptent pas.
- Les 404 sur un hôte inconnu de la passerelle ne sont pas comptés (ils ne passent pas par une route).
- Le ban posé porte le motif `threat: erreurs 4xx répétées` ; en mode `detect`, il est seulement journalisé.

### Paramètres configurables (UI Admin > Sécurité > Ephor)

| Paramètre | Défaut | Description |
|---|---|---|
| `score_threshold` | 0 | Score cumulatif avant blocage |
| `mode` | `block` | `block` ou `detect` |
| `rate_limit` | 0 | Req/s par IP, 0 = désactivé |
| `rate_window` | `1s` | Tolérance de pic : burst max = `rate_limit × rate_window` requêtes |
| `rate_ban_threshold` | 1 | Déclenchements avant ban (1 = immédiat) |
| `rate_ban_window` | = `rate_window` | Fenêtre de comptage pour le ban rate |
| `escalation.enabled` | `false` | Bans graduels : la durée croît avec les bans Ephor précédents de l'IP |
| `escalation.factor` | 2 | Multiplicateur par récidive : durée = `ban_duration` × facteur^n |
| `escalation.window` | `168h` | Période pendant laquelle les bans précédents comptent (max `720h`, rétention de l'historique) |
| `escalation.max_duration` | `720h` | Plafond de la durée d'un ban (ne raccourcit jamais `ban_duration`) |
| `ip_score.enabled` | `false` | Score cumulé par IP avec décroissance (voir ci-dessus) |
| `ip_score.ban_threshold` | 10 | Score cumulé qui déclenche le ban (chemin sensible 2, User-Agent suspect 3, débit 4) |
| `ip_score.half_life` | `10m` | Durée au bout de laquelle le score est divisé par deux |
| `ip_score.errors.enabled` | `false` | Verse les erreurs 4xx pondérées au score cumulé (remplace `error_threshold`) |
| `ip_score.errors.weights` | — | Points par code HTTP, ex. `{"404": 0.2}` (0 = ignoré) |
| `ip_score.errors.default_weight` | 0,5 | Points d'un 4xx non listé |
| `ip_score.errors.routes` | — | Multiplicateurs par préfixe de chemin, ex. `[{"prefix":"/login","factor":3}]` |
| `error_threshold` | 20 | Nb d'erreurs 4xx/5xx avant signal |
| `error_window` | `10s` | Fenêtre de comptage des erreurs |
| `global_rps` | 0 | Limite globale toutes IPs confondues (anti-DDoS), 0 = désactivé |
| `global_burst` | 0 | Burst associé (0 = 2×RPS) |
| `ban_duration` | `24h` | Durée du ban automatique |
| `tarpit.enabled` | `false` | Retient la réponse aux IP bloquées ou bannies par Ephor au lieu de refuser aussitôt |
| `tarpit.delay_ms` | 5000 | Durée de rétention (max 30000, sous les timeouts d'écriture usuels) |
| `tarpit.max_concurrent` | 200 | Requêtes retenues simultanément ; au-delà, refus immédiat (`403`) |
| `challenge.mode` | `off` | Défi à preuve de travail avant le ban : `off`, `detect` (compte sans servir) ou `block` — voir [Défi avant le ban](#défi-avant-le-ban) |
| `challenge.threshold` | moitié de `ip_score.ban_threshold` | Note commune à partir de laquelle l'IP reçoit le défi ; doit rester sous le seuil de ban |
| `challenge.difficulty` | 16 | Bits à zéro de la preuve (1 à 24 ; chaque bit double le travail) |
| `challenge.ttl` | `24h` | Durée de validité de la preuve (1 minute au moins) |
| `challenge.exempt_paths` | — | Préfixes de chemin jamais défiés (APIs, webhooks) |
| `challenge.secret` | propre à la passerelle | Signature de la preuve ; à partager entre les membres d'un groupe HA |
| `decoys.mode` | `off` | Chemins-leurres : `off`, `detect` (compte sans effet) ou `block` (verse le signal `decoy`) — voir [Leurres](#leurres) |
| `decoys.paths` | — | Chemins en plus du jeu par défaut (une barre finale = préfixe, sinon chemin exact ; 200 au plus) |
| `decoys.no_defaults` | `false` | Retire le jeu par défaut : seuls `decoys.paths` piègent |
| `thresholds.mode` | `off` | Mode des Seuils fournis (`auth-fail`, `waf-repeat`) : `off`, `detect` ou `block` — voir [Seuils](#seuils) |
| `thresholds.rules` | — | Seuils de l'administrateur (50 au plus), chacun avec son mode, son filtre, son compte, sa fenêtre et son action |
| `unknown_host.mode` | `off` | Signal « hôte inconnu » : `off`, `detect` (compte sans effet) ou `block` (verse des points) — voir [Hôte inconnu](#hôte-inconnu-signal-unknown_host) |
| `unknown_host.points` | 1 | Points par accès (max 5, sous le seuil de ban) |
| `unknown_host.probes` | — | IP ou CIDR de sondes connues (supervision, répartiteur de charge), jamais notées |

### Note commune et signaux de comportement (ADR 0011)

*(Admin `0.194.0`, Edge `0.108.0`)* Ephor n'additionne plus seulement des listes et des seuils : il tient **une note de risque par IP** dans un **magasin comportemental unique par passerelle**, que le WAF partage.

- **Qui l'alimente.** Ephor verse **chaque requête** (méthode, chemin, User-Agent, statut, empreinte TLS, route) une fois la réponse connue, **sans activation par route** ; le WAF y ajoute le score de ses règles ; CrowdSec y verse ses décisions. Une requête n'est comptée qu'une fois (si le WAF l'a déjà versée, Ephor ne la reverse pas). La fenêtre est celle de la passerelle (60 s) : le label `goproxify.waf.behavior.window` n'est plus pris en compte.
- **Ce que la note décide.** Avec `ip_score.enabled`, le ban se pose quand *score cumulé d'Ephor + signaux de comportement en `block`* atteint `ip_score.ban_threshold` (plus le bonus de confiance ci-dessous). Le ban dit tout : son explication liste les signaux d'Ephor **et** ceux de comportement, avec leurs points. Un ban remet la note à zéro.
- **Modes (`behavior`).** Chaque signal a un mode `off | detect | block`. **Tout signal naît en `detect`** : il est calculé, listé dans l'interface, et compté en *note fantôme* — le ban qu'il aurait provoqué est journalisé (`ephor: note fantôme au-dessus du seuil`) et compté par `gpx_threat_shadow_bans_total`, rien de plus. Il passe en `block` après lecture de la simulation (`simulate_ephor_config` rejoue la note commune sur les logs : `legit_blocked` en est le critère). `behavior.mode` fixe le défaut des signaux non réglés dans `behavior.signals` ; `off` coupe tout versement. En `mode: detect` d'Ephor, rien ne bannit quelles que soient les valeurs.
- **Signaux** (le score entre parenthèses ; les huit premiers existaient dans le WAF et gardent leur effet sur ses routes) :

| Signal | Points | Ce qu'il voit |
|---|---|---|
| `high_4xx_rate` | 4 | au moins 40 % de 4xx, sur 5 requêtes ou plus |
| `path_scanning` | 3 | 15 chemins distincts ou plus |
| `waf_score_accumulation` | 3 à 5 | règles WAF déclenchées requête après requête (8 points cumulés, 15 pour 5) |
| `ua_rotation` | 3 | 3 User-Agents différents ou plus |
| `request_burst` | 4 | 30 requêtes en 10 s |
| `high_post_ratio` | 2 | 70 % d'écritures sur 10 requêtes ou plus |
| `high_path_entropy` | 2 | chemins presque tous différents (20 requêtes ou plus) |
| `distributed_scan` | 5 à 8 | 5 IP ou plus du même /24 (/48 IPv6) |
| `ua_tls_mismatch` | 4 | le User-Agent annonce un navigateur de la table, les suites de chiffrement du JA4 ne sont pas les siennes (3 requêtes) |
| `no_assets` | 2 | 25 pages HTML demandées, aucune image, feuille de style, script ni police |
| `regular_interval` | 2 | 12 intervalles ou plus presque identiques (coefficient de variation < 10 %, moyenne entre 100 ms et 30 s) |
| `scan_breadth` | 3 | 10 chemins distincts en erreur ou plus, au moins la moitié des requêtes |
| `asn_aggregate` | 4 | 8 IP ou plus du même ASN, 30 requêtes ou plus, 60 % en erreur, sur dix fenêtres (attaque distribuée « lente ») |
| `rate_deviation` | 3 | débit de l'IP sur la route au-dessus du normal appris pour l'heure (voir plus bas) |
| `crowdsec` | 5 | une décision de ce moteur, valable le temps du ban |
| `surface_violation` | 3 | une requête hors de la politique de surface du proxy (contrôle `openapi` appris, voir plus bas) que le backend a refusée (4xx autre que 401), valable 10 minutes |

Les cinq premiers nouveaux signaux, et `rate_deviation`, **ne comptent pas dans le score du WAF**. Limites à connaître avant de les passer en `block` : `no_assets` voit aussi un robot d'indexation légitime (qui ne charge pas les images) ; `regular_interval` voit un client qui interroge à cadence fixe (supervision, lecteur de flux) ; `ua_tls_mismatch` voit un proxy d'entreprise qui inspecte le TLS ; `asn_aggregate` voit un gros opérateur mobile derrière un NAT. Les listes blanches d'Ephor les exemptent tous.

- **Table User-Agent ↔ TLS.** Livrée avec le binaire et versionnée (`TLSTableVersion`), volontairement courte : famille `chromium` (Chrome, Edge, Opera, Brave, Electron — pile BoringSSL, 15 suites de chiffrement, JA4 `…_8daaf6152771_…`). Le User-Agent d'un navigateur Apple (tous utilisent la pile du système) et d'une famille absente de la table ne sont jamais évalués : pas de signal, pas de faux positif. `behavior.tls_families` (`famille=empreinte` à 12 caractères hexadécimaux, la partie « b » d'un JA4) la complète.
- **Bonus de confiance.** Une IP à longue histoire propre voit son seuil de ban relevé : +1 par centaine de requêtes propres (jusqu'à 5, le bonus historique du WAF) et +1 par jour d'historique sans signal (jusqu'à 3, à partir de 50 requêtes propres). Un signal fait perdre la moitié des requêtes propres et repart l'historique. Conservé **7 jours** après la dernière requête, effacé avec l'IP (effacement RGPD) ; `behavior.no_trust` le coupe.
- **Base ASN.** `asn_aggregate` demande de savoir à quel ASN appartient une IP. L'Admin (Sécurité › ASN, base installée) l'**annonce** (`asn_db_offer`) à chaque connexion de passerelle et quand il la met à jour ; la passerelle qui n'a pas cette version la **réclame**, la reçoit en morceaux de 512 Kio (≈ 3 Mo compacte : plages et numéros d'ASN, ni noms ni pays), en garde une copie chiffrée (`asn-db.gpx`) et s'en sert seule. Sans base, l'agrégat par ASN reste muet. Elle n'est pas répliquée entre membres d'un groupe HA : chacun la tient de l'Admin.
- **Références apprises.** Le magasin apprend le **débit normal par IP de chaque route, heure du jour par heure du jour (UTC)** : chaque minute écoulée donne un échantillon (le 90ᵉ centile des requêtes par IP, parmi les IP sans signal) ; une médiane et un écart absolu médian robuste en tirent un seuil (médiane + 6 écarts). Le signal `rate_deviation` se déclenche quand une IP dépasse ce seuil (au moins 20 requêtes par minute) sur la route. Garde-fous : **démarrage à froid** (la référence compte à partir de 30 minutes observées pour l'heure ET 24 h d'ancienneté de la route, `behavior.reference_min_age` ; avant, le signal est marqué *froid* et ne compte jamais, quel que soit son mode), **empoisonnement** (les IP à signal ne nourrissent pas la référence ; statistiques robustes), **dérive plafonnée** (le seuil ne monte pas de plus de 25 % par 24 h). Elle ne contient aucune IP. Visible dans Ephor › Détections, `GET /api/v1/security/threat-references`, `goproxify security threat references`, MCP `get_ephor_references`.
- **Seuils proposés.** À partir des cumuls par minute (ADR 0010, sans IP), l'Admin propose une limite globale (`global_rps`) par passerelle : quatre fois le 99,9ᵉ centile du débit par minute sur sept jours, arrondi au palier supérieur. Il ne pousse rien : « Appliquer » remplit le formulaire, l'administrateur relit, simule et enregistre. `GET /api/v1/security/threat-config/suggestions`, `goproxify security threat suggest`, MCP `suggest_ephor_thresholds`.
- **Groupe HA.** La note d'une IP se fusionne **par maximum**, jamais par somme : une passerelle dont le pair a une note plus haute que la sienne reçoit la différence comme signal `ha_peer` jusqu'à l'expiration de l'entrée ; rejouer la même entrée ne change rien, et deux passerelles qui s'échangent leurs notes ne les gonflent pas l'une l'autre. (Avant l'ADR, la synchronisation HA du profil comportemental n'échangeait rien : son magasin d'échange n'était alimenté par personne.)
- **Mémoire bornée.** 128 événements compacts par IP, 50 000 profils, 20 000 /24 et 5 000 ASN suivis ; au-delà, la plus ancienne information cède la place (fail-open). Coût mesuré : ≈ 4 µs et 4 allocations par requête (`BenchmarkRecordCleanTraffic`, Windows/386, 1 024 IP en rotation).
- **Fonctionnement sans l'Admin.** Le magasin (notes en cours, historique propre, références apprises) est copié chiffré toutes les 5 minutes et à l'arrêt dans `behavior-state.gpx` (`GPX_BEHAVIOR_STATE_PATH`), relu au démarrage ; il remplace `waf-behavior.json`, qui était en clair. Les scores et fenêtres d'erreurs d'Ephor ont leur copie (`threat-state.gpx`, `GPX_THREAT_STATE_PATH`).

```
gpx_threat_shadow_bans_total   # bans que la note aurait posés (signaux en detect, ou mode detect)
```

### Fonctionnement sans l'Admin

Ephor tourne sur la passerelle sans dépendre de l'Admin, y compris après un redémarrage pendant une coupure :

- **Configuration** : la passerelle garde une copie chiffrée (clé du cache local) de la dernière configuration reçue, `/etc/goproxify/threat-config.gpx` (surchargeable par `GPX_THREAT_CONFIG_PATH`), et la recharge au démarrage avec les listes blanches `ephor.whitelist` des routes. Chaque envoi de l'Admin remplace la copie.
- **Bans** : un ban Ephor est écrit dans la base de bans locale de la passerelle (`bansdb`) : il bloque aussitôt les requêtes suivantes de l'IP pendant `ban_duration`, survit à un redémarrage et est transmis aux pairs HA. L'Admin en est notifié pour l'historique et la diffusion aux autres passerelles.

### Tarpit

Avec `tarpit.enabled`, une requête bloquée par Ephor (signal en mode `block`) ou venant d'une IP bannie par Ephor (ban dont la source est `threat`, y compris les bans posés par le WAF) n'est pas refusée aussitôt : la connexion est retenue `delay_ms` avant la réponse `403`. Un bot qui attend chaque réponse immobilise ses propres connexions et perd du débit.

- **Borné** : au plus `max_concurrent` requêtes retenues en même temps. Au-delà, ou tarpit désactivé, le refus est immédiat comme avant : le tarpit ne peut pas épuiser les connexions de la passerelle.
- Un client qui se déconnecte libère son slot aussitôt.
- Les bans CrowdSec et manuels, ainsi que les profils IP, ne sont **pas** retenus.
- Chaque requête retenue garde une goroutine et un socket ouverts : garder `max_concurrent` raisonnable, et `delay_ms` inférieur au `WriteTimeout` du serveur (max 30 s).

```
gpx_threat_tarpit_active
gpx_threat_tarpit_total{result}   # held | full
```

### Défi avant le ban

*(Edge `0.134.0`, [ADR 0020](adr/0020-reference-saisonniere-seuils-et-visibilite-amont.md), étape 1.b)* Entre « laisser passer » et « bannir » : une IP dont la note commune a franchi `challenge.threshold` sans atteindre le seuil de ban reçoit le **défi à preuve de travail** du filtre anti-bot (un petit calcul que le navigateur résout en une seconde environ) au lieu d'être refusée. Un humain ne le remarque presque pas, un robot qui fait des milliers de requêtes paie cher, et une IP partagée (NAT d'entreprise, CGNAT) n'est pas bannie à tort.

- **Il s'appuie sur le score cumulé** : `ip_score.enabled` est requis, et le seuil doit rester sous `ip_score.ban_threshold` (sinon la configuration est refusée). La note est celle du ban : score d'Ephor plus signaux de comportement en `block`. Le bonus de confiance des IP à longue histoire propre relève le seuil du défi comme celui du ban.
- **Il naît en `detect`** : le défi qui aurait été imposé est compté (`gpx_threat_challenge_total{result="shadow"}`) et journalisé, jamais servi. `off` est le défaut.
- **Seule une navigation reçoit la page** : un `GET` ou `HEAD` qui demande du HTML (`Accept: text/html`, ou `Sec-Fetch-Mode: navigate`). Un client d'API, une image, un `POST`, une mise à niveau WebSocket, une validation ACME (`/.well-known/`) et les `challenge.exempt_paths` passent comme avant : ils restent sur la voie du ban. Un robot qui n'annonce pas de HTML n'est donc pas défié ; le ban reste son issue.
- **Une route qui défie déjà** ses visiteurs (filtre anti-bot en mode `challenge`) n'est pas défiée deux fois, et ses `challenge_exempt_paths` s'appliquent aussi.
- **Cookie et URL propres** (`_gpx_ephor`, `POST /.gpx/ephor-challenge`) : la preuve de la passerelle et celle d'une route ne se mélangent pas. La preuve est liée à l'IP et au User-Agent, valable `challenge.ttl`, et retirée de la requête avant le backend. Résoudre le défi **n'efface pas la note** : si elle continue de monter jusqu'au seuil de ban, l'IP est bannie malgré la preuve.
- **Groupe HA** : sans `challenge.secret` commun, chaque passerelle signe avec son secret propre et re-défie après un redémarrage ou d'un membre à l'autre.
- **Exclusions** : les IP, User-Agents et chemins en liste blanche d'Ephor ne sont jamais défiés.

```
gpx_threat_challenge_total{result}   # served | shadow | solved | failed
```

Réglable dans **Sécurité › Ephor › Réglages › Défi avant le ban**, ou par la configuration Ephor (`challenge.*`).

### Leurres

*(Edge `0.136.0`, Admin `0.229.0` ; [ADR 0020](adr/0020-reference-saisonniere-seuils-et-visibilite-amont.md), étape 2.a)* Des chemins que l'application n'utilise jamais : un dépôt `.git` oublié, une sauvegarde `.sql`, une clé `.ssh`. Quiconque les demande est presque sûrement un scanner, avec très peu de risque de se tromper : l'accès verse le signal `decoy` (8 points) à la note commune de l'IP. Sans score cumulé, un signal fort bannit aussitôt ; avec `ip_score`, un deuxième leurre franchit le seuil de ban par défaut (10).

- **Jeu par défaut** (`/.git/`, `/.svn/`, `/.hg/`, `/.aws/`, `/.ssh/`, `/.ds_store`, `/backup.sql`, `/dump.sql`, `/db.sql`, `/database.sql`, `/backup.zip`, `/site-backup.zip`, `/wp-config.php.bak`, `/wp-config.php~`, `/.env.bak`, `/.env.old`) plus les `decoys.paths` de l'administrateur. Une entrée qui finit par `/` est un préfixe, les autres sont exactes ; la casse est ignorée. `/` seul est refusé (il piégerait tout).
- **Un chemin que l'application sert n'est jamais un piège.** Le garde-fou écarte l'accès (`gpx_threat_decoy_total{result="skipped"}`) quand la route qui sert l'hôte déclare une location sur ce chemin (hors `/`), ou quand son **profil de surface appris** ([ADR 0016](adr/0016-apprentissage-de-la-surface-d-un-proxy.md)) a vu ce chemin servi à des clients propres. Un hôte sans route n'a pas d'application derrière lui : le chemin y est un piège. **Limite** : sans apprentissage de la surface sur le proxy, seules les locations protègent ; la politique OpenAPI écrite à la main n'est pas consultée.
- **Il naît en `detect`** : l'accès est compté (`result="shadow"`) et journalisé, sans effet sur la note. `off` est le défaut.
- Les chemins de la liste blanche d'Ephor ne sont jamais des leurres.

```
gpx_threat_decoy_total{result}   # hit | shadow | skipped
```

Réglable dans **Sécurité › Ephor › Réglages › Leurres**, ou par la configuration Ephor (`decoys.*`).

### Seuils

*(Edge `0.138.0`, Admin `0.231.0` ; [ADR 0020](adr/0020-reference-saisonniere-seuils-et-visibilite-amont.md), étape 2.c)* Une règle explicite « **N événements en T secondes, action** », évaluée sur la réponse que la passerelle a rendue. Pas de regex sur du texte : un événement est une réponse qui correspond à un filtre structuré. Les Seuils complètent le score pondéré des erreurs 4xx, qui ignore à dessein les 401, 403 et 429.

**Un Seuil** (`thresholds.rules[]`) :

| Champ | Rôle |
|---|---|
| `name` | Identifiant (minuscules, chiffres, `-` et `_`, 40 caractères) : il figure dans le ban, les journaux et l'explication |
| `mode` | `off`, `detect` (défaut : le dépassement est compté et journalisé, jamais appliqué) ou `block` |
| `status` | Codes (`401`) ou classes (`4xx`, `5xx`) ; vide = tous |
| `paths`, `methods`, `hosts` | Préfixes de chemin, méthodes HTTP, noms de route ; vide = tous |
| `waf` | `hit` : la requête a déclenché une règle du WAF ; `blocked` : le WAF l'a refusée |
| `count`, `window` | `count` événements (1 à 10 000) en `window` (1 s à 24 h) déclenchent l'action |
| `action` | `ban` (défaut : ban d'Ephor, avec sa durée et son escalade) ou `score` (verse `points` à la note commune, défaut 4 ; demande `ip_score.enabled`) |

**Deux Seuils sont fournis**, réglés ensemble par `thresholds.mode` (`off` par défaut) :

- `auth-fail` : 10 réponses 401 ou 403 en 5 minutes sur un point d'entrée de connexion (`/login`, `/signin`, `/sign-in`, `/auth`, `/api/auth`, `/api/login`, `/user/login`, `/account/login`, `/oauth/token`, `/wp-login.php`, `/xmlrpc.php`), hors refus du WAF. Ban.
- `waf-repeat` : 5 requêtes en 10 minutes qui déclenchent une règle du WAF. Ban.

**Fonctionnement.**

- **Compteurs par IP** (une IPv6 par son /64), **bornés** (64 shards de 4 096 clés ; un shard plein évince, parmi seize entrées examinées, celle qui n’a pas servi depuis le plus longtemps) et **conservés au redémarrage** dans la copie chiffrée d'Ephor (`threat-state.gpx`, sans l'Admin). Dix compteurs par clé, un par dixième de fenêtre : quelques dizaines d'octets, quelle que soit la fenêtre ; la fenêtre couvre donc entre 90 % et 100 % de `window`.
- **Ne comptent pas** : les requêtes qu'Ephor, un ban ou un profil IP ont refusées avant le routage, ni celles des listes blanches d'Ephor (IP, User-Agent, chemins). Un dépassement remet le compteur de l'IP à zéro.
- **Le ban est un ban d'Ephor** : source `threat`, motif `threat: seuil <nom>`, signal `threshold:<nom>` avec le nombre d'événements et la fenêtre. L'effacement RGPD d'une IP efface ses compteurs.
- **Limite** : le ban vise l'adresse exacte, comme les autres bans d'Ephor (le compteur, lui, agrège l'IPv6 par /64). Ils ont remplacé le Fail2Ban natif des passerelles (retiré en Edge `0.139.0`).

```
gpx_threat_threshold_total{result}   # hit | shadow
```

Réglable dans **Sécurité › Ephor › Réglages › Seuils** (les Seuils personnalisés s'écrivent en JSON, validé avant l'enregistrement), ou par la configuration Ephor (`thresholds.*`).

### Hôte inconnu (signal `unknown_host`)

*(Edge `0.137.0`, Admin `0.230.0` ; [ADR 0020](adr/0020-reference-saisonniere-seuils-et-visibilite-amont.md), étape 2.b)* Un accès par l'adresse IP de la passerelle, ou à un nom qu'elle ne sert pas, verse des points **modérés** (1 par défaut) à la note commune de l'IP. Sont comptés : une requête HTTP sur un hôte sans route, et les rejets TLS `no_sni`, `ip_literal`, `unknown_sni` et `not_tls` ([Porte d'entrée](#porte-dentrée--connexions-tls-et-hôte-inconnu)). Les connexions coupées, en retard ou en surnombre ne le sont pas.

- **Jamais de ban au premier accès** : un accès isolé ne prouve rien, une page tierce peut envoyer vos visiteurs sur votre IP (`<img src="http://votre-IP/">`). Plusieurs d'affilée, ou des chemins de scan sur un hôte inconnu (qui ajoutent leurs propres signaux), franchissent le seuil de ban. Le signal demande le score cumulé (`ip_score.enabled`) et des points sous le seuil de ban : sinon la configuration est refusée.
- **Exemptions** : réseaux privés, plages Cloudflare, liste blanche d'Ephor, liste blanche des bans, et les **sondes déclarées** (`unknown_host.probes`).
- **Sondes probables** : une IP dont six accès au moins sont espacés d'un intervalle presque constant (au moins 2 s) est une sonde (supervision, répartiteur de charge), pas un scanner. Elle n'est plus notée et apparaît dans **Prism › Trafic direct › Sondes probables** (et dans `probes` de `GET /api/v1/security/rejections`) : à vous de l'ajouter à `unknown_host.probes`, rien n'est exempté sans vous.
- **Il naît en `detect`** : les accès sont comptés (`gpx_threat_unknown_host_total{result="shadow"}`), sans effet sur la note. `off` est le défaut.

```
gpx_threat_unknown_host_total{result}   # counted | shadow | exempt | regular
```

Réglable dans **Sécurité › Ephor › Réglages › Hôte inconnu**, ou par la configuration Ephor (`unknown_host.*`).

### Référence saisonnière du trafic

*(Edge `0.140.0`, Admin `0.233.0` ; [ADR 0020](adr/0020-reference-saisonniere-seuils-et-visibilite-amont.md), étape 3.a)* La référence par IP d'Ephor dit qu'*une IP* s'écarte ; celle-ci dit que *le trafic d'une route* s'écarte de ce qu'il est d'habitude à cette heure de cette journée. Elle attrape ce qu'aucune IP ne montre seule : une inondation répartie sur beaucoup d'adresses, un site qui reçoit dix fois son trafic de la nuit.

- **Ce qui est appris**, par route et pour l'entrée de la passerelle (hôtes inconnus, TLS refusé) : le débit, les IP distinctes (comptage approché, sans table par IP), la part de 4xx et 5xx, la part du chemin le plus demandé. Par **créneau** (jour de la semaine × heure, UTC : 168), avec un repli sur 48 créneaux (semaine ou week-end × heure) tant que le fin n'a pas assez d'échantillons. Moyenne et variance glissantes sur plusieurs semaines, à deux pas : dix secondes et une minute.
- **Deux fenêtres.** *Rapide* (dix secondes) : le débit dépasse dix fois la moyenne du créneau **et** un plancher absolu (20 req/s par défaut). *Lente* (une minute) : le débit dépasse la moyenne plus quatre écarts-types, avec le même plancher. Le plancher évite le bruit sur les petits sites.
- **Un volume seul n'est pas une attaque** (newsletter, promotion) : c'est un **avertissement** (`warning`). Avec au moins un écart de **nature** sur la minute — IP distinctes bien au-dessus de l'habitude, part d'erreurs en hausse, concentration sur un seul chemin — c'est une **attaque probable** (`probable`).
- **Garde-fous.** Un créneau qui n'a pas vu au moins deux heures de trafic (`min_hours`) est *froid* : il n'alerte jamais. L'apprentissage est gelé pendant une alerte, et une mesure est plafonnée par rapport à la moyenne connue : un attaquant qui monte lentement n'apprend pas un « normal » trop haut. Une alerte se termine après une minute calme.
- **En `detect`, elle signale seulement.** Un écart est journalisé (`ephor: trafic hors de sa référence saisonnière`), compté (`gpx_threat_seasonal_total{kind,level}`), affiché dans **Sécurité › Ephor › Détections › Références du trafic** et notifié par le déclencheur d'alerte `traffic_deviation` *(Edge `0.141.0`, Admin `0.234.0`, étape 3.b : une alerte par route et par début, de nouveau si elle s'aggrave ; disponible aussi comme événement d'alerte des flux d'automatisation)*. Le trafic des IP en liste blanche, et celui que la passerelle refuse avant la route (IP bannies), n'y est pas compté.
- **En `block`, une attaque probable durcit la route** *(Edge `0.142.0`, Admin `0.235.0`, étape 3.c)*. Tant que l'alerte dure, les IP **sans historique propre** (pas de bonus de confiance, c'est-à-dire pas sept jours d'historique sans signal) de **cette route** :
  - reçoivent le **défi à preuve de travail** quand elles naviguent (GET ou HEAD qui demande du HTML, hors chemins exemptés) et n'ont pas encore de preuve valide ;
  - partagent un **plafond de débit adaptatif** : `cap_factor` (3 par défaut) fois la moyenne apprise du créneau, au moins le plancher (`floor_rps`), avec une rafale de deux secondes. Au-delà : `503` et `Retry-After`. Une route d'ordinaire calme est donc plafonnée bas, une route d'ordinaire chargée haut ; le `global_rps` fixe reste en tête, inchangé.
  - Les **habitués**, la liste blanche d'Ephor, la liste blanche des bans et les autres routes ne sont pas touchés. Seule une attaque *probable* durcit : un avertissement (volume seul) ne durcit jamais. Le durcissement tombe avec l'alerte (une minute calme).
  - **Le volume écarté reste compté** : sans cela l'attaque disparaîtrait des mesures, l'alerte se croirait finie et la route serait relâchée en pleine attaque.
  - **Prérequis** : `challenge.mode` en `detect` ou `block` (le défi fournit le secret et la difficulté ; en `detect` il ne sert que le profil durci). Sans comportement appris (`behavior` coupé, `no_trust`), personne n'a d'historique : tous les visiteurs de la route attaquée résolvent le défi une fois (24 h par défaut). Métrique `gpx_threat_seasonal_harden_total{result}` (`challenged`, `shed`).
  - **Écart avec l'ADR** : pas de seuils abaissés ni de tarpit pendant l'alerte, le défi et le plafond suffisent ; à ajouter si la pratique le demande.
- **En `block`, une attaque probable durcit la route** *(Edge `0.142.0`, Admin `0.235.0`, étape 3.c)*. Tant que l'alerte dure, les IP **sans historique propre** (pas de bonus de confiance, c'est-à-dire pas sept jours d'historique sans signal) de **cette route** :
  - reçoivent le **défi à preuve de travail** quand elles naviguent (GET ou HEAD qui demande du HTML, hors chemins exemptés) et n'ont pas encore de preuve valide ;
  - partagent un **plafond de débit adaptatif** : `cap_factor` (3 par défaut) fois la moyenne apprise du créneau, au moins le plancher (`floor_rps`), avec une rafale de deux secondes. Au-delà : `503` et `Retry-After`. Une route d'ordinaire calme est donc plafonnée bas, une route d'ordinaire chargée haut ; le `global_rps` fixe reste en tête, inchangé.
  - Les **habitués**, la liste blanche d'Ephor, la liste blanche des bans et les autres routes ne sont pas touchés. Seule une attaque *probable* durcit : un avertissement (volume seul) ne durcit jamais. Le durcissement tombe avec l'alerte (une minute calme).
  - **Le volume écarté reste compté** : sans cela l'attaque disparaîtrait des mesures, l'alerte se croirait finie et la route serait relâchée en pleine attaque.
  - **Prérequis** : `challenge.mode` en `detect` ou `block` (le défi fournit le secret et la difficulté ; en `detect` il ne sert que le profil durci). Sans comportement appris (`behavior` coupé, `no_trust`), personne n'a d'historique : tous les visiteurs de la route attaquée résolvent le défi une fois (24 h par défaut). Métrique `gpx_threat_seasonal_harden_total{result}` (`challenged`, `shed`).
  - **Écart avec l'ADR** : pas de seuils abaissés ni de tarpit pendant l'alerte, le défi et le plafond suffisent ; à ajouter si la pratique le demande.
- **Simulation avant de quitter `detect`** *(Edge `0.143.0`, Admin `0.236.0`, étape 3.d)*. `goproxify security threat simulate`, le bouton « Simuler » du tiroir Ephor (fenêtre de 7 jours) et l'outil MCP `simulate_ephor_config` rejouent les accès de la passerelle sur l'horloge des logs, tranches vides comprises, et disent, route par route, si elle est **jugeable** (assez d'historique dans la fenêtre), combien d'avertissements et d'attaques probables la configuration aurait ouverts, pendant combien de temps et, en `block`, combien de requêtes d'IP sans historique le profil durci aurait touchées (dont combien avaient abouti : le risque de faux positif). Une route « froide » n'est pas jugée : élargir la fenêtre avant de conclure. Passer en `block` n'a de sens qu'après avoir lu ce rapport sur plusieurs jours.
- **Autonomie.** Chaque passerelle apprend son propre trafic, sans l'Admin ; la référence est conservée chiffrée avec l'état d'Ephor (`threat-state.gpx`) et relue au redémarrage. Rien n'est synchronisé entre les membres d'un groupe HA.
- **Coût.** Par requête : quelques incréments atomiques et un bit posé dans une table de 1 Ko, sans allocation (environ 25 ns mesurés). Par route : environ 21 Ko de référence en mémoire, moins sur disque (seuls les créneaux vus sont conservés). Un tick toutes les dix secondes (environ 170 µs pour 128 routes). Au plus 128 routes suivies ; au-delà, « (autres) ».

Réglable dans **Sécurité › Ephor › Réglages › Référence saisonnière**, ou par la configuration d'Ephor :

```json
{ "seasonal": { "mode": "detect", "floor_rps": 20, "fast_factor": 10, "slow_sigmas": 4, "min_hours": 2, "cap_factor": 3 } }
```

`mode` : `off` (défaut), `detect` ou `block` (voir ci-dessus ; `cap_factor` ne sert qu'en `block`). Les autres valeurs sont des points de départ à calibrer sur votre trafic.

Lecture : `GET /api/v1/security/traffic-reference`, `goproxify security traffic-reference`, outil MCP `get_traffic_reference`.

### Simuler une config avant de l'appliquer (MCP)

L'outil MCP `simulate_ephor_config` rejoue les access logs récents (1 à 24 h, jusqu'à 168 h pour la référence saisonnière) contre une config candidate et la compare à la config en production : requêtes bloquées en plus, bans, IP les plus touchées, et `legit_blocked` (requêtes qui auraient été bloquées alors qu'elles avaient abouti, signe probable de faux positifs). Rien n'est modifié. Les listes par défaut, `global_rps` et les règles User-Agent ne sont pas simulées ; voir [docs/mcp.md](mcp.md#simulate_ephor_config).

### Whitelist par route (labels Docker)

```yaml
goproxify.ephor.whitelist: "192.168.1.5,10.0.0.0/8"
goproxify.ephor.whitelist.self: "true"     # IP actuelle du conteneur
goproxify.ephor.whitelist.network: "true"  # sous-réseau Docker du conteneur
```


## Apprentissage de la surface d'un proxy

*(Admin `0.197.0`, Edge `0.111.0`, [ADR 0016](adr/0016-apprentissage-de-la-surface-d-un-proxy.md), étape 1)* Les listes (WAF, Ephor, IP) disent ce qui est mauvais. Pour fermer un proxy à ce qui n'est pas utilisé, il faut d'abord savoir ce qu'il utilise. Le mode `learn` le mesure sur le trafic réel, **sans rien bloquer**.

- **Type de proxy** *(Admin `0.204.0`, Edge `0.118.0`)* : `surface.type` vaut `api` (surface fermée : une liste de chemins a un sens), `site` (blog, CMS, contenu créé par les utilisateurs : des milliers de chemins qui changent chaque jour) ou vide (traité comme une API). Pour un **site**, la convergence ne dépend que de l'ancienneté et du volume (ni nouveaux gabarits, ni débordement), la politique de chemins et les suggestions d'ajout ne sont pas produites, et les propositions de tailles, réseaux, pays, CORS, débit et exclusions du WAF le restent. Le rapport dit à quoi le trafic ressemble (`type_hint` : un niveau de chemin avec plus de 64 valeurs distinctes ou des chemins non retenus, c'est un site) et décrit le proxy entier : méthodes, types de contenu des requêtes et des réponses, tailles de corps.
- **Activation** : par proxy, `surface.mode` = `learn` (carte *Apprentissage de la surface* de l'onglet Avancé, ou `goproxify proxy option <id> surface '{"mode":"learn"}'`). `off` par défaut ; `detect` et `enforce` sont refusés tant que la politique positive n'existe pas.
- **Ce qui est appris** : méthodes ; gabarits de chemin (`/api/users/{int}` : entiers, UUID, dates, empreintes hexadécimales, jetons longs et adresses électroniques deviennent des classes ; au-delà de 64 valeurs littérales sous un même parent, le niveau devient `{var}`) ; par gabarit, méthodes, statuts, types de contenu, taille des corps (maximum, 99ᵉ centile), noms et types des paramètres de requête, clients distincts et jours de présence ; noms des en-têtes ; protocole et version TLS ; pays et AS.
- **Ce qui n'est jamais gardé** : une valeur de paramètre ou d'en-tête, une IP, un segment de chemin variable. Les clients distincts sont comptés par un estimateur (HyperLogLog) qui ne permet pas de retrouver une adresse : il n'y a rien à effacer lors d'un effacement RGPD.
- **Qui enseigne** : une requête n'entre dans le profil que si son statut montre que la route existe (2xx, 3xx, 401) **et** si son IP est propre (aucun signal d'Ephor, aucune règle du WAF déclenchée, aucune note de risque). Un scanner qui sonde `/.env` ne l'inscrit donc pas ; ses requêtes sont comptées à part (*exclues*, *en échec*). Un gabarit vu par moins de 3 clients ou sur moins de 2 jours est marqué *à confirmer*.
- **Convergence** : le profil est fiable après 7 jours (un cycle complet, week-end compris), 1 000 requêtes apprises et 48 h sans nouveau gabarit. Tant que ce n'est pas le cas, le rapport dit lequel de ces critères manque.
- **Mémoire bornée** : 2 000 nœuds de chemin, 64 en-têtes, 32 paramètres par gabarit, 200 AS par proxy, 1 000 proxies par passerelle. Au-delà, le profil signale un *débordement* au lieu de grossir. Coût mesuré : ≈ 0,7 µs et aucune allocation par requête.
- **Sans l'Admin** : le profil est copié chiffré sur la passerelle (`surface-state.gpx`, `GPX_SURFACE_STATE_PATH`) et relu au démarrage. Les membres d'un groupe HA se tirent leurs profils locaux et chacun affiche le profil fusionné ; un échange répété ne compte jamais deux fois.
- **Lire et remettre à zéro** : `GET /api/v1/security/surface[/report]`, `POST /api/v1/security/surface/reset`, `goproxify security surface list|report|reset`, outils MCP `get_proxy_surface` et `reset_proxy_surface`. Remettre à zéro quand l'application change.
- **Réglages proposés** *(étape 2, Admin `0.198.0`, Edge `0.112.0`)* : le profil sait proposer `max_body_size` (le double du plus gros corps vu, arrondi), `rate_limit` (le double du seuil d'Ephor le plus haut parmi les heures fiables), `geo_ip` (les pays qui couvrent 99,5 % du trafic, au plus 15), `ip_filter` (les réseaux /24 ou /48 d'où vient tout le trafic, au plus 16) et `cors` (les origines inter-origines vues, au plus 10). Chaque proposition dit ce que le profil a vu, ce qu'elle aurait refusé sur le trafic appris (`would_refuse`) et ses limites, avec la commande `goproxify proxy option` qui la pose. **Rien n'est appliqué** ; un réglage déjà posé n'est jamais remplacé ; un réglage non proposé dit pourquoi (service public, corps de taille inconnue, base GeoIP absente…). `GET /api/v1/security/surface/proposals`, `goproxify security surface proposals`, outil MCP `get_proxy_surface_proposals`. - **Exclusion de règles du WAF** *(Admin `0.202.0`, Edge `0.116.0`)* : une règle du WAF qui se déclenche de façon répétée sur des clients ordinaires est probablement un faux positif. Le profil compte, par règle, les déclenchements des IP **propres si l'on met de côté le WAF** (ni signal d'Ephor, ni score d'Ephor, ni autre signal de comportement que l'accumulation du WAF), ceux que le backend a servis, ceux que le WAF a refusés, les clients distincts, les jours et les chemins. Une règle est proposée pour `waf.exclude_ids` si **chaque client recommence** (3 déclenchements par client au moins) : 10 requêtes servies, 3 clients propres, 2 jours ; ou, si le WAF bloque, 10 refus, 5 clients, 3 jours. La proposition est la configuration `waf` complète avec `exclude_ids` augmenté. **Une attaque lente ressemble à un faux positif**, et l'exclusion vaut pour tout le proxy : pour une règle d'injection, de chemin ou de commande, corrigez plutôt le champ qui la déclenche ou écrivez une règle personnalisée sur un seul chemin. Jamais proposé pour une règle déjà exclue, une règle personnalisée, un WAF défini par un snippet ou un proxy sans WAF. Le rapport liste les règles déclenchées.
- Le profil garde pour cela les **réseaux** /24 et /48 des clients (jamais l'adresse exacte, 256 au plus) et les valeurs de l'en-tête `Origin` (50 au plus).

### Politique positive générée *(étape 3, Admin `0.199.0`, Edge `0.113.0`)*

Le profil sait aussi s'écrire comme une **spécification OpenAPI 3.1** pour le contrôle `openapi` que le proxy a déjà, posée en mode `detect` avec `unknown_paths: block`. Rien n'est refusé : tout ce qui sort de la politique est compté.

- **Contenu** : les chemins appris (`/api/users/{users_id}` ; les paramètres sont nommés d'après le segment qui les précède et typés : entier, UUID, date, empreinte hexadécimale, sinon texte), les méthodes vues par chemin, les paramètres de requête typés (jamais obligatoires), les types de contenu de requête des méthodes à corps. **Pas les corps** : le profil ne les apprend pas. Le contrôle openapi ne refuse pas un paramètre de requête inconnu.
- **Écarté** : les chemins vus par moins de 3 clients ou sur moins de 2 jours (*à confirmer*, gardés par `include_low_support`), plus profonds que 12 segments, ou contenant une accolade. Deux gabarits qui se recouvrent (`/u/{int}` et `/u/{var}`) sont fusionnés en un chemin à paramètre texte, sans quoi le contrôle refuserait à tort.
- **Poser la politique** : bouton *Générer la politique (OpenAPI)* puis *Pré-remplir la validation OpenAPI* (la carte du même nom est remplie en `detect`, la politique s'applique à l'enregistrement du proxy) ; ou `goproxify security surface openapi -proxy … -out openapi.json` puis `goproxify proxy option <id> openapi @openapi.json` ; ou l'outil MCP `get_proxy_surface_openapi` puis `update_proxy`. Un contrôle openapi déjà actif est signalé (`replaces`), jamais écrasé sans confirmation dans l'interface.
- **Lire les violations** : tant que le mode `learn` est actif, le verdict du contrôle openapi remonte au profil, même en `detect`. Le rapport de surface liste, par raison (chemin inconnu, méthode inconnue, paramètre invalide, corps invalide, type de contenu, corps trop gros), méthode et **chemin normalisé** (les identifiants deviennent `{int}`, `{uuid}`…), le nombre de requêtes, de clients distincts et de réussites depuis une IP propre. Un chemin hors politique qui réussit le plus souvent depuis plusieurs clients propres est marqué *à ajouter ?* : c'est un chemin légitime que la politique ignore. 100 violations distinctes au plus par proxy ; aucune IP, aucun identifiant dans l'état.
- **Note d'Ephor** : le signal `surface_violation` (3 points, 10 minutes, `detect` par défaut) ne concerne qu'une violation que le backend a refusée ; une violation servie ne pèse pas.
- **Avant de bloquer** : le profil doit être convergé (`ready`), les violations *à ajouter ?* traitées, et les chemins exclus relus.

#### Refuser, type de violation par type de violation *(étape 4, Admin `0.200.0`, Edge `0.114.0`)*

Le réglage `openapi` du proxy accepte `block_reasons` : en mode `detect`, le contrôle refuse quand même les violations de ces types et laisse passer, en les comptant, les autres. En mode `block` la liste est sans effet (tout est refusé).

| Type | Réponse | Ce que c'est |
|---|---|---|
| `unknown_path` | 404 | chemin absent de la politique (exige `unknown_paths: block`) |
| `unknown_method` | 405 (+ `Allow`) | méthode absente pour ce chemin (idem) |
| `invalid_param` | 400 | paramètre de chemin ou de requête qui n'a pas le bon type |
| `invalid_body` | 422 | corps qui ne respecte pas son schéma (aucun, dans une politique apprise) |
| `unsupported_media` | 415 | type de contenu de la requête non déclaré |
| `too_large` | 413 | corps trop gros pour être validé |

- **Garde-fous** (Admin, `POST /api/v1/security/surface/enforce`) : une politique openapi **active** et un profil (jamais passés outre) ; un profil **convergé** ; aucun chemin *à ajouter ?* pour les types demandés ; un profil qui n'a pas débordé. Un refus renvoie `409` et `blockers`, sans rien modifier. `force` passe outre les trois derniers et le consigne à l'audit (`surface_enforce_forced`) ; `dry_run` calcule sans écrire.
- **Avant de cocher** : pour chaque type, le panneau et la réponse disent combien de requêtes ont été vues hors de la politique et **combien ont réussi depuis des IP propres** : ce sont des clients légitimes que le refus couperait.
- **Refuser des types, pas tout** : on commence par ce qui ne coûte rien (`unknown_method`, `unsupported_media`, `too_large`), puis `invalid_param`, enfin `unknown_path`, une fois les chemins *à ajouter ?* traités.
- **Retour en un geste** : `POST /api/v1/security/surface/relax` (bouton *Repasser en detect*, `goproxify security surface relax`) remet `mode: detect` et retire `block_reasons` ; la spécification reste. Consigné (`surface_relax`).
- **Journal des refus** : le rapport de surface compte les violations refusées (`blocked_totals`, `blocked` par violation).
- **Limite** : ces garde-fous sont ceux de l'assistant ; poser `block_reasons` ou `mode: block` à la main reste possible sans eux.

#### Ajouts suggérés à la politique *(étape 5, Admin `0.201.0`, Edge `0.115.0`)*

Le mode `learn` reste actif une fois la politique posée. Un chemin (`unknown_path`) ou une méthode (`unknown_method`) hors politique qui revient de plusieurs clients ordinaires sur plusieurs jours est proposé à l'ajout.

| Confiance | Le profil a vu | Seuils |
|---|---|---|
| **haute** | le backend a **servi** ces requêtes | 5 réussites au moins et au moins la moitié des requêtes hors politique, 3 clients propres, 2 jours |
| **basse** | le contrôle les **refuse** ; seuls des clients propres reviennent | 5 clients propres, 3 jours, 70 % de requêtes propres, la moitié au moins refusées |

- **Pourquoi deux niveaux** : une violation refusée n'a jamais de réussite à citer, et c'est précisément celle qu'on voudrait voir revenir quand la politique est en `block`. La confiance basse dit seulement que des clients ordinaires reviennent ; un scanner distribué ressemble à cela, d'où « à examiner ».
- **Jamais suggérés** : les chemins que visent les scanners (`.env`, `.git`, `wp-login`, `wp-admin`, `xmlrpc.php`, `phpmyadmin`, `cgi-bin`, `passwd`…), quel que soit le nombre d'IP. Les autres types de violation (paramètre, corps, type de contenu) restent dans le rapport : le profil n'y retient pas de quoi écrire un ajout.
- **Accepter** (`POST /api/v1/security/surface/accept`, panneau du rapport, `goproxify security surface accept`, outil MCP `accept_proxy_surface_suggestions`) **ajoute** à la spécification, sans rien retirer. Un chemin de même forme reçoit la méthode ; si le type de son paramètre diffère, il est élargi en texte. Seules les suggestions actuelles du profil sont acceptables, la spécification doit être en JSON (un texte YAML est refusé), l'ajout est consigné (`surface_accept`) et les violations acceptées sont effacées des profils de toutes les passerelles.
- **La politique ne s'élargit jamais seule.** Le nombre d'ajouts en attente figure dans la liste des proxies (`suggestions`), et le déclencheur d'alerte `surface_suggestion` prévient quand l'un apparaît.
- **Alerte `surface_suggestion`** *(Admin `0.203.0`, Edge `0.117.0`)* : dans les règles d'alerte (Admin → Alerting → Règles). Chaque passerelle envoie à l'Admin l'état de ses suggestions toutes les 5 minutes ; l'Admin alerte **une fois par proxy et par lot** de suggestions nouvelles de **confiance haute**. Les suggestions de confiance basse n'alertent pas (leur nombre est dans le message). Une suggestion réglée est oubliée, une suggestion qui revient alerte de nouveau ; un groupe HA n'alerte qu'une fois. Détail de l'événement : `proxy`, `domain`, `count`, `suggestions`, `low_confidence` ; gravité `info`, périmètre filtrable par domaine. L'Admin retient ce qu'il a signalé en mémoire : après son redémarrage, les suggestions en attente alertent une fois de plus.

## Cache disque : isolation entre utilisateurs

Le cache d'une route (`cache.enabled`) est partagé entre tous les clients ; il ne doit jamais faire fuiter la réponse d'un utilisateur vers un autre :

- une requête portant `Authorization` ou un cookie n'est ni servie depuis le cache ni stockée, sauf option explicite : `cache.ignore_cookies` (cookies ignorés, à réserver aux routes dont la réponse ne dépend pas d'eux) ou `cache.vary_cookies` (la valeur des cookies listés entre dans la clé) ;
- une réponse avec `Cache-Control: private` ou `no-store`, un `Set-Cookie` ou `Vary: *` n'est jamais stockée ;
- `Vary` est respecté : la clé inclut la valeur des en-têtes de requête listés ;
- `bypass_headers` et `bypass_cookies` restent disponibles pour d'autres critères de contournement.

---

## Validation JWT (JWKS)

La clé est choisie par `kid` dans le JWKS du fournisseur : `kty` `RSA` (RS256/384/512), `EC` (ES256 sur P-256, ES384 sur P-384, ES512 sur P-521) et `OKP` Ed25519 (EdDSA). Le type de clé doit correspondre à l'algorithme annoncé par le jeton (pas de confusion RS/ES). `alg: none` et les algorithmes HS* sont toujours refusés. `iss`, `aud` et `exp` sont contrôlés.

Le jeton est lu dans `Authorization: Bearer <jeton>` (préfixe insensible à la casse) ; avec `header_name: Authorization` le préfixe est retiré comme sans `header_name`, et dans un en-tête personnalisé (`X-Token`) le jeton peut être brut ou précédé de `Bearer `.

## Backpressure par route

Protège les backends (et la mémoire de la passerelle) quand ils ralentissent : au-delà d'un plafond de requêtes simultanées, les requêtes attendent dans une file bornée puis sont rejetées.

```json
"backpressure": { "max_inflight": 200, "queue": 100, "queue_timeout_ms": 1000 }
```

| Champ | Description |
|---|---|
| `max_inflight` | Requêtes traitées en parallèle sur la route. `0` = désactivé |
| `queue` | Requêtes en attente au-delà du plafond. `0` = rejet immédiat |
| `queue_timeout_ms` | Attente maximale en file (défaut `1000`) |

Une requête rejetée (file pleine, délai dépassé, client parti) reçoit `503` avec `Retry-After: 1`. Les upgrades WebSocket ne consomment pas de slot. Le plafond est propre à chaque instance de passerelle (non partagé en cluster) et repart de zéro à chaque rechargement de la route.

```
gpx_backpressure_inflight{host}
gpx_backpressure_queued{host}
gpx_backpressure_rejected_total{host, reason}   # queue_full | timeout | canceled
```

---

## Gestion des bans

Les bans sont centralisés dans l'Admin et propagés aux passerelles via WebSocket.

### Sources de ban

| Source | Description |
|--------|-------------|
| `native` | Ban manuel depuis l'UI Admin |
| `waf` | Ban automatique par le moteur comportemental WAF |
| `threat` | Ban automatique par l'Ephor |
| `fleet` | Ban posé par les Seuils multi-passerelles de l'Admin |
| `crowdsec` | Décision LAPI CrowdSec (stream push) |

### Bans par plage CIDR

Un ban manuel (UI, API, CLI `security bans add`, outils MCP `create_security_ban` / `ban_ip`) vise une adresse IPv4/IPv6 **ou une plage CIDR** : les passerelles bloquent toute adresse qu'elle contient (réseaux privés exemptés, comme pour un ban d'adresse). Avant d'enregistrer, la cible est **validée et normalisée** : une plage devient son adresse de réseau (`203.0.113.7/24` → `203.0.113.0/24`), une adresse seule reste telle quelle (`/32` et `/128` retirés, IPv6 en minuscules). Une valeur illisible est refusée, alors qu'elle était auparavant enregistrée puis ignorée sans rien dire.

Garde-fous :

- **Largeur maximale** : `/16` en IPv4, `/32` en IPv6. Pour bloquer plus large (un pays, un opérateur), utiliser un profil IP, avec ses sources et sa priorité allow/deny.
- **Pas d'auto-verrouillage** : une plage qui contient l'adresse de l'appelant est refusée (`409`). Une adresse seule n'est pas concernée.
- **Aperçu avant de créer** (`GET /security/bans/preview`, bouton « Aperçu de l'impact » du formulaire de ban, `security bans preview`, outil MCP `preview_security_ban`) : trafic récent de la cible, dont les requêtes **réussies** qu'un ban couperait (signe d'un faux positif), bans actifs qui la recoupent (déjà couverte, ou qui deviendraient redondants), profils IP qui la recoupent, et avertissements. Rien n'est créé.

Limites : débannir une adresse située dans une plage bannie ne lève pas le ban de la plage — supprimer la plage, ou ajouter l'adresse à la [liste blanche](#liste-blanche-des-bans) ; la répartition des bans par pays ne compte pas les plages (elle repose sur la géolocalisation d'adresses précises) ; Ephor, les Seuils multi-passerelles et CrowdSec continuent de poser des bans d'adresse.

### Bans par ASN

Un **ASN** (système autonome) est l'ensemble des adresses d'un opérateur : hébergeur, fournisseur d'accès, cloud. Bannir un ASN revient à bannir toutes les plages qu'il annonce, utile contre un hébergeur dont viennent les scanners et les robots (page Bans › **+ ASN**, API `POST /security/asn/ban`, CLI `security bans asn`, outils MCP `lookup_asn`, `preview_asn_ban`, `ban_asn`, `unban_asn`).

- **Chercher** par numéro (`AS16276`), par adresse IP (l'ASN qui l'annonce) ou par nom.
- **Mesurer avant de bannir** : l'aperçu donne le nombre de plages, celles qui seraient ignorées (déjà bannies, en liste blanche, privées), le trafic de l'ASN sur les dernières heures et surtout les requêtes **réussies** qui seraient coupées. Un gros opérateur grand public (un fournisseur d'accès) a des millions d'adresses : vérifier qu'il s'agit bien d'abus.
- **Bannir** crée un ban par plage (souvent des centaines), avec la portée, l'expiration et le motif choisis, en une transaction et **un seul envoi** aux passerelles. Les plages plus larges que `/16` (IPv4) sont découpées en `/16`. Un ASN qui contient votre adresse est refusé. Les plages en liste blanche restent exemptées.
- **Lever** : le bandeau « Bans par ASN » de la page Bans (une ligne par ASN, bouton « Lever »), `DELETE /security/asn/ban` ou `security bans asn unban` retirent tous les bans de l'ASN d'un coup. Les centaines de plages sont masquées de la liste des bans (bouton « Afficher les N plages »).

Les données viennent du jeu public **ip2asn** d'[iptoasn.com](https://iptoasn.com) (domaine public, sans compte, mis à jour toutes les heures), que l'Admin télécharge au premier usage dans `<stockage>/asn/ip2asn-combined.tsv.gz` (9 Mo ; `GPX_ASN_DB_PATH` pour l'emplacement, `GPX_ASN_DB_URL` pour la source) et recharge quand le fichier change. `POST /security/asn/refresh` (ou `security bans asn refresh`) le met à jour. **Les passerelles n'en ont pas besoin** : elles reçoivent de simples bans par plage, comme tout autre ban, et restent autonomes si l'Admin tombe.

Limites : le ban est un **instantané** des plages annoncées au moment où il est posé (relancer l'opération ajoute les plages annoncées depuis, sans doublon) ; chaque requête est comparée aux bans un par un : mesuré sur de vraies données, un gros ASN donne de quelques centaines à quelques milliers de plages (OVH : 660, Cloudflare : 2 837), mais l'effet de dizaines de milliers de plages sur la latence n'a pas été mesuré, donc éviter de bannir de très nombreux gros ASN ; une plage annoncée qui donnerait plus de 1 024 morceaux n'est pas bannie (comptée dans `too_wide`) ; la liste blanche et les profils `allow` l'emportent toujours.

### Import de liste

Page Bans › **Importer** (API `POST /security/bans/import`, CLI `security bans import`, outil MCP `import_security_bans`) : crée des bans, ou des entrées de la [liste blanche](#liste-blanche-des-bans), depuis une liste collée ou un fichier. Formats : **texte** (une adresse ou un CIDR par ligne, commentaires `#` et `;` — le commentaire devient le motif —, ce qui couvre les listes publiques FireHOL, blocklist.de, Spamhaus DROP), **CSV** (colonnes `ip`, `reason`, `domain`, `expires_at` ; l'export des bans se réimporte tel quel) et **JSON** (tableau de chaînes ou d'objets). 10 000 entrées et 2 Mo au plus par import.

Chaque entrée est validée comme un ban unitaire ([plages CIDR](#bans-par-plage-cidr)) : une valeur illisible, une plage trop large (au-delà de `/16` IPv4 ou `/32` IPv6), une plage qui contient l'adresse de l'appelant ou une expiration illisible sont **rejetées**. Sont **ignorées** (valides, mais sans objet) : les doublons, les entrées couvertes par une plage plus large de la même liste, les cibles déjà couvertes par un ban actif ou par la liste blanche, les plages privées ou locales (jamais bloquées). Le rapport donne le nombre d'adresses couvertes et, pour chaque entrée rejetée ou ignorée, sa ligne et la raison.

**Analyser avant d'importer** : `dry_run` (bouton « Analyser », `-dry-run`) produit le même rapport sans rien écrire. L'import réel crée les bans en une transaction (historique alimenté, import audité) puis les pousse **une seule fois** aux passerelles. Ils sont de source `native` : visibles, prolongeables et supprimables comme n'importe quel ban manuel ; un import répété est sans effet (tout est « déjà couvert »). Une liste publique importée ne se met pas à jour toute seule : pour un abonnement automatique à un flux, utiliser un profil IP à source distante (page Profils IP).

### Ban ciblant une passerelle ou un groupe

Par défaut un ban s'applique sur **toutes** les passerelles. Le champ « S'applique à » du formulaire Bannir et de l'import (`target_scope` côté API, `-scope` en CLI, `scope` pour les outils MCP `create_security_ban` et `import_security_bans`) le limite à **une passerelle** (par son nom) ou aux **membres d'un groupe HA** (`group:<nom>`). L'Admin n'envoie à chaque passerelle que les bans globaux, ceux qui la visent et ceux de son groupe ; une portée inconnue est refusée. Les passerelles pairs se partagent aussi leurs bans entre elles quand l'Admin est injoignable : la portée est conservée avec le ban, et une passerelle n'adopte d'un pair que les bans globaux, ceux qui la visent ou ceux de son groupe HA. La liste des bans affiche la portée (pastille « → … ») et se filtre par `?scope=`.

Limites : la portée se choisit à la création (pour la changer, supprimer le ban et le recréer) ; les bans posés par une passerelle (Ephor, plugins, règles) restent partagés avec toutes les autres comme avant ; un déban lève l'adresse sur toutes les passerelles, puis chacune reçoit de nouveau ses propres bans restants.

### Liste blanche des bans

Page Bans › **Liste blanche** (API `GET|POST|DELETE /security/bans/whitelist`, CLI `security bans whitelist`, outils MCP `list_ban_whitelist` / `add_ban_whitelist` / `remove_ban_whitelist`). Une adresse ou une plage CIDR en liste blanche :

- n'est atteinte par **aucun ban**, quelle qu'en soit la source (manuel, Seuils, CrowdSec, Ephor, règles automatiques, bans reçus d'un pair) ;
- **n'est pas évaluée par Ephor** : ses requêtes ne sont ni bloquées ni comptées (c'est ce qui la distingue d'un profil IP allow ordinaire, qui ne prime que sur les bans et les profils deny).

Les entrées (avec un commentaire) sont validées et normalisées comme la cible d'un ban (`/16` IPv4 et `/32` IPv6 au plus larges). Ajouter une entrée **ne supprime aucun ban** : les bans existants cessent seulement de s'appliquer à ces adresses (la liste des bans les marque « Exempté » quand la liste blanche couvre toute leur cible) et s'appliquent de nouveau si l'entrée est retirée. Une entrée déjà couverte par une plus large ne change rien ; une entrée plus large retire les plus précises. Un ban dont la cible est entièrement en liste blanche est refusé (`409`) ; une plage qui ne fait que recouper une entrée reste permise et l'entrée en reste exemptée.

La liste est recopiée dans un profil IP en mode `allow` d'identifiant `bans-whitelist`, **géré par la page Bans** (Profils IP ne peut ni le modifier ni le supprimer). Comme tout profil IP, les passerelles le reçoivent, le conservent sur leur disque et l'appliquent **sans l'Admin**, y compris après un redémarrage. Les adresses privées ou locales sont de toute façon jamais bloquées par un ban, mais restent évaluées par Ephor sauf si elles figurent dans la liste blanche.

Les listes blanches propres à chaque moteur (Ephor, Seuils multi-passerelles) subsistent ; la liste blanche des bans est le moyen de tout exempter en un seul endroit.

### Déban

Débannir une IP depuis l'Admin (UI, CLI `security bans delete`, outils MCP `delete_security_ban` / `unban_ip`) lève **tous** ses bans sur chaque passerelle, y compris ceux que la passerelle a posés elle-même (Ephor, plugins, règles automatiques, ban reçu d'un pair HA), et remet à zéro les compteurs d'Ephor de l'IP, Seuils compris. Le déban est conservé sur le disque de la passerelle (survit à un redémarrage) et rejoué à une passerelle qui était déconnectée au moment du déban, à sa reconnexion (débans des 30 derniers jours). Un pair HA qui n'a pas encore reçu le déban ne peut pas réinjecter l'ancien ban ; un ban posé **après** le déban reste appliqué normalement.

Les 403 servis à une IP bannie ne comptent pas pour les Seuils (Admin et passerelle) : sans cela, l'IP serait rebannie sur ses propres refus dès la levée du ban.

### Listes blanches et bans existants

Une IP de la liste blanche d'Ephor (globale ou `ephor.whitelist` d'une route) n'est plus bloquée par les bans d'Ephor et de ses plugins déjà posés. Pas besoin d'attendre l'expiration ni de débannir. Les bans manuels et CrowdSec restent appliqués ; pour exempter une IP de tout ban (et d'Ephor), utiliser la [liste blanche des bans](#liste-blanche-des-bans), ou un profil IP en mode `allow` pour les seuls bans.

### Seuils multi-passerelles

*(Edge `0.139.0`, Admin `0.232.0` ; [ADR 0020](adr/0020-reference-saisonniere-seuils-et-visibilite-amont.md), étape 2.c)* Le moteur de l'Admin qui additionne les erreurs client (4xx hors 404) comptées par **chaque** passerelle et bannit une IP dont les erreurs se répartissent sur plusieurs passerelles : elle ne dépasse le seuil d'aucune d'elles, seule l'Admin les voit toutes. C'était la moitié « Admin » de l'ancien « Fail2Ban natif », dont la moitié « passerelle » est remplacée par les [Seuils](#seuils) d'Ephor.

- **Réglages** (`GET|PUT /api/v1/security/fleet`, Sécurité › Moteurs › Seuils multi-passerelles) : `enabled`, `window_sec` (défaut 300), `max_errors`, `ban_duration_sec` (0 = permanent), `trust_forwarded_for`, `whitelist` (IPv4, IPv6, CIDR).
- **D'où viennent les compteurs** : chaque passerelle envoie à l'Admin des compteurs d'erreurs client par IP et par minute (`ip_stream`), sans autre donnée.
- **IPv4 et IPv6** : une IPv6 est comptée et bannie par /64 (un abonné y change d'adresse à volonté) ; le ban porte le préfixe (`2a01:e0a:1:2::/64`), qu'il faut débannir en entier. Si la liste blanche recoupe le /64, les adresses voisines de l'IP exemptée sont comptées et bannies une par une.
- **Avec des IP protégées** ([anonymisation ou pseudonymisation](rgpd.md#2-minimisation-options)), les passerelles n'envoient qu'une IP tronquée (`203.0.113.0`, préfixe /48) qui ne désigne aucun client : la compter cumulerait les erreurs de tout un /24 ou /48. Le moteur écarte ces lignes et **ne bannit plus du tout** tant que l'Admin pousse l'un des deux modes. Seule la détection d'une IP répartie sur plusieurs passerelles est alors perdue : les Seuils d'Ephor, eux, reçoivent l'IP réelle avant troncature et continuent de bannir.
- **Le ban** a la source `fleet` (« Seuils multi-passerelles » dans la page Bans), le motif `Seuils multi-passerelles : N erreurs en Ns` et le déclencheur d'alerte `fleet_ban`. Métriques `gpx_fleet_bans_total` et `gpx_fleet_scans_total`.

### CrowdSec

Bouncer LAPI en mode stream : les décisions CrowdSec sont poussées en temps réel à la passerelle (ban 403). Compatible déploiement Docker.

### Traçage d'une IP ou d'un CIDR

**Sécurité › Traçage IP** (ou « Parcours complet » dans l'historique d'une IP de la page Bans) répond à « que fait cette IP depuis des semaines ? » : on saisit une IP ou un CIDR et une période (24 h à tout l'historique conservé), et l'Admin assemble en une chronologie les requêtes d'accès, les détections WAF/Ephor/CrowdSec, les bans et débans, ainsi que l'état actuel (bans en cours, profils IP qui contiennent la cible).

- **Épisodes** : les requêtes de la cible séparées de moins de 10 minutes forment une seule étape (volume, bloquées, domaines, chemins, statuts, catégories WAF), pour qu'une période d'un an reste lisible.
- **CIDR** : toutes les IP du préfixe sont réunies ; l'en-tête donne leurs requêtes cumulées et les IP les plus actives. Un ban posé sur un CIDR apparaît dans le parcours d'une IP qu'il contient.
- **Limites** : les requêtes remontent aussi loin que la rétention des logs d'accès (365 jours par défaut, réglable dans les réglages des Logs) ; les bans et détections ont leur propre historique. Les IP pseudonymisées ou tronquées par la passerelle (RGPD) ne peuvent pas être retrouvées.

- **Opérateur et ASN** : quand la base ASN est installée (voir [Bans par ASN](#bans-par-asn)), l'en-tête du parcours d'une IP indique son opérateur (ASN, nom, pays), avec deux boutons : **Cette IP** et **Tout l'ASN** (sans avoir à connaître le CIDR), plus « Bannir l'ASN » (aperçu d'impact puis ban). Un traçage simple ne télécharge jamais la base : l'en-tête n'apparaît que si elle est déjà installée. Les adresses privées ou réservées, que le jeu de données ne connaît pas, se tracent comme avant, en choisissant l'IP ou un CIDR à la main. Un opérateur qui annonce de très larges préfixes regroupe beaucoup d'acteurs : l'ASN entier n'est pas forcément celui d'un attaquant, d'où le choix de l'étendue. Tracer tout un ASN parcourt les logs sans borne sur l'adresse (limites habituelles du traçage).

**Raccourci** : une loupe « Analyser l'IP » à côté des IP publiques (page Bans, menaces, Ephor, Prism, tiroir des logs) ouvre directement le parcours de l'IP ; l'élargissement à l'ASN se fait depuis l'en-tête (voir ci-dessus), ou à une plage par les boutons « Élargir à » (`/24`, `/16` ; `/64`, `/48` en IPv6). Les adresses privées, pseudonymisées ou tronquées n'ont pas de bouton.

La chronologie va du **plus récent au plus ancien** (bouton « Plus ancien d'abord » pour l'inverser). Quand le ban en cours ou l'étape de ban vient d'Ephor ou du WAF, la trace affiche aussi **pourquoi** : les signaux qui l'ont causé, avec leurs points et la valeur observée, et le **User-Agent** que la passerelle a vu en dernier pour l'IP — celui du client qui a provoqué le ban. Cela vaut pour tous les bans automatiques d'une passerelle : Ephor et WAF (Seuils compris), plugins de détection, règles automatiques. Les bans manuels, importés ou CrowdSec n'en ont pas (aucune requête vue par la passerelle). La page Bans l'affiche aussi sous la raison du ban.

API : `GET /api/v1/security/ip-trace` ; CLI : `goproxify security trace` ; MCP : `trace_ip`.

---

## Flux d'automatisation

Depuis Admin `0.139.0` (ADR 0009), les règles automatiques, les planifications et les playbooks sont un seul objet, le **flux**. Il se compose d'un déclencheur, d'un garde-fou et d'une suite d'étapes. On le construit dans `Automatisation > Automatisations > Éditeur de flux`, ou on l'installe depuis `Modèles`. Les onglets **Règles**, **Planifications** et **Playbooks** sont des vues des flux, selon leur déclencheur.

| Déclencheur | Onglet | Quand |
|---|---|---|
| `condition` | Règles | Une condition, ou un arbre ET / OU / NON, évaluée toutes les `interval_sec` secondes (60 par défaut) |
| `event` | Règles | Un événement du moteur d'alertes (ban des Seuils multi-passerelles, décision CrowdSec, backend indisponible, budget SLO…), filtré par nœud, domaine, gravité et motifs sur le détail |
| `schedule` | Planifications | Une expression cron à 5 champs, à l'heure locale de l'Admin |
| `manual` | Playbooks | Lancé à la main ou par l'étape « lancer un playbook » d'un autre flux, avec des paramètres |

### Conditions

| Type | Description | Paramètres |
|---|---|---|
| `cve_critical` | CVE ouverte avec score CVSS ≥ seuil sur un backend | `cvss_threshold` (défaut 9), `proxy_id` optionnel |
| `ban_spike` | Pic de nouveaux bans sur une fenêtre de temps | `ban_count`, `ban_window`, `ban_source` optionnel |
| `engine_silent` | Seuils multi-passerelles (`fleet`) ou CrowdSec inactifs depuis N minutes | `engine_type`, `silent_minutes` |
| `proxy_error_rate` | Taux d'erreurs 5xx d'un proxy ≥ seuil | `proxy_id` optionnel, `error_rate_threshold`, `error_rate_window` |
| `ban_repeat` | IP bannie N fois ou plus sur une période | `repeat_count`, `repeat_window` |
| `node_offline` | Nœud sans nouvelles depuis N minutes | `node_name` optionnel, `offline_minutes` |
| `cert_expiring` | Certificat TLS expirant sous N jours | `domain` optionnel, `days_left` |
| `metric_threshold` | Seuil sur une métrique relevée par l'Admin : trafic, erreurs et latence par proxy ou par passerelle, TLS, connexions, pipeline, compteurs de l'Admin. Les erreurs et la latence par proxy, le trafic de la passerelle et les métriques TLS sont aussi calculés par chaque passerelle : un flux simple qui en surveille une s'exécute sur les passerelles | `metric`, `entity`, `aggregation` (avg, min, max, last, increase, rate), `window` (1 h au plus), `operator`, `value`, `min_samples` |

Le détail produit par une condition (IP, proxy, domaine, valeur mesurée…) est disponible dans les étapes en `{{detail.x}}`. L'éditeur liste les variables disponibles à chaque étape.

### Étapes

| Étape | Effet |
|---|---|
| `action` | Exécute une action : `disable_proxy`, `ban_ip`, `notify`, `enable_strict`, `webhook_call`, `webhook_signed`, `pagerduty` ou `run_backup` |
| `wait` | Attend une durée, puis passe à l'étape suivante |
| `if` | Évalue une condition et suit la branche « alors » ou « sinon » |
| `approval` | Attend une décision humaine, avec un délai facultatif au bout duquel la décision par défaut s'applique |
| `call` | Lance un playbook, en attendant sa fin ou non, avec des paramètres (souvent des variables) |
| `stop` | Termine l'exécution avec un statut et une raison |

Par défaut, l'IP de `ban_ip` et le proxy de `disable_proxy` sont ceux du détail (`{{detail.ip}}`, `{{detail.proxy_id}}`). L'action `notify` publie l'événement `automation_notify`, que les règles de routage d'alertes acheminent vers les canaux. `webhook_call` et `webhook_signed` envoient `{flow, flow_id, run_id, description, detail, fired_at}`. La signature de `webhook_signed` est `X-GPX-Signature: sha256=…`, calculée sur `horodatage.corps`. Une étape en échec arrête l'exécution, sauf si elle est marquée « continuer si cette étape échoue ».

### Garde-fou

- **Délai minimum** (`cooldown_sec`) : intervalle minimal entre deux déclenchements automatiques. Il vaut 300 s par défaut pour une condition ou un événement, sinon une condition qui reste vraie relancerait ses actions à chaque évaluation. Il survit à un redémarrage de l'Admin.
- **Délai par valeur** (`cooldown_key`, par exemple `{{detail.ip}}`) : le délai s'applique séparément à chaque IP plutôt qu'au flux entier.
- **Exécutions simultanées** (`max_concurrent`, 1 par défaut) : un flux qui attend une approbation ne repart pas tant qu'elle n'est pas décidée.
- Un lancement manuel ignore ces garde-fous.

### Approbation

Une étape **Approbation** suspend l'exécution, qui passe au statut `waiting_approval`, et publie une notification « Approbation requise ».

La décision se prend à plusieurs endroits :
- le bandeau de la vue d'ensemble ;
- l'historique du flux ;
- le journal ;
- `POST /api/v1/automation/runs/{id}/approve|reject` ;
- `goproxify automation runs approve|reject` ;
- l'outil MCP `decide_flow_run`.

Chaque décision enregistre son auteur, disponible en `{{steps.<id>.actor}}`. Refuser termine l'exécution (`rejected`). Sans décision dans le délai choisi, l'option « sans décision » s'applique.

### Exécutions, reprise et journal

Chaque déclenchement crée une exécution, enregistrée après chaque étape avec son curseur et ses variables. Les attentes et les approbations reprennent donc après un redémarrage de l'Admin.

Une étape en cours au moment d'un arrêt n'est jamais relancée d'office, parce qu'une action pourrait agir deux fois : l'exécution passe à `interrupted`, et **Rejouer** la relance avec le même détail.

Le journal (`Automatisation > Journal`) liste toutes les exécutions, quelle que soit leur source :
- l'Admin ;
- une passerelle ;
- une personne ;
- un autre flux.

Pour chaque exécution, il montre le détail de ses étapes. Les exécutions terminées sont purgées après 30 jours. Seul le leader d'un Admin en haute disponibilité déclenche et fait avancer les flux.

### Simulation et versions

**Simuler** parcourt le flux sans rien exécuter, même un brouillon non enregistré :
- les conditions sont évaluées pour de vrai, sur les données actuelles ;
- les actions montrent leur configuration résolue ;
- les attentes sont sautées et les approbations supposées accordées ;
- les playbooks appelés sont parcourus.

Chaque enregistrement ajoute une version ; les 20 dernières sont conservées, et **Rétablir** en refait la version courante.

### Flux exécutés par les passerelles

Un flux simple s'exécute **sur chaque passerelle**, sur ses propres données, à deux conditions :
- son déclencheur est une condition que la passerelle sait évaluer (`ban_spike`, `engine_silent`, `proxy_error_rate`, `ban_repeat`) ;
- sa seule étape est une action qu'elle sait exécuter (`disable_proxy`, `ban_ip`, `notify`, `enable_strict`).

La passerelle en garde une copie locale chiffrée : le flux continue pendant une coupure de l'Admin, même après un redémarrage de la passerelle (ADR 0006). L'Admin lui envoie la liste à chaque modification, ne l'évalue plus lui-même, journalise ce qu'elle remonte (source `edge:<nœud>`) et achemine ses notifications vers les canaux.

L'éditeur indique où s'exécute chaque flux et pourquoi. Le garde-fou **Toujours sur l'Admin** force l'évaluation sur l'Admin, avec une vue de tout le cluster.

### Modèles

Les modèles (`Automatisation > Automatisations > Modèles`) sont des flux paramétrables : règles, planification de sauvegarde, playbooks d'isolement d'un proxy ou de bannissement.

- **Installation** : le formulaire des paramètres s'accompagne d'un aperçu du flux.
- **Réédition** : un flux installé depuis un modèle se modifie par ce même formulaire ; il est reconstruit avec la version courante du modèle.
- **Détachement** : **Personnaliser dans l'éditeur** détache le flux de son modèle ; il garde sa définition et se modifie ensuite dans l'éditeur.

### Mises en sourdine

Une **mise en sourdine** (`Automatisation > Alertes > Mises en sourdine`, table `automation_silences`) suspend, sur une fenêtre de temps, les déclenchements automatiques des flux et l'envoi des notifications des règles d'alerte. Elle s'applique à tout, ou à une liste de flux et de règles d'alerte (`rule_ids`).

- **Flux** : un déclenchement en sourdine est journalisé (`silenced`) sans être exécuté, et ne consomme pas le délai minimum. Un lancement manuel n'est pas concerné.
- **Moteur d'alertes** : aucun canal n'est notifié, l'événement est journalisé avec `silenced=1`, le délai de rappel n'est pas consommé.

Les flux exécutés par les passerelles sont aussi mis en sourdine : l'Admin envoie à chaque passerelle, avec chaque flux, les fenêtres en cours ou à venir qui le visent, et renvoie la liste à chaque création ou suppression d'une mise en sourdine. La passerelle les garde dans sa copie locale chiffrée (`auto-rules.gpx`) et les applique seule, y compris redémarrée pendant une coupure de l'Admin. Un déclenchement ignoré remonte au journal comme `silenced` (au plus un par délai minimum, une minute au moins).

### Export / import YAML (GitOps)

`GET /api/v1/automation/export` renvoie en YAML (`version: 2`) les flux, les canaux d'alerte et les mises en sourdine, avec les secrets masqués.

`POST /api/v1/automation/import` applique un document au même format :
- flux et canaux sont mis à jour par nom, en gardant leurs secrets, ou créés ;
- les playbooks sont importés d'abord, pour que les flux qui les appellent se valident ;
- les mises en sourdine sont ajoutées.

L'import est disponible depuis la vue d'ensemble, `goproxify automation export|import` et les outils MCP `export_automation` / `import_automation`.

### Canaux d'alerte

En plus d'email, webhook générique, ntfy et gotify, et des canaux de ticketing (Jira, Linear, GitHub, GitLab, Zammad, GLPI), le moteur d'alertes notifie :

| Type | Configuration | Détails |
|---|---|---|
| `slack` | `webhook_url` | Webhook entrant Slack (Slack App > Incoming Webhooks) |
| `teams` | `webhook_url` | Connecteur webhook entrant Microsoft Teams (ou flux Power Automate) |
| `telegram` | `bot_token`, `chat_id` | API Bot Telegram (`sendMessage`) — créer un bot via [@BotFather](https://t.me/BotFather) |
| `sms` | `account_sid`, `auth_token`, `from`, `to` | API Twilio (`Messages.json`), numéros au format E.164 |

### Regroupement anti-bruit

Une règle d'alerte peut définir `group_window_sec` (secondes, défaut 0 = désactivé) : tant qu'une fenêtre de regroupement est ouverte, les événements qui correspondent à la règle s'accumulent au lieu de notifier immédiatement ; à la fin de la fenêtre, une **notification unique** résume le nombre d'événements et liste les 5 premiers (les suivants sont comptés). Le cooldown habituel de la règle continue de s'appliquer par ailleurs (il détermine si un événement rejoint le tampon en cours, pas la fréquence des envois groupés). Réglable depuis `Automatisation > Alertes > Routage`, `goproxify alert rules create|update -file`, ou les outils MCP `create_alert_rule`/`list_alert_rules`.

### Escalades avec accusé de réception

Une règle d'alerte peut définir `escalation`, une liste de paliers `{ after_sec, channels }` : si l'événement déclenché n'a pas été **acquitté** avant `after_sec` secondes, il est renotifié vers `channels` (vide = les canaux de la règle), avec un titre préfixé `[ESCALADE]` et une sévérité forcée à `critical`. Chaque palier revérifie l'état d'acquittement au moment de se déclencher : un accusé de réception après la programmation d'un palier le rend simplement silencieux, sans avoir besoin de l'annuler.

**Acquitter** un événement (`POST /api/v1/alert-events/{id}/ack`, bouton **Acquitter** dans le tiroir de détail de `Alertes et SLO`, `goproxify alert ack <event-id>`, MCP `ack_alert_event`) enregistre `acked=1`, `acked_by` (l'acteur authentifié) et `acked_at`. Il n'existe pas encore de lien d'accusé cliquable directement depuis l'e-mail ou Slack/Teams/Telegram (pas de webhook entrant) : le corps du message d'escalade renvoie vers `Admin > Automatisation > Alertes` pour acquitter depuis une session authentifiée.

---

## Porte d'entrée : connexions TLS et hôte inconnu

Avant tout routage, la passerelle lit le début de chaque connexion HTTPS (le ClientHello) pour y trouver le nom demandé (SNI) et l'empreinte du client ([ADR 0020](adr/0020-reference-saisonniere-seuils-et-visibilite-amont.md), étape 0).

- **Lecture hors de la boucle d'acceptation** : une connexion qui n'envoie rien ne retarde pas les suivantes. Elle est fermée au bout de 3 secondes (`gpx_tls_rejected_total{reason="timeout"}`).
- **Plafond de lectures simultanées** : 2 048 au total et 32 par source (une IPv6 compte pour son /64). Au-delà, la connexion est fermée (`reason="too_many_pending"`). Valeurs fixes pour l'instant.
- **Nom sans certificat, ou accès par l'IP** (aucun SNI) : la poignée de main TLS échoue, sans page d'erreur. Aucun ban n'en découle : un accès isolé n'est pas une attaque, et une page tierce peut faire envoyer à vos visiteurs une requête vers votre IP.
- **Ce qui est refusé se voit** *(Edge `0.135.0`, étape 1.c)* : chaque rejet est compté par raison dans `gpx_tls_rejected_total{reason}` — `timeout` (ClientHello jamais reçu), `too_many_pending`, `bad_clienthello` (connexion coupée avant tout TLS), `not_tls` (HTTP en clair ou autre protocole sur le port TLS), `no_sni` (accès par l'IP), `ip_literal` (le nom demandé est une adresse), `unknown_sni` (nom sans certificat), `handshake_failed` (nom connu, poignée de main interrompue) — et les requêtes HTTP sur un hôte sans route dans `gpx_edge_unknown_host_total`. Aucun de ces compteurs ne porte le nom demandé : il est choisi par le client.
  - **Une ligne de journal par raison et par fenêtre de 5 secondes** (IP, empreinte JA4, nom tronqué à 64 caractères et assaini, nombre de rejets regroupés) : un scan de plusieurs milliers d'IP ne remplit pas les logs système.
  - **Classement en mémoire à taille fixe** (256 noms, 256 IP, 128 empreintes ; les petites entrées sont évincées, l'ordre est approché), vidé au redémarrage et à l'effacement RGPD d'une IP. Lu par `GET /internal/v1/rejections` sur l'API interne de la passerelle : totaux par raison, premiers noms demandés avec le nombre d'IP distinctes qui les demandent (plafonné à 64), premières IP, premières empreintes. Un nom demandé par beaucoup d'IP distinctes est plutôt un proxy oublié qu'un scanner. C'est de la visibilité : rien n'en dépend et rien n'en est banni. L'Admin l'affiche par passerelle dans l'onglet **Trafic direct** de Prism (sans période : ce sont les compteurs depuis le démarrage de chaque passerelle) et l'expose par `GET /api/v1/security/rejections`, `goproxify security rejections` et l'outil MCP `get_entry_rejections` *(Admin `0.228.0`)*.
- **Hôte inconnu en HTTP** (aucune route) : `network.unknown_host_action` dans `edge.json`, ou `GPX_NETWORK_UNKNOWN_HOST_ACTION` quand la clé est absente du JSON ; redémarrage nécessaire.

  | Valeur | Réponse |
  |---|---|
  | `neutral` (défaut) | `404` sans corps ni marque du produit |
  | `close` | connexion HTTP/1 coupée sans réponse ; en HTTP/2 (connexion non détournable), `404` neutre. Peut faire déclarer en panne un répartiteur de charge qui attend un statut HTTP |

  La page d'erreur à la marque de GoProxify n'est plus jamais servie pour un nom qui n'atteint aucune route ; les pages d'erreur personnalisées d'une route sont inchangées.
- **Métriques** : l'étiquette `host` d'une métrique n'est jamais le nom écrit par le client mais celui de la route qui le sert (`*.example.fr` pour un joker) : voir [metrics.md](metrics.md#tls--handshake--connexions-gpx_tls_).

Fermer la connexion ne fait pas passer l'IP pour inutilisée (le port reste ouvert et demande le bon nom) ; cela évite seulement de révéler le logiciel et d'y consacrer du travail.

---

## Timeouts serveur HTTP/QUIC

Configurable depuis l'UI Admin (Sécurité > Timeouts HTTP/QUIC). Propagé aux passerelles via WebSocket et persisté dans `edge.json`.

> ⚠️ Un **redémarrage de la passerelle** est nécessaire pour appliquer les timeouts.

| Paramètre | Défaut | Description |
|---|---|---|
| `read_header_seconds` | 10 | Protection anti-Slowloris : temps max pour lire les headers |
| `read_seconds` | 30 | Temps max pour lire la requête complète |
| `write_seconds` | 60 | Temps max pour envoyer la réponse |
| `idle_seconds` | 120 | Temps max d'inactivité sur une connexion keep-alive |
| `max_header_kb` | 32 | Taille max cumulée des en-têtes de requête (Ko) ; au-delà : `431`. `0` = défaut |

La passerelle refuse aussi les méthodes `TRACE` et `TRACK` (`405`) sur toutes les routes.

### Benchmark : couper le travail par requête

À réserver aux mesures de performance (`edge.json`, section `engine`, ou variables `GPX_ENGINE_METRICS_DISABLED` / `GPX_ENGINE_ACCESS_LOG_DISABLED`), redémarrage nécessaire :

| Paramètre | Défaut | Effet |
|---|---|---|
| `metrics_disabled` | `false` | Plus de métriques Prometheus par requête (`/metrics` reste servi, compteurs figés) |
| `access_log_disabled` | `false` | Plus de log d'accès global : plus de Prism/Logs, ni de signal Ephor ou proxy issu du log |

Par route, `logging.access_log` vaut `true` quand la clé est absente (un bloc `logging` sans `access_log` ne coupe plus le log). `max_body_size` : voir [labels.md](labels.md) (défaut 100 Mo, `-1` = illimité).

---

## Dashboard Ephor — répartition géographique des bans

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

Ces déclencheurs sont disponibles dans les règles d'alerte (Admin → **Alerting → Règles**) :

| Déclencheur | Événement |
|-------------|-----------|
| `ephor_ban` | Nouvelle IP bannie par l'Ephor (automatique ou signal comportemental) |
| `backend_down` | Un backend passe de `healthy` à `unhealthy` (callback `OnDown` du health-check) |
| `surface_suggestion` | Un ajout est suggéré à la politique de surface d'un proxy ([ADR 0016](adr/0016-apprentissage-de-la-surface-d-un-proxy.md)) : un chemin ou une méthode hors politique revient de plusieurs clients ordinaires sur plusieurs jours |
| `traffic_deviation` | Le trafic d'une route s'écarte de sa référence saisonnière ([ADR 0020](adr/0020-reference-saisonniere-seuils-et-visibilite-amont.md), étape 3.b) : une alerte par route et par début, de nouveau si elle s'aggrave ; sévérité `warning` (volume seul) ou `critical` (attaque probable). Variables : `{{detail.route}}`, `level`, `rps`, `expected`, `natures` |

Le payload du webhook `backend_down` contient :
```json
{ "url": "http://10.0.0.5:3000", "node_name": "edge-eu-west" }
```

Ces événements peuvent être routés vers n'importe quel canal d'alerte (email, Slack webhook, ntfy, Jira…) via les règles d'alerte standard.

---

## Scanner CVE

Analyse les backends HTTP configurés à la recherche de vulnérabilités connues (CVEs). Disponible dans l'Admin (Sécurité > Scanner CVE).

- Refuse par défaut les cibles sur IPs privées (RFC1918, localhost, metadata cloud) — protection anti-SSRF
- Option **Autoriser les backends IP privées** (toggle admin) : permet de scanner des backends Docker/LAN
  - Configurable aussi via `GPX_VULNSCAN_ALLOW_PRIVATE=true` sur l'Admin
- **Couverture et surcharges de CPE** *(Admin `0.210.0`)* : seuls les produits dont l'identifiant CPE de NVD est connu sont cherchés. Le rapport (`coverage` de `GET /api/v1/security/inventory`, page Vulnérabilités, `goproxify security cve inventory -gaps`) dit pour chaque entrée si elle est cherchée (`covered`), sans version (`no_version`), sans CPE sûr (`no_cpe`) ou absente de la table (`unknown`). L'administrateur donne un identifiant avec `PUT /api/v1/security/cpe-overrides` (`goproxify security cve cpe set`) : il complète la table sans jamais la corriger, et vit sur l'Admin, qui seul interroge NVD.
- **Empreinte des réponses du backend** *(Admin `0.209.0`, tous les proxys)* : la passerelle lit, **avant** `hide_server`, les en-têtes `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator` et le `<meta name="generator">` du début des pages HTML (échantillonné, la page n'est pas modifiée). Elle ne fait aucune requête de plus. Les entrées (produit, version, source `headers` ou `html`) sont copiées chiffrées (`apps-state.gpx`, `GPX_APPS_STATE_PATH`), relues au démarrage, partagées entre les membres d'un groupe HA et expirent après 30 jours sans nouvelle observation. Le scanner les traite comme celles de l'image : un serveur sur un réseau privé que l'Admin n'atteint pas est scanné d'après ce que la passerelle a vu. Si l'image et les réponses divergent, l'image l'emporte et une note le dit.
- **Inventaire par image** *(Admin `0.208.0`)* : pour un proxy créé par labels, l'Agent annonce l'image du conteneur et la passerelle la garde sur le backend. Le scanner lit cet inventaire (`GET /api/v1/security/inventory`) : un produit connu (table d'images, avec son identifiant CPE NVD) et une version lue dans l'étiquette (`wordpress:6.4.2-apache` donne 6.4.2) suffisent à interroger NVD **sans sonder le backend** (donc aussi pour un conteneur sur un réseau Docker privé). Une étiquette qui n'est pas une version (`latest`, `stable`, condensat), un produit inconnu ou une passerelle injoignable laissent le backend à la sonde d'en-têtes. Un produit sans CPE sûr est listé « non couvert », jamais cherché en texte libre. Les CVE sont rattachées à un proxy, un produit, une version et une source (`image` ou `headers`) ; un résultat est **à vérifier, pas une preuve**, car une distribution peut rétroporter un correctif sans changer la version. À la mise à jour d'un conteneur, les CVE de l'ancienne version qui ne concernent pas la nouvelle passent à `fixed`. L'inventaire sert uniquement les vulnérabilités : le WAF n'en reçoit rien.
- Le **certificat TLS du backend n'est pas vérifié** par la sonde (expiré, auto-signé, mauvais nom : le backend est scanné quand même). Elle ne lit que des en-têtes de réponse. Les appels à NVD, KEV et EPSS vérifient les certificats.
- Déclenchable manuellement ; intégrable aux alertes (notification sur CVE détectée)

### Exploitation active (KEV), probabilité d'exploitation (EPSS) et SLA de correction

En fin de scan, chaque CVE déjà détectée est enrichie (meilleur effort — réseau externe indisponible = simplement pas enrichie, le scan n'échoue pas) :

- **KEV** : la CVE figure au catalogue [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (exploitation activement observée). Catalogue entier mis en cache 24h en mémoire (`GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`).
- **EPSS** : probabilité (0-1) d'exploitation dans les 30 jours, modèle [FIRST.org EPSS](https://www.first.org/epss/) (`GET https://api.first.org/data/v1/epss`, par lots de 100 CVE).

Une CVE exploitée (KEV) pèse davantage dans le **score de risque** (page Vulnérabilités et Synthèse Sécurité) que son seul CVSS, et peut être isolée via le filtre KEV.

Le **SLA de correction** (délai attendu après détection, selon la gravité CVSS) est un réglage global, éditable dans la fenêtre **Moteurs de sécurité > Scanner CVE** (ou `GET/PUT /api/v1/security/sla-config`, `goproxify security cve sla get/set`). Défaut : 7 j (critique, CVSS ≥ 9), 14 j (élevée, ≥ 7), 30 j (moyenne, ≥ 4), 90 j (faible). L'échéance est recalculée à la lecture (jamais stockée), pour refléter immédiatement un changement de seuils.

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

- **Profils IP** : listes de blocage ou d'autorisation avec mise à jour automatique depuis des sources publiques (Tor, Cloudflare, AWS, Spamhaus, FireHOL…). Les profils `deny` bloquent sur toutes les passerelles ; les profils `allow` servent au filtrage CDN. Les CIDRs sont agrégés (doublons et préfixes contenus fusionnés), les plages privées sont exclues des profils `deny` et les feeds inchangés ne sont pas retéléchargés (ETag / 304). Spamhaus DROP, DShield et Feodo sont désactivés par défaut car inclus dans FireHOL Level 1. Un feed en échec est retenté avec un backoff (15 min → 6 h max), la dernière liste valide reste appliquée, l'état est visible dans l'UI, et une mise à jour qui perd plus de la moitié d'une liste (feed vide ou tronqué) est rejetée. Après N échecs consécutifs (3 par défaut, réglage `ipprofile.alert_after_failures`, `0` = désactivé), le déclencheur d'alerte `ip_profile_refresh_failed` est émis une fois par série.
- **GeoIP** : autorisation ou blocage par pays (MaxMind GeoLite2, téléchargé automatiquement au démarrage).

---

## Métriques et observabilité

Tous les moteurs exposent des métriques Prometheus. Sur une passerelle, elles sont servies par l'API interne — `GET /metrics` (ou `/internal/v1/metrics`) sur le port interne, avec le jeton de la passerelle (`authorization: { credentials: <jeton> }` côté Prometheus) — et **pas** sur les ports publics ; `GPX_METRICS_PUBLIC=1` sert `/metrics` sur les ports publics (à réserver à un accès filtré par le réseau : les métriques listent hôtes, backends et compteurs de sécurité). L'Agent sert `:9191/metrics` (CPU et mémoire de l'hôte).

```
# WAF
gpx_waf_matches_total
gpx_waf_requests_inspected_total
gpx_waf_behavior_signals_total

# Ephor
gpx_threat_*

# Bans
gpx_bans_active_total
```

Les logs d'accès incluent les décisions WAF (`waf_matches`, `waf_score`) sur chaque requête. Les refus d'un plugin de détection comme Coraza y figurent aussi (catégorie = nom du plugin) et peuvent bannir l'IP sous la source `plugin:<nom>` (voir [plugins.md](plugins.md#plugins-de-détection)). La page **Prism** permet d'analyser le trafic par IP, code HTTP et domaine, avec accès direct aux bans depuis la table des IPs.

---

## Locations et casse du chemin

Les locations `prefix`/`exact` portant `auth`, `ip_filter` ou `rate_limit` sont comparées **sans tenir compte de la casse** (chemin décodé, normalisé, mis en minuscules) : face à un backend insensible à la casse (IIS, ASP.NET), `/API/V1/ADMIN/x` et `/api/v1/%41dmin/x` atteignent sinon `/api/v1/admin` sans authentification (constat S3). Les autres locations restent sensibles à la casse ; l'option `case_insensitive` (`true`/`false`) sur la location force l'un ou l'autre. Les locations `regex` ne sont jamais repliées (utiliser `(?i)`). Ne forcer `case_insensitive: false` sur une location protégée que si le backend est lui-même sensible à la casse.

## WebSocket : contrôle d'Origin (CSWSH)

Quand une route définit `cors.allowed_origins` (liste non vide), l'upgrade WebSocket est refusé en `403` si l'en-tête `Origin` est présent et absent de la liste, y compris `Origin: null`. Une origine listée, ou une requête sans `Origin` (client non navigateur), passe. Le joker `*` n'est pas accepté (comme pour CORS) : une liste réduite à `*` refuse donc toute origine. Sans `cors.allowed_origins`, aucun contrôle n'est appliqué : à renseigner dès que l'authentification repose sur un cookie.

## Socket Docker de l'Agent

L'Agent crée, arrête, renomme et supprime des conteneurs (mises à jour d'image, retour arrière, escalade de santé, scaling). Son accès au socket Docker (`/var/run/docker.sock`) équivaut donc à **root sur l'hôte** : qui peut y envoyer des requêtes peut lancer un conteneur privilégié monté sur `/`.

- **Un montage `:ro` ne limite rien.** Il protège le fichier du socket, pas ce qu'on envoie au démon par ce socket. Les exemples de déploiement ne l'emploient plus, pour ne pas laisser croire le contraire.
- **Seul le code de l'Agent borne ce qu'il fait du socket.** Il ne modifie que les conteneurs qu'il gère et recrée un conteneur avec sa configuration d'origine, mais Docker ne l'impose pas : un Agent compromis obtient l'hôte.
- **L'Admin et la passerelle n'ont pas besoin du socket** et ne le montent pas. Ne déployez l'Agent que sur les hôtes dont vous voulez découvrir ou piloter les conteneurs (sous Kubernetes, `agent.config.runtime: none` par défaut et `agent.nodeSelector`).
- **Recréation d'un conteneur** : l'ancien est mis de côté sous un autre nom jusqu'à ce que le nouveau tourne ; en cas d'échec il est remis en place et redémarré. Variables, ports, montages (volumes anonymes compris), réseaux avec leurs alias et IP fixes, santé et ressources sont repris tels quels, seule l'image change.
