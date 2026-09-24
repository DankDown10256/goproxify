# Référence des labels Docker GoProxify

L'Agent GoProxify détecte automatiquement les conteneurs portant `goproxify.enable: "true"` et configure le Core en conséquence. Tous les labels sont optionnels sauf `goproxify.enable` et `goproxify.host`.

---

## Identification du proxy

| Label | Valeurs | Description |
|---|---|---|
| `goproxify.enable` | `"true"` | **Requis.** Active la découverte du conteneur. |
| `goproxify.type` | `http` \| `tcp` \| `udp` | Type de proxy (défaut : `http`). |
| `goproxify.host` | `app.example.fr` | **Requis.** Hostname(s) publics, séparés par virgule. Accepte aussi des préfixes de chemin : `app.example.fr, app.example.fr/admin`. |
| `goproxify.port` | `"3000"` | Port de l'application dans le conteneur. |
| `goproxify.backend` | `http://app:8080` | URL complète du backend (surcharge host+port). |
| `goproxify.tls` | `"true"` | Active la terminaison TLS (HTTPS public → HTTP interne). |
| `goproxify.https` | `"true"` | Le backend écoute en HTTPS. |
| `goproxify.passthrough` | `"true"` | SSL passthrough (le Core ne déchiffre pas). |
| `goproxify.ip` | `"10.0.1.5"` | Surcharge l'IP auto-détectée du conteneur. |

---

## Comportement HTTP

| Label | Valeurs | Description |
|---|---|---|
| `goproxify.preserve_host` | `"true"` | Transmet le `Host` original au backend (défaut : remplacé par l'adresse backend). |
| `goproxify.websocket` | `"true"` | Active le support WebSocket. |
| `goproxify.http_version` | `"1.1"` \| `"2"` | Version HTTP utilisée vers le backend. |
| `goproxify.request_id` | `"true"` | Injecte un header `X-Request-ID` unique par requête. |
| `goproxify.strip_prefix` | `"/api"` | Retire le préfixe avant de transmettre la requête au backend. |
| `goproxify.path_rewrite` | `"/api→/v2/api"` | Réécriture de chemin. |

---

## En-têtes

| Label | Valeurs | Description |
|---|---|---|
| `goproxify.headers.add` | `"X-Foo:bar,X-Baz:qux"` | Ajoute des headers à chaque requête transmise au backend. |
| `goproxify.headers.remove` | `"X-Powered-By,Server"` | Supprime des headers de la réponse. |

---

## Timeouts & limites

| Label | Valeurs | Description |
|---|---|---|
| `goproxify.timeout.connect` | `"5s"` | Timeout de connexion au backend. |
| `goproxify.timeout.response` | `"30s"` | Timeout d'attente de la réponse complète. |
| `goproxify.timeout.send` | `"10s"` | Timeout d'envoi de la requête. |
| `goproxify.max_body_size` | `"10m"` | Taille maximale du corps de requête (octets ou suffixe `k`/`m`/`g`). |

---

## Load balancing & résilience

| Label | Valeurs | Description |
|---|---|---|
| `goproxify.lb` | `round_robin` \| `weighted` \| `adaptive` | Algorithme de répartition de charge (plusieurs backends). |
| `goproxify.sticky_cookie` | `"GPXSESSION"` | Nom du cookie de session sticky. |
| `goproxify.retry` | `"3"` \| `"3:500ms"` | Nombre de tentatives et délai entre chacune. |
| `goproxify.circuit_breaker` | `"5:30s"` | Seuil d'erreurs : durée d'ouverture du circuit. |
| `goproxify.limit_conn` | `"50"` | Nombre maximum de connexions simultanées **par IP**, propre à la route. |
| `goproxify.backpressure` | `"200"` \| `"200:100"` \| `"200:100:2s"` | Plafond de requêtes simultanées de la route `max[:file[:attente max]]` ; les excédentaires attendent dans la file bornée puis reçoivent `503` + `Retry-After`. Voir [security.md](security.md#backpressure-par-route). |
| `goproxify.slow_start` | `"30"` \| `"30s"` \| `"2m"` | Durée de montée en charge (~5 % → 100 %) d'un backend nouvellement ajouté ou revenu après une panne, utile au scale-out. |

---

## Sécurité — Générale

| Label | Valeurs | Description |
|---|---|---|
| `goproxify.rate_limit` | `"100/s"` \| `"100/s:50"` | Rate limiting : requêtes/seconde et burst optionnel. |
| `goproxify.rate_limit.rps` | `"100"` | Alias généré par l'UI (rps uniquement). |
| `goproxify.rate_limit.burst` | `"50"` | Burst séparé (combiné avec `.rps`). |
| `goproxify.ip_filter` | `"allow:10.0.0.0/8"` \| `"deny:1.2.3.4"` | Filtrage IP/CIDR. Préfixe `allow:` ou `deny:`, valeurs séparées par virgule. |
| `goproxify.cors` | `"https://app.example.com,https://www.app.example.com"` | Origins CORS autorisées (CSV). |
| `goproxify.geo_ip` | `"allow:FR,DE"` \| `"deny:CN,RU"` | Filtrage géographique par code pays ISO 3166-1. |
| `goproxify.snippets` | `"waf-default,headers-secure"` | IDs de snippets de sécurité définis dans l'Admin (CSV). |
| `goproxify.auth_provider` | `"authentik-prod"` | ID du fournisseur d'authentification configuré dans l'Admin. |

---

## Sécurité — WAF

Le WAF applique les règles OWASP Core Rule Set (CRS) sur les requêtes HTTP.

| Label | Valeurs | Description |
|---|---|---|
| `goproxify.waf` | `"block"` \| `"detect"` \| `"true"` | Active le WAF. `block` bloque les requêtes malveillantes, `detect` journalise sans bloquer. |
| `goproxify.waf.anomaly_threshold` | `"10"` | Score d'anomalie cumulatif avant blocage (défaut : `5`). Augmenter réduit les faux positifs. |
| `goproxify.waf.max_body_mb` | `"10"` | Taille maximale du corps analysé par le WAF en Mo (défaut : `8`). |
| `goproxify.waf.exclude_ids` | `"942100,941100"` | IDs de règles OWASP CRS à désactiver pour ce proxy (CSV). |
| `goproxify.waf.behavior` | `"true"` | Active l'analyse comportementale par IP (score cumulatif sur une fenêtre glissante). |
| `goproxify.waf.behavior.window` | `"60"` | Fenêtre d'observation en secondes (défaut : `60`). |
| `goproxify.waf.behavior.threshold` | `"8"` | Score comportemental avant bannissement temporaire (défaut : `8`). |
| `goproxify.waf.trusted_proxies` | `"10.0.0.0/8,172.16.0.0/12"` | CIDRs de proxies de confiance dont le header `X-Forwarded-For` est accepté (CSV). Laisser vide pour utiliser `RemoteAddr` directement (plus sécurisé). |

---

## Sécurité — Protection bot

| Label | Valeurs | Description |
|---|---|---|
| `goproxify.bot` | `"true"` | Active la détection de bots. |
| `goproxify.bot.mode` | `"block"` \| `"monitor"` \| `"log"` \| `"challenge"` | Mode de réponse aux bots détectés. `challenge` déclenche un challenge JavaScript. |

---

## Sécurité — Sentinel (whitelist par route)

Le Sentinel est le moteur global de détection de menaces du Core. Il s'applique **avant le routage**, donc indépendamment des proxies. Ces labels permettent d'exempter certaines sources pour un conteneur donné — les entrées sont fusionnées dans la whitelist globale du Sentinel.

> **Note DHCP** : les IPs Docker sont dynamiques. Préférer `.self` ou `.network` plutôt que des IPs statiques dans `.whitelist`.

| Label | Valeurs | Description |
|---|---|---|
| `goproxify.sentinel.whitelist` | `"192.168.1.5,10.0.0.0/8"` | IPs/CIDRs statiques exemptés du Sentinel (CSV). |
| `goproxify.sentinel.whitelist.self` | `"true"` | Exempte automatiquement l'IP actuelle du conteneur. Compatible DHCP — l'IP est lue au démarrage du conteneur. |
| `goproxify.sentinel.whitelist.network` | `"true"` | Exempte automatiquement le sous-réseau Docker du conteneur (CIDR récupéré via l'API Docker). Utile pour les health-checkers internes. |

---

## Authentification

| Label | Valeurs | Description |
|---|---|---|
| `goproxify.jwt` | `"https://idp.example.com/.well-known/jwks.json"` | Valide les JWT entrants (signature vérifiée par la clé JWKS du fournisseur). Seule une URL JWKS est acceptée : un secret inline ou `"true"` ne sont **pas** supportés, le label est alors ignoré avec un avertissement dans les logs de l'Agent et la route n'est pas protégée. |
| `goproxify.jwt.issuer` | `"https://idp.example.com"` | Issuer exigé (optionnel, recommandé). |
| `goproxify.jwt.audience` | `"my-api"` | Audience exigée (optionnel, recommandé). |
| `goproxify.mtls` | `"/etc/goproxify/ca.pem"` | Chemin, **côté Core**, du fichier CA (PEM) qui signe les certificats clients ; un certificat client valide est exigé. Si le fichier est illisible, la route répond `503` au lieu de s'ouvrir. `"true"` n'est pas supporté (ignoré avec avertissement). |

---

## Cache

| Label | Valeurs | Description |
|---|---|---|
| `goproxify.cache` | `"60s"` \| `"true"` | Active le cache HTTP. `true` utilise les valeurs par défaut. |

---

## Logs

| Label | Valeurs | Description |
|---|---|---|
| `goproxify.logs` | `"true"` | Active le log forwarding (logs Docker → Core). |
| `goproxify.logs.format` | `combined` \| `json` \| `minimal` | Format des logs d'accès. |
| `goproxify.logs.level` | `debug` \| `info` \| `warn` \| `error` | Niveau de log. |

---

## Mises à jour d'images

| Label | Valeurs | Description |
|---|---|---|
| `goproxify.update.auto` | `"true"` | Active les mises à jour automatiques d'image. |
| `goproxify.update.schedule` | `"0 3 * * *"` | Cron de mise à jour (défaut : quotidien à 3h). |
| `goproxify.update.prune` | `"true"` | Supprime les anciennes images après mise à jour. |
| `goproxify.update.rollback_timeout` | `"60s"` | Délai avant rollback automatique si le conteneur mis à jour ne démarre pas. |

---

## Health checks

| Label | Valeurs | Description |
|---|---|---|
| `goproxify.healthcheck.restart_max` | `"3"` | Nombre de redémarrages avant recréation du conteneur. |
| `goproxify.healthcheck.recreate_timeout` | `"120s"` | Délai d'attente avant rollback lors d'une recréation. |

---

## Auto-scaling

| Label | Valeurs | Description |
|---|---|---|
| `goproxify.scale.min` | `"1"` | Nombre minimum d'instances. |
| `goproxify.scale.max` | `"5"` | Nombre maximum d'instances. |
| `goproxify.scale.cpu_threshold` | `"80"` | Seuil CPU (%) déclenchant un scale-out. |
| `goproxify.scale.cooldown` | `"120s"` | Délai minimum entre deux décisions de scaling. |

---

## Canary / Shadow

| Label | Valeurs | Description |
|---|---|---|
| `goproxify.canary` | `"true"` | Ce conteneur est un backend canary (reçoit un pourcentage du trafic). |
| `goproxify.canary.weight` | `"10"` | Pourcentage du trafic routé vers le canary (défaut : `10`). |
| `goproxify.shadow` | `"true"` | Ce conteneur est un backend shadow (copie silencieuse du trafic, réponse ignorée). |

---

## Exemple complet

```yaml
services:
  monapp:
    image: monapp:latest
    labels:
      # Identification
      goproxify.enable: "true"
      goproxify.host: "app.example.fr"
      goproxify.port: "3000"
      goproxify.tls: "true"

      # WAF
      goproxify.waf: "block"
      goproxify.waf.anomaly_threshold: "10"
      goproxify.waf.behavior: "true"
      goproxify.waf.trusted_proxies: "10.0.0.0/8"

      # Bot
      goproxify.bot: "true"
      goproxify.bot.mode: "challenge"

      # Sentinel — exempter le réseau interne (health-checkers, monitoring)
      goproxify.sentinel.whitelist.network: "true"
      goproxify.sentinel.whitelist.self: "true"

      # Rate limiting
      goproxify.rate_limit: "200/s:100"

      # Mises à jour auto la nuit
      goproxify.update.auto: "true"
      goproxify.update.schedule: "0 3 * * *"
    networks:
      - app_network

networks:
  app_network:
```
