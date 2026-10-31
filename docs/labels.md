# Référence des labels Docker GoProxify

L'Agent GoProxify détecte automatiquement les conteneurs portant `goproxify.enable: "true"` et configure la passerelle en conséquence. Tous les labels sont optionnels sauf `goproxify.enable` et `goproxify.host`.

Les mêmes étiquettes valent pour les instances lues dans un annuaire de services — tags et métadonnées Consul, tags Nomad, `dockerLabels` et tags ECS, valeur JSON etcd (voir « Service directory discovery » dans [fonctionnalites.md](fonctionnalites.md)) : seules changent l'adresse et le port, que l'annuaire fournit (étiquettes `goproxify.scheme` et `goproxify.port` pour les ajuster).

Pour un proxy déjà créé dans l'Admin, **Proxies › ⋯ › Labels** (ou `goproxify proxy labels <id>`, ou l'outil MCP `get_proxy_labels`) produit les labels équivalents en Docker Compose, Portainer (avec ou sans `stack.env`), `docker run` ou Kubernetes, et liste les réglages du proxy qu'aucun label ne porte.

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
| `goproxify.passthrough` | `"true"` | SSL passthrough (la passerelle ne déchiffre pas). |
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
| `goproxify.max_body_size` | `"10m"` | Taille maximale du corps de requête (octets ou suffixe `k`/`m`/`g`). Défaut 100 Mo ; `-1` = illimité. Au-delà : 413. |

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
| `goproxify.plugins` | `"geo-headers,audit"` | Plugins WebAssembly installés (CSV, dans l'ordre d'exécution). Voir [plugins.md](plugins.md). |
| `goproxify.plugin.<nom>.<clé>` | `"X-Geo"`, `"true"`, `"5"` | Configuration du plugin `<nom>` ; `true`/`false` et les nombres gardent leur type. Validée par le manifeste du plugin s'il est installé sur la passerelle. |

> **Un label de sécurité illisible refuse la route.** Si `ip_filter`, `geo_ip`, `waf`, `bot`, `rate_limit`, `cors`, `backpressure`, `jwt` ou `mtls` est présent mais ne peut pas être lu (valeur sans adresse, URL JWKS manquante, mode inconnu…), l'agent le signale et la passerelle répond `422` : la route n'est pas enregistrée, plutôt que servie sans la protection demandée (avant Agent `0.9.3`, certains de ces labels étaient ignorés en silence). `false`, `0`, `off`, `no`, `none` et `disabled` désactivent explicitement `waf` et `bot`. La passerelle valide aussi le contenu (mode, CIDR, code pays, expression WAF) comme le dry-run d'un proxy ; un snippet ou un plugin pas encore poussé par l'Admin n'est pas une erreur (la route refuse le trafic, `503`, jusqu'à son arrivée).

---

## Sécurité — WAF

Le WAF applique les règles OWASP passerelle Rule Set (CRS) sur les requêtes HTTP.

| Label | Valeurs | Description |
|---|---|---|
| `goproxify.waf` | `"block"` \| `"detect"` \| `"true"` | Active le WAF. `block` bloque les requêtes malveillantes, `detect` journalise sans bloquer. |
| `goproxify.waf.anomaly_threshold` | `"10"` | Score d'anomalie cumulatif avant blocage (défaut : `5`). Augmenter réduit les faux positifs. |
| `goproxify.waf.max_body_mb` | `"10"` | Taille maximale du corps analysé par le WAF en Mo (défaut : 128 Kio). Le reste du corps est transmis sans analyse ; plus la limite est haute, plus une requête volumineuse coûte de CPU. |
| `goproxify.waf.exclude_ids` | `"942100,941100"` | IDs de règles OWASP CRS à désactiver pour ce proxy (CSV). |
| *(pas de label)* | | Les exclusions de règles **par chemin** (`waf.exclusions`) ne se posent pas par label : `goproxify proxy option <id> waf '<json>'`, l'API ou la modale du proxy. Voir [docs/security.md](security.md#exclure-des-règles-sans-désarmer-le-proxy). |
| `goproxify.waf.behavior` | `"true"` | Active l'analyse comportementale par IP (score cumulatif sur une fenêtre glissante). |
| `goproxify.waf.behavior.window` | `"60"` | **Ignoré** depuis l'ADR 0011 : le magasin comportemental est unique par passerelle, sa fenêtre est de 60 s. |
| `goproxify.waf.behavior.threshold` | `"8"` | Score comportemental avant bannissement temporaire (défaut : `8`). |
| `goproxify.waf.trusted_proxies` | `"10.0.0.0/8,172.16.0.0/12"` | CIDRs de proxies de confiance dont le header `X-Forwarded-For` est accepté (CSV). Laisser vide pour utiliser `RemoteAddr` directement (plus sécurisé). |

---

## Sécurité — Protection bot

| Label | Valeurs | Description |
|---|---|---|
| `goproxify.bot` | `"true"` | Active la détection de bots. |
| `goproxify.bot.mode` | `"block"` \| `"monitor"` \| `"log"` \| `"challenge"` | Mode de réponse aux bots détectés. `challenge` déclenche un challenge JavaScript. |

---

## Sécurité — Ephor (whitelist par route)

L'Ephor est le moteur global de détection de menaces de la passerelle. Il s'applique **avant le routage**, donc indépendamment des proxies. Ces labels permettent d'exempter certaines sources pour un conteneur donné — les entrées sont fusionnées dans la whitelist globale d'Ephor.

> **Note DHCP** : les IPs Docker sont dynamiques. Préférer `.self` ou `.network` plutôt que des IPs statiques dans `.whitelist`.

| Label | Valeurs | Description |
|---|---|---|
| `goproxify.ephor.whitelist` | `"192.168.1.5,10.0.0.0/8"` | IPs/CIDRs statiques exemptés d'Ephor (CSV). |
| `goproxify.ephor.whitelist.self` | `"true"` | Exempte automatiquement l'IP actuelle du conteneur. Compatible DHCP — l'IP est lue au démarrage du conteneur. |
| `goproxify.ephor.whitelist.network` | `"true"` | Exempte automatiquement le sous-réseau Docker du conteneur (CIDR récupéré via l'API Docker). Utile pour les health-checkers internes. |

---

## Authentification

| Label | Valeurs | Description |
|---|---|---|
| `goproxify.jwt` | `"https://idp.example.com/.well-known/jwks.json"` | Valide les JWT entrants (signature vérifiée par la clé JWKS du fournisseur). Seule une URL JWKS est acceptée : un secret inline ou `"true"` ne sont **pas** supportés, le label est alors ignoré avec un avertissement dans les logs de l'Agent et la route n'est pas protégée. |
| `goproxify.jwt.issuer` | `"https://idp.example.com"` | Issuer exigé (optionnel, recommandé). |
| `goproxify.jwt.audience` | `"my-api"` | Audience exigée (optionnel, recommandé). |
| `goproxify.mtls` | `"/etc/goproxify/ca.pem"` | Chemin, **côté passerelle**, du fichier CA (PEM) qui signe les certificats clients ; un certificat client valide est exigé. Si le fichier est illisible, la route répond `503` au lieu de s'ouvrir. `"true"` n'est pas supporté (ignoré avec avertissement). |

---

## Cache

| Label | Valeurs | Description |
|---|---|---|
| `goproxify.cache` | `"60s"` \| `"true"` | Active le cache HTTP. `true` utilise les valeurs par défaut. |

---

## Logs

| Label | Valeurs | Description |
|---|---|---|
| `goproxify.logs` | `"true"` | Active le log forwarding (logs Docker → passerelle). Rien n'est perdu si la passerelle est injoignable ou si l'Agent redémarre : Docker garde les lignes, l'Agent reprend depuis la dernière position acquittée. La passerelle les garde dans sa base de logs (logs système, composant `agent`) avant d'acquitter. |
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
| `goproxify.scale.service` | `"web"` | Nom logique du service : les conteneurs qui portent le même nom forment un groupe d'instances. |
| `goproxify.scale.min` | `"1"` | Nombre minimum d'instances (défaut `1`). |
| `goproxify.scale.max` | `"5"` | Nombre maximum d'instances. Défaut `1` : **pas de scaling** tant que `max` n'est pas supérieur à `min` et à `1`. |

Les **seuils CPU et le délai entre deux décisions ne se règlent pas par label** : ils viennent de la section `autoscale` de `agent.json` (`enabled`, `check_interval_s` — 30 par défaut —, `cpu_scale_up_pct` — 80 —, `cpu_scale_down_pct` — 20 —, `cooldown_s` — 120, anti-battement). L'auto-scaling est désactivé tant que `autoscale.enabled` n'est pas vrai. Le déclencheur est le CPU moyen des instances du groupe : plus haut que le seuil de montée, une instance est ajoutée ; plus bas que celui de descente, la dernière est arrêtée.

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

      # Ephor — exempter le réseau interne (health-checkers, monitoring)
      goproxify.ephor.whitelist.network: "true"
      goproxify.ephor.whitelist.self: "true"

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
