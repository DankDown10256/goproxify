# GoProxify — Référence des métriques Prometheus

Toutes les métriques sont exposées au format Prometheus sur le port interne du Core (`/metrics`).  
Préfixes : `gpx_*` (data plane) · `goproxify_*` (plan de contrôle).

---

## Plan de données — Core (`gpx_core_*`)

| Métrique | Type | Labels | Description |
|---|---|---|---|
| `gpx_core_requests_total` | Counter | `host`, `method`, `status` | Requêtes HTTP proxifiées (status = code HTTP) |
| `gpx_core_request_duration_seconds` | Histogram | `host` | Durée totale vue client (pipeline inclus) |
| `gpx_core_active_requests` | Gauge | `host` | Requêtes HTTP en cours |
| `gpx_core_bytes_received_total` | Counter | — | Octets reçus (Content-Length) |
| `gpx_core_bytes_sent_total` | Counter | — | Octets envoyés (body réponse) |
| `gpx_core_routes_total` | Gauge | — | Routes actives en mémoire |
| `gpx_core_certs_total` | Gauge | — | Certificats TLS en mémoire |

---

## Trafic — payload sizes (`gpx_traffic_*`)

| Métrique | Type | Labels | Description |
|---|---|---|---|
| `gpx_traffic_request_size_bytes` | Histogram | `host` | Taille des corps de requêtes (Content-Length) |
| `gpx_traffic_response_size_bytes` | Histogram | `host` | Taille des corps de réponses |

Buckets : 100 B, 1 KB, 10 KB, 100 KB, 1 MB, 10 MB, 100 MB.

---

## TLS — handshake & connexions (`gpx_tls_*`)

| Métrique | Type | Labels | Description |
|---|---|---|---|
| `gpx_tls_handshake_seconds` | Histogram | `host` | Durée du handshake TLS côté serveur |
| `gpx_tls_active_connections` | Gauge | `host` | Connexions TLS actives (handshake en cours ou établies) |
| `gpx_tls_cert_expiry_seconds` | Gauge | `domain` | Secondes avant expiration du certificat (0 = expiré) |

Le label `host` correspond au SNI extrait du ClientHello.  
Buckets handshake : 1 ms → 1 s.

**Alertes recommandées :**
```yaml
- alert: TLSCertExpiringSoon
  expr: gpx_tls_cert_expiry_seconds < 7 * 86400
  annotations:
    summary: "Certificat {{ $labels.domain }} expire dans moins de 7 jours"

- alert: TLSHandshakeSlow
  expr: histogram_quantile(0.95, gpx_tls_handshake_seconds_bucket) > 0.5
  annotations:
    summary: "p95 handshake TLS > 500 ms sur {{ $labels.host }}"
```

---

## Backends upstream (`gpx_backend_*`)

| Métrique | Type | Labels | Description |
|---|---|---|---|
| `gpx_backend_requests_total` | Counter | `host`, `backend`, `status` | Requêtes envoyées par backend (status = code HTTP) |
| `gpx_backend_duration_seconds` | Histogram | `host`, `backend`, `status_class` | Durée totale backend (headers + body) |
| `gpx_backend_ttfb_seconds` | Histogram | `host`, `backend` | Time To First Byte (headers seulement) |
| `gpx_backend_errors_total` | Counter | `host`, `backend`, `error_type` | Erreurs transport (`timeout`, `connect`, `reset`, `other`) |
| `gpx_backend_retries_total` | Counter | `host`, `backend` | Tentatives de failover |

`status_class` : `2xx` / `3xx` / `4xx` / `5xx`.  
Buckets : 1 ms → 30 s.

**Requêtes utiles :**
```promql
# Taux d'erreur par backend
rate(gpx_backend_errors_total[5m]) / rate(gpx_backend_requests_total[5m])

# p95 TTFB par backend
histogram_quantile(0.95, rate(gpx_backend_ttfb_seconds_bucket[5m]))
```

---

## Pipeline de sécurité (`gpx_pipeline_*`)

| Métrique | Type | Labels | Description |
|---|---|---|---|
| `gpx_pipeline_blocked_total` | Counter | `host`, `stage`, `reason` | Requêtes bloquées par étape |

Valeurs de `stage` : `ipfilter`, `ratelimit`, `bot`, `jwt`, `geoip`.  
Valeurs de `reason` selon la `stage` :

| stage | reason |
|---|---|
| `ipfilter` | `not_in_allowlist`, `in_denylist` |
| `ratelimit` | `rate_exceeded` |
| `bot` | `ua_blacklist`, `js_challenge` |
| `jwt` | `missing_token`, `invalid_token` |
| `geoip` | code pays ISO 3166-1 alpha-2 (ex: `CN`, `RU`) |

---

## Rate limiting (`gpx_ratelimit_*`)

| Métrique | Type | Labels | Description |
|---|---|---|---|
| `gpx_ratelimit_tokens_current` | Gauge | `host`, `ip` | Tokens disponibles dans le bucket par IP |

Permet de détecter les IPs proches de l'épuisement de leur quota.

---

## Authentification (`gpx_auth_*`)

| Métrique | Type | Labels | Description |
|---|---|---|---|
| `gpx_auth_attempts_total` | Counter | `host`, `provider`, `result` | Tentatives d'authentification |

`provider` : `jwt`, `oidc`, `saml`.  
`result` : `success`, `failure`.

**Alerte bruteforce :**
```promql
rate(gpx_auth_attempts_total{result="failure"}[5m]) > 10
```

---

## Routage avancé (`gpx_routing_*`)

| Métrique | Type | Labels | Description |
|---|---|---|---|
| `gpx_routing_canary_requests_total` | Counter | `host` | Requêtes routées vers le backend canary |
| `gpx_routing_shadow_requests_total` | Counter | `host` | Requêtes dupliquées vers le backend shadow mirror |

---

## Configuration (`gpx_config_*`)

| Métrique | Type | Labels | Description |
|---|---|---|---|
| `gpx_config_reload_total` | Counter | `type`, `result` | Rechargements de configuration |
| `gpx_config_reload_duration_seconds` | Histogram | — | Durée du rechargement |

`type` : `routes`, `cert`, `full_sync`.  
`result` : `success`, `error`.

---

## Plan de contrôle WebSocket (`goproxify_ws_*` / `goproxify_controlplane_*`)

### Côté Core

| Métrique | Type | Labels | Description |
|---|---|---|---|
| `goproxify_ws_connections_active` | Gauge | `role` | Connexions WS actives (`admin`, `agent`) |
| `goproxify_ws_messages_sent_total` | Counter | `role`, `type` | Messages WS envoyés par le Core |

### Côté Admin

| Métrique | Type | Labels | Description |
|---|---|---|---|
| `goproxify_controlplane_ws_reconnects_total` | Counter | `core_id` | Reconnexions WebSocket Admin→Core |

Une valeur élevée indique une instabilité réseau ou des redémarrages Core fréquents.

---

## Buckets communs

| Série de buckets | Utilisée par |
|---|---|
| `[.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30]` (s) | Latences HTTP et backend |
| `[.001, .005, .01, .025, .05, .1, .25, .5, 1]` (s) | TLS handshake |
| `[.001, .005, .01, .05, .1, .5, 1, 5]` (s) | Config reload |
| `[100, 1K, 10K, 100K, 1M, 10M, 100M]` (bytes) | Tailles de payload |

---

## Endpoint Prometheus

```
GET http://<core-internal-host>:8000/metrics
Authorization: Bearer <token>
```

Le scraping sans authentification peut être activé via la config réseau du Core.

## Résumé JSON (usage Admin UI)

```
GET http://<core-internal-host>:8000/internal/v1/metrics/summary
Authorization: Bearer <token>
```

Retourne un objet JSON pré-agrégé : percentiles de latence, taux d'erreur, stats par backend, expiration des certificats, blocks pipeline. Destiné à l'interface d'administration.
