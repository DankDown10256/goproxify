# GoProxify — Référence des métriques Prometheus

Toutes les métriques sont exposées au format Prometheus sur le port interne de la passerelle (`/metrics`, ou `/internal/v1/metrics`), derrière le jeton de la passerelle.  
Préfixes : `gpx_*` (data plane) · `goproxify_*` (plan de contrôle).

---

## Plan de données — passerelle (`gpx_edge_*`)

| Métrique | Type | Labels | Description |
|---|---|---|---|
| `gpx_edge_requests_total` | Counter | `host`, `method`, `status` | Requêtes HTTP proxifiées (status = code HTTP) |
| `gpx_edge_request_duration_seconds` | Histogram | `host` | Durée totale vue client (pipeline inclus) |
| `gpx_edge_active_requests` | Gauge | `host` | Requêtes HTTP en cours |
| `gpx_edge_bytes_received_total` | Counter | — | Octets reçus (Content-Length) |
| `gpx_edge_bytes_sent_total` | Counter | — | Octets envoyés (body réponse) |
| `gpx_edge_routes_total` | Gauge | — | Routes actives en mémoire |
| `gpx_edge_certs_total` | Gauge | — | Certificats TLS en mémoire |

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
| `gpx_tls_handshake_seconds` | Histogram | `host` | Durée du handshake TLS côté serveur (poignées de main réussies seulement) |
| `gpx_tls_active_connections` | Gauge | `host` | Connexions TLS établies (comptées une fois la poignée de main réussie) |
| `gpx_tls_rejected_total` | Counter | `reason` | Connexions refusées à l'entrée : `timeout` (ClientHello jamais reçu), `too_many_pending` (trop de lectures en cours, au total ou pour une même source), `bad_clienthello` (coupée avant tout TLS), `not_tls`, `no_sni` (accès par l'IP), `ip_literal`, `unknown_sni` (nom sans certificat), `handshake_failed` |
| `gpx_edge_unknown_host_total` | Counter | — | Requêtes HTTP dont l'hôte n'a aucune route (sans étiquette d'hôte : le nom est choisi par le client) |
| `gpx_tls_cert_expiry_seconds` | Gauge | `domain` | Secondes avant expiration du certificat (0 = expiré) |
| `gpx_tls_ocsp_staple_seconds` | Gauge | `domain` | Secondes avant NextUpdate de la réponse OCSP agrafée (0 = périmée) ; absent sans agrafe |
| `gpx_tls_ocsp_revoked` | Gauge | `domain` | 1 si la réponse OCSP agrafée indique une révocation |

Le label `host` est le **nom du certificat qui sert la connexion** (`app.example.fr`, ou `*.example.fr` pour tout sous-domaine d'un certificat générique), ou `autre` : jamais le SNI brut, que le client choisit librement (un certificat générique aurait créé une série par sous-domaine inventé). Les autres métriques à étiquette `host` (requêtes, pipeline de contrôles, authentification, WAF…) suivent la même règle : un nom servi par une route à joker est compté sous le nom de la route (`*.example.fr`) ; un nom exact ou un alias garde sa propre étiquette.  
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
| `gpx_backend_up` | Gauge | `backend` | État de santé du backend : 1 = up, 0 = down (quarantaine) |

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
| `gpx_detector_decisions_total` | Counter | `detector`, `decision` | Décisions des détecteurs par route (`ip_filter`, `geo_ip`, `bot`, `waf`) : `pass` (la suite de la chaîne est appelée, y compris en mode détection) ou `block` |
| `gpx_plugin_log_calls_total` | Counter | `plugin`, `result` | Appels du hook `log` des plugins (`ok` / `error`) |
| `gpx_plugin_log_dropped_total` | Counter | `plugin` | Appels du hook `log` abandonnés, file pleine |

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
| `gpx_ratelimit_tokens_current` | Gauge | `host`, `key` | Tokens disponibles dans le bucket par clé |

Le label `key` est l'IP cliente par défaut. Si `key_by` est configuré sur la route (`jwt_sub`, `jwt_email`, `jwt_claim:<nom>`), il contient la valeur du claim JWT — utile pour détecter les utilisateurs proches de l'épuisement de leur quota.

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

## Bytes par proxy (`gpx_edge_*` — par host)

| Métrique | Type | Labels | Description |
|---|---|---|---|
| `gpx_edge_bytes_received_by_host_total` | Counter | `host` | Octets reçus par proxy (Content-Length) |
| `gpx_edge_bytes_sent_by_host_total` | Counter | `host` | Octets envoyés par proxy (body réponse) |

Complètent les agrégats globaux `gpx_edge_bytes_received_total` / `gpx_edge_bytes_sent_total` avec une granularité par domaine.

---

## Peers passerelle (`gpx_peer_*`)

| Métrique | Type | Labels | Description |
|---|---|---|---|
| `gpx_peer_sync_duration_seconds` | Histogram | `peer` | Durée d'une synchronisation menée à terme avec une passerelle pair (scores LB + profils WAF) ; un pair injoignable n'y figure pas |
| `gpx_peer_up` | Gauge | `peer` | 1 si le pair a répondu au dernier sondage de synchronisation, 0 sinon (un pair muet est resondé après 15 s, 30 s, 60 s, puis toutes les 2 min) |

Buckets : 10 ms → 20 s.

---

## WAF comportemental (`gpx_waf_*`)

| Métrique | Type | Labels | Description |
|---|---|---|---|
| `gpx_waf_profiles_active` | Gauge | — | Profils IP actifs dans la fenêtre glissante du WAF comportemental |

Mis à jour après chaque cycle GC du store comportemental.

---

## Portal sessions (`gpx_portal_*`)

| Métrique | Type | Labels | Description |
|---|---|---|---|
| `gpx_portal_sessions_active` | Gauge | `type` | Sessions portal actives (`one_shot` ou `multi`) |

---

## Admin HTTP (`gpx_admin_*`)

| Métrique | Type | Labels | Description |
|---|---|---|---|
| `gpx_admin_http_requests_total` | Counter | `method`, `status` | Requêtes HTTP reçues par l'Admin (code HTTP en string) |
| `gpx_admin_http_request_duration_seconds` | Histogram | `method` | Durée des requêtes HTTP Admin |

Buckets : 1 ms → 5 s.  
Les paths `/api/v1/health`, `/api/v1/logs/live` et `/internal/v1/` sont inclus dans les compteurs (pas filtrés).

---

## Seuils multi-passerelles (`gpx_fleet_*`)

| Métrique | Type | Labels | Description |
|---|---|---|---|
| `gpx_fleet_bans_total` | Counter | — | IPs bannies automatiquement par les Seuils multi-passerelles |
| `gpx_fleet_scans_total` | Counter | — | Cycles de scan des Seuils multi-passerelles (toutes les 30 s) |

---

## CrowdSec (`gpx_crowdsec_*`)

| Métrique | Type | Labels | Description |
|---|---|---|---|
| `gpx_crowdsec_decisions_total` | Counter | `action` | Décisions CrowdSec traitées (`new`, `deleted`) |
| `gpx_crowdsec_syncs_total` | Counter | `result` | Cycles de synchronisation LAPI (`attempt`, `success`) |

---

## Flux d'automatisation (`gpx_automation_*`)

Exposées par l'Admin. Seul le leader d'un Admin HA exécute les flux : sur les autres membres, ces compteurs restent à zéro. Les flux exécutés par les passerelles (ADR 0009) ne sont pas comptés ici ; leurs déclenchements apparaissent dans le journal des exécutions.

| Métrique | Type | Labels | Description |
|---|---|---|---|
| `gpx_automation_evals_total` | Counter | — | Passages d'évaluation des flux à condition (un toutes les 10 s) |
| `gpx_automation_eval_duration_seconds` | Histogram | — | Durée d'un passage d'évaluation des flux à condition |
| `gpx_automation_active_flows` | Gauge | `trigger` | Flux activés, par déclencheur (`condition`, `event`, `schedule`, `manual`) |
| `gpx_automation_runs_total` | Counter | `trigger`, `status` | Exécutions terminées, par déclencheur et statut (`completed`, `failed`, `cancelled`, `rejected`, `stopped`, `silenced`…) |
| `gpx_automation_actions_total` | Counter | `action`, `result` | Actions exécutées par les étapes, par type d'action × (`success`, `error`) |
| `gpx_automation_events_dropped_total` | Counter | — | Événements ignorés faute de place dans la file des déclencheurs (256) |

Buckets : 1 ms → 5 s.

---

## Scanner de vulnérabilités (`gpx_vulnscan_*`)

| Métrique | Type | Labels | Description |
|---|---|---|---|
| `gpx_vulnscan_scans_total` | Counter | `result` | Cycles de scan CVE (`attempt`, `success`, `error`) |
| `gpx_vulnscan_scan_duration_seconds` | Histogram | — | Durée totale d'un cycle de scan (peut dépasser plusieurs minutes) |
| `gpx_vulnscan_cves_detected_total` | Counter | `severity` | CVEs détectées par sévérité CVSS (`critical` ≥9.0, `high` ≥7.0, `medium` ≥4.0, `low` <4.0) |

Buckets : 1 s → 300 s.

---

## Plan de contrôle WebSocket (`goproxify_ws_*` / `goproxify_controlplane_*`)

### Côté passerelle

| Métrique | Type | Labels | Description |
|---|---|---|---|
| `goproxify_ws_connections_active` | Gauge | `role` | Connexions WS actives (`admin`, `agent`) |
| `goproxify_ws_messages_sent_total` | Counter | `role`, `type` | Messages WS envoyés par la passerelle |

### Côté Admin

| Métrique | Type | Labels | Description |
|---|---|---|---|
| `goproxify_controlplane_ws_reconnects_total` | Counter | `edge_id` | Reconnexions WebSocket Admin→Passerelle |

Une valeur élevée indique une instabilité réseau ou des redémarrages passerelle fréquents.

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
GET http://<edge-internal-host>:8000/metrics
Authorization: Bearer <token>
```

Côté Prometheus : `authorization: { credentials: <jeton> }`. Les ports publics (80/443) ne servent **pas** `/metrics` (les métriques listent hôtes, backends et compteurs de sécurité) ; `GPX_METRICS_PUBLIC=1` les y expose, pour un accès filtré par le réseau.

## Résumé JSON (usage Admin UI)

```
GET http://<edge-internal-host>:8000/internal/v1/metrics/summary
Authorization: Bearer <token>
```

Retourne un objet JSON pré-agrégé : percentiles de latence, taux d'erreur, stats par backend, expiration des certificats, blocks pipeline. Destiné à l'interface d'administration.
