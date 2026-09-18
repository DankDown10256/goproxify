# Changelog

Toutes les modifications notables sont documentées ici.  
Format : [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/), versionnement [SemVer](https://semver.org/).

---

## [0.3] — 2026-09-18 (en cours)

### Ajouté

#### Sécurité avancée
- **WAF avancé** : scoring anomalie, inspection requête (JSON/form/URI/headers/cookies) et réponse (CRS 951xxx), 13 jeux de règles OWASP CRS-4, règles custom hot-reload
- **Nouveaux jeux de règles WAF** : Java/Log4Shell (944xxx), RFI (931xxx), NodeJS/Prototype Pollution (934xxx), HTTP Request Smuggling (920xxx), Fichiers sensibles (930xxx), Fuites de données en réponse (951xxx)
- **Sentinel** : moteur de détection comportementale stateful par IP — fenêtre glissante, ban immédiat sur signal, paramètres anti-DDoS configurables (GlobalRPS, rate_window, rate_ban_threshold), detect mode, listes custom allowlist/denylist
- **Dashboard Sentinel** : endpoint `/security/bans/countries` — heatmap des bans actifs par pays (JOIN `geoip_cache`)
- **Webhooks sur événements** : déclencheurs `sentinel_ban` et `backend_down` dans les règles d'alerting ; callback `BackendHealth.OnDown` → message WS Core→Admin
- **Timeouts serveur HTTP/QUIC** : ReadHeader, Read, Write, Idle configurables depuis l'Admin et propagés aux Cores

#### Résilience backend
- **Health-check actif configurable** : `HealthCheckConfig` par route (path, interval, timeout, thresholds) ; `StartChecksFromRoutes` remplace l'appel global à intervalle fixe
- **Circuit-breaker câblé** : `circuitBreaker` thread-safe (mutex), `RecordSuccess`/`RecordFailure` appelés depuis le handler après chaque tentative
- **Rate-limiting par utilisateur authentifié** : champ `key_by` dans `RateLimitConfig` — `ip` (défaut), `jwt_sub`, `jwt_email`, `jwt_claim:<nom>`

#### Nouvelles fonctionnalités
- **Pipeline de transformation de requête** : `RequestTransform` sur `Route` — add/remove request+response headers, réécriture de préfixe URL ; middleware hot-reload
- **Tunnel L4 mTLS Core↔Core** : package `internal/core/tunnel` — `Manager` (pool de pairs, failover automatique) + `Serve` (listener mTLS TLS 1.3, protocole CONNECT-like)
- **Discovery Kubernetes** : Agent scrute les `Ingress`/`Service` avec annotations `goproxify.*`, symétrique du mode Docker
- **MCP server étendu** : outils `ban_ip`, `unban_ip`, `rotate_cert` ajoutés au MCP server
- **SBOM + attestation cosign** : workflow `.github/workflows/sbom-sign.yml` — génération SBOM SPDX (syft) + signature keyless cosign sur chaque image GHCR après build
- **Release automatique** : workflow `.github/workflows/release.yml` — tag SemVer + GitHub Release générés depuis `versions.json` à chaque push sur `main`
- **Scanner CVE** : toggle UI pour autoriser les backends IP privées (opt-in, anti-SSRF par défaut)
- **Politiques d'accès centralisées** : vue unifiée IP/GeoIP/Bot par proxy dans l'Admin
- **Logs** : corrélation exacte par `request_id`, keyset pagination, vue live mobile
- **Prism** : taux d'erreurs et IPs bannies par pays ; bouton accès rapide depuis la table des bans

#### UX & Documentation
- **Portal Access** : spinner de chargement, boutons désactivés pendant les actions async, état vide avec CTA
- **Docs opérateur Access** : `docs/operator-access.md` — SMTP, invitation, cycle de vie, sessions TTL, supervision

---

## [0.2] — 2026-08-01

### Ajouté

- Reverse proxy distribué Admin / Core / Agent (un binaire, trois modes)
- Relay Core→Core multi-hôtes (Portainer / délégation)
- GoProxify Access (portail SSH / shell, 2FA, sessions TTL)
- Wizard architecture (toile, tickets QR / `curl|bash`, multi-Core / HA)
- Sécurité : MFA, CrowdSec bouncer, WAF initial, GeoIP, RBAC grants, SSO (OIDC/SAML/LDAP/GitHub)
- Tokens API utilisateur (PAT) + MCP server (lecture et écriture proxy/nœuds/alertes)
- CLI opérationnel (`token`, `backup`, `alert`, `import`, `nodes`, `access`)
- Métriques Prometheus, Prism dashboard, Logs d'accès live
- i18n EN / FR / ES / DE
- Quickstart Docker Compose + images GHCR (preview)

---

## [0.1] — 2026-06-01

### Ajouté

- Premier reverse proxy HTTP/HTTPS fonctionnel (Core standalone)
- Interface Admin web (gestion proxy, certificats ACME, utilisateurs)
- Agent Docker (découverte labels `goproxify.*`, LB adaptatif)
- Passthrough SNI, HTTP/2, WebSocket
- Load balancing : Round Robin, Weighted, Adaptatif
