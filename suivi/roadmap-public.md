# Roadmap publique GoProxify

Vue allégée pour la communauté. Le détail interne n’est pas publié.

## Livré

### v0.3 — Sécurité avancée et observabilité _(septembre 2026)_

- **WAF avancé** : scoring anomalie, inspection requête (JSON/form/URI/headers/cookies) **et réponse** (CRS 951xxx), 13 jeux de règles OWASP CRS-4, règles custom hot-reload, métriques `gpx_waf_*`
- **WAF — nouveaux jeux de règles** : Java/Log4Shell (944xxx), RFI (931xxx), NodeJS/Prototype Pollution (934xxx), HTTP Request Smuggling (920xxx), Fichiers sensibles (930xxx), Fuites de données en réponse (951xxx)
- **Sentinel** : moteur de détection comportementale stateful par IP — fenêtre glissante, ban immédiat sur signal, paramètres anti-DDoS configurables depuis l’UI (GlobalRPS, rate_window, rate_ban_threshold), detect mode, listes custom allowlist/denylist
- **Moteur de règles automatiques** : conditions pilotées (CVE critique, pic de bans, moteur silencieux, taux d’erreur, IP récidiviste) → actions (désactiver proxy, bannir IP, alerte, mode strict F2B) ; cooldown par règle, test dry-run, historique d’exécution
- **Menu Automatisation restructuré** : sous-menus Règles automatiques / Canaux d'alerte / Store de règles préconfigurées (15 templates installables en un clic)
- **Page admin "Accès MCP"** : allowlist d'IP sources pour `/mcp` (réseaux privés par défaut), vue des utilisateurs porteurs d'un token, catalogue de scopes ↔ outils
- **Page Bans** refonte : tuiles KPI + 3 onglets (actifs / CrowdSec / historique)
- **Moteurs IPS** : page unifiée Fail2Ban / CrowdSec avec configuration in-place
- **Timeouts serveur HTTP/QUIC** : ReadHeader, Read, Write, Idle configurables depuis l’Admin et propagés aux Cores
- **Scanner CVE** : toggle UI pour autoriser les backends IP privées (opt-in, anti-SSRF par défaut)
- **Politiques d’accès centralisées** : vue unifiée IP/GeoIP/Bot par proxy dans l’Admin
- **Logs** : corrélation exacte par `request_id`, keyset pagination, vue live mobile
- **Prism** : taux d’erreurs et IPs bannies par pays ; bouton accès rapide depuis la table des bans

### v0.2 — Architecture distribuée _(juillet – août 2026)_

- Reverse proxy distribué Admin / Core / Agent (un binaire, trois modes)
- Relay Core→Core multi-hôtes (Portainer / délégation)
- GoProxify Access (portail SSH / shell, 2FA, sessions TTL)
- Wizard architecture (toile, tickets QR / `curl|bash`, multi-Core / HA)
- Sécurité : MFA, CrowdSec bouncer, WAF, GeoIP, RBAC grants, SSO (OIDC/SAML/LDAP/GitHub)
- Tokens API utilisateur (PAT) + MCP server
- CLI opérationnel (`token`, `backup`, `alert`, `import`, `nodes`, `access`)
- Métriques Prometheus, Prism dashboard, Logs d’accès live
- **Observabilité complète** : instrumentation Prometheus de tous les services (backend health, peer sync, WAF, portal sessions, Admin HTTP, VulnScan, Rules Engine) — `docs/services.md`
- i18n EN / FR / ES / DE
- Quickstart Docker Compose + images GHCR (preview)

## En cours / prochain

- [x] **Workspaces** : espaces de travail nommés regroupant proxies, domaines et cores — assignation d'équipes et utilisateurs pour une isolation multi-tenant ; page Admin dédiée (Accès → Espaces de travail)
- [x] Stabiliser les tags SemVer et Releases GitHub régulières
- [x] Hygiène CI publique (lint/tests documentés)
- [x] Polish UX Access et docs opérateur
- [x] SBOM attaché à chaque Release (workflow sbom-sign.yml)

### Résilience backend (v0.4)

- [x] **Health-check actif configurable** : `HealthCheckConfig` par route (path, interval, timeout, thresholds) ; `StartChecksFromRoutes` remplace l'appel global avec intervalle fixe
- [x] **Retry + circuit-breaker câblés** : `circuitBreaker` rendu thread-safe (mutex), `RecordSuccess`/`RecordFailure` appelés depuis le handler après chaque tentative
- [x] **Rate-limiting par utilisateur authentifié** : champ `key_by` dans `RateLimitConfig` — `ip` (défaut), `jwt_sub`, `jwt_email`, `jwt_claim:<nom>`

### Certificate Hub (v0.8)

- [x] **Certificate Deploy Hub** : deploy targets (webhook HMAC signé, ssh_exec), pull tokens multi-format (PEM/DER/PKCS#12/JSON), déclenchement automatique à chaque renouvellement ACME, historique d'audit
- [x] **Import de certificats externes** : upload PEM+clé via l'UI ou `POST /api/v1/certs/import` — domaine extrait automatiquement, push immédiat aux Cores connectés
- [x] **Monitoring ACME** : dashboard statut par cert (days_left, ok/warning/critical/expired), alertes automatiques `cert_expiring_soon` (≤30j warning, ≤7j critical) et `cert_deploy_failed` vers le moteur d'alertes existant
- [x] **Conversion de formats** : package `certformat` — PEM, DER, PKCS#8, PKCS#12/PFX, fullchain, JSON

### Fonctionnalités à venir

- [x] **Dashboard Sentinel** : endpoint `/security/bans/countries` (heatmap par pays, JOIN `geoip_cache`)
- [x] **Webhooks sur événements** : canal webhook générique sur `sentinel_ban` et `backend_down` ; `Manager.SetAlertEngine` pour injecter l'engine d'alertes ; callback `BackendHealth.OnDown` → message WS Core→Admin
- [x] **Discovery Kubernetes** : Agent qui lit les `Ingress`/`Service` avec annotations `goproxify.*`, symétrique du mode Docker existant
- [x] **Pipeline de transformation de requête** : `RequestTransform` sur `Route` (add/remove request+response headers, réécriture de préfixe URL) — middleware `Transform` hot-reload avec le reste de la config
- [x] **Tunnel L4 mTLS Core↔Core** : package `internal/core/tunnel` — `Manager` (pool de pairs, failover automatique) + `Serve` (listener mTLS, protocole CONNECT-like) + UI Admin de configuration des peers + WS push Admin→Core (`push_tunnel_config`) avec `SetPeers` à chaud
- [x] **Diff de config proxy** : endpoint `GET /api/v1/proxies/{id}/revisions/diff?from=&to=` + bouton "Diff config" dans l'UI Traffic — modal interactif avec comparaison champ par champ entre deux révisions (ou production vs. dernière)
- [x] **MCP server étendu** : outils `ban_ip`, `unban_ip`, `rotate_cert` ajoutés au MCP server
- [x] **SBOM + attestation cosign** : workflow `.github/workflows/sbom-sign.yml` — génération SBOM SPDX (syft) + signature keyless cosign sur chaque image GHCR après build

Proposer des idées via
[Discussions](https://github.com/Vincamok/goproxify/discussions) ou une issue
« feature ». Voir aussi [CONTRIBUTING.md](../CONTRIBUTING.md).
