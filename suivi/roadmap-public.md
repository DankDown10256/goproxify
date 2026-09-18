# Roadmap publique GoProxify

Vue allégée pour la communauté. Le détail interne n’est pas publié.

## Livré

### v0.3 — Sécurité avancée et observabilité _(septembre 2026)_

- **WAF avancé** : scoring anomalie, inspection requête (JSON/form/URI/headers/cookies) **et réponse** (CRS 951xxx), 13 jeux de règles OWASP CRS-4, règles custom hot-reload, métriques `gpx_waf_*`
- **WAF — nouveaux jeux de règles** : Java/Log4Shell (944xxx), RFI (931xxx), NodeJS/Prototype Pollution (934xxx), HTTP Request Smuggling (920xxx), Fichiers sensibles (930xxx), Fuites de données en réponse (951xxx)
- **Sentinel** : moteur de détection comportementale stateful par IP — fenêtre glissante, ban immédiat sur signal, paramètres anti-DDoS configurables depuis l’UI (GlobalRPS, rate_window, rate_ban_threshold), detect mode, listes custom allowlist/denylist
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
- i18n EN / FR / ES / DE
- Quickstart Docker Compose + images GHCR (preview)

## En cours / prochain

- [ ] Stabiliser les tags SemVer et Releases GitHub régulières
- [ ] Hygiène CI publique (lint/tests documentés)
- [ ] Polish UX Access et docs opérateur
- [ ] SBOM attaché à chaque Release

### Résilience backend (v0.4)

- [ ] **Health-check actif configurable** : path personnalisé, intervalle, timeout et seuils healthy/unhealthy par route — l'intervalle hardcodé à 30 s est remplacé par une config YAML/UI par proxy
- [ ] **Retry + circuit-breaker câblés** : `CBConfig` (threshold / timeout) existant rendu thread-safe et branché au handler — `RecordSuccess`/`RecordFailure` déclenchés à chaque tentative ; retry exponentiel déjà opérationnel
- [ ] **Rate-limiting par utilisateur authentifié** : champ `key_by` dans `RateLimitConfig` (`ip` par défaut, ou `jwt_sub` / `jwt_email` / `jwt_claim:<nom>`) pour limiter par identité JWT plutôt que par adresse IP

### Fonctionnalités à venir

- [ ] **Dashboard Sentinel** : timeline des bans, heatmap par pays, courbe RPS vs seuil
- [ ] **Webhooks sur événements** : notification externe (Slack, n8n, Zapier) sur ban, certificat expirant, backend down, taux d'erreurs soutenu
- [ ] **Discovery Kubernetes** : Agent qui lit les `Ingress`/`Service` avec annotations `goproxify.*`, symétrique du mode Docker existant
- [ ] **Pipeline de transformation de requête** : modifier headers, réécrire URL, injecter `X-Request-Id` — règles YAML hot-reload
- [ ] **Tunnel L4 mTLS Core↔Core** : remplace le relay actuel pour les déploiements multi-site, fail-over automatique entre tunnels
- [ ] **MCP server étendu** : lecture logs d'accès, ban/unban Sentinel, rotation certs depuis le MCP server existant
- [ ] **SBOM + attestation cosign** : SBOM attaché à chaque Release + signature cosign des images GHCR

Proposer des idées via
[Discussions](https://github.com/Vincamok/goproxify/discussions) ou une issue
« feature ». Voir aussi [CONTRIBUTING.md](../CONTRIBUTING.md).
