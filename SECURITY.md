# Politique de sécurité

## Signaler une vulnérabilité

Ne pas ouvrir d’issue publique pour une faille de sécurité.

Envoyez un rapport privé via les **GitHub Security Advisories** du dépôt
[Vincamok/goproxify](https://github.com/Vincamok/goproxify/security/advisories/new),
ou contactez les mainteneurs par le canal indiqué dans le profil du dépôt.

Merci d’inclure :
- description de la vulnérabilité et impact
- étapes de reproduction
- versions / commit concernés
- correctif proposé si disponible

## Délais

Nous accusons réception sous **72 h** ouvrées et visons un correctif ou un
plan de mitigation sous **14 jours** pour les problèmes critiques, selon la
complexité.

## Périmètre

Dans le périmètre : Admin, Core, Agent, portail Access, API REST, MCP, images
Docker officielles publiées.

Hors périmètre : déploiements tiers non maintenus, configs locales avec secrets
faibles, dépendances déjà signalées en amont.

## Versions supportées

Les versions actuelles sont en **préversion (0.x)**. Aucune garantie de
stabilité ni d’aptitude production — voir [DISCLAIMER.md](DISCLAIMER.md).

Seules les versions taguées les plus récentes de chaque composant
(`admin` / `core` / `agent`, voir `versions.json`) reçoivent des correctifs
de sécurité en priorité, **sans engagement de délai**.

## Audits

Les audits de sécurité internes restent privés. Les correctifs et avis
publics sont publiés via les GitHub Security Advisories du dépôt.

## Renforts ops recommandés

- **TLS Admin** : reverse-proxy HTTPS, ou `GPX_ADMIN_TLS_CERT` / `GPX_ADMIN_TLS_KEY`.
- **CrowdSec** : Admin → Sécurité → activer la LAPI (désactivé par défaut).
- **WAF** : label `goproxify.waf=detect|block` ou snippet par route (off par défaut).
- **Images** : pin SemVer (`GOPROXIFY_*_TAG`). Sur GHCR public : tags SemVer + `:preview`
  (pas de `:latest` en préversion). Éviter de s’appuyer sur un tag flottant en prod.
