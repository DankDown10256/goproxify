# ADR-0003 — Routage hybride : configuration manuelle + labels Docker

**Date :** 2026-07-15
**Statut :** Accepté

---

## Contexte

Deux paradigmes coexistent pour configurer des proxies : le mode impératif (UI/API/CLI) et le mode déclaratif (labels sur les conteneurs Docker, à la Traefik). Le risque principal est la désynchronisation entre les deux sources.

## Décision

**Hybridation avec ségrégation stricte des sources :**

1. **Mode Manuel (impératif) :** CRUD via l'UI/API/CLI. Persisté dans SQLite. Source `"manual"`.
2. **Mode Labels (déclaratif) :** Découvert par l'Agent via le socket Docker. Source `"label"`. **Lecture seule dans l'UI** (affiché en grisé).

Les proxies `source: "label"` ne peuvent pas être modifiés via l'Administration. Pour les modifier, l'opérateur met à jour les labels Docker Compose. L'Agent transmet le changement à l'Administration qui met à jour le Core.

Un **Générateur de Labels** interactif est intégré à l'UI pour guider la rédaction des labels Docker Compose.

## Conséquences

**Avantages :**
- Zéro désynchronisation possible (la source fait autorité)
- Compatible avec les workflows GitOps (les labels vivent dans le dépôt de l'application)
- L'UI reflète fidèlement l'état réel du système sans permettre d'états contradictoires

**Inconvénients :**
- Un opérateur ne peut pas "prendre la main" sur un proxy découvert par labels depuis l'UI (voulu — il doit modifier la source)
- Nécessite que l'Agent soit actif pour que les proxies labels soient visibles dans l'Administration
