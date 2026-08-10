# ADR-0001 — Binaire Go unique pour les trois composants

**Date :** 2026-07-15
**Statut :** Accepté

---

## Contexte

Goproxify comprend trois rôles distincts : Core (Data Plane), Administration (Control Plane) et Agent (Discovery). La question était de distribuer ces rôles sous forme de binaires séparés ou d'un binaire unique multi-personnalité.

## Décision

Un **binaire Go unique** compilé avec les trois rôles. La personnalité de l'instance est déterminée au démarrage par la sous-commande CLI (`core`, `admin`, `agent`) ou la variable d'environnement `GOPROXIFY_MODE`.

## Conséquences

**Avantages :**
- Distribution simplifiée (un seul artefact à versionner, signer, distribuer)
- Cohérence garantie des versions entre composants d'un même cluster
- CLI intégrée (`goproxify admin -reset-password`, `goproxify token`) sans dépendance externe
- Un seul Dockerfile, une seule image Docker

**Inconvénients :**
- Binaire légèrement plus lourd (mitigé par la compilation statique Go)
- Impossible de mettre à jour un composant indépendamment des autres (accepté : la cohérence de version est une contrainte voulue)
