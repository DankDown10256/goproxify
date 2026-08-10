# ADR-0002 — SQLite pour la persistance de l'Administration uniquement

**Date :** 2026-07-15
**Statut :** Accepté

---

## Contexte

Le Core (Data Plane) doit être entièrement volatile (zéro disque) pour garantir le zéro-reload et la performance. L'Administration a besoin de persistance pour les utilisateurs, proxies, tokens et snippets. Le choix de la base de données impacte directement la complexité opérationnelle.

## Décision

**SQLite** embarqué dans le binaire de l'Administration, stocké dans `/etc/goproxify/database/goproxify.db`.

Alternatives éliminées :
- **PostgreSQL/MySQL :** Dépendance externe, complexité opérationnelle, over-engineering pour un usage mono-nœud Administration
- **etcd/Consul :** Adapté aux clusters distribués, mais l'Administration est intentionnellement centralisée (single point of truth)
- **Fichiers YAML/JSON :** Pas de transactions ACID, risque de corruption en cas de crash

## Conséquences

**Avantages :**
- Zéro dépendance externe (SQLite est embarqué dans le binaire via `modernc.org/sqlite`)
- Backup trivial (copie du fichier `.db`)
- Transactions ACID pour les opérations critiques (création de tokens, mise à jour de proxies)
- Performances suffisantes pour le volume attendu (< 10 000 proxies, < 100 nodes)

**Inconvénients :**
- L'Administration n'est pas distribuable horizontalement (une seule instance avec SQLite)
- Pour les très grands déploiements (> 1 000 nodes), une migration vers PostgreSQL pourrait être nécessaire (prévu en backlog)

**Note :** Le Core est intentionnellement sans persistance — toute sa configuration est poussée en RAM par l'Administration au démarrage et à chaque mise à jour.
