# ADR 004 — Architecture Haute Disponibilité & Distribution

**Date :** 2026-07-16
**Statut :** Accepté

---

## Contexte

L'architecture initiale présente quatre fragilités identifiées :

1. L'Administration repose sur une instance SQLite unique — si elle tombe, plus aucune modification de configuration n'est possible
2. La passerelle stocke ses routes en mémoire vive — un redémarrage sans Administration disponible le vide complètement
3. L'élection de coordinateur entre passerelles prévoyait l'algorithme Bully, qui peut produire deux coordinateurs simultanés en cas de coupure réseau partielle
4. La synchronisation de configuration entre passerelles d'un même groupe n'était pas définie

L'objectif central est que **la passerelle soit autonome** : elle doit pouvoir servir le trafic même si l'Administration est temporairement indisponible.

---

## Décisions

### 1. Cache local de la passerelle

La passerelle sauvegarde sa table de routage et ses certificats dans un fichier local chiffré (`/etc/goproxify/edge-cache.gpx`) à chaque push de configuration reçu de l'Administration.

Au démarrage, si l'Administration est injoignable, la passerelle charge ce fichier et démarre normalement. Il se reconnecte à l'Administration dès qu'elle redevient disponible et met à jour son cache.

**Pourquoi :** la passerelle doit être autonome. Une indisponibilité de l'Administration ne doit jamais interrompre le trafic, même après un redémarrage de la passerelle.

### 2. Organisation des passerelles en groupes

Les passerelles s'organisent en groupes indépendants (par datacenter, région, client...). Chaque groupe élit son propre coordinateur et reçoit sa configuration de l'Administration indépendamment des autres groupes.

```
Administration (cluster rqlite)
    ├── Groupe Paris    : Passerelle-1 (coordinateur) + Passerelle-2 + Passerelle-3
    ├── Groupe New York : Passerelle-4 (coordinateur) + Passerelle-5
    └── Groupe Tokyo    : Passerelle-6
```

**Pourquoi :** découpler les groupes permet de scaler indépendamment par région et d'isoler les pannes.

### 3. Algorithme Raft pour l'élection de coordinateur

L'algorithme Bully est remplacé par **Raft** pour l'élection du coordinateur de chaque groupe.

Avec Raft, une passerelle ne peut devenir coordinateur que si la **majorité** du groupe vote pour lui. En cas de coupure réseau partielle, seule la moitié majoritaire peut élire un coordinateur — l'autre moitié attend. Il est mathématiquement impossible d'avoir deux coordinateurs simultanément dans le même groupe.

Raft sert également à la synchronisation de configuration : une modification n'est appliquée que lorsque la majorité du groupe l'a reçue et confirmée, garantissant que toutes les passerelles d'un groupe ont toujours la même table de routage.

**Pourquoi :** Raft est l'algorithme de consensus de référence (etcd, Consul, CockroachDB l'utilisent). Il résout le split-brain par construction. La bibliothèque Go `hashicorp/raft` est mature et bien documentée.

### 4. Administration distribuée avec rqlite

L'Administration passe de SQLite mono-instance à **rqlite** : SQLite distribué sur 3 nœuds via Raft.

- L'API reste identique à SQLite — aucun changement de code applicatif
- Les écritures passent par le nœud leader, les lectures sur n'importe quel nœud
- Si un nœud tombe, les deux autres continuent sans interruption
- Bascule automatique du leader en quelques secondes

**Pourquoi :** rqlite apporte la HA sans changer d'ORM ni de schéma. Passer à PostgreSQL aurait introduit une dépendance lourde non justifiée pour ce cas d'usage.

---

## Alternatives écartées

| Alternative | Raison de l'abandon |
|---|---|
| Algorithme Bully pour l'élection | Risque de split-brain documenté, pas adapté à un proxy de production |
| PostgreSQL pour l'Admin HA | Dépendance lourde, opérationnel plus complexe, pas de gain fonctionnel vs rqlite |
| Partage NFS pour le cache passerelle | Crée une dépendance réseau, contredit l'objectif d'autonomie de la passerelle |
| Pas de cache passerelle (Admin toujours dispo) | Inacceptable — l'Admin peut redémarrer, être en maintenance, ou être inaccessible temporairement |

---

## Conséquences

- Jalon 4 redessiné autour de Raft et rqlite
- Ajout du cache passerelle chiffré en Jalon 1
- Nouvelle CLI : `goproxify edge cache <show|refresh|export|clear>`
- Un minimum de 3 nœuds est recommandé pour chaque entité HA (groupe de passerelles, cluster Admin)
- La bibliothèque `hashicorp/raft` sera ajoutée aux dépendances Go
