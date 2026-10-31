# ADR 0018 — Logs : l'Admin porte la gestion des logs, la passerelle n'en garde qu'un tampon

**Statut :** accepté le 2026-10-26 ; livraisons 1 à 5 mises en œuvre (Admin 0.213.0 à 0.217.0 / Edge 0.126.0 à 0.129.0), le reste à suivre (voir « Ordre de mise en œuvre ») · **Date :** 2026-10-26
**Précise et infléchit :** ADR 0012 (la passerelle propriétaire de ses lignes devient un tampon ; l'Admin devient le dépositaire de l'historique) · **Respecte :** ADR-0006 (autonomie des composants) · **Retire :** la réplication des lignes entre membres d'un groupe HA (Edge 0.109.0)

---

## Contexte

L'ADR 0012 a donné les lignes aux passerelles : chacune écrit ses accès dans une base locale (365 jours), répond aux recherches de l'Admin, et ne lui envoie que des cumuls, des compteurs et des événements de sécurité. Edge 0.109.0 y a ajouté une réplication en maillage, toujours active : chaque membre d'un groupe HA garde les lignes de ses pairs. Un examen d'un parc réel (2026-10-25) et la discussion qui a suivi en tirent cinq constats.

1. **Les passerelles, qui sont sur le chemin du trafic, portent de la gestion de logs.** Écriture et rétention d'un an, recherches et classements de l'Admin (un classement exact lit la période jusqu'à trois fois, sans index sur le champ ; la passerelle plafonne à deux lectures simultanées pour se protéger), réplication vers les pairs, exporteur SIEM. Ce travail ne sert pas le trafic et devrait aller là où il ne le gêne pas : sur l'Admin.
2. **Le maillage coûte N fois le volume du groupe.** Chaque membre stocke tout le groupe. L'ADR 0012 estimait environ 80 Go par an pour l'ensemble des nœuds à 220 000 lignes d'accès par jour (environ 1 Ko par ligne) ; une mesure sur un petit parc donne environ 0,5 Ko par ligne, index compris. Un exploitant visé tourne à 9 fois ce trafic ou davantage.
3. **L'historique d'une passerelle retirée est perdu.** Rien ne purge l'Admin à la suppression d'une passerelle, mais ses accès ordinaires ne sont que sur son disque (et chez ses pairs si la réplication les a copiés).
4. **Ce qu'on voit dépend de la passerelle lue.** Les historiques diffèrent d'une passerelle à l'autre (base commencée plus tard, recréée, bascule). Sur le parc examiné la réplication fonctionnait : l'écart venait de la profondeur d'historique et d'une bascule.
5. **La sauvegarde est éclatée.** Le dossier `logs/` de chaque passerelle est exclu de la sauvegarde d'état ; sauvegarder l'historique complet demande autant de volumes que de passerelles.

L'exploitant veut que **l'Admin porte la gestion des logs**, sur son propre volume de logs, et que les passerelles soient allégées au maximum. Le SIEM externe reste une destination possible, pas une condition.

## Décision

### 1. Répartition des rôles

| | Passerelle | Admin |
|---|---|---|
| Écrire les lignes | Dans un **tampon local** | Dans un **store par passerelle**, sur un volume de logs dédié |
| Envoyer | **Toutes** ses lignes, avec curseur et rejeu | Les reçoit, les range, acquitte |
| Rétention | Courte (tampon) | Longue (365 jours par défaut, réglable) |
| Recherche, classements, exports, Prism | Plus par défaut (garde une API sur son tampon) | **Les sert**, sur ses stores |
| Mode Live | Rien de plus à faire | Publie les lignes au fil de leur arrivée |
| SIEM, export signé complet, gel légal | Sur son tampon seulement | **Source unique** pour l'historique complet |
| Réplication entre pairs | Supprimée (décision du 2026-10-29) | — |
| Cumuls par minute, compteurs d'erreurs par IP | Inchangés (calculés avec les lignes, envoyés comme aujourd'hui) | Les reçoit |

### 2. Deux volumes côté Admin

- **Volume de l'Admin** (celui d'aujourd'hui) : `admin.db`, secrets, configuration. Il ne contient plus aucune ligne de log de passerelle.
- **Volume de logs**, un **volume Docker distinct**, dédié aux seuls logs, monté dans le conteneur de l'Admin à l'emplacement donné par `GPX_ADMIN_LOG_DIR`. Il se sauvegarde, se restaure et se monte sur un autre Admin indépendamment du premier. Il contient un dossier `edges/<passerelle>/` par passerelle, avec le moteur de la passerelle (`internal/edge/logstore`) : un SQLite par semaine pour les accès, un par mois pour le système. Un fichier clos ne change plus : sauvegarde incrémentale, purge par suppression du fichier.

L'Admin est remplaçable sans perdre l'historique : le volume de logs se monte sur un nouvel Admin. Le curseur de chaque passerelle vit **dans son store, dans la même transaction que les lignes** : un volume restauré ne peut avoir ni trou ni doublon. Si le volume est neuf, l'Admin ne retrouve que ce que les tampons des passerelles détiennent encore : c'est ce volume qu'il faut sauvegarder, pas la reconstitution qu'il faut attendre.

### 3. Flux avec curseur et rejeu, sur ce qui existe

Les flux `access` et `system` de `log_resume` / `log_stream` portent déjà les positions (ADR 0012, section 5). L'envoi des accès ordinaires, retiré en Admin 0.178.1 / Edge 0.88.1, est rétabli pour toutes les lignes. Un Admin qui a une position plus basse que la base de la passerelle reçoit la suite ; le mécanisme `reset` existant couvre une base de passerelle remplacée ; la déduplication par (passerelle, identifiant) reste en filet.

**Tampon de la passerelle.** Les lignes **acquittées** par l'Admin sont purgées après une rétention courte (7 jours par défaut, réglable). Les lignes **non acquittées** sont conservées jusqu'à une borne (30 jours par défaut) puis purgées avec une alerte, comme le fait déjà l'exporteur SIEM. Une coupure de l'Admin plus courte que la borne ne perd rien, même si la passerelle redémarre.

### 4. Lecture

L'Admin applique ses recherches, histogrammes, facettes, classements et exports à ses stores avec le même code que pour des passerelles distantes (`logapi`, `edgetop`, `prismedge`) : chaque store local joue le rôle d'une cible, sans réseau, ce qui répartit aussi la lecture entre les fichiers de chaque passerelle. Le **Live** est alimenté par l'arrivée des lignes : la demande `log_live` et la lecture de la base par la passerelle ne sont plus nécessaires.

**Critère d'acceptation** : si plusieurs passerelles reçoivent du trafic, leurs lignes défilent en même temps dans le menu Logs de l'Admin. Une passerelle éteinte garde son historique visible ; seules ses lignes nouvelles manquent.

### 5. Retrait d'une passerelle

Sa copie reste lisible jusqu'à la rétention de l'Admin, attribuée à son nom. L'Admin propose de la supprimer, sur confirmation.

### 6. IP et effacement

Pour que l'Admin soit dépositaire, il protège lui-même l'IP des lignes qu'il range : la passerelle lui envoie l'IP réelle sur le canal authentifié existant, l'Admin applique le mode du parc (normal, anonymisation, pseudonymisation par sa clé, comme avant l'ADR 0012) et peut révéler une IP sans interroger la passerelle. C'est une régression par rapport à l'ADR 0012 (« l'IP réelle ne quitte plus la passerelle »), assumée : elle est le prix d'un dépositaire unique. Le tampon de la passerelle suit le même mode.

L'ordre d'effacement RGPD vise la passerelle, ses copies répliquées (si la réplication est active), et les stores de l'Admin ; la preuve par passerelle est conservée. Il n'atteint pas les destinations d'un SIEM externe : l'exploitant en est responsable, et la documentation le dit.

### 7. Réplication entre passerelles, SIEM

- **La réplication entre membres d'un groupe HA est supprimée**, code compris (`logs_replica.go`, colonnes `origin`, `scope=group`, lecture d'un membre par groupe avec repli sur le pair). L'Admin garde l'historique d'un groupe entier, y compris à travers une bascule : elle n'a plus de raison d'être, et coûtait N fois le volume. Aucune instance n'est déployée en production : pas de migration.
- L'exporteur SIEM peut s'exécuter depuis l'Admin sur l'historique complet (une seule configuration, un seul curseur par destination). Il reste disponible sur les passerelles pour qui veut un envoi direct.

### 8. Export signé et gel légal

Aujourd'hui, `edge logs export` signe un export complet sur la passerelle, Admin éteint. Avec un tampon court, la passerelle ne détient plus l'année. L'export signé de l'historique complet, le gel légal et la clé de signature migrent sur l'Admin (même paquet `logexport`, ouvert sur les stores de l'Admin). Les commandes de la passerelle restent pour ce que son tampon détient.

## Questions ouvertes

- **Capacité de l'Admin.** À 220 000 lignes par jour, l'écriture n'est pas un problème. Les classements exacts sur un an (environ 80 millions de lignes à ce rythme) n'ont jamais été mesurés sur l'Admin, qui est un seul processus. À mesurer avant de recommander ce mode au-delà d'un parc moyen. Au-delà de quelques dizaines de millions de lignes par jour, l'ADR 0012 recommande l'échantillonnage ou un SIEM comme stockage.
- **Lecture d'un SIEM par l'interface** : non prévue.

## Questions tranchées

- **IP réelle chez l'Admin** (2026-10-26) : acceptée. La passerelle envoie l'IP réelle à l'Admin, qui applique le mode du parc et révèle sans interroger la passerelle. C'est la régression RGPD de la section 6, assumée par le propriétaire du produit. Un chiffrement par la passerelle avec une clé partagée n'est pas retenu.
- **Tampon de la passerelle** (2026-10-26) : 7 jours après acquittement, 30 jours au plus pour les lignes non acquittées, réglables. Les valeurs sont celles à retenir tant qu'une mesure ne montre pas qu'elles sont mal adaptées.

## Alternatives écartées

- **Passerelle propriétaire avec 365 jours, Admin qui interroge** (ADR 0012 tel quel) : la passerelle porte stockage, recherche et classements ; une passerelle éteinte rend ses lignes illisibles ; la sauvegarde est éclatée.
- **Passerelle qui purge dès l'envoi, sans tampon** : une coupure de l'Admin fait perdre des lignes (le défaut que l'ADR 0012 a corrigé).
- **SIEM externe comme seul dépositaire** : composant de plus à exploiter, non lu par l'interface, effacement RGPD non propagé. Reste une destination.
- **Réplication en maillage active par défaut** : N fois le volume du groupe, sans gain pour l'historique d'une passerelle retirée.
- **Table `logs` de l'Admin dans `admin.db`** : revient au défaut de l'ADR 0010.

## Conséquences

**Gains**

- Les passerelles sont allégées : pas de recherche, pas de classement, pas de réplication, rétention courte.
- Un seul endroit où chercher, exporter, effacer et sauvegarder l'historique, sur un volume séparé de la base de gestion.
- L'historique d'une passerelle retirée ou éteinte reste lisible.
- Le volume total est de 1 fois l'historique, plus un tampon.

**Coûts**

- Le CPU, la RAM et le disque de l'Admin sont dimensionnés selon le volume cumulé de tous les nœuds ; il ne passe pas à l'échelle horizontalement.
- La perte du volume de logs de l'Admin emporte l'historique : il se sauvegarde.
- Une coupure de l'Admin plus longue que la borne du tampon perd des lignes.
- L'IP réelle quitte la passerelle vers l'Admin (section 6).
- Chantier large : store par passerelle, lecture locale, Live par le flux, migration de l'export signé et du gel légal.

**Autonomie (ADR-0006)** : le trafic, les certificats, Ephor et le Fail2Ban local fonctionnent sans l'Admin, y compris après un redémarrage de la passerelle. Seuls l'historique centralisé et la recherche s'interrompent quand l'Admin tombe, et la passerelle rejoue ses lignes à la reconnexion.

**Migration** : aucune instance n'est déployée en production ; les passerelles de 0.88 à 0.125 qui gardent un an de logs voient leur tampon purgé à la nouvelle rétention après acquittement.

---

## Ordre de mise en œuvre

Chaque livraison tient seule.

1. Store par passerelle côté Admin, avec la protection de l'IP par l'Admin (section 6) et flux `access` complet à curseur transactionnel, rejeu depuis le début, volume dédié `GPX_ADMIN_LOG_DIR`. Test de reconstitution : Admin neuf avec le volume de logs monté, passerelles en marche.
2. Lecture sur les stores de l'Admin (Prism, recherche, exports), Live alimenté par le flux. Test de bout en bout : deux passerelles réelles et un Admin, du trafic sur les deux, une vue Live et une liste statique qui montrent les deux.
3. Tampon : purge des lignes acquittées après la rétention courte, borne des non acquittées, alerte.
4. Effacement RGPD sur les stores de l'Admin ; export signé complet et gel légal sur l'Admin.
5. Exporteur SIEM depuis l'Admin, et retrait de la réplication entre passerelles.
6. Mesure du coût de lecture sur l'Admin sur des bases réalistes, et réglage des seuils.

## Avancement

### Livraison 1 (Admin 0.213.0, Edge 0.126.0) : le volume de logs reçoit toutes les lignes

- **Passerelle** : le flux `access` envoie toutes les lignes, plus seulement les événements de sécurité ; `through` et `ReadSecurityAfter` ne servent plus à l'envoi. Le flux porte aussi `user_agent`.
- **Moteur** (`internal/edge/logstore/shipped.go`) : `AddShipped` range un lot reçu d'une passerelle et fait avancer la position dans la transaction de la période la plus récente ; `ShipCursor` la relit (la position écrite le plus récemment fait foi entre deux fichiers) ; `ResetShipCursor` la ramène à 0. Les lignes reçues portent leur numéro d'origine (`origin_id`) et restent « propres » au store (`origin` vide), ce qui laisse les lectures, classements et exports inchangés ; un index unique sur (numéro, date) rend la réception idempotente.
- **Admin** : paquet `internal/admin/edgelogs` (un store par passerelle, dossier `GPX_ADMIN_LOG_DIR`, défaut `edge-logs/` sous la racine de stockage), branché sur le récepteur de flux. Le récepteur garde deux consommateurs, chacun avec sa position : le volume de logs (toutes les lignes) et la table `logs` (événements de sécurité et logs système, pour les lecteurs actuels). La passerelle reprend à la plus basse des deux. Si le volume ne s'ouvre pas, la table ne reçoit que les événements de sécurité.
- **Tests de bout en bout** : toutes les lignes dans le volume, coupure sans trou ni doublon, deux passerelles rangées chacune dans son store et vues ensemble par le mode Live, volume monté sur une Admin à la base neuve.
- **Pas encore fait dans cette livraison** : le tampon court de la passerelle (elle garde 365 jours), la lecture sur le volume de logs, l'export signé et le gel légal sur l'Admin, le réglage de rétention de l'Admin (365 et 90 jours fixes), le retrait de la réplication entre passerelles.

### Livraison 2 (Admin 0.214.0, Edge 0.127.0) : l'Admin lit sa copie, le Live suit le flux

- **Lecture** : `internal/edge/logserve` porte les lectures de logs (recherche, histogramme, facettes, classements, IP distinctes, révélation), extraites de la passerelle ; la passerelle les applique à sa base, l'Admin à ses stores (`edgelogs.Reader`, branché sur `edgeproxy.Client.do`), sans changer les appelants (API de logs, Prism, exports, trace d'IP). Parité vérifiée copie contre passerelle.
- **Numéros** : les lignes rendues par la copie portent le numéro de la passerelle (`Row.SourceID`), pour que les références de ligne et la révélation d'IP restent valables chez elle.
- **Réglage `logs.read_source`** (`auto`, `gateway`, `admin`) ; en `auto`, la copie sert quand elle a rattrapé les identifiants que la passerelle annonce (`log_info`).
- **Groupes HA** : plus de regroupement par groupe quand l'Admin lit sa copie (`CollapseGroups` ne regroupe plus) ; la réplication entre passerelles n'a plus de lecteur.
- **Live** : alimenté par l'arrivée des lignes dans la copie (lignes de moins de 2 minutes) ; `log_live` n'est plus envoyé aux passerelles.
- **Effacement RGPD** : l'effacement d'une IP vide aussi le volume de logs.
- **Reste** : le tampon court de la passerelle, l'export signé et le gel légal sur l'Admin, la rétention réglable de l'Admin, le retrait du code de réplication entre passerelles, la simulation Ephor (qui rejoue les accès sur la passerelle, tant qu'elle les garde).

### Livraison 3 (Admin 0.215.0, Edge 0.128.0) : la base de la passerelle devient un tampon

- **Acquittement** : `log_ack` (Admin → passerelle) avec les positions rangées par flux ; `log_resume` porte `stored`. Un Admin sans volume de logs n'acquitte rien. Les positions sont persistées côté passerelle (`acks.json`), et une position annoncée à la connexion fait foi même plus basse.
- **Purge** (`logstore.Buffer`) : période entièrement acquittée (lignes, cumuls, compteurs) supprimée 7 jours après sa fin, période non acquittée 30 jours après sa fin, avec une purge ligne à ligne dans la période à cheval sur la borne. Réglages `engine.log_buffer_days` et `engine.log_buffer_max_days`. Sans acquittement reçu, la rétention ordinaire s'applique.
- **Alerte** `log_buffer_risk` à 80 % (avertissement) et 90 % (critique) de la borne, depuis l'âge de la plus ancienne ligne non acquittée annoncé dans `log_info`.
- **Limite connue** : les cumuls par minute de l'Admin sont dans `admin.db`, hors sauvegarde ; une fois le tampon purgé, ils ne se reconstituent plus depuis les passerelles. Les recalculer depuis le volume de logs reste à faire.
- **Reste** : l'export signé et le gel légal sur l'Admin, la rétention réglable de l'Admin, le retrait du code de réplication entre passerelles, la simulation Ephor (qui rejoue les accès sur la passerelle : elle ne voit plus que le tampon).

### Livraison 4 (Admin 0.216.0) : export signé et gel légal sur l'Admin

- **Export** : `goproxify admin logs export|verify|hold|nodes|key|audit`, mêmes règles que `edge logs` (paquet `logexport`, désormais capable d'exporter plusieurs stores : `RunSources`), sur le volume de logs ouvert en lecture seule. Le manifeste nomme les passerelles couvertes ; les lignes portent leur numéro chez la passerelle ; l'IP réelle est déchiffrée avec la clé de l'Admin (`gdpr.LoadKey`, qui ne crée jamais de clé).
- **Gel légal** : registre commun à tous les stores du volume (`logstore.Options.HoldsPath`), archives `held/<id>/` par store pour un gel filtré, retrait partout si un store échoue.
- **Clé de signature et audit** dans `state/` de l'Admin, repris par sa sauvegarde.
- **Reste** : la rétention réglable de l'Admin (365 et 90 jours fixes), le retrait du code de réplication entre passerelles, le recalcul des cumuls depuis le volume de logs, un export déclenché depuis l'interface ou l'API (aujourd'hui, une commande locale, comme sur la passerelle).

### Livraison 5 (Admin 0.217.0, Edge 0.129.0) : conservation réglable, réplication retirée

- **Conservation du volume de logs** : réglage `vault_retention` de `GET/PUT /api/v1/logs/settings` (accès et système, 365 et 90 jours par défaut), appliqué à tous les stores du volume (`Vault.SetRetention`) par leur purge horaire. Commune à toutes les passerelles ; pas d'exception par passerelle pour l'instant. API seulement : la page Logs › réglages ne le propose pas encore.
- **Réplication entre passerelles retirée** (décision du 2026-10-29) : boucle de tirage, routes `replica/logs`, propagation de l'effacement, curseurs, `scope` et `origin` de l'API de logs, `CollapseGroups` et la lecture d'un seul membre par groupe. La colonne `origin` est gardée : les lectures ignorent (`origin = ''`) les lignes qu'une version d'avant le retrait a répliquées, qui partent avec leur fichier.
- **Reste** : le recalcul des cumuls par minute depuis le volume de logs, la page Logs › réglages et la CLI pour les nouveaux réglages (`read_source`, `vault_retention`), un export déclenché depuis l'interface ou l'API.

### Reprise des copies d'un pair (Admin 0.218.0, Edge 0.130.0)

Complément de la livraison 5 : les lignes qu'une version d'avant le retrait de la réplication avait copiées d'un pair ne sont plus lues. Elles se reprennent dans le volume de logs : `edge logs export -origin <pair>` (export signé, chiffré) puis `admin logs import -node <passerelle>` (contrôle de la signature avant écriture, numéros décalés de 2^60 pour ne pas se confondre avec ceux de la base remplacée du pair, IP réelle rechiffrée avec la clé de l'Admin, position du flux intacte, rejeu sans effet).

Interface (Admin 0.219.0) : la fenêtre de réglages de la page Logs porte la conservation du volume de logs (`vault_retention`, avec confirmation avant de baisser une durée) et la source de lecture (`read_source`), sans changer l'API.
