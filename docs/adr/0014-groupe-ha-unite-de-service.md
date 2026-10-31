# ADR 0014 — Le groupe HA, unité de service

**Statut :** accepté, mis en œuvre avec les restes listés dans les étapes 4 à 6 et les points ouverts (Admin 0.192.0, Edge 0.105.0, Agent 0.18.0) · **Date :** 2026-10-22
**S'appuie sur :** ADR-0004 (HA distribuée), ADR-0006 (autonomie des composants) · **Corrige :** la limite « Agent rattaché à un groupe HA » de l'ADR-0006 · **Dépend de :** ADR-0015 (enrôlement, identifiants et clés) pour l'éviction complète d'un membre

---

## Contexte

Un incident sur une installation à deux passerelles (un frontal et un backup) a montré que le groupe HA n'est pas l'unité de service que le produit laisse croire :

- **Une route découverte n'existe que sur la passerelle où l'Agent l'a publiée.** La synchronisation entre pairs ignore tout ce qui n'est pas Docker (`internal/edge/gateway_peers.go`, `it.Source != "docker"`) et, pour Docker, n'enrichit qu'un pool déjà présent. Les routes Portainer, Kubernetes, Podman et du catalogue ne sont jamais copiées.
- **L'Agent reste sur la passerelle où il a basculé.** `edgeset.Rotate` passe au membre suivant, rien ne le ramène ; les retraits d'une route ne partent que vers la passerelle courante, donc l'autre garde des routes obsolètes.
- **L'Admin présente des passerelles, pas des groupes.** Les tuiles regroupent par `edge_name` (le nom de connexion, par exemple l'ancien `goproxify-core`), pas par groupe ni par nom d'affichage ; la même route apparaît une fois par passerelle.
- **La configuration poussée par l'Admin n'est pas répliquée entre pairs.** L'Admin envoie edge par edge, filtré par rôle et périmètre (`internal/admin/edgews/manager.go`) ; un edge absent pendant un changement reste obsolète jusqu'à ce que l'Admin l'atteigne. Seuls le portail, les HMAC des Agents, les clés ECH, les bans, les listes de menaces, les profils WAF, les scores du LB et les quotas `shared` sont échangés entre pairs.
- **Raft ne réplique rien.** `ProposeRoutes` et `ProposeCert` ne sont appelés nulle part ; Raft ne sert qu'à élire un leader, et il exige une majorité : dans un groupe de deux, la chute d'un membre prive l'autre de leader.
- **`architecture.json` n'est connu que de l'Admin.** Aucune ligne de `internal/edge` ni de `internal/agent` ne le lit ; chaque passerelle ne reçoit que des listes séparées (pairs, groupe, Raft).
- **Un bug indépendant aggrave l'ensemble.** `isAgentRoute` (`internal/edge/internalapi.go`) ne préserve pas les routes `portainer:` et `podman:` : chaque envoi de routes de l'Admin (`table.Replace`) les efface jusqu'au scan suivant de l'Agent.

---

## Décision

### 1. Tout edge appartient à un groupe, éventuellement d'un seul membre

Il n'y a plus d'edge hors groupe. Une passerelle isolée est un groupe d'un membre. Le code, l'Admin, les Agents et l'interface ne gèrent qu'une notion. Un groupe d'un membre ne coûte rien : pas de pair à qui répliquer, pas de Raft (il est son propre leader).

Les membres d'un groupe sont égaux et interchangeables. Le flux entrant peut arriver sur n'importe lequel ; chacun doit pouvoir répondre.

### 2. Le groupe est une entrée de `architecture.json`

Le fichier déclare des **groupes** (et plus un attribut `cluster_group` dans la config d'un nœud) :

- leurs membres (nœuds physiques) ;
- leurs domaines (qui pointent vers le groupe, plus vers une passerelle) ;
- leurs délégations de domaine : **elles relient deux groupes différents**, jamais deux membres d'un même groupe, et sont refusées si la source et la cible sont le même groupe ;
- le mode de chacun de leurs services (section 5).

Le fichier déclare et ne contient pas les données des services : le portail y est « actif en sessions partagées », ses utilisateurs et son catalogue restent dans leurs stockages. Les secrets restent hors du fichier, hormis les identifiants DNS, chiffrés par la clé du groupe (section 8). L'Admin reste l'éditeur du fichier (principe `architecture.json` source de vérité, la base en est une projection).

### 3. L'état du groupe : un document répliqué, sans maître

L'« edge HA virtuel » n'est pas un composant : c'est un état que chaque membre garde en copie locale chiffrée, sur le modèle de `portal.gpx`.

- **Une fiche par groupe** : nom, membres (identifiant, nom, endpoint), périmètres, domaines, délégations dont le groupe est source, modes de services. Elle porte une **version** que l'Admin incrémente à chaque modification.
- **Les données du groupe** (routes découvertes, destinations du portail, liste et état des Agents, proxys configurés, réglages) y entrent avec une version par source : la plus récente d'une même source l'emporte, et ce que cette source ne déclare plus est supprimé.
- **Chiffrement** par la clé du groupe pour les échanges entre pairs ; chaque membre stocke sa copie chiffrée par sa clé locale (ADR-0015).
- **Rattrapage** : au démarrage et en continu, un membre compare ses versions à celles de ses pairs et récupère ce qui est plus récent, sans l'Admin. Un edge absent pendant un changement le rattrape à son retour.
- **Aucun point de passage** : si l'Admin ou un membre tombe, les autres lisent, appliquent et servent leur copie.

La configuration du groupe l'emporte sur la configuration propre d'un edge, pour les seules données listées en section 5.

### 4. Deux niveaux : propriétés du groupe et propriétés du membre

- Les propriétés **du membre** forment une liste **fermée** : endpoint annoncé, ports d'écoute, identité et jetons, région, mode « en attente » du portail, base GeoIP, cache de contenu, logs et métriques. Toute propriété qui n'y figure pas appartient au groupe.
- Les règles locales existantes restent du niveau du membre (par exemple niveau de log et tracing : « local l'emporte » dans `applyPushedSettings`).
- **Un plancher local ne peut pas être affaibli par le groupe** : l'anonymisation des IP fixée dans `edge.json`, que l'Admin ne peut déjà pas lever, ne le serait pas non plus par l'état du groupe.

### 5. Classement des services

« Vérifié » : lu dans le code. « Déduit » : conclu des noms de fichiers et de routes, à confirmer à l'implémentation.

| Service | Aujourd'hui | Mode |
|---|---|---|
| Portail Access : configuration, utilisateurs, catalogue | Envoyé à chaque edge, `portal.gpx` répliqué (vérifié) | Groupe ; enregistrements de session : à trancher |
| Routes et proxys configurés | Envoyés edge par edge selon rôle et périmètre (vérifié) | Groupe, périmètres alignés sur le groupe |
| Routes découvertes (Portainer, Docker, Kubernetes, Podman, catalogue, canary, shadow) | Sur la passerelle de l'Agent (vérifié) | Groupe |
| Destinations Docker du portail | Un Agent + un conteneur (vérifié) | Groupe |
| Certificats, clés, défis ACME | Envoyés aux edges dont le périmètre couvre le domaine (vérifié) | Groupe ; renouvellement : tâche unique |
| Snippets, pages d'erreur, plugins WASM, fournisseurs d'auth, profils IP | Envoyés à tous (vérifié) | Groupe |
| Réglages Ephor, WAF, CrowdSec, Fail2Ban | Portée de groupe déjà en place (vérifié) | Groupe ; actions sur l'hôte : locales |
| Bans, listes de menaces, profils WAF, scores du LB, quotas `shared`, clés ECH, HMAC des Agents | Échangés entre pairs (vérifié) | Inchangé |
| Liste et état des Agents ; commandes et shell | Par edge (vérifié) / commande via l'edge de l'Agent (déduit) | Groupe pour la liste et l'état |
| Automatisation (`auto-rules`) | Local (déduit) | Groupe ; exécution par le membre désigné (section 7) |
| Configuration serveur | Poussée par edge (vérifié) | Mixte : timeouts du groupe, ports locaux (déduit) |
| Délégations de domaine | Routes `deleg-` par edge (vérifié) | Entre groupes (section 2) |
| Tunnel, identité, jetons, cache de contenu, logs, métriques, GeoIP | Local (vérifié / déduit) | Membre ; purge du cache à propager (déduit) |

### 6. L'Agent s'adresse au groupe

- L'Agent connaît **la liste des membres** (annoncée par chaque membre, conservée sur disque comme aujourd'hui) et, si l'opérateur en fournit une, **une adresse de groupe** (IP virtuelle ou nom DNS) ; la liste sert de repli. Aucun edge spécial.
- Il publie à n'importe quel membre vivant. Ce membre écrit dans l'état du groupe, qui se répand aux autres. L'Agent n'a besoin des identifiants que d'un membre à la fois, et la notion de « retour sur la passerelle configurée » disparaît : l'endroit où il est connecté ne décide plus de qui sert quoi.
- Il publie un **état complet versionné** à chaque (re)connexion et à chaque scan, pas seulement des ajouts et des retraits : chaque membre supprime ce que l'Agent ne déclare plus. Cela remplace la suppression route par route, qui laisse des routes obsolètes dès qu'un retrait manque sa cible.
- **Joignabilité** : l'appartenance à un groupe suppose que chaque backend est joignable depuis tous les membres. Pour un endpoint Portainer local, l'Agent publie en groupe l'**IP de l'hôte et le port publié**, et plus le nom du conteneur (`resolveSpecs`). Il n'y a ni tunnel entre pairs ni route réservée à un membre.
- **Agent absent** : ses routes restent servies (ADR-0006) ; la santé des backends écarte ceux qui sont tombés. L'Admin marque ses routes obsolètes, sans les retirer.

### 7. Les actions uniques

Le renouvellement d'un certificat, une action d'automatisation (ban, notification) ne doivent partir qu'une fois. Raft ne convient pas : il exige une majorité, donc un groupe de deux perd son leader à la chute d'un membre. L'exécutant est le **premier membre de la fiche vu vivant** ; les actions sont idempotentes. Dans une partition réseau, deux membres peuvent exécuter la même action : c'est acceptable pour un ban ou un renouvellement, un doublon rare est possible pour une notification.

Raft n'élit donc plus rien d'utile. **Retiré des passerelles en Edge 0.110.0** : plus de leader, plus de port Raft, plus de topologie Raft ; n'importe quel membre du groupe, quelle que soit sa taille, prend le relais d'un autre par le mécanisme ci-dessus. Raft ne subsiste que pour la HA de l'Admin.

### 8. Composition du groupe, clé du groupe et reconstitution de l'Admin

- **Seul l'Admin ajoute ou retire un membre** : c'est une modification de topologie. Un nouveau membre s'enrôle avec un jeton à usage unique (ADR-0015), reçoit la fiche, la clé du groupe puis l'état d'un pair. L'ajout est impossible pendant une coupure de l'Admin.
- **Au retrait, la clé du groupe tourne**, exécutée par l'Admin (la composition d'un groupe ne se change que par lui, il n'y a donc qu'un auteur : pas d'époque ni de conflit à résoudre). Version abandonnée, où les membres la renouvelaient eux-mêmes :
  1. l'Admin retire le membre de la fiche (version n+1) ; les membres rejettent aussitôt ses identifiants ;
  2. un membre vivant génère la nouvelle clé, avec un numéro d'**époque**, et l'envoie à chaque autre membre sur le canal authentifié entre pairs, **jamais chiffrée par l'ancienne clé** que le membre retiré connaît ;
  3. chacun rechiffre ses documents et garde l'ancienne clé le temps de lire ce qui arrive encore.
  Un membre hors service pendant la rotation demande la clé courante à un pair à son retour, en s'authentifiant par ses identifiants, qui ne dépendent pas de la clé. Si deux membres génèrent chacun une clé, l'époque la plus haute l'emporte, puis l'identifiant de membre le plus bas. Un membre ne sert ses pairs qu'après avoir comparé sa fiche à celle d'un pair, pour ne pas accepter un membre retiré pendant qu'il était absent.
- **La clé du groupe existe dès la création du groupe**, et pas au premier usage du portail comme aujourd'hui (`groupPortalKey`).
- **L'Admin se reconstitue à partir des fiches** : un Admin vierge reçoit le secret d'appairage et l'adresse d'un edge (variables `GPX_IDENTITY_EDGE_NODE_NAME` ou `GPX_EDGE_EXTRA_ENDPOINTS`, ou un `architecture.json` qui la porte). Il se connecte à la passerelle par la signature HMAC du secret et lui pousse un jeton qu'il crée lui-même : aucun identifiant antérieur, aucune approbation n'est nécessaire. Les autres membres sont découverts par les battements de cœur des pairs. Il demande ensuite la fiche à chaque groupe, et recompose `architecture.json` par union (la version la plus haute l'emporte). Les identifiants DNS des domaines sont dans la fiche, chiffrés par la clé du groupe : le renouvellement DNS survit à la perte de l'Admin. Les utilisateurs, le RBAC, les règles d'alerte et l'historique ne sont pas dans l'architecture ; ils restent à sauvegarder côté Admin.

### 9. Ce que l'Admin affiche

Une route découverte apparaît **une fois par groupe**, avec la liste des membres qui la servent, le **nom d'affichage** de la passerelle (jamais le nom de connexion) et la version de l'état dont elle vient. Il en va de même pour la CLI (`cmd/goproxify`) et le MCP.

### 10. Identité : la clé d'un membre et celle d'un groupe

Aujourd'hui les données se rattachent à une passerelle par son nom de connexion (`edge_name`, par exemple l'ancien `goproxify-core`) ou par `nodes.id`, qui n'est pas stable. C'est ce qui a produit une tuile par passerelle pour la même route. Les clés sont fixées ainsi :

| Clé | Définition | Sert à |
|---|---|---|
| **Identifiant du membre** (`node_id`) | L'identifiant du jeton de la passerelle, qui est aussi l'identifiant du nœud dans `architecture.json` (`ensureEdgeTokenWithID`). Stable : il survit au renommage et au remplacement d'une machine perdue qui reprend le même nom déclaré (ADR-0015). | Tout ce qui vient d'un membre précis : logs, événements de sécurité, bans, métriques, sessions du portail, propriétés de membre, provenance d'une donnée |
| **Identifiant du groupe** | L'identifiant du groupe déclaré dans sa fiche (section 3). Stable comme le membre. | Tout ce que le groupe sert : routes découvertes, configuration et destinations du portail, domaines, délégations, modes de services |
| **Libellé** | Le nom d'affichage de la passerelle ou du groupe. | L'affichage seulement ; jamais une clé, jamais une jointure |

Règles :

- Une donnée est rattachée au **groupe** si elle est servie par tous ses membres (section 5), au **membre** si elle vient d'un seul. Une tuile de route découverte est donc indexée par le groupe et porte la liste des `node_id` des membres qui la servent ; indexée par le membre, elle redeviendrait une tuile par passerelle.
- Le nom de connexion n'est jamais utilisé comme clé ni affiché à la place du nom d'affichage. Un nom de connexion hérité (ancien `goproxify-core`) reste un alias de recherche.
- Un membre remplacé garde son `node_id` : l'historique de logs et de sécurité de ce membre reste rattaché au même identifiant.
- Tant que la fiche de groupe n'existe pas (étape 4 de la mise en œuvre), l'identifiant du groupe est le nom `cluster_group` déjà déclaré dans la config du nœud (`archstore.NodeEntry.Group`), comme clé provisoire ; il devient l'identifiant de la fiche ensuite, sans changer ce que les lecteurs voient.

---

## Comportement attendu par coupure

| Coupure | Ce qui continue | Ce qui s'arrête (et seulement cela) |
|---|---|---|
| **Un membre tombe ou redémarre** | Les autres membres servent toutes les routes du groupe ; au retour, le membre rattrape l'état d'un pair, sans l'Admin ni l'Agent | La capacité de ce membre |
| **Tous les membres sauf un tombent** | Le survivant sert tout le groupe sans attendre de quorum ; il exécute les actions uniques | La capacité des autres |
| **Un membre est absent pendant un changement** | Le changement s'applique aux membres présents | Rien ; à son retour il rattrape par ses pairs |
| **L'Admin tombe** | Trafic, découverte, réplication, rattrapage ; les copies locales de l'état du groupe | Modification de la topologie, ajout et retrait de membre, supervision |
| **Un Agent tombe** | Ses routes restent servies par tous les membres | Découverte, scaling, logs, shell de cet hôte |
| **Un Agent perd le membre qu'il joignait** | Il en joint un autre ; l'état du groupe est déjà identique partout | Rien |

---

## Conséquences

- La page Trafic, `/discovered-containers`, `/nodes`, la CLI et le MCP changent de forme : une entrée par groupe.
- Le fichier `architecture.json` change de schéma (groupes de premier niveau). Les domaines et délégations pointent vers un groupe.
- L'Agent change de contrat de publication (état complet versionné), la passerelle reçoit et propage.
- Les routes d'un endpoint Portainer local ne fonctionnent en groupe que si l'hôte et le port publié sont joignables de partout ; les groupes qui n'ont qu'un réseau Docker local à un hôte ne conviennent pas à un déploiement à plusieurs membres.
- Le projet n'a pas de migration de données prévue : le passage au schéma de groupes remplace l'ancien sans façade de compatibilité. À confirmer pour les installations déjà en service avant la mise en œuvre.

### Ordre de mise en œuvre

Chaque étape est livrable seule.

0. Corriger `isAgentRoute` (routes `portainer:` et `podman:` effacées par un envoi de routes), avec test. *Livrée en Edge 0.90.1.*
1. Afficher le nom d'affichage de la passerelle partout, et une tuile par route pour un groupe HA. *Livrée en Admin 0.173.1.*
2. L'Agent publie un état complet versionné ; les passerelles suppriment ce qui n'est plus déclaré. *2a livrée en Edge 0.91.0 / Agent 0.13.0* : `PUT /internal/v1/agent/state`, génération par (Agent, source, scope) tenue dans `agent-state-generation`, élagage des backends Docker et des routes Portainer de l'Agent, état par endpoint pour Portainer (un endpoint en échec n'envoie rien) ; repli route par route sur une passerelle ancienne. *2b livrée en Edge 0.92.0 / Agent 0.14.0* : Kubernetes (liste des Services et des Ingress avant chaque démarrage des watches, qui reprennent à la version de la liste ; rien n'est envoyé si l'une des deux listes échoue) et annuaires (état envoyé quand l'annuaire change, après un `Resync` ou toutes les 10 minutes ; rien sur une erreur de l'annuaire) ; l'élagage reconnaît les backends de chaque source (hexadécimal pour Docker, `k8s:` pour Kubernetes, `@source` pour un annuaire) et compare en entier les identifiants de Kubernetes et des annuaires.
3. Le document d'état de groupe et son rattrapage entre pairs ; le groupe d'un membre sans Raft. *3a livrée en Edge 0.93.0 / Agent 0.15.0* : les états complets des Agents (étape 2) sont transmis aux pairs du groupe (`/internal/v1/agent/state/replica`, chiffrés par la clé du groupe) et appliqués comme si l'Agent les avait envoyés ; un membre tire ses pairs à chaque tour de synchronisation (condensé des générations, `304` si identiques) et rattrape les états plus récents ; après un événement, l'Agent renvoie un état complet regroupé (Docker, Kubernetes). *Pas de code pour le groupe d'un membre sans Raft* : le cluster Raft de la passerelle est déjà optionnel (`cluster.enabled`) et rien n'y lit le rôle de leader. *3b livrée en Edge 0.95.0 / Admin 0.182.0* : la liste et l'état des Agents (`NodeInfo`) se partagent entre les membres (`/internal/v1/agent/nodes/replica`, tirage à chaque tour, l'entrée la plus récemment vue l'emporte, `connected_via`), les commandes sont transmises au membre qui tient l'Agent, et l'Admin n'affiche qu'une ligne par Agent. *3c livrée en Edge 0.97.0* : les proxys configurés (`proxystore`) se rattrapent entre les membres (`/internal/v1/replica/proxies`, version la plus récente par identifiant, suppressions retenues 30 jours dans `tombstones.json`). *3d livrée en Edge 0.100.0* : les documents que l'Admin pousse à chaque passerelle et qui sont les mêmes pour tout le groupe (certificats par nom, plugins, snippets, fournisseurs d'authentification, profils IP, CrowdSec, Fail2Ban, Ephor, WAF, pages d'erreur, modèles Access, règles automatiques, délégations) sont retenus dans un journal local chiffré avec leur date de réception ; un membre qui a manqué une poussée la rattrape auprès d'un pair (`/internal/v1/replica/pushed`, tirage à chaque tour, contenu identique = rien à faire, le plus récent l'emporte) en la rejouant par le chemin d'une poussée de l'Admin. Les réglages propres à une passerelle (réglages d'exploitation, délais du serveur, rétention des logs et export SIEM, qui ont une valeur par passerelle, pairs, jeton Admin) n'en font pas partie. *Conteneurs inactifs livrés en Edge 0.99.0 / Agent 0.16.0 / Admin 0.186.0* : l'état complet d'une source Docker ou Portainer porte aussi les conteneurs qui existent sans tourner, dans un champ `inactive` séparé (jamais dans les routes, donc jamais dans la table de routage et ignoré d'une passerelle ancienne) ; ils sont répliqués avec l'état et l'Admin les affiche grisés. *Étendus en Agent 0.17.0* à Kubernetes (Service dont les `Endpoints` n'ont aucune adresse prête) et aux annuaires Consul (contrôle en échec) et ECS (tâche pas prête ou en échec de santé).
4. Les groupes dans `architecture.json`, les fiches sur les edges, la reconstitution de l'Admin. *4a livrée en Admin 0.187.0 / Edge 0.101.0* : `architecture.json` porte une section `groups` (version et empreinte de la fiche de chaque groupe déclaré) ; l'Admin calcule la fiche (membres avec identifiant, nom et adresse ; domaines avec leurs identifiants DNS), augmente sa version à chaque changement et la pousse à chaque membre, aussi à chaque connexion (`push_group_card`) ; chaque passerelle la garde chiffrée (`group-card.gpx`), la rattrape auprès de ses pairs (la version décide, pas la date) et la sert (`GET /internal/v1/group-card`) ; `POST /api/v1/architecture/recover` (`goproxify architecture recover`) reconstitue `architecture.json` d'un Admin neuf à partir des fiches des passerelles appairées, sans modifier ce qu'il connaît déjà. *Reste* : la fiche d'une passerelle seule (groupe d'un membre, aujourd'hui sans groupe déclaré), les périmètres et les modes de services dans la fiche, et le jeton qu'un Admin remplacé a poussé aux passerelles, qui restait valable chez elles : traité par l'ADR-0015 (étape 5a, `nodes revoke-stale-admin-tokens`, Admin 0.188.0 / Edge 0.102.0).
5. La rotation de la clé du groupe au retrait d'un membre ; l'exécutant des actions uniques. *5b livrée en Edge 0.101.0* : l'exécutant est le premier membre de la fiche (ordre de l'identifiant) vu vivant, calculé par chaque membre à partir des échanges entre pairs (réponse dans les 45 s) ; la notification d'une règle automatique, vue par plusieurs membres, est transmise à l'exécutant (`/internal/v1/group/rule-fired`, chiffré par la clé du groupe) qui la remonte à l'Admin une fois par fenêtre de 90 s, et chaque membre la remonte lui-même si l'exécutant ne répond pas. Le renouvellement des certificats reste porté par l'Admin (ACME) : il n'y a pas d'action unique de ce type sur les passerelles. Raft n'élit plus rien d'utile : son retrait reste un point ouvert. *5a livrée en Admin 0.184.0* : une boucle de l'Admin (30 s) compare la composition déclarée à la dernière connue ; un membre sorti fait renouveler la clé (poussée aux membres restants avec la liste à jour, le membre sorti recevant la configuration de son propre groupe, sans champs HA tant que le groupe d'un membre n'existe pas), un membre ajouté fait pousser la liste sans changer la clé. L'Admin ne réagit qu'à une composition **déclarée** : une panne, même longue, n'est pas une exclusion. Depuis l'ADR-0015 (étape 5c, Admin 0.191.0 / Edge 0.105.0), la rotation de la clé s'accompagne du renouvellement du jeton de chaque membre restant, pour qu'un membre sorti ne puisse plus s'en servir auprès de ses anciens pairs.
6. Les délégations entre groupes. *Livrée en Admin 0.187.0* : `POST` et `PUT /api/v1/domains` refusent une délégation dont la source (passerelle d'entrée ou `ha:<groupe>`) et la cible sont dans le même groupe, ou sont la même passerelle ; une passerelle seule peut déléguer à un groupe et inversement. Les délégations déjà enregistrées entre membres d'un même groupe ne sont pas migrées : elles sont refusées à leur prochaine modification. *Reste* : la cible d'une délégation désigne toujours une passerelle unique, pas un groupe (le trafic délégué n'a pas de repli vers un autre membre de la cible).

## Points ouverts

- Les enregistrements de session du portail (locaux ou répliqués) et la purge du cache de contenu.
- Les services marqués « déduit » : à confirmer en les lisant à l'implémentation (automatisation, configuration serveur, purge du cache, jetons de jointure à usage unique, commandes d'Agent).
- Les actions uniques non idempotentes (notifications) : un doublon rare est accepté, ou un jeton de déduplication partagé est ajouté.
- L'éviction complète d'un membre malgré le secret d'appairage commun : traitée par l'ADR-0015 (clé de canal dérivée par passerelle, rotation avec recouvrement, jetons des pairs renouvelés). Limite restante : un membre sorti qui reste enregistré comme passerelle dans l'Admin reçoit les nouveaux jetons ; pour l'évincer, supprimer le nœud.
- La migration des lecteurs existants de `edge_name` vers `node_id` ou l'identifiant du groupe (logs, sécurité, portail, tuiles) : le chantier des logs (ADR-0012) y touche déjà ; l'ordre entre les deux est à convenir pour ne pas modifier deux fois les mêmes lecteurs.
