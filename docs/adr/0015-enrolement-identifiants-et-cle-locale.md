# ADR 0015 — Enrôlement, identifiants de service et clé locale

**Statut :** accepté, mis en œuvre avec les écarts listés en fin de document (Admin 0.191.0, Edge 0.105.0, Agent 0.18.0) · **Date :** 2026-10-22, mis en œuvre le 2026-10-23
**S'appuie sur :** ADR-0006 (autonomie des composants), ADR-0014 (groupe HA) · **Remplace :** l'usage de `GPX_PAIRING_SECRET` comme secret unique de l'enrôlement, du canal Admin → passerelle et du chiffrement local

---

## Contexte

`GPX_PAIRING_SECRET` est présent sur tous les composants et tient trois rôles à la fois (lecture du code, sans essai d'exploitation) :

1. **Il signe le WebSocket Admin → passerelle** : qui le possède se fait passer pour l'Admin auprès de toutes les passerelles (`internal/pairing/pairing.go`).
2. **Il protège l'appairage.**
   - Auprès de l'Admin (`handlePair`, point d'entrée public) : tout nœud qui présente le secret, sous n'importe quel nom et n'importe quel rôle (`edge` ou `agent`), est **accepté automatiquement**, avec le rôle RBAC `admin` et le jeton émis. Le commentaire du code l'assume : « le pairing secret valide suffit ».
   - Si le nom de nœud existe déjà, `handlePair` **renvoie le jeton existant** à quiconque présente le secret. Ce jeton est aussi celui que l'Admin envoie à l'API interne de la passerelle. Le secret est donc une clé de récupération du jeton de n'importe quel nœud.
   - Auprès d'une passerelle (`handleEdgePair`) : un Agent qui présente la clé dérivée reçoit aussitôt un jeton et est **pré-approuvé sans intervention humaine**.
3. **Il sert de clé de chiffrement des copies locales** de la passerelle (`cache.ResolveSecret`) : routes, certificats, plugins, configurations. Changer le secret change cette clé, et sans l'ancienne valeur la passerelle repart sans rien ; d'où `GPX_PAIRING_SECRET_PREVIOUS`, qui ne sert qu'à relire des données locales et n'authentifie volontairement jamais rien.

Conséquences : une seule passerelle compromise, ou une machine retirée du groupe mais encore allumée, donne la main sur toute l'infrastructure ; la rotation du secret impose de recréer chaque conteneur, puisque la valeur est une variable d'environnement. Le retrait d'un membre d'un groupe HA (ADR-0014) met ce défaut en évidence, il ne le crée pas.

Deux éléments existent déjà et servent de modèle : l'Agent ne reçoit pas le secret racine mais une **clé dérivée par une fonction à sens unique** (`pairing.AgentKey`), et il reçoit à l'approbation un **HMAC qu'il garde et que la passerelle peut faire tourner** (`TypeRotateHMAC`).

---

## Décision

### 1. Quatre niveaux de clés, un détenteur par niveau

| Clé | Qui la détient | Sert à |
|---|---|---|
| **Secret racine** | l'Admin seul | dériver les identifiants, signer le canal Admin → nœud |
| **Identifiant du nœud** | le nœud et l'Admin (qui peut le recalculer) | authentifier ce nœud ; révocable seul |
| **Clé de groupe** | les membres du groupe (copie possible sur l'Admin) | chiffrer l'état répliqué du groupe (ADR-0014) |
| **Clé locale** | le nœud seul | chiffrer ses propres copies (`edge-cache.gpx`, `portal.gpx`…) |
| **Clé des Agents** | l'Admin, les passerelles, les Agents | enrôler et authentifier les Agents (dérivée du secret racine) |

Aucune passerelle ne détient le secret racine. Elle détient son identifiant, la clé des Agents, la clé de son groupe et sa clé locale.

### 2. L'enrôlement : un jeton à usage unique, lié à un nœud déclaré

- L'Admin émet un **jeton d'enrôlement** : à usage unique, à durée courte, lié à un nom, un rôle et un groupe **déclarés dans `architecture.json`**. Les Agents ont déjà un `JOIN_TOKEN` du même genre ; il s'étend aux passerelles.
- Un nœud sans jeton valide **n'est plus accepté automatiquement** : il passe par l'approbation humaine, comme un nœud inconnu. L'acceptation automatique par simple secret disparaît.
- La **reconnexion** d'un nœud exige son identifiant. Elle ne rend plus jamais le jeton d'un nœud existant. Le secret d'enrôlement ne permet plus de récupérer un jeton.
- L'identifiant d'un nœud est dérivé du secret racine et de l'identifiant du nœud, sur le modèle d'`AgentKey`. Un Admin dont la base est perdue ou reconstituée (ADR-0014, section 8) reconnaît ses nœuds **sans état**, ce qui conserve le confort de la reconnexion automatique après un volume recréé, sans le secret partagé.
- Le remplacement d'un membre perdu passe par un nouveau jeton à usage unique pour le même nom déclaré.

### 3. L'Agent

- L'enrôlement d'un Agent auprès d'une passerelle reste possible avec la clé des Agents (dérivée), qui ne permet pas de remonter au secret racine ni de se faire passer pour l'Admin. La **pré-approbation** devient un choix : automatique (comportement actuel), sur déclaration seulement, ou manuelle. Le défaut est à fixer (point ouvert).
- Après approbation, l'Agent garde son HMAC, rotatif comme aujourd'hui. Le secret de départ n'intervient plus.
- L'option `GPX_AGENT_PAIRING_ROOT` (accepter le secret racine d'un Agent) est supprimée : une passerelle ne détient plus la racine pour la comparer.

### 4. La clé locale, propre à chaque nœud

- La clé de chiffrement des copies locales **n'est plus dérivée de `GPX_PAIRING_SECRET`**. Elle est propre au nœud, jamais partagée, et fournie par `GPX_NODE_KEY` ou par le fichier de secret Docker `GPX_NODE_KEY_FILE`. *Exception* : la clé maître du portail Access (`GPX_PORTAL_MASTER_KEY` ; à défaut le secret d'appairage s'il est présent, sinon la clé locale du nœud, qui suffit hors groupe HA) est un secret **de groupe** : elle doit être identique sur tous les membres pour que les coffres des comptes SSO se déchiffrent partout ; elle ne suit pas la clé locale.
- Sa rotation ne concerne que ce nœud. Le mécanisme `…_PREVIOUS` reste pour relire les anciennes copies ; les fichiers lus avec l'ancienne clé sont réécrits avec la courante.
- La clé du groupe est stockée par chaque membre, chiffrée par sa clé locale.
- Un nœud sans clé locale la **génère au premier démarrage** (`node.key` à la racine du volume d'état, 0600) avec un avertissement : elle protège alors contre une fuite partielle (copie d'un fichier seul), pas contre le vol du disque entier. Un fichier invalide n'est jamais écrasé. Le jeton, le secret d'appairage et la clé générée deviennent d'anciennes clés lisibles : la migration est sans intervention.

### 5. Rotation

Deux cas qui s'opposent :

- **Rotation planifiée** : l'identifiant et la clé des Agents précédents restent acceptés pour l'authentification pendant une période de recouvrement bornée et visible, puis expirent. Aujourd'hui l'ancien secret n'authentifie rien ; le recouvrement est nouveau.
- **Éviction d'urgence** (membre retiré, compromission) : l'identifiant du nœud est révoqué **aussitôt, sans recouvrement**, et la clé du groupe tourne (ADR-0014, section 8).

### 6. Livraison dans Docker

Trois niveaux, du plus rigide au plus souple :

1. **Variable d'environnement** : acceptable pour le secret d'amorçage seul, utilisé une fois à l'enrôlement.
2. **Fichier de secret Docker ou volume**, relu à chaud (signal ou lecture périodique) : on remplace le fichier sans recréer le conteneur. Pour la clé locale et la clé des Agents.
3. **Identifiants émis par l'Admin à l'enrôlement et gardés par le composant**, comme le HMAC des Agents : leur rotation ne demande aucune reconfiguration de conteneur. C'est la cible pour l'identifiant du nœud.

---

## Récupération d'un nœud perdu

| Situation | Ce qui se passe |
|---|---|
| **Membre perdu, autres membres vivants** | L'Admin émet un jeton à usage unique pour le nom déclaré ; le nouveau serveur génère sa clé locale, reçoit la fiche, la clé du groupe et l'état d'un pair ; les Agents le retrouvent. Sont perdus les logs et l'historique propres à ce membre. |
| **Edge seul dans son groupe** | L'Admin repousse configuration et certificats ; les Agents réannoncent leurs routes. Il manque les logs et l'historique locaux, sauf l'export de sauvegarde de l'edge. |
| **Admin perdu, edges vivants** | Un Admin vierge, avec le même secret racine et l'adresse d'une passerelle, se connecte par la signature de sa clé de canal, lui pousse un jeton qu'il crée lui-même et reconstitue l'architecture à partir des fiches (ADR-0014). Aucune approbation ni base d'état n'est nécessaire. Les jetons de l'ancien Admin restent valables jusqu'à `POST /api/v1/nodes/revoke-stale-admin-tokens`. |
| **Admin et groupe entier perdus** | Les sauvegardes seulement. |

---

## Limites assumées

- Le secret racine compromis compromet tout : il dérive les identifiants. Il reste chez l'Admin, et sa rotation est une opération de l'opérateur, sans interruption grâce aux valeurs `*_PREVIOUS` (étape 5b).
- Un membre retiré d'un groupe qui détenait le secret racine le connaît encore : une éviction complète demande de migrer les passerelles hors de ce secret **avant** (clés dérivées seules), ou de faire tourner le secret racine après (étape 5b). La rotation de la clé du groupe et celle des jetons des membres restants (étape 5c) sont automatiques.
- Une clé locale générée dans le volume d'état ne protège pas contre le vol du disque.

## Conséquences

- `GPX_PAIRING_SECRET` peut ne figurer que sur l'Admin : les passerelles reçoivent leur clé de canal et la clé des Agents, les Agents la clé des Agents. C'est un choix par composant, sans migration forcée. La documentation de déploiement (`docs/deployment.md`) décrit la migration et la rotation ; les modèles Helm et le script de démarrage rapide restent à adapter (voir plus haut).
- `handlePair` (Admin) et `handleEdgePair` (passerelle) changent de contrat.
- Le canal Admin → passerelle (`/ws/admin`) se signe par la clé dérivée de l'identifiant de la passerelle ; le secret commun n'est accepté que d'une passerelle qui le détient encore (et que l'Admin autorise à le présenter, `GPX_EDGE_CHANNEL_ROOT_FALLBACK`).
- Une façade de compatibilité a finalement été gardée : le secret racine reste accepté tant qu'une passerelle ou un Agent le détient, pour qu'une installation en service migre composant par composant sans interruption.

### Ordre de mise en œuvre

Chaque étape est livrable seule.

1. Clé locale propre à chaque nœud, indépendante du secret d'appairage (avec `…_PREVIOUS` pour la transition). *Livrée en Edge 0.98.0* : `GPX_NODE_KEY`, `GPX_NODE_KEY_FILE`, `node.key` généré, anciennes clés relues automatiquement ; la clé maître du portail garde son comportement.
2. Identifiants de nœud dérivés ; l'Admin les recalcule ; la reconnexion les exige. *Réalisée pour les passerelles par l'étape 4* (la clé de canal est l'identifiant dérivé de la passerelle) ; *abandonnée pour les Agents*, qui gardent un jeton et un HMAC propres à chacun, émis à l'approbation, et dont la clé d'appairage commune se renouvelle par la rotation (étape 5). *Détail du report initial* : la reconnexion exige déjà la présentation du jeton existant (étape 3), ce qui suffit tant que l'Admin garde sa base. *Constat* : la perte de la base de l'Admin ne dépend pas de cette étape pour les passerelles : l'Admin se connecte à elles par la signature HMAC du secret d'appairage et leur pousse un jeton qu'il crée lui-même (`TypeAdminToken`), sans identifiant antérieur ni approbation. Les identifiants dérivés ne serviraient qu'à reconnaître sans état les nœuds qui s'appairent *auprès* de l'Admin (Agents).
3. Enrôlement par jeton à usage unique ; fin de l'acceptation automatique par secret et de la restitution du jeton par le nom. *Livrée en Admin 0.185.0 / Agent 0.15.1* sur `POST /internal/v1/pair` de l'Admin : un jeton existant n'est rendu qu'à celui qui le présente, l'acceptation automatique est réservée aux nœuds déclarés (`auto_accept`) ou couverts par un ticket valide et sans jeton, les tickets sont à usage unique et liés aux noms, le jeton d'un nœud approuvé est remis une fois. *Constat* : les passerelles ne s'enrôlent pas elles-mêmes (l'Admin les contacte) et les Agents s'appairent d'abord avec leur passerelle locale (automatique, clé d'Agent) : ce chemin n'a pas changé.
4. Les passerelles ne détiennent plus la racine (clé des Agents dérivée seulement). *Livrée en Admin 0.189.0 / Edge 0.103.0* : la clé du canal Admin → passerelle est dérivée du secret racine et du nom de la passerelle (`goproxify/edge-channel/v1:<identifiant du nœud>:<racine>`, `GPX_EDGE_CHANNEL_KEY` ; l'identifiant est celui que l'Admin connaît, `dn_…`, pas le nom : il survit à un renommage). La passerelle la vérifie, et vérifie aussi la racine si elle l'a encore ; sa clé d'appairage des Agents vient de `GPX_AGENT_PAIRING_KEY`. Sans `GPX_PAIRING_SECRET`, la passerelle démarre, vérifie l'Admin, appaire des Agents et leur parle. L'Admin signe avec la clé dérivée et se replie sur la racine devant une passerelle qui la refuse (`GPX_EDGE_CHANNEL_ROOT_FALLBACK=false` l'interdit). *Limite* : c'est une clé symétrique, la passerelle qui détient la sienne peut se faire passer pour l'Admin **auprès d'elle-même** seulement ; une signature asymétrique de l'Admin n'a pas été retenue. Tant que `GPX_PAIRING_SECRET` reste sur une passerelle, rien n'est gagné : la migration se fait passerelle par passerelle.
5. Rotation planifiée avec recouvrement ; révocation d'urgence par nœud. *5a livrée en Admin 0.188.0 / Edge 0.102.0* : un Admin remplacé laissait son jeton valable sur les passerelles. `POST /api/v1/nodes/revoke-stale-admin-tokens` (`goproxify nodes revoke-stale-admin-tokens`) fait révoquer à chaque passerelle connectée tous les jetons poussés par un Admin sauf celui de l'appelant, enregistré d'abord ; les jetons d'amorçage de la configuration ne sont pas touchés. Opération volontaire, à ne pas lancer si deux Admins vivent ensemble avec des jetons différents. *5b livrée en Admin 0.190.0 / Edge 0.104.0 / Agent 0.18.0* : la rotation planifiée avec recouvrement. `<NOM>_PREVIOUS` (ou `_PREVIOUS_FILE`) liste les valeurs précédentes de `GPX_PAIRING_SECRET`, `GPX_EDGE_CHANNEL_KEY` et `GPX_AGENT_PAIRING_KEY`, acceptées en vérification pendant la bascule seulement et journalisées à chaque usage (le recouvrement est borné par l'opérateur qui les retire, et visible). L'Admin signe avec la clé du secret courant puis celle des précédents ; la passerelle vérifie la signature avec les deux ; elle appaire un Agent qui présente la clé courante ou la précédente ; l'Agent accepte en Bearer ses clés courante et précédentes et s'appaire avec la suivante si la passerelle refuse la première. Ordre : Agents, passerelles, Admin (voir `docs/deployment.md`). *5c livrée en Admin 0.191.0 / Edge 0.105.0* : l'éviction d'urgence d'un nœud et la fin automatique du recouvrement. (1) Un membre qui connaît les jetons de ses pairs (l'Admin les lui donne avec la liste des pairs) ne doit plus les valoir une fois sorti : quand un membre quitte un groupe, après la rotation de la clé du groupe, l'Admin **renouvelle le jeton de chaque membre restant**, le lui pousse, lui fait révoquer l'ancien (à sa reconnexion s'il est hors ligne) et redonne la liste des pairs. `POST /api/v1/nodes/{id}/rotate-token` (`goproxify nodes rotate-token -id`) le fait pour une passerelle précise. Le jeton d'un Agent se révoque comme avant (`reject` / suppression du nœud). (2) `<NOM>_PREVIOUS_UNTIL` (date RFC 3339) met fin au recouvrement à une date : une date passée ou illisible supprime les valeurs précédentes, qui ne sont plus jamais acceptées.
6. Fichiers de secret relus à chaud. *Livrée en Admin 0.190.0 / Edge 0.104.0 / Agent 0.18.0* : `GPX_PAIRING_SECRET_FILE`, `GPX_EDGE_CHANNEL_KEY_FILE` et `GPX_AGENT_PAIRING_KEY_FILE` (et leurs `_PREVIOUS_FILE`) sont relus à chaque usage, sans redémarrage. `GPX_NODE_KEY_FILE` (clé locale) est toujours lu au démarrage seulement : changer la clé locale à chaud exigerait de rechiffrer les copies.

## Décisions sur les points ouverts

- **Pré-approbation des Agents** : automatique par défaut (l'Agent qui présente la clé d'appairage, secret que seuls les Agents et les passerelles détiennent, est pré-approuvé comme aujourd'hui) ; `GPX_AGENT_PREAPPROVAL=manual` sur une passerelle le laisse en attente de l'approbation d'un opérateur (Edge 0.105.0). « Sur déclaration seulement » n'est pas retenu : la passerelle ne connaît pas les nœuds déclarés de l'Admin, et l'Admin accepte déjà automatiquement un nœud déclaré (`auto_accept`) ou couvert par un ticket.
- **Durées** : la validité d'un ticket d'installation reste celle qu'on lui donne à la création (`ttl_hours`). La durée d'un recouvrement de rotation n'a pas de valeur par défaut : l'opérateur la fixe avec `<NOM>_PREVIOUS_UNTIL` ou retire les valeurs précédentes lui-même.
- **Remplacement d'un membre sans Admin** : non pris en charge, comme l'ajout (ADR-0014, section 8). Un membre perdu pendant une coupure de l'Admin n'est remplacé qu'au retour de l'Admin ; le groupe continue avec ses membres restants. Rien ne permet à un membre de se faire admettre sans l'Admin.

## Écarts avec la décision initiale

Les objectifs de sécurité sont atteints (une passerelle compromise ne se fait plus passer pour l'Admin, le secret racine peut rester chez l'Admin seul, il se renouvelle sans interruption, un membre évincé perd la clé du groupe et les jetons de ses pairs). Quatre points du texte ne sont pas réalisés tels qu'écrits :

1. **Section 3, `GPX_AGENT_PAIRING_ROOT` supprimée** : l'option est **gardée, et son défaut ne change pas**. Une passerelle ou un Agent qui détient encore le secret racine peut le présenter, tant que `GPX_AGENT_PAIRING_ROOT=false` n'est pas posé ; chaque usage est journalisé. Le chart Helm (défaut `false`) et le démarrage rapide (qui le pose) la désactivent déjà. Retourner le défaut dans le code casserait sans bruit les Agents qui n'ont pas encore migré : c'est l'opérateur qui le décide, composant par composant.
2. **Conséquences, `GPX_PAIRING_SECRET` seulement sur l'Admin et modèles de déploiement changés** : réalisé pour le démarrage rapide (nouvelles installations) et pour le chart Helm en `Deployment` (`security.edgeWithoutRootSecret`, désactivé par défaut), et possible pour Docker Compose (`docs/deployment.md`). **Pas pour un DaemonSet Helm** : la clé de la passerelle dépend de son nom, que le chart ne connaît pas d'avance, donc elle y garde le secret racine. Pour ces déploiements automatisés, l'Admin accepte aussi la clé dérivée du **nom** de la passerelle, après celle de son identifiant.
3. **Section 6, niveau 3 : identifiants émis par l'Admin et gardés par le composant, rotation sans reconfigurer le conteneur** : **non réalisé**. La clé de canal d'une passerelle est une variable ou un fichier que l'opérateur dépose ; elle se renouvelle sans redémarrage (fichiers relus à chaud, valeurs précédentes), mais ce n'est pas l'Admin qui la remet.
4. **Section 2, jeton d'enrôlement étendu aux passerelles** : **sans objet en pratique**. Les passerelles ne s'enrôlent pas, l'Admin les contacte et leur pousse un jeton qu'il crée lui-même. Le remplacement d'un membre perdu reste une opération de l'Admin.

## Ce qui reste hors de cet ADR

- **DaemonSet Helm** : une passerelle déployée en DaemonSet se nomme d'après son nœud Kubernetes, connu au démarrage seulement. Le chart ne peut pas calculer sa clé de canal sans lui donner le secret racine : elle le garde (`security.edgeWithoutRootSecret` exige `edge.kind: Deployment`). Le chart Helm n'a pas pu être rendu avec `helm` lors de cette mise en œuvre (outil absent) : les gabarits ont été relus et leur syntaxe vérifiée, pas rendus.
- **Jetons des pairs** : l'Admin donne à chaque passerelle la liste de toutes les autres avec leurs jetons (équilibrage de charge, délégations entre groupes). Un membre sorti qui reste enregistré comme passerelle dans l'Admin reçoit donc les nouveaux jetons à la prochaine liste. Pour évincer une machine, supprimez le nœud : son jeton est révoqué et l'Admin cesse de lui pousser quoi que ce soit.
- **Clé locale** : `GPX_NODE_KEY_FILE` est lue au démarrage seulement ; la changer à chaud demanderait de rechiffrer les copies locales.
