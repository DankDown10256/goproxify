# ADR 0016 — Apprentissage de la surface d'un proxy : ne laisser passer que ce qui est utilisé

**Statut :** accepté et mis en œuvre : les cinq étapes (Admin 0.201.0, Edge 0.115.0) l'exclusion de règles du WAF (Admin 0.202.0, Edge 0.116.0), l'alerte à l'apparition d'une suggestion (Admin 0.203.0, Edge 0.117.0) et le type de proxy `api | site` (Admin 0.204.0, Edge 0.118.0) · **Date :** 2026-10-24
**S'appuie sur :** ADR-0006 (autonomie des composants), ADR-0011 (moteurs qui apprennent : mode `detect`, note de risque commune, simulation sur logs), ADR-0014 (groupe HA, unité de service) · **Complète :** ADR-0007 (registre de modules : cette fonction est native, pas un module)

---

## Contexte

Les protections actuelles disent **ce qui est mauvais** : règles WAF, signaux d'Ephor, listes d'IP, d'UA et de chemins. Aucun réglage par proxy ne dit **ce qui est attendu**. Pour fermer un proxy à ce qui n'est pas utilisé, l'administrateur doit déjà savoir quelles méthodes, quels chemins, quels types de contenu et quelles tailles son application emploie réellement. C'est la connaissance que cet ADR veut lui épargner.

État du code, tel que relu pour cet ADR :

- Pas de filtre de méthode ni de chemin autorisé qui se règle sans connaître l'application. `AllowedMethods` n'existe que dans la configuration CORS (qui informe le navigateur et ne contrôle aucun accès) et `Methods` dans celle du cache (`internal/edge/router/route.go`). Le seul contrôle positif existant est la **validation OpenAPI** (`openapi`, chemins, méthodes, paramètres et corps, avec un mode `detect`) et la validation JSON Schema (`request_schema`) : elles exigent que l'administrateur **fournisse** la spécification, c'est-à-dire qu'il connaisse déjà son application. Le profil appris est ce qui permet de la lui proposer (voir les questions ouvertes).
- Les réglages de bornage existent, mais chacun demande de connaître la bonne valeur : `max_body_size`, `rate_limit`, `ip_filter`, `geo_ip`, `waf.exclude_ids`.
- Le moteur comportemental d'Ephor et du WAF apprend déjà un « normal » **par IP** (ADR 0011). Rien n'apprend le normal **du proxy lui-même** : la forme de son trafic légitime.
- Le journal d'accès (`logstore.Entry`) garde méthode, chemin, statut, octets de réponse, IP, UA, référent, signaux. Il **ne garde pas** les en-têtes de requête, le Content-Type, la taille du corps de la requête ni les noms de paramètres. Une simulation sur logs ne peut donc pas tout rejouer ; la partie qui manque doit être observée en direct.

Un proxy découvre rarement seul ce qui est légitime ; il peut en revanche le **mesurer** sur le trafic qu'il voit déjà, puis le proposer pour validation. Cette approche existe sous d'autres noms dans le métier (apprentissage de politique des pare-feu applicatifs, schémas d'API déduits du trafic).

---

## Décision

Ajouter, **par proxy**, une fonction d'**apprentissage de surface** : la passerelle observe le trafic légitime, en déduit un profil, propose des réglages à partir de ce profil, puis applique une **politique positive** (ce qui n'est pas dans le profil est refusé) une fois que l'administrateur l'a validée.

Mode par proxy : `off | learn | detect | enforce`.

| Mode | Effet sur le trafic | Ce qui tourne |
|---|---|---|
| `off` | aucun | rien (défaut) |
| `learn` | **aucun** | le profil se construit ; aucune politique n'est évaluée |
| `detect` | aucun | la politique validée est évaluée ; les violations sont journalisées, comptées et versées à la note commune sans bloquer |
| `enforce` | refus des violations | idem, avec refus (par type de violation, voir l'étape 4) |

### Principes

- **Apprendre = mesurer ce qui est utilisé, pas deviner ce qui est sûr.** Le profil décrit le trafic légitime observé ; il ne dit pas que ce trafic est sans danger. La politique réduit la surface d'attaque, elle ne remplace ni le WAF ni Ephor, qui restent en amont de l'application pour ce qui passe.
- **Rien n'est appliqué sans validation.** Le profil appris n'est jamais de la configuration (ADR 0011). Il produit des **propositions** que l'administrateur accepte ligne par ligne ; une proposition acceptée devient un réglage ordinaire, modifiable.
- **Chaque proposition se justifie.** Pour chaque règle : le nombre de requêtes, d'IP et de jours qui la soutiennent, et ce qu'elle aurait refusé sur le trafic récent. C'est ce qui rend inutile de savoir « ce qui est faisable ou pas ».
- **Tout nouveau contrôle naît en `detect`** et passe en `enforce` après lecture des violations, jamais d'office.
- **Le trafic non légitime n'enseigne rien.** Une requête entre dans le profil seulement si elle ne ressemble pas à une attaque (voir *Ce qui entre dans le profil*).
- **Fonction native du cœur, pas un module** : c'est une fonction standard d'un proxy, sans point d'extension à ouvrir.

### Ce que le profil décrit

Le profil est une description **agrégée**, sans valeur ni IP :

| Dimension | Contenu retenu |
|---|---|
| Méthodes | liste des méthodes vues |
| Chemins | **gabarits** (`/api/users/{id}`), avec pour chacun : méthodes, statuts, Content-Types de requête et de réponse, taille maximale et 99ᵉ centile du corps, noms des paramètres de requête (avec leur classe : entier, UUID, énumération courte, texte, et longueur maximale), nombre de requêtes, d'IP distinctes (estimation), de jours, première et dernière date |
| En-têtes | **noms** des en-têtes de requête rencontrés (borné), jamais leurs valeurs |
| Clients | pays et ASN (compteurs), plages agrégées (/24 en IPv4, /48 en IPv6) |
| TLS | version et famille d'empreinte vues |
| Débit | débit appris par IP, route par route : repris des références de l'ADR 0011 (étape 4), pas recalculé |

**Gabarits de chemin.** Les segments sont classés en ligne : numérique, UUID, hexadécimal long, date, jeton long. Un segment littéral qui prend plus de N valeurs distinctes sous un même parent devient une variable `{var}`. Le nombre de gabarits est plafonné par proxy ; au-delà, les nouveaux chemins tombent dans un gabarit de débordement et le profil est marqué *non convergent*. Un segment qui ressemble à une donnée personnelle (adresse électronique, par exemple) est remplacé par une variable : le profil ne retient pas de valeur propre à une personne.

**Ce qui entre dans le profil.** Une requête alimente le profil si le statut final est 2xx, 3xx ou 401 (la route existe, éventuellement derrière une authentification) **et** si son IP n'a pas de note de risque non nulle, n'est pas bannie et n'a déclenché aucune règle du WAF. Les requêtes en 400, 404, 405, 5xx sont comptées à part (*vues mais en échec*) : elles alimentent le rapport, jamais la politique. Un gabarit n'est proposé qu'au-delà d'un **soutien minimal** (IP distinctes et jours distincts), pour qu'un seul client, en particulier un scanner, ne puisse pas y inscrire un chemin.

**Pas d'identifiant ni de valeur.** Les IP ne servent qu'à l'estimation du nombre de clients distincts (compteur approché à sel de processus) et ne sont pas écrites. Les en-têtes et paramètres sont réduits à leur nom et à une classe. Il n'y a donc rien à purger lors d'un effacement RGPD.

### Où ça vit

- **Observation** : sur la passerelle, en fin de requête (le statut est alors connu), en temps constant par requête et sans allocation : une descente dans un arbre de gabarits et quelques compteurs. Le coût est mesuré avant livraison, comme pour les signaux de l'ADR 0011.
- **Évaluation de la politique** : sur la passerelle, après le filtre d'IP et les bans, avant le WAF et le routage amont.
- **Autonomie (ADR 0006)** : le profil, les propositions et la politique tournent sur la passerelle seule. Le profil est copié chiffré (`surface-state.gpx`, toutes les 5 minutes et à l'arrêt, même mécanisme que `threat-state.gpx`) et restauré au démarrage sans l'Admin. La politique **validée** est de la configuration : elle est stockée avec le proxy, poussée par l'Admin, et la passerelle en garde sa copie locale chiffrée. Une coupure de l'Admin n'arrête ni l'observation ni l'application de la politique ; elle empêche seulement de la voir et de la modifier depuis l'Admin.
- **Groupe HA (ADR 0014)** : le trafic se répartit entre les membres, et chacun n'en voit qu'une part. Les membres **fusionnent leurs profils entre eux, sans l'Admin** : union des ensembles (gabarits, méthodes, noms), somme des compteurs propres à chaque membre, maximum pour les mesures. La fusion est idempotente, comme celle de la note commune. Tous les membres appliquent la même politique, puisqu'elle est de la configuration.
- **Admin** : affiche le profil et la convergence, produit la proposition, recueille la validation. L'Admin interroge la passerelle (un membre par groupe, repli sur un pair, comme pour les logs) ; il ne stocke pas le profil.

---

## Étapes

Chacune est livrable seule, dans cet ordre.

### 1. Observer et rapporter (`learn`, sans aucun effet sur le trafic)

Profil par proxy, indicateur de **convergence** (ancienneté, volume, taux de nouveaux gabarits par jour sur les dernières 48 h), rapport lisible : ce qui passe, par qui, avec quelles tailles. Interface, API, CLI et MCP en lecture seule. Cette étape ne casse rien et apporte déjà de la compréhension.

### 2. Proposer des réglages existants

À partir du profil, proposer : `max_body_size` (99ᵉ centile et marge), `rate_limit`, `geo_ip`, `ip_filter` (plages agrégées), `cors` (origines vues). La simulation sur logs de l'ADR 0011 mesure ce que chaque proposition aurait refusé pour la part que le journal porte (méthode, chemin, statut, IP). Pour les autres dimensions, le compteur *aurait refusé* se lit en direct dès l'application en `detect`.

Pour `waf.exclude_ids` : une règle qui se déclenche **de façon répétée sur des IP par ailleurs propres** peut être proposée à l'exclusion, avec un avertissement explicite (un faux positif et une attaque lente ont la même apparence). Jamais automatique.

### 3. Politique positive en `detect`

Nouveau réglage par proxy : méthodes autorisées, gabarits de chemin autorisés, et par gabarit : méthodes, Content-Types de requête, taille maximale du corps, noms de paramètres admis. Violations journalisées avec leur raison, comptées (`gpx_surface_violations_total`, étiquetées par type de violation), et versées à la note commune d'Ephor comme signaux `surface_*` en `detect`.

### 4. Application (`enforce`), règle par règle

`enforce` se règle **par type de violation**, pas en bloc :

| Violation | Réponse |
|---|---|
| méthode non autorisée | 405 |
| chemin hors profil | 404 (n'apprend rien à un scanner sur ce qui existe) |
| Content-Type non admis | 415 |
| corps trop grand pour le gabarit | 413 |
| paramètre inconnu | 400 |

Les violations d'un type en `enforce` alimentent aussi la note commune : un scanner qui multiplie les chemins hors profil finit banni par Ephor, sans règle supplémentaire. Retour en `detect` en un geste.

### 5. Maintenir

L'apprentissage **continue en arrière-plan** une fois la politique appliquée. Un chemin refusé qui revient de nombreuses IP distinctes sur plusieurs jours devient une **suggestion d'ajout** (« nouveau chemin vu par N clients sur K jours »). La politique ne s'élargit jamais seule.

---

## Règles

- **Démarrage à froid** : `enforce` est refusé tant que le profil n'a pas convergé (ancienneté et volume minimaux, par défaut un cycle de 7 jours pour voir l'activité du week-end ; plus aucun nouveau gabarit depuis 48 h). Le seuil se contourne par une confirmation explicite, journalisée à l'audit.
- **Sécurité par défaut, dans les deux sens** : une politique absente, illisible ou périmée ne bloque jamais plus (retour en `detect`). Elle ne coupe pas non plus le proxy : en cas de doute, le trafic passe, comme avant l'activation.
- **Empoisonnement** : un attaquant présent pendant l'apprentissage peut tenter d'inscrire ses chemins. Parades : exclusion des IP à note non nulle, soutien minimal (IP et jours distincts), validation humaine ligne par ligne, rapport des chemins à faible soutien marqués *à confirmer*.
- **Mémoire bornée** : gabarits, paramètres, en-têtes et plages sont plafonnés par proxy, avec éviction et indicateur *non convergent* au débordement. La mémoire totale croît avec le nombre de proxies en `learn`, pas avec le trafic.
- **Faux positifs** : refuser une route rare (export annuel, webhook de fin de mois) est le risque principal d'`enforce`. Il se traite par la durée minimale d'apprentissage, par `detect` avant `enforce`, par l'ajout manuel d'un gabarit, et par un journal des refus lisible depuis la page du proxy.
- **Pas de confusion avec une preuve de sécurité** : l'interface dit ce que la politique couvre (surface exposée) et ce qu'elle ne couvre pas (contenu des requêtes autorisées, laissé au WAF).

---

## Conséquences

- Un proxy peut passer de « tout ouvert, protégé par des listes de mauvais » à « ouvert à ce qui est utilisé » sans que l'administrateur connaisse sa propre application.
- L'étape 1 est utile seule (rapport) et n'a aucun effet sur le trafic : elle peut sortir en premier et servir à mesurer la qualité du profil avant toute politique.
- La note commune d'Ephor gagne une nouvelle famille de signaux (`surface_*`) alimentée par une source indépendante des listes et du comportement par IP.
- Nouveau coût permanent par proxy en `learn` : un arbre de gabarits en mémoire et une copie chiffrée sur disque. À mesurer avant l'étape 3.
- Nouvelle surface d'API, de CLI et de MCP (profil, propositions, politique, violations) à documenter à chaque étape livrée.

## Étape 1 : ce qui est livré, et les écarts

Livré (Admin 0.197.0, Edge 0.111.0) : mode `off | learn` par proxy (`detect` et `enforce` refusés à l'enregistrement), paquet `internal/edge/surface`, observation en fin de requête (avant Ephor, pour que la note de l'IP ne contienne pas ce que la requête vient d'y ajouter), profil chiffré en local (`surface-state.gpx`), fusion entre membres d'un groupe HA, rapport et convergence (API, interface, CLI, MCP), remise à zéro. Coût mesuré : ≈ 0,7 µs et aucune allocation par requête.

Écarts avec la décision :

- **Pas de plages d'IP (/24, /48) dans le profil.** Elles ne servent qu'à proposer un `ip_filter` (étape 2) et posent la question de leur effacement RGPD ; elles arriveront avec leur usage. Le profil ne contient donc aucune adresse, pas même tronquée.
- **Pas de famille d'empreinte TLS**, seulement la version de TLS et le protocole : la famille n'apporte rien tant qu'aucune politique ne s'en sert.
- **Hachage des IP non salé.** Un sel par passerelle empêcherait l'union des estimateurs de deux membres d'un groupe (une IP vue des deux côtés serait comptée deux fois). Les registres de l'estimateur ne permettent pas de retrouver une adresse.
- **Fusion de groupe par instantané des pairs.** Chaque membre garde le dernier profil local reçu de chaque pair (remplacé à chaque échange, jamais additionné) et affiche la fusion à la lecture. Cela rend la fusion idempotente sans compteur par origine. Tous les membres doivent être remis à zéro ensemble (l'Admin s'en charge) ; un instantané reste copié chiffré avec le profil local, pour qu'un redémarrage sans l'Admin ni le pair ne perde pas le groupe.
- **Convergence : les 48 h comptent les gabarits** dont la première apparition est récente, pas les requêtes.
- **Pas de label Docker** pour activer le mode : le champ `surface` de la configuration du proxy, l'interface, la CLI (`proxy option … surface`) et le MCP suffisent à ce stade.
- **Le rapport lit un membre par passerelle**, pas un seul par groupe : chaque membre rend déjà la fusion du groupe, l'interface garde celui qui en réunit le plus. Le repli sur un pair comme pour les logs n'est pas nécessaire tant que chacun connaît les autres.

## Étape 2 : ce qui est livré, et les écarts

Livré (Admin 0.198.0, Edge 0.112.0) : `max_body_size`, `rate_limit`, `geo_ip`, `ip_filter` et `cors` proposés avec leur justification, ce qu'ils auraient refusé, leurs limites et la commande qui les pose ; les réglages que le proxy a déjà, snippets compris, ne sont jamais remplacés ; chaque réglage non proposé dit pourquoi. Rien n'est appliqué : poser une proposition est un geste de l'administrateur (`proxy option`, `update_proxy`).

Écarts avec la décision :

- **Pas de rejeu de logs.** La décision prévoyait la simulation de l'ADR 0011 pour mesurer ce que chaque proposition aurait refusé. Le profil compte déjà, exactement et sur tout le trafic appris, de quoi le calculer (pays, réseaux, corps), alors que le journal ne porte ni le pays, ni les en-têtes, ni la taille du corps. Le nombre est donc exact, sans échantillon. Seul `rate_limit` n'est pas mesuré : le débit par IP est la propriété d'Ephor, dont les références servent de base (ADR 0011, étape 4).
- **Les plages d'IP entrent dans le profil** (/24 en IPv4, /48 en IPv6, 256 au plus), comme annoncé à l'étape 1. Ce sont des agrégats comparables à une adresse tronquée : le profil n'en tire aucune adresse exacte, et une justification n'en cite jamais.
- **Les valeurs de l'en-tête `Origin` entrent dans le profil** (50 au plus) : ce sont des noms d'hôtes d'applications web, pas des données de personnes. C'est la seule valeur d'en-tête gardée.
- **`waf.exclude_ids` n'était pas proposé à l'étape 2.** Il l'est depuis Admin 0.202.0 / Edge 0.116.0 (voir plus bas).
- **Seuils des propositions** (constantes, à régler à l'usage) : 100 requêtes apprises au moins ; `geo_ip` : 99,5 % de couverture, 15 pays au plus, pas plus de 1 % de trafic refusé ; `ip_filter` : 16 réseaux au plus ; `cors` : 10 origines au plus ; `max_body_size` : 16 Ko au plus bas, le double du plus gros corps.

## Étape 3 : ce qui est livré, et les écarts

Livré (Admin 0.199.0, Edge 0.113.0) : le profil s'écrit comme une **spécification OpenAPI 3.1** pour le contrôle `openapi` existant, en mode `detect` avec `unknown_paths: block` (question ouverte 3 tranchée : pas de second format de politique). Violations visibles dans le rapport, signal Ephor `surface_violation`, générateur vérifié contre le vrai contrôle dans les tests, interface (génération, pré-remplissage de la carte *Validation OpenAPI*, copie), CLI (`security surface openapi -out`), MCP (`get_proxy_surface_openapi`). Rien n'est appliqué sans que l'administrateur enregistre le proxy.

Écarts avec la décision :

- **Le mode `detect` n'a pas de compteur `gpx_surface_violations_total`** : le contrôle `openapi` a déjà sa métrique par résultat (`valid`, `invalid`, `unknown_path`, `unknown_method`). Ce qui manquait était la **raison** et le **chemin** : ils sont dans le profil (rapport de surface), par raison, méthode et chemin normalisé, 100 groupes au plus.
- **Un seul signal Ephor, `surface_violation`**, au lieu d'une famille `surface_*` : il ne sert qu'à dire « hors de la politique et refusé par le backend », ce qui ne demande pas de distinguer les raisons. Il reste en `detect` comme tout nouveau signal.
- **Les violations ne se comptent que pendant le mode `learn`** : c'est lui qui relie le verdict du contrôle à la requête finie (statut, IP propre). Une politique `openapi` posée sans `learn` garde sa métrique seule.
- **La politique ne décrit pas les corps** (le profil ne les apprend pas) : elle contrôle chemins, méthodes, paramètres typés et types de contenu. Les énumérations de paramètres ne sont pas écrites : le profil sait qu'une liste est fermée, pas ses valeurs, qu'il ne garde jamais.
- **Chemins à faible soutien exclus par défaut**, avec `include_low_support`, pour qu'un chemin ne passe pas dans la politique sur la foi d'un seul client.
- **Pas d'application automatique** : l'interface remplit la carte *Validation OpenAPI* de la modale ouverte, l'administrateur enregistre ; la CLI écrit un fichier. Ce choix évite d'écraser les champs d'une modale en cours d'édition.

## Étape 4 : ce qui est livré, et les écarts

Livré (Admin 0.200.0, Edge 0.114.0) : `block_reasons` sur le contrôle `openapi` existant (en `detect`, il refuse les types listés et compte les autres), `enforce` et `relax` côté Admin avec leurs garde-fous, simulation, audit, refus comptés dans le rapport, panneau de l'interface, CLI et MCP. Question ouverte 3 close : le « par type » est une liste sur le contrôle existant, pas un second mécanisme.

Écarts avec la décision :

- **Pas de refus des paramètres inconnus** (400 dans la table de l'étape 4) : le contrôle `openapi` n'examine que les paramètres déclarés. `invalid_param` couvre les paramètres déclarés qui n'ont pas le bon type. Les réponses sont celles du contrôle existant, avec son corps d'erreur JSON ; le 404 d'un chemin inconnu ne dit rien à un scanner sur ce qui existe, le 405 dit seulement quelles méthodes le chemin accepte (`Allow`).
- **Le retour en detect est `relax`, et le seuil de démarrage à froid se passe par `force`** (audit), pas par une confirmation séparée : un seul mécanisme de dérogation, journalisé.
- **Garde-fou ajouté** : le refus de `unknown_path` ou `unknown_method` impose `unknown_paths: block` (sans lui ces violations n'existent pas) ; il est posé avec un avertissement. Et une correction de l'étape 3 : un chemin inconnu n'est plus une violation quand le proxy les laisse passer (`unknown_paths: allow`).
- **Les garde-fous sont ceux de l'assistant, pas du contrôle** : `block_reasons` ou `mode: block` posés à la main (`proxy option`, `update_proxy`) les ignorent. C'est voulu : le contrôle `openapi` reste un contrôle ordinaire que l'administrateur règle comme il l'entend ; l'assistant empêche seulement de bloquer trop tôt.
- **Pas de refus automatique** : ni le passage en block ni son retour ne se font tout seuls (aucune détection d'un pic de refus qui relâcherait la politique) ; à reprendre avec l'étape 5 si l'usage le montre utile.

## Étape 5 : ce qui est livré, et les écarts

Livré (Admin 0.201.0, Edge 0.115.0) : suggestions d'ajout continues (`unknown_path`, `unknown_method`) avec deux niveaux de confiance, ajout à la spécification sans rien retirer, oubli des violations acceptées chez toutes les passerelles, panneau, CLI, MCP, nombre d'ajouts en attente dans la liste des proxies.

Écarts avec la décision :

- **« Un chemin refusé qui revient de nombreuses IP distinctes sur plusieurs jours »** ne suffit pas pour une politique en `block` : un scanner distribué fait de même. La décision est donc scindée en confiance haute (le backend a servi) et basse (refusé, plus de clients, plus de jours, à examiner), et les chemins de scanner connus ne sont jamais suggérés. C'est une liste courte (heuristique, `probeMarks`), à compléter à l'usage.
- **Seuls le chemin et la méthode s'ajoutent.** Le profil ne retient ni le type du paramètre ni le type de contenu d'une violation : pour les autres raisons, il n'y a pas de quoi écrire un ajout correct. Elles restent visibles dans le rapport.
- **L'ajout ne s'applique qu'à une spécification en JSON**, celle que l'assistant génère. Réécrire un YAML perdrait sa mise en forme ; il est refusé, l'administrateur ajoute le chemin à la main.
- **Alerte à l'apparition d'une suggestion** : livrée depuis Admin 0.203.0 / Edge 0.117.0 (`surface_suggestion`, voir plus bas).
- **Pas de remise à jour automatique de la spécification** : la politique générée à l'étape 3 reste la photo du moment ; les suggestions la complètent, mais une régénération complète (`surface openapi`) écraserait des ajouts faits à la main. Elle est signalée (`replaces`).
- **`waf.exclude_ids`** : proposé depuis Admin 0.202.0 / Edge 0.116.0.

## Exclusion de règles du WAF : ce qui est livré, et les écarts

Livré (Admin 0.202.0, Edge 0.116.0) : l'observation de la requête garde les règles du WAF déclenchées (et si le WAF a refusé), le profil les compte par règle avec leurs clients propres, la proposition `waf` reprend la configuration du proxy avec `exclude_ids` augmenté, le rapport et l'interface listent les règles.

Écarts avec la décision de l'étape 2 (« une règle qui se déclenche de façon répétée sur des IP par ailleurs propres ») :

- **« Par ailleurs propres » exclut le WAF lui-même.** L'IP est propre si elle n'a ni signal d'Ephor, ni score d'Ephor, ni signal de comportement autre que l'accumulation du WAF ; sans cela le déclenchement de la règle suffirait à la rendre suspecte, et aucune règle ne serait jamais proposée.
- **« De façon répétée » veut dire : chaque client recommence.** Un faux positif touche des clients qui refont la même action (une recherche avec une apostrophe) ; une attaque change d'IP ou fait vite lever d'autres signaux. Sans cette condition, une sonde distribuée à passe unique serait proposée.
- **Deux paliers**, comme à l'étape 5 : la règle dont le backend a servi les requêtes (preuve), et celle que le WAF refuse (on ne sait pas ce que l'application aurait fait, seuils plus hauts).
- **Une seule proposition `waf`**, valeur complète, pas une proposition par règle : `proxy option … waf` remplace l'objet entier, des propositions séparées s'écraseraient. L'administrateur peut retirer des identifiants de la commande.
- **Les règles critiques sont proposées avec une mise en garde renforcée** (injection, chemin, commande), pas écartées : c'est précisément là que les faux positifs coûtent le plus et que l'exclusion est la plus dangereuse.
- **Un WAF défini par un snippet** n'est pas modifiable depuis le proxy : la proposition renvoie vers le snippet, sans valeur.
- **Les règles dont l'identifiant est celui d'une règle personnalisée** ne sont jamais proposées (elles sont de l'administrateur).

## Alerte à l'apparition d'une suggestion : ce qui est livré, et les écarts

Livré (Admin 0.203.0, Edge 0.117.0) : déclencheur `surface_suggestion`, état des suggestions envoyé par chaque passerelle toutes les 5 minutes (message WebSocket `surface_suggestions`), déduction du nouveau côté Admin, une alerte par proxy et par lot.

Écarts et choix :

- **C'est l'Admin qui déduit ce qui est nouveau, pas la passerelle.** Une passerelle qui noterait « déjà signalé » dans son état perdrait l'alerte si l'Admin était coupé au moment de l'envoi ; en renvoyant l'état complet, la suggestion apparue pendant une coupure alerte à la reconnexion. Le prix : l'Admin retient ce qu'il a signalé en mémoire, et après son redémarrage les suggestions en attente alertent une fois de plus.
- **Confiance haute seulement.** Une suggestion de confiance basse (refusée par le contrôle, clients propres qui reviennent) est ce qu'un scanner distribué produit aussi : elle n'a pas à réveiller quelqu'un. Son nombre figure dans le message.
- **Autonomie (ADR 0006)** : rien ne dépend de l'alerte. Le profil, les suggestions et leur acceptation tournent sans l'Admin ; l'alerte est une supervision, que seule l'Admin sait router vers des canaux.

## Type de proxy `api | site` : ce qui est livré, et les écarts

Livré (Admin 0.204.0, Edge 0.118.0) : `surface.type` (`api`, `site`, vide = API), validation à l'enregistrement, convergence d'un site indépendante des chemins, pas de politique de chemins ni de suggestion pour un site, notes dans les propositions, indice `type_hint` donné par le trafic, liste *Type de proxy* dans l'interface.

Écarts avec la proposition de l'ADR (« pour un `site`, le profil propose méthodes, types de contenu et tailles, et pas de liste de chemins ») :

- **Les méthodes et les types de contenu ne se proposent pas comme réglage** : aucun contrôle par proxy ne les restreint (le contrôle `openapi` raisonne en chemins, et sa spécification ne sait pas dire « n'importe quel chemin »). Le rapport les **décrit** pour le proxy entier (méthodes, types de contenu des requêtes et des réponses, tailles de corps) ; ce qui se propose pour un site, c'est ce qui l'a toujours été : tailles de corps, réseaux, pays, CORS, débit, exclusions du WAF.
- **Le type reste déclaré par l'administrateur** ; le trafic ne fait que le suggérer. Un site pris pour une API ne convergerait jamais (ses chemins ne cessent de changer) : l'indice le dit dans le rapport et les propositions.
- **Une correction sur la route** : les corps de requête sont mesurés pour le proxy entier. Avant, ceux dont le chemin n'avait pas pu être retenu étaient perdus, et la proposition `max_body_size` d'un proxy qui débordait (un site, typiquement) pouvait être trop basse.
- **Les valeurs d'amorçage** (question 2) : tranchée (voir *Exclusions du WAF par chemin*) : pas de gabarits pré-remplis ; la reconnaissance d'une plateforme suggère des exclusions de règles **par chemin**, sans rien appliquer.

## Exclusions du WAF par chemin : ce qui est livré, et les écarts

Admin 0.205.0, Edge 0.119.0. Né de la vérification de l'exclusion « automatique » du WAF, qui ne faisait rien, puis de la question de fond : une règle exclue pour tout le proxy laisse sans défense le reste de l'application.

- **L'exclusion est par chemin** (`waf.exclusions` : `paths`, `rule_ids`, `platform`, `note`). Sous le préfixe la règle est retirée ; partout ailleurs elle reste. C'est la seule forme proposée par l'apprentissage. `exclude_ids` reste un choix explicite de l'administrateur, pour tout le proxy. `exclude_platforms` (les règles d'une plateforme retirées pour tout le proxy) a été retiré (Admin 0.211.0 / Edge 0.125.0) : nommer une plateforme ne se fait plus que dans une exclusion par chemin.
- **Pourquoi pas « WAF générique »** : la vraie alternative à une exclusion n'est pas un WAF complet mais un WAF éteint (ou en detect), parce qu'en `block` l'application devient inutilisable. L'exclusion par chemin est le compromis le plus étroit : une règle, un préfixe.
- **`auto` a été retiré (Admin 0.206.0 / Edge 0.120.0).** Il reconnaissait la plateforme d'après les noms d'hôte et de backend, la signalait et suggérait une exclusion par chemin, sans rien exclure. Reconnaître WordPress ne dit pas quelle règle se trompe ni où, et ne protège de rien ; pour les CVE il ne donne aucune version (voir l'[ADR 0017](0017-inventaire-des-applications-et-cve.md)). Les noms de plateformes explicitement nommés, eux, s'appliquent (ils ne s'appliquaient pas du tout avant : voir le changelog, *Corrigé*).
- **Sans chemin net, pas d'exclusion proposée.** Une règle dont les déclenchements ne se circonscrivent pas (racine, premier segment variable, chemins non retenus) reçoit un **conseil** : `anomaly_threshold` à 10 (une règle seule ne suffit plus à refuser, plusieurs concordantes si) ; le mode `detect` en dernier recours. Rien n'est conseillé à un WAF déjà en detect ou à un seuil de 10 ou plus.
- **Amorçage** : aucun chemin n'est embarqué ni suggéré d'après une plateforme ; les exclusions proposées viennent du trafic réel du proxy. Le profil n'est pas pré-rempli : il reste celui de l'application réelle.
- **Observabilité** : les propositions de l'apprentissage de la surface (`get_proxy_surface_proposals`) disent quelle règle se déclenche, sous quels chemins, et ce que coûterait chaque exclusion.
- **Autonomie (ADR 0006)** : la configuration est celle du proxy, copiée chiffrée sur la passerelle comme le reste ; reconnaissance, exclusions et état tournent sans l'Admin.
- **Limites** : pas de label Docker pour `exclusions` ; l'interface conserve les exclusions à l'enregistrement mais ne les édite pas encore (JSON via `proxy option`, API ou CLI) ; la compensation sous un chemin exclu (authentification, filtre d'IP) reste à la charge de l'administrateur, la documentation le dit.

## Questions ouvertes

1. **Sites et CMS.** *Tranchée (Admin 0.204.0 / Edge 0.118.0) : `surface.type`, voir plus bas.* Une liste blanche de chemins a du sens pour une API (surface fermée) et très peu pour un site avec du contenu créé par les utilisateurs (surface ouverte, milliers de chemins). Proposition : un type de proxy (`api | site`) ; pour un `site`, le profil propose méthodes, types de contenu et tailles, et pas de liste de chemins. À trancher avec un jeu de trafic réel.
2. **Valeurs d'amorçage.** *Tranchée : la reconnaissance de plateforme du WAF ne pré-remplit pas le profil, puis elle a été retirée (Admin 0.206.0 / Edge 0.120.0), voir plus bas.* Reprendre la détection de plateforme applicative du WAF pour pré-remplir des gabarits connus (WordPress, par exemple) évite un apprentissage de zéro, mais fige des chemins que l'application n'utilise peut-être pas.
3. **OpenAPI.** *Tranchée à l'étape 3 : la politique est une spécification OpenAPI pour le contrôle existant.* *Tranchée à l'étape 4 pour le « par type » (`block_reasons`).* Reste que ce qu'OpenAPI ne sait pas dire (taille maximale du corps par chemin, clients) reste des réglages à part (`max_body_size`, `ip_filter`).
4. **Le journal d'accès.** *Sans objet depuis l'étape 2 : le profil compte lui-même ce que chaque proposition aurait refusé.* La simulation de l'étape 2 aurait gagné à garder le gabarit de chemin et la taille du corps de la requête dans chaque ligne. Cela touche le format des logs (ADR 0010, ADR 0012) et se décide séparément.
5. **Chemin avec ou sans paramètres de requête dans le journal** : *sans objet*, le profil s'observe en direct et n'en dépend pas.
6. **WebSocket, gRPC, flux** : les gabarits fonctionnent (le service et la méthode gRPC sont des segments littéraux), mais la taille du corps et le Content-Type n'ont pas le même sens sur un flux. *Toujours ouverte* : jamais éprouvée sur un flux réel (WebSocket, gRPC en flux) ; le contrôle openapi ne valide pas les corps qui ne sont pas du JSON.
7. **Nom de la fonction** dans l'interface : *« Apprentissage de la surface »*, clé technique `surface`.
