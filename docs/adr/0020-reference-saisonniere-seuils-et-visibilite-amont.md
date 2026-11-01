# ADR 0020 — Porte d'entrée, réponse graduée, Seuils d'Ephor et référence saisonnière du trafic

**Statut :** proposé (à relire) ; toutes les étapes livrées (0 à 4 : Edge 0.146.0, Admin 0.240.0), calibrage sur de vrais logs à faire · **Date :** 2026-10-31
**S'appuie sur :** ADR-0006 (autonomie des composants), ADR-0011 (moteurs adaptatifs WAF et Ephor : cet ADR complète son étape 4, qui note que « la saisonnalité hebdomadaire n'est pas modélisée »), ADR-0012 (la passerelle possède ses logs, plus de fichier texte), ADR-0014 (groupe HA), ADR-0016 (profil de surface d'un proxy)
**Remplace :** le moteur « Fail2Ban » natif de la passerelle (`internal/edge/fail2ban`)

---

## Contexte

Sept constats, tirés du code le 2026-10-31. Les points 5 et 6 sont des lectures du code, **non encore confirmées par un test** : leur correctif commence par un test qui échoue.

1. **La référence apprise d'Ephor est par IP, et aveugle aux attaques distribuées.** `waf/behavior/references.go` apprend le débit « normal » *d'une IP* (90ᵉ centile des IP sans signal), par heure du jour. Un botnet de 10 000 IP à 3 requêtes par minute chacune ne dépasse le seuil d'aucune : le trafic total de la route est pourtant multiplié par vingt. Rien ne compare le trafic **agrégé** d'une route à son comportement habituel, et la référence ne distingue ni le jour de la semaine ni le week-end. Côté Admin, `DetectAnomalies` fait un z-score sur la période affichée : ce n'est pas une référence saisonnière, et il ne tourne pas sur la passerelle (donc pas pendant une coupure de l'Admin, ADR-0006).

2. **Les plafonds sont fixes.** Le limiteur global (`threat.globalBucket`, `GlobalRPS`) vaut autant pour 3 h du matin que pour le pic de midi : trop haut la nuit, trop bas le jour.

3. **Le « Fail2Ban » natif n'est pas Fail2Ban, et double Ephor.** C'est une réimplémentation en Go (`internal/edge/fail2ban/fail2ban.go`) qui n'utilise rien du vrai programme. Elle se réduit à **un seul jail câblé en dur** : les 4xx hors 404, 50 en 300 s, ban permanent par défaut. Ephor bannit déjà sur des 4xx répétées (signal `error4xx`, seuil par fenêtre et score pondéré par code et par route) ; en mode pondéré il ignore volontairement les 401, 403 et 429. Défauts relevés à la lecture (non reproduits) :
   - les compteurs ne survivent pas à un redémarrage (Ephor, lui, les persiste : ADR-0011, étape 1) ;
   - la table des IP n'est pas bornée et se protège par un mutex unique ;
   - l'ensemble `banned` ne se vide que dans `UnbanIP` (déban par l'Admin) : avec une durée de ban non nulle, une IP dont le ban a expiré semble ne plus pouvoir être rebannie avant un redémarrage. Le défaut par défaut (ban permanent) le masque ;
   - la documentation parle d'« échecs d'authentification » alors que le code compte tous les 4xx hors 404 ;
   - le nom fait croire à une compatibilité avec le vrai Fail2Ban (jails, filtres regex, récidive) qui n'existe pas.

4. **Chaque requête parcourt tous les bans.** `BanStore.CheckBlocked` (`router/ban_store.go:83`) fait un `net.ParseIP` puis une boucle linéaire sur tous les bans, avec test d'expiration, sous un verrou en lecture ; `IPProfileStore.CheckBlocked` fait de même sur les profils. Le coût par requête croît avec le nombre de bans (CrowdSec en mode stream, attaque distribuée) et il est payé par les requêtes légitimes. Aucun benchmark n'existe.

5. **La porte d'entrée HTTPS est fragile face aux scanners.**
   - **Acceptation sérialisée.** `sniListener.Accept` (`internal/edge/server.go:827`) lit le ClientHello *dans* la boucle d'acceptation, avec une échéance de 10 s. Une connexion TCP muette (ce que font les scanners sans ClientHello) retarde l'acceptation de toutes les suivantes jusqu'à ce délai.
   - **Étiquettes de métriques non bornées.** `gpx_tls_handshake_seconds{host}` et `gpx_tls_active_connections{host}` (`metrics/prometheus.go:239`) prennent le SNI brut (`server.go:876`, `server.go:802`). Avec un certificat wildcard (`tls/certstore.go:124`), n'importe quel sous-domaine termine sa poignée de main et crée de nouvelles séries : la mémoire croît sans limite. Aucune garde de cardinalité n'a été trouvée ; `BytesOutByHost` (`dispatch.go:274`) est à vérifier si des routes wildcard existent.

6. **Ce qui est rejeté à l'entrée est invisible, et trahit le produit.**
   - Une erreur de lecture du ClientHello (`server.go:838`) ou de poignée de main (`server.go:873`) ne laisse ni compteur ni log : accès par l'IP, SNI inconnu ou absent, tout est silencieux.
   - Un hôte inconnu en HTTP passe par Ephor avant le routage (`dispatch.go:185`) mais sa réponse n'est pas observée (`Observe` n'est appelé qu'après le routage, `dispatch.go:260`), et reçoit un 404 dont la page par défaut a pour titre « *code* — Goproxify » (`errorpages/errorpages.go:96`) : un scanner apprend quel logiciel tourne.

7. **Il n'y a pas de réponse intermédiaire entre « laisser passer » et « bannir ».** Le défi à preuve de travail (Edge 0.35.0, option `bot` d'un proxy) existe, mais il est statique, par proxy : Ephor ne peut pas l'imposer à une IP à note moyenne. Le dernier manque est de visibilité : ce qu'un pare-feu ou un Fail2Ban installé **sur l'hôte** bloque en amont n'atteint jamais la passerelle, qui ne peut pas le montrer. Il n'est traité que comme éventualité (voir « Éventualités »).

---

## Décision

Cinq étapes, livrables chacune seule, **dans l'ordre du rapport entre l'apport réel et le travail**. Les étapes 0 à 3 tournent sur la passerelle ; l'étape 4 mêle passerelle et Admin selon l'élément.

| Étape | Contenu | Pourquoi dans cet ordre |
|---|---|---|
| **0** | Porte d'entrée : acceptation TLS non bloquante, étiquettes bornées, réponse neutre | Trois petites corrections, gain immédiat, aucune dépendance |
| **1** | Index des bans, défi gradué, visibilité des rejets | Vitesse sous attaque, réponse proportionnée, et voir avant d'agir |
| **2** | Leurres, signal « hôte inconnu », Seuils | Signaux à faible risque d'erreur, puis le remplacement du moteur natif |
| **3** | Référence saisonnière du trafic | La pièce la plus riche et la plus longue à régler ; elle s'appuie sur 1 et 2 |
| **4** | Selon le type de sites : Seuils par compte, énumération, réputation d'empreintes, surveillance des domaines | Indépendantes, à engager selon les besoins (connexions, API…) |

### Étape 0 — Porte d'entrée

**0.a Acceptation TLS non bloquante.** La lecture du ClientHello sort de la boucle d'acceptation : une goroutine par connexion, qui remet la connexion prête à `Accept` par un canal. Échéance courte (2 à 3 s, à mesurer : les clients mobiles lents sont légitimes), plafond de lectures simultanées au-delà duquel la connexion est fermée et comptée. Critère : un test qui ouvre une connexion muette puis mesure le délai d'une seconde connexion, échoue avant le correctif et passe après.

**0.b Étiquettes bornées.** Une valeur fournie par le client (SNI, `Host`) ne devient jamais une étiquette de métrique telle quelle : elle est ramenée au nom du certificat ou de la route qui l'a servie (`*.example.fr`), ou à `autre` au-delà d'un plafond. Critère : un test qui présente 10 000 sous-domaines distincts d'un wildcard et vérifie que le nombre de séries reste borné. Même vérification pour toute métrique par hôte.

**0.c Réponse neutre pour un hôte inconnu.** Réglage par passerelle `unknown_host_action` : `neutral` (404 vide, sans marque ni en-tête distinctif) ou `close` (fermeture sans réponse, la plus économe, reconnaissable mais sans rien révéler). Jamais la page à la marque du produit pour une requête qui n'atteint aucune route ; les pages d'erreur personnalisées d'une route sont inchangées. Défaut proposé : `neutral`, parce que des sondes de répartiteur de charge peuvent attendre une réponse HTTP (voir question 9). Fermer la connexion ne fait pas passer l'IP pour inutilisée : le port reste ouvert, et les noms de domaine sont de toute façon connus par le DNS et les journaux de transparence des certificats. L'apport est de ne rien révéler du produit et de moins travailler.

**Livré (Edge 0.132.0).**

- **0.a** : le test de la connexion muette échouait sur l'ancien code (plus de 2 s pour accepter une seconde connexion), il passe. Lecture du ClientHello hors de la boucle d'acceptation (`internal/edge/sni_listener.go`, même schéma que l'écoute du protocole PROXY), échéance **3 s**, plafonds **2 048** lectures au total et **32 par source** (une IPv6 par /64). Le compteur `gpx_tls_rejected_total{reason}` est introduit dès maintenant avec les raisons `timeout`, `too_many_pending` et `other` ; la liste complète des raisons a été livrée à l'étape 1.c (`other` n'est plus émise).
- **0.b** : l'étiquette TLS est le nom du certificat qui sert (`CertStore.NameFor`, qui partage sa résolution avec `GetCertificate`) ou `autre` ; chaque connexion retient l'étiquette sous laquelle elle a été comptée. **Écart avec le texte initial** : le problème n'était pas limité au TLS. Les métriques HTTP (requêtes, pipeline de contrôles, authentification, WAF) prenaient aussi `Host` tel quel ; le dispatch fixe maintenant l'étiquette une fois la route trouvée (`Table.LabelHost`, `metrics.WithHost`, lue par `metrics.HostOf`). Non traité : `gpx_ratelimit_tokens_current{host,ip}` porte une série par client.
- **0.c** : `network.unknown_host_action` (`neutral` par défaut, `close`), réglage de fichier sans Admin (comme `proxy_protocol`). Défaut conservé à `neutral` (question 9 toujours ouverte).
- Les valeurs de 0.a restent à ajuster à la mesure (question 10) ; rien n'a été éprouvé sous charge réelle.

### Étape 1 — Vitesse, réponse graduée, visibilité

**1.a Index des bans** *(sans changement de comportement)*. Faire que le coût de la vérification d'un ban ne dépende plus du nombre de bans.

- **IP exactes** : table indexée par adresse (`netip.Addr`), en O(1).
- **Réseaux (CIDR, /64)** : une table par longueur de masque, interrogée du plus long au plus court (au plus 33 recherches en IPv4, 129 en IPv6, quel que soit le nombre de bans) ; un arbre de préfixes si la mesure le justifie.
- **Expiration hors du chemin de requête** : l'horodatage n'est vérifié que sur l'entrée trouvée, et un balayage périodique purge les bans expirés.
- **Profils IP** (`allow` prime sur `deny`, comportement conservé) : même structure.
- **Une seule analyse de l'adresse** par requête, partagée avec les étapes suivantes.
- **Critère** : un test d'équivalence qui rejoue les mêmes séries d'adresses contre l'ancienne et la nouvelle implémentation (mêmes verdicts, y compris expirés, privés, IPv6 et plages), et un benchmark à 10 000 puis 100 000 bans.

**Livré (Edge 0.133.0).** `internal/edge/router/prefix_index.go` (table par longueur de masque, entrées ordonnées par leur rang dans la liste reçue, index remplacé d'un bloc et lu sans verrou). Test d'équivalence : 3 000 bans et 40 000 adresses contre l'ancienne recherche linéaire gardée comme référence, mêmes verdicts et mêmes raisons ; idem pour les profils IP. Benchmark (Windows 386, bruité) : de 1 000 à 100 000 bans, ~1 à 1,5 µs avec l'index contre 2,3 µs, 12 µs puis 120 µs. **Écart** : pas de balayage périodique des bans expirés (écartés à la lecture, retirés au `Replace` suivant). Le dispatch lit l'adresse une fois (`ParseClientAddr`).

**1.b Défi à preuve de travail comme réponse graduée.** Une nouvelle action d'Ephor, `challenge`, entre le seuil de la note commune qui déclenche le défi et le seuil de ban : l'IP reçoit le défi existant au lieu d'un refus. La preuve est le cookie déjà prévu (lié à l'IP et au User-Agent, durée `challenge_ttl`). Moins de bans injustes (NAT, CGNAT), pas de nouveau mécanisme. Limites à respecter :

- **Seules les requêtes de navigation (GET) peuvent porter un défi.** Les requêtes non-GET sans preuve reçoivent un 403 (comportement existant) et les chemins de `challenge_exempt_paths` (API, webhooks) ne sont jamais défiés : pour eux l'action retombe sur le comportement actuel (limitation ou ban).
- Une **configuration de défi par défaut** de la passerelle (difficulté, durée) sert les routes qui n'ont pas la leur ; sans elle, l'action est sans effet.
- Les clients qui ne savent pas exécuter un défi (supervision, API) passent par la liste blanche ou les chemins exemptés.
- Naît en `detect` (le défi qui aurait été imposé est compté, pas servi). `challenge_secret` partagé dans un groupe HA pour que la preuve vaille sur tous les membres.

**Livré (Edge 0.134.0, Admin 0.227.0).** Réglages `challenge.*` d'Ephor (mode `off` par défaut, ce qui écarte l'idée d'un `detect` d'office ; seuil par défaut = moitié du seuil de ban ; difficulté, durée, chemins exemptés, secret). `threat.Engine.ChallengeDue` compare la note commune au seuil (bonus de confiance compris) ; `middleware.GatewayChallenge` enveloppe le défi existant avec son cookie `_gpx_ephor` et son URL `/.gpx/ephor-challenge` ; le dispatch le sert une fois la route trouvée. **Précisions par rapport au texte initial** : la page n'est servie qu'à une navigation (`GET`/`HEAD` avec `Accept: text/html` ou `Sec-Fetch-Mode: navigate`), donc un robot qui n'annonce pas de HTML reste sur la voie du ban ; une route qui défie déjà ses visiteurs ne l'est pas deux fois ; résoudre le défi n'efface pas la note. La configuration est refusée sans `ip_score.enabled` ou avec un seuil au niveau du ban. **Hors du texte** : l'interface d'Ephor reconstruisait toute la configuration à l'enregistrement, la section « Défi avant le ban » y a donc été ajoutée sans quoi le réglage aurait été effacé. Le défi gradué n'est pas encore utilisé par les Seuils ni par la référence saisonnière (étapes 2 et 3).

**1.c Visibilité des rejets.**

- Compteur `gpx_tls_rejected_total{raison}` à raisons **bornées** : `no_sni`, `unknown_sni`, `ip_literal`, `bad_clienthello`, `timeout`, `too_many_pending`, `other`. Compteur équivalent pour l'hôte inconnu en HTTP, sans étiquette d'hôte.
- Log échantillonné (limiteur existant) : IP, empreinte JA4, SNI tronqué (64 caractères au plus) et assaini.
- Un classement borné des noms demandés (structure à mémoire fixe), en mémoire seulement : c'est de la visibilité, pas du service, donc non persistée.
- Panneau « Trafic direct » dans Prism (IP, ASN, JA4, noms essayés), API, CLI, MCP. Un nom inconnu demandé par beaucoup d'IP distinctes est signalé comme un proxy probablement oublié, pas comme un scanner.

**Livré, partie passerelle (Edge 0.135.0).** `gpx_tls_rejected_total{reason}` porte désormais `timeout`, `too_many_pending`, `bad_clienthello`, `not_tls`, `no_sni`, `ip_literal`, `unknown_sni` et `handshake_failed` (la raison `other` disparaît) ; `gpx_edge_unknown_host_total` compte l'hôte inconnu en HTTP. Journal : une ligne par raison et par fenêtre de 5 s. Classement en mémoire à taille fixe (`internal/edge/rejections.go` : 256 noms avec le nombre d'IP distinctes plafonné à 64, 256 IP, 128 empreintes, éviction d'une entrée parmi 16 examinées, donc ordre approché), vidé à l'effacement RGPD d'une IP, servi par `GET /internal/v1/rejections`. **Écart** : le journal est limité par raison, non par IP, pour borner le volume de façon certaine sous un scan réparti. **Livré côté Admin (Admin 0.228.0)** : `GET /api/v1/security/rejections[?edge=]` (les passerelles sont interrogées par `prismedge.Source.Rejections`, comme l'inventaire), `goproxify security rejections`, l'outil MCP `get_entry_rejections` et l'onglet **Trafic direct** de Prism, libellés en quatre langues. Les types de la réponse vivent dans `internal/edge/logapi`, partagés entre la passerelle et l'Admin. **Écarts** : le panneau n'a pas de période (compteurs depuis le démarrage de chaque passerelle) ; il est un onglet de Prism plutôt qu'un panneau de la page d'accueil de Prism  ; l'onglet est dans le Prism commun, donc aussi dans celui du menu d'une passerelle seule (`edge-prism`), où il affiche « indisponible » tant que cette interface ne sert pas `/security/rejections` (non vérifié dans un navigateur). L'étape 1 est complète.

### Étape 2 — Signaux d'entrée et Seuils

**2.a Leurres.** Par proxy, une liste de chemins que l'application n'utilise jamais (`/.git/config`, `/backup.sql`…), avec un jeu par défaut. Tout accès est un signal `decoy` de forte valeur dans la note commune, avec très peu de risque de se tromper. Garde-fou : un leurre ne peut pas être un chemin du profil de surface appris (ADR-0016) ni de la politique OpenAPI du proxy ; s'il l'est, il est refusé avec le motif. `detect` d'abord. La génération d'entrées `Disallow` dans un `robots.txt` est une piste, hors première livraison.

**Livré (Edge 0.136.0, Admin 0.229.0).** Réglages `decoys.*` d'Ephor (`off` par défaut ; `detect`, `block` ; `paths`, `no_defaults`), signal `decoy` à 8 points, section « Leurres » du formulaire Ephor, `gpx_threat_decoy_total{result=hit|shadow|skipped}`. **Écarts par rapport au texte initial** : la liste est celle d'Ephor, pour toute la passerelle, et non par proxy (le garde-fou par route compense : un proxy qui sert le chemin n'est jamais piégé) ; le garde-fou consulte les locations déclarées et le profil de surface appris (`surface.Collector.Knows`), pas la politique OpenAPI du proxy, qui est elle-même générée de ce profil ; la génération d'un `robots.txt` reste une piste.

**2.b Signal `unknown_host`.** Les requêtes HTTP sur un hôte inconnu et les rejets TLS (étape 1.c) versent des points **modérés** à la note de l'IP. Un accès isolé ne prouve rien ; plusieurs d'affilée, ou des chemins de scan sur un hôte inconnu, mènent au ban par la note commune. **Jamais de ban au premier accès** : une page tierce peut faire envoyer à chaque navigateur de ses visiteurs une requête vers votre IP (`<img src="http://votre-IP/">`), ce qui ferait bannir vos propres visiteurs. Exemptions : sondes déclarées (liste d'IP/CIDR), réseaux privés, liste blanche. Une IP qui accède à intervalles réguliers (signal `regular_interval` existant) reçoit une **proposition d'exemption** plutôt qu'une escalade. Compteurs bornés comme ceux d'Ephor. `detect` d'abord, puis `block` après lecture de la simulation sur logs.

**Livré, 2.b (Edge 0.137.0, Admin 0.230.0).** Réglages `unknown_host.*` d'Ephor (`off` par défaut ; `detect`, `block` ; `points`, `probes`), `threat.Engine.NoteUnknownHost` appelé par le dispatch (hôte sans route) et par le listener TLS (rejets `no_sni`, `ip_literal`, `unknown_sni`, `not_tls`), points versés par le chemin du score cumulé (`scoreBan`). La configuration est refusée sans `ip_score.enabled` ou avec des points au niveau du seuil de ban. **Précisions** : Cloudflare et les réseaux privés sont exemptés (via `fail2ban.BanTarget`, à déplacer à l'étape 2.c) ; la « proposition d'exemption » est une détection de cadence propre au signal (six accès presque également espacés d'au moins 2 s), et non le signal `regular_interval` de l'ADR-0011, qui porte sur la note d'une IP et non sur ses accès à un hôte inconnu ; les sondes probables sont exposées dans `probes` de l'instantané des rejets et dans l'onglet Trafic direct, sans rien exempter d'office.

**2.c Le Fail2Ban natif devient les Seuils d'Ephor.** Le moteur natif est supprimé. Ce qu'il apportait en propre devient une fonction d'Ephor, sous un nom qui ne promet pas ce qu'il n'est pas : **Seuils** (Thresholds, Umbrales, Schwellen). Le nom « Fail2Ban » est réservé au vrai programme.

*Un Seuil* est une règle explicite « N événements en T secondes, ban » :

- un **filtre** sur des événements structurés (statut, chemin, méthode, route, catégorie WAF, signal d'Ephor) : pas de regex sur du texte, donc moins cher que Fail2Ban ;
- une **clé de comptage** (l'IP, ou le /64 d'une IPv6 ; compte, empreinte ou ASN à l'étape 4.a) ;
- une **fenêtre**, un **nombre**, une **durée de ban** avec escalade ;
- une **action** : bannir, imposer le défi (étape 1.b), ou verser des points à la note commune ;
- un **mode** `off | detect | block`, comme les signaux de l'ADR-0011.

*Jeu fourni* : `auth-fail` (401/403 sur les routes de connexion et le portail Access, que le score pondéré d'Ephor ignore), `waf-repeat` (détections WAF répétées), et un ban long après récidive. Rien pour les 4xx généraux : le signal `error4xx` d'Ephor les couvre déjà, et ne pas les compter deux fois est le but. L'administrateur peut ajouter ses propres Seuils, avec simulation sur logs avant activation.

*Intégration.*

- Un ban de Seuil est un ban d'Ephor : source `threat`, motif `threat: seuil <nom>`, signaux listés dans le ban (ADR-0011, étape 1), note commune alimentée. La clé technique reste `threat`, comme pour le renommage de Sentinel : le nom est un libellé.
- **Compteurs bornés et persistés** : table en shards avec plafond et éviction comme celle d'Ephor, sous-compteurs par fraction de fenêtre (quelques dizaines d'octets par IP, estimation) plutôt qu'une tranche d'horodatages, copie chiffrée avec `threat-state.gpx`.
- **Profil durci** : pendant une alerte de l'étape 3, les Seuils de la route passent à un profil plus strict.
- **Listes blanches, IPv6 et plages exemptées** (réseaux privés, Cloudflare) du moteur supprimé sont conservées. `BanTarget`, qu'utilisent les plugins (`plugin_guard.go`) pour viser les mêmes cibles, est déplacé avec elles.
- Les 403 servis à une IP déjà bannie ne comptent pas (comportement de `feedF2B`, à retrouver dans Ephor).

*Retrait et renommage.* Le paquet `internal/edge/fail2ban` disparaît, ainsi que sa configuration, son message WebSocket et son état. Tout ce qui nomme Fail2Ban est renommé : la source de ban `fail2ban`, le déclencheur d'alerte « nouveau ban Fail2Ban », la condition d'automatisation `engine_silent` (`engine_type`), l'API et `openapi.yaml`, la CLI, le MCP, la page Sécurité, les messages dans les quatre langues, la documentation, le README et la page d'accueil. Rien n'est déployé : on remplace, sans migration ni couche de compatibilité.

**Livré, 2.c première partie (Edge 0.138.0, Admin 0.231.0) : le moteur des Seuils.** `internal/edge/threat/thresholds.go` : un Seuil (filtre structuré sur la réponse rendue, `count` en `window`, action `ban` ou `score`, mode `off | detect | block`), deux Seuils fournis (`auth-fail`, `waf-repeat`) et jusqu'à 50 Seuils de l'administrateur, compteurs par IP à dix compteurs par clé (bornés, 64 × 4 096), conservés dans `threat-state.gpx`, effacés par l'ordre RGPD. Le ban est un ban d'Ephor (`threat: seuil <nom>`, signal `threshold:<nom>`). Section « Seuils » du formulaire Ephor. **Écarts par rapport au texte initial** : le jeu fourni se limite à `auth-fail` et `waf-repeat` (le ban long après récidive attend la question 3 : l'escalade d'Ephor existe déjà) ; l'action `challenge` n'existe pas en tant que telle, l'action `score` y mène par la note commune ; le filtre ne porte pas encore sur « un signal d'Ephor » ; la simulation sur logs ne rejoue pas encore les Seuils ; l'action `ban` vise l'adresse exacte (question 2). **Reste à faire pour clore 2.c** : retirer `internal/edge/fail2ban` et ce qui le nomme, déplacer `BanTarget`, renommer partout, et trancher la détection multi-passerelles de l'Admin (question 1).

**Livré, 2.c seconde partie (Edge 0.139.0, Admin 0.232.0) : retrait et renommage.** `internal/edge/fail2ban`, `f2b_config.go` et leurs tests sont supprimés ; `BanTarget` vit dans `internal/edge/bantarget`, avec les mêmes exemptions. Le mode strict des règles automatiques (`enable_strict`) appelle `threat.Engine.Harden`. Le moteur de l'Admin est conservé et renommé « Seuils multi-passerelles » (clé `fleet`, paquet `internal/admin/fleet`) : API, source de ban, déclencheur d'alerte, table, métriques, outils MCP, CLI, libellés en quatre langues, modèles de flux, documentation. Le signal `fail2ban` de la note commune disparaît. Aucune migration : le projet n'est pas déployé.

**Livré, 3.a (Edge 0.140.0, Admin 0.233.0) : apprendre, détecter, afficher.** `internal/edge/seasonal` (suivi sans verrou par route : compteurs atomiques, 32 compartiments de chemins, table de 8 192 bits pour les IP distinctes, tranche partagée pour une route sans requête ; référence de 168 + 48 créneaux × 2 pas × 4 métriques, moyenne et variance exponentielles, plafond de dérive, créneau fin puis grossier puis froid) et `threat/seasonal.go` (réglages `seasonal.*`, `off` | `detect` seulement). Écarts à ce qui était écrit : la mesure rapide compare le débit seul (les écarts de nature se jugent sur la minute) ; un écart de nature sans écart de volume n'alerte pas ; l'état persisté ne garde que les créneaux vus (octets, pas 16 Ko fixes) ; le profil d'entrée `(entrée)` est alimenté par les hôtes inconnus et les rejets TLS, les routes au-delà de 128 vont dans `(autres)`. Mesuré : 23,5 ns par requête sans allocation, 170 µs par tick pour 128 routes, environ 21 Ko de mémoire par route. Lecture par l'Admin : `GET /internal/v1/seasonal`, `GET /api/v1/security/traffic-reference`, carte « Références du trafic », CLI, MCP. **Reste** : la notification (événement d'Admin et flux d'automatisation), le profil durci de la route (défi à preuve de travail, seuils abaissés pour les IP sans historique), le plafond adaptatif à la place du `GlobalRPS` fixe, le mode `block`, la simulation sur logs avant de quitter `detect`.

**Livré, 3.b (Edge 0.141.0, Admin 0.234.0) : la notification.** Le message `traffic_deviation` porte toutes les alertes en cours de la passerelle (envoyé à chaque changement d'état et chaque minute tant qu'il y en a, liste vide à la fin) : l'Admin alerte une fois par route et par début, de nouveau à l'aggravation, sans rejouer d'événements perdus pendant une coupure (même modèle que les suggestions de surface). Déclencheur d'alerte `traffic_deviation`, donc utilisable aussi comme événement par les flux d'automatisation. Aucune décision n'est prise par l'Admin. **Reste** : le profil durci de la route, le plafond adaptatif, le mode `block`, la simulation sur logs.

**Livré, 3.c (Edge 0.142.0, Admin 0.235.0) : le profil durci et le plafond adaptatif, mode `block`.** Une alerte *probable* (jamais un simple avertissement) pose un profil durci sur la route (`seasonal.Hard`), lu sans verrou par le dispatch après le défi gradué : les IP sans historique propre (`trustBonus` nul) qui naviguent reçoivent le défi à preuve de travail ; toutes les IP sans historique se partagent un seau de jetons de `cap_factor` × la moyenne apprise du créneau (plancher `floor_rps`, rafale de deux secondes), au-delà duquel la réponse est un 503. Habitués, liste blanche d'Ephor et autres routes passent. Le volume écarté est versé au suivi (sinon l'attaque disparaîtrait des mesures et la route serait relâchée en pleine attaque). Le profil tombe avec l'alerte. Le mode `block` demande un défi actif (il en tire le secret et la difficulté). **Écarts à ce qui était écrit** : pas de seuils abaissés ni de tarpit pendant l'alerte (le défi et le plafond suffisent pour une première version) ; le plafond s'applique à l'ensemble des IP sans historique d'une route, non au `GlobalRPS` de la passerelle, qui reste fixe et en tête. **Reste** : la simulation de la référence saisonnière sur logs avant de quitter `detect` (rejouer les accès par tranches de dix secondes), et la mesure en production des valeurs initiales (question 4).

**Livré, 3.d (Edge 0.143.0, Admin 0.236.0) : la simulation sur logs, qui clôt l'étape 3.** `threat.Simulate` rejoue le suivi du trafic sur l'horloge des événements (un tick de dix secondes par tranche, vides comprises) et rend `seasonal` : par route, jugeable ou froide, avertissements, probables, durée, et en `block` l'exposition du profil durci (requêtes d'IP sans historique pendant que la route est durcie, dont celles qui avaient abouti). La fenêtre passe à 168 h dès qu'une des deux configurations rejoue la référence saisonnière. Limites : une passerelle rejoue au plus 200 000 accès (les plus récents), une route peut donc rester froide sur un site très chargé ; le rejeu ne distingue pas un visiteur légitime d'un attaquant qui a obtenu un 200 ; les IP de confiance (sept jours d'historique propre) ne sont pas connues d'un rejeu court, l'exposition est donc une borne haute. Les valeurs initiales (question 4) restent à calibrer sur des logs réels avec cet outil.

**Livré, 4.a (Edge 0.144.0, Admin 0.237.0) : les Seuils à clé de compte, d'empreinte ou d'opérateur.** `ThresholdRule.By` (`ip` | `account` | `ja4` | `asn`), action `protect` seule admise hors IP (`protect_for`, `limit`), `thresholds.logins` pour les routes dont le corps est lu. Le corps (POST, 8 Ko au plus, JSON ou formulaire) est lu avant la route puis rendu intact ; l'identifiant n'existe qu'en empreinte HMAC (clé propre au processus). Une clé protégée soumet les IP sans historique au défi (navigation) ou à `limit` tentatives par minute (429) ; jamais de ban ni de verrouillage. Compteurs et protections en mémoire seulement, donc rien à effacer par l'ordre d'effacement RGPD et rien de restauré au redémarrage. **Écarts à ce qui était écrit** : (1) l'« historique avec ce compte » est approché par la confiance de l'IP auprès de la passerelle ; (2) une clé `ja4` n'est jamais une pile de navigateur connue ; (3) les protections ne sont visibles que dans le journal et les métriques, pas dans l'Admin ; (4) la simulation sur logs ne rejoue pas ces Seuils (les logs n'ont pas le corps). **Reste de l'étape 4** : 4.b énumération, 4.c réputation d'empreinte TLS, 4.d surveillance des domaines.

**Livré, 4.b (Edge 0.145.0, Admin 0.238.0) : la détection d'énumération.** `threat/enumeration.go` : par clé « IP | route | gabarit », une table de 1 024 bits compte les valeurs d'identifiant distinctes (`surface.EnumShape` : entier, UUID, empreinte, jeton, courrier), sans en conserver aucune. Le dépassement du seuil (le plus grand du plancher et de la norme apprise du gabarit) n'est retenu que si `surface.Collector.Knows` connaît le gabarit et `Converged` dit le profil convergé, vérifié au seul moment du dépassement (le clonage du profil coûte). `detect` d'abord ; en `block` des points vont à la note commune (signal `enumeration`), jamais un ban à lui seul avec le seuil par défaut. **Écarts à ce qui était écrit** : la norme n'est pas tirée de la table des gabarits du profil mais des fenêtres closes des autres IP (plus directe : « combien de valeurs un client ordinaire parcourt-il en dix minutes »), avec un pas borné par fenêtre contre l'empoisonnement ; tant qu'elle n'est pas établie (vingt fenêtres) une mesure est plafonnée à deux fois le plancher, d'où la consigne de démarrer en `detect` sur une période ordinaire. La simulation sur logs ne le rejoue pas. **Reste de l'étape 4** : 4.c réputation d'empreinte TLS, 4.d surveillance des domaines.

**Livré, 4.c (Edge 0.146.0, Admin 0.239.0) : la réputation des empreintes TLS.** `threat/tlsrep.go` : par JA4, compteurs de requêtes, de requêtes marquées par le WAF, en erreur, et une table de 2 048 bits pour les IP distinctes ; piles de navigateurs connues (`Store.IsBrowserJA4`) comptées pour mémoire seulement. Une proposition exige `min_ips`, `min_requests`, une part mauvaise d'au moins `min_bad_share` **et** au moins un dixième marqué par le WAF (garde-fou ajouté : sans lui, une application cassée dont beaucoup de clients appellent un chemin périmé serait proposée). Admin : `GET /api/v1/security/tls-reputation`, `POST …/accept` (seules les propositions actuelles, 409 sinon ; configuration d'Ephor existante exigée ; le reste de la configuration est conservé), CLI `security tls-reputation [accept]`, outil MCP de lecture `get_tls_reputation`, carte et réglages dans le formulaire Ephor. **Écarts à ce qui était écrit** : l'acceptation n'a pas d'outil MCP (un geste d'administrateur, API ou CLI) ; les compteurs persistés ne portent que le nombre d'IP (la table de bits hachée avec une graine de processus ne se relit pas), restitué approximativement au redémarrage ; JA4 seulement, pas JA3 ; ni QUIC ni HTTP clair n'ont d'empreinte. La simulation sur logs ne le rejoue pas. **Reste de l'étape 4** : 4.d surveillance des domaines.

**Livré, 4.d (Admin 0.240.0) : la surveillance des domaines, qui clôt l'étape 4.** Paquet `internal/admin/domainwatch`, dans l'Admin seul. Opt-in à deux niveaux (interrupteur général, puis `ct`, `caa`, `dangling` un à un), requêtes espacées, 200 domaines et une analyse manuelle toutes les cinq minutes au plus. `ct` : client HTTP de style crt.sh (https obligatoire, `ssrf.ValidateHTTPURL`, redirections refusées) ; les numéros de série des certificats de la table `certs` sont enregistrés à chaque analyse dans la table `domain_watch`, si bien qu'un certificat renouvelé reste reconnu comme le sien ; la première analyse d'un domaine pose une référence (`baseline`) sans alerter, seul un certificat qui apparaît ensuite alerte. `caa` et `dangling` : client DNS `miekg/dns` (désormais dépendance directe), résolveur du système ou `resolver`. Déclencheur d'alerte `domain_watch`. **Écarts à ce qui était écrit** : le journal de transparence ne dit pas qui a demandé un certificat, l'indice est l'émetteur et l'absence dans la base de GoProxify (d'où `trusted_issuers`) ; la détection de sous-domaine pendant repose sur un CNAME qui mène à NXDOMAIN, pas sur la comparaison avec les adresses des passerelles ; pas de remontée du CAA au-delà des deux derniers libellés (pas de liste des suffixes publics) ; les constats ne sont pas purgés. **Reste de l'ADR** : le calibrage des valeurs initiales sur de vrais logs (questions 4 à 6), la question 3 (récidive) et les éventualités, non engagées.

### Étape 3 — Référence saisonnière du trafic

Apprendre le **comportement agrégé** d'une route et alerter quand il s'écarte de ce qu'il est d'habitude à cette heure de cette journée. Elle s'ajoute à la référence par IP de l'ADR-0011 sans la remplacer : l'une dit qu'*une IP* s'écarte, l'autre que *le trafic* s'écarte.

**Ce qu'on apprend.**

- **Par route**, et un profil global de la passerelle pour le trafic qu'aucune route ne retient (noms d'hôte aléatoires). Le taux de rejets TLS et d'hôtes inconnus de l'étape 1.c y est une métrique : une vague de scans ou une inondation de sous-domaines aléatoires y apparaît comme un écart.
- **168 créneaux** (jour de la semaine × heure, UTC) : ils portent à eux seuls l'heure, le jour et la semaine. Tant qu'un créneau n'a pas assez d'échantillons, on se replie sur 48 (semaine ou week-end × heure) ; avant, le signal est *froid* et ne compte jamais. Pas de créneau mensuel : il demanderait un an d'historique pour un gain faible. La dérive lente (croissance du site) est absorbée par une moyenne glissante exponentielle sur plusieurs semaines.
- **Métriques par créneau** : requêtes, IP distinctes (compteur approché, sans table par IP), part de 4xx/5xx, part du chemin le plus demandé. Pour chacune, moyenne et variance à **deux pas** : 10 secondes et 1 minute.

**Comment on détecte.** Une référence horaire, mais une mesure rapide : attendre la fin de l'heure pour comparer donnerait une alerte quand l'attaque est finie. Deux fenêtres, sur le modèle des alertes multi-fenêtres :

| Fenêtre | Cherche | Condition |
|---|---|---|
| **Rapide**, 5 à 10 s | un écart énorme | bien au-dessus de la moyenne du créneau (de l'ordre de dix fois) **et** d'un plancher absolu |
| **Lente**, 1 à 5 min | une montée plus modeste | moyenne + k écarts-types, avec le même plancher |

Les valeurs ci-dessus sont des points de départ à calibrer sur des logs réels, pas des constantes figées. Un plancher absolu évite le bruit sur les sites à faible trafic.

**Un volume seul n'est pas une attaque** (newsletter, promotion, événement). L'écart de volume donne un avertissement. Il devient « attaque probable » quand il s'accompagne d'au moins un écart de **nature** : explosion des IP distinctes jamais vues, hausse des 4xx/5xx, concentration sur un seul chemin.

**Ce qu'on en fait.** Tout naît en `detect` (note fantôme, comme l'ADR-0011), puis passe en `block` après lecture de la simulation sur logs.

1. Un événement et une notification (Admin, flux d'automatisation).
2. Un **profil durci pour la route** pendant l'alerte : les IP **sans historique propre** (celles qui n'ont pas le bonus de confiance de 7 jours) sont soumises à des seuils abaissés, au **défi à preuve de travail** (étape 1.b) et au tarpit ; les habitués passent. Retour automatique à la normale à la fin de l'alerte (avec hystérésis).
3. Un **plafond adaptatif** à la place du `GlobalRPS` fixe : un multiple de la valeur apprise du créneau, appliqué par le token bucket existant, d'abord aux seules IP sans historique propre.

La détection ne peut pas empêcher les premières secondes d'une attaque : ce qui borne les dégâts, c'est le délestage immédiat déjà présent (token bucket global, taux par IP, tarpit). La référence les **pilote** ; elle ne les remplace pas. Refuser une requête coûte quelques microsecondes, la proxifier jusqu'au backend coûte bien plus : le risque pendant ces secondes est souvent pour le backend avant la passerelle. Une saturation du lien (L3/L4) est hors d'atteinte d'un proxy et demande une protection en amont.

**Garde-fous.**

- **Empoisonnement** : l'apprentissage d'un créneau est gelé tant qu'une alerte y est active ; la dérive de la référence est plafonnée par période (comme l'étape 4 de l'ADR-0011), pour qu'un attaquant qui monte lentement n'enseigne pas un « normal » trop haut.
- **Démarrage à froid** : un créneau sans assez d'observations (durée et volume affichés) reste en `detect` quel que soit son mode.
- **Sécurité par défaut** : une référence absente, illisible ou périmée ne bloque jamais plus.

**Où et combien.**

- **Passerelle**, à côté de `references.go`, dans le magasin comportemental : horloge injectable, copie locale chiffrée relue au démarrage (ADR-0006). Chaque membre d'un groupe HA apprend son propre trafic ; rien n'est synchronisé au départ.
- **Admin** : affichage seul (courbe réelle contre bande attendue), notification, CLI et MCP. Aucune décision n'y est prise.
- **Coût estimé** (à mesurer, non mesuré) : 168 créneaux × 4 métriques × 2 pas × ~12 octets ≈ 16 Ko par route, quelques dizaines de Ko chiffrés sur disque ; par requête, un incrément atomique et la mise à jour du compteur d'IP distinctes (moins que `references.observe`, qui prend un mutex et une table par IP) ; par seconde, un tick par route. Aucun état par IP ajouté.

### Étape 4 — Selon le type de sites

Éléments indépendants, dans l'ordre où je les engagerais ; chacun se justifie par un usage précis.

**4.a Seuils à clé de compte, d'empreinte ou d'opérateur** *(sites avec connexion)*. Les attaques par bourrage d'identifiants changent d'IP mais visent les mêmes comptes. La clé de comptage d'un Seuil peut être l'**identifiant de connexion** (empreinte HMAC avec une clé locale, jamais stocké en clair, durée courte, effacé par l'ordre d'effacement RGPD), l'**empreinte JA4** ou l'**ASN**. La lecture du corps est limitée aux routes de connexion déclarées, et bornée en taille. **Aucun verrouillage du compte** : bloquer un compte par ses échecs permettrait à un attaquant de verrouiller la victime. L'action est de soumettre les tentatives sur ce compte, depuis les IP sans historique avec lui, au défi ou à la limitation.

**4.b Détection d'énumération** *(API)*. Une IP qui parcourt de nombreuses valeurs distinctes d'un même gabarit de chemin du profil de surface (`/api/users/{int}`) : c'est le premier risque des API, que les règles CRS ne voient pas. Par IP et par gabarit, un compteur approché de valeurs distinctes (aucune valeur stockée, ce qui respecte l'ADR-0016) ; signal `enumeration` en `detect`, seulement sur les routes dont le profil a convergé, avec un seuil relatif à la norme apprise pour ce gabarit.

**4.c Réputation d'empreinte TLS apprise.** Par JA4 : nombre d'IP distinctes (approché) et part de requêtes marquées par le WAF ou en erreur. Une empreinte partagée par beaucoup d'IP à taux anormal est **proposée** pour `custom_lists.tls_fingerprints`, avec ses preuves, comme les propositions de l'ADR-0016. Jamais de blocage automatique ; les familles de la table des navigateurs connus (ADR-0011) sont exclues.

**4.d Surveillance des domaines** *(côté Admin, indépendante du trafic)*. Alerter (système d'alertes existant) si un certificat est émis pour un domaine déclaré hors de GoProxify (journaux de transparence des certificats), si les enregistrements CAA sont absents ou trop larges, ou si un sous-domaine pointe vers une cible qui n'existe plus (risque de détournement). Ces vérifications envoient les noms de domaine à des services externes : **opt-in**, et à débit limité.

### Éventualités (non engagées)

Éléments décrits pour mémoire : aucune décision de les réaliser n'est prise, et aucune étape ne dépend d'eux. À reconsidérer si le besoin apparaît.

**Visibilité amont, en lecture seule.** Montrer ce qu'un Fail2Ban installé sur l'hôte a déjà banni, sans que GoProxify le pilote ni en dépende.

- **Sources** : la base SQLite de Fail2Ban (`fail2ban.sqlite3`), ouverte en lecture seule (jail, IP, date, durée, récidives, historique compris), ou `fail2ban-client status` pour l'état courant. Le pare-feu lui-même (`nft`, `ipset`) reflèterait ce qui est réellement appliqué, quelle qu'en soit l'origine ; c'est une piste, pas une décision.
- **Collecteur** : l'**Agent**, qui vit sur l'hôte (ADR-0006 : si l'Agent tombe, seule cette visibilité s'arrête). La passerelle lit elle-même si elle tourne comme binaire sur l'hôte ; en conteneur, la base est montée en lecture seule. Lecture toutes les 30 à 60 secondes d'une petite table.
- **Affichage** : une source « Fail2Ban (hôte) » dans la page Bans, en lecture seule et marquée comme appliquée par le pare-feu de l'hôte ; le traçage d'IP indique qu'une IP a été bannie en amont, avec son jail. Éventuellement, un signal en `detect` dans la note d'Ephor pour une IP bannie par un autre service de l'hôte qui frappe quand même la passerelle (une IP qui force SSH n'est pas forcément malveillante en HTTP, d'où le `detect`).
- **Aucun import dans le `BanStore`** : cela obligerait à synchroniser les expirations et les débans dans les deux sens.
- **Garde-fou d'affichage** : un ban posé dans `INPUT` ne filtre pas le trafic des ports publiés par Docker (chaîne `FORWARD`). Le panneau doit dire que les bans visibles peuvent n'avoir aucun effet sur le trafic de la passerelle.
- **Données** : ce sont des IP, donc des données personnelles : mêmes durées de conservation que la page Bans, et même ordre d'effacement RGPD.

---

## Règles

- **Autonomie (ADR-0006)** : acceptation, index, défi, leurres, Seuils et références tournent sur la passerelle seule, y compris après un redémarrage pendant une coupure de l'Admin ; l'état appris est chiffré localement. L'étape 4.d (domaines) a sa propre dépendance, qui ne touche pas le trafic.
- **Tout nouveau signal naît en `detect`**, avec note fantôme et simulation sur logs avant `block` (ADR-0011).
- **Aucune valeur fournie par le client** (SNI, `Host`, identifiant, chemin) n'est stockée ni journalisée sans être tronquée et assainie, et ne devient jamais une étiquette de métrique sans passer par la table des noms configurés.
- **Mémoire bornée, O(1) par requête**, avec plafond et éviction. Chaque étape livre un benchmark ; aucun chiffre de coût de cet ADR n'est mesuré à ce jour.
- **Faux positifs** : pics légitimes (campagne, promotion), NAT d'entreprise et CGNAT, sondes de supervision, visiteurs qui atteignent l'IP par une page tierce. D'où la combinaison de métriques à l'étape 3, la réponse graduée (défi avant ban), les exemptions, et l'absence de ban au premier accès.
- **Explicabilité** : une décision de l'étape 1.b, 2 ou 3 doit dire quel signal, quel Seuil ou quelle référence, avec la valeur observée contre la valeur attendue.

---

## Conséquences

- La porte d'entrée cesse d'être bloquable par une connexion muette et de gonfler en mémoire sous des noms inventés ; elle ne révèle plus le produit.
- Le coût par requête cesse de croître avec le nombre de bans, préalable à tout ce qui ajoute des bans.
- Ephor gagne une réponse graduée (le défi) et voit enfin le trafic agrégé d'une route, ce que ni la référence par IP ni l'Admin ne faisaient sur la passerelle.
- Un seul moteur compte les erreurs par IP : la double comptabilité Fail2Ban / Ephor disparaît, ainsi que le défaut d'expiration et la table non bornée.
- Un changement de nom touche une quarantaine de fichiers (code, traductions, documentation) ; il est fait d'un coup, sans migration.
- L'étape 3 introduit un état dépendant du temps : les tests rejouent des séries temporelles avec l'horloge injectable.

---

## Hors périmètre

- **Piloter le vrai Fail2Ban depuis la passerelle**, ou le lire par son socket. Il lit des fichiers texte, or la passerelle n'en écrit plus (ADR-0012) ; il faudrait une sortie de log texte optionnelle avec l'IP réelle (incompatible par nature avec l'anonymisation RGPD), un filtre et une action livrés et testés, et une pièce mobile de plus à exploiter, Linux seulement. Son socket n'est pas en lecture seule : il permet aussi de débannir et de redéfinir des actions exécutées avec les droits de Fail2Ban (en général root), et son protocole est propre à Python. Un Fail2Ban installé sur l'hôte protège très bien les services de l'hôte (SSH, messagerie, applications) sans aucune interaction avec GoProxify ; la documentation (`docs/security.md`) le dira.
- **Bannir au premier accès par l'IP**, ou à la première requête sur un hôte inconnu (voir 2.b).
- **Importer les bans amont** dans le `BanStore` de la passerelle (voir « Éventualités » : lecture seule d'abord).
- **Un « pare-feu amont » généralisé** : compteurs `nftables`, décisions du bouncer pare-feu de CrowdSec, règles Cloudflare.
- **Patch virtuel du WAF à partir de l'inventaire des applications et des CVE** : l'ADR-0017 l'écarte explicitement.
- **Saisonnalité mensuelle ou annuelle**, et **synchronisation des références entre membres d'un groupe HA**.
- **Protection contre la saturation du lien (L3/L4).**

---

## Questions ouvertes

1. ~~Détection de l'Admin sur plusieurs passerelles~~ — **tranché (étape 2.c)** : gardée, renommée « Seuils multi-passerelles » (clé `fleet`).
2. ~~Ban au /64~~ — **tranché (étape 2.c)** : les Seuils bannissent l'adresse exacte, comme le reste d'Ephor ; le compteur reste agrégé au /64.
3. **Récidive.** Ephor a déjà des bans graduels (`priorBans`, durée escaladée). Le ban long après récidive des Seuils fait-il doublon ? À trancher en regardant l'escalade existante.
4. **Valeurs initiales de l'étape 3** (multiple de la fenêtre rapide, nombre d'écarts-types, plancher, durée de l'hystérésis, multiple du plafond adaptatif) : à calibrer sur les logs réels, par rejeu.
5. **Pas de 10 secondes** : le bruit statistique d'une fenêtre aussi courte et le surcoût du double jeu de statistiques sont à mesurer avant de figer ce pas.
6. **Périmètre de la première livraison de l'étape 3** : volume et IP distinctes seulement, les autres métriques ensuite ?
7. **Noms** : « Seuils » et ses traductions à confirmer ; aucune vérification de marque faite (mot courant).
8. ~~Écarts entre `error4xx` et l'ancien jail~~ — **vérifié (étape 2.c)** : 403 servis par un ban non comptés, listes blanches et plages exemptées conservées, ban sur l'adresse exacte.
9. **Défaut de `unknown_host_action`.** `neutral` ou `close` ? Une fermeture sans réponse peut faire déclarer en panne un répartiteur de charge qui attend un statut HTTP.
10. **Valeurs de l'étape 0.a** : échéance du ClientHello (2 à 3 s proposées) et plafond de lectures simultanées, à mesurer pour ne pas pénaliser les clients lents légitimes. L'alerte TLS envoyée quand le certificat manque (`internal_error` côté Go, là où d'autres serveurs envoient `unrecognized_name`) trahit peut-être une pile Go : à vérifier, secondaire.
11. **Défi gradué (1.b)** : quelles routes peuvent le porter, durée de la preuve, comportement exact pour les clients non navigateurs.
12. **Leurres (2.a)** : jeu par défaut, et traitement d'une application qui utiliserait vraiment l'un de ces chemins ; génération du `robots.txt`.
13. **Seuils par compte (4.a)** : durée de conservation des empreintes d'identifiants (une empreinte d'identifiant reste une donnée personnelle pseudonymisée) et liste des routes de connexion.
14. **Surveillance des domaines (4.d)** : source des journaux de transparence et envoi des noms de domaine à un tiers (opt-in).
