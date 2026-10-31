# ADR 0019 — Le launcher : un seul composant de bootstrap pour tous les hôtes

**Statut :** accepté, étapes 1 à 9 mises en œuvre (Agent 0.19.1 à 0.27.0, Admin 0.221.0 à 0.226.0), voir « Ordre de mise en œuvre » pour ce qui reste ouvert · **Date :** 2026-10-30
**S'appuie sur :** ADR-0001 (binaire unifié), ADR-0006 (autonomie des composants), ADR-0014 (groupe HA), ADR-0015 (enrôlement et clés) · **Complète :** les tickets d'intégration existants (`bootstrap_tickets`, QR et `curl | bash`)

---

## Contexte

Monter une infrastructure GoProxify sur plusieurs hôtes demande aujourd'hui de passer par plusieurs mécanismes :

- `scripts/quickstart.sh` (Docker, un hôte : Admin, passerelle et Agent) et `setup.sh` (systemd, natif) ;
- le wizard d'architecture de l'Admin, qui édite `architecture.json` et génère pour chaque hôte un `compose_text` et un `env_text` ;
- les tickets d'intégration (`POST /api/v1/bootstrap-tickets`, `GET /i/{token}` et `/i/{token}.sh`) : un QR ou une ligne `curl | bash` qui écrit un `docker-compose.yml` et un `.env`, puis lance `docker compose up -d`. Ils valent 24 h par défaut (168 h au plus) et sont consommés quand le nœud arrive (ADR-0015, étape 3).

L'Admin doit donc exister avant tout autre hôte, et le premier hôte s'installe à la main. Quatre constats sur l'existant motivent cet ADR (lecture du code, sans essai d'exploitation).

1. **Le premier hôte n'a pas de chemin guidé depuis rien.** Le wizard vit dans l'Admin, qui n'existe pas encore.
2. **L'Admin sert en HTTP clair par défaut.** TLS n'est actif que si `GPX_ADMIN_TLS_CERT` et `GPX_ADMIN_TLS_KEY` sont posés, sinon l'Admin journalise qu'il faut une terminaison TLS devant. Un ticket qui transporte un jeton vers l'Admin n'a donc, par défaut, aucune garantie d'authenticité ni de confidentialité.
3. **Le moteur de recréation de conteneurs de l'Agent est incomplet.** `RecreateContainer` (`internal/agent/docker/lifecycle.go`) recrée un conteneur avec son image, ses labels et sa politique de redémarrage seulement : `ContainerCreateBody` ne porte ni ports, ni variables, ni réseaux, ni volumes réels. Il ne sait pas recréer un Admin ou une passerelle.
4. **La documentation promet un socket Docker « en lecture seule »** (README, `docs/architecture.md`, `docs/deployment.md`, `docs/fonctionnalites.md`, landing, exemples compose en `:ro`), alors que l'Agent crée, arrête et supprime des conteneurs (`autoscale.go`, `lifecycle.go`). Sur un socket Unix, `:ro` n'empêche rien : l'accès au socket équivaut à root sur l'hôte.

---

## Décision

### 1. Un seul composant, quel que soit l'hôte

Une image `ghcr.io/vincamok/goproxify/launcher`, qui est une sous-commande du binaire unifié (`goproxify launcher`). Le même code déploie le premier hôte, les suivants, et lit une architecture dessinée ou passée en ligne de commande. Ce qui change d'un cas à l'autre est **d'où vient la description de ce qu'il faut déployer sur cet hôte** :

| Situation | Source de la description | Comportement |
|---|---|---|
| Premier hôte, sans paramètre | UI de conception du launcher | L'utilisateur dessine, puis le launcher déploie |
| Premier hôte, avec indicateurs ou `architecture.json` | Ligne de commande ou fichier | Il déploie ; s'il manque une information, il ouvre l'UI pour la demander |
| Hôte suivant, sans paramètre | L'Admin, via un ticket reçu | Il attend le déclenchement, va chercher sa description, déploie |
| Hôte suivant, avec l'URL du ticket en paramètre | L'Admin, via le ticket | Il déploie tout de suite |

La règle commune : **s'il a assez d'informations il agit ; sinon il les demande (UI) ou il attend (déclenchement)**. Il n'existe pas de drapeau « mode maître » ou « mode worker » : le comportement se déduit de ce qu'il reçoit.

Le cœur est un moteur unique, **« appliquer la description d'un hôte »** (section 6), alimenté par ces trois sources.

### 2. La ligne de commande

```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock ghcr.io/vincamok/goproxify/launcher:preview \
  --admin --edge --agent \
  --host 192.168.1.50=agent \
  --host nas=192.168.1.60:edge,agent
```

- `--admin`, `--edge`, `--agent` : ce qui tourne sur la machine locale, qui est le premier hôte.
- `--host [nom=]IP[:rôles]` ou `--host IP=rôles`, répétable, sans limite : les autres hôtes et leurs rôles. Le nom est facultatif ; sans nom, l'hôte s'appelle `host-192-168-1-50`. Le nom sert de clé entre le ticket et le nœud déclaré (ADR-0015) ; il reste modifiable dans l'Admin avant l'intégration.
- `architecture.json` peut remplacer les indicateurs pour les cas complexes. Les indicateurs ne sont qu'un raccourci qui produit le même fichier : **`architecture.json` reste la source de vérité**.
- **Groupes HA** : chaque passerelle forme son propre groupe d'un membre (ADR-0014, section 1), nommé `ha-<hôte>` quand aucun groupe n'est déclaré : `architecture.json` porte `cluster: true` et `cluster_group` pour toute passerelle, c'est ainsi que l'Admin les voit comme des groupes. Un Agent est rattaché à ce groupe par `target_edge: ha:<groupe>` (et non par le nom de la passerelle), seule forme que l'Admin lit comme un rattachement à un groupe. Un regroupement n'est jamais déduit du nombre de passerelles ; il se déclare explicitement (par exemple `group=nom` sur `--host`) ou dans l'architecture dessinée.

Le launcher refuse de démarrer si l'architecture est incohérente : au moins un Admin et une passerelle, tout Agent rattaché à une passerelle déclarée (par défaut la première), noms uniques, IP valides.

### 3. Cycle de vie : éphémère, jamais résident

- **On ne garde jamais un bootstrap en service.** Le launcher se supprime (`--rm`) à la fin de son déploiement, sur le premier hôte comme sur les suivants. Les conteneurs qu'il a créés continuent de tourner : c'est le démon Docker qui les gère, pas lui.
- **Premier hôte** : il déploie Admin, passerelle et Agent selon le choix, puis sort. Ce n'est pas lui qui attend : **c'est l'Admin qui garde les hôtes en attente** et affiche leurs URL et QR codes. Dans une ligne de commande, il écrit une dernière fois dans le terminal l'adresse de l'Admin et le code de premier accès, pour que le parcours continue dans l'Admin.
- **Hôte suivant** : il écoute (fenêtre limitée), reçoit son déclenchement, déploie ce qui lui revient, puis sort.

### 4. Le QR code est une URL

Le QR code n'est qu'une façon parmi d'autres de transporter une URL de ticket, comme aujourd'hui : l'URL peut aussi être copiée dans la ligne de commande (`launcher join <url>`) ou ouverte depuis un navigateur.

Parcours d'un hôte suivant :

1. L'utilisateur déclare l'hôte dans l'Admin (nom, IP, rôles).
2. Sur l'hôte, il lance le launcher **sans paramètre** : même commande pour tous les hôtes, il écoute sur le port 8080.
3. Dans l'Admin, la fiche de l'hôte affiche un QR code, réaffichable à volonté tant que l'hôte n'est pas intégré. Le ticket est **créé à l'affichage, valable 15 minutes**, à usage unique.
4. Le scan ouvre, sur le téléphone, une URL de l'hôte (`http://192.168.1.50:8080/…`) qui porte l'adresse de l'Admin, le jeton et l'empreinte du certificat de l'Admin.
5. Le launcher affiche une **page de confirmation** : adresse et empreinte de l'Admin visé, nom de l'hôte, rôles à installer. Le déploiement démarre au clic, par un POST.
6. Le launcher va chercher sa description auprès de l'Admin, la fait appliquer, le téléphone affiche l'avancement, puis le launcher sort.

Règles :

- **Un GET n'a jamais d'effet.** Un scan ne produit qu'un GET, et une page web quelconque ouverte sur le réseau pourrait en émettre. Seul le POST de la page de confirmation déploie.
- **La fenêtre d'écoute est limitée** (15 minutes, comme le ticket) et un seul déclenchement valide est accepté.
- **La page de confirmation est la vérification humaine** : quand la commande lancée sur l'hôte est générique, elle est la seule possible. Elle n'est pas contournable par défaut.
- Un **Admin épinglé** (`--admin <url>` ou son empreinte donnés à la commande) peut dispenser de la confirmation, à condition que l'URL reçue lui corresponde. Ce n'est pas le mode par défaut.

### 5. Authenticité de l'Admin

Le launcher d'un hôte suivant doit savoir à quel Admin il parle avant de lui présenter un jeton et d'exécuter ce qu'il en reçoit.

- Le launcher du premier hôte **génère le certificat TLS de l'Admin** (auto-signé) et le lui remet par `GPX_ADMIN_TLS_CERT` et `GPX_ADMIN_TLS_KEY`. Il en connaît l'empreinte.
- Cette **empreinte est portée par l'URL du ticket**. Le launcher d'un hôte suivant refuse un certificat qui ne correspond pas. L'empreinte arrive par un canal distinct (l'écran de l'Admin), qu'un intermédiaire sur le réseau ne peut pas falsifier.
- Si l'Admin est derrière un reverse proxy avec un certificat public, la chaîne de confiance du système suffit et l'empreinte n'est pas exigée.
- Les appels internes dans le réseau Docker (`goproxify-net`) gardent leur fonctionnement actuel.

### 6. Le moteur de déploiement et la description structurée

Ce que le launcher récupère de l'Admin n'est **pas le `compose_text`** : c'est une **description structurée** (JSON) d'un hôte, appliquée par l'API Docker :

- réseau (`goproxify-net`), volumes ;
- pour chaque conteneur : image, variables, ports, montages, réseaux, labels, politique de redémarrage, contrôle de santé ;
- un ordre de démarrage.

Ce choix évite d'interpréter du compose dans un environnement différent de celui de l'hôte (chemins de montage relatifs au conteneur du launcher, comportement selon la version). Le même moteur est la base **commune** : la création initiale, et plus tard la recréation d'un conteneur par l'Agent, qui en a besoin (constat 3). Les tickets existants (`compose_text` et `env_text`, `curl | bash`) restent disponibles pour qui préfère cette voie, par l'API et la CLI : la fiche de l'hôte de l'Admin ne les propose plus (Admin 0.223.4), le QR code du launcher les remplace.

### 7. Enrôlement des hôtes

Le modèle de l'ADR-0015 ne change pas.

- Un **Agent** s'appaire avec **sa passerelle**, pas avec l'Admin (ADR-0006). La description porte l'adresse de la passerelle cible (le champ `edge_endpoint` des tickets existe déjà) et la clé d'appairage dérivée.
- Une **passerelle** ne s'enrôle pas : l'Admin la contacte à l'adresse déclarée et lui pousse son jeton. Les IP statiques sont donc un prérequis réel pour ces hôtes.
- Le launcher du premier hôte génère le **secret racine** et le premier compte Admin, et les affiche une seule fois. Un hôte suivant ne reçoit **jamais le secret racine** : seulement ses clés dérivées (clé des Agents, clé de canal de sa passerelle), livrées sur le canal dont l'empreinte a été vérifiée. Le QR ne contient aucun secret durable, seulement l'adresse de l'Admin, l'empreinte et le jeton à usage unique.
- Le ticket n'est **consommé qu'au moment où l'enrôlement aboutit**, pas à la lecture de l'URL : un déploiement raté peut être relancé avec le même QR tant que les 15 minutes ne sont pas écoulées.
- En cas d'échec, le launcher **défait ce qu'il a créé** sur l'hôte avant de sortir, pour ne pas laisser un hôte à moitié installé.

### 8. Accès à l'UI de conception

L'UI du launcher existe sur tous les hôtes (c'est le même composant). Elle tourne avec le socket Docker monté : y accéder revient à avoir root sur l'hôte.

- Elle est protégée par un **code d'accès aléatoire affiché dans la sortie du conteneur** au démarrage, demandé à l'ouverture.
- Ce code ne protège que l'UI. **L'endpoint de déclenchement du QR n'en a pas besoin** : il a son propre jeton, l'empreinte de l'Admin et la page de confirmation (section 4).
- L'UI s'arrête avec le launcher, comme tout le reste.

### 9. Le socket Docker : le dire honnêtement

- Le launcher monte le socket Docker en écriture, **le temps de son déploiement seulement**.
- **L'Admin et la passerelle ne montent pas le socket.** L'Agent le garde, avec les droits dont il a besoin pour ses fonctions (mises à jour, scaling).
- La documentation est corrigée : on cesse d'écrire « lecture seule » et `:ro` pour le socket. On écrit ce qui est vrai : l'accès au socket équivaut à root sur l'hôte, et seul le code de l'Agent limite ce qu'il en fait. L'« immutabilité » des spécifications lors des mises à jour est une règle de l'Agent, pas une garantie de Docker.

---

## Ce qui n'est pas retenu de la proposition initiale

- **Une PKI de nœuds avec endpoint mTLS d'émission de certificats.** Les nœuds s'authentifient par jeton, HMAC et clés dérivées (ADR-0015). Ajouter une seconde famille d'identifiants doublerait la surface sans en retirer une.
- **Un Agent qui dialogue avec l'Admin.** L'Agent ne dépend que de sa passerelle (ADR-0006).
- **Un POST envoyé par le téléphone avec un jeton en HTTP clair vers un launcher qui exécute aussitôt.** Remplacé par la confirmation, l'empreinte de l'Admin et un déclenchement par POST d'une page servie par le launcher.
- **Le port `8443` de l'Admin** : le port reste `9443`.
- **« L'hôte 1 héberge obligatoirement l'Admin »** : c'est le comportement par défaut du parcours, pas une règle. Une architecture peut déclarer l'Admin ailleurs.
- **Un launcher résident qui attend les hôtes suivants.**

## Test d'autonomie (ADR-0006)

« Si X redémarre alors que Y est injoignable, qu'est-ce qui s'arrête ? »

- **Après installation**, aucun hôte ne dépend du launcher, qui n'existe plus. Chaque hôte fonctionne seul avec ce qu'il a reçu, y compris après un redémarrage pendant une coupure de l'Admin.
- **L'ajout d'un hôte exige l'Admin**, ce que l'ADR-0015 accepte déjà (remplacement ou ajout d'un membre sans l'Admin non pris en charge).
- Un hôte qui échoue en cours d'installation n'affecte pas les autres.

## Limites assumées

- Le déclenchement s'appuie sur la confiance dans le réseau local pendant la fenêtre de 15 minutes : l'utilisateur est la dernière vérification (page de confirmation).
- L'UI et le launcher ont l'accès équivalent à root sur l'hôte. La protection tient au code d'accès, à la fenêtre limitée et à l'absence de service résident.
- Un certificat auto-signé généré par le launcher n'est pas reconnu par un navigateur : l'opérateur peut ensuite le remplacer par le sien.
- L'interface de conception est servie en HTTP sur le port 8080 : le code d'accès circule en clair sur le réseau local. Elle protège d'un passant, pas d'un écouteur du réseau ; sur un réseau qui n'est pas de confiance, on publie le port sur `127.0.0.1` et on passe par un tunnel (ce qui interdit le QR code depuis un téléphone).

## Ordre de mise en œuvre

Chaque étape est livrable seule.

1. **Correctifs préalables.** *Livrée en Agent 0.19.1* : le moteur de recréation de l'Agent garde toute la configuration (variables, commande, ports, montages, volumes anonymes, réseaux avec alias et IP fixes, santé, ressources), met l'ancien conteneur de côté jusqu'à ce que le nouveau tourne et le remet en place si la création ou le démarrage échoue ; la documentation et les exemples ne parlent plus de socket « en lecture seule ». *Restent* : les instances du scaling automatique (`createInstance`) ne reprennent toujours que l'image, les labels et la politique de redémarrage, et le retour arrière retrouve l'image par l'identifiant de l'ancien conteneur, qui n'existe plus après une recréation ; les deux se reprennent avec le moteur de l'étape 2.
2. **Moteur de déploiement.** *Livrée en Agent 0.19.2* (`internal/deploy`, pas encore branché à un binaire) : description structurée d'un hôte (version 1), validée avant tout appel au démon, appliquée par l'API Docker (`Plan` sans effet, `Apply` avec retour arrière à l'envers, y compris si le contexte est annulé), testée sous Windows et sous Linux. Deux précisions par rapport au texte de la section 6 : (1) la description ne peut pas exprimer le mode privilégié ni le réseau de l'hôte, et les montages de l'hôte passent par une politique (`DefaultAllowBind` refuse `/`, `/proc`, `/sys`, `/dev`, `/boot` ; le launcher pourra la durcir en liste blanche) ; (2) un conteneur du même nom déjà présent est un conflit, jamais écrasé. *Reste* : brancher le moteur à la recréation de l'Agent (étape 1, limites) et au launcher (étape 3).
3. **Launcher.** *Livrée en Agent 0.20.0* : sous-commande `goproxify launcher` (`cmd/goproxify/launcher.go`), paquet `internal/launcher`, `services/launcher/Dockerfile`. Elle lit `--admin/--edge/--agent`, `--addr`, `--host` (ou `--topology`), valide la topologie, génère le secret racine, le secret JWT, le mot de passe du premier compte et le certificat TLS de l'Admin, construit la description de l'hôte local et l'applique par le moteur de l'étape 2, avec `--dry-run`. L'Admin reçoit son certificat et `architecture.json` avant son premier démarrage (le moteur sait maintenant déposer des fichiers dans un conteneur créé, volumes compris). Vérifié contre un vrai démon Docker (Agent 0.20.1) : simulation sans effet, retour arrière complet après un démarrage qui échoue, installation complète (Admin sain en HTTPS, empreinte annoncée = empreinte servie, passerelle connectée à l'Admin, Agent appairé, nœuds déclarés visibles), refus de réinstaller par-dessus une installation, état conservé après redémarrage. La clé de canal d'une passerelle est dérivée de l'identifiant de son nœud (`dn_…`), que l'Admin essaie en premier. Écarts avec le texte de la section 2 : (1) l'entrée complexe est une **topologie** JSON (`--topology`), pas un `architecture.json`, car ce fichier ne dit ni où est l'Admin ni l'adresse des hôtes ; le launcher produit `architecture.json` à partir de la topologie ; (2) `--addr` est requis dès qu'il y a d'autres hôtes ; (3) les nœuds d'une topologie à plusieurs passerelles ou Agents se nomment `<hôte>-edge` et `<hôte>-agent`, sinon `goproxify-edge` et `goproxify-agent` comme le démarrage rapide ; (4) le mot de passe du premier compte reste dans l'environnement du conteneur de l'Admin, comme au démarrage rapide, et l'Admin le réapplique à chaque redémarrage (voir `docs/deployment.md`). *Ce qui restait alors est livré aux étapes 4 à 6* (hôtes déclarés, `launcher join`, déclenchement par ticket, interface de conception) ; les images du launcher sont construites par les pipelines `build` (registre privé) et `publish-ghcr`.
4. **Admin.** *Livrée en Admin 0.221.0 / Agent 0.20.2* (`internal/admin/api/hosts.go`) : `GET /api/v1/hosts` (hôtes de `architecture.json`, état `pending`, `partial` ou `joined`, ticket en cours), `POST /api/v1/hosts/{nom}/join-ticket` (ticket de 15 minutes créé à la demande, un seul valide par hôte, refusé si l'hôte est déjà intégré), `GET /api/v1/join/{jeton}` (publique, rend la description de l'hôte avec ses clés dérivées, jamais le secret racine) ; `goproxify hosts list|join-ticket` et les outils MCP `list_hosts` et `create_host_join_ticket`. L'Admin relit la topologie depuis `architecture.json` (`launcher.TopologyFromArchitecture`) : les noms et identifiants des nœuds du fichier font foi, et la description d'un hôte distant est la même que celle que le launcher aurait produite (test d'invariance). Consommation à l'enrôlement : un Agent consomme le ticket à son approbation, une passerelle à sa première connexion avec l'Admin (`SetEdgeConnectedHandler`) ; lire la description ne le consomme pas, un échec en route se relance avec le même. Écarts avec le texte : (1) **l'empreinte n'est pas dans l'URL de la description** mais dans la réponse (`fingerprint`) ; elle rejoindra l'URL du déclenchement (QR) avec l'étape 5, qui seule produit ce QR ; (2) **l'acceptation automatique ne vient plus du fichier** : le launcher ne pose plus `auto_accept` dans `architecture.json`, elle ne vaut que pendant la validité du ticket (étape 3 de l'ADR-0015) ; (3) l'état des Agents est demandé aux passerelles avec un délai de 2 secondes, car une passerelle pas encore installée ne répond pas (constaté sur un vrai Admin : sans ce délai, la liste attendait deux minutes) ; (4) les images des hôtes qui rejoignent viennent de `GPX_DEPLOY_REGISTRY` et `GPX_DEPLOY_TAG`, que le launcher pose sur l'Admin. Vérifié par des tests et sur le vrai binaire de l'Admin sous Linux (liste, ticket, empreinte égale à celle du certificat, description sans authentification, ancien jeton invalidé). L'arrivée réelle d'un hôte distant a été jouée à l'étape 6 (consommation du ticket par l'Agent).
5. **Déclenchement.** *Livrée en Admin 0.222.0 / Agent 0.21.0* (`internal/launcher/join.go`, `listen.go`) : mode attente (`goproxify launcher` sans rôle, `:8080`, 15 minutes, un seul déclenchement), page de confirmation (`GET /join` sans effet, `POST /join` avec jeton à usage unique et contrôle d'origine), avancement affiché sur le téléphone, `launcher join <url>`, empreinte de l'Admin vérifiée par la poignée de main (le jeton ne part pas si elle ne correspond pas), Admin épinglé facultatif ; côté Admin, `trigger_url`, `qr_code`, `listen_command` et `join_command` dans le ticket. Écarts avec le texte : (1) les options d'épinglage s'appellent `--expect-admin` et `--expect-fingerprint`, `--admin` étant déjà le rôle ; (2) le nom et les rôles de l'hôte affichés par la page viennent du lien, donc à titre d'indication : la description réelle n'est lue qu'après le clic, pour que le GET n'appelle personne ; (3) le QR code est produit par l'API, la CLI et le MCP ; son affichage dans la fiche de l'hôte de l'interface reste à faire (étape 6). Vérifié par des tests (Windows). L'arrivée réelle d'un hôte distant a été jouée contre de vrais démons Docker à l'étape 6 (Agent) ; l'arrivée d'une passerelle (hôte 2, passerelle et Agent rattachés au groupe) et le scan du QR code par un téléphone ont depuis été confirmés sur un vrai lab.
6. **UI de conception** du launcher et code d'accès. *Livrée en Admin 0.223.0 / Agent 0.22.0* *(refaite en Agent 0.27.0 : style clair ou sombre commun à toutes les pages du launcher, et schéma de l'infrastructure en Mermaid et en SVG à côté du formulaire, sans bibliothèque)* (`internal/launcher/design.go`, `design.html`) : tout launcher en attente sert `/design`, où l'on déclare ses hôtes (nom facultatif, adresse, rôles, groupe HA, hôte local) et le courriel du premier compte, simule (`Run` en `DryRun`), installe l'hôte local avec le moteur de l'étape 3, lit l'avancement et le rapport (Admin, empreinte, compte, mot de passe), puis termine. Code d'accès aléatoire écrit dans la sortie du conteneur, comparé en temps constant, verrouillage d'une minute après cinq échecs, session par cookie `HttpOnly` `SameSite=Strict` ; écritures exigées de la page (origine, JSON) ; page à CSP à nonce. Le QR code n'en dépend pas (section 8). Chaque action prolonge la fenêtre d'écoute ; l'interface et le déclenchement par QR code s'excluent, et un échec défait l'installation et permet de recommencer. `--ui`, ou une topologie incomplète en ligne de commande, l'ouvre préremplie (tableau de la section 1, deuxième ligne). La fiche de l'hôte de l'Admin (modale Configuration d'un hôte) a une section **Launcher (QR code)** qui crée le ticket à l'ouverture. Écarts avec le texte : (1) **le wizard d'architecture n'est pas réutilisé** : il dépend de l'API et des modules de l'Admin, qui n'existe pas encore sur le premier hôte ; l'interface est un éditeur autonome du même modèle ; (2) l'interface est en HTTP, le code d'accès passe en clair sur le réseau local (limite ci-dessous). Trouvé en l'essayant dans un navigateur : `Referrer-Policy: no-referrer` fait envoyer `Origin: null` avec un formulaire, que le contrôle d'origine de l'étape 5 refusait (le clic de la page de confirmation d'un QR code aurait échoué) ; l'en-tête est `same-origin`. **Vérifié de bout en bout** contre de vrais démons Docker (images construites du dépôt, un démon pour l'hôte 1, un second en Docker-in-Docker pour l'hôte 2) : installation de l'hôte 1 depuis `/design`, puis hôte 2 par le lien du QR code (GET sans effet, POST qui installe, Agent en ligne dans l'Admin, launcher disparu, ticket consommé : 404 rejoué, 409 sur un hôte intégré). Ce qui est resté simulé : le scan par un téléphone (le clic est un `curl`), et un hôte distant sur un autre réseau. L'essai a aussi trouvé que l'API renvoyait `null` pour les listes vides. L'Admin est unique et sur l'hôte du launcher (section 1 et validation) ; la page verrouille la case Admin en conséquence.
7. **Mise à jour d'un hôte.** *Livrée en Agent 0.23.0* (`internal/launcher/update.go`) : `goproxify launcher update` recrée les conteneurs `goproxify-admin`, `goproxify-edge` et `goproxify-agent` de l'hôte avec leur image la plus récente, en réutilisant le moteur de recréation de l'Agent (configuration complète conservée, volumes intacts, retour à l'ancienne image si le nouveau conteneur n'est pas sain). Les images sont toutes tirées avant d'arrêter quoi que ce soit ; un tirage refusé n'arrête pas la mise à jour si une image locale existe (registre privé tiré à la main). Limite : les variables d'environnement sont reprises telles quelles, sans celles qu'une version plus récente du launcher ajouterait.
8. **Documentation, CLI, MCP.** *Livrée* : `docs/cli.md`, `docs/deployment.md`, `docs/api_specs.md`, `docs/mcp.md` (hôtes et tickets), `docs/fonctionnalites.md`, onglet Launcher de la page d'accueil. `launcher update` n'a ni API ni outil MCP : il agit sur le démon Docker de l'hôte où il tourne, hors de l'Admin.
9. **Sauvegarde complète, adresses et ports, import.** *Livrée.* (a) *Livrée en Admin 0.224.0 / Agent 0.24.0.* Le launcher génère `GPX_BACKUP_KEY` et l'affiche une seule fois ; la partie chiffrée de la sauvegarde embarque le secret racine (et son précédent) et le dossier `tls` de l'Admin, pas le secret JWT. (b) *Livrée en Admin 0.225.0.* L'adresse d'un hôte déclaré se modifie dans l'assistant d'architecture (champ « Adresse joignable » : celui de la passerelle existait déjà, l'Agent d'un hôte sans passerelle en a maintenant un) et elle est relue à l'installation ; après l'intégration, un changement demande une réinstallation. Les ports (Admin 9443, hub 8000, 80 et 443) restent fixes : leur modification est écartée. (c) *Livrée en Agent 0.25.0 (ligne de commande) et 0.26.0 (interface de conception).* `launcher --restore`, ou la section « Reconstruire depuis une sauvegarde » de la page, reconstruit l'Admin d'une sauvegarde (secret racine, certificat, clé de sauvegarde, `architecture.json` déposé tel quel) ; les données se restaurent ensuite dans l'Admin, avec un compte temporaire à supprimer (le choix de ne pas l'automatiser est délibéré). La page Sauvegardes de l'Admin (Admin 0.226.0) donne la commande prête à copier. Éprouvé sur Docker : destruction totale, reconstruction, même empreinte, même secret racine, même clé de canal, comptes retrouvés ; une passerelle qui aurait continué de tourner n'a pas été essayée. Clés **à restaurer** : secret racine (obligatoire si au moins un hôte survit), clé de sauvegarde, identifiants tiers de la base (jetons DNS, canaux d'alerte), clé privée de la CA interne. Clés **régénérables** : secret JWT, mot de passe initial, clé locale d'un nœud (`node.key`), clés dérivées (recalculées depuis le secret racine), certificat de l'Admin (au prix d'une nouvelle empreinte). Avant l'étape (a), une sauvegarde ne contenait ni le secret racine ni le certificat, et le launcher ne définissait pas la clé de sauvegarde : elle sortait sans partie secrets.

## Points ouverts

- **Mises à jour de l'Admin et de la passerelle par l'Agent** : possible avec le moteur de l'étape 2, mais non décidé ici (en particulier, qui relève l'Agent lui-même si sa propre mise à jour échoue).
- **Registre privé** : le démon Docker n'utilise pas `~/.docker/config.json` pour les tirages demandés par son API, et le launcher n'envoie pas `X-Registry-Auth` (`deploy.Options.RegistryAuth` existe mais n'est branché ni à l'installation ni à `join`). Écarté pour l'instant : on tire les images à la main (`docker login`, `docker pull`) avant, et `launcher update` accepte alors l'image locale.
- **Variables d'un launcher plus récent** : `launcher update` reprend l'environnement des conteneurs tel quel ; celles qu'une version plus récente ajouterait à une installation neuve n'y sont pas.
- **Podman et hôtes non Linux** : les chemins de socket et le comportement diffèrent (`infra-config.js` distingue déjà `podman.sock`).
- **Architectures multiples** de l'image (amd64, arm64) pour les homelabs.
- **Adresses dynamiques** : un hôte dont l'IP change après l'installation n'est plus joignable pour l'Admin ; l'intégration reste réservée aux IP statiques.
- **Hôtes accessibles uniquement par SSH** : hors périmètre ; seul un hôte où l'on peut lancer le launcher est pris en charge.
