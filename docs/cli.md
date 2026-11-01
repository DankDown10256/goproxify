# GoProxify — Référence CLI

Le binaire `goproxify` regroupe tous les rôles et commandes opérationnelles.

```
goproxify <commande> [options]
```

Les options s'écrivent avec un ou deux tirets : `-reason` et `--reason` sont équivalents.

---

## Commandes de service

Ces commandes démarrent un composant en tant que processus long.

| Commande | Rôle |
|----------|------|
| `admin` | Control Plane — UI Web, API REST, MCP, alerting |
| `edge` | Data Plane — Reverse proxy HTTP/1·2·3, TCP/UDP L4 |
| `agent` | Discovery Docker & métriques |
| `landing` | Page de présentation (optionnel) |

### `goproxify admin`

```
goproxify admin [-config <chemin>]
```

Options spéciales :

```
goproxify admin -reset-password -email <email> -password <nouveau-mdp>
```

Réinitialise le mot de passe d'un utilisateur sans démarrer le serveur.

### `goproxify edge`

```
goproxify edge [-config <chemin>]
```

Sous-commandes locales (sans accès Admin) :

```
goproxify edge cache show
goproxify edge cache refresh
goproxify edge cache export [-output <fichier>]
goproxify edge cache clear

goproxify edge logs export -reason "<motif>" -from <date> -to <date> -output <base>
    [-origin <pair>]
    [-kind access|system] [-ip <ip>] [-domain <hôte>] [-format ndjson|csv]
    [-password-file <fichier> | -no-encrypt] [-config <chemin>]
goproxify edge logs verify -manifest <fichier> [-data <fichier>] [-password-file <fichier>]
    [-pubkey <base64>] [-decrypt-to <fichier>]
goproxify edge logs hold add -reason "<motif>" -from <date> -to <date> [-ip <ip>] [-domain <hôte>]
goproxify edge logs hold list
goproxify edge logs hold release -id <identifiant>
goproxify edge logs key
goproxify edge logs audit

goproxify admin logs export -reason "<motif>" -from <date> -to <date> -output <base>
    [-node <passerelle>|all] [-kind access|system] [-ip <ip>] [-domain <hôte>] [-format ndjson|csv]
    [-password-file <fichier> | -no-encrypt] [-config <chemin>]
goproxify admin logs verify -manifest <fichier> [-data <fichier>] [-password-file <fichier>]
    [-pubkey <base64>] [-decrypt-to <fichier>]
goproxify admin logs import -node <passerelle> -manifest <fichier> -data <fichier> [-password-file <fichier>]
    [-pubkey <base64>] [-dry-run]
goproxify admin logs hold add -reason "<motif>" -from <date> -to <date> [-ip <ip>] [-domain <hôte>]
goproxify admin logs hold list
goproxify admin logs hold release -id <identifiant>
goproxify admin logs nodes
goproxify admin logs key
goproxify admin logs audit

goproxify edge token create -name <nom> [-role admin|agent] [-ttl <durée>]
goproxify edge token list
goproxify edge token revoke <id>
```

**`edge cache`** — gestion du cache local (table de routage + certs sauvegardés).
La passerelle charge ce cache au démarrage si l'Admin est injoignable.

**`edge token`** — tokens d'authentification **locaux** de la passerelle (API interne port 8000).
Distinct de `goproxify token` qui parle à l'Admin.

**`edge logs`** *(Edge `0.88.0`, [ADR 0012](adr/0012-logs-proprietaire-edge.md))* — export complet des logs d'une passerelle pour une procédure légale, **sans l'Admin** : la commande lit la base de la passerelle (ouverte en lecture seule : aucune purge, aucune écriture, passerelle en marche ou arrêtée) avec ses clés locales, donc le secret d'appairage doit être celui de la passerelle (`GPX_PAIRING_SECRET` ou `GPX_CONTROL_PLANE_AUTH_TOKEN`). Réservée à qui a accès au volume de la passerelle.

- `export` écrit les lignes de la plage (`-from`, `-to` : date RFC 3339 ou `AAAA-MM-JJ`, la borne de fin couvrant la journée), filtrées par `-ip` (retrouve aussi les lignes pseudonymisées) et `-domain`, avec **l'IP réelle déchiffrée** par la clé locale. Le motif (`-reason`) est obligatoire. La sortie est chiffrée par un mot de passe d'au moins 12 caractères (`-password-file` ou `GPX_EXPORT_PASSWORD`, jamais en argument ; AES-256-GCM, clé dérivée par scrypt) ; `-no-encrypt` produit une sortie en clair, avec un avertissement. Deux fichiers : `<base>.ndjson[.gpxe]` (ou `.csv`) et `<base>.manifest.json`, que l'export n'écrase jamais. Le manifeste donne la passerelle, l'opérateur, le motif, la plage, le nombre de lignes, les empreintes SHA-256 du fichier remis et du contenu, l'horodatage de la passerelle (sa valeur de preuve dépend de son horloge : NTP) et la clé publique ; il est signé en Ed25519 par une clé dédiée de la passerelle (`log-sign-key.gpx`, créée à la première utilisation, reprise par la sauvegarde d'état). Il ne contient aucune IP : un filtre d'IP n'y figure que par son empreinte. En CSV, les champs de texte qui commencent par `=`, `+`, `-` ou `@` sont précédés d'une apostrophe (un tableur les lirait comme une formule) ; le NDJSON reste le format fidèle.
- `verify` contrôle un export, **n'importe où** (aucune passerelle n'est ouverte) : la signature du manifeste, l'empreinte du fichier remis et, avec le mot de passe, celle du contenu déchiffré (écrit dans `-decrypt-to`). Sans `-pubkey`, la signature prouve que le manifeste est intact mais pas qui l'a signé : comparer la clé à celle relevée à la remise avec `edge logs key`.
- `hold` pose un **gel légal** sur une plage de dates : sans filtre, aucun fichier de logs (accès ou système) qui la recoupe n'est purgé tant que le gel existe, le fichier entier étant gelé. Avec `-ip` (une IP en clair ou pseudonymisée, retrouvée par son empreinte) et/ou `-domain` *(Edge `0.89.0`)*, seules les lignes visées sont gardées : elles sont copiées tout de suite, et à la purge pour celles qui arrivent ensuite, dans une archive `logs/held/<id>/`, puis le fichier de période disparaît normalement avec les lignes des autres personnes ; ces lignes se lisent par `export` seulement, et un ordre d'effacement `logs delete` les supprime aussi. `hold release` supprime l'archive. L'audit local garde l'empreinte de l'IP, pas l'IP. Le registre est relu à chaque purge, la passerelle en marche en tient compte sans redémarrage ; un registre illisible suspend toute purge. `hold release` le lève, la rétention reprend à la prochaine purge. Un gel ne bloque pas un ordre d'effacement RGPD explicite (`logs delete`).
- `audit` affiche le journal local des exports et des gels (`log-export-audit.jsonl`), chaque ligne portant l'empreinte de la précédente : une ligne modifiée ou retirée au milieu casse la chaîne, détectée à la lecture. Il ne contient aucune IP.
- Groupe HA : chaque membre a sa base et sa clé ; on exporte sur chacun, chacun avec son manifeste.

**`admin logs`** *(Admin `0.216.0`, [ADR 0018](adr/0018-logs-geres-par-l-admin.md))* — l'export signé, le gel légal, la clé de signature et le journal d'audit, appliqués à l'**historique complet que l'Admin garde** dans son volume de logs, toutes passerelles confondues. Mêmes règles et mêmes fichiers que `edge logs` : la commande ouvre le volume en **lecture seule** (aucune purge, aucune écriture), serveur éteint ou en marche, et la passerelle n'a plus besoin de garder l'année pour qu'on puisse l'exporter.

- `export` écrit les lignes de la plage de **toutes les passerelles** du volume (`-node all`, défaut) ou d'une seule (`-node <nom ou identifiant>`) ; chaque ligne est identifiée `<passerelle>:<type>:<numéro chez la passerelle>`, l'IP réelle d'une ligne pseudonymisée est déchiffrée avec la clé de l'Admin (celle de `admin.db`), et le manifeste signé nomme les passerelles couvertes (`nodes`). Les passerelles retirées y figurent tant que leur dossier est dans le volume.
- `verify`, `key` et `audit` se comportent comme ceux de `edge logs`. La clé de signature (`log-sign-key.gpx`) et le journal (`log-export-audit.jsonl`) sont dans `state/` de l'Admin, que sa sauvegarde reprend (`GPX_ADMIN_LOG_SIGN_KEY_PATH`, `GPX_ADMIN_LOG_EXPORT_AUDIT_PATH` pour les déplacer) ; la clé est scellée par le secret d'appairage (`GPX_PAIRING_SECRET`, à défaut le secret JWT). Illisible, elle n'est jamais remplacée.
- `hold` pose, liste et lève un **gel légal pour tout le volume** : un registre commun (`legal-holds.json` à la racine du volume de logs), relu à chaque purge de chaque passerelle. Sans filtre, aucun fichier de période qui recoupe la plage n'est purgé ; avec `-ip` ou `-domain`, les lignes visées sont copiées dans l'archive `held/<id>/` de **chaque** store avant que la rétention ne supprime leur fichier. Si un store ne peut pas garder ses lignes, le gel est retiré partout. Un gel ne bloque pas un effacement RGPD explicite.
- `nodes` liste les passerelles qui ont un dossier dans le volume (identifiant et nom).
- `import` *(Admin `0.218.0`)* reprend dans le store d'une passerelle du volume de logs (`-node`) les lignes d'un export NDJSON signé d'une autre base : le cas visé est celui des **copies qu'une passerelle gardait d'un pair** avant le retrait de la réplication (Edge `0.129.0`), qui ne sont plus lues et partiraient avec leur fichier. Elles s'exportent sur la passerelle qui les détient avec `edge logs export -origin <pair>` (ajouté en Edge `0.130.0`), puis se reprennent ici. La signature du manifeste, l'empreinte du fichier et celle du contenu déchiffré sont contrôlées avant toute écriture ; `-pubkey` fixe la clé attendue ; `-dry-run` compte sans écrire. Les lignes gardent leur numéro d'origine **décalé de 2^60** (une référence de ligne reprise ne se confond pas avec une ligne que la passerelle a envoyée depuis, dont la base, remplacée, repart des mêmes numéros), l'IP réelle d'une ligne pseudonymisée est rechiffrée avec la clé de l'Admin et son IP tronquée reste lisible, et la position du flux de la passerelle n'est pas touchée. Rejouer la reprise n'écrit rien de plus. Un export par type de logs (`-kind access`, puis `-kind system`). La reprise **refuse** un export dont le manifeste n'a pas d'`origin` (export des lignes propres d'une passerelle, ou passerelle encore en Edge 0.129 qui ignore `-origin`) ou dont l'`origin` n'est pas la passerelle visée (Admin `0.218.1`) : contrôlez que le manifeste porte `"origin": "<pair>"` avant de reprendre.

Variables d'environnement :

| Variable | Défaut |
|----------|--------|
| `GPX_EDGE_CACHE_PATH` | `/etc/goproxify/edge-cache.gpx` |
| `GPX_EDGE_TOKENS_PATH` | `/etc/goproxify/edge-tokens.db` |
| `GPX_CONTROL_PLANE_AUTH_TOKEN` | — (dérive la clé de déchiffrement du cache) |
| `GPX_LOG_SIGN_KEY_PATH` | `/etc/goproxify/log-sign-key.gpx` (clé de signature des exports de logs) |
| `GPX_LOG_EXPORT_AUDIT_PATH` | `/etc/goproxify/log-export-audit.jsonl` (journal local des exports et des gels) |
| `GPX_EXPORT_PASSWORD` | — (mot de passe de l'export de logs ; préférer `-password-file`) |

### `goproxify agent`

```
goproxify agent [-config <chemin>]
goproxify agent pair -edge <url> -join-token <token>
goproxify agent approve <agent-id> [-admin-url <url>] [-token <token>]
```

**Workflow appairage Agent → passerelle :**

1. Admin UI → Tokens → Créer → rôle `agent`, TTL `24h` → obtenir `gpx_join_*`
2. `goproxify agent pair -edge http://edge:8000 -join-token gpx_join_xxx`
3. `goproxify agent` → l'Agent se connecte, statut `pending`
4. `goproxify agent approve <agent-id>` (ou approbation dans l'UI)
5. L'Agent reçoit son secret HMAC et passe en statut `approved`

### `goproxify launcher`

Installe GoProxify sur l'hôte local (Admin, passerelle, Agent) et déclare les autres hôtes dans l'Admin ([ADR 0019](adr/0019-launcher-bootstrap-multi-hotes.md)). C'est la commande de l'image éphémère `ghcr.io/vincamok/goproxify/launcher` : elle installe puis s'arrête, et `--rm` supprime son conteneur.

```
goproxify launcher --admin --edge --agent [--addr <ip>] [--name <hôte>] [--group <groupe>]
                   [--host [nom=]adresse[:rôles][@groupe] ...] [--email <courriel>]
                   [--registry <registre>] [--tag <étiquette>] [--tz <fuseau>] [--socket <chemin>] [--dry-run]
goproxify launcher --topology <fichier.json> [--dry-run]
```

| Option | Rôle |
|---|---|
| `--admin`, `--edge`, `--agent` | Ce qui s'installe sur cet hôte. L'Admin doit s'y trouver. |
| `--addr` | Adresse (IP ou nom) de cet hôte, joignable par les autres. Requise avec `--host` ; `localhost` sinon. |
| `--host` | Autre hôte, répétable : `[nom=]adresse[:rôles][@groupe]`, ou `adresse=rôles`. Sans rôle : un Agent. Sans nom : `host-192-168-1-50`. Sans `@groupe`, la passerelle de l'hôte forme son propre groupe `ha-<nom de l'hôte>`. |
| `--group` | Groupe HA de la passerelle de cet hôte. Sans groupe, chaque passerelle forme un groupe d'un seul membre. |
| `--topology` | Fichier JSON `{"local": "…", "hosts": [{"name", "addr", "roles", "group"}]}` à la place des options ci-dessus. |
| `--email` | Courriel du premier compte (défaut `admin@goproxify.local`). |
| `--dry-run` | Valide la topologie et affiche ce qui serait tiré et créé, sans rien créer. |

Le mot de passe du premier compte est lu dans `GPX_FIRST_ADMIN_PASSWORD`, ou généré ; il n'est affiché qu'à la fin de l'installation. Le launcher génère aussi le secret racine, le secret JWT et un certificat TLS auto-signé pour l'Admin, dont il affiche l'empreinte SHA-256. Si une étape échoue, tout ce qu'il a créé est retiré. Exemple :

```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock ghcr.io/vincamok/goproxify/launcher:preview \
  --admin --edge --agent --addr 192.168.1.10 \
  --host 192.168.1.50=agent --host nas=192.168.1.60:edge,agent
```

Les hôtes déclarés avec `--host` apparaissent dans la vue Infrastructure de l'Admin à l'état déclaré, sans acceptation automatique : elle ne vaut que pendant la validité d'un ticket d'installation (`goproxify hosts join-ticket`). Leur installation se fait avec le même launcher, en attente ou par `join` (ci-dessous).

#### Installer un hôte déclaré : attente du QR code, ou `join`

```
goproxify launcher [--listen :8080] [--window 15m] [--expect-admin https://hôte:port --expect-fingerprint <sha256>]
goproxify launcher join <spec_url> [--fingerprint <sha256>] [--socket <chemin>]
```

Sans rôle, sans topologie et sans `--host`, le launcher n'a rien à installer : il **attend** un lien de l'Admin pendant 15 minutes (`--window`), sur le port 8080 (`--listen`, à publier avec `-p 8080:8080`). C'est la même commande pour tous les hôtes :

```bash
docker run --rm -p 8080:8080 -v /var/run/docker.sock:/var/run/docker.sock ghcr.io/vincamok/goproxify/launcher:preview
```

1. Dans l'Admin, `goproxify hosts join-ticket -host <nom>` (ou la fiche de l'hôte) crée un ticket de 15 minutes et donne le QR code, `trigger_url`, `listen_command` et `join_command`.
2. Le scan du QR code ouvre, sur le téléphone, la page du launcher de l'hôte. **Un GET n'a jamais d'effet** : la page montre l'Admin visé (adresse et empreinte de son certificat) et ce que le lien annonce de l'hôte (nom, rôles, à titre d'indication), et attend un clic sur « Installer ». Le POST du bouton porte un jeton à usage unique donné par la page, et n'est accepté que de cette page (contrôle de l'origine) : une autre page ouverte sur le réseau ne peut pas le déclencher.
3. Au clic, le launcher récupère la description de l'hôte auprès de l'Admin **en vérifiant l'empreinte du certificat** (la poignée de main échoue avant que le jeton ne parte si ce n'est pas la bonne), l'applique, et le téléphone affiche l'avancement. Si une étape échoue, ce qui avait été créé est retiré et le même ticket permet de réessayer tant qu'il vaut.
4. Il se termine quand l'installation est finie (la page reste servie 20 secondes), ou à la fin de la fenêtre sans déclenchement. Un seul déclenchement est accepté.

`--expect-admin` et `--expect-fingerprint` épinglent l'Admin attendu : un lien qui en désigne un autre est refusé. Avec les deux, un lien conforme n'attend pas de clic (la page se valide seule, par un POST). Ce n'est pas le mode par défaut.

`launcher join <spec_url>` fait la même installation **tout de suite**, sans attendre ni QR code : c'est la variante à copier-coller (`join_command` du ticket). Sans `--fingerprint`, le certificat de l'Admin doit être public (Admin derrière un reverse proxy) ; seul https est accepté.

**Interface de conception.** Un launcher en attente sert aussi `http://<hôte>:8080/design` : on y déclare ses hôtes (nom facultatif, adresse, rôles, groupe HA, hôte local) et le courriel du premier compte, on lance une simulation (**Vérifier**) puis l'installation de l'hôte local (**Installer**) ; l'adresse de l'Admin, l'empreinte et le mot de passe s'affichent à la fin, et **Terminer** fait sortir le launcher. Elle équivaut à un accès root sur l'hôte : un **code d'accès** aléatoire (`ABCD-EFGH`) est écrit dans la sortie du launcher (`docker logs`) et demandé à l'ouverture ; cinq essais ratés de suite verrouillent les essais une minute. **Le QR code n'en a pas besoin.** Chaque action dans l'interface prolonge la fenêtre d'écoute. L'interface est en HTTP : le code circule en clair sur le réseau local, publiez le port sur `127.0.0.1` (`-p 127.0.0.1:8080:8080`) si le réseau n'est pas de confiance. La page montre en regard du formulaire le **schéma de l'infrastructure** (hôtes, rôles, pilotage des passerelles par l'Admin, routes des Agents, groupes HA), mis à jour pendant la saisie, y compris pour une sauvegarde lue : un dessin SVG, sans bibliothèque ni ressource externe, et le même schéma en texte **Mermaid** (onglet *Mermaid*, bouton de copie) à coller dans une doc ou un ADR. Elle suit le thème clair ou sombre du système. `--dry-run` imprime ce texte Mermaid.

```
goproxify launcher --ui [--admin --edge --agent --addr <ip> --host …]
```

`--ui` ouvre l'interface préremplie avec les indicateurs donnés, au lieu d'installer. Sans `--ui`, une topologie incomplète (pas d'Admin, pas de passerelle) l'ouvre aussi, en disant ce qui manque.

#### Mettre à jour un hôte : `launcher update`

```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock ghcr.io/vincamok/goproxify/launcher:preview update [--dry-run]
```

Recrée, avec leur image la plus récente, les conteneurs `goproxify-admin`, `goproxify-edge` et `goproxify-agent` **de l'hôte où il tourne** (à lancer sur chaque hôte). Les volumes ne sont pas touchés : comptes, certificats, `architecture.json` et clés restent en place.

- Chaque conteneur est recréé **avec sa configuration complète** (variables d'environnement, secrets compris, ports, montages, réseaux, politique de redémarrage) : seule l'image change. Les variables qu'une version plus récente du launcher ajouterait à une installation neuve ne sont donc pas ajoutées.
- L'image visée est celle que le conteneur désigne déjà (`registre/composant:étiquette`, par exemple `:preview` ou `:latest`). Toutes les images sont tirées **avant** d'arrêter quoi que ce soit ; un conteneur dont l'image n'a pas changé n'est pas touché. Pour changer de registre ou d'étiquette, il faut réinstaller.
- Les conteneurs sont recréés un à un, dans l'ordre Admin, passerelle, Agent. Un conteneur qui ne démarre pas ou ne devient pas sain dans les 2 minutes **retrouve son ancienne image** et la commande échoue ; ceux déjà mis à jour le restent.
- **Registre privé** : le démon Docker n'utilise pas les identifiants de `docker login` pour les tirages demandés par le launcher. Si le tirage échoue mais qu'une image locale existe (tirée à la main avec `docker pull`), c'est elle qui est utilisée, avec un avertissement.
- `--dry-run` liste les conteneurs et leurs images sans rien tirer ni recréer.
- Le conteneur `launcher` ne se met pas à jour lui-même : c'est son image qui porte la version de la commande, `docker pull` la rafraîchit avant de relancer.

#### Reconstruire l'Admin depuis une sauvegarde : `launcher --restore`

```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v $PWD/sauvegarde.gpx-admin-backup:/backup/snapshot:ro \
  ghcr.io/vincamok/goproxify/launcher:preview --restore /backup/snapshot --name <hôte> --addr <adresse> --backup-key <clé>
```

Pour un Admin perdu : le launcher lit le fichier d'une sauvegarde faite **avec la clé de sauvegarde** (Admin 0.224.0 ou plus : les sauvegardes plus anciennes n'ont pas le secret racine, et le launcher les refuse) et installe un Admin qui a le même secret racine, le même certificat (donc la même empreinte), la même clé de sauvegarde et le même `architecture.json`, déposé tel quel (domaines, délégations et réglages compris). Les passerelles et Agents déjà en place le reconnaissent donc sans réinstallation.

- `--name` désigne l'hôte de la sauvegarde qui porte cette machine (l'Admin n'est pas un nœud de `architecture.json`, il faut le dire) ; à défaut, `--addr` le retrouve par son adresse, et il remplace alors l'adresse déclarée si la machine en a changé. Sans l'un ni l'autre, la commande liste les hôtes de la sauvegarde.
- La clé vient de `--backup-key` ou de `GPX_BACKUP_KEY`. Elle devient aussi celle du nouvel Admin.
- `--restore` prend la topologie de la sauvegarde : il ne se combine pas avec `--admin`, `--edge`, `--agent`, `--group`, `--host`, `--topology` ni `--ui`. `--dry-run`, `--registry`, `--tag`, `--tz` et `--email` s'appliquent.
- **Les données ne sont pas restaurées par le launcher** (comptes, proxys, règles, secrets de la base). Un compte temporaire `restauration@goproxify.local` est créé : connectez-vous avec, restaurez le même fichier (*Sauvegardes › Restaurer › fichier*, case *Secrets*), redémarrez l'Admin, reconnectez-vous avec vos comptes puis supprimez le compte temporaire. Le launcher le rappelle à la fin.
- Sans le certificat dans la sauvegarde, un nouveau est généré et l'empreinte change.

**Depuis l'interface de conception** (`http://<hôte>:8080/design`) : la section **Reconstruire depuis une sauvegarde** prend le fichier et la clé de sauvegarde (le fichier part tel quel, 512 Mio au plus ; le launcher le garde en mémoire, jamais sur disque, et l'oublie une fois l'installation faite). La page liste les hôtes de la sauvegarde, demande lequel est cette machine et, si besoin, sa nouvelle adresse, puis remplace l'éditeur d'hôtes : **Vérifier** et **Reconstruire cet hôte** font la même chose que `--restore`. À la fin, le rapport redonne les étapes de restauration des données et **Terminer** renvoie vers l'Admin.

---

## Commandes opérationnelles

Ces commandes parlent à l'Admin via HTTP.

**Auth commune :**

```
-admin-url <url>   URL Admin (ou GPX_CONTROLPLANE_ADMIN_ENDPOINT)
-token <token>     JWT session ou PAT (ou GPX_CONTROLPLANE_AUTH_TOKEN)
```

---

### `goproxify token`

Gestion des tokens d'appairage passerelle/Agent enregistrés dans l'Admin.

```
goproxify token create -role edge|agent -node <nom> [options]
  -role        edge | agent
  -node        Nom du nœud (ex: prod-edge-1)
  -ttl         Durée de validité (ex: 24h, 7d, 0 = permanent)
  -endpoint    URL de la passerelle (enregistrée si role=edge)
  -rbac-role   admin | operator | viewer (défaut: admin)

goproxify token list [-role edge|agent]
goproxify token revoke <id>
```

Exemples :

```bash
goproxify token create -role edge  -node prod-1 -endpoint http://edge:8000
goproxify token create -role agent -node app-2  -ttl 24h
goproxify token list
goproxify token revoke <id>
```

> Distinct de `goproxify edge token` (tokens locaux de la passerelle, sans Admin).

---

### `goproxify backup`

Sauvegardes et restauration.

```
goproxify backup create [-target admin|full] [-output <dir>]
  -target  admin : snapshot SQLite Admin (.gpx-admin-backup, défaut)
           full  : DB + fichiers config (.gpx-full-backup)
  -output  Répertoire de destination (défaut: .)

goproxify backup list

goproxify backup restore -file <chemin> [-yes]
goproxify backup restore -id <snapshot-id>  [-yes]
goproxify backup status
goproxify backup verify <snapshot-id>
goproxify backup destinations list|add|test|delete
```

`status` affiche la clé, le dernier snapshot, les planifications manquées, l'état de chaque destination et l'image du launcher à utiliser pour reconstruire l'Admin (`launcher --restore`, voir plus haut). `verify` contrôle la somme de contrôle et le déchiffrement d'un snapshot (code retour 1 si invalide). `destinations add -name <n> -type dir|webdav|s3 [-retention N]` prend `-path` (dir), `-url -username -password` (webdav) ou `-endpoint -bucket -access-key -secret-key [-region -prefix -path-style false]` (s3).

Si le snapshot ou le fichier contient une section `secrets` (créée quand `GPX_BACKUP_KEY` est définie sur l'Admin), la restauration la rejoue aussi — mots de passe, MFA, clés, CA interne, fichiers d'état — à condition que l'Admin ait la même clé et que le token CLI soit celui d'un superadmin ; sinon `secrets_error` est renvoyé et le reste est restauré. Redémarrer l'Admin ensuite. Voir [sauvegardes.md](sauvegardes.md).

Exemples :

```bash
goproxify backup create
goproxify backup create -target admin -output /var/backups/goproxify
goproxify backup list
goproxify backup restore -file backup-2026-08-01.gpx-admin-backup -yes
```

---

### `goproxify import`

Import de configurations existantes (nginx, Traefik, Caddy, HAProxy, export Goproxify, JSON). Chaque format est un module du registre (ADR 0007) : `goproxify import formats` les liste avec leurs extensions.

```
goproxify import -file <chemin> [-format <format>] [-dry-run] [-select <domaines>] [-overwrite]
goproxify import formats
  -file       Fichier de configuration source (ou répertoire)
  -format     nginx | traefik-yaml | traefik-toml | caddy | haproxy | goproxify | json
              (défaut : détection par nom de fichier ; un format inconnu est lu comme du JSON générique)
  -dry-run    Affiche ce qui serait importé sans appliquer
  -select     Domaines à importer (virgules)
  -overwrite  Écrase les proxies existants (défaut : ignorés)
```

Exemples :

```bash
goproxify import -file nginx.conf -dry-run
goproxify import -file traefik.yml -format traefik-yaml
```

---

### `goproxify proxy`

Gestion des proxies (lecture et cycle de vie).

```
goproxify proxy list    [-admin-url …] [-token …]
goproxify proxy get     <id> [-admin-url …] [-token …]
goproxify proxy labels  <id> [-format compose|portainer|portainer_inline|docker_run|kubernetes] [-admin-url …] [-token …]
  Affiche les labels qui reproduisent le proxy (défaut `compose` ; `portainer` = avec stack.env, `portainer_inline` = sans). Les secrets sortent en variables `${GPX_…}` à renseigner (bloc de variables à la suite) ; les réglages sans label sont listés sur la sortie d'erreur
goproxify proxy enable  <id> [-admin-url …] [-token …]
goproxify proxy disable <id> [-admin-url …] [-token …]
goproxify proxy metrics [-admin-url …] [-token …]
goproxify proxy cache-purge <id> [-tag a,b] [-path /x,/y*] [-admin-url …] [-token …]
  Sans -tag ni -path, tout le cache du proxy est vidé
goproxify proxy option <id> <option> <json|@fichier|off> [-admin-url …] [-token …]
  Pose ou retire une option avancée du proxy : split, maintenance, signed_url, graphql, bandwidth, redact_json, html_inject, hedge, static, request_schema, openapi, grpc_transcode, grpc_web, rate_limit, conditions, surface, max_body_size, ip_filter, geo_ip, cors, waf (`off` la retire)
goproxify proxy delete  <id> [-y] [-admin-url …] [-token …]
  -y  Confirmation automatique
  Sur un proxy implicite (marqué « (implicite) » par `proxy list` : portail Access, délégation), retire seulement la surcouche — la route redevient celle que GoProxify génère
  -method  Validation ACME par la passerelle (sans fournisseur DNS) : `http-01` (port 80) ou `tls-alpn-01` (port 443), sans wildcard ; `renew` réutilise la méthode du domaine
```

Exemples :

```bash
goproxify proxy list
goproxify proxy get app.example.fr
goproxify proxy metrics
goproxify proxy disable app.example.fr
goproxify proxy delete app.example.fr -y
```

---

### `goproxify cert`

Gestion des certificats TLS (ACME / Let's Encrypt).

```
goproxify cert list   [-admin-url …] [-token …]
goproxify cert obtain <domaine> [-dns-provider <id>] [-admin-url …] [-token …]
goproxify cert delete <domaine> [-admin-url …] [-token …]
  -dns-provider  Fournisseur DNS nommé du challenge DNS-01 (voir goproxify acme), mémorisé et réutilisé au renouvellement
```

`list` affiche le domaine, le statut, le nombre de jours avant expiration (⚠ si < 14 j) et l'émetteur.

Exemples :

```bash
goproxify cert list
goproxify cert obtain app.example.fr
goproxify cert obtain "*.example.fr" -dns-provider 3f9c2a1b
goproxify cert delete old.example.fr
```

---

### `goproxify acme`

Fournisseurs DNS du challenge ACME DNS-01 : cinq natifs (OVH, Cloudflare, Route 53, Gandi, Hetzner) et 28 modules [libdns](https://github.com/libdns). Admin uniquement ; scopes PAT `certs:read` (lecture) et `certs:write` (écriture).

```
goproxify acme types [-q <filtre>] [-json]
goproxify acme providers list   [-json]
goproxify acme providers get    <id>
goproxify acme providers add    -name <nom> -type <type> [-set clé=valeur,…] [-file params.json]
goproxify acme providers update <id> [-name <nom>] [-set clé=valeur,…] [-file params.json]
goproxify acme providers delete <id> [-y]
```

- `types` liste chaque type avec son moteur (`libdns` pour les modules) et ses paramètres (`*` requis, `(secret)`) ; `-q` filtre sur le type ou le libellé.
- `-set` convient aux valeurs simples. Une valeur contenant une virgule passe par `-file`, un objet JSON `{ "clé": "valeur" }` ; `-set` s'applique après `-file`.
- Les secrets sont masqués à la lecture ; `update` part de la configuration enregistrée, ne change que ce qui est donné et conserve les secrets non fournis. Le type d'un fournisseur ne change pas : en créer un autre.

Exemples :

```bash
goproxify acme types -q ocean
goproxify acme providers add -name do-prod -type digitalocean -set auth_token=dop_v1_xxx
goproxify acme providers add -name gcp -type googleclouddns -set gcp_project=my-project,gcp_application_default=/etc/goproxify/gcp-sa.json
goproxify acme providers add -name pdns -type powerdns -file pdns-params.json
goproxify acme providers update 3f9c2a1b -set zone=example.fr
```

---

### `goproxify architecture`

Contenu et historique de `architecture.json` (fichier de vérité de l'architecture : nœuds du wizard avec leur hôte et leurs capacités, Passerelles, périmètres, domaines). Chaque écriture qui change le fichier en conserve la version précédente.

```
goproxify architecture show [-version <nom>]
goproxify architecture versions
goproxify architecture restore -name <version>
goproxify architecture recover [-edges nom1,nom2]
```

`show` affiche l'architecture courante en JSON, ou une version conservée avec `-version` (sans la restaurer). `recover` reconstitue le fichier à partir des fiches de groupe que détiennent les passerelles appairées (toutes, ou celles de `-edges`) : groupes, membres et domaines absents du fichier sont ajoutés, le reste n'est pas modifié (`POST /api/v1/architecture/recover`). À utiliser sur un Admin neuf, démarré avec le même `GPX_PAIRING_SECRET` et l'adresse d'au moins une passerelle (aucune approbation à faire) ; les passerelles qui n'ont pas répondu sont listées, et la commande peut être rejouée.

Exemple :

```bash
goproxify architecture show
goproxify architecture versions
goproxify architecture show -version architecture-20260926T070623359846127Z.json
goproxify architecture restore -name architecture-20260926T070623359846127Z.json
```

---

### `goproxify internal-ca`

Génère et gère une autorité de certification (CA) interne, pour émettre des certificats serveur/client internes hors ACME (services internes sans exposition publique).

```
goproxify internal-ca create-ca -name <nom> -cn <common-name> [-years N]
goproxify internal-ca list-ca
goproxify internal-ca issue -ca <id> -cn <cn> [-sans a,b] [-usage server|client] [-days N]
goproxify internal-ca list-certs -ca <id>
goproxify internal-ca revoke -ca <id> <certID>
```

Exemples :

```bash
goproxify internal-ca create-ca -name root -cn "GoProxify Internal Root" -years 10
goproxify internal-ca list-ca
goproxify internal-ca issue -ca abc123 -cn svc.internal.local -sans svc.internal.local,10.0.0.5 -usage server
goproxify internal-ca list-certs -ca abc123
goproxify internal-ca revoke -ca abc123 cert456
```

---

### `goproxify user`

Gestion des utilisateurs de l'Administration.

```
goproxify user list   [-admin-url …] [-token …]
goproxify user get    <id> [-admin-url …] [-token …]
goproxify user create -email <email> -password <mdp> [-role admin|user|dpo] [-permissions gdpr:reveal] [-admin-url …] [-token …]
goproxify user update <id> [-role admin|user|dpo] [-permissions gdpr:reveal|none] [-admin-url …] [-token …]
goproxify user passwd <id> -password <nouveau-mdp> [-admin-url …] [-token …]
goproxify user delete <id> [-y] [-admin-url …] [-token …]
```

- `list` affiche le rôle et les permissions effectives de chaque compte.
- `-role dpo` (délégué à la protection des données) et `-permissions gdpr:reveal` (révélation des IP pseudonymisées) ne sont acceptés que du superadmin ; `-permissions none` retire les permissions accordées en propre. Un compte superadmin ou détenteur de ce droit n'est modifiable (`update`, `passwd`, `delete`) que par le superadmin. Voir [rgpd.md](rgpd.md).
- Depuis Admin `0.78.0`, `-role` est réellement transmis (il était ignoré : les comptes étaient toujours créés en `user`) ; `-status` est retiré, l'API ne l'a jamais pris en charge.

Exemples :

```bash
goproxify user list
goproxify user create -email ops@example.fr -password s3cret -role user
goproxify user create -email dpo@example.fr -password s3cret -role dpo
goproxify user update <id> -permissions gdpr:reveal
goproxify user passwd <id> -password s3cret
goproxify user delete <id> -y
```

---

### `goproxify audit`

Journal d'audit des actions administratives.

```
goproxify audit list   [-actor <email>] [-action <action>] [-limit <n>] [-admin-url …] [-token …]
goproxify audit export [-output <fichier.csv>] [-admin-url …] [-token …]
```

Exemples :

```bash
goproxify audit list -actor admin@example.fr -limit 20
goproxify audit export -output /var/log/audit-2026.csv
```

---

### `goproxify logs`

Logs d'accès et logs système.

```
goproxify logs list
  [-level debug|info|warn|error]
  [-domain <host>]
  [-ip <ip>]
  [-method GET|POST|…]
  [-status <code>]
  [-path <préfixe>]
  [-tls-ja4 <empreinte>]  [-tls-ja3 <empreinte>]
  [-search <texte>]
  [-from <RFC3339>]  [-to <RFC3339>]
  [-limit <n>]  [-page <n>]
  [-source admin|edge]    [-node <passerelle>]    [-cursor <jeton>]
  [-admin-url …] [-token …]

goproxify logs export
  [-format csv|json]
  [-output <fichier>]
  [-level …] [-domain …] [-ip …] [-from …] [-to …]
  [-source admin|edge]    [-node <passerelle>]
  [-admin-url …] [-token …]

goproxify logs reveal-ip
  -entry-id <id> | -entry-ref <passerelle:type:id>   ligne pseudonymisée (id local, ou référence d'une ligne de passerelle)
  -reason "<motif>"   Motif légal, obligatoire, inscrit au journal d'audit
  [-admin-url …] [-token …]

goproxify logs delete
  -by-ip <ip> | -by-user <user_id>
  [-reason "<motif>"]
  [-admin-url …] [-token …]

goproxify logs subject-export
  -by-ip <ip> | -by-user <user_id>
  [-reason "<motif>"] [-output <fichier>]
  [-admin-url …] [-token …]

goproxify logs siem show
goproxify logs siem set -file <fichier.json> | -stdin
goproxify logs siem enable | disable
goproxify logs siem status
  [-admin-url …] [-token …]
```

- `logs siem` (Admin `0.178.0`, Edge `0.87.0`, [ADR 0012](adr/0012-logs-proprietaire-edge.md)) pilote l'**exporteur SIEM** : chaque passerelle envoie ses logs à vos destinations (syslog RFC 5424 sur TCP ou TLS, HTTP NDJSON ou OTLP/HTTP JSON, Admin `0.179.0`) avec son propre curseur, au moins une fois, même Admin éteint. `show` affiche la configuration en JSON (les valeurs des en-têtes, des jetons, sont masquées) ; `set` l'enregistre depuis un fichier ou l'entrée standard, dans le même format : une valeur laissée masquée garde le jeton enregistré, une destination sans `id` en reçoit un ; `enable` / `disable` allument ou éteignent l'exporteur sans toucher aux destinations (une destination retirée ou éteinte perd son curseur) ; `status` affiche, par passerelle et par destination, l'état, les lignes livrées, le retard (âge de la plus ancienne ligne non livrée), `À RISQUE` quand le retard menace des lignes qui vont être purgées, et la dernière erreur. Rôle admin ; avec un token API, `logs:read` pour `show` et `status`, `logs:write` pour le reste. Un retard au-delà du seuil de la destination (`alert_after_minutes`, 60 par défaut) déclenche l'alerte `siem_export_lag`.

- `-source edge` (Admin `0.169.0`, [ADR 0012](adr/0012-logs-proprietaire-edge.md)) lit les lignes dans la base de logs de **chaque passerelle** au lieu de la copie de l'Admin, et les fusionne du plus récent au plus ancien, avec les logs propres de l'Admin ; `-node` vise une seule passerelle. La liste signale sur la sortie d'erreur les passerelles injoignables (leurs lignes manquent) et une recherche arrêtée par son délai, et affiche le `-cursor` de la page suivante. `-limit` (500 au plus) devient la taille de page ; l'export fusionné va jusqu'à 100 000 lignes. La colonne `id` d'une ligne de passerelle est la référence à passer à `reveal-ip -entry-ref`.
- `reveal-ip` affiche l'IP réelle d'une entrée pseudonymisée (RGPD) ; réservé au superadmin (scope `gdpr:reveal` avec un token API). Fonctionne aussi après la désactivation de la pseudonymisation, tant que l'entrée est conservée.
- `delete` efface les logs d'une IP (entrées pseudonymisées comprises) ou d'un utilisateur (droit à l'effacement, Art. 17) et affiche le nombre d'entrées supprimées ; avec `-by-ip`, supprime aussi les bans de l'IP, leur historique et son entrée du cache GeoIP (et lève ses bans sur les passerelles) ; il affiche aussi, par passerelle, ce qu'elle a effacé ou qu'elle est injoignable et recevra l'ordre à sa connexion (Admin `0.177.0`) ; rôle admin, scope `logs:write` avec un token API. Le journal d'audit garde le motif et le nombre d'entrées, pas l'IP en clair.
- `subject-export` produit le fichier JSON du droit d'accès et de portabilité (RGPD Art. 15 et 20) : pour une IP, ses logs (pseudonymisés compris), bans, historique des bans, position GeoIP et entrées d'audit ; pour un compte, son profil (jamais le mot de passe), ses équipes, ses logs et ses entrées d'audit. Sans `-output`, le JSON va sur la sortie standard. L'IP voyage dans le corps de la requête ; l'audit garde le motif et les compteurs, pas l'IP. Rôle admin, scope `logs:write` avec un token API.

Exemples :

```bash
goproxify logs list -domain app.example.fr -status 5xx -limit 100
goproxify logs list -ip 1.2.3.4 -from 2026-09-01T00:00:00Z
goproxify logs list -source edge -node gw-paris -status 5xx -limit 200
goproxify logs export -format json -output access.json
goproxify logs reveal-ip --entry-id 4821 --reason "Réquisition judiciaire n° 2026/1234"
goproxify logs delete --by-ip 203.0.113.42 --reason "Demande RGPD Art. 17"
goproxify logs subject-export --by-ip 203.0.113.42 --reason "Demande RGPD Art. 15" --output export.json
goproxify logs siem show > siem.json   # modifier siem.json (destinations, filtres), puis :
goproxify logs siem set --file siem.json
goproxify logs siem status
```

---

### `goproxify prism`

Analyse du trafic (mêmes données que la page Prism).

```
goproxify prism anomalies
  [-hours <n>]  [-edge <nœud>]  [-proxy <hôte>]
  [-admin-url …] [-token …]

goproxify prism tls
  [-limit <n>]
  [-hours <n>]  [-edge <nœud>]  [-proxy <hôte>]
  [-admin-url …] [-token …]

goproxify prism geo
  [-level country|city]  [-limit <n>]
  [-hours <n>]  [-edge <nœud>]  [-proxy <hôte>]
  [-admin-url …] [-token …]
```

Exemples :

```bash
goproxify prism anomalies -hours 6 -edge paris-01
goproxify prism geo -level city -limit 20
goproxify prism tls -hours 24 -limit 10
```

---

### `goproxify alert`

Canaux de notification, règles d'alerte, et tests.

```
# Canaux
goproxify alert events [-days <n>] [-trigger <id>] [-node <passerelle>] [-limit <n>] [-admin-url …] [-token …]   # alertes déclenchées (30 jours)
goproxify alert channels list   [-admin-url …] [-token …]
goproxify alert channels types  [-admin-url …] [-token …]
goproxify alert channels get    <id> [-admin-url …] [-token …]
goproxify alert channels create -file <channel.json> [-admin-url …] [-token …]
goproxify alert channels update <id> -file <channel.json> [-admin-url …] [-token …]
goproxify alert channels delete <id> [-y] [-admin-url …] [-token …]

# Règles
goproxify alert rules list   [-admin-url …] [-token …]
goproxify alert rules get    <id> [-admin-url …] [-token …]
goproxify alert rules create -file <rule.json> [-admin-url …] [-token …]
goproxify alert rules update <id> -file <rule.json> [-admin-url …] [-token …]
goproxify alert rules delete <id> [-y] [-admin-url …] [-token …]

# Tests
goproxify alert test -channel <id> [-admin-url …] [-token …]
goproxify alert test -all          [-admin-url …] [-token …]

# Événements et accusé de réception
goproxify alert events [-days N] [-trigger <t>] [-node <n>] [-limit N] [-admin-url …] [-token …]
goproxify alert ack <event-id> [-admin-url …] [-token …]
```

`alert channels types` liste les types avec leurs champs (* = requis, « secret » = jamais réaffiché ; un secret omis lors d'un `update` est conservé). Types de canal (`alert channels create -file`, champ `type`) : `email`, `webhook`, `slack`, `teams`, `telegram`, `sms` (Twilio), `ntfy`, `gotify`, `jira`, `linear`, `github`, `gitlab`, `zammad`, `glpi`. `alert rules create`/`update` acceptent `group_window_sec` (secondes, défaut 0 = désactivé) : les événements qui correspondent à la règle dans cette fenêtre sont fusionnés en une seule notification au lieu d'une par événement. Ils acceptent aussi `escalation` (tableau `{after_sec, channels}`) : si l'événement n'est pas acquitté (`alert ack <event-id>`) avant `after_sec` secondes, il est renotifié vers `channels` (vide = canaux de la règle) ; les paliers déjà programmés se désactivent d'eux-mêmes dès l'accusé de réception.

Exemples :

```bash
goproxify alert channels list
goproxify alert channels create -file slack-channel.json
goproxify alert rules create -file cpu-alert.json
goproxify alert test -channel <id>
goproxify alert test -all
```

---

### `goproxify snippet`

Snippets de sécurité réutilisables (WAF, Ephor, rate-limit…).

```
goproxify snippet list   [-admin-url …] [-token …]
goproxify snippet types  [-admin-url …] [-token …]   # champs des types ip_filter, geo_ip, bot, waf
goproxify snippet get    <id> [-admin-url …] [-token …]
goproxify snippet create -file <snippet.json> [-admin-url …] [-token …]
goproxify snippet update <id> -file <snippet.json> [-admin-url …] [-token …]
goproxify snippet delete <id> [-admin-url …] [-token …]
```

Exemple de fichier `snippet.json` :

```json
{
  "name": "waf-strict",
  "type": "waf",
  "config": { "enabled": true, "mode": "block", "anomaly_threshold": 5 }
}
```

Les snippets `ip_filter`, `geo_ip`, `bot` et `waf` sont validés par leur manifeste (`goproxify snippet types`) : mode inconnu, CIDR ou code pays invalide, expression WAF invalide ou clé inconnue ⇒ erreur `400`. Les secrets (`challenge_secret`, `challenge_provider_secret`) sont masqués à la lecture et conservés à la modification.

Exemples :

```bash
goproxify snippet list
goproxify snippet create -file waf-strict.json
goproxify snippet update <id> -file waf-strict.json
goproxify snippet delete <id>
```

---

### `goproxify ech`

Encrypted Client Hello : chiffre le nom du site (SNI) dans le handshake TLS. Admin uniquement (`certs:write` pour un PAT).

```
goproxify ech status      [-admin-url …] [-token …]
goproxify ech enable      <nom-public> [-admin-url …] [-token …]
goproxify ech disable     [-admin-url …] [-token …]
goproxify ech rotate      [-admin-url …] [-token …]
goproxify ech delete-key  <id> [-admin-url …] [-token …]
```

`status` affiche la valeur `ech="…"` à publier dans l'enregistrement HTTPS de chaque domaine, et les clés (active / retirée). `enable` exige un nom public couvert par un certificat (ni wildcard, ni IP) ; changer de nom public génère une nouvelle clé. `rotate` retire l'ancienne clé de la publication DNS mais les passerelles l'acceptent encore ; `delete-key` ne supprime qu'une clé retirée.

---

### `goproxify domain`

Domaines gérés par ACME (certificats Let's Encrypt dédiés).

```
goproxify domain list   [-admin-url …] [-token …]
goproxify domain get    <id> [-admin-url …] [-token …]
goproxify domain create <domaine> [-edge <edge-id>] [-method http-01|tls-alpn-01] [-admin-url …] [-token …]
goproxify domain renew  <id> [-admin-url …] [-token …]
goproxify domain delete <id> [-y] [-admin-url …] [-token …]
  -y  Confirmation automatique
  -method  Validation ACME par la passerelle (sans fournisseur DNS) : `http-01` (port 80) ou `tls-alpn-01` (port 443), sans wildcard ; `renew` réutilise la méthode du domaine
```

`list` affiche l'expiration en jours (⚠ si < 14 j) et la passerelle associé.

Exemples :

```bash
goproxify domain list
goproxify domain create app.example.fr -edge prod-edge-1
goproxify domain renew <id>
goproxify domain delete <id> -y
```

---

### `goproxify agent-mgmt`

Agents Docker enregistrés auprès de l'Admin (distinct de `goproxify agent` qui démarre le processus).

```
goproxify agent-mgmt list    [-admin-url …] [-token …]
goproxify agent-mgmt get     <id> [-admin-url …] [-token …]
goproxify agent-mgmt approve <id> [-admin-url …] [-token …]
goproxify agent-mgmt revoke  <id> [-admin-url …] [-token …]
goproxify agent-mgmt delete  <id> [-y] [-admin-url …] [-token …]
goproxify agent-mgmt sources [-admin-url …] [-token …]
```

`sources` liste les sources de découverte de l'Agent (Docker/Podman, Portainer, Kubernetes, Consul, Nomad, etcd, ECS) avec leurs champs de configuration (`*` = requis, « secret » = masqué dans le heartbeat et conservé par un correctif de configuration). Chaque source est un module du registre (ADR 0007).

Exemples :

```bash
goproxify agent-mgmt list
goproxify agent-mgmt approve <id>
goproxify agent-mgmt revoke  <id>
```

---

### `goproxify settings`

Configuration de l'Admin.

```
goproxify settings smtp get  [-admin-url …] [-token …]
goproxify settings smtp set  -file <smtp.json> [-admin-url …] [-token …]
goproxify settings smtp test [-admin-url …] [-token …]
```

Exemple de fichier `smtp.json` :

```json
{
  "host": "smtp.example.fr",
  "port": 587,
  "username": "noreply@example.fr",
  "password": "s3cret",
  "from": "GoProxify <noreply@example.fr>",
  "tls": true
}
```

Exemples :

```bash
goproxify settings smtp get
goproxify settings smtp set -file smtp.json
goproxify settings smtp test
```

#### MFA serveur

```
goproxify settings mfa sms     get [-admin-url …] [-token …]
goproxify settings mfa sms     set -file <sms.json> [-admin-url …] [-token …]
goproxify settings mfa webauthn get [-admin-url …] [-token …]
goproxify settings mfa webauthn set -file <webauthn.json> [-admin-url …] [-token …]
```

Exemple `sms.json` :

```json
{ "provider": "twilio", "api_sid": "AC…", "api_secret": "…", "from": "+33600000000" }
```

Exemple `webauthn.json` :

```json
{ "rp_id": "admin.example.fr", "rp_origin": "https://admin.example.fr", "display_name": "GoProxify" }
```

> **Cas de déblocage** : si `rp_origin` est incorrect, personne ne peut se connecter via WebAuthn.
> Corrigez-le avec `settings mfa webauthn set` sans passer par l'UI.

```bash
goproxify settings mfa webauthn get
goproxify settings mfa webauthn set -file webauthn.json
goproxify settings mfa sms get
goproxify settings mfa sms set -file sms.json
```

---

### `goproxify plugin`

Plugins WebAssembly des passerelles (admin uniquement ; voir [plugins.md](plugins.md)).

```
goproxify plugin list    [-admin-url …] [-token …]
goproxify plugin get     <nom> [-admin-url …] [-token …]
goproxify plugin install -manifest <plugin.json> -wasm <plugin.wasm> [-sha256 <empreinte>] [-admin-url …] [-token …]
goproxify plugin update  -manifest <plugin.json> -wasm <plugin.wasm> [-sha256 <empreinte>] [-admin-url …] [-token …]
goproxify plugin delete  <nom> [-y] [-admin-url …] [-token …]
```

`goproxify plugin repo list|add|delete` gère les dépôts, `plugin catalog [-repo id]` liste les plugins proposés et `plugin fetch <nom> -repo <id> [-version v]` installe ou met à jour depuis un dépôt (mêmes contrôles qu'une installation manuelle, signature comprise).

`goproxify plugin keygen -out <préfixe>` crée une paire de clés de signature (la clé privée n'est jamais écrasée), `plugin sign -key … -manifest … -wasm …` affiche la signature d'un paquet, `plugin install … -signature <base64>` (ou `-signature-file`) la transmet, `plugin keys list|add|delete` gère les clés de confiance de l'Admin. Dès qu'une clé de confiance existe, la signature est obligatoire.

`install` calcule l'empreinte SHA-256 du module et la transmet ; avec `-sha256`, elle doit égaler l'empreinte publiée par l'auteur, sinon rien n'est installé.

---

### `goproxify auth-provider`

Fournisseurs d'authentification externe (OIDC, SAML, LDAP…).

```
goproxify auth-provider types   [-admin-url …] [-token …]   # types et champs de configuration
goproxify auth-provider list    [-admin-url …] [-token …]
goproxify auth-provider get     <id> [-admin-url …] [-token …]
goproxify auth-provider create  -file <provider.json> [-admin-url …] [-token …]
goproxify auth-provider update  <id> -file <provider.json> [-admin-url …] [-token …]
goproxify auth-provider enable  <id> [-admin-url …] [-token …]
goproxify auth-provider disable <id> [-admin-url …] [-token …]
goproxify auth-provider delete  <id> [-y] [-admin-url …] [-token …]
```

Exemple de fichier `provider.json` (OIDC) :

```json
{
  "name": "Google",
  "provider": "google",
  "enabled": true,
  "config": {
    "oidc": {
      "client_id": "xxx.apps.googleusercontent.com",
      "client_secret": "GOCSPX-…",
      "redirect_url": "https://app.example.fr/_gpx/oidc/callback",
      "session_secret": "<32 octets aléatoires>"
    }
  }
}
```

`provider` désigne le type (`type` est accepté comme synonyme). La configuration est validée par le manifeste du type (`goproxify auth-provider types`) : champ requis manquant ou clé inconnue ⇒ erreur `400`.

Exemples :

```bash
goproxify auth-provider list
goproxify auth-provider create -file google-oidc.json
goproxify auth-provider enable  <id>
goproxify auth-provider disable <id>
goproxify auth-provider delete  <id> -y
```

---

### `goproxify teams`

Équipes RBAC — regroupement d'utilisateurs avec un rôle commun.

```
goproxify teams list   [-admin-url …] [-token …]
goproxify teams get    <id> [-admin-url …] [-token …]
goproxify teams create <nom> [-role admin|operator|viewer] [-admin-url …] [-token …]
goproxify teams update <id> [-name <nom>] [-role admin|operator|viewer] [-admin-url …] [-token …]
goproxify teams delete <id> [-y] [-admin-url …] [-token …]

goproxify teams members list   <team-id> [-admin-url …] [-token …]
goproxify teams members add    <team-id> -user <user-id> [-admin-url …] [-token …]
goproxify teams members remove <team-id> -user <user-id> [-admin-url …] [-token …]

goproxify teams permissions <team-id> [-permissions gdpr:reveal|none] [-admin-url …] [-token …]
```

`teams permissions` affiche les permissions accordées aux membres de l'équipe ; avec `-permissions`, les remplace (`none` = aucune). `gdpr:reveal` permet aux membres de révéler les IP pseudonymisées (RGPD). Modifier ces permissions, les membres d'une équipe qui en porte, ou supprimer une telle équipe est réservé au superadmin.

Exemples :

```bash
goproxify teams list
goproxify teams create ops-team -role operator
goproxify teams members list   <team-id>
goproxify teams members add    <team-id> -user <user-id>
goproxify teams members remove <team-id> -user <user-id>
goproxify teams permissions <team-id> -permissions gdpr:reveal
goproxify teams delete <team-id> -y
```

---

### `goproxify ip-profile`

Profils IP — listes blanches/noires basées sur CIDR, pays (GeoIP) ou réputation.

```
goproxify ip-profile list   [-admin-url …] [-token …]
goproxify ip-profile get    <id> [-admin-url …] [-token …]
goproxify ip-profile create -file <profile.json> [-admin-url …] [-token …]
goproxify ip-profile update <id> -file <profile.json> [-admin-url …] [-token …]
goproxify ip-profile delete <id> [-y] [-admin-url …] [-token …]
```

`list` affiche une colonne `ETAT` : `ok`, ou `échec xN` après N échecs consécutifs du rafraîchissement automatique (détail : `ip-profile get <id>`, champs `last_error` et `next_attempt_at`).

Exemple de fichier `profile.json` (liste manuelle ; pour un feed, remplacer `cidrs` par `feed_urls`, `feed_format` et `refresh_interval_h`, les deux étant exclusifs) :

```json
{
  "name": "bureaux",
  "mode": "allow",
  "cidrs": ["203.0.113.0/24", "198.51.100.7"],
  "enabled": true
}
```

Exemples :

```bash
goproxify ip-profile list
goproxify ip-profile create -file blocklist.json
goproxify ip-profile update <id> -file blocklist.json
goproxify ip-profile delete <id> -y
```

---

### `goproxify security`

Ephor (threat engine global), gestion des bans, config WAF par proxy, et moteur de règles automatiques.

```
# Moteurs globaux et leurs champs de configuration (Ephor, Seuils multi-passerelles, CrowdSec, WAF)
goproxify security engines [-admin-url …] [-token …]

# Config du moteur Ephor
goproxify security threat get  [-edge <id>] [-admin-url …] [-token …]   # passerelle d'un groupe HA : config du groupe
goproxify security threat set  [-edge <id>] -file <threat-config.json> [-admin-url …] [-token …]
goproxify security threat simulate -file <threat-config.json> [-hours N] [-domain <d>] [-edge <id>] [-admin-url …] [-token …]   # dry-run : rejoue les logs, n'enregistre rien
goproxify security threat suggest [-days N] [-edge <id>] [-admin-url …] [-token …]   # seuils proposés à partir des cumuls par minute (rien n'est appliqué)
goproxify security threat references [-edge <id>] [-admin-url …] [-token …]   # ce que chaque passerelle a appris (débit normal par route et heure, base ASN)
goproxify security surface list   [-edge <id>] [-admin-url …] [-token …]   # proxies dont la surface est apprise, par passerelle
goproxify security surface report -proxy <id|hôte> [-edge <id>] [-admin-url …] [-token …]   # méthodes, gabarits de chemin, tailles, paramètres, convergence
goproxify security surface proposals -proxy <id|hôte> [-edge <id>] [-admin-url …] [-token …]   # réglages proposés à partir du profil (rien n'est appliqué)
goproxify security surface openapi -proxy <id|hôte> [-low] [-out <fichier>] [-edge <id>] [-admin-url …] [-token …]   # politique positive : spécification OpenAPI générée, en detect (rien n'est appliqué)
goproxify security surface suggestions -proxy <id|hôte> [-edge <id>] [-admin-url …] [-token …]   # ajouts suggérés à la politique (chemins et méthodes qui reviennent)
goproxify security surface accept -proxy <id|hôte> [-all-high] [-keys "<clé>;<clé>"] [-dry-run] [-edge <id>] [-admin-url …] [-token …]   # ajoute ces suggestions à la politique
goproxify security surface enforce -proxy <id|hôte> -reasons <raison,…> [-dry-run] [-force] [-edge <id>] [-admin-url …] [-token …]   # refuse ces violations, garde-fous compris
goproxify security surface relax  -proxy <id|hôte> [-admin-url …] [-token …]   # retour en detect : plus rien n'est refusé
goproxify security surface reset  -proxy <id|hôte> [-edge <id>] [-admin-url …] [-token …]   # l'apprentissage repart de zéro
# -edge : pour une passerelle membre d'un groupe HA, la config lue/écrite est celle du groupe (poussée à tous les membres)

# Interrupteur du WAF d'une passerelle (coupe ou rétablit le WAF de tous ses proxies, sans toucher à leurs réglages)
goproxify security waf-engine get [-edge <id>] [-admin-url …] [-token …]
goproxify security waf-engine set -enabled <true|false> [-edge <id>] [-admin-url …] [-token …]   # même règle de groupe HA que threat
goproxify security waf-engine activity [-hours N] [-edge <id>] [-admin-url …] [-token …]   # requêtes signalées par le WAF : refusées/passées, règles et domaines les plus touchés (défaut 24 h, max 168)

# Bans
goproxify security bans list   [-edge <passerelle>] [-source <source>] [-active true|false] [-scope <passerelle|group:nom>] [-admin-url …] [-token …]   # -source : native, fleet, crowdsec, threat, plugin:<nom> (ex. plugin:coraza) ; un ban d'Ephor ou du WAF est suivi d'une ligne « ↳ signal points (valeur) · … » qui l'explique
goproxify security bans add    -ip <ip|cidr> [-reason <raison>] [-ttl <durée>] [-scope <passerelle|group:nom>] [-admin-url …] [-token …]
goproxify security bans preview -ip <ip|cidr> [-hours N] [-json] [-admin-url …] [-token …]   # impact d'un ban avant de le créer
goproxify security bans whitelist list|add|delete [-ip <ip|cidr>] [-comment <texte>] [-admin-url …] [-token …]   # liste blanche des bans
goproxify security bans asn lookup|preview|ban|unban|info|refresh [-asn <ASN>] [-q <ASN|IP|nom>] [-hours N] [-ttl <durée>] [-scope <passerelle|group:nom>] [-dry-run] [-json]   # bans par ASN
goproxify security bans import -file <chemin|-> [-format auto|text|csv|json] [-target bans|whitelist] [-reason …] [-domain …] [-ttl …] [-scope <passerelle|group:nom>] [-dry-run] [-json] [-admin-url …] [-token …]
goproxify security bans delete -id <ban-id> [-admin-url …] [-token …]

# Parcours d'une IP ou d'un CIDR
goproxify security trace -target <ip|cidr> [-scope ip|asn] [-asn <ASN>] [-from <date>] [-to <date>] [-order desc|asc] [-limit N] [-offset N] [-json] [-admin-url …] [-token …]

# WAF par proxy
goproxify security waf get -proxy <proxy-id> [-admin-url …] [-token …]
goproxify security waf set -proxy <proxy-id> -file <waf-config.json> [-admin-url …] [-token …]

# SLA de correction des CVE (délai attendu selon la gravité)
goproxify security rejections [-edge <id>] [-admin-url …] [-token …]   # ce que l'entrée de chaque passerelle a refusé : poignées de main TLS ratées, hôtes sans route, noms demandés, IP, empreintes
goproxify security traffic-reference [-edge <id>] [-admin-url …] [-token …]   # la référence saisonnière du trafic de chaque route : débit réel, débit attendu à cette heure, alertes en cours
goproxify security tls-reputation [accept -ja4 <ja4,…> | -all] [-edge <id>] [-admin-url …] [-token …]   # empreintes TLS proposées pour la liste personnalisée d'Ephor, avec leurs preuves ; accept les ajoute
goproxify security domain-watch [run | accept -domain <d> -check <ct|caa|dangling> -key <k> | config -file <f.json>] [-admin-url …] [-token …]   # surveillance des domaines : certificat hors GoProxify, CAA, nom pendant
goproxify security cve inventory [-proxy <id|hôte>] [-edge <id>] [-gaps] [-admin-url …] [-token …]   # applications reconnues derrière les proxies ; -gaps : seulement ce que la recherche de CVE ne couvre pas
goproxify security cve cpe get [-admin-url …] [-token …]   # identifiants CPE donnés aux produits que la table ne couvre pas
goproxify security cve cpe set -file <overrides.json> [-admin-url …] [-token …]
goproxify security cve sla get [-admin-url …] [-token …]
goproxify security cve sla set -file <sla.json> [-admin-url …] [-token …]
```

**`security engines`** — liste les moteurs globaux et les champs de leur configuration (chemins pointés comme `ip_score.ban_threshold`, secrets repérés). `security threat set` valide le fichier avec ce manifeste : clé inconnue, mode hors `block|detect`, durée illisible ou négative, IP ou CIDR invalide, code d'erreur HTTP hors 400-599, source de liste qui n'est pas http(s) ⇒ erreur `400`, rien n'est enregistré.

**`security threat`** — lit ou écrit la configuration du moteur Ephor (seuils, whitelist globale…). Le paramètre `-edge` cible une passerelle spécifique dans un cluster multi-passerelle.

**`security threat suggest`** — seuils proposés à partir des cumuls par minute (`-days`, défaut 7 ; `-edge`) : débit normal par passerelle et limite globale proposée. N'applique rien. Voir `GET /api/v1/security/threat-config/suggestions`.

**`security surface`** — apprentissage de la surface d'un proxy ([ADR 0016](adr/0016-apprentissage-de-la-surface-d-un-proxy.md)) : ce que son trafic légitime utilise réellement, sans rien bloquer. `list` donne les proxies en apprentissage par passerelle, `report -proxy <id|hôte>` le rapport complet (gabarits de chemin, méthodes, types de contenu, tailles, paramètres, clients, convergence), `proposals -proxy <id|hôte>` les réglages que le profil permet de proposer (`max_body_size`, `rate_limit`, `geo_ip`, `ip_filter`, `cors`), chacun avec sa justification, ce qu'il aurait refusé et la commande qui le pose (rien n'est appliqué), `openapi -proxy <id|hôte> [-low] [-out openapi.json]` la politique positive : une spécification OpenAPI générée à partir du profil, sous la forme du réglage `openapi` du proxy en mode `detect` (`-low` garde les chemins à confirmer ; `-out` écrit la configuration, à poser avec `goproxify proxy option <id> openapi @openapi.json`), `suggestions -proxy …` les ajouts que le profil suggère à la politique (un chemin ou une méthode hors politique qui revient de plusieurs clients propres sur plusieurs jours ; confiance haute si le backend les sert, basse si le contrôle les refuse), `accept -proxy … -all-high` ou `-keys "unknown_path GET /nouveau/{int};…"` les ajoute à la spécification openapi sans rien retirer (les clés viennent de `suggestions` ; `-dry-run` simule ; un texte YAML est refusé), `enforce -proxy … -reasons unknown_path,invalid_param` fait refuser ces types de violation par le contrôle openapi (`unknown_path`, `unknown_method`, `invalid_param`, `invalid_body`, `unsupported_media`, `too_large`), avec garde-fous : politique active, profil convergé, aucun chemin à ajouter ; `-dry-run` simule, `-force` passe outre les garde-fous qui le permettent (audit) ; un refus des garde-fous affiche `blockers` et sort en erreur, rien n'est modifié ; `relax -proxy …` repasse en detect ; `reset -proxy …` remet l'apprentissage à zéro sur toutes les passerelles (ou `-edge`). L'activation se fait par proxy : `goproxify proxy option <id> surface '{"mode":"learn"}'` (ajoutez `"type":"site"` pour un blog, un CMS ou tout contenu ouvert : pas de politique de chemins ni de suggestions, une convergence qui ne dépend que de l'ancienneté et du volume). Voir `GET /api/v1/security/surface`, `…/surface/report` et `POST …/surface/reset`.

**`security threat references`** — ce que chaque passerelle a appris pour la note commune d'Ephor (`-edge` pour une seule) : références de débit par route et par heure, base ASN, profils. Voir `GET /api/v1/security/threat-references`.

**`security threat simulate`** — rejoue les access logs récents (`-hours`, défaut 1, max 24, et 168 quand la config rejoue la référence saisonnière ; `-domain` pour un seul domaine) contre la config candidate du fichier, surchargée sur la config actuelle, et affiche le résultat en JSON : requêtes bloquées, faux positifs probables (`legit_blocked`), IP et bans, actuel vs candidat. Ne modifie rien. Voir `POST /api/v1/security/threat-config/simulate`.

**`security bans`** — liste, ajoute ou supprime des IPs bannies manuellement. `-ttl` accepte une durée Go (`30m`, `1h`, `24h`) ou un nombre entier de jours (`7d`), convertie par la CLI en date d'expiration (`expires_at`) au moment de l'appel ; sans `-ttl`, le ban est permanent. Une durée invalide ou nulle est refusée sans rien créer (avant Admin `0.69.5`, `-ttl` était ignoré et le ban toujours permanent). `list` accepte `-edge` (nom du nœud ou id du token : les bans de cette passerelle et les bans globaux), `-source` et `-active true` (non expirés) ou `false` (expirés) ; la passerelle d’origine est affichée entre crochets.

`add` et `preview` acceptent une adresse IP **ou une plage CIDR** (`-ip 203.0.113.0/24`) : la valeur est normalisée (`203.0.113.7/24` devient `203.0.113.0/24`), une valeur invalide ou une plage plus large que `/16` (IPv4) ou `/32` (IPv6) est refusée, ainsi qu'une plage qui contient votre propre adresse. `preview` mesure l'impact sans rien créer : trafic de la cible sur `-hours` heures (24 par défaut, 168 au plus) dont les requêtes réussies qui seraient coupées, bans et profils IP qui la recoupent, avertissements ; `-json` affiche la réponse brute (`GET /api/v1/security/bans/preview`).

`security bans import` crée des bans (ou, avec `-target whitelist`, des entrées de la liste blanche) depuis une liste lue dans `-file` (`-` = entrée standard) : texte (une adresse ou un CIDR par ligne, commentaires `#` et `;`, comme les listes publiques FireHOL, blocklist.de ou Spamhaus DROP), CSV (l'export des bans se réimporte tel quel) ou JSON ; `-format` force le format, détecté sinon. `-reason` (motif par défaut, `import` sinon), `-domain` et `-ttl` (durée Go ou `7d`, expiration par défaut ; sans, permanents) s'appliquent aux entrées qui n'ont pas les leurs. Chaque entrée est validée comme `bans add` ; les doublons, cibles déjà couvertes et plages privées sont ignorés. **`-dry-run` analyse sans rien créer** : à lancer d'abord. Le rapport liste les entrées rejetées et ignorées avec leur ligne ; `-json` affiche la réponse brute (`POST /api/v1/security/bans/import`).

`security bans asn` bannit un **ASN** (tout un opérateur) : `lookup -q OVH` (ou `-q AS16276`, ou `-q 51.77.0.1` pour l'ASN d'une adresse) cherche ; `preview -asn AS16276` mesure l'impact sans rien créer (plages, trafic des dernières heures, avertissements) ; `ban -asn AS16276 [-reason …] [-ttl 7d] [-scope …] [-dry-run]` crée un ban par plage annoncée, en un seul envoi aux passerelles ; `unban -asn AS16276` les lève tous ; `info` et `refresh` montrent ou mettent à jour la base ASN de l'Admin. Un ASN qui contient votre adresse est refusé.

`security bans whitelist` gère la **liste blanche des bans** : `list` affiche les entrées (avec le nombre de bans actifs qu'elles neutralisent), `add -ip <ip|cidr> [-comment …]` ajoute une adresse ou une plage (normalisée comme un ban, `/16` IPv4 et `/32` IPv6 au plus larges), `delete -ip <valeur>` la retire. Une adresse en liste blanche n'est atteinte par aucun ban et n'est pas évaluée par Ephor ; les bans existants ne sont pas supprimés.

**`security rejections`** *(Admin `0.228.0`, Edge `0.135.0`)* — affiche, par passerelle (`-edge` en désigne une), ce que son entrée a refusé depuis son démarrage : totaux par raison (`unknown_sni`, `no_sni`, `ip_literal`, `not_tls`, `bad_clienthello`, `timeout`, `too_many_pending`, `handshake_failed`, `unknown_host`), premiers noms demandés avec le nombre d'IP distinctes qui les demandent, premières IP et premières empreintes JA4, en JSON (`GET /api/v1/security/rejections`). Classements approchés, tenus en mémoire, remis à zéro au redémarrage de la passerelle.

**`security domain-watch`** *(Admin `0.240.0`)* — la surveillance des domaines déclarés dans l'Admin. Sans sous-commande : affiche la configuration, l'état et les constats. `run` lance une analyse en arrière-plan (une toutes les cinq minutes au plus), `accept -domain <d> -check <ct|caa|dangling> -key <clé>` reconnaît un constat, `config -file <config.json>` enregistre les réglages (`enabled`, `ct`, `caa`, `dangling`, `interval_hours`, `trusted_issuers`, `ca_issuer`, `ct_endpoint`, `resolver`). Tout est désactivé par défaut : chaque vérification envoie des noms de domaine à un service extérieur.

**`security tls-reputation`** *(Admin `0.239.0`, Edge `0.146.0`)* — affiche, par passerelle (`-edge` en désigne une), les empreintes TLS (JA4) proposées pour la liste personnalisée d'Ephor avec leurs preuves. `security tls-reputation accept -ja4 <ja4,…>` (ou `-all`) les ajoute à `custom_lists.tls_fingerprints` et pousse la configuration ; seules les propositions actuelles sont acceptées, une empreinte déjà listée est ignorée. Équivalent de l'outil MCP `get_tls_reputation` pour la lecture.

**`security traffic-reference`** *(Admin `0.233.0`, Edge `0.140.0`)* — affiche, par passerelle (`-edge` en désigne une), la référence saisonnière du trafic : pour chaque route, le débit réel, le débit attendu à cette heure de cette journée, l'état (froid, normal, avertissement, attaque probable) et les alertes en cours. Lecture seule ; équivalent de l'outil MCP `get_traffic_reference`.

**`security trace`** (`-scope asn` : tout l'ASN de l'adresse, ou `-asn AS16276` sans adresse ; sans saisir de CIDR, grâce à la base ASN) — reconstitue tout ce qu'une IP ou un CIDR a fait : synthèse (requêtes, bloquées, IP distinctes, épisodes, bans/débans, détections, bans en cours, profils IP) puis les étapes (épisodes d'activité, bans, débans, détections) avec leur date. `-from` / `-to` acceptent une date `AAAA-MM-JJ` ou RFC3339 (défaut : 30 derniers jours) ; les étapes sont du plus récent au plus ancien, `-order asc` pour l'ordre chronologique ; un ban affiche le `User-Agent` qui l'a provoqué sur la ligne suivante ; `-limit` / `-offset` paginent (500 étapes par défaut) ; `-json` renvoie la réponse brute de `GET /api/v1/security/ip-trace`. Exemple : `goproxify security trace -target 198.51.100.0/24 -from 2026-01-01`. Les requêtes remontent aussi loin que la rétention des logs d'accès.

**`security cve inventory`** *(Admin `0.208.0`)* — affiche, par passerelle, les applications reconnues derrière les proxies (produit, version, identifiant CPE, image du conteneur ou réponses du backend lues avant `hide_server`) : ce que le scanner de vulnérabilités cherche dans NVD. `-proxy` limite à un proxy (identifiant ou hôte), `-edge` à une passerelle.

`security cve inventory -gaps` *(Admin `0.210.0`)* n'affiche que le rapport de couverture : les produits, images et logiciels que la recherche de CVE ne traite pas, avec la raison (`no_version`, `no_cpe`, `unknown`), la preuve et les proxys. **`security cve cpe`** lit (`get`) ou remplace (`set -file`) les identifiants CPE donnés par l'administrateur à ces produits :

```json
{ "overrides": [ { "match": "vaultwarden", "cpe": "dani-garcia:vaultwarden" } ] }
```

**`security cve sla`** — lit ou écrit le délai de correction attendu des CVE (en jours après détection), par tranche de gravité CVSS ; réglage global (Admin `0.52.3`). Fichier `sla.json` :

```json
{ "critical_days": 7, "high_days": 14, "medium_days": 30, "low_days": 90 }
```

**`security waf`** — lit (`get`) ou met à jour (`set`) les champs `waf` et `ephor_whitelist` d'un proxy sans toucher au reste de sa configuration. Le fichier JSON peut contenir uniquement les clés à modifier :

```json
{
  "waf": {
    "enabled": true,
    "mode": "block",
    "anomaly_threshold": 10,
    "behavior_enabled": true
  },
  "ephor_whitelist": ["10.0.0.0/8", "192.168.1.5"]
}
```

Le fichier de `security waf set` accepte `waf.exclusions` pour ne retirer des règles que sous un chemin :

```json
{
  "waf": {
    "enabled": true,
    "mode": "block",
    "exclusions": [
      { "paths": ["/wp-admin/"], "platform": "wordpress", "note": "éditeur d'articles" }
    ]
  }
}
```

Un chemin est un préfixe sur frontière de segment ; `/` est refusé (utilisez `exclude_ids`).

Exemples :

```bash
goproxify security threat get
goproxify security threat set -file threat.json

goproxify security bans list
goproxify security bans add -ip 1.2.3.4 -reason "scan" -ttl 24h
goproxify security bans preview -ip 203.0.113.0/24
goproxify security bans whitelist add -ip 198.51.100.0/24 -comment "bureau Paris"
goproxify security bans whitelist list
goproxify security bans asn lookup -q OVH
goproxify security bans asn preview -asn AS16276
goproxify security bans asn ban -asn AS16276 -ttl 30d -dry-run
goproxify security bans asn unban -asn AS16276
goproxify security bans import -file blocklist.txt -dry-run
goproxify security bans import -file blocklist.txt -reason "blocklist.de" -ttl 30d
curl -s https://lists.blocklist.de/lists/ssh.txt | goproxify security bans import -file - -ttl 7d
goproxify security bans add -ip 203.0.113.0/24 -reason "scanner" -ttl 7d
goproxify security bans add -ip 198.51.100.7 -scope paris          # appliqué par la seule passerelle « paris »
goproxify security bans add -ip 198.51.100.7 -scope group:ha-1     # appliqué par les membres du groupe HA ha-1
goproxify security bans delete -id <ban-id>

goproxify security waf get -proxy app.example.fr
goproxify security waf set -proxy app.example.fr -file waf.json

goproxify security cve sla get
goproxify security cve sla set -file sla.json

```

---

### `goproxify automation`

Flux d'automatisation (Admin 0.139.0). Les règles, planifications et playbooks sont des flux : un déclencheur (`condition`, `event`, `schedule`, `manual`), un garde-fou et des étapes. Cette commande remplace `security rules`, `security schedule` et `security playbook`. Le format JSON d'un flux est décrit dans [api_specs.md](api_specs.md#flux-dautomatisation-admin-01390).

```
goproxify automation flows list     [-trigger condition,event|schedule|manual] [-json]
goproxify automation flows get      <id>
goproxify automation flows create   -file <flux.json>
goproxify automation flows update   <id> -file <flux.json>
goproxify automation flows delete   <id> [-y]
goproxify automation flows enable   <id>
goproxify automation flows disable  <id>
goproxify automation flows run      <id> [-dry-run] [-input clé=valeur,…]
goproxify automation flows simulate -file <flux.json> [-input clé=valeur,…]
goproxify automation flows versions <id>
goproxify automation flows restore  <id> <version>
goproxify automation flows detach   <id>
goproxify automation flows params   <id> -set clé=valeur,… [-name <nom>]

goproxify automation runs list      [-flow <id>] [-status waiting_approval,…] [-limit N] [-json]
goproxify automation runs get       <run-id>
goproxify automation runs approve   <run-id>
goproxify automation runs reject    <run-id>
goproxify automation runs cancel    <run-id>
goproxify automation runs replay    <run-id>

goproxify automation templates list
goproxify automation templates preview <id> [-set clé=valeur,…] [-flow <id>]
goproxify automation templates install <id> [-set clé=valeur,…] [-name <nom>] [-disabled]

goproxify automation catalog [-json]
goproxify automation silences list
goproxify automation silences add    -name <nom> -starts <RFC3339> -ends <RFC3339> [-flows <id1,id2>]
goproxify automation silences delete <id> [-y]
goproxify automation export [-out <fichier.yaml>]
goproxify automation import -file <automation.yaml>
```

Toutes les commandes acceptent `-admin-url` et `-token`.

- **`flows`**
  - `list` affiche une ligne par flux : état, nom, lieu d'exécution (`edge` : sur les passerelles), déclencheur → étapes, origine (`manual` pour l'éditeur, `template`), suivie de « modèle mis à jour » ou « modèle supprimé » le cas échéant.
  - `run` lance un flux à la main, sans garde-fous ; un flux à condition l'évalue d'abord.
  - `run -dry-run` et `simulate` parcourent le flux sans rien exécuter et affichent la trace étape par étape. `simulate` accepte un fichier non enregistré.
  - `params` modifie les paramètres d'un flux issu d'un modèle ; `detach` le détache pour l'éditer comme les autres.
  - `versions` liste les versions et, sous chacune, ce qui a changé depuis la précédente (étapes ajoutées, retirées, modifiées, déplacées, déclencheur, garde-fou, paramètres).
  - `-input` et `-set` prennent des paires `clé=valeur` séparées par des virgules. Un nombre ou un booléen garde son type.
- **`runs`**
  - `list` affiche le journal des exécutions : statut, flux, source (`admin`, `edge:<nœud>`, `manual:<acteur>`, `call:<run>`).
  - `approve` et `reject` décident d'une approbation en attente (`-status waiting_approval` les liste).
  - `replay` relance un flux avec le détail d'une exécution terminée, par exemple interrompue par un redémarrage.
- **`templates preview -flow <id>`** affiche aussi ce que l'enregistrement de ces paramètres changerait sur un flux issu du modèle, nouvelle version du modèle comprise.
- **`catalog`** liste les déclencheurs, conditions, actions, types d'étape et métriques, avec leurs champs. Une métrique suivie de « aussi par chaque passerelle » est aussi calculée par chaque passerelle : un flux simple qui la surveille s'exécute sur les passerelles.
- **`export` / `import`** échangent flux, canaux et mises en sourdine en YAML `version: 2` (GitOps). Les secrets sont masqués à l'export et conservés à l'import.

Exemple : la règle « CVE critique → approbation → désactiver le proxy » (`flux.json`).

```json
{
  "name": "CVE critique : couper après accord",
  "enabled": true,
  "trigger": { "kind": "condition", "condition": { "type": "cve_critical", "config": { "cvss_threshold": 9 } } },
  "guard": { "cooldown_sec": 3600 },
  "steps": [
    { "id": "ok", "type": "approval", "config": { "message": "Couper {{detail.proxy_name}} ({{detail.cve_id}}) ?", "timeout": "1h" } },
    { "id": "off", "type": "action", "action": { "type": "disable_proxy" } },
    { "id": "say", "type": "action", "action": { "type": "notify", "config": { "notify_message": "{{detail.proxy_name}} coupé par {{steps.ok.actor}}" } } }
  ]
}
```

Exemple : la sauvegarde planifiée, installée depuis un modèle.

```
goproxify automation templates install schedule-nightly-backup -set "cron=0 2 * * *,retention=7"
```

---

### `goproxify containers`

Conteneurs découverts par les Agents. Agrège les résultats de toutes les passerelles connectées.

```
goproxify containers [list] [-admin-url …] [-token …]
goproxify containers convert <hôte|id> [-edge <passerelle>] [-admin-url …] [-token …]
goproxify containers enable|disable <hôte> [-admin-url …] [-token …]
goproxify containers show <hôte|id> [-edge <passerelle>] [-format compose|portainer|portainer_inline|docker_run|kubernetes]
goproxify containers orphans [-admin-url …] [-token …]
```

`list` affiche pour chaque conteneur : le host, TLS, la passerelle source (son nom affiché, ou son groupe HA), l'Agent, le proxy qui le remplace (`REMPLACÉ PAR`, `-` s'il est servi par ses labels) et les backends.

Un conteneur arrêté, en pause ou qui redémarre reste listé : la colonne `BACKENDS` indique `inactif (<état>)` et il n'a ni proxy de remplacement ni conversion possible.

`convert` crée un proxy modifiable à partir de la route issue des labels (`POST /api/v1/proxies/from-discovered`). Le proxy prend la place de la route des labels sur son hôte ; désactivé ou supprimé, il la lui rend. `-edge` n'est utile que si plusieurs passerelles annoncent la même route.

`enable` / `disable` active ou désactive la route issue des labels d'un hôte (`PUT /api/v1/discovered-containers/enabled`) : désactivée, elle ne sert plus de trafic sur aucune passerelle, mais reste listée (`BACKENDS` indique `désactivé`) et se réactive avec `enable`. Le conteneur n'est pas touché. Pour un proxy configuré, voir `goproxify proxy enable`.

`show` affiche le bilan de sécurité de la route (score, TLS / WAF / rate limit) et les **labels à ajouter** (modèle de sécurité : un snippet de l'Admin du bon type s'il existe, sinon WAF en blocage et `100/s:50`). Avec `-format`, il imprime le jeu de labels **corrigé** prêt à coller (Compose, Portainer, `docker run`, Kubernetes) — rien n'est modifié sur le conteneur.

`orphans` liste les proxys créés par `convert` dont le conteneur d'origine n'est plus annoncé par sa passerelle (routes mortes probables).

Exemples :

```bash
goproxify containers
goproxify containers list
goproxify containers convert app.example.fr
goproxify containers disable app.example.fr
goproxify containers enable app.example.fr
goproxify containers show app.example.fr -format compose
goproxify containers orphans
```

---

### `goproxify me`

Profil de l'utilisateur connecté et gestion de ses tokens API personnels (PAT `gpx_pat_*`).

```
goproxify me get    [-admin-url …] [-token …]
goproxify me update [-email <email>] [-admin-url …] [-token …]
goproxify me passwd -current <mdp-actuel> -password <nouveau-mdp> [-admin-url …] [-token …]

goproxify me tokens list   [-admin-url …] [-token …]
goproxify me tokens scopes [-admin-url …] [-token …]
goproxify me tokens create -label <nom> -scopes <s1,s2,…> [-expires <RFC3339>] [-admin-url …] [-token …]
goproxify me tokens revoke <id> [-admin-url …] [-token …]
```

`tokens scopes` liste les scopes disponibles pour votre compte (dépend de votre rôle).
`tokens create` affiche la valeur du token une seule fois à la création.

Utilisée avec un PAT, une commande d'écriture exige le scope `:write` de sa ressource, un scope de lecture ne suffit pas : `certs:write` pour `cert` et `internal-ca`, `domains:write` pour `domain`, `alerts:write` pour `alert` (canaux, règles, `alert ack`), `logs:write` pour `logs delete` (`gdpr:reveal` pour `logs reveal-ip`), `security:write` pour `automation` (lectures : `audit:read`, compte admin). Voir le tableau complet dans [api_specs.md](api_specs.md#scope-pat-exigé-par-route). Depuis Admin `0.70.0`, un token créé avant doit être recréé avec ces scopes.

Exemples :

```bash
goproxify me get
goproxify me tokens list
goproxify me tokens scopes
goproxify me tokens create -label "CI pipeline" -scopes "proxies:read,logs:read"
goproxify me tokens create -label "tmp" -scopes "proxies:read" -expires 2026-12-31T23:59:59Z
goproxify me tokens revoke <id>
```

---

### `goproxify status`

État du cluster — nœuds (Passerelle, Agent HTTP) et agents WS.

```
goproxify status [-short]
  -short   Résumé compact (compteurs uniquement)
```

Exemples :

```bash
goproxify status
goproxify status -short
```

---

### `goproxify access`

GoProxify Access — portail opérateur (terminal web, SSH UUID, coffre secrets).

```
goproxify access config get        -edge <nom>
goproxify access config set        -edge <nom> -enabled true|false [-public-host <host>] [-theme auto|clair|sombre|ocean|foret|amethyste|contraste] [-views '[{"host":"presta.domaine.fr","theme":"ocean","groups":["<id-groupe>"],"target_ids":["<id-destination>"]}]']
goproxify access config push       -edge <nom>

goproxify access destinations list   -edge <nom>
goproxify access destinations create -edge <nom> -name <n> -kind ssh|docker -host <h> -port <p> [-tags a,b]
goproxify access destinations delete -id <uuid>

goproxify access users list          [-edge <nom>]
goproxify access users invite        -email <email> -home-edge <nom> [-tags a,b] [-groups <id>,<id>]
goproxify access users update        -id <uuid> [-status active|disabled] [-tags a,b] [-groups <id>,<id>]
goproxify access users resend        -id <uuid>
goproxify access users delete        -id <uuid>

goproxify access groups list         -edge <nom>
goproxify access groups create       -edge <nom> -name <n> [-description <d>] [-members a@example.com,b@example.com]
goproxify access groups update       -id <uuid> -name <n> [-description <d>] [-members a@example.com,b@example.com]
goproxify access groups delete       -id <uuid>
goproxify access destination-groups list   -edge <nom>
goproxify access destination-groups create -edge <nom> -name <n> [-description <d>] [-targets <id-dest>,<id-dest>]
goproxify access destination-groups update -id <uuid> -name <n> [-description <d>] [-targets <id-dest>,<id-dest>]
goproxify access destination-groups delete -id <uuid>

goproxify access policy get           -edge <nom>
goproxify access policy set           -edge <nom> [-hours true -days 1,2,3,4,5 -start 07:00 -end 20:00 -tz Europe/Paris -ip <cidr,…> -idle <min> -record true -retention <jours>]
goproxify access recordings list     -edge <nom>
goproxify access recordings get      -edge <nom> -id <uuid> > session.cast
goproxify access recordings delete   -edge <nom> -id <uuid>
goproxify access requests list        -edge <nom> [-status pending]
goproxify access requests approve     -id <uuid> [-minutes <n>]
goproxify access requests deny        -id <uuid>
goproxify access requests revoke      -id <uuid>
goproxify access sessions list        -edge <nom>
goproxify access sessions watch       -edge <nom> -id <uuid>
goproxify access sessions terminate   -edge <nom> -id <uuid>
goproxify access audit list          [-edge <nom>] [-limit <n>]

goproxify access templates list
goproxify access templates get  -key <clé>
goproxify access templates set  -key <clé> -body-file <chemin>
goproxify access templates push
```

---

### `goproxify nodes`

Nœuds Infrastructure — liste, état temps réel (`live` : santé, débit req/s et score de risque sur 60 s, cf. `GET /api/v1/nodes/live`), acceptation et rejet des nœuds en attente.

```
goproxify nodes list         [-role edge|agent]
goproxify nodes live
goproxify nodes accept       -id <pending-id>
goproxify nodes reject       -id <pending-id>
goproxify nodes revoke-stale-admin-tokens
goproxify nodes rotate-token -id <passerelle>
```

`rotate-token` renouvelle le jeton que l'Admin a pour une passerelle (identifiant ou nom), le lui pousse, lui fait révoquer l'ancien et redonne la liste des pairs aux autres passerelles (`POST /api/v1/nodes/:id/rotate-token`). L'Admin le fait déjà tout seul pour les membres restants d'un groupe quand l'un d'eux le quitte.

`revoke-stale-admin-tokens` fait révoquer par chaque passerelle connectée les jetons qu'un ancien Admin lui avait poussés, en gardant celui de l'Admin courant (`POST /api/v1/nodes/revoke-stale-admin-tokens`). À lancer après le remplacement de l'Admin ou si l'ancien est compromis ; une passerelle hors ligne doit être resollicitée à son retour.

---

### `goproxify declared`

Nœuds déclarés via le wizard d'architecture (upsert par rôle + nom).

```
goproxify declared list
goproxify declared create -role edge|agent -name <nom> [-region <r>] [-environment <e>] [-config '<json>']
goproxify declared delete  -id <dn_...>
```

---

### `goproxify bootstrap`

Tickets QR / `curl|bash` pour intégrer un hôte (lien `/i/{token}`).

```
goproxify bootstrap create [options]
  -host <nom>              Nom de l'hôte
  -edge-endpoint <url>     Endpoint passerelle (ex: http://192.0.2.10:8000)
  -ttl <heures>            TTL du ticket (défaut 24, max 168)
  -auto-accept true|false  Auto-accept des nœuds liés (défaut true)
  -node-names a,b          Noms pré-approuvés
  -payload '{...}'         Payload JSON
  -payload-file <path>     Payload depuis un fichier JSON
  -no-qr                   Omet le champ qr_code (base64) dans la sortie
```

Exemples :

```bash
goproxify bootstrap create -host host-1 -edge-endpoint http://192.0.2.10:8000 -node-names edge-main -no-qr
curl -fsSL "$(goproxify bootstrap create -host h1 -no-qr | jq -r .script_url)" | bash
```

---

### `goproxify hosts`

Hôtes déclarés dans `architecture.json` et leur installation par ticket ([ADR 0019](adr/0019-launcher-bootstrap-multi-hotes.md), étape 4).

```
goproxify hosts list
goproxify hosts join-ticket -host <nom>
```

- `list` : adresse, rôles, groupe HA, état (`pending`, `partial`, `joined`), nœuds et ticket en cours de chaque hôte.
- `join-ticket` : crée pour un hôte un ticket d'installation de 15 minutes (il remplace le précédent) et affiche le jeton, `spec_url` (où le launcher de l'hôte récupère sa description), `fingerprint` (empreinte SHA-256 du certificat de l'Admin), `trigger_url` et `qr_code` (le QR code à scanner, vers le launcher de l'hôte en attente sur son port 8080), `listen_command` (lance ce launcher en attente) et `join_command` (installe l'hôte tout de suite, sans QR code). `-no-qr` omet `qr_code` (base64) de la sortie. Refusé si l'hôte est déjà intégré.

---

### `goproxify update`

Mise à jour des images Docker (via l'Agent — non encore implémenté).

```
goproxify update check    [-container <nom>]
goproxify update apply    -container <nom> | -all [-prune] [-dry-run]
goproxify update rollback -container <nom>
```

---

### `goproxify migrate-yaml`

Convertit les fichiers de configuration proxy du format JSON (legacy) vers YAML.

```
goproxify migrate-yaml
```

Lit tous les fichiers `*.json` dans le répertoire de données (`/etc/goproxify` ou `GPX_DATA_PATH`) et les convertit en `*.yaml`. Les fichiers JSON d'origine sont conservés ; une erreur de conversion est signalée sans interrompre les autres fichiers.

Variables d'environnement :

| Variable | Usage |
|----------|-------|
| `GPX_DATA_PATH` | Répertoire racine des données (prioritaire) |
| `GPX_EDGE_CACHE_PATH` | Utilisé pour déduire le répertoire si `GPX_DATA_PATH` absent |

> Cette commande est destinée à la migration ponctuelle depuis les versions < 0.2. Les nouvelles installations utilisent directement le format YAML.

---

### `goproxify version`

Affiche les versions de tous les composants embarqués.

---

## Variables d'environnement communes

| Variable | Usage |
|----------|-------|
| `GPX_CONTROLPLANE_ADMIN_ENDPOINT` | URL Admin (remplace `-admin-url`) |
| `GPX_CONTROLPLANE_AUTH_TOKEN` | Token / PAT Admin (remplace `-token`) |
| `GPX_<SECTION>_<KEY>` | Surcharge n'importe quelle clé de config JSON |

Voir `.env.example` pour la liste complète des variables de configuration.

---

## Configuration JSON

Chaque composant accepte un fichier JSON optionnel (défaut : `./internal/<composant>/config.json`).

```
goproxify admin  -config /etc/goproxify/admin.json
goproxify edge   -config /etc/goproxify/edge.json
goproxify agent  -config /etc/goproxify/agent.json
```

Les variables `GPX_*` ont priorité sur les valeurs du fichier de config.
