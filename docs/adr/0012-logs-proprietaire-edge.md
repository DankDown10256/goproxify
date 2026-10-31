# ADR 0012 — Logs : la passerelle possède ses lignes, l'Admin supervise

**Statut :** accepté, mis en œuvre (Admin 0.192.1, Edge 0.105.0) ; restent la compression des fichiers clos, l'échantillonnage par proxy et la mesure du coût des classements exacts sur une vraie base (voir « Questions tranchées ») · **Date :** 2026-10-20
**Remplace :** étapes 2 et 3 de l'ADR 0010, et oriente autrement son étape 1 · **Respecte :** ADR-0006 (autonomie des composants) · **Précise :** ADR-0002 (SQLite hors de l'Admin)

---

## Contexte

L'ADR 0010 traite un symptôme : une table `logs` de plus de 5 millions de lignes dans `admin.db`. Il propose de mieux ranger ces lignes sur l'Admin (cumuls par minute, base séparée, fichiers par période). Il ne remet pas en cause d'où elles viennent, et c'est là que se trouve le défaut de conception.

Trois constats, vérifiés dans le code le 2026-10-20 :

1. **Une coupure de l'Admin perd des logs pour de bon.** La passerelle écrit un fichier JSON local et pousse chaque ligne à l'Admin par `BroadcastToAdmins` (`internal/edge/ws/hub.go`). Sans Admin connecté la boucle d'envoi ne s'exécute pas : le lot disparaît. Il n'y a ni numéro de séquence, ni accusé de réception, ni rejeu à la reconnexion. Les canaux d'envoi (8 192 accès, 2 048 lignes système) jettent aussi leurs entrées quand ils sont pleins. Les logs de conteneurs de l'Agent sont relayés par la passerelle « sans stockage local » (`internal/edge/agenthandlers.go`) : ils se perdent de la même façon. La donnée existe encore dans le fichier de la passerelle, mais l'historique de l'Admin (Prism, SLO, anomalies, recherche) garde un trou que rien ne comble.
2. **L'Admin est devenu un point de passage des données.** L'ADR-0006 dit que l'Admin est « point de modification et de supervision, jamais point de passage du service » et que la passerelle fait tourner ce qui lui est confié. Ici, chaque requête de chaque passerelle est copiée vers un seul SQLite. La passerelle, qui produit la donnée, ne sait ni la chercher ni la résumer : son fichier JSON n'est lisible qu'à la main.
3. **Les volumes viennent de cette copie centrale.** 220 000 lignes d'accès par jour en octobre sur un serveur réel, environ 1 Ko par ligne index compris : près de 20 Go à 90 jours, environ 80 Go à un an, tous nœuds confondus. L'ADR 0010 les range mieux sur l'Admin, mais l'Admin les reçoit toujours toutes.

Deux faits d'environnement :

- Le pilote SQLite est `modernc.org/sqlite` (pur Go) : il ne chiffre pas les fichiers. Le chiffrement sera fait par colonne.
- L'ADR-0002 écrivait que la passerelle est « entièrement volatile (zéro disque) ». Ce n'est plus vrai : la passerelle a déjà une base SQLite des bans (`internal/edge/bansdb`) et plusieurs copies locales chiffrées (ADR-0006). Cette note de l'ADR-0002 est caduque.

---

## Décision

### 1. Répartition des rôles

| Composant | Rôle pour les logs |
|---|---|
| **Passerelle** | Propriétaire des lignes brutes de ses requêtes. Les garde dans une base locale, calcule les cumuls, sait chercher, effacer et exporter sans l'Admin. |
| **Admin** | Supervision : reçoit des cumuls, des compteurs et des événements de sécurité ; interroge les passerelles pour les lignes brutes ; garde son propre audit. Ne stocke plus les accès ordinaires. |
| **Agent** | Garde un curseur sur les logs de ses conteneurs et les redonne à sa passerelle après une coupure. |
| **Groupe HA** | Chaque membre possède ses propres lignes. La copie chez les pairs (Edge 0.109.0) est retirée : l'Admin garde l'historique de chaque passerelle (ADR 0018). |

Les logs d'accès (`status > 0`) sont le sujet principal. Les logs système de la passerelle suivent les mêmes mécanismes de stockage et de rejeu. L'audit de l'Admin et ses propres logs système restent sur l'Admin, dans leur table : il en est le producteur.

### 2. Base de logs locale sur la passerelle

- **Fichiers** : un SQLite par semaine pour les accès, un par mois pour le système, dans le dossier `logs/` de la passerelle. Seul le fichier courant est ouvert en écriture.
- **Écriture** : par lots (jusqu'à 500 lignes ou 250 ms), branchée sur la goroutine qui écrit déjà chaque requête. Un disque plein ou une base corrompue fait perdre des lignes ; ils ne ralentissent jamais le trafic.
- **Identifiant global** : `(numéro de fichier << 40) | rowid`, croissant. C'est le curseur de tous les consommateurs.
- **Rétention** : **365 jours** pour les accès (durée de conservation des données de connexion confirmée par le propriétaire du produit), par suppression du fichier entier, sans `DELETE` ni `VACUUM`. Dans le fichier à cheval sur la limite, la purge par ligne s'applique. Les durées restent réglables par type et par passerelle. Cette valeur remonte celle de 90 jours posée par Admin 0.163.0.
- **Statistiques** : `ANALYZE` à la fermeture d'un fichier de période.
- **Le fichier JSON actuel est supprimé** : la base le remplace. L'effacement RGPD qui réécrivait ces fichiers (`internal/edge/logger/erase.go`, écritures suspendues pendant la réécriture) devient un `DELETE` par empreinte d'IP. Suivre les logs en direct et alimenter un SIEM passent par le flux de la base (sections 6 et 7), pas par un fichier.

### 3. Protection de l'IP, sur la passerelle

Aujourd'hui, en mode pseudonymisation, la passerelle envoie l'IP réelle à l'Admin, qui la chiffre avec sa clé (`internal/admin/logs/store.go`). La passerelle étant propriétaire, c'est elle qui chiffre :

| Mode | Ce que la passerelle stocke |
|---|---|
| Normal | IP réelle en clair |
| Anonymisation | IP tronquée seulement ; l'IP réelle n'est gardée nulle part |
| Pseudonymisation | IP tronquée visible, plus l'IP réelle chiffrée (AES-GCM) avec la clé locale, et une empreinte HMAC pour la retrouver |

- **Clé** : aléatoire, propre à la passerelle, scellée par le chiffrement local existant (`cache.Store.SaveFile`, dérivé du secret d'appairage). Elle fait partie de la sauvegarde d'état ; le dossier `logs/` en est exclu.
- **L'IP réelle ne quitte plus la passerelle.** L'Admin ne la reçoit plus, ce qui est un gain RGPD net.
- **Révéler une IP** et **chercher par IP** : l'Admin envoie la demande, la passerelle déchiffre ou calcule l'empreinte avec sa propre clé. Il n'y a plus d'index commun entre passerelles, et il n'en faut pas.
- **Groupe HA** : une clé par membre, chaque membre révèle ses lignes. Une clé de groupe partagée élargirait ce qu'une seule compromission expose.
- **Perte de la clé** : les lignes pseudonymisées deviennent illisibles. D'où l'inclusion dans la sauvegarde d'état.
- Les primitives (`Encrypt`, `Decrypt`, `IPIndex`, `CanonicalIP` de `internal/admin/gdpr`) sont extraites dans un paquet neutre utilisé par l'Admin et la passerelle. La clé de l'Admin continue de servir pour ses logs d'audit.

### 4. Cumuls et événements envoyés à l'Admin

- **Cumuls par minute** : nœud × domaine × code de statut, avec requêtes, 5xx, refus, octets, somme des latences et comptes par bucket de latence (mêmes bornes que `internal/edge/metrics`). Aucune IP. Ils sont écrits par la passerelle **dans la même transaction que le lot de lignes** : ils ne peuvent pas diverger des lignes, ce que la tâche de fond actuelle de l'Admin (`internal/admin/logs/agg.go`) ne garantit pas. Ils sont envoyés à l'Admin avec un numéro de séquence et conservés 400 jours.
- **Compteurs d'erreurs 4xx par IP et par minute**, pour le Fail2Ban global de l'Admin (`internal/admin/fail2ban`). Même règle qu'aujourd'hui : rien n'est envoyé pour une IP tronquée. Conservés 24 h sur l'Admin. Chaque passerelle bannit déjà seule (Fail2Ban local plus propagation des bans) : l'Admin n'ajoute que la vue globale.
- **Événements de sécurité en lignes brutes** : refus 403 et 429, détections WAF, signaux Ephor. Petit volume, conservés sur l'Admin (90 jours, réglable) pour la trace d'IP, la simulation Ephor et l'activité WAF, même si une passerelle est éteinte.
- **Ce que l'Admin ne reçoit plus** : les accès ordinaires (200, 304, etc.).
- **Lecteurs de l'Admin** : `monitor` et `automation` (fenêtres de 5 minutes) lisent les cumuls ; `topology_live`, `analytics/*`, Prism et SLO aussi. Les IP uniques et les facettes passent par la recherche déportée ou, pour les IP uniques, par un sketch HyperLogLog dans le cumul (question ouverte).

### 5. Flux avec curseur et rejeu

- L'Admin retient, par passerelle, le dernier numéro reçu pour chaque flux (cumuls, événements de sécurité, système).
- À la connexion WebSocket il demande « depuis N » ; la passerelle rejoue depuis sa base. Déduplication par (passerelle, numéro).
- **Une coupure de l'Admin ne perd plus rien**, y compris si la passerelle redémarre pendant la coupure : la base est locale. C'est le correctif du premier constat, et il est livrable avant tout le reste.
- **Agent** : curseur sur les logs de chaque conteneur (reprise par l'option `since` de Docker), rejeu vers sa passerelle à la reconnexion. Livraison au moins une fois.

### 6. Recherche déportée

La recherche est une **capacité de la passerelle**, pas un composant à part. Elle suit le canal Admin→passerelle qui existe déjà (`edgeproxy.Client` et les routes `/internal/v1/...`).

- **Routes** de la passerelle : recherche, histogramme, facettes, export, révélation d'IP. Lecture seule, une ou deux requêtes à la fois, délai maximal, fenêtre par défaut de 24 h. Au-delà, le résultat est marqué « partiel ».
- **Page « Logs d'accès »** : 50 lignes par page, comme aujourd'hui. Menu d'une passerelle : appel direct. Menu global : l'Admin demande 50 lignes à chaque passerelle, fusionne par date et garde les 50 plus récentes. Le curseur devient un jeton opaque portant la position de chaque passerelle.
- **Histogramme et facettes** : sur les cumuls quand les filtres se limitent à passerelle, domaine et code ; sur les lignes brutes de chaque passerelle sinon.
- **Total** : plafonné (« 10 000+ »).
- **Passerelle injoignable** : ses lignes manquent, et la page l'affiche (« résultats incomplets »). C'est le coût principal de ce choix, accepté.
- **Mode Live** : l'Admin abonne les passerelles seulement quand une vue est ouverte. Aujourd'hui chaque ligne part en permanence, même sans spectateur.
- **Export depuis la page** : limité en nombre de lignes ; au-delà, l'export complet de la section 8.
- **Prism et la recherche** sont deux vues des mêmes données, séparées par leur nature : Prism lit les cumuls (rapide, indépendant des passerelles), la recherche lit les lignes brutes.

### 7. Exporteur SIEM

Consommateur du flux de la passerelle, avec son propre curseur persistant.

- Syslog RFC 5424 sur TCP/TLS, et HTTP en NDJSON (Splunk HEC, Elastic, Loki). OTLP plus tard.
- Livraison au moins une fois ; l'identifiant global sert à dédupliquer.
- Filtrage par type (accès, système) et par niveau.
- Configuration poussée par l'Admin et gardée en copie locale chiffrée.
- SIEM injoignable : le curseur reste en place. La rétention passe quand même, pour ne pas remplir le disque, et une alerte signale un retard sur des données qui vont être purgées.

### 8. Export complet pour les autorités, sans l'Admin

Commande locale de la passerelle (binaire Edge), utilisable Admin éteint.

- **Contenu** : toutes les lignes d'une plage, filtrables par IP et domaine, avec l'IP réelle déchiffrée par la clé locale. NDJSON ou CSV, sans pagination d'interface.
- **Intégrité** : manifeste avec empreintes SHA-256, signé par une clé de la passerelle, horodaté. La valeur de preuve dépend de l'heure de la passerelle (NTP).
- **Accès** : opérateur privilégié, sortie chiffrée par mot de passe, entrée dans l'audit local.
- **Minimisation** : on exporte ce qui est demandé, pas toute la base.
- **Gel légal** : un indicateur par période qui empêche la purge tant que la procédure dure.
- **Groupe HA** : un export par membre, chacun avec son manifeste.

### 9. Effacement RGPD

`TypeEraseIPs` et la file `edge_erasure_queue` de l'Admin (`internal/admin/gdpr/erasure_queue.go`) existent déjà : l'Admin envoie l'ordre, le garde pour une passerelle absente et le rejoue à sa reconnexion. Ils sont conservés. Changements : l'effacement devient un `DELETE` par empreinte d'IP dans la base de la passerelle, et la purge de la file passe de 90 à 365 jours pour suivre la rétention.

---

## Alternatives écartées

- **Garder l'Admin dépositaire et améliorer son stockage** (ADR 0010 tel quel) : ne corrige ni le trou après une coupure, ni l'inversion des rôles. Reste valable pour les tables que l'Admin garde (audit, événements de sécurité).
- **Garder le fichier JSON en plus de la base** : double les écritures. Aucun usage de ce fichier n'est documenté (aucune mention de SIEM, syslog ou `tail` dans `docs/deployment.md`, `docs/fonctionnalites.md` ni la roadmap) ; le flux de la base couvre les deux besoins.
- **Chiffrer le fichier SQLite entier** : `modernc.org/sqlite` ne le permet pas, et SQLCipher imposerait cgo. Le chiffrement par colonne vise ce qui est personnel (l'IP).
- **DuckDB, ClickHouse, PostgreSQL pour les logs** : un service ou une dépendance de plus, déjà écartés par l'ADR 0010. À reconsidérer au-delà de quelques dizaines de millions de lignes par jour et par passerelle.
- **Journal binaire maison** : écrit plus vite mais oblige à écrire un moteur de requêtes.
- **Clé de pseudonymisation partagée dans le groupe HA** : élargit l'effet d'une compromission. Une clé par membre.

---

## Conséquences

**Gains**

- Plus de trou de données sur coupure de l'Admin, redémarrage de la passerelle compris.
- L'Admin ne porte plus le volume des accès : cumuls (quelques milliers de lignes par jour et par passerelle), compteurs, événements de sécurité, audit.
- L'IP réelle ne quitte plus la passerelle.
- Une passerelle peut chercher, effacer et exporter ses logs sans l'Admin (ADR-0006).
- Les écritures de logs de l'Admin deviennent marginales.

**Coûts et risques**

- La recherche brute dépend de passerelles joignables ; la page affiche un résultat incomplet sinon.
- Une couche de lecture multi-passerelles à écrire : fusion, curseur composite, délais, export, MCP, CLI.
- Une base SQLite à entretenir sur chaque passerelle : disque (environ 80 Go par an sur l'ensemble des nœuds au trafic actuel, à mesurer par passerelle), compression éventuelle des fichiers clos.
- Débit d'écriture : mesuré en livraison 1 (`BenchmarkAddAndFlush`, Windows 386, IP chiffrée, 5 index) à environ 26 µs par ligne, soit près de 39 000 lignes par seconde : l'écriture n'est pas le facteur limitant, le volume sur disque l'est. À 1 000 requêtes par seconde, une passerelle écrit environ 86 millions de lignes par jour, soit de l'ordre de 86 Go par jour à 1 Ko par ligne : au-delà de quelques dizaines de millions de lignes par jour, échantillonnage par proxy (les cumuls restent exacts) ou SIEM comme stockage.
- Migration d'une vingtaine de lecteurs de la table `logs` côté Admin (analytics, monitor, automation, fail2ban, sécurité, MCP).
- Conservation légale d'un an face au droit à l'effacement : la rétention reste réglable, c'est à l'exploitant de la fixer selon sa situation.

**Autonomie (ADR-0006)** : la passerelle fonctionne, journalise, cherche, efface et exporte sans l'Admin, même après un redémarrage. Si l'Admin tombe, seuls l'historique centralisé et la recherche transversale s'interrompent, puis se rattrapent à la reconnexion.

**Migration** : aucune instance n'est déployée en production. L'ancienne table `logs` d'accès, `logs_minute` alimentée depuis les lignes et l'envoi brut sont remplacés sans reprise ni façade de compatibilité.

---

## Ordre de mise en œuvre

Chaque livraison tient seule.

1. Base de logs locale de la passerelle et clé de l'IP (remplace le fichier JSON). L'envoi à l'Admin reste inchangé. *Livrée en Edge 0.74.0* : `internal/edge/logstore`, dossier `engine.log_store_dir`, rétention `engine.log_retention_days` (365) et `engine.system_log_retention_days` (90), clé dans `log-ip-key.gpx` (variable `GPX_LOG_IP_KEY_PATH`), primitives partagées dans `internal/ipcrypt`. Jusqu'à la livraison 3, l'Admin reçoit encore l'IP réelle et la chiffre aussi.
2. Numéro de séquence et rejeu, pour la passerelle et pour l'Agent : le trou disparaît. *Livrée en Edge 0.75.0 / Admin 0.165.0 pour la passerelle* : messages `log_resume` (Admin → passerelle) et `log_stream` (passerelle → Admin), position écrite avec les lignes dans `edge_log_cursors`, flux `access` et `system`. *Agent livré en Agent 0.12.0 / Edge 0.76.0* : l'Agent reprend sa lecture Docker (`since`) depuis une position qu'il n'avance qu'après l'accusé de réception de la passerelle (`log-cursors.json`), et la passerelle garde les logs de conteneurs dans sa base (flux `system`, composant `agent`) avant d'acquitter.
3. Cumuls, compteurs par IP et événements de sécurité calculés à la passerelle ; migration des lecteurs de l'Admin ; l'Admin cesse de recevoir les accès ordinaires. **Découpée**, parce que l'Admin ne peut cesser de recevoir les lignes brutes qu'une fois la recherche déportée en place (sinon la page « Logs d'accès », la trace d'IP et la simulation Ephor se vident) :
   - **3a. Cumuls par minute calculés à la passerelle.** *Livrée en Edge 0.77.0 / Admin 0.166.0* : table `minute` dans chaque fichier d'accès, écrite dans la même transaction que les lignes ; flux `minute` (`agg_stream`) vers l'Admin, qui remplace la valeur de la minute dans `logs_minute` et enregistre la position dans la même transaction ; l'agrégation des lignes brutes de l'Admin ignore une passerelle qui envoie ses cumuls. L'Admin reçoit encore les lignes brutes.
   - **3b. Compteurs d'erreurs 4xx par IP** pour le Fail2Ban global de l'Admin. *Livrée en Edge 0.78.0 / Admin 0.167.0* : table `ip_errors` (minute × IP, 48 h) dans les fichiers d'accès, flux `iperr` (`ip_stream`) avec le même contrat que les cumuls, table `edge_ip_errors` côté Admin (24 h), jamais pour une IP tronquée ; le Fail2Ban de l'Admin additionne les compteurs de toutes les passerelles qui en envoient et lit encore les lignes brutes des autres. La minute qui contient le début de la fenêtre n'est pas comptée (moins de bans, jamais plus).
   - **3c. Arrêt de l'envoi des accès ordinaires** et copie brute des seuls événements de sécurité sur l'Admin : après la livraison 4, avec la migration des lecteurs restants de la table `logs` (voir livraison 8).
4. Recherche déportée, page « Logs d'accès », CLI et MCP. **Découpée** : *4a livrée en Edge 0.79.0 / Admin 0.168.0* — routes `/internal/v1/logs/{search,histogram,facets,reveal}` sur la passerelle, `source=edge` sur les routes de logs de l'Admin (fusion, curseur par passerelle, passerelles injoignables, révélation d'IP chez la passerelle), parité vérifiée avec la copie de l'Admin. *4b livrée en Admin 0.169.0 / Edge 0.80.0* : l'interface lit les passerelles (bandeau « résultats incomplets », pagination par `cursor`, révélation par référence de ligne), fusion avec les logs propres de l'Admin (passerelle locale), CLI (`-source edge`) et MCP (`source=edge`), filtre `request_id`. *Reste* : le mode Live à la demande, qui suivra l'arrêt de l'envoi brut (3c).
5. Effacement RGPD sur la nouvelle base, purge de la file à 365 jours. *Livrée en Admin 0.177.0 / Edge 0.86.0* (voir « Effacement RGPD sur les bases des passerelles »). *Corrigé en Admin 0.192.1* : la file n'était purgée qu'à 365 jours fixes alors qu'une passerelle peut garder ses accès jusqu'à 3 650 jours (réglage de l'Admin, `logs.edge_retention`) ; un ordre dure maintenant autant que la plus longue conservation que l'Admin impose, 365 jours au moins. Une passerelle qui garde plus longtemps par son seul `edge.json` n'est pas connue de l'Admin.
6. Exporteur SIEM. *Livrée en Edge 0.87.0 / Admin 0.178.0* : paquet `internal/edge/siem`. Chaque passerelle lit sa base de logs avec un curseur par destination et par type (`siem-state.gpx` à la racine du volume, donc dans la sauvegarde d'état ; variable `GPX_SIEM_STATE_PATH`), livre au moins une fois (le lot échoué est renvoyé tel quel après attente 1 s → 1 min, le curseur n'avance qu'après accusé) et démarre au boot avec la copie chiffrée de sa configuration (`siem-config.gpx`, variable `GPX_SIEM_CONFIG_PATH`), sans l'Admin. Syslog RFC 5424 (comptage d'octets RFC 6587, TCP ou TLS, élément structuré `gpx@32473`) et HTTP NDJSON (2xx = accusé) ; identifiant `passerelle:type:id`. Filtres : type, niveau, « sécurité seulement » (accès signalés par le WAF ou Ephor). Une nouvelle destination part de « maintenant » ou de N heures en arrière. L'Admin garde la configuration (réglage `logs.siem`, jetons des en-têtes masqués à la lecture), la pousse à chaque passerelle à l'enregistrement et à sa connexion, reçoit l'état toutes les 30 s (`siem_status`) et alerte (`siem_export_lag`) quand le retard dépasse le seuil de la destination (60 min par défaut) ; l'alerte devient critique quand le retard dépasse 80 % de la conservation, c'est-à-dire quand des lignes vont être purgées avant livraison. *Complété en Edge 0.89.0 / Admin 0.179.0* : destinations de type `otlp` (OTLP/HTTP JSON, `ExportLogsServiceRequest` par `POST`, mêmes en-têtes, mêmes filtres, mêmes curseurs) et champ `nodes` par destination (l'Admin ne pousse à chaque passerelle que les siennes, sans ce champ ; retirer une passerelle de la liste éteint la destination chez elle et supprime son curseur).
7. Export complet signé et gel légal. *Livrée en Edge 0.88.0* : paquet `internal/edge/logexport` et commandes `goproxify edge logs export|verify|hold|key|audit`. Base ouverte en lecture seule (`logstore.Options.ReadOnly`), IP réelle déchiffrée par la clé locale, sortie AES-256-GCM par blocs (clé scrypt), manifeste Ed25519 (clé dédiée `log-sign-key.gpx`), audit local chaîné (`log-export-audit.jsonl`), gel légal par plage de dates (`logs/legal-holds.json`, relu à chaque purge ; registre illisible = aucune purge). Questions ouvertes tranchées : gel par plage de dates, clé de signature dédiée. Un gel ne bloque pas un effacement RGPD explicite. *Gel par filtre livré en Edge 0.89.0* : `hold add -ip` / `-domain` copie les seules lignes visées dans `logs/held/<id>/` (à la pose, puis à chaque purge pour les lignes arrivées depuis) avant que la rétention supprime leur fichier ; l'export relit ces archives (sans doublon avec un fichier entamé), l'effacement RGPD les vide aussi, `hold release` les supprime. Si la copie échoue, le fichier n'est pas purgé.
8. Nettoyage de l'Admin : arrêt des accès ordinaires bruts (3c), migration des lecteurs restants, retrait de la table `logs` d'accès, de l'agrégation des lignes brutes et de l'envoi `access_log`. *Livrée en Admin 0.175.0 / Edge 0.85.0 (arrêt de l'envoi), Admin 0.176.0 (lecteurs et agrégation brute), Admin 0.178.1 / Edge 0.88.1 (mode `all` retiré)*. La table `logs` de l'Admin subsiste pour ses propres lignes, les événements de sécurité reçus et les logs système des passerelles.

## Questions tranchées

- **IP uniques** : un résumé fusionnable par passerelle, calculé à l'affichage et non stocké dans les cumuls (`internal/ipsketch`) : liste exacte jusqu'à 2 000 adresses, sketch HyperLogLog au-delà (environ 0,8 % d'erreur), et la réponse dit si le chiffre est estimé. Livré en Admin 0.171.0 / Edge 0.81.0.
- **Période des fichiers d'accès** : la semaine (lundi 00:00 UTC), le mois pour le système. Livré en Edge 0.74.0. Un fichier par jour pour de très gros volumes n'est pas fait : à reprendre si une passerelle dépasse la dizaine de millions de lignes par jour.
- **Événements de sécurité copiés sur l'Admin** : les accès signalés par le WAF ou Ephor (`waf_matches` ou `threat_signal` non vides) et les logs système des passerelles ; durée de la copie : `retention_access_days` (90 jours par défaut, réglable). Les refus 403 et 429 qu'aucun moteur n'a signalés restent dans les cumuls et dans la base de la passerelle.
- **Compression des fichiers clos** : non faite. Un fichier clos est en lecture seule et supprimé en entier à l'échéance ; la compression ferait de chaque lecture une décompression. À reprendre après une mesure du disque sur une passerelle à 365 jours.
- **Échantillonnage par proxy** des accès réussis : non fait. Il entrerait en conflit avec l'export complet, et les cumuls restent exacts sans lui. Le défaut reste « tout journaliser ».

## Restes

- **Coût des classements exacts** : un classement lit la période jusqu'à trois fois par passerelle (voir l'annexe, étape 2). À mesurer sur une vraie base avant de promettre une durée de fenêtre.
- **Compression** et **échantillonnage** : voir ci-dessus, selon la mesure du disque et du débit.

---

## Annexe — Inventaire des lecteurs de la table `logs` de l'Admin (livraison 3c)

Relevé du 2026-10-20, sur le code de `main` après la livraison 4b. Arrêter l'envoi des accès ordinaires à l'Admin suppose qu'aucun de ces lecteurs ne dépende encore des lignes brutes. Chacun est classé selon la donnée dont il a besoin, et la façon de la lui fournir autrement. Les mots « approchée » du relevé initial sont remplacés par les décisions de la fin de l'annexe : les tops sont exacts.

**Trois primitives à ajouter côté passerelle**, les mêmes que celles de la recherche déportée (livraison 4a) :

- **P1 · Regroupement par dimension** (`/internal/v1/logs/top`) : pour une période et des filtres, les N valeurs les plus fréquentes d'un champ (`path`, `ip`, `user_agent`, `referrer`, `tls_ja4`, `domain`, `status`), avec pour chacune le nombre de requêtes et des compteurs de refus (403 et 429), d'erreurs de backend (5xx), de détections WAF et de signaux Ephor. L'Admin additionne les réponses des passerelles et garde les N premières : exact pour toute dimension grâce à l'algorithme de seuil décrit en fin d'annexe.
- **P2 · Filtre d'IP par plage** dans la recherche (`ip_from` / `ip_to`, comme les bornes `idx_logs_ip_ts` d'aujourd'hui) : pour la trace d'IP, l'aperçu d'un ban et l'analyse d'un ASN.
- **P3 · Lecture massive** : la recherche par pages de 100 000 lignes existe déjà (`bulk`) ; elle sert la simulation Ephor et les exports.

| # | Lecteur (fichier) | Donnée nécessaire | Migration | Exactitude |
|---|---|---|---|---|
| 1 | `analytics/analytics.go` · KPIs, courbe, codes HTTP (`GetKPIs`, `GetTimeline`, `GetStatusGroups`) | requêtes, erreurs, octets, latence par minute | `logs_minute` pour **toute** fenêtre d'au moins une minute (aujourd'hui : une heure et sans filtre IP ni chemin) ; un filtre IP ou chemin passe par P1 | exacte |
| 2 | `analytics/slo.go` · `GetSLO`, `countReqErr` | requêtes et 5xx | `logs_minute` (déjà utilisé au-delà d'une heure) | exacte |
| 3 | `analytics/anomalies.go` · `GetBackendErrors`, `DetectAnomalies` | taux d'erreur par proxy, référence | `logs_minute` (jointure avec `proxies`) | exacte |
| 4 | `monitor/monitor.go` · `accessEvents`, présence des nœuds | erreurs et latence par domaine sur 5 min ; nœuds actifs sur 6 h | `logs_minute` (somme des latences, codes) ; présence par les battements | exacte |
| 5 | `automation/conditions.go` · taux de 5xx par proxy | requêtes et 5xx par domaine | `logs_minute` | exacte |
| 6 | `api/topology_live.go` · `trafficByNode` | requêtes, refus, 5xx par nœud sur la dernière fenêtre | **pas** les cumuls : la fenêtre est de 60 s, sondée toutes les 5 s, et des minutes entières compteraient jusqu'à deux fois le trafic. La passerelle rapporte son débit récent (requêtes, refus, 5xx sur 60 s) dans son battement | exacte |
| 7 | `analytics/analytics.go` · tops (`GetTopPaths`, `GetTopIPs`, `GetTopAgents`, `GetTopReferrers`), `analytics/tlsfp.go` · `GetTopTLSFingerprints`, `GetUniqueIPs` | valeurs les plus fréquentes d'un champ de ligne | **P1** | exacte (tops, algorithme de seuil en trois tours) ; **IP uniques** : résumé fusionnable, exact tant qu'il est petit, estimé à environ 1 % au-delà |
| 8 | `analytics/geoip.go` · `GetGeoBreakdown`, `GetGeoPoints`, `GetLiveIPs` | IP les plus fréquentes, résolues en pays ; IP actives dans les dernières minutes | **P1** : énumération des IP de chaque passerelle avec leurs comptes, union chez l'Admin, puis regroupement par pays ou par ville avec le cache de géolocalisation ; `GetLiveIPs` par la recherche de chaque passerelle — **livré (étape 2)** | exacte (comptes par IP, puis pays) |
| 9 | `analytics/geoip.go` · `resolve` (alimente `geoip_cache`) | IP jamais vues | résolution **à la demande** pour les IP d'une page ou d'un top, au lieu d'un balayage des nouvelles lignes | — |
| 10 | `api/prismapi_bans.go` · historique d'une IP bannie | requêtes, erreurs, premier et dernier passage, 5 premiers chemins d'une IP | **P1** (`ip` exacte) + recherche | exacte pour une IP |
| 11 | `api/security_banpreview.go` · aperçu d'un ban | requêtes de la plage d'IP sur N heures, par IP | **P1** sur `ip` avec **P2**, compteurs refus/WAF/Ephor | exacte (algorithme de seuil) |
| 12 | `api/security_asn.go` · analyse d'un ASN | requêtes de toutes les IP de l'ASN sur N heures | **P1** sur `ip` avec plages (**P2**) | exacte (algorithme de seuil) |
| 13 | `api/security_iptrace.go` · trace d'une IP ou d'un CIDR | lignes de la période, regroupées en épisodes | recherche (**P2**, **P3**) | exacte |
| 14 | `api/security_waf_activity.go` | détections WAF par domaine | **copie brute des événements de sécurité** sur l'Admin (décidée plus haut), ou P1 | exacte |
| 15 | `api/ephor_sim.go` · simulation d'une configuration Ephor | jusqu'à 200 000 requêtes récentes (heure, IP, chemin, statut) | lecture massive (**P3**) auprès de chaque passerelle, ou simulation exécutée sur la passerelle (elle a le moteur) — **décidé le 2026-10-20 : sur la passerelle** (elle a le moteur et les lignes ; l'Admin envoie la configuration, reçoit le verdict) | exacte |
| 16 | `analytics/analytics.go` · `ExportCSV/JSON/HTML` (Prism) | jusqu'à 50 000 lignes | **P3** | exacte |
| 17 | `logs/subject.go` · export RGPD d'une personne, `DeleteByIP` / `DeleteByUserID` | lignes d'une IP ou d'un compte | export : recherche par IP chez chaque passerelle ; effacement : déjà relayé aux passerelles (`erase_ips`) | exacte |
| 18 | `fail2ban/fail2ban.go` · repli sur les lignes brutes | erreurs par IP des passerelles sans compteurs | supprimé : les passerelles d'avant 0.78 n'alimentent plus le Fail2Ban global | — |
| 19 | `mcp/server.go` · `toolGetMetrics` | requêtes, erreurs, latence, IP uniques sur 24 h | `logs_minute` ; IP uniques comme au point 7 | exacte, sauf IP uniques |
| 20 | `logs/store.go` · `Search`, `Export`, `Facets`, `Histogram`, `Correlate*` | lignes de l'Admin lui-même | inchangés : ne portent plus que sur `component=admin` | — |
| 21 | `logs/agg.go` · agrégation depuis les lignes brutes | cumuls des sources sans flux de cumuls (audit de l'Admin) | réduite aux lignes de l'Admin ; supprimée pour les passerelles | — |

**Ordre de livraison.** Chaque étape se vérifie par un test de parité contre le résultat actuel, calculé sur les lignes brutes que l'Admin garde encore :

1. Lecteurs sur cumuls (1 à 6, 19) : exacts, sans nouvelle API, et ils suppriment la dépendance la plus répandue.
2. P1 puis les tops de Prism (7, 9) et la carte (8).
3. P2 puis les lecteurs par IP (10 à 13) et la trace.
4. Exports et export RGPD (16, 17), simulation Ephor (15) selon la décision.
5. Copie brute des événements de sécurité (14) — et le Live à la demande.
6. **Arrêt effectif** de l'envoi des accès ordinaires, retrait du repli Fail2Ban (18) et de l'agrégation brute (21), une fois que plus rien n'en dépend.

**Décisions (2026-10-20)** : le traitement se fait à l'affichage, sans rien stocker de plus. *Les tops sont exacts* : l'Admin interroge les passerelles en trois tours (algorithme de seuil, « TPUT » : les meilleurs de chacune, tous les éléments au-dessus d'un seuil calculé, puis les comptes exacts des candidats restants), au prix de deux ou trois requêtes courtes par passerelle ; le classement est le vrai, pas une somme de tops partiels. *Les IP uniques sont fusionnées sans doublon* : chaque passerelle rend un résumé qui se fusionne (liste exacte tant qu'elle reste petite, sketch HyperLogLog d'environ 1 % d'erreur au-delà), l'Admin en fait l'union, et la réponse indique si le chiffre est exact ou estimé. *Tranché ensuite (2026-10-20)* : la simulation Ephor se fait sur la passerelle.

### Avancement de l'étape 1 (Admin 0.170.0)

Migrés vers les cumuls par minute, chacun avec un test de parité contre le résultat des lignes brutes : KPIs, courbe et codes HTTP de Prism **pour toute durée de fenêtre** (plus de seuil d'une heure), SLO, erreurs par backend (`GetBackendErrors`), alertes du `monitor` (taux d'erreur et latence par domaine, passerelles actives), condition d'automatisation « taux d'erreur d'un proxy », métrique `get_metrics` du MCP (sauf les IP uniques, qui restent à l'étape 2). Les cumuls sont à la minute et incluent les deux bornes : une fenêtre non alignée compte jusqu'à 59 s de trafic en plus de chaque côté, et la période précédente d'un KPI s'arrête avant la minute où la courante commence, pour ne pas la compter deux fois. Le repli sur les lignes brutes reste en place tant que l'historique n'est pas rattrapé (`AggReady`) ; il disparaîtra avec l'arrêt de l'envoi brut. *Restent* : la topologie (débit récent rapporté par la passerelle), les règles d'anomalies par IP et par pays (étapes 2 et 3).

### Avancement de l'étape 2 (Admin 0.171.0, Edge 0.81.0)

**Décision (2026-10-20) : la simulation Ephor s'exécute sur la passerelle**, qui a le moteur et les lignes ; l'Admin ne lui envoie que la configuration à tester et reçoit le verdict. Elle sera livrée avec les lecteurs de l'étape 4.

Livré : la primitive **P1** et les lecteurs qui n'ont besoin que d'un classement ou d'un compte.

- **Passerelle** : `POST /internal/v1/logs/top` (champs `path`, `ip`, `component`, `referrer`, `tls_ja4`, `domain`, `status` ; modes `best`, `above`, `exact`) et `GET /internal/v1/logs/unique-ips`. Mêmes filtres que la recherche, plus `domains` (liste) et `path_prefix`. Une passerelle qui a plus de 200 000 valeurs au-dessus du seuil rend les premières et se déclare partielle.
- **Admin** : `internal/admin/edgetop` applique l'algorithme de seuil (TPUT) : K meilleures de chaque passerelle, toutes les valeurs au-dessus de `⌈τ₁/m⌉`, comptes exacts des candidats restants. *Vérifié* : 600 tirages aléatoires (1 à 6 passerelles, beaucoup d'égalités) rendent le classement et les comptes d'un `GROUP BY` sur l'union des lignes, et jamais plus de trois appels par passerelle ; une passerelle qui tombe en cours de route est écartée et le calcul recommencé sans elle, pour que les seuils restent cohérents. `internal/ipsketch` fait l'union des IP : liste exacte jusqu'à 2 000 adresses, sketch HyperLogLog (16 384 registres, environ 0,8 % d'erreur) au-delà ; la réponse dit si le chiffre est estimé.
- **Prism** (`internal/admin/prismedge`) : chemins, IP, composants, référents, empreintes TLS (dont les IP distinctes de chacune), IP uniques des KPIs, répartition par pays, carte par ville et accès récents de la carte en direct lisent les passerelles. La répartition par pays et la carte énumèrent les IP de chaque passerelle avec leurs comptes, l'Admin en fait l'union puis regroupe avec son cache de géolocalisation ; les IP absentes du cache sont **résolues à la demande** (`GeoResolver.Ensure`), ce qui rend inutile le balayage des nouvelles lignes une fois l'envoi brut arrêté (ligne 9). `source=admin` force la lecture de la copie de l'Admin ; une passerelle d'avant cette version (route absente, 404) fait aussi répondre la copie.
- **Passerelle manquante ou lente** : la réponse porte `X-Prism-Unreachable` (noms) et `X-Prism-Partial`, `X-Prism-Estimated` ; l'interface affiche un bandeau (à partir de la réponse `unique-ips`, qui interroge toutes les passerelles).
- **Parité** : `internal/edge/prism_edge_e2e_test.go` — trois passerelles réelles et un Admin réel, les mêmes 630 requêtes dans leurs bases et dans la copie de l'Admin ; chaque classement (6 filtres × 7 listes, avec pages, recherche, préfixe, IP, domaines multiples), les IP uniques, les pays, les villes et les accès récents sont identiques. Les égalités sont départagées par valeur croissante sur les passerelles ; la copie de l'Admin ne les départage pas, le test compare donc les comptes rang par rang et chaque entrée à celle de la copie.

*Coût mesuré à surveiller* : un classement exact lit la période jusqu'à trois fois par passerelle (un `GROUP BY` sans index sur le champ) ; le délai est de 20 s par lecture et la passerelle limite à deux lectures simultanées. À mesurer sur une vraie base avant de promettre une durée de fenêtre.

*Restent* : tops du Fail2Ban par IP, aperçu d'un ban, analyse d'un ASN (étape 3, avec le filtre d'IP par plage), exports et RGPD (étape 4), copie brute des événements de sécurité et Live (étape 5), arrêt effectif (étape 6).

### Avancement de l'étape 3 (Admin 0.172.0, Edge 0.82.0)

Livré : **P2** (filtre d'IP par plage) et les lecteurs par IP.

- **Passerelle** : `ip_from` / `ip_to` (un intervalle de la colonne texte `ip`, sur-ensemble aligné sur les octets que l'appelant raffine avec `TraceMatch`, comme `security.TraceIPRange` le faisait pour l'index de l'Admin), `ip_ranges` (jusqu'à 400 intervalles `de|à` séparés par des virgules, pour un ASN) et `attributable` (écarte les IP tronquées). `POST /internal/v1/logs/top` ajoute à chaque valeur les requêtes **refusées ou signalées** (403, 429, WAF, Ephor), les requêtes **réussies non bloquées**, le premier et le dernier passage, et un champ `all` qui rend un seul groupe, les totaux de la sélection.
- **Aperçu de ban et analyse d'ASN** (lignes 11 et 12) : les passerelles énumèrent les IP de la plage ou de toute la période avec leurs comptes, l'Admin additionne, garde celles que la cible contient et calcule exactement les mêmes champs qu'avant (requêtes, bloquées, réussies, IP, IP réussies, top 10, pays). Le plafond de lecture de 500 000 lignes disparaît : les comptes sont exacts ; `scan_limited` ne vaut vrai que si une passerelle est elle-même partielle. Une passerelle injoignable ajoute un avertissement.
- **Historique d'une IP** (ligne 10, `prism/ip-scan`) : totaux, premier et dernier passage par `all`, cinq premiers chemins par le classement exact. La recherche par IP retrouve maintenant aussi les lignes pseudonymisées de cette IP, par leur empreinte.
- **Trace d'IP** (ligne 13) : les passerelles servent les lignes (accès et système) par pages de 20 000, la plus récente d'abord, jusqu'à 400 000 lignes en tout (`scan_limited` au-delà : les plus anciennes manquent) ; l'Admin les trie, forme les épisodes et calcule le résumé comme avant. `partial` et `unreachable` apparaissent dans le résumé.
- **Anomalies de Prism** : « IP dominante » (IP attribuable la plus active) et « pays en erreur » lisent les passerelles.
- **Parité** (`internal/edge/prism_edge_e2e_test.go`) : aperçu de ban (4 cibles, dont une plage vide), historique d'une IP (3 IP), trace (une IP, une plage, une passerelle, une IP absente : résumé et étapes identiques) et anomalies (IP dominante et pays en erreur déclenchés) donnent les mêmes résultats par les passerelles et par la copie de l'Admin. La preuve de l'ASN passe par la même fonction que l'aperçu de ban (seul le filtre d'appartenance change).

*Restent* : Fail2Ban par IP sans repli brut (ligne 18, avec l'arrêt), exports Prism et RGPD (étape 4), simulation Ephor sur la passerelle, copie brute des événements de sécurité (WAF) et Live (étape 5), arrêt effectif (étape 6).

### Avancement de l'étape 4 (Admin 0.173.0, Edge 0.83.0)

Livré : exports de Prism, export RGPD d'une IP et simulation Ephor.

- **Exports de Prism** (ligne 16) : CSV et JSON lisent les 50 000 lignes d'accès les plus récentes de l'ensemble des passerelles (chacune en donne au plus 50 000, l'Admin fusionne par date et garde les premières ; lecture par pages de 20 000, un export à la fois par passerelle) ; le rapport HTML utilise les classements exacts et les IP uniques des passerelles. Vérifié contre la copie de l'Admin sur trois sélections (tout, un domaine, une passerelle).
- **Export RGPD d'une IP** (ligne 17) : ses lignes viennent des passerelles (100 000 au plus, pseudonymisées comprises, retrouvées par empreinte) ; les lignes propres de l'Admin restent celles de sa base. `gateways_missing` nomme les passerelles qui n'ont pas répondu : l'export est alors incomplet, et le dit. L'export d'un compte (`user_id`) ne lit que l'Admin, les passerelles n'attribuent pas leurs lignes à un compte. L'effacement d'une IP était déjà relayé aux passerelles (`erase_ips`).
- **Simulation Ephor sur la passerelle** (ligne 15, décidé) : `POST /internal/v1/ephor/simulate`. Chaque passerelle rejoue ses propres accès, ceux de la fenêtre et au plus 200 000, contre la configuration actuelle et la candidate avec `threat.Simulate`, **agents utilisateur compris** (la copie de l'Admin ne les avait pas : les règles `user_agent` n'étaient pas simulées). L'Admin additionne les rapports ; comme chaque passerelle applique Ephor à son seul trafic, c'est aussi plus fidèle qu'un rejeu mélangé, mais une IP vue par deux passerelles compte pour chacune et `top_ips` fusionne les dix premières de chaque passerelle (approximation de l'ordre au-delà). Avec une seule passerelle, le rapport est identique à celui de la copie de l'Admin (vérifié).

*Restent* : copie brute des événements de sécurité (WAF) sur l'Admin et mode Live à la demande (étape 5) ; arrêt effectif de l'envoi brut, débit récent de la topologie, retrait du repli Fail2Ban et de l'agrégation brute (étape 6).

### Avancement de l'étape 5 (Admin 0.174.0, Edge 0.84.0)

Livré, **sans encore rien arrêter** (le réglage vaut `all` par défaut) : tout ce qu'il faut pour que l'Admin ne reçoive que les événements de sécurité.

- **Réglage `logs.ship_access`** (`all` | `security`, dans les réglages des logs, audité ; **retiré en Admin 0.178.1 / Edge 0.88.1**, voir plus bas) : l'Admin l'annonçait à chaque `log_resume` et le redemandait à toutes les passerelles quand il changeait. En `security`, la passerelle n'envoie des accès que ceux que le WAF ou Ephor ont signalés (`waf_matches` ou `threat_signal` non vides) ; les logs système sont envoyés comme avant.
- **Curseur sans trou** : les accès écartés ne doivent pas être relus à chaque réveil. La lecture filtrée (`ReadSecurityAfter`) rend aussi `through`, la fin de la base au début de la lecture ; le lot le porte, l'Admin y avance son curseur dans la même transaction, et la passerelle n'envoie une avance sans ligne qu'au plus toutes les 30 s. Vérifié : 300 accès ordinaires, 5 événements, une coupure de l'Admin, 3 événements de plus — ils arrivent une fois chacun, aucun accès ordinaire ne passe, le curseur atteint la fin de la base.
- **Lecture des événements de sécurité par l'Admin** (ligne 14) : inchangée. `ComputeWAFActivity` lit les lignes `waf_matches` de la copie de l'Admin, qui continue de les recevoir ; elle n'a besoin ni de P1 ni d'une nouvelle table. La rétention de cette copie est celle des accès (`retention_access_days`, 90 jours par défaut, réglable), comme l'ADR l'avait décidé pour les événements de sécurité.
- **Live à la demande** : tant qu'une vue Live est ouverte (en mode `security` seulement), l'Admin envoie `log_live {ttl_sec: 30}` à chaque passerelle toutes les 10 s ; la passerelle suit sa base à partir de la position d'ouverture et envoie `log_live_rows` (accès et système, 500 lignes par seconde au plus, `dropped` si elle en saute), que l'Admin diffuse aux vues sans les enregistrer. Une Admin qui disparaît ne laisse donc pas les passerelles émettre plus de 30 s. Sans vue ouverte, rien n'est envoyé (vérifié). Les IP pseudonymisées arrivent tronquées, jamais en clair.
- **Restent (étape 6)** : passer le défaut à `security`, retirer l'envoi des accès ordinaires du code de la passerelle, la lecture brute de l'Admin (repli sur les lignes de Prism, monitor, automatisation, MCP, `logs_minute` alimentée depuis les lignes, agrégation brute, repli Fail2Ban) et rapporter le débit récent de la topologie.

### Sauvegardes et restauration (Admin 0.180.0, Edge 0.90.0)

La base de logs d'une passerelle (365 jours) n'est pas dans la sauvegarde d'état : trop volumineuse, et le SIEM ou l'export signé servent de conservation longue. Ce que le chantier a rendu nécessaire :

- **Edge** : les gels légaux (`logs/legal-holds.json`, `logs/held/`) sont repris et restaurables ; sans eux, une restauration levait les gels en silence. Les fichiers du SIEM (`siem-config.gpx`, `siem-state.gpx`), la clé et l'audit des exports étaient déjà dans l'état racine, donc repris.
- **Base de logs remplacée** : un identifiant n'est plus réattribué (`AUTOINCREMENT`, `LastID` lit le compteur) ; une passerelle dont l'Admin a une position plus haute que tout ce qu'elle a attribué (état restauré sans les logs, disque neuf) le signale (`log_stream` avec `reset`), l'Admin ramène la position du flux à 0 et reçoit la nouvelle base entière ; l'exporteur SIEM fait de même pour ses curseurs. Sans cela, les lignes de la nouvelle base, numérotées depuis 1, étaient prises pour déjà reçues et sautées.
- **Admin** : la file des effacements d'IP rejoint la section `secrets` ; les positions des flux de lignes rejoignent l'historique (avec les logs, jamais l'un sans l'autre) ; les cumuls par minute et les compteurs d'erreurs par IP ne sont pas sauvegardés (les passerelles les renvoient) ; les valeurs d'en-têtes SIEM sont vidées de la section standard (toutes, leur nom ne dit rien) et rendues par les secrets, sans effacer ceux d'un Admin qui en a déjà.

### Rétention des passerelles réglée depuis l'Admin (Admin 0.183.0, Edge 0.96.0)

La rétention de 365 jours vit dans la passerelle (livraison 1) mais ne se réglait que dans `edge.json`, et l'interface affichait celle de l'Admin, qui ne garde plus que les événements de sécurité. L'Admin impose maintenant une conservation commune plus des exceptions par passerelle (`logs.edge_retention`), poussée par `push_log_retention` ; la passerelle l'applique seule (`SetRetention`, purge horaire), la garde chiffrée (`log-retention.gpx`) et la relit avant `edge.json` au démarrage. Elle annonce ce qu'elle applique (`log_info`, 30 s) : l'interface s'en sert pour les périodes proposées. Sans réglage de l'Admin, `edge.json` et les défauts (365 et 90 jours) s'appliquent comme avant.

### Retrait du mode `all` (Admin 0.178.1, Edge 0.88.1)

Après le nettoyage de la livraison 8, plus aucun lecteur de l'Admin ne lisait les accès ordinaires : le mode `all` n'aurait produit qu'une copie inutile, coûteuse en disque et en écritures. Le réglage `logs.ship_access`, son champ d'API (`ship_access` de `GET/PUT /logs/settings`, l'audit `logs_ship_access`), le champ `access` de `log_resume`, la reprise forcée des passerelles au changement de réglage et la condition du Live (« seulement en mode `security` ») sont supprimés : la passerelle n'envoie jamais d'accès ordinaires, seulement les événements de sécurité, et le Live est toujours à la demande. Un `ship_access` encore envoyé par un client est ignoré. Les tests de reprise après coupure passent sur des événements de sécurité et vérifient les cumuls et les compteurs contre les lignes brutes que garde la passerelle.

### Avancement de l'étape 6 (Admin 0.175.0, Edge 0.85.0) : l'envoi brut s'arrête

- **Défaut `logs.ship_access = security`** : l'Admin ne reçoit plus des passerelles que les accès signalés par le WAF ou Ephor, les logs système, les cumuls par minute et les compteurs d'erreurs par IP. Les accès ordinaires restent dans la base de chaque passerelle (365 jours) et se lisent par la recherche, les classements, les exports et la trace. Le mode `all` (copie complète sur l'Admin) a été retiré ensuite : plus aucun lecteur de l'Admin ne lisait cette copie.
- **Topologie** (ligne 6) : la passerelle annonce toutes les 5 s son débit de la dernière minute (`edge_traffic` : requêtes, refusées 403/429, erreurs 5xx, lus dans sa base) ; l'Admin le retient en mémoire et l'oublie après 20 s de silence. La requête de l'Admin sur ses lignes est supprimée. Un Admin redémarré retrouve le débit à la prochaine annonce, soit 5 s.
- **Liste des domaines d'une passerelle** (filtre de Prism) : lue dans les cumuls par minute, plus dans les lignes.
- **Fail2Ban** (ligne 18) : le repli sur les lignes brutes est supprimé. Seuls les compteurs par IP des passerelles comptent ; les tests qui plaçaient des lignes brutes placent des compteurs, et ceux qui supposaient une précision à la seconde du déban tiennent compte de la minute.
- **Retrait de l'ancien envoi** : sans base de logs locale, la passerelle ne diffuse plus ses lignes en direct (le message `access_log` n'existe plus) ; un lot de logs d'Agent reçu sans base est refusé (`503`), l'Agent le garde et réessaie.
- **Ce qui continue de lire la table `logs` de l'Admin** : ses propres lignes (audit, process, requêtes de son API), les événements de sécurité reçus (page d'activité WAF), et, tant qu'elles existent, les lectures de repli de Prism, du moniteur, de l'automatisation, du MCP et des aperçus (utilisées quand aucune passerelle n'est enregistrée). Elles ne servent plus en exploitation normale ; leur suppression, avec celle de l'agrégation brute des lignes de passerelles (déjà exclues des cumuls), est le nettoyage de la livraison 8.

### Correctif de l'étape 6 (Admin 0.175.1, Edge 0.85.1) : Prism filtré par IP ou par chemin

L'arrêt de l'envoi brut laissait un trou : un filtre sur l'IP ou le chemin (clic sur une IP ou un chemin dans Prism) faisait calculer les KPIs, la courbe et les codes HTTP sur la table `logs` de l'Admin, qui n'a plus les accès ordinaires. Ils sont maintenant calculés par les passerelles : un regroupement `all` (totaux, robots compris), un regroupement par `minute` (que l'Admin range en heures, jours ou minutes locales) et par `status`, additionnés sans classement. L'écart des KPIs avec la période précédente utilise désormais le même filtre (la copie ne filtrait pas la période précédente, ce qui comparait une IP à tout le trafic). Les anomalies d'une sélection filtrée lisent la même source. Parité vérifiée contre la copie de l'Admin (une IP, un préfixe de chemin, chemin et domaines, une IP absente ; courbes par minute, heure et jour).

### Nettoyage de l'Admin (Admin 0.176.0) : plus aucune lecture de lignes d'accès

Une fois l'envoi arrêté, les lectures de repli sur la table `logs` n'avaient plus de raison d'être ; elles sont supprimées, sans façade.

- **Supprimé** : l'agrégation par minute depuis les lignes (`logs_minute` n'est plus alimentée que par les passerelles, la table `logs_minute_state` disparaît), les requêtes brutes de Prism (KPIs, courbe, codes HTTP, classements, IP uniques, carte, accès récents, exports, empreintes TLS), du SLO, des erreurs par backend, des anomalies, du moniteur, de l'automatisation, du MCP (`get_metrics`, géo, TLS), de l'aperçu de ban et d'ASN, de l'historique et de la trace d'IP, de la simulation Ephor, le balayage des nouvelles lignes par le géolocaliseur (les IP sont résolues à la demande) et les index `logs` qui servaient Prism.
- **Sans passerelle enregistrée** : les listes sont vides et les totaux nuls (il n'y a pas de trafic) ; la simulation Ephor est refusée (rien à rejouer). Des passerelles d'avant 0.81 répondent une erreur explicite, pas des chiffres faux.
- **Une anomalie de la migration trouvée en route** : `monitor.accessEvents` n'utilisait pas les cumuls (l'étape 1 n'avait branché que `accessRows`, jamais appelée) ; son test de parité ne pouvait pas le voir, les deux voies lisant les lignes. Après l'arrêt de l'envoi, les alertes de taux d'erreur n'auraient vu que les événements de sécurité. Corrigé : elles lisent les cumuls, avec un test sur les valeurs attendues.
- **Tests** : les tests de parité contre la copie de l'Admin n'ont plus d'oracle ; ils sont réécrits sur un oracle calculé à la main à partir du jeu d'essai (classements, KPIs filtrés ou non, courbes, pays et villes, accès récents, exports, aperçu de ban, historique d'IP, résumé de trace, simulation comparée au moteur). `internal/edge/logapi/logapitest` fournit aux tests de l'Admin une passerelle de logs sur une vraie base.
- **Ce qui reste dans la table `logs` de l'Admin** : ses propres lignes (audit, process, requêtes de son API), les événements de sécurité reçus, les logs système des passerelles. Le réglage `ship_access = all` reste possible mais plus aucun lecteur n'utilise cette copie, hormis la page Logs en `source=admin`.

### Réplication entre les membres d'un groupe HA (Edge 0.109.0)

La version initiale laissait chaque membre seul propriétaire de ses lignes : la vue d'un groupe dépendait de la présence de tous ses membres, et un disque perdu emportait l'historique de son membre. Chaque membre garde maintenant aussi les lignes de ses pairs.

- **Mécanisme** : un tirage toutes les 5 s par pair (`internal/edge/logs_replica.go`), sur le canal et la clé du groupe déjà utilisés pour les autres réplications (ADR 0014). Un membre demande à son pair les lignes **qu'il a lui-même écrites** après un identifiant, accès puis système, par lots de 2 000 (25 lots par tour : un membre neuf rattrape un an de logs sur plusieurs tours). Le curseur est un fichier par type et par pair (`replica-cursors.json` dans le dossier des logs) ; perdu, il ramène à 0 sans danger.
- **Stockage à part, dans les mêmes fichiers de période** : colonnes `origin` (nom du pair, vide pour une ligne propre) et `origin_id`, plus un index unique `(origin, origin_id, ts)` qui rend la réception idempotente. Un fichier plus ancien reçoit les colonnes à son ouverture.
- **Une copie n'est jamais « à soi »** : `ReadAfter`, la lecture des événements de sécurité, les cumuls par minute, les compteurs d'erreurs par IP, le trafic récent de la topologie, l'export signé et le gel légal ne lisent que `origin = ''`. L'Admin, le SIEM et les pairs ne voient donc chaque requête qu'une fois, de la passerelle qui l'a servie ; une copie n'est jamais retirée à un pair (pas de relais, donc pas de boucle).
- **Lecture** : par défaut une recherche, un classement ou un histogramme ne lit que les lignes propres de la passerelle, ce qui garde exacts les totaux que l'Admin additionne. `scope=group` ajoute les copies, `origin=<membre>` se limite à un membre ; chaque ligne répliquée porte `origin`.
- **Pseudonymisation** : « une clé par membre » tient. L'expéditeur déchiffre l'IP réelle de sa propre clé, la met dans le document chiffré par la clé du groupe, et le destinataire la rechiffre de la sienne : il la révèle et la retrouve par empreinte sans connaître la clé de l'autre. Un destinataire sans clé garde l'IP tronquée.
- **Base d'un pair remplacée** : `last` (dernier identifiant attribué par le pair) plus bas que le curseur → le curseur repart à 0 ; l'identifiant et la date distinguent les anciennes lignes des nouvelles qui reprennent les mêmes numéros.
- **Rétention** : les copies suivent celle du membre (une ligne plus vieille est écartée à la réception, la purge par fichier les emporte avec les siennes).
- **Effacement RGPD** : l'ordre de l'Admin est d'abord transmis aux pairs (`POST /internal/v1/replica/logs/erase`, jamais retransmis), puis exécuté ; sinon une copie ramènerait l'IP chez le membre qui vient d'effacer. Un pair injoignable reçoit l'ordre rejoué par l'Admin à sa connexion et le propage à son tour.
- **Coût** : chaque membre stocke le volume de tout le groupe (deux membres : deux fois le volume d'un seul). Écrire une copie s'ajoute à l'écriture des lignes propres, sur les mêmes fichiers.
- **Lecture par l'Admin (Admin 0.196.0, Edge 0.110.1)** : pour les lectures de lignes qui additionnent les passerelles (recherche, histogramme, facettes, classements, IP uniques, trace, exports, export RGPD), l'Admin remplace les membres d'un groupe par une seule cible et lit `scope=group` ; sur erreur réseau, `404`, `409`, `429` ou `5xx`, le membre suivant répond à sa place avec sa copie des lignes du premier (`scope=group` suffit : `origin=` n'est pas nécessaire, la copie est déjà dans la vue de groupe). Une ligne reste attribuée à son auteur (`origin`) ; sa référence désigne le membre qui a répondu (c'est sa base qui la numérote) ; le jeton de page reste celui du groupe. Le groupe reste détaillé tant qu'un membre tourne avant Edge 0.109.0 ou est inconnu de l'Admin, et un filtre sur une passerelle lit ses seules lignes. Restent par passerelle, car chacune agit sur son propre trafic : simulation Ephor, références apprises, révélation d'IP, effacement. Un membre tombé n'est plus signalé « injoignable » tant qu'un pair répond ; ce qu'il n'avait pas encore répliqué (moins de 5 s de lignes) manque. **Reste** : la reconstitution d'un membre à partir des copies de ses pairs (disque perdu) n'est pas faite : le membre neuf repart de sa propre base, il ne récupère pas ses anciennes lignes.

### Effacement RGPD sur les bases des passerelles (Admin 0.177.0, Edge 0.86.0)

L'effacement d'une IP existait déjà (ordre `erase_ips` mis en file, IP chiffrée, rejoué à chaque connexion pendant 365 jours, `DELETE` par adresse et par empreinte dans la base de la passerelle). Il manquait la **preuve** et un trou :

- **Preuve par passerelle** : `POST /internal/v1/logs/erase` (la passerelle efface et rend ses comptes). L'Admin l'appelle sur chaque passerelle joignable et répond `gateways: [{node_name, status, log_lines, ban_rows}]` ; `erased` = la passerelle a répondu avec ce qu'elle a supprimé, `pending` = elle n'a pas répondu et l'ordre mis en file lui sera rejoué. L'audit garde le total de lignes et le nombre de passerelles en attente, jamais l'IP en clair. La CLI l'affiche passerelle par passerelle.
- **Trou comblé** : les logs système (qui peuvent porter l'IP) n'étaient pas effacés ; ils le sont, comme les accès.
- **Garde** : une valeur qui n'est pas une adresse (« [pseudonymisé] ») est refusée (`400`) : elle effacerait d'un coup toutes les lignes pseudonymisées.
- **Vérifié** (`TestEraseIPReportsWhatEachGatewayDeleted`) : deux passerelles dont une arrêtée ; chez l'autre, les accès en clair, la ligne pseudonymisée et la ligne système disparaissent, les autres IP restent.
- **Limites assumées** : le texte libre d'un message de log système qui citerait une IP n'est pas retrouvable ; les sauvegardes et les exports déjà remis ne sont pas rouverts (voir la durée de conservation des sauvegardes).
