# Sauvegardes — comment et quoi

Ce document décrit le menu **Sauvegardes** de l'Administration : le fonctionnement des snapshots, leur contenu exact, ce qui est volontairement exclu, et le comportement à la restauration.

## 1. Fonctionnement

| Élément | Détail |
|---|---|
| Format | JSON (`.gpx-admin-backup`), champ `version: "1"` |
| Déclenchement | Manuel (bouton, CLI) ou planifié (jusqu'à **5 planifications** : quotidienne, hebdomadaire, mensuelle, annuelle, ou cron libre) |
| Stockage | Fichier `<storage.base_path>/backups/<horodatage>_<nom>_<id>.snap` (copie de référence) ; la table `backup_snapshots` de la base Admin n'en garde que les métadonnées (nom, taille, somme de contrôle, vérification). Sans `storage.base_path`, ou si l'écriture du fichier échoue, le contenu reste dans la colonne `data` de la base. La rétention d'une planification supprime aussi les fichiers |
| Rétention | Par planification (`retention` = nombre max de snapshots, 0 = illimité). Les snapshots manuels ne sont jamais purgés automatiquement |
| Chiffrement | AES-256-GCM avec la clé de chiffrement des sauvegardes : variable `GPX_BACKUP_KEY`, ou clé générée / saisie dans *Sauvegardes › Clé de chiffrement* (§4 quinquies). Snapshot entier chiffré (préfixe `GPXBK1:`), relisible avec la clé active ou une clé retirée. Sans clé, le snapshot est en clair, **sans secrets et sans section `secrets`** (§4) |
| Import d'un fichier | Menu Sauvegardes → *Restaurer* : analyse (`/api/v1/import/backup/preview`), sélection des entités, application (`/api/v1/import/backup/apply`) |
| CLI | `goproxify backup create / list / restore` (voir [cli.md](cli.md)) |

## 2. Ce qui EST sauvegardé

### 2.1 Entités principales

| Entité | Contenu | Remarques |
|---|---|---|
| Proxies | Configuration complète de chaque proxy (route, TLS, WAF, headers…) + état activé | Restauration : republication vers les passerelles |
| Utilisateurs | `id`, e-mail, rôle | **Sans mot de passe** (voir §3) |
| Tokens de nœuds | `id`, rôle, rôle RBAC, nom et endpoint du nœud, expiration | Secret **jamais** exporté ; tokens révoqués ignorés |
| Scopes de tokens | `token_scopes` | |
| PAT (tokens API utilisateur) | Hash, préfixe, libellé, scopes, expiration | Hash non réversible ; PAT révoqués ignorés |
| Snippets | Nom, type, config | |
| Canaux d'alerte | Nom, type, config, activé | Secrets vidés (§4) |
| Règles d'alerte | Scope, déclencheurs, canaux, cooldown, priorité, activé | |
| Nœuds déclarés | Topologie de l'assistant infrastructure | Les nœuds synthétiques `cfg:*` sont ignorés |

### 2.2 Tables de configuration (section `tables`)

Sauvegardées telles quelles (toutes colonnes), avec redaction des secrets.

| Domaine | Table | Contenu |
|---|---|---|
| Paramètres | `settings` | Paramètres clé/valeur (dont l'allowlist d'IP du MCP `mcp.allowed_ips`) |
| Sauvegardes | `backup_schedule` | Planifications |
| Sécurité | `fail2ban_config`, `crowdsec_config` | Configuration des moteurs IPS |
| Automatisation | `flows`, `flow_state`, `flow_versions`, `automation_silences` | Flux d'automatisation (règles, planifications, playbooks), leur état, leurs versions et les mises en sourdine. Les exécutions (`flow_runs`, `flow_run_steps`) font partie de l'historique |
| Domaines & certificats | `domains`, `cert_deploy_targets` | Domaines, délégation DNS, cibles de déploiement de certificats |
| Authentification | `auth_providers` | Fournisseurs OIDC / SAML / LDAP… |
| Réseau | `ip_profiles`, `node_tunnel_configs` | Profils IP (listes, feeds), tunnels de nœuds |
| Équipes & RBAC | `teams`, `team_members`, `team_scopes`, `user_scopes` | |
| Workspaces | `workspaces`, `workspace_members`, `workspace_resources` | |
| Pages | `error_page_templates`, `error_page_assets`, `portal_page_templates` | Les assets binaires sont encodés en base64 |
| Portail Access | `portal_destinations`, `portal_users`, `portal_groups`, `portal_dest_groups` | Utilisateurs sans hash d'invitation |

### 2.3 Configuration HA et fichiers de config

Les paramètres de Haute Disponibilité (`NodeID`, `Peers`, `RaftPort`, voir [internal/admin/ha/ha.go](../internal/admin/ha/ha.go)) ne sont **pas** en base : ils viennent du fichier de config Admin (YAML/env), pas d'une table SQL. Ils ne sont donc inclus dans le snapshot que via la section `configs` (voir note ci-dessous) — un snapshot standard sans `ExportConfigs` **ne sauvegarde pas la config HA**.

## 3. Ce qui N'EST PAS sauvegardé (volontairement)

| Donnée | Raison |
|---|---|
| Mots de passe (hash), MFA, clés RGPD/ECH, CA interne | Hors section standard ; **inclus dans la section `secrets` chiffrée** (§4 bis) quand `GPX_BACKUP_KEY` est définie |
| Secrets en clair (voir §4) | Snapshot potentiellement téléchargeable |
| Logs, journal d'audit, historique de bans, menaces, CVE, alertes émises, événements de nœuds, exécutions des flux d'automatisation, déploiements de certificats | Volumineux : **hors snapshot par défaut**, sauvegardés à la demande dans la section `history` chiffrée (§4 quater) |
| Enregistrements de sessions du portail (`*.cast.gpx`), bases GeoIP, listes de menaces téléchargées, base de logs de la passerelle (`logs/`, sauf ses gels légaux) | Volumineux ou re-téléchargeables ; les logs d'accès restent sur la passerelle (365 jours, [ADR 0012](adr/0012-logs-proprietaire-edge.md)) et se conservent par un export (`goproxify edge logs export`) ou par le SIEM |
| Cumuls par minute (`logs_minute`) et compteurs d'erreurs par IP de l'Admin | Reconstitués : chaque passerelle garde les siens et les renvoie depuis le début (la valeur de chaque minute est remplacée). Les positions de ces deux flux ne sont donc pas sauvegardées |
| Certificats TLS et clés privées de la passerelle | Repris avec l'état de la passerelle (`edge-cache.gpx`, §4 quater) ; ceux de l'Admin (`certs/`, CA interne) sont dans la section `secrets` |
| Autres snapshots (`backup_snapshots`) et historique des proxies (`proxy_history`) | Éviter la récursivité ; l'historique a son propre mécanisme de restauration |
| Nœuds actifs / agents enregistrés (`nodes`, `pending_nodes`) | État dynamique ; les nœuds se ré-enregistrent |

> La config HA effective (`NodeID`, `Peers`, `RaftPort`, lue du fichier **et** des variables `GPX_*`) et `admin.json` sont jointes à la section `secrets` (§4 bis) sous `config/admin-ha.json` et `config/admin.json`. À la restauration elles sont écrites dans `<storage.base_path>/restored-config/` : la configuration vivante n'est jamais écrasée, à vous de la reprendre. Les fichiers `edge.json` et `agent.json` ne sont pas lus par l'Admin ; `edge.json` est repris avec l'état de la passerelle (§4 quater).

## 4. Gestion des secrets

À l'export, sont **vidés** (`""`) :
- le secret des tokens de nœuds ;
- dans les canaux d'alerte : `password`, `token`, `secret`, `api_key`, `app_token`, `user_token`, `webhook_url`, `authorization`, `private_key` ;
- dans les tables de configuration : toute clé JSON dont le nom contient `secret`, `password`, `passwd`, `token`, `api_key`, `apikey`, `private_key`, `credential`, `webhook_url` ou `authorization` (ex. `client_secret` OIDC, identifiants DNS) ;
- dans `settings`, `fail2ban_config`, `crowdsec_config` : la valeur de toute clé dont le nom correspond à ces motifs ;
- `portal_users.invite_token_hash`.

**Conséquence** (snapshot sans clé `GPX_BACKUP_KEY`, donc sans section `secrets`) : après une restauration sur une instance vierge, il faut ressaisir ces secrets (tokens de nœuds à ré-émettre, secrets OIDC, identifiants DNS, webhooks…). À la restauration, un secret vidé **n'écrase jamais** une valeur déjà présente.

## 4 bis. Section `secrets` (restauration d'une infrastructure complète)

Si `GPX_BACKUP_KEY` est définie, le snapshot contient en plus une section `secrets` chiffrée à part (AES-256-GCM, préfixe `GPXSEC1:`), même si le reste du fichier est lisible. Elle n'est **jamais** écrite sans clé (journal : avertissement).

| Contenu | Détail |
|---|---|
| Tables sensibles, lignes brutes | `users` (hash des mots de passe), `tokens` (secrets des nœuds), `user_api_tokens`, `user_mfa`, `user_backup_codes`, `user_trusted_devices`, `gdpr_keys`, `ech_keys`, `internal_ca`, `internal_ca_certs`, `cert_pull_tokens`, `alert_channels`, `team_permissions`, `user_permissions` (permissions de capacité : restaurées par le seul superadmin) |
| Tables de configuration, non rédigées | Celles des tables du §2.2 que la rédaction modifie, avec leurs secrets (secrets OIDC/SAML/LDAP, identifiants DNS, webhooks…) |
| Fichiers hors dossiers | `admin-secrets.json` : le **secret racine** (`GPX_PAIRING_SECRET`) et ses précédents (`GPX_PAIRING_SECRET_PREVIOUS`), dont dérivent les clés de toutes les passerelles et de tous les Agents ; `admin-tls.crt` et `admin-tls.key` : le certificat TLS de l'Admin (chemins `GPX_ADMIN_TLS_CERT` et `GPX_ADMIN_TLS_KEY`) ; la config HA effective et `admin.json`. À la restauration ils sont déposés dans `restored-config/`, jamais dans la config vivante : ils servent à reconstruire un Admin sur une machine neuve. Le secret JWT n'y est pas (il ne sert qu'aux sessions) |
| Fichiers | Copie du dossier `<storage.base_path>/state/` (`architecture.json`, magasins utilisateurs et configuration, `acme-providers.yaml` : fournisseurs DNS nommés et leurs identifiants) et de `<storage.base_path>/certs/` (CA interne, certificats) ; fichiers de plus de 8 Mo ignorés |

**Restauration** : case *Secrets* (décochée par défaut) de la fenêtre *Restaurer*, ou `import_secrets` dans la sélection. Réservée au **superadmin**. Les lignes sont remplacées (ordre : utilisateurs d'abord) et les fichiers réécrits ; redémarrer l'Admin ensuite pour qu'il relise `state/`. Une restauration de snapshot sans corps, ou par la CLI, l'active d'office si le snapshot la contient. Une mauvaise clé fait échouer cette partie seule (`secrets_error`).

**Responsabilités** : un snapshot avec section `secrets` est sensible. La perte de `GPX_BACKUP_KEY` rend ces secrets irrécupérables : la conserver **hors du serveur**, séparément des snapshots. Le secret racine y figure : **une sauvegarde et sa clé réunies permettent de se faire passer pour l'Admin** auprès de toutes les passerelles et de tous les Agents. L'état des passerelles est joint (§4 quater) ; les fichiers propres à chaque Agent restent sur son volume (voir [volumes.md](volumes.md)).

## 4 ter. Destinations hors serveur, intégrité et alertes

| Élément | Détail |
|---|---|
| Destinations | Jusqu'à 10 : dossier local ou partage monté (`dir`), WebDAV, stockage compatible S3 (signature SigV4). Gérées dans *Sauvegardes › Destinations*, l'API `/backups/destinations` et `goproxify backup destinations` |
| Copie | Après chaque snapshot, sur toutes les destinations actives : écriture, relecture, comparaison de la somme de contrôle. Résultat par destination et par snapshot dans la liste (☁) |
| Rétention | Par destination (`retention`, 0 = illimité) : les copies les plus anciennes déposées par l'Admin sont supprimées. Supprimer un snapshot localement ne supprime pas ses copies externes |
| Secrets de destination | `password` et `secret_key` ne sont jamais renvoyés par l'API ; ils sont absents des snapshots standard et présents dans la section `secrets` chiffrée |
| Intégrité | SHA-256 enregistré à la création ; le snapshot est relu, déchiffré et contrôlé avant d'être accepté ; `POST /backups/snapshots/{id}/verify` ou le bouton *Vérifier* le refait. Un snapshot altéré est signalé « somme de contrôle différente » |
| Mémoire | Le résumé affiché à l'ouverture de la fenêtre *Restaurer* (noms des passerelles, comptes de lignes) est lu en flux, sans décoder les sections chiffrées, et la restauration n'en calcule pas. La vérification d'un snapshot ne décode pas son contenu : somme de contrôle, puis déchiffrement sur place de l'enveloppe AES-GCM (qui authentifie aussi les sections secrets et historique) et lecture de la version seulement — environ 2× la taille du snapshot en mémoire. Au démarrage, l'Admin aligne la limite souple de mémoire du runtime Go sur celle du conteneur (cgroup, 85 %) ou, sans limite de conteneur, sur la moitié de la mémoire de la machine, sauf si `GOMEMLIMIT` est défini ; après chaque sauvegarde il rend la mémoire au système. Près de la limite : près de la limite, le ramasse-miettes travaille davantage au lieu de laisser une sauvegarde volumineuse faire tuer l'Admin. Prévoir au moins 1 Go de mémoire pour l'Admin si les snapshots dépassent 50 Mo |
| Alertes | Déclencheur `backup_failed` : sauvegarde planifiée échouée, copie vers une destination échouée, planification manquée (contrôle toutes les 30 min, tolérance 1 h). À brancher sur un canal via une règle d'alerte |
| En cours | Pendant une sauvegarde, la page Sauvegardes affiche un bandeau animé (nom, phase — export, secrets et passerelles, historique, chiffrement, enregistrement, vérification —, durée) et les destinations en cours de copie ; la page se rafraîchit toute seule tant que ça tourne et le bouton *Créer* est neutralisé. Visible aussi depuis une autre session ou une planification (`GET /backups/status`, champ `running`) |
| État | Bandeau de la page Sauvegardes et `GET /backups/status` : clé absente, aucune destination, destination en échec, exécution manquée |

**Limites** : pas de SFTP ; pas de restauration directe depuis une destination (télécharger la copie, puis *Restaurer › fichier*) ; les envois ne sont pas relancés automatiquement (le prochain snapshot réessaie).

## 4 quater. Passerelles, Agents et historique

| Élément | Détail |
|---|---|
| État des passerelles | À chaque snapshot avec `GPX_BACKUP_KEY`, l'Admin interroge chaque passerelle enregistrée (`GET /internal/v1/backup/export`) et joint son état à la section `secrets` (clé `gateway/<nom>/<fichier>`) : `proxies/` et `proxies-revisions/`, les copies chiffrées `*.gpx` (portail, pairs, tunnels, Ephor, réglages…), `edge.json`, `edge-node-id`, `edge-tokens.db`, `bans.db` (copie cohérente à chaud par `VACUUM INTO`), `behavior-state.gpx` (note de risque, historique propre et références apprises du WAF et d'Ephor), `threat-state.gpx`, `group-card.gpx`, `pushed-journal.gpx`, `log-retention.gpx`, `agent-hmacs.json`, `join-tokens-used.json` et les états d'Agents. Repris depuis Edge `0.90.0` : la configuration et les curseurs de l'exporteur SIEM (`siem-config.gpx`, `siem-state.gpx`), la clé de signature des exports (`log-sign-key.gpx`) et leur audit local (`log-export-audit.jsonl`), la clé de pseudonymisation (`log-ip-key.gpx`), et **les gels légaux** (`logs/legal-holds.json` et `logs/held/`, les archives des lignes qu'ils gardent). Exclus : `geoip/`, `asn-db.gpx` (l'Admin la repousse à la reconnexion), le reste de `logs/` (les fichiers de période), `threat-lists/`, `*.mmdb`, enregistrements `*.cast.gpx` ; fichier > 16 Mo ignoré, 64 Mo au total par passerelle (réglables sur la passerelle : `GPX_BACKUP_MAX_FILE_MB`, `GPX_BACKUP_MAX_TOTAL_MB`). La passerelle répond **en flux**, un fichier à la fois, sans charger son état en mémoire ; les copies de bases SQLite passent par un dossier de travail du volume de données (`.gpx-backup-*`, nettoyé ensuite), si bien qu'un conteneur en système de fichiers en lecture seule fonctionne. Chaque fichier ignoré est signalé **avec sa raison** dans les journaux et par une alerte ; les fichiers de plus de 2 Mo sont listés au journal pour comprendre la taille d'un snapshot |
| Réglages sensibles de l'Admin | La **file des effacements d'IP à rejouer** (`edge_erasure_queue`) fait partie de la section `secrets` (Admin `0.180.0`) : c'est une obligation (droit à l'effacement), ses IP sont chiffrées par la clé RGPD qui y est aussi ; elle n'est plus perdue à la restauration. Les **valeurs des en-têtes** des destinations SIEM (`logs.siem`, jetons) sont vidées de la section standard quel que soit le nom de l'en-tête (`DD-API-KEY`, `X-Api-Key`…) et rendues par la section `secrets` ; restaurer la section standard sur un Admin qui a déjà sa configuration ne vide pas ses jetons |
| Passerelle injoignable | Le snapshot est créé quand même, l'incident est journalisé et une alerte `backup_failed` est émise (« Sauvegarde incomplète ») : une sauvegarde de passerelle silencieusement absente est un faux sentiment de sécurité |
| Restauration d'une passerelle | Avec les secrets, l'Admin renvoie à chaque passerelle de même **nom** son état (`POST /internal/v1/backup/restore`, chemins filtrés). Une passerelle absente de l'instance est signalée en erreur (l'enregistrer puis relancer). **Redémarrer la passerelle** ensuite : elle relit ses fichiers au démarrage. Les bases `.db` sont remplacées, leurs fichiers `-wal` / `-shm` supprimés. Une passerelle restaurée **sans** ses fichiers de logs repart d'une base neuve : elle le détecte (l'Admin a une position plus haute que tout ce qu'elle a attribué), l'Admin ramène sa position à 0 et reçoit tout ce que la nouvelle base contient ; l'exporteur SIEM fait de même pour ses curseurs (les destinations reçoivent alors quelques doublons, dédoublonnables par l'identifiant, plutôt que de sauter des lignes). Les lignes d'accès d'avant la restauration ne sont plus sur la passerelle |
| Agents | Chaque Agent approuvé copie ses fichiers d'état (`agent.token`, `agent.hmac`, `agent-node-id`, `agent-edges.json`) chez sa passerelle (message `agent_state`, à chaque connexion et après rotation du HMAC) ; ils font partie de l'état de la passerelle sauvegardé. Un Agent qui revient **sans** token ni HMAC (volume perdu) reçoit ses fichiers de sa passerelle (`restore_state`) ; le HMAC courant de la passerelle fait foi. Redémarrer l'Agent pour l'identité. Sans `GPX_IDENTITY_NODE_NAME`, un Agent au volume perdu reçoit un nouvel identifiant : il est alors un nouvel Agent à approuver |
| Historique | Option *Inclure l'historique* d'une planification, ou *Créer avec l'historique* : journaux, audit, bans passés, menaces, CVE, alertes émises, événements de nœuds, exécutions, historiques de déploiement et de proxy, audit et demandes du portail. Depuis Admin `0.180.0`, elle porte aussi les **positions des flux de lignes** (`edge_log_cursors`, accès et système) : restaurées avec les logs, les passerelles reprennent après la dernière ligne que l'Admin a, sans doublon ; sans historique, il n'y a ni logs ni positions et les passerelles renvoient tout (événements de sécurité et logs système, dans la limite de leur conservation). Section `history` chiffrée à part (`GPXHIS1:`), **clé obligatoire** (jamais en clair : adresses IP, actions d'administrateurs). `logs` : 100 000 lignes les plus récentes ; autres tables : 500 000. Restauration : case *Historique* (décochée par défaut, superadmin), **ajout sans écrasement** (identifiant déjà présent = ignoré). Les adresses IP des logs sont chiffrées par les clés RGPD : restaurer aussi les secrets, sinon elles restent illisibles |

**Taille** : un snapshot avec historique et états de passerelles peut peser plusieurs centaines de Mo (stocké dans `backups/`, plus dans la base depuis Admin 0.164.3). Réserver l'historique à une planification dédiée (hebdomadaire, par exemple) avec une rétention courte.

## 4 quinquies. Clé de chiffrement gérée depuis l'interface

| Élément | Détail |
|---|---|
| Source | `GPX_BACKUP_KEY` si elle est définie (elle l'emporte toujours, l'interface la montre en lecture seule) ; sinon la clé enregistrée sur le serveur dans `<storage.base_path>/keys/backup-keys.json` (0600, hors de `admin.db`, hors des dossiers repris par les snapshots) |
| Création | *Générer une clé* (256 bits) ou *Saisir une clé* (16 caractères au moins). Une clé générée n'est **affichée qu'une fois**, avec une case « je l'ai conservée » obligatoire |
| Rotation | Remplacer la clé conserve l'ancienne parmi les **clés retirées** : pour relire un snapshot, l'Admin essaie la clé active puis les retirées, si bien qu'aucun ancien snapshot ne devient illisible. *Ajouter une ancienne clé* couvre un changement de `GPX_BACKUP_KEY` ; *Oublier* retire définitivement une clé retirée (les snapshots qu'elle a chiffrés deviennent illisibles) |
| Révélation | Superadmin uniquement, avec son **mot de passe** (1 s d'attente et audit `backup_key_reveal_denied` si faux) ; jamais pour une clé venant de l'environnement. Chaque création, rotation, désactivation, révélation et oubli est audité (sévérité critique) ; l'empreinte (8 caractères du SHA-256) est la seule trace de la clé |
| Désactiver | La clé active passe parmi les retirées ; les snapshots suivants sont sans secrets |

**Limite à connaître** : la clé enregistrée sur le serveur est sur le même volume que `backups/`. Une copie de volume emporte donc les deux. La protection est celle du volume ; pour que les copies hors serveur restent illisibles à qui volerait le volume, définir `GPX_BACKUP_KEY` hors du serveur. Dans tous les cas, **conserver une copie de la clé ailleurs** : serveur perdu = clé perdue = snapshots indéchiffrables.

## 5. Restauration

| Point | Comportement |
|---|---|
| Restauration d'un snapshot (bouton *Restaurer*) | Ouvre une fenêtre listant le contenu du snapshot (compteurs par entité) : on coche les entités à restaurer (proxies, utilisateurs, tokens, PAT, snippets, canaux, règles, configuration) et le mode de conflit (**écraser** par défaut, ou ignorer). Sans sélection (API sans corps, CLI), applique tout : utilisateurs, tokens, PAT, snippets, canaux, règles d'alerte, nœuds déclarés, tables de configuration ; en mode **overwrite** (les lignes existantes de même identifiant sont remplacées) ; proxies republiés vers les passerelles ; planifications de sauvegarde rechargées |
| Snapshot de sécurité | Avant tout écrasement (restauration de snapshot ou import en `overwrite`), un snapshot `avant-restauration-<date>` / `avant-import-<date>` est pris automatiquement ; s'il échoue, l'opération est annulée. Il permet de revenir en arrière |
| Implications | Sous l'aperçu *Maintenant / Après restauration*, un panneau **« Ce que cela implique »** se recalcule à chaque case cochée et classe par gravité (danger, attention, information) : proxies recréés ou ramenés à la version du snapshot (changements faits depuis perdus), ce qui reste en place car une restauration ne supprime jamais rien, nœuds seulement *redéclarés* (machines ni redéployées ni ré-appairées), lignes de configuration écrasées, comptes et mots de passe, tokens non restaurables sans secrets, secrets écrasés (MFA, CA interne, clés), état des passerelles remplacé et redémarrage nécessaire, config HA copiée dans `restored-config/`, redémarrage de l'Admin, historique ajouté sans écrasement, snapshot de sécurité. Une section chiffrée illisible (clé absente ou fausse) est signalée avant de valider |
| Version | Une sauvegarde dont la `version` n'est pas `1` est refusée |
| Résultat | Compteurs par entité : proxies, utilisateurs, tokens, PAT, snippets, canaux, règles, lignes de configuration, nœuds déclarés, ignorés, erreurs |
| Restaurer un seul proxy | Fenêtre *Restaurer* : liste des proxies du snapshot (recherche, cases, « Tous / Aucun », « Seulement celui-ci » qui décoche tout le reste) ; chaque proxy indique s'il sera créé ou s'il existe. La topologie déclarée a sa propre case |
| Import d'un fichier (sélection) | Cases par entité : proxies, utilisateurs, tokens, PAT, snippets, canaux, règles, **configuration** (identique dans *Sauvegardes → Restaurer*, *Import* et l'assistant de premier démarrage) ; conflit `skip` (conserver l'existant) ou `overwrite` |
| Utilisateurs | Créés avec un mot de passe aléatoire ; en overwrite, seul le rôle est mis à jour |
| Ordre | Les tables de configuration sont restaurées dans un ordre fixe (settings → règles → domaines → équipes → workspaces → pages → portail) |
| Tokens de nœuds | Le secret n'étant jamais sauvegardé, les tokens de nœuds sont **ignorés** (comptés « ignorés ») à la restauration : les nœuds doivent être ré-appairés |
| Anciennes sauvegardes | Sans section `tables` : restauration inchangée, la case *Configuration* n'apparaît pas |
| Colonnes inconnues | Ignorées (compatibilité entre versions) |

## 5 bis. Reconstruire l'Admin sur une machine neuve

Si l'Admin est perdu mais pas ses passerelles, `goproxify launcher --restore <fichier> --name <hôte> --backup-key <clé>`, ou la section **Reconstruire depuis une sauvegarde** de l'interface du launcher (`:8080/design`) ([cli.md](cli.md#reconstruire-ladmin-depuis-une-sauvegarde--launcher---restore)) installe un Admin qui reprend de la sauvegarde ce que les autres composants attendent de lui, puis on restaure les données dans l'Admin neuf (§5). Rien de plus à faire côté passerelles et Agents si le secret racine est resté le même.

| Élément | Où il vit | Reconstruction |
|---|---|---|
| Secret racine | Environnement de l'Admin ; **section `secrets`** (`admin-secrets.json`) | **À restaurer** : les clés des passerelles et des Agents en dérivent. Sinon, il faut réinstaller chaque hôte |
| Clé de sauvegarde | À noter hors de l'Admin | **À fournir** : elle ouvre la section `secrets`. Introuvable, la sauvegarde ne se relit pas |
| Certificat TLS de l'Admin | Fichiers de l'Admin ; **section `secrets`** (`admin-tls.crt`, `.key`) | Conservé : même empreinte. Régénérable, au prix d'une nouvelle empreinte et d'un nouvel avertissement navigateur |
| `architecture.json` | Dossier `state/` ; **section `secrets`** | Déposé tel quel par le launcher |
| Comptes, proxys, règles, identifiants tiers (jetons DNS, canaux d'alerte), CA interne | Base de l'Admin ; **section `secrets`** | Restaurés depuis l'Admin (§5), pas par le launcher |
| Secret JWT | Environnement de l'Admin | Régénéré : les sessions ouvertes sont coupées, rien d'autre |
| Mot de passe du premier compte | Environnement de l'Admin | Sans objet : les comptes viennent de la base restaurée ; le compte temporaire se supprime |
| Clés dérivées (canal, Agents, portail) | Jamais stockées | Recalculées par le launcher depuis le secret racine : identiques |
| Clé locale d'une passerelle (`node.key`) | Volume de la passerelle ; jointe à l'état de la passerelle dans la sauvegarde (§4 quater) | Propre au nœud. Une passerelle neuve en génère une, mais ses copies chiffrées (`*.gpx`) ne se relisent qu'avec celle qui les a chiffrées : elles voyagent ensemble |

Ne se reconstruit pas : les journaux (hors historique inclus à la demande).

**Dans l'Admin** : l'onglet *Snapshots* de la page Sauvegardes a un panneau « Reconstruire l'Admin sur une machine neuve » (Admin 0.226.0) : on choisit l'hôte de la machine neuve (liste de `architecture.json`) et, si elle a changé d'adresse, la nouvelle ; la commande `docker run … --restore` est prête à copier, avec l'image du launcher de cette installation. La clé de sauvegarde n'y figure jamais (`<backup key>`) : l'Admin ne la montre qu'au superadmin, sur demande. Le panneau avertit si aucune clé n'est définie.

**Éprouvé** : sur Docker, installation par le launcher, création d'un compte, sauvegarde, destruction de tous les conteneurs et volumes, `launcher --restore`, restauration des données par l'API, redémarrage : même empreinte, même secret racine, même clé de canal de la passerelle, `architecture.json` identique à l'octet, comptes retrouvés avec leurs mots de passe. Passerelle et Agent étaient réinstallés avec l'Admin ; une passerelle qui aurait continué de tourner pendant ce temps n'a pas été essayée.

## 6. Recommandations

1. Définir `GPX_BACKUP_KEY` (**obligatoire** pour une restauration complète) et la conserver **hors** du serveur, séparément des snapshots. Une installation par le launcher la génère et l'affiche une seule fois à la fin (Agent 0.24.0) : notez-la.
2. Planifier au moins une sauvegarde quotidienne avec rétention ≥ 7.
3. Configurer au moins une **destination hors serveur** (§4 ter) ; à défaut, copier régulièrement `<storage.base_path>/backups/` hors de l'hôte.
4. Pour un cluster HA, définir `GPX_BACKUP_KEY` : la config HA effective est dans la section `secrets`, restaurée dans `restored-config/` (§2.3).
5. Pour les passerelles, vérifier dans la page Sauvegardes (ou les journaux de l'Admin) qu'aucune n'était injoignable lors du snapshot : une passerelle absente est signalée par une alerte `backup_failed`.
6. Tester une restauration sur une instance de test après tout changement majeur.

## 7. Taille de `admin.db` et de son WAL

L'Admin garde son journal d'écriture (`admin.db-wal`) sous 256 Mo : un point de contrôle `TRUNCATE` est lancé chaque minute, et `journal_size_limit` tronque le fichier après un point de contrôle complet. Une lecture très longue peut le retarder ; l'Admin le signale alors dans ses journaux (`point de contrôle WAL incomplet`).

La purge des logs libère des pages sans rétrécir le fichier. Une base **créée** par Admin ≥ 0.163.1 est en `auto_vacuum` incrémental et rend l'espace au disque (jusqu'à ~40 Mo par minute). Une base plus ancienne doit être compactée **une fois**, Admin arrêté, avec de la place libre ≥ à sa taille :

```bash
sqlite3 admin.db "PRAGMA auto_vacuum=INCREMENTAL; VACUUM;"
```

Si `admin.db-wal` est déjà énorme, l'Admin le recopie et le tronque au premier démarrage de cette version (plusieurs minutes pour quelques dizaines de Go) ; ne pas supprimer ce fichier à la main, il contient des écritures non encore reportées dans `admin.db`.

Avant Admin 0.164.3, chaque snapshot était gardé deux fois : dans la colonne `data` de `backup_snapshots` et dans `backups/` (1,7 Go de base pour 12 snapshots de 40 à 160 Mo sur un serveur réel). Au premier démarrage de cette version, l'Admin vide la copie en base de chaque snapshot dont le fichier existe et est **identique** (octet pour octet) ; un fichier absent est d'abord écrit depuis la base, un fichier différent laisse la copie en base intacte (avertissement dans les journaux). Les pages libérées ne rendent pas d'espace au disque tant que la base n'est pas compactée : refaire le `VACUUM` ci-dessus après cette migration.
