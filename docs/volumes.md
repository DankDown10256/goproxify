# Volumes Docker — GoProxify

Chaque service persiste ses données dans `/etc/goproxify` via un volume Docker dédié. Les trois volumes sont **distincts** : ne pas les partager entre services.

---

## `goproxify_admin_data` → `/etc/goproxify` (Admin)

| Chemin dans le volume | Contenu |
|---|---|
| `admin.db` | Base SQLite principale : comptes utilisateurs, proxies, tokens de nœuds, snapshots, alertes, audit log |
| `admin-node-id` | Identité stable du nœud Admin (générée au premier démarrage) |
| `error-pages/` | Pages d'erreur personnalisées par proxy |
| `ip-profiles/` | Profils IP persistés (listes blanches/noires par proxy) |

> **Important :** `admin.db` contient tout l'état opérationnel de l'Admin (configuration proxies, utilisateurs, secrets nœuds). Sa perte est irréversible sans snapshot. Utiliser `GPX_BACKUP_KEY` pour chiffrer les snapshots exportés.

## `goproxify_admin_logs` → `GPX_ADMIN_LOG_DIR` (Admin, volume de logs)

[ADR 0018](adr/0018-logs-geres-par-l-admin.md). L'Admin range **toutes** les lignes que chaque passerelle lui envoie dans un volume à part de celui de sa base de gestion. Sans `GPX_ADMIN_LOG_DIR`, le dossier est `edge-logs/` sous la racine de stockage (`/etc/goproxify/edge-logs`), donc dans le volume de l'Admin : monter un volume Docker dédié à cet emplacement les sépare.

| Chemin dans le volume | Contenu |
|---|---|
| `<id passerelle>/access-<lundi>.db`, `<id passerelle>/system-<mois>.db` | Un store par passerelle, du même moteur que sa base de logs : un fichier SQLite par semaine pour les accès, par mois pour les logs système. Rétention par suppression du fichier entier (365 jours pour les accès, 90 pour le système, fixes pour l'instant). Un fichier clos ne change plus : sauvegarde incrémentale possible |
| `<id passerelle>/node.json` | Identifiant et nom de la passerelle, pour reconnaître un dossier dont la passerelle a été retirée ou renommée |

La position de chaque flux est écrite dans le fichier de période, dans la même transaction que les lignes : un volume restauré n'a ni trou ni doublon, et une passerelle renvoie ce qui lui manque. Monter ce volume sur un Admin à la base neuve retrouve l'historique ; la passerelle renvoie son tampon, que le store écarte (déjà reçu).

> **Clé de pseudonymisation :** l'IP réelle d'une ligne pseudonymisée est chiffrée avec la clé de l'Admin, qui est dans `admin.db` (section `secrets` des snapshots, `GPX_BACKUP_KEY`). Restaurer le volume de logs **sans** la clé de l'Admin rend ces IP illisibles : sauvegarder les deux ensemble.

```yaml
services:
  admin:
    environment:
      GPX_ADMIN_LOG_DIR: /var/lib/goproxify-logs
    volumes:
      - goproxify_admin_data:/etc/goproxify
      - goproxify_admin_logs:/var/lib/goproxify-logs
volumes:
  goproxify_admin_logs:
```

---

## `goproxify_edge_data` → `/etc/goproxify` (Passerelle)

| Chemin dans le volume | Contenu |
|---|---|
| `proxies/` | Configurations de production des proxies (fichiers YAML, un par proxy) |
| `proxies-revisions/` | Historique des révisions pipeline (`<id>--<rev>.yaml`) |
| `edge-cache.gpx` | Cache interne de la passerelle (état runtime, reconnexion rapide) |
| `edge-tokens.db` | Base SQLite des tokens d'authentification des nœuds (Admin → passerelle) |
| `agent-states/` | Fichiers d'état des Agents approuvés, copiés par chaque Agent (rendus à un Agent au volume perdu) |
| `edge-node-id` | Identité stable du nœud passerelle |
| `threat-config.gpx` | Copie chiffrée de la configuration d'Ephor reçue de l'Admin |
| `threat-state.gpx` | Copie chiffrée des scores cumulés et fenêtres d'erreurs d'Ephor (écrite toutes les 5 min et à l'arrêt) |
| `behavior-state.gpx` | Copie chiffrée du magasin comportemental : notes en cours, historique propre des IP (7 jours), références de débit apprises |
| `asn-db.gpx` | Copie chiffrée de la base IP → ASN poussée par l'Admin (agrégat par ASN d'Ephor) |
| `geoip/GeoLite2-Country.mmdb` | Base GeoIP téléchargée automatiquement (clé `geoip.auto_download` de `edge.json`, activée par défaut) |
| `geoip/GeoLite2-City.mmdb` | Base GeoIP ville de l'Admin (carte Prism), téléchargée automatiquement (clé `geoip.auto_download` de `admin.json`, activée par défaut) ; sans elle, les IP restent sans position (le repli sur ip-api.com n'est actif qu'avec `geoip.allow_external_lookup: true`, hors RGPD par défaut) |
| `bans/` | Bannissements IP persistés |
| `threat-lists/` | Listes de menaces téléchargées (IPs malveillantes, etc.) |
| `threat-config.gpx` | Copie chiffrée de la configuration Ephor reçue de l'Admin, rechargée au démarrage sans l'Admin |
| `group-card.gpx` | Fiche du groupe HA (membres, domaines, version) déclarée par l'Admin, chiffrée par la clé locale du nœud (surchargeable par `GPX_GROUP_CARD_PATH`) : rattrapée entre les membres, servie à un Admin qui se reconstitue |
| `pushed-journal.gpx` | Dernier document reçu de l'Admin pour chaque type de configuration commun au groupe HA (certificats, snippets, plugins, WAF…), avec sa date de réception : ce qu'un membre propose à ses pairs pour qu'ils rattrapent une poussée manquée ; chiffré par la clé locale du nœud (surchargeable par `GPX_PUSHED_JOURNAL_PATH`) |
| `waf-config.gpx` | Copie chiffrée de l'interrupteur du WAF reçu de l'Admin, rechargée au démarrage sans l'Admin (surchargeable par `GPX_WAF_CONFIG_PATH`) ; absente ou illisible : WAF actif |
| `edge-settings.gpx` | Copie chiffrée des réglages runtime reçus de l'Admin (anonymisation / pseudonymisation des IP, journalisation, tracing, URL publique), rechargée au démarrage sans l'Admin (surchargeable par `GPX_EDGE_SETTINGS_PATH`) |
| `logs/access-<lundi>.db`, `logs/system-<mois>.db` | Base de logs de la passerelle ([ADR 0012](adr/0012-logs-proprietaire-edge.md)) : un fichier SQLite par semaine pour les accès HTTP et par mois pour les logs système. Rétention par suppression du fichier entier : 365 jours pour les accès (`engine.log_retention_days`), 90 jours pour le système (`engine.system_log_retention_days`) tant que l'Admin ne range pas les lignes ; dès qu'il les range et les acquitte ([ADR 0018](adr/0018-logs-geres-par-l-admin.md), Edge `0.128.0`), la base est un tampon : une période acquittée est supprimée 7 jours après sa fin (`engine.log_buffer_days`), une période non acquittée après 30 jours (`engine.log_buffer_max_days`). `acks.json` retient les positions acquittées. Dossier réglable par `engine.log_store_dir` (défaut `/etc/goproxify/logs`). Exclu de la sauvegarde |
| `log-retention.gpx` | Copie locale chiffrée de la conservation des logs imposée par l'Admin (accès et système, en jours ; surchargeable par `GPX_LOG_RETENTION_PATH`) : relue au démarrage avant `edge.json`, Admin éteint ; absente, `edge.json` s'applique |
| `log-ip-key.gpx` | Clé qui chiffre l'IP réelle des accès en pseudonymisation, copie locale chiffrée (surchargeable par `GPX_LOG_IP_KEY_PATH`), reprise par la sauvegarde d'état. Illisible (secret d'appairage changé sans `PreviousSecretsEnv`) : jamais remplacée, la passerelle journalise sans garder l'IP réelle |
| `log-sign-key.gpx` | Clé Ed25519 qui signe les exports de logs (`goproxify edge logs export`), copie locale chiffrée (surchargeable par `GPX_LOG_SIGN_KEY_PATH`), créée à la première utilisation et reprise par la sauvegarde d'état. Illisible : jamais recréée, une clé neuve ne vérifierait plus les exports déjà remis |
| `log-export-audit.jsonl` | Journal local des exports et des gels légaux (une ligne JSON par opération, chaque ligne portant l'empreinte de la précédente ; surchargeable par `GPX_LOG_EXPORT_AUDIT_PATH`), sans IP |
| `logs/held/<id>/` *(repris par la sauvegarde d'état)* | Archives des gels légaux filtrés par IP ou domaine (`goproxify edge logs hold add -ip`) : les seules lignes visées, gardées au-delà de la rétention, lisibles par l'export ; supprimées avec le gel |
| `logs/legal-holds.json` *(repris par la sauvegarde d'état, avec les archives ci-dessus ; le reste de `logs/` ne l'est pas)* | Gels légaux posés par `goproxify edge logs hold` : tant qu'un gel recoupe un fichier de période, la purge ne le supprime pas ; relu à chaque purge, illisible = rien n'est purgé |

> **Note :** `proxies/` et `proxies-revisions/` sont la source de vérité de la passerelle. La passerelle reçoit sa configuration depuis l'Admin via WebSocket au démarrage — ces fichiers sont ensuite mis à jour à chaque changement de configuration.

---

> **Sauvegarde :** l'Admin interroge chaque passerelle et joint son état (hors `geoip/`, `logs/`, `threat-lists/`) à la section `secrets` chiffrée de ses snapshots, avec `GPX_BACKUP_KEY` — voir [sauvegardes.md](sauvegardes.md) §4 quater. Le tar de volume ci-dessous reste valable.

## `goproxify_agent_data` → `/etc/goproxify` (Agent)

| Chemin dans le volume | Contenu |
|---|---|
| `agent.token` | Token de connexion à la passerelle (obtenu lors du pairing initial) |
| `agent.hmac` | Secret HMAC pour la vérification des messages WebSocket |
| `agent-hmacs.json` | Store des HMACs persistés |
| `join-tokens-used.json` | Tokens de join déjà consommés (anti-rejeu) |
| `agent-node-id` | Identité stable du nœud Agent |
| `log-cursors.json` | Position de lecture des logs de chaque conteneur suivi (`goproxify.logs`) : l'Agent ne l'avance qu'après l'accusé de réception de sa passerelle, et reprend de là après un redémarrage ou une coupure. Perdue : le suivi repart de « maintenant » |

> **Note :** Le volume Agent est léger. Sa suppression force un nouveau pairing : l'Agent repasse en état `pending` et doit être réapprouvé dans l'interface Admin (menu **Agents**).

---

## Bind mount spécial — Agent

```yaml
- /var/run/docker.sock:/var/run/docker.sock
```

L'Agent monte la socket Docker de l'hôte pour découvrir ses conteneurs et les piloter (mises à jour, scaling). Cet accès équivaut à root sur l'hôte : un montage `:ro` n'empêche pas d'y envoyer des requêtes d'écriture, c'est pourquoi il n'est pas utilisé ici. Ce n'est pas un volume nommé : il pointe directement sur le daemon Docker de la machine hôte.

---

## Opérations courantes

### Sauvegarder les données Admin

```bash
docker run --rm \
  -v goproxify_admin_data:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/admin-backup.tar.gz -C /data .
```

### Restaurer les données Admin

```bash
docker run --rm \
  -v goproxify_admin_data:/data \
  -v $(pwd):/backup \
  alpine tar xzf /backup/admin-backup.tar.gz -C /data
```

### Réinitialiser un Agent (forcer le re-pairing)

```bash
docker compose stop goproxify-agent
docker volume rm goproxify_agent_data
docker compose up -d goproxify-agent
# Puis approuver l'Agent dans l'UI Admin → menu Agents
```

### Inspecter le contenu d'un volume

```bash
docker run --rm -v goproxify_edge_data:/data alpine ls -la /data
```
