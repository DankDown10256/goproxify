# Volumes Docker — GoProxify

Chaque service persiste ses données dans `/etc/goproxify` via un volume Docker dédié. Les trois volumes sont **distincts** : ne pas les partager entre services.

---

## `goproxify_admin_data` → `/etc/goproxify` (Admin)

| Chemin dans le volume | Contenu |
|---|---|
| `admin.db` | Base SQLite principale : comptes utilisateurs, proxies, tokens de nœuds, snapshots, alertes, audit log |
| `admin-node-id` | Identité stable du nœud Admin (générée au premier démarrage) |
| `waf-behavior.json` | Snapshot du moteur WAF (règles apprises, comportements) |
| `error-pages/` | Pages d'erreur personnalisées par proxy |
| `ip-profiles/` | Profils IP persistés (listes blanches/noires par proxy) |

> **Important :** `admin.db` contient tout l'état opérationnel de l'Admin (configuration proxies, utilisateurs, secrets nœuds). Sa perte est irréversible sans snapshot. Utiliser `GPX_BACKUP_KEY` pour chiffrer les snapshots exportés.

---

## `goproxify_core_data` → `/etc/goproxify` (Core)

| Chemin dans le volume | Contenu |
|---|---|
| `proxies/` | Configurations de production des proxies (fichiers YAML, un par proxy) |
| `proxies-revisions/` | Historique des révisions pipeline (`<id>--<rev>.yaml`) |
| `core-cache.gpx` | Cache interne du Core (état runtime, reconnexion rapide) |
| `core-tokens.db` | Base SQLite des tokens d'authentification des nœuds (Admin → Core) |
| `core-node-id` | Identité stable du nœud Core |
| `geoip/GeoLite2-Country.mmdb` | Base GeoIP téléchargée automatiquement (si `GPX_GEOIP_AUTO_DOWNLOAD=true`) |
| `bans/` | Bannissements IP persistés |
| `threat-lists/` | Listes de menaces téléchargées (IPs malveillantes, etc.) |
| `logs/access.log` | Journal d'accès HTTP du reverse proxy |

> **Note :** `proxies/` et `proxies-revisions/` sont la source de vérité du Core. Le Core reçoit sa configuration depuis l'Admin via WebSocket au démarrage — ces fichiers sont ensuite mis à jour à chaque changement de configuration.

---

## `goproxify_agent_data` → `/etc/goproxify` (Agent)

| Chemin dans le volume | Contenu |
|---|---|
| `agent.token` | Token de connexion au Core (obtenu lors du pairing initial) |
| `agent.hmac` | Secret HMAC pour la vérification des messages WebSocket |
| `agent-hmacs.json` | Store des HMACs persistés |
| `join-tokens-used.json` | Tokens de join déjà consommés (anti-rejeu) |
| `agent-node-id` | Identité stable du nœud Agent |

> **Note :** Le volume Agent est léger. Sa suppression force un nouveau pairing : l'Agent repasse en état `pending` et doit être réapprouvé dans l'interface Admin (menu **Agents**).

---

## Bind mount spécial — Agent

```yaml
- /var/run/docker.sock:/var/run/docker.sock:ro
```

L'Agent monte la socket Docker de l'hôte en lecture seule pour découvrir automatiquement les conteneurs. Ce n'est pas un volume nommé : il pointe directement sur le daemon Docker de la machine hôte.

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
docker run --rm -v goproxify_core_data:/data alpine ls -la /data
```
