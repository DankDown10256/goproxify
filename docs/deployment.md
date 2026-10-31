# GoProxify — Guide de déploiement

De zéro à l'application fonctionnelle, toutes méthodes.

> **Préversion.** Les images sont en tag `preview` (pas de `:latest`). Voir [DISCLAIMER.md](../DISCLAIMER.md).

---

## Sommaire

1. [Prérequis](#1-prérequis)
2. [Comprendre l'architecture en trois minutes](#2-comprendre-larchitecture-en-trois-minutes)
3. [Méthode A — Docker Compose (recommandé)](#3-méthode-a--docker-compose-recommandé)
4. [Méthode B — Portainer (Stack avec stack.env)](#4-méthode-b--portainer-stack-avec-stackenv)
5. [Méthode C — Portainer (Stack tout-en-un, sans fichier d'env)](#5-méthode-c--portainer-stack-tout-en-un-sans-fichier-denv)
6. [Méthode D — CLI (binaire natif)](#6-méthode-d--cli-binaire-natif)
7. [Multi-hôtes — passerelle supplémentaire sur un serveur distant](#7-multi-hôtes--passerelle-supplémentaire-sur-un-serveur-distant)
8. [Multi-hôtes — Agent sur un serveur distant](#8-multi-hôtes--agent-sur-un-serveur-distant)
9. [Premier démarrage — initialisation de l'Admin](#9-premier-démarrage--initialisation-de-ladmin)
10. [Vérifier que tout est opérationnel](#10-vérifier-que-tout-est-opérationnel)
11. [Dépannage courant](#11-dépannage-courant)

---

## 1. Prérequis

| Besoin | Minimum |
|--------|---------|
| Docker | 20.10+ (ou Podman 4+) |
| Docker Compose | v2 (`docker compose` sans tiret) |
| RAM | 256 Mo libres |
| Ports ouverts | 80, 443, 9443 en entrée ; 8000 accessible depuis les Agents si multi-hôtes |
| DNS | Un domaine ou sous-domaine pointant vers l'IP du serveur (pour les certificats ACME) |

Pour la méthode CLI : Go 1.25+ ou le binaire pré-compilé depuis [les releases](https://github.com/Vincamok/goproxify/releases).

---

## 2. Comprendre l'architecture en trois minutes

GoProxify repose sur **trois services distincts**, chacun ayant un rôle précis :

```
Navigateur Admin
      │ HTTPS :9443
      ▼
┌─────────────┐      API interne :8000      ┌─────────────┐
│    ADMIN    │ ─────────────────────────►  │    EDGE     │ :80/:443 ◄── trafic web
│ Interface   │                             │ Reverse     │
│ de gestion  │                             │ Proxy       │
└─────────────┘                             └──────▲──────┘
                                                   │ WebSocket :8000
                                            ┌──────┴──────┐
                                            │    AGENT    │
                                            │ Discovery   │
                                            │ Docker      │
                                            └─────────────┘
```

- **Passerelle** : reçoit le trafic HTTP/HTTPS des utilisateurs finaux. Porte 80, 443.  
- **Admin** : interface web de configuration. Porte 9443. Communique avec la passerelle via son API interne (port 8000 — ne pas exposer sur Internet).  
- **Agent** : tourne sur chaque hôte Docker. Utilise `docker.sock` (accès équivalent à root sur l'hôte, qu'un montage `:ro` ne limite pas), remonte les conteneurs et métriques à la passerelle. N'expose aucun port.

**Deux exemples d'architecture** (il en existe bien d'autres) :

- **Home lab** — 1 Admin · 1 passerelle · 1 Agent sur une machine : sections 3 à 6.
- **Entreprise redondé** — 1 Admin · 2 passerelles (derrière un DNS round-robin ou une IP virtuelle) · 4 hôtes internes avec un Agent chacun : Admin + Passerelle 1 comme le home lab, puis section 7 (seconde passerelle) et section 8 (un Agent par hôte). Le trafic se lit de haut en bas : Internet → passerelles → Agents (proxies HTTP(S) par labels) ou hôtes (proxies TCP/UDP). L'Admin est le lien de gestion des passerelles.

**Secret de couplage (`GPX_PAIRING_SECRET`)** : l'Admin et la passerelle partagent la même valeur. C'est le seul mécanisme d'authentification au démarrage, et il signe le WebSocket Admin → passerelle : qui le possède peut se faire passer pour l'Admin auprès de toutes les passerelles. Générez-le aléatoirement, ne le réutilisez jamais entre environnements.

**Clé d'appairage des Agents (`GPX_AGENT_PAIRING_KEY`)** : les Agents tournent sur des machines d'application (accès au socket du runtime) et ne reçoivent **pas** le secret racine, mais une clé qui en est dérivée. Elle suffit à s'appairer et à authentifier les appels de l'Admin et de la passerelle vers l'Agent ; elle ne permet pas de remonter au secret ni de signer le WebSocket Admin. Calcul :

```bash
printf %s "goproxify/agent-pairing/v1:$GPX_PAIRING_SECRET" | sha256sum | cut -d' ' -f1
```

**Passerelle sans le secret racine (`GPX_EDGE_CHANNEL_KEY`)** : de la même façon, une passerelle peut ne détenir ni `GPX_PAIRING_SECRET` ni de quoi le retrouver. L'Admin signe sa connexion à chaque passerelle avec une clé qui ne vaut que pour elle, dérivée de son **identifiant** (`dn_…`, celui que l'Admin lui connaît, visible dans les logs de l'Admin et dans `architecture.json` : il survit à un renommage) :

```bash
printf %s "goproxify/edge-channel/v1:dn_bfc1086fe4e3:$GPX_PAIRING_SECRET" | sha256sum | cut -d' ' -f1
```

`GET /api/v1/pairing-secret?node=frontal` (identifiant ou nom) la renvoie (`edge_channel_key`). Sur la passerelle, posez `GPX_EDGE_CHANNEL_KEY` (sa clé) et `GPX_AGENT_PAIRING_KEY` (la clé des Agents, ci-dessus) et **retirez `GPX_PAIRING_SECRET`** ; posez aussi `GPX_PORTAL_MASTER_KEY` si le portail Access est utilisé (il se dérive sinon du secret racine, voir plus bas). Une passerelle compromise ne peut alors plus se faire passer pour l'Admin auprès des autres. **Migration** : tant que la passerelle a `GPX_PAIRING_SECRET`, elle accepte aussi la racine ; l'Admin signe d'abord avec la clé dérivée et se replie sur la racine si la passerelle la refuse (`GPX_EDGE_CHANNEL_ROOT_FALLBACK=false` l'interdit une fois toutes les passerelles migrées). L'identifiant entre dans la clé : un renommage de la passerelle ne la change pas.

**Clé du canal dérivée du nom, pour les déploiements automatisés (Admin `0.192.0`)** : le démarrage rapide et le chart Helm ne connaissent pas l'identifiant `dn_…` que l'Admin attribue à une passerelle, mais ils connaissent son nom. L'Admin essaie donc, après la clé dérivée de l'identifiant, celle dérivée du **nom** (`printf %s "goproxify/edge-channel/v1:<nom>:$GPX_PAIRING_SECRET" | sha256sum`). `GET /api/v1/pairing-secret?node=` renvoie les deux (`edge_channel_key`, `edge_channel_key_by_name`). Là où l'identifiant est connu, préférez-le : il survit à un renommage, le nom non.

**Démarrage rapide et Helm sans le secret racine sur la passerelle** : `scripts/quickstart.sh` génère `GPX_EDGE_CHANNEL_KEY` (dérivée de `EDGE_NODE_NAME`), `GPX_AGENT_PAIRING_KEY` et `GPX_PORTAL_MASTER_KEY`, et la passerelle du compose n'a plus `GPX_PAIRING_SECRET` ; l'Admin y pose `GPX_EDGE_CHANNEL_ROOT_FALLBACK=false` et `GPX_AGENT_PAIRING_ROOT=false`. Si vous changez `EDGE_NODE_NAME` après coup, recalculez `GPX_EDGE_CHANNEL_KEY`. Le chart Helm a `security.edgeWithoutRootSecret` (défaut `false`, aucun changement pour une installation existante) : à `true`, la passerelle reçoit sa clé de canal (dérivée du nom de son Deployment), la clé des Agents et `global.portalMasterKey`, et plus le secret racine ; la rotation (`global.previousPairingSecret`) passe aux Agents, aux passerelles et à l'Admin leurs valeurs `*_PREVIOUS`. Cela exige `edge.kind: Deployment` : un DaemonSet se nomme d'après le nœud Kubernetes, connu au démarrage seulement, donc sa clé ne peut pas être calculée par le chart sans lui donner le secret racine. Le chart n'a pas pu être rendu par `helm` ici : validez avec `helm template` avant de l'utiliser.

**Secrets de fichier et rotation (Admin `0.190.0`, passerelle `0.104.0`, Agent `0.18.0`)** : chacun des secrets `GPX_PAIRING_SECRET`, `GPX_EDGE_CHANNEL_KEY` et `GPX_AGENT_PAIRING_KEY` peut venir d'un fichier (un secret Docker) en posant `<NOM>_FILE=/run/secrets/…` à la place de la variable. Le fichier est **relu à chaque usage** (connexion de l'Admin, appairage, appel d'un Agent) : une valeur changée sur disque est prise en compte sans redémarrer le conteneur. Chacun accepte aussi `<NOM>_PREVIOUS` (ou `<NOM>_PREVIOUS_FILE`) : les valeurs précédentes, séparées par des virgules, acceptées **le temps d'une rotation**. Chaque connexion ou appairage qui passe par une valeur précédente est journalisé (`rotation en cours`), pour savoir quand la retirer.

Pour changer le secret racine sans interruption, dans cet ordre (chaque étape laisse tout fonctionner) :

1. Calculez les nouvelles clés avec le nouveau secret : celle des Agents, et celle de canal de chaque passerelle (voir plus haut).
2. **Agents** : `GPX_AGENT_PAIRING_KEY` = nouvelle clé des Agents, `GPX_AGENT_PAIRING_KEY_PREVIOUS` = l'ancienne. Ils acceptent alors les deux en Bearer.
3. **Passerelles** : `GPX_EDGE_CHANNEL_KEY` = nouvelle clé de la passerelle, `GPX_EDGE_CHANNEL_KEY_PREVIOUS` = l'ancienne ; `GPX_AGENT_PAIRING_KEY` et `GPX_AGENT_PAIRING_KEY_PREVIOUS` comme les Agents. Elles acceptent l'Admin avec l'une ou l'autre clé et envoient la nouvelle aux Agents.
4. **Admin** : `GPX_PAIRING_SECRET` = nouveau secret, `GPX_PAIRING_SECRET_PREVIOUS` = l'ancien. Il signe avec la nouvelle clé, et se rabat sur l'ancienne devant une passerelle qui ne l'a pas encore (journalisé).
5. Quand plus aucun journal ne signale de rotation en cours, **retirez tous les `*_PREVIOUS`**. L'ancien secret ne vaut plus rien. Pour que le recouvrement se termine seul, posez `<NOM>_PREVIOUS_UNTIL` (date RFC 3339, par exemple `GPX_PAIRING_SECRET_PREVIOUS_UNTIL=2026-11-01T00:00:00Z`) : à cette date, les valeurs précédentes ne sont plus acceptées. Une date illisible les supprime aussi.

**Secret racine présenté par un Agent (`GPX_AGENT_PAIRING_ROOT`)** : l'Admin et les passerelles l'acceptent encore par défaut, pour qu'une installation dont les Agents ont reçu la racine continue de fonctionner ; chaque appairage de ce type est journalisé. Posez `GPX_AGENT_PAIRING_ROOT=false` dès que vos Agents ont `GPX_AGENT_PAIRING_KEY` : le chart Helm et le démarrage rapide le font déjà. Le défaut ne change pas dans le code, parce qu'un changement casserait silencieusement les Agents que vous n'avez pas encore migrés.

**Approbation des Agents** : par défaut, un Agent qui présente la clé d'appairage à sa passerelle est pré-approuvé. `GPX_AGENT_PREAPPROVAL=manual` sur la passerelle le laisse en attente de l'approbation d'un opérateur (*Infrastructure*, ou `goproxify nodes accept`), tout en lui rendant son jeton.

**Éviction d'un membre** : quand un membre quitte un groupe, l'Admin renouvelle la clé du groupe et le jeton de chaque membre restant (ils les ont donnés à la liste des pairs du membre sorti). Pour évincer une machine pour de bon, supprimez-la aussi de l'Admin (son jeton est révoqué), et ne lui laissez pas le secret racine : migrez les passerelles vers leurs clés dérivées avant, ou faites tourner le secret racine après.

Un Agent s'appaire avec sa clé courante puis, si la passerelle la refuse, avec la précédente. Il ne se réappaire que s'il a perdu son jeton, donc rarement pendant la fenêtre.

L'écran *Infrastructure → Ajouter un Agent*, `GET /api/v1/pairing-secret` (`agent_key`), `scripts/quickstart.sh` et le chart Helm la fournissent. **Migration** : un Agent qui n'a que `GPX_PAIRING_SECRET` continue de fonctionner (la passerelle et l'Admin acceptent encore le secret racine d'un Agent) mais journalise un avertissement ; une fois tous les Agents passés à `GPX_AGENT_PAIRING_KEY`, posez `GPX_AGENT_PAIRING_ROOT=false` sur l'Admin et les passerelles pour refuser le secret racine côté Agent (le chart le fait par défaut). Pour retirer un secret racine déjà copié sur des hôtes d'application, **changez-le** (Admin, passerelles), puis redistribuez la clé dérivée du nouveau secret : l'ancienne clé est invalide.

---

## 3. Méthode A — Docker Compose (recommandé)

### 3.1 Générer les secrets

```bash
# Secret de couplage (partagé Admin + Passerelle + Agent)
PAIRING=$(openssl rand -hex 32)

# Secret JWT (Admin uniquement)
JWT=$(openssl rand -hex 32)

# Mot de passe admin initial
PASSWORD=$(openssl rand -base64 16)

echo "PAIRING : $PAIRING"
echo "JWT     : $JWT"
echo "PASSWORD: $PASSWORD"
```

> Conservez ces valeurs — vous en aurez besoin pour le `.env`.

### 3.2 Créer le fichier d'environnement

```bash
cat > .env <<EOF
GPX_PAIRING_SECRET=$PAIRING
GPX_JWT_SECRET=$JWT
GPX_FIRST_ADMIN_EMAIL=admin@example.com
GPX_FIRST_ADMIN_PASSWORD=$PASSWORD
ADMIN_PORT=9443
TZ=Europe/Paris
EDGE_NODE_NAME=goproxify-edge
AGENT_NODE_NAME=goproxify-agent
EOF
```

### 3.3 Créer le fichier `docker-compose.yml`

```yaml
networks:
  goproxify_net:
    name: goproxify_net

volumes:
  goproxify_admin_data:
  goproxify_edge_data:
  goproxify_agent_data:

services:
  goproxify-admin:
    image: ghcr.io/vincamok/goproxify/admin:preview
    container_name: goproxify-admin
    restart: unless-stopped
    command: ["admin"]
    environment:
      - TZ=${TZ:-Europe/Paris}
      - GPX_SECURITY_JWT_SECRET=${GPX_JWT_SECRET}
      - GPX_PAIRING_SECRET=${GPX_PAIRING_SECRET}
      - GPX_FIRST_ADMIN_EMAIL=${GPX_FIRST_ADMIN_EMAIL}
      - GPX_FIRST_ADMIN_PASSWORD=${GPX_FIRST_ADMIN_PASSWORD}
      - GPX_IDENTITY_EDGE_NODE_NAME=${EDGE_NODE_NAME:-goproxify-edge}
      - GPX_SERVER_API_PORT=9443
    ports:
      - "${ADMIN_PORT:-9443}:9443"
    volumes:
      - goproxify_admin_data:/etc/goproxify
    networks: [goproxify_net]

  goproxify-edge:
    image: ghcr.io/vincamok/goproxify/edge:preview
    container_name: goproxify-edge
    restart: unless-stopped
    command: ["edge"]
    environment:
      - TZ=${TZ:-Europe/Paris}
      - GPX_PAIRING_SECRET=${GPX_PAIRING_SECRET}
      - GPX_IDENTITY_EDGE_NODE_NAME=${EDGE_NODE_NAME:-goproxify-edge}
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
      - "8000:8000"
    volumes:
      - goproxify_edge_data:/etc/goproxify
    networks: [goproxify_net]
    depends_on: [goproxify-admin]

  goproxify-agent:
    image: ghcr.io/vincamok/goproxify/agent:preview
    container_name: goproxify-agent
    restart: unless-stopped
    command: ["agent"]
    environment:
      - TZ=${TZ:-Europe/Paris}
      - GPX_AGENT_PAIRING_KEY=${GPX_AGENT_PAIRING_KEY}   # dérivée de GPX_PAIRING_SECRET, voir plus haut
      - GPX_CONTROL_PLANE_EDGE_ENDPOINT=http://goproxify-edge:8000
      - GPX_CONTROL_PLANE_ADMIN_ENDPOINT=http://goproxify-admin:9443
      - GPX_IDENTITY_AGENT_NODE_NAME=${AGENT_NODE_NAME:-goproxify-agent}
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - goproxify_agent_data:/etc/goproxify
    networks: [goproxify_net]
    depends_on: [goproxify-edge]
```

### 3.4 Démarrer

```bash
docker compose up -d
docker compose logs -f   # Ctrl+C pour quitter les logs
```

L'Admin est accessible sur **`https://<IP>:9443`** après quelques secondes.

---

## 4. Méthode B — Portainer (Stack avec stack.env)

Portainer permet de déployer une Stack depuis l'UI ou depuis un dépôt Git.

### 4.1 Créer la Stack

Dans Portainer → **Stacks → Add stack** :

- **Name** : `goproxify`
- **Build method** : Web editor (coller le YAML ci-dessous) ou Git repository
- **Env file** : activer "Load variables from .env file" et coller le contenu du stack.env

### 4.2 Contenu du stack.env

```env
GPX_JWT_SECRET=<hex64>
GPX_PAIRING_SECRET=<hex64>
GPX_FIRST_ADMIN_EMAIL=admin@example.com
GPX_FIRST_ADMIN_PASSWORD=<motdepasse>
ADMIN_PORT=9443
TZ=Europe/Paris
EDGE_NODE_NAME=goproxify-edge
AGENT_NODE_NAME=goproxify-agent
```

Remplacez `<hex64>` par `openssl rand -hex 32` et `<motdepasse>` par un mot de passe d'au moins 12 caractères.

### 4.3 Contenu du docker-compose (éditeur web Portainer)

Utiliser le même YAML que la [méthode A §3.3](#33-créer-le-fichier-docker-composeyml) — Portainer résoudra les variables depuis le stack.env.

> **Important :** le réseau doit s'appeler `goproxify_net` (avec underscore). Spécifier `name: goproxify_net` comme dans l'exemple évite que Portainer préfixe automatiquement le nom avec le nom de la Stack.

### 4.4 Déployer

Cliquer **Deploy the stack**. Surveiller l'avancement dans **Containers**.

---

## 5. Méthode C — Portainer (Stack tout-en-un, sans fichier d'env)

Utile quand vous ne pouvez pas fournir de fichier d'env séparé. Tous les secrets sont inlinés directement dans le YAML.

> Générez les secrets **dans votre navigateur** via la page de démarrage de GoProxify (section « Démarrer en 5 minutes ») — ils ne transitent pas par nos serveurs.

```yaml
networks:
  goproxify_net:
    name: goproxify_net

volumes:
  goproxify_admin_data:
  goproxify_edge_data:
  goproxify_agent_data:

services:
  goproxify-admin:
    image: ghcr.io/vincamok/goproxify/admin:preview
    container_name: goproxify-admin
    restart: unless-stopped
    command: ["admin"]
    environment:
      - TZ=Europe/Paris
      - GPX_SECURITY_JWT_SECRET=CHANGE_ME_JWT_HEX32
      - GPX_PAIRING_SECRET=CHANGE_ME_PAIRING_HEX32
      - GPX_FIRST_ADMIN_EMAIL=admin@example.com
      - GPX_FIRST_ADMIN_PASSWORD=CHANGE_ME_PASSWORD_MIN12
      - GPX_IDENTITY_EDGE_NODE_NAME=goproxify-edge
      - GPX_SERVER_API_PORT=9443
    ports:
      - "9443:9443"
    volumes:
      - goproxify_admin_data:/etc/goproxify
    networks: [goproxify_net]

  goproxify-edge:
    image: ghcr.io/vincamok/goproxify/edge:preview
    container_name: goproxify-edge
    restart: unless-stopped
    command: ["edge"]
    environment:
      - TZ=Europe/Paris
      - GPX_PAIRING_SECRET=CHANGE_ME_PAIRING_HEX32
      - GPX_IDENTITY_EDGE_NODE_NAME=goproxify-edge
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
    volumes:
      - goproxify_edge_data:/etc/goproxify
    networks: [goproxify_net]
    depends_on: [goproxify-admin]

  goproxify-agent:
    image: ghcr.io/vincamok/goproxify/agent:preview
    container_name: goproxify-agent
    restart: unless-stopped
    command: ["agent"]
    environment:
      - TZ=Europe/Paris
      - GPX_AGENT_PAIRING_KEY=CHANGE_ME_CLE_DERIVEE   # sha256 de goproxify/agent-pairing/v1:<secret>
      - GPX_CONTROL_PLANE_EDGE_ENDPOINT=http://goproxify-edge:8000
      - GPX_IDENTITY_AGENT_NODE_NAME=goproxify-agent
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - goproxify_agent_data:/etc/goproxify
    networks: [goproxify_net]
    depends_on: [goproxify-edge]
```

Remplacer tous les `CHANGE_ME_*` avant de cliquer **Deploy**.

---

## 6. Méthode D — CLI (binaire natif)

Sans Docker — déploiement direct sur l'hôte.

### 6.1 Télécharger le binaire

```bash
# Dernière release (adapter l'OS/arch)
curl -L https://github.com/Vincamok/goproxify/releases/latest/download/goproxify-linux-amd64 \
  -o /usr/local/bin/goproxify
chmod +x /usr/local/bin/goproxify
```

Ou compiler depuis les sources :

```bash
git clone https://github.com/Vincamok/goproxify.git
cd goproxify
go build -o goproxify ./cmd/goproxify
```

### 6.2 Variables d'environnement

```bash
export GPX_PAIRING_SECRET=$(openssl rand -hex 32)
export GPX_SECURITY_JWT_SECRET=$(openssl rand -hex 32)
export GPX_FIRST_ADMIN_EMAIL=admin@example.com
export GPX_FIRST_ADMIN_PASSWORD=MonMotDePasse42!
export GPX_IDENTITY_EDGE_NODE_NAME=goproxify-edge
export GPX_IDENTITY_AGENT_NODE_NAME=goproxify-agent
export GPX_CONTROL_PLANE_EDGE_ENDPOINT=http://localhost:8000
export GPX_CONTROL_PLANE_ADMIN_ENDPOINT=http://localhost:9443
```

### 6.3 Démarrer les trois rôles (trois terminaux ou trois services systemd)

**Terminal 1 — Admin :**
```bash
goproxify admin
```

**Terminal 2 — passerelle :**
```bash
goproxify edge
```

**Terminal 3 — Agent :**
```bash
goproxify agent
```

### 6.4 Systemd (production)

Créer `/etc/systemd/system/goproxify-admin.service` :

```ini
[Unit]
Description=GoProxify Admin
After=network.target

[Service]
ExecStart=/usr/local/bin/goproxify admin
Restart=always
EnvironmentFile=/etc/goproxify/admin.env

[Install]
WantedBy=multi-user.target
```

Répéter pour `edge` et `agent` (avec leurs fichiers `.env` respectifs).

```bash
systemctl daemon-reload
systemctl enable --now goproxify-admin goproxify-edge goproxify-agent
```

---

## 7. Multi-hôtes — passerelle supplémentaire sur un serveur distant

Quand vous avez un **deuxième serveur** qui doit gérer du trafic HTTP/HTTPS indépendamment, déployez-y une passerelle seule. L'Admin central reste unique et pilote toutes les passerelles.

```
┌─────────────┐  WS :8000  ┌──────────────────┐  :80/:443
│    ADMIN    │ ──────────► │ passerelle principale  │ ◄── trafic web A
│  (serveur 1)│             └──────────────────┘
│             │  WS :8000  ┌──────────────────┐  :80/:443
│             │ ──────────► │ passerelle secondaire │ ◄── trafic web B
└─────────────┘             └──────────────────┘
```

### 7.1 Prérequis réseau

Le port **8000** de la passerelle secondaire doit être joignable depuis le serveur Admin (et depuis les Agents qui s'y connectent). Ouvrir uniquement vers les IPs concernées :

```bash
# Exemple UFW — sur le serveur passerelle secondaire
ufw allow from <IP_ADMIN> to any port 8000
ufw allow from <IP_AGENT> to any port 8000
```

### 7.2 Déployer la passerelle secondaire

Sur le serveur distant, créer un `docker-compose.yml` minimal :

```yaml
networks:
  goproxify_net:
    name: goproxify_net

volumes:
  edge-lucas_data:

services:
  goproxify-edge:
    image: ghcr.io/vincamok/goproxify/edge:preview
    container_name: goproxify-edge
    restart: unless-stopped
    command: ["edge"]
    environment:
      - TZ=Europe/Paris
      # Même valeur que l'Admin et la passerelle principale
      - GPX_PAIRING_SECRET=<MÊME_PAIRING_SECRET>
      # Nom unique pour cette passerelle — doit correspondre exactement au nom configuré dans l'Admin
      - GPX_IDENTITY_EDGE_NODE_NAME=edge-lucas
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
      # Exposer 8000 pour que l'Admin (et les Agents distants) puissent s'y connecter
      - "8000:8000"
    volumes:
      - edge-lucas_data:/etc/goproxify
    networks: [goproxify_net]
```

```bash
docker compose up -d
```

### 7.3 Enregistrer la passerelle secondaire dans l'Admin

L'Admin doit connaître l'adresse de la passerelle secondaire. Deux façons :

**Via le Wizard architecture** (recommandé) :
1. Admin → **Infrastructure → Wizard**
2. Ajouter un hôte de type passerelle, indiquer l'IP/hostname du serveur distant
3. Cliquer **Enregistrer** — l'Admin tente immédiatement la connexion WS

**Via les variables d'environnement de l'Admin** :
```bash
# Ajouter dans le .env de l'Admin (redémarrage requis)
GPX_IDENTITY_EDGE_NODE_NAME=edge-lucas        # nom de la passerelle secondaire tel que configuré sur lui
GPX_EDGE_EXTRA_ENDPOINTS=http://<IP_EDGE_SECONDAIRE>:8000
```

### 7.4 Vérifier la connexion

Dans l'Admin → **Infrastructure → Nœuds** : la passerelle secondaire doit passer de `declared` à `online` en quelques secondes après son démarrage.

Si la passerelle reste en `Non connecté / En attente` :

```bash
# Depuis le serveur Admin : le port 8000 est-il joignable ?
curl http://<IP_EDGE_SECONDAIRE>:8000/healthz

# Logs de la passerelle secondaire — doit afficher "full_sync reçu de l'Admin"
docker logs goproxify-edge | tail -50

# Vérifier que GPX_PAIRING_SECRET est identique sur les deux machines
docker exec goproxify-edge env | grep GPX_PAIRING_SECRET
```

> **`GPX_IDENTITY_EDGE_NODE_NAME` est critique.** La valeur configurée sur la passerelle doit correspondre exactement au nom que l'Admin utilise pour le joindre. Une divergence provoque un état `declared` permanent sans message d'erreur explicite.

---

## 8. Multi-hôtes — Agent sur un serveur distant



Quand l'Agent tourne sur un hôte **différent** de la passerelle :

### 7.1 Exposer le port 8000 de la passerelle

Sur le serveur passerelle, ouvrir le port 8000 dans le pare-feu **uniquement vers les IPs des serveurs agents** (ne pas exposer sur Internet) :

```bash
# Exemple UFW
ufw allow from <IP_AGENT> to any port 8000
```

### 7.2 Configurer l'Agent

Sur le serveur Agent :

```bash
# GPX_CONTROL_PLANE_EDGE_ENDPOINT pointe vers l'IP ou domaine de la passerelle, pas localhost
export GPX_CONTROL_PLANE_EDGE_ENDPOINT=http://<IP_DU_EDGE>:8000
export GPX_AGENT_PAIRING_KEY=<clé dérivée du secret de la passerelle — pas le secret lui-même>
export GPX_IDENTITY_AGENT_NODE_NAME=agent-prod-1  # nom unique par agent
```

Docker Compose pour l'Agent seul :

```yaml
networks:
  goproxify_net:
    name: goproxify_net

volumes:
  agent-prod-1_data:

services:
  goproxify-agent:
    image: ghcr.io/vincamok/goproxify/agent:preview
    container_name: goproxify-agent
    restart: unless-stopped
    command: ["agent"]
    environment:
      - GPX_AGENT_PAIRING_KEY=<CLE_DERIVEE_DU_SECRET_DU_EDGE>
      - GPX_CONTROL_PLANE_EDGE_ENDPOINT=http://<IP_DU_EDGE>:8000
      - GPX_CONTROL_PLANE_ADMIN_ENDPOINT=http://<IP_DU_EDGE>:9443
      - GPX_IDENTITY_AGENT_NODE_NAME=agent-prod-1
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - agent-prod-1_data:/etc/goproxify
    networks: [goproxify_net]
```

> **Chaque Agent doit avoir un `GPX_IDENTITY_AGENT_NODE_NAME` unique.** Deux agents avec le même nom : seul le dernier connecté est visible dans l'Admin.

---

## 9. Premier démarrage — initialisation de l'Admin

### 8.1 Accéder à l'Admin

Ouvrir **`https://<IP_SERVEUR>:9443`** dans un navigateur.

> Le certificat TLS est auto-signé par défaut — accepter l'exception de sécurité du navigateur (ou configurer un certificat valide via ACME dans les paramètres).

### 8.2 Compte administrateur

Lors du **tout premier démarrage**, GoProxify crée automatiquement le compte avec :

- Email : valeur de `GPX_FIRST_ADMIN_EMAIL`
- Mot de passe : valeur de `GPX_FIRST_ADMIN_PASSWORD`

**Changer le mot de passe après le premier login** (Menu → Compte → Sécurité).

Si vous avez perdu le mot de passe :

```bash
# Docker
docker exec goproxify-admin goproxify admin -reset-password \
  -email admin@example.com -password NouveauMotDePasse42!

# CLI
goproxify admin -reset-password -email admin@example.com -password NouveauMotDePasse42!
```

### 8.3 Vérifier les nœuds connectés

Dans l'Admin → **Infrastructure** :

- Le **Passerelle** doit apparaître comme `online`
- L'**Agent** doit apparaître comme `online` (quelques secondes après le démarrage)

Si un nœud reste en `declared` ou n'apparaît pas → voir [§10 Dépannage](#10-dépannage-courant).

### 8.4 Créer un premier proxy

1. Admin → **Proxies → Nouveau proxy**
2. Remplir : domaine, protocole cible, port cible
3. Activer le proxy → la passerelle commence à router le trafic immédiatement

Pour les certificats HTTPS automatiques (ACME Let's Encrypt) :

1. Admin → **Paramètres → Certificats**
2. Configurer l'email ACME et le fournisseur DNS (si DNS-01)
3. Sur chaque proxy : activer "TLS automatique"

---

## 10. Vérifier que tout est opérationnel

### Conteneurs actifs

```bash
docker compose ps
# Tous les services doivent être en état "Up"
```

### Logs en temps réel

```bash
docker compose logs -f goproxify-admin
docker compose logs -f goproxify-edge
docker compose logs -f goproxify-agent
```

### Connectivité

```bash
# Admin accessible
curl -k https://localhost:9443/healthz

# Passerelle accessible (API interne — depuis le même réseau que les agents)
curl http://localhost:8000/healthz

# Passerelle proxy HTTP
curl -I http://localhost/
```

### Dans l'Admin

| Endroit | Ce qu'on vérifie |
|---------|-----------------|
| Infrastructure → Nœuds | Passerelle et Agent en `online` |
| Infrastructure → Agent → Détail | CPU/RAM remontés (heartbeat actif) |
| Proxies | Statut `actif` sur les règles configurées |
| Logs | Pas d'erreur `401` ni `connection refused` |

---

## 11. Dépannage courant

### L'Agent n'apparaît pas dans l'Admin

Cause la plus fréquente : `GPX_AGENT_PAIRING_KEY` de l'Agent qui n'est pas la clé dérivée du `GPX_PAIRING_SECRET` de la passerelle.

```bash
# Calculer la clé attendue à partir du secret de la passerelle, puis la comparer à celle de l'Agent
docker exec goproxify-edge sh -c 'printf %s "goproxify/agent-pairing/v1:$GPX_PAIRING_SECRET" | sha256sum | cut -d" " -f1'
docker exec goproxify-agent env | grep GPX_AGENT_PAIRING_KEY

# Logs de l'agent — chercher status=401
docker logs goproxify-agent | grep -i "401\|heartbeat\|refused"
```

> `GPX_IDENTITY_AGENT_NODE_NAME` est **optionnel** : sans lui, un ID stable est auto-généré au premier démarrage et persisté dans le volume (`/etc/goproxify/agent-node-id`). Si le volume est absent ou recréé, l'agent change d'identité et apparaît comme un nouveau nœud.

### La passerelle reste en `declared` (jamais `online`)

```bash
# L'agent peut-il joindre la passerelle sur le port 8000 ?
docker exec goproxify-agent curl -s http://goproxify-edge:8000/healthz

# Vérifier que GPX_PAIRING_SECRET est identique sur les trois services
docker exec goproxify-edge env | grep GPX_PAIRING_SECRET
docker exec goproxify-admin env | grep GPX_PAIRING_SECRET
```

### Port 80/443 déjà utilisé

```bash
# Identifier le processus
ss -tlnp | grep -E ':80|:443'

# Arrêter Nginx/Apache si nécessaire
systemctl stop nginx apache2
```

### Erreur TLS sur l'Admin (certificat invalide)

Normal en auto-signé. Pour un certificat valide :

1. Configurer un sous-domaine DNS pointant vers le serveur
2. Admin → Paramètres → Certificats → Activer ACME
3. Ou placer un reverse proxy (Caddy, Nginx) devant le port 9443

### Réseau Docker introuvable

Si Compose crée un réseau `<stack>_goproxify_net` au lieu de `goproxify_net` :

```yaml
# Vérifier que le bloc networks inclut bien "name:"
networks:
  goproxify_net:
    name: goproxify_net   # ← obligatoire pour forcer le nom exact
```

---

## Installation par le launcher (en cours de mise en place)

Le launcher (`ghcr.io/vincamok/goproxify/launcher`, [ADR 0019](adr/0019-launcher-bootstrap-multi-hotes.md)) installe le premier hôte en une commande, sans écrire de `docker-compose.yml` ni de `.env`. Il génère les secrets, le compte administrateur et un certificat TLS pour l'Admin, déploie Admin, passerelle et Agent, puis disparaît. Les autres hôtes sont déclarés dans l'Admin (vue Infrastructure) en attendant leur installation. Voir [`goproxify launcher`](cli.md#goproxify-launcher).

Ce qui change par rapport au démarrage rapide :

- **L'Admin sert en HTTPS** (certificat auto-signé, valable deux ans, écrit dans `/etc/goproxify/tls/`). Le contrôle de santé de l'image parle en HTTP : le launcher le remplace par un contrôle HTTPS. Le navigateur demandera d'accepter le certificat ; comparez l'empreinte affichée par le launcher à celle du navigateur.
- **`architecture.json` est déposé dans l'Admin dès sa création** (`/etc/goproxify/state/`) : passerelles et Agents déclarés apparaissent à l'état déclaré. Un hôte distant n'est accepté automatiquement que pendant la validité d'un ticket d'installation de 15 minutes (`goproxify hosts join-ticket -host <nom>`, ou `POST /api/v1/hosts/{nom}/join-ticket`), créé à la demande et consommé quand ses nœuds arrivent.
- **Le hub de la passerelle (port 8000) n'est publié que s'il y a plusieurs hôtes** (et toujours sur une passerelle distante, par où l'Admin la joint). Restreignez-le au réseau d'infrastructure par le pare-feu.
- **L'Admin garde les images à installer** (`GPX_DEPLOY_REGISTRY`, `GPX_DEPLOY_TAG`) : les hôtes qui rejoignent reçoivent les mêmes que le premier.
- **Le mot de passe du premier compte** reste dans l'environnement du conteneur de l'Admin (`GPX_FIRST_ADMIN_PASSWORD`) : l'Admin le réapplique à chaque redémarrage si le compte existe avec un autre mot de passe. Retirez la variable une fois le compte en service, ou recréez le conteneur sans elle.

**Installer un hôte déclaré (`--host`).** Sur l'hôte, une seule commande, la même pour tous : le launcher attend un lien de l'Admin pendant 15 minutes sur le port 8080.

```bash
docker run --rm -p 8080:8080 -v /var/run/docker.sock:/var/run/docker.sock ghcr.io/vincamok/goproxify/launcher:preview
```

Puis `goproxify hosts join-ticket -host <nom>` (ou `POST /api/v1/hosts/{nom}/join-ticket`) donne un QR code, valable 15 minutes. Le scanner depuis un téléphone **du même réseau** ouvre la page du launcher de l'hôte : elle montre l'Admin visé et l'empreinte de son certificat, et l'installation ne démarre qu'au clic. Sans téléphone, copiez le `join_command` du ticket sur l'hôte.

- **Le téléphone doit joindre l'hôte** (port 8080, en HTTP clair sur le réseau local) et l'hôte doit joindre l'Admin en https. Le lien porte le jeton du ticket : pendant les 15 minutes, quelqu'un qui écoute le réseau local pourrait le lire. Pour un réseau qui n'est pas de confiance, préférez `join_command`, ou épinglez l'Admin (`--expect-admin`, `--expect-fingerprint`).
- **Si l'installation échoue**, ce qui avait été créé est retiré ; le même ticket permet de réessayer tant qu'il vaut. Les images se téléchargent avant tout : un téléchargement long peut dépasser les 15 minutes, auquel cas les composants arrivent après la fin de l'acceptation automatique et attendent votre approbation.
- **Sans adresse publique en https** pour l'Admin (`GPX_ADMIN_PUBLIC_URL`), le ticket ne produit ni QR code ni lien (le launcher refuse un Admin en clair) ; l'avertissement du ticket le dit.
- **Dans l'Admin**, la fiche de l'hôte (Infrastructure, Configuration de l'hôte) a une section **Launcher (QR code)** : le ticket de 15 minutes est créé à son ouverture (il remplace le précédent) et la section affiche le QR code, la commande à lancer sur l'hôte et la variante `launcher join`.

**Mettre à jour.** Sur chaque hôte, `docker run --rm -v /var/run/docker.sock:/var/run/docker.sock ghcr.io/vincamok/goproxify/launcher:preview update` tire les images les plus récentes de ses conteneurs et recrée ceux qui ont changé, en gardant leurs volumes, leurs variables et leurs secrets ; un conteneur qui ne devient pas sain retrouve son ancienne image (détails dans [cli.md](cli.md#mettre-à-jour-un-hôte--launcher-update)).

**Concevoir l'infrastructure depuis le navigateur.** Le même launcher, lancé sans paramètre, sert `http://<hôte>:8080/design` : on y déclare ses hôtes, on simule, puis on installe l'hôte local. L'interface donne l'accès d'un root sur l'hôte : le code d'accès (`ABCD-EFGH`) est dans la sortie du conteneur (`docker logs <conteneur>`, ou le terminal où vous l'avez lancé). Il circule en clair (HTTP) : si le réseau n'est pas de confiance, publiez le port sur `127.0.0.1` (`-p 127.0.0.1:8080:8080`) et passez par un tunnel SSH ; le QR code d'un hôte suivant exige en revanche que le port soit joignable depuis le téléphone. Le mot de passe du premier compte et la **clé de sauvegarde** (`GPX_BACKUP_KEY`, qui chiffre la partie secrets des sauvegardes de l'Admin, secret racine compris) s'affichent à la fin et restent dans la sortie du conteneur : lisez-les avant de cliquer sur **Terminer**, et notez la clé ailleurs que sur l'hôte (sans elle une sauvegarde ne se relit pas).

---

## Fond de carte vectoriel (optionnel)

Par défaut, les cartes de l'Admin (Prism, Sécurité, Vue Proxy) utilisent des contours de pays et de régions embarqués : aucune requête vers un tiers, mais un zoom limité à l'échelle régionale. Pour zoomer jusqu'à la rue **sans service de tuiles externe**, posez sur le serveur de l'Admin un fond vectoriel au format [PMTiles](https://docs.protomaps.com/pmtiles/) (données © contributeurs OpenStreetMap, découpées par Protomaps).

1. Installer l'outil `pmtiles` ([releases go-pmtiles](https://github.com/protomaps/go-pmtiles/releases)).
2. Découper la zone voulue dans une version quotidienne de la carte du monde (la planète entière pèse plus de 100 Go ; une région ou un pays suffit presque toujours) :

   ```bash
   # la France métropolitaine jusqu'au zoom 14 (plusieurs Go ; adapter --bbox=ouest,sud,est,nord)
   pmtiles extract https://build.protomaps.com/20261001.pmtiles basemap.pmtiles \n     --bbox=-5.5,41.2,9.8,51.3 --maxzoom=14
   ```

   Le nom du fichier source est une date de version au format AAAAMMJJ (`20261001.pmtiles` existait au moment de l'écriture ; en cas d'erreur 404, essayer une date plus récente). Un quartier (`--bbox=2.20,48.82,2.46,48.90 --maxzoom=14`) pèse une dizaine de Mo. Au-delà du zoom 14 les tuiles sont agrandies (surzoom).
3. Copier le fichier sur le serveur de l'Admin, à l'emplacement `<stockage>/basemap/basemap.pmtiles` (`/etc/goproxify/basemap/basemap.pmtiles` par défaut), ou ailleurs en renseignant la variable `GPX_BASEMAP_PATH`. Le fichier est relu à chaque requête : ni redémarrage ni reconstruction de l'image.
4. Recharger l'interface : la carte affiche le fond sous les pays et zoome jusqu'à 2 niveaux au-delà de la dernière tuile.

Le fond n'est dessiné que dans la zone qu'il couvre : à l'extérieur, la carte garde ses contours de pays. Le fichier est servi tel quel (`GET /map/basemap.pmtiles`, requêtes partielles `Range`, sans authentification : ce sont des données cartographiques publiques) ; le navigateur ne lit que les tuiles visibles. Le thème clair ou sombre de l'interface est suivi. Le fichier n'est pas inclus dans les sauvegardes de l'Admin : il se retélécharge.

## Base des systèmes autonomes (ASN)

Les bans par ASN s'appuient sur le jeu public ip2asn (iptoasn.com). L'Admin le télécharge **tout seul au premier usage** (9 Mo, depuis `https://iptoasn.com/data/ip2asn-combined.tsv.gz`) : il faut donc que l'Admin puisse joindre ce site, ou que le fichier soit posé à la main. Il est rangé dans `<stockage>/asn/ip2asn-combined.tsv.gz` (`/etc/goproxify/asn/…` par défaut, dans le volume de l'Admin). Variables : `GPX_ASN_DB_PATH` (emplacement du fichier) et `GPX_ASN_DB_URL` (source, par exemple un miroir interne). Sur un Admin sans accès à Internet, télécharger le fichier ailleurs et le copier à l'emplacement ci-dessus. Mise à jour : `goproxify security bans asn refresh`.

## Références

- [Architecture](architecture.md) — détail des composants et flux internes
- [CLI](cli.md) — toutes les commandes et options du binaire
- [FAQ](faq.md) — questions fréquentes
- [CONTRIBUTING.md](../CONTRIBUTING.md) — contribuer au projet

---

## Migration depuis la version « Core »

Le composant historique « Core » s'appelle désormais **passerelle** (`edge` dans les commandes, variables, images et fichiers). Il n'y a pas de couche de compatibilité : les anciens noms ne sont plus lus et un déploiement existant se migre à la main (voir ci-dessous).

À adapter :

| Avant | Après |
|---|---|
| service/conteneur `goproxify-core`, image `…/core` | `goproxify-edge`, `…/edge` |
| `goproxify core` | `goproxify edge` |
| `GPX_CORE_*`, `GPX_IDENTITY_CORE_NODE_NAME`, `GPX_CONTROL_PLANE_CORE_ENDPOINT` | `GPX_EDGE_*`, `GPX_IDENTITY_EDGE_NODE_NAME`, `GPX_CONTROL_PLANE_EDGE_ENDPOINT` |
| métriques `gpx_core_*` | `gpx_edge_*` (dashboards et alertes) |
| fichiers du volume `core.json`, `core-cache.gpx`, `core-tokens.db` | `edge.json`, `edge-cache.gpx`, `edge-tokens.db` (à renommer) |
| clés `core_*` dans `agent.json` / `edge.json` | `edge_*` |
| base SQLite de l'Admin (colonnes `core_*`, rôles et périmètres `core`) | non migrée : base neuve, ou renommage manuel |
| champs JSON `core_*`, options CLI `-core`, paramètres d'outils MCP | `edge_*`, `-edge` |

Pour garder les données du volume existant, déclarez-le sous son ancien nom :

```yaml
volumes:
  goproxify_edge_data:
    name: goproxify_core_data
```

---

## Clé locale de la passerelle

Depuis la passerelle `0.98.0`, les copies locales (cache de routes, certificats et plugins, configurations, clé de pseudonymisation des IP des logs) sont chiffrées par une **clé locale propre à la passerelle**, et plus par une clé dérivée du secret d'appairage. Changer `GPX_PAIRING_SECRET` ne les rend donc plus illisibles.

Ordre de choix de la clé :

1. `GPX_NODE_KEY` : la clé elle-même (32 caractères au moins).
2. `GPX_NODE_KEY_FILE` : le chemin d'un fichier de secret Docker qui la contient.
3. Sinon, la passerelle **génère** une clé au premier démarrage dans `node.key` à la racine du volume d'état (`GPX_NODE_KEY_PATH` pour changer l'emplacement), avec un avertissement dans les logs.
4. Sinon, l'ancienne clé dérivée du jeton ou du secret d'appairage.

Il n'y a rien à reconfigurer à la mise à jour : au premier démarrage, la passerelle relit ses copies avec l'ancienne clé et les réécrit avec la nouvelle. Une clé fournie plus tard par `GPX_NODE_KEY` ne rend pas illisible ce que la clé générée avait chiffré.

- **La clé générée est sur le même disque que les données.** Elle sépare le chiffrement du secret d'appairage, pas plus : pour la garder hors du volume, fournissez `GPX_NODE_KEY` ou un fichier de secret.
- **Sauvegardez `node.key` avec le volume** (la sauvegarde d'état de la passerelle l'inclut) : sans elle, une restauration sur un volume neuf ne relit plus les copies chiffrées, et la passerelle repart de ce que l'Admin lui renvoie.
- **Le portail Access** garde sa clé maître propre (`GPX_PORTAL_MASTER_KEY` ; à défaut le secret d'appairage s'il est présent, sinon la clé locale de la passerelle) : elle doit être identique sur tous les membres d'un groupe HA pour que les coffres des comptes SSO se déchiffrent partout. Un membre en attente du portail renvoie son hôte vers le port HTTP du portail (`8444`) des autres membres : ce port doit être joignable entre les membres.

## Changer le secret d'appairage

Depuis la passerelle `0.98.0`, la procédure ci-dessous ne concerne plus que les passerelles qui n'ont pas encore démarré avec une clé locale (voir ci-dessus) et la clé maître du portail quand `GPX_PORTAL_MASTER_KEY` n'est pas posée.

À faire après une fuite, un départ, ou périodiquement. Le secret `GPX_PAIRING_SECRET` fait deux choses sur la passerelle : il authentifie le WebSocket de l'Admin et l'appairage des Agents, et **il dérive la clé qui chiffre ses copies locales** (routes, certificats, plugins, réglages, règles automatiques, portail Access). Le changer sans précaution rend ces copies illisibles : la passerelle repart « sans config » et ne sert plus rien de ce qu'elle tenait de l'Admin tant qu'il ne lui renvoie pas tout — c'est exactement ce que l'autonomie (ADR 0006) doit éviter. Mesuré sur un cluster : après un changement sans précaution, la passerelle journalise `cache local illisible`, `paquet ignoré` pour chaque plugin et `copie locale illisible` pour les réglages, le portail et les règles.

Procédure (le principe est le même avec Compose, Portainer ou Helm) :

1. Générez le nouveau secret (`openssl rand -hex 32`) et la clé d'Agent qui en dérive (`printf %s "goproxify/agent-pairing/v1:<nouveau secret>" | sha256sum | cut -d' ' -f1`).
2. **Passerelles** : `GPX_PAIRING_SECRET=<nouveau>` et `GPX_PAIRING_SECRET_PREVIOUS=<ancien>` (plusieurs anciens séparés par des virgules). **Admin** : `GPX_PAIRING_SECRET=<nouveau>`. **Agents** : `GPX_AGENT_PAIRING_KEY=<nouvelle clé>`. Avec le chart : `--set global.pairingSecret=<nouveau> --set global.previousPairingSecret=<ancien>` ; un changement de secret redémarre seul les pods (annotation `checksum/secret`).
3. Redémarrez Admin, passerelles et Agents. Le WebSocket Admin → passerelle ne se rétablit que lorsque les deux ont le nouveau secret : les passerelles continuent de servir pendant ce temps, avec leurs copies locales relues grâce à l'ancien secret et **réécrites avec le nouveau** au démarrage.
4. Une fois toutes les passerelles redémarrées avec la variable, retirez `GPX_PAIRING_SECRET_PREVIOUS` (une passerelle qui n'a pas encore redémarré garde ses copies sous l'ancienne clé : attendez qu'elles l'aient toutes fait). Redémarrez une dernière fois pour vérifier : plus rien ne dépend de l'ancien secret.

À savoir :

- **`GPX_PAIRING_SECRET_PREVIOUS` ne sert qu'à relire des données locales** ; il n'authentifie jamais rien. Après une fuite, l'ancien secret cesse donc d'ouvrir `/ws/admin` et l'appairage dès le redémarrage, même si la variable reste posée.
- **Les jetons déjà émis restent valables** : l'ancien secret ne permet plus d'en obtenir, mais un jeton d'Agent ou de passerelle volé continue de fonctionner jusqu'à sa révocation (Admin → Jetons, ou suppression du nœud). Après une fuite, révoquez-les et réappairez les nœuds.
- **Le portail Access** dérive sa clé du même secret quand `GPX_PORTAL_MASTER_KEY` n'est pas posée : la base du portail, les coffres d'identifiants des comptes SSO et les enregistrements de sessions en dérivent. Pour le rendre indépendant du secret d'appairage, posez `GPX_PORTAL_MASTER_KEY` avec **la valeur actuelle** du secret (ou de `GPX_CONTROL_PLANE_AUTH_TOKEN` s'il est posé), identique sur tous les membres d'un groupe HA : rien ne change et le portail ne suit plus le secret d'appairage. **Ne la remplacez pas par une clé neuve** : les coffres SSO et les enregistrements existants ne se relisent pas avec une autre valeur (`GPX_PAIRING_SECRET_PREVIOUS` ne relit que le fichier de la base).
- **Vérifié** sur un cluster à Admin coupé : secret changé sans l'ancien → cache, deux plugins, réglages, règles et portail illisibles ; avec `GPX_PAIRING_SECRET_PREVIOUS` → tout relu, plugins chargés (2) ; redémarrage sans la variable → plugins chargés (2). Admin remis en route : passerelle et Agent en ligne, plugins conservés, aucun refus côté Agent.

## Épingler les clés de signature des plugins

Par défaut une passerelle fait confiance à l'Admin pour les plugins qu'il lui pousse (seule l'empreinte est contrôlée). Pour qu'un Admin compromis ne puisse pas lui faire exécuter de code, posez sur **chaque passerelle** `GPX_PLUGIN_TRUSTED_KEYS=<clé publique Ed25519 base64>[,…]` (ou `GPX_PLUGIN_TRUSTED_KEYS_FILE`) ; avec Helm, `global.pluginTrustedKeys`. Elle refuse alors tout plugin non signé par l'une de ces clés — les plugins intégrés de l'Admin compris — et revérifie ses copies locales au redémarrage. Détails, limites et mise en place des clés : [plugins.md](plugins.md#clés-épinglées-sur-la-passerelle).

## Kubernetes (chart Helm)

```bash
helm install goproxify ./helm/goproxify \
  --namespace goproxify --create-namespace \
  --set global.pairingSecret=$(openssl rand -hex 32)
```

`global.pairingSecret` est **obligatoire** : c'est le `GPX_PAIRING_SECRET` que partagent l'Admin et la passerelle (l'ancien `global.authToken` est encore lu). Les Agents n'en reçoivent pas : le chart leur donne `GPX_AGENT_PAIRING_KEY`, dérivée dans le secret `agent-pairing-key` ; `security.agentPairingWithRootSecret: true` ré-accepte le secret racine d'un Agent (anciennes installations). Le chart pose aussi `GPX_AGENT_BIND_IDENTITY=true` sur les passerelles : un Agent ne peut agir (heartbeat, routes, événements) qu'au nom sous lequel son jeton a été émis. Hors chart, activez-le une fois les Agents appairés sous leur nom définitif. Le chart crée :

| Objet | Rôle |
|---|---|
| `Deployment` Admin + `Service` + `PersistentVolumeClaim` | Administration, base SQLite sur le volume (`admin.persistence`) ; `ingress` facultatif |
| `DaemonSet` passerelle (`hostNetwork`, ports 80/443 de l'hôte) | Une passerelle par nœud, nommée d'après le nœud (`spec.nodeName`) et jointe par l'Admin à son adresse de pod |
| `Service` `…-edge` (80/443) et `…-edge-internal` (API interne, **ClusterIP** seulement) | Le trafic public, et l'API interne qui ne doit jamais sortir du cluster |
| `DaemonSet` Agent + `ClusterRole` en lecture | Découverte Kubernetes (`agent.config.kubernetes.*`) et, si `agent.config.runtime` vaut `docker` ou `podman`, des conteneurs du nœud ; il joint la passerelle de son nœud |

Les passerelles et les Agents gardent leur identité, leurs certificats chiffrés et leur état dans `/etc/goproxify`, monté depuis un dossier de l'hôte (`edge.persistence.hostPath`, `agent.persistence.hostPath`) : sans lui, chaque redémarrage de pod donnerait une nouvelle identité. Mettre la valeur à vide les passe en `emptyDir` (tests seulement).

**Sécurité du chart.** L'Admin s'exécute en utilisateur non privilégié (`security.adminRunAsUser`, 10001), sans capacité ni élévation de privilèges, avec le profil seccomp du runtime. L'Agent ne reçoit **aucun socket de conteneurs par défaut** (`agent.config.runtime: none`) : `docker` ou `podman` monte le socket de l'hôte, ce qui donne à l'Agent le contrôle de l'hôte — limitez-le aux nœuds concernés avec `agent.nodeSelector`. Monter un socket « en lecture seule » n'empêche pas d'y envoyer des requêtes d'écriture.

**Joindre les passerelles.** L'Admin ne devine pas l'adresse d'une passerelle : déclarez-les avec `admin.edgeEndpoints` (`--set "admin.edgeEndpoints[0].name=<nœud>" --set "admin.edgeEndpoints[0].url=http://<IP du nœud>:8000"`). Le nom est celui du nœud Kubernetes (`kubectl get nodes`), l'adresse celle du nœud (hostNetwork). Avec `edge.kind=Deployment`, la passerelle est déclarée automatiquement.

**Découverte Kubernetes.** Annotez un `Service` ou un `Ingress` : label `goproxify.enabled=true` (sélection) et annotation `goproxify.host=app.example.com` ; l'Agent du nœud annonce la route à sa passerelle. Un `Service` dont l'objet `Endpoints` n'a aucune adresse prête (zéro réplique, pods pas prêts) s'affiche **inactif** dans l'Admin et n'a plus de route tant qu'un pod n'est pas prêt ; le chart donne déjà à l'Agent le droit de lire les `endpoints`, sinon aucun Service n'est donné inactif.

Limites : le chart a été installé sur un cluster kind (un plan de contrôle, deux nœuds de travail) : Admin en utilisateur 10001, appairage de chaque Agent à la passerelle de son nœud, Admin ↔ passerelles, découverte d'un `Service` et d'un `Ingress` annotés (route créée puis retirée à la suppression), trafic jusqu'au pod par chaque nœud, identité conservée à la suppression des pods, mode `Deployment`. Choisissez `DaemonSet` ou `Deployment` à l'installation : en changer plus tard laisse les Agents avec le jeton de l'ancienne passerelle. Non éprouvé : un runtime Docker/Podman, un vrai cloud (stockage, LoadBalancer).
