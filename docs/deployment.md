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
7. [Multi-hôtes — Core supplémentaire sur un serveur distant](#7-multi-hôtes--core-supplémentaire-sur-un-serveur-distant)
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

Pour la méthode CLI : Go 1.22+ ou le binaire pré-compilé depuis [les releases](https://github.com/Vincamok/goproxify/releases).

---

## 2. Comprendre l'architecture en trois minutes

GoProxify repose sur **trois services distincts**, chacun ayant un rôle précis :

```
Navigateur Admin
      │ HTTPS :9443
      ▼
┌─────────────┐      API interne :8000      ┌─────────────┐
│    ADMIN    │ ─────────────────────────►  │    CORE     │ :80/:443 ◄── trafic web
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

- **Core** : reçoit le trafic HTTP/HTTPS des utilisateurs finaux. Porte 80, 443.  
- **Admin** : interface web de configuration. Porte 9443. Communique avec le Core via son API interne (port 8000 — ne pas exposer sur Internet).  
- **Agent** : tourne sur chaque hôte Docker. Lit `docker.sock`, remonte les conteneurs et métriques au Core. N'expose aucun port.

**Secret de couplage (`GPX_PAIRING_SECRET`)** : les trois services partagent la même valeur. C'est le seul mécanisme d'authentification au démarrage. Générez-le aléatoirement, ne le réutilisez jamais entre environnements.

---

## 3. Méthode A — Docker Compose (recommandé)

### 3.1 Générer les secrets

```bash
# Secret de couplage (partagé Admin + Core + Agent)
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
CORE_NODE_NAME=goproxify-core
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
  goproxify_core_data:
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
      - GPX_IDENTITY_CORE_NODE_NAME=${CORE_NODE_NAME:-goproxify-core}
      - GPX_SERVER_API_PORT=9443
    ports:
      - "${ADMIN_PORT:-9443}:9443"
    volumes:
      - goproxify_admin_data:/etc/goproxify
    networks: [goproxify_net]

  goproxify-core:
    image: ghcr.io/vincamok/goproxify/core:preview
    container_name: goproxify-core
    restart: unless-stopped
    command: ["core"]
    environment:
      - TZ=${TZ:-Europe/Paris}
      - GPX_PAIRING_SECRET=${GPX_PAIRING_SECRET}
      - GPX_IDENTITY_CORE_NODE_NAME=${CORE_NODE_NAME:-goproxify-core}
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
      - "8000:8000"
    volumes:
      - goproxify_core_data:/etc/goproxify
    networks: [goproxify_net]
    depends_on: [goproxify-admin]

  goproxify-agent:
    image: ghcr.io/vincamok/goproxify/agent:preview
    container_name: goproxify-agent
    restart: unless-stopped
    command: ["agent"]
    environment:
      - TZ=${TZ:-Europe/Paris}
      - GPX_PAIRING_SECRET=${GPX_PAIRING_SECRET}
      - GPX_CONTROL_PLANE_CORE_ENDPOINT=http://goproxify-core:8000
      - GPX_CONTROL_PLANE_ADMIN_ENDPOINT=http://goproxify-admin:9443
      - GPX_IDENTITY_AGENT_NODE_NAME=${AGENT_NODE_NAME:-goproxify-agent}
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - goproxify_agent_data:/etc/goproxify
    networks: [goproxify_net]
    depends_on: [goproxify-core]
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
CORE_NODE_NAME=goproxify-core
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
  goproxify_core_data:
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
      - GPX_IDENTITY_CORE_NODE_NAME=goproxify-core
      - GPX_SERVER_API_PORT=9443
    ports:
      - "9443:9443"
    volumes:
      - goproxify_admin_data:/etc/goproxify
    networks: [goproxify_net]

  goproxify-core:
    image: ghcr.io/vincamok/goproxify/core:preview
    container_name: goproxify-core
    restart: unless-stopped
    command: ["core"]
    environment:
      - TZ=Europe/Paris
      - GPX_PAIRING_SECRET=CHANGE_ME_PAIRING_HEX32
      - GPX_IDENTITY_CORE_NODE_NAME=goproxify-core
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
    volumes:
      - goproxify_core_data:/etc/goproxify
    networks: [goproxify_net]
    depends_on: [goproxify-admin]

  goproxify-agent:
    image: ghcr.io/vincamok/goproxify/agent:preview
    container_name: goproxify-agent
    restart: unless-stopped
    command: ["agent"]
    environment:
      - TZ=Europe/Paris
      - GPX_PAIRING_SECRET=CHANGE_ME_PAIRING_HEX32
      - GPX_CONTROL_PLANE_CORE_ENDPOINT=http://goproxify-core:8000
      - GPX_IDENTITY_AGENT_NODE_NAME=goproxify-agent
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - goproxify_agent_data:/etc/goproxify
    networks: [goproxify_net]
    depends_on: [goproxify-core]
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
export GPX_IDENTITY_CORE_NODE_NAME=goproxify-core
export GPX_IDENTITY_AGENT_NODE_NAME=goproxify-agent
export GPX_CONTROL_PLANE_CORE_ENDPOINT=http://localhost:8000
export GPX_CONTROL_PLANE_ADMIN_ENDPOINT=http://localhost:9443
```

### 6.3 Démarrer les trois rôles (trois terminaux ou trois services systemd)

**Terminal 1 — Admin :**
```bash
goproxify admin
```

**Terminal 2 — Core :**
```bash
goproxify core
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

Répéter pour `core` et `agent` (avec leurs fichiers `.env` respectifs).

```bash
systemctl daemon-reload
systemctl enable --now goproxify-admin goproxify-core goproxify-agent
```

---

## 7. Multi-hôtes — Core supplémentaire sur un serveur distant

Quand vous avez un **deuxième serveur** qui doit gérer du trafic HTTP/HTTPS indépendamment, déployez-y un Core seul. L'Admin central reste unique et pilote tous les Cores.

```
┌─────────────┐  WS :8000  ┌──────────────────┐  :80/:443
│    ADMIN    │ ──────────► │  Core principal  │ ◄── trafic web A
│  (serveur 1)│             └──────────────────┘
│             │  WS :8000  ┌──────────────────┐  :80/:443
│             │ ──────────► │  Core secondaire │ ◄── trafic web B
└─────────────┘             └──────────────────┘
```

### 7.1 Prérequis réseau

Le port **8000** du Core secondaire doit être joignable depuis le serveur Admin (et depuis les Agents qui s'y connectent). Ouvrir uniquement vers les IPs concernées :

```bash
# Exemple UFW — sur le serveur Core secondaire
ufw allow from <IP_ADMIN> to any port 8000
ufw allow from <IP_AGENT> to any port 8000
```

### 7.2 Déployer le Core secondaire

Sur le serveur distant, créer un `docker-compose.yml` minimal :

```yaml
networks:
  goproxify_net:
    name: goproxify_net

volumes:
  core-lucas_data:

services:
  goproxify-core:
    image: ghcr.io/vincamok/goproxify/core:preview
    container_name: goproxify-core
    restart: unless-stopped
    command: ["core"]
    environment:
      - TZ=Europe/Paris
      # Même valeur que l'Admin et le Core principal
      - GPX_PAIRING_SECRET=<MÊME_PAIRING_SECRET>
      # Nom unique pour ce Core — doit correspondre exactement au nom configuré dans l'Admin
      - GPX_IDENTITY_CORE_NODE_NAME=core-lucas
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
      # Exposer 8000 pour que l'Admin (et les Agents distants) puissent s'y connecter
      - "8000:8000"
    volumes:
      - core-lucas_data:/etc/goproxify
    networks: [goproxify_net]
```

```bash
docker compose up -d
```

### 7.3 Enregistrer le Core secondaire dans l'Admin

L'Admin doit connaître l'adresse du Core secondaire. Deux façons :

**Via le Wizard architecture** (recommandé) :
1. Admin → **Infrastructure → Wizard**
2. Ajouter un hôte de type Core, indiquer l'IP/hostname du serveur distant
3. Cliquer **Enregistrer** — l'Admin tente immédiatement la connexion WS

**Via les variables d'environnement de l'Admin** :
```bash
# Ajouter dans le .env de l'Admin (redémarrage requis)
GPX_IDENTITY_CORE_NODE_NAME=core-lucas        # nom du Core secondaire tel que configuré sur lui
GPX_CORE_EXTRA_ENDPOINTS=http://<IP_CORE_SECONDAIRE>:8000
```

### 7.4 Vérifier la connexion

Dans l'Admin → **Infrastructure → Nœuds** : le Core secondaire doit passer de `declared` à `online` en quelques secondes après son démarrage.

Si le Core reste en `Non connecté / En attente` :

```bash
# Depuis le serveur Admin : le port 8000 est-il joignable ?
curl http://<IP_CORE_SECONDAIRE>:8000/healthz

# Logs du Core secondaire — doit afficher "full_sync reçu de l'Admin"
docker logs goproxify-core | tail -50

# Vérifier que GPX_PAIRING_SECRET est identique sur les deux machines
docker exec goproxify-core env | grep GPX_PAIRING_SECRET
```

> **`GPX_IDENTITY_CORE_NODE_NAME` est critique.** La valeur configurée sur le Core doit correspondre exactement au nom que l'Admin utilise pour le joindre. Une divergence provoque un état `declared` permanent sans message d'erreur explicite.

---

## 8. Multi-hôtes — Agent sur un serveur distant



Quand l'Agent tourne sur un hôte **différent** du Core :

### 7.1 Exposer le port 8000 du Core

Sur le serveur Core, ouvrir le port 8000 dans le pare-feu **uniquement vers les IPs des serveurs agents** (ne pas exposer sur Internet) :

```bash
# Exemple UFW
ufw allow from <IP_AGENT> to any port 8000
```

### 7.2 Configurer l'Agent

Sur le serveur Agent :

```bash
# GPX_CONTROL_PLANE_CORE_ENDPOINT pointe vers l'IP ou domaine du Core, pas localhost
export GPX_CONTROL_PLANE_CORE_ENDPOINT=http://<IP_DU_CORE>:8000
export GPX_PAIRING_SECRET=<même valeur que le Core>
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
      - GPX_PAIRING_SECRET=<PAIRING_SECRET_DU_CORE>
      - GPX_CONTROL_PLANE_CORE_ENDPOINT=http://<IP_DU_CORE>:8000
      - GPX_CONTROL_PLANE_ADMIN_ENDPOINT=http://<IP_DU_CORE>:9443
      - GPX_IDENTITY_AGENT_NODE_NAME=agent-prod-1
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
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

- Le **Core** doit apparaître comme `online`
- L'**Agent** doit apparaître comme `online` (quelques secondes après le démarrage)

Si un nœud reste en `declared` ou n'apparaît pas → voir [§10 Dépannage](#10-dépannage-courant).

### 8.4 Créer un premier proxy

1. Admin → **Proxies → Nouveau proxy**
2. Remplir : domaine, protocole cible, port cible
3. Activer le proxy → le Core commence à router le trafic immédiatement

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
docker compose logs -f goproxify-core
docker compose logs -f goproxify-agent
```

### Connectivité

```bash
# Admin accessible
curl -k https://localhost:9443/healthz

# Core accessible (API interne — depuis le même réseau que les agents)
curl http://localhost:8000/healthz

# Core proxy HTTP
curl -I http://localhost/
```

### Dans l'Admin

| Endroit | Ce qu'on vérifie |
|---------|-----------------|
| Infrastructure → Nœuds | Core et Agent en `online` |
| Infrastructure → Agent → Détail | CPU/RAM remontés (heartbeat actif) |
| Proxies | Statut `actif` sur les règles configurées |
| Logs | Pas d'erreur `401` ni `connection refused` |

---

## 11. Dépannage courant

### L'Agent n'apparaît pas dans l'Admin

Cause la plus fréquente : `GPX_PAIRING_SECRET` différent entre l'Agent et le Core.

```bash
# Comparer — les deux valeurs doivent être identiques
docker exec goproxify-core  env | grep GPX_PAIRING_SECRET
docker exec goproxify-agent env | grep GPX_PAIRING_SECRET

# Logs de l'agent — chercher status=401
docker logs goproxify-agent | grep -i "401\|heartbeat\|refused"
```

> `GPX_IDENTITY_AGENT_NODE_NAME` est **optionnel** : sans lui, un ID stable est auto-généré au premier démarrage et persisté dans le volume (`/etc/goproxify/agent-node-id`). Si le volume est absent ou recréé, l'agent change d'identité et apparaît comme un nouveau nœud.

### Le Core reste en `declared` (jamais `online`)

```bash
# L'agent peut-il joindre le Core sur le port 8000 ?
docker exec goproxify-agent curl -s http://goproxify-core:8000/healthz

# Vérifier que GPX_PAIRING_SECRET est identique sur les trois services
docker exec goproxify-core env | grep GPX_PAIRING_SECRET
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

## Références

- [Architecture](architecture.md) — détail des composants et flux internes
- [CLI](cli.md) — toutes les commandes et options du binaire
- [FAQ](faq.md) — questions fréquentes
- [CONTRIBUTING.md](../CONTRIBUTING.md) — contribuer au projet
