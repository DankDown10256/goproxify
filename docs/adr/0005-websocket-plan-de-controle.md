# ADR-0005 — Plan de contrôle WebSocket (Agent→Core, Admin→Core)

**Statut :** Accepté  
**Date :** 2026-07-30  
**Remplace :** modèle HTTP push/poll décrit implicitement dans ADR-0001

---

## Contexte

Le plan de contrôle initial repose sur des appels HTTP ponctuels (fire-and-forget) entre trois composants :

| Flux | Mécanisme | Problèmes identifiés |
|------|-----------|----------------------|
| Admin → Core | `POST /internal/v1/routes` … (push immédiat) | Exige un port entrant sur chaque Core depuis l'Admin |
| Core → Admin | `POST /internal/v1/heartbeat` toutes les 30 s | Latence de détection de panne = 30 s |
| Agent → Core | `POST /internal/v1/agent/heartbeat` toutes les 30 s | Exige un port entrant sur Core depuis l'Agent et un port entrant sur l'Agent depuis Core pour les commandes relayées |
| Admin → Agent | Relay via Core → `POST /internal/v1/command` sur :8001 | Port :8001 de l'Agent doit être joignable depuis Core |

Ces contraintes imposent des règles de firewall complexes et empêchent l'utilisation de l'Agent derrière un NAT ou sur un réseau distant (cas Portainer multi-hôtes).

Par ailleurs, les tokens sont statiques (jamais rotatifs), ce qui réduit la sécurité en cas de fuite.

---

## Décision

Remplacer l'intégralité du plan de contrôle HTTP par des **tunnels WebSocket persistants initiés par le client** :

```
Admin  ──WS──►  Core :8000/ws/admin    (Admin initie, HMAC-SHA256)
Agent  ──WS──►  Core :8000/ws/agent    (Agent initie, JOIN_TOKEN → HMAC rotatif)
```

Le Core devient le seul hub de connexion. Il ne contacte plus Admin ni Agent de manière sortante — ce sont eux qui maintiennent la connexion.

### Protocole de messages

Chaque message WS est une enveloppe JSON :
```json
{ "seq": 42, "type": "push_routes", "payload": { ... } }
```

`seq` est un compteur croissant côté émetteur ; le récepteur peut détecter les trous et demander une re-synchronisation.

**Messages Admin → Core :**
- `push_routes`, `delete_route`, `push_cert`, `push_snippets`, `push_auth_providers`, `push_ip_profiles`, `push_settings`, `push_cluster_peers`, `push_delegations`, `full_sync`

**Messages Agent → Core :**
- `register`, `heartbeat`, `containers`, `metrics`, `event`, `log`

**Messages Core → Agent :**
- `approve`, `command`, `rescan`, `ping`

### Sécurité et cycle de vie des tokens

| Niveau | Mécanisme | Durée de vie |
|--------|-----------|--------------|
| Admin ↔ Core | HMAC-SHA256 sur header `X-Goproxify-Timestamp` + signature de l'URL, protection replay ±5 min | Clé statique configurée (`GPX_CONTROL_PLANE_ADMIN_HMAC_SECRET`) |
| Agent → Core (bootstrap) | `JOIN_TOKEN` transmis en header WS upgrade | 24 h, usage unique |
| Agent → Core (régime) | `agent_hmac` rotatif émis par Core après approbation | Rotation toutes les 1 h |
| Session UI Admin | JWT ECDSA P-256 | 8 h |
| Clés API externes | `gpx_api_*` révocables | Permanentes ou TTL configuré |

**Cycle de vie Agent :**
1. Opérateur génère un `JOIN_TOKEN` depuis l'UI Admin (TTL 24 h)
2. Agent se connecte à `GET /ws/agent` en transmettant le `JOIN_TOKEN`
3. Core crée l'entrée Agent en état `pending` et notifie Admin
4. Opérateur approuve l'Agent dans l'UI (`POST /api/v1/agents/{id}/approve`)
5. Core envoie un message `approve` sur le WS avec le premier `agent_hmac`
6. Agent stocke le `agent_hmac` et l'utilise pour toutes les connexions futures
7. Core émet un nouveau `agent_hmac` toutes les heures ; l'Agent l'adopte à la réception

### Résilience WS

- **Reconnexion** : backoff exponentiel 1 s → 60 s + jitter aléatoire ±20 %
- **Détection de panne** : ping/pong applicatif toutes les 30 s ; 3 pings sans pong → reconnexion
- **Séquence** : compteur `seq` par connexion ; full-sync automatique si trous détectés
- **Comportement Core en cas de coupure** :
  - Admin déconnecté → Core conserve la configuration en cache ; aucune interruption du trafic
  - Agent déconnecté → backends de cet Agent marqués `unhealthy` après 90 s d'absence de heartbeat

---

## Alternatives écartées

| Alternative | Raison d'exclusion |
|-------------|-------------------|
| gRPC bidirectionnel | Complexité (protobuf, codegen), dépendance externe lourde déjà présente mais sans usage WS |
| HTTP/2 server-push | Fragile, déprécié dans les clients modernes, non disponible en HTTP/1.1 |
| MQTT | Dépendance externe (broker), surcharge opérationnelle |
| SSE (Server-Sent Events) | Unidirectionnel, requiert HTTP polling retour pour commandes Core→Agent |
| Conserver HTTP polling | Latence 30 s, tokens statiques, ports entrants multiples — aucun des problèmes résolus |

---

## Conséquences

**Positives :**
- Seul le Core a besoin d'un port entrant (:8000), accessible uniquement en réseau interne
- Admin et Agent peuvent opérer derrière NAT, load balancer, ou réseau Docker overlay
- Propagation de config quasi-instantanée (vs 30 s de polling)
- Tokens rotatifs par Agent (rotation horaire)
- LB adaptatif natif : Agent streame CPU/mém/latence par conteneur en continu
- Canary et Shadow Mirror activables via labels Docker sans configuration manuelle

**Négatives / coûts :**
- Connexion persistante = état en mémoire dans Core (`WSHub` avec map des connexions actives)
- Migration progressive nécessaire (HTTP et WS coexistent pendant une phase transitoire)
- Nouveau workflow d'approbation Agent à documenter pour les opérateurs

**Bibliothèque choisie :** `nhooyr.io/websocket` — pure Go, API context-native, zéro dépendance CGO, activement maintenue.
