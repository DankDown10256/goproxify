# FAQ — Goproxify

Base de connaissances incidents utilisateurs et questions fréquentes.

---

## Démarrage & Initialisation

**Q : L'interface d'administration affiche un écran d'initialisation au premier lancement, est-ce normal ?**
Oui. Goproxify détecte l'absence de base SQLite et force la configuration du compte administrateur initial. Renseignez un email et un mot de passe fort, puis validez.

**Q : J'ai perdu le mot de passe administrateur. Comment le réinitialiser ?**
Utilisez la CLI directement sur le serveur (accès direct à la SQLite, sans passer par l'API) :
```bash
goproxify admin -reset-password -email "admin@example.fr" -password "nouveauMdp123!"
```

---

## Proxies & Routage

**Q : Pourquoi certains proxies apparaissent-ils grisés et non modifiables dans l'UI ?**
Ces proxies ont été découverts automatiquement via les **labels Docker** par un Agent. Ils sont en lecture seule pour éviter toute désynchronisation entre la configuration déclarative (Compose) et l'Administration. Pour les modifier, mettez à jour les labels dans votre fichier Docker Compose.

**Q : Comment configurer un proxy via Docker Compose ?**
Ajoutez des labels à votre service. Utilisez l'onglet "Générateur de Labels" dans l'UI pour vous guider. Exemple minimal :
```yaml
services:
  monapp:
    image: monapp:latest
    labels:
      goproxify.enable: "true"
      goproxify.host: "monapp.example.fr"
      goproxify.port: "8080"
      goproxify.tls: "true"
      # Optionnel — sécurité (snippets / auth Admin, ou inline)
      # goproxify.snippets: "headers-secure,rate-api"
      # goproxify.auth_provider: "authentik-prod"
      # goproxify.waf: "block"
    # Pas de ports: - "8080:8080" — le Core se connecte au réseau interne
    networks:
      - mon_reseau_app

networks:
  mon_reseau_app:
```

**Q : Mon application n'est pas accessible après le déploiement. Que vérifier ?**
1. L'Agent est-il démarré et connecté au Core (`GET /api/v1/agents`) ? Statut `online` attendu.
2. Si l'Agent est en statut `pending` : avez-vous approuvé l'Agent dans l'UI ?
3. Le conteneur du Core a-t-il été connecté au réseau Docker de l'app (vérifiez `docker network inspect`) ?
4. Le certificat TLS a-t-il été acquis (`GET /api/v1/certs`) ?
5. Les logs de l'Agent (`/etc/goproxify/logs/agent.log`) indiquent-ils une erreur ?

---

## TLS & Certificats

**Q : Goproxify supporte-t-il les certificats Wildcard ?**
Oui, via ACME DNS-01 (Let's Encrypt). Un certificat `*.example.fr` couvre tous les sous-domaines sans configuration individuelle. Configurez votre provider DNS dans les snippets (`dns_providers`).

**Q : Les certificats sont-ils rechargés sans interruption ?**
Oui. L'Administration pousse les certificats décodés directement en RAM dans le Core via la fonction `GetCertificate` du TLS natif Go. Aucun rechargement (`reload`) n'est nécessaire.

**Q : Quels providers DNS sont supportés pour ACME DNS-01 ?**
OVH, Cloudflare, Gandi, Route53 (AWS), Hetzner DNS.

---

## Performance & Stabilité

**Q : Le Core peut-il être mis à jour sans interrompre les connexions HTTP/3 QUIC ou WebSocket ?**
Oui. La table de routage est stockée dans un `sync.Map` — les mises à jour sont atomiques et ne coupent pas les connexions existantes.

**Q : Qu'est-ce que le "P99 plat" mentionné dans la documentation ?**
Grâce à un pool de buffers (`sync.Pool`), le Core recycle les allocations réseau au lieu de les soumettre au ramasse-miettes Go. Cela évite les pics de latence (GC pauses) sous charge intensive, maintenant le 99e percentile de latence stable.

---

## Sécurité & Tokens

**Q : Le scanner CVE marque tous les backends « Injoignable — adresse IP interdite (SSRF) ». Que faire ?**
C’est le comportement attendu. Le scanner (processus Admin) sonde directement les URLs `backends[].url` des proxies, pas le domaine public. Par défaut, les IPs privées (RFC1918/ULA : `192.168.x`, `10.x`, `172.16–31.x`), localhost et les endpoints metadata cloud sont refusés (anti-SSRF).

Pour scanner des backends Docker / LAN joignables depuis l’Admin, activez l’opt-in sur l’Admin puis redémarrez-le :

```bash
GPX_VULNSCAN_ALLOW_PRIVATE=true
```

(Helm : `admin.config.vulnscanAllowPrivate: true`.) Localhost et metadata restent bloqués. Vérifiez aussi que l’Admin peut joindre ces IPs sur le réseau ; sinon le refus SSRF sera remplacé par une erreur réseau.

Ne mettez pas l’URL publique du proxy dans `backends[].url` pour contourner le blocage : cela casserait le routage et le scan ne verrait pas les headers du vrai backend.

**Q : Que faire si un token d'appairage est compromis ?**
Révoquez-le immédiatement via l'UI (`DELETE /api/v1/tokens/:id`) ou la CLI, puis générez-en un nouveau pour le node concerné. Le Core ou l'Agent concerné se déconnectera et devra être redémarré avec le nouveau token.

**Q : Les tokens ont-ils une durée de vie limitée ?**
Par défaut, les tokens générés via `goproxify token` sont permanents. Vous pouvez spécifier un TTL (`-ttl 24h`) pour des tokens éphémères lors de déploiements CI/CD.

**Q : Qu'est-ce que le `JOIN_TOKEN` et à quoi sert-il ?**
Le `JOIN_TOKEN` (variable `GPX_CONTROL_PLANE_JOIN_TOKEN`) est un token éphémère (TTL 24 h) utilisé par l'Agent pour initier sa première connexion WebSocket vers le Core. Il identifie l'Agent et déclenche le workflow d'approbation :

1. L'Agent se connecte avec le `JOIN_TOKEN` → état `pending`
2. L'opérateur approuve dans l'UI ou via `POST /api/v1/agents/:id/approve`
3. Le Core envoie un `agent_hmac` (secret HMAC-SHA256) via WS → état `approved`
4. Les connexions WS suivantes utilisent l'`agent_hmac` (rotatif toutes les heures)

**Q : Pourquoi l'Agent n'a-t-il plus besoin de port entrant pour le plan de contrôle ?**
La nouvelle architecture WS inverse le modèle de connexion : c'est l'Agent qui initie la connexion vers le Core (tunnel WS persistant Agent→Core). Le Core est le seul hub de connexion. L'Agent n'écoute donc plus sur un port entrant pour recevoir des commandes — elles sont poussées via le tunnel WS établi par l'Agent.

Le port `:8001` (ancienne API interne Agent) est conservé temporairement pour la rétrocompatibilité mais disparaîtra après la migration complète.

**Q : Comment ré-appairer un Agent après rotation ou expiration du `agent_hmac` ?**
Si l'`agent_hmac` est perdu (redémarrage de l'Agent sans persistance), générez un nouveau `JOIN_TOKEN` dans l'UI (Admin → Tokens → Créer → rôle `agent`), et configurez-le dans `GPX_CONTROL_PLANE_JOIN_TOKEN` avant de redémarrer l'Agent. L'Admin recevra à nouveau une notification `agent_pending` et une approbation sera requise.

**Q : Comment fonctionne la rotation automatique du `agent_hmac` ?**
Toutes les heures, le Core génère un nouveau secret HMAC-SHA256 et l'envoie à l'Agent via le message WS `rotate_hmac`. L'Agent adopte immédiatement le nouveau secret pour ses connexions futures. Si la connexion est perdue durant la rotation, l'Agent se reconnecte avec l'ancien HMAC (toujours valide jusqu'à la prochaine connexion établie) — le Core le met à jour dès la reconnexion.

---

## Domaines & délégation multi-Core

**Q : Quelle est la différence entre Passthrough et Terminate ?**
- **Passthrough** : le Core d'entrée forward le flux TLS sans le déchiffrer. Le Core cible voit l'IP du Core d'entrée dans ses logs.
- **Terminate** : le Core d'entrée termine le TLS, puis proxy HTTP(S) vers le Core cible avec `X-Forwarded-For` / `X-Real-IP`. Le Core cible peut logger l'IP publique du client.

Détails, prérequis et schémas : [delegation.md](delegation.md).

**Q : En délégation, le Core cible ne loggue que l'IP du Core d'entrée — est-ce normal ?**
Oui en mode **Passthrough** (tunnel TCP). Passez en **Terminate** si vous avez besoin de l'IP client sur le Core cible (et que le Core d'entrée voit déjà des IPs publiques).

**Q : Terminate renvoie 502 / « aucun certificat » sur le Core cible ?**
Le Core d'entrée doit se reconnecter en HTTPS avec le **SNI = domaine** (pas l'IP de l'endpoint). C'est le comportement attendu depuis le correctif SNI vhost ; redéployez le Core d'entrée et re-poussez les délégations. Vérifiez aussi que le Core d'entrée a bien le certificat du domaine (périmètres token).

**Q : Core d'entrée vs droits sur un domaine ?**
Le Core d'entrée définit **qui reçoit le trafic** (routage / délégation / ACME). Les **droits** (qui reçoit routes et certificats) se gèrent via les **périmètres domaine** du token Core — les deux sont indépendants.

---

## Agent & Docker

**Q : L'application doit-elle obligatoirement exposer ses ports sur l'hôte ?**
Non — c'est précisément l'intérêt du modèle Agent. L'Agent connecte à chaud le conteneur Core au réseau bridge privé de l'application. Aucun port n'est publié sur l'hôte physique (`-p` ou `ports:` dans Compose).

**Q : L'Agent fonctionne-t-il avec Podman ?**
Podman expose une API compatible Docker sur un socket Unix. Pointez `AGENT_DOCKER_SOCKET` vers le socket Podman (ex: `/run/user/1000/podman/podman.sock`). Le support est expérimental.
