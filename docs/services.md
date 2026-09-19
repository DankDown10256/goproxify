# GoProxify — Services et architecture

GoProxify est composé de trois processus indépendants qui communiquent via WebSocket :

- **Admin** (port 8080/8443) — Control Plane : configuration, sécurité, interface utilisateur
- **Core** (ports 80/443/QUIC) — Data Plane : proxy HTTP/HTTPS, pipeline de sécurité
- **Agent** (Docker/K8s) — Workload Plane : sidecar de gestion des conteneurs

---

## Admin

| Service | Rôle |
|---|---|
| **HTTP Server** | Sert l'API REST (`/api/v1/`) et l'interface web. Point d'entrée unique du control plane. |
| **WebSocket Manager** | Maintient les connexions WebSocket persistantes vers chaque Core et Agent. Pousse config et commandes. |
| **Auth / JWT** | Émet et valide les tokens JWT des sessions utilisateur. Gère les providers OIDC et SAML. |
| **RBAC** | Contrôle les permissions par rôle (admin, viewer, operator) sur chaque ressource API. |
| **MFA** | Gère TOTP, passkeys WebAuthn et les codes de récupération pour les utilisateurs. |
| **Audit Logger** | Journalise chaque action admin (création/suppression/modification) dans la table SQLite `audit_logs`. |
| **Fail2Ban** | Analyse la table `logs` toutes les 30 s, bannit automatiquement les IPs abusives (4xx répétés). |
| **CrowdSec Bouncer** | Synchronise les décisions de la LAPI CrowdSec toutes les 60 s vers `security_bans`. |
| **Rules Engine** | Évalue des règles automatiques toutes les 60 s (pic de bans, CVE critique, moteur silencieux, taux d'erreur). |
| **VulnScan** | Sonde les en-têtes HTTP des backends toutes les 6 h et interroge NVD pour détecter les CVEs. |
| **Alerting** | Envoie des notifications (webhook, email, Slack) quand un seuil ou une règle est franchi. |
| **ACME / Let's Encrypt** | Renouvelle automatiquement les certificats TLS via DNS-01 ou HTTP-01. |
| **Backup Scheduler** | Crée des snapshots SQLite selon le cron configuré, les stocke dans `basePath/backups/`. |
| **HA / Raft** | Coordonne l'élection du leader en mode multi-nœuds (Raft) et relaie les requêtes vers le leader. |
| **Analytics** | Agrège les logs en métriques de trafic (requêtes/h, top IPs, top domaines) pour le dashboard. |
| **MCP Server** | Expose les ressources GoProxify comme outils pour les LLMs via le protocole MCP. |

---

## Core

| Service | Rôle |
|---|---|
| **HTTP Dispatcher** | Reçoit les requêtes HTTP/HTTPS entrantes, applique le pipeline de sécurité et les route vers les backends. |
| **HTTPS / TLS Server** | Termine le TLS, gère le SNI, sert les certificats depuis le CertStore. |
| **QUIC Server** | Accepte les connexions HTTP/3 via QUIC (port 443 UDP). |
| **Router** | Sélectionne le backend cible selon l'host, le path et les règles de routage (canary, shadow). |
| **Load Balancer** | Répartit le trafic entre les backends d'un groupe (round-robin, least-conn, adaptive). |
| **Backend Health** | Sonde périodiquement les backends, les met en quarantaine en cas d'erreur de transport. |
| **WAF Comportemental** | Accumule un profil par IP dans une fenêtre glissante et calcule un score de risque comportemental. |
| **WAF Règles** | Évalue les règles WAF (patterns OWASP, custom) sur chaque requête et bloque si le score dépasse le seuil. |
| **Rate Limiter** | Applique un token bucket par IP et par host ; bloque les IPs au-delà du seuil. |
| **Auth Pipeline** | Valide les tokens JWT/OIDC/SAML sur les routes protégées avant de relayer la requête. |
| **CertStore** | Stocke et distribue les certificats TLS en mémoire ; notifie le TLS server des mises à jour. |
| **ProxyStore** | Charge et recharge la configuration des proxies (YAML) sans redémarrage. |
| **Internal API** | Sert les endpoints `POST /internal/v1/` : push config depuis Admin, métriques, scores LB. |
| **Gateway Peers** | Synchronise les scores adaptatifs et les profils WAF avec les autres nœuds Core (cluster). |
| **Portal** | Gère les sessions UUID one-shot/multi pour l'accès terminal/web aux conteneurs via le Core. |
| **Metrics Exporter** | Expose `/metrics` (Prometheus) et `/internal/v1/metrics/summary` (JSON résumé par proxy). |

---

## Agent

| Service | Rôle |
|---|---|
| **WebSocket Client** | Maintient la connexion persistante vers le Core. Reçoit commandes et pousse événements. |
| **Docker Runtime** | Démarre, arrête, liste les conteneurs Docker sur l'hôte. Exécute les commandes `exec`. |
| **Kubernetes Runtime** | Interagit avec l'API Kubernetes pour gérer pods, déploiements et namespaces. |
| **Container Registry** | Tire les images depuis les registries configurées (Docker Hub, Harness, privé). |
| **Log Streamer** | Streame les logs des conteneurs vers le Core en temps réel (WebSocket). |
| **Health Monitor** | Vérifie périodiquement l'état des conteneurs gérés et notifie le Core en cas de crash. |
| **Tunnel Server** | Ouvre des tunnels TCP/WebSocket entre le navigateur (via Core) et les services internes des conteneurs. |
| **SSH Proxy** | Relaye les sessions SSH vers les conteneurs ou hôtes cibles, avec audit de session. |
| **Metrics Collector** | Collecte les métriques système (CPU, RAM, I/O) des conteneurs et les agrège pour le dashboard. |
| **Snapshot Manager** | Crée des snapshots de volume et les envoie vers le stockage objet configuré. |
| **Network Inspector** | Inspecte le trafic réseau inter-conteneurs pour détecter des anomalies (ports inattendus, exfiltration). |
| **Config Watcher** | Surveille les ConfigMaps/Secrets Kubernetes ou les fichiers de config Docker et déclenche un rechargement. |
| **Auto-Scaler** | Ajuste le nombre de réplicas d'un déploiement selon les métriques de charge reçues du Core. |
