# ADR-0006 — Autonomie des composants (passerelle, groupe HA, Agent)

**Statut :** Accepté  
**Date :** 2026-09-29  
**Complète :** ADR-004 (cache local de la passerelle), ADR-0005 (plan de contrôle WebSocket)

---

## Contexte

L'ADR-004 pose que la passerelle doit servir le **trafic** sans l'Administration, même après un redémarrage. Le principe n'était écrit ni pour les autres fonctions de la passerelle, ni pour les groupes HA, ni pour l'Agent.

Conséquence observée : la configuration du portail Access n'existe qu'en base Admin et en mémoire de la passerelle. Si une passerelle redémarre pendant une coupure de l'Admin, le portail ne redémarre pas, alors que ses comptes et ses coffres sont sur le disque.

---

## Décision

Chaque composant fonctionne seul avec ce qu'il a déjà reçu. Une coupure n'enlève que ce qui dépend directement du composant absent.

1. **Admin** : point de modification et de supervision, jamais point de passage du service. Tout ce qu'il envoie, la passerelle en garde une copie locale chiffrée.
2. **Passerelle** : fait tourner tout ce qui lui est confié (trafic, certificats, Ephor, portail Access…) sans l'Admin, **y compris après un redémarrage pendant la coupure**. Rien de nécessaire au fonctionnement ne doit exister uniquement en base Admin ou en mémoire de la passerelle.
3. **Groupe HA** : les membres se connaissent et se synchronisent entre eux sans l'Admin (liste des pairs, clé de groupe, magasins répliqués), y compris après un redémarrage.
4. **Agent** : dépend uniquement de sa passerelle, jamais de l'Admin. Sa configuration, son jeton et son HMAC sont locaux. Ses fonctions locales (santé, redémarrage, scaling, mises à jour d'image) tournent sans passerelle ni Admin. S'il tombe, seules ses propres fonctions s'arrêtent : ses conteneurs continuent de recevoir le trafic.
5. **Reprise** : au retour d'un composant, la resynchronisation est complète et idempotente (full_sync Admin → passerelle, réannonce de tous les conteneurs Agent → passerelle), sans action manuelle.

**Test à appliquer à toute fonctionnalité :** « si X redémarre alors que Y est injoignable, qu'est-ce qui s'arrête ? ». La réponse doit être : uniquement ce que Y fait lui-même.

---

## Comportement attendu par coupure

| Coupure | Ce qui continue | Ce qui s'arrête (et seulement cela) |
|---|---|---|
| **Admin injoignable** | Trafic, certificats, Ephor et bans, portail Access, découverte des conteneurs (l'Agent parle à la passerelle), réplication HA | Modifications de configuration, supervision et historique dans l'UI, approbation de nouveaux Agents, commandes vers les Agents (rescan, configuration, shell depuis l'Admin) |
| **Passerelle d'un Agent injoignable** | Conteneurs de l'hôte, fonctions locales de l'Agent (santé, scaling, mises à jour) ; les autres membres du groupe HA servent le trafic | Publication des changements de conteneurs, métriques du LB adaptatif, événements, logs, shell. Au retour : réannonce complète par l'Agent |
| **Agent arrêté** | La passerelle continue de router vers les conteneurs connus (routes conservées dans sa table et son cache) ; l'Agent est affiché hors ligne après 90 s | Découverte (conteneur ajouté ou arrêté non vu), scaling, redémarrage et mises à jour automatiques, métriques du LB adaptatif, logs, accès portail et shell aux conteneurs de cet hôte |
| **Un membre d'un groupe HA tombe** | Les autres membres servent le trafic et le portail (magasin répliqué) | La capacité de ce membre uniquement |

---

## État au 2026-09-29

### Conforme

- Routes (y compris celles découvertes par les Agents), certificats, snippets et fournisseurs d'authentification : cache chiffré `edge-cache.gpx`, rechargé au démarrage sans Admin.
- Bans, profils IP, listes de menaces, configuration CrowdSec et fail2ban, pages d'erreur : sur le disque de la passerelle.
- Réglages runtime (`push_settings` : anonymisation / pseudonymisation des IP, journalisation, tracing, URL publique) : copie chiffrée `edge-settings.gpx`, rechargée au démarrage (Edge `0.17.10`).
- Portail : comptes, coffres, catalogue et audit dans `portal.gpx` (chiffré, répliqué dans le groupe HA).
- HMAC des Agents approuvés persisté des deux côtés : un Agent se reconnecte à une passerelle redémarrée sans l'Admin.
- Groupe HA : liste des pairs de synchronisation (`gateway-peers.gpx`) poussée par l'Admin, conservées localement et rechargées au démarrage : les membres se retrouvent sans l'Admin (Edge 0.24.3 et 0.24.4).
- Agent : `agent.json`, `agent.token` et HMAC locaux ; santé, scaling et mises à jour sans passerelle ni Admin.
- Agent hors ligne : seul son statut change, ses routes restent actives.
- Agent rattaché à un groupe HA : les HMAC des Agents approuvés sont répliqués entre les membres (chiffrés par la clé du groupe, révocations comprises) et chaque membre annonce à ses Agents les autres membres, qu'ils conservent localement. Si sa passerelle reste injoignable, l'Agent bascule vers un autre membre, s'y reconnecte avec son HMAC, obtient un jeton HTTP par le secret d'appairage commun et republie ses conteneurs, sans l'Admin (Edge 0.25.0 et 0.26.0, Agent 0.7.0). Limites : les découvertes Docker, Portainer, Kubernetes et le catalogue, les événements et le heartbeat suivent la bascule (les journaux gardent l'adresse configurée) ; ce que l'Agent publie à une passerelle n'est cependant jamais copié aux autres membres, ce que l'ADR-0014 corrige ; les adresses annoncées sont celles que les passerelles se connaissent entre elles et doivent être joignables depuis l'hôte de l'Agent.
- Agent, reprise : il réannonce tous ses conteneurs à chaque (re)connexion à sa passerelle et dès qu'un envoi a échoué ; un conteneur disparu pendant la coupure est signalé arrêté (Agent 0.6.2).

### Écarts (suivis dans `suivi/roadmap-public.md`)

- **Portail Access** : la configuration poussée (réglages, thème, entrées dédiées, politique, accès temporaires, clé de groupe HA) est conservée dans `portal-config.gpx` (chiffré) et rechargée au démarrage : le portail redémarre sans l'Admin (Edge 0.23.0).
- **Challenges ACME HTTP-01 / TLS-ALPN-01** : posés par l'Admin en RAM sur la passerelle (15 min), jamais persistés ; l'émission et le renouvellement exigent l'Admin et une passerelle connectée, comme DNS-01. Un certificat déjà poussé reste servi sans l'Admin.
- **Clés ECH** : poussées par l'Admin et conservées dans le cache chiffré de chaque passerelle (fonctionnent sans l'Admin, après redémarrage) ; répliquées aussi entre les membres d'un groupe HA sans l'Admin (jeu chiffré par la clé du groupe, le plus récent l'emporte, Edge 0.40.0).
- **Logs d'accès** : la passerelle écrit un fichier local mais pousse chaque ligne à l'Admin sans numéro de séquence ni rejeu ; quand l'Admin est injoignable, les lignes envoyées sont perdues pour l'historique central (Prism, SLO, recherche). Les logs de conteneurs de l'Agent, relayés sans stockage, se perdaient de même. Corrigé par l'[ADR 0012](0012-logs-proprietaire-edge.md) : base locale sur la passerelle, curseur et rejeu (Edge 0.75.0), position de lecture de l'Agent acquittée par sa passerelle (Agent 0.12.0, Edge 0.76.0) ; reste le calcul des cumuls à la source.
- **Autres envois de l'Admin** : audit terminé. Les délégations de routes suivent la table de routes (cache `edge-cache.gpx`) ; la topologie du cluster Raft (`cluster-peers.gpx`, Edge 0.24.3) était conservée localement jusqu'au retrait de Raft des passerelles (Edge 0.110.0, ADR 0014). Les flux d'automatisation exécutés par la passerelle (`auto-rules.gpx`, renvoyés à chaque modification depuis Admin 0.139.0, ADR 0009 ; l'Admin ne les évalue plus lui-même), les pairs du tunnel L4 (`tunnel-config.gpx`) (Edge 0.24.1), la configuration serveur (`server-config.gpx`) et les modèles de pages du portail (`portal-templates.gpx`) (Edge 0.24.2) sont conservés dans une copie locale chiffrée et rechargés au démarrage. `edge.json` n'est jamais réécrit par la passerelle.

---

## Conséquences

- Toute nouvelle donnée envoyée par l'Admin à la passerelle doit préciser où elle est persistée côté passerelle et comment elle est rechargée au démarrage.
- La base Admin reste la source de modification ; la copie de la passerelle est une copie de fonctionnement, remplacée à chaque envoi de l'Admin.
- Les secrets conservés par la passerelle (clé de groupe HA, clés privées) sont chiffrés par sa clé maître.
