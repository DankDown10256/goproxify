# Rapport de tests — Core GoProxify (2026-09-24)

Campagne de tests de charge, de sécurité et de résilience du Core, menée avec le labo `tests/lab/` (procédure : [tests-lab.md](tests-lab.md)). Ce document consigne les objectifs, la méthode, les résultats chiffrés, les constats et leur statut, ainsi que les limites de la mesure.

## 1. Synthèse

| Domaine | Verdict |
|---|---|
| Sécurité (19 contrôles) | **19 / 19 PASS** après correctifs du Core `0.7.0` |
| Résilience (5 scénarios de panne) | **Tous PASS** : dégradation propre et reprise automatique |
| Charge (smoke, saturation) | **0 % d'erreur** sur 62 000 requêtes ; débit atteint ≈ 914 req/s dans cette configuration (VM 2 vCPU partagée, k6 co-localisé ; capacité maximale du Core non mesurée) ; la latence de service à débit imposé reste à mesurer (voir §5) |
| Constats | 3 défauts trouvés (1 moyen, 2 faibles), **corrigés et vérifiés en production** ; 1 observation informative ouverte |

Non exécutés (raison au §7) : `spike`, `stress`, `baseline`, `soak`, `mixed`, scanners ZAP/Nuclei, tests TLS/HTTP3, cluster Raft.

## 2. Périmètre et environnement

| Élément | Valeur |
|---|---|
| Date du dernier passage | 2026-09-24, 19:52 UTC |
| Cible | Core GoProxify en production (image `core:latest` construite le jour même ; comportement conforme à la version `0.7.0`) |
| VM | 2 vCPU, 2 Go de RAM (≈ 1 Go disponibles), **partagée avec d'autres services** (Portainer, applications internes) |
| Version du Core | Non lue directement dans les logs (la commande de relevé a retourné une ligne sans rapport). Déduite du comportement : `TRACE` en 405, en-têtes limités (431) et corps intégral transmis, propres à `0.7.0` |
| Labo | `lab-backend` (Go 1.22), `lab-toxiproxy` 2.9.0, `lab-tools` (Alpine 3.20), `lab-k6` (grafana/k6) |
| Routes de test | `lab-fast`, `lab-waf-block`, `lab-waf-detect`, `lab-ratelimit`, `lab-chaos` (`*.lab.test`) |
| Code du labo | commit `75a0328` ; correctifs du Core : commit `d63dbe6` |

**Contrainte majeure :** le labo est branché sur la stack de production (`goproxify_net`). Les tests à fort impact ont donc été exclus, et k6 tourne sur la même VM que le Core (voir §6).

## 3. Sécurité — 19 / 19 PASS

Script : `tests/lab/scripts/attacks.sh` avec `LAB_SAFE=1` (section Admin exclue, voir §7).

| Groupe | Contrôle | Attendu | Obtenu |
|---|---|---|---|
| WAF (mode block) | SQLi `' OR 1=1` | 403 | 403 |
| | SQLi `UNION SELECT` | 403 | 403 |
| | XSS `<script>` | 403 | 403 |
| | Path traversal | rejet ou chemin nettoyé | 400 |
| | Traversal encodé (`..%2f`) | 403 | 403 |
| | Log4Shell (User-Agent) | 403 | 403 |
| | Injection de commande | 403 | 403 |
| | Trafic légitime | 200 | 200 |
| WAF (mode detect) | SQLi tolérée | 200 | 200 |
| IP / en-têtes | `X-Forwarded-For` complété par le Core | IP du pair en fin de chaîne | conforme |
| | En-tête hop-by-hop (`Connection:`) | retiré | retiré |
| Routage / Host | Host inconnu | 404 | 404 |
| | Host en double (requête brute) | 400 | 400 |
| | `TRACE` | 405 | 405 |
| | En-tête de 64 Ko | 431 | 431 |
| | Corps de 3 Mo avec `max_body_mb=1` | transmis intact | transmis intact |
| Smuggling | CL + TE | une seule réponse | 1 |
| Rate-limit | 120 requêtes en rafale (rps 10, burst 20) | des 429 | 89 / 120 en 429 |
| Slowloris | En-têtes incomplets | connexion coupée | coupée à 10 s |

Information : `X-Real-IP` fourni par le client (6.6.6.6) est repris par le Core. C'est attendu ici : le runner est sur un réseau privé, traité comme proxy de confiance par défaut (`GPX_TRUSTED_PROXIES`). Ce point ne peut pas être éprouvé depuis un réseau privé.

## 4. Résilience — Toxiproxy entre le Core et le backend

Script : `tests/lab/scripts/chaos.sh` (n'agit que sur la route `lab-chaos`).

| Scénario | Résultat mesuré | Verdict |
|---|---|---|
| Latence +1,5 s (jitter 200 ms) | 200 en 1,59 s ; rétablissement immédiat | PASS |
| Backend coupé | 502 en **3,1 ms** ; reprise automatique au retour du backend | PASS |
| Connexion réinitialisée (RST) | 502 ; rétablissement | PASS |
| Backend muet | 502 après **30,0 s** (délai amont) ; rétablissement | PASS |
| Bande passante 50 Ko/s sur 1 Mo | 200 en 21,1 s (conforme au débit imposé) ; rétablissement | PASS |

Le Core met le backend défaillant en quarantaine 15 s (observé dans ses logs) puis reprend seul, sans intervention.

## 5. Charge

Script : k6, via `lab-k6`, sur la route `lab-fast` (backend renvoyant `ok`). Deux modèles : **saturation** (utilisateurs sans pause, débit atteint) et **moderate** (débit imposé, latence de service).

| Scénario | Requêtes | Débit | Échecs | p50 | p95 | p99 | max |
|---|---|---|---|---|---|---|---|
| Smoke (2 VUs, 15 s) | 7 514 | 501/s | 0,00 % | 2,7 ms | 6,9 ms | 20,0 ms | 78,6 ms |
| Saturation (ancien `moderate` : 50 VUs sans pause, 1 min) | 54 870 | 914/s | 0,00 % | 32,9 ms | 122,4 ms | 179,7 ms | 439,9 ms |

Ressources du Core pendant la saturation (`docker stats`, CPU exprimé par rapport à un cœur) :

| Moment | CPU | Mémoire |
|---|---|---|
| Avant | 0,06 % | 45,6 MiB |
| Pendant (t = 30 s) | 64,4 % | 51,1 MiB |
| Après | 13,0 % | 49,3 MiB |

**Lecture de la saturation.** Ce scénario avait un seuil `p95 < 100 ms` franchi à chaque passage (122,4 ms ici ; 117,6 ms au précédent), sans aucune erreur HTTP. Ce n'est pas une défaillance du Core : 50 utilisateurs sans pause saturent le système en permanence (modèle fermé), et la latence reflète alors la file d'attente. Loi de Little : latence moyenne ≈ 50 / 914 ≈ 55 ms, cohérente avec les p50/p95 mesurés. Ce test mesure donc le **débit atteint par l'ensemble** (≈ 914 req/s, Core à 64 % d'un cœur, k6 et backend sur les mêmes 2 vCPU), pas une latence de service ni la capacité maximale du Core : le facteur limitant peut être k6 ou la VM. Il devient le scénario `saturation`, sans seuil de latence.

**Latence de service.** Le scénario `moderate` est désormais à débit imposé (300 req/s, modèle ouvert, sous le débit atteint en saturation ; seuils p95 < 100 ms, p99 < 300 ms, aucune itération abandonnée). **Non encore exécuté : à mesurer.** Le smoke (2 utilisateurs, 501 req/s) donne un ordre de grandeur : p95 6,9 ms.

## 6. Limites de la mesure

- **VM partagée et k6 co-localisé :** le générateur de charge et le Core se partagent 2 vCPU avec d'autres services. En saturation (p50 32,9 ms contre 2,7 ms au smoke), les latences mesurent la file d'attente de la VM chargée, pas le Core seul.
- **Aucune capacité maximale mesurée :** 914 requêtes par seconde à 64 % d'un cœur n'est pas une limite ; `stress` n'a pas été lancé. Toute extrapolation serait spéculative.
- **Mémoire :** +6 MiB pendant la charge, retour proche de la valeur initiale ; une minute ne permet pas de conclure sur une fuite (il faudrait `soak`, 30 min).
- **Un seul backend, réponses triviales :** pas de backend lent ni de gros corps en charge (`mixed` non exécuté).
- **Faux positifs corrigés dans le labo :** plusieurs contrôles initiaux étaient faux (redirection 301 de nettoyage de chemin, slowloris mesuré sur un `sleep`, Host en double non envoyé par curl, Toxiproxy sans état). Ils sont corrigés ; les résultats du §3 et §4 sont ceux des scripts corrigés.

## 7. Tests non exécutés, et pourquoi

| Test | Raison |
|---|---|
| Section « Admin API » d'`attacks.sh` | Elle génère 25 échecs de connexion réels sur l'Admin de production. Exécutée **une fois, involontairement**, avec l'ancien script (avant `LAB_SAFE`) : accès sans jeton → 401, JWT `alg=none` → 401, frein anti brute-force → 429 après 25 essais, traversal API → 301 (nettoyage de chemin). Non rejouée dans ce passage. |
| `spike`, `stress`, `baseline`, `soak`, `mixed` | Chargeraient le Core de production et la VM partagée. À réserver à un environnement isolé ou à une fenêtre de maintenance. |
| ZAP, Nuclei (`lab-juice`) | Mode local uniquement (non disponible via `docker exec` distant) ; cible vulnérable non déployée. |
| TLS, HTTP/2, HTTP/3, mTLS | Routes du labo en HTTP uniquement. |
| Cluster Raft, WebSocket en charge | Hors périmètre du labo actuel. |

## 8. Constats

| # | Constat | Gravité | Statut |
|---|---|---|---|
| 1 | **WAF : corps de requête tronqué au-delà de `max_body_mb`** (le WAF remplaçait le corps par ses seuls premiers octets : 502 ou données corrompues, y compris pour les uploads légitimes plus gros que la limite, 10 Mo par défaut). Cause : `readBody`. | Moyenne | Corrigé (Core `0.7.0`, test de non-régression) ; **vérifié en production** |
| 2 | **`TRACE` transmis au backend** (200) | Faible | Corrigé : 405 sur `TRACE`/`TRACK` ; **vérifié** |
| 3 | **Aucune limite de taille d'en-têtes** (64 Ko acceptés ; défaut Go 1 Mo) | Faible | Corrigé : `timeouts.max_header_kb`, défaut 32 Ko, 431 au-delà ; **vérifié**. Attention : des en-têtes légitimes de plus de 32 Ko doivent relever cette valeur |
| 4 | **Pages d'erreur exposant l'URL publique de l'Admin** et un lien vers les logs (via `GPX_ADMIN_PUBLIC_URL`), visibles de tout visiteur | Info | **Corrigé (Core `0.8.0`)** : `Render()` n'insère plus de lien `<a href>` vers l'Admin ; le `request_id` reste affiché. `buildLogURL` conservé pour les templates custom opérateur via `{{log_url}}`. |

## 9. Recommandations

1. **Environnement isolé** pour `stress`, `spike` et `soak` (Admin et Core de test, réseau séparé), afin de mesurer la capacité maximale et la stabilité mémoire sans risque.
2. **Exécuter `moderate` à débit imposé** (300 req/s) pour obtenir la latence de service, et rejouer `saturation` sur un environnement isolé pour comparer le débit hors concurrence avec les autres services.
3. ~~**Décider du constat n° 4**~~ Corrigé : l'URL Admin n'est plus exposée dans les pages d'erreur publiques (Core `0.8.0`).
4. **Vérifier `GPX_TRUSTED_PROXIES`** en production : derrière un load balancer à IP publique, la valeur par défaut (réseaux privés de confiance) doit être adaptée.
5. **Ajouter TLS/HTTP3 au labo** et éventuellement un test de cluster.
6. **Nettoyer** : supprimer les routes `lab-*` (`cleanup.sh`), révoquer le PAT du labo, supprimer le stack lab.

## 10. Reproduire

Procédure complète, prérequis et dépannage : [tests-lab.md](tests-lab.md). Les résultats ci-dessus proviennent d'un unique rapport (`rapport-lab.txt`) capturé avec les commandes décrites dans ce document.
