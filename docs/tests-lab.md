# Labo de tests — procédure pas à pas

Guide d'exécution du labo `tests/lab/` (charge, sécurité, chaos) sur un daemon Docker distant, avec les résultats du premier passage (2026-09-24). Référence rapide : [tests/lab/README.md](../tests/lab/README.md).

> **Le labo se branche sur la stack existante (`goproxify_net`).** Sur une stack de production, il crée des routes `*.lab.test` dans l'Admin et le Core réels : n'exécuter que les tests « faible impact » (§4) et nettoyer ensuite (§7).

## 1. Principe

| Élément | Rôle |
|---|---|
| `lab-backend` | Backend Go contrôlable (`/`, `/echo`, `/slow`, `/flaky`, `/bytes`, `/upload`, `/sse`), source embarquée dans le compose |
| `lab-toxiproxy` | Injection de pannes réseau entre le Core et le backend (route `lab-chaos`) |
| `lab-tools` | Runner bash : `seed.sh`, `attacks.sh`, `chaos.sh`, `cleanup.sh` |
| `lab-k6` | Runner de charge (scénarios `smoke`, `moderate`, `baseline`, `spike`, `stress`, `soak`, `mixed`) |
| `lab-juice` | Cible vulnérable optionnelle (profil `vuln`) |

Aucun build ni montage de fichier : les scripts sont embarqués dans `docker-compose.lab.yml` par `tests/lab/gen-compose.sh` (à relancer après toute modification de `scripts/` ou `load/`). Les runners retrouvent eux-mêmes l'IP du Core (`scripts/hosts.sh`).

## 2. Déploiement

1. La stack principale (Admin + Core) doit tourner.
2. Déployer `tests/lab/docker-compose.lab.yml` comme stack séparée (dépôt git). Vérifier :

```bash
sudo docker ps --filter name=lab- --format '{{.Names}} {{.Status}}'
```

Attendu : `lab-backend`, `lab-toxiproxy`, `lab-tools`, `lab-k6` en `Up` (`lab-tools` installe ses paquets au démarrage : quelques secondes).

3. Après **chaque** modification des scripts : pousser, puis redéployer en récupérant à nouveau le dépôt (les scripts sont dans les conteneurs).

## 3. Authentification (seed)

Le seed appelle l'API Admin. Préférer un **jeton d'API (PAT)** à un mot de passe : Admin → Paramètres → Mes tokens API → « + Nouveau token », scopes `proxies:read`, `proxies:write`, `proxies:delete`, expiration courte. À défaut : `LAB_ADMIN_EMAIL` / `LAB_ADMIN_PASSWORD` (les identifiants du compose ne sont que des valeurs par défaut, pas des identifiants valides).

```bash
sudo docker exec -e LAB_ADMIN_TOKEN='gpx_pat_...' lab-tools bash /lab/scripts/seed.sh
```

Attendu : une ligne par route (`lab-fast`, `lab-waf-block`, `lab-waf-detect`, `lab-ratelimit`, `lab-chaos`, `lab-juice`) avec `(201)`, puis `toxiproxy: backend :8666 -> lab-backend:9000`. Relancé, le seed affiche « déjà présent : ignoré ».

## 4. Tests, dans l'ordre

Chaque commande affiche PASS/FAIL ; le code retour de `attacks.sh` et `chaos.sh` est le nombre d'échecs.

| # | Test | Commande | Impact production |
|---|---|---|---|
| 1 | Smoke (2 VUs, 15 s) | `docker exec lab-k6 sh -c "sh /hosts.sh && k6 run /scripts/smoke.js"` | Nul |
| 2 | Attaques sans la section Admin | `docker exec -e LAB_SAFE=1 lab-tools bash /lab/scripts/attacks.sh` | Faible (routes `lab-*`) |
| 3 | Chaos réseau | `docker exec lab-tools bash /lab/scripts/chaos.sh` | Faible (route `lab-chaos` seule) |
| 4 | Charge modérée (50 VUs, 1 min) | `docker exec lab-k6 sh -c "sh /hosts.sh && k6 run /scripts/moderate.js"` | Modéré (partage le CPU du Core) |
| — | Attaques complètes (brute-force login Admin) | sans `LAB_SAFE=1` | **Élevé** : échecs de connexion réels sur l'Admin, alertes/audit |
| — | `spike`, `stress`, `baseline`, `soak`, `mixed` | `k6 run /scripts/<nom>.js` | **Élevé** : à réserver à un environnement isolé ou à une fenêtre de maintenance |

Toutes les commandes `docker` s'écrivent avec `sudo` sur la VM.

## 5. Ce que vérifie chaque test

- **Attaques** : WAF en block/detect (SQLi, XSS, traversal, Log4Shell, injection de commande), `X-Forwarded-For` complété par le Core, en-têtes hop-by-hop, Host inconnu/dupliqué, `TRACE`, en-tête de 64 Ko, corps > `max_body_mb` transmis intact, request smuggling CL+TE, rate-limit, slowloris (coupure attendue à 10 s), et hors `LAB_SAFE` : API Admin sans jeton, JWT `alg=none`, traversal API, frein anti brute-force.
- **Chaos** : latence +1,5 s propagée, backend coupé → 502 immédiat puis reprise, connexion réinitialisée, backend muet (coupure à 30 s), bande passante 50 Ko/s. Toxiproxy est sans état : `chaos.sh` recrée son proxy à chaque lancement et s'arrête si la route de référence n'est pas saine.
- **Charge** : taux d'erreur et latences p50/p95/p99.

## 6. Résultats (2026-09-24, VM partagée avec la production)

| Test | Résultat |
|---|---|
| Smoke | 7 486 req (499/s), 0 % d'échec, p95 6,6 ms, p99 28,6 ms |
| Chaos | Tous PASS : latence 1,45 s, 502 en 3 ms si backend coupé, reprise auto, timeout amont à 30 s |
| Charge modérée | 56 809 req (947/s), 0 % d'échec, p95 117,6 ms, p99 180,9 ms (seuil p95 < 100 ms franchi ; k6 et le Core se partagent le CPU de la VM) |
| Attaques | 19 PASS (WAF, traversal, XFF, Host dupliqué en 400, smuggling : une seule réponse, rate-limit 88/120 en 429, slowloris coupé à 10 s) ; 3 échecs : `TRACE`, en-tête de 64 Ko, corps de 3 Mo (constats ci-dessous) |
| Attaques (après Core `0.7.0`) | **Tous les contrôles passent** : `TRACE` en 405, en-tête de 64 Ko en 431, corps de 3 Mo transmis intact, plus les 19 contrôles précédents |

### Constats

| Constat | Gravité | Statut |
|---|---|---|
| WAF : corps > `max_body_mb` tronqué (502 ou données corrompues) | Moyenne | Corrigé dans le Core `0.7.0` ; **vérifié en production** |
| `TRACE` transmis au backend (200) | Faible | Corrigé dans le Core `0.7.0` (405) ; **vérifié en production** |
| Aucune limite de taille d'en-tête (64 Ko accepté ; défaut Go 1 Mo) | Faible | Corrigé dans le Core `0.7.0` (`timeouts.max_header_kb`, défaut 32 Ko, 431) ; **vérifié en production** |
| Pages d'erreur exposant l'URL publique de l'Admin et un lien vers les logs (`GPX_ADMIN_PUBLIC_URL`) | Info | Comportement documenté ; vider la variable pour ne pas l'exposer |

Non-constats (faux positifs corrigés dans les scripts) : redirection 301 de nettoyage de chemin, `X-Real-IP` repris depuis un pair de réseau privé (proxy de confiance par défaut), slowloris mesuré sur un `sleep` au lieu de la connexion.

## 7. Nettoyage

```bash
sudo docker exec -e LAB_ADMIN_TOKEN='gpx_pat_...' lab-tools bash /lab/scripts/cleanup.sh
```

Puis : vérifier dans l'UI qu'il ne reste aucune route `lab-*` (y compris des révisions `pending` issues de seeds refusés), révoquer le PAT, supprimer le stack lab, effacer l'historique du shell (`history -c`) si un mot de passe a été saisi.

## 8. Dépannage

| Symptôme | Cause | Remède |
|---|---|---|
| `401` au seed | Identifiants invalides pour cet Admin | Utiliser un PAT ; sans variables `GPX_FIRST_ADMIN_*`, le compte a été créé via l'UI |
| `moduleSpecifier … couldn't be found` (k6) | Stack lab déployé avant l'ajout du scénario | Pousser puis redéployer |
| `LAB_SAFE` ignoré | Script déployé antérieur à son ajout | Redéployer avant de lancer |
| Seed : `422` `conflit host …` | Routes déjà créées (ancienne version du seed) | Utiliser le seed actuel (idempotent) ; `cleanup.sh` pour repartir de zéro |
| Attaques : 502 partout juste après un redéploiement | `lab-backend` recréé, en cours de compilation : le Core reçoit `connection refused` et met le backend en quarantaine 15 s | Transitoire ; `attacks.sh` attend désormais jusqu'à 60 s que `lab-fast` réponde 200, sinon s'arrête |
| Chaos : 502 partout en 3 ms | Proxy Toxiproxy perdu au redémarrage | Version actuelle de `chaos.sh` (recréation automatique) |
| Erreur de build « listing workers » | Endpoint Docker sans BuildKit | Aucun build dans ce compose : redéployer la version actuelle |
| `bind source path does not exist` | Montage de fichier sur daemon distant | Sources embarquées : redéployer la version actuelle |
| `\r: command not found` | Fins de ligne CRLF ajoutées par git sous Windows | Forcer LF pour `tests/lab` (`.gitattributes`) |
