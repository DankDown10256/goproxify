# Labo de tests GoProxify

Environnement isolé, branché sur la stack Docker existante (`goproxify_net`), pour éprouver le Core
**sans toucher aux routes réelles** : toutes les routes du labo sont en `*.lab.test`.

> Procédure complète, résultats et dépannage : [docs/tests-lab.md](../../docs/tests-lab.md).
>
> Usage strictement local. Ne jamais pointer ces scripts vers un système dont vous n'êtes pas propriétaire.

## Démarrage

> Déploiement direct du compose (Portainer…) : seuls `lab-backend` et `lab-toxiproxy` démarrent (`CORE_IP` vaut `127.0.0.1` par défaut, sans effet sur eux). Les runners (`k6`, `tools`, `zap`, `nuclei`) exigent `CORE_IP` = IP du Core sur `goproxify_net` : passez par `lab.sh`.

```bash
docker compose up -d          # stack principale (.env rempli, dont GPX_FIRST_ADMIN_*)
tests/lab/lab.sh up           # backend contrôlable + Toxiproxy
tests/lab/lab.sh seed         # crée les routes via l'API Admin
tests/lab/lab.sh all          # smoke + attaques + chaos
tests/lab/lab.sh down         # nettoyage (routes lab-* à supprimer depuis l'Admin)
```

Rapports dans `tests/lab/results/` (ignoré par git).

## Daemon distant (Portainer…) : docker exec, sans clone ni copie

Le stack déployé contient `lab-tools` et `lab-k6` (conteneurs permanents) avec **tous les scripts embarqués** dans le compose
(régénéré par `tests/lab/gen-compose.sh` après toute modif de `scripts/` ou `load/`). Depuis n'importe quelle machine dont `docker`
atteint le bon daemon (sur la VM : ajouter `sudo`) :

```bash
docker exec -e LAB_ADMIN_TOKEN=gpx_pat_... lab-tools bash /lab/scripts/seed.sh   # ou -e LAB_ADMIN_EMAIL=... -e LAB_ADMIN_PASSWORD=...
docker exec lab-tools bash /lab/scripts/attacks.sh
docker exec lab-tools bash /lab/scripts/chaos.sh
docker exec lab-k6 sh -c "sh /hosts.sh && k6 run /scripts/smoke.js"   # baseline | spike | stress | soak | mixed
```

Les scripts trouvent eux-mêmes l'IP du Core (`scripts/hosts.sh`) : `CORE_IP` n'est pas nécessaire. ZAP, Nuclei et `soak` restent en mode local.

## Sur une stack partagée avec la production

Le labo se branche sur la vraie stack : préférez ces commandes à faible impact.

```bash
# attaques sans la section Admin (brute-force login compris) : ne touchent que les routes lab-*
docker exec -e LAB_SAFE=1 lab-tools bash /lab/scripts/attacks.sh
# chaos : agit uniquement sur la route lab-chaos (Toxiproxy)
docker exec lab-tools bash /lab/scripts/chaos.sh
# charge plafonnée : 50 VUs, ~1 min
docker exec lab-k6 sh -c "sh /hosts.sh && k6 run /scripts/moderate.js"
```

Nettoyage des routes du labo (après les tests) :

```bash
docker exec -e LAB_ADMIN_TOKEN=... lab-tools bash /lab/scripts/cleanup.sh
```

À éviter sans fenêtre de maintenance : `spike`, `stress`, `baseline`, `soak`, `mixed`.

## Ce que couvre le labo

| Domaine | Commande | Outil | Vérifie |
|---|---|---|---|
| Charge | `lab.sh load smoke\|baseline\|mixed` | k6 | latence p95/p99, taux d'erreur, trafic mixte (gros corps, upload, SSE, backend lent/instable) |
| Pic | `lab.sh load spike` | k6 | 20 → 1000 VUs en 10 s, absence d'effondrement, reprise |
| Rupture | `lab.sh load stress` | k6 | débit maximal avant >10 % d'erreurs (arrêt automatique) |
| Endurance | `lab.sh soak` | k6 + docker stats | fuites mémoire/PIDs du Core (`results/soak-core-stats.csv`) ; `DURATION=2h RATE=500` |
| Attaques ciblées | `lab.sh attacks` | bash/curl/nc | WAF block/detect, XFF/X-Real-IP usurpés, hop-by-hop, Host inconnu/dupliqué, TRACE, en-têtes 64 Ko, corps trop gros, smuggling CL+TE, rate-limit, slowloris, API Admin (sans jeton, JWT `alg=none`, brute-force login) |
| Chaos | `lab.sh chaos` | Toxiproxy | latence, backend coupé, RST, timeout amont, bande passante : erreur rapide + reprise automatique |
| Scanners | `lab.sh up-vuln && lab.sh zap` / `nuclei` | ZAP, Nuclei, Juice Shop | détection de vulnérabilités via le WAF (mode detect) |

Chaque contrôle d'`attacks` et `chaos` affiche PASS/FAIL ; le code retour est le nombre d'échecs (utilisable en CI).

## Backend de test

`/` · `/echo` (ce que le backend a réellement reçu) · `/slow?ms=` · `/flaky?p=` · `/bytes?n=` ·
`/status/{code}` · `/upload` · `/sse?n=&ms=`

## Prérequis

Docker (Compose v2), Bash (Git Bash sur Windows). Les images k6, ZAP, Nuclei, Toxiproxy et Juice Shop sont tirées au premier lancement.

## Limites connues

- Pas de TLS dans le labo (routes HTTP) : la charge TLS/QUIC et testssl restent à ajouter.
- Le test slowloris dure ~75 s ; les tests de charge lourds doivent tourner sur une machine dédiée (les résultats sur poste de dev ne sont pas comparables à `docs/benchmark.md`).
- Les scénarios ont été écrits et validés statiquement (syntaxe, `docker compose config`, build Go) ; un premier passage réel peut nécessiter d'ajuster les seuils.
