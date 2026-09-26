#!/usr/bin/env bash
# Pilote du labo de tests GoProxify. Usage : tests/lab/lab.sh <commande> [args]
#
# Mode local  : Docker sur cette machine (compose run, EDGE_IP auto).
# Mode distant (LAB_REMOTE=1) : le stack lab est déjà déployé (lab-tools, lab-k6) sur un daemon distant ;
#   les scripts sont déjà embarqués dans les conteneurs (gen-compose.sh) : simple docker exec via le DOCKER_HOST / contexte courant.
#   Variables : LAB_ADMIN_EMAIL, LAB_ADMIN_PASSWORD (pour seed).
set -eu
cd "$(dirname "$0")"
ROOT=$(cd ../.. && pwd)
mkdir -p results
REMOTE=${LAB_REMOTE:-0}

if [ "$REMOTE" != 1 ]; then
  edge_ip() {
    docker inspect -f '{{(index .NetworkSettings.Networks "goproxify_net").IPAddress}}' goproxify-edge 2>/dev/null \
      || { echo "Stack principale absente : docker compose up -d à la racine." >&2; exit 1; }
  }
  export EDGE_IP; EDGE_IP=$(edge_ip)
  [ -f "$ROOT/.env" ] && set -a && . "$ROOT/.env" && set +a
  dc() { docker compose -p goproxify-lab --env-file "$ROOT/.env" -f docker-compose.lab.yml "$@"; }
  run() { dc --profile run run --rm "$@"; }
  tools() { run tools bash "/lab/scripts/$1"; }
  k6run() { run k6 run "/scripts/$1.js"; }
else
  ready() { docker exec "$1" true 2>/dev/null || { echo "conteneur $1 absent : déployer d'abord le stack lab." >&2; exit 1; }; }
  tools() {
    ready lab-tools
    docker exec -e LAB_SAFE="${LAB_SAFE:-0}" -e LAB_ADMIN_TOKEN="${LAB_ADMIN_TOKEN:-}" -e LAB_ADMIN_EMAIL="${LAB_ADMIN_EMAIL:-}" -e LAB_ADMIN_PASSWORD="${LAB_ADMIN_PASSWORD:-}" \
      lab-tools bash "/lab/scripts/$1"
  }
  k6run() {
    ready lab-k6
    rc=0; docker exec lab-k6 sh -c "sh /hosts.sh && k6 run /scripts/$1.js" || rc=$?
    docker cp lab-k6:/results/. results/ 2>/dev/null || true
    return $rc
  }
fi

cmd=${1:-help}; shift || true
case "$cmd" in
  up)     dc up -d lab-backend lab-toxiproxy ;;
  up-vuln) dc --profile vuln up -d lab-juice ;;
  down)   dc --profile vuln --profile run down -v --remove-orphans ;;
  seed)   tools seed.sh ;;
  attacks) tools attacks.sh ;;
  chaos)   tools chaos.sh ;;

  load)   # smoke | moderate | saturation | baseline | spike | stress | soak | mixed
    s=${1:-smoke}; [ -f "load/$s.js" ] || { echo "scénario inconnu : $s"; exit 1; }
    k6run "$s" ;;

  soak)   # local uniquement : soak + relevé mémoire/CPU de la passerelle toutes les 10 s
    ( while sleep 10; do docker stats --no-stream --format '{{.Name}},{{.CPUPerc}},{{.MemUsage}},{{.PIDs}}' goproxify-edge \
        | sed "s/^/$(date +%T),/" >> results/soak-edge-stats.csv; done ) & mon=$!
    trap 'kill $mon 2>/dev/null' EXIT
    k6run soak ;;

  zap)     # local uniquement (nécessite up-vuln)
    run zap zap-baseline.py -t http://lab-juice.lab.test -r zap-report.html -J zap-report.json -I ;;
  nuclei)  # local uniquement
    run nuclei -u http://lab-fast.lab.test -u http://lab-juice.lab.test \
      -severity medium,high,critical -o /results/nuclei.txt ;;

  all)    [ "$REMOTE" = 1 ] || "$0" up; "$0" seed; "$0" load smoke; "$0" attacks; "$0" chaos ;;
  *) cat <<'X'
Commandes :
  up | up-vuln | down               cycle de vie (local)
  seed                              crée les routes du labo via l'API Admin
  load <smoke|moderate|saturation|baseline|spike|stress|soak|mixed>   tests de charge (k6)
  attacks | chaos                   batterie d'attaques / pannes backend
  soak | zap | nuclei               endurance + ressources, scanners (local uniquement)
  all                               seed + smoke + attacks + chaos
Mode distant : LAB_REMOTE=1 LAB_ADMIN_EMAIL=... LAB_ADMIN_PASSWORD=... tests/lab/lab.sh all
Résultats : tests/lab/results/
X
  ;;
esac
