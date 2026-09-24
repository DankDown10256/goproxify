#!/usr/bin/env bash
# Pilote du labo de tests GoProxify. Usage : tests/lab/lab.sh [--isolated] <commande> [args]
#
# Mode normal (défaut) : se branche sur la stack de production (goproxify_net).
#   Tests faible impact uniquement : smoke, moderate, attacks (LAB_SAFE=1), chaos.
#
# Mode isolé (--isolated) : Admin + Core de test dans leur propre réseau (lab_isolated_net).
#   Aucun lien avec la production. Utiliser pour : stress, spike, soak, baseline, mixed.
#   Pré-requis : images Admin et Core disponibles (ghcr.io ou build local).
#
# Mode distant (LAB_REMOTE=1) : stack lab déjà déployée sur un daemon distant.
#   Variables : LAB_ADMIN_EMAIL, LAB_ADMIN_PASSWORD (pour seed).
set -eu
cd "$(dirname "$0")"
ROOT=$(cd ../.. && pwd)
mkdir -p results

# --- détection du flag --isolated -------------------------------------------
ISOLATED=0
if [ "${1:-}" = "--isolated" ]; then
  ISOLATED=1
  shift
fi
REMOTE=${LAB_REMOTE:-0}

if [ "$ISOLATED" = 1 ]; then
  # Mode isolé : Admin + Core de test dans docker-compose.isolated.yml
  dc() { docker compose -p goproxify-lab-isolated -f docker-compose.isolated.yml "$@"; }
  run() { dc --profile run run --rm "$@"; }
  tools() {
    run -e LAB_ADMIN_URL=http://172.30.0.2:9444 \
        -e LAB_ADMIN_EMAIL="${LAB_ADMIN_EMAIL:-lab@lab.test}" \
        -e LAB_ADMIN_PASSWORD="${LAB_ADMIN_PASSWORD:-Lab1234!}" \
        -e LAB_ADMIN_TOKEN="${LAB_ADMIN_TOKEN:-}" \
        -e LAB_SAFE="${LAB_SAFE:-0}" \
        tools bash "/lab/scripts/$1"
  }
  k6run() {
    rc=0; run k6 run "/scripts/$1.js" || rc=$?
    docker cp goproxify-lab-isolated-k6-1:/results/. results/ 2>/dev/null || true
    return $rc
  }
  core_container=lab-isolated-core

elif [ "$REMOTE" != 1 ]; then
  # Mode normal local : branchement sur la production
  core_ip() {
    docker inspect -f '{{(index .NetworkSettings.Networks "goproxify_net").IPAddress}}' goproxify-core 2>/dev/null \
      || { echo "Stack principale absente : docker compose up -d à la racine." >&2; exit 1; }
  }
  export CORE_IP; CORE_IP=$(core_ip)
  [ -f "$ROOT/.env" ] && set -a && . "$ROOT/.env" && set +a
  dc() { docker compose -p goproxify-lab --env-file "$ROOT/.env" -f docker-compose.lab.yml "$@"; }
  run() { dc --profile run run --rm "$@"; }
  tools() { run tools bash "/lab/scripts/$1"; }
  k6run() { run k6 run "/scripts/$1.js"; }
  core_container=goproxify-core

else
  # Mode distant
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
  core_container=goproxify-core
fi

cmd=${1:-help}; shift || true
case "$cmd" in
  up)
    if [ "$ISOLATED" = 1 ]; then
      dc up -d lab-admin lab-core lab-backend lab-toxiproxy
      echo "En attente du Core isolé (jusqu'à 60 s)..."
      for i in $(seq 1 12); do
        docker exec lab-isolated-core wget -qO- http://localhost:80/internal/v1/health >/dev/null 2>&1 && break
        sleep 5
      done
    else
      dc up -d lab-backend lab-toxiproxy
    fi ;;

  up-all)   # mode isolé uniquement : démarre tout
    [ "$ISOLATED" = 1 ] || { echo "up-all est réservé au mode --isolated." >&2; exit 1; }
    "$0" --isolated up
    "$0" --isolated seed ;;

  up-vuln)  dc --profile vuln up -d lab-juice ;;

  down)
    if [ "$ISOLATED" = 1 ]; then
      dc --profile run --profile vuln down -v --remove-orphans
    else
      dc --profile vuln --profile run down -v --remove-orphans
    fi ;;

  seed)   tools seed.sh ;;
  attacks) tools attacks.sh ;;
  chaos)   tools chaos.sh ;;
  tls)    tools tls.sh ;;

  load)   # smoke | moderate | saturation | baseline | spike | stress | soak | mixed | tls-smoke
    s=${1:-smoke}
    if [ "$ISOLATED" != 1 ] && echo "spike stress soak baseline mixed" | grep -qw "$s"; then
      echo "⚠ '$s' est un test à fort impact. Utiliser --isolated pour ne pas affecter la production." >&2
      echo "   Exemple : tests/lab/lab.sh --isolated load $s" >&2
      exit 1
    fi
    [ -f "load/$s.js" ] || { echo "scénario inconnu : $s"; exit 1; }
    k6run "$s" ;;

  soak)
    ( while sleep 10; do docker stats --no-stream --format '{{.Name}},{{.CPUPerc}},{{.MemUsage}},{{.PIDs}}' "$core_container" \
        | sed "s/^/$(date +%T),/" >> results/soak-core-stats.csv; done ) & mon=$!
    trap 'kill $mon 2>/dev/null' EXIT
    k6run soak ;;

  zap)     run zap zap-baseline.py -t http://lab-juice.lab.test -r zap-report.html -J zap-report.json -I ;;
  nuclei)  run nuclei -u http://lab-fast.lab.test -u http://lab-juice.lab.test \
             -severity medium,high,critical -o /results/nuclei.txt ;;

  all)
    if [ "$ISOLATED" = 1 ]; then
      "$0" --isolated up
      "$0" --isolated seed
      "$0" --isolated load smoke
      "$0" --isolated load moderate
      "$0" --isolated attacks
      "$0" --isolated chaos
      "$0" --isolated tls
    else
      [ "$REMOTE" = 1 ] || "$0" up
      "$0" seed
      "$0" load smoke
      "$0" attacks
      "$0" chaos
      "$0" tls
    fi ;;

  *) cat <<'X'
Commandes :
  up | up-vuln | down               cycle de vie
  up-all                            (--isolated) démarre tout et seed
  seed                              crée les routes du labo via l'API Admin
  load <smoke|moderate|saturation|baseline|spike|stress|soak|mixed>   tests de charge (k6)
  attacks | chaos | tls             batterie d'attaques / pannes backend / contrôles TLS
  soak | zap | nuclei               endurance + ressources, scanners

Flags :
  --isolated    Admin + Core de test dans un réseau séparé de la production.
                Obligatoire pour : stress, spike, soak, baseline, mixed.

Exemples :
  # Labo sur la production (faible impact)
  tests/lab/lab.sh up && tests/lab/lab.sh seed && tests/lab/lab.sh load smoke

  # Labo isolé (tests à fort impact)
  tests/lab/lab.sh --isolated up-all
  tests/lab/lab.sh --isolated load stress
  tests/lab/lab.sh --isolated load moderate   # latence de service (300 req/s)
  tests/lab/lab.sh --isolated soak            # endurance 30 min

Mode distant : LAB_REMOTE=1 LAB_ADMIN_EMAIL=... LAB_ADMIN_PASSWORD=... tests/lab/lab.sh all
Résultats : tests/lab/results/
X
  ;;
esac
