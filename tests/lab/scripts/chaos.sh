#!/usr/bin/env bash
# Chaos réseau côté backend via Toxiproxy : la passerelle doit dégrader proprement (5xx rapide, pas de blocage)
# et se rétablir seul. Code retour = nombre d'échecs.
set -u
. /lab/scripts/hosts.sh
T=http://lab-toxiproxy:8474
URL=http://lab-chaos.lab.test
fail=0
ok() { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
ko() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
req() { curl -s -o /dev/null -w '%{http_code} %{time_total}' --max-time "${1:-20}" "$URL${2:-/}"; }
reset() { curl -s -X POST "$T/reset" >/dev/null; }
toxic() { curl -s -X POST "$T/proxies/backend/toxics" -H 'Content-Type: application/json' -d "$1" >/dev/null; }
recovers() { for _ in $(seq 1 15); do [ "$(req 5 | cut -d' ' -f1)" = 200 ] && return 0; sleep 1; done; return 1; }

# Toxiproxy est sans état : le proxy disparaît à chaque redémarrage du conteneur. Création idempotente (409 si déjà là).
curl -s -X POST "$T/proxies" -H 'Content-Type: application/json' \
  -d '{"name":"backend","listen":"0.0.0.0:8666","upstream":"lab-backend:9000","enabled":true}' >/dev/null
reset
if [ "$(req | cut -d' ' -f1)" = 200 ]; then ok "référence saine"; else
  echo "  FAIL route chaos injoignable : vérifier lab-toxiproxy, lab-backend et la route lab-chaos.lab.test (seed) — arrêt"; exit 1
fi

echo "== Latence +1500 ms =="
toxic '{"type":"latency","attributes":{"latency":1500,"jitter":200}}'
read -r c t <<<"$(req)"; awk -v t="$t" 'BEGIN{exit !(t>=1.4)}' && ok "latence propagée ($c en ${t}s)" || ko "latence non observée ($c ${t}s)"
reset; recovers && ok "rétablissement après latence" || ko "pas de rétablissement"

echo "== Backend coupé (proxy désactivé) =="
curl -s -X POST "$T/proxies/backend" -H 'Content-Type: application/json' -d '{"enabled":false}' >/dev/null
read -r c t <<<"$(req 20)"
case "$c" in 502|503|504) awk -v t="$t" 'BEGIN{exit !(t<10)}' && ok "erreur $c rapide (${t}s)" || ko "erreur $c mais lente (${t}s)";; *) ko "code inattendu $c";; esac
curl -s -X POST "$T/proxies/backend" -H 'Content-Type: application/json' -d '{"enabled":true}' >/dev/null
recovers && ok "reprise automatique après retour du backend" || ko "Passerelle n'a pas repris le backend (circuit non refermé ?)"

echo "== Connexion réinitialisée (RST) =="
toxic '{"type":"reset_peer","attributes":{"timeout":0}}'
c=$(req 10 | cut -d' ' -f1); case "$c" in 502|503|504) ok "RST -> $c";; *) ko "RST -> $c";; esac
reset; recovers && ok "rétablissement après RST" || ko "pas de rétablissement"

echo "== Backend muet (timeout) =="
toxic '{"type":"timeout","attributes":{"timeout":0}}'
read -r c t <<<"$(req 90)"
case "$c" in 502|503|504) ok "timeout amont -> $c après ${t}s";; *) ko "timeout amont -> $c (${t}s) : la passerelle bloque le client ?";; esac
reset; recovers && ok "rétablissement après timeout" || ko "pas de rétablissement"

echo "== Bande passante 50 Ko/s sur 1 Mo (client lent / backend lent) =="
toxic '{"type":"bandwidth","attributes":{"rate":50}}'
read -r c t <<<"$(req 60 '/bytes?n=1048576')"; echo "  info: $c en ${t}s"
reset; recovers && ok "rétablissement après bridage" || ko "pas de rétablissement"

reset
echo; [ $fail -eq 0 ] && echo "Chaos : OK." || echo "$fail contrôle(s) en échec."
exit $fail
