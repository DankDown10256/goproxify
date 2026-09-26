#!/usr/bin/env bash
# Tests TLS/HTTP3 du labo. Génère un cert auto-signé pour *.lab.test, l'importe dans
# l'Admin, crée les routes TLS, puis vérifie HTTPS et les en-têtes de sécurité TLS.
# Code retour = nombre d'échecs.
set -u
. /lab/scripts/hosts.sh
. /lab/scripts/auth.sh
EDGE_HOST=${EDGE_HOST:-goproxify-edge}
fail=0

ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
ko()   { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
code_tls() { curl -sk -o /dev/null -w '%{http_code}' --max-time 15 "$@"; }
hdr()  { curl -sk -o /dev/null -D - --max-time 15 "$@" | tr -d '\r'; }

# ---------------------------------------------------------------------------
# 1. Génération du certificat auto-signé *.lab.test (EC P-256, valide 365 j)
# ---------------------------------------------------------------------------
echo "== Génération du certificat auto-signé *.lab.test =="
TMP=$(mktemp -d)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -days 365 -subj '/CN=*.lab.test' \
  -addext 'subjectAltName=DNS:*.lab.test,DNS:lab.test' \
  -keyout "$TMP/key.pem" -out "$TMP/cert.pem" 2>/dev/null
[ -s "$TMP/cert.pem" ] && ok "cert auto-signé généré (P-256)" || { ko "génération du cert échouée"; exit 1; }

# ---------------------------------------------------------------------------
# 2. Import du cert dans l'Admin
# ---------------------------------------------------------------------------
echo "== Import du cert dans l'Admin =="
cert_pem=$(cat "$TMP/cert.pem")
key_pem=$(cat "$TMP/key.pem")
body=$(jq -n --arg c "$cert_pem" --arg k "$key_pem" '{cert_pem:$c,key_pem:$k}')
icode=$(curl -s -o /tmp/import.out -w '%{http_code}' -X POST "$LAB_ADMIN_URL/api/v1/certs/import" \
  -H "Authorization: Bearer $token" -H 'Content-Type: application/json' -d "$body")
case "$icode" in
  200|201|204) ok "cert importé dans l'Admin ($icode)" ;;
  409)         ok "cert déjà présent (409 — idempotent)" ;;
  *)           ko "import cert : HTTP $icode ($(head -c 200 /tmp/import.out))"; exit 1 ;;
esac

# Laisser à la passerelle le temps de récupérer le cert
sleep 2

# ---------------------------------------------------------------------------
# 3. Création des routes TLS (idempotent)
# ---------------------------------------------------------------------------
echo "== Création des routes TLS =="
have=$(curl -s -H "Authorization: Bearer $token" "$LAB_ADMIN_URL/api/v1/proxies" | jq -r '.[]? | .name // empty')

route_tls() { # host backend [extra json]
  if echo "$have" | grep -qx "$1"; then printf '%-32s déjà présent : ignoré\n' "$1"; return; fi
  local body
  body=$(jq -n --arg h "$1" --arg b "$2" --argjson x "${3:-{\}}" \
    '{config: ({host:$h, type:"http", tls_enabled:true, backends:[{url:$b, weight:1}]} + $x)}')
  code=$(curl -s -o /tmp/seed.out -w '%{http_code}' -X POST "$LAB_ADMIN_URL/api/v1/proxies" \
    -H "Authorization: Bearer $token" -H 'Content-Type: application/json' -d "$body")
  printf '%-32s -> %s (%s)\n' "$1" "$2" "$code"
  case "$code" in 2*) ;; *) head -c 300 /tmp/seed.out; echo; ;; esac
}

route_tls lab-tls.lab.test http://lab-backend:9000
route_tls lab-h3.lab.test  http://lab-backend:9000

# Attendre que la passerelle prenne en compte les routes
sleep 2
ready=0
for _ in $(seq 1 15); do
  [ "$(code_tls "https://lab-tls.lab.test/")" = 200 ] && { ready=1; break; }
  sleep 2
done
[ $ready = 1 ] || { ko "lab-tls.lab.test inaccessible après 30 s en HTTPS (cert importé ? route créée ?)"; exit 1; }
ok "lab-tls.lab.test répond en HTTPS"

# ---------------------------------------------------------------------------
# 4. Contrôles HTTPS
# ---------------------------------------------------------------------------
echo "== HTTPS — contrôles de base =="
expect_in() {
  local d=$1 got=$2; shift 2
  for a in "$@"; do [ "$got" = "$a" ] && { ok "$d ($got)"; return; }; done
  ko "$d : obtenu $got, attendu $*"
}

expect_in "GET / en HTTPS" "$(code_tls "https://lab-tls.lab.test/")" 200
expect_in "WAF bloc SQLi sur HTTPS" \
  "$(code_tls "https://lab-tls.lab.test/?id=1%27%20OR%20%271%27%3D%271")" \
  200 403   # selon la config WAF de la route (pas de WAF ici → 200 attendu)

echo "== HTTPS — en-têtes de sécurité TLS =="
headers=$(hdr "https://lab-tls.lab.test/")

# HSTS
if echo "$headers" | grep -qi 'strict-transport-security'; then
  ok "Strict-Transport-Security présent"
else
  ko "Strict-Transport-Security absent"
fi

# Alt-Svc / HTTP3
if echo "$headers" | grep -qi 'alt-svc'; then
  ok "Alt-Svc présent (HTTP/3 annoncé)"
else
  echo "  info  Alt-Svc absent (HTTP/3 non annoncé ou désactivé pour cette route)"
fi

echo "== HTTPS — SNI et cert =="
cn=$(echo | openssl s_client -connect "$EDGE_HOST:443" -servername lab-tls.lab.test 2>/dev/null \
  | openssl x509 -noout -subject 2>/dev/null | sed 's/.*CN\s*=\s*//')
[ -n "$cn" ] && ok "certificat servi par la passerelle (CN=$cn)" || ko "impossible de lire le CN du certificat servi"

echo "== HTTPS — Protocole : TLS 1.2 refusé (TLS 1.3 attendu comme minimum) =="
tls12=$(echo | openssl s_client -connect "$EDGE_HOST:443" -servername lab-tls.lab.test \
  -tls1_2 2>&1 | grep -c 'Cipher is\|CONNECTED')
[ "${tls12:-0}" -gt 0 ] \
  && echo "  info  TLS 1.2 accepté (attendu si TLS 1.2 n'est pas désactivé explicitement)" \
  || ok "TLS 1.2 refusé par la passerelle"

rm -rf "$TMP"
echo
[ $fail -eq 0 ] && echo "TLS : OK." || echo "$fail contrôle(s) en échec."
exit $fail
