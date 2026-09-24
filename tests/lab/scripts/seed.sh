#!/usr/bin/env bash
# Crée les routes du labo via l'API Admin (idempotent : un host déjà présent est ignoré)
# et le proxy Toxiproxy utilisé par les scénarios de chaos.
set -u
. /lab/scripts/hosts.sh
. /lab/scripts/auth.sh

have=$(curl -s -H "Authorization: Bearer $token" "$LAB_ADMIN_URL/api/v1/proxies" | jq -r '.[]? | .name // empty')

route() { # host backend [extra json merge]
  local body
  if echo "$have" | grep -qx "$1"; then printf '%-28s déjà présent : ignoré\n' "$1"; return; fi
  body=$(jq -n --arg h "$1" --arg b "$2" --argjson x "${3:-{\}}" \
    '{config: ({host:$h, type:"http", tls_enabled:false, backends:[{url:$b, weight:1}]} + $x)}')
  code=$(curl -s -o /tmp/seed.out -w '%{http_code}' -X POST "$LAB_ADMIN_URL/api/v1/proxies" \
    -H "Authorization: Bearer $token" -H 'Content-Type: application/json' -d "$body")
  printf '%-28s -> %s (%s)\n' "$1" "$2" "$code"
  case "$code" in 2*) ;; *) jq -r '(.dry_run.errors // [])[] | "  erreur : " + .' /tmp/seed.out 2>/dev/null || head -c 300 /tmp/seed.out; ;; esac
}

route lab-fast.lab.test        http://lab-backend:9000
route lab-waf-block.lab.test   http://lab-backend:9000 '{"waf":{"enabled":true,"mode":"block","max_body_mb":1,"anomaly_threshold":0}}'
route lab-waf-detect.lab.test  http://lab-backend:9000 '{"waf":{"enabled":true,"mode":"detect","max_body_mb":1,"anomaly_threshold":0}}'
route lab-ratelimit.lab.test   http://lab-backend:9000 '{"rate_limit":{"rps":10,"burst":20}}'
route lab-chaos.lab.test       http://lab-toxiproxy:8666
route lab-juice.lab.test       http://lab-juice:3000    '{"waf":{"enabled":true,"mode":"detect","max_body_mb":5,"anomaly_threshold":0}}'

curl -s -X POST http://lab-toxiproxy:8474/proxies -H 'Content-Type: application/json' \
  -d '{"name":"backend","listen":"0.0.0.0:8666","upstream":"lab-backend:9000","enabled":true}' >/dev/null
echo "toxiproxy: backend :8666 -> lab-backend:9000"
