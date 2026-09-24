#!/usr/bin/env bash
# Supprime toutes les routes *.lab.test créées par seed.sh (à lancer après les tests).
set -u
. /lab/scripts/auth.sh
ids=$(curl -s -H "Authorization: Bearer $token" "$LAB_ADMIN_URL/api/v1/proxies" | jq -r '.[]? | select((.name // "") | endswith(".lab.test")) | "\(.id) \(.name)"')
[ -n "$ids" ] || { echo "aucune route *.lab.test"; exit 0; }
echo "$ids" | while read -r id name; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE -H "Authorization: Bearer $token" "$LAB_ADMIN_URL/api/v1/proxies/$id")
  printf '%-28s %s (%s)\n' "$name" "$id" "$code"
done
echo "Vérifier dans l'UI qu'il ne reste aucune route lab-* (révisions en attente comprises)."
