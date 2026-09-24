#!/usr/bin/env bash
# Source : obtient $token (PAT via LAB_ADMIN_TOKEN de préférence, sinon login email/mot de passe).
: "${LAB_ADMIN_URL:?}"
token=${LAB_ADMIN_TOKEN:-}
if [ -z "$token" ]; then
  : "${LAB_ADMIN_EMAIL:?définir LAB_ADMIN_TOKEN ou LAB_ADMIN_EMAIL/LAB_ADMIN_PASSWORD}" "${LAB_ADMIN_PASSWORD:?}"
  token=$(curl -fsS -X POST "$LAB_ADMIN_URL/api/v1/auth/login" \
    -H 'Content-Type: application/json' \
    -d "$(jq -n --arg e "$LAB_ADMIN_EMAIL" --arg p "$LAB_ADMIN_PASSWORD" '{email:$e,password:$p}')" | jq -r .token)
fi
[ -n "$token" ] && [ "$token" != null ] || { echo "authentification admin impossible (MFA activée ? utiliser LAB_ADMIN_TOKEN)"; exit 1; }
