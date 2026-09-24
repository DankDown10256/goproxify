#!/usr/bin/env bash
# Régénère les services lab-tools / lab-k6 de docker-compose.lab.yml en y embarquant scripts/*.sh et load/*.js
# (aucun montage ni copie nécessaire sur le daemon distant). À relancer après toute modif de ces fichiers.
set -eu
cd "$(dirname "$0")"
F=docker-compose.lab.yml
emb() { # prefix file... -> variables d'environnement YAML (les $ sont doublés pour Compose)
  local p=$1; shift
  for f in "$@"; do
    printf '      %s%s: |\n' "$p" "$(basename "$f" | sed 's/\..*//; s/-/_/g')"
    tr -d '\r' < "$f" | sed 's/\$/$$/g; s/^\(.\)/        \1/'
  done
}
gen() {
cat <<'X'
  # >>> GENERATED (tests/lab/gen-compose.sh) — ne pas éditer à la main
  # Runners permanents pour `docker exec` : scripts embarqués, écrits au démarrage.
  lab-tools:
    image: alpine:3.20
    container_name: lab-tools
    restart: unless-stopped
    entrypoint:
      - sh
      - -c
      - |
        apk add --no-cache bash curl jq netcat-openbsd openssl coreutils >/dev/null
        mkdir -p /lab/scripts
        for f in seed attacks chaos hosts auth cleanup; do eval "printf %s \"\$$S_$$f\"" > /lab/scripts/$$f.sh; done
        exec sleep infinity
    networks: [goproxify_net]
    environment:
      LAB_ADMIN_URL: http://goproxify-admin:9443
X
emb S_ scripts/seed.sh scripts/attacks.sh scripts/chaos.sh scripts/hosts.sh scripts/auth.sh scripts/cleanup.sh
cat <<'X'

  lab-k6:
    image: grafana/k6:latest
    container_name: lab-k6
    user: root
    restart: unless-stopped
    entrypoint:
      - sh
      - -c
      - |
        mkdir -p /scripts /results
        for f in common smoke moderate baseline spike stress soak mixed hosts; do eval "printf %s \"\$$K_$$f\"" > /scripts/$$f.js; done
        mv /scripts/hosts.js /hosts.sh
        exec sleep infinity
    networks: [goproxify_net]
    environment:
X
emb K_ load/common.js load/smoke.js load/moderate.js load/baseline.js load/spike.js load/stress.js load/soak.js load/mixed.js scripts/hosts.sh
echo
echo '  # <<< GENERATED'
}
s=$(grep -n '>>> GENERATED' $F | cut -d: -f1); e=$(grep -n '<<< GENERATED' $F | cut -d: -f1)
{ sed -n "1,$((s-1))p" $F; gen; sed -n "$((e+1)),\$p" $F; } > $F.new && mv $F.new $F
