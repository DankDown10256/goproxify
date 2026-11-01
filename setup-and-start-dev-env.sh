#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
export GPX_DEV_ROOT="$PWD"
dev_dir="$PWD/dev-data/dev-env"

for tool in docker openssl; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "Required command not found: $tool" >&2
    exit 1
  }
done
docker compose version >/dev/null
docker buildx version >/dev/null || {
  echo "Docker Buildx is required for an isolated, disposable build cache." >&2
  exit 1
}
docker info >/dev/null || {
  echo "Cannot access Docker. Check that Docker is running and your user has access." >&2
  exit 1
}

echo "Select services (space-separated numbers or names):"
echo "  1) Admin"
echo "  2) Edge"
echo "  3) Agent"
echo "  4) All"
read -r -p "Selection: " -a choices

admin=false
edge=false
agent=false
for choice in "${choices[@]}"; do
  case "$choice" in
    1|admin) admin=true ;;
    2|edge) edge=true ;;
    3|agent) agent=true ;;
    4|all) admin=true; edge=true; agent=true ;;
    *) echo "Invalid selection: $choice" >&2; exit 1 ;;
  esac
done

services=()
if "$admin"; then services+=(admin); fi
if "$edge"; then services+=(edge); fi
if "$agent"; then services+=(agent); fi
if ((${#services[@]} == 0)); then
  echo "Select at least one service." >&2
  exit 1
fi

umask 077
builder="goproxify-dev-$$"
buildkit_image="moby/buildkit:buildx-stable-1"
compose_ready=false
builder_started=false
remove_buildkit_image=false
compose=(docker compose --project-name goproxify-dev --file "$dev_dir/compose.yml")

cleanup() {
  local status=$?
  local failed=0
  trap - EXIT
  trap '' INT TERM
  set +e
  echo "Removing the development environment and its data..."

  if "$compose_ready"; then
    "${compose[@]}" down --volumes --rmi all --remove-orphans || failed=1
  fi
  if "$builder_started"; then
    docker buildx rm --force "$builder" || failed=1
  fi
  if "$remove_buildkit_image"; then
    if docker image inspect "$buildkit_image" >/dev/null 2>&1; then
      docker image rm "$buildkit_image" || failed=1
    fi
  fi

  if ((failed == 0)); then
    rm -rf -- "$dev_dir" || failed=1
    rmdir -- "$GPX_DEV_ROOT/dev-data" 2>/dev/null || true
  fi
  if ((failed != 0)); then
    echo "Cleanup incomplete. See the errors above; configuration retained for retry." >&2
    status=1
  else
    echo "Development resources and data removed."
  fi
  exit "$status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p "$dev_dir"
for secret in jwt pairing portal; do
  if [[ ! -s "$dev_dir/$secret" ]]; then
    openssl rand -hex 32 > "$dev_dir/$secret"
  fi
done
export GPX_DEV_JWT_SECRET="$(< "$dev_dir/jwt")"
export GPX_DEV_PAIRING_SECRET="$(< "$dev_dir/pairing")"
export GPX_DEV_PORTAL_MASTER_KEY="$(< "$dev_dir/portal")"
export GPX_DEV_AGENT_PAIRING_KEY
GPX_DEV_AGENT_PAIRING_KEY="$(
  printf '%s' "goproxify/agent-pairing/v1:$GPX_DEV_PAIRING_SECRET" |
    openssl dgst -sha256 | awk '{print $NF}'
)"

cat > "$dev_dir/compose.yml" <<'YAML'
services:
  admin:
    image: goproxify-dev-admin:local
    build:
      context: "${GPX_DEV_ROOT:?}"
      dockerfile: services/admin/Dockerfile
    environment:
      GPX_APP_ENVIRONMENT: development
      GPX_SECURITY_JWT_SECRET: "${GPX_DEV_JWT_SECRET:?}"
      GPX_PAIRING_SECRET: "${GPX_DEV_PAIRING_SECRET:?}"
      GPX_FIRST_ADMIN_EMAIL: admin@localhost.test
      GPX_FIRST_ADMIN_PASSWORD: "Dev-local-123!"
      GPX_IDENTITY_EDGE_NODE_NAME: edge
      GPX_SERVER_API_PORT: "9443"
      GPX_ENGINE_LOG_LEVEL: debug
    ports:
      - "127.0.0.1:9443:9443"
    volumes:
      - admin-data:/etc/goproxify

  edge:
    image: goproxify-dev-edge:local
    build:
      context: "${GPX_DEV_ROOT:?}"
      dockerfile: services/edge/Dockerfile
    environment:
      GPX_PAIRING_SECRET: "${GPX_DEV_PAIRING_SECRET:?}"
      GPX_AGENT_PAIRING_KEY: "${GPX_DEV_AGENT_PAIRING_KEY:?}"
      GPX_PORTAL_MASTER_KEY: "${GPX_DEV_PORTAL_MASTER_KEY:?}"
      GPX_IDENTITY_EDGE_NODE_NAME: edge
      GPX_ENGINE_LOG_LEVEL: debug
    ports:
      - "127.0.0.1:8080:80"
      - "127.0.0.1:8443:443"
      - "127.0.0.1:8443:443/udp"
      - "127.0.0.1:8000:8000"
    volumes:
      - edge-data:/etc/goproxify

  agent:
    image: goproxify-dev-agent:local
    build:
      context: "${GPX_DEV_ROOT:?}"
      dockerfile: services/agent/Dockerfile
    environment:
      GPX_AGENT_PAIRING_KEY: "${GPX_DEV_AGENT_PAIRING_KEY:?}"
      GPX_CONTROL_PLANE_EDGE_ENDPOINT: http://edge:8000
      GPX_IDENTITY_AGENT_NODE_NAME: dev-agent
      GPX_ENGINE_LOG_LEVEL: debug
    ports:
      - "127.0.0.1:9191:9191"
    volumes:
      - agent-data:/etc/goproxify
      - /var/run/docker.sock:/var/run/docker.sock:ro

volumes:
  admin-data:
  edge-data:
  agent-data:
YAML

compose_ready=true
if ! docker image inspect "$buildkit_image" >/dev/null 2>&1; then
  remove_buildkit_image=true
fi
builder_started=true
docker buildx create --name "$builder" --driver docker-container \
  --driver-opt "image=$buildkit_image" >/dev/null

for service in "${services[@]}"; do
  docker buildx build --builder "$builder" --load \
    --tag "goproxify-dev-${service}:local" \
    --file "$GPX_DEV_ROOT/services/$service/Dockerfile" "$GPX_DEV_ROOT"
done

echo "Starting: ${services[*]}"
if ! "${compose[@]}" up --detach --no-build --wait --wait-timeout 120 "${services[@]}"; then
  "${compose[@]}" ps --all || true
  "${compose[@]}" logs --tail 80 "${services[@]}" || true
  exit 1
fi

if "$admin"; then
  echo "Admin: http://localhost:9443"
  echo "Development login: admin@localhost.test / Dev-local-123!"
fi
if "$edge"; then
  echo "Edge: http://localhost:8080 / https://localhost:8443"
fi
echo "Press Ctrl+C to stop and DELETE the development environment and all its data."
"${compose[@]}" logs --follow "${services[@]}"
