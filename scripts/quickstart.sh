#!/usr/bin/env bash
# =============================================================================
# GOPROXIFY — Quickstart Docker (Admin + Core + Agent)
#
# Usage :
#   curl -fsSL …/scripts/quickstart.sh -o quickstart.sh && bash quickstart.sh
#   bash quickstart.sh --env-only
#   bash quickstart.sh --print-secrets
#
# Ne nécessite pas root. Distinct de setup.sh (install systemd native).
# =============================================================================
set -euo pipefail

COMPOSE_FILE="docker-compose.quickstart.yml"
ENV_FILE=".env"
ENV_EXAMPLE=".env.example"
RAW_BASE="${GOPROXIFY_RAW_BASE:-https://github.com/Vincamok/goproxify/raw/public/main}"
ADMIN_PORT="${ADMIN_PORT:-9443}"
MIN_DISK_MB=500
HEALTH_RETRIES=30
HEALTH_SLEEP=2

DO_ENV_ONLY=false
DO_PRINT_SECRETS=false
DO_YES=false
DO_FORCE=false
SKIP_PORTS=false
NO_PULL=false

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

info()    { echo -e "${CYAN}==>${RESET} ${BOLD}$*${RESET}"; }
success() { echo -e "${GREEN}  ✓${RESET} $*"; }
warn()    { echo -e "${YELLOW}  !${RESET} $*"; }
error()   { echo -e "${RED}  ✗${RESET} $*" >&2; exit 1; }
step()    { echo -e "\n${BOLD}${CYAN}[$1]${RESET} ${BOLD}$2${RESET}"; }

usage() {
  cat <<'EOF'
Usage: bash quickstart.sh [options]

Options:
  --env-only       Génère/écrit .env uniquement (pas de docker compose up)
  --print-secrets  Affiche deux secrets hex-32 et quitte
  --yes            Non-interactif (email/mdp via GPX_FIRST_ADMIN_EMAIL / PASSWORD)
  --force          Écrase un .env existant
  --skip-ports     Ignore le contrôle des ports 9443 / 80 / 443
  --no-pull        docker compose up sans --pull always
  -h, --help       Aide
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --env-only) DO_ENV_ONLY=true ;;
    --print-secrets) DO_PRINT_SECRETS=true ;;
    --yes) DO_YES=true ;;
    --force) DO_FORCE=true ;;
    --skip-ports) SKIP_PORTS=true ;;
    --no-pull) NO_PULL=true ;;
    -h|--help) usage; exit 0 ;;
    *) error "Option inconnue : $1 (voir --help)" ;;
  esac
  shift
done

banner() {
  echo ""
  echo -e "${BOLD}${CYAN}"
  echo "   ██████╗  ██████╗ ██████╗ ██████╗  ██████╗ ██╗  ██╗██╗███████╗██╗   ██╗"
  echo "  ██╔════╝ ██╔═══██╗██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝██║██╔════╝╚██╗ ██╔╝"
  echo "  ██║  ███╗██║   ██║██████╔╝██████╔╝██║   ██║ ╚███╔╝ ██║█████╗   ╚████╔╝ "
  echo "  ██║   ██║██║   ██║██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗ ██║██╔══╝    ╚██╔╝  "
  echo "  ╚██████╔╝╚██████╔╝██║     ██║  ██║╚██████╔╝██╔╝ ██╗██║██║        ██║   "
  echo "   ╚═════╝  ╚═════╝ ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝        ╚═╝   "
  echo -e "${RESET}"
  echo -e "  ${DIM}Quickstart Docker — Admin + Core + Agent${RESET}"
  echo ""
}

hex32() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  elif [ -r /dev/urandom ]; then
    # shellcheck disable=SC2002
    cat /dev/urandom | head -c 32 | od -An -tx1 | tr -d ' \n'
  else
    error "openssl ou /dev/urandom requis pour générer les secrets"
  fi
}

port_in_use() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -ltn "( sport = :$port )" 2>/dev/null | grep -q ":$port"
  elif command -v lsof >/dev/null 2>&1; then
    lsof -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
  else
    return 1
  fi
}

fetch_if_missing() {
  local file="$1" url="$2"
  if [ -f "$file" ]; then
    success "$file déjà présent"
    return 0
  fi
  info "Téléchargement de $file…"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$file" || error "Échec téléchargement $url"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$file" "$url" || error "Échec téléchargement $url"
  else
    error "curl ou wget requis"
  fi
  success "$file téléchargé"
}

escape_sed() {
  # Échappe \, / et & pour un remplacement sed safe (mots de passe arbitraires).
  printf '%s' "$1" | sed -e 's/[\\/&]/\\&/g'
}

set_env_key() {
  local key="$1" value="$2" escaped
  escaped="$(escape_sed "$value")"
  if grep -qE "^#?${key}=" "$ENV_FILE" 2>/dev/null; then
    sed -i.bak -e "s|^#\\?${key}=.*|${key}=${escaped}|" "$ENV_FILE"
  else
    printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
  fi
}

# Lit versions.json local, sinon télécharge depuis GitHub (RAW_BASE).
resolve_image_tags() {
  # Préversion : toujours le tag flottant preview (SemVer = versions.json pour les builds CI).
  TAG_ADMIN=preview
  TAG_CORE=preview
  TAG_AGENT=preview
  success "Tags images — preview (flottant)"
}

write_env() {
  local jwt="$1" pairing="$2" email="$3" password="$4"
  # Contrôle d’existence déjà fait avant prompt ; --force autorise l’écrasement.
  if [ ! -f "$ENV_EXAMPLE" ]; then
    error "$ENV_EXAMPLE introuvable (téléchargez-le avant)"
  fi
  resolve_image_tags
  cp "$ENV_EXAMPLE" "$ENV_FILE"
  set_env_key GPX_JWT_SECRET "$jwt"
  set_env_key GPX_PAIRING_SECRET "$pairing"
  set_env_key GPX_FIRST_ADMIN_EMAIL "$email"
  set_env_key GPX_FIRST_ADMIN_PASSWORD "$password"
  set_env_key GOPROXIFY_ADMIN_TAG "$TAG_ADMIN"
  set_env_key GOPROXIFY_CORE_TAG "$TAG_CORE"
  set_env_key GOPROXIFY_AGENT_TAG "$TAG_AGENT"
  rm -f "${ENV_FILE}.bak"
  chmod 600 "$ENV_FILE"
  success "$ENV_FILE écrit (chmod 600) — images :preview"
}

prompt_admin() {
  local email password password2
  if [ "$DO_YES" = true ]; then
    email="${GPX_FIRST_ADMIN_EMAIL:-}"
    password="${GPX_FIRST_ADMIN_PASSWORD:-}"
    [ -n "$email" ] || error "GPX_FIRST_ADMIN_EMAIL requis avec --yes"
    [ -n "$password" ] || error "GPX_FIRST_ADMIN_PASSWORD requis avec --yes"
    [ "${#password}" -ge 12 ] || error "Mot de passe trop court (min. 12 caractères)"
    ADMIN_EMAIL="$email"
    ADMIN_PASSWORD="$password"
    return 0
  fi
  echo ""
  read -r -p "  E-mail admin : " email
  [ -n "$email" ] || error "E-mail requis"
  while true; do
    read -r -s -p "  Mot de passe admin (min. 12) : " password
    echo ""
    [ "${#password}" -ge 12 ] || { warn "Trop court — réessayez"; continue; }
    read -r -s -p "  Confirmer le mot de passe : " password2
    echo ""
    [ "$password" = "$password2" ] || { warn "Ne correspond pas — réessayez"; continue; }
    break
  done
  ADMIN_EMAIL="$email"
  ADMIN_PASSWORD="$password"
}

# ---------------------------------------------------------------------------
banner

if [ "$DO_PRINT_SECRETS" = true ]; then
  echo -e "${BOLD}Secrets hex-32 (openssl rand -hex 32)${RESET}"
  echo ""
  echo "GPX_JWT_SECRET=$(hex32)"
  echo "GPX_PAIRING_SECRET=$(hex32)"
  echo ""
  echo -e "${DIM}Copiez dans Portainer (stack.env) ou .env — ne les committez pas.${RESET}"
  exit 0
fi

# ---------------------------------------------------------------------------
step 1 "Prérequis"
command -v docker >/dev/null 2>&1 || error "Docker introuvable — installez Docker ou utilisez l’onglet Binary / setup.sh"
if docker compose version >/dev/null 2>&1; then
  success "docker compose $(docker compose version --short 2>/dev/null || echo ok)"
else
  error "Docker Compose v2 requis (docker compose …)"
fi

if [ "$SKIP_PORTS" != true ] && [ "$DO_ENV_ONLY" != true ]; then
  for p in "$ADMIN_PORT" 80 443; do
    if port_in_use "$p"; then
      warn "Port $p déjà utilisé — libérez-le ou relancez avec --skip-ports / ADMIN_PORT=…"
      error "Contrôle ports échoué"
    fi
  done
  success "Ports $ADMIN_PORT / 80 / 443 libres"
else
  success "Contrôle ports ignoré"
fi

if command -v df >/dev/null 2>&1; then
  avail=$(df -Pm . 2>/dev/null | awk 'NR==2{print $4}')
  if [ -n "${avail:-}" ] && [ "$avail" -lt "$MIN_DISK_MB" ]; then
    error "Espace disque insuffisant (${avail} Mo < ${MIN_DISK_MB} Mo)"
  fi
  success "Espace disque OK (${avail:-?} Mo libres)"
fi

# ---------------------------------------------------------------------------
step 2 "Fichiers compose"
fetch_if_missing "$COMPOSE_FILE" "${RAW_BASE}/${COMPOSE_FILE}"
fetch_if_missing "$ENV_EXAMPLE" "${RAW_BASE}/${ENV_EXAMPLE}"

# ---------------------------------------------------------------------------
step 3 "Secrets & compte admin"
if [ -f "$ENV_FILE" ] && [ "$DO_FORCE" != true ]; then
  error "$ENV_FILE existe déjà — stack déjà configurée. Utilisez --force pour régénérer, ou : docker compose -f ${COMPOSE_FILE} up -d"
fi
JWT_SECRET="$(hex32)"
PAIRING_SECRET="$(hex32)"
success "GPX_JWT_SECRET et GPX_PAIRING_SECRET générés (hex-32)"
prompt_admin
write_env "$JWT_SECRET" "$PAIRING_SECRET" "$ADMIN_EMAIL" "$ADMIN_PASSWORD"
unset JWT_SECRET PAIRING_SECRET ADMIN_PASSWORD
# Ne pas laisser les secrets dans l’environnement du shell parent

if [ "$DO_ENV_ONLY" = true ]; then
  echo ""
  info "Mode --env-only : démarrage sauté"
  echo -e "  Ensuite : ${BOLD}docker compose -f ${COMPOSE_FILE} up -d${RESET}"
  echo -e "  Admin   : ${BOLD}http://localhost:${ADMIN_PORT}${RESET}"
  echo ""
  exit 0
fi

# ---------------------------------------------------------------------------
step 4 "Déploiement"
PULL_FLAG=(--pull always)
if [ "$NO_PULL" = true ]; then
  PULL_FLAG=()
fi
info "docker compose -f ${COMPOSE_FILE} up -d …"
# shellcheck disable=SC2086
docker compose -f "$COMPOSE_FILE" up -d "${PULL_FLAG[@]}" || {
  warn "Échec up — état des services :"
  docker compose -f "$COMPOSE_FILE" ps || true
  docker compose -f "$COMPOSE_FILE" logs --tail 40 || true
  error "Déploiement échoué"
}
success "Stack démarrée"

# ---------------------------------------------------------------------------
step 5 "Contrôle santé"
ok=false
info "Attente Admin sur :${ADMIN_PORT} (max $((HEALTH_RETRIES * HEALTH_SLEEP))s)…"
for i in $(seq 1 "$HEALTH_RETRIES"); do
  if curl -fsS "http://127.0.0.1:${ADMIN_PORT}/api/v1/health" >/dev/null 2>&1 \
    || wget -qO- "http://127.0.0.1:${ADMIN_PORT}/api/v1/health" >/dev/null 2>&1; then
    ok=true
    break
  fi
  # Affiche un point toutes les 2 s (pas un redémarrage du script)
  printf '%s' "."
  sleep "$HEALTH_SLEEP"
done
echo ""
if [ "$ok" = true ]; then
  success "Admin répond sur http://localhost:${ADMIN_PORT}"
else
  warn "Admin pas encore prêt après $((HEALTH_RETRIES * HEALTH_SLEEP))s"
  warn "Vérifiez : docker compose -f ${COMPOSE_FILE} ps && docker compose -f ${COMPOSE_FILE} logs"
fi

# Crash-loop Docker ≠ boucle du script
if docker compose -f "$COMPOSE_FILE" ps 2>/dev/null | grep -qiE 'Restarting|Exit'; then
  warn "Des conteneurs redémarrent ou sont sortis — ce n'est PAS une boucle du script."
  warn "Cause fréquente : image GHCR inaccessible (unauthorized) ou .env incomplet."
  docker compose -f "$COMPOSE_FILE" ps || true
fi

running=$(docker compose -f "$COMPOSE_FILE" ps --status running -q 2>/dev/null | wc -l | tr -d ' ')
success "Conteneurs running : ${running}"

echo ""
echo -e "${GREEN}${BOLD}Prêt.${RESET} Ouvrez ${BOLD}http://localhost:${ADMIN_PORT}${RESET}"
echo -e "  Appairage Core/Agent : automatique via ${BOLD}GPX_PAIRING_SECRET${RESET} (même .env)."
echo -e "  ${DIM}Ne committez pas .env — secrets à usage unique affichés uniquement à la génération.${RESET}"
echo ""
