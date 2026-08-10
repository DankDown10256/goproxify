#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# GOPROXIFY — Script d'installation (déploiement natif, hors Docker)
# Usage : sudo ./setup.sh
# =============================================================================

BINARY_NAME="goproxify"
INSTALL_DIR="/usr/local/bin"
GOPROXIFY_DIR="/etc/goproxify"
SYSTEMD_DIR="/etc/systemd/system"
RUN_USER="goproxify"

# ---------------------------------------------------------------------------
# Couleurs
# ---------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}==>${RESET} ${BOLD}$*${RESET}"; }
success() { echo -e "${GREEN}  ✓${RESET} $*"; }
warn()    { echo -e "${YELLOW}  !${RESET} $*"; }
error()   { echo -e "${RED}  ✗ ERREUR :${RESET} $*" >&2; exit 1; }
ask()     { echo -e "${BOLD}$*${RESET}"; }

# ---------------------------------------------------------------------------
# Vérifications préalables
# ---------------------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || error "Ce script doit être exécuté en root (sudo ./setup.sh)"

command -v systemctl >/dev/null 2>&1 || error "systemd est requis (systemctl introuvable)"

# ---------------------------------------------------------------------------
# Détection OS
# ---------------------------------------------------------------------------
detect_os() {
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_FAMILY="${ID_LIKE:-$ID}"
  else
    OS_ID="unknown"
    OS_FAMILY="unknown"
  fi
}

detect_os

# ---------------------------------------------------------------------------
# Bannière
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}${CYAN}"
echo "  ██████╗ ██████╗  ██████╗ ██████╗ ██████╗ ██╗██╗  ██╗██╗   ██╗"
echo "  ██╔════╝██╔═══██╗██╔══██╗██╔══██╗██╔══██╗██║╚██╗██╔╝╚██╗ ██╔╝"
echo "  ██║  ███╗██║   ██║██████╔╝██████╔╝██████╔╝██║ ╚███╔╝  ╚████╔╝ "
echo "  ██║   ██║██║   ██║██╔═══╝ ██╔══██╗██╔══██╗██║ ██╔██╗   ╚██╔╝  "
echo "  ╚██████╔╝╚██████╔╝██║     ██║  ██║██║  ██║██║██╔╝ ██╗   ██║   "
echo "   ╚═════╝  ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝   ╚═╝  "
echo -e "${RESET}"
echo -e "  Reverse proxy distribué & sécurisé — Installation native (hors Docker)"
echo ""

# ---------------------------------------------------------------------------
# Sélection des modules à installer
# ---------------------------------------------------------------------------
ask "Quels modules voulez-vous installer sur cette machine ?"
echo ""
echo "  [1] Administration  — Control Plane (UI web, API, SQLite) — port 9443"
echo "  [2] Core            — Data Plane (reverse proxy, HTTP/1/2/3) — ports 80, 443"
echo "  [3] Agent           — Discovery & Télémétrie (Docker labels, /proc metrics)"
echo ""
echo "  Entrez les numéros séparés par des espaces (ex: 1 2 pour Admin+Core)"
echo "  Appuyez sur Entrée pour tout installer [1 2 3]"
echo ""
read -r -p "  Choix : " MODULES_INPUT
MODULES_INPUT="${MODULES_INPUT:-1 2 3}"

INSTALL_ADMIN=false
INSTALL_CORE=false
INSTALL_AGENT=false

for m in $MODULES_INPUT; do
  case "$m" in
    1) INSTALL_ADMIN=true ;;
    2) INSTALL_CORE=true  ;;
    3) INSTALL_AGENT=true ;;
    *) warn "Choix '$m' ignoré." ;;
  esac
done

$INSTALL_ADMIN || $INSTALL_CORE || $INSTALL_AGENT \
  || error "Aucun module valide sélectionné."

echo ""
echo -e "  Modules sélectionnés :"
$INSTALL_ADMIN && echo -e "    ${GREEN}✓${RESET} Administration"
$INSTALL_CORE  && echo -e "    ${GREEN}✓${RESET} Core"
$INSTALL_AGENT && echo -e "    ${GREEN}✓${RESET} Agent"
echo ""
read -r -p "  Confirmer l'installation ? [O/n] : " CONFIRM
CONFIRM="${CONFIRM:-O}"
[[ "$CONFIRM" =~ ^[OoYy]$ ]] || { echo "Installation annulée."; exit 0; }

# ---------------------------------------------------------------------------
# Localisation du binaire
# ---------------------------------------------------------------------------
echo ""
info "Localisation du binaire Goproxify"

BINARY_PATH=""

# 1. Déjà installé ?
if command -v goproxify >/dev/null 2>&1; then
  BINARY_PATH="$(command -v goproxify)"
  success "Binaire existant trouvé : ${BINARY_PATH}"

# 2. Présent dans le répertoire courant ?
elif [ -f "./${BINARY_NAME}" ]; then
  BINARY_PATH="$(pwd)/${BINARY_NAME}"
  success "Binaire trouvé dans le répertoire courant : ${BINARY_PATH}"

# 3. Compiler depuis les sources si go est disponible ?
elif command -v go >/dev/null 2>&1 && [ -f "./cmd/goproxify/main.go" ]; then
  info "Compilation du binaire depuis les sources (go build)..."
  CGO_ENABLED=0 go build -ldflags="-s -w" -o "./${BINARY_NAME}" ./cmd/goproxify
  BINARY_PATH="$(pwd)/${BINARY_NAME}"
  success "Compilation réussie : ${BINARY_PATH}"

else
  error "Binaire '${BINARY_NAME}' introuvable.\n" \
        "  Options :\n" \
        "    - Placez le binaire compilé dans le répertoire courant, ou\n" \
        "    - Installez Go et relancez (les sources seront compilées automatiquement)"
fi

# ---------------------------------------------------------------------------
# Installation du binaire
# ---------------------------------------------------------------------------
info "Installation du binaire dans ${INSTALL_DIR}/"

install -o root -g root -m 0755 "${BINARY_PATH}" "${INSTALL_DIR}/${BINARY_NAME}"
success "Binaire installé : ${INSTALL_DIR}/${BINARY_NAME}"

# ---------------------------------------------------------------------------
# Création de l'utilisateur système
# ---------------------------------------------------------------------------
info "Création de l'utilisateur système '${RUN_USER}'"

if id "${RUN_USER}" >/dev/null 2>&1; then
  success "Utilisateur '${RUN_USER}' déjà présent"
else
  useradd --system --no-create-home --shell /usr/sbin/nologin "${RUN_USER}"
  success "Utilisateur '${RUN_USER}' créé"
fi

# Agent a besoin d'accéder au socket Docker
if $INSTALL_AGENT && getent group docker >/dev/null 2>&1; then
  usermod -aG docker "${RUN_USER}"
  success "Utilisateur '${RUN_USER}' ajouté au groupe 'docker'"
fi

# ---------------------------------------------------------------------------
# Arborescence /etc/goproxify/
# ---------------------------------------------------------------------------
info "Création de l'arborescence ${GOPROXIFY_DIR}/"

mkdir -p \
  "${GOPROXIFY_DIR}/certs/live" \
  "${GOPROXIFY_DIR}/database" \
  "${GOPROXIFY_DIR}/storage/errors" \
  "${GOPROXIFY_DIR}/storage/pages" \
  "${GOPROXIFY_DIR}/storage/static" \
  "${GOPROXIFY_DIR}/cache/proxy" \
  "${GOPROXIFY_DIR}/logs"

# Permissions
chown -R "${RUN_USER}:${RUN_USER}" "${GOPROXIFY_DIR}"
chmod 750 "${GOPROXIFY_DIR}/certs"
chmod 700 "${GOPROXIFY_DIR}/database"
chmod 755 "${GOPROXIFY_DIR}/storage"
chmod 755 "${GOPROXIFY_DIR}/logs"
chmod 755 "${GOPROXIFY_DIR}/cache"

# Core a besoin de lier les ports < 1024 sans être root
if $INSTALL_CORE && command -v setcap >/dev/null 2>&1; then
  setcap 'cap_net_bind_service=+ep' "${INSTALL_DIR}/${BINARY_NAME}"
  success "Capability cap_net_bind_service activée (ports < 1024 sans root)"
fi

success "Arborescence créée"

# ---------------------------------------------------------------------------
# Pages d'erreurs par défaut
# ---------------------------------------------------------------------------
info "Génération des pages d'erreurs HTTP par défaut"

declare -A ERROR_LABELS=(
  [400]="Bad Request"
  [403]="Accès refusé"
  [404]="Page introuvable"
  [500]="Erreur interne"
  [502]="Service indisponible"
  [503]="En maintenance"
  [504]="Délai dépassé"
)

for code in 400 403 404 500 502 503 504; do
  dest="${GOPROXIFY_DIR}/storage/errors/${code}.html"
  if [ ! -f "${dest}" ]; then
    label="${ERROR_LABELS[$code]}"
    cat > "${dest}" <<HTML
<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${code} — ${label}</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
         background:#0f172a;color:#e2e8f0;display:flex;align-items:center;
         justify-content:center;min-height:100vh}
    .box{text-align:center;padding:2rem}
    .code{font-size:6rem;font-weight:700;color:#38bdf8;line-height:1}
    .label{font-size:1.25rem;color:#94a3b8;margin-top:.5rem}
    .sep{width:3rem;height:2px;background:#38bdf8;margin:1.5rem auto}
    .brand{font-size:.8rem;color:#475569;margin-top:1.5rem;letter-spacing:.1em;text-transform:uppercase}
  </style>
</head>
<body>
  <div class="box">
    <div class="code">${code}</div>
    <div class="label">${label}</div>
    <div class="sep"></div>
    <div class="brand">Goproxify</div>
  </div>
</body>
</html>
HTML
    chown "${RUN_USER}:${RUN_USER}" "${dest}"
  fi
done

success "Pages d'erreurs générées"

# ---------------------------------------------------------------------------
# Fichier de configuration d'environnement
# ---------------------------------------------------------------------------
info "Configuration de l'environnement"

ENV_FILE="${GOPROXIFY_DIR}/goproxify.env"

if [ ! -f "${ENV_FILE}" ]; then
  cat > "${ENV_FILE}" <<ENV
# Goproxify — Variables d'environnement
# Généré par setup.sh le $(date -Iseconds)
# Éditez ce fichier puis relancez : systemctl restart goproxify-*

# ---------------------------------------------------------------------------
# ADMINISTRATION
# ---------------------------------------------------------------------------
ADMIN_PORT=9443
ADMIN_DB_PATH=${GOPROXIFY_DIR}/database/goproxify.db
LOG_LEVEL=info

# ---------------------------------------------------------------------------
# CORE
# ---------------------------------------------------------------------------
CORE_HTTP_PORT=80
CORE_HTTPS_PORT=443
CORE_ADMIN_API_URL=http://127.0.0.1:9443
CORE_TOKEN=
# Laisser vide : l'Admin génère le token au premier lancement et le partage via volume (/etc/goproxify/.pairing-token).
# Définir uniquement si vous gérez le token manuellement (avancé).

# ---------------------------------------------------------------------------
# AGENT
# ---------------------------------------------------------------------------
AGENT_DOCKER_SOCKET=/var/run/docker.sock
AGENT_METRICS_PORT=9191
AGENT_ADMIN_API_URL=http://127.0.0.1:9443
AGENT_TOKEN=CHANGEME_générez_avec__goproxify_token_-role_agent

# ---------------------------------------------------------------------------
# ACME / Let's Encrypt (DNS-01)
# ---------------------------------------------------------------------------
ACME_EMAIL=admin@example.fr
ACME_DNS_PROVIDER=ovh
ACME_CERT_STORAGE=${GOPROXIFY_DIR}/certs/live

# OVH
# OVH_ENDPOINT=ovh-eu
# OVH_APPLICATION_KEY=
# OVH_APPLICATION_SECRET=
# OVH_CONSUMER_KEY=

# Cloudflare
# CF_API_TOKEN=

# Gandi
# GANDI_API_KEY=
ENV
  chmod 640 "${ENV_FILE}"
  chown "root:${RUN_USER}" "${ENV_FILE}"
  success "Fichier d'environnement créé : ${ENV_FILE}"
else
  warn "Fichier d'environnement déjà présent, ignoré : ${ENV_FILE}"
fi

# ---------------------------------------------------------------------------
# Unités systemd
# ---------------------------------------------------------------------------
info "Création des unités systemd"

# --- Administration ----------------------------------------------------------
if $INSTALL_ADMIN; then
  cat > "${SYSTEMD_DIR}/goproxify-admin.service" <<UNIT
[Unit]
Description=Goproxify Administration (Control Plane)
Documentation=https://github.com/Vincamok/goproxify
After=network.target
Wants=network.target

[Service]
Type=simple
User=${RUN_USER}
Group=${RUN_USER}
EnvironmentFile=${ENV_FILE}
ExecStart=${INSTALL_DIR}/${BINARY_NAME} admin
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=goproxify-admin

# Durcissement
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${GOPROXIFY_DIR}
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
UNIT
  success "Unité systemd créée : goproxify-admin.service"
fi

# --- Core -------------------------------------------------------------------
if $INSTALL_CORE; then
  cat > "${SYSTEMD_DIR}/goproxify-core.service" <<UNIT
[Unit]
Description=Goproxify Core (Data Plane — Reverse Proxy)
Documentation=https://github.com/Vincamok/goproxify
After=network.target goproxify-admin.service
Wants=network.target
Requires=goproxify-admin.service

[Service]
Type=simple
User=${RUN_USER}
Group=${RUN_USER}
EnvironmentFile=${ENV_FILE}
ExecStart=${INSTALL_DIR}/${BINARY_NAME} core
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=goproxify-core

# Durcissement
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${GOPROXIFY_DIR}/logs ${GOPROXIFY_DIR}/cache
ReadOnlyPaths=${GOPROXIFY_DIR}/certs ${GOPROXIFY_DIR}/storage
# cap_net_bind_service positionné via setcap sur le binaire (ports 80/443)
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

# Ports ouverts par le Core :
#   :80   :443       → trafic proxy public
#   :8000            → API interne (push config/certs depuis l'Administration)
#                      À restreindre au réseau d'infra via firewall (ufw/iptables)

[Install]
WantedBy=multi-user.target
UNIT
  success "Unité systemd créée : goproxify-core.service"
fi

# --- Agent ------------------------------------------------------------------
if $INSTALL_AGENT; then
  cat > "${SYSTEMD_DIR}/goproxify-agent.service" <<UNIT
[Unit]
Description=Goproxify Agent (Discovery & Télémétrie)
Documentation=https://github.com/Vincamok/goproxify
After=network.target docker.service goproxify-admin.service
Wants=network.target docker.service

[Service]
Type=simple
User=${RUN_USER}
Group=${RUN_USER}
EnvironmentFile=${ENV_FILE}
ExecStart=${INSTALL_DIR}/${BINARY_NAME} agent
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s
TimeoutStopSec=15s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=goproxify-agent

# Lecture /proc pour la télémétrie CPU/RAM/IO
ProtectProc=noaccess
ProcSubset=pid

# Durcissement
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${GOPROXIFY_DIR}/logs
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
UNIT
  success "Unité systemd créée : goproxify-agent.service"
fi

# ---------------------------------------------------------------------------
# Rechargement systemd et activation
# ---------------------------------------------------------------------------
info "Activation des services systemd"

systemctl daemon-reload

if $INSTALL_ADMIN; then
  systemctl enable --now goproxify-admin.service
  success "goproxify-admin  activé et démarré"
fi

if $INSTALL_CORE; then
  systemctl enable goproxify-core.service
  success "goproxify-core   activé (démarrera après configuration du token)"
fi

if $INSTALL_AGENT; then
  systemctl enable goproxify-agent.service
  success "goproxify-agent  activé (démarrera après configuration du token)"
fi

# ---------------------------------------------------------------------------
# Récapitulatif
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Installation terminée${RESET}"
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${RESET}"
echo ""

if $INSTALL_ADMIN; then
  echo -e "  ${BOLD}Administration${RESET}"
  echo -e "    URL     : https://$(hostname -f 2>/dev/null || echo localhost):9443"
  echo -e "    Logs    : journalctl -u goproxify-admin -f"
  echo -e "    Statut  : systemctl status goproxify-admin"
  echo ""
fi

if $INSTALL_CORE; then
  echo -e "  ${BOLD}Core${RESET}"
  echo -e "    HTTP    : http://$(hostname -f 2>/dev/null || echo localhost):80"
  echo -e "    HTTPS   : https://$(hostname -f 2>/dev/null || echo localhost):443"
  echo -e "    API int : http://<ip-infra>:8000  ${YELLOW}(restreindre au réseau d'infra — voir ci-dessous)${RESET}"
  echo -e "    Logs    : journalctl -u goproxify-core -f"
  echo ""
fi

if $INSTALL_AGENT; then
  echo -e "  ${BOLD}Agent${RESET}"
  echo -e "    Metrics : http://$(hostname -f 2>/dev/null || echo localhost):9191/metrics"
  echo -e "    Logs    : journalctl -u goproxify-agent -f"
  echo ""
fi

echo -e "  ${BOLD}Prochaines étapes :${RESET}"
echo ""

if $INSTALL_ADMIN; then
  echo -e "  ${CYAN}1.${RESET} Éditez le fichier d'environnement :"
  echo -e "       nano ${ENV_FILE}"
  echo ""
  echo -e "  ${CYAN}2.${RESET} Accédez à l'interface d'initialisation (premier lancement) :"
  echo -e "       https://$(hostname -f 2>/dev/null || echo localhost):9443"
  echo ""
  echo -e "  ${CYAN}3.${RESET} Générez les tokens d'appairage pour Core et/ou Agent :"
  echo -e "       goproxify token -role core  -node \"\$(hostname)\""
  echo -e "       goproxify token -role agent -node \"\$(hostname)\""
  echo -e "     Puis renseignez CORE_TOKEN / AGENT_TOKEN dans ${ENV_FILE}"
  echo ""
fi

if $INSTALL_CORE || $INSTALL_AGENT; then
  step=$( $INSTALL_ADMIN && echo 4 || echo 1 )
  echo -e "  ${CYAN}${step}.${RESET} Démarrez les services restants :"
  $INSTALL_CORE  && echo -e "       systemctl start goproxify-core"
  $INSTALL_AGENT && echo -e "       systemctl start goproxify-agent"
  echo ""
fi

if $INSTALL_CORE; then
  echo -e "  ${YELLOW}Sécurité réseau — port 8000 (API interne Core) :${RESET}"
  echo -e "  Le port 8000 ne doit être accessible que depuis l'Administration."
  echo -e "  Exemples de restriction firewall :"
  echo -e ""
  echo -e "    # ufw (Ubuntu/Debian)"
  echo -e "    ufw deny 8000"
  echo -e "    ufw allow from <ip-admin> to any port 8000"
  echo -e ""
  echo -e "    # iptables"
  echo -e "    iptables -A INPUT -p tcp --dport 8000 ! -s <ip-admin> -j DROP"
  echo -e ""
fi

echo -e "  ${YELLOW}Pour désinstaller :${RESET}"
echo -e "    systemctl disable --now goproxify-admin goproxify-core goproxify-agent"
echo -e "    rm -f ${SYSTEMD_DIR}/goproxify-*.service"
echo -e "    rm -f ${INSTALL_DIR}/${BINARY_NAME}"
echo -e "    userdel ${RUN_USER}"
echo -e "    rm -rf ${GOPROXIFY_DIR}   # ATTENTION : supprime les données"
echo ""
