#!/usr/bin/env bash
# =============================================================================
#  deploy.sh — Threat Intelligence MTM (Ubuntu 24.04, SQLite, systemd)
#  Author   : Dailam (Tugas Akhir / Internal Threat Hunting Tool)
#  Usage    : sudo bash deploy.sh [install|update|status|logs|restart|stop]
#
#  CARA PAKAI:
#    1. Upload file ini ke server (atau clone repo lalu jalankan dari sini)
#    2. Edit bagian "KONFIGURASI" di bawah (khususnya REPO_URL)
#    3. sudo bash deploy.sh install   -> deploy pertama kali
#    4. sudo bash deploy.sh update    -> update dari GitHub (tanpa reinstall)
#    5. sudo bash deploy.sh status    -> cek status service
#    6. sudo bash deploy.sh logs      -> lihat log realtime
#    7. sudo bash deploy.sh restart   -> restart service
#    8. sudo bash deploy.sh stop      -> stop service
#
#  TIDAK ADA PERUBAHAN KODE — semua config lewat .env
# =============================================================================
set -euo pipefail

# =============================================================================
# KONFIGURASI — UBAH SESUAI KEBUTUHAN
# =============================================================================

# URL repo GitHub kamu
# Contoh public  : https://github.com/username/vt-proxy.git
# Contoh private : https://<TOKEN>@github.com/username/vt-proxy.git
REPO_URL="https://github.com/boyyywiliam/vt-proxy-.git"

# Branch yang akan di-deploy
BRANCH="main"

# Folder instalasi di server
INSTALL_DIR="/opt/vt-proxy"

# Nama systemd service
SERVICE_NAME="vt-proxy"

# User sistem yang menjalankan service (dibuat otomatis jika belum ada)
APP_USER="vtproxy"

# Port yang dipakai FastAPI/Uvicorn
APP_PORT="8000"

# Host binding (0.0.0.0 = semua interface, 127.0.0.1 = lokal saja jika pakai Nginx)
APP_HOST="0.0.0.0"

# Jumlah worker uvicorn
# PENTING: untuk SQLite pakai 1, karena WAL hanya aman 1 writer
UVICORN_WORKERS=1

# =============================================================================
# WARNA OUTPUT
# =============================================================================
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
header()  { echo -e "\n${BOLD}${BLUE}==========================================${NC}"; \
            echo -e "${BOLD}${BLUE}  $*${NC}"; \
            echo -e "${BOLD}${BLUE}==========================================${NC}\n"; }

# =============================================================================
# GUARD: harus jalan sebagai root
# =============================================================================
[[ $EUID -ne 0 ]] && error "Jalankan dengan: sudo bash deploy.sh $*"

# =============================================================================
# VALIDASI KONFIGURASI
# =============================================================================
validate_config() {
    if [[ "$REPO_URL" == *"GANTI_INI"* ]]; then
        error "Atur dulu REPO_URL di bagian KONFIGURASI pada file deploy.sh!"
    fi
}

# =============================================================================
# INSTALL DEPENDENCIES SISTEM
# =============================================================================
install_system_deps() {
    header "Install System Dependencies"
    apt-get update -qq
    apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
        git curl wget \
        build-essential \
        sqlite3 \
        libsqlite3-dev \
        ca-certificates \
        net-tools
    success "System dependencies installed"
}

# =============================================================================
# BUAT USER SISTEM
# =============================================================================
create_app_user() {
    header "Setup App User"
    if id "$APP_USER" &>/dev/null; then
        warn "User '$APP_USER' sudah ada, dilewati"
    else
        useradd --system --no-create-home --shell /usr/sbin/nologin "$APP_USER"
        success "User '$APP_USER' dibuat"
    fi
}

# =============================================================================
# CLONE / UPDATE REPO DARI GITHUB
# =============================================================================
deploy_code() {
    header "Deploy Code dari GitHub"

    if [[ -d "$INSTALL_DIR/.git" ]]; then
        info "Repo sudah ada, melakukan git pull..."
        cd "$INSTALL_DIR"
        git stash --include-untracked 2>/dev/null || true
        git fetch origin "$BRANCH"
        git reset --hard "origin/$BRANCH"
        git stash pop 2>/dev/null || true
        success "Code berhasil di-update dari branch '$BRANCH'"
    else
        info "Clone repo ke $INSTALL_DIR ..."
        mkdir -p "$(dirname "$INSTALL_DIR")"
        git clone --depth=1 --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
        success "Repo berhasil di-clone"
    fi
}

# =============================================================================
# SETUP PYTHON VIRTUAL ENVIRONMENT
# =============================================================================
setup_venv() {
    header "Setup Python Virtual Environment"

    VENV_DIR="$INSTALL_DIR/venv"

    if [[ ! -d "$VENV_DIR" ]]; then
        info "Membuat venv baru..."
        python3 -m venv "$VENV_DIR"
    fi

    info "Install/update dependencies Python..."
    "$VENV_DIR/bin/pip" install --upgrade pip -q
    "$VENV_DIR/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q
    success "Python dependencies installed"
}

# =============================================================================
# SETUP .env DI SERVER
# =============================================================================
setup_env() {
    header "Setup Environment (.env)"

    ENV_FILE="$INSTALL_DIR/.env"

    if [[ -f "$ENV_FILE" ]]; then
        warn ".env sudah ada di server -- DIPERTAHANKAN (tidak ditimpa)"
        warn "Edit manual jika perlu: nano $ENV_FILE"
    else
        info "Membuat .env default (SQLite) ..."
        # .env tidak ikut ke git (ada di .gitignore), dibuat fresh di sini
        cat > "$ENV_FILE" <<ENVEOF
# =====================================================
# VT Proxy -- Environment Production
# File ini TIDAK di-commit ke GitHub (.gitignore)
# Edit sesuai kebutuhan!
# =====================================================

# Database: SQLite untuk single-server deployment
DB_BACKEND=sqlite
SQLITE_URL=sqlite:///./vt_proxy.db

# Secret key -- JANGAN DIUBAH setelah deploy pertama!
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# VirusTotal API base URL
VT_API_BASE_URL=https://www.virustotal.com/api/v3

# Auto refresh interval (hari)
AUTO_REFRESH_INTERVAL_DAYS=3

# Log level: DEBUG | INFO | WARNING | ERROR
LOG_LEVEL=INFO

# ===== MULTI-SOURCE THREAT INTELLIGENCE =====
ABUSEIPDB_API_BASE_URL=https://api.abuseipdb.com/api/v2
URLHAUS_API_BASE_URL=https://urlhaus-api.abuse.ch/v1
MXTOOLBOX_API_BASE_URL=https://mxtoolbox.com/api/v1

ABUSEIPDB_MAX_AGE_DAYS=90
MXTOOLBOX_COMMAND=blacklist
HTTP_TIMEOUT_SECONDS=15
ENVEOF
        success ".env production dibuat: $ENV_FILE"
        warn "Tambahkan API key VT lewat dashboard setelah deploy selesai!"
    fi
}

# =============================================================================
# SETUP FOLDER & PERMISSIONS
# =============================================================================
setup_permissions() {
    header "Setup Folder & Permissions"

    mkdir -p "$INSTALL_DIR"
    chown -R "$APP_USER:$APP_USER" "$INSTALL_DIR"

    # File sensitif tidak boleh dibaca user lain
    chmod 640 "$INSTALL_DIR/.env"
    [[ -f "$INSTALL_DIR/vt_proxy.db" ]] && chmod 640 "$INSTALL_DIR/vt_proxy.db"

    success "Permissions diatur untuk user '$APP_USER'"
}

# =============================================================================
# BUAT SYSTEMD SERVICE
# =============================================================================
setup_systemd() {
    header "Setup systemd Service"

    SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
    VENV_DIR="$INSTALL_DIR/venv"

    cat > "$SERVICE_FILE" <<SVCEOF
[Unit]
Description=Threat Intelligence MTM -- Internal SOC Threat Hunting Tool
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=${APP_USER}
Group=${APP_USER}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${INSTALL_DIR}/.env

ExecStart=${VENV_DIR}/bin/uvicorn app.main:app \
    --host ${APP_HOST} \
    --port ${APP_PORT} \
    --workers ${UVICORN_WORKERS} \
    --log-level info \
    --access-log

ExecReload=/bin/kill -HUP \$MAINPID
KillSignal=SIGTERM
KillMode=mixed
TimeoutStopSec=30

# Auto-restart jika crash
Restart=always
RestartSec=5
StartLimitInterval=60
StartLimitBurst=5

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=${INSTALL_DIR}

# Logging ke systemd journal
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}

[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    success "systemd service '${SERVICE_NAME}' dibuat & di-enable (auto-start)"
}

# =============================================================================
# START / RESTART SERVICE
# =============================================================================
start_service() {
    header "Start Service"

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        info "Service sedang berjalan, melakukan restart..."
        systemctl restart "$SERVICE_NAME"
        success "Service di-restart"
    else
        systemctl start "$SERVICE_NAME"
        success "Service dimulai"
    fi

    sleep 3

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        success "Service '${SERVICE_NAME}' RUNNING di port ${APP_PORT}"
    else
        error "Service gagal start! Cek log: journalctl -u ${SERVICE_NAME} -n 50"
    fi
}

# =============================================================================
# PRINT SUMMARY AKHIR
# =============================================================================
print_summary() {
    header "Deploy Selesai!"

    SERVER_IP=$(hostname -I | awk '{print $1}')

    echo -e "${GREEN}${BOLD}"
    echo "  +-------------------------------------------------+"
    echo "  |       THREAT INTELLIGENCE MTM -- LIVE!         |"
    echo "  +-------------------------------------------------+"
    echo "  |  API    : http://${SERVER_IP}:${APP_PORT}              |"
    echo "  |  Health : http://${SERVER_IP}:${APP_PORT}/health        |"
    echo "  |  API Doc: http://${SERVER_IP}:${APP_PORT}/docs          |"
    echo "  +-------------------------------------------------+"
    echo "  |  PERINTAH BERGUNA:                              |"
    echo "  |  sudo bash deploy.sh update   -> update kode   |"
    echo "  |  sudo bash deploy.sh logs     -> lihat log     |"
    echo "  |  sudo bash deploy.sh status   -> cek status    |"
    echo "  |  sudo bash deploy.sh restart  -> restart       |"
    echo "  +-------------------------------------------------+"
    echo -e "${NC}"

    warn "Jangan lupa tambahkan API key di dashboard Threat Intelligence MTM!"
    warn "Buka dashboard.html di browser, arahkan API ke: http://${SERVER_IP}:${APP_PORT}"
}

# =============================================================================
# SUB-COMMAND: update (tanpa reinstall system deps)
# =============================================================================
cmd_update() {
    validate_config
    header "Update Threat Intelligence MTM dari GitHub"
    deploy_code
    setup_venv
    setup_permissions
    start_service
    success "Update selesai!"
}

# =============================================================================
# ENTRY POINT
# =============================================================================
COMMAND="${1:-install}"

case "$COMMAND" in
    install)
        validate_config
        header "Threat Intelligence MTM -- Fresh Install"
        install_system_deps
        create_app_user
        deploy_code
        setup_venv
        setup_env
        setup_permissions
        setup_systemd
        start_service
        print_summary
        ;;

    update)
        cmd_update
        ;;

    status)
        echo -e "\n${BOLD}Status Service:${NC}"
        systemctl status "$SERVICE_NAME" --no-pager
        echo -e "\n${BOLD}Port:${NC}"
        ss -tlnp | grep ":${APP_PORT}" || echo "  (port ${APP_PORT} tidak terbuka)"
        ;;

    logs)
        info "Log realtime (Ctrl+C untuk keluar):"
        journalctl -u "$SERVICE_NAME" -f --no-pager
        ;;

    restart)
        systemctl restart "$SERVICE_NAME"
        success "Service '${SERVICE_NAME}' di-restart"
        systemctl status "$SERVICE_NAME" --no-pager -l
        ;;

    stop)
        systemctl stop "$SERVICE_NAME"
        warn "Service '${SERVICE_NAME}' dihentikan"
        ;;

    *)
        echo "Usage: sudo bash deploy.sh [install|update|status|logs|restart|stop]"
        exit 1
        ;;
esac
