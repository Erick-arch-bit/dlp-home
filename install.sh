#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────
#  DLP Home — Instalación automatizada
#  Compatible con Arch Linux, Debian/Ubuntu, Fedora
# ─────────────────────────────────────────────

BOLD='\033[1m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERR]${NC}   $*"; exit 1; }

detect_distro() {
    if [ -f /etc/arch-release ]; then
        echo "arch"
    elif [ -f /etc/debian_version ]; then
        echo "debian"
    elif [ -f /etc/fedora-release ]; then
        echo "fedora"
    else
        echo "unknown"
    fi
}

install_deps() {
    local distro
    distro=$(detect_distro)
    info "Detected distro: ${distro}"

    case "$distro" in
        arch)
            sudo pacman -Syu --noconfirm
            sudo pacman -S --noconfirm postgresql rust iptables wget curl
            ;;
        debian)
            sudo apt-get update
            sudo apt-get install -y postgresql postgresql-client rustc cargo iptables wget curl
            ;;
        fedora)
            sudo dnf install -y postgresql-server rust cargo iptables wget curl
            ;;
        *)
            warn "Unknown distro. Install manually: postgresql, rust, iptables"
            ;;
    esac
}

setup_database() {
    info "Configuring PostgreSQL..."

    sudo systemctl enable postgresql --now 2>/dev/null || true

    # Create user and database if they don't exist
    sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='dlp'" 2>/dev/null | grep -q 1 || \
        sudo -u postgres psql -c "CREATE USER dlp WITH PASSWORD 'dlp_security_2026';"

    sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='dlp'" 2>/dev/null | grep -q 1 || \
        sudo -u postgres psql -c "CREATE DATABASE dlp OWNER dlp;"

    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE dlp TO dlp;"

    ok "Database configured"
}

setup_dirs() {
    sudo mkdir -p /etc/dlp /var/dlp/quarantine /var/dlp/integrity
    sudo chmod 755 /etc/dlp /var/dlp
    sudo chmod 755 /var/dlp/quarantine /var/dlp/integrity
}

setup_config() {
    if [ ! -f /etc/dlp/config.toml ]; then
        info "Creating default config at /etc/dlp/config.toml"
        sudo tee /etc/dlp/config.toml > /dev/null << 'TOML'
[database]
url = "postgres://dlp:dlp_security_2026@localhost:5432/dlp"
max_connections = 5

[dashboard]
bind = "0.0.0.0"
port = 9090

[monitor]
watch_dirs = ["/home/lab", "/tmp"]
watch_interval_secs = 5
process_interval_secs = 10

[scanner]
patterns_file = "/etc/dlp/patterns.toml"

[proxy]
enabled = false
bind = "0.0.0.0"
port = 8080
TOML
        ok "Default config created"
    else
        ok "Config already exists at /etc/dlp/config.toml"
    fi
}

setup_service() {
    info "Installing systemd service..."

    local bin_path
    if [ -f ./target/release/dlp-home ]; then
        bin_path=$(realpath ./target/release/dlp-home)
        sudo cp "$bin_path" /usr/local/bin/dlp-home
    elif [ -f ./target/debug/dlp-home ]; then
        bin_path=$(realpath ./target/debug/dlp-home)
        sudo cp "$bin_path" /usr/local/bin/dlp-home
    else
        err "Build the binary first: cargo build --release"
    fi

    sudo chmod +x /usr/local/bin/dlp-home

    sudo tee /etc/systemd/system/dlp-home.service > /dev/null << 'SERVICE'
[Unit]
Description=DLP Home - Data Loss Prevention System
After=network.target postgresql.service

[Service]
Type=simple
ExecStart=/usr/local/bin/dlp-home --daemon
Restart=on-failure
RestartSec=5
User=root
Environment="DLP_TELEGRAM_TOKEN="
Environment="DLP_TELEGRAM_CHAT="
Environment="DLP_DASHBOARD_TOKEN=dlp_admin_2026"
Environment="DLP_SYSLOG_SERVER="

[Install]
WantedBy=multi-user.target
SERVICE

    sudo systemctl daemon-reload
    sudo systemctl enable dlp-home
    ok "Systemd service installed"
}

setup_firewall() {
    info "Configuring firewall..."
    if command -v ufw &> /dev/null; then
        sudo ufw allow ssh
        sudo ufw allow 9090/tcp comment 'DLP Dashboard'
        sudo ufw allow 8080/tcp comment 'DLP Proxy'
        sudo ufw --force enable 2>/dev/null || true
        ok "UFW configured"
    elif command -v firewall-cmd &> /dev/null; then
        sudo firewall-cmd --permanent --add-port=9090/tcp
        sudo firewall-cmd --permanent --add-port=8080/tcp
        sudo firewall-cmd --reload
        ok "FirewallD configured"
    else
        warn "No firewall tool found (ufw/firewalld). Open ports 9090 and 8080 manually."
    fi
}

show_env() {
    echo ""
    echo -e "${GREEN}${BOLD}┌────────────────────────────────────────────────┐${NC}"
    echo -e "${GREEN}${BOLD}│         DLP Home instalado correctamente       │${NC}"
    echo -e "${GREEN}${BOLD}└────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "  ${BOLD}Variables de entorno recomendadas:${NC}"
    echo ""
    echo -e "  ${CYAN}DLP_TELEGRAM_TOKEN${NC}=<bot_token>  # Notificaciones Telegram"
    echo -e "  ${CYAN}DLP_TELEGRAM_CHAT${NC}=<chat_id>     # Chat ID de Telegram"
    echo -e "  ${CYAN}DLP_DASHBOARD_TOKEN${NC}=dlp_admin_2026  # Token del dashboard"
    echo -e "  ${CYAN}DLP_SYSLOG_SERVER${NC}=<ip:port>     # Syslog forwarding (opcional)"
    echo ""
    echo -e "  Para editarlas: ${YELLOW}sudo systemctl edit dlp-home --full${NC}"
    echo ""
    echo -e "  ${BOLD}Comandos útiles:${NC}"
    echo -e "  sudo systemctl start dlp-home"
    echo -e "  sudo systemctl stop dlp-home"
    echo -e "  sudo systemctl restart dlp-home"
    echo -e "  sudo journalctl -u dlp-home -f"
    echo ""
    echo -e "  Dashboard: ${GREEN}http://<ip>:9090${NC}"
    echo -e "  Proxy:     ${GREEN}http://<ip>:8080${NC}"
    echo ""
    echo -e "  ${YELLOW}¡No olvides configurar DLP_TELEGRAM_TOKEN y DLP_TELEGRAM_CHAT!${NC}"
    echo ""
}

# ── Main ──────────────────────────────────────

echo ""
echo -e "${GREEN}${BOLD}  ╔═══════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}  ║    DLP Home — Instalador      ║${NC}"
echo -e "${GREEN}${BOLD}  ╚═══════════════════════════════╝${NC}"
echo ""

case "${1:-all}" in
    deps)        install_deps ;;
    db)          setup_database ;;
    dirs)        setup_dirs ;;
    config)      setup_config ;;
    service)     setup_service ;;
    firewall)    setup_firewall ;;
    all|"")
        install_deps
        setup_database
        setup_dirs
        setup_config
        setup_service
        setup_firewall
        show_env
        ;;
    *)
        echo "Usage: $0 [deps|db|dirs|config|service|firewall|all]"
        exit 1
        ;;
esac
