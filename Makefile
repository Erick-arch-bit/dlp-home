.PHONY: all build release install clean run run-daemon run-dashboard \
        stop restart logs db-setup uninstall help

BINARY  = dlp-home
BIN_DIR = /usr/local/bin
SERVICE = /etc/systemd/system/$(BINARY).service

all: build

# ── Build ──────────────────────────────────────

build:
	cargo build

release:
	cargo build --release

# ── Install ────────────────────────────────────

install: release
	sudo install -m 755 target/release/$(BINARY) $(BIN_DIR)/$(BINARY)
	@echo "Binary installed to $(BIN_DIR)/$(BINARY)"

install-deps:
	sudo ./install.sh deps

install-db:
	sudo ./install.sh db

install-service:
	sudo ./install.sh service

install-firewall:
	sudo ./install.sh firewall

install-full:
	sudo ./install.sh all

# ── Run ────────────────────────────────────────

run-daemon: build
	@echo "Starting DLP daemon..."
	cargo run -- --daemon

run-dashboard: build
	@echo "Starting dashboard (standalone)..."
	cargo run -- --port 9090

# ── Systemd ────────────────────────────────────

start: install
	sudo systemctl daemon-reload
	sudo systemctl enable $(BINARY)
	sudo systemctl restart $(BINARY)
	@echo "Service started. Status:"
	sudo systemctl status $(BINARY) --no-pager | head -5

stop:
	sudo systemctl stop $(BINARY) 2>/dev/null || true

restart:
	sudo systemctl restart $(BINARY)

logs:
	sudo journalctl -u $(BINARY) -f -n 50

status:
	sudo systemctl status $(BINARY) --no-pager

# ── Uninstall ──────────────────────────────────

uninstall:
	sudo systemctl stop $(BINARY) 2>/dev/null || true
	sudo systemctl disable $(BINARY) 2>/dev/null || true
	sudo rm -f $(SERVICE)
	sudo systemctl daemon-reload
	sudo rm -f $(BIN_DIR)/$(BINARY)
	sudo rm -rf /etc/dlp
	sudo rm -rf /var/dlp
	@echo "DLP Home uninstalled"

# ── Utils ──────────────────────────────────────

clean:
	cargo clean

help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Build:"
	@echo "  build          Build (debug)"
	@echo "  release        Build (release)"
	@echo ""
	@echo "Install:"
	@echo "  install        Copy binary to $(BIN_DIR)"
	@echo "  install-full   Full automated install (deps + db + service)"
	@echo ""
	@echo "Run:"
	@echo "  run-daemon     Run as daemon (foreground)"
	@echo "  run-dashboard  Run dashboard only"
	@echo ""
	@echo "Service:"
	@echo "  start          Install + start systemd service"
	@echo "  stop           Stop service"
	@echo "  restart        Restart service"
	@echo "  logs           Tail service logs"
	@echo "  status         Service status"
	@echo ""
	@echo "Uninstall:"
	@echo "  uninstall      Remove binary, service, config"
	@echo ""
	@echo "Other:"
	@echo "  db-setup       Create PostgreSQL database"
	@echo "  clean          Remove build artifacts"
