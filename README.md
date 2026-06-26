# 🛡️ DLP Home

**Data Loss Prevention System** — Lightweight DLP written in Rust. Monitors files, processes, network traffic, and detects sensitive data leaks (credit cards, CURP, RFC, API keys, etc.) in real time.

![RAM](https://img.shields.io/badge/RAM-~7MB-green) ![Rust](https://img.shields.io/badge/Rust-2024-orange) ![License](https://img.shields.io/badge/license-MIT-blue)

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **File Monitor** | Watches directories for new/modified files, scans for sensitive patterns |
| 🧬 **YARA Scanning** | Integrates YARA rules for advanced threat detection |
| 🗂️ **Archive Scanner** | Extracts and scans zip, tar, gz, bz2, xz archives |
| 🔒 **File Quarantine** | Copies critical matches to `/var/dlp/quarantine/` |
| ✅ **File Integrity** | SHA256 hash tracking to detect file tampering |
| ⚙️ **Process Monitor** | Detects and blocks pentest tools and unauthorized processes |
| 🌐 **HTTP Proxy** | Inspects HTTP traffic on port 8080, blocks policy violations |
| 📊 **Web Dashboard** | Real-time alerts, trends, console, reports on port 9090 |
| 🤖 **Telegram Bot** | Interactive bot with commands: `/status`, `/recent`, `/block`, `/resolve` |
| 📧 **Notifications** | Telegram + Syslog forwarding for critical alerts |
| 🚫 **Entity Blocking** | Block IPs, users, and processes from dashboard or Telegram |
| 📈 **Reports** | CSV export + weekly PDF report generation |
| 🏦 **Bank Simulator** | Built-in panel to generate test data (credit cards, CURP, RFC) for practice |

## 🚀 Quick Start

```bash
# 1. Clone and build
git clone https://github.com/YOUR_USER/dlp-home.git
cd dlp-home
cargo build --release

# 2. Run installer
sudo ./install.sh all

# 3. Set environment variables (edit service file)
sudo systemctl edit dlp-home --full
# Add:
#   Environment="DLP_TELEGRAM_TOKEN=your_bot_token"
#   Environment="DLP_TELEGRAM_CHAT=your_chat_id"
#   Environment="DLP_DASHBOARD_TOKEN=your_token"

# 4. Start service
sudo systemctl start dlp-home

# 5. Open dashboard
# http://<your-ip>:9090
```

## 📋 Requirements

- Linux (Arch, Debian, Fedora, or any distro with systemd)
- PostgreSQL 14+
- Rust 2024 edition
- iptables (for IP blocking)

## ⚙️ Configuration

### config.toml

The main config file lives at `/etc/dlp/config.toml`. See [`config.toml.example`](config.toml.example) for all options.

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DLP_TELEGRAM_TOKEN` | No | Telegram bot token for notifications |
| `DLP_TELEGRAM_CHAT` | No | Telegram chat/group ID |
| `DLP_DASHBOARD_TOKEN` | Yes | Login token for web dashboard |
| `DLP_SYSLOG_SERVER` | No | UDP syslog server (e.g. `192.168.1.100:514`) |

### Detection Patterns

Customize patterns at `/etc/dlp/patterns.toml` (see [`patterns.toml.example`](patterns.toml.example)).

Default patterns include:
- **Credit cards** — Visa, Mastercard, Amex, etc.
- **CURP / RFC** — Mexican identification numbers
- **SSN** — US Social Security Numbers
- **API keys** — Generic tokens, AWS keys, GitHub tokens
- **Private keys** — RSA/DSA/EC private keys
- **Passwords** — Plain text credentials
- **Connection strings** — Database URLs
- **JWT tokens** — JSON Web Tokens
- **Phone numbers** — Mexican phone format
- **IP addresses** — Internal/private IPs

## 🤖 Telegram Commands

| Command | Description |
|---------|-------------|
| `/status` | System summary (total alerts, critical, blocked) |
| `/recent` | Last 5 alerts with location and ID |
| `/where` | Last critical/high alert details |
| `/resolve <ID>` | Mark alert as resolved |
| `/resolved` | List last 10 resolved alerts |
| `/block <type> <value>` | Block an IP, user, or process |
| `/unblock <ID>` | Unblock an entity |
| `/blocked` | List all blocked entities |
| `/help` | Show all commands |

## 🏦 Bank Simulator

The dashboard includes a **Banco** panel that generates test files with financial data (credit cards, CURP, RFC). This triggers the DLP alerts in real time, demonstrating:

1. File creation with sensitive data
2. Automatic pattern detection
3. File quarantine
4. Telegram + Dashboard notifications

## 🖥️ Dashboard

Access the web dashboard at `http://<your-ip>:9090`.

Panels:
- **Alertas** — Live alerts with severity, filter, and resolve
- **Eventos** — System event log
- **Trends** — 30-day alert chart, severity breakdown, top sources
- **Consola** — Live log console with command input
- **Reportes** — CSV export + weekly report
- **Banco** — Bank data generator for testing
- **Config** — Telegram, directories, blocked entities

## 🛠️ Development

```bash
# Run daemon locally
cargo run -- --daemon

# Run dashboard only (no monitoring)
cargo run -- --port 9090

# One-time scan
cargo run -- --scan
```

## 📁 Project Structure

```
dlp-home/
├── src/
│   ├── main.rs           # Entry point, CLI args, daemon setup
│   ├── config.rs         # TOML configuration loader
│   ├── scanner.rs        # Regex pattern scanner
│   ├── monitor.rs        # File system monitor (notify)
│   ├── dashboard.rs      # Axum web server + API routes
│   ├── db.rs             # PostgreSQL database layer
│   ├── proxy.rs          # HTTP proxy with content inspection
│   ├── proc_monitor.rs   # Process and network monitor
│   ├── notifications.rs  # Telegram + syslog notifications
│   ├── telegram_bot.rs   # Interactive Telegram bot
│   ├── quarantine.rs     # File quarantine system
│   ├── integrity.rs      # File integrity (SHA256)
│   ├── archiver.rs       # Archive extraction and scanning
│   ├── yara_scanner.rs   # YARA rule integration
│   ├── reporter.rs       # CSV export + weekly reports
│   └── syslog.rs         # UDP syslog forwarder
├── static/
│   ├── index.html        # Dashboard UI
│   └── login.html        # Login page
├── install.sh            # Automated installer
├── Makefile              # Build/install/run targets
├── config.toml.example   # Example configuration
├── patterns.toml.example # Example detection patterns
└── yara_rules.yar.example # Example YARA rules
```

## 📄 License

MIT

---

*Built for educational purposes — University DLP assignment.*
