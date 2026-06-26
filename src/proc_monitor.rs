use crate::db::Database;
use crate::notifications::Notifier;
use std::sync::Arc;
use sysinfo::{Networks, ProcessesToUpdate, System};
use tokio::time::{interval, Duration};

const BLOCKED_TOOLS: &[&str] = &[
    "nmap", "masscan", "sqlmap", "hydra", "john", "hashcat",
    "aircrack-ng", "netcat", "nc", "ncat", "socat",
    "proxychains", "tsocks", "torsocks",
    "crackmapexec", "metasploit", "msfconsole", "msfvenom",
    "nikto", "dirb", "gobuster", "wfuzz",
    "burpsuite", "zap", "mitmproxy",
    "sshpass", "medusa", "patator",
];

pub struct ProcMonitor {
    db: Arc<Database>,
    notifier: Arc<Notifier>,
}

impl ProcMonitor {
    pub fn new(db: Arc<Database>, notifier: Arc<Notifier>) -> Self {
        Self { db, notifier }
    }

    pub async fn run(&self, interval_secs: u64) {
        let mut tick = interval(Duration::from_secs(interval_secs));
        let mut sys = System::new();
        let mut known_pids: Vec<i32> = Vec::new();
        let mut net_rx: u64 = 0;
        let mut net_tx: u64 = 0;

        loop {
            tick.tick().await;
            sys.refresh_processes(ProcessesToUpdate::All, true);

            let current_pids: Vec<i32> = sys.processes().keys().map(|p| p.as_u32() as i32).collect();

            for &pid in &current_pids {
                if !known_pids.contains(&pid) {
                    if let Some(process) = sys.processes().get(&sysinfo::Pid::from_u32(pid as u32)) {
                        let name = process.name().to_string_lossy().to_string();
                        let cmd = process.cmd().join(std::ffi::OsStr::new(" ")).to_string_lossy().to_string();
                        let user = process.user_id().map(|uid| uid.to_string()).unwrap_or_default();

                        let blocked_process = match self.db.is_entity_blocked("process", &name.to_lowercase()).await {
                            Ok(true) => true,
                            _ => false,
                        };

                        if blocked_process {
                            let desc = format!("Process blocked by policy: {} (PID: {}, user: {})", name, pid, user);
                            tracing::warn!("{}", desc);
                            let _ = self.db.insert_alert("critical", "blocked_process", "proc_monitor", &desc, None).await;
                            self.notifier.send_alert("critical", "blocked_process", &desc).await;
                            let _ = std::process::Command::new("kill").args(["-9", &pid.to_string()]).output();
                            continue;
                        }

                        for &tool in BLOCKED_TOOLS {
                            if name.contains(tool) || cmd.to_lowercase().contains(tool) {
                                let desc = format!("Tool blocked: {} (PID: {}, user: {})", tool, pid, user);
                                tracing::warn!("{}", desc);

                                let _ = self.db.insert_alert("critical", "blocked_tool", "proc_monitor", &desc, None).await;
                                self.notifier.send_alert("critical", "blocked_tool", &desc).await;

                                let _ = std::process::Command::new("kill")
                                    .args(["-9", &pid.to_string()])
                                    .output();
                                break;
                            }
                        }

                        let _ = self.db.insert_event("new_process", "proc_monitor",
                            &format!("PID: {}, Name: {}", pid, name),
                            Some(&serde_json::json!({"pid": pid, "name": name, "cmd": cmd, "user": user})),
                        ).await;

                        known_pids.push(pid);
                    }
                }
            }

            known_pids.retain(|&pid| current_pids.contains(&pid));

            let networks = Networks::new_with_refreshed_list();
            let mut total_rx: u64 = 0;
            let mut total_tx: u64 = 0;

            for (name, data) in &networks {
                if name.starts_with("lo") { continue; }
                total_rx += data.total_received();
                total_tx += data.total_transmitted();
            }

            if net_rx > 0 {
                let rx_diff = total_rx.saturating_sub(net_rx);
                let tx_diff = total_tx.saturating_sub(net_tx);

                if rx_diff > 50_000_000 || tx_diff > 10_000_000 {
                    let rx_mb = rx_diff as f64 / 1_000_000.0;
                    let tx_mb = tx_diff as f64 / 1_000_000.0;
                    let desc = format!("High traffic: \u{2193}{:.1}MB \u{2191}{:.1}MB", rx_mb, tx_mb);
                    let _ = self.db.insert_alert("medium", "network_traffic", "proc_monitor", &desc, None).await;
                    self.notifier.send_alert("medium", "network_traffic", &desc).await;
                }
            }

            net_rx = total_rx;
            net_tx = total_tx;
        }
    }
}
