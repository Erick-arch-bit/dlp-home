use std::net::UdpSocket;

pub struct SyslogForwarder {
    enabled: bool,
    server: String,
    hostname: String,
}

impl SyslogForwarder {
    pub fn new() -> Self {
        let server = std::env::var("DLP_SYSLOG_SERVER").unwrap_or_default();
        let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap_or_default()
            .trim()
            .to_string();
        Self {
            enabled: !server.is_empty(),
            server,
            hostname,
        }
    }

    pub fn send(&self, severity: &str, msg: &str) {
        if !self.enabled {
            return;
        }
        let facility = 1; // user-level
        let sev_code = match severity {
            "critical" => 2,
            "high" => 3,
            "medium" => 4,
            "low" => 5,
            _ => 6,
        };
        let pri = facility * 8 + sev_code;
        let ts = chrono::Utc::now().format("%b %d %H:%M:%S").to_string();
        let syslog_msg = format!(
            "<{}>{} {} DLP: {}",
            pri, ts, self.hostname, msg
        );
        if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
            let _ = sock.send_to(syslog_msg.as_bytes(), &self.server);
        }
    }
}
