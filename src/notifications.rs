use crate::syslog::SyslogForwarder;

#[derive(Clone)]
pub struct Notifier {
    telegram_token: Option<String>,
    telegram_chat: Option<String>,
}

impl Notifier {
    pub fn new() -> Self {
        let telegram_token = std::env::var("DLP_TELEGRAM_TOKEN").ok();
        let telegram_chat = std::env::var("DLP_TELEGRAM_CHAT").ok();

        if telegram_token.is_some() && telegram_chat.is_some() {
            tracing::info!("Telegram notifications configured");
        }

        Self { telegram_token, telegram_chat }
    }

    pub async fn send_raw(&self, text: &str, parse_mode: &str) {
        if let (Some(token), Some(chat)) = (&self.telegram_token, &self.telegram_chat) {
            let url = format!("https://api.telegram.org/bot{}/sendMessage", token);
            let client = reqwest::Client::new();
            let _ = client
                .post(&url)
                .json(&serde_json::json!({
                    "chat_id": chat,
                    "text": text,
                    "parse_mode": parse_mode
                }))
                .send()
                .await;
        }
    }

    pub async fn send_alert(&self, severity: &str, category: &str, description: &str) {
        let syslog = SyslogForwarder::new();
        syslog.send(severity, &format!("[{}] {}: {}", category, description, severity));

        if severity == "critical" || severity == "high" {
            let (icon, color) = match severity {
                "critical" => ("🚨", "#FF3355"),
                "high" => ("⚠️", "#EE6600"),
                _ => ("🔔", "#4488FF"),
            };
            let text = format!(
                r#"{} <b>ALERTA DLP</b> [<code>{}</code>]
━━━━━━━━━━━━━━━━
<b>📂 Categoría:</b> <code>{}</code>
<b>📝 Detalle:</b> <i>{}</i>
━━━━━━━━━━━━━━━━
⏱ <code>{}</code>"#,
                icon, severity.to_uppercase(), category, description,
                chrono::Utc::now().format("%Y-%m-%d %H:%M:%S")
            );
            self.send_raw(&text, "HTML").await;
        }
    }
}
