use crate::db::Database;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

pub struct TelegramBot {
    token: String,
    db: Arc<Database>,
    last_update_id: AtomicI64,
}

impl TelegramBot {
    pub fn new(db: Arc<Database>) -> Option<Self> {
        let token = std::env::var("DLP_TELEGRAM_TOKEN").ok()?;
        Some(Self { token, db, last_update_id: AtomicI64::new(0) })
    }

    pub async fn run(&self) {
        let client = reqwest::Client::new();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3));

        loop {
            interval.tick().await;

            let offset = self.last_update_id.load(Ordering::Relaxed);

            let url = format!(
                "https://api.telegram.org/bot{}/getUpdates?offset={}&timeout=10",
                self.token, offset
            );

            let resp = match client.get(&url).send().await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("Telegram getUpdates error: {}", e);
                    continue;
                }
            };

            let body: serde_json::Value = match resp.json().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("Telegram JSON parse error: {}", e);
                    continue;
                }
            };

            if !body.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                let desc = body.get("description").and_then(|v| v.as_str()).unwrap_or("unknown error");
                tracing::warn!("Telegram API error: {}", desc);
                continue;
            }

            let updates = match body.get("result").and_then(|v| v.as_array()) {
                Some(arr) => arr.clone(),
                None => continue,
            };

            for update in &updates {
                let update_id = update.get("update_id").and_then(|v| v.as_i64()).unwrap_or(0);
                self.last_update_id.store(update_id + 1, Ordering::Relaxed);

                let msg = match update.get("message") {
                    Some(m) => m,
                    None => continue,
                };

                let chat_id = msg.get("chat").and_then(|c| c.get("id")).and_then(|v| v.as_i64()).unwrap_or(0);
                let text = msg.get("text").and_then(|v| v.as_str()).unwrap_or("").trim().to_lowercase();
                let text_original = msg.get("text").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();

                let reply = self.handle_command(&text, &text_original).await;

                if let Some(reply_text) = reply {
                    let send_url = format!("https://api.telegram.org/bot{}/sendMessage", self.token);
                    let _ = client.post(&send_url).json(&serde_json::json!({
                        "chat_id": chat_id,
                        "text": reply_text,
                        "parse_mode": "HTML",
                    })).send().await;
                }
            }
        }
    }

    async fn handle_command(&self, _cmd: &str, raw: &str) -> Option<String> {
        let parts: Vec<&str> = raw.splitn(4, ' ').collect();
        let command = parts[0].to_lowercase();

        Some(match command.as_str() {
            "/start" => self.cmd_start().await,
            "/status" | "/estado" => self.cmd_status().await,
            "/recent" | "/ultimas" => self.cmd_recent().await,
            "/where" | "/donde" | "/locate" => self.cmd_where().await,
            "/resolve" | "/resolver" => self.cmd_resolve(parts.get(1).copied()).await,
            "/resolved" | "/resueltas" => self.cmd_resolved().await,
            "/block" | "/bloquear" => self.cmd_block(parts).await,
            "/unblock" | "/desbloquear" => self.cmd_unblock(parts.get(1).copied()).await,
            "/blocked" | "/bloqueados" => self.cmd_blocked().await,
            "/help" | "/ayuda" => self.cmd_help().await,
            _ if command.starts_with('/') => {
                format!("❌ Comando `{}` no reconocido.\n\nUsa /help para ver los comandos disponibles.", command)
            }
            _ => return None,
        })
    }

    async fn cmd_start(&self) -> String {
        "👋 <b>DLP Home Bot activo</b>\n\n\
        Recibe notificaciones de alertas en tiempo real.\n\
        Puedes consultar, resolver y bloquear entidades desde este chat.\n\n\
        Usa /help para ver los comandos disponibles.".to_string()
    }

    async fn cmd_help(&self) -> String {
        "📋 <b>Comandos disponibles</b>\n\n\
        🔍 <b>Consultas</b>\n\
        └ /status — Resumen del sistema\n\
        └ /recent — Últimas 5 alertas\n\
        └ /where — Última alerta crítica\n\
        └ /resolved — Alertas resueltas\n\n\
        ✅ <b>Gestión</b>\n\
        └ /resolve &lt;ID&gt; — Resolver alerta\n\
        └ /block &lt;tipo&gt; &lt;valor&gt; — Bloquear entidad\n\
        └ /unblock &lt;ID&gt; — Desbloquear\n\
        └ /blocked — Listar bloqueos\n\n\
        💡 <b>Ejemplos:</b>\n\
        <code>/resolve 42</code>\n\
        <code>/block ip 192.168.1.100</code>\n\
        <code>/block user root</code>\n\
        <code>/block process nmap</code>".to_string()
    }

    async fn cmd_status(&self) -> String {
        let total: i64 = match sqlx::query_scalar("SELECT COUNT(*) FROM alerts")
            .fetch_one(self.db.pool()).await
        {
            Ok(v) => v,
            Err(e) => return format!("❌ Error al consultar BD: <code>{}</code>", e),
        };
        let critical: i64 = match sqlx::query_scalar("SELECT COUNT(*) FROM alerts WHERE severity = 'critical'")
            .fetch_one(self.db.pool()).await
        {
            Ok(v) => v,
            Err(e) => return format!("❌ Error al consultar BD: <code>{}</code>", e),
        };
        let high: i64 = match sqlx::query_scalar("SELECT COUNT(*) FROM alerts WHERE severity = 'high'")
            .fetch_one(self.db.pool()).await
        {
            Ok(v) => v,
            Err(e) => return format!("❌ Error al consultar BD: <code>{}</code>", e),
        };
        let unresolved: i64 = match sqlx::query_scalar("SELECT COUNT(*) FROM alerts WHERE NOT resolved")
            .fetch_one(self.db.pool()).await
        {
            Ok(v) => v,
            Err(e) => return format!("❌ Error al consultar BD: <code>{}</code>", e),
        };
        let today: i64 = match sqlx::query_scalar(
            "SELECT COUNT(*) FROM alerts WHERE timestamp >= $1",
        )
        .bind(chrono::Utc::now() - chrono::Duration::days(1))
        .fetch_one(self.db.pool()).await
        {
            Ok(v) => v,
            Err(e) => return format!("❌ Error al consultar BD: <code>{}</code>", e),
        };
        let blocked: i64 = match sqlx::query_scalar("SELECT COUNT(*) FROM blocked_entities")
            .fetch_one(self.db.pool()).await
        {
            Ok(v) => v,
            Err(e) => return format!("❌ Error al consultar BD: <code>{}</code>", e),
        };

        format!(
            "📊 <b>Resumen DLP</b>\n\
            ━━━━━━━━━━━━━━━━━━━━\n\
            🛡️ Total alertas:      <code>{total}</code>\n\
            🔴 Críticas:           <code>{critical}</code>\n\
            🟠 Altas:              <code>{high}</code>\n\
            ⏳ Sin resolver:       <code>{unresolved}</code>\n\
            📅 Últimas 24h:        <code>{today}</code>\n\
            🚫 Entidades bloqueadas: <code>{blocked}</code>\n\
            ━━━━━━━━━━━━━━━━━━━━\n\
            💡 <i>Usa /recent para ver detalles</i>",
            total = total, critical = critical, high = high,
            unresolved = unresolved, today = today, blocked = blocked
        )
    }

    async fn cmd_recent(&self) -> String {
        #[derive(sqlx::FromRow)]
        struct AlertRow {
            id: i64,
            severity: String,
            pattern_name: String,
            description: String,
            timestamp: chrono::DateTime<chrono::Utc>,
            resolved: bool,
        }

        let alerts: Vec<AlertRow> = match sqlx::query_as::<_, AlertRow>(
            "SELECT id, severity, pattern_name, description, timestamp, resolved FROM alerts ORDER BY timestamp DESC LIMIT 5"
        )
        .fetch_all(self.db.pool()).await
        {
            Ok(a) => a,
            Err(e) => return format!("❌ Error al consultar BD: <code>{}</code>", e),
        };

        if alerts.is_empty() {
            return "📭 No hay alertas registradas.".to_string();
        }

        let mut lines = vec!["📌 <b>Últimas 5 alertas</b>".to_string()];
        for a in &alerts {
            let (icon, color) = match a.severity.as_str() {
                "critical" => ("🚨", "#FF3355"),
                "high" => ("⚠️", "#EE6600"),
                "medium" => ("⚡", "#DD9900"),
                _ => ("ℹ️", "#4488FF"),
            };
            let ts = a.timestamp.format("%d/%m %H:%M").to_string();
            let loc = extract_location(&a.description);
            let status = if a.resolved { " ✅" } else { "" };
            lines.push(format!(
                r#"{icon} <b>#{id}</b> | <code>{sev}</code>{status}
└ 📂 <code>{pat}</code>
└ 📍 <code>{loc}</code>
└ 🕐 {ts}"#,
                icon = icon, id = a.id, sev = a.severity.to_uppercase(),
                status = status, pat = a.pattern_name, loc = loc, ts = ts
            ));
        }
        lines.join("\n\n")
    }

    async fn cmd_where(&self) -> String {
        #[derive(sqlx::FromRow)]
        struct AlertRow {
            id: i64,
            severity: String,
            pattern_name: String,
            description: String,
            timestamp: chrono::DateTime<chrono::Utc>,
            hostname: Option<String>,
            process_name: Option<String>,
            username: Option<String>,
            pid: Option<i32>,
        }

        let alert: Option<AlertRow> = sqlx::query_as::<_, AlertRow>(
            "SELECT id, severity, pattern_name, description, timestamp, hostname, process_name, username, pid \
             FROM alerts WHERE severity IN ('critical','high') ORDER BY timestamp DESC LIMIT 1"
        )
        .fetch_optional(self.db.pool()).await
        .unwrap_or(None);

        match alert {
            Some(a) => {
                let loc = extract_location(&a.description);
                let mut extra = String::new();
                if let Some(ref host) = a.hostname {
                    extra.push_str(&format!("\n🖥️ Host: <code>{}</code>", host));
                }
                if let Some(ref proc) = a.process_name {
                    extra.push_str(&format!("\n⚙️ Proceso: <code>{}</code>", proc));
                }
                if let Some(ref user) = a.username {
                    extra.push_str(&format!("\n👤 Usuario: <code>{}</code>", user));
                }
                if let Some(p) = a.pid {
                    extra.push_str(&format!("\n🆔 PID: <code>{}</code>", p));
                }
                format!(
                    "📍 <b>Última alerta {sev}</b>\n\
                    ━━━━━━━━━━━━━━━━━━━━\n\
                    📂 Ruta: <code>{loc}</code>\n\
                    🏷️ Patrón: <code>{pat}</code>{extra}\n\
                    📝 Detalle: <i>{desc}</i>\n\
                    🕐 <code>{ts}</code>\n\
                    ━━━━━━━━━━━━━━━━━━━━\n\
                    ✅ Para resolver: <code>/resolve {id}</code>",
                    sev = a.severity.to_uppercase(), loc = loc, pat = a.pattern_name,
                    extra = extra, desc = a.description, ts = a.timestamp.format("%d/%m %Y %H:%M:%S"), id = a.id
                )
            }
            None => "✅ No hay alertas críticas o altas sin resolver.".to_string(),
        }
    }

    async fn cmd_resolve(&self, arg: Option<&str>) -> String {
        let id: i64 = match arg.and_then(|s| s.parse().ok()) {
            Some(v) => v,
            None => return "❌ Uso: <code>/resolve &lt;ID&gt;</code>\nEjemplo: <code>/resolve 42</code>\n\nUsa /recent para ver los IDs de las alertas.".to_string(),
        };

        match self.db.resolve_alert(id).await {
            Ok(true) => format!("✅ Alerta <code>#{id}</code> marcada como resuelta.", id = id),
            Ok(false) => format!("❌ Alerta <code>#{id}</code> no encontrada.", id = id),
            Err(e) => format!("❌ Error de BD al resolver: <code>{}</code>", e),
        }
    }

    async fn cmd_resolved(&self) -> String {
        #[derive(sqlx::FromRow)]
        struct AlertRow {
            id: i64,
            pattern_name: String,
            description: String,
            timestamp: chrono::DateTime<chrono::Utc>,
        }

        let alerts: Vec<AlertRow> = match sqlx::query_as::<_, AlertRow>(
            "SELECT id, pattern_name, description, timestamp FROM alerts WHERE resolved = TRUE ORDER BY timestamp DESC LIMIT 10"
        )
        .fetch_all(self.db.pool()).await
        {
            Ok(a) => a,
            Err(e) => return format!("❌ Error al consultar BD: <code>{}</code>", e),
        };

        if alerts.is_empty() {
            return "📭 No hay alertas resueltas.".to_string();
        }

        let mut lines = vec!["✅ <b>Últimas 10 alertas resueltas</b>".to_string()];
        for a in &alerts {
            let loc = extract_location(&a.description);
            let ts = a.timestamp.format("%d/%m %H:%M").to_string();
            lines.push(format!("• <code>#{id}</code> | <b>{pat}</b>: <i>{loc}</i> ({ts})",
                id = a.id, pat = a.pattern_name, loc = loc, ts = ts));
        }
        lines.join("\n\n")
    }

    async fn cmd_block(&self, parts: Vec<&str>) -> String {
        if parts.len() < 3 {
            return "❌ Uso: <code>/block &lt;tipo&gt; &lt;valor&gt;</code>\n\
                    Tipos válidos: <code>ip</code>, <code>user</code>, <code>process</code>\n\
                    Ejemplos:\n\
                    <code>/block ip 192.168.1.100</code>\n\
                    <code>/block user root</code>\n\
                    <code>/block process nmap</code>".to_string();
        }

        let entity_type = parts[1].to_lowercase();
        if !["ip", "user", "process"].contains(&entity_type.as_str()) {
            return "❌ Tipo inválido. Usa: <code>ip</code>, <code>user</code> o <code>process</code>.".to_string();
        }

        let entity_value = parts[2];
        let reason = parts.get(3).copied().unwrap_or("Bloqueado por DLP");

        match self.db.block_entity(&entity_type, entity_value, reason).await {
            Ok(msg) => {
                if entity_type == "ip" {
                    let _ = block_ip_iptables(entity_value);
                    format!("✅ {}\n\n🛡️ Regla de iptables aplicada: tráfico desde <code>{}</code> será bloqueado.", msg, entity_value)
                } else {
                    format!("✅ {}", msg)
                }
            }
            Err(e) => format!("❌ Error al bloquear: <code>{}</code>", e),
        }
    }

    async fn cmd_unblock(&self, arg: Option<&str>) -> String {
        let id: i64 = match arg.and_then(|s| s.parse().ok()) {
            Some(v) => v,
            None => return "❌ Uso: <code>/unblock &lt;ID&gt;</code>\nEjemplo: <code>/unblock 1</code>\n\nUsa /blocked para ver los IDs.".to_string(),
        };

        match self.db.unblock_entity(id).await {
            Ok(true) => format!("✅ Entidad <code>#{id}</code> desbloqueada.", id = id),
            Ok(false) => format!("❌ Entidad <code>#{id}</code> no encontrada. Usa /blocked para listar.", id = id),
            Err(e) => format!("❌ Error de BD al desbloquear: <code>{}</code>", e),
        }
    }

    async fn cmd_blocked(&self) -> String {
        let entities = match self.db.list_blocked().await {
            Ok(e) => e,
            Err(err) => return format!("❌ Error al consultar BD: <code>{}</code>", err),
        };

        if entities.is_empty() {
            return "✅ No hay entidades bloqueadas.".to_string();
        }

        let mut lines = vec!["🚫 <b>Entidades bloqueadas</b>".to_string()];
        for e in &entities {
            let icon = match e.entity_type.as_str() {
                "ip" => "🌐",
                "user" => "👤",
                "process" => "⚙️",
                _ => "❓",
            };
            let reason = e.reason.as_deref().unwrap_or("-");
            let by = e.blocked_by.as_deref().unwrap_or("-");
            let ts = e.created_at.format("%d/%m %H:%M").to_string();
            lines.push(format!(
                "{icon} <code>#{id}</code> <b>{type_}</b>: <code>{val}</code>\n└ Razón: {reason}\n└ Por: {by} | {ts}",
                icon = icon, id = e.id, type_ = e.entity_type, val = e.entity_value,
                reason = reason, by = by, ts = ts
            ));
        }
        lines.join("\n\n")
    }
}

fn extract_location(desc: &str) -> String {
    if let Some(idx) = desc.find(": ") {
        let loc = &desc[..idx];
        if loc.contains('/') || loc.contains('\\') {
            return loc.to_string();
        }
    }
    desc.to_string()
}

fn block_ip_iptables(ip: &str) -> Result<(), String> {
    let output = std::process::Command::new("iptables")
        .args(["-C", "INPUT", "-s", ip, "-j", "DROP"])
        .output()
        .map_err(|e| format!("iptables error: {}", e))?;

    if output.status.success() {
        return Ok(()); // rule already exists
    }

    let output = std::process::Command::new("iptables")
        .args(["-A", "INPUT", "-s", ip, "-j", "DROP"])
        .output()
        .map_err(|e| format!("iptables error: {}", e))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("iptables falló: {}", stderr))
    }
}
