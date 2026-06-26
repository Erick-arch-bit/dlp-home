use crate::db::Database;
use crate::notifications::Notifier;
use crate::scanner::Scanner;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Json},
    routing::{delete, get, post},
    Router,
};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Database>,
    pub scanner: Arc<Mutex<Scanner>>,
    pub notifier: Arc<Notifier>,
    pub ws_clients: Arc<Mutex<Vec<tokio::sync::mpsc::UnboundedSender<String>>>>,
}

#[derive(Deserialize)]
pub struct AlertsQuery {
    limit: Option<i64>,
    offset: Option<i64>,
    severity: Option<String>,
    category: Option<String>,
    source: Option<String>,
    resolved: Option<bool>,
}

#[derive(Deserialize)]
pub struct SetConfigBody {
    key: String,
    value: String,
}

#[derive(Serialize)]
pub struct ConfigEntry {
    key: String,
    value: String,
}

pub fn router(db: Arc<Database>, scanner: Arc<Mutex<Scanner>>, notifier: Arc<Notifier>) -> Router {
    let ws_clients: Arc<Mutex<Vec<tokio::sync::mpsc::UnboundedSender<String>>>> =
        Arc::new(Mutex::new(Vec::new()));

    let state = AppState {
        db,
        scanner,
        notifier,
        ws_clients,
    };

    Router::new()
        .route("/", get(dashboard_page))
        .route("/login", get(login_page))
        .route("/api/login", get(api_login))
        .route("/api/summary", get(summary))
        .route("/api/alerts", get(alerts))
        .route("/api/events", get(events))
        .route("/api/logs", get(logs))
        .route("/api/config", get(get_config).post(set_config))
        .route("/api/test-telegram", post(test_telegram))
        .route("/api/export/csv", get(export_csv))
        .route("/api/report/weekly", post(weekly_report))
        .route("/api/alerts/resolve", post(resolve_alert))
        .route("/api/blocked", get(list_blocked).post(block_entity))
        .route("/api/blocked/{id}", delete(unblock_entity))
        .route("/api/command", post(run_command))
        .route("/api/trends", get(trends))
        .route("/api/patterns", get(patterns_list))
        .route("/api/bank/gen", post(bank_generate))
        .route("/ws", get(ws_handler))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn dashboard_page() -> impl IntoResponse {
    Html(include_str!("../static/index.html"))
}

async fn login_page() -> impl IntoResponse {
    Html(include_str!("../static/login.html"))
}

fn check_auth(headers: &HeaderMap) -> bool {
    let token = std::env::var("DLP_DASHBOARD_TOKEN").unwrap_or_default();
    if token.is_empty() {
        return false;
    }

    if let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if auth == format!("Bearer {}", token) {
            return true;
        }
        if let Some(base64) = auth.strip_prefix("Basic ") {
            use base64::Engine;
            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(base64) {
                if let Ok(creds) = String::from_utf8(decoded) {
                    let parts: Vec<&str> = creds.splitn(2, ':').collect();
                    if parts.len() == 2 && parts[1] == token {
                        return true;
                    }
                }
            }
        }
    }

    if let Some(cookie) = headers.get("cookie").and_then(|v| v.to_str().ok()) {
        if cookie.contains(&format!("token={}", token)) {
            return true;
        }
    }

    false
}

async fn api_login(Query(q): Query<std::collections::HashMap<String, String>>) -> impl IntoResponse {
    let token = std::env::var("DLP_DASHBOARD_TOKEN").unwrap_or_default();
    if token.is_empty() {
        return Json(serde_json::json!({ "token": "" }));
    }
    let input_token = q.get("token").map(|s| s.as_str()).unwrap_or("");
    if input_token == token {
        Json(serde_json::json!({ "token": token, "success": true }))
    } else {
        Json(serde_json::json!({ "success": false, "error": "Invalid token" }))
    }
}

async fn summary(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<serde_json::Value>, StatusCode> {
    if !check_auth(&headers) { return Err(StatusCode::UNAUTHORIZED); }
    match state.db.get_alert_summary().await {
        Ok(s) => Ok(Json(serde_json::to_value(s).unwrap_or_default())),
        Err(e) => { tracing::error!("Summary error: {}", e); Err(StatusCode::INTERNAL_SERVER_ERROR) }
    }
}

async fn alerts(State(state): State<AppState>, headers: HeaderMap, Query(q): Query<AlertsQuery>) -> Result<Json<serde_json::Value>, StatusCode> {
    if !check_auth(&headers) { return Err(StatusCode::UNAUTHORIZED); }
    let limit = q.limit.unwrap_or(50).min(200);
    let offset = q.offset.unwrap_or(0);
    match state.db.get_alerts(limit, offset, q.severity.as_deref(), q.category.as_deref(), q.source.as_deref(), q.resolved).await {
        Ok(data) => Ok(Json(serde_json::json!({ "data": data, "limit": limit, "offset": offset }))),
        Err(e) => { tracing::error!("Alerts error: {}", e); Err(StatusCode::INTERNAL_SERVER_ERROR) }
    }
}

async fn events(State(state): State<AppState>, headers: HeaderMap, Query(q): Query<AlertsQuery>) -> Result<Json<serde_json::Value>, StatusCode> {
    if !check_auth(&headers) { return Err(StatusCode::UNAUTHORIZED); }
    let limit = q.limit.unwrap_or(50).min(200);
    let offset = q.offset.unwrap_or(0);
    #[derive(sqlx::FromRow, serde::Serialize)]
    struct Event { id: i64, timestamp: chrono::DateTime<chrono::Utc>, event_type: String, source: String, detail: String, data: Option<serde_json::Value> }
    match sqlx::query_as::<_, Event>("SELECT id, timestamp, event_type, source, detail, data FROM events ORDER BY timestamp DESC LIMIT $1 OFFSET $2")
        .bind(limit).bind(offset).fetch_all(state.db.pool()).await {
        Ok(data) => Ok(Json(serde_json::json!({ "data": data, "limit": limit, "offset": offset }))),
        Err(e) => { tracing::error!("Events error: {}", e); Err(StatusCode::INTERNAL_SERVER_ERROR) }
    }
}

async fn logs(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<serde_json::Value>, StatusCode> {
    if !check_auth(&headers) { return Err(StatusCode::UNAUTHORIZED); }
    #[derive(sqlx::FromRow, serde::Serialize)]
    struct LogEntry {
        timestamp: chrono::DateTime<chrono::Utc>,
        #[sqlx(rename = "event_type")]
        log_type: String,
        source: String,
        detail: String,
    }
    let entries: Vec<LogEntry> = match sqlx::query_as::<_, LogEntry>(
        "SELECT timestamp, event_type, source, detail FROM events ORDER BY timestamp DESC LIMIT 50"
    ).fetch_all(state.db.pool()).await {
        Ok(d) => d,
        Err(e) => { tracing::error!("Logs error: {}", e); return Err(StatusCode::INTERNAL_SERVER_ERROR); }
    };
    Ok(Json(serde_json::json!(entries)))
}

async fn get_config(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<serde_json::Value>, StatusCode> {
    if !check_auth(&headers) { return Err(StatusCode::UNAUTHORIZED); }
    match state.db.get_all_config().await {
        Ok(map) => {
            let entries: Vec<ConfigEntry> = map.into_iter().map(|(k, v)| ConfigEntry { key: k, value: v }).collect();
            Ok(Json(serde_json::json!(entries)))
        }
        Err(e) => { tracing::error!("Config error: {}", e); Err(StatusCode::INTERNAL_SERVER_ERROR) }
    }
}

async fn set_config(State(state): State<AppState>, headers: HeaderMap, axum::Json(body): axum::Json<SetConfigBody>) -> Result<Json<serde_json::Value>, StatusCode> {
    if !check_auth(&headers) { return Err(StatusCode::UNAUTHORIZED); }
    match state.db.set_config(&body.key, &body.value).await {
        Ok(_) => Ok(Json(serde_json::json!({ "success": true }))),
        Err(e) => { tracing::error!("Set config error: {}", e); Err(StatusCode::INTERNAL_SERVER_ERROR) }
    }
}

async fn test_telegram(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<serde_json::Value>, StatusCode> {
    if !check_auth(&headers) { return Err(StatusCode::UNAUTHORIZED); }
    state.notifier.send_alert("high", "test", "Prueba de Telegram DLP - si recibes esto funciona").await;
    Ok(Json(serde_json::json!({ "success": true })))
}

async fn export_csv(State(state): State<AppState>, headers: HeaderMap) -> Result<axum::response::Response, StatusCode> {
    if !check_auth(&headers) { return Err(StatusCode::UNAUTHORIZED); }
    match crate::reporter::export_csv(state.db.clone()).await {
        Ok(csv) => {
            let headers = [("Content-Type", "text/csv; charset=utf-8"), ("Content-Disposition", "attachment; filename=dlp_alerts.csv")];
            Ok((headers, csv).into_response())
        }
        Err(e) => { tracing::error!("CSV export error: {}", e); Err(StatusCode::INTERNAL_SERVER_ERROR) }
    }
}

async fn weekly_report(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<serde_json::Value>, StatusCode> {
    if !check_auth(&headers) { return Err(StatusCode::UNAUTHORIZED); }
    match crate::reporter::generate_weekly_report(state.db.clone()).await {
        Ok(report) => Ok(Json(serde_json::json!(report))),
        Err(e) => { tracing::error!("Weekly report error: {}", e); Err(StatusCode::INTERNAL_SERVER_ERROR) }
    }
}

#[derive(Deserialize)]
struct ResolveBody { id: i64 }

async fn resolve_alert(State(state): State<AppState>, headers: HeaderMap, axum::Json(body): axum::Json<ResolveBody>) -> Result<Json<serde_json::Value>, StatusCode> {
    if !check_auth(&headers) { return Err(StatusCode::UNAUTHORIZED); }
    match state.db.resolve_alert(body.id).await {
        Ok(true) => Ok(Json(serde_json::json!({ "success": true }))),
        Ok(false) => Ok(Json(serde_json::json!({ "success": false, "error": "Alerta no encontrada" }))),
        Err(e) => { tracing::error!("Resolve error: {}", e); Err(StatusCode::INTERNAL_SERVER_ERROR) }
    }
}

async fn list_blocked(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<serde_json::Value>, StatusCode> {
    if !check_auth(&headers) { return Err(StatusCode::UNAUTHORIZED); }
    match state.db.list_blocked().await {
        Ok(data) => Ok(Json(serde_json::json!(data))),
        Err(e) => { tracing::error!("List blocked error: {}", e); Err(StatusCode::INTERNAL_SERVER_ERROR) }
    }
}

#[derive(Deserialize)]
struct BlockBody { entity_type: String, entity_value: String, reason: Option<String> }

async fn block_entity(State(state): State<AppState>, headers: HeaderMap, axum::Json(body): axum::Json<BlockBody>) -> Result<Json<serde_json::Value>, StatusCode> {
    if !check_auth(&headers) { return Err(StatusCode::UNAUTHORIZED); }
    let reason = body.reason.as_deref().unwrap_or("Blocked via dashboard");
    match state.db.block_entity(&body.entity_type, &body.entity_value, reason).await {
        Ok(msg) => Ok(Json(serde_json::json!({ "success": true, "message": msg }))),
        Err(e) => { tracing::error!("Block entity error: {}", e); Err(StatusCode::INTERNAL_SERVER_ERROR) }
    }
}

async fn unblock_entity(State(state): State<AppState>, headers: HeaderMap, Path(id): Path<i64>) -> Result<Json<serde_json::Value>, StatusCode> {
    if !check_auth(&headers) { return Err(StatusCode::UNAUTHORIZED); }
    match state.db.unblock_entity(id).await {
        Ok(true) => Ok(Json(serde_json::json!({ "success": true }))),
        Ok(false) => Ok(Json(serde_json::json!({ "success": false, "error": "Entidad no encontrada" }))),
        Err(e) => { tracing::error!("Unblock entity error: {}", e); Err(StatusCode::INTERNAL_SERVER_ERROR) }
    }
}

#[derive(Deserialize)]
struct CommandBody { cmd: String }

async fn run_command(State(_state): State<AppState>, headers: HeaderMap, axum::Json(body): axum::Json<CommandBody>) -> Result<Json<serde_json::Value>, StatusCode> {
    if !check_auth(&headers) { return Err(StatusCode::UNAUTHORIZED); }
    let cmd = body.cmd.trim().to_string();
    if cmd.is_empty() {
        return Ok(Json(serde_json::json!({ "output": "", "error": "comando vacío" })));
    }
    let blocked_prefixes = ["rm -rf /", "mkfs", "dd if=", ":(){ :|:& };:", "chmod -R 000", "mv /", "> /dev/sda"];
    for prefix in &blocked_prefixes {
        if cmd.starts_with(prefix) {
            return Ok(Json(serde_json::json!({ "output": "", "error": "comando bloqueado por seguridad" })));
        }
    }
    let shell = if cfg!(target_os = "windows") { "cmd" } else { "/bin/sh" };
    let flag = if cfg!(target_os = "windows") { "/C" } else { "-c" };
    match std::process::Command::new(shell).arg(flag).arg(&cmd).output() {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            let exit_code = out.status.code().unwrap_or(-1);
            Ok(Json(serde_json::json!({
                "output": stdout + &stderr,
                "exit_code": exit_code
            })))
        }
        Err(e) => Ok(Json(serde_json::json!({ "output": "", "error": e.to_string() }))),
    }
}

async fn trends(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<serde_json::Value>, StatusCode> {
    if !check_auth(&headers) { return Err(StatusCode::UNAUTHORIZED); }
    let days = 30;
    let daily = state.db.get_daily_trends(days).await.unwrap_or_default();
    let by_severity = state.db.get_severity_trends(days).await.unwrap_or_default();
    let top_sources = state.db.get_top_sources(days).await.unwrap_or_default();
    Ok(Json(serde_json::json!({ "daily": daily, "by_severity": by_severity, "top_sources": top_sources })))
}

async fn patterns_list(State(state): State<AppState>, headers: HeaderMap) -> Result<Json<serde_json::Value>, StatusCode> {
    if !check_auth(&headers) { return Err(StatusCode::UNAUTHORIZED); }
    let patterns = state.scanner.lock().await.patterns().to_vec();
    Ok(Json(serde_json::json!(patterns)))
}

#[derive(Deserialize)]
struct BankGenBody {
    count: Option<usize>,
    action: String,
}

async fn bank_generate(State(_state): State<AppState>, headers: HeaderMap, axum::Json(body): axum::Json<BankGenBody>) -> Result<Json<serde_json::Value>, StatusCode> {
    if !check_auth(&headers) { return Err(StatusCode::UNAUTHORIZED); }
    let count = body.count.unwrap_or(3).min(20);
    let ts = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
    let dir = "/home/lab";
    let mut files = Vec::new();

    let cards = vec![
        "4111 1111 1111 1111", "5500 0000 0000 0004", "3400 0000 0000 009",
        "6011 0000 0000 0004", "4000 0560 0000 1016", "5105 1051 0510 5100",
        "3714 4963 5398 431", "6222 0000 0000 0005", "4532 0186 3166 6005",
        "4716 4214 2318 9401",
    ];
    let curps = vec![
        "HEGG560427MVZRRL04", "MAGD740315HDFLNS09", "ROHJ850620HNECRD07",
        "VACA920813MMNLRR02", "PEGA780501HGTNND06",
    ];
    let rfcs = vec![
        "HEGG560427MZR", "MAGD740315H51", "ROHJ850620H65", "VACA920813H58",
    ];

    match body.action.as_str() {
        "estado_cuenta" => {
            for i in 0..count {
                let filename = format!("{}/estado_cuenta_{}_{}.txt", dir, ts, i);
                let card = cards[i % cards.len()];
                let curp = curps[i % curps.len()];
                let rfc = rfcs[i % rfcs.len()];
                let balance = (1000 + i * 500) as f64;
                let content = format!(
                    "=== ESTADO DE CUENTA BANCARIO ===\n\
                     Fecha: {}\n\
                     Cliente: Cliente-{}\n\
                     CURP: {}\n\
                     RFC: {}\n\
                     Tarjeta: {}\n\
                     Saldo: ${:.2}\n\
                     CLABE: {}\n\
                     \n--- MOVIMIENTOS ---\n",
                    chrono::Utc::now().format("%Y-%m-%d"),
                    i + 1000,
                    curp, rfc, card, balance,
                    format!("{:018}", 123456789012345678u64 + i as u64)
                );
                let mut movs = String::new();
                for m in 0..5 {
                    let monto = 50.0 + (i * 37 + m * 113) as f64 % 5000.0;
                    let desc = match m % 3 {
                        0 => "COMPRA EN LINEA",
                        1 => "RETIRO CAJERO",
                        _ => "TRANSFERENCIA",
                    };
                    movs.push_str(&format!("  {} | ${:.2} | {}\n", chrono::Utc::now().format("%d/%m"), monto, desc));
                }
                let full = content + &movs;
                std::fs::write(&filename, &full).ok();
                files.push(filename);
            }
        }
        _ => {
            for i in 0..count {
                let filename = format!("{}/datos_bancarios_{}_{}.txt", dir, ts, i);
                let card = cards[i % cards.len()];
                let content = format!(
                    "[BANCO SIMULACION]\n\
                     Titular: Usuario-{}\n\
                     Numero Tarjeta: {}\n\
                     CVV: {:03}\n\
                     Vencimiento: {}/{}\n\
                     NSS: {}-{:02}-{:04}\n\
                     Telefono: 55{}",
                    i + 1000, card,
                    i * 37 % 1000,
                    (i % 12) + 1, 2026 + (i % 5),
                    (100 + i) % 999, i % 99, i * 37 % 10000,
                    10000000 + i * 123456 % 100000000
                );
                std::fs::write(&filename, &content).ok();
                files.push(filename);
            }
        }
    }

    Ok(Json(serde_json::json!({ "files": files, "count": files.len() })))
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> axum::response::Response {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

async fn handle_ws(mut ws: WebSocket, state: AppState) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    {
        let mut clients = state.ws_clients.lock().await;
        clients.push(tx);
    }
    loop {
        tokio::select! {
            Some(msg) = rx.recv() => { if ws.send(Message::Text(msg.into())).await.is_err() { break; } }
            Some(Ok(msg)) = ws.recv() => { if let Message::Close(_) = msg { break; } }
            else => break,
        }
    }
}

pub async fn broadcast_alert(state: &AppState, alert_json: &str) {
    let mut clients = state.ws_clients.lock().await;
    clients.retain(|tx| tx.send(alert_json.to_string()).is_ok());
}
