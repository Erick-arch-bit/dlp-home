use crate::db::Database;
use crate::notifications::Notifier;
use crate::scanner::Scanner;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

pub struct DlpProxy {
    db: Arc<Database>,
    scanner: Arc<Mutex<Scanner>>,
    notifier: Arc<Notifier>,
    bind: String,
    port: u16,
}

impl DlpProxy {
    pub fn new(
        db: Arc<Database>,
        scanner: Arc<Mutex<Scanner>>,
        notifier: Arc<Notifier>,
        bind: String,
        port: u16,
    ) -> Self {
        Self { db, scanner, notifier, bind, port }
    }

    pub async fn run(&self) {
        let addr = format!("{}:{}", self.bind, self.port);
        let listener = match TcpListener::bind(&addr).await {
            Ok(l) => {
                tracing::info!("DLP Proxy listening on {}", addr);
                l
            }
            Err(e) => {
                tracing::error!("Cannot bind proxy to {}: {}", addr, e);
                return;
            }
        };

        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Accept error: {}", e);
                    continue;
                }
            };

            let db = self.db.clone();
            let scanner = self.scanner.clone();
            let notifier = self.notifier.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_client(stream, peer, db, scanner, notifier).await {
                    tracing::debug!("Proxy client {}: {}", peer, e);
                }
            });
        }
    }
}

async fn handle_client(
    mut client: TcpStream,
    peer: std::net::SocketAddr,
    db: Arc<Database>,
    scanner: Arc<Mutex<Scanner>>,
    notifier: Arc<Notifier>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = [0u8; 8192];
    let n = client.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf[..n]);

    if request.starts_with("CONNECT ") {
        return handle_connect(client, peer, &request, db, notifier).await;
    }

    let first_line = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Ok(());
    }

    let method = parts[0];
    let url = parts[1];

    let host = extract_host(&request);
    let body_start = request.find("\r\n\r\n").map(|i| i + 4).unwrap_or(n);
    let body = &buf[body_start..n];

    let scanner_guard = scanner.lock().await;
    let matches = scanner_guard.scan_bytes(body);
    drop(scanner_guard);

    if !matches.is_empty() {
        let has_critical = matches.iter().any(|m| m.severity == "critical");
        let has_high = matches.iter().any(|m| m.severity == "high");

        for m in &matches {
            let desc = format!(
                "Proxy {} {} -> [{}] {} (L:{})",
                method, url, m.severity, m.description, m.line
            );
            tracing::warn!("{}", desc);
            let _ = db.insert_alert(&m.severity, &m.pattern_name, "http_proxy", &desc, Some(&m.context)).await;
            notifier.send_alert(&m.severity, &m.pattern_name, &desc).await;
        }

        if has_critical || has_high {
            let _ = client
                .write_all(
                    b"HTTP/1.1 403 Blocked\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nBLOCKED BY DLP: Sensitive data detected in request\n",
                )
                .await;
            return Ok(());
        }
    }

    let _ = db
        .insert_event(
            "http_request",
            "http_proxy",
            &format!("{} {} ({} bytes)", method, url, body.len()),
            None,
        )
        .await;

    let mut remote = tokio::net::TcpStream::connect(format!("{}:80", host)).await?;

    let host_header = format!("Host: {}\r\n", host);
    let modified_request = if !request.contains("Host:") {
        format!("{}{}", request, host_header)
    } else {
        request.to_string()
    };

    let mut remaining = vec![0u8; 0];
    if body_start < n {
        remaining = buf[body_start..n].to_vec();
    }

    remote.write_all(modified_request.as_bytes()).await?;
    if !remaining.is_empty() {
        remote.write_all(&remaining).await?;
    }

    tokio::io::copy(&mut remote, &mut client).await?;
    Ok(())
}

async fn handle_connect(
    mut client: TcpStream,
    peer: std::net::SocketAddr,
    request: &str,
    db: Arc<Database>,
    _notifier: Arc<Notifier>,
) -> Result<(), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = request.split_whitespace().collect();
    let target = parts.get(1).unwrap_or(&"unknown");
    let desc = format!("CONNECT {} from {}", target, peer);
    let _ = db
        .insert_event("https_tunnel", "http_proxy", &desc, None)
        .await;
    tracing::info!("HTTPS tunnel: {} -> {}", peer, target);

    let target_parts: Vec<&str> = target.splitn(2, ':').collect();
    let host = target_parts.get(0).unwrap_or(&"");
    let port = target_parts.get(1).unwrap_or(&"443");
    let addr = format!("{}:{}", host, port);

    match tokio::net::TcpStream::connect(&addr).await {
        Ok(mut remote) => {
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            let (mut cr, mut cw) = client.split();
            let (mut rr, mut rw) = remote.split();
            let c_to_r = tokio::io::copy(&mut cr, &mut rw);
            let r_to_c = tokio::io::copy(&mut rr, &mut cw);
            tokio::join!(c_to_r, r_to_c);
        }
        Err(e) => {
            let _ = client
                .write_all(
                    format!(
                        "HTTP/1.1 502 Bad Gateway\r\n\r\nCannot connect to {}: {}\n",
                        target, e
                    )
                    .as_bytes(),
                )
                .await;
        }
    }
    Ok(())
}

fn extract_host(request: &str) -> &str {
    for line in request.lines() {
        if line.to_lowercase().starts_with("host:") {
            let host = line[5..].trim();
            if let Some(pos) = host.find(':') {
                return &host[..pos];
            }
            return host;
        }
    }
    "localhost"
}
