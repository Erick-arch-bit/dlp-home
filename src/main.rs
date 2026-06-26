mod config;
mod dashboard;
mod db;
mod monitor;
mod notifications;
mod proc_monitor;
mod proxy;
mod scanner;
mod yara_scanner;
mod archiver;
mod reporter;
mod telegram_bot;
mod quarantine;
mod integrity;
mod syslog;

use clap::Parser;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Parser)]
#[command(name = "dlp-home", version, about = "DLP Home - Data Loss Prevention System")]
struct Args {
    #[arg(long, default_value = "false")]
    scan: bool,

    #[arg(long, default_value = "false")]
    daemon: bool,

    #[arg(long, default_value_t = 9090)]
    port: u16,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "dlp_home=info".into()),
        )
        .json()
        .init();

    let args = Args::parse();
    let cfg = config::Config::load();

    let db = match db::Database::connect(&cfg.database.url, cfg.database.max_connections).await {
        Ok(db) => {
            tracing::info!("Connected to database");
            Arc::new(db)
        }
        Err(e) => {
            tracing::error!("Database connection failed: {}", e);
            return;
        }
    };

    let mut s = scanner::Scanner::new();
    s.compile();
    let scanner = Arc::new(Mutex::new(s));

    let notifier = Arc::new(notifications::Notifier::new());

    if args.scan {
        let monitor = monitor::FileMonitor::new(db.clone(), scanner.clone(), notifier.clone());
        tracing::info!("Running one-time scan of watched directories...");
        monitor.scan_all(&cfg.monitor.watch_dirs).await;
        tracing::info!("Scan complete.");
        return;
    }

    if args.daemon {
        tracing::info!("Starting DLP daemon...");

        quarantine::Quarantine::init().await;

        let n1 = notifier.clone();
        let n2 = notifier.clone();
        let n3 = notifier.clone();
        let n4 = notifier.clone();

        let db_m = db.clone();
        let scanner_m = scanner.clone();
        let watch_dirs = cfg.monitor.watch_dirs.clone();
        tokio::spawn(async move {
            let monitor = monitor::FileMonitor::new(db_m, scanner_m, n1);
            monitor.run(watch_dirs).await;
        });

        let db_p = db.clone();
        let interval = cfg.monitor.process_interval_secs;
        tokio::spawn(async move {
            let pmon = proc_monitor::ProcMonitor::new(db_p, n2);
            pmon.run(interval).await;
        });

        if cfg.proxy.enabled {
            let db_pr = db.clone();
            let scanner_pr = scanner.clone();
            let bind = cfg.proxy.bind.clone();
            let port = cfg.proxy.port;
            tokio::spawn(async move {
                let proxy = proxy::DlpProxy::new(db_pr, scanner_pr, n3, bind, port);
                proxy.run().await;
            });
        }

        if let Some(bot) = telegram_bot::TelegramBot::new(db.clone()) {
            tokio::spawn(async move {
                bot.run().await;
            });
        }

        let app = dashboard::router(db.clone(), scanner.clone(), n4);
        let addr = format!("{}:{}", cfg.dashboard.bind, cfg.dashboard.port);
        let listener = tokio::net::TcpListener::bind(&addr).await;

        match listener {
            Ok(l) => {
                tracing::info!("Dashboard listening on http://{}", addr);
                axum::serve(l, app).await.unwrap_or_else(|e| {
                    tracing::error!("Server error: {}", e);
                });
            }
            Err(e) => {
                tracing::error!("Cannot bind to {}: {}", addr, e);
            }
        }
    } else {
        let port = args.port;
        let app = dashboard::router(db, scanner, notifier);
        let addr = format!("0.0.0.0:{}", port);
        let listener = tokio::net::TcpListener::bind(&addr).await;

        match listener {
            Ok(l) => {
                tracing::info!("Dashboard only mode on http://{}", addr);
                axum::serve(l, app).await.unwrap_or_else(|e| {
                    tracing::error!("Server error: {}", e);
                });
            }
            Err(e) => {
                tracing::error!("Cannot bind to {}: {}", addr, e);
            }
        }
    }
}
