use crate::archiver::ArchiveScanner;
use crate::db::Database;
use crate::integrity::IntegrityMonitor;
use crate::notifications::Notifier;
use crate::quarantine::Quarantine;
use crate::scanner::Scanner;
use crate::yara_scanner::YaraScanner;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc;
use walkdir::WalkDir;

pub struct FileMonitor {
    db: Arc<Database>,
    scanner: Arc<tokio::sync::Mutex<Scanner>>,
    yara: Option<YaraScanner>,
    notifier: Arc<Notifier>,
    integrity: IntegrityMonitor,
}

impl FileMonitor {
    pub fn new(db: Arc<Database>, scanner: Arc<tokio::sync::Mutex<Scanner>>, notifier: Arc<Notifier>) -> Self {
        let yara = YaraScanner::new("/etc/dlp/yara_rules.yar");
        Self { db, scanner, yara, notifier, integrity: IntegrityMonitor::new() }
    }

    pub async fn run(&self, watch_dirs: Vec<String>) {
        let (tx, mut rx) = mpsc::channel::<notify::Result<Event>>(256);

        let mut watcher = match RecommendedWatcher::new(
            move |res| {
                let _ = tx.blocking_send(res);
            },
            Config::default(),
        ) {
            Ok(w) => w,
            Err(e) => {
                tracing::error!("Failed to create watcher: {}", e);
                return;
            }
        };

        for dir in &watch_dirs {
            if Path::new(dir).exists() {
                if let Err(e) = watcher.watch(Path::new(dir), RecursiveMode::Recursive) {
                    tracing::warn!("Cannot watch {}: {}", dir, e);
                } else {
                    tracing::info!("Watching directory: {}", dir);
                }
            } else {
                tracing::warn!("Watch directory does not exist: {}", dir);
            }
        }

        while let Some(Ok(event)) = rx.recv().await {
            match event.kind {
                EventKind::Create(_) | EventKind::Modify(_) => {
                    for path in event.paths {
                        if path.is_file() {
                            self.scan_file(&path).await;
                        }
                    }
                }
                _ => {}
            }
        }
    }

    pub async fn scan_file(&self, path: &Path) {
        let path_str = path.to_string_lossy().to_string();

        let metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return,
        };

        if metadata.len() > 10_000_000 {
            return;
        }

        let ext = path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        let skip_ext = ["so", "dll", "dylib", "o", "class", "pyc", "pyd"];
        if skip_ext.contains(&ext) {
            return;
        }

        let mut all_matches: Vec<crate::scanner::ScanMatch> = vec![];

        // YARA scan
        if let Some(ref yara) = self.yara {
            let yara_matches = yara.scan_file(&path_str);
            for m in &yara_matches {
                all_matches.push(crate::scanner::ScanMatch {
                    pattern_name: format!("yara/{}", m.rule),
                    description: format!("YARA rule: {}", m.rule),
                    severity: m.severity.clone(),
                    line: 0,
                    context: String::new(),
                });
            }

            if !yara_matches.is_empty() {
                tracing::info!("YARA match in {}: {:?}", path_str, yara_matches);
            }
        }

        // Archive scan
        if ArchiveScanner::is_archive(path) {
            let scanner = self.scanner.lock().await;
            let archive_matches = ArchiveScanner::scan(path, &scanner);
            if !archive_matches.is_empty() {
                for (entry_name, matches) in &archive_matches {
                    for m in matches {
                        let desc = format!("{} -> {}: {} (L:{})", path_str, entry_name, m.description, m.line);
                        tracing::warn!("{}", desc);
                        let _ = self.db.insert_alert(&m.severity, &m.pattern_name, "archive_scan", &desc, Some(&m.context)).await;
                        self.notifier.send_alert(&m.severity, &m.pattern_name, &desc).await;
                        all_matches.push(crate::scanner::ScanMatch {
                            pattern_name: m.pattern_name.clone(),
                            description: format!("{}[{}]", m.description, entry_name),
                            severity: m.severity.clone(),
                            line: m.line,
                            context: m.context.clone(),
                        });
                    }
                }
            }
            drop(scanner);
            return;
        }

        let content = match std::fs::read(path) {
            Ok(c) => c,
            Err(_) => return,
        };

        if content.is_empty() {
            return;
        }

        let scanner = self.scanner.lock().await;
        let matches = scanner.scan_bytes(&content);

        if !matches.is_empty() {
            for m in &matches {
                let desc = format!("{}: {} (L:{})", path_str, m.description, m.line);
                let _ = self.db.insert_alert(&m.severity, &m.pattern_name, "file_monitor", &desc, Some(&m.context)).await;
                self.notifier.send_alert(&m.severity, &m.pattern_name, &desc).await;
                all_matches.push(crate::scanner::ScanMatch {
                    pattern_name: m.pattern_name.clone(),
                    description: m.description.clone(),
                    severity: m.severity.clone(),
                    line: m.line,
                    context: m.context.clone(),
                });
            }
        }

        if !all_matches.is_empty() {
            let descriptions: Vec<String> = all_matches.iter().map(|m| format!("[{}] {}", m.severity, m.description)).collect();
            let _ = self.db.insert_file_scan(&path_str, metadata.len() as i64, all_matches.len() as i32, &descriptions.join("; ")).await;

            // quarantine critical matches
            let has_critical = all_matches.iter().any(|m| m.severity == "critical");
            if has_critical {
                let _ = Quarantine::quarantine(path, "critical").await;
                tracing::warn!("Quarantined critical file: {}", path_str);
            }
        }

        // integrity check
        if let Some(status) = self.integrity.check_file(path).await {
            tracing::info!("File integrity changed: {} ({})", path_str, status);
        }

        let _ = self.db.insert_event("file_access", "file_monitor", &format!("Scanned: {} ({} bytes)", path_str, metadata.len()), None).await;
    }

    pub async fn scan_all(&self, dirs: &[String]) {
        for dir in dirs {
            if !Path::new(dir).exists() {
                continue;
            }

            for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
                if entry.file_type().is_file() {
                    self.scan_file(entry.path()).await;
                }
            }
        }
    }
}
