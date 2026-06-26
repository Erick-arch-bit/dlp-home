use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub database: DatabaseConfig,
    pub dashboard: DashboardConfig,
    pub monitor: MonitorConfig,
    pub scanner: ScannerConfig,
    pub proxy: ProxyConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    pub bind: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorConfig {
    pub watch_dirs: Vec<String>,
    pub watch_interval_secs: u64,
    pub process_interval_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    pub patterns_file: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub enabled: bool,
    pub bind: String,
    pub port: u16,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            database: DatabaseConfig {
                url: "postgres://dlp:dlp_security_2026@localhost:5432/dlp".into(),
                max_connections: 5,
            },
            dashboard: DashboardConfig {
                bind: "0.0.0.0".into(),
                port: 9090,
            },
            monitor: MonitorConfig {
                watch_dirs: vec!["/home/lab".into(), "/tmp".into()],
                watch_interval_secs: 5,
                process_interval_secs: 10,
            },
            scanner: ScannerConfig {
                patterns_file: PathBuf::from("/etc/dlp/patterns.toml"),
            },
            proxy: ProxyConfig {
                enabled: false,
                bind: "0.0.0.0".into(),
                port: 8080,
            },
        }
    }
}

impl Config {
    pub fn load() -> Self {
        let config_paths = [
            "/etc/dlp/config.toml",
            "dlp.toml",
            "config.toml",
        ];

        for path in &config_paths {
            if let Ok(content) = std::fs::read_to_string(path) {
                if let Ok(config) = toml::from_str(&content) {
                    tracing::info!("Loaded config from {}", path);
                    return config;
                }
            }
        }

        tracing::info!("Using default config");
        Config::default()
    }
}
