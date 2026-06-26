use std::process::Command;

#[derive(Debug)]
pub struct YaraMatch {
    pub rule: String,
    pub severity: String,
}

pub struct YaraScanner;

impl YaraScanner {
    pub fn new(rules_path: &str) -> Option<Self> {
        if !std::path::Path::new(rules_path).exists() {
            tracing::warn!("YARA rules file not found: {}", rules_path);
            return None;
        }
        Some(Self)
    }

    pub fn scan_file(&self, path: &str) -> Vec<YaraMatch> {
        let rules_path = "/etc/dlp/yara_rules.yar";
        if !std::path::Path::new(rules_path).exists() {
            return vec![];
        }

        let output = match Command::new("yara")
            .args([rules_path, path])
            .output()
        {
            Ok(o) => o,
            Err(_) => return vec![],
        };

        if !output.status.success() {
            return vec![];
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut matches = Vec::new();

        for line in stdout.lines() {
            let parts: Vec<&str> = line.splitn(2, ' ').collect();
            if parts.len() == 2 {
                matches.push(YaraMatch {
                    rule: parts[0].to_string(),
                    severity: "high".to_string(),
                });
            }
        }

        matches
    }
}
