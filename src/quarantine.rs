use std::path::Path;
use tokio::fs;

const QUARANTINE_DIR: &str = "/var/dlp/quarantine";

pub struct Quarantine;

impl Quarantine {
    pub async fn init() {
        fs::create_dir_all(QUARANTINE_DIR).await.ok();
    }

    pub async fn quarantine(path: &Path, reason: &str) -> Result<String, String> {
        let filename = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        let ts = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let dest_name = format!("{}_{}_{}", ts, filename, reason.chars().take(20).collect::<String>().replace(|c: char| !c.is_alphanumeric(), "_"));
        let dest = Path::new(QUARANTINE_DIR).join(&dest_name);

        match fs::copy(path, &dest).await {
            Ok(_) => {
                tracing::info!("Quarantined: {} -> {:?}", path.display(), dest);
                Ok(dest.to_string_lossy().to_string())
            }
            Err(e) => Err(format!("quarantine copy error: {}", e)),
        }
    }

    pub async fn quarantine_and_remove(path: &Path, reason: &str) -> Result<String, String> {
        let result = Self::quarantine(path, reason).await?;
        fs::remove_file(path).await.ok();
        Ok(result)
    }
}
