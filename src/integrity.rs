use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct IntegrityMonitor {
    cache: Arc<Mutex<HashMap<String, String>>>,
}

impl IntegrityMonitor {
    pub fn new() -> Self {
        Self { cache: Arc::new(Mutex::new(HashMap::new())) }
    }

    pub async fn check_file(&self, path: &Path) -> Option<String> {
        let content = match std::fs::read(path) {
            Ok(c) => c,
            Err(_) => return None,
        };
        let hash = hex::encode(Sha256::digest(&content));
        let path_str = path.to_string_lossy().to_string();
        let mut cache = self.cache.lock().await;

        if let Some(old) = cache.get(&path_str) {
            if *old != hash {
                cache.insert(path_str.clone(), hash);
                return Some("modified".to_string());
            }
        } else {
            cache.insert(path_str, hash);
        }
        None
    }

    pub async fn clear(&self) {
        self.cache.lock().await.clear();
    }

    pub fn cache_count(&self) -> usize {
        self.cache.blocking_lock().len()
    }
}
