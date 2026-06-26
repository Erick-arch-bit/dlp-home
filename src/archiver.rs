use crate::scanner::ScanMatch;
use std::io::Read;
use std::path::Path;

pub struct ArchiveScanner;

impl ArchiveScanner {
    pub fn is_archive(path: &Path) -> bool {
        let ext = path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        matches!(ext, "zip" | "tar" | "gz" | "tgz" | "bz2" | "xz" | "7z" | "rar")
    }

    pub fn scan(path: &Path, scanner: &crate::scanner::Scanner) -> Vec<(String, Vec<ScanMatch>)> {
        let ext = path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        match ext {
            "zip" => Self::scan_zip(path, scanner),
            "tar" | "gz" | "tgz" | "bz2" | "xz" => Self::scan_tar(path, scanner),
            _ => {
                tracing::warn!("Unsupported archive format: {}", ext);
                vec![]
            }
        }
    }

    fn scan_zip(path: &Path, scanner: &crate::scanner::Scanner) -> Vec<(String, Vec<ScanMatch>)> {
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(_) => return vec![],
        };

        let mut archive = match zip::ZipArchive::new(file) {
            Ok(a) => a,
            Err(_) => return vec![],
        };

        let mut results = Vec::new();

        for i in 0..archive.len() {
            let mut entry = match archive.by_index(i) {
                Ok(e) => e,
                Err(_) => continue,
            };

            let name = entry.name().to_string();

            if entry.size() > 10_000_000 {
                continue;
            }

            let mut content = Vec::new();
            if entry.read_to_end(&mut content).is_err() || content.is_empty() {
                continue;
            }

            let matches = scanner.scan_bytes(&content);
            if !matches.is_empty() {
                results.push((name, matches));
            }
        }

        results
    }

    fn scan_tar(path: &Path, scanner: &crate::scanner::Scanner) -> Vec<(String, Vec<ScanMatch>)> {
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(_) => return vec![],
        };

        let archive: Box<dyn Read> = match path.extension().and_then(|e| e.to_str()) {
            Some("gz") | Some("tgz") => {
                Box::new(flate2::read::GzDecoder::new(file))
            }
            _ => Box::new(file),
        };

        let mut tar = tar::Archive::new(archive);
        let mut results = Vec::new();

        if let Ok(entries) = tar.entries() {
            for mut entry in entries.flatten() {
                let name = entry.path().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
                let size = entry.size();

                if size > 10_000_000 {
                    continue;
                }

                let mut content = Vec::new();
                if entry.read_to_end(&mut content).is_err() || content.is_empty() {
                    continue;
                }

                let matches = scanner.scan_bytes(&content);
                if !matches.is_empty() {
                    results.push((name, matches));
                }
            }
        }

        results
    }
}
