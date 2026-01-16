//! Project cache management.

use anyhow::Result;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use tracing::{debug, info, warn};

/// Base directory for RCH project caches.
const CACHE_BASE: &str = "/tmp/rch";

/// Clean up old project caches.
pub async fn cleanup(max_age_hours: u64) -> Result<()> {
    let cache_dir = PathBuf::from(CACHE_BASE);

    if !cache_dir.exists() {
        info!("Cache directory does not exist, nothing to clean");
        return Ok(());
    }

    let max_age = Duration::from_secs(max_age_hours * 3600);
    let now = SystemTime::now();
    let mut cleaned = 0;
    let mut errors = 0;

    for entry in std::fs::read_dir(&cache_dir)? {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                warn!("Failed to read directory entry: {}", e);
                errors += 1;
                continue;
            }
        };

        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        // Check modification time
        let metadata = match std::fs::metadata(&path) {
            Ok(m) => m,
            Err(e) => {
                warn!("Failed to get metadata for {:?}: {}", path, e);
                errors += 1;
                continue;
            }
        };

        let modified = match metadata.modified() {
            Ok(t) => t,
            Err(e) => {
                warn!("Failed to get modified time for {:?}: {}", path, e);
                errors += 1;
                continue;
            }
        };

        let age = match now.duration_since(modified) {
            Ok(d) => d,
            Err(_) => continue, // Modified in future, skip
        };

        if age > max_age {
            debug!("Removing old cache: {:?} (age: {:?})", path, age);
            if let Err(e) = std::fs::remove_dir_all(&path) {
                warn!("Failed to remove {:?}: {}", path, e);
                errors += 1;
            } else {
                cleaned += 1;
            }
        }
    }

    info!(
        "Cleanup complete: {} directories removed, {} errors",
        cleaned, errors
    );
    Ok(())
}

/// Get the cache path for a project.
pub fn cache_path(project: &str, hash: &str) -> PathBuf {
    PathBuf::from(CACHE_BASE).join(format!("{}_{}", project, hash))
}

/// Compute a hash for a project directory.
pub fn compute_project_hash(project_path: &str) -> String {
    // Use blake3 for fast hashing
    let mut hasher = blake3::Hasher::new();
    hasher.update(project_path.as_bytes());
    hasher.finalize().to_hex()[..12].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_path() {
        let path = cache_path("myproject", "abc123");
        assert!(path.to_string_lossy().contains("myproject_abc123"));
    }

    #[test]
    fn test_compute_hash() {
        let hash1 = compute_project_hash("/path/to/project");
        let hash2 = compute_project_hash("/path/to/project");
        assert_eq!(hash1, hash2);

        let hash3 = compute_project_hash("/different/path");
        assert_ne!(hash1, hash3);
    }
}
