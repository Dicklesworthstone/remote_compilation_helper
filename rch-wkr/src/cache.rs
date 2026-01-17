//! Project cache management.

#![allow(dead_code)] // Scaffold code - functions will be used in future beads

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

    // Level 1: Project directories
    let project_entries = match std::fs::read_dir(&cache_dir) {
        Ok(entries) => entries,
        Err(e) => {
            warn!("Failed to read cache directory: {}", e);
            return Ok(());
        }
    };

    for project_entry in project_entries {
        let project_entry = match project_entry {
            Ok(e) => e,
            Err(e) => {
                warn!("Failed to read directory entry: {}", e);
                errors += 1;
                continue;
            }
        };

        let project_path = project_entry.path();
        if !project_path.is_dir() {
            continue;
        }

        // Level 2: Hash directories
        let hash_entries = match std::fs::read_dir(&project_path) {
            Ok(entries) => entries,
            Err(e) => {
                warn!("Failed to read project directory {:?}: {}", project_path, e);
                errors += 1;
                continue;
            }
        };

        let mut active_caches = 0;

        for hash_entry in hash_entries {
            let hash_entry = match hash_entry {
                Ok(e) => e,
                Err(e) => {
                    warn!("Failed to read hash entry: {}", e);
                    errors += 1;
                    continue;
                }
            };

            let hash_path = hash_entry.path();
            if !hash_path.is_dir() {
                continue;
            }

            // Check modification time
            let metadata = match std::fs::metadata(&hash_path) {
                Ok(m) => m,
                Err(e) => {
                    warn!("Failed to get metadata for {:?}: {}", hash_path, e);
                    errors += 1;
                    continue;
                }
            };

            let modified = match metadata.modified() {
                Ok(t) => t,
                Err(e) => {
                    warn!("Failed to get modified time for {:?}: {}", hash_path, e);
                    errors += 1;
                    continue;
                }
            };

            let age = match now.duration_since(modified) {
                Ok(d) => d,
                Err(_) => continue, // Modified in future, skip
            };

            if age > max_age {
                debug!("Removing old cache: {:?} (age: {:?})", hash_path, age);
                if let Err(e) = std::fs::remove_dir_all(&hash_path) {
                    warn!("Failed to remove {:?}: {}", hash_path, e);
                    errors += 1;
                } else {
                    cleaned += 1;
                }
            } else {
                active_caches += 1;
            }
        }

        // If project dir is empty after cleanup, remove it
        if active_caches == 0 {
            // Re-check directory emptiness to be safe
            if let Ok(mut read_dir) = std::fs::read_dir(&project_path) {
                if read_dir.next().is_none() {
                    debug!("Removing empty project directory: {:?}", project_path);
                    if let Err(e) = std::fs::remove_dir(&project_path) {
                        warn!(
                            "Failed to remove empty project dir {:?}: {}",
                            project_path, e
                        );
                        errors += 1;
                    }
                }
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
    PathBuf::from(CACHE_BASE).join(project).join(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_path() {
        let path = cache_path("myproject", "abc123");
        assert_eq!(path, PathBuf::from("/tmp/rch/myproject/abc123"));
    }
}
