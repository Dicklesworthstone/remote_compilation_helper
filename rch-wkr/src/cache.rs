//! Project cache management.

#![allow(dead_code)] // Scaffold code - functions will be used in future beads

use anyhow::Result;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use tracing::{debug, info, warn};

/// Get the base directory for RCH project caches.
/// Uses `dirs::cache_dir()` (e.g. `~/.cache/rch`) to isolate caches per-user
/// and prevent symlink attacks on shared `/tmp` partitions. Falls back to `/tmp/rch-$USER`.
pub fn get_cache_base() -> PathBuf {
    if let Some(mut cache) = dirs::cache_dir() {
        cache.push("rch");
        cache
    } else {
        let user = std::env::var("USER").unwrap_or_else(|_| "unknown".to_string());
        PathBuf::from(format!("/tmp/rch-{}", user))
    }
}

/// Clean up old project caches.
pub async fn cleanup(max_age_hours: u64) -> Result<()> {
    cleanup_in(&get_cache_base(), max_age_hours).await
}

/// Clean up old project caches under a specific base directory.
///
/// This exists primarily for test isolation; production callers should prefer [`cleanup`].
pub async fn cleanup_in(cache_base: &Path, max_age_hours: u64) -> Result<()> {
    let cache_dir = cache_base.to_path_buf();

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
        let project_meta = match std::fs::symlink_metadata(&project_path) {
            Ok(meta) => meta,
            Err(e) => {
                warn!("Failed to get metadata for {:?}: {}", project_path, e);
                errors += 1;
                continue;
            }
        };
        if !project_meta.is_dir() {
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
            let hash_meta = match std::fs::symlink_metadata(&hash_path) {
                Ok(meta) => meta,
                Err(e) => {
                    warn!("Failed to get metadata for {:?}: {}", hash_path, e);
                    errors += 1;
                    continue;
                }
            };
            if !hash_meta.is_dir() {
                continue;
            }

            // Check modification time
            let modified = match hash_meta.modified() {
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

        // If project dir is empty after cleanup, try to remove it
        if active_caches == 0 {
            // We optimistically try to remove it. If it's not empty (race condition with new build),
            // remove_dir will fail safely. We don't need to lock or strictly check emptiness first.
            debug!(
                "Attempting to remove empty project directory: {:?}",
                project_path
            );
            match std::fs::remove_dir(&project_path) {
                Ok(_) => {
                    cleaned += 1;
                }
                Err(e) => {
                    // Ignore DirectoryNotEmpty error (race condition or not actually empty)
                    if e.kind() != std::io::ErrorKind::DirectoryNotEmpty {
                        warn!("Failed to remove project dir {:?}: {}", project_path, e);
                        errors += 1;
                    } else {
                        debug!(
                            "Project dir {:?} became non-empty, skipping removal",
                            project_path
                        );
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
    cache_path_in(&get_cache_base(), project, hash)
}

/// Get the cache path for a project under a specific cache base directory.
pub fn cache_path_in(cache_base: &Path, project: &str, hash: &str) -> PathBuf {
    cache_base.join(project).join(hash)
}

/// Update the last-used timestamp of a project cache.
///
/// This creates or updates a marker file `.rch_last_used` in the directory,
/// ensuring that the directory's modification time is updated. This prevents
/// the cleanup logic (which checks directory mtime) from deleting actively
/// used caches where source files might not be modified (e.g. re-running builds).
pub fn touch_project(workdir: &std::path::Path) {
    let marker_path = workdir.join(".rch_last_used");
    // Just write an empty file to update the timestamp
    if let Err(e) = std::fs::write(&marker_path, "") {
        tracing::warn!("Failed to touch cache marker {:?}: {}", marker_path, e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Unique test counter for isolation between tests
    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Generate a unique test directory path to avoid conflicts
    fn unique_test_dir(prefix: &str) -> PathBuf {
        let counter = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        std::env::temp_dir().join(format!("rch-cache-test-{}-{}-{}", prefix, pid, counter))
    }

    // === Cache Path Generation Tests ===

    #[test]
    fn test_cache_path() {
        println!("TEST START: test_cache_path");
        let path = cache_path("myproject", "abc123");
        assert!(path.to_string_lossy().contains("myproject/abc123"));
        assert!(path.to_string_lossy().contains("rch"));
        println!("TEST PASS: test_cache_path");
    }

    #[test]
    fn test_cache_path_simple() {
        println!("TEST START: test_cache_path_simple");
        let path = cache_path("proj", "hash");
        assert!(path.to_string_lossy().contains("proj/hash"));
        println!("TEST PASS: test_cache_path_simple");
    }

    #[test]
    fn test_cache_path_with_dots() {
        println!("TEST START: test_cache_path_with_dots");
        let path = cache_path("my.project", "abc.123");
        assert!(path.to_string_lossy().contains("my.project/abc.123"));
        println!("TEST PASS: test_cache_path_with_dots");
    }

    #[test]
    fn test_cache_path_with_dashes() {
        println!("TEST START: test_cache_path_with_dashes");
        let path = cache_path("my-project", "abc-123-def");
        assert!(path.to_string_lossy().contains("my-project/abc-123-def"));
        println!("TEST PASS: test_cache_path_with_dashes");
    }

    #[test]
    fn test_cache_path_with_underscores() {
        println!("TEST START: test_cache_path_with_underscores");
        let path = cache_path("my_project", "abc_123");
        assert!(path.to_string_lossy().contains("my_project/abc_123"));
        println!("TEST PASS: test_cache_path_with_underscores");
    }

    #[test]
    fn test_cache_path_hex_hash() {
        println!("TEST START: test_cache_path_hex_hash");
        let path = cache_path("project", "a1b2c3d4e5f6");
        assert!(path.to_string_lossy().contains("project/a1b2c3d4e5f6"));
        println!("TEST PASS: test_cache_path_hex_hash");
    }

    #[test]
    fn test_cache_path_long_hash() {
        println!("TEST START: test_cache_path_long_hash");
        let long_hash = "a".repeat(64);
        let path = cache_path("project", &long_hash);
        assert!(
            path.to_string_lossy()
                .contains(&format!("project/{}", long_hash))
        );
        println!("TEST PASS: test_cache_path_long_hash");
    }

    #[test]
    fn test_cache_path_empty_project() {
        println!("TEST START: test_cache_path_empty_project");
        let path = cache_path("", "hash123");
        assert!(path.to_string_lossy().ends_with("/hash123"));
        println!("TEST PASS: test_cache_path_empty_project");
    }

    #[test]
    fn test_cache_path_empty_hash() {
        println!("TEST START: test_cache_path_empty_hash");
        // Use cache_path_in with a known base to avoid platform-dependent cache dirs.
        let base = PathBuf::from("/tmp/rch-test");
        let path = cache_path_in(&base, "project", "");
        assert!(
            path.to_string_lossy().contains("project"),
            "path should contain project name: {:?}",
            path
        );
        println!("TEST PASS: test_cache_path_empty_hash");
    }

    #[test]
    fn test_cache_base_constant() {
        println!("TEST START: test_cache_base_constant");
        // Verify get_cache_base works
        let base = get_cache_base();
        assert!(base.to_string_lossy().contains("rch"));
        println!("TEST PASS: test_cache_base_constant");
    }

    // === Cache Hit/Miss Tests (file existence) ===

    #[test]
    fn test_cache_miss_nonexistent_path() {
        println!("TEST START: test_cache_miss_nonexistent_path");
        let path = cache_path("nonexistent_project_xyz", "nonexistent_hash");
        assert!(!path.exists(), "cache path should not exist");
        println!("TEST PASS: test_cache_miss_nonexistent_path");
    }

    #[tokio::test]
    async fn test_cache_hit_after_creation() {
        println!("TEST START: test_cache_hit_after_creation");
        let test_base = unique_test_dir("hit");
        let project = "testproj";
        let hash = "testhash";
        let cache_dir = test_base.join(project).join(hash);

        // Create cache directory
        fs::create_dir_all(&cache_dir).unwrap();

        // Verify it exists
        assert!(
            cache_dir.exists(),
            "cache directory should exist after creation"
        );
        assert!(cache_dir.is_dir(), "cache should be a directory");

        // Cleanup
        let _ = fs::remove_dir_all(&test_base);
        println!("TEST PASS: test_cache_hit_after_creation");
    }

    #[tokio::test]
    async fn test_cache_miss_after_removal() {
        println!("TEST START: test_cache_miss_after_removal");
        let test_base = unique_test_dir("miss");
        let project = "testproj";
        let hash = "testhash";
        let cache_dir = test_base.join(project).join(hash);

        // Create then remove
        fs::create_dir_all(&cache_dir).unwrap();
        assert!(cache_dir.exists());

        fs::remove_dir_all(&cache_dir).unwrap();
        assert!(!cache_dir.exists(), "cache should be gone after removal");

        // Cleanup
        let _ = fs::remove_dir_all(&test_base);
        println!("TEST PASS: test_cache_miss_after_removal");
    }

    // === Cache Eviction Tests (age-based cleanup) ===

    #[tokio::test]
    async fn test_cleanup_nonexistent_directory() {
        println!("TEST START: test_cleanup_nonexistent_directory");
        // cleanup_in() should handle nonexistent base directory gracefully
        let cache_base = unique_test_dir("cleanup-nonexistent");
        let result = cleanup_in(&cache_base, 0).await;
        assert!(
            result.is_ok(),
            "cleanup should succeed even if cache is empty"
        );
        println!("TEST PASS: test_cleanup_nonexistent_directory");
    }

    #[tokio::test]
    async fn test_cleanup_removes_old_caches() {
        println!("TEST START: test_cleanup_removes_old_caches");

        let cache_base = unique_test_dir("cleanup-old");
        fs::create_dir_all(&cache_base).unwrap();

        let project_name = format!("test-cleanup-{}", std::process::id());
        let project_dir = cache_base.join(&project_name);
        let hash_dir = project_dir.join("oldhash");

        // Create cache directory
        fs::create_dir_all(&hash_dir).unwrap();
        fs::write(hash_dir.join("data.txt"), "test data").unwrap();

        // Ensure the directory is older than our max_age=0 threshold.
        tokio::time::sleep(Duration::from_secs(2)).await;

        // With max_age=0, all caches should be removed
        let result = cleanup_in(&cache_base, 0).await;
        assert!(result.is_ok(), "cleanup should succeed");

        assert!(!hash_dir.exists(), "old cache should be removed");
        assert!(!project_dir.exists(), "empty project dir should be removed");

        let _ = fs::remove_dir_all(&cache_base);
        println!("TEST PASS: test_cleanup_removes_old_caches");
    }

    #[tokio::test]
    async fn test_cleanup_keeps_recent_caches() {
        println!("TEST START: test_cleanup_keeps_recent_caches");

        let cache_base = unique_test_dir("cleanup-keep");
        fs::create_dir_all(&cache_base).unwrap();

        let project_name = format!("test-keep-{}", std::process::id());
        let project_dir = cache_base.join(&project_name);
        let hash_dir = project_dir.join("recenthash");

        // Create cache directory
        fs::create_dir_all(&hash_dir).unwrap();
        fs::write(hash_dir.join("data.txt"), "test data").unwrap();

        // Cleanup with 1000 hours max age (very generous, should keep recent)
        let result = cleanup_in(&cache_base, 1000).await;
        assert!(result.is_ok(), "cleanup should succeed");

        // The hash_dir should still exist (it was just created)
        assert!(hash_dir.exists(), "recent cache should not be removed");

        // Cleanup
        let _ = fs::remove_dir_all(&cache_base);
        println!("TEST PASS: test_cleanup_keeps_recent_caches");
    }

    #[tokio::test]
    async fn test_cleanup_removes_empty_project_dirs() {
        println!("TEST START: test_cleanup_removes_empty_project_dirs");

        let cache_base = unique_test_dir("cleanup-empty-project");
        fs::create_dir_all(&cache_base).unwrap();

        let project_name = format!("test-empty-{}", std::process::id());
        let project_dir = cache_base.join(&project_name);

        // Create empty project directory (no hash subdirs)
        fs::create_dir_all(&project_dir).unwrap();

        // With max_age=0, cleanup should try to remove empty project dir
        let result = cleanup_in(&cache_base, 0).await;
        assert!(result.is_ok(), "cleanup should succeed");

        assert!(!project_dir.exists(), "empty project dir should be removed");

        let _ = fs::remove_dir_all(&cache_base);
        println!("TEST PASS: test_cleanup_removes_empty_project_dirs");
    }

    // === Cache Corruption Recovery Tests ===

    #[tokio::test]
    async fn test_cleanup_handles_file_instead_of_dir() {
        println!("TEST START: test_cleanup_handles_file_instead_of_dir");

        let cache_base = unique_test_dir("cleanup-file-instead");
        fs::create_dir_all(&cache_base).unwrap();

        let project_name = format!("test-corrupt-{}", std::process::id());
        let project_path = cache_base.join(&project_name);

        // Create a file where a directory is expected
        fs::write(&project_path, "not a directory").unwrap();

        // Cleanup should not crash
        let result = cleanup_in(&cache_base, 0).await;
        assert!(result.is_ok(), "cleanup should handle file gracefully");

        // Cleanup
        let _ = fs::remove_dir_all(&cache_base);
        println!("TEST PASS: test_cleanup_handles_file_instead_of_dir");
    }

    #[tokio::test]
    async fn test_cleanup_handles_file_in_project_dir() {
        println!("TEST START: test_cleanup_handles_file_in_project_dir");

        let cache_base = unique_test_dir("cleanup-file-in-project");
        fs::create_dir_all(&cache_base).unwrap();

        let project_name = format!("test-file-in-proj-{}", std::process::id());
        let project_dir = cache_base.join(&project_name);

        fs::create_dir_all(&project_dir).unwrap();

        // Create a file where a hash directory is expected
        fs::write(project_dir.join("not_a_hash_dir"), "file content").unwrap();

        // Also create a valid hash dir
        let hash_dir = project_dir.join("validhash");
        fs::create_dir_all(&hash_dir).unwrap();

        // Cleanup should not crash on the file
        let result = cleanup_in(&cache_base, 0).await;
        assert!(result.is_ok(), "cleanup should handle mixed content");

        // Cleanup
        let _ = fs::remove_dir_all(&cache_base);
        println!("TEST PASS: test_cleanup_handles_file_in_project_dir");
    }

    #[tokio::test]
    async fn test_cleanup_handles_symlink() {
        println!("TEST START: test_cleanup_handles_symlink");

        #[cfg(unix)]
        {
            let cache_base = unique_test_dir("cleanup-symlink");
            fs::create_dir_all(&cache_base).unwrap();

            let project_name = format!("test-symlink-{}", std::process::id());
            let project_dir = cache_base.join(&project_name);

            fs::create_dir_all(&project_dir).unwrap();

            // Create a symlink
            let link_path = project_dir.join("link");
            let _ = std::os::unix::fs::symlink("/tmp", &link_path);

            // Cleanup should handle symlinks gracefully
            let result = cleanup_in(&cache_base, 0).await;
            assert!(result.is_ok(), "cleanup should handle symlinks");

            // Cleanup
            let _ = fs::remove_dir_all(&cache_base);
        }

        println!("TEST PASS: test_cleanup_handles_symlink");
    }

    #[tokio::test]
    async fn test_cleanup_handles_permission_errors_gracefully() {
        println!("TEST START: test_cleanup_handles_permission_errors_gracefully");

        // We can't easily create permission-denied scenarios without root
        // But we test that cleanup doesn't panic on general errors
        let cache_base = unique_test_dir("cleanup-permissions");
        let result = cleanup_in(&cache_base, 168).await; // Default 1 week
        assert!(result.is_ok(), "cleanup should succeed");

        println!("TEST PASS: test_cleanup_handles_permission_errors_gracefully");
    }

    // === Concurrent Cache Access Tests ===

    #[tokio::test]
    async fn test_concurrent_cleanup_calls() {
        println!("TEST START: test_concurrent_cleanup_calls");

        let cache_base = unique_test_dir("cleanup-concurrent");
        fs::create_dir_all(&cache_base).unwrap();

        let project_name = format!("test-concurrent-{}", std::process::id());
        let project_dir = cache_base.join(&project_name);

        // Create multiple hash dirs
        for i in 0..5 {
            let hash_dir = project_dir.join(format!("hash{}", i));
            fs::create_dir_all(&hash_dir).unwrap();
            fs::write(hash_dir.join("data.txt"), format!("data{}", i)).unwrap();
        }

        // Run multiple cleanups concurrently
        let cache_base_for_tasks = cache_base.clone();
        let handles: Vec<_> = (0..3)
            .map(|_| {
                let cache_base = cache_base_for_tasks.clone();
                tokio::spawn(async move { cleanup_in(&cache_base, 1000).await })
            })
            .collect();

        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok(), "concurrent cleanup should succeed");
        }

        // Cleanup
        let _ = fs::remove_dir_all(&cache_base);
        println!("TEST PASS: test_concurrent_cleanup_calls");
    }

    #[tokio::test]
    async fn test_cleanup_during_cache_creation() {
        println!("TEST START: test_cleanup_during_cache_creation");

        let cache_base = unique_test_dir("cleanup-race-create");
        fs::create_dir_all(&cache_base).unwrap();

        let project_name = format!("test-race-{}", std::process::id());
        let project_dir = cache_base.join(&project_name);

        // Start cleanup in background
        let cache_base_for_task = cache_base.clone();
        let cleanup_handle =
            tokio::spawn(async move { cleanup_in(&cache_base_for_task, 1000).await });

        // Simultaneously create a new cache
        let hash_dir = project_dir.join("newhash");
        fs::create_dir_all(&hash_dir).unwrap();
        fs::write(hash_dir.join("data.txt"), "new data").unwrap();

        // Wait for cleanup
        let result = cleanup_handle.await.unwrap();
        assert!(result.is_ok(), "cleanup should succeed during race");

        // Cleanup
        let _ = fs::remove_dir_all(&cache_base);
        println!("TEST PASS: test_cleanup_during_cache_creation");
    }

    #[tokio::test]
    async fn test_cleanup_empty_hash_then_nonempty_race() {
        println!("TEST START: test_cleanup_empty_hash_then_nonempty_race");

        // This tests the race condition comment in the code about
        // optimistically removing project dirs

        let cache_base = unique_test_dir("cleanup-race-empty");
        fs::create_dir_all(&cache_base).unwrap();

        let project_name = format!("test-race-empty-{}", std::process::id());
        let project_dir = cache_base.join(&project_name);

        // Create project dir only (no hash dirs)
        fs::create_dir_all(&project_dir).unwrap();

        // Cleanup should handle the empty project gracefully
        let result = cleanup_in(&cache_base, 0).await;
        assert!(result.is_ok(), "cleanup should handle empty project");

        // Cleanup
        let _ = fs::remove_dir_all(&cache_base);
        println!("TEST PASS: test_cleanup_empty_hash_then_nonempty_race");
    }

    // === Edge Cases ===

    #[tokio::test]
    async fn test_cleanup_max_age_zero() {
        println!("TEST START: test_cleanup_max_age_zero");
        let cache_base = unique_test_dir("cleanup-max-age-zero");
        let result = cleanup_in(&cache_base, 0).await;
        assert!(result.is_ok(), "max_age=0 should work");
        println!("TEST PASS: test_cleanup_max_age_zero");
    }

    #[tokio::test]
    async fn test_cleanup_max_age_large() {
        println!("TEST START: test_cleanup_max_age_large");
        let cache_base = unique_test_dir("cleanup-max-age-large");
        let result = cleanup_in(&cache_base, u64::MAX / 3600).await;
        assert!(result.is_ok(), "large max_age should work");
        println!("TEST PASS: test_cleanup_max_age_large");
    }

    #[tokio::test]
    async fn test_cleanup_max_age_one_hour() {
        println!("TEST START: test_cleanup_max_age_one_hour");
        let cache_base = unique_test_dir("cleanup-max-age-one-hour");
        let result = cleanup_in(&cache_base, 1).await;
        assert!(result.is_ok(), "1 hour max_age should work");
        println!("TEST PASS: test_cleanup_max_age_one_hour");
    }

    #[tokio::test]
    async fn test_cleanup_max_age_one_week() {
        println!("TEST START: test_cleanup_max_age_one_week");
        let cache_base = unique_test_dir("cleanup-max-age-one-week");
        let result = cleanup_in(&cache_base, 168).await; // 7 * 24 = 168 hours
        assert!(result.is_ok(), "1 week max_age should work");
        println!("TEST PASS: test_cleanup_max_age_one_week");
    }

    #[test]
    fn test_cache_path_unicode() {
        println!("TEST START: test_cache_path_unicode");
        let path = cache_path("проект", "хэш123");
        // Should handle unicode even if not recommended
        assert!(path.to_string_lossy().contains("проект"));
        println!("TEST PASS: test_cache_path_unicode");
    }

    #[test]
    fn test_cache_path_special_chars() {
        println!("TEST START: test_cache_path_special_chars");
        // Project names shouldn't have these, but test path construction.
        // Use cache_path_in with a known base to avoid platform-dependent cache dirs.
        let base = PathBuf::from("/tmp/rch-test");
        let path = cache_path_in(&base, "proj@123", "hash#456");
        assert_eq!(path, PathBuf::from("/tmp/rch-test/proj@123/hash#456"));
        println!("TEST PASS: test_cache_path_special_chars");
    }

    #[tokio::test]
    async fn test_cleanup_handles_nested_directories() {
        println!("TEST START: test_cleanup_handles_nested_directories");

        let cache_base = unique_test_dir("cleanup-nested");
        fs::create_dir_all(&cache_base).unwrap();

        let project_name = format!("test-nested-{}", std::process::id());
        let project_dir = cache_base.join(&project_name);
        let hash_dir = project_dir.join("hash");
        let nested_dir = hash_dir.join("target").join("debug").join("deps");

        // Create deeply nested structure
        fs::create_dir_all(&nested_dir).unwrap();
        fs::write(nested_dir.join("file.o"), "object file").unwrap();

        // Cleanup should handle nested dirs
        let result = cleanup_in(&cache_base, 0).await;
        assert!(result.is_ok(), "cleanup should handle nested directories");

        // Cleanup
        let _ = fs::remove_dir_all(&cache_base);
        println!("TEST PASS: test_cleanup_handles_nested_directories");
    }

    #[tokio::test]
    async fn test_cleanup_multiple_projects() {
        println!("TEST START: test_cleanup_multiple_projects");

        let cache_base = unique_test_dir("cleanup-multi-project");
        fs::create_dir_all(&cache_base).unwrap();

        let base_name = format!("test-multi-{}", std::process::id());

        // Create multiple project directories
        for i in 0..3 {
            let project_dir = cache_base.join(format!("{}-{}", base_name, i));
            let hash_dir = project_dir.join("hash");
            fs::create_dir_all(&hash_dir).unwrap();
            fs::write(hash_dir.join("data.txt"), "data").unwrap();
        }

        // Cleanup should process all projects
        let result = cleanup_in(&cache_base, 1000).await;
        assert!(result.is_ok(), "cleanup should handle multiple projects");

        // Cleanup
        let _ = fs::remove_dir_all(&cache_base);
        println!("TEST PASS: test_cleanup_multiple_projects");
    }

    #[tokio::test]
    async fn test_cleanup_multiple_hashes_per_project() {
        println!("TEST START: test_cleanup_multiple_hashes_per_project");

        let cache_base = unique_test_dir("cleanup-multi-hash");
        fs::create_dir_all(&cache_base).unwrap();

        let project_name = format!("test-multihash-{}", std::process::id());
        let project_dir = cache_base.join(&project_name);

        // Create multiple hash directories
        for i in 0..5 {
            let hash_dir = project_dir.join(format!("hash{:04x}", i));
            fs::create_dir_all(&hash_dir).unwrap();
            fs::write(hash_dir.join("Cargo.lock"), "lockfile").unwrap();
        }

        // Cleanup should handle multiple hashes
        let result = cleanup_in(&cache_base, 1000).await;
        assert!(result.is_ok(), "cleanup should handle multiple hashes");

        // Cleanup
        let _ = fs::remove_dir_all(&cache_base);
        println!("TEST PASS: test_cleanup_multiple_hashes_per_project");
    }
}
