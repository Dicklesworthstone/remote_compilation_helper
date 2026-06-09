//! Local staging-tree garbage collection for `rch cache clean` (bd-s3433).
//!
//! rch rsyncs each project into a per-project staging tree under the configured
//! `transfer.remote_base` (default `/tmp/rch`, often `/tmp/rch-sync` on a fleet
//! worker): `<remote_base>/<project_id>/<project_hash>`. Nothing pruned these,
//! so on a busy multi-agent host they accumulate to tens of GB — the largest
//! `/tmp` consumer and a disk-full risk mid-swarm.
//!
//! This adds a sanctioned GC: enumerate the staging trees, then a **pure**
//! [`plan_staging_gc`] decides which to prune by age while never touching a
//! tree that was modified inside the in-flight window (the same freshness guard
//! the remote reaper uses, so an active build's tree is protected). The
//! `rch cache clean` command reports the plan and, unless `--dry-run`, removes
//! the prunable trees — each path re-validated with
//! [`rch_common::stale_target_reap::is_safe_reap_path`] before any `remove`.
//!
//! Default is **dry-run**: a bare `rch cache clean` never deletes.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;

/// One enumerated staging tree.
#[derive(Debug, Clone)]
pub struct StagingTree {
    pub path: PathBuf,
    /// Total bytes under the tree.
    pub size_bytes: u64,
    /// Age of the most recently modified file in the tree (`now - newest_mtime`).
    pub age: Duration,
}

/// GC policy.
#[derive(Debug, Clone, Copy)]
pub struct StagingGcPolicy {
    /// Only prune trees whose newest file is older than this. Doubles as the
    /// in-flight guard: an active build touches files continuously, so its tree
    /// stays younger than any sane `min_age`.
    pub min_age: Duration,
}

/// What the planner decided for one tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GcAction {
    /// Old enough and safe — prune.
    Prune,
    /// Modified within `min_age` — kept (possibly in-flight).
    KeepRecent,
    /// Path failed the safe-reap validation — kept, never touched.
    KeepUnsafePath,
}

/// Per-tree plan entry.
#[derive(Debug, Clone, Serialize)]
pub struct StagingGcEntry {
    pub path: String,
    pub size_bytes: u64,
    pub age_secs: u64,
    pub action: GcAction,
    pub reason: String,
}

/// The full GC plan.
#[derive(Debug, Clone, Serialize)]
pub struct StagingGcPlan {
    pub entries: Vec<StagingGcEntry>,
    /// Bytes that would be reclaimed by pruning the `Prune` entries.
    pub prunable_bytes: u64,
    /// Number of trees that would be pruned.
    pub prunable_count: usize,
    /// Total bytes across all enumerated trees.
    pub total_bytes: u64,
}

/// Whether `path` is safe to prune: structurally a safe reap path AND strictly
/// under the staging `base` root. The base-containment check is defense in
/// depth — `is_safe_reap_path` accepts any deep absolute path (e.g.
/// `/etc/passwd`), so on its own it does not prove the path is staging.
fn is_prunable_path(path: &str, base: &Path) -> bool {
    let candidate = Path::new(path);
    candidate.starts_with(base)
        && candidate != base
        && rch_common::stale_target_reap::is_safe_reap_path(path)
}

/// Decide, per tree, whether to prune — pure, no filesystem access.
///
/// A tree is pruned iff it is under the staging `base`, is a safe reap path,
/// AND its newest file is older than `policy.min_age` (the in-flight guard).
#[must_use]
pub fn plan_staging_gc(
    trees: &[StagingTree],
    policy: StagingGcPolicy,
    base: &Path,
) -> StagingGcPlan {
    let mut entries = Vec::with_capacity(trees.len());
    let mut prunable_bytes = 0u64;
    let mut prunable_count = 0usize;
    let mut total_bytes = 0u64;

    for tree in trees {
        total_bytes = total_bytes.saturating_add(tree.size_bytes);
        let path_str = tree.path.to_string_lossy().to_string();
        let (action, reason) = if !is_prunable_path(&path_str, base) {
            (
                GcAction::KeepUnsafePath,
                "path is not a safe reap path under the staging root".to_string(),
            )
        } else if tree.age < policy.min_age {
            (
                GcAction::KeepRecent,
                format!(
                    "modified {}s ago (< {}s min-age); may be in-flight",
                    tree.age.as_secs(),
                    policy.min_age.as_secs()
                ),
            )
        } else {
            prunable_bytes = prunable_bytes.saturating_add(tree.size_bytes);
            prunable_count += 1;
            (
                GcAction::Prune,
                format!("idle {}s (>= min-age)", tree.age.as_secs()),
            )
        };
        entries.push(StagingGcEntry {
            path: path_str,
            size_bytes: tree.size_bytes,
            age_secs: tree.age.as_secs(),
            action,
            reason,
        });
    }

    StagingGcPlan {
        entries,
        prunable_bytes,
        prunable_count,
        total_bytes,
    }
}

/// Enumerate the staging trees under `remote_base`, optionally restricted to a
/// single `project` (the `<project_id>` directory name). Each
/// `<remote_base>/<project_id>/<project_hash>` directory is one tree.
///
/// `now` is injected so callers (and tests) control the clock; ages are derived
/// from the newest mtime found while sizing the tree.
pub fn enumerate_staging_trees(
    remote_base: &Path,
    project: Option<&str>,
    now: std::time::SystemTime,
) -> std::io::Result<Vec<StagingTree>> {
    let mut trees = Vec::new();
    if !remote_base.is_dir() {
        return Ok(trees);
    }
    for project_entry in std::fs::read_dir(remote_base)? {
        let project_entry = match project_entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        if !project_entry.path().is_dir() {
            continue;
        }
        if let Some(filter) = project
            && project_entry.file_name().to_string_lossy() != filter
        {
            continue;
        }
        // Each <project_id>/<project_hash> dir is a tree.
        let hash_dirs = match std::fs::read_dir(project_entry.path()) {
            Ok(rd) => rd,
            Err(_) => continue,
        };
        for hash_entry in hash_dirs {
            let Ok(hash_entry) = hash_entry else { continue };
            let tree_path = hash_entry.path();
            if !tree_path.is_dir() {
                continue;
            }
            let (size_bytes, newest) = tree_size_and_newest_mtime(&tree_path);
            let age = newest
                .and_then(|m| now.duration_since(m).ok())
                .unwrap_or(Duration::ZERO);
            trees.push(StagingTree {
                path: tree_path,
                size_bytes,
                age,
            });
        }
    }
    Ok(trees)
}

/// Parse a human duration like `30m`, `24h`, `7d`, `90s` (or a bare number =
/// seconds) into a [`Duration`]. Used for `--older`.
pub fn parse_human_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".to_string());
    }
    let (num, unit_secs): (&str, u64) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        Some('d') => (&s[..s.len() - 1], 86_400),
        Some(c) if c.is_ascii_digit() => (s, 1),
        _ => return Err(format!("invalid duration unit in '{s}' (use s/m/h/d)")),
    };
    let value: u64 = num
        .trim()
        .parse()
        .map_err(|_| format!("invalid duration number in '{s}'"))?;
    Ok(Duration::from_secs(value.saturating_mul(unit_secs)))
}

/// Format a byte count as a short human string (binary units).
#[must_use]
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Outcome of executing a GC plan.
#[derive(Debug, Clone, Default, Serialize)]
pub struct StagingGcOutcome {
    pub removed_count: usize,
    pub removed_bytes: u64,
    pub failed: Vec<String>,
}

/// Remove the `Prune` entries of a plan. Each path is **re-validated** with
/// [`is_prunable_path`] (safe reap path AND under `base`) immediately before
/// removal as a final guard, so a plan can never drive a `remove_dir_all` on an
/// unsafe or out-of-tree path. Returns counts; per-path failures are collected,
/// not fatal.
pub fn execute_staging_gc(plan: &StagingGcPlan, base: &Path) -> StagingGcOutcome {
    let mut outcome = StagingGcOutcome::default();
    for entry in &plan.entries {
        if entry.action != GcAction::Prune {
            continue;
        }
        // Final defensive re-validation right before the destructive call.
        if !is_prunable_path(&entry.path, base) {
            outcome.failed.push(entry.path.clone());
            continue;
        }
        match std::fs::remove_dir_all(&entry.path) {
            Ok(()) => {
                outcome.removed_count += 1;
                outcome.removed_bytes = outcome.removed_bytes.saturating_add(entry.size_bytes);
            }
            Err(_) => outcome.failed.push(entry.path.clone()),
        }
    }
    outcome
}

/// Recursively sum file sizes and find the newest mtime under `root`.
/// Best-effort: unreadable entries are skipped.
fn tree_size_and_newest_mtime(root: &Path) -> (u64, Option<std::time::SystemTime>) {
    let mut total = 0u64;
    let mut newest: Option<std::time::SystemTime> = None;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if let Ok(mtime) = meta.modified() {
                newest = Some(match newest {
                    Some(cur) if cur >= mtime => cur,
                    _ => mtime,
                });
            }
            if meta.is_dir() {
                stack.push(entry.path());
            } else {
                total = total.saturating_add(meta.len());
            }
        }
    }
    (total, newest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    fn tree(path: &str, size_bytes: u64, age_secs: u64) -> StagingTree {
        StagingTree {
            path: PathBuf::from(path),
            size_bytes,
            age: Duration::from_secs(age_secs),
        }
    }

    fn policy(min_age_secs: u64) -> StagingGcPolicy {
        StagingGcPolicy {
            min_age: Duration::from_secs(min_age_secs),
        }
    }

    fn base() -> &'static Path {
        Path::new("/tmp/rch")
    }

    #[test]
    fn prunes_old_trees_and_keeps_recent_ones() {
        let trees = vec![
            tree("/tmp/rch/proj/oldhash", 80 * 1024 * 1024 * 1024, 6 * 3600),
            tree("/tmp/rch/proj/freshhash", 1024, 60),
        ];
        let plan = plan_staging_gc(&trees, policy(3600), base());
        assert_eq!(plan.prunable_count, 1);
        assert_eq!(plan.prunable_bytes, 80 * 1024 * 1024 * 1024);
        assert_eq!(plan.total_bytes, 80 * 1024 * 1024 * 1024 + 1024);
        let old = plan
            .entries
            .iter()
            .find(|e| e.path.contains("oldhash"))
            .unwrap();
        assert_eq!(old.action, GcAction::Prune);
        let fresh = plan
            .entries
            .iter()
            .find(|e| e.path.contains("freshhash"))
            .unwrap();
        // The freshness/in-flight guard protects the recent tree.
        assert_eq!(fresh.action, GcAction::KeepRecent);
    }

    #[test]
    fn at_exactly_min_age_is_prunable() {
        let plan = plan_staging_gc(&[tree("/tmp/rch/p/h", 10, 3600)], policy(3600), base());
        assert_eq!(plan.entries[0].action, GcAction::Prune);
    }

    #[test]
    fn refuses_paths_outside_base_or_unsafe() {
        // Outside the staging root (even structurally-safe ones like
        // /etc/passwd), too-shallow, the base itself, and relative paths must
        // never be pruned — regardless of age.
        for bad in ["/", "/tmp", "/etc/passwd", "/tmp/rch", "relative/path"] {
            let plan = plan_staging_gc(&[tree(bad, 999, 999_999)], policy(60), base());
            assert_eq!(
                plan.entries[0].action,
                GcAction::KeepUnsafePath,
                "must refuse non-staging path {bad}"
            );
            assert_eq!(
                plan.prunable_count, 0,
                "non-staging path must not be prunable"
            );
        }
    }

    #[test]
    fn empty_pool_is_a_noop_plan() {
        let plan = plan_staging_gc(&[], policy(60), base());
        assert_eq!(plan.prunable_count, 0);
        assert_eq!(plan.prunable_bytes, 0);
        assert_eq!(plan.total_bytes, 0);
        assert!(plan.entries.is_empty());
    }

    #[test]
    fn enumerate_reads_two_level_layout_and_sizes_trees() {
        let base = tempfile::tempdir().expect("tempdir");
        // <base>/proj-a/hash1/{file}, <base>/proj-a/hash2/{file}, <base>/proj-b/hash3
        let make = |rel: &str, bytes: usize| {
            let dir = base.path().join(rel);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("src.rs"), vec![b'x'; bytes]).unwrap();
        };
        make("proj-a/hash1", 100);
        make("proj-a/hash2", 50);
        make("proj-b/hash3", 10);

        let all = enumerate_staging_trees(base.path(), None, SystemTime::now()).expect("enumerate");
        assert_eq!(all.len(), 3, "three <project>/<hash> trees");
        assert!(all.iter().any(|t| t.size_bytes >= 100));

        // Project filter restricts to one project's trees.
        let only_a =
            enumerate_staging_trees(base.path(), Some("proj-a"), SystemTime::now()).unwrap();
        assert_eq!(only_a.len(), 2);

        // Missing base => empty, no error.
        let missing =
            enumerate_staging_trees(&base.path().join("does-not-exist"), None, SystemTime::now())
                .unwrap();
        assert!(missing.is_empty());
    }

    #[test]
    fn parse_human_duration_units() {
        assert_eq!(
            parse_human_duration("90s").unwrap(),
            Duration::from_secs(90)
        );
        assert_eq!(
            parse_human_duration("30m").unwrap(),
            Duration::from_secs(1800)
        );
        assert_eq!(
            parse_human_duration("24h").unwrap(),
            Duration::from_secs(86_400)
        );
        assert_eq!(
            parse_human_duration("7d").unwrap(),
            Duration::from_secs(604_800)
        );
        // Bare number = seconds.
        assert_eq!(
            parse_human_duration("120").unwrap(),
            Duration::from_secs(120)
        );
        assert!(parse_human_duration("").is_err());
        assert!(parse_human_duration("12x").is_err());
        assert!(parse_human_duration("abch").is_err());
    }

    #[test]
    fn execute_only_removes_prune_entries_and_revalidates() {
        // Build a real tree, plan it as Prune (age 0 with min_age 0), execute.
        let base = tempfile::tempdir().expect("tempdir");
        let tree_dir = base.path().join("proj/hash");
        std::fs::create_dir_all(&tree_dir).unwrap();
        std::fs::write(tree_dir.join("f"), b"data").unwrap();
        // Path must be a safe reap path; tempdir paths under /tmp qualify when
        // deep enough. Construct the plan entry directly to control the action.
        let plan = StagingGcPlan {
            entries: vec![
                StagingGcEntry {
                    path: tree_dir.to_string_lossy().to_string(),
                    size_bytes: 4,
                    age_secs: 9999,
                    action: GcAction::Prune,
                    reason: "test".to_string(),
                },
                StagingGcEntry {
                    path: "/".to_string(),
                    size_bytes: 0,
                    age_secs: 9999,
                    // Even if mislabeled Prune, the re-validation guard refuses "/".
                    action: GcAction::Prune,
                    reason: "adversarial".to_string(),
                },
            ],
            prunable_bytes: 4,
            prunable_count: 2,
            total_bytes: 4,
        };
        // Only run when the tempdir path is actually a safe reap path; otherwise
        // the assertion below would be environment-dependent.
        if rch_common::stale_target_reap::is_safe_reap_path(&plan.entries[0].path) {
            let outcome = execute_staging_gc(&plan, base.path());
            assert_eq!(outcome.removed_count, 1, "only the safe tree removed");
            assert!(!tree_dir.exists(), "safe tree was removed");
            assert!(
                outcome.failed.iter().any(|p| p == "/"),
                "unsafe '/' refused by re-validation"
            );
        }
    }

    #[test]
    fn plan_serializes_for_dry_run_output() {
        let plan = plan_staging_gc(&[tree("/tmp/rch/p/h", 2048, 7200)], policy(3600), base());
        let json = serde_json::to_string(&plan).expect("serialize");
        assert!(json.contains("\"action\":\"prune\""));
        assert!(json.contains("prunable_bytes"));
    }
}
