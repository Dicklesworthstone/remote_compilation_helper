//! Local staging-tree garbage collection for `rch cache clean` (bd-s3433).
//!
//! rch rsyncs each project into a per-project staging tree under the configured
//! `transfer.remote_base` (default `/tmp/rch`, often `/tmp/rch-sync` on a fleet
//! worker): `<remote_base>/<project_id>/<project_hash>`. Nothing pruned these,
//! so on a busy multi-agent host they accumulate to tens of GB — the largest
//! `/tmp` consumer and a disk-full risk mid-swarm.
//!
//! Age proposes candidates; it cannot establish that source or recovery
//! custody ended. Preview observes the shared source registry, retention
//! markers and live process gates. Explicit execution repeats those checks
//! under the same durable GC claim used by worker cleanup, verifies the
//! enumerated directory identities and metadata, and keeps that claim through
//! descriptor-relative removal and checked retirement.
//!
//! Default is **dry-run**: a bare `rch cache clean` never deletes.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

/// Metadata only: no source contents are read or hashed. The witness prevents
/// a stale proposal from authorizing a replaced tree or newly changed inputs.
#[derive(Debug, Clone, Serialize)]
struct StagingWitness {
    canonical_base: PathBuf,
    base: DirectoryIdentity,
    parent: DirectoryIdentity,
    tree: DirectoryIdentity,
    metadata_digest: String,
}

/// One enumerated staging tree.
#[derive(Debug, Clone)]
pub struct StagingTree {
    pub path: PathBuf,
    /// Total bytes under the tree.
    pub size_bytes: u64,
    /// Age of the most recently modified file in the tree (`now - newest_mtime`).
    pub age: Duration,
    witness: Option<StagingWitness>,
}

/// GC policy.
#[derive(Debug, Clone, Copy)]
pub struct StagingGcPolicy {
    /// Only propose trees whose newest entry is older than this. Quiet live
    /// builds and completed recovery inputs additionally require custody and
    /// process checks; old mtimes alone never authorize collection.
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
    /// Source ownership or a retention marker forbids collection.
    KeepSourceCustody,
    /// A process has an open handle, cwd, or command referring to this tree.
    KeepInUse,
    /// The proposal no longer describes the same directory and metadata.
    KeepChanged,
    /// A required ownership, metadata, or liveness observation was unavailable.
    KeepUnavailable,
}

/// Per-tree plan entry.
#[derive(Debug, Clone, Serialize)]
pub struct StagingGcEntry {
    pub path: String,
    pub size_bytes: u64,
    pub age_secs: u64,
    pub action: GcAction,
    pub reason: String,
    #[serde(skip)]
    witness: Option<StagingWitness>,
    #[serde(skip)]
    min_age: Duration,
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
        && candidate.strip_prefix(base).is_ok_and(|relative| {
            relative.components().count() == 2
                && relative
                    .components()
                    .all(|part| matches!(part, std::path::Component::Normal(_)))
        })
        && rch_common::stale_target_reap::is_safe_reap_path(path)
}

fn is_source_container(path: &Path, base: &Path) -> bool {
    path.strip_prefix(base)
        .ok()
        .and_then(|relative| relative.components().next())
        .is_some_and(|part| {
            part.as_os_str()
                .to_string_lossy()
                .starts_with("source-content-")
        })
}

/// Decide, per tree, whether to prune — pure, no filesystem access.
///
/// An old legacy staging tree under `base` becomes a proposal. Source-content
/// containers remain in custody; inspection and execution must establish the
/// remaining ownership, liveness, and identity requirements.
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
        } else if is_source_container(&tree.path, base) {
            (
                GcAction::KeepSourceCustody,
                "source-content containers are not legacy project/hash staging".to_string(),
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
            witness: tree.witness.clone(),
            min_age: policy.min_age,
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
        // Use the directory entry's own type, which does NOT follow symlinks.
        // Path::is_dir() follows symlinks (fs::metadata), so a symlinked
        // project/hash entry pointing at an external directory would be treated
        // as a real staging tree and could be remove_dir_all'd.
        if !project_entry
            .file_type()
            .map(|ft| ft.is_dir())
            .unwrap_or(false)
        {
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
            // Same as above: skip symlinked hash entries (do not follow).
            if !hash_entry
                .file_type()
                .map(|ft| ft.is_dir())
                .unwrap_or(false)
            {
                continue;
            }
            let observation = observe_tree(remote_base, &tree_path);
            // An incomplete traversal never contributes deletion authority.
            // Keep the path visible so preview can explain the refusal.
            let (size_bytes, newest, witness) = match observation {
                Ok((bytes, modified, witness)) => (bytes, Some(modified), Some(witness)),
                Err(_) => (0, None, None),
            };
            let age = newest
                .and_then(|m| now.duration_since(m).ok())
                .unwrap_or(Duration::ZERO);
            trees.push(StagingTree {
                path: tree_path,
                size_bytes,
                age,
                witness,
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

/// Enrich the age proposal with read-only custody and liveness observations.
/// This does not create a source registry, repair records, or acquire a claim.
pub fn inspect_staging_gc_plan(plan: StagingGcPlan, base: &Path) -> StagingGcPlan {
    inspect_staging_gc_plan_with_registry(
        plan,
        base,
        rch_common::stale_target_reap::SOURCE_CLAIM_REGISTRY,
    )
}

fn inspect_staging_gc_plan_with_registry(
    mut plan: StagingGcPlan,
    base: &Path,
    registry: &str,
) -> StagingGcPlan {
    for entry in &mut plan.entries {
        if entry.action != GcAction::Prune {
            continue;
        }
        let verdict = inspect_or_collect(entry, base, registry, false);
        if verdict != "ready" {
            entry.action = match verdict.as_str() {
                "source-ownership" | "retention" => GcAction::KeepSourceCustody,
                "in-use" => GcAction::KeepInUse,
                "changed" => GcAction::KeepChanged,
                "recent" => GcAction::KeepRecent,
                _ => GcAction::KeepUnavailable,
            };
            entry.reason = format!("collection refused: {verdict}");
        }
    }
    plan.prunable_count = 0;
    plan.prunable_bytes = 0;
    for entry in &plan.entries {
        if entry.action == GcAction::Prune {
            plan.prunable_count += 1;
            plan.prunable_bytes = plan.prunable_bytes.saturating_add(entry.size_bytes);
        }
    }
    plan
}

/// A plan is a proposal, never deletion authority. Apply reacquires the shared
/// source transaction and all process gates, verifies the exact enumerated
/// metadata and directory identities, and retires its claim only after the
/// removal child has finished. Unknown observations retain the candidate.
pub fn execute_staging_gc(plan: &StagingGcPlan, base: &Path) -> StagingGcOutcome {
    execute_staging_gc_with_registry(
        plan,
        base,
        rch_common::stale_target_reap::SOURCE_CLAIM_REGISTRY,
    )
}

fn execute_staging_gc_with_registry(
    plan: &StagingGcPlan,
    base: &Path,
    registry: &str,
) -> StagingGcOutcome {
    let mut outcome = StagingGcOutcome::default();
    for entry in &plan.entries {
        if entry.action != GcAction::Prune {
            continue;
        }
        if inspect_or_collect(entry, base, registry, true) == "removed" {
            outcome.removed_count += 1;
            outcome.removed_bytes = outcome.removed_bytes.saturating_add(entry.size_bytes);
        } else {
            outcome.failed.push(entry.path.clone());
        }
    }
    outcome
}

fn inspect_or_collect(entry: &StagingGcEntry, base: &Path, registry: &str, apply: bool) -> String {
    if !is_prunable_path(&entry.path, base) || is_source_container(Path::new(&entry.path), base) {
        return "source-ownership".into();
    }
    let Some(witness) = &entry.witness else {
        return "unavailable".into();
    };
    let Ok(witness) = serde_json::to_string(witness) else {
        return "unavailable".into();
    };
    let (gates, cleanup) = rch_common::stale_target_reap::gc_liveness_guard_fragments();
    let script = format!(
        r#"set -u
{worker_locator}
if ! rch_wkr_locate; then
    printf 'RCH_STAGING_GC_V1 unavailable\n'
    exit 0
fi
{source_guard}
mode=$3
if [ "$mode" = apply ]; then
    if __gc_source_begin "$1"; then :; else
        status=$?
        case "$status" in 1) verdict=source-ownership;; 3) verdict=retention;; 4) verdict=changed;; *) verdict=unavailable;; esac
        printf 'RCH_STAGING_GC_V1 %s\n' "$verdict"
        exit 0
    fi
else
    if __gc_source_inspect "$1"; then :; else
        status=$?
        case "$status" in 1) verdict=source-ownership;; 3) verdict=retention;; *) verdict=unavailable;; esac
        printf 'RCH_STAGING_GC_V1 %s\n' "$verdict"
        exit 0
    fi
fi
{gates}
handles=$(__gc_handles "$__gc_candidate")
processes=$(__gc_procs "$__gc_candidate")
if [ "$handles" = held ] || [ "$processes" = held ]; then
    verdict=in-use
elif [ "$handles" != free ] || [ "$processes" != free ]; then
    verdict=unavailable
elif verdict=$("$RCH_WKR" staging-gc --protocol v1 "$1" "$2" "$3" "$4" "$5" "$__gc_candidate"); then
    case "$verdict" in ready|removed|changed|recent|unavailable) ;; *) verdict=unavailable;; esac
else
    verdict=unavailable
fi
{cleanup}
if [ "$mode" = apply ] && ! __gc_source_end; then
    printf 'RCH_STAGING_GC_V1 unavailable\n'
    exit 1
fi
printf 'RCH_STAGING_GC_V1 %s\n' "$verdict"
"#,
        source_guard =
            rch_common::stale_target_reap::source_claim_gc_guard_fragment_with_registry(registry),
        worker_locator = rch_common::wkr_locate::WKR_LOCATE_SHELL,
    );
    let mut command = std::process::Command::new("sh");
    command
        .args(["-c", &script, "rch-cache-clean"])
        .arg(&entry.path)
        .arg(base)
        .arg(if apply { "apply" } else { "preview" })
        .arg(witness)
        .arg(entry.min_age.as_nanos().to_string())
        .stdin(std::process::Stdio::null());
    // The worker integration suite compiles this exact dispatcher module and
    // exercises its witness/claim protocol against the freshly built worker.
    #[cfg(test)]
    if let Some(worker) = option_env!("CARGO_BIN_EXE_rch-wkr") {
        command.env("RCH_WKR_BIN", worker);
    }
    let output = match command.output() {
        Ok(output) if output.status.success() => output,
        _ => return "unavailable".into(),
    };
    let Ok(stdout) = std::str::from_utf8(&output.stdout) else {
        return "unavailable".into();
    };
    let mut verdicts = stdout
        .lines()
        .filter_map(|line| line.strip_prefix("RCH_STAGING_GC_V1 "));
    match (verdicts.next(), verdicts.next()) {
        (Some(verdict), None) => verdict.to_owned(),
        _ => "unavailable".into(),
    }
}

#[cfg(unix)]
fn observe_tree(
    base: &Path,
    root: &Path,
) -> std::io::Result<(u64, std::time::SystemTime, StagingWitness)> {
    use sha2::{Digest, Sha256};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    fn identity(metadata: &std::fs::Metadata) -> DirectoryIdentity {
        DirectoryIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
    fn fields(metadata: &std::fs::Metadata) -> String {
        format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}\0",
            metadata.dev(),
            metadata.ino(),
            metadata.mode(),
            metadata.uid(),
            metadata.gid(),
            metadata.nlink(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec()
        )
    }
    fn walk(
        path: &Path,
        relative: &Path,
        digest: &mut Sha256,
        size: &mut u64,
        newest: &mut std::time::SystemTime,
    ) -> std::io::Result<()> {
        let metadata = std::fs::symlink_metadata(path)?;
        let name = relative.as_os_str().as_bytes();
        digest.update((name.len() as u64).to_le_bytes());
        digest.update(name);
        digest.update(fields(&metadata).as_bytes());
        *newest = (*newest).max(metadata.modified()?);
        if metadata.is_dir() {
            let before = fields(&metadata);
            let mut entries = std::fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
            entries.sort_by_key(|entry| entry.file_name().as_bytes().to_vec());
            for entry in entries {
                walk(
                    &entry.path(),
                    &relative.join(entry.file_name()),
                    digest,
                    size,
                    newest,
                )?;
            }
            if fields(&std::fs::symlink_metadata(path)?) != before {
                return Err(std::io::Error::other(
                    "staging directory changed during enumeration",
                ));
            }
        } else {
            *size = size.saturating_add(metadata.len());
        }
        Ok(())
    }
    let canonical_base = base.canonicalize()?;
    let relative = root.strip_prefix(base).map_err(std::io::Error::other)?;
    let canonical_root = canonical_base.join(relative);
    if root.canonicalize()? != canonical_root {
        return Err(std::io::Error::other("staging tree traverses a symlink"));
    }
    let base_metadata = std::fs::metadata(&canonical_base)?;
    let parent_metadata = std::fs::symlink_metadata(
        canonical_root
            .parent()
            .ok_or_else(|| std::io::Error::other("staging parent missing"))?,
    )?;
    let root_metadata = std::fs::symlink_metadata(&canonical_root)?;
    if !base_metadata.is_dir() || !parent_metadata.is_dir() || !root_metadata.is_dir() {
        return Err(std::io::Error::other(
            "staging ancestors are not real directories",
        ));
    }
    let mut digest = Sha256::new();
    digest.update(b"rch-staging-metadata-v1\0");
    let mut size = 0;
    let mut newest = root_metadata.modified()?;
    walk(
        &canonical_root,
        Path::new(""),
        &mut digest,
        &mut size,
        &mut newest,
    )?;
    if root.canonicalize()? != canonical_root
        || identity(&std::fs::metadata(base)?) != identity(&base_metadata)
        || identity(&std::fs::symlink_metadata(
            canonical_root.parent().unwrap(),
        )?) != identity(&parent_metadata)
        || fields(&std::fs::symlink_metadata(&canonical_root)?) != fields(&root_metadata)
    {
        return Err(std::io::Error::other(
            "staging ancestry changed during enumeration",
        ));
    }
    Ok((
        size,
        newest,
        StagingWitness {
            canonical_base,
            base: identity(&base_metadata),
            parent: identity(&parent_metadata),
            tree: identity(&root_metadata),
            metadata_digest: digest
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        },
    ))
}

#[cfg(not(unix))]
fn observe_tree(
    _base: &Path,
    _root: &Path,
) -> std::io::Result<(u64, std::time::SystemTime, StagingWitness)> {
    Err(std::io::Error::other(
        "staging collection requires POSIX directory identity",
    ))
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
            witness: None,
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

    #[cfg(unix)]
    #[test]
    fn enumerate_and_sizing_do_not_follow_symlinks() {
        // Regression (bd-review-cachegc-symlink-walk): the walk must never follow
        // symlinks. A symlinked project/hash entry must not be enumerated as a
        // prunable tree, and a symlink INSIDE a tree must not drag the tree's
        // size/mtime to reflect its (possibly old, quiescent) target — which
        // could get an active build tree judged idle and pruned.
        use std::os::unix::fs::symlink;

        let base = tempfile::tempdir().expect("tempdir");
        // A large file in a directory OUTSIDE any staging tree.
        let external = tempfile::tempdir().expect("external tempdir");
        std::fs::write(external.path().join("big.bin"), vec![b'x'; 10_000]).unwrap();

        // A real staging tree with a small file plus a symlink to the external dir.
        let tree = base.path().join("proj-a/hash1");
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("src.rs"), vec![b'x'; 100]).unwrap();
        symlink(external.path(), tree.join("ext")).unwrap();

        // Symlinked hash and project entries must be skipped during enumeration.
        symlink(external.path(), base.path().join("proj-a/hashsym")).unwrap();
        symlink(external.path(), base.path().join("projsym")).unwrap();

        let trees =
            enumerate_staging_trees(base.path(), None, SystemTime::now()).expect("enumerate");
        assert_eq!(
            trees.len(),
            1,
            "symlinked project/hash entries must not be enumerated"
        );
        assert!(trees[0].path.ends_with("proj-a/hash1"));
        assert!(
            trees[0].size_bytes < 10_000,
            "symlink target bytes ({}) must not be counted via descent",
            trees[0].size_bytes
        );
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

    #[cfg(target_os = "linux")]
    #[test]
    fn execute_only_removes_prune_entries_and_revalidates() {
        let root = retained_fixture("staging-gc-positive-");
        let base = root.join("staging");
        let registry = root.join("claims");
        let tree_dir = base.join("proj/hash");
        std::fs::create_dir_all(&tree_dir).unwrap();
        std::fs::write(tree_dir.join("f"), b"data").unwrap();
        // Include directory-prefix ordering and a symlink whose target must
        // survive. Rust enumeration and the actual descriptor-relative helper
        // must agree on the metadata witness without reading file contents.
        std::fs::create_dir(tree_dir.join("a")).unwrap();
        std::fs::write(tree_dir.join("a/child"), b"nested").unwrap();
        std::fs::write(tree_dir.join("a."), b"prefix sibling").unwrap();
        use std::os::unix::ffi::OsStringExt as _;
        std::fs::write(
            tree_dir.join(std::ffi::OsString::from_vec(b"opaque-\xff".to_vec())),
            b"non-UTF8 filename",
        )
        .unwrap();
        let outside = root.join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("retained"), b"outside the proposal").unwrap();
        std::os::unix::fs::symlink(&outside, tree_dir.join("link")).unwrap();
        std::os::unix::fs::symlink(
            &outside,
            tree_dir.join(std::ffi::OsString::from_vec(b"opaque-link-\xff".to_vec())),
        )
        .unwrap();
        let mut plan = proposed(&base);
        plan = inspect_staging_gc_plan_with_registry(plan, &base, registry.to_str().unwrap());
        assert_eq!(
            plan.entries[0].action,
            GcAction::Prune,
            "{:?}",
            plan.entries
        );
        assert!(
            !registry.exists(),
            "preview must not create an ownership registry"
        );
        plan.entries.push(StagingGcEntry {
            path: "/".into(),
            size_bytes: 0,
            age_secs: 9999,
            action: GcAction::Prune,
            reason: "adversarial".into(),
            witness: None,
            min_age: Duration::ZERO,
        });
        let outcome = execute_staging_gc_with_registry(&plan, &base, registry.to_str().unwrap());
        assert_eq!(outcome.removed_count, 1, "{outcome:?}");
        assert!(!tree_dir.exists());
        assert_eq!(
            std::fs::read(outside.join("retained")).unwrap(),
            b"outside the proposal"
        );
        assert!(outcome.failed.iter().any(|path| path == "/"));
        assert!(std::fs::read_dir(&registry).unwrap().all(|entry| {
            !entry
                .unwrap()
                .path()
                .extension()
                .is_some_and(|extension| extension == "claim")
        }));
        assert_eq!(
            std::fs::read_dir(registry.join("released"))
                .unwrap()
                .count(),
            1
        );
    }

    #[cfg(target_os = "linux")]
    fn retained_fixture(prefix: &str) -> PathBuf {
        let path = tempfile::Builder::new()
            .prefix(prefix)
            .disable_cleanup(true)
            .tempdir()
            .unwrap()
            .keep()
            .canonicalize()
            .unwrap();
        eprintln!("Retained cache-clean fixture: {}", path.display());
        path
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn future_modified_input_is_retained_even_with_zero_minimum_age() {
        let root = retained_fixture("staging-gc-future-");
        let base = root.join("staging");
        let registry = root.join("claims");
        let tree = base.join("project/hash");
        std::fs::create_dir_all(&tree).unwrap();
        let input = tree.join("future");
        std::fs::write(&input, b"not old enough").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&input)
            .unwrap()
            .set_modified(SystemTime::now() + Duration::from_secs(86_400))
            .unwrap();
        let plan = proposed(&base);
        assert_eq!(plan.entries[0].action, GcAction::Prune);
        assert_eq!(
            inspect_or_collect(&plan.entries[0], &base, registry.to_str().unwrap(), true),
            "recent"
        );
        assert_eq!(std::fs::read(&input).unwrap(), b"not old enough");
    }

    #[cfg(target_os = "linux")]
    fn proposed(base: &Path) -> StagingGcPlan {
        let trees = enumerate_staging_trees(base, None, SystemTime::now()).unwrap();
        plan_staging_gc(&trees, policy(0), base)
    }

    #[cfg(target_os = "linux")]
    fn source_claim(registry: &Path, root: &Path) -> PathBuf {
        use sha2::{Digest, Sha256};
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(registry).unwrap();
        std::fs::set_permissions(registry, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(registry.join("metadata.lock"), b"").unwrap();
        let bytes = format!("{}\n", root.display());
        let digest: String = Sha256::digest(bytes.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let path = registry.join(format!("{}.{}.claim", "a".repeat(32), digest));
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retained_source_containers_and_marked_ancestors_never_authorize_cleanup() {
        for project in ["source-content-pair-key.retained-owner", "legacy-project"] {
            let root = retained_fixture("staging-gc-retention-");
            let base = root.join("staging");
            let registry = root.join("claims");
            let tree = base.join(project).join("projects");
            std::fs::create_dir_all(&tree).unwrap();
            std::fs::write(tree.join("source"), b"retained original source").unwrap();
            std::os::unix::fs::symlink(
                "identity-only-not-a-path",
                tree.parent().unwrap().join(".rch-retention-v1"),
            )
            .unwrap();
            let proposal = proposed(&base);
            let preview = inspect_staging_gc_plan_with_registry(
                proposal.clone(),
                &base,
                registry.to_str().unwrap(),
            );
            assert_eq!(preview.entries[0].action, GcAction::KeepSourceCustody);
            assert_eq!(preview.prunable_count, 0);
            assert!(!registry.exists(), "retention preview must be read-only");
            let outcome =
                execute_staging_gc_with_registry(&proposal, &base, registry.to_str().unwrap());
            assert_eq!(outcome.removed_count, 0);
            assert_eq!(
                std::fs::read(tree.join("source")).unwrap(),
                b"retained original source"
            );
            assert!(!registry.join("released").exists());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn apply_rechecks_new_source_claims_and_retention_after_preview() {
        for hold in ["claim", "marker"] {
            let root = retained_fixture("staging-gc-new-custody-");
            let base = root.join("staging");
            let registry = root.join("claims");
            let tree = base.join("project/hash");
            std::fs::create_dir_all(&tree).unwrap();
            std::fs::write(tree.join("source"), b"protected").unwrap();
            let preview = inspect_staging_gc_plan_with_registry(
                proposed(&base),
                &base,
                registry.to_str().unwrap(),
            );
            assert_eq!(
                preview.entries[0].action,
                GcAction::Prune,
                "{:?}",
                preview.entries
            );
            let claim = if hold == "claim" {
                Some(source_claim(&registry, tree.parent().unwrap()))
            } else {
                std::os::unix::fs::symlink(
                    "held",
                    tree.parent().unwrap().join(".rch-retention-v1"),
                )
                .unwrap();
                None
            };
            let held_preview = inspect_staging_gc_plan_with_registry(
                preview.clone(),
                &base,
                registry.to_str().unwrap(),
            );
            assert_eq!(held_preview.entries[0].action, GcAction::KeepSourceCustody);
            let outcome =
                execute_staging_gc_with_registry(&preview, &base, registry.to_str().unwrap());
            assert_eq!(outcome.removed_count, 0);
            assert_eq!(std::fs::read(tree.join("source")).unwrap(), b"protected");
            if let Some(claim) = claim {
                assert!(claim.is_file(), "active source claim must remain untouched");
            }
            assert!(!registry.join("released").exists());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn changed_inputs_replaced_trees_and_aliased_parents_refuse_the_old_proposal() {
        for change in ["input", "tree", "parent"] {
            let root = retained_fixture("staging-gc-changed-");
            let base = root.join("staging");
            let registry = root.join("claims");
            let tree = base.join("project/hash");
            std::fs::create_dir_all(&tree).unwrap();
            std::fs::write(tree.join("source"), b"old input").unwrap();
            let plan = proposed(&base);
            let saved = root.join("retained-original");
            match change {
                "input" => std::fs::write(tree.join("source"), b"new selected input").unwrap(),
                "tree" => {
                    std::fs::rename(&tree, &saved).unwrap();
                    std::fs::create_dir(&tree).unwrap();
                    std::fs::write(tree.join("source"), b"new selected input").unwrap();
                }
                "parent" => {
                    std::fs::rename(tree.parent().unwrap(), &saved).unwrap();
                    let outside = root.join("outside");
                    std::fs::create_dir_all(outside.join("hash")).unwrap();
                    std::fs::write(outside.join("hash/source"), b"new selected input").unwrap();
                    std::os::unix::fs::symlink(&outside, tree.parent().unwrap()).unwrap();
                }
                _ => unreachable!(),
            }
            assert_eq!(
                inspect_or_collect(&plan.entries[0], &base, registry.to_str().unwrap(), true),
                "changed"
            );
            assert_eq!(
                std::fs::read(tree.join("source")).unwrap(),
                b"new selected input"
            );
            if change != "input" {
                let original = if change == "tree" {
                    saved.join("source")
                } else {
                    saved.join("hash/source")
                };
                assert_eq!(std::fs::read(original).unwrap(), b"old input");
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn removal_requires_the_same_physical_candidate_as_the_acquired_claim() {
        let root = retained_fixture("staging-gc-claim-binding-");
        let base = root.join("staging");
        let tree = base.join("project/hash");
        let other = root.join("other/project/hash");
        for candidate in [&tree, &other] {
            std::fs::create_dir_all(candidate).unwrap();
            std::fs::write(candidate.join("source"), b"separate custody").unwrap();
        }
        let plan = proposed(&base);
        let witness = serde_json::to_string(plan.entries[0].witness.as_ref().unwrap()).unwrap();
        // Model the exact boundary after a configured base alias changed to
        // another tree during source admission, then changed back. Every
        // witnessed inode is still valid, but the acquired claim is foreign.
        let script = format!(
            "{}\nrch_wkr_locate || exit 73\nexec \"$RCH_WKR\" staging-gc --protocol v1 \"$@\"",
            rch_common::wkr_locate::WKR_LOCATE_SHELL,
        );
        let mut command = std::process::Command::new("sh");
        command
            .args(["-c", &script, "rch-staging-operation-test"])
            .arg(&tree)
            .arg(&base)
            .arg("apply")
            .arg(witness)
            .arg("0")
            .arg(&other);
        if let Some(worker) = option_env!("CARGO_BIN_EXE_rch-wkr") {
            command.env("RCH_WKR_BIN", worker);
        }
        let result = command.output().unwrap();
        assert!(result.status.success(), "{result:?}");
        assert_eq!(result.stdout, b"changed\n");
        for candidate in [&tree, &other] {
            assert_eq!(
                std::fs::read(candidate.join("source")).unwrap(),
                b"separate custody"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn preview_preserves_unknown_pending_records_and_detects_live_descriptors() {
        let root = retained_fixture("staging-gc-observation-");
        let base = root.join("staging");
        let registry = root.join("claims");
        let tree = base.join("project/hash");
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("source"), b"still open").unwrap();
        let open = std::fs::File::open(tree.join("source")).unwrap();
        let preview = inspect_staging_gc_plan_with_registry(
            proposed(&base),
            &base,
            registry.to_str().unwrap(),
        );
        assert_eq!(
            preview.entries[0].action,
            GcAction::KeepInUse,
            "{:?}",
            preview.entries
        );
        assert!(!registry.exists());
        drop(open);
        std::fs::create_dir(&registry).unwrap();
        std::fs::write(registry.join("metadata.lock"), b"").unwrap();
        let pending = registry.join(format!("{}.{}.pending", "b".repeat(32), "0".repeat(64)));
        std::fs::write(&pending, b"interrupted publication").unwrap();
        let preview = inspect_staging_gc_plan_with_registry(
            proposed(&base),
            &base,
            registry.to_str().unwrap(),
        );
        assert_eq!(preview.entries[0].action, GcAction::KeepUnavailable);
        assert_eq!(std::fs::read(pending).unwrap(), b"interrupted publication");
        assert!(!registry.join("quarantine").exists());
        assert!(!registry.join("released").exists());
        assert_eq!(std::fs::read(tree.join("source")).unwrap(), b"still open");
    }

    #[test]
    fn plan_serializes_for_dry_run_output() {
        let plan = plan_staging_gc(&[tree("/tmp/rch/p/h", 2048, 7200)], policy(3600), base());
        let json = serde_json::to_string(&plan).expect("serialize");
        assert!(json.contains("\"action\":\"prune\""));
        assert!(json.contains("prunable_bytes"));
    }
}
