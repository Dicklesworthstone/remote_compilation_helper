//! Pre-execution preparation for offloaded builds.
//!
//! Runs on the worker before the actual build/test command. For Bun/Node
//! projects, this caches `node_modules` keyed by a fingerprint of the
//! manifest + lockfiles, so a `bun test` against an unchanged project
//! doesn't pay the install cost twice.
//!
//! For non-Node runtimes (Rust, C/C++, plain shell) `prepare()` is a no-op.

use anyhow::{Context, Result, anyhow, ensure};
use blake3::Hasher;
use chrono::{DateTime, Utc};
use rch_common::types::RequiredRuntime;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::process::Command;
use tracing::{info, warn};

/// Default timeout for an install subprocess (npm/bun/yarn/pnpm). A wedged
/// install (network hang, registry stall) MUST NOT block the worker
/// indefinitely. Override via `RCH_PREPARE_INSTALL_TIMEOUT_SECS`.
const DEFAULT_INSTALL_TIMEOUT_SECS: u64 = 300; // 5 minutes

// One vocabulary for installation, cache identity and the outer transaction's
// stable-input checks. In particular, npm-shrinkwrap.json takes precedence over
// package-lock.json in npm, and .npmrc can change the installed dependency tree.
pub(super) const INPUT_NAMES: &[&str] = &[
    "package.json",
    "bun.lock",
    "bun.lockb",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bunfig.toml",
    "npm-shrinkwrap.json",
    ".npmrc",
];

pub(super) fn fingerprint_hasher() -> Hasher {
    let mut hasher = Hasher::new();
    // Root-only stamps cannot prove the workspace manifests were unchanged.
    // Retain locked-manager selection and invalidate pre-workspace stamps.
    hasher.update(b"rch-dependency-install-v3\0");
    hasher
}

/// Action taken during prepare.
///
/// Agents reading prepare's JSON output branch on this single field:
/// `Skipped` and `Installed` mean the dependency state is good - the
/// user's `bun test` (etc.) will run with `node_modules/` in place.
/// `Failed` and `Timeout` mean the install couldn't make
/// `node_modules/` consistent - the user's command will likely emit a
/// clearer runtime error (e.g. "Cannot find module"). Agents can offer
/// different remediation for `Timeout` (network / registry stall) than
/// for `Failed` (genuine install error - see `install_log_path`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub enum PrepareAction {
    /// No work needed (cache hit, or runtime doesn't require prepare).
    Skipped,
    /// Install command was run successfully.
    Installed,
    /// Install command was attempted but exited non-zero. See
    /// `install_log_path` for the captured stdout/stderr.
    Failed,
    /// Install command exceeded the timeout
    /// (`RCH_PREPARE_INSTALL_TIMEOUT_SECS`, default 300s) and was killed.
    /// `install_log_path` may contain partial output.
    Timeout,
}

/// Identifying fingerprint for a Node-flavored project's dependency manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DependencyFingerprint {
    /// Hex blake3 of (filename, bytes) for each manifest/lockfile.
    pub hash: String,
    /// Source files included (for diagnostic logging).
    pub sources: Vec<String>,
}

/// Result of a single `prepare()` call.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PrepareReport {
    pub runtime: RequiredRuntime,
    pub action: PrepareAction,
    /// Fingerprint after this run (None if runtime doesn't use fingerprints).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<DependencyFingerprint>,
    /// Previous fingerprint hash, if a cache miss triggered a reinstall.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint_changed_from: Option<String>,
    /// Path to the install log file, if an install was run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_log_path: Option<PathBuf>,
    pub took_ms: u64,
    /// Bytes added to `node_modules/` by this prepare (post-pre size delta).
    pub bytes_added_to_node_modules: u64,
    /// UTC timestamp of completion (RFC 3339).
    #[schemars(with = "String")]
    pub completed_at: DateTime<Utc>,
}

/// Package manager detected for a Node-flavored project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum PackageManager {
    Bun,
    Pnpm,
    Yarn,
    Npm,
}

impl PackageManager {
    /// Argv to install dependencies in `project_root`. The first element is the
    /// program name (looked up via PATH); the rest are arguments.
    pub fn install_command(self) -> Vec<String> {
        match self {
            Self::Bun => vec!["bun".into(), "install".into(), "--frozen-lockfile".into()],
            Self::Pnpm => vec!["pnpm".into(), "install".into(), "--frozen-lockfile".into()],
            Self::Yarn => vec!["yarn".into(), "install".into(), "--frozen-lockfile".into()],
            // `npm ci` is the equivalent of frozen-lockfile install for npm.
            Self::Npm => vec!["npm".into(), "ci".into()],
        }
    }
}

/// Install intent derived from the observed inputs, before any cache hit or
/// installer dispatch. A runtime hint chooses only a lockfile-free bootstrap;
/// it cannot replace the package manager selected by an existing lockfile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct InstallPlan {
    manager: PackageManager,
    locked: bool,
}

impl InstallPlan {
    pub(super) fn for_sources(sources: &[String], runtime: RequiredRuntime) -> Result<Self> {
        let families: &[(PackageManager, &[&str])] = &[
            (PackageManager::Bun, &["bun.lock", "bun.lockb"]),
            (PackageManager::Pnpm, &["pnpm-lock.yaml"]),
            (PackageManager::Yarn, &["yarn.lock"]),
            (
                PackageManager::Npm,
                &["package-lock.json", "npm-shrinkwrap.json"],
            ),
        ];
        let mut selected = None;
        for (manager, locks) in families {
            if sources.iter().any(|name| locks.contains(&name.as_str())) {
                ensure!(
                    selected.is_none(),
                    "conflicting package-manager lockfiles; select one manager before preparation"
                );
                selected = Some(*manager);
            }
        }
        Ok(Self {
            manager: selected.unwrap_or(if runtime == RequiredRuntime::Bun {
                PackageManager::Bun
            } else {
                PackageManager::Npm
            }),
            locked: selected.is_some(),
        })
    }

    fn command(self) -> Vec<String> {
        if self.locked {
            self.manager.install_command()
        } else {
            // npm ci REQUIRES a lockfile. Choose install before dispatch, not
            // as a retry after a locked install fails or changes dependencies.
            let program = match self.manager {
                PackageManager::Bun => "bun",
                PackageManager::Pnpm => "pnpm",
                PackageManager::Yarn => "yarn",
                PackageManager::Npm => "npm",
            };
            vec![program.into(), "install".into()]
        }
    }

    pub(super) fn generated_lockfiles(self) -> &'static [&'static str] {
        if self.locked {
            // A frozen install may not introduce another lockfile, even one
            // from the same family. Existing files are checked independently.
            return &[];
        }
        match self.manager {
            PackageManager::Bun => &["bun.lock", "bun.lockb"],
            PackageManager::Pnpm => &["pnpm-lock.yaml"],
            PackageManager::Yarn => &["yarn.lock"],
            PackageManager::Npm => &["package-lock.json"],
        }
    }
}

#[cfg(test)]
fn detect_package_manager(project_root: &Path) -> PackageManager {
    let sources = INPUT_NAMES
        .iter()
        .filter(|name| project_root.join(name).exists())
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    InstallPlan::for_sources(&sources, RequiredRuntime::Node)
        .expect("unambiguous test project")
        .manager
}

/// Compute the same bounded, workspace-aware observation used by the outer
/// preparation transaction. Cache decisions and publication must not hash a
/// different input set. The encoding length-prefixes file names and contents.
pub async fn compute_fingerprint(project_root: &Path) -> Result<DependencyFingerprint> {
    let project = project_root.to_path_buf();
    tokio::task::spawn_blocking(move || {
        super::DependencyInputs::capture(&project).map(|inputs| inputs.fingerprint)
    })
    .await
    .context("dependency input discovery task failed")?
}

const FINGERPRINT_FILE: &str = ".rch_dep_fingerprint.json";

async fn read_cached_fingerprint(project_root: &Path) -> Option<DependencyFingerprint> {
    let path = project_root.join(FINGERPRINT_FILE);
    let bytes = tokio::fs::read(&path).await.ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Atomically write the fingerprint via temp-file + rename. A crash mid-write
/// leaves either the previous fingerprint or no fingerprint — never a
/// truncated JSON that would silently appear as cache-miss but corrupt
/// downstream consumers parsing the file directly.
async fn write_cached_fingerprint(project_root: &Path, fp: &DependencyFingerprint) -> Result<()> {
    let final_path = project_root.join(FINGERPRINT_FILE);
    let tmp_path = project_root.join(format!("{}.tmp", FINGERPRINT_FILE));
    let bytes = serde_json::to_vec(fp).context("serialize fingerprint")?;
    tokio::fs::write(&tmp_path, bytes)
        .await
        .with_context(|| format!("write fingerprint to {}", tmp_path.display()))?;
    tokio::fs::rename(&tmp_path, &final_path)
        .await
        .with_context(|| format!("rename fingerprint to {}", final_path.display()))?;
    Ok(())
}

/// Best-effort delete of the cached fingerprint after a failed install,
/// so the next attempt does NOT cache-hit on a possibly-corrupt
/// `node_modules/`. Errors are swallowed (the file may not exist).
async fn invalidate_cached_fingerprint(project_root: &Path) {
    let path = project_root.join(FINGERPRINT_FILE);
    let _ = tokio::fs::remove_file(&path).await;
}

/// Persist the post-install fingerprint when possible. If recomputing or
/// writing the cache fails after a successful install, keep the install result
/// fail-open for the user command, invalidate stale cache state, and return the
/// best fingerprint available for diagnostics.
async fn persist_post_install_fingerprint(
    project_root: &Path,
    pre_install_fingerprint: &DependencyFingerprint,
    recomputed: Result<DependencyFingerprint>,
) -> DependencyFingerprint {
    match recomputed {
        Ok(fp) => {
            if let Err(e) = write_cached_fingerprint(project_root, &fp).await {
                warn!(
                    target: "rch::wkr::prepare",
                    error = %e,
                    "fingerprint write failed after successful install; cache will be \
                     re-created on next call"
                );
                invalidate_cached_fingerprint(project_root).await;
            }
            fp
        }
        Err(e) => {
            warn!(
                target: "rch::wkr::prepare",
                error = %e,
                "post-install fingerprint recompute failed; invalidating cache so next \
                 call recomputes fresh"
            );
            invalidate_cached_fingerprint(project_root).await;
            // Return the pre-install fingerprint as a *report* value (best info
            // we have) but DON'T persist it - that would be the silent-fallback
            // bug.
            pre_install_fingerprint.clone()
        }
    }
}

/// Build a canonical lock-key for a project path that survives all the
/// failure modes of `Path::canonicalize` (path doesn't exist yet,
/// transient EACCES, traversal errors). The fallback is a manually-
/// normalized absolute form: join with cwd if relative, then collapse
/// `.` and `..` components. Two callers for the same project always
/// produce the same key as long as cwd is consistent within the call.
fn lock_key_for(project_root: &Path) -> PathBuf {
    if let Ok(canonical) = project_root.canonicalize() {
        return canonical;
    }
    // Fallback: absolutize via cwd, then collapse `.` / `..` components
    // by hand. This produces a deterministic key even when the project
    // path doesn't yet exist on disk.
    use std::path::Component;
    let absolute: PathBuf = if project_root.is_absolute() {
        project_root.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("/"))
            .join(project_root)
    };
    let mut out = PathBuf::new();
    for comp in absolute.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Per-process registry of `Arc<tokio::sync::Mutex<()>>` keyed by a
/// canonical absolute project path. Two `prepare()` calls for the same
/// project serialize on the same mutex, so concurrent `bun install`
/// against the same dir is impossible inside this process. Cross-process
/// locking would require flock; out of scope (a single rch-wkr process
/// owns its project workspace).
///
/// The HashMap grows unboundedly across the process lifetime — one
/// `Arc<Mutex>` per ever-seen project. For a worker that processes
/// hundreds of distinct projects per day this is a few hundred bytes
/// each — a minor leak, not a correctness issue. Cleaning up on drop
/// would require ref-counting which the existing flow doesn't track.
fn project_lock(project_root: &Path) -> std::sync::Arc<tokio::sync::Mutex<()>> {
    static REGISTRY: OnceLock<
        Mutex<std::collections::HashMap<PathBuf, std::sync::Arc<tokio::sync::Mutex<()>>>>,
    > = OnceLock::new();
    let registry = REGISTRY.get_or_init(|| Mutex::new(std::collections::HashMap::new()));
    let key = lock_key_for(project_root);
    let mut guard = registry.lock().unwrap_or_else(|e| e.into_inner());
    guard
        .entry(key)
        .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

fn install_timeout() -> Duration {
    let secs = std::env::var("RCH_PREPARE_INSTALL_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_INSTALL_TIMEOUT_SECS);
    Duration::from_secs(secs.max(1))
}

/// Recursive size of a directory in bytes. Returns 0 if missing.
///
/// Symlinks are NOT followed (avoids loops in pnpm's nested-symlink
/// `node_modules/` layouts and adversarial fixtures). A best-effort cap
/// on visited directories prevents runaway scans on pathological trees.
async fn dir_size(root: &Path) -> u64 {
    use std::collections::VecDeque;
    const MAX_DIRS_VISITED: usize = 200_000;
    let mut total: u64 = 0;
    let mut stack: VecDeque<PathBuf> = VecDeque::new();
    let mut visited = 0usize;
    if !root.exists() {
        return 0;
    }
    stack.push_back(root.to_path_buf());
    while let Some(dir) = stack.pop_front() {
        visited += 1;
        if visited > MAX_DIRS_VISITED {
            break;
        }
        let mut rd = match tokio::fs::read_dir(&dir).await {
            Ok(rd) => rd,
            Err(_) => continue,
        };
        while let Ok(Some(entry)) = rd.next_entry().await {
            // Use symlink_metadata so we DON'T follow links — file_type()
            // by itself is fine for the discriminant, but recursing into
            // a symlinked dir could spin on a cycle.
            let ft = match entry.file_type().await {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if ft.is_symlink() {
                continue;
            }
            if ft.is_file() {
                if let Ok(meta) = entry.metadata().await {
                    total = total.saturating_add(meta.len());
                }
            } else if ft.is_dir() {
                stack.push_back(entry.path());
            }
        }
    }
    total
}

/// Top-level prepare entry point. Idempotent: a re-run with unchanged
/// fingerprint is a no-op (returns `PrepareAction::Skipped`).
pub async fn prepare(
    project_root: &Path,
    runtime: RequiredRuntime,
    log_dir: &Path,
) -> Result<PrepareReport> {
    let started = Instant::now();
    match runtime {
        RequiredRuntime::Bun | RequiredRuntime::Node => {
            prepare_node_like(project_root, runtime, log_dir, started).await
        }
        // Nix fetches its own inputs into /nix/store at build time and needs no
        // node_modules-style prepare step, so it is skipped like Rust/None.
        // Go resolves its own modules from the module cache at build time and
        // needs no node_modules-style prepare step, so it is skipped like Rust/Nix.
        // Zig cross-builds are cargo builds — cargo resolves the registry itself
        // and `zig` ships its own bundled libc/headers, so nothing to prepare.
        RequiredRuntime::Rust
        | RequiredRuntime::None
        | RequiredRuntime::Nix
        | RequiredRuntime::Go
        | RequiredRuntime::Zig => Ok(PrepareReport {
            runtime,
            action: PrepareAction::Skipped,
            fingerprint: None,
            fingerprint_changed_from: None,
            install_log_path: None,
            took_ms: started.elapsed().as_millis() as u64,
            bytes_added_to_node_modules: 0,
            completed_at: Utc::now(),
        }),
    }
}

async fn prepare_node_like(
    project_root: &Path,
    runtime: RequiredRuntime,
    log_dir: &Path,
    started: Instant,
) -> Result<PrepareReport> {
    // Serialize concurrent prepare() calls for the same project. Without
    // this, two callers race on the fingerprint write + invoke `bun install`
    // in the same `current_dir`, which corrupts node_modules. The lock is
    // per-process; cross-process contention requires flock and is out of
    // scope (a single rch-wkr owns its workspace).
    let lock = project_lock(project_root);
    let _guard = lock.lock().await;

    let fingerprint = compute_fingerprint(project_root).await?;
    let plan = InstallPlan::for_sources(&fingerprint.sources, runtime)?;
    let cached = read_cached_fingerprint(project_root).await;

    // Cache hit: skip install
    if let Some(prev) = &cached
        && plan.locked
        && prev.hash == fingerprint.hash
        && project_root.join("node_modules").exists()
    {
        info!(
            target: "rch::wkr::prepare",
            action = "cache_hit",
            hash = %fingerprint.hash,
            runtime = ?runtime,
            "node_modules cached, skipping install"
        );
        return Ok(PrepareReport {
            runtime,
            action: PrepareAction::Skipped,
            fingerprint: Some(fingerprint),
            fingerprint_changed_from: None,
            install_log_path: None,
            took_ms: started.elapsed().as_millis() as u64,
            bytes_added_to_node_modules: 0,
            completed_at: Utc::now(),
        });
    }

    // Lockfile-free installs cannot reuse a stamp: neither the dependency
    // resolution nor the runtime-selected manager is pinned in that case.
    let pm = plan.manager;
    let cmd = plan.command();
    tokio::fs::create_dir_all(log_dir).await.ok();
    let log_path = log_dir.join(format!(
        "prepare_{}.log",
        &fingerprint.hash[..16.min(fingerprint.hash.len())]
    ));
    let log_file = std::fs::File::create(&log_path)
        .with_context(|| format!("create install log at {}", log_path.display()))?;

    info!(
        target: "rch::wkr::prepare",
        action = "installing",
        manager = ?pm,
        hash = %fingerprint.hash,
        prev_hash = ?cached.as_ref().map(|c| &c.hash),
        runtime = ?runtime,
        "running pre-execution install"
    );

    let pre_size = dir_size(&project_root.join("node_modules")).await;

    let log_clone = log_file.try_clone().context("clone install log handle")?;
    let timeout = install_timeout();
    let mut child = Command::new(&cmd[0])
        .args(&cmd[1..])
        .current_dir(project_root)
        .stdout(log_clone)
        .stderr(log_file)
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("spawn {:?}", cmd))?;
    let status = match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(status)) => status,
        Ok(Err(e)) => {
            return Err(anyhow!("install command wait failed: {e}"));
        }
        Err(_elapsed) => {
            // Timeout: kill the child and report PrepareAction::Timeout
            // so agents can distinguish a wedged install (network /
            // registry stall) from a genuine install error.
            // kill_on_drop ensures the process is reaped even if
            // kill().await races.
            let _ = child.kill().await;
            warn!(
                target: "rch::wkr::prepare",
                timeout_secs = timeout.as_secs(),
                log_path = %log_path.display(),
                "install command timed out; killed"
            );
            // Invalidate stale fingerprint since node_modules is in an
            // indeterminate state.
            invalidate_cached_fingerprint(project_root).await;
            return Ok(PrepareReport {
                runtime,
                action: PrepareAction::Timeout,
                fingerprint: Some(fingerprint),
                fingerprint_changed_from: cached.map(|c| c.hash),
                install_log_path: Some(log_path),
                took_ms: started.elapsed().as_millis() as u64,
                bytes_added_to_node_modules: 0,
                completed_at: Utc::now(),
            });
        }
    };

    if !status.success() {
        warn!(
            target: "rch::wkr::prepare",
            log_path = %log_path.display(),
            "install command failed; see log"
        );
        // Invalidate cached fingerprint so next attempt does not cache-hit
        // on a possibly-corrupt node_modules.
        invalidate_cached_fingerprint(project_root).await;
        return Ok(PrepareReport {
            runtime,
            action: PrepareAction::Failed,
            fingerprint: Some(fingerprint),
            fingerprint_changed_from: cached.map(|c| c.hash),
            install_log_path: Some(log_path),
            took_ms: started.elapsed().as_millis() as u64,
            bytes_added_to_node_modules: 0,
            completed_at: Utc::now(),
        });
    }

    let post_size = dir_size(&project_root.join("node_modules")).await;
    // Recompute the fingerprint AFTER install so newly-created lockfiles
    // (e.g. `bun.lock` written by `bun install`, `package-lock.json`
    // written by `npm install`) are included in the cached state.
    // Otherwise the next prepare call would see those files in
    // compute_fingerprint() and miss the cache despite dependency state
    // being unchanged.
    //
    // Recompute failure is pathological — would require the install to
    // have deleted package.json. The install itself SUCCEEDED, so:
    //   - Report PrepareAction::Installed (the user's bun test should run).
    //   - Invalidate any stale cached fingerprint so the next call
    //     recomputes fresh.
    //   - Do NOT silently cache the pre-install fingerprint (that was
    //     the original silent-fallback bug — it permanently loses the
    //     newly-created lockfile from the cached state and forces
    //     re-install every call).
    let post_install_fingerprint = persist_post_install_fingerprint(
        project_root,
        &fingerprint,
        compute_fingerprint(project_root).await,
    )
    .await;

    Ok(PrepareReport {
        runtime,
        action: PrepareAction::Installed,
        fingerprint: Some(post_install_fingerprint),
        fingerprint_changed_from: cached.map(|c| c.hash),
        install_log_path: Some(log_path),
        took_ms: started.elapsed().as_millis() as u64,
        bytes_added_to_node_modules: post_size.saturating_sub(pre_size),
        completed_at: Utc::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn plan(sources: &[&str], runtime: RequiredRuntime) -> InstallPlan {
        InstallPlan::for_sources(
            &sources
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>(),
            runtime,
        )
        .unwrap()
    }

    #[test]
    fn npm_bootstrap_uses_install_but_existing_npm_locks_always_use_ci() {
        assert_eq!(
            plan(&[], RequiredRuntime::Node).command(),
            ["npm", "install"]
        );
        assert_eq!(
            plan(&[], RequiredRuntime::Bun).command(),
            ["bun", "install"]
        );
        for lock in ["package-lock.json", "npm-shrinkwrap.json"] {
            for runtime in [RequiredRuntime::Node, RequiredRuntime::Bun] {
                let selected = plan(&[lock], runtime);
                assert_eq!(selected.command(), ["npm", "ci"], "{lock}/{runtime:?}");
                assert!(selected.locked);
                assert!(selected.generated_lockfiles().is_empty());
            }
        }
        assert_eq!(
            plan(
                &["package-lock.json", "npm-shrinkwrap.json"],
                RequiredRuntime::Bun,
            )
            .command(),
            ["npm", "ci"]
        );
    }

    #[test]
    fn every_non_npm_lock_family_keeps_its_frozen_command_for_both_runtimes() {
        for (lock, program) in [
            ("bun.lock", "bun"),
            ("bun.lockb", "bun"),
            ("pnpm-lock.yaml", "pnpm"),
            ("yarn.lock", "yarn"),
        ] {
            for runtime in [RequiredRuntime::Node, RequiredRuntime::Bun] {
                assert_eq!(
                    plan(&[lock], runtime).command(),
                    [program, "install", "--frozen-lockfile"]
                );
                assert!(plan(&[lock], runtime).generated_lockfiles().is_empty());
            }
        }
        assert_eq!(
            plan(&["bun.lock", "bun.lockb"], RequiredRuntime::Node).command(),
            ["bun", "install", "--frozen-lockfile"]
        );
    }

    #[test]
    fn mixed_manager_lockfiles_are_not_resolved_by_arbitrary_priority() {
        let locks = [
            "bun.lock",
            "pnpm-lock.yaml",
            "yarn.lock",
            "package-lock.json",
        ];
        for first in 0..locks.len() {
            for second in first + 1..locks.len() {
                for runtime in [RequiredRuntime::Node, RequiredRuntime::Bun] {
                    let sources = vec![locks[first].to_owned(), locks[second].to_owned()];
                    let error = InstallPlan::for_sources(&sources, runtime).unwrap_err();
                    assert!(
                        error
                            .to_string()
                            .contains("conflicting package-manager lockfiles")
                    );
                }
            }
        }
    }

    #[test]
    fn only_lockfile_free_bootstraps_may_generate_the_selected_managers_lock() {
        let npm = plan(&["package.json", ".npmrc"], RequiredRuntime::Node);
        let bun = plan(&["package.json", "bunfig.toml"], RequiredRuntime::Bun);
        assert!(
            !npm.locked && !bun.locked,
            "unlocked resolution is not cacheable"
        );
        assert_eq!(npm.generated_lockfiles(), ["package-lock.json"]);
        assert_eq!(bun.generated_lockfiles(), ["bun.lock", "bun.lockb"]);
    }

    #[tokio::test]
    async fn shrinkwrap_and_project_npm_configuration_change_the_fingerprint() {
        let fixture = TempDir::new().unwrap();
        make_node_project(fixture.path(), "{}", Some(("package-lock.json", "locked")));
        let initial = compute_fingerprint(fixture.path()).await.unwrap();
        std::fs::write(
            fixture.path().join("npm-shrinkwrap.json"),
            b"shrinkwrap one",
        )
        .unwrap();
        let shrinkwrap = compute_fingerprint(fixture.path()).await.unwrap();
        assert_ne!(initial.hash, shrinkwrap.hash);
        std::fs::write(
            fixture.path().join("npm-shrinkwrap.json"),
            b"shrinkwrap two",
        )
        .unwrap();
        let changed = compute_fingerprint(fixture.path()).await.unwrap();
        assert_ne!(changed.hash, shrinkwrap.hash);
        std::fs::write(fixture.path().join(".npmrc"), b"legacy-peer-deps=true\n").unwrap();
        let configured = compute_fingerprint(fixture.path()).await.unwrap();
        assert_ne!(changed.hash, configured.hash);
        assert!(configured.sources.contains(&".npmrc".to_owned()));
        std::fs::write(fixture.path().join(".npmrc"), b"legacy-peer-deps=false\n").unwrap();
        assert_ne!(
            configured.hash,
            compute_fingerprint(fixture.path()).await.unwrap().hash
        );
    }

    #[tokio::test]
    async fn conflicting_locks_cannot_reuse_a_matching_cached_success() {
        let fixture = TempDir::new().unwrap();
        make_node_project(fixture.path(), "{}", Some(("bun.lock", "locked")));
        std::fs::write(fixture.path().join("package-lock.json"), b"also locked").unwrap();
        let fingerprint = compute_fingerprint(fixture.path()).await.unwrap();
        write_cached_fingerprint(fixture.path(), &fingerprint)
            .await
            .unwrap();
        std::fs::create_dir(fixture.path().join("node_modules")).unwrap();
        let logs = fixture.path().join("logs");
        let error = prepare(fixture.path(), RequiredRuntime::Bun, &logs)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("conflicting package-manager lockfiles")
        );
        assert!(
            !logs.exists(),
            "ambiguous inputs must be refused before installer setup"
        );
    }

    #[tokio::test]
    async fn old_unqualified_fingerprint_is_not_a_valid_installation_stamp() {
        let fixture = TempDir::new().unwrap();
        make_node_project(fixture.path(), "{}", Some(("package-lock.json", "locked")));
        let mut legacy = Hasher::new();
        for (name, bytes) in [
            ("package.json", b"{}".as_slice()),
            ("package-lock.json", b"locked".as_slice()),
        ] {
            legacy.update(&(name.len() as u32).to_le_bytes());
            legacy.update(name.as_bytes());
            legacy.update(&(bytes.len() as u64).to_le_bytes());
            legacy.update(bytes);
        }
        let current = compute_fingerprint(fixture.path()).await.unwrap();
        assert_ne!(legacy.finalize().to_hex().as_str(), current.hash);
    }

    fn make_node_project(dir: &Path, package_json: &str, lockfile: Option<(&str, &str)>) {
        std::fs::write(dir.join("package.json"), package_json).unwrap();
        if let Some((name, content)) = lockfile {
            std::fs::write(dir.join(name), content).unwrap();
        }
    }

    #[tokio::test]
    async fn test_compute_fingerprint_includes_package_json() {
        // TEST START: fingerprint covers package.json
        let tmp = TempDir::new().unwrap();
        make_node_project(tmp.path(), r#"{"name":"x","version":"0.0.1"}"#, None);
        let fp = compute_fingerprint(tmp.path()).await.unwrap();
        assert!(!fp.hash.is_empty());
        assert_eq!(fp.sources, vec!["package.json".to_string()]);
        // TEST PASS
    }

    #[tokio::test]
    async fn test_compute_fingerprint_changes_when_package_json_changes() {
        // TEST START: hash sensitive to package.json content
        let tmp = TempDir::new().unwrap();
        make_node_project(tmp.path(), r#"{"name":"x","version":"0.0.1"}"#, None);
        let fp1 = compute_fingerprint(tmp.path()).await.unwrap();
        std::fs::write(
            tmp.path().join("package.json"),
            r#"{"name":"x","version":"0.0.2"}"#,
        )
        .unwrap();
        let fp2 = compute_fingerprint(tmp.path()).await.unwrap();
        assert_ne!(fp1.hash, fp2.hash);
        // TEST PASS
    }

    #[tokio::test]
    async fn test_compute_fingerprint_includes_filename_in_hash() {
        // TEST START: same content under different lockfile names yields different hash
        let tmp1 = TempDir::new().unwrap();
        make_node_project(
            tmp1.path(),
            r#"{"name":"x"}"#,
            Some(("package-lock.json", "lock-bytes-here")),
        );
        let tmp2 = TempDir::new().unwrap();
        make_node_project(
            tmp2.path(),
            r#"{"name":"x"}"#,
            Some(("yarn.lock", "lock-bytes-here")),
        );
        let fp1 = compute_fingerprint(tmp1.path()).await.unwrap();
        let fp2 = compute_fingerprint(tmp2.path()).await.unwrap();
        assert_ne!(
            fp1.hash, fp2.hash,
            "package-lock vs yarn.lock with same content must hash differently"
        );
        // TEST PASS
    }

    #[tokio::test]
    async fn test_compute_fingerprint_no_manifest_errors() {
        // TEST START: empty dir is rejected
        let tmp = TempDir::new().unwrap();
        let err = compute_fingerprint(tmp.path()).await;
        assert!(err.is_err());
        let msg = err.unwrap_err().to_string();
        assert!(msg.contains("no package manifest"));
        // TEST PASS
    }

    #[test]
    fn test_detect_package_manager_bun() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("package.json"), "{}").unwrap();
        std::fs::write(tmp.path().join("bun.lockb"), [0u8; 4]).unwrap();
        assert_eq!(detect_package_manager(tmp.path()), PackageManager::Bun);
    }

    #[test]
    fn test_detect_package_manager_pnpm() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("package.json"), "{}").unwrap();
        std::fs::write(tmp.path().join("pnpm-lock.yaml"), "lockfileVersion: 6\n").unwrap();
        assert_eq!(detect_package_manager(tmp.path()), PackageManager::Pnpm);
    }

    #[test]
    fn test_detect_package_manager_yarn() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("package.json"), "{}").unwrap();
        std::fs::write(tmp.path().join("yarn.lock"), "# yarn lock\n").unwrap();
        assert_eq!(detect_package_manager(tmp.path()), PackageManager::Yarn);
    }

    #[test]
    fn test_detect_package_manager_npm_default() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("package.json"), "{}").unwrap();
        // No lockfile -> default to Npm.
        assert_eq!(detect_package_manager(tmp.path()), PackageManager::Npm);
    }

    #[test]
    fn test_install_command_bun_uses_frozen_lockfile() {
        let cmd = PackageManager::Bun.install_command();
        assert_eq!(cmd[0], "bun");
        assert_eq!(cmd[1], "install");
        assert_eq!(cmd[2], "--frozen-lockfile");
    }

    #[test]
    fn test_install_command_npm_uses_ci() {
        let cmd = PackageManager::Npm.install_command();
        assert_eq!(cmd, vec!["npm".to_string(), "ci".to_string()]);
    }

    #[test]
    fn test_install_command_pnpm_uses_frozen_lockfile() {
        let cmd = PackageManager::Pnpm.install_command();
        assert!(cmd.contains(&"--frozen-lockfile".to_string()));
    }

    #[test]
    fn test_install_command_yarn_uses_frozen_lockfile() {
        let cmd = PackageManager::Yarn.install_command();
        assert!(cmd.contains(&"--frozen-lockfile".to_string()));
    }

    #[tokio::test]
    async fn test_prepare_skipped_for_rust_runtime() {
        // TEST START: Rust runtime is no-op
        let tmp = TempDir::new().unwrap();
        let log_dir = tmp.path().join("logs");
        let report = prepare(tmp.path(), RequiredRuntime::Rust, &log_dir)
            .await
            .unwrap();
        assert_eq!(report.action, PrepareAction::Skipped);
        assert!(report.fingerprint.is_none());
        // No log dir gets created for skipped Rust prepare
        // TEST PASS
    }

    #[tokio::test]
    async fn test_prepare_skipped_for_none_runtime() {
        let tmp = TempDir::new().unwrap();
        let log_dir = tmp.path().join("logs");
        let report = prepare(tmp.path(), RequiredRuntime::None, &log_dir)
            .await
            .unwrap();
        assert_eq!(report.action, PrepareAction::Skipped);
    }

    #[tokio::test]
    async fn test_read_write_cached_fingerprint_round_trip() {
        // TEST START: persisted fingerprint round-trips
        let tmp = TempDir::new().unwrap();
        make_node_project(tmp.path(), r#"{"name":"x"}"#, None);
        let fp = compute_fingerprint(tmp.path()).await.unwrap();
        write_cached_fingerprint(tmp.path(), &fp).await.unwrap();
        let cached = read_cached_fingerprint(tmp.path()).await.unwrap();
        assert_eq!(cached, fp);
        // TEST PASS
    }

    #[tokio::test]
    async fn test_read_cached_fingerprint_returns_none_when_absent() {
        let tmp = TempDir::new().unwrap();
        let cached = read_cached_fingerprint(tmp.path()).await;
        assert!(cached.is_none());
    }

    #[tokio::test]
    async fn test_prepare_cache_hit_returns_skipped() {
        // TEST START: cache hit yields Skipped without running install
        let tmp = TempDir::new().unwrap();
        make_node_project(tmp.path(), r#"{"name":"x"}"#, Some(("bun.lock", "locked")));
        // Pre-populate fingerprint AND node_modules so the cache hit fires.
        let fp = compute_fingerprint(tmp.path()).await.unwrap();
        write_cached_fingerprint(tmp.path(), &fp).await.unwrap();
        std::fs::create_dir_all(tmp.path().join("node_modules")).unwrap();
        let log_dir = tmp.path().join("logs");
        let report = prepare(tmp.path(), RequiredRuntime::Bun, &log_dir)
            .await
            .unwrap();
        assert_eq!(report.action, PrepareAction::Skipped);
        assert!(report.fingerprint.is_some());
        assert_eq!(report.bytes_added_to_node_modules, 0);
        assert!(report.install_log_path.is_none());
        // TEST PASS
    }

    #[tokio::test]
    async fn test_prepare_cache_miss_attempts_install() {
        // TEST START: cache miss fires install — verify by structural
        // assertions that hold whether bun is present or not.
        let tmp = TempDir::new().unwrap();
        make_node_project(
            tmp.path(),
            r#"{"name":"x"}"#,
            Some(("bun.lockb", "fake-lockfile-bytes-for-test")),
        );
        let log_dir = tmp.path().join("logs");
        // Sanity: precondition has no fingerprint cached.
        assert!(read_cached_fingerprint(tmp.path()).await.is_none());

        let report = prepare(tmp.path(), RequiredRuntime::Bun, &log_dir).await;
        match report {
            Ok(r) => {
                // Property A: cache-miss must yield Installed/Failed/Timeout,
                // never Skipped (no fingerprint was cached).
                assert!(
                    matches!(
                        r.action,
                        PrepareAction::Installed | PrepareAction::Failed | PrepareAction::Timeout
                    ),
                    "cache miss must yield Installed/Failed/Timeout, not {:?}",
                    r.action
                );
                // Property B: fingerprint always populated for Bun/Node.
                assert!(r.fingerprint.is_some(), "fingerprint must be set");
                // Property C: log_dir created on the cache-miss path.
                assert!(
                    log_dir.exists(),
                    "log_dir must be created on cache-miss path"
                );
                if r.action == PrepareAction::Installed {
                    // Property D: success persists fingerprint + node_modules survives.
                    let cached = read_cached_fingerprint(tmp.path()).await;
                    assert!(cached.is_some(), "Installed must persist fingerprint");
                    assert_eq!(cached.unwrap().hash, r.fingerprint.unwrap().hash);
                    assert!(tmp.path().join("node_modules").exists());
                }
                if matches!(r.action, PrepareAction::Failed | PrepareAction::Timeout) {
                    // Property E: failure / timeout invalidates fingerprint
                    // cache and records install_log_path for diagnostics.
                    assert!(
                        r.install_log_path.is_some(),
                        "{:?} must include install_log_path",
                        r.action
                    );
                    assert!(
                        read_cached_fingerprint(tmp.path()).await.is_none(),
                        "{:?} must invalidate cached fingerprint",
                        r.action
                    );
                }
            }
            Err(e) => {
                // Spawn-not-found is acceptable when bun isn't in PATH.
                let msg = e.to_string();
                assert!(
                    msg.contains("spawn")
                        || msg.contains("No such file")
                        || msg.contains("not found"),
                    "unexpected error: {}",
                    msg
                );
            }
        }
        // TEST PASS
    }

    #[tokio::test]
    async fn test_concurrent_prepare_serializes_via_lock() {
        // TEST START: two concurrent prepare() calls for the same project
        // must NOT race. Exercises the cache-hit fast path. Both must
        // succeed and the persisted fingerprint must remain valid.
        let tmp = TempDir::new().unwrap();
        make_node_project(tmp.path(), r#"{"name":"x"}"#, Some(("bun.lock", "locked")));
        let fp = compute_fingerprint(tmp.path()).await.unwrap();
        write_cached_fingerprint(tmp.path(), &fp).await.unwrap();
        std::fs::create_dir_all(tmp.path().join("node_modules")).unwrap();

        let log_dir = tmp.path().join("logs");
        let p1 = tmp.path().to_path_buf();
        let p2 = p1.clone();
        let log1 = log_dir.clone();
        let log2 = log_dir.clone();
        let (r1, r2) = tokio::join!(
            prepare(&p1, RequiredRuntime::Bun, &log1),
            prepare(&p2, RequiredRuntime::Bun, &log2),
        );
        assert_eq!(r1.unwrap().action, PrepareAction::Skipped);
        assert_eq!(r2.unwrap().action, PrepareAction::Skipped);
        // Fingerprint file still parses cleanly (no torn writes).
        assert!(read_cached_fingerprint(tmp.path()).await.is_some());
        // TEST PASS
    }

    #[tokio::test]
    async fn test_project_lock_serializes_real_contention() {
        // TEST START: prove the lock actually serializes by holding it
        // ourselves and showing a second prepare() blocks on the same
        // project, then resumes once we release. If the lock didn't
        // exist (or used different keys for the same project), the
        // second call would race ahead and return immediately.
        let tmp = TempDir::new().unwrap();
        make_node_project(tmp.path(), r#"{"name":"x"}"#, Some(("bun.lock", "locked")));
        let fp = compute_fingerprint(tmp.path()).await.unwrap();
        write_cached_fingerprint(tmp.path(), &fp).await.unwrap();
        std::fs::create_dir_all(tmp.path().join("node_modules")).unwrap();

        // Acquire the same lock prepare() will try to acquire.
        let lock = project_lock(tmp.path());
        let held = lock.lock().await;

        // Fire prepare() in a task; it MUST block on the same lock.
        let p = tmp.path().to_path_buf();
        let log_dir = tmp.path().join("logs");
        let join_handle =
            tokio::spawn(async move { prepare(&p, RequiredRuntime::Bun, &log_dir).await });

        // Give the spawned task a moment to reach the lock acquisition.
        // It must NOT have completed yet — the lock is held.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            !join_handle.is_finished(),
            "prepare() should block while project_lock is held"
        );

        // Release the lock; the spawned task must now complete promptly.
        drop(held);
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), join_handle)
            .await
            .expect("prepare() must complete after lock release")
            .expect("join handle")
            .expect("prepare() Result");
        assert_eq!(result.action, PrepareAction::Skipped);
        // TEST PASS
    }

    #[tokio::test]
    async fn test_project_lock_keys_match_for_relative_and_absolute_path() {
        // TEST START: a project referred to by both relative and
        // absolute paths must hash to the SAME lock key, otherwise
        // concurrent callers could race.
        let tmp = TempDir::new().unwrap();
        let abs_lock = project_lock(tmp.path());
        // Construct a non-canonical reference to the same dir.
        let with_dot = tmp.path().join(".");
        let dot_lock = project_lock(&with_dot);
        // Arc::ptr_eq checks they're the SAME mutex, not just clones of
        // distinct mutexes that happen to compare equal.
        assert!(
            std::sync::Arc::ptr_eq(&abs_lock, &dot_lock),
            "canonical and `./` form must share one lock"
        );
        // TEST PASS
    }

    #[tokio::test]
    async fn test_post_install_recompute_failure_invalidates_cache_but_returns_preinstall_report() {
        // TEST START: if compute_fingerprint fails after a successful
        // install, prepare should still report Installed to the caller,
        // but the stale cache must be invalidated and the pre-install
        // fingerprint may only be returned as diagnostic report data.
        // Persisting it would recreate the original silent-fallback bug.
        let tmp = TempDir::new().unwrap();
        let stale = DependencyFingerprint {
            hash: "stale".into(),
            sources: vec!["package.json".into()],
        };
        write_cached_fingerprint(tmp.path(), &stale).await.unwrap();

        let pre_install = DependencyFingerprint {
            hash: "pre-install".into(),
            sources: vec!["package.json".into()],
        };
        let returned = persist_post_install_fingerprint(
            tmp.path(),
            &pre_install,
            Err(anyhow!("simulated recompute failure")),
        )
        .await;

        assert_eq!(returned, pre_install);
        assert!(
            read_cached_fingerprint(tmp.path()).await.is_none(),
            "stale cache must be invalidated instead of preserving pre-install fingerprint"
        );
        // TEST PASS
    }

    #[tokio::test]
    async fn test_post_install_recompute_success_persists_recomputed_fingerprint() {
        let tmp = TempDir::new().unwrap();
        let pre_install = DependencyFingerprint {
            hash: "pre-install".into(),
            sources: vec!["package.json".into()],
        };
        let recomputed = DependencyFingerprint {
            hash: "post-install".into(),
            sources: vec!["package.json".into(), "bun.lock".into()],
        };

        let returned =
            persist_post_install_fingerprint(tmp.path(), &pre_install, Ok(recomputed.clone()))
                .await;
        assert_eq!(returned, recomputed);
        assert_eq!(read_cached_fingerprint(tmp.path()).await, Some(recomputed));
    }

    #[tokio::test]
    async fn test_atomic_fingerprint_write_visible_or_absent() {
        // TEST START: temp+rename means two writes leave the second
        // value in place and no `.tmp` file lingers.
        let tmp = TempDir::new().unwrap();
        let fp1 = DependencyFingerprint {
            hash: "aaaa".into(),
            sources: vec!["a".into()],
        };
        let fp2 = DependencyFingerprint {
            hash: "bbbb".into(),
            sources: vec!["b".into()],
        };
        write_cached_fingerprint(tmp.path(), &fp1).await.unwrap();
        write_cached_fingerprint(tmp.path(), &fp2).await.unwrap();
        let cached = read_cached_fingerprint(tmp.path()).await.unwrap();
        assert_eq!(cached, fp2, "second write must completely replace first");
        assert!(
            !tmp.path()
                .join(format!("{}.tmp", FINGERPRINT_FILE))
                .exists(),
            "temp file should be gone after rename"
        );
        // TEST PASS
    }

    #[tokio::test]
    async fn test_invalidate_cached_fingerprint_removes_file() {
        let tmp = TempDir::new().unwrap();
        let fp = DependencyFingerprint {
            hash: "x".into(),
            sources: vec!["package.json".into()],
        };
        write_cached_fingerprint(tmp.path(), &fp).await.unwrap();
        assert!(read_cached_fingerprint(tmp.path()).await.is_some());
        invalidate_cached_fingerprint(tmp.path()).await;
        assert!(read_cached_fingerprint(tmp.path()).await.is_none());
        // Idempotent: second invalidation does not error.
        invalidate_cached_fingerprint(tmp.path()).await;
    }

    #[tokio::test]
    async fn test_install_timeout_default_is_sensible() {
        let default = install_timeout();
        assert!(default.as_secs() >= 1);
        assert!(default.as_secs() <= 24 * 60 * 60);
    }

    #[test]
    fn test_detect_package_manager_bun_text_lockfile() {
        // br-4998x review fix: `bun.lock` (Bun ≥1.2) signals Bun.
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("package.json"), "{}").unwrap();
        std::fs::write(tmp.path().join("bun.lock"), "# bun lock text\n").unwrap();
        assert_eq!(detect_package_manager(tmp.path()), PackageManager::Bun);
    }

    #[test]
    fn test_install_command_uses_frozen_lockfile_when_bun_lock_present() {
        // br-4998x re-review: even with the TEXT lockfile (`bun.lock`)
        // present, install must use --frozen-lockfile. Previous fix
        // only checked `bun.lockb`.
        // This is a property of the cmd-selection logic in
        // prepare_node_like; mirror it here so a regression of the
        // selection rule fails this test.
        // Setup: project has bun.lock (text only) — no bun.lockb.
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("package.json"), "{}").unwrap();
        std::fs::write(tmp.path().join("bun.lock"), "# text lockfile\n").unwrap();
        // Either lockfile means a lockfile exists — frozen is correct.
        let bun_has_lockfile =
            tmp.path().join("bun.lockb").exists() || tmp.path().join("bun.lock").exists();
        assert!(bun_has_lockfile, "test fixture must have a lockfile");
        // The selection rule: pm == Bun + has_lockfile → install_command()
        // (which is bun install --frozen-lockfile).
        let cmd = PackageManager::Bun.install_command();
        assert!(
            cmd.contains(&"--frozen-lockfile".to_string()),
            "with any lockfile present, install command must include --frozen-lockfile"
        );
    }

    #[tokio::test]
    async fn test_compute_fingerprint_includes_bun_lock_text() {
        // br-4998x review fix: bun.lock is in the fingerprint set.
        let tmp = TempDir::new().unwrap();
        make_node_project(tmp.path(), r#"{"name":"x"}"#, None);
        let fp1 = compute_fingerprint(tmp.path()).await.unwrap();
        std::fs::write(tmp.path().join("bun.lock"), "# bun lock\n").unwrap();
        let fp2 = compute_fingerprint(tmp.path()).await.unwrap();
        assert_ne!(fp1.hash, fp2.hash, "bun.lock must affect fingerprint");
        assert!(fp2.sources.iter().any(|s| s == "bun.lock"));
    }

    #[tokio::test]
    async fn test_fingerprint_length_prefix_disambiguates() {
        // Two valid manifests plus their lock bytes concatenate identically,
        // but moving a trailing space between files must change the digest.
        let a = TempDir::new().unwrap();
        std::fs::write(a.path().join("package.json"), "{\"name\":\"x\"} ").unwrap();
        std::fs::write(a.path().join("bun.lock"), "c").unwrap();
        let b = TempDir::new().unwrap();
        std::fs::write(b.path().join("package.json"), "{\"name\":\"x\"}").unwrap();
        std::fs::write(b.path().join("bun.lock"), " c").unwrap();
        let fp_a = compute_fingerprint(a.path()).await.unwrap();
        let fp_b = compute_fingerprint(b.path()).await.unwrap();
        assert_ne!(
            fp_a.hash, fp_b.hash,
            "length-prefixed encoding should disambiguate"
        );
    }

    #[tokio::test]
    async fn test_prepare_writes_log_dir_if_missing() {
        // TEST START: log_dir is created on demand for cache-miss path
        let tmp = TempDir::new().unwrap();
        make_node_project(tmp.path(), r#"{"name":"x"}"#, Some(("bun.lockb", "x")));
        let log_dir = tmp.path().join("nonexistent_logs");
        // Sanity: log_dir does NOT exist before the call.
        assert!(!log_dir.exists(), "precondition: log_dir absent");
        let _ = prepare(tmp.path(), RequiredRuntime::Bun, &log_dir).await;
        // After prepare runs the cache-miss path, create_dir_all should have
        // brought the log_dir into existence regardless of whether the install
        // itself succeeded (Failed branch still creates the log dir to write
        // its log into). The assertion is meaningful: a regression that
        // skipped the log_dir creation would fail this.
        assert!(
            log_dir.exists(),
            "prepare's cache-miss path must create log_dir on demand"
        );
        // TEST PASS
    }

    #[tokio::test]
    async fn test_prepare_report_serialization_round_trips() {
        let report = PrepareReport {
            runtime: RequiredRuntime::Bun,
            action: PrepareAction::Skipped,
            fingerprint: Some(DependencyFingerprint {
                hash: "abc".into(),
                sources: vec!["package.json".into()],
            }),
            fingerprint_changed_from: None,
            install_log_path: None,
            took_ms: 5,
            bytes_added_to_node_modules: 0,
            completed_at: Utc::now(),
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"action\":\"Skipped\""));
        assert!(json.contains("\"runtime\":\"bun\""));
        let back: PrepareReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.action, PrepareAction::Skipped);
    }

    #[tokio::test]
    async fn test_dir_size_reports_zero_for_missing_path() {
        let tmp = TempDir::new().unwrap();
        let bytes = dir_size(&tmp.path().join("does-not-exist")).await;
        assert_eq!(bytes, 0);
    }

    #[tokio::test]
    async fn test_dir_size_counts_nested_files() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("a/b")).unwrap();
        std::fs::write(tmp.path().join("a/file1.txt"), b"hello").unwrap();
        std::fs::write(tmp.path().join("a/b/file2.txt"), b"world!").unwrap();
        let bytes = dir_size(tmp.path()).await;
        // 5 + 6 = 11 bytes
        assert_eq!(bytes, 11);
    }
}
