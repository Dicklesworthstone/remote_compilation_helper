//! Pre-execution preparation for offloaded builds.
//!
//! Runs on the worker before the actual build/test command. For Bun/Node
//! projects, this caches `node_modules` keyed by a fingerprint of the
//! manifest + lockfiles, so a `bun test` against an unchanged project
//! doesn't pay the install cost twice.
//!
//! For non-Node runtimes (Rust, C/C++, plain shell) `prepare()` is a no-op.

use anyhow::{Context, Result, anyhow};
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

/// Action taken during prepare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub enum PrepareAction {
    /// No work needed (cache hit, or runtime doesn't require prepare).
    Skipped,
    /// Install command was run successfully.
    Installed,
    /// Install command was attempted but failed.
    Failed,
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

/// Detect which package manager a Node-flavored project uses based on
/// which lockfile is present. Defaults to npm when only `package.json` is.
///
/// Bun ≥1.2 emits a TEXT lockfile at `bun.lock` by default; older Bun
/// emits a binary `bun.lockb`. Either signals a Bun project. We probe
/// both forms.
pub fn detect_package_manager(project_root: &Path) -> PackageManager {
    if project_root.join("bun.lock").exists() || project_root.join("bun.lockb").exists() {
        return PackageManager::Bun;
    }
    if project_root.join("pnpm-lock.yaml").exists() {
        return PackageManager::Pnpm;
    }
    if project_root.join("yarn.lock").exists() {
        return PackageManager::Yarn;
    }
    PackageManager::Npm
}

/// Compute a fingerprint over the project's manifest + lockfiles.
///
/// The fingerprint includes each file's NAME and SIZE (length-prefixed)
/// alongside its content so that:
///   1. Two files with adjacent contents like `("a", "bc")` vs `("ab", "c")`
///      cannot collide (length-prefix removes the boundary ambiguity).
///   2. Switching package manager (yarn → pnpm) produces a different hash
///      even if the lockfile bytes happened to be identical.
pub async fn compute_fingerprint(project_root: &Path) -> Result<DependencyFingerprint> {
    let mut hasher = Hasher::new();
    let mut sources = Vec::new();
    // `bun.lock` (text, Bun ≥1.2) AND `bun.lockb` (binary, older Bun) are both
    // probed so a project that switches Bun versions still hashes correctly.
    for name in [
        "package.json",
        "bun.lock",
        "bun.lockb",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "bunfig.toml",
    ] {
        let p = project_root.join(name);
        if p.exists() {
            let bytes = tokio::fs::read(&p)
                .await
                .with_context(|| format!("read {}", p.display()))?;
            // Length-prefixed encoding eliminates the boundary ambiguity.
            // `name_len:u32_le | name | content_len:u64_le | content`.
            let name_bytes = name.as_bytes();
            hasher.update(&(name_bytes.len() as u32).to_le_bytes());
            hasher.update(name_bytes);
            hasher.update(&(bytes.len() as u64).to_le_bytes());
            hasher.update(&bytes);
            sources.push(name.to_string());
        }
    }
    if sources.is_empty() {
        return Err(anyhow!(
            "no package manifest found in {}",
            project_root.display()
        ));
    }
    Ok(DependencyFingerprint {
        hash: hasher.finalize().to_hex().to_string(),
        sources,
    })
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

/// Per-process registry of `Arc<tokio::sync::Mutex<()>>` keyed by canonical
/// project path. Two `prepare()` calls for the same project serialize on
/// the same mutex, so concurrent `bun install` against the same dir is
/// impossible inside this process. (Cross-process locking would require
/// flock; out of scope for this hook — a single rch-wkr process owns its
/// project workspace.)
fn project_lock(project_root: &Path) -> std::sync::Arc<tokio::sync::Mutex<()>> {
    static REGISTRY: OnceLock<
        Mutex<std::collections::HashMap<PathBuf, std::sync::Arc<tokio::sync::Mutex<()>>>>,
    > = OnceLock::new();
    let registry = REGISTRY.get_or_init(|| Mutex::new(std::collections::HashMap::new()));
    let key = project_root
        .canonicalize()
        .unwrap_or_else(|_| project_root.to_path_buf());
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
        RequiredRuntime::Rust | RequiredRuntime::None => Ok(PrepareReport {
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
    let cached = read_cached_fingerprint(project_root).await;

    // Cache hit: skip install
    if let Some(prev) = &cached
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

    // Cache miss: install. When the runtime hint is Bun and there's no
    // lockfile that would otherwise specify a package manager, prefer
    // `bun install` over the Npm default — the user explicitly asked for
    // the Bun runtime, so respect that intent.
    let pm = match (runtime, detect_package_manager(project_root)) {
        // If runtime=Bun and detected fell back to Npm (no lockfile), use Bun.
        (RequiredRuntime::Bun, PackageManager::Npm) => PackageManager::Bun,
        (_, p) => p,
    };
    // When runtime=Bun and we picked Bun via the runtime hint above, the
    // project likely has no lockfile yet — so `--frozen-lockfile` would
    // fail. Use a permissive install in that case.
    let cmd = if pm == PackageManager::Bun && !project_root.join("bun.lockb").exists() {
        vec!["bun".into(), "install".into()]
    } else {
        pm.install_command()
    };
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
            // Timeout: kill the child and report Failed. kill_on_drop
            // ensures the process is reaped even if kill() races.
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
                action: PrepareAction::Failed,
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
    // written by `npm install`) are included. Otherwise the next prepare
    // call would see those files in compute_fingerprint() and miss the
    // cache despite the dependency state being unchanged.
    let post_install_fingerprint = compute_fingerprint(project_root)
        .await
        .unwrap_or_else(|_| fingerprint.clone());
    write_cached_fingerprint(project_root, &post_install_fingerprint).await?;

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
        make_node_project(tmp.path(), r#"{"name":"x"}"#, None);
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
                // Property A: cache-miss must yield Installed or Failed,
                // never Skipped (no fingerprint was cached).
                assert!(
                    matches!(r.action, PrepareAction::Installed | PrepareAction::Failed),
                    "cache miss must yield Installed or Failed, not {:?}",
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
                if r.action == PrepareAction::Failed {
                    // Property E: failure invalidates fingerprint cache and
                    // records install_log_path for diagnostics.
                    assert!(
                        r.install_log_path.is_some(),
                        "Failed must include install_log_path"
                    );
                    assert!(
                        read_cached_fingerprint(tmp.path()).await.is_none(),
                        "Failed must invalidate cached fingerprint"
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
        // must NOT race. We pre-populate the cache so both calls hit the
        // fast cache-hit path (no install runs), and verify the
        // fingerprint file remains intact afterward.
        let tmp = TempDir::new().unwrap();
        make_node_project(tmp.path(), r#"{"name":"x"}"#, None);
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
        // br-4998x review fix: with length-prefixed encoding, two
        // adjacent-content scenarios that would collide under simple
        // concatenation produce distinct hashes.
        let a = TempDir::new().unwrap();
        std::fs::write(a.path().join("package.json"), "ab").unwrap();
        std::fs::write(a.path().join("bun.lock"), "c").unwrap();
        let b = TempDir::new().unwrap();
        std::fs::write(b.path().join("package.json"), "a").unwrap();
        std::fs::write(b.path().join("bun.lock"), "bc").unwrap();
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
