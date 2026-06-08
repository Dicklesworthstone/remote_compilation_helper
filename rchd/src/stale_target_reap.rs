//! Daemon-side worker sweep that reaps *stale* per-job `.rch-target-*` dirs.
//!
//! # Why this exists
//!
//! rch gives every forwarded-`CARGO_TARGET_DIR` build a per-job target dir
//! (`.rch-target-<worker>-job-<id>-…` / `…-pid-…`) placed **directly inside** the
//! synced repo dir, i.e. `<sync-root>/<repo>/.rch-target-*` (e.g.
//! `/data/projects/<repo>/.rch-target-<worker>-job-…`). The orchestrator hook
//! already reaps *abandoned* such dirs — but **only for the single repo currently
//! being built**, and only as a side-effect of an offloaded build. Per-job dirs in
//! any repo that nobody is actively rch-building therefore accumulate forever (we
//! hand-reclaimed ~1.6 TB across the fleet because of exactly this gap).
//!
//! This module closes that gap with a periodic background task inside `rchd`:
//! every `interval_mins` it SSHes to each healthy worker and applies the
//! **identical** idle predicate as the orchestrator reaper — shared via
//! [`rch_common::stale_target_reap`] so the two cannot drift — across **all** repo
//! dirs under the worker's `remote_base` (the repo sync-root, default
//! `/data/projects`).
//!
//! # Safety
//!
//! - Matches only the shared globs `.rch-target-*-job-*` / `.rch-target-*-pid-*`
//!   ([`rch_common::stale_target_reap::REAP_GLOBS`]) at the per-job depth
//!   (`<base>/<repo>/<glob>`). A bare `target`, a source dir, `.git`, `.beads`,
//!   etc. are structurally unreachable by the glob + depth.
//! - A dir is removed only if **neither it nor any descendant** was modified
//!   within the idle window (default 12h). An active build touches its dir
//!   continuously, so a live (or merely paused-for-minutes) build is always kept —
//!   this is what makes the sweep safe to run concurrently with active builds, on
//!   the same worker or even the same repo.
//! - The `remote_base` is validated against
//!   [`rch_common::stale_target_reap::is_safe_reap_base`] before being embedded in
//!   the generated shell (the security boundary).
//! - Only `WorkerStatus::Healthy` workers with a closed circuit are swept; SSH and
//!   reap failures are swallowed (best-effort, never load-bearing).

use crate::config::StaleTargetReapConfig;
use crate::workers::{WorkerPool, WorkerState};
use rch_common::stale_target_reap;
use rch_common::{SshClient, SshOptions, WorkerId, WorkerStatus};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::interval;
use tracing::{debug, info, warn};

/// Metrics emitted by the worker-side reap script.
#[derive(Debug, Clone, Default)]
struct ReapMetrics {
    removed: u64,
    freed_bytes: u64,
}

/// Aggregate stats for one sweep cycle across all workers.
#[derive(Debug, Default, Clone)]
pub struct ReapCycleStats {
    pub workers_checked: u32,
    pub workers_swept: u32,
    pub workers_skipped: u32,
    pub errors: u32,
    pub total_removed: u64,
    pub total_bytes_freed: u64,
}

/// Build the worker-wide sweep script.
///
/// `escaped_base` is the remote repo sync-root rch rsyncs each repo into. rch
/// places per-job target dirs **directly inside** the synced repo dir, so the
/// real on-worker layout is `<base>/<repo>/.rch-target-*-job-*` — i.e. the
/// per-job dir sits one level below `<base>/<repo>` (depth 2 under `<base>`), NOT
/// `<base>/<project_id>/<hash>/.rch-target-*`. This mirrors the orchestrator
/// reaper, which `cd`s into `remote_path()` (= the synced repo dir) and globs
/// `.rch-target-*-job-*` directly. For every repo dir one level under
/// `escaped_base` we iterate the shared per-job globs and apply the shared
/// [`stale_target_reap::reap_loop_body`] predicate, accumulating a removed-count
/// and freed-KB, then print a parseable metrics line.
///
/// # Depth-robust matching
///
/// rch places a per-job target dir directly inside the synced repo dir, but the
/// synced "repo dir" is not always one level under `escaped_base`: a top-level
/// project sits at `<base>/<repo>/.rch-target-*` (depth 2), a canonical multi-repo
/// layout at `<base>/<id>/<hash>/.rch-target-*`, and a **workspace member** even
/// deeper (`<base>/<repo>/crates/<member>/.rch-target-*`). A fixed depth-2 glob
/// (`for proj in "$base"/*; …`) misses the nested per-job dirs. So we walk with a
/// single `find "$__rt" -maxdepth 8 -type d ( -name ".rch-target-*-job-*" -o -name
/// ".rch-target-*-pid-*" ) -prune` that matches the per-job dir at *any* depth and
/// `-prune`s so it never descends into the (large) artifact tree. This mirrors the
/// orchestrator hook's own depth-robust full-tree sweep (now retired in favor of
/// this daemon sweep). The bound is 8 to give deep nested layouts ample headroom
/// while still bounding the source-tree walk.
///
/// # Metrics survive the loop
///
/// A `find … | while read … done` pipe would run the loop body in a **subshell**
/// in POSIX `sh`, discarding the `removed`/`freed_kb` increments. To keep the
/// counters in the parent shell we redirect `find` output to a temp file and feed
/// the `while read` loop *from the file* (`done < "$tmpf"`) — a redirect-from-file
/// (unlike the right side of a pipe) does not spawn a subshell, so the shared
/// [`stale_target_reap::reap_loop_body`] increments persist and the emitted
/// `RCH_WORKER_REAP_METRICS` line reflects the true removed/freed totals.
///
/// `escaped_base` is canonicalized at runtime with `cd … && pwd -P` (defensive
/// against a symlinked base) before the walk, and MUST already be validated by
/// [`stale_target_reap::is_safe_reap_base`] in the Rust caller; it is embedded
/// inside double quotes. The `find -name` globs are double-quoted so they survive
/// the single-quoted `sh -c '…'` dispatch unchanged.
fn build_sweep_command(escaped_base: &str, idle_minutes: u64) -> String {
    // No exclude token (the daemon has no "current job" of its own); accumulate
    // metrics into `removed` / `freed_kb` via the shared per-dir predicate.
    let loop_body = stale_target_reap::reap_loop_body(idle_minutes, None, "removed", "freed_kb");
    format!(
        "set -u; \
         base=\"{escaped_base}\"; \
         removed=0; freed_kb=0; \
         if [ ! -d \"$base\" ]; then \
           printf 'RCH_WORKER_REAP_METRICS removed=0 freed_kb=0\\n'; exit 0; \
         fi; \
         __rt=$(cd \"$base\" 2>/dev/null && pwd -P) || {{ printf 'RCH_WORKER_REAP_METRICS removed=0 freed_kb=0\\n'; exit 0; }}; \
         [ -n \"$__rt\" ] || {{ printf 'RCH_WORKER_REAP_METRICS removed=0 freed_kb=0\\n'; exit 0; }}; \
         case \"$__rt\" in */*/*) ;; *) printf 'RCH_WORKER_REAP_METRICS removed=0 freed_kb=0\\n'; exit 0;; esac; \
         __tmpf=$(mktemp 2>/dev/null || mktemp -p \"${{TMPDIR:-/data/tmp}}\" 2>/dev/null) || {{ printf 'RCH_WORKER_REAP_METRICS removed=0 freed_kb=0\\n'; exit 0; }}; \
         find \"$__rt\" -maxdepth 8 -type d \\( -name \".rch-target-*-job-*\" -o -name \".rch-target-*-pid-*\" \\) -prune 2>/dev/null > \"$__tmpf\"; \
         while IFS= read -r d; do {loop_body} done < \"$__tmpf\"; \
         rm -f \"$__tmpf\"; \
         printf 'RCH_WORKER_REAP_METRICS removed=%s freed_kb=%s\\n' \"$removed\" \"$freed_kb\""
    )
}

fn parse_reap_metrics(stdout: &str) -> Option<ReapMetrics> {
    let line = stdout
        .lines()
        .find(|l| l.contains("RCH_WORKER_REAP_METRICS"))?;
    let mut removed = None;
    let mut freed_kb = None;
    for token in line.split_whitespace().skip(1) {
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        match key {
            "removed" => removed = value.parse::<u64>().ok(),
            "freed_kb" => freed_kb = value.parse::<u64>().ok(),
            _ => {}
        }
    }
    Some(ReapMetrics {
        removed: removed.unwrap_or(0),
        freed_bytes: freed_kb.unwrap_or(0).saturating_mul(1024),
    })
}

/// Periodic worker-side stale-target reaper.
pub struct StaleTargetReaper {
    pool: WorkerPool,
    config: StaleTargetReapConfig,
    ssh_options: SshOptions,
}

impl StaleTargetReaper {
    pub fn new(pool: WorkerPool, config: StaleTargetReapConfig) -> Self {
        Self {
            pool,
            config,
            ssh_options: SshOptions::default(),
        }
    }

    /// Spawn the background sweep loop. Returns the task handle.
    pub fn start(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let reaper = self;
        tokio::spawn(async move {
            if !reaper.config.enabled {
                info!("Worker stale-target reaper disabled");
                return;
            }
            // Validate the base once up-front; a bad base disables the whole sweep
            // rather than risking an unsafe embedded path.
            if !stale_target_reap::is_safe_reap_base(&reaper.config.remote_base) {
                warn!(
                    "Worker stale-target reaper disabled: unsafe remote_base {:?}",
                    reaper.config.remote_base
                );
                return;
            }
            info!(
                "Worker stale-target reaper started (interval={}min, idle>{}h, base={})",
                reaper.config.interval_mins,
                reaper
                    .config
                    .idle_hours
                    .max(stale_target_reap::MIN_IDLE_HOURS),
                reaper.config.remote_base
            );
            let mut ticker = interval(Duration::from_secs(reaper.config.interval_mins.max(1) * 60));
            loop {
                ticker.tick().await;
                let stats = reaper.run_cycle().await;
                if stats.total_removed > 0 || stats.errors > 0 {
                    info!(
                        "Worker stale-target reap cycle: checked={}, swept={}, skipped={}, errors={}, removed={} dirs, freed={}MB",
                        stats.workers_checked,
                        stats.workers_swept,
                        stats.workers_skipped,
                        stats.errors,
                        stats.total_removed,
                        stats.total_bytes_freed / (1024 * 1024),
                    );
                } else {
                    debug!("Worker stale-target reap cycle: nothing to reap");
                }
            }
        })
    }

    /// Run one sweep across all workers.
    pub async fn run_cycle(&self) -> ReapCycleStats {
        let mut stats = ReapCycleStats::default();
        let idle_minutes = stale_target_reap::idle_minutes_from_hours(self.config.idle_hours);
        let workers = self.pool.all_workers().await;

        for worker_state in workers {
            stats.workers_checked += 1;
            let worker_id = worker_state.config.read().await.id.clone();

            // Only sweep workers we can reliably SSH to. The mtime predicate — not
            // worker idleness — is what protects active builds, so we deliberately
            // do NOT skip busy workers: a busy worker may have stale dirs in repos
            // it is not currently building, which is the entire reason this sweep
            // exists. Active dirs on a busy worker are still preserved because they
            // are touched within the idle window.
            if !self.is_worker_sweepable(&worker_state, &worker_id).await {
                stats.workers_skipped += 1;
                continue;
            }

            match self.sweep_worker(&worker_state, idle_minutes).await {
                Ok(metrics) => {
                    stats.workers_swept += 1;
                    stats.total_removed += metrics.removed;
                    stats.total_bytes_freed += metrics.freed_bytes;
                    if metrics.removed > 0 {
                        info!(
                            worker = %worker_id,
                            removed = metrics.removed,
                            freed_mb = metrics.freed_bytes / (1024 * 1024),
                            "Reaped stale per-job target dirs on worker"
                        );
                    }
                }
                Err(e) => {
                    warn!(worker = %worker_id, error = %e, "Worker stale-target sweep failed");
                    stats.errors += 1;
                }
            }
        }

        stats
    }

    /// Whether a worker is in a state where SSH-based sweeping is sensible.
    async fn is_worker_sweepable(&self, worker_state: &WorkerState, worker_id: &WorkerId) -> bool {
        let status = worker_state.status().await;
        if status != WorkerStatus::Healthy {
            debug!(worker = %worker_id, ?status, "Skipping non-healthy worker for stale-target sweep");
            return false;
        }
        let circuit_state = worker_state.circuit_state().await;
        if circuit_state != Some(rch_common::CircuitState::Closed) {
            debug!(worker = %worker_id, ?circuit_state, "Skipping worker with non-closed circuit for stale-target sweep");
            return false;
        }
        true
    }

    /// Run the sweep script on a single worker and return its metrics.
    async fn sweep_worker(
        &self,
        worker_state: &WorkerState,
        idle_minutes: u64,
    ) -> anyhow::Result<ReapMetrics> {
        let start = Instant::now();
        let config = worker_state.config.read().await.clone();
        let worker_id = config.id.clone();

        // `remote_base` was validated once in `start()`, but re-check defensively:
        // config can be hot-reloaded between cycles.
        if !stale_target_reap::is_safe_reap_base(&self.config.remote_base) {
            anyhow::bail!("unsafe remote_base {:?}", self.config.remote_base);
        }
        let cmd = build_sweep_command(&self.config.remote_base, idle_minutes);

        debug!(worker = %worker_id, idle_minutes, "Starting stale-target sweep");

        let mut ssh = SshClient::new(config.clone(), self.ssh_options.clone());
        ssh.connect().await?;
        let result = ssh.execute(&cmd).await;
        let _ = ssh.disconnect().await;
        let result = result?;

        let metrics = parse_reap_metrics(&result.stdout).unwrap_or_default();
        debug!(
            worker = %worker_id,
            removed = metrics.removed,
            freed_bytes = metrics.freed_bytes,
            duration_ms = start.elapsed().as_millis() as u64,
            exit = result.exit_code,
            "Stale-target sweep finished"
        );
        Ok(metrics)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sweep_command_confines_to_base_and_per_job_globs() {
        let cmd = build_sweep_command("/data/projects", 720);
        // Depth-robust find at ANY depth under the canonicalized base — NOT a
        // fixed depth-2 `for proj in "$base"/*` glob (which would miss nested
        // workspace-member per-job dirs).
        assert!(cmd.contains(
            "find \"$__rt\" -maxdepth 8 -type d \\( -name \".rch-target-*-job-*\" -o -name \".rch-target-*-pid-*\" \\) -prune"
        ));
        assert!(!cmd.contains("for proj in \"$base\"/*"));
        // Base is canonicalized with `cd … && pwd -P` (defensive vs symlinks).
        assert!(cmd.contains("__rt=$(cd \"$base\" 2>/dev/null && pwd -P)"));
        // Defense-in-depth: the RESOLVED base must still be >=2 segments deep, so a
        // base that symlinks to `/` or a shallow root can never be swept (mirrors
        // the orchestrator-side guard; is_safe_reap_base alone permits 1 segment).
        assert!(cmd.contains("case \"$__rt\" in */*/*) ;; *)"));
        // The validated sync-root base is embedded.
        assert!(cmd.contains("base=\"/data/projects\""));
        // Only the per-job globs are matched.
        assert!(cmd.contains(".rch-target-*-job-*"));
        assert!(cmd.contains(".rch-target-*-pid-*"));
        // Shared idle predicate (no -type f) is present.
        assert!(cmd.contains("find \"$d\" -mmin -720 -print -quit"));
        assert!(!cmd.contains("-type f"));
        // Never a bare `target` glob.
        assert!(!cmd.contains("/target "));
        // Metrics counters survive the loop: the `while read` is fed from a temp
        // file (redirect-from-file, NOT the right side of a pipe → no subshell).
        assert!(cmd.contains("done < \"$__tmpf\""));
        assert!(!cmd.contains("-prune 2>/dev/null | \\\n"));
        assert!(!cmd.contains("-prune 2>/dev/null | while"));
        // Emits parseable metrics.
        assert!(cmd.contains("RCH_WORKER_REAP_METRICS"));
        // Exits cleanly if base is missing.
        assert!(cmd.contains("if [ ! -d \"$base\" ]"));
    }

    /// Run the generated sweep script under a real `sh` against a fabricated
    /// sync-root and assert which per-job dirs are reaped vs kept AND that the
    /// emitted metrics line reflects the actual removals. Linux/macOS only (needs
    /// `sh`, `find`, `du`, `mktemp`).
    #[cfg(unix)]
    #[test]
    fn sweep_script_reaps_idle_dirs_at_all_depths_and_keeps_live_and_empty() {
        use std::fs;
        use std::process::Command;
        use tempfile::tempdir;

        let tmp = tempdir().expect("create tmp root");
        let base = tmp.path().join("projects");
        fs::create_dir_all(&base).unwrap();

        // Helper: make a per-job dir at `path` with one file, then backdate the
        // whole subtree (via `touch -t`, portable across GNU/BSD) so it reads as
        // idle — well beyond the 12h window.
        let make_idle = |path: &std::path::Path| {
            fs::create_dir_all(path).unwrap();
            fs::write(path.join("artifact.o"), b"x").unwrap();
            let ok = Command::new("find")
                .arg(path)
                .args(["-exec", "touch", "-t", "202601010000", "{}", ";"])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            assert!(ok, "aging {path:?} should succeed");
        };

        // Depth 1 directly under base: <base>/.rch-target-…-job-…. Depth 2:
        // <base>/<repo>/.rch-target-…. Depth 3 (workspace member):
        // <base>/<repo>/crates/<member>/.rch-target-….
        let idle_d1 = base.join(".rch-target-w-job-1-1-0");
        let idle_d2 = base.join("repoA").join(".rch-target-w-job-2-2-0");
        let idle_d3 = base
            .join("repoB")
            .join("crates")
            .join("member")
            .join(".rch-target-w-pid-3-3-0");
        make_idle(&idle_d1);
        make_idle(&idle_d2);
        make_idle(&idle_d3);

        // A FRESH (recently-touched) per-job dir must be kept.
        let live = base.join("repoC").join(".rch-target-w-job-4-4-0");
        fs::create_dir_all(&live).unwrap();
        fs::write(live.join("fresh.o"), b"y").unwrap(); // current mtime → live

        // An EMPTY just-created per-job dir (mkdir but no first write) must be kept
        // (recent dir mtime, zero files — the v1.0.35 race case).
        let empty = base.join("repoD").join(".rch-target-w-pid-5-5-0");
        fs::create_dir_all(&empty).unwrap();

        // A non-rch sibling dir must never be considered.
        let bystander = base.join("repoE").join("target");
        fs::create_dir_all(&bystander).unwrap();
        make_idle(&bystander); // even idle, the glob must not match it

        let cmd = build_sweep_command(base.to_str().unwrap(), 720);
        let out = Command::new("sh").arg("-c").arg(&cmd).output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);

        // Idle dirs at every depth reaped.
        assert!(!idle_d1.exists(), "idle depth-1 dir should be reaped");
        assert!(!idle_d2.exists(), "idle depth-2 dir should be reaped");
        assert!(
            !idle_d3.exists(),
            "idle depth-3 workspace-member dir should be reaped"
        );
        // Live, empty, and the bystander `target` kept.
        assert!(live.exists(), "freshly-touched dir must be kept");
        assert!(empty.exists(), "empty just-created dir must be kept");
        assert!(bystander.exists(), "non-rch `target` must never be touched");

        // Metrics survive the loop: exactly 3 removals are reported.
        let m = parse_reap_metrics(&stdout).expect("metrics line present");
        assert_eq!(
            m.removed, 3,
            "metrics must count all 3 reaped dirs: {stdout}"
        );
        assert!(
            m.freed_bytes > 0,
            "freed bytes must be > 0 when dirs were removed: {stdout}"
        );
    }

    #[test]
    fn parse_metrics_reads_values() {
        let out = "noise\nRCH_WORKER_REAP_METRICS removed=3 freed_kb=2048\n";
        let m = parse_reap_metrics(out).expect("parse");
        assert_eq!(m.removed, 3);
        assert_eq!(m.freed_bytes, 2048 * 1024);
    }

    #[test]
    fn parse_metrics_missing_line() {
        assert!(parse_reap_metrics("no metrics\n").is_none());
    }

    #[test]
    fn config_default_is_off_and_conservative() {
        let c = StaleTargetReapConfig::default();
        // Ships default-OFF: an autonomous periodic deleter pointed at
        // /data/projects is opt-in until canary-soaked (carnage-history lesson).
        assert!(!c.enabled);
        assert_eq!(c.interval_mins, 120);
        assert_eq!(c.idle_hours, 12);
        // Default base is the remote repo sync-root (canonical project root),
        // where rch actually places per-job target dirs — NOT `/tmp/rch`.
        assert_eq!(c.remote_base, rch_common::DEFAULT_CANONICAL_PROJECT_ROOT);
        assert_eq!(c.remote_base, "/data/projects");
    }

    #[tokio::test]
    async fn cycle_skips_unhealthy_workers() {
        use rch_common::WorkerConfig;
        let pool = WorkerPool::new();
        let worker_id = WorkerId::new("w1");
        pool.add_worker(WorkerConfig {
            id: worker_id.clone(),
            host: "h".into(),
            user: "u".into(),
            identity_file: "/home/u/.ssh/id".into(),
            total_slots: 4,
            priority: 50,
            tags: vec![],
        })
        .await;
        // Newly-added workers default to `Healthy` (see `WorkerState::new`), so
        // force a non-healthy status to exercise the skip path: an Unreachable
        // worker must be skipped and no SSH attempted.
        pool.set_status(&worker_id, WorkerStatus::Unreachable).await;
        let reaper = StaleTargetReaper::new(pool, StaleTargetReapConfig::default());
        let stats = reaper.run_cycle().await;
        assert_eq!(stats.workers_checked, 1);
        assert_eq!(stats.workers_skipped, 1);
        assert_eq!(stats.workers_swept, 0);
        assert_eq!(stats.errors, 0);
    }
}
