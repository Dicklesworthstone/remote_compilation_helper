//! `rch sync --force`: agent-safe force-resync of stale path-dependency roots.
//!
//! This wires the pure planner in [`rch_common::force_resync`] to the real SSH
//! pool and daemon. It is the one supported command an agent runs when stale
//! worker-side caches block verification (bd-apg5l, consuming
//! bd-session-history-remediation-ocv9i.8.3).
//!
//! Flow:
//! 1. Resolve the target project's path-dependency closure
//!    ([`build_dependency_closure_plan`]). The closure is fail-open: a
//!    non-Cargo or unresolvable project degrades to invalidating just the
//!    target root, never an error.
//! 2. Map every closure root to its RCH-managed worker cache path under the
//!    configured `transfer.remote_base` (`<remote_base>/<project_id>`), the
//!    same id the transfer pipeline uses (`project_id_from_path`).
//! 3. Plan a safety-checked invalidation ([`plan_force_resync`]): every target
//!    must live strictly under the managed base, never the base itself, never
//!    an escaping `..` path. Canonical source mirrors (e.g. `/data/projects/x`)
//!    are therefore *refused*, never wiped — only RCH-managed cache is touched.
//! 4. Only when `--force` is given without `--dry-run` and the worker is
//!    reachable, apply a safety-**re-checked** recursive remove over SSH
//!    ([`apply_force_resync`] decides; `is_safe_invalidation_target` re-gates
//!    each path at the SSH boundary), then trigger a daemon-driven convergence
//!    repair so the closure re-syncs. Default (no `--force`, or `--dry-run`) is
//!    a safe preview that takes no destructive action.

use std::path::{Path, PathBuf};

use anyhow::Result;
use rch_common::{
    ApiResponse, ForceResyncPlan, StaleRoot, WorkerConfig, apply_force_resync,
    build_dependency_closure_plan, is_safe_invalidation_target, plan_force_resync,
};
use serde::Serialize;

use crate::config::load_config;
use crate::transfer::project_id_from_path;
use crate::ui::context::OutputContext;

use super::load_workers_from_config;
use super::send_daemon_command;
use super::workers_setup::run_worker_ssh_command;

/// A refused invalidation surfaced to the agent (cache path escaped the base).
#[derive(Debug, Clone, Serialize)]
struct RefusedEntry {
    local_root: String,
    worker_cache_path: String,
    reason: String,
}

/// Per-worker outcome of a force-resync.
#[derive(Debug, Clone, Serialize)]
struct SyncForceWorkerResult {
    worker_id: String,
    reachable: bool,
    /// `applied`, `deferred_worker_unavailable`, or `preview`.
    outcome: String,
    removed_ok: usize,
    remove_failures: Vec<String>,
    repair_triggered: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    repair_status: Option<String>,
}

/// The agent-facing force-resync report.
#[derive(Debug, Clone, Serialize)]
struct SyncForceResult {
    project: String,
    managed_base: String,
    force: bool,
    dry_run: bool,
    /// True only when `force && !dry_run` — i.e. destructive action was taken.
    applied: bool,
    closure_roots: Vec<String>,
    /// RCH-managed cache paths that were (or, in preview, would be) invalidated.
    planned_invalidations: Vec<String>,
    refused: Vec<RefusedEntry>,
    workers: Vec<SyncForceWorkerResult>,
}

/// Entry point for `rch sync`.
///
/// `force` gates the destructive invalidation; without it (or with `dry_run`)
/// the command only previews the plan. `project` defaults to the current
/// directory. Worker selection requires `--worker <id>` or `--all` before any
/// destructive action is taken.
pub async fn sync_force(
    force: bool,
    worker: Option<String>,
    all: bool,
    project: Option<PathBuf>,
    dry_run: bool,
    ctx: &OutputContext,
) -> Result<()> {
    let is_apply = force && !dry_run;

    // 1. Resolve the target project root (canonicalize so ids match the
    //    closure planner's canonical topology resolution).
    let project_root = project.unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    let project_root = std::fs::canonicalize(&project_root).unwrap_or(project_root);

    // 2. Managed base from config (the only root under which we ever delete).
    let config = load_config()?;
    let managed_base = PathBuf::from(config.transfer.remote_base.trim_end_matches('/'));

    // 3. Select target workers and validate the request *before* doing any
    //    (potentially expensive) closure resolution.
    let workers = load_workers_from_config()?;
    let target_workers: Vec<WorkerConfig> = if all {
        workers
    } else if let Some(id) = worker.as_deref() {
        workers.into_iter().filter(|w| w.id.0 == id).collect()
    } else {
        Vec::new()
    };

    // A specific worker was named but not found in config — a usage error.
    if !all && worker.is_some() && target_workers.is_empty() {
        anyhow::bail!(
            "worker '{}' is not configured in workers.toml",
            worker.as_deref().unwrap_or("")
        );
    }

    // Applying without a target worker is a usage error (never silently a
    // no-op): we refuse rather than pretend something was invalidated.
    if is_apply && target_workers.is_empty() {
        anyhow::bail!("force-resync requires an explicit target: pass --worker <id> or --all");
    }

    // 4. Closure roots -> stale roots -> safety-checked plan.
    let closure_roots = closure_roots_for(&project_root);
    let stale_roots = stale_roots_for(&closure_roots, &managed_base);
    let plan = plan_force_resync(&stale_roots, &managed_base);

    // 5. Apply (or preview) per worker.
    let mut worker_results = Vec::with_capacity(target_workers.len());
    for w in &target_workers {
        worker_results.push(apply_on_worker(w, &plan, &managed_base, is_apply).await);
    }

    // 6. Assemble + render.
    let result = SyncForceResult {
        project: project_root.display().to_string(),
        managed_base: managed_base.display().to_string(),
        force,
        dry_run,
        applied: is_apply,
        closure_roots: closure_roots
            .iter()
            .map(|r| r.display().to_string())
            .collect(),
        planned_invalidations: plan
            .invalidations
            .iter()
            .map(|a| a.worker_cache_path.display().to_string())
            .collect(),
        refused: plan
            .refused
            .iter()
            .map(|r| RefusedEntry {
                local_root: r.local_root.display().to_string(),
                worker_cache_path: r.worker_cache_path.display().to_string(),
                reason: r.reason.clone(),
            })
            .collect(),
        workers: worker_results,
    };

    let _ = ctx.json(&ApiResponse::ok("sync", &result));
    if ctx.is_json() {
        return Ok(());
    }

    render_human(&result, ctx);
    Ok(())
}

/// Resolve the path-dependency closure roots for `project_root`. Fail-open: an
/// empty/unresolvable closure degrades to just the target root, and the target
/// root is always included so a single-crate project still force-resyncs.
fn closure_roots_for(project_root: &Path) -> Vec<PathBuf> {
    let plan = build_dependency_closure_plan(project_root);
    let mut roots = plan.sync_roots();
    if !roots.iter().any(|r| r == project_root) {
        roots.insert(0, project_root.to_path_buf());
    }
    // Stable de-dup, preserving first-seen (sync) order.
    let mut seen = std::collections::BTreeSet::new();
    roots.retain(|r| seen.insert(r.clone()));
    roots
}

/// Map each closure root to the RCH-managed worker cache path the transfer
/// pipeline uses (`<managed_base>/<project_id>`). Always strictly under the
/// managed base, so `plan_force_resync` admits them.
fn stale_roots_for(roots: &[PathBuf], managed_base: &Path) -> Vec<StaleRoot> {
    roots
        .iter()
        .map(|root| StaleRoot {
            local_root: root.clone(),
            worker_cache_path: managed_base.join(project_id_from_path(root)),
        })
        .collect()
}

/// Single-quote a string for safe interpolation into a remote shell command.
fn shell_single_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// The remote command that removes a safety-checked cache path. `--` guards
/// against any leading-dash interpretation; the path is single-quoted.
fn remote_rm_command(path: &Path) -> String {
    format!("rm -rf -- {}", shell_single_quote(&path.to_string_lossy()))
}

/// Probe + (optionally) apply the invalidation on one worker.
async fn apply_on_worker(
    worker: &WorkerConfig,
    plan: &ForceResyncPlan,
    managed_base: &Path,
    is_apply: bool,
) -> SyncForceWorkerResult {
    // Reachability probe (also gates apply_force_resync's deferral decision).
    let reachable = match run_worker_ssh_command(worker, "true").await {
        Ok(out) => out.status.success(),
        Err(_) => false,
    };

    // The pure module decides what (if anything) is safe to invalidate.
    let report = apply_force_resync(plan, reachable);

    let mut removed_ok = 0usize;
    let mut remove_failures = Vec::new();
    let mut repair_triggered = false;
    let mut repair_status = None;

    if is_apply && reachable {
        for path in &report.invalidated {
            // Defense-in-depth: never rm a path that is not strictly under the
            // managed base, even though plan_force_resync already gated it.
            if !is_safe_invalidation_target(path, managed_base) {
                remove_failures.push(format!(
                    "{} (refused at SSH boundary: not strictly under managed base)",
                    path.display()
                ));
                continue;
            }
            let cmd = remote_rm_command(path);
            match run_worker_ssh_command(worker, &cmd).await {
                Ok(out) if out.status.success() => removed_ok += 1,
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    remove_failures.push(format!(
                        "{} (exit {}: {})",
                        path.display(),
                        out.status.code().unwrap_or(-1),
                        stderr.trim()
                    ));
                }
                Err(e) => {
                    remove_failures.push(format!("{} (ssh error: {e})", path.display()));
                }
            }
        }

        // Trigger a daemon-driven convergence repair so the closure re-syncs.
        // Best-effort: the next build re-syncs naturally even if this fails.
        let (triggered, status) = trigger_repair(worker).await;
        repair_triggered = triggered;
        repair_status = status;
    }

    let outcome = if !is_apply {
        "preview"
    } else if reachable {
        "applied"
    } else {
        "deferred_worker_unavailable"
    };

    SyncForceWorkerResult {
        worker_id: worker.id.0.clone(),
        reachable,
        outcome: outcome.to_string(),
        removed_ok,
        remove_failures,
        repair_triggered,
        repair_status,
    }
}

/// Ask the daemon to reset convergence for `worker` so the closure re-syncs.
async fn trigger_repair(worker: &WorkerConfig) -> (bool, Option<String>) {
    let command = format!(
        "POST /repo-convergence/repair?worker={}\n",
        urlencoding::encode(&worker.id.0)
    );
    match send_daemon_command(&command).await {
        Ok(resp) => {
            let ok = resp.contains("\"status\":\"ok\"") || resp.contains("\"status\": \"ok\"");
            let status = if ok {
                "ok".to_string()
            } else {
                format!("non-ok: {}", resp.trim())
            };
            (true, Some(status))
        }
        Err(e) => (false, Some(format!("repair request failed: {e}"))),
    }
}

fn render_human(result: &SyncForceResult, ctx: &OutputContext) {
    let style = ctx.style();
    println!("{}", style.format_header("Force Resync"));
    println!(
        "  {} {}",
        style.key("project:"),
        style.value(&result.project)
    );
    println!(
        "  {} {}",
        style.key("managed base:"),
        style.value(&result.managed_base)
    );
    let mode = if result.applied {
        style.warning("APPLY (destructive)")
    } else {
        style.info("preview (no destructive action)")
    };
    println!("  {} {}", style.key("mode:"), mode);

    println!(
        "  {} {} closure root(s), {} planned invalidation(s), {} refused",
        style.key("plan:"),
        style.value(&result.closure_roots.len().to_string()),
        style.value(&result.planned_invalidations.len().to_string()),
        style.value(&result.refused.len().to_string()),
    );
    for path in &result.planned_invalidations {
        println!("    {} {}", style.muted("invalidate:"), path);
    }
    for refused in &result.refused {
        println!(
            "    {} {} ({})",
            style.error("REFUSED:"),
            refused.worker_cache_path,
            style.muted(&refused.reason)
        );
    }

    if result.workers.is_empty() {
        println!(
            "  {}",
            style.muted("no target worker selected (use --worker <id> or --all to act)")
        );
        return;
    }

    for w in &result.workers {
        let status = match w.outcome.as_str() {
            "applied" => style.success(&format!(
                "applied ({} removed, {} failed)",
                w.removed_ok,
                w.remove_failures.len()
            )),
            "deferred_worker_unavailable" => style.warning("deferred (worker unreachable)"),
            _ => style.info("preview"),
        };
        println!("  {} {}", style.key(&format!("{}:", w.worker_id)), status);
        for failure in &w.remove_failures {
            println!("      {} {}", style.error("remove failed:"), failure);
        }
        if let Some(repair) = &w.repair_status {
            println!("      {} {}", style.muted("convergence repair:"), repair);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "/tmp/rch";

    #[test]
    fn stale_roots_map_under_managed_base_and_are_safe() {
        let base = Path::new(BASE);
        let roots = vec![
            PathBuf::from("/data/projects/alpha"),
            PathBuf::from("/data/projects/beta"),
        ];
        let stale = stale_roots_for(&roots, base);
        assert_eq!(stale.len(), 2);
        for s in &stale {
            assert!(
                s.worker_cache_path.starts_with(base),
                "{} should be under {}",
                s.worker_cache_path.display(),
                base.display()
            );
            assert_ne!(s.worker_cache_path, base.to_path_buf());
            assert!(
                is_safe_invalidation_target(&s.worker_cache_path, base),
                "mapped cache path must always be a safe invalidation target"
            );
        }
        // Distinct local roots map to distinct cache paths.
        assert_ne!(stale[0].worker_cache_path, stale[1].worker_cache_path);
    }

    #[test]
    fn plan_over_mapped_roots_never_refuses() {
        // Because every mapping lands strictly under the managed base, the
        // plan admits all of them — refusals only happen for caller-supplied
        // escaping paths, which this command never constructs.
        let base = Path::new(BASE);
        let roots = vec![PathBuf::from("/data/projects/a"), PathBuf::from("/dp/b")];
        let stale = stale_roots_for(&roots, base);
        let plan = plan_force_resync(&stale, base);
        assert_eq!(plan.invalidations.len(), 2);
        assert!(!plan.has_refusals());
    }

    #[test]
    fn shell_single_quote_escapes_embedded_quote() {
        assert_eq!(shell_single_quote("abc"), "'abc'");
        assert_eq!(shell_single_quote("a b"), "'a b'");
        // The classic single-quote escape: ' -> '\''
        assert_eq!(shell_single_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn remote_rm_command_is_quoted_and_guarded() {
        let cmd = remote_rm_command(Path::new("/tmp/rch/myproj"));
        assert_eq!(cmd, "rm -rf -- '/tmp/rch/myproj'");
        // A path with a space stays a single shell token.
        let cmd = remote_rm_command(Path::new("/tmp/rch/my proj"));
        assert_eq!(cmd, "rm -rf -- '/tmp/rch/my proj'");
        // Always has the -- option terminator before the path.
        assert!(cmd.contains(" -- '"));
    }

    #[test]
    fn closure_roots_always_includes_target_root() {
        // A directory with no Cargo.toml fails open to just the target root.
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(tmp.path()).unwrap_or_else(|_| tmp.path().to_path_buf());
        let roots = closure_roots_for(&root);
        assert!(
            roots.iter().any(|r| r == &root),
            "closure must always include the target root, got {roots:?}"
        );
    }

    #[test]
    fn closure_roots_are_deduped() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(tmp.path()).unwrap_or_else(|_| tmp.path().to_path_buf());
        let roots = closure_roots_for(&root);
        let mut sorted = roots.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), roots.len(), "closure roots must be unique");
    }

    #[test]
    fn result_serializes_with_expected_shape() {
        let result = SyncForceResult {
            project: "/data/projects/x".to_string(),
            managed_base: BASE.to_string(),
            force: true,
            dry_run: false,
            applied: true,
            closure_roots: vec!["/data/projects/x".to_string()],
            planned_invalidations: vec!["/tmp/rch/x".to_string()],
            refused: vec![],
            workers: vec![SyncForceWorkerResult {
                worker_id: "css".to_string(),
                reachable: true,
                outcome: "applied".to_string(),
                removed_ok: 1,
                remove_failures: vec![],
                repair_triggered: true,
                repair_status: Some("ok".to_string()),
            }],
        };
        let json = serde_json::to_value(&result).expect("serializes");
        assert_eq!(json["applied"], true);
        assert_eq!(json["managed_base"], BASE);
        assert_eq!(json["workers"][0]["outcome"], "applied");
        assert_eq!(json["workers"][0]["removed_ok"], 1);
        assert_eq!(json["workers"][0]["repair_status"], "ok");
    }
}
