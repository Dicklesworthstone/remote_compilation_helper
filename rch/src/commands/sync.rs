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
//! 2. Resolve each selected worker's staging base from its configured override
//!    or the global transfer fallback. Map every closure root below that base
//!    using the same project id as the transfer pipeline. Each worker's report
//!    includes its exact plan; an untargeted preview uses only the default base.
//! 3. Plan a safety-checked invalidation ([`plan_force_resync`]): every target
//!    must live strictly under the managed base, never the base itself, never
//!    an escaping `..` path. Canonical source mirrors (e.g. `/data/projects/x`)
//!    are therefore *refused*, never wiped — only RCH-managed cache is touched.
//! 4. Only when `--force` is given without `--dry-run` and the worker is
//!    reachable, invalidate under the worker's durable source transaction and
//!    retention/liveness gates. The managed directory is pinned as the shell's
//!    CWD, and only its verified immediate child can be removed. Confirm the
//!    removal and retirement receipt before requesting convergence repair.
//!    Default (no force, or dry-run) previews the lexical plan only.

use std::path::{Path, PathBuf};

use anyhow::Result;
use rch_common::force_resync::remote_invalidation_command;
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

/// Per-worker outcome of a force-resync.
#[derive(Debug, Clone, Serialize)]
struct SyncForceWorkerResult {
    worker_id: String,
    /// Exact staging namespace and paths selected for this worker.
    plan: ForceResyncPlan,
    reachable: bool,
    /// Applied, partially applied, refused, deferred, or preview.
    outcome: String,
    removed_ok: usize,
    already_absent: usize,
    remove_failures: Vec<String>,
    repair_triggered: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    repair_status: Option<String>,
}

/// The agent-facing force-resync report.
#[derive(Debug, Clone, Serialize)]
struct SyncForceResult {
    project: String,
    force: bool,
    dry_run: bool,
    /// True only when at least one worker confirmed a completed removal.
    applied: bool,
    closure_roots: Vec<String>,
    /// A default-root lexical preview when no worker was selected. A selected
    /// worker always carries its own exact plan instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    default_plan: Option<ForceResyncPlan>,
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

    // 2. Worker staging overrides resolve against this configured fallback.
    let config = load_config()?;

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

    // 4. Resolve and validate every selected namespace before the first SSH
    // operation. A worker override replaces its fallback; it never adds roots.
    let closure_roots = closure_roots_for(&project_root);
    let worker_plans = target_workers
        .iter()
        .map(|worker| plan_for_worker(worker, &closure_roots, &config.transfer))
        .collect::<Result<Vec<_>>>()?;
    let default_plan = if target_workers.is_empty() {
        let base =
            rch_common::types::validate_worker_remote_base(&config.transfer.remote_base, None)
                .map_err(anyhow::Error::msg)?;
        let base = PathBuf::from(base);
        Some(plan_force_resync(
            &stale_roots_for(&closure_roots, &base),
            &base,
        ))
    } else {
        None
    };

    // 5. Apply (or preview) each worker's independently resolved plan.
    let mut worker_results = Vec::with_capacity(target_workers.len());
    for (worker, plan) in target_workers.iter().zip(worker_plans) {
        worker_results.push(apply_on_worker(worker, plan, is_apply).await);
    }

    // 6. Assemble + render.
    let result = SyncForceResult {
        project: project_root.display().to_string(),
        force,
        dry_run,
        applied: worker_results.iter().any(|worker| worker.removed_ok > 0),
        closure_roots: closure_roots
            .iter()
            .map(|root| root.display().to_string())
            .collect(),
        default_plan,
        workers: worker_results,
    };

    if !ctx.is_json() {
        render_human(&result, ctx);
    }
    if apply_failed(&result) {
        return Err(crate::GcFailure {
            command: "sync",
            data: serde_json::to_value(&result)?,
            api_error: rch_common::ApiError::from_code(rch_common::ErrorCode::WorkerReclaimFailed)
                .with_details(
                    "force-resync incomplete; inspect per-worker refusals and confirmed removals",
                ),
            format: ctx.format(),
        }
        .into());
    }
    ctx.json(&ApiResponse::ok("sync", &result))?;
    Ok(())
}

fn apply_failed(result: &SyncForceResult) -> bool {
    result.force
        && !result.dry_run
        && result
            .workers
            .iter()
            .any(|worker| worker.outcome != "applied" || worker.plan.has_refusals())
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

#[derive(Debug, PartialEq, Eq)]
enum InvalidationReceipt {
    Removed,
    Absent,
}

fn invalidation_receipt(stdout: &str) -> Result<InvalidationReceipt> {
    let receipts: Vec<_> = stdout
        .lines()
        .filter(|line| line.starts_with("RCH_SYNC_INVALIDATED "))
        .collect();
    anyhow::ensure!(
        receipts.len() == 1 && stdout.ends_with(&format!("{}\n", receipts[0])),
        "worker did not confirm one completed invalidation and retirement"
    );
    match receipts[0] {
        "RCH_SYNC_INVALIDATED removed" => Ok(InvalidationReceipt::Removed),
        "RCH_SYNC_INVALIDATED absent" => Ok(InvalidationReceipt::Absent),
        _ => anyhow::bail!("worker returned an unrecognized invalidation receipt"),
    }
}

fn plan_for_worker(
    worker: &WorkerConfig,
    roots: &[PathBuf],
    configured: &rch_common::TransferConfig,
) -> Result<ForceResyncPlan> {
    let selected = crate::staging_transfer_config_for_worker(worker, configured)?;
    let base = PathBuf::from(selected.remote_base);
    Ok(plan_force_resync(&stale_roots_for(roots, &base), &base))
}

/// Probe + (optionally) apply the invalidation on one worker.
async fn apply_on_worker(
    worker: &WorkerConfig,
    plan: ForceResyncPlan,
    is_apply: bool,
) -> SyncForceWorkerResult {
    if is_apply && crate::transfer::WorkerPlatform::from_worker(worker).is_windows() {
        return SyncForceWorkerResult {
            worker_id: worker.id.0.clone(),
            plan,
            reachable: false,
            outcome: "refused".into(),
            removed_ok: 0,
            already_absent: 0,
            remove_failures: vec![
                "force-resync requires the POSIX source-ownership protocol; Windows invalidation is unsupported".into(),
            ],
            repair_triggered: false,
            repair_status: None,
        };
    }
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(300);
    let mut output_budget = crate::GC_OUTPUT_LIMIT;
    // One worker budget covers reachability and every invalidation. Streaming
    // SSH retains local child custody and a bounded stdout/stderr aggregate.
    let reachable =
        match crate::run_gc_surface_command(worker, "true", deadline, &mut output_budget).await {
            Ok(out) => out.success(),
            Err(_) => false,
        };
    let managed_base = &plan.managed_base;
    let report = apply_force_resync(&plan, reachable);
    let mut removed_ok = 0usize;
    let mut already_absent = 0usize;
    let mut remove_failures = Vec::new();
    let mut repair_triggered = false;
    let mut repair_status = None;

    if is_apply && reachable {
        for path in &report.invalidated {
            if !is_safe_invalidation_target(path, managed_base) {
                remove_failures.push(format!(
                    "{} (refused at SSH boundary: not strictly under managed base)",
                    path.display()
                ));
                continue;
            }
            let command = match remote_invalidation_command(path, managed_base) {
                Ok(command) => command,
                Err(error) => {
                    remove_failures.push(format!("{} ({error})", path.display()));
                    continue;
                }
            };
            match crate::run_gc_surface_command(worker, &command, deadline, &mut output_budget)
                .await
            {
                Ok(out) if out.success() => match invalidation_receipt(&out.stdout) {
                    Ok(InvalidationReceipt::Removed) => removed_ok += 1,
                    Ok(InvalidationReceipt::Absent) => already_absent += 1,
                    Err(error) => {
                        remove_failures.push(format!("{} ({error})", path.display()));
                    }
                },
                Ok(out) => {
                    remove_failures.push(format!(
                        "{} (exit {}: {})",
                        path.display(),
                        out.exit_code,
                        out.stderr.trim()
                    ));
                }
                Err(error) => {
                    remove_failures.push(format!("{} (ssh error: {error})", path.display()));
                }
            }
        }

        // The next build also resyncs naturally. Never claim this repair step
        // after any selected cache failed its guarded invalidation.
        if remove_failures.is_empty() && !plan.has_refusals() {
            let (triggered, status) = trigger_repair(worker).await;
            repair_triggered = triggered;
            repair_status = status;
        }
    }

    let outcome = if !is_apply {
        "preview"
    } else if reachable && remove_failures.is_empty() && !plan.has_refusals() {
        "applied"
    } else if removed_ok > 0 {
        "partially_applied"
    } else if reachable {
        "refused"
    } else {
        "deferred_worker_unavailable"
    };

    SyncForceWorkerResult {
        worker_id: worker.id.0.clone(),
        plan,
        reachable,
        outcome: outcome.to_string(),
        removed_ok,
        already_absent,
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
    let mode = if result.force && !result.dry_run {
        style.warning("APPLY (destructive)")
    } else {
        style.info("preview (no destructive action)")
    };
    println!("  {} {}", style.key("mode:"), mode);
    println!(
        "  {} {}",
        style.key("closure roots:"),
        style.value(&result.closure_roots.len().to_string()),
    );

    let render_plan = |plan: &ForceResyncPlan| {
        println!(
            "    {} {}",
            style.key("managed base:"),
            style.value(&plan.managed_base.display().to_string())
        );
        println!(
            "    {} {} planned invalidation(s), {} refused",
            style.key("plan:"),
            style.value(&plan.invalidations.len().to_string()),
            style.value(&plan.refused.len().to_string()),
        );
        for action in &plan.invalidations {
            println!(
                "      {} {}",
                style.muted("invalidate:"),
                action.worker_cache_path.display()
            );
        }
        for refused in &plan.refused {
            println!(
                "      {} {} ({})",
                style.error("REFUSED:"),
                refused.worker_cache_path.display(),
                style.muted(&refused.reason)
            );
        }
    };

    if result.workers.is_empty() {
        if let Some(plan) = &result.default_plan {
            println!("  {}", style.key("default staging preview:"));
            render_plan(plan);
        }
        println!(
            "  {}",
            style.muted("no target worker selected (use --worker <id> or --all to act)")
        );
        return;
    }

    for worker in &result.workers {
        let status = match worker.outcome.as_str() {
            "applied" => style.success(&format!(
                "applied ({} removed, {} already absent)",
                worker.removed_ok, worker.already_absent
            )),
            "partially_applied" => style.warning(&format!(
                "partially applied ({} removed, {} failed)",
                worker.removed_ok,
                worker.remove_failures.len()
            )),
            "refused" => style.error("refused (no confirmed removal)"),
            "deferred_worker_unavailable" => style.warning("deferred (worker unreachable)"),
            _ => style.info("preview"),
        };
        println!(
            "  {} {}",
            style.key(&format!("{}:", worker.worker_id)),
            status
        );
        render_plan(&worker.plan);
        for failure in &worker.remove_failures {
            println!("      {} {}", style.error("remove failed:"), failure);
        }
        if let Some(repair) = &worker.repair_status {
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

    #[cfg(unix)]
    #[test]
    fn worker_plans_match_the_real_cache_warm_destinations() {
        let roots = vec![
            PathBuf::from("/data/projects/primary"),
            PathBuf::from("/data/projects/dependency"),
        ];
        let configured = rch_common::TransferConfig {
            remote_base: "/var/cache/rch-default".into(),
            ..Default::default()
        };
        let mut plans = Vec::new();
        for (id, root, expected) in [
            ("default", None, "/var/cache/rch-default"),
            ("first", Some("/mnt/worker-one/rch"), "/mnt/worker-one/rch"),
            (
                "second",
                Some("/Volumes/Build Disk/$HOME/'quoted/rch///"),
                "/Volumes/Build Disk/$HOME/'quoted/rch",
            ),
        ] {
            let worker = WorkerConfig {
                id: rch_common::WorkerId::new(id),
                remote_base: root.map(str::to_owned),
                ..Default::default()
            };
            let plan = plan_for_worker(&worker, &roots, &configured).unwrap();
            assert_eq!(plan.managed_base, Path::new(expected));
            assert!(!plan.has_refusals());
            assert_eq!(plan.invalidations.len(), roots.len());
            for (root, action) in roots.iter().zip(&plan.invalidations) {
                let pipeline = crate::cache_warm_pipeline(
                    root,
                    &project_id_from_path(root),
                    "0123456789abcdef",
                    &configured,
                    &worker,
                    0,
                )
                .unwrap();
                let destination = PathBuf::from(pipeline.remote_path());
                assert_eq!(
                    destination.parent().unwrap(),
                    action.worker_cache_path.as_path(),
                    "force-resync must invalidate the parent containing this worker's warmed hash"
                );
                assert!(
                    remote_invalidation_command(&action.worker_cache_path, &plan.managed_base)
                        .is_ok(),
                    "the exact selected literal scope must pass the guarded command builder"
                );
            }
            plans.push(plan);
        }
        assert_ne!(
            plans[1].invalidations[0].worker_cache_path,
            plans[2].invalidations[0].worker_cache_path
        );
        assert_eq!(configured.remote_base, "/var/cache/rch-default");
    }

    #[test]
    fn worker_plans_reject_invalid_roots_before_dispatch() {
        let roots = [PathBuf::from("/data/projects/demo")];
        for root in ["~/rch", "/tmp", "/mnt/rch/../outside", "/mnt/build\nrch"] {
            let worker = WorkerConfig {
                id: rch_common::WorkerId::new("invalid-root"),
                remote_base: Some(root.into()),
                ..Default::default()
            };
            assert!(
                plan_for_worker(&worker, &roots, &Default::default()).is_err(),
                "{root:?}"
            );
        }
        let invalid_fallback = rch_common::TransferConfig {
            remote_base: "/".into(),
            ..Default::default()
        };
        assert!(plan_for_worker(&Default::default(), &roots, &invalid_fallback).is_err());
    }

    #[tokio::test]
    async fn windows_apply_preserves_the_native_preview_scope_and_refuses_before_transport() {
        let worker = WorkerConfig {
            id: rch_common::WorkerId::new("windows"),
            host: "must-not-contact.invalid".into(),
            tags: vec!["os:windows".into()],
            ..Default::default()
        };
        let roots = [PathBuf::from("/data/projects/demo")];
        let plan = plan_for_worker(&worker, &roots, &Default::default()).unwrap();
        assert_eq!(plan.managed_base, Path::new("C:/rch"));
        let result = apply_on_worker(&worker, plan, true).await;
        assert_eq!(result.outcome, "refused");
        assert_eq!(result.plan.managed_base, Path::new("C:/rch"));
        assert_eq!(result.removed_ok, 0);
        assert_eq!(result.already_absent, 0);
        assert!(!result.repair_triggered);
        assert!(!result.reachable);
        assert!(result.remove_failures[0].contains("Windows invalidation is unsupported"));
    }

    #[test]
    fn invalidation_rejects_scope_changes_before_worker_dispatch() {
        for (base, target) in [
            ("/", "/project"),
            ("relative/base", "relative/base/project"),
            ("/tmp/rch", "/tmp/rch"),
            ("/tmp/rch", "/tmp/rch/project/nested"),
            ("/tmp/rch", "/tmp/rch/../outside"),
            ("/tmp/rch", "/tmp/other/project"),
        ] {
            assert!(
                remote_invalidation_command(Path::new(target), Path::new(base)).is_err(),
                "{base:?} {target:?}"
            );
        }
    }

    #[test]
    fn invalidation_requires_one_final_retirement_receipt() {
        assert_eq!(
            invalidation_receipt("RCH_GC_GATES handles=1 procs=1\nRCH_SYNC_INVALIDATED removed\n")
                .unwrap(),
            InvalidationReceipt::Removed
        );
        assert_eq!(
            invalidation_receipt("RCH_SYNC_INVALIDATED absent\n").unwrap(),
            InvalidationReceipt::Absent
        );
        for output in [
            "",
            "RCH_SYNC_INVALIDATED removed",
            "RCH_SYNC_INVALIDATED removed\npartial\n",
            "RCH_SYNC_INVALIDATED removed\nRCH_SYNC_INVALIDATED removed\n",
            "RCH_SYNC_INVALIDATED unknown\n",
        ] {
            assert!(invalidation_receipt(output).is_err(), "{output:?}");
        }
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
    fn result_serializes_worker_scopes_and_preserves_guarded_apply_failures() {
        let roots = [PathBuf::from("/data/projects/x")];
        let first_plan =
            plan_force_resync(&stale_roots_for(&roots, Path::new(BASE)), Path::new(BASE));
        let second_base = Path::new("/mnt/second/rch");
        let second_plan = plan_force_resync(&stale_roots_for(&roots, second_base), second_base);
        let mut second = SyncForceWorkerResult {
            worker_id: "second".into(),
            plan: second_plan,
            reachable: true,
            outcome: "applied".into(),
            removed_ok: 1,
            already_absent: 0,
            remove_failures: vec![],
            repair_triggered: true,
            repair_status: Some("ok".into()),
        };
        let first = SyncForceWorkerResult {
            worker_id: "first".into(),
            plan: first_plan.clone(),
            ..second.clone()
        };
        second.removed_ok = 0;
        second.already_absent = 1;
        let result = SyncForceResult {
            project: "/data/projects/x".into(),
            force: true,
            dry_run: false,
            applied: true,
            closure_roots: vec!["/data/projects/x".into()],
            default_plan: None,
            workers: vec![first, second],
        };
        let json = serde_json::to_value(&result).expect("serializes");
        assert_eq!(json["applied"], true);
        assert!(json.get("managed_base").is_none());
        assert!(json.get("default_plan").is_none());
        assert_eq!(json["workers"][0]["plan"]["managed_base"], BASE);
        assert_eq!(
            json["workers"][1]["plan"]["managed_base"],
            "/mnt/second/rch"
        );
        assert_ne!(
            json["workers"][0]["plan"]["invalidations"][0]["worker_cache_path"],
            json["workers"][1]["plan"]["invalidations"][0]["worker_cache_path"]
        );
        assert_eq!(json["workers"][0]["outcome"], "applied");
        assert_eq!(json["workers"][0]["removed_ok"], 1);
        assert_eq!(json["workers"][0]["repair_status"], "ok");
        assert_eq!(json["workers"][1]["already_absent"], 1);
        assert!(!apply_failed(&result));

        // The live output boundary uses this same decision before emitting a
        // JSON success envelope, retaining all partial per-worker evidence.
        let mut result = result;
        for outcome in [
            "refused",
            "partially_applied",
            "deferred_worker_unavailable",
        ] {
            result.workers[0].outcome = outcome.into();
            assert!(apply_failed(&result), "{outcome}");
        }
        result.workers[0].outcome = "applied".into();
        result.workers[0]
            .plan
            .refused
            .push(rch_common::force_resync::RefusedInvalidation {
                local_root: "/data/projects/y".into(),
                worker_cache_path: "/outside".into(),
                reason: "outside managed base".into(),
            });
        assert!(apply_failed(&result));
        result.dry_run = true;
        assert!(!apply_failed(&result));

        result.force = false;
        result.applied = false;
        result.workers.clear();
        result.default_plan = Some(first_plan);
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["default_plan"]["managed_base"], BASE);
        assert_eq!(json["workers"], serde_json::json!([]));
        assert!(!apply_failed(&result));
    }
}
