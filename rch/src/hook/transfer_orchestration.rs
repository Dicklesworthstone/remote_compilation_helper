//! Transfer / remote-execution orchestration for the hook.
//!
//! This submodule owns the remote-build execution pipeline: `execute_remote_compilation`
//! — which syncs the project to a worker, runs the command remotely with a
//! streaming heartbeat, and retrieves artifacts back — together with the leaf
//! telemetry-forwarding helpers it drives (wrapping the remote command so it
//! piggybacks worker telemetry on stdout, and the two daemon-IPC POST helpers
//! that forward the collected `WorkerTelemetry` / `TestRunRecord` back to the
//! local daemon).
//!
//! It reaches its support layer from the parent via `use super::*`: the
//! sync-topology / dependency-manifest helpers, `HookReporter`, and the
//! `rch_common` types/consts. The offload SSH primitives now live in the sibling
//! `ssh` submodule — this module drives the remote topology preflight via
//! `ensure_worker_projects_topology`, imported explicitly below. The build
//! heartbeat (`progress_reporting`) and the repo_updater pre-sync entry point
//! (`repo_updater`) likewise live in sibling submodules and are imported below.
//!
//! `execute_remote_compilation` is `pub(super)` (its only non-test callers,
//! `run_hook`/`run_exec`, are re-exported into `hook`); `wrap_command_with_telemetry`
//! stays `pub(super)` for the hook test suite; the two daemon-IPC POST helpers
//! are private to this module.

use super::artifact_patterns::{
    get_artifact_patterns, get_custom_target_artifact_patterns,
    kind_produces_transferable_artifacts,
};
use super::cargo_target_dir::{
    cargo_target_env_allowlist, cargo_target_env_overrides, remote_cargo_pooled_target_dir_name,
    remote_cargo_target_dir_name, stale_target_reap_idle_hours, target_reuse_disabled,
};
use super::daemon_ipc::urlencoding_encode;
use super::dependency_closure::{
    SyncClosureMode, SyncClosurePlanEntry, SyncRootOutcome, build_sync_closure_manifest,
    build_sync_closure_plan, merge_sync_result, verify_remote_dependency_manifests,
    workspace_metadata_sync_patterns,
};
use super::progress_reporting::{BuildHeartbeatLoop, mark_heartbeat_progress};
use super::remote_result::RemoteExecutionResult;
use super::repo_updater::maybe_sync_repo_set_with_repo_updater;
use super::ssh::ensure_worker_projects_topology;
use super::*;

pub(super) fn wrap_command_with_telemetry(command: &str, worker_id: &WorkerId) -> String {
    let escaped_worker = shell_escape::escape(worker_id.as_str().into());
    // Use newline instead of semicolon to ensure trailing comments in command
    // don't comment out the status capture logic.
    format!(
        "{cmd}\nstatus=$?; if command -v rch-telemetry >/dev/null 2>&1; then \
         telemetry=$(rch-telemetry collect --format json --worker-id {worker} 2>/dev/null || true); \
         if [ -n \"$telemetry\" ]; then echo '{marker}'; echo \"$telemetry\"; fi; \
         fi; exit $status",
        cmd = command,
        worker = escaped_worker,
        marker = PIGGYBACK_MARKER
    )
}

async fn send_telemetry(
    socket_path: &str,
    source: TelemetrySource,
    telemetry: &WorkerTelemetry,
) -> anyhow::Result<()> {
    if !Path::new(socket_path).exists() {
        return Ok(());
    }

    let stream = match timeout(Duration::from_secs(2), UnixStream::connect(socket_path)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Ok(()), // Timeout connecting — don't block hook
    };
    let (reader, mut writer) = stream.into_split();

    let body = telemetry.to_json()?;
    let request = format!(
        "POST /telemetry/ingest?source={}\n{}\n",
        urlencoding_encode(&source.to_string()),
        body
    );

    writer.write_all(request.as_bytes()).await?;
    writer.flush().await?;
    writer.shutdown().await?;

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let _ = timeout(Duration::from_secs(5), reader.read_line(&mut line)).await;

    Ok(())
}

async fn send_test_run(socket_path: &str, record: &TestRunRecord) -> anyhow::Result<()> {
    if !Path::new(socket_path).exists() {
        return Ok(());
    }

    let stream = match timeout(Duration::from_secs(2), UnixStream::connect(socket_path)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => return Ok(()), // Timeout connecting — don't block hook
    };
    let (reader, mut writer) = stream.into_split();

    let body = record.to_json()?;
    let request = format!("POST /test-run\n{}\n", body);

    writer.write_all(request.as_bytes()).await?;
    writer.flush().await?;
    writer.shutdown().await?;

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let _ = timeout(Duration::from_secs(5), reader.read_line(&mut line)).await;

    Ok(())
}

/// Execute a compilation command on a remote worker.
///
/// This function:
/// 1. Syncs the project to the remote worker
/// 2. Executes the command remotely with streaming output
/// 3. Retrieves build artifacts back to local
///
/// Returns the execution result including exit code and stderr.
#[allow(clippy::too_many_arguments)] // Pipeline wiring favors explicit params
pub(super) async fn execute_remote_compilation(
    worker: &SelectedWorker,
    command: &str,
    transfer_config: TransferConfig,
    env_allowlist: Vec<String>,
    forwarded_cargo_target_dir: Option<PathBuf>,
    compilation_config: &rch_common::CompilationConfig,
    toolchain: Option<&ToolchainInfo>,
    kind: Option<CompilationKind>,
    reporter: &HookReporter,
    socket_path: &str,
    color_mode: ColorMode,
    build_id: Option<u64>,
    topology_policy: &PathTopologyPolicy,
) -> anyhow::Result<RemoteExecutionResult> {
    let worker_config = selected_worker_to_config(worker);

    // Get current working directory and normalize it to the canonical project root.
    let project_root =
        std::env::current_dir().map_err(|e| TransferError::NoProjectRoot { source: e })?;
    let normalized_project = normalize_project_path_with_policy(&project_root, topology_policy)
        .map_err(|e| {
            anyhow::anyhow!(
                "Project path normalization failed for {}: {}",
                project_root.display(),
                e
            )
        })?;
    for decision in normalized_project.decision_trace() {
        reporter.verbose(&format!("[RCH] project path normalized: {}", decision));
    }
    let normalized_project_root = normalized_project.canonical_path().to_path_buf();

    let dependency_plan =
        build_dependency_runtime_plan(&normalized_project_root, kind, reporter, topology_policy);
    let exact_dependency_closure_sync = command_uses_cargo_dependency_graph(kind);
    if let Some(decision) = dependency_plan.fail_open_decision.as_ref() {
        let report = build_dependency_runtime_fail_open_report(
            &worker_config,
            &normalized_project_root,
            decision,
        );
        if let Ok(report_json) = serde_json::to_string(&report) {
            reporter.verbose(&format!(
                "[RCH] dependency planner fail-open report: {}",
                report_json
            ));
        }
        if exact_dependency_closure_sync
            && should_force_local_fallback_for_runtime_fail_open(decision.reason_code)
        {
            warn!(
                "Dependency planner fail-open on {} [{}]: refusing remote Cargo execution and falling back local ({})",
                worker_config.id, decision.reason_code, decision.remediation
            );
            reporter.verbose(&format!(
                "[RCH] dependency planner fail-open [{}]: exact dependency closure required, forcing local fallback — {}",
                decision.reason_code, decision.remediation
            ));
            return Err(DependencyPreflightFailure::from_report(report).into());
        }
        warn!(
            "Dependency planner fail-open on {} [{}]: proceeding with primary-root-only sync ({})",
            worker_config.id, decision.reason_code, decision.remediation
        );
        reporter.verbose(&format!(
            "[RCH] dependency planner fail-open [{}]: proceeding with primary root only — {}",
            decision.reason_code, decision.remediation
        ));
    }
    let raw_sync_roots = dependency_plan.sync_roots;
    let project_id = project_id_from_path(&normalized_project_root);
    let project_hash = compute_project_hash_with_dependency_roots_and_policy(
        &normalized_project_root,
        &raw_sync_roots,
        topology_policy,
    );
    let sync_plan = build_sync_closure_plan(
        &raw_sync_roots,
        &normalized_project_root,
        &project_hash,
        topology_policy,
    );
    let sync_roots = sync_plan
        .iter()
        .map(|entry| entry.local_root.clone())
        .collect::<Vec<_>>();
    let sync_manifest = build_sync_closure_manifest(&sync_plan, &normalized_project_root);

    let output_ctx = OutputContext::detect();
    let console = RchConsole::with_context(output_ctx);
    let feedback_visible = reporter.visibility != OutputVisibility::None && !console.is_machine();
    let progress_enabled =
        output_ctx.supports_rich() && reporter.visibility != OutputVisibility::None;
    let remote_pgid_file = build_id.and_then(|id| {
        sync_plan
            .iter()
            .find(|entry| entry.is_primary)
            .map(|entry| TransferPipeline::remote_pgid_file_path_for_root(&entry.remote_root, id))
    });
    let mut heartbeat_loop =
        build_id.map(|id| BuildHeartbeatLoop::start(socket_path, id, &worker_config.id));
    if let Some(loop_ref) = heartbeat_loop.as_ref() {
        loop_ref.set_remote_pgid_file(remote_pgid_file);
        loop_ref.update_phase(BuildHeartbeatPhase::SyncUp, Some("sync_start".to_string()));
        loop_ref.flush().await;
    }

    if feedback_visible {
        emit_job_banner(&console, output_ctx, worker, build_id);
    }

    info!(
        "Starting remote compilation pipeline for {} (hash: {})",
        project_id, project_hash
    );
    reporter.verbose(&format!(
        "[RCH] dependency sync roots planned: {}",
        sync_plan.len()
    ));
    for (idx, entry) in sync_plan.iter().enumerate() {
        reporter.verbose(&format!(
            "[RCH] dependency sync root {}/{}: {}",
            idx + 1,
            sync_plan.len(),
            entry.local_root.display()
        ));
    }
    match serde_json::to_string(&sync_manifest) {
        Ok(manifest_json) => {
            reporter.verbose(&format!(
                "[RCH] dependency sync manifest: {}",
                manifest_json
            ));
            info!(
                "Prepared dependency sync manifest for {} roots",
                sync_manifest.entries.len()
            );
        }
        Err(err) => warn!("Failed to serialize dependency sync manifest: {}", err),
    }
    reporter.verbose(&format!(
        "[RCH] sync start (project {} on {})",
        project_id, worker_config.id
    ));

    // Ensure deterministic remote topology before any repo synchronization.
    ensure_worker_projects_topology(&worker_config, reporter, topology_policy).await?;

    // Best-effort repo convergence for multi-repo dependency graphs.
    maybe_sync_repo_set_with_repo_updater(&worker_config, &sync_roots, reporter).await;

    // Build transfer pipelines with color mode, command timeout, and compilation kind.
    // When the in-session watchdog is active it enforces the real build cap
    // remotely (same timeout_for_kind value). Give the local SSH stream a grace
    // margin over that cap so a genuine remote group-kill propagates as exit
    // 137 instead of losing the race to a local "SSH command timed out" (#20).
    let remote_cap = compilation_config.timeout_for_kind(kind);
    let command_timeout = if compilation_config.external_timeout_enabled() {
        remote_cap + std::time::Duration::from_secs(30)
    } else {
        remote_cap
    };
    let effective_env_allowlist =
        cargo_target_env_allowlist(&env_allowlist, forwarded_cargo_target_dir.is_some());
    let cargo_env_overrides = cargo_target_env_overrides(forwarded_cargo_target_dir.as_deref());
    // Remote target-dir name for the forwarded-CARGO_TARGET_DIR sync. By default
    // this is a STABLE pooled name keyed on (project, toolchain, triple, profile,
    // features) so independent jobs with identical dimensions REUSE the same warm
    // remote incremental cache instead of cold-recompiling into a unique-per-job
    // dir. `RCH_DISABLE_TARGET_REUSE=1` restores the legacy unique-per-job name.
    let remote_cargo_target_dir_name_override = forwarded_cargo_target_dir.as_ref().map(|_| {
        if target_reuse_disabled() {
            reporter.verbose(
                "[RCH] remote target-dir reuse disabled (RCH_DISABLE_TARGET_REUSE); using unique-per-job dir",
            );
            remote_cargo_target_dir_name(build_id, &worker_config.id)
        } else {
            let name = remote_cargo_pooled_target_dir_name(
                &worker_config.id,
                &normalized_project_root,
                toolchain,
                command,
            );
            reporter.verbose(&format!(
                "[RCH] remote target-dir reuse active; pooled dir {name}"
            ));
            name
        }
    });
    let mut primary_pipeline: Option<TransferPipeline> = None;
    let mut aggregate_sync_result: Option<SyncResult> = None;

    // Step 1: Sync project to remote
    info!("Syncing project to worker {}...", worker_config.id);
    let mut upload_progress = if progress_enabled {
        Some(TransferProgress::upload(
            output_ctx,
            "Syncing workspace closure",
            reporter.visibility == OutputVisibility::None,
        ))
    } else {
        None
    };
    let mut root_outcomes: Vec<(SyncClosurePlanEntry, SyncRootOutcome)> = Vec::new();
    for entry in &sync_plan {
        let mut root_pipeline = TransferPipeline::new(
            entry.local_root.clone(),
            entry.project_id.clone(),
            entry.root_hash.clone(),
            transfer_config.clone(),
        )
        .with_color_mode(color_mode)
        .with_command_timeout(command_timeout)
        .with_compilation_config(compilation_config.clone())
        .with_compilation_kind(kind)
        .with_remote_path_override(entry.remote_root.clone())
        .with_build_id(build_id);
        if entry.mode == SyncClosureMode::WorkspaceMetadata {
            root_pipeline = root_pipeline
                .with_sync_include_patterns(workspace_metadata_sync_patterns())
                .with_sync_delete(false);
        }
        if entry.is_primary {
            root_pipeline = root_pipeline.with_env_allowlist(effective_env_allowlist.clone());
            if let Some(overrides) = cargo_env_overrides.as_ref() {
                root_pipeline = root_pipeline.with_env_overrides(overrides.clone());
            }
            if let Some(name) = remote_cargo_target_dir_name_override.as_ref() {
                root_pipeline = root_pipeline.with_remote_cargo_target_dir_name(name.clone());
            }
        }

        if exact_dependency_closure_sync {
            reporter.verbose(&format!(
                "[RCH] exact dependency closure sync required; bypassing transfer estimator for {}",
                entry.local_root.display()
            ));
        } else if let Some(skip_reason) = root_pipeline.should_skip_transfer(&worker_config).await {
            info!(
                "Transfer estimation indicates skip for {}: {} (worker {})",
                entry.local_root.display(),
                skip_reason,
                worker_config.id
            );
            reporter.verbose(&format!(
                "[RCH] skip transfer for {}: {}",
                entry.local_root.display(),
                skip_reason
            ));
            if entry.is_primary {
                // Primary root skip is fatal — cannot build without the main project.
                return Err(TransferError::TransferSkipped {
                    reason: skip_reason,
                }
                .into());
            }
            root_outcomes.push((
                entry.clone(),
                SyncRootOutcome::Skipped {
                    reason: skip_reason,
                },
            ));
            continue;
        }

        reporter.verbose(&format!(
            "[RCH] syncing dependency root {} to remote {}",
            entry.local_root.display(),
            entry.remote_root.as_str()
        ));
        let sync_attempt = if let Some(progress) = &mut upload_progress {
            root_pipeline
                .sync_to_remote_streaming(&worker_config, |line| {
                    progress.update_from_line(line);
                })
                .await
        } else {
            root_pipeline.sync_to_remote(&worker_config).await
        };
        match sync_attempt {
            Ok(root_sync_result) => {
                aggregate_sync_result = Some(match &aggregate_sync_result {
                    Some(existing) => merge_sync_result(existing, &root_sync_result),
                    None => root_sync_result,
                });
                if entry.is_primary {
                    primary_pipeline = Some(root_pipeline);
                }
                root_outcomes.push((entry.clone(), SyncRootOutcome::Synced));
            }
            Err(e) => {
                if entry.is_primary || exact_dependency_closure_sync {
                    // Cargo dependency-closure builds must not continue against
                    // stale sibling repositories on the worker.
                    return Err(e);
                }
                // Dependency root failure is non-fatal (fail-open for deps).
                warn!(
                    "Dependency root sync failed for {} (non-fatal): {}",
                    entry.local_root.display(),
                    e
                );
                reporter.verbose(&format!(
                    "[RCH] dependency root sync failed (fail-open): {} — {}",
                    entry.local_root.display(),
                    e
                ));
                root_outcomes.push((
                    entry.clone(),
                    SyncRootOutcome::Failed {
                        error: e.to_string(),
                    },
                ));
            }
        }
    }

    // Emit structured partial-sync diagnostics when any dependency roots had issues.
    let failed_count = root_outcomes
        .iter()
        .filter(|(_, o)| !matches!(o, SyncRootOutcome::Synced))
        .count();
    if failed_count > 0 {
        warn!(
            "Partial sync: {}/{} closure roots had issues (build continues with available roots)",
            failed_count,
            sync_plan.len()
        );
        for (entry, outcome) in &root_outcomes {
            match outcome {
                SyncRootOutcome::Synced => {}
                SyncRootOutcome::Skipped { reason } => {
                    info!(
                        "  dependency root skipped: {} — {}",
                        entry.local_root.display(),
                        reason
                    );
                }
                SyncRootOutcome::Failed { error } => {
                    info!(
                        "  dependency root failed: {} — {}",
                        entry.local_root.display(),
                        error
                    );
                }
            }
        }
    }
    let sync_result = aggregate_sync_result
        .ok_or_else(|| anyhow::anyhow!("dependency sync produced no transfer result"))?;
    let pipeline = primary_pipeline.ok_or_else(|| {
        anyhow::anyhow!(
            "dependency sync did not include primary project root {}",
            normalized_project_root.display()
        )
    })?;
    info!(
        "Sync complete: {} files, {} bytes in {}ms",
        sync_result.files_transferred, sync_result.bytes_transferred, sync_result.duration_ms
    );
    // Opportunistically reclaim *abandoned* per-job target dirs for this project
    // on the chosen worker. Only siblings with no file activity past the threshold
    // are removed, so any dir still in active use is preserved and this never races
    // a concurrent build on the same project. The heavy removal is detached on the
    // worker (a backgrounded rm); only a quick SSH dispatch is awaited here.
    // Best-effort; gated to the forwarded-CARGO_TARGET_DIR mode that makes per-job dirs.
    if forwarded_cargo_target_dir.is_some() {
        // Cheap, current-project-only reap: only this build's own repo dir is
        // swept for abandoned sibling per-job dirs. The durable cross-project
        // GC (every repo under the worker's sync-root) now runs OFF this
        // per-dispatch path in the background daemon sweep
        // (`rchd::stale_target_reap`), so this stays a single `cd` + glob loop.
        pipeline
            .reap_stale_sibling_per_job_target_dirs(&worker_config, stale_target_reap_idle_hours())
            .await;
    }
    reporter.verbose(&format!(
        "[RCH] sync done: {} files, {} bytes in {}ms",
        sync_result.files_transferred, sync_result.bytes_transferred, sync_result.duration_ms
    ));
    if let Some(progress) = &mut upload_progress {
        progress.apply_summary(sync_result.bytes_transferred, sync_result.files_transferred);
        progress.finish();
    }
    if let Some(loop_ref) = heartbeat_loop.as_ref() {
        loop_ref.update_phase(
            BuildHeartbeatPhase::Execute,
            Some("remote_exec_start".to_string()),
        );
        loop_ref.flush().await;
    }

    if command_uses_cargo_dependency_graph(kind) {
        verify_remote_dependency_manifests(&worker_config, &root_outcomes, reporter).await?;
    }

    // Step 2: Execute command remotely with streaming output
    // Mask sensitive data (API keys, tokens, passwords) before logging
    let masked_command = mask_sensitive_command(command);
    info!("Executing command remotely: {}", masked_command);
    reporter.verbose(&format!("[RCH] exec start: {}", masked_command));

    // Capture stderr for toolchain failure detection
    //
    // `std::env::set_var` is unsafe in Rust 2024, but reading env is fine. For streaming,
    // we need shared mutable state across stdout/stderr callbacks; use `Rc<RefCell<_>>`
    // to avoid borrow-checker conflicts between the two closures.
    use std::cell::RefCell;
    use std::rc::Rc;

    let stderr_capture_cell = Rc::new(RefCell::new(String::new()));

    struct CompileUiState {
        progress: Option<CompilationProgress>,
        output: String,
        output_truncated: bool,
        crates_compiled: Option<u32>,
        warnings: Option<u32>,
    }
    let use_compile_progress = progress_enabled
        && matches!(
            kind,
            Some(
                CompilationKind::CargoBuild
                    | CompilationKind::CargoCheck
                    | CompilationKind::CargoClippy
                    | CompilationKind::CargoDoc
                    | CompilationKind::CargoBench
            )
        );
    let ui_state = Rc::new(RefCell::new(CompileUiState {
        progress: if use_compile_progress {
            Some(CompilationProgress::new(
                output_ctx,
                worker_config.id.as_str().to_string(),
                reporter.visibility == OutputVisibility::None,
            ))
        } else {
            None
        },
        output: String::new(),
        output_truncated: false,
        crates_compiled: None,
        warnings: None,
    }));

    // Add per-worker CARGO_HOME isolation to prevent cache lock contention
    let isolated_command = add_cargo_isolation(command, &worker_config.id);

    // Stream stdout/stderr to our stderr so the agent sees the output
    let command_with_telemetry = wrap_command_with_telemetry(&isolated_command, &worker_config.id);
    let ui_state_stdout = Rc::clone(&ui_state);
    let ui_state_stderr = Rc::clone(&ui_state);
    let stderr_capture_stderr = Rc::clone(&stderr_capture_cell);
    let heartbeat_state_stdout = heartbeat_loop
        .as_ref()
        .map(BuildHeartbeatLoop::shared_state);
    let heartbeat_state_stderr = heartbeat_loop
        .as_ref()
        .map(BuildHeartbeatLoop::shared_state);
    let mut suppress_telemetry = false;

    let result = pipeline
        .execute_remote_streaming(
            &worker_config,
            &command_with_telemetry,
            toolchain,
            move |line| {
                if suppress_telemetry {
                    return;
                }
                if line.trim() == PIGGYBACK_MARKER {
                    suppress_telemetry = true;
                    return;
                }
                if let Some(state) = heartbeat_state_stdout.as_ref() {
                    mark_heartbeat_progress(state);
                }

                let mut state = ui_state_stdout.borrow_mut();
                if let Some(progress) = state.progress.as_mut() {
                    progress.update_from_line(line);
                    if !state.output_truncated {
                        const MAX_OUTPUT_BYTES: usize = 256 * 1024;
                        if state.output.len() + line.len() <= MAX_OUTPUT_BYTES {
                            state.output.push_str(line);
                        } else {
                            state.output_truncated = true;
                        }
                    }
                } else {
                    // Write stdout lines to stderr (hook stdout is for protocol)
                    eprint!("{}", line);
                }
            },
            move |line| {
                if let Some(state) = heartbeat_state_stderr.as_ref() {
                    mark_heartbeat_progress(state);
                }
                // Write stderr lines to stderr and capture for analysis
                let mut state = ui_state_stderr.borrow_mut();
                if let Some(progress) = state.progress.as_mut() {
                    progress.update_from_line(line);
                    if !state.output_truncated {
                        const MAX_OUTPUT_BYTES: usize = 256 * 1024;
                        if state.output.len() + line.len() <= MAX_OUTPUT_BYTES {
                            state.output.push_str(line);
                        } else {
                            state.output_truncated = true;
                        }
                    }
                } else {
                    eprint!("{}", line);
                }
                drop(state);

                stderr_capture_stderr.borrow_mut().push_str(line);
            },
        )
        .await?;

    let stderr_capture = std::mem::take(&mut *stderr_capture_cell.borrow_mut());

    info!(
        "Remote command finished: exit={} in {}ms",
        result.exit_code, result.duration_ms
    );
    reporter.verbose(&format!(
        "[RCH] exec done: exit={} in {}ms",
        result.exit_code, result.duration_ms
    ));

    {
        let mut state = ui_state.borrow_mut();

        let mut progress_stats = None;
        if let Some(progress) = state.progress.as_mut() {
            progress_stats = Some((progress.crates_compiled(), progress.warnings()));
            if result.success() {
                progress.finish();
            } else {
                let message = stderr_capture
                    .lines()
                    .find(|line| !line.trim().is_empty())
                    .unwrap_or("remote compilation failed");
                progress.finish_error(message);
            }
        }
        if let Some((crates_compiled, warnings)) = progress_stats {
            state.crates_compiled = Some(crates_compiled);
            state.warnings = Some(warnings);
        }

        if use_compile_progress && !result.success() && !state.output.is_empty() {
            eprintln!("{}", state.output);
            if state.output_truncated {
                eprintln!("[RCH] output truncated (increase buffer if needed)");
            }
        }
    }

    let mut artifacts_result: Option<SyncResult> = None;
    let mut artifacts_failed = false;
    // Step 3: Retrieve artifacts
    if result.success() {
        if let Some(loop_ref) = heartbeat_loop.as_ref() {
            loop_ref.update_phase(
                BuildHeartbeatPhase::SyncDown,
                Some("artifact_sync_start".to_string()),
            );
            loop_ref.flush().await;
        }
        info!("Retrieving build artifacts...");
        reporter.verbose("[RCH] artifacts: retrieving...");
        let artifact_patterns = get_artifact_patterns(kind);
        let heartbeat_state_download = heartbeat_loop
            .as_ref()
            .map(BuildHeartbeatLoop::shared_state);
        let mut download_progress = if progress_enabled {
            Some(TransferProgress::download(
                output_ctx,
                "Retrieving artifacts",
                reporter.visibility == OutputVisibility::None,
            ))
        } else {
            None
        };

        let retrieval = if let Some(progress) = &mut download_progress {
            pipeline
                .retrieve_artifacts_streaming(&worker_config, &artifact_patterns, |line| {
                    progress.update_from_line(line);
                    if let Some(state) = heartbeat_state_download.as_ref() {
                        mark_heartbeat_progress(state);
                    }
                })
                .await
        } else {
            pipeline
                .retrieve_artifacts(&worker_config, &artifact_patterns)
                .await
        };

        match retrieval {
            Ok(artifact_result) => {
                info!(
                    "Artifacts retrieved: {} files, {} bytes in {}ms",
                    artifact_result.files_transferred,
                    artifact_result.bytes_transferred,
                    artifact_result.duration_ms
                );
                reporter.verbose(&format!(
                    "[RCH] artifacts done: {} files, {} bytes in {}ms",
                    artifact_result.files_transferred,
                    artifact_result.bytes_transferred,
                    artifact_result.duration_ms
                ));
                if let Some(progress) = &mut download_progress {
                    progress.apply_summary(
                        artifact_result.bytes_transferred,
                        artifact_result.files_transferred,
                    );
                    progress.finish();
                }
                artifacts_result = Some(match artifacts_result.take() {
                    Some(existing) => merge_sync_result(&existing, &artifact_result),
                    None => artifact_result,
                });
            }
            Err(e) => {
                artifacts_failed = true;

                // Extract rsync exit code from error message if present
                let error_str = e.to_string();
                let rsync_exit_code = error_str.find("exit code").and_then(|_| {
                    error_str
                        .split("exit code")
                        .nth(1)
                        .and_then(|s| s.split(':').next())
                        .and_then(|s| {
                            s.trim()
                                .trim_start_matches("Some(")
                                .trim_end_matches(')')
                                .parse()
                                .ok()
                        })
                });

                // Create structured warning (bd-1q3p)
                let warning = ArtifactRetrievalWarning::new(
                    worker_config.id.as_str(),
                    artifact_patterns.clone(),
                    &error_str,
                    rsync_exit_code,
                );

                warn!("Failed to retrieve artifacts: {}", e);

                // Show detailed warning in verbose mode or when not in machine mode
                if !console.is_machine() {
                    reporter.verbose(&warning.format_warning());
                } else {
                    // For machine mode, output JSON warning
                    debug!("Artifact retrieval warning (JSON): {}", warning.to_json());
                    reporter.verbose("[RCH] artifacts failed (continuing)");
                }

                if let Some(progress) = &mut download_progress {
                    progress.finish_error(&e.to_string());
                }
                // Continue anyway - compilation succeeded
            }
        }

        if let Some(local_target_dir) = forwarded_cargo_target_dir.as_ref() {
            let remote_target_path = pipeline.remote_cargo_target_dir();
            let custom_patterns = get_custom_target_artifact_patterns(kind);
            if custom_patterns.is_empty() {
                reporter.verbose(&format!(
                    "[RCH] custom target dir sync skipped for {} after command with no target artifacts",
                    local_target_dir.display()
                ));
            } else {
                let target_pipeline = TransferPipeline::new(
                    local_target_dir.clone(),
                    project_id_from_path(local_target_dir),
                    compute_project_hash_with_dependency_roots_and_policy(
                        local_target_dir,
                        &[],
                        topology_policy,
                    ),
                    transfer_config.clone(),
                )
                .with_color_mode(color_mode)
                .with_command_timeout(command_timeout)
                .with_compilation_config(compilation_config.clone())
                .with_compilation_kind(kind)
                .with_remote_path_override(remote_target_path.clone());

                let mut target_progress = if progress_enabled {
                    Some(TransferProgress::download(
                        output_ctx,
                        "Syncing custom CARGO_TARGET_DIR artifacts",
                        reporter.visibility == OutputVisibility::None,
                    ))
                } else {
                    None
                };

                let target_retrieval = if let Some(progress) = &mut target_progress {
                    let heartbeat_state_target = heartbeat_loop
                        .as_ref()
                        .map(BuildHeartbeatLoop::shared_state);
                    target_pipeline
                        .retrieve_artifacts_streaming(&worker_config, &custom_patterns, |line| {
                            progress.update_from_line(line);
                            if let Some(state) = heartbeat_state_target.as_ref() {
                                mark_heartbeat_progress(state);
                            }
                        })
                        .await
                } else {
                    target_pipeline
                        .retrieve_artifacts(&worker_config, &custom_patterns)
                        .await
                };

                match target_retrieval {
                    Ok(target_result) => {
                        info!(
                            "Custom CARGO_TARGET_DIR artifacts retrieved: {} files, {} bytes in {}ms",
                            target_result.files_transferred,
                            target_result.bytes_transferred,
                            target_result.duration_ms
                        );
                        reporter.verbose(&format!(
                            "[RCH] custom target dir sync done: {} -> {} ({} files, {} bytes in {}ms)",
                            remote_target_path,
                            local_target_dir.display(),
                            target_result.files_transferred,
                            target_result.bytes_transferred,
                            target_result.duration_ms
                        ));
                        if let Some(progress) = &mut target_progress {
                            progress.apply_summary(
                                target_result.bytes_transferred,
                                target_result.files_transferred,
                            );
                            progress.finish();
                        }
                        artifacts_result = Some(match artifacts_result.take() {
                            Some(existing) => merge_sync_result(&existing, &target_result),
                            None => target_result,
                        });
                    }
                    Err(e) => {
                        artifacts_failed = true;
                        warn!("Failed to sync custom CARGO_TARGET_DIR artifacts: {}", e);
                        reporter.verbose(&format!(
                            "[RCH] custom target dir sync failed for {}: {}",
                            local_target_dir.display(),
                            e
                        ));
                        if let Some(progress) = &mut target_progress {
                            progress.finish_error(&e.to_string());
                        }
                    }
                }
            }
        }
    }

    // Step 4: Extract and forward telemetry (piggybacked in stdout)
    let extraction = extract_piggybacked_telemetry(&result.stdout);
    if let Some(error) = extraction.extraction_error {
        warn!("Telemetry extraction failed: {}", error);
    }
    if let Some(telemetry) = extraction.telemetry
        && let Err(e) = send_telemetry(socket_path, TelemetrySource::Piggyback, &telemetry).await
    {
        warn!("Failed to forward telemetry to daemon: {}", e);
    }

    if is_test_kind(kind)
        && let Some(kind) = kind
    {
        let record = TestRunRecord::new(
            project_id.clone(),
            worker_config.id.as_str().to_string(),
            command.to_string(),
            kind,
            result.exit_code,
            result.duration_ms,
        );
        if let Err(e) = send_test_run(socket_path, &record).await {
            warn!("Failed to forward test run telemetry: {}", e);
        }
    }

    let (crates_compiled, output_snapshot) = {
        let state = ui_state.borrow();
        (state.crates_compiled, state.output.clone())
    };

    if feedback_visible {
        render_compile_summary(
            &console,
            output_ctx,
            worker,
            build_id,
            &sync_result,
            result.duration_ms,
            artifacts_result.as_ref(),
            artifacts_failed,
            cache_hit(&sync_result),
            result.success(),
        );
    }

    if result.success() {
        let artifacts_summary = artifacts_result.as_ref().map(|artifact| ArtifactSummary {
            files: u64::from(artifact.files_transferred),
            bytes: artifact.bytes_transferred,
        });
        let target_label = detect_target_label(command, &output_snapshot);

        let summary = CelebrationSummary::new(project_id.clone(), result.duration_ms)
            .worker(worker_config.id.as_str())
            .crates_compiled(crates_compiled)
            .artifacts(artifacts_summary)
            .cache_hit(Some(cache_hit(&sync_result)))
            .target(target_label)
            .quiet(reporter.visibility == OutputVisibility::None);

        CompletionCelebration::new(summary).record_and_render(output_ctx);
    }

    // Construct per-phase timing breakdown
    let timing = CommandTimingBreakdown {
        sync_up: Some(Duration::from_millis(sync_result.duration_ms)),
        exec: Some(Duration::from_millis(result.duration_ms)),
        sync_down: artifacts_result
            .as_ref()
            .map(|ar| Duration::from_millis(ar.duration_ms)),
        ..Default::default()
    };

    if let Some(loop_ref) = heartbeat_loop.take() {
        let detail = if result.success() {
            Some("build_complete".to_string())
        } else {
            Some(format!("build_exit_{}", result.exit_code))
        };
        loop_ref.finish(BuildHeartbeatPhase::Finalize, detail).await;
    }

    // Loud, fatal sync-back failure (issue #19 Fix 1). A remote compile that
    // SUCCEEDED but whose artifacts never came back leaves the local build
    // incomplete — no binary/lib where the agent expects one. Reporting exit 0
    // here is a silent footgun: the agent believes the build succeeded and the
    // missing artifact only surfaces much later. So when the compile succeeded,
    // artifact retrieval failed, AND this kind actually produces transferable
    // artifacts, surface a PROMINENT stderr error and return a non-zero,
    // build-failure-class exit code. The retrieval layer already turns exit-0
    // partial transfers into `TransferError::SyncFailed` (transfer.rs); this
    // propagates that as a non-zero hook exit instead of swallowing it.
    let exit_code =
        if result.success() && artifacts_failed && kind_produces_transferable_artifacts(kind) {
            let code = ErrorCode::BuildArtifactMissing;
            // stderr, not just `warn!`: this MUST reach the operator/agent even when
            // tracing is silenced. stderr is the diagnostics stream (AGENTS.md).
            eprintln!(
                "[RCH] {} remote compile on {} SUCCEEDED but build artifacts could not be \
             retrieved — the local build is INCOMPLETE (expected binaries/libraries are \
             missing). Treating as a build failure (exit {EXIT_ARTIFACT_TRANSFER_FAILED}); \
             re-run to rebuild, or check connectivity to the worker.",
                code.code_string(),
                worker_config.id,
            );
            warn!(
                "Artifact transfer failed after a successful remote compile on {} [{}]; \
             returning exit {} so the caller knows the local build is incomplete",
                worker_config.id,
                code.code_string(),
                EXIT_ARTIFACT_TRANSFER_FAILED
            );
            EXIT_ARTIFACT_TRANSFER_FAILED
        } else {
            result.exit_code
        };

    Ok(RemoteExecutionResult {
        exit_code,
        stderr: stderr_capture,
        duration_ms: result.duration_ms,
        timing,
    })
}
