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
    expected_output_glob_list, get_custom_target_artifact_patterns, get_project_artifact_patterns,
    kind_produces_transferable_artifacts, sync_back_verified_zero_build_outputs,
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
use super::formatting::{cache_hit, detect_target_label, emit_job_banner, render_compile_summary};
use super::progress_reporting::{BuildHeartbeatLoop, BuildHeartbeatSnapshot, mark_heartbeat_progress};
use super::remote_result::RemoteExecutionResult;
use super::repo_updater::maybe_sync_repo_set_with_repo_updater;
use super::source_fidelity::{
    PreparedSourceContentRoot, finalize_source_content_receipt, prepare_source_content_root,
    verify_source_content_roots,
};
use super::ssh::{acquire_remote_source_authority_lock, ensure_worker_projects_topology};
use super::*;

pub(super) fn source_sync_terminal_summary(
    attempts: &[crate::transfer::TransferAttemptDiagnostic],
    clean_overlay: bool,
) -> Option<String> {
    let last = attempts.last()?;
    let label = if clean_overlay {
        "clean-overlay source sync"
    } else {
        "source sync"
    };
    Some(format!(
        "[RCH] {label} failed before remote Cargo execution after {}/{} attempts; remote Cargo was not started: {}",
        attempts.len(),
        last.max_attempts,
        last.detail
    ))
}

pub(super) fn apply_source_sync_integrity_policy(
    pipeline: TransferPipeline,
    exact_dependency_closure_sync: bool,
    source_content_receipt: bool,
) -> TransferPipeline {
    // Exact Cargo closure sync is correctness-authoritative: rsync's default size-and-mtime
    // quick check can otherwise retain stale dependency bytes with matching metadata.
    if exact_dependency_closure_sync || source_content_receipt {
        pipeline.with_sync_checksum(true)
    } else {
        pipeline
    }
}

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

/// Derive the remote-root component for one clean-overlay execution.
///
/// The job nonce deliberately keeps even identical source snapshots in
/// separate directories: overlapping jobs must never synchronize into the
/// same remote project root.
fn clean_overlay_remote_project_hash(
    base_commit: &str,
    overlay_fingerprint: &str,
    job_nonce: uuid::Uuid,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"rch-clean-overlay-remote-root-v1\0");
    hasher.update(base_commit.as_bytes());
    hasher.update(b"\0");
    hasher.update(overlay_fingerprint.as_bytes());
    hasher.update(b"\0");
    hasher.update(job_nonce.as_bytes());
    hasher.finalize().to_hex()[..16].to_string()
}

/// The STABLE absolute location for a clean-overlay run's pooled Cargo target
/// store (issue #60): a sibling of the per-command overlay roots under
/// `<remote_base>/<project_id>/`, never inside them. The per-command root
/// embeds a job nonce and is reaped at teardown; the pooled store must
/// survive both to stay warm across gates.
fn clean_overlay_stable_pooled_target_dir(
    remote_base: &str,
    project_id: &str,
    pooled_dir_name: &str,
) -> String {
    format!(
        "{}/{}/{}",
        remote_base.trim_end_matches('/'),
        project_id,
        pooled_dir_name
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
    local_wrapper_id: Option<&str>,
    durable_lease: Option<&DurableLeaseWriter>,
    topology_policy: &PathTopologyPolicy,
    clean_overlay: Option<&CleanOverlaySpec>,
    source_content_receipt: bool,
    // Declared job result directories (bd-p0yoo), repository-relative.
    // Retrieved after the command completes on ANY exit code; a directory
    // that is missing or only partially transferable fails the invocation
    // loudly instead of surfacing the job's bare exit status.
    result_dirs: &[PathBuf],
    // Resolved Layer 0 pack env pairs (bd-bqu38), forced onto the remote
    // build regardless of the ambient environment.
    layer0_env: &[(String, String)],
    // Configured `[remediation.pooled_target] reaper_pooled_idle_hours`
    // (issue #53): the transfer-start janitor prunes idle pooled target
    // stores on exactly this window so it never undercuts the reaper.
    pooled_target_prune_idle_hours: u32,
) -> anyhow::Result<RemoteExecutionResult> {
    let worker_config = selected_worker_to_config(worker);
    if source_content_receipt && WorkerPlatform::from_worker(&worker_config).is_windows() {
        anyhow::bail!("source-content receipts require the Unix rsync transport");
    }
    if !result_dirs.is_empty() && WorkerPlatform::from_worker(&worker_config).is_windows() {
        anyhow::bail!("--result-dir requires the Unix rsync transport; worker is Windows");
    }
    let source_content_build_id = if source_content_receipt {
        Some(build_id.ok_or_else(|| {
            anyhow::anyhow!("source-content receipt requires a durable remote build id")
        })?)
    } else {
        None
    };

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

    // Windows workers have no Unix canonical/alias projects topology and cargo
    // needs drive-letter paths, so their whole remote layout lives under the
    // Windows build base and syncs via tar-over-ssh (no rsync/streaming).
    let worker_is_windows = WorkerPlatform::from_worker(&worker_config).is_windows();

    let exact_dependency_closure_sync =
        clean_overlay.is_none() && command_uses_cargo_dependency_graph(kind);
    let raw_sync_roots = if clean_overlay.is_some() {
        // The immutable Git archive already contains every in-repository
        // workspace member. Syncing ambient sibling roots here could reintroduce
        // the peer dirt this mode exists to exclude, so clean-overlay starts
        // with one primary root and lets unsupported external path dependencies
        // fail closed during the remote build.
        vec![normalized_project_root.clone()]
    } else {
        let dependency_plan = build_dependency_runtime_plan(
            &normalized_project_root,
            kind,
            reporter,
            topology_policy,
        );
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
            if source_content_receipt {
                warn!(
                    "Dependency planner could not prove the exact source closure on {} [{}]: refusing source-content receipt mode ({})",
                    worker_config.id, decision.reason_code, decision.remediation
                );
                reporter.verbose(&format!(
                    "[RCH] dependency planner refusal [{}]: source-content receipt requires an exact closure — {}",
                    decision.reason_code, decision.remediation
                ));
                return Err(DependencyPreflightFailure::from_report(report).into());
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
        dependency_plan.sync_roots
    };
    let project_id = project_id_from_path(&normalized_project_root);
    let project_hash = if let Some(spec) = clean_overlay {
        clean_overlay_remote_project_hash(
            spec.base_commit(),
            spec.overlay_fingerprint(),
            uuid::Uuid::new_v4(),
        )
    } else {
        compute_project_hash_with_dependency_roots_and_policy(
            &normalized_project_root,
            &raw_sync_roots,
            topology_policy,
        )
    };
    // Proof runs use an invocation-unique remote source root. Without this, a
    // concurrent ordinary sync of the same project hash could mutate the tree
    // after verification but before Cargo opens a source file.
    let project_hash = if let Some(proof_build_id) = source_content_build_id {
        blake3::hash(
            format!(
                "rch.source_content_remote_root.v1\0{}\0{}\0{}",
                project_hash, proof_build_id, worker_config.id
            )
            .as_bytes(),
        )
        .to_hex()
        .to_string()
    } else {
        project_hash
    };
    let mut sync_plan = build_sync_closure_plan(
        &raw_sync_roots,
        &normalized_project_root,
        &project_hash,
        topology_policy,
    );
    // Ordinary Cargo invocations target shared canonical worker paths. Capture
    // those logical authorities before any proof/overlay/Windows relocation so
    // overlapping primary projects that share a path dependency take the same
    // remote lock. Source-content and clean-overlay runs already own isolated
    // source roots and do not need this mutable-authority guard.
    let mutable_source_authority_roots =
        if exact_dependency_closure_sync && source_content_build_id.is_none() {
            sync_plan
                .iter()
                .map(|entry| entry.remote_root.clone())
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
    if let Some(proof_build_id) = source_content_build_id {
        let proof_base = format!(
            "{}/source-content-{}-{}",
            transfer_config.remote_base.trim_end_matches('/'),
            proof_build_id,
            &project_hash[..project_hash.len().min(16)]
        );
        for entry in &mut sync_plan {
            let relative = entry
                .local_root
                .strip_prefix(topology_policy.canonical_root())
                .with_context(|| {
                    format!(
                        "source-content root {} is outside canonical topology {}",
                        entry.local_root.display(),
                        topology_policy.canonical_root().display()
                    )
                })?;
            let relative = relative.to_str().ok_or_else(|| {
                anyhow::anyhow!(
                    "source-content remote relative path is not UTF-8: {}",
                    relative.display()
                )
            })?;
            if relative.is_empty() || relative.chars().any(char::is_control) {
                anyhow::bail!("source-content remote relative path is invalid");
            }
            entry.remote_root = format!("{proof_base}/{relative}");
            entry.root_hash = blake3::hash(
                format!(
                    "rch.source_content_root_hash.v1\0{}\0{}\0{}",
                    entry.root_hash, proof_build_id, relative
                )
                .as_bytes(),
            )
            .to_hex()
            .to_string();
        }
    }
    let mut overlay_remote_root: Option<String> = None;
    if clean_overlay.is_some() {
        if sync_plan.len() != 1 || !sync_plan[0].is_primary {
            anyhow::bail!(
                "clean-overlay requires a single primary sync root; found {} roots",
                sync_plan.len()
            );
        }
        let remote_base = transfer_config.remote_base.trim_end_matches('/');
        sync_plan[0].remote_root = format!("{remote_base}/{project_id}/{project_hash}");
        overlay_remote_root = Some(sync_plan[0].remote_root.clone());
        sync_plan[0].root_hash.clone_from(&project_hash);
    }
    // Relocate every closure root under the Windows build base so all downstream
    // remote paths (sync target, build cwd, CARGO_TARGET_DIR, manifest
    // verification) use drive-letter paths. Mirrors the clean-overlay remote_root
    // override above but applies to the whole plan. See rch#<NN>.
    if worker_is_windows {
        for entry in sync_plan.iter_mut() {
            entry.remote_root = format!(
                "{}/{}/{}",
                crate::transfer::WINDOWS_DEFAULT_REMOTE_BASE,
                entry.project_id,
                entry.root_hash
            );
        }
    }
    let sync_roots = sync_plan
        .iter()
        .map(|entry| entry.local_root.clone())
        .collect::<Vec<_>>();
    let sync_manifest = build_sync_closure_manifest(&sync_plan, &normalized_project_root);

    let output_ctx = OutputContext::detect();
    let console = RchConsole::with_context(output_ctx);
    let feedback_visible = reporter.visibility != OutputVisibility::None && !console.is_machine();
    // The Windows tar-over-ssh transport has no streaming (rsync-style) progress
    // variant, so disable progress there to force the Windows-aware
    // non-streaming sync/retrieve paths.
    let progress_enabled = output_ctx.supports_rich()
        && reporter.visibility != OutputVisibility::None
        && !worker_is_windows;
    let remote_pgid_file = build_id.and_then(|id| {
        sync_plan
            .iter()
            .find(|entry| entry.is_primary)
            .map(|entry| TransferPipeline::remote_pgid_file_path_for_root(&entry.remote_root, id))
    });
    let mut heartbeat_loop = build_id.map(|id| {
        BuildHeartbeatLoop::start(
            socket_path,
            id,
            &worker_config.id,
            local_wrapper_id,
            durable_lease,
        )
    });
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
    // bd-8iwkm/bd-gc0ze: the ownership sweep inside is scoped to this
    // dispatch's closure remote roots so its cost tracks the trees about to
    // be written, not the entire multi-GB mirror tree.
    let ownership_scan_roots: Vec<PathBuf> = sync_plan
        .iter()
        .map(|entry| PathBuf::from(entry.remote_root.as_str()))
        .collect();
    ensure_worker_projects_topology(
        &worker_config,
        reporter,
        topology_policy,
        &ownership_scan_roots,
    )
    .await?;

    // Hold every mutable source authority from before repo convergence and the
    // first rsync until Cargo exits. A sync-only lock is insufficient: another
    // invocation could otherwise replace a manifest or source file after
    // preflight while rustc is still opening the closure.
    let remote_cap = compilation_config.timeout_for_kind(kind);
    let command_timeout = if compilation_config.external_timeout_enabled() {
        remote_cap + std::time::Duration::from_secs(30)
    } else {
        remote_cap
    };
    let mut source_authority_lock = if mutable_source_authority_roots.is_empty()
        || super::ssh::should_skip_remote_preflight(&worker_config)
    {
        None
    } else {
        reporter.verbose(&format!(
            "[RCH] waiting for {} remote source-authority lock(s) on {}",
            mutable_source_authority_roots.len(),
            worker_config.id
        ));
        let guard = acquire_remote_source_authority_lock(
            &worker_config,
            &mutable_source_authority_roots,
            command_timeout,
        )
        .await?;
        reporter.verbose(&format!(
            "[RCH] acquired remote source-authority locks on {}",
            worker_config.id
        ));
        Some(guard)
    };

    // Best-effort repo convergence for ordinary multi-repo dependency graphs.
    // A clean-overlay run already names an immutable base; mutating repositories
    // behind that receipt would break the source identity guarantee.
    if clean_overlay.is_none() {
        maybe_sync_repo_set_with_repo_updater(&worker_config, &sync_roots, reporter).await;
    }

    // Build transfer pipelines with color mode, command timeout, and compilation kind.
    // When the in-session watchdog is active it enforces the real build cap
    // remotely (same timeout_for_kind value). Give the local SSH stream a grace
    // margin over that cap so a genuine remote group-kill propagates as exit
    // 137 instead of losing the race to a local "SSH command timed out" (#20).
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
    // Issue #60: a clean-overlay run hashes a per-command job nonce into its
    // remote root (a deliberate overlap-safety invariant) and reaps that root
    // wholesale at teardown, so a pooled target dir placed UNDER it can never
    // be reused — every clean-overlay gate was a cold build. Relocate the
    // pooled store to a STABLE per-project sibling path outside the throwaway
    // root, keeping the `.rch-target-…-pool-…` basename so the pool-janitor /
    // sbh GC conventions (and Cargo's own CACHEDIR.TAG) still apply. Cargo's
    // target-dir flock serializes overlapping jobs sharing the pool.
    let pooled_target_dir_override = if clean_overlay.is_some() && !target_reuse_disabled() {
        remote_cargo_target_dir_name_override.as_ref().map(|name| {
            let base = if worker_is_windows {
                crate::transfer::WINDOWS_DEFAULT_REMOTE_BASE
            } else {
                transfer_config.remote_base.trim_end_matches('/')
            };
            let stable = clean_overlay_stable_pooled_target_dir(base, &project_id, name);
            reporter.verbose(&format!(
                "[RCH] clean-overlay pooled target relocated outside per-command root: {stable}"
            ));
            stable
        })
    } else {
        None
    };
    let mut primary_pipeline: Option<TransferPipeline> = None;
    let mut aggregate_sync_result: Option<SyncResult> = None;
    let mut prepared_source_roots: Vec<PreparedSourceContentRoot> = Vec::new();

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
    // Issue #59: the streaming sync path is used for every non-Windows worker
    // (not only when the rich progress UI is enabled) so rsync's output feeds
    // BOTH the silence-based stall detector inside the transfer layer and the
    // build heartbeat here — a live sync stays observably alive to the daemon
    // while the phase is still `sync_up`.
    let sync_streaming = !worker_is_windows;
    let sync_heartbeat_state = heartbeat_loop.as_ref().map(BuildHeartbeatLoop::shared_state);
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
        .with_worker_platform(WorkerPlatform::from_worker(&worker_config))
        .with_build_id(build_id)
        .with_pooled_target_prune_idle_hours(pooled_target_prune_idle_hours);
        if let Some(spec) = clean_overlay {
            root_pipeline = root_pipeline
                .with_sync_include_patterns(clean_overlay_include_patterns(
                    &entry.local_root,
                    spec.overlay_paths(),
                )?)
                .with_sync_delete(false)
                .with_sync_checksum(true);
        }
        if entry.mode == SyncClosureMode::WorkspaceMetadata {
            root_pipeline =
                root_pipeline.with_sync_include_patterns(workspace_metadata_sync_patterns());
            root_pipeline = root_pipeline.with_env_allowlist(effective_env_allowlist.clone());
            if !layer0_env.is_empty() {
                root_pipeline = root_pipeline.with_layer0_env(layer0_env.to_vec());
            }
        }
        if entry.is_primary {
            root_pipeline = root_pipeline.with_env_allowlist(effective_env_allowlist.clone());
            if let Some(overrides) = cargo_env_overrides.as_ref() {
                root_pipeline = root_pipeline.with_env_overrides(overrides.clone());
            }
            if let Some(name) = remote_cargo_target_dir_name_override.as_ref() {
                root_pipeline = root_pipeline.with_remote_cargo_target_dir_name(name.clone());
            }
            if let Some(stable_pool) = pooled_target_dir_override.as_ref() {
                root_pipeline =
                    root_pipeline.with_remote_cargo_target_dir_override(stable_pool.clone());
            }
        }
        root_pipeline = apply_source_sync_integrity_policy(
            root_pipeline,
            exact_dependency_closure_sync,
            source_content_receipt,
        );

        let prepared_source_root = if source_content_receipt {
            Some(
                prepare_source_content_root(prepared_source_roots.len(), entry, &root_pipeline)
                    .await?,
            )
        } else {
            None
        };

        if let Some(spec) = clean_overlay {
            reporter.verbose(&format!(
                "[RCH] clean-overlay transfer estimator bypassed for immutable base {}",
                spec.base_commit()
            ));
        } else if exact_dependency_closure_sync || source_content_receipt {
            reporter.verbose(&format!(
                "[RCH] exact source sync required; bypassing transfer estimator for {}",
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
        let sync_attempt = if let Some(spec) = clean_overlay {
            spec.verify_archive_attributes(&entry.local_root).await?;
            spec.verify_overlay_unchanged(&entry.local_root)?;
            let base_materialization = match root_pipeline
                .materialize_git_archive(&worker_config, &entry.local_root, spec.base_commit())
                .await
            {
                Ok(materialization) => materialization,
                Err(error) => {
                    if let Some(history) =
                        error.downcast_ref::<crate::transfer::TransferAttemptsExhausted>()
                    {
                        for attempt in &history.attempts {
                            reporter.verbose(&format!(
                                "[RCH] clean-overlay base transfer attempt {}/{} {} before remote Cargo execution: {}",
                                attempt.attempt,
                                attempt.max_attempts,
                                attempt.outcome,
                                attempt.detail
                            ));
                        }
                        if let Some(summary) = source_sync_terminal_summary(&history.attempts, true)
                        {
                            reporter.summary(&summary);
                        }
                    }
                    return Err(error.context(
                        "clean-overlay base transfer failed before remote Cargo execution",
                    ));
                }
            };
            for attempt in &base_materialization.attempts {
                reporter.verbose(&format!(
                    "[RCH] clean-overlay base transfer attempt {}/{} {} before remote Cargo execution: {}",
                    attempt.attempt, attempt.max_attempts, attempt.outcome, attempt.detail
                ));
            }
            let base_result = base_materialization.sync_result;
            spec.verify_archive_attributes(&entry.local_root).await?;
            let result = if spec.is_base_only() {
                base_result
            } else {
                let overlay_result = if sync_streaming {
                    root_pipeline
                        .sync_to_remote_streaming(&worker_config, |line| {
                            sync_progress_line(
                                upload_progress.as_mut(),
                                sync_heartbeat_state.as_ref(),
                                line,
                            );
                        })
                        .await?
                } else {
                    root_pipeline.sync_to_remote(&worker_config).await?
                };
                merge_sync_result(&base_result, &overlay_result)
            };
            spec.verify_overlay_unchanged(&entry.local_root)?;
            Ok(result)
        } else if sync_streaming {
            root_pipeline
                .sync_to_remote_streaming(&worker_config, |line| {
                    sync_progress_line(
                        upload_progress.as_mut(),
                        sync_heartbeat_state.as_ref(),
                        line,
                    );
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
                if let Some(prepared) = prepared_source_root {
                    prepared_source_roots.push(prepared);
                }
                root_outcomes.push((entry.clone(), SyncRootOutcome::Synced));
            }
            Err(e) => {
                if entry.is_primary || exact_dependency_closure_sync || source_content_receipt {
                    // Cargo dependency-closure builds must not continue against
                    // stale sibling repositories on the worker.
                    if let Some(history) =
                        e.downcast_ref::<crate::transfer::TransferAttemptsExhausted>()
                    {
                        for attempt in &history.attempts {
                            reporter.verbose(&format!(
                                "[RCH] source sync attempt {}/{} {} before remote Cargo execution: {}",
                                attempt.attempt,
                                attempt.max_attempts,
                                attempt.outcome,
                                attempt.detail
                            ));
                        }
                        if let Some(summary) =
                            source_sync_terminal_summary(&history.attempts, false)
                        {
                            reporter.summary(&summary);
                        }
                    } else {
                        reporter.summary(&format!(
                            "[RCH] source sync failed before remote Cargo execution; remote Cargo was not started: {e}"
                        ));
                    }
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
    if clean_overlay.is_none() && forwarded_cargo_target_dir.is_some() {
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

    if exact_dependency_closure_sync {
        verify_remote_dependency_manifests(&worker_config, &root_outcomes, reporter).await?;
    }

    if source_content_build_id.is_some() {
        if prepared_source_roots.len() != sync_plan.len() {
            anyhow::bail!(
                "source-content proof prepared {} of {} planned roots",
                prepared_source_roots.len(),
                sync_plan.len()
            );
        }
        // Admission check immediately before Cargo opens the isolated source
        // tree. The same roots are verified again after Cargo exits, and only
        // then is the single receipt emitted.
        verify_source_content_roots(&worker_config, &prepared_source_roots).await?;
    }
    if let Some(lock) = source_authority_lock.as_mut() {
        lock.ensure_held()?;
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

    if let Some(lock) = source_authority_lock.take() {
        lock.release().await?;
        reporter.verbose(&format!(
            "[RCH] released remote source-authority locks on {} after Cargo exit",
            worker_config.id
        ));
    }

    let stderr_capture = std::mem::take(&mut *stderr_capture_cell.borrow_mut());

    info!(
        "Remote command finished: exit={} in {}ms",
        result.exit_code, result.duration_ms
    );
    reporter.verbose(&format!(
        "[RCH] exec done: exit={} in {}ms",
        result.exit_code, result.duration_ms
    ));

    if let Some(proof_build_id) = source_content_build_id {
        let receipt = finalize_source_content_receipt(
            &worker_config,
            proof_build_id,
            command,
            result.exit_code,
            &prepared_source_roots,
        )
        .await?;
        reporter.summary_critical(&format!(
            "[RCH] source content receipt: {}",
            receipt.canonical_json()?
        ));
    }

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
    // Per-file evidence from the phase that carries the build's `target/`
    // outputs, for the zero-build-output loud-failure gate (bd-mpbav): the
    // matched-file manifest and the rsync-reported matched regular-file count.
    // `custom_target_basis` records which path basis the manifest uses (paths
    // relative to the remote target dir vs `target/`-prefixed project-root
    // paths); `expected_output_patterns` feeds the failure message.
    let mut retrieval_manifest: Vec<String> = Vec::new();
    let mut retrieval_matched_regular: Option<u32> = None;
    let mut retrieval_custom_target_basis = false;
    let mut expected_output_patterns: Vec<String> = Vec::new();
    // Step 3: Retrieve artifacts
    if result.success() {
        if let Some(loop_ref) = heartbeat_loop.as_ref() {
            loop_ref.update_phase(
                BuildHeartbeatPhase::SyncDown,
                Some("artifact_sync_start".to_string()),
            );
            loop_ref.flush().await;
        }
        // Project-root artifact retrieval. When a custom CARGO_TARGET_DIR is
        // forwarded, the build's `target/` outputs are retrieved exclusively by
        // the custom-target phase below; the project-root phase must not carry
        // `target/`-prefixed patterns, or it re-materializes stale worker-side
        // `<project>/target/` residue onto the local project-root filesystem the
        // custom target dir exists to protect, and a failed stale-residue pull
        // spuriously fails an otherwise-complete build (rch#30). For cargo
        // build/doc/rustc the filtered list is empty, so the phase is skipped.
        let artifact_patterns = get_project_artifact_patterns(
            kind,
            Some(command),
            forwarded_cargo_target_dir.is_some(),
        );
        if !artifact_patterns.is_empty() {
            info!("Retrieving build artifacts...");
            reporter.verbose("[RCH] artifacts: retrieving...");
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
                        artifact_result.stats.files_transferred,
                        artifact_result.stats.bytes_transferred,
                        artifact_result.stats.duration_ms
                    );
                    reporter.verbose(&format!(
                        "[RCH] artifacts done: {} files, {} bytes in {}ms",
                        artifact_result.stats.files_transferred,
                        artifact_result.stats.bytes_transferred,
                        artifact_result.stats.duration_ms
                    ));
                    if let Some(progress) = &mut download_progress {
                        progress.apply_summary(
                            artifact_result.stats.bytes_transferred,
                            artifact_result.stats.files_transferred,
                        );
                        progress.finish();
                    }
                    // Default-root basis: this phase carries the `target/`
                    // outputs whenever no custom target dir is forwarded, so
                    // its manifest is the zero-output gate's evidence.
                    if forwarded_cargo_target_dir.is_none() {
                        retrieval_manifest = artifact_result.manifest_regular_files;
                        retrieval_matched_regular = artifact_result.matched_regular_files;
                        retrieval_custom_target_basis = false;
                        expected_output_patterns = expected_output_glob_list(&artifact_patterns);
                    }
                    artifacts_result = Some(match artifacts_result.take() {
                        Some(existing) => merge_sync_result(&existing, &artifact_result.stats),
                        None => artifact_result.stats,
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
        } // end: project-root artifact retrieval (skipped when patterns empty)

        if let Some(local_target_dir) = forwarded_cargo_target_dir.as_ref() {
            let remote_target_path = pipeline.remote_cargo_target_dir();
            let custom_patterns = get_custom_target_artifact_patterns(kind, Some(command));
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
                .with_remote_path_override(remote_target_path.clone())
                .with_worker_platform(WorkerPlatform::from_worker(&worker_config));

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
                            target_result.stats.files_transferred,
                            target_result.stats.bytes_transferred,
                            target_result.stats.duration_ms
                        );
                        reporter.verbose(&format!(
                            "[RCH] custom target dir sync done: {} -> {} ({} files, {} bytes in {}ms)",
                            remote_target_path,
                            local_target_dir.display(),
                            target_result.stats.files_transferred,
                            target_result.stats.bytes_transferred,
                            target_result.stats.duration_ms
                        ));
                        if let Some(progress) = &mut target_progress {
                            progress.apply_summary(
                                target_result.stats.bytes_transferred,
                                target_result.stats.files_transferred,
                            );
                            progress.finish();
                        }
                        // The custom-target phase exclusively carries the
                        // build's `target/` outputs under a forwarded
                        // CARGO_TARGET_DIR, so its manifest is the
                        // zero-output gate's evidence (paths relative to the
                        // target-dir sync root).
                        retrieval_manifest = target_result.manifest_regular_files;
                        retrieval_matched_regular = target_result.matched_regular_files;
                        retrieval_custom_target_basis = true;
                        expected_output_patterns = expected_output_glob_list(&custom_patterns);
                        artifacts_result = Some(match artifacts_result.take() {
                            Some(existing) => merge_sync_result(&existing, &target_result.stats),
                            None => target_result.stats,
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

    // Step 3b: declared job result directories (bd-p0yoo). Unlike patterned
    // artifact sync-back above, this is NOT gated on `result.success()`:
    // GH#27 exists precisely because non-compilation jobs (sharded tests,
    // fuzzers, mutation testing) produce their valuable output on FAILURE
    // exits too. Each directory is pulled as an explicit rsync source, so a
    // directory the job never created is a hard error rather than a silent
    // zero-file success. Any failure overrides the surfaced exit code below
    // bd-uoh4x: capture per-dir collection outcomes for the machine envelope.
    let mut result_dir_failures: Vec<String> = Vec::new();
    let mut exec_dir_stats: Vec<ExecResultDirStat> = Vec::new();
    if !result_dirs.is_empty() {
        if let Some(loop_ref) = heartbeat_loop.as_ref() {
            loop_ref.update_phase(
                BuildHeartbeatPhase::SyncDown,
                Some("result_dir_sync_start".to_string()),
            );
            loop_ref.flush().await;
        }
        for dir in result_dirs {
            match pipeline.retrieve_result_dir(&worker_config, dir).await {
                Ok(retrieved) => {
                    reporter.verbose(&format!(
                        "[RCH] result dir '{}': {} files, {} bytes",
                        dir.display(),
                        retrieved.files_transferred,
                        retrieved.bytes_transferred
                    ));
                    exec_dir_stats.push(ExecResultDirStat {
                        path: dir.display().to_string(),
                        files: u64::from(retrieved.files_transferred),
                        bytes: retrieved.bytes_transferred,
                        status: "ok".to_string(),
                    });
                }
                Err(e) => {
                    warn!(
                        "Declared result dir '{}' could not be retrieved from {}: {}",
                        dir.display(),
                        worker_config.id,
                        e
                    );
                    result_dir_failures.push(format!("{}: {}", dir.display(), e));
                    exec_dir_stats.push(ExecResultDirStat {
                        path: dir.display().to_string(),
                        files: 0,
                        bytes: 0,
                        status: "collection_failed".to_string(),
                    });
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
    let exit_code = if !result_dir_failures.is_empty() {
        // Declared job result directories (bd-p0yoo) could not be retrieved.
        // This outranks the job's own exit status: a run whose declared
        // outputs are absent or partial is untrustworthy no matter what the
        // command reported, and GH#27 requires reliable result return
        // INCLUDING on nonzero exits. Same loud-fatal treatment as the
        // artifact sync-back failure below (issue #19 Fix 1 precedent).
        let code = ErrorCode::BuildArtifactMissing;
        // stderr, not just `warn!`: this MUST reach the operator/agent even
        // when tracing is silenced. stderr is the diagnostics stream.
        eprintln!(
            "[RCH] {} job on {} exited {} but declared result directories could \
         not be retrieved — the invocation's outputs are INCOMPLETE: {}. \
         Treating as a transfer failure (exit {EXIT_ARTIFACT_TRANSFER_FAILED}).",
            code.code_string(),
            worker_config.id,
            result.exit_code,
            result_dir_failures.join("; "),
        );
        warn!(
            "Result-dir retrieval failed on {} after remote exit {}; \
         returning exit {} so the caller knows declared outputs are missing",
            worker_config.id, result.exit_code, EXIT_ARTIFACT_TRANSFER_FAILED
        );
        EXIT_ARTIFACT_TRANSFER_FAILED
    } else if result.success() && artifacts_failed && kind_produces_transferable_artifacts(kind) {
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
    } else if result.success()
        && !artifacts_failed
        && sync_back_verified_zero_build_outputs(
            &retrieval_manifest,
            retrieval_matched_regular,
            kind,
            retrieval_custom_target_basis,
        )
    {
        // bd-mpbav loud failure, layer B: the sync-back SUCCEEDED (unlike the
        // issue-#19 arm above) yet matched ZERO build outputs — every matched
        // file was loose target metadata or cache state. The classic cause is
        // an output directory the include patterns don't cover (a custom
        // cargo profile's `target/<profile>/` before layer A added its globs,
        // or any future pattern gap): the remote binary exists, rsync happily
        // pulls 4 metadata files, exits 0, and the LOCAL artifact silently
        // stays the previous build's. Surfacing exit 0 here would let an
        // agent benchmark or ship a stale binary. Same class of loud-fatal
        // treatment as issue #19 Fix 1, with its own error code so the two
        // hazards are distinguishable in logs (E326 vs E309).
        let code = ErrorCode::BuildArtifactSyncEmpty;
        let expected = expected_output_patterns.join(", ");
        // stderr, not just `warn!`: this MUST reach the operator/agent even
        // when tracing is silenced. stderr is the diagnostics stream (AGENTS.md).
        eprintln!(
            "[RCH] {} remote compile on {} SUCCEEDED but the artifact sync-back \
             matched ZERO build outputs ({} of {} matched file(s): {}) — the local \
             build is INCOMPLETE and any existing local artifacts may be STALE. \
             Expected outputs under: {}. Treating as a build failure \
             (exit {EXIT_ARTIFACT_TRANSFER_FAILED}); re-run to retry the sync, or \
             build locally before trusting any binary.",
            code.code_string(),
            worker_config.id,
            retrieval_manifest.len(),
            retrieval_matched_regular.unwrap_or(0),
            retrieval_manifest.join(", "),
            expected,
        );
        warn!(
            "Artifact sync-back matched zero build outputs after a successful remote \
             compile on {} [{}]; returning exit {} so the caller knows local \
             artifacts may be stale",
            worker_config.id,
            code.code_string(),
            EXIT_ARTIFACT_TRANSFER_FAILED
        );
        EXIT_ARTIFACT_TRANSFER_FAILED
    } else {
        result.exit_code
    };

    // bd-p1vlb: a clean-overlay root is invocation-unique (a job nonce is
    // hashed into it) and holds a full materialized snapshot; once artifacts
    // and declared result dirs are retrieved above, the tree is dead weight
    // on the worker's staging base. Best-effort reap: failures only log —
    // residue is caught by periodic `rch cache clean --base` sweeps — and
    // never affect the surfaced exit code.
    if let Some(overlay_remote_root) = overlay_remote_root.as_deref() {
        match pipeline
            .reap_remote_tree(&worker_config, overlay_remote_root)
            .await
        {
            Ok(()) => reporter.verbose(&format!(
                "[RCH] clean-overlay remote root {overlay_remote_root} reaped"
            )),
            Err(e) => warn!(
                "clean-overlay reap of {} on {} failed (residue ages out): {e}",
                overlay_remote_root, worker_config.id
            ),
        }
    }

    Ok(RemoteExecutionResult {
        exit_code,
        stderr: stderr_capture,
        duration_ms: result.duration_ms,
        timing,
        result_dirs: exec_dir_stats,
    })
}

#[cfg(test)]
mod tests {
    use super::clean_overlay_remote_project_hash;

    #[test]
    fn clean_overlay_concurrent_jobs_use_distinct_remote_roots() {
        let base = "0123456789abcdef0123456789abcdef01234567";
        let first = std::thread::spawn(move || {
            clean_overlay_remote_project_hash(
                base,
                "first-dirty-overlay-fingerprint",
                uuid::Uuid::from_u128(1),
            )
        });
        let second = std::thread::spawn(move || {
            clean_overlay_remote_project_hash(
                base,
                "second-conflicting-overlay-fingerprint",
                uuid::Uuid::from_u128(2),
            )
        });

        let first_root = first.join().expect("first clean-overlay job panicked");
        let second_root = second.join().expect("second clean-overlay job panicked");
        assert_ne!(
            first_root, second_root,
            "concurrent clean-overlay jobs must never share a remote root"
        );

        let fixed_nonce = uuid::Uuid::from_u128(3);
        assert_ne!(
            clean_overlay_remote_project_hash(base, "first-dirty-overlay-fingerprint", fixed_nonce,),
            clean_overlay_remote_project_hash(
                "fedcba9876543210fedcba9876543210fedcba98",
                "first-dirty-overlay-fingerprint",
                fixed_nonce,
            ),
            "the immutable base must be part of the remote-root identity"
        );
        assert_ne!(
            clean_overlay_remote_project_hash(base, "first-dirty-overlay-fingerprint", fixed_nonce,),
            clean_overlay_remote_project_hash(
                base,
                "second-conflicting-overlay-fingerprint",
                fixed_nonce,
            ),
            "the dirty overlay fingerprint must be part of the remote-root identity"
        );
    }

    /// Issue #60 regression: the pooled target store must resolve to the SAME
    /// absolute path for two clean-overlay executions whose remote roots
    /// differ only by job nonce — and that path must sit OUTSIDE both
    /// (teardown-reaped) roots, while keeping the `.rch-target-…-pool-…`
    /// naming GC conventions rely on.
    #[test]
    fn clean_overlay_pooled_target_dir_is_stable_across_job_nonces() {
        use super::clean_overlay_stable_pooled_target_dir;

        let base_commit = "0123456789abcdef0123456789abcdef01234567";
        let fingerprint = "same-overlay-fingerprint";
        let hash_a =
            clean_overlay_remote_project_hash(base_commit, fingerprint, uuid::Uuid::from_u128(10));
        let hash_b =
            clean_overlay_remote_project_hash(base_commit, fingerprint, uuid::Uuid::from_u128(11));
        assert_ne!(hash_a, hash_b, "job nonces must keep remote roots distinct");

        let remote_base = "/data/tmp/rch";
        let project_id = "myproject";
        let root_a = format!("{remote_base}/{project_id}/{hash_a}");
        let root_b = format!("{remote_base}/{project_id}/{hash_b}");

        let pooled_name = ".rch-target-w1-pool-0123456789abcdef0123456789abcdef";
        let pool_a = clean_overlay_stable_pooled_target_dir(remote_base, project_id, pooled_name);
        let pool_b = clean_overlay_stable_pooled_target_dir(remote_base, project_id, pooled_name);

        assert_eq!(pool_a, pool_b, "pool location must not vary with the job nonce");
        assert!(
            !pool_a.starts_with(&root_a) && !pool_a.starts_with(&root_b),
            "pool must live outside every per-command root: {pool_a}"
        );
        assert!(
            pool_a.contains("/.rch-target-") && pool_a.contains("-pool-"),
            "pool must keep the GC-recognized .rch-target-…-pool-… naming: {pool_a}"
        );
        // Trailing-slash remote_base normalizes identically.
        assert_eq!(
            clean_overlay_stable_pooled_target_dir("/data/tmp/rch/", project_id, pooled_name),
            pool_a
        );
    }
}
