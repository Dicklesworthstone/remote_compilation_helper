//! repo_updater pre-sync orchestration for the hook.
//!
//! When a build's path-dependency closure spans more than one repository, RCH
//! converges the worker's checkout of that closure *before* transferring code,
//! by driving the `repo_updater` adapter over SSH. This submodule owns that
//! whole subsystem (extracted from `hook.rs` per bead
//! `remote_compilation_helper-zcecy.14`):
//!
//! - `maybe_sync_repo_set_with_repo_updater` — the top-level orchestrator,
//!   called once from `execute_remote_compilation`. It collects the repo
//!   closure, gates on dirty/unsuitable sync roots, resolves the adapter
//!   contract + auth context, then runs a dry-run / sync-apply / status pass.
//! - the adapter-invocation layer (`execute_repo_updater_command`,
//!   `build_repo_updater_remote_command`, `repo_updater_command_name`,
//!   `repo_updater_timeout_for`, the idempotency-key builders).
//! - the contract/auth-context resolution layer (env policy, auto-tuning,
//!   inference, hydration, operator overrides) and its env-parsing primitives.
//!
//! It reaches everything it needs from the parent via `use super::*`: the
//! `RepoUpdater*` contract types and `REPO_UPDATER_*` consts (re-exported from
//! `rch_common` in `hook.rs`), the shared SSH helper `run_worker_ssh_command`,
//! the sync-root detection helpers (`collect_repo_updater_roots_and_specs`,
//! `detect_dirty_sync_roots`, `detect_remote_unsuitable_sync_roots`,
//! `should_skip_remote_preflight`) and their `RepoUpdaterSyncRoots` carrier,
//! and `HookReporter`. Only the six symbols consumed from outside the moved set
//! (`execute_remote_compilation` and the hook test suite) are `pub(super)`;
//! everything else stays private to this module.

use super::*;

fn repo_updater_timeout_for(
    contract: &RepoUpdaterAdapterContract,
    command: RepoUpdaterAdapterCommand,
) -> u64 {
    contract
        .command_budgets
        .iter()
        .find(|budget| budget.command == command)
        .map(|budget| budget.timeout_secs)
        .unwrap_or(contract.timeout_policy.sync_timeout_secs)
        .max(1)
}

fn build_repo_updater_remote_command(
    invocation: &rch_common::repo_updater_contract::RepoUpdaterInvocation,
) -> String {
    let env_prefix = invocation
        .env
        .iter()
        .map(|(k, v)| format!("{k}={}", shell_escape::escape(v.as_str().into())))
        .collect::<Vec<_>>()
        .join(" ");
    let escaped_binary = shell_escape::escape(invocation.binary.as_str().into()).to_string();
    let escaped_args = invocation
        .args
        .iter()
        .map(|arg| shell_escape::escape(arg.as_str().into()).to_string())
        .collect::<Vec<_>>()
        .join(" ");
    if env_prefix.is_empty() {
        format!("{escaped_binary} {escaped_args}")
    } else {
        format!("{env_prefix} {escaped_binary} {escaped_args}")
    }
}

fn build_repo_sync_idempotency_key(worker_id: &WorkerId, sync_roots: &[PathBuf]) -> String {
    build_repo_sync_idempotency_key_for_command(
        worker_id,
        sync_roots,
        RepoUpdaterAdapterCommand::SyncApply,
    )
}

pub(super) fn repo_updater_command_name(command: RepoUpdaterAdapterCommand) -> &'static str {
    match command {
        RepoUpdaterAdapterCommand::ListPaths => "list-paths",
        RepoUpdaterAdapterCommand::StatusNoFetch => "status-no-fetch",
        RepoUpdaterAdapterCommand::SyncDryRun => "sync-dry-run",
        RepoUpdaterAdapterCommand::SyncApply => "sync-apply",
        RepoUpdaterAdapterCommand::RobotDocsSchemas => "robot-docs-schemas",
        RepoUpdaterAdapterCommand::Version => "version",
    }
}

pub(super) fn build_repo_sync_idempotency_key_for_command(
    worker_id: &WorkerId,
    sync_roots: &[PathBuf],
    command: RepoUpdaterAdapterCommand,
) -> String {
    let mut material = worker_id.as_str().to_string();
    material.push('|');
    material.push_str(repo_updater_command_name(command));
    for root in sync_roots {
        material.push('|');
        material.push_str(&root.to_string_lossy());
    }
    let hash = blake3::hash(material.as_bytes()).to_hex();
    format!("rch-repo-sync-{}", &hash[..16])
}

async fn execute_repo_updater_command(
    worker: &WorkerConfig,
    contract: &RepoUpdaterAdapterContract,
    base_request: &RepoUpdaterAdapterRequest,
    sync_roots: &[PathBuf],
    command: RepoUpdaterAdapterCommand,
    reporter: &HookReporter,
) -> bool {
    let mut request = base_request.clone();
    let timeout_secs = repo_updater_timeout_for(contract, command);
    request.command = command;
    request.timeout_secs = timeout_secs;
    request.idempotency_key =
        build_repo_sync_idempotency_key_for_command(&worker.id, sync_roots, command);

    if let Err(err) = request.validate(contract) {
        let failure_kind = err.failure_kind();
        warn!(
            "repo_updater {} validation failed for {} [{} {:?}]: {}",
            repo_updater_command_name(command),
            worker.id,
            err.reason_code(),
            failure_kind,
            err
        );
        reporter.verbose(&format!(
            "[RCH] repo_updater {} skipped (validation failed [{} {:?}]): {} | remediation: {}",
            repo_updater_command_name(command),
            err.reason_code(),
            failure_kind,
            err,
            err.remediation()
        ));
        return false;
    }

    let invocation = build_invocation(&request, contract);
    let remote_cmd = build_repo_updater_remote_command(&invocation);
    let retry_policy = &contract.retry_policy;
    let max_attempts = retry_policy.max_attempts.max(1);
    let mut backoff_ms = retry_policy.initial_backoff_ms;

    for attempt in 0..max_attempts {
        if attempt > 0 {
            reporter.verbose(&format!(
                "[RCH] repo_updater {} retry {}/{} on {} (backoff {}ms)",
                repo_updater_command_name(command),
                attempt + 1,
                max_attempts,
                worker.id,
                backoff_ms
            ));
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
            backoff_ms = backoff_ms
                .saturating_mul(u64::from(retry_policy.backoff_multiplier_percent))
                .saturating_div(100)
                .min(retry_policy.max_backoff_ms);
        }

        match run_worker_ssh_command(worker, &remote_cmd, Duration::from_secs(timeout_secs)).await {
            Ok(output) if output.status.success() => {
                if attempt > 0 {
                    reporter.verbose(&format!(
                        "[RCH] repo_updater {} succeeded on attempt {}/{} for {} repositories on {}",
                        repo_updater_command_name(command),
                        attempt + 1,
                        max_attempts,
                        request.repo_specs.len(),
                        worker.id
                    ));
                } else {
                    reporter.verbose(&format!(
                        "[RCH] repo_updater {} succeeded for {} repositories on {}",
                        repo_updater_command_name(command),
                        request.repo_specs.len(),
                        worker.id
                    ));
                }
                return true;
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                warn!(
                    "repo_updater {} failed on {} attempt {}/{} (status {:?}): {}",
                    repo_updater_command_name(command),
                    worker.id,
                    attempt + 1,
                    max_attempts,
                    output.status.code(),
                    stderr
                );
                // Last attempt — give up
                if attempt + 1 >= max_attempts {
                    reporter.verbose(&format!(
                        "[RCH] repo_updater {} exhausted {} attempts on {} (continuing with direct sync)",
                        repo_updater_command_name(command),
                        max_attempts,
                        worker.id
                    ));
                    return false;
                }
            }
            Err(err) => {
                warn!(
                    "repo_updater {} transport failure on {} attempt {}/{}: {}",
                    repo_updater_command_name(command),
                    worker.id,
                    attempt + 1,
                    max_attempts,
                    err
                );
                // Last attempt — give up
                if attempt + 1 >= max_attempts {
                    reporter.verbose(&format!(
                        "[RCH] repo_updater {} unavailable on {} after {} attempts (continuing with direct sync)",
                        repo_updater_command_name(command),
                        max_attempts,
                        worker.id
                    ));
                    return false;
                }
            }
        }
    }

    false
}

fn parse_csv_env_var(var_name: &str) -> Option<Vec<String>> {
    let raw = std::env::var(var_name).ok()?;
    let entries = raw
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>();
    (!entries.is_empty()).then_some(entries)
}

fn parse_host_identity_pairs(raw: &str) -> Vec<(String, String)> {
    raw.split(',')
        .filter_map(|entry| {
            let trimmed = entry.trim();
            let (host, fingerprint) = trimmed.split_once('=')?;
            let host = host.trim();
            let fingerprint = fingerprint.trim();
            if host.is_empty() || fingerprint.is_empty() {
                return None;
            }
            Some((host.to_string(), fingerprint.to_string()))
        })
        .collect()
}

fn parse_auth_source(raw: &str) -> Option<RepoUpdaterCredentialSource> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "gh_cli" | "gh" => Some(RepoUpdaterCredentialSource::GhCli),
        "token_env" | "token" => Some(RepoUpdaterCredentialSource::TokenEnv),
        "ssh_agent" | "ssh" => Some(RepoUpdaterCredentialSource::SshAgent),
        _ => None,
    }
}

fn parse_auth_mode(raw: &str) -> Option<RepoUpdaterAuthMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "inherit_environment" | "inherit" => Some(RepoUpdaterAuthMode::InheritEnvironment),
        "require_gh_auth" | "gh" | "gh_cli" => Some(RepoUpdaterAuthMode::RequireGhAuth),
        "require_token_env" | "token_env" | "token" => Some(RepoUpdaterAuthMode::RequireTokenEnv),
        _ => None,
    }
}

fn env_flag_is_truthy(var_name: &str) -> bool {
    std::env::var(var_name)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn env_var_present(var_name: &str) -> bool {
    std::env::var(var_name)
        .ok()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
}

fn apply_repo_updater_contract_env_policy(contract: &mut RepoUpdaterAdapterContract) {
    if let Some(hosts) = parse_csv_env_var(REPO_UPDATER_ALLOWED_HOSTS_ENV) {
        contract.trust_policy.allowed_repo_hosts = hosts;
    }
    if let Some(spec_allowlist) = parse_csv_env_var(REPO_UPDATER_ALLOWLIST_ENV) {
        contract.trust_policy.allowlisted_repo_specs = spec_allowlist;
    }
    if let Ok(raw_mode) = std::env::var(REPO_UPDATER_AUTH_MODE_ENV)
        && let Some(mode) = parse_auth_mode(&raw_mode)
    {
        contract.auth_policy.mode = mode;
    }
    if env_flag_is_truthy(REPO_UPDATER_ALLOW_OVERRIDE_ENV) {
        contract.trust_policy.allow_operator_override = true;
    }
    if let Some(required_scopes) = parse_csv_env_var(REPO_UPDATER_REQUIRED_SCOPES_ENV) {
        contract.auth_policy.required_scopes = required_scopes;
    }
    if let Ok(rotation_max_age_secs) = std::env::var(REPO_UPDATER_ROTATION_MAX_AGE_SECS_ENV)
        && let Ok(parsed) = rotation_max_age_secs.trim().parse::<u64>()
    {
        contract.auth_policy.rotation_max_age_secs = parsed.max(1);
    }
    if env_flag_is_truthy(REPO_UPDATER_REQUIRE_HOST_IDENTITY_ENV) {
        contract.auth_policy.require_host_identity_verification = true;
    }
    if let Ok(raw_identities) = std::env::var(REPO_UPDATER_TRUSTED_HOST_IDENTITIES_ENV) {
        let trusted = parse_host_identity_pairs(&raw_identities)
            .into_iter()
            .map(|(host, key_fingerprint)| RepoUpdaterTrustedHostIdentity {
                host,
                key_fingerprint,
            })
            .collect::<Vec<_>>();
        if !trusted.is_empty() {
            contract.auth_policy.trusted_host_identities = trusted;
        }
    }
}

fn repo_updater_auth_context_env_supplied() -> bool {
    [
        REPO_UPDATER_AUTH_SOURCE_ENV,
        REPO_UPDATER_AUTH_CREDENTIAL_ID_ENV,
        REPO_UPDATER_AUTH_ISSUED_AT_MS_ENV,
        REPO_UPDATER_AUTH_EXPIRES_AT_MS_ENV,
        REPO_UPDATER_AUTH_SCOPES_ENV,
        REPO_UPDATER_AUTH_REVOKED_ENV,
        REPO_UPDATER_AUTH_VERIFIED_HOSTS_ENV,
    ]
    .iter()
    .any(|var_name| std::env::var(var_name).is_ok())
}

pub(super) fn infer_repo_updater_auth_context_with_env_lookup<F>(
    requested_at_unix_ms: i64,
    env_present: F,
) -> Option<RepoUpdaterAuthContext>
where
    F: Fn(&str) -> bool,
{
    let (source, credential_id, granted_scopes) = if env_present("GH_TOKEN") {
        (
            RepoUpdaterCredentialSource::TokenEnv,
            "env:GH_TOKEN".to_string(),
            vec!["repo:read".to_string()],
        )
    } else if env_present("GITHUB_TOKEN") {
        (
            RepoUpdaterCredentialSource::TokenEnv,
            "env:GITHUB_TOKEN".to_string(),
            vec!["repo:read".to_string()],
        )
    } else if env_present("SSH_AUTH_SOCK") {
        (
            RepoUpdaterCredentialSource::SshAgent,
            "ssh-agent".to_string(),
            Vec::new(),
        )
    } else {
        return None;
    };

    let issued_at_unix_ms = if requested_at_unix_ms > 1_000 {
        requested_at_unix_ms - 1_000
    } else {
        1
    };
    let expires_at_unix_ms = requested_at_unix_ms.saturating_add(86_400_000);

    Some(RepoUpdaterAuthContext {
        source,
        credential_id,
        issued_at_unix_ms,
        expires_at_unix_ms,
        granted_scopes,
        revoked: false,
        verified_hosts: Vec::new(),
    })
}

fn infer_repo_updater_auth_context(requested_at_unix_ms: i64) -> Option<RepoUpdaterAuthContext> {
    infer_repo_updater_auth_context_with_env_lookup(requested_at_unix_ms, env_var_present)
}

pub(super) fn auto_tune_repo_updater_contract(
    contract: &mut RepoUpdaterAdapterContract,
    repo_specs: &[String],
    auth_context: Option<&RepoUpdaterAuthContext>,
    has_explicit_allowlist: bool,
    has_explicit_auth_mode: bool,
    reporter: &HookReporter,
) {
    if !has_explicit_allowlist
        && contract.trust_policy.enforce_repo_spec_allowlist
        && contract.trust_policy.allowlisted_repo_specs.is_empty()
    {
        contract.trust_policy.allowlisted_repo_specs = repo_specs.to_vec();
        reporter.verbose(&format!(
            "[RCH] repo_updater allowlist auto-seeded from dependency closure ({} repos)",
            contract.trust_policy.allowlisted_repo_specs.len()
        ));
    }

    if !has_explicit_auth_mode {
        contract.auth_policy.mode = match auth_context.map(|ctx| ctx.source) {
            Some(RepoUpdaterCredentialSource::TokenEnv) => RepoUpdaterAuthMode::RequireTokenEnv,
            Some(RepoUpdaterCredentialSource::GhCli) => RepoUpdaterAuthMode::RequireGhAuth,
            Some(RepoUpdaterCredentialSource::SshAgent) | None => {
                RepoUpdaterAuthMode::InheritEnvironment
            }
        };
        reporter.verbose(&format!(
            "[RCH] repo_updater auth mode auto-selected: {:?}",
            contract.auth_policy.mode
        ));
    }
}

pub(super) fn hydrate_repo_updater_auth_context_defaults(
    auth_context: &mut RepoUpdaterAuthContext,
    requested_at_unix_ms: i64,
    contract: &RepoUpdaterAdapterContract,
) {
    if auth_context.credential_id.trim().is_empty() {
        auth_context.credential_id = match auth_context.source {
            RepoUpdaterCredentialSource::GhCli => "gh-cli",
            RepoUpdaterCredentialSource::TokenEnv => "token-env",
            RepoUpdaterCredentialSource::SshAgent => "ssh-agent",
        }
        .to_string();
    }

    if auth_context.issued_at_unix_ms <= 0 || auth_context.issued_at_unix_ms > requested_at_unix_ms
    {
        auth_context.issued_at_unix_ms = if requested_at_unix_ms > 1_000 {
            requested_at_unix_ms - 1_000
        } else {
            1
        };
    }

    if auth_context.expires_at_unix_ms <= requested_at_unix_ms {
        let ttl_ms_u64 = contract
            .auth_policy
            .rotation_max_age_secs
            .saturating_mul(1_000)
            .max(60_000);
        let ttl_ms = i64::try_from(ttl_ms_u64).unwrap_or(i64::MAX / 2);
        auth_context.expires_at_unix_ms = requested_at_unix_ms.saturating_add(ttl_ms);
    }

    if auth_context.granted_scopes.is_empty() && !contract.auth_policy.required_scopes.is_empty() {
        auth_context.granted_scopes = contract.auth_policy.required_scopes.clone();
    }

    if auth_context.verified_hosts.is_empty()
        && contract.auth_policy.require_host_identity_verification
    {
        auth_context.verified_hosts = contract
            .auth_policy
            .trusted_host_identities
            .iter()
            .map(|identity| RepoUpdaterVerifiedHostIdentity {
                host: identity.host.clone(),
                key_fingerprint: identity.key_fingerprint.clone(),
                verified_at_unix_ms: requested_at_unix_ms,
            })
            .collect();
    }
}

fn repo_updater_operator_override_from_env() -> Option<RepoUpdaterOperatorOverride> {
    let operator_id = std::env::var(REPO_UPDATER_OVERRIDE_OPERATOR_ID_ENV).ok();
    let justification = std::env::var(REPO_UPDATER_OVERRIDE_JUSTIFICATION_ENV).ok();
    let ticket_ref = std::env::var(REPO_UPDATER_OVERRIDE_TICKET_REF_ENV).ok();
    let audit_event_id = std::env::var(REPO_UPDATER_OVERRIDE_AUDIT_EVENT_ID_ENV).ok();
    let approved_at_unix_ms = std::env::var(REPO_UPDATER_OVERRIDE_APPROVED_AT_MS_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<i64>().ok())
        .unwrap_or_default();

    if operator_id.is_none()
        && justification.is_none()
        && ticket_ref.is_none()
        && audit_event_id.is_none()
        && approved_at_unix_ms == 0
    {
        return None;
    }

    Some(RepoUpdaterOperatorOverride {
        operator_id: operator_id.unwrap_or_default(),
        justification: justification.unwrap_or_default(),
        ticket_ref: ticket_ref.unwrap_or_default(),
        audit_event_id: audit_event_id.unwrap_or_default(),
        approved_at_unix_ms,
    })
}

fn repo_updater_auth_context_from_env(requested_at_unix_ms: i64) -> Option<RepoUpdaterAuthContext> {
    let source = std::env::var(REPO_UPDATER_AUTH_SOURCE_ENV)
        .ok()
        .and_then(|raw| parse_auth_source(&raw));
    let credential_id = std::env::var(REPO_UPDATER_AUTH_CREDENTIAL_ID_ENV).ok();
    let issued_at_unix_ms = std::env::var(REPO_UPDATER_AUTH_ISSUED_AT_MS_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<i64>().ok());
    let expires_at_unix_ms = std::env::var(REPO_UPDATER_AUTH_EXPIRES_AT_MS_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<i64>().ok());
    let scopes = parse_csv_env_var(REPO_UPDATER_AUTH_SCOPES_ENV).unwrap_or_default();
    let revoked = env_flag_is_truthy(REPO_UPDATER_AUTH_REVOKED_ENV);
    let verified_hosts = std::env::var(REPO_UPDATER_AUTH_VERIFIED_HOSTS_ENV)
        .ok()
        .map(|raw| {
            parse_host_identity_pairs(&raw)
                .into_iter()
                .map(|(host, key_fingerprint)| RepoUpdaterVerifiedHostIdentity {
                    host,
                    key_fingerprint,
                    verified_at_unix_ms: requested_at_unix_ms,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    if source.is_none()
        && credential_id.is_none()
        && issued_at_unix_ms.is_none()
        && expires_at_unix_ms.is_none()
        && scopes.is_empty()
        && !revoked
        && verified_hosts.is_empty()
    {
        return None;
    }

    Some(RepoUpdaterAuthContext {
        source: source.unwrap_or(RepoUpdaterCredentialSource::TokenEnv),
        credential_id: credential_id.unwrap_or_default(),
        issued_at_unix_ms: issued_at_unix_ms.unwrap_or_default(),
        expires_at_unix_ms: expires_at_unix_ms.unwrap_or_default(),
        granted_scopes: scopes,
        revoked,
        verified_hosts,
    })
}

pub(super) async fn maybe_sync_repo_set_with_repo_updater(
    worker: &WorkerConfig,
    sync_roots: &[PathBuf],
    reporter: &HookReporter,
) {
    if sync_roots.len() <= 1 {
        return;
    }
    if should_skip_remote_preflight(worker) {
        reporter.verbose("[RCH] repo_updater pre-sync skipped in mock mode");
        return;
    }

    let repo_updater_roots = collect_repo_updater_roots_and_specs(sync_roots).await;
    if repo_updater_roots.specs.is_empty() {
        reporter.verbose("[RCH] repo_updater pre-sync skipped (no git origin remotes found)");
        return;
    }

    let dirty_roots = detect_dirty_sync_roots(&repo_updater_roots.roots).await;
    if !dirty_roots.is_empty() {
        let joined = dirty_roots
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(", ");
        reporter.verbose(&format!(
            "[RCH] repo_updater pre-sync skipped (dirty local sync roots: {joined})"
        ));
        return;
    }

    let remote_unsuitable_roots =
        detect_remote_unsuitable_sync_roots(worker, &repo_updater_roots.roots).await;
    if !remote_unsuitable_roots.is_empty() {
        let joined = remote_unsuitable_roots
            .iter()
            .map(|(path, reason)| format!("{} ({reason})", path.display()))
            .collect::<Vec<_>>()
            .join(", ");
        reporter.verbose(&format!(
            "[RCH] repo_updater pre-sync skipped (dirty/broken remote sync roots on {}: {joined})",
            worker.id
        ));
        return;
    }

    let mut contract = RepoUpdaterAdapterContract::default();
    apply_repo_updater_contract_env_policy(&mut contract);
    let has_explicit_allowlist = env_var_present(REPO_UPDATER_ALLOWLIST_ENV);
    let has_explicit_auth_mode = env_var_present(REPO_UPDATER_AUTH_MODE_ENV);

    let command = RepoUpdaterAdapterCommand::SyncApply;
    let timeout_secs = repo_updater_timeout_for(&contract, command);
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default();

    let mut auth_context = if repo_updater_auth_context_env_supplied() {
        repo_updater_auth_context_from_env(now_ms)
    } else {
        None
    };
    if auth_context.is_none() {
        auth_context = infer_repo_updater_auth_context(now_ms);
        if auth_context.is_some() {
            reporter.verbose("[RCH] repo_updater auth context inferred from runtime environment");
        } else {
            reporter.verbose(
                "[RCH] repo_updater auth context unavailable in local environment; sync-apply may be skipped",
            );
        }
    }

    auto_tune_repo_updater_contract(
        &mut contract,
        &repo_updater_roots.specs,
        auth_context.as_ref(),
        has_explicit_allowlist,
        has_explicit_auth_mode,
        reporter,
    );
    if let Some(context) = auth_context.as_mut() {
        hydrate_repo_updater_auth_context_defaults(context, now_ms, &contract);
    }

    let request = RepoUpdaterAdapterRequest {
        schema_version: rch_common::REPO_UPDATER_CONTRACT_SCHEMA_VERSION.to_string(),
        correlation_id: format!("rch-{}-{}", worker.id, now_ms),
        worker_id: worker.id.to_string(),
        command,
        requested_at_unix_ms: now_ms,
        projects_root: PathBuf::from(REPO_UPDATER_CANONICAL_PROJECTS_ROOT),
        repo_specs: repo_updater_roots.specs.clone(),
        idempotency_key: build_repo_sync_idempotency_key(&worker.id, &repo_updater_roots.roots),
        retry_attempt: 0,
        timeout_secs,
        expected_output_format: RepoUpdaterOutputFormat::Json,
        auth_context,
        operator_override: repo_updater_operator_override_from_env(),
    };

    if let Err(err) = request.validate(&contract) {
        let failure_kind = err.failure_kind();
        warn!(
            "repo_updater request validation failed for {} [{} {:?}]: {}",
            worker.id,
            err.reason_code(),
            failure_kind,
            err
        );
        reporter.verbose(&format!(
            "[RCH] repo_updater pre-sync skipped (validation failed [{} {:?}]): {} | remediation: {}",
            err.reason_code(),
            failure_kind,
            err,
            err.remediation()
        ));
        return;
    }

    // Read-only convergence preflight to surface policy/auth/drift issues before mutation.
    let dry_run_ok = execute_repo_updater_command(
        worker,
        &contract,
        &request,
        &repo_updater_roots.roots,
        RepoUpdaterAdapterCommand::SyncDryRun,
        reporter,
    )
    .await;
    if !dry_run_ok {
        reporter.verbose(
            "[RCH] repo_updater dry-run did not complete cleanly; attempting sync apply anyway",
        );
    }

    let sync_apply_ok = execute_repo_updater_command(
        worker,
        &contract,
        &request,
        &repo_updater_roots.roots,
        RepoUpdaterAdapterCommand::SyncApply,
        reporter,
    )
    .await;
    if sync_apply_ok {
        // Post-apply non-mutating snapshot for diagnostics and observability.
        let _ = execute_repo_updater_command(
            worker,
            &contract,
            &request,
            &repo_updater_roots.roots,
            RepoUpdaterAdapterCommand::StatusNoFetch,
            reporter,
        )
        .await;
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct RepoUpdaterSyncRoots {
    pub(super) roots: Vec<PathBuf>,
    pub(super) specs: Vec<String>,
}

pub(super) async fn collect_repo_updater_roots_and_specs(
    sync_roots: &[PathBuf],
) -> RepoUpdaterSyncRoots {
    let mut specs = std::collections::BTreeSet::new();
    let mut roots = Vec::new();

    for root in sync_roots {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .arg("remote")
            .arg("get-url")
            .arg("origin")
            .output()
            .await;

        let Ok(output) = output else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let remote = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !remote.is_empty() {
            roots.push(root.clone());
            specs.insert(remote);
        }
    }

    RepoUpdaterSyncRoots {
        roots,
        specs: specs.into_iter().collect(),
    }
}

async fn detect_dirty_sync_roots(sync_roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut dirty = Vec::new();

    for root in sync_roots {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .arg("status")
            .arg("--porcelain")
            .output()
            .await;

        let Ok(output) = output else {
            continue;
        };
        if !output.status.success() {
            continue;
        }

        let status = String::from_utf8_lossy(&output.stdout);
        if !status.trim().is_empty() {
            dirty.push(root.clone());
        }
    }

    dirty
}

async fn detect_remote_unsuitable_sync_roots(
    worker: &WorkerConfig,
    sync_roots: &[PathBuf],
) -> Vec<(PathBuf, String)> {
    let mut unsuitable = Vec::new();

    for root in sync_roots {
        let escaped_root = shell_escape::escape(root.to_string_lossy()).to_string();
        let command = format!("git -C {escaped_root} status --porcelain");

        match run_worker_ssh_command(worker, &command, Duration::from_secs(10)).await {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if !stdout.trim().is_empty() {
                    unsuitable.push((root.clone(), "dirty".to_string()));
                }
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                let reason = if stderr.is_empty() {
                    format!("git status failed with exit {:?}", output.status.code())
                } else {
                    format!("git status failed: {stderr}")
                };
                unsuitable.push((root.clone(), reason));
            }
            Err(err) => unsuitable.push((root.clone(), format!("status probe error: {err}"))),
        }
    }

    unsuitable
}
