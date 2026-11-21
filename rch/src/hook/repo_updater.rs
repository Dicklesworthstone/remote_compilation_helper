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
//! `rch_common` in `hook.rs`) and `HookReporter`. The shared SSH primitives it
//! drives (`run_offload_ssh_command`, `should_skip_remote_preflight`) live in
//! the sibling `ssh` submodule and are imported explicitly below. The sync-root
//! detection helpers (`collect_repo_updater_roots_and_specs`,
//! `status_probe::local`, `detect_remote_unsuitable_sync_roots`) and their
//! `RepoUpdaterSyncRoots` carrier are local to this module. Only the symbols
//! consumed from outside the moved set (`execute_remote_compilation` and the
//! hook test suite) are `pub(super)`; everything else stays private.

use super::ssh::{
    run_offload_ssh_command, should_skip_remote_preflight, wrap_remote_source_activity,
};
use super::*;

mod status_probe;

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
    source_identity: Option<&str>,
) -> anyhow::Result<bool> {
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
        return Ok(false);
    }

    let invocation = build_invocation(&request, contract);
    let remote_cmd = build_repo_updater_remote_command(&invocation);
    const UNAVAILABLE: &[u8] = b"RCH_REPO_UPDATER_UNAVAILABLE\n";
    let remote_cmd = match source_identity {
        Some(identity) => {
            // The optional adapter may be absent. Prove that before invoking
            // it; after an invoked mutator fails, cancel instead of continuing
            // toward execution while one of its children might survive.
            let checked = format!(
                "if ! command -v {} >/dev/null 2>&1; then printf 'RCH_REPO_UPDATER_UNAVAILABLE\\n'; exit 0; fi; {remote_cmd}",
                shell_escape::escape(invocation.binary.as_str().into())
            );
            wrap_remote_source_activity(&checked, identity)?
        }
        None => remote_cmd,
    };
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

        match run_offload_ssh_command(worker, &remote_cmd, Duration::from_secs(timeout_secs)).await
        {
            Ok(output) if output.status.success() => {
                if source_identity.is_some() && output.stdout == UNAVAILABLE {
                    reporter.verbose(
                        "[RCH] repo_updater unavailable; using direct source synchronization",
                    );
                    return Ok(false);
                }
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
                return Ok(true);
            }
            Ok(output) if source_identity.is_some() => {
                anyhow::bail!(
                    "repo_updater failed; source preparation must be cancelled before continuing: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
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
                    return Ok(false);
                }
            }
            Err(err) if source_identity.is_some() => {
                return Err(err.context(
                    "repo_updater source preparation remains unconfirmed; cancellation required",
                ));
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
                    return Ok(false);
                }
            }
        }
    }

    Ok(false)
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
    source_identity: Option<&str>,
) -> anyhow::Result<()> {
    if sync_roots.len() <= 1 {
        return Ok(());
    }
    if should_skip_remote_preflight(worker) {
        reporter.verbose("[RCH] repo_updater pre-sync skipped in mock mode");
        return Ok(());
    }

    let repo_updater_roots = collect_repo_updater_roots_and_specs(sync_roots).await;
    if repo_updater_roots.specs.is_empty() {
        reporter.verbose("[RCH] repo_updater pre-sync skipped (no git origin remotes found)");
        return Ok(());
    }

    let dirty_roots = match status_probe::local(&repo_updater_roots.roots).await {
        Ok(roots) => roots,
        Err(err) => {
            // Unknown local state is not a clean checkout. This optional
            // convergence pass must not mutate repositories on that basis;
            // the normal source sync still performs its own integrity checks.
            reporter.verbose(&format!(
                "[RCH] repo_updater pre-sync skipped (local status unconfirmed: {err})"
            ));
            return Ok(());
        }
    };
    if !dirty_roots.is_empty() {
        let joined = dirty_roots
            .iter()
            .map(|(path, reason)| format!("{} ({reason})", path.display()))
            .collect::<Vec<_>>()
            .join(", ");
        reporter.verbose(&format!(
            "[RCH] repo_updater pre-sync skipped (dirty/unavailable local sync roots: {joined})"
        ));
        return Ok(());
    }

    let remote_unsuitable_roots =
        detect_remote_unsuitable_sync_roots(worker, &repo_updater_roots.roots, source_identity)
            .await?;
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
        return Ok(());
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
        return Ok(());
    }

    // Read-only convergence preflight to surface policy/auth/drift issues before mutation.
    let dry_run_ok = execute_repo_updater_command(
        worker,
        &contract,
        &request,
        &repo_updater_roots.roots,
        RepoUpdaterAdapterCommand::SyncDryRun,
        reporter,
        source_identity,
    )
    .await?;
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
        source_identity,
    )
    .await?;
    if sync_apply_ok {
        // Post-apply non-mutating snapshot for diagnostics and observability.
        let _ = execute_repo_updater_command(
            worker,
            &contract,
            &request,
            &repo_updater_roots.roots,
            RepoUpdaterAdapterCommand::StatusNoFetch,
            reporter,
            source_identity,
        )
        .await?;
    }
    Ok(())
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct RepoUpdaterSyncRoots {
    pub(super) roots: Vec<PathBuf>,
    pub(super) specs: Vec<String>,
}

const MAX_CONCURRENT_ORIGIN_PROBES: usize = 8;
const MAX_ORIGIN_RESPONSE_BYTES: usize = 16 * 1024;
const ORIGIN_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Origin discovery is optional preparation, not an unbounded prerequisite to
/// direct synchronization. Keep the directly owned Git process and its output
/// inside one deadline, including a Git process that closes stdout but stalls
/// before exiting. Cancellation drops and kills that process as well.
async fn probe_repo_origin(
    mut command: Command,
    allowance: Duration,
) -> anyhow::Result<Option<String>> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("cannot start repository origin probe")?;
    let stdout = child.stdout.take().context("missing origin probe stdout")?;
    let observed = async {
        let mut bytes = Vec::new();
        stdout
            .take((MAX_ORIGIN_RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .await?;
        anyhow::ensure!(
            bytes.len() <= MAX_ORIGIN_RESPONSE_BYTES,
            "repository origin response exceeded its bound"
        );
        let status = child.wait().await?;
        if !status.success() {
            return Ok(None);
        }
        let origin = String::from_utf8_lossy(&bytes).trim().to_string();
        Ok::<_, anyhow::Error>((!origin.is_empty()).then_some(origin))
    };
    let result = tokio::time::timeout(allowance, observed)
        .await
        .context("repository origin probe timed out")
        .and_then(std::convert::identity);
    if result.is_err() {
        // Do not leave a timed-out or overproducing Git process running while
        // direct source sync proceeds. The kill-on-drop owner remains active
        // if cancellation interrupts this bounded reap.
        let _ = child.start_kill();
        let _ = tokio::time::timeout(Duration::from_secs(1), child.wait()).await;
    }
    result
}

pub(super) async fn collect_repo_updater_roots_and_specs(
    sync_roots: &[PathBuf],
) -> RepoUpdaterSyncRoots {
    collect_repo_updater_roots_with(sync_roots, |root| async move {
        let mut command = Command::new("git");
        command
            .arg("-C")
            .arg(root)
            .arg("remote")
            .arg("get-url")
            .arg("origin");
        probe_repo_origin(command, ORIGIN_PROBE_TIMEOUT)
            .await
            .ok()
            .flatten()
    })
    .await
}

async fn collect_repo_updater_roots_with<F, Fut>(
    sync_roots: &[PathBuf],
    mut probe: F,
) -> RepoUpdaterSyncRoots
where
    F: FnMut(PathBuf) -> Fut,
    Fut: std::future::Future<Output = Option<String>>,
{
    use futures::StreamExt;

    // Futures remain in this task: dropping preparation drops every active
    // process owner. Unordered polling lets later roots progress when an early
    // Git probe stalls, without spawning one process per closure entry at once.
    let mut completed =
        futures::stream::iter(sync_roots.iter().enumerate().map(|(index, root)| {
            let origin = probe(root.clone());
            async move { (index, root, origin.await) }
        }))
        .buffer_unordered(MAX_CONCURRENT_ORIGIN_PROBES)
        .collect::<Vec<_>>()
        .await;
    completed.sort_by_key(|(index, _, _)| *index);

    let mut specs = std::collections::BTreeSet::new();
    let mut roots = Vec::new();
    for (_, root, origin) in completed {
        if let Some(origin) = origin {
            roots.push(root.clone());
            specs.insert(origin);
        }
    }

    RepoUpdaterSyncRoots {
        roots,
        specs: specs.into_iter().collect(),
    }
}

async fn detect_remote_unsuitable_sync_roots(
    worker: &WorkerConfig,
    sync_roots: &[PathBuf],
    source_identity: Option<&str>,
) -> anyhow::Result<Vec<(PathBuf, String)>> {
    if !crate::transfer::WorkerPlatform::from_worker(worker).is_windows() {
        return status_probe::remote(worker, sync_roots, source_identity).await;
    }
    // Windows uses stdin for the control script itself, not a second data
    // stream. Retain its existing transport until the batch protocol has a
    // separately qualified Windows framing path.
    let mut unsuitable = Vec::new();

    for root in sync_roots {
        let escaped_root = shell_escape::escape(root.to_string_lossy()).to_string();
        let command = format!("GIT_OPTIONAL_LOCKS=0 git -C {escaped_root} status --porcelain");
        let command = match source_identity {
            Some(identity) => wrap_remote_source_activity(&command, identity)?,
            None => command,
        };

        match run_offload_ssh_command(worker, &command, Duration::from_secs(10)).await {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if !stdout.trim().is_empty() {
                    unsuitable.push((root.clone(), "dirty".to_string()));
                }
            }
            Ok(output)
                if source_identity.is_some() && !matches!(output.status.code(), Some(0..=254)) =>
            {
                anyhow::bail!("remote repository status transport ended without completion");
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
            Err(err) if source_identity.is_some() => return Err(err),
            Err(err) => unsuitable.push((root.clone(), format!("status probe error: {err}"))),
        }
    }

    Ok(unsuitable)
}

#[cfg(test)]
mod origin_probe_tests {
    use super::*;

    fn git_command(root: &Path, home: &Path) -> Command {
        let mut command = Command::new("git");
        command
            .arg("-C")
            .arg(root)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .stdin(Stdio::null())
            .kill_on_drop(true);
        command
    }

    async fn git_ok(root: &Path, home: &Path, args: &[&str]) {
        let output = git_command(root, home).args(args).output().await.unwrap();
        assert!(output.status.success(), "{args:?}: {output:?}");
    }

    async fn wait_for_probe_pids(paths: &[PathBuf]) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while paths.iter().any(|path| {
                std::fs::read_to_string(path)
                    .ok()
                    .and_then(|value| value.trim().parse::<u32>().ok())
                    .is_none()
            }) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("origin probe processes did not reach their fixture barrier");
    }

    async fn assert_processes_reaped(paths: &[PathBuf]) {
        let pids: Vec<_> = paths
            .iter()
            .map(|path| {
                let pid = std::fs::read_to_string(path)
                    .unwrap()
                    .trim()
                    .parse::<i32>()
                    .unwrap();
                rustix::process::Pid::from_raw(pid).unwrap()
            })
            .collect();
        tokio::time::timeout(Duration::from_secs(5), async {
            while pids
                .iter()
                .any(|pid| rustix::process::test_kill_process(*pid) != Err(rustix::io::Errno::SRCH))
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("an owned origin probe survived cancellation or its deadline");
    }

    #[tokio::test]
    async fn origin_discovery_preserves_git_rewrites_and_distinct_worktree_origins() {
        let retained = tempfile::tempdir().unwrap().keep();
        let home = retained.join("home");
        let root = retained.join("repo-'\n");
        let linked = retained.join("linked");
        let no_origin = retained.join("no-origin");
        for directory in [&home, &root, &no_origin] {
            std::fs::create_dir(directory).unwrap();
        }
        git_ok(&root, &home, &["init", "-q", "--initial-branch=main"]).await;
        git_ok(
            &root,
            &home,
            &[
                "config",
                "url.https://example.invalid/.insteadOf",
                "fixture:",
            ],
        )
        .await;
        git_ok(
            &root,
            &home,
            &["config", "extensions.worktreeConfig", "true"],
        )
        .await;
        git_ok(
            &root,
            &home,
            &[
                "config",
                "--worktree",
                "remote.origin.url",
                "fixture:source.git",
            ],
        )
        .await;
        git_ok(
            &root,
            &home,
            &[
                "-c",
                "user.name=Origin Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "--allow-empty",
                "-q",
                "-m",
                "initial",
            ],
        )
        .await;
        git_ok(
            &root,
            &home,
            &[
                "worktree",
                "add",
                "-q",
                "-b",
                "linked",
                linked.to_str().unwrap(),
            ],
        )
        .await;
        git_ok(
            &linked,
            &home,
            &[
                "config",
                "--worktree",
                "remote.origin.url",
                "fixture:linked.git",
            ],
        )
        .await;
        git_ok(&no_origin, &home, &["init", "-q"]).await;
        let nested = root.join("nested");
        std::fs::create_dir(&nested).unwrap();
        let roots = [
            linked.clone(),
            root.clone(),
            retained.join("missing"),
            no_origin,
            nested.clone(),
        ];
        let collected = collect_repo_updater_roots_with(&roots, |root| {
            let mut command = git_command(&root, &home);
            command.args(["remote", "get-url", "origin"]);
            async move {
                probe_repo_origin(command, ORIGIN_PROBE_TIMEOUT)
                    .await
                    .ok()
                    .flatten()
            }
        })
        .await;
        assert_eq!(collected.roots, [linked, root, nested]);
        assert_eq!(
            collected.specs,
            [
                "https://example.invalid/linked.git",
                "https://example.invalid/source.git",
            ]
        );
    }

    #[tokio::test]
    async fn origin_probe_bounds_bytes_and_waits_for_successful_process_exit() {
        for (script, accepted) in [
            ("printf 'https://example.invalid/repo.git\\n'", true),
            (
                "read unused || printf 'https://example.invalid/repo.git\\n'",
                true,
            ),
            (
                "printf 'https://example.invalid/repo.git\\n'; exit 1",
                false,
            ),
            ("exit 0", false),
        ] {
            let mut command = Command::new("sh");
            command.args(["-c", script]);
            let origin = probe_repo_origin(command, Duration::from_secs(2))
                .await
                .unwrap();
            assert_eq!(origin.is_some(), accepted, "{script}");
        }
        let mut overflow = Command::new("sh");
        overflow.args(["-c", "printf '%16385s' ''"]);
        let error = probe_repo_origin(overflow, Duration::from_secs(2))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("exceeded its bound"),
            "{error:#}"
        );

        let retained = tempfile::tempdir().unwrap().keep();
        for (case, script) in [
            "printf '%s\\n' \"$$\" > \"$1\"; exec sleep 30",
            "printf '%s\\n' \"$$\" > \"$1\"; exec 1>&-; exec sleep 30",
        ]
        .into_iter()
        .enumerate()
        {
            let pid = retained.join(format!("{case}.pid"));
            let mut command = Command::new("sh");
            command.args(["-c", script, "origin-fixture"]).arg(&pid);
            let error = probe_repo_origin(command, Duration::from_secs(2))
                .await
                .unwrap_err();
            assert!(error.to_string().contains("timed out"), "{error:#}");
            assert_processes_reaped(&[pid]).await;
        }
    }

    #[tokio::test]
    async fn origin_discovery_admits_later_roots_without_waiting_for_the_first() {
        let retained = tempfile::tempdir().unwrap().keep();
        let roots: Vec<_> = (0..MAX_CONCURRENT_ORIGIN_PROBES + 3)
            .map(|index| retained.join(index.to_string()))
            .collect();
        let last_started = roots.last().unwrap().with_extension("started");
        let collected = collect_repo_updater_roots_with(&roots, |root| {
            let mut command = Command::new("sh");
            // The first process cannot finish until a root beyond the initial
            // window has run. Sequential execution or ordered head blocking
            // would time it out and lose an otherwise valid repository.
            command
                .args([
                    "-c",
                    "printf started > \"$1.started\"; if [ \"${1##*/}\" = 0 ]; then while [ ! -f \"$2\" ]; do sleep 0.01; done; fi; printf 'https://example.invalid/%s.git\\n' \"${1##*/}\"",
                    "origin-fixture",
                ])
                .arg(&root)
                .arg(&last_started);
            async move {
                probe_repo_origin(command, Duration::from_secs(5))
                    .await
                    .ok()
                    .flatten()
            }
        })
        .await;
        assert_eq!(collected.roots, roots);
        assert_eq!(collected.specs.len(), roots.len());
    }

    #[tokio::test]
    async fn cancelling_origin_discovery_drops_every_bounded_process_owner() {
        let retained = tempfile::tempdir().unwrap().keep();
        let roots: Vec<_> = (0..MAX_CONCURRENT_ORIGIN_PROBES + 3)
            .map(|index| retained.join(format!("{index}.pid")))
            .collect();
        let mut discovery = Box::pin(collect_repo_updater_roots_with(&roots, |root| {
            let mut command = Command::new("sh");
            command
                .args([
                    "-c",
                    "printf '%s\\n' \"$$\" > \"$1\"; exec sleep 30",
                    "origin-fixture",
                ])
                .arg(root);
            async move {
                probe_repo_origin(command, Duration::from_secs(20))
                    .await
                    .ok()
                    .flatten()
            }
        }));
        tokio::select! {
            _ = &mut discovery => panic!("stalled origin discovery completed unexpectedly"),
            () = wait_for_probe_pids(&roots[..MAX_CONCURRENT_ORIGIN_PROBES]) => {},
        }
        drop(discovery);
        assert!(
            roots[MAX_CONCURRENT_ORIGIN_PROBES..]
                .iter()
                .all(|root| !root.exists())
        );
        assert_processes_reaped(&roots[..MAX_CONCURRENT_ORIGIN_PROBES]).await;
    }
}
