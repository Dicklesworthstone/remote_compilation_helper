//! Source-registry storage evidence and its scheduling consequence (bd-5ojmb).
//!
//! A responsive SSH session or telemetry command does not prove that this user
//! can write ownership records. Keep storage refusals out of normal placement
//! until a real probe succeeds, without changing admin intent or claim state.

use super::{HealthCheckResult, HealthConfig, HealthProbeError, ProbeStage, derive_worker_status};
use crate::workers::RegistryStoragePressure;
use rch_common::{CircuitState, CommandResult, WorkerStatus};

// The wire/storage protocol path also used by the hook and worker GC. A test
// checks all three literals together; do not move a probe to another filesystem.
const REGISTRY: &str = "/var/tmp/rch-source-authority-locks/claims-v1";
const REFUSAL: &str = "RCH_SOURCE_REGISTRY_UNWRITABLE";
const DEGRADED: &str = "RCH_SOURCE_REGISTRY_DEGRADED";
const PRESSURE: &str = "RCH_SOURCE_REGISTRY_PRESSURE";
const RESERVE_UNSAFE: &str = "RCH_RECOVERY_RESERVE_UNSAFE";

pub(super) fn command() -> String {
    let ready = rch_common::recovery_reserve::readiness_command(REGISTRY);
    format!(
        "{ready}\n__rch_ready=$?; [ \"$__rch_ready\" -eq 0 ] || exit \"$__rch_ready\";\n{}\nrch_source_registry_health '{}'",
        include_str!("../source_registry_health.sh"),
        REGISTRY,
    )
}

pub(super) fn is_degraded(result: &HealthCheckResult) -> bool {
    result
        .error
        .as_deref()
        .is_some_and(|message| message.starts_with("RCH_SOURCE_REGISTRY_DEGRADED: "))
}

/// A confirmed storage failure is an immediate exclusion, not a slow response
/// or a network blip. Once excluded, an inconclusive probe cannot promote the
/// worker to Degraded (which accepts jobs), even if telemetry reset its circuit.
/// A successful storage probe resumes the ordinary circuit-governed policy.
/// A low-headroom warning (`RCH_SOURCE_REGISTRY_DEGRADED`) after a successful
/// scratch write marks the worker `Degraded` without taking it offline.
/// The caller applies this health result through the admin/quarantine lifecycle.
pub(super) fn status_after_probe(
    previous: WorkerStatus,
    circuit: CircuitState,
    result: &HealthCheckResult,
    config: &HealthConfig,
) -> WorkerStatus {
    let storage_refused = result
        .error
        .as_deref()
        .is_some_and(|message| message.starts_with("RCH_SOURCE_REGISTRY_UNWRITABLE: "));
    let storage_degraded = is_degraded(result);
    if !result.healthy
        && !storage_degraded
        && (storage_refused || previous == WorkerStatus::Unreachable)
    {
        WorkerStatus::Unreachable
    } else if storage_degraded && circuit != CircuitState::Open {
        WorkerStatus::Degraded
    } else {
        derive_worker_status(circuit, result.healthy, result.response_time_ms, config)
    }
}

/// Bound presentation without slicing through a UTF-8 code point. Classification
/// always sees the complete returned stderr, never the truncated excerpt.
fn excerpt(output: &str) -> String {
    let mut chars = output.trim().chars();
    let mut result: String = chars.by_ref().take(1024).collect();
    if chars.next().is_some() {
        result.push('…');
    }
    result
}

fn has_marker(output: &str, marker: &str) -> bool {
    output.lines().any(|line| {
        line.strip_prefix(marker)
            .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with(' '))
    })
}

/// Only the complete, dedicated pressure protocol grants a recovery attempt.
/// Error prose, an unrelated path, an unsafe reserve, or truncated/contradictory
/// output remains an ordinary refusal. Inspect before truncating diagnostics.
fn pressure_evidence(result: &CommandResult) -> Option<RegistryStoragePressure> {
    if result.exit_code != 75
        || !result.stdout.is_empty()
        || has_marker(&result.stderr, REFUSAL)
        || has_marker(&result.stderr, RESERVE_UNSAFE)
        || has_marker(&result.stderr, DEGRADED)
    {
        return None;
    }
    let prefix = format!("{PRESSURE} {REGISTRY}: ");
    let mut pressure = None;
    for line in result.stderr.split_inclusive('\n') {
        if !line.starts_with(PRESSURE) {
            continue;
        }
        let reason = line.strip_suffix('\n')?.strip_prefix(&prefix)?;
        let reason = match reason {
            "insufficient-headroom" => RegistryStoragePressure::InsufficientHeadroom,
            "no-space" => RegistryStoragePressure::NoSpace,
            "quota-exhausted" => RegistryStoragePressure::QuotaExhausted,
            "recovery-pending" => RegistryStoragePressure::RecoveryPending,
            _ => return None,
        };
        if pressure.replace(reason).is_some() {
            return None;
        }
    }
    pressure
}

pub(super) fn classify_output(result: &CommandResult) -> Result<(), HealthProbeError> {
    let registry_storage_pressure = pressure_evidence(result);
    let storage_refused = has_marker(&result.stderr, REFUSAL)
        || has_marker(&result.stderr, PRESSURE)
        || has_marker(&result.stderr, RESERVE_UNSAFE);
    let storage_degraded = result.stderr.lines().any(|line| {
        line.strip_prefix(DEGRADED)
            .is_some_and(|suffix| suffix.starts_with(' '))
    });
    if result.success()
        && result.stdout.trim() == "health_check"
        && !storage_refused
        && !storage_degraded
    {
        return Ok(());
    }
    let reason = if storage_refused {
        REFUSAL
    } else if storage_degraded {
        DEGRADED
    } else {
        "Unexpected response"
    };
    Err(HealthProbeError {
        message: format!(
            "{reason}: exit={}, stdout={}, stderr={}",
            result.exit_code,
            excerpt(&result.stdout),
            excerpt(&result.stderr),
        ),
        retryable: false,
        stage: ProbeStage::Command,
        registry_storage_pressure,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::{CircuitBreakerConfig, CircuitStats};

    fn output(exit_code: i32, stdout: &str, stderr: &str) -> CommandResult {
        CommandResult {
            exit_code,
            stdout: stdout.to_owned(),
            stderr: stderr.to_owned(),
            duration_ms: 1,
        }
    }

    fn refused() -> HealthCheckResult {
        let error = classify_output(&output(
            74,
            "",
            "RCH_SOURCE_REGISTRY_UNWRITABLE /tmp/claims: write\n",
        ))
        .expect_err("the storage probe must refuse");
        HealthCheckResult::command_failure(error.message, error.retryable)
    }

    #[test]
    fn exact_pressure_protocol_preserves_reason_before_diagnostic_excerpting() {
        for (reason, expected) in [
            (
                "insufficient-headroom",
                RegistryStoragePressure::InsufficientHeadroom,
            ),
            ("no-space", RegistryStoragePressure::NoSpace),
            ("quota-exhausted", RegistryStoragePressure::QuotaExhausted),
            ("recovery-pending", RegistryStoragePressure::RecoveryPending),
        ] {
            let stderr = format!("{}\n{PRESSURE} {REGISTRY}: {reason}\n", "λ".repeat(1500));
            let error = classify_output(&output(75, "", &stderr)).expect_err("storage refused");
            assert_eq!(error.registry_storage_pressure, Some(expected));
            let result = HealthCheckResult::from_probe_error(error);
            assert_eq!(result.registry_storage_pressure, Some(expected));
            assert_eq!(
                status_after_probe(
                    WorkerStatus::Healthy,
                    CircuitState::Closed,
                    &result,
                    &HealthConfig::default(),
                ),
                WorkerStatus::Unreachable,
                "recovery permission must never admit ordinary builds"
            );
        }
    }

    #[test]
    fn pressure_exception_requires_one_complete_matching_uncontradicted_record() {
        let valid = format!("{PRESSURE} {REGISTRY}: no-space\n");
        for candidate in [
            output(0, "", &valid),
            output(74, "", &valid),
            output(75, "health_check\n", &valid),
            output(75, "", valid.trim_end()),
            output(
                75,
                "",
                &format!("{PRESSURE} /unrelated/registry: no-space\n"),
            ),
            output(
                75,
                "",
                &format!("{PRESSURE} {REGISTRY}/released: no-space\n"),
            ),
            output(75, "", &format!("{PRESSURE} {REGISTRY}: unknown-header\n")),
            output(75, "", &format!("{PRESSURE} {REGISTRY}: no-space extra\n")),
            output(75, "", &format!("{valid}{valid}")),
            output(75, "", &format!("{valid}{REFUSAL} {REGISTRY}: symlink\n")),
            output(
                75,
                "",
                &format!("{valid}{RESERVE_UNSAFE} {REGISTRY}: identity\n"),
            ),
            output(
                75,
                "",
                &format!(
                    "{PRESSURE} {REGISTRY}: recovery-pending\n{RESERVE_UNSAFE} {REGISTRY}: substituted-claim\n"
                ),
            ),
            output(
                75,
                "",
                &format!("{valid}{DEGRADED} {REGISTRY}: free_bytes=0\n"),
            ),
        ] {
            let error = classify_output(&candidate).expect_err("invalid pressure must refuse");
            assert_eq!(error.registry_storage_pressure, None, "{candidate:?}");
            let result = HealthCheckResult::from_probe_error(error);
            assert_eq!(
                status_after_probe(
                    WorkerStatus::Healthy,
                    CircuitState::Closed,
                    &result,
                    &HealthConfig::default(),
                ),
                WorkerStatus::Unreachable,
                "uncertain storage must stay excluded: {candidate:?}"
            );
        }
        for stderr in [
            format!("{REFUSAL} {REGISTRY}: no space left on device\n"),
            format!("{REFUSAL} {REGISTRY}: quota exceeded\n"),
            format!("{RESERVE_UNSAFE} {REGISTRY}: unknown-header\n"),
            format!("tool mentioned {PRESSURE} {REGISTRY}: no-space\n"),
        ] {
            let error = classify_output(&output(74, "", &stderr)).expect_err("failed probe");
            assert_eq!(error.registry_storage_pressure, None, "{stderr}");
        }
    }

    #[tokio::test]
    async fn repeated_storage_pressure_allows_recovery_without_reopening_build_placement() {
        use crate::workers::{WorkerPool, WorkerState};
        use rch_common::{WorkerConfig, WorkerId};
        use std::time::Duration;

        let pool = WorkerPool::new();
        let id = WorkerId::new("pressure-recovery");
        pool.add_worker(WorkerConfig {
            id: id.clone(),
            ..Default::default()
        })
        .await;
        let worker = pool.get(&id).await.unwrap();
        let config = HealthConfig::default();
        let endpoint = worker.endpoint_snapshot().await;
        let network = worker.background_probe().await.unwrap();
        let pressure = format!("{PRESSURE} {REGISTRY}: insufficient-headroom\n");
        let pending = format!("{PRESSURE} {REGISTRY}: recovery-pending\n");
        for diagnostic in [&pressure, &pending] {
            for _ in
                0..config.circuit.failure_threshold + config.circuit.command_failure_threshold + 2
            {
                let result = HealthCheckResult::from_probe_error(
                    classify_output(&output(75, "", diagnostic)).expect_err("storage refused"),
                );
                let endpoint_guard = worker.lock_current_endpoint(&endpoint).await.unwrap();
                let publication_guard = worker.lock_network_publication(&network).await.unwrap();
                assert!(
                    worker
                        .record_registry_storage_pressure(
                            &endpoint,
                            &network,
                            result.registry_storage_pressure,
                        )
                        .await
                );
                worker
                    .record_transport_result(true, config.check_interval, &config.circuit)
                    .await;
                let (_, circuit) =
                    super::super::record_probe_circuit_outcome(&worker, &result, &config).await;
                let status = status_after_probe(worker.status().await, circuit, &result, &config);
                worker.apply_health_status(status).await;
                drop(publication_guard);
                drop(endpoint_guard);
                assert_eq!(worker.status().await, WorkerStatus::Unreachable);
                assert_eq!(circuit, CircuitState::Closed);
                assert_eq!(
                    worker.circuit_stats().await.consecutive_command_failures(),
                    0
                );
                assert!(worker.background_disk_recovery_allowed().await);
                assert!(pool.healthy_workers().await.is_empty());
            }
        }

        // A later failed exchange clears the typed exception before revoking
        // this network generation, just as the health publisher does.
        let failed = HealthCheckResult::transient_failure("connection reset".into());
        assert!(
            worker
                .record_registry_storage_pressure(
                    &endpoint,
                    &network,
                    failed.registry_storage_pressure
                )
                .await
        );
        worker
            .record_transport_result(false, config.check_interval, &config.circuit)
            .await;
        super::super::record_probe_circuit_outcome(&worker, &failed, &config).await;
        assert!(worker.registry_storage_pressure().await.is_none());
        assert!(!worker.background_disk_recovery_allowed().await);

        // Completed pressure probes do not force an already-open circuit shut
        // or erase unrelated command-failure debt during its cooldown.
        let blocked = WorkerState::new(WorkerConfig::default());
        let config = HealthConfig {
            circuit: CircuitBreakerConfig {
                command_failure_threshold: 1,
                open_cooldown_secs: 60,
                ..Default::default()
            },
            check_interval: Duration::from_secs(30),
            ..Default::default()
        };
        blocked.record_command_outcome(false, &config.circuit).await;
        let result = HealthCheckResult::from_probe_error(
            classify_output(&output(75, "", &pressure)).expect_err("storage refused"),
        );
        let (_, circuit) =
            super::super::record_probe_circuit_outcome(&blocked, &result, &config).await;
        assert_eq!(circuit, CircuitState::Open);
        assert_eq!(
            blocked.circuit_stats().await.consecutive_command_failures(),
            1
        );
        assert!(!blocked.background_disk_recovery_allowed().await);
    }

    #[test]
    fn command_uses_the_ownership_registry_and_real_helper() {
        let invocation = format!("rch_source_registry_health '{REGISTRY}'");
        assert!(command().contains(invocation.as_str()));
        // These are protocol locations, not caller-selected scratch roots.
        let hook = include_str!("../../../rch/src/hook/ssh.rs");
        let namespace = include_str!("../../../rch/src/hook/source_namespace.rs");
        let gc = include_str!("../../../rch-common/src/stale_target_reap.rs");
        let hook_path = format!("const REMOTE_SOURCE_CLAIM_REGISTRY: &str = \"{REGISTRY}\";");
        let namespace_path = format!("const REGISTRY: &str = \"{REGISTRY}\";");
        let gc_path = format!("const SOURCE_CLAIM_REGISTRY: &str = \"{REGISTRY}\";");
        assert!(hook.contains(hook_path.as_str()));
        assert!(namespace.contains(namespace_path.as_str()));
        assert!(gc.contains(gc_path.as_str()));
    }

    #[test]
    fn storage_refusal_is_command_evidence_not_transport_retry() {
        let error = classify_output(&output(
            74,
            "",
            "RCH_SOURCE_REGISTRY_UNWRITABLE /tmp/claims: write\n",
        ))
        .expect_err("unwritable storage must not succeed");
        assert!(
            error
                .message
                .starts_with("RCH_SOURCE_REGISTRY_UNWRITABLE: ")
        );
        assert!(error.message.contains("write"));
        assert_eq!(error.stage, ProbeStage::Command);
        assert!(!error.retryable);
    }

    #[test]
    fn success_cannot_override_a_storage_refusal() {
        assert!(
            classify_output(&output(
                0,
                "health_check\n",
                "RCH_SOURCE_REGISTRY_UNWRITABLE /tmp/claims: cleanup\n",
            ))
            .is_err()
        );
        assert!(classify_output(&output(0, "health_check\n", "")).is_ok());
        assert!(classify_output(&output(74, "health_check\n", "")).is_err());
        assert!(classify_output(&output(0, "partial", "")).is_err());
    }

    #[test]
    fn refusal_beyond_excerpt_is_still_classified() {
        let stderr = format!("{}\n{REFUSAL} /tmp/claims: write\n", "λ".repeat(5000));
        let error = classify_output(&output(74, "", &stderr)).expect_err("must refuse");
        assert!(
            error
                .message
                .starts_with("RCH_SOURCE_REGISTRY_UNWRITABLE: ")
        );
        assert!(error.message.chars().count() < 1200);
        assert!(error.message.ends_with('…'));
    }

    #[test]
    fn incidental_marker_text_is_not_storage_evidence() {
        let error = classify_output(&output(
            1,
            "",
            "tool mentioned RCH_SOURCE_REGISTRY_UNWRITABLE in a diagnostic\n",
        ))
        .expect_err("the command failed");
        assert!(error.message.starts_with("Unexpected response:"));
    }

    #[test]
    fn confirmed_refusal_excludes_independently_of_circuit_thresholds() {
        for circuit in [
            CircuitState::Closed,
            CircuitState::HalfOpen,
            CircuitState::Open,
        ] {
            assert_eq!(
                status_after_probe(
                    WorkerStatus::Healthy,
                    circuit,
                    &refused(),
                    &HealthConfig::default(),
                ),
                WorkerStatus::Unreachable,
            );
        }
    }

    #[test]
    fn unknown_health_does_not_reopen_an_excluded_worker_after_telemetry_success() {
        let config = HealthConfig::default();
        let mut circuit = CircuitStats::new();
        circuit.apply_command_outcome(false, &config.circuit);
        circuit.apply_command_outcome(true, &config.circuit);
        for result in [
            HealthCheckResult::transient_failure("connection reset".into()),
            HealthCheckResult::command_failure("probe timed out".into(), true),
            HealthCheckResult::failure("no usable response".into()),
        ] {
            assert_eq!(
                status_after_probe(WorkerStatus::Unreachable, circuit.state(), &result, &config,),
                WorkerStatus::Unreachable,
            );
        }
    }

    #[test]
    fn successful_storage_probe_resumes_circuit_governed_recovery() {
        let config = HealthConfig {
            circuit: CircuitBreakerConfig {
                command_failure_threshold: 1,
                success_threshold: 2,
                open_cooldown_secs: 0,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut circuit = CircuitStats::new();
        circuit.apply_command_outcome(false, &config.circuit);
        circuit.apply_command_outcome(true, &config.circuit);
        circuit.apply_command_outcome(true, &config.circuit);
        assert_eq!(circuit.state(), CircuitState::Closed);
        assert_eq!(
            status_after_probe(
                WorkerStatus::Unreachable,
                circuit.state(),
                &HealthCheckResult::success(1),
                &config,
            ),
            WorkerStatus::Healthy,
        );
        assert_eq!(
            status_after_probe(
                WorkerStatus::Unreachable,
                CircuitState::Open,
                &HealthCheckResult::success(1),
                &config,
            ),
            WorkerStatus::Unreachable,
        );
    }

    #[test]
    fn ordinary_first_transport_failure_retains_existing_policy() {
        assert_eq!(
            status_after_probe(
                WorkerStatus::Healthy,
                CircuitState::Closed,
                &HealthCheckResult::failure("network".into()),
                &HealthConfig::default(),
            ),
            WorkerStatus::Degraded,
        );
    }

    #[test]
    fn storage_recovery_never_overrides_admin_intent_or_quarantine() {
        use crate::workers::{AdminIntent, EligibilityState, WorkerLifecycle};

        let config = HealthConfig::default();
        let failed = status_after_probe(
            WorkerStatus::Healthy,
            CircuitState::Closed,
            &refused(),
            &config,
        );
        let recovered = status_after_probe(
            failed,
            CircuitState::Closed,
            &HealthCheckResult::success(1),
            &config,
        );
        assert_eq!(failed, WorkerStatus::Unreachable);
        let eligibility = match recovered {
            WorkerStatus::Healthy => EligibilityState::Healthy,
            other => panic!("storage did not recover: {other:?}"),
        };
        for admin in [
            AdminIntent::Disabled,
            AdminIntent::Draining,
            AdminIntent::Drained,
        ] {
            let mut lifecycle = WorkerLifecycle::new();
            lifecycle.set_admin(admin);
            lifecycle.observe_health(EligibilityState::Unreachable);
            lifecycle.observe_health(eligibility);
            assert_eq!(lifecycle.admin, admin);
            assert!(!lifecycle.is_schedulable());
        }
        for quarantined in [
            EligibilityState::TemporaryBypass,
            EligibilityState::RecoveredPendingCanary,
        ] {
            let mut lifecycle = WorkerLifecycle {
                eligibility: quarantined,
                ..Default::default()
            };
            assert!(!lifecycle.observe_health(eligibility));
            assert_eq!(lifecycle.eligibility, quarantined);
            assert!(!lifecycle.is_schedulable());
        }
    }

    #[test]
    fn degraded_headroom_marks_worker_degraded_without_exclusion() {
        let error = classify_output(&output(
            75,
            "",
            "RCH_SOURCE_REGISTRY_DEGRADED /var/tmp/rch-source-authority-locks/claims-v1: free_bytes=1048576 free_kb=1024 free_inodes=512\n",
        ))
        .expect_err("low headroom must surface as degraded probe result");
        assert!(error.message.starts_with("RCH_SOURCE_REGISTRY_DEGRADED: "));
        assert!(error.message.contains("free_bytes=1048576"));
        let result = HealthCheckResult::command_failure(error.message, error.retryable);
        assert!(is_degraded(&result));
        assert_eq!(
            status_after_probe(
                WorkerStatus::Healthy,
                CircuitState::Closed,
                &result,
                &HealthConfig::default(),
            ),
            WorkerStatus::Degraded,
        );
        assert_eq!(
            status_after_probe(
                WorkerStatus::Unreachable,
                CircuitState::Closed,
                &result,
                &HealthConfig::default(),
            ),
            WorkerStatus::Degraded,
        );
        assert_eq!(
            status_after_probe(
                WorkerStatus::Healthy,
                CircuitState::Open,
                &result,
                &HealthConfig::default(),
            ),
            WorkerStatus::Unreachable,
        );
    }
}
