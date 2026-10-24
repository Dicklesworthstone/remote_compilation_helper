//! Source-registry storage evidence and its scheduling consequence (bd-5ojmb).
//!
//! A responsive SSH session or telemetry command does not prove that this user
//! can write ownership records. Keep storage refusals out of normal placement
//! until a real probe succeeds, without changing admin intent or claim state.

use super::{HealthCheckResult, HealthConfig, HealthProbeError, ProbeStage, derive_worker_status};
use rch_common::{CircuitState, CommandResult, WorkerStatus};

// The wire/storage protocol path also used by the hook and worker GC. A test
// checks all three literals together; do not move a probe to another filesystem.
const REGISTRY: &str = "/tmp/rch-source-authority-locks/claims-v1";
const REFUSAL: &str = "RCH_SOURCE_REGISTRY_UNWRITABLE";

pub(super) fn command() -> String {
    format!(
        "{}\nrch_source_registry_health '{}'",
        include_str!("../source_registry_health.sh"),
        REGISTRY,
    )
}

/// A confirmed storage failure is an immediate exclusion, not a slow response
/// or a network blip. Once excluded, an inconclusive probe cannot promote the
/// worker to Degraded (which accepts jobs), even if telemetry reset its circuit.
/// A successful storage probe resumes the ordinary circuit-governed policy.
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
    if !result.healthy && (storage_refused || previous == WorkerStatus::Unreachable) {
        WorkerStatus::Unreachable
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

pub(super) fn classify_output(result: &CommandResult) -> Result<(), HealthProbeError> {
    let storage_refused = result.stderr.lines().any(|line| {
        line.strip_prefix(REFUSAL)
            .is_some_and(|suffix| suffix.starts_with(' '))
    });
    if result.success() && result.stdout.trim() == "health_check" && !storage_refused {
        return Ok(());
    }
    let reason = if storage_refused {
        REFUSAL
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
    fn command_uses_the_ownership_registry_and_real_helper() {
        let invocation = format!("rch_source_registry_health '{REGISTRY}'");
        assert!(command().contains(invocation.as_str()));
        // These are protocol locations, not caller-selected scratch roots.
        let hook = include_str!("../../../rch/src/hook/ssh.rs");
        let gc = include_str!("../../../rch-common/src/stale_target_reap.rs");
        let hook_path = format!("const REMOTE_SOURCE_CLAIM_REGISTRY: &str = \"{REGISTRY}\";");
        let gc_path = format!("const SOURCE_CLAIM_REGISTRY: &str = \"{REGISTRY}\";");
        assert!(hook.contains(hook_path.as_str()));
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
}
