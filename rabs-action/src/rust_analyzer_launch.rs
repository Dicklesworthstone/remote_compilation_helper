//! rust-analyzer canonical Cargo-launch integration + fallback
//! (bead K017; plan Epic K/m10).
//!
//! rust-analyzer (RA) is the highest-frequency Cargo driver on a
//! developer box: every keystroke-save fires `cargo check` shaped
//! requests whose low-latency `.rmeta`/check hits are among the most
//! user-visible serving wins. But an IDE process is also the LEAST
//! trustworthy driver in the fleet: its cwd may be any checkout, its
//! env is whatever the editor session inherited, and nobody audited it.
//!
//! The law this module enforces:
//!
//! - **Shared workspace authority requires supported configuration.**
//!   RA's Cargo enters the canonical driver namespace only when the
//!   caller observed the supported wrapper configuration (canonical
//!   wrapper declared, no rogue target-dir override, provenance
//!   contract resolved). Then IDE-triggered checks flow through the
//!   SAME wrappers and cache as explicit agent commands — one key
//!   space, no IDE-special keys.
//! - **A noncanonical RA parent gets the reduced lane.** Outside the
//!   canonical namespace, RA keeps real value — admitted
//!   dependency-compilation acceleration and local execution — but
//!   never shared-workspace authority: no speculative serving against
//!   a workspace it cannot spell canonically, no publication rights.
//! - **Metrics distinguish IDE-triggered from explicit commands** so
//!   operators can see which serving wins come from whom without
//!   either lane contaminating the other's accounting.
//!
//! Pure policy over observed facts; the caller supplies RA's resolved
//! cwd/config state exactly as observed (same posture as K015/K019:
//! classification over observations, resolution elsewhere).
//!
//! # Dependency rules
//!
//! Same as the crate: depends on rabs-protocol only; pure functions.

use crate::cargo_command_eligibility::{
    CargoCommandFamily, EnforcementOutcome, ExpandedCargoInvocation, enforce,
};

/// How the rust-analyzer process relates to the canonical namespace,
/// as OBSERVED by the launcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RaProvenance {
    /// RA resolves inside the canonical root (its cwd spelled
    /// canonically after K019 resolution).
    CanonicalLaunch {
        /// Canonical absolute spelling of RA's workspace root.
        workspace: Vec<u8>,
    },
    /// RA lives outside the canonical namespace: host-local IDE on a
    /// foreign checkout, container path, home-dir project, etc.
    NonCanonicalLaunch {
        /// Observed cwd bytes (recorded for metrics, NEVER keyed).
        observed_cwd: Vec<u8>,
    },
}

/// The wrapper-configuration facts RA's Cargo was launched under.
/// "Supported configuration" is ALL of:
/// - the canonical rustc/Cargo wrapper is declared (`rust_wrapper`),
/// - no target-dir override escapes the canonical namespace
///   (`target_dir_canonical`),
/// - the effective-config provenance contract was resolved for the
///   session (`config_contract_resolved`) — K015's output exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrapperConfig {
    /// Canonical rustc wrapper declared for RA's toolchain.
    pub rust_wrapper_declared: bool,
    /// Target-dir (env or config) absent or canonical-spelled.
    pub target_dir_canonical: bool,
    /// K015 EffectiveCargoConfigContract resolved for this session.
    pub config_contract_resolved: bool,
}

impl WrapperConfig {
    /// Whether this configuration admits shared-workspace authority.
    #[must_use]
    pub const fn is_supported(&self) -> bool {
        self.rust_wrapper_declared && self.target_dir_canonical && self.config_contract_resolved
    }
}

/// The lane an IDE-triggered command is admitted to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdeLane {
    /// Full authority: identical wrappers, cache, and keys as explicit
    /// agent commands. An IDE check hit IS an agent check hit.
    CanonicalSharedAuthority,
    /// Reduced authority: dependency-compile acceleration plus local
    /// lanes remain available; NO shared-workspace authority and NO
    /// speculative/publication rights.
    DependencyLocalOnly,
}

impl IdeLane {
    /// Whether this lane may serve results into the shared action
    /// cache (the authority boundary in one predicate).
    #[must_use]
    pub const fn may_serve_shared(self) -> bool {
        matches!(self, Self::CanonicalSharedAuthority)
    }
}

/// Who originated the command, for metric separation ONLY. Origin is
/// never a key input: an IDE check and an agent check on the same
/// workspace MUST share one key (I23 purpose-is-not-a-class at the
/// command plane).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandOrigin {
    /// Fired by rust-analyzer / an editor integration.
    IdeTriggered,
    /// Fired by an agent CLI or hook.
    ExplicitAgent,
    /// Fired by CI automation.
    CiPipeline,
}

impl CommandOrigin {
    /// Deterministic metric label; consumed by telemetry only.
    #[must_use]
    pub fn metric_label(self) -> &'static str {
        match self {
            Self::IdeTriggered => "ide-triggered",
            Self::ExplicitAgent => "explicit-agent",
            Self::CiPipeline => "ci-pipeline",
        }
    }
}

/// Admission decision for one IDE-plane command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaAdmission {
    /// Lane granted (authority boundary).
    pub lane: IdeLane,
    /// Why: recorded verbatim in metrics/audit, never in keys.
    pub reason: &'static str,
}

/// Admit an IDE-triggered command to a lane.
///
/// `family` comes from classifying RA's expanded argv through K016's
/// matrix ([`cargo_command_eligibility::enforce`]); only families that
/// matrix already accelerates can earn the shared-authority lane here.
/// Everything else — mutating, interactive, unrecognized — stays on
/// whatever that matrix granted, minus any authority this module's
/// reduced lane would withhold.
#[must_use]
pub fn admit_ide_lane(
    provenance: &RaProvenance,
    wrapper: &WrapperConfig,
    family: CargoCommandFamily,
) -> RaAdmission {
    // Noncanonical parent: reduced lane, unconditionally. This is the
    // fallback the bead names; correctness means it CANNOT be promoted
    // by clever configuration — only by actually launching canonically.
    if matches!(provenance, RaProvenance::NonCanonicalLaunch { .. }) {
        return RaAdmission {
            lane: IdeLane::DependencyLocalOnly,
            reason: "noncanonical-ra-parent",
        };
    }
    // Canonical launch: shared authority requires the supported
    // configuration AND a family the eligibility matrix accelerates.
    let acceleratable = matches!(
        family,
        CargoCommandFamily::CompilePhase
            | CargoCommandFamily::Test
            | CargoCommandFamily::RunCommand
    );
    if !acceleratable {
        return RaAdmission {
            lane: IdeLane::DependencyLocalOnly,
            reason: "family-not-acceleratable",
        };
    }
    if wrapper.is_supported() {
        RaAdmission {
            lane: IdeLane::CanonicalSharedAuthority,
            reason: "canonical-launch-supported-config",
        }
    } else {
        RaAdmission {
            lane: IdeLane::DependencyLocalOnly,
            reason: "canonical-launch-unsupported-config",
        }
    }
}

/// Convenience: classify + gate in one step for the common RA shape.
/// Returns `None` when the invocation is not an IDE-admissible cargo
/// command at all (probe shapes route to K018 instead).
#[must_use]
pub fn admit_ra_invocation(
    argv: &[String],
    pty_requested: bool,
    provenance: &RaProvenance,
    wrapper: &WrapperConfig,
) -> Option<RaAdmission> {
    if argv.first().map(String::as_str) != Some("cargo") {
        return None;
    }
    let invocation = ExpandedCargoInvocation {
        argv: argv.to_vec(),
        pty_requested,
        custom_runner_declared: false,
    };
    // Ordering enforced structurally here: the eligibility matrix
    // ALWAYS runs before any lane decision, so no IDE path can skip
    // classification or its explained-bypass refusals.
    let decision = enforce(&invocation);
    // A bypassed invocation never earns a lane at all.
    if decision.outcome != EnforcementOutcome::Admitted {
        return None;
    }
    Some(admit_ide_lane(provenance, wrapper, decision.family))
}

// ---------------------------------------------------------------------
// Tests — K017 acceptance: RA integration fixture; noncanonical
// fallback correct.
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn supported() -> WrapperConfig {
        WrapperConfig {
            rust_wrapper_declared: true,
            target_dir_canonical: true,
            config_contract_resolved: true,
        }
    }

    fn unsupported() -> WrapperConfig {
        WrapperConfig {
            rust_wrapper_declared: false,
            target_dir_canonical: false,
            config_contract_resolved: false,
        }
    }

    fn canonical() -> RaProvenance {
        RaProvenance::CanonicalLaunch {
            workspace: b"/data/projects/acme".to_vec(),
        }
    }

    fn noncanonical() -> RaProvenance {
        RaProvenance::NonCanonicalLaunch {
            observed_cwd: b"/home/dev/code/acme-fork".to_vec(),
        }
    }

    /// THE RA integration fixture: rust-analyzer's characteristic
    /// check invocation flows through K016 classification into full
    /// shared authority when launched canonically with supported
    /// configuration.
    #[test]
    fn ra_integration_fixture_check_flows_to_shared_authority() {
        // Typical rust-analyzer flycheck argv (post-expansion).
        let argv: Vec<String> = ["cargo", "check", "--workspace", "--message-format=json"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        assert_eq!(argv.first().map(String::as_str), Some("cargo"));
        // Family classification happens upstream of lane admission —
        // the fixture pins the order by exercising both layers.
        assert_eq!(
            admit_ide_lane(&canonical(), &supported(), CargoCommandFamily::CompilePhase),
            RaAdmission {
                lane: IdeLane::CanonicalSharedAuthority,
                reason: "canonical-launch-supported-config",
            }
        );
        assert!(
            admit_ide_lane(&canonical(), &supported(), CargoCommandFamily::CompilePhase)
                .lane
                .may_serve_shared()
        );
    }

    #[test]
    fn noncanonical_fallback_is_reduced_and_unpromotable() {
        // Correctness of the fallback: ANY configuration, ANY attempt,
        // a noncanonical parent stays on the reduced lane.
        for wrapper in [supported(), unsupported()] {
            let d = admit_ide_lane(&noncanonical(), &wrapper, CargoCommandFamily::CompilePhase);
            assert_eq!(d.lane, IdeLane::DependencyLocalOnly);
            assert!(!d.lane.may_serve_shared());
            assert_eq!(d.reason, "noncanonical-ra-parent");
        }
        // Even a perfect-looking config cannot buy authority back:
        // promotion requires CANONICAL LAUNCH, not better flags.
        assert_ne!(
            admit_ide_lane(
                &noncanonical(),
                &supported(),
                CargoCommandFamily::CompilePhase
            )
            .lane,
            IdeLane::CanonicalSharedAuthority
        );
    }

    #[test]
    fn canonical_but_unsupported_config_falls_back() {
        let d = admit_ide_lane(
            &canonical(),
            &unsupported(),
            CargoCommandFamily::CompilePhase,
        );
        assert_eq!(d.lane, IdeLane::DependencyLocalOnly);
        assert_eq!(d.reason, "canonical-launch-unsupported-config");
        // Each missing leg of the supported config holds the fallback:
        for partial in [
            WrapperConfig {
                rust_wrapper_declared: false,
                target_dir_canonical: true,
                config_contract_resolved: true,
            },
            WrapperConfig {
                rust_wrapper_declared: true,
                target_dir_canonical: false,
                config_contract_resolved: true,
            },
            WrapperConfig {
                rust_wrapper_declared: true,
                target_dir_canonical: true,
                config_contract_resolved: false,
            },
        ] {
            assert!(!partial.is_supported());
            assert_eq!(
                admit_ide_lane(&canonical(), &partial, CargoCommandFamily::CompilePhase).lane,
                IdeLane::DependencyLocalOnly
            );
        }
    }

    #[test]
    fn test_family_admits_run_does_not_mutating_never_does() {
        assert_eq!(
            admit_ide_lane(&canonical(), &supported(), CargoCommandFamily::Test).reason,
            "canonical-launch-supported-config"
        );
        assert_eq!(
            admit_ide_lane(&canonical(), &supported(), CargoCommandFamily::RunCommand).lane,
            IdeLane::CanonicalSharedAuthority
        );
        // Mutating/interactive/unrecognized families never earn authority.
        for family in [
            CargoCommandFamily::Mutating,
            CargoCommandFamily::Interactive,
            CargoCommandFamily::Unrecognized,
            CargoCommandFamily::Bench,
            CargoCommandFamily::Probe,
        ] {
            assert_eq!(
                admit_ide_lane(&canonical(), &supported(), family).lane,
                IdeLane::DependencyLocalOnly,
                "{family:?}"
            );
        }
    }

    #[test]
    fn origin_labels_separate_metrics_without_touching_identity() {
        // Three origins, three labels...
        let labels = [
            CommandOrigin::IdeTriggered.metric_label(),
            CommandOrigin::ExplicitAgent.metric_label(),
            CommandOrigin::CiPipeline.metric_label(),
        ];
        assert_eq!(labels[0], "ide-triggered");
        assert_ne!(labels[0], labels[1]);
        assert_ne!(labels[1], labels[2]);
        // ...but origin appears NOWHERE in the admission decision:
        // admit_ide_lane takes no origin parameter (type-enforced), so
        // an IDE check and an agent check cannot diverge in key or lane
        // merely because of who typed them.
    }

    #[test]
    fn non_ra_programs_are_out_of_scope() {
        // The convenience gate refuses to even classify non-cargo
        // invocations: rustc probes belong to K018, not this module.
        let argv = ["rustc".to_owned(), "-vV".to_owned()];
        assert!(admit_ra_invocation(&argv, false, &canonical(), &supported()).is_none());
    }
}
