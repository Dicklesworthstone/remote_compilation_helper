//! Per-`ActionClass` sandbox/execution policy registry (bead E001;
//! plan §15/§71; invariants I23/I24 at the policy level).
//!
//! Every action class gets ONE policy record: eligibility switches,
//! required isolation, network/secret policy, resource class,
//! provisional-output allowance, and the minimum publication evidence
//! tier. Two structural rules:
//!
//! - **Purpose is not a class.** Speculative, GitPrewarm, CiRequired,
//!   DeterminismAudit, CacheVerification, and AdministrativeRepair are
//!   `SubscriberKind`/attempt-purpose values — the registry is keyed by
//!   `ActionClass` alone and has no purpose field, so identical
//!   speculative and foreground compiles CANNOT be given different
//!   policies (or keys) through this table.
//! - The table is **total**: a test proves every class has exactly one
//!   record, so a new class cannot ship without a policy decision.
//!
//! Values encode the plan's defaults; per-fleet overrides layer on
//! later (D-series) without changing the schema.

use crate::authority_matrix::IsolationProfile;
use crate::descriptor::ActionClass;
use crate::serving::TrustEvidenceTier;

/// Network posture for a class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkPolicy {
    /// Default-deny (no network namespace access).
    DenyAll,
    /// Loopback only (some test harnesses).
    LoopbackOnly,
    /// Ambient network — forces local/volatile handling.
    AmbientVolatile,
}

/// Secret exposure policy for a class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretPolicy {
    /// No secrets presented at all.
    NonePresented,
    /// Output-affecting secrets only as F006 opaque digests.
    OpaqueDigestOnly,
}

/// Coarse resource class for scheduling budgets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum ResourceClass {
    Light,
    Standard,
    Heavy,
    Bulk,
}

/// The per-class policy record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionClassPolicy {
    /// The class this record governs (the ONLY key — purpose is not
    /// representable here).
    pub class: ActionClass,
    /// May results be cached locally?
    pub local_cache: bool,
    /// May the action execute remotely?
    pub remote_exec: bool,
    /// May deterministic failures be cached (I16 admission)?
    pub deterministic_failure_cache: bool,
    /// May speculation subscribe to this class?
    pub speculation: bool,
    /// May hedge attempts run?
    pub hedge: bool,
    /// Minimum isolation profile for shareable results.
    pub required_isolation: IsolationProfile,
    /// Network posture.
    pub network: NetworkPolicy,
    /// Secret exposure policy.
    pub secrets: SecretPolicy,
    /// May provisional outputs (.rmeta pipelining) be exposed?
    pub provisional_outputs: bool,
    /// Scheduling resource class.
    pub resource_class: ResourceClass,
    /// Minimum evidence tier for publication serving.
    pub min_publication_evidence: TrustEvidenceTier,
}

/// Shorthand for the common cacheable-compile shape.
const fn compile(class: ActionClass, resource_class: ResourceClass) -> ActionClassPolicy {
    ActionClassPolicy {
        class,
        local_cache: true,
        remote_exec: true,
        deterministic_failure_cache: true,
        speculation: true,
        hedge: true,
        required_isolation: IsolationProfile::StrictHermeticLinux,
        network: NetworkPolicy::DenyAll,
        secrets: SecretPolicy::NonePresented,
        provisional_outputs: false,
        resource_class,
        min_publication_evidence: TrustEvidenceTier::UnverifiedCandidate,
    }
}

/// The registry: one record per class (totality proven by test).
pub const CLASS_POLICY_REGISTRY: &[ActionClassPolicy] = &[
    ActionClassPolicy {
        // Whole-command bounded Cargo runs: heavyweight, no hedging
        // (double whole builds), no provisional exposure.
        hedge: false,
        ..compile(ActionClass::CargoWholeCommandBounded, ResourceClass::Bulk)
    },
    ActionClassPolicy {
        // The bread-and-butter dependency compile: everything on, and
        // .rmeta pipelining allowed.
        provisional_outputs: true,
        ..compile(ActionClass::RustcDependencyCompile, ResourceClass::Standard)
    },
    ActionClassPolicy {
        provisional_outputs: true,
        ..compile(ActionClass::RustcWorkspaceCompile, ResourceClass::Standard)
    },
    compile(ActionClass::RustdocCompile, ResourceClass::Standard),
    ActionClassPolicy {
        // Links are heavy and rarely worth hedging.
        hedge: false,
        ..compile(ActionClass::Link, ResourceClass::Heavy)
    },
    compile(ActionClass::BuildScriptCompile, ResourceClass::Standard),
    ActionClassPolicy {
        // Build-script RUN: cacheable only under strict isolation;
        // secrets may reach it as opaque digests (env-var driven
        // scripts); never speculated (arbitrary effects).
        speculation: false,
        secrets: SecretPolicy::OpaqueDigestOnly,
        ..compile(ActionClass::BuildScriptRun, ResourceClass::Standard)
    },
    compile(ActionClass::NativeCompileC, ResourceClass::Standard),
    compile(ActionClass::NativeCompileCxx, ResourceClass::Standard),
    compile(ActionClass::NativeArchive, ResourceClass::Light),
    compile(ActionClass::BindgenGeneration, ResourceClass::Standard),
    ActionClassPolicy {
        speculation: false,
        ..compile(ActionClass::CodeGeneratorRun, ResourceClass::Standard)
    },
    ActionClassPolicy {
        // Test cases may need loopback harnesses; failures cache as
        // deterministic ONLY under the I16 admission rules.
        network: NetworkPolicy::LoopbackOnly,
        ..compile(ActionClass::NextestTestCase, ResourceClass::Standard)
    },
    ActionClassPolicy {
        network: NetworkPolicy::LoopbackOnly,
        ..compile(ActionClass::TestBinaryBatch, ResourceClass::Heavy)
    },
    compile(ActionClass::DoctestCompile, ResourceClass::Standard),
    ActionClassPolicy {
        network: NetworkPolicy::LoopbackOnly,
        ..compile(ActionClass::DoctestRun, ResourceClass::Light)
    },
    compile(ActionClass::ClippyCompile, ResourceClass::Standard),
    compile(ActionClass::BenchmarkCompile, ResourceClass::Standard),
    ActionClassPolicy {
        // Benchmark RUNS are timing-sensitive: never cached or shared,
        // local volatile execution only.
        local_cache: false,
        remote_exec: false,
        deterministic_failure_cache: false,
        speculation: false,
        hedge: false,
        required_isolation: IsolationProfile::VolatileLocal,
        network: NetworkPolicy::AmbientVolatile,
        ..compile(ActionClass::BenchmarkRun, ResourceClass::Heavy)
    },
    ActionClassPolicy {
        hedge: false,
        speculation: false,
        ..compile(ActionClass::ToolchainProbe, ResourceClass::Light)
    },
    ActionClassPolicy {
        hedge: false,
        speculation: false,
        local_cache: false,
        ..compile(ActionClass::WorkerProbe, ResourceClass::Light)
    },
];

/// Look up the policy for a class (total; the registry test proves it).
#[must_use]
pub fn policy_for(class: ActionClass) -> &'static ActionClassPolicy {
    CLASS_POLICY_REGISTRY
        .iter()
        .find(|p| p.class == class)
        .expect("registry totality is test-enforced")
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_CLASSES: [ActionClass; 21] = [
        ActionClass::CargoWholeCommandBounded,
        ActionClass::RustcDependencyCompile,
        ActionClass::RustcWorkspaceCompile,
        ActionClass::RustdocCompile,
        ActionClass::Link,
        ActionClass::BuildScriptCompile,
        ActionClass::BuildScriptRun,
        ActionClass::NativeCompileC,
        ActionClass::NativeCompileCxx,
        ActionClass::NativeArchive,
        ActionClass::BindgenGeneration,
        ActionClass::CodeGeneratorRun,
        ActionClass::NextestTestCase,
        ActionClass::TestBinaryBatch,
        ActionClass::DoctestCompile,
        ActionClass::DoctestRun,
        ActionClass::ClippyCompile,
        ActionClass::BenchmarkCompile,
        ActionClass::BenchmarkRun,
        ActionClass::ToolchainProbe,
        ActionClass::WorkerProbe,
    ];

    #[test]
    fn registry_is_total_with_exactly_one_record_per_class() {
        for class in ALL_CLASSES {
            let count = CLASS_POLICY_REGISTRY
                .iter()
                .filter(|p| p.class == class)
                .count();
            assert_eq!(count, 1, "{class:?} must have exactly one policy");
        }
        assert_eq!(CLASS_POLICY_REGISTRY.len(), ALL_CLASSES.len());
    }

    #[test]
    fn purpose_is_not_representable_in_the_policy_key() {
        // The exhaustive destructure: no SubscriberKind/purpose field
        // exists — a speculative and a foreground compile of identical
        // semantics consult the SAME record (and, per the descriptor
        // tests, share one key). Adding a purpose field here is a
        // compile error until this test is consciously rewritten.
        let ActionClassPolicy {
            class: _,
            local_cache: _,
            remote_exec: _,
            deterministic_failure_cache: _,
            speculation: _,
            hedge: _,
            required_isolation: _,
            network: _,
            secrets: _,
            provisional_outputs: _,
            resource_class: _,
            min_publication_evidence: _,
        } = *policy_for(ActionClass::RustcDependencyCompile);
    }

    #[test]
    fn volatile_and_probe_classes_carry_their_restrictions() {
        let bench = policy_for(ActionClass::BenchmarkRun);
        assert!(!bench.local_cache && !bench.remote_exec);
        assert_eq!(bench.required_isolation, IsolationProfile::VolatileLocal);
        assert_eq!(bench.network, NetworkPolicy::AmbientVolatile);
        let bsr = policy_for(ActionClass::BuildScriptRun);
        assert!(!bsr.speculation, "arbitrary effects: never speculated");
        assert_eq!(bsr.secrets, SecretPolicy::OpaqueDigestOnly);
        assert!(bsr.local_cache, "cacheable under strict isolation");
    }

    #[test]
    fn provisional_outputs_only_where_pipelining_exists() {
        for policy in CLASS_POLICY_REGISTRY {
            if policy.provisional_outputs {
                assert!(
                    matches!(
                        policy.class,
                        ActionClass::RustcDependencyCompile | ActionClass::RustcWorkspaceCompile
                    ),
                    "{:?}: .rmeta pipelining is a rustc-compile concept",
                    policy.class
                );
            }
        }
    }

    #[test]
    fn shareable_classes_require_strict_isolation_and_default_deny() {
        for policy in CLASS_POLICY_REGISTRY {
            if policy.remote_exec {
                assert_eq!(
                    policy.required_isolation,
                    IsolationProfile::StrictHermeticLinux,
                    "{:?}: shareable results need the strict profile",
                    policy.class
                );
                assert_ne!(
                    policy.network,
                    NetworkPolicy::AmbientVolatile,
                    "{:?}: ambient network forces local volatile",
                    policy.class
                );
            }
        }
    }
}
