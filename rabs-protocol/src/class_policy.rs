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
use crate::result_identity::TypedDigest;
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

/// Domain separator for signing-identity digests (bead S016; risk R74).
pub const SIGNING_IDENTITY_DIGEST_DOMAIN: &str = "rabs.signing-identity.sha256.v1";
/// Domain separator for captured reproducible signing/notarization/TSA responses (bead S016; risk R74).
pub const CAPTURED_RELEASE_RESPONSE_DOMAIN: &str = "rabs.release-response.sha256.v1";

/// Separate credentialed release/signing step kinds (bead S016; risk R74).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseCredentialStepKind {
    /// Cryptographic code signing with a credentialed signing identity.
    CodeSigning,
    /// Apple notarization service submission/stapling.
    AppleNotarization,
    /// Registry/package publication (e.g. crates.io, OCI, apt/rpm repo).
    PackagePublication,
    /// External RFC 3161 / timestamp-authority signing call.
    TimestampAuthorityCall,
}

/// Signing posture of an action step (bead S016; risk R74).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningActionPosture {
    /// Ordinary compilation/link intermediate with no signing credentials.
    UnsignedIntermediate {
        /// Underlying compilation/link action class.
        class: ActionClass,
        /// Whether any private signing key material was attached to the request.
        carries_private_signing_key: bool,
    },
    /// Unsigned/ad-hoc intermediate (such as Darwin `codesign -s -`), cacheable
    /// in the shared cache when policy permits and no private key is present.
    AdHocIntermediate {
        /// Underlying compilation/link action class.
        class: ActionClass,
        /// Canonical ad-hoc identifier entering the action key.
        ad_hoc_identifier: String,
        /// Whether any private signing key material was attached to the request.
        carries_private_signing_key: bool,
    },
    /// Credentialed signing, notarization, publication, or timestamp-authority action.
    CredentialedReleaseStep {
        /// Specific credentialed step kind.
        kind: ReleaseCredentialStepKind,
        /// Digest of the exact signing/release credential identity.
        signing_identity_digest: TypedDigest,
        /// Optional digest of a captured deterministic response/ticket/timestamp token.
        captured_response_digest: Option<TypedDigest>,
        /// Whether the signature/output is deterministic given the identity + captured response.
        reproducible_signature: bool,
        /// Whether raw private signing key material is injected into the worker environment.
        injects_raw_private_key_into_worker: bool,
    },
}

/// Worker role with respect to signing/release credentials (bead S016; risk R74).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerCredentialRole {
    /// Ordinary compiler/linker worker in the shared build fleet.
    OrdinaryCompilerWorker,
    /// Dedicated isolated signing/release worker authorized for specific signing identities.
    DedicatedSigningWorker {
        /// Signing identity digests this isolated release worker may exercise.
        authorized_signing_identities: Vec<TypedDigest>,
    },
}

/// Cache namespace scope for an action's outputs (bead S016; risk R74).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheNamespaceScope {
    /// Shared compilation/link cache namespace across the fleet.
    SharedCompilationCache,
    /// Namespace scoped strictly to one exact signing identity and captured response.
    SigningIdentityScopedCache {
        /// Exact signing identity scoping the namespace.
        signing_identity_digest: TypedDigest,
    },
    /// Noncacheable side-effecting release step (never enters any result cache).
    NonCacheableReleaseStep,
}

/// Admitted execution and caching disposition under S016 signing separation (risk R74).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningActionDecision {
    /// Unsigned or policy-admitted ad-hoc intermediate cached in the shared compilation namespace.
    SharedIntermediateCacheable {
        /// Underlying compilation/link class.
        class: ActionClass,
        /// Optional ad-hoc identifier mixed into the action key.
        keyed_ad_hoc_identifier: Option<String>,
    },
    /// Reproducible credentialed signature cached ONLY in the signing-identity-scoped namespace,
    /// keyed by exact signing identity + captured response digest.
    IdentityScopedCredentialCacheable {
        /// Credentialed step kind.
        kind: ReleaseCredentialStepKind,
        /// Exact signing identity digest.
        signing_identity_digest: TypedDigest,
        /// Captured response digest bound into the key.
        captured_response_digest: TypedDigest,
    },
    /// Noncacheable side-effecting release step (e.g., package publication, live notarization/TSA
    /// without reproducible captured response).
    NonCacheableSideEffectingReleaseStep {
        /// Credentialed step kind.
        kind: ReleaseCredentialStepKind,
        /// Reason the step is noncacheable.
        reason: &'static str,
    },
}

/// Typed refusal when signing/notarization/publication separation is violated (bead S016; risk R74).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningSeparationRefusal {
    /// Private signing key material was presented to an ordinary compiler worker or intermediate compile/link.
    PrivateSigningKeyInOrdinaryCompileOrWorker,
    /// A credentialed signing/notarization/publication/TSA step was routed to an ordinary compiler worker.
    CredentialedStepOnOrdinaryWorker,
    /// A credentialed release step attempted to read/write the shared compilation cache namespace.
    CredentialedStepInSharedCacheNamespace,
    /// Ad-hoc intermediate caching was requested when disabled by project policy, or with an empty identifier.
    AdHocIntermediateNotPermitted,
    /// Malformed signing-identity or captured-response digest domain.
    MalformedSigningOrResponseDigestDomain,
    /// Dedicated signing worker is not authorized for the requested signing identity.
    SigningIdentityNotAuthorizedOnWorker,
    /// Scoped cache namespace identity does not match the step's signing identity.
    CacheNamespaceIdentityMismatch,
}

/// Enforce S016 separation of signing/notarization/publication credentials and effects
/// from ordinary compilation/link caching (risk R74).
///
/// # Errors
/// Returns [`SigningSeparationRefusal`] if private keys enter ordinary workers or shared
/// compilation caches, or if credentialed steps violate identity/namespace scoping.
pub fn evaluate_signing_action_separation(
    posture: &SigningActionPosture,
    worker_role: &WorkerCredentialRole,
    requested_namespace: &CacheNamespaceScope,
    allow_ad_hoc_intermediate_caching: bool,
) -> Result<SigningActionDecision, SigningSeparationRefusal> {
    match posture {
        SigningActionPosture::UnsignedIntermediate {
            class,
            carries_private_signing_key,
        } => {
            if *carries_private_signing_key {
                return Err(SigningSeparationRefusal::PrivateSigningKeyInOrdinaryCompileOrWorker);
            }
            if !matches!(
                requested_namespace,
                CacheNamespaceScope::SharedCompilationCache
            ) {
                return Err(SigningSeparationRefusal::CacheNamespaceIdentityMismatch);
            }
            Ok(SigningActionDecision::SharedIntermediateCacheable {
                class: *class,
                keyed_ad_hoc_identifier: None,
            })
        }
        SigningActionPosture::AdHocIntermediate {
            class,
            ad_hoc_identifier,
            carries_private_signing_key,
        } => {
            if *carries_private_signing_key {
                return Err(SigningSeparationRefusal::PrivateSigningKeyInOrdinaryCompileOrWorker);
            }
            if !allow_ad_hoc_intermediate_caching || ad_hoc_identifier.trim().is_empty() {
                return Err(SigningSeparationRefusal::AdHocIntermediateNotPermitted);
            }
            if !matches!(
                requested_namespace,
                CacheNamespaceScope::SharedCompilationCache
            ) {
                return Err(SigningSeparationRefusal::CacheNamespaceIdentityMismatch);
            }
            Ok(SigningActionDecision::SharedIntermediateCacheable {
                class: *class,
                keyed_ad_hoc_identifier: Some(ad_hoc_identifier.clone()),
            })
        }
        SigningActionPosture::CredentialedReleaseStep {
            kind,
            signing_identity_digest,
            captured_response_digest,
            reproducible_signature,
            injects_raw_private_key_into_worker,
        } => {
            if *injects_raw_private_key_into_worker {
                return Err(SigningSeparationRefusal::PrivateSigningKeyInOrdinaryCompileOrWorker);
            }
            if signing_identity_digest.domain != SIGNING_IDENTITY_DIGEST_DOMAIN {
                return Err(SigningSeparationRefusal::MalformedSigningOrResponseDigestDomain);
            }
            if let Some(resp) = captured_response_digest
                && resp.domain != CAPTURED_RELEASE_RESPONSE_DOMAIN
            {
                return Err(SigningSeparationRefusal::MalformedSigningOrResponseDigestDomain);
            }
            let WorkerCredentialRole::DedicatedSigningWorker {
                authorized_signing_identities,
            } = worker_role
            else {
                return Err(SigningSeparationRefusal::CredentialedStepOnOrdinaryWorker);
            };
            if !authorized_signing_identities.contains(signing_identity_digest) {
                return Err(SigningSeparationRefusal::SigningIdentityNotAuthorizedOnWorker);
            }
            if matches!(
                requested_namespace,
                CacheNamespaceScope::SharedCompilationCache
            ) {
                return Err(SigningSeparationRefusal::CredentialedStepInSharedCacheNamespace);
            }

            // Package publication is always an external side-effecting release step.
            if matches!(kind, ReleaseCredentialStepKind::PackagePublication) {
                return Ok(
                    SigningActionDecision::NonCacheableSideEffectingReleaseStep {
                        kind: *kind,
                        reason: "package-publication-is-external-side-effect",
                    },
                );
            }

            // Credentialed signatures/notarization/TSA calls are cacheable ONLY when reproducible
            // AND paired with a captured response digest inside an identity-scoped namespace.
            if *reproducible_signature && let Some(captured) = captured_response_digest {
                match requested_namespace {
                    CacheNamespaceScope::SigningIdentityScopedCache {
                        signing_identity_digest: ns_identity,
                    } => {
                        if ns_identity != signing_identity_digest {
                            return Err(SigningSeparationRefusal::CacheNamespaceIdentityMismatch);
                        }
                        Ok(SigningActionDecision::IdentityScopedCredentialCacheable {
                            kind: *kind,
                            signing_identity_digest: signing_identity_digest.clone(),
                            captured_response_digest: captured.clone(),
                        })
                    }
                    CacheNamespaceScope::NonCacheableReleaseStep => Ok(
                        SigningActionDecision::NonCacheableSideEffectingReleaseStep {
                            kind: *kind,
                            reason: "operator-requested-noncacheable-release-step",
                        },
                    ),
                    CacheNamespaceScope::SharedCompilationCache => {
                        Err(SigningSeparationRefusal::CredentialedStepInSharedCacheNamespace)
                    }
                }
            } else {
                Ok(
                    SigningActionDecision::NonCacheableSideEffectingReleaseStep {
                        kind: *kind,
                        reason: "nonreproducible-or-uncaptured-external-authority-response",
                    },
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result_identity::DigestAlgorithm;

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

    #[test]
    fn s016_signing_notarization_publication_separation_fixtures() {
        let signing_id = TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: SIGNING_IDENTITY_DIGEST_DOMAIN,
            bytes: [0x11; 32],
        };
        let other_signing_id = TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: SIGNING_IDENTITY_DIGEST_DOMAIN,
            bytes: [0x22; 32],
        };
        let captured_response = TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: CAPTURED_RELEASE_RESPONSE_DOMAIN,
            bytes: [0x33; 32],
        };
        let dedicated_worker = WorkerCredentialRole::DedicatedSigningWorker {
            authorized_signing_identities: vec![signing_id.clone()],
        };

        // 1. Unsigned intermediate link action caches normally in SharedCompilationCache.
        let unsigned_link = SigningActionPosture::UnsignedIntermediate {
            class: ActionClass::Link,
            carries_private_signing_key: false,
        };
        assert_eq!(
            evaluate_signing_action_separation(
                &unsigned_link,
                &WorkerCredentialRole::OrdinaryCompilerWorker,
                &CacheNamespaceScope::SharedCompilationCache,
                true,
            ),
            Ok(SigningActionDecision::SharedIntermediateCacheable {
                class: ActionClass::Link,
                keyed_ad_hoc_identifier: None,
            })
        );

        // 2. Ad-hoc signed intermediate caches when policy allows, and refuses when disabled.
        let ad_hoc_link = SigningActionPosture::AdHocIntermediate {
            class: ActionClass::Link,
            ad_hoc_identifier: "com.example.rch.dev-adhoc".into(),
            carries_private_signing_key: false,
        };
        assert_eq!(
            evaluate_signing_action_separation(
                &ad_hoc_link,
                &WorkerCredentialRole::OrdinaryCompilerWorker,
                &CacheNamespaceScope::SharedCompilationCache,
                true,
            ),
            Ok(SigningActionDecision::SharedIntermediateCacheable {
                class: ActionClass::Link,
                keyed_ad_hoc_identifier: Some("com.example.rch.dev-adhoc".into()),
            })
        );
        assert_eq!(
            evaluate_signing_action_separation(
                &ad_hoc_link,
                &WorkerCredentialRole::OrdinaryCompilerWorker,
                &CacheNamespaceScope::SharedCompilationCache,
                false,
            ),
            Err(SigningSeparationRefusal::AdHocIntermediateNotPermitted)
        );

        // 3. Private signing keys NEVER enter ordinary compiler workers or ordinary compile/link steps.
        let poisoned_link = SigningActionPosture::UnsignedIntermediate {
            class: ActionClass::Link,
            carries_private_signing_key: true,
        };
        assert_eq!(
            evaluate_signing_action_separation(
                &poisoned_link,
                &WorkerCredentialRole::OrdinaryCompilerWorker,
                &CacheNamespaceScope::SharedCompilationCache,
                true,
            ),
            Err(SigningSeparationRefusal::PrivateSigningKeyInOrdinaryCompileOrWorker)
        );

        // 4. Reproducible credentialed code signing is refused on ordinary compiler workers
        // and refused in SharedCompilationCache, but admitted on a dedicated signing worker
        // in SigningIdentityScopedCache keyed to exact signing identity + captured response.
        let code_signing = SigningActionPosture::CredentialedReleaseStep {
            kind: ReleaseCredentialStepKind::CodeSigning,
            signing_identity_digest: signing_id.clone(),
            captured_response_digest: Some(captured_response.clone()),
            reproducible_signature: true,
            injects_raw_private_key_into_worker: false,
        };
        assert_eq!(
            evaluate_signing_action_separation(
                &code_signing,
                &WorkerCredentialRole::OrdinaryCompilerWorker,
                &CacheNamespaceScope::SigningIdentityScopedCache {
                    signing_identity_digest: signing_id.clone(),
                },
                true,
            ),
            Err(SigningSeparationRefusal::CredentialedStepOnOrdinaryWorker)
        );
        assert_eq!(
            evaluate_signing_action_separation(
                &code_signing,
                &dedicated_worker,
                &CacheNamespaceScope::SharedCompilationCache,
                true,
            ),
            Err(SigningSeparationRefusal::CredentialedStepInSharedCacheNamespace)
        );
        assert_eq!(
            evaluate_signing_action_separation(
                &code_signing,
                &dedicated_worker,
                &CacheNamespaceScope::SigningIdentityScopedCache {
                    signing_identity_digest: other_signing_id,
                },
                true,
            ),
            Err(SigningSeparationRefusal::CacheNamespaceIdentityMismatch)
        );
        assert_eq!(
            evaluate_signing_action_separation(
                &code_signing,
                &dedicated_worker,
                &CacheNamespaceScope::SigningIdentityScopedCache {
                    signing_identity_digest: signing_id.clone(),
                },
                true,
            ),
            Ok(SigningActionDecision::IdentityScopedCredentialCacheable {
                kind: ReleaseCredentialStepKind::CodeSigning,
                signing_identity_digest: signing_id.clone(),
                captured_response_digest: captured_response.clone(),
            })
        );

        // 5. Apple notarization without captured ticket, TSA call without captured response,
        // and package publication classify as NonCacheableSideEffectingReleaseStep.
        for (kind, captured, reproducible, expected_reason) in [
            (
                ReleaseCredentialStepKind::AppleNotarization,
                None,
                false,
                "nonreproducible-or-uncaptured-external-authority-response",
            ),
            (
                ReleaseCredentialStepKind::TimestampAuthorityCall,
                None,
                false,
                "nonreproducible-or-uncaptured-external-authority-response",
            ),
            (
                ReleaseCredentialStepKind::PackagePublication,
                Some(captured_response),
                true,
                "package-publication-is-external-side-effect",
            ),
        ] {
            let step = SigningActionPosture::CredentialedReleaseStep {
                kind,
                signing_identity_digest: signing_id.clone(),
                captured_response_digest: captured,
                reproducible_signature: reproducible,
                injects_raw_private_key_into_worker: false,
            };
            assert_eq!(
                evaluate_signing_action_separation(
                    &step,
                    &dedicated_worker,
                    &CacheNamespaceScope::NonCacheableReleaseStep,
                    true,
                ),
                Ok(
                    SigningActionDecision::NonCacheableSideEffectingReleaseStep {
                        kind,
                        reason: expected_reason,
                    }
                )
            );
        }
    }

    #[test]
    fn l010_cmake_and_meson_launcher_integration_admits_proven_configs_and_bypasses_unsafe_configs()
    {
        let safe_cmake = NativeLauncherConfig {
            system: NativeBuildSystemKind::CMake,
            compiler_class: ActionClass::NativeCompileC,
            compile_commands_canonicalized: true,
            depfile_emission_verified: true,
            uses_precompiled_headers_or_cxx20_modules: false,
            uses_unity_or_jumbo_build: false,
            mutates_source_tree_in_place: false,
        };
        let decision = evaluate_native_launcher_integration(&safe_cmake);
        assert_eq!(
            decision,
            NativeLauncherDisposition::AdmittedFineGrainedLauncher {
                system: NativeBuildSystemKind::CMake,
                class: ActionClass::NativeCompileC,
                launcher_env_var: "CMAKE_C_COMPILER_LAUNCHER",
            }
        );

        let safe_meson_cxx = NativeLauncherConfig {
            system: NativeBuildSystemKind::Meson,
            compiler_class: ActionClass::NativeCompileCxx,
            compile_commands_canonicalized: true,
            depfile_emission_verified: true,
            uses_precompiled_headers_or_cxx20_modules: false,
            uses_unity_or_jumbo_build: false,
            mutates_source_tree_in_place: false,
        };
        assert_eq!(
            evaluate_native_launcher_integration(&safe_meson_cxx),
            NativeLauncherDisposition::AdmittedFineGrainedLauncher {
                system: NativeBuildSystemKind::Meson,
                class: ActionClass::NativeCompileCxx,
                launcher_env_var: "RABS_MESON_CXX_LAUNCHER",
            }
        );

        // Unsafe configs must bypass fine-grained launcher caching and stay inside the parent action:
        let mut pch_config = safe_cmake.clone();
        pch_config.uses_precompiled_headers_or_cxx20_modules = true;
        assert_eq!(
            evaluate_native_launcher_integration(&pch_config),
            NativeLauncherDisposition::BypassToParentActionUncached {
                system: NativeBuildSystemKind::CMake,
                reason: NativeLauncherBypassReason::PrecompiledHeadersOrCxxModules,
            }
        );

        let mut unity_config = safe_meson_cxx.clone();
        unity_config.uses_unity_or_jumbo_build = true;
        assert_eq!(
            evaluate_native_launcher_integration(&unity_config),
            NativeLauncherDisposition::BypassToParentActionUncached {
                system: NativeBuildSystemKind::Meson,
                reason: NativeLauncherBypassReason::UnityOrJumboBuildEnabled,
            }
        );

        let mut mutating_config = safe_cmake.clone();
        mutating_config.mutates_source_tree_in_place = true;
        assert_eq!(
            evaluate_native_launcher_integration(&mutating_config),
            NativeLauncherDisposition::BypassToParentActionUncached {
                system: NativeBuildSystemKind::CMake,
                reason: NativeLauncherBypassReason::InPlaceSourceTreeMutation,
            }
        );

        let mut uncanonical_config = safe_cmake;
        uncanonical_config.compile_commands_canonicalized = false;
        assert_eq!(
            evaluate_native_launcher_integration(&uncanonical_config),
            NativeLauncherDisposition::BypassToParentActionUncached {
                system: NativeBuildSystemKind::CMake,
                reason: NativeLauncherBypassReason::MissingCanonicalIncludeOrDepfileProof,
            }
        );
    }
}

/// Native build system driving subcompiles inside a build script or native target (bead L010).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeBuildSystemKind {
    /// CMake (`CMAKE_C_COMPILER_LAUNCHER` / `CMAKE_CXX_COMPILER_LAUNCHER`).
    CMake,
    /// Meson (`[binaries]` compiler wrapper / launcher).
    Meson,
}

/// Why a CMake/Meson native build configuration bypasses fine-grained launcher caching
/// and remains uncached within the parent action (bead L010).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeLauncherBypassReason {
    /// Action class is not a C/C++ translation-unit compile (`NativeCompileC` / `NativeCompileCxx`).
    UnsupportedActionClass,
    /// Include paths, `-ffile-prefix-map`, or `-MD -MF` depfile emission are not proven canonical.
    MissingCanonicalIncludeOrDepfileProof,
    /// Precompiled headers (`.pch`/`.gch`) or C++20 modules (`.pcm`/BMI) carry cross-TU state.
    PrecompiledHeadersOrCxxModules,
    /// CMake `CMAKE_UNITY_BUILD` or Meson `unity=on` dynamically amalgamates sources.
    UnityOrJumboBuildEnabled,
    /// Custom target/command mutates the source tree in place rather than writing to the build dir.
    InPlaceSourceTreeMutation,
}

/// Configuration and compatibility proof inputs for CMake/Meson launcher interception (bead L010).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeLauncherConfig {
    /// Build system (`CMake` or `Meson`).
    pub system: NativeBuildSystemKind,
    /// Target compilation class (`NativeCompileC` or `NativeCompileCxx`).
    pub compiler_class: ActionClass,
    /// Whether `compile_commands.json` / flags are proven free of non-canonical host paths.
    pub compile_commands_canonicalized: bool,
    /// Whether deterministic `-MD -MF` depfile emission is verified.
    pub depfile_emission_verified: bool,
    /// Whether PCH or C++20 module state is active.
    pub uses_precompiled_headers_or_cxx20_modules: bool,
    /// Whether Unity/Jumbo source amalgamation is active.
    pub uses_unity_or_jumbo_build: bool,
    /// Whether the build mutates the source tree in place.
    pub mutates_source_tree_in_place: bool,
}

/// Decision for CMake/Meson compiler launcher integration (bead L010).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeLauncherDisposition {
    /// Compatibility proof holds: enable fine-grained `rabs-wrap` compiler launcher interception.
    AdmittedFineGrainedLauncher {
        /// Build system.
        system: NativeBuildSystemKind,
        /// Admitted compilation class.
        class: ActionClass,
        /// Launcher variable injected into the build system environment.
        launcher_env_var: &'static str,
    },
    /// Unsafe configuration: bypass fine-grained launcher caching and keep native compilation
    /// uncached inside the parent `BuildScriptRun` / whole-command action.
    BypassToParentActionUncached {
        /// Build system.
        system: NativeBuildSystemKind,
        /// Exact bypass reason.
        reason: NativeLauncherBypassReason,
    },
}

/// Evaluate whether a CMake or Meson native build may use fine-grained `rabs-wrap`
/// compiler launcher interception, or must bypass to uncached execution within the
/// parent action (bead L010).
#[must_use]
pub const fn evaluate_native_launcher_integration(
    config: &NativeLauncherConfig,
) -> NativeLauncherDisposition {
    let launcher_env_var = match (config.system, config.compiler_class) {
        (NativeBuildSystemKind::CMake, ActionClass::NativeCompileC) => "CMAKE_C_COMPILER_LAUNCHER",
        (NativeBuildSystemKind::CMake, ActionClass::NativeCompileCxx) => {
            "CMAKE_CXX_COMPILER_LAUNCHER"
        }
        (NativeBuildSystemKind::Meson, ActionClass::NativeCompileC) => "RABS_MESON_CC_LAUNCHER",
        (NativeBuildSystemKind::Meson, ActionClass::NativeCompileCxx) => "RABS_MESON_CXX_LAUNCHER",
        _ => {
            return NativeLauncherDisposition::BypassToParentActionUncached {
                system: config.system,
                reason: NativeLauncherBypassReason::UnsupportedActionClass,
            };
        }
    };

    if config.uses_precompiled_headers_or_cxx20_modules {
        return NativeLauncherDisposition::BypassToParentActionUncached {
            system: config.system,
            reason: NativeLauncherBypassReason::PrecompiledHeadersOrCxxModules,
        };
    }
    if config.uses_unity_or_jumbo_build {
        return NativeLauncherDisposition::BypassToParentActionUncached {
            system: config.system,
            reason: NativeLauncherBypassReason::UnityOrJumboBuildEnabled,
        };
    }
    if config.mutates_source_tree_in_place {
        return NativeLauncherDisposition::BypassToParentActionUncached {
            system: config.system,
            reason: NativeLauncherBypassReason::InPlaceSourceTreeMutation,
        };
    }
    if !config.compile_commands_canonicalized || !config.depfile_emission_verified {
        return NativeLauncherDisposition::BypassToParentActionUncached {
            system: config.system,
            reason: NativeLauncherBypassReason::MissingCanonicalIncludeOrDepfileProof,
        };
    }

    NativeLauncherDisposition::AdmittedFineGrainedLauncher {
        system: config.system,
        class: config.compiler_class,
        launcher_env_var,
    }
}
