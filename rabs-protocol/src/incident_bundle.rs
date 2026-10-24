//! Incident classes, evidence bundles, and runbook links (bead R008;
//! plan §105; runbook twin: `docs/rabs-incident-runbooks.md`, pinned
//! by test).
//!
//! Thirteen incident classes, each with six facets — detection
//! signal, automatic containment, operator runbook anchor, evidence
//! item list, recovery path, regression-test requirement. Bundle
//! generation is REDACTION-SAFE (ids, digests, and stable strings
//! only) and every bundle links its runbook section; the runbook doc
//! is compiled in so prose and registry cannot drift.

/// The thirteen incident classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum IncidentClass {
    IncorrectResultDivergence,
    ObjectCorruption,
    PublicationFenceViolation,
    OrphanProcessOrResource,
    ProtocolCompatibilityFailure,
    WorkerIdentityMismatch,
    SecretExposure,
    StorageExhaustion,
    SchedulerPressureCollapse,
    CancellationHang,
    ReconciliationConflict,
    KeyInstabilityRegression,
    HitRateFragmentation,
}

/// Every class, in registry order (count pinned by test).
pub const ALL_INCIDENT_CLASSES: [IncidentClass; 13] = [
    IncidentClass::IncorrectResultDivergence,
    IncidentClass::ObjectCorruption,
    IncidentClass::PublicationFenceViolation,
    IncidentClass::OrphanProcessOrResource,
    IncidentClass::ProtocolCompatibilityFailure,
    IncidentClass::WorkerIdentityMismatch,
    IncidentClass::SecretExposure,
    IncidentClass::StorageExhaustion,
    IncidentClass::SchedulerPressureCollapse,
    IncidentClass::CancellationHang,
    IncidentClass::ReconciliationConflict,
    IncidentClass::KeyInstabilityRegression,
    IncidentClass::HitRateFragmentation,
];

/// The six facets of one incident class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncidentProfile {
    /// What fires the incident.
    pub detection_signal: &'static str,
    /// The automatic containment ("none" only where honesty demands).
    pub containment: &'static str,
    /// The runbook anchor in `docs/rabs-incident-runbooks.md`.
    pub runbook_anchor: &'static str,
    /// What the evidence bundle must include.
    pub evidence_items: &'static [&'static str],
    /// The recovery path.
    pub recovery: &'static str,
    /// The regression-test requirement (closure gate).
    pub regression_requirement: &'static str,
}

impl IncidentClass {
    /// The class profile (total over the registry).
    #[must_use]
    pub const fn profile(self) -> IncidentProfile {
        match self {
            Self::IncorrectResultDivergence => IncidentProfile {
                detection_signal: "F022/J016 differential mismatch or SemanticDivergence",
                containment: "quarantine the action key; stop serving; preserve both candidates",
                runbook_anchor: "incorrect-result-divergence",
                evidence_items: &[
                    "both-canonical-manifests",
                    "both-attempt-evidence-bundles",
                    "key-breakdown",
                    "projection-decision",
                ],
                recovery: "fix the unsound key component; epoch-bump if semantics changed",
                regression_requirement: "divergence fixture lands red-then-green",
            },
            Self::ObjectCorruption => IncidentProfile {
                detection_signal: "digest mismatch on read/verify (F024) or collision quarantine",
                containment: "quarantine the object; peers re-fetch from source",
                runbook_anchor: "object-corruption",
                evidence_items: &[
                    "quarantined-bytes",
                    "expected-digest",
                    "observed-digest",
                    "storage-metadata",
                ],
                recovery: "re-ingest from authoritative source; storage diagnostics if disk-level",
                regression_requirement: "corruption-injection fixture over the read path",
            },
            Self::PublicationFenceViolation => IncidentProfile {
                detection_signal: "stale boot generation/incarnation (F029) or F031 tombstone hit",
                containment: "publication refuses (fenced); lease not renewed",
                runbook_anchor: "publication-fence-violation",
                evidence_items: &[
                    "fencing-tokens",
                    "publication-record",
                    "worker-identity-row",
                ],
                recovery: "worker re-registers with a fresh incarnation; no data repair",
                regression_requirement: "new ordering added to the F029/F031 suites",
            },
            Self::OrphanProcessOrResource => IncidentProfile {
                detection_signal: "G002 obligation leak / reap sweep finds unowned resources",
                containment: "kill the process group; reap under crash-cleanup policy",
                runbook_anchor: "orphan-process-or-resource",
                evidence_items: &["crash-scene", "obligation-snapshot", "resource-inventory"],
                recovery: "verify the reap; a leaked obligation is a supervision bug",
                regression_requirement: "cancellation-at-that-await fixture (G012)",
            },
            Self::ProtocolCompatibilityFailure => IncidentProfile {
                detection_signal: "J002 refusal spike or R009 doctor skew finding",
                containment: "refused sessions stay refused; no downgrade",
                runbook_anchor: "protocol-compatibility-failure",
                evidence_items: &["both-hellos", "doctor-report", "deploy-timeline"],
                recovery: "upgrade the older side per the doctor; re-run the doctor",
                regression_requirement: "T009 upgrade-matrix case for the failing pair",
            },
            Self::WorkerIdentityMismatch => IncidentProfile {
                detection_signal: "presented identity does not match the pinned S001 key",
                containment: "connection refuses; worker hard-excluded from scheduling",
                runbook_anchor: "worker-identity-mismatch",
                evidence_items: &["presented-identity", "pinned-identity", "rotation-history"],
                recovery: "re-pin via rotation if legitimate; else treat as compromise",
                regression_requirement: "identity-mismatch fixture on the handshake",
            },
            Self::SecretExposure => IncidentProfile {
                detection_signal: "nonshareable artifact left the box / plaintext in audit",
                containment: "pull from serving; REVOKE the affected slot's tokens immediately",
                runbook_anchor: "secret-exposure",
                evidence_items: &[
                    "redaction-outcome",
                    "artifact-identity",
                    "slot-name",
                    "delivery-audit-trail",
                ],
                recovery: "rotate the secret at source FIRST; re-run under the new slot version",
                regression_requirement: "planted-secret fixture through the exact leak path",
            },
            Self::StorageExhaustion => IncidentProfile {
                detection_signal: "S008 disk/temp quota refusals; store write failures",
                containment: "per-peer quotas bound blast radius; retention evicts by policy",
                runbook_anchor: "storage-exhaustion",
                evidence_items: &["quota-counters", "largest-namespace-table", "eviction-log"],
                recovery: "raise quota or tighten retention; verify headroom",
                regression_requirement: "quota-exhaustion fixture stays bounded (S008)",
            },
            Self::SchedulerPressureCollapse => IncidentProfile {
                detection_signal: "I006 pressure + I012 brownout engaging; admission refusals",
                containment: "brownout sheds speculation first; hard exclusions protect workers",
                runbook_anchor: "scheduler-pressure-collapse",
                evidence_items: &["pressure-receipts", "brownout-decisions", "queue-depths"],
                recovery: "brownout lifts by hysteresis; review pool sizing",
                regression_requirement: "I014 storm scenario at the collapse shape",
            },
            Self::CancellationHang => IncidentProfile {
                detection_signal: "cancel acknowledged but obligations held past deadline",
                containment: "escalate kill to the process group; fence the attempt",
                runbook_anchor: "cancellation-hang",
                evidence_items: &[
                    "cancellation-timeline",
                    "await-point-inventory",
                    "crash-scene",
                ],
                recovery: "kill+reap verified; the await point gets a G012 lab case",
                regression_requirement: "cancellation-at-every-await covers the point",
            },
            Self::ReconciliationConflict => IncidentProfile {
                detection_signal: "two irreconcilable authoritative records for one identity",
                containment: "preserve both; quarantine the identity — never pick silently",
                runbook_anchor: "reconciliation-conflict",
                evidence_items: &["both-records", "sequence-provenance", "authority-rows"],
                recovery: "A005 authority rules decide; else stays quarantined",
                regression_requirement: "T040-family scenario reproducing the ordering",
            },
            Self::KeyInstabilityRegression => IncidentProfile {
                detection_signal: "fragmentation spike on one component or F014 invariance failure",
                containment: "affected families demote to the preserving/local lane",
                runbook_anchor: "key-instability-regression",
                evidence_items: &[
                    "breakdown-diffs",
                    "component-histogram",
                    "recent-key-changes",
                ],
                recovery: "fix the unstable component; F014/F015 green; epoch-bump if poisoned",
                regression_requirement: "F014 invariance case for the unstable input",
            },
            Self::HitRateFragmentation => IncidentProfile {
                detection_signal: "hit rate sags while Q011 variant spread rises",
                containment: "none (efficiency incident; serving stays sound)",
                runbook_anchor: "hit-rate-fragmentation",
                evidence_items: &[
                    "analyzer-report",
                    "per-category-waste",
                    "convergence-deltas",
                ],
                recovery: "converge the top fragmenter; re-measure",
                regression_requirement: "fleet corpus report tracks the category",
            },
        }
    }
}

/// A generated incident bundle (redaction-safe: ids and stable
/// strings only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentBundle {
    /// The class.
    pub class: IncidentClass,
    /// Sequence at generation (the incident's own event domain).
    pub generated_at_seq: u64,
    /// The request/operation ids involved.
    pub involved_request_ids: Vec<u64>,
    /// The evidence items the bundle must gather (from the profile).
    pub evidence_items: Vec<&'static str>,
    /// The automatic containment that was applied.
    pub containment_applied: &'static str,
    /// Link to the runbook section.
    pub runbook_link: String,
    /// The regression-test requirement (closure gate).
    pub regression_requirement: &'static str,
}

/// Generate the bundle for an incident.
#[must_use]
pub fn generate_bundle(
    class: IncidentClass,
    generated_at_seq: u64,
    involved_request_ids: Vec<u64>,
) -> IncidentBundle {
    let profile = class.profile();
    IncidentBundle {
        class,
        generated_at_seq,
        involved_request_ids,
        evidence_items: profile.evidence_items.to_vec(),
        containment_applied: profile.containment,
        runbook_link: format!("docs/rabs-incident-runbooks.md#{}", profile.runbook_anchor),
        regression_requirement: profile.regression_requirement,
    }
}

// ============================================================================
// Bead R013: Required Documentation Set (16 documents, plan Part XXIII §173)
// ============================================================================

use crate::schema_registry::REGISTRY as SCHEMA_REGISTRY;

/// Compiled-in handbook containing the incident runbooks and Section 173
/// required documentation set (`docs/rabs-incident-runbooks.md`).
pub const COMPILED_RABS_HANDBOOK: &str = include_str!("../../docs/rabs-incident-runbooks.md");

/// Schema fingerprint recorded in [`COMPILED_RABS_HANDBOOK`] (bead R013).
pub const DOCUMENTED_SCHEMA_FINGERPRINT: u64 = 0x1a61_e5bd_8ad2_cfb5;

/// Evidence vocabulary required across RABS documentation (bead R013; plan §173).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvidenceStanding {
    /// Directly measured or observed in live/corpus execution.
    Observed,
    /// Proven by deterministic test or formal check in CI.
    Verified,
    /// Implemented and verified on a subset of profiles/platforms.
    Partial,
    /// Reported on telemetry/dashboards without blocking release gates.
    Reported,
    /// Quantitative long-run target posture.
    Target,
    /// Unproven design hypothesis awaiting empirical confirmation.
    Hypothesis,
    /// Open design/implementation question.
    Open,
    /// Blocked on an external dependency or prerequisite gate.
    Blocked,
    /// Explicitly deferred beyond V1 scope.
    Deferred,
    /// Explicitly rejected design alternative or non-goal.
    Rejected,
}

/// Complete 10-term evidence vocabulary (bead R013).
pub const ALL_EVIDENCE_VOCABULARY: [EvidenceStanding; 10] = [
    EvidenceStanding::Observed,
    EvidenceStanding::Verified,
    EvidenceStanding::Partial,
    EvidenceStanding::Reported,
    EvidenceStanding::Target,
    EvidenceStanding::Hypothesis,
    EvidenceStanding::Open,
    EvidenceStanding::Blocked,
    EvidenceStanding::Deferred,
    EvidenceStanding::Rejected,
];

impl EvidenceStanding {
    /// Canonical uppercase vocabulary token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "OBSERVED",
            Self::Verified => "VERIFIED",
            Self::Partial => "PARTIAL",
            Self::Reported => "REPORTED",
            Self::Target => "TARGET",
            Self::Hypothesis => "HYPOTHESIS",
            Self::Open => "OPEN",
            Self::Blocked => "BLOCKED",
            Self::Deferred => "DEFERRED",
            Self::Rejected => "REJECTED",
        }
    }
}

/// Identifiers for the 16 required documents in plan Part XXIII §173 (bead R013).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequiredDocumentId {
    /// (1) Architecture overview.
    ArchitectureOverview,
    /// (2) Action-key contract.
    ActionKeyContract,
    /// (3) Canonical execroot contract.
    CanonicalExecrootContract,
    /// (4) Sandbox policy matrix.
    SandboxPolicyMatrix,
    /// (5) RABS/ATP protocol specification.
    RabsAtpProtocolSpec,
    /// (6) Object/CAS format and GC policy.
    ObjectCasFormatAndGcPolicy,
    /// (7) Cancellation and obligation contract.
    CancellationAndObligationContract,
    /// (8) Trust/provenance policy.
    TrustProvenancePolicy,
    /// (9) Worker admission policy.
    WorkerAdmissionPolicy,
    /// (10) Wrapper/Cargo compatibility matrix.
    WrapperCargoCompatibilityMatrix,
    /// (11) Rollout and rollback guide.
    RolloutAndRollbackGuide,
    /// (12) Incident runbooks (pairs with R008).
    IncidentRunbooks,
    /// (13) Benchmark methodology.
    BenchmarkMethodology,
    /// (14) Agent command palette.
    AgentCommandPalette,
    /// (15) Developer contribution guide.
    DeveloperContributionGuide,
    /// (16) Unsafe-boundary ledger and review guide (pairs with A011).
    UnsafeBoundaryLedgerAndReviewGuide,
}

/// Descriptor for one required document in the Section 173 documentation set (bead R013).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequiredDocumentSpec {
    /// Document identifier.
    pub id: RequiredDocumentId,
    /// 1-based ordinal in plan §173 (`1..=16`).
    pub ordinal: u8,
    /// Human-readable document title.
    pub title: &'static str,
    /// Section anchor in `docs/rabs-incident-runbooks.md`.
    pub section_anchor: &'static str,
    /// Companion standalone markdown path in `docs/` or `benchmarks/`.
    pub companion_path: &'static str,
    /// Primary evidence standing using [`EvidenceStanding`].
    pub standing: EvidenceStanding,
    /// Schema names in `schema_registry::REGISTRY` governed by this document.
    pub governed_schemas: &'static [&'static str],
    /// Explicit profile boundary statement.
    pub profile_boundary: &'static str,
    /// Explicit non-claim boundary statement.
    pub non_claim_boundary: &'static str,
    /// Operator surfaces (`doctor`, `why`, `incident_bundle`, etc.) linking to this document.
    pub operator_surfaces: &'static [&'static str],
}

/// Authoritative registry of all 16 required documents (bead R013; plan §173).
pub const REQUIRED_DOCUMENTATION_SET: [RequiredDocumentSpec; 16] = [
    RequiredDocumentSpec {
        id: RequiredDocumentId::ArchitectureOverview,
        ordinal: 1,
        title: "Architecture overview",
        section_anchor: "doc-01-architecture-overview",
        companion_path: "docs/rabs-incident-runbooks.md#doc-01-architecture-overview",
        standing: EvidenceStanding::Verified,
        governed_schemas: &["rabs.local-wrapper", "rabs.application", "atp.transport"],
        profile_boundary: "Single-trust-domain fleet (local wrapper, rabsd edge, coordinator, rabs-wkr)",
        non_claim_boundary: "DEFERRED cross-organization untrusted multi-tenant federation",
        operator_surfaces: &["doctor", "why", "status"],
    },
    RequiredDocumentSpec {
        id: RequiredDocumentId::ActionKeyContract,
        ordinal: 2,
        title: "Action-key contract",
        section_anchor: "doc-02-action-key-contract",
        companion_path: "docs/rabs-incident-runbooks.md#doc-02-action-key-contract",
        standing: EvidenceStanding::Verified,
        governed_schemas: &[
            "rabs.action-key",
            "rabs.action-family-key",
            "rabs.action-key-breakdown",
            "rabs.dependency-projection",
            "rabs.observed-input-recipe",
        ],
        profile_boundary: "SHA-256 domain-separated canonical descriptors and v1 exact-artifact dependency projection",
        non_claim_boundary: "REJECTED raw host path strings in portable keys",
        operator_surfaces: &["why", "incident_bundle"],
    },
    RequiredDocumentSpec {
        id: RequiredDocumentId::CanonicalExecrootContract,
        ordinal: 3,
        title: "Canonical execroot contract",
        section_anchor: "doc-03-canonical-execroot-contract",
        companion_path: "docs/rabs-incident-runbooks.md#doc-03-canonical-execroot-contract",
        standing: EvidenceStanding::Verified,
        governed_schemas: &["rabs.build-path-semantic-policy"],
        profile_boundary: "Canonical /rabs/execroot/{work,out,deps,sysroot,tmp} layout with prefix remapping",
        non_claim_boundary: "PARTIAL macOS host-sandbox path-remapped fallback without Linux userns",
        operator_surfaces: &["doctor", "why", "incident_bundle"],
    },
    RequiredDocumentSpec {
        id: RequiredDocumentId::SandboxPolicyMatrix,
        ordinal: 4,
        title: "Sandbox policy matrix",
        section_anchor: "doc-04-sandbox-policy-matrix",
        companion_path: "docs/rabs-incident-runbooks.md#doc-04-sandbox-policy-matrix",
        standing: EvidenceStanding::Verified,
        governed_schemas: &[
            "rabs.sandbox-semantic-policy",
            "rabs.isolation-profile",
            "rabs.source-capture-policy",
        ],
        profile_boundary: "Per-ActionClass hermetic sandbox profiles with network off and explicit source capture policy",
        non_claim_boundary: "BLOCKED shared serving from VolatileLocal or HostSandboxAudit without trust promotion",
        operator_surfaces: &["doctor", "why", "incident_bundle"],
    },
    RequiredDocumentSpec {
        id: RequiredDocumentId::RabsAtpProtocolSpec,
        ordinal: 5,
        title: "RABS/ATP protocol specification",
        section_anchor: "doc-05-rabs-atp-protocol-specification",
        companion_path: "docs/rabs-incident-runbooks.md#doc-05-rabs-atp-protocol-specification",
        standing: EvidenceStanding::Verified,
        governed_schemas: &[
            "rabs.local-wrapper",
            "rabs.application",
            "atp.transport",
            "rabs.reason-codes",
        ],
        profile_boundary: "Length-framed canonical codecs, explicit ATP/0 and RABS/1 negotiation, and control-reserve gate",
        non_claim_boundary: "REJECTED implicit protocol downgrade or non-idempotent 0-RTT mutation",
        operator_surfaces: &["doctor", "incident_bundle"],
    },
    RequiredDocumentSpec {
        id: RequiredDocumentId::ObjectCasFormatAndGcPolicy,
        ordinal: 6,
        title: "Object/CAS format and GC policy",
        section_anchor: "doc-06-object-cas-format-and-gc-policy",
        companion_path: "docs/rabs-cas-maintenance.md",
        standing: EvidenceStanding::Verified,
        governed_schemas: &[
            "rabs.object-manifest",
            "rabs.artifact-bundle",
            "rabs.chunking-profile",
            "rabs.pack-format",
            "rabs.metadata-store",
        ],
        profile_boundary: "Bounded acyclic manifests, CDC chunking, small-object packs, two-phase publication, and pinned GC",
        non_claim_boundary: "NON-CLAIM serving unverified or partially closed blobs",
        operator_surfaces: &["doctor", "incident_bundle"],
    },
    RequiredDocumentSpec {
        id: RequiredDocumentId::CancellationAndObligationContract,
        ordinal: 7,
        title: "Cancellation and obligation contract",
        section_anchor: "doc-07-cancellation-and-obligation-contract",
        companion_path: "docs/rabs-incident-runbooks.md#doc-07-cancellation-and-obligation-contract",
        standing: EvidenceStanding::Verified,
        governed_schemas: &["rabs.metadata-store", "rabs.local-wrapper"],
        profile_boundary: "Ref-counted subscriber interests, quiescent drain, process-group/cgroup kill escalation, zero leaked obligations",
        non_claim_boundary: "VERIFIED attempt fencing tombstones any late output after cancellation",
        operator_surfaces: &["doctor", "why", "incident_bundle"],
    },
    RequiredDocumentSpec {
        id: RequiredDocumentId::TrustProvenancePolicy,
        ordinal: 8,
        title: "Trust/provenance policy",
        section_anchor: "doc-08-trust-provenance-policy",
        companion_path: "docs/rabs-trust-model-v1.md",
        standing: EvidenceStanding::Verified,
        governed_schemas: &["rabs.metadata-store", "rabs.artifact-bundle"],
        profile_boundary: "Single administrative trust domain V1, Ed25519 worker identity pinning, Tier0-Tier5 evidence tiers",
        non_claim_boundary: "DEFERRED cross-domain untrusted peer cache federation",
        operator_surfaces: &["doctor", "why", "incident_bundle"],
    },
    RequiredDocumentSpec {
        id: RequiredDocumentId::WorkerAdmissionPolicy,
        ordinal: 9,
        title: "Worker admission policy",
        section_anchor: "doc-09-worker-admission-policy",
        companion_path: "docs/rabs-incident-runbooks.md#doc-09-worker-admission-policy",
        standing: EvidenceStanding::Verified,
        governed_schemas: &["rabs.isolation-profile", "rabs.application"],
        profile_boundary: "Pinned worker identity handshake, toolchain/CPU equivalence, PSI/disk headroom, boot-generation fencing",
        non_claim_boundary: "NON-CLAIM scheduling onto workers with drifted schema fingerprints",
        operator_surfaces: &["doctor", "why", "incident_bundle"],
    },
    RequiredDocumentSpec {
        id: RequiredDocumentId::WrapperCargoCompatibilityMatrix,
        ordinal: 10,
        title: "Wrapper/Cargo compatibility matrix",
        section_anchor: "doc-10-wrapper-cargo-compatibility-matrix",
        companion_path: "docs/rabs-canonical-cargo.md",
        standing: EvidenceStanding::Verified,
        governed_schemas: &["rabs.local-wrapper", "rabs.invocation-record"],
        profile_boundary: "RUSTC_WRAPPER interception, Cargo JSON diagnostic + early .rmeta streaming, jobserver hygiene",
        non_claim_boundary: "PARTIAL proc-macro host dylib cross-target sharing; interactive/watch runs locally",
        operator_surfaces: &["doctor", "why"],
    },
    RequiredDocumentSpec {
        id: RequiredDocumentId::RolloutAndRollbackGuide,
        ordinal: 11,
        title: "Rollout and rollback guide",
        section_anchor: "doc-11-rollout-and-rollback-guide",
        companion_path: "docs/rabs-incident-runbooks.md#doc-11-rollout-and-rollback-guide",
        standing: EvidenceStanding::Verified,
        governed_schemas: &["rabs.application", "rabs.metadata-store"],
        profile_boundary: "14 scoped feature modes, canary low-risk dependency routing, and one-command rollback",
        non_claim_boundary: "REJECTED rollback below coordinator N-1 compatibility floor without draining",
        operator_surfaces: &["doctor", "why", "incident_bundle"],
    },
    RequiredDocumentSpec {
        id: RequiredDocumentId::IncidentRunbooks,
        ordinal: 12,
        title: "Incident runbooks",
        section_anchor: "doc-12-incident-runbooks",
        companion_path: "docs/rabs-incident-runbooks.md",
        standing: EvidenceStanding::Verified,
        governed_schemas: &["rabs.reason-codes", "rabs.metadata-store"],
        profile_boundary: "13 incident classes with detection, containment, evidence bundle, recovery, and regression gate",
        non_claim_boundary: "NON-CLAIM automatic containment for HitRateFragmentation (efficiency-only incident)",
        operator_surfaces: &["doctor", "why", "incident_bundle"],
    },
    RequiredDocumentSpec {
        id: RequiredDocumentId::BenchmarkMethodology,
        ordinal: 13,
        title: "Benchmark methodology",
        section_anchor: "doc-13-benchmark-methodology",
        companion_path: "benchmarks/GATE_LEDGER.md",
        standing: EvidenceStanding::Observed,
        governed_schemas: &["rabs.invocation-record", "rabs.reason-codes"],
        profile_boundary: "Nearest-rank p50/p95/p99 integer percentiles, live incumbent comparison, and >900 permille long-run target",
        non_claim_boundary: "TARGET >90% served fraction is ReportedNotGated until M16 frontier review",
        operator_surfaces: &["why"],
    },
    RequiredDocumentSpec {
        id: RequiredDocumentId::AgentCommandPalette,
        ordinal: 14,
        title: "Agent command palette",
        section_anchor: "doc-14-agent-command-palette",
        companion_path: "docs/rabs-incident-runbooks.md#doc-14-agent-command-palette",
        standing: EvidenceStanding::Verified,
        governed_schemas: &["rabs.reason-codes", "rabs.action-key-breakdown"],
        profile_boundary: "Bounded JSON/TOON stdout payloads across rch why and rch rabs subcommands",
        non_claim_boundary: "NON-CLAIM unredacted secret or raw env values in agent output",
        operator_surfaces: &["doctor", "why"],
    },
    RequiredDocumentSpec {
        id: RequiredDocumentId::DeveloperContributionGuide,
        ordinal: 15,
        title: "Developer contribution guide",
        section_anchor: "doc-15-developer-contribution-guide",
        companion_path: "docs/rabs-incident-runbooks.md#doc-15-developer-contribution-guide",
        standing: EvidenceStanding::Verified,
        governed_schemas: &[
            "rabs.action-key",
            "rabs.local-wrapper",
            "rabs.application",
            "rabs.metadata-store",
            "rabs.object-manifest",
            "rabs.sandbox-semantic-policy",
        ],
        profile_boundary: "Dependency-direction DAG, forbid(unsafe_code), cold-namespace epoch bumps, and CI doc-currency gates",
        non_claim_boundary: "REJECTED compatibility shims or schema edits without documentation updates",
        operator_surfaces: &["doctor"],
    },
    RequiredDocumentSpec {
        id: RequiredDocumentId::UnsafeBoundaryLedgerAndReviewGuide,
        ordinal: 16,
        title: "Unsafe-boundary ledger and review guide",
        section_anchor: "doc-16-unsafe-boundary-ledger-and-review-guide",
        companion_path: "docs/rabs-unsafe-boundary-ledger.md",
        standing: EvidenceStanding::Verified,
        governed_schemas: &["rabs.sandbox-semantic-policy", "rabs.isolation-profile"],
        profile_boundary: "Zero inline unsafe in libraries; privileged helpers isolated and audited in docs/rabs-unsafe-boundary-ledger.md",
        non_claim_boundary: "BLOCKED shipping any helper binary absent from the unsafe-boundary ledger",
        operator_surfaces: &["doctor", "incident_bundle"],
    },
];

/// Return the documentation links for a given operator surface (`"doctor"`, `"why"`, `"incident_bundle"`).
#[must_use]
pub fn operator_surface_doc_links(surface: &str) -> Vec<&'static str> {
    REQUIRED_DOCUMENTATION_SET
        .iter()
        .filter(|doc| doc.operator_surfaces.contains(&surface))
        .map(|doc| doc.companion_path)
        .collect()
}

/// Typed CI error when the Section 173 documentation set is incomplete or out of sync with schemas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DocumentationCurrencyError {
    /// Compiled handbook is missing a required document section heading.
    MissingDocumentSection {
        /// Ordinal of the missing document (`1..=16`).
        ordinal: u8,
        /// Missing section anchor.
        section_anchor: &'static str,
    },
    /// Document is missing an explicit profile or non-claim boundary or operator surface link.
    IncompleteDocumentMetadata {
        /// Ordinal of the incomplete document.
        ordinal: u8,
    },
    /// A schema in `schema_registry::REGISTRY` is not covered by any document in [`REQUIRED_DOCUMENTATION_SET`].
    UncoveredSchema {
        /// Uncovered schema name.
        schema_name: &'static str,
    },
    /// The live schema registry fingerprint differs from the fingerprint documented in the handbook.
    SchemaChangedWithoutDocUpdate {
        /// Live schema registry fingerprint.
        live_fingerprint: u64,
        /// Fingerprint recorded in the documentation set.
        documented_fingerprint: u64,
    },
}

/// Verify that all 16 required documents exist, carry profile and non-claim boundaries,
/// are linked from operator surfaces (`doctor`, `why`, `incident_bundle`), cover every
/// schema in `schema_registry::REGISTRY`, and match `live_schema_fingerprint` (bead R013).
///
/// # Errors
/// Returns [`DocumentationCurrencyError`] if any document section is missing or if a
/// schema change occurred without updating the documentation set.
pub fn verify_required_documentation_set(
    live_schema_fingerprint: u64,
) -> Result<(), DocumentationCurrencyError> {
    let fingerprint_tag = format!("`{DOCUMENTED_SCHEMA_FINGERPRINT:#x}`");
    if live_schema_fingerprint != DOCUMENTED_SCHEMA_FINGERPRINT
        || !COMPILED_RABS_HANDBOOK.contains(&fingerprint_tag)
    {
        return Err(DocumentationCurrencyError::SchemaChangedWithoutDocUpdate {
            live_fingerprint: live_schema_fingerprint,
            documented_fingerprint: DOCUMENTED_SCHEMA_FINGERPRINT,
        });
    }

    for doc in &REQUIRED_DOCUMENTATION_SET {
        let heading = format!("## {}", doc.section_anchor);
        if !COMPILED_RABS_HANDBOOK.contains(&heading) {
            return Err(DocumentationCurrencyError::MissingDocumentSection {
                ordinal: doc.ordinal,
                section_anchor: doc.section_anchor,
            });
        }
        if doc.profile_boundary.is_empty()
            || doc.non_claim_boundary.is_empty()
            || doc.governed_schemas.is_empty()
            || doc.operator_surfaces.is_empty()
            || !COMPILED_RABS_HANDBOOK.contains(doc.standing.as_str())
        {
            return Err(DocumentationCurrencyError::IncompleteDocumentMetadata {
                ordinal: doc.ordinal,
            });
        }
    }

    for entry in SCHEMA_REGISTRY {
        let covered = REQUIRED_DOCUMENTATION_SET
            .iter()
            .any(|doc| doc.governed_schemas.contains(&entry.name));
        if !covered {
            return Err(DocumentationCurrencyError::UncoveredSchema {
                schema_name: entry.name,
            });
        }
        let versioned_token = format!("`{}@{}`", entry.name, entry.version);
        if !COMPILED_RABS_HANDBOOK.contains(&versioned_token) {
            return Err(DocumentationCurrencyError::UncoveredSchema {
                schema_name: entry.name,
            });
        }
    }

    Ok(())
}

// ============================================================================
// Bead T012: Automated failing-trace minimization (lab, chaos, differential)
// ============================================================================

/// Suite classes producing failing traces eligible for automated minimization (bead T012).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailingTraceSuiteClass {
    /// Deterministic lab scenario (virtual time, interleaving schedule).
    LabScenario,
    /// Chaos kill/restart injection scenario.
    ChaosKill,
    /// Stock-vs-RABS differential divergence scenario.
    DifferentialDivergence,
}

/// Un-minimized failing trace input carrying T053 seed, causal IDs, input manifest,
/// invocation args, and action/message trace (bead T012).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailingTraceCandidate {
    /// Suite class that produced the failure.
    pub suite_class: FailingTraceSuiteClass,
    /// Associated incident class for archiving.
    pub incident_class: IncidentClass,
    /// Deterministic replay seed (from T053 structured log).
    pub replay_seed: u64,
    /// Originating causal trace IDs.
    pub causal_ids: Vec<u64>,
    /// Input manifest entry digests (`[u8; 32]`).
    pub input_manifest_entries: Vec<[u8; 32]>,
    /// Normalized invocation argument tokens.
    pub invocation_args: Vec<String>,
    /// Ordered sequence of action/message event IDs in the trace.
    pub trace_events: Vec<u64>,
}

/// Archived minimized reproduction bundled alongside an [`IncidentBundle`] (bead T012).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimizedTraceArchive {
    /// Suite class of the minimized failure.
    pub suite_class: FailingTraceSuiteClass,
    /// Deterministic replay seed preserved for instant reproduction.
    pub replay_seed: u64,
    /// Preserved causal IDs.
    pub causal_ids: Vec<u64>,
    /// Bisected minimal input manifest entries required to reproduce the failure.
    pub minimal_input_manifest: Vec<[u8; 32]>,
    /// Shrunk invocation argument tokens required to reproduce the failure.
    pub minimal_invocation_args: Vec<String>,
    /// Reduced action/message event trace required to reproduce the failure.
    pub minimal_trace_events: Vec<u64>,
    /// Number of reduction/re-verification steps executed.
    pub reduction_steps: u32,
    /// Paired [`IncidentBundle`] archived alongside the minimized trace.
    pub incident_bundle: IncidentBundle,
}

/// Automatically minimize a [`FailingTraceCandidate`] via delta-debugging bisection over
/// the input manifest, invocation arguments, and action/message trace, re-verifying
/// deterministic reproduction at every step and archiving alongside an [`IncidentBundle`] (bead T012).
pub fn minimize_failing_trace_and_archive<F>(
    candidate: &FailingTraceCandidate,
    generated_at_seq: u64,
    mut reproduces: F,
) -> Option<MinimizedTraceArchive>
where
    F: FnMut(&[[u8; 32]], &[String], &[u64]) -> bool,
{
    if !reproduces(
        &candidate.input_manifest_entries,
        &candidate.invocation_args,
        &candidate.trace_events,
    ) {
        return None;
    }

    let mut reduction_steps = 0_u32;

    // 1. Bisect / delta-debug the input manifest entries.
    let mut inputs = candidate.input_manifest_entries.clone();
    let mut chunk_size = inputs.len() / 2;
    while chunk_size > 0 {
        let mut idx = 0;
        let mut reduced = false;
        while idx < inputs.len() {
            let end = (idx + chunk_size).min(inputs.len());
            let mut trial = inputs.clone();
            trial.drain(idx..end);
            reduction_steps = reduction_steps.saturating_add(1);
            if !trial.is_empty()
                && reproduces(&trial, &candidate.invocation_args, &candidate.trace_events)
            {
                inputs = trial;
                reduced = true;
            } else {
                idx += chunk_size;
            }
        }
        if !reduced {
            chunk_size /= 2;
        }
    }

    // 2. Shrink invocation arguments one-by-one while preserving reproduction.
    let mut args = candidate.invocation_args.clone();
    let mut i = 0;
    while i < args.len() {
        let mut trial = args.clone();
        trial.remove(i);
        reduction_steps = reduction_steps.saturating_add(1);
        if !trial.is_empty() && reproduces(&inputs, &trial, &candidate.trace_events) {
            args = trial;
        } else {
            i += 1;
        }
    }

    // 3. Drop uninvolved actions/messages from the event trace while preserving reproduction.
    let mut events = candidate.trace_events.clone();
    let mut j = 0;
    while j < events.len() {
        let mut trial = events.clone();
        trial.remove(j);
        reduction_steps = reduction_steps.saturating_add(1);
        if !trial.is_empty() && reproduces(&inputs, &args, &trial) {
            events = trial;
        } else {
            j += 1;
        }
    }

    let incident_bundle = generate_bundle(
        candidate.incident_class,
        generated_at_seq,
        candidate.causal_ids.clone(),
    );

    Some(MinimizedTraceArchive {
        suite_class: candidate.suite_class,
        replay_seed: candidate.replay_seed,
        causal_ids: candidate.causal_ids.clone(),
        minimal_input_manifest: inputs,
        minimal_invocation_args: args,
        minimal_trace_events: events,
        reduction_steps,
        incident_bundle,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema_registry::registry_fingerprint;

    const RUNBOOKS: &str = COMPILED_RABS_HANDBOOK;

    #[test]
    fn the_registry_is_closed_with_all_six_facets_per_class() {
        assert_eq!(ALL_INCIDENT_CLASSES.len(), 13, "thirteen classes, pinned");
        for class in ALL_INCIDENT_CLASSES {
            let p = class.profile();
            assert!(!p.detection_signal.is_empty(), "{class:?} detection");
            assert!(!p.containment.is_empty(), "{class:?} containment");
            assert!(!p.runbook_anchor.is_empty(), "{class:?} anchor");
            assert!(!p.evidence_items.is_empty(), "{class:?} evidence");
            assert!(!p.recovery.is_empty(), "{class:?} recovery");
            assert!(
                !p.regression_requirement.is_empty(),
                "{class:?} regression gate"
            );
        }
    }

    #[test]
    fn every_runbook_section_exists_in_the_doc() {
        // THE runbooks-written acceptance, pinned: each class anchor
        // is a section heading in the compiled-in doc.
        for class in ALL_INCIDENT_CLASSES {
            let heading = format!("## {}", class.profile().runbook_anchor);
            assert!(
                RUNBOOKS.contains(&heading),
                "runbook section missing: {heading}"
            );
        }
    }

    #[test]
    fn bundle_generation_works_for_every_class() {
        // THE bundle acceptance: per class, the bundle carries the
        // class, evidence list, containment, runbook link, and the
        // regression gate.
        for class in ALL_INCIDENT_CLASSES {
            let bundle = generate_bundle(class, 42, vec![100, 101]);
            assert_eq!(bundle.class, class);
            assert_eq!(bundle.generated_at_seq, 42);
            assert_eq!(bundle.involved_request_ids, vec![100, 101]);
            assert!(!bundle.evidence_items.is_empty());
            assert!(
                bundle
                    .runbook_link
                    .starts_with("docs/rabs-incident-runbooks.md#")
            );
            assert!(!bundle.regression_requirement.is_empty());
        }
    }

    #[test]
    fn spot_checks_pin_the_load_bearing_facets() {
        // Secret exposure containment revokes tokens immediately.
        let secret = IncidentClass::SecretExposure.profile();
        assert!(secret.containment.contains("REVOKE"));
        assert!(secret.evidence_items.contains(&"slot-name"));
        assert!(
            !secret.evidence_items.iter().any(|i| i.contains("value")),
            "the evidence list must never ask for a secret value"
        );
        // Divergence preserves BOTH candidates (H003 rule 8 posture).
        let divergence = IncidentClass::IncorrectResultDivergence.profile();
        assert!(divergence.containment.contains("both candidates"));
        // Fragmentation honestly declares no automatic containment.
        let frag = IncidentClass::HitRateFragmentation.profile();
        assert!(frag.containment.starts_with("none"));
    }

    #[test]
    fn r013_all_16_required_documents_exist_linked_from_operator_surfaces_and_ci_flags_schema_drift()
     {
        assert_eq!(REQUIRED_DOCUMENTATION_SET.len(), 16);
        for (idx, doc) in REQUIRED_DOCUMENTATION_SET.iter().enumerate() {
            assert_eq!(usize::from(doc.ordinal), idx + 1);
            assert!(!doc.title.is_empty());
        }
        for term in ALL_EVIDENCE_VOCABULARY {
            assert!(
                COMPILED_RABS_HANDBOOK.contains(term.as_str()),
                "compiled handbook must declare evidence vocabulary token {}",
                term.as_str()
            );
        }

        // Operator surfaces (doctor, why, incident_bundle) all link into the 16-document set.
        let doctor_links = operator_surface_doc_links("doctor");
        let why_links = operator_surface_doc_links("why");
        let bundle_links = operator_surface_doc_links("incident_bundle");
        assert!(!doctor_links.is_empty());
        assert!(!why_links.is_empty());
        assert!(!bundle_links.is_empty());

        // Live schema fingerprint matches the documented schema set -> passes CI check.
        let live_fp = registry_fingerprint();
        assert_eq!(verify_required_documentation_set(live_fp), Ok(()));

        // Simulated schema change without updating the documentation set -> flagged by CI check.
        let drifted_fp = live_fp ^ 0x1;
        assert_eq!(
            verify_required_documentation_set(drifted_fp),
            Err(DocumentationCurrencyError::SchemaChangedWithoutDocUpdate {
                live_fingerprint: drifted_fp,
                documented_fingerprint: DOCUMENTED_SCHEMA_FINGERPRINT,
            })
        );
    }

    #[test]
    fn t012_automated_failing_trace_minimization_across_lab_chaos_and_differential_suites() {
        let suites = [
            (
                FailingTraceSuiteClass::LabScenario,
                IncidentClass::CancellationHang,
                [0x11_u8; 32],
                "--cfg=lab_deadlock",
                404_u64,
            ),
            (
                FailingTraceSuiteClass::ChaosKill,
                IncidentClass::PublicationFenceViolation,
                [0x22_u8; 32],
                "--chaos-kill=publish",
                505_u64,
            ),
            (
                FailingTraceSuiteClass::DifferentialDivergence,
                IncidentClass::IncorrectResultDivergence,
                [0x33_u8; 32],
                "-Copt-level=3",
                606_u64,
            ),
        ];

        for (suite_class, incident_class, trigger_input, trigger_arg, trigger_event) in suites {
            let mut input_manifest_entries: Vec<[u8; 32]> = (1..=16_u8).map(|b| [b; 32]).collect();
            input_manifest_entries.push(trigger_input);

            let invocation_args = vec![
                "rustc".to_owned(),
                "--edition=2024".to_owned(),
                "-Wunused".to_owned(),
                trigger_arg.to_owned(),
                "src/lib.rs".to_owned(),
            ];

            let mut trace_events: Vec<u64> = (100..120).collect();
            trace_events.push(trigger_event);

            let candidate = FailingTraceCandidate {
                suite_class,
                incident_class,
                replay_seed: 0xDEAD_BEEF_CAFE_0001,
                causal_ids: vec![9001, 9002],
                input_manifest_entries,
                invocation_args,
                trace_events,
            };

            let archive =
                minimize_failing_trace_and_archive(&candidate, 77, |inputs, args, evs| {
                    inputs.contains(&trigger_input)
                        && args.iter().any(|a| a == trigger_arg)
                        && evs.contains(&trigger_event)
                })
                .expect("seeded failure reproduces and minimizes");

            assert_eq!(archive.suite_class, suite_class);
            assert_eq!(archive.minimal_input_manifest, vec![trigger_input]);
            assert_eq!(
                archive.minimal_invocation_args,
                vec![trigger_arg.to_owned()]
            );
            assert_eq!(archive.minimal_trace_events, vec![trigger_event]);
            assert!(archive.reduction_steps > 0);
            assert_eq!(archive.incident_bundle.class, incident_class);
            assert_eq!(
                archive.incident_bundle.involved_request_ids,
                vec![9001, 9002]
            );
        }
    }
}
