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

#[cfg(test)]
mod tests {
    use super::*;

    const RUNBOOKS: &str = include_str!("../../docs/rabs-incident-runbooks.md");

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
}
