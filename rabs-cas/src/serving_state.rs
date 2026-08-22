//! Revisioned, authority-bound serving state with conservative durable
//! TTL/clock-epoch semantics (bead H040; risk R126).
//!
//! The store rows (schema v9) carry `state_revision`, the evaluating
//! authority's digest key, a [`ServingValidity`] window, and NAMED
//! blocking-quarantine references in a junction table. The rules this
//! module gates on:
//!
//! - **Replay is explicit**: a serving write whose revision is not
//!   strictly greater than the stored one is a typed refusal
//!   (`StaleServingRevision`), never an overwrite — idempotency lives at
//!   the message layer, not by clobbering state.
//! - **References are the authority**: serving is blocked by quarantine
//!   ROWS the record names; a reason string is never the gate, and a
//!   dangling reference is refused at write time
//!   (`UnknownQuarantineReference`).
//! - **Clocks are distrusted conservatively**: wall-clock rollback,
//!   clock-epoch discontinuity, or uncertainty crossing the not-after
//!   bound all EXPIRE serving (deny), never extend it. The validity
//!   arithmetic is `rabs_protocol::serving::ServingValidity::still_valid`
//!   — this module only names the cause; the protocol impl stays the
//!   single authority on the verdict.
//!
//! Recovery from a blocking quarantine is a NEW record at a higher
//! revision without the reference (written after the repair is
//! processed); quarantine rows themselves are released by the H012
//! repair flow, not here.

use rabs_protocol::result_identity::TypedDigest;
use rabs_protocol::serving::ServingValidity;

use crate::metadata_store::{
    DivergenceIncidentRow, QuarantineScope, RabsMetadataStore, StoreError,
};

/// Disposition string under which serving is possible at all.
pub const SERVABLE_DISPOSITION: &str = "servable";

/// The gate's typed decision for one action key at one instant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeDecision {
    /// No serving record exists.
    NoRecord,
    /// The disposition forbids serving.
    NotServable {
        /// The stored disposition.
        disposition: String,
    },
    /// Blocked by named quarantine references.
    Blocked {
        /// The (scope, subject) rows blocking serving.
        references: Vec<(String, String)>,
    },
    /// The coordinator clock epoch changed since evaluation
    /// (discontinuity): conservative expiry.
    ExpiredClockEpoch,
    /// The wall clock ran backward past the evaluation instant:
    /// conservative expiry.
    ExpiredClockRollback,
    /// Age plus uncertainty crossed the not-after bound.
    ExpiredTtl,
    /// Serving is permitted right now.
    Servable,
}

/// Evaluate whether an action may serve at (`now_unix_micros`,
/// `now_epoch`). Checks run strictest-first; the validity verdict is
/// [`ServingValidity::still_valid`], with this function only naming the
/// cause on denial.
pub fn serving_gate(
    store: &mut dyn RabsMetadataStore,
    action_key: &str,
    now_unix_micros: i64,
    now_epoch: u64,
) -> Result<ServeDecision, StoreError> {
    let Some(record) = store.serving_record(action_key)? else {
        return Ok(ServeDecision::NoRecord);
    };
    if record.disposition != SERVABLE_DISPOSITION {
        return Ok(ServeDecision::NotServable {
            disposition: record.disposition,
        });
    }
    if !record.blocking.is_empty() {
        return Ok(ServeDecision::Blocked {
            references: record.blocking,
        });
    }
    if !record.validity.still_valid(now_unix_micros, now_epoch) {
        let validity: &ServingValidity = &record.validity;
        if now_epoch != validity.coordinator_clock_epoch {
            return Ok(ServeDecision::ExpiredClockEpoch);
        }
        if now_unix_micros < validity.evaluated_at_unix_micros {
            return Ok(ServeDecision::ExpiredClockRollback);
        }
        return Ok(ServeDecision::ExpiredTtl);
    }
    Ok(ServeDecision::Servable)
}

// ---------------------------------------------------------------------
// Deterministic-failure publication classification + TTL-governed
// serving/revalidation (K007; plan §66; risk R28).
//
// A FAILED attempt may publish only as an ADMITTED deterministic
// failure — one publication path shared with success (I16) — and its
// manifest carries canonical diagnostics plus the normalized outcome,
// never materializable outputs (`CanonicalActionResultManifest::validate`
// refuses outputs on `DeterministicFailure` structurally). Everything
// that makes a failure NON-deterministic — OOM, signals, cancellation,
// timeout, worker loss, transport failure, panic — is a named variant
// here, so "never publish" is exhaustive over the R28 class by
// construction, not by string matching.
//
// Served failures live under a SHORT revalidation TTL: expiry
// suppresses serving and schedules re-execution. Revalidation is the
// soundness experiment: byte-identical reproduction APPENDS evidence
// and renews the window; success or a DIFFERENT failure under the same
// key is a soundness incident — divergence recorded, action
// quarantined, serving suppressed.
// ---------------------------------------------------------------------

/// Default short revalidation TTL for served dependency failures.
pub const DEFAULT_REVALIDATION_TTL_MICROS: u64 = 60_000_000;

/// Normalized terminal outcome of one attempt. The non-`Exit` variants
/// ARE the R28 never-publish class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalOutcome {
    /// The tool terminated itself with this exit code.
    Exit(i32),
    /// The process died to memory pressure.
    Oom,
    /// The process died to signal N (including 128+N translations).
    Signal(i32),
    /// Cancelled before natural termination.
    Cancelled,
    /// Killed at a configured deadline.
    Timeout,
    /// The worker vanished mid-attempt.
    WorkerLost,
    /// Transfer/transport error corrupted the attempt.
    TransportFailed,
    /// The executor itself panicked.
    Panicked,
}

/// Why a failed attempt may not publish as a deterministic failure.
/// Every variant is a REFUSAL TO SERVE, never a downgrade to success
/// or a silent drop of the diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureRefusal {
    /// Exit 0 is a SUCCESS candidate, not a failure.
    ZeroExitIsNotAFailure,
    /// An R28-class outcome: nondeterministic by nature.
    NotDeterministic(&'static str),
    /// Canonical diagnostics/events were not fully captured.
    CaptureIncomplete,
    /// Positive or negative input closure is not closed.
    InputsNotClosed,
    /// The attempt declared (or cannot disclaim) undeclared side
    /// effects.
    UndeclaredSideEffects,
    /// The action class policy refuses failure caching.
    ClassPolicyRefused,
    /// The trust policy refuses failure serving for this action.
    TrustPolicyRefused,
}

impl std::fmt::Display for FailureRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroExitIsNotAFailure => write!(f, "exit 0 is a success candidate"),
            Self::NotDeterministic(class) => write!(f, "nondeterministic outcome: {class}"),
            Self::CaptureIncomplete => write!(f, "canonical capture incomplete"),
            Self::InputsNotClosed => write!(f, "input closure not closed"),
            Self::UndeclaredSideEffects => write!(f, "undeclared side effects"),
            Self::ClassPolicyRefused => write!(f, "class policy refuses failure caching"),
            Self::TrustPolicyRefused => write!(f, "trust policy refuses failure serving"),
        }
    }
}

impl std::error::Error for FailureRefusal {}

/// Admission receipt for a deterministic-failure publication: the
/// normalized outcome a failure manifest carries (with the canonical
/// diagnostics object references).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureAdmission {
    /// The normalized nonzero exit code (signal/OOM classes never get
    /// here, so this IS the deterministic observable).
    pub normalized_exit: i32,
}

/// Decide whether a failed attempt may publish under
/// [`rabs_protocol::result_identity::ResultKind::DeterministicFailure`].
/// Checks run in bead order; the first refusal wins.
///
/// # Errors
/// [`FailureRefusal`] — the attempt stays unpublished; callers may
/// still report its diagnostics as a plain local failure.
pub fn classify_deterministic_failure(
    outcome: TerminalOutcome,
    capture_complete: bool,
    inputs_closed: bool,
    no_undeclared_side_effects: bool,
    class_policy_permits: bool,
    trust_policy_permits: bool,
) -> Result<FailureAdmission, FailureRefusal> {
    let normalized_exit = match outcome {
        TerminalOutcome::Exit(0) => {
            return Err(FailureRefusal::ZeroExitIsNotAFailure);
        }
        TerminalOutcome::Exit(code) => code,
        TerminalOutcome::Oom => return Err(FailureRefusal::NotDeterministic("oom")),
        TerminalOutcome::Signal(_) => {
            return Err(FailureRefusal::NotDeterministic("signal"));
        }
        TerminalOutcome::Cancelled => return Err(FailureRefusal::NotDeterministic("cancelled")),
        TerminalOutcome::Timeout => return Err(FailureRefusal::NotDeterministic("timeout")),
        TerminalOutcome::WorkerLost => return Err(FailureRefusal::NotDeterministic("worker-loss")),
        TerminalOutcome::TransportFailed => {
            return Err(FailureRefusal::NotDeterministic("transport-failure"));
        }
        TerminalOutcome::Panicked => return Err(FailureRefusal::NotDeterministic("panic")),
    };
    if !capture_complete {
        return Err(FailureRefusal::CaptureIncomplete);
    }
    if !inputs_closed {
        return Err(FailureRefusal::InputsNotClosed);
    }
    if !no_undeclared_side_effects {
        return Err(FailureRefusal::UndeclaredSideEffects);
    }
    if !class_policy_permits {
        return Err(FailureRefusal::ClassPolicyRefused);
    }
    if !trust_policy_permits {
        return Err(FailureRefusal::TrustPolicyRefused);
    }
    Ok(FailureAdmission { normalized_exit })
}

/// What revalidation concluded about a served failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevalidationVerdict {
    /// Byte-identical failure reproduced under the same key: evidence
    /// appended, serving renewed with a fresh short TTL at a higher
    /// revision.
    IdenticalEvidenceAppended {
        /// Serving revision written.
        new_revision: u64,
    },
    /// Success or a DIFFERENT failure under the same key: soundness
    /// incident appended AND the action quarantined (serving
    /// suppressed until the repair flow releases it).
    SoundnessIncidentQuarantined {
        /// Incident sequence recorded.
        incident_seq: u64,
        /// Serving revision written.
        new_revision: u64,
    },
}

/// Typed revalidation refusals (distinct from store errors so callers
/// can distinguish "nothing to revalidate" from storage faults).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevalidationError {
    /// No serving record exists for this key.
    NoServingRecord,
    /// The stored record's revision moved past `expected_revision`:
    /// someone else revalidated concurrently; retry against fresh
    /// state instead of clobbering (H040 replay rule).
    StaleRevision {
        /// Revision actually stored.
        stored: u64,
    },
    Store(String),
}

impl std::fmt::Display for RevalidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoServingRecord => write!(f, "no serving record to revalidate"),
            Self::StaleRevision { stored } => {
                write!(f, "serving revision moved to {stored}; retry")
            }
            Self::Store(error) => write!(f, "store: {error}"),
        }
    }
}

impl std::error::Error for RevalidationError {}

/// Apply one revalidation result for a served dependency failure
/// (K007 lifecycle). Compares the revalidating attempt's observable
/// signature against the published one:
///
/// - identical → verification sample appended (H033), serving renewed
///   at `expected_revision + 1` with a fresh TTL window;
/// - different → divergence incident appended (H026), scoped
///   quarantine row added, serving disposition flipped to
///   `"quarantined"` at the same higher revision.
///
/// `ttl_micros` of `None` uses [`DEFAULT_REVALIDATION_TTL_MICROS`].
///
/// # Errors
/// [`RevalidationError`] — nothing was written unless the store call
/// itself succeeded partway (each step is one transaction; the
/// quarantine-before-disposition order means a crash between them
/// leaves the action blocked-but-unlabeled, which the repair flow
/// reconciles — never serving-while-quarantined).
#[allow(clippy::too_many_arguments)]
pub fn apply_revalidation(
    store: &mut dyn RabsMetadataStore,
    authority: &TypedDigest,
    action_key_str: &str,
    action_key_typed: &TypedDigest,
    expected_revision: u64,
    attempt: u128,
    generation: u128,
    published_signature: &str,
    revalidated_signature: &str,
    committed_manifest_key: &str,
    candidate_manifest_key: &str,
    candidate_evidence_key: &str,
    now_unix_micros: i64,
    now_epoch: u64,
    ttl_micros: Option<u64>,
) -> Result<RevalidationVerdict, RevalidationError> {
    let record = store
        .serving_record(action_key_str)
        .map_err(|e| RevalidationError::Store(format!("{e:?}")))?
        .ok_or(RevalidationError::NoServingRecord)?;
    if record.state_revision != expected_revision {
        return Err(RevalidationError::StaleRevision {
            stored: record.state_revision,
        });
    }
    let new_revision = expected_revision + 1;
    let ttl = ttl_micros.unwrap_or(DEFAULT_REVALIDATION_TTL_MICROS);
    let validity = ServingValidity {
        evaluated_at_unix_micros: now_unix_micros,
        maximum_age_micros: Some(ttl),
        clock_uncertainty_micros: 0,
        coordinator_clock_epoch: now_epoch,
    };

    if published_signature == revalidated_signature {
        // Byte-identical reproduction: append evidence, renew serving.
        store
            .record_verification_sample(action_key_typed, attempt, true, new_revision)
            .map_err(|e| RevalidationError::Store(format!("{e:?}")))?;
        store
            .put_serving_record(
                authority,
                action_key_str,
                SERVABLE_DISPOSITION,
                new_revision,
                &validity,
                &[],
            )
            .map_err(|e| RevalidationError::Store(format!("{e:?}")))?;
        Ok(RevalidationVerdict::IdenticalEvidenceAppended { new_revision })
    } else {
        // Success-or-different-failure under the same key is a
        // SOUNDNESS INCIDENT: record it, then suppress serving.
        let seq = new_revision;
        store
            .record_divergence_incident(
                authority,
                &DivergenceIncidentRow {
                    action_key: action_key_str.to_owned(),
                    seq,
                    class: "soundness".to_owned(),
                    committed_manifest_key: committed_manifest_key.to_owned(),
                    candidate_manifest_key: candidate_manifest_key.to_owned(),
                    candidate_evidence_key: candidate_evidence_key.to_owned(),
                    candidate_pin_hex: String::new(),
                    generation_hex: format!("{generation:x}"),
                    attempt_hex: format!("{attempt:x}"),
                    detail: format!(
                        "revalidation diverged: published {published_signature}, \
                         revalidated {revalidated_signature}"
                    ),
                },
            )
            .map_err(|e| RevalidationError::Store(format!("{e:?}")))?;
        store
            .add_quarantine(
                QuarantineScope::ActionEntry,
                action_key_str,
                "k007-soundness-incident",
            )
            .map_err(|e| RevalidationError::Store(format!("{e:?}")))?;
        store
            .put_serving_record(
                authority,
                action_key_str,
                "quarantined",
                new_revision,
                &validity,
                &[(QuarantineScope::ActionEntry, action_key_str.to_owned())],
            )
            .map_err(|e| RevalidationError::Store(format!("{e:?}")))?;
        Ok(RevalidationVerdict::SoundnessIncidentQuarantined {
            incident_seq: seq,
            new_revision,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata_store::{
        ActionEntryRow, AuthorityRow, CommitOutcome, FsqliteEngine, PublicationRow,
        QuarantineScope, ResultKindTag, RusqliteEngine, SqlMetadataStore, digest_key,
    };
    use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};
    use std::sync::atomic::{AtomicU64, Ordering};

    static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn fresh_path(tag: &str) -> std::path::PathBuf {
        let n = DB_COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!("rabs-h040-{}-{}-{}.db", std::process::id(), tag, n))
    }

    fn digest(domain: &'static str, tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain,
            bytes: [tag; 32],
        }
    }

    fn authority_row(tag: u8) -> AuthorityRow {
        AuthorityRow {
            digest: digest("rabs.authority.sha256.v1", tag),
            cluster_id: "cluster-a".to_owned(),
            incarnation: u128::from(tag),
            term: u64::from(tag),
            acquired_seq: 1,
        }
    }

    fn validity(
        evaluated_at: i64,
        max_age: Option<u64>,
        uncertainty: u64,
        epoch: u64,
    ) -> ServingValidity {
        ServingValidity {
            evaluated_at_unix_micros: evaluated_at,
            maximum_age_micros: max_age,
            clock_uncertainty_micros: uncertainty,
            coordinator_clock_epoch: epoch,
        }
    }

    /// Publish action 7 and return (active authority, action key string).
    fn published_fixture(store: &mut dyn RabsMetadataStore) -> (TypedDigest, String) {
        store.acquire_authority(&authority_row(1)).unwrap();
        let active = digest("rabs.authority.sha256.v1", 1);
        let action = ActionEntryRow {
            action_key: digest("rabs.action-key.sha256.v1", 7),
            key_epoch: 0,
            projection_epoch: 0,
        };
        store.upsert_action_entry(&action).unwrap();
        store
            .create_generation(&active, 10, &action.action_key)
            .unwrap();
        store.record_attempt(20, 10, "worker-a", 5).unwrap();
        let row = PublicationRow {
            action_key: action.action_key.clone(),
            descriptor_digest: digest("rabs.descriptor.sha256.v1", 1),
            manifest_digest: digest("rabs.result-manifest.sha256.v1", 1),
            evidence_digest: digest("rabs.evidence-bundle.sha256.v1", 1),
            winner_generation: 10,
            winner_attempt: 20,
            result_kind: ResultKindTag::Success,
            pin_id: 40,
            pin_owner: "coordinator".to_owned(),
            provisional_ancestors: Vec::new(),
        };
        assert_eq!(
            store.commit_publication(&active, &row).unwrap(),
            CommitOutcome::Committed
        );
        (active, digest_key(&action.action_key))
    }

    /// T048, run identically on any backend; returns the final snapshot
    /// for differential comparison.
    fn t048_scenarios(store: &mut dyn RabsMetadataStore) -> Vec<String> {
        let (active, action_key) = published_fixture(store);

        // The commit wrote a legacy revision-0 'servable' row; the gate
        // treats it as servable with an unbounded validity window.
        let legacy = store.serving_record(&action_key).unwrap().unwrap();
        assert_eq!(legacy.state_revision, 0);
        assert_eq!(legacy.disposition, "servable");
        assert_eq!(
            serving_gate(store, &action_key, 1_000, 0).unwrap(),
            ServeDecision::Servable
        );
        assert_eq!(
            serving_gate(store, "missing:key", 1_000, 0).unwrap(),
            ServeDecision::NoRecord
        );

        // H040 record with a TTL: revision 1 supersedes the legacy row.
        store
            .put_serving_record(
                &active,
                &action_key,
                "servable",
                1,
                &validity(1_000, Some(500), 100, 1),
                &[],
            )
            .unwrap();
        let record = store.serving_record(&action_key).unwrap().unwrap();
        assert_eq!(record.state_revision, 1);
        assert_eq!(record.authority_key, digest_key(&active));

        // T048/TTL: inside the bound serve; age + uncertainty crossing
        // the bound denies CONSERVATIVELY (naive age alone would pass).
        assert_eq!(
            serving_gate(store, &action_key, 1_300, 1).unwrap(),
            ServeDecision::Servable
        );
        assert_eq!(
            serving_gate(store, &action_key, 1_450, 1).unwrap(),
            ServeDecision::ExpiredTtl
        );

        // T048/rollback: the wall clock running backward denies; a clock
        // epoch discontinuity denies regardless of the time value.
        assert_eq!(
            serving_gate(store, &action_key, 900, 1).unwrap(),
            ServeDecision::ExpiredClockRollback
        );
        assert_eq!(
            serving_gate(store, &action_key, 1_300, 2).unwrap(),
            ServeDecision::ExpiredClockEpoch
        );

        // T048/stale-revision replay: equal and lower revisions are
        // typed refusals and the stored record is untouched; revision 0
        // can never be written through this path.
        assert_eq!(
            store.put_serving_record(
                &active,
                &action_key,
                "servable",
                1,
                &validity(2_000, None, 0, 1),
                &[],
            ),
            Err(StoreError::StaleServingRevision)
        );
        assert_eq!(
            store.put_serving_record(
                &active,
                &action_key,
                "servable",
                0,
                &validity(2_000, None, 0, 1),
                &[],
            ),
            Err(StoreError::StaleServingRevision)
        );
        assert_eq!(
            store.serving_record(&action_key).unwrap().unwrap(),
            record,
            "refused replays must not move the stored record"
        );

        // Authority binding: a non-active authority cannot write.
        let wrong = digest("rabs.authority.sha256.v1", 2);
        assert_eq!(
            store.put_serving_record(
                &wrong,
                &action_key,
                "servable",
                2,
                &validity(2_000, None, 0, 1),
                &[],
            ),
            Err(StoreError::NotActiveAuthority)
        );

        // T048/quarantine references: a dangling reference is refused;
        // after the quarantine row exists the record lands and the gate
        // reports the NAMED references (never a reason string).
        let reference = (QuarantineScope::ActionEntry, action_key.clone());
        assert_eq!(
            store.put_serving_record(
                &active,
                &action_key,
                "servable",
                2,
                &validity(2_000, None, 0, 1),
                std::slice::from_ref(&reference),
            ),
            Err(StoreError::UnknownQuarantineReference)
        );
        store
            .add_quarantine(
                QuarantineScope::ActionEntry,
                &action_key,
                "divergent recompute",
            )
            .unwrap();
        store
            .put_serving_record(
                &active,
                &action_key,
                "servable",
                2,
                &validity(2_000, None, 0, 1),
                std::slice::from_ref(&reference),
            )
            .unwrap();
        assert_eq!(
            serving_gate(store, &action_key, 2_100, 1).unwrap(),
            ServeDecision::Blocked {
                references: vec![("action-entry".to_owned(), action_key.clone())],
            }
        );

        // T048/recovery: after the repair is processed the coordinator
        // writes the NEXT revision without the reference — serving
        // returns; the junction set is replaced atomically.
        store
            .put_serving_record(
                &active,
                &action_key,
                "servable",
                3,
                &validity(3_000, None, 0, 1),
                &[],
            )
            .unwrap();
        assert_eq!(
            serving_gate(store, &action_key, 3_100, 1).unwrap(),
            ServeDecision::Servable
        );
        assert!(
            store
                .serving_record(&action_key)
                .unwrap()
                .unwrap()
                .blocking
                .is_empty()
        );

        // A non-servable disposition gates before validity.
        store
            .put_serving_record(
                &active,
                &action_key,
                "evidence-pending",
                4,
                &validity(3_000, None, 0, 1),
                &[],
            )
            .unwrap();
        assert_eq!(
            serving_gate(store, &action_key, 3_100, 1).unwrap(),
            ServeDecision::NotServable {
                disposition: "evidence-pending".to_owned(),
            }
        );

        // Legacy disposition-only writers must NOT reset the revision:
        // the H040 columns survive a set_serving_disposition_key.
        store
            .set_serving_disposition_key(&action_key, "servable")
            .unwrap();
        let after = store.serving_record(&action_key).unwrap().unwrap();
        assert_eq!(
            after.state_revision, 4,
            "disposition-only write reset the revision — replay protection lost"
        );
        assert_eq!(after.disposition, "servable");

        store.differential_snapshot().unwrap()
    }

    #[test]
    fn t048_reference_backend() {
        let engine = RusqliteEngine::open_in_memory().unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        t048_scenarios(&mut store);
    }

    #[test]
    fn t048_differential_reference_vs_frankensqlite() {
        let reference_engine = RusqliteEngine::open(&fresh_path("ref")).unwrap();
        let mut reference = SqlMetadataStore::open(reference_engine).unwrap();
        let candidate_engine = FsqliteEngine::open(&fresh_path("fsq")).unwrap();
        let mut candidate = SqlMetadataStore::open(candidate_engine).unwrap();
        assert_eq!(
            t048_scenarios(&mut reference),
            t048_scenarios(&mut candidate)
        );
    }

    #[test]
    fn h040_record_survives_reopen() {
        // The validity window and revision are DURABLE: reopening the
        // store changes nothing about the conservative verdicts.
        let path = fresh_path("reopen");
        let action_key;
        {
            let engine = RusqliteEngine::open(&path).unwrap();
            let mut store = SqlMetadataStore::open(engine).unwrap();
            let (active, key) = published_fixture(&mut store);
            action_key = key;
            store
                .put_serving_record(
                    &active,
                    &action_key,
                    "servable",
                    5,
                    &validity(1_000, Some(500), 100, 3),
                    &[],
                )
                .unwrap();
        }
        let engine = RusqliteEngine::open(&path).unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        assert_eq!(
            serving_gate(&mut store, &action_key, 1_200, 3).unwrap(),
            ServeDecision::Servable
        );
        assert_eq!(
            serving_gate(&mut store, &action_key, 1_450, 3).unwrap(),
            ServeDecision::ExpiredTtl
        );
        assert_eq!(
            serving_gate(&mut store, &action_key, 1_200, 4).unwrap(),
            ServeDecision::ExpiredClockEpoch
        );
        // Replay protection also survives the reopen.
        store.acquire_authority(&authority_row(1)).unwrap();
        let active = digest("rabs.authority.sha256.v1", 1);
        assert_eq!(
            store.put_serving_record(
                &active,
                &action_key,
                "servable",
                5,
                &validity(2_000, None, 0, 3),
                &[],
            ),
            Err(StoreError::StaleServingRevision)
        );
    }

    // -------------------------------------------------------------------
    // K007: R28-class publication fixtures + served-failure TTL /
    // revalidation lifecycle.
    // -------------------------------------------------------------------

    /// Every R28-class terminal outcome refuses publication with its
    /// named class (OOM/signals NEVER publish); exit 0 is not a
    /// failure; a plain nonzero exit with every gate open is admitted;
    /// each closed gate yields its typed refusal in bead-check order.
    #[test]
    fn k007_r28_class_never_publishes() {
        let r28 = [
            (TerminalOutcome::Oom, "oom"),
            (TerminalOutcome::Signal(9), "signal"),
            (TerminalOutcome::Signal(137), "signal"),
            (TerminalOutcome::Cancelled, "cancelled"),
            (TerminalOutcome::Timeout, "timeout"),
            (TerminalOutcome::WorkerLost, "worker-loss"),
            (TerminalOutcome::TransportFailed, "transport-failure"),
            (TerminalOutcome::Panicked, "panic"),
        ];
        for (outcome, class) in r28 {
            assert_eq!(
                classify_deterministic_failure(outcome, true, true, true, true, true),
                Err(FailureRefusal::NotDeterministic(class)),
                "{class} must never publish as a deterministic failure"
            );
        }
        assert_eq!(
            classify_deterministic_failure(TerminalOutcome::Exit(0), true, true, true, true, true),
            Err(FailureRefusal::ZeroExitIsNotAFailure),
        );
        assert_eq!(
            classify_deterministic_failure(
                TerminalOutcome::Exit(101),
                true,
                true,
                true,
                true,
                true
            ),
            Ok(FailureAdmission {
                normalized_exit: 101
            }),
        );
        // The first closed gate wins, in bead-check order.
        assert_eq!(
            classify_deterministic_failure(
                TerminalOutcome::Exit(1),
                false,
                false,
                false,
                false,
                false
            ),
            Err(FailureRefusal::CaptureIncomplete),
        );
        assert_eq!(
            classify_deterministic_failure(
                TerminalOutcome::Exit(1),
                true,
                false,
                false,
                false,
                false
            ),
            Err(FailureRefusal::InputsNotClosed),
        );
        assert_eq!(
            classify_deterministic_failure(
                TerminalOutcome::Exit(1),
                true,
                true,
                false,
                false,
                false
            ),
            Err(FailureRefusal::UndeclaredSideEffects),
        );
        assert_eq!(
            classify_deterministic_failure(
                TerminalOutcome::Exit(1),
                true,
                true,
                true,
                false,
                false
            ),
            Err(FailureRefusal::ClassPolicyRefused),
        );
        assert_eq!(
            classify_deterministic_failure(TerminalOutcome::Exit(1), true, true, true, true, false),
            Err(FailureRefusal::TrustPolicyRefused),
        );
    }

    /// Served-failure lifecycle: short-TTL serving, expiry suppression,
    /// stale-revision refusal, byte-identical revalidation appending
    /// evidence and renewing the window, divergent revalidation
    /// quarantining the action as a soundness incident. Run identically
    /// on any backend; returns the final snapshot for differential
    /// comparison.
    fn k007_lifecycle_scenarios(store: &mut dyn RabsMetadataStore) -> Vec<String> {
        let (active, action_key) = published_fixture(store);
        let action_typed = digest("rabs.action-key.sha256.v1", 7);

        // Revalidation without a serving record is a typed refusal.
        assert_eq!(
            apply_revalidation(
                store,
                &active,
                "missing:key",
                &digest("rabs.action-key.sha256.v1", 99),
                1,
                21,
                10,
                "exit=1|diag=d1",
                "exit=1|diag=d1",
                "manifest-a",
                "manifest-a",
                "ev-a",
                1_000,
                1,
                None,
            ),
            Err(RevalidationError::NoServingRecord)
        );

        // The admitted failure serves under the SHORT default TTL.
        store
            .put_serving_record(
                &active,
                &action_key,
                "servable",
                1,
                &validity(1_000_000, Some(DEFAULT_REVALIDATION_TTL_MICROS), 0, 1),
                &[],
            )
            .unwrap();
        assert_eq!(
            serving_gate(
                store,
                &action_key,
                1_000_000 + i64::try_from(DEFAULT_REVALIDATION_TTL_MICROS / 2).unwrap(),
                1,
            )
            .unwrap(),
            ServeDecision::Servable
        );
        // Expiry suppresses serving (re-execution gets scheduled).
        assert_eq!(
            serving_gate(
                store,
                &action_key,
                1_000_000 + i64::try_from(DEFAULT_REVALIDATION_TTL_MICROS + 1).unwrap(),
                1,
            )
            .unwrap(),
            ServeDecision::ExpiredTtl
        );

        // A wrong expected revision never clobbers stored state.
        assert_eq!(
            apply_revalidation(
                store,
                &active,
                &action_key,
                &action_typed,
                7,
                21,
                10,
                "exit=1|diag=d1",
                "exit=1|diag=d1",
                "manifest-a",
                "manifest-a",
                "ev-a",
                1_040_000,
                1,
                None,
            ),
            Err(RevalidationError::StaleRevision { stored: 1 })
        );

        // Byte-identical reproduction APPENDS evidence and renews the
        // window at the next revision.
        assert_eq!(
            apply_revalidation(
                store,
                &active,
                &action_key,
                &action_typed,
                1,
                21,
                10,
                "exit=1|diag=d1",
                "exit=1|diag=d1",
                "manifest-a",
                "manifest-a",
                "ev-a",
                1_040_000,
                1,
                None,
            ),
            Ok(RevalidationVerdict::IdenticalEvidenceAppended { new_revision: 2 })
        );
        assert_eq!(
            store
                .serving_record(&action_key)
                .unwrap()
                .unwrap()
                .state_revision,
            2
        );
        // Renewed from 1_040_000 under the default TTL.
        assert_eq!(
            serving_gate(
                store,
                &action_key,
                1_040_000 + i64::try_from(DEFAULT_REVALIDATION_TTL_MICROS / 2).unwrap(),
                1,
            )
            .unwrap(),
            ServeDecision::Servable
        );
        assert_eq!(
            serving_gate(
                store,
                &action_key,
                1_040_000 + i64::try_from(DEFAULT_REVALIDATION_TTL_MICROS + 1).unwrap(),
                1,
            )
            .unwrap(),
            ServeDecision::ExpiredTtl
        );

        // Success under the same key is a SOUNDNESS INCIDENT: recorded,
        // quarantined, serving suppressed.
        assert_eq!(
            apply_revalidation(
                store,
                &active,
                &action_key,
                &action_typed,
                2,
                22,
                11,
                "exit=1|diag=d1",
                "success",
                "manifest-a",
                "manifest-b",
                "ev-b",
                1_060_000,
                1,
                None,
            ),
            Ok(RevalidationVerdict::SoundnessIncidentQuarantined {
                incident_seq: 3,
                new_revision: 3,
            })
        );
        let incidents = store.list_divergence_incidents(&action_key).unwrap();
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].class, "soundness");
        assert_eq!(incidents[0].seq, 3);
        let record = store.serving_record(&action_key).unwrap().unwrap();
        assert_eq!(record.disposition, "quarantined");
        assert_eq!(
            record.blocking,
            vec![("action-entry".to_owned(), action_key.clone())]
        );
        assert_eq!(
            serving_gate(store, &action_key, 1_060_000, 1).unwrap(),
            ServeDecision::NotServable {
                disposition: "quarantined".to_owned(),
            }
        );

        store.differential_snapshot().unwrap()
    }

    #[test]
    fn k007_failure_ttl_lifecycle_reference_backend() {
        let engine = RusqliteEngine::open_in_memory().unwrap();
        let mut store = SqlMetadataStore::open(engine).unwrap();
        k007_lifecycle_scenarios(&mut store);
    }

    #[test]
    fn k007_failure_ttl_lifecycle_differential_reference_vs_frankensqlite() {
        let reference_engine = RusqliteEngine::open(&fresh_path("k007ref")).unwrap();
        let mut reference = SqlMetadataStore::open(reference_engine).unwrap();
        let candidate_engine = FsqliteEngine::open(&fresh_path("k007fsq")).unwrap();
        let mut candidate = SqlMetadataStore::open(candidate_engine).unwrap();
        assert_eq!(
            k007_lifecycle_scenarios(&mut reference),
            k007_lifecycle_scenarios(&mut candidate)
        );
    }
}
