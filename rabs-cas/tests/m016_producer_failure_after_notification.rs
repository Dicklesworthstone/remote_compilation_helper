//! M016 end-to-end scenarios: producer failure AFTER Cargo already
//! consumed the metadata notification and dependents started (bead
//! rabs-root-4pidu.31.16; plan §88; runs with M019's journal).
//!
//! The nastiest ordering, exercised against the PUBLIC crate surface
//! exactly as the coordinator/wrapper layers would drive it:
//!
//! 1. producers open provisional pins; dependents resolve early
//!    metadata (`resolve_for_reader`) — the notification edge;
//! 2. a dependent INSTALLS an output to a real path before lineage
//!    closes (`provisional_recovery::record_installed_output`);
//! 3. THEN the producer lineage fails (M007 generation-failure trigger,
//!    or M017 divergent-winner adoption);
//! 4. ASSERT: every dependent is refused at its terminal gate, reads of
//!    invalidated pins refuse with the recorded reason, publication is
//!    impossible for cancelled lineages (M008 gate), the filesystem side
//!    recovers ownership-safely through the M019 journal, and a second
//!    sweep converges.

use std::path::PathBuf;

use rabs_cas::metadata_store::{RabsMetadataStore, RusqliteEngine, SqlMetadataStore};
use rabs_cas::provisional_pins::{
    AdoptionOutcome, OpenOutcome, ProducerContracts, ProvisionalIdentity, ProvisionalReader,
    TerminalGate, WinningAttemptContext, adopt_from_winning_attempt, authorize_reader,
    descendant_terminal_gate, invalidate_lineage_for_generation_failure, open_provisional_pin,
    provisional_causal_trace, resolve_for_reader,
};
use rabs_cas::provisional_recovery::{
    RecoverySummary, record_installed_output, recover_after_lineage_failure,
};
use rabs_protocol::authority::{ClusterId, CoordinatorAuthority};
use rabs_protocol::generation::{ActionGenerationId, AttemptId, ExecutionLeaseId};
use rabs_protocol::raw_bytes::RawBytes;
use rabs_protocol::result_identity::{DigestAlgorithm, ObjectId, OutputRole, TypedDigest};

fn action(tag: u8) -> TypedDigest {
    let mut bytes = [0u8; 32];
    bytes[0] = tag;
    bytes[31] = tag;
    TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain: "rabs.action-key.sha256.v1",
        bytes,
    }
}

fn obj(tag: u8) -> ObjectId {
    let mut d = action(tag);
    d.domain = "rabs.object.sha256.v1";
    ObjectId(d)
}

fn authority(tag: u64) -> CoordinatorAuthority {
    CoordinatorAuthority {
        cluster_id: ClusterId(format!("cluster-{tag}")),
        credential_generation: tag,
        term: 100 + tag,
        incarnation_id: rabs_protocol::authority::CoordinatorIncarnationId(
            0xAA00_0000_0000_0000 + u128::from(tag),
        ),
    }
}

/// One provisional plane: shared action/generation, distinct attempts.
fn identity(attempt_tag: u128) -> ProvisionalIdentity {
    ProvisionalIdentity {
        authority: authority(1),
        action_key: action(10),
        generation: ActionGenerationId(0x50),
        attempt: AttemptId(attempt_tag),
        lease: ExecutionLeaseId(attempt_tag + 1),
        role: OutputRole::ProvisionalMetadata,
        virtual_path: RawBytes::new(b"target/debug/deps/libfeat.rmeta".to_vec()),
    }
}

fn contracts() -> ProducerContracts {
    ProducerContracts {
        toolchain: action(200),
        events: action(201),
    }
}

fn dependent(worker: &str, attempt: u128) -> ProvisionalReader {
    ProvisionalReader::DependentAttempt {
        worker: worker.to_owned(),
        attempt: AttemptId(attempt),
    }
}

fn unique_tmp(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "m016-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A -> B chain WITH the nasty ordering fully realized: B consumed A's
/// metadata notification AND installed its own early output to disk
/// BEFORE any lineage closed.
struct FailedChain {
    store: SqlMetadataStore<RusqliteEngine>,
    a: ProvisionalIdentity,
    b: ProvisionalIdentity,
    b_output: PathBuf,
}

fn chain_with_dependent_install(tag: &str, bytes: &[u8]) -> FailedChain {
    let engine = RusqliteEngine::open_in_memory().unwrap();
    let mut store = SqlMetadataStore::open(engine).unwrap();
    let a = identity(30);
    let b = identity(31);

    // Notification edge: B resolves A's early metadata.
    open_provisional_pin(&mut store, &a, &obj(141), &contracts()).unwrap();
    assert_eq!(
        open_provisional_pin(&mut store, &a, &obj(141), &contracts()).unwrap(),
        OpenOutcome::AlreadyPinned
    );
    authorize_reader(&mut store, &a, &dependent("worker-b", 31)).unwrap();
    resolve_for_reader(&mut store, &a, &dependent("worker-b", 31)).unwrap();

    // B starts producing and installs ITS early output pre-closure.
    open_provisional_pin(&mut store, &b, &obj(142), &contracts()).unwrap();
    let dir = unique_tmp(tag);
    let b_output = dir.join("b-early.rmeta");
    std::fs::write(&b_output, bytes).unwrap();
    record_installed_output(
        &mut store,
        &b.pin_key(),
        "worker-b",
        AttemptId(31),
        &b_output,
        11,
    )
    .unwrap();

    FailedChain {
        store,
        a,
        b,
        b_output,
    }
}

#[test]
fn m016_generation_failure_after_notification_refuses_and_recovers() {
    let mut chain = chain_with_dependent_install("m016-genfail", b"early-output-bytes");

    // THE FAILURE: producer generation dies after the notification was
    // consumed and the dependent already installed output.
    let summary = invalidate_lineage_for_generation_failure(
        &mut chain.store,
        &action(10),
        ActionGenerationId(0x50),
        "producer generation tombstoned after worker loss",
    )
    .unwrap();
    assert_eq!(summary.pins_invalidated, 2);
    assert_eq!(summary.obligations_cancelled, 1);

    // Dependents CANNOT PUBLISH: terminal gate refuses permanently.
    assert!(matches!(
        descendant_terminal_gate(&mut chain.store, "worker-b", AttemptId(31)).unwrap(),
        TerminalGate::Refused { .. }
    ));

    // Reads of both invalidated pins refuse with the recorded reason.
    let err =
        resolve_for_reader(&mut chain.store, &chain.a, &dependent("worker-b", 31)).unwrap_err();
    let rabs_cas::provisional_pins::ProvisionalPinError::ProducerInvalidated { reason, .. } = err
    else {
        panic!("expected ProducerInvalidated, got {err:?}");
    };
    assert!(reason.contains("tombstoned"));

    // Ownership-safe target recovery through the M019 journal.
    let recovery = recover_after_lineage_failure(&mut chain.store, &[chain.a.pin_key()]).unwrap();
    assert_eq!(
        recovery,
        RecoverySummary {
            removed: 1,
            marked_dirty: 0
        }
    );
    assert!(!chain.b_output.exists());

    // The causal trace records the whole story for the incident report.
    let trace = provisional_causal_trace(&mut chain.store, &chain.a.pin_key()).unwrap();
    assert_eq!(trace.len(), 1);
    assert_eq!(trace[0].status, "cancelled");
}

#[test]
fn m016_divergent_winner_cancels_chain_and_preserves_user_edits() {
    let mut chain = chain_with_dependent_install("m016-diverge", b"installed-before-divergence");

    // USER state arrives between install and failure: the file gets
    // rewritten by someone else AFTER RABS recorded it.
    std::fs::write(&chain.b_output, b"user-took-over-this-file").unwrap();

    acquire_active(&mut chain.store, 5);
    let winner = WinningAttemptContext {
        authority: authority(5),
        action_key: chain.a.action_key.clone(),
        generation: ActionGenerationId(0x51),
        attempt: AttemptId(39),
        contracts: contracts(),
    };

    // Divergent object from a DIFFERENT winning attempt: cascade.
    assert_eq!(
        adopt_from_winning_attempt(&mut chain.store, &chain.a, &winner, &obj(199)).unwrap(),
        AdoptionOutcome::DivergenceCancelled {
            pins_invalidated: 2,
            obligations_cancelled: 1,
        }
    );
    // Ownership-safe recovery must NOT delete the user's file:
    // ownership cannot be proven, so the target goes dirty for
    // revalidation instead.
    let recovery = recover_after_lineage_failure(&mut chain.store, &[chain.a.pin_key()]).unwrap();
    assert_eq!(
        recovery,
        RecoverySummary {
            removed: 0,
            marked_dirty: 1
        }
    );
    assert!(chain.b_output.exists());
    assert_eq!(
        std::fs::read(&chain.b_output).unwrap(),
        b"user-took-over-this-file"
    );

    let dirty = chain
        .store
        .list_provisional_installs_by_state("dirty")
        .unwrap();
    assert_eq!(dirty.len(), 1);
}

#[test]
fn m016_second_recovery_sweep_converges_on_mixed_targets() {
    let mut chain = chain_with_dependent_install("m016-mixed", b"exact-match-bytes");

    // A SECOND dependent installs its own early output, which the user
    // then overwrites: one exact-match removal + one dirty preservation
    // in the SAME sweep, then convergence on the next sweep.
    let c = identity(32);
    open_provisional_pin(&mut chain.store, &c, &obj(143), &contracts()).unwrap();
    authorize_reader(&mut chain.store, &c, &dependent("worker-c", 33)).unwrap();
    resolve_for_reader(&mut chain.store, &c, &dependent("worker-c", 33)).unwrap();
    let c_output = unique_tmp("m016-mixed").join("c-early.rmeta");
    std::fs::write(&c_output, b"c-installed-bytes").unwrap();
    record_installed_output(
        &mut chain.store,
        &c.pin_key(),
        "worker-c",
        AttemptId(33),
        &c_output,
        12,
    )
    .unwrap();
    std::fs::write(&c_output, b"overwritten-after-install").unwrap();

    invalidate_lineage_for_generation_failure(
        &mut chain.store,
        &action(10),
        ActionGenerationId(0x50),
        "generation failed post-notification",
    )
    .unwrap();

    let roots = [chain.a.pin_key(), chain.b.pin_key(), c.pin_key()];
    let recovery = recover_after_lineage_failure(&mut chain.store, &roots).unwrap();
    assert_eq!(
        recovery,
        RecoverySummary {
            removed: 1,
            marked_dirty: 1
        }
    );
    assert!(!chain.b_output.exists());
    assert!(c_output.exists());

    // Convergence: the second sweep finds only durable terminal states.
    let again = recover_after_lineage_failure(&mut chain.store, &roots).unwrap();
    assert_eq!(again, RecoverySummary::default());
}

fn acquire_active(store: &mut SqlMetadataStore<RusqliteEngine>, tag: u64) {
    use rabs_cas::metadata_store::AuthorityRow;
    use rabs_cas::publication::authority_digest;
    store
        .acquire_authority(&AuthorityRow {
            digest: authority_digest(&authority(tag)),
            cluster_id: format!("cluster-{tag}"),
            incarnation: 0xCC + u128::from(tag),
            term: 100 + tag,
            acquired_seq: tag,
        })
        .unwrap();
}
