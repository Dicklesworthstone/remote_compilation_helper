//! Durable identity and incarnation admission for pinned operator sessions.
//!
//! The existing coordinator store owns both the exclusive process lock and S022
//! fence. A stable operator worker name selects the local store; its first
//! authenticated key binding is durable. Changing a configured pin cannot start
//! another boot-generation history for the same name. This narrow capability
//! exposes no action submission, execution lease, or publication operation.

use super::{hex, invalid, require};
use crate::coord::live::CoordLive;
use crate::janitor::store::{LiveCas, mount_and_reconcile};
use rabs_cas::metadata_store::{RabsMetadataStore, SqlValue};
use rabs_protocol::generation::{WorkerBootGeneration, WorkerIncarnationId};
use rabs_protocol::identity_store::TransportIdentity;
use rabs_protocol::wire_time::PeerId;
use rabs_protocol::worker_fence::WorkerSessionOffer;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io;
use std::path::{Component, Path};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const PIN_BINDING: &str = "rabs-pinned-worker-key-v1";
const REQUEST_ALLOCATION: &str = "rabs-pinned-worker-request-id-v1";
const REQUEST_ALLOCATION_REASON: &str = "reserved before constructing immutable dependency request";

/// Exclusive, persistent admission for one locally named, TLS-pinned worker.
/// Concurrent operator processes targeting the same worker refuse while its
/// owner is live. Different workers have independent admission stores. This
/// capability is not cloneable: a public delivery entrypoint consumes it, so
/// two live transports cannot share one owner's admission state.
pub struct PinnedWorkerAdmission {
    coord: CoordLive,
    cas: Arc<LiveCas>,
    worker: String,
    pin: [u8; 32],
}

impl PinnedWorkerAdmission {
    /// Open the durable admission history before listening for a new session.
    /// A new name is bound only after the expected key completes authentication;
    /// failed TLS or challenge exchanges cannot poison a first enrollment.
    pub fn open(state: &Path, worker: &str, pin: [u8; 32]) -> io::Result<Self> {
        require(
            state.is_absolute()
                && state
                    .components()
                    .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
            "worker admission state root must be absolute without traversal",
        )?;
        require(
            !worker.is_empty() && worker.len() <= 1024 && !worker.chars().any(char::is_control),
            "worker admission requires a bounded nonempty worker name",
        )?;
        require(
            pin != [0; 32],
            "worker admission requires a nonzero SPKI pin",
        )?;
        // Names select local expectations, never transport authority. Hash the
        // exact bytes so labels cannot introduce filesystem paths or aliases.
        let namespace = hex(&Sha256::digest(worker.as_bytes()));
        let root = state.join("worker-admission").join(&namespace);
        let cas = Arc::new(mount_and_reconcile(&root).map_err(invalid)?);
        require(
            !cas.serving_refused,
            "worker admission store reconciliation refused",
        )?;
        {
            let mut store = cas
                .store()
                .lock()
                .map_err(|_| invalid("worker admission lock poisoned"))?;
            check_pin(&mut *store, worker, pin)?;
        }
        let coord = CoordLive::with_cas(Arc::clone(&cas));
        coord
            .acquire_boot_authority(&format!("pinned-worker-admission-v1:{namespace}"))
            .map_err(invalid)?;
        Ok(Self {
            coord,
            cas,
            worker: worker.to_owned(),
            pin,
        })
    }

    /// Reserve an ID for explicitly requested new work on a blocking lane.
    /// The receipt is committed and synced before the caller constructs its
    /// immutable request. Retain THIS admission owner through preparation and
    /// pass it into authenticated delivery: releasing and reopening it could
    /// let a later request overtake this one at the worker's high-water fence.
    /// A failed preparation burns its ID. Allocation grants no execution rights.
    ///
    /// This allocator owns a dedicated worker journal. A manually dispatched
    /// future ID on that worker remains a pre-dispatch high-water refusal; an
    /// already saved request is never rewritten from a peer's hello.
    ///
    /// # Errors
    /// Invalid/exhausted allocation history or unavailable durable storage.
    pub fn allocate_request_id(&self) -> io::Result<u64> {
        let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        let floor = u64::try_from(elapsed.as_nanos())
            .map_err(|_| invalid("worker request clock seed exceeds u64"))?;
        self.allocate_request_id_at(floor)
    }

    fn allocate_request_id_at(&self, floor: u64) -> io::Result<u64> {
        let mut store = self.cas.store().lock()
            .map_err(|_| invalid("worker request allocation lock poisoned"))?;
        // The normal store uses SQLite's durable defaults. Refuse a store
        // configured to acknowledge commits without crash-safe journaling.
        let synchronous = store.query("PRAGMA synchronous", &[])
            .map_err(|error| invalid(format!("read worker request durability: {error:?}")))?;
        require(
            matches!(synchronous.as_slice(), [row] if matches!(row.as_slice(), [SqlValue::Int(2 | 3)])),
            "worker request allocation requires durable SQLite synchronization",
        )?;
        let journal = store.query("PRAGMA journal_mode", &[])
            .map_err(|error| invalid(format!("read worker request journal: {error:?}")))?;
        require(
            matches!(journal.as_slice(), [row] if matches!(row.as_slice(),
                [SqlValue::Text(mode)] if matches!(mode.as_str(), "delete" | "truncate" | "persist" | "wal"))),
            "worker request allocation requires a crash-safe SQLite journal",
        )?;
        let rows = store.query(
            "SELECT seq, decision, reason FROM decision_receipts WHERE kind = ?1 AND subject = ?2 ORDER BY seq DESC LIMIT 1",
            &[SqlValue::Text(REQUEST_ALLOCATION.to_owned()), SqlValue::Text(self.worker.clone())],
        ).map_err(|error| invalid(format!("read worker request allocation: {error:?}")))?;
        let (sequence, previous) = match rows.as_slice() {
            [] => (0, 0),
            [row] => {
                let [SqlValue::Int(sequence), SqlValue::Text(value), SqlValue::Text(reason)] = row.as_slice() else {
                    return Err(invalid("invalid worker request allocation receipt"));
                };
                require(
                    *sequence >= 0
                        && value.len() == 16
                        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                        && reason == REQUEST_ALLOCATION_REASON,
                    "invalid worker request allocation receipt",
                )?;
                let previous = u64::from_str_radix(value, 16)
                    .map_err(|_| invalid("invalid worker request allocation value"))?;
                require(previous > 0, "zero worker request allocation")?;
                let sequence = sequence.checked_add(1)
                    .ok_or_else(|| invalid("worker request allocation sequence exhausted"))?;
                (u64::try_from(sequence)
                    .map_err(|_| invalid("invalid worker request allocation sequence"))?, previous)
            }
            _ => return Err(invalid("ambiguous worker request allocation history")),
        };
        let next = previous.checked_add(1)
            .ok_or_else(|| invalid("worker request ID exhausted"))?
            .max(floor);
        store.record_decision_receipt(
            REQUEST_ALLOCATION,
            &self.worker,
            sequence,
            &format!("{next:016x}"),
            REQUEST_ALLOCATION_REASON,
        ).map_err(|error| invalid(format!("persist worker request allocation: {error:?}")))?;
        // Hold the metadata guard and exclusive mount ownership through fsync.
        // Burn an ID on any later error; never hand out an unsynced reservation.
        File::open(self.cas.cas_root().join("meta.sqlite"))?.sync_all()?;
        match File::open(self.cas.cas_root().join("meta.sqlite-wal")) {
            Ok(wal) => wal.sync_all()?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        // The first allocation may have created several state directories.
        // Persist the complete entry chain, including after a previous failed
        // first-allocation fsync, before any request using the ID can escape.
        for directory in self.cas.cas_root().ancestors() {
            File::open(directory)?.sync_all()?;
        }
        Ok(next)
    }

    pub(super) fn pin(&self) -> [u8; 32] {
        self.pin
    }

    pub(super) fn worker(&self) -> &str {
        &self.worker
    }

    /// Called only after the TLS-pinned session challenge succeeds, and before
    /// a grant, source upload, or execution write is sent to the worker.
    pub(super) fn admit(
        self: &Arc<Self>,
        identity: &TransportIdentity,
        hello: &Value,
    ) -> io::Result<AdmittedWorkerSession> {
        require(
            identity.peer_id == self.pin && identity.fingerprint == self.pin,
            "worker admission differs from authenticated SPKI identity",
        )?;
        require(
            hello.get("worker_id").and_then(Value::as_str) == Some(self.worker.as_str()),
            "worker admission differs from the selected worker name",
        )?;
        let generation = hello
            .get("boot_generation")
            .and_then(Value::as_u64)
            .filter(|generation| *generation > 0)
            .ok_or_else(|| invalid("invalid worker boot generation"))?;
        let incarnation = hello
            .get("incarnation")
            .and_then(Value::as_str)
            .filter(|value| {
                value.len() == 32
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .and_then(|value| u128::from_str_radix(value, 16).ok())
            .filter(|value| *value != 0)
            .ok_or_else(|| invalid("invalid worker incarnation"))?;
        // No wire claim supplies an operator signature or resets history.
        require(
            hello.get("reenrollment_proof").is_none(),
            "worker-supplied re-enrollment proof is not authorized",
        )?;
        {
            let mut store = self
                .cas
                .store()
                .lock()
                .map_err(|_| invalid("worker admission lock poisoned"))?;
            if !check_pin(&mut *store, &self.worker, self.pin)? {
                store
                    .record_decision_receipt(
                        PIN_BINDING,
                        &self.worker,
                        0,
                        &hex(&self.pin),
                        "operator-selected SPKI authenticated before persistent worker admission",
                    )
                    .map_err(|error| invalid(format!("persist worker pin: {error:?}")))?;
            }
        }
        let offer = WorkerSessionOffer {
            worker_peer_id: PeerId(hex(&self.pin)),
            boot_generation: WorkerBootGeneration(generation),
            incarnation: WorkerIncarnationId(incarnation),
            reenrollment_proof: None,
        };
        let (outcome, started) = self.coord.admit_worker_session(&offer).map_err(invalid)?;
        let started = started
            .ok_or_else(|| invalid(format!("durable worker session refused: {outcome:?}")))?;
        Ok(AdmittedWorkerSession {
            admission: Arc::clone(self),
            offer,
            started,
        })
    }
}

/// A successful admission owns exactly one durable session row. Dropping a
/// transport releases that row without clearing another connection's ownership
/// or lowering boot high-water/clone ambiguity. A killed process retains its
/// unclosed row, which is deliberately conservative on a later reconnect.
pub(super) struct AdmittedWorkerSession {
    admission: Arc<PinnedWorkerAdmission>,
    offer: WorkerSessionOffer,
    started: u64,
}

impl AdmittedWorkerSession {
    /// Evidence for a caller's independent live coordinator admission. This
    /// offer has already passed TLS pin, challenge and durable boot fencing.
    pub(super) fn offer(&self) -> &WorkerSessionOffer {
        &self.offer
    }
}

impl Drop for AdmittedWorkerSession {
    fn drop(&mut self) {
        if let Err(error) = self.admission.coord.release_worker_session(
            &self.offer.worker_peer_id,
            self.offer.incarnation,
            self.started,
        ) {
            eprintln!(
                "{}",
                serde_json::json!({"kind":"worker-session-release-error",
                "worker":self.admission.worker, "detail":error, "reexecute":false})
            );
        }
    }
}

fn check_pin(store: &mut dyn RabsMetadataStore, worker: &str, pin: [u8; 32]) -> io::Result<bool> {
    let rows = store
        .query(
            "SELECT decision FROM decision_receipts WHERE kind = ?1 AND subject = ?2 AND seq = 0",
            &[
                SqlValue::Text(PIN_BINDING.to_owned()),
                SqlValue::Text(worker.to_owned()),
            ],
        )
        .map_err(|error| invalid(format!("read worker pin binding: {error:?}")))?;
    match rows.as_slice() {
        [] => Ok(false),
        [row] if row.as_slice() == [SqlValue::Text(hex(&pin))] => Ok(true),
        [_] => Err(invalid(
            "worker name already bound to another SPKI pin; explicit operator re-enrollment is required",
        )),
        _ => Err(invalid("invalid durable worker pin binding")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn identity() -> TransportIdentity {
        TransportIdentity {
            peer_id: [1; 32],
            fingerprint: [1; 32],
        }
    }

    fn hello(generation: u64, incarnation: u128) -> Value {
        json!({"worker_id":"worker", "boot_generation":generation,
            "incarnation":format!("{incarnation:032x}")})
    }

    fn open(root: &Path, worker: &str, pin: [u8; 32]) -> io::Result<Arc<PinnedWorkerAdmission>> {
        PinnedWorkerAdmission::open(root, worker, pin).map(Arc::new)
    }

    #[test]
    fn request_ids_are_durable_monotonic_and_ignore_clock_rollback() {
        let root = tempfile::tempdir().unwrap();
        let admission = open(root.path(), "worker", [1; 32]).unwrap();
        assert_eq!(admission.allocate_request_id_at(500).unwrap(), 500);
        assert_eq!(admission.allocate_request_id_at(400).unwrap(), 501);
        assert_eq!(admission.allocate_request_id_at(900).unwrap(), 900);
        drop(admission);

        let reopened = open(root.path(), "worker", [1; 32]).unwrap();
        assert_eq!(reopened.allocate_request_id_at(0).unwrap(), 901);
        let rows = reopened.cas.store().lock().unwrap().query(
            "SELECT seq, decision FROM decision_receipts WHERE kind = ?1 AND subject = ?2 ORDER BY seq",
            &[SqlValue::Text(REQUEST_ALLOCATION.to_owned()), SqlValue::Text("worker".into())],
        ).unwrap();
        assert_eq!(rows, vec![
            vec![SqlValue::Int(0), SqlValue::Text("00000000000001f4".into())],
            vec![SqlValue::Int(1), SqlValue::Text("00000000000001f5".into())],
            vec![SqlValue::Int(2), SqlValue::Text("0000000000000384".into())],
            vec![SqlValue::Int(3), SqlValue::Text("0000000000000385".into())],
        ]);
    }

    #[test]
    fn request_allocator_exhaustion_cannot_wrap_or_reset_on_reopen() {
        let root = tempfile::tempdir().unwrap();
        let admission = open(root.path(), "worker", [1; 32]).unwrap();
        assert_eq!(admission.allocate_request_id_at(u64::MAX).unwrap(), u64::MAX);
        assert!(admission.allocate_request_id_at(0).unwrap_err().to_string().contains("ID exhausted"));
        drop(admission);
        let reopened = open(root.path(), "worker", [1; 32]).unwrap();
        assert!(reopened.allocate_request_id_at(0).unwrap_err().to_string().contains("ID exhausted"));

        let other = open(root.path(), "sequence-exhausted", [2; 32]).unwrap();
        other.cas.store().lock().unwrap().record_decision_receipt(
            REQUEST_ALLOCATION, "sequence-exhausted", i64::MAX as u64,
            "0000000000000001", REQUEST_ALLOCATION_REASON,
        ).unwrap();
        assert!(other.allocate_request_id_at(0).unwrap_err().to_string().contains("sequence exhausted"));
    }

    #[test]
    fn corrupt_request_allocation_receipts_refuse_instead_of_starting_over() {
        for (value, reason) in [
            ("", REQUEST_ALLOCATION_REASON),
            ("000000000000001", REQUEST_ALLOCATION_REASON),
            ("GGGGGGGGGGGGGGGG", REQUEST_ALLOCATION_REASON),
            ("000000000000000A", REQUEST_ALLOCATION_REASON),
            ("0000000000000000", REQUEST_ALLOCATION_REASON),
            ("0000000000000001", "different allocation protocol"),
        ] {
            let root = tempfile::tempdir().unwrap();
            let admission = open(root.path(), "worker", [1; 32]).unwrap();
            admission.cas.store().lock().unwrap().record_decision_receipt(
                REQUEST_ALLOCATION, "worker", 0, value, reason,
            ).unwrap();
            assert!(admission.allocate_request_id_at(10_000).is_err(), "{value:?}");
            drop(admission);
            let reopened = open(root.path(), "worker", [1; 32]).unwrap();
            assert!(reopened.allocate_request_id_at(20_000).is_err(), "{value:?}");
        }
    }

    #[test]
    fn request_allocators_share_worker_exclusion_and_keep_other_workers_independent() {
        let root = tempfile::tempdir().unwrap();
        let first = open(root.path(), "worker", [1; 32]).unwrap();
        assert_eq!(first.allocate_request_id_at(10).unwrap(), 10);
        assert!(open(root.path(), "worker", [1; 32]).is_err());
        let other = open(root.path(), "other-worker", [2; 32]).unwrap();
        assert_eq!(other.allocate_request_id_at(2).unwrap(), 2);
        drop(first);
        let reopened = open(root.path(), "worker", [1; 32]).unwrap();
        assert_eq!(reopened.allocate_request_id_at(1).unwrap(), 11);
        assert_eq!(other.allocate_request_id_at(1).unwrap(), 3);
    }

    #[test]
    fn worker_boot_high_water_survives_clean_receiver_restart() {
        let root = tempfile::tempdir().unwrap();
        let admission = open(root.path(), "worker", [1; 32]).unwrap();
        drop(admission.admit(&identity(), &hello(5, 1)).unwrap());
        drop(admission);

        let reopened = open(root.path(), "worker", [1; 32]).unwrap();
        let stale = reopened.admit(&identity(), &hello(4, 2)).err().unwrap();
        assert!(stale.to_string().contains("RejectStaleBootGeneration"));
        drop(reopened.admit(&identity(), &hello(6, 3)).unwrap());
        let fence = reopened
            .cas
            .store()
            .lock()
            .unwrap()
            .worker_incarnation_fence(&PeerId(hex(&[1; 32])))
            .unwrap()
            .unwrap();
        assert_eq!(fence.highest_boot_generation, WorkerBootGeneration(6));
        assert!(fence.active_incarnation.is_none());
    }

    #[test]
    fn clone_ambiguity_survives_reopen_and_rejects_claimed_reenrollment() {
        let root = tempfile::tempdir().unwrap();
        let admission = open(root.path(), "worker", [1; 32]).unwrap();
        let session = admission.admit(&identity(), &hello(5, 1)).unwrap();
        let clone = admission.admit(&identity(), &hello(5, 2)).err().unwrap();
        assert!(clone.to_string().contains("RejectCloneAmbiguity"));
        drop(session);
        drop(admission);

        let reopened = open(root.path(), "worker", [1; 32]).unwrap();
        for offered in [hello(5, 1), hello(5, 2), hello(6, 3)] {
            let refusal = reopened.admit(&identity(), &offered).err().unwrap();
            assert!(refusal.to_string().contains("RejectCloneAmbiguity"));
        }
        let mut forged = hello(6, 3);
        forged["reenrollment_proof"] = json!(u64::MAX);
        let refusal = reopened.admit(&identity(), &forged).err().unwrap();
        assert!(refusal.to_string().contains("not authorized"));
    }

    #[test]
    fn stable_name_pin_binding_cannot_be_changed_to_reset_worker_history() {
        let root = tempfile::tempdir().unwrap();
        let admission = open(root.path(), "worker", [1; 32]).unwrap();
        drop(admission.admit(&identity(), &hello(5, 1)).unwrap());
        drop(admission);
        let refused = open(root.path(), "worker", [2; 32]).err().unwrap();
        assert!(
            refused
                .to_string()
                .contains("already bound to another SPKI pin")
        );
        let original = open(root.path(), "worker", [1; 32]).unwrap();
        assert!(original.admit(&identity(), &hello(4, 3)).is_err());
    }

    #[test]
    fn unauthenticated_first_connection_cannot_pin_a_worker_name() {
        let root = tempfile::tempdir().unwrap();
        let admission = open(root.path(), "worker", [2; 32]).unwrap();
        assert!(admission.admit(&identity(), &hello(5, 1)).is_err());
        drop(admission);
        let corrected = open(root.path(), "worker", [1; 32]).unwrap();
        drop(corrected.admit(&identity(), &hello(5, 1)).unwrap());
    }

    #[test]
    fn local_lock_excludes_duplicate_receivers_but_not_other_workers() {
        let root = tempfile::tempdir().unwrap();
        let first = open(root.path(), "worker", [1; 32]).unwrap();
        assert!(open(root.path(), "worker", [1; 32]).is_err());
        let independent = open(root.path(), "other-worker", [2; 32]).unwrap();
        drop(independent);
        drop(first);
        assert!(open(root.path(), "worker", [1; 32]).is_ok());
    }

    #[test]
    fn releasing_an_older_session_does_not_clear_an_active_reconnect() {
        let root = tempfile::tempdir().unwrap();
        let admission = open(root.path(), "worker", [1; 32]).unwrap();
        let first = admission.admit(&identity(), &hello(5, 1)).unwrap();
        let second = admission.admit(&identity(), &hello(5, 1)).unwrap();
        drop(first);
        let fence = admission
            .cas
            .store()
            .lock()
            .unwrap()
            .worker_incarnation_fence(&PeerId(hex(&[1; 32])))
            .unwrap()
            .unwrap();
        assert_eq!(fence.active_incarnation, Some(WorkerIncarnationId(1)));
        drop(second);
        let fence = admission
            .cas
            .store()
            .lock()
            .unwrap()
            .worker_incarnation_fence(&PeerId(hex(&[1; 32])))
            .unwrap()
            .unwrap();
        assert!(fence.active_incarnation.is_none());
    }
}
