//! Authority-scoped pin leases, grace, and fail-toward-retention
//! (bead H041; plan §63; risk R127).
//!
//! Pin validity is judged ONLY in coordinator sequence space — there is
//! no API through which a worker's wall clock can participate, so "pin
//! expiry never depends on a worker comparing wall clocks with
//! coordinator timestamps" holds by construction.
//!
//! - RELEASE is authority-scoped and idempotent: a worker may release
//!   only its own non-publication pins; an `action-publication` pin can
//!   be released by NO worker under any identity claim, and by a
//!   coordinator only while presenting the ACTIVE authority;
//! - RENEWAL is strictly monotonic per pin (H010's `renew_pin`); a
//!   renewal naming a different pin cannot touch this one —
//!   contradictory leases are inert, not merged;
//! - EXPIRY fails toward RETENTION: an expired-looking pin keeps
//!   protecting until reconciliation has confirmed the expiry AND a
//!   grace window has elapsed past it. Restart, partition, or clock
//!   uncertainty therefore never turns "unresolved" into "deleted".

use crate::metadata_store::{RabsMetadataStore, StoreError};
use rabs_protocol::result_identity::TypedDigest;

use crate::publication::authority_digest;
use rabs_protocol::authority::CoordinatorAuthority;

/// Pin class that only an active-authority coordinator may release.
pub const PUBLICATION_PIN_CLASS: &str = "action-publication";

/// Who is asking for a pin release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Releaser {
    /// A coordinator presenting its FULL authority value.
    Coordinator(CoordinatorAuthority),
    /// A worker identity (owner string it claims).
    Worker(String),
}

/// Outcome of an authority-scoped release request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseOutcome {
    /// Pin released.
    Released,
    /// Pin was already released: idempotent no-op.
    AlreadyReleased,
    /// No such pin.
    UnknownPin,
    /// A worker attempted to release a publication root — forbidden for
    /// every worker identity (R127).
    RefusedWorkerOnPublicationRoot,
    /// A worker attempted to release a pin it does not own.
    RefusedNotOwner,
    /// A coordinator attempted a release without the active authority.
    RefusedNotActiveAuthority,
}

/// Release a pin under authority scoping (H041). Idempotent: releasing
/// a released pin reports [`ReleaseOutcome::AlreadyReleased`] and
/// changes nothing.
///
/// # Errors
/// Store errors from the underlying reads/writes.
pub fn release_pin_scoped(
    store: &mut dyn RabsMetadataStore,
    pin_id: u128,
    releaser: &Releaser,
) -> Result<ReleaseOutcome, StoreError> {
    let Some(row) = store.pin_row(pin_id)? else {
        return Ok(ReleaseOutcome::UnknownPin);
    };
    if row.released {
        return Ok(ReleaseOutcome::AlreadyReleased);
    }
    match releaser {
        Releaser::Worker(worker_owner) => {
            if row.class == PUBLICATION_PIN_CLASS {
                // No worker identity claim releases a publication root.
                return Ok(ReleaseOutcome::RefusedWorkerOnPublicationRoot);
            }
            if row.owner != *worker_owner {
                return Ok(ReleaseOutcome::RefusedNotOwner);
            }
            store.release_pin(pin_id, worker_owner)?;
            Ok(ReleaseOutcome::Released)
        }
        Releaser::Coordinator(authority) => {
            let presented: TypedDigest = authority_digest(authority);
            match store.active_authority()? {
                Some(active) if active.digest == presented => {
                    store.release_pin(pin_id, &row.owner)?;
                    Ok(ReleaseOutcome::Released)
                }
                _ => Ok(ReleaseOutcome::RefusedNotActiveAuthority),
            }
        }
    }
}

/// Protection state of a pin under the fail-toward-retention rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinProtection {
    /// Unexpired (or unexpiring) and unreleased: protecting.
    Protecting,
    /// Expired by sequence, but reconciliation has not confirmed it or
    /// the grace window has not elapsed: STILL protecting.
    GraceProtecting,
    /// Released, or expiry confirmed by reconciliation with grace
    /// elapsed: no longer protecting.
    Expired,
}

/// Judge one pin's protection at `now_seq`. `reconciliation_confirmed`
/// is whether a startup/periodic reconciliation pass has run since the
/// pin last looked expired; `grace_windows` is the additional sequence
/// margin past expiry.
///
/// The asymmetry IS the specification: every uncertain branch lands on
/// a protecting variant (restart, partition, missing reconciliation,
/// in-grace), and only released or confirmed-and-grace-elapsed pins
/// stop protecting.
///
/// # Errors
/// Store errors from the pin lookup; an unknown pin is `Ok(None)`.
pub fn pin_protection(
    store: &mut dyn RabsMetadataStore,
    pin_id: u128,
    now_seq: u64,
    reconciliation_confirmed: bool,
    grace_windows: u64,
) -> Result<Option<PinProtection>, StoreError> {
    let Some(row) = store.pin_row(pin_id)? else {
        return Ok(None);
    };
    if row.released {
        return Ok(Some(PinProtection::Expired));
    }
    let Some(expires_at_seq) = row.expires_at_seq else {
        return Ok(Some(PinProtection::Protecting));
    };
    if now_seq <= expires_at_seq {
        return Ok(Some(PinProtection::Protecting));
    }
    // Expired-looking. Fail toward retention.
    if !reconciliation_confirmed {
        return Ok(Some(PinProtection::GraceProtecting));
    }
    if now_seq <= expires_at_seq.saturating_add(grace_windows) {
        return Ok(Some(PinProtection::GraceProtecting));
    }
    Ok(Some(PinProtection::Expired))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata_store::{
        AuthorityRow, FsqliteEngine, RusqliteEngine, SqlEngine, SqlMetadataStore, StoreError,
    };
    use rabs_protocol::authority::{ClusterId, CoordinatorIncarnationId};
    use rabs_protocol::result_identity::DigestAlgorithm;
    use std::sync::atomic::{AtomicU64, Ordering};

    static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn fresh_path(tag: &str) -> std::path::PathBuf {
        let n = DB_COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!("rabs-h041-{}-{}-{}.db", std::process::id(), tag, n))
    }

    fn digest(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.object.sha256.v1",
            bytes: [tag; 32],
        }
    }

    fn authority(term: u64) -> CoordinatorAuthority {
        CoordinatorAuthority {
            cluster_id: ClusterId("c".to_owned()),
            credential_generation: 1,
            term,
            incarnation_id: CoordinatorIncarnationId(9),
        }
    }

    /// Store with an active authority, a publication-root pin (1), a
    /// worker-owned materialization pin (2), and an expiring pin (3).
    fn install<E: SqlEngine>(store: &mut SqlMetadataStore<E>) {
        store
            .acquire_authority(&AuthorityRow {
                digest: authority_digest(&authority(3)),
                cluster_id: "c".to_owned(),
                incarnation: 9,
                term: 3,
                acquired_seq: 1,
            })
            .unwrap();
        store
            .create_pin(
                1,
                &digest(1),
                "coordinator",
                PUBLICATION_PIN_CLASS,
                None,
                None,
                true,
                "publication root",
            )
            .unwrap();
        store
            .create_pin(
                2,
                &digest(2),
                "worker-a",
                "materialization",
                None,
                None,
                false,
                "worker hold",
            )
            .unwrap();
        store
            .create_pin(
                3,
                &digest(3),
                "worker-a",
                "transfer",
                Some(100),
                None,
                false,
                "expiring hold",
            )
            .unwrap();
    }

    #[test]
    fn h041_worker_can_never_release_a_publication_root() {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        install(&mut store);
        // Even a worker CLAIMING the coordinator's owner string.
        for claimed in ["worker-a", "coordinator"] {
            assert_eq!(
                release_pin_scoped(&mut store, 1, &Releaser::Worker(claimed.to_owned())).unwrap(),
                ReleaseOutcome::RefusedWorkerOnPublicationRoot
            );
        }
        assert!(!store.pin_row(1).unwrap().unwrap().released);
    }

    #[test]
    fn h041_release_is_authority_scoped_and_idempotent() {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        install(&mut store);

        // Non-active authority (stale term) refused.
        assert_eq!(
            release_pin_scoped(&mut store, 1, &Releaser::Coordinator(authority(2))).unwrap(),
            ReleaseOutcome::RefusedNotActiveAuthority
        );
        // Active authority releases the publication root.
        assert_eq!(
            release_pin_scoped(&mut store, 1, &Releaser::Coordinator(authority(3))).unwrap(),
            ReleaseOutcome::Released
        );
        // Duplicate release: idempotent, typed.
        assert_eq!(
            release_pin_scoped(&mut store, 1, &Releaser::Coordinator(authority(3))).unwrap(),
            ReleaseOutcome::AlreadyReleased
        );

        // Worker releases its own pin; a different worker cannot.
        assert_eq!(
            release_pin_scoped(&mut store, 2, &Releaser::Worker("worker-b".to_owned())).unwrap(),
            ReleaseOutcome::RefusedNotOwner
        );
        assert_eq!(
            release_pin_scoped(&mut store, 2, &Releaser::Worker("worker-a".to_owned())).unwrap(),
            ReleaseOutcome::Released
        );
        assert_eq!(
            release_pin_scoped(&mut store, 2, &Releaser::Worker("worker-a".to_owned())).unwrap(),
            ReleaseOutcome::AlreadyReleased
        );
        assert_eq!(
            release_pin_scoped(&mut store, 99, &Releaser::Worker("worker-a".to_owned())).unwrap(),
            ReleaseOutcome::UnknownPin
        );
    }

    #[test]
    fn h041_expiry_fails_toward_retention_through_grace() {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        install(&mut store);
        let judge = |store: &mut SqlMetadataStore<RusqliteEngine>,
                     now: u64,
                     confirmed: bool|
         -> PinProtection {
            pin_protection(store, 3, now, confirmed, 10)
                .unwrap()
                .unwrap()
        };
        // Before expiry: protecting.
        assert_eq!(judge(&mut store, 100, true), PinProtection::Protecting);
        // Expired but NOT reconciliation-confirmed (restart/partition/
        // clock uncertainty): still protecting, indefinitely.
        assert_eq!(
            judge(&mut store, 101, false),
            PinProtection::GraceProtecting
        );
        assert_eq!(
            judge(&mut store, 10_000, false),
            PinProtection::GraceProtecting
        );
        // Confirmed but within grace: still protecting.
        assert_eq!(judge(&mut store, 110, true), PinProtection::GraceProtecting);
        // Confirmed and grace elapsed: expired.
        assert_eq!(judge(&mut store, 111, true), PinProtection::Expired);
        // Unexpiring pin never expires; released pin never protects.
        assert_eq!(
            pin_protection(&mut store, 2, u64::MAX, true, 0)
                .unwrap()
                .unwrap(),
            PinProtection::Protecting
        );
        release_pin_scoped(&mut store, 2, &Releaser::Worker("worker-a".to_owned())).unwrap();
        assert_eq!(
            pin_protection(&mut store, 2, 0, false, 0).unwrap().unwrap(),
            PinProtection::Expired
        );
        assert_eq!(pin_protection(&mut store, 99, 0, false, 0).unwrap(), None);
    }

    #[test]
    fn h041_contradictory_lease_renewals_are_inert() {
        let mut store = SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap();
        install(&mut store);
        store.renew_pin(3, 5).unwrap();
        // A stale sequence and a wrong pin id both refuse without
        // touching pin 3's lease.
        assert_eq!(
            store.renew_pin(3, 5),
            Err(StoreError::NonMonotonicPinRenewal)
        );
        assert_eq!(store.renew_pin(98, 6), Err(StoreError::UnknownPin));
        assert_eq!(store.pin_row(3).unwrap().unwrap().renewal_seq, 5);
    }

    #[test]
    fn h041_unresolved_pin_survives_restart() {
        let path = fresh_path("restart");
        {
            let mut store = SqlMetadataStore::open(RusqliteEngine::open(&path).unwrap()).unwrap();
            install(&mut store);
        }
        // Restart: fresh process, no reconciliation yet. The
        // expired-looking pin still protects.
        let mut store = SqlMetadataStore::open(RusqliteEngine::open(&path).unwrap()).unwrap();
        assert_eq!(
            pin_protection(&mut store, 3, 10_000, false, 10)
                .unwrap()
                .unwrap(),
            PinProtection::GraceProtecting
        );
    }

    #[test]
    fn h041_differential_reference_vs_frankensqlite() {
        fn scenario<E: SqlEngine>(store: &mut SqlMetadataStore<E>) -> Vec<String> {
            install(store);
            assert_eq!(
                release_pin_scoped(store, 1, &Releaser::Worker("worker-a".to_owned())).unwrap(),
                ReleaseOutcome::RefusedWorkerOnPublicationRoot
            );
            assert_eq!(
                release_pin_scoped(store, 2, &Releaser::Worker("worker-a".to_owned())).unwrap(),
                ReleaseOutcome::Released
            );
            assert_eq!(
                release_pin_scoped(store, 1, &Releaser::Coordinator(authority(3))).unwrap(),
                ReleaseOutcome::Released
            );
            store.differential_snapshot().unwrap()
        }
        let mut reference =
            SqlMetadataStore::open(RusqliteEngine::open(&fresh_path("ref41")).unwrap()).unwrap();
        let mut candidate =
            SqlMetadataStore::open(FsqliteEngine::open(&fresh_path("fsq41")).unwrap()).unwrap();
        assert_eq!(scenario(&mut reference), scenario(&mut candidate));
    }
}
