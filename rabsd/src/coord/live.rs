//! The live coordinator state (bead S6 / bridge plan Phase S): the
//! first live mounts of the D024 [`TargetLeaseRegistry`], the D031
//! [`DestinationArbiter`], and a singleflight table keyed by the Epic F
//! action key. One binary, structural authority split (plan §10): the
//! edge routes every consult through THIS state in-process, and the
//! coord region owns its lifecycle.
//!
//! ## Shadow-tier singleflight window
//!
//! Production singleflight closes a flight when the action COMPLETES.
//! In shadow tier nothing completes through us — the wrapper execs the
//! compiler and its connection closes (fds are CLOEXEC). The flight
//! window is therefore CONNECTION-SCOPED: begin at consult, end when
//! the connection drops. Two overlapping consults for one key yield
//! exactly one leader and N followers, observable and receipted. (This
//! is also the design direction: a serving wrapper will hold its
//! connection through the compile, making the window the real one.)
//!
//! ## Degraded mode
//!
//! If the coord region is down (lab-injected today, crashed tomorrow),
//! edge consults DO NOT fail: they answer in the typed
//! `shadow-coord-degraded` mode — fail-open extends to the authority
//! split itself, and the shutdown receipt shows the coord region
//! abandoned so nothing hides.

use crate::coord::target_lease::TargetLeaseRegistry;
use crate::edge::destination_arbiter::DestinationArbiter;
use crate::janitor::store::LiveCas;
use rabs_cas::metadata_store::{AuthorityRow, RabsMetadataStore, StoreError, digest_key};
use rabs_cas::publication::{
    AUTHORITY_DIGEST_DOMAIN, CommitDurabilityProfile, OfferPreparedActionResult, OfferRefusal,
    PublicationOutcome, authority_digest, process_offer,
};
use rabs_protocol::authority::{ClusterId, CoordinatorAuthority, CoordinatorIncarnationId};
use rabs_protocol::result_identity::{CanonicalActionResultManifest, TypedDigest};
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// The role a consult played in its key's flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlightRole {
    /// First open flight for the key.
    Leader,
    /// Joined while the leader's flight is still open.
    Follower,
    /// Coord unavailable: no flight accounting (typed, never silent).
    Degraded,
}

impl FlightRole {
    /// Receipt/report label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Leader => "leader",
            Self::Follower => "follower",
            Self::Degraded => "degraded",
        }
    }
}

/// Why a commit did not happen. Every variant is a REFUSAL: nothing was
/// written, and no result may be served on its account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitRefusal {
    /// No store is mounted (the janitor mount failed at boot). The
    /// daemon still runs — builds fall back locally — but it commits
    /// nothing.
    NoStore,
    /// The coordinator has not acquired its authority (coord region
    /// down, or authority acquisition failed at boot).
    NoAuthority,
    /// The store mutex was poisoned by a panic in another commit.
    StoreUnavailable,
    /// The publication engine refused the offer (typed A018/H011 fence).
    Offer(OfferRefusal),
    /// A store error surfaced outside `process_offer`.
    Store(String),
}

impl std::fmt::Display for CommitRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoStore => write!(f, "no rabs-cas store mounted"),
            Self::NoAuthority => write!(f, "coordinator holds no active authority"),
            Self::StoreUnavailable => write!(f, "store lock poisoned"),
            Self::Offer(refusal) => write!(f, "offer refused: {refusal:?}"),
            Self::Store(error) => write!(f, "store error: {error}"),
        }
    }
}

/// The live coordinator state shared edge↔coord in-process.
#[derive(Default)]
pub struct CoordLive {
    available: AtomicBool,
    leases: Mutex<TargetLeaseRegistry>,
    arbiter: Mutex<DestinationArbiter>,
    flights: Mutex<HashMap<String, u64>>,
    /// The durable store, shared with the janitor region that mounted it.
    /// `None` when the mount failed: the daemon runs, but the coordinator
    /// refuses every commit rather than pretending to have one.
    cas: Option<std::sync::Arc<LiveCas>>,
    /// The authority acquired at coord boot; `None` until then.
    authority: Mutex<Option<CoordinatorAuthority>>,
    /// Canonical manifests this coordinator has admitted this
    /// incarnation, by manifest digest key. `process_offer` needs the
    /// COMMITTED manifest to classify a same-key candidate (A018); after
    /// a restart this cache is empty, so a divergent offer against a
    /// pre-restart commit is refused (`CommittedManifestUnavailable`)
    /// rather than mis-classified. Durable manifest reload from the CAS
    /// bytes is the next slice.
    manifests: Mutex<HashMap<String, CanonicalActionResultManifest>>,
    /// High half of every pin id this incarnation allocates: pin ids must
    /// not collide with pins written by a previous boot, and the store has
    /// no id allocator. Seeded from the boot instant.
    boot_nonce: u64,
    /// Low half of the pin id (monotone within the incarnation).
    next_pin: AtomicU64,
    /// Causal sequence for publications/incidents. Seeded from the boot
    /// instant so it stays monotone across restarts (append-only incident
    /// rows are keyed by (action, seq); a reused seq with different
    /// content is a typed store refusal, never a silent patch).
    next_seq: AtomicU64,
}

impl std::fmt::Debug for CoordLive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoordLive")
            .field("available", &self.available())
            .field("cas_mounted", &self.cas.is_some())
            .field(
                "authority_held",
                &self.authority.lock().is_ok_and(|a| a.is_some()),
            )
            .finish_non_exhaustive()
    }
}

/// Microseconds since the Unix epoch, or 0 if the clock is before it.
/// Used only to seed monotone-across-restart counters.
fn boot_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
}

impl CoordLive {
    /// New, with no store (unavailable until the coord region marks
    /// itself up). Commits refuse with [`CommitRefusal::NoStore`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            boot_nonce: boot_micros(),
            next_seq: AtomicU64::new(boot_micros()),
            ..Self::default()
        }
    }

    /// New, sharing the store the janitor region mounted.
    #[must_use]
    pub fn with_cas(cas: std::sync::Arc<LiveCas>) -> Self {
        Self {
            cas: Some(cas),
            ..Self::new()
        }
    }

    /// Acquire this incarnation's coordinator authority in the durable
    /// store — the fence `process_offer` checks first (an offer whose
    /// authority does not digest to the ACTIVE row is refused as
    /// `NotActiveAuthority`, so before this ran the daemon could not
    /// commit anything at all).
    ///
    /// Boot semantics (plan §10.8, V1): fresh incarnation every start and
    /// a durably advanced term. A row left behind by a previous boot of
    /// THIS store belongs to a dead incarnation — we hold the store's
    /// exclusive mount, which is the local fence — so it is released and
    /// superseded at `term + 1`. A row from a different cluster is NOT
    /// superseded: that is a misconfiguration, and it refuses loudly.
    /// Cross-host election is M6.
    ///
    /// # Errors
    /// A string reason if no store is mounted or the store refuses.
    pub fn acquire_boot_authority(&self, cluster_id: &str) -> Result<CoordinatorAuthority, String> {
        let cas = self.cas.as_ref().ok_or("no rabs-cas store mounted")?;
        let mut store = cas.store().lock().map_err(|_| "store lock poisoned")?;
        // A fresh incarnation has written nothing yet, so it must declare
        // the authority domain before it can read back the row a previous
        // boot left (R121 fail-closed domain restore).
        store.intern_domain(AUTHORITY_DIGEST_DOMAIN);
        let prior = store
            .active_authority()
            .map_err(|e| format!("active authority: {e:?}"))?;
        let term = match &prior {
            Some(row) if row.cluster_id != cluster_id => {
                return Err(format!(
                    "store is held by cluster {:?} but this coordinator claims {cluster_id:?} — \
                     refusing to supersede another cluster's authority",
                    row.cluster_id
                ));
            }
            Some(row) => {
                store
                    .release_authority(&row.digest)
                    .map_err(|e| format!("release prior authority: {e:?}"))?;
                row.term.saturating_add(1)
            }
            None => 1,
        };
        let authority = CoordinatorAuthority {
            cluster_id: ClusterId(cluster_id.to_owned()),
            // Credential rotation (S013) is not wired yet; generation 1
            // is this deployment's only credential generation so far.
            credential_generation: 1,
            term,
            incarnation_id: CoordinatorIncarnationId(u128::from(self.boot_nonce)),
        };
        let digest = authority_digest(&authority);
        store
            .acquire_authority(&AuthorityRow {
                digest,
                cluster_id: cluster_id.to_owned(),
                incarnation: u128::from(self.boot_nonce),
                term,
                acquired_seq: self.next_seq(),
            })
            .map_err(|e: StoreError| format!("acquire authority: {e:?}"))?;
        drop(store);
        *self
            .authority
            .lock()
            .map_err(|_| "authority lock poisoned")? = Some(authority.clone());
        Ok(authority)
    }

    /// The authority this incarnation holds, if it acquired one.
    #[must_use]
    pub fn authority(&self) -> Option<CoordinatorAuthority> {
        self.authority.lock().ok().and_then(|a| a.clone())
    }

    /// Commit a worker's prepared-result offer: the coordinator-only
    /// compare-and-set publication transaction (I8/I9/I10 — the worker
    /// offers, only this commits).
    ///
    /// The object BYTES are not this call's business: under
    /// [`CommitDurabilityProfile::RequireDurableClosure`] the engine
    /// refuses any offer whose closure is not already durably located, so
    /// an incomplete upload can never become a committed pointer.
    ///
    /// # Errors
    /// A typed [`CommitRefusal`]. Nothing is written on any of them.
    pub fn commit_offer(
        &self,
        offer: &OfferPreparedActionResult,
        expected_descriptor: &TypedDigest,
    ) -> Result<PublicationOutcome, CommitRefusal> {
        let cas = self.cas.as_ref().ok_or(CommitRefusal::NoStore)?;
        if self.authority().is_none() {
            return Err(CommitRefusal::NoAuthority);
        }
        // Remember the offered manifest BEFORE admission: if this one
        // commits it becomes the committed manifest a later same-key
        // candidate is classified against (A018).
        let mut manifests = self
            .manifests
            .lock()
            .map_err(|_| CommitRefusal::StoreUnavailable)?;
        manifests.insert(digest_key(&offer.manifest_id.0), offer.manifest.clone());
        let pin_id = self.next_pin_id();
        let seq = self.next_seq();
        let mut store = cas
            .store()
            .lock()
            .map_err(|_| CommitRefusal::StoreUnavailable)?;
        process_offer(
            &mut *store,
            offer,
            expected_descriptor,
            |key| manifests.get(key).cloned(),
            pin_id,
            seq,
            CommitDurabilityProfile::RequireDurableClosure,
        )
        .map_err(CommitRefusal::Offer)
    }

    /// Allocate a pin id unique to this incarnation.
    fn next_pin_id(&self) -> u128 {
        let low = self.next_pin.fetch_add(1, Ordering::Relaxed);
        (u128::from(self.boot_nonce) << 64) | u128::from(low)
    }

    /// Allocate the next causal sequence.
    fn next_seq(&self) -> u64 {
        self.next_seq.fetch_add(1, Ordering::Relaxed)
    }

    /// The coord region is up (called from coord work at boot).
    pub fn mark_up(&self) {
        self.available.store(true, Ordering::Release);
    }

    /// The coord region is down (shutdown or crash).
    pub fn mark_down(&self) {
        self.available.store(false, Ordering::Release);
    }

    /// Whether the authority split is live.
    #[must_use]
    pub fn available(&self) -> bool {
        self.available.load(Ordering::Acquire)
    }

    /// Begin a flight for `key` (connection-scoped window).
    #[must_use]
    pub fn begin_flight(&self, key: &str) -> FlightRole {
        if !self.available() {
            return FlightRole::Degraded;
        }
        let Ok(mut flights) = self.flights.lock() else {
            return FlightRole::Degraded;
        };
        let count = flights.entry(key.to_string()).or_insert(0);
        *count += 1;
        if *count == 1 {
            FlightRole::Leader
        } else {
            FlightRole::Follower
        }
    }

    /// End one flight participation for `key` (connection closed).
    pub fn end_flight(&self, key: &str) {
        if let Ok(mut flights) = self.flights.lock()
            && let Some(count) = flights.get_mut(key)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                flights.remove(key);
            }
        }
    }

    /// Coord status as one JSON line (`--coord-status` surface).
    #[must_use]
    pub fn status_json(&self) -> String {
        let open_flights = self.flights.lock().map(|f| f.len()).unwrap_or(0);
        let (lease_holders, reservations) = (
            // The registries expose no len today; report mount state —
            // the numbers arrive when Phase 1 gives them real traffic.
            self.leases.lock().is_ok(),
            self.arbiter.lock().is_ok(),
        );
        let authority = self.authority();
        format!(
            "{{\"v\":1,\"kind\":\"coord-status\",\"available\":{},\"open_flights\":{open_flights},\
             \"lease_registry_mounted\":{lease_holders},\"destination_arbiter_mounted\":{reservations},\
             \"cas_mounted\":{},\"authority_held\":{},\"authority_term\":{}}}",
            self.available(),
            self.cas.is_some(),
            authority.is_some(),
            authority.map_or(0, |a| a.term),
        )
    }

    /// Exclusive access to the lease registry (Phase 1 serving path).
    pub fn leases(&self) -> &Mutex<TargetLeaseRegistry> {
        &self.leases
    }

    /// Exclusive access to the destination arbiter (Phase 1 path).
    pub fn arbiter(&self) -> &Mutex<DestinationArbiter> {
        &self.arbiter
    }
}

/// The cluster this coordinator claims (`RABS_CLUSTER_ID`, default
/// `local`). One store may only ever be held by one cluster's authority.
#[must_use]
pub fn cluster_id() -> String {
    std::env::var("RABS_CLUSTER_ID").unwrap_or_else(|_| "local".to_owned())
}

/// Build the coord region work: mark the authority split live, acquire
/// this incarnation's coordinator authority in the durable store, hold
/// until shutdown.
///
/// Authority acquisition is fail-closed on its own terms and fail-open for
/// the daemon: if it fails, the region logs the typed reason and stays up
/// WITHOUT authority, so consults still answer and builds still run — but
/// [`CoordLive::commit_offer`] refuses every commit
/// ([`CommitRefusal::NoAuthority`]) instead of publishing under an
/// authority nobody granted.
pub fn coord_work(
    coord: std::sync::Arc<CoordLive>,
) -> rabs_asupersync::daemon_runtime::SubsystemWork {
    Box::new(move |cx, mut shutdown| {
        Box::pin(async move {
            if std::env::var("RABS_LAB_COORD_DOWN").is_ok() {
                // Lab fault injection: the coord region dies at boot;
                // edge consults must survive in degraded mode and the
                // receipt must show this region abandoned.
                return Err("lab: coord region down (RABS_LAB_COORD_DOWN)".to_string());
            }
            coord.mark_up();
            match coord.acquire_boot_authority(&cluster_id()) {
                Ok(authority) => println!(
                    "{{\"v\":1,\"kind\":\"coord-authority-acquired\",\"cluster_id\":\"{}\",\
                     \"credential_generation\":{},\"term\":{},\"incarnation\":\"{}\",\
                     \"digest\":\"{}\"}}",
                    authority.cluster_id.0,
                    authority.credential_generation,
                    authority.term,
                    authority.incarnation_id.0,
                    digest_key(&authority_digest(&authority)),
                ),
                Err(reason) => println!(
                    "{{\"v\":1,\"kind\":\"coord-authority-refused\",\"reason\":\"{}\"}}",
                    reason.replace('"', "'")
                ),
            }
            cx.trace("coord region up: leases + arbiter + singleflight mounted");
            shutdown.wait().await;
            coord.mark_down();
            Ok(())
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlapping_flights_one_leader_then_followers() {
        let coord = CoordLive::new();
        coord.mark_up();
        assert_eq!(coord.begin_flight("k1"), FlightRole::Leader);
        assert_eq!(coord.begin_flight("k1"), FlightRole::Follower);
        assert_eq!(coord.begin_flight("k1"), FlightRole::Follower);
        // A different key gets its own leader.
        assert_eq!(coord.begin_flight("k2"), FlightRole::Leader);
        // Window closes only when every participant ends.
        coord.end_flight("k1");
        coord.end_flight("k1");
        assert_eq!(
            coord.begin_flight("k1"),
            FlightRole::Follower,
            "leader still open"
        );
        coord.end_flight("k1");
        coord.end_flight("k1");
        assert_eq!(
            coord.begin_flight("k1"),
            FlightRole::Leader,
            "window closed"
        );
    }

    #[test]
    fn degraded_mode_is_typed_never_silent() {
        let coord = CoordLive::new(); // never marked up
        assert_eq!(coord.begin_flight("k"), FlightRole::Degraded);
        coord.mark_up();
        assert_eq!(coord.begin_flight("k"), FlightRole::Leader);
        coord.mark_down();
        assert_eq!(coord.begin_flight("k"), FlightRole::Degraded);
    }

    #[test]
    fn status_reports_mounts_and_open_flights() {
        let coord = CoordLive::new();
        coord.mark_up();
        let _ = coord.begin_flight("k1");
        let status = coord.status_json();
        assert!(status.contains("\"available\":true"), "{status}");
        assert!(status.contains("\"open_flights\":1"), "{status}");
        assert!(
            status.contains("\"lease_registry_mounted\":true"),
            "{status}"
        );
        assert!(
            status.contains("\"destination_arbiter_mounted\":true"),
            "{status}"
        );
    }
}
