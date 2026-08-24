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
use crate::edge::destination_arbiter::{BundleId, DestinationArbiter};
use crate::janitor::store::LiveCas;
use rabs_cas::blob_store::RAW_PROFILE_V1;
use rabs_cas::digest_set::ATP_OBJECT_CONTENT_DOMAIN;
use rabs_cas::manifest_codec::decode_manifest_v1;
use rabs_cas::materialization::{decide_materialization, materialize_object};
use rabs_cas::metadata_store::{AuthorityRow, RabsMetadataStore, StoreError, digest_key};
use rabs_cas::publication::{
    AUTHORITY_DIGEST_DOMAIN, CommitDurabilityProfile, OBSERVABLE_PROJECTION_DOMAIN,
    OfferPreparedActionResult, OfferRefusal, PublicationOutcome, SEMANTIC_PROJECTION_DOMAIN,
    authority_digest, process_offer,
};
use rabs_cas::serving_state::{ServeDecision, serving_gate};
use rabs_key::logical_output_map::DOMAIN_ARTIFACT_BUNDLE_ROOT;
use rabs_key::typed_digest::{DOMAIN_ACTION_KEY, DOMAIN_DESCRIPTOR};
use rabs_protocol::authority::{ClusterId, CoordinatorAuthority, CoordinatorIncarnationId};
use rabs_protocol::generation::WorkerIncarnationId;
use rabs_protocol::result_identity::{
    CanonicalActionResultManifest, DigestAlgorithm, OutputRole, TypedDigest,
};
use rabs_protocol::wire_time::PeerId;
use rabs_protocol::worker_fence::{WorkerAdmission, WorkerSessionOffer};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
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
    /// The offer's CoordinatorAuthority does not match the authority this
    /// incarnation holds: it was prepared under a dead coordinator and can
    /// never publish here (G019; F033 digest equality).
    StaleAuthority {
        /// Term the offering attempt was created under.
        offered_term: u64,
        /// Term this coordinator holds.
        active_term: u64,
    },
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
            Self::StaleAuthority {
                offered_term,
                active_term,
            } => write!(
                f,
                "offer prepared under stale coordinator authority \
                 (offered term {offered_term}, active term {active_term})"
            ),
        }
    }
}

/// The answer to a serve request that is not a fault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeOutcome {
    /// Materialized; these files now exist (empty when the committed
    /// manifest declares no materializable output).
    Served {
        /// The destinations written, in manifest order.
        files: Vec<PathBuf>,
    },
    /// The serving gate said no. The typed decision is preserved —
    /// "quarantined" and "expired TTL" are not the same fact.
    NotServable(ServeDecision),
    /// Servable disposition, no publication row: a torn store, never a
    /// hit.
    NoCommit,
    /// The committed manifest's bytes could not be read back (missing
    /// or undecodable copy). Conservative: no hit, nothing written.
    ManifestUnavailable {
        /// The manifest object key that could not be loaded.
        key: String,
    },
    /// The committed result does not produce the output set the caller
    /// said its work would produce. NOT a hit: materializing it would
    /// leave the caller's build missing files it was promised, or
    /// carrying files it never asked for.
    OutputSetMismatch {
        /// Expected by the caller, absent from the commit.
        missing: Vec<String>,
        /// Present in the commit, not expected by the caller.
        unexpected: Vec<String>,
    },
}

/// What the caller says the work it is about to skip would produce.
///
/// A serve that lands a different set of files than the caller's own
/// work would have produced is the one failure mode a cache must never
/// have: a build silently missing (or gaining) a file. So the check is
/// opt-OUT and explicit — never satisfied by a caller that simply forgot
/// to state its expectation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpectedOutputs {
    /// The caller's derived output set (filenames relative to the
    /// destination root, e.g. from `rabs_key::output_derivation`). The
    /// committed manifest's materializable outputs must equal it
    /// exactly.
    Exactly(std::collections::BTreeSet<String>),
    /// The caller is not skipping any work and accepts whatever the
    /// commit declares: operator and diagnostic paths only. A wrapper
    /// must never use this.
    WhateverWasCommitted,
}

/// Why a serve could not even be attempted. Nothing is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeError {
    /// No store is mounted.
    NoStore,
    /// A lock was poisoned by a panic elsewhere.
    StoreUnavailable,
    /// The metadata store refused a lookup.
    Store(String),
    /// A manifest's virtual path would escape the destination root.
    /// Refused — a cache hit must never write outside the worktree it
    /// was asked to fill.
    UnsafeVirtualPath {
        /// The offending path, escaped for display.
        path: String,
    },
    /// Another bundle holds an overlapping destination (D031).
    DestinationConflict {
        /// The destination that overlapped.
        path: String,
        /// The bundle holding it.
        holder: String,
    },
    /// Materializing one output failed.
    Materialize {
        /// Which destination.
        path: String,
        /// The typed materialization failure.
        reason: String,
    },
}

impl std::fmt::Display for ServeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoStore => write!(f, "no rabs-cas store mounted"),
            Self::StoreUnavailable => write!(f, "store lock poisoned"),
            Self::Store(error) => write!(f, "store error: {error}"),
            Self::UnsafeVirtualPath { path } => {
                write!(f, "virtual path {path:?} escapes the destination root")
            }
            Self::DestinationConflict { path, holder } => {
                write!(f, "destination {path} is held by {holder}")
            }
            Self::Materialize { path, reason } => write!(f, "materializing {path}: {reason}"),
        }
    }
}

/// Join a manifest's virtual path under `root`, or `None` if it would
/// leave: absolute paths, any `..` or `.` component, empty paths, and
/// (on unix) embedded NULs are all refused. A served artifact writes
/// where the caller said, or nowhere.
fn resolve_destination(root: &Path, virtual_path: &[u8]) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    if virtual_path.is_empty() || virtual_path.contains(&0) || virtual_path[0] == b'/' {
        return None;
    }
    let mut out = root.to_path_buf();
    let mut components = 0_usize;
    for segment in virtual_path.split(|b| *b == b'/') {
        if segment.is_empty() || segment == b".." || segment == b"." {
            return None;
        }
        out.push(std::ffi::OsStr::from_bytes(segment));
        components += 1;
    }
    (components > 0).then_some(out)
}

/// Materialize every planned output, stopping at the first failure.
fn install_all(
    store: &mut dyn RabsMetadataStore,
    plan: &[(TypedDigest, PathBuf, String)],
) -> Result<Vec<PathBuf>, ServeError> {
    let mut written = Vec::with_capacity(plan.len());
    for (object, path, text) in plan {
        // The destination is a subscriber's mutable target tree, and no
        // reflink isolation has been verified here (nothing computes
        // that yet), so the policy resolves to a private copy.
        let mode = decide_materialization(true, false, false);
        materialize_object(store, object, path, mode).map_err(|e| ServeError::Materialize {
            path: text.clone(),
            reason: e.to_string(),
        })?;
        written.push(path.clone());
    }
    Ok(written)
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
    /// Generations closed by this incarnation's authority acquisition
    /// (G020/R120): every still-active generation minted under a PRIOR
    /// authority, tombstoned at boot so no prior-authority attempt can
    /// ever publish.
    closed_prior_generations: AtomicU64,
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
        declare_coordinator_domains(&mut *store);
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
                digest: digest.clone(),
                cluster_id: cluster_id.to_owned(),
                incarnation: u128::from(self.boot_nonce),
                term,
                acquired_seq: self.next_seq(),
            })
            .map_err(|e: StoreError| format!("acquire authority: {e:?}"))?;
        // G020/R120: this term supersedes every prior one. Durably close
        // all still-active generations minted under earlier authorities so
        // no prior-authority attempt can publish; publication-eligible
        // work reissues only in fresh generations minted (above the
        // never-reuse high-water mark) under THIS authority. Fail-closed:
        // if closure cannot be made durable, this incarnation refuses the
        // authority rather than running where R120 is unenforceable — the
        // acquired row is released and re-acquired at the next boot.
        let closed = store
            .close_generations_for_other_authorities(&digest)
            .map_err(|e: StoreError| format!("close prior-authority generations: {e:?}"))?;
        self.closed_prior_generations
            .store(closed, Ordering::Relaxed);
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

    /// How many prior-authority generations this incarnation's boot
    /// closed (G020); zero for the first boot over a fresh store.
    #[must_use]
    pub fn closed_prior_generations(&self) -> u64 {
        self.closed_prior_generations.load(Ordering::Relaxed)
    }

    /// Admit one worker connection through the durable S022 fence.
    /// The returned sequence exists only for admitted sessions and must
    /// be presented to [`Self::release_worker_session`]; rejections write
    /// neither the fence nor the session journal.
    ///
    /// # Errors
    /// A precise reason if the CAS, coordinator authority, lock, or
    /// metadata transaction is unavailable.
    pub fn admit_worker_session(
        &self,
        offer: &WorkerSessionOffer,
    ) -> Result<(WorkerAdmission, Option<u64>), String> {
        let cas = self.cas.as_ref().ok_or("no rabs-cas store mounted")?;
        let held = self.authority().ok_or("no coordinator authority")?;
        let started_seq = self.next_seq();
        let mut store = cas.store().lock().map_err(|_| "store lock poisoned")?;
        let admission = store
            .admit_worker_session(&authority_digest(&held), offer, started_seq)
            .map_err(|e| format!("worker session admission: {e:?}"))?;
        let admitted = matches!(
            admission,
            WorkerAdmission::AdmitNewGeneration
                | WorkerAdmission::AdmitReconnect
                | WorkerAdmission::AdmitResume
                | WorkerAdmission::AdmitViaReenrollment
        );
        Ok((admission, admitted.then_some(started_seq)))
    }

    /// End the exact worker session that owns the active incarnation.
    /// A stale connection cannot clear a newer session's fence.
    ///
    /// # Errors
    /// A precise reason if the CAS, coordinator authority, lock, or
    /// metadata transaction is unavailable.
    pub fn release_worker_session(
        &self,
        worker: &PeerId,
        incarnation: WorkerIncarnationId,
        started_seq: u64,
    ) -> Result<bool, String> {
        let cas = self.cas.as_ref().ok_or("no rabs-cas store mounted")?;
        let held = self.authority().ok_or("no coordinator authority")?;
        let ended_seq = self.next_seq();
        let mut store = cas.store().lock().map_err(|_| "store lock poisoned")?;
        store
            .release_worker_session(
                &authority_digest(&held),
                worker,
                incarnation,
                started_seq,
                ended_seq,
            )
            .map_err(|e| format!("worker session release: {e:?}"))
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
        let held = self.authority().ok_or(CommitRefusal::NoAuthority)?;
        // G019 offer-admission fence: refuse an offer prepared under any
        // OTHER authority BEFORE the store transaction opens — a dead
        // incarnation's attempts never publish here, independent of what
        // the durable active row or `process_offer` would later say.
        if authority_digest(&offer.authority.coordinator) != authority_digest(&held) {
            return Err(CommitRefusal::StaleAuthority {
                offered_term: offer.authority.coordinator.term,
                active_term: held.term,
            });
        }
        let pin_id = self.next_pin_id();
        let seq = self.next_seq();
        let mut store = cas
            .store()
            .lock()
            .map_err(|_| CommitRefusal::StoreUnavailable)?;

        // A018 classification needs the COMMITTED manifest for this key.
        // Resolve it up front, out of its CAS bytes: `process_offer`
        // borrows the store for the whole admission, so the resolver it
        // takes cannot itself touch the store — and the only key it ever
        // asks for is this one. Reading the bytes (rather than
        // remembering the manifest in process memory) is what makes
        // classification survive a restart.
        let committed_key = store
            .published_manifest_key(&offer.manifest.action_key)
            .map_err(|e| CommitRefusal::Store(format!("{e:?}")))?;
        let committed = match &committed_key {
            Some(key) => load_manifest(&mut *store, key),
            None => None,
        };
        let resolver = |key: &str| match (&committed_key, &committed) {
            (Some(committed_key), Some(manifest)) if committed_key == key => Some(manifest.clone()),
            _ => None,
        };

        process_offer(
            &mut *store,
            offer,
            expected_descriptor,
            resolver,
            pin_id,
            seq,
            CommitDurabilityProfile::RequireDurableClosure,
        )
        .map_err(CommitRefusal::Offer)
    }

    /// Serve a committed action into a live worktree: the first path in
    /// RABS by which a cache hit becomes files on disk.
    ///
    /// Order matters and is fail-closed at every step:
    ///
    /// 1. the H040 serving gate decides — anything but `Servable` (no
    ///    record, quarantined, blocked, expired) returns the typed
    ///    decision and writes nothing;
    /// 2. the committed manifest is reloaded from its CAS bytes, so
    ///    what gets materialized is what was committed, not what some
    ///    process remembered;
    /// 3. the commit's materializable outputs are checked against
    ///    `expected` — a caller skipping work must get exactly the files
    ///    that work would have produced, or no hit at all;
    /// 4. every destination is resolved under `destination_root` and
    ///    refused if it escapes (absolute, `..`, empty);
    /// 5. the D031 arbiter reserves ALL of them all-or-nothing, so two
    ///    concurrent serves cannot install into overlapping paths;
    /// 6. only then do bytes land, each verified against its object id
    ///    and renamed into place.
    ///
    /// A failure part-way leaves the files already written in place —
    /// they are individually correct, verified artifacts — and reports
    /// the failure; the caller must not treat a partial serve as a hit.
    ///
    /// # Errors
    /// A typed [`ServeError`]. The non-error non-serve cases (nothing
    /// committed, not servable) are [`ServeOutcome`] variants, because
    /// they are normal answers, not faults.
    pub fn serve_action(
        &self,
        action_key: &TypedDigest,
        destination_root: &Path,
        expected: &ExpectedOutputs,
        now_unix_micros: i64,
        now_epoch: u64,
    ) -> Result<ServeOutcome, ServeError> {
        let cas = self.cas.as_ref().ok_or(ServeError::NoStore)?;
        let key = digest_key(action_key);
        let mut store = cas
            .store()
            .lock()
            .map_err(|_| ServeError::StoreUnavailable)?;
        declare_coordinator_domains(&mut *store);

        match serving_gate(&mut *store, &key, now_unix_micros, now_epoch)
            .map_err(|e| ServeError::Store(format!("{e:?}")))?
        {
            ServeDecision::Servable => {}
            decision => return Ok(ServeOutcome::NotServable(decision)),
        }
        let Some(manifest_key) = store
            .published_manifest_key(action_key)
            .map_err(|e| ServeError::Store(format!("{e:?}")))?
        else {
            // A servable disposition with no publication row is a torn
            // store, not a hit.
            return Ok(ServeOutcome::NoCommit);
        };
        let Some(manifest) = load_manifest(&mut *store, &manifest_key) else {
            return Ok(ServeOutcome::ManifestUnavailable { key: manifest_key });
        };

        // The interlock: does this commit produce what the caller's own
        // work would have produced? Checked BEFORE any path resolution,
        // reservation, or byte — a mismatch must cost nothing.
        if let ExpectedOutputs::Exactly(expected) = expected {
            let mut committed_outputs = std::collections::BTreeSet::new();
            for output in &manifest.logical_outputs {
                if output.role != OutputRole::Materializable {
                    continue;
                }
                // No lossy comparison in a safety interlock: a path this
                // build cannot even read is a path it cannot promise.
                let text = std::str::from_utf8(output.virtual_path.as_bytes()).map_err(|_| {
                    ServeError::UnsafeVirtualPath {
                        path: output.virtual_path.escaped(),
                    }
                })?;
                committed_outputs.insert(text.to_owned());
            }
            if committed_outputs != *expected {
                return Ok(ServeOutcome::OutputSetMismatch {
                    missing: expected.difference(&committed_outputs).cloned().collect(),
                    unexpected: committed_outputs.difference(expected).cloned().collect(),
                });
            }
        }

        // Resolve destinations first: nothing is reserved, and no byte
        // is written, until every path is known to stay inside the root.
        let mut plan: Vec<(TypedDigest, PathBuf, String)> = Vec::new();
        for output in &manifest.logical_outputs {
            if output.role != OutputRole::Materializable {
                continue;
            }
            let path = resolve_destination(destination_root, output.virtual_path.as_bytes())
                .ok_or_else(|| ServeError::UnsafeVirtualPath {
                    path: output.virtual_path.escaped(),
                })?;
            let text = path.to_string_lossy().into_owned();
            plan.push((output.object.0.clone(), path, text));
        }
        if plan.is_empty() {
            return Ok(ServeOutcome::Served { files: Vec::new() });
        }

        // D031: reserve every destination all-or-nothing before any
        // install, so a concurrent serve into an overlapping path is
        // refused rather than interleaved.
        let bundle = BundleId(format!("serve:{key}:{}", self.next_seq()));
        let paths: Vec<String> = plan.iter().map(|(_, _, text)| text.clone()).collect();
        {
            let mut arbiter = self
                .arbiter
                .lock()
                .map_err(|_| ServeError::StoreUnavailable)?;
            arbiter.reserve(&bundle, &paths).map_err(|conflict| {
                ServeError::DestinationConflict {
                    path: conflict.path,
                    holder: conflict.holder.0,
                }
            })?;
        }
        let result = install_all(&mut *store, &plan);
        if let Ok(mut arbiter) = self.arbiter.lock() {
            arbiter.release(&bundle);
        }
        let files = result?;
        Ok(ServeOutcome::Served { files })
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
             \"cas_mounted\":{},\"authority_held\":{},\"authority_term\":{},\
             \"closed_prior_authority_generations\":{}}}",
            self.available(),
            self.cas.is_some(),
            authority.is_some(),
            authority.map_or(0, |a| a.term),
            self.closed_prior_generations(),
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

/// Declare every digest domain the coordinator reads back out of a
/// store a PREVIOUS incarnation wrote.
///
/// Domain restore is fail-closed (R121): a process may only re-type a
/// stored domain it names itself, as a `'static` from its own build.
/// Writes intern implicitly, which covers everything within one
/// incarnation — but a fresh coordinator's very first acts are READS
/// (its predecessor's authority row, the committed publication for a key
/// it is about to admit), so it declares them here at boot. Anything not
/// on this list still fails closed.
pub fn declare_coordinator_domains(store: &mut dyn RabsMetadataStore) {
    for domain in [
        AUTHORITY_DIGEST_DOMAIN,
        DOMAIN_ACTION_KEY,
        DOMAIN_DESCRIPTOR,
        DOMAIN_ARTIFACT_BUNDLE_ROOT,
        ATP_OBJECT_CONTENT_DOMAIN,
        SEMANTIC_PROJECTION_DOMAIN,
        OBSERVABLE_PROJECTION_DOMAIN,
    ] {
        store.intern_domain(domain);
    }
}

/// Load a canonical result manifest out of its CAS bytes, by object
/// digest key (`domain:hex`, as stored on the publication row).
///
/// `None` for every "cannot be sure" case — an unparsable key, a key
/// that is not an object id, no non-quarantined raw copy, unreadable
/// bytes, or bytes that do not decode. A caller that needs the manifest
/// then refuses conservatively; a wrong manifest would mean a wrong
/// divergence verdict, which is far worse than a refusal.
#[must_use]
pub fn load_manifest(
    store: &mut dyn RabsMetadataStore,
    manifest_key: &str,
) -> Option<CanonicalActionResultManifest> {
    let object = object_id_from_key(manifest_key)?;
    let locations = store.object_locations(&object).ok()?;
    locations
        .into_iter()
        // Only the raw representation is bytes-as-stored; compressed and
        // packed copies need their own decoders (H030) and are skipped
        // rather than mis-read.
        .filter(|(_, encoding, _)| encoding == RAW_PROFILE_V1)
        .find_map(|(path, _, _)| {
            let bytes = std::fs::read(&path).ok()?;
            decode_manifest_v1(&bytes).ok()
        })
}

/// Parse a `rabs.object.sha256.v1:<64 hex>` digest key back into a typed
/// digest. The domain is this build's `'static` constant — a key naming
/// any other domain is refused, never re-typed (R121).
fn object_id_from_key(key: &str) -> Option<TypedDigest> {
    let hex = key
        .strip_prefix(ATP_OBJECT_CONTENT_DOMAIN)?
        .strip_prefix(':')?;
    if hex.len() != 64 {
        return None;
    }
    let mut bytes = [0_u8; 32];
    let (pairs, _) = hex.as_bytes().as_chunks::<2>();
    for (slot, pair) in bytes.iter_mut().zip(pairs) {
        let text = std::str::from_utf8(pair).ok()?;
        *slot = u8::from_str_radix(text, 16).ok()?;
    }
    Some(TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain: ATP_OBJECT_CONTENT_DOMAIN,
        bytes,
    })
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
                     \"digest\":\"{}\",\"prior_generations_closed\":{}}}",
                    authority.cluster_id.0,
                    authority.credential_generation,
                    authority.term,
                    authority.incarnation_id.0,
                    digest_key(&authority_digest(&authority)),
                    coord.closed_prior_generations(),
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
    use crate::janitor::store::mount_and_reconcile;
    use rabs_protocol::generation::WorkerBootGeneration;
    use std::sync::Arc;

    fn worker_offer(generation: u64, incarnation: u128) -> WorkerSessionOffer {
        WorkerSessionOffer {
            worker_peer_id: PeerId("worker-a".to_owned()),
            boot_generation: WorkerBootGeneration(generation),
            incarnation: WorkerIncarnationId(incarnation),
            reenrollment_proof: None,
        }
    }

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

    #[test]
    fn worker_fence_is_atomic_exact_owner_and_durable() {
        let dir = tempfile::tempdir().expect("temp store");
        let cas = Arc::new(mount_and_reconcile(dir.path()).expect("mount"));
        let coord = CoordLive::with_cas(Arc::clone(&cas));
        coord
            .acquire_boot_authority("test-cluster")
            .expect("authority");

        let first = worker_offer(5, 0x11);
        let (admission, started) = coord.admit_worker_session(&first).expect("first admission");
        assert_eq!(admission, WorkerAdmission::AdmitNewGeneration);
        let started = started.expect("admitted session sequence");

        let (reconnect, reconnect_started) = coord
            .admit_worker_session(&first)
            .expect("reconnect admission");
        assert_eq!(reconnect, WorkerAdmission::AdmitReconnect);
        let reconnect_started = reconnect_started.expect("reconnect session sequence");
        assert_ne!(reconnect_started, started);

        let (clone, clone_started) = coord
            .admit_worker_session(&worker_offer(5, 0x22))
            .expect("clone decision");
        assert_eq!(clone, WorkerAdmission::RejectCloneAmbiguity);
        assert_eq!(clone_started, None, "a rejected clone opens no session");
        assert!(
            !coord
                .release_worker_session(
                    &PeerId("worker-a".to_owned()),
                    WorkerIncarnationId(0x22),
                    started,
                )
                .expect("wrong-owner release")
        );
        assert!(
            coord
                .release_worker_session(
                    &PeerId("worker-a".to_owned()),
                    WorkerIncarnationId(0x11),
                    started,
                )
                .expect("exact-owner release")
        );

        let (still_clone, still_clone_started) = coord
            .admit_worker_session(&worker_offer(5, 0x22))
            .expect("clone decision with reconnect still open");
        assert_eq!(still_clone, WorkerAdmission::RejectCloneAmbiguity);
        assert_eq!(still_clone_started, None);
        assert!(
            coord
                .release_worker_session(
                    &PeerId("worker-a".to_owned()),
                    WorkerIncarnationId(0x11),
                    reconnect_started,
                )
                .expect("final reconnect release")
        );

        let (resume, resumed_seq) = coord
            .admit_worker_session(&worker_offer(5, 0x22))
            .expect("resume admission");
        assert_eq!(resume, WorkerAdmission::AdmitResume);
        assert!(resumed_seq.is_some());

        drop(coord);
        drop(cas);
        let reopened = Arc::new(mount_and_reconcile(dir.path()).expect("reopen"));
        let restarted = CoordLive::with_cas(reopened);
        restarted
            .acquire_boot_authority("test-cluster")
            .expect("restarted authority");
        let (stale, stale_seq) = restarted
            .admit_worker_session(&worker_offer(4, 0x33))
            .expect("stale decision");
        assert_eq!(stale, WorkerAdmission::RejectStaleBootGeneration);
        assert_eq!(stale_seq, None);

        let mut rolled_back = worker_offer(1, 0x44);
        rolled_back.reenrollment_proof = Some(1);
        let (rejected_reset, rejected_reset_seq) = restarted
            .admit_worker_session(&rolled_back)
            .expect("rolled-back reenrollment decision");
        assert_eq!(rejected_reset, WorkerAdmission::RejectStaleBootGeneration);
        assert_eq!(rejected_reset_seq, None);

        let mut reenrolled = worker_offer(5, 0x44);
        reenrolled.reenrollment_proof = Some(1);
        let (reset, reset_seq) = restarted
            .admit_worker_session(&reenrolled)
            .expect("operator reenrollment");
        assert_eq!(reset, WorkerAdmission::AdmitViaReenrollment);
        assert!(reset_seq.is_some());

        let mut replay = worker_offer(5, 0x55);
        replay.reenrollment_proof = Some(1);
        let (rejected_replay, replay_seq) = restarted
            .admit_worker_session(&replay)
            .expect("replayed proof decision");
        assert_eq!(rejected_replay, WorkerAdmission::RejectCloneAmbiguity);
        assert_eq!(replay_seq, None);
    }
}
