//! Edge content-identity index, digest singleflight, watcher-overflow
//! detection, periodic rehash audit (bead D029; risk R83).
//!
//! Rehashing the workspace on every command blows the miss SLO, so the
//! edge memoizes content identity — but memoization that trusts the
//! wrong evidence serves stale digests, which is worse than slow. The
//! index reuses a digest only under evidence, strongest-first:
//!
//! 1. a **materialization receipt** binding an immutable installed file
//!    to an object ID;
//! 2. a real fs snapshot with a proven-stable file identity primitive;
//! 3. open-descriptor stat/version checks backed by a **no-overflow**
//!    mutation journal;
//! 4. otherwise: full rehash.
//!
//! Mtime/size alone are NEVER content authority (the R83 sentence this
//! module exists to enforce): a version match is a precondition for
//! reuse, not a proof of it — the journal/receipt/snapshot evidence is
//! what upgrades "probably unchanged" to "reusable". Watcher overflow,
//! index corruption, or an audit mismatch drop the index to reduced
//! authority: every lookup rehashes until a bounded rescan completes.

use std::collections::BTreeMap;

/// A file-version observation (NEVER content authority by itself).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileVersion {
    /// Inode (0 where the platform has none — which downgrades trust).
    pub inode: u64,
    /// Byte size.
    pub size: u64,
    /// mtime in ns.
    pub mtime_ns: u128,
}

/// The evidence class under which a digest was recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IdentityEvidence {
    /// RABS materialization receipt: immutable file ↔ object ID.
    MaterializationReceipt,
    /// Filesystem snapshot + proven stable identity primitive.
    SnapshotStableIdentity,
    /// Descriptor-verified stat + healthy mutation journal.
    DescriptorStatJournal,
}

/// The filesystem trust class for a path's home.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsTrustClass {
    /// Local fs with fine timestamps and stable inodes.
    LocalFine,
    /// Coarse timestamps (FAT-class): stat evidence insufficient.
    CoarseTimestamps,
    /// Network filesystem: stat evidence insufficient.
    Network,
}

/// Why a lookup must rehash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RehashReason {
    /// Nothing memoized (the memoization-miss fixture).
    MemoizationMiss,
    /// The mutation journal overflowed: identities unproven.
    WatcherOverflow,
    /// Observed version differs from the recorded one.
    VersionMismatch,
    /// Journal-backed evidence on an fs class where stat is not
    /// trustworthy (coarse timestamps / network).
    UntrustworthyStatSurface,
    /// A prior audit caught a stale entry: reduced authority.
    AuditMismatch,
}

/// Lookup outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupOutcome {
    /// Reuse the memoized digest under the named evidence.
    ReuseDigest {
        /// The memoized content digest.
        digest: [u8; 32],
        /// The evidence class that justified reuse.
        evidence: IdentityEvidence,
    },
    /// Rehash, and record why.
    MustRehash {
        /// The reason (typed, for `rch why` and telemetry).
        reason: RehashReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IndexEntry {
    digest: [u8; 32],
    version: FileVersion,
    evidence: IdentityEvidence,
}

/// The per-filesystem content-identity index.
#[derive(Debug, Default)]
pub struct ContentIndex {
    entries: BTreeMap<String, IndexEntry>,
    overflowed: bool,
    audit_failed: bool,
}

impl ContentIndex {
    /// New empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a freshly established identity.
    pub fn record(
        &mut self,
        path: &str,
        digest: [u8; 32],
        version: FileVersion,
        evidence: IdentityEvidence,
    ) {
        self.entries.insert(
            path.to_string(),
            IndexEntry {
                digest,
                version,
                evidence,
            },
        );
    }

    /// The watcher reported overflow: identities are unproven until a
    /// bounded rescan completes.
    pub fn mark_watcher_overflow(&mut self) {
        self.overflowed = true;
    }

    /// A bounded rescan re-established every surviving identity.
    pub fn rescan_complete(&mut self) {
        self.overflowed = false;
        self.audit_failed = false;
    }

    /// Look up a path given the currently observed version and fs class.
    #[must_use]
    pub fn lookup(
        &self,
        path: &str,
        observed: FileVersion,
        fs_class: FsTrustClass,
    ) -> LookupOutcome {
        if self.audit_failed {
            return LookupOutcome::MustRehash {
                reason: RehashReason::AuditMismatch,
            };
        }
        if self.overflowed {
            return LookupOutcome::MustRehash {
                reason: RehashReason::WatcherOverflow,
            };
        }
        let Some(entry) = self.entries.get(path) else {
            return LookupOutcome::MustRehash {
                reason: RehashReason::MemoizationMiss,
            };
        };
        if entry.version != observed {
            return LookupOutcome::MustRehash {
                reason: RehashReason::VersionMismatch,
            };
        }
        // A version MATCH is only a precondition. Journal-backed stat
        // evidence is not trustworthy on coarse/network surfaces —
        // mtime/size alone are never content authority.
        let stat_trustworthy = matches!(fs_class, FsTrustClass::LocalFine);
        if entry.evidence == IdentityEvidence::DescriptorStatJournal && !stat_trustworthy {
            return LookupOutcome::MustRehash {
                reason: RehashReason::UntrustworthyStatSurface,
            };
        }
        LookupOutcome::ReuseDigest {
            digest: entry.digest,
            evidence: entry.evidence,
        }
    }

    /// Audit: rehash the named entries with `real_digest` and compare.
    /// Any mismatch evicts the entry, drops the index to reduced
    /// authority (every lookup rehashes until [`Self::rescan_complete`]),
    /// and is returned for telemetry.
    pub fn audit<F>(&mut self, sample: &[String], mut real_digest: F) -> Vec<String>
    where
        F: FnMut(&str) -> [u8; 32],
    {
        let mut stale = Vec::new();
        for path in sample {
            if let Some(entry) = self.entries.get(path)
                && real_digest(path) != entry.digest
            {
                stale.push(path.clone());
            }
        }
        for path in &stale {
            self.entries.remove(path);
        }
        if !stale.is_empty() {
            self.audit_failed = true;
        }
        stale
    }
}

/// Digest singleflight: concurrent requests for one path's digest
/// collapse to one leader; followers reuse the published result.
#[derive(Debug, Default)]
pub struct DigestSingleflight {
    inflight: BTreeMap<String, Vec<u64>>,
    published: BTreeMap<String, [u8; 32]>,
}

/// The requester's role for one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlightRole {
    /// This requester hashes; everyone else waits on it.
    Leader,
    /// Another requester is already hashing this path.
    Follower,
    /// The digest is already published — no hashing at all.
    Ready([u8; 32]),
}

impl DigestSingleflight {
    /// New empty singleflight table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Ask to hash `path` as `requester`.
    pub fn begin(&mut self, path: &str, requester: u64) -> FlightRole {
        if let Some(digest) = self.published.get(path) {
            return FlightRole::Ready(*digest);
        }
        match self.inflight.get_mut(path) {
            None => {
                self.inflight.insert(path.to_string(), vec![requester]);
                FlightRole::Leader
            }
            Some(waiters) => {
                waiters.push(requester);
                FlightRole::Follower
            }
        }
    }

    /// The leader publishes; returns the followers to wake.
    pub fn complete(&mut self, path: &str, digest: [u8; 32]) -> Vec<u64> {
        self.published.insert(path.to_string(), digest);
        self.inflight.remove(path).map_or_else(Vec::new, |waiters| {
            waiters.into_iter().skip(1).collect() // leader is waiters[0]
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V1: FileVersion = FileVersion {
        inode: 10,
        size: 100,
        mtime_ns: 1_000,
    };

    #[test]
    fn memoization_miss_and_overflow_fixtures_force_rehash() {
        // THE acceptance fixtures. Miss:
        let mut index = ContentIndex::new();
        assert_eq!(
            index.lookup("src/lib.rs", V1, FsTrustClass::LocalFine),
            LookupOutcome::MustRehash {
                reason: RehashReason::MemoizationMiss
            }
        );
        // Record → reuse.
        index.record(
            "src/lib.rs",
            [1; 32],
            V1,
            IdentityEvidence::DescriptorStatJournal,
        );
        assert!(matches!(
            index.lookup("src/lib.rs", V1, FsTrustClass::LocalFine),
            LookupOutcome::ReuseDigest { .. }
        ));
        // Overflow: EVERYTHING rehashes until the bounded rescan ends.
        index.mark_watcher_overflow();
        assert_eq!(
            index.lookup("src/lib.rs", V1, FsTrustClass::LocalFine),
            LookupOutcome::MustRehash {
                reason: RehashReason::WatcherOverflow
            }
        );
        index.rescan_complete();
        assert!(matches!(
            index.lookup("src/lib.rs", V1, FsTrustClass::LocalFine),
            LookupOutcome::ReuseDigest { .. }
        ));
    }

    #[test]
    fn mtime_and_size_alone_are_never_content_authority() {
        let mut index = ContentIndex::new();
        index.record(
            "src/lib.rs",
            [1; 32],
            V1,
            IdentityEvidence::DescriptorStatJournal,
        );
        // Identical stat on an untrustworthy surface: REHASH anyway.
        for fs in [FsTrustClass::CoarseTimestamps, FsTrustClass::Network] {
            assert_eq!(
                index.lookup("src/lib.rs", V1, fs),
                LookupOutcome::MustRehash {
                    reason: RehashReason::UntrustworthyStatSurface
                }
            );
        }
        // A RECEIPT survives those surfaces (it does not rest on stat).
        index.record(
            "vendored.rlib",
            [2; 32],
            V1,
            IdentityEvidence::MaterializationReceipt,
        );
        assert!(matches!(
            index.lookup("vendored.rlib", V1, FsTrustClass::Network),
            LookupOutcome::ReuseDigest {
                evidence: IdentityEvidence::MaterializationReceipt,
                ..
            }
        ));
        // Any version drift (inode swap with same size/mtime) rehashes.
        let inode_swapped = FileVersion { inode: 11, ..V1 };
        assert_eq!(
            index.lookup("vendored.rlib", inode_swapped, FsTrustClass::LocalFine),
            LookupOutcome::MustRehash {
                reason: RehashReason::VersionMismatch
            }
        );
    }

    #[test]
    fn audit_catches_seeded_stale_entries_and_reduces_authority() {
        // THE audit acceptance: seed a stale entry (indexed digest lies
        // about content), audit with the real hasher.
        let mut index = ContentIndex::new();
        index.record(
            "ok.rs",
            [1; 32],
            V1,
            IdentityEvidence::DescriptorStatJournal,
        );
        index.record(
            "stale.rs",
            [9; 32], // seeded lie
            V1,
            IdentityEvidence::DescriptorStatJournal,
        );
        let real = |path: &str| -> [u8; 32] { if path == "ok.rs" { [1; 32] } else { [7; 32] } };
        let stale = index.audit(&["ok.rs".to_string(), "stale.rs".to_string()], real);
        assert_eq!(stale, vec!["stale.rs".to_string()]);
        // Reduced authority: even the GOOD entry rehashes until rescan.
        assert_eq!(
            index.lookup("ok.rs", V1, FsTrustClass::LocalFine),
            LookupOutcome::MustRehash {
                reason: RehashReason::AuditMismatch
            }
        );
        index.rescan_complete();
        assert!(matches!(
            index.lookup("ok.rs", V1, FsTrustClass::LocalFine),
            LookupOutcome::ReuseDigest { .. }
        ));
        // The stale entry is gone for good.
        assert_eq!(
            index.lookup("stale.rs", V1, FsTrustClass::LocalFine),
            LookupOutcome::MustRehash {
                reason: RehashReason::MemoizationMiss
            }
        );
    }

    #[test]
    fn digest_singleflight_collapses_concurrent_hashers() {
        let mut flight = DigestSingleflight::new();
        assert_eq!(flight.begin("big.rs", 1), FlightRole::Leader);
        assert_eq!(flight.begin("big.rs", 2), FlightRole::Follower);
        assert_eq!(flight.begin("big.rs", 3), FlightRole::Follower);
        // A different path gets its own leader.
        assert_eq!(flight.begin("other.rs", 4), FlightRole::Leader);
        // Leader publishes: exactly the followers wake.
        let woken = flight.complete("big.rs", [5; 32]);
        assert_eq!(woken, vec![2, 3]);
        // Late requesters get the published digest with zero hashing.
        assert_eq!(flight.begin("big.rs", 9), FlightRole::Ready([5; 32]));
    }
}
