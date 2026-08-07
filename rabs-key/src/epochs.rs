//! Key and projection epoch registry (bead F002; plan §17.1).
//!
//! `key_epoch` is the cheap global invalidation lever for key-logic
//! changes; `projection_epoch` independently versions dependency/input
//! projections. **An epoch bump creates a cold namespace** — old entries
//! are never reinterpreted under new semantics; they simply stop matching.
//!
//! ## When a bump is REQUIRED (any one suffices)
//!
//! - adding a previously omitted semantic or negative input;
//! - changing path or environment normalization;
//! - changing dependency-artifact projection (projection epoch);
//! - changing sandbox-visible state;
//! - changing canonical serialization (the F001 goldens breaking is the
//!   tripwire — fixing the golden without bumping here is the forbidden
//!   move);
//! - changing logical output interpretation.
//!
//! ## Change discipline
//!
//! The constants below carry a change log in code. CI-level enforcement:
//! the F001 golden fixtures and the A014 component-list test break on
//! key-affecting changes; both failure messages point here. A change that
//! trips either fixture MUST land with either (a) a bump + change-log
//! entry below, or (b) a written justification of why the change cannot
//! affect any produced key (e.g. comment-only).

/// Current key epoch.
///
/// Change log:
/// - 1 (2026-08-07): initial epoch — the twelve-component descriptor
///   (A014) over the F001 canonical encoding.
pub const CURRENT_KEY_EPOCH: u32 = 1;

/// Current projection epoch.
///
/// Change log:
/// - 1 (2026-08-07): conservative exact-artifact dependency identity ONLY
///   (I22). No reduced projection exists; enabling one is a projection
///   bump gated by the F010/F022 shadow framework.
pub const CURRENT_PROJECTION_EPOCH: u32 = 1;

/// A (key, projection) epoch pair as carried in descriptors and entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Epochs {
    /// Key epoch.
    pub key: u32,
    /// Projection epoch.
    pub projection: u32,
}

/// The current epoch pair.
#[must_use]
pub const fn current() -> Epochs {
    Epochs {
        key: CURRENT_KEY_EPOCH,
        projection: CURRENT_PROJECTION_EPOCH,
    }
}

/// Whether an entry written under `entry` epochs may even be LOOKED UP by
/// a requester at `requester` epochs. Cold-namespace rule: any mismatch is
/// a miss-by-namespace — never a reinterpretation, never an error.
#[must_use]
pub const fn same_namespace(entry: Epochs, requester: Epochs) -> bool {
    entry.key == requester.key && entry.projection == requester.projection
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_epochs_match_the_schema_registry() {
        // The rabs-protocol registry entry for the action key is v1; the
        // key epoch and that schema version advance together at v1.
        use rabs_protocol::schema_registry::{SchemaDomain, lookup};
        let entry = lookup(SchemaDomain::Key, "rabs.action-key").expect("registered");
        assert_eq!(entry.version, CURRENT_KEY_EPOCH);
        let proj = lookup(SchemaDomain::Key, "rabs.dependency-projection").expect("registered");
        assert_eq!(proj.version, CURRENT_PROJECTION_EPOCH);
    }

    #[test]
    fn epoch_mismatch_is_a_cold_namespace_not_an_error() {
        let now = current();
        let old_key = Epochs {
            key: now.key + 1,
            projection: now.projection,
        };
        let old_proj = Epochs {
            key: now.key,
            projection: now.projection + 1,
        };
        assert!(same_namespace(now, now));
        assert!(
            !same_namespace(old_key, now),
            "key epoch splits the namespace"
        );
        assert!(
            !same_namespace(old_proj, now),
            "projection epoch independently splits the namespace"
        );
    }
}
