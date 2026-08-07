//! Local wrapper↔edge protocol version handshake (bead C001; plan §182).
//!
//! The local Unix-socket protocol version is DISTINCT from the ATP
//! transport version and the RABS application version — each negotiates
//! independently, and a change in one never silently changes another.
//!
//! Negotiation doctrine (plan §47 applied locally): a mismatch yields an
//! **explicit** typed outcome — select, downgrade, or refuse — never a
//! silent compatibility assumption. On refusal the wrapper runs the
//! original tool chain (fail-open, C004/C006); a version mismatch must
//! never strand a build.

/// A local-protocol version. Version 1 is `rabs.local-wrapper` v1 in the
/// A005 schema registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LocalProtocolVersion(pub u32);

/// The current version this build speaks.
pub const CURRENT_LOCAL_PROTOCOL: LocalProtocolVersion = LocalProtocolVersion(1);

/// One side's supported (contiguous, inclusive) version range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionRange {
    /// Minimum version this side still speaks.
    pub min: LocalProtocolVersion,
    /// Maximum version this side speaks.
    pub max: LocalProtocolVersion,
}

impl VersionRange {
    /// A well-formed range (min <= max).
    #[must_use]
    pub const fn new(min: u32, max: u32) -> Option<Self> {
        if min > max {
            return None;
        }
        Some(Self {
            min: LocalProtocolVersion(min),
            max: LocalProtocolVersion(max),
        })
    }

    /// A single-version range.
    #[must_use]
    pub const fn exactly(v: u32) -> Self {
        Self {
            min: LocalProtocolVersion(v),
            max: LocalProtocolVersion(v),
        }
    }
}

/// The negotiation outcome. Refusal carries both ranges so the reason is
/// diagnosable from the receipt alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Negotiation {
    /// Both sides speak `selected`: the highest mutually supported version.
    Selected(LocalProtocolVersion),
    /// No overlap. The wrapper must fail open to the original tool chain;
    /// reason code PROTOCOL_VERSION_UNSUPPORTED accompanies the receipt.
    Refused {
        /// The wrapper's offered range.
        wrapper: VersionRange,
        /// The edge's offered range.
        edge: VersionRange,
    },
}

/// Negotiate: highest version inside both ranges, else explicit refusal.
#[must_use]
pub const fn negotiate(wrapper: VersionRange, edge: VersionRange) -> Negotiation {
    let low = if wrapper.min.0 > edge.min.0 {
        wrapper.min.0
    } else {
        edge.min.0
    };
    let high = if wrapper.max.0 < edge.max.0 {
        wrapper.max.0
    } else {
        edge.max.0
    };
    if low > high {
        Negotiation::Refused { wrapper, edge }
    } else {
        Negotiation::Selected(LocalProtocolVersion(high))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_versions_select_that_version() {
        let n = negotiate(VersionRange::exactly(1), VersionRange::exactly(1));
        assert_eq!(n, Negotiation::Selected(LocalProtocolVersion(1)));
    }

    #[test]
    fn forward_compatibility_selects_highest_common() {
        // Upgraded edge (1..=3) with an older wrapper (1..=2): overlap
        // exists, highest common wins — the N/N-1 rolling-upgrade case.
        let wrapper = VersionRange::new(1, 2).unwrap();
        let edge = VersionRange::new(1, 3).unwrap();
        assert_eq!(
            negotiate(wrapper, edge),
            Negotiation::Selected(LocalProtocolVersion(2))
        );
        // And the mirror image (upgraded wrapper, older edge).
        assert_eq!(
            negotiate(edge, wrapper),
            Negotiation::Selected(LocalProtocolVersion(2))
        );
    }

    #[test]
    fn disjoint_ranges_refuse_explicitly_with_both_ranges() {
        let wrapper = VersionRange::exactly(1);
        let edge = VersionRange::new(2, 3).unwrap();
        match negotiate(wrapper, edge) {
            Negotiation::Refused {
                wrapper: w,
                edge: e,
            } => {
                assert_eq!(w, wrapper);
                assert_eq!(e, edge);
            }
            other @ Negotiation::Selected(_) => {
                panic!("disjoint ranges must refuse, got {other:?}")
            }
        }
    }

    #[test]
    fn malformed_ranges_are_unconstructable() {
        assert!(VersionRange::new(3, 1).is_none());
    }

    #[test]
    fn current_version_is_registered() {
        use crate::schema_registry::{SchemaDomain, lookup};
        let entry = lookup(SchemaDomain::Protocol, "rabs.local-wrapper")
            .expect("local wrapper protocol must be registered (A005)");
        assert_eq!(entry.version, CURRENT_LOCAL_PROTOCOL.0);
    }
}
