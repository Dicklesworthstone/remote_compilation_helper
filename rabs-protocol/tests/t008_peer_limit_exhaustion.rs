//! T008: adversarial peers against every per-peer limit (bead S008;
//! plan §106).
//!
//! S008 ships a good sweep — fill each dimension to its limit, one more
//! unit refuses naming the dimension, usage unchanged — plus an
//! adversary hammering 10x every limit, per-peer isolation, and the
//! independent control reserve. None of that is redone.
//!
//! Every one of those tests iterates `DEFAULT_LIMITS`, the TABLE. That
//! is the gap this file closes, and it is the difference between
//! "every limit is enforced" and "every resource class has a limit":
//!
//! `index_of` finds a dimension by scanning the table and
//! `.expect("closed registry")` if it is absent. Adding a `Dimension`
//! variant WITHOUT a table row therefore compiles, leaves the table at
//! 19 so the pinned-length assertion still passes, and is never visited
//! by any sweep — because every sweep enumerates the table, which does
//! not contain it. The first production call carrying that dimension
//! panics. In a per-peer limit path, whose entire job is to survive
//! adversarial peers, a panic is the denial of service the limits exist
//! to prevent.
//!
//! So the check here enumerates the ENUM and cross-references the
//! table. An exhaustive `match` makes the compiler refuse to build
//! until a new variant is listed, and the test then refuses to pass
//! until it has a limit. That is the chain S008's close reason already
//! claims ("a new resource class fails the sweep until it gets a
//! limit") — the pinned count alone does not provide it, because a new
//! enum variant does not change the table's length.

use rabs_protocol::peer_limits::{DEFAULT_LIMITS, Dimension, PeerAccount};

/// Every dimension the enum can express.
///
/// The exhaustive match below is the load-bearing part: it does nothing
/// at runtime and exists so that adding a `Dimension` variant fails to
/// COMPILE until it is named here, which in turn forces it through the
/// table cross-check in `t008_every_dimension_variant_has_a_limit`.
fn every_dimension() -> Vec<Dimension> {
    const fn exhaustive(dimension: Dimension) -> Dimension {
        match dimension {
            Dimension::ConcurrentSessions
            | Dimension::FramesPerSecond
            | Dimension::FrameBytes
            | Dimension::ExtensionBytes
            | Dimension::QueuedControlBytes
            | Dimension::QueuedDataBytes
            | Dimension::InFlightObjectRequests
            | Dimension::ManifestDepth
            | Dimension::ManifestFanOut
            | Dimension::SparseRanges
            | Dimension::DiagnosticsBytes
            | Dimension::OutputCount
            | Dimension::OutputBytes
            | Dimension::ProcessCount
            | Dimension::MemoryBytes
            | Dimension::TempBytes
            | Dimension::DiskBytes
            | Dimension::Retries
            | Dimension::Restarts => dimension,
        }
    }

    [
        Dimension::ConcurrentSessions,
        Dimension::FramesPerSecond,
        Dimension::FrameBytes,
        Dimension::ExtensionBytes,
        Dimension::QueuedControlBytes,
        Dimension::QueuedDataBytes,
        Dimension::InFlightObjectRequests,
        Dimension::ManifestDepth,
        Dimension::ManifestFanOut,
        Dimension::SparseRanges,
        Dimension::DiagnosticsBytes,
        Dimension::OutputCount,
        Dimension::OutputBytes,
        Dimension::ProcessCount,
        Dimension::MemoryBytes,
        Dimension::TempBytes,
        Dimension::DiskBytes,
        Dimension::Retries,
        Dimension::Restarts,
    ]
    .into_iter()
    .map(exhaustive)
    .collect()
}

fn limit_of(dimension: Dimension) -> u64 {
    DEFAULT_LIMITS
        .iter()
        .find(|(d, _)| *d == dimension)
        .map(|(_, limit)| *limit)
        .expect("dimension has a limit")
}

#[test]
fn t008_every_dimension_variant_has_a_limit() {
    // The chain: the compiler forces a new variant into
    // `every_dimension`, and this forces it into `DEFAULT_LIMITS`.
    // Without it, a new resource class reaches production with no bound
    // and panics inside `index_of` the first time a peer uses it.
    for dimension in every_dimension() {
        assert!(
            DEFAULT_LIMITS.iter().any(|(d, _)| *d == dimension),
            "{dimension:?} is a resource class with NO limit: index_of would panic \
             on it in production, and no sweep over DEFAULT_LIMITS can see it"
        );
    }
    // And nothing in the table is absent from the enumeration, so the
    // two lists are the same set rather than merely overlapping.
    assert_eq!(
        every_dimension().len(),
        DEFAULT_LIMITS.len(),
        "the enumeration and the table must describe the same closed registry"
    );
    for (dimension, _) in DEFAULT_LIMITS {
        assert!(
            every_dimension().contains(&dimension),
            "{dimension:?} is in the table but not in the enumeration"
        );
    }
}

#[test]
fn t008_a_saturating_request_is_refused_rather_than_wrapping_into_headroom() {
    // The arithmetic an adversary attacks first. A peer that asks for
    // u64::MAX on an already-full dimension must be refused with a
    // would-reach that SATURATES; wrapping would produce a small number
    // that slips under the bound and grants unbounded capacity.
    for dimension in every_dimension() {
        let limit = limit_of(dimension);
        let mut peer = PeerAccount::default();
        peer.admit(dimension, limit).expect("fills to the bound");

        let refusal = peer
            .admit(dimension, u64::MAX)
            .expect_err("a saturating request must be refused");
        assert_eq!(refusal.dimension, dimension);
        assert_eq!(
            refusal.would_reach,
            u64::MAX,
            "{dimension:?}: would_reach must saturate, not wrap"
        );
        assert_eq!(
            peer.usage(dimension),
            limit,
            "{dimension:?}: a refused request must change nothing"
        );
    }
}

#[test]
fn t008_one_dimension_filling_never_consumes_another_s_budget() {
    // Per-DIMENSION independence, which is a different claim from
    // S008's per-PEER isolation. If two classes shared a counter, an
    // adversary could exhaust an expensive bound (disk, memory) by
    // hammering a cheap one (retries).
    for filled in every_dimension() {
        let mut peer = PeerAccount::default();
        peer.admit(filled, limit_of(filled)).expect("fills");

        for other in every_dimension() {
            if other == filled {
                continue;
            }
            assert_eq!(
                peer.usage(other),
                0,
                "filling {filled:?} moved {other:?}'s usage"
            );
            assert_eq!(
                peer.admit(other, limit_of(other)),
                Ok(()),
                "filling {filled:?} consumed {other:?}'s headroom"
            );
            peer.release(other, limit_of(other));
        }
    }
}

#[test]
fn t008_releasing_more_than_was_admitted_grants_no_extra_capacity() {
    // `release` saturates at zero, so an over-release cannot drive usage
    // negative — but the property that matters is the one after it: the
    // peer must still be held to the SAME bound afterwards, not handed a
    // larger budget because it over-released.
    for dimension in every_dimension() {
        let limit = limit_of(dimension);
        let mut peer = PeerAccount::default();
        peer.admit(dimension, limit).expect("fills");

        peer.release(dimension, u64::MAX);
        assert_eq!(
            peer.usage(dimension),
            0,
            "{dimension:?}: release floors at 0"
        );

        assert_eq!(
            peer.admit(dimension, limit),
            Ok(()),
            "{dimension:?}: the freed budget is exactly the bound"
        );
        assert!(
            peer.admit(dimension, 1).is_err(),
            "{dimension:?}: over-releasing must not raise the ceiling"
        );
    }
}

#[test]
fn t008_a_refusal_is_reported_with_the_dimension_that_actually_refused() {
    // The refusals are the product here: an operator reading one has to
    // be able to act on it. Every dimension, filled and then pushed, must
    // name ITSELF, its own limit, and a would-reach that exceeds it —
    // not a neighbour's numbers.
    for dimension in every_dimension() {
        let limit = limit_of(dimension);
        let mut peer = PeerAccount::default();
        peer.admit(dimension, limit).expect("fills");

        let refusal = peer.admit(dimension, 1).expect_err("bound holds");
        assert_eq!(refusal.dimension, dimension);
        assert_eq!(refusal.limit, limit, "{dimension:?}: wrong limit reported");
        assert!(
            refusal.would_reach > refusal.limit,
            "{dimension:?}: a refusal must show the bound being exceeded"
        );
    }
}

#[test]
fn t008_the_suite_is_not_satisfied_by_refusing_everything() {
    // The control. Everything above is about refusals and bounds; an
    // implementation that refused every admission would satisfy most of
    // it while making the daemon useless. So: a fresh peer admits right
    // up to each bound, and its usage reflects exactly what it asked
    // for.
    for dimension in every_dimension() {
        let limit = limit_of(dimension);
        let mut peer = PeerAccount::default();
        assert_eq!(peer.usage(dimension), 0, "a fresh peer owes nothing");
        assert_eq!(peer.admit(dimension, limit), Ok(()));
        assert_eq!(
            peer.usage(dimension),
            limit,
            "{dimension:?}: an admitted request must be accounted"
        );
    }
}
