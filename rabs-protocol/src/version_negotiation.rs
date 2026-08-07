//! ATP/RABS version negotiation (bead J002; Asupersync blocker 44.2;
//! risk R64).
//!
//! Every session opens with an explicit version handshake. Rules:
//!
//! - both sides advertise a CONCRETE transport range and application
//!   range (`current` + `minimum_compatible`) — there is no "ATP/0+"
//!   wildcard: any later version gets a concrete negotiated number
//!   checked against the matrix;
//! - negotiation picks the highest version inside BOTH ranges;
//! - mismatch produces a TYPED refusal carrying both sides' ranges so
//!   the operator sees exactly what to upgrade;
//! - N/N-1 is the supported skew: fixtures pin that a current node
//!   negotiates with a one-behind node, and that older skews refuse.

/// A concrete version range: minimum compatible to current, inclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionRange {
    /// Minimum version this side still speaks.
    pub minimum_compatible: u32,
    /// Current (preferred) version.
    pub current: u32,
}

impl VersionRange {
    /// Whether this range is well-formed.
    #[must_use]
    pub const fn well_formed(&self) -> bool {
        self.minimum_compatible <= self.current
    }
}

/// One side's hello: transport + application ranges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionHello {
    /// ATP transport version range.
    pub transport: VersionRange,
    /// RABS application version range.
    pub application: VersionRange,
}

/// Negotiation outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Negotiation {
    /// Agreed: the concrete versions BOTH sides run for this session.
    Agreed {
        /// Negotiated transport version.
        transport: u32,
        /// Negotiated application version.
        application: u32,
    },
    /// Refused: the typed unsupported-version response.
    Refused(VersionRefusal),
}

/// The typed refusal — both sides' ranges travel so the operator sees
/// exactly what to upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionRefusal {
    /// Which layer failed to overlap.
    pub layer: RefusedLayer,
    /// Our range for that layer.
    pub ours: VersionRange,
    /// Their range for that layer.
    pub theirs: VersionRange,
}

/// Which layer refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum RefusedLayer {
    Transport,
    Application,
    MalformedHello,
}

/// Highest version inside both ranges, if any.
const fn overlap(a: VersionRange, b: VersionRange) -> Option<u32> {
    let low = if a.minimum_compatible > b.minimum_compatible {
        a.minimum_compatible
    } else {
        b.minimum_compatible
    };
    let high = if a.current < b.current {
        a.current
    } else {
        b.current
    };
    if low <= high { Some(high) } else { None }
}

/// Negotiate a session from both hellos.
#[must_use]
pub fn negotiate(ours: &VersionHello, theirs: &VersionHello) -> Negotiation {
    if !ours.transport.well_formed()
        || !ours.application.well_formed()
        || !theirs.transport.well_formed()
        || !theirs.application.well_formed()
    {
        return Negotiation::Refused(VersionRefusal {
            layer: RefusedLayer::MalformedHello,
            ours: ours.transport,
            theirs: theirs.transport,
        });
    }
    let Some(transport) = overlap(ours.transport, theirs.transport) else {
        return Negotiation::Refused(VersionRefusal {
            layer: RefusedLayer::Transport,
            ours: ours.transport,
            theirs: theirs.transport,
        });
    };
    let Some(application) = overlap(ours.application, theirs.application) else {
        return Negotiation::Refused(VersionRefusal {
            layer: RefusedLayer::Application,
            ours: ours.application,
            theirs: theirs.application,
        });
    };
    Negotiation::Agreed {
        transport,
        application,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The N node: transport 3 (min 2), application 7 (min 6).
    fn current_node() -> VersionHello {
        VersionHello {
            transport: VersionRange {
                minimum_compatible: 2,
                current: 3,
            },
            application: VersionRange {
                minimum_compatible: 6,
                current: 7,
            },
        }
    }

    /// The N-1 node.
    fn n_minus_1() -> VersionHello {
        VersionHello {
            transport: VersionRange {
                minimum_compatible: 1,
                current: 2,
            },
            application: VersionRange {
                minimum_compatible: 5,
                current: 6,
            },
        }
    }

    #[test]
    fn n_n_minus_1_negotiates_the_older_concrete_versions() {
        // THE rolling-upgrade fixture: N with N-1 agrees on concrete
        // numbers (the highest both speak) — no wildcard, no ambiguity.
        assert_eq!(
            negotiate(&current_node(), &n_minus_1()),
            Negotiation::Agreed {
                transport: 2,
                application: 6
            }
        );
        // Symmetric: both sides derive the same answer.
        assert_eq!(
            negotiate(&n_minus_1(), &current_node()),
            Negotiation::Agreed {
                transport: 2,
                application: 6
            }
        );
        // N with N: the current versions.
        assert_eq!(
            negotiate(&current_node(), &current_node()),
            Negotiation::Agreed {
                transport: 3,
                application: 7
            }
        );
    }

    #[test]
    fn stale_skew_refuses_with_both_ranges() {
        // An N-2 node (transport current 1 < our minimum 2): typed
        // transport refusal carrying BOTH ranges.
        let n_minus_2 = VersionHello {
            transport: VersionRange {
                minimum_compatible: 1,
                current: 1,
            },
            application: VersionRange {
                minimum_compatible: 5,
                current: 5,
            },
        };
        let Negotiation::Refused(refusal) = negotiate(&current_node(), &n_minus_2) else {
            panic!("N-2 must refuse");
        };
        assert_eq!(refusal.layer, RefusedLayer::Transport);
        assert_eq!(refusal.ours.minimum_compatible, 2);
        assert_eq!(refusal.theirs.current, 1);
    }

    #[test]
    fn application_layer_refuses_independently_of_transport() {
        // Transports overlap; applications do not: the refusal names
        // the APPLICATION layer.
        let app_stale = VersionHello {
            transport: current_node().transport,
            application: VersionRange {
                minimum_compatible: 3,
                current: 4, // < our minimum 6
            },
        };
        let Negotiation::Refused(refusal) = negotiate(&current_node(), &app_stale) else {
            panic!("stale application must refuse");
        };
        assert_eq!(refusal.layer, RefusedLayer::Application);
    }

    #[test]
    fn future_versions_get_concrete_numbers_never_wildcards() {
        // An N+3 peer: we still negotiate OUR current — a concrete
        // number inside both ranges — never "whatever you have".
        let future = VersionHello {
            transport: VersionRange {
                minimum_compatible: 2,
                current: 6,
            },
            application: VersionRange {
                minimum_compatible: 6,
                current: 10,
            },
        };
        assert_eq!(
            negotiate(&current_node(), &future),
            Negotiation::Agreed {
                transport: 3,
                application: 7
            }
        );
        // Malformed hello (min > current): typed refusal, not UB.
        let malformed = VersionHello {
            transport: VersionRange {
                minimum_compatible: 9,
                current: 3,
            },
            application: current_node().application,
        };
        assert!(matches!(
            negotiate(&current_node(), &malformed),
            Negotiation::Refused(VersionRefusal {
                layer: RefusedLayer::MalformedHello,
                ..
            })
        ));
    }
}
