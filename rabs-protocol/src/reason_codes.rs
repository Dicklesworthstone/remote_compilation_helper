//! The stable RABS reason-code registry (bead A006).
//!
//! Every refusal, fallback, miss, quarantine, and scheduling decision in
//! RABS carries a stable machine-readable reason code so `rch why`,
//! `DecisionReceipt`s, and agents can act on outcomes without parsing prose
//! (explainability is a product pillar, goal G6).
//!
//! ## Rules (binding)
//!
//! - Codes are **append-only within a protocol major version**: a shipped
//!   code is never removed or renamed; supersede by adding a new code and
//!   noting it. The registry fingerprint test makes edits deliberate.
//! - Every code belongs to exactly one family and is prefixed by that
//!   family's `PREFIX_` (validated by tests).
//! - Codes are terse claims, not sentences; human wording lives in the
//!   `summary` and in renderers, so text can improve without breaking
//!   automation.

/// The 23 reason-code families from the plan (Part XXV §181).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReasonFamily {
    /// Key construction/epoch/breakdown outcomes.
    Key,
    /// Cache lookup/serving outcomes.
    Cache,
    /// Positive/negative input closure outcomes.
    Input,
    /// Path canonicalization/leak/policy outcomes.
    Path,
    /// Toolchain contract outcomes.
    Toolchain,
    /// Output-platform contract outcomes.
    Platform,
    /// Sandbox policy/enforcement outcomes.
    Sandbox,
    /// Worker admission/eligibility outcomes.
    Worker,
    /// Pressure/admission-class outcomes.
    Pressure,
    /// Transfer plan/break-even outcomes.
    Transfer,
    /// Execution-lease lifecycle outcomes.
    Lease,
    /// Coordinator-authority/fencing outcomes.
    Authority,
    /// Cancellation outcomes.
    Cancel,
    /// Subscriber-delivery frontier outcomes.
    Delivery,
    /// Publication/commit outcomes.
    Publication,
    /// Trust-evidence outcomes.
    Evidence,
    /// CAS/storage outcomes.
    Storage,
    /// Verification/audit outcomes.
    Verify,
    /// Quarantine scope outcomes.
    Quarantine,
    /// Fail-open/fallback outcomes.
    Fallback,
    /// Protocol/version negotiation outcomes.
    Protocol,
    /// Speculation lifecycle outcomes.
    Speculation,
    /// Test-action eligibility outcomes.
    Test,
}

impl ReasonFamily {
    /// The `SCREAMING_SNAKE` prefix every code in this family must carry.
    #[must_use]
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Key => "KEY_",
            Self::Cache => "CACHE_",
            Self::Input => "INPUT_",
            Self::Path => "PATH_",
            Self::Toolchain => "TOOLCHAIN_",
            Self::Platform => "PLATFORM_",
            Self::Sandbox => "SANDBOX_",
            Self::Worker => "WORKER_",
            Self::Pressure => "PRESSURE_",
            Self::Transfer => "TRANSFER_",
            Self::Lease => "LEASE_",
            Self::Authority => "AUTHORITY_",
            Self::Cancel => "CANCEL_",
            Self::Delivery => "DELIVERY_",
            Self::Publication => "PUBLICATION_",
            Self::Evidence => "EVIDENCE_",
            Self::Storage => "STORAGE_",
            Self::Verify => "VERIFY_",
            Self::Quarantine => "QUARANTINE_",
            Self::Fallback => "FALLBACK_",
            Self::Protocol => "PROTOCOL_",
            Self::Speculation => "SPECULATION_",
            Self::Test => "TEST_",
        }
    }

    /// All families, for exhaustiveness checks.
    pub const ALL: [Self; 23] = [
        Self::Key,
        Self::Cache,
        Self::Input,
        Self::Path,
        Self::Toolchain,
        Self::Platform,
        Self::Sandbox,
        Self::Worker,
        Self::Pressure,
        Self::Transfer,
        Self::Lease,
        Self::Authority,
        Self::Cancel,
        Self::Delivery,
        Self::Publication,
        Self::Evidence,
        Self::Storage,
        Self::Verify,
        Self::Quarantine,
        Self::Fallback,
        Self::Protocol,
        Self::Speculation,
        Self::Test,
    ];
}

/// One registered reason code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReasonCode {
    /// Family the code belongs to (its prefix is validated against this).
    pub family: ReasonFamily,
    /// Stable machine-readable code, e.g. `FALLBACK_EDGE_UNAVAILABLE`.
    pub code: &'static str,
    /// One-line human summary (renderers may improve wording freely).
    pub summary: &'static str,
}

/// The authoritative registry: the initial seed set, at least one code per
/// family, chosen from decisions the plan already names. Append-only.
pub const REGISTRY: &[ReasonCode] = &[
    ReasonCode {
        family: ReasonFamily::Key,
        code: "KEY_EPOCH_MISMATCH",
        summary: "Entry was written under a different key/projection epoch (cold namespace).",
    },
    ReasonCode {
        family: ReasonFamily::Key,
        code: "KEY_FIRST_SEEN",
        summary: "No prior entry for this action key.",
    },
    ReasonCode {
        family: ReasonFamily::Cache,
        code: "CACHE_HIT_VALIDATED",
        summary: "Committed result served after descriptor byte-verification.",
    },
    ReasonCode {
        family: ReasonFamily::Cache,
        code: "CACHE_MISS_COMPONENT_CHANGED",
        summary: "Key breakdown diff attributes the miss to a changed component.",
    },
    ReasonCode {
        family: ReasonFamily::Cache,
        code: "CACHE_SERVING_EXPIRED_NEEDS_REVALIDATION",
        summary: "Serving disposition TTL expired; revalidation required before serving.",
    },
    ReasonCode {
        family: ReasonFamily::Input,
        code: "INPUT_NEGATIVE_DEPENDENCY_CHANGED",
        summary: "A previously failed open/listing/lookup now resolves differently.",
    },
    ReasonCode {
        family: ReasonFamily::Input,
        code: "INPUT_UNDECLARED_READ_ABORT",
        summary: "Closed-view execution observed a new read; attempt aborted, re-discovery queued.",
    },
    ReasonCode {
        family: ReasonFamily::Path,
        code: "PATH_LEAK_DETECTED",
        summary: "Hidden physical/worktree path found in a visible surface; portable authority lost.",
    },
    ReasonCode {
        family: ReasonFamily::Path,
        code: "PATH_POLICY_PRESERVING_LANE",
        summary: "Build-path semantics route this action to the path-preserving lane.",
    },
    ReasonCode {
        family: ReasonFamily::Toolchain,
        code: "TOOLCHAIN_CONTRACT_MISMATCH",
        summary: "Toolchain identity differs from the entry's contract.",
    },
    ReasonCode {
        family: ReasonFamily::Platform,
        code: "PLATFORM_CLASS_MISMATCH",
        summary: "Output-platform/filesystem-semantic class does not match.",
    },
    ReasonCode {
        family: ReasonFamily::Sandbox,
        code: "SANDBOX_PROFILE_UNSUPPORTED_ON_HOST",
        summary: "Required isolation profile cannot be enforced on this host; authority reduced.",
    },
    ReasonCode {
        family: ReasonFamily::Sandbox,
        code: "SANDBOX_VOLATILE_CLASSIFICATION",
        summary: "Action classified volatile (clock/randomness/network/host identity); not shareable.",
    },
    ReasonCode {
        family: ReasonFamily::Worker,
        code: "WORKER_INADMISSIBLE_REFUSED",
        summary: "Requested/selected worker failed hard eligibility; refused, never silently swapped.",
    },
    ReasonCode {
        family: ReasonFamily::Pressure,
        code: "PRESSURE_BROWNOUT_OPTIONAL_WORK",
        summary: "Optional/speculative work suspended under pressure; foreground unaffected.",
    },
    ReasonCode {
        family: ReasonFamily::Transfer,
        code: "TRANSFER_BREAK_EVEN_LOCAL",
        summary: "Predicted remote benefit negative; executing locally.",
    },
    ReasonCode {
        family: ReasonFamily::Lease,
        code: "LEASE_EXPIRED_ATTEMPT_FENCED",
        summary: "Execution lease expired; attempt may offer blobs but cannot publish.",
    },
    ReasonCode {
        family: ReasonFamily::Authority,
        code: "AUTHORITY_STALE_TERM_REJECTED",
        summary: "Message carried a stale coordinator credential-generation/term; rejected.",
    },
    ReasonCode {
        family: ReasonFamily::Cancel,
        code: "CANCEL_SUBSCRIBER_INTEREST_RELEASED",
        summary: "One subscriber cancelled; shared action continues under retained interest.",
    },
    ReasonCode {
        family: ReasonFamily::Delivery,
        code: "DELIVERY_UNCERTAIN_FAIL_CLOSED",
        summary: "Crash between stateful commit intent and acknowledgement; no replay, no fallback.",
    },
    ReasonCode {
        family: ReasonFamily::Publication,
        code: "PUBLICATION_DIVERGENCE_QUARANTINED",
        summary: "Same-key candidate with different canonical semantic result; action quarantined.",
    },
    ReasonCode {
        family: ReasonFamily::Evidence,
        code: "EVIDENCE_TIER_INSUFFICIENT_FOR_SUBSCRIBER",
        summary: "Committed result exists but subscriber's minimum evidence tier is not met.",
    },
    ReasonCode {
        family: ReasonFamily::Storage,
        code: "STORAGE_DIGEST_COLLISION_INCIDENT",
        summary: "Existing digest resolves to different bytes; locations quarantined, publication refused.",
    },
    ReasonCode {
        family: ReasonFamily::Verify,
        code: "VERIFY_STOCK_DIFFERENTIAL_DIVERGENCE",
        summary: "Shadow/stock differential produced a divergent result; serving disabled.",
    },
    ReasonCode {
        family: ReasonFamily::Quarantine,
        code: "QUARANTINE_LOCATION_REFETCH",
        summary: "One storage location failed verification; refetching from a verified copy.",
    },
    ReasonCode {
        family: ReasonFamily::Fallback,
        code: "FALLBACK_EDGE_UNAVAILABLE_ORIGINAL_CHAIN",
        summary: "Edge unreachable within budget; wrapper ran the original tool chain.",
    },
    ReasonCode {
        family: ReasonFamily::Fallback,
        code: "FALLBACK_PRE_FRONTIER_NONPUBLISHING",
        summary: "Coordinator lost before any exposure; safe nonpublishing local fallback taken.",
    },
    ReasonCode {
        family: ReasonFamily::Fallback,
        code: "FALLBACK_UNCOORDINATED_STORM_MODE",
        summary: "Mass fail-open without fleet accounting; labeled degraded mode.",
    },
    ReasonCode {
        family: ReasonFamily::Protocol,
        code: "PROTOCOL_VERSION_UNSUPPORTED",
        summary: "Peer offered no mutually supported ATP/RABS version; explicit refusal.",
    },
    ReasonCode {
        family: ReasonFamily::Speculation,
        code: "SPECULATION_SUPERSEDED_BY_EDIT",
        summary: "A newer edit superseded the speculative snapshot; work cancelled, not promoted.",
    },
    ReasonCode {
        family: ReasonFamily::Test,
        code: "TEST_INELIGIBLE_SIDE_EFFECTS",
        summary: "Test has unrepresented side effects or suite coupling; result caching denied.",
    },
];

/// Look up a reason code by its stable string.
#[must_use]
pub fn lookup(code: &str) -> Option<&'static ReasonCode> {
    REGISTRY.iter().find(|r| r.code == code)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry_fingerprint() -> u64 {
        const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
        let mut h = FNV_OFFSET;
        for r in REGISTRY {
            for &b in r.code.as_bytes() {
                h ^= u64::from(b);
                h = h.wrapping_mul(FNV_PRIME);
            }
            h ^= 0xff;
            h = h.wrapping_mul(FNV_PRIME);
        }
        h
    }

    /// Codes are append-only: any change fails until this golden is updated
    /// deliberately in the same reviewed commit. Removing/renaming a shipped
    /// code within a protocol major version is forbidden regardless.
    #[test]
    fn registry_change_is_deliberate() {
        let fp = registry_fingerprint();
        assert_eq!(
            fp, 0x0000_0000_0000_0000,
            "reason-code registry changed (fingerprint {fp:#x}); codes are \
             append-only within a protocol major — if this change only adds \
             codes, update this golden in the same commit"
        );
    }

    #[test]
    fn every_code_carries_its_family_prefix() {
        for r in REGISTRY {
            assert!(
                r.code.starts_with(r.family.prefix()),
                "code {} does not start with its family prefix {}",
                r.code,
                r.family.prefix()
            );
        }
    }

    #[test]
    fn codes_are_unique_and_screaming_snake() {
        for (i, a) in REGISTRY.iter().enumerate() {
            assert!(
                a.code
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'),
                "code {} is not SCREAMING_SNAKE",
                a.code
            );
            for b in &REGISTRY[i + 1..] {
                assert_ne!(a.code, b.code, "duplicate reason code {}", a.code);
            }
        }
    }

    #[test]
    fn every_family_has_at_least_one_code() {
        for family in ReasonFamily::ALL {
            assert!(
                REGISTRY.iter().any(|r| r.family == family),
                "reason family {family:?} (prefix {}) has no seed codes",
                family.prefix()
            );
        }
    }

    #[test]
    fn family_prefixes_are_unambiguous() {
        // No family prefix may be a prefix of another family's prefix,
        // otherwise code->family attribution from the string is ambiguous.
        for a in ReasonFamily::ALL {
            for b in ReasonFamily::ALL {
                if a != b {
                    assert!(
                        !a.prefix().starts_with(b.prefix()),
                        "family prefix {} is shadowed by {}",
                        a.prefix(),
                        b.prefix()
                    );
                }
            }
        }
    }

    #[test]
    fn lookup_hits_and_misses() {
        assert!(lookup("FALLBACK_EDGE_UNAVAILABLE_ORIGINAL_CHAIN").is_some());
        assert!(lookup("NO_SUCH_CODE").is_none());
        let hit = lookup("PUBLICATION_DIVERGENCE_QUARANTINED").expect("registered");
        assert_eq!(hit.family, ReasonFamily::Publication);
    }

    #[test]
    fn summaries_are_nonempty() {
        for r in REGISTRY {
            assert!(!r.summary.trim().is_empty(), "{} has empty summary", r.code);
        }
    }
}
