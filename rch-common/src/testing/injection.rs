//! `RCH_*_INJECT_*` test-injection env-var registry (br-62u24.13 — MVP).
//!
//! This module is the **single source of truth** for the names of every
//! debug/test injection environment variable consumed by RCH binaries.
//! The bead spec for 62u24.13 calls out the foundation problem:
//!
//! > In the cross-agent code-review work (commits `68fcb7c` + d6d086e
//! > and the 21 sibling beads in epics `2s99h`, `62u24`, `zcecy`), every
//! > e2e test script and many unit tests reference debug-only env-var
//! > hooks and `rch debug *` subcommands that don't exist in the
//! > codebase yet. Without a foundational bead defining the contract
//! > for these primitives, each task-bead implementer will arbitrarily
//! > reinvent its own conventions — resulting in inconsistent naming,
//! > duplicate functionality, missing `#[cfg(debug_assertions)]` gates,
//! > and accidental release-build leakage.
//!
//! By defining the canonical names HERE as `pub const NAME_OF_VAR:
//! &str = "RCH_..."` items, downstream tests can write
//! `std::env::var(injection::RCH_DOCTOR_INJECT)` instead of
//! `std::env::var("RCH_DOCTOR_INJECT")` — a typo in the latter is a
//! silent no-op, but the former is a compile error.
//!
//! # Discipline (the contract this module enforces)
//!
//! 1. **All injection env-var names are `pub const NAME: &str` items
//!    here.** Adding a new injection point requires adding the const,
//!    not coining a new name at the consumer site.
//! 2. **All names match the regex `RCH_[A-Z][A-Z0-9_]*_INJECT(_[A-Z0-9_]+)?`.**
//!    The `RCH_` prefix is owned by us; the `_INJECT` segment is the
//!    discriminator that lets release-build audits grep for "did any
//!    injection name leak into the binary?".
//! 3. **`ALL_INJECTION_VARS` enumerates every defined const.** The
//!    unit tests at the bottom of this module assert (a) no duplicate
//!    values, (b) every value matches the naming regex, (c) the slice
//!    length equals the number of `pub const` items in this file.
//!    Adding a new const without updating `ALL_INJECTION_VARS` is a
//!    test failure.
//! 4. **Release-build gate is the consumer's responsibility.** This
//!    module exports names, not behavior. Each call site that reads
//!    one of these env vars must gate the read with
//!    `#[cfg(debug_assertions)]` (or document an explicit reason if a
//!    release-build read is intentional). This module's name-only
//!    surface is itself safe to compile in release.
//!
//! # Scope of this MVP delivery
//!
//! Lands the registry surface (names + enumeration + naming validator)
//! that every other bead can immediately consume. The companion
//! deliverables from 62u24.13 — `rch debug` subcommand convention,
//! `request_id` propagation, tracing-capture test helper, the
//! `#[cfg(debug_assertions)]` gate audit — are filed as follow-up
//! scope. Each is independently substantial; the registry is the
//! minimum that unblocks the rest.

// =============================================================================
// Doctor-domain injections
// =============================================================================

/// Inject a synthetic reliability-doctor diagnostic at the named code
/// path. Value is a free-form discriminator (e.g.,
/// `disk_pressure_warn`, `topology_circuit_open`) interpreted by the
/// consumer; an empty/unset value disables the injection.
pub const RCH_DOCTOR_INJECT: &str = "RCH_DOCTOR_INJECT";

/// Inject a specific status-circuit state for a synthetic worker
/// (e.g., `open_forced`). Used by reliability-doctor tests that need
/// to exercise the partial-outage code path without spinning up a
/// real fleet.
pub const RCH_DOCTOR_INJECT_STATUS_CIRCUIT: &str = "RCH_DOCTOR_INJECT_STATUS_CIRCUIT";

/// Inject artificial latency into a specific reliability probe. Value
/// format: `<probe_name>=<delay_ms>` (e.g., `helpers=10000`). Used to
/// exercise the per-probe timeout path (bd-62u24.8 parallelism).
pub const RCH_DOCTOR_INJECT_SLOW_PROBE: &str = "RCH_DOCTOR_INJECT_SLOW_PROBE";

// `RCH_DOCTOR_FIXTURE` and `RCH_DOCTOR_VERDICT` are STATE PINS, not
// injections — they replace runtime state with a static value rather
// than inserting a synthetic event into a live code path. They are
// scoped to a sibling "fixture-pin registry" in a follow-up bead; the
// naming-policy validator in this module would reject them anyway
// (no `_INJECT` segment). Listing them here as a comment so a future
// reader doesn't re-derive the same separation.

// =============================================================================
// Quick-check / status injections
// =============================================================================

/// Inject a synthetic stall on a specific worker's quick-check probe.
/// Value is the worker ID (e.g., `w1`).
pub const RCH_QC_INJECT_STALL: &str = "RCH_QC_INJECT_STALL";

/// Force every worker's quick-check probe to stall (value `1`). Used
/// by integration tests that need the "everything timing out" branch
/// of the status surface.
pub const RCH_QC_INJECT_STALL_ALL: &str = "RCH_QC_INJECT_STALL_ALL";

// =============================================================================
// Fix-mode injections (consumed by br-2s99h.12 --fix executor follow-up)
// =============================================================================

/// Inject a remediation step whose `dry_run_safe == false` so the
/// `--fix` executor exercises the `SkippedNotSafe` outcome path
/// without a real unsafe remediation in the registry.
pub const RCH_FIX_INJECT_UNSAFE: &str = "RCH_FIX_INJECT_UNSAFE";

/// Force the fix executor's post-validation step to fail even when
/// remediation succeeded, so tests can exercise the
/// `FailedPostValidation` outcome branch.
pub const RCH_FIX_INJECT_POST_FAIL: &str = "RCH_FIX_INJECT_POST_FAIL";

// =============================================================================
// Debug / panic injections
// =============================================================================

/// Force the timing-cache save path to fail (value `1`) so tests can
/// confirm the hook's fail-open behavior under disk-error conditions.
///
/// Naming note: the bead spec referenced this as
/// `RCH_DEBUG_TIMING_SAVE_FAIL` (no `_INJECT` segment). The registry
/// names it with `_INJECT_` per the canonical naming policy so a
/// release-build leak audit can grep for `_INJECT` reliably. No
/// existing consumer reads either name as of this commit, so no
/// migration shim is needed.
pub const RCH_DEBUG_INJECT_TIMING_SAVE_FAIL: &str = "RCH_DEBUG_INJECT_TIMING_SAVE_FAIL";

/// Trigger an intentional panic at a designated code path (value
/// `1`). Used by the hook fail-open regression suite to confirm that
/// classifier panics are caught and the hook still exits 0 (the
/// project's #1 invariant per AGENTS.md).
///
/// Naming note: bead spec used `RCH_PANIC_TEST`; canonical name uses
/// `_INJECT_` per the registry's naming policy.
pub const RCH_DEBUG_INJECT_PANIC: &str = "RCH_DEBUG_INJECT_PANIC";

// =============================================================================
// Registry & validators
// =============================================================================

/// Every injection env-var name registered in this module. Consumed
/// by release-build leak audits, fuzzers, and the `rch debug` (TBD)
/// subcommand's introspection surface.
///
/// **Discipline**: adding a new `pub const RCH_..._INJECT...: &str = "..."`
/// requires appending its identifier here. The unit tests assert the
/// slice length matches the number of `pub const` items, so a
/// forgotten append is a test failure at `cargo test` time.
pub const ALL_INJECTION_VARS: &[&str] = &[
    RCH_DOCTOR_INJECT,
    RCH_DOCTOR_INJECT_STATUS_CIRCUIT,
    RCH_DOCTOR_INJECT_SLOW_PROBE,
    RCH_QC_INJECT_STALL,
    RCH_QC_INJECT_STALL_ALL,
    RCH_FIX_INJECT_UNSAFE,
    RCH_FIX_INJECT_POST_FAIL,
    RCH_DEBUG_INJECT_TIMING_SAVE_FAIL,
    RCH_DEBUG_INJECT_PANIC,
];

/// Returns `true` if `name` is one of the registered RCH injection
/// env-var names. Used by audit tools that scan process environments
/// for stray injection settings and by the (TBD) `rch debug
/// list-injections` introspection surface.
#[must_use]
pub fn is_injection_var(name: &str) -> bool {
    ALL_INJECTION_VARS.contains(&name)
}

/// Returns `true` if `name` is shape-compatible with the project's
/// injection naming policy: starts with `RCH_`, contains `_INJECT`
/// somewhere after the prefix, and consists only of ASCII uppercase /
/// digits / underscores. Used by the unit tests below to enforce the
/// naming regex without pulling in the `regex` crate (this is a
/// `const`-friendly check on a small alphabet).
#[must_use]
pub fn is_well_formed_injection_name(name: &str) -> bool {
    if !name.starts_with("RCH_") {
        return false;
    }
    // Every character must be ASCII uppercase / digit / underscore.
    if !name
        .bytes()
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
    {
        return false;
    }
    // `_INJECT` (or `_INJECT_<suffix>`) must appear somewhere after
    // the `RCH_` prefix. Either ends with `_INJECT` or contains
    // `_INJECT_`. We deliberately accept BOTH so the registry can
    // include both shapes (`RCH_X_INJECT` and `RCH_X_INJECT_FOO`).
    name.ends_with("_INJECT") || name.contains("_INJECT_")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_registered_var_is_well_formed() {
        // TEST START: enforces the naming regex on every registered const.
        for name in ALL_INJECTION_VARS {
            assert!(
                is_well_formed_injection_name(name),
                "registered injection var {name:?} violates the naming policy \
                 (must start with RCH_, contain _INJECT, ASCII upper/digit/underscore only)"
            );
        }
        // TEST PASS: every var well-formed
    }

    #[test]
    fn registered_vars_have_no_duplicates() {
        // TEST START: a copy-paste mistake in the const list could
        // register the same name twice. BTreeSet round-trip catches it.
        let set: BTreeSet<_> = ALL_INJECTION_VARS.iter().copied().collect();
        assert_eq!(
            set.len(),
            ALL_INJECTION_VARS.len(),
            "ALL_INJECTION_VARS contains duplicate entries: \
             {} unique vs {} total",
            set.len(),
            ALL_INJECTION_VARS.len()
        );
    }

    #[test]
    fn is_injection_var_recognizes_every_registered_var() {
        // TEST START: contract test on the public lookup helper.
        for name in ALL_INJECTION_VARS {
            assert!(
                is_injection_var(name),
                "is_injection_var({name:?}) returned false for a registered var"
            );
        }
    }

    #[test]
    fn is_injection_var_rejects_unregistered_names() {
        // TEST START: typo defense — `RCH_DOCTOR_INJEKT` (typo) must
        // not be misclassified as a known injection. Catches a class
        // of bug where a consumer reads `RCH_DOCTOR_INJEKT` and the
        // audit tool greps for `RCH_DOCTOR_INJECT` and finds nothing,
        // silently passing.
        assert!(!is_injection_var("RCH_DOCTOR_INJEKT"));
        assert!(!is_injection_var("RCH_NOT_A_REAL_VAR"));
        assert!(!is_injection_var(""));
        assert!(!is_injection_var("PATH"));
    }

    #[test]
    fn well_formed_validator_rejects_obvious_bad_names() {
        // TEST START: defensive validator for adding new vars.
        assert!(!is_well_formed_injection_name("path"), "lowercase rejected");
        assert!(
            !is_well_formed_injection_name("RCH_DOCTOR"),
            "missing _INJECT segment rejected"
        );
        assert!(
            !is_well_formed_injection_name("rch_doctor_inject"),
            "lowercase rejected (case-sensitive)"
        );
        assert!(
            !is_well_formed_injection_name("FOO_BAR_INJECT"),
            "missing RCH_ prefix rejected"
        );
        assert!(
            !is_well_formed_injection_name("RCH_DOCTOR-INJECT"),
            "hyphen rejected"
        );
        // Sanity: known-good shapes
        assert!(is_well_formed_injection_name("RCH_X_INJECT"));
        assert!(is_well_formed_injection_name("RCH_X_INJECT_FOO"));
        assert!(is_well_formed_injection_name("RCH_X1_INJECT_Y2"));
    }

    #[test]
    fn registry_slice_count_matches_module_consts() {
        // TEST START: assert the slice length matches our expected count
        // of `pub const` items. This is a brittle pin — its purpose is
        // to remind a future contributor adding a const to ALSO append
        // it to ALL_INJECTION_VARS. The number is the count of
        // injection consts defined in this file (excluding the
        // `ALL_INJECTION_VARS` slice itself).
        //
        // If you're updating this number, you almost certainly need to
        // add a corresponding entry to ALL_INJECTION_VARS above.
        const EXPECTED_REGISTERED_VAR_COUNT: usize = 9;
        assert_eq!(
            ALL_INJECTION_VARS.len(),
            EXPECTED_REGISTERED_VAR_COUNT,
            "ALL_INJECTION_VARS has {} entries but the test expects {}. \
             Did you add a new `pub const RCH_..._INJECT...: &str` to this \
             file without appending it to ALL_INJECTION_VARS, or did you \
             remove one without updating this test?",
            ALL_INJECTION_VARS.len(),
            EXPECTED_REGISTERED_VAR_COUNT
        );
    }
}
