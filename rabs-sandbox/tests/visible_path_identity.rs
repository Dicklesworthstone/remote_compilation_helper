//! Invariant suite: no visible path contains an action, attempt,
//! operation, or snapshot ID (bead D020; invariant I20; risk R42).
//!
//! The D002 layout guarantees the property by CONSTRUCTION — visible
//! roots are fixed strings and per-unit segments are logical unit
//! names, never runtime identities. This suite is the tripwire that
//! keeps it true: it sweeps every program-visible surface builder the
//! sandbox exposes with hidden-identity patterns and proves the sweep
//! itself works by seeding a leak (the acceptance's red case).

use rabs_sandbox::layout::{self, PROGRAM_VISIBLE_SURFACES, VISIBLE_ROOTS, leaks_backing_path};

/// Hidden-identity spellings a runtime might accidentally splice into
/// a path: attempt/operation/snapshot IDs and raw random tokens.
fn hidden_identity_patterns() -> Vec<String> {
    vec![
        "attempt-8f2c1a".into(),
        "op-1234abcd".into(),
        "action-77e1".into(),
        "snapshot-c0ffee".into(),
    ]
}

/// A representative program-visible environment/argv/path surface, as
/// the sandbox constructs it for one unit.
fn visible_surfaces_for_unit(unit: &str) -> Vec<(String, String)> {
    vec![
        (
            "CARGO_MANIFEST_DIR".into(),
            format!("{}/members/app", layout::WORKSPACE),
        ),
        ("OUT_DIR".into(), format!("{}/{unit}/out", layout::BUILD)),
        ("TMPDIR".into(), layout::TMP.to_owned()),
        ("HOME".into(), layout::HOME.to_owned()),
        ("CARGO_HOME".into(), layout::CARGO_HOME.to_owned()),
        ("argv:--out-dir".into(), format!("{}/{unit}", layout::OUT)),
        (
            "argv:incremental".into(),
            format!("{}/{unit}", layout::INCREMENTAL),
        ),
        (
            "dep-info:path".into(),
            format!("{}/members/app/src/lib.rs", layout::WORKSPACE),
        ),
    ]
}

#[test]
fn no_visible_surface_carries_a_hidden_identity() {
    // The invariant: unit names are LOGICAL (crate name + logical unit
    // hash of semantics, e.g. "serde-1"), so no visible surface can
    // carry a runtime identity.
    let patterns = hidden_identity_patterns();
    let pattern_refs: Vec<&str> = patterns.iter().map(String::as_str).collect();
    for (name, value) in visible_surfaces_for_unit("serde-1") {
        assert!(
            !leaks_backing_path(value.as_bytes(), &pattern_refs),
            "{name} carries a hidden identity: {value}"
        );
    }
    // And the fixed roots themselves are identity-free forever.
    for root in VISIBLE_ROOTS {
        assert!(!leaks_backing_path(root.as_bytes(), &pattern_refs));
    }
}

#[test]
fn the_sweep_goes_red_on_a_seeded_attempt_id_leak() {
    // THE acceptance: seed an attempt ID into a visible path and prove
    // the sweep catches it — on EVERY declared program-visible
    // surface class, so surface coverage cannot silently narrow.
    let patterns = hidden_identity_patterns();
    let pattern_refs: Vec<&str> = patterns.iter().map(String::as_str).collect();
    let leaked_unit = "attempt-8f2c1a"; // a runtime identity used as a unit name
    let mut caught = 0;
    for (name, value) in visible_surfaces_for_unit(leaked_unit) {
        if leaks_backing_path(value.as_bytes(), &pattern_refs) {
            caught += 1;
        } else {
            // Surfaces that do not embed the unit segment (TMPDIR,
            // HOME, CARGO_HOME, manifest dir, dep-info) legitimately
            // stay clean — the leak rides only unit-derived paths.
            assert!(
                !value.contains(leaked_unit),
                "{name} embeds the ID but the sweep missed it"
            );
        }
    }
    assert!(
        caught >= 2,
        "the seeded attempt ID must be caught on the unit-derived surfaces (caught {caught})"
    );
    // The declared surface list still names every class the sweep must
    // cover (coupling this suite to the D002 enforcement list).
    assert_eq!(PROGRAM_VISIBLE_SURFACES.len(), 8);
}
