//! Unsafe-boundary ledger currency check (bead A011).
//!
//! `docs/rabs-unsafe-boundary-ledger.md` must gain an entry in the SAME
//! change that introduces or modifies a privileged helper. This test makes
//! the ledger's existence and structure non-optional, and fails when a
//! known privileged-helper location appears without the ledger naming it.
//!
//! The helper-location list below is the enforcement seam: beads D003/D013/
//! E005/E017 must extend it as they add real helpers (the ledger doc's
//! "expected entrants" table mirrors it).

use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn ledger() -> String {
    let path = workspace_root().join("docs/rabs-unsafe-boundary-ledger.md");
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("unsafe-boundary ledger missing at {}: {e}", path.display()))
}

/// Directories that, if they ever exist, contain privileged helpers and
/// therefore REQUIRE a ledger entry naming them. Extend in the same change
/// that creates the directory.
const PRIVILEGED_HELPER_DIRS: &[&str] = &[
    "rabs-sandbox/helpers",
    "rabs-sandbox/privileged",
    "rabs-helpers",
];

#[test]
fn ledger_exists_with_required_structure() {
    let text = ledger();
    for required in [
        "## Entry contract",
        "Protocol bounds",
        "Blast radius",
        "Fuzz status",
        "Deletion condition",
        "## Entries",
        "## Change log",
    ] {
        assert!(
            text.contains(required),
            "ledger is missing required section/field marker: {required}"
        );
    }
}

#[test]
fn ledger_is_current() {
    let text = ledger();
    for dir in PRIVILEGED_HELPER_DIRS {
        let path = workspace_root().join(dir);
        if path.exists() {
            assert!(
                text.contains(dir),
                "privileged helper location `{dir}` exists but the \
                 unsafe-boundary ledger has no entry naming it; add the \
                 six-field entry in the SAME change (bead A011)"
            );
        }
    }
}

#[test]
fn library_crates_still_forbid_unsafe_code() {
    // The ledger only works if privileged code CANNOT hide in libraries:
    // every rabs crate manifest must keep unsafe_code = "forbid".
    for krate in [
        "rabs-protocol",
        "rabs-action",
        "rabs-key",
        "rabs-cas",
        "rabs-sandbox",
        "rabs-scheduler",
        "rabs-asupersync",
        "rabsd",
        "rabs-wkr",
    ] {
        let manifest = fs::read_to_string(workspace_root().join(krate).join("Cargo.toml"))
            .unwrap_or_else(|e| panic!("read {krate}/Cargo.toml: {e}"));
        assert!(
            manifest.contains(r#"unsafe_code = "forbid""#),
            "`{krate}` no longer forbids unsafe_code; privileged operations \
             must live in ledgered helper binaries, not in libraries"
        );
    }
}
