//! Live ATP/RABS coverage ledger, regenerated from compiled test
//! metadata (bead T001; Asupersync blocker 44.7).
//!
//! The ledger (`docs/rabs-coverage-ledger.md`) is NEVER maintained by
//! hand: this test scans every test-bearing source file in the RABS
//! crates, extracts the coverage markers (bead/risk/invariant IDs)
//! and `#[test]` counts, regenerates the ledger content, and FAILS on
//! any drift between the committed ledger and compiled reality. A
//! production cutover reading the ledger therefore reads scanned
//! fact, not a stale PLANNED row — and a `PLANNED` row is itself a
//! failure.
//!
//! To regenerate after adding tests:
//! `RABS_REGENERATE_COVERAGE_LEDGER=1 cargo test -p rabs-protocol --test coverage_ledger`

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const CRATES: [&str; 7] = [
    "rabs-protocol",
    "rabs-key",
    "rabs-action",
    "rabs-cas",
    "rabs-sandbox",
    "rabs-scheduler",
    "rabs-asupersync",
];

const LEDGER_PATH: &str = "docs/rabs-coverage-ledger.md";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

/// Coverage markers: tokens like `F010`, `R121`, `I52` — an
/// uppercase letter followed by 1..=3 digits, taken from test-bearing
/// files (the IDs the plan's beads/risks/invariants use).
fn markers_in(text: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_ascii_uppercase() {
            // Preceding char must not be alphanumeric (token start).
            let start_ok = i == 0 || !(bytes[i - 1] as char).is_ascii_alphanumeric();
            let mut j = i + 1;
            while j < bytes.len() && (bytes[j] as char).is_ascii_digit() {
                j += 1;
            }
            let digits = j - i - 1;
            let end_ok = j == bytes.len() || !(bytes[j] as char).is_ascii_alphabetic();
            if start_ok && end_ok && (2..=3).contains(&digits) {
                found.insert(text[i..j].to_owned());
            }
            i = j;
        } else {
            i += 1;
        }
    }
    found
}

/// Scan one crate: (test function count, markers) over every
/// test-bearing `.rs` file in `src/` and `tests/`.
fn scan_crate(root: &Path, name: &str) -> (usize, BTreeSet<String>) {
    let mut tests = 0;
    let mut markers = BTreeSet::new();
    for sub in ["src", "tests"] {
        let dir = root.join(name).join(sub);
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut paths: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "rs"))
            .collect();
        paths.sort();
        for path in paths {
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let file_tests = text.matches("#[test]").count();
            if file_tests == 0 {
                continue; // only test-bearing files feed the ledger
            }
            tests += file_tests;
            markers.extend(markers_in(&text));
        }
    }
    (tests, markers)
}

/// Regenerate the ledger content from scanned reality.
fn generate() -> String {
    let root = workspace_root();
    let mut out = String::new();
    out.push_str(
        "# RABS Coverage Ledger (auto-generated — bead T001)\n\n\
         Regenerated from compiled test metadata by\n\
         `rabs-protocol/tests/coverage_ledger.rs`; NEVER edit by hand.\n\
         Drift between this file and the scanned tests fails CI. To\n\
         refresh: `RABS_REGENERATE_COVERAGE_LEDGER=1 cargo test -p\n\
         rabs-protocol --test coverage_ledger`.\n\n\
         | Crate | Test fns | Coverage markers (bead/risk/invariant IDs) |\n\
         |---|---|---|\n",
    );
    let mut total_tests = 0;
    let mut all_markers: BTreeSet<String> = BTreeSet::new();
    for name in CRATES {
        let (tests, markers) = scan_crate(&root, name);
        total_tests += tests;
        all_markers.extend(markers.iter().cloned());
        let list: Vec<&str> = markers.iter().map(String::as_str).collect();
        out.push_str(&format!("| {name} | {tests} | {} |\n", list.join(" ")));
    }
    out.push_str(&format!(
        "\n**Totals:** {total_tests} test fns across {} crates; {} distinct markers.\n",
        CRATES.len(),
        all_markers.len()
    ));
    out
}

#[test]
fn the_ledger_matches_compiled_reality_or_fails() {
    // THE acceptance: the committed ledger equals the regenerated
    // one; drift fails with the refresh command.
    let expected = generate();
    let path = workspace_root().join(LEDGER_PATH);
    if std::env::var_os("RABS_REGENERATE_COVERAGE_LEDGER").is_some() {
        std::fs::write(&path, &expected).expect("write ledger");
        return;
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(
        committed, expected,
        "docs/rabs-coverage-ledger.md is stale: regenerate with \
         RABS_REGENERATE_COVERAGE_LEDGER=1 cargo test -p rabs-protocol \
         --test coverage_ledger"
    );
}

#[test]
fn the_ledger_carries_no_planned_rows() {
    // The blocker-44.7 rule: hand-maintained PLANNED rows that can
    // disagree with reality are prohibited outright.
    let committed = std::fs::read_to_string(workspace_root().join(LEDGER_PATH)).unwrap_or_default();
    assert!(
        !committed.contains("PLANNED"),
        "the ledger may only contain scanned fact, never PLANNED rows"
    );
}

#[test]
fn the_scanner_actually_sees_the_fleet() {
    // Sanity floor: the scan must find substantial real coverage —
    // a broken scanner producing an empty ledger must not pass.
    let root = workspace_root();
    let mut total = 0;
    for name in CRATES {
        let (tests, _) = scan_crate(&root, name);
        assert!(tests > 0, "{name} must have test-bearing files");
        total += tests;
    }
    assert!(total > 400, "the fleet has hundreds of tests; saw {total}");
    // And the marker extractor recognizes the three ID shapes.
    let m = markers_in("bead F010, risk R121, invariant I52, not f10 or ABC1234x");
    assert!(m.contains("F010") && m.contains("R121") && m.contains("I52"));
    assert!(!m.contains("ABC1234"));
}
