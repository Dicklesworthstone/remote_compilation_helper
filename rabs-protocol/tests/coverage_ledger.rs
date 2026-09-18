//! Live ATP/RABS coverage ledger, regenerated from compiled test
//! metadata (bead T001; Asupersync blocker 44.7).
//!
//! The ledger (`docs/rabs-coverage-ledger.md`) is NEVER maintained by
//! hand: this test scans every test-bearing source file in the RABS
//! crates, extracts the coverage markers (bead/risk/invariant IDs) and
//! `#[test]` counts, and holds the committed file to them. A production
//! cutover reading the ledger therefore reads scanned fact, not a stale
//! PLANNED row — and a `PLANNED` row is itself a failure.
//!
//! The committed counts are a **floor**, not a snapshot (bd-b3ap9): a
//! crate dropping below them, or losing a marker the ledger claims,
//! fails; adding tests does not. Exact equality made every agent's test
//! addition red the suite for whoever ran next, and a gate that fails
//! for unrelated reasons is one people learn to regenerate without
//! reading. The file may lag reality, which is the safe direction — it
//! undercounts, never overstates.
//!
//! To refresh the floor:
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
         These counts are a FLOOR, not a snapshot: the suite fails if a\n\
         crate drops below them or loses a marker listed here, and passes\n\
         silently when tests are added, so concurrent work cannot red the\n\
         gate. The file may therefore lag reality — it undercounts, never\n\
         overstates. To refresh the floor:\n\
         `RABS_REGENERATE_COVERAGE_LEDGER=1 cargo test -p rabs-protocol\n\
         --test coverage_ledger`.\n\n\
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

/// One committed row: the floor a crate must still clear.
struct LedgerFloor {
    crate_name: String,
    tests: usize,
    markers: BTreeSet<String>,
}

/// Parse the committed ledger's table rows.
///
/// Returns only well-formed `| crate | count | markers |` rows, so a
/// mangled file yields no floor and the emptiness check below fails
/// loudly rather than silently admitting everything.
fn parse_floor(committed: &str) -> Vec<LedgerFloor> {
    committed
        .lines()
        .filter(|line| line.starts_with("| ") && !line.starts_with("|---"))
        .filter_map(|line| {
            let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
            let [name, tests, markers] = cells.as_slice() else {
                return None;
            };
            let tests = tests.parse::<usize>().ok()?;
            Some(LedgerFloor {
                crate_name: (*name).to_owned(),
                tests,
                markers: markers
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect::<BTreeSet<String>>(),
            })
        })
        .collect()
}

#[test]
fn the_ledger_never_overstates_coverage_and_coverage_never_disappears() {
    // THE acceptance, stated as a FLOOR rather than as equality.
    //
    // Exact equality was unmaintainable here and, worse, misleading. A
    // dozen agents add tests to these crates concurrently, so the
    // committed file was invalidated by work unrelated to whoever ran the
    // suite next: this file was already stale on arrival (four crates, ~40
    // tests, none of them the committer's) and went stale again twenty
    // minutes after being regenerated. A gate that fails for reasons
    // unrelated to the change under test is one people learn to regenerate
    // reflexively without reading — which is exactly how a real coverage
    // regression would pass through the gate that exists to catch it
    // (bd-b3ap9).
    //
    // What the ledger is FOR survives intact, and is now stated directly:
    //
    //   1. It must never OVERSTATE coverage. A production cutover reading
    //      it must not be told there are more tests or markers than exist.
    //      Lagging behind reality is the safe direction — an undercount is
    //      conservative, an overcount is a lie.
    //   2. Coverage must never DISAPPEAR. Every marker the ledger claims
    //      must still be found by the scan, and no crate may lose tests.
    //
    // Additions therefore pass silently (they only make the floor more
    // conservative) while deletions still fail. Refresh the floor with:
    // `RABS_REGENERATE_COVERAGE_LEDGER=1 cargo test -p rabs-protocol
    // --test coverage_ledger`.
    let path = workspace_root().join(LEDGER_PATH);
    if std::env::var_os("RABS_REGENERATE_COVERAGE_LEDGER").is_some() {
        std::fs::write(&path, generate()).expect("write ledger");
        return;
    }

    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    let floor = parse_floor(&committed);
    assert_eq!(
        floor.len(),
        CRATES.len(),
        "the committed ledger must carry one parseable row per crate; \
         regenerate with RABS_REGENERATE_COVERAGE_LEDGER=1"
    );

    let root = workspace_root();
    for row in &floor {
        let (tests, markers) = scan_crate(&root, &row.crate_name);
        if let Err(violation) = check_floor(row, tests, &markers) {
            panic!("{violation}");
        }
    }
}

/// Hold one crate to its committed floor.
///
/// Pure, so the gate's teeth can be tested directly: a floor check that
/// is never shown to FAIL is indistinguishable from no gate at all, and
/// the whole point of replacing exact equality was to keep the teeth
/// while dropping the noise.
///
/// # Errors
/// A message naming the crate and what it lost.
fn check_floor(
    row: &LedgerFloor,
    scanned_tests: usize,
    scanned_markers: &BTreeSet<String>,
) -> Result<(), String> {
    if scanned_tests < row.tests {
        return Err(format!(
            "{} lost coverage: the ledger claims {} test fns, the scan finds \
             {scanned_tests}. Tests were deleted, or the ledger overstates \
             reality — either way it must not be refreshed without explaining \
             the drop.",
            row.crate_name, row.tests
        ));
    }
    let lost: Vec<&str> = row
        .markers
        .difference(scanned_markers)
        .map(String::as_str)
        .collect();
    if !lost.is_empty() {
        return Err(format!(
            "{} no longer covers markers the ledger claims: {lost:?}",
            row.crate_name
        ));
    }
    Ok(())
}

#[test]
fn the_floor_still_bites_on_deleted_tests_and_lost_markers() {
    let row = LedgerFloor {
        crate_name: "rabs-example".to_owned(),
        tests: 10,
        markers: ["F010", "R121"].iter().map(|m| (*m).to_owned()).collect(),
    };
    let covered: BTreeSet<String> = ["F010", "R121", "I52"]
        .iter()
        .map(|m| (*m).to_owned())
        .collect();

    // Equal to the floor passes; ABOVE it passes, which is the whole
    // point — concurrent test additions must never red this gate.
    assert!(check_floor(&row, 10, &covered).is_ok());
    assert!(check_floor(&row, 10_000, &covered).is_ok());

    // One deleted test still fails, and the message names the drop.
    let dropped = check_floor(&row, 9, &covered).expect_err("a lost test must fail the floor");
    assert!(dropped.contains("lost coverage"), "{dropped}");
    assert!(dropped.contains("claims 10"), "{dropped}");

    // A marker that stops being covered still fails even when the test
    // COUNT went up — the case exact equality could not distinguish from
    // ordinary growth.
    let without_marker: BTreeSet<String> = ["F010", "I52", "T999"]
        .iter()
        .map(|m| (*m).to_owned())
        .collect();
    let lost = check_floor(&row, 50, &without_marker)
        .expect_err("a marker that lost its coverage must fail the floor");
    assert!(lost.contains("R121"), "{lost}");
}

#[test]
fn a_mangled_ledger_yields_no_floor_rather_than_an_empty_pass() {
    // A hand-edited or truncated table must not silently admit
    // everything: unparseable rows produce no floor, and the gate's
    // row-count assertion then fails loudly.
    assert!(parse_floor("not a table at all").is_empty());
    assert!(parse_floor("| rabs-protocol | not-a-number | F010 |").is_empty());
    let good = parse_floor("| rabs-protocol | 12 | F010 R121 |");
    assert_eq!(good.len(), 1);
    assert_eq!(good[0].tests, 12);
    assert_eq!(good[0].markers.len(), 2);
    // A crate with no markers yet is still a valid, parseable floor.
    let empty_markers = parse_floor("| rabs-new | 3 |  |");
    assert_eq!(empty_markers.len(), 1);
    assert!(empty_markers[0].markers.is_empty());
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
