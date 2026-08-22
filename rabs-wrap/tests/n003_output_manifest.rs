//! N003 end-to-end completeness proof: the output manifest captured from
//! a REAL cargo build matches the on-disk OUT_DIR tree exactly, and a
//! genuine deletion between captures surfaces as an explicit tombstone
//! (bead rabs-root-4pidu.32.3).
//!
//! Deletion realism: cargo does NOT manage OUT_DIR contents — removing
//! a generated file after the first build is never undone by a later
//! no-op build, so the second capture legitimately lacks it. The diff
//! must name that path as a first-class [`TreeDeltaRow::Removed`]
//! tombstone, not silently shrink.
//!
//! Victim choice matters: the fixture generates an INCLUDED unit
//! (`gen.rs`) plus a side-data file NOT referenced by the crate.
//! Deleting the included file would break subsequent builds once cargo
//! re-fingerprints; the unreferenced side-data file is the safe,
//! honest victim.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use rabs_protocol::output_manifest::{
    OutputEntry, OutputSection, OutputTreeManifest, TreeDeltaRow, diff_manifests, has_tombstones,
};

const FIXTURE_NAME: &str = "n003_probe";
/// Deletion victim: present in OUT_DIR, deliberately NOT referenced by
/// the crate (deleting an INCLUDED file would break later builds).
const DELETION_VICTIM_REL: &[u8] = b"out/side_data.bin";
/// Hard deadline per cargo invocation.
const CARGO_PHASE_BUDGET_SECS: u64 = 180;

#[test]
fn n003_output_manifest_captures_tree_and_names_deletions() {
    let channel = first_available_channel();
    let dir = tempfile::tempdir().expect("scratch dir");
    let project = copy_fixture(dir.path());

    // Build 1: fresh stock build producing OUT_DIR artifacts.
    let outcome = run_bounded(stock_cargo(&channel, &project));
    assert!(
        outcome.success && !outcome.timed_out,
        "fresh build failed: {}",
        outcome.stderr_tail
    );
    let Some(run_dir) = find_run_dir(&project) else {
        panic!("run dir not found after fresh build");
    };

    // CAPTURE 1: full tree walk — OUT_DIR subtree + run-root cache files.
    let before = capture_manifest(&run_dir);

    // Completeness direction 1: walked paths == manifest section.
    let raw_out = walk_files(&run_dir.join("out"), "out");
    let raw_cache = walk_cache_files(&run_dir);
    assert_eq!(
        before.section(OutputSection::OutDir),
        sorted_entries(&raw_out),
        "OUT_DIR section must be complete"
    );
    assert_eq!(
        before.section(OutputSection::OutputCache),
        sorted_entries(&raw_cache),
        "cache section must be complete"
    );

    // THE DELETION: remove the side-data file. Cargo will NOT restore it
    // (rerun-if-changed=build.rs only), and the crate still compiles.
    let victim = run_dir.join(std::path::Path::new(
        std::str::from_utf8(DELETION_VICTIM_REL).expect("victim rel is UTF-8"),
    ));
    assert!(victim.is_file(), "victim must exist pre-deletion");
    fs::remove_file(&victim).expect("delete generated output");

    // Build 2: succeeds WITHOUT regenerating the deleted file.
    let outcome2 = run_bounded(stock_cargo(&channel, &project));
    assert!(
        outcome2.success && !outcome2.timed_out,
        "second build failed: {}",
        outcome2.stderr_tail
    );
    let after = capture_manifest(&run_dir);
    assert!(
        !victim.exists(),
        "precondition: deletion was not restored by cargo"
    );

    // THE ACCEPTANCE: the delta names the deletion explicitly.
    let rows = diff_manifests(&before, &after).expect("valid manifests");
    assert!(
        has_tombstones(&rows),
        "a real deletion must produce a tombstone"
    );
    assert!(rows.iter().any(|r| matches!(
        r,
        TreeDeltaRow::Removed {
            last_entry,
            section: OutputSection::OutDir,
        } if last_entry.path == DELETION_VICTIM_REL
    )));
}

// --- Bounded execution -------------------------------------------------------

struct RunOutcome {
    success: bool,
    timed_out: bool,
    stderr_tail: String,
}

fn run_bounded(mut cmd: Command) -> RunOutcome {
    let mut child = cmd
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn cargo");
    let deadline = Instant::now() + Duration::from_secs(CARGO_PHASE_BUDGET_SECS);
    loop {
        match child.try_wait().expect("poll cargo") {
            Some(status) => {
                let mut err = String::new();
                if let Some(mut pipe) = child.stderr.take() {
                    let _ = pipe.read_to_string(&mut err);
                }
                let lines: Vec<&str> = err.lines().collect();
                let tail = lines
                    .iter()
                    .rev()
                    .take(5)
                    .rev()
                    .copied()
                    .collect::<Vec<_>>()
                    .join("\n");
                return RunOutcome {
                    success: status.success(),
                    timed_out: false,
                    stderr_tail: tail,
                };
            }
            None if Instant::now() > deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return RunOutcome {
                    success: false,
                    timed_out: true,
                    stderr_tail: String::new(),
                };
            }
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

fn stock_cargo(channel: &str, cwd: &Path) -> Command {
    let mut cmd = Command::new(channel);
    cmd.arg("build")
        .current_dir(cwd)
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("CARGO_BUILD_TARGET_DIR")
        .env_remove("RUSTUP_TOOLCHAIN");
    cmd
}

fn first_available_channel() -> String {
    const PREFERRED: [&str; 3] = ["nightly", "beta", "stable"];
    let rustup_ok = Command::new("rustup")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if rustup_ok {
        for name in PREFERRED {
            let Ok(out) = Command::new("rustup")
                .args(["which", "cargo", "--toolchain", name])
                .output()
            else {
                continue;
            };
            if out.status.success() {
                let path = String::from_utf8_lossy(&out.stdout).trim().to_owned();
                if !path.is_empty() {
                    return path;
                }
            }
        }
    }
    "cargo".to_owned()
}

// --- Fixture staging -------------------------------------------------------

fn copy_fixture(scratch: &Path) -> PathBuf {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/n003_out_dir");
    let project = scratch.join(FIXTURE_NAME);
    fs::create_dir_all(project.join("src")).expect("mkdir src");
    for rel in ["Cargo.toml", "build.rs", "src/lib.rs"] {
        fs::copy(src.join(rel), project.join(rel)).expect("copy fixture file");
    }
    project
}

// --- Layout discovery (content-identified, both vintages) --------------------

fn all_build_dirs(root: &Path) -> Vec<PathBuf> {
    fn visit(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                out.push(p.clone());
                if depth < 1 {
                    visit(&p, depth + 1, out);
                }
            }
        }
    }
    let mut out = Vec::new();
    if root.is_dir() {
        visit(root, 0, &mut out);
    }
    out.sort();
    out
}

fn directive_cache_present(run_dir: &Path) -> bool {
    run_dir.join("run/stdout").is_file() || run_dir.join("output").is_file()
}

fn find_run_dir(project: &Path) -> Option<PathBuf> {
    all_build_dirs(&project.join("target/debug/build"))
        .into_iter()
        .find(|d| d.join("out").is_dir() && directive_cache_present(d))
}

// --- Tree walking ------------------------------------------------------------

/// Recursively collect `(rel_path, len)` for every FILE under `root`,
/// prefixed with `prefix`.
fn walk_files(root: &Path, prefix: &str) -> Vec<(Vec<u8>, u64)> {
    let mut out = Vec::new();
    visit_files(root, prefix.as_bytes(), &mut out);
    out.sort();
    out
}

fn visit_files(dir: &Path, rel: &[u8], out: &mut Vec<(Vec<u8>, u64)>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        let name = entry.file_name();
        let mut child_rel = rel.to_vec();
        child_rel.push(b'/');
        child_rel.extend_from_slice(name.as_encoded_bytes());
        if p.is_dir() {
            visit_files(&p, &child_rel, out);
        } else if let Ok(meta) = p.metadata() {
            out.push((child_rel, meta.len()));
        }
    }
}

/// Cache-section capture: every FILE directly at the run root (flat
/// vintage: `output`, `stderr`, …), plus nested-vintage `run/` files
/// prefixed `run/`. The `out/` subtree belongs to the OUT_DIR section.
fn walk_cache_files(run_dir: &Path) -> Vec<(Vec<u8>, u64)> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir(run_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            let name = entry.file_name();
            if p.is_file() {
                out.push((
                    name.as_encoded_bytes().to_vec(),
                    p.metadata().map(|m| m.len()).unwrap_or(0),
                ));
            } else if name == "run" {
                // Nested vintage: cargo cache files live under run/.
                if let Ok(nested) = fs::read_dir(&p) {
                    for n in nested.flatten() {
                        let np = n.path();
                        if np.is_file() {
                            let mut rel = b"run/".to_vec();
                            rel.extend_from_slice(n.file_name().as_encoded_bytes());
                            out.push((rel, np.metadata().map(|m| m.len()).unwrap_or(0)));
                        }
                    }
                }
            }
        }
    }
    out.sort();
    out
}

fn sorted_entries(raw: &[(Vec<u8>, u64)]) -> Vec<OutputEntry> {
    raw.iter()
        .map(|(p, l)| OutputEntry::new(p.clone(), *l))
        .collect()
}

/// Capture one complete manifest from the run dir.
fn capture_manifest(run_dir: &Path) -> OutputTreeManifest {
    OutputTreeManifest::new(
        sorted_entries(&walk_files(&run_dir.join("out"), "out")),
        sorted_entries(&walk_cache_files(run_dir)),
    )
    .expect("walked trees are sorted and unique")
}
