//! N012/T022 end-to-end proof: a stale OUT_DIR ghost file (leftover of
//! an earlier failed run) is planned for DELETE by
//! [`plan_swap`], and applying that plan makes the live tree EQUAL a
//! clean run's tree (bead rabs-root-4pidu.32.12).
//!
//! The ghost here is injected AFTER a clean build, simulating exactly
//! what the N010 probe measured: failed-run partials survive in OUT_DIR
//! and pollute any later capture until explicitly removed.
//! A second probe changes a generated source file WITHOUT changing its
//! length and restores the clean bytes through a private replacement
//! tree, proving content identity participates in keys and swap plans.
//!
//! Run-dir identification uses the FIXTURE'S OWN ARTIFACT as the marker
//! (`out/gen.rs`): on nested-nightly layouts several sibling units
//! (lib, build-script compile, build-script run) each carry an `out/`
//! dir, and picking by shape alone is flaky — the lib unit's `out/`
//! holds `.rlib`/`.rmeta` and matches every structural predicate.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use rabs_protocol::output_manifest::{
    OutputEntry, OutputSection, OutputTreeManifest, TreeDeltaRow, diff_manifests,
};
use rabs_protocol::post_state_replacement::{OutputPath, plan_swap, pre_state_key_material};
use sha2::{Digest, Sha256};

const FIXTURE_NAME: &str = "n003_probe";
/// Marker file identifying the BUILD-SCRIPT RUN unit's out dir.
const RUN_MARKER: &str = "out/gen.rs";
/// Ghost path relative to the run dir (matches the capture prefix).
const GHOST_REL: &str = "out/ghost_of_failed_run.dat";
const CARGO_PHASE_BUDGET_SECS: u64 = 180;

#[test]
fn t022_replay_swap_removes_ghosts_and_matches_clean_run() {
    let channel = first_available_channel();
    let dir = tempfile::tempdir().expect("scratch dir");
    let project = copy_fixture(dir.path());

    // CLEAN REFERENCE: one successful stock build.
    let build1 = run_bounded(stock_cargo(&channel, &project));
    assert!(
        build1.success && !build1.timed_out,
        "{}",
        build1.stderr_tail
    );
    let run_dir = find_run_dir(&project).expect("run dir after clean build");
    let clean_manifest = capture_manifest(&run_dir);
    let clean_key_material = pre_state_key_material(&clean_manifest);

    // POLLUTE: inject the ghost a failed run would have left behind —
    // into the SAME run dir the capture walks.
    let ghost = run_dir.join(GHOST_REL);
    fs::write(&ghost, b"stale partial bytes from failed run\n").expect("inject ghost");

    let live_manifest = capture_manifest(&run_dir);
    assert_ne!(
        clean_key_material,
        pre_state_key_material(&live_manifest),
        "polluted pre-state must produce different key material"
    );

    // PLAN: pure computation from live vs clean.
    let plan = plan_swap(&live_manifest, &clean_manifest).expect("plans");
    assert_eq!(
        plan.delete,
        vec![OutputPath::new(OutputSection::OutDir, GHOST_REL)],
        "the ghost must be planned for DELETE"
    );
    assert!(
        plan.create.is_empty(),
        "clean target adds nothing the live tree lacks"
    );

    // APPLY (executor role): DELETE rows only.
    for p in &plan.delete {
        assert_eq!(p.section, OutputSection::OutDir);
        let rel = std::str::from_utf8(&p.path).expect("plan paths are UTF-8");
        fs::remove_file(run_dir.join(rel)).expect("apply delete");
    }

    // PROOF: live tree now equals the clean run's tree EXACTLY.
    let after_apply = capture_manifest(&run_dir);
    assert_eq!(
        after_apply.out_dir_entries, clean_manifest.out_dir_entries,
        "replay == clean run after applying the swap plan"
    );
    assert!(
        diff_manifests(&after_apply, &clean_manifest)
            .expect("valid")
            .is_empty()
    );
    assert!(!ghost.exists(), "the ghost is gone");

    // Key material returns to the clean value: state fully restored.
    assert_eq!(pre_state_key_material(&after_apply), clean_key_material);
}

#[test]
fn same_length_generated_source_change_requires_private_tree_replacement() {
    let channel = first_available_channel();
    let dir = tempfile::tempdir().expect("scratch dir");
    let project = copy_fixture(dir.path());
    let build = run_bounded(stock_cargo(&channel, &project));
    assert!(
        build.success && !build.timed_out,
        "clean stock build failed: {}",
        build.stderr_tail
    );
    let run_dir = find_run_dir(&project).expect("run dir after clean build");
    let generated_file = run_dir.join(RUN_MARKER);
    let clean_bytes = fs::read(&generated_file).expect("read stock-generated source");
    let clean_manifest = capture_manifest(&run_dir);
    let clean_key_material = pre_state_key_material(&clean_manifest);
    let clean_entry = clean_manifest
        .out_dir_entries
        .iter()
        .find(|entry| entry.path == RUN_MARKER.as_bytes())
        .expect("generated source is captured");

    // Change the function's return value while preserving the exact file
    // length: metadata-only capture would mistake this for clean state.
    let mutated_bytes = b"pub fn g() -> u32 { 2 }\n";
    assert_eq!(clean_bytes.len(), mutated_bytes.len());
    assert_ne!(clean_bytes.as_slice(), mutated_bytes.as_slice());
    fs::write(&generated_file, mutated_bytes).expect("mutate generated source");
    let live_manifest = capture_manifest(&run_dir);
    let live_entry = live_manifest
        .out_dir_entries
        .iter()
        .find(|entry| entry.path == RUN_MARKER.as_bytes())
        .expect("mutated source is captured");
    assert_eq!(live_entry.len, clean_entry.len);
    assert_ne!(live_entry.content_sha256, clean_entry.content_sha256);
    assert_ne!(
        pre_state_key_material(&live_manifest),
        clean_key_material,
        "an equal-length content mutation must change the pre-state key"
    );
    assert_eq!(
        diff_manifests(&clean_manifest, &live_manifest).expect("valid manifests"),
        vec![TreeDeltaRow::Modified {
            new_entry: live_entry.clone(),
            previous_len: clean_entry.len,
            previous_content_sha256: clean_entry.content_sha256,
            section: OutputSection::OutDir,
        }],
        "the actual byte mutation must produce exactly one modification"
    );

    let plan = plan_swap(&live_manifest, &clean_manifest).expect("replacement plan");
    let generated_path = OutputPath::new(OutputSection::OutDir, RUN_MARKER);
    assert_eq!(plan.delete, vec![generated_path.clone()]);
    assert_eq!(plan.create, vec![generated_path.clone()]);
    assert!(!plan.is_noop());

    // Apply DELETE-then-CREATE in a private tree copied from the polluted
    // live state. Retain clean bytes captured before mutation as the
    // executor's materialization source; untouched files must also survive.
    let private_run_dir = dir.path().join("private-replacement");
    for entry in &live_manifest.out_dir_entries {
        let rel = std::str::from_utf8(&entry.path).expect("fixture paths are UTF-8");
        let destination = private_run_dir.join(rel);
        fs::create_dir_all(destination.parent().expect("output parent"))
            .expect("create private output directory");
        fs::copy(run_dir.join(rel), destination).expect("stage live output bytes");
    }
    assert_eq!(
        fs::read(private_run_dir.join(RUN_MARKER)).expect("read staged mutated source"),
        mutated_bytes,
        "the replacement tree must start with the actual mutated bytes"
    );
    for path in &plan.delete {
        assert_eq!(path.section, OutputSection::OutDir);
        let rel = std::str::from_utf8(&path.path).expect("plan paths are UTF-8");
        fs::remove_file(private_run_dir.join(rel)).expect("delete mutated private output");
    }
    for path in &plan.create {
        assert_eq!(path, &generated_path);
        let rel = std::str::from_utf8(&path.path).expect("plan paths are UTF-8");
        fs::write(private_run_dir.join(rel), &clean_bytes).expect("restore clean output bytes");
    }

    assert_eq!(
        fs::read(private_run_dir.join(RUN_MARKER)).expect("read restored source"),
        clean_bytes,
        "replacement must restore the exact stock-generated source bytes"
    );
    assert_eq!(
        fs::read(&generated_file).expect("read original live source"),
        mutated_bytes,
        "replacement preparation must leave the live tree untouched"
    );
    let restored_manifest = capture_manifest(&private_run_dir);
    assert_eq!(restored_manifest, clean_manifest);
    assert_eq!(
        pre_state_key_material(&restored_manifest),
        clean_key_material
    );
    assert!(
        plan_swap(&restored_manifest, &clean_manifest)
            .expect("valid restored manifest")
            .is_noop()
    );
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

// --- Layout discovery (artifact-marker identified) ---------------------------

fn all_build_dirs(root: &Path) -> Vec<PathBuf> {
    fn visit(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                out.push(p.clone());
                if depth < 2 {
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

/// The build-script RUN dir: the candidate whose `out/` holds the
/// fixture's marker artifact. Shape predicates alone are flaky across
/// vintages (lib units carry `out/` too, with `.rlib`/`.rmeta`).
fn find_run_dir(project: &Path) -> Option<PathBuf> {
    all_build_dirs(&project.join("target/debug/build"))
        .into_iter()
        .find(|d| d.join(RUN_MARKER).is_file())
}

fn visit_files(dir: &Path, rel: &[u8], out: &mut Vec<OutputEntry>) {
    assert!(
        fs::symlink_metadata(dir)
            .expect("inspect capture directory")
            .file_type()
            .is_dir(),
        "capture directory must not be a symlink: {}",
        dir.display()
    );
    for entry in fs::read_dir(dir).expect("read complete capture directory") {
        let entry = entry.expect("read every directory entry");
        let p = entry.path();
        let name = entry.file_name();
        let mut child_rel = rel.to_vec();
        child_rel.push(b'/');
        child_rel.extend_from_slice(name.as_encoded_bytes());
        let kind = entry.file_type().expect("inspect captured entry");
        if kind.is_dir() {
            visit_files(&p, &child_rel, out);
        } else {
            assert!(
                kind.is_file(),
                "only regular files can be captured: {}",
                p.display()
            );
            let bytes = fs::read(&p).expect("read every captured file completely");
            out.push(OutputEntry::new(
                child_rel,
                u64::try_from(bytes.len()).expect("captured byte length fits u64"),
                Sha256::digest(&bytes).into(),
            ));
        }
    }
}

fn capture_manifest(run_dir: &Path) -> OutputTreeManifest {
    let mut entries = Vec::new();
    visit_files(&run_dir.join("out"), b"out", &mut entries);
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    OutputTreeManifest::new(entries, Vec::new()).expect("walked tree is sorted and unique")
}
