//! N010/T034 end-to-end proof against REAL cargo: a failed build-script
//! run leaves partial OUT_DIR contents (stock behavior, measured), that
//! partial state is REFUSED for publishing by the protocol law, and a
//! fixed retry ACCUMULATES beside the stale partials — ghost files the
//! ghost analysis names exactly (bead rabs-root-4pidu.32.10).

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use rabs_protocol::output_manifest::{OutputEntry, OutputTreeManifest, diff_manifests};
use rabs_protocol::run_publish_policy::{
    RunOutcomeKind, StagingState, ghost_files, publish_decision, resolve_retry_parity,
};

const FIXTURE_NAME: &str = "n010_probe";
const CARGO_PHASE_BUDGET_SECS: u64 = 180;

#[test]
fn n010_failed_run_never_publishes_and_retry_accumulates_ghosts() {
    let cargo = first_available_cargo();
    let dir = tempfile::tempdir().expect("scratch dir");
    let project = copy_fixture(dir.path());
    // An unrelated compiler-unit directory must never be mistaken for OUT_DIR.
    fs::create_dir_all(project.join("target/debug/build/000-decoy/000/out"))
        .expect("plant unrelated compiler output directory");

    // PHASE 1: failing run. Stock cargo reports failure; partial OUT_DIR
    // contents survive.
    let failed = run_bounded(phase_cargo(&cargo, &project, "fail"));
    assert!(
        !failed.success && !failed.timed_out,
        "phase-1 run must FAIL (timed_out={}): {}",
        failed.timed_out,
        failed.stderr_tail
    );
    assert!(
        failed
            .stderr_tail
            .contains("n010: failing after partial writes"),
        "the intended build-script failure must occur, not a compiler failure: {}",
        failed.stderr_tail
    );
    let out_dir = recorded_out_dir(&project, "fail");
    assert!(
        out_dir.join("partial_one.rs").is_file() && out_dir.join("partial_two.dat").is_file(),
        "stock keeps both partial files after a failed run in {}",
        out_dir.display()
    );

    // LAW 1 applied to the REAL outcome: exit-3 failure never publishes.
    assert_eq!(
        publish_decision(RunOutcomeKind::Failed),
        rabs_protocol::run_publish_policy::PublishDecision::NeverPublish {
            reason: "failed-run-partial-state"
        }
    );
    // The captured manifest of the failed run exists as EVIDENCE but the
    // decision is structural: no path through this type publishes it.
    let failure_manifest = capture_manifest(&out_dir);
    assert!(!failure_manifest.out_dir_entries.is_empty());

    // PHASE 2: fixed retry in the SAME destination — stock accumulates.
    let fixed = run_bounded(phase_cargo(&cargo, &project, "fix"));
    assert!(
        fixed.success && !fixed.timed_out,
        "phase-2 retry failed: {}",
        fixed.stderr_tail
    );
    assert_eq!(
        recorded_out_dir(&project, "fix"),
        out_dir,
        "the retry must actually execute in the same OUT_DIR"
    );
    let retry_manifest = capture_manifest(&out_dir);

    // Retry-parity arms resolve; unresolved semantics fall back local.
    assert_eq!(
        resolve_retry_parity(None),
        rabs_protocol::run_publish_policy::PostStatePolicy::LocalFallback
    );
    // LAW 3: staging held until resolved, releasable afterwards.
    assert!(!StagingState::Held.releasable());
    assert!(
        StagingState::Held
            .release_after_policy_resolved(
                rabs_protocol::run_publish_policy::PostStatePolicy::OperationOwnedDestination
            )
            .releasable()
    );

    // T034 GHOST ANALYSIS over the real delta: gen.rs added; the two
    // stale partials persist into the retry capture.
    let rows = diff_manifests(&failure_manifest, &retry_manifest).expect("valid manifests");
    assert!(rows.iter().any(|r| matches!(
        r,
        rabs_protocol::output_manifest::TreeDeltaRow::Added { entry, .. }
            if entry.path == b"out/gen.rs"
    )));
    let retry_paths: Vec<Vec<u8>> = retry_manifest
        .section(rabs_protocol::output_manifest::OutputSection::OutDir)
        .iter()
        .map(|e| e.path.clone())
        .collect();
    let ghosts = ghost_files(&retry_paths, &[b"out/gen.rs".to_vec()]);
    assert_eq!(
        ghosts,
        vec![
            b"out/partial_one.rs".to_vec(),
            b"out/partial_two.dat".to_vec(),
        ],
        "stale partials must be named as ghosts of the failed run"
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

fn phase_cargo(cargo: &str, project: &Path, phase: &str) -> Command {
    // Discovery already returns the executable, not a rustup channel name.
    // Its sibling compiler belongs to the same installed toolchain.
    let rustc = Path::new(cargo).with_file_name(if cfg!(windows) { "rustc.exe" } else { "rustc" });
    let mut cmd = Command::new(cargo);
    cmd.arg("build")
        .arg("--offline")
        .arg("--target-dir")
        .arg(project.join("target"))
        .current_dir(project)
        .env("N010_PHASE", phase)
        .env("N010_OUT_DIR_RECORD", out_dir_record(project, phase))
        // Explicit empty flags override ancestor Cargo configuration too.
        .env("RUSTFLAGS", "")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("CARGO_BUILD_RUSTFLAGS")
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env_remove("CARGO_BUILD_RUSTC_WRAPPER")
        .env_remove("CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER")
        .env_remove("CARGO_BUILD_RUSTC")
        .env("RUSTC", rustc)
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("CARGO_BUILD_TARGET_DIR")
        .env_remove("CARGO_BUILD_TARGET")
        .env("CARGO_BUILD_BUILD_DIR", project.join("target"))
        .env_remove("RUSTUP_TOOLCHAIN")
        .env("RUSTUP_AUTO_INSTALL", "0");
    cmd
}

fn cargo_bin_for(channel: &str) -> String {
    let Ok(out) = Command::new("rustup")
        .args(["which", "cargo", "--toolchain", channel])
        .env("RUSTUP_AUTO_INSTALL", "0")
        .output()
    else {
        return "cargo".to_owned();
    };
    if out.status.success() {
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    } else {
        "cargo".to_owned()
    }
}

fn first_available_cargo() -> String {
    const PREFERRED: [&str; 3] = ["nightly", "beta", "stable"];
    let rustup_ok = Command::new("rustup")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if rustup_ok {
        for name in PREFERRED {
            let bin = cargo_bin_for(name);
            if bin != "cargo" || Path::new("cargo").exists() {
                return bin;
            }
        }
    }
    "cargo".to_owned()
}

// --- Fixture staging -------------------------------------------------------

fn copy_fixture(scratch: &Path) -> PathBuf {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/n010_failed_run");
    let project = scratch.join(FIXTURE_NAME);
    fs::create_dir_all(project.join("src")).expect("mkdir src");
    for rel in ["Cargo.toml", "build.rs", "src/lib.rs"] {
        fs::copy(src.join(rel), project.join(rel)).expect("copy fixture file");
    }
    project
}

// --- Recorded run identity + capture -----------------------------------------

fn out_dir_record(project: &Path, phase: &str) -> PathBuf {
    project.join(format!("n010-{phase}-out-dir"))
}

fn recorded_out_dir(project: &Path, phase: &str) -> PathBuf {
    // Cargo 1.100 also gives compiler units an `out` directory. Read the
    // build script's actual OUT_DIR instead of guessing from internal layout.
    let recorded = fs::read_to_string(out_dir_record(project, phase))
        .expect("the build script must record this phase's OUT_DIR");
    let out = PathBuf::from(recorded);
    assert!(out.is_absolute(), "recorded OUT_DIR must be absolute");
    let out = out.canonicalize().expect("recorded OUT_DIR exists");
    let target = project
        .join("target")
        .canonicalize()
        .expect("target exists");
    assert!(
        out.starts_with(target),
        "OUT_DIR must stay in the owned target"
    );
    assert!(out.is_dir(), "OUT_DIR must be a directory");
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

fn capture_manifest(out_dir: &Path) -> OutputTreeManifest {
    let mut raw = Vec::new();
    visit_files(out_dir, b"out", &mut raw);
    raw.sort();
    OutputTreeManifest::new(
        raw.iter()
            .map(|(p, l)| OutputEntry::new(p.clone(), *l))
            .collect(),
        Vec::new(),
    )
    .expect("walked tree is sorted and unique")
}
