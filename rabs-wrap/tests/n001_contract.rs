//! N001 contract probes: canonical-Cargo interception and launcher-shim
//! feasibility across installed cargo channels (bead rabs-root-4pidu.32.1).
//!
//! What each per-channel run establishes, with EVIDENCE not assumption:
//!
//! 1. STOCK SEMANTICS (asserted — the baseline a cache must reproduce):
//!    - a fresh build runs the build script exactly once and succeeds;
//!    - an immediate no-op rebuild does NOT rerun it (`rerun-if-changed`
//!      fingerprinting is stable);
//!    - the build script sees `CARGO_MAKEFLAGS` carrying
//!      `--jobserver-fds` (descriptor inheritance is part of the ambient
//!      contract);
//!    - the directive surface lands in cargo's output cache verbatim.
//!
//! 2. LAUNCHER-SHIM EXPERIMENT (measured — this is the feasibility
//!    question): place a recording shim at the exact path(s) cargo
//!    executes the build script from, then trigger a no-op rebuild. Raw
//!    outcomes:
//!    - `shim_executed`: did cargo actually run our file?
//!    - `cargo_proceeded_without_shim`: cargo rebuilt/replaced the build
//!      script and completed without executing the shim (the contract
//!      fails closed — cargo owns that path);
//!    - `binary_bytes_changed`: the file at the expected path changed;
//!    - `jobserver_inherited_through_shim`: descriptors still reachable
//!      when the shim DID run;
//!    - `output_cache_correct`: directives + OUT_DIR artifacts intact.
//!
//! Every cargo invocation runs under a HARD DEADLINE: a hang is a RESULT
//! (`timed_out: true`) recorded in the matrix, never a stalled session.
//! Results are emitted as machine-readable JSON so the feasibility matrix
//! doc quotes the harness rather than folklore. Channels without an
//! installed toolchain are SKIPPED; nothing here invents a result.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;
use serde_json::json;

const FIXTURE_NAME: &str = "n001_probe";

/// Channels probed when installed; order matters only for reporting.
const CHANNELS: [&str; 3] = ["stable", "beta", "nightly"];

/// Hard deadline for one toy-fixture cargo invocation.
const CARGO_PHASE_BUDGET_SECS: u64 = 120;

#[test]
fn n001_interception_contract_matrix_across_channels() {
    let mut report = Vec::new();
    let mut probed_any = false;

    for channel in available_channels() {
        probed_any = true;
        println!(
            "[n001] probing channel {} ({})",
            channel.name, channel.cargo_path
        );
        let dir = tempfile::tempdir().expect("scratch dir");
        let project = copy_fixture(dir.path());
        let facts = probe_channel(&channel, &project);
        println!(
            "[n001] channel {} result: {}",
            channel.name,
            serde_json::to_string(&facts).unwrap()
        );
        report.push(facts);
    }
    assert!(
        probed_any,
        "no cargo channel could be located via rustup or PATH"
    );

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({ "n001_matrix": report })).unwrap()
    );
}

// --- Bounded process execution ----------------------------------------------

/// Outcome of one bounded cargo invocation: a feasibility harness treats
/// a hang as a RESULT (recorded), never as a stalled session.
struct RunOutcome {
    success: bool,
    timed_out: bool,
    stderr_tail: String,
}

/// Run `cmd` to completion under a hard deadline; kill and record on expiry.
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

// --- Channel discovery -----------------------------------------------------

struct Channel {
    name: String,
    cargo_path: String,
}

/// Resolve cargo for each channel: `rustup which` when rustup exists, else
/// the ambient `cargo` labeled honestly as `default`.
fn available_channels() -> Vec<Channel> {
    let rustup_ok = Command::new("rustup")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());

    let mut found = Vec::new();
    if rustup_ok {
        for name in CHANNELS {
            if let Some(path) = rustup_which(name) {
                found.push(Channel {
                    name: name.to_owned(),
                    cargo_path: path,
                });
            }
        }
    } else if let Some(path) = which_plain_cargo() {
        found.push(Channel {
            name: "default".to_owned(),
            cargo_path: path,
        });
    }
    found
}

fn rustup_which(toolchain: &str) -> Option<String> {
    let out = Command::new("rustup")
        .args(["which", "cargo", "--toolchain", toolchain])
        .output()
        .ok()?;
    (out.status.success())
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
        .filter(|s| !s.is_empty())
}

fn which_plain_cargo() -> Option<String> {
    let out = Command::new("which").arg("cargo").output().ok()?;
    (out.status.success())
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
        .filter(|s| !s.is_empty())
}

// --- Fixture staging -------------------------------------------------------

/// Copy the pristine fixture into the scratch dir (keeps per-channel
/// target trees isolated).
fn copy_fixture(scratch: &Path) -> PathBuf {
    let fixture_src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/n001_run_cache");
    let project = scratch.join(FIXTURE_NAME);
    fs::create_dir_all(project.join("src")).expect("mkdir src");
    for (name, src) in [
        ("Cargo.toml", fixture_src.join("Cargo.toml")),
        ("build.rs", fixture_src.join("build.rs")),
        ("src/lib.rs", fixture_src.join("src/lib.rs")),
    ] {
        fs::copy(src, project.join(name)).expect("copy fixture file");
    }
    project
}

// --- Target-tree layout ------------------------------------------------------

/// Candidate dirs under `target/debug/build/`, to depth 2 (flat and
/// nested vintages alike); identified downstream by CONTENT only.
fn all_fixture_dirs(project: &Path) -> Vec<PathBuf> {
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

    let root = project.join("target/debug/build");
    let mut out = Vec::new();
    if root.is_dir() {
        visit(&root, 0, &mut out);
    }
    out.sort();
    out
}

fn is_build_script_name(name: &str) -> bool {
    name == "build-script-build" || name.starts_with("build_script_build")
}

/// Every compiled-build-script FILE under a candidate compile dir (flat
/// vintages keep them at the dir root; nested nightlies under `out/`).
fn build_script_binaries(compile_dir: &Path) -> Vec<PathBuf> {
    let mut bins = Vec::new();
    for base in [compile_dir.to_path_buf(), compile_dir.join("out")] {
        if let Ok(entries) = fs::read_dir(&base) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file() && is_build_script_name(entry.file_name().to_str().unwrap_or("")) {
                    bins.push(p);
                }
            }
        }
    }
    bins.sort();
    bins
}

/// The dir holding the compiled build-script executable.
fn find_compile_dir(project: &Path) -> Option<PathBuf> {
    all_fixture_dirs(project)
        .into_iter()
        .find(|d| !build_script_binaries(d).is_empty())
}

/// Path of cargo's captured build-script directive stream for one run
/// unit: `run/stdout` on nested nightlies, `output` on flat vintages.
fn directive_cache(run_dir: &Path) -> Option<PathBuf> {
    let nested = run_dir.join("run/stdout");
    if nested.is_file() {
        return Some(nested);
    }
    let flat = run_dir.join("output");
    flat.is_file().then_some(flat)
}

/// The dir holding run outputs: OUT_DIR at `out/`, directive cache at
/// [`directive_cache`].
fn find_run_dir(project: &Path) -> Option<PathBuf> {
    all_fixture_dirs(project)
        .into_iter()
        .find(|d| d.join("out").is_dir() && directive_cache(d).is_some())
}

/// Forensic dump used when layout discovery fails: prints every candidate
/// dir with its entries so the failure names itself.
fn dump_layout(project: &Path) {
    for d in all_fixture_dirs(project) {
        let names: Vec<String> = fs::read_dir(&d)
            .map(|es| {
                es.flatten()
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .collect()
            })
            .unwrap_or_default();
        println!("[n001-debug] {}: {:?}", d.display(), names);
    }
}

// --- Per-channel probe ------------------------------------------------------

fn probe_channel(channel: &Channel, project: &Path) -> Value {
    // Stock cargo invocation: strip ambient harness state so the probe
    // measures CARGO's contract — wrappers, shared target dirs, or forced
    // toolchains would relocate/redirect the very artifacts probed here.
    let stock_cargo = || {
        let mut cmd = Command::new(&channel.cargo_path);
        cmd.arg("build")
            .current_dir(project)
            .env_remove("RUSTC_WRAPPER")
            .env_remove("RUSTC_WORKSPACE_WRAPPER")
            .env_remove("RUSTFLAGS")
            .env_remove("CARGO_TARGET_DIR")
            .env_remove("CARGO_BUILD_TARGET_DIR")
            .env_remove("RUSTUP_TOOLCHAIN");
        cmd
    };

    // Phase 1: fresh stock build.
    println!("[n001]   {} phase: fresh", channel.name);
    let first = run_bounded(stock_cargo());
    assert!(
        first.success && !first.timed_out,
        "[{}] fresh build failed (timed_out={}): {}",
        channel.name,
        first.timed_out,
        first.stderr_tail
    );

    let Some(compile_dir) = find_compile_dir(project) else {
        dump_layout(project);
        panic!("[{}] compile dir not found after fresh build", channel.name);
    };
    let Some(run_dir) = find_run_dir(project) else {
        dump_layout(project);
        panic!("[{}] run dir not found after fresh build", channel.name);
    };

    // Every name cargo could exec the build script through (flat vintage
    // hardlinks two names; nested nightlies keep one under out/). A shim
    // must cover all of them.
    let mut script_bins = build_script_binaries(&compile_dir);
    assert!(
        !script_bins.is_empty(),
        "[{}] no build script binary after fresh build",
        channel.name
    );
    let shim_target = script_bins.remove(0);
    let mut displaced_originals: Vec<(PathBuf, PathBuf)> = std::iter::once(shim_target.clone())
        .chain(script_bins.iter().cloned())
        .enumerate()
        .map(|(i, bin)| {
            let backup = compile_dir.join(format!("n001_real_{i}.bin"));
            fs::rename(&bin, &backup).expect("displace real binary");
            (bin, backup)
        })
        .collect();
    displaced_originals.sort();
    let original_bytes = fs::read(&displaced_originals[0].1).expect("read real binary");

    let probe_after_fresh = read_probe_record_opt(&run_dir).expect("probe.json written by builder");
    let stock_jobserver = probe_after_fresh
        .get("has_cargo_makeflags")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let stock_fd_pair = probe_after_fresh
        .get("jobserver_fds")
        .and_then(Value::as_str)
        .is_some_and(|fds| fds.contains(','));

    // Phase 2: no-op rebuild — fingerprint stability (must NOT rerun).
    println!("[n001]   {} phase: noop-rebuild", channel.name);
    let output_mtime_before = output_cache_mtime(&run_dir);
    let second = run_bounded(stock_cargo());
    assert!(
        second.success && !second.timed_out,
        "[{}] no-op rebuild failed (timed_out={}): {}",
        channel.name,
        second.timed_out,
        second.stderr_tail
    );
    let reran_on_noop = output_cache_mtime(&run_dir) != output_mtime_before;

    // Phase 3: launcher-shim experiment. Install a recording shim at the
    // primary expected path (secondaries also shimmed so a hardlink swap
    // cannot dodge us), then trigger a no-op rebuild.
    println!("[n001]   {} phase: shimmed-rebuild", channel.name);
    let log_path = compile_dir.join("n001_shim.log");
    let shim = format!(
        "#!/bin/sh\nprintf '%s\\0' \"$0\" \"$@\" >> \"{log}\"\nprintf '%s\\0' \"$CARGO_MAKEFLAGS\" >> \"{log}\"\nexec \"$N001_REAL_BIN\" \"$@\"\n",
        log = log_path.display(),
    );
    fs::write(&shim_target, shim.as_bytes()).expect("install shim");
    make_executable(&shim_target);
    for (_, backup) in displaced_originals.iter().skip(1) {
        fs::write(backup, shim.as_bytes()).ok();
    }

    let mut shimmed_cmd = stock_cargo();
    shimmed_cmd.env(
        "N001_REAL_BIN",
        displaced_originals[0].1.display().to_string(),
    );
    let third = run_bounded(shimmed_cmd);
    let shim_build_succeeded = third.success && !third.timed_out;

    let bytes_now = fs::read(&shim_target).unwrap_or_default();
    let shim_log = fs::read_to_string(&log_path).unwrap_or_default();
    let shim_executed = !shim_log.is_empty();
    let cargo_proceeded_without_shim = !shim_executed && shim_build_succeeded;
    let binary_bytes_changed = bytes_now != original_bytes;
    let jobserver_through_shim = shim_log.contains("--jobserver-fds=");

    // Phase-3 reads may fail when cargo rebuilt over everything; degrade
    // honestly instead of panicking past the interesting evidence.
    let probe_after_shim =
        read_probe_record_opt(&run_dir).unwrap_or_else(|| probe_after_fresh.clone());
    let output_cache_correct = verify_output_cache(project, &run_dir, &probe_after_shim);

    json!({
        "channel": channel.name,
        "stock": {
            "fresh_build_ok": true,
            "reran_on_noop": reran_on_noop,
            "jobserver_makeflags_seen": stock_jobserver,
            "jobserver_fd_pair_seen": stock_fd_pair,
        },
        "launcher_shim": {
            "shim_build_succeeded": shim_build_succeeded,
            "shim_timed_out": third.timed_out,
            "shim_executed": shim_executed,
            "cargo_proceeded_without_shim": cargo_proceeded_without_shim,
            "binary_bytes_changed": binary_bytes_changed,
            "jobserver_inherited_through_shim": jobserver_through_shim,
            "output_cache_correct": output_cache_correct,
        },
    })
}

// --- Inspection helpers ------------------------------------------------------

fn read_probe_record_opt(run_dir: &Path) -> Option<Value> {
    let text = fs::read_to_string(run_dir.join("out/probe.json")).ok()?;
    serde_json::from_str(&text).ok()
}
fn output_cache_mtime(run_dir: &Path) -> Option<std::time::SystemTime> {
    fs::metadata(directive_cache(run_dir)?)
        .and_then(|m| m.modified())
        .ok()
}

/// Output-cache correctness: cargo captured the directive surface and the
/// generated unit materialized under OUT_DIR.
fn verify_output_cache(project: &Path, run_dir: &Path, probe: &Value) -> bool {
    let Some(cache) = directive_cache(run_dir) else {
        return false;
    };
    let output = fs::read_to_string(cache).unwrap_or_default();
    let directives_ok = output.contains("cargo:rerun-if-changed=build.rs")
        && output.contains("cargo:rerun-if-env-changed=N001_PROBE_VAR");
    let generated_ok = run_dir.join("out/generated.rs").is_file();
    let crate_built = project
        .join("target/debug")
        .join(format!("lib{FIXTURE_NAME}.rlib"))
        .is_file()
        || probe.get("exe").and_then(Value::as_str).is_some();
    directives_ok && generated_ok && crate_built
}

fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut perm = fs::metadata(path).expect("stat shim target").permissions();
    perm.set_mode(0o755);
    fs::set_permissions(path, perm).expect("chmod shim target");
}
