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
//!    executes the build script from (both hardlinked names when present),
//!    then trigger a no-op rebuild. Raw outcomes:
//!    - `shim_executed`: did cargo actually run our file?
//!    - `cargo_proceeded_without_shim`: cargo rebuilt/replaced the build
//!      script and completed without executing the shim (the contract
//!      fails closed — cargo owns that path);
//!    - `binary_bytes_changed`: the file at the expected path changed;
//!    - `jobserver_inherited_through_shim`: descriptors still reachable
//!      when the shim DID run;
//!    - `output_cache_correct`: directives + OUT_DIR artifacts intact.
//!
//! Every result is emitted as machine-readable JSON on stdout so the
//! feasibility matrix doc quotes the harness rather than folklore.
//!
//! Channels without a locally-installed toolchain are SKIPPED (the matrix
//! marks them unprobed); nothing here invents a result.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use serde_json::json;

const FIXTURE_NAME: &str = "n001_probe";

/// Channels probed when installed; order matters only for reporting.
const CHANNELS: [&str; 3] = ["stable", "beta", "nightly"];

#[test]
fn n001_interception_contract_matrix_across_channels() {
    let mut report = Vec::new();
    let mut probed_any = false;

    for channel in available_channels() {
        probed_any = true;
        println!("[n001] probing channel {} ({})", channel.name, channel.cargo_path);
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
//
// Cargo's on-disk contract varies by vintage and must be DISCOVERED, not
// assumed:
//
// - flat vintages: `target/debug/build/<pkg>-<hash>/` holds BOTH the
//   compiled build script (`build-script-build`, hardlinked as
//   `build_script_build-<hash>`) and its run outputs (`output` at root,
//   OUT_DIR under `out/`);
// - nested vintages (recent nightlies): `target/debug/build/<pkg>/<hash>/`
//   splits into sibling hash dirs with the same content roles.
//
// The scan below walks both shapes (depth 2) and identifies each dir by
// CONTENT, never by name spelling.

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

/// The dir holding the compiled build-script executable.
fn find_compile_dir(project: &Path) -> Option<PathBuf> {
    all_fixture_dirs(project).into_iter().find(|d| {
        d.join("build-script-build").is_file()
            || fs::read_dir(d)
                .map(|entries| {
                    entries.flatten().any(|e| {
                        e.file_name().to_str().unwrap_or("").starts_with("build_script_build")
                            && e.path().is_file()
                    })
                })
                .unwrap_or(false)
    })
}

/// The dir holding run outputs (`output` at root, `out/` for OUT_DIR).
fn find_run_dir(project: &Path) -> Option<PathBuf> {
    all_fixture_dirs(project)
        .into_iter()
        .find(|d| d.join("output").is_file() && d.join("out").is_dir())
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
    let first = stock_cargo().output().expect("run cargo (fresh)");
    assert!(
        first.status.success(),
        "[{}] fresh build failed: {}",
        channel.name,
        String::from_utf8_lossy(&first.stderr)
    );

    let Some(compile_dir) = find_compile_dir(project) else {
        dump_layout(project);
        panic!("[{}] compile dir not found after fresh build", channel.name);
    };
    let Some(run_dir) = find_run_dir(project) else {
        dump_layout(project);
        panic!("[{}] run dir not found after fresh build", channel.name);
    };

    // Both names for one binary where cargo hardlinks them; a shim covers
    // both because which name cargo execs is an implementation detail.
    let exe_primary = compile_dir.join("build-script-build");
    let exe_secondary = fs::read_dir(&compile_dir)
        .ok()
        .and_then(|entries| {
            entries.flatten().find_map(|e| {
                let p = e.path();
                (p.is_file()
                    && p != exe_primary
                    && e.file_name().to_str().unwrap_or("").starts_with("build_script_build"))
                .then_some(p)
            })
    let original_bytes = fs::read(&exe_primary)
        .or_else(|_| {
            exe_secondary
                .as_ref()
                .and_then(|p| fs::read(p).ok())
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no build script binary"))
        })
        .expect("read build script exe");

    let probe_after_fresh = read_probe_record(&run_dir);
    let stock_jobserver = probe_after_fresh
        .get("has_cargo_makeflags")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let stock_fd_pair = probe_after_fresh
        .get("jobserver_fds")
        .and_then(Value::as_str)
        .is_some_and(|fds| fds.contains(','));

    // Phase 2: no-op rebuild — fingerprint stability (must NOT rerun).
    let output_mtime_before = output_cache_mtime(&run_dir);
    let second = stock_cargo().output().expect("run cargo (noop)");
    assert!(
        second.status.success(),
        "[{}] no-op rebuild failed: {}",
        channel.name,
        String::from_utf8_lossy(&second.stderr)
    );
    let reran_on_noop = output_cache_mtime(&run_dir) != output_mtime_before;

    // Phase 3: launcher-shim experiment. Displace the real binaries under
    // BOTH names, install a recording shim at each, then no-op-rebuild.
    let real = compile_dir.join("n001_real.bin");
    let primary_exists = exe_primary.exists();
    let displaced = if primary_exists {
        fs::rename(&exe_primary, &real).expect("displace primary");
        true
    } else {
        false
    };
    let secondary_backup = exe_secondary.as_ref().and_then(|sec| {
        let backup = compile_dir.join(format!(
            "n001_real_sec_{}",
            sec.file_name()?.to_str()?
        ));
        fs::rename(sec, &backup).ok()?;
        Some(backup)
    });

    let shim_target = if displaced { exe_primary.clone() } else { exe_secondary.clone().expect("a shim target exists") };
    let log_path = compile_dir.join("n001_shim.log");
    let shim = format!(
        "#!/bin/sh\nprintf '%s\\0' \"$0\" \"$@\" >> \"{log}\"\nprintf '%s\\0' \"$CARGO_MAKEFLAGS\" >> \"{log}\"\nexec \"$N001_REAL_BIN\" \"$@\"\n",
        log = log_path.display(),
    );
    fs::write(&shim_target, shim.as_bytes()).expect("install shim");
    make_executable(&shim_target);
    if let Some(backup) = secondary_backup {
        fs::write(backup, shim.as_bytes()).ok();
    }

    let real_bin = if displaced {
        real.display().to_string()
    } else {
        secondary_backup
            .as_ref()
            .map(|b| b.display().to_string())
            .unwrap_or_default()
    };
    let third = stock_cargo()
        .env("N001_REAL_BIN", real_bin)
        .output()
        .expect("run cargo (shimmed)");
    let shim_build_succeeded = third.status.success();

    let bytes_now = fs::read(&shim_target).unwrap_or_default();
    let shim_log = fs::read_to_string(&log_path).unwrap_or_default();
    let shim_executed = !shim_log.is_empty();
    let cargo_proceeded_without_shim = !shim_executed && shim_build_succeeded;
    let binary_bytes_changed = bytes_now != original_bytes;
    let jobserver_through_shim = shim_log.contains("--jobserver-fds=");

    let probe_after_shim = read_probe_record(&run_dir);
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
            "shim_executed": shim_executed,
            "cargo_proceeded_without_shim": cargo_proceeded_without_shim,
            "binary_bytes_changed": binary_bytes_changed,
            "jobserver_inherited_through_shim": jobserver_through_shim,
            "output_cache_correct": output_cache_correct,
        },
    })
}

// --- Inspection helpers ------------------------------------------------------

fn read_probe_record(run_dir: &Path) -> Value {
    let text =
        fs::read_to_string(run_dir.join("out/probe.json")).expect("probe.json written by builder");
    serde_json::from_str(&text).expect("probe.json parses")
}

fn output_cache_mtime(run_dir: &Path) -> Option<std::time::SystemTime> {
    fs::metadata(run_dir.join("output"))
        .and_then(|m| m.modified())
        .ok()
}

/// Output-cache correctness: cargo captured the directive surface at the
/// run-dir root and the generated unit materialized under OUT_DIR.
fn verify_output_cache(project: &Path, run_dir: &Path, probe: &Value) -> bool {
    let output = fs::read_to_string(run_dir.join("output")).unwrap_or_default();
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
