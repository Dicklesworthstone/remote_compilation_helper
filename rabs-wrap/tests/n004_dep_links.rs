//! N004 end-to-end proof: DEP_* values observed by a dependent crate's
//! build script under STOCK cargo must equal the replay-side
//! reconstruction (`reconstruct_dep_env`) computed from the PROVIDER's
//! captured directive manifest — byte for byte (bead rabs-root-4pidu.32.4).
//!
//! Stock side: real cargo builds the two-crate fixture; the consumer's
//! build script records every `DEP_*` var it observes into its OUT_DIR.
//!
//! Replay side: the provider's captured stdout (cargo's own directive
//! cache) is parsed with [`extract_directives`] and reconstructed with
//! [`reconstruct_dep_env`] using the provider's `links` value.
//!
//! The two sides agreeing IS the acceptance criterion: "dependent-crate
//! fixtures observe identical DEP_* values under replay vs stock."

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use rabs_protocol::dep_links::reconstruct_dep_env;
use rabs_protocol::directive_manifest::extract_directives;
use rabs_protocol::stream_chunker::{CanonicalObservation, StdStream};

const FIXTURE_NAME: &str = "n004_dep_links";
const LINKS: &[u8] = b"Sys-Probe_v1";
/// Hard deadline per cargo invocation (a hang is a recorded failure).
const CARGO_PHASE_BUDGET_SECS: u64 = 180;

#[test]
fn n004_replay_reconstruction_matches_stock_dep_env() {
    let channel = first_available_channel();
    let dir = tempfile::tempdir().expect("scratch dir");
    let project = copy_fixture(dir.path());

    // STOCK: one bounded real-cargo build of the dependent crate (cargo
    // builds the provider first, capturing its directives itself).
    let mut cmd = Command::new(&channel);
    cmd.arg("build")
        .current_dir(project.join("consumer"))
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("CARGO_BUILD_TARGET_DIR")
        .env_remove("RUSTUP_TOOLCHAIN");
    let outcome = run_bounded(cmd);
    assert!(
        outcome.success && !outcome.timed_out,
        "stock build failed (timed_out={}): {}",
        outcome.timed_out,
        outcome.stderr_tail
    );

    // Ground truth from the consumer's OUT_DIR record.
    let stock_lines = stock_observed_dep_vars(&project);

    // Replay side: parse the provider's captured stdout directive cache.
    let provider_cache = find_directive_cache(&project, "n004_dep_provider")
        .expect("provider directive cache after stock build");
    let cache_bytes = fs::read(provider_cache).expect("read provider directive cache");
    let observations: Vec<CanonicalObservation> = split_lines(&cache_bytes)
        .into_iter()
        .enumerate()
        .map(|(i, bytes)| CanonicalObservation::Line {
            stream: StdStream::Stdout,
            seq: i as u64 + 1,
            bytes,
        })
        .collect();
    let manifest = extract_directives(&observations).expect("ordered provider transcript");
    let reconstruction = reconstruct_dep_env(LINKS, &manifest);
    assert!(
        reconstruction.is_complete(),
        "unparsed spills would make replay incomplete"
    );

    // THE ACCEPTANCE, byte for byte.
    let mut replay_lines: Vec<String> = reconstruction
        .vars
        .iter()
        .map(|(name, value)| {
            format!(
                "{}={}",
                String::from_utf8(name.clone()).expect("var names are UTF-8"),
                String::from_utf8_lossy(value)
            )
        })
        .collect();
    replay_lines.sort();
    assert_eq!(
        replay_lines, stock_lines,
        "replay reconstruction must reproduce the stock DEP_* env exactly"
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

// --- Channel discovery -------------------------------------------------------

/// First installed channel via rustup (`stable` preferred); ambient
/// cargo as fallback.
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

/// Copy both standalone packages into the scratch dir, preserving the
/// two-directory shape (provider depends on consumer? no: consumer on
/// provider — the relative `../provider` path dep survives the copy).
fn copy_fixture(scratch: &Path) -> PathBuf {
    let src_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(FIXTURE_NAME);
    let project = scratch.join(FIXTURE_NAME);
    for pkg in ["provider", "consumer"] {
        fs::create_dir_all(project.join(pkg).join("src")).expect("mkdir package src");
        for rel in ["Cargo.toml", "build.rs", "src/lib.rs"] {
            fs::copy(src_root.join(pkg).join(rel), project.join(pkg).join(rel))
                .expect("copy fixture file");
        }
    }
    project
}

// --- Target-tree layout (content-identified, vintage-agnostic) ---------------

/// Candidate dirs under `target/debug/build/**`, to depth 2.
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

/// Cargo's captured stdout directive cache for one run unit:
/// `run/stdout` on nested nightlies, `output` on flat vintages.
fn directive_cache(run_dir: &Path) -> Option<PathBuf> {
    let nested = run_dir.join("run/stdout");
    if nested.is_file() {
        return Some(nested);
    }
    let flat = run_dir.join("output");
    flat.is_file().then_some(flat)
}

/// The provider's directive cache under the CONSUMER's target tree
/// (path dependencies build into the dependent's single target root;
/// both flat `<pkg>-<hash>` and nested `<pkg>/<hash>` vintages are
/// covered by scanning depth-2 and matching the package in the path).
fn find_directive_cache(project: &Path, package: &str) -> Option<PathBuf> {
    let build_root = project.join("consumer/target/debug/build");
    all_build_dirs(&build_root)
        .into_iter()
        .filter(|d| d.to_string_lossy().contains(package))
        .find_map(|d| directive_cache(&d))
}

/// The consumer's recorded DEP_* observation, sorted lines.
fn stock_observed_dep_vars(project: &Path) -> Vec<String> {
    let record = all_build_dirs(&project.join("consumer/target/debug/build"))
        .into_iter()
        .find_map(|d| {
            let p = d.join("out/dep_observed.txt");
            p.is_file().then_some(p)
        })
        .or_else(|| {
            all_build_dirs(&project.join("."))
                .into_iter()
                .find_map(|d| {
                    let p = d.join("out/dep_observed.txt");
                    p.is_file().then_some(p)
                })
        })
        .expect("consumer recorded dep_observed.txt");
    let text = fs::read_to_string(record).expect("read dep_observed.txt");
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    lines.sort();
    lines
}

/// Split captured stream bytes into LINES, terminators included.
fn split_lines(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut lines = Vec::new();
    let mut current = Vec::new();
    for &b in bytes {
        current.push(b);
        if b == b'\n' {
            lines.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}
