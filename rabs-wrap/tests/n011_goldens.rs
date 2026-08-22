//! N011 golden corpus: ordered directive/stdout/DEP_LINKS_* fixtures
//! across installed cargo channels (bead rabs-root-4pidu.32.11).
//!
//! Per channel, a real build of the two-crate golden fixture produces
//! THREE sections of the replay contract:
//!
//! 1. `transcript_lines` — the provider build script's captured stdout,
//!    byte-exact lines in arrival order;
//! 2. `directives` — the [`extract_directives`] view (seq, registry
//!    kind, captured key, parsed value);
//! 3. `dep_vars` — the DEP_* environment the CONSUMER's build script
//!    actually observed (sorted NAME=VALUE), the downstream half.
//!
//! Modes:
//! - compare (default): each channel's sections must equal its
//!   committed golden (`tests/goldens/n011/<channel>.json`) exactly;
//!   channels without a committed golden are SKIPPED loudly;
//! - regenerate (`N011_REGEN=1`): write the goldens instead, so a
//!   toolchain bump refreshes evidence deliberately rather than by
//!   silent drift.
//!
//! THE CROSS-CHANNEL LAW, asserted whenever ≥2 channels run: sections
//! 1–3 must be IDENTICAL across channels — same source, same bytes,
//! same downstream env, regardless of toolchain vintage or target-tree
//! layout. A violation means the replay contract is not portable.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use rabs_protocol::directive_manifest::extract_directives;
use rabs_protocol::stream_chunker::{CanonicalObservation, StdStream};
use serde_json::{Value, json};

const FIXTURE_NAME: &str = "n011_goldens";
const LINKS: &[u8] = b"GoldenLinks";
const CARGO_PHASE_BUDGET_SECS: u64 = 180;
const CHANNELS: [&str; 3] = ["stable", "beta", "nightly"];

#[test]
fn n011_ordered_goldens_across_channels() {
    let regen = std::env::var("N011_REGEN").is_ok();
    let mut captured: Vec<(String, Value)> = Vec::new();

    for channel in installed_channels() {
        println!("[n011] probing channel {channel}");
        let dir = tempfile::tempdir().expect("scratch dir");
        let project = copy_fixture(dir.path());
        let outcome = build_consumer(&channel, &project);
        assert!(
            outcome.success && !outcome.timed_out,
            "[{channel}] stock build failed (timed_out={}): {}",
            outcome.timed_out,
            outcome.stderr_tail
        );

        let transcript_lines = provider_transcript_lines(&project);
        assert!(
            !transcript_lines.is_empty(),
            "[{channel}] empty provider transcript"
        );
        let observations: Vec<CanonicalObservation> = transcript_lines
            .iter()
            .enumerate()
            .map(|(i, line)| CanonicalObservation::Line {
                stream: StdStream::Stdout,
                seq: i as u64 + 1,
                bytes: format!("{line}\n").into_bytes(),
            })
            .collect();
        let manifest = extract_directives(&observations).expect("ordered transcript");
        let directives: Vec<Value> = manifest
            .entries
            .iter()
            .filter_map(|e| match e {
                rabs_protocol::directive_manifest::ManifestEntry::Directive {
                    seq,
                    kind,
                    key,
                    value,
                    ..
                } => Some(json!({
                    "seq": seq,
                    "registry_kind": kind.key(),
                    "key": String::from_utf8_lossy(key),
                    "value": value.as_deref().map(String::from_utf8_lossy).map(|v| v.to_string()),
                })),
                _ => None,
            })
            .collect();
        let dep_vars = consumer_observed_dep_vars(&project);

        let section = json!({
            "channel": channel,
            "exit_status": 0,
            "transcript_lines": transcript_lines,
            "directives": directives,
            "dep_vars": dep_vars,
        });
        if regen {
            let path = golden_path(&channel);
            fs::create_dir_all(path.parent().unwrap()).expect("mkdir goldens");
            fs::write(
                &path,
                serde_json::to_string_pretty(&section).expect("golden serializes"),
            )
            .expect("write golden");
            println!("[n011] REGENERATED golden for {channel}");
        } else {
            let path = golden_path(&channel);
            match fs::read_to_string(&path) {
                Ok(text) => {
                    let golden: Value = serde_json::from_str(&text).expect("golden parses");
                    for field in ["transcript_lines", "directives", "dep_vars"] {
                        assert_eq!(
                            section[field], golden[field],
                            "[{channel}] {field} diverges from committed golden"
                        );
                    }
                }
                Err(_) => {
                    println!(
                        "[n011] SKIP compare for {channel}: no committed golden at {}",
                        path.display()
                    );
                }
            }
        }
        captured.push((channel.clone(), section));
    }

    // THE CROSS-CHANNEL LAW: every captured pair agrees on the three
    // content sections (the channel field itself differs on purpose).
    for pair in captured.windows(2) {
        let (a_name, a) = &pair[0];
        let (b_name, b) = &pair[1];
        for field in ["transcript_lines", "directives", "dep_vars"] {
            assert_eq!(
                a[field], b[field],
                "{a_name} vs {b_name}: {field} must be identical across channels"
            );
        }
    }
    if captured.len() >= 2 {
        println!(
            "[n011] cross-channel law holds across {} channels: {:?}",
            captured.len(),
            captured.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>()
        );
    }
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

fn installed_channels() -> Vec<String> {
    let rustup_ok = Command::new("rustup")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    let mut found = Vec::new();
    if rustup_ok {
        for name in CHANNELS {
            let Ok(out) = Command::new("rustup")
                .args(["which", "cargo", "--toolchain", name])
                .output()
            else {
                continue;
            };
            if out.status.success()
                && !String::from_utf8_lossy(&out.stdout).trim().is_empty()
            {
                found.push(name.to_owned());
            }
        }
    } else {
        found.push("default".to_owned());
    }
    found
}

fn cargo_bin_for(channel: &str) -> String {
    let Ok(out) = Command::new("rustup")
        .args(["which", "cargo", "--toolchain", channel])
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

fn build_consumer(channel: &str, project: &Path) -> RunOutcome {
    let mut cmd = Command::new(cargo_bin_for(channel));
    cmd.arg("build")
        .current_dir(project.join("consumer"))
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("CARGO_BUILD_TARGET_DIR")
        .env_remove("RUSTUP_TOOLCHAIN");
    run_bounded(cmd)
}

// --- Fixture staging -------------------------------------------------------

fn copy_fixture(scratch: &Path) -> PathBuf {
    let src_root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(FIXTURE_NAME);
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

// --- Target-tree layout (content-identified) ---------------------------------

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

fn directive_cache(run_dir: &Path) -> Option<PathBuf> {
    let nested = run_dir.join("run/stdout");
    if nested.is_file() {
        return Some(nested);
    }
    let flat = run_dir.join("output");
    flat.is_file().then_some(flat)
}

/// The provider's captured stdout cache under the shared target tree.
fn provider_directive_cache(project: &Path) -> Option<PathBuf> {
    all_build_dirs(&project.join("consumer/target/debug/build"))
        .into_iter()
        .filter(|d| d.to_string_lossy().contains("n011_golden_provider"))
        .find_map(|d| directive_cache(&d))
}

/// Provider stdout split into UTF-8 lines (terminators stripped).
fn provider_transcript_lines(project: &Path) -> Vec<String> {
    let cache = provider_directive_cache(project).expect("provider directive cache");
    let mut bytes = Vec::new();
    fs::File::open(cache)
        .expect("open cache")
        .read_to_end(&mut bytes)
        .expect("read cache");
    String::from_utf8(bytes)
        .expect("stdout cache is UTF-8")
        .lines()
        .map(str::to_owned)
        .collect()
}

/// Consumer-recorded DEP_* observation, sorted.
fn consumer_observed_dep_vars(project: &Path) -> Vec<String> {
    let record = all_build_dirs(&project.join("consumer/target/debug/build"))
        .into_iter()
        .find_map(|d| {
            let p = d.join("out/dep_observed.txt");
            p.is_file().then_some(p)
        })
        .expect("consumer recorded dep_observed.txt");
    let text = fs::read_to_string(record).expect("read dep_observed.txt");
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    lines.sort();
    lines
}

// --- Golden paths ------------------------------------------------------------

fn golden_path(channel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/goldens/n011")
        .join(format!("{channel}.json"))
}
