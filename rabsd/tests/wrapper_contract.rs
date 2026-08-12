//! C009: stable/beta/nightly wrapper-contract fixture matrix (risk
//! R29). Cargo/rustc contract drift — argv shapes, wrapper env, JSON
//! diagnostics framing, artifact notifications — must become red CI,
//! not production breakage. This suite CAPTURES the live contract of
//! the ambient toolchain (a real `cargo build` of a fixture crate with
//! a logging RUSTC_WRAPPER) as a host-independent fingerprint, and
//! compares it against the RECORDED fixture for that channel.
//!
//! The fingerprint deliberately contains SHAPES, never host values:
//! flag NAMES per unit class (plus the full `--error-format` and
//! `--json` values — that pair IS the diagnostics-framing contract),
//! and the NAME SET of `CARGO_*`/`RUSTC_*` env vars cargo presents to
//! wrapper invocations. Paths, hashes, and versions stay out, so one
//! fixture per channel holds across machines.
//!
//! Recording mode: `RABS_RECORD_CONTRACT=1 cargo test -p rabsd --test
//! wrapper_contract` rewrites the ambient channel's fixture. CI runs
//! the comparison across {stable, beta, nightly}
//! (`.github/workflows/wrapper-contract.yml`).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;

fn write(root: &std::path::Path, rel: &str, contents: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

/// One unit class's contract shape.
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct UnitShape {
    /// Flag names in canonical (sorted) order; `-C`/`-Z` keep their key
    /// (`-C metadata`), value-carrying long flags keep the name only —
    /// EXCEPT the framing pair, kept whole below.
    flags: BTreeSet<String>,
    /// The full `--error-format` value (framing contract).
    error_format: String,
    /// The full `--json` value set, sorted (framing contract: this is
    /// what makes artifact notifications appear).
    json: BTreeSet<String>,
}

/// The whole channel contract.
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct ContractFingerprint {
    /// Unit class → shape (`build-script`, `crate`).
    units: BTreeMap<String, UnitShape>,
    /// `CARGO_*` / `RUSTC_*` env NAME set cargo presents to wrappers.
    env_keys: BTreeSet<String>,
}

fn flag_name(argument: &str, next: Option<&str>) -> Option<String> {
    if let Some(codegen) = argument.strip_prefix("-C") {
        let key = if codegen.is_empty() {
            next.unwrap_or_default()
        } else {
            codegen
        };
        return Some(format!("-C {}", key.split('=').next().unwrap_or_default()));
    }
    if let Some(unstable) = argument.strip_prefix("-Z") {
        let key = if unstable.is_empty() {
            next.unwrap_or_default()
        } else {
            unstable
        };
        return Some(format!("-Z {}", key.split('=').next().unwrap_or_default()));
    }
    if argument.starts_with("--") {
        return Some(argument.split('=').next().unwrap_or_default().to_string());
    }
    if argument.starts_with('-') && argument.len() == 2 {
        return Some(argument.to_string());
    }
    None // positional (paths, crate names)
}

/// Capture one CHANNEL's live wrapper contract by driving that
/// channel's own cargo via `rustup run` — the harness itself builds
/// under the workspace's pinned nightly (stable rustc cannot compile
/// this workspace, and does not need to: the contract under test is
/// the channel's cargo→wrapper interface, not the harness).
fn capture_contract(channel: &str) -> ContractFingerprint {
    let source = tempfile::tempdir().unwrap();
    write(
        source.path(),
        "Cargo.toml",
        "[package]\nname = \"rabs-c009\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n",
    );
    write(source.path(), "build.rs", "fn main() {}\n");
    write(source.path(), "src/main.rs", "fn main() {}\n");
    let log_path = source.path().join("wrapper.log");
    let env_path = source.path().join("wrapper.env");
    write(
        source.path(),
        "log-rustc.sh",
        "#!/bin/sh\n\
         line=$(printf '%s\\037' \"$@\")\n\
         printf '%s\\n' \"$line\" >> \"$RABS_ARGV_LOG\"\n\
         env | cut -d= -f1 | grep -E '^(CARGO|RUSTC)' >> \"$RABS_ENV_LOG\"\n\
         exec \"$@\"\n",
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            source.path().join("log-rustc.sh"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }
    let target = tempfile::tempdir().unwrap();
    let status = std::process::Command::new("rustup")
        .args(["run", channel, "cargo", "build"])
        .current_dir(source.path())
        .env("RUSTC_WRAPPER", source.path().join("log-rustc.sh"))
        .env("RABS_ARGV_LOG", &log_path)
        .env("RABS_ENV_LOG", &env_path)
        .env("CARGO_TARGET_DIR", target.path())
        .env("CARGO_INCREMENTAL", "0") // pin: incremental flags vary by default profile
        .status()
        .expect("cargo build");
    assert!(status.success(), "fixture build failed");

    let mut units = BTreeMap::new();
    let log = std::fs::read_to_string(&log_path).unwrap();
    for line in log.lines() {
        let argv: Vec<&str> = line.split('\u{1f}').filter(|s| !s.is_empty()).collect();
        let Some(crate_name_at) = argv.iter().position(|a| *a == "--crate-name") else {
            continue;
        };
        let crate_name = argv.get(crate_name_at + 1).copied().unwrap_or_default();
        if crate_name == "___" {
            continue; // cargo's target-info probe
        }
        let class = if crate_name == "build_script_build" {
            "build-script"
        } else {
            "crate"
        };
        let mut flags = BTreeSet::new();
        let mut error_format = String::new();
        let mut json = BTreeSet::new();
        for (index, argument) in argv.iter().enumerate() {
            if let Some(value) = argument.strip_prefix("--error-format=") {
                error_format = value.to_string();
            } else if let Some(value) = argument.strip_prefix("--json=") {
                json = value.split(',').map(str::to_string).collect();
            }
            if let Some(name) = flag_name(argument, argv.get(index + 1).copied()) {
                flags.insert(name);
            }
        }
        units.insert(
            class.to_string(),
            UnitShape {
                flags,
                error_format,
                json,
            },
        );
    }
    assert!(
        units.contains_key("crate") && units.contains_key("build-script"),
        "capture must observe both unit classes: {:?}",
        units.keys().collect::<Vec<_>>()
    );

    let env_keys = std::fs::read_to_string(&env_path)
        .unwrap()
        .lines()
        // Keys that embed crate/package specifics or point at OUR
        // logging stay out of the cross-machine contract shape.
        //
        // `CARGO_BIN_EXE_*` is the same class of leak, and a nastier one:
        // the fixture build inherits this HARNESS's environment, so every
        // binary target we ever add to `rabsd` would otherwise show up as
        // "drift" in the channel's cargo→wrapper interface. It names our
        // own binaries; cargo never presents it to a real wrapper run.
        .filter(|key| {
            !key.starts_with("CARGO_PKG_")
                && !key.starts_with("CARGO_BIN_EXE_")
                && !key.starts_with("RABS_")
        })
        .map(str::to_string)
        .collect();

    ContractFingerprint { units, env_keys }
}

/// Channels under test: `RABS_CONTRACT_CHANNELS` (comma-separated) or
/// the full matrix. A channel whose toolchain is not installed FAILS —
/// a silently skipped channel would be a hole in the drift net.
fn channels() -> Vec<String> {
    std::env::var("RABS_CONTRACT_CHANNELS")
        .unwrap_or_else(|_| "stable,beta,nightly".to_string())
        .split(',')
        .map(str::trim)
        .filter(|channel| !channel.is_empty())
        .map(str::to_string)
        .collect()
}

/// THE matrix test: for each channel, capture the live contract and
/// compare to its recorded fixture (or re-record under
/// RABS_RECORD_CONTRACT=1).
#[test]
fn wrapper_contract_matches_the_recorded_channel_fixtures() {
    for channel in channels() {
        let probe = std::process::Command::new("rustup")
            .args(["run", &channel, "rustc", "-V"])
            .output()
            .expect("rustup present");
        assert!(
            probe.status.success(),
            "channel {channel} not installed — install it or narrow \
             RABS_CONTRACT_CHANNELS explicitly; a silent skip is a drift hole"
        );
        let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(format!("wrapper_contract_{channel}.json"));
        let live = capture_contract(&channel);

        if std::env::var("RABS_RECORD_CONTRACT").is_ok() {
            std::fs::create_dir_all(fixture_path.parent().unwrap()).unwrap();
            let mut file = std::fs::File::create(&fixture_path).unwrap();
            writeln!(file, "{}", serde_json::to_string_pretty(&live).unwrap()).unwrap();
            eprintln!("recorded {} fixture: {}", channel, fixture_path.display());
            continue;
        }

        let recorded = std::fs::read_to_string(&fixture_path).unwrap_or_else(|_| {
            panic!(
                "no recorded fixture for channel {channel} at {} — record one with \
                 RABS_RECORD_CONTRACT=1",
                fixture_path.display()
            )
        });
        let recorded: ContractFingerprint = serde_json::from_str(&recorded).unwrap();
        assert_eq!(
            recorded, live,
            "wrapper contract DRIFTED on channel {channel} (R29): recorded vs live differ"
        );
        eprintln!("channel {channel}: contract matches the recorded fixture");
    }
}
