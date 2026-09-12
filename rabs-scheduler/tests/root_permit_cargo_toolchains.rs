//! I019: root-permit accounting around REAL Cargo across installed
//! toolchains (rabs-root-4pidu.27.19).
//!
//! The pure-policy property suite (`root_permit_token_storm.rs`) proves
//! conservation over the broker alone. This leg pins the same accounting
//! around an ACTUAL `cargo` process, per supported toolchain channel
//! (stable / beta / nightly, discovered via `rustup which cargo`):
//!
//! - open a C-capacity root permit (implicit token consumed at open);
//! - issue exactly `C-1` transferables — the jobserver tokens a
//!   coordinating Cargo would hand its children;
//! - run `cargo check -j <C>` on a dependency-free scratch crate and
//!   require success (every tested channel accepts `-j == capacity`);
//! - release every token, re-fill, confirm the typed ceiling;
//! - conservation asserted at every step.
//!
//! fd-level jobserver INJECTION (feeding our tokens to child processes
//! through `CARGO_MAKEFLAGS`) arrives with the wrapper plumbing from
//! I002's follow-ups; until that surface exists this is the maximal
//! honest cross-toolchain verification.

use rabs_scheduler::acquisition_order::{GrantRefusal, RootGrant};

const CHANNELS: [&str; 3] = ["stable", "beta", "nightly"];
const CAPACITY: u32 = 4;

fn tool_for(channel: &str, tool: &str) -> Option<std::path::PathBuf> {
    let output = std::process::Command::new("rustup")
        .args(["which", "--toolchain", channel, tool])
        .env("RUSTUP_AUTO_INSTALL", "0")
        .env_remove("RUSTUP_TOOLCHAIN")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if path.is_empty() {
        None
    } else {
        Some(std::path::PathBuf::from(path))
    }
}

/// A dependency-free scratch crate: builds offline on every channel.
fn scratch_crate(dir: &std::path::Path) {
    std::fs::create_dir_all(dir.join("src")).expect("crate dirs");
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"i019_probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n",
    )
    .expect("manifest");
    std::fs::write(dir.join("src/main.rs"), "fn main() {}\n").expect("entrypoint");
    // Observe the compiler chosen by the real Cargo invocation, rather than
    // assuming that launching a channel's Cargo also selects its rustc.
    std::fs::write(
        dir.join("build.rs"),
        r#"fn main() {
    let rustc = std::env::var_os("RUSTC").expect("Cargo-selected compiler");
    let output = std::process::Command::new(&rustc)
        .arg("-vV")
        .output()
        .expect("compiler identity");
    assert!(output.status.success(), "compiler identity failed");
    let root = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    std::fs::write(root.join("observed-rustc-path"), rustc.to_str().unwrap()).unwrap();
    std::fs::write(root.join("observed-rustc-version"), output.stdout).unwrap();
}
"#,
    )
    .expect("compiler identity build script");
}

#[test]
fn grant_accounts_exactly_around_real_cargo_on_every_installed_channel() {
    let mut tested = 0usize;
    for channel in CHANNELS {
        let Some(cargo) = tool_for(channel, "cargo") else {
            eprintln!("channel {channel} not installed — skipped");
            continue;
        };
        let rustc = tool_for(channel, "rustc")
            .unwrap_or_else(|| panic!("{channel}: installed Cargo requires its rustc"));
        let identity = std::process::Command::new(&rustc)
            .arg("-vV")
            .env("RUSTUP_TOOLCHAIN", channel)
            .env("RUSTUP_AUTO_INSTALL", "0")
            .output()
            .expect("selected compiler identity");
        assert!(
            identity.status.success(),
            "{channel}: rustc -vV failed: {}",
            String::from_utf8_lossy(&identity.stderr)
        );
        eprintln!(
            "{channel}: cargo={}, rustc={}\n{}",
            cargo.display(),
            rustc.display(),
            String::from_utf8_lossy(&identity.stdout)
        );
        let dir = tempfile::tempdir().expect("scratch dir");
        scratch_crate(dir.path());

        // Open the root permit: implicit token consumed HERE, at open.
        let mut grant = RootGrant::open(CAPACITY).expect("opens");
        assert_eq!(grant.transferable_budget(), CAPACITY - 1);

        // Issue the full transferable budget — the children's jobserver
        // share — BEFORE the coordinating Cargo process starts.
        let mut held = Vec::new();
        while let Ok(token) = grant.issue_transferable() {
            held.push(token);
        }
        assert_eq!(held.len(), CAPACITY as usize - 1);

        // The REAL Cargo process runs under the implicit token while the
        // transferables are outstanding.
        let status = std::process::Command::new(&cargo)
            .arg("check")
            .arg("--offline")
            .arg(format!("-j{CAPACITY}"))
            .current_dir(dir.path())
            // An explicit empty value also overrides ancestor Cargo config:
            // RCH scratch directories can inherit this repository's nightly
            // rustflags. Clear parent wrappers/targets and select the compiler.
            .env("RUSTFLAGS", "")
            .env_remove("CARGO_ENCODED_RUSTFLAGS")
            .env_remove("CARGO_BUILD_RUSTFLAGS")
            .env_remove("RUSTC_WRAPPER")
            .env_remove("RUSTC_WORKSPACE_WRAPPER")
            .env_remove("CARGO_BUILD_RUSTC_WRAPPER")
            .env_remove("CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER")
            .env_remove("CARGO_TARGET_DIR")
            .env_remove("CARGO_BUILD_TARGET_DIR")
            .env_remove("CARGO_BUILD_TARGET")
            .env("RUSTC", &rustc)
            .env("RUSTUP_TOOLCHAIN", channel)
            .env("RUSTUP_AUTO_INSTALL", "0")
            .status()
            .expect("spawn cargo");
        assert!(
            status.success(),
            "{channel}: cargo check -j{CAPACITY} must succeed"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("observed-rustc-path"))
                .expect("Cargo must run the compiler observation build script"),
            rustc.to_str().expect("rustup compiler path is UTF-8"),
            "{channel}: Cargo must use the explicitly selected compiler"
        );
        assert_eq!(
            std::fs::read(dir.path().join("observed-rustc-version"))
                .expect("build script compiler version"),
            identity.stdout,
            "{channel}: Cargo's compiler identity must match the selected channel"
        );

        // Children finished: every transferable returns; books balance.
        for token in &held {
            grant.release(token).expect("release after build");
        }
        assert_eq!(grant.transferable_outstanding(), 0);

        // Re-fill and confirm the typed ceiling, per channel.
        for _ in 1..CAPACITY {
            assert!(grant.issue_transferable().is_ok());
        }
        let refusal = grant.issue_transferable().expect_err("ceiling");
        assert_eq!(
            refusal,
            GrantRefusal::TransferablesExhausted {
                outstanding: CAPACITY - 1,
                capacity: CAPACITY
            }
        );
        grant.close();

        tested += 1;
    }
    // The development fleet installs all three channels; a host without
    // any would make this leg vacuous, so say so loudly.
    assert!(
        tested > 0,
        "no stable/beta/nightly toolchains found via rustup"
    );
}
