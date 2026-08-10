//! D019 acceptance (Linux): under the canonical driver, Cargo's child
//! rustc argv — including `-C metadata` seeds and `-C extra-filename`
//! unit-hash suffixes — converges byte-for-byte across two different
//! host worktrees, and the produced output filenames match. The test
//! prints the toolchain-bound convergence digest so the same run on a
//! second machine of the platform class completes the cross-machine
//! comparison arm (recorded in the bead).
//!
//! Executes real `bwrap` namespaces; skips loudly on any host whose
//! [`HostIsolationSupport`] probe fails rather than fake a pass.
#![cfg(target_os = "linux")]

use rabs_sandbox::canonical_mounts::{CanonicalMountPlan, UnitMount};
use rabs_sandbox::canonical_namespace::{HostIsolationSupport, build_canonical_argv, command_for};
use rabs_sandbox::layout;
use rabs_sandbox::unit_convergence::{compare, convergence_digest, normalize, parse_wrapper_log};

fn supported() -> Option<HostIsolationSupport> {
    let support = HostIsolationSupport::probe();
    if support.missing_for_canonical().is_empty() {
        Some(support)
    } else {
        eprintln!(
            "SKIP: host cannot run D019 acceptance; missing {:?}",
            support.missing_for_canonical()
        );
        None
    }
}

/// The running toolchain root (parent of `bin/`), from $CARGO.
fn toolchain_dir() -> std::path::PathBuf {
    let cargo_path = std::env::var("CARGO").expect("cargo sets $CARGO for tests");
    std::path::Path::new(&cargo_path)
        .parent()
        .and_then(std::path::Path::parent)
        .expect("<root>/bin/cargo")
        .to_path_buf()
}

fn write(root: &std::path::Path, rel: &str, contents: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

/// A fixture with a build script (two rustc units) plus the argv-logging
/// wrapper the namespace runs as RUSTC_WRAPPER.
fn fixture(root: &std::path::Path) {
    write(
        root,
        "Cargo.toml",
        "[package]\nname = \"rabs-d019\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n",
    );
    write(root, "build.rs", "fn main() {}\n");
    write(root, "src/main.rs", "fn main() {}\n");
    write(
        root,
        "log-rustc.sh",
        "#!/bin/sh\n\
         line=$(printf '%s\\x1f' \"$@\")\n\
         printf '%s\\n' \"$line\" >> \"$RABS_ARGV_LOG\"\n\
         exec \"$@\"\n",
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            root.join("log-rustc.sh"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }
}

/// Build from one worktree; return (wrapper log, produced deps names).
fn build_and_log(
    support: &HostIsolationSupport,
    source_backing: &std::path::Path,
) -> (String, Vec<String>) {
    let cargo_home = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let out_backing = tempfile::tempdir().unwrap();
    let mut plan = CanonicalMountPlan::new(
        toolchain_dir(),
        source_backing,
        cargo_home.path(),
        home.path(),
    );
    plan.out_units.push(UnitMount {
        unit: "fixture".into(),
        backing: out_backing.path().to_path_buf(),
    });
    plan.extra_env.push((
        "CARGO_TARGET_DIR".into(),
        format!("{}/fixture", layout::OUT),
    ));
    plan.extra_env.push((
        "RUSTC_WRAPPER".into(),
        format!("{}/log-rustc.sh", layout::WORKSPACE),
    ));
    plan.extra_env.push((
        "RABS_ARGV_LOG".into(),
        format!("{}/fixture/rustc-argv.log", layout::OUT),
    ));
    let spec = plan.to_spec().unwrap();
    let launch = build_canonical_argv(
        &spec,
        support,
        "cargo",
        &["build".to_string(), "--offline".to_string()],
    )
    .unwrap();
    let out = command_for(&launch).output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "fixture build failed:\n{stderr}");
    let log = std::fs::read_to_string(out_backing.path().join("rustc-argv.log")).unwrap();
    let mut produced: Vec<String> = std::fs::read_dir(out_backing.path().join("debug/deps"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    produced.sort();
    (log, produced)
}

/// ACCEPTANCE: -C metadata, unit-hash-bearing extra-filenames, output
/// names, and the ENTIRE child rustc argv converge across two host
/// worktrees under the canonical driver.
#[test]
fn child_rustc_identity_converges_across_worktrees() {
    let Some(support) = supported() else { return };

    let worktree_a = tempfile::tempdir().unwrap();
    let worktree_b = tempfile::tempdir().unwrap();
    fixture(worktree_a.path());
    fixture(worktree_b.path());
    assert_ne!(worktree_a.path(), worktree_b.path());

    let (log_a, produced_a) = build_and_log(&support, worktree_a.path());
    let (log_b, produced_b) = build_and_log(&support, worktree_b.path());

    let a = normalize(parse_wrapper_log(&log_a));
    let b = normalize(parse_wrapper_log(&log_b));
    assert!(
        a.len() >= 2,
        "expected build-script + main units in the log, got {a:#?}"
    );
    // Metadata seeds must actually exist for the claim to mean anything.
    for invocation in &a {
        assert!(
            !invocation.metadata.is_empty(),
            "{} carries no -C metadata; the comparison would be vacuous",
            invocation.crate_name
        );
    }
    let divergences = compare(&a, &b);
    assert!(
        divergences.is_empty(),
        "unit identity diverged across worktrees (R43): {divergences:#?}"
    );
    assert_eq!(
        produced_a, produced_b,
        "output filenames (unit-hash-bearing) must match across worktrees"
    );

    // The toolchain-bound digest for the cross-machine arm: equal
    // digests on two machines of the platform class (same toolchain)
    // complete the D019 acceptance; recorded in the bead comments.
    let version = std::process::Command::new(toolchain_dir().join("bin/rustc"))
        .arg("-vV")
        .output()
        .unwrap();
    let version = String::from_utf8_lossy(&version.stdout);
    let digest = convergence_digest(version.trim(), &a);
    println!("D019-CONVERGENCE-DIGEST: {}", hex(&digest));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
