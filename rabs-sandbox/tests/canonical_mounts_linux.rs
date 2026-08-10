//! D005 acceptance (Linux): with the toolchain mounted at the canonical
//! `/__rabs/toolchain`, `rustc --print sysroot` and `rustc -vV` report the
//! canonical path (no host/digest path leaks), and a registry source
//! resolves at its checksum path inside the namespace.
//!
//! Executes real `bwrap` namespaces; skips loudly on any host whose
//! [`HostIsolationSupport`] probe fails rather than fake a pass.
#![cfg(target_os = "linux")]

use rabs_sandbox::canonical_mounts::{CanonicalMountPlan, ChecksumMount};
use rabs_sandbox::canonical_namespace::{HostIsolationSupport, build_canonical_argv, command_for};
use rabs_sandbox::layout;

fn supported() -> Option<HostIsolationSupport> {
    let support = HostIsolationSupport::probe();
    if support.missing_for_canonical().is_empty() {
        Some(support)
    } else {
        eprintln!(
            "SKIP: host cannot run D005 acceptance; missing {:?}",
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

fn plan_dirs() -> (
    tempfile::TempDir,
    tempfile::TempDir,
    tempfile::TempDir,
    CanonicalMountPlan,
) {
    let ws = tempfile::tempdir().unwrap();
    let cargo_home = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let plan = CanonicalMountPlan::new(toolchain_dir(), ws.path(), cargo_home.path(), home.path());
    (ws, cargo_home, home, plan)
}

/// ACCEPTANCE part 1: rustc reports the canonical sysroot and no leak.
#[test]
fn rustc_reports_canonical_sysroot_and_no_host_path_leak() {
    let Some(support) = supported() else { return };
    let (_ws, _ch, _home, plan) = plan_dirs();
    let spec = plan.to_spec().unwrap();

    // Invoke rustc via the canonical bin path — sysroot resolves relative to
    // the rustc binary's location, so this must report /__rabs/toolchain.
    let launch = build_canonical_argv(
        &spec,
        &support,
        "/__rabs/toolchain/bin/rustc",
        &["--print".to_string(), "sysroot".to_string()],
    )
    .unwrap();
    let out = command_for(&launch).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "rustc --print sysroot failed: {stderr}"
    );
    assert_eq!(
        stdout.trim(),
        layout::TOOLCHAIN,
        "sysroot must be the canonical path, got {stdout:?}"
    );

    // -vV host triple line is present, and the host toolchain backing path
    // must NOT appear anywhere in rustc's own version output.
    let vv = build_canonical_argv(
        &spec,
        &support,
        "/__rabs/toolchain/bin/rustc",
        &["-vV".to_string()],
    )
    .unwrap();
    let out = command_for(&vv).output().unwrap();
    let vout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    assert!(vout.contains("host:"), "rustc -vV shape: {vout}");
    let backing = toolchain_dir();
    assert!(
        !vout.contains(&backing.to_string_lossy().into_owned()),
        "hidden toolchain backing path leaked into rustc -vV: {vout}"
    );
}

/// ACCEPTANCE part 2: a registry source resolves at its checksum path.
#[test]
fn registry_source_resolves_at_checksum_path() {
    let Some(support) = supported() else { return };
    let (_ws, _ch, _home, mut plan) = plan_dirs();

    let reg_backing = tempfile::tempdir().unwrap();
    std::fs::write(reg_backing.path().join("Cargo.toml"), "name = \"x\"\n").unwrap();
    let checksum = "0123abcd4567ef89";
    plan.registry
        .push(ChecksumMount::new(checksum, reg_backing.path()));
    let spec = plan.to_spec().unwrap();

    let script = format!(
        "test -f /__rabs/registry/{checksum}/Cargo.toml && echo registry_ok; \
         test -x /__rabs/toolchain/bin/rustc && echo toolchain_ok"
    );
    let launch =
        build_canonical_argv(&spec, &support, "/bin/sh", &["-c".to_string(), script]).unwrap();
    let out = command_for(&launch).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "resolve script failed: {stdout}");
    assert!(stdout.contains("registry_ok"), "{stdout}");
    assert!(stdout.contains("toolchain_ok"), "{stdout}");
}

/// A full plan builds Cargo end to end using only canonical mounts (no
/// separately-passed toolchain bind), proving the plan is self-sufficient.
#[test]
fn full_plan_builds_cargo_fixture() {
    let Some(support) = supported() else { return };
    let (ws, _ch, _home, mut plan) = plan_dirs();

    std::fs::create_dir_all(ws.path().join("src")).unwrap();
    std::fs::write(
        ws.path().join("Cargo.toml"),
        "[package]\nname = \"rabs-d005\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n",
    )
    .unwrap();
    std::fs::write(ws.path().join("src/main.rs"), "fn main() {}\n").unwrap();

    let out_backing = tempfile::tempdir().unwrap();
    plan.out_units
        .push(rabs_sandbox::canonical_mounts::UnitMount {
            unit: "fixture".into(),
            backing: out_backing.path().to_path_buf(),
        });
    plan.extra_env.push((
        "CARGO_TARGET_DIR".into(),
        format!("{}/fixture", layout::OUT),
    ));
    let spec = plan.to_spec().unwrap();

    let launch = build_canonical_argv(
        &spec,
        &support,
        "cargo",
        &["build".to_string(), "--offline".to_string()],
    )
    .unwrap();
    let out = command_for(&launch).output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "cargo build via mount plan failed:\n{stderr}"
    );
    assert!(out_backing.path().join("debug/rabs-d005").exists());
}
