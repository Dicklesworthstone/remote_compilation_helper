//! D004 acceptance (Linux): a coherent D018 snapshot materialized as
//! the workspace mounts READ-ONLY in the canonical namespace — a
//! write-to-source attempt inside the sandbox FAILS as an error, output
//! roots stay writable, a full cargo build still succeeds from the
//! immutable source, and the snapshot identity is bound into the plan's
//! provenance.
//!
//! Executes real `bwrap` namespaces; skips loudly on any host whose
//! [`HostIsolationSupport`] probe fails rather than fake a pass.
#![cfg(target_os = "linux")]

use rabs_sandbox::canonical_mounts::{CanonicalMountPlan, UnitMount};
use rabs_sandbox::canonical_namespace::{HostIsolationSupport, build_canonical_argv, command_for};
use rabs_sandbox::layout;
use rabs_sandbox::snapshot_capture::{CaptureConfig, capture_coherent, scan_directory};

fn supported() -> Option<HostIsolationSupport> {
    let support = HostIsolationSupport::probe();
    if support.missing_for_canonical().is_empty() {
        Some(support)
    } else {
        eprintln!(
            "SKIP: host cannot run D004 acceptance; missing {:?}",
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

/// ACCEPTANCE: capture a real coherent snapshot, mount it as the
/// immutable workspace, and prove — inside the namespace — that source
/// writes fail loudly, outputs write fine, cargo builds from the
/// read-only source, and provenance carries the manifest digest.
#[test]
fn immutable_snapshot_source_refuses_writes_and_still_builds() {
    let Some(support) = supported() else { return };

    // A real fixture crate, captured through the D018 engine.
    let source = tempfile::tempdir().unwrap();
    write(
        source.path(),
        "Cargo.toml",
        "[package]\nname = \"rabs-d004\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n",
    );
    write(source.path(), "src/main.rs", "fn main() {}\n");
    let manifest = capture_coherent(CaptureConfig::generation_scan(), "workspace", |_a, _p| {
        scan_directory(source.path(), false)
    })
    .unwrap();
    let provenance = manifest.provenance();

    let cargo_home = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let out_backing = tempfile::tempdir().unwrap();
    let mut plan = CanonicalMountPlan::new(
        toolchain_dir(),
        "/nonexistent-placeholder-workspace",
        cargo_home.path(),
        home.path(),
    )
    .with_immutable_source(source.path(), provenance.clone());
    assert_eq!(
        plan.immutable_source.as_ref().unwrap().manifest_sha256,
        manifest.manifest_sha256,
        "snapshot identity must be bound into the plan's provenance"
    );
    plan.out_units.push(UnitMount {
        unit: "fixture".into(),
        backing: out_backing.path().to_path_buf(),
    });
    plan.extra_env.push((
        "CARGO_TARGET_DIR".into(),
        format!("{}/fixture", layout::OUT),
    ));
    let spec = plan.to_spec().unwrap();

    // Part 1: write-to-source attempts FAIL inside the sandbox — both
    // overwriting an existing file and creating a new one — while the
    // output root accepts writes. Errors, not silent divergence.
    let script = format!(
        "if echo mutated > {ws}/src/main.rs 2>/dev/null; then echo SRC_OVERWRITE_ALLOWED; fi; \
         if touch {ws}/injected.rs 2>/dev/null; then echo SRC_CREATE_ALLOWED; fi; \
         if echo ok > {out}/fixture-probe 2>/dev/null; then echo OUT_WRITE_OK; fi",
        ws = layout::WORKSPACE,
        out = layout::OUT,
    );
    let launch =
        build_canonical_argv(&spec, &support, "/bin/sh", &["-c".to_string(), script]).unwrap();
    let out = command_for(&launch).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("SRC_OVERWRITE_ALLOWED") && !stdout.contains("SRC_CREATE_ALLOWED"),
        "source must be immutable inside the sandbox: {stdout}"
    );
    assert!(
        stdout.contains("OUT_WRITE_OK"),
        "output root must remain writable: {stdout}"
    );
    // And the backing snapshot on the host is byte-identical to what
    // was captured — nothing leaked through.
    assert_eq!(
        std::fs::read_to_string(source.path().join("src/main.rs")).unwrap(),
        "fn main() {}\n"
    );
    assert!(!source.path().join("injected.rs").exists());

    // Part 2: a full cargo build still succeeds from the read-only
    // immutable source (outputs land in the out unit, not the source).
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
        "cargo build from immutable source failed:\n{stderr}"
    );
    assert!(out_backing.path().join("debug/rabs-d004").exists());
}
