//! D011 acceptance (Linux): the M1 harness. Two host worktrees of the
//! same fixture workspace run the same canonical command; the suite
//! collects `.rmeta`, `.rlib`, dep-info, and binary artifacts from both
//! and requires byte equality with CLASSIFIED findings on any
//! divergence — plus the D019 argv comparison, so command and artifact
//! sides are checked together. Coverage guards make a vacuous pass
//! impossible.
//!
//! Executes real `bwrap` namespaces; skips loudly on any host whose
//! [`HostIsolationSupport`] probe fails rather than fake a pass.
#![cfg(target_os = "linux")]

use rabs_sandbox::canonical_mounts::{CanonicalMountPlan, UnitMount};
use rabs_sandbox::canonical_namespace::{HostIsolationSupport, build_canonical_argv, command_for};
use rabs_sandbox::equality_suite::{
    ArtifactClass, classes_covered, collect_run_artifacts, compare_runs,
};
use rabs_sandbox::layout;
use rabs_sandbox::unit_convergence::{compare, normalize, parse_wrapper_log};

fn supported() -> Option<HostIsolationSupport> {
    let support = HostIsolationSupport::probe();
    if support.missing_for_canonical().is_empty() {
        Some(support)
    } else {
        eprintln!(
            "SKIP: host cannot run D011 acceptance; missing {:?}",
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

/// Fixture workspace: lib + bin targets (rmeta/rlib/dep-info/binary all
/// produced) with a build script and the argv-logging wrapper.
fn fixture(root: &std::path::Path) {
    write(
        root,
        "Cargo.toml",
        "[package]\nname = \"rabs-d011\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n",
    );
    write(root, "build.rs", "fn main() {}\n");
    write(root, "src/lib.rs", "pub fn answer() -> u32 { 42 }\n");
    write(
        root,
        "src/main.rs",
        "fn main() { println!(\"{}\", rabs_d011::answer()); }\n",
    );
    write(
        root,
        "log-rustc.sh",
        "#!/bin/sh\n\
         line=$(printf '%s\\037' \"$@\")\n\
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

/// Build from one worktree; return (out backing dir, wrapper log).
fn build_run(
    support: &HostIsolationSupport,
    source_backing: &std::path::Path,
) -> (tempfile::TempDir, String) {
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
    (out_backing, log)
}

/// ACCEPTANCE: the M1 harness green on the fixture workspace — argv
/// AND artifact equality across two worktrees, with coverage guards.
#[test]
fn m1_harness_argv_and_artifacts_equal_across_worktrees() {
    let Some(support) = supported() else { return };

    let worktree_a = tempfile::tempdir().unwrap();
    let worktree_b = tempfile::tempdir().unwrap();
    fixture(worktree_a.path());
    fixture(worktree_b.path());

    let (out_a, log_a) = build_run(&support, worktree_a.path());
    let (out_b, log_b) = build_run(&support, worktree_b.path());

    // Command side (D019 comparator).
    let argv_a = normalize(parse_wrapper_log(&log_a));
    let argv_b = normalize(parse_wrapper_log(&log_b));
    assert!(argv_a.len() >= 3, "lib + bin + build-script units expected");
    let argv_divergences = compare(&argv_a, &argv_b);
    assert!(
        argv_divergences.is_empty(),
        "argv diverged: {argv_divergences:#?}"
    );

    // Artifact side: rmeta / rlib / dep-info / binary all present and
    // byte-equal, with classified findings on anything else.
    let run_a = collect_run_artifacts(&out_a.path().join("debug/deps")).unwrap();
    let run_b = collect_run_artifacts(&out_b.path().join("debug/deps")).unwrap();
    let required = [
        ArtifactClass::Rmeta,
        ArtifactClass::Rlib,
        ArtifactClass::DepInfo,
        ArtifactClass::Binary,
    ];
    assert!(
        classes_covered(&run_a, &required),
        "coverage guard: expected rmeta+rlib+dep-info+binary, got {:?}",
        run_a.artifacts.keys().collect::<Vec<_>>()
    );
    let findings = compare_runs(&run_a, &run_b);
    assert!(
        findings.is_empty(),
        "cross-worktree artifact divergence (classified): {findings:#?}"
    );
}
