//! D007 acceptance (Linux): capability detection against the real
//! mounted toolchain, and a DIFFERENTIAL fixture proving remap flags
//! change what debuginfo embeds — without remap the binary carries the
//! canonical workspace root (`DW_AT_comp_dir`), with remap it does not.
//!
//! Executes real `bwrap` namespaces; skips loudly on any host whose
//! [`HostIsolationSupport`] probe fails rather than fake a pass.
#![cfg(target_os = "linux")]

use rabs_sandbox::canonical_mounts::{CanonicalMountPlan, UnitMount};
use rabs_sandbox::canonical_namespace::{HostIsolationSupport, build_canonical_argv, command_for};
use rabs_sandbox::layout;
use rabs_sandbox::path_remap::{RemapCapability, inject_remap_into_plan, project_relative_entries};

fn supported() -> Option<HostIsolationSupport> {
    let support = HostIsolationSupport::probe();
    if support.missing_for_canonical().is_empty() {
        Some(support)
    } else {
        eprintln!(
            "SKIP: host cannot run D007 acceptance; missing {:?}",
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

/// Probe `rustc -vV` INSIDE the canonical namespace (against the mounted
/// `/__rabs/toolchain`) and detect capabilities from its real output.
fn detect_live_capability(support: &HostIsolationSupport) -> RemapCapability {
    let ws = tempfile::tempdir().unwrap();
    let cargo_home = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let plan = CanonicalMountPlan::new(toolchain_dir(), ws.path(), cargo_home.path(), home.path());
    let spec = plan.to_spec().unwrap();
    let launch = build_canonical_argv(
        &spec,
        support,
        &format!("{}/bin/rustc", layout::TOOLCHAIN),
        &["-vV".to_string()],
    )
    .unwrap();
    let out = command_for(&launch).output().unwrap();
    assert!(out.status.success(), "rustc -vV probe failed");
    RemapCapability::detect(&String::from_utf8_lossy(&out.stdout))
}

/// Build the fixture in the canonical namespace, with or without the
/// D007 remap injection, and return the produced binary's bytes.
fn build_fixture(support: &HostIsolationSupport, with_remap: bool) -> Vec<u8> {
    let ws = tempfile::tempdir().unwrap();
    let cargo_home = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(ws.path().join("src")).unwrap();
    std::fs::write(
        ws.path().join("Cargo.toml"),
        "[package]\nname = \"rabs-d007\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n",
    )
    .unwrap();
    std::fs::write(ws.path().join("src/main.rs"), "fn main() {}\n").unwrap();

    let mut plan =
        CanonicalMountPlan::new(toolchain_dir(), ws.path(), cargo_home.path(), home.path());
    let out_backing = tempfile::tempdir().unwrap();
    plan.out_units.push(UnitMount {
        unit: "fixture".into(),
        backing: out_backing.path().to_path_buf(),
    });
    plan.extra_env.push((
        "CARGO_TARGET_DIR".into(),
        format!("{}/fixture", layout::OUT),
    ));
    if with_remap {
        let capability = detect_live_capability(support);
        assert!(
            capability.remap_path_prefix,
            "the fixture toolchain must support --remap-path-prefix"
        );
        let applied =
            inject_remap_into_plan(&mut plan, capability, &project_relative_entries()).unwrap();
        assert!(applied, "remap must actually be injected for the diff arm");
    }
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
    std::fs::read(out_backing.path().join("debug/rabs-d007")).unwrap()
}

/// ACCEPTANCE part 1: capability detection against the real toolchain —
/// the mounted rustc reports a version whose parsed capabilities include
/// `--remap-path-prefix` (any modern toolchain), detected from live
/// `-vV` output, not assumed.
#[test]
fn live_toolchain_capability_detection() {
    let Some(support) = supported() else { return };
    let capability = detect_live_capability(&support);
    assert!(
        capability.remap_path_prefix,
        "mounted toolchain must detect --remap-path-prefix support"
    );
}

/// ACCEPTANCE part 2: the differential fixture. The SAME fixture built
/// in the SAME canonical namespace embeds the canonical workspace root
/// in debuginfo without remap, and stops embedding it with the D007
/// injection — proving the flags were applied and did the remapping.
#[test]
fn differential_fixture_shows_debuginfo_remapped() {
    let Some(support) = supported() else { return };
    let needle = layout::WORKSPACE.as_bytes();

    let plain = build_fixture(&support, false);
    assert!(
        plain.windows(needle.len()).any(|window| window == needle),
        "control arm must embed {} in debuginfo (comp_dir) — \
         if it does not, the differential proves nothing",
        layout::WORKSPACE
    );

    let remapped = build_fixture(&support, true);
    assert!(
        !remapped
            .windows(needle.len())
            .any(|window| window == needle),
        "remapped arm must NOT embed {} anywhere in the binary",
        layout::WORKSPACE
    );
}
