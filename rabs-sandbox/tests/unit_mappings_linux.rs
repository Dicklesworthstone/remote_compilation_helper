//! D006 acceptance (Linux): an OUT_DIR-embedding build script produces
//! IDENTICAL bytes across two different host worktrees, because inside
//! the canonical namespace both worktrees are `/__rabs/workspace`, the
//! target dir is the canonical out unit, and therefore Cargo selects
//! the same unit hashes and the same OUT_DIR both times — no host path
//! reaches the embedded artifact.
//!
//! Executes real `bwrap` namespaces; skips loudly on any host whose
//! [`HostIsolationSupport`] probe fails rather than fake a pass.
#![cfg(target_os = "linux")]

use rabs_sandbox::canonical_mounts::{CanonicalMountPlan, UnitMount};
use rabs_sandbox::canonical_namespace::{HostIsolationSupport, build_canonical_argv, command_for};
use rabs_sandbox::layout;

fn supported() -> Option<HostIsolationSupport> {
    let support = HostIsolationSupport::probe();
    if support.missing_for_canonical().is_empty() {
        Some(support)
    } else {
        eprintln!(
            "SKIP: host cannot run D006 acceptance; missing {:?}",
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

/// The OUT_DIR-embedding fixture: build.rs bakes its OUT_DIR into
/// generated source that the binary carries as a string constant.
fn out_dir_embedding_fixture(root: &std::path::Path) {
    write(
        root,
        "Cargo.toml",
        "[package]\nname = \"rabs-d006\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n",
    );
    write(
        root,
        "build.rs",
        r#"fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let generated = format!("pub const BAKED_OUT_DIR: &str = {out_dir:?};\n");
    std::fs::write(std::path::Path::new(&out_dir).join("baked.rs"), generated).unwrap();
}
"#,
    );
    write(
        root,
        "src/main.rs",
        "include!(concat!(env!(\"OUT_DIR\"), \"/baked.rs\"));\nfn main() { println!(\"{BAKED_OUT_DIR}\"); }\n",
    );
}

/// Build the fixture from `source_backing` inside the canonical
/// namespace and return the produced binary's bytes.
fn build_from_worktree(
    support: &HostIsolationSupport,
    source_backing: &std::path::Path,
) -> Vec<u8> {
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
    std::fs::read(out_backing.path().join("debug/rabs-d006")).unwrap()
}

/// ACCEPTANCE: the same OUT_DIR-embedding fixture, materialized in two
/// DIFFERENT host worktrees, builds to byte-identical binaries — and
/// the baked OUT_DIR is the canonical path, not either host backing.
#[test]
fn out_dir_embedding_build_script_is_byte_identical_across_worktrees() {
    let Some(support) = supported() else { return };

    let worktree_a = tempfile::tempdir().unwrap();
    let worktree_b = tempfile::tempdir().unwrap();
    out_dir_embedding_fixture(worktree_a.path());
    out_dir_embedding_fixture(worktree_b.path());
    assert_ne!(
        worktree_a.path(),
        worktree_b.path(),
        "the two host worktrees must actually differ"
    );

    let bytes_a = build_from_worktree(&support, worktree_a.path());
    let bytes_b = build_from_worktree(&support, worktree_b.path());
    assert_eq!(
        bytes_a, bytes_b,
        "OUT_DIR-embedding build must be byte-identical across worktrees"
    );

    // The baked OUT_DIR is canonical (under the canonical target dir)
    // and neither host worktree path appears anywhere in the binary.
    let canonical_marker = format!("{}/fixture/debug/build/", layout::OUT);
    let contains = |haystack: &[u8], needle: &[u8]| {
        !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
    };
    assert!(
        contains(&bytes_a, canonical_marker.as_bytes()),
        "baked OUT_DIR must live under {canonical_marker}"
    );
    for host_path in [worktree_a.path(), worktree_b.path()] {
        assert!(
            !contains(&bytes_a, host_path.to_string_lossy().as_bytes()),
            "host worktree path {} leaked into the artifact",
            host_path.display()
        );
    }
}
