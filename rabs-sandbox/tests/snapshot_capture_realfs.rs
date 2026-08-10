//! D018 acceptance against the REAL filesystem: coherent capture of an
//! actual tree via descriptor-verified reads, a deterministic
//! concurrent-mutation arm that forces retry and yields only the
//! post-mutation world, sustained mutation refusing with a typed
//! refusal, and `.git`/`target`/ephemeral-lock membership enforced on
//! disk. Runs on any host (no namespace primitives required).

use rabs_sandbox::snapshot_capture::{
    CaptureConfig, CaptureError, MemberKind, capture_coherent, scan_directory,
};
use sha2::{Digest, Sha256};
use std::path::Path;

fn write(root: &Path, rel: &str, contents: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

fn fixture_tree(root: &Path) {
    write(root, "Cargo.toml", "[package]\nname=\"fx\"\n");
    write(root, "Cargo.lock", "# lock\n");
    write(root, "src/lib.rs", "pub fn f() {}\n");
    write(root, ".cargo/config.toml", "[build]\n");
    write(root, "rust-toolchain.toml", "[toolchain]\n");
    // Members that must NOT appear:
    write(root, "target/debug/fx.d", "build output\n");
    write(root, ".git/HEAD", "ref: refs/heads/main\n");
    write(root, ".cargo/.package-cache", "");
}

#[test]
fn quiet_tree_captures_and_membership_is_enforced_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    fixture_tree(dir.path());
    #[cfg(unix)]
    std::os::unix::fs::symlink("src/lib.rs", dir.path().join("link.rs")).unwrap();

    let manifest = capture_coherent(CaptureConfig::generation_scan(), "workspace", |_a, _p| {
        scan_directory(dir.path(), false)
    })
    .unwrap();

    // Included members, with REAL content hashes.
    match &manifest.members["src/lib.rs"] {
        MemberKind::Regular {
            size,
            content_sha256,
            ..
        } => {
            assert_eq!(*size, b"pub fn f() {}\n".len() as u64);
            assert_eq!(*content_sha256, sha256(b"pub fn f() {}\n"));
        }
        other => panic!("src/lib.rs: {other:?}"),
    }
    for member in ["Cargo.lock", ".cargo/config.toml", "rust-toolchain.toml"] {
        assert!(manifest.members.contains_key(member), "{member} missing");
    }
    #[cfg(unix)]
    assert_eq!(
        manifest.members["link.rs"],
        MemberKind::Symlink {
            target: "src/lib.rs".into()
        },
        "symlink structure is preserved, not followed"
    );
    // Excluded members stay excluded on the real walk.
    assert!(
        !manifest
            .members
            .keys()
            .any(|k| k.starts_with("target") || k.starts_with(".git")),
        "target/ and .git must not be captured: {:?}",
        manifest.members.keys().collect::<Vec<_>>()
    );
    assert!(!manifest.members.contains_key(".cargo/.package-cache"));
}

#[test]
fn real_mid_scan_mutation_forces_retry_and_only_the_new_world_survives() {
    // THE acceptance on real I/O: between the two scans of attempt 0
    // the "concurrent editor" rewrites a file AND adds a new one. The
    // engine must discard attempt 0 wholesale; the manifest must be
    // exactly the post-mutation world — a mixed manifest (old lib.rs
    // hash, or missing new file) is the I2 violation this test exists
    // to catch.
    let dir = tempfile::tempdir().unwrap();
    fixture_tree(dir.path());

    let mut mutated = false;
    let manifest = capture_coherent(CaptureConfig::generation_scan(), "workspace", |_a, pass| {
        let scan = scan_directory(dir.path(), false);
        if pass == 0 && !mutated {
            mutated = true;
            write(dir.path(), "src/lib.rs", "pub fn f() { /* edited */ }\n");
            write(dir.path(), "src/new_module.rs", "pub struct New;\n");
        }
        scan
    })
    .unwrap();

    match &manifest.members["src/lib.rs"] {
        MemberKind::Regular { content_sha256, .. } => assert_eq!(
            *content_sha256,
            sha256(b"pub fn f() { /* edited */ }\n"),
            "manifest must carry the POST-mutation bytes only"
        ),
        other => panic!("src/lib.rs: {other:?}"),
    }
    assert!(
        manifest.members.contains_key("src/new_module.rs"),
        "the file added mid-capture must be present in the coherent retry"
    );
}

#[test]
fn sustained_real_mutation_refuses_with_a_typed_refusal() {
    let dir = tempfile::tempdir().unwrap();
    fixture_tree(dir.path());

    let mut tick = 0u32;
    let err = capture_coherent(CaptureConfig::generation_scan(), "workspace", |_a, _p| {
        tick += 1;
        // Every scan sees a different world: a hot editor loop.
        write(
            dir.path(),
            "src/lib.rs",
            &format!("pub fn f() {{ /* {tick} */ }}\n"),
        );
        scan_directory(dir.path(), false)
    })
    .unwrap_err();

    match err {
        CaptureError::Incoherent(refusal) => assert_eq!(refusal.attempts, 3),
        CaptureError::Io(io) => panic!("wrong class: {io}"),
    }
}

#[test]
fn declared_git_state_reveals_git_and_changes_the_manifest() {
    let dir = tempfile::tempdir().unwrap();
    fixture_tree(dir.path());

    let hidden = capture_coherent(CaptureConfig::generation_scan(), "workspace", |_a, _p| {
        scan_directory(dir.path(), false)
    })
    .unwrap();
    let declared = capture_coherent(CaptureConfig::generation_scan(), "workspace", |_a, _p| {
        scan_directory(dir.path(), true)
    })
    .unwrap();

    assert!(!hidden.members.contains_key(".git/HEAD"));
    assert!(declared.members.contains_key(".git/HEAD"));
    assert_ne!(
        hidden.manifest_sha256, declared.manifest_sha256,
        "git visibility is part of the bound identity"
    );
}
