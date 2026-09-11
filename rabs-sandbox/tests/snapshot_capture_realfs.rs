//! D018 acceptance against the REAL filesystem: coherent capture of an
//! actual tree via descriptor-verified reads, a deterministic
//! concurrent-mutation arm that forces retry and yields only the
//! post-mutation world, sustained mutation refusing with a typed
//! refusal, and `.git`/`target`/ephemeral-lock membership enforced on
//! disk. Runs on any host (no namespace primitives required).

use rabs_sandbox::snapshot_capture::{
    CaptureConfig, CaptureError, CaptureRejection, MemberKind, capture_coherent,
    capture_sealed_source, scan_directory,
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
    // to catch. Emits T053 structured logs (the standard's first
    // adopted suite).
    use rabs_protocol::test_log::{CausalAttribution, TestLogger, TestOutcome};
    let mut logger = TestLogger::start(
        std::io::stderr(),
        "unit/snapshot",
        "real_mid_scan_mutation_forces_retry",
        "unit-snapshot-mutation-0",
        None,
        CausalAttribution {
            region: Some("edge".into()),
            ..Default::default()
        },
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    fixture_tree(dir.path());

    let mut mutated = false;
    let mut scans = 0u32;
    let manifest = capture_coherent(CaptureConfig::generation_scan(), "workspace", |_a, pass| {
        scans += 1;
        let scan = scan_directory(dir.path(), false);
        if pass == 0 && !mutated {
            mutated = true;
            write(dir.path(), "src/lib.rs", "pub fn f() { /* edited */ }\n");
            write(dir.path(), "src/new_module.rs", "pub struct New;\n");
        }
        scan
    })
    .unwrap();
    logger
        .step("captured", &[("scan_passes", &scans.to_string())])
        .unwrap();
    assert!(scans > 2, "attempt 0 must have been discarded and retried");

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
    logger
        .finish(&TestOutcome::Pass {
            evidence: format!(
                "mid-scan mutation forced retry ({scans} scan passes); manifest \
                 carries only the post-mutation world (edited hash + added file)"
            ),
        })
        .unwrap();
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
        CaptureError::Rejected { .. } => panic!("unexpected policy refusal"),
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

#[test]
fn sealed_bytes_and_materialization_survive_live_checkout_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("live");
    write(&source, "src/main.rs", "fn main() { println!(\"old\"); }\n");
    write(&source, "run.sh", "#!/bin/sh\nprintf old\n");
    write(&source, "target/cache", "excluded");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            source.join("run.sh"),
            std::fs::Permissions::from_mode(0o751),
        )
        .unwrap();
        std::os::unix::fs::symlink("src/main.rs", source.join("link.rs")).unwrap();
    }
    let roots = vec![("workspace".to_string(), source.clone())];
    let old = capture_sealed_source(&roots, false, 3, 4096).unwrap();
    let old_bytes = old.file_bytes("workspace", "src/main.rs").unwrap().to_vec();
    let old_digest = old.closure_digest();
    assert!(old.file_bytes("workspace", "target/cache").is_none());

    // Replacing the checkout inode cannot change retained bytes. There is no
    // post-seal source reread when materializing the old image.
    std::fs::rename(source.join("src/main.rs"), dir.path().join("old-source.rs")).unwrap();
    write(&source, "src/main.rs", "fn main() { println!(\"new\"); }\n");
    let new = capture_sealed_source(&roots, false, 3, 4096).unwrap();
    assert_ne!(old_digest, new.closure_digest());
    assert_eq!(
        old.file_bytes("workspace", "src/main.rs").unwrap(),
        old_bytes
    );
    assert_ne!(
        old.file_bytes("workspace", "src/main.rs"),
        new.file_bytes("workspace", "src/main.rs")
    );

    let old_output = dir.path().join("old-image");
    let old_materialized = old.materialize_into(&old_output).unwrap();
    let new_materialized = new.materialize_into(&dir.path().join("new-image")).unwrap();
    let old_root = old_materialized.backing("workspace").unwrap();
    let new_root = new_materialized.backing("workspace").unwrap();
    assert_eq!(
        std::fs::read(old_root.join("src/main.rs")).unwrap(),
        old_bytes
    );
    assert_eq!(
        std::fs::read(new_root.join("src/main.rs")).unwrap(),
        new.file_bytes("workspace", "src/main.rs").unwrap()
    );
    assert_eq!(
        old_materialized.provenance("workspace"),
        old.provenance("workspace")
    );
    assert_ne!(old_root, source);
    assert!(!old_root.join("target").exists());
    // Existing destinations are never overwritten or accepted as a fresh
    // materialization, even when they contain an earlier valid image.
    assert!(old.materialize_into(&old_output).is_err());
    assert_eq!(
        std::fs::read(old_root.join("src/main.rs")).unwrap(),
        old_bytes
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        assert_ne!(
            std::fs::metadata(old_root.join("run.sh")).unwrap().ino(),
            std::fs::metadata(source.join("run.sh")).unwrap().ino()
        );
        assert_eq!(
            std::fs::metadata(old_root.join("run.sh"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o751
        );
        assert_eq!(
            std::fs::read_link(old_root.join("link.rs")).unwrap(),
            Path::new("src/main.rs")
        );
        assert_eq!(std::fs::read(old_root.join("link.rs")).unwrap(), old_bytes);
    }
}

#[test]
fn sealed_closure_byte_limit_is_cumulative_and_root_identity_is_validated() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    write(&a, "file", "aaaa");
    write(&b, "file", "bbbb");
    let roots = vec![("a".into(), a.clone()), ("b".into(), b.clone())];
    assert!(matches!(
        capture_sealed_source(&roots, false, 3, 7),
        Err(CaptureError::Rejected {
            reason: CaptureRejection::ByteLimitExceeded,
            ..
        })
    ));
    let image = capture_sealed_source(&roots, false, 3, 8).unwrap();
    assert_eq!(image.file_bytes("a", "file"), Some(b"aaaa".as_slice()));
    assert_eq!(image.file_bytes("b", "file"), Some(b"bbbb".as_slice()));
    let reverse = vec![("b".into(), b.clone()), ("a".into(), a.clone())];
    assert_eq!(
        image.closure_digest(),
        capture_sealed_source(&reverse, false, 3, 8)
            .unwrap()
            .closure_digest()
    );
    for invalid in [
        vec![],
        vec![("a".into(), a.clone()), ("a".into(), b)],
        vec![("../escape".into(), a)],
    ] {
        assert!(matches!(
            capture_sealed_source(&invalid, false, 1, 8),
            Err(CaptureError::Rejected {
                reason: CaptureRejection::InvalidRoot,
                ..
            })
        ));
    }
}

#[cfg(unix)]
#[test]
fn sealed_capture_refuses_special_nodes_lossy_paths_and_escaping_links() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::net::UnixListener;

    // Unix socket addresses have a small fixed path limit. RCH's isolated
    // TMPDIR can exceed it before the fixture name is even appended.
    let socket_dir = tempfile::tempdir_in("/tmp").unwrap();
    let socket_root = socket_dir.path().to_path_buf();
    let _socket = UnixListener::bind(socket_root.join("node")).unwrap();
    assert!(matches!(
        capture_sealed_source(&[("root".into(), socket_root)], false, 1, 100),
        Err(CaptureError::Rejected {
            reason: CaptureRejection::UnsupportedKind,
            ..
        })
    ));

    let dir = tempfile::tempdir().unwrap();
    let lossy_root = dir.path().join("lossy");
    std::fs::create_dir(&lossy_root).unwrap();
    std::fs::write(lossy_root.join(OsString::from_vec(vec![0xff])), "bytes").unwrap();
    assert!(matches!(
        capture_sealed_source(&[("root".into(), lossy_root)], false, 1, 100),
        Err(CaptureError::Rejected {
            reason: CaptureRejection::InvalidPath,
            ..
        })
    ));

    let escape_root = dir.path().join("escape");
    write(&escape_root, "sub/file", "bytes");
    std::os::unix::fs::symlink("..", escape_root.join("sub/back")).unwrap();
    // Lexically sub/back/../outside appears root-contained. Expanding back
    // first reveals that the second .. escapes the captured root.
    std::os::unix::fs::symlink("sub/back/../outside", escape_root.join("link")).unwrap();
    assert!(matches!(
        capture_sealed_source(&[("root".into(), escape_root)], false, 1, 100),
        Err(CaptureError::Rejected {
            reason: CaptureRejection::UnsafeSymlink,
            ..
        })
    ));
}

#[cfg(unix)]
#[test]
fn sealed_capture_special_node_fixture_handles_long_tmpdir() {
    let dir = tempfile::tempdir().unwrap();
    let long_tmpdir = dir.path().join("long-tmpdir-".repeat(12));
    std::fs::create_dir(&long_tmpdir).unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "sealed_capture_refuses_special_nodes_lossy_paths_and_escaping_links",
            "--nocapture",
        ])
        .env("TMPDIR", &long_tmpdir)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "long-TMPDIR fixture failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
}

#[cfg(unix)]
#[test]
fn executable_mode_changes_snapshot_identity_without_changing_bytes() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "script", "#!/bin/sh\ntrue\n");
    let path = dir.path().join("script");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let roots = vec![("workspace".to_string(), dir.path().to_path_buf())];
    let before = capture_sealed_source(&roots, false, 1, 100).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let after = capture_sealed_source(&roots, false, 1, 100).unwrap();
    assert_eq!(
        before.file_bytes("workspace", "script"),
        after.file_bytes("workspace", "script")
    );
    assert_ne!(before.closure_digest(), after.closure_digest());
    assert_ne!(
        before.provenance("workspace"),
        after.provenance("workspace")
    );
}
