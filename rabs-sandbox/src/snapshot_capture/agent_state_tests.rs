//! Session directories must be pruned, not captured as empty mutable inputs.

use super::*;
use std::fs;

const STATE_DIRS: &[&str] = &[
    ".ntm",
    ".beads-recovery",
    ".beads",
    "nested/.ntm",
    "nested/.beads-recovery",
    "nested/deep/.beads",
];
const INPUTS: &[&str] = &[
    "src/lib.rs",
    "scratch/input.rs",
    "data/input.bin",
    "artifacts/input.bin",
    ".cargo/config.toml",
    ".claude/settings.json",
    "fixtures/.ntm",
    "fixtures/.beads-recovery",
    "fixtures/.beads",
    ".ntm-fixtures/input.rs",
    ".beads-recovery-tools/input.rs",
];

fn fixture() -> (PathBuf, Vec<(String, PathBuf)>) {
    let retained = tempfile::tempdir().unwrap().keep();
    let roots: Vec<_> = ["workspace", "dependency"]
        .into_iter()
        .map(|id| (id.to_owned(), retained.join(id)))
        .collect();
    for (_, root) in &roots {
        for input in INPUTS {
            let path = root.join(input);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"build-input").unwrap();
        }
        for directory in STATE_DIRS {
            let path = root.join(directory);
            fs::create_dir_all(&path).unwrap();
            fs::write(path.join("session.json"), b"private state").unwrap();
        }
    }
    (retained, roots)
}

fn assert_inputs(image: &SealedSourceSnapshot, roots: &[(String, PathBuf)]) {
    for (id, root) in roots {
        let manifest = image.manifest(id).unwrap();
        for input in INPUTS {
            assert_eq!(image.file_bytes(id, input), Some(b"build-input".as_slice()));
        }
        for directory in STATE_DIRS {
            assert!(
                !manifest.members.contains_key(*directory),
                "{id}/{directory}"
            );
            assert!(
                image
                    .file_bytes(id, &format!("{directory}/session.json"))
                    .is_none()
            );
            assert_eq!(
                fs::read(root.join(directory).join("session.json")).unwrap(),
                b"private state"
            );
        }
    }
}

#[test]
fn agent_directories_are_absent_from_all_snapshot_surfaces_but_files_remain() {
    let (retained, roots) = fixture();
    for (_, root) in &roots {
        let scan = scan_directory(root, false).unwrap();
        for directory in STATE_DIRS {
            assert!(!scan.members.contains_key(*directory));
            assert!(!scan.identities.contains_key(*directory));
        }
        for input in INPUTS {
            assert!(matches!(
                scan.members.get(*input),
                Some(MemberKind::Regular { .. })
            ));
        }
    }
    let image = capture_sealed_source(&roots, false, 1, 4096).unwrap();
    assert_inputs(&image, &roots);
    let output = image
        .materialize_into(&retained.join("materialized"))
        .unwrap();
    for (id, _) in &roots {
        let backing = output.backing(id).unwrap();
        for directory in STATE_DIRS {
            assert!(!backing.join(directory).exists());
        }
        for input in INPUTS {
            assert_eq!(fs::read(backing.join(input)).unwrap(), b"build-input");
        }
    }
}

#[test]
fn agent_directory_churn_between_capture_passes_does_not_consume_retries() {
    let (_, roots) = fixture();
    let before: Vec<_> = roots
        .iter()
        .map(|(_, root)| scan_directory(root, false).unwrap())
        .collect();
    let mut passes = Vec::new();
    let image = capture_sealed_source_with(&roots, false, 1, 4096, |attempt, pass| {
        passes.push((attempt, pass));
        if pass == 0 {
            // Real directory-entry creation changes the session directory's
            // metadata. No selected file or parent directory is touched.
            std::thread::sleep(std::time::Duration::from_millis(10));
            for (_, root) in &roots {
                for directory in STATE_DIRS {
                    fs::write(root.join(directory).join("new-session.json"), b"new state").unwrap();
                }
            }
        }
    })
    .unwrap();
    assert_eq!(passes, [(0, 0), (0, 1)]);
    assert_inputs(&image, &roots);
    for (index, (_, root)) in roots.iter().enumerate() {
        let after = scan_directory(root, false).unwrap();
        assert_eq!(first_divergence(&before[index], &after), None);
        for directory in STATE_DIRS {
            assert_eq!(
                fs::read(root.join(directory).join("new-session.json")).unwrap(),
                b"new state"
            );
        }
    }
}

#[test]
fn source_changes_with_agent_names_still_exhaust_the_capture_budget() {
    let (_, roots) = fixture();
    let mut mutations = 0;
    let error = capture_sealed_source_with(&roots, false, 2, 4096, |attempt, pass| {
        if pass == 0 {
            mutations += 1;
            // The leaf is a FILE. Directory hygiene must never swallow it.
            fs::write(
                roots[1].1.join("fixtures/.ntm"),
                format!("source-{attempt}"),
            )
            .unwrap();
        }
    })
    .unwrap_err();
    assert_eq!(mutations, 2);
    assert!(matches!(
        error,
        CaptureError::Incoherent(CaptureRefusal { attempts: 2, .. })
    ));
}

#[cfg(unix)]
#[test]
fn excluded_directories_are_not_enumerated_even_with_opaque_or_unreadable_children() {
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::PermissionsExt;

    let (_, roots) = fixture();
    for (_, root) in &roots {
        for directory in STATE_DIRS {
            let path = root.join(directory);
            let opaque = std::ffi::OsString::from_vec(b"invalid-\xff-name".to_vec());
            fs::write(path.join(opaque), b"private opaque filename").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        }
    }
    // Root can read mode-000 directories; the invalid filename separately
    // proves that sealed capture did not enumerate the excluded directory.
    let image = capture_sealed_source(&roots, false, 1, 4096).unwrap();
    for (id, root) in &roots {
        let scan = scan_directory(root, false).unwrap();
        for directory in STATE_DIRS {
            assert!(!scan.members.contains_key(*directory));
            assert!(!image.manifest(id).unwrap().members.contains_key(*directory));
            fs::set_permissions(root.join(directory), fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    assert_inputs(&image, &roots);
}

#[cfg(unix)]
#[test]
fn same_named_symlink_to_selected_directory_is_not_pruned_or_followed_during_scan() {
    let (retained, roots) = fixture();
    for (_, root) in &roots {
        fs::create_dir(root.join("links")).unwrap();
        std::os::unix::fs::symlink("../src", root.join("links/.ntm")).unwrap();
    }
    let image = capture_sealed_source(&roots, false, 1, 4096).unwrap();
    let output = image
        .materialize_into(&retained.join("with-links"))
        .unwrap();
    for (id, root) in &roots {
        assert!(matches!(
            image.manifest(id).unwrap().members.get("links/.ntm"),
            Some(MemberKind::Symlink { target }) if target == "../src"
        ));
        assert!(image.file_bytes(id, "links/.ntm/lib.rs").is_none());
        assert_eq!(
            fs::read(output.backing(id).unwrap().join("links/.ntm/lib.rs")).unwrap(),
            b"build-input"
        );
        assert_eq!(
            fs::read_link(root.join("links/.ntm")).unwrap(),
            PathBuf::from("../src")
        );
    }
}
