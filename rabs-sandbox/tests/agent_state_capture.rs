//! Exercise the production snapshot/retention/materialization path for #109.
//! These are local filesystem tests, not remote-worker or Cargo-build proofs.

use rabs_sandbox::snapshot_capture::{
    MemberDisposition, MemberKind, capture_sealed_source, member_disposition, scan_directory,
};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const INPUTS: &[&str] = &[
    "src/lib.rs",
    "Cargo.lock",
    "scratch/generated.rs",
    "data/input.bin",
    "artifacts/fixture.txt",
    ".cargo/config.toml",
    ".claude/settings.json",
    ".rch/config.toml",
    ".ntm-fixtures/input.txt",
    ".beads-recovery-tools/input.txt",
    "fixtures/files/.ntm",
    "fixtures/files/.beads-recovery",
    "fixtures/files/.beads",
];
const STATE: &[&str] = &[
    ".ntm/log.txt",
    ".ntm/sessions/log.txt",
    ".beads-recovery/checkpoint.json",
    ".beads/.br_recovery/state.json",
    "nested/.ntm/log.txt",
    "nested/.beads-recovery/checkpoint.json",
    "nested/deep/.beads/.br_recovery/state.json",
    ".ntm/Cargo.lock",
    ".beads-recovery/.cargo/config.toml",
];
const INPUT: &[u8] = b"build-input";
const STATE_BYTES: u64 = 8 * 1024 * 1024;

fn write(root: &Path, relative: &str, bytes: &[u8]) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn fixture() -> (PathBuf, Vec<(String, PathBuf)>, u64) {
    // Keep the owned fixtures for inspection; never contact or clean a worker.
    let temporary = tempfile::tempdir().unwrap().keep();
    let roots: Vec<_> = ["workspace", "dependency"]
        .into_iter()
        .map(|name| (name.to_string(), temporary.join(name)))
        .collect();
    for (_, root) in &roots {
        for path in INPUTS {
            write(root, path, INPUT);
        }
        for path in STATE {
            let path = root.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            // A sparse file bigger than the WHOLE capture budget proves the
            // exclusion happens before retaining bytes, not after filtering
            // the manifest. The old classifier fails with ByteLimitExceeded.
            fs::File::create(path)
                .unwrap()
                .set_len(STATE_BYTES)
                .unwrap();
        }
    }
    let budget = (INPUTS.len() * INPUT.len() * roots.len()) as u64;
    (temporary, roots, budget)
}

fn expected_inputs() -> BTreeSet<String> {
    INPUTS.iter().map(|path| (*path).to_string()).collect()
}

#[test]
fn agent_state_stays_out_of_legacy_scans_and_membership_checks() {
    let (_, roots, _) = fixture();
    for (_, root) in &roots {
        let scanned = scan_directory(root, false).unwrap();
        let files: BTreeSet<_> = scanned
            .members
            .iter()
            .filter(|(_, member)| matches!(member, MemberKind::Regular { .. }))
            .map(|(path, _)| path.clone())
            .collect();
        assert_eq!(files, expected_inputs());
        for path in STATE {
            assert!(!scanned.members.contains_key(*path));
            // The coordinator validates caller-selected source paths through
            // this same membership gate; a named Cargo.lock cannot bypass it.
            assert_ne!(member_disposition(path, false), MemberDisposition::Include);
        }
        for path in INPUTS {
            assert_eq!(member_disposition(path, false), MemberDisposition::Include);
        }
    }
}

#[test]
fn agent_state_is_not_retained_or_materialized_across_dependency_roots() {
    let (temporary, roots, budget) = fixture();
    let sealed = capture_sealed_source(&roots, false, 1, budget).unwrap();
    for (id, root) in &roots {
        let files: BTreeSet<_> = sealed
            .manifest(id)
            .unwrap()
            .members
            .iter()
            .filter(|(_, member)| matches!(member, MemberKind::Regular { .. }))
            .map(|(path, _)| path.clone())
            .collect();
        assert_eq!(files, expected_inputs());
        for path in STATE {
            assert!(sealed.file_bytes(id, path).is_none());
            assert_eq!(fs::metadata(root.join(path)).unwrap().len(), STATE_BYTES);
        }
        // Materialization must use the retained source bytes, not re-read the
        // now-changed checkout or expand an excluded session tree recursively.
        write(root, "src/lib.rs", b"later-input");
        write(root, ".ntm/new-session.json", b"private-session-state");
    }
    let destination = temporary.join("materialized");
    let materialized = sealed.materialize_into(&destination).unwrap();
    for (id, root) in &roots {
        let backing = materialized.backing(id).unwrap();
        for path in INPUTS {
            assert_eq!(sealed.file_bytes(id, path), Some(INPUT));
            assert_eq!(fs::read(backing.join(path)).unwrap(), INPUT);
        }
        for path in STATE {
            assert!(!backing.join(path).exists());
            assert_eq!(fs::metadata(root.join(path)).unwrap().len(), STATE_BYTES);
        }
        assert!(!backing.join(".ntm/new-session.json").exists());
        assert_eq!(fs::read(root.join("src/lib.rs")).unwrap(), b"later-input");
        assert_eq!(
            materialized.provenance(id).unwrap().manifest_sha256,
            sealed.manifest(id).unwrap().manifest_sha256
        );
    }
}

#[test]
fn agent_state_churn_does_not_change_content_identity_but_source_edits_do() {
    let (_, roots, budget) = fixture();
    let before = capture_sealed_source(&roots, false, 1, budget).unwrap();
    for (_, root) in &roots {
        write(root, ".ntm/new-session.json", b"session-state");
        write(root, "nested/.beads-recovery/next.json", b"recovery-state");
    }
    let after_state = capture_sealed_source(&roots, false, 1, budget).unwrap();
    assert_eq!(before.closure_digest(), after_state.closure_digest());

    let source = roots[1].1.join("src/lib.rs");
    let modified = fs::metadata(&source).unwrap().modified().unwrap();
    fs::write(&source, b"stale-input").unwrap();
    fs::File::options()
        .write(true)
        .open(&source)
        .unwrap()
        .set_modified(modified)
        .unwrap();
    let after_source = capture_sealed_source(&roots, false, 1, budget).unwrap();
    assert_ne!(after_state.closure_digest(), after_source.closure_digest());
    assert_eq!(before.file_bytes("dependency", "src/lib.rs"), Some(INPUT));
    assert_eq!(
        after_source.file_bytes("dependency", "src/lib.rs"),
        Some(&b"stale-input"[..])
    );
}
