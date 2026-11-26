//! Real private files and the production framing/ownership implementation.
use super::*;
use std::fs::OpenOptions;
use std::os::unix::fs::{PermissionsExt, symlink};

struct Fixture {
    root: tempfile::TempDir,
    directory: File,
    binding: String,
}

fn hash(bytes: &str) -> String {
    blake3::hash(bytes.as_bytes()).to_hex().to_string()
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let directory = File::open(root.path()).unwrap();
        Self {
            root,
            directory,
            binding: hash("wrapper/build/worker/phase/root/contract"),
        }
    }

    fn empty(&self) -> JournalRef {
        JournalRef::create(&self.directory, &self.binding, &BTreeMap::new(), None).unwrap()
    }

    fn path(&self, reference: &JournalRef) -> PathBuf {
        self.root.path().join(&reference.name)
    }

    fn reload(&self, reference: &JournalRef) -> (JournalRef, Replay) {
        let mut loaded: JournalRef =
            serde_json::from_value(serde_json::to_value(reference).unwrap()).unwrap();
        assert!(!loaded.has_cursor());
        let replay = loaded.replay(&self.directory, &self.binding).unwrap();
        (loaded, replay)
    }
}

#[test]
fn bootstrap_preserves_commits_and_exact_pending_predecessor() {
    let fixture = Fixture::new();
    let published = BTreeMap::from([(PathBuf::from("out/first"), hash("first"))]);
    let intent = Intent {
        relative: "out/second".into(),
        hash: hash("second"),
        prior: Some(hash("original")),
    };
    let reference = JournalRef::create(
        &fixture.directory,
        &fixture.binding,
        &published,
        Some(intent.clone()),
    )
    .unwrap();
    let (mut loaded, replay) = fixture.reload(&reference);
    assert_eq!(replay.published, published);
    assert_eq!(replay.pending, Some(intent.clone()));
    assert!(!replay.sealed && !replay.torn_tail);
    loaded
        .append_published(&fixture.directory, &intent.relative, &intent.hash)
        .unwrap();
    loaded.seal(&fixture.directory).unwrap();
    let (_, replay) = fixture.reload(&loaded);
    assert!(replay.sealed);
    assert!(replay.pending.is_none());
    assert_eq!(replay.published.len(), 2);
    assert_eq!(replay.published[&intent.relative], intent.hash);
    let mut lost_prefix = reference.clone();
    OpenOptions::new()
        .write(true)
        .open(fixture.path(&reference))
        .unwrap()
        .set_len(reference.initial.offset - 1)
        .unwrap();
    assert!(
        lost_prefix
            .replay(&fixture.directory, &fixture.binding)
            .is_err()
    );
}

#[test]
fn journal_bytes_scale_linearly_and_live_lease_reference_stays_fixed() {
    fn run(count: usize) -> (u64, usize) {
        let fixture = Fixture::new();
        let mut reference = fixture.empty();
        let original = serde_json::to_vec(&reference).unwrap();
        let mut last = fixture.path(&reference).metadata().unwrap().len();
        for index in 0..count {
            let relative = PathBuf::from(format!("out/file-{index:06}"));
            let digest = hash(&format!("payload-{index}"));
            reference
                .append_pending(&fixture.directory, &relative, &digest, None)
                .unwrap();
            let pending_end = fixture.path(&reference).metadata().unwrap().len();
            assert!(pending_end > last && pending_end - last < 1024);
            reference
                .append_published(&fixture.directory, &relative, &digest)
                .unwrap();
            let committed_end = fixture.path(&reference).metadata().unwrap().len();
            assert!(committed_end > pending_end && committed_end - pending_end < 1024);
            assert_eq!(serde_json::to_vec(&reference).unwrap(), original);
            last = committed_end;
        }
        reference.seal(&fixture.directory).unwrap();
        let (_, replay) = fixture.reload(&reference);
        assert_eq!(replay.published.len(), count);
        assert!(replay.sealed && !replay.torn_tail && replay.pending.is_none());
        (
            fixture.path(&reference).metadata().unwrap().len(),
            serde_json::to_vec(&reference).unwrap().len(),
        )
    }
    let (small, small_reference) = run(250);
    let (large, large_reference) = run(1000);
    eprintln!(
        "production publication journal: 250 files={small} bytes,1000 files={large} bytes; sealed refs={small_reference}/{large_reference} bytes"
    );
    assert!(
        large > small * 3 && large < small * 5,
        "actual journal bytes must scale with the fourfold file count"
    );
    assert!(small_reference.abs_diff(large_reference) < 32);
}

#[test]
fn crash_prefixes_recover_intent_commit_and_unpinned_seal() {
    let fixture = Fixture::new();
    let mut reference = fixture.empty();
    let relative = Path::new("out/result");
    let digest = hash("result");
    let (_, replay) = fixture.reload(&reference);
    assert!(replay.pending.is_none() && replay.published.is_empty());
    reference
        .append_pending(&fixture.directory, relative, &digest, Some(&hash("old")))
        .unwrap();
    let (_, replay) = fixture.reload(&reference);
    assert_eq!(replay.pending.unwrap().prior, Some(hash("old")));
    reference
        .append_published(&fixture.directory, relative, &digest)
        .unwrap();
    let (_, replay) = fixture.reload(&reference);
    assert_eq!(replay.published[relative], digest);
    let old_lease_ref = reference.clone();
    reference.seal(&fixture.directory).unwrap();
    let (adopted, replay) = fixture.reload(&old_lease_ref);
    assert!(replay.sealed && adopted.is_sealed());
    let mut pinned = reference.clone();
    let file = OpenOptions::new()
        .write(true)
        .open(fixture.path(&reference))
        .unwrap();
    file.set_len(file.metadata().unwrap().len() - 1).unwrap();
    assert!(pinned.replay(&fixture.directory, &fixture.binding).is_err());
}

#[test]
fn torn_intent_and_commit_fork_the_valid_prefix_without_changing_old_bytes() {
    for committed_intent in [false, true] {
        for cut in [2, 17, 50] {
            let fixture = Fixture::new();
            let mut reference = fixture.empty();
            let relative = Path::new("out/result");
            let digest = hash("result");
            if committed_intent {
                reference
                    .append_pending(&fixture.directory, relative, &digest, Some(&hash("old")))
                    .unwrap();
            }
            let before = reference.clone();
            let offset = before.cursor.as_ref().unwrap().checkpoint.offset;
            if committed_intent {
                reference
                    .append_published(&fixture.directory, relative, &digest)
                    .unwrap();
            } else {
                reference
                    .append_pending(&fixture.directory, relative, &digest, None)
                    .unwrap();
            }
            OpenOptions::new()
                .write(true)
                .open(fixture.path(&reference))
                .unwrap()
                .set_len(offset + cut)
                .unwrap();
            let retained = std::fs::read(fixture.path(&reference)).unwrap();
            let (mut interrupted, replay) = fixture.reload(&before);
            assert!(replay.torn_tail && !replay.sealed);
            assert_eq!(replay.pending.is_some(), committed_intent);
            assert!(
                interrupted
                    .append_pending(&fixture.directory, Path::new("other"), &hash("other"), None)
                    .is_err()
            );
            let mut repaired = interrupted
                .fork(&fixture.directory, &fixture.binding)
                .unwrap();
            assert_ne!(repaired.inode, interrupted.inode);
            if !committed_intent {
                repaired
                    .append_pending(&fixture.directory, relative, &digest, None)
                    .unwrap();
            }
            repaired
                .append_published(&fixture.directory, relative, &digest)
                .unwrap();
            repaired.seal(&fixture.directory).unwrap();
            assert_eq!(std::fs::read(fixture.path(&reference)).unwrap(), retained);
            let (_, replay) = fixture.reload(&repaired);
            assert_eq!(replay.published[relative], digest);
        }
    }
}

#[test]
fn stale_clones_and_deserialized_refs_cannot_append_until_replayed() {
    let fixture = Fixture::new();
    let mut live = fixture.empty();
    let mut stale = live.clone();
    let relative = Path::new("out/first");
    let digest = hash("first");
    live.append_pending(&fixture.directory, relative, &digest, None)
        .unwrap();
    let before = std::fs::read(fixture.path(&live)).unwrap();
    assert!(
        stale
            .append_pending(
                &fixture.directory,
                Path::new("out/other"),
                &hash("other"),
                None
            )
            .is_err()
    );
    assert!(!stale.has_cursor());
    assert_eq!(std::fs::read(fixture.path(&live)).unwrap(), before);
    stale.replay(&fixture.directory, &fixture.binding).unwrap();
    stale
        .append_published(&fixture.directory, relative, &digest)
        .unwrap();
    assert!(
        live.append_published(&fixture.directory, relative, &digest)
            .is_err()
    );
    let mut unhydrated: JournalRef =
        serde_json::from_value(serde_json::to_value(&stale).unwrap()).unwrap();
    assert!(unhydrated.seal(&fixture.directory).is_err());
    unhydrated
        .replay(&fixture.directory, &fixture.binding)
        .unwrap();
    unhydrated.seal(&fixture.directory).unwrap();
}

#[test]
fn released_payload_requires_exact_sealed_replay_and_unchanged_owned_log() {
    let fixture = Fixture::new();
    let mut reference = fixture.empty();
    let relative = Path::new("out/result");
    let digest = hash("result");
    assert!(reference.released_payload(&fixture.directory).is_err());
    reference
        .append_pending(&fixture.directory, relative, &digest, None)
        .unwrap();
    assert!(reference.released_payload(&fixture.directory).is_err());
    reference
        .append_published(&fixture.directory, relative, &digest)
        .unwrap();
    assert!(reference.released_payload(&fixture.directory).is_err());
    reference.seal(&fixture.directory).unwrap();

    let bytes = std::fs::read(fixture.path(&reference)).unwrap();
    let payload = reference.released_payload(&fixture.directory).unwrap();
    assert_eq!(payload.name, reference.name);
    assert_eq!(payload.bytes, bytes.len() as u64);
    assert_eq!(payload.blake3, blake3::hash(&bytes).to_hex().to_string());
    assert_eq!(std::fs::read(fixture.path(&reference)).unwrap(), bytes);

    let mut reloaded: JournalRef =
        serde_json::from_value(serde_json::to_value(&reference).unwrap()).unwrap();
    assert!(reloaded.released_payload(&fixture.directory).is_err());
    let replay = reloaded
        .replay(&fixture.directory, &fixture.binding)
        .unwrap();
    assert!(replay.sealed && !replay.torn_tail && replay.pending.is_none());
    assert_eq!(
        reloaded.released_payload(&fixture.directory).unwrap(),
        payload
    );

    for mutation in [
        "same-length-content",
        "trailing-bytes",
        "replace",
        "symlink",
        "hardlink",
        "permissions",
    ] {
        let fixture = Fixture::new();
        let mut reference = fixture.empty();
        reference.seal(&fixture.directory).unwrap();
        reference.released_payload(&fixture.directory).unwrap();
        let path = fixture.path(&reference);
        let kept = fixture.root.path().join("kept-original");
        match mutation {
            "same-length-content" => {
                let mut bytes = std::fs::read(&path).unwrap();
                bytes[0] ^= 1;
                OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .write_all_at(&bytes, 0)
                    .unwrap();
            }
            "trailing-bytes" => OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap()
                .write_all(&[0])
                .unwrap(),
            "replace" => {
                let bytes = std::fs::read(&path).unwrap();
                std::fs::rename(&path, &kept).unwrap();
                std::fs::write(&path, bytes).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            "symlink" => {
                std::fs::rename(&path, &kept).unwrap();
                symlink(&kept, &path).unwrap();
            }
            "hardlink" => std::fs::hard_link(&path, &kept).unwrap(),
            "permissions" => {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
            }
            _ => unreachable!(),
        }
        let preserved = std::fs::read(&path).unwrap();
        assert!(
            reference.released_payload(&fixture.directory).is_err(),
            "{mutation}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), preserved, "{mutation}");
        if matches!(mutation, "replace" | "symlink" | "hardlink") {
            assert!(kept.is_file(), "{mutation}");
        }
    }
}

#[test]
fn complete_corruption_and_out_of_order_frames_are_not_torn_tail() {
    let fixture = Fixture::new();
    let mut reference = fixture.empty();
    reference
        .append_pending(
            &fixture.directory,
            Path::new("out/file"),
            &hash("file"),
            None,
        )
        .unwrap();
    let mut bytes = std::fs::read(fixture.path(&reference)).unwrap();
    let changed = reference.initial.offset as usize + 10;
    bytes[changed] ^= 1;
    OpenOptions::new()
        .write(true)
        .open(fixture.path(&reference))
        .unwrap()
        .write_all_at(&bytes, 0)
        .unwrap();
    assert!(
        reference
            .replay(&fixture.directory, &fixture.binding)
            .is_err()
    );

    for event in [
        Event::Published {
            relative: "out/file".into(),
            hash: hash("file"),
        },
        Event::Start,
        Event::Header {
            version: 1,
            binding: fixture.binding.clone(),
        },
    ] {
        let mut reference = fixture.empty();
        let (bytes, _) = encode(&reference.cursor.as_ref().unwrap().checkpoint, event).unwrap();
        OpenOptions::new()
            .append(true)
            .open(fixture.path(&reference))
            .unwrap()
            .write_all(&bytes)
            .unwrap();
        assert!(
            reference
                .replay(&fixture.directory, &fixture.binding)
                .is_err()
        );
    }
}

#[test]
fn identity_guards_refuse_symlinks_hardlinks_replacements_and_unsafe_permissions() {
    for mutation in ["symlink", "hardlink", "replace", "permissions"] {
        let fixture = Fixture::new();
        let mut reference = fixture.empty();
        let path = fixture.path(&reference);
        let kept = fixture.root.path().join("kept-original");
        match mutation {
            "symlink" => {
                std::fs::rename(&path, &kept).unwrap();
                symlink(&kept, &path).unwrap();
            }
            "hardlink" => std::fs::hard_link(&path, &kept).unwrap(),
            "replace" => {
                let bytes = std::fs::read(&path).unwrap();
                std::fs::rename(&path, &kept).unwrap();
                std::fs::write(&path, bytes).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            "permissions" => {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap()
            }
            _ => unreachable!(),
        }
        assert!(
            reference
                .replay(&fixture.directory, &fixture.binding)
                .is_err(),
            "{mutation}"
        );
    }
    let fixture = Fixture::new();
    let other = Fixture::new();
    let mut reference = fixture.empty();
    assert!(
        reference
            .replay(&other.directory, &fixture.binding)
            .is_err()
    );
    std::fs::set_permissions(fixture.root.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(
        reference
            .replay(&fixture.directory, &fixture.binding)
            .is_err()
    );
}

#[test]
fn binding_paths_bounds_and_transition_guards_fail_without_appending() {
    let fixture = Fixture::new();
    let mut reference = fixture.empty();
    assert_eq!(reference.binding(), fixture.binding);
    assert!(
        reference
            .replay(&fixture.directory, &hash("different contract"))
            .is_err()
    );
    reference
        .replay(&fixture.directory, &fixture.binding)
        .unwrap();
    for path in [
        "../escape",
        "/absolute",
        "",
        "out/../escape",
        "out/./alias",
        "out//alias",
        "out/trailing/",
        "out/control\n",
    ] {
        assert!(
            reference
                .append_pending(&fixture.directory, Path::new(path), &hash("file"), None)
                .is_err()
        );
    }
    assert!(
        reference
            .append_pending(&fixture.directory, Path::new("safe"), "not-a-hash", None)
            .is_err()
    );
    let initial = std::fs::read(fixture.path(&reference)).unwrap();
    assert!(
        reference
            .append_pending(
                &fixture.directory,
                Path::new(&"x".repeat(MAX_RECORD_BYTES)),
                &hash("file"),
                None
            )
            .is_err()
    );
    assert!(!reference.has_cursor());
    assert_eq!(std::fs::read(fixture.path(&reference)).unwrap(), initial);
    reference
        .replay(&fixture.directory, &fixture.binding)
        .unwrap();
    reference
        .append_pending(&fixture.directory, Path::new("safe"), &hash("file"), None)
        .unwrap();
    assert!(reference.seal(&fixture.directory).is_err());
    reference
        .replay(&fixture.directory, &fixture.binding)
        .unwrap();
    assert!(
        reference
            .append_published(&fixture.directory, Path::new("wrong"), &hash("file"))
            .is_err()
    );
    reference
        .replay(&fixture.directory, &fixture.binding)
        .unwrap();
    reference
        .append_published(&fixture.directory, Path::new("safe"), &hash("file"))
        .unwrap();
    reference.seal(&fixture.directory).unwrap();
    let sealed_bytes = std::fs::read(fixture.path(&reference)).unwrap();
    assert!(
        reference
            .append_pending(&fixture.directory, Path::new("later"), &hash("later"), None)
            .is_err()
    );
    assert_eq!(
        std::fs::read(fixture.path(&reference)).unwrap(),
        sealed_bytes
    );
}

#[test]
fn fork_keeps_sealed_snapshot_independent_and_rejects_extra_bytes() {
    let fixture = Fixture::new();
    let mut original = fixture.empty();
    original
        .append_pending(
            &fixture.directory,
            Path::new("out/file"),
            &hash("file"),
            None,
        )
        .unwrap();
    original
        .append_published(&fixture.directory, Path::new("out/file"), &hash("file"))
        .unwrap();
    original.seal(&fixture.directory).unwrap();
    let forked = original.fork(&fixture.directory, &fixture.binding).unwrap();
    assert!(forked.is_sealed());
    assert_ne!(forked.inode, original.inode);
    assert_eq!(
        std::fs::read(fixture.path(&original)).unwrap(),
        std::fs::read(fixture.path(&forked)).unwrap()
    );
    OpenOptions::new()
        .append(true)
        .open(fixture.path(&original))
        .unwrap()
        .write_all(&[0])
        .unwrap();
    assert!(
        original
            .replay(&fixture.directory, &fixture.binding)
            .is_err()
    );
    assert!(fixture.reload(&forked).1.sealed);
}
