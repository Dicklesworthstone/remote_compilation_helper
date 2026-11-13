//! Exercise native Git archive reuse through the actual worker executable.
//! The cache has no authority over source contents: every selected archive is
//! bound to an independent digest and copied into an unlinked private inode.

#![cfg(unix)]
#![forbid(unsafe_code)]

use sha2::{Digest as _, Sha256};
use std::fs::{self, File};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const WORKER: &str = env!("CARGO_BIN_EXE_rch-wkr");
const CACHE: &str = ".rch-git-archive-cache-v1";
const ARCHIVE: &str = ".rch-clean-overlay-base.tar";
const SLOT: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const OTHER: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

struct Fixture {
    root: PathBuf,
    source: PathBuf,
    target: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let base = if cfg!(target_os = "macos") {
            "/private/tmp"
        } else {
            "/tmp"
        };
        let root = tempfile::Builder::new()
            .prefix("rch-native-archive-")
            .tempdir_in(base)
            .unwrap()
            .keep();
        Self {
            source: root.join("selected source α ' quoted"),
            target: root.join("paired target β"),
            root,
        }
    }

    fn arguments(&self, operation: &str, payload: &[u8]) -> Vec<String> {
        vec![
            operation.into(),
            self.source.to_str().unwrap().into(),
            self.target.to_str().unwrap().into(),
            SLOT.into(),
            digest(payload),
            payload.len().to_string(),
            "0".into(),
        ]
    }

    fn command(&self, arguments: &[String]) -> Command {
        let mut command = Command::new(WORKER);
        command
            .arg("git-archive-cache")
            .args(arguments)
            // No shell, interpreter, executable lookup, temporary logging or
            // async runtime may be required by this worker-side operation.
            .env_clear()
            .env("PATH", "")
            .env("TMPDIR", self.root.join("absent-parent/tmp"))
            .env("RCH_LOG_FILE", self.root.join("absent-parent/worker.log"))
            .env("TOKIO_WORKER_THREADS", "0");
        command
    }

    fn invoke(&self, arguments: &[String]) -> Output {
        self.command(arguments).output().unwrap()
    }

    fn status(&self, expected: &str, operation: &str, payload: &[u8]) {
        assert_status(&self.invoke(&self.arguments(operation, payload)), expected);
    }

    fn stage(&self, payload: &[u8]) -> PathBuf {
        fs::create_dir_all(&self.source).unwrap();
        fs::set_permissions(&self.source, fs::Permissions::from_mode(0o755)).unwrap();
        let archive = self.source.join(ARCHIVE);
        fs::write(&archive, payload).unwrap();
        fs::set_permissions(&archive, fs::Permissions::from_mode(0o600)).unwrap();
        archive
    }

    fn sealed(&self) -> PathBuf {
        self.target.join(CACHE).join(format!("{SLOT}.sealed"))
    }

    fn prepare_cache(&self) -> PathBuf {
        let cache = self.target.join(CACHE);
        fs::create_dir_all(&cache).unwrap();
        fs::set_permissions(&self.target, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&cache, fs::Permissions::from_mode(0o700)).unwrap();
        cache
    }
}

fn assert_status(output: &Output, status: &str) {
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(
        output.stdout,
        format!("RCH_GIT_ARCHIVE_CACHE_V1 {status}\n").as_bytes(),
        "{output:?}"
    );
    assert!(output.stderr.is_empty(), "{output:?}");
}

fn assert_refused(output: &Output) {
    assert_eq!(output.status.code(), Some(74), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(
        output.stderr.starts_with(b"RCH_GIT_ARCHIVE_CACHE_ERROR:"),
        "{output:?}"
    );
}

fn mode(path: &Path, value: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(value)).unwrap();
}

fn git(repository: &Path, arguments: &[&str]) -> Vec<u8> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(output.status.success(), "{arguments:?}: {output:?}");
    output.stdout
}

#[test]
fn native_capability_and_invalid_argv_need_no_interpreter_or_runtime() {
    let fixture = Fixture::new();
    let output = fixture.invoke(&["probe".into()]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"rch-wkr git-archive-cache v1\n");
    assert!(output.stderr.is_empty());
    for arguments in [vec![], vec!["probe".into(), "extra".into()]] {
        assert_refused(&fixture.invoke(&arguments));
    }
    for (index, value) in [
        (0, "other"),
        (1, "relative"),
        (1, "/unselected/../source"),
        (1, "/source/"),
        (1, "/source//extra"),
        (3, "../escape"),
        (4, "not-a-digest"),
        (5, "0"),
        (5, "+1"),
        (5, "-1"),
        (5, "9223372036854775808"),
        (6, "-1"),
        (6, "18446744073709551616"),
    ] {
        let mut arguments = fixture.arguments("restore", b"pin");
        arguments[index] = value.into();
        assert_refused(&fixture.invoke(&arguments));
    }
    for target in [&fixture.source, &fixture.source.join("nested")] {
        let mut arguments = fixture.arguments("restore", b"pin");
        arguments[2] = target.to_str().unwrap().into();
        assert_refused(&fixture.invoke(&arguments));
    }
    assert!(!fixture.source.exists());
    assert!(!fixture.target.exists());
}

#[test]
fn real_git_archive_warm_restore_is_private_exact_and_does_not_reuse_overlay_state() {
    let fixture = Fixture::new();
    let repository = fixture.root.join("git input");
    fs::create_dir(&repository).unwrap();
    git(&repository, &["init", "-q"]);
    fs::create_dir(repository.join("src")).unwrap();
    fs::write(
        repository.join("src/lib.rs"),
        b"pub fn pinned() -> u32 { 41 }\n",
    )
    .unwrap();
    fs::write(repository.join("run.sh"), b"#!/bin/sh\nexit 0\n").unwrap();
    mode(&repository.join("run.sh"), 0o755);
    symlink("src/lib.rs", repository.join("source-link")).unwrap();
    git(&repository, &["add", "."]);
    git(
        &repository,
        &[
            "-c",
            "user.name=RCH native cache test",
            "-c",
            "user.email=rch-cache@example.invalid",
            "commit",
            "-qm",
            "pinned input",
        ],
    );
    let archive = git(
        &repository,
        &["-c", "tar.umask=0022", "archive", "--format=tar", "HEAD"],
    );
    fixture.status("MISS", "restore", &archive);
    assert!(!fixture.source.exists());
    assert!(!fixture.target.exists());
    fixture.stage(&archive);
    fixture.status("PUBLISHED", "publish", &archive);
    let cache_before = fs::metadata(fixture.sealed()).unwrap();
    let retained = fixture.root.join("retained old source");
    fs::rename(&fixture.source, &retained).unwrap();
    fs::write(retained.join("generated-previous-build"), b"do not restore").unwrap();
    for _ in 0..2 {
        fixture.status("HIT", "restore", &archive);
    }
    let received = fixture.source.join(ARCHIVE);
    let received_info = fs::metadata(&received).unwrap();
    assert_eq!(fs::read(&received).unwrap(), archive);
    assert_eq!(received_info.nlink(), 1);
    assert_ne!(received_info.ino(), cache_before.ino());
    assert_eq!(fs::read_dir(&fixture.source).unwrap().count(), 1);
    let cache_after = fs::metadata(fixture.sealed()).unwrap();
    assert_eq!(cache_after.mtime_nsec(), cache_before.mtime_nsec());
    assert_eq!(cache_after.mtime(), cache_before.mtime());
    assert_eq!(cache_after.mode() & 0o777, 0o400);
    let extracted = Command::new("tar")
        .arg("-xOf")
        .arg(&received)
        .arg("src/lib.rs")
        .output()
        .unwrap();
    assert!(extracted.status.success(), "{extracted:?}");
    assert_eq!(extracted.stdout, b"pub fn pinned() -> u32 { 41 }\n");
    let overlay = fixture.source.join("selected-overlay");
    fs::write(&overlay, b"new live input").unwrap();
    fixture.status("HIT", "restore", &archive);
    assert_eq!(fs::read(overlay).unwrap(), b"new live input");
}

#[test]
fn changed_pin_misses_without_source_writes_then_replaces_only_its_slot() {
    let fixture = Fixture::new();
    fixture.stage(b"original pin");
    fixture.status("PUBLISHED", "publish", b"original pin");
    let previous = fs::read(fixture.sealed()).unwrap();
    fs::rename(&fixture.source, fixture.root.join("retained-source")).unwrap();
    fixture.status("MISS", "restore", b"differentpin");
    assert!(!fixture.source.exists());
    assert_eq!(fs::read(fixture.sealed()).unwrap(), previous);
    fixture.stage(b"differentpin");
    fixture.status("PUBLISHED", "publish", b"differentpin");
    fixture.status("HIT", "restore", b"differentpin");
    fixture.status("MISS", "restore", b"original pin");
    assert_eq!(fs::read_dir(fixture.target.join(CACHE)).unwrap().count(), 1);
}

#[test]
fn sibling_repositories_keep_independent_cache_slots() {
    let fixture = Fixture::new();
    fixture.stage(b"first repository");
    fixture.status("PUBLISHED", "publish", b"first repository");
    fixture.stage(b"second repository");
    let mut arguments = fixture.arguments("publish", b"second repository");
    arguments[3] = OTHER.into();
    assert_status(&fixture.invoke(&arguments), "PUBLISHED");
    for (payload, slot) in [
        (b"first repository".as_slice(), SLOT),
        (b"second repository".as_slice(), OTHER),
        (b"first repository".as_slice(), SLOT),
    ] {
        let mut arguments = fixture.arguments("restore", payload);
        arguments[3] = slot.into();
        assert_status(&fixture.invoke(&arguments), "HIT");
        assert_eq!(fs::read(fixture.source.join(ARCHIVE)).unwrap(), payload);
    }
    assert_eq!(fs::read_dir(fixture.target.join(CACHE)).unwrap().count(), 2);
}

#[test]
fn corrupt_sealed_bytes_are_retained_and_failed_private_copies_are_invalidated() {
    let fixture = Fixture::new();
    fixture.stage(b"original bytes");
    fixture.status("PUBLISHED", "publish", b"original bytes");
    let cache = fixture.sealed();
    let mut damaged = fs::read(&cache).unwrap();
    *damaged.last_mut().unwrap() ^= 1;
    mode(&cache, 0o600);
    fs::write(&cache, &damaged).unwrap();
    fixture.status("MISS", "restore", b"unrelated data");
    assert_eq!(
        fs::read(fixture.source.join(ARCHIVE)).unwrap(),
        b"original bytes"
    );
    fixture.status("BYPASS_CORRUPT", "restore", b"original bytes");
    assert_eq!(fs::metadata(fixture.source.join(ARCHIVE)).unwrap().len(), 0);
    assert_eq!(fs::read(&cache).unwrap(), damaged);
    fixture.stage(b"unrelated data");
    fixture.status("BYPASS_CORRUPT", "publish", b"unrelated data");
    assert_eq!(fs::read(cache).unwrap(), damaged);
}

#[test]
fn wrong_slot_noncanonical_duplicate_oversized_and_truncated_headers_never_touch_source() {
    let fixture = Fixture::new();
    fixture.stage(b"selected");
    fixture.status("PUBLISHED", "publish", b"selected");
    let sealed = fs::read(fixture.sealed()).unwrap();
    let mut lines = sealed.splitn(3, |byte| *byte == b'\n');
    let magic = lines.next().unwrap();
    let header = lines.next().unwrap();
    let payload = lines.next().unwrap();
    let mut wrong_slot: serde_json::Value = serde_json::from_slice(header).unwrap();
    wrong_slot["slot"] = OTHER.into();
    let variants = [
        serde_json::to_vec(&wrong_slot).unwrap(),
        [b" ".as_slice(), header].concat(),
        [b"{\"size\":1,".as_slice(), &header[1..]].concat(),
        [vec![b' '; 1025].as_slice(), header].concat(),
        b"{\"unknown\":true}".to_vec(),
    ];
    for (index, header) in variants.iter().enumerate() {
        let target = fixture.root.join(format!("invalid-header-{index}"));
        let directory = target.join(CACHE);
        fs::create_dir_all(&directory).unwrap();
        mode(&target, 0o755);
        mode(&directory, 0o700);
        let stored = [magic, b"\n", header, b"\n", payload].concat();
        let entry = directory.join(format!("{SLOT}.sealed"));
        fs::write(&entry, &stored).unwrap();
        mode(&entry, 0o400);
        let mut arguments = fixture.arguments("restore", b"selected");
        arguments[2] = target.to_str().unwrap().into();
        assert_status(&fixture.invoke(&arguments), "BYPASS_CORRUPT");
        assert_eq!(fs::read(fixture.source.join(ARCHIVE)).unwrap(), b"selected");
        assert_eq!(fs::read(&entry).unwrap(), stored);
    }
    mode(&fixture.sealed(), 0o600);
    fs::write(fixture.sealed(), b"incomplete header").unwrap();
    fixture.status("BYPASS_CORRUPT", "restore", b"selected");
    assert_eq!(fs::read(fixture.source.join(ARCHIVE)).unwrap(), b"selected");
}

#[test]
fn interrupted_pending_is_never_a_hit_and_readonly_pending_can_be_replaced() {
    for permissions in [0o600, 0o400] {
        let fixture = Fixture::new();
        fixture.stage(b"selected archive");
        let pending = fixture.prepare_cache().join(format!("{SLOT}.pending"));
        fs::write(&pending, b"previous incomplete publication").unwrap();
        mode(&pending, permissions);
        fixture.status("MISS", "restore", b"selected archive");
        assert_eq!(
            fs::read(&pending).unwrap(),
            b"previous incomplete publication"
        );
        fixture.status("PUBLISHED", "publish", b"selected archive");
        assert!(!pending.exists());
        fixture.status("HIT", "restore", b"selected archive");
    }
}

#[test]
fn quotas_count_partial_slots_and_sparse_bytes_without_evicting_evidence() {
    let fixture = Fixture::new();
    fixture.stage(b"selected");
    let cache = fixture.prepare_cache();
    for number in 0..64 {
        let path = cache.join(format!("{:064x}.pending", number));
        fs::write(&path, b"partial").unwrap();
        mode(&path, 0o600);
    }
    fixture.status("BYPASS_CAPACITY", "publish", b"selected");
    assert_eq!(fs::read_dir(&cache).unwrap().count(), 64);
    let fixture = Fixture::new();
    fixture.stage(b"selected");
    fixture.status("PUBLISHED", "publish", b"selected");
    let sparse = fixture.target.join(CACHE).join(format!("{OTHER}.pending"));
    File::create(&sparse)
        .unwrap()
        .set_len(1024 * 1024 * 1024)
        .unwrap();
    mode(&sparse, 0o600);
    assert!(fs::metadata(&sparse).unwrap().blocks() * 512 <= 4096);
    fixture.status("BYPASS_CAPACITY", "restore", b"selected");
    fixture.status("BYPASS_CAPACITY", "publish", b"selected");
    let mut oversized = fixture.arguments("restore", b"selected");
    oversized[5] = (1024_u64 * 1024 * 1024).to_string();
    assert_status(&fixture.invoke(&oversized), "BYPASS_CAPACITY");
}

#[test]
fn disk_reserve_preserves_source_and_previous_published_slot() {
    let fixture = Fixture::new();
    fixture.stage(b"previous");
    fixture.status("PUBLISHED", "publish", b"previous");
    let before = fs::read(fixture.sealed()).unwrap();
    fixture.stage(b"next pin");
    for (operation, payload) in [("publish", b"next pin"), ("restore", b"previous")] {
        let mut arguments = fixture.arguments(operation, payload);
        arguments[6] = (1_u64 << 60).to_string();
        assert_status(&fixture.invoke(&arguments), "BYPASS_CAPACITY");
        assert_eq!(fs::read(fixture.source.join(ARCHIVE)).unwrap(), b"next pin");
        assert_eq!(fs::read(fixture.sealed()).unwrap(), before);
    }
}

#[test]
fn unsafe_cache_entries_and_hardlinked_source_are_hard_failures() {
    for kind in ["hardlink", "symlink", "fifo", "writable"] {
        let fixture = Fixture::new();
        fixture.stage(b"selected");
        fixture.prepare_cache();
        let cache = fixture.sealed();
        match kind {
            "hardlink" => {
                fixture.status("PUBLISHED", "publish", b"selected");
                fs::hard_link(&cache, fixture.root.join("retained-link")).unwrap();
            }
            "symlink" => symlink(fixture.root.join("outside"), &cache).unwrap(),
            "fifo" => {
                assert!(
                    Command::new("mkfifo")
                        .arg(&cache)
                        .status()
                        .unwrap()
                        .success()
                );
            }
            "writable" => {
                fs::write(&cache, b"untrusted cache").unwrap();
                mode(&cache, 0o666);
            }
            _ => unreachable!(),
        }
        assert_refused(&fixture.invoke(&fixture.arguments("restore", b"selected")));
        assert_refused(&fixture.invoke(&fixture.arguments("publish", b"selected")));
        assert_eq!(fs::read(fixture.source.join(ARCHIVE)).unwrap(), b"selected");
    }
    let fixture = Fixture::new();
    let source = fixture.stage(b"selected");
    fixture.status("PUBLISHED", "publish", b"selected");
    let outside = fixture.root.join("source-second-link");
    fs::hard_link(&source, &outside).unwrap();
    assert_refused(&fixture.invoke(&fixture.arguments("restore", b"selected")));
    assert_refused(&fixture.invoke(&fixture.arguments("publish", b"selected")));
    assert_eq!(fs::read(outside).unwrap(), b"selected");
}

#[test]
fn cache_directory_and_exact_root_symlinks_are_never_followed() {
    let fixture = Fixture::new();
    fixture.stage(b"selected");
    fs::create_dir(&fixture.target).unwrap();
    mode(&fixture.target, 0o755);
    let outside = fixture.root.join("outside-cache");
    fs::create_dir(&outside).unwrap();
    mode(&outside, 0o700);
    symlink(&outside, fixture.target.join(CACHE)).unwrap();
    for operation in ["restore", "publish"] {
        assert_refused(&fixture.invoke(&fixture.arguments(operation, b"selected")));
    }
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    for (index, target) in [(1, &fixture.source), (2, &fixture.target)] {
        let alias = fixture.root.join(format!("root-alias-{index}"));
        symlink(target, &alias).unwrap();
        let mut arguments = fixture.arguments("publish", b"selected");
        arguments[index] = alias.to_str().unwrap().into();
        assert_refused(&fixture.invoke(&arguments));
    }
}

#[test]
fn untrusted_ancestors_bypass_and_missing_ancestors_are_never_created() {
    for permissions in [0o775, 0o777, 0o1777] {
        let mut fixture = Fixture::new();
        let parent = fixture.root.join("pool-parent");
        fs::create_dir(&parent).unwrap();
        mode(&parent, permissions);
        fixture.source = parent.join("source");
        fixture.target = parent.join("target");
        fixture.stage(b"selected");
        if permissions == 0o1777 {
            fixture.status("PUBLISHED", "publish", b"selected");
            fixture.status("HIT", "restore", b"selected");
        } else {
            fixture.status("BYPASS_UNAVAILABLE", "publish", b"selected");
            fixture.status("BYPASS_UNAVAILABLE", "restore", b"selected");
            assert!(!fixture.target.exists());
        }
    }
    let fixture = Fixture::new();
    fixture.stage(b"selected");
    let physical = fixture.root.join("physical");
    fs::create_dir(&physical).unwrap();
    let alias = fixture.root.join("alias");
    symlink(&physical, &alias).unwrap();
    for target in [alias.join("target"), fixture.root.join("missing/target")] {
        let mut arguments = fixture.arguments("publish", b"selected");
        arguments[2] = target.to_str().unwrap().into();
        assert_status(&fixture.invoke(&arguments), "BYPASS_UNAVAILABLE");
        assert!(!target.exists());
    }
    assert_eq!(fs::read_dir(physical).unwrap().count(), 0);
    assert!(!fixture.root.join("missing").exists());
}

#[test]
fn writable_exact_roots_and_nonprivate_caches_are_not_accepted() {
    for permissions in [0o775, 0o1777] {
        let fixture = Fixture::new();
        fixture.stage(b"selected");
        fs::create_dir(&fixture.target).unwrap();
        mode(&fixture.target, permissions);
        assert_refused(&fixture.invoke(&fixture.arguments("publish", b"selected")));
        assert!(!fixture.target.join(CACHE).exists());
    }
    let fixture = Fixture::new();
    fixture.stage(b"selected");
    let cache = fixture.prepare_cache();
    mode(&cache, 0o755);
    assert_refused(&fixture.invoke(&fixture.arguments("publish", b"selected")));
}

#[test]
fn uploaded_digest_or_length_mismatch_never_publishes() {
    let fixture = Fixture::new();
    fixture.stage(b"wrong bytes");
    assert_refused(&fixture.invoke(&fixture.arguments("publish", b"right bytes")));
    fixture.stage(b"short");
    assert_refused(&fixture.invoke(&fixture.arguments("publish", b"right bytes")));
    assert!(!fixture.target.exists());
}

#[test]
fn publication_uses_worker_time_instead_of_future_uploaded_archive_time() {
    use std::fs::FileTimes;
    use std::time::{Duration, SystemTime};
    let fixture = Fixture::new();
    let archive = fixture.stage(b"selected archive");
    let future = SystemTime::UNIX_EPOCH + Duration::from_secs(4_102_444_800);
    File::open(&archive)
        .unwrap()
        .set_times(FileTimes::new().set_modified(future))
        .unwrap();
    fixture.status("PUBLISHED", "publish", b"selected archive");
    assert_eq!(fs::metadata(archive).unwrap().modified().unwrap(), future);
    assert!(fs::metadata(fixture.sealed()).unwrap().modified().unwrap() < future);
    fixture.status("HIT", "restore", b"selected archive");
}

#[test]
fn unknown_entries_preserve_evidence_and_never_masquerade_as_a_miss() {
    let fixture = Fixture::new();
    fixture.stage(b"selected");
    let unknown = fixture.prepare_cache().join("unexpected-evidence");
    fs::write(&unknown, b"preserve").unwrap();
    fixture.status("BYPASS_CORRUPT", "restore", b"selected");
    fixture.status("BYPASS_CORRUPT", "publish", b"selected");
    assert_eq!(fs::read(unknown).unwrap(), b"preserve");
}
