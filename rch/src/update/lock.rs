//! Serialize updates and rollbacks with a persistent kernel lock.
//!
//! The gate is never unlinked: removing a locked file would let another
//! process lock a different inode at the same path. The PID sentinel remains
//! for older clients, but new clients hold the gate through sentinel cleanup
//! and the entire installation. Process-inspection failure is not proof of death.

use super::types::UpdateError;
use rch_common::process_identity::{OwnerPresence, owner_presence};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

const GATED_RECORD: &str = "rch-update-gate-v1";
const MAX_RECORD_BYTES: u64 = 4096;

/// Exclusive ownership of an update, including rollback and daemon restart.
pub struct UpdateLock {
    path: PathBuf,
    body: String,
    // Closed only after Drop has finished cleaning up our sentinel.
    _gate: File,
}

impl UpdateLock {
    pub fn acquire() -> Result<Self, UpdateError> {
        Self::acquire_at(&get_lock_path()?)
    }

    fn acquire_at(path: &Path) -> Result<Self, UpdateError> {
        let parent = path.parent().ok_or_else(|| {
            UpdateError::InstallFailed("Update lock has no parent directory".into())
        })?;
        fs::create_dir_all(parent).map_err(|error| lock_error("create lock directory", error))?;
        let gate = open_gate(path, true)?.ok_or(UpdateError::LockHeld)?;
        if let Some(body) = read_record(path).map_err(|error| lock_error("read lock", error))? {
            if !reclaimable(&body, legacy_owner_absent) {
                return Err(UpdateError::LockHeld);
            }
            // New clients cannot race this read/unlink: every acquire and Drop
            // holds the same persistent gate. Retain a full-body comparison
            // for legacy clients, which do not yet participate in the gate.
            if read_record(path).ok().flatten().as_deref() != Some(body.as_str()) {
                return Err(UpdateError::LockHeld);
            }
            fs::remove_file(path).map_err(|error| lock_error("retire stale lock", error))?;
        }

        // Publish an already complete record without ever overwriting an
        // existing sentinel. A crash while writing leaves only a temporary
        // file, not an ambiguous empty update.lock that blocks all future work.
        let body = format!(
            "{} {GATED_RECORD} {}\n",
            std::process::id(),
            uuid::Uuid::new_v4()
        );
        let mut temporary = tempfile::Builder::new()
            .prefix(".rch-update-lock-")
            .tempfile_in(parent)
            .map_err(|error| lock_error("create lock record", error))?;
        temporary
            .write_all(body.as_bytes())
            .and_then(|()| temporary.as_file().sync_all())
            .map_err(|error| lock_error("write lock record", error))?;
        match temporary.persist_noclobber(path) {
            Ok(file) => drop(file),
            Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(UpdateError::LockHeld);
            }
            Err(error) => return Err(lock_error("publish lock record", error.error)),
        }
        Ok(Self {
            path: path.to_owned(),
            body,
            _gate: gate,
        })
    }

    /// Advisory status, not permission to install. An unreadable or ambiguous
    /// owner is reported as locked. This probe never reaps a sentinel.
    #[allow(dead_code)]
    pub fn is_locked() -> bool {
        get_lock_path().map_or(true, |path| Self::is_locked_at(&path))
    }

    fn is_locked_at(path: &Path) -> bool {
        let _gate = match open_gate(path, false) {
            Ok(gate) => gate,
            Err(_) => return true,
        };
        match read_record(path) {
            Ok(None) => false,
            Ok(Some(body)) => !reclaimable(&body, legacy_owner_absent),
            Err(_) => true,
        }
    }
}

impl Drop for UpdateLock {
    fn drop(&mut self) {
        // The gate is still held here, including if the sentinel was removed
        // manually during this update. Never remove someone else's record.
        if read_record(&self.path).ok().flatten().as_deref() == Some(self.body.as_str()) {
            let _ = fs::remove_file(&self.path);
        }
        // Do not unlink the gate. Closing our File releases kernel ownership,
        // also on process death when this destructor does not run.
    }
}

fn get_lock_path() -> Result<PathBuf, UpdateError> {
    let data_dir = dirs::data_dir().ok_or_else(|| {
        UpdateError::InstallFailed("Could not determine data directory".to_owned())
    })?;
    Ok(data_dir.join("rch/update.lock"))
}

fn lock_error(operation: &str, error: io::Error) -> UpdateError {
    UpdateError::InstallFailed(format!("Failed to {operation}: {error}"))
}

/// No caller may remove or replace this file. As with the other local
/// ownership journals, its parent directory must be operator-controlled.
fn open_gate(path: &Path, create: bool) -> Result<Option<File>, UpdateError> {
    let path = path.with_extension("gate");
    match fs::symlink_metadata(&path) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            return Err(UpdateError::InstallFailed(
                "Update gate is not a regular file".into(),
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound && !create => return Ok(None),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(lock_error("inspect update gate", error)),
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(create)
        .truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound && !create => return Ok(None),
        Err(error) => return Err(lock_error("open update gate", error)),
    };
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(TryLockError::WouldBlock) => Err(UpdateError::LockHeld),
        Err(TryLockError::Error(error)) => Err(lock_error("lock update gate", error)),
    }
}

fn read_record(path: &Path) -> io::Result<Option<String>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_file() || metadata.len() > MAX_RECORD_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid update lock record",
        ));
    }
    let mut body = String::new();
    File::open(path)?
        .take(MAX_RECORD_BYTES + 1)
        .read_to_string(&mut body)?;
    if body.len() as u64 > MAX_RECORD_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oversized update lock record",
        ));
    }
    Ok(Some(body))
}

/// Called only while holding the gate (or from its read-only status probe).
/// A complete gated record is stale whenever the gate can be acquired, even
/// if its PID has been reused. Legacy records need affirmative death evidence.
fn reclaimable(body: &str, legacy_absent: impl FnOnce(u32) -> bool) -> bool {
    let fields: Vec<_> = body.split_whitespace().collect();
    let Some(pid) = fields
        .first()
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|value| value.parse::<u32>().ok())
    else {
        return false;
    };
    if pid == 0 {
        return false;
    }
    if fields.get(1) == Some(&GATED_RECORD) {
        return fields.len() == 3
            && body.ends_with('\n')
            && uuid::Uuid::parse_str(fields[2]).is_ok_and(|nonce| nonce.to_string() == fields[2]);
    }
    // Both previously emitted formats: PID only, or PID/time/counter in hex.
    let legacy = fields.len() == 1
        || (fields.len() == 3
            && fields[1..]
                .iter()
                .all(|value| value.bytes().all(|b| b.is_ascii_hexdigit())));
    legacy && pid > 1 && legacy_absent(pid)
}

fn legacy_owner_absent(pid: u32) -> bool {
    // The shared observer distinguishes death from permission errors, foreign
    // procfs namespaces and unsupported platforms. A reused/live PID with no
    // recorded birth identity remains unknown. In particular,
    // Windows inspection being unavailable must NEVER mean "not running".
    owner_presence(pid, None) == OwnerPresence::Absent
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Child, Command, Stdio};
    use std::sync::{Arc, Barrier};
    use std::time::{Duration, Instant};

    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("update.lock");
        (directory, path)
    }

    #[test]
    fn acquisition_and_drop_preserve_the_persistent_gate() {
        let (_directory, path) = fixture();
        assert!(!UpdateLock::is_locked_at(&path));
        assert!(!path.with_extension("gate").exists(), "status is read-only");
        let first = UpdateLock::acquire_at(&path).unwrap();
        assert!(UpdateLock::is_locked_at(&path));
        assert!(matches!(
            UpdateLock::acquire_at(&path),
            Err(UpdateError::LockHeld)
        ));
        let body = read_record(&path).unwrap().unwrap();
        assert_eq!(
            body.split_whitespace().next(),
            Some(std::process::id().to_string().as_str())
        );
        assert!(reclaimable(&body, |_| panic!(
            "new record must not consult a PID"
        )));
        drop(first);
        assert!(!path.exists());
        assert!(path.with_extension("gate").is_file());
        assert!(!UpdateLock::is_locked_at(&path));
        drop(UpdateLock::acquire_at(&path).unwrap());
    }

    #[test]
    fn stale_gated_record_does_not_depend_on_pid_liveness() {
        let (_directory, path) = fixture();
        // Model process death after publication: the PID may now be live again
        // but the old kernel owner is gone. No process is signalled or queried.
        let stale = format!(
            "{} {GATED_RECORD} {}\n",
            std::process::id(),
            uuid::Uuid::new_v4()
        );
        fs::write(&path, &stale).unwrap();
        assert!(!UpdateLock::is_locked_at(&path));
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            stale,
            "status must not sweep"
        );
        let lock = UpdateLock::acquire_at(&path).unwrap();
        assert_ne!(lock.body, stale);
        drop(lock);
        // A container's updater may itself be PID 1. Its gated record is
        // recoverable by kernel proof, unlike an ambiguous legacy PID 1.
        let init_record = format!("1 {GATED_RECORD} {}\n", uuid::Uuid::new_v4());
        fs::write(&path, &init_record).unwrap();
        assert!(reclaimable(&init_record, |_| panic!(
            "PID 1 needs no probe"
        )));
        drop(UpdateLock::acquire_at(&path).unwrap());
    }

    #[test]
    fn legacy_live_owner_and_unknown_platform_are_never_swept() {
        let (_directory, path) = fixture();
        for body in [
            std::process::id().to_string(),
            format!("{} abc def", std::process::id()),
        ] {
            fs::write(&path, &body).unwrap();
            assert!(UpdateLock::is_locked_at(&path));
            assert!(matches!(
                UpdateLock::acquire_at(&path),
                Err(UpdateError::LockHeld)
            ));
            assert_eq!(fs::read_to_string(&path).unwrap(), body);
        }
        for body in ["12345", "12345 abc def"] {
            assert!(!reclaimable(body, |_| false), "unknown/live owner: {body}");
            assert!(reclaimable(body, |pid| pid == 12345), "proved dead: {body}");
        }
        assert!(!legacy_owner_absent(0));
        assert!(!legacy_owner_absent(1));
        assert!(!legacy_owner_absent(u32::MAX));
    }

    #[test]
    fn ambiguous_and_incomplete_records_fail_closed() {
        let (_directory, path) = fixture();
        for body in [
            String::new(),
            "garbage".into(),
            "0".into(),
            "1".into(),
            "12345 unknown protocol".into(),
            "12345 abc".into(),
            format!("12345 {GATED_RECORD}"),
            format!("12345 {GATED_RECORD} invalid\n"),
            format!("12345 {GATED_RECORD} {}", uuid::Uuid::new_v4()),
            format!("12345 {GATED_RECORD} {} extra\n", uuid::Uuid::new_v4()),
        ] {
            assert!(!reclaimable(&body, |_| true), "{body:?}");
            fs::write(&path, &body).unwrap();
            assert!(UpdateLock::is_locked_at(&path));
            assert!(UpdateLock::acquire_at(&path).is_err());
            assert_eq!(fs::read_to_string(&path).unwrap(), body);
        }
    }

    #[test]
    fn oversized_non_utf8_and_nonregular_records_are_not_followed_or_removed() {
        let (_directory, path) = fixture();
        for bytes in [vec![b'1'; MAX_RECORD_BYTES as usize + 1], vec![0xff]] {
            fs::write(&path, &bytes).unwrap();
            assert!(UpdateLock::is_locked_at(&path));
            assert!(UpdateLock::acquire_at(&path).is_err());
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
        let other = path.with_file_name("directory.lock");
        fs::create_dir(&other).unwrap();
        assert!(UpdateLock::is_locked_at(&other));
        assert!(UpdateLock::acquire_at(&other).is_err());
        assert!(other.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_gate_and_sentinel_leave_the_target_untouched() {
        use std::os::unix::fs::symlink;
        let (directory, path) = fixture();
        let target = directory.path().join("unrelated");
        fs::write(&target, "keep me").unwrap();
        symlink(&target, &path).unwrap();
        assert!(UpdateLock::acquire_at(&path).is_err());
        assert!(UpdateLock::is_locked_at(&path));
        let other = directory.path().join("other.lock");
        symlink(&target, other.with_extension("gate")).unwrap();
        assert!(UpdateLock::acquire_at(&other).is_err());
        assert!(UpdateLock::is_locked_at(&other));
        assert_eq!(fs::read_to_string(target).unwrap(), "keep me");
    }

    #[test]
    fn sentinel_removal_does_not_release_kernel_ownership() {
        let (_directory, path) = fixture();
        let owner = UpdateLock::acquire_at(&path).unwrap();
        fs::remove_file(&path).unwrap(); // only this test's temporary sentinel
        assert!(UpdateLock::is_locked_at(&path));
        assert!(matches!(
            UpdateLock::acquire_at(&path),
            Err(UpdateError::LockHeld)
        ));
        drop(owner);
        drop(UpdateLock::acquire_at(&path).unwrap());
    }

    #[test]
    fn drop_does_not_remove_a_replacement_sentinel() {
        let (_directory, path) = fixture();
        let owner = UpdateLock::acquire_at(&path).unwrap();
        let replacement = std::process::id().to_string();
        fs::write(&path, &replacement).unwrap();
        drop(owner);
        assert_eq!(fs::read_to_string(&path).unwrap(), replacement);
        assert!(matches!(
            UpdateLock::acquire_at(&path),
            Err(UpdateError::LockHeld)
        ));
    }

    #[test]
    fn simultaneous_stale_reclaimers_have_exactly_one_winner() {
        let (_directory, path) = fixture();
        fs::write(
            &path,
            format!("12345 {GATED_RECORD} {}\n", uuid::Uuid::new_v4()),
        )
        .unwrap();
        let barrier = Arc::new(Barrier::new(12));
        let handles: Vec<_> = (0..12)
            .map(|_| {
                let barrier = barrier.clone();
                let path = path.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    UpdateLock::acquire_at(&path)
                })
            })
            .collect();
        // Keep the winning guard until every racing acquire has finished.
        let mut winners = Vec::new();
        for handle in handles {
            match handle.join().unwrap() {
                Ok(guard) => winners.push(guard),
                Err(UpdateError::LockHeld) => {}
                Err(error) => panic!("unexpected lock error: {error}"),
            }
        }
        assert_eq!(winners.len(), 1);
        drop(winners);
        drop(UpdateLock::acquire_at(&path).unwrap());
    }

    struct OwnedChild(Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn child(path: &Path, mode: &str) -> OwnedChild {
        OwnedChild(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "update::lock::tests::subprocess_fixture",
                    "--nocapture",
                ])
                .env("RCH_UPDATE_LOCK_TEST_PATH", path)
                .env("RCH_UPDATE_LOCK_TEST_MODE", mode)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        )
    }

    fn wait_for_file(child: &mut OwnedChild, path: &Path) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !path.exists() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "fixture child exited before ready"
            );
            assert!(Instant::now() < deadline, "fixture readiness timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    // Running this test normally does nothing. A parent test passes a private
    // TempDir path to a dedicated child, never the operator's real data dir.
    #[test]
    fn subprocess_fixture() {
        let Some(path) = std::env::var_os("RCH_UPDATE_LOCK_TEST_PATH") else {
            return;
        };
        let path = PathBuf::from(path);
        let mode = std::env::var("RCH_UPDATE_LOCK_TEST_MODE").unwrap();
        if mode == "blocked" {
            assert!(matches!(
                UpdateLock::acquire_at(&path),
                Err(UpdateError::LockHeld)
            ));
            fs::write(path.with_extension("blocked"), b"blocked").unwrap();
            return;
        }
        let _owner = if mode == "before-record" {
            Some(open_gate(&path, true).unwrap().unwrap())
        } else {
            None
        };
        let _update = if mode == "holding" {
            Some(UpdateLock::acquire_at(&path).unwrap())
        } else if mode == "legacy" {
            fs::write(&path, std::process::id().to_string()).unwrap();
            None
        } else {
            assert_eq!(mode, "before-record");
            None
        };
        fs::write(path.with_extension("ready"), b"ready").unwrap();
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    #[test]
    fn another_process_cannot_acquire_during_an_update() {
        let (_directory, path) = fixture();
        let owner = UpdateLock::acquire_at(&path).unwrap();
        let mut contender = child(&path, "blocked");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = contender.0.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(
                Instant::now() < deadline,
                "contender hung instead of refusing"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            path.with_extension("blocked").exists(),
            "child test must actually run"
        );
        drop(owner);
        drop(UpdateLock::acquire_at(&path).unwrap());
    }

    #[test]
    fn legacy_reclamation_requires_native_evidence_after_child_exit() {
        let (_directory, path) = fixture();
        let mut owner = child(&path, "legacy");
        wait_for_file(&mut owner, &path.with_extension("ready"));
        assert!(matches!(
            UpdateLock::acquire_at(&path),
            Err(UpdateError::LockHeld)
        ));
        owner.0.kill().unwrap();
        owner.0.wait().unwrap();
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        drop(UpdateLock::acquire_at(&path).unwrap());
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        assert!(matches!(
            UpdateLock::acquire_at(&path),
            Err(UpdateError::LockHeld)
        ));
    }

    #[test]
    fn process_death_releases_gate_before_and_after_record_publication() {
        for mode in ["before-record", "holding"] {
            let (_directory, path) = fixture();
            let mut owner = child(&path, mode);
            wait_for_file(&mut owner, &path.with_extension("ready"));
            assert!(UpdateLock::is_locked_at(&path));
            assert!(matches!(
                UpdateLock::acquire_at(&path),
                Err(UpdateError::LockHeld)
            ));
            owner.0.kill().unwrap(); // exact test-owned child handle, no PID search
            owner.0.wait().unwrap();
            // No Drop ran in the child. Kernel release, not PID guessing or
            // a manual sentinel sweep, must allow the next update on all OSes.
            assert!(!UpdateLock::is_locked_at(&path));
            drop(UpdateLock::acquire_at(&path).unwrap());
            assert!(!path.exists());
            assert!(path.with_extension("gate").is_file());
        }
    }
}
