//! Durable local/remote job identity and lifecycle correlation
//! (bd-session-history-remediation-ocv9i.10.1).
//!
//! Session history showed agents unable to tell whether a `cargo` command they
//! launched was queued, running, already finished, abandoned, or had failed
//! before the daemon ever admitted it — because there was no stable identity
//! tying the local `rch exec` wrapper to the daemon's remote build.
//!
//! This module introduces that identity:
//! - a [`LocalWrapperId`] minted by `rch exec` the instant a command is
//!   intercepted, *before* any daemon contact, so it exists even when
//!   admission fails;
//! - the daemon's existing remote build id (`u64`), recorded once admitted;
//! - [`JobIdentity`] pairing the two;
//! - [`JobLifecycleState`] (the five operator-facing states) plus a pure
//!   [`derive_job_lifecycle_state`] correlation over observable [`JobSignals`],
//!   and [`JobRecord`] for `rch jobs --json`.
//!
//! The wrapper persists this identity through admission, heartbeat and retrieval;
//! recovery commands reconcile the same identity without replaying a command.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// Locally-generated wrapper id, minted by `rch exec` before any daemon
/// contact. Stable for the whole life of the command.
pub type LocalWrapperId = String;

/// Remote build id assigned by the daemon on queue admission. Mirrors the
/// existing `build_id: u64` used across the status/history surfaces.
pub type RemoteBuildId = u64;

/// Prefix of every local wrapper id, so logs and cleanup can recognise them.
pub const LOCAL_WRAPPER_ID_PREFIX: &str = "rchw-";

/// Resolve the durable client-lease directory using RCH's shared state-home
/// policy.  Both the hook and restart remediator use this function so they
/// cannot accidentally inspect different state roots.
#[must_use]
pub fn default_job_lease_directory() -> PathBuf {
    let state_dir = std::env::var_os("RCH_STATE_HOME")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .or_else(|| {
            std::env::var_os("XDG_STATE_HOME")
                .map(|path| PathBuf::from(path).join("rch"))
                .filter(|path| !path.as_os_str().is_empty())
        })
        .or_else(|| {
            std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state/rch"))
        })
        .unwrap_or_else(|| PathBuf::from("/tmp/rch"));
    state_dir.join("job-leases")
}

/// Descriptor-bound journal ownership shared by live writers, recovery and
/// the daemon's history reaper. The persistent lock inode is never unlinked.
#[cfg(unix)]
pub mod journal {
    use super::{DurableJobLease, LOCAL_WRAPPER_ID_PREFIX};
    use anyhow::{Context, Result, ensure};
    use rustix::fs::{Mode, OFlags};
    use serde::Serialize;
    use std::ffi::{CStr, CString};
    use std::fs::{File, Metadata};
    use std::io::{Read, Write};
    use std::os::fd::{AsFd, BorrowedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};

    const READ_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::CLOEXEC)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::NONBLOCK)
        .union(OFlags::NOCTTY);

    fn open_directory(parent: &Path) -> Result<File> {
        Ok(File::from(rustix::fs::open(
            parent,
            OFlags::RDONLY
                | OFlags::DIRECTORY
                | OFlags::CLOEXEC
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK,
            Mode::empty(),
        )?))
    }

    fn verify_directory(directory: &File, parent: &Path) -> Result<()> {
        let held = directory.metadata()?;
        let named = std::fs::symlink_metadata(parent)?;
        ensure!(
            named.is_dir() && held.dev() == named.dev() && held.ino() == named.ino(),
            "recovery journal directory changed; retry the retained same wrapper"
        );
        Ok(())
    }

    fn read_regular_at(directory: BorrowedFd<'_>, name: &CStr) -> Result<(File, Vec<u8>)> {
        let mut file = File::from(rustix::fs::openat(
            directory,
            name,
            READ_FLAGS,
            Mode::empty(),
        )?);
        ensure!(file.metadata()?.is_file(), "journal is not a regular file");
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .context("journal read failed")?;
        Ok((file, bytes))
    }

    /// Observe a journal without taking ownership. Reject symlinks and special
    /// files without waiting for a FIFO writer, and retain the directory binding.
    pub fn read_lease_bytes(path: &Path) -> Result<Vec<u8>> {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let name = CString::new(path.file_name().context("journal has no name")?.as_bytes())?;
        let directory = open_directory(parent)?;
        let (_, bytes) = read_regular_at(directory.as_fd(), &name)?;
        verify_directory(&directory, parent)?;
        Ok(bytes)
    }

    /// A retained journal is evidence of an earlier observation, never the
    /// current attempt's scheduling, cancellation or publication authority.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
    #[serde(rename_all = "snake_case")]
    pub enum RetainedSnapshotKind {
        Recovery,
        LegacyArtifactPolicy,
    }

    impl RetainedSnapshotKind {
        pub const fn as_str(self) -> &'static str {
            match self {
                Self::Recovery => "recovery",
                Self::LegacyArtifactPolicy => "legacy_artifact_policy",
            }
        }
    }

    /// Select candidate filename families before reading them. A malformed
    /// name in a known family is still evidence to report as unreadable, not
    /// an unrelated file to silently omit from a supposedly complete census.
    pub fn retained_snapshot_kind(name: &CStr) -> Option<RetainedSnapshotKind> {
        let bytes = name.to_bytes();
        if !bytes.ends_with(b".before") {
            return None;
        }
        if bytes.starts_with(b"artifact-policy-") {
            Some(RetainedSnapshotKind::LegacyArtifactPolicy)
        } else if bytes.starts_with(LOCAL_WRAPPER_ID_PREFIX.as_bytes())
            && bytes
                .windows(b".recovery-".len())
                .any(|part| part == b".recovery-")
        {
            Some(RetainedSnapshotKind::Recovery)
        } else {
            None
        }
    }

    #[derive(Debug)]
    pub struct RetainedJournalSnapshot {
        pub lease: DurableJobLease,
        /// BLAKE3 of the observed exact bytes. Recovery names bind this digest;
        /// legacy names do not contain a stored digest to verify against.
        pub digest: String,
        pub kind: RetainedSnapshotKind,
    }

    fn canonical_wrapper(wrapper: &str) -> bool {
        wrapper
            .strip_prefix(LOCAL_WRAPPER_ID_PREFIX)
            .is_some_and(|suffix| {
                uuid::Uuid::parse_str(suffix).is_ok_and(|id| id.to_string() == suffix)
            })
    }

    fn owned_regular(metadata: &Metadata) -> bool {
        metadata.is_file()
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.nlink() == 1
    }

    fn private_regular(metadata: &Metadata) -> bool {
        owned_regular(metadata) && metadata.mode() & 0o077 == 0
    }

    #[derive(Clone, Copy)]
    enum JournalFileRole {
        Current,
        Retained,
    }

    impl JournalFileRole {
        fn accepts(self, metadata: &Metadata) -> bool {
            match self {
                // Earlier and fallback journal writers use the process umask.
                // Reading an owned journal does not permit another user to
                // change its recovery evidence; foreign write access does.
                Self::Current => owned_regular(metadata) && metadata.mode() & 0o022 == 0,
                Self::Retained => private_regular(metadata),
            }
        }
    }

    fn require_named_bytes(
        directory: BorrowedFd<'_>,
        name: &CStr,
        held: &File,
        expected: &[u8],
        role: JournalFileRole,
    ) -> Result<()> {
        let (named, bytes) = read_regular_at(directory, name)?;
        let held = held.metadata()?;
        let named = named.metadata()?;
        ensure!(
            role.accepts(&held)
                && role.accepts(&named)
                && held.dev() == named.dev()
                && held.ino() == named.ino()
                && bytes == expected,
            "retained journal file identity, permissions or exact bytes changed"
        );
        Ok(())
    }

    fn read_retained_file_at(
        directory: BorrowedFd<'_>,
        name: &CStr,
    ) -> Result<(File, Vec<u8>, RetainedJournalSnapshot)> {
        let kind = retained_snapshot_kind(name).context("unrecognized retained journal name")?;
        let spelling = name
            .to_str()
            .context("retained journal name is not UTF-8")?;
        if kind == RetainedSnapshotKind::LegacyArtifactPolicy {
            let token = spelling
                .strip_prefix("artifact-policy-")
                .and_then(|name| name.strip_suffix(".before"))
                .context("invalid legacy journal name")?;
            ensure!(
                uuid::Uuid::parse_str(token).is_ok_and(|id| id.simple().to_string() == token),
                "invalid legacy journal name"
            );
        }
        let (file, bytes) = read_regular_at(directory, name)?;
        ensure!(
            private_regular(&file.metadata()?),
            "unsafe retained journal file"
        );
        let lease: DurableJobLease =
            serde_json::from_slice(&bytes).context("invalid retained journal")?;
        ensure!(
            lease.schema_version == 1 && canonical_wrapper(&lease.identity.local_wrapper_id),
            "retained journal identity or schema is unsupported"
        );
        let digest = blake3::hash(&bytes).to_hex().to_string();
        if kind == RetainedSnapshotKind::Recovery {
            ensure!(
                spelling
                    == format!(
                        "{}.recovery-{digest}.before",
                        lease.identity.local_wrapper_id
                    ),
                "retained journal filename does not bind its exact bytes and wrapper"
            );
        }
        require_named_bytes(directory, name, &file, &bytes, JournalFileRole::Retained)?;
        Ok((
            file,
            bytes,
            RetainedJournalSnapshot {
                lease,
                digest,
                kind,
            },
        ))
    }

    /// Read immutable evidence through an already held directory, without
    /// adopting it as the wrapper's current journal. No path is followed to
    /// sources, staging, caller artifacts or a remote worker.
    pub fn read_retained_snapshot_at(
        directory: BorrowedFd<'_>,
        name: &CStr,
    ) -> Result<RetainedJournalSnapshot> {
        read_retained_file_at(directory, name).map(|(_, _, snapshot)| snapshot)
    }

    /// One exclusive journal owner. Dropping it releases the lock, not its inode.
    pub struct JobJournalGate {
        gate: File,
        directory: File,
        parent: PathBuf,
        gate_name: CString,
        journal_name: CString,
    }

    impl JobJournalGate {
        /// `None` means another handle owns this journal. Callers must not wait
        /// inside admission scans or continue a destructive operation unlocked.
        pub fn try_acquire(lease_path: &Path) -> Result<Option<Self>> {
            let path = lease_path.with_extension("recovery.lock");
            let parent = path.parent().context("recovery lock has no parent")?;
            let name = CString::new(
                path.file_name()
                    .context("recovery lock has no name")?
                    .as_bytes(),
            )?;
            let directory = open_directory(parent)?;
            let uid = rustix::process::geteuid().as_raw();
            let safe = |metadata: &Metadata| {
                metadata.file_type().is_file()
                    && metadata.uid() == uid
                    && metadata.nlink() == 1
                    && metadata.mode() & 0o077 == 0
            };
            match std::fs::symlink_metadata(&path) {
                Ok(metadata) => ensure!(safe(&metadata), "unsafe recovery lock file"),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            let flags = OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY;
            let gate = File::from(rustix::fs::openat(
                directory.as_fd(),
                name.as_c_str(),
                OFlags::RDWR | OFlags::CREATE | flags,
                Mode::RUSR | Mode::WUSR,
            )?);
            ensure!(safe(&gate.metadata()?), "unsafe recovery lock file");
            let named_gate = File::from(rustix::fs::openat(
                directory.as_fd(),
                name.as_c_str(),
                READ_FLAGS,
                Mode::empty(),
            )?);
            let held = gate.metadata()?;
            let named = named_gate.metadata()?;
            let held_directory = directory.metadata()?;
            let named_directory = std::fs::symlink_metadata(parent)?;
            ensure!(
                safe(&held)
                    && safe(&named)
                    && held.dev() == named.dev()
                    && held.ino() == named.ino()
                    && named_directory.is_dir()
                    && held_directory.dev() == named_directory.dev()
                    && held_directory.ino() == named_directory.ino(),
                "recovery lock path changed during acquisition"
            );
            match gate.try_lock() {
                Ok(()) => {}
                Err(std::fs::TryLockError::WouldBlock) => return Ok(None),
                Err(std::fs::TryLockError::Error(error)) => {
                    return Err(error).context("cannot inspect exclusive job journal ownership");
                }
            }
            let ownership = Self {
                gate,
                directory,
                parent: parent.to_owned(),
                gate_name: name,
                journal_name: CString::new(
                    lease_path
                        .file_name()
                        .context("journal has no name")?
                        .as_bytes(),
                )?,
            };
            ownership.verify()?;
            Ok(Some(ownership))
        }

        /// Names must still refer to the held directory and persistent lock.
        pub fn verify(&self) -> Result<()> {
            verify_directory(&self.directory, &self.parent)?;
            let named_gate = File::from(rustix::fs::openat(
                self.directory.as_fd(),
                self.gate_name.as_c_str(),
                READ_FLAGS,
                Mode::empty(),
            )?);
            let held = self.gate.metadata()?;
            let named = named_gate.metadata()?;
            ensure!(
                named.is_file()
                    && held.is_file()
                    && named.dev() == held.dev()
                    && named.ino() == held.ino()
                    && named.uid() == held.uid()
                    && named.nlink() == 1
                    && held.nlink() == 1
                    && named.mode() & 0o077 == 0,
                "recovery lock changed; no journal mutation acknowledged"
            );
            Ok(())
        }

        pub fn directory(&self) -> &File {
            &self.directory
        }

        pub fn parent(&self) -> &Path {
            &self.parent
        }

        pub fn journal_name(&self) -> &CStr {
            &self.journal_name
        }

        pub fn lock_metadata(&self) -> std::io::Result<Metadata> {
            self.gate.metadata()
        }

        /// Keep the opened inode with the bytes used for a reap decision.
        pub fn read_snapshot(&self) -> Result<(File, Vec<u8>)> {
            self.verify()?;
            let snapshot = read_regular_at(self.directory.as_fd(), &self.journal_name)?;
            self.verify()?;
            Ok(snapshot)
        }

        /// Durably preserve the exact current journal before its recovery
        /// recipe is superseded. The content-bound name makes repeating an
        /// interrupted or refused retry idempotent. Snapshots are not active
        /// leases and are never removed by the ordinary history reaper.
        pub fn retain_snapshot(&self, expected: &DurableJobLease) -> Result<PathBuf> {
            self.retain_snapshot_with(expected, |_| Ok(()))
        }

        fn retain_snapshot_with(
            &self,
            expected: &DurableJobLease,
            before_publication: impl FnOnce(&Path) -> Result<()>,
        ) -> Result<PathBuf> {
            ensure!(
                expected.schema_version == 1
                    && canonical_wrapper(&expected.identity.local_wrapper_id),
                "cannot retain an unsupported journal identity or schema"
            );
            let (original, bytes) = self.read_snapshot()?;
            let observed: DurableJobLease = serde_json::from_slice(&bytes)?;
            ensure!(
                observed == *expected,
                "current journal changed before preserving recovery custody"
            );
            require_named_bytes(
                self.directory.as_fd(),
                &self.journal_name,
                &original,
                &bytes,
                JournalFileRole::Current,
            )?;
            let digest = blake3::hash(&bytes).to_hex().to_string();
            let name = CString::new(format!(
                "{}.recovery-{digest}.before",
                expected.identity.local_wrapper_id
            ))?;
            let retained = match read_retained_file_at(self.directory.as_fd(), &name) {
                Ok((file, retained_bytes, snapshot)) => {
                    ensure!(
                        retained_bytes == bytes && snapshot.lease == *expected,
                        "existing retained journal contradicts the current exact bytes"
                    );
                    file
                }
                Err(error)
                    if error.downcast_ref::<rustix::io::Errno>()
                        == Some(&rustix::io::Errno::NOENT) =>
                {
                    // A failed write must not occupy the stable content-bound
                    // name. Keep its partial temporary and the current journal
                    // so a later retry can publish a new complete snapshot.
                    let temporary = CString::new(format!(
                        ".recovery-snapshot-{}.tmp",
                        uuid::Uuid::new_v4().simple()
                    ))?;
                    let mut file = File::from(rustix::fs::openat(
                        self.directory.as_fd(),
                        temporary.as_c_str(),
                        OFlags::RDWR
                            | OFlags::CREATE
                            | OFlags::EXCL
                            | OFlags::CLOEXEC
                            | OFlags::NOFOLLOW
                            | OFlags::NONBLOCK
                            | OFlags::NOCTTY,
                        Mode::RUSR | Mode::WUSR,
                    )?);
                    file.write_all(&bytes)?;
                    file.sync_all()?;
                    before_publication(&self.parent.join(temporary.to_str()?))?;
                    self.verify()?;
                    require_named_bytes(
                        self.directory.as_fd(),
                        &temporary,
                        &file,
                        &bytes,
                        JournalFileRole::Retained,
                    )?;
                    match publish_snapshot_name(self.directory.as_fd(), &temporary, &name) {
                        Ok(()) => file,
                        Err(error)
                            if error.downcast_ref::<rustix::io::Errno>()
                                == Some(&rustix::io::Errno::EXIST) =>
                        {
                            // A competing name can only be accepted as the
                            // identical private snapshot. Never overwrite it
                            // or remove the prepared temporary on this path.
                            let (existing, retained_bytes, snapshot) =
                                read_retained_file_at(self.directory.as_fd(), &name)?;
                            ensure!(
                                retained_bytes == bytes && snapshot.lease == *expected,
                                "retained journal name collision"
                            );
                            existing
                        }
                        Err(error) => return Err(error),
                    }
                }
                Err(error) => return Err(error),
            };
            // Reusing a matching name also has to establish durability: an
            // earlier process may have stopped between rename and directory
            // sync. Keep the active journal until both names are verified.
            retained.sync_all()?;
            self.directory.sync_all()?;
            self.verify()?;
            require_named_bytes(
                self.directory.as_fd(),
                &name,
                &retained,
                &bytes,
                JournalFileRole::Retained,
            )?;
            require_named_bytes(
                self.directory.as_fd(),
                &self.journal_name,
                &original,
                &bytes,
                JournalFileRole::Current,
            )?;
            self.verify()?;
            Ok(self.parent.join(name.to_str()?))
        }

        /// The caller supplies its history-retention policy. This operation
        /// only removes the exact unchanged journal inspected under this gate;
        /// it never removes staging, sidecars, source trees or the gate itself.
        /// An ordinary unlink failure is best effort (`false`), while changed
        /// evidence or an unsafe namespace is an error and must be retained.
        pub fn remove_journal_if_unchanged(
            &self,
            snapshot: &File,
            expected: &[u8],
        ) -> Result<bool> {
            self.verify()?;
            let (named_file, bytes) = read_regular_at(self.directory.as_fd(), &self.journal_name)?;
            let held = snapshot.metadata()?;
            let named = named_file.metadata()?;
            ensure!(
                held.is_file()
                    && named.is_file()
                    && held.dev() == named.dev()
                    && held.ino() == named.ino()
                    && held.uid() == rustix::process::geteuid().as_raw()
                    && named.uid() == held.uid()
                    && held.nlink() == 1
                    && named.nlink() == 1
                    && named.mode() & 0o022 == 0
                    && bytes == expected,
                "job journal changed before history reaping"
            );
            self.verify()?;
            if rustix::fs::unlinkat(
                self.directory.as_fd(),
                self.journal_name.as_c_str(),
                rustix::fs::AtFlags::empty(),
            )
            .is_err()
            {
                return Ok(false);
            }
            // Reappearing disposable history after a failed directory sync is
            // harmless; a later scan can repeat the same policy and checks.
            let _ = self.directory.sync_all();
            Ok(true)
        }
    }

    fn publish_snapshot_name(
        directory: BorrowedFd<'_>,
        temporary: &CStr,
        name: &CStr,
    ) -> Result<()> {
        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_vendor = "apple",
            target_os = "redox"
        ))]
        {
            rustix::fs::renameat_with(
                directory,
                temporary,
                directory,
                name,
                rustix::fs::RenameFlags::NOREPLACE,
            )?;
            Ok(())
        }
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_vendor = "apple",
            target_os = "redox"
        )))]
        {
            let _ = (directory, temporary, name);
            anyhow::bail!(
                "atomic no-replace journal snapshots are unsupported on this platform; current recovery evidence retained"
            )
        }
    }

    #[cfg(all(
        test,
        any(
            target_os = "linux",
            target_os = "android",
            target_vendor = "apple",
            target_os = "redox"
        )
    ))]
    mod tests {
        use super::*;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        fn write_private(path: &Path, bytes: &[u8]) {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .unwrap();
            file.write_all(bytes).unwrap();
            file.sync_all().unwrap();
        }

        struct Fixture {
            root: tempfile::TempDir,
            path: PathBuf,
            lease: DurableJobLease,
            bytes: Vec<u8>,
            gate: JobJournalGate,
        }

        impl Fixture {
            fn new() -> Self {
                let root = tempfile::Builder::new()
                    .disable_cleanup(true)
                    .tempdir()
                    .unwrap();
                let directory = root.path().join("jobs");
                std::fs::create_dir(&directory).unwrap();
                let path = directory.join("lease.json");
                let mut lease = DurableJobLease::new(
                    super::super::JobIdentity::new_local(),
                    12345,
                    None,
                    None,
                    1,
                    true,
                    false,
                    "blake3:fixture".into(),
                );
                lease.admit(41, "first-worker".into(), 2);
                lease.exit_code = Some(137);
                lease.recovery = Some(serde_json::json!({
                    "retired": true,
                    "retained_root": "/worker/retained-source",
                    "returned": 102,
                    "phases": [{"complete": false, "pending": ["report", "original-hash"]}],
                }));
                let mut value = serde_json::to_value(&lease).unwrap();
                // The current typed reader does not understand this field.
                // Re-serializing the lease would silently lose these bytes.
                value["future_custody"] = serde_json::json!({
                    "staging": "/custom/retrieval/old-attempt",
                    "opaque": [1, "preserve exactly", {"version": 9}],
                });
                let bytes = serde_json::to_vec_pretty(&value).unwrap();
                write_private(&path, &bytes);
                let gate = JobJournalGate::try_acquire(&path).unwrap().unwrap();
                Self {
                    root,
                    path,
                    lease,
                    bytes,
                    gate,
                }
            }

            fn snapshot_path(&self) -> PathBuf {
                self.path.parent().unwrap().join(format!(
                    "{}.recovery-{}.before",
                    self.lease.identity.local_wrapper_id,
                    blake3::hash(&self.bytes).to_hex()
                ))
            }

            fn temporary_paths(&self) -> Vec<PathBuf> {
                std::fs::read_dir(self.path.parent().unwrap())
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .filter(|path| {
                        path.file_name()
                            .unwrap()
                            .as_bytes()
                            .starts_with(b".recovery-snapshot-")
                    })
                    .collect()
            }
        }

        #[test]
        fn retained_snapshot_is_exact_private_and_idempotent() {
            let fixture = Fixture::new();
            let snapshot = fixture.gate.retain_snapshot(&fixture.lease).unwrap();
            assert_eq!(snapshot, fixture.snapshot_path());
            assert_eq!(std::fs::read(&snapshot).unwrap(), fixture.bytes);
            let inode = std::fs::metadata(&snapshot).unwrap().ino();
            assert!(private_regular(&std::fs::metadata(&snapshot).unwrap()));
            let name = CString::new(snapshot.file_name().unwrap().as_bytes()).unwrap();
            let observed =
                read_retained_snapshot_at(fixture.gate.directory().as_fd(), &name).unwrap();
            assert_eq!(observed.kind, RetainedSnapshotKind::Recovery);
            assert_eq!(observed.lease, fixture.lease);
            assert_eq!(
                observed.digest,
                blake3::hash(&fixture.bytes).to_hex().as_str()
            );
            assert_eq!(
                fixture.gate.retain_snapshot(&fixture.lease).unwrap(),
                snapshot
            );
            assert_eq!(std::fs::metadata(snapshot).unwrap().ino(), inode);
            assert!(fixture.temporary_paths().is_empty());
            assert_eq!(std::fs::read(&fixture.path).unwrap(), fixture.bytes);
            assert!(!observed.lease.terminal_acknowledged);
            assert_eq!(
                observed.lease.recovery.unwrap()["phases"][0]["complete"],
                false
            );
        }

        #[test]
        fn snapshot_preserves_readable_originals_as_private_idempotent_evidence() {
            for mode in [0o640, 0o644] {
                let fixture = Fixture::new();
                std::fs::set_permissions(&fixture.path, std::fs::Permissions::from_mode(mode))
                    .unwrap();
                let original = std::fs::metadata(&fixture.path).unwrap();
                let snapshot = fixture.gate.retain_snapshot(&fixture.lease).unwrap();
                assert_eq!(snapshot, fixture.snapshot_path());
                let retained = std::fs::metadata(&snapshot).unwrap();
                assert!(private_regular(&retained));
                assert_eq!(retained.mode() & 0o777, 0o600);
                assert_eq!(std::fs::read(&snapshot).unwrap(), fixture.bytes);
                let name = CString::new(snapshot.file_name().unwrap().as_bytes()).unwrap();
                let observed =
                    read_retained_snapshot_at(fixture.gate.directory().as_fd(), &name).unwrap();
                assert_eq!(observed.lease, fixture.lease);
                assert_eq!(
                    fixture.gate.retain_snapshot(&fixture.lease).unwrap(),
                    snapshot
                );
                assert_eq!(std::fs::metadata(&snapshot).unwrap().ino(), retained.ino());
                let current = std::fs::metadata(&fixture.path).unwrap();
                assert_eq!(current.dev(), original.dev());
                assert_eq!(current.ino(), original.ino());
                assert_eq!(current.uid(), original.uid());
                assert_eq!(current.nlink(), original.nlink());
                assert_eq!(current.mode(), original.mode());
                assert_eq!(std::fs::read(&fixture.path).unwrap(), fixture.bytes);
                assert!(fixture.temporary_paths().is_empty());
            }
        }

        #[test]
        fn snapshot_refuses_writable_or_hardlinked_originals_without_mutation() {
            for change in ["group_writable", "other_writable", "hardlink"] {
                let fixture = Fixture::new();
                let alias = fixture.root.path().join("original-alias");
                let mode = match change {
                    "group_writable" => 0o664,
                    "other_writable" => 0o606,
                    "hardlink" => 0o644,
                    _ => unreachable!(),
                };
                std::fs::set_permissions(&fixture.path, std::fs::Permissions::from_mode(mode))
                    .unwrap();
                if change == "hardlink" {
                    std::fs::hard_link(&fixture.path, &alias).unwrap();
                }
                let original = std::fs::metadata(&fixture.path).unwrap();
                assert!(
                    fixture.gate.retain_snapshot(&fixture.lease).is_err(),
                    "accepted {change}"
                );
                let current = std::fs::metadata(&fixture.path).unwrap();
                assert_eq!(current.dev(), original.dev());
                assert_eq!(current.ino(), original.ino());
                assert_eq!(current.mode(), original.mode());
                assert_eq!(current.nlink(), original.nlink());
                assert_eq!(std::fs::read(&fixture.path).unwrap(), fixture.bytes);
                assert!(!fixture.snapshot_path().exists());
                assert!(fixture.temporary_paths().is_empty());
                if change == "hardlink" {
                    assert_eq!(std::fs::read(alias).unwrap(), fixture.bytes);
                }
            }
        }

        #[test]
        fn readable_original_changes_refuse_success_and_preserve_both_records() {
            for change in ["bytes", "inode", "permissions", "hardlink"] {
                let fixture = Fixture::new();
                std::fs::set_permissions(&fixture.path, std::fs::Permissions::from_mode(0o644))
                    .unwrap();
                let preserved = fixture.root.path().join("original-before-change");
                let result = fixture.gate.retain_snapshot_with(&fixture.lease, |_| {
                    match change {
                        "bytes" => std::fs::write(&fixture.path, b"changed readable journal")?,
                        "inode" => {
                            std::fs::rename(&fixture.path, &preserved)?;
                            write_private(&fixture.path, &fixture.bytes);
                        }
                        "permissions" => std::fs::set_permissions(
                            &fixture.path,
                            std::fs::Permissions::from_mode(0o664),
                        )?,
                        "hardlink" => std::fs::hard_link(&fixture.path, &preserved)?,
                        _ => unreachable!(),
                    }
                    Ok(())
                });
                assert!(result.is_err(), "accepted changed original: {change}");
                let snapshot = fixture.snapshot_path();
                assert_eq!(std::fs::read(&snapshot).unwrap(), fixture.bytes);
                assert!(private_regular(&std::fs::metadata(&snapshot).unwrap()));
                if change == "bytes" {
                    assert_eq!(
                        std::fs::read(&fixture.path).unwrap(),
                        b"changed readable journal"
                    );
                } else {
                    assert_eq!(std::fs::read(&fixture.path).unwrap(), fixture.bytes);
                }
                if matches!(change, "inode" | "hardlink") {
                    assert_eq!(std::fs::read(&preserved).unwrap(), fixture.bytes);
                }
                if change == "permissions" {
                    assert_eq!(
                        std::fs::metadata(&fixture.path).unwrap().mode() & 0o777,
                        0o664
                    );
                }
            }
        }

        #[test]
        fn snapshot_refuses_a_stale_expected_epoch_without_creating_evidence() {
            let fixture = Fixture::new();
            let mut stale = fixture.lease.clone();
            stale.heartbeat_unix_ms += 1;
            assert!(fixture.gate.retain_snapshot(&stale).is_err());
            assert!(!fixture.snapshot_path().exists());
            assert!(fixture.temporary_paths().is_empty());
            assert_eq!(std::fs::read(&fixture.path).unwrap(), fixture.bytes);
        }

        #[test]
        fn incomplete_snapshot_write_keeps_current_and_allows_a_fresh_retry() {
            let fixture = Fixture::new();
            let result = fixture
                .gate
                .retain_snapshot_with(&fixture.lease, |temporary| {
                    std::fs::write(temporary, &fixture.bytes[..17])?;
                    anyhow::bail!("simulated interrupted snapshot publication")
                });
            assert!(result.is_err());
            assert!(!fixture.snapshot_path().exists());
            assert_eq!(std::fs::read(&fixture.path).unwrap(), fixture.bytes);
            let temporary = fixture.temporary_paths();
            assert_eq!(temporary.len(), 1);
            assert_eq!(std::fs::read(&temporary[0]).unwrap(), fixture.bytes[..17]);
            let snapshot = fixture.gate.retain_snapshot(&fixture.lease).unwrap();
            assert_eq!(std::fs::read(snapshot).unwrap(), fixture.bytes);
            assert_eq!(std::fs::read(&temporary[0]).unwrap(), fixture.bytes[..17]);
            assert_eq!(std::fs::read(&fixture.path).unwrap(), fixture.bytes);
        }

        #[test]
        fn snapshot_refuses_corrupt_or_unsafe_existing_names_without_overwriting() {
            for change in [
                "corrupt",
                "hardlink",
                "writable",
                "readable",
                "symlink",
                "fifo",
                "directory",
            ] {
                let fixture = Fixture::new();
                let snapshot = fixture.snapshot_path();
                let unrelated = fixture.root.path().join("unrelated-source.c");
                write_private(&unrelated, b"unrelated source bytes");
                match change {
                    "corrupt" => write_private(&snapshot, b"corrupt retained journal"),
                    "hardlink" => {
                        write_private(&snapshot, &fixture.bytes);
                        std::fs::hard_link(&snapshot, fixture.root.path().join("alias")).unwrap();
                    }
                    "writable" | "readable" => {
                        write_private(&snapshot, &fixture.bytes);
                        let mode = if change == "readable" { 0o644 } else { 0o666 };
                        std::fs::set_permissions(&snapshot, std::fs::Permissions::from_mode(mode))
                            .unwrap();
                    }
                    "symlink" => std::os::unix::fs::symlink(&unrelated, &snapshot).unwrap(),
                    "fifo" => assert!(
                        std::process::Command::new("mkfifo")
                            .arg(&snapshot)
                            .status()
                            .unwrap()
                            .success()
                    ),
                    "directory" => std::fs::create_dir(&snapshot).unwrap(),
                    _ => unreachable!(),
                }
                let inode = std::fs::symlink_metadata(&snapshot).unwrap().ino();
                assert!(
                    fixture.gate.retain_snapshot(&fixture.lease).is_err(),
                    "{change}"
                );
                assert_eq!(std::fs::symlink_metadata(&snapshot).unwrap().ino(), inode);
                if change == "corrupt" {
                    assert_eq!(
                        std::fs::read(&snapshot).unwrap(),
                        b"corrupt retained journal"
                    );
                }
                assert!(fixture.temporary_paths().is_empty());
                assert_eq!(std::fs::read(&fixture.path).unwrap(), fixture.bytes);
                assert_eq!(std::fs::read(unrelated).unwrap(), b"unrelated source bytes");
            }
        }

        #[test]
        fn snapshot_detects_namespace_and_current_epoch_changes_before_success() {
            for change in [
                "parent",
                "gate",
                "temporary",
                "temporary_hardlink",
                "current",
                "current_inode",
                "collision",
            ] {
                let fixture = Fixture::new();
                let original_parent = fixture.path.parent().unwrap();
                let preserved = fixture.root.path().join("preserved");
                let result = fixture
                    .gate
                    .retain_snapshot_with(&fixture.lease, |temporary| {
                        match change {
                            "parent" => {
                                std::fs::rename(original_parent, &preserved)?;
                                std::fs::create_dir(original_parent)?;
                                write_private(&fixture.path, b"replacement current journal");
                            }
                            "gate" => {
                                std::fs::rename(
                                    fixture.path.with_extension("recovery.lock"),
                                    &preserved,
                                )?;
                                write_private(
                                    &fixture.path.with_extension("recovery.lock"),
                                    b"replacement gate",
                                );
                            }
                            "temporary" => {
                                std::fs::rename(temporary, &preserved)?;
                                write_private(temporary, &fixture.bytes);
                            }
                            "temporary_hardlink" => std::fs::hard_link(temporary, &preserved)?,
                            "current" => std::fs::write(&fixture.path, b"changed current journal")?,
                            "current_inode" => {
                                std::fs::rename(&fixture.path, &preserved)?;
                                write_private(&fixture.path, &fixture.bytes);
                            }
                            "collision" => {
                                write_private(&fixture.snapshot_path(), b"competing snapshot bytes")
                            }
                            _ => unreachable!(),
                        }
                        Ok(())
                    });
                assert!(result.is_err(), "accepted {change}");
                match change {
                    "parent" => {
                        assert_eq!(
                            std::fs::read(preserved.join("lease.json")).unwrap(),
                            fixture.bytes
                        );
                        assert_eq!(
                            std::fs::read(&fixture.path).unwrap(),
                            b"replacement current journal"
                        );
                    }
                    "current" => assert_eq!(
                        std::fs::read(&fixture.path).unwrap(),
                        b"changed current journal"
                    ),
                    _ => assert_eq!(std::fs::read(&fixture.path).unwrap(), fixture.bytes),
                }
                if matches!(change, "temporary" | "temporary_hardlink" | "current_inode") {
                    assert_eq!(std::fs::read(&preserved).unwrap(), fixture.bytes);
                }
                if change == "collision" {
                    assert_eq!(
                        std::fs::read(fixture.snapshot_path()).unwrap(),
                        b"competing snapshot bytes"
                    );
                }
                if matches!(change, "current" | "current_inode") {
                    assert_eq!(
                        std::fs::read(fixture.snapshot_path()).unwrap(),
                        fixture.bytes
                    );
                }
            }
        }

        #[test]
        fn snapshot_reader_distinguishes_bound_and_legacy_evidence() {
            let fixture = Fixture::new();
            let legacy = CString::new(format!(
                "artifact-policy-{}.before",
                uuid::Uuid::new_v4().simple()
            ))
            .unwrap();
            write_private(
                &fixture
                    .path
                    .parent()
                    .unwrap()
                    .join(legacy.to_str().unwrap()),
                &fixture.bytes,
            );
            let observed =
                read_retained_snapshot_at(fixture.gate.directory().as_fd(), &legacy).unwrap();
            assert_eq!(observed.kind, RetainedSnapshotKind::LegacyArtifactPolicy);
            assert_eq!(observed.lease, fixture.lease);
            assert_eq!(
                observed.digest,
                blake3::hash(&fixture.bytes).to_hex().as_str()
            );
            for name in [
                c"artifact-policy-not-a-uuid.before",
                c"rchw-invalid.recovery-not-a-digest.before",
            ] {
                assert!(retained_snapshot_kind(name).is_some());
                write_private(
                    &fixture.path.parent().unwrap().join(name.to_str().unwrap()),
                    &fixture.bytes,
                );
                assert!(read_retained_snapshot_at(fixture.gate.directory().as_fd(), name).is_err());
            }
            assert!(retained_snapshot_kind(c"operator-note.before").is_none());
            assert!(retained_snapshot_kind(c"lease.json").is_none());
            assert!(retained_snapshot_kind(c".recovery-snapshot-leftover.tmp").is_none());
        }

        #[test]
        fn snapshot_reader_refuses_wrong_binding_schema_and_noncanonical_legacy_names() {
            for change in [
                "digest",
                "digest_case",
                "wrapper",
                "schema",
                "inner_identity",
                "legacy_spelling",
                "legacy_case",
            ] {
                let fixture = Fixture::new();
                let mut value: serde_json::Value = serde_json::from_slice(&fixture.bytes).unwrap();
                match change {
                    "wrapper" => {
                        value["identity"]["local_wrapper_id"] = serde_json::Value::String(
                            super::super::JobIdentity::new_local().local_wrapper_id,
                        )
                    }
                    "schema" => value["schema_version"] = 2.into(),
                    "inner_identity" => {
                        value["identity"]["local_wrapper_id"] = "rchw-not-a-uuid".into()
                    }
                    _ => {}
                }
                let bytes = serde_json::to_vec_pretty(&value).unwrap();
                let digest = blake3::hash(&bytes).to_hex().to_string();
                let name = match change {
                    "inner_identity" => {
                        format!("artifact-policy-{}.before", uuid::Uuid::new_v4().simple())
                    }
                    "legacy_spelling" => format!("artifact-policy-{}.before", uuid::Uuid::new_v4()),
                    "legacy_case" => {
                        "artifact-policy-AAAAAAAAAAAA4AAA8AAAAAAAAAAAAAAA.before".into()
                    }
                    _ => format!(
                        "{}.recovery-{}.before",
                        fixture.lease.identity.local_wrapper_id,
                        match change {
                            "digest" => "0".repeat(64),
                            "digest_case" => format!("A{}", &digest[1..]),
                            _ => digest,
                        }
                    ),
                };
                let path = fixture.path.parent().unwrap().join(&name);
                write_private(&path, &bytes);
                let inode = std::fs::metadata(&path).unwrap().ino();
                let name = CString::new(name).unwrap();
                assert!(retained_snapshot_kind(&name).is_some(), "{change}");
                assert!(
                    read_retained_snapshot_at(fixture.gate.directory().as_fd(), &name).is_err(),
                    "accepted {change}"
                );
                assert_eq!(std::fs::read(&path).unwrap(), bytes);
                assert_eq!(std::fs::metadata(path).unwrap().ino(), inode);
                assert_eq!(std::fs::read(&fixture.path).unwrap(), fixture.bytes);
            }
        }
    }
}

/// Mint a fresh, unique local wrapper id.
#[must_use]
pub fn new_local_wrapper_id() -> LocalWrapperId {
    format!("{LOCAL_WRAPPER_ID_PREFIX}{}", Uuid::new_v4())
}

/// The two-part identity of a job: the always-present local wrapper id and the
/// remote build id once admitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobIdentity {
    /// Local wrapper id, always present.
    pub local_wrapper_id: LocalWrapperId,
    /// Remote build id, present iff the daemon admitted the command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_build_id: Option<RemoteBuildId>,
}

impl JobIdentity {
    /// A brand-new identity for a command just intercepted by `rch exec`
    /// (no remote build id yet).
    #[must_use]
    pub fn new_local() -> Self {
        Self {
            local_wrapper_id: new_local_wrapper_id(),
            remote_build_id: None,
        }
    }

    /// Record the daemon-assigned remote build id at admission.
    pub fn admit(&mut self, remote_build_id: RemoteBuildId) {
        self.remote_build_id = Some(remote_build_id);
    }

    /// Whether the command was admitted (has a remote build id).
    #[must_use]
    pub fn is_admitted(&self) -> bool {
        self.remote_build_id.is_some()
    }
}

/// The five operator-/agent-facing lifecycle states a job can be correlated to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobLifecycleState {
    /// The wrapper ran but the command never received a remote build id — it
    /// was rejected/failed before admission (e.g. no admissible workers).
    FailedBeforeAdmission,
    /// Admitted and waiting for a worker slot.
    Queued,
    /// Admitted and actively executing on a worker.
    Running,
    /// Completed (success or failure) with a recorded exit.
    Finished,
    /// Admitted/started but its heartbeat went stale past the abandon
    /// threshold with no completion record — presumed dead.
    Abandoned,
}

impl JobLifecycleState {
    /// Stable lowercase token (matches the serde representation).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            JobLifecycleState::FailedBeforeAdmission => "failed_before_admission",
            JobLifecycleState::Queued => "queued",
            JobLifecycleState::Running => "running",
            JobLifecycleState::Finished => "finished",
            JobLifecycleState::Abandoned => "abandoned",
        }
    }

    /// Whether this is a terminal state (no further transitions expected).
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            JobLifecycleState::Finished
                | JobLifecycleState::Abandoned
                | JobLifecycleState::FailedBeforeAdmission
        )
    }
}

/// Observable signals used to correlate a job to a lifecycle state. Plain data
/// so the derivation is pure and unit-testable.
#[derive(Debug, Clone, Copy, Default)]
pub struct JobSignals {
    /// A remote build id was assigned (the daemon admitted the command).
    pub admitted: bool,
    /// A worker began executing the build.
    pub started: bool,
    /// A terminal completion/exit was recorded.
    pub completed: bool,
    /// The last heartbeat is older than the abandon threshold.
    pub heartbeat_stale: bool,
}

/// Correlate observable signals into the single lifecycle state.
///
/// Precedence (most-terminal wins): a recorded completion is `Finished` even if
/// a late heartbeat looks stale; a command with no remote build id is
/// `FailedBeforeAdmission`; an admitted job whose heartbeat went stale without
/// completing is `Abandoned`; a started job is `Running`; otherwise `Queued`.
#[must_use]
pub fn derive_job_lifecycle_state(signals: JobSignals) -> JobLifecycleState {
    if signals.completed {
        return JobLifecycleState::Finished;
    }
    if !signals.admitted {
        return JobLifecycleState::FailedBeforeAdmission;
    }
    if signals.heartbeat_stale {
        return JobLifecycleState::Abandoned;
    }
    if signals.started {
        return JobLifecycleState::Running;
    }
    JobLifecycleState::Queued
}

/// A correlated job record for `rch jobs --json`. Bundles the identity, the
/// derived lifecycle state, and the salient human/agent fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRecord {
    pub identity: JobIdentity,
    pub state: JobLifecycleState,
    /// The command line (or a fingerprint) this job ran.
    pub command: String,
    /// Worker the job was placed on, once admitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<String>,
    /// Exit code, once finished.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

/// Atomically persisted local evidence for one `rch exec` wrapper.
///
/// The client creates this record before contacting the daemon and rewrites the
/// same file as admission, progress, and completion are observed.  It is
/// deliberately an evidence record rather than a replay recipe: it contains a
/// one-way command fingerprint, never an argv string or environment values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableJobLease {
    /// Format version for forward-compatible on-disk readers.
    pub schema_version: u32,
    /// Stable local/remote correlation identity.
    pub identity: JobIdentity,
    /// PID of the wrapper process which owns this lease.
    pub wrapper_pid: u32,
    /// Linux `/proc/<pid>/stat` start tick, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_start_ticks: Option<u64>,
    /// Linux boot identifier, when available, to disambiguate PID reuse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_id: Option<String>,
    /// Native process birth identity. Older Linux journals use the two fields
    /// above; old macOS journals without this evidence remain unverified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_birth: Option<crate::process_identity::ProcessIdentity>,
    /// Current operator-facing lifecycle state.
    pub state: JobLifecycleState,
    /// Current remote pipeline phase or `admission` before a worker is selected.
    pub phase: String,
    /// Selected worker after daemon admission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<String>,
    /// Wall-clock heartbeat observation time in Unix milliseconds.
    pub heartbeat_unix_ms: u64,
    /// Whether this wrapper is in a strict remote-only proof lane.
    pub strict_remote: bool,
    /// Whether the wrapper may attempt the bounded daemon self-healing path.
    pub self_healing_enabled: bool,
    /// Irreversible fingerprint of the command; raw argv is never persisted.
    pub command_fingerprint: String,
    /// A terminal state is valid only after the daemon acknowledges release or
    /// completion.  A dead wrapper with this false must remain uncertain.
    pub terminal_acknowledged: bool,
    /// Validated retrieval-only recipe. Never contains command argv or environment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<serde_json::Value>,
    /// Observed command result, independent of artifact delivery and release.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

impl DurableJobLease {
    /// Create the pre-admission lease.  It stays nonterminal until the caller
    /// has concrete daemon evidence for the final transition.
    #[must_use]
    #[allow(clippy::too_many_arguments)] // Lease evidence is intentionally explicit so callers cannot omit an identity component.
    pub fn new(
        identity: JobIdentity,
        wrapper_pid: u32,
        process_start_ticks: Option<u64>,
        boot_id: Option<String>,
        heartbeat_unix_ms: u64,
        strict_remote: bool,
        self_healing_enabled: bool,
        command_fingerprint: String,
    ) -> Self {
        Self {
            schema_version: 1,
            identity,
            wrapper_pid,
            process_start_ticks,
            boot_id,
            process_birth: None,
            state: JobLifecycleState::Queued,
            phase: "admission".to_string(),
            worker_id: None,
            heartbeat_unix_ms,
            strict_remote,
            self_healing_enabled,
            command_fingerprint,
            terminal_acknowledged: false,
            recovery: None,
            exit_code: None,
        }
    }

    /// Prefer explicit native evidence. An invalid new field must never fall
    /// back to otherwise plausible legacy fields from a different owner.
    pub fn owner_identity(&self) -> Option<crate::process_identity::ProcessIdentity> {
        use crate::process_identity::{ProcessIdentity, ProcessStart};
        let identity = match &self.process_birth {
            Some(identity) => identity.clone(),
            None => ProcessIdentity {
                boot_id: self.boot_id.clone()?,
                start: ProcessStart::Linux {
                    ticks: self.process_start_ticks?,
                },
            },
        };
        identity.is_valid().then_some(identity)
    }

    /// Record an admission from the daemon.
    pub fn admit(&mut self, remote_build_id: u64, worker_id: String, heartbeat_unix_ms: u64) {
        self.identity.admit(remote_build_id);
        self.worker_id = Some(worker_id);
        self.state = JobLifecycleState::Running;
        self.phase = "sync_up".to_string();
        self.heartbeat_unix_ms = heartbeat_unix_ms;
    }

    /// Record an observed nonterminal phase transition.
    pub fn heartbeat(&mut self, phase: impl Into<String>, heartbeat_unix_ms: u64) {
        self.phase = phase.into();
        self.heartbeat_unix_ms = heartbeat_unix_ms;
    }

    /// Mark completion only after a daemon acknowledgement.
    pub fn acknowledge_terminal(&mut self, heartbeat_unix_ms: u64) {
        self.state = JobLifecycleState::Finished;
        self.phase = "finished".to_string();
        self.heartbeat_unix_ms = heartbeat_unix_ms;
        self.terminal_acknowledged = true;
    }
}

impl JobRecord {
    /// Build a record, deriving the lifecycle state from the identity +
    /// signals. `admitted` is taken from the identity so callers cannot pass a
    /// state inconsistent with the presence of a remote build id.
    #[must_use]
    pub fn correlate(
        identity: JobIdentity,
        command: impl Into<String>,
        worker_id: Option<String>,
        exit_code: Option<i32>,
        mut signals: JobSignals,
    ) -> Self {
        signals.admitted = identity.is_admitted();
        if exit_code.is_some() {
            signals.completed = true;
        }
        let state = derive_job_lifecycle_state(signals);
        Self {
            identity,
            state,
            command: command.into(),
            worker_id,
            exit_code,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn private_journal(path: &std::path::Path, bytes: &[u8]) {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn journal_gate_preserves_its_inode_across_exclusive_owners() {
        use std::os::unix::fs::MetadataExt;
        let directory = tempfile::Builder::new()
            .disable_cleanup(true)
            .tempdir()
            .unwrap();
        let path = directory.path().join("lease.json");
        private_journal(&path, b"original journal");
        let first = journal::JobJournalGate::try_acquire(&path)
            .unwrap()
            .unwrap();
        let inode = first.lock_metadata().unwrap().ino();
        assert!(
            journal::JobJournalGate::try_acquire(&path)
                .unwrap()
                .is_none()
        );
        drop(first);
        let next = journal::JobJournalGate::try_acquire(&path)
            .unwrap()
            .unwrap();
        assert_eq!(next.lock_metadata().unwrap().ino(), inode);
        next.verify().unwrap();
        assert_eq!(std::fs::read(path).unwrap(), b"original journal");
    }

    #[cfg(unix)]
    #[test]
    fn journal_reap_requires_the_exact_unchanged_regular_snapshot() {
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};
        for change in [
            "unchanged",
            "rewrite",
            "replace",
            "hardlink",
            "writable",
            "symlink",
            "fifo",
        ] {
            let directory = tempfile::Builder::new()
                .disable_cleanup(true)
                .tempdir()
                .unwrap();
            let path = directory.path().join("lease.json");
            let preserved = directory.path().join("preserved-journal");
            let unrelated = directory.path().join("unrelated-source.c");
            private_journal(&path, b"original journal");
            private_journal(&unrelated, b"unrelated retained source");
            let gate = journal::JobJournalGate::try_acquire(&path)
                .unwrap()
                .unwrap();
            let (snapshot, bytes) = gate.read_snapshot().unwrap();
            match change {
                "unchanged" => {}
                "rewrite" => std::fs::write(&path, b"updated journal").unwrap(),
                "replace" => {
                    std::fs::rename(&path, &preserved).unwrap();
                    private_journal(&path, &bytes);
                }
                "hardlink" => std::fs::hard_link(&path, &preserved).unwrap(),
                "writable" => {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap()
                }
                "symlink" => {
                    std::fs::rename(&path, &preserved).unwrap();
                    std::os::unix::fs::symlink(&unrelated, &path).unwrap();
                }
                "fifo" => {
                    std::fs::rename(&path, &preserved).unwrap();
                    assert!(
                        std::process::Command::new("mkfifo")
                            .arg(&path)
                            .status()
                            .unwrap()
                            .success()
                    );
                }
                _ => unreachable!(),
            }
            let result = gate.remove_journal_if_unchanged(&snapshot, &bytes);
            if change == "unchanged" {
                assert!(result.unwrap());
                assert!(!path.exists());
            } else {
                assert!(result.is_err(), "accepted changed journal: {change}");
                match change {
                    "rewrite" => assert_eq!(std::fs::read(&path).unwrap(), b"updated journal"),
                    "symlink" => assert!(
                        std::fs::symlink_metadata(&path)
                            .unwrap()
                            .file_type()
                            .is_symlink()
                    ),
                    "fifo" => assert!(
                        std::fs::symlink_metadata(&path)
                            .unwrap()
                            .file_type()
                            .is_fifo()
                    ),
                    _ => assert_eq!(std::fs::read(&path).unwrap(), bytes),
                }
            }
            if matches!(change, "replace" | "hardlink" | "symlink" | "fifo") {
                assert_eq!(std::fs::read(preserved).unwrap(), bytes);
            }
            assert!(path.with_extension("recovery.lock").is_file());
            assert_eq!(
                std::fs::read(unrelated).unwrap(),
                b"unrelated retained source"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn journal_reap_rejects_replaced_parent_and_gate_namespaces() {
        use std::os::unix::fs::MetadataExt;
        for change in ["parent", "gate"] {
            let directory = tempfile::Builder::new()
                .disable_cleanup(true)
                .tempdir()
                .unwrap();
            let jobs = directory.path().join("jobs");
            std::fs::create_dir(&jobs).unwrap();
            let path = jobs.join("lease.json");
            private_journal(&path, b"original journal");
            let gate = journal::JobJournalGate::try_acquire(&path)
                .unwrap()
                .unwrap();
            let gate_inode = gate.lock_metadata().unwrap().ino();
            let (snapshot, bytes) = gate.read_snapshot().unwrap();
            let preserved = directory.path().join("preserved");
            if change == "parent" {
                std::fs::rename(&jobs, &preserved).unwrap();
                std::fs::create_dir(&jobs).unwrap();
                private_journal(&path, b"replacement journal");
                private_journal(&path.with_extension("recovery.lock"), b"replacement gate");
            } else {
                std::fs::rename(path.with_extension("recovery.lock"), &preserved).unwrap();
                private_journal(&path.with_extension("recovery.lock"), b"replacement gate");
            }
            assert!(gate.remove_journal_if_unchanged(&snapshot, &bytes).is_err());
            if change == "parent" {
                assert_eq!(std::fs::read(preserved.join("lease.json")).unwrap(), bytes);
                assert_eq!(std::fs::read(&path).unwrap(), b"replacement journal");
                assert_eq!(
                    std::fs::metadata(preserved.join("lease.recovery.lock"))
                        .unwrap()
                        .ino(),
                    gate_inode
                );
            } else {
                assert_eq!(std::fs::read(&path).unwrap(), bytes);
                assert_eq!(std::fs::metadata(&preserved).unwrap().ino(), gate_inode);
            }
            assert_eq!(
                std::fs::read(path.with_extension("recovery.lock")).unwrap(),
                b"replacement gate"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn journal_observation_refuses_symlink_fifo_and_redirected_parent() {
        let directory = tempfile::Builder::new()
            .disable_cleanup(true)
            .tempdir()
            .unwrap();
        let real = directory.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let path = real.join("lease.json");
        private_journal(&path, b"original journal");
        let link = directory.path().join("linked.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(journal::read_lease_bytes(&link).is_err());
        let fifo = directory.path().join("fifo.json");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        assert!(journal::read_lease_bytes(&fifo).is_err());
        let redirected = directory.path().join("redirected");
        std::os::unix::fs::symlink(&real, &redirected).unwrap();
        assert!(journal::read_lease_bytes(&redirected.join("lease.json")).is_err());
        assert_eq!(
            journal::read_lease_bytes(&path).unwrap(),
            b"original journal"
        );
    }

    #[test]
    fn local_wrapper_ids_are_prefixed_and_unique() {
        let a = new_local_wrapper_id();
        let b = new_local_wrapper_id();
        assert!(a.starts_with(LOCAL_WRAPPER_ID_PREFIX));
        assert_ne!(a, b, "wrapper ids must be unique");
    }

    #[test]
    fn default_job_lease_directory_has_the_stable_leaf() {
        assert_eq!(
            default_job_lease_directory()
                .file_name()
                .and_then(|name| name.to_str()),
            Some("job-leases")
        );
    }

    #[test]
    fn identity_admit_sets_remote_build_id() {
        let mut id = JobIdentity::new_local();
        assert!(!id.is_admitted());
        assert!(id.remote_build_id.is_none());
        id.admit(42);
        assert!(id.is_admitted());
        assert_eq!(id.remote_build_id, Some(42));
    }

    #[test]
    fn lifecycle_state_matrix() {
        // Not admitted => failed before admission (regardless of other signals).
        assert_eq!(
            derive_job_lifecycle_state(JobSignals {
                admitted: false,
                started: true,
                heartbeat_stale: true,
                completed: false,
            }),
            JobLifecycleState::FailedBeforeAdmission
        );
        // Completed always wins, even over a stale heartbeat.
        assert_eq!(
            derive_job_lifecycle_state(JobSignals {
                admitted: true,
                started: true,
                heartbeat_stale: true,
                completed: true,
            }),
            JobLifecycleState::Finished
        );
        // Admitted + stale heartbeat + not completed => abandoned.
        assert_eq!(
            derive_job_lifecycle_state(JobSignals {
                admitted: true,
                started: true,
                heartbeat_stale: true,
                completed: false,
            }),
            JobLifecycleState::Abandoned
        );
        // Admitted + started + fresh => running.
        assert_eq!(
            derive_job_lifecycle_state(JobSignals {
                admitted: true,
                started: true,
                heartbeat_stale: false,
                completed: false,
            }),
            JobLifecycleState::Running
        );
        // Admitted + not started => queued.
        assert_eq!(
            derive_job_lifecycle_state(JobSignals {
                admitted: true,
                started: false,
                heartbeat_stale: false,
                completed: false,
            }),
            JobLifecycleState::Queued
        );
    }

    #[test]
    fn terminal_states_classified() {
        assert!(JobLifecycleState::Finished.is_terminal());
        assert!(JobLifecycleState::Abandoned.is_terminal());
        assert!(JobLifecycleState::FailedBeforeAdmission.is_terminal());
        assert!(!JobLifecycleState::Queued.is_terminal());
        assert!(!JobLifecycleState::Running.is_terminal());
    }

    #[test]
    fn correlate_uses_identity_admission_and_exit_code() {
        // Un-admitted identity => FailedBeforeAdmission even if caller passed
        // optimistic signals.
        let unadmitted = JobIdentity::new_local();
        let rec = JobRecord::correlate(
            unadmitted,
            "cargo build",
            None,
            None,
            JobSignals {
                admitted: true,
                started: true,
                ..JobSignals::default()
            },
        );
        assert_eq!(rec.state, JobLifecycleState::FailedBeforeAdmission);

        // Admitted + exit code => Finished, with the exit recorded.
        let mut admitted = JobIdentity::new_local();
        admitted.admit(7);
        let rec = JobRecord::correlate(
            admitted,
            "cargo test",
            Some("worker-a".to_string()),
            Some(0),
            JobSignals::default(),
        );
        assert_eq!(rec.state, JobLifecycleState::Finished);
        assert_eq!(rec.exit_code, Some(0));
        assert_eq!(rec.worker_id.as_deref(), Some("worker-a"));
    }

    #[test]
    fn identity_serde_omits_absent_remote_build_id() {
        let id = JobIdentity::new_local();
        let json = serde_json::to_string(&id).expect("serialize");
        assert!(!json.contains("remote_build_id"), "None must be omitted");
        let back: JobIdentity = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, id);
    }

    #[test]
    fn job_record_serializes_state_token() {
        let mut id = JobIdentity::new_local();
        id.admit(99);
        let rec = JobRecord::correlate(
            id,
            "cargo check",
            Some("w1".to_string()),
            None,
            JobSignals {
                started: false,
                ..JobSignals::default()
            },
        );
        let json = serde_json::to_string(&rec).expect("serialize");
        assert!(json.contains("\"state\":\"queued\""));
        assert!(json.contains("rchw-"));
    }

    #[test]
    fn durable_lease_requires_acknowledgement_for_terminal_state() {
        let mut lease = DurableJobLease::new(
            JobIdentity::new_local(),
            42,
            Some(99),
            Some("boot-a".to_string()),
            1,
            true,
            false,
            "blake3:abc".to_string(),
        );
        assert_eq!(lease.state, JobLifecycleState::Queued);
        assert!(!lease.terminal_acknowledged);

        lease.admit(7, "worker-a".to_string(), 2);
        lease.heartbeat("execute", 3);
        assert_eq!(lease.identity.remote_build_id, Some(7));
        assert_eq!(lease.phase, "execute");
        assert!(!lease.terminal_acknowledged);

        lease.acknowledge_terminal(4);
        assert_eq!(lease.state, JobLifecycleState::Finished);
        assert!(lease.terminal_acknowledged);
    }

    #[test]
    fn durable_lease_serialization_has_fingerprint_not_command() {
        let lease = DurableJobLease::new(
            JobIdentity::new_local(),
            42,
            None,
            None,
            1,
            false,
            true,
            "blake3:abc".to_string(),
        );
        let json = serde_json::to_string(&lease).expect("serialize");
        assert!(json.contains("command_fingerprint"));
        assert!(!json.contains("command\":"));
    }

    #[test]
    fn legacy_linux_and_native_darwin_leases_keep_precise_owner_identity() {
        use crate::process_identity::{ProcessIdentity, ProcessStart};
        let boot = "3f1c2a9e-5b7d-4e2a-9c1f-0a1b2c3d4e5f";
        let mut lease = DurableJobLease::new(
            JobIdentity::new_local(),
            42,
            Some(99),
            Some(boot.into()),
            1,
            false,
            true,
            "blake3:abc".into(),
        );
        let bytes = serde_json::to_vec(&lease).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("process_birth"));
        let legacy: DurableJobLease = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            legacy.owner_identity().unwrap().start,
            ProcessStart::Linux { ticks: 99 }
        );

        lease.process_birth =
            ProcessIdentity::from_record(&format!("{boot}:darwin:1791280000:123456"));
        let restored: DurableJobLease =
            serde_json::from_slice(&serde_json::to_vec(&lease).unwrap()).unwrap();
        assert_eq!(restored.owner_identity(), lease.process_birth);
        assert_ne!(restored.owner_identity(), legacy.owner_identity());
        lease.process_birth.as_mut().unwrap().boot_id = "not-a-boot".into();
        assert!(
            lease.owner_identity().is_none(),
            "invalid explicit evidence must not fall back to valid legacy fields"
        );
    }
}
