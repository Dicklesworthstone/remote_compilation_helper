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
    use anyhow::{Context, Result, ensure};
    use rustix::fs::{Mode, OFlags};
    use std::ffi::{CStr, CString};
    use std::fs::{File, Metadata};
    use std::io::Read;
    use std::os::fd::AsFd;
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

    fn read_regular_at(directory: &File, name: &CStr) -> Result<(File, Vec<u8>)> {
        let mut file = File::from(rustix::fs::openat(
            directory.as_fd(),
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
        let (_, bytes) = read_regular_at(&directory, &name)?;
        verify_directory(&directory, parent)?;
        Ok(bytes)
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
            let snapshot = read_regular_at(&self.directory, &self.journal_name)?;
            self.verify()?;
            Ok(snapshot)
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
            let (named_file, bytes) = read_regular_at(&self.directory, &self.journal_name)?;
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
