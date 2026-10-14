//! Exclusive detached recovery of one durable wrapper, never command replay.
//!
//! Output-root locks cover publication only. A recovery command must also own
//! the journal across worker probes, publication and source release, and must
//! reload it AFTER taking that ownership. Otherwise two independently loaded
//! writers can roll back each other's durable retirement or failure evidence.

use super::*;
use std::future::Future;
use std::os::unix::fs::MetadataExt;

#[path = "recovery_artifact_policy.rs"]
mod artifact_policy;

/// The inode stays on disk. Unlinking it on release would let a waiting opener
/// lock the old inode while a new recovery command locks its replacement.
pub(in crate::hook) struct RecoveryOwnership {
    _gate: File,
    directory: File,
    parent: PathBuf,
    gate_name: std::ffi::CString,
    journal_name: std::ffi::CString,
}

impl RecoveryOwnership {
    /// Both the persistent gate and journal must still name the held directory.
    /// Reads/writes use that descriptor even if a rename races this check.
    pub(in crate::hook) fn verify(&self) -> anyhow::Result<()> {
        use rustix::fs::{Mode, OFlags};
        use std::os::fd::AsFd;

        let held_directory = self.directory.metadata()?;
        let named_directory = std::fs::symlink_metadata(&self.parent)?;
        anyhow::ensure!(
            named_directory.is_dir()
                && held_directory.dev() == named_directory.dev()
                && held_directory.ino() == named_directory.ino(),
            "recovery journal directory changed; retry the retained same wrapper"
        );
        let named_gate = File::from(rustix::fs::openat(
            self.directory.as_fd(),
            self.gate_name.as_c_str(),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY,
            Mode::empty(),
        )?);
        let held = self._gate.metadata()?;
        let named = named_gate.metadata()?;
        anyhow::ensure!(
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

    pub(in crate::hook) fn read(&self, wrapper_id: &str) -> anyhow::Result<DurableJobLease> {
        use std::os::fd::AsFd;
        self.verify()?;
        let bytes = crate::state::primitives::read_regular_file_at(
            self.directory.as_fd(),
            &self.journal_name,
        )?;
        self.verify()?;
        DurableLeaseWriter::decode_journal(&bytes, wrapper_id)
    }

    /// The first lease must never replace an existing wrapper's evidence.
    /// Readers can refuse an incomplete initial file; daemon admission starts
    /// only after this write and its held directory have been synchronized.
    /// An initialization failure retains its exact partial bytes, too.
    pub(in crate::hook) fn initialize(&self, bytes: &[u8]) -> anyhow::Result<()> {
        use rustix::fs::{Mode, OFlags};
        use std::io::Write;
        use std::os::fd::AsFd;

        self.verify()?;
        let mut file = File::from(rustix::fs::openat(
            self.directory.as_fd(),
            self.journal_name.as_c_str(),
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        )?);
        file.write_all(bytes)?;
        file.sync_all()?;
        self.finish_initialization(&file, bytes)
    }

    fn finish_initialization(&self, file: &File, expected: &[u8]) -> anyhow::Result<()> {
        self.verify()?;
        self.require_named_file(file, &self.journal_name)?;
        crate::state::primitives::verify_atomic_write_bytes(file, expected)
            .context("verify initial journal bytes before admission")?;
        self.directory
            .sync_all()
            .context("sync initial held job journal directory before admission")?;
        self.verify()?;
        self.require_named_file(file, &self.journal_name)?;
        crate::state::primitives::verify_atomic_write_bytes(file, expected)
            .context("verify synchronized initial journal bytes before admission")
    }

    pub(in crate::hook) fn publish(&self, bytes: &[u8]) -> anyhow::Result<()> {
        use rustix::fs::{Mode, OFlags};
        use std::os::fd::AsFd;

        self.verify()?;
        // Validate prospective success before creating even a journal temp.
        // The caller's cached lease may be locked while publishing, so inspect
        // these exact serialized bytes, not a snapshot from the writer.
        let prospective: DurableJobLease =
            serde_json::from_slice(bytes).context("invalid prospective recovery journal")?;
        super::recovery_completion::validate_recorded_delivery(&prospective)?;
        // An exclusive fresh name cannot truncate an existing receipt. A failed
        // publication retains its temporary bytes for diagnosis, never cleanup.
        let temporary =
            std::ffi::CString::new(format!(".recovery-{}.tmp", uuid::Uuid::new_v4().simple(),))?;
        let mut file = File::from(rustix::fs::openat(
            self.directory.as_fd(),
            temporary.as_c_str(),
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        )?);
        use std::io::Write;
        file.write_all(bytes)?;
        file.sync_all()?;
        self.publish_temporary(&file, &temporary, bytes)
    }

    fn require_named_file(&self, held: &File, name: &std::ffi::CStr) -> anyhow::Result<()> {
        use rustix::fs::{Mode, OFlags};
        use std::os::fd::AsFd;

        let named = File::from(rustix::fs::openat(
            self.directory.as_fd(),
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY,
            Mode::empty(),
        )?);
        let held = held.metadata()?;
        let named = named.metadata()?;
        anyhow::ensure!(
            held.is_file()
                && named.is_file()
                && held.dev() == named.dev()
                && held.ino() == named.ino()
                && held.nlink() == 1
                && named.nlink() == 1,
            "recovery publication file changed; committed bytes are unverified"
        );
        Ok(())
    }

    fn publish_temporary(
        &self,
        file: &File,
        temporary: &std::ffi::CStr,
        expected: &[u8],
    ) -> anyhow::Result<()> {
        use std::os::fd::AsFd;

        self.verify()?;
        self.require_named_file(file, temporary)?;
        crate::state::primitives::verify_atomic_write_bytes(file, expected)
            .context("verify recovery journal bytes before publication")?;
        rustix::fs::renameat(
            self.directory.as_fd(),
            temporary,
            self.directory.as_fd(),
            self.journal_name.as_c_str(),
        )?;
        self.require_named_file(file, &self.journal_name)?;
        self.directory
            .sync_all()
            .context("sync held recovery journal directory before advancing ownership")?;
        self.verify()?;
        self.require_named_file(file, &self.journal_name)?;
        crate::state::primitives::verify_atomic_write_bytes(file, expected)
            .context("verify synchronized recovery journal bytes before acknowledgment")
    }
}

pub(in crate::hook) fn acquire_gate(lease_path: &Path) -> anyhow::Result<RecoveryOwnership> {
    use rustix::fs::{Mode, OFlags};
    use std::os::fd::AsFd;
    use std::os::unix::ffi::OsStrExt;

    let path = lease_path.with_extension("recovery.lock");
    let parent = path.parent().context("recovery lock has no parent")?;
    let name = std::ffi::CString::new(
        path.file_name()
            .context("recovery lock has no name")?
            .as_bytes(),
    )?;
    let directory = File::from(rustix::fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )?);
    // Gate acquisition is also used by the synchronous live constructor.
    // It must not allocate a Tokio socket or require a running reactor.
    let uid = rustix::process::geteuid().as_raw();
    let safe = |metadata: &std::fs::Metadata| {
        metadata.file_type().is_file()
            && metadata.uid() == uid
            && metadata.nlink() == 1
            && metadata.mode() & 0o077 == 0
    };
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) => anyhow::ensure!(safe(&metadata), "unsafe recovery lock file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    // A replaced parent cannot redirect creation. The leaf is never followed
    // or truncated, and the persistent inode remains the cross-recovery gate.
    let flags = OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY;
    let gate = File::from(rustix::fs::openat(
        directory.as_fd(),
        name.as_c_str(),
        OFlags::RDWR | OFlags::CREATE | flags,
        Mode::RUSR | Mode::WUSR,
    )?);
    anyhow::ensure!(safe(&gate.metadata()?), "unsafe recovery lock file");
    let held = gate.metadata()?;
    let named_gate = File::from(rustix::fs::openat(
        directory.as_fd(),
        name.as_c_str(),
        OFlags::RDONLY | flags,
        Mode::empty(),
    )?);
    let named = named_gate.metadata()?;
    let held_directory = directory.metadata()?;
    let named_directory = std::fs::symlink_metadata(parent)?;
    anyhow::ensure!(
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
        Err(std::fs::TryLockError::WouldBlock) => return Err(JobJournalBusy.into()),
        Err(std::fs::TryLockError::Error(error)) => {
            return Err(error).context("cannot inspect exclusive job journal ownership");
        }
    }
    let ownership = RecoveryOwnership {
        _gate: gate,
        directory,
        parent: parent.to_owned(),
        gate_name: name,
        journal_name: std::ffi::CString::new(
            lease_path
                .file_name()
                .context("journal has no name")?
                .as_bytes(),
        )?,
    };
    ownership.verify()?;
    Ok(ownership)
}

fn validate_same_owner(observed: &DurableJobLease, latest: &DurableJobLease) -> anyhow::Result<()> {
    anyhow::ensure!(
        observed.schema_version == 1
            && latest.schema_version == 1
            && observed.identity == latest.identity
            && observed.worker_id == latest.worker_id
            && observed.wrapper_pid == latest.wrapper_pid
            && observed.process_start_ticks == latest.process_start_ticks
            && observed.boot_id == latest.boot_id
            && observed.process_birth == latest.process_birth
            && observed.command_fingerprint == latest.command_fingerprint,
        "durable job identity changed before recovery; reload the same wrapper, never replay"
    );
    Ok(())
}

/// Native inspection can prove PID reuse, including Darwin births within one
/// second. Unknown evidence is never permission to take over.
fn native_owner_absent(lease: &DurableJobLease) -> Option<bool> {
    use rch_common::process_identity::{OwnerPresence, owner_presence};
    match owner_presence(lease.wrapper_pid, lease.owner_identity().as_ref()) {
        OwnerPresence::Live => Some(false),
        OwnerPresence::Absent => Some(true),
        OwnerPresence::Unknown => None,
    }
}

fn absent_from_process_list(bytes: &[u8], owner: u32, observer: u32) -> anyhow::Result<bool> {
    anyhow::ensure!(bytes.ends_with(b"\n"), "incomplete process listing");
    let text = std::str::from_utf8(bytes).context("process listing is not UTF-8")?;
    let mut seen = std::collections::BTreeSet::new();
    for line in text.lines() {
        let pid = line.trim();
        anyhow::ensure!(
            !pid.is_empty() && pid.bytes().all(|byte| byte.is_ascii_digit()),
            "malformed process listing"
        );
        let pid = pid.parse::<u32>()?;
        anyhow::ensure!(
            pid > 0 && seen.insert(pid),
            "invalid or duplicate process id"
        );
    }
    anyhow::ensure!(
        seen.contains(&observer),
        "process listing omitted the recovery process"
    );
    Ok(!seen.contains(&owner))
}

async fn owner_is_absent(lease: &DurableJobLease) -> anyhow::Result<bool> {
    if lease.wrapper_pid <= 1 || lease.wrapper_pid == std::process::id() {
        return Ok(false);
    }
    if let Some(absent) = native_owner_absent(lease) {
        return Ok(absent);
    }
    if cfg!(any(target_os = "linux", target_os = "macos")) {
        // Native inspection already recognizes a genuinely absent PID without
        // a birth marker. Unknown must stay unknown: ps can expose the same
        // foreign procfs view and a coincidental numeric observer PID cannot
        // prove that the listing is in our signal namespace.
        return Ok(false);
    }
    // Other Unix platforms retain a complete listing as absence evidence.
    // A present/reused PID stays conservative without a native birth marker.
    // An empty, failed, truncated or malformed listing never authorizes work.
    let mut child = tokio::process::Command::new("/bin/ps")
        .args(["-A", "-o", "pid="])
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("inspect original wrapper before detached recovery")?;
    let stdout = child
        .stdout
        .take()
        .context("process listing lacks stdout")?;
    let stderr = child
        .stderr
        .take()
        .context("process listing lacks stderr")?;
    let inspection = async {
        let (stdout, stderr) = tokio::try_join!(
            crate::transfer::read_bounded_output_stream(stdout, 8 * 1024 * 1024),
            crate::transfer::read_bounded_output_stream(stderr, 64 * 1024),
        )?;
        let status = child.wait().await?;
        anyhow::ensure!(
            status.success() && stderr.is_empty(),
            "process inspection failed; original wrapper absence is unverified"
        );
        absent_from_process_list(&stdout, lease.wrapper_pid, std::process::id())
    };
    tokio::time::timeout(Duration::from_secs(3), inspection)
        .await
        .context("original wrapper inspection timed out; no recovery started")?
}

pub(in crate::hook) async fn claim(
    writer: &DurableLeaseWriter,
) -> anyhow::Result<DurableLeaseWriter> {
    let owned = claim_with(writer, |lease| async move { owner_is_absent(&lease).await }).await?;
    artifact_policy::apply_from_environment(&owned)?;
    Ok(owned)
}

async fn claim_with<F, Fut>(
    writer: &DurableLeaseWriter,
    inspect: F,
) -> anyhow::Result<DurableLeaseWriter>
where
    F: FnOnce(DurableJobLease) -> Fut,
    Fut: Future<Output = anyhow::Result<bool>>,
{
    let observed = writer.snapshot();
    anyhow::ensure!(
        writer.recovery_ownership.is_none(),
        "recovery writer is already owned"
    );
    let ownership = acquire_gate(&writer.path)?;
    let read = || -> anyhow::Result<DurableJobLease> {
        ownership.read(&observed.identity.local_wrapper_id)
    };
    let latest = read()?;
    validate_same_owner(&observed, &latest)?;
    // A legacy premature `returned = 0` must not reach source retirement or
    // the acknowledged shortcut. This is read-only and precedes every peer
    // probe and artifact-policy/config mutation under the recovered owner.
    super::recovery_completion::validate_recorded_delivery(&latest)?;
    if !latest.terminal_acknowledged {
        anyhow::ensure!(
            inspect(latest.clone()).await?,
            "original wrapper is still present or unverified; use jobs attach or retry after it exits; no recovery started"
        );
    }
    // The owner may have persisted one last update while we inspected it.
    // Refuse rather than copying an obsolete snapshot over its final evidence.
    anyhow::ensure!(
        read()? == latest,
        "job journal changed during owner inspection; retry with its latest evidence"
    );
    *writer
        .lease
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = latest;
    let mut bound = writer.clone();
    bound.recovery_ownership = Some(Arc::new(ownership));
    Ok(bound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::{CompilationKind, TransferConfig, WorkerConfig, WorkerId};
    use std::cell::Cell;

    #[test]
    fn live_journal_gate_survives_clones_and_loaded_cancellation_requires_current_bytes() {
        // No Tokio runtime: the live constructor and cancellation fencing are
        // synchronous. Retain every fixture, including setup failures.
        let directory = tempfile::Builder::new()
            .disable_cleanup(true)
            .tempdir()
            .unwrap();
        let root = directory.path().join("new-journal-directory");
        let writer = DurableLeaseWriter::create_in(&root, "cargo build", true, false).unwrap();
        let path = writer.path.clone();
        let wrapper = writer.wrapper_id();
        let gate = path.with_extension("recovery.lock");
        let gate_inode = std::fs::metadata(&gate).unwrap().ino();
        let mut loaded = DurableLeaseWriter {
            path: path.clone(),
            lease: Arc::new(Mutex::new(
                DurableLeaseWriter::read_journal(&path, &wrapper).unwrap(),
            )),
            recovery_ownership: None,
        };
        let initial = std::fs::read(&path).unwrap();
        assert_eq!(loaded.snapshot(), writer.snapshot());
        assert!(acquire_gate(&path).is_err());
        assert!(!loaded.confirm_selection_cancelled().unwrap());
        assert!(!loaded.snapshot().terminal_acknowledged);
        assert_eq!(std::fs::read(&path).unwrap(), initial);
        let clone = writer.clone();
        drop(writer);
        assert!(acquire_gate(&path).is_err());
        clone.heartbeat("queued").unwrap();
        let latest = std::fs::read(&path).unwrap();
        assert_ne!(latest, initial);
        assert_eq!(
            DurableLeaseWriter::read_journal(&path, &wrapper).unwrap(),
            clone.snapshot()
        );
        drop(clone);
        // The gate is free now, but the independently cached lease is stale.
        assert!(loaded.confirm_selection_cancelled().is_err());
        assert_eq!(std::fs::read(&path).unwrap(), latest);
        assert!(!loaded.snapshot().terminal_acknowledged);
        loaded.lease = Arc::new(Mutex::new(
            DurableLeaseWriter::read_journal(&path, &wrapper).unwrap(),
        ));
        // This exercises publication of an assumed validated daemon no-start
        // receipt, not a real daemon cancellation or compiler/SDK observation.
        assert!(loaded.confirm_selection_cancelled().unwrap());
        let committed = DurableLeaseWriter::read_journal(&path, &wrapper).unwrap();
        assert_eq!(committed, loaded.snapshot());
        assert!(committed.terminal_acknowledged);
        assert_eq!(committed.exit_code, Some(130));
        assert_eq!(std::fs::metadata(&gate).unwrap().ino(), gate_inode);
        let _ownership = acquire_gate(&path).unwrap();
    }

    #[test]
    fn initial_journal_publication_preserves_occupied_names() {
        use std::io::Write;
        let directory = tempfile::Builder::new()
            .disable_cleanup(true)
            .tempdir()
            .unwrap();
        let path = directory.path().join("occupied-wrapper.json");
        let original = b"previous wrapper's retained journal";
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(original).unwrap();
        file.sync_all().unwrap();
        let ownership = acquire_gate(&path).unwrap();
        assert!(ownership.initialize(b"replacement refused").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert!(path.with_extension("recovery.lock").is_file());
    }

    #[test]
    fn owned_journal_bytes_are_bound_before_initial_admission_and_republication() {
        use std::io::{Seek, Write};
        use std::os::unix::fs::{FileExt, OpenOptionsExt};

        for initial in [true, false] {
            for change in ["unchanged", "rewrite", "growth"] {
                let directory = tempfile::Builder::new()
                    .disable_cleanup(true)
                    .tempdir()
                    .unwrap();
                let path = directory.path().join("lease.json");
                let ownership = acquire_gate(&path).unwrap();
                let gate_inode = ownership._gate.metadata().unwrap().ino();
                let mut lease = DurableJobLease::new(
                    JobIdentity::new_local(),
                    12345,
                    None,
                    None,
                    0,
                    true,
                    false,
                    "journal-byte-fixture".into(),
                );
                let original = serde_json::to_vec_pretty(&lease).unwrap();
                if !initial {
                    ownership.initialize(&original).unwrap();
                }
                lease.heartbeat("prepared", now_unix_ms());
                let expected = serde_json::to_vec_pretty(&lease).unwrap();
                let temporary = if initial {
                    path.clone()
                } else {
                    directory.path().join(".prepared-journal.tmp")
                };
                let mut held = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&temporary)
                    .unwrap();
                held.write_all(&expected).unwrap();
                held.sync_all().unwrap();
                let before = held.metadata().unwrap();
                let cursor = held.stream_position().unwrap();
                crate::state::primitives::verify_atomic_write_bytes(&held, &expected).unwrap();
                assert_eq!(held.stream_position().unwrap(), cursor);
                let mut retained = expected.clone();
                match change {
                    "rewrite" => {
                        assert_eq!(held.write_at(b"X", 0).unwrap(), 1);
                        retained[0] = b'X';
                    }
                    "growth" => {
                        let extra = b"retained growth";
                        assert_eq!(
                            held.write_at(extra, expected.len() as u64).unwrap(),
                            extra.len()
                        );
                        retained.extend_from_slice(extra);
                    }
                    "unchanged" => {}
                    _ => unreachable!(),
                }
                held.sync_all().unwrap();
                let after = held.metadata().unwrap();
                assert_eq!(before.ino(), after.ino());
                assert_eq!(before.dev(), after.dev());
                assert_eq!(before.nlink(), after.nlink());
                assert_eq!(before.mode(), after.mode());
                let result = if initial {
                    // This is the production initialize tail, after exclusive
                    // creation/write/sync, with the real name and gate intact.
                    ownership.finish_initialization(&held, &expected)
                } else {
                    // Exercise the actual rename/sync publisher, not a mock.
                    ownership.publish_temporary(&held, c".prepared-journal.tmp", &expected)
                };
                if change == "unchanged" {
                    result.unwrap();
                    assert_eq!(std::fs::read(&path).unwrap(), expected);
                    assert_eq!(std::fs::metadata(&path).unwrap().ino(), before.ino());
                    assert_eq!(
                        ownership.read(&lease.identity.local_wrapper_id).unwrap(),
                        lease
                    );
                } else {
                    let error = result.unwrap_err();
                    assert!(format!("{error:#}").contains("atomic write"));
                    assert_eq!(std::fs::read(&temporary).unwrap(), retained);
                    if !initial {
                        assert_eq!(std::fs::read(&path).unwrap(), original);
                    }
                }
                assert_eq!(held.stream_position().unwrap(), cursor);
                if initial || change != "unchanged" {
                    assert_eq!(std::fs::metadata(&temporary).unwrap().ino(), before.ino());
                } else {
                    assert_eq!(
                        std::fs::symlink_metadata(&temporary).unwrap_err().kind(),
                        std::io::ErrorKind::NotFound
                    );
                }
                assert_eq!(ownership._gate.metadata().unwrap().ino(), gate_inode);
                ownership.verify().unwrap();
            }
        }
    }

    #[test]
    fn live_owned_journal_publication_matches_the_installed_lease() {
        let directory = tempfile::Builder::new()
            .disable_cleanup(true)
            .tempdir()
            .unwrap();
        let writer =
            DurableLeaseWriter::create_in(directory.path(), "cargo build", true, false).unwrap();
        assert!(writer.recovery_ownership.is_some());
        let wrapper = writer.wrapper_id();
        assert_eq!(
            DurableLeaseWriter::read_journal(&writer.path, &wrapper).unwrap(),
            writer.snapshot()
        );
        writer.heartbeat("queued").unwrap();
        assert_eq!(
            DurableLeaseWriter::read_journal(&writer.path, &wrapper).unwrap(),
            writer.snapshot()
        );
    }

    fn fixture() -> (tempfile::TempDir, DurableLeaseWriter) {
        let directory = tempfile::tempdir().unwrap();
        let mut lease = DurableJobLease::new(
            JobIdentity::new_local(),
            12345,
            None,
            None,
            0,
            true,
            false,
            "command".into(),
        );
        lease.admit(42, "worker".into(), 1);
        let writer = DurableLeaseWriter {
            path: directory.path().join("lease.json"),
            lease: Arc::new(Mutex::new(lease)),
            recovery_ownership: None,
        };
        writer.persist().unwrap();
        (directory, writer)
    }

    fn independent_writer(writer: &DurableLeaseWriter) -> DurableLeaseWriter {
        DurableLeaseWriter {
            path: writer.path.clone(),
            lease: Arc::new(Mutex::new(writer.snapshot())),
            recovery_ownership: None,
        }
    }

    /// Deliberately supplied lifecycle facts, not a remote execution receipt.
    /// Only the real local journal/ownership boundaries run in these tests.
    fn delivery_fixture() -> (PathBuf, DurableLeaseWriter, RecoveryRecipe) {
        let (root, writer) = retained_namespace_fixture();
        let caller = root.join("caller");
        let remote = root.join("worker");
        std::fs::create_dir(&caller).unwrap();
        std::fs::create_dir(&remote).unwrap();
        std::fs::write(remote.join("retained-output"), b"completed worker output").unwrap();
        let worker = WorkerConfig {
            id: WorkerId::new("worker"),
            host: "unreachable.invalid".into(),
            user: "test".into(),
            identity_file: "/unused/key".into(),
            total_slots: 1,
            priority: 100,
            tags: Vec::new(),
            tools: Vec::new(),
        };
        RecoverySession::begin(
            &writer,
            &worker,
            vec![remote.to_str().unwrap().to_owned()],
            None,
            None,
            None,
            TransferConfig::default(),
            caller.clone(),
            uuid::Uuid::new_v4().simple().to_string(),
        )
        .unwrap();
        let mut recipe = load_recipe(&writer).unwrap();
        recipe.prepared = true;
        recipe.execution_started = true;
        recipe.kind = Some(CompilationKind::Make);
        recipe.exit_code = Some(0);
        recipe.returned = Some(0);
        let project = RecoveryPhase {
            name: "project".into(),
            local: caller,
            remote: remote.to_str().unwrap().to_owned(),
            patterns: vec!["build/**".into()],
            result_dir: None,
            custom_target: false,
            output_gate: false,
            cargo_outputs: None,
            native_outputs: None,
            baseline: BTreeMap::new(),
            published: BTreeMap::new(),
            pending: None,
            complete: true,
            missing_result: None,
        };
        let mut report = project.clone();
        report.name = "result:reports".into();
        report.patterns.clear();
        report.result_dir = Some("reports".into());
        recipe.phases = vec![project, report];
        (root, writer, recipe)
    }

    fn invalidate_delivery(recipe: &mut RecoveryRecipe, case: &str) {
        match case {
            "project" | "partial-project" => {
                recipe.phases[0].complete = false;
                if case == "partial-project" {
                    recipe.phases[0].published.insert(
                        "build/one.o".into(),
                        blake3::hash(b"published bytes").to_hex().to_string(),
                    );
                }
            }
            "report" => recipe.phases[1].complete = false,
            "pending-project" | "pending-report" => {
                let index = usize::from(case == "pending-report");
                recipe.phases[index].pending =
                    Some(("build/pending".into(), "retained-hash".into()));
            }
            "unprepared" => recipe.prepared = false,
            "unstarted" => recipe.execution_started = false,
            "cancelled" => recipe.preparation_cancelled = true,
            "failed" => recipe.exit_code = Some(7),
            "unknown" => recipe.exit_code = None,
            _ => panic!("unknown delivery fixture: {case}"),
        }
    }

    #[tokio::test]
    async fn premature_make_success_cannot_be_persisted_by_the_live_return_boundary() {
        for case in [
            "project",
            "partial-project",
            "report",
            "pending-project",
            "pending-report",
            "unprepared",
            "unstarted",
            "cancelled",
            "failed",
            "unknown",
        ] {
            let (root, writer, mut recipe) = delivery_fixture();
            recipe.returned = None;
            invalidate_delivery(&mut recipe, case);
            writer
                .set_recovery(serde_json::to_value(recipe).unwrap())
                .unwrap();
            writer.record_exit(EXIT_ARTIFACT_TRANSFER_FAILED).unwrap();
            let owned = claim_with(&writer, |_| async { Ok(true) }).await.unwrap();
            let mut session = RecoverySession {
                recipe: load_recipe(&owned).unwrap(),
                writer: owned.clone(),
            };
            let before = std::fs::read(&writer.path).unwrap();
            let lease = writer.snapshot();
            let entries = std::fs::read_dir(root.join("jobs")).unwrap().count();
            let error = session.returned(0).unwrap_err();
            assert!(
                format!("{error:#}").contains("successful recovery"),
                "{case}: {error:#}"
            );
            assert_eq!(writer.snapshot(), lease, "{case}");
            assert_eq!(std::fs::read(&writer.path).unwrap(), before, "{case}");
            assert_eq!(
                std::fs::read_dir(root.join("jobs")).unwrap().count(),
                entries
            );
            assert!(session.recipe.returned.is_none());
            assert!(!session.recipe.sources_released);
            assert!(!session.recipe.retired);
            assert!(!writer.snapshot().terminal_acknowledged);
            assert_eq!(
                serde_json::to_value(&session.recipe).unwrap(),
                lease.recovery.unwrap(),
                "failed publication changed cached recovery evidence: {case}"
            );
            assert_eq!(
                std::fs::read(root.join("worker/retained-output")).unwrap(),
                b"completed worker output"
            );
        }
    }

    #[tokio::test]
    async fn old_premature_success_is_refused_before_recovery_or_terminal_shortcut() {
        for acknowledged in [false, true] {
            for case in [
                "project",
                "partial-project",
                "report",
                "pending-project",
                "failed",
            ] {
                let (root, writer, mut recipe) = delivery_fixture();
                invalidate_delivery(&mut recipe, case);
                // Write adversarial old-format evidence with the unowned test
                // writer; never manufacture an observed worker/daemon success.
                writer
                    .set_recovery(serde_json::to_value(recipe).unwrap())
                    .unwrap();
                writer.record_exit(0).unwrap();
                if acknowledged {
                    writer.lease.lock().unwrap().acknowledge_terminal(3);
                    writer.persist().unwrap();
                }
                let before = std::fs::read(&writer.path).unwrap();
                let lease = writer.snapshot();
                let retained = root.join("worker/retained-output");
                let inode = std::fs::metadata(&retained).unwrap().ino();
                let inspected = Cell::new(false);
                let result = claim_with(&writer, |_| async {
                    inspected.set(true);
                    Ok(true)
                })
                .await;
                assert!(result.is_err(), "{case}, acknowledged={acknowledged}");
                assert!(
                    !inspected.get(),
                    "invalid delivery reached owner inspection"
                );
                assert_eq!(writer.snapshot(), lease);
                assert_eq!(std::fs::read(&writer.path).unwrap(), before);
                assert_eq!(
                    std::fs::read(&retained).unwrap(),
                    b"completed worker output"
                );
                assert_eq!(std::fs::metadata(&retained).unwrap().ino(), inode);
                assert_eq!(std::fs::read_dir(root.join("caller")).unwrap().count(), 0);
                // Only this failed collector's lock is released. The journal
                // and source-ownership facts remain exactly as supplied.
                let _retry_gate = acquire_gate(&writer.path).unwrap();
            }
        }
    }

    #[tokio::test]
    async fn verified_delivery_can_precede_exit_reconciliation_and_source_release() {
        for kind in [CompilationKind::Make, CompilationKind::CargoTest] {
            let (root, writer, mut recipe) = delivery_fixture();
            recipe.returned = None;
            recipe.kind = Some(kind);
            recipe.phases[0].complete = kind == CompilationKind::Make;
            writer
                .set_recovery(serde_json::to_value(recipe).unwrap())
                .unwrap();
            writer.record_exit(EXIT_ARTIFACT_TRANSFER_FAILED).unwrap();
            let owned = claim_with(&writer, |_| async { Ok(true) }).await.unwrap();
            let mut session = RecoverySession {
                recipe: load_recipe(&owned).unwrap(),
                writer: owned.clone(),
            };
            // Phony Make has a complete empty output set; streaming tests
            // need no optional artifact phase. Both still require the report.
            session.returned(0).unwrap();
            let disk =
                DurableLeaseWriter::read_journal(&writer.path, &writer.wrapper_id()).unwrap();
            assert_eq!(disk.exit_code, Some(EXIT_ARTIFACT_TRANSFER_FAILED));
            assert_eq!(disk.recovery.as_ref().unwrap()["returned"], 0);
            assert!(!disk.terminal_acknowledged);
            assert!(!session.recipe.sources_released);
            assert!(owned.acknowledge_terminal().is_err());
            drop(session);
            drop(owned);
            let _retry = claim_with(&writer, |_| async { Ok(true) }).await.unwrap();
            assert_eq!(writer.snapshot(), disk);
            assert_eq!(
                std::fs::read(root.join("worker/retained-output")).unwrap(),
                b"completed worker output"
            );
        }
    }

    #[tokio::test]
    async fn pending_and_failed_collection_keep_their_incomplete_evidence() {
        for returned in [None, Some(EXIT_ARTIFACT_TRANSFER_FAILED)] {
            let (root, writer, mut recipe) = delivery_fixture();
            recipe.returned = returned;
            invalidate_delivery(&mut recipe, "partial-project");
            let expected = serde_json::to_value(recipe).unwrap();
            writer.set_recovery(expected.clone()).unwrap();
            writer.record_exit(EXIT_ARTIFACT_TRANSFER_FAILED).unwrap();
            let owned = claim_with(&writer, |_| async { Ok(true) }).await.unwrap();
            owned.heartbeat("recovery").unwrap();
            assert_eq!(owned.snapshot().recovery.as_ref(), Some(&expected));
            assert!(!owned.snapshot().terminal_acknowledged);
            assert_eq!(
                std::fs::read(root.join("worker/retained-output")).unwrap(),
                b"completed worker output"
            );
        }
    }

    #[tokio::test]
    async fn successful_delivery_must_belong_to_the_same_wrapper_build_and_worker() {
        for field in ["version", "wrapper_id", "build_id", "worker"] {
            let (root, writer, mut recipe) = delivery_fixture();
            recipe.returned = None;
            writer
                .set_recovery(serde_json::to_value(&recipe).unwrap())
                .unwrap();
            let owned = claim_with(&writer, |_| async { Ok(true) }).await.unwrap();
            recipe.returned = Some(0);
            match field {
                "version" => recipe.version = 99,
                "wrapper_id" => recipe.wrapper_id = "rchw-other".into(),
                "build_id" => recipe.build_id += 1,
                "worker" => recipe.worker.id = WorkerId::new("other-worker"),
                _ => unreachable!(),
            }
            let before = std::fs::read(&writer.path).unwrap();
            let lease = writer.snapshot();
            assert!(
                owned
                    .set_recovery(serde_json::to_value(recipe).unwrap())
                    .is_err()
            );
            assert_eq!(writer.snapshot(), lease);
            assert_eq!(std::fs::read(&writer.path).unwrap(), before);
            assert_eq!(
                std::fs::read(root.join("worker/retained-output")).unwrap(),
                b"completed worker output"
            );
        }
    }

    #[tokio::test]
    async fn one_recovery_owns_the_journal_through_release() {
        let (_directory, writer) = fixture();
        let stale = independent_writer(&writer);
        let guard = claim_with(&writer, |_| async { Ok(true) }).await.unwrap();
        let called = Cell::new(false);
        assert!(
            claim_with(&stale, |_| async {
                called.set(true);
                Ok(true)
            })
            .await
            .is_err()
        );
        assert!(
            !called.get(),
            "a contender must not reach process or worker probes"
        );
        let lock_path = writer.path.with_extension("recovery.lock");
        let inode = std::fs::metadata(&lock_path).unwrap().ino();
        let (_other_directory, other) = fixture();
        let _other_guard = claim_with(&other, |_| async { Ok(true) }).await.unwrap();
        guard.record_exit(102).unwrap();
        guard.acknowledge_terminal().unwrap();
        drop(guard);
        let _next = claim_with(&stale, |_| async {
            panic!("already acknowledged terminal state needs no owner probe")
        })
        .await
        .unwrap();
        assert_eq!(std::fs::metadata(&lock_path).unwrap().ino(), inode);
        assert!(stale.snapshot().terminal_acknowledged);
        assert_eq!(stale.snapshot().exit_code, Some(102));
    }

    #[tokio::test]
    async fn recovery_reloads_latest_progress_without_writing_it_back() {
        let (_directory, writer) = fixture();
        let stale = independent_writer(&writer);
        writer
            .set_recovery(serde_json::json!({
                "returned": 102,
                "sources_released": true,
                "retired": false,
                "phases": [{"missing_result": {"command_exit": 1}}],
            }))
            .unwrap();
        let bytes = std::fs::read(&writer.path).unwrap();
        let _guard = claim_with(&stale, |_| async { Ok(true) }).await.unwrap();
        assert_eq!(stale.snapshot(), writer.snapshot());
        assert_eq!(std::fs::read(&writer.path).unwrap(), bytes);
    }

    fn retained_namespace_fixture() -> (PathBuf, DurableLeaseWriter) {
        let root = tempfile::tempdir().unwrap().keep();
        let directory = root.join("jobs");
        std::fs::create_dir(&directory).unwrap();
        let mut lease = DurableJobLease::new(
            JobIdentity::new_local(),
            12345,
            None,
            None,
            0,
            true,
            false,
            "namespace-fixture".into(),
        );
        lease.admit(42, "worker".into(), 1);
        let writer = DurableLeaseWriter {
            path: directory.join("lease.json"),
            lease: Arc::new(Mutex::new(lease)),
            recovery_ownership: None,
        };
        writer.persist().unwrap();
        (root, writer)
    }

    #[tokio::test]
    async fn replacement_during_owner_inspection_cannot_rebind_recovery() {
        let (root, writer) = retained_namespace_fixture();
        let original = writer.snapshot();
        let bytes = std::fs::read(&writer.path).unwrap();
        let result = claim_with(&writer, |_| async {
            std::fs::rename(root.join("jobs"), root.join("original-jobs"))?;
            std::fs::create_dir(root.join("jobs"))?;
            // A copied, valid same-wrapper journal must not pass the namespace fence.
            std::fs::write(&writer.path, &bytes)?;
            Ok(true)
        })
        .await;
        assert!(result.is_err());
        assert_eq!(writer.snapshot(), original);
        assert_eq!(std::fs::read(&writer.path).unwrap(), bytes);
        assert_eq!(
            std::fs::read(root.join("original-jobs/lease.json")).unwrap(),
            bytes
        );
        assert!(root.join("original-jobs/lease.recovery.lock").is_file());
    }

    #[tokio::test]
    async fn recovery_clones_retain_lock_and_never_write_replacement_namespace() {
        let (root, writer) = retained_namespace_fixture();
        let bound = claim_with(&writer, |_| async { Ok(true) }).await.unwrap();
        let clone = bound.clone();
        drop(bound);
        assert!(acquire_gate(&writer.path).is_err());
        clone.record_exit(102).unwrap();
        clone.acknowledge_terminal().unwrap();
        let wrapper = clone.wrapper_id();
        let report = clone
            .terminal_job_report(&wrapper, "recovered", Some(102))
            .unwrap();
        assert_eq!(report["exit_code"], 102);
        assert_eq!(report["admission"]["remote_build_id"], "42");
        let original = clone.snapshot();
        let bytes = std::fs::read(&writer.path).unwrap();
        // Preserve both namespaces and the persistent original gate, with no unlink.
        std::fs::rename(root.join("jobs"), root.join("original-jobs")).unwrap();
        std::fs::create_dir(root.join("jobs")).unwrap();
        std::fs::write(&writer.path, &bytes).unwrap();
        let before = std::fs::read_dir(root.join("jobs")).unwrap().count();
        assert!(clone.record_exit(103).is_err());
        assert!(clone.persist().is_err());
        assert!(
            clone
                .terminal_job_report(&wrapper, "recovered", Some(102))
                .is_err()
        );
        assert!(
            clone
                .recovery_ownership
                .as_ref()
                .unwrap()
                .read(&wrapper)
                .is_err()
        );
        assert_eq!(clone.snapshot(), original);
        assert_eq!(std::fs::read(&writer.path).unwrap(), bytes);
        assert_eq!(
            std::fs::read(root.join("original-jobs/lease.json")).unwrap(),
            bytes
        );
        assert_eq!(
            std::fs::read_dir(root.join("jobs")).unwrap().count(),
            before
        );
        // A new lock in the replacement directory does not own the original.
        let replacement = acquire_gate(&writer.path).unwrap();
        assert!(clone.persist().is_err());
        drop(replacement);
        drop(clone);
        let _released = acquire_gate(&root.join("original-jobs/lease.json")).unwrap();
    }

    #[tokio::test]
    async fn replaced_gate_refuses_without_changing_lease_or_journal() {
        use std::os::unix::fs::OpenOptionsExt;

        let (root, writer) = retained_namespace_fixture();
        let bound = claim_with(&writer, |_| async { Ok(true) }).await.unwrap();
        let original = bound.snapshot();
        let bytes = std::fs::read(&writer.path).unwrap();
        let gate_path = writer.path.with_extension("recovery.lock");
        let original_gate = root.join("jobs/original-recovery.lock");
        std::fs::rename(&gate_path, &original_gate).unwrap();
        let replacement = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&gate_path)
            .unwrap();
        assert!(bound.record_exit(103).is_err());
        assert!(bound.persist().is_err());
        assert_eq!(bound.snapshot(), original);
        assert_eq!(std::fs::read(&writer.path).unwrap(), bytes);
        assert_eq!(
            std::fs::metadata(&original_gate).unwrap().ino(),
            bound
                .recovery_ownership
                .as_ref()
                .unwrap()
                ._gate
                .metadata()
                .unwrap()
                .ino()
        );
        assert_eq!(replacement.metadata().unwrap().len(), 0);
        // Both real lock files and the journal remain retained; no replacement
        // gate can grant this bound writer authority over a new journal epoch.
    }

    #[tokio::test]
    async fn substituted_publication_leaf_does_not_replace_the_journal() {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let (root, writer) = retained_namespace_fixture();
        let bound = claim_with(&writer, |_| async { Ok(true) }).await.unwrap();
        let ownership = bound.recovery_ownership.as_ref().unwrap();
        let bytes = std::fs::read(&writer.path).unwrap();
        let temporary_path = root.join("jobs/.publication-fixture.tmp");
        let mut held = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary_path)
            .unwrap();
        held.write_all(b"intended lease bytes").unwrap();
        held.sync_all().unwrap();
        std::fs::rename(&temporary_path, root.join("jobs/original-publication.tmp")).unwrap();
        std::fs::write(&temporary_path, b"substituted bytes").unwrap();
        let error = ownership
            .publish_temporary(&held, c".publication-fixture.tmp", b"intended lease bytes")
            .unwrap_err();
        assert!(format!("{error:#}").contains("publication file changed"));
        assert_eq!(std::fs::read(&writer.path).unwrap(), bytes);
        assert_eq!(
            std::fs::read(&temporary_path).unwrap(),
            b"substituted bytes"
        );
        assert_eq!(
            std::fs::read(root.join("jobs/original-publication.tmp")).unwrap(),
            b"intended lease bytes"
        );
        // The real publication helper is exercised against real replaced files;
        // no synthetic compiler/daemon success, no temporary-file deletion.
    }

    #[tokio::test]
    async fn live_or_unknown_owner_never_yields_recovery_authority() {
        let (_directory, writer) = fixture();
        let before = std::fs::read(&writer.path).unwrap();
        assert!(claim_with(&writer, |_| async { Ok(false) }).await.is_err());
        assert!(
            claim_with(&writer, |_| async {
                anyhow::bail!("owner inspection unavailable")
            })
            .await
            .is_err()
        );
        assert_eq!(std::fs::read(&writer.path).unwrap(), before);
        let _retry = claim_with(&writer, |_| async { Ok(true) }).await.unwrap();
    }

    #[tokio::test]
    async fn changed_identity_or_mid_probe_publication_is_not_overwritten() {
        let (_directory, writer) = fixture();
        let original = writer.snapshot();
        let mut replacement = original.clone();
        replacement.identity.admit(43);
        std::fs::write(&writer.path, serde_json::to_vec(&replacement).unwrap()).unwrap();
        assert!(
            claim_with(&writer, |_| async {
                panic!("a replaced job must fail before owner inspection")
            })
            .await
            .is_err()
        );
        assert_eq!(writer.snapshot(), original);
        std::fs::write(&writer.path, serde_json::to_vec(&original).unwrap()).unwrap();
        assert!(
            claim_with(&writer, |_| async {
                let mut latest = original.clone();
                latest.heartbeat("final-owner-update", 9);
                std::fs::write(&writer.path, serde_json::to_vec(&latest)?)?;
                Ok(true)
            })
            .await
            .is_err()
        );
        assert_eq!(writer.snapshot(), original);
        let disk: DurableJobLease =
            serde_json::from_slice(&std::fs::read(&writer.path).unwrap()).unwrap();
        assert_eq!(disk.phase, "final-owner-update");
    }

    #[tokio::test]
    async fn cancelling_inspection_releases_only_the_recovery_lock() {
        let (_directory, writer) = fixture();
        let before = std::fs::read(&writer.path).unwrap();
        let mut claim = Box::pin(claim_with(&writer, |_| std::future::pending()));
        // Drive acquisition and then stop exactly at the pending inspection.
        assert!(matches!(
            futures::poll!(claim.as_mut()),
            std::task::Poll::Pending
        ));
        assert!(acquire_gate(&writer.path).is_err());
        drop(claim);
        let _next = claim_with(&writer, |_| async { Ok(true) }).await.unwrap();
        assert_eq!(std::fs::read(&writer.path).unwrap(), before);
    }

    #[tokio::test]
    async fn recovery_refuses_unsafe_lock_entries_without_changing_them() {
        let (directory, writer) = fixture();
        let path = writer.path.with_extension("recovery.lock");
        let sentinel = directory.path().join("sentinel");
        std::fs::write(&sentinel, b"keep").unwrap();
        std::os::unix::fs::symlink(&sentinel, &path).unwrap();
        assert!(claim_with(&writer, |_| async { Ok(true) }).await.is_err());
        assert_eq!(std::fs::read_link(&path).unwrap(), sentinel);
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"keep");
    }

    #[test]
    #[cfg_attr(target_vendor = "apple", allow(unused_imports, unused_variables))]
    fn recovery_owner_refuses_fifo_journal_before_owner_inspection() {
        use rustix::fs::{Mode, OFlags};
        use std::os::fd::AsFd;
        use std::os::unix::fs::FileTypeExt;

        let retained = tempfile::tempdir().unwrap().keep();
        let directory =
            rustix::fs::open(&retained, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()).unwrap();
        #[cfg(not(target_vendor = "apple"))]
        rustix::fs::mkfifoat(directory.as_fd(), c"lease.json", Mode::RUSR | Mode::WUSR).unwrap();
        // rustix has no mkfifoat on Apple targets and this crate forbids unsafe
        // code, so make the FIFO by path; `directory` is open on `retained`.
        #[cfg(target_vendor = "apple")]
        assert!(
            std::process::Command::new("/usr/bin/mkfifo")
                .args(["-m", "600"])
                .arg(retained.join("lease.json"))
                .status()
                .unwrap()
                .success()
        );
        let writer = DurableLeaseWriter {
            path: retained.join("lease.json"),
            recovery_ownership: None,
            lease: Arc::new(Mutex::new(DurableJobLease::new(
                JobIdentity::new_local(),
                std::process::id(),
                None,
                None,
                0,
                true,
                false,
                "filesystem-fixture".into(),
            ))),
        };
        let original = writer.snapshot();
        let other = writer.clone();
        let (sender, receiver) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let result = runtime
                .block_on(claim_with(&other, |_| async {
                    panic!("invalid FIFO must be refused before any owner or worker probe")
                }))
                .map(|_| ());
            sender.send(result).unwrap();
        });
        let error = receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("recovery-owner reload waited for a FIFO writer")
            .unwrap_err();
        reader.join().unwrap();
        assert!(format!("{error:#}").contains("journal is not a regular file"));
        assert_eq!(writer.snapshot(), original);
        assert!(
            std::fs::symlink_metadata(&writer.path)
                .unwrap()
                .file_type()
                .is_fifo()
        );
        // Retained real FIFO/lock I/O only, no successful owner takeover,
        // daemon reservation, compiler replay or native/SDK qualification.
    }

    #[test]
    fn owner_absence_requires_a_complete_pid_listing_that_contains_observer() {
        assert!(absent_from_process_list(b" 1\n 42\n 900\n", 17, 42).unwrap());
        assert!(!absent_from_process_list(b" 1\n 42\n 900\n", 900, 42).unwrap());
        for bytes in [
            &b""[..],
            &b"1\n"[..],
            &b"42"[..],
            &b"42\nPID\n"[..],
            &b"42\n0\n"[..],
            &b"42\n42\n"[..],
            &b"42\n-1\n"[..],
            &b"42\n4294967296\n"[..],
            &b"42\n\xff\n"[..],
        ] {
            assert!(
                absent_from_process_list(bytes, 17, 42).is_err(),
                "{bytes:?}"
            );
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn native_birth_marker_detects_pid_reuse_without_signalling_any_process() {
        use rch_common::process_identity::{ProcessStart, current_process_identity};
        let (_directory, writer) = fixture();
        let mut lease = writer.snapshot();
        lease.wrapper_pid = std::process::id();
        lease.process_birth = Some(current_process_identity().expect("native process birth"));
        assert_eq!(native_owner_absent(&lease), Some(false));
        match &mut lease.process_birth.as_mut().unwrap().start {
            ProcessStart::Linux { ticks } => *ticks += 1,
            ProcessStart::Darwin { microseconds, .. } => {
                *microseconds = (*microseconds + 1) % 1_000_000
            }
        }
        assert_eq!(native_owner_absent(&lease), Some(true));
        lease.process_birth.as_mut().unwrap().boot_id = "unverified-boot-marker".into();
        assert_eq!(native_owner_absent(&lease), None);
        lease.process_birth = None;
        assert_eq!(native_owner_absent(&lease), None);
    }

    #[test]
    fn reloaded_owner_must_preserve_exact_darwin_microseconds() {
        let (_directory, writer) = fixture();
        let mut before = writer.snapshot();
        before.process_birth = rch_common::process_identity::ProcessIdentity::from_record(
            "3f1c2a9e-5b7d-4e2a-9c1f-0a1b2c3d4e5f:darwin:1791280000:123456",
        );
        let mut after: DurableJobLease =
            serde_json::from_slice(&serde_json::to_vec(&before).unwrap()).unwrap();
        validate_same_owner(&before, &after).unwrap();
        if let rch_common::process_identity::ProcessStart::Darwin { microseconds, .. } =
            &mut after.process_birth.as_mut().unwrap().start
        {
            *microseconds += 1;
        }
        assert!(validate_same_owner(&before, &after).is_err());
    }

    #[tokio::test]
    async fn a_live_wrapper_and_unknown_pid_cannot_be_taken_over() {
        let (_directory, writer) = fixture();
        let mut lease = writer.snapshot();
        for pid in [0, 1, std::process::id(), u32::MAX] {
            lease.wrapper_pid = pid;
            assert!(!owner_is_absent(&lease).await.unwrap());
        }
        let mut child = tokio::process::Command::new("/bin/sleep")
            .arg("30")
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        lease.wrapper_pid = child.id().unwrap();
        let live = owner_is_absent(&lease).await;
        child.kill().await.unwrap();
        child.wait().await.unwrap();
        assert!(!live.unwrap());
        assert!(owner_is_absent(&lease).await.unwrap());
    }
}
