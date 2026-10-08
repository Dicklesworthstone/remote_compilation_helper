//! Exclusive detached recovery of one durable wrapper, never command replay.
//!
//! Output-root locks cover publication only. A recovery command must also own
//! the journal across worker probes, publication and source release, and must
//! reload it AFTER taking that ownership. Otherwise two independently loaded
//! writers can roll back each other's durable retirement or failure evidence.

use super::*;
use std::future::Future;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

/// The inode stays on disk. Unlinking it on release would let a waiting opener
/// lock the old inode while a new recovery command locks its replacement.
pub(super) struct RecoveryOwnership {
    _gate: File,
}

fn acquire_gate(lease_path: &Path) -> anyhow::Result<RecoveryOwnership> {
    let path = lease_path.with_extension("recovery.lock");
    let (socket, _peer) = tokio::net::UnixStream::pair()?;
    let uid = socket.peer_cred()?.uid();
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
    let gate = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&path)?;
    gate.try_lock().map_err(|error| {
        anyhow::anyhow!(
            "cannot acquire exclusive job recovery: {error}; another recovery may be active; retry the same wrapper"
        )
    })?;
    let held = gate.metadata()?;
    let named = std::fs::symlink_metadata(&path)?;
    anyhow::ensure!(
        safe(&held) && safe(&named) && held.dev() == named.dev() && held.ino() == named.ino(),
        "recovery lock path changed during acquisition"
    );
    Ok(RecoveryOwnership { _gate: gate })
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

pub(super) async fn claim(writer: &DurableLeaseWriter) -> anyhow::Result<RecoveryOwnership> {
    claim_with(writer, |lease| async move { owner_is_absent(&lease).await }).await
}

async fn claim_with<F, Fut>(
    writer: &DurableLeaseWriter,
    inspect: F,
) -> anyhow::Result<RecoveryOwnership>
where
    F: FnOnce(DurableJobLease) -> Fut,
    Fut: Future<Output = anyhow::Result<bool>>,
{
    let observed = writer.snapshot();
    let ownership = acquire_gate(&writer.path)?;
    let read = || -> anyhow::Result<DurableJobLease> {
        Ok(serde_json::from_slice(&std::fs::read(&writer.path)?)?)
    };
    let latest = read()?;
    validate_same_owner(&observed, &latest)?;
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
    Ok(ownership)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

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
        };
        writer.persist().unwrap();
        (directory, writer)
    }

    fn independent_writer(writer: &DurableLeaseWriter) -> DurableLeaseWriter {
        DurableLeaseWriter {
            path: writer.path.clone(),
            lease: Arc::new(Mutex::new(writer.snapshot())),
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
        writer.record_exit(102).unwrap();
        writer.acknowledge_terminal().unwrap();
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
