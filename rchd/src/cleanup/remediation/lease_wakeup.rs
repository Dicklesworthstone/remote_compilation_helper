//! A changed client lease is a retry hint, NEVER proof of source retirement.
//!
//! A dead SyncUp wrapper may leave a source-owning lease without any remote
//! process-group record (bd-r1kcc). Recovery updates that lease independently of
//! active history. Notice replacement/modification/removal without waiting out
//! the old failure delay; cancellation still has to verify every ownership fact.

use super::RetryStamp;
use rch_common::job_identity::{LOCAL_WRAPPER_ID_PREFIX, default_job_lease_directory};
use std::path::Path;
use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum LeaseStamp {
    Missing,
    Present {
        length: u64,
        modified: SystemTime,
        #[cfg(unix)]
        object: (u64, u64, i64, i64),
    },
}

fn canonical_wrapper(wrapper: &str) -> Option<&str> {
    let suffix = wrapper.strip_prefix(LOCAL_WRAPPER_ID_PREFIX)?;
    let id = uuid::Uuid::parse_str(suffix).ok()?;
    (id.to_string() == suffix).then_some(wrapper)
}

/// Inspect only the bound filename. Unknown errors and wrong object types are
/// not absence. Inode/ctime also notice atomic replacement with equal size and
/// mtime. These are scheduling hints, not a record-content or durability check.
fn observe_in(directory: &Path, wrapper: &str) -> Option<LeaseStamp> {
    let wrapper = canonical_wrapper(wrapper)?;
    let path = directory.join(format!("{wrapper}.json"));
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => metadata,
        Ok(_) => return None,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Some(LeaseStamp::Missing);
        }
        Err(_) => return None,
    };
    #[cfg(unix)]
    let object = {
        use std::os::unix::fs::MetadataExt;
        (
            metadata.dev(),
            metadata.ino(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        )
    };
    Some(LeaseStamp::Present {
        length: metadata.len(),
        modified: metadata.modified().ok()?,
        #[cfg(unix)]
        object,
    })
}

pub(super) fn observe(attempted: &RetryStamp) -> Option<LeaseStamp> {
    if attempted.remote_pgid_file.is_some() {
        return None;
    }
    observe_in(
        &default_job_lease_directory(),
        attempted.wrapper.as_deref()?,
    )
}

pub(super) fn changed(previous: &Option<LeaseStamp>, current: &Option<LeaseStamp>) -> bool {
    current.is_some() && current != previous
}

pub(super) fn recovery_hint(attempted: &RetryStamp) -> Option<String> {
    if attempted.remote_pgid_file.is_some() {
        return None;
    }
    // The canonical prefix/UUID contains no shell metacharacters. Invalid
    // legacy identifiers must not be turned into executable operator advice.
    let wrapper = canonical_wrapper(attempted.wrapper.as_deref()?)?;
    Some(format!(
        "Resume source recovery: rch jobs recover {wrapper}"
    ))
}

#[cfg(test)]
mod tests {
    use super::super::{RETRY_BASE, RetryBackoff};
    use super::*;
    use std::time::Instant;

    const WRAPPER: &str = "rchw-10000000-0000-4000-8000-000000000001";

    fn attempt() -> RetryStamp {
        let now = Instant::now();
        RetryStamp {
            build_id: 1,
            worker_id: "retained-worker".into(),
            wrapper: Some(WRAPPER.into()),
            hook_pid: 0,
            hook_identity: None,
            started: now,
            heartbeat: now,
            progress: now,
            remote_pgid_file: None,
            slots: 1,
        }
    }

    #[test]
    fn canonical_wrapper_is_required_before_any_path_or_operator_hint() {
        assert_eq!(canonical_wrapper(WRAPPER), Some(WRAPPER));
        for invalid in [
            "rchw-../outside",
            "rchw-10000000000040008000000000000001",
            "rchw-AAAAAAAA-0000-4000-8000-000000000001",
            "rchw-10000000-0000-4000-8000-000000000001; echo injected",
            "../rchw-10000000-0000-4000-8000-000000000001",
            "wrapper-legacy",
        ] {
            let mut stamp = attempt();
            stamp.wrapper = Some(invalid.into());
            assert!(canonical_wrapper(invalid).is_none());
            assert!(recovery_hint(&stamp).is_none());
        }
        let mut stamp = attempt();
        assert!(recovery_hint(&stamp).unwrap().ends_with(WRAPPER));
        stamp.remote_pgid_file = Some("/already-launched.pgid".into());
        assert!(observe(&stamp).is_none());
        assert!(recovery_hint(&stamp).is_none());
    }

    #[test]
    fn replacement_and_removal_wake_retry_without_certifying_completion() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(format!("{WRAPPER}.json"));
        std::fs::write(&path, "original lease bytes").unwrap();
        let original = observe_in(root.path(), WRAPPER);
        assert!(matches!(
            original.as_ref(),
            Some(LeaseStamp::Present { .. })
        ));
        assert!(!changed(&original, &observe_in(root.path(), WRAPPER)));

        // Atomic publication of a same-length replacement must still wake up.
        let temporary = root.path().join("next-lease");
        std::fs::write(&temporary, "replaced lease bytes").unwrap();
        std::fs::rename(&temporary, &path).unwrap();
        let replaced = observe_in(root.path(), WRAPPER);
        assert!(changed(&original, &replaced));

        // Move, rather than delete, the fixture: no ownership bytes are lost.
        std::fs::rename(&path, root.path().join("retired-fixture")).unwrap();
        let missing = observe_in(root.path(), WRAPPER);
        assert_eq!(missing, Some(LeaseStamp::Missing));
        assert!(changed(&replaced, &missing));
        assert!(!changed(&missing, &missing));
        assert_eq!(
            std::fs::read(root.path().join("retired-fixture")).unwrap(),
            b"replaced lease bytes"
        );
    }

    #[test]
    fn unavailable_observation_never_clears_backoff() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(format!("{WRAPPER}.json"));
        std::fs::create_dir(&path).unwrap();
        assert!(observe_in(root.path(), WRAPPER).is_none());
        assert!(!changed(&Some(LeaseStamp::Missing), &None));
        assert!(!changed(&None, &None));
        assert!(changed(&None, &Some(LeaseStamp::Missing)));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_is_not_treated_as_an_observed_lease_or_its_absence() {
        let root = tempfile::tempdir().unwrap();
        let outside = root.path().join("not-the-lease");
        std::fs::write(&outside, "do not read or mutate").unwrap();
        let path = root.path().join(format!("{WRAPPER}.json"));
        std::os::unix::fs::symlink(&outside, &path).unwrap();
        assert!(observe_in(root.path(), WRAPPER).is_none());
        std::fs::rename(&outside, root.path().join("moved-target")).unwrap();
        assert!(
            observe_in(root.path(), WRAPPER).is_none(),
            "dangling is not absent"
        );
    }

    #[test]
    fn actual_lease_change_reopens_retry_policy_before_its_deadline() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(format!("{WRAPPER}.json"));
        std::fs::write(&path, "retained").unwrap();
        let original = observe_in(root.path(), WRAPPER);
        let stamp = attempt();
        let now = Instant::now();
        let mut backoff = RetryBackoff::default();
        backoff.failed_with_lease(stamp.clone(), now, original.clone());
        assert!(!backoff.ready_after_lease_observation(&stamp, now, original));
        assert!(!backoff.ready_after_lease_observation(&stamp, now, None));
        std::fs::write(&path, "recovery retired the source recipe").unwrap();
        assert!(backoff.ready_after_lease_observation(
            &stamp,
            now,
            observe_in(root.path(), WRAPPER)
        ));
        assert!(backoff.failures.is_empty());
        assert_eq!(backoff.failed(stamp, now), RETRY_BASE);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"recovery retired the source recipe"
        );
    }
}

#[cfg(test)]
mod racing_completion {
    use super::super::{RETRY_MAX, RetryBackoff};
    use super::*;
    use std::time::Instant;

    #[test]
    fn lease_changed_during_failure_does_not_wait_for_the_new_deadline() {
        let root = tempfile::tempdir().unwrap();
        let wrapper = "rchw-20000000-0000-4000-8000-000000000001";
        let path = root.path().join(format!("{wrapper}.json"));
        std::fs::write(&path, "source retained").unwrap();
        let before = observe_in(root.path(), wrapper);
        let started = Instant::now();
        let stamp = RetryStamp {
            build_id: 77,
            worker_id: "worker".into(),
            wrapper: Some(wrapper.into()),
            hook_pid: 0,
            hook_identity: None,
            started,
            heartbeat: started,
            progress: started,
            remote_pgid_file: None,
            slots: 1,
        };
        // Model recovery publishing while an admitted cancellation is waiting.
        std::fs::write(&path, "source retirement recorded during cancellation").unwrap();
        let finished = started + RETRY_MAX;
        let mut backoff = RetryBackoff::default();
        backoff.failed_with_lease(stamp.clone(), finished, before);
        assert!(backoff.ready_after_lease_observation(
            &stamp,
            finished,
            observe_in(root.path(), wrapper),
        ));
        assert!(backoff.failures.is_empty());
    }
}
