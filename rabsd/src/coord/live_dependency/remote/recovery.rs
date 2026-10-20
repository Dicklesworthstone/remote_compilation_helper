//! Retain an uncertain live remote attempt for the existing result-only recovery lane.
//!
//! A delivery receiver deliberately retains incomplete files, but its caller must
//! retain the containing directory too. Persist the exact request before dispatch,
//! then default to retention on error or unwind. Only confirmed no-execution or
//! verified delivery with confirmed acknowledgments permits scratch cleanup.
//! This record grants no execution, publication, installation or actor-repair right.

use rabs_asupersync::worker_transport::MAX_JSON_RECORD;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions, Permissions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(super) struct ResultDirectory {
    directory: Option<tempfile::TempDir>,
    path: PathBuf,
    recorded: bool,
    retention: Option<&'static str>,
}

impl ResultDirectory {
    pub(super) fn new(parent: &Path) -> io::Result<Self> {
        let directory = tempfile::Builder::new()
            .prefix("result-")
            .permissions(Permissions::from_mode(0o700))
            .tempdir_in(parent)?;
        Ok(Self {
            path: directory.path().to_path_buf(),
            directory: Some(directory),
            recorded: false,
            retention: None,
        })
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// This MUST succeed before the transport can send the execution request.
    /// The raw request is directly consumable by the existing --resume operator;
    /// the separate record binds its digest and configured worker, not a claimed
    /// execution incarnation. Request environment values may be sensitive and
    /// stay private; no TLS private-key material or source contents are copied.
    pub(super) fn record_request(
        &mut self,
        request: &Value,
        action_key: &str,
        configuration: &Value,
    ) -> io::Result<()> {
        if self.recorded {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "remote recovery request was already recorded",
            ));
        }
        if request["kind"] != "canonical-exec"
            || !request["request_id"].as_u64().is_some_and(|id| id != 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "remote recovery requires the exact allocated execution request",
            ));
        }
        let bytes = serde_json::to_vec(request)?;
        if bytes.len() > MAX_JSON_RECORD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "remote recovery request exceeds the transport frame bound",
            ));
        }
        let digest: String = Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let parent = self.path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "remote recovery parent missing")
        })?;
        let state = parent.to_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "remote recovery state is not UTF-8")
        })?;
        let record = serde_json::to_vec_pretty(&json!({
            "schema": "rabs-live-remote-recovery-v1",
            "action_key": action_key,
            "request_id": request["request_id"],
            "request_sha256": digest,
            "request_file": "request.json",
            "partial_delivery": "delivery",
            "remote_configuration": configuration,
            "transport_state_dir": state,
            "execution_state": "unknown",
            "recovery_mode": "resume-or-acknowledge-only",
            "publication_authorized": false,
            "reexecute": false,
        }))?;
        if record.len() > MAX_JSON_RECORD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "remote recovery metadata exceeds the frame bound",
            ));
        }
        write_new_synced(&self.path.join("request.json"), &bytes)?;
        write_new_synced(&self.path.join("recovery.json"), &record)?;
        File::open(&self.path)?.sync_all()?;
        File::open(parent)?.sync_all()?;
        self.recorded = true;
        // Arm before handing control to the transport. Unwind, lost replies and
        // poisoned ownership default to retention, never to presumed completion.
        self.retention = Some("execution-unknown");
        Ok(())
    }

    /// Called only with verified complete execution, or transport evidence that
    /// execution never started. An error string or a timeout is not that proof.
    pub(super) fn execution_finished(&mut self) {
        self.retention = None;
    }

    /// A verified delivery already has its own synced delivery.json. Keep it
    /// for the existing acknowledgment-only operator when final ACKs were lost;
    /// that marker, not the initial unknown-intent record, proves byte delivery.
    pub(super) fn delivery_finished(&mut self, acknowledgments_confirmed: bool) {
        self.retention = (!acknowledgments_confirmed).then_some("acknowledgment-unconfirmed");
    }
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

impl Drop for ResultDirectory {
    fn drop(&mut self) {
        if let Some(reason) = self.retention
            && let Some(directory) = self.directory.take()
        {
            let path = directory.keep();
            // Reporting must not panic during unwind. This is an observation,
            // not a receipt authorizing recovery, reexecution or publication.
            let _ = writeln!(
                std::io::stderr().lock(),
                "{}",
                json!({
                    "v": 1,
                    "kind": "rabs-remote-recovery-retained",
                    "directory": path.to_string_lossy(),
                    "reason": reason,
                    "reexecute": false,
                }),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Value {
        json!({
            "kind": "canonical-exec", "request_id": 17,
            "program": "/toolchain/bin/rustc",
            "args": ["src/lib.rs", "--cfg", "label=\"snow 雪\""],
        })
    }

    fn configuration() -> Value {
        json!({
            "remote_protocol": 1, "worker_id": "worker-a",
            "worker_spki_sha256": "ab".repeat(32), "listen": "127.0.0.1:9123",
        })
    }

    fn recorded(parent: &Path) -> ResultDirectory {
        let mut directory = ResultDirectory::new(parent).unwrap();
        directory
            .record_request(&request(), "action-key", &configuration())
            .unwrap();
        directory
    }

    #[test]
    fn exact_request_and_non_authoritative_worker_context_are_private_and_persisted() {
        let parent = tempfile::tempdir().unwrap();
        let mut directory = recorded(parent.path());
        let bytes = std::fs::read(directory.path().join("request.json")).unwrap();
        assert_eq!(bytes, serde_json::to_vec(&request()).unwrap());
        let record: Value = serde_json::from_slice(
            &std::fs::read(directory.path().join("recovery.json")).unwrap(),
        )
        .unwrap();
        let digest: String = Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(record["request_sha256"], digest);
        assert_eq!(record["request_id"], 17);
        assert_eq!(record["action_key"], "action-key");
        assert_eq!(record["remote_configuration"], configuration());
        assert_eq!(record["execution_state"], "unknown");
        assert_eq!(record["recovery_mode"], "resume-or-acknowledge-only");
        assert_eq!(record["transport_state_dir"], parent.path().to_str().unwrap());
        assert_eq!(record["publication_authorized"], false);
        assert_eq!(record["reexecute"], false);
        for path in [
            directory.path().to_path_buf(),
            directory.path().join("request.json"),
            directory.path().join("recovery.json"),
        ] {
            assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o077, 0);
        }
        directory.execution_finished();
    }

    #[test]
    fn uncertain_drop_preserves_partial_diagnostics_and_exact_request() {
        let parent = tempfile::tempdir().unwrap();
        let directory = recorded(parent.path());
        let path = directory.path().to_path_buf();
        std::fs::create_dir_all(path.join("delivery/diagnostics")).unwrap();
        std::fs::write(path.join("delivery/diagnostics/stderr"), b"partial\0\xff").unwrap();
        drop(directory);
        assert_eq!(
            std::fs::read(path.join("delivery/diagnostics/stderr")).unwrap(),
            b"partial\0\xff",
        );
        assert_eq!(
            std::fs::read(path.join("request.json")).unwrap(),
            serde_json::to_vec(&request()).unwrap(),
        );
        assert!(path.join("recovery.json").is_file());
    }

    #[test]
    fn confirmed_completion_releases_only_owned_scratch() {
        let parent = tempfile::tempdir().unwrap();
        let sentinel = parent.path().join("unrelated-result");
        std::fs::write(&sentinel, b"untouched").unwrap();
        let mut directory = recorded(parent.path());
        let path = directory.path().to_path_buf();
        directory.execution_finished();
        drop(directory);
        assert!(!path.exists());
        assert_eq!(std::fs::read(sentinel).unwrap(), b"untouched");
    }

    #[test]
    fn verified_delivery_is_retained_until_its_acknowledgments_are_confirmed() {
        let parent = tempfile::tempdir().unwrap();
        for confirmed in [false, true] {
            let mut directory = recorded(parent.path());
            let path = directory.path().to_path_buf();
            std::fs::create_dir(path.join("delivery")).unwrap();
            // Only an explicit marker fixture: this unit does not claim to
            // validate delivery bytes or perform a worker acknowledgment.
            std::fs::write(path.join("delivery/delivery.json"), b"verified fixture").unwrap();
            directory.delivery_finished(confirmed);
            drop(directory);
            assert_eq!(path.exists(), !confirmed);
            if !confirmed {
                assert_eq!(
                    std::fs::read(path.join("delivery/delivery.json")).unwrap(),
                    b"verified fixture",
                );
                assert!(path.join("request.json").is_file());
            }
        }
    }

    #[test]
    fn retention_owner_can_cross_the_existing_blocking_lane_boundary() {
        let parent = tempfile::tempdir().unwrap();
        let directory = recorded(parent.path());
        let path = directory.path().to_path_buf();
        std::thread::spawn(move || drop(directory)).join().unwrap();
        assert!(path.join("request.json").is_file());
        assert!(path.join("recovery.json").is_file());
    }

    #[test]
    fn preparation_without_dispatch_keeps_existing_temporary_lifetime() {
        let parent = tempfile::tempdir().unwrap();
        let directory = ResultDirectory::new(parent.path()).unwrap();
        let path = directory.path().to_path_buf();
        drop(directory);
        assert!(!path.exists());
    }

    #[test]
    fn a_second_request_cannot_replace_recovery_identity_even_after_completion() {
        let parent = tempfile::tempdir().unwrap();
        let mut directory = recorded(parent.path());
        directory.execution_finished();
        let mut changed = request();
        changed["request_id"] = json!(18);
        assert_eq!(
            directory
                .record_request(&changed, "other-action", &configuration())
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists,
        );
        assert_eq!(
            std::fs::read(directory.path().join("request.json")).unwrap(),
            serde_json::to_vec(&request()).unwrap(),
        );
        assert!(directory.retention.is_none());
    }

    #[test]
    fn invalid_or_oversized_requests_never_arm_retention() {
        let parent = tempfile::tempdir().unwrap();
        let mut oversized = request();
        oversized["args"] = json!(["x".repeat(MAX_JSON_RECORD)]);
        for request in [json!({}), json!({"kind":"canonical-exec","request_id":0}), oversized] {
            let mut directory = ResultDirectory::new(parent.path()).unwrap();
            assert!(directory.record_request(&request, "action", &configuration()).is_err());
            assert!(directory.retention.is_none());
            assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        }
    }

    #[test]
    fn existing_request_is_never_overwritten_or_mistaken_for_prepared_intent() {
        let parent = tempfile::tempdir().unwrap();
        let mut directory = ResultDirectory::new(parent.path()).unwrap();
        let path = directory.path().join("request.json");
        std::fs::write(&path, b"prior bytes").unwrap();
        assert_eq!(
            directory.record_request(&request(), "action", &configuration()).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists,
        );
        assert!(directory.retention.is_none());
        assert_eq!(std::fs::read(path).unwrap(), b"prior bytes");
        assert!(!directory.path().join("recovery.json").exists());
    }

    #[cfg(panic = "unwind")]
    #[test]
    fn unwinding_after_handoff_retains_the_record_and_partial_result() {
        let parent = tempfile::tempdir().unwrap();
        let directory = recorded(parent.path());
        let path = directory.path().to_path_buf();
        let outcome = std::panic::catch_unwind(move || {
            let _directory = directory;
            panic!("transport owner panicked after possible execution");
        });
        assert!(outcome.is_err());
        assert!(path.join("request.json").is_file());
        assert!(path.join("recovery.json").is_file());
    }
}
