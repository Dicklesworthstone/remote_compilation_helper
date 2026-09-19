//! Durable admission and outcome reconciliation for the prototype worker.
//!
//! A request is recorded before its process may start. An interrupted admission
//! is uncertain, NOT permission to run it again. Even newer work is refused until
//! that uncertainty is resolved outside this prototype. Terminal receipts are
//! metadata only: they neither restore output bytes nor authorize publication.
//!
//! One private, local, fsync-capable state directory belongs to one worker and
//! coordinator endpoint. The held lock excludes overlapping local processes;
//! random incarnations and increasing boot generations do not authenticate peers
//! or protect against copied/restored state directories. ATP enrollment is still
//! required for those guarantees. Never delete this directory to retry a build.

use crate::session::sha256_hex;
use rabs_protocol::generation::{WorkerBootGeneration, WorkerIncarnationId};
use serde_json::{Value, json};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The wire capability names reconciliation of metadata, not output resumption.
pub const RECOVERY_PROTOCOL: &str = "request-journal-v1";
const MAX_STATE_BYTES: u64 = 64 * 1024;
const STATE_FILE: &str = "requests.json";
const LOCK_FILE: &str = "owner.lock";

/// Durable per-worker admission owner. Dropping it releases the process lock.
pub struct WorkerJournal {
    root: PathBuf,
    _lock: File,
    state: Value,
    poisoned: bool,
    #[cfg(test)]
    fail_after_rename: bool,
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn hex_string(value: &Value, digits: usize) -> bool {
    value.as_str().is_some_and(|text| {
        text.len() == digits && text.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn exact_fields(value: &Value, fields: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == fields.len() && fields.iter().all(|field| object.contains_key(*field))
    })
}

fn validate_state(state: &Value, worker: &str, coordinator: &str) -> io::Result<()> {
    if !exact_fields(state, &["version", "worker", "coordinator", "boot_generation", "incarnation", "last"])
        || state["version"].as_u64() != Some(1)
        || state["worker"].as_str() != Some(worker)
        || state["coordinator"].as_str() != Some(coordinator)
        || state["boot_generation"].as_u64().is_none_or(|generation| generation == 0)
        || !hex_string(&state["incarnation"], 32)
        || state["incarnation"] == "00000000000000000000000000000000"
    {
        return Err(invalid("invalid journal schema or worker/coordinator binding"));
    }
    let last = &state["last"];
    if last.is_null() {
        return Ok(());
    }
    if !exact_fields(last, &["request_id", "fingerprint", "boot_generation", "resolved", "receipt"])
        || last["request_id"].as_u64().is_none()
        || !hex_string(&last["fingerprint"], 64)
        || last["boot_generation"].as_u64().is_none_or(|generation| {
            generation == 0 || generation > state["boot_generation"].as_u64().unwrap_or(0)
        })
        || last["resolved"].as_bool().is_none()
        || (!last["receipt"].is_null() && !last["receipt"].is_object())
        || (last["resolved"] == true && last["receipt"].is_null())
        || (!last["receipt"].is_null() && last["receipt"]["request_id"] != last["request_id"])
    {
        return Err(invalid("invalid durable admission or terminal receipt"));
    }
    Ok(())
}

#[cfg(unix)]
fn private_path(path: &Path, directory: bool) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || metadata.is_dir() != directory
        || (!directory && (!metadata.is_file() || metadata.nlink() != 1))
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(invalid(format!("journal path must be private and ordinary: {}", path.display())));
    }
    Ok(())
}

#[cfg(not(unix))]
fn private_path(_path: &Path, _directory: bool) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "durable worker journal requires Unix filesystem semantics"))
}

fn fresh_incarnation() -> io::Result<String> {
    #[cfg(unix)]
    {
        let mut bytes = [0_u8; 16];
        File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        if bytes == [0; 16] {
            return Err(invalid("random worker incarnation was zero"));
        }
        Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
    }
    #[cfg(not(unix))]
    {
        Err(io::Error::new(io::ErrorKind::Unsupported, "no worker incarnation entropy source"))
    }
}

/// Digest the complete parsed wire request, including future extensions such as
/// artifact declarations, and its effective timeout. Unknown fields cannot be
/// accidentally omitted by a projection of only the original request struct.
/// The persisted fingerprint avoids recording raw argv or source paths.
#[must_use]
pub fn request_fingerprint(request: &Value, timeout: Duration) -> String {
    let framed = json!([
        "rabs.worker-request.v1", request,
        timeout.as_secs(), timeout.subsec_nanos()
    ]);
    sha256_hex(framed.to_string().as_bytes())
}

impl WorkerJournal {
    /// Acquire exclusive ownership, validate existing state, and durably mint the
    /// next boot generation before advertising this process to a coordinator.
    ///
    /// # Errors
    /// Refuses corrupt/missing prior state, an occupied lock, binding mismatch,
    /// unsupported storage, overflow, or any uncertain persistence operation.
    pub fn open(root: &Path, worker: &str, coordinator: &str) -> io::Result<Self> {
        if worker.is_empty() || coordinator.is_empty() {
            return Err(invalid("empty journal identity"));
        }
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(root)?;
        private_path(root, true)?;
        let root = std::fs::canonicalize(root)?;
        // Durably link any freshly-created directory ancestry as well as the
        // state file itself. A missing parent after power loss must not reset IDs.
        for ancestor in root.ancestors() {
            File::open(ancestor)?.sync_all()?;
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock_path = root.join(LOCK_FILE);
        let (lock, new_lock) = match options.open(&lock_path) {
            Ok(lock) => (lock, true),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                private_path(&lock_path, false)?;
                (OpenOptions::new().read(true).write(true).open(&lock_path)?, false)
            }
            Err(error) => return Err(error),
        };
        lock.try_lock()?;
        lock.sync_all()?;
        File::open(&root)?.sync_all()?;
        let path = root.join(STATE_FILE);
        let mut state = match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                private_path(&path, false)?;
                let mut bytes = Vec::new();
                File::open(&path)?.take(MAX_STATE_BYTES + 1).read_to_end(&mut bytes)?;
                if bytes.len() as u64 > MAX_STATE_BYTES {
                    return Err(invalid("journal exceeds storage bound"));
                }
                let state: Value = serde_json::from_slice(&bytes).map_err(|error| invalid(error.to_string()))?;
                validate_state(&state, worker, coordinator)?;
                state
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound && new_lock => json!({
                "version": 1, "worker": worker, "coordinator": coordinator,
                "boot_generation": 0, "incarnation": "", "last": null,
            }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(invalid("prior journal missing; refusing to reset execution history"));
            }
            Err(error) => return Err(error),
        };
        let generation = state["boot_generation"].as_u64().and_then(|value| value.checked_add(1))
            .ok_or_else(|| invalid("worker boot generation exhausted"))?;
        let incarnation = fresh_incarnation()?;
        if state["incarnation"] == incarnation {
            return Err(invalid("worker incarnation repeated"));
        }
        state["boot_generation"] = json!(generation);
        state["incarnation"] = json!(incarnation);
        let mut journal = Self {
            root, _lock: lock, state: Value::Null, poisoned: false,
            #[cfg(test)]
            fail_after_rename: false,
        };
        journal.store(state)?;
        Ok(journal)
    }

    /// Durable generation advertised in worker-hello.
    #[must_use]
    pub fn boot_generation(&self) -> WorkerBootGeneration {
        WorkerBootGeneration(self.state["boot_generation"].as_u64().expect("validated generation"))
    }

    /// Fresh process identity; not an authentication credential.
    #[must_use]
    pub fn incarnation(&self) -> WorkerIncarnationId {
        WorkerIncarnationId(u128::from_str_radix(
            self.state["incarnation"].as_str().expect("validated incarnation"), 16,
        ).expect("validated incarnation hex"))
    }

    /// Highest admitted ID, retained even after its result is acknowledged.
    #[must_use]
    pub fn high_water(&self) -> Option<u64> {
        self.state["last"]["request_id"].as_u64()
    }

    /// Durably reserve an execution before invoking any process-launch seam.
    /// `Ok(Some(reason))` refuses without modifying state; `Ok(None)` admits.
    ///
    /// # Errors
    /// Any persistence failure poisons this owner: no later admission is safe.
    pub fn admit(&mut self, request: &Value, timeout: Duration) -> io::Result<Option<&'static str>> {
        self.ensure_healthy()?;
        if request["kind"].as_str() != Some("canonical-exec") {
            return Err(invalid("only execution requests may acquire admission"));
        }
        let request_id = request["request_id"].as_u64()
            .ok_or_else(|| invalid("request lacks an unsigned identity"))?;
        let fingerprint = request_fingerprint(request, timeout);
        if let Some(last) = self.high_water() {
            if request_id == last {
                return Ok(Some(if self.state["last"]["fingerprint"] == fingerprint {
                    "durable-request-already-admitted"
                } else {
                    "durable-request-conflict"
                }));
            }
            if request_id < last {
                return Ok(Some("durable-request-retired"));
            }
            if self.state["last"]["resolved"] != true {
                return Ok(Some("prior-execution-uncertain"));
            }
        }
        let mut next = self.state.clone();
        next["last"] = json!({
            "request_id": request_id, "fingerprint": fingerprint,
            "boot_generation": self.boot_generation().0, "resolved": false, "receipt": null,
        });
        self.store(next)?;
        Ok(None)
    }

    /// Persist an observed terminal receipt before sending it over the wire.
    /// `resolved` means the process owner proved cleanup, NOT build success.
    /// A capture panic or unresolved descendants must pass false.
    ///
    /// # Errors
    /// Refuses a foreign/prior-boot receipt, conflicting completion, or unsafe IO.
    pub fn finish(&mut self, request_id: u64, receipt: &Value, resolved: bool) -> io::Result<()> {
        self.ensure_healthy()?;
        let last = &self.state["last"];
        if last["request_id"].as_u64() != Some(request_id)
            || last["boot_generation"].as_u64() != Some(self.boot_generation().0)
            || receipt["request_id"].as_u64() != Some(request_id)
            || !matches!(receipt["kind"].as_str(), Some("exec-result" | "error"))
        {
            return Err(invalid("terminal receipt does not own this admission"));
        }
        // Scratch paths and transfer advertisements never become durable output
        // references. The receipt only supports outcome reconciliation.
        let mut receipt = receipt.clone();
        if let Some(object) = receipt.as_object_mut() {
            for field in ["stdout_spill_path", "stderr_spill_path", "output_transfer", "output_ack_required"] {
                object.remove(field);
            }
        }
        if !last["receipt"].is_null() {
            return if last["receipt"] == receipt && last["resolved"] == resolved {
                Ok(())
            } else {
                Err(invalid("conflicting terminal receipt"))
            };
        }
        let mut next = self.state.clone();
        next["last"]["receipt"] = receipt;
        next["last"]["resolved"] = json!(resolved);
        self.store(next)
    }

    /// Reconciliation-only response. Never replay this as compiler output or a
    /// prepared result; anonymous diagnostic snapshots do not survive restart.
    #[must_use]
    pub fn status(&self, request_id: u64) -> Value {
        let current = self.high_water() == Some(request_id);
        let status = if self.poisoned {
            "journal-unavailable"
        } else if current && self.state["last"]["resolved"] == true {
            "terminal-observed"
        } else if current {
            "execution-uncertain"
        } else if self.high_water().is_some_and(|last| request_id < last) {
            "retired"
        } else {
            "unknown"
        };
        json!({
            "kind": "request-status", "request_id": request_id, "status": status,
            "high_water": self.high_water(), "replay_authorized": false,
            "output_recovery": "unavailable", "publication_authorized": false,
            "receipt": if current && !self.poisoned { self.state["last"]["receipt"].clone() } else { Value::Null },
        })
    }

    fn ensure_healthy(&self) -> io::Result<()> {
        if self.poisoned {
            Err(io::Error::other("journal persistence uncertain; restart required"))
        } else {
            Ok(())
        }
    }

    fn store(&mut self, next: Value) -> io::Result<()> {
        self.ensure_healthy()?;
        let result = (|| {
            let bytes = serde_json::to_vec(&next).map_err(|error| invalid(error.to_string()))?;
            if bytes.len() as u64 > MAX_STATE_BYTES {
                return Err(invalid("journal exceeds storage bound"));
            }
            let mut file = tempfile::NamedTempFile::new_in(&self.root)?;
            file.write_all(&bytes)?;
            file.as_file().sync_all()?;
            file.persist(self.root.join(STATE_FILE)).map_err(|error| error.error)?;
            #[cfg(test)]
            if self.fail_after_rename {
                return Err(io::Error::other("injected directory sync failure"));
            }
            File::open(&self.root)?.sync_all()?;
            Ok(())
        })();
        match result {
            Ok(()) => { self.state = next; Ok(()) }
            Err(error) => { self.poisoned = true; Err(error) }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn request(id: u64) -> Value {
        json!({
            "kind": "canonical-exec", "request_id": id, "program": "rustc",
            "args": ["private.rs"], "toolchain_backing": "/tc",
            "workspace_backing": "/ws", "jobserver_grant": 2,
        })
    }
    fn open(root: &Path) -> WorkerJournal { WorkerJournal::open(root, "worker", "coord:7000").unwrap() }
    fn receipt(id: u64) -> Value { json!({"kind": "exec-result", "request_id": id, "exit_code": 0}) }

    #[test]
    fn exclusive_owner_and_durable_generation_survive_restart() {
        let root = tempfile::tempdir().unwrap();
        let first = open(root.path());
        assert!(WorkerJournal::open(root.path(), "worker", "coord:7000").is_err());
        let incarnation = first.incarnation();
        assert_eq!(first.boot_generation().0, 1);
        drop(first);
        let second = open(root.path());
        assert_eq!(second.boot_generation().0, 2);
        assert_ne!(second.incarnation(), incarnation);
    }

    #[test]
    fn uncertain_execution_blocks_both_replay_and_new_work_after_restart() {
        let root = tempfile::tempdir().unwrap();
        let mut journal = open(root.path());
        assert_eq!(journal.admit(&request(10), Duration::from_secs(1)).unwrap(), None);
        drop(journal);
        let mut journal = open(root.path());
        assert_eq!(journal.status(10)["status"], "execution-uncertain");
        assert_eq!(journal.admit(&request(10), Duration::from_secs(1)).unwrap(), Some("durable-request-already-admitted"));
        assert_eq!(journal.admit(&request(11), Duration::from_secs(1)).unwrap(), Some("prior-execution-uncertain"));
        assert!(journal.finish(10, &receipt(10), true).is_err(), "new process cannot certify old cleanup");
    }

    #[test]
    fn terminal_reconciliation_never_promises_output_recovery_or_publication() {
        let root = tempfile::tempdir().unwrap();
        let mut journal = open(root.path());
        journal.admit(&request(1), Duration::from_secs(1)).unwrap();
        let mut done = receipt(1);
        done["stdout_spill_path"] = json!("/private/spill");
        done["output_transfer"] = json!("ranges-v1");
        journal.finish(1, &done, true).unwrap();
        journal.finish(1, &done, true).unwrap();
        assert!(journal.finish(1, &json!({"kind":"exec-result","request_id":1,"exit_code":1}), true).is_err());
        drop(journal);
        let mut journal = open(root.path());
        let status = journal.status(1);
        assert_eq!(status["status"], "terminal-observed");
        assert_eq!(status["publication_authorized"], false);
        assert_eq!(status["replay_authorized"], false);
        assert_eq!(status["output_recovery"], "unavailable");
        assert!(status["receipt"].get("stdout_spill_path").is_none());
        assert_eq!(journal.admit(&request(2), Duration::from_secs(1)).unwrap(), None);
        assert_eq!(journal.status(1)["status"], "retired");
        assert_eq!(journal.admit(&request(1), Duration::from_secs(1)).unwrap(), Some("durable-request-retired"));
    }

    #[test]
    fn changed_request_and_budget_cannot_reuse_an_identity() {
        let root = tempfile::tempdir().unwrap();
        let mut journal = open(root.path());
        let original = request(3);
        journal.admit(&original, Duration::from_secs(1)).unwrap();
        let mut changed = original.clone();
        changed["args"] = json!(["private.rs", "--cfg=changed"]);
        for (request, timeout) in [(&changed, Duration::from_secs(1)), (&original, Duration::from_secs(2))] {
            assert_eq!(journal.admit(request, timeout).unwrap(), Some("durable-request-conflict"));
        }
        let persisted = std::fs::read_to_string(root.path().join(STATE_FILE)).unwrap();
        assert!(!persisted.contains("private.rs"));
    }

    #[test]
    fn failed_directory_sync_poisoning_preserves_admission_after_reopen() {
        let root = tempfile::tempdir().unwrap();
        let mut journal = open(root.path());
        journal.fail_after_rename = true;
        assert!(journal.admit(&request(8), Duration::from_secs(1)).is_err());
        assert!(journal.admit(&request(9), Duration::from_secs(1)).is_err());
        assert_eq!(journal.status(8)["status"], "journal-unavailable");
        drop(journal);
        let mut journal = open(root.path());
        assert_eq!(journal.high_water(), Some(8));
        assert_eq!(journal.admit(&request(9), Duration::from_secs(1)).unwrap(), Some("prior-execution-uncertain"));
    }

    #[test]
    fn corrupt_state_and_wrong_bindings_never_reset_history() {
        let root = tempfile::tempdir().unwrap();
        drop(open(root.path()));
        assert!(WorkerJournal::open(root.path(), "other", "coord:7000").is_err());
        assert!(WorkerJournal::open(root.path(), "worker", "other:7000").is_err());
        let path = root.path().join(STATE_FILE);
        let valid = std::fs::read(&path).unwrap();
        for bad in [b"{".to_vec(), vec![b' '; MAX_STATE_BYTES as usize + 1]] {
            std::fs::write(&path, bad).unwrap();
            assert!(WorkerJournal::open(root.path(), "worker", "coord:7000").is_err());
        }
        let mut exhausted: Value = serde_json::from_slice(&valid).unwrap();
        exhausted["boot_generation"] = json!(u64::MAX);
        std::fs::write(&path, exhausted.to_string()).unwrap();
        assert!(WorkerJournal::open(root.path(), "worker", "coord:7000").is_err());
    }

    #[test]
    fn missing_prior_state_and_symlink_state_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let lock = OpenOptions::new().write(true).create_new(true).open(root.path().join(LOCK_FILE)).unwrap();
        use std::os::unix::fs::{PermissionsExt, symlink};
        lock.set_permissions(std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(WorkerJournal::open(root.path(), "worker", "coord:7000").is_err());
        let target = root.path().join("elsewhere");
        std::fs::write(&target, "{}").unwrap();
        symlink(&target, root.path().join(STATE_FILE)).unwrap();
        assert!(WorkerJournal::open(root.path(), "worker", "coord:7000").is_err());
        assert_eq!(std::fs::read_to_string(target).unwrap(), "{}");
    }

    #[test]
    fn unresolved_terminal_error_does_not_authorize_new_work() {
        let root = tempfile::tempdir().unwrap();
        let mut journal = open(root.path());
        journal.admit(&request(1), Duration::from_secs(1)).unwrap();
        journal.finish(1, &json!({"kind":"error","request_id":1,"execution_may_have_run":true}), false).unwrap();
        assert_eq!(journal.status(1)["status"], "execution-uncertain");
        assert_eq!(journal.admit(&request(2), Duration::from_secs(1)).unwrap(), Some("prior-execution-uncertain"));
    }
}
