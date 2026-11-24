//! Operator vertical slice: retained source -> verified delivery -> private outputs.
//! The delivery receipt is the recovery boundary. Installation may be retried
//! offline, and an uncertain execution is never converted into another dispatch.

use super::{
    Delivery, DeliveryFailure, DeliveryMode, DeliveryTrust, Digest, Sha256, TlsOperationControl,
    WorkerOperation, invalid, operation_arguments, operation_failure, prepare_resume_source,
    read_request, recover_existing_delivery, request_manifest, run_loopback_operation,
    run_tls_operation, run_tls_operation_inner,
};
use crate::prepared_jobs::ClientDeadline;
use rabsd::coord::delivery_recovery::{InstalledOutputs, install_delivery_outputs};
use rabsd::coord::prepared_operation::DiagnosticSnapshot;
use rabsd::coord::secure_worker_delivery::{PinnedWorkerAdmission, parse_worker_pin};
use serde_json::{Value, json};
use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

const DIAGNOSTIC_REPLAY_BUDGET: Duration = Duration::from_secs(300);

mod live;

/// Own process interruption through both worker cleanup and the final console
/// writes. Runtime signal handlers can outlive their last receiver, so returning
/// from authenticated delivery does not restore the process default actions.
#[cfg(target_os = "linux")]
struct ReportSignals {
    cancellation: super::OperationCancellation,
    stopped: std::sync::Arc<std::sync::atomic::AtomicBool>,
    first_signal: std::sync::Arc<std::sync::atomic::AtomicI32>,
    handle: signal_hook::iterator::Handle,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(target_os = "linux")]
impl ReportSignals {
    fn start() -> io::Result<Self> {
        use signal_hook::consts::signal::{SIGINT, SIGTERM};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

        let mut signals = signal_hook::iterator::Signals::new([SIGINT, SIGTERM])?;
        let handle = signals.handle();
        let cancellation = super::OperationCancellation::new();
        let stopped = Arc::new(AtomicBool::new(false));
        let first_signal = Arc::new(AtomicI32::new(0));
        let child_cancellation = cancellation.clone();
        let child_stopped = Arc::clone(&stopped);
        let child_signal = Arc::clone(&first_signal);
        let thread = std::thread::Builder::new()
            .name("rabs-direct-report-signals".into())
            .spawn(move || {
                let observe = |signal| {
                    if child_signal
                        .compare_exchange(0, signal, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        child_stopped.store(true, Ordering::Release);
                        child_cancellation.cancel();
                    }
                };
                for signal in signals.forever() {
                    observe(signal);
                }
                // Closing the iterator must not discard a signal already
                // delivered while the last console write was completing.
                for signal in signals.pending() {
                    observe(signal);
                }
            })?;
        Ok(Self {
            cancellation,
            stopped,
            first_signal,
            handle,
            thread: Some(thread),
        })
    }

    fn join(&mut self) {
        self.handle.close();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }

    fn finish(mut self) -> Option<i32> {
        self.join();
        match self.first_signal.load(std::sync::atomic::Ordering::Acquire) {
            0 => None,
            signal => Some(signal),
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for ReportSignals {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.join();
    }
}

/// Carries the original exclusive worker admission from allocation to transport.
/// Allocation is not authentication or execution authority. Only the normal
/// pinned TLS/challenge path can grant those. The prepared request is bound
/// before any later reopening, so a changed bundle cannot spend this reservation.
pub(super) struct ReservedWorkerAdmission {
    owner: PinnedWorkerAdmission,
    worker: String,
    pin: [u8; 32],
    request_id: u64,
    request_sha256: Option<String>,
}

impl std::fmt::Debug for ReservedWorkerAdmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReservedWorkerAdmission")
            .field("worker", &self.worker)
            .field("request_id", &self.request_id)
            .field("prepared", &self.request_sha256.is_some())
            .finish_non_exhaustive()
    }
}

impl ReservedWorkerAdmission {
    fn open(state: &Path, worker: &str, pin: [u8; 32]) -> io::Result<Self> {
        let owner = PinnedWorkerAdmission::open(state, worker, pin)?;
        let request_id = owner.allocate_request_id()?;
        Ok(Self {
            owner,
            worker: worker.to_owned(),
            pin,
            request_id,
            request_sha256: None,
        })
    }

    fn bind_prepared(&mut self, report: &Value) -> io::Result<()> {
        let digest = report["request_sha256"]
            .as_str()
            .filter(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .ok_or_else(|| invalid("prepared request has no canonical digest"))?;
        if self.request_sha256.is_some()
            || report["kind"] != "prepared-source-bundle"
            || report["request_id"].as_u64() != Some(self.request_id)
        {
            return Err(invalid("preparation differs from its worker reservation"));
        }
        self.request_sha256 = Some(digest.to_owned());
        Ok(())
    }

    fn bind_request(&mut self, request: &Value) -> io::Result<()> {
        super::validate_request(request)?;
        if self.request_sha256.is_some() || request["request_id"].as_u64() != Some(self.request_id)
        {
            return Err(invalid(
                "daemon request differs from its worker reservation",
            ));
        }
        self.request_sha256 = Some(
            Sha256::digest(serde_json::to_vec(request)?)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        );
        Ok(())
    }

    fn validate_identity(&self, worker: &str, pin: &str, request_id: &Value) -> io::Result<()> {
        if worker != self.worker
            || parse_worker_pin(pin)? != self.pin
            || request_id.as_u64() != Some(self.request_id)
            || self.request_sha256.is_none()
        {
            return Err(invalid(
                "request differs from its reserved worker admission",
            ));
        }
        Ok(())
    }

    pub(super) fn validate_request(
        &self,
        worker: &str,
        pin: &str,
        request: &Value,
    ) -> io::Result<()> {
        self.validate_identity(worker, pin, &request["request_id"])?;
        let digest: String = Sha256::digest(serde_json::to_vec(request)?)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        if self.request_sha256.as_deref() != Some(digest.as_str()) {
            return Err(invalid("prepared request changed after worker reservation"));
        }
        Ok(())
    }

    pub(super) fn into_admission(
        self,
        worker: &str,
        pin: &str,
        request_id: &Value,
    ) -> io::Result<PinnedWorkerAdmission> {
        self.validate_identity(worker, pin, request_id)?;
        Ok(self.owner)
    }
}

/// Reject links in every existing ancestor, and require the immediate parent of
/// a new directory to exist. The installer still publishes exclusively against
/// destination-creation races. The operator owns these paths during the command.
fn ordinary_directory(path: &Path, allow_missing: bool) -> io::Result<()> {
    named_directory(path)?;
    let mut prefix = PathBuf::new();
    for part in path.components() {
        prefix.push(part.as_os_str());
        match fs::symlink_metadata(&prefix) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => return Err(invalid("build path contains a link or non-directory")),
            Err(error)
                if allow_missing && prefix == path && error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn named_directory(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || !path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(invalid(
            "build directories must be named absolute paths without traversal",
        ));
    }
    Ok(())
}

struct PreparedBuild<'a> {
    address: &'a str,
    worker: &'a str,
    pin: Option<&'a str>,
    bundle: &'a Path,
    directory: &'a Path,
    output: &'a Path,
    mode: DeliveryMode,
    resume_from: Option<&'a Path>,
}

impl PreparedBuild<'_> {
    fn validate_preparation(&self, source: &str) -> io::Result<()> {
        if self.mode != DeliveryMode::Execute || self.resume_from.is_some() {
            return Err(invalid(
                "source preparation cannot be combined with result recovery",
            ));
        }
        // Validate placement/trust before copying source or a large toolchain.
        let address: std::net::SocketAddr = self
            .address
            .parse()
            .map_err(|_| invalid("listen must be a literal IP:port"))?;
        match self.pin {
            Some(pin) => {
                parse_worker_pin(pin)?;
            }
            None if !address.ip().is_loopback() => {
                return Err(invalid("plaintext worker execution requires loopback"));
            }
            None => {}
        }
        self.validate_paths(false)?;
        ordinary_directory(Path::new(source), false)?;
        for destination in [self.bundle, self.directory, self.output] {
            ordinary_directory(destination, true)?;
            if destination.starts_with(source) || Path::new(source).starts_with(destination) {
                return Err(invalid(
                    "build destinations must not overlap the source anchor",
                ));
            }
            match fs::symlink_metadata(destination) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
                Ok(_) => {
                    return Err(invalid(
                        "prepare-from requires new bundle, delivery and output directories; recover the existing operation without prepare-from",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Preparation and execution share this one CLI process. In particular,
    /// do not start a second orchestration child between a mutable checkout
    /// and the existing retained-request execution/recovery boundary.
    fn prepare_from(
        &self,
        source: &str,
        specification: &str,
        state: &Path,
        live_stderr: bool,
    ) -> io::Result<Option<ReservedWorkerAdmission>> {
        self.validate_preparation(source)?;
        let mut reserved = None;
        // Only this combined TLS operation may replace explicit local allocation
        // intent. Saved numeric requests, standalone preparation, and recovery
        // never acquire another identity. A failed capture burns its allocation.
        let report = crate::prepare_from_arguments_with(
            &[
                source.to_owned(),
                specification.to_owned(),
                self.bundle
                    .to_str()
                    .ok_or_else(|| invalid("bundle path must be UTF-8"))?
                    .to_owned(),
            ],
            |specification| {
                if live_stderr {
                    live::validate_request(specification)?;
                }
                if specification["request_id"].as_str() != Some("allocate") {
                    return Ok(());
                }
                if specification["kind"] != "canonical-exec" {
                    return Err(invalid("request allocation requires new execution intent"));
                }
                let pin = self.pin.ok_or_else(|| {
                    invalid("request allocation requires combined pinned TLS preparation")
                })?;
                self.validate_allocation_state(state, source, specification)?;
                let allocation =
                    ReservedWorkerAdmission::open(state, self.worker, parse_worker_pin(pin)?)?;
                specification["request_id"] = json!(allocation.request_id);
                reserved = Some(allocation);
                Ok(())
            },
        )?;
        if let Some(reserved) = &mut reserved {
            reserved.bind_prepared(&report)?;
        }
        // The normal build path reopens and validates that exact retained
        // request and its source bytes before any execution write. It does not
        // recapture the original checkout or trust this informational event.
        crate::prepared_jobs::write_client_status(
            json!({"kind":"worker-build-prepared", "bundle":self.bundle,
                "request_id":report["request_id"],
                "execution_may_have_run":false, "publication_authorized":false}),
        )?;
        Ok(reserved)
    }

    /// Keep allocation metadata outside the source anchor, compiler tree and
    /// new outputs. Existing state ancestors may not be filesystem aliases.
    fn validate_allocation_state(
        &self,
        state: &Path,
        source: &str,
        spec: &Value,
    ) -> io::Result<()> {
        named_directory(state)?;
        let mut prefix = PathBuf::new();
        for component in state.components() {
            prefix.push(component.as_os_str());
            match fs::symlink_metadata(&prefix) {
                Ok(meta) if meta.is_dir() => {}
                Ok(_) => return Err(invalid("worker allocation state has a filesystem alias")),
                Err(error) if error.kind() == io::ErrorKind::NotFound => break,
                Err(error) => return Err(error),
            }
        }
        let overlaps = |path: &Path| state.starts_with(path) || path.starts_with(state);
        if [Path::new(source), self.bundle, self.directory, self.output]
            .into_iter()
            .any(overlaps)
        {
            return Err(invalid(
                "worker allocation state overlaps build inputs or outputs",
            ));
        }
        if let Some(toolchain) = spec.get("toolchain_source").and_then(Value::as_str) {
            let toolchain = fs::canonicalize(toolchain)?;
            if overlaps(&toolchain) {
                return Err(invalid("worker allocation state overlaps the toolchain"));
            }
        }
        Ok(())
    }

    fn failure(&self, detail: String) -> DeliveryFailure {
        operation_failure(self.directory, self.mode, detail)
    }

    fn validate_paths(&self, require_bundle: bool) -> io::Result<()> {
        named_directory(self.bundle)?;
        if require_bundle {
            ordinary_directory(self.bundle, false)?;
        }
        ordinary_directory(self.directory, true)?;
        ordinary_directory(self.output, true)?;
        for (left, right) in [
            (self.bundle, self.directory),
            (self.bundle, self.output),
            (self.directory, self.output),
        ] {
            if left.starts_with(right) || right.starts_with(left) {
                return Err(invalid(
                    "bundle, delivery and output directories must not overlap",
                ));
            }
        }
        Ok(())
    }

    fn request(&self) -> Result<Value, DeliveryFailure> {
        let preflight = || -> io::Result<Value> {
            self.validate_paths(true)?;
            let path = self.bundle.join("request.json");
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.is_file() || metadata.len() > super::MAX_FRAME_BYTES as u64 {
                return Err(invalid("prepared request must be a bounded ordinary file"));
            }
            let request = read_request(&path)?;
            if request_manifest(&request)?.is_none() || request.get("artifacts").is_none() {
                return Err(invalid(
                    "prepared builds require a source_manifest and declared artifacts",
                ));
            }
            Ok(request)
        };
        preflight().map_err(|error| self.failure(error.to_string()))
    }

    fn execute(
        &self,
        reserved: Option<ReservedWorkerAdmission>,
    ) -> Result<(Delivery, Option<InstalledOutputs>), DeliveryFailure> {
        let request = self.request()?;
        self.execute_bound(&request, None, reserved)
    }

    /// The daemon supplies the exact request it durably accepted. Neither its
    /// queued identity nor its recovery path is reloaded from request.json.
    fn execute_bound(
        &self,
        request: &Value,
        control: Option<TlsOperationControl<'_>>,
        reserved: Option<ReservedWorkerAdmission>,
    ) -> Result<(Delivery, Option<InstalledOutputs>), DeliveryFailure> {
        if let Some(reserved) = &reserved {
            let pin = self.pin.ok_or_else(|| {
                self.failure("reserved request cannot select plaintext execution".into())
            })?;
            if self.mode != DeliveryMode::Execute || self.resume_from.is_some() {
                return Err(self.failure("request allocation is not result recovery".into()));
            }
            reserved
                .validate_request(self.worker, pin, request)
                .map_err(|error| self.failure(error.to_string()))?;
        }
        self.validate_paths(false)
            .map_err(|error| self.failure(error.to_string()))?;
        super::validate_request(request).map_err(|error| self.failure(error.to_string()))?;
        if request_manifest(request)
            .map_err(|error| self.failure(error.to_string()))?
            .is_none()
            || request.get("artifacts").is_none()
        {
            return Err(
                self.failure("prepared builds require source_manifest and artifacts".to_owned())
            );
        }
        let trust = match self.pin {
            Some(pin) => DeliveryTrust::PinnedWorker(
                parse_worker_pin(pin).map_err(|error| self.failure(error.to_string()))?,
            ),
            None => DeliveryTrust::Loopback,
        };
        // A complete receipt is sufficient even if source, credentials, or the
        // worker are gone. Incomplete/mismatched receipts refuse here, before
        // the absence of an output directory could suggest fresh execution.
        let delivery = match recover_existing_delivery(request, self.worker, self.directory, trust)?
        {
            Some(delivery) => delivery,
            None => {
                if control
                    .as_ref()
                    .is_some_and(|control| control.cancellation.is_cancelled())
                {
                    return Err(
                        self.failure("prepared operation cancelled before dispatch".to_owned())
                    );
                }
                match fs::symlink_metadata(self.output) {
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    // Explicit recovery cannot execute. Its newly verified
                    // result must still match every byte/mode already installed
                    // before the installer may reuse this ordinary directory.
                    Ok(_) if self.mode == DeliveryMode::Resume => {}
                    Ok(_) => return Err(self.failure(
                        "output directory already exists without a verified delivery; refusing dispatch".to_owned(),
                    )),
                    Err(error) => return Err(self.failure(error.to_string())),
                }
                // Local reuse remains read-only through BOTH delivery and later
                // output installation. Complete local recovery above does not
                // depend on this old directory continuing to exist.
                if let Some(reuse) =
                    prepare_resume_source(self.mode, self.resume_from, self.directory)
                        .map_err(|error| self.failure(error.to_string()))?
                {
                    for path in [self.bundle, self.output] {
                        reuse
                            .validate_destination(path)
                            .map_err(|error| self.failure(error.to_string()))?;
                    }
                }
                let source = self.bundle.join("source");
                let toolchain = self.bundle.join("toolchain");
                let source_root = if self.mode == DeliveryMode::Execute {
                    ordinary_directory(&source, false)
                        .map_err(|error| self.failure(error.to_string()))?;
                    Some(source.as_path())
                } else {
                    None
                };
                let operation = WorkerOperation {
                    address: self.address,
                    worker: self.worker,
                    request,
                    directory: self.directory,
                    mode: self.mode,
                    source_root,
                    toolchain_root: (self.mode == DeliveryMode::Execute
                        && request.get("toolchain_transfer").is_some())
                    .then_some(toolchain.as_path()),
                    resume_from: self.resume_from,
                };
                match self.pin {
                    Some(pin) if control.is_some() || reserved.is_some() => {
                        run_tls_operation_inner(operation, pin, control, reserved)?
                    }
                    Some(pin) => run_tls_operation(operation, pin)?,
                    None => run_loopback_operation(operation)?,
                }
            }
        };
        // Retain diagnostics and the original compiler status on failure. Partial
        // artifacts from a failed or interrupted build are never installed.
        if delivery.receipt["exit_code"] != 0 || !delivery.receipt["stop_reason"].is_null() {
            return Ok((delivery, None));
        }
        let installed =
            install_delivery_outputs(request, self.worker, self.directory, self.output, trust)
                .map_err(|detail| DeliveryFailure {
                    directory: self.directory.to_path_buf(),
                    execution_may_have_run: true,
                    transport_interrupted: false,
                    sealed_result: None,
                    detail,
                })?;
        Ok((delivery, Some(installed)))
    }

    #[cfg(target_os = "linux")]
    fn execute_with_report_signals(
        &self,
        signals: &ReportSignals,
        reserved: Option<ReservedWorkerAdmission>,
    ) -> Result<(Delivery, Option<InstalledOutputs>), DeliveryFailure> {
        let request = self.request()?;
        let mut on_listening = |address: std::net::SocketAddr| {
            // Cancellation must also release a blocked listener announcement,
            // before accept or an authenticated request can acquire ownership.
            let mut stderr = rabsd::ControlledOutput::new(
                &io::stderr(),
                &signals.stopped,
                Instant::now() + super::ACCEPT_BUDGET,
            )?;
            writeln!(
                stderr,
                "{}",
                json!({
                    "kind":"worker-exec-listening", "address":address.to_string(),
                    "expected_worker":self.worker, "expected_worker_spki_sha256":self.pin,
                    "request_id":request["request_id"], "transport":"mutual-tls-atp",
                    "operation":if self.mode == DeliveryMode::Resume { "result-resume" } else { "canonical-exec" },
                    "authentication_required":true,
                })
            )?;
            stderr.flush()
        };
        self.execute_bound(
            &request,
            Some(TlsOperationControl {
                cancellation: signals.cancellation.clone(),
                preview: None,
                on_listening: &mut on_listening,
            }),
            reserved,
        )
    }

    fn report(&self, replay_diagnostics: bool, reserved: Option<ReservedWorkerAdmission>) -> i32 {
        let uninterrupted = std::sync::atomic::AtomicBool::new(false);
        #[cfg(target_os = "linux")]
        let signals = match self.pin.map(|_| ReportSignals::start()).transpose() {
            Ok(signals) => signals,
            Err(error) => {
                let error = self.failure(error.to_string());
                crate::prepared_jobs::report_client_error(json!({
                    "kind":"worker-build-error", "directory":error.directory,
                    "output_directory":self.output, "detail":error.detail,
                    "execution_may_have_run":error.execution_may_have_run, "reexecute":false,
                    "diagnostics_may_have_been_exposed":false,
                }));
                return 1;
            }
        };
        #[cfg(target_os = "linux")]
        let stopped = signals
            .as_ref()
            .map_or(&uninterrupted, |signals| signals.stopped.as_ref());
        #[cfg(not(target_os = "linux"))]
        let stopped = &uninterrupted;
        #[cfg(target_os = "linux")]
        let execution = match &signals {
            Some(signals) => self.execute_with_report_signals(signals, reserved),
            None => self.execute(reserved),
        };
        #[cfg(not(target_os = "linux"))]
        let execution = self.execute(reserved);

        let mut diagnostics_may_have_been_exposed = false;
        #[cfg(target_os = "linux")]
        let mut console_interrupted = false;
        let result = execution.and_then(|(delivery, installed)| {
            let report = self.report_value(&delivery, installed.as_ref());
            let failed = |error: io::Error| DeliveryFailure {
                directory: self.directory.to_path_buf(),
                execution_may_have_run: true,
                transport_interrupted: false,
                sealed_result: None,
                detail: format!(
                    "build completed but its console output could not be delivered: {error}"
                ),
            };
            let deadline = ClientDeadline::new(Instant::now() + DIAGNOSTIC_REPLAY_BUDGET);
            let diagnostics = if replay_diagnostics {
                // The execution/recovery path has already verified this entire
                // delivery. Capture and hash BOTH streams again before exposing
                // either, so corruption cannot print only half a compiler result.
                let snapshot =
                    DiagnosticSnapshot::from_delivery(&delivery, deadline.get()).map_err(failed)?;
                diagnostics_may_have_been_exposed = true;
                Some(snapshot)
            } else {
                None
            };
            emit_client_report(&report, diagnostics, &deadline, stopped).map_err(|error| {
                #[cfg(target_os = "linux")]
                {
                    console_interrupted = error.kind() == io::ErrorKind::Interrupted;
                }
                failed(error)
            })?;
            let code = delivery.receipt["exit_code"]
                .as_i64()
                .and_then(|code| i32::try_from(code).ok())
                .unwrap_or(1);
            Ok(if code == 0 && installed.is_none() {
                1
            } else {
                code
            })
        });
        #[cfg(target_os = "linux")]
        if let Some(signal_number) = signals.and_then(ReportSignals::finish) {
            // All transport/output owners have returned before native relay.
            // An uncertain worker result or failed verification stays an error;
            // only a settled delivery (or a proven pre-dispatch stop) can relay.
            if result.is_ok()
                || console_interrupted
                || result
                    .as_ref()
                    .err()
                    .is_some_and(|error| !error.execution_may_have_run)
            {
                rabsd::coord::canonical_local::exit_like(
                    rabs_protocol::subscriber_interest::ChildTermination::Signaled {
                        signal_number,
                    },
                );
            }
        }
        match result {
            Ok(code) => code,
            Err(error) => {
                crate::prepared_jobs::report_client_error(json!({
                    "kind":"worker-build-error", "directory":error.directory,
                    "output_directory":self.output, "detail":error.detail,
                    "execution_may_have_run":error.execution_may_have_run, "reexecute":false,
                    "diagnostics_may_have_been_exposed":diagnostics_may_have_been_exposed,
                }));
                1
            }
        }
    }

    fn report_value(&self, delivery: &Delivery, installed: Option<&InstalledOutputs>) -> Value {
        json!({
            "kind":"worker-build", "bundle":self.bundle, "delivery":delivery.to_json(),
            "installed_outputs":installed.map(InstalledOutputs::to_json),
            "publication_authorized":false, "reexecute":false,
        })
    }
}

/// Bound the console writes themselves as well as diagnostic verification. A
/// full pipe must not strand a completed build or renew its replay budget.
fn emit_client_report(
    report: &Value,
    diagnostics: Option<DiagnosticSnapshot>,
    deadline: &ClientDeadline,
    stopped: &std::sync::atomic::AtomicBool,
) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        emit_client_report_to(
            report,
            diagnostics,
            &io::stdout(),
            &io::stderr(),
            deadline,
            stopped,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = stopped;
        emit_report(
            report,
            diagnostics,
            &mut io::stdout().lock(),
            &mut io::stderr().lock(),
            deadline.get(),
        )
    }
}

#[cfg(target_os = "linux")]
fn emit_client_report_to(
    report: &Value,
    diagnostics: Option<DiagnosticSnapshot>,
    stdout: &impl std::os::fd::AsFd,
    stderr: &impl std::os::fd::AsFd,
    deadline: &ClientDeadline,
    stopped: &std::sync::atomic::AtomicBool,
) -> io::Result<()> {
    if let Some(snapshot) = diagnostics {
        crate::prepared_jobs::client_console_to(
            stdout,
            stderr,
            deadline,
            stopped,
            |mut stdout, mut stderr| {
                emit_report(
                    report,
                    Some(snapshot),
                    &mut stdout,
                    &mut stderr,
                    deadline.get(),
                )
            },
        )
    } else {
        // Native JSON owns only stdout. An unused closed or read-only stderr
        // cannot turn a successfully delivered report into a build failure.
        crate::prepared_jobs::client_stdout_to(stdout, deadline, stopped, |mut stdout| {
            emit_report(report, None, &mut stdout, &mut io::sink(), deadline.get())
        })
    }
}

/// Keep stdout entirely in the selected contract: the native JSON report, or
/// the exact worker stdout. Diagnostic mode moves only our status to stderr;
/// retained compiler/test bytes are never decoded, reformatted or retried.
fn emit_report(
    report: &Value,
    diagnostics: Option<DiagnosticSnapshot>,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    until: Instant,
) -> io::Result<()> {
    if let Some(snapshot) = diagnostics {
        snapshot.emit(stdout, stderr, until)?;
        writeln!(stderr, "{report}")?;
        stderr.flush()
    } else {
        writeln!(stdout, "{report}")?;
        stdout.flush()
    }
}

fn run(args: &[String], tls: bool) -> i32 {
    let (args, replay_diagnostics) = match args {
        [flag, rest @ ..] if flag == "--replay-diagnostics" => (rest, true),
        _ => (args, false),
    };
    let (args, live_stderr) = match args {
        [flag, rest @ ..] if flag == "--live-stderr" => (rest, true),
        _ => (args, false),
    };
    if live_stderr && (!tls || !replay_diagnostics) {
        crate::prepared_jobs::report_client_error(
            "--live-stderr requires --worker-build-tls --replay-diagnostics",
        );
        return 2;
    }
    if live_stderr && !cfg!(target_os = "linux") {
        crate::prepared_jobs::report_client_error(
            "direct --live-stderr requires Linux bounded console support",
        );
        return 2;
    }
    let (args, preparation) = match args {
        [flag, source, specification, rest @ ..] if flag == "--prepare-from" => {
            (rest, Some((source.as_str(), specification.as_str())))
        }
        _ => (args, None),
    };
    let count = if tls { 6 } else { 5 };
    let Some((args, mode, resume_from)) =
        operation_arguments(args, count).filter(|(args, mode, resume_from)| {
            (preparation.is_none() || (*mode == DeliveryMode::Execute && resume_from.is_none()))
                && args
                    .iter()
                    .all(|arg| !arg.is_empty() && !arg.starts_with("--"))
        })
    else {
        eprintln!(
            "usage: rabsd --worker-build-{} [--replay-diagnostics [--live-stderr]] [--prepare-from <absolute-source-root> <spec.json> | --resume | --resume-from <absolute-old-delivery>] <IP:port> <worker> {}<absolute-bundle-directory> <absolute-delivery-directory> <absolute-output-directory>",
            if tls { "tls" } else { "loopback" },
            if tls { "<worker-spki-sha256> " } else { "" }
        );
        eprintln!(
            "The bundle supplies request.json and source/. New execution installs successful verified outputs; resume retrieves a retained result without source upload or execution. --resume-from may reuse independently verified local prefixes in a NEW delivery directory. --replay-diagnostics replays the complete verified stdout/stderr on success or failure, with the JSON build report on stderr."
        );
        return 2;
    };
    let offset = if tls { 3 } else { 2 };
    let build = PreparedBuild {
        address: &args[0],
        worker: &args[1],
        pin: tls.then(|| args[2].as_str()),
        bundle: Path::new(&args[offset]),
        directory: Path::new(&args[offset + 1]),
        output: Path::new(&args[offset + 2]),
        mode,
        resume_from,
    };
    let reserved = if let Some((source, specification)) = preparation {
        match build.prepare_from(
            source,
            specification,
            &super::worker_admission_state(),
            live_stderr,
        ) {
            Ok(reserved) => reserved,
            Err(error) => {
                crate::prepared_jobs::report_client_error(
                    json!({"kind":"worker-build-prepare-error", "bundle":build.bundle,
                        "directory":build.directory, "output_directory":build.output,
                        "detail":error.to_string(), "execution_may_have_run":false,
                        "publication_authorized":false, "reexecute":false}),
                );
                return 1;
            }
        }
    } else {
        None
    };
    if live_stderr {
        build.report_live(reserved)
    } else {
        build.report(replay_diagnostics, reserved)
    }
}

pub fn run_build(args: &[String]) -> i32 {
    run(args, false)
}
pub fn run_build_tls(args: &[String]) -> i32 {
    run(args, true)
}

/// The foreground daemon client captures only immutable inputs. No worker ID is
/// allocated until the existing durable queue claims this exact template.
pub fn prepare_daemon_build(
    spec: &rabsd::coord::prepared_operation::PreparedOperationSpec,
    source: &str,
    specification: &str,
    live_stderr: bool,
) -> io::Result<Value> {
    let build = PreparedBuild {
        address: &spec.address,
        worker: &spec.worker,
        pin: Some(&spec.worker_spki_sha256),
        bundle: &spec.bundle,
        directory: &spec.delivery,
        output: &spec.output,
        mode: DeliveryMode::Execute,
        resume_from: None,
    };
    build.validate_preparation(source)?;
    crate::prepare_template_from_arguments(
        &[
            source.to_owned(),
            specification.to_owned(),
            spec.bundle
                .to_str()
                .ok_or_else(|| invalid("bundle path must be UTF-8"))?
                .to_owned(),
        ],
        |request| {
            // Use the exact bounded specification which capture will consume.
            // Unsupported live presentation must refuse before even a source
            // bundle is produced, and therefore before daemon submission.
            if live_stderr && rabs_sandbox::cargo_artifacts::requested(request)?.is_none() {
                return Err(invalid(
                    "live stderr requires the native whole-Cargo diagnostics contract",
                ));
            }
            Ok(())
        },
    )
}

/// Run one durable daemon claim without writing CLI output or subscribing to
/// process signals. The caller owns a dedicated blocking thread and persists
/// the returned outcome through `OperationClaim::finish` before releasing it.
pub fn execute_prepared_operation(
    claim: &mut rabsd::coord::prepared_operation::OperationClaim,
) -> rabsd::coord::prepared_operation::OperationOutcome {
    use rabsd::coord::prepared_operation::OperationOutcome;
    let reserved = if claim.needs_request_allocation() {
        let mut allocate = || -> io::Result<ReservedWorkerAdmission> {
            let spec = claim.spec();
            let state = super::worker_admission_state();
            let build = PreparedBuild {
                address: &spec.address,
                worker: &spec.worker,
                pin: Some(&spec.worker_spki_sha256),
                bundle: &spec.bundle,
                directory: &spec.delivery,
                output: &spec.output,
                mode: DeliveryMode::Execute,
                resume_from: None,
            };
            build.validate_allocation_state(
                &state,
                spec.bundle
                    .join("source")
                    .to_str()
                    .ok_or_else(|| invalid("source bundle must be UTF-8"))?,
                claim.request(),
            )?;
            let mut reserved = ReservedWorkerAdmission::open(
                &state,
                &spec.worker,
                parse_worker_pin(&spec.worker_spki_sha256)?,
            )?;
            claim.bind_request_id(reserved.request_id)?;
            reserved.bind_request(claim.request())?;
            Ok(reserved)
        };
        match allocate() {
            Ok(reserved) => Some(reserved),
            Err(error) => {
                return OperationOutcome::Failed {
                    detail: error.to_string(),
                    execution_may_have_run: false,
                };
            }
        }
    } else {
        None
    };
    let spec = claim.spec();
    let build = PreparedBuild {
        address: &spec.address,
        worker: &spec.worker,
        pin: Some(&spec.worker_spki_sha256),
        bundle: &spec.bundle,
        directory: &spec.delivery,
        output: &spec.output,
        mode: claim.mode(),
        resume_from: claim.resume_from(),
    };
    let mut on_listening = |address| claim.listening(address);
    let control = TlsOperationControl {
        cancellation: claim.cancellation(),
        preview: claim.preview_observer().map(Into::into),
        on_listening: &mut on_listening,
    };
    let acknowledgment_only = claim.acknowledgment_only();
    let outcome = if acknowledgment_only {
        // Acceptance reconciles the retained delivery, independently of later
        // edits to the operator's installed output tree. It never replaces or
        // reinstalls those files and needs no source bundle.
        super::run_tls_acknowledgment_bound(
            &spec.address,
            &spec.worker,
            &spec.worker_spki_sha256,
            claim.request(),
            &spec.delivery,
            Some(control),
        )
        .map(|delivery| (delivery, None))
    } else {
        build.execute_bound(claim.request(), Some(control), reserved)
    };
    match outcome {
        Ok((delivery, installed)) => {
            let mut result = build.report_value(&delivery, installed.as_ref());
            if acknowledgment_only {
                result["operation"] = json!("acknowledge");
            }
            if delivery.receipt["stop_reason"] == "cancelled" {
                OperationOutcome::Cancelled { result }
            } else {
                OperationOutcome::Completed { result }
            }
        }
        Err(error) if error.transport_interrupted => OperationOutcome::TransportInterrupted {
            detail: error.detail,
            execution_may_have_run: error.execution_may_have_run,
        },
        Err(error) => OperationOutcome::Failed {
            detail: error.detail,
            execution_may_have_run: error.execution_may_have_run,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn diagnostic_snapshot(stdout: &[u8], stderr: &[u8]) -> DiagnosticSnapshot {
        use sha2::{Digest, Sha256};
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().canonicalize().unwrap();
        fs::create_dir(directory.join("diagnostics")).unwrap();
        let receipt = json!({
            "kind":"verified-worker-delivery", "exit_code":101,
            "publication_authorized":false, "reexecute":false,
            "stdout_bytes":stdout.len(), "stdout_sha256":Sha256::digest(stdout).iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
            "stderr_bytes":stderr.len(), "stderr_sha256":Sha256::digest(stderr).iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
        });
        fs::write(directory.join("diagnostics/stdout"), stdout).unwrap();
        fs::write(directory.join("diagnostics/stderr"), stderr).unwrap();
        fs::write(
            directory.join("delivery.json"),
            serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                directory.join("diagnostics"),
                fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            for name in ["diagnostics/stdout", "diagnostics/stderr", "delivery.json"] {
                fs::set_permissions(directory.join(name), fs::Permissions::from_mode(0o600))
                    .unwrap();
            }
        }
        // This is a stream-routing fixture; the completion module separately
        // exercises real receiver/recovery verification before snapshotting.
        DiagnosticSnapshot::from_delivery(
            &Delivery {
                directory,
                receipt,
                acknowledgments_confirmed: true,
                acknowledgment_error: None,
                acknowledgment_interrupted: false,
            },
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap()
    }

    #[test]
    fn replay_keeps_worker_streams_exact_and_moves_only_status_to_stderr() {
        let raw_stdout = b"test output\0\xff\n{\"reason\":\"build-finished\",\"success\":false}\n";
        let raw_stderr = b"compiler/test diagnostic\xff";
        let report = json!({"kind":"worker-build", "exit_code":101, "reexecute":false});
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        emit_report(
            &report,
            Some(diagnostic_snapshot(raw_stdout, raw_stderr)),
            &mut stdout,
            &mut stderr,
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!(stdout, raw_stdout);
        assert!(stderr.starts_with(raw_stderr));
        assert_eq!(
            &stderr[raw_stderr.len()..],
            format!("{report}\n").as_bytes()
        );

        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        emit_report(
            &report,
            None,
            &mut stdout,
            &mut stderr,
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!(stdout, format!("{report}\n").as_bytes());
        assert!(
            stderr.is_empty(),
            "default native JSON contract is unchanged"
        );
    }

    #[test]
    fn failed_console_replay_never_emits_a_success_report_or_retries_output() {
        struct ClosedConsole(usize);
        impl Write for ClosedConsole {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                self.0 += 1;
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed console"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut stdout = ClosedConsole(0);
        let mut stderr = Vec::new();
        let error = emit_report(
            &json!({"kind":"worker-build"}),
            Some(diagnostic_snapshot(b"worker output", b"worker error")),
            &mut stdout,
            &mut stderr,
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(stdout.0, 1);
        assert!(stderr.is_empty());
    }

    #[cfg(target_os = "linux")]
    fn console_bytes(file: &fs::File) -> Vec<u8> {
        use std::io::{Read, Seek};
        let mut reader = file.try_clone().unwrap();
        reader.rewind().unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        bytes
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_direct_console_preserves_exact_diagnostics_and_native_reports() {
        use std::sync::atomic::AtomicBool;

        let raw_stdout = b"compiler output\0\xff\n";
        let raw_stderr = b"compiler diagnostic\xff";
        for exit_code in [0, 101] {
            for replay in [false, true] {
                let stdout = tempfile::tempfile().unwrap();
                let stderr = tempfile::tempfile().unwrap();
                let report = json!({"kind":"worker-build", "exit_code":exit_code,
                    "publication_authorized":false, "reexecute":false});
                let diagnostics = replay.then(|| diagnostic_snapshot(raw_stdout, raw_stderr));
                let deadline = ClientDeadline::new(Instant::now() + Duration::from_secs(10));
                let until = deadline.get();
                emit_client_report_to(
                    &report,
                    diagnostics,
                    &stdout,
                    &stderr,
                    &deadline,
                    &AtomicBool::new(false),
                )
                .unwrap();
                let status = format!("{report}\n");
                if replay {
                    assert_eq!(console_bytes(&stdout), raw_stdout);
                    assert_eq!(
                        console_bytes(&stderr),
                        [raw_stderr.as_slice(), status.as_bytes()].concat()
                    );
                } else {
                    assert_eq!(console_bytes(&stdout), status.as_bytes());
                    assert!(console_bytes(&stderr).is_empty());
                }
                assert_eq!(deadline.get(), until, "output must not renew the budget");
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn direct_native_report_does_not_open_an_unused_read_only_stderr() {
        use std::sync::atomic::AtomicBool;

        let stdout = tempfile::tempfile().unwrap();
        let unused = tempfile::NamedTempFile::new().unwrap();
        let stderr = fs::File::open(unused.path()).unwrap();
        let report = json!({"kind":"worker-build", "exit_code":0, "reexecute":false});
        let deadline = ClientDeadline::new(Instant::now() + Duration::from_secs(10));
        emit_client_report_to(
            &report,
            None,
            &stdout,
            &stderr,
            &deadline,
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(console_bytes(&stdout), format!("{report}\n").as_bytes());
        assert!(console_bytes(&stderr).is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn direct_report_deadline_bounds_every_used_output_pipe() {
        use crate::prepared_jobs::tests::with_full_pipe;
        use std::sync::atomic::AtomicBool;

        for (replay, stdout_stalls) in [(false, true), (true, true), (true, false)] {
            with_full_pipe(move |pipe| {
                let ordinary = tempfile::tempfile().unwrap();
                let diagnostics =
                    replay.then(|| diagnostic_snapshot(b"worker stdout", b"worker stderr"));
                let (stdout, stderr) = if stdout_stalls {
                    (&pipe, &ordinary)
                } else {
                    (&ordinary, &pipe)
                };
                let deadline = ClientDeadline::new(Instant::now() + Duration::from_millis(50));
                let error = emit_client_report_to(
                    &json!({"kind":"worker-build", "exit_code":0, "reexecute":false}),
                    diagnostics,
                    stdout,
                    stderr,
                    &deadline,
                    &AtomicBool::new(false),
                )
                .unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::TimedOut);
                assert_eq!(
                    console_bytes(&ordinary),
                    if stdout_stalls {
                        b"".as_slice()
                    } else {
                        b"worker stdout".as_slice()
                    },
                    "a stalled stream cannot trigger a retry or a success report"
                );
            });
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn direct_report_cancellation_interrupts_an_already_stalled_pipe() {
        use crate::prepared_jobs::tests::with_full_pipe;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::mpsc::{self, RecvTimeoutError};

        for (replay, stdout_stalls) in [(false, true), (true, true), (true, false)] {
            with_full_pipe(move |pipe| {
                let ordinary = tempfile::tempfile().unwrap();
                let diagnostics =
                    replay.then(|| diagnostic_snapshot(b"worker stdout", b"worker stderr"));
                let (stdout, stderr) = if stdout_stalls {
                    (&pipe, &ordinary)
                } else {
                    (&ordinary, &pipe)
                };
                let stopped = AtomicBool::new(false);
                let error = std::thread::scope(|scope| {
                    let (entered, started) = mpsc::sync_channel(0);
                    let (finished, result) = mpsc::sync_channel(1);
                    let stop_flag = &stopped;
                    scope.spawn(move || {
                        let deadline =
                            ClientDeadline::new(Instant::now() + Duration::from_secs(30));
                        entered.send(()).unwrap();
                        let outcome = emit_client_report_to(
                            &json!({"kind":"worker-build", "exit_code":0, "reexecute":false}),
                            diagnostics,
                            stdout,
                            stderr,
                            &deadline,
                            stop_flag,
                        );
                        let _ = finished.send(outcome);
                    });
                    started.recv_timeout(Duration::from_secs(2)).unwrap();
                    let pending = result.recv_timeout(Duration::from_millis(50));
                    stopped.store(true, Ordering::Release);
                    assert!(
                        matches!(pending, Err(RecvTimeoutError::Timeout)),
                        "the full pipe must still be pending before cancellation: {pending:?}"
                    );
                    result
                        .recv_timeout(Duration::from_secs(2))
                        .expect("cancellation did not release the stalled report")
                        .unwrap_err()
                });
                assert_eq!(error.kind(), io::ErrorKind::Interrupted);
                assert_eq!(
                    console_bytes(&ordinary),
                    if stdout_stalls {
                        b"".as_slice()
                    } else {
                        b"worker stdout".as_slice()
                    },
                    "cancelled replay cannot duplicate diagnostics or emit success"
                );
            });
        }
    }

    #[cfg(target_os = "linux")]
    mod signal_reporting {
        use super::*;
        use rabs_sandbox::source_transfer::{SourceFile, SourceManifest};
        use rabsd::coord::worker_delivery::{WorkerAuthentication, WorkerPeer, receive_execution};
        use std::collections::VecDeque;
        use std::os::unix::process::ExitStatusExt;
        use std::process::{Child, Command, ExitStatus, Stdio};

        const PIN: [u8; 32] = [0xab; 32];
        const STDOUT: &[u8] = b"compiler stdout\0\xff\n";
        const STDERR: &[u8] = b"compiler stderr\0\xfe";
        const ARTIFACT: &[u8] = b"A\0\xffB";
        const MANIFEST: &str = "548324c3a5c96511944c6ec6af94ee9bbb6683170bb0143f9d99cd192f80bfd6";

        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|byte| format!("{byte:02x}")).collect()
        }

        fn hash(bytes: &[u8]) -> String {
            hex(&Sha256::digest(bytes))
        }

        fn request_bundle(root: &Path) -> Value {
            let manifest = SourceManifest::new(vec![SourceFile {
                path: "lib.rs".into(),
                len: 1,
                sha256: Sha256::digest(b"x").into(),
                executable: false,
            }])
            .unwrap();
            let request = json!({
                "kind":"canonical-exec", "request_id":7, "program":"fixture-only",
                "args":["lib.rs"], "toolchain_backing":"/tc",
                "source_manifest":{"manifest_sha256":hex(&manifest.digest()),
                    "files":[{"path":"lib.rs", "bytes":1, "sha256":hash(b"x"), "executable":false}]},
                "artifacts":{"unit":"dep", "files":["a"]},
            });
            fs::create_dir(root.join("bundle")).unwrap();
            fs::write(
                root.join("bundle/request.json"),
                serde_json::to_vec(&request).unwrap(),
            )
            .unwrap();
            request
        }

        fn chunk(name: &str, bytes: &[u8], artifact: bool) -> Value {
            let mut chunk = json!({
                "kind":if artifact { "artifact-chunk" } else { "output-chunk" },
                "request_id":7, "offset":0, "next_offset":bytes.len(),
                "total_bytes":bytes.len(), "sha256":hash(bytes), "chunk_sha256":hash(bytes),
                "eof":true, "data_hex":hex(bytes),
            });
            chunk[if artifact { "name" } else { "stream" }] = json!(name);
            if artifact {
                chunk["executable"] = json!(false);
                chunk["manifest_sha256"] = json!(MANIFEST);
            }
            chunk
        }

        fn retained_delivery(root: &Path, exit: i32) -> Value {
            // The real receiver creates the receipt from bounded fixture frames.
            // This tests retained delivery and native process I/O, not TLS
            // authentication, a compiler, a sandbox, or a production fleet.
            struct Peer {
                replies: VecDeque<Value>,
                executions: usize,
            }
            impl WorkerPeer for Peer {
                fn send(&mut self, frame: &Value) -> io::Result<()> {
                    if frame["kind"] == "canonical-exec" {
                        self.executions += 1;
                    }
                    Ok(())
                }
                fn receive(&mut self) -> io::Result<Value> {
                    self.replies
                        .pop_front()
                        .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
                }
                fn authentication(&self) -> Option<WorkerAuthentication> {
                    Some(WorkerAuthentication {
                        spki_sha256: PIN,
                        session_id: 17,
                        identity_generation: 1,
                    })
                }
            }
            let request = request_bundle(root);
            let artifacts = json!({"unit":"dep", "files":[{"name":"a", "bytes":ARTIFACT.len(),
                "sha256":hash(ARTIFACT), "executable":false}], "total_bytes":ARTIFACT.len(),
                "manifest_sha256":MANIFEST});
            let mut peer = Peer {
                replies: VecDeque::from([
                    json!({"kind":"worker-hello", "worker_id":"fixture-worker", "canonical":true,
                        "slots":1, "boot_generation":1, "incarnation":"00000000000000000000000000000001",
                        "request_high_water":null, "recovery_protocols":["request-journal-v1"],
                        "output_transfers":["ranges-v1"], "artifact_transfers":["files-v1"]}),
                    json!({"kind":"exec-result", "request_id":7, "executed":true, "exit_code":exit,
                        "residual_group_members":0, "stop_reason":null,
                        "output_transfer":"ranges-v1", "output_ack_required":true,
                        "stdout_bytes":STDOUT.len(), "stdout_sha256":hash(STDOUT),
                        "stderr_bytes":STDERR.len(), "stderr_sha256":hash(STDERR),
                        "artifact_transfer":"files-v1", "artifact_ack_required":exit == 0,
                        "artifact_manifest":if exit == 0 { artifacts } else { Value::Null }}),
                    chunk("stdout", STDOUT, false),
                    chunk("stderr", STDERR, false),
                ]),
                executions: 0,
            };
            if exit == 0 {
                peer.replies.push_back(chunk("a", ARTIFACT, true));
            }
            peer.replies.push_back(json!({
                "kind":"output-acknowledged", "request_id":7, "already_released":false,
            }));
            if exit == 0 {
                peer.replies.push_back(json!({
                    "kind":"artifact-acknowledged", "request_id":7, "already_released":false,
                }));
            }
            let delivery = receive_execution(
                &mut peer,
                &request,
                "fixture-worker",
                &root.join("delivery"),
            )
            .unwrap();
            assert!(peer.replies.is_empty());
            assert_eq!(peer.executions, 1);
            assert!(delivery.acknowledgments_confirmed);
            delivery.receipt
        }

        struct ChildOwner(Child);
        impl Drop for ChildOwner {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        impl ChildOwner {
            fn wait_for(&mut self, path: &Path) {
                let until = Instant::now() + Duration::from_secs(5);
                while !path.exists() {
                    assert!(
                        self.0.try_wait().unwrap().is_none(),
                        "child exited before {path:?}"
                    );
                    assert!(Instant::now() < until, "child never reached {path:?}");
                    std::thread::sleep(Duration::from_millis(5));
                }
            }

            fn wait(&mut self) -> ExitStatus {
                let until = Instant::now() + Duration::from_secs(5);
                loop {
                    if let Some(status) = self.0.try_wait().unwrap() {
                        return status;
                    }
                    assert!(Instant::now() < until, "signal did not release the client");
                    std::thread::sleep(Duration::from_millis(5));
                }
            }

            fn signal(&self, signal: rustix::process::Signal) {
                let pid =
                    rustix::process::Pid::from_raw(i32::try_from(self.0.id()).unwrap()).unwrap();
                rustix::process::kill_process(pid, signal).unwrap();
            }
        }

        fn start(
            root: &Path,
            attempt: &str,
            replay: bool,
            address: &str,
            case: &str,
            stdout: fs::File,
            stderr: fs::File,
        ) -> ChildOwner {
            let test = format!(
                "{}::report_process",
                module_path!()
                    .strip_prefix("rabsd::")
                    .unwrap_or(module_path!())
            );
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", &test, "--nocapture", "--quiet"])
                .env("RABS_DIRECT_REPORT_TEST_ROOT", root)
                .env("RABS_DIRECT_REPORT_TEST_ATTEMPT", attempt)
                .env("RABS_DIRECT_REPORT_TEST_ADDRESS", address)
                .env("RABS_DIRECT_REPORT_TEST_CASE", case)
                .env(
                    "RABS_DIRECT_REPORT_TEST_REPLAY",
                    if replay { "1" } else { "0" },
                )
                .env("RABS_STATE_DIR", root.join("state"))
                .env_remove("RABS_COORD_TLS_CA")
                .env_remove("RABS_COORD_TLS_CERT")
                .env_remove("RABS_COORD_TLS_KEY")
                .stdin(Stdio::null())
                .stdout(stdout)
                .stderr(stderr);
            let mut child = ChildOwner(command.spawn().unwrap());
            child.wait_for(&root.join(format!("ready-{attempt}")));
            child
        }

        #[test]
        fn report_process() {
            let Some(root) = std::env::var_os("RABS_DIRECT_REPORT_TEST_ROOT") else {
                return;
            };
            let root = PathBuf::from(root);
            let attempt = std::env::var("RABS_DIRECT_REPORT_TEST_ATTEMPT").unwrap();
            let before_dispatch =
                std::env::var("RABS_DIRECT_REPORT_TEST_CASE").unwrap() == "before-dispatch";
            // Reproduce the completed TLS receive's actual handler lifecycle.
            // Dropping these streams leaves the runtime dispatcher installed.
            drop(asupersync::signal::sigint().unwrap());
            drop(asupersync::signal::sigterm().unwrap());
            let signals = before_dispatch.then(|| ReportSignals::start().unwrap());
            io::stdout().flush().unwrap();
            fs::write(root.join(format!("ready-{attempt}")), b"ready").unwrap();
            let until = Instant::now() + Duration::from_secs(5);
            while !root.join(format!("go-{attempt}")).exists() {
                assert!(Instant::now() < until, "parent did not release the child");
                std::thread::sleep(Duration::from_millis(5));
            }
            let address = std::env::var("RABS_DIRECT_REPORT_TEST_ADDRESS").unwrap();
            let pin = hex(&PIN);
            if let Some(signals) = signals {
                while !signals.cancellation.is_cancelled() {
                    assert!(
                        Instant::now() < until,
                        "native signal did not cancel the operation"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
                let bundle = root.join("bundle");
                let directory = root.join("delivery");
                let output = root.join("output");
                let build = PreparedBuild {
                    address: &address,
                    worker: "fixture-worker",
                    pin: Some(&pin),
                    bundle: &bundle,
                    directory: &directory,
                    output: &output,
                    mode: DeliveryMode::Execute,
                    resume_from: None,
                };
                let error = build
                    .execute_with_report_signals(&signals, None)
                    .unwrap_err();
                assert_eq!(error.detail, "prepared operation cancelled before dispatch");
                assert!(!error.execution_may_have_run);
                assert!(!directory.exists() && !output.exists());
                let signal_number = signals.finish().unwrap();
                rabsd::coord::canonical_local::exit_like(
                    rabs_protocol::subscriber_interest::ChildTermination::Signaled {
                        signal_number,
                    },
                );
            }
            let mut args = Vec::new();
            if std::env::var("RABS_DIRECT_REPORT_TEST_REPLAY").unwrap() == "1" {
                args.push("--replay-diagnostics".to_owned());
            }
            args.extend([
                address,
                "fixture-worker".into(),
                pin,
                root.join("bundle").to_str().unwrap().to_owned(),
                root.join("delivery").to_str().unwrap().to_owned(),
                root.join("output").to_str().unwrap().to_owned(),
            ]);
            std::process::exit(run_build_tls(&args));
        }

        fn assert_recovery(root: &Path, address: &str, exit: i32, receipt: &Value) {
            for replay in [false, true] {
                let attempt = if replay { "replay" } else { "native" };
                let stdout = root.join(format!("{attempt}.stdout"));
                let stderr = root.join(format!("{attempt}.stderr"));
                let mut child = start(
                    root,
                    attempt,
                    replay,
                    address,
                    "report",
                    fs::File::create(&stdout).unwrap(),
                    fs::File::create(&stderr).unwrap(),
                );
                // The child is gated after libtest's own preamble, before the
                // production CLI. Exclude only those already observed bytes.
                let stdout_prefix = fs::metadata(&stdout).unwrap().len() as usize;
                let stderr_prefix = fs::metadata(&stderr).unwrap().len() as usize;
                fs::write(root.join(format!("go-{attempt}")), b"go").unwrap();
                let status = child.wait();
                assert_eq!(status.signal(), None);
                assert_eq!(status.code(), Some(exit));
                let stdout = fs::read(stdout).unwrap();
                let stderr = fs::read(stderr).unwrap();
                let stdout = &stdout[stdout_prefix..];
                let stderr = &stderr[stderr_prefix..];
                let report: Value = if replay {
                    assert_eq!(stdout, STDOUT);
                    assert!(stderr.starts_with(STDERR));
                    serde_json::from_slice(&stderr[STDERR.len()..]).unwrap()
                } else {
                    assert!(stderr.is_empty());
                    serde_json::from_slice(stdout).unwrap()
                };
                assert_eq!(report["kind"], "worker-build");
                assert_eq!(report["delivery"]["receipt"], *receipt);
                assert_eq!(report["installed_outputs"].is_null(), exit != 0);
                assert_eq!(report["publication_authorized"], false);
                assert_eq!(report["reexecute"], false);
                assert_eq!(root.join("output").exists(), exit == 0);
                assert!(!root.join("bundle/source").exists());
                assert!(!root.join("state").exists());
            }
        }

        #[test]
        fn native_signals_release_full_direct_report_pipes_and_preserve_offline_recovery() {
            use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
            use rustix::io::Errno;
            use rustix::pipe::{PipeFlags, pipe_with};
            use rustix::process::Signal;

            for signal in [Signal::INT, Signal::TERM] {
                for (replay, stdout_stalls) in [(false, true), (true, true), (true, false)] {
                    let temporary = tempfile::tempdir().unwrap();
                    let root = temporary.path().canonicalize().unwrap();
                    let receipt = retained_delivery(&root, 0);
                    let retained = fs::read(root.join("delivery/delivery.json")).unwrap();
                    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                    let address = occupied.local_addr().unwrap().to_string();
                    let (_reader, writer) = pipe_with(PipeFlags::CLOEXEC).unwrap();
                    let writer = fs::File::from(writer);
                    let ordinary = tempfile::tempfile().unwrap();
                    let (stdout, stderr) = if stdout_stalls {
                        (writer.try_clone().unwrap(), ordinary)
                    } else {
                        (ordinary, writer.try_clone().unwrap())
                    };
                    let mut child =
                        start(&root, "blocked", replay, &address, "report", stdout, stderr);
                    // Fill only after the subprocess entered its test body:
                    // libtest itself may print to stdout before our CLI starts.
                    let flags = fcntl_getfl(&writer).unwrap();
                    fcntl_setfl(&writer, flags | OFlags::NONBLOCK).unwrap();
                    for bytes in [&[0x5a; 4096][..], &[0x5a][..]] {
                        loop {
                            match rustix::io::write(&writer, bytes) {
                                Ok(count) => assert!(count > 0),
                                Err(Errno::AGAIN) => break,
                                result => panic!("unexpected pipe fill: {result:?}"),
                            }
                        }
                    }
                    assert_eq!(rustix::io::write(&writer, b"x"), Err(Errno::AGAIN));
                    fcntl_setfl(&writer, flags).unwrap();
                    fs::write(root.join("go-blocked"), b"go").unwrap();
                    child.wait_for(&root.join("output/a"));
                    std::thread::sleep(Duration::from_millis(50));
                    assert!(
                        child.0.try_wait().unwrap().is_none(),
                        "pipe was not stalled"
                    );
                    child.signal(signal);
                    let status = child.wait();
                    assert_eq!(status.signal(), Some(signal.as_raw()));
                    assert_eq!(fcntl_getfl(&writer).unwrap(), flags);
                    assert_eq!(
                        fs::read(root.join("delivery/delivery.json")).unwrap(),
                        retained
                    );
                    assert_eq!(
                        fs::read(root.join("delivery/diagnostics/stdout")).unwrap(),
                        STDOUT
                    );
                    assert_eq!(
                        fs::read(root.join("delivery/diagnostics/stderr")).unwrap(),
                        STDERR
                    );
                    assert_eq!(fs::read(root.join("output/a")).unwrap(), ARTIFACT);
                    assert_recovery(&root, &address, 0, &receipt);
                }
            }
        }

        #[test]
        fn ordinary_high_exit_codes_remain_exit_codes_with_native_report_signals_installed() {
            for exit in [101, 137, 143] {
                let temporary = tempfile::tempdir().unwrap();
                let root = temporary.path().canonicalize().unwrap();
                let receipt = retained_delivery(&root, exit);
                let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                assert_recovery(
                    &root,
                    &occupied.local_addr().unwrap().to_string(),
                    exit,
                    &receipt,
                );
            }
        }

        #[test]
        fn native_stop_before_dispatch_needs_no_source_credentials_or_listener() {
            for signal in [rustix::process::Signal::INT, rustix::process::Signal::TERM] {
                let temporary = tempfile::tempdir().unwrap();
                let root = temporary.path().canonicalize().unwrap();
                request_bundle(&root);
                let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let mut child = start(
                    &root,
                    "cancel",
                    false,
                    &occupied.local_addr().unwrap().to_string(),
                    "before-dispatch",
                    tempfile::tempfile().unwrap(),
                    tempfile::tempfile().unwrap(),
                );
                child.signal(signal);
                fs::write(root.join("go-cancel"), b"go").unwrap();
                assert_eq!(child.wait().signal(), Some(signal.as_raw()));
                assert!(!root.join("delivery").exists());
                assert!(!root.join("output").exists());
                assert!(!root.join("state").exists());
                assert!(!root.join("bundle/source").exists());
            }
        }
    }

    fn preparation_fixture(root: &Path) -> (PathBuf, PathBuf) {
        let source = root.join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("lib.rs"), b"pub fn value() -> u32 { 42 }\n").unwrap();
        let specification = root.join("spec.json");
        fs::write(
            &specification,
            json!({"kind":"canonical-exec", "request_id":91, "program":"rustc",
                "toolchain_backing":"/tc", "source_files":["lib.rs"],
                "artifacts":{"unit":"build", "files":["lib.rlib"]}})
            .to_string(),
        )
        .unwrap();
        (source, specification)
    }

    fn preparation_build(root: &Path) -> PreparedBuild<'_> {
        // Callers provide stable borrowed paths below; this helper only tests
        // refusals, so its three paths may deliberately share this root.
        PreparedBuild {
            address: "127.0.0.1:0",
            worker: "worker",
            pin: None,
            bundle: root,
            directory: root,
            output: root,
            mode: DeliveryMode::Execute,
            resume_from: None,
        }
    }

    #[test]
    fn live_stderr_refuses_non_cargo_before_capture_without_changing_default_preparation() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let (source, specification) = preparation_fixture(&root);
        let mut request: Value =
            serde_json::from_slice(&fs::read(&specification).unwrap()).unwrap();
        request["request_id"] = json!("allocate");
        fs::write(&specification, serde_json::to_vec(&request).unwrap()).unwrap();
        let spec = rabsd::coord::prepared_operation::PreparedOperationSpec {
            id: "0123456789abcdef0123456789abcdef".into(),
            address: "127.0.0.1:0".into(),
            worker: "worker".into(),
            worker_spki_sha256: "01".repeat(32),
            bundle: root.join("bundle"),
            delivery: root.join("delivery"),
            output: root.join("output"),
        };
        let error = prepare_daemon_build(
            &spec,
            source.to_str().unwrap(),
            specification.to_str().unwrap(),
            true,
        )
        .unwrap_err();
        assert!(error.to_string().contains("whole-Cargo"));
        assert!(!spec.bundle.exists() && !spec.delivery.exists() && !spec.output.exists());
        let prepared = prepare_daemon_build(
            &spec,
            source.to_str().unwrap(),
            specification.to_str().unwrap(),
            false,
        )
        .unwrap();
        assert_eq!(prepared["kind"], "prepared-source-template");
        assert_eq!(prepared["request_id"], "allocate");
        assert_eq!(
            fs::read(spec.bundle.join("source/lib.rs")).unwrap(),
            fs::read(source.join("lib.rs")).unwrap()
        );
        assert!(!spec.delivery.exists() && !spec.output.exists());
    }

    #[test]
    fn direct_live_stderr_refuses_non_cargo_before_allocating_or_capturing_source() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let (source, specification) = preparation_fixture(&root);
        let mut request: Value =
            serde_json::from_slice(&fs::read(&specification).unwrap()).unwrap();
        request["request_id"] = json!("allocate");
        fs::write(&specification, serde_json::to_vec(&request).unwrap()).unwrap();
        let (bundle, delivery, output, state) = (
            root.join("bundle"),
            root.join("delivery"),
            root.join("output"),
            root.join("state"),
        );
        let pin = "01".repeat(32);
        let build = PreparedBuild {
            pin: Some(&pin),
            bundle: &bundle,
            directory: &delivery,
            output: &output,
            ..preparation_build(&root)
        };
        let error = build
            .prepare_from(
                source.to_str().unwrap(),
                specification.to_str().unwrap(),
                &state,
                true,
            )
            .unwrap_err();
        assert!(error.to_string().contains("whole-Cargo"));
        assert!(
            [bundle, delivery, output, state]
                .iter()
                .all(|path| !path.exists())
        );
        assert_eq!(
            fs::read(source.join("lib.rs")).unwrap(),
            b"pub fn value() -> u32 { 42 }\n"
        );
    }

    #[test]
    fn direct_live_stderr_requires_tls_and_exact_replay_flag_order_before_io() {
        for (arguments, tls) in [
            (vec!["--live-stderr"], true),
            (vec!["--replay-diagnostics", "--live-stderr"], false),
            (vec!["--live-stderr", "--replay-diagnostics"], true),
        ] {
            let arguments: Vec<String> = arguments.into_iter().map(str::to_owned).collect();
            assert_eq!(run(&arguments, tls), 2);
        }
    }

    #[test]
    fn prepare_from_captures_once_and_keeps_original_checkout_out_of_execution() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let (source, specification) = preparation_fixture(&root);
        let bundle = root.join("bundle");
        let delivery = root.join("delivery");
        let output = root.join("output");
        let build = PreparedBuild {
            bundle: &bundle,
            directory: &delivery,
            output: &output,
            ..preparation_build(&root)
        };
        assert!(
            build
                .prepare_from(
                    source.to_str().unwrap(),
                    specification.to_str().unwrap(),
                    &root.join("state"),
                    false,
                )
                .unwrap()
                .is_none()
        );
        let request = build.request().unwrap();
        assert!(request_manifest(&request).unwrap().is_some());
        assert!(request.get("source_files").is_none());
        assert_eq!(request["request_id"], 91);
        fs::write(source.join("lib.rs"), b"changed original").unwrap();
        assert_eq!(
            fs::read(bundle.join("source/lib.rs")).unwrap(),
            b"pub fn value() -> u32 { 42 }\n"
        );
        assert_eq!(build.request().unwrap(), request);
        assert!(!delivery.exists());
        assert!(!output.exists());
        assert!(
            build
                .prepare_from(
                    source.to_str().unwrap(),
                    specification.to_str().unwrap(),
                    &root.join("state"),
                    false,
                )
                .is_err()
        );
        assert_eq!(build.request().unwrap(), request);
    }

    #[test]
    fn prepare_from_cannot_overwrite_any_existing_build_directory() {
        for occupied in ["bundle", "delivery", "output"] {
            let temporary = tempfile::tempdir().unwrap();
            let root = temporary.path().canonicalize().unwrap();
            let (source, specification) = preparation_fixture(&root);
            let bundle = root.join("bundle");
            let delivery = root.join("delivery");
            let output = root.join("output");
            fs::create_dir(root.join(occupied)).unwrap();
            fs::write(root.join(occupied).join("retained"), b"keep").unwrap();
            let build = PreparedBuild {
                bundle: &bundle,
                directory: &delivery,
                output: &output,
                ..preparation_build(&root)
            };
            let error = build
                .prepare_from(
                    source.to_str().unwrap(),
                    specification.to_str().unwrap(),
                    &root.join("state"),
                    false,
                )
                .unwrap_err();
            assert!(error.to_string().contains("requires new"));
            assert_eq!(
                fs::read(root.join(occupied).join("retained")).unwrap(),
                b"keep"
            );
            assert!(!bundle.join("request.json").exists());
        }
    }

    #[test]
    fn recovery_and_invalid_transport_refuse_before_source_preparation() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let missing = root.join("not-read");
        for (mode, address, pin) in [
            (DeliveryMode::Resume, "127.0.0.1:0", None),
            (DeliveryMode::Execute, "not-an-address", None),
            (DeliveryMode::Execute, "192.0.2.1:1234", None),
            (DeliveryMode::Execute, "127.0.0.1:0", Some("invalid-pin")),
        ] {
            let build = PreparedBuild {
                mode,
                address,
                pin,
                ..preparation_build(&root)
            };
            assert!(
                build
                    .prepare_from(
                        missing.to_str().unwrap(),
                        "not-read.json",
                        &root.join("state"),
                        false,
                    )
                    .is_err()
            );
            assert!(fs::read_dir(&root).unwrap().next().is_none());
        }
    }

    #[test]
    fn prepare_from_rejects_destinations_inside_approved_source() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let (source, specification) = preparation_fixture(&root);
        let bundle = source.join("bundle");
        let delivery = root.join("delivery");
        let output = root.join("output");
        let build = PreparedBuild {
            bundle: &bundle,
            directory: &delivery,
            output: &output,
            ..preparation_build(&root)
        };
        let error = build
            .prepare_from(
                source.to_str().unwrap(),
                specification.to_str().unwrap(),
                &root.join("state"),
                false,
            )
            .unwrap_err();
        assert!(error.to_string().contains("overlap the source"));
        assert!(!bundle.exists());
    }

    #[test]
    fn malformed_preparation_does_not_create_an_executable_bundle() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let (source, specification) = preparation_fixture(&root);
        fs::write(&specification, b"{not valid JSON").unwrap();
        let bundle = root.join("bundle");
        let delivery = root.join("delivery");
        let output = root.join("output");
        let build = PreparedBuild {
            bundle: &bundle,
            directory: &delivery,
            output: &output,
            ..preparation_build(&root)
        };
        assert!(
            build
                .prepare_from(
                    source.to_str().unwrap(),
                    specification.to_str().unwrap(),
                    &root.join("state"),
                    false,
                )
                .is_err()
        );
        assert!(!bundle.exists());
        assert!(!delivery.exists());
        assert!(!output.exists());
    }

    #[test]
    fn prepare_and_resume_flags_are_mutually_exclusive_before_io() {
        for args in [
            vec![
                "--prepare-from",
                "/source",
                "/spec",
                "--resume",
                "127.0.0.1:1",
                "worker",
                "/bundle",
                "/delivery",
                "/output",
            ],
            vec![
                "--prepare-from",
                "/source",
                "/spec",
                "127.0.0.1:1",
                "worker",
                "/bundle",
                "/delivery",
                "/output",
                "--resume",
            ],
            vec!["--prepare-from", "/source"],
        ] {
            assert_eq!(
                run_build(&args.into_iter().map(str::to_owned).collect::<Vec<_>>()),
                2
            );
        }
    }

    #[test]
    fn output_preflight_rejects_missing_parents_traversal_and_symlink_ancestors() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        assert!(ordinary_directory(&root.join("new"), true).is_ok());
        for path in [
            root.join("missing/new"),
            root.join("../new"),
            PathBuf::from("relative"),
        ] {
            assert!(ordinary_directory(&path, true).is_err());
        }
        #[cfg(unix)]
        {
            let alias = root.join("alias");
            std::os::unix::fs::symlink(&root, &alias).unwrap();
            assert!(ordinary_directory(&alias.join("new"), true).is_err());
        }
    }

    #[test]
    fn prepared_build_refuses_existing_outputs_before_connecting() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let source = root.join("checkout");
        let bundle = root.join("bundle");
        let directory = root.join("delivery");
        let output = root.join("outputs");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("lib.rs"), b"pub fn answer() -> u32 { 42 }\n").unwrap();
        let spec = json!({"kind":"canonical-exec", "request_id":1, "program":"rustc",
            "toolchain_backing":"/tc", "source_files":["lib.rs"],
            "artifacts":{"unit":"build", "files":["lib.rlib"]}});
        rabsd::coord::source_delivery::prepare_source_bundle(&source, &spec, &bundle).unwrap();
        fs::create_dir(&output).unwrap();
        fs::write(output.join("existing"), b"keep").unwrap();
        let build = PreparedBuild {
            address: "invalid-address",
            worker: "worker",
            pin: None,
            bundle: &bundle,
            directory: &directory,
            output: &output,
            mode: DeliveryMode::Execute,
            resume_from: None,
        };
        let error = build.execute(None).unwrap_err();
        assert!(
            error
                .detail
                .contains("already exists without a verified delivery")
        );
        assert!(!error.execution_may_have_run);
        assert!(!directory.exists());
        assert_eq!(fs::read(output.join("existing")).unwrap(), b"keep");
        let overlap = PreparedBuild {
            output: &source,
            bundle: &source,
            ..build
        };
        assert!(overlap.request().unwrap_err().detail.contains("overlap"));
    }

    #[test]
    fn queued_execution_uses_saved_request_and_refuses_mutated_source_before_listening() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let source = root.join("checkout");
        let bundle = root.join("bundle");
        let directory = root.join("delivery");
        let output = root.join("outputs");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("lib.rs"), b"original source").unwrap();
        let spec = json!({"kind":"canonical-exec", "request_id":1, "program":"rustc",
            "toolchain_backing":"/tc", "source_files":["lib.rs"],
            "artifacts":{"unit":"build", "files":["lib.rlib"]}});
        rabsd::coord::source_delivery::prepare_source_bundle(&source, &spec, &bundle).unwrap();
        let request = read_request(&bundle.join("request.json")).unwrap();
        // Neither a rewritten request nor its newly matching source can replace
        // the identity that the daemon accepted earlier.
        fs::write(bundle.join("request.json"), b"not the accepted JSON").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                bundle.join("source/lib.rs"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        fs::write(bundle.join("source/lib.rs"), b"changed source").unwrap();
        let pin = "ab".repeat(32);
        let build = PreparedBuild {
            address: "127.0.0.1:0",
            worker: "worker",
            pin: Some(&pin),
            bundle: &bundle,
            directory: &directory,
            output: &output,
            mode: DeliveryMode::Execute,
            resume_from: None,
        };
        let mut listened = false;
        let mut on_listening = |_| {
            listened = true;
            Ok(())
        };
        let control = TlsOperationControl {
            cancellation: super::super::OperationCancellation::default(),
            preview: None,
            on_listening: &mut on_listening,
        };
        let error = build
            .execute_bound(&request, Some(control), None)
            .unwrap_err();
        assert!(
            error.detail.contains("captured source differs from"),
            "{}",
            error.detail
        );
        assert!(!error.execution_may_have_run);
        assert!(!listened);
        assert!(!directory.exists());
        assert!(!output.exists());
    }

    #[test]
    fn cancelled_queued_execution_does_not_need_source_credentials_or_a_listener() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let source = root.join("checkout");
        let bundle = root.join("bundle");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("lib.rs"), b"original source").unwrap();
        let spec = json!({"kind":"canonical-exec", "request_id":1, "program":"rustc",
            "toolchain_backing":"/tc", "source_files":["lib.rs"],
            "artifacts":{"unit":"build", "files":["lib.rlib"]}});
        rabsd::coord::source_delivery::prepare_source_bundle(&source, &spec, &bundle).unwrap();
        let request = read_request(&bundle.join("request.json")).unwrap();
        fs::rename(&bundle, root.join("retired-bundle")).unwrap();
        let directory = root.join("delivery");
        let output = root.join("output");
        let pin = "ab".repeat(32);
        let build = PreparedBuild {
            address: "127.0.0.1:0",
            worker: "worker",
            pin: Some(&pin),
            bundle: &bundle,
            directory: &directory,
            output: &output,
            mode: DeliveryMode::Execute,
            resume_from: None,
        };
        let token = super::super::OperationCancellation::default();
        token.cancel();
        let mut on_listening = |_| panic!("cancelled operation cannot listen");
        let error = build
            .execute_bound(
                &request,
                Some(TlsOperationControl {
                    cancellation: token,
                    preview: None,
                    on_listening: &mut on_listening,
                }),
                None,
            )
            .unwrap_err();
        assert!(error.detail.contains("cancelled before dispatch"));
        assert!(!error.execution_may_have_run);
        assert!(!directory.exists());
        assert!(!output.exists());
    }

    #[test]
    fn resumed_build_keeps_prefix_roots_separate_from_bundle_and_installation() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let source = root.join("checkout");
        let bundle = root.join("bundle");
        let directory = root.join("delivery");
        let old = root.join("old");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&old).unwrap();
        fs::write(source.join("lib.rs"), b"source").unwrap();
        let spec = json!({"kind":"canonical-exec", "request_id":1, "program":"rustc",
            "toolchain_backing":"/tc", "source_files":["lib.rs"],
            "artifacts":{"unit":"build", "files":["lib.rlib"]}});
        rabsd::coord::source_delivery::prepare_source_bundle(&source, &spec, &bundle).unwrap();
        for (resume_from, output) in [(&bundle, root.join("out")), (&old, old.join("out"))] {
            let build = PreparedBuild {
                address: "invalid-address",
                worker: "worker",
                pin: None,
                bundle: &bundle,
                directory: &directory,
                output: &output,
                mode: DeliveryMode::Resume,
                resume_from: Some(resume_from),
            };
            let error = build.execute(None).unwrap_err();
            assert!(error.execution_may_have_run);
            assert!(error.detail.contains("overlap"));
            assert!(!directory.exists());
            assert!(!output.exists());
        }
        assert_eq!(fs::read(source.join("lib.rs")).unwrap(), b"source");
        assert!(fs::read_dir(old).unwrap().next().is_none());
    }

    fn allocating_fixture(root: &Path) -> (PathBuf, PathBuf) {
        let (source, specification) = preparation_fixture(root);
        let mut spec: Value = serde_json::from_slice(&fs::read(&specification).unwrap()).unwrap();
        spec["request_id"] = json!("allocate");
        fs::write(&specification, serde_json::to_vec(&spec).unwrap()).unwrap();
        (source, specification)
    }

    #[test]
    fn allocated_preparation_persists_numeric_identity_and_hands_off_exclusive_ownership() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let (source, spec) = allocating_fixture(&root);
        let original = fs::read(&spec).unwrap();
        let state = root.join("state");
        let bundle = root.join("bundle");
        let delivery = root.join("delivery");
        let output = root.join("output");
        let pin = "01".repeat(32);
        let build = PreparedBuild {
            pin: Some(&pin),
            bundle: &bundle,
            directory: &delivery,
            output: &output,
            ..preparation_build(&root)
        };
        let reservation = build
            .prepare_from(
                source.to_str().unwrap(),
                spec.to_str().unwrap(),
                &state,
                false,
            )
            .unwrap()
            .unwrap();
        let request = build.request().unwrap();
        let id = request["request_id"].as_u64().unwrap();
        assert!(id > 0);
        assert_eq!(id, reservation.request_id);
        reservation
            .validate_request("worker", &pin, &request)
            .unwrap();
        assert_eq!(fs::read(&spec).unwrap(), original);
        assert!(!delivery.exists());
        assert!(!output.exists());
        assert!(PinnedWorkerAdmission::open(&state, "worker", [1; 32]).is_err());
        let owner = reservation
            .into_admission("worker", &pin, &request["request_id"])
            .unwrap();
        assert!(PinnedWorkerAdmission::open(&state, "worker", [1; 32]).is_err());
        drop(owner);
        let reopened = PinnedWorkerAdmission::open(&state, "worker", [1; 32]).unwrap();
        assert!(reopened.allocate_request_id().unwrap() > id);
    }

    #[test]
    fn successive_preparations_share_durable_ids_without_rewriting_saved_bundles() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let (source, spec) = allocating_fixture(&root);
        let state = root.join("state");
        let pin = "01".repeat(32);
        let mut previous = 0;
        let mut saved = Vec::new();
        for index in 0..4 {
            let bundle = root.join(format!("bundle-{index}"));
            let delivery = root.join(format!("delivery-{index}"));
            let output = root.join(format!("output-{index}"));
            let build = PreparedBuild {
                pin: Some(&pin),
                bundle: &bundle,
                directory: &delivery,
                output: &output,
                ..preparation_build(&root)
            };
            let reserved = build
                .prepare_from(
                    source.to_str().unwrap(),
                    spec.to_str().unwrap(),
                    &state,
                    false,
                )
                .unwrap()
                .unwrap();
            let request = build.request().unwrap();
            let id = request["request_id"].as_u64().unwrap();
            assert!(id > previous);
            previous = id;
            let path = bundle.join("request.json");
            saved.push((path.clone(), fs::read(path).unwrap()));
            drop(reserved);
        }
        for (path, bytes) in saved {
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
    }

    #[test]
    fn reserved_request_cannot_change_worker_pin_id_or_command_before_dispatch() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let (source, spec) = allocating_fixture(&root);
        let state = root.join("state");
        let bundle = root.join("bundle");
        let delivery = root.join("delivery");
        let output = root.join("output");
        let pin = "01".repeat(32);
        let build = PreparedBuild {
            pin: Some(&pin),
            bundle: &bundle,
            directory: &delivery,
            output: &output,
            ..preparation_build(&root)
        };
        let reserved = build
            .prepare_from(
                source.to_str().unwrap(),
                spec.to_str().unwrap(),
                &state,
                false,
            )
            .unwrap()
            .unwrap();
        let request = build.request().unwrap();
        assert!(reserved.validate_request("other", &pin, &request).is_err());
        assert!(
            reserved
                .validate_request("worker", &"02".repeat(32), &request)
                .is_err()
        );
        let mut other = request.clone();
        other["request_id"] = json!(reserved.request_id + 1);
        assert!(reserved.validate_request("worker", &pin, &other).is_err());
        other = request;
        other["program"] = json!("another-compiler");
        // Refuse before source capture, credentials or a listener, even though
        // the modified command still carries the allocated numeric identity.
        let error = build
            .execute_bound(&other, None, Some(reserved))
            .unwrap_err();
        assert!(error.detail.contains("changed after worker reservation"));
        assert!(!error.execution_may_have_run);
        assert!(!delivery.exists());
        assert!(PinnedWorkerAdmission::open(&state, "worker", [1; 32]).is_ok());
    }

    #[test]
    fn failed_capture_burns_allocation_and_releases_the_worker_without_dispatch() {
        use rabs_cas::metadata_store::{RabsMetadataStore, SqlValue};
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let (source, spec) = allocating_fixture(&root);
        let state = root.join("state");
        let before = PinnedWorkerAdmission::open(&state, "worker", [1; 32]).unwrap();
        let first = before.allocate_request_id().unwrap();
        drop(before);
        let mut invalid_spec: Value = serde_json::from_slice(&fs::read(&spec).unwrap()).unwrap();
        invalid_spec["source_files"] = json!(["missing.rs"]);
        fs::write(&spec, serde_json::to_vec(&invalid_spec).unwrap()).unwrap();
        let bundle = root.join("bundle");
        let delivery = root.join("delivery");
        let output = root.join("output");
        let pin = "01".repeat(32);
        let build = PreparedBuild {
            pin: Some(&pin),
            bundle: &bundle,
            directory: &delivery,
            output: &output,
            ..preparation_build(&root)
        };
        assert!(
            build
                .prepare_from(
                    source.to_str().unwrap(),
                    spec.to_str().unwrap(),
                    &state,
                    false
                )
                .is_err()
        );
        // Inspect the production allocator's durable receipt count: merely
        // observing a larger wall-clock-derived ID would not prove a burn.
        let namespace: String = Sha256::digest(b"worker")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let cas = rabsd::janitor::store::mount_and_reconcile(
            &state.join("worker-admission").join(namespace),
        )
        .unwrap();
        let rows = cas
            .store()
            .lock()
            .unwrap()
            .query(
                "SELECT decision FROM decision_receipts WHERE kind = ?1 AND subject = ?2 ORDER BY seq",
                &[
                    SqlValue::Text("rabs-pinned-worker-request-id-v1".into()),
                    SqlValue::Text("worker".into()),
                ],
            )
            .unwrap();
        assert_eq!(
            rows.len(),
            2,
            "failed preparation must durably burn its own ID"
        );
        let [SqlValue::Text(burned)] = rows[1].as_slice() else {
            panic!("missing durable allocation value");
        };
        let burned = u64::from_str_radix(burned, 16).unwrap();
        assert!(burned > first);
        drop(cas);
        let after = PinnedWorkerAdmission::open(&state, "worker", [1; 32]).unwrap();
        assert!(after.allocate_request_id().unwrap() > burned);
        assert!(!bundle.join("request.json").exists());
        assert!(!delivery.exists());
        assert!(!output.exists());
    }

    #[test]
    fn allocation_intent_cannot_enter_standalone_or_plaintext_preparation() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let (source, spec) = allocating_fixture(&root);
        let bundle = root.join("bundle");
        let delivery = root.join("delivery");
        let output = root.join("output");
        let state = root.join("state");
        let build = PreparedBuild {
            bundle: &bundle,
            directory: &delivery,
            output: &output,
            ..preparation_build(&root)
        };
        assert!(
            build
                .prepare_from(
                    source.to_str().unwrap(),
                    spec.to_str().unwrap(),
                    &state,
                    false
                )
                .is_err()
        );
        assert!(!state.exists());
        assert!(!bundle.exists());
        assert!(
            crate::prepare_from_arguments(&[
                source.to_str().unwrap().to_owned(),
                spec.to_str().unwrap().to_owned(),
                bundle.to_str().unwrap().to_owned(),
            ])
            .is_err()
        );
        assert!(!bundle.join("request.json").exists());
        assert!(!state.exists());
    }

    #[test]
    fn numeric_preparation_does_not_open_an_allocator_or_change_the_request_id() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let (source, spec) = preparation_fixture(&root);
        let bundle = root.join("bundle");
        let delivery = root.join("delivery");
        let output = root.join("output");
        let state = root.join("unused-state");
        let pin = "01".repeat(32);
        let build = PreparedBuild {
            pin: Some(&pin),
            bundle: &bundle,
            directory: &delivery,
            output: &output,
            ..preparation_build(&root)
        };
        assert!(
            build
                .prepare_from(
                    source.to_str().unwrap(),
                    spec.to_str().unwrap(),
                    &state,
                    false
                )
                .unwrap()
                .is_none()
        );
        assert_eq!(build.request().unwrap()["request_id"], 91);
        assert!(!state.exists());
    }

    #[test]
    fn reserved_execution_is_not_recovery_and_must_be_bound_to_a_prepared_request() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let state = root.join("state");
        let pin = "01".repeat(32);
        let mut reserved = ReservedWorkerAdmission::open(&state, "worker", [1; 32]).unwrap();
        // An intentionally incomplete request tests binding/refusal only, not
        // execution. Real preparation and durable ownership are covered above.
        let request = json!({"request_id":reserved.request_id, "kind":"canonical-exec"});
        assert!(reserved.validate_request("worker", &pin, &request).is_err());
        let hash: String = Sha256::digest(serde_json::to_vec(&request).unwrap())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let report = json!({"kind":"prepared-source-bundle", "request_id":reserved.request_id,
            "request_sha256":hash});
        reserved.bind_prepared(&report).unwrap();
        assert!(reserved.bind_prepared(&report).is_err());
        let build = PreparedBuild {
            mode: DeliveryMode::Resume,
            pin: Some(&pin),
            ..preparation_build(&root)
        };
        let error = build
            .execute_bound(&request, None, Some(reserved))
            .unwrap_err();
        assert!(error.detail.contains("not result recovery"));
        assert!(error.execution_may_have_run);
        assert!(PinnedWorkerAdmission::open(&state, "worker", [1; 32]).is_ok());
    }

    #[test]
    fn allocation_state_cannot_be_captured_as_source_or_shadow_output_storage() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let (source, spec) = allocating_fixture(&root);
        let bundle = root.join("bundle");
        let delivery = root.join("delivery");
        let output = root.join("output");
        let pin = "01".repeat(32);
        let build = PreparedBuild {
            pin: Some(&pin),
            bundle: &bundle,
            directory: &delivery,
            output: &output,
            ..preparation_build(&root)
        };
        for state in [
            source.join("state"),
            bundle.clone(),
            delivery.clone(),
            output.clone(),
            root.clone(),
        ] {
            assert!(
                build
                    .prepare_from(
                        source.to_str().unwrap(),
                        spec.to_str().unwrap(),
                        &state,
                        false
                    )
                    .is_err()
            );
            assert!(!bundle.exists());
            assert!(!delivery.exists());
            assert!(!output.exists());
        }
        assert!(!source.join("state").exists());
        #[cfg(unix)]
        {
            let alias = root.join("state-alias");
            std::os::unix::fs::symlink(&source, &alias).unwrap();
            assert!(
                build
                    .prepare_from(
                        source.to_str().unwrap(),
                        spec.to_str().unwrap(),
                        &alias,
                        false
                    )
                    .is_err()
            );
            assert!(!source.join("worker-admission").exists());
        }
    }
}
