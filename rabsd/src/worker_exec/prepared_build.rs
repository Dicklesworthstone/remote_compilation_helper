//! Operator vertical slice: retained source -> verified delivery -> private outputs.
//! The delivery receipt is the recovery boundary. Installation may be retried
//! offline, and an uncertain execution is never converted into another dispatch.

use super::{
    Delivery, DeliveryFailure, DeliveryMode, DeliveryTrust, WorkerOperation, invalid,
    operation_arguments, operation_failure, prepare_resume_source, read_request, recover_existing_delivery,
    request_manifest, run_loopback_operation, run_tls_operation, run_tls_operation_inner,
    TlsOperationControl,
};
use rabsd::coord::delivery_recovery::{InstalledOutputs, install_delivery_outputs};
use rabsd::coord::secure_worker_delivery::parse_worker_pin;
use serde_json::{Value, json};
use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

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

    fn execute(&self) -> Result<(Delivery, Option<InstalledOutputs>), DeliveryFailure> {
        let request = self.request()?;
        self.execute_bound(&request, None)
    }

    /// The daemon supplies the exact request it durably accepted. Neither its
    /// queued identity nor its recovery path is reloaded from request.json.
    fn execute_bound(
        &self,
        request: &Value,
        control: Option<TlsOperationControl<'_>>,
    ) -> Result<(Delivery, Option<InstalledOutputs>), DeliveryFailure> {
        self.validate_paths(false).map_err(|error| self.failure(error.to_string()))?;
        super::validate_request(request).map_err(|error| self.failure(error.to_string()))?;
        if request_manifest(request).map_err(|error| self.failure(error.to_string()))?.is_none()
            || request.get("artifacts").is_none()
        {
            return Err(self.failure("prepared builds require source_manifest and artifacts".to_owned()));
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
        let delivery = match recover_existing_delivery(
            request,
            self.worker,
            self.directory,
            trust,
        )? {
            Some(delivery) => delivery,
            None => {
                if control.as_ref().is_some_and(|control| control.cancellation.is_cancelled()) {
                    return Err(self.failure("prepared operation cancelled before dispatch".to_owned()));
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
                if let Some(reuse) = prepare_resume_source(self.mode, self.resume_from, self.directory)
                    .map_err(|error| self.failure(error.to_string()))?
                {
                    for path in [self.bundle, self.output] {
                        reuse.validate_destination(path).map_err(|error| self.failure(error.to_string()))?;
                    }
                }
                let source = self.bundle.join("source");
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
                    resume_from: self.resume_from,
                };
                match self.pin {
                    Some(pin) if control.is_some() => run_tls_operation_inner(operation, pin, control)?,
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
                    detail,
                })?;
        Ok((delivery, Some(installed)))
    }

    fn report(&self) -> i32 {
        let result = self.execute().and_then(|(delivery, installed)| {
            let report = self.report_value(&delivery, installed.as_ref());
            let mut stdout = io::stdout().lock();
            writeln!(stdout, "{report}")
                .and_then(|()| stdout.flush())
                .map_err(|error| DeliveryFailure {
                    directory: self.directory.to_path_buf(),
                    execution_may_have_run: true,
                    detail: format!("build completed but its status could not be written: {error}"),
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
        match result {
            Ok(code) => code,
            Err(error) => {
                eprintln!(
                    "{}",
                    json!({
                        "kind":"worker-build-error", "directory":error.directory,
                        "output_directory":self.output, "detail":error.detail,
                        "execution_may_have_run":error.execution_may_have_run, "reexecute":false,
                    })
                );
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

fn run(args: &[String], tls: bool) -> i32 {
    let count = if tls { 6 } else { 5 };
    let Some((args, mode, resume_from)) = operation_arguments(args, count).filter(|(args, _, _)| {
        args.iter()
            .all(|arg| !arg.is_empty() && !arg.starts_with("--"))
    }) else {
        eprintln!(
            "usage: rabsd --worker-build-{} [--resume | --resume-from <absolute-old-delivery>] <IP:port> <worker> {}<absolute-bundle-directory> <absolute-delivery-directory> <absolute-output-directory>",
            if tls { "tls" } else { "loopback" },
            if tls { "<worker-spki-sha256> " } else { "" }
        );
        eprintln!(
            "The bundle supplies request.json and source/. New execution installs successful verified outputs; resume retrieves a retained result without source upload or execution. --resume-from may reuse independently verified local prefixes in a NEW delivery directory."
        );
        return 2;
    };
    let offset = if tls { 3 } else { 2 };
    PreparedBuild {
        address: &args[0],
        worker: &args[1],
        pin: tls.then(|| args[2].as_str()),
        bundle: Path::new(&args[offset]),
        directory: Path::new(&args[offset + 1]),
        output: Path::new(&args[offset + 2]),
        mode,
        resume_from,
    }
    .report()
}

pub fn run_build(args: &[String]) -> i32 {
    run(args, false)
}
pub fn run_build_tls(args: &[String]) -> i32 {
    run(args, true)
}

/// Run one durable daemon claim without writing CLI output or subscribing to
/// process signals. The caller owns a dedicated blocking thread and persists
/// the returned outcome through `OperationClaim::finish` before releasing it.
pub fn execute_prepared_operation(
    claim: &rabsd::coord::prepared_operation::OperationClaim,
) -> rabsd::coord::prepared_operation::OperationOutcome {
    use rabsd::coord::prepared_operation::OperationOutcome;
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
        on_listening: &mut on_listening,
    };
    let acknowledgment_only = claim.acknowledgment_only();
    let outcome = if acknowledgment_only {
        // Acceptance reconciles the retained delivery, independently of later
        // edits to the operator's installed output tree. It never replaces or
        // reinstalls those files and needs no source bundle.
        super::run_tls_acknowledgment_bound(
            &spec.address, &spec.worker, &spec.worker_spki_sha256, claim.request(),
            &spec.delivery, Some(control),
        ).map(|delivery| (delivery, None))
    } else {
        build.execute_bound(claim.request(), Some(control))
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
        Err(error) => OperationOutcome::Failed {
            detail: error.detail,
            execution_may_have_run: error.execution_may_have_run,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let error = build.execute().unwrap_err();
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
        fs::write(bundle.join("source/lib.rs"), b"changed source").unwrap();
        let pin = "ab".repeat(32);
        let build = PreparedBuild {
            address:"127.0.0.1:0", worker:"worker", pin:Some(&pin), bundle:&bundle,
            directory:&directory, output:&output, mode:DeliveryMode::Execute, resume_from:None,
        };
        let mut listened = false;
        let mut on_listening = |_| { listened = true; Ok(()) };
        let control = TlsOperationControl {
            cancellation:super::super::OperationCancellation::default(),
            on_listening:&mut on_listening,
        };
        let error = build.execute_bound(&request, Some(control)).unwrap_err();
        assert!(error.detail.contains("captured source differs from"), "{}", error.detail);
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
            address:"127.0.0.1:0", worker:"worker", pin:Some(&pin), bundle:&bundle,
            directory:&directory, output:&output, mode:DeliveryMode::Execute, resume_from:None,
        };
        let token = super::super::OperationCancellation::default();
        token.cancel();
        let mut on_listening = |_| panic!("cancelled operation cannot listen");
        let error = build.execute_bound(&request, Some(TlsOperationControl {
            cancellation:token, on_listening:&mut on_listening,
        })).unwrap_err();
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
                address:"invalid-address", worker:"worker", pin:None,
                bundle:&bundle, directory:&directory, output:&output,
                mode:DeliveryMode::Resume, resume_from:Some(resume_from),
            };
            let error = build.execute().unwrap_err();
            assert!(error.execution_may_have_run);
            assert!(error.detail.contains("overlap"));
            assert!(!directory.exists());
            assert!(!output.exists());
        }
        assert_eq!(fs::read(source.join("lib.rs")).unwrap(), b"source");
        assert!(fs::read_dir(old).unwrap().next().is_none());
    }
}
