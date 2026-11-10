//! Server-owned canonical operations admitted after authenticated input transfer.
//!
//! Wire settings contain only logical Cargo intent. The server retains the
//! sealed source and compiler owners, injects every physical path, and keeps
//! the same coordinator publication provenance through final artifact delivery.

use super::remote_toolchains::ReceivedToolchain;
use super::target_state::TargetCacheConfig;
use super::{
    CompilationCommand, CompilationSelection, OperationOutput, OperationProvenance, Profile,
    SharedRuntime, SourceSelection, default_jobs, default_manifest, default_timeout, invalid,
    overlap, private_directory, project_environment, require, run_operation,
};
use crate::coord::{source_manifest, worker_delivery};
use rabs_protocol::authority::CoordinatorAuthority;
use rabs_sandbox::artifact_tree::TreeInventory;
use rabs_sandbox::cargo_target::state::SourceTimestamps;
use rabs_sandbox::source_transfer::{MAX_SOURCE_BYTES, SourceReceiver};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

fn complete_selection(selection: &SourceSelection) -> bool {
    *selection == SourceSelection::Complete
}

/// A strict wire whitelist. Physical roots, executables, socket paths, worker
/// endpoints and persistent-target controls are exclusively server supplied.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RemoteOperationSettings {
    #[serde(default)]
    pub(super) command: CompilationCommand,
    #[serde(default = "default_manifest")]
    pub(super) manifest: String,
    pub(super) vendor: Option<String>,
    #[serde(default, skip_serializing_if = "complete_selection")]
    pub(super) source_selection: SourceSelection,
    pub(super) selection: Option<CompilationSelection>,
    #[serde(default = "default_jobs")]
    pub(super) jobs: u32,
    #[serde(default = "default_timeout")]
    pub(super) timeout_seconds: u64,
    #[serde(default, deserialize_with = "project_environment")]
    pub(super) env: BTreeMap<String, String>,
}

impl RemoteOperationSettings {
    /// Produce the existing source-preparation request from this exact logical
    /// intent. These two host paths are used only by the local capture caller;
    /// source preparation removes them from the executable transfer request.
    pub(super) fn source_specification(
        &self,
        toolchain_root: &Path,
        cargo_home_source: Option<&Path>,
    ) -> io::Result<Value> {
        self.validate()?;
        let mut profile = self.profile();
        profile.toolchain_root = toolchain_root.to_path_buf();
        profile.cargo_home_source = cargo_home_source.map(Path::to_path_buf);
        profile.validate_logical()?;
        profile.source_specification()
    }

    pub(super) fn validate(&self) -> io::Result<()> {
        let profile = self.profile();
        profile.validate_logical()?;
        require(
            !profile.inherits_stdin(),
            "remote canonical service does not accept commands with inherited stdin",
        )?;
        require(
            serde_json::to_vec(self)?.len() <= 64 * 1024,
            "remote canonical settings exceed their byte bound",
        )
    }

    fn profile(&self) -> Profile {
        Profile {
            version: super::PROFILE_VERSION.to_owned(),
            source_root: PathBuf::new(),
            toolchain_root: PathBuf::new(),
            state_root: PathBuf::new(),
            operation_root: PathBuf::new(),
            wrapper: PathBuf::new(),
            service_socket: None,
            command: self.command,
            manifest: self.manifest.clone(),
            vendor: self.vendor.clone(),
            cargo_home_source: None,
            source_selection: self.source_selection,
            selection: self.selection.clone(),
            jobs: self.jobs,
            timeout_seconds: self.timeout_seconds,
            env: self.env.clone(),
            target_cache: None,
        }
    }
}

/// In-process custody constructed from the actual bounded receivers. This
/// type is intentionally neither serializable nor constructible from paths.
pub(super) struct RemoteOperationInputs {
    // Close receiver/compiler handles before releasing their private parent.
    pub(super) source: SourceReceiver,
    pub(super) toolchain: Arc<ReceivedToolchain>,
    pub(super) owner: Arc<tempfile::TempDir>,
    pub(super) request: Value,
    // The transport supplies the authenticated TLS identity. Neither logical
    // settings nor a prepared request may choose a persistent-target namespace.
    authenticated_edge_pin: [u8; 32],
}

impl RemoteOperationInputs {
    pub(super) fn new(
        owner: Arc<tempfile::TempDir>,
        source: SourceReceiver,
        toolchain: Arc<ReceivedToolchain>,
        request: Value,
        authenticated_edge_pin: [u8; 32],
        stopped: &impl Fn() -> bool,
    ) -> io::Result<Self> {
        let inputs = Self {
            source,
            toolchain,
            owner,
            request,
            authenticated_edge_pin,
        };
        inputs.verify(stopped)?;
        Ok(inputs)
    }

    pub(super) fn authenticated_edge_pin(&self) -> [u8; 32] {
        self.authenticated_edge_pin
    }

    fn verify(&self, stopped: &impl Fn() -> bool) -> io::Result<()> {
        checkpoint(stopped)?;
        require(
            self.authenticated_edge_pin != [0; 32],
            "remote input custody requires an authenticated edge key",
        )?;
        private_directory(self.owner.path())?;
        let source = self
            .source
            .sealed_root()
            .ok_or_else(|| invalid("remote source receiver is not sealed"))?;
        require(
            source != self.owner.path()
                && source.starts_with(self.owner.path())
                && !overlap(self.owner.path(), self.toolchain.owner().path()),
            "remote source and compiler must have disjoint retained owners",
        )?;
        private_directory(source)?;
        let allowed = [
            "kind",
            "request_id",
            "program",
            "args",
            "command_context",
            "source_manifest",
            "toolchain_transfer",
            "toolchain_identity",
            "cargo_home",
        ];
        require(
            self.request
                .as_object()
                .is_some_and(|fields| fields.keys().all(|field| allowed.contains(&field.as_str()))),
            "remote prepared request contains unsupported execution or host-path controls",
        )?;
        worker_delivery::validate_local_canonical_request(&self.request)?;
        require(
            self.request["request_id"]
                .as_u64()
                .is_some_and(|id| id != 0)
                && worker_delivery::toolchain_transfer(&self.request)?,
            "remote operation requires an explicit prepared source and compiler transfer",
        )?;
        require(
            source_manifest::request_manifest(&self.request)?.as_ref()
                == Some(self.source.manifest()),
            "remote source owner differs from the prepared request manifest",
        )?;
        require(
            worker_delivery::toolchain_identity(&self.request)?.as_ref()
                == Some(self.toolchain.image().identity()),
            "remote compiler owner differs from the prepared request identity",
        )?;
        verify_source(&self.source, stopped)?;
        self.toolchain.verify(stopped)?;
        checkpoint(stopped)
    }

    pub(super) fn verify_for_profile(
        &self,
        profile: &Profile,
        stopped: &impl Fn() -> bool,
    ) -> io::Result<()> {
        self.verify(stopped)?;
        require(
            self.source.sealed_root() == Some(profile.source_root.as_path())
                && self.toolchain.root() == profile.toolchain_root,
            "remote operation roots differ from their retained input owners",
        )?;
        let expected = profile.source_specification()?;
        require(
            ["program", "args", "command_context"]
                .into_iter()
                .all(|field| self.request.get(field) == expected.get(field)),
            "remote prepared request differs from its logical Cargo settings",
        )
    }
}

fn checkpoint(stopped: &impl Fn() -> bool) -> io::Result<()> {
    if stopped() {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "remote canonical operation cancelled",
        ))
    } else {
        Ok(())
    }
}

fn verify_source(source: &SourceReceiver, stopped: &impl Fn() -> bool) -> io::Result<()> {
    let root = source
        .sealed_root()
        .ok_or_else(|| invalid("remote source lost its sealed receiver"))?;
    // The complete walk rejects extra members; the shared timestamp verifier
    // checks every declared byte, mode and ordinary-file ownership through
    // anchored descriptors. A sealed flag alone is not a fresh byte check.
    let inventory = TreeInventory::scan_complete_private(root, MAX_SOURCE_BYTES, stopped)?;
    require(
        inventory.names().eq(source
            .manifest()
            .files()
            .iter()
            .map(|file| file.path.as_str())),
        "remote source no longer matches its complete transferred file set",
    )?;
    SourceTimestamps::capture(root, source.manifest(), stopped)?;
    inventory.verify(stopped)
}

/// One operation's typed result and its live provenance. Retain this value
/// until sealed artifact transfer and the client's acknowledgment complete.
pub(super) struct RemoteOperationOutcome {
    pub(super) exit_code: i32,
    pub(super) retained_target: Option<PathBuf>,
    provenance: OperationProvenance,
    runtime: Arc<SharedRuntime>,
    authority: CoordinatorAuthority,
    stopped: Arc<AtomicBool>,
}

impl RemoteOperationOutcome {
    /// Call after artifact sealing and again immediately before terminal
    /// success. Transfer checks cannot substitute for current producer safety.
    pub(super) fn verify_before_delivery(
        &self,
        external_stopped: &impl Fn() -> bool,
    ) -> io::Result<()> {
        let cancelled = || {
            external_stopped() || self.stopped.load(Ordering::Acquire) || !self.runtime.healthy()
        };
        checkpoint(&cancelled)?;
        require(
            self.provenance.coord.authority().as_ref() == Some(&self.authority),
            "remote completion lost its original coordinator authority",
        )?;
        self.provenance
            .paths
            .verify_captured_toolchain(&cancelled)?;
        verify_source(&self.provenance._source, &cancelled)?;
        self.provenance
            .paths
            .verify_completed_producers(&self.provenance.coord, &cancelled)
    }
}

/// Dropping an unjoined operation first cancels it, then joins all of its
/// operation-owned writers. Shared producers retain their other subscribers.
pub(super) struct RemoteOperationOwner {
    stopped: Arc<AtomicBool>,
    thread: Option<JoinHandle<io::Result<RemoteOperationOutcome>>>,
}

impl RemoteOperationOwner {
    pub(super) fn finished(&self) -> bool {
        self.thread.as_ref().is_none_or(JoinHandle::is_finished)
    }

    pub(super) fn cancel(&self) {
        self.stopped.store(true, Ordering::Release);
    }

    pub(super) fn join(mut self) -> io::Result<RemoteOperationOutcome> {
        self.thread
            .take()
            .ok_or_else(|| invalid("remote canonical operation was already joined"))?
            .join()
            .map_err(|_| io::Error::other("remote canonical operation panicked"))?
    }
}

impl Drop for RemoteOperationOwner {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.cancel();
            let _ = thread.join();
        }
    }
}

/// Start only after the frontend has authenticated, reserved a bounded
/// operation slot and received the complete sealed inputs. Every filesystem
/// binding here is server supplied, independently of the settings on the wire.
#[allow(clippy::too_many_arguments)]
pub(super) fn start(
    runtime: Arc<SharedRuntime>,
    wrapper: PathBuf,
    operation_root: PathBuf,
    target_cache: Option<TargetCacheConfig>,
    inputs: RemoteOperationInputs,
    settings: RemoteOperationSettings,
    stdout: File,
    stderr: File,
    stopped: Arc<AtomicBool>,
    maximum_output_bytes: u64,
) -> io::Result<RemoteOperationOwner> {
    settings.validate()?;
    checkpoint(&|| stopped.load(Ordering::Acquire))?;
    require(
        runtime.healthy() && settings.jobs <= runtime.jobs_per_root,
        "remote canonical service is unavailable or its job grant was exceeded",
    )?;
    let mut profile = settings.profile();
    profile.source_root = inputs
        .source
        .sealed_root()
        .ok_or_else(|| invalid("remote source receiver is not sealed"))?
        .to_path_buf();
    profile.toolchain_root = inputs.toolchain.root().to_path_buf();
    profile.state_root = runtime.parent.clone();
    profile.operation_root = operation_root;
    profile.wrapper = wrapper;
    profile.target_cache = target_cache;
    profile.validate()?;
    // Admission already sealed and verified these receivers under its input
    // deadline. run_operation rechecks their exact profile binding and bytes
    // inside the owned thread before execution, where the transport can cancel
    // and join that work. Do not repeat the full scan on the session thread.
    let output = OperationOutput::captured(stdout, stderr, maximum_output_bytes)?;
    let authority = runtime
        .coord
        .authority()
        .ok_or_else(|| invalid("remote canonical coordinator has no active authority"))?;
    let child_stop = Arc::clone(&stopped);
    let thread = std::thread::Builder::new()
        .name("rabs-remote-canonical-build".into())
        .spawn(move || {
            let outcome = run_operation(
                profile,
                runtime.release_mode,
                runtime.build_identity.clone(),
                Some(Arc::clone(&runtime)),
                Arc::clone(&child_stop),
                output,
                Some(inputs),
            )?;
            let outcome = RemoteOperationOutcome {
                exit_code: outcome.exit_code,
                retained_target: outcome.retained_target,
                provenance: outcome.provenance,
                runtime,
                authority,
                stopped: child_stop,
            };
            outcome.verify_before_delivery(&|| false)?;
            Ok(outcome)
        })?;
    Ok(RemoteOperationOwner {
        stopped,
        thread: Some(thread),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::raw_bytes::encode_hex;
    use rabs_sandbox::source_transfer::{SourceFile, SourceManifest};
    use rabs_sandbox::toolchain_dataset::{ToolchainLimits, capture_toolchain};
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::time::Duration;

    fn settings(value: Value) -> RemoteOperationSettings {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn remote_settings_reject_host_controls_and_preserve_logical_selection() {
        let value = json!({"command":"build", "manifest":"member/Cargo.toml",
            "selection":{"packages":["member"], "release":true},
            "jobs":2, "timeout_seconds":90, "env":{"FEATURE_INPUT":"enabled"}});
        let selected = settings(value.clone());
        selected.validate().unwrap();
        let encoded = serde_json::to_value(&selected).unwrap();
        assert!(encoded.get("source_selection").is_none());
        assert!(encoded.get("source_root").is_none());
        settings(encoded).validate().unwrap();
        let request = selected
            .source_specification(Path::new("/client/toolchain"), None)
            .unwrap();
        assert_eq!(request["toolchain_source"], "/client/toolchain");
        assert_eq!(request["cargo_source"]["manifest"], "member/Cargo.toml");
        assert_eq!(
            request["command_context"]["env"]["FEATURE_INPUT"],
            "enabled"
        );
        for field in [
            "source_root",
            "toolchain_root",
            "state_root",
            "operation_root",
            "wrapper",
            "service_socket",
            "cargo_home_source",
            "workspace_backing",
            "toolchain_backing",
            "remote_workers",
            "target_cache",
            "authenticated_edge_pin",
            "program",
            "args",
        ] {
            let mut injected = value.clone();
            injected[field] = json!("/peer/selected");
            assert!(
                serde_json::from_value::<RemoteOperationSettings>(injected).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn remote_settings_retain_existing_control_environment_and_stdin_refusals() {
        for value in [
            json!({"manifest":"../Cargo.toml"}),
            json!({"vendor":"/host/vendor"}),
            json!({"command":"run"}),
            json!({"command":"bench"}),
            json!({"jobs":0}),
            json!({"timeout_seconds":7201}),
            json!({"env":{"RABS_DEPENDENCY_WORKERS_JSON":"[]"}}),
            json!({"env":{"RUSTC_WRAPPER":"/peer/tool"}}),
            json!({"selection":{"target":["/peer/target.json"]}}),
        ] {
            assert!(settings(value.clone()).validate().is_err(), "{value}");
        }
        assert!(
            serde_json::from_str::<RemoteOperationSettings>(
                r#"{"env":{"INPUT":"first","INPUT":"second"}}"#,
            )
            .is_err()
        );
        settings(json!({"command":"bench", "selection":{"no_run":true}}))
            .validate()
            .unwrap();
    }

    fn fixture() -> RemoteOperationInputs {
        fixture_with_owner(Arc::new(crate::test_util::private_tempdir()))
    }

    fn fixture_with_owner(owner: Arc<tempfile::TempDir>) -> RemoteOperationInputs {
        let compiler_source = tempfile::tempdir().unwrap();
        let sdk_owner = Arc::new(crate::test_util::private_tempdir());
        fs::create_dir(compiler_source.path().join("lib")).unwrap();
        fs::write(
            compiler_source.path().join("compiler-data"),
            b"fixture dataset",
        )
        .unwrap();
        let toolchain = Arc::new(
            capture_toolchain(
                compiler_source.path(),
                &sdk_owner.path().join("toolchain"),
                None,
                &ToolchainLimits::default(),
                || false,
            )
            .unwrap(),
        );
        let toolchain = Arc::new(ReceivedToolchain::new(sdk_owner, toolchain, || false).unwrap());
        let bytes = b"[package]\nname = 'input-owner-fixture'\nversion = '0.1.0'\n";
        let manifest = SourceManifest::new(vec![SourceFile {
            path: "Cargo.toml".into(),
            len: bytes.len() as u64,
            sha256: Sha256::digest(bytes).into(),
            executable: false,
        }])
        .unwrap();
        let mut source =
            SourceReceiver::create(&owner.path().join("source"), manifest.clone()).unwrap();
        source
            .write_chunk("Cargo.toml", 0, bytes, Sha256::digest(bytes).into())
            .unwrap();
        source.seal().unwrap();
        let mut request = settings(json!({}))
            .source_specification(toolchain.root(), None)
            .unwrap();
        let object = request.as_object_mut().unwrap();
        object.remove("toolchain_source");
        object.remove("cargo_source");
        request["source_manifest"] = json!({"manifest_sha256":encode_hex(&manifest.digest()),
            "files":[{"path":"Cargo.toml", "bytes":bytes.len(),
                "sha256":encode_hex(&Sha256::digest(bytes)), "executable":false}]});
        request["toolchain_transfer"] =
            json!(rabs_sandbox::toolchain_transfer::TOOLCHAIN_TRANSFER_VERSION);
        request["toolchain_identity"] =
            worker_delivery::toolchain_identity_value(toolchain.identity());
        RemoteOperationInputs::new(owner, source, toolchain, request, [7; 32], &|| false).unwrap()
    }

    #[test]
    fn remote_input_custody_preserves_the_authenticated_peer() {
        let inputs = fixture();
        assert_eq!(inputs.authenticated_edge_pin(), [7; 32]);
        let request = inputs.request.clone();
        let source_root = inputs.source.sealed_root().unwrap().to_path_buf();
        let sdk_root = inputs.toolchain.root().to_path_buf();
        let inputs = RemoteOperationInputs::new(
            inputs.owner,
            inputs.source,
            inputs.toolchain,
            inputs.request,
            [29; 32],
            &|| false,
        )
        .unwrap();
        inputs.verify(&|| false).unwrap();
        assert_eq!(inputs.authenticated_edge_pin(), [29; 32]);
        assert_eq!(inputs.request, request);
        assert_eq!(inputs.source.sealed_root(), Some(source_root.as_path()));
        assert_eq!(inputs.toolchain.root(), sdk_root);

        // Server target policy is independent of the prepared logical intent;
        // it cannot alter the retained source/compiler or replace the TLS peer.
        let mut profile = settings(json!({})).profile();
        assert!(profile.target_cache.is_none());
        profile.source_root = source_root;
        profile.toolchain_root = sdk_root;
        profile.target_cache = Some(TargetCacheConfig {
            runtime_epoch: "coordinator-runtime-1".into(),
            max_bytes: 1024 * 1024,
            max_families: 2,
        });
        inputs.verify_for_profile(&profile, &|| false).unwrap();
        assert_eq!(inputs.authenticated_edge_pin(), [29; 32]);
    }

    #[test]
    fn remote_input_custody_rejects_missing_or_client_injected_peer() {
        let inputs = fixture();
        let refused = RemoteOperationInputs::new(
            inputs.owner,
            inputs.source,
            inputs.toolchain,
            inputs.request,
            [0; 32],
            &|| false,
        );
        assert!(
            refused
                .err()
                .unwrap()
                .to_string()
                .contains("authenticated edge key")
        );

        let mut inputs = fixture();
        inputs.authenticated_edge_pin = [0; 32];
        assert!(inputs.verify(&|| false).is_err());

        let mut inputs = fixture();
        inputs.request["authenticated_edge_pin"] = json!("1d".repeat(32));
        assert!(inputs.verify(&|| false).is_err());
        assert_eq!(inputs.authenticated_edge_pin(), [7; 32]);

        for value in [
            json!({"target_cache":{"runtime_epoch":"client-selected"}}),
            json!({"authenticated_edge_pin":"1d".repeat(32)}),
        ] {
            assert!(serde_json::from_value::<RemoteOperationSettings>(value).is_err());
        }
    }

    #[test]
    fn remote_inputs_refuse_unowned_stale_and_mismatched_captures() {
        let inputs = fixture();
        let foreign = Arc::new(crate::test_util::private_tempdir());
        assert!(
            RemoteOperationInputs::new(
                foreign,
                inputs.source,
                inputs.toolchain,
                inputs.request,
                inputs.authenticated_edge_pin,
                &|| false
            )
            .is_err()
        );
        let mut inputs = fixture();
        inputs.request["toolchain_identity"]["sha256"] = json!("00".repeat(32));
        assert!(inputs.verify(&|| false).is_err());
        let inputs = fixture();
        fs::write(
            inputs.source.sealed_root().unwrap().join("extra-input"),
            b"undeclared",
        )
        .unwrap();
        assert!(inputs.verify(&|| false).is_err());
        let inputs = fixture();
        let path = inputs.source.sealed_root().unwrap().join("Cargo.toml");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(path, b"changed after sealing").unwrap();
        assert!(inputs.verify(&|| false).is_err());
    }

    #[test]
    fn remote_input_admission_observes_the_original_cancellation_budget() {
        let inputs = fixture();
        let result = RemoteOperationInputs::new(
            inputs.owner,
            inputs.source,
            inputs.toolchain,
            inputs.request,
            inputs.authenticated_edge_pin,
            &|| true,
        );
        assert_eq!(result.err().unwrap().kind(), io::ErrorKind::Interrupted);
    }

    #[test]
    fn remote_preparation_must_bind_the_exact_logical_command() {
        let inputs = fixture();
        let mut profile = settings(json!({})).profile();
        profile.source_root = inputs.source.sealed_root().unwrap().to_path_buf();
        profile.toolchain_root = inputs.toolchain.root().to_path_buf();
        inputs.verify_for_profile(&profile, &|| false).unwrap();
        profile.command = CompilationCommand::Build;
        let refusal = inputs.verify_for_profile(&profile, &|| false).unwrap_err();
        assert!(refusal.to_string().contains("logical Cargo settings"));
        profile.command = CompilationCommand::Check;
        profile.env.insert("CONFIGURATION".into(), "changed".into());
        assert!(inputs.verify_for_profile(&profile, &|| false).is_err());
    }

    #[test]
    fn canonical_producer_owner_retains_uploaded_inputs_after_request_drop() {
        let inputs = fixture();
        let input_root = inputs.owner.path().to_path_buf();
        let sdk_root = inputs.toolchain.owner().path().to_path_buf();
        let runtime = Arc::new(crate::test_util::private_tempdir());
        let runtime_root = runtime.path().to_path_buf();
        let paths = remote_paths(&inputs, &runtime);
        drop(inputs);
        drop(runtime);
        let subscriber = Arc::clone(&paths);
        drop(paths);
        assert!(runtime_root.join("target").is_dir());
        assert!(input_root.join("source/Cargo.toml").is_file());
        assert!(sdk_root.join("toolchain/compiler-data").is_file());
        subscriber
            .captured_toolchain()
            .unwrap()
            .verify_retained_generation(|| false)
            .unwrap();
        drop(subscriber);
        assert!(!runtime_root.exists());
        assert!(!input_root.exists());
        assert!(!sdk_root.exists());
    }

    #[test]
    fn shared_sdk_does_not_retain_another_operations_source_or_runtime() {
        let first = fixture();
        let mut second = fixture();
        second.toolchain = Arc::clone(&first.toolchain);
        second.verify(&|| false).unwrap();
        let first_source = first.owner.path().to_path_buf();
        let second_source = second.owner.path().to_path_buf();
        let sdk_root = first.toolchain.owner().path().to_path_buf();
        let first_runtime = Arc::new(crate::test_util::private_tempdir());
        let second_runtime = Arc::new(crate::test_util::private_tempdir());
        let first_runtime_path = first_runtime.path().to_path_buf();
        let second_runtime_path = second_runtime.path().to_path_buf();
        let first_paths = remote_paths(&first, &first_runtime);
        let second_paths = remote_paths(&second, &second_runtime);
        assert!(Arc::ptr_eq(
            first_paths.captured_toolchain().unwrap(),
            second_paths.captured_toolchain().unwrap(),
        ));
        drop((first, first_runtime, first_paths));
        assert!(!first_source.exists());
        assert!(!first_runtime_path.exists());
        assert!(second_source.join("source/Cargo.toml").is_file());
        assert!(sdk_root.join("toolchain/compiler-data").is_file());
        second_paths.verify_captured_toolchain(&|| false).unwrap();
        // A downstream upload can keep only the SDK image and its actual
        // owner after the canonical operation and source have drained.
        let image = Arc::clone(second_paths.captured_toolchain().unwrap());
        let sdk_owner = Arc::clone(second.toolchain.owner());
        drop((second, second_runtime, second_paths));
        assert!(!second_source.exists());
        assert!(!second_runtime_path.exists());
        image.verify_retained_generation(|| false).unwrap();
        assert_eq!(sdk_owner.path(), sdk_root);
        drop(image);
        drop(sdk_owner);
        assert!(!sdk_root.exists());
    }

    #[test]
    fn received_sdk_only_authorizes_its_exact_readonly_compiler_mount() {
        let inputs = fixture();
        let runtime = Arc::new(crate::test_util::private_tempdir());
        let paths = remote_paths(&inputs, &runtime);
        let logical_roots = [
            "/__rabs/workspace",
            "/__rabs/cargo-home",
            "/__rabs/toolchain",
            "/__rabs/out/cargo",
            "/__rabs/home",
        ];
        let mappings = logical_roots
            .iter()
            .map(|root| {
                (
                    PathBuf::from(root),
                    paths.physical(Path::new(root)).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        // A legitimate captured subdirectory keeps lease verification valid;
        // the refusal must come from the mount capability, not corrupt data.
        let unrelated_sdk_directory = inputs.toolchain.root().join("lib");
        inputs.toolchain.verify(|| false).unwrap();
        for index in 0..logical_roots.len() {
            let mut forged = mappings.clone();
            forged[index].1 = unrelated_sdk_directory.clone();
            assert!(
                super::super::CanonicalPaths::new_with_received_toolchain(
                    Arc::clone(&runtime),
                    Arc::clone(&inputs.owner),
                    Arc::clone(&inputs.toolchain),
                    forged,
                )
                .is_err(),
                "received SDK custody authorized {} outside its declared mount",
                logical_roots[index],
            );
        }
        let foreign = fixture();
        assert!(
            super::super::CanonicalPaths::new_with_received_toolchain(
                runtime,
                Arc::clone(&inputs.owner),
                Arc::clone(&foreign.toolchain),
                mappings,
            )
            .is_err()
        );
    }

    #[test]
    fn shared_sdk_mutation_invalidates_every_retained_operation() {
        let first = fixture();
        let mut second = fixture();
        second.toolchain = Arc::clone(&first.toolchain);
        let runtime = Arc::new(crate::test_util::private_tempdir());
        let paths = remote_paths(&first, &runtime);
        let compiler = first.toolchain.root().join("compiler-data");
        fs::set_permissions(&compiler, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&compiler, b"changed dataset").unwrap();
        assert!(first.verify(&|| false).is_err());
        assert!(second.verify(&|| false).is_err());
        assert!(paths.verify_captured_toolchain(&|| false).is_err());
    }

    fn remote_paths(
        inputs: &RemoteOperationInputs,
        runtime: &Arc<tempfile::TempDir>,
    ) -> Arc<super::super::CanonicalPaths> {
        let root = runtime.path();
        for child in ["cargo-home", "target", "home"] {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(root.join(child))
                .unwrap();
        }
        super::super::CanonicalPaths::new_with_received_toolchain(
            Arc::clone(runtime),
            Arc::clone(&inputs.owner),
            Arc::clone(&inputs.toolchain),
            vec![
                (
                    "/__rabs/workspace".into(),
                    inputs.source.sealed_root().unwrap().to_path_buf(),
                ),
                ("/__rabs/cargo-home".into(), root.join("cargo-home")),
                (
                    "/__rabs/toolchain".into(),
                    inputs.toolchain.root().to_path_buf(),
                ),
                (super::super::TARGET.into(), root.join("target")),
                ("/__rabs/home".into(), root.join("home")),
            ],
        )
        .unwrap()
        .with_captured_toolchain(Some(Arc::clone(inputs.toolchain.image())))
        .unwrap()
    }

    #[test]
    fn long_upload_directory_keeps_the_real_unix_socket_under_the_short_runtime_root() {
        use std::os::unix::net::{UnixListener, UnixStream};

        let parent = tempfile::Builder::new()
            .prefix("rabs-r-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in("/tmp")
            .unwrap();
        let input_owner = Arc::new(
            tempfile::Builder::new()
                .prefix(&"uploaded-inputs-".repeat(10))
                .permissions(fs::Permissions::from_mode(0o700))
                .tempdir_in(parent.path())
                .unwrap(),
        );
        let inputs = fixture_with_owner(input_owner);
        assert!(
            inputs
                .owner
                .path()
                .join("home/control/rustc.sock")
                .as_os_str()
                .as_encoded_bytes()
                .len()
                >= 108
        );
        let runtime = Arc::new(
            tempfile::Builder::new()
                .prefix("rabs-compile-")
                .permissions(fs::Permissions::from_mode(0o700))
                .tempdir_in(parent.path())
                .unwrap(),
        );
        let paths = remote_paths(&inputs, &runtime);
        let control = paths
            .physical(Path::new("/__rabs/home"))
            .unwrap()
            .join("control");
        fs::DirBuilder::new().mode(0o700).create(&control).unwrap();
        let socket = control.join("rustc.sock");
        assert!(socket.starts_with(runtime.path()));
        assert!(!socket.starts_with(inputs.owner.path()));
        assert!(socket.as_os_str().as_encoded_bytes().len() < 108);
        let listener = UnixListener::bind(&socket).unwrap();
        let client = UnixStream::connect(&socket).unwrap();
        let (server, _) = listener.accept().unwrap();
        drop((client, server, listener));
        assert_eq!(
            paths.physical(Path::new("/__rabs/workspace")).unwrap(),
            inputs.source.sealed_root().unwrap()
        );
        assert_eq!(
            paths.physical(Path::new("/__rabs/toolchain")).unwrap(),
            inputs.toolchain.root()
        );
    }

    #[test]
    fn dropping_remote_operation_cancels_and_joins_its_owner() {
        let stopped = Arc::new(AtomicBool::new(false));
        let joined = Arc::new(AtomicBool::new(false));
        let child_stop = Arc::clone(&stopped);
        let child_joined = Arc::clone(&joined);
        let thread = std::thread::spawn(move || {
            while !child_stop.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(1));
            }
            child_joined.store(true, Ordering::Release);
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "cancelled fixture owner",
            ))
        });
        drop(RemoteOperationOwner {
            stopped: Arc::clone(&stopped),
            thread: Some(thread),
        });
        assert!(stopped.load(Ordering::Acquire));
        assert!(joined.load(Ordering::Acquire));
    }
}
