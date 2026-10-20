//! Live remote execution of closed metadata-only dependency actions.
//!
//! A reserved worker slot is not an execution lease. The authenticated transport
//! supplies the actual worker offer before any inputs or execution are sent;
//! only that offer can admit this action into the existing coordinator. Complete
//! verified output stays private through capture/publication and a second,
//! manifest-specific wrapper acknowledgment. A transport-loss result never
//! declares an unobserved remote compiler drained.

use super::{
    CanonicalActionResultManifest, CompletionOutcome, CompletionReport, CoordLive,
    DependencyActionPlan, ExecutionAttempt, InstallResult, LiveDecision, LiveDependencyKey,
    LiveDependencyLane, LiveDependencyRequest, MAX_TRANSCRIPT_BYTES, Path, PathBuf, ServeOutcome,
    ToolchainGuard, TypedDigest, WorkerSessionOffer, canonicalize_placements, expected_outputs,
    known_installed_output, now_micros, read_stable, render_placements,
};
use crate::coord::remote_dependency_transport::{
    RemoteDependencyReservation, RemoteDependencyTransport,
};
use crate::coord::secure_worker_delivery::{OperationCancellation, parse_worker_pin};
use crate::coord::source_delivery::SourceUpload;
use crate::coord::worker_delivery::{Delivery, toolchain_identity_value};
use crate::edge::live_facts::{GENERATED_ROOT, PACKAGE_ROOT};
use rabs_key::live_dependency::remote::{
    remote_dependency_key, remote_dependency_shape, remote_empty_loader_directories,
};
use rabs_key::live_dependency::{DependencyDirectoryFact, ToolchainFacts};
use rabs_protocol::generation::AttemptAuthority;
use rabs_protocol::input_evidence::ActionInputManifest;
use rabs_protocol::result_identity::OutputRole;
use rabs_sandbox::dependency_context::{
    DEPENDENCY_CONTEXT_VERSION, DependencyArtifactRoot, DependencyExecContext,
};
use rabs_sandbox::loader_directories::{LoaderDirectoryWitness, observe_loader_directories};
use rabs_sandbox::runtime_cohort::observe_runtime_cohort;
use rabs_sandbox::toolchain_dataset::{PreparedToolchain, ToolchainLimits, capture_toolchain};
use rabs_sandbox::toolchain_transfer::TOOLCHAIN_TRANSFER_VERSION;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

mod recovery;

const CONFIG_KEYS: [&str; 3] = [
    "RABS_DEPENDENCY_WORKER_LISTEN",
    "RABS_DEPENDENCY_WORKER_ID",
    "RABS_DEPENDENCY_WORKER_SPKI_SHA256",
];
const POOL_CONFIG_KEY: &str = "RABS_DEPENDENCY_WORKERS_JSON";
const MAX_WORKER_CONFIG_BYTES: usize = 128 * 1024;
/// One explicitly pinned worker per slot; the edge execution lane uses this bound.
pub const MAX_DEPENDENCY_WORKERS: usize = 32;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn invalid(reason: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason.to_string())
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerEndpoint {
    listen: SocketAddr,
    worker_id: String,
    worker_spki_sha256: String,
}

impl WorkerEndpoint {
    fn value(&self) -> Value {
        json!({
            "listen":self.listen.to_string(), "worker_id":self.worker_id,
            "worker_spki_sha256":self.worker_spki_sha256,
        })
    }
}

#[derive(Debug)]
struct WorkerConfiguration {
    endpoints: Vec<WorkerEndpoint>,
    pool: bool,
}

impl WorkerConfiguration {
    /// Parse without reading process state so all configuration refusal paths
    /// can be exercised without mutating the concurrent daemon's environment.
    fn parse(pool: Option<&str>, legacy: [Option<&str>; 3]) -> io::Result<Option<Self>> {
        let (endpoints, pool) = if let Some(value) = pool {
            if legacy.iter().any(Option::is_some) {
                return Err(invalid(
                    "dependency worker pool cannot be mixed with singleton settings",
                ));
            }
            if value.len() > MAX_WORKER_CONFIG_BYTES {
                return Err(invalid(
                    "dependency worker pool exceeds the configuration byte limit",
                ));
            }
            let endpoints: Vec<WorkerEndpoint> = serde_json::from_str(value)
                .map_err(|error| invalid(format!("invalid dependency worker pool: {error}")))?;
            (endpoints, true)
        } else {
            if legacy.iter().all(Option::is_none) {
                return Ok(None);
            }
            let required = |index: usize| {
                legacy[index]
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| invalid(format!("missing {}", CONFIG_KEYS[index])))
            };
            (
                vec![WorkerEndpoint {
                    listen: required(0)?.parse().map_err(|error| {
                        invalid(format!("invalid dependency worker listener: {error}"))
                    })?,
                    worker_id: required(1)?.to_owned(),
                    worker_spki_sha256: required(2)?.to_owned(),
                }],
                false,
            )
        };
        if endpoints.is_empty() || endpoints.len() > MAX_DEPENDENCY_WORKERS {
            return Err(invalid(format!(
                "dependency worker pool requires 1..={MAX_DEPENDENCY_WORKERS} workers"
            )));
        }
        let mut addresses = HashSet::new();
        let mut names = HashSet::new();
        let mut pins = HashSet::new();
        for endpoint in &endpoints {
            if endpoint.listen.port() == 0 {
                return Err(invalid(
                    "remote dependency listener requires a fixed nonzero port",
                ));
            }
            if endpoint.worker_id.is_empty()
                || endpoint.worker_id.len() > 1024
                || endpoint.worker_id.chars().any(char::is_control)
            {
                return Err(invalid("remote dependency worker name is empty or invalid"));
            }
            let pin = parse_worker_pin(&endpoint.worker_spki_sha256)?;
            if !addresses.insert(endpoint.listen) {
                return Err(invalid("duplicate dependency worker listener"));
            }
            if !names.insert(endpoint.worker_id.as_str()) {
                return Err(invalid("duplicate dependency worker identity"));
            }
            if !pins.insert(pin) {
                return Err(invalid("duplicate dependency worker SPKI pin"));
            }
        }
        Ok(Some(Self { endpoints, pool }))
    }

    fn value(&self) -> Value {
        let mut configuration = if self.pool {
            json!({"workers":self.endpoints.iter().map(WorkerEndpoint::value).collect::<Vec<_>>()})
        } else {
            self.endpoints[0].value()
        };
        configuration["remote_protocol"] = json!(1);
        configuration["dependency_context"] = json!(DEPENDENCY_CONTEXT_VERSION);
        configuration
    }
}

/// A reservation prevents duplicate dispatch while the worker is connecting,
/// before the authoritative coordinator can admit the authenticated attempt.
/// Its lifetime covers the offer, execution and publication. It grants no
/// execution authority and never replaces CoordLive's action ownership.
#[derive(Debug)]
struct PendingActionClaim {
    actions: Arc<Mutex<HashSet<TypedDigest>>>,
    key: TypedDigest,
}

impl Drop for PendingActionClaim {
    fn drop(&mut self) {
        // A poisoned decision lock must not strand claims owned by already
        // admitted requests. Further reservations still report its failure.
        let mut actions = self
            .actions
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        actions.remove(&self.key);
    }
}

#[derive(Debug)]
struct DependencyWorkerPool {
    workers: Vec<Arc<RemoteDependencyTransport>>,
    next: AtomicUsize,
    pending: Arc<Mutex<HashSet<TypedDigest>>>,
}

impl DependencyWorkerPool {
    fn new(workers: Vec<Arc<RemoteDependencyTransport>>) -> Self {
        Self {
            workers,
            next: AtomicUsize::new(0),
            pending: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    fn try_reserve(
        &self,
        key: &TypedDigest,
    ) -> io::Result<(RemoteDependencyReservation, PendingActionClaim)> {
        let mut actions = self
            .pending
            .lock()
            .map_err(|_| io::Error::other("remote pending-action lock poisoned"))?;
        if !actions.insert(key.clone()) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "another subscriber is preparing this remote action",
            ));
        }
        let claim = PendingActionClaim {
            actions: Arc::clone(&self.pending),
            key: key.clone(),
        };
        drop(actions);
        if self.workers.is_empty() {
            return Err(invalid("remote dependency worker pool is empty"));
        }
        let start = self.next.fetch_add(1, Ordering::Relaxed) % self.workers.len();
        for offset in 0..self.workers.len() {
            let worker = &self.workers[(start + offset) % self.workers.len()];
            match worker.try_reserve() {
                Ok(reservation) => return Ok((reservation, claim)),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "all remote dependency workers are busy",
        ))
    }
}

/// An explicitly configured, bounded pool for the first live dependency class.
#[derive(Debug)]
pub struct RemoteDependencies {
    workers: DependencyWorkerPool,
    state: PathBuf,
    configuration: Value,
    toolchain: Mutex<Option<ToolchainMemo>>,
}

/// The private directory is retained for as long as any upload uses its image.
#[derive(Debug)]
struct RetainedToolchain {
    guard: ToolchainGuard,
    image: Arc<PreparedToolchain>,
    _directory: tempfile::TempDir,
}

/// The edge has checked the actual key and the same typed execution context
/// accepted by the worker. Unsupported path/loader shapes cannot fail late
/// after the transport crossed its execution frontier.
#[derive(Debug)]
pub struct RemoteInvocation {
    argv: Vec<String>,
    context: DependencyExecContext,
    validation: RemoteValidation,
}

/// The exact complete toolchain and measured runtime selected during keying.
/// Cache hits retain the same witness through materialization, too.
#[derive(Debug, Clone)]
pub(super) struct RemoteValidation {
    retained: Arc<RetainedToolchain>,
    runtime: TypedDigest,
    loader: LoaderDirectoryWitness,
}

impl RemoteValidation {
    pub(super) fn verify(&self, request: &LiveDependencyRequest) -> Result<(), String> {
        request.verify_toolchain()?;
        self.retained
            .image
            .verify_source_unchanged(request.toolchain.sysroot(), || false)
            .map_err(|error| format!("complete original toolchain changed: {error}"))?;
        self.loader
            .verify_absence(|| false)
            .map_err(|error| format!("original loader directories changed: {error}"))?;
        verify_runtime(request, &self.runtime)?;
        self.loader
            .verify_absence(|| false)
            .map_err(|error| format!("original loader directories changed: {error}"))?;
        self.retained
            .image
            .verify_source_unchanged(request.toolchain.sysroot(), || false)
            .map_err(|error| format!("complete original toolchain changed: {error}"))?;
        request.verify_toolchain()?;
        // Both newly produced remote results and remote cache hits call this
        // after synchronous materialization. Checking only runtime/toolchain
        // state would allow changed source, OUT_DIR or Cargo run records to
        // authorize a compiler skip under the earlier input generation.
        verify_package_generation(&request.package, &request.plan)
    }
}

#[derive(Debug)]
enum ToolchainMemo {
    Warming(ToolchainCapture),
    Ready(Arc<RetainedToolchain>),
}

/// One owned background warmup, never one copy per compiler invocation.
/// Drop cancels the bounded filesystem walker and joins its owner.
#[derive(Debug)]
struct ToolchainCapture {
    cancellation: OperationCancellation,
    handle: Option<std::thread::JoinHandle<Result<Arc<RetainedToolchain>, String>>>,
}

impl Drop for ToolchainCapture {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl RemoteDependencies {
    /// No variables selects the ordinary local lane. Partial or invalid explicit
    /// configuration refuses daemon startup instead of silently disabling it.
    pub fn from_environment(state: &Path) -> io::Result<Option<Arc<Self>>> {
        let optional = |name: &str| -> io::Result<Option<String>> {
            match std::env::var(name) {
                Ok(value) => Ok(Some(value)),
                Err(std::env::VarError::NotPresent) => Ok(None),
                Err(std::env::VarError::NotUnicode(_)) => Err(invalid(format!("non-UTF-8 {name}"))),
            }
        };
        let legacy = CONFIG_KEYS.map(optional);
        let [listen, worker, pin] = legacy;
        let (listen, worker, pin) = (listen?, worker?, pin?);
        let pool = optional(POOL_CONFIG_KEY)?;
        let Some(configured) = WorkerConfiguration::parse(
            pool.as_deref(),
            [listen.as_deref(), worker.as_deref(), pin.as_deref()],
        )?
        else {
            return Ok(None);
        };
        let state = state.join("dependency-workers");
        std::fs::create_dir_all(&state)?;
        let state = std::fs::canonicalize(state)?;
        // PinnedWorkerAdmission namespaces this same root by the exact worker
        // name. Keep that layout when moving a singleton into a pool: its key,
        // boot-generation fences and request high-water history must survive.
        let workers = configured
            .endpoints
            .iter()
            .map(|endpoint| {
                RemoteDependencyTransport::from_environment(
                    endpoint.listen,
                    &endpoint.worker_id,
                    &endpoint.worker_spki_sha256,
                    &state,
                )
                .map(Arc::new)
            })
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Some(Arc::new(Self {
            workers: DependencyWorkerPool::new(workers),
            state,
            configuration: configured.value(),
            toolchain: Mutex::new(None),
        })))
    }

    /// The configured pool size, used to bound the edge's remote execution lane.
    #[must_use]
    pub fn worker_count(&self) -> usize {
        self.workers.workers.len()
    }

    /// The connected daemon's pinned workers, for launcher compatibility checks.
    #[must_use]
    pub fn configuration(&self) -> &Value {
        &self.configuration
    }

    /// Measure the edge host and bind the separate remote isolation contract.
    /// A refusal leaves the caller's original local key untouched.
    /// `None` means the owned complete-toolchain capture is still preparing;
    /// a waiting caller can retry without acquiring execution authority.
    #[allow(clippy::too_many_arguments)]
    pub fn key(
        &self,
        plan: &DependencyActionPlan,
        toolchain: &ToolchainFacts,
        guard: &ToolchainGuard,
        directories: &[DependencyDirectoryFact],
        inputs: &ActionInputManifest,
        build_script_output: Option<&[u8]>,
        argv: &[String],
    ) -> Result<Option<(LiveDependencyKey, RemoteInvocation)>, String> {
        if argv.first().map(String::as_str) != Some(plan.compiler.as_str()) {
            return Err("remote argv does not name the observed compiler".into());
        }
        guard.verify_unchanged(Path::new(&plan.compiler))?;
        let root = guard.sysroot();
        let visible_root = root.to_str().ok_or("non-UTF-8 original toolchain root")?;
        remote_dependency_shape(plan, directories, visible_root)
            .map_err(|error| error.to_string())?;
        let empty_loader = remote_empty_loader_directories(plan, visible_root)
            .map_err(|error| error.to_string())?;
        let loader_witness = observe_loader_directories(&empty_loader, || false)
            .map_err(|error| format!("original loader directories: {error}"))?;
        let Some(retained) = self.retained_toolchain(guard, Path::new(&plan.compiler))? else {
            return Ok(None);
        };
        // Probe the compiler's complete original lookup order. The worker may
        // omit independently witnessed private aliases from its physical probe,
        // but the source observation must preserve loader selection and errors.
        let loader = original_loader_search_paths(plan);
        let runtime = observe_runtime_cohort(
            Path::new(&plan.compiler),
            root,
            &loader,
            Path::new(&plan.out_dir),
        )
        .map_err(|error| format!("edge runtime cohort: {error}"))?;
        let key = remote_dependency_key(
            plan,
            toolchain,
            directories,
            inputs,
            build_script_output,
            visible_root,
            &retained.image.identity().sha256,
            &runtime,
        )
        .map_err(|error| error.to_string())?;
        let runtime_bytes: [u8; 32] = runtime
            .bytes
            .as_slice()
            .try_into()
            .map_err(|_| "runtime cohort digest is not SHA-256")?;
        let artifact_roots = directories
            .iter()
            .enumerate()
            .filter(|(_, directory)| !directory.artifacts.is_empty())
            .map(|(index, directory)| DependencyArtifactRoot {
                path: directory.path.clone(),
                prefix: format!("dependencies/{index:04}"),
            })
            .collect();
        let context = DependencyExecContext::new_with_generated_artifacts(
            plan.source_root.clone(),
            plan.cwd.clone(),
            visible_root.to_owned(),
            plan.compiler.clone(),
            plan.out_dir.clone(),
            plan.dependency_dirs.clone(),
            loader_witness.directories().to_vec(),
            artifact_roots,
            plan.generated_root.clone(),
            plan.execution_env.clone(),
            runtime_bytes,
        )
        .map_err(|error| error.to_string())?;
        loader_witness.verify_absence(|| false).map_err(|error| {
            format!("original loader directories changed during keying: {error}")
        })?;
        guard.verify_unchanged(Path::new(&plan.compiler))?;
        retained
            .image
            .verify_source_unchanged(root, || false)
            .map_err(|error| format!("original toolchain changed during keying: {error}"))?;
        Ok(Some((
            key,
            RemoteInvocation {
                argv: argv.to_vec(),
                context,
                validation: RemoteValidation {
                    retained,
                    runtime,
                    loader: loader_witness,
                },
            },
        )))
    }

    fn retained_toolchain(
        &self,
        guard: &ToolchainGuard,
        compiler: &Path,
    ) -> Result<Option<Arc<RetainedToolchain>>, String> {
        guard.verify_unchanged(compiler)?;
        let mut memo = self
            .toolchain
            .lock()
            .map_err(|_| "toolchain retention lock poisoned")?;
        if let Some(ToolchainMemo::Warming(warmup)) = memo.as_mut() {
            if !warmup
                .handle
                .as_ref()
                .is_some_and(std::thread::JoinHandle::is_finished)
            {
                return Ok(None);
            }
            let handle = warmup
                .handle
                .take()
                .ok_or("toolchain warmup owner missing")?;
            let outcome = handle
                .join()
                .map_err(|_| "toolchain warmup panicked".to_owned());
            *memo = None;
            let retained = outcome??;
            *memo = Some(ToolchainMemo::Ready(retained));
        }
        if let Some(ToolchainMemo::Ready(retained)) = memo.as_ref()
            && retained.guard.verify_unchanged(compiler).is_ok()
            && retained
                .image
                .verify_source_unchanged(guard.sysroot(), || false)
                .is_ok()
        {
            return Ok(Some(Arc::clone(retained)));
        }
        // A warmup never blocks the hot decision lane on a multi-GB copy.
        // A waiting wrapper retries this same invocation after preparation;
        // nonwaiting callers retain the ordinary local lane. Neither acquires
        // a remote action key or execution authority from the pending copy.
        let state = self.state.clone();
        let guard = guard.clone();
        let compiler = compiler.to_path_buf();
        let cancellation = OperationCancellation::new();
        let stopped = cancellation.clone();
        let handle = std::thread::Builder::new()
            .name("rabs-remote-toolchain".into())
            .spawn(move || {
                guard.verify_unchanged(&compiler)?;
                let directory = tempfile::Builder::new()
                    .prefix("compiler-")
                    .tempdir_in(state)
                    .map_err(|error| error.to_string())?;
                let image = capture_toolchain(
                    guard.sysroot(),
                    &directory.path().join("tree"),
                    None,
                    &ToolchainLimits::default(),
                    || stopped.is_cancelled(),
                )
                .map_err(|error| format!("capture complete original toolchain: {error}"))?;
                guard.verify_unchanged(&compiler)?;
                image
                    .verify_source_unchanged(guard.sysroot(), || stopped.is_cancelled())
                    .map_err(|error| error.to_string())?;
                Ok(Arc::new(RetainedToolchain {
                    guard,
                    image: Arc::new(image),
                    _directory: directory,
                }))
            })
            .map_err(|error| error.to_string())?;
        *memo = Some(ToolchainMemo::Warming(ToolchainCapture {
            cancellation,
            handle: Some(handle),
        }));
        Ok(None)
    }
}

impl LiveDependencyLane {
    /// A normal sampled cache hit may serve immediately. A miss reserves a
    /// worker, but creates no fake local attempt under a remote isolation key.
    #[must_use]
    pub fn decide_remote(
        &self,
        request: LiveDependencyRequest,
        remote: Arc<RemoteDependencies>,
        invocation: RemoteInvocation,
    ) -> LiveDecision {
        if let Err(reason) = request.verify_toolchain() {
            return LiveDecision::PassThrough(reason);
        }
        let request = match self.preview(request) {
            Ok(Ok(mut pending)) => {
                pending.remote_validation = Some(invocation.validation);
                return LiveDecision::Hit(pending);
            }
            Ok(Err(request)) => request,
            Err(reason) => return LiveDecision::PassThrough(format!("serve-fault: {reason}")),
        };
        match self.coord.submitted_actor(&request.key.action_key) {
            Ok(Some(_)) => return LiveDecision::InFlight,
            Ok(None) => {}
            Err(error) => return LiveDecision::PassThrough(format!("remote dispatch: {error:?}")),
        }
        match remote.workers.try_reserve(&request.key.action_key) {
            Ok((reservation, action_claim)) => LiveDecision::Remote(PendingRemote {
                lane: self.clone(),
                request,
                remote,
                invocation,
                reservation,
                action_claim,
            }),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => LiveDecision::InFlight,
            Err(error) => LiveDecision::PassThrough(format!("remote worker: {error}")),
        }
    }
}

/// Private worker capacity and action ownership retained through publication.
#[derive(Debug)]
pub struct PendingRemote {
    lane: LiveDependencyLane,
    request: LiveDependencyRequest,
    remote: Arc<RemoteDependencies>,
    invocation: RemoteInvocation,
    reservation: RemoteDependencyReservation,
    action_claim: PendingActionClaim,
}

impl PendingRemote {
    #[must_use]
    pub fn action_key(&self) -> &TypedDigest {
        &self.request.key.action_key
    }

    /// Run only on the edge's bounded dedicated execution lane. The transport
    /// must already have the wrapper's private-execution acknowledgment.
    pub fn execute(self, cancellation: OperationCancellation) -> RemoteResult {
        match self.execute_inner(cancellation) {
            Ok(pending) => RemoteResult::Ready(pending),
            Err((reason, execution_finished)) => RemoteResult::Failed {
                reason,
                execution_finished,
            },
        }
    }

    #[allow(clippy::too_many_lines)]
    fn execute_inner(
        self,
        cancellation: OperationCancellation,
    ) -> Result<PendingRemoteInstall, (String, bool)> {
        let Self {
            lane,
            request,
            remote,
            invocation,
            mut reservation,
            action_claim: _action_claim,
        } = self;
        let settled = |reason: String| (reason, true);
        if cancellation.is_cancelled() {
            return Err(settled(
                "remote execution cancelled before preparation".into(),
            ));
        }
        verify_request(&request).map_err(settled)?;
        invocation.validation.verify(&request).map_err(settled)?;
        let retained = Arc::clone(&invocation.validation.retained);
        let mut directory = recovery::ResultDirectory::new(&remote.state)
            .map_err(|error| settled(error.to_string()))?;
        let destination = directory.path().join("delivery");
        let paths = request
            .package
            .files
            .iter()
            .map(|(path, _, _)| path.clone())
            .collect::<Vec<_>>();
        // Capture the complete keyed candidate inventory only after private
        // execution was accepted, on this bounded blocking lane. The observer
        // checks every byte digest and both inventory fences; the upload then
        // owns these bytes without reopening the caller's mutable target tree.
        let dependency_artifacts = request.dependencies.retained_artifacts().map_err(settled)?;
        let mut upload = SourceUpload::from_snapshot(
            Arc::clone(&request.package.snapshot),
            PACKAGE_ROOT,
            &paths,
        )
        .map_err(|error| settled(error.to_string()))?;
        if request.plan.generated_root.is_some() {
            let generated_paths = request
                .package
                .generated_files
                .iter()
                .map(|(path, _, _)| path.clone())
                .collect::<Vec<_>>();
            upload = upload
                .with_generated_snapshot(
                    Arc::clone(&request.package.snapshot),
                    GENERATED_ROOT,
                    &generated_paths,
                )
                .map_err(|error| settled(format!("prepare generated inputs: {error}")))?;
        }
        let upload = upload
            .with_dependency_artifacts(dependency_artifacts)
            .map_err(|error| settled(error.to_string()))?;
        verify_request(&request).map_err(settled)?;
        // The worker persists a request-id high-water mark. The admission owner
        // durably allocates before sending; random ids fail on ordinary reuse.
        let request_id = reservation
            .allocate_request_id()
            .map_err(|error| settled(format!("allocate worker request: {error}")))?;
        let wire = json!({
            "kind":"canonical-exec", "request_id":request_id,
            "program":request.plan.compiler, "args":invocation.argv[1..],
            // One standalone metadata compiler consumes one action grant. Its
            // original keyed NUM_JOBS remains exact in dependency_context.
            "jobserver_grant":1,
            "source_manifest":upload.wire_manifest(),
            "toolchain_transfer":TOOLCHAIN_TRANSFER_VERSION,
            "toolchain_identity":toolchain_identity_value(retained.image.identity()),
            "artifacts":{"unit":format!("dependency-{request_id:016x}"),
                "files":request.plan.output_names()},
            "dependency_context":context_value(&invocation.context),
        });
        let upload = upload
            .with_shared_toolchain(Arc::clone(&retained.image), &wire)
            .map_err(|error| settled(format!("prepare worker upload: {error}")))?;
        let owner: Arc<Mutex<Option<AdmittedRemote>>> = Arc::new(Mutex::new(None));
        let admitted_owner = Arc::clone(&owner);
        // Persist exact recovery intent BEFORE execution can leave this process.
        // Recovery must target this reserved worker, even when the pool changes
        // order or membership. The whole pool is not a worker identity.
        directory
            .record_request(
                &wire,
                &rabs_cas::metadata_store::digest_key(&request.key.action_key),
                &reservation.worker_configuration(),
            )
            .map_err(|error| settled(format!("persist remote recovery request: {error}")))?;
        let selected_worker = reservation.worker().to_owned();
        // Borrow the reservation: transport completion alone does not release
        // worker capacity. Its later drop follows the admitted session's drop
        // after capture/publication, including every error return below.
        let delivery = reservation.execute(
            &wire,
            &upload,
            &destination,
            cancellation.clone(),
            move |worker| {
                let (admission, started) = lane
                    .coord
                    .admit_worker_session(worker)
                    .map_err(io::Error::other)?;
                let started = started.ok_or_else(|| {
                    io::Error::other(format!("live worker session not admitted: {admission:?}"))
                })?;
                // Install the release owner before action admission: a losing
                // dispatch claim must not leave this worker permanently busy.
                let session = LiveWorkerSession {
                    coord: Arc::clone(&lane.coord),
                    offer: worker.clone(),
                    started,
                };
                let attempt = lane
                    .begin_execution_on(request, worker)
                    .map_err(io::Error::other)?
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "another subscriber owns the remote action",
                        )
                    })?;
                let mut slot = admitted_owner
                    .lock()
                    .map_err(|_| io::Error::other("remote attempt owner poisoned"))?;
                let key = rabs_cas::metadata_store::digest_key(&attempt.request.key.action_key);
                *slot = Some(AdmittedRemote {
                    attempt: Some(attempt),
                    _session: session,
                    execution_finished: false,
                });
                drop(slot);
                crate::edge::server::log_line(
                    "rabsd-remote-dependency-admitted",
                    &[
                        ("key", &key),
                        ("worker_id", &selected_worker),
                        ("worker_spki_sha256", &worker.worker_peer_id.0),
                    ],
                );
                Ok(())
            },
        );
        // Keep the compiler backing and source snapshot owners until transfer,
        // execution, drain and verified delivery have all returned.
        drop(upload);
        drop(retained);
        let mut owned = owner
            .lock()
            .map_err(|_| ("remote attempt owner poisoned".to_owned(), false))?
            .take();
        let delivery = match delivery {
            Ok(delivery) => delivery,
            Err(failure) => {
                if let Some(owned) = owned.as_mut() {
                    owned.execution_finished = !failure.execution_may_have_run;
                }
                let detail = if failure.execution_may_have_run {
                    format!(
                        "{}; retained remote recovery directory: {}",
                        failure.detail,
                        directory.path().display(),
                    )
                } else {
                    directory.execution_finished();
                    failure.detail
                };
                return Err((detail, !failure.execution_may_have_run));
            }
        };
        let owned = owned
            .as_mut()
            .ok_or_else(|| ("delivery has no live admitted attempt".to_owned(), false))?;
        let attempt = owned
            .attempt
            .as_ref()
            .ok_or_else(|| ("delivery lost its admitted attempt".to_owned(), false))?;
        verify_receipt(&delivery, &wire, attempt.authority.as_ref()).map_err(|reason| {
            (
                format!(
                    "{reason}; retained remote recovery directory: {}",
                    directory.path().display(),
                ),
                false,
            )
        })?;
        owned.execution_finished = true;
        // Complete execution is distinct from remote ACK confirmation. Keep a
        // verified delivery for acknowledgment-only reconciliation when needed.
        directory.delivery_finished(delivery.acknowledgments_confirmed);
        if cancellation.is_cancelled() {
            return Err(settled("caller left after private remote execution".into()));
        }
        let attempt = owned
            .attempt
            .as_mut()
            .ok_or_else(|| ("delivery lost its admitted attempt".to_owned(), false))?;
        let (_, stdout) = read_stable(
            &delivery.directory.join("diagnostics/stdout"),
            MAX_TRANSCRIPT_BYTES as u64,
        )
        .map_err(|error| settled(format!("remote stdout: {error}")))?;
        let (_, stderr) = read_stable(
            &delivery.directory.join("diagnostics/stderr"),
            MAX_TRANSCRIPT_BYTES as u64,
        )
        .map_err(|error| settled(format!("remote stderr: {error}")))?;
        let exit_code = delivery.receipt["exit_code"]
            .as_i64()
            .and_then(|code| i32::try_from(code).ok());
        let report = CompletionReport {
            exit_code,
            signal: None,
            stdout,
            stderr,
        };
        // A closed view may reject include_str! of an external host file which
        // stock rustc can read. A failed private compile therefore falls back
        // only after verified drain; it never replaces the stock diagnostics.
        if report.exit_code != Some(0) || !delivery.receipt["stop_reason"].is_null() {
            return Err(settled(
                "private remote compiler did not finish successfully".into(),
            ));
        }
        invocation
            .validation
            .verify(&attempt.request)
            .map_err(settled)?;
        let captured = attempt
            .capture_result(
                &report,
                &delivery.directory.join("artifacts"),
                Some(&delivery.receipt),
            )
            .map_err(settled)?;
        let manifest = captured.offer.manifest.clone();
        let manifest_key = captured.manifest_key.clone();
        let canonical_transcript = canonicalize_placements(&report.stderr, &attempt.request.plan)
            .map_err(|e| settled(e.to_owned()))?;
        // Capture streams can take time. Recheck the complete original dataset
        // and measured runtime after them, before crossing publication.
        invocation
            .validation
            .verify(&attempt.request)
            .map_err(settled)?;
        let (outcome, _) = attempt.publish_captured(captured).map_err(settled)?;
        if !matches!(
            outcome,
            CompletionOutcome::Committed | CompletionOutcome::Verified
        ) {
            return Err(settled(format!("remote publication: {outcome:?}")));
        }
        attempt.settle();
        let attempt = owned
            .attempt
            .take()
            .ok_or_else(|| ("published attempt owner missing".to_owned(), false))?;
        // AdmittedRemote's session owner drops on return, after publication and
        // before waiting for permission to write any caller destination.
        Ok(PendingRemoteInstall {
            attempt,
            manifest,
            manifest_key,
            canonical_transcript,
            validation: invocation.validation,
        })
    }
}

fn context_value(context: &DependencyExecContext) -> Value {
    json!({
        "version":DEPENDENCY_CONTEXT_VERSION,
        "source_root":context.source_root(), "cwd":context.cwd(),
        "generated_root":context.generated_root(),
        "toolchain_root":context.toolchain_root(), "compiler":context.compiler(),
        "out_dir":context.out_dir(), "dependency_dirs":context.dependency_dirs(),
        "loader_dirs":context.loader_dirs(),
        "artifact_roots":context.artifact_roots().iter().map(|root| json!({
            "path":root.path, "prefix":root.prefix,
        })).collect::<Vec<_>>(),
        "env":context.env(), "runtime_cohort_sha256":hex(context.runtime_cohort_sha256()),
    })
}

/// Release the exact session even if admission, upload, capture or publication
/// fails. A stale owner cannot end a later incarnation's session.
#[derive(Debug)]
struct LiveWorkerSession {
    coord: Arc<CoordLive>,
    offer: WorkerSessionOffer,
    started: u64,
}

impl Drop for LiveWorkerSession {
    fn drop(&mut self) {
        let _ = self.coord.release_worker_session(
            &self.offer.worker_peer_id,
            self.offer.incarnation,
            self.started,
        );
    }
}

/// Unwind/cancellation defaults to uncertainty. Only the verified receiver can
/// establish that no execution started or that its complete process tree ended.
#[derive(Debug)]
struct AdmittedRemote {
    attempt: Option<ExecutionAttempt>,
    _session: LiveWorkerSession,
    execution_finished: bool,
}

impl Drop for AdmittedRemote {
    fn drop(&mut self) {
        if !self.execution_finished
            && let Some(attempt) = self.attempt.as_mut()
        {
            attempt.abandon();
        }
    }
}

fn verify_request(request: &LiveDependencyRequest) -> Result<(), String> {
    request.verify_toolchain()?;
    verify_package_generation(&request.package, &request.plan)?;
    request.dependencies.verify_unchanged()
}

fn verify_package_generation(
    package: &super::PackageFacts,
    plan: &DependencyActionPlan,
) -> Result<(), String> {
    package
        .verify_unchanged(Path::new(&plan.source_root))
        .and_then(|()| package.verify_generated_disjoint(plan))
        .map_err(|reason| format!("captured dependency inputs changed: {reason}"))
}

/// The plan has already rejected ambiguous loader entries. Keep their exact
/// spelling and order, including non-toolchain roots whose absence is guarded.
fn original_loader_search_paths(plan: &DependencyActionPlan) -> Vec<PathBuf> {
    plan.execution_env
        .iter()
        .find(|(name, _)| name == "LD_LIBRARY_PATH")
        .map(|(_, value)| value.split(':').map(PathBuf::from).collect())
        .unwrap_or_default()
}

fn verify_runtime(request: &LiveDependencyRequest, expected: &TypedDigest) -> Result<(), String> {
    // Runtime observation is separate from the dependency inventory. The
    // installer's final inventory check excludes only this action's exact
    // declared outputs and still detects changed inputs after those writes.
    request.verify_toolchain()?;
    let root = request.toolchain.sysroot();
    let loader = original_loader_search_paths(&request.plan);
    let actual = observe_runtime_cohort(
        Path::new(&request.plan.compiler),
        root,
        &loader,
        Path::new(&request.plan.out_dir),
    )
    .map_err(|error| format!("edge runtime revalidation: {error}"))?;
    if &actual != expected {
        return Err("edge runtime changed during remote dependency execution".into());
    }
    request.verify_toolchain()
}

fn verify_receipt(
    delivery: &Delivery,
    wire: &Value,
    authority: Option<&AttemptAuthority>,
) -> Result<(), String> {
    let authority = authority.ok_or("remote delivery has no execution authority")?;
    let receipt = &delivery.receipt;
    let request_digest = hex(&Sha256::digest(
        serde_json::to_vec(wire).map_err(|error| error.to_string())?,
    ));
    let incarnation = format!("{:032x}", authority.worker_incarnation_id.0);
    if receipt["transport_authenticated"] != true
        || receipt["resumed"] == true
        || receipt["request_id"] != wire["request_id"]
        || receipt["request_sha256"].as_str() != Some(request_digest.as_str())
        || receipt["worker_spki_sha256"].as_str() != Some(authority.worker_peer_id.0.as_str())
        || receipt["boot_generation"].as_u64() != Some(authority.worker_boot_generation.0)
        || receipt["incarnation"].as_str() != Some(incarnation.as_str())
    {
        return Err("verified delivery does not bind the live authenticated attempt".into());
    }
    Ok(())
}

/// No caller output was touched by either alternative.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum RemoteResult {
    /// Complete private result awaiting a second, manifest-specific consent.
    Ready(PendingRemoteInstall),
    /// Local fallback is permitted only when execution_finished is true.
    Failed {
        reason: String,
        execution_finished: bool,
    },
}

/// A successful current producer, not an arbitrary cache-read capability.
/// Its constructor requires actual execution, complete verified bytes, closure
/// checks and H011 publication. Later requests still pass normal replay sampling.
#[derive(Debug)]
pub struct PendingRemoteInstall {
    attempt: ExecutionAttempt,
    manifest: CanonicalActionResultManifest,
    manifest_key: String,
    canonical_transcript: Vec<u8>,
    validation: RemoteValidation,
}

impl PendingRemoteInstall {
    #[must_use]
    pub fn action_key(&self) -> &TypedDigest {
        &self.attempt.key
    }

    #[must_use]
    pub fn capture(&self) -> &str {
        &self.manifest_key
    }

    /// Called only after the wrapper acknowledges this exact captured result.
    /// Full publication/quarantine/authority/materialization gates remain active;
    /// cache-replay sampling does not discard this subscriber's own new execution.
    #[must_use]
    pub fn install(self) -> InstallResult {
        let request = &self.attempt.request;
        if let Err(reason) = verify_request(request).and_then(|()| self.validation.verify(request))
        {
            return InstallResult::Declined(reason);
        }
        let plan = &request.plan;
        match self.attempt.coord.serve_produced_result(
            &self.attempt.key,
            &self.manifest_key,
            Path::new(&plan.out_dir),
            &expected_outputs(plan),
            now_micros(),
        ) {
            Ok(ServeOutcome::Served { files }) => {
                if files.len() != self.manifest.logical_outputs.len() {
                    return InstallResult::Fault(
                        "remote installed output set is incomplete".into(),
                    );
                }
                let mut installed = Vec::new();
                for path in files {
                    let Some(output) =
                        path.file_name()
                            .and_then(|name| name.to_str())
                            .and_then(|name| {
                                self.manifest.logical_outputs.iter().find(|output| {
                                    output.virtual_path.as_bytes() == name.as_bytes()
                                })
                            })
                    else {
                        return InstallResult::Fault(
                            "remote installed output is undeclared".into(),
                        );
                    };
                    if output.role != OutputRole::DepInfo {
                        match known_installed_output(&path, &output.object.0) {
                            Ok(output) => installed.push(output),
                            Err(reason) => return InstallResult::Fault(reason),
                        }
                    }
                }
                if let Err(reason) = self.validation.verify(request) {
                    return InstallResult::Fault(reason);
                }
                super::finish_installation(
                    &request.dependencies,
                    render_placements(&self.canonical_transcript, plan),
                    installed,
                )
            }
            Ok(other) => InstallResult::Declined(format!("remote install: {other:?}")),
            Err(error) => InstallResult::Fault(format!("remote install: {error}")),
        }
    }
}

#[cfg(test)]
mod worker_pool_tests {
    use super::*;
    use rabs_asupersync::worker_transport::TlsFiles;
    use rabs_key::typed_digest::compute;

    fn endpoint(index: u16) -> Value {
        json!({
            "listen":format!("127.0.0.1:{}", 9000 + index),
            "worker_id":format!("worker-{index}"),
            "worker_spki_sha256":format!("{index:064x}"),
        })
    }

    fn configured(entries: &[Value]) -> io::Result<WorkerConfiguration> {
        WorkerConfiguration::parse(Some(&json!(entries).to_string()), [None; 3])
            .map(|configuration| configuration.expect("explicit pool"))
    }

    fn pool(state: &Path, count: u16) -> DependencyWorkerPool {
        let configured = configured(&(1..=count).map(endpoint).collect::<Vec<_>>()).unwrap();
        DependencyWorkerPool::new(
            configured
                .endpoints
                .into_iter()
                .map(|endpoint| {
                    Arc::new(
                        RemoteDependencyTransport::new(
                            endpoint.listen,
                            endpoint.worker_id,
                            parse_worker_pin(&endpoint.worker_spki_sha256).unwrap(),
                            state.to_path_buf(),
                            TlsFiles {
                                ca: PathBuf::from("/private/ca.pem"),
                                certificate: PathBuf::from("/private/coord.pem"),
                                private_key: PathBuf::from("/private/coord.key"),
                            },
                        )
                        .unwrap(),
                    )
                })
                .collect(),
        )
    }

    fn key(index: u8) -> TypedDigest {
        compute("rabs.test.worker-pool.v1", &[index])
    }

    #[test]
    fn singleton_configuration_is_unchanged_and_pool_preserves_order() {
        assert!(
            WorkerConfiguration::parse(None, [None; 3])
                .unwrap()
                .is_none()
        );
        let pin = format!("{:064x}", 1);
        let singleton = WorkerConfiguration::parse(
            None,
            [Some("127.0.0.1:9001"), Some("worker-1"), Some(&pin)],
        )
        .unwrap()
        .unwrap();
        let expected = json!({
            "remote_protocol":1, "dependency_context":DEPENDENCY_CONTEXT_VERSION,
            "listen":"127.0.0.1:9001", "worker_id":"worker-1", "worker_spki_sha256":pin,
        });
        assert_eq!(singleton.value(), expected);

        let entries = [endpoint(2), endpoint(1)];
        let configuration = configured(&entries).unwrap();
        assert_eq!(
            configuration.value(),
            json!({
                "remote_protocol":1, "dependency_context":DEPENDENCY_CONTEXT_VERSION,
                "workers":entries,
            })
        );
        let mut ipv6 = endpoint(3);
        ipv6["listen"] = json!("[0:0:0:0:0:0:0:1]:9003");
        assert_eq!(
            configured(&[ipv6]).unwrap().value()["workers"][0]["listen"],
            "[::1]:9003"
        );
    }

    #[test]
    fn explicit_pool_refuses_incomplete_ambiguous_and_unbounded_configuration() {
        for count in [0, MAX_DEPENDENCY_WORKERS + 1] {
            let entries = (1..=count)
                .map(|index| endpoint(u16::try_from(index).unwrap()))
                .collect::<Vec<_>>();
            assert!(configured(&entries).is_err());
        }
        assert!(
            configured(
                &(1..=u16::try_from(MAX_DEPENDENCY_WORKERS).unwrap())
                    .map(endpoint)
                    .collect::<Vec<_>>()
            )
            .is_ok()
        );
        for text in ["", "null", "{}", "[null]", "[{}]", "[true]"] {
            assert!(
                WorkerConfiguration::parse(Some(text), [None; 3]).is_err(),
                "{text}"
            );
        }
        assert!(
            WorkerConfiguration::parse(Some(&" ".repeat(MAX_WORKER_CONFIG_BYTES + 1)), [None; 3])
                .is_err()
        );
        let valid = json!([endpoint(1)]).to_string();
        for index in 0..3 {
            let mut legacy = [None; 3];
            legacy[index] = Some("");
            assert!(WorkerConfiguration::parse(Some(&valid), legacy).is_err());
            assert!(WorkerConfiguration::parse(None, legacy).is_err());
        }
        for (field, value) in [
            ("extra", json!(true)),
            ("listen", json!("127.0.0.1:0")),
            ("listen", json!("worker.example:9001")),
            ("listen", json!(9001)),
            ("worker_id", json!("")),
            ("worker_id", json!("worker\nname")),
            ("worker_id", json!("w".repeat(1025))),
            ("worker_id", json!("é".repeat(513))),
            ("worker_spki_sha256", json!("00".repeat(32))),
            ("worker_spki_sha256", json!("AB".repeat(32))),
            ("worker_spki_sha256", json!("1")),
        ] {
            let mut entry = endpoint(1);
            entry[field] = value;
            assert!(configured(&[entry]).is_err(), "{field}");
        }
        let repeated = format!(
            "[{{\"listen\":\"127.0.0.1:9001\",\"listen\":\"127.0.0.1:9002\",\"worker_id\":\"worker\",\"worker_spki_sha256\":\"{}\"}}]",
            "01".repeat(32)
        );
        assert!(WorkerConfiguration::parse(Some(&repeated), [None; 3]).is_err());
    }

    #[test]
    fn pool_rejects_duplicate_endpoints_and_worker_key_aliases() {
        for field in ["listen", "worker_id", "worker_spki_sha256"] {
            let first = endpoint(1);
            let mut second = endpoint(2);
            second[field] = first[field].clone();
            assert!(configured(&[first, second]).is_err(), "{field}");
        }
        let mut first = endpoint(1);
        let mut second = endpoint(2);
        first["listen"] = json!("[0:0:0:0:0:0:0:1]:9001");
        second["listen"] = json!("[::1]:9001");
        assert!(configured(&[first, second]).is_err());
    }

    #[test]
    fn independent_actions_fill_the_pool_and_busy_workers_are_skipped() {
        let pool = pool(Path::new("/private/worker-pool"), 3);
        let first = pool.try_reserve(&key(1)).unwrap();
        let second = pool.try_reserve(&key(2)).unwrap();
        let third = pool.try_reserve(&key(3)).unwrap();
        assert_eq!(
            [first.0.worker(), second.0.worker(), third.0.worker()],
            ["worker-1", "worker-2", "worker-3"]
        );
        assert_eq!(
            pool.try_reserve(&key(4)).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(
            !pool.pending.lock().unwrap().contains(&key(4)),
            "a full pool must release the unoffered action claim"
        );
        drop(second);
        let fourth = pool.try_reserve(&key(4)).unwrap();
        assert_eq!(fourth.0.worker(), "worker-2");
        drop((first, third, fourth));
        assert!(pool.pending.lock().unwrap().is_empty());
        // Every dropped pre-execution offer restores real worker capacity.
        let all = (5..=7)
            .map(|index| pool.try_reserve(&key(index)).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(all.len(), 3);
    }

    #[cfg(unix)]
    #[test]
    fn recovery_records_the_selected_worker_without_ambiguous_pool_membership() {
        let state = crate::test_util::private_tempdir();
        let pool = pool(state.path(), 2);
        let first = pool.try_reserve(&key(1)).unwrap();
        let selected = pool.try_reserve(&key(2)).unwrap();
        let mut expected = endpoint(2);
        expected["remote_protocol"] = json!(1);
        expected["dependency_context"] = json!(DEPENDENCY_CONTEXT_VERSION);
        assert_eq!(selected.0.worker_configuration(), expected);

        let request = json!({"kind":"canonical-exec", "request_id":17,
            "program":"/toolchain/bin/rustc", "args":["src/lib.rs"]});
        let action_key = rabs_cas::metadata_store::digest_key(&key(2));
        let mut directory = recovery::ResultDirectory::new(state.path()).unwrap();
        directory
            .record_request(&request, &action_key, &selected.0.worker_configuration())
            .unwrap();
        let retained = directory.path().to_path_buf();
        drop(directory);
        drop((first, selected, pool));

        let record: Value =
            serde_json::from_slice(&std::fs::read(retained.join("recovery.json")).unwrap())
                .unwrap();
        assert_eq!(record["remote_configuration"], expected);
        assert!(record["remote_configuration"].get("workers").is_none());
        assert_eq!(record["action_key"], action_key);
        assert_eq!(record["publication_authorized"], false);
        assert_eq!(record["reexecute"], false);
        assert_eq!(
            std::fs::read(retained.join("request.json")).unwrap(),
            serde_json::to_vec(&request).unwrap()
        );
    }

    #[test]
    fn same_action_cannot_dispatch_twice_even_before_worker_authentication() {
        let pool = pool(Path::new("/private/worker-pool"), 2);
        let (first_worker, first_claim) = pool.try_reserve(&key(1)).unwrap();
        assert_eq!(
            pool.try_reserve(&key(1)).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(
            pool.try_reserve(&key(2)).is_ok(),
            "duplicate did not occupy the other worker"
        );
        drop(first_worker);
        assert_eq!(
            pool.try_reserve(&key(1)).unwrap_err().kind(),
            io::ErrorKind::WouldBlock,
            "releasing worker capacity does not release the action's publication claim"
        );
        drop(first_claim);
        assert!(pool.try_reserve(&key(1)).is_ok());

        let first = pool.try_reserve(&key(7)).unwrap();
        let mut other_domain = key(7);
        other_domain.domain = "rabs.test.other-domain.v1";
        assert!(
            pool.try_reserve(&other_domain).is_ok(),
            "claims use the entire typed identity"
        );
        drop(first);
    }

    #[test]
    fn concurrent_duplicate_subscribers_consume_exactly_one_worker() {
        let pool = pool(Path::new("/private/worker-pool"), 3);
        let start = std::sync::Barrier::new(12);
        let reserved = std::sync::Barrier::new(12);
        let successes = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..12 {
                scope.spawn(|| {
                    start.wait();
                    let result = pool.try_reserve(&key(1));
                    if result.is_ok() {
                        successes.fetch_add(1, Ordering::Relaxed);
                    }
                    reserved.wait();
                    if let Err(error) = &result {
                        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                    }
                    drop(result);
                });
            }
        });
        assert_eq!(successes.load(Ordering::Relaxed), 1);
        assert!(pool.pending.lock().unwrap().is_empty());
        let capacity = (1..=3)
            .map(|index| pool.try_reserve(&key(index)).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(capacity.len(), 3);
    }

    #[cfg(unix)]
    #[test]
    fn workers_have_independent_durable_admission_but_preserve_singleton_history() {
        let state = crate::test_util::private_tempdir();
        let pool = pool(state.path(), 2);
        let (mut first, first_claim) = pool.try_reserve(&key(1)).unwrap();
        let (mut second, second_claim) = pool.try_reserve(&key(2)).unwrap();
        let first_id = first.allocate_request_id().unwrap();
        let second_id = second.allocate_request_id().unwrap();
        assert!(
            first_id > 0 && second_id > 0,
            "different stores can be held concurrently"
        );
        let singleton = Arc::clone(&pool.workers[0]);
        drop((first, first_claim, second, second_claim));
        let mut returned_singleton = singleton.try_reserve().unwrap();
        assert!(
            returned_singleton.allocate_request_id().unwrap() > first_id,
            "changing pool membership must not reset the worker request high-water mark"
        );
        drop(returned_singleton);
        let mut independent = pool.workers[1].try_reserve().unwrap();
        assert!(independent.allocate_request_id().unwrap() > second_id);
    }
}

#[cfg(all(test, unix))]
mod installed_input_generation_tests {
    use super::super::{object_id, output_role};
    use super::*;
    use crate::edge::live_facts::{LiveFacts, PackageFacts};
    use crate::janitor::store::{LiveCas, mount_and_reconcile};
    use rabs_cas::blob_store::{DurabilityPolicy, PutLimits, put_if_absent};
    use rabs_cas::materialization::{
        MaterializationMode, PlannedActionOutput, materialize_action_outputs_prepared,
    };
    use rabs_key::live_dependency::{LiveRustcRequest, plan_dependency_action};
    use rabs_key::output_declarations::OutputClass;
    use rabs_protocol::raw_bytes::RawBytes;

    // Real capture and CAS materialization exercise the completion boundary.
    // Fixture artifact bytes do not claim compiler, daemon or TLS execution.
    struct MaterializedInputs {
        _directory: tempfile::TempDir,
        plan: DependencyActionPlan,
        package: Arc<PackageFacts>,
        cas: LiveCas,
        outputs: Vec<PlannedActionOutput>,
    }

    impl MaterializedInputs {
        fn new(populated: bool) -> Self {
            let directory = crate::test_util::private_tempdir();
            let cargo = directory.path().join("cargo");
            let source = cargo.join("registry/src/install-index/consumer-1.0.0");
            let output = directory.path().join("target/debug/deps");
            let generated = directory
                .path()
                .join("target/debug/build/consumer-unit/out");
            for root in [&source, &output, &generated] {
                std::fs::create_dir_all(root).unwrap();
            }
            std::fs::write(source.join("lib.rs"), b"pub const VALUE: u32 = 17;").unwrap();
            if populated {
                std::fs::write(
                    generated.join("value.rs"),
                    b"pub const GENERATED: u32 = 17;",
                )
                .unwrap();
            }
            let unit = generated.parent().unwrap();
            std::fs::write(unit.join("output"), b"cargo::rustc-cfg=generated\n").unwrap();
            std::fs::write(unit.join("root-output"), generated.to_str().unwrap()).unwrap();
            let argv = vec![
                "/toolchain/bin/rustc".into(),
                source.join("lib.rs").to_str().unwrap().into(),
                "--crate-name=consumer".into(),
                "--crate-type=lib".into(),
                "--emit=dep-info,metadata".into(),
                "--cap-lints=allow".into(),
                "--error-format=json".into(),
                format!("--out-dir={}", output.display()),
            ];
            let env = vec![
                ("CARGO_HOME".into(), cargo.to_str().unwrap().into()),
                ("CARGO_MANIFEST_DIR".into(), source.to_str().unwrap().into()),
                ("CARGO_PKG_NAME".into(), "consumer".into()),
                ("OUT_DIR".into(), generated.to_str().unwrap().into()),
            ];
            let plan = plan_dependency_action(
                LiveRustcRequest {
                    argv: &argv,
                    cwd: source.to_str().unwrap(),
                    env: &env,
                },
                "x86_64-unknown-linux-gnu",
            )
            .unwrap();
            let package = LiveFacts::new()
                .package(&source, plan.source_kind, Some(&generated))
                .unwrap();
            let cas = mount_and_reconcile(&directory.path().join("cas")).unwrap();
            let outputs = plan
                .outputs
                .declarations
                .iter()
                .map(|declaration| {
                    let bytes = if declaration.class == OutputClass::DepInfo {
                        b"libconsumer.rmeta: lib.rs\n".as_slice()
                    } else {
                        b"verified replacement metadata".as_slice()
                    };
                    let object = object_id(bytes).unwrap();
                    let mut store = cas.store().lock().unwrap();
                    put_if_absent(
                        cas.layout(),
                        &mut *store,
                        &object,
                        &mut &bytes[..],
                        PutLimits::default(),
                        DurabilityPolicy::FULL,
                    )
                    .unwrap();
                    PlannedActionOutput {
                        role: output_role(declaration.class),
                        virtual_path: RawBytes::new(declaration.virtual_path.as_bytes().to_vec()),
                        object,
                        destination: output.join(&declaration.virtual_path),
                    }
                })
                .collect();
            Self {
                _directory: directory,
                plan,
                package,
                cas,
                outputs,
            }
        }

        fn materialize(&self, during_tail: impl Fn()) -> Result<(), String> {
            verify_package_generation(&self.package, &self.plan)?;
            let mut store = self.cas.store().lock().unwrap();
            let receipt = materialize_action_outputs_prepared(
                &mut *store,
                &self.outputs,
                MaterializationMode::PrivateCopy,
                std::time::SystemTime::now(),
                &|output, _| {
                    if output.role == OutputRole::DepInfo {
                        assert_eq!(
                            std::fs::read(Path::new(&self.plan.out_dir).join("libconsumer.rmeta"))
                                .unwrap(),
                            b"verified replacement metadata"
                        );
                        during_tail();
                    }
                    Ok(())
                },
            )
            .map_err(|error| format!("materialization failed: {error:?}"))?;
            assert_eq!(receipt.installed.len(), 2);
            drop(store);
            // The production RemoteValidation uses this same final check for
            // both produced-result and cache-hit installation completion.
            verify_package_generation(&self.package, &self.plan)
        }
    }

    #[test]
    fn declared_materialization_preserves_populated_and_empty_generated_inputs() {
        for populated in [false, true] {
            let fixture = MaterializedInputs::new(populated);
            assert!(fixture.materialize(|| {}).is_ok());
            assert_eq!(
                fixture.package.generated_files.len(),
                usize::from(populated)
            );
        }
    }

    #[test]
    fn changes_during_materialization_refuse_the_original_source_generation() {
        for mutation in [
            "source",
            "generated",
            "new-generated",
            "stdout",
            "root-output",
        ] {
            let fixture = MaterializedInputs::new(mutation != "new-generated");
            let generated = Path::new(fixture.plan.generated_root.as_ref().unwrap());
            let result = fixture.materialize(|| {
                let (path, bytes): (PathBuf, &[u8]) = match mutation {
                    "source" => (
                        Path::new(&fixture.plan.source_root).join("lib.rs"),
                        b"changed source",
                    ),
                    "generated" => (generated.join("value.rs"), b"changed generated input"),
                    "new-generated" => (
                        generated.join("introduced.rs"),
                        b"new formerly absent input",
                    ),
                    "stdout" => (
                        generated.parent().unwrap().join("output"),
                        b"cargo::rustc-cfg=changed\n",
                    ),
                    "root-output" => (
                        generated.parent().unwrap().join("root-output"),
                        b"/another/generated/root",
                    ),
                    _ => unreachable!(),
                };
                std::fs::write(path, bytes).unwrap();
            });
            assert!(
                result
                    .unwrap_err()
                    .starts_with("captured dependency inputs changed:"),
                "changed input generation was accepted: {mutation}"
            );
        }
    }

    #[test]
    fn post_materialization_output_alias_cannot_reuse_unchanged_generated_bytes() {
        use std::os::unix::fs::symlink;
        let fixture = MaterializedInputs::new(true);
        fixture.materialize(|| {}).unwrap();
        let generated = Path::new(fixture.plan.generated_root.as_ref().unwrap());
        std::fs::rename(
            &fixture.plan.out_dir,
            fixture._directory.path().join("retained-output"),
        )
        .unwrap();
        symlink(generated, &fixture.plan.out_dir).unwrap();
        fixture
            .package
            .verify_unchanged(Path::new(&fixture.plan.source_root))
            .unwrap();
        assert!(verify_package_generation(&fixture.package, &fixture.plan).is_err());
    }
}
