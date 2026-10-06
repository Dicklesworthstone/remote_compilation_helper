//! Live registry-dependency action keys (bd-14t4j / bd-k52xe): the first
//! production path from a real `RUSTC_WRAPPER` request to a real
//! [`ActionDescriptor`].
//!
//! Until this module, every descriptor a running daemon built from a live
//! wrapper request was the shadow projection (`rabsd/src/edge/shadow.rs`):
//! raw argv, env NAMES only, and seven constant placeholder components. A
//! cache answer keyed that way can never be allowed to skip a compiler.
//! This module composes the existing component builders (invocation
//! parsing, output derivation, extern resolution, dependency inputs,
//! toolchain/output-platform contracts, presented environment, input
//! manifest) into an exact key for ONE narrow class, and refuses —
//! typed, never silently — everything outside it.
//!
//! ## The class (`live-dependency-v1`)
//!
//! Plan §204's first served target, restricted to what can be keyed
//! exactly without a sandbox on the edge host:
//!
//! - rustc invoked by Cargo for an immutable crates.io-style registry
//!   package: `CARGO_MANIFEST_DIR` is exactly
//!   `<cargo-home>/registry/src/<index>/<package>`, rustc's working
//!   directory is that package root, `--cap-lints allow` is present and
//!   `CARGO_PRIMARY_PACKAGE` is absent;
//! - no build script output (`OUT_DIR` absent) — build-script crates need
//!   the N-epic run cache before they can be served;
//! - `lib`/`rlib` outputs only, through the bounded
//!   [`derive_dependency_output_declarations`] adapter (no `-Z`, no
//!   incremental, no explicit emit paths, Linux targets);
//! - every dependency artifact is a `.rmeta`/`.rlib` inside the
//!   invocation's own out-dir; proc-macro consumption is refused because
//!   untracked proc-macro reads cannot be proven closed (plan §33.10);
//! - no native link inputs (`-l`) and no search path other than
//!   `-L dependency=<out-dir>`;
//! - JSON diagnostics (`--error-format=json`), so the transcript is
//!   Cargo's machine protocol and can be canonicalized exactly.
//!
//! ## Exactness rules
//!
//! - **Source:** the COMPLETE registry package tree is the positive input
//!   set (callers enumerate and hash every regular file under the package
//!   root). A file added anywhere in the package changes the key, which is
//!   why the negative-dependency component is the declared
//!   "complete enumeration" fact rather than a probe list. Anything rustc
//!   reads outside the package root is caught after execution by
//!   [`dep_info_closure_violation`] and the result is not published.
//! - **Out-dir virtualization:** the out-dir is placement, not semantics:
//!   `--out-dir`, `-L dependency=` and `--extern` paths are rewritten to
//!   [`CANONICAL_OUT_DIR`] before keying. rustc does not embed the out-dir
//!   in `.rlib`/`.rmeta` bytes (pinned by a real-rustc test); dep-info and
//!   the JSON artifact notifications do mention it, and are canonicalized
//!   by [`canonicalize_out_dir`] / rendered back by [`render_out_dir`].
//!   Every other path (source, cwd, `--remap-path-prefix`, `--sysroot`)
//!   is keyed as given — local-host serving only (`SubscriberPathPreserving`).
//! - **Dependencies:** the exact bytes of every `--extern` artifact
//!   (plan §17.7's conservative default), bound to their crate names.
//!   Transitive crates rustc loads from the search path are pinned through
//!   the strict version hashes recorded inside those direct artifacts.
//! - **Environment (`dependency-env-v1`):** the action's environment is
//!   CONSTRUCTED, not inherited: `CARGO*`, `RUSTC*`, `RUST_*` and a short
//!   fixed list are keyed with their values; the jobserver variables are
//!   passed through unkeyed (host-local descriptors, plan §17.4); every
//!   other variable is ABSENT from the executed compiler. The executing
//!   process must use [`DependencyActionPlan::execution_env`] verbatim, so
//!   a served result and a private execution see the same environment.
//! - **Toolchain:** binary digests and the complete `rustc -vV` identity
//!   supplied by the caller's probe.
//!
//! Like the rest of this crate: zero filesystem, process, or network
//! effects. Callers observe; this module normalizes and hashes.

use rabs_protocol::descriptor::{ActionClass, ActionDescriptor};
use rabs_protocol::input_evidence::{ActionInputManifest, InputFileType};
use rabs_protocol::result_identity::TypedDigest;

use crate::action_key::{action_input_manifest_digest, compute_action_key};
use crate::canonical::CanonicalEncoder;
use crate::dependency_identity::{ConsumedArtifact, DependencyInputs};
use crate::environment::{DESCRIPTOR_AUTH_VARS, EnvDisposition, PresentedEnvironment};
use crate::extern_resolution::{
    DependencyArtifactIdentity, DependencyArtifactKind, resolve_externs, resolved_externs_digest,
};
use crate::hit_verification::{descriptor_canonical_bytes, descriptor_digest};
use crate::invocation::{NormalizedRustcInvocation, SourceInput, parse};
use crate::output_declarations::OutputDeclarationSet;
use crate::output_derivation::derive_dependency_output_declarations;
use crate::output_platform::{CpuBaseline, OutputPlatformContract};
use crate::path_policy::{BuildPathSemanticPolicy, policy_component_digest};
use crate::toolchain::ToolchainContract;
use crate::typed_digest::compute;

/// Key epoch of the live dependency class.
pub const LIVE_DEPENDENCY_KEY_EPOCH: u32 = 1;
/// Projection epoch: exact (unprojected) dependency artifacts.
pub const LIVE_DEPENDENCY_PROJECTION_EPOCH: u32 = 1;
/// Canonical spelling of the invocation's out-dir in keys, committed
/// dep-info and committed transcripts.
pub const CANONICAL_OUT_DIR: &str = "/__rabs/out";
/// Canonical parent of the package root in input-manifest virtual paths.
pub const CANONICAL_PACKAGE_PARENT: &str = "/__rabs/repos";

/// Normalized-invocation component domain for this class.
pub const DOMAIN_LIVE_INVOCATION: &str = "rabs.live-dependency.invocation.v1";
/// Working-directory component domain.
pub const DOMAIN_LIVE_CWD: &str = "rabs.live-dependency.cwd.v1";
/// Negative-dependency component domain.
pub const DOMAIN_LIVE_NEGATIVE: &str = "rabs.live-dependency.negative.v1";
/// Dependency-artifact component domain (inputs + name binding).
pub const DOMAIN_LIVE_ARTIFACTS: &str = "rabs.live-dependency.artifacts.v1";
/// Sandbox/isolation policy component domain.
pub const DOMAIN_LIVE_ISOLATION: &str = "rabs.live-dependency.isolation.v1";
/// Execution-semantics component domain.
pub const DOMAIN_LIVE_EXECUTION: &str = "rabs.live-dependency.execution.v1";
/// Target-specification digest domain (built-in triples only).
pub const DOMAIN_LIVE_TARGET_SPEC: &str = "rabs.live-dependency.target-spec.v1";

/// The isolation profile this class actually has. Deliberately plain: it
/// is NOT a sandbox, and the key says so.
pub const ISOLATION_PROFILE: &str = "live-dependency-v1: unsandboxed local edge process; \
     environment constructed by dependency-env-v1 (allowlisted names keyed, jobserver \
     passthrough unkeyed, all other names absent); source = complete registry package \
     tree; closure enforced after execution by dep-info containment; proc-macro \
     consumption and build-script outputs refused";

/// What the executed compiler must produce for a publishable result.
pub const EXECUTION_SEMANTICS: &str = "live-dependency-v1: rustc exit status 0 by normal \
     exit, empty stdout, stderr = JSON diagnostics transcript canonicalized by out-dir \
     substitution; every declared output present";

/// Names keyed with their values regardless of prefix.
const FIXED_KEYED_NAMES: &[&str] = &[
    "PATH",
    "HOME",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_COLLATE",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LC_NUMERIC",
    "LC_TIME",
    "TZ",
    "RUSTUP_HOME",
    "RUSTUP_TOOLCHAIN",
    "SOURCE_DATE_EPOCH",
    "DOCS_RS",
    "LD_LIBRARY_PATH",
];

/// Names whose presence takes the request out of this class.
const REFUSED_NAMES: &[&str] = &[
    // Build-script output: needs the N-epic run cache.
    "OUT_DIR",
    // A workspace member is not an immutable dependency.
    "CARGO_PRIMARY_PACKAGE",
    // Loader injection vectors change the compiler itself.
    "LD_PRELOAD",
    "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES",
];

/// Why a request is outside the live dependency class. Every variant
/// means "compile it normally"; none is an error of the build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveRefusal {
    /// argv could not be parsed into one rustc invocation.
    Unparseable(String),
    /// The bounded output adapter refused (outputs not exactly derivable).
    Outputs(String),
    /// A required environment variable is absent.
    MissingEnv(&'static str),
    /// An environment variable whose presence leaves the class.
    RefusedEnv(String),
    /// Duplicate environment variable name in the request.
    DuplicateEnv(String),
    /// `CARGO_MANIFEST_DIR` is not a registry package root.
    NotRegistryPackage(String),
    /// Not invoked by Cargo as a capped-lint dependency compile.
    NotDependencyCompile(&'static str),
    /// rustc working directory differs from the package root.
    WorkingDirectory(String),
    /// The source file is not inside the package root.
    SourceOutsidePackage(String),
    /// A path cannot be represented exactly in dep-info and JSON.
    UnrepresentablePath(String),
    /// A search path other than `dependency=<out-dir>`.
    SearchPath(String),
    /// A dependency artifact outside the out-dir or of an unknown kind.
    Extern(String),
    /// A proc-macro dependency (untracked reads, plan §33).
    ProcMacroDependency(String),
    /// Native link inputs.
    NativeLibrary(String),
    /// JSON diagnostics are required.
    DiagnosticFormat,
    /// `target-cpu=native` has no resolved cohort here.
    NativeCpu,
    /// Supplied facts do not cover the plan (caller bug or a race).
    Facts(String),
}

impl LiveRefusal {
    /// Stable reason code (receipts, `rch why`).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Unparseable(_) => "LIVE_DEP_UNPARSEABLE",
            Self::Outputs(_) => "LIVE_DEP_OUTPUTS",
            Self::MissingEnv(_) => "LIVE_DEP_MISSING_ENV",
            Self::RefusedEnv(_) => "LIVE_DEP_REFUSED_ENV",
            Self::DuplicateEnv(_) => "LIVE_DEP_DUPLICATE_ENV",
            Self::NotRegistryPackage(_) => "LIVE_DEP_NOT_REGISTRY",
            Self::NotDependencyCompile(_) => "LIVE_DEP_NOT_DEPENDENCY",
            Self::WorkingDirectory(_) => "LIVE_DEP_CWD",
            Self::SourceOutsidePackage(_) => "LIVE_DEP_SOURCE",
            Self::UnrepresentablePath(_) => "LIVE_DEP_PATH",
            Self::SearchPath(_) => "LIVE_DEP_SEARCH_PATH",
            Self::Extern(_) => "LIVE_DEP_EXTERN",
            Self::ProcMacroDependency(_) => "LIVE_DEP_PROC_MACRO",
            Self::NativeLibrary(_) => "LIVE_DEP_NATIVE_LIB",
            Self::DiagnosticFormat => "LIVE_DEP_DIAGNOSTIC_FORMAT",
            Self::NativeCpu => "LIVE_DEP_NATIVE_CPU",
            Self::Facts(_) => "LIVE_DEP_FACTS",
        }
    }
}

impl std::fmt::Display for LiveRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unparseable(detail)
            | Self::Outputs(detail)
            | Self::RefusedEnv(detail)
            | Self::DuplicateEnv(detail)
            | Self::NotRegistryPackage(detail)
            | Self::WorkingDirectory(detail)
            | Self::SourceOutsidePackage(detail)
            | Self::UnrepresentablePath(detail)
            | Self::SearchPath(detail)
            | Self::Extern(detail)
            | Self::ProcMacroDependency(detail)
            | Self::NativeLibrary(detail)
            | Self::Facts(detail) => write!(f, "{}: {detail}", self.code()),
            Self::MissingEnv(name) => write!(f, "{}: {name}", self.code()),
            Self::NotDependencyCompile(why) => write!(f, "{}: {why}", self.code()),
            Self::DiagnosticFormat | Self::NativeCpu => f.write_str(self.code()),
        }
    }
}

/// One live wrapper request: the complete compiler argv (argv\[0\] is the
/// real compiler), rustc's working directory and its full environment.
#[derive(Debug, Clone, Copy)]
pub struct LiveRustcRequest<'a> {
    /// The real compiler followed by every argument.
    pub argv: &'a [String],
    /// rustc's working directory.
    pub cwd: &'a str,
    /// Every environment variable the wrapper received.
    pub env: &'a [(String, String)],
}

/// One `--extern` the action consumes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlannedExtern {
    /// A file inside the out-dir; its bytes key the action.
    File {
        /// Crate name.
        name: String,
        /// Real absolute path the compiler reads.
        path: String,
        /// Artifact kind (by extension).
        kind: DependencyArtifactKind,
    },
    /// A sysroot crate named without a path.
    Toolchain {
        /// Crate name.
        name: String,
    },
}

/// A request inside the class, with everything a caller must observe
/// before the key can be computed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyActionPlan {
    /// The invocation as it executes (real paths).
    pub invocation: NormalizedRustcInvocation,
    /// The real compiler argv\[0\].
    pub compiler: String,
    /// rustc's working directory (= the package root).
    pub cwd: String,
    /// Absolute out-dir (placement; virtualized in the key).
    pub out_dir: String,
    /// The registry package root (`CARGO_MANIFEST_DIR`).
    pub package_root: String,
    /// Final component of the package root (`name-version`).
    pub package_dir_name: String,
    /// Target triple the outputs are for.
    pub target_triple: String,
    /// Host triple from the toolchain probe.
    pub host_triple: String,
    /// Dependency artifacts in argv order.
    pub externs: Vec<PlannedExtern>,
    /// Derived outputs, relative to the out-dir.
    pub outputs: OutputDeclarationSet,
    /// Keyed environment, sorted by name.
    pub keyed_env: Vec<(String, String)>,
    /// The COMPLETE environment the compiler must execute with, sorted:
    /// the keyed variables plus the unkeyed jobserver passthrough.
    pub execution_env: Vec<(String, String)>,
}

impl DependencyActionPlan {
    /// Virtual root of the package's files in the input manifest.
    #[must_use]
    pub fn package_virtual_root(&self) -> String {
        format!("{CANONICAL_PACKAGE_PARENT}/{}", self.package_dir_name)
    }

    /// The input-manifest virtual path for a file at `relative` (a `/`
    /// separated path below the package root).
    #[must_use]
    pub fn input_virtual_path(&self, relative: &str) -> String {
        format!("{}/{relative}", self.package_virtual_root())
    }

    /// Output file names relative to the out-dir, sorted.
    #[must_use]
    pub fn output_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .outputs
            .declarations
            .iter()
            .map(|output| output.virtual_path.clone())
            .collect();
        names.sort();
        names
    }
}

/// Toolchain facts from the caller's probe of the REAL compiler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolchainFacts {
    /// Content digest of the resolved rustc binary.
    pub compiler_binary_digest: TypedDigest,
    /// Complete `rustc -vV` stdout (trimmed of trailing whitespace).
    pub verbose_version: String,
    /// Digest over the sysroot object tree the compiler loads from.
    pub sysroot_root_digest: TypedDigest,
    /// Digests of runtime libraries the compiler itself loads
    /// (`librustc_driver`, LLVM), sorted by the caller.
    pub runtime_libraries: Vec<TypedDigest>,
}

impl ToolchainFacts {
    /// The `host:` triple reported by the probe.
    #[must_use]
    pub fn host_triple(&self) -> Option<&str> {
        self.verbose_version
            .lines()
            .find_map(|line| line.strip_prefix("host: "))
            .map(str::trim)
    }

    fn line(&self, prefix: &str) -> String {
        self.verbose_version
            .lines()
            .find_map(|line| line.strip_prefix(prefix))
            .map(|value| value.trim().to_owned())
            .unwrap_or_default()
    }
}

/// The content identity of one planned extern file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternFact {
    /// The real path from the plan.
    pub path: String,
    /// Content digest of the file bytes.
    pub content_digest: TypedDigest,
}

/// The exact key of one live dependency action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveDependencyKey {
    /// The full descriptor.
    pub descriptor: ActionDescriptor,
    /// `compute_action_key(descriptor).final_key`.
    pub action_key: TypedDigest,
    /// Independent descriptor digest (the manifest's
    /// `canonical_descriptor_digest`).
    pub descriptor_digest: TypedDigest,
}

/// Path bytes that survive dep-info escaping, JSON escaping and the
/// dep-info rule grammar unchanged. Paths outside this alphabet are
/// refused rather than escaped: an exact transcript is worth more than
/// coverage of exotic directory names.
fn plain_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() > 1
        && !path.ends_with('/')
        && !path.contains("//")
        && path.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-' | b'+' | b'@')
        })
        && !path.split('/').any(|part| part == "." || part == "..")
        && !path.contains("/__rabs")
}

fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
}

fn within(path: &str, root: &str) -> bool {
    path.len() > root.len() && path.starts_with(root) && path.as_bytes()[root.len()] == b'/'
}

/// Classify one environment variable under `dependency-env-v1`.
enum EnvRole {
    Keyed,
    Passthrough,
    Scrubbed,
}

fn env_role(name: &str) -> EnvRole {
    if DESCRIPTOR_AUTH_VARS.contains(&name.as_bytes()) {
        return EnvRole::Passthrough;
    }
    let prefixed = |prefix: &str| name == prefix || name.starts_with(&format!("{prefix}_"));
    if prefixed("CARGO") || prefixed("RUSTC") || name.starts_with("RUST_") {
        return EnvRole::Keyed;
    }
    if FIXED_KEYED_NAMES.contains(&name) {
        EnvRole::Keyed
    } else {
        EnvRole::Scrubbed
    }
}

/// The complete `dependency-env-v1` environment for a compiler process:
/// keyed names with their values plus the unkeyed jobserver passthrough,
/// sorted by name. Every other name is absent. Toolchain probes use this
/// too, so a probe sees exactly what an executed compile would see.
#[must_use]
pub fn constructed_environment(env: &[(String, String)]) -> Vec<(String, String)> {
    let mut constructed: Vec<(String, String)> = env
        .iter()
        .filter(|(name, _)| !matches!(env_role(name), EnvRole::Scrubbed))
        .cloned()
        .collect();
    constructed.sort();
    constructed
}

fn env_value<'a>(env: &'a [(String, String)], name: &str) -> Option<&'a str> {
    env.iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

/// Decide whether a live request is inside the class and, if so, what must
/// be observed to key it. `host_triple` comes from the toolchain probe.
///
/// # Errors
/// A typed [`LiveRefusal`]: the request compiles normally, unkeyed.
#[allow(clippy::too_many_lines)]
pub fn plan_dependency_action(
    request: LiveRustcRequest<'_>,
    host_triple: &str,
) -> Result<DependencyActionPlan, LiveRefusal> {
    // Environment first: it is the cheapest way out of the class.
    let mut names: Vec<&str> = request.env.iter().map(|(name, _)| name.as_str()).collect();
    names.sort_unstable();
    if let Some(pair) = names.windows(2).find(|pair| pair[0] == pair[1]) {
        return Err(LiveRefusal::DuplicateEnv(pair[0].to_owned()));
    }
    if let Some(name) = names.iter().find(|name| REFUSED_NAMES.contains(name)) {
        return Err(LiveRefusal::RefusedEnv((*name).to_owned()));
    }
    let package_root = env_value(request.env, "CARGO_MANIFEST_DIR")
        .ok_or(LiveRefusal::MissingEnv("CARGO_MANIFEST_DIR"))?
        .to_owned();
    env_value(request.env, "CARGO_PKG_NAME").ok_or(LiveRefusal::MissingEnv("CARGO_PKG_NAME"))?;
    let cargo_home = match env_value(request.env, "CARGO_HOME") {
        Some(home) => home.trim_end_matches('/').to_owned(),
        None => format!(
            "{}/.cargo",
            env_value(request.env, "HOME")
                .ok_or(LiveRefusal::MissingEnv("HOME"))?
                .trim_end_matches('/')
        ),
    };
    if !plain_path(&package_root) {
        return Err(LiveRefusal::UnrepresentablePath(package_root));
    }
    let registry_src = format!("{cargo_home}/registry/src");
    let (index_dir, package_dir_name) = package_root
        .strip_prefix(&registry_src)
        .and_then(|rest| rest.strip_prefix('/'))
        .and_then(|rest| rest.split_once('/'))
        .filter(|(index, package)| safe_component(index) && safe_component(package))
        .ok_or_else(|| LiveRefusal::NotRegistryPackage(package_root.clone()))?;
    let _ = index_dir;
    let package_dir_name = package_dir_name.to_owned();

    if request.cwd != package_root {
        return Err(LiveRefusal::WorkingDirectory(request.cwd.to_owned()));
    }

    let invocation = parse(request.argv, None)
        .map_err(|error| LiveRefusal::Unparseable(format!("{error:?}")))?;
    let outputs = derive_dependency_output_declarations(&invocation, host_triple)
        .map_err(|error| LiveRefusal::Outputs(format!("{error:?}")))?;
    if invocation.cap_lints.as_deref() != Some("allow") {
        return Err(LiveRefusal::NotDependencyCompile(
            "Cargo caps lints for registry dependencies; this invocation does not",
        ));
    }
    if !invocation
        .passthrough
        .iter()
        .any(|arg| arg == "--error-format=json")
    {
        return Err(LiveRefusal::DiagnosticFormat);
    }
    if invocation
        .codegen
        .iter()
        .any(|(name, value)| name == "target-cpu" && value.as_deref() == Some("native"))
    {
        return Err(LiveRefusal::NativeCpu);
    }
    if let Some(library) = invocation.native_libs.first() {
        return Err(LiveRefusal::NativeLibrary(library.clone()));
    }
    let source = match &invocation.source {
        Some(SourceInput::Path(path)) => path.clone(),
        _ => return Err(LiveRefusal::SourceOutsidePackage("no source path".into())),
    };
    if !plain_path(&source) || !within(&source, &package_root) {
        return Err(LiveRefusal::SourceOutsidePackage(source));
    }
    let out_dir = invocation
        .out_dir
        .clone()
        .ok_or_else(|| LiveRefusal::Outputs("missing --out-dir".into()))?;
    if !plain_path(&out_dir)
        || out_dir == package_root
        || within(&out_dir, &package_root)
        || within(&package_root, &out_dir)
    {
        return Err(LiveRefusal::UnrepresentablePath(out_dir));
    }
    let dependency_search = format!("dependency={out_dir}");
    if let Some(other) = invocation
        .lib_search
        .iter()
        .find(|entry| **entry != dependency_search)
    {
        return Err(LiveRefusal::SearchPath(other.clone()));
    }

    let mut externs = Vec::with_capacity(invocation.externs.len());
    for (name, path) in &invocation.externs {
        let Some(path) = path else {
            externs.push(PlannedExtern::Toolchain { name: name.clone() });
            continue;
        };
        let file = path
            .strip_prefix(&out_dir)
            .and_then(|rest| rest.strip_prefix('/'))
            .filter(|file| safe_component(file))
            .ok_or_else(|| LiveRefusal::Extern(path.clone()))?;
        let kind = if file.ends_with(".rmeta") {
            DependencyArtifactKind::Rmeta
        } else if file.ends_with(".rlib") {
            DependencyArtifactKind::Rlib
        } else if file.ends_with(".so") || file.ends_with(".dylib") {
            return Err(LiveRefusal::ProcMacroDependency(path.clone()));
        } else {
            return Err(LiveRefusal::Extern(path.clone()));
        };
        externs.push(PlannedExtern::File {
            name: name.clone(),
            path: path.clone(),
            kind,
        });
    }

    let execution_env = constructed_environment(request.env);
    let keyed_env: Vec<(String, String)> = execution_env
        .iter()
        .filter(|(name, _)| matches!(env_role(name), EnvRole::Keyed))
        .cloned()
        .collect();

    let target_triple = invocation
        .target
        .clone()
        .unwrap_or_else(|| host_triple.to_owned());
    Ok(DependencyActionPlan {
        compiler: invocation.compiler_argv0.clone(),
        invocation,
        cwd: request.cwd.to_owned(),
        out_dir,
        package_root,
        package_dir_name,
        target_triple,
        host_triple: host_triple.to_owned(),
        externs,
        outputs,
        keyed_env,
        execution_env,
    })
}

fn virtual_out_path(out_dir: &str, path: &str) -> String {
    match path.strip_prefix(out_dir) {
        Some(rest) => format!("{CANONICAL_OUT_DIR}{rest}"),
        None => path.to_owned(),
    }
}

/// The normalized-invocation component: out-dir placement virtualized,
/// every other path kept, presentation flags bound (an exact transcript
/// is only replayable under the presentation that produced it).
fn invocation_component(plan: &DependencyActionPlan) -> TypedDigest {
    let mut virtual_invocation = plan.invocation.clone();
    virtual_invocation.out_dir = Some(CANONICAL_OUT_DIR.to_owned());
    for entry in &mut virtual_invocation.lib_search {
        *entry = format!("dependency={CANONICAL_OUT_DIR}");
    }
    for (_, path) in &mut virtual_invocation.externs {
        if let Some(path) = path {
            *path = virtual_out_path(&plan.out_dir, path);
        }
    }
    let mut enc = CanonicalEncoder::new();
    enc.bytes(&virtual_invocation.canonical_bytes());
    enc.seq(&virtual_invocation.excluded_presentation, |enc, flag| {
        enc.str(flag);
    });
    compute(DOMAIN_LIVE_INVOCATION, &enc.finish())
}

fn artifacts_component(
    plan: &DependencyActionPlan,
    facts: &[ExternFact],
) -> Result<TypedDigest, LiveRefusal> {
    let identity_of = |path: &str| -> Option<DependencyArtifactIdentity> {
        let kind = plan.externs.iter().find_map(|planned| match planned {
            PlannedExtern::File {
                path: planned,
                kind,
                ..
            } if planned == path => Some(*kind),
            _ => None,
        })?;
        let fact = facts.iter().find(|fact| fact.path == path)?;
        Some(DependencyArtifactIdentity {
            kind,
            content_digest: fact.content_digest.clone(),
        })
    };
    let resolved = resolve_externs(&plan.invocation.externs, identity_of)
        .map_err(|error| LiveRefusal::Facts(format!("{error:?}")))?;
    let compile_inputs = plan
        .externs
        .iter()
        .filter_map(|planned| match planned {
            PlannedExtern::File { path, kind, .. } => Some((path, kind)),
            PlannedExtern::Toolchain { .. } => None,
        })
        .map(|(path, kind)| {
            let digest = facts
                .iter()
                .find(|fact| &fact.path == path)
                .map(|fact| fact.content_digest.clone())
                .ok_or_else(|| LiveRefusal::Facts(format!("no digest for {path}")))?;
            Ok(match kind {
                DependencyArtifactKind::Rlib => ConsumedArtifact::RlibBytes(digest),
                _ => ConsumedArtifact::RmetaBytes(digest),
            })
        })
        .collect::<Result<Vec<_>, LiveRefusal>>()?;
    let inputs = DependencyInputs {
        compile_inputs,
        link_inputs: Vec::new(),
        link_semantics: None,
    };
    let names = resolved_externs_digest(&resolved);
    let digest = inputs.inputs_digest();
    let mut enc = CanonicalEncoder::new();
    enc.str(digest.domain)
        .bytes(&digest.bytes)
        .str(names.domain)
        .bytes(&names.bytes);
    Ok(compute(DOMAIN_LIVE_ARTIFACTS, &enc.finish()))
}

/// Normalizer identity for dynamic-library search paths: Cargo prepends
/// the invocation's out-dir to `LD_LIBRARY_PATH` for rustc, which is the
/// same placement fact as `--out-dir` and is virtualized the same way.
pub const DYLIB_PATH_NORMALIZER: &str = "live-dependency.dylib-path-out-dir.v1";

fn environment_component(plan: &DependencyActionPlan) -> Result<TypedDigest, LiveRefusal> {
    let mut variables: Vec<(Vec<u8>, EnvDisposition)> = plan
        .keyed_env
        .iter()
        .map(|(name, value)| {
            let disposition = if name == "LD_LIBRARY_PATH" {
                EnvDisposition::SemanticNormalized {
                    normalizer: DYLIB_PATH_NORMALIZER.to_owned(),
                    normalized: value
                        .split(':')
                        .map(|entry| {
                            if entry == plan.out_dir {
                                CANONICAL_OUT_DIR
                            } else {
                                entry
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(":")
                        .into_bytes(),
                }
            } else {
                EnvDisposition::SemanticHashed(value.as_bytes().to_vec())
            };
            (name.as_bytes().to_vec(), disposition)
        })
        .collect();
    for (name, _) in &plan.execution_env {
        if !plan.keyed_env.iter().any(|(keyed, _)| keyed == name) {
            variables.push((name.as_bytes().to_vec(), EnvDisposition::VolatileRefusal));
        }
    }
    PresentedEnvironment {
        variables,
        path_manifest: Vec::new(),
    }
    .dataset_digest()
    .map_err(|error| LiveRefusal::Facts(format!("{error:?}")))
}

fn output_platform_component(plan: &DependencyActionPlan) -> TypedDigest {
    let codegen = |name: &str| -> Vec<String> {
        plan.invocation
            .codegen
            .iter()
            .filter(|(flag, _)| flag == name)
            .filter_map(|(_, value)| value.clone())
            .collect()
    };
    OutputPlatformContract {
        target_triple: plan.target_triple.clone(),
        host_abi_triple: plan.host_triple.clone(),
        cpu_baseline: CpuBaseline::Explicit {
            baseline: codegen("target-cpu")
                .pop()
                .unwrap_or_else(|| "target-default".to_owned()),
            feature_adjustments: codegen("target-feature"),
        },
        // rlib/rmeta outputs are not linked against a C runtime or a
        // linker; a linking class must replace these with real identities.
        libc_runtime: "unlinked-rust-library".to_owned(),
        linker_format: "unlinked-rust-library".to_owned(),
        sdk_identity: None,
        deployment_target: None,
        signing_policy: None,
        filesystem_semantic_class: "local-edge-host".to_owned(),
    }
    .contract_digest()
}

/// Compute the exact key of a planned action from the caller's observed
/// facts: the toolchain probe, the content digest of every planned extern
/// file, and the complete package input manifest (virtual paths from
/// [`DependencyActionPlan::input_virtual_path`]).
///
/// # Errors
/// [`LiveRefusal::Facts`] when the facts do not exactly cover the plan.
pub fn live_dependency_key(
    plan: &DependencyActionPlan,
    toolchain: &ToolchainFacts,
    externs: &[ExternFact],
    inputs: &ActionInputManifest,
) -> Result<LiveDependencyKey, LiveRefusal> {
    if toolchain.host_triple() != Some(plan.host_triple.as_str()) {
        return Err(LiveRefusal::Facts(
            "toolchain probe host differs from the planned host".into(),
        ));
    }
    let root = format!("{}/", plan.package_virtual_root());
    if inputs.inputs.is_empty()
        || !inputs.directory_enumerations.is_empty()
        || !inputs.approved_generated_objects.is_empty()
        || inputs.inputs.iter().any(|input| {
            input.file_type != InputFileType::Regular
                || !input.symlink_resolution.is_empty()
                || !input.virtual_path.as_bytes().starts_with(root.as_bytes())
        })
    {
        return Err(LiveRefusal::Facts(
            "the input manifest must be the package's complete regular-file tree".into(),
        ));
    }
    let source_relative = plan
        .invocation
        .source
        .as_ref()
        .and_then(|source| match source {
            SourceInput::Path(path) => path.strip_prefix(&format!("{}/", plan.package_root)),
            SourceInput::Stdin(_) => None,
        })
        .map(|relative| plan.input_virtual_path(relative))
        .ok_or_else(|| LiveRefusal::Facts("source path left the package".into()))?;
    if !inputs
        .inputs
        .iter()
        .any(|input| input.virtual_path.as_bytes() == source_relative.as_bytes())
    {
        return Err(LiveRefusal::Facts(
            "the input manifest does not contain the compiled source file".into(),
        ));
    }
    let action_inputs = action_input_manifest_digest(inputs)
        .map_err(|error| LiveRefusal::Facts(format!("{error:?}")))?;

    let negative = {
        let mut enc = CanonicalEncoder::new();
        enc.str("complete-package-tree-enumeration-v1")
            .str(&plan.package_virtual_root());
        compute(DOMAIN_LIVE_NEGATIVE, &enc.finish())
    };
    let toolchain_contract = ToolchainContract {
        compiler_binary_digest: toolchain.compiler_binary_digest.clone(),
        // The COMPLETE verbose identity, not just the commit line: release,
        // date, host and backend all participate.
        commit_identity: toolchain.verbose_version.trim_end().to_owned(),
        backend_identity: toolchain.line("LLVM version: "),
        sysroot_root_digest: toolchain.sysroot_root_digest.clone(),
        target_spec_digest: compute(DOMAIN_LIVE_TARGET_SPEC, plan.target_triple.as_bytes()),
        unstable_feature_profile: Vec::new(),
        cargo_identity: None,
        component_identity: None,
        native_tools: Vec::new(),
        runtime_libraries: toolchain.runtime_libraries.clone(),
        semantic_adapter_epoch: 1,
    };
    let output_declarations = plan
        .outputs
        .declaration_digest()
        .map_err(|error| LiveRefusal::Facts(format!("{error:?}")))?;
    let descriptor = ActionDescriptor {
        key_epoch: LIVE_DEPENDENCY_KEY_EPOCH,
        projection_epoch: LIVE_DEPENDENCY_PROJECTION_EPOCH,
        action_class: ActionClass::RustcDependencyCompile,
        normalized_invocation: invocation_component(plan),
        virtual_working_directory: compute(DOMAIN_LIVE_CWD, plan.cwd.as_bytes()),
        action_inputs,
        negative_dependencies: negative,
        dependency_inputs: artifacts_component(plan, externs)?,
        toolchain: toolchain_contract.dataset_digest(),
        output_platform: output_platform_component(plan),
        environment: environment_component(plan)?,
        sandbox_semantic_policy: compute(DOMAIN_LIVE_ISOLATION, ISOLATION_PROFILE.as_bytes()),
        build_path_semantic_policy: policy_component_digest(
            BuildPathSemanticPolicy::SubscriberPathPreserving,
        ),
        execution_semantics: compute(DOMAIN_LIVE_EXECUTION, EXECUTION_SEMANTICS.as_bytes()),
        output_declarations,
    };
    let action_key = compute_action_key(&descriptor).final_key;
    let descriptor_digest = descriptor_digest(&descriptor_canonical_bytes(&descriptor));
    Ok(LiveDependencyKey {
        descriptor,
        action_key,
        descriptor_digest,
    })
}

/// Rewrite every occurrence of the real out-dir to [`CANONICAL_OUT_DIR`]
/// (committed dep-info and transcripts). Refuses bytes that already
/// contain the canonical marker: the rewrite would not be invertible.
///
/// # Errors
/// A static reason when the rewrite would be ambiguous.
pub fn canonicalize_out_dir(raw: &[u8], out_dir: &str) -> Result<Vec<u8>, &'static str> {
    if contains(raw, b"/__rabs") {
        return Err("bytes already contain a canonical /__rabs path");
    }
    if !plain_path(out_dir) {
        return Err("out-dir is not a plain path");
    }
    Ok(replace_all(
        raw,
        out_dir.as_bytes(),
        CANONICAL_OUT_DIR.as_bytes(),
    ))
}

/// Inverse of [`canonicalize_out_dir`] for one subscriber's out-dir.
#[must_use]
pub fn render_out_dir(canonical: &[u8], out_dir: &str) -> Vec<u8> {
    replace_all(canonical, CANONICAL_OUT_DIR.as_bytes(), out_dir.as_bytes())
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn replace_all(haystack: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(haystack.len());
    let mut index = 0;
    while index < haystack.len() {
        if haystack[index..].starts_with(needle) {
            out.extend_from_slice(replacement);
            index += needle.len();
        } else {
            out.push(haystack[index]);
            index += 1;
        }
    }
    out
}

/// Resolve `.` and `..` components of an absolute path without touching
/// the filesystem. `None` when `..` would climb above `/`.
fn lexically_normalized(absolute: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for part in absolute.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            other => parts.push(other),
        }
    }
    Some(format!("/{}", parts.join("/")))
}

/// Post-execution closure enforcement from rustc's own dep-info: every
/// rule target must be inside the out-dir, every source dependency inside
/// the package root, and every tracked environment read (`# env-dep:`)
/// must name a variable the key covers (keyed) or one the constructed
/// environment removed. `is_input` answers whether a package-relative
/// path is a member of the keyed input manifest: a read of a package file
/// the key does not cover is a violation too. Returns the first
/// violation, or `None` when the observed reads are inside the closure.
#[must_use]
pub fn dep_info_closure_violation(
    plan: &DependencyActionPlan,
    dep_info: &[u8],
    is_input: impl Fn(&str) -> bool,
) -> Option<String> {
    let Ok(text) = std::str::from_utf8(dep_info) else {
        return Some("dep-info is not UTF-8".into());
    };
    for line in text.lines() {
        if let Some(comment) = line.strip_prefix('#') {
            if let Some(read) = comment.trim_start().strip_prefix("env-dep:") {
                let name = read.split_once('=').map_or(read, |(name, _)| name);
                let passthrough = plan
                    .execution_env
                    .iter()
                    .any(|(present, _)| present == name)
                    && !plan.keyed_env.iter().any(|(keyed, _)| keyed == name);
                if passthrough {
                    return Some(format!("tracked read of unkeyed variable {name}"));
                }
            }
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        if line.contains('\\') {
            return Some(format!("escaped dep-info token: {line}"));
        }
        let Some((targets, deps)) = line
            .split_once(": ")
            .or_else(|| line.strip_suffix(':').map(|targets| (targets, "")))
        else {
            return Some(format!("unrecognized dep-info line: {line}"));
        };
        for target in targets.split_whitespace() {
            let absolute = if target.starts_with('/') {
                target.to_owned()
            } else {
                format!("{}/{target}", plan.cwd)
            };
            let in_out_dir = within(&absolute, &plan.out_dir);
            let in_package = within(&absolute, &plan.package_root);
            // rustc also emits phony `src: ` rules for every input.
            if !in_out_dir && !(in_package && deps.trim().is_empty()) {
                return Some(format!("dep-info target outside the closure: {target}"));
            }
        }
        for dep in deps.split_whitespace() {
            let absolute = if dep.starts_with('/') {
                dep.to_owned()
            } else {
                format!("{}/{dep}", plan.cwd)
            };
            // rustc reports `include_str!("../README.md")` from `src/` as
            // `src/../README.md`. The keyed package tree is symlink-free
            // (capture refuses links), so lexical normalization is exact.
            let Some(normalized) = lexically_normalized(&absolute) else {
                return Some(format!("read outside the filesystem root: {dep}"));
            };
            if !within(&normalized, &plan.package_root) {
                return Some(format!("read outside the package: {dep}"));
            }
            let relative = &normalized[plan.package_root.len() + 1..];
            if !is_input(relative) {
                return Some(format!("read of an unkeyed package file: {dep}"));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::input_evidence::{INPUT_EVIDENCE_SCHEMA_VERSION, PositiveInput};
    use rabs_protocol::raw_bytes::RawBytes;
    use rabs_protocol::result_identity::ObjectId;

    const HOME: &str = "/home/agent";
    const PACKAGE: &str =
        "/home/agent/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/itoa-1.0.15";
    const OUT_A: &str = "/work/a/target/debug/deps";
    const OUT_B: &str = "/work/b/target/debug/deps";

    fn argv(out_dir: &str, extra: &[&str]) -> Vec<String> {
        let mut argv: Vec<String> = [
            "/toolchain/bin/rustc",
            "--crate-name",
            "itoa",
            "--edition=2018",
            &format!("{PACKAGE}/src/lib.rs"),
            "--error-format=json",
            "--json=diagnostic-rendered-ansi,artifacts,future-incompat",
            "--crate-type",
            "lib",
            "--emit=dep-info,metadata,link",
            "-C",
            "embed-bitcode=no",
            "-C",
            "debuginfo=2",
            "-C",
            "metadata=c2b2f4e1a6d0b3c9",
            "-C",
            "extra-filename=-c2b2f4e1a6d0b3c9",
            "--out-dir",
            out_dir,
            "-L",
            &format!("dependency={out_dir}"),
            "--extern",
            &format!("dep={out_dir}/libdep-0123456789abcdef.rmeta"),
            "--cap-lints",
            "allow",
        ]
        .iter()
        .map(|arg| (*arg).to_owned())
        .collect();
        argv.extend(extra.iter().map(|arg| (*arg).to_owned()));
        argv
    }

    fn env(extra: &[(&str, &str)]) -> Vec<(String, String)> {
        let mut env: Vec<(String, String)> = [
            ("HOME", HOME),
            ("PATH", "/usr/bin:/bin"),
            ("CARGO", "/toolchain/bin/cargo"),
            ("CARGO_MANIFEST_DIR", PACKAGE),
            ("CARGO_PKG_NAME", "itoa"),
            ("CARGO_PKG_VERSION", "1.0.15"),
            ("CARGO_CRATE_NAME", "itoa"),
            ("CARGO_MAKEFLAGS", "-j --jobserver-fds=3,4"),
            ("TERM", "xterm-256color"),
            ("SSH_AUTH_SOCK", "/tmp/agent.sock"),
        ]
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect();
        for (name, value) in extra {
            env.retain(|(present, _)| present != name);
            env.push(((*name).to_owned(), (*value).to_owned()));
        }
        env
    }

    fn plan_for(
        out_dir: &str,
        extra_args: &[&str],
        extra_env: &[(&str, &str)],
    ) -> Result<DependencyActionPlan, LiveRefusal> {
        let argv = argv(out_dir, extra_args);
        let env = env(extra_env);
        plan_dependency_action(
            LiveRustcRequest {
                argv: &argv,
                cwd: PACKAGE,
                env: &env,
            },
            "x86_64-unknown-linux-gnu",
        )
    }

    fn digest(tag: u8) -> TypedDigest {
        compute("rabs.test-object.v1", &[tag])
    }

    fn toolchain() -> ToolchainFacts {
        ToolchainFacts {
            compiler_binary_digest: digest(1),
            verbose_version: "rustc 1.100.0-nightly (908501772 2026-08-30)\nbinary: rustc\n\
                              commit-hash: 908501772\nhost: x86_64-unknown-linux-gnu\n\
                              release: 1.100.0-nightly\nLLVM version: 21.1.0"
                .to_owned(),
            sysroot_root_digest: digest(2),
            runtime_libraries: vec![digest(3)],
        }
    }

    fn inputs(plan: &DependencyActionPlan, lib_tag: u8) -> ActionInputManifest {
        let input = |relative: &str, tag: u8| PositiveInput {
            virtual_path: RawBytes::new(plan.input_virtual_path(relative).into_bytes()),
            object: ObjectId(digest(tag)),
            file_type: InputFileType::Regular,
            executable: false,
            symlink_resolution: Vec::new(),
        };
        ActionInputManifest {
            schema_version: INPUT_EVIDENCE_SCHEMA_VERSION,
            inputs: vec![input("Cargo.toml", 10), input("src/lib.rs", lib_tag)],
            ..ActionInputManifest::default()
        }
    }

    fn externs(plan: &DependencyActionPlan, tag: u8) -> Vec<ExternFact> {
        plan.externs
            .iter()
            .filter_map(|planned| match planned {
                PlannedExtern::File { path, .. } => Some(ExternFact {
                    path: path.clone(),
                    content_digest: digest(tag),
                }),
                PlannedExtern::Toolchain { .. } => None,
            })
            .collect()
    }

    fn key(plan: &DependencyActionPlan) -> TypedDigest {
        live_dependency_key(plan, &toolchain(), &externs(plan, 20), &inputs(plan, 11))
            .unwrap()
            .action_key
    }

    #[test]
    fn the_out_dir_is_placement_and_never_keys() {
        let a = plan_for(OUT_A, &[], &[]).unwrap();
        let b = plan_for(OUT_B, &[], &[]).unwrap();
        assert_eq!(a.out_dir, OUT_A);
        assert_eq!(key(&a), key(&b));
        // Cargo prepends the out-dir to rustc's LD_LIBRARY_PATH (observed
        // live): that entry is placement too, every other entry keys.
        let dylib = |out: &str, toolchain: &str| {
            key(&plan_for(
                out,
                &[],
                &[("LD_LIBRARY_PATH", &format!("{out}:{toolchain}"))],
            )
            .unwrap())
        };
        assert_eq!(dylib(OUT_A, "/tc/lib"), dylib(OUT_B, "/tc/lib"));
        assert_ne!(dylib(OUT_A, "/tc/lib"), dylib(OUT_A, "/other/lib"));
        // The executed environment keeps the real value.
        let real = plan_for(
            OUT_A,
            &[],
            &[("LD_LIBRARY_PATH", &format!("{OUT_A}:/tc/lib"))],
        )
        .unwrap();
        assert!(
            real.execution_env
                .contains(&("LD_LIBRARY_PATH".to_owned(), format!("{OUT_A}:/tc/lib")))
        );
        assert_eq!(
            a.output_names(),
            vec![
                "itoa-c2b2f4e1a6d0b3c9.d".to_owned(),
                "libitoa-c2b2f4e1a6d0b3c9.rlib".to_owned(),
                "libitoa-c2b2f4e1a6d0b3c9.rmeta".to_owned(),
            ]
        );
    }

    #[test]
    fn every_semantic_input_changes_the_key() {
        let plan = plan_for(OUT_A, &[], &[]).unwrap();
        let base = key(&plan);
        let with = |toolchain: ToolchainFacts, externs: Vec<ExternFact>, inputs| {
            live_dependency_key(&plan, &toolchain, &externs, &inputs)
                .unwrap()
                .action_key
        };
        // Source bytes, dependency bytes, compiler bytes, sysroot bytes.
        assert_ne!(
            with(toolchain(), externs(&plan, 20), inputs(&plan, 12)),
            base
        );
        assert_ne!(
            with(toolchain(), externs(&plan, 21), inputs(&plan, 11)),
            base
        );
        let mut compiler = toolchain();
        compiler.compiler_binary_digest = digest(9);
        assert_ne!(with(compiler, externs(&plan, 20), inputs(&plan, 11)), base);
        let mut sysroot = toolchain();
        sysroot.sysroot_root_digest = digest(9);
        assert_ne!(with(sysroot, externs(&plan, 20), inputs(&plan, 11)), base);
        // A new file anywhere in the package (complete enumeration).
        let mut added = inputs(&plan, 11);
        added.inputs.push(PositiveInput {
            virtual_path: RawBytes::new(plan.input_virtual_path("src/extra.rs").into_bytes()),
            object: ObjectId(digest(30)),
            file_type: InputFileType::Regular,
            executable: false,
            symlink_resolution: Vec::new(),
        });
        assert_ne!(with(toolchain(), externs(&plan, 20), added), base);
        // Keyed environment and codegen flags.
        assert_ne!(
            key(&plan_for(OUT_A, &[], &[("RUSTC_BOOTSTRAP", "1")]).unwrap()),
            base
        );
        assert_ne!(
            key(&plan_for(OUT_A, &[], &[("CARGO_PKG_VERSION", "1.0.16")]).unwrap()),
            base
        );
        assert_ne!(
            key(&plan_for(OUT_A, &["-C", "opt-level=3"], &[]).unwrap()),
            base
        );
        // Presentation flags bind the transcript variant.
        assert_ne!(
            key(&plan_for(OUT_A, &["--diagnostic-width=80"], &[]).unwrap()),
            base
        );
    }

    #[test]
    fn scrubbed_and_jobserver_variables_never_key_but_jobserver_executes() {
        let plan = plan_for(OUT_A, &[], &[]).unwrap();
        let other_shell = plan_for(
            OUT_A,
            &[],
            &[
                ("TERM", "dumb"),
                ("SSH_AUTH_SOCK", "/elsewhere"),
                ("CARGO_MAKEFLAGS", "-j --jobserver-auth=7,8"),
                ("EDITOR", "vi"),
            ],
        )
        .unwrap();
        assert_eq!(key(&plan), key(&other_shell));
        let names: Vec<&str> = plan.execution_env.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"CARGO_MAKEFLAGS"));
        assert!(names.contains(&"CARGO_PKG_NAME"));
        assert!(!names.contains(&"TERM"));
        assert!(!names.contains(&"SSH_AUTH_SOCK"));
        assert!(
            !plan
                .keyed_env
                .iter()
                .any(|(name, _)| name == "CARGO_MAKEFLAGS")
        );
    }

    #[test]
    fn out_of_class_requests_are_typed_refusals() {
        let code = |result: Result<DependencyActionPlan, LiveRefusal>| result.unwrap_err().code();
        assert_eq!(
            code(plan_for(OUT_A, &[], &[("OUT_DIR", "/x")])),
            "LIVE_DEP_REFUSED_ENV"
        );
        assert_eq!(
            code(plan_for(OUT_A, &[], &[("CARGO_PRIMARY_PACKAGE", "1")])),
            "LIVE_DEP_REFUSED_ENV"
        );
        assert_eq!(
            code(plan_for(
                OUT_A,
                &[],
                &[("CARGO_MANIFEST_DIR", "/work/a/crates/x")]
            )),
            "LIVE_DEP_NOT_REGISTRY"
        );
        assert_eq!(
            code(plan_for(OUT_A, &["-Z", "threads=8"], &[])),
            "LIVE_DEP_OUTPUTS"
        );
        assert_eq!(
            code(plan_for(OUT_A, &["-C", "incremental=/x"], &[])),
            "LIVE_DEP_OUTPUTS"
        );
        assert_eq!(
            code(plan_for(OUT_A, &["-l", "z"], &[])),
            "LIVE_DEP_NATIVE_LIB"
        );
        assert_eq!(
            code(plan_for(
                OUT_A,
                &["-L", "native=/work/a/target/debug/build/x/out"],
                &[]
            )),
            "LIVE_DEP_SEARCH_PATH"
        );
        assert_eq!(
            code(plan_for(
                OUT_A,
                &[
                    "--extern",
                    &format!("serde_derive={OUT_A}/libserde_derive-1.so")
                ],
                &[]
            )),
            "LIVE_DEP_PROC_MACRO"
        );
        assert_eq!(
            code(plan_for(
                OUT_A,
                &["--extern", "x=/elsewhere/libx.rlib"],
                &[]
            )),
            "LIVE_DEP_EXTERN"
        );
        assert_eq!(code(plan_for("/work/a b/deps", &[], &[])), "LIVE_DEP_PATH");
        // Not capped: Cargo compiles workspace members without --cap-lints.
        let mut uncapped = argv(OUT_A, &[]);
        uncapped.truncate(uncapped.len() - 2);
        let env = env(&[]);
        assert_eq!(
            plan_dependency_action(
                LiveRustcRequest {
                    argv: &uncapped,
                    cwd: PACKAGE,
                    env: &env,
                },
                "x86_64-unknown-linux-gnu"
            )
            .unwrap_err()
            .code(),
            "LIVE_DEP_NOT_DEPENDENCY"
        );
        // Wrong working directory.
        let argv = argv(OUT_A, &[]);
        assert_eq!(
            plan_dependency_action(
                LiveRustcRequest {
                    argv: &argv,
                    cwd: "/work/a",
                    env: &env,
                },
                "x86_64-unknown-linux-gnu"
            )
            .unwrap_err()
            .code(),
            "LIVE_DEP_CWD"
        );
    }

    #[test]
    fn facts_must_cover_the_plan_exactly() {
        let plan = plan_for(OUT_A, &[], &[]).unwrap();
        assert_eq!(
            live_dependency_key(&plan, &toolchain(), &[], &inputs(&plan, 11))
                .unwrap_err()
                .code(),
            "LIVE_DEP_FACTS"
        );
        let mut outside = inputs(&plan, 11);
        outside.inputs[0].virtual_path = RawBytes::new(b"/__rabs/repos/other/Cargo.toml".to_vec());
        assert_eq!(
            live_dependency_key(&plan, &toolchain(), &externs(&plan, 20), &outside)
                .unwrap_err()
                .code(),
            "LIVE_DEP_FACTS"
        );
        let mut no_source = inputs(&plan, 11);
        no_source.inputs.pop();
        assert!(live_dependency_key(&plan, &toolchain(), &externs(&plan, 20), &no_source).is_err());
        let mut foreign_host = toolchain();
        foreign_host.verbose_version = foreign_host
            .verbose_version
            .replace("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu");
        assert!(
            live_dependency_key(
                &plan,
                &foreign_host,
                &externs(&plan, 20),
                &inputs(&plan, 11)
            )
            .is_err()
        );
    }

    #[test]
    fn out_dir_canonicalization_round_trips_exactly() {
        let raw = format!(
            "{{\"$message_type\":\"artifact\",\"artifact\":\"{OUT_A}/libitoa-1.rmeta\",\"emit\":\"metadata\"}}\n"
        );
        let canonical = canonicalize_out_dir(raw.as_bytes(), OUT_A).unwrap();
        assert!(!String::from_utf8_lossy(&canonical).contains("/work/a"));
        assert_eq!(render_out_dir(&canonical, OUT_A), raw.as_bytes());
        assert_eq!(
            render_out_dir(&canonical, OUT_B),
            raw.replace(OUT_A, OUT_B).as_bytes()
        );
        assert!(canonicalize_out_dir(b"/__rabs/out/x", OUT_A).is_err());
        assert!(canonicalize_out_dir(b"x", "/a b").is_err());
    }

    #[test]
    fn dep_info_closure_admits_package_reads_and_refuses_escapes() {
        let plan = plan_for(OUT_A, &[], &[("CARGO_PKG_VERSION", "1.0.15")]).unwrap();
        let good = format!(
            "{OUT_A}/itoa-1.d: {PACKAGE}/src/lib.rs {PACKAGE}/src/udiv128.rs\n\n\
             {OUT_A}/libitoa-1.rmeta: {PACKAGE}/src/lib.rs {PACKAGE}/src/udiv128.rs\n\n\
             {PACKAGE}/src/lib.rs:\n{PACKAGE}/src/udiv128.rs:\n\n\
             # env-dep:CARGO_PKG_VERSION=1.0.15\n# env-dep:SCRUBBED_VAR\n"
        );
        let keyed = |relative: &str| matches!(relative, "src/lib.rs" | "src/udiv128.rs");
        let check = |dep_info: &str| dep_info_closure_violation(&plan, dep_info.as_bytes(), keyed);
        assert_eq!(check(&good), None);
        let escaped = format!("{OUT_A}/libitoa-1.rmeta: {PACKAGE}/src/lib.rs /etc/passwd\n");
        assert!(check(&escaped).is_some());
        let traversal = format!("{OUT_A}/libitoa-1.rmeta: {PACKAGE}/../x/lib.rs\n");
        assert!(check(&traversal).is_some());
        let unkeyed = format!("{OUT_A}/x.d: {PACKAGE}/src/lib.rs\n# env-dep:CARGO_MAKEFLAGS=-j\n");
        assert!(check(&unkeyed).is_some());
        let foreign_target = format!("/tmp/x.rmeta: {PACKAGE}/src/lib.rs\n");
        assert!(check(&foreign_target).is_some());
        // A package file the input manifest does not cover.
        let uncovered = format!("{OUT_A}/libitoa-1.rmeta: {PACKAGE}/src/generated.rs\n");
        assert!(check(&uncovered).is_some());
        // `include_str!("../README.md")` from src/ (seen live in clap_builder)
        // stays inside the package and is keyed once normalized.
        let with_readme =
            |relative: &str| matches!(relative, "src/lib.rs" | "src/udiv128.rs" | "README.md");
        let readme =
            format!("{OUT_A}/libitoa-1.rmeta: {PACKAGE}/src/lib.rs {PACKAGE}/src/../README.md\n");
        assert_eq!(
            dep_info_closure_violation(&plan, readme.as_bytes(), with_readme),
            None
        );
        assert!(check(&readme).is_some(), "README.md must be a keyed input");
        let climbing = format!("{OUT_A}/x.rmeta: /../../etc/passwd\n");
        assert!(check(&climbing).is_some());
        assert_eq!(
            lexically_normalized("/a/b/../c/./d"),
            Some("/a/c/d".to_owned())
        );
        assert_eq!(lexically_normalized("/.."), None);
    }
}
