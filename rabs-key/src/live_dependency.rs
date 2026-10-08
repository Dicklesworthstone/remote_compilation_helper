//! Live registry and Git dependency action keys (bd-14t4j / bd-k52xe): the first
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
//! - rustc invoked by Cargo for a registry package at
//!   `<cargo-home>/registry/src/<index>/<package>` or a Git dependency at
//!   `<cargo-home>/git/checkouts/<repository>/<revision>[/<member>]`;
//!   rustc's working directory is `CARGO_MANIFEST_DIR`, `--cap-lints allow`
//!   is present and `CARGO_PRIMARY_PACKAGE` is absent;
//! - build scripts themselves still run normally; a compiler may consume
//!   their complete, separately captured `OUT_DIR` tree. Its exact path and
//!   environment value remain semantic inputs, never placement aliases;
//!   Cargo's completed run record is bound to that tree and keyed too;
//!   rustc-env directives outside the keyed environment refuse serving;
//! - `lib`/`rlib` outputs only, through the bounded
//!   [`derive_dependency_output_declarations`] adapter (Cargo's detached
//!   metadata mode is modeled; other unstable output controls, incremental
//!   state and explicit emit paths are refused; Linux targets);
//! - every dependency artifact is a `.rmeta`/`.rlib` inside a completely
//!   enumerated dependency directory; proc-macro consumption is refused because
//!   untracked proc-macro reads cannot be proven closed (plan §33.10);
//! - no native link inputs (`-l`) and no search path other than
//!   explicit `-L dependency=<directory>`;
//! - JSON diagnostics (`--error-format=json`), so the transcript is
//!   Cargo's machine protocol and can be canonicalized exactly.
//!
//! ## Exactness rules
//!
//! - **Source:** the COMPLETE registry package or Git checkout tree is the
//!   positive input set. Git workspace members can read sibling files in
//!   that checkout. Git metadata is excluded, and reading it prevents
//!   publication. Captured bytes, including dirty and untracked files,
//!   define identity; a revision directory name never proves cleanliness.
//!   A file added anywhere in the source tree changes the key, so the
//!   negative-dependency component binds complete enumeration. Reads
//!   outside that tree are caught after execution by
//!   [`dep_info_closure_violation`] and the result is not published.
//! - **Placement virtualization:** `--out-dir` is rewritten to
//!   [`CANONICAL_OUT_DIR`]; ordered dependency search directories and
//!   `--extern` paths use distinct canonical roots before keying. rustc does not embed the out-dir
//!   in `.rlib`/`.rmeta` bytes (pinned by a real-rustc test); dep-info and
//!   the JSON artifact notifications do mention it, and are canonicalized
//!   by [`canonicalize_out_dir`] / rendered back by [`render_out_dir`].
//!   Dependency-root mentions in diagnostics are refused instead of rewritten.
//!   Every other path (source, cwd, `--remap-path-prefix`, `--sysroot`)
//!   is keyed as given — local-host serving only (`SubscriberPathPreserving`).
//! - **Dependencies:** the exact bytes of every `--extern` artifact
//!   (plan §17.7's conservative default), bound to their crate names.
//!   Every Rust artifact candidate in every dependency search directory is
//!   also keyed, including transitive candidates and negative membership.
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

/// Key epoch of the live dependency class. Epoch 2 requires acknowledged
/// immutable output capture before publication; earlier entries are not reused.
pub const LIVE_DEPENDENCY_KEY_EPOCH: u32 = 2;
/// Projection epoch: exact (unprojected) dependency artifacts.
pub const LIVE_DEPENDENCY_PROJECTION_EPOCH: u32 = 1;
/// Canonical spelling of the invocation's out-dir in keys, committed
/// dep-info and committed transcripts.
pub const CANONICAL_OUT_DIR: &str = "/__rabs/out";
/// Canonical parent of the source root in input-manifest virtual paths.
pub const CANONICAL_PACKAGE_PARENT: &str = "/__rabs/repos";

/// Normalized-invocation component domain for this class.
pub const DOMAIN_LIVE_INVOCATION: &str = "rabs.live-dependency.invocation.v1";
/// Working-directory component domain.
pub const DOMAIN_LIVE_CWD: &str = "rabs.live-dependency.cwd.v1";
/// Negative-dependency component domain.
pub const DOMAIN_LIVE_NEGATIVE: &str = "rabs.live-dependency.negative.v1";
/// Dependency-artifact component domain (inputs + name binding).
pub const DOMAIN_LIVE_ARTIFACTS: &str = "rabs.live-dependency.artifacts.v4";
/// Sandbox/isolation policy component domain.
pub const DOMAIN_LIVE_ISOLATION: &str = "rabs.live-dependency.isolation.v1";
/// Execution-semantics component domain.
pub const DOMAIN_LIVE_EXECUTION: &str = "rabs.live-dependency.execution.v1";
/// Target-specification digest domain (built-in triples only).
pub const DOMAIN_LIVE_TARGET_SPEC: &str = "rabs.live-dependency.target-spec.v1";

/// The registry isolation profile. Deliberately plain: it is NOT a
/// sandbox, and the key says so. V2 requires new evidence after closing
/// warm-root symlink and leave-and-reenter dep-info traversal gaps.
pub const ISOLATION_PROFILE: &str = "live-dependency-v5: unsandboxed local edge process; \
     environment constructed by dependency-env-v1 (allowlisted names keyed, jobserver \
     passthrough unkeyed, all other names absent); source = complete registry package \
     tree with a real directory root revalidated on every observation; closure enforced \
     after execution by dep-info traversal bounded to the observed source root; proc-macro \
     consumption refused; generated compiler inputs captured as a complete disjoint \
     regular-file OUT_DIR tree, with exact OUT_DIR spelling keyed and generation revalidated; \
     build-script execution is not cached; exact crate-locator candidates of every \
     dependency directory (lib-prefixed rlib/rmeta, metadata-shadowed rlibs excluded, \
     other lib-prefixed kinds refused) revalidated before serving and after execution";

/// Git checkout capture includes all source members, including dirty and
/// untracked files, but never authorizes reads of Git metadata.
pub const GIT_ISOLATION_PROFILE: &str = "live-git-dependency-v4: unsandboxed local edge process; \
     environment constructed by dependency-env-v1 (allowlisted names keyed, jobserver \
     passthrough unkeyed, all other names absent); source = complete Cargo Git checkout \
     tree including dirty and untracked source files, root .git excluded before capture; \
     real directory root revalidated on every observation; closure enforced after execution \
     by dep-info traversal bounded to the observed source root, Git metadata reads refused; \
     proc-macro consumption refused; generated compiler inputs captured as a complete disjoint \
     regular-file OUT_DIR tree, with exact OUT_DIR spelling keyed and generation revalidated; \
     build-script execution is not cached; exact crate-locator candidates of every \
     dependency directory (lib-prefixed rlib/rmeta, metadata-shadowed rlibs excluded, \
     other lib-prefixed kinds refused) revalidated before serving and after execution";

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
    "OUT_DIR",
];

/// Names whose presence takes the request out of this class.
const REFUSED_NAMES: &[&str] = &[
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
    /// `CARGO_MANIFEST_DIR` is not a supported Cargo dependency source.
    NotDependencySource(String),
    /// Not invoked by Cargo as a capped-lint dependency compile.
    NotDependencyCompile(&'static str),
    /// rustc working directory differs from the package root.
    WorkingDirectory(String),
    /// The source file is not inside the package root.
    SourceOutsidePackage(String),
    /// A path cannot be represented exactly in dep-info and JSON.
    UnrepresentablePath(String),
    /// A search path outside the bounded dependency-directory model.
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
            Self::NotDependencySource(_) => "LIVE_DEP_NOT_DEPENDENCY_SOURCE",
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
            | Self::NotDependencySource(detail)
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
    /// A file inside an enumerated dependency directory; its bytes key the action.
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

/// The Cargo-managed source layout and corresponding capture policy.
/// Directory names classify the source; captured bytes establish identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DependencySourceKind {
    /// One complete package below Cargo's registry source directory.
    RegistryPackage,
    /// One complete Git checkout, possibly containing workspace members.
    GitCheckout,
}

impl DependencySourceKind {
    /// Stable spelling used in source evidence and policy bindings.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RegistryPackage => "registry-package",
            Self::GitCheckout => "git-checkout",
        }
    }
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
    /// The compiled package root (`CARGO_MANIFEST_DIR`).
    pub package_root: String,
    /// Capture policy for the Cargo-managed source tree.
    pub source_kind: DependencySourceKind,
    /// Complete source closure: registry package or whole Git checkout.
    pub source_root: String,
    /// Single safe component identifying the source's virtual root.
    pub source_dir_name: String,
    /// Cargo's build-script output tree consumed by this compile, if present.
    /// Its exact spelling is keyed; it is not a placement mapping.
    pub generated_root: Option<String>,
    /// Target triple the outputs are for.
    pub target_triple: String,
    /// Host triple from the toolchain probe.
    pub host_triple: String,
    /// Dependency artifacts in argv order.
    pub externs: Vec<PlannedExtern>,
    /// Unique dependency directories in first-use order (-L, then externs).
    /// Callers must capture all regular Rust artifact candidates in each.
    pub dependency_dirs: Vec<String>,
    /// Derived outputs, relative to the out-dir.
    pub outputs: OutputDeclarationSet,
    /// Keyed environment, sorted by name.
    pub keyed_env: Vec<(String, String)>,
    /// The COMPLETE environment the compiler must execute with, sorted:
    /// the keyed variables plus the unkeyed jobserver passthrough.
    pub execution_env: Vec<(String, String)>,
}

impl DependencyActionPlan {
    /// Real placement roots and their canonical counterparts. Roots are
    /// disjoint, so replacing one can never hide another.
    #[must_use]
    pub fn placement_mappings(&self) -> Vec<(String, String)> {
        let mut mappings = vec![(self.out_dir.clone(), CANONICAL_OUT_DIR.to_owned())];
        for (index, root) in self.dependency_dirs.iter().enumerate() {
            if root != &self.out_dir {
                mappings.push((root.clone(), format!("/__rabs/deps/{index:03}")));
            }
        }
        mappings
    }

    fn virtual_dependency_path(&self, path: &str) -> String {
        for (root, canonical) in self.placement_mappings() {
            if path == root {
                return canonical;
            }
            if let Some(relative) = path.strip_prefix(&format!("{root}/")) {
                return format!("{canonical}/{relative}");
            }
        }
        path.to_owned()
    }

    /// Virtual root of the complete source tree in the input manifest.
    #[must_use]
    pub fn source_virtual_root(&self) -> String {
        format!("{CANONICAL_PACKAGE_PARENT}/{}", self.source_dir_name)
    }

    /// The input-manifest virtual path for a file at `relative` (a `/`
    /// separated path below the source root, including any workspace member).
    #[must_use]
    pub fn input_virtual_path(&self, relative: &str) -> String {
        format!("{}/{relative}", self.source_virtual_root())
    }

    /// Distinct sealed-snapshot root for build-script generated inputs.
    #[must_use]
    pub fn generated_virtual_root(&self) -> String {
        format!(
            "{CANONICAL_PACKAGE_PARENT}/{}-generated",
            self.source_dir_name
        )
    }

    /// Virtual input path of a member of the complete generated tree.
    #[must_use]
    pub fn generated_input_virtual_path(&self, relative: &str) -> String {
        format!("{}/{relative}", self.generated_virtual_root())
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

/// Complete crate-candidate inventory of one dependency search directory:
/// exactly the files rustc's crate locator can open for a library compile.
/// Entries the locator never opens (no `lib` prefix: codegen scratch, temp
/// directories, dep-info, executables) and `.rlib`s shadowed by a non-empty
/// same-stem `.rmeta` are not inputs and are not listed; the edge refuses
/// any other `lib*` entry (dylibs, proc-macros, interfaces, static libs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyDirectoryFact {
    /// Real absolute directory, in the plan's first-use order.
    pub path: String,
    /// Every `.rmeta`/`.rlib` candidate, sorted by absolute path.
    pub artifacts: Vec<ExternFact>,
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

fn git_metadata(relative: &str) -> bool {
    relative.split('/').any(|component| component == ".git")
}

fn dependency_source(
    cargo_home: &str,
    package_root: &str,
) -> Result<(DependencySourceKind, String, String), LiveRefusal> {
    if !plain_path(cargo_home) {
        return Err(LiveRefusal::UnrepresentablePath(cargo_home.to_owned()));
    }
    let registry_src = format!("{cargo_home}/registry/src/");
    if let Some((index, package)) = package_root
        .strip_prefix(&registry_src)
        .and_then(|rest| rest.split_once('/'))
        .filter(|(index, package)| safe_component(index) && safe_component(package))
    {
        let _ = index;
        return Ok((
            DependencySourceKind::RegistryPackage,
            package_root.to_owned(),
            package.to_owned(),
        ));
    }
    let checkouts = format!("{cargo_home}/git/checkouts/");
    if let Some(relative) = package_root.strip_prefix(&checkouts) {
        let mut components = relative.split('/');
        if let (Some(repository), Some(revision)) = (components.next(), components.next())
            && safe_component(repository)
            // Cargo uses an abbreviated commit directory. Permit longer
            // hex names too; no revision name is trusted as source identity.
            && (7..=64).contains(&revision.len())
            && revision.bytes().all(|byte| byte.is_ascii_hexdigit())
            && components.all(safe_component)
            && !git_metadata(relative)
        {
            return Ok((
                DependencySourceKind::GitCheckout,
                format!("{checkouts}{repository}/{revision}"),
                format!("git-{repository}-{revision}"),
            ));
        }
    }
    Err(LiveRefusal::NotDependencySource(package_root.to_owned()))
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
    let (source_kind, source_root, source_dir_name) =
        dependency_source(&cargo_home, &package_root)?;

    if request.cwd != package_root {
        return Err(LiveRefusal::WorkingDirectory(request.cwd.to_owned()));
    }

    let invocation = parse(request.argv, None)
        .map_err(|error| LiveRefusal::Unparseable(format!("{error:?}")))?;
    let outputs = derive_dependency_output_declarations(&invocation, host_triple)
        .map_err(|error| LiveRefusal::Outputs(format!("{error:?}")))?;
    if invocation.cap_lints.as_deref() != Some("allow") {
        return Err(LiveRefusal::NotDependencyCompile(
            "Cargo caps lints for external dependencies; this invocation does not",
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
        || out_dir == source_root
        || within(&out_dir, &source_root)
        || within(&source_root, &out_dir)
    {
        return Err(LiveRefusal::UnrepresentablePath(out_dir));
    }
    let generated_root = env_value(request.env, "OUT_DIR").map(str::to_owned);
    if let Some(root) = &generated_root
        && (!plain_path(root)
            // Dep-info replay substitutes the compiler output placement.
            // It must never rewrite a retained exact generated-input path.
            || root.contains(&out_dir)
            || [source_root.as_str(), out_dir.as_str()]
                .iter()
                .any(|other| root == other || within(root, other) || within(other, root)))
    {
        return Err(LiveRefusal::UnrepresentablePath(root.clone()));
    }
    let mut dependency_dirs = Vec::new();
    let mut add_directory = |path: &str| -> Result<(), LiveRefusal> {
        if !plain_path(path)
            || path == source_root
            || within(path, &source_root)
            || within(&source_root, path)
            || (path != out_dir && (within(path, &out_dir) || within(&out_dir, path)))
            || generated_root
                .as_ref()
                .is_some_and(|root| path == root || within(path, root) || within(root, path))
            || dependency_dirs
                .iter()
                .any(|other: &String| other != path && (within(path, other) || within(other, path)))
        {
            return Err(LiveRefusal::SearchPath(path.to_owned()));
        }
        if !dependency_dirs.iter().any(|other| other == path) {
            if dependency_dirs.len() >= 128 {
                return Err(LiveRefusal::SearchPath(
                    "too many dependency directories".into(),
                ));
            }
            dependency_dirs.push(path.to_owned());
        }
        Ok(())
    };
    for entry in &invocation.lib_search {
        let path = entry
            .strip_prefix("dependency=")
            .ok_or_else(|| LiveRefusal::SearchPath(entry.clone()))?;
        add_directory(path)?;
    }

    let mut externs = Vec::with_capacity(invocation.externs.len());
    for (name, path) in &invocation.externs {
        let Some(path) = path else {
            externs.push(PlannedExtern::Toolchain { name: name.clone() });
            continue;
        };
        let (directory, file) = path
            .rsplit_once('/')
            .filter(|(_, file)| safe_component(file))
            .ok_or_else(|| LiveRefusal::Extern(path.clone()))?;
        add_directory(directory)?;
        if directory == out_dir
            && outputs
                .declarations
                .iter()
                .any(|output| output.virtual_path == file)
        {
            return Err(LiveRefusal::Extern(
                "dependency aliases a declared output".into(),
            ));
        }
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
        source_kind,
        source_root,
        source_dir_name,
        generated_root,
        target_triple,
        host_triple: host_triple.to_owned(),
        externs,
        dependency_dirs,
        outputs,
        keyed_env,
        execution_env,
    })
}

/// The normalized-invocation component: out-dir placement virtualized,
/// every other path kept, presentation flags bound (an exact transcript
/// is only replayable under the presentation that produced it).
fn invocation_component(plan: &DependencyActionPlan) -> TypedDigest {
    let mut virtual_invocation = plan.invocation.clone();
    virtual_invocation.out_dir = Some(CANONICAL_OUT_DIR.to_owned());
    for entry in &mut virtual_invocation.lib_search {
        let root = entry
            .strip_prefix("dependency=")
            .expect("planned dependency search");
        *entry = format!("dependency={}", plan.virtual_dependency_path(root));
    }
    for (_, path) in &mut virtual_invocation.externs {
        if let Some(path) = path {
            *path = plan.virtual_dependency_path(path);
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
    directories: &[DependencyDirectoryFact],
) -> Result<TypedDigest, LiveRefusal> {
    if directories.len() != plan.dependency_dirs.len() {
        return Err(LiveRefusal::Facts(
            "dependency directory inventory is incomplete".into(),
        ));
    }
    let mut candidates = CanonicalEncoder::new();
    candidates
        .str("exact-crate-locator-candidates-v2")
        .u64(directories.len() as u64);
    for (root, directory) in plan.dependency_dirs.iter().zip(directories) {
        if &directory.path != root {
            return Err(LiveRefusal::Facts(
                "dependency directories are reordered or missing".into(),
            ));
        }
        candidates.str(&plan.virtual_dependency_path(root));
        let prefix = format!("{root}/");
        let mut previous = None;
        candidates.u64(directory.artifacts.len() as u64);
        for artifact in &directory.artifacts {
            let name = artifact
                .path
                .strip_prefix(&prefix)
                .filter(|name| {
                    safe_component(name)
                        && name.starts_with("lib")
                        && (name.ends_with(".rlib") || name.ends_with(".rmeta"))
                })
                .ok_or_else(|| LiveRefusal::Facts("invalid Rust dependency candidate".into()))?;
            if previous.is_some_and(|old: &str| old >= name)
                || (root == &plan.out_dir
                    && plan.output_names().iter().any(|output| output == name))
            {
                return Err(LiveRefusal::Facts(
                    "duplicate, unsorted, or output-alias candidate".into(),
                ));
            }
            previous = Some(name);
            candidates
                .str(name)
                .str(artifact.content_digest.domain)
                .bytes(&artifact.content_digest.bytes);
        }
    }
    for fact in facts {
        if !directories
            .iter()
            .flat_map(|directory| &directory.artifacts)
            .any(|candidate| candidate == fact)
        {
            return Err(LiveRefusal::Facts(
                "extern not covered by the exact candidate inventory".into(),
            ));
        }
    }
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
        .bytes(&names.bytes)
        .bytes(&candidates.finish());
    Ok(compute(DOMAIN_LIVE_ARTIFACTS, &enc.finish()))
}

/// Normalizer identity for dynamic-library search paths: when Cargo puts
/// the invocation's out-dir in `LD_LIBRARY_PATH`, that entry is virtualized
/// as output placement. Every other entry remains exact; a tracked read of
/// the normalized variable prevents publication.
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
/// file, complete candidate directory inventories, and the complete source input manifest (virtual paths from
/// [`DependencyActionPlan::input_virtual_path`]).
///
/// # Errors
/// [`LiveRefusal::Facts`] when the facts do not exactly cover the plan.
pub fn live_dependency_key(
    plan: &DependencyActionPlan,
    toolchain: &ToolchainFacts,
    externs: &[ExternFact],
    directories: &[DependencyDirectoryFact],
    build_script_output: Option<&[u8]>,
    inputs: &ActionInputManifest,
) -> Result<LiveDependencyKey, LiveRefusal> {
    if toolchain.host_triple() != Some(plan.host_triple.as_str()) {
        return Err(LiveRefusal::Facts(
            "toolchain probe host differs from the planned host".into(),
        ));
    }
    validate_build_script_output(plan, build_script_output)?;
    let root = format!("{}/", plan.source_virtual_root());
    let generated = format!("{}/", plan.generated_virtual_root());
    if inputs.inputs.is_empty()
        || !inputs.directory_enumerations.is_empty()
        || !inputs.approved_generated_objects.is_empty()
        || inputs.inputs.iter().any(|input| {
            input.file_type != InputFileType::Regular
                || !input.symlink_resolution.is_empty()
                || !(input.virtual_path.as_bytes().starts_with(root.as_bytes())
                    || (plan.generated_root.is_some()
                        && input
                            .virtual_path
                            .as_bytes()
                            .starts_with(generated.as_bytes())))
                || (input.virtual_path.as_bytes().starts_with(root.as_bytes())
                    && plan.source_kind == DependencySourceKind::GitCheckout
                    && input.virtual_path.as_bytes()[root.len()..]
                        .split(|byte| *byte == b'/')
                        .any(|component| component == b".git"))
        })
    {
        return Err(LiveRefusal::Facts(
            "the input manifest must cover only the complete regular-file source and generated trees without Git metadata"
                .into(),
        ));
    }
    let source_relative = plan
        .invocation
        .source
        .as_ref()
        .and_then(|source| match source {
            SourceInput::Path(path) => path.strip_prefix(&format!("{}/", plan.source_root)),
            SourceInput::Stdin(_) => None,
        })
        .map(|relative| plan.input_virtual_path(relative))
        .ok_or_else(|| LiveRefusal::Facts("source path left the source tree".into()))?;
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
        match plan.source_kind {
            DependencySourceKind::RegistryPackage => {
                enc.str("complete-package-tree-enumeration-v1")
                    .str(&plan.source_virtual_root());
            }
            DependencySourceKind::GitCheckout => {
                enc.str("complete-git-checkout-tree-enumeration-v1")
                    .str(plan.source_kind.as_str())
                    .str(&plan.source_root)
                    .str(&plan.source_virtual_root());
            }
        }
        if let Some(generated_root) = &plan.generated_root {
            enc.str("complete-generated-input-tree-enumeration-v1")
                .str(generated_root)
                .str(&plan.generated_virtual_root());
        }
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
        unstable_feature_profile: plan
            .invocation
            .unstable
            .iter()
            .map(|(name, value)| match value {
                Some(value) => format!("{name}={value}"),
                None => name.clone(),
            })
            .collect(),
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
        dependency_inputs: {
            let artifacts = artifacts_component(plan, externs, directories)?;
            let mut encoder = CanonicalEncoder::new();
            encoder.str(artifacts.domain).bytes(&artifacts.bytes);
            if let Some(output) = build_script_output {
                encoder
                    .str("exact-cargo-build-script-output-v1")
                    .bytes(output);
            }
            compute(DOMAIN_LIVE_ARTIFACTS, &encoder.finish())
        },
        toolchain: toolchain_contract.dataset_digest(),
        output_platform: output_platform_component(plan),
        environment: environment_component(plan)?,
        sandbox_semantic_policy: compute(
            DOMAIN_LIVE_ISOLATION,
            match plan.source_kind {
                DependencySourceKind::RegistryPackage => ISOLATION_PROFILE,
                DependencySourceKind::GitCheckout => GIT_ISOLATION_PROFILE,
            }
            .as_bytes(),
        ),
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

/// Cargo's persisted build-script stdout is a required eligibility witness
/// for generated-input compiles. In particular, an arbitrary rustc-env
/// directive must not be silently scrubbed by dependency-env-v1.
fn validate_build_script_output(
    plan: &DependencyActionPlan,
    output: Option<&[u8]>,
) -> Result<(), LiveRefusal> {
    let Some(root) = &plan.generated_root else {
        return if output.is_none() {
            Ok(())
        } else {
            Err(LiveRefusal::Facts(
                "unexpected build-script output record".into(),
            ))
        };
    };
    let output = output.ok_or_else(|| {
        LiveRefusal::Facts(format!("missing build-script output record for {root}"))
    })?;
    if output.len() > 1024 * 1024 {
        return Err(LiveRefusal::Facts(
            "build-script output record exceeds limit".into(),
        ));
    }
    let text = std::str::from_utf8(output)
        .map_err(|_| LiveRefusal::Facts("non-UTF-8 build-script output record".into()))?;
    for line in text.lines() {
        let capture = crate::build_script_directives::capture_stdout(line.trim());
        for captured in capture.lines {
            if let Some(crate::build_script_directives::Directive::Rustc { kind, value }) =
                captured.directive
                && kind == "env"
            {
                let Some((name, value)) = value.split_once('=') else {
                    return Err(LiveRefusal::Facts("malformed rustc-env directive".into()));
                };
                if !plan
                    .keyed_env
                    .iter()
                    .any(|(keyed, presented)| keyed == name && presented == value)
                {
                    return Err(LiveRefusal::RefusedEnv(name.to_owned()));
                }
            } else if line.contains("rustc-env") {
                return Err(LiveRefusal::Facts(
                    "unmodeled rustc-env output record".into(),
                ));
            }
        }
    }
    Ok(())
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

/// Canonicalize output placement in replayable dep-info or diagnostics.
/// Dependency directory strings are refused: an arbitrary diagnostic may
/// quote a source-authored literal, so replacing those strings is not sound.
///
/// # Errors
/// Canonical markers and observable dependency placement are refused.
pub fn canonicalize_placements(
    raw: &[u8],
    plan: &DependencyActionPlan,
) -> Result<Vec<u8>, &'static str> {
    for root in &plan.dependency_dirs {
        if root != &plan.out_dir && contains(raw, root.as_bytes()) {
            return Err("observable dependency directory placement cannot be replayed");
        }
    }
    canonicalize_out_dir(raw, &plan.out_dir)
}

/// Render the output placement admitted by [`canonicalize_placements`].
#[must_use]
pub fn render_placements(canonical: &[u8], plan: &DependencyActionPlan) -> Vec<u8> {
    render_out_dir(canonical, &plan.out_dir)
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

/// Resolve `.` and `..` below an observed root without leaving it, even
/// temporarily. Only this tree is known to be symlink-free; normalizing a
/// traversal through an unobserved parent and back into it would be unsound.
fn normalized_within(absolute: &str, root: &str) -> Option<String> {
    let relative = absolute.strip_prefix(root)?.strip_prefix('/')?;
    let mut parts: Vec<&str> = Vec::new();
    for part in relative.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            other => parts.push(other),
        }
    }
    (!parts.is_empty()).then(|| format!("{root}/{}", parts.join("/")))
}

/// Post-execution closure enforcement from rustc's own dep-info: every
/// rule target must be inside the out-dir, every source dependency inside
/// the source root, and every tracked environment read (`# env-dep:`)
/// must name a variable the key covers (keyed) or one the constructed
/// environment removed. `is_input` answers whether a virtual input path
/// is a member of the keyed input manifest: a read of a source or generated file
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
                if name == "LD_LIBRARY_PATH"
                    && plan.keyed_env.iter().any(|(name, value)| {
                        name == "LD_LIBRARY_PATH"
                            && value.split(':').any(|entry| entry == plan.out_dir)
                    })
                {
                    return Some("tracked read of placement-normalized LD_LIBRARY_PATH".into());
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
            if plan.source_kind == DependencySourceKind::GitCheckout && git_metadata(&absolute) {
                return Some(format!(
                    "dep-info target traverses excluded Git metadata: {target}"
                ));
            }
            if normalized_within(&absolute, &plan.out_dir).is_none() {
                // rustc also emits phony `src: ` rules for every input.
                let Some(virtual_path) =
                    observed_input_virtual_path(plan, &absolute).filter(|_| deps.trim().is_empty())
                else {
                    return Some(format!("dep-info target outside the closure: {target}"));
                };
                if !is_input(&virtual_path) {
                    return Some(format!(
                        "dep-info target is an unkeyed source file: {target}"
                    ));
                }
            }
        }
        for dep in deps.split_whitespace() {
            let absolute = if dep.starts_with('/') {
                dep.to_owned()
            } else {
                format!("{}/{dep}", plan.cwd)
            };
            // The pruned .git entry may itself be a symlink. Never erase
            // such a traversal with lexical `..` normalization: its real
            // filesystem resolution need not remain in the source tree.
            if plan.source_kind == DependencySourceKind::GitCheckout && git_metadata(&absolute) {
                return Some(format!("read traverses excluded Git metadata: {dep}"));
            }
            // rustc reports `include_str!("../README.md")` from `src/` as
            // `src/../README.md`. The keyed source tree is symlink-free
            // (capture refuses links), so lexical normalization is exact.
            let Some(virtual_path) = observed_input_virtual_path(plan, &absolute) else {
                return Some(format!(
                    "read outside the source and generated trees: {dep}"
                ));
            };
            if !is_input(&virtual_path) {
                return Some(format!("read of an unkeyed source file: {dep}"));
            }
        }
    }
    None
}

fn observed_input_virtual_path(plan: &DependencyActionPlan, absolute: &str) -> Option<String> {
    if let Some(normalized) = normalized_within(absolute, &plan.source_root) {
        let relative = &normalized[plan.source_root.len() + 1..];
        if plan.source_kind == DependencySourceKind::GitCheckout && git_metadata(relative) {
            return None;
        }
        return Some(plan.input_virtual_path(relative));
    }
    let root = plan.generated_root.as_ref()?;
    let normalized = normalized_within(absolute, root)?;
    Some(plan.generated_input_virtual_path(&normalized[root.len() + 1..]))
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

    fn directory_facts(
        plan: &DependencyActionPlan,
        externs: &[ExternFact],
    ) -> Vec<DependencyDirectoryFact> {
        plan.dependency_dirs
            .iter()
            .map(|root| {
                let mut artifacts: Vec<_> = externs
                    .iter()
                    .filter(|fact| {
                        fact.path
                            .rsplit_once('/')
                            .is_some_and(|(parent, _)| parent == root)
                    })
                    .cloned()
                    .collect();
                artifacts.sort_by(|a, b| a.path.cmp(&b.path));
                DependencyDirectoryFact {
                    path: root.clone(),
                    artifacts,
                }
            })
            .collect()
    }

    fn live_dependency_key(
        plan: &DependencyActionPlan,
        toolchain: &ToolchainFacts,
        externs: &[ExternFact],
        inputs: &ActionInputManifest,
    ) -> Result<LiveDependencyKey, LiveRefusal> {
        super::live_dependency_key(
            plan,
            toolchain,
            externs,
            &directory_facts(plan, externs),
            plan.generated_root.as_ref().map(|_| b"".as_slice()),
            inputs,
        )
    }

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

    const GIT_ROOT: &str = "/home/agent/.cargo/git/checkouts/itoa-f00dcafe/0123456";
    const GIT_PACKAGE: &str = "/home/agent/.cargo/git/checkouts/itoa-f00dcafe/0123456/crates/itoa";

    fn plan_in_package(
        package: &str,
        out_dir: &str,
        extra_env: &[(&str, &str)],
    ) -> Result<DependencyActionPlan, LiveRefusal> {
        let argv = argv(out_dir, &[])
            .into_iter()
            .map(|arg| arg.replace(PACKAGE, package))
            .collect::<Vec<_>>();
        let mut env = env(extra_env);
        env.iter_mut()
            .find(|(name, _)| name == "CARGO_MANIFEST_DIR")
            .unwrap()
            .1 = package.to_owned();
        plan_dependency_action(
            LiveRustcRequest {
                argv: &argv,
                cwd: package,
                env: &env,
            },
            "x86_64-unknown-linux-gnu",
        )
    }

    fn git_inputs(plan: &DependencyActionPlan) -> ActionInputManifest {
        let mut inputs = inputs(plan, 11);
        inputs.inputs[1].virtual_path = RawBytes::new(
            plan.input_virtual_path("crates/itoa/src/lib.rs")
                .into_bytes(),
        );
        inputs.inputs.push(PositiveInput {
            virtual_path: RawBytes::new(plan.input_virtual_path("shared/value.txt").into_bytes()),
            object: ObjectId(digest(12)),
            file_type: InputFileType::Regular,
            executable: false,
            symlink_resolution: Vec::new(),
        });
        inputs
    }

    #[test]
    fn cargo_git_members_use_the_complete_checkout_source_root() {
        let plan = plan_in_package(GIT_PACKAGE, OUT_A, &[]).unwrap();
        assert_eq!(plan.source_kind, DependencySourceKind::GitCheckout);
        assert_eq!(plan.source_root, GIT_ROOT);
        assert_eq!(plan.package_root, GIT_PACKAGE);
        assert_eq!(plan.cwd, GIT_PACKAGE);
        assert_eq!(
            plan.source_virtual_root(),
            "/__rabs/repos/git-itoa-f00dcafe-0123456"
        );
        assert_eq!(
            plan_in_package(GIT_ROOT, OUT_A, &[]).unwrap().source_root,
            GIT_ROOT
        );
        let custom_root = "/opt/cargo/git/checkouts/itoa-f00dcafe/0123456789abcdef";
        assert_eq!(
            plan_in_package(custom_root, OUT_A, &[("CARGO_HOME", "/opt/cargo/")])
                .unwrap()
                .source_root,
            custom_root
        );
        let registry = plan_for(OUT_A, &[], &[]).unwrap();
        assert_eq!(registry.source_kind, DependencySourceKind::RegistryPackage);
        assert_eq!(registry.source_root, PACKAGE);
        assert_eq!(registry.source_virtual_root(), "/__rabs/repos/itoa-1.0.15");
        // Registry enumeration retains its component. The stronger source
        // closure must require new evidence instead of serving a historical
        // result that passed the older root/traversal checks.
        let keyed = live_dependency_key(
            &registry,
            &toolchain(),
            &externs(&registry, 20),
            &inputs(&registry, 11),
        )
        .unwrap();
        let mut negative = CanonicalEncoder::new();
        negative
            .str("complete-package-tree-enumeration-v1")
            .str(&registry.source_virtual_root());
        assert_eq!(
            keyed.descriptor.negative_dependencies,
            compute(DOMAIN_LIVE_NEGATIVE, &negative.finish())
        );
        assert_eq!(
            keyed.descriptor.sandbox_semantic_policy,
            compute(DOMAIN_LIVE_ISOLATION, ISOLATION_PROFILE.as_bytes())
        );
        let legacy = "live-dependency-v1: unsandboxed local edge process; \
            environment constructed by dependency-env-v1 (allowlisted names keyed, jobserver \
            passthrough unkeyed, all other names absent); source = complete registry package \
            tree; closure enforced after execution by dep-info containment; proc-macro \
            consumption and build-script outputs refused";
        assert_ne!(
            keyed.descriptor.sandbox_semantic_policy,
            compute(DOMAIN_LIVE_ISOLATION, legacy.as_bytes())
        );
    }

    #[test]
    fn cargo_git_layout_and_whole_checkout_output_overlap_are_bounded() {
        for package in [
            "/home/agent/.cargo/git/checkouts/itoa-f00dcafe",
            "/home/agent/.cargo/git/checkouts/itoa-f00dcafe/main/crates/itoa",
            "/home/agent/.cargo/git/checkouts/itoa-f00dcafe/012345",
            "/home/agent/.cargo/git/checkouts/itoa-f00dcafe/0123456/.git/objects",
            "/home/agent/.cargo/git/checkouts/itoa-f00dcafe/0123456/../other",
            "/home/agent/.cargo/git/db/itoa-f00dcafe/0123456",
            "/work/local-dependency",
        ] {
            assert!(plan_in_package(package, OUT_A, &[]).is_err(), "{package}");
        }
        for out in [
            GIT_ROOT.to_owned(),
            format!("{GIT_ROOT}/target/debug/deps"),
            format!("{GIT_ROOT}/other-member/target/deps"),
            "/home/agent/.cargo/git/checkouts".to_owned(),
        ] {
            assert_eq!(
                plan_in_package(GIT_PACKAGE, &out, &[]).unwrap_err().code(),
                "LIVE_DEP_PATH",
                "source/output overlap: {out}"
            );
        }
    }

    #[test]
    fn git_sibling_content_and_added_files_key_but_output_placement_does_not() {
        let a = plan_in_package(GIT_PACKAGE, OUT_A, &[]).unwrap();
        let b = plan_in_package(GIT_PACKAGE, OUT_B, &[]).unwrap();
        let keyed = |plan: &DependencyActionPlan, inputs: &ActionInputManifest| {
            live_dependency_key(plan, &toolchain(), &externs(plan, 20), inputs).unwrap()
        };
        let original = git_inputs(&a);
        let base = keyed(&a, &original);
        assert_eq!(base.action_key, keyed(&b, &git_inputs(&b)).action_key);
        assert_eq!(
            base.descriptor.sandbox_semantic_policy,
            compute(DOMAIN_LIVE_ISOLATION, GIT_ISOLATION_PROFILE.as_bytes())
        );
        let mut dirty = original.clone();
        dirty.inputs[2].object = ObjectId(digest(13));
        assert_ne!(base.action_key, keyed(&a, &dirty).action_key);
        let mut added = original.clone();
        let mut new_file = added.inputs[2].clone();
        new_file.virtual_path = RawBytes::new(a.input_virtual_path("untracked.txt").into_bytes());
        added.inputs.push(new_file);
        assert_ne!(base.action_key, keyed(&a, &added).action_key);
        for metadata in [".git/config", "crates/.git/HEAD"] {
            let mut forbidden = original.clone();
            forbidden.inputs[0].virtual_path =
                RawBytes::new(a.input_virtual_path(metadata).into_bytes());
            assert!(
                live_dependency_key(&a, &toolchain(), &externs(&a, 20), &forbidden).is_err(),
                "Git metadata must never become a keyed source input: {metadata}"
            );
        }
    }

    #[test]
    fn git_dep_info_allows_keyed_siblings_but_never_git_metadata() {
        let plan = plan_in_package(GIT_PACKAGE, OUT_A, &[]).unwrap();
        let keyed = |path: &str| {
            ["crates/itoa/src/lib.rs", "shared/value.txt"]
                .iter()
                .any(|relative| path == plan.input_virtual_path(relative))
        };
        let sibling = format!("{GIT_PACKAGE}/src/../../../shared/value.txt");
        let good = format!("{OUT_A}/itoa.d: {GIT_PACKAGE}/src/lib.rs {sibling}\n\n{sibling}:\n");
        assert_eq!(
            dep_info_closure_violation(&plan, good.as_bytes(), keyed),
            None
        );
        for read in [
            format!("{GIT_ROOT}/../other-checkout/shared/value.txt"),
            format!("{GIT_ROOT}/untracked-after-capture.txt"),
            format!("{GIT_PACKAGE}/src/../../../.git/config"),
        ] {
            let dep_info = format!("{OUT_A}/itoa.d: {read}\n");
            assert!(dep_info_closure_violation(&plan, dep_info.as_bytes(), keyed).is_some());
        }
        // Even a faulty caller cannot authorize metadata reads or phony
        // rules by claiming that the path was captured.
        for dep_info in [
            format!("{OUT_A}/itoa.d: {GIT_ROOT}/.git/HEAD\n"),
            format!("{OUT_A}/itoa.d: {GIT_ROOT}/.git/../shared/value.txt\n"),
            format!("{GIT_ROOT}/.git/../shared/value.txt:\n"),
            format!("{OUT_A}/itoa.d: {GIT_ROOT}/../0123456/shared/value.txt\n"),
            format!("{GIT_ROOT}/../0123456/shared/value.txt:\n"),
            format!("{GIT_PACKAGE}/src/../../../.git/HEAD:\n"),
            format!("{OUT_A}/../../../outside.rmeta: {GIT_PACKAGE}/src/lib.rs\n"),
        ] {
            assert!(dep_info_closure_violation(&plan, dep_info.as_bytes(), |_| true).is_some());
        }
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
    fn cargo_detached_metadata_mode_is_bound_to_the_invocation_and_toolchain() {
        let embedded = plan_for(OUT_A, &[], &[]).unwrap();
        let detached = plan_for(OUT_A, &["-Z", "embed-metadata=no"], &[]).unwrap();
        let relocated = plan_for(OUT_B, &["-Zembed-metadata=no"], &[]).unwrap();
        let keyed = |plan: &DependencyActionPlan| {
            live_dependency_key(plan, &toolchain(), &externs(plan, 20), &inputs(plan, 11)).unwrap()
        };
        assert_eq!(embedded.output_names(), detached.output_names());
        let embedded = keyed(&embedded);
        let detached = keyed(&detached);
        assert_ne!(embedded.action_key, detached.action_key);
        assert_ne!(
            embedded.descriptor.normalized_invocation,
            detached.descriptor.normalized_invocation
        );
        assert_ne!(embedded.descriptor.toolchain, detached.descriptor.toolchain);
        assert_eq!(detached.action_key, keyed(&relocated).action_key);
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
    fn generated_inputs_key_exact_out_dir_and_content_and_close_observed_reads() {
        let generated = "/work/build/generated";
        let plan = plan_for(OUT_A, &[], &[("OUT_DIR", generated)]).unwrap();
        assert_eq!(plan.generated_root.as_deref(), Some(generated));
        assert!(
            plan.execution_env
                .contains(&("OUT_DIR".into(), generated.into()))
        );
        assert!(
            plan.keyed_env
                .contains(&("OUT_DIR".into(), generated.into()))
        );
        let mut manifest = inputs(&plan, 11);
        manifest.inputs.push(PositiveInput {
            virtual_path: RawBytes::new(plan.generated_input_virtual_path("value.rs").into_bytes()),
            object: ObjectId(digest(42)),
            file_type: InputFileType::Regular,
            executable: false,
            symlink_resolution: Vec::new(),
        });
        let keyed = |plan: &DependencyActionPlan, manifest: &ActionInputManifest| {
            live_dependency_key(plan, &toolchain(), &externs(plan, 20), manifest)
                .unwrap()
                .action_key
        };
        let original = keyed(&plan, &manifest);
        let other_output = plan_for(OUT_B, &[], &[("OUT_DIR", generated)]).unwrap();
        assert_eq!(original, keyed(&other_output, &manifest));
        let other_generated =
            plan_for(OUT_A, &[], &[("OUT_DIR", "/work/other/generated")]).unwrap();
        assert_ne!(original, keyed(&other_generated, &manifest));
        manifest.inputs.last_mut().unwrap().object = ObjectId(digest(43));
        assert_ne!(original, keyed(&plan, &manifest));
        let covered = |path: &str| {
            manifest
                .inputs
                .iter()
                .any(|input| input.virtual_path.as_bytes() == path.as_bytes())
        };
        let good = format!(
            "{OUT_A}/itoa.d: {PACKAGE}/src/lib.rs {generated}/value.rs\n{generated}/value.rs:\n# env-dep:OUT_DIR={generated}\n"
        );
        assert_eq!(
            dep_info_closure_violation(&plan, good.as_bytes(), covered),
            None
        );
        assert_eq!(
            canonicalize_placements(good.as_bytes(), &plan).unwrap(),
            good.replace(OUT_A, CANONICAL_OUT_DIR).into_bytes()
        );
        for path in [
            format!("{generated}/missing.rs"),
            format!("{generated}/../generated/value.rs"),
            "/unobserved/value.rs".into(),
        ] {
            assert!(
                dep_info_closure_violation(
                    &plan,
                    format!("{OUT_A}/itoa.d: {path}\n").as_bytes(),
                    covered
                )
                .is_some()
            );
        }
        let no_generated = plan_for(OUT_A, &[], &[]).unwrap();
        assert!(
            live_dependency_key(
                &no_generated,
                &toolchain(),
                &externs(&no_generated, 20),
                &manifest
            )
            .is_err()
        );
    }

    #[test]
    fn generated_input_run_records_are_required_bound_and_preserve_env_policy() {
        let plan = plan_for(
            OUT_A,
            &[],
            &[
                ("OUT_DIR", "/work/generated"),
                ("RUST_BUILD_VALUE", "present"),
            ],
        )
        .unwrap();
        let keyed = |plan: &DependencyActionPlan, record: Option<&[u8]>| {
            let direct = externs(plan, 20);
            super::live_dependency_key(
                plan,
                &toolchain(),
                &direct,
                &directory_facts(plan, &direct),
                record,
                &inputs(plan, 11),
            )
        };
        assert!(keyed(&plan, None).is_err());
        let a = keyed(&plan, Some(b"cargo::rustc-cfg=a\n")).unwrap();
        let b = keyed(&plan, Some(b"cargo::rustc-cfg=b\n")).unwrap();
        assert_ne!(
            a.action_key, b.action_key,
            "exact run-record bytes must key"
        );
        assert!(keyed(&plan, Some(b"cargo::rustc-env=RUST_BUILD_VALUE=present\n")).is_ok());
        for record in [
            b"cargo:rustc-env=MY_VALUE=example\n".as_slice(),
            b" cargo::rustc-env=MY_VALUE=example \n",
            b"cargo::rustc-env=RUST_BUILD_VALUE=different\n",
            b"cargo::rustc-env=MAKEFLAGS=unkeyed\n",
            b"cargo::rustc-env=malformed\n",
            b"\xff",
        ] {
            assert!(keyed(&plan, Some(record)).is_err());
        }
        let no_generated = plan_for(OUT_A, &[], &[]).unwrap();
        assert!(keyed(&no_generated, Some(b"")).is_err());
    }

    #[test]
    fn generated_input_roots_cannot_overlap_source_outputs_or_dependency_search() {
        for root in [
            PACKAGE.to_owned(),
            format!("{PACKAGE}/generated"),
            OUT_A.to_owned(),
            format!("{OUT_A}/generated"),
            format!("{OUT_A}-generated"),
            "relative/generated".into(),
            "/work/../generated".into(),
        ] {
            assert!(
                plan_for(OUT_A, &[], &[("OUT_DIR", &root)]).is_err(),
                "{root}"
            );
        }
        assert!(
            plan_for(
                OUT_A,
                &["-Ldependency=/generated"],
                &[("OUT_DIR", "/generated")]
            )
            .is_err()
        );
        // The extension is about consuming generated Rust inputs, not
        // executing macros or resolving native library search paths.
        assert!(plan_for(OUT_A, &["-Lnative=/native"], &[("OUT_DIR", "/generated")]).is_err());
        assert!(
            plan_for(
                OUT_A,
                &["--extern=macro=/deps/libmacro.so"],
                &[("OUT_DIR", "/generated")]
            )
            .is_err()
        );
    }

    #[test]
    fn out_of_class_requests_are_typed_refusals() {
        let code = |result: Result<DependencyActionPlan, LiveRefusal>| result.unwrap_err().code();
        assert_eq!(
            code(plan_for(OUT_A, &[], &[("LD_PRELOAD", "/x")])),
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
            "LIVE_DEP_NOT_DEPENDENCY_SOURCE"
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
                &["--extern", "x=/elsewhere/../libx.rlib"],
                &[]
            )),
            "LIVE_DEP_SEARCH_PATH"
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
    fn sibling_dependency_candidates_are_complete_ordered_and_content_bound() {
        let sibling_plan = |base: &str| {
            let mut args = argv(&format!("{base}/middle/out"), &[]);
            for arg in &mut args {
                if arg.starts_with("dependency=") {
                    *arg = format!("dependency={base}/leaf/out");
                }
                if arg.starts_with("dep=") {
                    *arg = format!("dep={base}/leaf/out/libdep-0123456789abcdef.rmeta");
                }
            }
            plan_dependency_action(
                LiveRustcRequest {
                    argv: &args,
                    cwd: PACKAGE,
                    env: &env(&[]),
                },
                "x86_64-unknown-linux-gnu",
            )
            .unwrap()
        };
        let a = sibling_plan("/work/a");
        let b = sibling_plan("/work/b");
        assert_eq!(key(&a), key(&b));
        let direct = externs(&a, 20);
        let facts = directory_facts(&a, &direct);
        let keyed = |facts: &[DependencyDirectoryFact]| {
            super::live_dependency_key(&a, &toolchain(), &direct, facts, None, &inputs(&a, 11))
        };
        assert!(keyed(&[]).is_err());
        let mut added = facts.clone();
        added[0].artifacts.push(ExternFact {
            path: format!("{}/libtransitive.rlib", a.dependency_dirs[0]),
            content_digest: digest(30),
        });
        assert_ne!(keyed(&added).unwrap().action_key, key(&a));
        let original = keyed(&added).unwrap().action_key;
        added[0].artifacts[1].content_digest = digest(31);
        assert_ne!(keyed(&added).unwrap().action_key, original);
        added[0].artifacts.reverse();
        assert!(keyed(&added).is_err());
        let raw = format!("{}: {} {}", a.out_dir, direct[0].path, a.dependency_dirs[0]);
        assert!(canonicalize_placements(raw.as_bytes(), &a).is_err());
        // A warning can quote a string literal authored in source. Its
        // meaning must not be changed to the next subscriber's directory.
        let literal = format!("#[deprecated(note = \"{}\")]", a.dependency_dirs[0]);
        let diagnostic =
            format!("{{\"message\":\"source-authored path\",\"rendered\":{literal:?}}}");
        assert!(canonicalize_placements(diagnostic.as_bytes(), &a).is_err());
        let raw = format!("{}/libmiddle.rlib", a.out_dir);
        let canonical = canonicalize_placements(raw.as_bytes(), &a).unwrap();
        assert_eq!(render_placements(&canonical, &a), raw.as_bytes());
        assert_eq!(
            render_placements(&canonical, &b),
            raw.replace("/work/a", "/work/b").as_bytes()
        );
    }

    #[test]
    fn reading_a_normalized_loader_value_prevents_publication() {
        let plan = plan_for(OUT_A, &[], &[("LD_LIBRARY_PATH", OUT_A)]).unwrap();
        assert!(
            dep_info_closure_violation(
                &plan,
                format!("# env-dep:LD_LIBRARY_PATH={OUT_A}\n").as_bytes(),
                |_| true
            )
            .unwrap()
            .contains("placement-normalized")
        );
        let exact = plan_for(OUT_A, &[], &[("LD_LIBRARY_PATH", "/toolchain/lib")]).unwrap();
        assert_eq!(
            dep_info_closure_violation(
                &exact,
                b"# env-dep:LD_LIBRARY_PATH=/toolchain/lib\n",
                |_| true
            ),
            None
        );
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
        let keyed = |path: &str| {
            ["src/lib.rs", "src/udiv128.rs"]
                .iter()
                .any(|relative| path == plan.input_virtual_path(relative))
        };
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
        let with_readme = |path: &str| keyed(path) || path == plan.input_virtual_path("README.md");
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
            normalized_within("/a/b/../c/./d", "/a"),
            Some("/a/c/d".to_owned())
        );
        assert_eq!(normalized_within("/a/../a/c", "/a"), None);
        assert_eq!(normalized_within("/..", "/a"), None);
    }

    #[test]
    fn acknowledged_capture_has_a_separate_live_key_namespace() {
        for plan in [
            plan_for(OUT_A, &[], &[]).unwrap(),
            plan_in_package(GIT_ROOT, OUT_A, &[]).unwrap(),
        ] {
            let current =
                live_dependency_key(&plan, &toolchain(), &externs(&plan, 20), &inputs(&plan, 11))
                    .unwrap();
            assert_eq!(current.descriptor.key_epoch, 2);
            let mut previous = current.descriptor.clone();
            previous.key_epoch = 1;
            assert_ne!(current.action_key, compute_action_key(&previous).final_key);
            assert_ne!(
                current.descriptor_digest,
                descriptor_digest(&descriptor_canonical_bytes(&previous))
            );
        }
    }
}
