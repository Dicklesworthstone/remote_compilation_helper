//! Live registry, Git and directory-source dependency keys (bd-14t4j / bd-k52xe): the first
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
//! Plan §204's first dependency target. Planning models library invocations;
//! authoritative serving additionally requires
//! [`check_dependency_cache_read_closure`]. The unsandboxed edge currently
//! serves only metadata plus dep-info, because rustc does not report every
//! assembler/codegen input in dep-info:
//!
//! - rustc invoked by Cargo for a registry package at
//!   `<cargo-home>/registry/src/<index>/<package>` or a Git dependency at
//!   `<cargo-home>/git/checkouts/<repository>/<revision>[/<member>]`;
//!   a Cargo directory source outside those caches is admitted separately
//!   through a captured `.cargo-checksum.json` witness, not by a `vendor` name;
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
//!   enumerated dependency directory; proc-macro consumption and dynamic
//!   candidates are refused because even a regular metadata dependency can
//!   reexport a macro with untracked reads (plan §33.10);
//! - no native link inputs (`-l`) and no search path other than
//!   explicit `-L dependency=<directory>`;
//! - JSON diagnostics (`--error-format=json`), so the transcript is
//!   Cargo's machine protocol and can be canonicalized exactly.
//!
//! ## Exactness rules
//!
//! - **Source:** the COMPLETE registry/directory package or Git checkout tree is the
//!   positive input set. Git workspace members can read sibling files in
//!   that checkout. Git metadata is excluded, and reading it prevents
//!   publication. Captured bytes, including dirty and untracked files,
//!   define identity; a revision directory name never proves cleanliness.
//!   A file added anywhere in the source tree changes the key, so the
//!   negative-dependency component binds complete enumeration. Source reads
//!   reported outside that tree are caught after execution by
//!   [`dep_info_closure_violation`] and the result is not published. Dep-info
//!   is not a complete codegen read observer: for example, `global_asm!` can
//!   use `.incbin` without reporting that file. Such invocations may be
//!   planned for discovery, but may not publish or serve in this lane.
//! - **Placement virtualization:** `--out-dir` is rewritten to
//!   [`CANONICAL_OUT_DIR`]; ordered dependency search directories and
//!   `--extern` paths use distinct canonical roots before keying. rustc does not embed the out-dir
//!   in `.rlib`/`.rmeta` bytes (pinned by a real-rustc test); dep-info and
//!   the JSON artifact notifications do mention it, and use separate bounded
//!   [`canonicalize_placements`] / [`canonicalize_compiler_transcript`] adapters.
//!   Dependency-root mentions in diagnostics are refused instead of rewritten.
//!   Every other path (source, cwd, `--remap-path-prefix`, `--sysroot`)
//!   is keyed as given — local-host serving only (`SubscriberPathPreserving`).
//!   The separately prepared canonical Cargo profile already executes at its
//!   stable visible paths. It keys those exact placements and replays bytes
//!   unchanged, with its own isolation identity; ordinary wrapper requests
//!   cannot select that profile through reserved path spelling alone.
//! - **Dependencies:** the exact bytes of every `--extern` artifact
//!   (plan §17.7's conservative default), bound to their crate names.
//!   Every Rust artifact candidate in every dependency search directory is
//!   also keyed, including transitive candidates and negative membership.
//!   With `-Zbinary-dep-depinfo`, every reported binary path must additionally
//!   identify an exact keyed dependency or retained sysroot file. This evidence
//!   does not narrow the candidate inventory or admit procedural macros.
//! - **Environment (`dependency-env-v3`, applied by the edge through
//!   [`DependencyActionPlan::narrow_to_source_env_reads`]; unnarrowed plans
//!   keep `dependency-env-v2`, hashing every non-control value):** preserve
//!   the compiler's complete
//!   environment, but hash only what can matter: names the compiler process
//!   consumes untracked (rustc/rustup controls, loader, libc locale, LLVM,
//!   allocator) and the crate environment Cargo presents, plus every
//!   `env!`/`option_env!` name the package source spells literally
//!   ([`source_env_reads`]), keyed by value or by absence. Everything else —
//!   terminal, multiplexer, SSH and agent-session variables, Cargo's own
//!   configuration such as `CARGO_TARGET_DIR` — is ambient: hashing it made
//!   every agent session mint its own keys, so no two sessions ever shared
//!   a dependency. Only rustc runs in an admitted action (proc-macro
//!   consumption is refused and build-script effects are captured inputs),
//!   so nothing reads ambient names untracked; a TRACKED read the scan did
//!   not key (or of jobserver descriptors, wrapper controls, shell
//!   bookkeeping, host placement or the RCH source stamp) prevents
//!   publication, even when the variable was absent. The executing process
//!   must use [`DependencyActionPlan::execution_env`] verbatim; unknown
//!   variables are never silently removed from a private execution.
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
use crate::output_derivation::{
    derive_dependency_output_declarations, derive_workspace_output_declarations,
};
use crate::output_platform::{CpuBaseline, OutputPlatformContract};
use crate::path_policy::{BuildPathSemanticPolicy, policy_component_digest};
use crate::toolchain::ToolchainContract;
use crate::typed_digest::compute;

pub mod remote;

mod canonical_cargo;
mod metadata_replay;
pub use canonical_cargo::{
    canonical_cargo_dependency_key, plan_canonical_cargo_dependency_action,
    plan_canonical_remote_dependency_action,
};
pub use metadata_replay::metadata_replay_prefix_len;
pub mod workspace_cache;
pub mod workspace_dependency_cache;
mod workspace_execution;
pub use workspace_execution::{
    plan_canonical_workspace_execution, remote_workspace_execution_isolation_policy,
    remote_workspace_execution_key, remote_workspace_execution_shape, workspace_source_path,
};

/// Key epoch of the live dependency class. Epoch 6 requires the complete
/// generated-directory topology, including empty directories, in input evidence.
/// Earlier file-only keys must not serve generated-tree results. Exact artifact
/// transcript rewriting, complete environment keying, dynamic-dependency refusal
/// and acknowledged immutable capture remain required.
pub const LIVE_DEPENDENCY_KEY_EPOCH: u32 = 6;
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
/// Complete environment dataset under the named host-placement/read-veto policy.
/// All live profiles use this domain, including when those names are absent:
/// earlier publications cannot supply evidence for the expanded read veto.
pub const DOMAIN_LIVE_ENVIRONMENT: &str = "rabs.live-dependency.environment.v1";
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
pub const ISOLATION_PROFILE: &str = "live-dependency-v8: unsandboxed local edge process; \
     environment preserved, keyed by dependency-env-v2 (all non-control values hashed) or, \
     when the edge narrows it, dependency-env-v3 (compiler-consumed and Cargo crate names \
     hashed; ambient names hashed by value or absence only when the source names them); \
     jobserver, wrapper controls, shell bookkeeping, RCH source stamp and unkeyed ambient \
     names unkeyed; tracked reads of unkeyed names, including absent reads, refuse publication); source = complete registry package \
     tree with a real directory root revalidated on every observation; closure enforced \
     after execution by dep-info traversal bounded to the observed source root; proc-macro \
     consumption refused; generated compiler inputs captured as a complete disjoint \
     regular-file OUT_DIR tree with every directory and immediate-child listing keyed, \
     including empty directories, with exact OUT_DIR spelling keyed and generation revalidated; \
     build-script execution is not cached; exact crate-locator candidates of every \
     dependency directory (lib-prefixed rlib/rmeta, metadata-shadowed rlibs excluded, \
     dynamic candidates refused because regular dependencies can reexport procedural macros; \
     other lib-prefixed kinds refused) revalidated before serving and after execution";

/// Git checkout capture includes all source members, including dirty and
/// untracked files, but never authorizes reads of Git metadata.
pub const GIT_ISOLATION_PROFILE: &str = "live-git-dependency-v7: unsandboxed local edge process; \
     environment preserved, keyed by dependency-env-v2 (all non-control values hashed) or, \
     when the edge narrows it, dependency-env-v3 (compiler-consumed and Cargo crate names \
     hashed; ambient names hashed by value or absence only when the source names them); \
     jobserver, wrapper controls, shell bookkeeping, RCH source stamp and unkeyed ambient \
     names unkeyed; tracked reads of unkeyed names, including absent reads, refuse publication); source = complete Cargo Git checkout \
     tree including dirty and untracked source files, root .git excluded before capture; \
     real directory root revalidated on every observation; closure enforced after execution \
     by dep-info traversal bounded to the observed source root, Git metadata reads refused; \
     proc-macro consumption refused; generated compiler inputs captured as a complete disjoint \
     regular-file OUT_DIR tree with every directory and immediate-child listing keyed, \
     including empty directories, with exact OUT_DIR spelling keyed and generation revalidated; \
     build-script execution is not cached; exact crate-locator candidates of every \
     dependency directory (lib-prefixed rlib/rmeta, metadata-shadowed rlibs excluded, \
     dynamic candidates refused because regular dependencies can reexport procedural macros; \
     other lib-prefixed kinds refused) revalidated before serving and after execution";

/// Directory sources retain their real paths and complete package contents.
/// The checksum document identifies the source class, never the file closure:
/// even files absent from its `files` map are captured, hashed and revalidated.
pub const DIRECTORY_ISOLATION_PROFILE: &str = "live-directory-dependency-v4: unsandboxed local edge process; \
     environment preserved, keyed by dependency-env-v2 (all non-control values hashed) or, \
     when the edge narrows it, dependency-env-v3 (compiler-consumed and Cargo crate names \
     hashed; ambient names hashed by value or absence only when the source names them); \
     jobserver, wrapper controls, shell bookkeeping, RCH source stamp and unkeyed ambient \
     names unkeyed; tracked reads of unkeyed names, including absent reads, refuse publication); source = complete Cargo directory-source \
     package tree including Cargo.toml and the exact observed .cargo-checksum.json witness; \
     checksum declarations never substitute for captured bytes or exclude unlisted files; \
     real directory root and complete tree revalidated before serving and after execution; \
     symlinks and source-policy exclusions refuse capture; dep-info reads bounded to the \
     source and generated trees; proc-macro consumption and native link inputs refused; \
     dynamic dependency candidates refused because regular dependencies can reexport procedural macros; \
     generated inputs captured as a complete disjoint regular-file OUT_DIR tree with every \
     directory and immediate-child listing keyed, including empty directories, with exact \
     OUT_DIR spelling keyed and generation revalidated; build-script execution is not cached; \
     exact dependency-directory crate candidates revalidated before serving and after execution";

/// What the executed compiler must produce for a publishable result.
pub const EXECUTION_SEMANTICS: &str = "live-dependency-v2: rustc exit status 0 by normal \
     exit, empty stdout, stderr = byte-preserved JSON diagnostics with placement \
     substitution only in declared rustc artifact paths; diagnostics containing \
     output or dependency placement refuse replay; every declared output present";

/// Shell location/process hints are preserved without fragmenting otherwise
/// identical dependency actions. A compiler's tracked read of any of these
/// names, including an absent `option_env!` read, prevents publication.
const SHELL_BOOKKEEPING_NAMES: &[&str] = &["PWD", "OLDPWD", "SHLVL", "_"];

/// RCH's per-job cache/temp directories and the SSH login session change even
/// for identical rustc inputs. Rustc uses TMPDIR only for temporary placement;
/// the other names do not configure it. Preserve exact execution bindings and
/// veto publication on every tracked read, including an absent option_env!.
/// These are exact names, never broad SSH_*, XDG_* or Go/RCH namespaces.
const HOST_PLACEMENT_NAMES: &[&str] = &[
    "GOCACHE",
    "GOMODCACHE",
    "GOPATH",
    "TMPDIR",
    "SSH_CLIENT",
    "SSH_CONNECTION",
    "XDG_SESSION_ID",
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
    /// Codegen can read inputs that rustc's dep-info does not report.
    UnclosedCodegenInputs,
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
            Self::UnclosedCodegenInputs => "LIVE_DEP_CODEGEN_READ_CLOSURE",
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
            Self::UnclosedCodegenInputs => write!(
                f,
                "{}: only metadata and dep-info have serving authority; codegen requires enforced input closure",
                self.code()
            ),
        }
    }
}

/// Restrict live cache authority to the output mode whose reads the current
/// dependency lane can validate. This is a serving gate, not an invocation
/// parser or a source scanner. Keep it separate from planning so discovery
/// and output-conformance probes can still describe ordinary rlib compiles.
///
/// A complete package inventory and repeated matching outputs do not close
/// codegen inputs: assembler `.incbin`, including assembly introduced through
/// macro expansion, can read outside every keyed root without appearing in
/// rustc's dep-info. A codegen result therefore cannot qualify merely by
/// accumulating verification samples. Callers must apply this check before
/// persisted-result lookup and again at execution/publication boundaries.
/// Re-enabling codegen requires a distinct enforced-view policy and key.
///
/// # Errors
/// Returns [`LiveRefusal::UnclosedCodegenInputs`] for implicit link output,
/// explicit link/object/assembly/LLVM outputs, and every emit set other than
/// exactly metadata plus dep-info. Success still requires all normal planning,
/// input observation, dep-info and serving checks.
pub fn check_dependency_cache_read_closure(
    invocation: &NormalizedRustcInvocation,
) -> Result<(), LiveRefusal> {
    if invocation.emit.len() == 2
        && invocation.emit.iter().any(|kind| kind == "metadata")
        && invocation.emit.iter().any(|kind| kind == "dep-info")
    {
        Ok(())
    } else {
        Err(LiveRefusal::UnclosedCodegenInputs)
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
/// Workspace cache V2 profiles qualify the independently isolated compiler
/// action even when other units in the Cargo operation execute project code.
/// Their names never grant trust to local wrapper-completion claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DependencySourceKind {
    /// One complete package below Cargo's registry source directory.
    RegistryPackage,
    /// One complete Git checkout, possibly containing workspace members.
    GitCheckout,
    /// One Cargo directory-source package, witnessed before source capture.
    DirectoryPackage,
    /// The complete retained canonical workspace for one fresh worker execution.
    /// This source class never grants dependency-cache publication or serving.
    WorkspaceExecutionOnly,
    /// A complete canonical workspace for a separately qualified, closed pure
    /// Rust leaf-library archive. Its worker receipt and cache policy remain
    /// distinct from the unrestricted fresh workspace execution class and from
    /// the operation's other project executors.
    WorkspaceClosedRlib,
    /// A complete canonical workspace for a separately qualified ordinary Rust
    /// leaf-library metadata check. Its explicit closed metadata worker context
    /// excludes procfs and entropy devices; ordinary metadata is not authority.
    WorkspaceClosedMetadata,
    /// A closed ordinary leaf-library archive with the complete own OUT_DIR
    /// tree and exact completed Cargo build-script record as retained inputs.
    /// Build-script execution itself never receives cache authority.
    WorkspaceGeneratedRlib,
    /// A closed leaf-library metadata check with complete generated inputs.
    /// Its separate class still requires the strict closed metadata namespace.
    WorkspaceGeneratedMetadata,
    /// Independently qualified generated library archive with static native
    /// inputs confined to the complete own OUT_DIR and no Rust producers.
    WorkspaceNativeGeneratedRlib,
    /// Independently qualified closed metadata with static native inputs
    /// confined to the complete own OUT_DIR and no Rust producers.
    WorkspaceNativeGeneratedMetadata,
    /// A closed library archive with a complete own OUT_DIR and an exact
    /// committed workspace/immutable producer DAG. Its retained dependency
    /// capability is mandatory; generated leaf evidence cannot authorize it.
    WorkspaceGeneratedDagRlib,
    /// The separately qualified closed metadata form of a generated-input
    /// workspace library with complete committed producer ancestry.
    WorkspaceGeneratedDagMetadata,
    /// Generated library archive with closed own-OUT_DIR static native inputs
    /// and an exact committed workspace/immutable Rust producer DAG.
    WorkspaceNativeGeneratedDagRlib,
    /// Closed metadata with own-OUT_DIR static native inputs and a complete
    /// committed Rust producer DAG, independently qualified from archives.
    WorkspaceNativeGeneratedDagMetadata,
    /// Closed canonical workspace archive whose entire retained Rust candidate
    /// inventory comes from verified, already committed workspace producers.
    WorkspaceCommittedRlib,
    /// Closed canonical workspace metadata whose entire retained Rust candidate
    /// inventory comes from verified, already committed workspace producers.
    /// Its strict metadata namespace and serving class are distinct from archives.
    WorkspaceCommittedMetadata,
    /// Closed workspace archive with committed workspace producers or separately
    /// qualified canonical remote immutable dependency archive leaves.
    WorkspaceMixedRlib,
    /// Closed workspace metadata with committed workspace producers or separately
    /// qualified canonical remote immutable dependency leaves. Every retained
    /// candidate still requires exact installed and current publication authority.
    WorkspaceMixedMetadata,
    /// A selected binary/example or test/bench metadata check. Independent leaf
    /// and committed-input policies share this complete workspace source scope;
    /// terminal outputs never establish dependency-producer authority.
    WorkspaceTerminalMetadata,
}

impl DependencySourceKind {
    /// Stable spelling used in source evidence and policy bindings.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RegistryPackage => "registry-package",
            Self::GitCheckout => "git-checkout",
            Self::DirectoryPackage => "directory-package",
            Self::WorkspaceExecutionOnly => "canonical-workspace-execution-only",
            Self::WorkspaceClosedRlib => "canonical-workspace-closed-rlib-v2",
            Self::WorkspaceClosedMetadata => "canonical-workspace-closed-metadata-v2",
            Self::WorkspaceGeneratedRlib => "canonical-workspace-generated-rlib-v1",
            Self::WorkspaceGeneratedMetadata => "canonical-workspace-generated-metadata-v1",
            Self::WorkspaceNativeGeneratedRlib => "canonical-workspace-native-generated-rlib-v1",
            Self::WorkspaceNativeGeneratedMetadata => {
                "canonical-workspace-native-generated-metadata-v1"
            }
            Self::WorkspaceGeneratedDagRlib => "canonical-workspace-generated-dag-rlib-v1",
            Self::WorkspaceGeneratedDagMetadata => "canonical-workspace-generated-dag-metadata-v1",
            Self::WorkspaceNativeGeneratedDagRlib => {
                "canonical-workspace-native-generated-dag-rlib-v1"
            }
            Self::WorkspaceNativeGeneratedDagMetadata => {
                "canonical-workspace-native-generated-dag-metadata-v1"
            }
            Self::WorkspaceCommittedRlib => "canonical-workspace-committed-rlib-v2",
            Self::WorkspaceCommittedMetadata => "canonical-workspace-committed-metadata-v2",
            Self::WorkspaceMixedRlib => "canonical-workspace-committed-mixed-rlib-v2",
            Self::WorkspaceMixedMetadata => "canonical-workspace-committed-mixed-metadata-v2",
            Self::WorkspaceTerminalMetadata => "canonical-workspace-terminal-metadata-v2",
        }
    }

    /// These profiles capture the same complete workspace files and directory
    /// topology. This describes source scope only, never cache authority.
    #[must_use]
    pub const fn is_workspace(self) -> bool {
        matches!(
            self,
            Self::WorkspaceExecutionOnly
                | Self::WorkspaceClosedRlib
                | Self::WorkspaceClosedMetadata
                | Self::WorkspaceGeneratedRlib
                | Self::WorkspaceGeneratedMetadata
                | Self::WorkspaceNativeGeneratedRlib
                | Self::WorkspaceNativeGeneratedMetadata
                | Self::WorkspaceGeneratedDagRlib
                | Self::WorkspaceGeneratedDagMetadata
                | Self::WorkspaceNativeGeneratedDagRlib
                | Self::WorkspaceNativeGeneratedDagMetadata
                | Self::WorkspaceCommittedRlib
                | Self::WorkspaceCommittedMetadata
                | Self::WorkspaceMixedRlib
                | Self::WorkspaceMixedMetadata
                | Self::WorkspaceTerminalMetadata
        )
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
    /// The prepared canonical Cargo planner admitted these visible paths.
    /// This selects exact placement keying and byte-preserving replay; it is
    /// not proof of execution or publication authority. Ordinary wrapper input
    /// cannot select this profile through an environment variable or wire flag.
    pub canonical_cargo: bool,
    /// rustc's working directory. Workspace execution may use the workspace
    /// root while CARGO_MANIFEST_DIR names a selected member package.
    pub cwd: String,
    /// Absolute out-dir (virtualized for ordinary host plans; exact for
    /// prepared canonical Cargo plans).
    pub out_dir: String,
    /// The compiled package root (`CARGO_MANIFEST_DIR`).
    pub package_root: String,
    /// Capture policy for the Cargo-managed source tree.
    pub source_kind: DependencySourceKind,
    /// Exact object identity of the observed Cargo directory-source checksum
    /// document. It must also occur in the sealed input manifest. `None` for
    /// the existing registry and Git source classes.
    pub directory_source_manifest: Option<TypedDigest>,
    /// Complete source closure: registry/directory package or whole Git checkout.
    pub source_root: String,
    /// Single safe component identifying the source's virtual root.
    pub source_dir_name: String,
    /// Cargo's build-script output tree consumed by this compile, if present.
    /// Its exact spelling is keyed; it is not a placement mapping.
    pub generated_root: Option<String>,
    /// Complete foreign build-script OUT_DIR trees reached through Cargo's
    /// propagated native searches, sorted by exact canonical visible path.
    /// These require independently retained Cargo run records and closed
    /// worker execution; ordinary/local dependency capture cannot use them.
    pub native_roots: Vec<String>,
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
    /// exact caller values, including unkeyed jobserver and launcher controls.
    pub execution_env: Vec<(String, String)>,
    /// `None`: every present non-control name is keyed (`dependency-env-v2`,
    /// so every absence is keyed too). `Some(absent)`: narrowed by
    /// [`DependencyActionPlan::narrow_to_source_env_reads`] to
    /// `dependency-env-v3`; `absent` lists the source-named ambient names
    /// missing here, whose absence is keyed. Sorted.
    pub source_named_env: Option<Vec<String>>,
}

impl DependencyActionPlan {
    /// Whether the compiler was explicitly asked to report binary inputs in
    /// dep-info. The output adapter validates every occurrence; rustc applies
    /// the last occurrence when the option is repeated.
    #[must_use]
    pub fn records_binary_dependencies(&self) -> bool {
        self.invocation
            .unstable
            .iter()
            .rev()
            .find(|(name, _)| name == "binary-dep-depinfo")
            .and_then(|(_, value)| crate::binary_dep_info::flag_value(value.as_deref()))
            == Some(true)
    }

    /// Narrow to `dependency-env-v3`: keep ambient names keyed only when
    /// `names` (the [`source_env_reads`] of every captured source and
    /// generated file) spells them — by value when present, by absence
    /// otherwise — and stop keying every other ambient name. Call once,
    /// before binding build-script exports and before keying. A tracked
    /// read of a name this drops refuses publication. Canonical-Cargo and
    /// workspace execution-only plans keep their exact environment.
    pub fn narrow_to_source_env_reads(&mut self, names: &[String]) {
        if self.canonical_cargo || self.source_kind == DependencySourceKind::WorkspaceExecutionOnly
        {
            return;
        }
        let ambient = |name: &str| matches!(env_role(name), EnvRole::Ambient);
        self.keyed_env
            .retain(|(name, _)| !ambient(name) || names.iter().any(|named| named == name));
        let mut absent: Vec<String> = names
            .iter()
            .filter(|name| ambient(name))
            .filter(|name| !self.execution_env.iter().any(|(bound, _)| bound == *name))
            .cloned()
            .collect();
        absent.sort();
        absent.dedup();
        self.source_named_env = Some(absent);
    }

    /// A tracked read of `name` is covered by the key: a keyed value, a
    /// keyed absence, or the absence of a name whose every present value
    /// would be keyed.
    fn env_read_keyed(&self, name: &str) -> bool {
        let present = self.execution_env.iter().any(|(bound, _)| bound == name);
        if present {
            return self.keyed_env.iter().any(|(keyed, _)| keyed == name);
        }
        match (env_role(name), &self.source_named_env) {
            (EnvRole::Keyed, _) | (EnvRole::Ambient, None) => true,
            (EnvRole::Passthrough, _) => false,
            (EnvRole::Ambient, Some(absent)) => absent.iter().any(|named| named == name),
        }
    }

    /// Real placement roots and their canonical counterparts. Roots are
    /// disjoint, so replacing one can never hide another.
    #[must_use]
    pub fn placement_mappings(&self) -> Vec<(String, String)> {
        if self.canonical_cargo {
            // Cargo already planned under these exact visible paths. They are
            // semantic key inputs, not subscriber-specific placement aliases.
            return Vec::new();
        }
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

    /// Distinct input-manifest root of one foreign native input tree. The
    /// index is the position in the sorted `native_roots` contract, never the
    /// order of native searches, which remains exact in the invocation.
    #[must_use]
    pub fn native_input_virtual_root(&self, index: usize) -> String {
        format!("{}-native-{index:04}", self.source_virtual_root())
    }

    /// Virtual input path of a member of one complete foreign native tree.
    #[must_use]
    pub fn native_input_virtual_path(&self, index: usize, relative: &str) -> String {
        format!("{}/{relative}", self.native_input_virtual_root(index))
    }

    /// Synthetic evidence path for the exact completed Cargo stdout record of
    /// a foreign native producer. This object is keyed but never mounted into
    /// the compiler's tree. Its `root-output` spelling is checked separately by
    /// the coordinator against the retained logical/physical root mapping.
    #[must_use]
    pub fn native_record_virtual_path(&self, index: usize) -> String {
        format!("{}-native-records/{index:04}", self.source_virtual_root())
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

/// Whether an exact object is empty metadata that rustc's crate locator skips.
///
/// This is a byte/format classification, never an installation witness. Callers
/// must keep the file in the keyed inventory and compiler-visible namespace,
/// verify its original physical generation, and reject it when explicitly named
/// by `--extern`. Nonempty metadata, archives and other digest domains never
/// acquire this exemption from committed-producer provenance.
#[must_use]
pub fn is_empty_metadata_artifact(path: &str, content_digest: &TypedDigest) -> bool {
    static EMPTY: std::sync::LazyLock<TypedDigest> =
        std::sync::LazyLock::new(empty_metadata_object_digest);
    path.rsplit('/').next().is_some_and(|name| {
        safe_component(name) && name.starts_with("lib") && name.ends_with(".rmeta")
    }) && content_digest == &*EMPTY
}

fn empty_metadata_object_digest() -> TypedDigest {
    use rabs_protocol::result_identity::DigestAlgorithm;
    use sha2::{Digest, Sha256};

    // CAS object identities use a streaming domain-length prefix, not the
    // length-framed descriptor/key encoding in typed_digest::compute.
    const DOMAIN: &str = "rabs.object.sha256.v1";
    let mut hash = Sha256::new();
    hash.update((DOMAIN.len() as u64).to_be_bytes());
    hash.update(DOMAIN.as_bytes());
    TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain: DOMAIN,
        bytes: hash.finalize().into(),
    }
}

/// Complete crate-candidate inventory of one dependency search directory:
/// exactly the files rustc's crate locator can open for a library compile.
/// Entries the locator never opens (no `lib` prefix: codegen scratch, temp
/// directories, dep-info, executables) and `.rlib`s shadowed by a non-empty
/// same-stem `.rmeta` are not inputs and are not listed; the edge refuses
/// any other `lib*` entry (dylibs, proc-macros, interfaces, static libs).
/// Empty `.rmeta` files remain exact keyed and materialized inputs even though
/// rustc skips them during crate discovery. Only producer-witness eligibility
/// distinguishes those inert files from loadable metadata.
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
    plain_path_in_profile(path, false)
}

fn plain_path_in_profile(path: &str, canonical_cargo: bool) -> bool {
    path.starts_with('/')
        && path.len() > 1
        && !path.ends_with('/')
        && !path.contains("//")
        && path.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-' | b'+' | b'@')
        })
        && !path.split('/').any(|part| part == "." || part == "..")
        && if canonical_cargo {
            within(path, "/__rabs")
        } else {
            !path.contains("/__rabs")
        }
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
    canonical_cargo: bool,
) -> Result<(DependencySourceKind, String, String), LiveRefusal> {
    if !plain_path_in_profile(cargo_home, canonical_cargo) {
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

fn directory_source(
    cargo_home: &str,
    package_root: &str,
    canonical_cargo: bool,
) -> Result<(DependencySourceKind, String, String), LiveRefusal> {
    // A witness must not reinterpret an invalid/incomplete Cargo cache path
    // as a standalone package and silently shrink a Git checkout's closure.
    if !plain_path_in_profile(cargo_home, canonical_cargo)
        || !plain_path_in_profile(package_root, canonical_cargo)
        || git_metadata(package_root)
        || package_root == cargo_home
        || within(package_root, cargo_home)
        || within(cargo_home, package_root)
    {
        return Err(LiveRefusal::NotDependencySource(package_root.to_owned()));
    }
    let name = package_root
        .rsplit_once('/')
        .map(|(_, name)| name)
        .filter(|name| safe_component(name))
        .ok_or_else(|| LiveRefusal::NotDependencySource(package_root.to_owned()))?;
    Ok((
        DependencySourceKind::DirectoryPackage,
        package_root.to_owned(),
        format!("directory-{name}"),
    ))
}

/// Classify one environment variable under `dependency-env-v3`.
pub(crate) enum EnvRole {
    /// Value (or absence) keyed: something in the compiler process can read
    /// it without a dep-info record, or Cargo presents it to every crate.
    Keyed,
    /// Never keyed; any tracked read refuses publication.
    Passthrough,
    /// Session noise nothing in the action consumes untracked (terminal,
    /// multiplexer, SSH and agent-session variables, Cargo's own
    /// configuration such as `CARGO_TARGET_DIR`). Unkeyed unless the
    /// package source names it; a tracked read of an unnamed one refuses
    /// publication, so the source scan is never trusted for soundness.
    Ambient,
}

/// Prefixes of names the compiler process may consume untracked (rustc and
/// rustup controls, the dynamic loader, LLVM, the allocator, locale) or that
/// Cargo presents to every crate compile (package metadata, cfg/feature
/// values for build scripts, Cargo-internal handshakes).
const KEYED_PREFIXES: &[&str] = &[
    "RUSTC",
    "RUST_",
    "RUSTDOC",
    "RUSTUP_",
    "CARGO_PKG_",
    "CARGO_BIN_EXE_",
    "CARGO_CFG_",
    "CARGO_FEATURE_",
    "__CARGO",
    "LD_",
    "DYLD_",
    "LC_",
    "LLVM_",
    "MALLOC_",
    "_RJEM_",
];

/// Exact names keyed for the same reasons as [`KEYED_PREFIXES`].
const KEYED_NAMES: &[&str] = &[
    "CARGO",
    "CARGO_MANIFEST_DIR",
    "CARGO_MANIFEST_PATH",
    "CARGO_MANIFEST_LINKS",
    "CARGO_CRATE_NAME",
    "CARGO_BIN_NAME",
    "CARGO_PRIMARY_PACKAGE",
    "CARGO_TARGET_TMPDIR",
    "CARGO_RUSTC_CURRENT_DIR",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_SBOM_PATH",
    "OUT_DIR",
    "PATH",
    "HOME",
    "LANG",
    "LANGUAGE",
    "TZ",
    "TERM",
    "NO_COLOR",
    "CLICOLOR",
    "CLICOLOR_FORCE",
    "COLUMNS",
    "SOURCE_DATE_EPOCH",
    "GLIBC_TUNABLES",
    "LOCPATH",
    "NLSPATH",
    "GCONV_PATH",
    "SDKROOT",
    "DOCS_RS",
];

pub(crate) fn env_role(name: &str) -> EnvRole {
    // These values control the wrapper or identify host-local descriptors.
    // RCH_BUILD_SOURCE changes when unrelated workspace files change; the
    // dependency's own captured source bytes already establish its identity.
    // Preserve every value for execution and veto any tracked read, including
    // an absent read. Never exempt broad RUST* or RCH_* namespaces.
    if DESCRIPTOR_AUTH_VARS.contains(&name.as_bytes())
        || SHELL_BOOKKEEPING_NAMES.contains(&name)
        || HOST_PLACEMENT_NAMES.contains(&name)
        || name.starts_with("RABS_")
        || name.starts_with("CARGO_RABS_")
        || name == "RCH_BUILD_SOURCE"
    {
        EnvRole::Passthrough
    } else if KEYED_NAMES.contains(&name)
        || KEYED_PREFIXES.iter().any(|prefix| name.starts_with(prefix))
        || name.ends_with("_DEPLOYMENT_TARGET")
    {
        EnvRole::Keyed
    } else {
        EnvRole::Ambient
    }
}

/// Names a Rust source text reads with `env!`/`option_env!` (any macro
/// whose name ends in `env!`) given a plain or raw string literal first
/// argument. Sorted and deduplicated. This is a keying aid, not a closure
/// proof: reads it misses (names produced by other macros) are still
/// refused publication by [`dep_info_closure_violation`]. Comments and
/// strings are not excluded; a spurious name only keys more.
#[must_use]
pub fn source_env_reads(source: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    let mut at = 0;
    while let Some(found) = find_bytes(&source[at..], b"env!") {
        let mut cursor = at + found + b"env!".len();
        at = cursor;
        let skip_space = |cursor: &mut usize| {
            while source.get(*cursor).is_some_and(u8::is_ascii_whitespace) {
                *cursor += 1;
            }
        };
        skip_space(&mut cursor);
        if !matches!(source.get(cursor), Some(b'(' | b'[' | b'{')) {
            continue;
        }
        cursor += 1;
        skip_space(&mut cursor);
        // Plain "…" or raw r"…"/r#"…"# literals; escapes in plain literals
        // are not decoded (an escaped name is refused by the dep-info veto).
        let mut hashes = 0;
        if source.get(cursor) == Some(&b'r') {
            cursor += 1;
            while source.get(cursor) == Some(&b'#') {
                hashes += 1;
                cursor += 1;
            }
        }
        if source.get(cursor) != Some(&b'"') {
            continue;
        }
        cursor += 1;
        let start = cursor;
        while source
            .get(cursor)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            cursor += 1;
        }
        let closed = source.get(cursor) == Some(&b'"')
            && source
                .get(cursor + 1..cursor + 1 + hashes)
                .is_some_and(|tail| tail.iter().all(|byte| *byte == b'#'));
        if closed
            && cursor > start
            && let Ok(name) = std::str::from_utf8(&source[start..cursor])
        {
            names.push(name.to_owned());
        }
    }
    names.sort();
    names.dedup();
    names
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// The complete `dependency-env-v3` environment for a compiler process,
/// sorted by name. Preserve every exact caller binding: arbitrary variables
/// can affect `env!` and `option_env!`, so an allowlist changes real builds.
/// Toolchain probes use this too, matching the admitted compiler process.
#[must_use]
pub fn constructed_environment(env: &[(String, String)]) -> Vec<(String, String)> {
    let mut constructed = env.to_vec();
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
pub fn plan_dependency_action(
    request: LiveRustcRequest<'_>,
    host_triple: &str,
) -> Result<DependencyActionPlan, LiveRefusal> {
    plan_with_directory_manifest(request, host_triple, None, DependencyPlanningMode::Ordinary)
}

/// Plan a Cargo directory-source dependency after the edge observed a valid
/// `.cargo-checksum.json` document at `CARGO_MANIFEST_DIR`. This is not an
/// arbitrary path/workspace-crate admission switch. The key builder requires
/// the same document identity in the complete captured package manifest.
/// No source path or executed environment is rewritten.
///
/// # Errors
/// The existing dependency-class refusals, or an unsupported directory root.
pub fn plan_directory_dependency_action(
    request: LiveRustcRequest<'_>,
    host_triple: &str,
    checksum_document: TypedDigest,
) -> Result<DependencyActionPlan, LiveRefusal> {
    plan_with_directory_manifest(
        request,
        host_triple,
        Some(checksum_document),
        DependencyPlanningMode::Ordinary,
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DependencyPlanningMode {
    Ordinary,
    CanonicalLocal,
    CanonicalRemote,
    WorkspaceExecutionOnly,
}

#[allow(clippy::too_many_lines)]
fn plan_with_directory_manifest(
    request: LiveRustcRequest<'_>,
    host_triple: &str,
    directory_source_manifest: Option<TypedDigest>,
    mode: DependencyPlanningMode,
) -> Result<DependencyActionPlan, LiveRefusal> {
    plan_in_profile(request, host_triple, directory_source_manifest, mode)
}

#[allow(clippy::too_many_lines)]
fn plan_in_profile(
    request: LiveRustcRequest<'_>,
    host_triple: &str,
    directory_source_manifest: Option<TypedDigest>,
    mode: DependencyPlanningMode,
) -> Result<DependencyActionPlan, LiveRefusal> {
    let canonical_cargo = mode != DependencyPlanningMode::Ordinary;
    let workspace_execution_only = mode == DependencyPlanningMode::WorkspaceExecutionOnly;
    let canonical_archive_execution = matches!(
        mode,
        DependencyPlanningMode::CanonicalRemote | DependencyPlanningMode::WorkspaceExecutionOnly
    );
    // Environment first: it is the cheapest way out of the class.
    let mut names: Vec<&str> = request.env.iter().map(|(name, _)| name.as_str()).collect();
    names.sort_unstable();
    if let Some(pair) = names.windows(2).find(|pair| pair[0] == pair[1]) {
        return Err(LiveRefusal::DuplicateEnv(pair[0].to_owned()));
    }
    if let Some(name) = names.iter().find(|name| {
        REFUSED_NAMES.contains(name)
            && !(workspace_execution_only && **name == "CARGO_PRIMARY_PACKAGE")
    }) {
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
    if !plain_path_in_profile(&package_root, canonical_cargo) {
        return Err(LiveRefusal::UnrepresentablePath(package_root));
    }
    let (source_kind, source_root, source_dir_name) = if workspace_execution_only {
        if !canonical_cargo
            || directory_source_manifest.is_some()
            || !(package_root == workspace_execution::WORKSPACE
                || within(&package_root, workspace_execution::WORKSPACE))
        {
            return Err(LiveRefusal::NotDependencySource(package_root));
        }
        (
            DependencySourceKind::WorkspaceExecutionOnly,
            workspace_execution::WORKSPACE.to_owned(),
            "workspace".to_owned(),
        )
    } else if directory_source_manifest.is_some() {
        directory_source(&cargo_home, &package_root, canonical_cargo)?
    } else {
        dependency_source(&cargo_home, &package_root, canonical_cargo)?
    };

    if if workspace_execution_only {
        !plain_path_in_profile(request.cwd, true)
            || !(request.cwd == source_root || within(request.cwd, &source_root))
    } else {
        request.cwd != package_root
    } {
        return Err(LiveRefusal::WorkingDirectory(request.cwd.to_owned()));
    }

    let invocation = parse(request.argv, None)
        .map_err(|error| LiveRefusal::Unparseable(format!("{error:?}")))?;
    let outputs = if workspace_execution_only {
        derive_workspace_output_declarations(&invocation, host_triple)
    } else {
        derive_dependency_output_declarations(&invocation, host_triple)
    }
    .map_err(|error| LiveRefusal::Outputs(error.to_string()))?;
    if !workspace_execution_only && invocation.cap_lints.as_deref() != Some("allow") {
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
    if !canonical_archive_execution && let Some(library) = invocation.native_libs.first() {
        return Err(LiveRefusal::NativeLibrary(library.clone()));
    }
    let source = match &invocation.source {
        Some(SourceInput::Path(path)) => path.clone(),
        _ => return Err(LiveRefusal::SourceOutsidePackage("no source path".into())),
    };
    let source_inside = if workspace_execution_only {
        workspace_execution::resolved_workspace_source(request.cwd, &source)
            .is_some_and(|source| within(&source, &source_root))
    } else {
        plain_path_in_profile(&source, canonical_cargo) && within(&source, &package_root)
    };
    if !source_inside {
        return Err(LiveRefusal::SourceOutsidePackage(source));
    }
    let out_dir = invocation
        .out_dir
        .clone()
        .ok_or_else(|| LiveRefusal::Outputs("missing --out-dir".into()))?;
    if !plain_path_in_profile(&out_dir, canonical_cargo)
        || out_dir == source_root
        || within(&out_dir, &source_root)
        || within(&source_root, &out_dir)
    {
        return Err(LiveRefusal::UnrepresentablePath(out_dir));
    }
    let generated_root = env_value(request.env, "OUT_DIR").map(str::to_owned);
    // Raw Cargo requests with direct native-library directives need their
    // package's build-script owner before observation can begin. Retained-key
    // validation separately checks complete foreign trees and named archives;
    // that stronger evidence must not be mistaken for request admission.
    if canonical_archive_execution && !invocation.native_libs.is_empty() && generated_root.is_none()
    {
        return Err(LiveRefusal::MissingEnv("OUT_DIR"));
    }
    if let Some(root) = &generated_root
        && (!plain_path_in_profile(root, canonical_cargo)
            // Dep-info replay substitutes the compiler output placement.
            // It must never rewrite a retained exact generated-input path.
            || root.contains(&out_dir)
            || [source_root.as_str(), out_dir.as_str()]
                .iter()
                .any(|other| root == other || within(root, other) || within(other, root)))
    {
        return Err(LiveRefusal::UnrepresentablePath(root.clone()));
    }
    let native_roots = if canonical_archive_execution {
        remote::canonical_generated_native_roots(&invocation, generated_root.as_deref())?
    } else {
        Vec::new()
    };
    remote::validate_generated_native_inputs_with_roots(
        &invocation,
        generated_root.as_deref(),
        &native_roots,
        canonical_archive_execution,
    )?;
    let mut dependency_dirs = Vec::new();
    let mut add_directory = |path: &str| -> Result<(), LiveRefusal> {
        if !plain_path_in_profile(path, canonical_cargo)
            || path == source_root
            || within(path, &source_root)
            || within(&source_root, path)
            || (path != out_dir && (within(path, &out_dir) || within(&out_dir, path)))
            || generated_root
                .as_ref()
                .is_some_and(|root| path == root || within(path, root) || within(root, path))
            || native_roots
                .iter()
                .any(|root| path == root || within(path, root) || within(root, path))
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
        // These inputs belong to the complete generated tree, not to Rust's
        // crate-candidate inventory. The bounded remote validator above has
        // already proved every native directory is within an exact retained
        // OUT_DIR. Foreign producers have independent run-record evidence.
        if canonical_archive_execution && entry.starts_with("native=") {
            continue;
        }
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
        .filter(|(name, _)| {
            workspace_execution_only || !matches!(env_role(name), EnvRole::Passthrough)
        })
        .cloned()
        .collect();

    let target_triple = invocation
        .target
        .clone()
        .unwrap_or_else(|| host_triple.to_owned());
    Ok(DependencyActionPlan {
        compiler: invocation.compiler_argv0.clone(),
        canonical_cargo,
        invocation,
        cwd: request.cwd.to_owned(),
        out_dir,
        package_root,
        source_kind,
        directory_source_manifest,
        source_root,
        source_dir_name,
        generated_root,
        native_roots,
        target_triple,
        host_triple: host_triple.to_owned(),
        externs,
        dependency_dirs,
        outputs,
        keyed_env,
        execution_env,
        source_named_env: None,
    })
}

/// The normalized-invocation component: ordinary host output and dependency
/// placement virtualized, prepared canonical Cargo placement exact. Every
/// other path is kept and presentation flags are bound (an exact transcript
/// is only replayable under the presentation that produced it).
fn invocation_component(plan: &DependencyActionPlan) -> TypedDigest {
    let mut virtual_invocation = plan.invocation.clone();
    if !plan.canonical_cargo {
        virtual_invocation.out_dir = Some(CANONICAL_OUT_DIR.to_owned());
    }
    for entry in &mut virtual_invocation.lib_search {
        if let Some(root) = entry.strip_prefix("dependency=") {
            *entry = format!("dependency={}", plan.virtual_dependency_path(root));
        }
        // Generated native searches preserve their exact canonical spelling
        // and ordering. They are never projected onto a dependency/output root.
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
    if plan.records_binary_dependencies() && !plan.canonical_cargo {
        // The shared invocation encoder deliberately omits compiler argv[0]
        // and toolchain identity is content-based. Binary dep-info additionally
        // exposes the implicit sysroot's absolute path, which this host adapter
        // preserves. Bind that placement before another installation of the
        // same compiler bytes could replay .d paths from the first one.
        enc.str("binary-dep-info-host-toolchain-placement-v1")
            .str(&plan.compiler);
    }
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
        if is_empty_metadata_artifact(&fact.path, &fact.content_digest) {
            return Err(LiveRefusal::Extern(
                "explicit extern metadata is empty".into(),
            ));
        }
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
            let disposition = if name == "LD_LIBRARY_PATH" && !plan.canonical_cargo {
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
    let dataset = PresentedEnvironment {
        variables,
        path_manifest: Vec::new(),
    }
    .dataset_digest()
    .map_err(|error| LiveRefusal::Facts(format!("{error:?}")))?;
    let mut policy = CanonicalEncoder::new();
    policy
        .str(dataset.domain)
        .bytes(&dataset.bytes)
        .str("exact execution; host placement tracked reads refuse publication, even absent");
    for name in HOST_PLACEMENT_NAMES {
        policy.str(name);
    }
    // dependency-env-v3: compiler-consumed and Cargo crate names keyed;
    // ambient names keyed only when the source reads them, by value (above)
    // or by absence (here); other tracked reads refuse publication. An
    // unnarrowed (v2) plan's digest is unchanged.
    if let Some(absent) = &plan.source_named_env {
        policy
            .str("dependency-env-v3")
            .seq(absent, |encoder, name| {
                encoder.str(name);
            });
    }
    Ok(compute(DOMAIN_LIVE_ENVIRONMENT, &policy.finish()))
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
    if plan.canonical_cargo || !plan.native_roots.is_empty() {
        return Err(LiveRefusal::Facts(
            "canonical Cargo plans require their distinct dependency-key policy".into(),
        ));
    }
    remote::validate_generated_native_inputs(
        &plan.invocation,
        plan.generated_root.as_deref(),
        false,
    )?;
    dependency_key(
        plan,
        toolchain,
        externs,
        directories,
        build_script_output,
        inputs,
    )
}

fn dependency_key(
    plan: &DependencyActionPlan,
    toolchain: &ToolchainFacts,
    externs: &[ExternFact],
    directories: &[DependencyDirectoryFact],
    build_script_output: Option<&[u8]>,
    inputs: &ActionInputManifest,
) -> Result<LiveDependencyKey, LiveRefusal> {
    if plan.source_kind.is_workspace() {
        return Err(LiveRefusal::Facts(
            "workspace plans require their separate execution or cache authority".into(),
        ));
    }
    captured_action_key(
        plan,
        toolchain,
        externs,
        directories,
        build_script_output,
        inputs,
    )
}

/// Shared input validation and descriptor assembly. Only the separate workspace
/// execution builder may use this for WorkspaceExecutionOnly, and that builder
/// replaces the execution policy before returning an execution identity.
fn captured_action_key(
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
    validate_directory_source_manifest(plan, inputs)?;
    if plan.source_kind.is_workspace() {
        workspace_input_directories(plan, inputs)?;
    }
    generated_input_directories(plan, inputs)?;
    if !plan.native_roots.is_empty() {
        remote::validate_plan_native_roots(plan)?;
        for index in 0..plan.native_roots.len() {
            native_input_directories(plan, inputs, index)?;
            let record = plan.native_record_virtual_path(index);
            let mut records = inputs
                .inputs
                .iter()
                .filter(|input| input.virtual_path.as_bytes() == record.as_bytes());
            let Some(input) = records.next() else {
                return Err(LiveRefusal::Facts(
                    "foreign native input tree lacks its completed Cargo output record".into(),
                ));
            };
            if records.next().is_some()
                || input.file_type != InputFileType::Regular
                || input.executable
                || !input.symlink_resolution.is_empty()
            {
                return Err(LiveRefusal::Facts(
                    "foreign native Cargo output record must be one exact regular input".into(),
                ));
            }
        }
    }
    let root = format!("{}/", plan.source_virtual_root());
    let generated = format!("{}/", plan.generated_virtual_root());
    let native = (0..plan.native_roots.len())
        .map(|index| {
            (
                format!("{}/", plan.native_input_virtual_root(index)),
                plan.native_record_virtual_path(index),
            )
        })
        .collect::<Vec<_>>();
    if inputs.inputs.is_empty()
        || !inputs.approved_generated_objects.is_empty()
        || inputs.inputs.iter().any(|input| {
            input.file_type != InputFileType::Regular
                || !input.symlink_resolution.is_empty()
                || !(input.virtual_path.as_bytes().starts_with(root.as_bytes())
                    || (plan.generated_root.is_some()
                        && input
                            .virtual_path
                            .as_bytes()
                            .starts_with(generated.as_bytes()))
                    || native.iter().any(|(tree, record)| {
                        input.virtual_path.as_bytes().starts_with(tree.as_bytes())
                            || input.virtual_path.as_bytes() == record.as_bytes()
                    }))
                || (input.virtual_path.as_bytes().starts_with(root.as_bytes())
                    && matches!(
                        plan.source_kind,
                        DependencySourceKind::GitCheckout
                            | DependencySourceKind::DirectoryPackage
                            | DependencySourceKind::WorkspaceExecutionOnly
                            | DependencySourceKind::WorkspaceClosedRlib
                            | DependencySourceKind::WorkspaceClosedMetadata
                            | DependencySourceKind::WorkspaceGeneratedRlib
                            | DependencySourceKind::WorkspaceGeneratedMetadata
                            | DependencySourceKind::WorkspaceNativeGeneratedRlib
                            | DependencySourceKind::WorkspaceNativeGeneratedMetadata
                            | DependencySourceKind::WorkspaceGeneratedDagRlib
                            | DependencySourceKind::WorkspaceGeneratedDagMetadata
                            | DependencySourceKind::WorkspaceNativeGeneratedDagRlib
                            | DependencySourceKind::WorkspaceNativeGeneratedDagMetadata
                            | DependencySourceKind::WorkspaceCommittedRlib
                            | DependencySourceKind::WorkspaceCommittedMetadata
                            | DependencySourceKind::WorkspaceMixedRlib
                            | DependencySourceKind::WorkspaceMixedMetadata
                            | DependencySourceKind::WorkspaceTerminalMetadata
                    )
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
    let workspace_source = if plan.source_kind.is_workspace() {
        Some(workspace_source_path(plan)?)
    } else {
        None
    };
    let source_relative = plan
        .invocation
        .source
        .as_ref()
        .and_then(|source| match source {
            SourceInput::Path(path) => workspace_source
                .as_deref()
                .unwrap_or(path)
                .strip_prefix(&format!("{}/", plan.source_root)),
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
            DependencySourceKind::DirectoryPackage => {
                enc.str("complete-directory-package-tree-enumeration-v1")
                    .str(plan.source_kind.as_str())
                    .str(&plan.source_root)
                    .str(&plan.source_virtual_root());
            }
            DependencySourceKind::WorkspaceExecutionOnly
            | DependencySourceKind::WorkspaceClosedRlib
            | DependencySourceKind::WorkspaceClosedMetadata
            | DependencySourceKind::WorkspaceGeneratedRlib
            | DependencySourceKind::WorkspaceGeneratedMetadata
            | DependencySourceKind::WorkspaceNativeGeneratedRlib
            | DependencySourceKind::WorkspaceNativeGeneratedMetadata
            | DependencySourceKind::WorkspaceGeneratedDagRlib
            | DependencySourceKind::WorkspaceGeneratedDagMetadata
            | DependencySourceKind::WorkspaceNativeGeneratedDagRlib
            | DependencySourceKind::WorkspaceNativeGeneratedDagMetadata
            | DependencySourceKind::WorkspaceCommittedRlib
            | DependencySourceKind::WorkspaceCommittedMetadata
            | DependencySourceKind::WorkspaceMixedRlib
            | DependencySourceKind::WorkspaceMixedMetadata
            | DependencySourceKind::WorkspaceTerminalMetadata => {
                enc.str("complete-canonical-workspace-execution-tree-v1")
                    .str(plan.source_kind.as_str())
                    .str(&plan.source_root)
                    .str(&plan.source_virtual_root());
            }
        }
        if let Some(generated_root) = &plan.generated_root {
            enc.str("complete-generated-input-tree-enumeration-v2")
                .str(generated_root)
                .str(&plan.generated_virtual_root());
        }
        if !plan.native_roots.is_empty() {
            enc.str("complete-foreign-native-input-trees-v1");
            for (index, root) in plan.native_roots.iter().enumerate() {
                enc.str(root)
                    .str(&plan.native_input_virtual_root(index))
                    .str(&plan.native_record_virtual_path(index));
            }
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
        action_class: if plan.source_kind.is_workspace() {
            ActionClass::RustcWorkspaceCompile
        } else {
            ActionClass::RustcDependencyCompile
        },
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
                DependencySourceKind::DirectoryPackage => DIRECTORY_ISOLATION_PROFILE,
                DependencySourceKind::WorkspaceExecutionOnly => {
                    workspace_execution::WORKSPACE_EXECUTION_PROFILE
                }
                DependencySourceKind::WorkspaceClosedRlib => workspace_cache::ISOLATION_PROFILE,
                DependencySourceKind::WorkspaceClosedMetadata => {
                    workspace_cache::METADATA_ISOLATION_PROFILE
                }
                DependencySourceKind::WorkspaceGeneratedRlib => {
                    workspace_cache::GENERATED_ISOLATION_PROFILE
                }
                DependencySourceKind::WorkspaceGeneratedMetadata => {
                    workspace_cache::GENERATED_METADATA_ISOLATION_PROFILE
                }
                DependencySourceKind::WorkspaceNativeGeneratedRlib => {
                    workspace_cache::NATIVE_GENERATED_ISOLATION_PROFILE
                }
                DependencySourceKind::WorkspaceNativeGeneratedMetadata => {
                    workspace_cache::NATIVE_GENERATED_METADATA_ISOLATION_PROFILE
                }
                DependencySourceKind::WorkspaceGeneratedDagRlib => {
                    workspace_dependency_cache::GENERATED_DAG_RLIB_ISOLATION_PROFILE
                }
                DependencySourceKind::WorkspaceGeneratedDagMetadata => {
                    workspace_dependency_cache::GENERATED_DAG_METADATA_ISOLATION_PROFILE
                }
                DependencySourceKind::WorkspaceNativeGeneratedDagRlib => {
                    workspace_dependency_cache::NATIVE_GENERATED_DAG_RLIB_ISOLATION_PROFILE
                }
                DependencySourceKind::WorkspaceNativeGeneratedDagMetadata => {
                    workspace_dependency_cache::NATIVE_GENERATED_DAG_METADATA_ISOLATION_PROFILE
                }
                DependencySourceKind::WorkspaceCommittedRlib => {
                    workspace_dependency_cache::ISOLATION_PROFILE
                }
                DependencySourceKind::WorkspaceCommittedMetadata => {
                    workspace_dependency_cache::METADATA_ISOLATION_PROFILE
                }
                DependencySourceKind::WorkspaceMixedRlib => {
                    workspace_dependency_cache::MIXED_RLIB_ISOLATION_PROFILE
                }
                DependencySourceKind::WorkspaceMixedMetadata => {
                    workspace_dependency_cache::MIXED_METADATA_ISOLATION_PROFILE
                }
                DependencySourceKind::WorkspaceTerminalMetadata => {
                    workspace_dependency_cache::TERMINAL_METADATA_ISOLATION_PROFILE
                }
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

/// Validate the complete generated-tree directory closure bound into an action
/// input manifest, returning sorted relative subdirectories excluding the root.
/// Every directory, including an empty OUT_DIR itself, needs one exact listing
/// of immediate file and directory names. Files and directories may not collide,
/// every parent must be declared, and no listing outside OUT_DIR is accepted.
///
/// Callers supply observations from the same coherent capture as the positive
/// file objects. This pure check proves their consistency, not that a caller
/// observed a live filesystem or acquired authority to execute an action.
///
/// # Errors
/// [`LiveRefusal::Facts`] for missing, unsafe, duplicate, unbounded or inconsistent
/// generated input evidence, or directory evidence without a generated root.
pub fn generated_input_directories(
    plan: &DependencyActionPlan,
    inputs: &ActionInputManifest,
) -> Result<Vec<String>, LiveRefusal> {
    let refuse = || {
        LiveRefusal::Facts(
            "generated inputs require complete normalized directory listings matching every captured file"
                .into(),
        )
    };
    let mut other_roots = (0..plan.native_roots.len())
        .map(|index| plan.native_input_virtual_root(index))
        .collect::<Vec<_>>();
    if plan.source_kind.is_workspace() {
        other_roots.push(plan.source_virtual_root());
    }
    if plan.generated_root.is_none() {
        return if inputs.directory_enumerations.iter().all(|enumeration| {
            other_roots.iter().any(|root| {
                enumeration.virtual_path.as_bytes() == root.as_bytes()
                    || enumeration
                        .virtual_path
                        .as_bytes()
                        .starts_with(format!("{root}/").as_bytes())
            })
        }) {
            Ok(Vec::new())
        } else {
            Err(refuse())
        };
    }
    complete_input_directories(inputs, &plan.generated_virtual_root(), &other_roots)
}

/// Validate the complete retained workspace directory closure for an
/// workspace plan, returning sorted relative subdirectories without the
/// root. Generated-directory listings may accompany it only at their separate
/// declared virtual root and are independently checked by the key builder.
///
/// # Errors
/// Any other action class, missing or inconsistent source listings, unsafe
/// paths, symlinks, file/directory collisions, or incomplete parent closure.
pub fn workspace_input_directories(
    plan: &DependencyActionPlan,
    inputs: &ActionInputManifest,
) -> Result<Vec<String>, LiveRefusal> {
    if !plan.canonical_cargo
        || !plan.source_kind.is_workspace()
        || plan.source_root != workspace_execution::WORKSPACE
    {
        return Err(LiveRefusal::Facts(
            "workspace directory evidence requires a canonical workspace plan".into(),
        ));
    }
    let mut other_roots = plan
        .generated_root
        .as_ref()
        .map(|_| plan.generated_virtual_root())
        .into_iter()
        .collect::<Vec<_>>();
    other_roots
        .extend((0..plan.native_roots.len()).map(|index| plan.native_input_virtual_root(index)));
    complete_input_directories(inputs, &plan.source_virtual_root(), &other_roots)
}

/// Validate one complete foreign native OUT_DIR's file and directory closure.
/// Each root must retain every immediate listing, including empty directories;
/// the synthetic Cargo stdout record is separate evidence, never tree content.
///
/// # Errors
/// Noncanonical plans, missing/out-of-range roots, undeclared listings, duplicate
/// paths, symlinks, absent parents or inconsistent file/directory membership.
pub fn native_input_directories(
    plan: &DependencyActionPlan,
    inputs: &ActionInputManifest,
    index: usize,
) -> Result<Vec<String>, LiveRefusal> {
    if !plan.canonical_cargo
        || index >= plan.native_roots.len()
        || plan.native_roots.len() > remote::MAX_CANONICAL_NATIVE_ROOTS
    {
        return Err(LiveRefusal::Facts(
            "foreign native directory evidence requires an exact canonical root".into(),
        ));
    }
    remote::validate_plan_native_roots(plan)?;
    let mut other_roots = (0..plan.native_roots.len())
        .filter(|other| *other != index)
        .map(|other| plan.native_input_virtual_root(other))
        .collect::<Vec<_>>();
    if plan.source_kind.is_workspace() {
        other_roots.push(plan.source_virtual_root());
    }
    if plan.generated_root.is_some() {
        other_roots.push(plan.generated_virtual_root());
    }
    complete_input_directories(inputs, &plan.native_input_virtual_root(index), &other_roots)
}

fn complete_input_directories(
    inputs: &ActionInputManifest,
    root: &str,
    other_roots: &[String],
) -> Result<Vec<String>, LiveRefusal> {
    use std::collections::{BTreeMap, BTreeSet};

    let refuse = || {
        LiveRefusal::Facts(
            "retained inputs require complete normalized directory listings matching every captured file"
                .into(),
        )
    };
    // Match the independently bounded generated-directory execution contract.
    // The generated root occupies one additional enumeration but no relative
    // directory name in the worker context.
    if inputs.directory_enumerations.is_empty()
        || other_roots.len() > remote::MAX_CANONICAL_NATIVE_ROOTS + 1
        || inputs.directory_enumerations.len() > 4097 * (other_roots.len() + 1)
    {
        return Err(refuse());
    }
    let prefix = format!("{root}/");
    let mut declared = BTreeMap::new();
    for enumeration in &inputs.directory_enumerations {
        let path =
            std::str::from_utf8(enumeration.virtual_path.as_bytes()).map_err(|_| refuse())?;
        if other_roots
            .iter()
            .any(|other| path == other || within(path, other))
        {
            continue;
        }
        let relative = if path == root {
            ""
        } else {
            let relative = path.strip_prefix(&prefix).ok_or_else(refuse)?;
            if !normalized_generated_relative(relative) {
                return Err(refuse());
            }
            relative
        };
        if declared.insert(relative, enumeration).is_some()
            || enumeration
                .entries
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || enumeration.entries.iter().any(|entry| {
                std::str::from_utf8(entry.as_bytes()).map_or(true, |entry| {
                    entry.contains('/') || !normalized_generated_relative(entry)
                })
            })
        {
            return Err(refuse());
        }
    }
    if !declared.contains_key("") || declared.len() > 4097 {
        return Err(refuse());
    }
    let mut expected: BTreeMap<&str, BTreeSet<&str>> = declared
        .keys()
        .map(|directory| (*directory, BTreeSet::new()))
        .collect();
    for relative in declared.keys().filter(|relative| !relative.is_empty()) {
        let (parent, name) = relative.rsplit_once('/').unwrap_or(("", relative));
        let children = expected.get_mut(parent).ok_or_else(refuse)?;
        if !children.insert(name) {
            return Err(refuse());
        }
    }
    for input in &inputs.inputs {
        if input.virtual_path.as_bytes() == root.as_bytes() {
            return Err(refuse());
        }
        let Some(relative) = input
            .virtual_path
            .as_bytes()
            .strip_prefix(prefix.as_bytes())
        else {
            continue;
        };
        let relative = std::str::from_utf8(relative).map_err(|_| refuse())?;
        if !normalized_generated_relative(relative)
            || input.file_type != InputFileType::Regular
            || !input.symlink_resolution.is_empty()
            || declared.contains_key(relative)
        {
            return Err(refuse());
        }
        let (parent, name) = relative.rsplit_once('/').unwrap_or(("", relative));
        if !expected.get_mut(parent).ok_or_else(refuse)?.insert(name) {
            return Err(refuse());
        }
    }
    for (relative, enumeration) in &declared {
        let children = &expected[relative];
        if enumeration.entries.len() != children.len()
            || enumeration
                .entries
                .iter()
                .zip(children)
                .any(|(actual, expected)| actual.as_bytes() != expected.as_bytes())
        {
            return Err(refuse());
        }
    }
    Ok(declared
        .keys()
        .filter(|relative| !relative.is_empty())
        .map(|relative| (*relative).to_owned())
        .collect())
}

fn normalized_generated_relative(path: &str) -> bool {
    path.len() <= 1024
        && !path.contains(['\\', ':'])
        && !path.chars().any(char::is_control)
        && path.split('/').count() <= 32
        && path
            .split('/')
            .all(|part| !part.is_empty() && !matches!(part, "." | ".."))
}

fn validate_directory_source_manifest(
    plan: &DependencyActionPlan,
    inputs: &ActionInputManifest,
) -> Result<(), LiveRefusal> {
    if plan.source_kind != DependencySourceKind::DirectoryPackage {
        return if plan.directory_source_manifest.is_none() {
            Ok(())
        } else {
            Err(LiveRefusal::Facts(
                "unexpected directory-source witness".into(),
            ))
        };
    }
    let witness = plan
        .directory_source_manifest
        .as_ref()
        .ok_or_else(|| LiveRefusal::Facts("missing directory-source checksum witness".into()))?;
    if plan.source_root != plan.package_root || git_metadata(&plan.source_root) {
        return Err(LiveRefusal::Facts("invalid directory-source scope".into()));
    }
    for name in ["Cargo.toml", ".cargo-checksum.json"] {
        let path = plan.input_virtual_path(name);
        let mut matching = inputs
            .inputs
            .iter()
            .filter(|input| input.virtual_path.as_bytes() == path.as_bytes());
        let valid = matching.next().is_some_and(|input| {
            input.file_type == InputFileType::Regular
                && input.symlink_resolution.is_empty()
                && (name != ".cargo-checksum.json" || &input.object.0 == witness)
        }) && matching.next().is_none();
        if !valid {
            return Err(LiveRefusal::Facts(format!(
                "directory-source capture does not bind the observed {name}"
            )));
        }
    }
    Ok(())
}

/// Cargo's persisted build-script stdout is a required eligibility witness
/// for generated-input compiles. Each rustc-env directive must match the exact
/// compiler environment and must be covered by the environment key.
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

/// Low-level byte substitution for an already classified output payload.
/// Live dep-info and compiler transcripts require their separate bounded
/// adapters below; arbitrary diagnostic text is not safe to rewrite.
/// Refuses bytes already containing the canonical marker because substitution
/// would not be invertible.
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

/// Canonicalize output placement in closure-checked dep-info. Only an absolute
/// path token beneath a declared placement directory is rewritten: a source
/// path with a matching substring or sibling prefix is not output placement.
/// Dependency paths are admitted only with explicitly selected binary dep-info
/// and its exact keyed-input closure check. Environment comments stay verbatim.
/// Prepared canonical Cargo plans retain every byte because their actual
/// visible placement is already exact and included in the key.
/// Compiler transcripts must use [`canonicalize_compiler_transcript`] instead.
///
/// # Errors
/// Canonical markers and unmodeled dependency placement are refused for
/// ordinary host plans; prepared plans require the fixed canonical layout.
pub fn canonicalize_placements(
    raw: &[u8],
    plan: &DependencyActionPlan,
) -> Result<Vec<u8>, &'static str> {
    if plan.canonical_cargo {
        if plan.source_kind.is_workspace() {
            workspace_execution::workspace_layout(plan)
        } else {
            canonical_cargo::canonical_layout(plan)
        }
        .map_err(|_| "invalid prepared canonical Cargo layout")?;
        // These are the compiler's actual keyed paths, already identical for
        // the producer and consumer. Replacing /__rabs/out would corrupt the
        // nested real target path /__rabs/out/cargo as well as source literals.
        return Ok(raw.to_vec());
    }
    if !plan.records_binary_dependencies() {
        for root in &plan.dependency_dirs {
            if root != &plan.out_dir && contains(raw, root.as_bytes()) {
                return Err("observable dependency directory placement cannot be replayed");
            }
        }
    }
    if contains(raw, b"/__rabs") {
        return Err("bytes already contain a canonical /__rabs path");
    }
    if !plain_path(&plan.out_dir) {
        return Err("out-dir is not a plain path");
    }
    if plan.records_binary_dependencies() {
        let mappings = plan.placement_mappings();
        if mappings.iter().any(|(root, _)| !plain_path(root)) {
            return Err("dependency directory is not a plain path");
        }
        return Ok(rewrite_dep_info_placements(raw, &mappings));
    }
    let prefix = format!("{}/", plan.out_dir);
    let mut canonical = Vec::with_capacity(raw.len());
    let mut at = 0;
    while at < raw.len() {
        if (at == 0 || raw[at - 1].is_ascii_whitespace())
            && raw[at..].starts_with(prefix.as_bytes())
        {
            canonical.extend_from_slice(CANONICAL_OUT_DIR.as_bytes());
            at += plan.out_dir.len();
        } else {
            canonical.push(raw[at]);
            at += 1;
        }
    }
    Ok(canonical)
}

/// The input has already passed the bounded dep-info grammar and exact closure
/// checks. Rewrite complete path-token prefixes only, never arbitrary bytes or
/// tracked environment values. Escaped whitespace remains inside its token even
/// though the live closure currently refuses escaped paths and continuations.
/// Mappings are disjoint by the live plan's rules.
fn rewrite_dep_info_placements(raw: &[u8], mappings: &[(String, String)]) -> Vec<u8> {
    let mut rewritten = Vec::with_capacity(raw.len());
    for line in raw.split_inclusive(|byte| *byte == b'\n') {
        if line.starts_with(b"#") {
            rewritten.extend_from_slice(line);
            continue;
        }
        let mut at = 0;
        let mut token_start = true;
        while at < line.len() {
            let mapping = token_start
                .then(|| {
                    mappings.iter().find(|(from, _)| {
                        line[at..].starts_with(from.as_bytes())
                            && line.get(at + from.len()) == Some(&b'/')
                    })
                })
                .flatten();
            if let Some((from, to)) = mapping {
                rewritten.extend_from_slice(to.as_bytes());
                at += from.len();
                token_start = false;
            } else if line[at] == b'\\' && at + 1 < line.len() {
                rewritten.extend_from_slice(&line[at..at + 2]);
                at += 2;
                token_start = false;
            } else {
                rewritten.push(line[at]);
                token_start = line[at].is_ascii_whitespace();
                at += 1;
            }
        }
    }
    rewritten
}

/// Render the output placement admitted by [`canonicalize_placements`].
#[must_use]
pub fn render_placements(canonical: &[u8], plan: &DependencyActionPlan) -> Vec<u8> {
    if plan.canonical_cargo {
        canonical.to_vec()
    } else if plan.records_binary_dependencies() {
        let mappings = plan
            .placement_mappings()
            .into_iter()
            .map(|(real, virtual_root)| (virtual_root, real))
            .collect::<Vec<_>>();
        rewrite_dep_info_placements(canonical, &mappings)
    } else {
        render_out_dir(canonical, &plan.out_dir)
    }
}

/// Canonicalize only declared artifact paths in a compiler transcript, retaining
/// every other byte (including whitespace, field order and line terminators).
/// A diagnostic can quote a source-authored string that happens to equal the
/// output directory. Rewriting that string for another subscriber changes what
/// rustc said. Such ambiguous observations refuse publication instead.
/// Prepared canonical Cargo plans key the exact output and dependency paths;
/// they retain the original transcript, including source-authored path strings.
/// Artifact events must still match the declared outputs in both profiles.
///
/// The artifact adapter deliberately recognizes only rustc's flat, three-string
/// event schema. A future schema or escaped path must gain an explicit adapter;
/// neither a nested `artifact` field nor an arbitrary JSON string grants a path
/// rewrite. The rest of the pure key crate needs no JSON dependency.
///
/// # Errors
/// Ambiguous placement, undeclared artifact paths, unsupported artifact events,
/// pre-existing canonical markers in ordinary host plans, an invalid prepared
/// canonical layout, or non-UTF-8 compiler output.
pub fn canonicalize_compiler_transcript(
    raw: &[u8],
    plan: &DependencyActionPlan,
) -> Result<Vec<u8>, &'static str> {
    if plan.canonical_cargo {
        if plan.source_kind.is_workspace() {
            workspace_execution::workspace_layout(plan)
        } else {
            canonical_cargo::canonical_layout(plan)
        }
        .map_err(|_| "invalid prepared canonical Cargo layout")?;
    }
    if !plan.canonical_cargo && contains(raw, b"/__rabs") {
        return Err("bytes already contain a canonical /__rabs path");
    }
    if !plain_path_in_profile(&plan.out_dir, plan.canonical_cargo) {
        return Err("out-dir is not a plain path");
    }
    for root in &plan.dependency_dirs {
        if !plan.canonical_cargo && root != &plan.out_dir && contains(raw, root.as_bytes()) {
            return Err("observable dependency directory placement cannot be replayed");
        }
    }
    let mut canonical = Vec::with_capacity(raw.len());
    for line in raw.split_inclusive(|byte| *byte == b'\n') {
        std::str::from_utf8(line).map_err(|_| "compiler transcript is not UTF-8")?;
        let (artifact, mentions_output) = transcript_observations(line, plan)?;
        if !artifact {
            if mentions_output && !plan.canonical_cargo {
                return Err("diagnostic contains ambiguous output directory placement");
            }
            canonical.extend_from_slice(line);
            continue;
        }
        let (path, emit) =
            artifact_event_fields(line).ok_or("unsupported compiler artifact notification")?;
        let relative = line[path.clone()]
            .strip_prefix(plan.out_dir.as_bytes())
            .and_then(|path| path.strip_prefix(b"/"))
            .ok_or("compiler artifact is outside the output directory")?;
        if !plan.outputs.declarations.iter().any(|output| {
            use crate::output_declarations::OutputClass;
            output.virtual_path.as_bytes() == relative
                && matches!(
                    (output.class, emit),
                    (OutputClass::ProvisionalMetadata, b"metadata")
                        | (OutputClass::DepInfo, b"dep-info")
                        | (OutputClass::File, b"link")
                )
        }) {
            return Err("compiler artifact does not match a declared output");
        }
        if plan.canonical_cargo {
            canonical.extend_from_slice(line);
        } else {
            canonical.extend_from_slice(&line[..path.start]);
            canonical.extend_from_slice(CANONICAL_OUT_DIR.as_bytes());
            canonical.push(b'/');
            canonical.extend_from_slice(relative);
            canonical.extend_from_slice(&line[path.end..]);
        }
    }
    Ok(canonical)
}

/// Render a transcript accepted by [`canonicalize_compiler_transcript`]. Only
/// an ordinary host plan's validated artifact-path fields can contain its
/// reserved replay marker. Prepared canonical Cargo transcripts remain exact.
#[must_use]
pub fn render_compiler_transcript(canonical: &[u8], plan: &DependencyActionPlan) -> Vec<u8> {
    if plan.canonical_cargo {
        canonical.to_vec()
    } else {
        render_out_dir(canonical, &plan.out_dir)
    }
}

/// Decode JSON strings for REFUSAL/classification only. Raw substring checks
/// alone miss `\/` and `\u002f`; an escaped discriminator must not disguise an
/// artifact as ordinary diagnostic text. The accepted transcript keeps its
/// original bytes. Actual artifact admission still requires the strict grammar
/// below, so this observer cannot authorize a new event shape or a path rewrite.
fn transcript_observations(
    line: &[u8],
    plan: &DependencyActionPlan,
) -> Result<(bool, bool), &'static str> {
    let mut at = 0;
    let mut containers = Vec::new();
    let mut artifact = false;
    let mut mentions_output = contains(line, plan.out_dir.as_bytes());
    while at < line.len() {
        match line[at] {
            b'"' => {
                let value = transcript_string(line, &mut at)
                    .ok_or("invalid JSON string in compiler transcript")?;
                if !plan.canonical_cargo && contains(&value, b"/__rabs") {
                    return Err("bytes already contain a canonical /__rabs path");
                }
                if !plan.canonical_cargo
                    && plan
                        .dependency_dirs
                        .iter()
                        .any(|root| root != &plan.out_dir && contains(&value, root.as_bytes()))
                {
                    return Err("observable dependency directory placement cannot be replayed");
                }
                mentions_output |= contains(&value, plan.out_dir.as_bytes());
                if containers.as_slice() == b"{" && value == b"$message_type" {
                    let mut next = at;
                    while line.get(next).is_some_and(u8::is_ascii_whitespace) {
                        next += 1;
                    }
                    if line.get(next) == Some(&b':') {
                        next += 1;
                        while line.get(next).is_some_and(u8::is_ascii_whitespace) {
                            next += 1;
                        }
                        let kind = transcript_string(line, &mut next)
                            .ok_or("invalid compiler message discriminator")?;
                        // Keep any artifact discriminator, including an earlier
                        // duplicate that a permissive map parser might replace.
                        artifact |= kind == b"artifact";
                    }
                }
            }
            opening @ (b'{' | b'[') => {
                if containers.len() >= 128 {
                    return Err("compiler transcript nesting exceeds its bound");
                }
                containers.push(opening);
                at += 1;
            }
            closing @ (b'}' | b']') => {
                let expected = if closing == b'}' { b'{' } else { b'[' };
                if containers.pop() != Some(expected) {
                    return Err("unbalanced compiler transcript containers");
                }
                at += 1;
            }
            _ => at += 1,
        }
    }
    if !containers.is_empty() {
        return Err("unbalanced compiler transcript containers");
    }
    Ok((artifact, mentions_output))
}

fn transcript_string(bytes: &[u8], at: &mut usize) -> Option<Vec<u8>> {
    fn hex_quad(bytes: &[u8], at: &mut usize) -> Option<u32> {
        let mut value = 0;
        for _ in 0..4 {
            value = value * 16 + char::from(*bytes.get(*at)?).to_digit(16)?;
            *at += 1;
        }
        Some(value)
    }
    if bytes.get(*at) != Some(&b'"') {
        return None;
    }
    *at += 1;
    let mut decoded = Vec::new();
    loop {
        let byte = *bytes.get(*at)?;
        *at += 1;
        match byte {
            b'"' => return Some(decoded),
            0..=31 => return None,
            b'\\' => {
                let escape = *bytes.get(*at)?;
                *at += 1;
                match escape {
                    b'"' | b'\\' | b'/' => decoded.push(escape),
                    b'b' => decoded.push(8),
                    b'f' => decoded.push(12),
                    b'n' => decoded.push(b'\n'),
                    b'r' => decoded.push(b'\r'),
                    b't' => decoded.push(b'\t'),
                    b'u' => {
                        let mut value = hex_quad(bytes, at)?;
                        if (0xd800..=0xdbff).contains(&value) {
                            if bytes.get(*at..*at + 2)? != b"\\u" {
                                return None;
                            }
                            *at += 2;
                            let low = hex_quad(bytes, at)?;
                            if !(0xdc00..=0xdfff).contains(&low) {
                                return None;
                            }
                            value = 0x10000 + ((value - 0xd800) << 10) + (low - 0xdc00);
                        }
                        let character = char::from_u32(value)?;
                        decoded.extend_from_slice(character.encode_utf8(&mut [0; 4]).as_bytes());
                    }
                    _ => return None,
                }
            }
            _ => decoded.push(byte),
        }
    }
}

/// A bounded grammar for the known rustc artifact event. Return the original
/// path's byte span rather than reserializing JSON and changing rustc's bytes.
fn artifact_event_fields(line: &[u8]) -> Option<(std::ops::Range<usize>, &[u8])> {
    fn whitespace(bytes: &[u8], at: &mut usize) {
        while bytes
            .get(*at)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        {
            *at += 1;
        }
    }
    fn string(bytes: &[u8], at: &mut usize) -> Option<std::ops::Range<usize>> {
        whitespace(bytes, at);
        if bytes.get(*at) != Some(&b'"') {
            return None;
        }
        *at += 1;
        let start = *at;
        loop {
            match *bytes.get(*at)? {
                b'"' => {
                    let end = *at;
                    *at += 1;
                    return Some(start..end);
                }
                b'\\' | 0..=31 => return None,
                _ => *at += 1,
            }
        }
    }
    let mut at = 0;
    whitespace(line, &mut at);
    if line.get(at) != Some(&b'{') {
        return None;
    }
    at += 1;
    let mut path = None;
    let mut emit = None;
    let mut message_type = false;
    for field in 0..3 {
        let name = string(line, &mut at)?;
        whitespace(line, &mut at);
        if line.get(at) != Some(&b':') {
            return None;
        }
        at += 1;
        let value = string(line, &mut at)?;
        match &line[name] {
            b"artifact" if path.is_none() => path = Some(value),
            b"emit" if emit.is_none() => emit = Some(&line[value]),
            b"$message_type" if !message_type && &line[value] == b"artifact" => {
                message_type = true;
            }
            _ => return None,
        }
        whitespace(line, &mut at);
        if line.get(at) != Some(&if field == 2 { b'}' } else { b',' }) {
            return None;
        }
        at += 1;
    }
    whitespace(line, &mut at);
    (at == line.len() && message_type).then_some((path?, emit?))
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
/// the source root (or an explicitly reported, keyed binary input), and every
/// tracked environment read (`# env-dep:`)
/// must name a variable whose value or absence the key covers. Reads of
/// unkeyed controls refuse publication even when absent. `is_input` answers
/// whether a virtual input path is a member of the keyed source/generated
/// manifest or, with binary dep-info enabled, the exact dependency/sysroot
/// inventory. A directory-prefix match alone is never sufficient evidence.
/// A read of a file the key does not cover is a violation too. Returns the first
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
                let unkeyed =
                    matches!(env_role(name), EnvRole::Passthrough) || !plan.env_read_keyed(name);
                if unkeyed {
                    return Some(format!("tracked read of unkeyed variable {name}"));
                }
                if name == "LD_LIBRARY_PATH"
                    && !plan.canonical_cargo
                    && plan.keyed_env.iter().any(|(name, value)| {
                        name == "LD_LIBRARY_PATH"
                            && value.split(':').any(|entry| entry == plan.out_dir)
                    })
                {
                    return Some("tracked read of placement-normalized LD_LIBRARY_PATH".into());
                }
                // Preserve the ordinary host class's refusal of observed
                // output placement in environment names/values. The narrower
                // transcript and dep-info adapters do not prove such a read
                // cannot also affect native output. Execution preserved the
                // value; only publication is refused. Prepared canonical
                // Cargo plans preserve and key the exact paths and values.
                if !plan.canonical_cargo && read.contains(&plan.out_dir) {
                    return Some(format!(
                        "tracked read of {name} contains compiler output placement"
                    ));
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
                        "dep-info target is an unkeyed input file: {target}"
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
                return Some(format!("read outside the admitted input classes: {dep}"));
            };
            if !is_input(&virtual_path) {
                return Some(format!("read of an unkeyed input file: {dep}"));
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
    if let Some(root) = &plan.generated_root
        && let Some(normalized) = normalized_within(absolute, root)
    {
        return Some(plan.generated_input_virtual_path(&normalized[root.len() + 1..]));
    }
    if let Some(path) = plan
        .native_roots
        .iter()
        .enumerate()
        .find_map(|(index, root)| {
            let normalized = normalized_within(absolute, root)?;
            Some(plan.native_input_virtual_path(index, &normalized[root.len() + 1..]))
        })
    {
        return Some(path);
    }
    // Binary evidence never grants a new read capability. Only paths in the
    // already keyed artifact/sysroot classes reach the caller's exact member
    // lookup. No lexical traversal through an unobserved directory is allowed.
    if !plan.records_binary_dependencies()
        || !plain_path_in_profile(absolute, plan.canonical_cargo)
        || !absolute.rsplit('/').next().is_some_and(|name| {
            name.starts_with("lib") && (name.ends_with(".rmeta") || name.ends_with(".rlib"))
        })
    {
        return None;
    }
    for root in &plan.dependency_dirs {
        if absolute
            .strip_prefix(&format!("{root}/"))
            .is_some_and(safe_component)
        {
            return Some(plan.virtual_dependency_path(absolute));
        }
    }
    let sysroot = plan.compiler.strip_suffix("/bin/rustc")?;
    absolute
        .starts_with(&format!("{sysroot}/lib/rustlib/"))
        .then(|| absolute.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::input_evidence::{
        DirectoryEnumeration, INPUT_EVIDENCE_SCHEMA_VERSION, PositiveInput,
    };
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

    #[test]
    fn cache_read_closure_requires_exact_metadata_and_dep_info_without_codegen() {
        for emit in ["dep-info,metadata", "metadata,dep-info"] {
            let mut args = argv(OUT_A, &[]);
            *args
                .iter_mut()
                .find(|argument| argument.starts_with("--emit="))
                .unwrap() = format!("--emit={emit}");
            let invocation = parse(&args, None).unwrap();
            assert_eq!(check_dependency_cache_read_closure(&invocation), Ok(()));
        }
        for emit in [
            "dep-info,metadata,link",
            "dep-info,link",
            "dep-info,obj",
            "dep-info,asm",
            "dep-info,llvm-ir",
            "dep-info,llvm-bc",
            "dep-info,mir",
            "metadata",
            "dep-info",
            "",
        ] {
            let mut args = argv(OUT_A, &[]);
            args.retain(|argument| !argument.starts_with("--emit="));
            if !emit.is_empty() {
                args.push(format!("--emit={emit}"));
            }
            let invocation = parse(&args, None).unwrap();
            assert_eq!(
                check_dependency_cache_read_closure(&invocation),
                Err(LiveRefusal::UnclosedCodegenInputs),
                "the emit set {emit:?} cannot gain authority through dep-info"
            );
        }
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
            directory_enumerations: plan
                .generated_root
                .as_ref()
                .map(|_| DirectoryEnumeration {
                    virtual_path: RawBytes::new(plan.generated_virtual_root().into_bytes()),
                    entries: Vec::new(),
                })
                .into_iter()
                .collect(),
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
    fn compiler_environment_is_preserved_and_custom_values_change_keys() {
        let plan = plan_for(OUT_A, &[], &[]).unwrap();
        let mut expected = env(&[]);
        expected.sort();
        assert_eq!(plan.execution_env, expected);
        for name in [
            "TERM",
            "SSH_AUTH_SOCK",
            "DEPENDENCY_FLAVOR",
            "RCH_BUILD_SOURCE_OTHER",
            "RUSTC_LOG",
            "RUST_FEATURE",
            "GOPATH_OTHER",
            "TMPDIR_OTHER",
            "SSH_CONNECTION_OTHER",
            "XDG_SESSION_ID_OTHER",
        ] {
            let changed = plan_for(OUT_A, &[], &[(name, "custom = exact value")]).unwrap();
            assert!(
                changed
                    .execution_env
                    .contains(&(name.into(), "custom = exact value".into()))
            );
            assert!(
                changed
                    .keyed_env
                    .contains(&(name.into(), "custom = exact value".into()))
            );
            assert_ne!(key(&plan), key(&changed), "{name}");
            assert_eq!(
                dep_info_closure_violation(
                    &changed,
                    format!("# env-dep:{name}=custom = exact value\n").as_bytes(),
                    |_| true
                ),
                None,
                "{name}"
            );
        }
        let variants = [None, Some(""), Some("first"), Some("second")];
        let mut keys = Vec::new();
        for value in variants {
            let extra = value.map(|value| ("DEPENDENCY_FLAVOR", value));
            let plan = plan_for(OUT_A, &[], extra.as_slice()).unwrap();
            let keyed =
                live_dependency_key(&plan, &toolchain(), &externs(&plan, 20), &inputs(&plan, 11))
                    .unwrap();
            assert!(!keys.contains(&keyed.action_key));
            keys.push(keyed.action_key);
        }
        let custom = plan_for(
            OUT_A,
            &[],
            &[("DEPENDENCY_FLAVOR", "private compiler environment value")],
        )
        .unwrap();
        let keyed = live_dependency_key(
            &custom,
            &toolchain(),
            &externs(&custom, 20),
            &inputs(&custom, 11),
        )
        .unwrap();
        assert!(
            !String::from_utf8_lossy(&descriptor_canonical_bytes(&keyed.descriptor))
                .contains("private compiler environment value"),
            "durable descriptors carry environment digests, not arbitrary raw values"
        );
        let mut reversed = env(&[("DEPENDENCY_FLAVOR", "first")]);
        reversed.reverse();
        assert_eq!(
            constructed_environment(&reversed),
            constructed_environment(&env(&[("DEPENDENCY_FLAVOR", "first")]))
        );
    }

    #[test]
    fn jobserver_launcher_and_shell_bookkeeping_are_preserved_without_keying_values() {
        let plan = plan_for(OUT_A, &[], &[]).unwrap();
        let controls = [
            ("CARGO_MAKEFLAGS", "-j --jobserver-auth=7,8"),
            ("MAKEFLAGS", "-j4"),
            ("MFLAGS", "-j4"),
            ("RABS_SOCKET", "/tmp/other-rabs.sock"),
            ("CARGO_RABS_LAYOUT_PROJECTION", "1"),
            ("RCH_BUILD_SOURCE", "different-workspace-snapshot"),
            ("PWD", "/work/other"),
            ("OLDPWD", "/work/previous"),
            ("SHLVL", "4"),
            ("_", "/other/cargo"),
        ];
        let other = plan_for(OUT_A, &[], &controls).unwrap();
        assert_eq!(key(&plan), key(&other));
        for (name, value) in controls {
            assert!(other.execution_env.contains(&(name.into(), value.into())));
            assert!(!other.keyed_env.iter().any(|(keyed, _)| keyed == name));
        }
    }

    #[test]
    fn host_placement_preserves_execution_and_requires_fresh_environment_evidence() {
        let base = plan_for(OUT_A, &[], &[]).unwrap();
        let base_key =
            live_dependency_key(&base, &toolchain(), &externs(&base, 20), &inputs(&base, 11))
                .unwrap();
        assert_eq!(
            base_key.descriptor.environment.domain,
            DOMAIN_LIVE_ENVIRONMENT
        );
        for &name in HOST_PLACEMENT_NAMES {
            for value in ["", "/first/job", "/second/job"] {
                let changed = plan_for(OUT_A, &[], &[(name, value)]).unwrap();
                assert_eq!(key(&base), key(&changed), "{name}={value}");
                assert!(
                    changed
                        .execution_env
                        .contains(&(name.to_string(), value.into()))
                );
                assert!(!changed.keyed_env.iter().any(|(keyed, _)| keyed == name));
            }
        }
        let legacy_environment = PresentedEnvironment {
            variables: base
                .keyed_env
                .iter()
                .map(|(name, value)| {
                    (
                        name.as_bytes().to_vec(),
                        EnvDisposition::SemanticHashed(value.as_bytes().to_vec()),
                    )
                })
                .collect(),
            path_manifest: Vec::new(),
        }
        .dataset_digest()
        .unwrap();
        assert_ne!(base_key.descriptor.environment, legacy_environment);
        let mut old_descriptor = base_key.descriptor.clone();
        old_descriptor.environment = legacy_environment;
        assert_ne!(
            base_key.action_key,
            compute_action_key(&old_descriptor).final_key
        );
    }

    #[test]
    fn source_env_reads_finds_literal_env_macro_names_only() {
        let source = br##"
            const A: &str = env!("CARGO_PKG_VERSION");
            const B: Option<&str> = option_env!( "DEPENDENCY_OPTION" );
            const C: &str = std::env!{"BRACED"};
            const D: &str = core::env![r"RAW_PLAIN"];
            const E: Option<&str> = option_env!(
                r#"RAW_HASHED"#
            );
            const F: &str = my_env!("CUSTOM_MACRO");
            const G: &str = env!("CARGO_PKG_VERSION");
            include!(concat!(env!("OUT_DIR"), "/generated.rs"));
            const H: &str = env!(concat!("NOT", "_LITERAL"));
            const I: &str = env!("bad-name");
            const J: &str = env!("ESCAPED\x41");
            const K: &str = "env!";
            const L: &str = env!(r#"UNTERMINATED");
            const M: &str = env!("");
        "##;
        assert_eq!(
            source_env_reads(source),
            [
                "BRACED",
                "CARGO_PKG_VERSION",
                "CUSTOM_MACRO",
                "DEPENDENCY_OPTION",
                "OUT_DIR",
                "RAW_HASHED",
                "RAW_PLAIN",
            ]
        );
        assert!(source_env_reads(b"").is_empty());
        assert!(source_env_reads(b"env!").is_empty());
        assert_eq!(source_env_reads(b"env!(\"END\")"), ["END"]);
    }

    /// Variables that differ between agent sessions on one host. Hashing
    /// them (dependency-env-v2) gave every session its own keys.
    const SESSION_NOISE: &[(&str, &str)] = &[
        ("TMUX_PANE", "%17"),
        ("SSH_AUTH_SOCK", "/tmp/ssh-x/agent.42"),
        ("CARGO_TARGET_DIR", "/work/b/target"),
        ("CARGO_BUILD_JOBS", "3"),
        ("AGENT_SESSION_ID", "agent-b"),
        ("EDITOR", "vi"),
    ];

    fn narrowed(extra: &[(&str, &str)], named: &[&str]) -> DependencyActionPlan {
        let mut plan = plan_for(OUT_A, &[], extra).unwrap();
        let names: Vec<String> = named.iter().map(|name| (*name).to_owned()).collect();
        plan.narrow_to_source_env_reads(&names);
        plan
    }

    #[test]
    fn narrowed_keys_ignore_session_noise_but_keep_compiler_and_cargo_inputs() {
        let base = narrowed(&[], &[]);
        let noisy = narrowed(SESSION_NOISE, &[]);
        assert_eq!(key(&base), key(&noisy), "agent sessions must share keys");
        // The same requests keyed by dependency-env-v2 differ; the narrowed
        // policy is itself part of the key.
        assert_ne!(
            key(&plan_for(OUT_A, &[], &[]).unwrap()),
            key(&plan_for(OUT_A, &[], SESSION_NOISE).unwrap())
        );
        assert_ne!(key(&base), key(&plan_for(OUT_A, &[], &[]).unwrap()));
        // Execution still preserves every binding exactly.
        for (name, value) in SESSION_NOISE {
            assert!(
                noisy
                    .execution_env
                    .contains(&((*name).into(), (*value).into()))
            );
            assert!(!noisy.keyed_env.iter().any(|(keyed, _)| keyed == name));
        }
        for (name, value) in [
            ("RUSTC_LOG", "debug"),
            ("RUST_MIN_STACK", "8388608"),
            ("RUSTC_BOOTSTRAP", "1"),
            ("CARGO_PKG_VERSION", "9.9.9"),
            ("CARGO_PKG_AUTHORS", "someone"),
            ("CARGO_CFG_FEATURE", "x"),
            ("PATH", "/elsewhere/bin"),
            ("TERM", "dumb"),
            ("LD_LIBRARY_PATH", "/toolchain/lib"),
            ("LC_ALL", "C"),
            ("LLVM_PROFILE_FILE", "x.profraw"),
            ("MALLOC_ARENA_MAX", "2"),
            ("SOURCE_DATE_EPOCH", "1"),
            ("MACOSX_DEPLOYMENT_TARGET", "11.0"),
        ] {
            assert_ne!(
                key(&base),
                key(&narrowed(&[(name, value)], &[])),
                "{name} is consumed untracked or presented by Cargo"
            );
        }
    }

    #[test]
    fn narrowed_keys_bind_every_source_named_ambient_value_and_absence() {
        let mut keys = Vec::new();
        for value in [None, Some(""), Some("first"), Some("second")] {
            let extra = value.map(|value| ("DEPENDENCY_FLAVOR", value));
            let plan = narrowed(extra.as_slice(), &["DEPENDENCY_FLAVOR"]);
            let keyed = key(&plan);
            assert!(!keys.contains(&keyed), "{value:?}");
            keys.push(keyed);
        }
        // Naming an ambient variable that is absent is a keyed fact too.
        assert_ne!(
            key(&narrowed(&[], &[])),
            key(&narrowed(&[], &["DEPENDENCY_FLAVOR"]))
        );
        // Session noise still does not split a crate that names one variable.
        assert_eq!(
            key(&narrowed(
                &[("DEPENDENCY_FLAVOR", "x")],
                &["DEPENDENCY_FLAVOR"]
            )),
            key(&narrowed(
                &[SESSION_NOISE, &[("DEPENDENCY_FLAVOR", "x")]].concat(),
                &["DEPENDENCY_FLAVOR"]
            ))
        );
        // Control names stay unkeyed even when a source spells them.
        assert_eq!(
            key(&narrowed(&[("PWD", "/a")], &["PWD"])),
            key(&narrowed(&[("PWD", "/b")], &["PWD"]))
        );
    }

    #[test]
    fn narrowed_plans_veto_tracked_reads_the_key_does_not_cover() {
        let plan = narrowed(
            &[("TMUX_PANE", "%3"), ("NAMED_PRESENT", "v")],
            &["NAMED_PRESENT", "NAMED_ABSENT"],
        );
        let violation = |read: &str| {
            dep_info_closure_violation(&plan, format!("# env-dep:{read}\n").as_bytes(), |_| true)
        };
        for covered in [
            "NAMED_PRESENT=v",
            "NAMED_ABSENT",
            "CARGO_PKG_VERSION=1.0.15",
            "CARGO_FEATURE_STD",
            "RUSTC_BOOTSTRAP",
        ] {
            assert_eq!(violation(covered), None, "{covered}");
        }
        for unkeyed in [
            "TMUX_PANE=%3",
            "UNNAMED_ABSENT",
            "CARGO_TARGET_DIR",
            "PWD",
            "CARGO_MAKEFLAGS=-j --jobserver-fds=3,4",
        ] {
            assert!(
                violation(unkeyed)
                    .is_some_and(|reason| reason.contains("tracked read of unkeyed variable")),
                "{unkeyed}"
            );
        }
        // Unnarrowed (v2) plans keep their meaning: every present non-control
        // value is keyed, so its read and an absent read are both covered.
        let exact = plan_for(OUT_A, &[], &[("TMUX_PANE", "%3")]).unwrap();
        for read in ["TMUX_PANE=%3", "UNNAMED_ABSENT"] {
            assert_eq!(
                dep_info_closure_violation(
                    &exact,
                    format!("# env-dep:{read}\n").as_bytes(),
                    |_| { true }
                ),
                None,
                "{read}"
            );
        }
    }

    #[test]
    fn unkeyed_control_reads_veto_publication_even_when_absent() {
        for name in [
            "MAKEFLAGS",
            "MFLAGS",
            "CARGO_MAKEFLAGS",
            "RABS_TEST_HINT",
            "CARGO_RABS_TEST_HINT",
            "RCH_BUILD_SOURCE",
            "PWD",
            "OLDPWD",
            "SHLVL",
            "_",
        ]
        .into_iter()
        .chain(HOST_PLACEMENT_NAMES.iter().copied())
        {
            let args = argv(OUT_A, &[]);
            let mut absent_env = env(&[]);
            absent_env.retain(|(present, _)| present != name);
            let absent = plan_dependency_action(
                LiveRustcRequest {
                    argv: &args,
                    cwd: PACKAGE,
                    env: &absent_env,
                },
                "x86_64-unknown-linux-gnu",
            )
            .unwrap();
            let present = plan_for(OUT_A, &[], &[(name, "exact-control-value")]).unwrap();
            assert_eq!(key(&absent), key(&present), "{name}");
            for (plan, read) in [
                (&absent, format!("# env-dep:{name}\n")),
                (&present, format!("# env-dep:{name}=exact-control-value\n")),
            ] {
                assert!(
                    dep_info_closure_violation(plan, read.as_bytes(), |_| true)
                        .unwrap()
                        .contains("tracked read of unkeyed variable"),
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn semantic_environment_paths_cannot_be_rewritten_as_output_placement() {
        let a = plan_for(OUT_A, &[], &[("DEPENDENCY_FLAVOR", OUT_A)]).unwrap();
        let b = plan_for(OUT_B, &[], &[("DEPENDENCY_FLAVOR", OUT_A)]).unwrap();
        assert_eq!(key(&a), key(&b), "only output placement changed");
        let read = format!("# env-dep:DEPENDENCY_FLAVOR={OUT_A}\n");
        assert!(
            dep_info_closure_violation(&a, read.as_bytes(), |_| true)
                .unwrap()
                .contains("contains compiler output placement")
        );
        assert_eq!(
            dep_info_closure_violation(&b, read.as_bytes(), |_| true),
            None
        );
        assert_eq!(
            canonicalize_placements(read.as_bytes(), &b).unwrap(),
            read.as_bytes()
        );
        for suffix in ["/generated", "-suffix"] {
            let value = format!("{OUT_A}{suffix}");
            let plan = plan_for(OUT_A, &[], &[("DEPENDENCY_FLAVOR", &value)]).unwrap();
            assert!(
                dep_info_closure_violation(
                    &plan,
                    format!("# env-dep:DEPENDENCY_FLAVOR={value}\n").as_bytes(),
                    |_| true
                )
                .is_some()
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn real_rustc_custom_environment_matches_stock_compiler_outputs() {
        use std::path::Path;
        use std::process::{Command, Output};

        fn successful(command: &mut Command) -> Output {
            let output = command.output().expect("execute real rustc fixture");
            assert!(
                output.status.success(),
                "{command:?}: {}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            output
        }

        let sysroot = successful(Command::new("rustc").args(["--print", "sysroot"]));
        let rustc = Path::new(String::from_utf8(sysroot.stdout).unwrap().trim()).join("bin/rustc");
        let version = successful(Command::new(&rustc).arg("-vV"));
        let version = String::from_utf8(version.stdout).unwrap();
        let host = version
            .lines()
            .find_map(|line| line.strip_prefix("host: "))
            .unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let cargo_home = temporary.path().join("cargo-home");
        let package =
            cargo_home.join("registry/src/index.example-0123456789abcdef/env_fixture-1.0.0");
        std::fs::create_dir_all(package.join("src")).unwrap();
        std::fs::write(
            package.join("Cargo.toml"),
            "[package]\nname='env_fixture'\nversion='1.0.0'\nedition='2021'\n",
        )
        .unwrap();
        let source = package.join("src/lib.rs");
        std::fs::write(
            &source,
            "pub fn message() -> String {\n\
             format!(\"{}|{:?}\", env!(\"DEPENDENCY_FLAVOR\"), option_env!(\"DEPENDENCY_OPTION\"))\n\
             }\n",
        )
        .unwrap();
        let driver_source = temporary.path().join("main.rs");
        std::fs::write(
            &driver_source,
            "fn main() { println!(\"{}\", env_fixture::message()); }\n",
        )
        .unwrap();
        for (index, optional, expected) in [
            (0, None, "strawberry|None\n"),
            (1, Some(""), "strawberry|Some(\"\")\n"),
            (2, Some("extra"), "strawberry|Some(\"extra\")\n"),
        ] {
            let stock_dir = temporary.path().join(format!("stock-{index}"));
            let executed_dir = temporary.path().join(format!("executed-{index}"));
            std::fs::create_dir_all(&stock_dir).unwrap();
            std::fs::create_dir_all(&executed_dir).unwrap();
            let mut environment = vec![
                ("HOME".into(), temporary.path().display().to_string()),
                ("CARGO_HOME".into(), cargo_home.display().to_string()),
                ("CARGO_MANIFEST_DIR".into(), package.display().to_string()),
                ("CARGO_PKG_NAME".into(), "env_fixture".into()),
                ("CARGO_PKG_VERSION".into(), "1.0.0".into()),
                ("DEPENDENCY_FLAVOR".into(), "strawberry".into()),
                (
                    "PATH".into(),
                    std::env::var("PATH").expect("real toolchain PATH"),
                ),
            ];
            if let Some(value) = optional {
                environment.push(("DEPENDENCY_OPTION".into(), value.into()));
            }
            let arguments = |out: &Path| {
                vec![
                    rustc.display().to_string(),
                    "--crate-name=env_fixture".into(),
                    "--edition=2021".into(),
                    source.display().to_string(),
                    "--error-format=json".into(),
                    "--json=artifacts".into(),
                    "--crate-type=lib".into(),
                    "--emit=dep-info,metadata,link".into(),
                    "--cap-lints=allow".into(),
                    "--out-dir".into(),
                    out.display().to_string(),
                ]
            };
            let stock_argv = arguments(&stock_dir);
            let stock = successful(
                Command::new(&rustc)
                    .args(&stock_argv[1..])
                    .env_clear()
                    .envs(environment.iter().cloned())
                    .current_dir(&package),
            );
            let executed_argv = arguments(&executed_dir);
            let plan = plan_dependency_action(
                LiveRustcRequest {
                    argv: &executed_argv,
                    cwd: package.to_str().unwrap(),
                    env: &environment,
                },
                host,
            )
            .unwrap();
            let executed = successful(
                Command::new(&rustc)
                    .args(&executed_argv[1..])
                    .env_clear()
                    .envs(plan.execution_env.iter().cloned())
                    .current_dir(&package),
            );
            assert!(stock.stdout.is_empty());
            assert!(executed.stdout.is_empty());
            assert_eq!(
                canonicalize_out_dir(&stock.stderr, stock_dir.to_str().unwrap()).unwrap(),
                canonicalize_compiler_transcript(&executed.stderr, &plan).unwrap()
            );
            for name in plan.output_names() {
                let stock_bytes = std::fs::read(stock_dir.join(&name)).unwrap();
                let executed_bytes = std::fs::read(executed_dir.join(&name)).unwrap();
                if name.ends_with(".d") {
                    assert_eq!(
                        dep_info_closure_violation(&plan, &executed_bytes, |_| true),
                        None
                    );
                    // dependency-env-v3 keys exactly what the source names,
                    // so the narrowed plan publishes too; narrowing without
                    // the scan must refuse the same real tracked reads.
                    let names = source_env_reads(&std::fs::read(&source).unwrap());
                    assert_eq!(names, ["DEPENDENCY_FLAVOR", "DEPENDENCY_OPTION"]);
                    let mut scanned = plan.clone();
                    scanned.narrow_to_source_env_reads(&names);
                    assert_eq!(
                        dep_info_closure_violation(&scanned, &executed_bytes, |_| true),
                        None
                    );
                    let mut unscanned = plan.clone();
                    unscanned.narrow_to_source_env_reads(&[]);
                    assert!(
                        dep_info_closure_violation(&unscanned, &executed_bytes, |_| true)
                            .is_some_and(|reason| reason.contains("DEPENDENCY_"))
                    );
                    assert_eq!(
                        canonicalize_out_dir(&stock_bytes, stock_dir.to_str().unwrap()).unwrap(),
                        canonicalize_placements(&executed_bytes, &plan).unwrap()
                    );
                } else {
                    assert_eq!(stock_bytes, executed_bytes, "{name}");
                }
            }
            let driver = temporary.path().join(format!("driver-{index}"));
            successful(
                Command::new(&rustc)
                    .arg(&driver_source)
                    .arg("--edition=2021")
                    .arg("--extern")
                    .arg(format!(
                        "env_fixture={}",
                        executed_dir.join("libenv_fixture.rlib").display()
                    ))
                    .arg("-o")
                    .arg(&driver),
            );
            assert_eq!(
                successful(&mut Command::new(driver)).stdout,
                expected.as_bytes()
            );
        }
    }

    #[test]
    fn narrowing_keeps_the_exact_out_dir_lane_for_generated_file_consumers() {
        const GENERATED_A: &str = "/work/a/target/debug/build/itoa-0123/out";
        const GENERATED_B: &str = "/elsewhere/b/target/debug/build/itoa-0123/out";
        let narrowed = |out: &str, generated: &str| {
            let mut plan = plan_for(out, &[], &[("OUT_DIR", generated)]).unwrap();
            plan.narrow_to_source_env_reads(&[]);
            plan
        };
        let manifest = |plan: &DependencyActionPlan, tag: u8| {
            let mut manifest = inputs(plan, 11);
            manifest.inputs.push(PositiveInput {
                virtual_path: RawBytes::new(
                    plan.generated_input_virtual_path("value.rs").into_bytes(),
                ),
                object: ObjectId(digest(tag)),
                file_type: InputFileType::Regular,
                executable: false,
                symlink_resolution: Vec::new(),
            });
            manifest.directory_enumerations[0].entries = vec![RawBytes::from("value.rs")];
            manifest
        };
        let keyed = |plan: &DependencyActionPlan, tag: u8| {
            live_dependency_key(plan, &toolchain(), &externs(plan, 20), &manifest(plan, tag))
                .unwrap()
                .action_key
        };
        let a = narrowed(OUT_A, GENERATED_A);
        let b = narrowed(OUT_B, GENERATED_B);
        // Generated-file consumers keep the exact-path lane: the spelling
        // stays keyed (a captured EMPTY tree is projected separately, by the
        // edge's opt-in empty-OUT_DIR class), and contents stay keyed.
        assert_ne!(keyed(&a, 40), keyed(&b, 40));
        assert_ne!(keyed(&a, 40), keyed(&a, 41));
        assert!(
            a.keyed_env
                .contains(&("OUT_DIR".into(), GENERATED_A.into()))
        );
        let covered = |path: &str| {
            manifest(&a, 40)
                .inputs
                .iter()
                .any(|input| input.virtual_path.as_bytes() == path.as_bytes())
        };
        let reads = format!(
            "{OUT_A}/itoa.d: {PACKAGE}/src/lib.rs {GENERATED_A}/value.rs\n\
             {GENERATED_A}/value.rs:\n# env-dep:OUT_DIR={GENERATED_A}\n"
        );
        assert_eq!(
            dep_info_closure_violation(&a, reads.as_bytes(), covered),
            None
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
        manifest.directory_enumerations[0].entries = vec![RawBytes::from("value.rs")];
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

    fn generated_listing(
        plan: &DependencyActionPlan,
        relative: &str,
        entries: &[&str],
    ) -> DirectoryEnumeration {
        DirectoryEnumeration {
            virtual_path: RawBytes::new(
                if relative.is_empty() {
                    plan.generated_virtual_root()
                } else {
                    plan.generated_input_virtual_path(relative)
                }
                .into_bytes(),
            ),
            entries: entries.iter().map(|entry| RawBytes::from(*entry)).collect(),
        }
    }

    #[test]
    fn generated_empty_directory_topology_changes_action_identity() {
        let plan = plan_for(OUT_A, &[], &[("OUT_DIR", "/work/generated")]).unwrap();
        let empty = inputs(&plan, 11);
        assert!(
            generated_input_directories(&plan, &empty)
                .unwrap()
                .is_empty()
        );
        let keyed = |manifest: &ActionInputManifest| {
            live_dependency_key(&plan, &toolchain(), &externs(&plan, 20), manifest)
                .unwrap()
                .action_key
        };
        let empty_key = keyed(&empty);
        let mut directories = empty.clone();
        directories.directory_enumerations = vec![
            generated_listing(&plan, "", &["empty"]),
            generated_listing(&plan, "empty", &[]),
        ];
        assert_eq!(
            generated_input_directories(&plan, &directories).unwrap(),
            ["empty"]
        );
        let directory_key = keyed(&directories);
        assert_ne!(empty_key, directory_key);

        let mut renamed = empty.clone();
        renamed.directory_enumerations = vec![
            generated_listing(&plan, "", &["renamed"]),
            generated_listing(&plan, "renamed", &[]),
        ];
        assert_ne!(directory_key, keyed(&renamed));

        let mut nested = directories.clone();
        nested.directory_enumerations[1] = generated_listing(&plan, "empty", &["child"]);
        nested
            .directory_enumerations
            .push(generated_listing(&plan, "empty/child", &[]));
        assert_eq!(
            generated_input_directories(&plan, &nested).unwrap(),
            ["empty", "empty/child"]
        );
        assert_ne!(directory_key, keyed(&nested));
        assert_ne!(empty_key, keyed(&nested));
        nested.directory_enumerations.reverse();
        let mut ordered = nested.clone();
        ordered.directory_enumerations.reverse();
        assert_eq!(keyed(&nested), keyed(&ordered));
        assert_eq!(empty.inputs, directories.inputs);
        assert_eq!(empty.inputs, nested.inputs);
    }

    #[test]
    fn generated_directory_evidence_must_match_every_file_and_directory() {
        let plan = plan_for(OUT_A, &[], &[("OUT_DIR", "/work/generated")]).unwrap();
        let mut good = inputs(&plan, 11);
        good.inputs.push(PositiveInput {
            virtual_path: RawBytes::new(
                plan.generated_input_virtual_path("nested/value.rs")
                    .into_bytes(),
            ),
            object: ObjectId(digest(42)),
            file_type: InputFileType::Regular,
            executable: false,
            symlink_resolution: Vec::new(),
        });
        good.directory_enumerations = vec![
            generated_listing(&plan, "", &["empty", "nested"]),
            generated_listing(&plan, "empty", &["child"]),
            generated_listing(&plan, "empty/child", &[]),
            generated_listing(&plan, "nested", &["value.rs"]),
        ];
        assert_eq!(
            generated_input_directories(&plan, &good).unwrap(),
            ["empty", "empty/child", "nested"]
        );
        assert!(live_dependency_key(&plan, &toolchain(), &externs(&plan, 20), &good).is_ok());
        for fault in 0..15 {
            let mut invalid = good.clone();
            match fault {
                0 => invalid.directory_enumerations.clear(),
                1 => {
                    invalid.directory_enumerations.remove(0);
                }
                2 => {
                    invalid.directory_enumerations.remove(1);
                }
                3 => {
                    invalid.directory_enumerations.remove(3);
                }
                4 => invalid
                    .directory_enumerations
                    .push(good.directory_enumerations[0].clone()),
                5 => invalid.directory_enumerations[1].virtual_path = RawBytes::from("/outside"),
                6 => invalid.directory_enumerations[0]
                    .entries
                    .push(RawBytes::from("unobserved")),
                7 => {
                    invalid.directory_enumerations[0].entries = vec![
                        RawBytes::from("empty"),
                        RawBytes::from("empty"),
                        RawBytes::from("nested"),
                    ]
                }
                8 => invalid.directory_enumerations[0].entries.reverse(),
                9 => invalid.directory_enumerations[0].entries[0] = RawBytes::from("../escape"),
                10 => invalid.directory_enumerations[3].entries.clear(),
                11 => {
                    invalid.inputs.last_mut().unwrap().virtual_path =
                        RawBytes::new(plan.generated_input_virtual_path("nested").into_bytes())
                }
                12 => {
                    invalid.inputs.last_mut().unwrap().virtual_path = RawBytes::new(
                        plan.generated_input_virtual_path("nested/../value.rs")
                            .into_bytes(),
                    )
                }
                13 => invalid.inputs.last_mut().unwrap().file_type = InputFileType::Symlink,
                14 => {
                    invalid.directory_enumerations[2].virtual_path = RawBytes::new(
                        plan.generated_input_virtual_path("empty/./child")
                            .into_bytes(),
                    )
                }
                _ => unreachable!(),
            }
            assert!(
                generated_input_directories(&plan, &invalid).is_err(),
                "fault {fault}"
            );
            assert!(
                live_dependency_key(&plan, &toolchain(), &externs(&plan, 20), &invalid).is_err(),
                "fault {fault}"
            );
        }
        let no_generated = plan_for(OUT_A, &[], &[]).unwrap();
        assert!(generated_input_directories(&no_generated, &good).is_err());
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
    fn explicit_frontend_thread_counts_are_admitted_and_remain_keyed() {
        let implicit = plan_for(OUT_A, &[], &[]).unwrap();
        let one = plan_for(OUT_A, &["-Z", "threads=1"], &[]).unwrap();
        let eight = plan_for(OUT_A, &["-Z", "threads=8"], &[]).unwrap();
        let joined_eight = plan_for(OUT_A, &["-Zthreads=8"], &[]).unwrap();
        assert_eq!(
            eight.invocation.unstable,
            [("threads".to_owned(), Some("8".to_owned()))]
        );
        assert_eq!(key(&eight), key(&joined_eight));
        assert_ne!(key(&implicit), key(&one));
        assert_ne!(key(&one), key(&eight));
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
            code(plan_for(OUT_A, &["-Z", "no-codegen"], &[])),
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
    fn compiler_transcript_rewrites_only_declared_artifact_fields_byte_for_byte() {
        let a = plan_for(OUT_A, &[], &[]).unwrap();
        let b = plan_for(OUT_B, &[], &[]).unwrap();
        let diagnostic = [
            br#"{ "$message_type" : "diagnostic", "message":"retain \"quotes\" and \u2603", "spans":[] }"#.as_slice(),
            b"\r\n",
        ].concat();
        for output in &a.outputs.declarations {
            let emit = match output.class {
                crate::output_declarations::OutputClass::ProvisionalMetadata => "metadata",
                crate::output_declarations::OutputClass::DepInfo => "dep-info",
                crate::output_declarations::OutputClass::File => "link",
                _ => panic!("unexpected fixture output"),
            };
            // Nonstandard whitespace and ordering must survive without JSON
            // reserialization; ordinary diagnostics remain an exact prefix.
            let event = format!(
                "  {{ \"emit\" : \"{emit}\", \"artifact\" : \"{OUT_A}/{}\", \"$message_type\" : \"artifact\" }}\r\n",
                output.virtual_path
            );
            let raw = [diagnostic.as_slice(), event.as_bytes()].concat();
            let canonical = canonicalize_compiler_transcript(&raw, &a).unwrap();
            assert!(canonical.starts_with(&diagnostic));
            assert_eq!(render_compiler_transcript(&canonical, &a), raw);
            let expected = [
                diagnostic.as_slice(),
                event.replace(OUT_A, OUT_B).as_bytes(),
            ]
            .concat();
            assert_eq!(render_compiler_transcript(&canonical, &b), expected);
            let decoded: serde_json::Value =
                serde_json::from_slice(&canonical[diagnostic.len()..]).unwrap();
            assert_eq!(
                decoded["artifact"],
                format!("{CANONICAL_OUT_DIR}/{}", output.virtual_path)
            );
        }
        assert!(
            canonicalize_compiler_transcript(&[], &a)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn real_rustc_dep_info_then_metadata_is_an_early_replay_prefix() {
        use std::path::Path;
        use std::process::{Command, Output, Stdio};

        fn successful(command: &mut Command) -> Output {
            let output = command.stdin(Stdio::inherit()).output().unwrap();
            assert!(
                output.status.success(),
                "{command:?}: {}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr),
            );
            output
        }
        let sysroot = successful(Command::new("rustc").args(["--print", "sysroot"]));
        let compiler =
            Path::new(std::str::from_utf8(&sysroot.stdout).unwrap().trim()).join("bin/rustc");
        let version = successful(Command::new(&compiler).arg("-vV"));
        let version = std::str::from_utf8(&version.stdout).unwrap();
        let host = version
            .lines()
            .find_map(|line| line.strip_prefix("host: "))
            .unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let cargo_home = temporary.path().join("cargo-home");
        let package =
            cargo_home.join("registry/src/index.example-0123456789abcdef/metadata_fixture-1.0.0");
        let out = temporary.path().join("target/deps");
        std::fs::create_dir_all(package.join("src")).unwrap();
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(
            package.join("Cargo.toml"),
            "[package]\nname='metadata_fixture'\nversion='1.0.0'\nedition='2021'\n",
        )
        .unwrap();
        let source = package.join("src/lib.rs");
        std::fs::write(&source, "pub fn answer() -> u32 { 42 }\n").unwrap();
        let environment = vec![
            ("CARGO_HOME".into(), cargo_home.display().to_string()),
            ("CARGO_MANIFEST_DIR".into(), package.display().to_string()),
            ("CARGO_PKG_NAME".into(), "metadata_fixture".into()),
            ("CARGO_PKG_VERSION".into(), "1.0.0".into()),
        ];
        let argv = vec![
            compiler.display().to_string(),
            "--crate-name=metadata_fixture".into(),
            "--edition=2021".into(),
            source.display().to_string(),
            "--crate-type=lib".into(),
            "--emit=dep-info,metadata,link".into(),
            "--error-format=json".into(),
            "--json=artifacts".into(),
            "--cap-lints=allow".into(),
            "--out-dir".into(),
            out.display().to_string(),
        ];
        let plan = plan_dependency_action(
            LiveRustcRequest {
                argv: &argv,
                cwd: package.to_str().unwrap(),
                env: &environment,
            },
            host,
        )
        .unwrap();
        let output = successful(
            Command::new(&compiler)
                .args(&argv[1..])
                .current_dir(&package)
                .env_clear()
                .envs(plan.execution_env.iter().cloned()),
        );
        assert!(output.stdout.is_empty());
        let boundary = metadata_replay_prefix_len(&output.stderr, &plan)
            .unwrap()
            .expect("real dep-info before metadata must permit early replay");
        let events = |bytes: &[u8]| -> Vec<String> {
            std::str::from_utf8(bytes)
                .unwrap()
                .lines()
                .filter_map(|line| {
                    let event: serde_json::Value = serde_json::from_str(line).unwrap();
                    (event["$message_type"] == "artifact")
                        .then(|| event["emit"].as_str().unwrap().to_owned())
                })
                .collect()
        };
        assert_eq!(events(&output.stderr[..boundary]), ["dep-info", "metadata"]);
        assert_eq!(events(&output.stderr[boundary..]), ["link"]);
        for name in plan.output_names() {
            assert!(std::fs::metadata(out.join(name)).unwrap().len() > 0);
        }
        let canonical = canonicalize_compiler_transcript(&output.stderr, &plan).unwrap();
        assert_eq!(render_compiler_transcript(&canonical, &plan), output.stderr);
    }

    #[test]
    fn metadata_replay_preserves_exact_prefix_and_terminal_suffix() {
        let plan = plan_for(OUT_A, &[], &[]).unwrap();
        let metadata = plan
            .outputs
            .declarations
            .iter()
            .find(|output| {
                output.class == crate::output_declarations::OutputClass::ProvisionalMetadata
            })
            .unwrap();
        let archive = plan
            .outputs
            .declarations
            .iter()
            .find(|output| output.class == crate::output_declarations::OutputClass::File)
            .unwrap();
        let dep_info = plan
            .outputs
            .declarations
            .iter()
            .find(|output| output.class == crate::output_declarations::OutputClass::DepInfo)
            .unwrap();
        let prefix = format!(
            "{{\"$message_type\":\"diagnostic\",\"message\":\"retain whitespace\"}}\r\n{{\"$message_type\":\"artifact\",\"artifact\":\"{OUT_A}/{}\",\"emit\":\"dep-info\"}}\n  {{ \"emit\" : \"metadata\", \"artifact\" : \"{OUT_A}/{}\", \"$message_type\" : \"artifact\" }}\r\n",
            dep_info.virtual_path, metadata.virtual_path
        );
        let suffix = format!(
            "{{\"$message_type\":\"diagnostic\",\"message\":\"later warning\"}}\n{{\"$message_type\":\"artifact\",\"artifact\":\"{OUT_A}/{}\",\"emit\":\"link\"}}\n",
            archive.virtual_path
        );
        let transcript = [prefix.as_bytes(), suffix.as_bytes()].concat();
        let boundary = metadata_replay_prefix_len(&transcript, &plan)
            .unwrap()
            .unwrap();
        assert_eq!(&transcript[..boundary], prefix.as_bytes());
        assert_eq!(&transcript[boundary..], suffix.as_bytes());
        assert_eq!(
            [&transcript[..boundary], &transcript[boundary..]].concat(),
            transcript
        );
    }

    #[test]
    fn metadata_replay_never_passes_unready_or_ambiguous_artifact_events() {
        let plan = plan_for(OUT_A, &[], &[]).unwrap();
        let metadata = format!(
            "{{\"$message_type\":\"artifact\",\"artifact\":\"{OUT_A}/libitoa-c2b2f4e1a6d0b3c9.rmeta\",\"emit\":\"metadata\"}}\n"
        );
        let archive = format!(
            "{{\"$message_type\":\"artifact\",\"artifact\":\"{OUT_A}/libitoa-c2b2f4e1a6d0b3c9.rlib\",\"emit\":\"link\"}}\n"
        );
        for transcript in [
            Vec::new(),
            archive.as_bytes().to_vec(),
            [archive.as_bytes(), metadata.as_bytes()].concat(),
            [metadata.as_bytes(), metadata.as_bytes()].concat(),
            [metadata.as_bytes(), archive.as_bytes(), metadata.as_bytes()].concat(),
        ] {
            assert_eq!(metadata_replay_prefix_len(&transcript, &plan), Ok(None));
        }
        for transcript in [
            metadata.replace("libitoa-", "libforeign-"),
            metadata.replace("\"metadata\"", "\"link\""),
            metadata.replace("\"$message_type\"", "\"\\u0024message_type\""),
            metadata.replace("/libitoa", "\\/libitoa"),
        ] {
            assert!(metadata_replay_prefix_len(transcript.as_bytes(), &plan).is_err());
        }
    }

    #[test]
    fn compiler_transcript_refuses_source_authored_placement_and_ambiguous_events() {
        let plan = plan_for(OUT_A, &[], &[]).unwrap();
        let path = format!("{OUT_A}/libitoa-c2b2f4e1a6d0b3c9.rmeta");
        for raw in [
            format!(
                "{{\"$message_type\":\"diagnostic\",\"message\":\"deprecated note: {OUT_A}\"}}\n"
            ),
            format!("{{\"message\":\"literal {OUT_A}-backup\"}}\n"),
            format!("{{\"message\":\"nested\",\"span\":{{\"artifact\":\"{path}\"}}}}\n"),
            format!(
                "{{\"$message_type\":\"artifact\",\"artifact\":\"{path}\",\"emit\":\"link\"}}\n"
            ),
            format!(
                "{{\"$message_type\":\"artifact\",\"artifact\":\"{OUT_A}-backup/file.rmeta\",\"emit\":\"metadata\"}}\n"
            ),
            format!(
                "{{\"$message_type\":\"artifact\",\"artifact\":\"{OUT_A}/undeclared.rmeta\",\"emit\":\"metadata\"}}\n"
            ),
            format!(
                "{{\"$message_type\":\"artifact\",\"artifact\":\"{path}\",\"emit\":\"metadata\",\"note\":\"extra field\"}}\n"
            ),
            format!(
                "{{\"$message_type\":\"artifact\",\"artifact\":\"{path}\",\"artifact\":\"{path}\",\"emit\":\"metadata\"}}\n"
            ),
            format!(
                "{{\"$message_type\":\"artifact\",\"artifact\":\"{}\",\"emit\":\"metadata\"}}\n",
                path.replace('/', "\\/")
            ),
            format!(
                "{{\"$message_type\":\"artifact\",\"artifact\":\"{path}\",\"emit\":\"metadata\"}} trailing"
            ),
            format!(
                r#"{{"message":"escaped literal {}"}}"#,
                OUT_A.replace('/', r"\/")
            ),
            format!(
                r#"{{"message":"Unicode literal {}"}}"#,
                OUT_A.replace('/', r"\u002f")
            ),
            format!(
                r#"{{"\u0024message_type":"ar\u0074ifact","artifact":"{}","emit":"metadata"}}"#,
                path.replace('/', r"\u002f")
            ),
            r#"{"$message_type":"ar\u0074ifact","artifact":"/unrelated/result.rmeta","emit":"metadata"}"#.into(),
            format!(
                r#"{{"$message_type":"artifact","$message_type":"diagnostic","artifact":"{}","emit":"metadata"}}"#,
                path.replace('/', r"\u002f")
            ),
            r#"{"message":"literal \u002f__rabs\u002fout"}"#.into(),
            r#"{"message":"invalid \q escape"}"#.into(),
            r#"{"message":"invalid \ud800 surrogate"}"#.into(),
            "{\"message\":\"literal /__rabs/out\"}\n".into(),
        ] {
            assert!(
                canonicalize_compiler_transcript(raw.as_bytes(), &plan).is_err(),
                "{raw}"
            );
        }
    }

    #[test]
    fn transcript_string_observer_matches_json_decoding_without_changing_bytes() {
        let plan = plan_for(OUT_A, &[], &[]).unwrap();
        for encoded in [
            r#""plain""#,
            r#""quoted \"content\" and \\slashes\\""#,
            r#""line\ncarriage\rtab\tbackspace\bformfeed\f""#,
            r#""\u0061\u0062\u0063 \u2603 \ud83d\ude80""#,
            r#""literal \\u002f and \\/""#,
            "\"literal snowman ☃\"",
        ] {
            let mut at = 0;
            let decoded = transcript_string(encoded.as_bytes(), &mut at).unwrap();
            assert_eq!(at, encoded.len());
            let expected: String = serde_json::from_str(encoded).unwrap();
            assert_eq!(decoded, expected.as_bytes());
            let line = format!("{{\"$message_type\":\"diagnostic\",\"message\":{encoded}}}\n");
            assert_eq!(
                canonicalize_compiler_transcript(line.as_bytes(), &plan).unwrap(),
                line.as_bytes(),
                "valid diagnostic escaping must remain byte-identical"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_rustc_diagnostic_literals_survive_replay_to_another_output_directory() {
        use std::path::Path;
        use std::process::Command;

        let sysroot = Command::new("rustc")
            .args(["--print", "sysroot"])
            .output()
            .unwrap();
        assert!(
            sysroot.status.success(),
            "{}",
            String::from_utf8_lossy(&sysroot.stderr)
        );
        let compiler =
            Path::new(std::str::from_utf8(&sysroot.stdout).unwrap().trim()).join("bin/rustc");
        let version = Command::new(&compiler).arg("-vV").output().unwrap();
        assert!(
            version.status.success(),
            "{}",
            String::from_utf8_lossy(&version.stderr)
        );
        let version = std::str::from_utf8(&version.stdout).unwrap();
        let host = version
            .lines()
            .find_map(|line| line.strip_prefix("host: "))
            .unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let cargo_home = temporary.path().join("cargo-home");
        let package =
            cargo_home.join("registry/src/index.example-0123456789abcdef/diagnostic_fixture-1.0.0");
        let first_out = temporary.path().join("first-out");
        let second_out = temporary.path().join("second-out");
        for directory in [&package, &first_out, &second_out] {
            std::fs::create_dir_all(directory).unwrap();
        }
        let source = package.join("lib.rs");
        std::fs::write(
            &source,
            format!(
                "#[deprecated(note = {:?})]\npub fn old() {{}}\npub fn invoke() {{ old(); }}\n",
                first_out.to_str().unwrap()
            ),
        )
        .unwrap();
        let environment = vec![
            ("CARGO_HOME".into(), cargo_home.display().to_string()),
            ("CARGO_MANIFEST_DIR".into(), package.display().to_string()),
            ("CARGO_PKG_NAME".into(), "diagnostic_fixture".into()),
            ("CARGO_PKG_VERSION".into(), "1.0.0".into()),
        ];
        let compile = |out: &Path| {
            let argv = vec![
                compiler.display().to_string(),
                "--crate-name=diagnostic_fixture".into(),
                "--edition=2021".into(),
                source.display().to_string(),
                "--error-format=json".into(),
                "--json=artifacts,diagnostic-rendered-ansi".into(),
                "--crate-type=lib".into(),
                "--emit=dep-info,metadata".into(),
                "--cap-lints=allow".into(),
                "--force-warn=deprecated".into(),
                "--out-dir".into(),
                out.display().to_string(),
            ];
            let plan = plan_dependency_action(
                LiveRustcRequest {
                    argv: &argv,
                    cwd: package.to_str().unwrap(),
                    env: &environment,
                },
                host,
            )
            .unwrap();
            let output = Command::new(&compiler)
                .args(&argv[1..])
                .current_dir(&package)
                .env_clear()
                .envs(plan.execution_env.iter().cloned())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(output.stdout.is_empty());
            let diagnostics = std::str::from_utf8(&output.stderr).unwrap();
            assert!(
                diagnostics.lines().any(|line| {
                    let value: serde_json::Value = serde_json::from_str(line).unwrap();
                    value["message"]
                        .as_str()
                        .is_some_and(|message| message.contains(first_out.to_str().unwrap()))
                }),
                "real compiler must emit the source-authored path in its warning"
            );
            (plan, output.stderr)
        };
        let (first_plan, first_transcript) = compile(&first_out);
        let (second_plan, second_transcript) = compile(&second_out);
        // A first-output-root occurrence in diagnostic prose is ambiguous,
        // even though artifact notifications themselves are safely rewritable.
        assert!(canonicalize_compiler_transcript(&first_transcript, &first_plan).is_err());
        // Capturing the same source in another output directory must retain
        // that literal, then reproduce stock rustc's EXACT bytes at both roots.
        let canonical = canonicalize_compiler_transcript(&second_transcript, &second_plan).unwrap();
        assert_eq!(
            render_compiler_transcript(&canonical, &second_plan),
            second_transcript
        );
        assert_eq!(
            render_compiler_transcript(&canonical, &first_plan),
            first_transcript
        );
    }

    #[test]
    fn dep_info_does_not_relocate_source_paths_with_output_prefixes_or_substrings() {
        let a = plan_for(OUT_A, &[], &[]).unwrap();
        let b = plan_for(OUT_B, &[], &[]).unwrap();
        let source_prefix = format!("{OUT_A}-source/src/lib.rs");
        let source_substring = format!("/unrelated{OUT_A}/src/lib.rs");
        let raw = format!(
            "{OUT_A}/libitoa.rmeta: {source_prefix} {source_substring}\n\n{source_prefix}:\n{source_substring}:\n"
        );
        let canonical = canonicalize_placements(raw.as_bytes(), &a).unwrap();
        assert_eq!(render_placements(&canonical, &a), raw.as_bytes());
        assert_eq!(
            render_placements(&canonical, &b),
            raw.replacen(
                &format!("{OUT_A}/libitoa.rmeta"),
                &format!("{OUT_B}/libitoa.rmeta"),
                1
            )
            .as_bytes()
        );
    }

    #[test]
    fn empty_metadata_is_retained_in_keys_but_cannot_be_an_explicit_extern() {
        let plan = plan_for(OUT_A, &[], &[]).unwrap();
        let mut direct = externs(&plan, 20);
        let original = super::live_dependency_key(
            &plan,
            &toolchain(),
            &direct,
            &directory_facts(&plan, &direct),
            None,
            &inputs(&plan, 11),
        )
        .unwrap();
        let mut candidates = directory_facts(&plan, &direct);
        let empty = ExternFact {
            path: format!("{}/libzzbinary.rmeta", plan.dependency_dirs[0]),
            content_digest: empty_metadata_object_digest(),
        };
        assert!(is_empty_metadata_artifact(
            &empty.path,
            &empty.content_digest
        ));
        candidates[0].artifacts.push(empty.clone());
        let with_empty = super::live_dependency_key(
            &plan,
            &toolchain(),
            &direct,
            &candidates,
            None,
            &inputs(&plan, 11),
        )
        .unwrap();
        assert_ne!(with_empty.action_key, original.action_key);
        for path in ["libbinary.rlib", "libbinary.so", "binary.rmeta"] {
            assert!(!is_empty_metadata_artifact(path, &empty.content_digest));
        }
        let mut wrong_domain = empty.content_digest.clone();
        wrong_domain.domain = "rabs.test.v1";
        assert!(!is_empty_metadata_artifact(&empty.path, &wrong_domain));
        let mut different = empty.content_digest.clone();
        different.bytes[0] ^= 1;
        assert!(!is_empty_metadata_artifact(&empty.path, &different));

        direct[0].content_digest = empty_metadata_object_digest();
        assert!(matches!(
            super::live_dependency_key(
                &plan,
                &toolchain(),
                &direct,
                &directory_facts(&plan, &direct),
                None,
                &inputs(&plan, 11),
            ),
            Err(LiveRefusal::Extern(_))
        ));
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
    fn binary_dep_info_requires_exact_members_and_preserves_negative_candidates() {
        let plan = plan_for(OUT_A, &["-Zbinary-dep-depinfo"], &[]).unwrap();
        let binary = format!("{OUT_A}/libdep-0123456789abcdef.rmeta");
        let sysroot = "/toolchain/lib/rustlib/x86_64-unknown-linux-gnu/lib/libstd-123.rlib";
        let source = format!("{PACKAGE}/src/lib.rs");
        let raw = format!(
            "{OUT_A}/itoa.d: {source} {binary} {sysroot}\n\n\
             {source}:\n{binary}:\n{sysroot}:\n"
        );
        let keyed = |path: &str| {
            path == plan.input_virtual_path("src/lib.rs")
                || path == plan.virtual_dependency_path(&binary)
                || path == sysroot
        };
        assert!(plan.records_binary_dependencies());
        assert_eq!(
            dep_info_closure_violation(&plan, raw.as_bytes(), keyed),
            None
        );
        for path in [
            format!("{OUT_A}/libunobserved.rmeta"),
            format!(
                "{OUT_A}/libunobserved.rmeta/../{}",
                "libdep-0123456789abcdef.rmeta"
            ),
            format!("{OUT_A}/libmacro.so"),
            format!("{OUT_A}/nested/libdep-0123456789abcdef.rmeta"),
            "/toolchain/lib/rustlib/x86_64-unknown-linux-gnu/lib/libmissing.rlib".into(),
            "/toolchain/lib/rustlib/../libstd-123.rlib".into(),
            "/other/libstd-123.rlib".into(),
            "/etc/passwd".into(),
        ] {
            let mut invalid_rules = vec![format!("{OUT_A}/itoa.d: {path}\n")];
            // A phony target inside the output directory is not itself a
            // reported input read. Outside that directory it must identify
            // an exact keyed input, just like dependencies in a real rule.
            if normalized_within(&path, OUT_A).is_none() {
                invalid_rules.push(format!("{path}:\n"));
            }
            for invalid in invalid_rules {
                assert!(
                    dep_info_closure_violation(&plan, invalid.as_bytes(), keyed).is_some(),
                    "unproven binary input accepted: {invalid}"
                );
            }
        }
        for flags in [vec![], vec!["-Zbinary-dep-depinfo=no"]] {
            let ordinary = plan_for(OUT_A, &flags, &[]).unwrap();
            assert!(!ordinary.records_binary_dependencies());
            assert!(dep_info_closure_violation(&ordinary, raw.as_bytes(), keyed).is_some());
        }
        assert!(
            dep_info_closure_violation(&plan, b"# env-dep:CARGO_MAKEFLAGS=-j\n", |_| true)
                .is_some()
        );

        let direct = externs(&plan, 20);
        let mut inventory = directory_facts(&plan, &direct);
        let keyed_action = |inventory: &[DependencyDirectoryFact]| {
            super::live_dependency_key(
                &plan,
                &toolchain(),
                &direct,
                inventory,
                None,
                &inputs(&plan, 11),
            )
            .unwrap()
            .action_key
        };
        let original = keyed_action(&inventory);
        inventory[0].artifacts.push(ExternFact {
            path: format!("{OUT_A}/libunobserved.rmeta"),
            content_digest: digest(42),
        });
        let added = keyed_action(&inventory);
        assert_ne!(
            added, original,
            "binary evidence cannot drop negative membership"
        );
        inventory[0].artifacts[1].content_digest = digest(43);
        assert_ne!(
            keyed_action(&inventory),
            added,
            "unread candidate bytes remain keyed"
        );
    }

    #[test]
    fn binary_dep_info_binds_untranslated_host_sysroot_location() {
        let make_plan = |compiler: &str, flags: &[&str]| {
            let mut args = argv(OUT_A, flags);
            args[0] = compiler.to_owned();
            let env = env(&[]);
            plan_dependency_action(
                LiveRustcRequest {
                    argv: &args,
                    cwd: PACKAGE,
                    env: &env,
                },
                "x86_64-unknown-linux-gnu",
            )
            .unwrap()
        };
        // `key` supplies identical toolchain content facts. Ordinary metadata
        // can still share them; binary dep-info retains each real sysroot path.
        for flags in [vec![], vec!["-Zbinary-dep-depinfo=no"]] {
            assert_eq!(
                key(&make_plan("/toolchain-a/bin/rustc", &flags)),
                key(&make_plan("/toolchain-b/bin/rustc", &flags)),
            );
        }
        assert_ne!(
            key(&make_plan(
                "/toolchain-a/bin/rustc",
                &["-Zbinary-dep-depinfo"]
            )),
            key(&make_plan(
                "/toolchain-b/bin/rustc",
                &["-Zbinary-dep-depinfo"]
            )),
            "binary evidence must never replay a different installation's sysroot paths"
        );
    }

    #[test]
    fn binary_dep_info_rewrites_only_input_tokens_for_each_subscriber() {
        let make_plan = |base: &str| {
            let mut args = argv(&format!("{base}/middle/out"), &["-Zbinary-dep-depinfo"]);
            for arg in &mut args {
                if arg.starts_with("dependency=") {
                    *arg = format!("dependency={base}/leaf/out");
                }
                if arg.starts_with("dep=") {
                    *arg = format!("dep={base}/leaf/out/libdep-0123456789abcdef.rmeta");
                }
            }
            let env = env(&[]);
            plan_dependency_action(
                LiveRustcRequest {
                    argv: &args,
                    cwd: PACKAGE,
                    env: &env,
                },
                "x86_64-unknown-linux-gnu",
            )
            .unwrap()
        };
        let a = make_plan("/work/a");
        let b = make_plan("/work/b");
        assert_eq!(key(&a), key(&b));
        let raw = format!(
            "{}/middle.d: {PACKAGE}/src/lib.rs {}/libdep-0123456789abcdef.rmeta\n\
             {}/libdep-0123456789abcdef.rmeta:\n\
             # env-dep:NOTE=literal /work/a/leaf/out/value\n",
            a.out_dir, a.dependency_dirs[0], a.dependency_dirs[0]
        );
        let canonical = canonicalize_placements(raw.as_bytes(), &a).unwrap();
        assert!(String::from_utf8_lossy(&canonical).contains("/__rabs/deps/000/libdep-"));
        assert_eq!(render_placements(&canonical, &a), raw.as_bytes());
        let expected = raw
            .lines()
            .map(|line| {
                if line.starts_with('#') {
                    line.to_owned()
                } else {
                    line.replace("/work/a", "/work/b")
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        assert_eq!(render_placements(&canonical, &b), expected.as_bytes());
        let sibling = b"/work/a/leaf/outside/libsame.rmeta: /source/work/a/leaf/out/value\n";
        assert_eq!(canonicalize_placements(sibling, &a).unwrap(), sibling);
        for escaped_source in [
            "src/odd\\ /work/a/leaf/out/lib.rs",
            "src/odd\\\t/work/a/leaf/out/lib.rs",
            "src/odd\\ /work/a/middle/out/lib.rs",
            "src/odd\\\t/work/a/middle/out/lib.rs",
        ] {
            let escaped = format!("{}/middle.d: {escaped_source}\n", a.out_dir);
            let canonical = canonicalize_placements(escaped.as_bytes(), &a).unwrap();
            let expected = format!("{}/middle.d: {escaped_source}\n", b.out_dir);
            assert_eq!(render_placements(&canonical, &b), expected.as_bytes());
            assert!(
                dep_info_closure_violation(&a, escaped.as_bytes(), |_| true).is_some(),
                "the live closure must still refuse escaped source paths"
            );
        }
        let continued = format!(
            "{}/middle.d: \\\n {}/libdep-0123456789abcdef.rmeta\n\
             # env-dep:NOTE=literal /work/a/leaf/out/value\\\n",
            a.out_dir, a.dependency_dirs[0]
        );
        assert!(dep_info_closure_violation(&a, continued.as_bytes(), |_| true).is_some());
        let canonical = canonicalize_placements(continued.as_bytes(), &a).unwrap();
        assert_eq!(render_placements(&canonical, &a), continued.as_bytes());
        assert!(
            String::from_utf8_lossy(&canonical)
                .ends_with("# env-dep:NOTE=literal /work/a/leaf/out/value\\\n")
        );
        let ordinary = plan_for(OUT_A, &[], &[]).unwrap();
        assert_ne!(
            key(&ordinary),
            key(&plan_for(OUT_A, &["-Zbinary-dep-depinfo"], &[]).unwrap())
        );
    }

    #[test]
    fn dep_info_closure_admits_package_reads_and_refuses_escapes() {
        let plan = plan_for(OUT_A, &[], &[("CARGO_PKG_VERSION", "1.0.15")]).unwrap();
        let good = format!(
            "{OUT_A}/itoa-1.d: {PACKAGE}/src/lib.rs {PACKAGE}/src/udiv128.rs\n\n\
             {OUT_A}/libitoa-1.rmeta: {PACKAGE}/src/lib.rs {PACKAGE}/src/udiv128.rs\n\n\
             {PACKAGE}/src/lib.rs:\n{PACKAGE}/src/udiv128.rs:\n\n\
             # env-dep:CARGO_PKG_VERSION=1.0.15\n# env-dep:ABSENT_CUSTOM_VAR\n"
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
    fn complete_dependency_inputs_require_new_evidence_for_every_source_kind() {
        for plan in [
            plan_for(OUT_A, &[], &[]).unwrap(),
            plan_in_package(GIT_ROOT, OUT_A, &[]).unwrap(),
            directory_plan(DIRECTORY_PACKAGE, OUT_A, &[], &[]).unwrap(),
        ] {
            let manifest = if plan.source_kind == DependencySourceKind::DirectoryPackage {
                directory_inputs(&plan)
            } else {
                inputs(&plan, 11)
            };
            let current =
                live_dependency_key(&plan, &toolchain(), &externs(&plan, 20), &manifest).unwrap();
            assert_eq!(current.descriptor.key_epoch, 6);
            for previous_epoch in [1, 2, 3, 4, 5] {
                let mut previous = current.descriptor.clone();
                previous.key_epoch = previous_epoch;
                assert_ne!(current.action_key, compute_action_key(&previous).final_key);
                assert_ne!(
                    current.descriptor_digest,
                    descriptor_digest(&descriptor_canonical_bytes(&previous))
                );
            }
        }
    }

    const DIRECTORY_PACKAGE: &str = "/sources/vendor/itoa-1.0.15";

    fn directory_plan(
        package: &str,
        out_dir: &str,
        extra_args: &[&str],
        extra_env: &[(&str, &str)],
    ) -> Result<DependencyActionPlan, LiveRefusal> {
        let argv = argv(out_dir, extra_args)
            .into_iter()
            .map(|arg| arg.replace(PACKAGE, package))
            .collect::<Vec<_>>();
        let mut env = env(extra_env);
        env.iter_mut()
            .find(|(name, _)| name == "CARGO_MANIFEST_DIR")
            .unwrap()
            .1 = package.to_owned();
        plan_directory_dependency_action(
            LiveRustcRequest {
                argv: &argv,
                cwd: package,
                env: &env,
            },
            "x86_64-unknown-linux-gnu",
            digest(40),
        )
    }

    fn directory_inputs(plan: &DependencyActionPlan) -> ActionInputManifest {
        let mut manifest = inputs(plan, 11);
        manifest.inputs.push(PositiveInput {
            virtual_path: RawBytes::new(
                plan.input_virtual_path(".cargo-checksum.json").into_bytes(),
            ),
            object: ObjectId(digest(40)),
            file_type: InputFileType::Regular,
            executable: false,
            symlink_resolution: Vec::new(),
        });
        manifest
    }

    fn directory_key(
        plan: &DependencyActionPlan,
        inputs: &ActionInputManifest,
    ) -> Result<LiveDependencyKey, LiveRefusal> {
        live_dependency_key(plan, &toolchain(), &externs(plan, 20), inputs)
    }

    #[test]
    fn directory_sources_require_explicit_witnessed_planning_and_keep_real_paths() {
        assert!(matches!(
            plan_in_package(DIRECTORY_PACKAGE, OUT_A, &[]),
            Err(LiveRefusal::NotDependencySource(_))
        ));
        let plan = directory_plan(DIRECTORY_PACKAGE, OUT_A, &[], &[]).unwrap();
        assert_eq!(plan.source_kind, DependencySourceKind::DirectoryPackage);
        assert_eq!(plan.source_kind.as_str(), "directory-package");
        assert_eq!(plan.source_root, DIRECTORY_PACKAGE);
        assert_eq!(plan.cwd, DIRECTORY_PACKAGE);
        assert_eq!(plan.package_root, DIRECTORY_PACKAGE);
        assert_eq!(plan.directory_source_manifest, Some(digest(40)));
        assert!(
            plan.execution_env
                .contains(&("CARGO_MANIFEST_DIR".into(), DIRECTORY_PACKAGE.into()))
        );
        let key = directory_key(&plan, &directory_inputs(&plan)).unwrap();
        assert_eq!(
            key.descriptor.sandbox_semantic_policy,
            compute(
                DOMAIN_LIVE_ISOLATION,
                DIRECTORY_ISOLATION_PROFILE.as_bytes()
            )
        );
        let mut negative = CanonicalEncoder::new();
        negative
            .str("complete-directory-package-tree-enumeration-v1")
            .str("directory-package")
            .str(DIRECTORY_PACKAGE)
            .str(&plan.source_virtual_root());
        assert_eq!(
            key.descriptor.negative_dependencies,
            compute(DOMAIN_LIVE_NEGATIVE, &negative.finish())
        );
    }

    #[test]
    fn directory_source_key_binds_the_exact_captured_checksum_and_package_manifest() {
        let plan = directory_plan(DIRECTORY_PACKAGE, OUT_A, &[], &[]).unwrap();
        let original = directory_inputs(&plan);
        directory_key(&plan, &original).unwrap();
        for missing in ["Cargo.toml", ".cargo-checksum.json"] {
            let mut incomplete = original.clone();
            incomplete.inputs.retain(|input| {
                input.virtual_path.as_bytes() != plan.input_virtual_path(missing).as_bytes()
            });
            assert!(directory_key(&plan, &incomplete).is_err(), "{missing}");
        }
        let mut changed = original.clone();
        changed.inputs[2].object = ObjectId(digest(41));
        assert!(
            directory_key(&plan, &changed).is_err(),
            "the pre-capture witness changed"
        );
        let mut duplicated = original.clone();
        duplicated.inputs.push(original.inputs[2].clone());
        assert!(directory_key(&plan, &duplicated).is_err());
        let mut moved = original.clone();
        moved.inputs[2].virtual_path = RawBytes::new(
            plan.input_virtual_path("nested/.cargo-checksum.json")
                .into_bytes(),
        );
        assert!(directory_key(&plan, &moved).is_err());
        let mut without_witness = plan.clone();
        without_witness.directory_source_manifest = None;
        assert!(directory_key(&without_witness, &original).is_err());
    }

    #[test]
    fn directory_checksum_declarations_never_replace_real_source_identity() {
        let plan = directory_plan(DIRECTORY_PACKAGE, OUT_A, &[], &[]).unwrap();
        let original = directory_inputs(&plan);
        let base = directory_key(&plan, &original).unwrap().action_key;
        let mut changed = original.clone();
        changed.inputs[1].object = ObjectId(digest(42));
        assert_ne!(base, directory_key(&plan, &changed).unwrap().action_key);
        let mut added = original.clone();
        let mut extra = original.inputs[1].clone();
        extra.virtual_path = RawBytes::new(plan.input_virtual_path("unlisted.txt").into_bytes());
        added.inputs.push(extra);
        assert_ne!(base, directory_key(&plan, &added).unwrap().action_key);
        // Source edits/additions above retained precisely the same witness.
        assert_eq!(added.inputs[2], original.inputs[2]);
        let mut new_witness = plan.clone();
        new_witness.directory_source_manifest = Some(digest(43));
        let mut new_manifest = original.clone();
        new_manifest.inputs[2].object = ObjectId(digest(43));
        assert_ne!(
            base,
            directory_key(&new_witness, &new_manifest)
                .unwrap()
                .action_key
        );
    }

    #[test]
    fn directory_sources_share_target_placements_but_not_source_locations() {
        let a = directory_plan(DIRECTORY_PACKAGE, OUT_A, &[], &[]).unwrap();
        let b = directory_plan(DIRECTORY_PACKAGE, OUT_B, &[], &[]).unwrap();
        let other = directory_plan("/other/vendor/itoa-1.0.15", OUT_A, &[], &[]).unwrap();
        let base = directory_key(&a, &directory_inputs(&a)).unwrap().action_key;
        assert_eq!(
            base,
            directory_key(&b, &directory_inputs(&b)).unwrap().action_key
        );
        assert_ne!(
            base,
            directory_key(&other, &directory_inputs(&other))
                .unwrap()
                .action_key
        );
    }

    #[test]
    fn directory_witness_does_not_reinterpret_cargo_cache_or_git_metadata_paths() {
        for path in [
            PACKAGE,
            GIT_PACKAGE,
            "/home/agent/.cargo",
            "/home/agent",
            "/home/agent/.cargo/git/db/malformed",
            "/sources/.git/vendor/pkg",
            "/sources/vendor/../pkg",
            "/sources/vendor/pkg/",
            "relative/pkg",
        ] {
            assert!(directory_plan(path, OUT_A, &[], &[]).is_err(), "{path}");
        }
        // Neither the directory name `vendor` nor a claimed witness admits
        // outputs inside the captured source closure.
        assert!(
            directory_plan(
                DIRECTORY_PACKAGE,
                &format!("{DIRECTORY_PACKAGE}/target/deps"),
                &[],
                &[],
            )
            .is_err()
        );
        let mut registry = plan_for(OUT_A, &[], &[]).unwrap();
        registry.directory_source_manifest = Some(digest(40));
        assert!(directory_key(&registry, &inputs(&registry, 11)).is_err());
    }

    #[test]
    fn directory_sources_preserve_execution_class_and_environment_refusals() {
        for extra in [
            vec!["--extern=macro=/deps/libmacro.so"],
            vec!["-Lnative=/native"],
            vec!["-lssl"],
            vec!["-Cincremental=/incremental"],
        ] {
            assert!(directory_plan(DIRECTORY_PACKAGE, OUT_A, &extra, &[]).is_err());
        }
        for env in [
            vec![("CARGO_PRIMARY_PACKAGE", "1")],
            vec![("LD_PRELOAD", "/inject.so")],
        ] {
            assert!(directory_plan(DIRECTORY_PACKAGE, OUT_A, &[], &env).is_err());
        }
        let mut argv = argv(OUT_A, &[])
            .into_iter()
            .map(|arg| arg.replace(PACKAGE, DIRECTORY_PACKAGE))
            .collect::<Vec<_>>();
        argv.truncate(argv.len() - 2);
        let env = env(&[("CARGO_MANIFEST_DIR", DIRECTORY_PACKAGE)]);
        assert!(matches!(
            plan_directory_dependency_action(
                LiveRustcRequest {
                    argv: &argv,
                    cwd: DIRECTORY_PACKAGE,
                    env: &env,
                },
                "x86_64-unknown-linux-gnu",
                digest(40),
            ),
            Err(LiveRefusal::NotDependencyCompile(_))
        ));
    }

    #[test]
    fn directory_source_dep_info_cannot_read_siblings_or_unlisted_uncaptured_inputs() {
        let plan = directory_plan(DIRECTORY_PACKAGE, OUT_A, &[], &[]).unwrap();
        let manifest = directory_inputs(&plan);
        let covered = |path: &str| {
            manifest
                .inputs
                .iter()
                .any(|input| input.virtual_path.as_bytes() == path.as_bytes())
        };
        let good = format!("{OUT_A}/itoa.d: {DIRECTORY_PACKAGE}/src/lib.rs\n");
        assert_eq!(
            dep_info_closure_violation(&plan, good.as_bytes(), covered),
            None
        );
        for read in [
            format!("{DIRECTORY_PACKAGE}/../sibling/src/lib.rs"),
            format!("{DIRECTORY_PACKAGE}/../itoa-1.0.15/src/lib.rs"),
            format!("{DIRECTORY_PACKAGE}/uncaptured.txt"),
            "/etc/hostname".into(),
        ] {
            assert!(
                dep_info_closure_violation(
                    &plan,
                    format!("{OUT_A}/itoa.d: {read}\n").as_bytes(),
                    covered,
                )
                .is_some(),
                "{read}"
            );
        }
        let mut git_metadata = manifest.clone();
        git_metadata.inputs[1].virtual_path =
            RawBytes::new(plan.input_virtual_path(".git/HEAD").into_bytes());
        assert!(directory_key(&plan, &git_metadata).is_err());
    }
}
