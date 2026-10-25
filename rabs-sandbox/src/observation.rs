//! Filesystem/exec/network observation prototype — ptrace via `strace` —
//! plus the measurement discipline that chooses it (bead E005; plan §186;
//! miss-path SLO <1-2%).
//!
//! WHY PTRACE FIRST: the bead names eBPF, fanotify, ptrace, seccomp-notify
//! and Landlock as candidates and demands the mechanism be CHOSEN BY
//! MEASUREMENT. ptrace/strace is the only candidate that is (a) zero-
//! privilege, (b) present on every fleet worker out of the box, and (c)
//! able to observe file/exec/network syscalls for an ENTIRE process tree
//! without kernel builds or capabilities — so it is the baseline every
//! fancier mechanism must beat. The live fixture
//! (`tests/observation_overhead_linux.rs`) measures it on representative
//! compiles inside the canonical namespace; MEASURED VERDICT (hz2,
//! strace 6.19, cold one-lib `cargo build` in the D003 namespace, 3-run
//! medians): untraced 140.7 ms vs traced 330.0 ms ⇒ **+134.5%** — two
//! orders of magnitude past the <1-2% miss-path SLO. CHOSEN DEFAULT
//! therefore: ptrace/strace for FIRST-RUN DISCOVERY only (E011 recipes);
//! NEVER steady-state observation; the hot path needs eBPF or
//! seccomp-notify, which E009/E019 must measure against this baseline.
//! The numbers below are updated from those runs rather than asserted
//! from preference.
//!
//! ## What observation means here
//!
//! One traced action yields an [`ObservationRecord`]: positive file
//! reads/writes, FAILED opens (E020's negative-dependency facts), the
//! exec chain (E008's subprocess graph seed), and network attempts with
//! their denial status (feeding E002's
//! [`crate::network_isolation::denied_attempt_observation`] contract and
//! E009's detection). [`ObservationRecord::observed_effects`] maps the
//! record onto `rabs_protocol::volatility::ObservedEffects` so the
//! existing classifier (`EffectClass::NetworkSensitive`, …) consumes
//! tracer output directly.
//!
//! ## Boundary honesty
//!
//! Wrapping a launch with strace does NOT change the namespace boundary:
//! the bwrap argv is untouched and the tracer runs INSIDE the closed view
//! (host `/usr` is already visible read-only), observing exactly the
//! action and nothing of the host.

use crate::canonical_namespace::NamespaceLaunch;
use rabs_protocol::volatility::ObservedEffects;
use std::ffi::OsString;
use std::path::Path;

/// Syscall set traced by the prototype: the whole `%file` class (opens,
/// stats, metadata), program launches, and EGRESS network attempts —
/// `connect`/`sendto`/`sendmsg` address a peer, which is what hermeticity
/// cares about; `socket()` merely creates an fd and SUCCEEDS even in a
/// closed netns, so counting it would fake an attempt.
pub const DEFAULT_SYSCALL_SET: &str = "%file,execve,execveat,connect,sendto,sendmsg";

/// Hard cap on retained path samples per category: a cargo build touches
/// tens of thousands of files and the observation must stay bounded (the
/// wrapper OOM discipline); counts stay exact, only samples truncate.
const MAX_SAMPLES: usize = 1024;

/// A zero-privilege observation mechanism available on this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tracer {
    /// `strace` (ptrace-based); carries the reported version string.
    StracePtrace(String),
}

impl Tracer {
    /// Probe for the mechanism. `None` = not available here (callers skip
    /// honestly; observation gaps classify `Unclosable`, never `Hermetic`).
    #[must_use]
    pub fn probe() -> Option<Self> {
        if !cfg!(target_os = "linux") {
            return None;
        }
        let out = std::process::Command::new("strace")
            .arg("--version")
            .output()
            .ok()
            .filter(|o| o.status.success())?;
        let first = String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()?
            .trim()
            .to_owned();
        Some(Self::StracePtrace(first))
    }

    /// Absolute-ish binary name resolvable inside the canonical namespace
    /// (host `/usr` is bound read-only there).
    #[must_use]
    pub fn in_namespace_binary(&self) -> &'static str {
        match self {
            Self::StracePtrace(_) => "/usr/bin/strace",
        }
    }
}

/// Compose a traced launch: the SAME namespace argv with the tracer
/// inserted after bwrap's `--`, so the ACTION (not the namespace setup)
/// is what gets observed. The log must live on a path writable inside the
/// namespace (an out-unit or workspace path) and is parsed after the run.
///
/// # Errors
/// [`IsolationArgumentError::MissingSeparator`] when the launch argv has
/// no `--` separator (never expected from the D003 builder).
/// [`IsolationArgumentError::EmptyArgv`] for an empty argv.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IsolationArgumentError {
    /// The launch argv lacked the bwrap `--` separator.
    MissingSeparator,
    /// The launch argv was empty.
    EmptyArgv,
}

impl std::fmt::Display for IsolationArgumentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSeparator => write!(f, "launch argv has no `--` separator"),
            Self::EmptyArgv => write!(f, "launch argv is empty"),
        }
    }
}

impl std::error::Error for IsolationArgumentError {}

/// Insert the tracer into a namespace launch. Pure argv algebra: the
/// returned launch's boundary is the ORIGINAL boundary (tracing adds no
/// namespace property and removes none).
///
/// # Errors
/// [`IsolationArgumentError`] when the argv shape is not the D003 shape.
pub fn wrap_with_tracer(
    launch: &NamespaceLaunch,
    tracer: &Tracer,
    syscall_set: &str,
    log_visible_path: &str,
) -> Result<NamespaceLaunch, IsolationArgumentError> {
    let sep = launch
        .argv
        .iter()
        .position(|a| a == "--")
        .ok_or(IsolationArgumentError::MissingSeparator)?;
    if launch.argv.is_empty() {
        return Err(IsolationArgumentError::EmptyArgv);
    }
    let mut argv: Vec<OsString> = launch.argv[..=sep].to_vec();
    argv.push(tracer.in_namespace_binary().into());
    argv.push("-f".into()); // Follow the whole process tree.
    argv.push("-qq".into()); // No attach/detach chatter, no summary.
    argv.push("-o".into());
    argv.push(log_visible_path.into());
    argv.push("-e".into());
    argv.push(format!("trace={syscall_set}").into());
    argv.extend(launch.argv[(sep + 1)..].iter().cloned());
    Ok(NamespaceLaunch {
        argv,
        boundary: launch.boundary.clone(),
    })
}

/// One observed action, bounded: exact COUNTS for every category, capped
/// path SAMPLES for the categories that feed downstream manifests.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ObservationRecord {
    /// Successful read-class file operations (openat O_RDONLY, stat
    /// family, access).
    pub reads: u64,
    /// Successful write-class operations (O_WRONLY/O_RDWR/O_CREAT/O_TRUNC).
    pub writes: u64,
    /// Failed opens (ENOENT & friends) — E020 negative-dependency seeds.
    pub failed_opens: Vec<String>,
    /// Successfully executed program paths — E008 exec-chain seeds.
    pub execs: Vec<String>,
    /// Failed execs (missing interpreter, ENOENT).
    pub failed_execs: Vec<String>,
    /// Network-touching syscalls attempted.
    pub network_attempts: u64,
    /// Of those, the ones the kernel DENIED (netns default-deny shows up
    /// as fast ENETUNREACH/EACCES failures here).
    pub network_denied: u64,
    /// Any sample category hit its cap: the record is complete for
    /// counting but NOT for manifest identity (E010 consumers must treat
    /// this action as observation-incomplete).
    pub truncated: bool,
}

impl ObservationRecord {
    /// Map the tracer facts onto the volatility classifier's input.
    /// `observation_complete` is true only when nothing truncated — an
    /// incomplete trace must classify `Unclosable`, never `Hermetic`.
    #[must_use]
    pub fn observed_effects(&self) -> ObservedEffects {
        ObservedEffects {
            observation_complete: !self.truncated,
            touched_network: self.network_attempts > 0,
            ..ObservedEffects::default()
        }
    }

    /// Construct the canonical [`rabs_protocol::input_evidence::NegativeDependencySet`]
    /// from observed failed opens, failed executable PATH probes, directory
    /// enumerations/glob results, and dangling symlink targets (`E020`, risk `R57`).
    #[must_use]
    pub fn to_negative_dependency_set(
        &self,
        directory_enumerations: &[(String, Vec<String>)],
        dangling_symlinks: &[(String, String)],
    ) -> rabs_protocol::input_evidence::NegativeDependencySet {
        use rabs_protocol::input_evidence::{
            INPUT_EVIDENCE_SCHEMA_VERSION, NegativeDependency, NegativeDependencySet,
        };
        use rabs_protocol::raw_bytes::RawBytes;

        let mut entries = Vec::new();
        for failed_open in &self.failed_opens {
            entries.push(NegativeDependency::FailedOpen {
                virtual_path: RawBytes::new(failed_open.as_bytes().to_vec()),
            });
        }

        // Group failed execve probes by tool basename in observed probe order.
        let mut tool_probes: Vec<(String, Vec<RawBytes>)> = Vec::new();
        for failed_exec in &self.failed_execs {
            if let Some((dir, tool)) = failed_exec.rsplit_once('/')
                && !tool.is_empty()
            {
                let dir_bytes = RawBytes::new(if dir.is_empty() {
                    b"/".to_vec()
                } else {
                    dir.as_bytes().to_vec()
                });
                if let Some((_, dirs)) = tool_probes.iter_mut().find(|(t, _)| t == tool) {
                    if !dirs.contains(&dir_bytes) {
                        dirs.push(dir_bytes);
                    }
                } else {
                    tool_probes.push((tool.to_string(), vec![dir_bytes]));
                }
            }
        }
        for (tool, probed_absent) in tool_probes {
            entries.push(NegativeDependency::PathLookupMiss {
                tool: RawBytes::new(tool.into_bytes()),
                probed_absent,
            });
        }

        for (pattern, matches) in directory_enumerations {
            let mut sorted_matches: Vec<RawBytes> = matches
                .iter()
                .map(|m| RawBytes::new(m.as_bytes().to_vec()))
                .collect();
            sorted_matches.sort_unstable();
            sorted_matches.dedup();
            entries.push(NegativeDependency::GlobResult {
                pattern: RawBytes::new(pattern.as_bytes().to_vec()),
                matches: sorted_matches,
            });
        }

        for (symlink, target) in dangling_symlinks {
            entries.push(NegativeDependency::MissingSymlinkTarget {
                symlink: RawBytes::new(symlink.as_bytes().to_vec()),
                target: RawBytes::new(target.as_bytes().to_vec()),
            });
        }

        NegativeDependencySet {
            schema_version: INPUT_EVIDENCE_SCHEMA_VERSION,
            entries,
        }
    }
}

/// One negative-dependency invalidation event detected against a later tree (`E020`, `R57`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NegativeDependencyInvalidation {
    /// A previously missing or failed-open path now exists.
    NewlyPresentPath {
        /// The virtual path that appeared.
        virtual_path: String,
    },
    /// A directory enumeration or glob result changed.
    ListingChanged {
        /// The directory or glob pattern.
        pattern: String,
        /// Previously recorded sorted matches.
        expected: Vec<String>,
        /// Current sorted matches.
        actual: Vec<String>,
    },
    /// An earlier PATH candidate that previously missed now provides the tool.
    EarlierPathCandidateAppeared {
        /// Tool basename.
        tool: String,
        /// Directory in PATH where the tool appeared.
        directory: String,
    },
    /// A previously dangling symlink target now resolves.
    DanglingSymlinkResolved {
        /// The symlink path.
        symlink: String,
        /// The target path that appeared.
        target: String,
    },
}

/// Evaluate a recorded [`rabs_protocol::input_evidence::NegativeDependencySet`]
/// against a new filesystem state (`E020`, risk `R57`).
///
/// Any non-empty return means the cached key/recipe is invalidated by an
/// absence-to-presence or listing change.
#[must_use]
pub fn evaluate_negative_dependencies_against_tree(
    set: &rabs_protocol::input_evidence::NegativeDependencySet,
    existing_paths: &std::collections::BTreeSet<String>,
    directory_listings: &std::collections::BTreeMap<String, Vec<String>>,
) -> Vec<NegativeDependencyInvalidation> {
    use rabs_protocol::input_evidence::NegativeDependency;

    let mut invalidations = Vec::new();
    for entry in &set.entries {
        match entry {
            NegativeDependency::FailedOpen { virtual_path }
            | NegativeDependency::MissingPath { virtual_path } => {
                let path_str = String::from_utf8_lossy(virtual_path.as_bytes()).into_owned();
                if existing_paths.contains(&path_str) {
                    invalidations.push(NegativeDependencyInvalidation::NewlyPresentPath {
                        virtual_path: path_str,
                    });
                }
            }
            NegativeDependency::GlobResult { pattern, matches } => {
                let pat_str = String::from_utf8_lossy(pattern.as_bytes()).into_owned();
                let mut expected: Vec<String> = matches
                    .iter()
                    .map(|m| String::from_utf8_lossy(m.as_bytes()).into_owned())
                    .collect();
                expected.sort_unstable();
                expected.dedup();
                let mut actual = directory_listings
                    .get(&pat_str)
                    .cloned()
                    .unwrap_or_default();
                actual.sort_unstable();
                actual.dedup();
                if expected != actual {
                    invalidations.push(NegativeDependencyInvalidation::ListingChanged {
                        pattern: pat_str,
                        expected,
                        actual,
                    });
                }
            }
            NegativeDependency::PathLookupMiss {
                tool,
                probed_absent,
            } => {
                let tool_str = String::from_utf8_lossy(tool.as_bytes()).into_owned();
                for dir in probed_absent {
                    let dir_str = String::from_utf8_lossy(dir.as_bytes()).into_owned();
                    let candidate = if dir_str == "/" {
                        format!("/{tool_str}")
                    } else {
                        format!("{dir_str}/{tool_str}")
                    };
                    if existing_paths.contains(&candidate) {
                        invalidations.push(
                            NegativeDependencyInvalidation::EarlierPathCandidateAppeared {
                                tool: tool_str.clone(),
                                directory: dir_str,
                            },
                        );
                    }
                }
            }
            NegativeDependency::MissingSymlinkTarget { symlink, target } => {
                let sym_str = String::from_utf8_lossy(symlink.as_bytes()).into_owned();
                let target_str = String::from_utf8_lossy(target.as_bytes()).into_owned();
                if existing_paths.contains(&target_str) {
                    invalidations.push(NegativeDependencyInvalidation::DanglingSymlinkResolved {
                        symlink: sym_str,
                        target: target_str,
                    });
                }
            }
        }
    }
    invalidations
}

/// Parse one strace log (the `-o FILE` product of a traced run).
#[must_use]
pub fn parse_strace_log(log: &str) -> ObservationRecord {
    let mut record = ObservationRecord::default();
    for line in log.lines() {
        // Unfinished/resumed pairs ("-1 ENOSYS" style noise, signals) and
        // unrelated syscalls are skipped by the prefix dispatch below.
        if let Some(rest) = strip_call(line, "openat(").or_else(|| strip_call(line, "open(")) {
            observe_open(rest, &mut record);
        } else if let Some(rest) = strip_call(line, "execve(") {
            observe_exec(rest, &mut record);
        } else if is_network_call(line) {
            observe_network(line, &mut record);
        } else if is_read_class(line) && result_ok(line) {
            record.reads += 1;
        }
    }
    record
}

/// Match `… name(` at a line start (after the optional pid prefix) and
/// return the argument region.
fn strip_call<'a>(line: &'a str, call: &str) -> Option<&'a str> {
    let body = line.trim_start();
    // Skip the pid prefix strace prints with -f ("123  openat(...)").
    let after_pid = body
        .split_once(' ')
        .filter(|(head, _)| head.bytes().all(|b| b.is_ascii_digit()))
        .map(|(_, tail)| tail.trim_start())
        .unwrap_or(body);
    after_pid.strip_prefix(call)
}

fn first_quoted(args: &str) -> Option<&str> {
    let start = args.find('"')? + 1;
    let end = args[start..].find('"')? + start;
    Some(&args[start..end])
}

/// Everything after the final `) ` is the result region.
fn result_region(args_and_result: &str) -> &str {
    match args_and_result.rfind(") =") {
        Some(idx) => &args_and_result[idx + 2..],
        None => "",
    }
}

fn result_ok(args_and_result: &str) -> bool {
    let region = result_region(args_and_result);
    let trimmed = region.trim_start();
    trimmed.starts_with('=') && !trimmed[1..].trim_start().starts_with("-1")
}

fn observe_open(args: &str, record: &mut ObservationRecord) {
    let Some(path) = first_quoted(args) else {
        return;
    };
    let failed = {
        let region = result_region(args);
        let trimmed = region.trim_start();
        trimmed.starts_with('=') && trimmed[1..].trim_start().starts_with("-1")
    };
    if failed {
        if record.failed_opens.len() < MAX_SAMPLES {
            record.failed_opens.push(path.to_owned());
        } else {
            record.truncated = true;
        }
        return;
    }
    let write_class = args.contains("O_WRONLY")
        || args.contains("O_RDWR")
        || args.contains("O_CREAT")
        || args.contains("O_TRUNC")
        || args.contains("O_TMPFILE");
    if write_class {
        record.writes += 1;
    } else {
        record.reads += 1;
    }
}

fn observe_exec(args: &str, record: &mut ObservationRecord) {
    let Some(path) = first_quoted(args) else {
        return;
    };
    let failed = {
        let region = result_region(args);
        let trimmed = region.trim_start();
        trimmed.starts_with('=') && trimmed[1..].trim_start().starts_with("-1")
    };
    let bucket = if failed {
        &mut record.failed_execs
    } else {
        &mut record.execs
    };
    if bucket.len() < MAX_SAMPLES {
        bucket.push(path.to_owned());
    } else {
        record.truncated = true;
    }
}

fn is_network_call(line: &str) -> bool {
    // Egress only: these address a peer. `socket()` just creates an fd
    // (succeeds even in a closed netns); passive `recv*` without a
    // connected peer proves nothing about initiation.
    ["connect(", "sendto(", "sendmsg("]
        .iter()
        .any(|call| strip_call(line, call).is_some())
}

fn observe_network(line: &str, record: &mut ObservationRecord) {
    record.network_attempts += 1;
    let region = result_region(line.trim_start());
    let trimmed = region.trim_start();
    if trimmed.starts_with('=') && trimmed[1..].trim_start().starts_with("-1") {
        record.network_denied += 1;
    }
}

/// Metadata/read-class syscalls worth counting as reads (the stat family
/// and access probes ARE input observations — a build that stats a file
/// depends on its existence).
fn is_read_class(line: &str) -> bool {
    [
        "newfstatat(",
        "stat(",
        "lstat(",
        "faccessat(",
        "access(",
        "readlink(",
    ]
    .iter()
    .any(|call| strip_call(line, call).is_some())
}

/// Convenience: trace log sitting at a visible path, parse from its
/// backing location after the run.
#[must_use]
pub fn parse_strace_log_file(path: &Path) -> ObservationRecord {
    match std::fs::read_to_string(path) {
        Ok(log) => parse_strace_log(&log),
        Err(_) => ObservationRecord {
            // A missing log is an observation GAP, never silence: classify
            // downstream as incomplete.
            truncated: true,
            ..ObservationRecord::default()
        },
    }
}

/// One node in the captured subprocess/tool invocation graph (`E008`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubprocessGraphNode {
    /// Traced PID of the process executing this tool (0 when unattributed).
    pub pid: u32,
    /// Parent PID that spawned this process (`None` for the root tool).
    pub parent_pid: Option<u32>,
    /// Tool basename (e.g. `"cc"`, `"as"`, `"ld"`).
    pub tool_name: String,
    /// Resolved executable path that succeeded in `execve`.
    pub resolved_executable_path: String,
    /// Content identity of the resolved executable.
    pub executable_object: Option<rabs_protocol::result_identity::ObjectId>,
    /// Ordered directories in `PATH` probed and found not containing `tool_name`
    /// before `resolved_executable_path` succeeded (negative dependencies).
    pub probed_absent_dirs: Vec<String>,
}

/// Complete subprocess/tool invocation graph for an action (`E008`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SubprocessInvocationGraph {
    /// Ordered tool execution nodes in invocation order.
    pub nodes: Vec<SubprocessGraphNode>,
    /// Executables whose content identity could not be resolved (forces non-authoritative).
    pub unidentified_executables: Vec<String>,
}

fn parse_line_pid(line: &str) -> Option<u32> {
    let body = line.trim_start();
    let (head, _) = body.split_once(' ')?;
    if head.bytes().all(|b| b.is_ascii_digit()) {
        head.parse::<u32>().ok()
    } else {
        None
    }
}

/// Capture the subprocess/tool invocation graph from a `strace -f` log (`E008`).
///
/// Tracks parent→child process creation (`clone`/`vfork`/`fork` return values or
/// sequential child PID introduction), records `ENOENT` `execve` probes as ordered
/// `probed_absent_dirs` per tool, and binds each resolved executable to its content
/// [`rabs_protocol::result_identity::ObjectId`].
pub fn capture_subprocess_invocation_graph(
    log: &str,
    identify_executable: impl Fn(&str) -> Option<rabs_protocol::result_identity::ObjectId>,
) -> SubprocessInvocationGraph {
    use std::collections::BTreeMap;

    let mut parent_of: BTreeMap<u32, u32> = BTreeMap::new();
    let mut pending_misses_by_pid: BTreeMap<(u32, String), Vec<String>> = BTreeMap::new();
    let mut last_exec_pid: Option<u32> = None;
    let mut nodes = Vec::new();
    let mut unidentified_executables = Vec::new();

    for line in log.lines() {
        let pid = parse_line_pid(line).unwrap_or(0);
        if (strip_call(line, "clone(").is_some()
            || strip_call(line, "clone3(").is_some()
            || strip_call(line, "vfork(").is_some()
            || strip_call(line, "fork(").is_some())
            && result_ok(line)
        {
            let region = result_region(line);
            if let Some(eq_rest) = region.trim_start().strip_prefix('=')
                && let Ok(child_pid) = eq_rest.trim().parse::<u32>()
                && pid != 0
            {
                parent_of.insert(child_pid, pid);
            }
            continue;
        }

        let Some(rest) = strip_call(line, "execve(") else {
            continue;
        };
        let Some(path) = first_quoted(rest) else {
            continue;
        };
        let tool_name = path
            .rsplit_once('/')
            .map(|(_, base)| base)
            .unwrap_or(path)
            .to_string();
        let dir_name = path
            .rsplit_once('/')
            .map(|(dir, _)| if dir.is_empty() { "/" } else { dir })
            .unwrap_or(".")
            .to_string();

        if !result_ok(rest) {
            let entry = pending_misses_by_pid.entry((pid, tool_name)).or_default();
            if !entry.contains(&dir_name) {
                entry.push(dir_name);
            }
            continue;
        }

        let parent_pid = if let Some(&explicit_parent) = parent_of.get(&pid) {
            Some(explicit_parent)
        } else if let Some(prev_pid) = last_exec_pid
            && prev_pid != pid
        {
            Some(prev_pid)
        } else {
            None
        };
        last_exec_pid = Some(pid);

        let probed_absent_dirs = pending_misses_by_pid
            .remove(&(pid, tool_name.clone()))
            .unwrap_or_default();
        let executable_object = identify_executable(path);
        if executable_object.is_none() {
            unidentified_executables.push(path.to_string());
        }
        nodes.push(SubprocessGraphNode {
            pid,
            parent_pid,
            tool_name,
            resolved_executable_path: path.to_string(),
            executable_object,
            probed_absent_dirs,
        });
    }

    SubprocessInvocationGraph {
        nodes,
        unidentified_executables,
    }
}

/// Isolation profile surface capabilities for clock, entropy, and host-identity
/// virtualization (`E009` / `E022`, risk `R46`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileSurfaceSupport {
    /// Whether the profile virtualizes or denies vDSO + syscall wall clocks (`TIMENS` / vDSO scrub).
    pub virtualizes_clock_including_vdso: bool,
    /// Whether the profile virtualizes or denies `getrandom`, `/dev/urandom`, and `AT_RANDOM` auxv.
    pub virtualizes_entropy_all_channels: bool,
    /// Whether the profile isolates UTS hostname (`/__rabs` constant hostname) and blocks host identity.
    pub isolates_uts_hostname: bool,
    /// Whether the profile enforces a default-deny network namespace (`E002`).
    pub enforces_default_deny_network: bool,
}

impl ProfileSurfaceSupport {
    /// Strict Linux canonical namespace with full clock/entropy/UTS/net virtualization.
    #[must_use]
    pub const fn strict_virtualized() -> Self {
        Self {
            virtualizes_clock_including_vdso: true,
            virtualizes_entropy_all_channels: true,
            isolates_uts_hostname: true,
            enforces_default_deny_network: true,
        }
    }

    /// Standard namespace without vDSO time namespace or `AT_RANDOM`/`getrandom` interception:
    /// actions that read clock or randomness cannot be proven deterministic and must
    /// classify `ClockSensitive` / `RandomnessSensitive` (`R46`).
    #[must_use]
    pub const fn namespace_without_vdso_or_entropy_interception() -> Self {
        Self {
            virtualizes_clock_including_vdso: false,
            virtualizes_entropy_all_channels: false,
            isolates_uts_hostname: true,
            enforces_default_deny_network: true,
        }
    }
}

/// Classify an action's [`ObservedEffects`] and [`rabs_protocol::volatility::EffectClass`]
/// under a specific [`ProfileSurfaceSupport`] (`E009` / `E022`, risk `R46`).
///
/// Crucially, syscall tracing (`strace`) CANNOT observe vDSO `clock_gettime` or
/// `AT_RANDOM` auxv reads; therefore when `probe_used_clock_or_vdso` or
/// `probe_used_entropy_or_auxv` is true (or `/dev/urandom` / `/dev/random` was read)
/// and the profile does not virtualize that surface, the action is classified
/// `ClockSensitive` / `RandomnessSensitive` and loses shared cache authority.
#[must_use]
pub fn classify_effects_under_profile(
    record: &ObservationRecord,
    positive_read_paths: &[String],
    probe_used_clock_or_vdso: bool,
    probe_used_entropy_or_auxv: bool,
    profile: &ProfileSurfaceSupport,
) -> (ObservedEffects, rabs_protocol::volatility::EffectClass) {
    let mut effects = record.observed_effects();

    // Network: if any network attempt succeeded (network_attempts > network_denied)
    // or default-deny was not enforced when an attempt occurred, mark touched_network.
    effects.touched_network = record.network_attempts > record.network_denied
        || (record.network_attempts > 0 && !profile.enforces_default_deny_network);

    // Git state detection: any read under `.git/` or `/.git/`.
    effects.read_git_state = positive_read_paths
        .iter()
        .any(|p| p == ".git" || p.starts_with(".git/") || p.contains("/.git/"));

    // Host identity detection: `/etc/hostname`, `/etc/machine-id`, `/sys/class/dmi`, or unisolated UTS.
    let read_host_path = positive_read_paths.iter().any(|p| {
        p == "/etc/hostname"
            || p == "/etc/machine-id"
            || p == "/var/lib/dbus/machine-id"
            || p.starts_with("/sys/class/dmi")
    });
    effects.read_host_identity = read_host_path || !profile.isolates_uts_hostname;

    // Entropy detection: `/dev/urandom`, `/dev/random`, `getrandom`, or `AT_RANDOM` auxv.
    let read_dev_random = positive_read_paths
        .iter()
        .any(|p| p == "/dev/urandom" || p == "/dev/random");
    effects.read_randomness = (probe_used_entropy_or_auxv || read_dev_random)
        && !profile.virtualizes_entropy_all_channels;

    // Clock detection (including vDSO clock_gettime / rdtsc):
    effects.read_clock = probe_used_clock_or_vdso && !profile.virtualizes_clock_including_vdso;

    let class = rabs_protocol::volatility::classify(&effects);
    (effects, class)
}

/// Observed-input recipe stored by `(action_family_key, recipe_epoch)` (`E011` / `E012`).
///
/// Recipes are optimization hints for constructing the closed filesystem view and
/// candidate key on subsequent runs — never trust anchors on their own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedInputRecipe {
    /// Action family key (invocation shape + target + crate without fine file contents).
    pub action_family_key: rabs_protocol::result_identity::TypedDigest,
    /// Recipe epoch (bumped on compiler/projection/sandbox epoch changes).
    pub recipe_epoch: u32,
    /// Positive virtual paths read during discovery (dep-info + observed raw reads + proc-macro reads).
    pub declared_positive_paths: std::collections::BTreeSet<String>,
    /// Directory enumerations observed (`dir_path -> sorted entries`).
    pub declared_enumerations: std::collections::BTreeMap<String, Vec<String>>,
    /// Subprocess/tool executables observed (`resolved_path -> content ObjectId`).
    pub declared_executables:
        std::collections::BTreeMap<String, rabs_protocol::result_identity::ObjectId>,
    /// Recorded negative dependencies (`FailedOpen`, `GlobResult`, `PathLookupMiss`, `MissingSymlinkTarget`).
    pub negative_dependencies: rabs_protocol::input_evidence::NegativeDependencySet,
    /// Classified volatility effect class from discovery.
    pub effect_class: rabs_protocol::volatility::EffectClass,
    /// Whether this recipe has passed `E024` second closed-view validation.
    /// Broad-snapshot first-run discovery always produces `validated_closed_view = false` (candidate only).
    pub validated_closed_view: bool,
    /// Count of consecutive authoritative executions since last discovery/audit (`E018`).
    pub authoritative_runs_since_audit: u64,
}

/// Construct a candidate [`ObservedInputRecipe`] from a first-run broad-snapshot
/// discovery execution (`E011`).
///
/// Combines `rustc` dep-info paths (`E006`), raw tracer positive reads (`E005` / `E014`),
/// directory enumerations, subprocess tool graph (`E008`), negative dependencies (`E020`),
/// and profile-aware volatility classification (`E009`).
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn discover_first_run_recipe(
    action_family_key: rabs_protocol::result_identity::TypedDigest,
    recipe_epoch: u32,
    dep_info_paths: &[String],
    observed_read_paths: &[String],
    directory_enumerations: &[(String, Vec<String>)],
    dangling_symlinks: &[(String, String)],
    subprocess_graph: &SubprocessInvocationGraph,
    record: &ObservationRecord,
    profile: &ProfileSurfaceSupport,
) -> ObservedInputRecipe {
    let mut declared_positive_paths = std::collections::BTreeSet::new();
    for p in dep_info_paths.iter().chain(observed_read_paths.iter()) {
        declared_positive_paths.insert(p.clone());
    }

    let mut declared_enumerations = std::collections::BTreeMap::new();
    for (dir, entries) in directory_enumerations {
        let mut sorted = entries.clone();
        sorted.sort_unstable();
        sorted.dedup();
        declared_enumerations.insert(dir.clone(), sorted);
    }

    let mut declared_executables = std::collections::BTreeMap::new();
    for node in &subprocess_graph.nodes {
        if let Some(obj) = &node.executable_object {
            declared_executables.insert(node.resolved_executable_path.clone(), obj.clone());
        }
    }

    let negative_dependencies =
        record.to_negative_dependency_set(directory_enumerations, dangling_symlinks);
    let (_, mut effect_class) =
        classify_effects_under_profile(record, observed_read_paths, false, false, profile);
    if !subprocess_graph.unidentified_executables.is_empty() {
        effect_class = rabs_protocol::volatility::EffectClass::Unclosable;
    }

    ObservedInputRecipe {
        action_family_key,
        recipe_epoch,
        declared_positive_paths,
        declared_enumerations,
        declared_executables,
        negative_dependencies,
        effect_class,
        validated_closed_view: false,
        authoritative_runs_since_audit: 0,
    }
}

/// Why a persisted [`ObservedInputRecipe`] drifted against a new snapshot (`E012`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecipeDriftReason {
    /// Recipe epoch does not match current epoch.
    EpochMismatch {
        /// Recipe's epoch.
        recipe_epoch: u32,
        /// Current required epoch.
        current_epoch: u32,
    },
    /// A declared positive input path is missing from the new snapshot.
    MissingPositiveInput {
        /// The missing virtual path.
        virtual_path: String,
    },
    /// A declared executable's content identity changed or disappeared.
    ExecutableChanged {
        /// Executable path.
        executable_path: String,
    },
    /// One or more negative dependencies were invalidated (`E020`).
    NegativeDependencyInvalidated(NegativeDependencyInvalidation),
}

/// Outcome of validating a stored [`ObservedInputRecipe`] against a new snapshot (`E012`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecipeValidationOutcome {
    /// Recipe matches the snapshot: returns the reconstructed [`rabs_protocol::input_evidence::ActionInputManifest`]
    /// and [`rabs_protocol::input_evidence::NegativeDependencySet`] ready for key construction.
    Reusable {
        /// Reconstructed positive input manifest from the new snapshot's object IDs.
        action_inputs: rabs_protocol::input_evidence::ActionInputManifest,
        /// Validated negative-dependency set.
        negative_dependencies: rabs_protocol::input_evidence::NegativeDependencySet,
    },
    /// Drift detected: caller must abort recipe fast-path and re-enter discovery (`R38`).
    DriftDetected {
        /// All detected drift reasons.
        reasons: Vec<RecipeDriftReason>,
    },
}

/// Validate a stored [`ObservedInputRecipe`] against a new coherent snapshot and
/// reconstruct its [`rabs_protocol::input_evidence::ActionInputManifest`] (`E012`).
#[must_use]
pub fn evaluate_recipe_against_snapshot(
    recipe: &ObservedInputRecipe,
    current_epoch: u32,
    snapshot_files: &std::collections::BTreeMap<String, rabs_protocol::result_identity::ObjectId>,
    snapshot_listings: &std::collections::BTreeMap<String, Vec<String>>,
    snapshot_executables: &std::collections::BTreeMap<
        String,
        rabs_protocol::result_identity::ObjectId,
    >,
) -> RecipeValidationOutcome {
    use rabs_protocol::input_evidence::{
        ActionInputManifest, DirectoryEnumeration, INPUT_EVIDENCE_SCHEMA_VERSION, InputFileType,
        PositiveInput,
    };
    use rabs_protocol::raw_bytes::RawBytes;

    let mut reasons = Vec::new();
    if recipe.recipe_epoch != current_epoch {
        reasons.push(RecipeDriftReason::EpochMismatch {
            recipe_epoch: recipe.recipe_epoch,
            current_epoch,
        });
    }

    let mut existing_paths: std::collections::BTreeSet<String> =
        snapshot_files.keys().cloned().collect();
    existing_paths.extend(snapshot_executables.keys().cloned());

    for inv in evaluate_negative_dependencies_against_tree(
        &recipe.negative_dependencies,
        &existing_paths,
        snapshot_listings,
    ) {
        reasons.push(RecipeDriftReason::NegativeDependencyInvalidated(inv));
    }

    let mut inputs = Vec::new();
    for path in &recipe.declared_positive_paths {
        if let Some(obj) = snapshot_files.get(path) {
            inputs.push(PositiveInput {
                virtual_path: RawBytes::new(path.as_bytes().to_vec()),
                object: obj.clone(),
                file_type: InputFileType::Regular,
                executable: false,
                symlink_resolution: Vec::new(),
            });
        } else {
            reasons.push(RecipeDriftReason::MissingPositiveInput {
                virtual_path: path.clone(),
            });
        }
    }

    let mut approved_generated_objects = Vec::new();
    for (exec_path, expected_obj) in &recipe.declared_executables {
        match snapshot_executables.get(exec_path) {
            Some(actual_obj) if actual_obj == expected_obj => {
                approved_generated_objects.push(actual_obj.clone());
            }
            _ => {
                reasons.push(RecipeDriftReason::ExecutableChanged {
                    executable_path: exec_path.clone(),
                });
            }
        }
    }

    let mut directory_enumerations = Vec::new();
    for (dir, expected_entries) in &recipe.declared_enumerations {
        let mut actual = snapshot_listings.get(dir).cloned().unwrap_or_default();
        actual.sort_unstable();
        actual.dedup();
        if &actual != expected_entries {
            reasons.push(RecipeDriftReason::NegativeDependencyInvalidated(
                NegativeDependencyInvalidation::ListingChanged {
                    pattern: dir.clone(),
                    expected: expected_entries.clone(),
                    actual,
                },
            ));
        } else {
            directory_enumerations.push(DirectoryEnumeration {
                virtual_path: RawBytes::new(dir.as_bytes().to_vec()),
                entries: expected_entries
                    .iter()
                    .map(|e| RawBytes::new(e.as_bytes().to_vec()))
                    .collect(),
            });
        }
    }

    if !reasons.is_empty() {
        return RecipeValidationOutcome::DriftDetected { reasons };
    }

    RecipeValidationOutcome::Reusable {
        action_inputs: ActionInputManifest {
            schema_version: INPUT_EVIDENCE_SCHEMA_VERSION,
            inputs,
            directory_enumerations,
            approved_generated_objects,
        },
        negative_dependencies: recipe.negative_dependencies.clone(),
    }
}

/// Violation detected during closed authoritative filesystem view execution (`E021`, invariant `I3`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClosedViewViolation {
    /// Action attempted to escape the canonical `/__rabs/` namespace or traverse `..`.
    PathEscapeAttempt {
        /// The offending path.
        path: String,
    },
    /// Action read a path not present in the enforced recipe closure.
    UndeclaredPositiveRead {
        /// The newly read virtual path.
        virtual_path: String,
    },
    /// Action observed a directory enumeration not matching the enforced recipe closure.
    ChangedDirectoryEnumeration {
        /// The directory path.
        directory_path: String,
    },
    /// Action executed a tool binary not declared in the recipe's executable closure.
    UndeclaredExecutable {
        /// The executable path.
        executable_path: String,
    },
}

/// Outcome of enforcing the closed authoritative filesystem view (`E021`, invariant `I3`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClosedViewEnforcementOutcome {
    /// Every observed read, enumeration, and executable stayed strictly inside the closed view.
    Satisfied,
    /// Escape or undeclared read detected: authoritative publication is ABORTED,
    /// the recipe's candidate path set is expanded, and the action re-enters discovery.
    AbortAndRediscover {
        /// All violations that triggered the abort.
        violations: Vec<ClosedViewViolation>,
        /// Updated positive path closure incorporating newly observed in-bounds reads.
        updated_candidate_paths: std::collections::BTreeSet<String>,
    },
}

fn is_canonical_rabs_path(path: &str) -> bool {
    path.starts_with("/__rabs/") && !path.split('/').any(|seg| seg == "..")
}

/// Enforce the closed authoritative filesystem view (`E021`, invariant `I3`).
///
/// Any path escape, undeclared read, changed directory enumeration, or undeclared
/// executable aborts the authoritative attempt BEFORE publication and returns
/// `AbortAndRediscover` with the updated candidate path closure.
#[must_use]
pub fn enforce_closed_authoritative_view(
    recipe: &ObservedInputRecipe,
    observed_reads: &[String],
    observed_enumerations: &std::collections::BTreeMap<String, Vec<String>>,
    observed_execs: &[String],
) -> ClosedViewEnforcementOutcome {
    let mut violations = Vec::new();
    let mut updated_candidate_paths = recipe.declared_positive_paths.clone();

    for read_path in observed_reads {
        if !is_canonical_rabs_path(read_path) {
            violations.push(ClosedViewViolation::PathEscapeAttempt {
                path: read_path.clone(),
            });
        } else if !recipe.declared_positive_paths.contains(read_path) {
            violations.push(ClosedViewViolation::UndeclaredPositiveRead {
                virtual_path: read_path.clone(),
            });
            updated_candidate_paths.insert(read_path.clone());
        }
    }

    for (dir, entries) in observed_enumerations {
        let mut sorted = entries.clone();
        sorted.sort_unstable();
        sorted.dedup();
        if recipe.declared_enumerations.get(dir) != Some(&sorted) {
            violations.push(ClosedViewViolation::ChangedDirectoryEnumeration {
                directory_path: dir.clone(),
            });
        }
    }

    for exec_path in observed_execs {
        if !recipe.declared_executables.contains_key(exec_path) {
            violations.push(ClosedViewViolation::UndeclaredExecutable {
                executable_path: exec_path.clone(),
            });
        }
    }

    if violations.is_empty() {
        ClosedViewEnforcementOutcome::Satisfied
    } else {
        ClosedViewEnforcementOutcome::AbortAndRediscover {
            violations,
            updated_candidate_paths,
        }
    }
}

/// First authoritative publication gate (`E024`, discovery step 9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirstPublicationDecision {
    /// Output digests and closed-view observations match (or the class is an admitted
    /// pre-known immutable fast-path class with a satisfied closed view); recipe is
    /// promoted to `validated_closed_view = true` and outputs may be published.
    AdmittedAuthoritative,
    /// Mismatch or closed-view violation between broad-snapshot discovery and
    /// closed-view validation; publication is blocked and family re-enters discovery.
    BlockedReenterDiscovery {
        /// Diagnostic reason explaining why first publication was blocked.
        reason: String,
    },
}

/// Validate a second closed-view execution against the broad-snapshot discovery run
/// before FIRST authoritative publication (`E024`).
#[must_use]
pub fn validate_second_closed_view_for_first_publication(
    broad_run_outputs: &std::collections::BTreeMap<
        String,
        rabs_protocol::result_identity::ObjectId,
    >,
    closed_run_outputs: Option<
        &std::collections::BTreeMap<String, rabs_protocol::result_identity::ObjectId>,
    >,
    closed_view_outcome: &ClosedViewEnforcementOutcome,
    immutable_fast_path_class: bool,
) -> FirstPublicationDecision {
    if let ClosedViewEnforcementOutcome::AbortAndRediscover { violations, .. } = closed_view_outcome
    {
        return FirstPublicationDecision::BlockedReenterDiscovery {
            reason: format!(
                "closed-view enforcement aborted with {} violation(s): {:?}",
                violations.len(),
                violations.first()
            ),
        };
    }

    if immutable_fast_path_class {
        return FirstPublicationDecision::AdmittedAuthoritative;
    }

    let Some(closed_outputs) = closed_run_outputs else {
        return FirstPublicationDecision::BlockedReenterDiscovery {
            reason: "newly discovered family requires second closed-view validation run before first authoritative publication (E024)".into(),
        };
    };

    if broad_run_outputs != closed_outputs {
        return FirstPublicationDecision::BlockedReenterDiscovery {
            reason: "second closed-view validation outputs diverged from broad-snapshot discovery outputs (E024)".into(),
        };
    }

    FirstPublicationDecision::AdmittedAuthoritative
}

/// Sampled re-audit scheduler for previously stable action families (`E018`, risk `R38`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SampledReauditScheduler {
    /// Deterministic sampling interval in authoritative executions (e.g. every Nth hit/run).
    pub audit_every_n_runs: u64,
}

/// Outcome of a sampled re-audit on a previously validated recipe (`E018`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReauditDisposition {
    /// Audit matched the closed recipe and outputs: family remains authoritative
    /// and its audit counter resets.
    ConfirmedStable,
    /// Audit detected undeclared reads, enumeration drift, or output divergence:
    /// family is demoted (`validated_closed_view = false`) and re-enters discovery.
    DemotedToDiscovery {
        /// Diagnostic reason for demotion.
        reason: String,
    },
}

impl SampledReauditScheduler {
    /// Determine whether `recipe` must undergo a sampled re-audit on this execution (`E018`).
    #[must_use]
    pub const fn should_reaudit(&self, recipe: &ObservedInputRecipe, current_epoch: u32) -> bool {
        if !recipe.validated_closed_view || recipe.recipe_epoch != current_epoch {
            return true;
        }
        if self.audit_every_n_runs == 0 {
            return false;
        }
        recipe.authoritative_runs_since_audit >= self.audit_every_n_runs
    }

    /// Apply the result of a sampled re-audit to `recipe` (`E018`).
    pub fn record_reaudit_outcome(
        &self,
        recipe: &mut ObservedInputRecipe,
        expected_outputs: &std::collections::BTreeMap<
            String,
            rabs_protocol::result_identity::ObjectId,
        >,
        audited_outputs: &std::collections::BTreeMap<
            String,
            rabs_protocol::result_identity::ObjectId,
        >,
        closed_view_outcome: &ClosedViewEnforcementOutcome,
    ) -> ReauditDisposition {
        if let ClosedViewEnforcementOutcome::AbortAndRediscover {
            violations,
            updated_candidate_paths,
        } = closed_view_outcome
        {
            recipe.validated_closed_view = false;
            recipe.authoritative_runs_since_audit = 0;
            recipe.declared_positive_paths = updated_candidate_paths.clone();
            return ReauditDisposition::DemotedToDiscovery {
                reason: format!(
                    "sampled re-audit detected {} closed-view violation(s) (R38)",
                    violations.len()
                ),
            };
        }
        if expected_outputs != audited_outputs {
            recipe.validated_closed_view = false;
            recipe.authoritative_runs_since_audit = 0;
            return ReauditDisposition::DemotedToDiscovery {
                reason: "sampled re-audit output digests diverged from expected outputs (R38)"
                    .into(),
            };
        }
        recipe.authoritative_runs_since_audit = 0;
        ReauditDisposition::ConfirmedStable
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical_namespace::{
        Bind, CanonicalNamespaceSpec, HostIsolationSupport, build_canonical_argv,
    };
    use crate::layout;

    fn full_support() -> HostIsolationSupport {
        HostIsolationSupport {
            bubblewrap: Some("bubblewrap 0.11.1".into()),
            unprivileged_userns: true,
            overlayfs: true,
            cgroup_v2: true,
            landlock: true,
        }
    }

    #[test]
    fn wrap_inserts_tracer_after_separator_and_keeps_boundary() {
        let mut spec = CanonicalNamespaceSpec::new();
        spec.rw_binds
            .push(Bind::new("/data/rabs/ws", layout::WORKSPACE));
        let launch =
            build_canonical_argv(&spec, &full_support(), "cargo", &["build".into()]).unwrap();
        let tracer = Tracer::StracePtrace("strace -- version 6.19".into());
        let wrapped = wrap_with_tracer(
            &launch,
            &tracer,
            DEFAULT_SYSCALL_SET,
            "/__rabs/out/strace.log",
        )
        .unwrap();
        let strs: Vec<String> = wrapped
            .argv
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let sep = strs.iter().position(|a| a == "--").unwrap();
        assert_eq!(strs[sep + 1], "/usr/bin/strace");
        assert!(
            strs.windows(2)
                .any(|w| w[0] == "-e" && w[1].starts_with("trace=%file"))
        );
        assert_eq!(strs.last().map(String::as_str), Some("build"));
        // Tracing changes no namespace property.
        assert_eq!(wrapped.boundary, launch.boundary);
        assert!(wrapped.boundary.satisfies_strict_hermetic_linux());
    }

    #[test]
    fn wrap_refuses_argv_without_separator() {
        let launch = NamespaceLaunch {
            argv: vec!["sh".into(), "-c".into()],
            boundary: crate::canonical_namespace::NamespaceBoundary {
                user_ns: false,
                pid_ns: false,
                ipc_ns: false,
                uts_hostname: None,
                net_isolated: false,
                mounts_closed_view: false,
                clearenv: false,
                host_usr_ro: false,
                tmpfs_tmp: false,
                proc_private: false,
                die_with_parent: false,
            },
        };
        let tracer = Tracer::StracePtrace("x".into());
        assert!(wrap_with_tracer(&launch, &tracer, "%file", "/log").is_err());
    }

    #[test]
    fn parser_classifies_reads_writes_failures_and_network() {
        let log = "\
1234  execve(\"/usr/bin/cargo\", [\"cargo\", \"build\"], 0x… /* 30 vars */) = 0
1234  newfstatat(AT_FDCWD, \"/__rabs/workspace/Cargo.toml\", {st_mode=S_IFREG|0644, ...}, 0) = 0
1234  openat(AT_FDCWD, \"/__rabs/workspace/src/lib.rs\", O_RDONLY|O_CLOEXEC) = 3
1234  openat(AT_FDCWD, \"/__rabs/out/fixture/debug/lib.rmeta\", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
1234  openat(AT_FDCWD, \"/__rabs/out/fixture/debug/deps/x\", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 4
1234  connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr(\"93.184.216.34\")}, 16) = -1 ENETUNREACH (Network is unreachable)
1234  +++ exited with 0 +++
";
        let record = parse_strace_log(log);
        assert_eq!(record.reads, 2); // openat read + newfstatat
        assert_eq!(record.writes, 1);
        assert_eq!(
            record.failed_opens,
            vec!["/__rabs/out/fixture/debug/lib.rmeta"]
        );
        assert_eq!(record.execs, vec!["/usr/bin/cargo"]);
        assert_eq!(record.network_attempts, 1);
        assert_eq!(record.network_denied, 1);
        assert!(!record.truncated);

        let effects = record.observed_effects();
        assert!(effects.observation_complete);
        assert!(effects.touched_network);
        let class = rabs_protocol::volatility::classify(&effects);
        assert_eq!(
            class,
            rabs_protocol::volatility::EffectClass::NetworkSensitive
        );
    }

    #[test]
    fn failed_exec_and_pid_prefixes_are_handled() {
        let log = "\
42    execve(\"/usr/bin/missing-tool\", [\"missing-tool\"], 0x…) = -1 ENOENT (No such file or directory)
7     openat(AT_FDCWD, \"/etc/ld.so.cache\", O_RDONLY|O_CLOEXEC) = 3
";
        let record = parse_strace_log(log);
        assert_eq!(record.failed_execs, vec!["/usr/bin/missing-tool"]);
        assert_eq!(record.reads, 1);
        assert!(!record.observed_effects().touched_network);
    }

    #[test]
    fn truncation_marks_observation_incomplete() {
        let record = ObservationRecord {
            failed_opens: vec!["x".to_owned(); MAX_SAMPLES],
            truncated: true,
            ..ObservationRecord::default()
        };
        let effects = record.observed_effects();
        assert!(!effects.observation_complete);
        // An incomplete trace must classify Unclosable — never Hermetic.
        assert_eq!(
            rabs_protocol::volatility::classify(&effects),
            rabs_protocol::volatility::EffectClass::Unclosable
        );
    }

    #[test]
    fn missing_log_file_is_an_observation_gap() {
        let record = parse_strace_log_file(Path::new("/nonexistent/rabs-e005.log"));
        assert!(record.truncated);
        assert!(!record.observed_effects().observation_complete);
    }

    #[test]
    fn e020_create_file_after_miss_and_glob_result_change_invalidate_negative_deps() {
        use std::collections::{BTreeMap, BTreeSet};

        let log = "\
101   openat(AT_FDCWD, \"/__rabs/workspace/optional.toml\", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
101   execve(\"/opt/custom/bin/cc\", [\"cc\"], 0x0) = -1 ENOENT (No such file or directory)
101   execve(\"/usr/local/bin/cc\", [\"cc\"], 0x0) = -1 ENOENT (No such file or directory)
101   execve(\"/usr/bin/cc\", [\"cc\"], 0x0) = 0
";
        let record = parse_strace_log(log);
        let negdeps = record.to_negative_dependency_set(
            &[(
                "/__rabs/workspace/plugins/*.rs".into(),
                vec!["/__rabs/workspace/plugins/a.rs".into()],
            )],
            &[(
                "/__rabs/workspace/dangling.rs".into(),
                "/__rabs/workspace/missing_target.rs".into(),
            )],
        );

        let mut existing = BTreeSet::from([
            "/__rabs/workspace/plugins/a.rs".to_string(),
            "/usr/bin/cc".to_string(),
        ]);
        let mut listings = BTreeMap::from([(
            "/__rabs/workspace/plugins/*.rs".to_string(),
            vec!["/__rabs/workspace/plugins/a.rs".to_string()],
        )]);

        assert!(
            evaluate_negative_dependencies_against_tree(&negdeps, &existing, &listings).is_empty(),
            "unchanged tree must satisfy all recorded negative dependencies"
        );

        // 1. Create file after miss (`optional.toml`).
        existing.insert("/__rabs/workspace/optional.toml".to_string());
        let inv1 = evaluate_negative_dependencies_against_tree(&negdeps, &existing, &listings);
        assert!(
            inv1.contains(&NegativeDependencyInvalidation::NewlyPresentPath {
                virtual_path: "/__rabs/workspace/optional.toml".into(),
            })
        );
        existing.remove("/__rabs/workspace/optional.toml");

        // 2. Glob/listing result change (`b.rs` added).
        listings
            .get_mut("/__rabs/workspace/plugins/*.rs")
            .unwrap()
            .push("/__rabs/workspace/plugins/b.rs".to_string());
        let inv2 = evaluate_negative_dependencies_against_tree(&negdeps, &existing, &listings);
        assert!(
            inv2.contains(&NegativeDependencyInvalidation::ListingChanged {
                pattern: "/__rabs/workspace/plugins/*.rs".into(),
                expected: vec!["/__rabs/workspace/plugins/a.rs".into()],
                actual: vec![
                    "/__rabs/workspace/plugins/a.rs".into(),
                    "/__rabs/workspace/plugins/b.rs".into(),
                ],
            })
        );
        listings
            .get_mut("/__rabs/workspace/plugins/*.rs")
            .unwrap()
            .pop();

        // 3. Earlier PATH directory gains shadowing `cc` (`/opt/custom/bin/cc`).
        existing.insert("/opt/custom/bin/cc".to_string());
        let inv3 = evaluate_negative_dependencies_against_tree(&negdeps, &existing, &listings);
        assert!(inv3.contains(
            &NegativeDependencyInvalidation::EarlierPathCandidateAppeared {
                tool: "cc".into(),
                directory: "/opt/custom/bin".into(),
            }
        ));
        existing.remove("/opt/custom/bin/cc");

        // 4. Dangling symlink target resolves.
        existing.insert("/__rabs/workspace/missing_target.rs".to_string());
        let inv4 = evaluate_negative_dependencies_against_tree(&negdeps, &existing, &listings);
        assert!(
            inv4.contains(&NegativeDependencyInvalidation::DanglingSymlinkResolved {
                symlink: "/__rabs/workspace/dangling.rs".into(),
                target: "/__rabs/workspace/missing_target.rs".into(),
            })
        );
    }

    fn obj(tag: u8) -> rabs_protocol::result_identity::ObjectId {
        rabs_protocol::result_identity::ObjectId(rabs_protocol::result_identity::TypedDigest {
            algorithm: rabs_protocol::result_identity::DigestAlgorithm::Sha256V1,
            domain: "rabs.object.v1",
            bytes: [tag; 32],
        })
    }

    fn fam_key(tag: u8) -> rabs_protocol::result_identity::TypedDigest {
        rabs_protocol::result_identity::TypedDigest {
            algorithm: rabs_protocol::result_identity::DigestAlgorithm::Sha256V1,
            domain: "rabs.family.v1",
            bytes: [tag; 32],
        }
    }

    #[test]
    fn e008_nested_tool_fixture_captures_build_script_spawning_cc_as_ld_graph() {
        let log = "\
1000  execve(\"/__rabs/out/build-script-build\", [\"build-script-build\"], 0x0) = 0
1000  clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD) = 1001
1001  execve(\"/__rabs/toolchain/bin/cc\", [\"cc\", \"-c\", \"foo.c\"], 0x0) = -1 ENOENT (No such file or directory)
1001  execve(\"/usr/local/bin/cc\", [\"cc\", \"-c\", \"foo.c\"], 0x0) = -1 ENOENT (No such file or directory)
1001  execve(\"/usr/bin/cc\", [\"cc\", \"-c\", \"foo.c\"], 0x0) = 0
1001  vfork() = 1002
1002  execve(\"/usr/bin/as\", [\"as\", \"-o\", \"foo.o\"], 0x0) = 0
1001  vfork() = 1003
1003  execve(\"/usr/local/bin/ld\", [\"ld\"], 0x0) = -1 ENOENT (No such file or directory)
1003  execve(\"/usr/bin/ld\", [\"ld\"], 0x0) = 0
";
        let graph = capture_subprocess_invocation_graph(log, |path| match path {
            "/__rabs/out/build-script-build" => Some(obj(1)),
            "/usr/bin/cc" => Some(obj(2)),
            "/usr/bin/as" => Some(obj(3)),
            "/usr/bin/ld" => Some(obj(4)),
            _ => None,
        });
        assert!(graph.unidentified_executables.is_empty());
        assert_eq!(graph.nodes.len(), 4);

        assert_eq!(graph.nodes[0].pid, 1000);
        assert_eq!(graph.nodes[0].parent_pid, None);
        assert_eq!(graph.nodes[0].tool_name, "build-script-build");

        assert_eq!(graph.nodes[1].pid, 1001);
        assert_eq!(graph.nodes[1].parent_pid, Some(1000));
        assert_eq!(graph.nodes[1].tool_name, "cc");
        assert_eq!(
            graph.nodes[1].probed_absent_dirs,
            vec!["/__rabs/toolchain/bin", "/usr/local/bin"]
        );
        assert_eq!(graph.nodes[1].executable_object, Some(obj(2)));

        assert_eq!(graph.nodes[2].pid, 1002);
        assert_eq!(graph.nodes[2].parent_pid, Some(1001));
        assert_eq!(graph.nodes[2].tool_name, "as");

        assert_eq!(graph.nodes[3].pid, 1003);
        assert_eq!(graph.nodes[3].parent_pid, Some(1001));
        assert_eq!(graph.nodes[3].tool_name, "ld");
        assert_eq!(graph.nodes[3].probed_absent_dirs, vec!["/usr/local/bin"]);
    }

    #[test]
    fn e009_and_e022_vdso_clock_and_alternate_entropy_classify_per_profile() {
        use rabs_protocol::volatility::EffectClass;

        let clean_record = ObservationRecord {
            reads: 4,
            ..ObservationRecord::default()
        };
        let strict = ProfileSurfaceSupport::strict_virtualized();
        let unvirtualized = ProfileSurfaceSupport::namespace_without_vdso_or_entropy_interception();

        // Program reading vDSO clock_gettime (unseen by strace) under unvirtualized profile -> ClockSensitive.
        let (effects_vdso_unvirt, class_vdso_unvirt) = classify_effects_under_profile(
            &clean_record,
            &["/__rabs/workspace/src/lib.rs".into()],
            true,
            false,
            &unvirtualized,
        );
        assert!(effects_vdso_unvirt.read_clock);
        assert_eq!(class_vdso_unvirt, EffectClass::ClockSensitive);
        assert!(!class_vdso_unvirt.shareable());

        // Same vDSO probe under a profile that virtualizes vDSO time -> Hermetic.
        let (effects_vdso_virt, class_vdso_virt) = classify_effects_under_profile(
            &clean_record,
            &["/__rabs/workspace/src/lib.rs".into()],
            true,
            false,
            &strict,
        );
        assert!(!effects_vdso_virt.read_clock);
        assert_eq!(class_vdso_virt, EffectClass::Hermetic);

        // Program reading alternate entropy (`AT_RANDOM` auxv / `getrandom` / `/dev/urandom`)
        // under unvirtualized profile -> RandomnessSensitive.
        let (_, class_entropy_unvirt) = classify_effects_under_profile(
            &clean_record,
            &["/dev/urandom".into()],
            false,
            true,
            &unvirtualized,
        );
        assert_eq!(class_entropy_unvirt, EffectClass::RandomnessSensitive);
        assert!(!class_entropy_unvirt.shareable());

        // Git state and host identity detection.
        let (_, class_git) = classify_effects_under_profile(
            &clean_record,
            &["/__rabs/workspace/.git/HEAD".into()],
            false,
            false,
            &strict,
        );
        assert_eq!(class_git, EffectClass::GitStateSensitive);

        let (_, class_host) = classify_effects_under_profile(
            &clean_record,
            &["/etc/hostname".into()],
            false,
            false,
            &strict,
        );
        assert_eq!(class_host, EffectClass::HostIdentitySensitive);
    }

    #[test]
    fn e011_e012_e014_e018_e021_e024_discovery_closed_view_and_proc_macro_untracked_input_pipeline()
    {
        use std::collections::BTreeMap;

        let log = "\
500   execve(\"/__rabs/out/proc-macro-srv\", [\"proc-macro-srv\"], 0x0) = 0
500   openat(AT_FDCWD, \"/__rabs/workspace/src/lib.rs\", O_RDONLY) = 3
500   openat(AT_FDCWD, \"/__rabs/workspace/schema/untracked.sql\", O_RDONLY) = 4
500   openat(AT_FDCWD, \"/__rabs/workspace/schema/optional.sql\", O_RDONLY) = -1 ENOENT (No such file or directory)
";
        let record = parse_strace_log(log);
        let graph = capture_subprocess_invocation_graph(log, |p| {
            (p == "/__rabs/out/proc-macro-srv").then(|| obj(0x10))
        });

        // E011: First-run discovery produces a complete recipe (candidate only: validated_closed_view == false).
        let mut recipe = discover_first_run_recipe(
            fam_key(1),
            1,
            &["/__rabs/workspace/src/lib.rs".into()],
            &[
                "/__rabs/workspace/src/lib.rs".into(),
                "/__rabs/workspace/schema/untracked.sql".into(),
            ],
            &[(
                "/__rabs/workspace/schema".into(),
                vec!["untracked.sql".into()],
            )],
            &[],
            &graph,
            &record,
            &ProfileSurfaceSupport::strict_virtualized(),
        );
        assert!(!recipe.validated_closed_view);
        assert!(
            recipe
                .declared_positive_paths
                .contains("/__rabs/workspace/schema/untracked.sql"),
            "E014: proc-macro untracked raw read beyond dep-info must enter the recipe"
        );

        let mut snapshot_files = BTreeMap::from([
            ("/__rabs/workspace/src/lib.rs".to_string(), obj(1)),
            ("/__rabs/workspace/schema/untracked.sql".to_string(), obj(2)),
        ]);
        let mut snapshot_listings = BTreeMap::from([(
            "/__rabs/workspace/schema".to_string(),
            vec!["untracked.sql".to_string()],
        )]);
        let snapshot_execs =
            BTreeMap::from([("/__rabs/out/proc-macro-srv".to_string(), obj(0x10))]);

        // E012: Unchanged snapshot reconstructs identical positive + negative manifests.
        let outcome_1 = evaluate_recipe_against_snapshot(
            &recipe,
            1,
            &snapshot_files,
            &snapshot_listings,
            &snapshot_execs,
        );
        let outcome_2 = evaluate_recipe_against_snapshot(
            &recipe,
            1,
            &snapshot_files,
            &snapshot_listings,
            &snapshot_execs,
        );
        assert_eq!(outcome_1, outcome_2);
        let RecipeValidationOutcome::Reusable {
            action_inputs: manifest_before,
            ..
        } = outcome_1
        else {
            panic!("expected Reusable");
        };

        // E014: Mutating the proc-macro's untracked file (`untracked.sql`) changes the reconstructed manifest!
        snapshot_files.insert("/__rabs/workspace/schema/untracked.sql".into(), obj(99));
        let RecipeValidationOutcome::Reusable {
            action_inputs: manifest_after,
            ..
        } = evaluate_recipe_against_snapshot(
            &recipe,
            1,
            &snapshot_files,
            &snapshot_listings,
            &snapshot_execs,
        )
        else {
            panic!("expected Reusable with updated object ID");
        };
        assert_ne!(
            manifest_before, manifest_after,
            "proc_macro_untracked_input_invalidates_key: mutating untracked.sql changes ActionInputManifest"
        );

        // E012: Drift fixture — creating `optional.sql` (previously FailedOpen) triggers DriftDetected!
        snapshot_files.insert("/__rabs/workspace/schema/optional.sql".into(), obj(3));
        snapshot_listings
            .get_mut("/__rabs/workspace/schema")
            .unwrap()
            .push("optional.sql".into());
        assert!(matches!(
            evaluate_recipe_against_snapshot(
                &recipe,
                1,
                &snapshot_files,
                &snapshot_listings,
                &snapshot_execs,
            ),
            RecipeValidationOutcome::DriftDetected { .. }
        ));

        // E021: Closed authoritative view enforcement — undeclared read and path escape abort!
        let valid_enum = BTreeMap::from([(
            "/__rabs/workspace/schema".to_string(),
            vec!["untracked.sql".to_string()],
        )]);
        assert_eq!(
            enforce_closed_authoritative_view(
                &recipe,
                &[
                    "/__rabs/workspace/src/lib.rs".into(),
                    "/__rabs/workspace/schema/untracked.sql".into()
                ],
                &valid_enum,
                &["/__rabs/out/proc-macro-srv".into()],
            ),
            ClosedViewEnforcementOutcome::Satisfied
        );

        let escape_outcome = enforce_closed_authoritative_view(
            &recipe,
            &[
                "/__rabs/workspace/src/lib.rs".into(),
                "/__rabs/workspace/schema/secret_new.sql".into(),
                "/etc/passwd".into(),
            ],
            &valid_enum,
            &["/__rabs/out/proc-macro-srv".into()],
        );
        match &escape_outcome {
            ClosedViewEnforcementOutcome::AbortAndRediscover {
                violations,
                updated_candidate_paths,
            } => {
                assert!(
                    violations.contains(&ClosedViewViolation::UndeclaredPositiveRead {
                        virtual_path: "/__rabs/workspace/schema/secret_new.sql".into(),
                    })
                );
                assert!(
                    violations.contains(&ClosedViewViolation::PathEscapeAttempt {
                        path: "/etc/passwd".into(),
                    })
                );
                assert!(
                    updated_candidate_paths.contains("/__rabs/workspace/schema/secret_new.sql")
                );
                assert!(!updated_candidate_paths.contains("/etc/passwd"));
            }
            ClosedViewEnforcementOutcome::Satisfied => panic!("expected AbortAndRediscover"),
        }

        // E024: Second closed-view validation before first authoritative publication.
        let broad_outputs = BTreeMap::from([("libfoo.rlib".to_string(), obj(0x50))]);
        let matching_closed = BTreeMap::from([("libfoo.rlib".to_string(), obj(0x50))]);
        let diverging_closed = BTreeMap::from([("libfoo.rlib".to_string(), obj(0x51))]);

        assert!(matches!(
            validate_second_closed_view_for_first_publication(
                &broad_outputs,
                None,
                &ClosedViewEnforcementOutcome::Satisfied,
                false,
            ),
            FirstPublicationDecision::BlockedReenterDiscovery { .. }
        ));
        assert!(matches!(
            validate_second_closed_view_for_first_publication(
                &broad_outputs,
                Some(&diverging_closed),
                &ClosedViewEnforcementOutcome::Satisfied,
                false,
            ),
            FirstPublicationDecision::BlockedReenterDiscovery { .. }
        ));
        assert_eq!(
            validate_second_closed_view_for_first_publication(
                &broad_outputs,
                Some(&matching_closed),
                &ClosedViewEnforcementOutcome::Satisfied,
                false,
            ),
            FirstPublicationDecision::AdmittedAuthoritative
        );
        recipe.validated_closed_view = true;

        // E018: Sampled re-audit scheduler triggers at interval and demotes on divergence.
        let scheduler = SampledReauditScheduler {
            audit_every_n_runs: 3,
        };
        assert!(!scheduler.should_reaudit(&recipe, 1));
        recipe.authoritative_runs_since_audit = 3;
        assert!(scheduler.should_reaudit(&recipe, 1));

        assert_eq!(
            scheduler.record_reaudit_outcome(
                &mut recipe,
                &broad_outputs,
                &matching_closed,
                &ClosedViewEnforcementOutcome::Satisfied,
            ),
            ReauditDisposition::ConfirmedStable
        );
        assert_eq!(recipe.authoritative_runs_since_audit, 0);
        assert!(recipe.validated_closed_view);

        // Divergence during sampled re-audit demotes the recipe back to discovery!
        assert!(matches!(
            scheduler.record_reaudit_outcome(
                &mut recipe,
                &broad_outputs,
                &diverging_closed,
                &ClosedViewEnforcementOutcome::Satisfied,
            ),
            ReauditDisposition::DemotedToDiscovery { .. }
        ));
        assert!(!recipe.validated_closed_view);
    }
}
