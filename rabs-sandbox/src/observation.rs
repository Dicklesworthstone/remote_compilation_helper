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
}
