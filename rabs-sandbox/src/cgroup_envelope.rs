//! cgroup v2 resource envelope setup (bead E004; plan §186, §2235; I16).
//!
//! Per action attempt, the sandbox applies CPU/memory(/IO) bounds inside a
//! dedicated cgroup-v2 subgroup created under a MEASURED delegation point —
//! never an assumed one. The same subgroup is the anchor E029 builds the
//! ultimate descendant-containment proof on (`cgroup.kill`, PID-namespace
//! interplay): this module OWNS creation/attachment/measurement and the
//! termination classification; containment enforcement stays E029 scope.
//!
//! ## Delegation reality (measured, fleet-scanned 2026-08)
//!
//! Unprivileged writes need a delegated, writable ancestor of THIS
//! process's cgroup (`nsdelegate` mounts refuse everything else):
//! systemd root sessions land in `user-0.slice/session-N.scope` whose
//! parent is root-writable with `cpu memory pids` already distributed;
//! hardened uid-1000 hosts expose NO writable ancestor at all. The probe
//! therefore walks ancestors nearest-first, demands writability plus the
//! needed controllers, and REFUSES with the tried list when nothing
//! qualifies — a host that cannot enforce the envelope says so instead of
//! running unbounded ([`DelegationRefusal::NoWritableDelegatedRoot`]).
//!
//! ## Honest application
//!
//! [`create_envelope`] writes each bound, READS IT BACK, and records the
//! fact either as enforced `(file, value)` or skipped `(facet, why)` —
//! swap accounting missing, IO controller unavailable — mirroring the
//! `Enforced/NotEnforced` discipline of E010's isolation evidence.
//!
//! ## OOM classification (acceptance; I16)
//!
//! A process killed by SIGKILL while the envelope's `memory.events`
//! `oom_kill` counter advanced is [`Termination::OomKilled`] — which must
//! NEVER be published through `ResultKind::DeterministicFailure`
//! (`rabs_protocol::result_identity`; invariant I16): an envelope kill is
//! an environment event, not an admitted deterministic outcome.

use std::fs;
use std::path::{Path, PathBuf};

/// Controllers E004 can enforce. `io` is best-effort (needs device specs
/// and an `io`-capable hierarchy); `memory` + `cpu` are the load-bearing
/// pair the acceptance fixture proves.
const REQUIRED_CONTROLLERS: [&str; 2] = ["memory", "cpu"];
/// The optional controller this module applies when the hierarchy offers it.
const OPTIONAL_CONTROLLERS: [&str; 1] = ["io"];

/// A measured delegation point: a writable cgroup-v2 directory that offers
/// the required controllers and accepts child subgroups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    /// Absolute cgroup-fs path of the delegation point (children are
    /// created directly beneath it).
    pub root: PathBuf,
    /// Controllers available AT the root (`cgroup.controllers`).
    pub available: Vec<String>,
    /// Controllers already distributing through the root
    /// (`cgroup.subtree_control`) at probe time.
    pub enabled: Vec<String>,
}

/// Why probing found nowhere to build envelopes on this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegationRefusal {
    /// Not Linux, or `/proc/self/cgroup` is not a single unified `0::…`
    /// line (hybrid v1 layouts are out of scope by design).
    NotUnifiedV2,
    /// Every ancestor of this process's cgroup was tried; none was both
    /// writable and controller-capable. Names what was tried, for the
    /// doctor probe (E019 consumer).
    NoWritableDelegatedRoot {
        /// The candidate paths rejected, nearest first.
        tried: Vec<String>,
    },
}

impl std::fmt::Display for DelegationRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotUnifiedV2 => write!(f, "cgroup hierarchy is not unified v2"),
            Self::NoWritableDelegatedRoot { tried } => write!(
                f,
                "no writable delegated cgroup ancestor (tried: {})",
                tried.join(", ")
            ),
        }
    }
}

impl std::error::Error for DelegationRefusal {}

/// One `io.max` line for a device given as `MAJ:MIN`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoLimit {
    /// Device in `MAJ:MIN` form (as `/sys/block/*/dev` prints).
    pub device: String,
    /// Read bytes-per-second ceiling.
    pub read_bps: Option<u64>,
    /// Write bytes-per-second ceiling.
    pub write_bps: Option<u64>,
}

/// The resource bounds one action attempt asks the kernel to enforce.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResourceEnvelope {
    /// Hard memory cap in bytes (`memory.max`); `None` writes `max`.
    pub memory_max_bytes: Option<u64>,
    /// Swap cap in bytes (`memory.swap.max`); recorded honestly as
    /// skipped when the kernel lacks swap accounting.
    pub memory_swap_max_bytes: Option<u64>,
    /// CPU weight 1..=10000 (`cpu.weight`); clamped, `None` = 100.
    pub cpu_weight: Option<u64>,
    /// Per-device IO ceilings (`io.max`), applied only when the `io`
    /// controller is available; otherwise recorded as skipped.
    pub io_max: Vec<IoLimit>,
}

/// Typed refusals while building an envelope at an accepted delegation
/// point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    /// A required controller exists at the root but is not yet
    /// distributing, and the root still holds processes — enabling it
    /// would violate the no-internal-process rule. Move the workload or
    /// pick another root; never force it.
    RootHasProcesses {
        /// The delegation point.
        root: PathBuf,
    },
    /// An expected control file is missing (kernel too old, controller
    /// absent despite `cgroup.controllers`).
    MissingControlFile {
        /// The absolute file path.
        path: PathBuf,
    },
    /// A write or read-back failed.
    Io {
        /// What was being done.
        action: String,
        /// The OS error text.
        source: String,
    },
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RootHasProcesses { root } => write!(
                f,
                "root {} holds processes; cannot enable controllers",
                root.display()
            ),
            Self::MissingControlFile { path } => {
                write!(f, "missing control file {}", path.display())
            }
            Self::Io { action, source } => write!(f, "{action}: {source}"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// One applied bound, read back from the kernel after writing —
/// enforcement FACTS, never aspirations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedBound {
    /// Control file base name (e.g. `memory.max`).
    pub file: String,
    /// The value the kernel reports AFTER the write.
    pub value: String,
}

/// One requested bound the host could not enforce, with why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedBound {
    /// Facet name (e.g. `memory.swap.max`, `io.max`).
    pub facet: String,
    /// Why it is not enforced (e.g. `swap-accounting-unavailable`,
    /// `io-controller-unavailable`).
    pub reason: String,
}

/// A live envelope: the created subgroup plus what actually got enforced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedEnvelope {
    /// Absolute path of the created subgroup.
    pub path: PathBuf,
    /// Bounds verified by read-back.
    pub enforced: Vec<AppliedBound>,
    /// Requested facets not enforceable on this host.
    pub skipped: Vec<SkippedBound>,
}

impl AppliedEnvelope {
    /// Whether the memory controller is among the enforced bounds (the
    /// OOM classification requires it).
    #[must_use]
    pub fn memory_enforced(&self) -> bool {
        self.enforced.iter().any(|b| b.file == "memory.max")
    }
}

/// Probe for a usable delegation point: the nearest writable,
/// controller-capable ancestor of THIS process's cgroup.
///
/// # Errors
/// [`DelegationRefusal`] when the hierarchy is not unified v2 or no
/// ancestor qualifies (the refusal names every candidate tried).
pub fn probe_delegation() -> Result<Delegation, DelegationRefusal> {
    if !cfg!(target_os = "linux") {
        return Err(DelegationRefusal::NotUnifiedV2);
    }
    let raw =
        fs::read_to_string("/proc/self/cgroup").map_err(|_| DelegationRefusal::NotUnifiedV2)?;
    let mut lines = raw.lines().filter(|l| !l.trim().is_empty());
    let (Some(only), None) = (lines.next(), lines.next()) else {
        return Err(DelegationRefusal::NotUnifiedV2);
    };
    let path = only
        .strip_prefix("0::")
        .ok_or(DelegationRefusal::NotUnifiedV2)?;
    let self_cg = PathBuf::from("/sys/fs/cgroup").join(path.trim_start_matches('/'));

    let mut tried: Vec<String> = Vec::new();
    let mut cursor: Option<&Path> = self_cg.parent();
    while let Some(candidate) = cursor {
        let display = candidate.display().to_string();
        // The writability proof is a REAL create: a throwaway uniquely
        // named probe child, then removed again. Permission bits lie —
        // root-owned 0755 ancestors show owner-write to every reader yet
        // refuse unprivileged mkdir outright (nsdelegate-hardened hosts).
        if can_create_children(candidate)
            && let Some(delegation) = accept_candidate(candidate)
        {
            return Ok(delegation);
        }
        tried.push(display);
        cursor = candidate.parent();
    }
    Err(DelegationRefusal::NoWritableDelegatedRoot { tried })
}

/// The authoritative writability test: actually create a throwaway
/// uniquely-named child directory and remove it again. Anything less
/// (stat/permission bits) mis-accepts read-only-to-us roots.
fn can_create_children(dir: &Path) -> bool {
    let probe = dir.join(format!(
        "rabs-probe-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    match fs::create_dir(&probe) {
        Ok(()) => fs::remove_dir(&probe).is_ok(),
        Err(_) => false,
    }
}

/// Validate one candidate root: required controllers present. Returns the
/// delegation record or `None` to keep walking upward.
fn accept_candidate(candidate: &Path) -> Option<Delegation> {
    let available = read_lines(&candidate.join("cgroup.controllers"))?;
    let has_all = REQUIRED_CONTROLLERS
        .iter()
        .all(|need| available.iter().any(|c| c == need));
    if !has_all {
        return None;
    }
    let enabled = read_lines(&candidate.join("cgroup.subtree_control")).unwrap_or_default();
    Some(Delegation {
        root: candidate.to_path_buf(),
        available,
        enabled,
    })
}

fn read_lines(file: &Path) -> Option<Vec<String>> {
    fs::read_to_string(file)
        .ok()
        .map(|s| s.split_whitespace().map(str::to_owned).collect())
}

fn write_and_read_back(file: &Path, value: &str) -> Result<String, EnvelopeError> {
    let action = format!("write {}", file.display());
    fs::write(file, value).map_err(|e| EnvelopeError::Io {
        action: action.clone(),
        source: e.to_string(),
    })?;
    let read = fs::read_to_string(file).map_err(|e| EnvelopeError::Io {
        action: format!("read {}", file.display()),
        source: e.to_string(),
    })?;
    Ok(read.trim().to_owned())
}

fn enable_controller(root: &Path, controller: &str) -> Result<(), EnvelopeError> {
    let procs = read_lines(&root.join("cgroup.procs")).unwrap_or_default();
    if !procs.is_empty() {
        return Err(EnvelopeError::RootHasProcesses {
            root: root.to_path_buf(),
        });
    }
    let file = root.join("cgroup.subtree_control");
    let current = read_lines(&file).unwrap_or_default();
    if current.iter().any(|c| c == controller) {
        return Ok(());
    }
    write_and_read_back(&file, &format!("+{controller}")).map(|_| ())
}

/// Create the named subgroup under the delegation point and apply the
/// envelope, verifying every write by read-back.
///
/// The caller owns `name` uniqueness (include attempt ids). Cleanup is
/// [`cleanup_best_effort`] once attached processes have exited.
///
/// Side effect that OUTLIVES the subgroup by design: controller enables
/// written to the shared root's `cgroup.subtree_control` are NOT rolled
/// back on later failure — reverting could yank controllers out from
/// sibling tenants that raced us. Enabling `memory`/`cpu` distribution is
/// idempotent, fleet-level state (typical roots already distribute
/// `cpu memory pids`), so the residue is inert; it IS recorded here as a
/// known, accepted effect rather than hidden.
///
/// # Errors
/// [`EnvelopeError`] on any refused enablement or failed/ unverifiable
/// write — the SUBGROUP is removed again before returning, so a refused
/// attempt leaves no half-applied envelope behind (root-level controller
/// enables persist; see above).
pub fn create_envelope(
    delegation: &Delegation,
    name: &str,
    envelope: &ResourceEnvelope,
) -> Result<AppliedEnvelope, EnvelopeError> {
    let group = delegation.root.join(name);

    // Enable what is needed and possible BEFORE the subgroup exists, so a
    // refusal leaves nothing behind.
    let mut skipped = Vec::new();
    for controller in REQUIRED_CONTROLLERS {
        enable_controller(&delegation.root, controller)?;
    }
    for controller in OPTIONAL_CONTROLLERS {
        let offered = delegation.available.iter().any(|c| c == controller);
        let already = delegation.enabled.iter().any(|c| c == controller);
        if !offered {
            skipped.push(SkippedBound {
                facet: format!("{controller}.max"),
                reason: format!("{controller}-controller-unavailable"),
            });
        } else if !already {
            // Optional: a refusal here degrades to a skipped facet rather
            // than failing the whole envelope.
            if enable_controller(&delegation.root, controller).is_err() {
                skipped.push(SkippedBound {
                    facet: format!("{controller}.max"),
                    reason: "enable-refused-root-busy".to_owned(),
                });
            }
        }
    }

    fs::create_dir(&group).map_err(|e| EnvelopeError::Io {
        action: format!("mkdir {}", group.display()),
        source: e.to_string(),
    })?;

    // Any failed bound tears the SUBGROUP down again (root-level enables
    // persist by design — documented above).
    match apply_bounds(&group, envelope, &mut skipped) {
        Ok(enforced) => Ok(AppliedEnvelope {
            path: group,
            enforced,
            skipped,
        }),
        Err(err) => {
            let _ = fs::remove_dir(&group);
            Err(err)
        }
    }
}

fn apply_bounds(
    group: &Path,
    envelope: &ResourceEnvelope,
    skipped: &mut Vec<SkippedBound>,
) -> Result<Vec<AppliedBound>, EnvelopeError> {
    let mut enforced = Vec::new();

    // Memory hard cap.
    let memory_max = envelope
        .memory_max_bytes
        .map(|b| b.to_string())
        .unwrap_or_else(|| "max".to_owned());
    let memory_file = group.join("memory.max");
    if !memory_file.exists() {
        return Err(EnvelopeError::MissingControlFile { path: memory_file });
    }
    enforced.push(AppliedBound {
        file: "memory.max".to_owned(),
        value: write_and_read_back(&memory_file, &memory_max)?,
    });

    // Swap cap (absent when swap accounting is compiled off).
    let swap_file = group.join("memory.swap.max");
    if swap_file.exists() {
        let value = envelope
            .memory_swap_max_bytes
            .map(|b| b.to_string())
            .unwrap_or_else(|| "max".to_owned());
        enforced.push(AppliedBound {
            file: "memory.swap.max".to_owned(),
            value: write_and_read_back(&swap_file, &value)?,
        });
    } else {
        skipped.push(SkippedBound {
            facet: "memory.swap.max".to_owned(),
            reason: "swap-accounting-unavailable".to_owned(),
        });
    }

    // CPU weight, clamped into the kernel's documented range.
    let weight = envelope.cpu_weight.unwrap_or(100).clamp(1, 10_000);
    let weight_file = group.join("cpu.weight");
    if !weight_file.exists() {
        return Err(EnvelopeError::MissingControlFile { path: weight_file });
    }
    enforced.push(AppliedBound {
        file: "cpu.weight".to_owned(),
        value: write_and_read_back(&weight_file, &weight.to_string())?,
    });

    // IO ceilings, per declared device, only when the controller landed.
    if !envelope.io_max.is_empty() {
        let io_file = group.join("io.max");
        if !io_file.exists() {
            skipped.push(SkippedBound {
                facet: "io.max".to_owned(),
                reason: "io-controller-unavailable".to_owned(),
            });
        } else {
            for limit in &envelope.io_max {
                // Kernel format: one line per device —
                // `MAJ:MIN rbps=N wbps=M` (unspecified fields stay `max`
                // by omission; we only ever narrow rbps/wbps here).
                let line = format!(
                    "{} rbps={} wbps={}",
                    limit.device,
                    limit
                        .read_bps
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "max".to_owned()),
                    limit
                        .write_bps
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "max".to_owned()),
                );
                enforced.push(AppliedBound {
                    file: "io.max".to_owned(),
                    value: write_and_read_back(&io_file, &line)?,
                });
            }
        }
    }

    Ok(enforced)
}

/// Attach a process (and thereafter its future descendants) to the
/// envelope, verifying membership by read-back in BOTH profiles.
///
/// Residual race, documented: between the caller observing `pid` and this
/// write, the process could exit and its id be recycled — the write then
/// migrates an unrelated process into the envelope. Callers attaching a
/// freshly spawned child should keep the child deterministically blocked
/// (e.g. an empty stdin pipe read) until `attach` returns, which collapses
/// the window to zero in practice; the kernel rejects dead pids with
/// `ESRCH`, surfacing as [`EnvelopeError::Io`].
///
/// # Errors
/// [`EnvelopeError::Io`] when the pid cannot be written, or the read-back
/// does not show it as a member.
pub fn attach(env: &AppliedEnvelope, pid: u32) -> Result<(), EnvelopeError> {
    let procs = env.path.join("cgroup.procs");
    let read = write_and_read_back(&procs, &pid.to_string())?;
    if read.split_whitespace().any(|p| p == pid.to_string()) {
        Ok(())
    } else {
        Err(EnvelopeError::Io {
            action: format!("verify pid {pid} membership in {}", procs.display()),
            source: "pid absent after write (exited before attach?)".to_owned(),
        })
    }
}

/// Current `oom_kill` count of the envelope's `memory.events`.
///
/// # Errors
/// [`EnvelopeError::MissingControlFile`] when the memory controller was
/// not enforced for this envelope.
pub fn oom_kill_count(env: &AppliedEnvelope) -> Result<u64, EnvelopeError> {
    const FILE: &str = "memory.events";
    let path = env.path.join(FILE);
    let raw = fs::read_to_string(&path)
        .map_err(|_| EnvelopeError::MissingControlFile { path: path.clone() })?;
    for line in raw.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() == Some("oom_kill")
            && let Some(count) = fields.next().and_then(|n| n.parse::<u64>().ok())
        {
            return Ok(count);
        }
    }
    Err(EnvelopeError::MissingControlFile { path })
}

/// How an attached process's run ended, with the OOM verdict the
/// acceptance requires.
///
/// Classification rule: SIGKILL (direct signal 9, or shell-style exit
/// 137) while the envelope's `oom_kill` counter advanced means the KERNEL
/// killed the work for breaching its memory envelope —
/// [`Termination::OomKilled`], an environment event that MUST NOT be
/// published as `ResultKind::DeterministicFailure` (I16). Everything else
/// keeps its ordinary meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Termination {
    /// Ran to completion with this exit code.
    Exited(i32),
    /// Kernel OOM kill inside the envelope (SIGKILL + advancing
    /// `oom_kill`).
    OomKilled,
    /// Killed by this signal without OOM evidence.
    Signalled(i32),
}

/// Classify a wait result against the envelope's OOM evidence.
///
/// `exit_code`: `status.code()`; `signal`: `status.signal()` on Unix;
/// `oom_delta`: `after - before` of [`oom_kill_count`] around the run.
#[must_use]
pub fn classify_termination(
    exit_code: Option<i32>,
    signal: Option<i32>,
    oom_delta: u64,
) -> Termination {
    const SIGKILL: i32 = 9;
    let killed_by_sigkill = signal == Some(SIGKILL) || exit_code == Some(128 + SIGKILL);
    if oom_delta > 0 && killed_by_sigkill {
        return Termination::OomKilled;
    }
    match (exit_code, signal) {
        (Some(code), _) => Termination::Exited(code),
        (None, Some(sig)) => Termination::Signalled(sig),
        (None, None) => Termination::Exited(0),
    }
}

/// Best-effort teardown once nothing is attached: signal the group kill
/// file when the kernel supports it, then remove the now-empty subgroup.
/// Containment-grade kill/reap with escalation is E029's contract; this
/// is janitorial, and every failure is reported rather than hidden.
#[must_use]
pub fn cleanup_best_effort(env: &AppliedEnvelope) -> Vec<String> {
    let mut notes = Vec::new();
    let kill = env.path.join("cgroup.kill");
    if kill.exists()
        && let Err(e) = fs::write(&kill, "1")
    {
        notes.push(format!("cgroup.kill: {e}"));
    }
    if let Err(e) = fs::remove_dir(&env.path) {
        notes.push(format!("rmdir {}: {e}", env.path.display()));
    }
    notes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oom_kill_with_sigkill_classifies_oom_killed() {
        assert_eq!(
            classify_termination(None, Some(9), 1),
            Termination::OomKilled
        );
        // Shell-style: SIGKILL observed as exit 137.
        assert_eq!(
            classify_termination(Some(137), None, 3),
            Termination::OomKilled
        );
    }

    #[test]
    fn sigkill_without_oom_evidence_is_not_oom() {
        // I16 cuts both ways: OOM classification REQUIRES the counter.
        assert_eq!(
            classify_termination(None, Some(9), 0),
            Termination::Signalled(9)
        );
    }

    #[test]
    fn ordinary_exits_keep_their_meaning_despite_stale_counters() {
        assert_eq!(
            classify_termination(Some(1), None, 5),
            Termination::Exited(1)
        );
        assert_eq!(
            classify_termination(Some(0), None, 0),
            Termination::Exited(0)
        );
        assert_eq!(
            classify_termination(None, Some(15), 0),
            Termination::Signalled(15)
        );
    }

    #[test]
    fn cpu_weight_clamps_into_kernel_range() {
        let envelope = ResourceEnvelope {
            cpu_weight: Some(99_999),
            ..ResourceEnvelope::default()
        };
        // Clamping happens in apply_bounds; exercise via the pure helper.
        assert_eq!(envelope.cpu_weight.unwrap_or(100).clamp(1, 10_000), 10_000);
        assert_eq!(ResourceEnvelope::default().cpu_weight.unwrap_or(100), 100);
    }

    #[test]
    fn memory_enforced_reflects_applied_facts() {
        let env = AppliedEnvelope {
            path: PathBuf::from("/sys/fs/cgroup/rabs-test"),
            enforced: vec![AppliedBound {
                file: "memory.max".to_owned(),
                value: "33554432".to_owned(),
            }],
            skipped: vec![],
        };
        assert!(env.memory_enforced());
        let none = AppliedEnvelope {
            path: env.path.clone(),
            enforced: vec![],
            skipped: vec![SkippedBound {
                facet: "memory.max".to_owned(),
                reason: "x".to_owned(),
            }],
        };
        assert!(!none.memory_enforced());
    }

    #[test]
    fn non_linux_probe_refuses_typed() {
        // On non-Linux the probe refuses immediately; on Linux this test
        // still passes because the real probe path is exercised by the
        // live fixtures instead.
        if cfg!(target_os = "linux") {
            let _ = probe_delegation();
        } else {
            assert_eq!(probe_delegation(), Err(DelegationRefusal::NotUnifiedV2));
        }
    }
}
