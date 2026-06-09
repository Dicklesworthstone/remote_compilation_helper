//! Exact user/path capability probes for runtimes, toolchains, and targets
//! (bd-session-history-remediation-ocv9i.12.2).
//!
//! A capability probe runs **as the configured remote user, using the exact
//! executable paths RCH will actually invoke** (not whatever a login shell's
//! PATH happens to resolve), so the facts reflect what an offloaded build will
//! really see. The probe is a single shell script that prints `RCH_FACT k=v`
//! lines; [`parse_capability_probe`] turns that output into [`ProbedFacts`],
//! and [`assess_admissibility`] decides whether the worker is admissible for a
//! given [`CapabilityRequirement`].
//!
//! Crucially this distinguishes **SSH reachability** (did the script run at
//! all?) from **capability admissibility** (it ran, but lacks a needed target /
//! the binary at the exact path is broken / the protocol is stale) — the two
//! failure classes operators kept conflating.

use crate::incident::IncidentReasonCode;
use crate::worker_facts::{
    DiskRootFacts, RuntimeFacts, RustFacts, WorkerBinaryFacts, derive_target_triple,
};

/// Sentinel prefix every probe fact line carries, so probe output is easy to
/// separate from incidental stdout.
pub const FACT_PREFIX: &str = "RCH_FACT ";

/// Exact paths/identity the probe must use (never PATH-resolved).
#[derive(Debug, Clone)]
pub struct ProbeSpec {
    /// SSH login user the probe runs as.
    pub remote_user: String,
    /// Exact path to the `rch-wkr` binary RCH will invoke.
    pub rch_wkr_path: String,
    /// Exact path to `cargo`, if known (else the probe tries `command -v`).
    pub cargo_path: Option<String>,
    /// Exact path to `rustup`, if known.
    pub rustup_path: Option<String>,
    /// Disk roots whose capacity to report (temp root, build roots, cargo home).
    pub disk_roots: Vec<String>,
}

impl ProbeSpec {
    #[must_use]
    pub fn new(remote_user: impl Into<String>, rch_wkr_path: impl Into<String>) -> Self {
        Self {
            remote_user: remote_user.into(),
            rch_wkr_path: rch_wkr_path.into(),
            cargo_path: None,
            rustup_path: None,
            disk_roots: Vec::new(),
        }
    }
}

/// Shell-quote a value for safe single-argument embedding.
fn shq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Build the capability-probe shell script. It is intentionally fail-soft:
/// every probe that errors simply omits its fact line, so a missing rustup or a
/// broken binary shows up as *absent facts* (capability), never as a script
/// crash (reachability).
#[must_use]
pub fn build_capability_probe_script(spec: &ProbeSpec) -> String {
    let wkr = shq(&spec.rch_wkr_path);
    let cargo = spec
        .cargo_path
        .as_deref()
        .map_or_else(|| "cargo".to_string(), shq);
    let rustup = spec
        .rustup_path
        .as_deref()
        .map_or_else(|| "rustup".to_string(), shq);

    let mut s = String::new();
    s.push_str("set -u; P='RCH_FACT '; ");
    // Host facts.
    s.push_str("printf '%sos=%s\\n' \"$P\" \"$(uname -s | tr 'A-Z' 'a-z')\"; ");
    s.push_str("printf '%sarch=%s\\n' \"$P\" \"$(uname -m)\"; ");
    s.push_str("printf '%suser=%s\\n' \"$P\" \"$(id -un 2>/dev/null)\"; ");
    // Worker binary at the EXACT path (version + protocol). Absent => broken.
    s.push_str(&format!("printf '%srch_wkr_path=%s\\n' \"$P\" {wkr}; "));
    s.push_str(&format!(
        "if [ -x {wkr} ]; then v=$({wkr} --version 2>/dev/null) && printf '%sworker_version=%s\\n' \"$P\" \"$v\"; \
         pr=$({wkr} --protocol-version 2>/dev/null) && printf '%sworker_protocol=%s\\n' \"$P\" \"$pr\"; fi; "
    ));
    // Cargo / rust.
    s.push_str(&format!(
        "cv=$({cargo} --version 2>/dev/null) && printf '%scargo_version=%s\\n' \"$P\" \"$cv\"; "
    ));
    // Toolchains + installed targets via rustup (each on its own fact line).
    s.push_str(&format!(
        "{rustup} toolchain list 2>/dev/null | awk -v p=\"$P\" '{{print p\"toolchain=\"$1}}'; "
    ));
    s.push_str(&format!(
        "{rustup} target list --installed 2>/dev/null | awk -v p=\"$P\" '{{print p\"target=\"$1}}'; "
    ));
    // JS runtimes (PATH-resolved is acceptable for these advisory facts).
    s.push_str("bv=$(bun --version 2>/dev/null) && printf '%sbun_version=%s\\n' \"$P\" \"$bv\"; ");
    s.push_str(
        "nv=$(node --version 2>/dev/null) && printf '%snode_version=%s\\n' \"$P\" \"$nv\"; ",
    );
    s.push_str(
        "npmv=$(npm --version 2>/dev/null) && printf '%snpm_version=%s\\n' \"$P\" \"$npmv\"; ",
    );
    // Disk roots: path;total_kb;avail_kb;avail_inodes (df -Pk and df -Pi).
    for root in &spec.disk_roots {
        let q = shq(root);
        s.push_str(&format!(
            "if [ -d {q} ]; then \
               b=$(df -Pk {q} 2>/dev/null | awk 'NR==2{{print $2\";\"$4}}'); \
               i=$(df -Pi {q} 2>/dev/null | awk 'NR==2{{print $4}}'); \
               printf '%sdisk=%s;%s;%s\\n' \"$P\" {q} \"$b\" \"$i\"; \
             fi; "
        ));
    }
    s
}

/// Structured facts parsed from probe output. Sub-facts are `None`/empty when
/// the corresponding probe produced no line (i.e. the capability is absent).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProbedFacts {
    pub os: Option<String>,
    pub arch: Option<String>,
    pub probed_user: Option<String>,
    pub rch_wkr_path: Option<String>,
    pub worker: Option<WorkerBinaryFacts>,
    pub rust: RustFacts,
    pub runtimes: RuntimeFacts,
    pub disk_roots: Vec<DiskRootFacts>,
    /// Raw worker_version line (kept even if protocol was missing).
    worker_version: Option<String>,
    worker_protocol: Option<u32>,
}

impl ProbedFacts {
    /// The worker's derived target triple from probed os/arch (libc unknown here
    /// — defaults to gnu on linux; collectors that know musl override on the
    /// assembled [`crate::worker_facts::HostFacts`]).
    #[must_use]
    pub fn target_triple(&self) -> Option<String> {
        match (&self.os, &self.arch) {
            (Some(os), Some(arch)) => Some(derive_target_triple(os, arch, None)),
            _ => None,
        }
    }
}

/// Parse `RCH_FACT k=v` probe output into [`ProbedFacts`]. Lines without the
/// prefix are ignored, so incidental stdout never corrupts the parse.
#[must_use]
pub fn parse_capability_probe(stdout: &str) -> ProbedFacts {
    let mut f = ProbedFacts::default();
    for line in stdout.lines() {
        let Some(kv) = line.trim().strip_prefix(FACT_PREFIX) else {
            continue;
        };
        let Some((key, value)) = kv.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key {
            "os" => f.os = Some(value.to_string()),
            "arch" => f.arch = Some(value.to_string()),
            "user" => f.probed_user = Some(value.to_string()),
            "rch_wkr_path" => f.rch_wkr_path = Some(value.to_string()),
            "worker_version" => f.worker_version = Some(value.to_string()),
            "worker_protocol" => f.worker_protocol = value.parse::<u32>().ok(),
            "cargo_version" => f.rust.rustc_version = Some(value.to_string()),
            "toolchain" => f.rust.toolchains.push(value.to_string()),
            "target" => f.rust.targets.push(value.to_string()),
            "bun_version" => f.runtimes.bun_version = Some(value.to_string()),
            "node_version" => f.runtimes.node_version = Some(value.to_string()),
            "npm_version" => f.runtimes.npm_version = Some(value.to_string()),
            "disk" => {
                // path;total_kb;avail_kb;avail_inodes
                let parts: Vec<&str> = value.split(';').collect();
                if parts.len() == 4 {
                    let kb = |s: &str| s.parse::<u64>().unwrap_or(0).saturating_mul(1024);
                    f.disk_roots.push(DiskRootFacts {
                        path: parts[0].to_string(),
                        total_bytes: kb(parts[1]),
                        available_bytes: kb(parts[2]),
                        available_inodes: parts[3].parse::<u64>().unwrap_or(0),
                    });
                }
            }
            _ => {}
        }
    }
    // Assemble the worker binary facts only if a version was reported (i.e. the
    // binary at the exact path actually ran).
    if let Some(version) = f.worker_version.clone() {
        f.worker = Some(WorkerBinaryFacts {
            rch_wkr_path: f.rch_wkr_path.clone().unwrap_or_default(),
            version,
            protocol_version: f.worker_protocol.unwrap_or(0),
        });
    }
    f
}

/// What a command needs from a worker before it is admissible.
#[derive(Debug, Clone, Default)]
pub struct CapabilityRequirement {
    /// rustup targets the build needs (e.g. `wasm32-unknown-unknown`).
    pub needs_targets: Vec<String>,
    /// Minimum acceptable worker wire protocol.
    pub min_protocol: u32,
    /// Whether a working cargo is required.
    pub needs_cargo: bool,
    /// Required host OS for the produced artifact (e.g. `linux`, `darwin`).
    /// Matched case-insensitively against the worker's probed `os`.
    pub needs_os: Option<String>,
    /// Required host arch (e.g. `x86_64`, `aarch64`), matched case-insensitively.
    pub needs_arch: Option<String>,
    /// Whether a working `bun` runtime is required.
    pub needs_bun: bool,
    /// Whether a working `node` runtime is required.
    pub needs_node: bool,
    /// Specific rustup toolchains the build needs (prefix-matched against the
    /// worker's installed toolchains, e.g. `nightly-2025-11-01` matches
    /// `nightly-2025-11-01-x86_64-unknown-linux-gnu`).
    pub needs_toolchains: Vec<String>,
}

impl CapabilityRequirement {
    /// A bare Rust build requirement (cargo, given wire protocol).
    #[must_use]
    pub fn rust(min_protocol: u32) -> Self {
        Self {
            min_protocol,
            needs_cargo: true,
            ..Self::default()
        }
    }

    /// Require these rustup targets (builder style).
    #[must_use]
    pub fn with_targets<I, S>(mut self, targets: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.needs_targets = targets.into_iter().map(Into::into).collect();
        self
    }

    /// Require a host OS (e.g. `linux` / `darwin`).
    #[must_use]
    pub fn with_os(mut self, os: impl Into<String>) -> Self {
        self.needs_os = Some(os.into());
        self
    }

    /// Require a host arch (e.g. `x86_64` / `aarch64`).
    #[must_use]
    pub fn with_arch(mut self, arch: impl Into<String>) -> Self {
        self.needs_arch = Some(arch.into());
        self
    }

    /// Require specific rustup toolchains (builder style).
    #[must_use]
    pub fn with_toolchains<I, S>(mut self, toolchains: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.needs_toolchains = toolchains.into_iter().map(Into::into).collect();
        self
    }
}

/// Outcome of an admissibility assessment. Reachability is the caller's concern
/// (did the SSH probe run?); this answers "it ran — is it usable?".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityVerdict {
    /// Worker is admissible for the requirement.
    Admissible,
    /// Worker ran the probe but is not admissible, with the incident reason.
    Rejected {
        reason: IncidentReasonCode,
        detail: String,
    },
}

/// Assess admissibility of probed facts against a requirement. Assumes the
/// probe was reachable (non-empty facts); a fully empty parse should be treated
/// as unreachable by the caller, not passed here.
#[must_use]
pub fn assess_admissibility(facts: &ProbedFacts, req: &CapabilityRequirement) -> CapabilityVerdict {
    // The exact-path worker binary must have produced a version (root-good /
    // user-broken: the binary at the configured path is unusable for this user).
    let Some(worker) = &facts.worker else {
        return CapabilityVerdict::Rejected {
            reason: IncidentReasonCode::WrongUserPathWorkerBinary,
            detail: format!(
                "rch-wkr at {} did not report a version as the configured user",
                facts.rch_wkr_path.as_deref().unwrap_or("<unknown path>")
            ),
        };
    };
    if worker.protocol_version < req.min_protocol {
        return CapabilityVerdict::Rejected {
            reason: IncidentReasonCode::WrongUserPathWorkerBinary,
            detail: format!(
                "worker protocol {} < required {}",
                worker.protocol_version, req.min_protocol
            ),
        };
    }
    // Host OS/arch must match the required output triple — a worker that ran the
    // probe fine can still produce the wrong-platform artifact.
    if let Some(needed_os) = &req.needs_os {
        let matches = facts
            .os
            .as_deref()
            .is_some_and(|os| os.eq_ignore_ascii_case(needed_os));
        if !matches {
            return CapabilityVerdict::Rejected {
                reason: IncidentReasonCode::OsArchMismatch,
                detail: format!(
                    "worker OS {} does not satisfy required {}",
                    facts.os.as_deref().unwrap_or("<unknown>"),
                    needed_os
                ),
            };
        }
    }
    if let Some(needed_arch) = &req.needs_arch {
        let matches = facts
            .arch
            .as_deref()
            .is_some_and(|arch| arch.eq_ignore_ascii_case(needed_arch));
        if !matches {
            return CapabilityVerdict::Rejected {
                reason: IncidentReasonCode::OsArchMismatch,
                detail: format!(
                    "worker arch {} does not satisfy required {}",
                    facts.arch.as_deref().unwrap_or("<unknown>"),
                    needed_arch
                ),
            };
        }
    }
    if req.needs_cargo && facts.rust.rustc_version.is_none() {
        return CapabilityVerdict::Rejected {
            reason: IncidentReasonCode::MissingRuntimeToolchainTarget,
            detail: "cargo/rust toolchain not found at the configured user/path".to_string(),
        };
    }
    for needed in &req.needs_toolchains {
        // Prefix match: `nightly-2025-11-01` satisfies
        // `nightly-2025-11-01-x86_64-unknown-linux-gnu`.
        if !facts.rust.toolchains.iter().any(|t| t.starts_with(needed)) {
            return CapabilityVerdict::Rejected {
                reason: IncidentReasonCode::MissingRuntimeToolchainTarget,
                detail: format!("missing rustup toolchain {needed}"),
            };
        }
    }
    for needed in &req.needs_targets {
        if !facts.rust.targets.iter().any(|t| t == needed) {
            return CapabilityVerdict::Rejected {
                reason: IncidentReasonCode::MissingRuntimeToolchainTarget,
                detail: format!("missing rustup target {needed}"),
            };
        }
    }
    if req.needs_bun && facts.runtimes.bun_version.is_none() {
        return CapabilityVerdict::Rejected {
            reason: IncidentReasonCode::MissingRuntimeToolchainTarget,
            detail: "bun runtime not found at the configured user/path".to_string(),
        };
    }
    if req.needs_node && facts.runtimes.node_version.is_none() {
        return CapabilityVerdict::Rejected {
            reason: IncidentReasonCode::MissingRuntimeToolchainTarget,
            detail: "node runtime not found at the configured user/path".to_string(),
        };
    }
    CapabilityVerdict::Admissible
}

/// A worker's live admission state, separate from its (structural) capability.
/// Capability says *can this worker ever run the command*; liveness says *is it
/// usable right now*. Keeping them distinct is what lets selection report a
/// missing-capability reason instead of conflating it with an unhealthy or busy
/// worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerLiveness {
    /// The worker's capability facts are too stale to trust.
    pub telemetry_stale: bool,
    /// The worker is healthy (circuit closed, reachable).
    pub healthy: bool,
    /// The worker has at least one free build slot.
    pub has_free_slot: bool,
}

impl WorkerLiveness {
    /// A fresh, healthy, idle worker.
    #[must_use]
    pub fn ready() -> Self {
        Self {
            telemetry_stale: false,
            healthy: true,
            has_free_slot: true,
        }
    }
}

/// The distinct eligibility outcomes selection must tell apart, each with its
/// own incident reason — so an agent learns *why* a worker was not chosen
/// (missing capability vs unhealthy vs busy vs stale facts) rather than a single
/// opaque "no admissible workers".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EligibilityVerdict {
    /// Capable, fresh, healthy, and has a free slot.
    Eligible,
    /// The worker structurally cannot run this command.
    MissingCapability {
        reason: IncidentReasonCode,
        detail: String,
    },
    /// Capability is unknowable because the facts are stale.
    StaleTelemetry,
    /// Capable but unhealthy (circuit open / unreachable).
    Unhealthy,
    /// Capable and healthy but at capacity right now.
    Busy,
}

impl EligibilityVerdict {
    /// The incident reason for this verdict (`None` when eligible).
    #[must_use]
    pub fn reason(&self) -> Option<IncidentReasonCode> {
        match self {
            EligibilityVerdict::Eligible => None,
            EligibilityVerdict::MissingCapability { reason, .. } => Some(*reason),
            EligibilityVerdict::StaleTelemetry => Some(IncidentReasonCode::TelemetryStale),
            EligibilityVerdict::Unhealthy => Some(IncidentReasonCode::CircuitOpen),
            EligibilityVerdict::Busy => Some(IncidentReasonCode::InsufficientSlots),
        }
    }

    /// Whether the worker is eligible to run the command.
    #[must_use]
    pub fn is_eligible(&self) -> bool {
        matches!(self, EligibilityVerdict::Eligible)
    }
}

/// Assess a worker's full eligibility for a command, distinguishing missing
/// capability from an unhealthy or busy worker. Pure and total.
///
/// Precedence: stale facts (can't trust capability) first; then a structural
/// capability rejection (no point waiting for a slot it can never use); then
/// health; then capacity. Capacity/health are transient, so they only matter
/// once the worker is known capable on fresh facts.
#[must_use]
pub fn assess_worker_eligibility(
    facts: &ProbedFacts,
    req: &CapabilityRequirement,
    liveness: &WorkerLiveness,
) -> EligibilityVerdict {
    if liveness.telemetry_stale {
        return EligibilityVerdict::StaleTelemetry;
    }
    if let CapabilityVerdict::Rejected { reason, detail } = assess_admissibility(facts, req) {
        return EligibilityVerdict::MissingCapability { reason, detail };
    }
    if !liveness.healthy {
        return EligibilityVerdict::Unhealthy;
    }
    if !liveness.has_free_slot {
        return EligibilityVerdict::Busy;
    }
    EligibilityVerdict::Eligible
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> ProbeSpec {
        let mut s = ProbeSpec::new("rch", "/home/rch/.local/bin/rch-wkr");
        s.cargo_path = Some("/home/rch/.cargo/bin/cargo".to_string());
        s.disk_roots = vec!["/data/tmp".to_string()];
        s
    }

    #[test]
    fn script_uses_exact_paths_and_probes_all_facts() {
        let script = build_capability_probe_script(&spec());
        // Exact rch-wkr path is embedded (not PATH-resolved).
        assert!(script.contains("/home/rch/.local/bin/rch-wkr"));
        assert!(script.contains("/home/rch/.cargo/bin/cargo"));
        // Probes every required capability dimension.
        assert!(script.contains("--version"));
        assert!(script.contains("--protocol-version"));
        assert!(script.contains("toolchain list"));
        assert!(script.contains("target list --installed"));
        assert!(script.contains("bun --version"));
        assert!(script.contains("df -Pk"));
        assert!(script.contains("df -Pi"));
        // Quoted disk root.
        assert!(script.contains("'/data/tmp'"));
    }

    fn good_output() -> &'static str {
        "RCH_FACT os=linux\n\
         RCH_FACT arch=x86_64\n\
         RCH_FACT user=rch\n\
         RCH_FACT rch_wkr_path=/home/rch/.local/bin/rch-wkr\n\
         RCH_FACT worker_version=1.0.41\n\
         RCH_FACT worker_protocol=3\n\
         RCH_FACT cargo_version=cargo 1.98.0-nightly\n\
         RCH_FACT toolchain=stable\n\
         RCH_FACT toolchain=nightly-2026-05-22\n\
         RCH_FACT target=x86_64-unknown-linux-gnu\n\
         RCH_FACT target=wasm32-unknown-unknown\n\
         RCH_FACT bun_version=1.1.0\n\
         RCH_FACT disk=/data/tmp;1048576;524288;900000\n\
         incidental noise line that must be ignored\n"
    }

    #[test]
    fn parses_full_probe_output() {
        let f = parse_capability_probe(good_output());
        assert_eq!(f.os.as_deref(), Some("linux"));
        assert_eq!(f.arch.as_deref(), Some("x86_64"));
        assert_eq!(f.probed_user.as_deref(), Some("rch"));
        let w = f.worker.as_ref().unwrap();
        assert_eq!(w.version, "1.0.41");
        assert_eq!(w.protocol_version, 3);
        assert_eq!(w.rch_wkr_path, "/home/rch/.local/bin/rch-wkr");
        assert_eq!(f.rust.toolchains, vec!["stable", "nightly-2026-05-22"]);
        assert!(f.rust.targets.iter().any(|t| t == "wasm32-unknown-unknown"));
        assert_eq!(f.runtimes.bun_version.as_deref(), Some("1.1.0"));
        assert_eq!(f.disk_roots.len(), 1);
        assert_eq!(f.disk_roots[0].path, "/data/tmp");
        assert_eq!(f.disk_roots[0].available_bytes, 524288 * 1024);
        assert_eq!(f.disk_roots[0].available_inodes, 900000);
        assert_eq!(
            f.target_triple().as_deref(),
            Some("x86_64-unknown-linux-gnu")
        );
    }

    fn req_wasm() -> CapabilityRequirement {
        CapabilityRequirement {
            needs_targets: vec!["wasm32-unknown-unknown".to_string()],
            min_protocol: 3,
            needs_cargo: true,
            ..CapabilityRequirement::default()
        }
    }

    #[test]
    fn admissible_when_all_capabilities_present() {
        let f = parse_capability_probe(good_output());
        assert_eq!(
            assess_admissibility(&f, &req_wasm()),
            CapabilityVerdict::Admissible
        );
    }

    #[test]
    fn user_broken_binary_rejected_distinct_from_unreachable() {
        // The probe RAN (host facts present) but the exact-path binary produced
        // no version — root-good / user-broken. This is capability rejection,
        // not unreachability.
        let out = "RCH_FACT os=linux\nRCH_FACT arch=x86_64\n\
                   RCH_FACT rch_wkr_path=/home/rch/.local/bin/rch-wkr\n";
        let f = parse_capability_probe(out);
        assert!(f.worker.is_none());
        match assess_admissibility(&f, &req_wasm()) {
            CapabilityVerdict::Rejected { reason, .. } => {
                assert_eq!(reason, IncidentReasonCode::WrongUserPathWorkerBinary);
            }
            other => panic!("expected rejection, got {other:?}"),
        }
    }

    #[test]
    fn missing_rustup_rejected_for_cargo_requirement() {
        // Worker fine, but no cargo/toolchains were probed.
        let out = "RCH_FACT os=linux\nRCH_FACT arch=x86_64\n\
                   RCH_FACT worker_version=1.0.41\nRCH_FACT worker_protocol=3\n";
        let f = parse_capability_probe(out);
        match assess_admissibility(&f, &req_wasm()) {
            CapabilityVerdict::Rejected { reason, detail } => {
                assert_eq!(reason, IncidentReasonCode::MissingRuntimeToolchainTarget);
                assert!(detail.contains("cargo"));
            }
            other => panic!("expected rejection, got {other:?}"),
        }
    }

    #[test]
    fn missing_wasm_target_rejected() {
        // Has cargo + protocol, but lacks the wasm target.
        let out = "RCH_FACT worker_version=1.0.41\nRCH_FACT worker_protocol=3\n\
                   RCH_FACT cargo_version=cargo 1.98\nRCH_FACT target=x86_64-unknown-linux-gnu\n";
        let f = parse_capability_probe(out);
        match assess_admissibility(&f, &req_wasm()) {
            CapabilityVerdict::Rejected { reason, detail } => {
                assert_eq!(reason, IncidentReasonCode::MissingRuntimeToolchainTarget);
                assert!(detail.contains("wasm32-unknown-unknown"));
            }
            other => panic!("expected rejection, got {other:?}"),
        }
    }

    #[test]
    fn stale_worker_protocol_rejected() {
        let out = "RCH_FACT worker_version=0.9.0\nRCH_FACT worker_protocol=1\n\
                   RCH_FACT cargo_version=cargo 1.98\nRCH_FACT target=wasm32-unknown-unknown\n";
        let f = parse_capability_probe(out);
        match assess_admissibility(&f, &req_wasm()) {
            CapabilityVerdict::Rejected { reason, detail } => {
                assert_eq!(reason, IncidentReasonCode::WrongUserPathWorkerBinary);
                assert!(detail.contains("protocol"));
            }
            other => panic!("expected rejection, got {other:?}"),
        }
    }

    #[test]
    fn empty_output_parses_empty() {
        // A fully empty parse is the caller's signal of unreachability.
        let f = parse_capability_probe("");
        assert_eq!(f, ProbedFacts::default());
        assert!(f.worker.is_none());
        assert!(f.os.is_none());
    }

    // --- 12.3: OS/arch, runtime, toolchain capability dimensions -----------

    #[test]
    fn os_mismatch_rejected_with_osarch_reason() {
        // A linux worker cannot produce a darwin artifact.
        let f = parse_capability_probe(good_output());
        let req = CapabilityRequirement::rust(3).with_os("darwin");
        match assess_admissibility(&f, &req) {
            CapabilityVerdict::Rejected { reason, detail } => {
                assert_eq!(reason, IncidentReasonCode::OsArchMismatch);
                assert!(detail.contains("darwin"));
            }
            other => panic!("expected OS-mismatch rejection, got {other:?}"),
        }
        // The matching OS is admissible.
        assert_eq!(
            assess_admissibility(&f, &CapabilityRequirement::rust(3).with_os("linux")),
            CapabilityVerdict::Admissible
        );
    }

    #[test]
    fn arch_mismatch_rejected_with_osarch_reason() {
        let f = parse_capability_probe(good_output());
        let req = CapabilityRequirement::rust(3).with_arch("aarch64");
        match assess_admissibility(&f, &req) {
            CapabilityVerdict::Rejected { reason, .. } => {
                assert_eq!(reason, IncidentReasonCode::OsArchMismatch);
            }
            other => panic!("expected arch-mismatch rejection, got {other:?}"),
        }
    }

    #[test]
    fn missing_node_runtime_rejected() {
        // good_output has bun but no node.
        let f = parse_capability_probe(good_output());
        let mut req = CapabilityRequirement::rust(3);
        req.needs_node = true;
        match assess_admissibility(&f, &req) {
            CapabilityVerdict::Rejected { reason, detail } => {
                assert_eq!(reason, IncidentReasonCode::MissingRuntimeToolchainTarget);
                assert!(detail.contains("node"));
            }
            other => panic!("expected node rejection, got {other:?}"),
        }
        // bun IS present, so a bun requirement is admissible.
        let mut bun_req = CapabilityRequirement::rust(3);
        bun_req.needs_bun = true;
        assert_eq!(
            assess_admissibility(&f, &bun_req),
            CapabilityVerdict::Admissible
        );
    }

    #[test]
    fn specific_toolchain_prefix_matched() {
        let f = parse_capability_probe(good_output());
        // Installed nightly-2026-05-22 satisfies the bare prefix.
        let ok = CapabilityRequirement::rust(3).with_toolchains(["nightly-2026-05-22"]);
        assert_eq!(assess_admissibility(&f, &ok), CapabilityVerdict::Admissible);
        // A different pinned nightly is missing.
        let missing = CapabilityRequirement::rust(3).with_toolchains(["nightly-2025-01-01"]);
        match assess_admissibility(&f, &missing) {
            CapabilityVerdict::Rejected { reason, detail } => {
                assert_eq!(reason, IncidentReasonCode::MissingRuntimeToolchainTarget);
                assert!(detail.contains("nightly-2025-01-01"));
            }
            other => panic!("expected toolchain rejection, got {other:?}"),
        }
    }

    // --- 12.3: eligibility distinguishes missing-capability / unhealthy /
    //           busy / stale ------------------------------------------------

    #[test]
    fn eligible_when_capable_fresh_healthy_idle() {
        let f = parse_capability_probe(good_output());
        let v = assess_worker_eligibility(&f, &req_wasm(), &WorkerLiveness::ready());
        assert_eq!(v, EligibilityVerdict::Eligible);
        assert!(v.is_eligible());
        assert_eq!(v.reason(), None);
    }

    #[test]
    fn no_worker_with_runtime_is_missing_capability_not_busy() {
        // A worker without cargo, even if idle+healthy, is missing-capability —
        // distinct from a busy or unhealthy worker.
        let out = "RCH_FACT os=linux\nRCH_FACT arch=x86_64\n\
                   RCH_FACT worker_version=1.0.41\nRCH_FACT worker_protocol=3\n";
        let f = parse_capability_probe(out);
        let v = assess_worker_eligibility(&f, &req_wasm(), &WorkerLiveness::ready());
        assert_eq!(
            v.reason(),
            Some(IncidentReasonCode::MissingRuntimeToolchainTarget)
        );
        assert!(matches!(v, EligibilityVerdict::MissingCapability { .. }));
    }

    #[test]
    fn os_arch_mismatch_surfaces_as_missing_capability() {
        let f = parse_capability_probe(good_output());
        let req = CapabilityRequirement::rust(3).with_os("darwin");
        let v = assess_worker_eligibility(&f, &req, &WorkerLiveness::ready());
        assert_eq!(v.reason(), Some(IncidentReasonCode::OsArchMismatch));
    }

    #[test]
    fn unhealthy_and_busy_are_distinct_from_missing_capability() {
        let f = parse_capability_probe(good_output());
        // Capable but circuit-open => Unhealthy.
        let unhealthy = WorkerLiveness {
            telemetry_stale: false,
            healthy: false,
            has_free_slot: true,
        };
        assert_eq!(
            assess_worker_eligibility(&f, &req_wasm(), &unhealthy).reason(),
            Some(IncidentReasonCode::CircuitOpen)
        );
        // Capable + healthy but no slot => Busy.
        let busy = WorkerLiveness {
            telemetry_stale: false,
            healthy: true,
            has_free_slot: false,
        };
        assert_eq!(
            assess_worker_eligibility(&f, &req_wasm(), &busy).reason(),
            Some(IncidentReasonCode::InsufficientSlots)
        );
    }

    #[test]
    fn stale_capability_cache_is_distinct_reason() {
        let f = parse_capability_probe(good_output());
        let stale = WorkerLiveness {
            telemetry_stale: true,
            healthy: true,
            has_free_slot: true,
        };
        let v = assess_worker_eligibility(&f, &req_wasm(), &stale);
        assert_eq!(v, EligibilityVerdict::StaleTelemetry);
        assert_eq!(v.reason(), Some(IncidentReasonCode::TelemetryStale));
    }

    #[test]
    fn capability_refresh_changes_eligibility() {
        // Before refresh: worker lacks the wasm target => missing capability.
        let before = parse_capability_probe(
            "RCH_FACT os=linux\nRCH_FACT arch=x86_64\n\
             RCH_FACT worker_version=1.0.41\nRCH_FACT worker_protocol=3\n\
             RCH_FACT cargo_version=cargo 1.98\nRCH_FACT target=x86_64-unknown-linux-gnu\n",
        );
        let v_before = assess_worker_eligibility(&before, &req_wasm(), &WorkerLiveness::ready());
        assert!(matches!(
            v_before,
            EligibilityVerdict::MissingCapability { .. }
        ));

        // After refresh: the wasm target was installed => now eligible.
        let after = parse_capability_probe(good_output());
        let v_after = assess_worker_eligibility(&after, &req_wasm(), &WorkerLiveness::ready());
        assert_eq!(v_after, EligibilityVerdict::Eligible);
    }
}
