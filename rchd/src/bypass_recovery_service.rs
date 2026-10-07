//! Periodic recovery loop for temporarily-bypassed workers
//! (bd-session-history-remediation-ocv9i.1.3).
//!
//! When a worker hits a transient failure it is quarantined into
//! [`crate::workers::EligibilityState::TemporaryBypass`] and a durable
//! [`BypassRecord`] is written (see [`record_worker_bypass`], the producer). It
//! then drops out of scheduling (its `status()` reads `Unreachable`). This
//! service is the consumer side: a background task that, for each bypassed
//! worker whose backoff window has elapsed, runs a recovery probe across every
//! required dimension and feeds the result into the pure decision core
//! ([`decide_probe`] / [`decide_canary`]). A worker rejoins ONLY after the
//! required number of consecutive fully-healthy probes followed by a passing
//! canary build — never on one lucky SSH response, never while admin-disabled.
//!
//! ## Why a separate service
//!
//! The decision *policy* lives in `rch_common::bypass_recovery` (pure, fully
//! unit-tested). The *execution* — SSH/capability probes, disk/load/telemetry
//! assessment, the canary build, and keeping the in-memory worker lifecycle in
//! lockstep with the persisted record — is the daemon's job and lives here. The
//! [`RecoveryProber`] trait is the seam between them, so the orchestration is
//! exercised end-to-end against scripted probe outcomes in tests.
//!
//! ## Two representations, one orchestrator
//!
//! The durable [`BypassRecord`] (backoff, counters, next-probe time, survives
//! restart) and the in-memory [`crate::workers::WorkerLifecycle`] eligibility
//! (what selection reads) are two views of the same quarantine. This service is
//! the single place that advances them together — and [`Self::reconcile_on_start`]
//! re-derives the lifecycle from the persisted records on daemon startup so a
//! restart can never silently un-bypass a worker.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tokio::sync::Mutex;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::interval;
use tracing::{debug, info, warn};

use rch_common::bypass_record::{
    BypassBackoff, BypassRecord, BypassRecordStore, BypassState, classify_disable_reason,
};
use rch_common::bypass_recovery::{
    CanaryDecision, CanaryOutcome, ProbeDecision, RecoveryProbe, decide_canary, decide_probe,
};
use rch_common::capability_probe::{
    FACT_PREFIX, NamedToolProbe, ProbeSpec, build_capability_probe_script, parse_capability_probe,
    remote_worker_binary_path,
};
use rch_common::ssh::{SshClient, SshOptions};
use rch_common::{BypassFailureClass, WorkerConfig, WorkerId};
use rch_telemetry::remediation::{self, BypassTransition, SelfHealingAction, SelfHealingOutcome};

use crate::history::BuildHistory;
use crate::telemetry::TelemetryStore;
use crate::workers::{
    AdminIntent, EligibilityState, WorkerEndpointSnapshot, WorkerPool, WorkerState,
};

/// Current epoch milliseconds (the clock the decision core reasons in).
fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

const RECOVERY_ENDPOINT: &str = "recovery_endpoint_v1";

fn recovery_endpoint(config: &WorkerConfig) -> String {
    serde_json::json!([
        config.host,
        config.user,
        config.identity_file,
        rch_common::declared_os(&config.tags),
    ])
    .to_string()
}

/// Recovery evidence belongs to an endpoint, not just a reusable worker id.
/// Legacy records cannot attest their former key/OS and need one fresh start.
/// Incident history and disk roots remain obligations of the worker record.
fn rebind_recovery(record: &mut BypassRecord, config: &WorkerConfig, now_ms: u64) -> bool {
    let endpoint = recovery_endpoint(config);
    if record.host == config.host
        && record.user == config.user
        && record.details.get(RECOVERY_ENDPOINT) == Some(&endpoint)
    {
        return false;
    }
    reset_recovery(record, config, now_ms);
    true
}

fn reset_recovery(record: &mut BypassRecord, config: &WorkerConfig, now_ms: u64) {
    record.host.clone_from(&config.host);
    record.user.clone_from(&config.user);
    record
        .details
        .insert(RECOVERY_ENDPOINT.into(), recovery_endpoint(config));
    record.state = BypassState::TemporaryBypass;
    record.consecutive_failures = 0;
    record.consecutive_passes = 0;
    record.backoff = BypassBackoff::initial();
    record.next_probe_unix_ms = now_ms;
}

/// Bytes per gigabyte, for the disk-free-GB → bytes threshold.
const BYTES_PER_GB: f64 = 1024.0 * 1024.0 * 1024.0;

/// Tunable knobs for the recovery loop and the real SSH prober.
#[derive(Debug, Clone, PartialEq)]
pub struct BypassRecoveryConfig {
    /// How often the service scans for due recovery probes.
    pub check_interval: Duration,
    /// SSH/probe timeout for a single capability probe or canary command.
    pub probe_timeout: Duration,
    /// Minimum free disk (GB) a worker must report on every probed root to pass
    /// the disk dimension.
    pub min_disk_free_gb: f64,
    /// Minimum free inodes a worker must report on every probed root.
    pub min_disk_inodes: u64,
    /// Disk roots whose capacity/inodes the probe reports (the roots real builds
    /// use). 11.1's mount-aware policy can supply precise roots; the default
    /// covers the standard transfer base.
    pub disk_roots: Vec<String>,
    /// Maximum load-per-core a worker may report to pass the load dimension.
    pub max_load_per_core: f64,
    /// Minimum worker wire protocol required. Held at 0 because the current
    /// `rch-wkr` exposes no `--protocol-version`; raise once it does so a stale
    /// binary's missing handshake fails the protocol dimension distinctly.
    pub min_protocol: u32,
    /// rustup targets a recovered worker must have installed (e.g.
    /// `wasm32-unknown-unknown`). Empty = only a working cargo/rustc is required.
    pub required_targets: Vec<String>,
    /// rustup toolchains a recovered worker must have (prefix-matched).
    pub required_toolchains: Vec<String>,
    /// Maximum telemetry age that still counts as "fresh".
    pub telemetry_max_age: Duration,
    /// The canary command run over the SSH path before full rejoin.
    pub canary_command: String,
}

impl Default for BypassRecoveryConfig {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_secs(30),
            probe_timeout: Duration::from_secs(10),
            min_disk_free_gb: 5.0,
            min_disk_inodes: 10_000,
            disk_roots: vec![
                "/tmp".to_string(),
                "/tmp/rch".to_string(),
                rch_common::types::default_remote_base(),
            ],
            max_load_per_core: 4.0,
            min_protocol: 0,
            required_targets: Vec::new(),
            required_toolchains: Vec::new(),
            telemetry_max_age: Duration::from_secs(120),
            // A lightweight toolchain exercise through the same SSH transport
            // real builds use. Configurable for heavier canaries.
            canary_command: "rustc --version".to_string(),
        }
    }
}

impl BypassRecoveryConfig {
    /// Build the recovery config from the central remediation config (bd-28xs5).
    ///
    /// The probe-dimension knobs come from `remediation.auto_rejoin` and the
    /// freshness tolerance from `remediation.telemetry_freshness`; the
    /// consecutive-pass / canary-required thresholds live in
    /// [`rch_common::bypass_record::AutoRejoinCriteria`] (also derived from
    /// `auto_rejoin`) and are applied by the recovery state machine, so they are
    /// intentionally absent here. The [`Default`] impl mirrors the central
    /// defaults; the `drift_guard_bypass_recovery_config` test fails on divergence.
    #[must_use]
    pub fn from_remediation(rem: &rch_common::remediation_config::RemediationConfig) -> Self {
        let ar = &rem.auto_rejoin;
        Self {
            check_interval: Duration::from_secs(ar.check_interval_secs),
            probe_timeout: Duration::from_secs(ar.probe_timeout_secs),
            min_disk_free_gb: ar.min_disk_free_gb,
            min_disk_inodes: ar.min_disk_inodes,
            disk_roots: ar.disk_roots.clone(),
            max_load_per_core: ar.max_load_per_core,
            min_protocol: ar.min_protocol,
            required_targets: ar.required_targets.clone(),
            required_toolchains: ar.required_toolchains.clone(),
            telemetry_max_age: Duration::from_secs(rem.telemetry_freshness.max_age_secs),
            canary_command: ar.canary_command.clone(),
        }
    }
}

/// Runs a recovery probe and a canary build for a worker. The seam between the
/// pure decision policy and real SSH execution; faked in tests.
///
/// Both methods take an owned `Arc<WorkerState>` (cheap clone) so the returned
/// future is `'static` and `Send`, and can be awaited inside the background task.
pub trait RecoveryProber: Send + Sync {
    /// Probe every required recovery dimension for `worker`.
    fn probe(
        &self,
        worker: Arc<WorkerState>,
        record: BypassRecord,
    ) -> impl std::future::Future<Output = RecoveryProbe> + Send;

    /// Run the canary build for a worker that passed its recovery probes.
    fn canary(
        &self,
        worker: Arc<WorkerState>,
    ) -> impl std::future::Future<Output = CanaryOutcome> + Send;
}

/// The real prober: a capability probe over SSH plus disk/load/telemetry checks
/// and an SSH canary command.
pub struct SshRecoveryProber {
    telemetry: Arc<TelemetryStore>,
    config: BypassRecoveryConfig,
}

impl SshRecoveryProber {
    /// Build a prober from the shared telemetry store and recovery config.
    #[must_use]
    pub fn new(telemetry: Arc<TelemetryStore>, config: BypassRecoveryConfig) -> Self {
        Self { telemetry, config }
    }

    /// Build the exact-path capability [`ProbeSpec`] for a worker. The absolute
    /// `rch-wkr` path comes from the shared [`remote_worker_binary_path`] (the
    /// probe script shell-quotes it, so a literal `~` would never expand — the
    /// single source of truth shared with `rch self-test --smoke`). A wrong path
    /// simply omits the worker-binary fact, keeping the worker bypassed (the safe
    /// failure mode — never a false rejoin).
    fn probe_spec(&self, config: &WorkerConfig) -> ProbeSpec {
        let declared_os = rch_common::declared_os(&config.tags);
        let mut spec = ProbeSpec::new(
            config.user.clone(),
            remote_worker_binary_path(&config.user, declared_os.as_deref()),
        );
        spec.disk_roots.clone_from(&self.config.disk_roots);
        // Operator-declared tool probes are part of the worker's capability
        // facts, so a rejoining worker is measured on the same evidence
        // selection uses. Invalid entries were refused at config load.
        spec.tools = config
            .tools
            .iter()
            .filter_map(|tool| NamedToolProbe::try_from(tool).ok())
            .collect();
        spec
    }

    fn ssh_options(&self) -> SshOptions {
        SshOptions {
            command_timeout: self.config.probe_timeout,
            connect_timeout: self.config.probe_timeout,
            ..Default::default()
        }
    }

    /// Run a command on the worker over SSH, returning its stdout, or `None` if
    /// the worker is unreachable (connect/exec failed).
    async fn ssh_run(&self, config: &WorkerConfig, command: &str) -> Option<String> {
        let mut client = SshClient::new(config.clone(), self.ssh_options());
        if client.connect().await.is_err() {
            return None;
        }
        client.execute(command).await.ok().map(|r| r.stdout)
    }

    /// Whether the worker's most recent telemetry sample is within tolerance.
    /// No sample at all is treated as stale — a worker with no fresh telemetry
    /// must not rejoin (the bead's "stale telemetry must not rejoin" property).
    fn telemetry_fresh(&self, endpoint: &WorkerEndpointSnapshot) -> bool {
        match self.telemetry.latest_for_endpoint(endpoint) {
            Some(sample) => Utc::now()
                .signed_duration_since(sample.received_at)
                .to_std()
                .is_ok_and(|age| age <= self.config.telemetry_max_age),
            None => false,
        }
    }

    /// Derive load-per-core from the appended `loadavg1`/`nproc` probe facts.
    fn parse_load_per_core(stdout: &str) -> Option<f64> {
        let (mut load1, mut nproc): (Option<f64>, Option<f64>) = (None, None);
        for line in stdout.lines() {
            let Some(kv) = line.trim().strip_prefix(FACT_PREFIX) else {
                continue;
            };
            if let Some(v) = kv.strip_prefix("loadavg1=") {
                load1 = v.trim().parse().ok();
            } else if let Some(v) = kv.strip_prefix("nproc=") {
                nproc = v.trim().parse().ok();
            }
        }
        match (load1, nproc) {
            (Some(l), Some(n)) if n > 0.0 => Some(l / n),
            _ => None,
        }
    }
}

/// Map exact-path capability [`ProbedFacts`] (+ fresh load + telemetry verdict)
/// onto the 7-dimension [`RecoveryProbe`]. Pure, so the dimension fidelity is
/// unit-tested without real SSH.
///
/// `worker_binary_ok` requires the exact-path `rch-wkr` to have reported a
/// version; `toolchain_ok` requires cargo plus every configured target/toolchain;
/// `disk_ok` requires every probed root to clear both the byte and inode floor.
/// A reachable worker with a dimension we could not measure (no probed disk
/// roots, no load fact) is not trapped on that dimension. A fully empty parse is
/// unreachable — every dimension fails.
fn assess_probe_facts(
    facts: &rch_common::capability_probe::ProbedFacts,
    load_per_core: Option<f64>,
    telemetry_ok: bool,
    config: &BypassRecoveryConfig,
) -> RecoveryProbe {
    // The script always emits os/arch/user (uname/id); their total absence means
    // the shell never ran -> unreachable.
    let reachable = facts.os.is_some() || facts.arch.is_some() || facts.probed_user.is_some();
    if !reachable {
        return RecoveryProbe {
            ssh_ok: false,
            worker_binary_ok: false,
            protocol_ok: false,
            toolchain_ok: false,
            disk_ok: false,
            load_ok: false,
            telemetry_ok: false,
        };
    }

    let worker_binary_ok = facts.worker.is_some();
    let protocol_ok = facts
        .worker
        .as_ref()
        .is_some_and(|w| w.protocol_version >= config.min_protocol);
    let toolchain_ok = facts.rust.rustc_version.is_some()
        && config
            .required_targets
            .iter()
            .all(|t| facts.rust.targets.iter().any(|have| have == t))
        && config.required_toolchains.iter().all(|t| {
            facts
                .rust
                .toolchains
                .iter()
                .any(|have| have.starts_with(t.as_str()))
        });
    let min_bytes = (config.min_disk_free_gb * BYTES_PER_GB) as u64;
    // Git Bash reports `-` for NTFS inode availability; the capability parser
    // represents that unavailable count as zero. Windows has no fixed Unix
    // inode pool, so require free bytes there and retain both floors elsewhere.
    let requires_inodes = facts.os.as_deref() != Some("windows");
    let disk_ok = if facts.disk_roots.is_empty() {
        true
    } else {
        facts.disk_roots.iter().all(|r| {
            r.available_bytes >= min_bytes
                && (!requires_inodes || r.available_inodes >= config.min_disk_inodes)
        })
    };
    let load_ok = load_per_core.is_none_or(|lpc| lpc <= config.max_load_per_core);

    RecoveryProbe {
        ssh_ok: true,
        worker_binary_ok,
        protocol_ok,
        toolchain_ok,
        disk_ok,
        load_ok,
        telemetry_ok,
    }
}

/// A disk-failure quarantine needs affirmative measurements of every
/// configured root. Partial stdout, an empty probe or a failed `df` cannot
/// establish that the filesystem which stopped the build has recovered.
fn has_complete_disk_evidence(
    facts: &rch_common::capability_probe::ProbedFacts,
    config: &BypassRecoveryConfig,
) -> bool {
    !config.disk_roots.is_empty()
        && config.disk_roots.iter().all(|root| {
            if root.is_empty() {
                return false;
            }
            let mut matches = facts.disk_roots.iter().filter(|fact| &fact.path == root);
            matches.next().is_some_and(|fact| {
                fact.total_bytes > 0 && fact.available_bytes <= fact.total_bytes
            }) && matches.next().is_none()
        })
}

/// The durable record, including roots reported by the failed job, owns the
/// recovery requirements. Canary lifecycle transitions may clear their live
/// cause, and a daemon restart must not weaken this evidence.
fn recovery_disk_config(
    config: &BypassRecoveryConfig,
    record: &BypassRecord,
) -> BypassRecoveryConfig {
    let mut config = config.clone();
    config.disk_roots.extend(record.disk_roots.iter().cloned());
    config.disk_roots.sort();
    config.disk_roots.dedup();
    config
}

fn assess_recovery_probe_facts(
    facts: &rch_common::capability_probe::ProbedFacts,
    load_per_core: Option<f64>,
    telemetry_ok: bool,
    config: &BypassRecoveryConfig,
    record: &BypassRecord,
) -> RecoveryProbe {
    let config = recovery_disk_config(config, record);
    let mut probe = assess_probe_facts(facts, load_per_core, telemetry_ok, &config);
    if record.failure_class == BypassFailureClass::DiskInodePressure {
        probe.disk_ok &= has_complete_disk_evidence(facts, &config);
    }
    probe
}

/// Whether the telemetry dimension admits this worker during bypass recovery.
///
/// Windows workers run under Git Bash and cannot produce the Linux `/proc`-based
/// telemetry stream. Their declared OS is already a hard placement fence, while
/// the capability probe still checks SSH, the exact worker binary, protocol,
/// toolchain, disk, and load. Treating the expected Windows telemetry gap as a
/// hard recovery failure would make any temporary bypass permanent. Every other
/// host remains freshness-gated.
fn recovery_telemetry_ok(config: &WorkerConfig, observed_fresh: bool) -> bool {
    observed_fresh
        || rch_common::declared_os(&config.tags)
            .is_some_and(|os| os.eq_ignore_ascii_case("windows"))
}

impl RecoveryProber for SshRecoveryProber {
    async fn probe(&self, worker: Arc<WorkerState>, record: BypassRecord) -> RecoveryProbe {
        let endpoint = worker.endpoint_snapshot().await;
        let config = &endpoint.config;
        let mut spec = self.probe_spec(config);
        spec.disk_roots = recovery_disk_config(&self.config, &record).disk_roots;
        // The 12.2 exact-path capability script (rch-wkr --version at the exact
        // path, rustup toolchains/targets, df -Pk/-Pi disk+inode roots), plus a
        // fresh load probe the capability script doesn't cover.
        let mut script = build_capability_probe_script(&spec);
        script.push_str(
            " la=$(awk 'NR==1{print $1}' /proc/loadavg 2>/dev/null) && printf '%sloadavg1=%s\\n' \"$P\" \"$la\"; \
             nc=$(nproc 2>/dev/null) && printf '%snproc=%s\\n' \"$P\" \"$nc\"; ",
        );

        let Some(stdout) = self.ssh_run(config, &script).await else {
            // SSH/shell never ran -> unreachable; every dimension fails.
            return RecoveryProbe {
                ssh_ok: false,
                worker_binary_ok: false,
                protocol_ok: false,
                toolchain_ok: false,
                disk_ok: false,
                load_ok: false,
                telemetry_ok: false,
            };
        };

        let facts = parse_capability_probe(&stdout);
        let load_per_core = Self::parse_load_per_core(&stdout);
        let telemetry_ok = recovery_telemetry_ok(config, self.telemetry_fresh(&endpoint));
        assess_recovery_probe_facts(&facts, load_per_core, telemetry_ok, &self.config, &record)
    }

    async fn canary(&self, worker: Arc<WorkerState>) -> CanaryOutcome {
        let config = worker.config.read().await.clone();
        let mut client = SshClient::new(config, self.ssh_options());
        if client.connect().await.is_err() {
            return CanaryOutcome::Failed;
        }
        match client.execute(&self.config.canary_command).await {
            Ok(result) if result.exit_code == 0 => CanaryOutcome::Passed,
            _ => CanaryOutcome::Failed,
        }
    }
}

/// Exercise the real producer with an explicit failure in recovery tests.
/// Live detection already holds the store and endpoint guards while reading
/// the failure evidence and calls `record_worker_bypass_locked` directly.
#[cfg(test)]
async fn record_worker_bypass(
    store: &Arc<Mutex<BypassRecordStore>>,
    worker: &Arc<WorkerState>,
    class: BypassFailureClass,
    diagnostic: impl Into<String>,
    now_ms: u64,
) {
    // Store -> endpoint -> lifecycle is also the recovery publication order.
    let mut store = store.lock().await;
    let config = worker.config.read().await;
    record_worker_bypass_locked(
        &mut store,
        worker,
        &config,
        class,
        diagnostic.into(),
        now_ms,
    )
    .await;
}

/// Caller retains the bypass store and current endpoint guards throughout the
/// eligibility transition and its durable publication.
async fn record_worker_bypass_locked(
    store: &mut BypassRecordStore,
    worker: &WorkerState,
    config: &WorkerConfig,
    class: BypassFailureClass,
    diagnostic: String,
    now_ms: u64,
) {
    let (id, host, user) = (
        config.id.to_string(),
        config.host.clone(),
        config.user.clone(),
    );
    // Serialize the live transition and its record with recovery's final
    // comparison. A failure arriving while an SSH probe/canary is in flight
    // must invalidate that old recovery result before it can reopen admission.
    if worker.lifecycle().await.admin == AdminIntent::Disabled {
        return;
    }
    let class = if store
        .get(&id)
        .is_some_and(|record| record.failure_class == BypassFailureClass::DiskInodePressure)
    {
        BypassFailureClass::DiskInodePressure
    } else {
        class
    };
    worker.enter_bypass(class).await;
    // Remediation observability (bead 14.5): a worker just entered temporary
    // bypass — record the lifecycle transition and the ineligibility reason.
    remediation::record_bypass_transition(BypassTransition::Bypassed);
    remediation::record_worker_ineligible(class);

    let mut record = if let Some(existing) = store.get(&id) {
        let mut rec = existing.clone();
        rec.failure_class = class;
        rec.reason_code = class.incident_reason_code();
        if rebind_recovery(&mut rec, config, now_ms) {
            rec.last_failure_unix_ms = now_ms;
            rec.consecutive_failures = 1;
            rec = rec.with_diagnostic(diagnostic);
        } else {
            rec.record_failure(now_ms, diagnostic);
        }
        rec
    } else {
        BypassRecord::new(id, host, user, class, now_ms).with_diagnostic(diagnostic)
    };
    record
        .details
        .insert(RECOVERY_ENDPOINT.into(), recovery_endpoint(config));
    if let Err(e) = store.upsert(record) {
        warn!(error = %e, "failed to persist bypass record");
    }
}

/// Validate remote paths without interpreting them on the dispatcher's
/// filesystem. These are quoted probe inputs, never command fragments.
pub fn validate_disk_fault_roots(roots: &[String]) -> anyhow::Result<Vec<String>> {
    anyhow::ensure!(roots.len() <= 256, "too many disk-fault roots");
    let mut normalized = Vec::with_capacity(roots.len());
    for root in roots {
        anyhow::ensure!(
            !root.is_empty() && root.len() <= 4096 && !root.chars().any(char::is_control),
            "invalid disk-fault root length or control character"
        );
        let bytes = root.as_bytes();
        let relative = if let Some(relative) = root.strip_prefix('/') {
            relative
        } else if bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && &bytes[1..3] == b":/" {
            &root[3..]
        } else {
            anyhow::bail!("disk-fault roots must be absolute remote paths");
        };
        anyhow::ensure!(
            relative.is_empty()
                || relative
                    .split('/')
                    .all(|part| !matches!(part, "" | "." | "..")),
            "disk-fault roots must be canonical remote paths"
        );
        normalized.push(root.clone());
    }
    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}

/// Publish an exact-owner disk incident before acknowledging its durable
/// completion intent. Recovery shares this lock and additionally checks the
/// history's pending intents, so a failed acknowledgment cannot lose dedupe
/// evidence by letting the worker rejoin first.
#[allow(clippy::too_many_arguments)]
pub async fn record_worker_disk_bypass(
    store: &Arc<Mutex<BypassRecordStore>>,
    worker: Option<&Arc<WorkerState>>,
    worker_id: &str,
    incident_id: &str,
    roots: &[String],
    diagnostic: &str,
    now_ms: u64,
    acknowledge: impl FnOnce() -> std::io::Result<()>,
) -> anyhow::Result<()> {
    let roots = validate_disk_fault_roots(roots)?;
    anyhow::ensure!(
        !incident_id.is_empty()
            && incident_id.len() <= 256
            && !incident_id.chars().any(char::is_control),
        "invalid disk-fault incident identity"
    );
    let mut store = store.lock().await;
    let config = if let Some(worker) = worker {
        Some(worker.config.read().await)
    } else {
        None
    };
    let (host, user) = if let Some(config) = &config {
        anyhow::ensure!(
            config.id.as_str() == worker_id,
            "disk-fault worker identity mismatch"
        );
        (config.host.clone(), config.user.clone())
    } else {
        (String::new(), String::new())
    };
    if let Some(worker) = worker
        && worker.lifecycle().await.admin == AdminIntent::Disabled
    {
        // The durable operator disable already excludes this worker. A later
        // explicit enable is the operator's choice; never change that axis.
        acknowledge()?;
        return Ok(());
    }
    if let Some(worker) = worker {
        worker
            .enter_bypass(BypassFailureClass::DiskInodePressure)
            .await;
    }
    const INCIDENTS: &str = "disk_fault_incidents";
    let previous = store.get(worker_id);
    let mut incidents: Vec<String> = previous
        .and_then(|record| record.details.get(INCIDENTS))
        .map(|json| serde_json::from_str(json))
        .transpose()?
        .unwrap_or_default();
    let already_recorded = incidents.iter().any(|id| id == incident_id);
    anyhow::ensure!(
        already_recorded || incidents.len() < 4096,
        "too many unretired disk incidents"
    );
    let mut record = if let Some(previous) = previous {
        let mut record = previous.clone();
        let retargeted = config
            .as_ref()
            .is_some_and(|config| rebind_recovery(&mut record, config, now_ms));
        record.failure_class = BypassFailureClass::DiskInodePressure;
        record.reason_code = record.failure_class.incident_reason_code();
        if !already_recorded {
            if retargeted {
                record.last_failure_unix_ms = now_ms;
                record.consecutive_failures = 1;
                record = record.with_diagnostic(diagnostic);
            } else {
                record.record_failure(now_ms, diagnostic);
            }
        }
        record
    } else {
        BypassRecord::new(
            worker_id,
            host,
            user,
            BypassFailureClass::DiskInodePressure,
            now_ms,
        )
        .with_diagnostic(diagnostic)
    };
    if let Some(config) = &config {
        record
            .details
            .insert(RECOVERY_ENDPOINT.into(), recovery_endpoint(config));
    }
    record.disk_roots.extend(roots);
    record.disk_roots.sort();
    record.disk_roots.dedup();
    record.disk_roots = validate_disk_fault_roots(&record.disk_roots)?;
    if !already_recorded {
        incidents.push(incident_id.to_string());
    }
    record
        .details
        .insert(INCIDENTS.to_string(), serde_json::to_string(&incidents)?);
    // Always retry persistence, even for an incident already in the in-memory
    // map: a previous upsert may have updated that map but failed its fsync.
    store.upsert(record)?;
    acknowledge()?;
    if !already_recorded {
        remediation::record_bypass_transition(BypassTransition::Bypassed);
        remediation::record_worker_ineligible(BypassFailureClass::DiskInodePressure);
    }
    Ok(())
}

/// Background service that probes bypassed workers and rejoins the ones that
/// recover, keeping the durable record and live lifecycle in lockstep.
pub struct BypassRecoveryService<P: RecoveryProber> {
    pool: WorkerPool,
    store: Arc<Mutex<BypassRecordStore>>,
    prober: Arc<P>,
    config: BypassRecoveryConfig,
    history: Option<Arc<BuildHistory>>,
}

impl<P: RecoveryProber> Clone for BypassRecoveryService<P> {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            store: Arc::clone(&self.store),
            prober: Arc::clone(&self.prober),
            config: self.config.clone(),
            history: self.history.clone(),
        }
    }
}

impl<P: RecoveryProber + 'static> BypassRecoveryService<P> {
    /// Build the service from the worker pool, shared record store, prober, and
    /// config.
    pub fn new(
        pool: WorkerPool,
        store: Arc<Mutex<BypassRecordStore>>,
        prober: P,
        config: BypassRecoveryConfig,
    ) -> Self {
        Self {
            pool,
            store,
            prober: Arc::new(prober),
            config,
            history: None,
        }
    }

    /// Pending durable disk-fault intents must finish publication before
    /// recovery may discard the matching bypass and its dedupe evidence.
    #[must_use]
    pub fn with_history(mut self, history: Arc<BuildHistory>) -> Self {
        self.history = Some(history);
        self
    }

    /// Spawn the periodic loop. Reconciles persisted records into live worker
    /// lifecycle once, then on every tick quarantines newly-unreachable workers
    /// and probes due records.
    pub fn start(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut endpoint_changes = self.pool.subscribe_endpoint_changes();
            self.reconcile_on_start().await;
            let mut ticker = interval(self.config.check_interval);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {}
                    changed = endpoint_changes.changed() => {
                        if changed.is_err() {
                            return;
                        }
                    }
                }
                let now = now_unix_ms();
                self.detect_new_bypasses(now).await;
                self.evaluate_once(now).await;
            }
        })
    }

    /// Bind persisted retry state to the currently configured endpoint before
    /// consulting its due time. Never carry a former endpoint's backoff or
    /// partially passed recovery sequence into the replacement.
    async fn current_record(
        &self,
        worker: &Arc<WorkerState>,
        now_ms: u64,
        rejected_trial: Option<&BypassRecord>,
    ) -> Option<(WorkerEndpointSnapshot, BypassRecord)> {
        let snapshot = worker.endpoint_snapshot().await;
        let mut store = self.store.lock().await;
        let endpoint = worker.lock_current_endpoint(&snapshot).await?;
        let mut record = store.get(snapshot.config.id.as_str())?.clone();
        let rejected_current = rejected_trial == Some(&record);
        let retargeted = rebind_recovery(&mut record, &endpoint, now_ms);
        if rejected_current {
            // A -> B -> A has the same stable identity but a new generation.
            // Discard this old trial without erasing a newer incident record.
            reset_recovery(&mut record, &endpoint, now_ms);
        }
        if retargeted || rejected_current {
            // enter_bypass changes only eligibility, preserving admin disable.
            worker.enter_bypass(record.failure_class).await;
            if let Err(error) = store.upsert(record.clone()) {
                warn!(%error, "failed to persist retargeted bypass record");
                return None;
            }
        }
        drop(endpoint);
        Some((snapshot, record))
    }

    /// A watch notification cancels only network work, never the local durable
    /// publication sequence. Unchanged endpoints may retry an interrupted
    /// canary immediately; a retarget discards the old trial entirely.
    async fn interrupted_trial(
        &self,
        worker: &Arc<WorkerState>,
        snapshot: &WorkerEndpointSnapshot,
        record: &BypassRecord,
        now_ms: u64,
    ) {
        let mut store = self.store.lock().await;
        let Some(_endpoint) = worker.lock_current_endpoint(snapshot).await else {
            drop(store);
            let _ = self.current_record(worker, now_ms, Some(record)).await;
            return;
        };
        if record.state == BypassState::RecoveredPendingCanary
            && store.get(&record.worker_id) == Some(record)
        {
            let mut retry = record.clone();
            retry.next_probe_unix_ms = now_ms;
            if let Err(error) = store.upsert(retry) {
                warn!(%error, "failed to reschedule interrupted recovery canary");
            }
        }
    }

    /// Producer pass: quarantine workers the health monitor has marked plainly
    /// `Unreachable` (a sustained failure — the health circuit opened) that the
    /// operator still wants in service and that are not already recorded. This
    /// is what turns a transient failure into a [`BypassRecord`] so the consumer
    /// pass can probe it back to health. The failure class is inferred from the
    /// worker's last error via [`classify_disable_reason`], defaulting to SSH.
    ///
    /// Workers already in `TemporaryBypass` / `RecoveredPendingCanary` read as
    /// `Unreachable` at the legacy-status boundary but have a *quarantine*
    /// eligibility (not plain `Unreachable`), so they are not re-detected here.
    pub async fn detect_new_bypasses(&self, now_ms: u64) {
        for worker in self.pool.all_workers().await {
            // The detection and publication must inspect the same endpoint.
            // In particular, a reload resets its circuit and marks it awaiting
            // a first health probe; that is not evidence of a new incident.
            let mut store = self.store.lock().await;
            let config = worker.config.read().await;
            let lifecycle = worker.lifecycle().await;
            if lifecycle.admin != AdminIntent::Active
                || lifecycle.eligibility != EligibilityState::Unreachable
            {
                continue;
            }
            let id = config.id.to_string();
            if store.contains(&id) {
                continue;
            }
            let circuit = worker.circuit_stats().await;
            if circuit.state() == rch_common::CircuitState::Closed
                && circuit.consecutive_failures() == 0
                && circuit.consecutive_command_failures() == 0
            {
                continue;
            }
            let last_error = worker.last_error().await;
            let class = last_error
                .as_deref()
                .and_then(classify_disable_reason)
                .unwrap_or(BypassFailureClass::Ssh);
            let diagnostic = last_error.unwrap_or_else(|| "worker unreachable".to_string());
            info!(worker = %id, ?class, "quarantining unreachable worker into temporary bypass");
            record_worker_bypass_locked(&mut store, &worker, &config, class, diagnostic, now_ms)
                .await;
        }
    }

    /// Re-derive live worker eligibility from the persisted records so a daemon
    /// restart cannot silently un-bypass a worker. Operator-disabled workers are
    /// left to the admin axis.
    pub async fn reconcile_on_start(&self) {
        let records: Vec<BypassRecord> =
            self.store.lock().await.all().into_iter().cloned().collect();
        let mut restored = 0_usize;
        for record in records {
            let Some(worker) = self.pool.get(&WorkerId::new(&record.worker_id)).await else {
                continue;
            };
            let Some((snapshot, record)) = self.current_record(&worker, now_unix_ms(), None).await
            else {
                continue;
            };
            let store = self.store.lock().await;
            let Some(_endpoint) = worker.lock_current_endpoint(&snapshot).await else {
                continue;
            };
            if store.get(&record.worker_id) != Some(&record) {
                continue;
            }
            if worker.lifecycle().await.admin == AdminIntent::Disabled {
                continue;
            }
            match record.state {
                BypassState::TemporaryBypass => worker.enter_bypass(record.failure_class).await,
                BypassState::RecoveredPendingCanary => {
                    worker.enter_bypass(record.failure_class).await;
                    let _ = worker.recover_to_canary().await;
                }
            }
            restored += 1;
        }
        if restored > 0 {
            info!(
                restored,
                "reconciled bypassed workers from persisted records"
            );
        }
    }

    /// Run one scan: probe every bypassed worker whose backoff window elapsed.
    pub async fn evaluate_once(&self, now_ms: u64) {
        let records: Vec<BypassRecord> = {
            let store = self.store.lock().await;
            store.all().into_iter().cloned().collect()
        };
        let mut evaluations = JoinSet::new();
        for record in records {
            let service = self.clone();
            evaluations.spawn(async move {
                service.evaluate_record(record, now_ms).await;
            });
        }
        while let Some(result) = evaluations.join_next().await {
            if let Err(error) = result {
                warn!(%error, "worker recovery task failed");
            }
        }
    }

    async fn evaluate_record(&self, record: BypassRecord, now_ms: u64) {
        let mut endpoint_changes = self.pool.subscribe_endpoint_changes();
        let worker_id = record.worker_id.clone();
        let Some(worker) = self.pool.get(&WorkerId::new(&worker_id)).await else {
            // A fresh or partial daemon pool cannot prove that an absent worker
            // recovered. Retain its durable quarantine for a later reconciliation
            // instead of silently clearing backoff and canary requirements.
            warn!(
                worker = %worker_id,
                event = "reduced_capacity",
                reason = "quarantine_record_missing_live_worker",
                "retaining durable bypass record until its worker is observable"
            );
            remediation::record_bypass_transition(BypassTransition::StayBypassed);
            return;
        };
        let Some((snapshot, record)) = self.current_record(&worker, now_ms, None).await else {
            return;
        };
        if !record.probe_due(now_ms)
            || self
                .history
                .as_ref()
                .is_some_and(|history| history.has_pending_disk_fault(&worker_id))
        {
            return;
        }
        // An operator-disabled worker is NEVER probed for auto-rejoin: that is an
        // admin-axis decision and the recovery loop must not override it.
        if worker.lifecycle().await.admin == AdminIntent::Disabled {
            debug!(worker = %worker_id, "skipping recovery probe: admin-disabled");
            return;
        }

        let probe = tokio::select! {
            probe = self.prober.probe(worker.clone(), record.clone()) => probe,
            _ = endpoint_changes.changed() => {
                self.interrupted_trial(&worker, &snapshot, &record, now_ms).await;
                return;
            }
        };
        let mut store = self.store.lock().await;
        let Some(endpoint) = worker.lock_current_endpoint(&snapshot).await else {
            drop(store);
            let _ = self.current_record(&worker, now_ms, Some(&record)).await;
            debug!(worker = %worker_id, "discarding recovery probe from a replaced endpoint");
            return;
        };
        if store.get(&worker_id) != Some(&record)
            || worker.lifecycle().await.admin == AdminIntent::Disabled
        {
            debug!(worker = %worker_id, "discarding recovery probe superseded by a new failure or operator action");
            return;
        }
        match decide_probe(record, &probe, now_ms) {
            ProbeDecision::StayBypassed {
                failed_dimension,
                record,
            } => {
                debug!(worker = %worker_id, dimension = %failed_dimension, "recovery probe failed; staying bypassed");
                remediation::record_bypass_transition(BypassTransition::StayBypassed);
                worker.enter_bypass(record.failure_class).await;
                if let Err(error) = store.upsert(*record) {
                    warn!(%error, "failed to persist bypass record");
                }
            }
            ProbeDecision::KeepProbing {
                consecutive_passes,
                required,
                record,
            } => {
                debug!(worker = %worker_id, consecutive_passes, required, "recovery probe passed; keep probing");
                remediation::record_bypass_transition(BypassTransition::KeepProbing);
                if let Err(error) = store.upsert(*record) {
                    warn!(%error, "failed to persist bypass record");
                }
            }
            ProbeDecision::ReadyForCanary { record } => {
                info!(worker = %worker_id, "recovery probes passed; running canary");
                remediation::record_bypass_transition(BypassTransition::ReadyForCanary);
                if worker.recover_to_canary().await.is_err() {
                    // Lifecycle wasn't TemporaryBypass (e.g. it was reconciled or
                    // raced); re-quarantine then advance so record and lifecycle
                    // stay in lockstep.
                    worker.enter_bypass(record.failure_class).await;
                    let _ = worker.recover_to_canary().await;
                }
                if let Err(error) = store.upsert((*record).clone()) {
                    warn!(%error, "failed to persist canary-pending bypass record");
                    worker.enter_bypass(record.failure_class).await;
                    return;
                }
                drop(endpoint);
                drop(store);
                let outcome = tokio::select! {
                    outcome = self.prober.canary(worker.clone()) => outcome,
                    _ = endpoint_changes.changed() => {
                        self.interrupted_trial(&worker, &snapshot, record.as_ref(), now_ms).await;
                        return;
                    }
                };
                let mut store = self.store.lock().await;
                let Some(_endpoint) = worker.lock_current_endpoint(&snapshot).await else {
                    drop(store);
                    let _ = self
                        .current_record(&worker, now_ms, Some(record.as_ref()))
                        .await;
                    debug!(worker = %worker_id, "discarding canary from a replaced endpoint");
                    return;
                };
                if store.get(&worker_id) != Some(record.as_ref())
                    || worker.lifecycle().await.admin == AdminIntent::Disabled
                {
                    debug!(worker = %worker_id, "discarding canary superseded by a new failure or operator action");
                    return;
                }
                // Remediation observability (bead 14.5): record the canary result.
                remediation::record_canary(outcome);
                let expected = (*record).clone();
                match decide_canary(*record, outcome, now_ms) {
                    CanaryDecision::Rejoin => {
                        if self.rejoin(&worker, &mut store, &expected).await {
                            info!(worker = %worker_id, "canary passed; rejoined worker");
                        }
                    }
                    CanaryDecision::Relapse { record } => {
                        warn!(worker = %worker_id, "canary failed; relapsing into bypass");
                        remediation::record_bypass_transition(BypassTransition::Relapse);
                        worker.enter_bypass(record.failure_class).await;
                        if let Err(error) = store.upsert(*record) {
                            warn!(%error, "failed to persist bypass record");
                        }
                    }
                }
            }
            ProbeDecision::Rejoin => {
                let expected = store
                    .get(&worker_id)
                    .cloned()
                    .expect("record compared above");
                if self.rejoin(&worker, &mut store, &expected).await {
                    info!(worker = %worker_id, "recovery criteria met (no canary required); rejoined worker");
                }
            }
        }
    }

    /// Drive the worker back to fully healthy, reconcile the selection-side
    /// circuit breaker, and drop the record. For the no-canary path the worker
    /// is still `TemporaryBypass`, so step it through the legal transitions; for
    /// the canary path it is already `RecoveredPendingCanary`.
    /// Callers hold both the store lock and the matching endpoint read guard
    /// through retirement and the live transition.
    async fn rejoin(
        &self,
        worker: &Arc<WorkerState>,
        store: &mut BypassRecordStore,
        expected: &BypassRecord,
    ) -> bool {
        if self
            .history
            .as_ref()
            .is_some_and(|history| history.has_pending_disk_fault(&expected.worker_id))
        {
            return false;
        }
        // Keep admission closed if durable retirement fails. `remove` updates
        // the in-memory map before writing, so restore that map on an error.
        if let Err(error) = store.remove(&expected.worker_id) {
            let _ = store.upsert(expected.clone());
            warn!(%error, "failed to retire bypass record; worker remains quarantined");
            return false;
        }
        if worker.is_canary_pending().await {
            let _ = worker.promote_from_canary().await;
        } else {
            let _ = worker.recover_to_canary().await;
            let _ = worker.promote_from_canary().await;
        }
        // The bypass opened the selection-side circuit (WorkerState.circuit) for
        // this worker; close it so the rejoined worker is actually schedulable.
        worker.close_circuit().await;
        remediation::record_bypass_transition(BypassTransition::Rejoin);
        remediation::record_self_healing(
            SelfHealingAction::WorkerRejoin,
            SelfHealingOutcome::Success,
        );
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::bypass_record::AutoRejoinCriteria;
    use rch_common::capability_probe::ProbedFacts;
    use std::collections::VecDeque;

    const GB: u64 = 1024 * 1024 * 1024;

    /// Drift guard (bd-28xs5): the recovery config built from the central
    /// `RemediationConfig` defaults (auto_rejoin + telemetry_freshness) must
    /// reproduce this module's own `BypassRecoveryConfig::default()`. Fails if
    /// the central defaults ever diverge from the rchd recovery defaults.
    #[test]
    fn drift_guard_bypass_recovery_config() {
        let from_cfg = BypassRecoveryConfig::from_remediation(
            &rch_common::remediation_config::RemediationConfig::default(),
        );
        assert_eq!(from_cfg, BypassRecoveryConfig::default());
    }

    /// A fully-healthy fact set, built through the real `parse_capability_probe`
    /// so the test also pins the probe-output contract. Disk is reported in KiB
    /// (`df -Pk`): 50 GiB free, 1M inodes on `/tmp`.
    fn facts_all_good() -> ProbedFacts {
        let out = [
            "RCH_FACT os=linux",
            "RCH_FACT arch=x86_64",
            "RCH_FACT user=ubuntu",
            "RCH_FACT rch_wkr_path=/home/ubuntu/.local/bin/rch-wkr",
            "RCH_FACT worker_version=rch-wkr 1.0.41",
            "RCH_FACT worker_protocol=1",
            "RCH_FACT cargo_version=cargo 1.90",
            "RCH_FACT toolchain=nightly-2026-05-22-x86_64-unknown-linux-gnu",
            "RCH_FACT target=x86_64-unknown-linux-gnu",
            "RCH_FACT target=wasm32-unknown-unknown",
            "RCH_FACT disk=/tmp;104857600;52428800;1000000",
        ]
        .join("\n");
        let facts = parse_capability_probe(&out);
        assert_eq!(facts.disk_roots[0].available_bytes, 50 * GB);
        facts
    }

    /// A scripted prober: returns queued probe outcomes (falling back to a
    /// default) and a fixed canary outcome.
    struct FakeProber {
        probes: Mutex<VecDeque<RecoveryProbe>>,
        default_probe: RecoveryProbe,
        canary: CanaryOutcome,
    }

    impl FakeProber {
        fn new(
            probes: Vec<RecoveryProbe>,
            default_probe: RecoveryProbe,
            canary: CanaryOutcome,
        ) -> Self {
            Self {
                probes: Mutex::new(probes.into_iter().collect()),
                default_probe,
                canary,
            }
        }
    }

    impl RecoveryProber for FakeProber {
        async fn probe(&self, _worker: Arc<WorkerState>, _record: BypassRecord) -> RecoveryProbe {
            self.probes
                .lock()
                .await
                .pop_front()
                .unwrap_or(self.default_probe)
        }

        async fn canary(&self, _worker: Arc<WorkerState>) -> CanaryOutcome {
            self.canary
        }
    }

    fn worker_config(id: &str) -> WorkerConfig {
        WorkerConfig {
            id: WorkerId::new(id),
            host: "h".to_string(),
            user: "u".to_string(),
            identity_file: "/dev/null".to_string(),
            total_slots: 4,
            priority: 100,
            tags: vec![],
            tools: Vec::new(),
        }
    }

    fn store() -> Arc<Mutex<BypassRecordStore>> {
        // A unique parent DIRECTORY per call. The store's atomic persistence
        // writes a temp file keyed only on pid in the store's parent dir, so
        // parallel tests must not share a parent dir or those temp files collide.
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("rch_bypass_test_{}_{n}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        Arc::new(Mutex::new(BypassRecordStore::with_path(
            dir.join("bypass_records.json"),
        )))
    }

    fn probe_failing(dim: &str) -> RecoveryProbe {
        let mut p = RecoveryProbe::all_ok();
        match dim {
            "ssh" => p.ssh_ok = false,
            "worker_binary" => p.worker_binary_ok = false,
            "toolchain" => p.toolchain_ok = false,
            "disk" => p.disk_ok = false,
            "load" => p.load_ok = false,
            "telemetry" => p.telemetry_ok = false,
            _ => unreachable!(),
        }
        p
    }

    async fn pool_with(ids: &[&str]) -> WorkerPool {
        let pool = WorkerPool::new();
        for id in ids {
            pool.add_worker(worker_config(id)).await;
        }
        pool
    }

    const T0: u64 = 1_700_000_000_000;

    #[tokio::test]
    async fn two_healthy_probes_then_passing_canary_rejoins() {
        let pool = pool_with(&["css"]).await;
        let store = store();
        let worker = pool.get(&WorkerId::new("css")).await.unwrap();

        record_worker_bypass(
            &store,
            &worker,
            BypassFailureClass::Ssh,
            "went unreachable",
            T0,
        )
        .await;
        assert!(store.lock().await.contains("css"));
        assert!(!worker.lifecycle().await.is_schedulable());

        let svc = BypassRecoveryService::new(
            pool.clone(),
            store.clone(),
            // Default criteria need 2 consecutive passes + canary; feed 2 all_ok.
            FakeProber::new(
                vec![RecoveryProbe::all_ok(), RecoveryProbe::all_ok()],
                RecoveryProbe::all_ok(),
                CanaryOutcome::Passed,
            ),
            BypassRecoveryConfig::default(),
        );

        // First probe: keep probing (1 pass).
        svc.evaluate_once(T0 + 60_000).await;
        assert!(
            store.lock().await.contains("css"),
            "one pass must not rejoin"
        );
        // Second probe meets criteria, canary passes -> rejoin.
        svc.evaluate_once(T0 + 1_000_000).await;

        assert!(
            !store.lock().await.contains("css"),
            "rejoined worker has no record"
        );
        assert_eq!(worker.status().await, rch_common::WorkerStatus::Healthy);
        assert!(worker.lifecycle().await.is_schedulable());
    }

    #[tokio::test]
    async fn one_lucky_ssh_never_rejoins() {
        // The classic scenario: SSH answers but every other dimension fails.
        // The worker must stay bypassed forever, no matter how many probes.
        let pool = pool_with(&["css"]).await;
        let store = store();
        let worker = pool.get(&WorkerId::new("css")).await.unwrap();
        record_worker_bypass(&store, &worker, BypassFailureClass::Ssh, "down", T0).await;

        let mut lucky = RecoveryProbe::all_ok();
        lucky.toolchain_ok = false;
        lucky.disk_ok = false;
        let svc = BypassRecoveryService::new(
            pool.clone(),
            store.clone(),
            FakeProber::new(vec![], lucky, CanaryOutcome::Passed),
            BypassRecoveryConfig::default(),
        );

        let mut now = T0 + 60_000;
        for _ in 0..8 {
            svc.evaluate_once(now).await;
            now += 2_000_000;
        }
        assert!(
            store.lock().await.contains("css"),
            "lucky SSH must never rejoin"
        );
        assert_eq!(worker.status().await, rch_common::WorkerStatus::Unreachable);
    }

    #[tokio::test]
    async fn flapping_worker_never_reaches_canary() {
        let pool = pool_with(&["css"]).await;
        let store = store();
        let worker = pool.get(&WorkerId::new("css")).await.unwrap();
        record_worker_bypass(&store, &worker, BypassFailureClass::Ssh, "down", T0).await;

        // Alternate pass/fail: every failure resets the streak.
        let probes = vec![
            RecoveryProbe::all_ok(),
            probe_failing("ssh"),
            RecoveryProbe::all_ok(),
            probe_failing("disk"),
            RecoveryProbe::all_ok(),
            probe_failing("telemetry"),
        ];
        let svc = BypassRecoveryService::new(
            pool.clone(),
            store.clone(),
            FakeProber::new(probes, probe_failing("ssh"), CanaryOutcome::Passed),
            BypassRecoveryConfig::default(),
        );

        let mut now = T0 + 60_000;
        for _ in 0..6 {
            svc.evaluate_once(now).await;
            now += 4_000_000;
        }
        assert!(store.lock().await.contains("css"));
        let rec = store.lock().await.get("css").cloned().unwrap();
        assert!(
            rec.consecutive_passes < 2,
            "flapping never accumulates 2 passes"
        );
        assert_eq!(rec.state, BypassState::TemporaryBypass);
    }

    #[tokio::test]
    async fn stale_telemetry_and_wrong_binary_stay_bypassed() {
        for dim in ["telemetry", "worker_binary"] {
            let pool = pool_with(&["css"]).await;
            let store = store();
            let worker = pool.get(&WorkerId::new("css")).await.unwrap();
            record_worker_bypass(&store, &worker, BypassFailureClass::Ssh, "down", T0).await;

            let svc = BypassRecoveryService::new(
                pool.clone(),
                store.clone(),
                FakeProber::new(vec![], probe_failing(dim), CanaryOutcome::Passed),
                BypassRecoveryConfig::default(),
            );
            svc.evaluate_once(T0 + 60_000).await;
            svc.evaluate_once(T0 + 5_000_000).await;
            assert!(
                store.lock().await.contains("css"),
                "{dim} failure must stay bypassed"
            );
            assert!(!worker.lifecycle().await.is_schedulable());
        }
    }

    #[tokio::test]
    async fn failing_canary_relapses_into_bypass() {
        let pool = pool_with(&["css"]).await;
        let store = store();
        let worker = pool.get(&WorkerId::new("css")).await.unwrap();
        record_worker_bypass(&store, &worker, BypassFailureClass::Ssh, "down", T0).await;

        let svc = BypassRecoveryService::new(
            pool.clone(),
            store.clone(),
            FakeProber::new(
                vec![RecoveryProbe::all_ok(), RecoveryProbe::all_ok()],
                RecoveryProbe::all_ok(),
                CanaryOutcome::Failed,
            ),
            BypassRecoveryConfig::default(),
        );
        svc.evaluate_once(T0 + 60_000).await;
        svc.evaluate_once(T0 + 1_000_000).await;

        assert!(
            store.lock().await.contains("css"),
            "failed canary keeps the record"
        );
        let rec = store.lock().await.get("css").cloned().unwrap();
        assert_eq!(rec.state, BypassState::TemporaryBypass);
        assert_eq!(rec.consecutive_passes, 0, "relapse resets the pass streak");
        assert!(!worker.lifecycle().await.is_schedulable());
    }

    #[tokio::test]
    async fn admin_disabled_worker_is_never_probed_for_rejoin() {
        let pool = pool_with(&["css"]).await;
        let store = store();
        let worker = pool.get(&WorkerId::new("css")).await.unwrap();
        record_worker_bypass(&store, &worker, BypassFailureClass::Ssh, "down", T0).await;
        // Operator disables the worker after it was bypassed.
        worker.disable(Some("maintenance".to_string())).await;

        let svc = BypassRecoveryService::new(
            pool.clone(),
            store.clone(),
            // All probes pass — but the worker must STILL not rejoin.
            FakeProber::new(vec![], RecoveryProbe::all_ok(), CanaryOutcome::Passed),
            BypassRecoveryConfig::default(),
        );
        svc.evaluate_once(T0 + 60_000).await;
        svc.evaluate_once(T0 + 5_000_000).await;

        assert!(
            store.lock().await.contains("css"),
            "record untouched for disabled worker"
        );
        assert_eq!(worker.status().await, rch_common::WorkerStatus::Disabled);
    }

    #[tokio::test]
    async fn missing_live_worker_retains_durable_quarantine_record() {
        let pool = pool_with(&[]).await;
        let store = store();
        let record = BypassRecord::new("missing", "h", "u", BypassFailureClass::Ssh, T0);
        store.lock().await.upsert(record.clone()).unwrap();

        let svc = BypassRecoveryService::new(
            pool,
            store.clone(),
            FakeProber::new(vec![], RecoveryProbe::all_ok(), CanaryOutcome::Passed),
            BypassRecoveryConfig::default(),
        );
        svc.evaluate_once(T0 + 60_000).await;

        assert_eq!(
            store.lock().await.get("missing"),
            Some(&record),
            "a fresh daemon pool must not erase a durable quarantine record"
        );
    }

    #[tokio::test]
    async fn no_canary_required_rejoins_after_passes() {
        let pool = pool_with(&["css"]).await;
        let store = store();
        let worker = pool.get(&WorkerId::new("css")).await.unwrap();
        record_worker_bypass(&store, &worker, BypassFailureClass::Ssh, "down", T0).await;
        // Switch the stored record to no-canary criteria.
        {
            let mut s = store.lock().await;
            let mut rec = s.get("css").cloned().unwrap();
            rec.auto_rejoin = AutoRejoinCriteria {
                required_consecutive_passes: 2,
                canary_required: false,
            };
            s.upsert(rec).unwrap();
        }

        let svc = BypassRecoveryService::new(
            pool.clone(),
            store.clone(),
            FakeProber::new(vec![], RecoveryProbe::all_ok(), CanaryOutcome::Failed),
            BypassRecoveryConfig::default(),
        );
        svc.evaluate_once(T0 + 60_000).await;
        svc.evaluate_once(T0 + 1_000_000).await;

        assert!(
            !store.lock().await.contains("css"),
            "no-canary rejoin removes the record"
        );
        assert!(worker.lifecycle().await.is_schedulable());
    }

    #[tokio::test]
    async fn reconcile_on_start_restores_lifecycle_from_records() {
        let pool = pool_with(&["css", "vmi"]).await;
        let store = store();
        {
            let mut s = store.lock().await;
            s.upsert(BypassRecord::new(
                "css",
                "h",
                "u",
                BypassFailureClass::Ssh,
                T0,
            ))
            .unwrap();
            let mut canary =
                BypassRecord::new("vmi", "h", "u", BypassFailureClass::DiskInodePressure, T0);
            canary.details.insert(
                RECOVERY_ENDPOINT.into(),
                recovery_endpoint(&worker_config("vmi")),
            );
            canary.state = BypassState::RecoveredPendingCanary;
            s.upsert(canary).unwrap();
        }

        let svc = BypassRecoveryService::new(
            pool.clone(),
            store.clone(),
            FakeProber::new(vec![], RecoveryProbe::all_ok(), CanaryOutcome::Passed),
            BypassRecoveryConfig::default(),
        );
        svc.reconcile_on_start().await;

        let css = pool.get(&WorkerId::new("css")).await.unwrap();
        let vmi = pool.get(&WorkerId::new("vmi")).await.unwrap();
        assert_eq!(
            css.eligibility().await,
            crate::workers::EligibilityState::TemporaryBypass
        );
        assert!(
            vmi.is_canary_pending().await,
            "canary-pending record restores canary-pending lifecycle"
        );
    }

    #[tokio::test]
    async fn retarget_discards_old_backoff_and_passes_but_retains_incidents_and_admin_intent() {
        for dimension in ["host", "user", "key", "os"] {
            for disabled in [false, true] {
                let pool = pool_with(&["retarget"]).await;
                let store = store();
                let worker = pool.get(&WorkerId::new("retarget")).await.unwrap();
                record_worker_bypass(
                    &store,
                    &worker,
                    BypassFailureClass::DiskInodePressure,
                    "disk incident",
                    T0,
                )
                .await;
                let mut record = store.lock().await.get("retarget").cloned().unwrap();
                for number in 1..=6 {
                    record.record_failure(T0 + number, "disk incident");
                }
                record.consecutive_passes = 2;
                record.state = BypassState::RecoveredPendingCanary;
                record.auto_rejoin.required_consecutive_passes = 3;
                record.disk_roots = vec!["/build-volume/rch".into()];
                record
                    .details
                    .insert("disk_fault_incidents".into(), "[\"build-42\"]".into());
                let old_due = record.next_probe_unix_ms;
                store.lock().await.upsert(record).unwrap();
                worker.recover_to_canary().await.unwrap();
                if disabled {
                    worker.disable(Some("operator maintenance".into())).await;
                }
                let mut replacement = worker_config("retarget");
                match dimension {
                    "host" => replacement.host = "new-host".into(),
                    "user" => replacement.user = "new-user".into(),
                    "key" => replacement.identity_file = "/new/key".into(),
                    "os" => replacement.tags = vec!["os:windows".into()],
                    _ => unreachable!(),
                }
                pool.add_worker(replacement.clone()).await;
                let service = BypassRecoveryService::new(
                    pool,
                    store.clone(),
                    FakeProber::new(
                        vec![RecoveryProbe::all_ok()],
                        RecoveryProbe::all_ok(),
                        CanaryOutcome::Failed,
                    ),
                    BypassRecoveryConfig::default(),
                );
                let now = T0 + 10;
                assert!(now < old_due);
                service.evaluate_once(now).await;

                let current = store.lock().await.get("retarget").cloned().unwrap();
                assert_eq!(current.host, replacement.host);
                assert_eq!(current.user, replacement.user);
                assert_eq!(
                    current.details[RECOVERY_ENDPOINT],
                    recovery_endpoint(&replacement)
                );
                assert_eq!(current.details["disk_fault_incidents"], "[\"build-42\"]");
                assert_eq!(current.disk_roots, ["/build-volume/rch"]);
                assert_eq!(current.last_diagnostic, "disk incident");
                assert_eq!(current.failure_class, BypassFailureClass::DiskInodePressure);
                assert_eq!(current.backoff, BypassBackoff::initial());
                assert_eq!(current.consecutive_failures, 0);
                assert_eq!(current.consecutive_passes, u32::from(!disabled));
                assert_eq!(current.state, BypassState::TemporaryBypass);
                assert!(current.next_probe_unix_ms < old_due);
                assert_eq!(
                    service.prober.probes.lock().await.len(),
                    usize::from(disabled)
                );
                assert_eq!(
                    worker.lifecycle().await.admin,
                    if disabled {
                        AdminIntent::Disabled
                    } else {
                        AdminIntent::Active
                    }
                );
                assert_eq!(
                    worker.eligibility().await,
                    EligibilityState::TemporaryBypass
                );
                let persisted = BypassRecordStore::load(store.lock().await.path());
                assert_eq!(persisted.get("retarget"), Some(&current));
            }
        }
    }

    #[tokio::test]
    async fn restart_rebinds_changed_or_legacy_endpoints_once_and_retains_current_backoff() {
        for legacy in [false, true] {
            let store = store();
            let original = worker_config("restart");
            let mut record = BypassRecord::new("restart", "h", "u", BypassFailureClass::Ssh, T0);
            if !legacy {
                record
                    .details
                    .insert(RECOVERY_ENDPOINT.into(), recovery_endpoint(&original));
            }
            record.record_failure(T0 + 1, "old endpoint unavailable");
            record.state = BypassState::RecoveredPendingCanary;
            record.consecutive_passes = 2;
            record.disk_roots = vec!["/known-volume/rch".into()];
            record.next_probe_unix_ms = u64::MAX;
            store.lock().await.upsert(record).unwrap();
            let path = store.lock().await.path().to_path_buf();
            let mut replacement = original;
            if !legacy {
                replacement.identity_file = "/replacement/key".into();
            }
            let pool = WorkerPool::new();
            pool.add_worker(replacement.clone()).await;
            let reloaded = Arc::new(Mutex::new(BypassRecordStore::load(&path)));
            let service = BypassRecoveryService::new(
                pool,
                reloaded.clone(),
                FakeProber::new(vec![], RecoveryProbe::all_ok(), CanaryOutcome::Passed),
                BypassRecoveryConfig::default(),
            );
            service.reconcile_on_start().await;
            let rebound = reloaded.lock().await.get("restart").cloned().unwrap();
            assert_eq!(rebound.state, BypassState::TemporaryBypass);
            assert_eq!(rebound.consecutive_passes, 0);
            assert_eq!(rebound.consecutive_failures, 0);
            assert!(rebound.probe_due(now_unix_ms()));
            assert_eq!(rebound.disk_roots, ["/known-volume/rch"]);

            // Once bound, normal daemon restarts must not erase new backoff.
            let mut delayed = rebound;
            delayed.record_failure(now_unix_ms(), "replacement still unavailable");
            reloaded.lock().await.upsert(delayed.clone()).unwrap();
            let again = Arc::new(Mutex::new(BypassRecordStore::load(&path)));
            let pool = WorkerPool::new();
            pool.add_worker(replacement).await;
            let service = BypassRecoveryService::new(
                pool,
                again.clone(),
                FakeProber::new(vec![], RecoveryProbe::all_ok(), CanaryOutcome::Passed),
                BypassRecoveryConfig::default(),
            );
            service.reconcile_on_start().await;
            assert_eq!(again.lock().await.get("restart"), Some(&delayed));
            assert_eq!(
                BypassRecordStore::load(&path).get("restart"),
                Some(&delayed)
            );
        }
    }

    #[tokio::test]
    async fn ordinary_capacity_reload_does_not_reset_endpoint_recovery() {
        let pool = pool_with(&["unchanged"]).await;
        let store = store();
        let worker = pool.get(&WorkerId::new("unchanged")).await.unwrap();
        record_worker_bypass(&store, &worker, BypassFailureClass::Ssh, "down", T0).await;
        let before = store.lock().await.get("unchanged").cloned().unwrap();
        let mut replacement = worker_config("unchanged");
        replacement.total_slots = 32;
        replacement.priority = 200;
        replacement.tags = vec!["rust".into()];
        pool.add_worker(replacement).await;
        let service = BypassRecoveryService::new(
            pool,
            store.clone(),
            FakeProber::new(
                vec![RecoveryProbe::all_ok()],
                RecoveryProbe::all_ok(),
                CanaryOutcome::Passed,
            ),
            BypassRecoveryConfig::default(),
        );
        service.evaluate_once(T0 + 1).await;
        assert_eq!(store.lock().await.get("unchanged"), Some(&before));
        assert_eq!(service.prober.probes.lock().await.len(), 1);
    }

    struct DiskFactsProber {
        facts: ProbedFacts,
        config: BypassRecoveryConfig,
        expect_canary: bool,
    }

    impl RecoveryProber for DiskFactsProber {
        async fn probe(&self, worker: Arc<WorkerState>, record: BypassRecord) -> RecoveryProbe {
            assert!(worker.is_canary_pending().await);
            assert_eq!(worker.lifecycle().await.bypass_cause, None);
            assert_eq!(record.failure_class, BypassFailureClass::DiskInodePressure);
            assert_eq!(record.disk_roots, ["/separate-build-volume/rch"]);
            assess_recovery_probe_facts(&self.facts, Some(0.1), true, &self.config, &record)
        }

        async fn canary(&self, _worker: Arc<WorkerState>) -> CanaryOutcome {
            assert!(
                self.expect_canary,
                "partial disk evidence must not reach a canary"
            );
            CanaryOutcome::Passed
        }
    }

    #[tokio::test]
    async fn restarted_disk_canary_requires_the_failed_jobs_actual_filesystems() {
        for complete in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("bypasses.json");
            let mut before_restart = BypassRecordStore::with_path(path.clone());
            let endpoint = worker_config("disk-worker");
            let mut record = BypassRecord::new(
                "disk-worker",
                endpoint.host.clone(),
                endpoint.user.clone(),
                BypassFailureClass::DiskInodePressure,
                T0,
            );
            // This is a restart of the same endpoint's pending disk canary.
            // Unbound legacy records are separately required to start fresh.
            record
                .details
                .insert(RECOVERY_ENDPOINT.to_string(), recovery_endpoint(&endpoint));
            record.state = BypassState::RecoveredPendingCanary;
            record.auto_rejoin.required_consecutive_passes = 1;
            record.disk_roots = vec!["/separate-build-volume/rch".to_string()];
            before_restart.upsert(record).unwrap();

            let store = Arc::new(Mutex::new(BypassRecordStore::load(&path)));
            let pool = pool_with(&["disk-worker"]).await;
            let worker = pool.get(&WorkerId::new("disk-worker")).await.unwrap();
            let config = BypassRecoveryConfig::default();
            let mut facts = facts_all_good();
            let measurement = facts.disk_roots[0].clone();
            facts.disk_roots = config
                .disk_roots
                .iter()
                .map(|root| {
                    let mut fact = measurement.clone();
                    fact.path.clone_from(root);
                    fact
                })
                .collect();
            if complete {
                let mut fact = measurement;
                fact.path = "/separate-build-volume/rch".to_string();
                facts.disk_roots.push(fact);
            }
            let service = BypassRecoveryService::new(
                pool,
                store.clone(),
                DiskFactsProber {
                    facts,
                    config: config.clone(),
                    expect_canary: complete,
                },
                config,
            );
            service.reconcile_on_start().await;
            service.evaluate_once(T0 + 60_000).await;

            assert_eq!(worker.lifecycle().await.is_schedulable(), complete);
            let persisted = BypassRecordStore::load(&path);
            if complete {
                assert!(!persisted.contains("disk-worker"));
            } else {
                let remaining = persisted.get("disk-worker").unwrap();
                assert_eq!(remaining.state, BypassState::TemporaryBypass);
                assert_eq!(remaining.disk_roots, ["/separate-build-volume/rch"]);
                assert_eq!(remaining.consecutive_passes, 0);
            }
        }
    }

    #[tokio::test]
    async fn producer_advances_backoff_on_repeated_failures() {
        let pool = pool_with(&["css"]).await;
        let store = store();
        let worker = pool.get(&WorkerId::new("css")).await.unwrap();

        record_worker_bypass(&store, &worker, BypassFailureClass::Ssh, "first", T0).await;
        let after_first = store.lock().await.get("css").cloned().unwrap();
        record_worker_bypass(
            &store,
            &worker,
            BypassFailureClass::Ssh,
            "second",
            T0 + 1000,
        )
        .await;
        let after_second = store.lock().await.get("css").cloned().unwrap();

        assert_eq!(after_first.consecutive_failures, 1);
        assert_eq!(after_second.consecutive_failures, 2);
        assert!(after_second.backoff.current_ms > after_first.backoff.current_ms);
        // The first-failure timestamp is preserved across repeated failures.
        assert_eq!(
            after_first.first_failure_unix_ms,
            after_second.first_failure_unix_ms
        );
    }

    #[tokio::test]
    async fn disk_intent_is_not_acknowledged_until_its_record_reaches_storage() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let directory = tempfile::tempdir().unwrap();
        let blocked_parent = directory.path().join("state");
        std::fs::write(&blocked_parent, b"preserved obstruction").unwrap();
        let path = blocked_parent.join("bypasses.json");
        let store = Arc::new(Mutex::new(BypassRecordStore::with_path(&path)));
        let pool = pool_with(&["disk-worker"]).await;
        let worker = pool.get(&WorkerId::new("disk-worker")).await.unwrap();
        let roots = vec!["/build volume/rch".to_string()];
        let acknowledged = AtomicUsize::new(0);
        let result = record_worker_disk_bypass(
            &store,
            Some(&worker),
            "disk-worker",
            "incident-a",
            &roots,
            "disk full",
            T0,
            || {
                acknowledged.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;
        assert!(result.is_err());
        assert_eq!(acknowledged.load(Ordering::SeqCst), 0);
        assert_eq!(
            worker.eligibility().await,
            EligibilityState::TemporaryBypass
        );

        // Preserve the obstructing file, then allow the same real persistence
        // path to succeed. Its in-memory dedupe entry is not a durable receipt.
        std::fs::rename(
            &blocked_parent,
            directory.path().join("obstruction-evidence"),
        )
        .unwrap();
        record_worker_disk_bypass(
            &store,
            Some(&worker),
            "disk-worker",
            "incident-a",
            &roots,
            "disk full",
            T0,
            || {
                acknowledged.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(acknowledged.load(Ordering::SeqCst), 1);
        let persisted = BypassRecordStore::load(&path);
        let record = persisted.get("disk-worker").unwrap();
        assert_eq!(record.consecutive_failures, 1);
        assert_eq!(record.disk_roots, roots);
    }

    #[tokio::test]
    async fn disk_intent_replay_deduplicates_older_incidents_after_a_new_failure() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("bypasses.json");
        let store = Arc::new(Mutex::new(BypassRecordStore::with_path(&path)));
        let pool = pool_with(&["disk-worker"]).await;
        let worker = pool.get(&WorkerId::new("disk-worker")).await.unwrap();
        let result = record_worker_disk_bypass(
            &store,
            Some(&worker),
            "disk-worker",
            "incident-a",
            &["/build-volume/rch".to_string()],
            "disk full",
            T0,
            || Err(std::io::Error::other("interrupted history acknowledgment")),
        )
        .await;
        assert!(result.is_err());
        let reloaded = Arc::new(Mutex::new(BypassRecordStore::load(&path)));
        record_worker_disk_bypass(
            &reloaded,
            Some(&worker),
            "disk-worker",
            "incident-b",
            &["/target-volume/rch".to_string()],
            "disk full",
            T0 + 1,
            || Ok(()),
        )
        .await
        .unwrap();
        record_worker_disk_bypass(
            &reloaded,
            Some(&worker),
            "disk-worker",
            "incident-a",
            &["/build-volume/rch".to_string()],
            "disk full",
            T0,
            || Ok(()),
        )
        .await
        .unwrap();
        let persisted = BypassRecordStore::load(&path);
        let record = persisted.get("disk-worker").unwrap();
        assert_eq!(record.consecutive_failures, 2);
        assert_eq!(record.last_failure_unix_ms, T0 + 1);
        assert_eq!(
            record.disk_roots,
            ["/build-volume/rch", "/target-volume/rch"]
        );
    }

    #[tokio::test]
    async fn disk_recovery_waits_until_pending_completion_intent_is_acknowledged() {
        let directory = tempfile::tempdir().unwrap();
        let history = Arc::new(
            BuildHistory::new(10).with_persistence(directory.path().join("history.jsonl")),
        );
        let build = history.start_active_build_with_wrapper(
            "project".into(),
            "disk-worker".into(),
            "cargo build".into(),
            12345,
            Some("disk-owner".into()),
            1,
            rch_common::BuildLocation::Remote,
        );
        history
            .complete_durable_with_disk_fault(
                build.id,
                "disk-worker",
                Some("disk-owner"),
                crate::history::BuildCompletion {
                    exit_code: 101,
                    duration_ms: Some(10),
                    bytes_transferred: None,
                    timing: None,
                    cancellation: None,
                },
                Some(vec!["/build-volume/rch".to_string()]),
            )
            .unwrap();
        let fault = history.pending_disk_fault(build.id).unwrap();
        let store = Arc::new(Mutex::new(BypassRecordStore::with_path(
            directory.path().join("bypasses.json"),
        )));
        let pool = pool_with(&["disk-worker"]).await;
        let worker = pool.get(&WorkerId::new("disk-worker")).await.unwrap();
        assert!(
            record_worker_disk_bypass(
                &store,
                Some(&worker),
                "disk-worker",
                &fault.incident_id,
                &fault.roots,
                "disk full",
                T0,
                || Err(std::io::Error::other("acknowledgment interrupted")),
            )
            .await
            .is_err()
        );
        let mut expected = store.lock().await.get("disk-worker").unwrap().clone();
        expected.auto_rejoin.required_consecutive_passes = 1;
        store.lock().await.upsert(expected.clone()).unwrap();
        let service = BypassRecoveryService::new(
            pool,
            store.clone(),
            FakeProber::new(vec![], RecoveryProbe::all_ok(), CanaryOutcome::Passed),
            BypassRecoveryConfig::default(),
        )
        .with_history(history.clone());
        service.evaluate_once(T0 + 60_000).await;
        assert_eq!(store.lock().await.get("disk-worker"), Some(&expected));
        assert!(!worker.lifecycle().await.is_schedulable());

        record_worker_disk_bypass(
            &store,
            Some(&worker),
            "disk-worker",
            &fault.incident_id,
            &fault.roots,
            "disk full",
            T0,
            || history.acknowledge_disk_fault(build.id, &fault.incident_id),
        )
        .await
        .unwrap();
        service.evaluate_once(T0 + 60_000).await;
        assert!(worker.lifecycle().await.is_schedulable());
        assert!(!store.lock().await.contains("disk-worker"));
    }

    #[test]
    fn disk_fault_roots_preserve_remote_path_semantics_and_refuse_ambiguous_paths() {
        let roots = vec![
            "/worker's build volume/rch".to_string(),
            "C:/rch/builds".to_string(),
            "/worker's build volume/rch".to_string(),
        ];
        assert_eq!(validate_disk_fault_roots(&roots).unwrap().len(), 2);
        for root in [
            "",
            "relative/rch",
            "/build/../other",
            "/build/./rch",
            "/build//rch",
            "/build/rch/",
            "/build\nother",
        ] {
            assert!(
                validate_disk_fault_roots(&[root.to_string()]).is_err(),
                "{root:?}"
            );
        }
    }

    #[tokio::test]
    async fn disk_failure_upgrades_existing_bypass_and_cannot_be_forgotten_by_ssh_failure() {
        let pool = pool_with(&["disk-worker"]).await;
        let store = store();
        let worker = pool.get(&WorkerId::new("disk-worker")).await.unwrap();
        for (index, class) in [
            BypassFailureClass::Ssh,
            BypassFailureClass::DiskInodePressure,
            BypassFailureClass::Ssh,
        ]
        .into_iter()
        .enumerate()
        {
            record_worker_bypass(
                &store,
                &worker,
                class,
                "observed failure",
                T0 + index as u64,
            )
            .await;
            let record = store.lock().await.get("disk-worker").cloned().unwrap();
            let expected = if index == 0 {
                BypassFailureClass::Ssh
            } else {
                BypassFailureClass::DiskInodePressure
            };
            assert_eq!(record.failure_class, expected);
            assert_eq!(record.reason_code, expected.incident_reason_code());
            assert_eq!(worker.lifecycle().await.bypass_cause, Some(expected));
            assert_eq!(worker.lifecycle().await.admin, AdminIntent::Active);
        }
    }

    struct FailingDuringRecovery {
        store: Arc<Mutex<BypassRecordStore>>,
        during_canary: bool,
    }

    struct RetargetingProber {
        during_canary: bool,
        restore_original: bool,
    }

    impl RetargetingProber {
        async fn retarget(&self, worker: &WorkerState) {
            let original = worker.config.read().await.clone();
            let mut replacement = original.clone();
            replacement.host = "replacement".into();
            assert!(worker.update_config(replacement).await);
            if self.restore_original {
                assert!(worker.update_config(original).await);
            }
        }
    }

    impl RecoveryProber for RetargetingProber {
        async fn probe(&self, worker: Arc<WorkerState>, _record: BypassRecord) -> RecoveryProbe {
            if !self.during_canary {
                self.retarget(&worker).await;
            }
            RecoveryProbe::all_ok()
        }

        async fn canary(&self, worker: Arc<WorkerState>) -> CanaryOutcome {
            assert!(self.during_canary);
            self.retarget(&worker).await;
            CanaryOutcome::Passed
        }
    }

    #[tokio::test]
    async fn stale_probe_and_canary_cannot_rejoin_after_retarget_even_when_endpoint_returns() {
        for during_canary in [false, true] {
            for restore_original in [false, true] {
                let pool = pool_with(&["stale"]).await;
                let store = store();
                let worker = pool.get(&WorkerId::new("stale")).await.unwrap();
                record_worker_bypass(&store, &worker, BypassFailureClass::Ssh, "down", T0).await;
                let mut initial = store.lock().await.get("stale").cloned().unwrap();
                initial.auto_rejoin.required_consecutive_passes = 1;
                initial.auto_rejoin.canary_required = during_canary;
                store.lock().await.upsert(initial).unwrap();
                let service = BypassRecoveryService::new(
                    pool.clone(),
                    store.clone(),
                    RetargetingProber {
                        during_canary,
                        restore_original,
                    },
                    BypassRecoveryConfig::default(),
                );
                // update_config needs the writer lock. This also catches any
                // accidental endpoint read guard held during network probing.
                tokio::time::timeout(Duration::from_secs(2), service.evaluate_once(T0 + 60_000))
                    .await
                    .unwrap();
                let current = store
                    .lock()
                    .await
                    .get("stale")
                    .cloned()
                    .expect("stale result cannot retire quarantine");
                assert_eq!(current.consecutive_passes, 0);
                assert_eq!(current.consecutive_failures, 0);
                assert_eq!(current.state, BypassState::TemporaryBypass);
                assert_eq!(current.backoff, BypassBackoff::initial());
                assert_eq!(current.next_probe_unix_ms, T0 + 60_000);
                assert_eq!(
                    worker.eligibility().await,
                    EligibilityState::TemporaryBypass
                );
                let persisted = BypassRecordStore::load(store.lock().await.path());
                assert_eq!(persisted.get("stale"), Some(&current));

                let fresh = BypassRecoveryService::new(
                    pool,
                    store.clone(),
                    FakeProber::new(vec![], RecoveryProbe::all_ok(), CanaryOutcome::Passed),
                    BypassRecoveryConfig::default(),
                );
                fresh.evaluate_once(T0 + 60_001).await;
                assert!(!store.lock().await.contains("stale"));
                assert!(worker.lifecycle().await.is_schedulable());
            }
        }
    }

    struct CanceledTrial(Arc<std::sync::atomic::AtomicBool>);

    impl Drop for CanceledTrial {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    struct BlockingEndpointProber {
        started: Arc<tokio::sync::Notify>,
        canceled: Arc<std::sync::atomic::AtomicBool>,
        during_canary: bool,
    }

    impl RecoveryProber for BlockingEndpointProber {
        async fn probe(&self, worker: Arc<WorkerState>, record: BypassRecord) -> RecoveryProbe {
            let config = worker.config.read().await.clone();
            if config.id.as_str() == "blocked" && config.host == "h" && !self.during_canary {
                let _trial = CanceledTrial(Arc::clone(&self.canceled));
                self.started.notify_one();
                return std::future::pending().await;
            }
            if config.host == "replacement" {
                assert_eq!(record.consecutive_passes, 0);
                assert_eq!(record.state, BypassState::TemporaryBypass);
                assert_eq!(record.backoff, BypassBackoff::initial());
            }
            RecoveryProbe::all_ok()
        }

        async fn canary(&self, worker: Arc<WorkerState>) -> CanaryOutcome {
            let config = worker.config.read().await.clone();
            if config.id.as_str() == "blocked" && config.host == "h" && self.during_canary {
                let _trial = CanceledTrial(Arc::clone(&self.canceled));
                self.started.notify_one();
                return std::future::pending().await;
            }
            CanaryOutcome::Passed
        }
    }

    #[tokio::test]
    async fn retarget_interrupts_stalled_network_and_other_workers_recover_concurrently() {
        for during_canary in [false, true] {
            let pool = pool_with(&["blocked", "healthy"]).await;
            let store = store();
            for id in ["blocked", "healthy"] {
                let worker = pool.get(&WorkerId::new(id)).await.unwrap();
                record_worker_bypass(&store, &worker, BypassFailureClass::Ssh, "down", T0).await;
                let mut record = store.lock().await.get(id).cloned().unwrap();
                record.auto_rejoin.required_consecutive_passes = 1;
                record.auto_rejoin.canary_required = during_canary;
                store.lock().await.upsert(record).unwrap();
            }
            let started = Arc::new(tokio::sync::Notify::new());
            let canceled = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let service = BypassRecoveryService::new(
                pool.clone(),
                store.clone(),
                BlockingEndpointProber {
                    started: Arc::clone(&started),
                    canceled: Arc::clone(&canceled),
                    during_canary,
                },
                BypassRecoveryConfig {
                    check_interval: Duration::from_secs(3600),
                    ..Default::default()
                },
            );
            let task = service.start();
            let completed = tokio::time::timeout(Duration::from_secs(2), async {
                started.notified().await;
                // The blocked worker must not stall another worker's recovery.
                while store.lock().await.contains("healthy") {
                    tokio::task::yield_now().await;
                }
                let mut replacement = worker_config("blocked");
                replacement.host = "replacement".into();
                pool.add_worker(replacement).await;
                // The check interval is an hour; only the watch can cancel the
                // old network future and start recovery of the replacement now.
                let worker = pool.get(&WorkerId::new("blocked")).await.unwrap();
                while store.lock().await.contains("blocked")
                    || !worker.lifecycle().await.is_schedulable()
                {
                    tokio::task::yield_now().await;
                }
            })
            .await;
            task.abort();
            let _ = task.await;
            assert!(
                completed.is_ok(),
                "recovery remained blocked after endpoint change"
            );
            assert!(canceled.load(std::sync::atomic::Ordering::SeqCst));
            assert!(
                pool.get(&WorkerId::new("blocked"))
                    .await
                    .unwrap()
                    .lifecycle()
                    .await
                    .is_schedulable()
            );
        }
    }

    impl RecoveryProber for FailingDuringRecovery {
        async fn probe(&self, worker: Arc<WorkerState>, _record: BypassRecord) -> RecoveryProbe {
            if !self.during_canary {
                record_worker_bypass(
                    &self.store,
                    &worker,
                    BypassFailureClass::DiskInodePressure,
                    "new disk failure during probe",
                    T0 + 60_001,
                )
                .await;
            }
            RecoveryProbe::all_ok()
        }

        async fn canary(&self, worker: Arc<WorkerState>) -> CanaryOutcome {
            assert!(self.during_canary);
            record_worker_bypass(
                &self.store,
                &worker,
                BypassFailureClass::DiskInodePressure,
                "new disk failure during canary",
                T0 + 60_001,
            )
            .await;
            CanaryOutcome::Passed
        }
    }

    #[tokio::test]
    async fn new_disk_failure_supersedes_an_in_flight_healthy_probe_or_canary() {
        for during_canary in [false, true] {
            let pool = pool_with(&["disk-worker"]).await;
            let store = store();
            let worker = pool.get(&WorkerId::new("disk-worker")).await.unwrap();
            record_worker_bypass(
                &store,
                &worker,
                BypassFailureClass::Ssh,
                "initial failure",
                T0,
            )
            .await;
            let mut initial = store.lock().await.get("disk-worker").cloned().unwrap();
            initial.auto_rejoin.required_consecutive_passes = 1;
            initial.auto_rejoin.canary_required = during_canary;
            store.lock().await.upsert(initial).unwrap();
            let service = BypassRecoveryService::new(
                pool,
                store.clone(),
                FailingDuringRecovery {
                    store: store.clone(),
                    during_canary,
                },
                BypassRecoveryConfig::default(),
            );

            service.evaluate_once(T0 + 60_000).await;

            let latest = store
                .lock()
                .await
                .get("disk-worker")
                .cloned()
                .expect("new failure must remain durable");
            assert_eq!(latest.last_failure_unix_ms, T0 + 60_001);
            assert_eq!(latest.failure_class, BypassFailureClass::DiskInodePressure);
            assert_eq!(latest.consecutive_passes, 0);
            assert_eq!(latest.state, BypassState::TemporaryBypass);
            assert_eq!(
                worker.eligibility().await,
                EligibilityState::TemporaryBypass
            );
            assert_eq!(
                worker.lifecycle().await.bypass_cause,
                Some(BypassFailureClass::DiskInodePressure)
            );
            let persisted = BypassRecordStore::load(store.lock().await.path());
            assert_eq!(persisted.get("disk-worker"), Some(&latest));
        }
    }

    #[test]
    fn disk_recovery_requires_one_valid_measurement_for_every_configured_root() {
        let config = BypassRecoveryConfig::default();
        let mut facts = facts_all_good();
        assert!(!has_complete_disk_evidence(
            &ProbedFacts::default(),
            &config
        ));
        assert!(
            !has_complete_disk_evidence(&facts, &config),
            "one root is still missing"
        );
        for root in config.disk_roots.iter().skip(1) {
            let mut other = facts.disk_roots[0].clone();
            other.path.clone_from(root);
            facts.disk_roots.push(other);
        }
        assert!(has_complete_disk_evidence(&facts, &config));
        assert!(assess_probe_facts(&facts, Some(0.1), true, &config).fully_healthy());
        for (total, free) in [(0, 0), (GB, 2 * GB)] {
            let mut invalid = facts.clone();
            invalid.disk_roots[1].total_bytes = total;
            invalid.disk_roots[1].available_bytes = free;
            assert!(!has_complete_disk_evidence(&invalid, &config));
        }
        let mut duplicate = facts.clone();
        duplicate.disk_roots.push(facts.disk_roots[0].clone());
        assert!(!has_complete_disk_evidence(&duplicate, &config));
        facts.disk_roots[1].available_bytes = GB;
        assert!(has_complete_disk_evidence(&facts, &config));
        assert!(!assess_probe_facts(&facts, Some(0.1), true, &config).disk_ok);
    }

    #[tokio::test]
    async fn detect_bypasses_only_quarantines_active_unreachable_workers() {
        let pool = pool_with(&["healthy", "unreachable", "disabled"]).await;
        let store = store();

        // Mark one worker plainly unreachable (health circuit opened) and one
        // operator-disabled.
        pool.get(&WorkerId::new("unreachable"))
            .await
            .unwrap()
            .set_status(rch_common::WorkerStatus::Unreachable)
            .await;
        pool.get(&WorkerId::new("unreachable"))
            .await
            .unwrap()
            .open_circuit()
            .await;
        pool.get(&WorkerId::new("disabled"))
            .await
            .unwrap()
            .disable(Some("operator".to_string()))
            .await;

        let svc = BypassRecoveryService::new(
            pool.clone(),
            store.clone(),
            FakeProber::new(vec![], RecoveryProbe::all_ok(), CanaryOutcome::Passed),
            BypassRecoveryConfig::default(),
        );
        svc.detect_new_bypasses(T0).await;

        let s = store.lock().await;
        assert!(
            s.contains("unreachable"),
            "unreachable worker is quarantined"
        );
        assert!(!s.contains("healthy"), "healthy worker is left alone");
        assert!(
            !s.contains("disabled"),
            "operator-disabled worker is never auto-bypassed"
        );
        drop(s);

        assert_eq!(
            pool.get(&WorkerId::new("unreachable"))
                .await
                .unwrap()
                .eligibility()
                .await,
            EligibilityState::TemporaryBypass
        );

        // Idempotent: a second pass does not create a duplicate or reset the record.
        let before = store.lock().await.get("unreachable").cloned().unwrap();
        svc.detect_new_bypasses(T0 + 1000).await;
        let after = store.lock().await.get("unreachable").cloned().unwrap();
        assert_eq!(
            before, after,
            "re-detecting an already-recorded worker is a no-op"
        );
    }

    #[test]
    fn assess_facts_all_good_is_fully_healthy() {
        let probe = assess_probe_facts(
            &facts_all_good(),
            Some(0.5),
            true,
            &BypassRecoveryConfig::default(),
        );
        assert!(probe.fully_healthy(), "{:?}", probe.first_failure());
    }

    #[tokio::test]
    async fn retarget_awaiting_first_probe_does_not_create_a_new_bypass() {
        for old_endpoint_failed in [false, true] {
            let pool = pool_with(&["retarget-pending-health"]).await;
            let store = store();
            let worker = pool
                .get(&WorkerId::new("retarget-pending-health"))
                .await
                .unwrap();
            if old_endpoint_failed {
                worker
                    .set_status(rch_common::WorkerStatus::Unreachable)
                    .await;
                worker.open_circuit().await;
            }
            let svc = BypassRecoveryService::new(
                pool,
                store.clone(),
                FakeProber::new(vec![], RecoveryProbe::all_ok(), CanaryOutcome::Passed),
                BypassRecoveryConfig::default(),
            );
            // Even a detection pass queued while the old endpoint had an open
            // circuit must recheck after acquiring its publication guards.
            let held_store = store.lock().await;
            let detector = svc.clone();
            let pending = tokio::spawn(async move { detector.detect_new_bypasses(T0).await });
            tokio::task::yield_now().await;
            let mut replacement = worker.endpoint_snapshot().await.config;
            replacement.host = "replacement-awaiting-health".to_string();
            assert!(worker.update_config(replacement).await);
            drop(held_store);
            tokio::time::timeout(Duration::from_secs(1), pending)
                .await
                .expect("bypass detector must finish after reload")
                .unwrap();
            assert!(store.lock().await.get("retarget-pending-health").is_none());
            assert_eq!(worker.eligibility().await, EligibilityState::Unreachable);

            // A real failure of this replacement still creates a bound record.
            worker
                .record_failure(Some("replacement authentication failed".to_string()))
                .await;
            worker.open_circuit().await;
            svc.detect_new_bypasses(T0 + 1).await;
            let record = store
                .lock()
                .await
                .get("retarget-pending-health")
                .cloned()
                .unwrap();
            assert_eq!(record.host, "replacement-awaiting-health");
            assert_eq!(
                worker.eligibility().await,
                EligibilityState::TemporaryBypass
            );
        }
    }

    #[test]
    fn assess_facts_empty_parse_is_unreachable() {
        let probe = assess_probe_facts(
            &ProbedFacts::default(),
            None,
            true,
            &BypassRecoveryConfig::default(),
        );
        assert!(!probe.ssh_ok);
        assert_eq!(probe.first_failure(), Some("ssh"));
    }

    #[test]
    fn assess_facts_missing_exact_path_binary_fails_binary_and_protocol() {
        let mut f = facts_all_good();
        f.worker = None; // exact-path rch-wkr never reported a version
        let probe = assess_probe_facts(&f, Some(0.1), true, &BypassRecoveryConfig::default());
        assert!(probe.ssh_ok);
        assert!(!probe.worker_binary_ok);
        assert!(!probe.protocol_ok);
        assert!(!probe.fully_healthy());
    }

    #[test]
    fn assess_facts_missing_cargo_or_required_target_fails_toolchain() {
        let mut no_cargo = facts_all_good();
        no_cargo.rust.rustc_version = None;
        assert!(
            !assess_probe_facts(&no_cargo, Some(0.1), true, &BypassRecoveryConfig::default())
                .toolchain_ok
        );

        let mut no_wasm = facts_all_good();
        no_wasm.rust.targets = vec!["x86_64-unknown-linux-gnu".to_string()];
        let needs_wasm = BypassRecoveryConfig {
            required_targets: vec!["wasm32-unknown-unknown".to_string()],
            ..BypassRecoveryConfig::default()
        };
        assert!(!assess_probe_facts(&no_wasm, Some(0.1), true, &needs_wasm).toolchain_ok);
        // ...but the all-good facts DO have the wasm target.
        assert!(assess_probe_facts(&facts_all_good(), Some(0.1), true, &needs_wasm).toolchain_ok);
    }

    #[test]
    fn assess_facts_low_disk_or_inodes_fails_disk() {
        let mut low_bytes = facts_all_good();
        low_bytes.disk_roots[0].available_bytes = GB; // 1 GiB < 5 GiB floor
        assert!(
            !assess_probe_facts(
                &low_bytes,
                Some(0.1),
                true,
                &BypassRecoveryConfig::default()
            )
            .disk_ok
        );

        let mut low_inodes = facts_all_good();
        low_inodes.disk_roots[0].available_inodes = 5; // < 10_000 floor
        assert!(
            !assess_probe_facts(
                &low_inodes,
                Some(0.1),
                true,
                &BypassRecoveryConfig::default()
            )
            .disk_ok
        );
    }

    #[test]
    fn assess_facts_no_probed_roots_does_not_trap_disk() {
        let mut f = facts_all_good();
        f.disk_roots.clear();
        assert!(
            assess_probe_facts(&f, Some(0.1), true, &BypassRecoveryConfig::default()).disk_ok,
            "an unmeasurable disk dimension must not trap a reachable worker"
        );
    }

    #[test]
    fn assess_windows_disk_without_unix_inode_counts_preserves_byte_floor() {
        // The real wsurf Git Bash probe reports bytes but `-` for free inodes.
        // Exercise parsing as well as admission so a healthy native worker can
        // recover, while missing/low byte capacity still refuses recovery.
        let config = BypassRecoveryConfig::default();
        for (available_kb, expected) in [("67108864", true), ("1048576", false), ("-", false)] {
            let facts = parse_capability_probe(&format!(
                "RCH_FACT os=mingw64_nt-10.0-26200\n\
                 RCH_FACT disk=/tmp;498499580;{available_kb};-\n"
            ));
            assert_eq!(facts.os.as_deref(), Some("windows"));
            assert_eq!(facts.disk_roots.len(), 1);
            assert_eq!(facts.disk_roots[0].available_inodes, 0);
            assert_eq!(
                assess_probe_facts(&facts, None, true, &config).disk_ok,
                expected,
                "available_kb={available_kb}"
            );
        }
    }

    #[test]
    fn assess_non_windows_disk_still_requires_free_inodes() {
        let config = BypassRecoveryConfig::default();
        for os in ["linux", "darwin", "unknown"] {
            for (inodes, expected) in [("-", false), ("0", false), ("9999", false), ("10000", true)]
            {
                let facts = parse_capability_probe(&format!(
                    "RCH_FACT os={os}\n\
                     RCH_FACT disk=/tmp;498499580;67108864;{inodes}\n"
                ));
                assert_eq!(
                    assess_probe_facts(&facts, None, true, &config).disk_ok,
                    expected,
                    "os={os}, inodes={inodes}"
                );
            }
        }
    }

    #[test]
    fn assess_facts_high_load_fails_but_unknown_load_is_lenient() {
        assert!(
            !assess_probe_facts(
                &facts_all_good(),
                Some(99.0),
                true,
                &BypassRecoveryConfig::default()
            )
            .load_ok
        );
        assert!(
            assess_probe_facts(
                &facts_all_good(),
                None,
                true,
                &BypassRecoveryConfig::default()
            )
            .load_ok
        );
    }

    #[test]
    fn assess_facts_stale_telemetry_fails_telemetry() {
        let probe = assess_probe_facts(
            &facts_all_good(),
            Some(0.1),
            false,
            &BypassRecoveryConfig::default(),
        );
        assert!(!probe.telemetry_ok);
        assert!(!probe.fully_healthy());
    }

    #[test]
    fn parse_load_per_core_divides_loadavg_by_cores() {
        let out = "incidental noise\nRCH_FACT loadavg1=2.0\nRCH_FACT nproc=4\nRCH_FACT os=linux\n";
        assert_eq!(SshRecoveryProber::parse_load_per_core(out), Some(0.5));
        // Missing nproc or empty -> unmeasurable.
        assert_eq!(
            SshRecoveryProber::parse_load_per_core("RCH_FACT loadavg1=2.0\n"),
            None
        );
        assert_eq!(SshRecoveryProber::parse_load_per_core(""), None);
    }

    #[test]
    fn rch_wkr_path_is_absolute_per_user() {
        assert_eq!(
            remote_worker_binary_path("ubuntu", None),
            "/home/ubuntu/.local/bin/rch-wkr"
        );
        assert_eq!(
            remote_worker_binary_path("root", None),
            "/root/.local/bin/rch-wkr"
        );
        assert_eq!(
            remote_worker_binary_path("jeffr", Some("windows")),
            "/c/Users/jeffr/.local/bin/rch-wkr.exe"
        );
    }

    #[test]
    fn recovery_probe_uses_declared_windows_worker_binary_path() {
        let prober = SshRecoveryProber::new(
            Arc::new(TelemetryStore::new(Duration::from_secs(300), None)),
            BypassRecoveryConfig::default(),
        );
        let mut worker = worker_config("wsurf");
        worker.user = "jeffr".to_string();
        worker.tags = vec![rch_common::os_tag("windows")];

        let spec = prober.probe_spec(&worker);

        assert_eq!(spec.rch_wkr_path, "/c/Users/jeffr/.local/bin/rch-wkr.exe");
    }

    #[tokio::test]
    async fn recovery_freshness_requires_replacement_endpoint_evidence() {
        use rch_telemetry::protocol::{TelemetrySource, WorkerTelemetry};

        let worker = WorkerState::new(worker_config("retarget-telemetry"));
        let telemetry = Arc::new(TelemetryStore::new(Duration::from_secs(300), None));
        let prober = SshRecoveryProber::new(telemetry.clone(), BypassRecoveryConfig::default());
        let sample: WorkerTelemetry = serde_json::from_value(serde_json::json!({
            "version": 1,
            "worker_id": "retarget-telemetry",
            "timestamp": Utc::now(),
            "collection_duration_ms": 1,
            "cpu": {
                "timestamp": Utc::now(), "overall_percent": 10.0,
                "per_core_percent": [10.0], "num_cores": 1,
                "load_average": { "one_min": 0.1, "five_min": 0.1,
                    "fifteen_min": 0.1, "running_processes": 1, "total_processes": 10 }
            },
            "memory": {
                "timestamp": Utc::now(), "total_gb": 32.0, "available_gb": 24.0,
                "used_percent": 25.0, "pressure_score": 25.0,
                "swap_used_gb": 0.0, "dirty_mb": 0.0
            }
        }))
        .unwrap();
        let before = worker.endpoint_snapshot().await;
        telemetry.ingest_for_endpoint(sample.clone(), TelemetrySource::SshPoll, &before);
        assert!(prober.telemetry_fresh(&before));

        let mut replacement = before.config.clone();
        replacement.host = "replacement.host".to_string();
        assert!(worker.update_config(replacement).await);
        let current = worker.endpoint_snapshot().await;
        assert!(!prober.telemetry_fresh(&current));
        telemetry.ingest(sample.clone(), TelemetrySource::Piggyback);
        assert!(!prober.telemetry_fresh(&current));

        telemetry.ingest_for_endpoint(sample, TelemetrySource::SshPoll, &current);
        assert!(prober.telemetry_fresh(&current));
        assert!(worker.update_config(before.config).await);
        assert!(
            !prober.telemetry_fresh(&worker.endpoint_snapshot().await),
            "returning to the original host still requires a new observation"
        );
    }

    #[test]
    fn recovery_telemetry_gap_is_expected_only_for_declared_windows_workers() {
        let mut windows = worker_config("wsurf");
        windows.tags = vec![rch_common::os_tag("windows")];
        assert!(recovery_telemetry_ok(&windows, false));

        let linux = worker_config("linux-worker");
        assert!(!recovery_telemetry_ok(&linux, false));
        assert!(recovery_telemetry_ok(&linux, true));
    }
}
