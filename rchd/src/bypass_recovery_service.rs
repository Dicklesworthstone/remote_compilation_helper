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
use tokio::task::JoinHandle;
use tokio::time::interval;
use tracing::{debug, info, warn};

use rch_common::bypass_record::{
    BypassRecord, BypassRecordStore, BypassState, classify_disable_reason,
};
use rch_common::bypass_recovery::{
    CanaryDecision, CanaryOutcome, ProbeDecision, RecoveryProbe, decide_canary, decide_probe,
};
use rch_common::capability_probe::{
    FACT_PREFIX, ProbeSpec, build_capability_probe_script, parse_capability_probe,
};
use rch_common::ssh::{SshClient, SshOptions};
use rch_common::{BypassFailureClass, WorkerConfig, WorkerId};
use rch_telemetry::remediation::{self, BypassTransition, SelfHealingAction, SelfHealingOutcome};

use crate::telemetry::TelemetryStore;
use crate::workers::{AdminIntent, EligibilityState, WorkerPool, WorkerState};

/// Current epoch milliseconds (the clock the decision core reasons in).
fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Bytes per gigabyte, for the disk-free-GB → bytes threshold.
const BYTES_PER_GB: f64 = 1024.0 * 1024.0 * 1024.0;

/// Tunable knobs for the recovery loop and the real SSH prober.
#[derive(Debug, Clone)]
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
            disk_roots: vec!["/tmp".to_string(), "/tmp/rch".to_string()],
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

    /// The exact absolute path to `rch-wkr` for the worker's SSH user. The
    /// capability probe shell-quotes this path (no `~`/`$HOME` expansion), so it
    /// must be absolute; a wrong path simply omits the worker-binary fact, which
    /// keeps the worker bypassed (the safe failure mode — never a false rejoin).
    fn rch_wkr_path(user: &str) -> String {
        let home = if user == "root" {
            "/root".to_string()
        } else {
            format!("/home/{user}")
        };
        format!("{home}/.local/bin/rch-wkr")
    }

    /// Build the exact-path capability [`ProbeSpec`] for a worker.
    fn probe_spec(&self, config: &WorkerConfig) -> ProbeSpec {
        let mut spec = ProbeSpec::new(config.user.clone(), Self::rch_wkr_path(&config.user));
        spec.disk_roots.clone_from(&self.config.disk_roots);
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
    async fn telemetry_fresh(&self, worker_id: &str) -> bool {
        match self.telemetry.latest(worker_id) {
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
    let disk_ok = if facts.disk_roots.is_empty() {
        true
    } else {
        facts
            .disk_roots
            .iter()
            .all(|r| r.available_bytes >= min_bytes && r.available_inodes >= config.min_disk_inodes)
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

impl RecoveryProber for SshRecoveryProber {
    async fn probe(&self, worker: Arc<WorkerState>) -> RecoveryProbe {
        let config = worker.config.read().await.clone();
        let spec = self.probe_spec(&config);
        // The 12.2 exact-path capability script (rch-wkr --version at the exact
        // path, rustup toolchains/targets, df -Pk/-Pi disk+inode roots), plus a
        // fresh load probe the capability script doesn't cover.
        let mut script = build_capability_probe_script(&spec);
        script.push_str(
            " la=$(awk 'NR==1{print $1}' /proc/loadavg 2>/dev/null) && printf '%sloadavg1=%s\\n' \"$P\" \"$la\"; \
             nc=$(nproc 2>/dev/null) && printf '%snproc=%s\\n' \"$P\" \"$nc\"; ",
        );

        let Some(stdout) = self.ssh_run(&config, &script).await else {
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
        let telemetry_ok = self.telemetry_fresh(config.id.as_str()).await;
        assess_probe_facts(&facts, load_per_core, telemetry_ok, &self.config)
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

/// Quarantine a worker into temporary bypass and persist a [`BypassRecord`].
///
/// The producer half of the loop: called from the failure-handling path (e.g.
/// the health monitor when a worker's circuit opens). Never quarantines an
/// operator-disabled worker — the admin axis owns that worker. An existing
/// record for the worker has its failure recorded (advancing backoff); a fresh
/// failure creates a new record.
pub async fn record_worker_bypass(
    store: &Arc<Mutex<BypassRecordStore>>,
    worker: &Arc<WorkerState>,
    class: BypassFailureClass,
    diagnostic: impl Into<String>,
    now_ms: u64,
) {
    if worker.lifecycle().await.admin == AdminIntent::Disabled {
        return;
    }
    worker.enter_bypass(class).await;
    // Remediation observability (bead 14.5): a worker just entered temporary
    // bypass — record the lifecycle transition and the ineligibility reason.
    remediation::record_bypass_transition(BypassTransition::Bypassed);
    remediation::record_worker_ineligible(class);

    let (id, host, user) = {
        let c = worker.config.read().await;
        (c.id.to_string(), c.host.clone(), c.user.clone())
    };
    let diagnostic = diagnostic.into();
    let mut store = store.lock().await;
    let record = if let Some(existing) = store.get(&id) {
        let mut rec = existing.clone();
        rec.record_failure(now_ms, diagnostic);
        rec
    } else {
        BypassRecord::new(id, host, user, class, now_ms).with_diagnostic(diagnostic)
    };
    if let Err(e) = store.upsert(record) {
        warn!(error = %e, "failed to persist bypass record");
    }
}

/// Background service that probes bypassed workers and rejoins the ones that
/// recover, keeping the durable record and live lifecycle in lockstep.
pub struct BypassRecoveryService<P: RecoveryProber> {
    pool: WorkerPool,
    store: Arc<Mutex<BypassRecordStore>>,
    prober: P,
    config: BypassRecoveryConfig,
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
            prober,
            config,
        }
    }

    /// Spawn the periodic loop. Reconciles persisted records into live worker
    /// lifecycle once, then on every tick quarantines newly-unreachable workers
    /// and probes due records.
    pub fn start(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            self.reconcile_on_start().await;
            let mut ticker = interval(self.config.check_interval);
            loop {
                ticker.tick().await;
                let now = now_unix_ms();
                self.detect_new_bypasses(now).await;
                self.evaluate_once(now).await;
            }
        })
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
            let lifecycle = worker.lifecycle().await;
            if lifecycle.admin != AdminIntent::Active
                || lifecycle.eligibility != EligibilityState::Unreachable
            {
                continue;
            }
            let id = worker.config.read().await.id.to_string();
            if self.store.lock().await.contains(&id) {
                continue;
            }
            let last_error = worker.last_error().await;
            let class = last_error
                .as_deref()
                .and_then(classify_disable_reason)
                .unwrap_or(BypassFailureClass::Ssh);
            let diagnostic = last_error.unwrap_or_else(|| "worker unreachable".to_string());
            info!(worker = %id, ?class, "quarantining unreachable worker into temporary bypass");
            record_worker_bypass(&self.store, &worker, class, diagnostic, now_ms).await;
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
        let due: Vec<BypassRecord> = {
            let store = self.store.lock().await;
            store
                .all()
                .into_iter()
                .filter(|r| r.probe_due(now_ms))
                .cloned()
                .collect()
        };
        for record in due {
            self.evaluate_record(record, now_ms).await;
        }
    }

    async fn evaluate_record(&self, record: BypassRecord, now_ms: u64) {
        let worker_id = record.worker_id.clone();
        let Some(worker) = self.pool.get(&WorkerId::new(&worker_id)).await else {
            // Worker was removed from the pool; drop the stale record.
            let _ = self.store.lock().await.remove(&worker_id);
            return;
        };
        // An operator-disabled worker is NEVER probed for auto-rejoin: that is an
        // admin-axis decision and the recovery loop must not override it.
        if worker.lifecycle().await.admin == AdminIntent::Disabled {
            debug!(worker = %worker_id, "skipping recovery probe: admin-disabled");
            return;
        }

        let probe = self.prober.probe(worker.clone()).await;
        match decide_probe(record, &probe, now_ms) {
            ProbeDecision::StayBypassed {
                failed_dimension,
                record,
            } => {
                debug!(worker = %worker_id, dimension = %failed_dimension, "recovery probe failed; staying bypassed");
                remediation::record_bypass_transition(BypassTransition::StayBypassed);
                worker.enter_bypass(record.failure_class).await;
                self.persist(*record).await;
            }
            ProbeDecision::KeepProbing {
                consecutive_passes,
                required,
                record,
            } => {
                debug!(worker = %worker_id, consecutive_passes, required, "recovery probe passed; keep probing");
                remediation::record_bypass_transition(BypassTransition::KeepProbing);
                self.persist(*record).await;
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
                self.persist((*record).clone()).await;
                let outcome = self.prober.canary(worker.clone()).await;
                // Remediation observability (bead 14.5): record the canary result.
                remediation::record_canary(outcome);
                match decide_canary(*record, outcome, now_ms) {
                    CanaryDecision::Rejoin => {
                        info!(worker = %worker_id, "canary passed; rejoining worker");
                        remediation::record_bypass_transition(BypassTransition::Rejoin);
                        remediation::record_self_healing(
                            SelfHealingAction::WorkerRejoin,
                            SelfHealingOutcome::Success,
                        );
                        self.rejoin(&worker, &worker_id).await;
                    }
                    CanaryDecision::Relapse { record } => {
                        warn!(worker = %worker_id, "canary failed; relapsing into bypass");
                        remediation::record_bypass_transition(BypassTransition::Relapse);
                        worker.enter_bypass(record.failure_class).await;
                        self.persist(*record).await;
                    }
                }
            }
            ProbeDecision::Rejoin => {
                info!(worker = %worker_id, "recovery criteria met (no canary required); rejoining worker");
                remediation::record_bypass_transition(BypassTransition::Rejoin);
                remediation::record_self_healing(
                    SelfHealingAction::WorkerRejoin,
                    SelfHealingOutcome::Success,
                );
                self.rejoin(&worker, &worker_id).await;
            }
        }
    }

    /// Drive the worker back to fully healthy, reconcile the selection-side
    /// circuit breaker, and drop the record. For the no-canary path the worker
    /// is still `TemporaryBypass`, so step it through the legal transitions; for
    /// the canary path it is already `RecoveredPendingCanary`.
    async fn rejoin(&self, worker: &Arc<WorkerState>, worker_id: &str) {
        if worker.is_canary_pending().await {
            let _ = worker.promote_from_canary().await;
        } else {
            let _ = worker.recover_to_canary().await;
            let _ = worker.promote_from_canary().await;
        }
        // The bypass opened the selection-side circuit (WorkerState.circuit) for
        // this worker; close it so the rejoined worker is actually schedulable.
        worker.close_circuit().await;
        let _ = self.store.lock().await.remove(worker_id);
    }

    async fn persist(&self, record: BypassRecord) {
        if let Err(e) = self.store.lock().await.upsert(record) {
            warn!(error = %e, "failed to persist bypass record");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::bypass_record::AutoRejoinCriteria;
    use rch_common::capability_probe::ProbedFacts;
    use std::collections::VecDeque;

    const GB: u64 = 1024 * 1024 * 1024;

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
        async fn probe(&self, _worker: Arc<WorkerState>) -> RecoveryProbe {
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
            SshRecoveryProber::rch_wkr_path("ubuntu"),
            "/home/ubuntu/.local/bin/rch-wkr"
        );
        assert_eq!(
            SshRecoveryProber::rch_wkr_path("root"),
            "/root/.local/bin/rch-wkr"
        );
    }
}
