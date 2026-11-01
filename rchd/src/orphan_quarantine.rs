//! Clears E104 orphan quarantines once the recorded process group is verified
//! dead (issue #62 follow-up, bd-g8m4g).
//!
//! The hook quarantines a worker when a client timeout could not verify that
//! the remote build's process group died. That durable admin-disable record
//! used to be permanent: hz3/hz4 sat disabled on five dispatchers for days
//! after the orphan was gone. When the record carries evidence (build id and
//! worker-side process record), this service re-runs the same kill probe the
//! hook ran and re-enables the worker on a `verified_dead` verdict — the
//! same evidence standard that would have avoided the quarantine in the first
//! place. A worker-side record that stays absent for [`RECORD_ABSENT_GRACE`]
//! also clears it: the cache sweep's orphan watchdog deletes a record only
//! once its group is gone, a build's own completion and a reboot remove it
//! too, and without a record nothing can ever re-probe (bd-sh0tr: vmi1156319
//! sat disabled on csd for 41 h with no record left). Still-alive and channel
//! failures keep it. Process evidence is bound to its original SSH endpoint;
//! old reasons require that endpoint to be proven from durable active-build
//! ownership. Unproven legacy and operator-reasoned disables stay untouched.

use crate::history::BuildHistory;
use crate::workers::WorkerPool;
use rch_common::bypass_record::{AdminDisableRecord, AdminDisableStore};
use rch_common::orphan_quarantine::{
    QuarantineEvidence, kill_probe_script, parse_quarantine_reason, probe_record_absent,
    probe_verified_dead,
};
use rch_common::ssh::{SshClient, SshOptions};
use rch_common::{BuildLocation, WorkerConfig, WorkerId};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

/// How often quarantined workers with evidence are re-probed.
pub const ORPHAN_QUARANTINE_CHECK_INTERVAL: Duration = Duration::from_secs(300);
const PROBE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a quarantine's worker-side record must have been absent before
/// that absence clears it. Longer than the cache sweep's 240-minute orphan
/// window, so a missing record is the watchdog's verdict, not a race.
pub const RECORD_ABSENT_GRACE: Duration = Duration::from_secs(6 * 3600);

/// Runs the kill probe on a worker. The seam between the decision loop and
/// SSH; faked in tests.
pub trait OrphanProber: Send + Sync {
    /// The probe's stdout, or `None` when the channel failed (which keeps the
    /// quarantine, like any other unverified outcome).
    fn probe(
        &self,
        worker: WorkerConfig,
        evidence: QuarantineEvidence,
    ) -> impl std::future::Future<Output = Option<String>> + Send;
}

/// The real prober: the hook's kill probe over a fresh SSH session.
pub struct SshOrphanProber;

impl OrphanProber for SshOrphanProber {
    async fn probe(&self, worker: WorkerConfig, evidence: QuarantineEvidence) -> Option<String> {
        let options = SshOptions {
            command_timeout: PROBE_TIMEOUT,
            connect_timeout: PROBE_TIMEOUT,
            ..Default::default()
        };
        let mut client = SshClient::new(worker, options);
        client.connect().await.ok()?;
        let script = kill_probe_script(&evidence.pgid_file, evidence.build_id);
        let command = format!("sh -c {}", shell_escape::escape(script.into()));
        let result = client.execute(&command).await.ok()?;
        // The probe always exits 0; anything else is a channel failure.
        (result.exit_code == 0).then_some(result.stdout)
    }
}

pub struct OrphanQuarantineService<P: OrphanProber> {
    pool: WorkerPool,
    store: Arc<Mutex<AdminDisableStore>>,
    history: Option<Arc<BuildHistory>>,
    prober: P,
    interval: Duration,
    evaluation: Mutex<()>,
}

impl<P: OrphanProber + 'static> OrphanQuarantineService<P> {
    pub fn new(
        pool: WorkerPool,
        store: Arc<Mutex<AdminDisableStore>>,
        prober: P,
        interval: Duration,
    ) -> Self {
        Self {
            pool,
            store,
            history: None,
            prober,
            interval,
            evaluation: Mutex::new(()),
        }
    }

    /// Older clients recorded only a build ID and process-record path. The
    /// admitted endpoint in durable ownership can supply their missing proof;
    /// today's worker configuration cannot. Recovery never completes the build
    /// or releases its retained slot reservation.
    pub fn with_history(mut self, history: Arc<BuildHistory>) -> Self {
        self.history = Some(history);
        self
    }

    fn proven_probe_target(
        &self,
        worker_id: &str,
        evidence: &QuarantineEvidence,
    ) -> Option<WorkerConfig> {
        if let Some(endpoint) = evidence.endpoint.as_ref() {
            return (endpoint.id.as_str() == worker_id).then(|| endpoint.worker_config());
        }
        let active = self.history.as_ref()?.active_build(evidence.build_id)?;
        if active.worker_id != worker_id
            || active.location != BuildLocation::Remote
            || active.remote_pgid_file.as_deref() != Some(evidence.pgid_file.as_str())
        {
            return None;
        }
        let endpoint = active.worker_endpoint?;
        (endpoint.config.id.as_str() == worker_id).then_some(endpoint.config)
    }

    pub fn start(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(self.interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                self.evaluate_once().await;
            }
        })
    }

    /// One pass over the durable records; returns how many quarantines were
    /// cleared.
    pub async fn evaluate_once(&self) -> usize {
        let Ok(_evaluation) = self.evaluation.try_lock() else {
            return 0;
        };
        let candidates: Vec<(AdminDisableRecord, QuarantineEvidence)> = {
            let store = self.store.lock().await;
            store
                .all()
                .into_iter()
                .filter_map(|record| {
                    let reason = record.reason.as_deref()?;
                    parse_quarantine_reason(reason).map(|evidence| (record.clone(), evidence))
                })
                .collect()
        };
        let now_ms = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        )
        .unwrap_or(u64::MAX);
        let mut cleared = 0;
        for (record, evidence) in candidates {
            let worker_id = &record.worker_id;
            // This is the probe's target authority. The current inventory
            // snapshot below fences administrative changes and publication;
            // it cannot prove where a historical process was launched.
            let Some(config) = self.proven_probe_target(worker_id, &evidence) else {
                debug!(worker = %worker_id, build_id = evidence.build_id,
                    "orphan quarantine has no proven execution endpoint; keeping");
                continue;
            };
            let Some(worker) = self.pool.get(&WorkerId::new(worker_id)).await else {
                continue;
            };
            // Only the exact automatic E104 quarantine authorizes this probe.
            // A normal operator disable never gets this narrow exception to
            // the background-network gate, even if it replaces a queued item.
            let store = self.store.lock().await;
            if store.get(worker_id) != Some(&record)
                || worker.disabled_reason().await != record.reason
            {
                continue;
            }
            let mut revision = worker.network_revision_guard();
            let endpoint = worker.endpoint_snapshot().await;
            // The registry lookup can predate removal while the durable store
            // is busy. Reject that incarnation before dialing: capturing its
            // already-revoked epoch would otherwise authorize a probe whose
            // result can never pass the publication check below.
            let Some(endpoint_guard) = worker.lock_current_endpoint(&endpoint).await else {
                continue;
            };
            if !revision.is_current() {
                continue;
            }
            drop(endpoint_guard);
            drop(store);
            if rch_common::declared_os(&config.tags).as_deref() == Some("windows") {
                continue;
            }
            let Some(Ok(Some(stdout))) = revision
                .run(tokio::time::timeout(
                    PROBE_TIMEOUT,
                    self.prober.probe(config, evidence.clone()),
                ))
                .await
            else {
                debug!(worker = %worker_id, "orphan quarantine probe channel failed; keeping");
                continue;
            };
            let quarantine_age =
                Duration::from_millis(now_ms.saturating_sub(record.disabled_unix_ms));
            let verdict = if probe_verified_dead(&stdout) {
                "recorded process group verified dead"
            } else if probe_record_absent(&stdout) && quarantine_age >= RECORD_ABSENT_GRACE {
                "worker-side process record absent past the grace period"
            } else {
                debug!(worker = %worker_id, "orphan process group not verified dead; keeping");
                continue;
            };
            // The operator may have replaced or removed the record while the
            // probe ran; only the exact record that was verified is cleared.
            let mut store = self.store.lock().await;
            let Some(_endpoint) = worker.lock_current_endpoint(&endpoint).await else {
                continue;
            };
            if store.get(worker_id) != Some(&record) || !revision.is_current() {
                continue;
            }
            if let Err(error) = store.remove(worker_id) {
                warn!(worker = %worker_id, "could not remove orphan quarantine record: {error}");
                continue;
            }
            // Operator enable/disable uses the same durable-store lock. Keep
            // it until the live transition is finished so a newer disable
            // cannot be erased between removing this record and enabling.
            worker.enable().await;
            self.pool.notify_endpoint_change();
            drop(store);
            info!(
                worker = %worker_id,
                build_id = evidence.build_id,
                quarantine_age_secs = quarantine_age.as_secs(),
                "cleared E104 orphan quarantine: {verdict}"
            );
            cleared += 1;
        }
        cleared
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disk_pressure::DiskHeadroomAdmission;
    use rch_common::bypass_record::AdminDisableRecord;
    use rch_common::orphan_quarantine::{QuarantineEndpoint, quarantine_reason};
    use rch_common::{BuildHeartbeatPhase, BuildHeartbeatRequest};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct FakeProber {
        stdout: Option<&'static str>,
        calls: AtomicUsize,
        /// Replaces the record mid-probe to model an operator edit.
        overwrite: Option<Arc<Mutex<AdminDisableStore>>>,
    }

    impl OrphanProber for FakeProber {
        async fn probe(
            &self,
            worker: WorkerConfig,
            _evidence: QuarantineEvidence,
        ) -> Option<String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(store) = &self.overwrite {
                store
                    .lock()
                    .await
                    .upsert(AdminDisableRecord {
                        worker_id: worker.id.to_string(),
                        reason: Some("operator: keep out".into()),
                        disabled_unix_ms: 2,
                    })
                    .unwrap();
            }
            self.stdout.map(str::to_owned)
        }
    }

    fn evidence() -> QuarantineEvidence {
        QuarantineEvidence {
            build_id: 42,
            pgid_file: "/data/projects/app/.rch-run/42.pgid".into(),
            endpoint: Some(QuarantineEndpoint {
                id: WorkerId::new("w1"),
                host: "w1.invalid".into(),
                user: "u".into(),
                identity_file: "/dev/null".into(),
                declared_os: None,
            }),
        }
    }

    async fn fixture(
        reason: String,
    ) -> (tempfile::TempDir, WorkerPool, Arc<Mutex<AdminDisableStore>>) {
        let dir = tempfile::tempdir().unwrap();
        let mut store = AdminDisableStore::load(dir.path().join("admin_disables.json"));
        store
            .upsert(AdminDisableRecord {
                worker_id: "w1".into(),
                reason: Some(reason.clone()),
                disabled_unix_ms: 1,
            })
            .unwrap();
        let pool = WorkerPool::new();
        pool.add_worker(WorkerConfig {
            id: WorkerId::new("w1"),
            host: "w1.invalid".to_string(),
            user: "u".to_string(),
            identity_file: "/dev/null".to_string(),
            total_slots: 4,
            priority: 100,
            tags: vec![],
            tools: Vec::new(),
        })
        .await;
        pool.get(&WorkerId::new("w1"))
            .await
            .unwrap()
            .disable(Some(reason))
            .await;
        (dir, pool, Arc::new(Mutex::new(store)))
    }

    fn prober(stdout: Option<&'static str>) -> FakeProber {
        FakeProber {
            stdout,
            calls: AtomicUsize::new(0),
            overwrite: None,
        }
    }

    struct RecordingProber {
        observed: Arc<Mutex<Vec<(QuarantineEndpoint, QuarantineEvidence)>>>,
        stdout: Option<&'static str>,
    }

    impl OrphanProber for RecordingProber {
        async fn probe(
            &self,
            worker: WorkerConfig,
            evidence: QuarantineEvidence,
        ) -> Option<String> {
            self.observed
                .lock()
                .await
                .push((QuarantineEndpoint::from_config(&worker), evidence));
            self.stdout.map(str::to_owned)
        }
    }

    async fn legacy_owned_fixture(
        include_endpoint: bool,
    ) -> (
        tempfile::TempDir,
        WorkerPool,
        Arc<Mutex<AdminDisableStore>>,
        Arc<BuildHistory>,
        QuarantineEvidence,
    ) {
        let (dir, pool, store) = fixture(quarantine_reason(None)).await;
        let worker = pool.get(&WorkerId::new("w1")).await.unwrap();
        let history =
            Arc::new(BuildHistory::new(10).with_persistence(dir.path().join("history.jsonl")));
        let endpoint = worker.endpoint_snapshot().await;
        let active = history
            .try_start_active_build_with_waiter(
                "quarantined-project".into(),
                "w1".into(),
                "cargo build".into(),
                std::process::id(),
                Some("quarantined-wrapper".into()),
                2,
                BuildLocation::Remote,
                None,
                DiskHeadroomAdmission::default(),
                include_endpoint.then_some(endpoint),
            )
            .unwrap()
            .unwrap();
        let evidence = QuarantineEvidence {
            build_id: active.id,
            pgid_file: format!("/tmp/rch-run/quarantined-project/{}.pgid", active.id),
            endpoint: None,
        };
        history
            .record_build_heartbeat(BuildHeartbeatRequest {
                build_id: active.id,
                worker_id: WorkerId::new("w1"),
                hook_pid: Some(std::process::id()),
                local_wrapper_id: Some("quarantined-wrapper".into()),
                remote_pgid_file: Some(evidence.pgid_file.clone()),
                phase: BuildHeartbeatPhase::Execute,
                detail: None,
                progress_counter: Some(1),
                progress_percent: None,
            })
            .unwrap();
        assert!(!history.ownership_failed());
        worker.restore_slots(active.slots).unwrap();
        let reason = quarantine_reason(Some(&evidence));
        store
            .lock()
            .await
            .upsert(AdminDisableRecord {
                worker_id: "w1".into(),
                reason: Some(reason.clone()),
                disabled_unix_ms: 1,
            })
            .unwrap();
        worker.disable(Some(reason)).await;
        (dir, pool, store, history, evidence)
    }

    #[tokio::test]
    async fn captured_endpoint_survives_retarget_and_durable_restart() {
        let original = evidence();
        let (dir, pool, store) = fixture(quarantine_reason(Some(&original))).await;
        let id = WorkerId::new("w1");
        let mut replacement = pool.get(&id).await.unwrap().config.read().await.clone();
        replacement.host = "replacement.invalid".into();
        replacement.user = "replacement-user".into();
        replacement.identity_file = "/keys/replacement".into();
        replacement.tags = vec!["os:windows".into()];
        pool.add_worker(replacement.clone()).await;
        let observed = Arc::new(Mutex::new(Vec::new()));
        let service = OrphanQuarantineService::new(
            pool,
            store,
            RecordingProber {
                observed: observed.clone(),
                stdout: None,
            },
            ORPHAN_QUARANTINE_CHECK_INTERVAL,
        );
        assert_eq!(service.evaluate_once().await, 0);
        assert_eq!(
            observed.lock().await.as_slice(),
            &[(original.endpoint.clone().unwrap(), original.clone())]
        );

        let store = Arc::new(Mutex::new(AdminDisableStore::load(
            dir.path().join("admin_disables.json"),
        )));
        let pool = WorkerPool::new().with_admin_disable_store(store.clone());
        pool.add_worker(replacement).await;
        let service = OrphanQuarantineService::new(
            pool.clone(),
            store.clone(),
            RecordingProber {
                observed: observed.clone(),
                stdout: Some("RCH_E104_KILL=verified_dead"),
            },
            ORPHAN_QUARANTINE_CHECK_INTERVAL,
        );
        assert_eq!(service.evaluate_once().await, 1);
        assert_eq!(
            observed.lock().await.as_slice(),
            &[
                (original.endpoint.clone().unwrap(), original.clone()),
                (original.endpoint.clone().unwrap(), original),
            ]
        );
        assert!(!pool.get(&id).await.unwrap().is_disabled().await);
        assert!(store.lock().await.get("w1").is_none());
    }

    #[tokio::test]
    async fn legacy_quarantine_uses_exact_durable_owner_without_releasing_build_slots() {
        for (retarget, restart) in [(false, false), (true, false), (true, true)] {
            let (dir, pool, store, history, evidence) = legacy_owned_fixture(true).await;
            let id = WorkerId::new("w1");
            let original = history.active_build(evidence.build_id).unwrap();
            let expected_endpoint =
                QuarantineEndpoint::from_config(&original.worker_endpoint.as_ref().unwrap().config);
            let mut config = pool.get(&id).await.unwrap().config.read().await.clone();
            if retarget {
                config.host = "replacement.invalid".into();
                config.identity_file = "/keys/replacement".into();
                pool.add_worker(config.clone()).await;
            }
            let (pool, store, history) = if restart {
                let history = Arc::new(
                    BuildHistory::load_from_file(&dir.path().join("history.jsonl"), 10).unwrap(),
                );
                assert!(
                    !history
                        .active_build(evidence.build_id)
                        .unwrap()
                        .worker_endpoint
                        .as_ref()
                        .unwrap()
                        .has_runtime_identity()
                );
                let store = Arc::new(Mutex::new(AdminDisableStore::load(
                    dir.path().join("admin_disables.json"),
                )));
                let pool = WorkerPool::new().with_admin_disable_store(store.clone());
                pool.add_worker(config).await;
                pool.restore_recovered_slots(&id, original.slots)
                    .await
                    .unwrap();
                (pool, store, history)
            } else {
                (pool, store, history)
            };
            let observed = Arc::new(Mutex::new(Vec::new()));
            let service = OrphanQuarantineService::new(
                pool.clone(),
                store.clone(),
                RecordingProber {
                    observed: observed.clone(),
                    stdout: Some("RCH_E104_KILL=verified_dead"),
                },
                ORPHAN_QUARANTINE_CHECK_INTERVAL,
            )
            .with_history(history.clone());
            assert_eq!(service.evaluate_once().await, 1);
            assert_eq!(
                observed.lock().await.as_slice(),
                &[(expected_endpoint.clone(), evidence.clone())]
            );
            let retained = history.active_build(evidence.build_id).unwrap();
            assert_eq!(retained.remote_pgid_file, original.remote_pgid_file);
            assert_eq!(retained.slots, original.slots);
            assert!(expected_endpoint.matches_config(&retained.worker_endpoint.unwrap().config));
            let worker = pool.get(&id).await.unwrap();
            assert_eq!(worker.used_slots(), original.slots);
            assert!(!worker.is_disabled().await);
            assert!(store.lock().await.get("w1").is_none());
        }
    }

    #[tokio::test]
    async fn mismatched_legacy_ownership_and_foreign_endpoint_never_authorize_a_probe() {
        for mismatch in 0..4 {
            let (_dir, pool, store, history, mut evidence) =
                legacy_owned_fixture(mismatch != 0).await;
            match mismatch {
                0 => {}
                1 => evidence.build_id += 1,
                2 => evidence.pgid_file.push_str(".other"),
                3 => {
                    let mut foreign = QuarantineEndpoint::from_config(
                        &*pool
                            .get(&WorkerId::new("w1"))
                            .await
                            .unwrap()
                            .config
                            .read()
                            .await,
                    );
                    foreign.id = WorkerId::new("another-worker");
                    evidence.endpoint = Some(foreign);
                }
                _ => unreachable!(),
            }
            let reason = quarantine_reason(Some(&evidence));
            store
                .lock()
                .await
                .upsert(AdminDisableRecord {
                    worker_id: "w1".into(),
                    reason: Some(reason.clone()),
                    disabled_unix_ms: 1,
                })
                .unwrap();
            let worker = pool.get(&WorkerId::new("w1")).await.unwrap();
            worker.disable(Some(reason)).await;
            let service = OrphanQuarantineService::new(
                pool,
                store.clone(),
                prober(Some("RCH_E104_KILL=verified_dead")),
                ORPHAN_QUARANTINE_CHECK_INTERVAL,
            )
            .with_history(history);
            assert_eq!(service.evaluate_once().await, 0, "mismatch {mismatch}");
            assert_eq!(service.prober.calls.load(Ordering::SeqCst), 0);
            assert!(worker.is_disabled().await);
            assert_eq!(worker.used_slots(), 2);
            assert!(store.lock().await.get("w1").is_some());
        }
    }

    #[tokio::test]
    async fn legacy_quarantine_never_probes_an_unproven_replacement_after_retarget_or_restart() {
        // Old records identify a process, but contain no proof of which SSH
        // endpoint owned it. The replacement having no such record does not
        // prove that the original process is gone, regardless of record age.
        let reason = "e104-timeout-orphan-unverified[build=42]: old client timeout \
                      (pgid_file=/data/projects/app/.rch-run/42.pgid)"
            .to_owned();
        let (dir, pool, store) = fixture(reason.clone()).await;
        let id = WorkerId::new("w1");
        let mut replacement = pool.get(&id).await.unwrap().config.read().await.clone();
        replacement.host = "replacement.invalid".into();
        pool.add_worker(replacement.clone()).await;
        let service = OrphanQuarantineService::new(
            pool.clone(),
            store.clone(),
            prober(Some("RCH_E104_KILL=record_absent")),
            ORPHAN_QUARANTINE_CHECK_INTERVAL,
        );
        assert_eq!(service.evaluate_once().await, 0);
        assert_eq!(service.prober.calls.load(Ordering::SeqCst), 0);
        assert!(pool.get(&id).await.unwrap().is_disabled().await);

        let restarted_store = Arc::new(Mutex::new(AdminDisableStore::load(
            dir.path().join("admin_disables.json"),
        )));
        let restarted_pool = WorkerPool::new().with_admin_disable_store(restarted_store.clone());
        restarted_pool.add_worker(replacement).await;
        let service = OrphanQuarantineService::new(
            restarted_pool.clone(),
            restarted_store.clone(),
            prober(Some("RCH_E104_KILL=verified_dead")),
            ORPHAN_QUARANTINE_CHECK_INTERVAL,
        );
        assert_eq!(service.evaluate_once().await, 0);
        assert_eq!(service.prober.calls.load(Ordering::SeqCst), 0);
        assert!(restarted_pool.get(&id).await.unwrap().is_disabled().await);
        assert_eq!(
            restarted_store
                .lock()
                .await
                .get("w1")
                .unwrap()
                .reason
                .as_deref(),
            Some(reason.as_str())
        );
    }

    #[tokio::test]
    async fn verified_dead_clears_record_and_enables_worker() {
        let (_dir, pool, store) = fixture(quarantine_reason(Some(&evidence()))).await;
        let service = OrphanQuarantineService::new(
            pool.clone(),
            store.clone(),
            prober(Some("noise\nRCH_E104_KILL=verified_dead\n")),
            ORPHAN_QUARANTINE_CHECK_INTERVAL,
        );
        assert_eq!(service.evaluate_once().await, 1);
        assert!(store.lock().await.get("w1").is_none());
        let worker = pool.get(&WorkerId::new("w1")).await.unwrap();
        assert!(worker.disabled_reason().await.is_none());
    }

    #[tokio::test]
    async fn unverified_outcomes_keep_the_quarantine() {
        for stdout in [Some("RCH_E104_KILL=still_alive"), Some("garbage"), None] {
            let (_dir, pool, store) = fixture(quarantine_reason(Some(&evidence()))).await;
            let service = OrphanQuarantineService::new(
                pool,
                store.clone(),
                prober(stdout),
                ORPHAN_QUARANTINE_CHECK_INTERVAL,
            );
            assert_eq!(service.evaluate_once().await, 0, "{stdout:?}");
            assert!(store.lock().await.get("w1").is_some(), "{stdout:?}");
        }
    }

    #[tokio::test]
    async fn an_absent_record_clears_only_after_the_grace_period() {
        // The fixture's record is from 1970: far past the grace period.
        let (_dir, pool, store) = fixture(quarantine_reason(Some(&evidence()))).await;
        let service = OrphanQuarantineService::new(
            pool.clone(),
            store.clone(),
            prober(Some("RCH_E104_KILL=record_absent")),
            ORPHAN_QUARANTINE_CHECK_INTERVAL,
        );
        assert_eq!(service.evaluate_once().await, 1);
        assert!(store.lock().await.get("w1").is_none());
        let worker = pool.get(&WorkerId::new("w1")).await.unwrap();
        assert!(worker.disabled_reason().await.is_none());

        // A fresh quarantine keeps its worker even with the record absent.
        let (_dir, pool, store) = fixture(quarantine_reason(Some(&evidence()))).await;
        let now_ms = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        store
            .lock()
            .await
            .upsert(AdminDisableRecord {
                worker_id: "w1".into(),
                reason: Some(quarantine_reason(Some(&evidence()))),
                disabled_unix_ms: now_ms,
            })
            .unwrap();
        let service = OrphanQuarantineService::new(
            pool,
            store.clone(),
            prober(Some("RCH_E104_KILL=record_absent")),
            ORPHAN_QUARANTINE_CHECK_INTERVAL,
        );
        assert_eq!(service.evaluate_once().await, 0);
        assert!(store.lock().await.get("w1").is_some());
    }

    #[tokio::test]
    async fn records_without_evidence_are_never_probed() {
        for reason in [quarantine_reason(None), "corrupt cargo cache".to_owned()] {
            let (_dir, pool, store) = fixture(reason.clone()).await;
            let service = OrphanQuarantineService::new(
                pool,
                store.clone(),
                prober(Some("RCH_E104_KILL=verified_dead")),
                ORPHAN_QUARANTINE_CHECK_INTERVAL,
            );
            assert_eq!(service.evaluate_once().await, 0);
            assert_eq!(service.prober.calls.load(Ordering::SeqCst), 0, "{reason}");
            assert!(store.lock().await.get("w1").is_some());
        }
    }

    #[tokio::test]
    async fn an_operator_edit_during_the_probe_wins() {
        let (_dir, pool, store) = fixture(quarantine_reason(Some(&evidence()))).await;
        let service = OrphanQuarantineService::new(
            pool,
            store.clone(),
            FakeProber {
                stdout: Some("RCH_E104_KILL=verified_dead"),
                calls: AtomicUsize::new(0),
                overwrite: Some(store.clone()),
            },
            ORPHAN_QUARANTINE_CHECK_INTERVAL,
        );
        assert_eq!(service.evaluate_once().await, 0);
        let store = store.lock().await;
        assert_eq!(
            store.get("w1").and_then(|record| record.reason.as_deref()),
            Some("operator: keep out")
        );
    }

    #[tokio::test]
    async fn removal_while_waiting_for_durable_intent_never_probes_a_retired_endpoint() {
        let (dir, initial_pool, store) = fixture(quarantine_reason(Some(&evidence()))).await;
        let id = WorkerId::new("w1");
        let config = initial_pool
            .get(&id)
            .await
            .unwrap()
            .config
            .read()
            .await
            .clone();
        // Use production insertion semantics: a replacement inherits durable
        // intent under the same store lock used by administrative requests.
        let pool = WorkerPool::new().with_admin_disable_store(store.clone());
        pool.add_worker(config.clone()).await;
        let original = pool.get(&id).await.unwrap();
        let service = OrphanQuarantineService::new(
            pool.clone(),
            store.clone(),
            prober(Some("RCH_E104_KILL=verified_dead")),
            ORPHAN_QUARANTINE_CHECK_INTERVAL,
        );

        // Put another store waiter between the candidate snapshot and its
        // admission check. Tokio's FIFO mutex lets us pause the actual service
        // after it has resolved the worker Arc, without sleeps or test hooks.
        let initial_lock = store.lock().await;
        let evaluation = service.evaluate_once();
        tokio::pin!(evaluation);
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(evaluation.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(initial_lock);
        let competing_lock = store.lock();
        tokio::pin!(competing_lock);
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(competing_lock.as_mut(), cx).is_pending());
            assert!(std::future::Future::poll(evaluation.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        let durable = competing_lock.await;

        assert!(pool.remove_worker(&id).await);
        assert!(original.is_endpoint_retired());
        let replacement = pool.add_worker(config);
        tokio::pin!(replacement);
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(replacement.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(durable);

        let (cleared, ()) = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(evaluation, replacement)
        })
        .await
        .expect("replacement and stale admission must not wait for probe I/O");
        assert_eq!(cleared, 0);
        assert_eq!(
            service.prober.calls.load(Ordering::SeqCst),
            0,
            "a stale candidate must not start a probe whose result cannot be published"
        );
        let current = pool.get(&id).await.unwrap();
        assert!(!Arc::ptr_eq(&original, &current));
        assert!(current.is_disabled().await);
        assert!(
            AdminDisableStore::load(dir.path().join("admin_disables.json"))
                .get("w1")
                .is_some()
        );

        // The narrow evidence-based recovery exception remains live for the
        // current endpoint; only the obsolete incarnation was refused.
        assert_eq!(service.evaluate_once().await, 1);
        assert_eq!(service.prober.calls.load(Ordering::SeqCst), 1);
        assert!(!current.is_disabled().await);
    }

    struct BlockingProber {
        started: Arc<tokio::sync::Notify>,
        canceled: Arc<AtomicBool>,
    }

    impl OrphanProber for BlockingProber {
        async fn probe(
            &self,
            _worker: WorkerConfig,
            _evidence: QuarantineEvidence,
        ) -> Option<String> {
            struct CancelOnDrop(Arc<AtomicBool>);
            impl Drop for CancelOnDrop {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::SeqCst);
                }
            }
            let _canceled = CancelOnDrop(self.canceled.clone());
            self.started.notify_one();
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn retarget_cancels_inflight_probe_and_next_scan_keeps_original_target() {
        let original = evidence();
        let (dir, pool, store) = fixture(quarantine_reason(Some(&original))).await;
        let started = Arc::new(tokio::sync::Notify::new());
        let canceled = Arc::new(AtomicBool::new(false));
        let service = Arc::new(OrphanQuarantineService::new(
            pool.clone(),
            store.clone(),
            BlockingProber {
                started: started.clone(),
                canceled: canceled.clone(),
            },
            ORPHAN_QUARANTINE_CHECK_INTERVAL,
        ));
        let task = {
            let service = service.clone();
            tokio::spawn(async move { service.evaluate_once().await })
        };
        tokio::time::timeout(Duration::from_secs(1), started.notified())
            .await
            .expect("bound quarantine must begin its evidence probe");
        let worker = pool.get(&WorkerId::new("w1")).await.unwrap();
        let mut replacement = worker.config.read().await.clone();
        replacement.host = "replacement.invalid".into();
        pool.add_worker(replacement).await;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .expect("retarget must revoke the in-flight publication permit")
                .unwrap(),
            0
        );
        assert!(canceled.load(Ordering::SeqCst));
        assert!(worker.is_disabled().await);
        assert!(
            AdminDisableStore::load(dir.path().join("admin_disables.json"))
                .get("w1")
                .is_some()
        );
        let observed = Arc::new(Mutex::new(Vec::new()));
        let next = OrphanQuarantineService::new(
            pool,
            store,
            RecordingProber {
                observed: observed.clone(),
                stdout: Some("RCH_E104_KILL=verified_dead"),
            },
            ORPHAN_QUARANTINE_CHECK_INTERVAL,
        );
        assert_eq!(next.evaluate_once().await, 1);
        assert_eq!(
            observed.lock().await.as_slice(),
            &[(original.endpoint.clone().unwrap(), original)]
        );
    }

    #[tokio::test]
    async fn operator_disable_cancels_an_inflight_orphan_probe_and_keeps_durable_intent() {
        let (dir, pool, store) = fixture(quarantine_reason(Some(&evidence()))).await;
        let started = Arc::new(tokio::sync::Notify::new());
        let canceled = Arc::new(AtomicBool::new(false));
        let service = Arc::new(OrphanQuarantineService::new(
            pool.clone(),
            store.clone(),
            BlockingProber {
                started: started.clone(),
                canceled: canceled.clone(),
            },
            ORPHAN_QUARANTINE_CHECK_INTERVAL,
        ));
        let task = {
            let service = service.clone();
            tokio::spawn(async move { service.evaluate_once().await })
        };
        tokio::time::timeout(Duration::from_secs(1), started.notified())
            .await
            .expect("automatic quarantine must begin its evidence probe");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), service.evaluate_once())
                .await
                .expect("overlapping scan must not start another probe"),
            0
        );
        let worker = pool.get(&WorkerId::new("w1")).await.unwrap();
        let reason = "operator: laptop intentionally off".to_string();
        {
            let mut durable = store.lock().await;
            durable
                .upsert(AdminDisableRecord {
                    worker_id: "w1".into(),
                    reason: Some(reason.clone()),
                    disabled_unix_ms: 2,
                })
                .unwrap();
            worker.disable(Some(reason.clone())).await;
        }
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .expect("disable must cancel the stalled orphan transport")
                .unwrap(),
            0
        );
        assert!(canceled.load(Ordering::SeqCst));
        assert!(worker.is_disabled().await);
        let restarted = AdminDisableStore::load(dir.path().join("admin_disables.json"));
        assert_eq!(
            restarted.get("w1").unwrap().reason.as_deref(),
            Some(reason.as_str())
        );
        assert_eq!(service.evaluate_once().await, 0);
    }

    struct RenewingProber(Arc<Mutex<AdminDisableStore>>);

    impl OrphanProber for RenewingProber {
        async fn probe(
            &self,
            worker: WorkerConfig,
            _evidence: QuarantineEvidence,
        ) -> Option<String> {
            let mut store = self.0.lock().await;
            let mut renewed = store.get(worker.id.as_str()).unwrap().clone();
            // Repeating exactly the same reason is still a NEW decision. A
            // reason-only comparison would incorrectly clear this record.
            renewed.disabled_unix_ms += 1;
            store.upsert(renewed).unwrap();
            Some("RCH_E104_KILL=verified_dead".into())
        }
    }

    #[tokio::test]
    async fn a_renewed_quarantine_with_the_same_reason_is_not_cleared_by_an_old_probe() {
        let (_dir, pool, store) = fixture(quarantine_reason(Some(&evidence()))).await;
        let service = OrphanQuarantineService::new(
            pool.clone(),
            store.clone(),
            RenewingProber(store.clone()),
            ORPHAN_QUARANTINE_CHECK_INTERVAL,
        );
        assert_eq!(service.evaluate_once().await, 0);
        assert_eq!(store.lock().await.get("w1").unwrap().disabled_unix_ms, 2);
        assert!(
            pool.get(&WorkerId::new("w1"))
                .await
                .unwrap()
                .is_disabled()
                .await
        );
    }
}
