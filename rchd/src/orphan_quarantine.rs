//! Clears E104 orphan quarantines once the recorded process group is verified
//! dead (issue #62 follow-up, bd-g8m4g).
//!
//! The hook quarantines a worker when a client timeout could not verify that
//! the remote build's process group died. That durable admin-disable record
//! used to be permanent: hz3/hz4 sat disabled on five dispatchers for days
//! after the orphan was gone. When the record carries evidence (build id and
//! worker-side process record), this service re-runs the same kill probe the
//! hook ran and re-enables the worker ONLY on a `verified_dead` verdict —
//! the same evidence standard that would have avoided the quarantine in the
//! first place. Still-alive, missing-record and channel failures keep it, and
//! legacy or operator-reasoned disables are never touched.

use crate::workers::WorkerPool;
use rch_common::bypass_record::AdminDisableStore;
use rch_common::orphan_quarantine::{
    QuarantineEvidence, kill_probe_script, parse_quarantine_reason, probe_verified_dead,
};
use rch_common::ssh::{SshClient, SshOptions};
use rch_common::{WorkerConfig, WorkerId};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

/// How often quarantined workers with evidence are re-probed.
pub const ORPHAN_QUARANTINE_CHECK_INTERVAL: Duration = Duration::from_secs(300);
const PROBE_TIMEOUT: Duration = Duration::from_secs(30);

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
    prober: P,
    interval: Duration,
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
            prober,
            interval,
        }
    }

    pub fn start(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(self.interval);
            loop {
                ticker.tick().await;
                self.evaluate_once().await;
            }
        })
    }

    /// One pass over the durable records; returns how many quarantines were
    /// cleared.
    pub async fn evaluate_once(&self) -> usize {
        let candidates: Vec<(String, String, QuarantineEvidence)> = {
            let store = self.store.lock().await;
            store
                .all()
                .into_iter()
                .filter_map(|record| {
                    let reason = record.reason.as_deref()?;
                    parse_quarantine_reason(reason)
                        .map(|evidence| (record.worker_id.clone(), reason.to_owned(), evidence))
                })
                .collect()
        };
        let mut cleared = 0;
        for (worker_id, reason, evidence) in candidates {
            let Some(worker) = self.pool.get(&WorkerId::new(&worker_id)).await else {
                continue;
            };
            let config = worker.config.read().await.clone();
            if rch_common::declared_os(&config.tags).as_deref() == Some("windows") {
                continue;
            }
            let Some(stdout) = self.prober.probe(config, evidence.clone()).await else {
                debug!(worker = %worker_id, "orphan quarantine probe channel failed; keeping");
                continue;
            };
            if !probe_verified_dead(&stdout) {
                debug!(worker = %worker_id, "orphan process group not verified dead; keeping");
                continue;
            }
            // The operator may have replaced or removed the record while the
            // probe ran; only the exact record that was verified is cleared.
            let mut store = self.store.lock().await;
            if store
                .get(&worker_id)
                .and_then(|record| record.reason.as_deref())
                != Some(reason.as_str())
            {
                continue;
            }
            if let Err(error) = store.remove(&worker_id) {
                warn!(worker = %worker_id, "could not remove orphan quarantine record: {error}");
                continue;
            }
            drop(store);
            worker.enable().await;
            info!(
                worker = %worker_id,
                build_id = evidence.build_id,
                "cleared E104 orphan quarantine: recorded process group verified dead"
            );
            cleared += 1;
        }
        cleared
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::bypass_record::AdminDisableRecord;
    use rch_common::orphan_quarantine::quarantine_reason;
    use std::sync::atomic::{AtomicUsize, Ordering};

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
}
