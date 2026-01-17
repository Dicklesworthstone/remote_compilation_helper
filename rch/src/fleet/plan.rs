//! Deployment planning and data structures.

use chrono::{DateTime, Utc};
use rch_common::WorkerConfig;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A complete deployment plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentPlan {
    /// Unique identifier for this deployment.
    pub id: Uuid,
    /// When the plan was created.
    pub created_at: DateTime<Utc>,
    /// Target version to deploy.
    pub target_version: String,
    /// Workers to deploy to.
    pub workers: Vec<WorkerDeployment>,
    /// Deployment strategy.
    pub strategy: DeploymentStrategy,
    /// Deployment options.
    pub options: DeployOptions,
}

impl DeploymentPlan {
    /// Create a new deployment plan.
    pub fn new(
        workers: &[&WorkerConfig],
        strategy: DeploymentStrategy,
        options: DeployOptions,
    ) -> anyhow::Result<Self> {
        let target_version = options
            .target_version
            .clone()
            .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());

        let worker_deployments = workers
            .iter()
            .map(|w| WorkerDeployment::new(&w.id.0, &target_version))
            .collect();

        Ok(Self {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            target_version,
            workers: worker_deployments,
            strategy,
            options,
        })
    }
}

/// Deployment strategy determining rollout behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeploymentStrategy {
    /// Deploy to all workers at once with parallelism limit.
    AllAtOnce { parallelism: usize },
    /// Canary deployment - deploy to subset first, then all.
    Canary {
        /// Percentage of workers for initial canary.
        percent: u8,
        /// Seconds to wait after canary before full rollout.
        wait_secs: u64,
        /// Automatically promote after successful canary.
        auto_promote: bool,
    },
    /// Rolling deployment - deploy in batches.
    Rolling {
        /// Number of workers per batch.
        batch_size: usize,
        /// Seconds to wait between batches.
        wait_between: u64,
    },
}

/// Options controlling deployment behavior.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeployOptions {
    /// Force deployment even if version matches.
    pub force: bool,
    /// Run verification after deployment.
    pub verify: bool,
    /// Drain active builds before deployment.
    pub drain_first: bool,
    /// Timeout for draining in seconds.
    pub drain_timeout: u64,
    /// Skip toolchain synchronization.
    pub no_toolchain: bool,
    /// Resume from previous failed deployment.
    pub resume: bool,
    /// Target version to deploy (None = current local).
    pub target_version: Option<String>,
}

/// Deployment state for a single worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerDeployment {
    /// Worker identifier.
    pub worker_id: String,
    /// Current installed version (if known).
    pub current_version: Option<String>,
    /// Target version to deploy.
    pub target_version: String,
    /// Current deployment status.
    pub status: DeploymentStatus,
    /// Deployment steps with their status.
    pub steps: Vec<DeployStep>,
    /// When deployment started.
    pub started_at: Option<DateTime<Utc>>,
    /// When deployment completed.
    pub completed_at: Option<DateTime<Utc>>,
    /// Error message if failed.
    pub error: Option<String>,
}

impl WorkerDeployment {
    /// Create a new worker deployment entry.
    pub fn new(worker_id: &str, target_version: &str) -> Self {
        Self {
            worker_id: worker_id.to_string(),
            current_version: None,
            target_version: target_version.to_string(),
            status: DeploymentStatus::Pending,
            steps: vec![
                DeployStep::new("preflight"),
                DeployStep::new("transfer"),
                DeployStep::new("install"),
                DeployStep::new("verify"),
            ],
            started_at: None,
            completed_at: None,
            error: None,
        }
    }

    /// Check if this deployment can transition to the given status.
    pub fn can_transition_to(&self, status: DeploymentStatus) -> bool {
        use DeploymentStatus::*;
        matches!(
            (&self.status, status),
            (Pending, Preflight)
                | (Preflight, Draining)
                | (Preflight, Transferring)
                | (Draining, Transferring)
                | (Transferring, Installing)
                | (Installing, Verifying)
                | (Verifying, Completed)
                | (_, Failed)
                | (_, Skipped)
                | (_, RolledBack)
        )
    }
}

/// Status of a worker deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeploymentStatus {
    /// Not yet started.
    Pending,
    /// Running preflight checks.
    Preflight,
    /// Draining active builds.
    Draining,
    /// Transferring binaries.
    Transferring,
    /// Installing binaries.
    Installing,
    /// Running verification.
    Verifying,
    /// Successfully completed.
    Completed,
    /// Failed with error.
    Failed,
    /// Skipped (already at target version).
    Skipped,
    /// Rolled back after failure.
    RolledBack,
}

/// A single step in the deployment process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployStep {
    /// Step name.
    pub name: String,
    /// Step status.
    pub status: StepStatus,
    /// When step started.
    pub started_at: Option<DateTime<Utc>>,
    /// When step completed.
    pub completed_at: Option<DateTime<Utc>>,
    /// Step output or error message.
    pub output: Option<String>,
}

impl DeployStep {
    /// Create a new deployment step.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            status: StepStatus::Pending,
            started_at: None,
            completed_at: None,
            output: None,
        }
    }

    /// Mark step as in progress.
    pub fn start(&mut self) {
        self.status = StepStatus::InProgress;
        self.started_at = Some(Utc::now());
    }

    /// Mark step as completed.
    pub fn complete(&mut self, output: Option<String>) {
        self.status = StepStatus::Completed;
        self.completed_at = Some(Utc::now());
        self.output = output;
    }

    /// Mark step as failed.
    pub fn fail(&mut self, error: String) {
        self.status = StepStatus::Failed;
        self.completed_at = Some(Utc::now());
        self.output = Some(error);
    }
}

/// Status of a deployment step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepStatus {
    /// Not yet started.
    Pending,
    /// Currently running.
    InProgress,
    /// Successfully completed.
    Completed,
    /// Failed with error.
    Failed,
    /// Skipped.
    Skipped,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================
    // DeployStep tests
    // ========================

    #[test]
    fn deploy_step_new_creates_pending_step() {
        let step = DeployStep::new("preflight");
        assert_eq!(step.name, "preflight");
        assert_eq!(step.status, StepStatus::Pending);
        assert!(step.started_at.is_none());
        assert!(step.completed_at.is_none());
        assert!(step.output.is_none());
    }

    #[test]
    fn deploy_step_start_sets_in_progress_and_timestamp() {
        let mut step = DeployStep::new("transfer");
        step.start();
        assert_eq!(step.status, StepStatus::InProgress);
        assert!(step.started_at.is_some());
        assert!(step.completed_at.is_none());
    }

    #[test]
    fn deploy_step_complete_sets_completed_and_timestamps() {
        let mut step = DeployStep::new("install");
        step.start();
        step.complete(Some("Installed successfully".to_string()));
        assert_eq!(step.status, StepStatus::Completed);
        assert!(step.started_at.is_some());
        assert!(step.completed_at.is_some());
        assert_eq!(step.output, Some("Installed successfully".to_string()));
    }

    #[test]
    fn deploy_step_complete_without_output() {
        let mut step = DeployStep::new("verify");
        step.start();
        step.complete(None);
        assert_eq!(step.status, StepStatus::Completed);
        assert!(step.output.is_none());
    }

    #[test]
    fn deploy_step_fail_sets_failed_and_error_message() {
        let mut step = DeployStep::new("transfer");
        step.start();
        step.fail("Connection refused".to_string());
        assert_eq!(step.status, StepStatus::Failed);
        assert!(step.completed_at.is_some());
        assert_eq!(step.output, Some("Connection refused".to_string()));
    }

    // ========================
    // WorkerDeployment tests
    // ========================

    #[test]
    fn worker_deployment_new_creates_pending_deployment() {
        let wd = WorkerDeployment::new("worker-1", "1.0.0");
        assert_eq!(wd.worker_id, "worker-1");
        assert!(wd.current_version.is_none());
        assert_eq!(wd.target_version, "1.0.0");
        assert_eq!(wd.status, DeploymentStatus::Pending);
        assert_eq!(wd.steps.len(), 4);
        assert!(wd.started_at.is_none());
        assert!(wd.completed_at.is_none());
        assert!(wd.error.is_none());
    }

    #[test]
    fn worker_deployment_new_creates_correct_steps() {
        let wd = WorkerDeployment::new("w1", "2.0.0");
        assert_eq!(wd.steps[0].name, "preflight");
        assert_eq!(wd.steps[1].name, "transfer");
        assert_eq!(wd.steps[2].name, "install");
        assert_eq!(wd.steps[3].name, "verify");
        for step in &wd.steps {
            assert_eq!(step.status, StepStatus::Pending);
        }
    }

    #[test]
    fn worker_deployment_can_transition_pending_to_preflight() {
        let wd = WorkerDeployment::new("w1", "1.0.0");
        assert!(wd.can_transition_to(DeploymentStatus::Preflight));
    }

    #[test]
    fn worker_deployment_can_transition_preflight_to_draining() {
        let mut wd = WorkerDeployment::new("w1", "1.0.0");
        wd.status = DeploymentStatus::Preflight;
        assert!(wd.can_transition_to(DeploymentStatus::Draining));
    }

    #[test]
    fn worker_deployment_can_transition_preflight_to_transferring() {
        let mut wd = WorkerDeployment::new("w1", "1.0.0");
        wd.status = DeploymentStatus::Preflight;
        assert!(wd.can_transition_to(DeploymentStatus::Transferring));
    }

    #[test]
    fn worker_deployment_can_transition_draining_to_transferring() {
        let mut wd = WorkerDeployment::new("w1", "1.0.0");
        wd.status = DeploymentStatus::Draining;
        assert!(wd.can_transition_to(DeploymentStatus::Transferring));
    }

    #[test]
    fn worker_deployment_can_transition_transferring_to_installing() {
        let mut wd = WorkerDeployment::new("w1", "1.0.0");
        wd.status = DeploymentStatus::Transferring;
        assert!(wd.can_transition_to(DeploymentStatus::Installing));
    }

    #[test]
    fn worker_deployment_can_transition_installing_to_verifying() {
        let mut wd = WorkerDeployment::new("w1", "1.0.0");
        wd.status = DeploymentStatus::Installing;
        assert!(wd.can_transition_to(DeploymentStatus::Verifying));
    }

    #[test]
    fn worker_deployment_can_transition_verifying_to_completed() {
        let mut wd = WorkerDeployment::new("w1", "1.0.0");
        wd.status = DeploymentStatus::Verifying;
        assert!(wd.can_transition_to(DeploymentStatus::Completed));
    }

    #[test]
    fn worker_deployment_can_transition_any_to_failed() {
        for status in [
            DeploymentStatus::Pending,
            DeploymentStatus::Preflight,
            DeploymentStatus::Draining,
            DeploymentStatus::Transferring,
            DeploymentStatus::Installing,
            DeploymentStatus::Verifying,
        ] {
            let mut wd = WorkerDeployment::new("w1", "1.0.0");
            wd.status = status;
            assert!(wd.can_transition_to(DeploymentStatus::Failed));
        }
    }

    #[test]
    fn worker_deployment_can_transition_any_to_skipped() {
        let mut wd = WorkerDeployment::new("w1", "1.0.0");
        wd.status = DeploymentStatus::Pending;
        assert!(wd.can_transition_to(DeploymentStatus::Skipped));
    }

    #[test]
    fn worker_deployment_can_transition_any_to_rolledback() {
        let mut wd = WorkerDeployment::new("w1", "1.0.0");
        wd.status = DeploymentStatus::Installing;
        assert!(wd.can_transition_to(DeploymentStatus::RolledBack));
    }

    #[test]
    fn worker_deployment_cannot_transition_pending_to_transferring() {
        let wd = WorkerDeployment::new("w1", "1.0.0");
        assert!(!wd.can_transition_to(DeploymentStatus::Transferring));
    }

    #[test]
    fn worker_deployment_cannot_transition_pending_to_completed() {
        let wd = WorkerDeployment::new("w1", "1.0.0");
        assert!(!wd.can_transition_to(DeploymentStatus::Completed));
    }

    // ========================
    // DeployOptions tests
    // ========================

    #[test]
    fn deploy_options_default_all_false() {
        let opts = DeployOptions::default();
        assert!(!opts.force);
        assert!(!opts.verify);
        assert!(!opts.drain_first);
        assert_eq!(opts.drain_timeout, 0);
        assert!(!opts.no_toolchain);
        assert!(!opts.resume);
        assert!(opts.target_version.is_none());
    }

    // ========================
    // DeploymentStrategy serialization tests
    // ========================

    #[test]
    fn deployment_strategy_all_at_once_serializes() {
        let strategy = DeploymentStrategy::AllAtOnce { parallelism: 4 };
        let json = serde_json::to_string(&strategy).unwrap();
        assert!(json.contains("AllAtOnce"));
        assert!(json.contains("4"));
    }

    #[test]
    fn deployment_strategy_canary_serializes() {
        let strategy = DeploymentStrategy::Canary {
            percent: 10,
            wait_secs: 60,
            auto_promote: true,
        };
        let json = serde_json::to_string(&strategy).unwrap();
        assert!(json.contains("Canary"));
        assert!(json.contains("10"));
        assert!(json.contains("60"));
        assert!(json.contains("true"));
    }

    #[test]
    fn deployment_strategy_rolling_serializes() {
        let strategy = DeploymentStrategy::Rolling {
            batch_size: 2,
            wait_between: 30,
        };
        let json = serde_json::to_string(&strategy).unwrap();
        assert!(json.contains("Rolling"));
        assert!(json.contains("2"));
        assert!(json.contains("30"));
    }

    #[test]
    fn deployment_strategy_deserializes_roundtrip() {
        let strategy = DeploymentStrategy::Canary {
            percent: 25,
            wait_secs: 120,
            auto_promote: false,
        };
        let json = serde_json::to_string(&strategy).unwrap();
        let restored: DeploymentStrategy = serde_json::from_str(&json).unwrap();
        match restored {
            DeploymentStrategy::Canary {
                percent,
                wait_secs,
                auto_promote,
            } => {
                assert_eq!(percent, 25);
                assert_eq!(wait_secs, 120);
                assert!(!auto_promote);
            }
            _ => panic!("Expected Canary strategy"),
        }
    }

    // ========================
    // DeploymentStatus tests
    // ========================

    #[test]
    fn deployment_status_variants_are_distinct() {
        let statuses = [
            DeploymentStatus::Pending,
            DeploymentStatus::Preflight,
            DeploymentStatus::Draining,
            DeploymentStatus::Transferring,
            DeploymentStatus::Installing,
            DeploymentStatus::Verifying,
            DeploymentStatus::Completed,
            DeploymentStatus::Failed,
            DeploymentStatus::Skipped,
            DeploymentStatus::RolledBack,
        ];
        for (i, s1) in statuses.iter().enumerate() {
            for (j, s2) in statuses.iter().enumerate() {
                if i == j {
                    assert_eq!(s1, s2);
                } else {
                    assert_ne!(s1, s2);
                }
            }
        }
    }

    #[test]
    fn deployment_status_serializes() {
        let status = DeploymentStatus::Completed;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"Completed\"");
    }

    // ========================
    // StepStatus tests
    // ========================

    #[test]
    fn step_status_variants_are_distinct() {
        let statuses = [
            StepStatus::Pending,
            StepStatus::InProgress,
            StepStatus::Completed,
            StepStatus::Failed,
            StepStatus::Skipped,
        ];
        for (i, s1) in statuses.iter().enumerate() {
            for (j, s2) in statuses.iter().enumerate() {
                if i == j {
                    assert_eq!(s1, s2);
                } else {
                    assert_ne!(s1, s2);
                }
            }
        }
    }

    #[test]
    fn step_status_serializes() {
        let status = StepStatus::InProgress;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"InProgress\"");
    }

    // ========================
    // WorkerDeployment serialization tests
    // ========================

    #[test]
    fn worker_deployment_serializes_roundtrip() {
        let wd = WorkerDeployment::new("worker-test", "3.0.0");
        let json = serde_json::to_string(&wd).unwrap();
        let restored: WorkerDeployment = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.worker_id, "worker-test");
        assert_eq!(restored.target_version, "3.0.0");
        assert_eq!(restored.status, DeploymentStatus::Pending);
    }

    // ========================
    // DeployOptions serialization tests
    // ========================

    #[test]
    fn deploy_options_serializes_roundtrip() {
        let opts = DeployOptions {
            force: true,
            verify: true,
            drain_first: false,
            drain_timeout: 30,
            no_toolchain: true,
            resume: false,
            target_version: Some("2.0.0".to_string()),
        };
        let json = serde_json::to_string(&opts).unwrap();
        let restored: DeployOptions = serde_json::from_str(&json).unwrap();
        assert!(restored.force);
        assert!(restored.verify);
        assert!(!restored.drain_first);
        assert_eq!(restored.drain_timeout, 30);
        assert!(restored.no_toolchain);
        assert!(!restored.resume);
        assert_eq!(restored.target_version, Some("2.0.0".to_string()));
    }

    // ========================
    // DeployStep serialization tests
    // ========================

    #[test]
    fn deploy_step_serializes_roundtrip() {
        let mut step = DeployStep::new("test-step");
        step.start();
        step.complete(Some("Done!".to_string()));

        let json = serde_json::to_string(&step).unwrap();
        let restored: DeployStep = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.name, "test-step");
        assert_eq!(restored.status, StepStatus::Completed);
        assert!(restored.started_at.is_some());
        assert!(restored.completed_at.is_some());
        assert_eq!(restored.output, Some("Done!".to_string()));
    }
}
