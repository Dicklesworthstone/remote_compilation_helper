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
