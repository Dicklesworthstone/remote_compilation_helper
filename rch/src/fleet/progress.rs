//! Fleet progress tracking for parallel operations.
//!
//! Provides multi-worker progress bars that update in real-time during
//! fleet deployments and other parallel worker operations.

use crate::ui::context::OutputContext;
use crate::ui::progress::MultiProgressManager;
use indicatif::ProgressBar;
use rch_common::WorkerId;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Deployment phase for per-worker progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeployPhase {
    /// Waiting in queue.
    Queued,
    /// Connecting to worker via SSH.
    Connecting,
    /// Uploading binary.
    Uploading,
    /// Installing binary.
    Installing,
    /// Running verification.
    Verifying,
    /// Deployment complete.
    Complete,
    /// Deployment failed.
    Failed,
}

impl DeployPhase {
    /// Get percentage for this phase.
    pub fn percent(&self) -> u64 {
        match self {
            DeployPhase::Queued => 0,
            DeployPhase::Connecting => 10,
            DeployPhase::Uploading => 40,
            DeployPhase::Installing => 70,
            DeployPhase::Verifying => 90,
            DeployPhase::Complete => 100,
            DeployPhase::Failed => 0,
        }
    }

    /// Get descriptive message for this phase.
    pub fn message(&self) -> &'static str {
        match self {
            DeployPhase::Queued => "queued",
            DeployPhase::Connecting => "connecting...",
            DeployPhase::Uploading => "uploading binary...",
            DeployPhase::Installing => "installing...",
            DeployPhase::Verifying => "verifying...",
            DeployPhase::Complete => "✓ complete",
            DeployPhase::Failed => "✗ failed",
        }
    }
}

/// Per-worker progress state.
struct WorkerProgress {
    bar: ProgressBar,
    phase: DeployPhase,
}

/// Fleet-wide progress manager for parallel deployments.
///
/// Shows an overall progress bar plus per-worker progress bars:
/// ```text
/// Deploying rch-wkr to fleet (2/5 complete)
///
///   css   ████████████████████ 100% ✓ complete
///   csd   ████████████████████ 100% ✓ complete
///   cse   ████████████░░░░░░░░  60% uploading binary...
///   csf   ████░░░░░░░░░░░░░░░░  20% connecting...
///   csg   ░░░░░░░░░░░░░░░░░░░░   0% queued
/// ```
pub struct FleetProgress {
    manager: MultiProgressManager,
    workers: Arc<Mutex<HashMap<String, WorkerProgress>>>,
    overall: ProgressBar,
    visible: bool,
}

impl FleetProgress {
    /// Create a new fleet progress tracker for the given workers.
    pub fn new(ctx: &OutputContext, worker_ids: &[WorkerId]) -> Self {
        let manager = MultiProgressManager::new(ctx);
        let visible = manager.is_visible();

        // Create overall progress bar
        let overall = manager.add_progress_bar(worker_ids.len() as u64, "Deploying");

        // Create per-worker progress bars
        let mut workers = HashMap::new();
        for id in worker_ids {
            let bar = manager.add_progress_bar(100, &id.0);
            bar.set_message(DeployPhase::Queued.message().to_string());
            workers.insert(
                id.0.clone(),
                WorkerProgress {
                    bar,
                    phase: DeployPhase::Queued,
                },
            );
        }

        Self {
            manager,
            workers: Arc::new(Mutex::new(workers)),
            overall,
            visible,
        }
    }

    /// Update a worker's deployment phase.
    pub async fn set_phase(&self, worker_id: &str, phase: DeployPhase) {
        let mut workers = self.workers.lock().await;
        if let Some(wp) = workers.get_mut(worker_id) {
            wp.phase = phase;
            wp.bar.set_position(phase.percent());
            wp.bar.set_message(phase.message().to_string());

            // Update overall progress on completion/failure
            if phase == DeployPhase::Complete || phase == DeployPhase::Failed {
                self.overall.inc(1);
            }
        }
    }

    /// Update a worker's progress within the current phase.
    ///
    /// For upload progress, use this to show detailed transfer progress.
    pub async fn set_progress(&self, worker_id: &str, percent: u64, message: &str) {
        let workers = self.workers.lock().await;
        if let Some(wp) = workers.get(worker_id) {
            wp.bar.set_position(percent);
            wp.bar.set_message(message.to_string());
        }
    }

    /// Mark a worker as successfully completed.
    pub async fn worker_complete(&self, worker_id: &str, version: &str) {
        let mut workers = self.workers.lock().await;
        if let Some(wp) = workers.get_mut(worker_id) {
            wp.phase = DeployPhase::Complete;
            wp.bar.set_position(100);
            wp.bar
                .finish_with_message(format!("✓ {} installed", version));
            self.overall.inc(1);
        }
    }

    /// Mark a worker as skipped (already at target version).
    pub async fn worker_skipped(&self, worker_id: &str, reason: &str) {
        let mut workers = self.workers.lock().await;
        if let Some(wp) = workers.get_mut(worker_id) {
            wp.phase = DeployPhase::Complete;
            wp.bar.set_position(100);
            wp.bar.finish_with_message(format!("⊘ {}", reason));
            self.overall.inc(1);
        }
    }

    /// Mark a worker as failed.
    pub async fn worker_failed(&self, worker_id: &str, error: &str) {
        let mut workers = self.workers.lock().await;
        if let Some(wp) = workers.get_mut(worker_id) {
            wp.phase = DeployPhase::Failed;
            wp.bar.abandon_with_message(format!("✗ {}", error));
            self.overall.inc(1);
        }
    }

    /// Finish all progress bars.
    pub fn finish(&self) {
        self.overall.finish();
    }

    /// Clear all progress bars.
    pub fn clear(&self) {
        self.manager.clear();
    }

    /// Check if progress is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Suspend progress display for streaming output.
    pub fn suspend<F, T>(&self, f: F) -> T
    where
        F: FnOnce() -> T,
    {
        self.manager.suspend(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::{OutputConfig, OutputContext};

    fn make_quiet_context() -> OutputContext {
        OutputContext::new(OutputConfig {
            quiet: true,
            ..Default::default()
        })
    }

    fn make_json_context() -> OutputContext {
        OutputContext::new(OutputConfig {
            json: true,
            ..Default::default()
        })
    }

    #[test]
    fn test_deploy_phase_percent() {
        assert_eq!(DeployPhase::Queued.percent(), 0);
        assert_eq!(DeployPhase::Connecting.percent(), 10);
        assert_eq!(DeployPhase::Uploading.percent(), 40);
        assert_eq!(DeployPhase::Installing.percent(), 70);
        assert_eq!(DeployPhase::Verifying.percent(), 90);
        assert_eq!(DeployPhase::Complete.percent(), 100);
    }

    #[test]
    fn test_deploy_phase_message() {
        assert_eq!(DeployPhase::Queued.message(), "queued");
        assert_eq!(DeployPhase::Connecting.message(), "connecting...");
        assert!(DeployPhase::Complete.message().contains("complete"));
    }

    #[tokio::test]
    async fn test_fleet_progress_quiet_mode() {
        let ctx = make_quiet_context();
        let ids = vec![WorkerId("w1".to_string()), WorkerId("w2".to_string())];
        let progress = FleetProgress::new(&ctx, &ids);
        assert!(!progress.is_visible());

        // Should not panic in quiet mode
        progress.set_phase("w1", DeployPhase::Connecting).await;
        progress.worker_complete("w1", "0.1.2").await;
        progress.worker_failed("w2", "connection timeout").await;
    }

    #[tokio::test]
    async fn test_fleet_progress_json_mode() {
        let ctx = make_json_context();
        let ids = vec![WorkerId("css".to_string())];
        let progress = FleetProgress::new(&ctx, &ids);
        assert!(!progress.is_visible());

        // Should not panic in JSON mode
        progress.set_phase("css", DeployPhase::Uploading).await;
        progress.worker_skipped("css", "already at version").await;
    }

    #[tokio::test]
    async fn test_fleet_progress_phase_transitions() {
        let ctx = make_quiet_context();
        let ids = vec![WorkerId("test".to_string())];
        let progress = FleetProgress::new(&ctx, &ids);

        // Simulate full deployment cycle
        progress.set_phase("test", DeployPhase::Connecting).await;
        progress.set_phase("test", DeployPhase::Uploading).await;
        progress.set_phase("test", DeployPhase::Installing).await;
        progress.set_phase("test", DeployPhase::Verifying).await;
        progress.worker_complete("test", "0.1.2").await;
        progress.finish();
    }

    #[tokio::test]
    async fn test_fleet_progress_custom_progress() {
        let ctx = make_quiet_context();
        let ids = vec![WorkerId("w1".to_string())];
        let progress = FleetProgress::new(&ctx, &ids);

        // Set custom progress within upload phase
        progress.set_progress("w1", 50, "uploading 50%...").await;
    }
}
