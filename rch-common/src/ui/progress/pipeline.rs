//! PipelineProgress - Multi-stage operation visualization.
//!
//! Renders a tree-like display of pipeline stages with:
//! - Stage-by-stage progress with checkmarks for completed stages
//! - Current stage highlighted with timing
//! - Stage timing breakdown (completed stages show duration)
//! - Overall elapsed time and ETA
//! - Error indication at failed stage with subsequent stages grayed

use crate::ui::{Icons, OutputContext, ProgressContext};
use std::time::{Duration, Instant};

/// Pipeline stages for RCH compile workflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PipelineStage {
    /// Workspace analysis (file enumeration).
    WorkspaceAnalysis,
    /// Upload to worker (rsync).
    Upload,
    /// Remote compilation (cargo).
    Compilation,
    /// Artifact retrieval (rsync download).
    ArtifactRetrieval,
    /// Cache update (optional).
    CacheUpdate,
}

impl PipelineStage {
    /// Get the display label for this stage.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::WorkspaceAnalysis => "Workspace analysis",
            Self::Upload => "Upload to worker",
            Self::Compilation => "Remote compilation",
            Self::ArtifactRetrieval => "Artifact retrieval",
            Self::CacheUpdate => "Cache update",
        }
    }

    /// Get the short label for compact display.
    #[must_use]
    pub fn short_label(self) -> &'static str {
        match self {
            Self::WorkspaceAnalysis => "Workspace",
            Self::Upload => "Upload",
            Self::Compilation => "Compile",
            Self::ArtifactRetrieval => "Download",
            Self::CacheUpdate => "Cache",
        }
    }

    /// Get all stages in order.
    #[must_use]
    pub fn all() -> &'static [PipelineStage] {
        &[
            Self::WorkspaceAnalysis,
            Self::Upload,
            Self::Compilation,
            Self::ArtifactRetrieval,
            Self::CacheUpdate,
        ]
    }

    /// Get the index of this stage (0-based).
    #[must_use]
    pub fn index(self) -> usize {
        match self {
            Self::WorkspaceAnalysis => 0,
            Self::Upload => 1,
            Self::Compilation => 2,
            Self::ArtifactRetrieval => 3,
            Self::CacheUpdate => 4,
        }
    }
}

/// Status of a pipeline stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StageStatus {
    /// Stage not yet started.
    #[default]
    Pending,
    /// Stage currently in progress.
    InProgress,
    /// Stage completed successfully.
    Completed,
    /// Stage skipped (e.g., cache hit).
    Skipped,
    /// Stage failed with error.
    Failed,
}

impl StageStatus {
    fn icon(self, ctx: OutputContext) -> &'static str {
        match self {
            Self::Pending => Icons::bullet_hollow(ctx),
            Self::InProgress => Icons::hourglass(ctx),
            Self::Completed => Icons::check(ctx),
            Self::Skipped => Icons::status_disabled(ctx),
            Self::Failed => Icons::cross(ctx),
        }
    }
}

/// Information about a single stage's execution.
#[derive(Debug, Clone)]
struct StageInfo {
    status: StageStatus,
    start_time: Option<Instant>,
    duration: Option<Duration>,
    detail: Option<String>,
    skip_reason: Option<String>,
    error_message: Option<String>,
}

impl Default for StageInfo {
    fn default() -> Self {
        Self {
            status: StageStatus::Pending,
            start_time: None,
            duration: None,
            detail: None,
            skip_reason: None,
            error_message: None,
        }
    }
}

/// Progress display for multi-stage pipeline operations.
///
/// Tracks and renders progress through the RCH compile pipeline:
/// 1. Workspace analysis (file enumeration)
/// 2. Upload to worker (rsync)
/// 3. Remote compilation (cargo)
/// 4. Artifact retrieval (rsync)
/// 5. Cache update (optional)
///
/// # Example
///
/// ```ignore
/// use rch_common::ui::{OutputContext, PipelineProgress, PipelineStage};
///
/// let ctx = OutputContext::detect();
/// let mut pipeline = PipelineProgress::new(ctx, "worker1", false);
///
/// pipeline.start_stage(PipelineStage::WorkspaceAnalysis);
/// pipeline.set_stage_detail("425 files");
/// pipeline.complete_stage();
///
/// pipeline.start_stage(PipelineStage::Upload);
/// pipeline.set_stage_detail("78.1 MB");
/// pipeline.complete_stage();
///
/// pipeline.finish();
/// ```
#[derive(Debug)]
pub struct PipelineProgress {
    ctx: OutputContext,
    worker: String,
    enabled: bool,
    progress: Option<ProgressContext>,
    start: Instant,
    stages: Vec<StageInfo>,
    current_stage: Option<PipelineStage>,
    cache_saved_time: Option<Duration>,
}

impl PipelineProgress {
    /// Create a new pipeline progress display.
    #[must_use]
    pub fn new(ctx: OutputContext, worker: impl Into<String>, quiet: bool) -> Self {
        let enabled = !quiet && !ctx.is_machine();
        let progress = if enabled && matches!(ctx, OutputContext::Interactive) {
            Some(ProgressContext::new(ctx))
        } else {
            None
        };

        let stages = PipelineStage::all()
            .iter()
            .map(|_| StageInfo::default())
            .collect();

        Self {
            ctx,
            worker: worker.into(),
            enabled,
            progress,
            start: Instant::now(),
            stages,
            current_stage: None,
            cache_saved_time: None,
        }
    }

    /// Start a new pipeline stage.
    pub fn start_stage(&mut self, stage: PipelineStage) {
        let idx = stage.index();
        if idx < self.stages.len() {
            self.stages[idx].status = StageStatus::InProgress;
            self.stages[idx].start_time = Some(Instant::now());
            self.current_stage = Some(stage);
        }
        self.render();
    }

    /// Set detail text for the current stage (e.g., "425 files", "78.1 MB").
    pub fn set_stage_detail(&mut self, detail: impl Into<String>) {
        if let Some(stage) = self.current_stage {
            let idx = stage.index();
            if idx < self.stages.len() {
                self.stages[idx].detail = Some(detail.into());
            }
        }
        self.render();
    }

    /// Update the current stage detail (rate-limited render).
    pub fn update_detail(&mut self, detail: impl Into<String>) {
        if let Some(stage) = self.current_stage {
            let idx = stage.index();
            if idx < self.stages.len() {
                self.stages[idx].detail = Some(detail.into());
            }
        }
        self.render();
    }

    /// Complete the current stage successfully.
    pub fn complete_stage(&mut self) {
        if let Some(stage) = self.current_stage.take() {
            let idx = stage.index();
            if idx < self.stages.len() {
                let info = &mut self.stages[idx];
                info.status = StageStatus::Completed;
                info.duration = info.start_time.map(|start| start.elapsed());
            }
        }
        self.render();
    }

    /// Skip a stage with a reason.
    pub fn skip_stage(&mut self, stage: PipelineStage, reason: impl Into<String>) {
        let idx = stage.index();
        if idx < self.stages.len() {
            self.stages[idx].status = StageStatus::Skipped;
            self.stages[idx].skip_reason = Some(reason.into());
        }
        // Clear current if it matches
        if self.current_stage == Some(stage) {
            self.current_stage = None;
        }
        self.render();
    }

    /// Mark the current stage as failed.
    pub fn fail_stage(&mut self, error: impl Into<String>) {
        if let Some(stage) = self.current_stage.take() {
            let idx = stage.index();
            if idx < self.stages.len() {
                let info = &mut self.stages[idx];
                info.status = StageStatus::Failed;
                info.duration = info.start_time.map(|start| start.elapsed());
                info.error_message = Some(error.into());
            }
        }
        self.render();
    }

    /// Set time saved due to cache hit.
    pub fn set_cache_saved_time(&mut self, saved: Duration) {
        self.cache_saved_time = Some(saved);
    }

    /// Get the total elapsed time.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    /// Check if any stage has failed.
    #[must_use]
    pub fn has_failed(&self) -> bool {
        self.stages.iter().any(|s| s.status == StageStatus::Failed)
    }

    /// Get the current stage if any.
    #[must_use]
    pub fn current_stage(&self) -> Option<PipelineStage> {
        self.current_stage
    }

    /// Calculate estimated time remaining based on completed stages.
    fn estimate_remaining(&self) -> Option<Duration> {
        // Simple estimation: average completed stage time * remaining stages
        let completed: Vec<Duration> = self
            .stages
            .iter()
            .filter_map(|s| {
                if s.status == StageStatus::Completed {
                    s.duration
                } else {
                    None
                }
            })
            .collect();

        if completed.is_empty() {
            return None;
        }

        let avg_duration: Duration = completed.iter().sum::<Duration>() / completed.len() as u32;

        let remaining_count = self
            .stages
            .iter()
            .filter(|s| matches!(s.status, StageStatus::Pending | StageStatus::InProgress))
            .count();

        if remaining_count == 0 {
            return None;
        }

        Some(avg_duration * remaining_count as u32)
    }

    /// Render the pipeline progress display.
    fn render(&mut self) {
        if !self.enabled {
            return;
        }

        let elapsed = format_duration(self.start.elapsed());
        let eta = self
            .estimate_remaining()
            .map(|d| format!("~{}", format_duration(d)))
            .unwrap_or_else(|| "--".to_string());

        // Build compact single-line display (for future multi-line rendering)
        let _stages_display: Vec<String> = PipelineStage::all()
            .iter()
            .map(|stage| {
                let idx = stage.index();
                let info = &self.stages[idx];
                let icon = info.status.icon(self.ctx);
                let label = stage.short_label();

                match info.status {
                    StageStatus::Completed => {
                        let dur = info
                            .duration
                            .map(format_duration)
                            .unwrap_or_else(|| "-".to_string());
                        let detail = info
                            .detail
                            .as_ref()
                            .map(|d| format!(" ({d})"))
                            .unwrap_or_default();
                        format!("{icon} {label} {dur}{detail}")
                    }
                    StageStatus::InProgress => {
                        let dur = info
                            .start_time
                            .map(|s| format_duration(s.elapsed()))
                            .unwrap_or_else(|| "-".to_string());
                        let detail = info
                            .detail
                            .as_ref()
                            .map(|d| format!(" ({d})"))
                            .unwrap_or_default();
                        format!("{icon} {label} {dur}{detail}")
                    }
                    StageStatus::Skipped => {
                        let reason = info
                            .skip_reason
                            .as_ref()
                            .map(|r| format!(" ({r})"))
                            .unwrap_or_default();
                        format!("{icon} {label}{reason}")
                    }
                    StageStatus::Failed => {
                        let dur = info
                            .duration
                            .map(format_duration)
                            .unwrap_or_else(|| "-".to_string());
                        format!("{icon} {label} {dur} FAILED")
                    }
                    StageStatus::Pending => {
                        format!("{icon} {label}")
                    }
                }
            })
            .collect();

        let line = format!(
            "Pipeline [{}/{}] {} | {} | ETA {}",
            self.count_completed(),
            PipelineStage::all().len(),
            self.worker,
            elapsed,
            eta
        );

        if let Some(progress) = &mut self.progress {
            progress.render(&line);
        }
    }

    fn count_completed(&self) -> usize {
        self.stages
            .iter()
            .filter(|s| matches!(s.status, StageStatus::Completed | StageStatus::Skipped))
            .count()
    }

    /// Clear progress display.
    pub fn clear(&self) {
        if let Some(progress) = &self.progress {
            progress.clear();
        }
    }

    /// Finish the pipeline and print summary.
    pub fn finish(&mut self) {
        self.clear();

        if !self.enabled {
            return;
        }

        let duration = self.start.elapsed();
        let icon = if self.has_failed() {
            Icons::cross(self.ctx)
        } else {
            Icons::check(self.ctx)
        };

        let status = if self.has_failed() {
            "failed"
        } else {
            "completed"
        };
        let elapsed = format_duration(duration);

        // Build summary line
        let mut summary = format!("{icon} Pipeline {status} on {} in {elapsed}", self.worker);

        // Add cache savings if applicable
        if let Some(saved) = self.cache_saved_time {
            let saved_str = format_duration(saved);
            summary.push_str(&format!(" (cache saved ~{saved_str})"));
        }

        eprintln!("{summary}");

        // Print stage breakdown if verbose
        for stage in PipelineStage::all() {
            let idx = stage.index();
            let info = &self.stages[idx];
            let icon = info.status.icon(self.ctx);
            let label = stage.label();

            match info.status {
                StageStatus::Completed => {
                    let dur = info
                        .duration
                        .map(format_duration)
                        .unwrap_or_else(|| "-".to_string());
                    let detail = info
                        .detail
                        .as_ref()
                        .map(|d| format!("  ({d})"))
                        .unwrap_or_default();
                    eprintln!("   {icon} {label:<22} {dur:>8}{detail}");
                }
                StageStatus::Skipped => {
                    let reason = info
                        .skip_reason
                        .as_ref()
                        .map(|r| format!("  ({r})"))
                        .unwrap_or_default();
                    eprintln!("   {icon} {label:<22} skipped{reason}");
                }
                StageStatus::Failed => {
                    let dur = info
                        .duration
                        .map(format_duration)
                        .unwrap_or_else(|| "-".to_string());
                    let error = info
                        .error_message
                        .as_ref()
                        .map(|e| format!("  ({e})"))
                        .unwrap_or_default();
                    eprintln!("   {icon} {label:<22} {dur:>8} FAILED{error}");
                }
                _ => {}
            }
        }
    }

    /// Finish with error summary.
    pub fn finish_error(&mut self, error: &str) {
        self.clear();

        if !self.enabled {
            return;
        }

        let icon = Icons::cross(self.ctx);
        let elapsed = format_duration(self.start.elapsed());

        eprintln!(
            "{icon} Pipeline failed on {} after {elapsed}: {error}",
            self.worker
        );

        // Show completed stages for debugging
        for stage in PipelineStage::all() {
            let idx = stage.index();
            let info = &self.stages[idx];
            if info.status == StageStatus::Completed || info.status == StageStatus::Failed {
                let stage_icon = info.status.icon(self.ctx);
                let label = stage.label();
                let dur = info
                    .duration
                    .map(format_duration)
                    .unwrap_or_else(|| "-".to_string());
                eprintln!("   {stage_icon} {label:<22} {dur:>8}");
            }
        }
    }
}

fn format_duration(duration: Duration) -> String {
    let total_secs = duration.as_secs();
    if total_secs == 0 {
        let ms = duration.as_millis();
        if ms < 100 {
            return format!("{ms}ms");
        }
        return format!("{:.1}s", duration.as_secs_f64());
    }
    if total_secs < 60 {
        format!("{:.1}s", duration.as_secs_f64())
    } else if total_secs < 3600 {
        let mins = total_secs / 60;
        let secs = total_secs % 60;
        format!("{mins}:{secs:02}")
    } else {
        let hours = total_secs / 3600;
        let mins = (total_secs % 3600) / 60;
        let secs = total_secs % 60;
        format!("{hours}:{mins:02}:{secs:02}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipeline_stage_ordering() {
        let stages = PipelineStage::all();
        assert_eq!(stages.len(), 5);
        assert_eq!(stages[0], PipelineStage::WorkspaceAnalysis);
        assert_eq!(stages[4], PipelineStage::CacheUpdate);
    }

    #[test]
    fn pipeline_stage_indices() {
        assert_eq!(PipelineStage::WorkspaceAnalysis.index(), 0);
        assert_eq!(PipelineStage::Upload.index(), 1);
        assert_eq!(PipelineStage::Compilation.index(), 2);
        assert_eq!(PipelineStage::ArtifactRetrieval.index(), 3);
        assert_eq!(PipelineStage::CacheUpdate.index(), 4);
    }

    #[test]
    fn stage_status_icons_ascii() {
        let ctx = OutputContext::Plain;
        assert_eq!(StageStatus::Pending.icon(ctx), "o");
        assert_eq!(StageStatus::Completed.icon(ctx), "[OK]");
        assert_eq!(StageStatus::Failed.icon(ctx), "[FAIL]");
    }

    #[test]
    fn pipeline_progress_stages() {
        let ctx = OutputContext::Plain;
        let mut pipeline = PipelineProgress::new(ctx, "test-worker", true);

        assert!(pipeline.current_stage().is_none());
        assert!(!pipeline.has_failed());

        pipeline.start_stage(PipelineStage::WorkspaceAnalysis);
        assert_eq!(
            pipeline.current_stage(),
            Some(PipelineStage::WorkspaceAnalysis)
        );

        pipeline.set_stage_detail("100 files");
        pipeline.complete_stage();
        assert!(pipeline.current_stage().is_none());

        assert_eq!(pipeline.count_completed(), 1);
    }

    #[test]
    fn pipeline_skip_stage() {
        let ctx = OutputContext::Plain;
        let mut pipeline = PipelineProgress::new(ctx, "worker", true);

        pipeline.skip_stage(PipelineStage::Upload, "cache hit");
        assert_eq!(pipeline.stages[1].status, StageStatus::Skipped);
        assert_eq!(pipeline.stages[1].skip_reason.as_deref(), Some("cache hit"));
    }

    #[test]
    fn pipeline_fail_stage() {
        let ctx = OutputContext::Plain;
        let mut pipeline = PipelineProgress::new(ctx, "worker", true);

        pipeline.start_stage(PipelineStage::Compilation);
        pipeline.fail_stage("build error");

        assert!(pipeline.has_failed());
        assert_eq!(pipeline.stages[2].status, StageStatus::Failed);
        assert_eq!(
            pipeline.stages[2].error_message.as_deref(),
            Some("build error")
        );
    }

    #[test]
    fn format_duration_milliseconds() {
        assert_eq!(format_duration(Duration::from_millis(50)), "50ms");
        assert_eq!(format_duration(Duration::from_millis(250)), "0.2s");
    }

    #[test]
    fn format_duration_seconds() {
        assert_eq!(format_duration(Duration::from_secs(5)), "5.0s");
        assert_eq!(format_duration(Duration::from_secs(45)), "45.0s");
    }

    #[test]
    fn format_duration_minutes() {
        assert_eq!(format_duration(Duration::from_secs(90)), "1:30");
        assert_eq!(format_duration(Duration::from_secs(605)), "10:05");
    }

    #[test]
    fn format_duration_hours() {
        assert_eq!(format_duration(Duration::from_secs(3665)), "1:01:05");
    }

    #[test]
    fn estimate_remaining_no_completed() {
        let ctx = OutputContext::Plain;
        let pipeline = PipelineProgress::new(ctx, "worker", true);
        assert!(pipeline.estimate_remaining().is_none());
    }

    #[test]
    fn count_completed_with_skipped() {
        let ctx = OutputContext::Plain;
        let mut pipeline = PipelineProgress::new(ctx, "worker", true);

        pipeline.start_stage(PipelineStage::WorkspaceAnalysis);
        pipeline.complete_stage();
        pipeline.skip_stage(PipelineStage::Upload, "cache hit");

        assert_eq!(pipeline.count_completed(), 2);
    }

    // -------------------------------------------------------------------------
    // PipelineStage label tests
    // -------------------------------------------------------------------------

    #[test]
    fn pipeline_stage_labels() {
        assert_eq!(
            PipelineStage::WorkspaceAnalysis.label(),
            "Workspace analysis"
        );
        assert_eq!(PipelineStage::Upload.label(), "Upload to worker");
        assert_eq!(PipelineStage::Compilation.label(), "Remote compilation");
        assert_eq!(
            PipelineStage::ArtifactRetrieval.label(),
            "Artifact retrieval"
        );
        assert_eq!(PipelineStage::CacheUpdate.label(), "Cache update");
    }

    #[test]
    fn pipeline_stage_short_labels() {
        assert_eq!(PipelineStage::WorkspaceAnalysis.short_label(), "Workspace");
        assert_eq!(PipelineStage::Upload.short_label(), "Upload");
        assert_eq!(PipelineStage::Compilation.short_label(), "Compile");
        assert_eq!(PipelineStage::ArtifactRetrieval.short_label(), "Download");
        assert_eq!(PipelineStage::CacheUpdate.short_label(), "Cache");
    }

    #[test]
    fn stage_status_in_progress_icon() {
        let ctx = OutputContext::Plain;
        assert_eq!(StageStatus::InProgress.icon(ctx), "[...]");
    }

    #[test]
    fn stage_status_skipped_icon() {
        let ctx = OutputContext::Plain;
        assert_eq!(StageStatus::Skipped.icon(ctx), "[x]");
    }

    #[test]
    fn stage_status_default() {
        assert_eq!(StageStatus::default(), StageStatus::Pending);
    }

    #[test]
    fn pipeline_progress_worker_info() {
        let ctx = OutputContext::Plain;
        let pipeline = PipelineProgress::new(ctx, "my-worker", false);
        assert_eq!(pipeline.worker, "my-worker");
        // enabled=true when quiet=false and not machine context
        assert!(pipeline.enabled);
    }

    #[test]
    fn pipeline_progress_quiet_mode() {
        let ctx = OutputContext::Plain;
        let pipeline = PipelineProgress::new(ctx, "worker", true);
        // enabled=false when quiet=true
        assert!(!pipeline.enabled);
    }

    #[test]
    fn format_duration_zero() {
        assert_eq!(format_duration(Duration::ZERO), "0ms");
    }

    #[test]
    fn format_duration_exact_minute() {
        assert_eq!(format_duration(Duration::from_secs(60)), "1:00");
    }

    #[test]
    fn format_duration_exact_hour() {
        assert_eq!(format_duration(Duration::from_secs(3600)), "1:00:00");
    }
}
