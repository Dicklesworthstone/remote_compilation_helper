//! JobLifecycleLog - structured job event display for `rchd`.
//!
//! This module focuses on *human-readable* job lifecycle lines written to stderr
//! (operators watching the daemon in a terminal), while structured tracing logs
//! remain unchanged for log aggregation.
//!
//! Bead: bd-3ndq

#![forbid(unsafe_code)]
#![allow(dead_code)]

use rch_common::ui::{Icons, OutputContext, RateLimiter};
use std::collections::HashMap;
use std::time::Duration;

const ANSI_RESET: &str = "\x1b[0m";
const ANSI_BLUE: &str = "\x1b[34m";
const ANSI_YELLOW: &str = "\x1b[33m";
const ANSI_GREEN: &str = "\x1b[32m";
const ANSI_RED: &str = "\x1b[31m";

/// Rendering mode for job lifecycle output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobLifecycleMode {
    /// Single-line compact output (default).
    Compact,
    /// Multi-line output with additional details.
    Detailed,
}

/// High-level job phase used for progress lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobPhase {
    /// Source upload / rsync up.
    TransferUp,
    /// Compilation/build phase.
    Build,
    /// Artifact download / rsync down.
    TransferDown,
    /// Other/unknown phase.
    Other,
}

impl JobPhase {
    fn label(self) -> &'static str {
        match self {
            Self::TransferUp => "SYNC",
            Self::Build => "BUILD",
            Self::TransferDown => "PULL",
            Self::Other => "PROG",
        }
    }
}

/// Job lifecycle events consumed by [`JobLifecycleLog`].
#[derive(Debug, Clone)]
pub enum JobEvent {
    /// Job submission/dispatch.
    Start(JobStart),
    /// Job progress update.
    Progress(JobProgress),
    /// Job completed successfully.
    Done(JobDone),
    /// Job failed.
    Fail(JobFail),
}

#[derive(Debug, Clone)]
pub struct JobStart {
    pub job_id: String,
    pub source: Option<String>,
    pub command_summary: String,
    pub worker_id: String,
}

#[derive(Debug, Clone)]
pub struct JobProgress {
    pub job_id: String,
    pub phase: JobPhase,
    pub elapsed: Duration,
    pub message: String,
    pub resource_usage: Option<String>,
}

#[derive(Debug, Clone)]
pub struct JobDone {
    pub job_id: String,
    pub elapsed: Duration,
    pub artifacts: Option<u32>,
    pub note: Option<String>,
}

#[derive(Debug, Clone)]
pub struct JobFail {
    pub job_id: String,
    pub elapsed: Duration,
    pub error_type: Option<String>,
    pub worker_state: Option<String>,
    pub remediation: Option<String>,
}

/// Formatter that renders job lifecycle events into log lines.
///
/// The caller owns writing to stderr; this type only produces strings so it can
/// be unit tested deterministically.
pub struct JobLifecycleLog {
    ctx: OutputContext,
    mode: JobLifecycleMode,
    // Per-job limiter to avoid log spam for progress updates (max 1/s per job).
    progress_limiters: HashMap<String, RateLimiter>,
}

impl JobLifecycleLog {
    /// Create a new logger using the detected output context.
    #[must_use]
    pub fn new() -> Self {
        Self::with_context(OutputContext::detect())
    }

    /// Create a logger with explicit context (useful for tests).
    #[must_use]
    pub fn with_context(ctx: OutputContext) -> Self {
        Self {
            ctx,
            mode: JobLifecycleMode::Compact,
            progress_limiters: HashMap::new(),
        }
    }

    /// Set the rendering mode.
    #[must_use]
    pub fn with_mode(mut self, mode: JobLifecycleMode) -> Self {
        self.mode = mode;
        self
    }

    /// Render an event into one or more lines.
    ///
    /// Returns `None` when the event is intentionally suppressed (rate limited).
    pub fn render(&mut self, event: JobEvent) -> Option<Vec<String>> {
        match event {
            JobEvent::Start(ev) => Some(self.render_start(&ev)),
            JobEvent::Progress(ev) => self.render_progress(&ev),
            JobEvent::Done(ev) => Some(self.render_done(&ev)),
            JobEvent::Fail(ev) => Some(self.render_fail(&ev)),
        }
    }

    fn render_start(&self, ev: &JobStart) -> Vec<String> {
        let ctx = self.ctx;
        let icon = Icons::status_healthy(ctx);
        let status = self.colorize_segment(JobEventKind::Start, &format!("{icon} START"));
        let arrow = Icons::arrow_right(ctx);

        let line = format!(
            "{} {} {} {arrow} {}",
            prefix_now(&ev.job_id),
            status,
            pad_command(&ev.command_summary),
            ev.worker_id
        );

        // Keep START lines short; detailed mode adds a second line with source.
        let mut lines = vec![line];
        if self.mode == JobLifecycleMode::Detailed
            && let Some(source) = ev.source.as_deref()
        {
            lines.push(format!("{}   src: {source}", prefix_now(&ev.job_id)));
        }
        lines
    }

    fn render_progress(&mut self, ev: &JobProgress) -> Option<Vec<String>> {
        let limiter = self
            .progress_limiters
            .entry(ev.job_id.clone())
            .or_insert_with(|| RateLimiter::new(1));
        if !limiter.allow() {
            return None;
        }

        let ctx = self.ctx;
        let icon = Icons::status_degraded(ctx);
        let phase = ev.phase.label();
        let status = self.colorize_segment(
            JobEventKind::Progress,
            &format!("{icon} {phase:<5} {}", format_elapsed(ev.elapsed)),
        );
        let pipe = pipe(ctx);
        let mut lines = vec![format!(
            "{} {} {pipe} {}",
            prefix_now(&ev.job_id),
            status,
            ev.message
        )];

        if self.mode == JobLifecycleMode::Detailed
            && let Some(usage) = ev.resource_usage.as_deref()
        {
            lines.push(format!("{}   res: {usage}", prefix_now(&ev.job_id)));
        }

        Some(lines)
    }

    fn render_done(&self, ev: &JobDone) -> Vec<String> {
        let ctx = self.ctx;
        let icon = Icons::check(ctx);
        let mut tail = String::new();
        let pipe = pipe(ctx);
        if let Some(artifacts) = ev.artifacts {
            tail.push_str(&format!(" {pipe} {artifacts} artifacts"));
        }
        if let Some(note) = ev.note.as_deref() {
            if !tail.is_empty() {
                tail.push(' ');
            }
            tail.push_str(note);
        }

        let status = self.colorize_segment(
            JobEventKind::Done,
            &format!("{icon} DONE  {}", format_elapsed(ev.elapsed)),
        );
        vec![format!("{} {}{}", prefix_now(&ev.job_id), status, tail)]
    }

    fn render_fail(&self, ev: &JobFail) -> Vec<String> {
        let ctx = self.ctx;
        let icon = Icons::cross(ctx);
        let mut tail = String::new();
        let pipe = pipe(ctx);

        if let Some(error) = ev.error_type.as_deref() {
            tail.push_str(&format!(" {pipe} {error}"));
        }
        if let Some(state) = ev.worker_state.as_deref() {
            if !tail.is_empty() {
                tail.push(' ');
            }
            tail.push_str(&format!("{pipe} {state}"));
        }

        let status = self.colorize_segment(
            JobEventKind::Fail,
            &format!("{icon} FAIL  {}", format_elapsed(ev.elapsed)),
        );
        let mut lines = vec![format!("{} {}{}", prefix_now(&ev.job_id), status, tail)];

        if self.mode == JobLifecycleMode::Detailed
            && let Some(remediation) = ev.remediation.as_deref()
        {
            lines.push(format!("{}   fix: {remediation}", prefix_now(&ev.job_id)));
        }

        lines
    }

    fn colorize_segment(&self, kind: JobEventKind, text: &str) -> String {
        if !self.ctx.supports_color() {
            return text.to_string();
        }

        let color = match kind {
            JobEventKind::Start => ANSI_BLUE,
            JobEventKind::Progress => ANSI_YELLOW,
            JobEventKind::Done => ANSI_GREEN,
            JobEventKind::Fail => ANSI_RED,
        };

        format!("{color}{text}{ANSI_RESET}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JobEventKind {
    Start,
    Progress,
    Done,
    Fail,
}

fn format_elapsed(elapsed: Duration) -> String {
    // Matches README examples like "44.2s".
    let secs = elapsed.as_secs_f64();
    if secs >= 10.0 {
        format!("{:>4.1}s", secs)
    } else {
        format!("{:>4.2}s", secs)
    }
}

fn pad_command(command: &str) -> String {
    // Keep column alignment predictable without trying to fully parse commands.
    // This also avoids allocating huge strings for long commands.
    const MAX: usize = 60;
    const SUFFIX: &str = "...";

    // Fast path for common ASCII-ish commands.
    if command.chars().count() <= MAX {
        command.to_string()
    } else {
        let keep = MAX.saturating_sub(SUFFIX.len());
        let truncated: String = command.chars().take(keep).collect();
        format!("{truncated}{SUFFIX}")
    }
}

fn prefix_now(job_id: &str) -> String {
    // HH:MM:SS matches the bead format examples.
    let now = chrono::Local::now();
    format!("[{}] [{job_id}]", now.format("%H:%M:%S"))
}

fn pipe(ctx: OutputContext) -> &'static str {
    if ctx.supports_unicode() {
        "\u{2502}" // │
    } else {
        "|"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::test_guard;

    // ==================== format_elapsed tests ====================

    #[test]
    fn test_format_elapsed_sub_10_seconds() {
        let _guard = test_guard!();
        assert_eq!(format_elapsed(Duration::from_secs_f64(1.23)), "1.23s");
        assert_eq!(format_elapsed(Duration::from_secs_f64(5.5)), "5.50s");
        assert_eq!(format_elapsed(Duration::from_secs_f64(9.99)), "9.99s");
    }

    #[test]
    fn test_format_elapsed_10_seconds_and_above() {
        let _guard = test_guard!();
        assert_eq!(format_elapsed(Duration::from_secs_f64(10.0)), "10.0s");
        assert_eq!(format_elapsed(Duration::from_secs_f64(44.25)), "44.2s");
        assert_eq!(format_elapsed(Duration::from_secs_f64(100.0)), "100.0s");
    }

    #[test]
    fn test_format_elapsed_zero() {
        let _guard = test_guard!();
        assert_eq!(format_elapsed(Duration::ZERO), "0.00s");
    }

    // ==================== pad_command tests ====================

    #[test]
    fn test_pad_command_short() {
        let _guard = test_guard!();
        let cmd = "cargo build";
        assert_eq!(pad_command(cmd), cmd);
    }

    #[test]
    fn test_pad_command_exactly_60() {
        let _guard = test_guard!();
        let cmd = "a".repeat(60);
        assert_eq!(pad_command(&cmd), cmd);
    }

    #[test]
    fn test_pad_command_long_truncates() {
        let _guard = test_guard!();
        let cmd = "a".repeat(100);
        let result = pad_command(&cmd);
        assert!(result.len() <= 60);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn test_pad_command_unicode() {
        let _guard = test_guard!();
        // Unicode command with emojis
        let cmd = "🚀".repeat(70);
        let result = pad_command(&cmd);
        assert!(result.chars().count() <= 60);
    }

    // ==================== pipe tests ====================

    #[test]
    fn test_pipe_unicode() {
        let _guard = test_guard!();
        let ctx = OutputContext::interactive();
        assert_eq!(pipe(ctx), "│");
    }

    #[test]
    fn test_pipe_ascii() {
        let _guard = test_guard!();
        let ctx = OutputContext::plain();
        assert_eq!(pipe(ctx), "|");
    }

    // ==================== JobPhase tests ====================

    #[test]
    fn test_job_phase_labels() {
        let _guard = test_guard!();
        assert_eq!(JobPhase::TransferUp.label(), "SYNC");
        assert_eq!(JobPhase::Build.label(), "BUILD");
        assert_eq!(JobPhase::TransferDown.label(), "PULL");
        assert_eq!(JobPhase::Other.label(), "PROG");
    }

    #[test]
    fn test_job_phase_equality() {
        let _guard = test_guard!();
        assert_eq!(JobPhase::Build, JobPhase::Build);
        assert_ne!(JobPhase::Build, JobPhase::TransferUp);
    }

    // ==================== JobLifecycleMode tests ====================

    #[test]
    fn test_lifecycle_mode_equality() {
        let _guard = test_guard!();
        assert_eq!(JobLifecycleMode::Compact, JobLifecycleMode::Compact);
        assert_eq!(JobLifecycleMode::Detailed, JobLifecycleMode::Detailed);
        assert_ne!(JobLifecycleMode::Compact, JobLifecycleMode::Detailed);
    }

    // ==================== JobLifecycleLog tests ====================

    #[test]
    fn test_lifecycle_log_default_mode() {
        let _guard = test_guard!();
        let log = JobLifecycleLog::with_context(OutputContext::plain());
        assert_eq!(log.mode, JobLifecycleMode::Compact);
    }

    #[test]
    fn test_lifecycle_log_with_mode() {
        let _guard = test_guard!();
        let log = JobLifecycleLog::with_context(OutputContext::plain())
            .with_mode(JobLifecycleMode::Detailed);
        assert_eq!(log.mode, JobLifecycleMode::Detailed);
    }

    #[test]
    fn start_line_contains_timestamp_and_job_id() {
        let _guard = test_guard!();
        let mut log = JobLifecycleLog::with_context(OutputContext::plain());
        let lines = log
            .render(JobEvent::Start(JobStart {
                job_id: "j-a3f2".to_string(),
                source: Some("agent-1".to_string()),
                command_summary: "cargo build --release".to_string(),
                worker_id: "worker1".to_string(),
            }))
            .expect("start renders");
        assert!(!lines.is_empty());
        assert!(lines[0].contains("[j-a3f2]"));
        assert!(lines[0].contains("START"));
        assert!(lines[0].contains("cargo build --release"));
    }

    #[test]
    fn test_start_detailed_mode_shows_source() {
        let _guard = test_guard!();
        let mut log = JobLifecycleLog::with_context(OutputContext::plain())
            .with_mode(JobLifecycleMode::Detailed);
        let lines = log
            .render(JobEvent::Start(JobStart {
                job_id: "j-test".to_string(),
                source: Some("my-source".to_string()),
                command_summary: "cargo test".to_string(),
                worker_id: "worker1".to_string(),
            }))
            .expect("start renders");
        // Detailed mode adds source line
        assert_eq!(lines.len(), 2);
        assert!(lines[1].contains("src: my-source"));
    }

    #[test]
    fn test_start_no_source() {
        let _guard = test_guard!();
        let mut log = JobLifecycleLog::with_context(OutputContext::plain())
            .with_mode(JobLifecycleMode::Detailed);
        let lines = log
            .render(JobEvent::Start(JobStart {
                job_id: "j-test".to_string(),
                source: None,
                command_summary: "cargo test".to_string(),
                worker_id: "worker1".to_string(),
            }))
            .expect("start renders");
        // No source, so only 1 line even in detailed mode
        assert_eq!(lines.len(), 1);
    }

    #[test]
    fn progress_is_rate_limited_per_job() {
        let _guard = test_guard!();
        let mut log = JobLifecycleLog::with_context(OutputContext::plain());
        let ev = JobEvent::Progress(JobProgress {
            job_id: "j-a3f2".to_string(),
            phase: JobPhase::Build,
            elapsed: Duration::from_secs(1),
            message: "Compiling foo".to_string(),
            resource_usage: None,
        });

        assert!(log.render(ev.clone()).is_some());
        // Second call should be suppressed due to 1/s limiter.
        assert!(log.render(ev).is_none());
    }

    #[test]
    fn test_progress_different_jobs_not_limited() {
        let _guard = test_guard!();
        let mut log = JobLifecycleLog::with_context(OutputContext::plain());

        let ev1 = JobEvent::Progress(JobProgress {
            job_id: "job-1".to_string(),
            phase: JobPhase::Build,
            elapsed: Duration::from_secs(1),
            message: "Building".to_string(),
            resource_usage: None,
        });

        let ev2 = JobEvent::Progress(JobProgress {
            job_id: "job-2".to_string(),
            phase: JobPhase::Build,
            elapsed: Duration::from_secs(1),
            message: "Building".to_string(),
            resource_usage: None,
        });

        assert!(log.render(ev1).is_some());
        assert!(log.render(ev2).is_some()); // Different job, should render
    }

    #[test]
    fn test_progress_contains_phase() {
        let _guard = test_guard!();
        let mut log = JobLifecycleLog::with_context(OutputContext::plain());
        let lines = log
            .render(JobEvent::Progress(JobProgress {
                job_id: "j-test".to_string(),
                phase: JobPhase::TransferUp,
                elapsed: Duration::from_secs(5),
                message: "Uploading files".to_string(),
                resource_usage: None,
            }))
            .expect("progress renders");
        assert!(lines[0].contains("SYNC"));
    }

    #[test]
    fn test_done_renders() {
        let _guard = test_guard!();
        let mut log = JobLifecycleLog::with_context(OutputContext::plain());
        let lines = log
            .render(JobEvent::Done(JobDone {
                job_id: "j-done".to_string(),
                elapsed: Duration::from_secs(30),
                artifacts: Some(5),
                note: Some("cached".to_string()),
            }))
            .expect("done renders");
        assert!(lines[0].contains("DONE"));
        assert!(lines[0].contains("5 artifacts"));
        assert!(lines[0].contains("cached"));
    }

    #[test]
    fn test_done_no_artifacts_no_note() {
        let _guard = test_guard!();
        let mut log = JobLifecycleLog::with_context(OutputContext::plain());
        let lines = log
            .render(JobEvent::Done(JobDone {
                job_id: "j-done".to_string(),
                elapsed: Duration::from_secs(10),
                artifacts: None,
                note: None,
            }))
            .expect("done renders");
        assert!(lines[0].contains("DONE"));
        assert!(!lines[0].contains("artifacts"));
    }

    #[test]
    fn test_fail_renders() {
        let _guard = test_guard!();
        let mut log = JobLifecycleLog::with_context(OutputContext::plain());
        let lines = log
            .render(JobEvent::Fail(JobFail {
                job_id: "j-fail".to_string(),
                elapsed: Duration::from_secs(15),
                error_type: Some("CompilationError".to_string()),
                worker_state: Some("busy".to_string()),
                remediation: None,
            }))
            .expect("fail renders");
        assert!(lines[0].contains("FAIL"));
        assert!(lines[0].contains("CompilationError"));
    }

    #[test]
    fn test_fail_detailed_mode_shows_remediation() {
        let _guard = test_guard!();
        let mut log = JobLifecycleLog::with_context(OutputContext::plain())
            .with_mode(JobLifecycleMode::Detailed);
        let lines = log
            .render(JobEvent::Fail(JobFail {
                job_id: "j-fail".to_string(),
                elapsed: Duration::from_secs(15),
                error_type: None,
                worker_state: None,
                remediation: Some("Retry later".to_string()),
            }))
            .expect("fail renders");
        assert_eq!(lines.len(), 2);
        assert!(lines[1].contains("fix: Retry later"));
    }

    #[test]
    fn test_fail_no_extras() {
        let _guard = test_guard!();
        let mut log = JobLifecycleLog::with_context(OutputContext::plain());
        let lines = log
            .render(JobEvent::Fail(JobFail {
                job_id: "j-fail".to_string(),
                elapsed: Duration::from_secs(5),
                error_type: None,
                worker_state: None,
                remediation: None,
            }))
            .expect("fail renders");
        assert!(lines[0].contains("FAIL"));
    }

    // ==================== colorize_segment tests ====================

    #[test]
    fn test_colorize_with_color_support() {
        let _guard = test_guard!();
        let log = JobLifecycleLog::with_context(OutputContext::interactive());
        let result = log.colorize_segment(JobEventKind::Start, "TEST");
        assert!(result.contains("\x1b[")); // Contains ANSI escape
        assert!(result.contains("TEST"));
    }

    #[test]
    fn test_colorize_without_color_support() {
        let _guard = test_guard!();
        let log = JobLifecycleLog::with_context(OutputContext::plain());
        let result = log.colorize_segment(JobEventKind::Start, "TEST");
        assert_eq!(result, "TEST"); // No ANSI escapes
    }

    // ==================== Event struct tests ====================

    #[test]
    fn test_job_start_fields() {
        let _guard = test_guard!();
        let start = JobStart {
            job_id: "j-123".to_string(),
            source: Some("src".to_string()),
            command_summary: "cmd".to_string(),
            worker_id: "w1".to_string(),
        };
        assert_eq!(start.job_id, "j-123");
        assert_eq!(start.source.unwrap(), "src");
    }

    #[test]
    fn test_job_progress_fields() {
        let _guard = test_guard!();
        let progress = JobProgress {
            job_id: "j-123".to_string(),
            phase: JobPhase::Build,
            elapsed: Duration::from_secs(10),
            message: "msg".to_string(),
            resource_usage: Some("cpu: 100%".to_string()),
        };
        assert_eq!(progress.phase, JobPhase::Build);
        assert!(progress.resource_usage.is_some());
    }

    #[test]
    fn test_job_done_fields() {
        let _guard = test_guard!();
        let done = JobDone {
            job_id: "j-123".to_string(),
            elapsed: Duration::from_secs(60),
            artifacts: Some(10),
            note: Some("note".to_string()),
        };
        assert_eq!(done.artifacts, Some(10));
    }

    #[test]
    fn test_job_fail_fields() {
        let _guard = test_guard!();
        let fail = JobFail {
            job_id: "j-123".to_string(),
            elapsed: Duration::from_secs(30),
            error_type: Some("E001".to_string()),
            worker_state: Some("down".to_string()),
            remediation: Some("fix".to_string()),
        };
        assert_eq!(fail.error_type.unwrap(), "E001");
    }
}
