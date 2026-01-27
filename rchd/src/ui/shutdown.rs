//! ShutdownSequence - Graceful termination display for rchd daemon.
//!
//! This module provides beautiful, informative shutdown messaging including:
//! - SIGTERM/SIGINT receipt acknowledgment
//! - In-flight job status and drain progress
//! - Worker disconnection sequence
//! - Final statistics summary
//! - Clean exit confirmation with exit code
//!
//! # Example Output
//!
//! ```text
//! [14:45:00] ⚠ SIGTERM received, initiating graceful shutdown...
//! [14:45:00] ◐ Draining 3 in-flight jobs (timeout: 60s)
//! [14:45:12]   ✓ j-a3f2 completed
//! [14:45:18]   ✓ j-b7c1 completed
//! [14:45:25]   ✓ j-c9d3 completed
//! [14:45:25] ✓ All jobs drained successfully
//! [14:45:25] Disconnecting workers... 3/3 done
//! ╭─ Session Summary ────────────────────────────────────────╮
//! │ Uptime: 4h 15m │ Jobs: 1,247 │ Success: 99.2% │
//! ╰──────────────────────────────────────────────────────────╯
//! [14:45:26] ● rchd v0.5.2 shutdown complete (exit 0)
//! ```

#![allow(dead_code)]

use chrono::{DateTime, Local, Utc};
use rch_common::ui::{Icons, OutputContext, RchTheme};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

#[cfg(feature = "rich-ui")]
use rich_rust::r#box::ROUNDED;
#[cfg(feature = "rich-ui")]
use rich_rust::prelude::*;

/// Signal type that triggered shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShutdownSignal {
    /// SIGTERM (graceful termination request)
    Term,
    /// SIGINT (interrupt, Ctrl+C)
    Int,
    /// SIGQUIT (quit with core dump request)
    Quit,
    /// Programmatic shutdown (API request)
    Api,
}

impl ShutdownSignal {
    /// Get the display name for this signal.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Term => "SIGTERM",
            Self::Int => "SIGINT",
            Self::Quit => "SIGQUIT",
            Self::Api => "API shutdown",
        }
    }
}

impl std::fmt::Display for ShutdownSignal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Event for tracking job drain progress.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobDrainEvent {
    /// Job identifier (e.g., "j-a3f2")
    pub job_id: String,
    /// Whether the job completed successfully
    pub success: bool,
    /// Optional exit code
    pub exit_code: Option<i32>,
    /// Time when the job completed
    pub completed_at: DateTime<Utc>,
}

impl JobDrainEvent {
    /// Create a new job drain event for a successful completion.
    #[must_use]
    pub fn success(job_id: impl Into<String>) -> Self {
        Self {
            job_id: job_id.into(),
            success: true,
            exit_code: Some(0),
            completed_at: Utc::now(),
        }
    }

    /// Create a new job drain event for a failed completion.
    #[must_use]
    pub fn failed(job_id: impl Into<String>, exit_code: i32) -> Self {
        Self {
            job_id: job_id.into(),
            success: false,
            exit_code: Some(exit_code),
            completed_at: Utc::now(),
        }
    }

    /// Create a new job drain event for a cancelled/interrupted job.
    #[must_use]
    pub fn cancelled(job_id: impl Into<String>) -> Self {
        Self {
            job_id: job_id.into(),
            success: false,
            exit_code: None,
            completed_at: Utc::now(),
        }
    }
}

/// Session statistics for the final summary.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionStats {
    /// Total time the daemon was running
    pub uptime: Duration,
    /// Total number of jobs handled
    pub total_jobs: u64,
    /// Number of successful jobs
    pub successful_jobs: u64,
    /// Number of failed jobs
    pub failed_jobs: u64,
    /// Number of workers that were connected
    pub total_workers: usize,
    /// Total bytes transferred (uploads + downloads)
    pub bytes_transferred: u64,
    /// Average job duration in milliseconds
    pub avg_job_duration_ms: u64,
}

impl SessionStats {
    /// Create new session stats.
    #[must_use]
    pub fn new(
        uptime: Duration,
        total_jobs: u64,
        successful_jobs: u64,
        failed_jobs: u64,
        total_workers: usize,
    ) -> Self {
        Self {
            uptime,
            total_jobs,
            successful_jobs,
            failed_jobs,
            total_workers,
            bytes_transferred: 0,
            avg_job_duration_ms: 0,
        }
    }

    /// Add bytes transferred stat.
    #[must_use]
    pub fn with_bytes(mut self, bytes: u64) -> Self {
        self.bytes_transferred = bytes;
        self
    }

    /// Add average job duration stat.
    #[must_use]
    pub fn with_avg_duration(mut self, duration_ms: u64) -> Self {
        self.avg_job_duration_ms = duration_ms;
        self
    }

    /// Calculate success rate as a percentage.
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        if self.total_jobs == 0 {
            100.0
        } else {
            (self.successful_jobs as f64 / self.total_jobs as f64) * 100.0
        }
    }

    /// Format uptime as human-readable string (e.g., "4h 15m").
    #[must_use]
    pub fn uptime_display(&self) -> String {
        let total_secs = self.uptime.as_secs();
        let hours = total_secs / 3600;
        let minutes = (total_secs % 3600) / 60;
        let seconds = total_secs % 60;

        if hours > 0 {
            format!("{}h {}m", hours, minutes)
        } else if minutes > 0 {
            format!("{}m {}s", minutes, seconds)
        } else {
            format!("{}s", seconds)
        }
    }

    /// Format bytes transferred as human-readable string.
    #[must_use]
    pub fn bytes_display(&self) -> String {
        let bytes = self.bytes_transferred;
        if bytes >= 1024 * 1024 * 1024 {
            format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
        } else if bytes >= 1024 * 1024 {
            format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
        } else if bytes >= 1024 {
            format!("{:.1} KB", bytes as f64 / 1024.0)
        } else {
            format!("{} B", bytes)
        }
    }
}

/// ShutdownSequence - Manages graceful shutdown display.
///
/// Provides consistent, informative output during daemon shutdown,
/// ensuring the final message is visible even in degraded terminal state.
pub struct ShutdownSequence {
    /// Output context for terminal detection
    ctx: OutputContext,
    /// Signal that triggered shutdown
    signal: ShutdownSignal,
    /// Daemon version string
    version: String,
    /// Time when shutdown started
    started_at: Instant,
    /// Total jobs that need to drain
    total_jobs_to_drain: usize,
    /// Jobs drained so far
    jobs_drained: Vec<JobDrainEvent>,
    /// Total workers to disconnect
    total_workers: usize,
    /// Workers disconnected so far
    workers_disconnected: usize,
    /// Shutdown timeout in seconds
    timeout_secs: u64,
}

impl ShutdownSequence {
    /// Create a new shutdown sequence.
    ///
    /// # Arguments
    ///
    /// * `signal` - The signal that triggered shutdown
    /// * `version` - Daemon version string (e.g., "0.5.2")
    /// * `total_jobs` - Number of in-flight jobs to drain
    /// * `total_workers` - Number of workers to disconnect
    /// * `timeout_secs` - Shutdown timeout in seconds
    #[must_use]
    pub fn new(
        signal: ShutdownSignal,
        version: impl Into<String>,
        total_jobs: usize,
        total_workers: usize,
        timeout_secs: u64,
    ) -> Self {
        Self {
            ctx: OutputContext::detect(),
            signal,
            version: version.into(),
            started_at: Instant::now(),
            total_jobs_to_drain: total_jobs,
            jobs_drained: Vec::with_capacity(total_jobs),
            total_workers,
            workers_disconnected: 0,
            timeout_secs,
        }
    }

    /// Create with explicit output context (for testing).
    #[must_use]
    pub fn with_context(mut self, ctx: OutputContext) -> Self {
        self.ctx = ctx;
        self
    }

    /// Display shutdown initiation message.
    ///
    /// Shows: `[HH:MM:SS] ⚠ SIGTERM received, initiating graceful shutdown...`
    pub fn show_signal_received(&self) {
        let timestamp = Self::timestamp();
        let icon = Icons::warning(self.ctx);
        let signal_name = self.signal.name();

        if self.ctx.supports_color() {
            eprintln!(
                "\x1b[33m[{}] {} {} received, initiating graceful shutdown...\x1b[0m",
                timestamp, icon, signal_name
            );
        } else {
            eprintln!(
                "[{}] {} {} received, initiating graceful shutdown...",
                timestamp, icon, signal_name
            );
        }
    }

    /// Display job drain initiation message.
    ///
    /// Shows: `[HH:MM:SS] ◐ Draining N in-flight jobs (timeout: Xs)`
    pub fn show_drain_started(&self) {
        let timestamp = Self::timestamp();
        let icon = Icons::status_draining(self.ctx);
        let count = self.total_jobs_to_drain;
        let timeout = self.timeout_secs;

        if self.ctx.supports_color() {
            eprintln!(
                "\x1b[33m[{}] {} Draining {} in-flight job{} (timeout: {}s)\x1b[0m",
                timestamp,
                icon,
                count,
                if count == 1 { "" } else { "s" },
                timeout
            );
        } else {
            eprintln!(
                "[{}] {} Draining {} in-flight job{} (timeout: {}s)",
                timestamp,
                icon,
                count,
                if count == 1 { "" } else { "s" },
                timeout
            );
        }
    }

    /// Record and display a job drain event.
    ///
    /// Shows: `[HH:MM:SS]   ✓ j-xxxx completed` or `[HH:MM:SS]   ✗ j-xxxx failed`
    pub fn record_job_drained(&mut self, event: JobDrainEvent) {
        let timestamp = Self::timestamp();
        let (icon, color) = if event.success {
            (Icons::check(self.ctx), "32") // Green
        } else {
            (Icons::cross(self.ctx), "31") // Red
        };
        let status = if event.success {
            "completed"
        } else if event.exit_code.is_some() {
            "failed"
        } else {
            "cancelled"
        };

        if self.ctx.supports_color() {
            eprintln!(
                "  \x1b[{}m[{}]   {} {} {}\x1b[0m",
                color, timestamp, icon, event.job_id, status
            );
        } else {
            eprintln!("[{}]   {} {} {}", timestamp, icon, event.job_id, status);
        }

        self.jobs_drained.push(event);
    }

    /// Display drain completion message.
    ///
    /// Shows: `[HH:MM:SS] ✓ All jobs drained successfully` or failure message
    pub fn show_drain_complete(&self, all_success: bool) {
        let timestamp = Self::timestamp();

        if all_success {
            let icon = Icons::check(self.ctx);
            if self.ctx.supports_color() {
                eprintln!(
                    "\x1b[32m[{}] {} All jobs drained successfully\x1b[0m",
                    timestamp, icon
                );
            } else {
                eprintln!("[{}] {} All jobs drained successfully", timestamp, icon);
            }
        } else {
            let failed = self.jobs_drained.iter().filter(|j| !j.success).count();
            let icon = Icons::warning(self.ctx);
            if self.ctx.supports_color() {
                eprintln!(
                    "\x1b[33m[{}] {} Drain complete ({} job{} failed)\x1b[0m",
                    timestamp,
                    icon,
                    failed,
                    if failed == 1 { "" } else { "s" }
                );
            } else {
                eprintln!(
                    "[{}] {} Drain complete ({} job{} failed)",
                    timestamp,
                    icon,
                    failed,
                    if failed == 1 { "" } else { "s" }
                );
            }
        }
    }

    /// Display drain timeout message.
    ///
    /// Shows countdown and forced termination warning.
    pub fn show_drain_timeout(&self, remaining_jobs: usize) {
        let timestamp = Self::timestamp();
        let icon = Icons::warning(self.ctx);

        if self.ctx.supports_color() {
            eprintln!(
                "\x1b[31m[{}] {} Drain timeout! Force-terminating {} remaining job{}\x1b[0m",
                timestamp,
                icon,
                remaining_jobs,
                if remaining_jobs == 1 { "" } else { "s" }
            );
        } else {
            eprintln!(
                "[{}] {} Drain timeout! Force-terminating {} remaining job{}",
                timestamp,
                icon,
                remaining_jobs,
                if remaining_jobs == 1 { "" } else { "s" }
            );
        }
    }

    /// Display worker disconnection progress.
    ///
    /// Shows: `[HH:MM:SS] Disconnecting workers... N/M done`
    pub fn show_workers_disconnecting(&mut self, disconnected: usize) {
        self.workers_disconnected = disconnected;
        let timestamp = Self::timestamp();

        eprintln!(
            "[{}] Disconnecting workers... {}/{} done",
            timestamp, disconnected, self.total_workers
        );
    }

    /// Display session summary panel.
    ///
    /// Shows a bordered panel with uptime, job count, and success rate.
    #[cfg(feature = "rich-ui")]
    pub fn show_session_summary(&self, stats: &SessionStats) {
        if self.ctx.supports_rich() {
            self.show_session_summary_rich(stats);
        } else {
            self.show_session_summary_plain(stats);
        }
    }

    /// Display session summary panel (non-rich fallback).
    #[cfg(not(feature = "rich-ui"))]
    pub fn show_session_summary(&self, stats: &SessionStats) {
        self.show_session_summary_plain(stats);
    }

    /// Rich session summary using rich_rust Panel.
    #[cfg(feature = "rich-ui")]
    fn show_session_summary_rich(&self, stats: &SessionStats) {
        let content = format!(
            "Uptime: {} | Jobs: {} | Success: {:.1}%",
            stats.uptime_display(),
            stats.total_jobs,
            stats.success_rate()
        );

        let border_color = Color::parse(RchTheme::SECONDARY).unwrap_or_default();
        let border_style = Style::new().color(border_color);

        let panel = Panel::from_text(&content)
            .title("Session Summary")
            .border_style(border_style)
            .box_style(&ROUNDED);

        let console = Console::builder().force_terminal(true).build();
        console.print_renderable(&panel);
    }

    /// Plain text session summary.
    fn show_session_summary_plain(&self, stats: &SessionStats) {
        // Box drawing characters with ASCII fallback
        let (tl, tr, bl, br, h, v) = if self.ctx.supports_unicode() {
            (
                '\u{256D}', '\u{256E}', '\u{2570}', '\u{256F}', '\u{2500}', '\u{2502}',
            )
        } else {
            ('+', '+', '+', '+', '-', '|')
        };

        let title = " Session Summary ";
        let content = format!(
            "Uptime: {} {} Jobs: {} {} Success: {:.1}%",
            stats.uptime_display(),
            v,
            stats.total_jobs,
            v,
            stats.success_rate()
        );

        // Calculate width (content + padding)
        let width = content.len().max(title.len()) + 4;
        let h_line: String = std::iter::repeat_n(h, width - 2).collect();

        // Top border with title
        let title_padding_left = (width - 2 - title.len()) / 2;
        let title_padding_right = width - 2 - title.len() - title_padding_left;
        let top_line = format!(
            "{}{}{}{}{}",
            tl,
            std::iter::repeat_n(h, title_padding_left).collect::<String>(),
            title,
            std::iter::repeat_n(h, title_padding_right).collect::<String>(),
            tr
        );

        // Content line
        let content_padding = width - 2 - content.len();
        let content_line = format!("{} {}{} {}", v, content, " ".repeat(content_padding), v);

        // Bottom border
        let bottom_line = format!("{}{}{}", bl, h_line, br);

        eprintln!("{}", top_line);
        eprintln!("{}", content_line);
        eprintln!("{}", bottom_line);
    }

    /// Display final shutdown complete message.
    ///
    /// Shows: `[HH:MM:SS] ● rchd vX.Y.Z shutdown complete (exit N)`
    pub fn show_shutdown_complete(&self, exit_code: i32) {
        let timestamp = Self::timestamp();
        let icon = Icons::status_healthy(self.ctx);
        let version = &self.version;

        // Use green for exit 0, red for non-zero
        let color = if exit_code == 0 { "32" } else { "31" };

        if self.ctx.supports_color() {
            eprintln!(
                "\x1b[{}m[{}] {} rchd v{} shutdown complete (exit {})\x1b[0m",
                color, timestamp, icon, version, exit_code
            );
        } else {
            eprintln!(
                "[{}] {} rchd v{} shutdown complete (exit {})",
                timestamp, icon, version, exit_code
            );
        }
    }

    /// Display timeout countdown.
    ///
    /// Shows remaining time before forced shutdown.
    pub fn show_countdown(&self, remaining_secs: u64, remaining_jobs: usize) {
        let timestamp = Self::timestamp();

        if self.ctx.supports_color() {
            eprint!(
                "\r\x1b[33m[{}] Waiting for {} job{} to complete ({}s remaining)...\x1b[0m\x1b[K",
                timestamp,
                remaining_jobs,
                if remaining_jobs == 1 { "" } else { "s" },
                remaining_secs
            );
        } else {
            eprint!(
                "\r[{}] Waiting for {} job{} to complete ({}s remaining)...",
                timestamp,
                remaining_jobs,
                if remaining_jobs == 1 { "" } else { "s" },
                remaining_secs
            );
        }
        // Flush stderr to ensure countdown is visible
        use std::io::Write;
        let _ = std::io::stderr().flush();
    }

    /// Clear countdown line (call after countdown completes).
    pub fn clear_countdown(&self) {
        eprint!("\r\x1b[K"); // Clear line
        use std::io::Write;
        let _ = std::io::stderr().flush();
    }

    /// Get elapsed time since shutdown started.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// Get number of jobs drained so far.
    #[must_use]
    pub fn jobs_drained_count(&self) -> usize {
        self.jobs_drained.len()
    }

    /// Check if all jobs drained successfully.
    #[must_use]
    pub fn all_jobs_success(&self) -> bool {
        self.jobs_drained.iter().all(|j| j.success)
    }

    /// Get current timestamp in HH:MM:SS format.
    fn timestamp() -> String {
        Local::now().format("%H:%M:%S").to_string()
    }
}

/// Run the complete shutdown sequence.
///
/// This is a convenience function that orchestrates the full shutdown display.
///
/// # Arguments
///
/// * `signal` - The signal that triggered shutdown
/// * `version` - Daemon version string
/// * `in_flight_jobs` - List of in-flight job IDs
/// * `workers` - Number of connected workers
/// * `timeout` - Shutdown timeout
/// * `stats` - Session statistics
/// * `drain_fn` - Async function to drain a single job, returns JobDrainEvent
///
/// # Returns
///
/// Exit code (0 for success, non-zero for errors)
pub async fn run_shutdown_sequence<F, Fut>(
    signal: ShutdownSignal,
    version: &str,
    in_flight_jobs: Vec<String>,
    workers: usize,
    timeout: Duration,
    stats: SessionStats,
    mut drain_fn: F,
) -> i32
where
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = JobDrainEvent>,
{
    let total_jobs = in_flight_jobs.len();
    let mut sequence =
        ShutdownSequence::new(signal, version, total_jobs, workers, timeout.as_secs());

    // 1. Show signal received
    sequence.show_signal_received();

    // 2. Drain jobs if any
    if total_jobs > 0 {
        sequence.show_drain_started();

        for job_id in in_flight_jobs {
            let event = drain_fn(job_id).await;
            sequence.record_job_drained(event);
        }

        sequence.show_drain_complete(sequence.all_jobs_success());
    }

    // 3. Disconnect workers
    sequence.show_workers_disconnecting(workers);

    // 4. Show session summary
    sequence.show_session_summary(&stats);

    // 5. Show final message
    let exit_code = if sequence.all_jobs_success() { 0 } else { 1 };
    sequence.show_shutdown_complete(exit_code);

    exit_code
}

#[cfg(test)]
mod tests {
        use rch_common::test_guard;

    #[test]
    fn test_shutdown_signal_names() {
        let _guard = test_guard!();
        assert_eq!(ShutdownSignal::Term.name(), "SIGTERM");
        assert_eq!(ShutdownSignal::Int.name(), "SIGINT");
        assert_eq!(ShutdownSignal::Quit.name(), "SIGQUIT");
        assert_eq!(ShutdownSignal::Api.name(), "API shutdown");
    }

    #[test]
    fn test_shutdown_signal_display() {
        let _guard = test_guard!();
        assert_eq!(format!("{}", ShutdownSignal::Term), "SIGTERM");
    }

    #[test]
    fn test_job_drain_event_success() {
        let _guard = test_guard!();
        let event = JobDrainEvent::success("j-abc123");
        assert!(event.success);
        assert_eq!(event.exit_code, Some(0));
        assert_eq!(event.job_id, "j-abc123");
    }

    #[test]
    fn test_job_drain_event_failed() {
        let _guard = test_guard!();
        let event = JobDrainEvent::failed("j-xyz789", 1);
        assert!(!event.success);
        assert_eq!(event.exit_code, Some(1));
    }

    #[test]
    fn test_job_drain_event_cancelled() {
        let _guard = test_guard!();
        let event = JobDrainEvent::cancelled("j-cancelled");
        assert!(!event.success);
        assert!(event.exit_code.is_none());
    }

    #[test]
    fn test_session_stats_success_rate() {
        let _guard = test_guard!();
        let stats = SessionStats::new(Duration::from_secs(3600), 100, 95, 5, 3);
        assert!((stats.success_rate() - 95.0).abs() < 0.01);
    }

    #[test]
    fn test_session_stats_success_rate_zero_jobs() {
        let _guard = test_guard!();
        let stats = SessionStats::new(Duration::from_secs(3600), 0, 0, 0, 3);
        assert!((stats.success_rate() - 100.0).abs() < 0.01);
    }

    #[test]
    fn test_session_stats_uptime_display() {
        let _guard = test_guard!();
        // Hours and minutes
        let stats = SessionStats::new(Duration::from_secs(4 * 3600 + 15 * 60), 0, 0, 0, 0);
        assert_eq!(stats.uptime_display(), "4h 15m");

        // Minutes and seconds
        let stats = SessionStats::new(Duration::from_secs(5 * 60 + 30), 0, 0, 0, 0);
        assert_eq!(stats.uptime_display(), "5m 30s");

        // Seconds only
        let stats = SessionStats::new(Duration::from_secs(45), 0, 0, 0, 0);
        assert_eq!(stats.uptime_display(), "45s");
    }

    #[test]
    fn test_session_stats_bytes_display() {
        let _guard = test_guard!();
        // GB
        let mut stats = SessionStats {
            bytes_transferred: 2_500_000_000,
            ..Default::default()
        };
        assert!(stats.bytes_display().contains("GB"));

        // MB
        stats.bytes_transferred = 50_000_000;
        assert!(stats.bytes_display().contains("MB"));

        // KB
        stats.bytes_transferred = 50_000;
        assert!(stats.bytes_display().contains("KB"));

        // Bytes
        stats.bytes_transferred = 500;
        assert!(stats.bytes_display().contains("B"));
    }

    #[test]
    fn test_shutdown_sequence_creation() {
        let _guard = test_guard!();
        let seq = ShutdownSequence::new(ShutdownSignal::Term, "0.5.2", 3, 2, 60);
        assert_eq!(seq.total_jobs_to_drain, 3);
        assert_eq!(seq.total_workers, 2);
        assert_eq!(seq.timeout_secs, 60);
    }

    #[test]
    fn test_shutdown_sequence_record_job() {
        let _guard = test_guard!();
        let mut seq = ShutdownSequence::new(ShutdownSignal::Term, "0.5.2", 2, 1, 60)
            .with_context(OutputContext::Plain);

        seq.record_job_drained(JobDrainEvent::success("j-001"));
        seq.record_job_drained(JobDrainEvent::failed("j-002", 1));

        assert_eq!(seq.jobs_drained_count(), 2);
        assert!(!seq.all_jobs_success());
    }

    #[test]
    fn test_shutdown_sequence_all_success() {
        let _guard = test_guard!();
        let mut seq = ShutdownSequence::new(ShutdownSignal::Int, "0.5.2", 2, 1, 60)
            .with_context(OutputContext::Plain);

        seq.record_job_drained(JobDrainEvent::success("j-001"));
        seq.record_job_drained(JobDrainEvent::success("j-002"));

        assert!(seq.all_jobs_success());
    }

    #[test]
    fn test_shutdown_sequence_show_functions_dont_panic() {
        let _guard = test_guard!();
        let seq = ShutdownSequence::new(ShutdownSignal::Term, "0.5.2", 3, 2, 60)
            .with_context(OutputContext::Plain);

        // These should not panic
        seq.show_signal_received();
        seq.show_drain_started();
        seq.show_drain_complete(true);
        seq.show_drain_complete(false);
        seq.show_drain_timeout(2);
        seq.show_countdown(30, 2);
        seq.clear_countdown();
    }

    #[test]
    fn test_shutdown_sequence_workers_disconnecting() {
        let _guard = test_guard!();
        let mut seq = ShutdownSequence::new(ShutdownSignal::Term, "0.5.2", 0, 5, 60)
            .with_context(OutputContext::Plain);

        seq.show_workers_disconnecting(3);
        assert_eq!(seq.workers_disconnected, 3);

        seq.show_workers_disconnecting(5);
        assert_eq!(seq.workers_disconnected, 5);
    }

    #[test]
    fn test_shutdown_sequence_session_summary_plain() {
        let _guard = test_guard!();
        let seq = ShutdownSequence::new(ShutdownSignal::Term, "0.5.2", 0, 0, 60)
            .with_context(OutputContext::Plain);
        let stats = SessionStats::new(Duration::from_secs(3600), 100, 95, 5, 3);

        // Should not panic
        seq.show_session_summary(&stats);
    }

    #[test]
    fn test_shutdown_sequence_final_message() {
        let _guard = test_guard!();
        let seq = ShutdownSequence::new(ShutdownSignal::Term, "0.5.2", 0, 0, 60)
            .with_context(OutputContext::Plain);

        // Should not panic
        seq.show_shutdown_complete(0);
        seq.show_shutdown_complete(1);
    }

    #[test]
    fn test_session_stats_builder() {
        let _guard = test_guard!();
        let stats = SessionStats::new(Duration::from_secs(3600), 100, 95, 5, 3)
            .with_bytes(1_000_000)
            .with_avg_duration(500);

        assert_eq!(stats.bytes_transferred, 1_000_000);
        assert_eq!(stats.avg_job_duration_ms, 500);
    }

    #[test]
    fn test_shutdown_sequence_elapsed() {
        let _guard = test_guard!();
        let seq = ShutdownSequence::new(ShutdownSignal::Term, "0.5.2", 0, 0, 60);
        std::thread::sleep(Duration::from_millis(10));
        assert!(seq.elapsed().as_millis() >= 10);
    }
}
