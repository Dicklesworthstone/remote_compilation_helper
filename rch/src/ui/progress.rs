//! Progress indicators for long-running CLI operations.
//!
//! Provides spinners, progress bars, step indicators, and multi-progress
//! managers using the indicatif crate. All progress types are aware of
//! output mode and gracefully degrade in non-TTY, JSON, or quiet modes.
//!
//! # Usage
//!
//! ```rust,ignore
//! use rch::ui::progress::{Spinner, TransferProgress, MultiProgressManager};
//! use rch::ui::OutputContext;
//!
//! // Spinner for unknown-duration operations
//! let spinner = Spinner::new(&ctx, "Connecting...");
//! // ... do work ...
//! spinner.finish_success("Connected");
//!
//! // Progress bar for known-size transfers
//! let bar = TransferProgress::new(&ctx, total_bytes, "Syncing");
//! bar.set_position(bytes_transferred);
//! bar.finish();
//! ```

use super::context::{OutputContext, OutputMode};
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::time::Duration;

/// The tick rate for spinner animations (80ms = 12.5 fps).
const SPINNER_TICK_RATE: Duration = Duration::from_millis(80);

/// Braille dot spinner characters for smooth animation.
const SPINNER_CHARS: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// ASCII fallback spinner for non-unicode terminals.
const SPINNER_CHARS_ASCII: &[&str] = &["|", "/", "-", "\\"];

/// Progress bar characters for filled display.
const PROGRESS_CHARS: &str = "█▓░";

/// ASCII fallback progress bar characters.
const PROGRESS_CHARS_ASCII: &str = "#-·";

/// Check if progress should be displayed based on output context.
///
/// Returns false if:
/// - JSON mode is active
/// - Quiet mode is active
/// - stderr is not a TTY (piped output)
fn should_show_progress(ctx: &OutputContext) -> bool {
    !ctx.is_json() && !ctx.is_quiet() && ctx.mode() == OutputMode::Human
}

/// Get the appropriate spinner characters for the terminal.
fn spinner_chars(ctx: &OutputContext) -> &'static [&'static str] {
    if ctx.theme().supports_unicode() {
        SPINNER_CHARS
    } else {
        SPINNER_CHARS_ASCII
    }
}

/// Get the appropriate progress bar characters for the terminal.
fn progress_chars(ctx: &OutputContext) -> &'static str {
    if ctx.theme().supports_unicode() {
        PROGRESS_CHARS
    } else {
        PROGRESS_CHARS_ASCII
    }
}

/// A spinner for unknown-duration operations.
///
/// Displays an animated spinner with a message. Automatically hides
/// in non-TTY, JSON, or quiet modes.
///
/// # Example
///
/// ```rust,ignore
/// let spinner = Spinner::new(&ctx, "Connecting to worker...");
/// do_connection().await;
/// spinner.finish_success("Connected");
/// ```
pub struct Spinner {
    inner: ProgressBar,
    _visible: bool,
}

impl Spinner {
    /// Create a new spinner with the given message.
    ///
    /// The spinner is hidden in JSON/quiet modes or when output is piped.
    pub fn new(ctx: &OutputContext, message: &str) -> Self {
        let visible = should_show_progress(ctx);

        let inner = if visible {
            let pb = ProgressBar::new_spinner();
            let chars = spinner_chars(ctx);
            pb.set_style(
                ProgressStyle::default_spinner()
                    .tick_strings(chars)
                    .template("{spinner:.cyan} {msg}")
                    .expect("valid template"),
            );
            pb.set_message(message.to_string());
            pb.enable_steady_tick(SPINNER_TICK_RATE);
            pb
        } else {
            ProgressBar::hidden()
        };

        Self {
            inner,
            _visible: visible,
        }
    }

    /// Update the spinner message.
    pub fn set_message(&self, msg: &str) {
        self.inner.set_message(msg.to_string());
    }

    /// Finish the spinner with a success message.
    pub fn finish_success(&self, msg: &str) {
        self.inner.finish_with_message(format!("✓ {}", msg));
    }

    /// Finish the spinner with an error message.
    pub fn finish_error(&self, msg: &str) {
        self.inner.finish_with_message(format!("✗ {}", msg));
    }

    /// Finish the spinner with a warning message.
    pub fn finish_warning(&self, msg: &str) {
        self.inner.finish_with_message(format!("⚠ {}", msg));
    }

    /// Abandon the spinner (cancel without message change).
    pub fn abandon(&self) {
        self.inner.abandon();
    }

    /// Finish and clear the spinner line.
    pub fn finish_and_clear(&self) {
        self.inner.finish_and_clear();
    }

    /// Get the underlying progress bar for advanced operations.
    pub fn inner(&self) -> &ProgressBar {
        &self.inner
    }
}

/// A progress bar for known-size operations like file transfers.
///
/// Displays: label [█████░░░░░] bytes/total speed ETA
///
/// # Example
///
/// ```rust,ignore
/// let bar = TransferProgress::new(&ctx, total_bytes, "Syncing");
/// for chunk in chunks {
///     transfer_chunk(chunk)?;
///     bar.set_position(bytes_so_far);
/// }
/// bar.finish();
/// ```
pub struct TransferProgress {
    inner: ProgressBar,
}

impl TransferProgress {
    /// Create a new progress bar for a transfer operation.
    pub fn new(ctx: &OutputContext, total: u64, label: &str) -> Self {
        let visible = should_show_progress(ctx);

        let inner = if visible {
            let pb = ProgressBar::new(total);
            let chars = progress_chars(ctx);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{msg:12} [{bar:40.cyan/blue}] {bytes}/{total_bytes} {bytes_per_sec} ETA {eta}")
                    .expect("valid template")
                    .progress_chars(chars),
            );
            pb.set_message(label.to_string());
            pb
        } else {
            ProgressBar::hidden()
        };

        Self { inner }
    }

    /// Create a progress bar for item count (not bytes).
    pub fn new_items(ctx: &OutputContext, total: u64, label: &str) -> Self {
        let visible = should_show_progress(ctx);

        let inner = if visible {
            let pb = ProgressBar::new(total);
            let chars = progress_chars(ctx);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{msg:12} [{bar:40.cyan/blue}] {pos}/{len} ({percent}%)")
                    .expect("valid template")
                    .progress_chars(chars),
            );
            pb.set_message(label.to_string());
            pb
        } else {
            ProgressBar::hidden()
        };

        Self { inner }
    }

    /// Set the current position.
    pub fn set_position(&self, pos: u64) {
        self.inner.set_position(pos);
    }

    /// Increment the position by the given amount.
    pub fn inc(&self, delta: u64) {
        self.inner.inc(delta);
    }

    /// Set the message/label.
    pub fn set_message(&self, msg: &str) {
        self.inner.set_message(msg.to_string());
    }

    /// Finish the progress bar.
    pub fn finish(&self) {
        self.inner.finish();
    }

    /// Finish and clear the progress bar line.
    pub fn finish_and_clear(&self) {
        self.inner.finish_and_clear();
    }

    /// Get the underlying progress bar.
    pub fn inner(&self) -> &ProgressBar {
        &self.inner
    }
}

/// Step progress indicator for multi-phase operations.
///
/// Displays:
/// ```text
/// [1/3] ✓ Synced files (2.3s)
/// [2/3] ◐ Compiling...
/// [3/3] ○ Retrieve artifacts
/// ```
#[derive(Clone)]
pub struct StepProgress {
    steps: Vec<StepState>,
    current: usize,
    ctx_mode: OutputMode,
    ctx_unicode: bool,
}

#[derive(Clone)]
struct StepState {
    name: String,
    status: StepStatus,
    message: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StepStatus {
    Pending,
    InProgress,
    Complete,
    Failed,
    Skipped,
}

impl StepProgress {
    /// Create a new step progress indicator.
    pub fn new(ctx: &OutputContext, step_names: &[&str]) -> Self {
        let steps = step_names
            .iter()
            .map(|name| StepState {
                name: name.to_string(),
                status: StepStatus::Pending,
                message: None,
            })
            .collect();

        Self {
            steps,
            current: 0,
            ctx_mode: ctx.mode(),
            ctx_unicode: ctx.theme().supports_unicode(),
        }
    }

    /// Start a step (mark as in-progress).
    pub fn start_step(&mut self, idx: usize) {
        if idx < self.steps.len() {
            self.steps[idx].status = StepStatus::InProgress;
            self.current = idx;
            self.print_current();
        }
    }

    /// Complete a step with an optional message.
    pub fn complete_step(&mut self, idx: usize, message: Option<&str>) {
        if idx < self.steps.len() {
            self.steps[idx].status = StepStatus::Complete;
            self.steps[idx].message = message.map(|s| s.to_string());
            self.print_current();
        }
    }

    /// Fail a step with an optional message.
    pub fn fail_step(&mut self, idx: usize, message: Option<&str>) {
        if idx < self.steps.len() {
            self.steps[idx].status = StepStatus::Failed;
            self.steps[idx].message = message.map(|s| s.to_string());
            self.print_current();
        }
    }

    /// Skip a step.
    pub fn skip_step(&mut self, idx: usize) {
        if idx < self.steps.len() {
            self.steps[idx].status = StepStatus::Skipped;
            self.print_current();
        }
    }

    fn print_current(&self) {
        if self.ctx_mode == OutputMode::Json || self.ctx_mode == OutputMode::Quiet {
            return;
        }

        let total = self.steps.len();
        for (i, step) in self.steps.iter().enumerate() {
            let symbol = self.status_symbol(step.status);
            let num = format!("[{}/{}]", i + 1, total);
            let msg = step
                .message
                .as_ref()
                .map(|m| format!(" ({})", m))
                .unwrap_or_default();
            eprintln!("{} {} {}{}", num, symbol, step.name, msg);
        }
    }

    fn status_symbol(&self, status: StepStatus) -> &'static str {
        if self.ctx_unicode {
            match status {
                StepStatus::Pending => "○",
                StepStatus::InProgress => "◐",
                StepStatus::Complete => "✓",
                StepStatus::Failed => "✗",
                StepStatus::Skipped => "⊘",
            }
        } else {
            match status {
                StepStatus::Pending => "[ ]",
                StepStatus::InProgress => "[~]",
                StepStatus::Complete => "[x]",
                StepStatus::Failed => "[!]",
                StepStatus::Skipped => "[-]",
            }
        }
    }
}

/// Multi-progress manager for parallel operations.
///
/// Manages multiple spinners or progress bars that update simultaneously.
///
/// # Example
///
/// ```rust,ignore
/// let manager = MultiProgressManager::new(&ctx);
/// let spinner1 = manager.add_spinner("worker-1", "Connecting...");
/// let spinner2 = manager.add_spinner("worker-2", "Connecting...");
///
/// // Update independently
/// spinner1.finish_success("OK (45ms)");
/// spinner2.finish_error("Connection refused");
/// ```
pub struct MultiProgressManager {
    multi: MultiProgress,
    visible: bool,
    ctx_unicode: bool,
}

impl MultiProgressManager {
    /// Create a new multi-progress manager.
    pub fn new(ctx: &OutputContext) -> Self {
        let visible = should_show_progress(ctx);

        let multi = if visible {
            MultiProgress::new()
        } else {
            MultiProgress::with_draw_target(ProgressDrawTarget::hidden())
        };

        Self {
            multi,
            visible,
            ctx_unicode: ctx.theme().supports_unicode(),
        }
    }

    /// Add a spinner to the multi-progress display.
    pub fn add_spinner(&self, prefix: &str, message: &str) -> ProgressBar {
        let pb = self.multi.add(ProgressBar::new_spinner());

        if self.visible {
            let chars = if self.ctx_unicode {
                SPINNER_CHARS
            } else {
                SPINNER_CHARS_ASCII
            };

            #[allow(clippy::literal_string_with_formatting_args)]
            let template = "{prefix:12} {spinner:.cyan} {msg}";
            pb.set_style(
                ProgressStyle::default_spinner()
                    .tick_strings(chars)
                    .template(template)
                    .expect("valid template"),
            );
            pb.set_prefix(prefix.to_string());
            pb.set_message(message.to_string());
            pb.enable_steady_tick(SPINNER_TICK_RATE);
        }

        pb
    }

    /// Add a progress bar to the multi-progress display.
    pub fn add_progress_bar(&self, total: u64, prefix: &str) -> ProgressBar {
        let pb = self.multi.add(ProgressBar::new(total));

        if self.visible {
            let chars = if self.ctx_unicode {
                PROGRESS_CHARS
            } else {
                PROGRESS_CHARS_ASCII
            };

            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{prefix:12} [{bar:30.cyan/blue}] {percent:3}%")
                    .expect("valid template")
                    .progress_chars(chars),
            );
            pb.set_prefix(prefix.to_string());
        }

        pb
    }

    /// Suspend the multi-progress display temporarily.
    ///
    /// Use this when streaming output that would conflict with progress.
    pub fn suspend<F, T>(&self, f: F) -> T
    where
        F: FnOnce() -> T,
    {
        self.multi.suspend(f)
    }

    /// Hide the draw target temporarily.
    pub fn hide(&self) {
        self.multi.set_draw_target(ProgressDrawTarget::hidden());
    }

    /// Show the draw target (restore to stderr).
    pub fn show(&self) {
        if self.visible {
            self.multi.set_draw_target(ProgressDrawTarget::stderr());
        }
    }

    /// Clear all progress bars.
    pub fn clear(&self) {
        self.multi.clear().ok();
    }

    /// Check if progress is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }
}

/// Execute an async operation with a spinner.
///
/// The spinner shows while the operation is in progress, then finishes
/// with success or error based on the result.
///
/// # Example
///
/// ```rust,ignore
/// let result = with_spinner(&ctx, "Connecting...", async {
///     connect_to_worker().await
/// }).await;
/// ```
pub async fn with_spinner<F, T>(ctx: &OutputContext, message: &str, future: F) -> T
where
    F: std::future::Future<Output = T>,
{
    let spinner = Spinner::new(ctx, message);
    let result = future.await;
    spinner.finish_and_clear();
    result
}

/// Execute an async operation with a spinner, showing success/error on completion.
pub async fn with_spinner_result<F, T, E>(
    ctx: &OutputContext,
    message: &str,
    success_msg: &str,
    future: F,
) -> Result<T, E>
where
    F: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let spinner = Spinner::new(ctx, message);
    let result = future.await;

    match &result {
        Ok(_) => spinner.finish_success(success_msg),
        Err(e) => spinner.finish_error(&e.to_string()),
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::{OutputConfig, OutputContext};

    fn make_plain_context() -> OutputContext {
        OutputContext::new(OutputConfig {
            color: super::super::context::ColorChoice::Never,
            ..Default::default()
        })
    }

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
    fn test_spinner_lifecycle() {
        let ctx = make_plain_context();
        let spinner = Spinner::new(&ctx, "Testing...");
        spinner.set_message("Still testing...");
        spinner.finish_success("Done");
        // Hidden spinner should not panic
    }

    #[test]
    fn test_spinner_in_quiet_mode() {
        let ctx = make_quiet_context();
        let spinner = Spinner::new(&ctx, "Testing...");
        spinner.finish_success("Done");
        // Should use hidden progress bar
    }

    #[test]
    fn test_spinner_in_json_mode() {
        let ctx = make_json_context();
        let spinner = Spinner::new(&ctx, "Testing...");
        spinner.finish_error("Failed");
        // Should use hidden progress bar
    }

    #[test]
    fn test_spinner_error_finish() {
        let ctx = make_plain_context();
        let spinner = Spinner::new(&ctx, "Working...");
        spinner.finish_error("Connection failed");
    }

    #[test]
    fn test_spinner_warning_finish() {
        let ctx = make_plain_context();
        let spinner = Spinner::new(&ctx, "Working...");
        spinner.finish_warning("Partial success");
    }

    #[test]
    fn test_spinner_abandon() {
        let ctx = make_plain_context();
        let spinner = Spinner::new(&ctx, "Working...");
        spinner.abandon();
    }

    #[test]
    fn test_transfer_progress_lifecycle() {
        let ctx = make_plain_context();
        let bar = TransferProgress::new(&ctx, 100, "Syncing");
        bar.set_position(50);
        bar.inc(25);
        bar.finish();
    }

    #[test]
    fn test_transfer_progress_items() {
        let ctx = make_plain_context();
        let bar = TransferProgress::new_items(&ctx, 10, "Items");
        bar.set_position(5);
        bar.finish_and_clear();
    }

    #[test]
    fn test_transfer_progress_quiet() {
        let ctx = make_quiet_context();
        let bar = TransferProgress::new(&ctx, 100, "test");
        bar.set_position(50);
        bar.finish();
        // Should use hidden bar
    }

    #[test]
    fn test_step_progress_lifecycle() {
        let ctx = make_plain_context();
        let mut steps = StepProgress::new(&ctx, &["Sync", "Compile", "Retrieve"]);
        steps.start_step(0);
        steps.complete_step(0, Some("2.3s"));
        steps.start_step(1);
        steps.complete_step(1, None);
        steps.start_step(2);
        steps.complete_step(2, Some("45ms"));
    }

    #[test]
    fn test_step_progress_failure() {
        let ctx = make_plain_context();
        let mut steps = StepProgress::new(&ctx, &["Sync", "Compile"]);
        steps.start_step(0);
        steps.fail_step(0, Some("Connection refused"));
    }

    #[test]
    fn test_step_progress_skip() {
        let ctx = make_plain_context();
        let mut steps = StepProgress::new(&ctx, &["Sync", "Compile"]);
        steps.skip_step(0);
    }

    #[test]
    fn test_multi_progress_manager() {
        let ctx = make_plain_context();
        let manager = MultiProgressManager::new(&ctx);
        let pb1 = manager.add_spinner("worker-1", "Connecting...");
        let pb2 = manager.add_spinner("worker-2", "Connecting...");
        pb1.finish_with_message("OK");
        pb2.finish_with_message("OK");
    }

    #[test]
    fn test_multi_progress_suspend() {
        let ctx = make_plain_context();
        let manager = MultiProgressManager::new(&ctx);
        let result = manager.suspend(|| {
            // Simulate streaming output
            42
        });
        assert_eq!(result, 42);
    }

    #[test]
    fn test_multi_progress_visibility() {
        let ctx = make_quiet_context();
        let manager = MultiProgressManager::new(&ctx);
        assert!(!manager.is_visible());

        let ctx_plain = make_plain_context();
        let manager_plain = MultiProgressManager::new(&ctx_plain);
        // Plain mode is not TTY, so visibility depends on detection
        // This test just ensures no panic
        let _ = manager_plain.is_visible();
    }

    #[test]
    fn test_multi_progress_bar() {
        let ctx = make_plain_context();
        let manager = MultiProgressManager::new(&ctx);
        let pb = manager.add_progress_bar(100, "Task");
        pb.set_position(50);
        pb.finish();
    }

    #[test]
    fn test_should_show_progress() {
        let ctx_quiet = make_quiet_context();
        assert!(!should_show_progress(&ctx_quiet));

        let ctx_json = make_json_context();
        assert!(!should_show_progress(&ctx_json));
    }

    #[test]
    fn test_spinner_chars_selection() {
        let ctx = make_plain_context();
        // Plain mode typically doesn't support unicode
        let chars = spinner_chars(&ctx);
        // Just verify it returns something valid
        assert!(!chars.is_empty());
    }

    #[test]
    fn test_progress_chars_selection() {
        let ctx = make_plain_context();
        let chars = progress_chars(&ctx);
        assert!(!chars.is_empty());
    }
}
