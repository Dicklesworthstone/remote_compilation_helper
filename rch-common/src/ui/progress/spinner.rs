//! AnimatedSpinner - Indeterminate progress display for unknown-duration operations.
//!
//! Provides animated spinners with:
//! - Multiple spinner styles: dots, braille, arrows, bouncing bar
//! - Message alongside spinner with elapsed time
//! - Spinner-to-progress-bar transition when total becomes known
//! - Success/failure final state replacement
//! - Nested spinners for sub-operations
//!
//! # Example
//!
//! ```ignore
//! use rch_common::ui::{OutputContext, AnimatedSpinner, SpinnerStyle};
//!
//! let ctx = OutputContext::detect();
//! let mut spinner = AnimatedSpinner::new(ctx, "Connecting to worker...");
//!
//! // Later, when operation completes:
//! spinner.finish_success("Connected to worker1");
//! // Or on failure:
//! spinner.finish_error("Connection refused");
//! ```

use crate::ui::{Icons, OutputContext, ProgressContext};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Spinner animation style.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SpinnerStyle {
    /// Unicode braille dots animation (⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏).
    #[default]
    Dots,
    /// Arrow rotation (← ↖ ↑ ↗ → ↘ ↓ ↙).
    Arrows,
    /// Bouncing bar animation ([=    ] [==   ] ...).
    Bounce,
    /// Simple ASCII rotation (| / - \).
    Ascii,
}

impl SpinnerStyle {
    /// Get the animation frames for this style.
    fn frames(self, supports_unicode: bool) -> &'static [&'static str] {
        if !supports_unicode {
            return Self::ASCII_FRAMES;
        }

        match self {
            Self::Dots => Self::DOTS_FRAMES,
            Self::Arrows => Self::ARROWS_FRAMES,
            Self::Bounce => Self::BOUNCE_FRAMES,
            Self::Ascii => Self::ASCII_FRAMES,
        }
    }

    const DOTS_FRAMES: &'static [&'static str] =
        &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

    const ARROWS_FRAMES: &'static [&'static str] = &["←", "↖", "↑", "↗", "→", "↘", "↓", "↙"];

    const BOUNCE_FRAMES: &'static [&'static str] = &[
        "[=    ]", "[ =   ]", "[  =  ]", "[   = ]", "[    =]", "[   = ]", "[  =  ]", "[ =   ]",
    ];

    const ASCII_FRAMES: &'static [&'static str] = &["|", "/", "-", "\\"];
}

/// Final state of a spinner operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpinnerResult {
    /// Operation completed successfully.
    Success,
    /// Operation failed.
    Error,
    /// Operation was cancelled/skipped.
    Skipped,
}

/// Shared state for nested spinners (thread-safe).
#[derive(Debug)]
struct SharedSpinnerState {
    /// Current frame index across all spinners.
    frame_index: AtomicUsize,
    /// Last frame update time (nanoseconds since epoch).
    #[allow(dead_code)]
    last_frame_ns: AtomicU64,
    /// Number of active spinners.
    #[allow(dead_code)]
    active_count: AtomicUsize,
}

impl SharedSpinnerState {
    fn new() -> Self {
        Self {
            frame_index: AtomicUsize::new(0),
            last_frame_ns: AtomicU64::new(0),
            active_count: AtomicUsize::new(0),
        }
    }

    fn next_frame(&self, frame_count: usize) -> usize {
        let idx = self.frame_index.fetch_add(1, Ordering::Relaxed);
        idx % frame_count
    }
}

/// Animated spinner for indeterminate progress.
///
/// Displays an animated spinner with a message and elapsed time.
/// Thread-safe and uses RAII for clean terminal state on drop.
///
/// # Features
///
/// - Automatic rate limiting (10 FPS / 100ms per frame)
/// - Multiple animation styles
/// - Elapsed time display
/// - Success/failure/skipped final states
/// - Transition to progress bar when total becomes known
///
/// # Example
///
/// ```ignore
/// let mut spinner = AnimatedSpinner::new(ctx, "Connecting to worker...");
///
/// // Animate while working...
/// for _ in 0..100 {
///     spinner.tick(); // Call periodically to animate
///     std::thread::sleep(std::time::Duration::from_millis(50));
/// }
///
/// // When done:
/// spinner.finish_success("Connected!");
/// ```
#[derive(Debug)]
pub struct AnimatedSpinner {
    ctx: OutputContext,
    style: SpinnerStyle,
    message: String,
    enabled: bool,
    progress: Option<ProgressContext>,
    start: Instant,
    shared_state: Arc<SharedSpinnerState>,
    frame_interval: Duration,
    last_frame: Instant,
    finished: bool,
    /// Optional progress bar state for transition.
    progress_state: Option<ProgressBarState>,
}

/// State for spinner-to-progress-bar transition.
#[derive(Debug)]
struct ProgressBarState {
    current: u64,
    total: u64,
}

impl AnimatedSpinner {
    /// Create a new animated spinner.
    pub fn new(ctx: OutputContext, message: impl Into<String>) -> Self {
        Self::with_style(ctx, message, SpinnerStyle::default())
    }

    /// Create a spinner with a specific animation style.
    pub fn with_style(ctx: OutputContext, message: impl Into<String>, style: SpinnerStyle) -> Self {
        let enabled = !ctx.is_machine();
        let progress = if enabled && matches!(ctx, OutputContext::Interactive) {
            Some(ProgressContext::new(ctx))
        } else {
            None
        };

        let now = Instant::now();
        Self {
            ctx,
            style,
            message: message.into(),
            enabled,
            progress,
            start: now,
            shared_state: Arc::new(SharedSpinnerState::new()),
            frame_interval: Duration::from_millis(100), // 10 FPS
            last_frame: now,
            finished: false,
            progress_state: None,
        }
    }

    /// Create a nested spinner that shares animation state with parent.
    ///
    /// Nested spinners synchronize their animation frames for visual coherence.
    pub fn nested(&self, message: impl Into<String>) -> Self {
        let enabled = self.enabled;
        let progress = if enabled && matches!(self.ctx, OutputContext::Interactive) {
            Some(ProgressContext::new(self.ctx))
        } else {
            None
        };

        let now = Instant::now();
        Self {
            ctx: self.ctx,
            style: self.style,
            message: message.into(),
            enabled,
            progress,
            start: now,
            shared_state: Arc::clone(&self.shared_state),
            frame_interval: self.frame_interval,
            last_frame: now,
            finished: false,
            progress_state: None,
        }
    }

    /// Set the spinner message.
    pub fn set_message(&mut self, message: impl Into<String>) {
        self.message = message.into();
    }

    /// Update the spinner animation.
    ///
    /// Call this periodically while the operation is in progress.
    /// Rate-limited to 10 FPS automatically.
    pub fn tick(&mut self) {
        if !self.enabled || self.finished {
            return;
        }

        let now = Instant::now();
        if now.duration_since(self.last_frame) < self.frame_interval {
            return;
        }
        self.last_frame = now;

        self.render();
    }

    /// Transition the spinner to a progress bar.
    ///
    /// When the total count becomes known, the spinner transforms into
    /// a determinate progress bar.
    pub fn set_total(&mut self, total: u64) {
        self.progress_state = Some(ProgressBarState { current: 0, total });
    }

    /// Update progress when in progress bar mode.
    pub fn set_progress(&mut self, current: u64) {
        if let Some(state) = &mut self.progress_state {
            state.current = current;
        }
        self.tick();
    }

    /// Increment progress by one.
    pub fn inc(&mut self) {
        if let Some(state) = &mut self.progress_state {
            state.current = state.current.saturating_add(1);
        }
        self.tick();
    }

    /// Get elapsed time since spinner started.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    /// Finish with success state.
    pub fn finish_success(&mut self, message: impl Into<String>) {
        self.finish_with(SpinnerResult::Success, message);
    }

    /// Finish with error state.
    pub fn finish_error(&mut self, message: impl Into<String>) {
        self.finish_with(SpinnerResult::Error, message);
    }

    /// Finish with skipped state.
    pub fn finish_skipped(&mut self, message: impl Into<String>) {
        self.finish_with(SpinnerResult::Skipped, message);
    }

    /// Finish with a specific result state.
    pub fn finish_with(&mut self, result: SpinnerResult, message: impl Into<String>) {
        if self.finished {
            return;
        }
        self.finished = true;

        if let Some(progress) = &self.progress {
            progress.clear();
        }

        if !self.enabled {
            return;
        }

        let icon = match result {
            SpinnerResult::Success => Icons::check(self.ctx),
            SpinnerResult::Error => Icons::cross(self.ctx),
            SpinnerResult::Skipped => Icons::arrow_right(self.ctx),
        };

        let elapsed = format_duration(self.elapsed());
        let msg = message.into();

        eprintln!("{icon} {msg}  {elapsed}");
    }

    /// Clear the spinner without printing a final message.
    pub fn clear(&mut self) {
        self.finished = true;
        if let Some(progress) = &self.progress {
            progress.clear();
        }
    }

    fn render(&mut self) {
        if !self.enabled {
            return;
        }

        // Check if we should render as progress bar
        if let Some(state) = &self.progress_state {
            self.render_progress_bar(state.current, state.total);
            return;
        }

        let supports_unicode = self.ctx.supports_unicode();
        let frames = self.style.frames(supports_unicode);
        let frame_idx = self.shared_state.next_frame(frames.len());
        let frame = frames[frame_idx];

        let elapsed = format_duration(self.elapsed());
        let line = format!("{frame} {}  {elapsed}", self.message);

        if let Some(progress) = &mut self.progress {
            progress.render(&line);
        }
    }

    fn render_progress_bar(&mut self, current: u64, total: u64) {
        if !self.enabled {
            return;
        }

        let percent = if total > 0 {
            (current as f64 / total as f64).clamp(0.0, 1.0)
        } else {
            0.0
        };

        let bar = render_bar(self.ctx, percent, 20);
        let pct = (percent * 100.0).round() as u32;
        let elapsed = format_duration(self.elapsed());
        let line = format!("{bar} {pct}% | {} | {elapsed}", self.message);

        if let Some(progress) = &mut self.progress {
            progress.render(&line);
        }
    }
}

impl Drop for AnimatedSpinner {
    fn drop(&mut self) {
        if !self.finished {
            // Clean up without printing if dropped before finish
            if let Some(progress) = &self.progress {
                progress.clear();
            }
        }
    }
}

/// Render a simple progress bar.
fn render_bar(ctx: OutputContext, percent: f64, width: usize) -> String {
    let filled = (percent * width as f64).round() as usize;
    let empty = width.saturating_sub(filled);

    let (filled_char, empty_char) = if ctx.supports_unicode() {
        ("█", "░")
    } else {
        ("#", "-")
    };

    let mut bar = String::from("[");
    bar.push_str(&filled_char.repeat(filled));
    bar.push_str(&empty_char.repeat(empty));
    bar.push(']');
    bar
}

/// Format a duration for display.
fn format_duration(duration: Duration) -> String {
    let total_secs = duration.as_secs_f64();
    if total_secs < 60.0 {
        format!("{total_secs:.1}s")
    } else {
        let mins = (total_secs / 60.0).floor() as u64;
        let secs = (total_secs % 60.0).round() as u64;
        format!("{mins}:{secs:02}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spinner_style_frames_count() {
        assert_eq!(SpinnerStyle::DOTS_FRAMES.len(), 10);
        assert_eq!(SpinnerStyle::ARROWS_FRAMES.len(), 8);
        assert_eq!(SpinnerStyle::BOUNCE_FRAMES.len(), 8);
        assert_eq!(SpinnerStyle::ASCII_FRAMES.len(), 4);
    }

    #[test]
    fn spinner_style_ascii_fallback() {
        let dots = SpinnerStyle::Dots;
        let ascii_frames = dots.frames(false);
        assert_eq!(ascii_frames, SpinnerStyle::ASCII_FRAMES);
    }

    #[test]
    fn spinner_style_unicode_frames() {
        let dots = SpinnerStyle::Dots;
        let frames = dots.frames(true);
        assert_eq!(frames, SpinnerStyle::DOTS_FRAMES);
    }

    #[test]
    fn spinner_creates_with_message() {
        let ctx = OutputContext::Plain;
        let spinner = AnimatedSpinner::new(ctx, "Testing...");
        assert_eq!(spinner.message, "Testing...");
        assert!(!spinner.finished);
    }

    #[test]
    fn spinner_disabled_in_machine_mode() {
        let ctx = OutputContext::Machine;
        let spinner = AnimatedSpinner::new(ctx, "Testing...");
        assert!(!spinner.enabled);
    }

    #[test]
    fn spinner_set_message() {
        let ctx = OutputContext::Plain;
        let mut spinner = AnimatedSpinner::new(ctx, "Initial");
        spinner.set_message("Updated");
        assert_eq!(spinner.message, "Updated");
    }

    #[test]
    fn spinner_elapsed_increases() {
        let ctx = OutputContext::Plain;
        let spinner = AnimatedSpinner::new(ctx, "Testing...");
        std::thread::sleep(Duration::from_millis(10));
        assert!(spinner.elapsed() >= Duration::from_millis(10));
    }

    #[test]
    fn spinner_finish_marks_finished() {
        let ctx = OutputContext::Plain;
        let mut spinner = AnimatedSpinner::new(ctx, "Testing...");
        assert!(!spinner.finished);
        spinner.finish_success("Done!");
        assert!(spinner.finished);
    }

    #[test]
    fn spinner_finish_idempotent() {
        let ctx = OutputContext::Plain;
        let mut spinner = AnimatedSpinner::new(ctx, "Testing...");
        spinner.finish_success("Done 1");
        spinner.finish_success("Done 2"); // Should not panic or double-print
        assert!(spinner.finished);
    }

    #[test]
    fn spinner_clear() {
        let ctx = OutputContext::Plain;
        let mut spinner = AnimatedSpinner::new(ctx, "Testing...");
        spinner.clear();
        assert!(spinner.finished);
    }

    #[test]
    fn spinner_nested_shares_state() {
        let ctx = OutputContext::Plain;
        let parent = AnimatedSpinner::new(ctx, "Parent");
        let child = parent.nested("Child");

        // Both should reference the same shared state
        assert!(Arc::ptr_eq(&parent.shared_state, &child.shared_state));
    }

    #[test]
    fn spinner_progress_transition() {
        let ctx = OutputContext::Plain;
        let mut spinner = AnimatedSpinner::new(ctx, "Processing...");

        assert!(spinner.progress_state.is_none());

        spinner.set_total(100);
        assert!(spinner.progress_state.is_some());
        assert_eq!(spinner.progress_state.as_ref().unwrap().total, 100);
        assert_eq!(spinner.progress_state.as_ref().unwrap().current, 0);

        spinner.set_progress(50);
        assert_eq!(spinner.progress_state.as_ref().unwrap().current, 50);

        spinner.inc();
        assert_eq!(spinner.progress_state.as_ref().unwrap().current, 51);
    }

    #[test]
    fn format_duration_seconds() {
        let dur = Duration::from_secs_f64(5.7);
        assert_eq!(format_duration(dur), "5.7s");
    }

    #[test]
    fn format_duration_minutes() {
        let dur = Duration::from_secs(125);
        assert_eq!(format_duration(dur), "2:05");
    }

    #[test]
    fn render_bar_empty() {
        let bar = render_bar(OutputContext::Plain, 0.0, 10);
        assert_eq!(bar, "[----------]");
    }

    #[test]
    fn render_bar_full() {
        let bar = render_bar(OutputContext::Plain, 1.0, 10);
        assert_eq!(bar, "[##########]");
    }

    #[test]
    fn render_bar_half() {
        let bar = render_bar(OutputContext::Plain, 0.5, 10);
        assert_eq!(bar, "[#####-----]");
    }

    #[test]
    fn shared_state_next_frame_wraps() {
        let state = SharedSpinnerState::new();

        // Advance past frame count
        for i in 0..15 {
            let frame = state.next_frame(4);
            assert!(frame < 4, "Frame {frame} at iteration {i} should be < 4");
        }
    }

    #[test]
    fn spinner_result_variants() {
        assert_ne!(SpinnerResult::Success, SpinnerResult::Error);
        assert_ne!(SpinnerResult::Error, SpinnerResult::Skipped);
        assert_ne!(SpinnerResult::Success, SpinnerResult::Skipped);
    }

    #[test]
    fn spinner_style_default_is_dots() {
        assert_eq!(SpinnerStyle::default(), SpinnerStyle::Dots);
    }
}
