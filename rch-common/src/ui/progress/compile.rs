//! CompilationProgress - Cargo build status visualization.
//!
//! Parses cargo output and renders compilation progress with:
//! - Crate count tracking (X/Y crates)
//! - Build phase indication (Compiling, Linking, Running tests)
//! - Rate calculation (crates/sec)
//! - Warning accumulation
//! - Optional memory usage display

use crate::ui::{Icons, OutputContext, ProgressContext};
use std::time::{Duration, Instant};

#[cfg(feature = "rich-ui")]
use crate::ui::RchTheme;
#[cfg(feature = "rich-ui")]
use rich_rust::prelude::{BarStyle, ProgressBar, Style};

const DEFAULT_BAR_WIDTH: usize = 28;
const RATE_SAMPLE_WINDOW: usize = 10;

/// Build phases during compilation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BuildPhase {
    /// Initial state before any output.
    #[default]
    Starting,
    /// Compiling crates.
    Compiling,
    /// Running build scripts (build.rs).
    BuildScript,
    /// Linking final binary.
    Linking,
    /// Running tests.
    Testing,
    /// Running documentation tests.
    DocTest,
    /// Finished (success or failure).
    Finished,
}

impl BuildPhase {
    fn label(self) -> &'static str {
        match self {
            Self::Starting => "Starting",
            Self::Compiling => "Compiling",
            Self::BuildScript => "Build script",
            Self::Linking => "Linking",
            Self::Testing => "Testing",
            Self::DocTest => "Doc tests",
            Self::Finished => "Finished",
        }
    }

    fn icon(self, ctx: OutputContext) -> &'static str {
        match self {
            Self::Starting => Icons::hourglass(ctx),
            Self::Compiling => Icons::gear(ctx),
            Self::BuildScript => Icons::gear(ctx),
            Self::Linking => Icons::transfer(ctx),
            Self::Testing => Icons::clock(ctx),
            Self::DocTest => Icons::clock(ctx),
            Self::Finished => Icons::check(ctx),
        }
    }
}

/// Parsed information from a single cargo output line.
#[derive(Debug, Clone)]
pub struct CrateInfo {
    /// Crate name.
    pub name: String,
    /// Crate version (if available).
    pub version: Option<String>,
}

/// Build configuration detected from cargo output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BuildProfile {
    #[default]
    Debug,
    Release,
}

impl BuildProfile {
    #[allow(dead_code)] // Part of public API, may be used by consumers
    fn label(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Release => "release",
        }
    }
}

/// Smoothed rate calculation for crates/sec.
#[derive(Debug, Default)]
struct RateSmoother {
    samples: Vec<f64>,
}

impl RateSmoother {
    fn push(&mut self, value: f64) {
        if value <= 0.0 || !value.is_finite() {
            return;
        }
        self.samples.push(value);
        if self.samples.len() > RATE_SAMPLE_WINDOW {
            self.samples.remove(0);
        }
    }

    fn average(&self) -> Option<f64> {
        if self.samples.is_empty() {
            return None;
        }
        let sum: f64 = self.samples.iter().sum();
        Some(sum / self.samples.len() as f64)
    }
}

/// Progress display for cargo compilation.
///
/// Parses cargo output lines and renders a compact progress display showing:
/// - Crate count (X/Y crates)
/// - Current crate being compiled
/// - Elapsed time and compilation rate
/// - Build phase (Compiling, Linking, Testing)
/// - Warning count accumulator
///
/// # Example
///
/// ```ignore
/// use rch_common::ui::{OutputContext, CompilationProgress};
///
/// let ctx = OutputContext::detect();
/// let mut progress = CompilationProgress::new(ctx, "worker1", false);
///
/// // Feed cargo output lines
/// progress.update_from_line("   Compiling serde v1.0.193");
/// progress.update_from_line("   Compiling serde_json v1.0.108");
/// progress.update_from_line("    Finished `release` profile [optimized] target(s) in 45.23s");
///
/// progress.finish();
/// ```
#[derive(Debug)]
pub struct CompilationProgress {
    ctx: OutputContext,
    worker: String,
    enabled: bool,
    progress: Option<ProgressContext>,
    start: Instant,
    phase: BuildPhase,
    profile: BuildProfile,
    crates_compiled: u32,
    crates_total: Option<u32>,
    current_crate: Option<CrateInfo>,
    warnings: u32,
    rate: RateSmoother,
    memory_mb: Option<u32>,
    last_crate_time: Instant,
    linking_start: Option<Instant>,
}

impl CompilationProgress {
    /// Create a new compilation progress display.
    pub fn new(ctx: OutputContext, worker: impl Into<String>, quiet: bool) -> Self {
        let enabled = !quiet && !ctx.is_machine();
        let progress = if enabled && matches!(ctx, OutputContext::Interactive) {
            Some(ProgressContext::new(ctx))
        } else {
            None
        };

        let now = Instant::now();
        Self {
            ctx,
            worker: worker.into(),
            enabled,
            progress,
            start: now,
            phase: BuildPhase::Starting,
            profile: BuildProfile::Debug,
            crates_compiled: 0,
            crates_total: None,
            current_crate: None,
            warnings: 0,
            rate: RateSmoother::default(),
            memory_mb: None,
            last_crate_time: now,
            linking_start: None,
        }
    }

    /// Update progress from a raw cargo output line.
    pub fn update_from_line(&mut self, line: &str) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return;
        }

        // Parse the line and update state
        self.parse_line(trimmed);
        self.render();
    }

    /// Set the total number of crates to compile.
    ///
    /// If known ahead of time (e.g., from cargo metadata),
    /// this enables percentage display.
    pub fn set_total_crates(&mut self, total: u32) {
        self.crates_total = Some(total);
    }

    /// Set memory usage (in MB) for display.
    pub fn set_memory_mb(&mut self, mb: u32) {
        self.memory_mb = Some(mb);
    }

    /// Finish the progress display and print a summary line.
    pub fn finish(&mut self) {
        if let Some(progress) = &self.progress {
            progress.clear();
        }

        if !self.enabled {
            return;
        }

        let duration = self.start.elapsed();
        let icon = Icons::check(self.ctx);
        let crates = self.crates_compiled;
        let duration_str = format_duration(duration);
        let rate = self.rate.average().unwrap_or(0.0);
        let rate_str = if rate > 0.0 {
            format!("{rate:.1} crates/sec")
        } else {
            "--".to_string()
        };

        let warnings_str = if self.warnings > 0 {
            format!(
                ", {} warning{}",
                self.warnings,
                if self.warnings == 1 { "" } else { "s" }
            )
        } else {
            String::new()
        };

        eprintln!(
            "{icon} Build complete: {crates} crates in {duration_str} ({rate_str}{warnings_str})"
        );
    }

    /// Finish with a failure message.
    pub fn finish_error(&mut self, message: &str) {
        if let Some(progress) = &self.progress {
            progress.clear();
        }

        if !self.enabled {
            return;
        }

        let icon = Icons::cross(self.ctx);
        let duration = self.start.elapsed();
        let duration_str = format_duration(duration);

        eprintln!("{icon} Build failed after {duration_str}: {message}");
    }

    /// Get the current build phase.
    #[must_use]
    pub fn phase(&self) -> BuildPhase {
        self.phase
    }

    /// Get the number of crates compiled so far.
    #[must_use]
    pub fn crates_compiled(&self) -> u32 {
        self.crates_compiled
    }

    /// Get the warning count.
    #[must_use]
    pub fn warnings(&self) -> u32 {
        self.warnings
    }

    fn parse_line(&mut self, line: &str) {
        // Check for summary warning count FIRST (before individual warning check)
        if let Some(rest) = line.strip_prefix("warning: ") {
            if let Some(count_str) = rest.strip_suffix(" warnings emitted") {
                if let Ok(count) = count_str.parse::<u32>() {
                    self.warnings = count;
                    return;
                }
            } else if rest.ends_with(" warning emitted") {
                self.warnings = 1;
                return;
            }
            // Not a summary line, fall through to individual warning check
        }

        // Check for individual warning lines
        if line.contains("warning:") && !line.starts_with("warning:") {
            // Inline warning in crate output (e.g., "src/lib.rs:10: warning: ..."), don't count
        } else if line.starts_with("warning:") || line.contains(": warning") {
            self.warnings += 1;
            return;
        }

        // Detect "Compiling crate v1.2.3"
        if let Some(rest) = line.strip_prefix("Compiling ") {
            self.phase = BuildPhase::Compiling;
            self.parse_crate_info(rest);
            self.record_crate_compiled();
            return;
        }

        // Detect build script running
        if line.starts_with("Running `") && line.contains("build-script") {
            self.phase = BuildPhase::BuildScript;
            return;
        }

        // Detect linking phase
        if line.starts_with("Linking ") || line.contains("Linking ") {
            self.phase = BuildPhase::Linking;
            self.linking_start = Some(Instant::now());
            return;
        }

        // Detect test running
        if line.starts_with("Running ") && (line.contains("tests") || line.contains("test")) {
            self.phase = BuildPhase::Testing;
            return;
        }

        // Detect doc tests
        if line.contains("Doc-tests") {
            self.phase = BuildPhase::DocTest;
            return;
        }

        // Detect finished
        if line.starts_with("Finished ") {
            self.phase = BuildPhase::Finished;
            if line.contains("`release`") || line.contains("release") {
                self.profile = BuildProfile::Release;
            }
            return;
        }

        // Detect profile from early output
        if line.contains("--release") || line.contains("`release`") {
            self.profile = BuildProfile::Release;
        }

        // Parse fresh/dirty crate messages (cargo check/clippy)
        if let Some(rest) = line.strip_prefix("Checking ") {
            self.phase = BuildPhase::Compiling;
            self.parse_crate_info(rest);
            self.record_crate_compiled();
        }
    }

    fn parse_crate_info(&mut self, rest: &str) {
        // Format: "crate_name v1.2.3" or "crate_name v1.2.3 (path+...)"
        let parts: Vec<&str> = rest.split_whitespace().collect();
        if parts.is_empty() {
            return;
        }

        let name = parts[0].to_string();
        let version = parts.get(1).and_then(|v| {
            if v.starts_with('v') || v.starts_with('V') {
                Some(v[1..].to_string())
            } else {
                Some((*v).to_string())
            }
        });

        self.current_crate = Some(CrateInfo { name, version });
    }

    fn record_crate_compiled(&mut self) {
        self.crates_compiled += 1;

        // Calculate rate
        let now = Instant::now();
        let elapsed_since_last = now.duration_since(self.last_crate_time).as_secs_f64();
        if elapsed_since_last > 0.0 {
            let rate = 1.0 / elapsed_since_last;
            self.rate.push(rate);
        }
        self.last_crate_time = now;
    }

    fn render(&mut self) {
        if !self.enabled {
            return;
        }

        let phase_icon = self.phase.icon(self.ctx);
        let worker = &self.worker;
        let elapsed = format_duration(self.start.elapsed());

        // Build progress bar
        let (bar, percent_str) = if let Some(total) = self.crates_total {
            let percent = if total > 0 {
                (self.crates_compiled as f64 / total as f64).clamp(0.0, 1.0)
            } else {
                0.0
            };
            let bar = render_bar(
                self.ctx,
                self.crates_compiled as u64,
                Some(total as u64),
                Some(percent),
                DEFAULT_BAR_WIDTH,
            );
            let pct = (percent * 100.0).round() as u32;
            (bar, format!("{pct}%"))
        } else {
            // Unknown total - show indeterminate progress
            let bar = render_bar(
                self.ctx,
                self.crates_compiled as u64,
                None,
                None,
                DEFAULT_BAR_WIDTH,
            );
            (bar, "??%".to_string())
        };

        // Crate counts
        let crates_str = if let Some(total) = self.crates_total {
            format!("{}/{} crates", self.crates_compiled, total)
        } else {
            format!("{} crates", self.crates_compiled)
        };

        // Rate
        let rate = self.rate.average().unwrap_or(0.0);
        let rate_str = if rate > 0.0 {
            format!("{rate:.1} crates/sec")
        } else {
            "--/sec".to_string()
        };

        // Current crate
        let current = self
            .current_crate
            .as_ref()
            .map(|c| {
                if let Some(v) = &c.version {
                    format!("{} v{v}", c.name)
                } else {
                    c.name.clone()
                }
            })
            .unwrap_or_else(|| "--".to_string());

        // Phase label
        let phase_label = self.phase.label();

        // Warning indicator
        let warnings_str = if self.warnings > 0 {
            let icon = Icons::warning(self.ctx);
            format!(" {icon} {}", self.warnings)
        } else {
            String::new()
        };

        // Memory indicator
        let memory_str = self
            .memory_mb
            .map(|mb| format!(" [{mb}MB]"))
            .unwrap_or_default();

        // Linking duration (if in linking phase)
        let linking_str = if self.phase == BuildPhase::Linking {
            if let Some(start) = self.linking_start {
                let dur = format_duration(start.elapsed());
                format!(" ({dur})")
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        // For single-line rendering, compress to one line
        let compact_line = format!(
            "{phase_icon} Building on {worker}  {bar} {percent_str} | {crates_str} | {elapsed} | {rate_str}{warnings_str} | {phase_label}: {current}"
        );

        if let Some(progress) = &mut self.progress {
            progress.render(&compact_line);
        }
    }
}

#[cfg(feature = "rich-ui")]
fn render_bar(
    ctx: OutputContext,
    current: u64,
    total: Option<u64>,
    percent: Option<f64>,
    width: usize,
) -> String {
    let mut bar = if let Some(total) = total {
        ProgressBar::with_total(total)
    } else {
        ProgressBar::new()
    };

    let bar_style = if ctx.supports_unicode() {
        BarStyle::Block
    } else {
        BarStyle::Ascii
    };

    let completed_style = Style::new()
        .color_str(RchTheme::SECONDARY)
        .unwrap_or_default();
    let remaining_style = Style::new().color_str("bright_black").unwrap_or_default();

    bar = bar
        .width(width)
        .bar_style(bar_style)
        .completed_style(completed_style)
        .remaining_style(remaining_style)
        .show_percentage(false)
        .show_eta(false)
        .show_speed(false)
        .show_elapsed(false);

    if let Some(total) = total {
        bar.update(current);
    } else if let Some(percent) = percent {
        bar.set_progress(percent);
    }

    bar.render_plain(width + 2).trim_end().to_string()
}

#[cfg(not(feature = "rich-ui"))]
fn render_bar(
    ctx: OutputContext,
    _current: u64,
    _total: Option<u64>,
    percent: Option<f64>,
    width: usize,
) -> String {
    let progress = percent.unwrap_or(0.0).clamp(0.0, 1.0);
    let filled = (progress * width as f64).round() as usize;
    let empty = width.saturating_sub(filled);
    let filled_char = Icons::progress_filled(ctx);
    let empty_char = Icons::progress_empty(ctx);

    let mut bar = String::from("[");
    bar.push_str(&filled_char.repeat(filled));
    bar.push_str(&empty_char.repeat(empty));
    bar.push(']');
    bar
}

fn format_duration(duration: Duration) -> String {
    let total_secs = duration.as_secs();
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
    fn parse_compiling_line() {
        let ctx = OutputContext::Plain;
        let mut progress = CompilationProgress::new(ctx, "test-worker", false);

        progress.update_from_line("   Compiling serde v1.0.193");

        assert_eq!(progress.crates_compiled(), 1);
        assert_eq!(progress.phase(), BuildPhase::Compiling);
        assert!(progress.current_crate.is_some());

        let crate_info = progress.current_crate.as_ref().unwrap();
        assert_eq!(crate_info.name, "serde");
        assert_eq!(crate_info.version.as_deref(), Some("1.0.193"));
    }

    #[test]
    fn parse_checking_line() {
        let ctx = OutputContext::Plain;
        let mut progress = CompilationProgress::new(ctx, "test-worker", false);

        progress.update_from_line("    Checking rch-common v0.1.0 (/path/to/crate)");

        assert_eq!(progress.crates_compiled(), 1);
        assert_eq!(progress.phase(), BuildPhase::Compiling);
    }

    #[test]
    fn parse_finished_line() {
        let ctx = OutputContext::Plain;
        let mut progress = CompilationProgress::new(ctx, "test-worker", false);

        progress.update_from_line("    Finished `release` profile [optimized] target(s) in 45.23s");

        assert_eq!(progress.phase(), BuildPhase::Finished);
        assert_eq!(progress.profile, BuildProfile::Release);
    }

    #[test]
    fn parse_warning_count() {
        let ctx = OutputContext::Plain;
        let mut progress = CompilationProgress::new(ctx, "test-worker", false);

        progress.update_from_line("warning: 5 warnings emitted");

        assert_eq!(progress.warnings(), 5);
    }

    #[test]
    fn parse_single_warning() {
        let ctx = OutputContext::Plain;
        let mut progress = CompilationProgress::new(ctx, "test-worker", false);

        progress.update_from_line("warning: 1 warning emitted");

        assert_eq!(progress.warnings(), 1);
    }

    #[test]
    fn parse_linking_phase() {
        let ctx = OutputContext::Plain;
        let mut progress = CompilationProgress::new(ctx, "test-worker", false);

        progress.update_from_line("   Linking target/release/myapp");

        assert_eq!(progress.phase(), BuildPhase::Linking);
        assert!(progress.linking_start.is_some());
    }

    #[test]
    fn parse_testing_phase() {
        let ctx = OutputContext::Plain;
        let mut progress = CompilationProgress::new(ctx, "test-worker", false);

        progress.update_from_line("     Running unittests src/lib.rs (target/debug/deps/rch-...)");

        assert_eq!(progress.phase(), BuildPhase::Testing);
    }

    #[test]
    fn multiple_crates_compiled() {
        let ctx = OutputContext::Plain;
        let mut progress = CompilationProgress::new(ctx, "test-worker", false);

        progress.update_from_line("   Compiling serde v1.0.193");
        progress.update_from_line("   Compiling serde_json v1.0.108");
        progress.update_from_line("   Compiling tokio v1.35.1");

        assert_eq!(progress.crates_compiled(), 3);
    }

    #[test]
    fn total_crates_percentage() {
        let ctx = OutputContext::Plain;
        let mut progress = CompilationProgress::new(ctx, "test-worker", true); // quiet mode

        progress.set_total_crates(100);
        progress.update_from_line("   Compiling crate1 v0.1.0");
        progress.update_from_line("   Compiling crate2 v0.1.0");

        assert_eq!(progress.crates_compiled(), 2);
        // 2/100 = 2%
    }

    #[test]
    fn format_duration_seconds() {
        let dur = Duration::from_secs_f64(45.7);
        assert_eq!(format_duration(dur), "45.7s");
    }

    #[test]
    fn format_duration_minutes() {
        let dur = Duration::from_secs(125);
        assert_eq!(format_duration(dur), "2:05");
    }

    #[test]
    fn format_duration_hours() {
        let dur = Duration::from_secs(3725);
        assert_eq!(format_duration(dur), "1:02:05");
    }

    #[test]
    fn rate_smoother_average() {
        let mut smoother = RateSmoother::default();
        smoother.push(1.0);
        smoother.push(2.0);
        smoother.push(3.0);

        let avg = smoother.average().unwrap();
        assert!((avg - 2.0).abs() < 0.001);
    }

    #[test]
    fn rate_smoother_ignores_invalid() {
        let mut smoother = RateSmoother::default();
        smoother.push(-1.0);
        smoother.push(f64::NAN);
        smoother.push(0.0);

        assert!(smoother.average().is_none());
    }
}
