//! CompletionCelebration - Success feedback for completed builds.
//!
//! Renders a compact success panel with build summary, cache impact, and
//! optional "personal best" or milestone callouts. Uses plain ASCII by
//! default and rich_rust panels when available.

use crate::ui::{Icons, OutputContext, RchTheme};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

#[cfg(feature = "rich-ui")]
use rich_rust::r#box::HEAVY;
#[cfg(feature = "rich-ui")]
use rich_rust::prelude::*;

const HISTORY_LIMIT: usize = 200;
const MAX_RENDER_WIDTH: usize = 80;

/// Summary of artifacts returned from a successful build.
#[derive(Debug, Clone)]
pub struct ArtifactSummary {
    pub files: u64,
    pub bytes: u64,
}

/// Summary information for a completed build.
#[derive(Debug, Clone)]
pub struct CelebrationSummary {
    pub project_id: String,
    pub worker: Option<String>,
    pub duration_ms: u64,
    pub crates_compiled: Option<u32>,
    pub artifacts: Option<ArtifactSummary>,
    pub cache_hit: Option<bool>,
    pub target: Option<String>,
    pub quiet: bool,
    pub timestamp: DateTime<Utc>,
}

impl CelebrationSummary {
    #[must_use]
    pub fn new(project_id: impl Into<String>, duration_ms: u64) -> Self {
        Self {
            project_id: project_id.into(),
            worker: None,
            duration_ms,
            crates_compiled: None,
            artifacts: None,
            cache_hit: None,
            target: None,
            quiet: false,
            timestamp: Utc::now(),
        }
    }

    #[must_use]
    pub fn worker(mut self, worker: impl Into<String>) -> Self {
        self.worker = Some(worker.into());
        self
    }

    #[must_use]
    pub fn crates_compiled(mut self, crates: Option<u32>) -> Self {
        self.crates_compiled = crates;
        self
    }

    #[must_use]
    pub fn artifacts(mut self, artifacts: Option<ArtifactSummary>) -> Self {
        self.artifacts = artifacts;
        self
    }

    #[must_use]
    pub fn cache_hit(mut self, cache_hit: Option<bool>) -> Self {
        self.cache_hit = cache_hit;
        self
    }

    #[must_use]
    pub fn target(mut self, target: Option<String>) -> Self {
        self.target = target;
        self
    }

    #[must_use]
    pub fn quiet(mut self, quiet: bool) -> Self {
        self.quiet = quiet;
        self
    }

    #[must_use]
    pub fn timestamp(mut self, timestamp: DateTime<Utc>) -> Self {
        self.timestamp = timestamp;
        self
    }
}

/// Render and record a completion celebration.
#[derive(Debug, Clone)]
pub struct CompletionCelebration {
    summary: CelebrationSummary,
}

impl CompletionCelebration {
    #[must_use]
    pub fn new(summary: CelebrationSummary) -> Self {
        Self { summary }
    }

    /// Record build history and render success feedback (if enabled).
    pub fn record_and_render(&self, ctx: OutputContext) {
        let history_path = match history_path() {
            Some(path) => path,
            None => {
                if !self.summary.quiet && !ctx.is_machine() {
                    self.render(ctx, BuildStats::default());
                }
                return;
            }
        };

        let mut history = BuildHistory::load(&history_path);
        let mut stats = history.stats_for_project(&self.summary.project_id);
        stats = compute_stats(&self.summary, stats);

        // Record current build after computing comparisons.
        let entry = BuildHistoryEntry::from_summary(&self.summary);
        history.record(entry);
        let _ = history.save(&history_path);

        if self.summary.quiet || ctx.is_machine() {
            return;
        }

        self.render(ctx, stats);
    }

    fn render(&self, ctx: OutputContext, stats: BuildStats) {
        #[cfg(feature = "rich-ui")]
        if ctx.supports_rich() {
            self.render_rich(ctx, stats);
            return;
        }

        self.render_plain(ctx, stats);
    }

    #[cfg(feature = "rich-ui")]
    fn render_rich(&self, ctx: OutputContext, stats: BuildStats) {
        let title = self.title_line(ctx, &stats);
        let content = self.render_lines(ctx, &stats).join("\n");

        let border_color = Color::parse(RchTheme::SUCCESS).unwrap_or_else(|_| Color::default());
        let border_style = Style::new().bold().color(border_color);

        let panel = Panel::from_text(&content)
            .title(title.as_str())
            .border_style(border_style)
            .box_style(&HEAVY);

        let console = Console::builder().force_terminal(true).build();
        console.print_renderable(&panel);
    }

    fn render_plain(&self, ctx: OutputContext, stats: BuildStats) {
        let title = self.title_line(ctx, &stats);
        let lines = self.render_lines(ctx, &stats);
        let rendered = render_box(ctx, &title, &lines);
        eprintln!("{rendered}");
    }

    fn title_line(&self, ctx: OutputContext, stats: &BuildStats) -> String {
        let icon = if stats.is_record || stats.milestone.is_some() {
            star_icon(ctx)
        } else {
            Icons::check(ctx)
        };
        format!("{icon} Build Successful")
    }

    fn render_lines(&self, ctx: OutputContext, stats: &BuildStats) -> Vec<String> {
        let mut lines = Vec::new();
        let duration_str = format_duration_ms(self.summary.duration_ms);

        if stats.is_record
            && let Some(best_ms) = stats.best_ms
            && best_ms > 0
        {
            lines.push(format!(
                "New personal best! {duration_str} (previous: {})",
                format_duration_ms(best_ms)
            ));
        }

        if let Some(milestone) = stats.milestone {
            lines.push(format!(
                "This is your {} successful RCH build!",
                format_ordinal(milestone)
            ));
        }

        if let Some(target) = &self.summary.target {
            lines.push(format!("Target: {}", target));
        }

        let mut duration_line = format!("Duration: {}", duration_str);
        if let Some(comparison) = &stats.comparison {
            duration_line.push_str(&format!(" {}", comparison.format(ctx)));
        }
        lines.push(duration_line);

        let crates_line = self
            .summary
            .crates_compiled
            .map(|count| format!("Crates: {}", count));

        let artifacts_line = self.summary.artifacts.as_ref().map(|artifacts| {
            format!(
                "Artifacts: {} files ({})",
                artifacts.files,
                format_bytes(artifacts.bytes)
            )
        });

        match (crates_line, artifacts_line) {
            (Some(crates), Some(artifacts)) => {
                lines.push(format!("{} | {}", crates, artifacts));
            }
            (Some(line), None) | (None, Some(line)) => {
                lines.push(line);
            }
            (None, None) => {}
        }

        if let Some(worker) = &self.summary.worker {
            lines.push(format!("Worker: {}", worker));
        }

        if let Some(cache_line) = cache_line(&self.summary, stats) {
            lines.push(cache_line);
        }

        lines.push(format!(
            "Time: {}",
            self.summary.timestamp.format("%Y-%m-%d %H:%M:%S")
        ));

        lines
    }
}

// ========================================================================
// History
// ========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BuildHistoryEntry {
    project_id: String,
    duration_ms: u64,
    timestamp: DateTime<Utc>,
    cache_hit: Option<bool>,
}

impl BuildHistoryEntry {
    fn from_summary(summary: &CelebrationSummary) -> Self {
        Self {
            project_id: summary.project_id.clone(),
            duration_ms: summary.duration_ms,
            timestamp: summary.timestamp,
            cache_hit: summary.cache_hit,
        }
    }
}

#[derive(Debug, Default)]
struct BuildHistory {
    entries: Vec<BuildHistoryEntry>,
}

impl BuildHistory {
    fn load(path: &Path) -> Self {
        let content = fs::read_to_string(path).ok();
        let entries = content
            .and_then(|text| serde_json::from_str::<Vec<BuildHistoryEntry>>(&text).ok())
            .unwrap_or_default();
        Self { entries }
    }

    fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&self.entries).unwrap_or_else(|_| "[]".into());
        atomic_write(path, json.as_bytes())
    }

    fn record(&mut self, entry: BuildHistoryEntry) {
        self.entries.push(entry);
        if self.entries.len() > HISTORY_LIMIT {
            let overflow = self.entries.len() - HISTORY_LIMIT;
            self.entries.drain(0..overflow);
        }
    }

    fn stats_for_project(&self, project_id: &str) -> BuildStats {
        let mut stats = BuildStats::default();
        let mut durations = Vec::new();

        for entry in self
            .entries
            .iter()
            .filter(|entry| entry.project_id == project_id)
        {
            durations.push(entry.duration_ms);
        }

        stats.count = durations.len() as u64;
        stats.previous_ms = durations.last().copied();
        stats.best_ms = durations.iter().min().copied();
        stats.average_ms = if durations.is_empty() {
            None
        } else {
            Some(durations.iter().sum::<u64>() / durations.len() as u64)
        };

        stats
    }
}

fn history_path() -> Option<PathBuf> {
    dirs::cache_dir().map(|dir| dir.join("rch").join("history.json"))
}

fn atomic_write(path: &Path, content: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let temp = parent.join(format!(".history.{}.tmp", std::process::id()));
    fs::write(&temp, content)?;
    fs::rename(temp, path)?;
    Ok(())
}

// ========================================================================
// Rendering helpers
// ========================================================================

#[derive(Debug, Default, Clone)]
struct BuildStats {
    count: u64,
    previous_ms: Option<u64>,
    best_ms: Option<u64>,
    average_ms: Option<u64>,
    comparison: Option<Comparison>,
    milestone: Option<u64>,
    is_record: bool,
}

#[derive(Debug, Clone)]
struct Comparison {
    percent: f64,
    faster: bool,
    baseline_ms: u64,
}

impl Comparison {
    fn format(&self, ctx: OutputContext) -> String {
        let arrow = if self.faster {
            Icons::arrow_down(ctx)
        } else {
            Icons::arrow_up(ctx)
        };
        let speed = if self.faster { "faster" } else { "slower" };
        format!(
            "({} {:.0}% {} vs previous {})",
            arrow,
            self.percent,
            speed,
            format_duration_ms(self.baseline_ms)
        )
    }
}

fn cache_line(summary: &CelebrationSummary, stats: &BuildStats) -> Option<String> {
    match summary.cache_hit {
        Some(true) => {
            let baseline = stats.average_ms.or(stats.previous_ms);
            let saved = baseline
                .and_then(|base| base.checked_sub(summary.duration_ms))
                .filter(|saved| *saved >= 1_000);
            if let Some(saved) = saved {
                Some(format!("Cache: HIT (saved ~{})", format_duration_ms(saved)))
            } else {
                Some("Cache: HIT".to_string())
            }
        }
        Some(false) => Some("Cache: MISS (warming cache)".to_string()),
        None => None,
    }
}

fn render_box(ctx: OutputContext, title: &str, raw_lines: &[String]) -> String {
    let (tl, tr, bl, br, h, v) = if ctx.supports_unicode() {
        ("╭", "╮", "╰", "╯", "─", "│")
    } else {
        ("+", "+", "+", "+", "-", "|")
    };

    let title = truncate_line(title, MAX_RENDER_WIDTH);
    let mut lines: Vec<String> = raw_lines
        .iter()
        .map(|line| truncate_line(line, MAX_RENDER_WIDTH))
        .collect();

    let content_width = lines
        .iter()
        .map(|line| UnicodeWidthStr::width(line.as_str()))
        .max()
        .unwrap_or(0)
        .max(UnicodeWidthStr::width(title.as_str()));

    let inner_width = content_width.max(1);
    let mut output = String::new();

    let title_padding = inner_width
        .saturating_sub(UnicodeWidthStr::width(title.as_str()))
        .saturating_sub(2);
    let title_left = title_padding / 2;
    let title_right = title_padding - title_left;

    output.push_str(tl);
    output.push_str(&h.repeat(title_left + 1));
    output.push_str(&format!(" {title} "));
    output.push_str(&h.repeat(title_right + 1));
    output.push_str(tr);
    output.push('\n');

    if lines.is_empty() {
        lines.push(String::new());
    }

    for line in lines {
        let padding = inner_width.saturating_sub(UnicodeWidthStr::width(line.as_str()));
        output.push_str(v);
        output.push(' ');
        output.push_str(&line);
        output.push_str(&" ".repeat(padding));
        output.push(' ');
        output.push_str(v);
        output.push('\n');
    }

    output.push_str(bl);
    output.push_str(&h.repeat(inner_width + 2));
    output.push_str(br);
    output
}

fn truncate_line(line: &str, max_width: usize) -> String {
    if UnicodeWidthStr::width(line) <= max_width {
        return line.to_string();
    }

    let ellipsis = "...";
    let max_content = max_width.saturating_sub(ellipsis.len());
    let mut out = String::new();
    let mut width = 0;

    for ch in line.chars() {
        let w = UnicodeWidthChar::width(ch).unwrap_or(0);
        if width + w > max_content {
            break;
        }
        out.push(ch);
        width += w;
    }

    out.push_str(ellipsis);
    out
}

fn format_duration_ms(ms: u64) -> String {
    if ms >= 60_000 {
        format!("{:.1}m", ms as f64 / 60_000.0)
    } else if ms >= 1000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else {
        format!("{}ms", ms)
    }
}

fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    let bytes_f = bytes as f64;
    if bytes_f >= GB {
        format!("{:.1} GB", bytes_f / GB)
    } else if bytes_f >= MB {
        format!("{:.1} MB", bytes_f / MB)
    } else if bytes_f >= KB {
        format!("{:.1} KB", bytes_f / KB)
    } else {
        format!("{} B", bytes)
    }
}

fn star_icon(ctx: OutputContext) -> &'static str {
    if ctx.supports_unicode() { "★" } else { "*" }
}

fn format_ordinal(value: u64) -> String {
    let suffix = match value % 100 {
        11..=13 => "th",
        _ => match value % 10 {
            1 => "st",
            2 => "nd",
            3 => "rd",
            _ => "th",
        },
    };
    format!("{}{}", value, suffix)
}

// ========================================================================
// Stats derivation
// ========================================================================

fn compute_stats(summary: &CelebrationSummary, mut stats: BuildStats) -> BuildStats {
    if let Some(previous_ms) = stats.previous_ms
        && previous_ms > 0
    {
        let diff = summary.duration_ms as f64 - previous_ms as f64;
        let percent = (diff.abs() / previous_ms as f64) * 100.0;
        if percent >= 1.0 {
            stats.comparison = Some(Comparison {
                percent,
                faster: diff < 0.0,
                baseline_ms: previous_ms,
            });
        }
    }

    if let Some(best_ms) = stats.best_ms {
        stats.is_record = summary.duration_ms < best_ms;
    }

    let next_count = stats.count + 1;
    if next_count > 0 && next_count.is_multiple_of(100) {
        stats.milestone = Some(next_count);
    }

    stats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_stats_sets_comparison_when_faster() {
        let summary = CelebrationSummary::new("proj", 9_000);
        let stats = BuildStats {
            previous_ms: Some(10_000),
            ..BuildStats::default()
        };

        let stats = compute_stats(&summary, stats);
        let comparison = stats.comparison.expect("comparison should be set");

        assert!(comparison.faster);
        assert_eq!(comparison.baseline_ms, 10_000);
        assert!((comparison.percent - 10.0).abs() < 0.01);
    }

    #[test]
    fn compute_stats_sets_comparison_when_slower() {
        let summary = CelebrationSummary::new("proj", 11_000);
        let stats = BuildStats {
            previous_ms: Some(10_000),
            ..BuildStats::default()
        };

        let stats = compute_stats(&summary, stats);
        let comparison = stats.comparison.expect("comparison should be set");

        assert!(!comparison.faster);
        assert_eq!(comparison.baseline_ms, 10_000);
        assert!((comparison.percent - 10.0).abs() < 0.01);
    }

    #[test]
    fn compute_stats_sets_record_and_milestone() {
        let summary = CelebrationSummary::new("proj", 7_000);
        let stats = BuildStats {
            count: 99,
            best_ms: Some(8_000),
            ..BuildStats::default()
        };

        let stats = compute_stats(&summary, stats);
        assert!(stats.is_record);
        assert_eq!(stats.milestone, Some(100));
    }

    #[test]
    fn cache_line_reports_saved_time_on_hit() {
        let summary = CelebrationSummary::new("proj", 9_000).cache_hit(Some(true));
        let stats = BuildStats {
            average_ms: Some(20_000),
            ..BuildStats::default()
        };

        let line = cache_line(&summary, &stats).expect("cache line");
        assert!(line.contains("Cache: HIT"));
        assert!(line.contains("saved ~"));
    }

    #[test]
    fn render_box_uses_ascii_when_unicode_not_supported() {
        let ctx = OutputContext::plain();
        let rendered = render_box(ctx, "Build Successful", &[String::from("Duration: 1.0s")]);
        let first_line = rendered.lines().next().unwrap_or_default();
        assert!(first_line.starts_with('+'));
        assert!(rendered.contains('|'));
        assert!(!rendered.contains('╭'));
    }

    #[test]
    fn build_history_enforces_limit() {
        let mut history = BuildHistory::default();

        for idx in 0..(HISTORY_LIMIT + 10) {
            history.record(BuildHistoryEntry {
                project_id: "proj".to_string(),
                duration_ms: idx as u64,
                timestamp: Utc::now(),
                cache_hit: None,
            });
        }

        assert_eq!(history.entries.len(), HISTORY_LIMIT);
    }

    // -------------------------------------------------------------------------
    // Format utility tests
    // -------------------------------------------------------------------------

    #[test]
    fn format_duration_ms_milliseconds() {
        assert_eq!(format_duration_ms(500), "500ms");
        assert_eq!(format_duration_ms(0), "0ms");
        assert_eq!(format_duration_ms(999), "999ms");
    }

    #[test]
    fn format_duration_ms_seconds() {
        assert_eq!(format_duration_ms(1000), "1.0s");
        assert_eq!(format_duration_ms(1500), "1.5s");
        assert_eq!(format_duration_ms(59_999), "60.0s");
    }

    #[test]
    fn format_duration_ms_minutes() {
        assert_eq!(format_duration_ms(60_000), "1.0m");
        assert_eq!(format_duration_ms(90_000), "1.5m");
        assert_eq!(format_duration_ms(120_000), "2.0m");
    }

    #[test]
    fn format_bytes_plain_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1023), "1023 B");
    }

    #[test]
    fn format_bytes_kilobytes() {
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(10_240), "10.0 KB");
    }

    #[test]
    fn format_bytes_megabytes() {
        assert_eq!(format_bytes(1_048_576), "1.0 MB");
        assert_eq!(format_bytes(5_242_880), "5.0 MB");
    }

    #[test]
    fn format_bytes_gigabytes() {
        assert_eq!(format_bytes(1_073_741_824), "1.0 GB");
        assert_eq!(format_bytes(2_684_354_560), "2.5 GB");
    }

    #[test]
    fn format_ordinal_first_ten() {
        assert_eq!(format_ordinal(1), "1st");
        assert_eq!(format_ordinal(2), "2nd");
        assert_eq!(format_ordinal(3), "3rd");
        assert_eq!(format_ordinal(4), "4th");
        assert_eq!(format_ordinal(5), "5th");
    }

    #[test]
    fn format_ordinal_teens() {
        assert_eq!(format_ordinal(11), "11th");
        assert_eq!(format_ordinal(12), "12th");
        assert_eq!(format_ordinal(13), "13th");
    }

    #[test]
    fn format_ordinal_twenties() {
        assert_eq!(format_ordinal(21), "21st");
        assert_eq!(format_ordinal(22), "22nd");
        assert_eq!(format_ordinal(23), "23rd");
        assert_eq!(format_ordinal(24), "24th");
    }

    #[test]
    fn format_ordinal_hundreds() {
        assert_eq!(format_ordinal(100), "100th");
        assert_eq!(format_ordinal(101), "101st");
        assert_eq!(format_ordinal(111), "111th");
        assert_eq!(format_ordinal(112), "112th");
        assert_eq!(format_ordinal(113), "113th");
    }

    #[test]
    fn truncate_line_short_string() {
        let line = "hello";
        assert_eq!(truncate_line(line, 10), "hello");
    }

    #[test]
    fn truncate_line_exact_width() {
        let line = "hello";
        assert_eq!(truncate_line(line, 5), "hello");
    }

    #[test]
    fn truncate_line_long_string() {
        let line = "this is a very long string";
        let truncated = truncate_line(line, 15);
        assert!(truncated.width() <= 15);
    }

    #[test]
    fn star_icon_plain() {
        let ctx = OutputContext::plain();
        assert_eq!(star_icon(ctx), "*");
    }

    #[test]
    fn celebration_summary_builder() {
        let summary = CelebrationSummary::new("myproject", 1000)
            .worker("worker1")
            .crates_compiled(Some(10))
            .cache_hit(Some(true))
            .target(Some("x86_64".to_string()))
            .quiet(false);

        assert_eq!(summary.project_id, "myproject");
        assert_eq!(summary.duration_ms, 1000);
        assert_eq!(summary.worker, Some("worker1".to_string()));
        assert_eq!(summary.crates_compiled, Some(10));
        assert_eq!(summary.cache_hit, Some(true));
        assert_eq!(summary.target, Some("x86_64".to_string()));
        assert!(!summary.quiet);
    }

    #[test]
    fn artifact_summary_stores_values() {
        let artifact = ArtifactSummary {
            files: 42,
            bytes: 1_000_000,
        };
        assert_eq!(artifact.files, 42);
        assert_eq!(artifact.bytes, 1_000_000);
    }
}
