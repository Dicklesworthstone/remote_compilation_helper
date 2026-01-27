//! TransferProgress - rsync progress visualization.
//!
//! Parses `rsync --info=progress2` output and renders a compact progress line.

use crate::ui::{Icons, OutputContext, ProgressContext};
use std::time::{Duration, Instant};

#[cfg(feature = "rich-ui")]
use crate::ui::RchTheme;
#[cfg(feature = "rich-ui")]
use rich_rust::prelude::{BarStyle, ProgressBar, Style};

const DEFAULT_BYTES_BAR_WIDTH: usize = 18;
const DEFAULT_FILES_BAR_WIDTH: usize = 10;
const SPEED_SAMPLE_WINDOW: usize = 10;
const MIN_PERCENT_FOR_TOTAL: u8 = 1;

/// Transfer direction for progress display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    Upload,
    Download,
}

impl TransferDirection {
    fn arrow(self, ctx: OutputContext) -> &'static str {
        if ctx.supports_unicode() {
            match self {
                Self::Upload => "\u{2191}",   // ↑
                Self::Download => "\u{2193}", // ↓
            }
        } else {
            match self {
                Self::Upload => "^",
                Self::Download => "v",
            }
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Upload => "Syncing",
            Self::Download => "Fetching",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ProgressSample {
    bytes: u64,
    percent: Option<u8>,
    speed_bps: Option<f64>,
    eta: Option<Duration>,
    files_done: Option<u32>,
    files_total: Option<u32>,
}

#[derive(Debug, Default)]
struct SpeedSmoother {
    samples: Vec<f64>,
}

impl SpeedSmoother {
    fn push(&mut self, value: f64) {
        if value <= 0.0 {
            return;
        }
        self.samples.push(value);
        if self.samples.len() > SPEED_SAMPLE_WINDOW {
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

    fn sparkline(&self, ctx: OutputContext) -> String {
        if self.samples.is_empty() {
            return String::new();
        }

        let levels: [&str; 8] = if ctx.supports_unicode() {
            [
                "\u{2581}", // ▁
                "\u{2582}", // ▂
                "\u{2583}", // ▃
                "\u{2584}", // ▄
                "\u{2585}", // ▅
                "\u{2586}", // ▆
                "\u{2587}", // ▇
                "\u{2588}", // █
            ]
        } else {
            [".", ":", "-", "=", "+", "*", "#", "@"] // ASCII fallback
        };

        let max = self
            .samples
            .iter()
            .cloned()
            .fold(0.0_f64, f64::max)
            .max(1.0);

        let mut out = String::new();
        for sample in &self.samples {
            let ratio = (sample / max).clamp(0.0, 1.0);
            let idx = (ratio * (levels.len() as f64 - 1.0)).round() as usize;
            out.push_str(levels[idx]);
        }
        out
    }
}

/// Progress display for rsync transfers.
#[derive(Debug)]
pub struct TransferProgress {
    ctx: OutputContext,
    direction: TransferDirection,
    label: String,
    enabled: bool,
    progress: Option<ProgressContext>,
    start: Instant,
    bytes_transferred: u64,
    bytes_total: Option<u64>,
    percent: Option<u8>,
    files_transferred: u32,
    files_total: Option<u32>,
    current_file: Option<String>,
    speed: SpeedSmoother,
    eta: Option<Duration>,
    compression_ratio: Option<f64>,
}

/// Snapshot of transfer progress stats.
#[derive(Debug, Clone, Copy, Default)]
pub struct TransferStats {
    pub bytes_transferred: u64,
    pub bytes_total: Option<u64>,
    pub files_transferred: u32,
    pub files_total: Option<u32>,
    pub percent: Option<u8>,
}

impl TransferProgress {
    /// Create a new transfer progress display.
    pub fn new(
        ctx: OutputContext,
        direction: TransferDirection,
        label: impl Into<String>,
        quiet: bool,
    ) -> Self {
        let enabled = !quiet && !ctx.is_machine();
        let progress = if enabled && matches!(ctx, OutputContext::Interactive) {
            Some(ProgressContext::new(ctx))
        } else {
            None
        };

        Self {
            ctx,
            direction,
            label: label.into(),
            enabled,
            progress,
            start: Instant::now(),
            bytes_transferred: 0,
            bytes_total: None,
            percent: None,
            files_transferred: 0,
            files_total: None,
            current_file: None,
            speed: SpeedSmoother::default(),
            eta: None,
            compression_ratio: None,
        }
    }

    /// Convenience constructor for uploads.
    pub fn upload(ctx: OutputContext, label: impl Into<String>, quiet: bool) -> Self {
        Self::new(ctx, TransferDirection::Upload, label, quiet)
    }

    /// Convenience constructor for downloads.
    pub fn download(ctx: OutputContext, label: impl Into<String>, quiet: bool) -> Self {
        Self::new(ctx, TransferDirection::Download, label, quiet)
    }

    /// Update progress from a raw rsync output line.
    pub fn update_from_line(&mut self, line: &str) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return;
        }

        if let Some(sample) = parse_progress_line(trimmed) {
            self.apply_sample(sample);
        } else {
            self.set_current_file(trimmed.to_string());
        }

        self.render();
    }

    /// Set the current file being transferred.
    pub fn set_current_file(&mut self, path: impl Into<String>) {
        self.current_file = Some(path.into());
    }

    /// Set compression ratio (e.g. 3.2 for 3.2:1).
    pub fn set_compression_ratio(&mut self, ratio: f64) {
        if ratio.is_finite() && ratio > 0.0 {
            self.compression_ratio = Some(ratio);
        }
    }

    /// Apply a final summary from an external source.
    ///
    /// Useful when progress lines are unavailable (e.g., mock transport).
    pub fn apply_summary(&mut self, bytes_transferred: u64, files_transferred: u32) {
        if bytes_transferred > 0 {
            self.bytes_transferred = bytes_transferred;
        }
        if files_transferred > 0 {
            self.files_transferred = files_transferred;
        }
    }

    /// Snapshot current transfer stats for callers.
    #[must_use]
    pub fn stats(&self) -> TransferStats {
        TransferStats {
            bytes_transferred: self.bytes_transferred,
            bytes_total: self.bytes_total,
            files_transferred: self.files_transferred,
            files_total: self.files_total,
            percent: self.percent,
        }
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
        let avg_speed = if duration.as_secs_f64() > 0.0 {
            self.bytes_transferred as f64 / duration.as_secs_f64()
        } else {
            0.0
        };

        let icon = Icons::check(self.ctx);
        let files = self.files_transferred;
        let bytes = format_bytes(self.bytes_transferred);
        let speed = format_speed(avg_speed);
        let duration_str = format_duration(duration);
        let ratio = self
            .compression_ratio
            .map(|r| format!(" {r:.1}:1 compression"))
            .unwrap_or_default();

        eprintln!("{icon} Synced {files} files ({bytes}) in {duration_str} ({speed} avg{ratio})");
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
        eprintln!("{icon} Transfer failed after {duration_str}: {message}");
    }

    fn apply_sample(&mut self, sample: ProgressSample) {
        self.bytes_transferred = sample.bytes;
        self.percent = sample.percent;

        if self.bytes_total.is_none()
            && let Some(percent) = sample.percent
            && percent >= MIN_PERCENT_FOR_TOTAL
        {
            let total = (self.bytes_transferred as f64 / (percent as f64 / 100.0)).round();
            if total.is_finite() && total > 0.0 {
                self.bytes_total = Some(total as u64);
            }
        }

        if let Some(total) = sample.files_total {
            self.files_total = Some(total);
        }
        if let Some(done) = sample.files_done {
            self.files_transferred = done;
        }

        if let Some(speed) = sample.speed_bps {
            self.speed.push(speed);
        }

        if let Some(eta) = sample.eta {
            self.eta = Some(eta);
        }
    }

    fn render(&mut self) {
        if !self.enabled {
            return;
        }

        let arrow = self.direction.arrow(self.ctx);
        let label = if self.label.is_empty() {
            self.direction.label()
        } else {
            self.label.as_str()
        };

        let bytes_bar = render_bar(
            self.ctx,
            self.bytes_transferred,
            self.bytes_total,
            self.percent.map(|p| f64::from(p) / 100.0),
            DEFAULT_BYTES_BAR_WIDTH,
        );

        let files_percent = match (self.files_transferred, self.files_total) {
            (_, Some(total)) if total > 0 => Some(self.files_transferred as f64 / total as f64),
            _ => None,
        };

        let files_bar = render_bar(
            self.ctx,
            u64::from(self.files_transferred),
            self.files_total.map(u64::from),
            files_percent,
            DEFAULT_FILES_BAR_WIDTH,
        );

        let bytes_total = self
            .bytes_total
            .map(format_bytes)
            .unwrap_or_else(|| "?".to_string());
        let bytes_done = format_bytes(self.bytes_transferred);

        let files_total = self
            .files_total
            .map(|total| total.to_string())
            .unwrap_or_else(|| "?".to_string());

        let avg_speed = self.speed.average().unwrap_or(0.0);
        let speed = format_speed(avg_speed);
        let sparkline = self.speed.sparkline(self.ctx);

        let eta = if let (Some(total), Some(speed_bps)) = (self.bytes_total, self.speed.average()) {
            if speed_bps > 0.0 && total > self.bytes_transferred {
                let remaining = (total - self.bytes_transferred) as f64;
                Some(Duration::from_secs_f64(remaining / speed_bps))
            } else {
                self.eta
            }
        } else {
            self.eta
        };

        let eta_str = eta.map(format_duration).unwrap_or_else(|| "--".to_string());

        let ratio = self
            .compression_ratio
            .map(|r| format!("{r:.1}:1"))
            .unwrap_or_else(|| "--".to_string());

        let current_file = self
            .current_file
            .as_ref()
            .map(|path| truncate_middle(path, 36))
            .unwrap_or_else(|| "--".to_string());

        let mut line = format!(
            "{arrow} {label} {bytes_bar} {bytes_done}/{bytes_total} {speed} {sparkline} ETA {eta_str} ratio {ratio} | {files_bar} {files_transferred}/{files_total} files | {current_file}",
            files_transferred = self.files_transferred
        );

        line = line.trim_end().to_string();

        if let Some(progress) = &mut self.progress {
            progress.render(&line);
        }
    }
}

fn parse_progress_line(line: &str) -> Option<ProgressSample> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.len() < 4 {
        return None;
    }

    if !tokens[1].ends_with('%') || !tokens[2].contains("/s") {
        return None;
    }

    let bytes = parse_size(tokens[0])?;
    let percent = tokens[1].trim_end_matches('%').parse::<u8>().ok();
    let speed_bps = parse_speed(tokens[2]);
    let eta = parse_eta(tokens[3]);

    let details = if tokens.len() > 4 {
        Some(tokens[4..].join(" "))
    } else {
        None
    };

    let (files_done, files_total) = details
        .as_deref()
        .and_then(parse_details)
        .unwrap_or((None, None));

    Some(ProgressSample {
        bytes,
        percent,
        speed_bps,
        eta,
        files_done,
        files_total,
    })
}

fn parse_details(details: &str) -> Option<(Option<u32>, Option<u32>)> {
    let cleaned = details.trim().trim_start_matches('(').trim_end_matches(')');

    let mut files_done = None;
    let mut files_total = None;

    for part in cleaned.split(',') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix("to-chk=") {
            let mut iter = rest.split('/');
            let remaining = iter.next()?.trim().parse::<u32>().ok()?;
            let total = iter.next()?.trim().parse::<u32>().ok()?;
            files_total = Some(total);
            files_done = Some(total.saturating_sub(remaining));
        }
    }

    if files_done.is_none() && files_total.is_none() {
        None
    } else {
        Some((files_done, files_total))
    }
}

fn parse_speed(token: &str) -> Option<f64> {
    let trimmed = token.trim();
    let value = trimmed.trim_end_matches("/s");
    parse_size_f64(value)
}

fn parse_eta(token: &str) -> Option<Duration> {
    let parts: Vec<&str> = token.trim().split(':').collect();
    if parts.len() < 2 {
        return None;
    }

    let mut nums = Vec::new();
    for part in parts {
        nums.push(part.parse::<u64>().ok()?);
    }

    let (hours, minutes, seconds) = match nums.len() {
        2 => (0, nums[0], nums[1]),
        3 => (nums[0], nums[1], nums[2]),
        _ => return None,
    };

    Some(Duration::from_secs(hours * 3600 + minutes * 60 + seconds))
}

fn parse_size(input: &str) -> Option<u64> {
    parse_size_f64(input).map(|value| value.round() as u64)
}

fn parse_size_f64(input: &str) -> Option<f64> {
    let mut num = String::new();
    let mut unit = String::new();

    for ch in input.trim().chars() {
        if ch.is_ascii_digit() || ch == '.' {
            num.push(ch);
        } else if ch == ',' {
            continue;
        } else if !ch.is_whitespace() {
            unit.push(ch);
        }
    }

    if num.is_empty() {
        return None;
    }

    let value = num.parse::<f64>().ok()?;
    let unit = unit.to_ascii_lowercase();

    let multiplier = match unit.as_str() {
        "" | "b" => 1.0,
        "k" | "kb" => 1024.0,
        "m" | "mb" => 1024.0 * 1024.0,
        "g" | "gb" => 1024.0 * 1024.0 * 1024.0,
        "t" | "tb" => 1024.0_f64.powi(4),
        "p" | "pb" => 1024.0_f64.powi(5),
        "e" | "eb" => 1024.0_f64.powi(6),
        _ => 1.0,
    };

    Some(value * multiplier)
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

    if total.is_some() {
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

fn format_bytes(bytes: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < units.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", units[unit])
    }
}

fn format_speed(bytes_per_sec: f64) -> String {
    if bytes_per_sec <= 0.0 {
        return "--/s".to_string();
    }
    let formatted = format_bytes(bytes_per_sec.round() as u64);
    format!("{formatted}/s")
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

fn truncate_middle(value: &str, max_len: usize) -> String {
    let len = value.chars().count();
    if len <= max_len {
        return value.to_string();
    }
    if max_len <= 3 {
        return value.chars().take(max_len).collect();
    }

    let head = (max_len - 3) / 2;
    let tail = max_len - 3 - head;
    let start: String = value.chars().take(head).collect();
    let end: String = value
        .chars()
        .rev()
        .take(tail)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("{start}...{end}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_progress_line_with_details() {
        let line = "9.53G  21%  317.26MB/s    0:00:28 (xfr#83063, to-chk=443926/538653)";
        let sample = parse_progress_line(line).expect("parse");
        assert_eq!(sample.percent, Some(21));
        assert_eq!(sample.files_total, Some(538_653));
        assert!(sample.bytes > 0);
        assert!(sample.speed_bps.unwrap_or(0.0) > 0.0);
        assert_eq!(sample.eta, Some(Duration::from_secs(28)));
    }

    #[test]
    fn parse_progress_line_numeric_bytes() {
        let line = "1234567  12%  1.23MB/s  0:01:23 (xfr#5, to-chk=10/20)";
        let sample = parse_progress_line(line).expect("parse");
        assert_eq!(sample.bytes, 1_234_567);
        assert_eq!(sample.percent, Some(12));
        assert_eq!(sample.files_total, Some(20));
        assert_eq!(sample.files_done, Some(10));
    }

    #[test]
    fn truncate_middle_shortens() {
        let value = "path/to/very/long/file.rs";
        let truncated = truncate_middle(value, 12);
        assert!(truncated.len() <= 12);
        assert!(truncated.contains("..."));
    }

    #[test]
    fn truncate_middle_no_change_when_short() {
        let value = "short.rs";
        let truncated = truncate_middle(value, 20);
        assert_eq!(truncated, value);
    }

    #[test]
    fn truncate_middle_exact_length() {
        let value = "exactly_12c";
        let truncated = truncate_middle(value, 11);
        assert_eq!(truncated.len(), 11);
    }

    #[test]
    fn transfer_direction_label() {
        assert_eq!(TransferDirection::Upload.label(), "Syncing");
        assert_eq!(TransferDirection::Download.label(), "Fetching");
    }

    #[test]
    fn transfer_direction_arrow_plain() {
        // Plain context doesn't support rich output, so gets ASCII arrows
        let ctx = OutputContext::plain();
        assert_eq!(TransferDirection::Upload.arrow(ctx), "^");
        assert_eq!(TransferDirection::Download.arrow(ctx), "v");
    }

    #[test]
    fn speed_smoother_empty() {
        let smoother = SpeedSmoother::default();
        assert!(smoother.average().is_none());
    }

    #[test]
    fn speed_smoother_single_value() {
        let mut smoother = SpeedSmoother::default();
        smoother.push(100.0);
        assert_eq!(smoother.average(), Some(100.0));
    }

    #[test]
    fn speed_smoother_ignores_zero() {
        let mut smoother = SpeedSmoother::default();
        smoother.push(0.0);
        assert!(smoother.average().is_none());
    }

    #[test]
    fn speed_smoother_ignores_negative() {
        let mut smoother = SpeedSmoother::default();
        smoother.push(-50.0);
        assert!(smoother.average().is_none());
    }

    #[test]
    fn speed_smoother_computes_average() {
        let mut smoother = SpeedSmoother::default();
        smoother.push(100.0);
        smoother.push(200.0);
        smoother.push(300.0);
        assert_eq!(smoother.average(), Some(200.0));
    }

    #[test]
    fn speed_smoother_sparkline_empty() {
        let smoother = SpeedSmoother::default();
        let ctx = OutputContext::plain();
        assert!(smoother.sparkline(ctx).is_empty());
    }

    #[test]
    fn speed_smoother_sparkline_plain() {
        let mut smoother = SpeedSmoother::default();
        smoother.push(10.0);
        smoother.push(50.0);
        smoother.push(100.0);
        let ctx = OutputContext::plain();
        // Plain context still generates sparkline with ASCII fallback
        let sparkline = smoother.sparkline(ctx);
        assert!(!sparkline.is_empty());
    }

    #[test]
    fn parse_progress_line_minimal() {
        let line = "1024  50%  1.0MB/s  0:00:10";
        let sample = parse_progress_line(line).expect("parse");
        assert_eq!(sample.bytes, 1024);
        assert_eq!(sample.percent, Some(50));
    }

    #[test]
    fn parse_progress_line_kilobytes() {
        let line = "1.5K  10%  500.0KB/s  0:00:05";
        let sample = parse_progress_line(line).expect("parse");
        assert_eq!(sample.bytes, 1536); // 1.5 * 1024
        assert_eq!(sample.percent, Some(10));
    }

    #[test]
    fn parse_progress_line_megabytes() {
        let line = "2.5M  25%  10.0MB/s  0:00:30";
        let sample = parse_progress_line(line).expect("parse");
        assert_eq!(sample.bytes, 2_621_440); // 2.5 * 1024 * 1024
    }

    #[test]
    fn parse_progress_line_gigabytes() {
        let line = "1.0G  75%  100.0MB/s  0:00:10";
        let sample = parse_progress_line(line).expect("parse");
        assert_eq!(sample.bytes, 1_073_741_824); // 1.0 * 1024^3
    }

    #[test]
    fn parse_progress_line_invalid() {
        let line = "not valid progress";
        assert!(parse_progress_line(line).is_none());
    }

    #[test]
    fn parse_progress_line_empty() {
        assert!(parse_progress_line("").is_none());
    }
}
