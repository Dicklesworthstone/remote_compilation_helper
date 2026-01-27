//! MetricsDashboard - periodic performance summary for rchd.
//!
//! Bead: bd-3jru

#![forbid(unsafe_code)]
#![allow(dead_code)]

use crate::history::BuildHistory;
use crate::metrics;
use crate::selection::{CacheUse, WorkerSelector};
use crate::workers::WorkerPool;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use rch_common::BuildLocation;
use rch_common::ui::{Icons, OutputContext, RchTheme};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

#[cfg(feature = "rich-ui")]
use rich_rust::prelude::*;
#[cfg(feature = "rich-ui")]
use rich_rust::renderables::{Column, Row, Table};
#[cfg(feature = "rich-ui")]
use rich_rust::text::JustifyMethod;

const DEFAULT_INTERVAL_SECS: u64 = 300;
const SPARKLINE_SAMPLES: usize = 6;
const TREND_THRESHOLD: f64 = 0.05;

#[derive(Debug)]
pub struct MetricsDashboard {
    ctx: OutputContext,
    refresh_interval: Duration,
    window: Duration,
    last_refresh: Instant,
    last_reset: Instant,
    avg_history: VecDeque<f64>,
    queue_peak: usize,
    transfer_baseline: TransferCounters,
}

#[derive(Debug, Default, Clone, Copy)]
struct TransferCounters {
    up: f64,
    down: f64,
}

#[derive(Debug, Default)]
struct MetricsSnapshot {
    total_jobs: usize,
    success_jobs: usize,
    failed_jobs: usize,
    cache_hits: Option<usize>,
    cache_misses: Option<usize>,
    avg_ms: Option<f64>,
    p50_ms: Option<f64>,
    p95_ms: Option<f64>,
    p99_ms: Option<f64>,
    utilization_pct: Option<f64>,
    used_slots: u32,
    total_slots: u32,
    transfer_up: u64,
    transfer_down: u64,
    queue_peak: usize,
    trend_arrow: String,
    sparkline: String,
}

impl MetricsDashboard {
    #[must_use]
    pub fn new(interval: Duration) -> Self {
        Self::with_context(OutputContext::detect(), interval)
    }

    #[must_use]
    pub fn with_context(ctx: OutputContext, interval: Duration) -> Self {
        let interval = if interval.is_zero() {
            Duration::from_secs(DEFAULT_INTERVAL_SECS)
        } else {
            interval
        };
        let now = Instant::now();
        let baseline = TransferCounters::read();
        Self {
            ctx,
            refresh_interval: interval,
            window: interval,
            last_refresh: now.checked_sub(interval).unwrap_or_else(Instant::now),
            last_reset: now,
            avg_history: VecDeque::with_capacity(SPARKLINE_SAMPLES),
            queue_peak: 0,
            transfer_baseline: baseline,
        }
    }

    pub async fn emit_update(
        &mut self,
        pool: &WorkerPool,
        history: &BuildHistory,
        selector: &WorkerSelector,
    ) {
        if !self.should_render() {
            return;
        }

        let now = Instant::now();
        if now.duration_since(self.last_refresh) < self.refresh_interval {
            return;
        }

        if now.duration_since(self.last_reset) >= self.window {
            self.reset_window();
        }

        let snapshot = self.collect_snapshot(pool, history, selector).await;
        self.last_refresh = now;

        #[cfg(feature = "rich-ui")]
        self.render_rich(&snapshot);
    }

    fn should_render(&self) -> bool {
        if !self.ctx.supports_rich() {
            return false;
        }

        !matches!(rich_override(), Some(false))
    }

    fn reset_window(&mut self) {
        self.avg_history.clear();
        self.queue_peak = 0;
        self.transfer_baseline = TransferCounters::read();
        self.last_reset = Instant::now();
    }

    async fn collect_snapshot(
        &mut self,
        pool: &WorkerPool,
        history: &BuildHistory,
        selector: &WorkerSelector,
    ) -> MetricsSnapshot {
        let records = history.recent(history.len());
        let cutoff = Utc::now()
            - ChronoDuration::from_std(self.window)
                .unwrap_or_else(|_| ChronoDuration::seconds(DEFAULT_INTERVAL_SECS as i64));
        let mut window_records = Vec::new();
        for record in records {
            if parse_timestamp(&record.completed_at)
                .map(|ts| ts >= cutoff)
                .unwrap_or(false)
            {
                window_records.push(record);
            }
        }

        let total_jobs = window_records.len();
        let success_jobs = window_records
            .iter()
            .filter(|record| record.exit_code == 0)
            .count();
        let failed_jobs = total_jobs.saturating_sub(success_jobs);

        let mut durations: Vec<u64> = window_records.iter().map(|r| r.duration_ms).collect();
        durations.sort_unstable();
        let avg_ms = average_ms(&durations);
        let p50_ms = percentile_ms(&durations, 0.50);
        let p95_ms = percentile_ms(&durations, 0.95);
        let p99_ms = percentile_ms(&durations, 0.99);

        let (cache_hits, cache_misses) =
            estimate_cache_hits(selector, &window_records, self.window).await;

        let (utilization_pct, used_slots, total_slots) = utilization(pool).await;

        let transfer_delta = TransferCounters::read();
        let transfer_up = delta_counter(transfer_delta.up, self.transfer_baseline.up);
        let transfer_down = delta_counter(transfer_delta.down, self.transfer_baseline.down);

        let queue_depth = metrics::BUILD_QUEUE_DEPTH.get() as usize;
        if queue_depth > self.queue_peak {
            self.queue_peak = queue_depth;
        }

        let prev_avg = self.avg_history.back().copied();
        if let Some(avg) = avg_ms {
            if self.avg_history.len() == SPARKLINE_SAMPLES {
                self.avg_history.pop_front();
            }
            self.avg_history.push_back(avg);
        }
        let trend_arrow = trend_arrow(prev_avg, avg_ms, self.ctx).to_string();
        let sparkline = sparkline(&self.avg_history, self.ctx);

        MetricsSnapshot {
            total_jobs,
            success_jobs,
            failed_jobs,
            cache_hits,
            cache_misses,
            avg_ms,
            p50_ms,
            p95_ms,
            p99_ms,
            utilization_pct,
            used_slots,
            total_slots,
            transfer_up,
            transfer_down,
            queue_peak: self.queue_peak,
            trend_arrow,
            sparkline,
        }
    }

    #[cfg(feature = "rich-ui")]
    fn render_rich(&self, snapshot: &MetricsSnapshot) {
        let title = format!("Metrics (last {})", format_interval(self.window));
        let mut table = Table::new()
            .title(title)
            .border_style(RchTheme::secondary());

        table = table
            .with_column(Column::new("Metric").header_style(RchTheme::table_header()))
            .with_column(
                Column::new("Value")
                    .header_style(RchTheme::table_header())
                    .justify(JustifyMethod::Right),
            )
            .with_column(
                Column::new("Trend")
                    .header_style(RchTheme::table_header())
                    .justify(JustifyMethod::Right),
            );

        let jobs_value = if snapshot.total_jobs > 0 {
            let success_rate = (snapshot.success_jobs as f64 / snapshot.total_jobs as f64) * 100.0;
            format!(
                "{} ok / {} fail ({:.0}%)",
                snapshot.success_jobs, snapshot.failed_jobs, success_rate
            )
        } else {
            "n/a".to_string()
        };
        table = table.with_row(Row::new(vec![
            Cell::new("Jobs (rch_builds_total)"),
            Cell::new(jobs_value),
            Cell::new(""),
        ]));

        let cache_value = match (snapshot.cache_hits, snapshot.cache_misses) {
            (Some(hits), Some(misses)) => {
                let total = hits + misses;
                let rate = if total > 0 {
                    (hits as f64 / total as f64) * 100.0
                } else {
                    0.0
                };
                format!("{hits} hits / {misses} misses ({rate:.0}%)")
            }
            _ => "n/a".to_string(),
        };
        table = table.with_row(Row::new(vec![
            Cell::new("Cache hits (rch_cache_hits_est)"),
            Cell::new(cache_value),
            Cell::new(""),
        ]));

        let avg_value = snapshot
            .avg_ms
            .map(format_duration_ms)
            .unwrap_or_else(|| "n/a".to_string());
        let trend = if snapshot.sparkline.is_empty() {
            snapshot.trend_arrow.clone()
        } else {
            format!("{} {}", snapshot.trend_arrow, snapshot.sparkline)
        };
        table = table.with_row(Row::new(vec![
            Cell::new("Avg duration (rch_build_duration_seconds)"),
            Cell::new(avg_value),
            Cell::new(trend),
        ]));

        let latency_value = match (snapshot.p50_ms, snapshot.p95_ms, snapshot.p99_ms) {
            (Some(p50), Some(p95), Some(p99)) => format!(
                "p50 {} | p95 {} | p99 {}",
                format_duration_ms(p50),
                format_duration_ms(p95),
                format_duration_ms(p99)
            ),
            _ => "n/a".to_string(),
        };
        table = table.with_row(Row::new(vec![
            Cell::new("Latency p50/p95/p99 (rch_build_duration_seconds)"),
            Cell::new(latency_value),
            Cell::new(""),
        ]));

        let utilization_value = if let Some(util) = snapshot.utilization_pct {
            format!(
                "{util:.0}% ({}/{})",
                snapshot.used_slots, snapshot.total_slots
            )
        } else {
            "n/a".to_string()
        };
        table = table.with_row(Row::new(vec![
            Cell::new("Workers utilized (rch_worker_slots_available)"),
            Cell::new(utilization_value),
            Cell::new(""),
        ]));

        let up_icon = Icons::arrow_up(self.ctx);
        let down_icon = Icons::arrow_down(self.ctx);
        let transfer_value = format!(
            "{up_icon} {}  {down_icon} {}",
            format_bytes(snapshot.transfer_up),
            format_bytes(snapshot.transfer_down)
        );
        table = table.with_row(Row::new(vec![
            Cell::new("Transfer bytes (rch_transfer_bytes_total)"),
            Cell::new(transfer_value),
            Cell::new(""),
        ]));

        table = table.with_row(Row::new(vec![
            Cell::new("Queue peak (rch_build_queue_depth)"),
            Cell::new(snapshot.queue_peak.to_string()),
            Cell::new(""),
        ]));

        let console = Console::builder().force_terminal(true).build();
        console.print_renderable(&table);
    }
}

impl TransferCounters {
    fn read() -> Self {
        let up = counter_value(&["upload", "up"]);
        let down = counter_value(&["download", "down"]);
        Self { up, down }
    }
}

fn counter_value(labels: &[&str]) -> f64 {
    for label in labels {
        if let Ok(counter) = metrics::TRANSFER_BYTES_TOTAL.get_metric_with_label_values(&[*label]) {
            return counter.get();
        }
    }
    0.0
}

fn delta_counter(current: f64, baseline: f64) -> u64 {
    if current >= baseline {
        (current - baseline).round() as u64
    } else {
        current.round() as u64
    }
}

async fn utilization(pool: &WorkerPool) -> (Option<f64>, u32, u32) {
    let workers = pool.all_workers().await;
    let mut total_slots = 0u32;
    let mut used_slots = 0u32;
    for worker in workers {
        let config = worker.config.read().await;
        let worker_total = config.total_slots;
        drop(config);
        let available = worker.available_slots().await;
        total_slots = total_slots.saturating_add(worker_total);
        used_slots = used_slots.saturating_add(worker_total.saturating_sub(available));
    }

    if total_slots == 0 {
        return (None, used_slots, total_slots);
    }
    let utilization = (used_slots as f64 / total_slots as f64) * 100.0;
    (Some(utilization), used_slots, total_slots)
}

async fn estimate_cache_hits(
    selector: &WorkerSelector,
    records: &[rch_common::BuildRecord],
    window: Duration,
) -> (Option<usize>, Option<usize>) {
    let cache = selector.cache_tracker.read().await;
    let mut hits = 0usize;
    let mut total = 0usize;
    for record in records {
        if record.location != BuildLocation::Remote {
            continue;
        }
        let Some(worker_id) = record.worker_id.as_deref() else {
            continue;
        };
        total += 1;
        if cache.has_recent_build(worker_id, &record.project_id, CacheUse::Build, window) {
            hits += 1;
        }
    }
    if total == 0 {
        return (None, None);
    }
    let misses = total.saturating_sub(hits);
    (Some(hits), Some(misses))
}

fn parse_timestamp(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

fn average_ms(values: &[u64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let total: u64 = values.iter().sum();
    Some(total as f64 / values.len() as f64)
}

fn percentile_ms(values: &[u64], pct: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let idx = ((values.len() - 1) as f64 * pct).round() as usize;
    values.get(idx).map(|v| *v as f64)
}

fn format_duration_ms(ms: f64) -> String {
    if ms >= 1000.0 {
        format!("{:.1}s", ms / 1000.0)
    } else {
        format!("{:.0}ms", ms)
    }
}

fn format_interval(duration: Duration) -> String {
    let secs = duration.as_secs();
    if secs.is_multiple_of(3600) {
        format!("{}h", secs / 3600)
    } else if secs.is_multiple_of(60) {
        format!("{}m", secs / 60)
    } else {
        format!("{}s", secs)
    }
}

fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * KB;
    const GB: f64 = 1024.0 * MB;

    let bytes_f = bytes as f64;
    if bytes_f >= GB {
        format!("{:.1} GB", bytes_f / GB)
    } else if bytes_f >= MB {
        format!("{:.1} MB", bytes_f / MB)
    } else if bytes_f >= KB {
        format!("{:.1} KB", bytes_f / KB)
    } else {
        format!("{bytes} B")
    }
}

fn trend_arrow(prev: Option<f64>, current: Option<f64>, ctx: OutputContext) -> &'static str {
    let Some(prev) = prev else {
        return Icons::arrow_right(ctx);
    };
    let Some(current) = current else {
        return Icons::arrow_right(ctx);
    };
    if prev <= f64::EPSILON {
        return Icons::arrow_right(ctx);
    }
    let delta = (current - prev) / prev;
    if delta.abs() < TREND_THRESHOLD {
        Icons::arrow_right(ctx)
    } else if delta > 0.0 {
        Icons::arrow_up(ctx)
    } else {
        Icons::arrow_down(ctx)
    }
}

fn sparkline(values: &VecDeque<f64>, ctx: OutputContext) -> String {
    if values.is_empty() {
        return String::new();
    }
    let (min, max) = values.iter().fold((f64::MAX, f64::MIN), |acc, val| {
        (acc.0.min(*val), acc.1.max(*val))
    });
    let range = (max - min).abs();

    let unicode_levels = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"];
    let ascii_levels = [".", ":", "-", "=", "+", "*", "#", "@"];
    let levels = if ctx.supports_unicode() {
        &unicode_levels
    } else {
        &ascii_levels
    };

    let mut out = String::new();
    for value in values {
        let normalized = if range < f64::EPSILON {
            0.5
        } else {
            (value - min) / range
        };
        let idx = ((levels.len() - 1) as f64 * normalized).round() as usize;
        out.push_str(levels[idx]);
    }
    out
}

fn rich_override() -> Option<bool> {
    let Ok(value) = std::env::var("RCHD_RICH_OUTPUT") else {
        return None;
    };
    let normalized = value.trim().to_lowercase();
    match normalized.as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;
    use rch_common::test_guard;

    // ==================== delta_counter tests ====================

    #[test]
    fn test_delta_counter_positive_delta() {
        let _guard = test_guard!();
        assert_eq!(delta_counter(100.0, 50.0), 50);
    }

    #[test]
    fn test_delta_counter_zero_delta() {
        let _guard = test_guard!();
        assert_eq!(delta_counter(100.0, 100.0), 0);
    }

    #[test]
    fn test_delta_counter_baseline_higher_returns_current() {
        let _guard = test_guard!();
        // When current < baseline (counter wrapped), return current
        assert_eq!(delta_counter(50.0, 100.0), 50);
    }

    #[test]
    fn test_delta_counter_rounds_correctly() {
        let _guard = test_guard!();
        assert_eq!(delta_counter(100.6, 50.0), 51);
        assert_eq!(delta_counter(100.4, 50.0), 50);
    }

    // ==================== parse_timestamp tests ====================

    #[test]
    fn test_parse_timestamp_valid_rfc3339() {
        let _guard = test_guard!();
        let result = parse_timestamp("2024-01-15T10:30:00Z");
        assert!(result.is_some());
        let ts = result.unwrap();
        assert_eq!(ts.year(), 2024);
        assert_eq!(ts.month(), 1);
        assert_eq!(ts.day(), 15);
    }

    #[test]
    fn test_parse_timestamp_with_offset() {
        let _guard = test_guard!();
        let result = parse_timestamp("2024-01-15T10:30:00+05:00");
        assert!(result.is_some());
    }

    #[test]
    fn test_parse_timestamp_invalid_format() {
        let _guard = test_guard!();
        assert!(parse_timestamp("not-a-timestamp").is_none());
        assert!(parse_timestamp("2024/01/15").is_none());
        assert!(parse_timestamp("").is_none());
    }

    // ==================== average_ms tests ====================

    #[test]
    fn test_average_ms_empty_returns_none() {
        let _guard = test_guard!();
        assert!(average_ms(&[]).is_none());
    }

    #[test]
    fn test_average_ms_single_value() {
        let _guard = test_guard!();
        assert_eq!(average_ms(&[100]), Some(100.0));
    }

    #[test]
    fn test_average_ms_multiple_values() {
        let _guard = test_guard!();
        assert_eq!(average_ms(&[100, 200, 300]), Some(200.0));
    }

    #[test]
    fn test_average_ms_with_zeros() {
        let _guard = test_guard!();
        assert_eq!(average_ms(&[0, 100, 200]), Some(100.0));
    }

    // ==================== percentile_ms tests ====================

    #[test]
    fn test_percentile_ms_empty_returns_none() {
        let _guard = test_guard!();
        assert!(percentile_ms(&[], 0.5).is_none());
    }

    #[test]
    fn test_percentile_ms_p50() {
        let _guard = test_guard!();
        let values = vec![10, 20, 30, 40, 50];
        assert_eq!(percentile_ms(&values, 0.5), Some(30.0));
    }

    #[test]
    fn test_percentile_ms_p0() {
        let _guard = test_guard!();
        let values = vec![10, 20, 30, 40, 50];
        assert_eq!(percentile_ms(&values, 0.0), Some(10.0));
    }

    #[test]
    fn test_percentile_ms_p100() {
        let _guard = test_guard!();
        let values = vec![10, 20, 30, 40, 50];
        assert_eq!(percentile_ms(&values, 1.0), Some(50.0));
    }

    #[test]
    fn test_percentile_ms_p95_interpolation() {
        let _guard = test_guard!();
        // With 5 values, index 4 * 0.95 = 3.8, rounds to 4
        let values = vec![10, 20, 30, 40, 50];
        assert_eq!(percentile_ms(&values, 0.95), Some(50.0));
    }

    // ==================== format_duration_ms tests ====================

    #[test]
    fn test_format_duration_ms_milliseconds() {
        let _guard = test_guard!();
        assert_eq!(format_duration_ms(500.0), "500ms");
        assert_eq!(format_duration_ms(50.0), "50ms");
        assert_eq!(format_duration_ms(999.0), "999ms");
    }

    #[test]
    fn test_format_duration_ms_seconds() {
        let _guard = test_guard!();
        assert_eq!(format_duration_ms(1000.0), "1.0s");
        assert_eq!(format_duration_ms(1500.0), "1.5s");
        assert_eq!(format_duration_ms(60000.0), "60.0s");
    }

    #[test]
    fn test_format_duration_ms_zero() {
        let _guard = test_guard!();
        assert_eq!(format_duration_ms(0.0), "0ms");
    }

    // ==================== format_interval tests ====================

    #[test]
    fn test_format_interval_seconds() {
        let _guard = test_guard!();
        assert_eq!(format_interval(Duration::from_secs(30)), "30s");
        assert_eq!(format_interval(Duration::from_secs(45)), "45s");
    }

    #[test]
    fn test_format_interval_minutes() {
        let _guard = test_guard!();
        assert_eq!(format_interval(Duration::from_secs(60)), "1m");
        assert_eq!(format_interval(Duration::from_secs(300)), "5m");
        assert_eq!(format_interval(Duration::from_secs(900)), "15m");
    }

    #[test]
    fn test_format_interval_hours() {
        let _guard = test_guard!();
        assert_eq!(format_interval(Duration::from_secs(3600)), "1h");
        assert_eq!(format_interval(Duration::from_secs(7200)), "2h");
    }

    // ==================== format_bytes tests ====================

    #[test]
    fn test_format_bytes_bytes() {
        let _guard = test_guard!();
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1023), "1023 B");
    }

    #[test]
    fn test_format_bytes_kilobytes() {
        let _guard = test_guard!();
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(10240), "10.0 KB");
    }

    #[test]
    fn test_format_bytes_megabytes() {
        let _guard = test_guard!();
        assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.0 MB");
    }

    #[test]
    fn test_format_bytes_gigabytes() {
        let _guard = test_guard!();
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GB");
        assert_eq!(format_bytes(2 * 1024 * 1024 * 1024), "2.0 GB");
    }

    // ==================== trend_arrow tests ====================

    #[test]
    fn test_trend_arrow_no_previous() {
        let _guard = test_guard!();
        let ctx = OutputContext::plain();
        assert_eq!(trend_arrow(None, Some(100.0), ctx), Icons::arrow_right(ctx));
    }

    #[test]
    fn test_trend_arrow_no_current() {
        let _guard = test_guard!();
        let ctx = OutputContext::plain();
        assert_eq!(trend_arrow(Some(100.0), None, ctx), Icons::arrow_right(ctx));
    }

    #[test]
    fn test_trend_arrow_stable() {
        let _guard = test_guard!();
        let ctx = OutputContext::plain();
        // Within threshold (5%)
        assert_eq!(
            trend_arrow(Some(100.0), Some(102.0), ctx),
            Icons::arrow_right(ctx)
        );
    }

    #[test]
    fn test_trend_arrow_increasing() {
        let _guard = test_guard!();
        let ctx = OutputContext::plain();
        // Above threshold
        assert_eq!(
            trend_arrow(Some(100.0), Some(110.0), ctx),
            Icons::arrow_up(ctx)
        );
    }

    #[test]
    fn test_trend_arrow_decreasing() {
        let _guard = test_guard!();
        let ctx = OutputContext::plain();
        // Below threshold (negative)
        assert_eq!(
            trend_arrow(Some(100.0), Some(90.0), ctx),
            Icons::arrow_down(ctx)
        );
    }

    #[test]
    fn test_trend_arrow_zero_previous() {
        let _guard = test_guard!();
        let ctx = OutputContext::plain();
        assert_eq!(
            trend_arrow(Some(0.0), Some(100.0), ctx),
            Icons::arrow_right(ctx)
        );
    }

    // ==================== sparkline tests ====================

    #[test]
    fn test_sparkline_empty() {
        let _guard = test_guard!();
        let values: VecDeque<f64> = VecDeque::new();
        let ctx = OutputContext::plain();
        assert_eq!(sparkline(&values, ctx), "");
    }

    #[test]
    fn test_sparkline_single_value() {
        let _guard = test_guard!();
        let mut values = VecDeque::new();
        values.push_back(50.0);
        let ctx = OutputContext::plain();
        let result = sparkline(&values, ctx);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_sparkline_uniform_values() {
        let _guard = test_guard!();
        let mut values = VecDeque::new();
        values.push_back(100.0);
        values.push_back(100.0);
        values.push_back(100.0);
        let ctx = OutputContext::plain();
        let result = sparkline(&values, ctx);
        // All values same, should all be mid-level
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_sparkline_increasing() {
        let _guard = test_guard!();
        let mut values = VecDeque::new();
        values.push_back(0.0);
        values.push_back(50.0);
        values.push_back(100.0);
        let ctx = OutputContext::plain();
        let result = sparkline(&values, ctx);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_sparkline_unicode_vs_ascii() {
        let _guard = test_guard!();
        let mut values = VecDeque::new();
        values.push_back(0.0);
        values.push_back(100.0);

        let plain_ctx = OutputContext::plain();
        let ascii_result = sparkline(&values, plain_ctx);

        // ASCII uses single-byte characters
        assert!(ascii_result.is_ascii());
    }

    // ==================== TransferCounters tests ====================

    #[test]
    fn test_transfer_counters_default() {
        let _guard = test_guard!();
        let tc = TransferCounters::default();
        assert_eq!(tc.up, 0.0);
        assert_eq!(tc.down, 0.0);
    }

    // ==================== MetricsSnapshot tests ====================

    #[test]
    fn test_metrics_snapshot_default() {
        let _guard = test_guard!();
        let snapshot = MetricsSnapshot::default();
        assert_eq!(snapshot.total_jobs, 0);
        assert_eq!(snapshot.success_jobs, 0);
        assert_eq!(snapshot.failed_jobs, 0);
        assert!(snapshot.cache_hits.is_none());
        assert!(snapshot.avg_ms.is_none());
    }

    // ==================== MetricsDashboard tests ====================

    #[test]
    fn test_metrics_dashboard_new() {
        let _guard = test_guard!();
        let dashboard = MetricsDashboard::new(Duration::from_secs(60));
        assert_eq!(dashboard.refresh_interval, Duration::from_secs(60));
    }

    #[test]
    fn test_metrics_dashboard_zero_interval_uses_default() {
        let _guard = test_guard!();
        let dashboard = MetricsDashboard::new(Duration::ZERO);
        assert_eq!(
            dashboard.refresh_interval,
            Duration::from_secs(DEFAULT_INTERVAL_SECS)
        );
    }

    #[test]
    fn test_metrics_dashboard_with_context() {
        let _guard = test_guard!();
        let ctx = OutputContext::plain();
        let dashboard = MetricsDashboard::with_context(ctx, Duration::from_secs(120));
        assert_eq!(dashboard.refresh_interval, Duration::from_secs(120));
    }

    #[test]
    fn test_metrics_dashboard_reset_window() {
        let _guard = test_guard!();
        let mut dashboard = MetricsDashboard::new(Duration::from_secs(60));
        dashboard.avg_history.push_back(100.0);
        dashboard.avg_history.push_back(200.0);
        dashboard.queue_peak = 10;

        dashboard.reset_window();

        assert!(dashboard.avg_history.is_empty());
        assert_eq!(dashboard.queue_peak, 0);
    }
}
