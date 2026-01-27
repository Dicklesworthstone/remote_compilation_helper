//! DaemonBanner - startup display for rchd daemon.
//!
//! Shows a rich, branded startup panel when stderr is a TTY, with a
//! single-line fallback for non-interactive environments.

use chrono::{DateTime, Local};
use rch_common::ui::{OutputContext, RchTheme};
use std::time::Duration;

#[cfg(feature = "rich-ui")]
use rich_rust::r#box::DOUBLE;
#[cfg(feature = "rich-ui")]
use rich_rust::prelude::*;

const LOGO: &[&str] = &[
    " ____   ____ _   _ ____  ",
    "|  _ \\ / ___| | | |  _ \\ ",
    "| |_) | |   | | | | | | |",
    "|  _ <| |___| |_| | |_| |",
    "|_| \\_\\\\____|\\___/|____/ ",
];

/// Startup banner for rchd.
#[derive(Debug, Clone)]
pub struct DaemonBanner {
    ctx: OutputContext,
    version: String,
    build_profile: Option<String>,
    build_target: Option<String>,
    commit_hash: Option<String>,
    socket_path: String,
    workers: usize,
    total_slots: u32,
    metrics_port: u16,
    telemetry_enabled: bool,
    otel_enabled: bool,
    pid: u32,
    started_at: DateTime<Local>,
    startup_duration: Duration,
}

impl DaemonBanner {
    /// Create a new daemon banner.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        version: impl Into<String>,
        build_profile: Option<String>,
        build_target: Option<String>,
        commit_hash: Option<String>,
        socket_path: impl Into<String>,
        workers: usize,
        total_slots: u32,
        metrics_port: u16,
        telemetry_enabled: bool,
        otel_enabled: bool,
        pid: u32,
        started_at: DateTime<Local>,
        startup_duration: Duration,
    ) -> Self {
        Self {
            ctx: OutputContext::detect(),
            version: version.into(),
            build_profile,
            build_target,
            commit_hash,
            socket_path: socket_path.into(),
            workers,
            total_slots,
            metrics_port,
            telemetry_enabled,
            otel_enabled,
            pid,
            started_at,
            startup_duration,
        }
    }

    /// Show the banner (rich if possible, plain otherwise).
    pub fn show(&self) {
        let force_rich = Self::rich_override();

        if force_rich == Some(false) {
            self.show_plain();
            return;
        }

        #[cfg(feature = "rich-ui")]
        if force_rich == Some(true) || self.ctx.supports_rich() {
            self.show_rich();
            return;
        }

        self.show_plain();
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

    fn commit_short(&self) -> String {
        self.commit_hash
            .as_deref()
            .map(|hash| hash.chars().take(8).collect::<String>())
            .unwrap_or_else(|| "unknown".to_string())
    }

    fn build_info(&self) -> String {
        let mut parts = Vec::new();
        if let Some(profile) = &self.build_profile {
            parts.push(format!("profile {profile}"));
        }
        if let Some(target) = &self.build_target {
            parts.push(format!("target {target}"));
        }
        let commit = self.commit_short();
        parts.push(format!("commit {commit}"));
        parts.join(" | ")
    }

    fn features_summary(&self) -> String {
        let telemetry = if self.telemetry_enabled {
            "telemetry"
        } else {
            "telemetry off"
        };
        let metrics = if self.metrics_port > 0 {
            "metrics"
        } else {
            "metrics off"
        };
        let otel = if self.otel_enabled {
            "otel"
        } else {
            "otel off"
        };
        format!("{telemetry} | {metrics} | {otel}")
    }

    fn startup_ms(&self) -> u128 {
        self.startup_duration.as_millis()
    }

    #[cfg(feature = "rich-ui")]
    fn show_rich(&self) {
        let header_color = RchTheme::SECONDARY;
        let value_color = RchTheme::BRIGHT;
        let dim_color = RchTheme::DIM;

        let mut lines = Vec::new();
        for line in LOGO {
            lines.push(format!("[bold {header_color}]{line}[/]"));
        }

        lines.push(format!(
            "[{header_color}]Version:[/] [bold {value_color}]v{}[/] [dim {dim_color}]({})[/]",
            self.version,
            self.build_info()
        ));

        lines.push(format!(
            "[{header_color}]Socket:[/] [bold {value_color}]{}[/]  \
[{header_color}]Workers:[/] [bold {value_color}]{}[/]  \
[{header_color}]Slots:[/] [bold {value_color}]{}[/]",
            self.socket_path, self.workers, self.total_slots
        ));

        let metrics_label = if self.metrics_port > 0 {
            format!(":{port}", port = self.metrics_port)
        } else {
            "disabled".to_string()
        };

        lines.push(format!(
            "[{header_color}]Metrics:[/] [bold {value_color}]{}[/]  \
[{header_color}]Features:[/] [dim {dim_color}]{}[/]",
            metrics_label,
            self.features_summary()
        ));

        lines.push(format!(
            "[{header_color}]PID:[/] [bold {value_color}]{}[/]  \
[{header_color}]Started:[/] [bold {value_color}]{}[/]  \
[dim {dim_color}]startup {}ms[/]",
            self.pid,
            self.started_at.format("%Y-%m-%d %H:%M:%S"),
            self.startup_ms()
        ));

        let content = lines.join("\n");
        let border_color = Color::parse(RchTheme::SECONDARY).unwrap_or_default();
        let border_style = Style::new().color(border_color);

        let panel = Panel::from_text(&content)
            .title("RCHD")
            .border_style(border_style)
            .box_style(&DOUBLE);

        let console = Console::builder().force_terminal(true).build();
        console.print_renderable(&panel);
    }

    fn show_plain(&self) {
        let started = self.started_at.format("%Y-%m-%d %H:%M:%S");
        let metrics = if self.metrics_port > 0 {
            format!("metrics=:{}", self.metrics_port)
        } else {
            "metrics=off".to_string()
        };
        eprintln!(
            "[rchd] v{} ({}) | socket={} | workers={} slots={} | {} | pid={} | started={} | startup={}ms",
            self.version,
            self.build_info(),
            self.socket_path,
            self.workers,
            self.total_slots,
            metrics,
            self.pid,
            started,
            self.startup_ms()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::test_guard;

    fn test_banner() -> DaemonBanner {
        DaemonBanner::new(
            "0.1.0",
            Some("debug".to_string()),
            Some("x86_64-unknown-linux-gnu".to_string()),
            Some("abcdef123456".to_string()),
            "/tmp/rch.sock",
            2,
            16,
            9100,
            true,
            true,
            1234,
            Local::now(),
            Duration::from_millis(10),
        )
    }

    fn banner_with_options(
        telemetry: bool,
        metrics_port: u16,
        otel: bool,
        commit: Option<String>,
    ) -> DaemonBanner {
        DaemonBanner::new(
            "1.0.0",
            None,
            None,
            commit,
            "/var/run/rch.sock",
            4,
            32,
            metrics_port,
            telemetry,
            otel,
            5678,
            Local::now(),
            Duration::from_millis(150),
        )
    }

    #[test]
    fn build_info_includes_commit() {
        let _guard = test_guard!();
        let banner = test_banner();
        let info = banner.build_info();
        assert!(info.contains("commit"));
        assert!(info.contains("abcdef12"));
    }

    // ==================== commit_short tests ====================

    #[test]
    fn test_commit_short_truncates_to_8_chars() {
        let _guard = test_guard!();
        let banner = test_banner();
        let short = banner.commit_short();
        assert_eq!(short, "abcdef12");
    }

    #[test]
    fn test_commit_short_no_commit() {
        let _guard = test_guard!();
        let banner = banner_with_options(true, 9100, true, None);
        let short = banner.commit_short();
        assert_eq!(short, "unknown");
    }

    #[test]
    fn test_commit_short_short_hash() {
        let _guard = test_guard!();
        let banner = banner_with_options(true, 9100, true, Some("abc".to_string()));
        let short = banner.commit_short();
        assert_eq!(short, "abc");
    }

    // ==================== build_info tests ====================

    #[test]
    fn test_build_info_with_profile_and_target() {
        let _guard = test_guard!();
        let banner = test_banner();
        let info = banner.build_info();
        assert!(info.contains("profile debug"));
        assert!(info.contains("target x86_64-unknown-linux-gnu"));
    }

    #[test]
    fn test_build_info_without_profile_or_target() {
        let _guard = test_guard!();
        let banner = banner_with_options(true, 9100, true, Some("deadbeef".to_string()));
        let info = banner.build_info();
        assert!(!info.contains("profile"));
        assert!(!info.contains("target"));
        assert!(info.contains("commit deadbeef"));
    }

    // ==================== features_summary tests ====================

    #[test]
    fn test_features_summary_all_enabled() {
        let _guard = test_guard!();
        let banner = banner_with_options(true, 9100, true, None);
        let summary = banner.features_summary();
        assert!(summary.contains("telemetry"));
        assert!(summary.contains("metrics"));
        assert!(summary.contains("otel"));
        assert!(!summary.contains("off"));
    }

    #[test]
    fn test_features_summary_all_disabled() {
        let _guard = test_guard!();
        let banner = banner_with_options(false, 0, false, None);
        let summary = banner.features_summary();
        assert!(summary.contains("telemetry off"));
        assert!(summary.contains("metrics off"));
        assert!(summary.contains("otel off"));
    }

    #[test]
    fn test_features_summary_mixed() {
        let _guard = test_guard!();
        let banner = banner_with_options(true, 0, false, None);
        let summary = banner.features_summary();
        assert!(!summary.contains("telemetry off"));
        assert!(summary.contains("metrics off"));
        assert!(summary.contains("otel off"));
    }

    // ==================== startup_ms tests ====================

    #[test]
    fn test_startup_ms() {
        let _guard = test_guard!();
        let banner = test_banner();
        assert_eq!(banner.startup_ms(), 10);
    }

    #[test]
    fn test_startup_ms_larger_value() {
        let _guard = test_guard!();
        let banner = banner_with_options(true, 9100, true, None);
        assert_eq!(banner.startup_ms(), 150);
    }

    // ==================== show_plain tests ====================

    #[test]
    fn test_show_plain_does_not_panic() {
        let _guard = test_guard!();
        let banner = test_banner();
        // Just verify it doesn't panic - output goes to stderr
        banner.show_plain();
    }

    #[test]
    fn test_show_plain_with_metrics_disabled() {
        let _guard = test_guard!();
        let banner = banner_with_options(false, 0, false, None);
        banner.show_plain();
    }

    // ==================== show tests ====================

    #[test]
    fn test_show_does_not_panic() {
        let _guard = test_guard!();
        let banner = test_banner();
        // This should fall back to plain in test environment
        banner.show();
    }

    // ==================== DaemonBanner construction tests ====================

    #[test]
    fn test_daemon_banner_fields() {
        let _guard = test_guard!();
        let banner = test_banner();
        assert_eq!(banner.version, "0.1.0");
        assert_eq!(banner.socket_path, "/tmp/rch.sock");
        assert_eq!(banner.workers, 2);
        assert_eq!(banner.total_slots, 16);
        assert_eq!(banner.metrics_port, 9100);
        assert!(banner.telemetry_enabled);
        assert!(banner.otel_enabled);
        assert_eq!(banner.pid, 1234);
    }
}
